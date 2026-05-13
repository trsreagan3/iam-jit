# Bootstrap — getting the first admin into a fresh deployment

A freshly-deployed iam-jit instance has zero users. Every API write
(create-user, register-account, approve-request) requires an authenticated
admin, but admins are themselves stored in the user store. Without an
explicit bootstrap step, a fresh `UserConfigSource=dynamodb` deployment
is unreachable.

## ⚠ One iam-jit stack per AWS account + region

The template uses fixed names for the Lambda function, IAM role, log
group, and several DynamoDB tables. A second `sam deploy` with the
same template into the same account+region will fail with
`AlreadyExistsException` errors mid-deploy and leave a partial stack
behind. If you need iam-jit in two accounts, deploy each in its
own account; if you need it in two regions of the same account,
ask first — running concurrent iam-jit deploys with different
data planes hasn't been tested and the SCP / IAM trust-policy
implications haven't been audited.

Resources that would collide:

  - `iam-jit` Lambda function name
  - `iam-jit-lambda-execution` IAM role
  - `/aws/lambda/iam-jit` CloudWatch log group
  - `iam-jit-cidrs` DynamoDB table
  - `iam-jit-users` + `iam-jit-api-tokens` (defaults; can be
    overridden via SAM parameters if you really need parallel
    deploys, but you're swimming upstream)

Pre-flight check: run
`aws lambda get-function --function-name iam-jit --profile <hub>`
before `sam deploy`. If it returns a Lambda not owned by your
intended new stack, the deploy will fail.

This document covers the four production-supported ways to seed the first
admin. Pick one based on how you deployed.

## TL;DR by deployment shape

| Deployment | Bootstrap path |
|---|---|
| **SAM, `UserConfigSource=dynamodb`, no SES** | **Recommended Phase 1.** Set `AdminBootstrapEmail` + `BootstrapSetupKey` at deploy. Lambda seeds the admin record; you visit `/setup`, type the email and key once, and you're signed in as admin. No SES verification needed. |
| SAM, `UserConfigSource=dynamodb`, SES configured | Set `AdminBootstrapEmail` + `SesSenderAddress`. Lambda seeds the admin; you sign in via `/login`, the magic-link arrives by email. |
| SAM, `UserConfigSource=file` | Upload `users.yaml` with the admin to `s3://<state-bucket>/users.yaml` *before* first sign-in. |
| Local `iam-jit serve --users-file ./users.yaml` | Run `iam-jit seed-admin --email <addr> --users-file ./users.yaml` once. |
| Already-running prod, no admin yet | Run `iam-jit seed-admin --email <addr> --users-table iam-jit-users` from a workstation with AWS creds. |

After seeding the first admin, every additional user is added either
through the web UI (`/admin/users`) or programmatically by an agent
holding an admin's API token.

## Phase 1 (no SES): `/setup` claim flow

The fastest end-to-end happy path. No SES verification, no logged-in
shell required, no plaintext URL containing a secret.

```bash
# 1. Generate a one-time setup key. Save it — you'll type it into a form.
BOOTSTRAP_KEY="$(openssl rand -hex 32)"
echo "$BOOTSTRAP_KEY"   # copy to clipboard / password manager

# 2. Deploy with both the admin email AND the setup key:
sam deploy \
  --stack-name iam-jit \
  --parameter-overrides \
    AdminBootstrapEmail=you@your-corp.com \
    BootstrapSetupKey="$BOOTSTRAP_KEY" \
    StateBucketName=iam-jit-state-... \
    AllowPublicNetworkExposure=false \
  --capabilities CAPABILITY_IAM

# 3. Read the BootstrapClaimUrl from CFN outputs. It's just the
#    Function URL + /setup — no secret in it.
aws cloudformation describe-stacks \
  --stack-name iam-jit \
  --query 'Stacks[0].Outputs[?OutputKey==`BootstrapClaimUrl`].OutputValue' \
  --output text
```

Open the URL in a browser, type `AdminBootstrapEmail` + the setup key,
submit. You'll be redirected to `/admin/network` with an admin session
cookie. Single-use: a `[claimed at …]` marker is appended to the
bootstrap user's `notes` field, so a second submit returns "already
consumed". To reset, redeploy with a fresh `BootstrapSetupKey`.

**Trust boundary.** The secret never enters any AWS resource that a
wide IAM role can read. CFN outputs and the URL itself contain no
secret — anyone with `cloudformation:DescribeStacks` sees only the
bare URL. The key lives in the Lambda env var
`IAM_JIT_BOOTSTRAP_SETUP_KEY` (NoEcho parameter), which is readable
only by principals with `lambda:GetFunctionConfiguration` on the
iam-jit function — a much narrower set than CFN-stack-read. The
deployer's local terminal / password manager is the authoritative
copy.

**If your AWS Organization denies public Function URLs (SCP),** add
`EnablePublicALB=true` along with VPC + subnet IDs:

```bash
# 1. Detect the operator's egress IP (the IP their BROWSER will
#    use, not necessarily this terminal's egress — they differ if
#    you're on a remote / cloud session). Ask them to run on
#    their workstation:
#       curl -sS https://checkip.amazonaws.com
#    Use the result as the AlbIngressCidr below.
MY_IP="<from step above>"

# 2. Deploy
sam deploy \
  --parameter-overrides \
    AdminBootstrapEmail=you@your-corp.com \
    BootstrapSetupKey="$BOOTSTRAP_KEY" \
    StateBucketName=iam-jit-state-... \
    AllowPublicNetworkExposure=false \
    EnablePublicALB=true \
    AlbVpcId=vpc-xxxx \
    AlbSubnetIds=subnet-aaaa,subnet-bbbb \
    AlbIngressCidr="${MY_IP}/32" \
  --capabilities CAPABILITY_NAMED_IAM
```

The template REFUSES to deploy with `EnablePublicALB=true` and an
empty `AlbIngressCidr` — the choice must be explicit. Use
`AlbIngressCidr=0.0.0.0/0` if you genuinely want the ALB open to
the internet (the BootstrapSetupKey defenses still apply, but
this is a deliberate trade-off, not a default).

The template provisions an internet-facing ALB that invokes the
Lambda via `lambda:InvokeFunction` — a different IAM action than
`lambda:InvokeFunctionUrl`, so SCPs that deny public Function URLs
don't apply. The ALB becomes the public surface; the Function URL
stays unused (and unreachable through the SCP) for direct
`aws lambda invoke` smoke testing only.

By default the ALB listens on HTTP (port 80). For HTTPS, provide
an ACM certificate via `AlbCertificateArn` — see
[`docs/HTTPS-SETUP.md`](HTTPS-SETUP.md) for the full guide
(BYO cert, DNS validation walkthrough, wildcards, rotation,
cross-account, custom domain pointing).

HTTP-only is acceptable for VPN-fronted staging or sandbox accounts.
It is NOT acceptable for any deployment where users will paste the
`BootstrapSetupKey` or magic-link tokens over the public internet —
the form POST and the URL respectively travel in cleartext.

For deeper hardening, store the key in Secrets Manager with a
resource policy and read it at runtime (v2 idea — tracked in
`docs/ROADMAP.md`).

## Path 1: SAM deploy with DynamoDB user store (recommended)

This is the production default. The SAM `Rules` block refuses to deploy
`UserConfigSource=dynamodb` without `AdminBootstrapEmail` set, so the
foot-gun is impossible.

```bash
sam deploy \
  --stack-name iam-jit \
  --parameter-overrides \
    AdminBootstrapEmail=you@your-corp.com \
    StateBucketName=iam-jit-state-... \
    AllowPublicNetworkExposure=false \
  --capabilities CAPABILITY_IAM
```

What happens on the first Lambda cold-start:
1. The factory builds a `DynamoDBUserStore` pointing at the empty
   `iam-jit-users` table.
2. `iam_jit.user_bootstrap.maybe_seed_at_startup` reads
   `IAM_JIT_ADMIN_BOOTSTRAP_EMAIL` (set by the SAM template).
3. Lookup against the empty table returns `UserNotFound`, so the function
   writes a single record: `email:you@your-corp.com` with `roles=[admin]`,
   `enabled=True`, `notes="seeded by IAM_JIT_ADMIN_BOOTSTRAP_EMAIL on
   first deploy"`.
4. Operator visits the Function URL, signs in with `you@your-corp.com`,
   gets the magic-link, lands as admin.

The bootstrap is idempotent. Subsequent cold-starts find the user and
skip the put. You can leave `AdminBootstrapEmail` set forever — once the
record exists, changing the parameter value won't overwrite the existing
admin's role or settings.

## Path 2: SAM deploy with YAML user store

Choose this if you want the user list in version control or under
GitOps review:

1. Author `users.yaml`:

   ```yaml
   schema_version: 1
   auth_mode: local
   users:
     - id: email:you@your-corp.com
       display_name: You
       roles: [admin]
   ```

2. Upload before first sign-in:

   ```bash
   aws s3 cp users.yaml s3://${STATE_BUCKET}/users.yaml
   ```

3. Deploy with `UserConfigSource=file`:

   ```bash
   sam deploy \
     --stack-name iam-jit \
     --parameter-overrides \
       UserConfigSource=file \
       StateBucketName=${STATE_BUCKET} \
     --capabilities CAPABILITY_IAM
   ```

In this mode the `iam-jit users` API endpoints return 409 — adding users
means editing `users.yaml` and re-uploading. This is intentional for
GitOps-style deployments; the trade-off is that **agents cannot add
users** (they need a writable backend). If your agents need to add
users, use Path 1.

## Path 3: Local dev (`iam-jit serve`)

```bash
# One-shot seed
.venv/bin/iam-jit seed-admin \
  --email you@example.com \
  --users-file ./dev-users.yaml

# Now run the server pointed at the same file
IAM_JIT_DEV_INSECURE_SECRET=1 \
.venv/bin/iam-jit serve --users-file ./dev-users.yaml
```

The CLI creates `dev-users.yaml` if missing and appends the admin record.
Re-running with the same email is a no-op — you'll see "User … already in
… — no change."

## Path 3.5: "I just want to try it" — random-fallback bootstrap

Useful for kicking the tires without configuring an email or hand-
editing YAML. **Off by default** — opt in with one env var.

```bash
IAM_JIT_DEV_INSECURE_SECRET=1 \
IAM_JIT_MAGIC_LINK_SECRET=$(openssl rand -hex 32) \
IAM_JIT_ALLOW_RANDOM_BOOTSTRAP=1 \
.venv/bin/iam-jit serve
```

What happens on startup:

1. iam-jit notices: opt-in is set, no admin-email env var, store is
   empty.
2. Generates a random user_id like `email:bootstrap-a3f9e7@iam-jit.local`
   with `roles=[admin]`.
3. Mints a one-shot magic-link valid for 15 minutes.
4. Writes the sign-in URL to `/tmp/iam-jit-bootstrap-link.txt`
   (mode 0600). Override with `IAM_JIT_BOOTSTRAP_STATE_DIR=…`.
5. Logs a single warning line so you also see it in the terminal.

Then:

```bash
$ cat /tmp/iam-jit-bootstrap-link.txt
# iam-jit random-bootstrap link
# user: email:bootstrap-a3f9e7@iam-jit.local
# valid for: 15 minutes (single-use)
…
http://127.0.0.1:8000/auth/magic-callback?token=…
```

Open the URL → you're admin. **Then immediately**:

1. `/admin/users` → add your real email as admin.
2. Sign out, sign in as your real email.
3. `/admin/users` → delete the random `bootstrap-…@iam-jit.local`
   record. (The notes field on it says "delete after use" so you
   won't lose track.)

The random fallback is intentionally not allowed by the production
SAM `Rules` block — it's a dev-mode escape hatch, not something you
ship to prod. In prod you set `AdminBootstrapEmail` and let the
deterministic path run.

## Path 4: Already-running prod, no admin yet (recovery path)

If you deployed with the old SAM template (no Rules block) and ended up
with an empty users table, you can seed the first admin from any
workstation that has AWS creds for the iam-jit account:

```bash
AWS_REGION=us-east-1 \
.venv/bin/iam-jit seed-admin \
  --email you@your-corp.com \
  --users-table iam-jit-users
```

This writes directly to the DynamoDB table from outside the Lambda, using
the deployer's AWS credentials. Idempotent — if the user already exists,
prints a message and exits zero.

After running, sign in via the Function URL.

## Adding more users programmatically (agents)

Once the first admin exists, the second admin can be added either via
the web UI or via the API. Agents typically use the API:

```bash
# As the bootstrap admin, mint an API token (one-time)
TOKEN=$(curl -s -X POST https://iam-jit.example.com/api/v1/tokens \
  --cookie "iam_jit_session=$SESSION" \
  -H 'Content-Type: application/json' \
  -d '{"label":"agent-onboarding"}' \
  | jq -r .token)

# Agent uses the token from then on
curl -X POST https://iam-jit.example.com/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "email:newhire@your-corp.com",
    "display_name": "New Hire",
    "roles": ["requester"]
  }'
```

Roles a token-bearing agent can grant are bounded by the token holder's
own role — admin tokens can create admins, approver tokens cannot. The
token inherits its caller's privileges, no privilege escalation.

The user-add API path requires `UserConfigSource=dynamodb`. In `file`
mode the route returns 409 — the YAML is the source of truth and agents
shouldn't be writing it directly.

## What the bootstrap does NOT do

- Does **not** lock the admin into iam-jit forever. Once they're in,
  the admin can promote others, demote themselves, or delete their
  own record (with the usual self-action restrictions).
- Does **not** set their password / auth method. Authentication is
  via magic-link email regardless of how the user was created.
- Does **not** override an existing record. If the bootstrap email
  already exists with `roles=[requester]`, it stays a requester — the
  bootstrap is a *create-if-missing*, never a *promote-on-each-deploy*.
- Does **not** persist the admin if the user store is reset
  (e.g., stack delete + redeploy). The next deploy re-seeds them.

## Verification

After bootstrap, confirm:

```bash
# Should list at least the bootstrap admin.
curl -s https://iam-jit.example.com/api/v1/users \
  --cookie "iam_jit_session=$SESSION" | jq

# Should include `roles: ["admin"]` on the bootstrap user.
```

Or in the UI: visit `/admin/users` and confirm the bootstrap email is
listed with the admin role. From there, the rest of the team gets added
through the normal workflow.
