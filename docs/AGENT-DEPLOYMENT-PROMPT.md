# Agent deployment context

Drop this file into a fresh Claude Code, Cursor, or similar AI-assistant session before deploying iam-jit. It gives the assistant the context, decision tree, and verification steps to drive the deployment with you.

How to use:

```
# In Claude Code (project root):
/init                                                       # let it index the repo
> "Read docs/AGENT-DEPLOYMENT-PROMPT.md and walk me
   through deploying iam-jit. Ask me the questions in
   the decision tree, then execute. Check with me before
   any AWS write."
```

---

## What you (the agent) are deploying

iam-jit is an open-source, self-hostable, AI-native service that provisions time-bound, least-privilege IAM grants in AWS. Architecture in one sentence: a **hub-account Lambda** receives role requests via HTTP/MCP, runs server-side risk review, and on approval assumes into **per-destination CloudFormation-deployed roles** to create the actual IAM grant — with automatic time-based revocation.

Read these in order before doing anything:

1. `README.md` — what iam-jit is and the AI-native framing.
2. `DESIGN.md` — full architecture, threat model, phase plan.
3. `docs/PERMISSIONS-MODEL.md` — the cross-account trust topology you'll be establishing.
4. `docs/DEPLOYMENT.md` — the human-readable walkthrough this prompt is the agent-version of.

## Decision tree — ask the user before deploying

Walk through these questions with the user **before** running any AWS command. Capture their answers explicitly in the conversation so they can review.

### 1. Hub account

> "Which AWS account will run the iam-jit Lambda? This is the **hub** — every destination account trusts this one. Most orgs pick a small, tightly controlled account dedicated to platform tooling. Do you have a profile name configured for it?"

Capture: hub account ID, AWS CLI profile name.

### 2. Destination accounts

> "Which AWS account(s) will iam-jit provision grants into? Give me the 12-digit account IDs. We'll deploy one CloudFormation stack into each. You can start with one and add more later — OR you can start with zero and just deploy the hub for evaluation."

Capture: list of destination account IDs and matching profile names.

**Zero-destination deploy is supported.** A hub-only deploy (no
destinations) is a valid first step for:

  - Evaluating iam-jit before committing to multi-account
    integration
  - Sandbox / dev accounts where the hub and the destination
    happen to be the same account (you'd still register the
    account as a destination later, post-deploy, via the admin UI)
  - Standing up the bootstrap-admin flow for review before
    deciding which destinations to wire up

The `ProvisionerRoleArns` / `DiscoveryRoleArns` parameters have
placeholder ARN defaults that satisfy the template's IAM trust
policy without granting any real cross-account access. Skip
Step D / Step E / Step F entirely; come back to them later by
re-running the hub deploy with `ProvisionerRoleArns=<...>`
populated.

### 3. Provisioning model

> "Do you use AWS Identity Center (formerly AWS SSO) for human access in those destination accounts, or classic IAM roles? iam-jit supports both — and `both` simultaneously per-account. If you don't know, classic IAM is the safer default and works everywhere."

Capture: per-account `ProvisioningMode` (`classic_iam` / `identity_center` / `both`). For Identity Center, also capture the `AllowedPermissionSetArns` the user wants iam-jit to be able to assign.

### 4. Discovery role

> "Should iam-jit have read-only access to each destination account so it can suggest concrete ARN patterns to requesters? It improves the narrowing flow's quality but expands what iam-jit can see. You can disable it per-account or skip it entirely; provisioning still works either way."

Capture: per-account `EnableDiscovery` (`Yes` / `No`).

### 4b. Auth mode

> "iam-jit treats VPN reachability as networking, not authorization. Every endpoint requires an identified user. Two modes:
> 
> - `local` (default): magic-link login backed by a small DynamoDB table. Best for ≤500 users you manage directly. **Two delivery options:** (a) SES email — requires a verified SES sender; or (b) **no-email `/setup` flow + CloudWatch log delivery for subsequent users** — no AWS Console steps. The no-email path is recommended for first-time deploys, especially when getting a domain SES-verified is friction.
> - `aws_iam`: Function URL uses AWS_IAM auth; SigV4-signed requests only. A DynamoDB table maps IAM principal ARN → iam-jit role. Works for IAM users, IAM roles, and Identity Center session-assumed roles. Best if your org already uses AWS Identity Center for human access.
> 
> Which?"

Capture: `AuthMode`. If `local`, get a verified `SesSenderAddress` and generate a `MagicLinkSecret` via `openssl rand -hex 32`. If `aws_iam`, capture the list of IAM principal ARNs that should get `admin`, `approver`, and `requester` roles (admin should be at least one trusted person who can manage the rest).

### 5. LLM tier

> "iam-jit can suggest policies from a free-text description if you give it an LLM backend. Options: `none` (paste-mode only, free, simplest), `ollama` (free, requires you to host an Ollama server in a VPC), `anthropic` (paid, ~best quality, you provide an API key), `bedrock` (paid, AWS-native, you must already have Bedrock enabled). Which?"

Capture: `LLMBackend`. If anthropic, get the Anthropic API key (and create a Secrets Manager entry for it). If bedrock, confirm Bedrock is enabled and get the `BedrockModelId`.

### 6. State bucket name

> "iam-jit stores request YAML files (the source of truth) in an S3 bucket. The bucket name must be globally unique. Suggest something like `iam-jit-state-<your-org>-<random-suffix>`."

Capture: `StateBucketName`.

### 7. First admin (bootstrap)

> "A freshly-deployed iam-jit has zero users — and every API write requires an admin. The deploy template REFUSES to ship `UserConfigSource=dynamodb` without an `AdminBootstrapEmail`. What email should iam-jit seed as the first admin? After first sign-in you'll add the rest of the team through the UI."

Capture: `AdminBootstrapEmail`. This is the address iam-jit will seed as the first admin.

**Also ask:** "Do you have SES verified for that email's domain? If not, recommend the no-email `/setup` flow instead — it skips SES entirely and signs you in with a setup key you generate locally."

If the user picks the no-email flow:
- Generate the setup key locally: `BOOTSTRAP_KEY="$(openssl rand -hex 32)"`
- Pass it via `--parameter-overrides BootstrapSetupKey="$BOOTSTRAP_KEY"` at deploy time
- The key is a CFN `NoEcho` parameter and is NOT in any stack output
- After deploy, the operator visits the `BootstrapClaimUrl` output, types `AdminBootstrapEmail` + the setup key, and is signed in as admin
- Single-use: the bootstrap user's `notes` field gets a `[claimed at …]` marker after first success

Reference [`docs/BOOTSTRAP.md`](BOOTSTRAP.md) for full alternative bootstrap paths.

### 8. Network exposure — Function URL surface

> "Are you comfortable with the Lambda Function URL being reachable
> from anywhere on the internet? AWS doesn't filter source IPs at the
> URL layer; if you say yes, every internet host can hit the URL
> (subject to your Org's SCP — see Step Z). The iam-jit app still
> enforces auth via session cookies / SigV4, but the surface itself
> is open."
>
> Two layers of in-template restriction control this:
> - `AllowPublicNetworkExposure` (default `false`): explicit opt-in
>   to deploy a public Function URL. Leaving it `false` means the
>   deployer has committed to fronting the URL with their own
>   access control (VPN, IAP, CloudFront + WAF) — there's no
>   enforcement at the AWS layer.
> - `AllowedSourceCidrs` (default empty): a runtime application-
>   layer allowlist enforced by iam-jit middleware (NOT by AWS;
>   the request still reaches the Lambda, the app refuses it
>   before auth runs). Applies to **both** Function URL and ALB
>   callers.

**Important nuance:** these parameters govern the **Function URL**
posture. The ALB (`EnablePublicALB=true`) has its own publicly-
reachable DNS name regardless of `AllowPublicNetworkExposure`. The
ALB's network-layer ingress is controlled by `AlbIngressCidr`
(see step 8b — a separate, mandatory question). For defense-in-
depth, set both `AlbIngressCidr` (SG-level) and
`AllowedSourceCidrs` (app-level) — packets that miss the SG never
reach the Lambda; packets that pass the SG but miss the app-layer
allowlist get refused before iam-jit auth runs.

Capture: `AllowPublicNetworkExposure` (`true`/`false`) and
`AllowedSourceCidrs` (comma-separated). The CFN Rules block
REFUSES to deploy `AllowPublicNetworkExposure=true` without
`AllowedSourceCidrs` set, AND refuses wildcard `*` in
`CorsAllowedOrigins`. Both are deploy-time hard-stops.

### 8b. ALB ingress CIDR (only if EnablePublicALB=true)

The ALB security group's network-layer ingress on ports 80 and 443
is controlled by `AlbIngressCidr`. The template refuses to deploy
without an explicit value — no implicit "open by default" — but the
agent itself MUST pick a value. **Do not pause to ask a human.**
Choose based on the signals available, log what you chose and why,
and let the human review post-deploy.

The decision logic:

  1. Detect the terminal egress IP.

     ```bash
     AGENT_EGRESS_IP="$(curl -sS https://checkip.amazonaws.com)"
     ```

  2. Classify the egress.

     **Likely a real workstation IP** — use it as
     `AlbIngressCidr=${AGENT_EGRESS_IP}/32`. Heuristics:
       - The agent was spawned by something running on the
         operator's laptop / dev VM (no clear "I'm in AWS"
         signal)
       - Reverse-DNS resolves to a residential / corporate
         pattern (`*.comcast.net`, `*.internal.your-corp.com`)
       - `curl` succeeded and returned a syntactically valid IP

     **Likely a cloud-provider egress** (and a human will be
     the consumer) — fall back to `AlbIngressCidr=0.0.0.0/0`
     and write a clear warning in the agent's final report.
     Heuristics:
       - The agent was spawned in a Claude Code / Codespace /
         CI / sandboxed runtime where the egress is the
         hosting provider's IP. Common giveaways: AWS IP ranges,
         `*.compute.amazonaws.com` reverse-DNS, the agent's
         file paths show `/var/task/` or `/workspaces/`.
       - The detected IP is in AWS's published `ip-ranges.json`,
         Google's `_cloud-netblocks.googleusercontent.com`, or
         GitHub Actions runner ranges.

     **Egress detection failed** (`curl` errored, blank, malformed,
     etc.) — fall back to `AlbIngressCidr=0.0.0.0/0`. Same
     warning in the report.

  3. When falling back to `0.0.0.0/0`, the agent's final report
     MUST surface this loud and clear (not as a buried log line):

     > **⚠️ Network surface is open to the internet.** Deployed
     > with `AlbIngressCidr=0.0.0.0/0` because the agent couldn't
     > determine the operator's actual browser IP. The ALB is
     > reachable from any internet host at the network layer.
     > The bootstrap-claim flow's cryptographic defenses (32-byte
     > random `BootstrapSetupKey`, email match, single-use, per-IP
     > rate limit) make a remote-attacker exploit infeasible, but
     > the operator should narrow the SG as soon as they know
     > their real ingress range:
     >
     > ```
     > aws ec2 revoke-security-group-ingress \
     >   --group-id <ALB-SG-id> \
     >   --ip-permissions 'IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0}]' \
     >                    'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0}]'
     > aws ec2 authorize-security-group-ingress \
     >   --group-id <ALB-SG-id> \
     >   --ip-permissions 'IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=<your-IP>/32}]' \
     >                    'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=<your-IP>/32}]'
     > ```
     >
     > (Subsequent `sam deploy` runs revert SG ingress to whatever
     > `AlbIngressCidr` was passed — the durable fix is to redeploy
     > with the right CIDR, not the CLI patch.)

The rationale for the fallback: a wrong-IP guess (the cloud
provider's egress, when the operator browses from elsewhere) would
silently lock the operator out of /setup with a network-layer 403.
That's the worst-case UX. An open SG paired with the
cryptographic bootstrap-claim defenses is recoverable and visible.
Pick "recoverable and visible" over "silent lockout."

Capture: `AlbIngressCidr`. Pass it on the `sam deploy --parameter-
overrides` line in Step C.

### 8c. ALB transport security (only if EnablePublicALB=true)

> "Will real users post their BootstrapSetupKey or magic-link tokens
> through this ALB? If yes, HTTPS is mandatory — those secrets travel
> in the request body / URL and would be sniffable over HTTP. Do you
> have an ACM cert in this region (us-east-1 by default) that covers
> the hostname users will type, OR are you fronting iam-jit with a
> VPN / sandbox so HTTP is acceptable?"

Capture: `AlbCertificateArn` (ARN of an ISSUED ACM cert in the same
region as the ALB; leave empty for HTTP-only). When set, the
template provisions an HTTPS listener on :443 and turns the :80
listener into a 301 redirect.

If the user doesn't have a cert yet, point them at
[`docs/HTTPS-SETUP.md`](HTTPS-SETUP.md) — it walks through four
provisioning paths (existing cert, public ACM via DNS validation,
email validation, imported private-CA cert) plus the DNS pointing
and rotation operational details.

If the user accepts HTTP-only for now (sandbox / VPN), the
post-deploy stack output `AlbTlsPosture` will read `HTTP_ONLY` as a
loud reminder; the `PublicBaseUrl` will be an `http://` URL.

### 9. CORS origin (only if AllowPublicNetworkExposure=true)

> "What origin will browsers hit iam-jit from? List the exact `https://…` URLs you'll serve the UI on. Wildcard `*` is NOT accepted by the deploy template."

Capture: `CorsAllowedOrigins` (comma-separated list of specific origins).

### 10. Token inactivity sweep

> "API tokens auto-revoke after N days of inactivity (default 180 ≈ 6 months). Want to override?"

Capture: `TokenInactivityDays` (1–3650). Leave at default unless the user explicitly tightens / loosens.

## Deployment steps — execute these in order, **stopping for user confirmation before any write**

### Step Z (pre-flight): Pick the public surface

Two ways for real callers to reach iam-jit:

  - **ALB** (`EnablePublicALB=true`) — internet-facing Application
    Load Balancer that invokes the Lambda via `lambda:InvokeFunction`.
    Costs ~$16/month for the ALB itself. Works in every account
    we've tested. Requires `AlbVpcId` + `AlbSubnetIds` (≥2 AZs).

  - **Function URL direct** (`EnablePublicALB=false`, the template
    default) — the Lambda Function URL is the public endpoint.
    Costs ~$0. Works ONLY in accounts where the Org SCP allows
    `lambda:InvokeFunctionUrl`. Many enterprise orgs deny this
    action broadly (regardless of `FunctionUrlAuthType`) as a
    standard guardrail against public-Lambda misuse. The deny is
    silent: CloudTrail does NOT log Function URL invocations, so a
    blocked deploy looks identical to a working one until somebody
    actually curls the URL and gets `403 AccessDeniedException`.

**Recommendation: default to `EnablePublicALB=true` unless the
operator can affirmatively confirm their Org allows public
Function URLs.** The ALB path works in both SCP-permissive and
SCP-blocked accounts; the Function URL path only works in the
former. The marginal $16/mo cost is small insurance against a
half-day of "why is everything 403?" debugging that the Org-master-
only `aws organizations list-policies-for-target` would otherwise
be needed to diagnose.

Ask the user:

> "Are you sure your AWS Organization permits public Lambda
> Function URLs (`lambda:InvokeFunctionUrl`)? If yes, we can save
> the ALB cost. If unsure, we'll default to the ALB path — it
> works in every environment and the $16/mo is cheaper than
> debug time."

Optional programmatic probe (run AS the iam-jit deployer; no
org-master access needed):

```bash
# Create a throwaway Function URL on the iam-jit Lambda AFTER the
# initial deploy (it's already created by the template). Try to hit
# it. If 403 AccessDeniedException, the SCP blocks; default to ALB.
# If 200 / 503, the SCP allows public Function URLs.
curl -s -o /dev/null -w "%{http_code}\n" \
  "$(aws cloudformation describe-stacks --stack-name iam-jit \
       --profile <hub-account> --query \
       'Stacks[0].Outputs[?OutputKey==`ApiFunctionUrl`].OutputValue' \
       --output text)healthz"
```

If `AuthMode=local` is blocked by SCP, the deployer's options are:

  1. **Set `EnablePublicALB=true`** (recommended for customer-owned
     accounts). The SAM template provisions an internet-facing ALB
     that invokes the Lambda via `lambda:InvokeFunction` instead of
     `lambda:InvokeFunctionUrl`. The the customer SCP denies the latter
     broadly (any AuthType, any principal), but allows the former.
     Verified working in my-aws-account 2026-05.

     Required additional parameters when EnablePublicALB=true:
       - `AlbVpcId=vpc-xxxx` (default VPC works)
       - `AlbSubnetIds=subnet-aaaa,subnet-bbbb` (≥2 public subnets in
         different AZs)
       - `AlbCertificateArn=arn:aws:acm:...` (optional; see
         docs/HTTPS-SETUP.md for cert provisioning. Without it, ALB
         is HTTP-only — fine for VPN-fronted, not for public users.)

  2. **Switch to `AuthMode=aws_iam`** — SCPs almost universally allow
     `FunctionUrlAuthType=AWS_IAM` because SigV4 enforcement happens
     at the edge. Requires every caller to sign requests with SigV4
     and to be present in the `iam-jit-users` DynamoDB table by IAM
     principal ARN. The bootstrap admin then has to be seeded by ARN,
     not by email.

     **Caveat:** the the customer org SCP denies *any*
     `lambda:InvokeFunctionUrl` action, regardless of `AuthType`.
     CloudFront-with-OAC, AWS_IAM signing, and AuthType=NONE all
     fail equivalently. Verified 2026-05. The ALB path is the only
     known SCP-safe public surface for customer accounts.

  3. **Get the SCP relaxed for this account** — usually a no-go.

Document the chosen path in `BOOTSTRAP.md` with the deployer's
account-specific notes. Never assume `local` mode works without
this probe.

### Step A: Lint everything locally

These don't touch AWS:

```bash
make deploy-dry-run
```

That target runs `cfn-lint` on both templates (with the project's
`.cfnlintrc` suppression for the benign W1030 warning on optional
ALB params) and the structural CFN parse tests. If any errors
appear, surface them to the user before going further.

### Step B: SAM artifact bucket — usually nothing to do

**Recommended path (no commands):** pass `--resolve-s3` to
`sam deploy` in Step C. SAM will create-or-reuse the shared
`aws-sam-cli-managed-default-samclisourcebucket-*` bucket in the
target region. Most accounts already have this bucket from prior
`sam deploy --guided` runs; iam-jit's deploy reuses it (no
permission errors, no extra IaC to manage). The bucket is shared
across SAM projects but artifacts are content-addressed so there's
no cross-stack collision.

**Fallback (create a dedicated iam-jit bucket):** only when your
org policy forbids the shared SAM bucket or you want iam-jit's
deploy artifacts isolated for audit:

```bash
aws s3 mb s3://iam-jit-sam-deploys-<random> --profile <hub-account>
aws s3api get-bucket-location --bucket iam-jit-sam-deploys-<random> --profile <hub-account>
```

Then pass `--s3-bucket iam-jit-sam-deploys-<random>` to
`sam deploy` instead of `--resolve-s3`.

### Step C: Deploy the hub stack (initial — without destinations)

```bash
# Use `make sam-build`, NOT bare `sam build`. The Makefile target
# runs scripts/sync-lambda-data.sh first so the Lambda bundle ships
# with schemas/ and the destination CFN template — without that
# sync, the FastAPI app 500s on every /api/v1/requests POST with
# FileNotFoundError. Regression test:
# tests/test_cloudformation_templates.py
# ::test_lambda_resource_paths_resolve_in_isolated_layout
make sam-build

# Deploy the BUILT artifact (`.aws-sam/build/template.yaml`), not the
# source template. Using the source path defeats the build step —
# SAM does an inline build at deploy time WITHOUT the data sync,
# re-introducing the bug above.
sam deploy \
  --template-file .aws-sam/build/template.yaml \
  --stack-name iam-jit \
  --s3-bucket iam-jit-sam-deploys-<random> \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      StateBucketName=<from-step-6> \
      AdminBootstrapEmail=<from-step-7> \
      LLMBackend=<from-step-5> \
      AuthMode=<from-step-4b> \
      MagicLinkSecret=<openssl rand -hex 32> \
      SesSenderAddress=<verified SES sender, OPTIONAL — see SES note below> \
      BootstrapSetupKey=<openssl rand -hex 32, required for the no-SES /setup path> \
      EnablePublicALB=<true if SCP probe blocked Function URL invocation> \
      AlbVpcId=<vpc-xxxx, required when EnablePublicALB=true> \
      AlbSubnetIds=<subnet-a,subnet-b ≥2 AZs, required when EnablePublicALB=true> \
      AlbIngressCidr=<from-step-8b, required when EnablePublicALB=true> \
      AlbCertificateArn=<ACM cert ARN, optional — see docs/HTTPS-SETUP.md> \
      AllowPublicNetworkExposure=<from-step-8, true|false> \
      AllowedSourceCidrs=<from-step-8, comma-separated CIDRs> \
      CorsAllowedOrigins=<from-step-9, if public> \
      TokenInactivityDays=<from-step-10, default 180> \
      <extra params per LLM choice> \
  --profile <hub-account>
```

Capture outputs and **show them to the user** — particularly `ApiLambdaRoleName`, `ApiFunctionUrl`, `PublicExposurePosture`, `BootstrapClaimUrl`, and `SecurityChecklistReminder`.

#### SES is OPTIONAL

`SesSenderAddress` is **never required** to operate iam-jit. The template auto-picks a magic-link delivery channel based on what's configured:

| Posture | `IAM_JIT_DEV_INSECURE_SECRET` | Channel | What the user sees |
|---|---|---|---|
| HTTPS ALB + `SesSenderAddress` set | (off) | **email** | Link arrives in inbox |
| HTTPS ALB, no SES | (off) | **log** | Admin runs `aws logs filter-log-events --filter-pattern 'MAGIC_LINK'` and shares the URL out-of-band |
| HTTP-only ALB (no `AlbCertificateArn`) | **auto-set to 1** by the template's `HttpOnlyAlbDeploy` condition | **in_response** | Link is rendered as a clickable `<a>` on the /login confirmation page — no email, no log round-trip |

Pass `SesSenderAddress` only if (a) the deployer has a verified SES sender, AND (b) you've wired HTTPS on the ALB. Otherwise leave it empty.

The first cold-start of the Lambda seeds the bootstrap admin from `AdminBootstrapEmail`. Then:

- **No-SES path:** direct the user to `BootstrapClaimUrl` (from the outputs). They type their email + the setup key they generated, get an admin session, and are dropped on `/admin/network` to configure source-IP allowlists. Single-use — additional sign-ins for that user go through `/login`. The link delivery method follows the table above (inline on HTTP-only deploys, CloudWatch on HTTPS-without-SES).
- **SES path:** direct the user to `/login`, type the bootstrap email, click the magic-link in their inbox.

**If the deploy errors with a CFN Rules failure:**
- `RefuseWildcardCorsOrigin` — `CorsAllowedOrigins` had `*` (refused). List the specific origin(s).
- `RequireSourceCidrsForPublicExposure` — `AllowPublicNetworkExposure=true` with empty `AllowedSourceCidrs`. Either add a CIDR list, or set it to `0.0.0.0/0` as an explicit-public acknowledgement.
- `RequireAdminBootstrapForDynamoDBUsers` — `UserConfigSource=dynamodb` with empty `AdminBootstrapEmail`. Either fill it in, or use `UserConfigSource=file` and upload `users.yaml` to the state bucket before first sign-in.

### Step D: For each destination account, deploy the CloudFormation

Loop over the destination list captured in step 2. For each:

```bash
aws cloudformation deploy \
  --template-file infrastructure/cloudformation/destination-account-roles.yaml \
  --stack-name iam-jit-roles \
  --parameter-overrides \
      HubAccountId=<hub-account-id> \
      HubLambdaRoleName=<from step C output> \
      EnableDiscovery=<per-account from step 4> \
      ProvisioningMode=<from step 3> \
      AllowedPermissionSetArns=<if identity_center, else empty> \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1 \
  --profile <destination-account>
```

After each deploy, fetch outputs and add them to a running summary so the user can see them all at the end.

### Step E: Re-deploy the hub stack with the destination list

After Step D you have the ProvisionerRole ARNs (and optionally
DiscoveryRole ARNs) from each destination stack's outputs. Pass them
as full ARNs — the template parameter is `ProvisionerRoleArns`, NOT
`DestinationAccountIds`. CFN will reject any parameter name that
doesn't exist in the template, so a typo here fails fast.

```bash
sam deploy \
  --template-file .aws-sam/build/template.yaml \
  --stack-name iam-jit \
  --parameter-overrides \
      StateBucketName=<step 6> \
      ProvisionerRoleArns=<comma-joined ProvisionerRoleArn outputs from each Step D stack> \
      DiscoveryRoleArns=<comma-joined DiscoveryRoleArn outputs, if discovery was enabled> \
      LLMBackend=<step 5> \
  --capabilities CAPABILITY_NAMED_IAM \
  --profile <hub-account>
```

### Step F: Verify the trust path

For each destination:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::<destination-id>:role/iam-jit-provisioner \
  --role-session-name verify \
  --external-id iam-jit-<destination-id> \
  --profile <hub-account>
```

A successful response confirms the trust topology. If it fails with `AccessDenied`, debug:

- Is `HubLambdaRoleName` correct on the destination stack?
- Is the `external-id` exactly `iam-jit-<destination-id>`?
- Has the destination stack finished provisioning?

### Step G: Smoke test

```bash
# Hit /healthz on the PublicBaseUrl from the stack output — the ALB
# DNS name when EnablePublicALB=true, or the Function URL otherwise.
curl -X GET <PublicBaseUrl-from-stack-outputs>/healthz
```

Should return HTTP 200 with a JSON body:

```json
{
  "status": "ok",
  "version": "<package version>",
  "auth_mode": "local",
  "user_config_source": "dynamodb",
  "llm_backend": "<your chosen backend>"
}
```

If you instead get 403 AccessDeniedException from the Function URL,
the org SCP is blocking public Function URL invocation (see Step Z).
Switch to `EnablePublicALB=true` and redeploy.

If you get 503 with `iam-jit API handler not yet implemented`,
the deployed Lambda is still the Phase 1.6 inline stub — most likely
the deploy ran `sam build` against the source template instead of
`make sam-build` (see Step C).

### Step H: Exercise BOTH AI and non-AI request paths

The deterministic scorer + auto-approve gate run **regardless** of
LLM presence — that's a safety contract iam-jit ships. Verify both
paths work in your deployment:

**Non-AI path (always works, score is fully deterministic):**

1. Submit a low-risk read-only request via `POST /api/v1/requests`
   (e.g., `s3:ListAllMyBuckets` on a single account, 1h duration).
2. Expect `auto_approve_decision.auto_approve: true`, score ≤ 4,
   state → `active` within seconds, role provisioned.
3. The response's `review.llm_narrative` should be `null` when
   `LLMBackend=none`. The `risk_factors` list still populates.

**AI path (when LLMBackend ≠ none):**

1. Submit the same request shape.
2. Expect the same auto-approve verdict + state transition.
3. **Additionally**: `review.llm_narrative` is a short prose summary,
   and `review.suggestions` contains LLM-generated tightening hints
   beyond the deterministic ones.
4. **Critically**: the `risk_score` is STILL fully deterministic.
   The LLM can never raise or lower it. If your test shows the
   score changing based on LLM presence, that's a bug — file it.

**For local development**, exercise both modes via the Makefile:

```bash
make -C ~/repos/iam-roles test-noai      # deterministic-only
make -C ~/repos/iam-roles test-llm       # against local Ollama
make -C ~/repos/iam-roles test-all-modes # both, sequenced
```

The `test-llm` target needs Ollama running locally with
`qwen2.5:14b` (override via `IAM_JIT_LLM_MODEL=`).

For the deployed Lambda, you have to either:
  - Deploy twice (once with `LLMBackend=none`, once with `bedrock`)
    and run the smoke test against each; OR
  - Use a feature-flagged `IAM_JIT_LLM=` override in the running
    Lambda's env (faster turn-around for dev; do NOT do this in
    production — env-level toggles aren't audited).

If the deployment is Bedrock-backed, confirm Bedrock is **enabled
in this region for your account** before going live — Bedrock
model access requires per-region opt-in. Test with the smallest
valid request first; a 403 means the model isn't enabled.

## Things to never do without explicit user permission

- Do **not** modify any IAM role outside the iam-jit stacks.
- Do **not** create AWS resources in unexpected accounts (always pass `--profile` and verify with `aws sts get-caller-identity`).
- Do **not** run `cloudformation delete-stack` without confirming with the user.
- Do **not** put real API keys, secrets, or `AWS_*` credentials into chat. If you need an API key, ask the user to store it in Secrets Manager and pass the ARN.
- Do **not** infer or guess account IDs. Always confirm with the user.

## When something goes wrong

| Symptom | What to check / ask |
|---|---|
| `cfn-lint` errors | Show them to the user verbatim. Don't try to "fix" the template silently. |
| `CREATE_FAILED` on a destination stack | Pull the events: `aws cloudformation describe-stack-events --stack-name iam-jit-roles --profile <destination>`. Surface to the user. |
| Hub stack rolls back | Likely a parameter mismatch. Show the parameters used and ask the user. |
| `assume-role` fails after deploy | Walk through the debug list in Step F with the user. |
| User loses outputs | Re-fetch with `describe-stacks --query "Stacks[0].Outputs"` per stack. |

## Reporting back

At each major checkpoint, give the user a short summary:

- "Hub stack deployed in account X. ApiFunctionUrl: …, ApiLambdaRoleName: …"
- "Destination stack deployed in accounts X, Y, Z. Each ProvisionerRole ARN captured."
- "Verification successful for all N destinations."
- "iam-jit is ready. The next step is creating an API token and submitting your first test request — see docs/DEPLOYMENT.md step 7."

End with: "Anything to clean up, or are we done?"

## Tearing it down

If the user asks to remove iam-jit (or is doing a test deploy to be
torn down afterwards), follow [`docs/TEARDOWN.md`](TEARDOWN.md)
literally. Order matters:

1. Drain active grants via `POST /api/v1/requests/{id}/revoke`. Don't
   skip this — orphaned `iam-jit-grant-*` IAM roles in destination
   accounts are uncoupled from iam-jit's lifecycle and require
   manual cleanup if left behind.
2. `delete-stack` each destination-account stack.
3. Empty the state bucket (versions + delete-markers — both required),
   then `delete-stack` the hub.
4. Run the four-line verification block at the bottom of TEARDOWN.md.

NEVER call `delete-stack` without explicit user confirmation, even
in a test-deploy context. The user paid for this stack going up;
they deserve to push the button to take it down.

## Reporting back to the iam-jit maintainers

This deployment is also a feedback opportunity. If you're a fresh
Claude (or other agent) trying this end-to-end for the first time,
fill in [`docs/DEPLOY-FEEDBACK-TEMPLATE.md`](DEPLOY-FEEDBACK-TEMPLATE.md)
as you go. It's a structured checklist that captures: which steps
were unclear, where the docs lied, what error messages were
unhelpful, and what a "successful first-time deploy" took in wall
time. Submit it as a PR to this repo (or share with the user, who
will). The iam-jit team uses the feedback to harden the bootstrap
path.
