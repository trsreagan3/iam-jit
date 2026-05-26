# Getting started

This doc walks you from "git clone" to a working deploy in 5 minutes
(MVP path), then shows what to layer on top for a production launch.

If you only want the offline CLI (`pip install git+https://github.com/trsreagan3/iam-jit.git` — the scorer
ships as the `iam-risk-score` console script inside the `iam-jit`
wheel; there is no separate `iam-risk-score` PyPI package; will switch
to `pip install iam-jit` once published to PyPI, #235), stop
reading — that's already covered in the main [README](../README.md).
This doc is for the **self-hosted deploy** of the full iam-jit stack
(scoring API + provisioning workflow).

---

## Pre-flight (one-time, ~10 min)

You need:

| Thing | Why | Skip if |
|---|---|---|
| Python 3.12 | Lambda runtime + local CLI | — |
| Docker | `sam build --use-container` for reproducible Lambda bundles | You're OK with `sam build` against your host Python (less reproducible) |
| AWS SAM CLI | The deploy tool | — |
| AWS CLI v2 | Auth + verification | — |
| An AWS account | Where the stack lives | Local-only testing (use `iam-risk-score --offline`) |
| `boto3 + venv` of this repo | Most scripts run locally first | — |

Install + verify:

```bash
# macOS
brew install python@3.12 docker aws-sam-cli awscli

# Linux: apt install python3.12 python3.12-venv && pipx install aws-sam-cli awscli

# Project bootstrap
cd ~/repos
git clone https://github.com/trsreagan3/iam-jit.git
cd iam-jit
python3.12 -m venv .venv
.venv/bin/pip install --upgrade pip   # PEP 660 editable needs pip >= 22.3; venv ships older pip on some distros (#548)
.venv/bin/pip install -e '.[dev]'
make test   # 2,668 tests must pass — confirms your local env is healthy
```

Then point AWS CLI at your account:

```bash
aws configure --profile iam-jit
aws sts get-caller-identity --profile iam-jit   # confirms creds work
```

---

## MVP deploy (~5 min, ~$6/mo)

The **minimum-viable deployment**. What you get:

- ✅ The full iam-jit Lambda running
- ✅ `/api/v1/score` endpoint reachable via Lambda Function URL (HTTPS)
- ✅ All DynamoDB tables for users/requests/settings/etc.
- ✅ Deterministic scoring (no LLM yet)
- ✅ ~$6/mo idle AWS cost
- ❌ No custom domain (uses `*.lambda-url.us-east-1.on.aws`)
- ❌ No Bedrock LLM (deterministic-only — free tier exact match)
- ❌ No CloudFront / WAF (in-Lambda rate limit only — vulnerable to instance-bypass at scale)
- ❌ No Stripe billing (manual API-key management)

This is the right shape for: **soft launch, internal-tool usage,
or local-development self-hosting**. Public launch needs the
production-hardening section below.

### Three required parameters

You MUST set three values. Everything else has sensible defaults.

| Parameter | What | How to get one |
|---|---|---|
| `StateBucketName` | Globally-unique S3 bucket name for request YAMLs | Pick anything unique: `iam-jit-state-<your-account-id>` |
| `AdminBootstrapEmail` | First admin's email (your email) | Your actual email |
| `BootstrapSetupKey` | One-time admin-claim secret | `openssl rand -hex 32` |

### Deploy command

```bash
# From the repo root, with AWS_PROFILE=iam-jit set:
AWS_PROFILE=iam-jit make sam-build

BOOT_KEY=$(openssl rand -hex 32)
echo "$BOOT_KEY" > ~/.iam-jit/bootstrap-setup-key   # save it!

AWS_PROFILE=iam-jit DOCKER_HOST="$DOCKER_HOST" sam deploy \
  --template-file .aws-sam/build/template.yaml \
  --stack-name iam-jit-mvp \
  --region us-east-1 \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --resolve-s3 \
  --no-confirm-changeset \
  --parameter-overrides \
    StateBucketName=iam-jit-state-$(aws sts get-caller-identity --profile iam-jit --query Account --output text) \
    AdminBootstrapEmail=YOUR_EMAIL@example.com \
    BootstrapSetupKey="$BOOT_KEY" \
    AllowPublicNetworkExposure=true \
    AllowedSourceCidrs=0.0.0.0/0 \
    CorsAllowedOrigins=https://example.com
```

Wait ~5 min. Then grab the outputs:

```bash
aws cloudformation describe-stacks --profile iam-jit \
  --stack-name iam-jit-mvp \
  --query 'Stacks[0].Outputs' --output table
```

Test the score endpoint:

```bash
URL=$(aws cloudformation describe-stacks --profile iam-jit \
  --stack-name iam-jit-mvp --query 'Stacks[0].Outputs[?OutputKey==`ApiFunctionUrl`].OutputValue' \
  --output text)

curl -X POST "$URL/api/v1/score" \
  -H "Content-Type: application/json" \
  -d '{"policy":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:DeleteBucket"],"Resource":["*"]}]},"access_type":"read-write"}'
```

You should see a JSON response with `"score": 7`, `"tier": "high"`, factors, and suggestions.

**You're live.** The score endpoint is public; rate-limited at 30
req/min per IP; doesn't invoke any LLM.

---

## Production hardening (layered)

After the MVP works, add these one at a time. Each is independent;
none of them require redeploying the Lambda code — they're
parameter changes that CFN applies via stack update.

### Tier 1: Edge protection (~$10–20/mo, recommended before public traffic)

Adds CloudFront + WAFv2 rate-based rule in front of the Function URL.
Real per-IP rate limiting (the in-Lambda limit is per-instance only —
useless at AWS scale). HTTPS termination, Shield Standard DDoS, and
optional caching by `policy_fingerprint`.

```bash
# Re-deploy with edge protection on:
sam deploy --stack-name iam-jit-mvp --parameter-overrides \
  ...existing-params... \
  EnableEdgeProtection=true \
  WafRateLimitPer5Min=2000
```

Wait ~15 min for CloudFront to propagate. New output `CloudFrontUrl`
is the URL real callers should use.

### Tier 2: LLM narratives (variable cost — Bedrock tokens)

The paid-tier feature. Adds an LLM-generated explanation of the score.

You need:
- Bedrock model access enabled in the AWS console (https://console.aws.amazon.com/bedrock/home → Model catalog → Anthropic models → submit use-case form, first-time accounts only)
- A supported model ID

```bash
sam deploy --stack-name iam-jit-mvp --parameter-overrides \
  ...existing-params... \
  LLMBackend=bedrock \
  BedrockModelId=us.anthropic.claude-opus-4-7
```

**Cost lever**: also set `IAM_JIT_LLM_MAX_OUTPUT_TOKENS=256` to halve
Bedrock output spend with minimal narrative-quality impact. Without
this, an aggressive caller can burn ~$0.005 per request on Opus 4.7.

### Tier 3: Custom domain (~$15/yr domain + $0 ACM)

Replace `*.lambda-url.us-east-1.on.aws` with `api.yourcorp.com`.

1. Register the domain (Route 53 Domains: `aws route53domains register-domain`, or Namecheap / etc.)
2. Request ACM cert (DNS validation) for `api.yourcorp.com`
3. Either:
   - **With edge protection on**: add `AlternateDomainNames` + `EdgeCertificateArn` to the CloudFront distribution (not yet templated — manual console step or template extension)
   - **With ALB**: set `EnablePublicALB=true` + `AlbCertificateArn=<cert>` + VPC/subnet params (see template comments)

### Tier 4: Magic-link auth (SES setup, ~$0)

Required for the admin UI to function (currently the bootstrap admin
claim works via `make claim-bootstrap` even without SES).

```bash
# Verify your sender address in SES sandbox mode:
aws ses verify-email-identity --email-address YOUR_EMAIL@example.com

# Re-deploy with sender configured:
sam deploy --stack-name iam-jit-mvp --parameter-overrides \
  ...existing-params... \
  SesSenderAddress=YOUR_EMAIL@example.com
```

For multi-user sign-in (more than just the bootstrap admin), request
SES production access via support case to exit sandbox mode.

### Tier 5: Stripe billing (production-only, ~$0 base)

For commercial deploys with paying customers. Out of scope of this
SAM template — see `docs/PUBLISHING.md` § Billing for the Stripe-
webhook-Lambda flow (separate stack, separate function).

---

## Which params are MVP vs production?

Quick reference for `sam deploy --parameter-overrides`:

### Always required (3)
- `StateBucketName` — globally unique S3 name
- `AdminBootstrapEmail` — your email
- `BootstrapSetupKey` — `openssl rand -hex 32`

### Required when `AllowPublicNetworkExposure=true` (for public deploys)
- `AllowedSourceCidrs` — `0.0.0.0/0` for explicit fully-public, or a CIDR list
- `CorsAllowedOrigins` — at least one explicit origin, never `*`

### MVP-skippable (sensible defaults)
- `LLMBackend=none` — deterministic-only is fully functional
- `AuthMode=local` — magic-link auth (needs SES); `aws_iam` is the alternative
- `UserConfigSource=dynamodb` — the table-backed user store
- `LogRetentionDays=545` — compliance-safe; do not lower below 365 if SOC 2 / PCI matters
- All `*TableName` defaults — `iam-jit-*` pattern is fine
- `TokenInactivityDays=180` — API token expiry

### Production-grade additions (off by default, opt in)
- `EnableEdgeProtection=true` — CloudFront + WAF (Tier 1 above)
- `EnablePublicALB=true` — ALB instead of Function URL (for SCP-restricted orgs)
- `LLMBackend=bedrock` + `BedrockModelId=...` — paid-tier LLM
- `WebhookSigningSecret` — only if you're consuming webhooks
- `AlbCertificateArn`, `AlbVpcId`, `AlbSubnetIds`, `AlbIngressCidr` — required if `EnablePublicALB=true`

### Customization (rarely changed)
- `ProvisionerRoleArns`, `DiscoveryRoleArns` — destination-account cross-account roles
- `AdditionalSensitiveServices`, `AdditionalHighImpactActions` — extend the scorer's risk model for your org

---

## "Is my deploy production-ready?" checklist

Run through this before pointing public traffic at the URL:

- [ ] `EnableEdgeProtection=true` set (real rate limit at the edge, not just per-Lambda-instance)
- [ ] `WafRateLimitPer5Min` tuned for your expected traffic (default 2000)
- [ ] CloudWatch alarm `${stack-name}-waf-blocked-requests` wired to SNS / pager
- [ ] AWS Budget alarm set on the account (Billing → Budgets → forecast > $50)
- [ ] `IAM_JIT_LLM_MAX_OUTPUT_TOKENS=256` env var set if `LLMBackend=bedrock` (cost defense)
- [ ] `LogRetentionDays` ≥ 365 (PCI/SOC 2 minimum)
- [ ] AWS account verified (no day-0 service-eligibility gates blocking Route 53 / Bedrock — see `docs/AWS-VERIFICATION.md` if you hit those)
- [ ] Custom domain + ACM cert wired (Tier 3)
- [ ] SES production access requested (so magic-link works for non-bootstrap users)
- [ ] Stripe billing wired if commercial (Tier 5)
- [ ] At least one secondary admin added to the users table (don't single-point-of-failure on the bootstrap admin)

---

## Common bootstrap gotchas

**`sam build` fails with "container runtime"** — Docker daemon not
running, or you're on a Mac with colima and need
`DOCKER_HOST=unix:///Users/$USER/.colima/default/docker.sock` set
before `sam build`.

**Deploy fails immediately with "We can't finish registering"** —
new AWS account hasn't cleared verification yet. This affects Route 53
domain registration, Bedrock model access, and public Lambda Function
URLs. Open an "Account and billing → Account verification" support
case; usually clears within 24 hours. Until then, deploy works fine
within the SAM stack (Lambda + DynamoDB + S3 are not gated), but
public-internet traffic to the Function URL may 403 and Bedrock
invocations get `Operation not allowed`.

**Function URL returns 403 even with `AllowPublicNetworkExposure=true`** —
new-account verification gate (see above). Confirm by direct
invocation: `aws lambda invoke --function-name iam-jit
--payload '...' /tmp/out.json` should work, while the public URL
won't — proves the Lambda is alive and only the public surface is
gated.

**"Bedrock returned ValidationException: Operation not allowed"** —
Anthropic-models-on-Bedrock first-time use needs a use-case form
submission (no longer the old "Model access" page). Console:
https://us-east-1.console.aws.amazon.com/bedrock/home#/model-catalog
→ pick the model → "Submit use case details".

**Tests fail after `pip install -e .`** — make sure you used
`python3.12` specifically (the SAM build needs 3.12 too) and that
you're inside the venv (`source .venv/bin/activate`).

**`pip install -e .` fails with `error: Multiple top-level packages
discovered` / `Backend subprocess exited` / `Cannot install editable
project ... no setup.py`** — your pip is too old. PEP 660 editable
installs need pip >= 22.3 (`build_editable` hook); stock `ubuntu:22.04`
ships pip 22.0.2, and venv-created environments inherit whatever pip
the system Python had. Fix: `.venv/bin/pip install --upgrade pip`, then
re-run `pip install -e .` (closes #548 from UAT L1 2026-05-24).
