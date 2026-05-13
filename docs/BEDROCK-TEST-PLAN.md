# Bedrock LLM smoke test — `omise-experimental`, us-east-1

**Purpose:** verify that iam-jit's LLM-narrative path works end-to-end
when the Lambda is configured with `LLMBackend=bedrock`. Today the
deployed Lambda has only been exercised in `LLMBackend=none` mode;
this test closes that gap.

**Scheduled:** when the user (Reagan / `thomas.s@opn.ooo`) is
available to monitor — explicitly NOT to be run unsupervised.

**Hard constraints:**

  - Use the **existing** Bedrock setup in `omise-experimental`. No
    model-access changes, no provisioned throughput, no shared keys.
  - Test connectivity + one minimal invocation. Do **not** put the
    model under load.
  - Tear down the test stack at the end of the session.

## Connectivity confirmed (2026-05-12)

A bare connectivity test was already run against this profile:

```
$ aws bedrock-runtime converse \
    --profile omise-experimental --region us-east-1 \
    --model-id us.anthropic.claude-opus-4-7 \
    --messages '[{"role":"user","content":[{"text":"Reply with the single word: pong"}]}]' \
    --inference-config '{"maxTokens":20}'

{ "output": "pong", "stopReason": "end_turn",
  "usage": {"inputTokens": 21, "outputTokens": 6, "totalTokens": 27} }
```

The model responded successfully on the FIRST try from the user's
SSO admin role. Model access is enabled; no setup needed.

**One code fix landed at the same time:** Opus 4.7 has deprecated
the `temperature` parameter (returns ValidationException). The
iam-jit Bedrock backend in `src/iam_jit/llm.py` was passing
`temperature: 0.0` on lines 316 and 336 — both removed in the same
session. Without this fix, the smoke test would have failed.

## Pre-flight (already verified — safe to proceed)

The state of `omise-experimental` Bedrock as of test-plan write time:

| Property | Value | Risk to running env |
|---|---|---|
| Provisioned throughputs in region | **None** (`aws bedrock list-provisioned-model-throughputs` → empty) | Zero. No shared paid capacity to consume. |
| Recent InvokeModel events (90d) | All from `thomas.s@opn.ooo`, none more recent than 2026-03-31 | Zero. No other workload would notice us. |
| Newest Opus inference profile | `us.anthropic.claude-opus-4-7` (status: ACTIVE, type: SYSTEM_DEFINED) | Standard on-demand. No reservation = no shared paid capacity. |
| Bedrock model access already enabled | Implicit (the SYSTEM_DEFINED profile is listed for this account) | We're using what's already turned on; we don't request access we don't have. |
| Lambda IAM grant for Bedrock | `bedrock-invoke` policy in `~/repos/iam-roles/infrastructure/sam/template.yaml` line 970+ already grants `bedrock:InvokeModel` + `bedrock:Converse` on `*` — fires only when `UsesBedrock` (LLMBackend=bedrock) | Scoped to OUR test Lambda's role; no other principal gets the grant. |

**The model we'll call:** `us.anthropic.claude-opus-4-7` (newest Opus
inference profile in this account / region, as confirmed by
`aws bedrock list-inference-profiles`).

## Why this is safe

The test creates exactly **one** new IAM role (the iam-jit Lambda
execution role) and **one** new Lambda function. Everything else in
the account is untouched:

1. **No shared key invalidation.** AWS Bedrock does not use API
   keys — auth is per-call IAM. Our Lambda has its own role; we
   don't touch anyone else's role.
2. **No shared resource modification.** The inference profile
   `us.anthropic.claude-opus-4-7` is read-only to us (it's
   SYSTEM_DEFINED, AWS-managed). We can't accidentally change it.
3. **No model-access toggle.** Bedrock model access is configured
   at the account level. We use what's already enabled. Listing
   the profiles confirmed it is.
4. **No quota impact.** On-demand pricing on a system-defined
   inference profile draws from the regional pool. A single
   request consumes ~hundreds of tokens, well below any meaningful
   throttle threshold (Bedrock's per-account default TPM is in the
   tens of thousands for Opus models). Anyone else using Bedrock
   in this account would not notice us. There are no anyone-elses
   right now (per CloudTrail).
5. **Bounded blast radius.** The test stack is named
   `iam-jit-test-r4` (or whichever suffix we pick). Anything that
   goes wrong is contained to that stack. Tearing it down with
   `aws cloudformation delete-stack --stack-name iam-jit-test-r4`
   removes everything we created. The persistent DDB tables and
   S3 bucket are intentionally retained but contain only test data.

## Test sequence (~15 min total, supervised)

### Step 1 — Build + deploy with `LLMBackend=bedrock`

```bash
make -C ~/repos/iam-roles sam-build
sam package \
  --template-file ~/repos/iam-roles/.aws-sam/build/template.yaml \
  --output-template-file ~/repos/iam-roles/.aws-sam/build/packaged.yaml \
  --resolve-s3 \
  --profile omise-experimental --region us-east-1

# Use a fresh suffix to avoid retained-table collisions.
# (The retained tables from earlier runs are NOT touched.)
SUFFIX="r4"

sam deploy \
  --template-file ~/repos/iam-roles/.aws-sam/build/packaged.yaml \
  --stack-name iam-jit-test-${SUFFIX} \
  --profile omise-experimental --region us-east-1 \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --no-confirm-changeset --no-fail-on-empty-changeset --resolve-s3 \
  --parameter-overrides \
    "ApiTokensTableName=iam-jit-test-${SUFFIX}-api-tokens" \
    "UsersTableName=iam-jit-test-${SUFFIX}-users" \
    "SettingsTableName=iam-jit-test-${SUFFIX}-settings" \
    "CidrsTableName=iam-jit-test-${SUFFIX}-cidrs" \
    "AccountsTableName=iam-jit-test-${SUFFIX}-accounts" \
    "StateBucketName=iam-jit-state-omise-experimental-test-${SUFFIX}-$(openssl rand -hex 4)" \
    "AdminBootstrapEmail=trsreagan3@gmail.com" \
    "BootstrapSetupKey=$(openssl rand -hex 32)" \
    "MagicLinkSecret=$(openssl rand -hex 32)" \
    "AllowPublicNetworkExposure=true" \
    "AllowedSourceCidrs=0.0.0.0/0" \
    "CorsAllowedOrigins=http://localhost:3000" \
    "EnablePublicALB=true" \
    "AlbVpcId=vpc-900522ea" \
    "AlbSubnetIds=subnet-9a5445b4,subnet-584e9515,subnet-6bb1a537" \
    "AlbIngressCidr=0.0.0.0/0" \
    "LLMBackend=bedrock" \
    "BedrockModelId=us.anthropic.claude-opus-4-7"
```

`BedrockModelId` is the inference profile ID (with the `us.`
prefix). This is what `bedrock-runtime:Converse` expects.

### Step 2 — Confirm Lambda can reach Bedrock (cold connectivity test)

Before any iam-jit-specific test, confirm the Lambda's IAM grant
actually works:

```bash
ALB=$(aws cloudformation describe-stacks --stack-name iam-jit-test-r4 \
  --profile omise-experimental --region us-east-1 \
  --query "Stacks[0].Outputs[?OutputKey=='PublicBaseUrl'].OutputValue" --output text)

curl -sS "${ALB}/healthz"
```

Expected: HTTP 200 with `"llm_backend":"bedrock"` in the response.
That alone proves the Lambda boots with the Bedrock config.

### Step 3 — Submit a single test request (the actual Bedrock call)

```bash
# Bootstrap admin first.
curl -sS -c /tmp/iam-jit-bedrock-test-cookies.txt -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=trsreagan3@gmail.com&key=${BOOTSTRAP_SETUP_KEY_FROM_STEP_1}" \
  "${ALB}/setup"

# ONE request only. Read-only, low risk — the LLM narrative should
# describe why it's low risk.
curl -sS -b /tmp/iam-jit-bedrock-test-cookies.txt -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "iam-jit.dev/v1alpha1",
    "kind": "RoleRequest",
    "metadata": {"requester": {"name": "Bedrock Test", "email": "trsreagan3@gmail.com"}},
    "spec": {
      "description": "List S3 buckets in the experimental account for the Bedrock smoke test",
      "access_type": "read-only",
      "duration": {"duration_hours": 1},
      "accounts": [{"account_id": "518710148615", "regions": ["us-east-1"]}],
      "policy": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": ["*"]}]
      },
      "provisioning": {"mode": "classic_iam"}
    }
  }' \
  "${ALB}/api/v1/requests"
```

This produces **one** Bedrock InvokeModel call. The response should
include:

- `review.risk_score` (deterministic; same value as the NoAI path
  gave before — confirms LLM cannot change the score)
- `review.llm_narrative` — a populated, non-empty string. **This
  is the success criterion** — its presence proves the Bedrock
  round-trip worked.
- `review.suggestions` — may include LLM-generated entries beyond
  the deterministic ones.

### Step 4 — Verify in CloudTrail that we made exactly N InvokeModel calls

```bash
aws cloudtrail lookup-events \
  --profile omise-experimental --region us-east-1 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=InvokeModel \
  --start-time "$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ)" \
  --query "Events[].[EventTime,Username]" --output table
```

Expected: only the events from the iam-jit Lambda role
(`iam-jit-lambda-execution`), counted in single digits. Any
unexpected entries would mean we lost control of the test scope —
which would require investigation but no rollback (nothing was
modified).

### Step 5 — Tear down

```bash
aws cloudformation delete-stack \
  --stack-name iam-jit-test-r4 \
  --profile omise-experimental --region us-east-1

aws cloudformation wait stack-delete-complete \
  --stack-name iam-jit-test-r4 \
  --profile omise-experimental --region us-east-1
```

Persistent stores survive (retained policy). No Bedrock cleanup
needed — we made no Bedrock configuration changes.

## Abort criteria (any one of these = stop immediately)

- `healthz` returns `"llm_backend":"none"` despite `LLMBackend=bedrock`
  parameter → template didn't pick up the parameter; investigate
  before invoking Bedrock.
- `bedrock:InvokeModel` returns `AccessDeniedException` → IAM grant
  not applied. Check Lambda role's policies before re-trying.
- `bedrock:InvokeModel` returns `ValidationException` /
  `ResourceNotFoundException` → model-access isn't actually
  enabled for this profile in this account. Stop. Do NOT request
  access (changes account state); document the gap.
- Any Lambda invocation takes >30s (Bedrock latency or throttle)
  → stop, investigate. Don't auto-retry.
- CloudTrail shows an InvokeModel event NOT from our Lambda role
  during the test window → unexpected. Stop, audit who/what made
  it; could be coincidental but worth pausing for.

## What this test does NOT verify (out of scope)

- Throughput behavior under load (we're intentionally one-shot).
- LLM-narrative quality across diverse policy shapes — that's the
  integration suite's job (`tests/integration/test_review_with_llm.py`).
- Failover behavior if Bedrock is down — separate concern.
- Cost optimization choices (prompt length, response truncation) —
  separate concern.

## After the test

If everything passes:

  - Note the LLM-narrative text seen in the response (it'll be the
    first Opus 4.7 narrative we've recorded against iam-jit).
  - Add a brief mention to `docs/EVOLVING-THE-SCORER.md` under
    "What's verified" that Bedrock-backed deployments work
    end-to-end with iam-jit's contract (score deterministic,
    narrative optional, no influence on the gate).
  - Update `ROADMAP.md` § "Validated as of v1 ship" with a Bedrock
    smoke entry.

If something fails:

  - Capture the full response + CloudTrail events + Lambda logs in
    a writeup for `docs/BEDROCK-TEST-FINDINGS.md`. No retry without
    user review.
