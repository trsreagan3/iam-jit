# Deploying iam-jit

End-to-end walkthrough for deploying iam-jit into your AWS organization. If you're using Claude Code or another AI assistant to drive this, point it at [`AGENT-DEPLOYMENT-PROMPT.md`](./AGENT-DEPLOYMENT-PROMPT.md) — it's structured so the agent can ask you the right questions and run the right commands at each step.

## Architecture in one diagram

```
┌─────────────────────────────────────────────────────────────┐
│ Hub account (any one AWS account you control)               │
│                                                             │
│  SAM stack: iam-jit                                         │
│  ├─ IAMJitFunction       single Lambda, dispatched by event │
│  │                        source: HTTP API + MCP-over-HTTP, │
│  │                        plus scheduled expiry sweep       │
│  │                        (every 15 min via EventBridge)    │
│  ├─ StateBucket          request YAML files (versioned)     │
│  ├─ ApiTokensTable       per-user API tokens                │
│  └─ ApiLambdaRole        sts:AssumeRole into destinations   │
└─────────────────────────────┬───────────────────────────────┘
                              │ sts:AssumeRole
        ┌─────────────────────┼──────────────────────────┐
        ▼                     ▼                          ▼
┌────────────────┐    ┌────────────────┐         ┌────────────────┐
│ Destination 1  │    │ Destination 2  │   ...   │ Destination N  │
│                │    │                │         │                │
│ CloudFormation │    │ CloudFormation │         │ CloudFormation │
│ ├ Provisioner  │    │ ├ Provisioner  │         │ ├ Provisioner  │
│ │  Role        │    │ │  Role        │         │ │  Role        │
│ └ Discovery    │    │ └ Discovery    │         │ └ Discovery    │
│   Role (opt)   │    │   Role (opt)   │         │   Role (opt)   │
└────────────────┘    └────────────────┘         └────────────────┘
```

## Prerequisites

- An AWS account you'll designate as the **hub** (where the Lambda runs).
- One or more AWS accounts you'll designate as **destinations** (where grants get provisioned).
- AWS CLI v2 + appropriate profiles for each.
- AWS SAM CLI (`brew install aws-sam-cli` or `pipx install aws-sam-cli`).
- `cfn-lint` for local validation (`pip install cfn-lint`).
- Decision: **classic IAM roles** vs **AWS Identity Center permission sets** as your provisioning model. iam-jit supports both (and `both` simultaneously per-account).

## Step 1 — pick the hub account and bootstrap S3 for SAM

SAM needs a deployment bucket in the hub account.

```bash
aws s3 mb s3://iam-jit-sam-deploys-<random> --profile <hub-account>
```

Note that bucket name; you'll pass it to `sam deploy` as `--s3-bucket`.

## Step 2 — deploy the SAM stack in the hub account

From the repo root:

```bash
sam build --template infrastructure/sam/template.yaml

sam deploy \
  --template-file infrastructure/sam/template.yaml \
  --stack-name iam-jit \
  --s3-bucket iam-jit-sam-deploys-<random> \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      StateBucketName=iam-jit-state-<random> \
      LLMBackend=none \
  --profile <hub-account>
```

(`ProvisionerRoleArns` and `DiscoveryRoleArns` keep their placeholder defaults during the initial deploy; we fill them in at Step 4 once the destination stacks exist.)

Initial deploy uses placeholder ARNs for `ProvisionerRoleArns` / `DiscoveryRoleArns` and `LLMBackend=none`. We'll fill these in once we've deployed the destination CloudFormation stacks and decided on an LLM tier.

Capture the outputs:

```bash
aws cloudformation describe-stacks \
  --stack-name iam-jit \
  --query "Stacks[0].Outputs" \
  --profile <hub-account>
```

Note the value of `ApiLambdaRoleName` — you'll pass this to every destination stack as `HubLambdaRoleName`.

## Step 3 — deploy the destination CloudFormation in each destination account

For **each** destination account:

```bash
aws cloudformation deploy \
  --template-file infrastructure/cloudformation/destination-account-roles.yaml \
  --stack-name iam-jit-roles \
  --parameter-overrides \
      HubAccountId=<hub-account-id> \
      HubLambdaRoleName=iam-jit-lambda-execution \
      EnableDiscovery=Yes \
      ProvisioningMode=classic_iam \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1 \
  --profile <destination-account>
```

Capture each stack's outputs (ProvisionerRoleArn, ProvisionerExternalId, DiscoveryRoleArn, DiscoveryExternalId).

For organizations with many destinations, deploy via [StackSets](../infrastructure/cloudformation/README.md#multi-account-roll-out-via-stacksets) instead.

## Step 4 — re-deploy the hub SAM with the destination ARNs

Now that the destination roles exist, redeploy the hub stack to grant `sts:AssumeRole` on them. Concatenate the ProvisionerRoleArn outputs from each destination stack:

```bash
sam deploy \
  --template-file infrastructure/sam/template.yaml \
  --stack-name iam-jit \
  --parameter-overrides \
      StateBucketName=iam-jit-state-<random> \
      ProvisionerRoleArns=arn:aws:iam::222222222222:role/iam-jit-provisioner,arn:aws:iam::333333333333:role/iam-jit-provisioner \
      DiscoveryRoleArns=arn:aws:iam::222222222222:role/iam-jit-discovery,arn:aws:iam::333333333333:role/iam-jit-discovery \
  --capabilities CAPABILITY_NAMED_IAM \
  --profile <hub-account>
```

The `iam-jit-lambda-execution` role now has `sts:AssumeRole` on each listed ARN — and only those.

## Step 4.5 — pick an auth mode

iam-jit doesn't trust network reachability for authorization — every endpoint requires identity. Two modes:

**`local`** — DynamoDB-backed user database, magic-link login via SES. Best for small teams (~5–500 users) where you want to manage the user list directly.

```
sam deploy ... \
  --parameter-overrides \
      AuthMode=local \
      MagicLinkSecret=$(openssl rand -hex 32) \
      SesSenderAddress=noreply@your-domain.com \
      ...
```

You'll need to verify `noreply@your-domain.com` in SES first (or use a verified domain). Phase 1b includes the bootstrap flow for the first admin user.

**`aws_iam`** — Function URL with `AuthType: AWS_IAM`; callers SigV4-sign requests with their AWS credentials. A DynamoDB table maps IAM principal ARN → iam-jit role. Best for orgs already on AWS Identity Center.

```
sam deploy ... \
  --parameter-overrides \
      AuthMode=aws_iam \
      ...
```

After deploy, populate the UsersTable with the principal ARNs you want to grant access to:

```bash
aws dynamodb put-item \
  --table-name iam-jit-users \
  --item '{
    "user_id": {"S": "iam:arn:aws:iam::111111111111:role/AWSReservedSSO_DevOps_xxx"},
    "roles": {"SS": ["approver"]}
  }' \
  --profile <hub-account>
```

The full list of supported principal ARN shapes (IAM users, IAM roles, Identity Center sessions) is in [PERMISSIONS-MODEL.md](./PERMISSIONS-MODEL.md#two-auth-modes).

## Step 5 — pick an LLM tier and configure it

**Recommendation: use Bedrock with Claude Sonnet 4.6.** It handles the
multi-rule prompt + org-context grounding cleanly, costs roughly $0.013
per intake turn (~$10-50/month at typical volume), runs inside your AWS
account, and adds zero hosting overhead. Haiku 4.5 is a reasonable
budget alternative (~3x cheaper, similar quality to a self-hosted 8B
model) — flip `BedrockModelId` to swap.

| Tier | Backend | When to use | Notes |
|---|---|---|---|
| 0 | `none` | air-gapped or evaluation-only deployments | paste mode works fully; chat surface is hidden |
| **2 (recommended)** | **`bedrock` with Claude Sonnet 4.6** | **production default** | re-deploy with `LLMBackend=bedrock`, `BedrockModelId=anthropic.claude-sonnet-4-6-20251001-v1:0` |
| 2 (budget) | `bedrock` with Claude Haiku 4.5 | high-volume, cost-sensitive | `BedrockModelId=anthropic.claude-haiku-4-5-20251001-v1:0` |
| 2 (alt) | `anthropic` (direct) | when you have an existing API key and don't want Bedrock | API key in Secrets Manager → `AnthropicApiKeySecret=arn:...` |
| 1 | `ollama` | self-hosted requirements (regulatory, air-gap variants) | run Ollama in ECS/EKS, point `OllamaHost=http://...` at it. Use `qwen2.5:14b` (or larger) — `llama3.1:8b` struggles with the multi-rule prompt; see [TESTING.md](./TESTING.md#tier-25--llm-behavioral-tests-opt-in-three-sub-modes) for the comparison data |

**Cost comparison at typical volume** (~50 intake turns/day):

| Backend | ~$/month |
|---|---|
| Bedrock Sonnet 4.6 | ~$20 |
| Bedrock Haiku 4.5 | ~$7 |
| Self-hosted llama3.1:8b on EC2 Spot | ~$44 |
| Self-hosted llama3.1:8b on Fargate 24/7 | ~$170 |

Bedrock crosses over self-hosted around 100+ requests/day; below that
it's both cheaper *and* better-quality.

For self-hosted Ollama, see [the LLM hosting Terraform modules](../infrastructure/terraform/) (ships in a follow-up phase) or run Ollama in your own ECS/EKS cluster.

## Step 5.5 — cost ownership for self-hosted deployments

**When you self-host iam-jit, every cost lands on YOUR AWS bill —
not on iam-jit (the company).** This is by design and is structurally
enforced by the deployment shape:

- The Lambda runs in your account → Lambda costs on your bill
- DynamoDB tables are in your account → DDB costs on your bill
- Bedrock calls use the Lambda's local execution role → **Bedrock
  costs billed to your AWS account directly**
- Anthropic-API calls (if you chose `LLMBackend=anthropic`) use the
  API key in *your* Secrets Manager secret → billed to your
  Anthropic account
- iam-jit phones home for nothing — no telemetry, no usage reports,
  no licensing call-back. You can deploy in a sealed account with
  no egress to anything outside AWS APIs

The `IAM_JIT_LLM_BUDGET_*` per-tier monthly call caps that exist in
the code default to multi-tenant SaaS values (Pro=1500/mo,
Team=2500/mo). For a single-tenant self-hosted deployment, those
defaults are typically too low — they exist to protect iam-jit's
hosted-SaaS wallet from a single noisy customer, not yours from
yourself. **For self-hosted, either raise the caps far above your
expected volume, or disable them and use AWS Budgets as your
real spending control:**

```bash
# Disable the per-tier LLM call caps (recommend AWS Budgets for spend
# control instead — see CDK snippet below).
sam deploy ... --parameter-overrides \
    LLMBackend=bedrock \
    BedrockModelId=anthropic.claude-sonnet-4-6-20251001-v1:0 \
    LLMBudgetPro=unlimited \
    LLMBudgetTeam=unlimited \
    LLMBudgetEnterprise=unlimited
```

Accepted values for the `LLMBudget*` parameters: `unlimited`,
`none`, `-1`, or any positive integer (monthly call cap).

### AWS Budget alarm (recommended)

Add an account-level Budget alarm scoped to Bedrock so AWS notifies
you before you spend more than expected:

```yaml
# Append to your SAM template OR deploy as a separate stack.
BedrockBudgetAlarm:
  Type: AWS::Budgets::Budget
  Properties:
    Budget:
      BudgetName: iam-jit-bedrock-monthly
      BudgetType: COST
      TimeUnit: MONTHLY
      BudgetLimit:
        Amount: 100        # adjust to your expected monthly spend
        Unit: USD
      CostFilters:
        Service:
          - "Amazon Bedrock"
    NotificationsWithSubscribers:
      - Notification:
          NotificationType: ACTUAL
          ComparisonOperator: GREATER_THAN
          Threshold: 80     # alert at 80% of budget
        Subscribers:
          - SubscriptionType: EMAIL
            Address: !Ref BudgetAlertEmail
      - Notification:
          NotificationType: FORECASTED
          ComparisonOperator: GREATER_THAN
          Threshold: 100    # alert if forecast exceeds 100%
        Subscribers:
          - SubscriptionType: EMAIL
            Address: !Ref BudgetAlertEmail
```

Sized starting points (Bedrock Sonnet 4.6, no caps):

| Volume                | Approx monthly Bedrock spend |
|-----------------------|------------------------------|
| 50 grants/day         | ~$20                         |
| 200 grants/day        | ~$80                         |
| 1,000 grants/day      | ~$400                        |
| 5,000 grants/day      | ~$2,000                      |

Multiply by ~5x for Opus, divide by ~3x for Haiku.

### Bedrock model access — your customer-side prerequisite

Before iam-jit's Bedrock backend will work in your account, you
must enable Anthropic model access in the Bedrock console for the
deployment region. AWS gates this per-account via a one-time
verification (typically a short questionnaire about intended use).

1. Open the Bedrock console in your deployment region
2. Go to **Model access**
3. Request access for the Anthropic Claude models you'll use
4. Wait for approval (usually under 30 minutes; sometimes a day)

You only do this once per account / region. iam-jit can't do this
on your behalf — Bedrock model access is account-scoped, and the
verification is binding to your AWS account holder's terms with
Anthropic.

### What this means for pricing if you eventually subscribe to a paid tier

If you self-host iam-jit Pro/Team/Enterprise (paid tiers), the
subscription covers the **software license + support**, not the
infrastructure cost. Standard enterprise self-host model (same
shape as GitLab Self-Managed, Sentry Self-Hosted, Mattermost, etc.).
You continue to pay AWS / Anthropic directly for the runtime; you
pay iam-jit (the company) for the right to use the paid-tier
features and for support/SLA.

This separation of cost ownership is captured in the
[[self-host-zero-billing-dependency]] memo and is a deliberate
architectural choice.

## Step 5.6 — Pilot deployment profile (design-partner / first-customer)

If you are evaluating iam-jit as a design partner — full
Enterprise-tier feature set on, but with hard cost ceilings so the
trial cannot accidentally generate substantial Bedrock spend — use
this parameter set. It's intentionally conservative on cost while
leaving every feature exercisable.

### What this profile does

- Enables Enterprise-tier features (task-description analysis,
  audit report export, custom intent types) so the customer can
  test the full surface.
- Picks Sonnet — not Opus — as the LLM backend for all tiers.
  Sonnet is ~5× cheaper, handles the scoring + narrative prompts
  cleanly, and is the right cost/quality point for a pilot.
- Sets a per-tier monthly LLM-call cap that is generous for
  pilot-scale traffic (a 20-engineer team running 5-10 grants per
  engineer per day) but tight enough to surface runaway usage
  before the bill is large.
- Disables LLM use entirely for any grant whose deterministic
  score is already high-confidence (≥0.7 or ≤0.2), so the LLM
  budget gets spent on the borderline cases where it actually
  helps.
- Provisions an AWS Budget alarm scoped to Bedrock at $50 / $200
  / $500 monthly thresholds.

### Parameter overrides

```bash
sam deploy \
  --template-file infrastructure/sam/template.yaml \
  --stack-name iam-jit-pilot \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      Tier=enterprise \
      LLMBackend=bedrock \
      BedrockModelId=anthropic.claude-sonnet-4-6-20251001-v1:0 \
      BedrockModelIdEnterpriseOverride=anthropic.claude-sonnet-4-6-20251001-v1:0 \
      LLMBudgetPro=5000 \
      LLMBudgetTeam=5000 \
      LLMBudgetEnterprise=10000 \
      LLMSkipBelowConfidence=0.2 \
      LLMSkipAboveConfidence=0.7 \
      EnableEnterpriseFeatures=true \
      EnableTaskDescriptionAnalysis=true \
      EnableAuditReportExport=true \
      EnableRoleDiscovery=true \
      ReservedConcurrentExecutions=10 \
      ProvisionedConcurrency=2 \
  --profile <hub-account>
```

`BedrockModelIdEnterpriseOverride` is deliberately set to Sonnet
(not Opus) for the pilot — the launch-default has Enterprise on
Opus per [[launch-infra-vs-pricing-audit]], but a pilot doesn't
need Opus's marginal quality improvement and Opus is ~5× the cost.
Flip this to `anthropic.claude-opus-4-7-20251015-v1:0` after the
pilot validates volume and you've sized the steady-state spend.

### AWS Budget alarms (CloudFormation stack)

Deploy this alongside the iam-jit stack — same hub account.
Substitute your alerting email.

```yaml
Resources:
  IAMJitBedrockBudget:
    Type: AWS::Budgets::Budget
    Properties:
      Budget:
        BudgetName: iam-jit-pilot-bedrock
        BudgetType: COST
        TimeUnit: MONTHLY
        BudgetLimit:
          Amount: 500
          Unit: USD
        CostFilters:
          Service:
            - "Amazon Bedrock"
      NotificationsWithSubscribers:
        - Notification:
            NotificationType: ACTUAL
            ComparisonOperator: GREATER_THAN
            Threshold: 10        # $50 — early signal
          Subscribers:
            - SubscriptionType: EMAIL
              Address: !Ref AlertEmail
        - Notification:
            NotificationType: ACTUAL
            ComparisonOperator: GREATER_THAN
            Threshold: 40        # $200 — mid alarm
          Subscribers:
            - SubscriptionType: EMAIL
              Address: !Ref AlertEmail
        - Notification:
            NotificationType: FORECASTED
            ComparisonOperator: GREATER_THAN
            Threshold: 100       # $500 — projection alarm
          Subscribers:
            - SubscriptionType: EMAIL
              Address: !Ref AlertEmail
```

### What a pilot's monthly Bedrock spend looks like (sanity check)

Sonnet 4.6 pricing (2026): ~$3/M input, ~$15/M output. A typical
intake turn is ~5K input + ~1K output tokens ≈ $0.030. So:

| Pilot volume                           | Approx Bedrock spend per month |
| -------------------------------------- | ------------------------------ |
| 20 engineers × 5 grants/day, all use LLM | ~$90                           |
| 20 engineers × 10 grants/day, all use LLM | ~$180                          |
| 100 engineers × 10 grants/day, all use LLM | ~$900                          |

With `LLMSkipBelowConfidence=0.2` + `LLMSkipAboveConfidence=0.7`
filtering out high-confidence requests (typically 50-70% of
traffic), the realistic spend at 20 × 5 grants/day pilot scale is
**~$30-50/month** — well inside the $50 first-alarm threshold.

### Per-account LLM policy (Enterprise feature)

For customers with many accounts of varying sensitivity, the
deployment-wide LLM toggle is too coarse. iam-jit Enterprise
supports a per-account `llm_policy` field on the Account record
so the customer can surgically choose which accounts get LLM
narrative on grant scoring:

```yaml
# accounts.yaml (or DDB UpdateItem)
accounts:
  - account_id: "111111111111"
    alias: dev
    llm_policy: deterministic_only        # don't pay for LLM here
    llm_policy_reason: "high volume; LLM narrative not worth the spend"
  - account_id: "222222222222"
    alias: staging-non-pci
    llm_policy: deterministic_only
  - account_id: "222222222223"
    alias: staging-pci
    llm_policy: use_llm                   # PCI gets LLM regardless of env
  - account_id: "333333333333"
    alias: prod
    llm_policy: use_llm
  - account_id: "444444444444"
    alias: infra
    llm_policy: use_llm
  - account_id: "555555555555"
    alias: management
    llm_policy: use_llm
```

Decision order at score time (cheapest gate first):

1. **Account policy** — if `account.llm_policy` is set, honor it
2. **Deployment default** — `LLMDefaultPolicy=deterministic_only`
   (or `use_llm`) when account policy is unset
3. **Budget cap** — per-customer monthly LLM-call cap
4. **Confidence band** — skip LLM when deterministic score is
   already high-confidence (`LLMSkipBelowConfidence` /
   `LLMSkipAboveConfidence`)

The score response includes `llm_used` + `llm_skip_reason` so
approvers can see why a given grant did or didn't get LLM
narrative.

This is typically the LARGEST cost-control lever at Enterprise
scale — a customer with 60 dev accounts + 5 prod accounts can cut
LLM spend ~10× by setting `deterministic_only` on dev while
keeping `use_llm` on prod where the narrative actually helps
approvers.

### Pilot cost controls iam-jit enforces automatically

The defaults below ship in code; the parameter overrides above
just expose them at deploy time so the pilot operator can tune
them without redeploying:

| Control                                  | Default for pilot profile | Behavior when exceeded |
| ---------------------------------------- | ------------------------- | ---------------------- |
| Monthly LLM-call cap per tier            | 5,000 (Pro/Team), 10,000 (Enterprise) | Falls back to deterministic-only scoring; logs a `LLM_BUDGET_EXCEEDED` event |
| Per-request LLM token cap                | 4,096 output tokens       | Truncates the response; flagged in audit log |
| Bedrock model whitelist                  | Sonnet only               | Other model IDs rejected at boot — prevents accidental Opus usage |
| AWS Budget alarm (operator-installed)    | $50 / $200 / $500         | Notification only — does not block (iam-jit cannot enforce AWS-side billing) |

### Recommended pilot success metrics

Collect these during the pilot so the post-trial readout is concrete:

- **Time-to-grant** (request submitted → credentials issued)
- **Auto-approve rate** (grants below threshold / total grants)
- **Approver burden** (admin Slack interactions per business day)
- **Bedrock spend per business day** (from the AWS Budget metric)
- **Blast-radius reduction** (average grant TTL vs prior 8-hour
  Hoop session)
- **False-positive auto-approvals** (grants that, on retrospective
  audit, should have routed to approval)

The last metric is the calibration signal — feeds the scoring
adversarial loop ([[adversarial-loop-process]]).

## Step 6 — verify cross-account assume-role

From the hub account, simulate the assume-role chain:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::<destination-account>:role/iam-jit-provisioner \
  --role-session-name test \
  --external-id iam-jit-<destination-account> \
  --profile <hub-account>
```

A successful response means the trust path is correct. If you get `AccessDenied`, double-check `HubLambdaRoleName` matches the actual role name in the hub stack and that you used the right `external-id`.

## Step 7 — create a first user API token

Once Phase 1b's API is built (the `/api/v1/tokens` endpoint), run:

```bash
curl -X POST https://<api-function-url>/api/v1/tokens \
  -H "Authorization: Bearer <bootstrap-secret>" \
  -d '{"user_email": "you@example.com"}'
```

The response includes the API token and a sample MCP server config block to drop into `~/.claude/claude_desktop_config.json` or your editor's MCP config.

## Step 8 — submit a test request

Two ways:

**Via the MCP server (in Claude Code):**

```
"Submit a test iam-jit role request that needs read access to the
 'example-config' S3 bucket in account 555555555555 for 24 hours."
```

The agent calls `submit_role_request`, the response includes the request ID and risk score.

**Via curl:**

```bash
curl -X POST https://<api-function-url>/api/v1/requests \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d @examples/example-request.yaml.json
```

## Step 9 — approve / verify provisioning

In the UI (`https://<api-function-url>/queue`) or via the MCP `approve_request` tool. Once approved, the provisioning Lambda runs, and the role appears in the destination account tagged `managed-by: iam-jit`.

Verify:

```bash
aws iam get-role \
  --role-name iam-jit/<request-id> \
  --profile <destination-account>
```

## Step 10 — let expiry run

Wait until `not_after` passes (or set a short duration for testing). The expiry Lambda runs every 15 minutes; it'll destroy expired grants and archive the request to `library/`.

## Common pitfalls

| Symptom | Likely cause |
|---|---|
| `AccessDenied` on assume-role from the hub | `HubLambdaRoleName` mismatch, or wrong `external-id` |
| `iam:CreateRole` denied | Request didn't include `managed-by: iam-jit` tag, or path isn't `/iam-jit/*` — check the ProvisionerRole policy |
| LLM backend silently disabled | `LLMBackend` env var not set; check Lambda env in console |
| Expiry never runs | EventBridge schedule disabled on `IAMJitFunction`; `aws lambda list-event-source-mappings` or check the SAM-generated rule |
| Function URL returns 503 | Phase 1.6 stub — Phase 2 fills in the real handler |

## Docker (ibounce local proxy)

Convenience image for running the **ibounce** local AWS-API proxy without installing Python on the host. Published to GHCR on every push to `main` and on every `v*` tag.

```bash
docker pull ghcr.io/trsreagan3/ibounce:latest

# Run with your host AWS credentials mounted in.
docker run --rm -it \
  -v "$HOME/.aws:/home/ibounce/.aws:ro" \
  -v "$HOME/.iam-jit:/home/ibounce/.iam-jit" \
  -e AWS_PROFILE=default \
  -p 127.0.0.1:8767:8767 \
  ghcr.io/trsreagan3/ibounce:latest \
    run --host 0.0.0.0 --port 8767 --i-know-this-binds-externally
```

Then point your AWS SDK at it:

```bash
export AWS_ENDPOINT_URL=http://127.0.0.1:8767
aws sts get-caller-identity   # flows through ibounce, gets logged + scored
```

**A few intentional things about this image:**

- It is a **packaging convenience**, not a different product. Same binary as `pip install iam-jit`, same opt-in `ibounce version-check`, no phone-home, no telemetry.
- The image does **not** include the AWS CLI. Mount `~/.aws` from the host so `AWS_PROFILE` / SSO sessions work.
- The audit DB lives at `~/.iam-jit/bouncer/state.db` inside the container. Mount `~/.iam-jit` from the host (as above) to persist your rules + decision log across `docker run` invocations.
- The container binds **loopback only by default** for the same security reasons the binary refuses external binds without an explicit acknowledgement flag. To make the proxy reachable from outside the container you need both `-p 127.0.0.1:8767:8767` (host → container port forward) *and* `--host 0.0.0.0 --i-know-this-binds-externally` (binary refuses external bind otherwise). The example above publishes only on the host loopback, which is the sane default.
- The image runs as a non-root user `ibounce` (UID 10001).

## Tearing down

```bash
sam delete --stack-name iam-jit --profile <hub-account>
# Then for each destination:
aws cloudformation delete-stack --stack-name iam-jit-roles --profile <destination>
```

The state bucket has versioning, so deleting it requires `aws s3 rm s3://iam-jit-state-<random> --recursive --include-versions` first if you want a clean tear-down.
