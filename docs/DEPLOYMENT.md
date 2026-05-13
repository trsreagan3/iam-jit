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

## Tearing down

```bash
sam delete --stack-name iam-jit --profile <hub-account>
# Then for each destination:
aws cloudformation delete-stack --stack-name iam-jit-roles --profile <destination>
```

The state bucket has versioning, so deleting it requires `aws s3 rm s3://iam-jit-state-<random> --recursive --include-versions` first if you want a clean tear-down.
