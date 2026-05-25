# Agent + iam-jit + Hoop: end-to-end examples

> **Rewritten 2026-05-25** to lead with the AssumeRole / IRSA pattern
> per Hoop's own [EKS quickstart](https://hoop.dev/docs/quickstart/cloud-services/kubernetes/kubernetes-eks)
> and [[create-not-assume-pattern]]. The previous draft of this doc
> led with a Secrets-Manager-rotated wrapper script; that pattern is
> kept as Pattern 2 (fallback) for Hoop deployments that don't have
> IRSA configured, but Pattern 1 (AssumeRole) is what the recipe
> recommends and what every scenario below uses by default.
>
> Scenarios showing how an AI agent (Claude Code, Cursor, etc.) uses
> iam-jit to get a scoped AWS role and then opens a Hoop session
> that assumes that role. **Zero changes to either iam-jit or Hoop**
> — the integration relies on Hoop's existing `EKS_ROLE_ARN`
> connection option and iam-jit's existing grant API. **No held
> credentials. No Secrets Manager dependency.**

## How the integration works (in 60 seconds)

Hoop's EKS quickstart configures connections to **assume an IAM
role at session-open** rather than hold static credentials. The
Hoop agent runs in EKS with an IRSA-attached service account (call
its role `RoleX`); each connection lists an `EKS_ROLE_ARN` env var
(call it `RoleY`). When a session opens, the Hoop agent does
`sts:AssumeRole(RoleY)` using `RoleX`'s identity.

iam-jit slots into that flow by **creating `RoleY` on demand**,
scoped to the requested task, with `RoleX` in its trust policy.
The agent never holds AWS credentials; the Hoop agent never holds
credentials beyond its IRSA-issued token; the only thing that
crosses the wire is a role ARN.

```
agent ──► iam-jit /api/v1/grant ──► role ARN (e.g. iam-jit/grant-rq-abc)
                                         │
                                         ▼
                          iam-jit creates role with:
                            trust:  { Principal: RoleX_ARN, Action: sts:AssumeRole }
                            inline: scoped task policy
                            TTL:    1h (iam-jit auto-deletes at expiry)
                                         │
                                         ▼
agent ──► hoop session open <connection-id> --env EKS_ROLE_ARN=<roleY>
                                         │
                                         ▼
       Hoop agent (RoleX/IRSA) ──► sts:AssumeRole(RoleY) ──► STS creds
                                         │
                                         ▼
              session-scoped, time-bound creds in the session env
```

**No iam-jit code changes. No Hoop fork. No plugin. No Secrets
Manager. No held credentials anywhere in the path** — the only
long-lived identity is Hoop's IRSA service-account token, and that
identity can only AssumeRole on roles iam-jit creates under
`role/iam-jit/*` (the iam-jit naming prefix).

This composes directly with [[create-not-assume-pattern]] — the
pattern where iam-jit CREATES roles in the customer account but
never holds credentials to use them, and the caller (here: Hoop
agent's IRSA identity) does the AssumeRole directly.

---

## Pattern 1 (RECOMMENDED): AssumeRole + IRSA

For any Hoop connection where the Hoop agent runs in EKS with IRSA
configured (the default for EKS deployments per Hoop's docs), use
this pattern. Zero held credentials anywhere.

### One-time setup per Hoop deployment

1. **Confirm Hoop agent is IRSA-attached.** Per Hoop's
   [EKS quickstart](https://hoop.dev/docs/quickstart/cloud-services/kubernetes/kubernetes-eks),
   the Hoop agent's K8s service account has an annotation:
   ```yaml
   eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/HoopAgentRole
   ```
   Record that ARN — that's `RoleX`. Every iam-jit-created role
   trusts this principal.

2. **Grant iam-jit permission to create scoped roles.** iam-jit's
   own AWS principal needs:
   ```json
   {
     "Effect": "Allow",
     "Action": [
       "iam:CreateRole",
       "iam:PutRolePolicy",
       "iam:DeleteRole",
       "iam:DeleteRolePolicy"
     ],
     "Resource": "arn:aws:iam::*:role/iam-jit/*",
     "Condition": {
       "StringEquals": {
         "iam:PermissionsBoundary":
           "arn:aws:iam::ACCT:policy/iam-jit-boundary"
       }
     }
   }
   ```
   The PermissionsBoundary condition is mandatory — every role
   iam-jit creates must attach the customer-controlled boundary
   per [[create-not-assume-pattern]].

3. **iam-jit does NOT need `sts:AssumeRole` on anything.** Per
   [[create-not-assume-pattern]] — iam-jit never holds credentials;
   the Hoop agent assumes the role directly.

That's it. No Secrets Manager secret to pre-provision, no per-
connection plumbing.

### Per-grant flow

When an agent requests a grant:

1. **Agent calls iam-jit `/api/v1/grant`** with the task intent
   (actions, resources, duration).
2. **iam-jit scores + creates `RoleY`** with:
   - Name: `iam-jit/grant-rq-<id>`
   - Trust policy: principal = `RoleX` (the Hoop agent's IRSA role)
   - Inline policy: the scored, scoped task policy
   - PermissionsBoundary: `iam-jit-boundary` (customer-controlled)
   - Tags: `iam-jit:grant-id=...`, `iam-jit:ttl-expires=...`
3. **iam-jit returns the role ARN** in the grant response —
   `role_arn` field; no `credentials` field.
4. **Agent (or operator) sets `EKS_ROLE_ARN` on the Hoop session**
   (either ad-hoc via `hoop connect ... --env EKS_ROLE_ARN=...`
   or via a Hoop connection update).
5. **Hoop opens the session.** The Hoop agent does
   `sts:AssumeRole(RoleY)` using its IRSA identity; injects the
   resulting STS triple into the session env.
6. **Session runs the task.** Every AWS call uses the scoped
   credentials.
7. **At TTL expiry**, iam-jit calls `iam:DeleteRole` on `RoleY`.
   Future AssumeRole attempts (by any principal, including Hoop)
   fail closed — the role no longer exists.

No credentials live anywhere outside of the active session. No
secret to rotate. No wrapper script. The grant API is the single
point of authorization.

---

## Scenario 1: agent debugs a payment failure (Pattern 1)

### Situation

An on-call engineer is investigating a customer payment that failed
silently. They ask their Claude Code session for help:

> "Help me debug payment 4521 — the customer says it didn't go through
> but our dashboard shows success."

### Agent steps

**1. Agent reads source to identify the data surface.**

```
$ rg "payment" --type rb -l | head
app/services/payment_service.rb
app/jobs/payment_webhook_job.rb
app/models/payment.rb
lib/payment_gateway_client.rb

# Agent inspects payment_service.rb and finds:
#   - DynamoDB table `payments` (read by id)
#   - S3 bucket `payment-events` (write per attempt; reads for replay)
#   - CloudWatch log group `/payments/svc` (correlates with payment_id)
```

The agent now knows the exact resources and minimum actions needed:

- `dynamodb:GetItem` on `arn:aws:dynamodb:ap-southeast-1:123456789012:table/payments`
- `s3:GetObject` on `arn:aws:s3:::payment-events/payment-4521*`
- `logs:FilterLogEvents` on `arn:aws:logs:ap-southeast-1:123456789012:log-group:/payments/svc:*`

**2. Agent submits a richly-parameterized intent to iam-jit.**

This is [[agent-context-primacy]] in action — the agent passes the
exact ARNs and actions it inferred from source, not just a vague
"I need payment debugging access."

```bash
curl -sS -X POST https://iam-jit.acme.internal/api/v1/grant \
  -H "Authorization: Bearer $IAMJIT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "intent": {
      "type": "freeform",
      "natural_language": "Investigate payment 4521 — read DynamoDB row, read S3 events, filter CloudWatch logs",
      "parameters": {
        "actions": [
          "dynamodb:GetItem",
          "s3:GetObject",
          "logs:FilterLogEvents",
          "logs:GetLogEvents"
        ],
        "resources": [
          "arn:aws:dynamodb:ap-southeast-1:123456789012:table/payments",
          "arn:aws:s3:::payment-events/payment-4521*",
          "arn:aws:logs:ap-southeast-1:123456789012:log-group:/payments/svc:*"
        ]
      }
    },
    "principal": {"kind": "human", "identifier": "alice@acme.com"},
    "duration_seconds": 3600,
    "caller": {"source": "mcp", "session_id": "claude-code-..." },
    "integration": {"kind": "hoop", "trust_principal": "arn:aws:iam::123456789012:role/HoopAgentRole"}
  }'
```

The `integration` field signals iam-jit to set the trust principal
on the created role to the Hoop agent's IRSA role (`RoleX`).

**3. iam-jit scores, auto-approves, and creates the role.**

```json
{
  "status": "success",
  "grant_id": "G-2026-05-15-abc123",
  "policy": { /* the scored least-privilege policy */ },
  "score": 0.18,
  "score_explanation": "Read-only with narrow ARN scoping. Below auto-approve threshold (0.5).",
  "role_arn": "arn:aws:iam::123456789012:role/iam-jit/grant-rq-abc123",
  "role_expires_at": 1747007200,
  "audit_id": "..."
}
```

Score is 0.18 — well below the 0.5 auto-approve threshold (read-only,
narrow resource ARNs, no IAM-modify actions). Role created. No
credentials are returned — iam-jit does not hold any.

**4. Agent opens the Hoop session with `EKS_ROLE_ARN` set.**

```bash
hoop connect payments-debug \
  --env EKS_ROLE_ARN=arn:aws:iam::123456789012:role/iam-jit/grant-rq-abc123
```

Or, if the Hoop connection `payments-debug` is configured to read
`EKS_ROLE_ARN` from a Hoop variable that the agent sets via Hoop's
API, the role ARN flows that way instead. Either path: the role ARN
is the only thing handed off.

**5. Hoop opens the session; agent does the AssumeRole.**

Hoop's agent (running as `RoleX` via IRSA) calls:
```
sts:AssumeRole(
  RoleArn=arn:aws:iam::123456789012:role/iam-jit/grant-rq-abc123,
  RoleSessionName=hoop-payments-debug-...,
  DurationSeconds=3600
)
```

STS issues a triple; Hoop injects `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` into the session env.

**6. Agent uses the session.**

The agent (still inside the engineer's Claude Code session) runs:

```bash
aws dynamodb get-item \
  --table-name payments \
  --key '{"id":{"S":"4521"}}'

aws logs filter-log-events \
  --log-group-name /payments/svc \
  --filter-pattern 'payment_id="4521"' \
  --start-time $(date -d '2 hours ago' +%s)000

aws s3 cp s3://payment-events/payment-4521-attempt-1.json - | jq .
```

Each command succeeds because the iam-jit-created role grants
exactly these actions on exactly these resources. The agent
correlates the data, finds the issue (rejected by upstream gateway,
not retried), and reports back.

**7. Cleanup.**

When the grant TTL expires (1 hour), iam-jit's sweeper:
- Calls `iam:DeleteRole` on `arn:aws:iam::123456789012:role/iam-jit/grant-rq-abc123`
- Marks the grant as expired in audit
- Any new Hoop session-open against `payments-debug` would attempt
  `sts:AssumeRole` on the deleted role and get an explicit STS
  failure → fails closed

The next session-open requires a fresh iam-jit grant. No orphan
role, no stale secret value.

---

## Scenario 2: agent runs a one-off rake task to reconcile data

### Situation

> "We need to reconcile last week's settlements between AcmePay and
> Bankco. The rake task is `rake settlements:reconcile`. Run it."

### Agent steps

**1. Agent reads the rake task to find its AWS surface.**

```
$ cat lib/tasks/settlements.rake
namespace :settlements do
  task :reconcile => :environment do
    settlements = Aws::DynamoDB::Client.new.scan(table_name: 'settlements_prod')
    # ... reconciliation logic ...
    Aws::DynamoDB::Client.new.batch_write_item(
      request_items: { 'settlements_recon_staging' => ... }
    )
  end
end
```

Surface identified:
- `dynamodb:Scan` on `settlements_prod` (production read)
- `dynamodb:BatchWriteItem` on `settlements_recon_staging` (staging write)

This is **cross-environment** (read prod, write staging), which is
why the agent should expect iam-jit to flag this as needing approval.

**2. Agent submits the intent.**

```json
{
  "intent": {
    "type": "freeform",
    "natural_language": "Run rake settlements:reconcile — scan prod settlements, batch-write to staging recon table",
    "parameters": {
      "actions": ["dynamodb:Scan", "dynamodb:BatchWriteItem"],
      "resources": [
        "arn:aws:dynamodb:ap-southeast-1:123456789012:table/settlements_prod",
        "arn:aws:dynamodb:ap-southeast-1:444455556666:table/settlements_recon_staging"
      ]
    }
  },
  "principal": {"kind": "human", "identifier": "alice@acme.com"},
  "duration_seconds": 7200,
  "integration": {"kind": "hoop", "trust_principal": "arn:aws:iam::123456789012:role/HoopAgentRole"}
}
```

**3. iam-jit scores and routes to admin.**

```json
{
  "status": "needs_approval",
  "grant_id": "G-2026-05-15-def456",
  "score": 0.62,
  "score_explanation": "Cross-account write (staging recon table is in a different AWS account from the source). Above auto-approve threshold (0.5).",
  "approval_request_id": "REQ-2026-05-15-def456",
  "approver_notification_sent": true,
  "narrowing_hints": [
    {
      "remove_actions": ["dynamodb:BatchWriteItem"],
      "projected_score": 0.21,
      "would_auto_approve": true,
      "explanation": "If you only need to READ prod for analysis (not write the recon results), drop BatchWriteItem and rerun. Auto-approves."
    }
  ]
}
```

The agent has two choices:
- (a) Wait for admin approval (because the write IS necessary for
  this task)
- (b) Apply the narrowing hint and only do the read part

The agent picks (a) and tells the engineer:

> "Submitted as REQ-2026-05-15-def456 — needs admin approval because
> it crosses account boundaries (prod read + staging write). I'll
> notify you when approved."

**4. Admin reviews + approves in iam-jit's web UI.**

Admin sees the request with the agent's natural-language description,
the exact actions and ARNs the agent inferred from source, and the
score breakdown. Approves with a 2-hour TTL. iam-jit creates the
role (with the cross-account write permissions and the Hoop agent's
trust principal) and returns the role ARN.

**5. Agent runs the task via Hoop.**

```bash
hoop connect rake-runner \
  --env EKS_ROLE_ARN=arn:aws:iam::123456789012:role/iam-jit/grant-rq-def456 \
  -- rake settlements:reconcile
```

The Hoop `rake-runner` connection is configured to spawn a Ruby
container with the assumed-role creds in the env, run the provided
command, capture output, then exit. Hoop's agent assumes the
iam-jit-created role at session-open.

Output streams back; the agent summarizes results.

**6. Cleanup happens automatically at TTL expiry** — iam-jit's
sweeper deletes the role.

---

## Scenario 3: live debug during a production incident

### Situation

PagerDuty alert: wallet service throwing 500s. On-call has 2 minutes
to start triaging.

### Agent steps

**1. On-call types into Claude Code:**

> "Wallet service is down. Get me into a debug pod."

**2. Agent immediately recognizes this as an incident-response flow.**

It infers the minimum surface:
- `logs:FilterLogEvents` on `/wallet/svc` (to read recent logs)
- `eks:DescribeCluster` (for `aws eks get-token` to get kubectl access)

It does NOT request:
- Any write actions
- Any production database access (debug pod doesn't need it)
- Any cross-service permissions (no S3, no DynamoDB)

This restraint is critical: in incident-response mode, the agent
should request the minimum the on-call needs to *see* the problem,
not the maximum that *might* help fix it. Fixes can request more
access later.

**3. Agent submits intent with `caller.source: "incident-response"`.**

This caller-source signals iam-jit to log the request as
incident-context and emit a notification to the SRE channel.

```json
{
  "intent": {
    "type": "freeform",
    "natural_language": "On-call incident: wallet service 500s. Read CloudWatch logs + kubectl access for debug pod.",
    "parameters": {
      "actions": [
        "logs:FilterLogEvents",
        "logs:GetLogEvents",
        "eks:DescribeCluster"
      ],
      "resources": [
        "arn:aws:logs:ap-southeast-1:123456789012:log-group:/wallet/svc:*",
        "arn:aws:eks:ap-southeast-1:123456789012:cluster/prod-eks"
      ]
    }
  },
  "principal": {"kind": "human", "identifier": "alice@acme.com"},
  "duration_seconds": 1800,
  "caller": {"source": "incident-response", "incident_id": "INC-2026-05-15-001"},
  "integration": {"kind": "hoop", "trust_principal": "arn:aws:iam::123456789012:role/HoopAgentRole"}
}
```

**4. iam-jit auto-approves (read-only + narrow ARNs) and creates the role.**

Score: 0.12. Role created in <500ms.

**5. On-call connects via Hoop; assumes the iam-jit role; kubectls into the debug pod.**

```bash
hoop connect kube-debug-prod \
  --env EKS_ROLE_ARN=arn:aws:iam::123456789012:role/iam-jit/grant-rq-inc001
# Inside the pod:
kubectl logs -n wallet -l app=wallet-svc --tail=500
kubectl exec -it wallet-svc-7b9f4-xyzqp -- /bin/sh
```

Agent helps interpret the logs in real-time. Find: a single Redis
node OOM'd; failover hadn't completed.

**6. Fix path requires more access.**

The fix requires `elasticache:DescribeReplicationGroups` +
`elasticache:CompleteFailover`. Agent submits a follow-up grant
(iam-jit creates a second role, returns its ARN; agent re-opens a
Hoop session with the new role).

This second grant gets caught by the same-purpose retry lockout
(layer 2 anti-spam) → routes to admin. SRE manager approves
in 30 seconds (incident context = high priority).

Failover completes. Service recovers. Both roles auto-delete at
TTL.

---

## Scenario 4: agent self-serves a CloudWatch alert investigation

### Situation

A CloudWatch alarm fires, routed to the `#alerts` Slack channel.
A Claude bot sits in the channel and processes the alert.

### Agent steps

**1. Bot reads the alert payload.**

```json
{
  "AlarmName": "ECS-task-failures-payments",
  "MetricName": "RunningTaskCount",
  "Threshold": 3,
  "Description": "Payments service tasks falling below threshold"
}
```

**2. Bot infers the investigation surface.**

- `ecs:DescribeServices` on the payments service
- `ecs:ListTasks` + `ecs:DescribeTasks` (recent failed tasks)
- `logs:FilterLogEvents` on `/ecs/payments`

**3. Bot submits intent with `principal.kind: "agent"`.**

The agent kind triggers iam-jit's agent-specific anti-spam thresholds
(higher per-hour cap because automated agents have more legitimate
volume than humans, but boundary-probe detection is still active).

```json
{
  "intent": {
    "type": "freeform",
    "natural_language": "Auto-investigate ECS-task-failures-payments alert",
    "parameters": {
      "actions": ["ecs:DescribeServices", "ecs:ListTasks", "ecs:DescribeTasks", "logs:FilterLogEvents"],
      "resources": [
        "arn:aws:ecs:ap-southeast-1:123456789012:service/prod/payments",
        "arn:aws:ecs:ap-southeast-1:123456789012:task/prod/*",
        "arn:aws:logs:ap-southeast-1:123456789012:log-group:/ecs/payments:*"
      ]
    }
  },
  "principal": {"kind": "agent", "identifier": "slack-alert-investigator-bot"},
  "duration_seconds": 900,
  "caller": {"source": "alert-router", "alarm_name": "ECS-task-failures-payments"},
  "integration": {"kind": "hoop", "trust_principal": "arn:aws:iam::123456789012:role/HoopAgentRole"}
}
```

**4. iam-jit auto-approves and creates the role.**

**5. Bot opens Hoop session, gathers data, summarizes.**

```bash
hoop connect ecs-investigate \
  --env EKS_ROLE_ARN=arn:aws:iam::123456789012:role/iam-jit/grant-rq-ecs01
# Bot runs:
aws ecs describe-services --cluster prod --services payments | jq '.services[0].events[:5]'
aws ecs list-tasks --cluster prod --service-name payments --desired-status STOPPED \
  | jq -r '.taskArns[]' | head -5 \
  | xargs -I{} aws ecs describe-tasks --cluster prod --tasks {} \
  | jq '.tasks[].stoppedReason'
aws logs filter-log-events --log-group-name /ecs/payments \
  --filter-pattern '?error ?Error ?ERROR' --start-time $(date -d '15 min ago' +%s)000
```

Bot posts a summary to `#alerts`:

> "ECS payments task failures: 4 tasks stopped in last 15min, all with
> `ResourceInitializationError: failed to invoke EFS utils command`.
> EFS mount issue. Page on-call."

**6. Cleanup at TTL** — iam-jit deletes the role.

---

## Scenario 5: rotate one secret (write to one secret only)

### Situation

> "The third-party API key in `prod/external/payment-gateway` was
> leaked in a stack trace. Rotate it now."

### Agent steps

**1. Agent reads code to confirm the secret name + how it's consumed.**

```
$ rg "payment-gateway" lib/ app/
lib/payment_gateway_client.rb:14:    @api_key = AWS::SecretsManager.get_secret(name: "prod/external/payment-gateway")['api_key']
```

Confirmed name: `prod/external/payment-gateway`.

**2. Agent submits a TIGHT intent: write to ONE secret only.**

```json
{
  "intent": {
    "type": "freeform",
    "natural_language": "Rotate compromised secret prod/external/payment-gateway",
    "parameters": {
      "actions": [
        "secretsmanager:PutSecretValue",
        "secretsmanager:UpdateSecretVersionStage"
      ],
      "resources": [
        "arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:prod/external/payment-gateway-*"
      ]
    }
  },
  "principal": {"kind": "human", "identifier": "alice@acme.com"},
  "duration_seconds": 900,
  "integration": {"kind": "hoop", "trust_principal": "arn:aws:iam::123456789012:role/HoopAgentRole"}
}
```

Note: the suffix `-*` matches the AWS-generated random suffix on
secret ARNs.

**3. iam-jit scores HIGH and routes to admin.**

```json
{
  "status": "needs_approval",
  "score": 0.71,
  "score_explanation": "Write to Secrets Manager in production scope. Above auto-approve threshold for write-class secret operations.",
  "narrowing_hints": []
}
```

No narrowing hints because the request is already minimal — there's
no way to "make it less risky" while still doing the rotation. The
single-secret resource scope is already as tight as the action
allows; the production-scope flag is what drives the score.

**4. Admin (security on-call) reviews and approves.**

The natural-language description is clear; the resource is one
secret; the actions are the minimum needed for rotation; the TTL is
15 minutes. Approved in seconds. iam-jit creates the role and
returns the ARN.

**5. Agent rotates the secret via Hoop session.**

```bash
hoop connect secret-rotate \
  --env EKS_ROLE_ARN=arn:aws:iam::123456789012:role/iam-jit/grant-rq-rot01 \
  -- bash -c '
    NEW_KEY=$(curl -sS -H "Authorization: Bearer $UPSTREAM_TOKEN" \
      https://gateway.example.com/api-keys/rotate | jq -r .new_key)
    aws secretsmanager put-secret-value \
      --secret-id prod/external/payment-gateway \
      --secret-string "{\"api_key\":\"$NEW_KEY\"}"
    aws secretsmanager update-secret-version-stage \
      --secret-id prod/external/payment-gateway \
      --version-stage AWSCURRENT \
      --move-to-version-id $(aws secretsmanager describe-secret --secret-id prod/external/payment-gateway --query VersionIdsToStages --output json | jq -r "to_entries[] | select(.value[] == \"AWSPENDING\") | .key")
'
```

**6. Agent verifies + reports.**

```bash
# Confirm the new value is live (without printing the actual value):
aws secretsmanager describe-secret --secret-id prod/external/payment-gateway \
  | jq '.LastChangedDate'
```

Reports to Slack: "Rotated. New version live as of 2026-05-15
14:32:18 UTC."

---

## Scenario 6: chatbot agent that PREVIOUSLY had no AWS access

This scenario inverts the value prop. The other five make existing
AWS access safer. This one **unlocks AWS access that was previously
refused on security grounds**.

### Situation

A company runs an "infra-ai" Slack chatbot deployed in their K8s
cluster. Today it has access to cluster-internal data only —
**zero AWS access** — because giving a long-lived bot persistent AWS
credentials was correctly judged too risky by the security team.

This means the bot today CAN'T answer questions like:

- "What's the current size of the payment-events bucket?"
- "Show me the last 5 CloudWatch alarms in the payments account."
- "Which Lambda functions invoked the failed Bedrock call this
  morning?"
- "How many ECS tasks are running for the wallet service across
  prod and staging?"

Engineers either dig the answers up themselves or the bot punts.

### How iam-jit changes this

The security concern that blocked the bot's AWS access — *standing
credentials in a long-running pod* — is exactly the concern iam-jit
solves. Instead of provisioning the bot with persistent AWS keys,
we:

1. Give the bot's pod NO standing AWS credentials
2. Give the bot iam-jit API access (a single scoped token to call
   `/api/v1/grant`) AND IRSA-bind a trust principal the bot itself
   can assume (call it `BotIRSARole`)
3. When the bot needs AWS data to answer a question, it requests a
   narrow, short-lived grant per query — iam-jit creates a role
   trusting `BotIRSARole`
4. The bot's pod assumes the created role using IRSA-issued STS
   credentials (no standing AWS keys involved)
5. The bot uses those assumed creds for the specific query, then
   lets them expire

The bot's ambient AWS posture stays **zero standing credentials**.
Each query carves out a tiny, audit-logged window of access just
for that question. The IRSA token is short-lived and pod-scoped —
not a long-lived AWS access key.

### Concrete flow

A user asks in Slack:

> @infra-ai how big is the payment-events S3 bucket right now?

**1. Bot infers the AWS surface needed.**

- `s3:ListBucket` on `arn:aws:s3:::payment-events`
- `s3:GetBucketLocation` (just to confirm region for the metric query)
- Optionally `cloudwatch:GetMetricStatistics` on
  `AWS/S3/BucketSizeBytes` for an exact answer without listing

**2. Bot submits intent.**

```json
{
  "intent": {
    "type": "freeform",
    "natural_language": "Answer Slack question: how big is the payment-events S3 bucket",
    "parameters": {
      "actions": ["s3:ListBucket", "s3:GetBucketLocation", "cloudwatch:GetMetricStatistics"],
      "resources": [
        "arn:aws:s3:::payment-events",
        "arn:aws:cloudwatch:ap-southeast-1:123456789012:metric/AWS/S3"
      ]
    }
  },
  "principal": {"kind": "agent", "identifier": "infra-ai-slack-bot"},
  "duration_seconds": 300,
  "caller": {
    "source": "slack-bot",
    "slack_user_id": "U01ABC...",
    "slack_question_id": "..."
  },
  "integration": {"kind": "irsa-direct", "trust_principal": "arn:aws:iam::123456789012:role/BotIRSARole"}
}
```

Note: `duration_seconds: 300` — five minutes is plenty for a single
metric lookup. The narrower the time window, the lower the score
contribution from duration. `integration.kind: irsa-direct` signals
the bot will assume the role directly (no Hoop in this path).

**3. iam-jit auto-approves and creates the role.**

Score: 0.08. Read-only metadata + metric read on one bucket / one
service. Below threshold.

**4. Bot assumes the iam-jit-created role and runs the query.**

```python
# Inside the bot's request handler:
import boto3
sts = boto3.client("sts")  # uses pod's IRSA-issued identity
assumed = sts.assume_role(
    RoleArn=grant["role_arn"],
    RoleSessionName="bot-query-..." + grant["grant_id"],
    DurationSeconds=300,
)
creds = assumed["Credentials"]
session = boto3.Session(
    aws_access_key_id=creds["AccessKeyId"],
    aws_secret_access_key=creds["SecretAccessKey"],
    aws_session_token=creds["SessionToken"],
)
cw = session.client("cloudwatch", region_name="ap-southeast-1")
result = cw.get_metric_statistics(
    Namespace="AWS/S3", MetricName="BucketSizeBytes",
    Dimensions=[
        {"Name": "BucketName", "Value": "payment-events"},
        {"Name": "StorageType", "Value": "StandardStorage"},
    ],
    StartTime=..., EndTime=..., Period=86400, Statistics=["Average"],
)
size_gb = result["Datapoints"][0]["Average"] / (1024**3)
bot.respond(f"payment-events is {size_gb:.1f} GB as of yesterday's metric.")
```

**5. Creds expire; role auto-deletes at TTL.**

The bot doesn't write the creds to disk, doesn't cache them
beyond the request, and lets them expire. iam-jit deletes the role
at TTL. If the same user asks a similar question 10 minutes later,
the bot makes a fresh grant request.

### Why this is the highest-leverage use case for iam-jit at scale

It demonstrates the **default-to-iam-jit** posture for agents in
production: the bot's normal state is "no standing AWS access at
all," and every interaction-with-AWS is a discrete, audited,
scored, and short-lived grant. This is the structural posture
iam-jit makes practical and that nothing else in the market does
well today.

It also opens up an entire category of agent capability that today
gets refused at the InfoSec review: bots that can introspect AWS
state to answer questions, but that can't accumulate or hold
credentials beyond a single query.

### Anti-spam considerations for chatbots

A chatty Slack bot can easily exceed default per-principal rate
limits if every user question triggers a grant. Two configuration
adjustments matter:

1. **Set the bot principal's per-hour cap higher than the human
   default.** Anti-spam Layer 1 supports per-principal-kind caps;
   default `agent` cap is higher than `human` for this reason.
2. **Enable boundary-probe detection** so a bot that gets buggy and
   starts hammering iam-jit with near-threshold queries gets
   throttled before it inflates costs or pollutes the audit log.

Both are config, not code. See the recommender spec's "Anti-spam"
section.

---

## Pattern 2 (FALLBACK): Wrapper script + Secrets Manager

> **Use this only if your Hoop deployment doesn't have IRSA set up
> yet** OR the Hoop connection type doesn't natively accept an
> `EKS_ROLE_ARN`. For any EKS-hosted Hoop agent, Pattern 1 above is
> what Hoop's own docs recommend and what this recipe leads with.

The original draft of this doc used a small wrapper that bridged
iam-jit's grant response into a Secrets Manager secret that a Hoop
connection reads via Hoop's `_aws:secret:KEY` source. That pattern
still works in v1.0 and is documented here as a fallback for the
deployments where Pattern 1 isn't an option (older Hoop configs,
non-EKS Hoop deployments without IRSA configured).

### When to use Pattern 2

- Hoop agent runs OUTSIDE EKS (Docker on a VM, bare-metal, etc.)
  and doesn't have an IRSA equivalent
- Hoop connection type only accepts static credentials via
  `_aws:secret:KEY` source (older connection types)
- You're migrating from an existing Secrets-Manager-based Hoop
  config and don't want to flip it yet

For everything else, prefer Pattern 1 — no held credentials, no
secret rotation, no wrapper.

### How Pattern 2 works

iam-jit issues STS credentials (instead of returning a role ARN)
via the legacy `/api/v1/grant?issue_credentials=true` query
parameter. A small wrapper script writes the STS triple to a
Secrets Manager secret. Hoop's connection envs reference that
secret via `_aws:<secret>:KEY` syntax.

```
agent ──► iam-jit /api/v1/grant?issue_credentials=true ──► STS triple
                                         │
                                         ▼
                          wrapper writes creds → AWS Secrets Manager
                          (path: /iam-jit/hoop-session/<connection-id>)
                                         │
                                         ▼
agent ──► hoop session open <connection-id>
                                         │
                                         ▼
       Hoop reads from Secrets Manager → injects into session env
```

### Wrapper script skeleton (Pattern 2 only)

`infrastructure/recipes/hoop-credential-bridge.py` (one file, ~60
lines — kept here as a reference; not currently shipped under
`infrastructure/recipes/` in the repo because Pattern 1 supersedes
it):

```python
"""Bridge: iam-jit grant response → AWS Secrets Manager → Hoop session.

PATTERN 2 FALLBACK — only use this when Pattern 1 (AssumeRole) is
not possible. Pattern 1 is what Hoop's EKS quickstart documents and
what this recipe leads with.

Reads a grant response on stdin (or via --grant-id arg + iam-jit
fetch), writes the STS triple as JSON to a Secrets Manager secret
that a Hoop connection is configured to read from.

Usage:
  curl ...?issue_credentials=true | python3 hoop-credential-bridge.py --secret-path /iam-jit/hoop-session/<connection-id>
  python3 hoop-credential-bridge.py --grant-id G-... --secret-path ...
"""
import argparse
import json
import sys

import boto3


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--secret-path", required=True)
    p.add_argument("--region", default="ap-southeast-1")
    p.add_argument("--grant-id", default=None,
                   help="Fetch grant by ID instead of reading stdin")
    p.add_argument("--iamjit-base-url", default=None)
    p.add_argument("--iamjit-token", default=None)
    args = p.parse_args()

    if args.grant_id:
        import urllib.request
        req = urllib.request.Request(
            f"{args.iamjit_base_url}/api/v1/grant/{args.grant_id}",
            headers={"Authorization": f"Bearer {args.iamjit_token}"},
        )
        grant = json.loads(urllib.request.urlopen(req).read())
    else:
        grant = json.load(sys.stdin)

    creds = grant.get("credentials")
    if not creds:
        sys.exit(f"grant has no credentials field: status={grant.get('status')}. "
                 "Pattern 1 (role ARN handoff) is recommended; this wrapper only "
                 "works with the issue_credentials=true legacy path.")

    payload = {
        "AWS_ACCESS_KEY_ID":     creds["access_key_id"],
        "AWS_SECRET_ACCESS_KEY": creds["secret_access_key"],
        "AWS_SESSION_TOKEN":     creds["session_token"],
        "EXPIRES_AT":            str(creds["expires_at"]),
        "GRANT_ID":              grant.get("grant_id", ""),
    }

    sm = boto3.client("secretsmanager", region_name=args.region)
    try:
        sm.put_secret_value(
            SecretId=args.secret_path,
            SecretString=json.dumps(payload),
        )
    except sm.exceptions.ResourceNotFoundException:
        sm.create_secret(
            Name=args.secret_path,
            SecretString=json.dumps(payload),
            Description="iam-jit-issued ephemeral creds for Hoop session (Pattern 2 fallback)",
        )
    print(f"wrote creds to {args.secret_path} (expires_at={creds['expires_at']})")


if __name__ == "__main__":
    main()
```

### One-time setup per Hoop connection (Pattern 2 only)

1. Create a Secrets Manager secret with a placeholder value:
   ```bash
   aws secretsmanager create-secret \
     --name /iam-jit/hoop-session/<connection-id> \
     --secret-string '{"AWS_ACCESS_KEY_ID":"placeholder","AWS_SECRET_ACCESS_KEY":"placeholder","AWS_SESSION_TOKEN":"placeholder"}'
   ```

2. Grant Hoop's agent role read access to that secret path
   (`secretsmanager:GetSecretValue` on
   `arn:aws:secretsmanager:...:secret:/iam-jit/hoop-session/*`).

3. Configure the Hoop connection's envs to read from the secret (in
   the Hoop UI or config):
   ```yaml
   envs:
     AWS_ACCESS_KEY_ID:     "_aws:/iam-jit/hoop-session/<connection-id>:AWS_ACCESS_KEY_ID"
     AWS_SECRET_ACCESS_KEY: "_aws:/iam-jit/hoop-session/<connection-id>:AWS_SECRET_ACCESS_KEY"
     AWS_SESSION_TOKEN:     "_aws:/iam-jit/hoop-session/<connection-id>:AWS_SESSION_TOKEN"
   ```

That's the Pattern 2 setup. Each session-open reads the latest
creds from Secrets Manager. iam-jit rotates the secret per grant
(via the wrapper).

### Why Pattern 1 is preferred over Pattern 2

| | Pattern 1 (AssumeRole / IRSA) | Pattern 2 (Wrapper + Secrets Manager) |
|---|---|---|
| Held credentials | None | STS triple in Secrets Manager |
| iam-jit holds creds | No | No (wrapper writes them) |
| Secret rotation | N/A — no secret | Wrapper rewrites per grant |
| Required infra | IRSA + iam-jit role-create perms | Secrets Manager + wrapper + Hoop secret config |
| Hoop docs alignment | Yes (EKS quickstart) | Legacy / no longer the documented path |
| Failure mode | Role deleted → session fails closed | Stale secret → session may briefly use old creds |
| Operator complexity | One-time IRSA binding | Per-connection secret setup |

---

## Failure modes + how the recipe handles them

### Pattern 1 (recommended)

| Failure | Behavior |
|---|---|
| iam-jit unreachable | Grant request fails; agent reports the error. No role gets created; Hoop session-open has nothing to assume. No stale creds anywhere. |
| iam-jit returns role ARN but role-create races with session-open | AssumeRole retries briefly (STS eventual consistency); usually clears within 1-2 seconds. Hoop's session-open will surface the failure cleanly if it persists. |
| Grant TTL expires mid-session | Already-fetched STS triple continues to work until STS rejects it (~at TTL boundary). Next API call after TTL fails with `ExpiredToken`. Engineer requests a new grant; iam-jit creates a fresh role. |
| Multiple agents request grants simultaneously | Each gets a different role ARN. No shared mutable state. Both sessions work independently. |
| iam-jit deletes role before session ends | Active sessions keep working until STS-issued triple expires (STS doesn't re-check the role). Next session-open against the same role fails (role gone). |

### Pattern 2 (fallback)

| Failure | Behavior |
|---|---|
| iam-jit unreachable | Wrapper exits non-zero; agent reports the error. Hoop session has no fresh creds; previous grant's creds still in secret may work IF still within TTL, otherwise session-open fails closed. |
| Secrets Manager write fails | Wrapper exits non-zero; agent retries OR reports. Old creds still in secret; old session may still work briefly. |
| Hoop session-open while wrapper is mid-write | Hoop reads the current secret value (atomic in Secrets Manager). Either gets old creds (still valid if pre-TTL) or new creds. No partial reads. |
| Grant TTL expires mid-session | Same as Pattern 1 — STS triple continues until rejected. |
| Multiple agents request grants for the same connection simultaneously | Each gets a different grant_id; whoever's wrapper writes to Secrets Manager last wins (the secret holds the latest). The "loser" can detect this by reading back and seeing a different `GRANT_ID` than they wrote. Anti-spam layer 2 (same-purpose retry lockout) catches genuine same-purpose duplicates. |

## What this recipe deliberately does NOT do

- **No protocol change to Hoop.** Uses Hoop's existing
  `EKS_ROLE_ARN` connection env (Pattern 1) or `_aws:secret:KEY`
  source (Pattern 2).
- **No iam-jit code change.** Uses iam-jit's existing
  `/api/v1/grant` endpoint.
- **No fork of either tool.** Just a one-time IRSA binding (Pattern
  1) or a wrapper script (Pattern 2).
- **No vendor coupling.** The same Pattern-1 shape (iam-jit creates
  role + caller assumes it) works with Teleport (`AssumeRoleArn`),
  StrongDM (workload identity), Boundary, or any other proxy that
  supports per-session role assumption. The same Pattern-2 shape
  (wrapper writes STS triple to a secret) works with anything that
  reads creds from Secrets Manager / Vault / file.

## Related docs

- [`docs/RECOMMENDER-API-SPEC.md`](../RECOMMENDER-API-SPEC.md) — the
  recommender API the agent calls
- [Hoop EKS quickstart](https://hoop.dev/docs/quickstart/cloud-services/kubernetes/kubernetes-eks)
  — the upstream pattern Pattern 1 is built on
- [[create-not-assume-pattern]] (memory) — the architectural
  pattern (iam-jit creates roles; caller assumes them; iam-jit
  never holds creds)
- [[agent-context-primacy]] (memory) — why agent-supplied
  parameters produce better recommendations than iam-jit guessing
- [[recommender-context-boundary]] (memory) — what context channels
  iam-jit consumes (and what it never will)
