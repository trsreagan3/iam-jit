# Agent + iam-jit + Hoop: end-to-end examples

> Five concrete scenarios showing how an AI agent (Claude Code, Cursor,
> etc.) uses iam-jit to get scoped AWS credentials and then opens a
> Hoop session with those credentials. **Zero changes to either iam-jit
> or Hoop** — the integration relies on Hoop's existing AWS Secrets
> Manager secret-source and iam-jit's existing grant API.

## How the integration works (in 60 seconds)

Hoop already supports AWS Secrets Manager as a secret source for
connection credentials (`_aws:<secret-id>:KEY` in connection envs).
iam-jit issues short-lived STS credentials per request. A small
wrapper script bridges the two:

```
agent ──► iam-jit /api/v1/grant ──► STS creds (e.g. 1hr TTL)
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
                                         │
                                         ▼
                        agent's session has scoped, time-bound creds
```

**No iam-jit code changes. No Hoop fork. No plugin.** Just the
wrapper script and a Hoop connection configured to read from
Secrets Manager.

The wrapper script is ~50 lines of Python — see
[`infrastructure/recipes/hoop-credential-bridge.py`](#wrapper-script-skeleton)
at the bottom of this doc.

---

## Scenario 1: agent debugs a payment failure

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
curl -sS -X POST https://iam-jit.omise.internal/api/v1/grant \
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
    "principal": {"kind": "human", "identifier": "alice@omise.com"},
    "duration_seconds": 3600,
    "caller": {"source": "mcp", "session_id": "claude-code-..." }
  }'
```

**3. iam-jit scores and auto-approves.**

```json
{
  "status": "success",
  "grant_id": "G-2026-05-15-abc123",
  "policy": { /* the synthesized least-privilege policy */ },
  "score": 0.18,
  "score_explanation": "Read-only with narrow ARN scoping. Below auto-approve threshold (0.5).",
  "credentials": {
    "access_key_id": "ASIA...",
    "secret_access_key": "...",
    "session_token": "...",
    "expires_at": 1747007200
  },
  "audit_id": "..."
}
```

Score is 0.18 — well below the 0.5 auto-approve threshold (read-only,
narrow resource ARNs, no IAM-modify actions). Auto-issued.

**4. Wrapper script writes creds to Secrets Manager.**

```bash
# The agent (or a helper alias) pipes the grant response through
# the wrapper, which updates the Hoop connection's secret:
curl ... | python3 hoop-credential-bridge.py \
  --connection payments-debug \
  --secret-path /iam-jit/hoop-session/payments-debug
```

Internally the wrapper:
1. Pulls the STS triple from the grant response
2. Calls `secretsmanager:PutSecretValue` on
   `arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:/iam-jit/hoop-session/payments-debug`
3. The secret value is a JSON object with `AWS_ACCESS_KEY_ID`,
   `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`

**5. Hoop session opens with the rotated creds.**

```bash
hoop connect payments-debug
```

The Hoop connection `payments-debug` is configured (in Hoop's UI or
config file) with envs:

```yaml
envs:
  AWS_ACCESS_KEY_ID: "_aws:/iam-jit/hoop-session/payments-debug:AWS_ACCESS_KEY_ID"
  AWS_SECRET_ACCESS_KEY: "_aws:/iam-jit/hoop-session/payments-debug:AWS_SECRET_ACCESS_KEY"
  AWS_SESSION_TOKEN: "_aws:/iam-jit/hoop-session/payments-debug:AWS_SESSION_TOKEN"
```

Hoop reads the secret at session-open and injects the values into
the engineer's shell. Their AWS-SDK calls now use the iam-jit-issued
credentials.

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

Each command succeeds because the iam-jit-issued credentials grant
exactly these actions on exactly these resources. The agent
correlates the data, finds the issue (rejected by upstream gateway,
not retried), and reports back.

**7. Cleanup.**

When the grant TTL expires (1 hour), iam-jit automatically:
- Marks the grant as expired
- Calls `secretsmanager:UpdateSecret` to overwrite the secret with
  a sentinel value (or empty JSON) so future Hoop sessions read
  invalid creds and fail closed

The next session-open by anyone for `payments-debug` will require a
fresh iam-jit grant.

---

## Scenario 2: agent runs a one-off rake task to reconcile data

### Situation

> "We need to reconcile last week's settlements between Omise and
> Kbank. The rake task is `rake settlements:reconcile`. Run it."

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
  "principal": {"kind": "human", "identifier": "alice@omise.com"},
  "duration_seconds": 7200
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
score breakdown. Approves with a 2-hour TTL.

**5. iam-jit issues credentials, wrapper rotates Hoop secret, agent
runs the task.**

```bash
hoop connect rake-runner -- rake settlements:reconcile
```

The Hoop `rake-runner` connection is configured to spawn a Ruby
container with the iam-jit-issued AWS creds in the env, run the
provided command, capture output, then exit.

Output streams back; the agent summarizes results.

**6. Cleanup happens automatically at TTL expiry.**

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
  "principal": {"kind": "human", "identifier": "alice@omise.com"},
  "duration_seconds": 1800,
  "caller": {"source": "incident-response", "incident_id": "INC-2026-05-15-001"}
}
```

**4. iam-jit auto-approves (read-only + narrow ARNs).**

Score: 0.12. Issued in <500ms.

**5. Wrapper rotates Hoop secret; on-call kubectls into the debug pod.**

```bash
hoop connect kube-debug-prod
# Inside the pod:
kubectl logs -n wallet -l app=wallet-svc --tail=500
kubectl exec -it wallet-svc-7b9f4-xyzqp -- /bin/sh
```

Agent helps interpret the logs in real-time. Find: a single Redis
node OOM'd; failover hadn't completed.

**6. Fix path requires more access.**

The fix requires `elasticache:DescribeReplicationGroups` +
`elasticache:CompleteFailover`. Agent submits a follow-up grant.

This second grant gets caught by the same-purpose retry lockout
(layer 2 anti-spam) → routes to admin. SRE manager approves
in 30 seconds (incident context = high priority).

Failover completes. Service recovers.

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
  "caller": {"source": "alert-router", "alarm_name": "ECS-task-failures-payments"}
}
```

**4. iam-jit auto-approves; wrapper rotates Hoop secret.**

**5. Bot opens Hoop session, gathers data, summarizes.**

```bash
hoop connect ecs-investigate
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

**6. Cleanup at TTL.**

---

## Scenario 5: rotate one Secrets Manager secret

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
  "principal": {"kind": "human", "identifier": "alice@omise.com"},
  "duration_seconds": 900
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
no way to "make it less risky" while still doing the rotation.

**4. Admin (security on-call) reviews and approves.**

The natural-language description is clear; the resource is one
secret; the actions are the minimum needed for rotation; the TTL is
15 minutes. Approved in seconds.

**5. Agent rotates the secret via Hoop session.**

```bash
hoop connect secret-rotate -- bash -c '
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
   `/api/v1/grant`)
3. When the bot needs AWS data to answer a question, it requests a
   narrow, short-lived grant per query
4. iam-jit scores, gates, and issues credentials with a 5-15 minute
   TTL
5. The bot uses those creds for the specific query, then discards them

The bot's ambient AWS posture stays **zero**. Each query carves out
a tiny, audit-logged window of access just for that question.

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
  }
}
```

Note: `duration_seconds: 300` — five minutes is plenty for a single
metric lookup. The narrower the time window, the lower the score
contribution from duration.

**3. iam-jit auto-approves.**

Score: 0.08. Read-only metadata + metric read on one bucket / one
service. Below threshold.

**4. Bot uses creds directly (no Hoop session needed for read-only
out-of-cluster API calls).**

```python
# Inside the bot's request handler:
creds = grant["credentials"]
session = boto3.Session(
    aws_access_key_id=creds["access_key_id"],
    aws_secret_access_key=creds["secret_access_key"],
    aws_session_token=creds["session_token"],
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

**5. Creds are discarded; grant expires at TTL.**

The bot doesn't write the creds to disk, doesn't cache them
beyond the request, and lets them expire. If the same user asks a
similar question 10 minutes later, the bot makes a fresh grant
request.

### Why this is the highest-leverage use case for iam-jit at scale

It demonstrates the **default-to-iam-jit** posture for agents in
production: the bot's normal state is "no AWS access at all," and
every interaction-with-AWS is a discrete, audited, scored, and
short-lived grant. This is the structural posture iam-jit makes
practical and that nothing else in the market does well today.

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

## Wrapper script skeleton

`infrastructure/recipes/hoop-credential-bridge.py` (one file, ~60
lines):

```python
"""Bridge: iam-jit grant response → AWS Secrets Manager → Hoop session.

Reads a grant response on stdin (or via --grant-id arg + iam-jit
fetch), writes the STS triple as JSON to a Secrets Manager secret
that a Hoop connection is configured to read from.

Usage:
  curl ... | python3 hoop-credential-bridge.py --secret-path /iam-jit/hoop-session/<connection-id>
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
        sys.exit(f"grant has no credentials field: status={grant.get('status')}")

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
            Description="iam-jit-issued ephemeral creds for Hoop session",
        )
    print(f"wrote creds to {args.secret_path} (expires_at={creds['expires_at']})")


if __name__ == "__main__":
    main()
```

### One-time setup per Hoop connection

For each Hoop connection that should use iam-jit-issued credentials:

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

That's it. Each session-open reads the latest creds from Secrets
Manager. iam-jit rotates the secret per grant.

---

## Failure modes + how the recipe handles them

| Failure | Behavior |
|---|---|
| iam-jit unreachable | Wrapper exits non-zero; agent reports the error. Hoop session has no fresh creds; previous grant's creds still in secret may work IF still within TTL, otherwise session-open fails closed. |
| Secrets Manager write fails | Wrapper exits non-zero; agent retries OR reports. Old creds still in secret; old session may still work briefly. |
| Hoop session-open while wrapper is mid-write | Hoop reads the current secret value (atomic in Secrets Manager). Either gets old creds (still valid if pre-TTL) or new creds. No partial reads. |
| Grant TTL expires mid-session | The session's already-fetched creds continue to work until STS rejects them (~at TTL boundary). The next API call after TTL fails with `ExpiredToken`. Engineer requests a new grant if more time needed. |
| Multiple agents request grants for the same connection simultaneously | Each gets a different grant_id; whoever's wrapper writes to Secrets Manager last wins (the secret holds the latest). The "loser" can detect this by reading back and seeing a different `GRANT_ID` than they wrote. Anti-spam layer 2 (same-purpose retry lockout) catches genuine same-purpose duplicates. |

## What this recipe deliberately does NOT do

- **No protocol change to Hoop.** Uses Hoop's existing
  `_aws:secret:KEY` source.
- **No iam-jit code change.** Uses iam-jit's existing
  `/api/v1/grant` endpoint.
- **No fork of either tool.** Just a wrapper script and config.
- **No vendor coupling.** The same shape (write STS triple →
  named-secret) works with Teleport, StrongDM, Boundary, or any
  other proxy that reads creds from Secrets Manager / Vault / file.

## Related docs

- [`docs/RECOMMENDER-API-SPEC.md`](../RECOMMENDER-API-SPEC.md) — the
  recommender API the agent calls
- [`docs/integrations/HOOP-IAMJIT.md`](../integrations/HOOP-IAMJIT.md)
  — the Hoop integration runbook (this recipe extends it)
- [[agent-context-primacy]] (memory) — why agent-supplied
  parameters produce better recommendations than iam-jit guessing
- [[recommender-context-boundary]] (memory) — what context channels
  iam-jit consumes (and what it never will)
