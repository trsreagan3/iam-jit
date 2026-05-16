# Live action tail

Read the AWS API calls a JIT-issued grant's role session is making —
the "what is alice's agent doing right now with the grant I approved
10 minutes ago?" view.

Surfaced as:
- `iam-jit tail <grant-id>` CLI command
- `tail_grant` MCP tool (for agent-driven audit flows)

## How it works

When iam-jit issues a JIT role, the assumed-role session name follows
the pattern `iam-jit-provision-{request_id}`. Every AWS API call made
under that session is recorded by CloudTrail in the customer's own
account. The live action tail queries CloudTrail by that session name
to retrieve recent activity.

Per [[creates-never-mutates]] this only READS CloudTrail; iam-jit
never modifies IAM. Per [[no-hosted-saas]] the query runs against
the customer's own CloudTrail in the customer's own account — no
iam-jit-the-company involvement at runtime.

## Source configuration

The OSS distribution ships three concrete sources:

| Source | When to use | Cost / freshness |
|---|---|---|
| `NullLiveActionTailSource` | Default. Returns empty with a "no source configured" note. Lets the MCP tool / CLI exist on a fresh install without blowing up. | Free, no events. |
| `InMemoryLiveActionTailSource` | Local dev, tests, comic-strip demos. Takes a pre-loaded event list. | Free, no real AWS data. |
| `CloudTrailLookupSource` | Self-host default for real grants. Calls `cloudtrail:LookupEvents` against the customer's own account. | ~$2.00 per 100k events queried; up to ~15 min lag; 90d retention. |

The Enterprise plugin (post-launch) adds:

| Source | When to use | Cost / freshness |
|---|---|---|
| `EventBridgeSubscriptionSource` | Real-time streaming, multi-account aggregation. | iam-jit-the-company infra cost; sub-second lag. |

## Self-host wiring (FREE, OSS)

Add to your iam-jit bootstrap (typically `src/iam_jit/app.py` or a
custom entrypoint):

```python
from iam_jit.live_action_tail import set_default_source
from iam_jit.live_action_tail_cloudtrail import CloudTrailLookupSource

set_default_source(CloudTrailLookupSource(default_region="us-east-1"))
```

The iam-jit-runner principal needs `cloudtrail:LookupEvents` on the
account hosting the JIT-issued role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "cloudtrail:LookupEvents",
    "Resource": "*"
  }]
}
```

That's read-only — no IAM modification required.

## CLI usage

```bash
# Show last 100 events for grant `req-2026-05-17-alice-readonly`
iam-jit tail req-2026-05-17-alice-readonly

# Errors only
iam-jit tail req-2026-05-17-alice-readonly --errors-only

# Narrow to one region + custom window
iam-jit tail req-2026-05-17-alice-readonly \
  --region eu-west-1 \
  --since 2026-05-17T15:00:00Z \
  --until 2026-05-17T15:30:00Z
```

Output is one event per line in CloudTrail-descending order:

```
# grant: req-2026-05-17-alice-readonly
# role:  iam-jit-req-2026-05-17-alice-readonly (session: iam-jit-provision-req-2026-05-17-alice-readonly)
# account: 111111111111
# source: cloudtrail:LookupEvents (region=us-east-1, lag~15min, retention=90d)
# events: 3
15:14:22Z OK s3:GetObject (us-east-1) -> arn:aws:s3:::reports-2026/q1.csv
15:14:19Z OK s3:ListBucket (us-east-1) -> arn:aws:s3:::reports-2026
15:14:01Z FAIL[AccessDenied] secretsmanager:GetSecretValue (us-east-1)
```

## MCP usage (for agents)

Agents can fetch a tail via the `tail_grant` tool:

```json
{
  "method": "tools/call",
  "params": {
    "name": "tail_grant",
    "arguments": {
      "grant_id": "req-2026-05-17-alice-readonly",
      "only_errors": false,
      "max_events": 50
    }
  }
}
```

Response includes `events` (machine-readable list), `summaries`
(one-line human format), and `source` (the source's self-description
so the agent knows the freshness lag).

## Known caveats

- **Eventual consistency** — `LookupEvents` can take up to ~15 minutes
  to surface a freshly-recorded event. For sub-second lag, use the
  Enterprise EventBridge plugin.
- **90-day retention** — `LookupEvents` only sees the last 90 days.
  Older events require CloudTrail Lake or a configured trail querying
  S3. iam-jit grants are short-lived (typically <24h) so this rarely
  matters, but: forensic investigation of historical incidents needs
  the longer-retention path.
- **Rate limit** — 2 TPS per account/region. Don't tail in a tight
  loop; the CLI / MCP tool are snapshot-style by design.
- **Region scope** — CloudTrail is regional. If a grant is exercised
  across multiple regions, query each region separately (or use the
  Enterprise plugin which aggregates).

## Roadmap (post-launch, Enterprise plugin)

- EventBridge real-time subscription (push, not pull)
- Web UI streaming view (auto-refreshing event tail)
- Slack streaming ("posting last 5 minutes to #iam-jit-audit")
- Multi-account aggregation
- Anomaly detection (flag actions outside the policy's typical surface)

These are gated to Enterprise because they require iam-jit-the-company
to operate real infrastructure (EventBridge bus, websocket layer, etc.)
beyond "make one boto3 call per request."
