# Recommender API Spec

> Status: design draft (2026-05-15). Extends what already exists in
> `policy_gen/`, `narrow.py`, and `routes/policy.py`. The behaviors
> below are NOT yet implemented in the listed shape — this doc defines
> the target so the calibration corpus and Hoop integration can be
> built against it.

## Why this spec exists

Today iam-jit's policy-generation surface is a deterministic pattern
matcher (`policy_gen.generate_policy`) wrapped by an "analyze a
policy I already have" endpoint (`POST /api/v1/policy/analyze`).
The pieces work but don't compose into the shape the Hoop integration
and the agent / MCP flow need:

- A caller (Hoop session, MCP client, web UI) wants to express
  **intent** — "give me 1 hour of read-only S3 on bucket X" — and
  receive either a policy, a structured "I need more context" answer,
  or a refusal.
- The same caller may not have all the deployment context (cluster
  ARN, OIDC provider ARN, KMS key ARN). Today the generator silently
  falls back to wildcards; the right behavior is to ASK.
- The recommender's quality needs to be measurable against a corpus,
  ratcheting up over time. Today no calibration loop exists.

This spec defines the API + response shapes + tier behavior + the
calibration loop. Implementation lands in phases — see
"Implementation phases" at the end.

## Agent-context primacy

A foundational point that shapes every other decision in this spec:

**The most accurate recommendations come from an agent that has
access to the source code, not from iam-jit guessing at intent.**

iam-jit's recommender — even with structured intents and Pro-tier
account discovery — is operating on what the *caller chose to tell
it*. An agent inside the dev environment can:

- Read the rake task's source to see exactly which boto3 / aws-sdk
  calls it makes
- Grep the Rails app for bucket names, DynamoDB table references,
  Secrets Manager secret IDs
- Run static analysis to enumerate the exact action surface a code
  path needs
- Read environment variable definitions to find AWS-related config
- Trace from a Hoop session intent ("rails console for issue #4521")
  through to the specific code under investigation and the
  permissions THAT code needs

iam-jit's recommender only sees the intent payload. The agent sees
the truth.

This is why the highest-quality flow is:

1. **Agent gathers context from the codebase** — extracts exact
   ARNs, exact actions, the minimum surface required.
2. **Agent submits a richly-parameterized intent** to iam-jit via
   the MCP server (or `/api/v1/recommend` directly).
3. **iam-jit synthesizes the policy, scores it, and applies the
   safety floor** — refusing or routing to admin if the agent's
   inferred surface is over-broad relative to the threshold.

The recommender's deterministic patterns are the **fallback** for
when there is no agent in the loop (CLI, web UI, GitHub Action with
no source-code introspection). They produce reasonable defaults from
intent alone — but they cannot beat agent-with-source-code on
accuracy, and we shouldn't pretend otherwise.

### Implications for the API design

- The `intent.parameters` field is intentionally rich (resource
  ARNs, action overrides, condition seeds) so an agent that already
  did the work can pass its findings forward instead of forcing
  iam-jit to re-derive them from natural language.
- The MCP server's `recommend` tool surface should encourage
  agent-context patterns: the tool description should explicitly
  prompt the calling agent to inspect the source first and pass the
  exact actions/resources it found.
- The calibration corpus should include both agent-rich entries
  (with full parameters supplied) AND naive-call entries (with only
  natural language) — measuring the delta tells us how much value
  agent context actually adds, and motivates the "pass us your
  findings" UX in the MCP tool.
- Free tier ships the deterministic recommender; paid tiers add LLM
  oversight; **but the highest-quality outcome on any tier comes
  from an agent that gathered context first**. This is part of the
  pitch, not a footnote.

### Implications for positioning

iam-jit's positioning sharpens to:

> The IAM safety floor, scorer, audit trail, and policy synthesizer
> for any process — agent or human — that needs scoped AWS access.
> When called by an agent that gathered context from your codebase,
> iam-jit produces near-perfect least-privilege policies. When
> called without that context, it produces solid deterministic
> defaults that the scorer floor still keeps safe.

This composes cleanly with `[[agents-default-to-iam-jit]]`: agents
should default to iam-jit not just because it's the safety boundary,
but because *agents are iam-jit's best customer* — they have the
context iam-jit needs to be most accurate.

Related: `[[agent-context-primacy]]` (memory).

---

## Scope boundary

iam-jit is AWS IAM only ([[aws-only-positioning]] in memory). The
recommender:

- IN scope: AWS IAM policies — managed, inline, trust, session.
- IN scope: AWS-IAM-shaped K8s context (IRSA role permissions,
  `aws eks get-token` IAM creds).
- OUT of scope: K8s RBAC (ServiceAccounts, Roles, RoleBindings).
- OUT of scope: non-AWS cloud IAM (GCP, Azure).
- OUT of scope: application-layer permissions (Rails Pundit, etc.).

When the caller submits an out-of-scope intent, the recommender
**refuses with a pointer**, not a guess. Saying no clearly is part of
being a good tool.

---

## API surface

### `POST /api/v1/recommend`

Authenticated. Rate-limited (see "Anti-spam").

#### Request

```json
{
  "intent": {
    "type": "s3.read_objects",
    "natural_language": "let me grab the upload manifests from yesterday",
    "parameters": {
      "bucket": "production-uploads",
      "prefix": "manifests/2026-05-14/"
    }
  },
  "principal": {
    "kind": "human" | "agent" | "pod",
    "identifier": "alice@company.com"
  },
  "duration_seconds": 3600,
  "context": {
    "account_id": "123456789012",
    "region": "us-east-1",
    "kms_key_arns": ["arn:aws:kms:us-east-1:123456789012:key/abc-..."],
    "oidc_provider_arn": null,
    "vpc_endpoint_ids": []
  },
  "caller": {
    "source": "mcp" | "web" | "cli" | "hoop" | "github_action",
    "session_id": "...",
    "request_id": "..."
  }
}
```

Field notes:

- `intent.type` is the structured intent — see catalog below. If
  `type` is `"freeform"`, the recommender falls back to natural
  language → pattern matching (current `generate_policy` behavior).
- `intent.parameters` are intent-specific. Each intent type declares
  its required + optional parameters (see catalog).
- `intent.natural_language` is always optional. Used for audit log,
  for the LLM tier, and for the human-readable approval-request UI.
- `context` is the deployment context. On Pro+ tier the recommender
  auto-discovers most of this from the connected account; the caller
  can pass overrides.
- `caller.source` lets us tune anti-spam thresholds per surface
  (an MCP agent and a human web user have different normal request
  volumes).

#### Response: success

```json
{
  "status": "success",
  "policy": {
    "Version": "2012-10-17",
    "Statement": [...]
  },
  "score": 0.32,
  "score_explanation": "...",
  "matched_patterns": ["s3-read-narrow"],
  "context_resolved": {
    "bucket_arn": "arn:aws:s3:::production-uploads",
    "kms_key_arn": null
  },
  "duration_granted_seconds": 3600,
  "expires_at": 1747000000,
  "narrowing_hints": [],
  "audit_id": "..."
}
```

`narrowing_hints` is non-empty when the score is in the borderline
band (e.g., 0.4–0.6 in a deployment whose auto-approve threshold is
0.5). Each hint is structured:

```json
{
  "remove_actions": ["s3:DeleteObject"],
  "remove_resources": [],
  "add_conditions": [{"Bool": {"aws:SecureTransport": "true"}}],
  "projected_score": 0.18,
  "would_auto_approve": true,
  "explanation": "removing s3:DeleteObject moves this from write to read-only — drops below threshold"
}
```

This is what enables "guided narrowing" instead of "guess and
retry." Combined with the same-purpose anti-spam lockout, the
agent's optimal behavior becomes: read the hint, narrow once,
accept the result.

#### Response: needs_context

The recommender knows what intent the caller wants but doesn't have
all the deployment context required to produce a correct,
non-wildcard policy. It returns the missing pieces structurally:

```json
{
  "status": "needs_context",
  "missing": [
    {
      "key": "cluster_arn",
      "type": "arn",
      "arn_resource_type": "eks-cluster",
      "why": "IRSA roles bind to a specific EKS cluster's OIDC provider — without the cluster ARN we can't construct the trust policy.",
      "auto_discoverable_with_pro": true,
      "example": "arn:aws:eks:us-east-1:123456789012:cluster/prod-eks"
    },
    {
      "key": "namespace",
      "type": "string",
      "why": "OIDC subject claim is namespace+SA-scoped.",
      "auto_discoverable_with_pro": false,
      "example": "wallet"
    }
  ],
  "partial_policy_preview": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "PreviewIncomplete",
        "Effect": "Allow",
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Resource": "<NEEDS cluster_arn>",
        "Condition": {
          "StringEquals": {
            "<NEEDS oidc_provider_arn>:sub": "system:serviceaccount:<NEEDS namespace>:<NEEDS sa_name>"
          }
        }
      }
    ]
  },
  "explanation": "This intent involves an IRSA role binding. Free tier needs these inputs supplied; Pro tier auto-discovers cluster + OIDC provider from the connected account.",
  "request_id": "..."
}
```

Caller environments handle this differently:

| Caller            | Handling                                                         |
| ----------------- | ---------------------------------------------------------------- |
| MCP / agent       | Receives `needs_context`, prompts the user OR fetches itself     |
| Web UI            | Renders missing fields as a progressive form                     |
| CLI               | Interactive `?`-prompts per missing field                        |
| API-only / GHA    | Fails with the `missing` list — caller retries with full payload |
| Hoop integration  | Returns the missing list to Hoop's session-open response, which surfaces it to the engineer |

Once context is provided, the caller resubmits with the same
`request_id` (echoed in `caller.request_id`) so the recommender can
correlate retries (relevant for anti-spam).

#### Response: needs_approval

Score crossed the deployment's auto-approve threshold:

```json
{
  "status": "needs_approval",
  "policy": {...},
  "score": 0.78,
  "approval_request_id": "REQ-2026-05-15-abc123",
  "approver_notification_sent": true,
  "narrowing_hints": [
    {
      "remove_actions": ["s3:DeleteObject", "s3:PutObjectAcl"],
      "projected_score": 0.42,
      "would_auto_approve": true,
      "explanation": "drop write/ACL actions to land under threshold"
    }
  ],
  "explanation": "Above your deployment's auto-approve threshold of 0.5. Routed to admin. Either narrow per the hints (and resubmit), or wait for approval."
}
```

The hints here are the **escape valve** that makes anti-spam
tractable: if the agent narrows once per the hint, the next request
auto-approves; if the agent ignores the hint and resubmits the same
shape, anti-spam catches it (see below).

#### Response: refused

Out-of-scope, anti-spam lockout, or hard-deny condition:

```json
{
  "status": "refused",
  "reason": "out_of_scope" | "anti_spam_lockout" | "hard_deny",
  "explanation": "This intent involves Kubernetes RBAC, which iam-jit doesn't manage. iam-jit handles the AWS-IAM half of K8s deployments (IRSA roles, eks:get-token credentials).",
  "alternatives": [
    {
      "name": "K8s RBAC docs",
      "url": "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
      "why": "ServiceAccount + Role + RoleBinding is the right surface here"
    },
    {
      "name": "Hoop",
      "url": "https://hoop.dev",
      "why": "If you want a session-recorded kubectl proxy with RBAC enforcement"
    }
  ],
  "request_id": "..."
}
```

Refusal MUST always include either an alternative pointer or a
clear "why this can't be done" — never just a status code.

---

## Intent type catalog

Each intent type declares: `required_parameters`,
`optional_parameters`, `required_context`, `produces_actions`. The
recommender uses these to:

1. Validate the request payload (return 400 on missing required
   parameters).
2. Resolve which deployment context fields are needed (drives the
   `needs_context` response).
3. Map to action sets (the deterministic pattern library).

### AWS-service intents

These are the "free tier ships" intents — pure AWS IAM, no K8s
context needed.

| Intent type                       | Required params              | Required context | Produces                                |
| --------------------------------- | ---------------------------- | ---------------- | --------------------------------------- |
| `s3.read_objects`                 | `bucket`, `prefix`           | account, region  | `s3:GetObject` + bucket/prefix ARN      |
| `s3.list_bucket`                  | `bucket`                     | account, region  | `s3:ListBucket` with `s3:prefix` cond   |
| `s3.write_objects`                | `bucket`, `prefix`           | account, region  | `s3:PutObject` + bucket/prefix ARN      |
| `secretsmanager.read_one`         | `secret_name_or_pattern`     | account, region  | `secretsmanager:GetSecretValue` scoped  |
| `secretsmanager.list`             | `name_pattern`               | account, region  | `secretsmanager:ListSecrets`            |
| `secretsmanager.rotate_one`       | `secret_name`                | account, region  | `secretsmanager:UpdateSecretVersionStage`, etc. |
| `cloudwatch.read_logs`            | `log_group_name`, `time_range` | account, region | `logs:FilterLogEvents`, `logs:GetLogEvents` |
| `cloudwatch.tail_logs`            | `log_group_name`             | account, region  | same as read_logs                       |
| `ssm.read_parameters`             | `path_prefix`                | account, region  | `ssm:GetParametersByPath` scoped        |
| `dynamodb.read_table`             | `table_name`                 | account, region  | `dynamodb:Query`, `dynamodb:GetItem`    |
| `dynamodb.scan_table`             | `table_name`                 | account, region  | `dynamodb:Scan` (often flagged borderline) |
| `sqs.peek_messages`               | `queue_name`                 | account, region  | `sqs:ReceiveMessage` (no DeleteMessage) |
| `sqs.send_messages`               | `queue_name`                 | account, region  | `sqs:SendMessage`                       |
| `rds.connect`                     | `db_cluster_identifier`      | account, region  | `rds-db:connect` with resource ARN      |
| `rds.performance_insights`        | `db_instance_identifier`     | account, region  | `pi:GetResourceMetrics` scoped          |
| `kms.encrypt_decrypt`             | `key_id_or_alias`            | account, region  | `kms:Encrypt`, `kms:Decrypt` scoped     |

### Proxy / JIT-tool integrations (no proxy-specific intent types)

The recommender does NOT have proxy-specific intent types (no
`hoop.*`, no `teleport.*`, no `strongdm.*`). Integration with
proxy / JIT-access tools follows the **recipe pattern**:

1. The caller (an agent, CLI, or proxy wrapper) submits a normal
   intent — `s3.read_objects`, `cloudwatch.read_logs`,
   `dynamodb.read_table`, etc. — with the resources the session
   needs to touch.
2. The recommender produces a policy + issues STS credentials.
3. A small wrapper script writes those credentials to wherever the
   proxy reads its session credentials from (AWS Secrets Manager,
   a Vault path, env injection, etc.).

This keeps iam-jit decoupled from any single proxy's release
cycle, and lets the same recipe target Hoop, Teleport, StrongDM,
Boundary, or anything else without changes to the recommender.

For a worked example, see
[`docs/recipes/AGENT-IAMJIT-HOOP-EXAMPLES.md`](recipes/AGENT-IAMJIT-HOOP-EXAMPLES.md).

### IRSA intents (require K8s deployment context)

| Intent type                 | Required params                | Required context                                        | Produces |
| --------------------------- | ------------------------------ | ------------------------------------------------------- | -------- |
| `irsa.create_role_for_sa`   | `aws_actions`, `aws_resources` | `cluster_arn`, `oidc_provider_arn`, `namespace`, `sa_name` | A trust policy + permissions policy bound to the K8s SA |
| `irsa.scope_existing_role`  | `existing_role_arn`, `aws_resources` | `cluster_arn`, `oidc_provider_arn` | A scoped permissions-policy update for an existing IRSA role |

These are the intents that most heavily exercise the
`needs_context` flow on free tier. Pro tier auto-discovers
cluster + OIDC provider; free tier asks the caller.

### Out-of-scope intents (refused with pointer)

| Intent type                 | Refused with pointer to                              |
| --------------------------- | ---------------------------------------------------- |
| `k8s.create_serviceaccount` | K8s RBAC docs                                        |
| `k8s.rolebinding`           | K8s RBAC docs                                        |
| `k8s.exec_into_pod`         | Hoop / K8s RBAC                                      |
| `gcp.*`, `azure.*`          | "iam-jit is AWS-only" — link to project positioning  |
| `app.pundit_grant`          | Application-layer authz docs                         |

These return `status: "refused"`, `reason: "out_of_scope"` with the
alternative pointer.

---

## The needs_context flow (detailed)

### When it fires

The recommender's intent-handler declares `required_context`. After
parameter validation, the handler checks each required context field
against the merged context (request payload + Pro-tier
auto-discovery). If anything is missing, the handler returns
`needs_context` BEFORE attempting policy synthesis.

This is different from today's `narrow.py` behavior, which produces
narrowing questions AFTER generating a (broad) policy. Both can
coexist:

- `needs_context` (new): pre-generation, "I literally cannot produce
  a correct policy without these inputs."
- `narrowing_questions` (existing, in `narrow.py`): post-generation,
  "I produced a policy but it has wildcards you might want to
  scope down."

### Pro-tier auto-discovery

When the caller is on Pro/Team/Enterprise and has connected an AWS
account, the recommender consults a discovery cache before declaring
context missing. Discovery is implemented per resource type:

| Context key             | Discovered via                                                       |
| ----------------------- | -------------------------------------------------------------------- |
| `cluster_arn`           | `eks:ListClusters` filtered by name match in intent                  |
| `oidc_provider_arn`     | `iam:ListOpenIDConnectProviders` filtered by cluster                 |
| `bucket_arn`            | `s3:ListBuckets` exact match                                         |
| `kms_key_arn`           | `kms:ListAliases` + `kms:DescribeKey` filtered by use                |
| `vpc_endpoint_ids`      | `ec2:DescribeVpcEndpoints` filtered by service                       |
| `db_cluster_arn`        | `rds:DescribeDBClusters` exact match                                 |

The discovery cache is per-customer-account, TTL'd at 1 hour, and
invalidated on customer-initiated "rescan" action. Read-only IAM
permission required on the customer side
(`AWSReadOnlyAccess`-equivalent — documented in the Pro-tier setup
guide).

Auto-discovery never silently changes the policy the caller asked
for. If discovery resolves an ambiguous reference (e.g.,
`bucket: "uploads"` matches both `production-uploads` and
`staging-uploads`), the response is `needs_context` with the
`missing` field describing the disambiguation:

```json
{
  "status": "needs_context",
  "missing": [{
    "key": "bucket_arn",
    "type": "arn",
    "why": "Multiple buckets match \"uploads\" in this account.",
    "candidates": [
      "arn:aws:s3:::production-uploads",
      "arn:aws:s3:::staging-uploads"
    ]
  }]
}
```

### Caller correlation

When a caller responds to a `needs_context` by resubmitting with
filled-in context, they pass the original `request_id` in
`caller.request_id`. This:

- Marks the resubmission as a continuation, not a fresh request,
  for anti-spam purposes (a context-fill resubmission does NOT count
  against the per-purpose retry limit).
- Correlates the audit trail (one logical "Alice asked for X"
  spans all the back-and-forth).
- Caps continuation depth at 3 — if the caller can't supply the
  context after 3 rounds, the request is dropped.

---

## Tier behavior

| Behavior                                  | Free | Pro | Team | Enterprise |
| ----------------------------------------- | ---- | --- | ---- | ---------- |
| Structural recommendation (intent → actions + ARN templates) | ✓    | ✓   | ✓    | ✓          |
| Account-connected context auto-discovery  | —    | ✓   | ✓    | ✓          |
| LLM-tier override (Sonnet)                | —    | ✓   | —    | —          |
| LLM-tier override (Opus)                  | —    | —   | ✓    | ✓          |
| IRSA intents (with `needs_context`)       | ✓    | ✓   | ✓    | ✓          |
| Calibration regression tests in CI        | ✓    | ✓   | ✓    | ✓          |
| Custom intent types                       | —    | —   | —    | ✓          |
| Audit-report export                       | —    | —   | —    | ✓          |

LLM-tier override behavior: see `[[llm-pro-tier-architecture]]` in
memory. The LLM can RAISE a score / NARROW a policy but never lower
or broaden. The free-tier deterministic recommender is the floor.

---

## Anti-spam

Three layers, each with its own DDB store:

### Layer 1: hard rate limits per principal

Store: `recommend_rate_limits` (TTL'd hourly + daily counters).

Defaults (overridable per deployment):

| Principal kind | per hour | per day |
| -------------- | -------- | ------- |
| `human`        | 20       | 100     |
| `agent`        | 60       | 300     |
| `pod`          | 60       | 300     |

Above the cap → ALL requests route to admin even if they would
auto-approve, until the window resets. Admin can issue "trust this
principal" to clear early.

### Layer 2: same-purpose retry lockout

Store: `recommend_purpose_dedup` (10-minute TTL).

The recommender hashes the request shape:
`hash(intent.type + sorted(parameters) + principal.identifier)`.
Resource ARNs and actions go in; `natural_language` and timestamps
do not.

If two requests with the same hash arrive within 10 minutes:

- The second is **auto-routed to admin** (regardless of score),
  with the explanation "same purpose as REQ-... 4m ago — review
  why this is being retried."
- Forces the agent to either accept the original decision or
  escalate ONCE — can't iterate-shop the threshold.

Context-fill resubmissions (same `request_id`) are exempt — they're
the same logical request, not a retry.

### Layer 3: boundary-probe detection

Store: `recommend_boundary_probe` (30-minute sliding window).

Track each principal's recent grant scores. If 3+ grants from the
same principal cluster within 0.05 of the deployment's auto-approve
threshold inside 30 minutes:

- Flag the principal in the admin dashboard as `boundary_probing`.
- Disable auto-approval for that principal for 1 hour cooldown.
- All requests from the principal during cooldown route to admin.

This is the layer that catches deliberate gaming. Layers 1 and 2
are mechanical; Layer 3 is the suspicious-pattern catch.

---

## Calibration loop

### Corpus structure

```
tests/calibration/intent_to_policy/
  corpus/
    aws/
      s3-read-bucket-prefix.json
      cloudwatch-tail-log-group.json
      secretsmanager-read-one.json
      ...
    hoop/
      rails-console-for-payments-app.json
      rake-reports-export.json
      kubectl-exec-debug-worker-pod.json
      ...
    irsa/
      create-role-for-app-runtime-sa.json
      scope-existing-role-add-bucket.json
      ...
  fixtures/
    opus_responses_cache.json
  runners/
    compare_recommender_to_opus.py
    structured_policy_diff.py
  reports/
    latest.html
```

### Corpus entry shape

```json
{
  "id": "s3-read-bucket-prefix",
  "intent": {
    "type": "s3.read_objects",
    "natural_language": "let me grab the upload manifests from yesterday",
    "parameters": {
      "bucket": "production-uploads",
      "prefix": "manifests/2026-05-14/"
    }
  },
  "context": {
    "account_id": "123456789012",
    "region": "us-east-1"
  },
  "expected": {
    "policy_shape": {
      "actions_must_include": ["s3:GetObject"],
      "actions_must_exclude": ["s3:PutObject", "s3:DeleteObject", "s3:*"],
      "resource_must_include": "arn:aws:s3:::production-uploads/manifests/2026-05-14/*",
      "resource_must_exclude_patterns": ["arn:aws:s3:::*"],
      "conditions_should_include": [{"Bool": {"aws:SecureTransport": "true"}}]
    },
    "score_band": [0.0, 0.3]
  },
  "notes": "Narrow read-only object fetch with prefix scoping. Should be auto-approve in any sane threshold."
}
```

The `expected.policy_shape` is the **structural assertion**, NOT a
literal-policy match. This is critical: two semantically equivalent
policies can be expressed many ways (action ordering, single-string
vs list, etc.). The diff harness checks structural equivalence, not
text identity.

### Comparison harness

`runners/compare_recommender_to_opus.py` runs each corpus entry
through:

1. iam-jit's deterministic recommender → policy A
2. Opus 4.7 prompted with the same intent + a calibration prompt
   that asks for an IAM policy in JSON → policy B
3. Structured diff (`structured_policy_diff.py`):
   - Action-set diff (set difference both directions)
   - Resource-pattern diff (does A's resource ARN cover B's? Vice
     versa?)
   - Condition diff (which conditions does each include?)
4. Score the diff: `false_positive` (A includes what B excludes —
   over-permissive), `false_negative` (A excludes what B includes —
   under-permissive), `equivalent`, `divergent`.

Output: per-entry verdict + aggregate report.

### Opus response caching

Opus calls are cached at `fixtures/opus_responses_cache.json` keyed
on `hash(intent + context)`. Re-running the harness uses the cache
unless `--refresh-opus` is passed. This keeps regression runs cheap
(~free) and reproducible. Refresh quarterly or when a corpus entry
changes.

### Meta-loop (avoid converging on Opus's biases)

Opus is not infallible at IAM. If we only optimize for "matches
Opus," we converge on Opus's mistakes. Mitigations:

1. Spot-check ~10% of Opus responses against AWS service docs.
   Track corrections — when Opus is wrong AND iam-jit was right, the
   corpus entry's `expected` is iam-jit's, not Opus's.
2. Track Opus's *additions* separately from its *omissions*.
   Additions are the suspicious direction (over-conservatism dilutes
   least privilege). If Opus systematically adds `kms:Decrypt`
   everywhere, that's a flag, not ground truth.
3. Periodic human-IAM-SME review of corpus entries (~annually for
   the active corpus).

### Gate criteria

For free-tier launch:

- 95% action-set semantic equivalence on baseline corpus
- 90% resource-pattern equivalence on baseline corpus
- 0 entries where iam-jit produces a policy that scores higher
  than Opus's by >0.2

CI gate blocks merge if regression on any criterion.

### Seed corpus harvest

Source priority for the first 100 corpus entries:

1. **Real Hoop role requests** harvested from the user's company
   Jira ([[hoop-partnership-strategy]] — DEVOPS-18870, DEVOPS-18871,
   etc.). These are gold: real production needs.
2. **AWS service docs canonical examples** — every "least privilege
   for X" example in the AWS IAM docs.
3. **Top-N AWS API calls by call volume** — public CloudTrail event
   reference, pick the top 50.
4. **Adversarial cases inverted** — for each scoring corpus entry
   that exists today (`policy → score`), construct the matching
   intent and assert the recommender produces something equivalent
   to the input policy.

Target 100 entries before launch-ready free tier; 300 entries by
end of Q3 2026.

---

## Out-of-scope refusal protocol

Refusal is a first-class feature, not a fallback. The protocol:

1. The recommender's intent registry includes both in-scope and
   out-of-scope intent types.
2. Out-of-scope intents have their own handlers that emit
   `status: "refused"` with `reason: "out_of_scope"` and
   `alternatives: [...]`.
3. The freeform fallback (when `intent.type == "freeform"`) runs the
   pattern matcher; if no patterns match AND the natural language
   contains K8s-RBAC / GCP / Azure / app-layer signals, it routes to
   the appropriate refusal handler.
4. Every refusal includes at least one alternative pointer.

Test coverage for refusals lives at
`tests/calibration/refusals/`. Each entry asserts the pointer text
and alternative URL.

---

## Implementation phases

### Phase 0 (pre-launch): no shipping changes
- Spec written (this doc).
- Corpus seed (~50 entries) harvested from existing patterns +
  Hoop / Jira tickets. Stored at
  `tests/calibration/intent_to_policy/corpus/`.
- Calibration harness shell (Opus call + diff, no gate yet).

### Phase 1 (W2 post-launch): free-tier recommender API
- `POST /api/v1/recommend` endpoint, structural-only.
- Intent type registry covering S3, CloudWatch, Secrets Manager,
  SSM, DynamoDB, SQS, RDS, KMS.
- `needs_context` response shape implemented.
- Calibration harness wired into CI (warn-only first).

### Phase 2 (W3-W4 post-launch): Proxy-integration recipes
- Recipe doc + wrapper script productized as
  `iam-jit grant --for-secret <secret-arn>` — issues a grant via
  the normal recommender flow and writes the STS triple to a
  Secrets Manager secret a proxy (Hoop / Teleport / etc.) reads
  its session credentials from.
- No proxy-specific intent types added. No fork of any proxy
  required. Pilot deploy at first design-partner customer.

### Phase 3 (W5-W6 post-launch): anti-spam stores
- Three DDB tables shipped (rate / dedup / boundary-probe).
- Layer logic implemented per spec above.

### Phase 4 (W7-W8 post-launch): Pro-tier auto-discovery
- Discovery cache + per-resource-type discoverers.
- Read-only AWS account connection flow on Pro tier.
- Disambiguation `needs_context` shape.

### Phase 5 (W9+ post-launch): LLM-tier override
- Pro tier (Sonnet) + Team tier (Opus) backends.
- LLM-can-raise-never-lower semantics
  ([[llm-pro-tier-architecture]]).
- Per-LLM calibration corpus (separate from the deterministic one).

---

## Open questions

1. **Intent type granularity vs explosion.** The catalog above has
   ~25 intent types. At what point does it become
   `aws-cli-cheat-sheet-as-intents` and stop being useful? Need to
   draw the line — probably "the most common 50 are intents; the
   long tail uses freeform + the deterministic pattern matcher."
2. **Hoop session-open latency budget.** Adding an iam-jit roundtrip
   to every Hoop session-open adds 100-500ms. Acceptable for human
   sessions; may be felt by automated agents doing many sessions.
   Mitigation: short-lived (5min) caching keyed on intent hash. Need
   to measure end-to-end before committing to the V0 design.
3. **`needs_context` UX in the MCP server.** The MCP server's
   `recommend` tool would need to either return the missing list as
   a structured tool result (and let the agent prompt the user) or
   bail with a single-shot error. The agent-prompts-user shape is
   richer but requires the agent's host to support tool-result-with-
   followup. Check Claude / Cursor / Devin tool-result handling.
4. **Score-band tunability per deployment.** Auto-approve threshold
   is currently a global config. Customers will want it per-intent-
   type ("auto-approve all S3-read; require admin for any IAM
   action"). Adds spec complexity; probably Phase 4.
5. **Refusal-pointer rot.** Linked alternatives (Hoop URL, K8s docs
   URL) will rot over time. Need a dead-link checker in CI for the
   refusal corpus.

---

## Related memos

- `[[hoop-partnership-strategy]]` — why Hoop integration is the
  highest-leverage adoption path
- `[[aws-only-positioning]]` — scope boundary that constrains the
  refusal protocol
- `[[llm-pro-tier-architecture]]` — LLM-can-raise-never-lower
  semantics for Phase 5
- `[[calibration-quality-bar]]` — don't ship scorer-adjacent
  features without their own calibration corpus (this spec
  satisfies that bar for the recommender)
- `[[adversarial-loop-process]]` — process discipline that the
  recommender calibration loop is modeled after
- `[[principal-whitelist]]` — orthogonal admin gate; interacts
  with anti-spam Layer 1 (whitelisted principals get higher caps)
