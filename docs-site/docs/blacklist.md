# Action blacklist

A per-deployment list of action patterns iam-risk-score will refuse
to score. Different from the risk *score*: scoring tells you "how
dangerous is this policy"; the blacklist says "we won't process THIS
at all."

## When to use it

The blacklist is for **categorical rules** — operations your
organization has decided are off-limits via JIT under any
circumstances:

- "We never grant `iam:CreateAccessKey` via JIT — credentials come
  from onboarding only."
- "We never auto-process anything that touches CloudTrail."
- "Account-closure / org-leave is admin-console-only, not JIT."

If you want the request reviewed (just at a higher risk level), use
the risk score's threshold. The blacklist is for the "no, never,
period" case.

## How to add rules

Three paths:

### Path 1: Adopt a starter template

```bash
# Via the iam-jit admin CLI (when iam-jit is deployed):
iam-jit admin blacklist apply --template ban-catastrophic-actions
```

Templates are documented below. Each ships with sensible rule names
and reasons that surface in audit logs.

### Path 2: Add individual rules via API (self-hosted iam-jit)

```bash
# Replace https://iam-jit.your-domain.example with your self-hosted
# iam-jit endpoint. The hosted api.iam-risk-score.com endpoint was
# dropped 2026-05-24 — see [[no-hosted-saas]].
curl -X POST https://iam-jit.your-domain.example/api/v1/admin/blacklist \
  -H "Authorization: Bearer <admin-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_id": "ban-create-access-key",
    "pattern": "iam:CreateAccessKey",
    "reason": "Long-lived credentials must come from onboarding."
  }'
```

### Path 3: Via the admin UI

`https://iam-jit.your-domain.com/admin/blacklist` — drag-and-drop
rule management. Same audit-logging applies.

## Pattern syntax

Glob-style on the `service:Action` form:

| Pattern | Matches |
|---|---|
| `iam:CreateAccessKey` | Exact action |
| `iam:*AccessKey*` | Any IAM action with "AccessKey" in the name |
| `cloudtrail:*` | Every action in CloudTrail |
| `*:Delete*` | Every Delete* action in every service |

Patterns are matched case-insensitively (AWS IAM is case-insensitive
on action names, so the blacklist must be too).

**The bare `*` pattern is rejected** — it would block every request.

## Oracle-attack consideration

If the API tells anonymous callers exactly WHICH rule fired, an
attacker could bisect their payload to map the rule set. The
mitigation is built in:

- **Authenticated callers** receive specific detail (rule_id, matched
  action, reason). They've already passed access control; we want
  them to fix their policy.
- **Anonymous callers** receive ONLY a generic 400 response. No
  signal about which probe was "warmer."
- **Audit log** records every hit (with source IP + matched action
  + rule_id) regardless of caller — operators can detect bisection
  patterns and respond.
- **Rate limiting** (30 req/min/IP on the hosted API) makes bisection
  against AWS's ~400-service IAM action space prohibitively slow.

You can tighten further by adding edge-WAF rules to harder-throttle
sources that hit `400` responses repeatedly.

## Default templates

### `ban-catastrophic-actions`

The "we never want these via JIT" starter set. Account closure, org
leaving, CloudTrail tampering, KMS key deletion. Every action here
has essentially zero legitimate need to flow through a JIT-IAM
workflow.

| Rule | Pattern | Why |
|---|---|---|
| ban-close-account | `account:CloseAccount` | Irreversible, never JIT |
| ban-leave-org | `organizations:LeaveOrganization` | Drops governance + billing |
| ban-cloudtrail-tampering | `cloudtrail:DeleteTrail` | Breaks audit evidence |
| ban-cloudtrail-stop | `cloudtrail:StopLogging` | Stops audit logging |
| ban-schedule-key-deletion | `kms:ScheduleKeyDeletion` | Irreversible data loss |

### `ban-credential-minting`

Credential-creation primitives that should flow through onboarding,
not JIT.

| Rule | Pattern | Why |
|---|---|---|
| ban-create-access-key | `iam:CreateAccessKey` | Long-lived credentials should come from onboarding |
| ban-update-login-profile | `iam:UpdateLoginProfile` | Console password mutation |
| ban-create-service-specific-cred | `iam:CreateServiceSpecificCredential` | Persistent service credentials |

### `ban-iam-escalation-primitives`

The IAM mutations that compose into privilege escalation.

| Rule | Pattern | Why |
|---|---|---|
| ban-attach-role-policy | `iam:AttachRolePolicy` | Classic escalation primitive |
| ban-put-role-policy | `iam:PutRolePolicy` | Inline-policy bypass |
| ban-update-assume-role-policy | `iam:UpdateAssumeRolePolicy` | Trust-policy rewrite |
| ban-create-policy-version | `iam:CreatePolicyVersion` | Silent-swap escalation |

### `ban-audit-evasion`

Actions that disable detection / response capabilities.

| Rule | Pattern | Why |
|---|---|---|
| ban-cloudwatch-disable-alarms | `cloudwatch:DisableAlarmActions` | Suppresses detection |
| ban-config-disable | `config:StopConfigurationRecorder` | Drops compliance posture |
| ban-config-delete | `config:DeleteConfigurationRecorder` | Destroys evidence |
| ban-guardduty-disable | `guardduty:UpdateDetector` | Disables threat detection |
| ban-guardduty-delete | `guardduty:DeleteDetector` | Removes detection |

## Choosing a starting blacklist

Most deployments should start with **`ban-catastrophic-actions` +
`ban-audit-evasion`**. Those two cover the "we obviously never want
this" cases without blocking common legitimate work.

Add `ban-iam-escalation-primitives` if your JIT use case never grants
IAM-mutation rights (most organizations).

Add `ban-credential-minting` if you have a separate onboarding
pipeline for long-lived credentials.

You can also compose your own. Each rule is independent; rules can
be added and removed live without redeploying.

## How blacklist interacts with the score endpoint

```
POST /api/v1/score
  │
  ├─ 1. Auth check (IAM_JIT_SCORE_API_KEY if configured)
  ├─ 2. Rate limit (anonymous only; authenticated bypass)
  ├─ 3. Prompt-injection scan
  ├─ 4. Blacklist check  ◄── you are here
  ├─ 5. Deterministic scoring
  └─ 6. (Optional) LLM narrative when a backend is configured
```

Blacklist fires BEFORE scoring — if a request is blacklisted, no
scoring happens, no Bedrock invocation, no log of the policy content
(only the fingerprint + matched action + rule_id is audit-logged).
This means a blacklist hit is the cheapest reject path in the
pipeline.

## Tests

The blacklist is covered by 20 dedicated unit tests
(`tests/test_blacklist.py`) + 4 integration tests on the score
endpoint (`tests/test_routes_score.py`). Run with:

```bash
make test
```

The test suite verifies: pattern matching (exact, glob, case-
insensitive), NotAction-bypass-prevention, the empty-store no-op,
malformed-policy robustness, the bare-`*` rejection, all 4 templates,
the oracle-attack defense (anonymous calls get generic detail), and
the authenticated-caller-specific-detail UX.
