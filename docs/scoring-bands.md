# Risk scoring bands: what each level means

The iam-risk-score engine outputs a single number 1-10 for any IAM
policy. This page explains what each band means in concrete terms,
with example policies and typical auto-approval guidance. It's a
trust artifact — when a score lands, you should be able to
understand *why* without reading the rules source.

The bands are calibrated against an adversarial corpus of 2,000+
policies and validated round-by-round against Opus-4.7 as an
independent oracle. Calibration discipline is the product moat —
see [docs/research/IAM-BYPASS-RESEARCH.md](research/IAM-BYPASS-RESEARCH.md).

| Score | Tier | Meaning | Typical examples | Auto-approve? |
|------:|------|---------|------------------|---------------|
| **1** | trivial | Read a single named resource; no mutation potential | `s3:GetObject` on one bucket; `ec2:DescribeInstances` on one instance ID | ✅ |
| **2** | very-low | Read a small set of named resources | Read 2-3 specific S3 objects + their tags | ✅ |
| **3** | low | Read a service's metadata at scale, no resource content | `ec2:Describe*` / `ListBuckets` — names + statuses only | ✅ |
| **4** | low-medium | Broader read scoped to one service; or single narrow write | `s3:Get*` on a single bucket; `dynamodb:PutItem` on one table | ✅ (default threshold) |
| **5** | medium | High-impact mutation on a narrow ARN | `route53:ChangeResourceRecordSets` on one zone; `lambda:UpdateFunctionConfiguration` on one function | ⚠ human review recommended |
| **6** | medium-high | Service-wide wildcard read on a normal service | `ec2:*` on `Resource: *` filtered to read-only verbs; broad logs read | ⚠ human review |
| **7** | high | Secret-bearing read on broad resource; or high-risk single action on `Resource: *` | `secretsmanager:GetSecretValue` on `*`; `s3:GetObject` on bucket-name wildcards | ❌ |
| **8** | very-high | `service:*` on a sensitive service (kms, secretsmanager, iam); high-impact mutation on broad resource; code-execution primitive on `*` | `kms:*` on `*`; `lambda:UpdateFunctionCode` on `*`; `cloudformation:CreateStack` on `*` | ❌ |
| **9** | critical | Catastrophic single-action (irreversible / privesc / defense-evasion); cross-account exfil primitive; code-exec + PassRole composition | `iam:AttachRolePolicy`; `cloudtrail:StopLogging`; `organizations:CloseAccount`; `iam:PassRole` + `lambda:CreateFunction` | ❌ never auto |
| **10** | catastrophic | Effective full account admin in one statement | `Action: "*", Resource: "*"`; `NotAction: [] + Resource: "*"`; `Principal: "*"` on a resource policy | ❌ never auto |

## How to read this

**Bands 1-4 (auto-approve zone):** these are operations a junior
developer might do dozens of times a day. The engine recognizes them
as routine and lets them through without ceremony. The default
auto-approve threshold is 5 — anything ≤ 4 auto-approves.

**Bands 5-6 (human-review zone):** the action is plausibly legitimate
but warrants someone glancing at it. A `route53:ChangeResourceRecordSet`
on a production zone is the canonical example — usually fine, but
"usually" isn't good enough to skip review.

**Bands 7-8 (high-risk zone):** the engine is saying "this could
realistically break production or leak data if used wrong." Reviewers
should ask: *does the requester need this specific action, or would a
narrower scope work?*

**Bands 9-10 (catastrophic zone):** the engine is saying "this single
statement is enough to lose the account if misused." These can be
approved — they're legitimate for some workflows — but only with
explicit human sign-off and an audit-log entry that says *who*
approved *what* *why*. The engine never silently lets a 9 through.

## Why scores can be lower than you expect

The engine prefers conservative scoring on resource-narrow inputs.
A `dynamodb:Query` on a specific table ARN scores 1-2 even though
querying-everything would be 7. **Resource scope is doing real
risk-reduction work**, and we credit it. This is one of the most
common surprises — "I expected this to score higher because the
action is dangerous." It scores low *because of the resource*.

## Why scores can be higher than you expect

The engine assumes the worst-case interpretation of ambiguous
grammar. `Effect: "allow"` (lowercase), `Statement: {dict}` (not
list), `Principal: "*"`, missing `Effect`, vacuous Conditions — all
get scored as if AWS would treat them at face value, because AWS
*does* treat them that way. This is also where many real-world
bypasses live, and where the calibration discipline (rounds of
adversarial testing) pays off.

## What the engine WON'T tell you

The score is about *what the policy permits*, not about *whether
the requester should have it*. A `secretsmanager:GetSecretValue`
on `arn:aws:secretsmanager:...:secret:prod-db-password` scores 4
(narrow read on a high-risk action). That's the right risk score
for the policy. Whether *this specific human* should be allowed to
read that secret is a separate access-control question — the
JIT-approval workflow handles that, not the scorer.

## Calibration confidence

The deterministic engine is calibrated to:
- **100% within ±1 score** against Opus-4.7 on a 1,500+ policy
  AWS-managed corpus.
- **Adversarial-tested** across 9+ rounds of black-box and
  white-box agent attacks (~3,000 corpus YAMLs total).
- **No silent bypasses found** against the engine since round 6
  closed Principal + Condition handling.

See [scripts/round-stats.py](../scripts/round-stats.py) for the
per-round convergence trend.

## Future: per-customer calibration

Some organizations consider certain actions higher-risk than the
default scorer does (e.g. a fintech might treat any `kms:*` as
catastrophic regardless of resource). The engine accepts admin
context to extend the sensitive-service and high-impact-action
lists per organization — without ever *lowering* the default
floor. See [TUNING-RISK.md](TUNING-RISK.md) for the workflow.
