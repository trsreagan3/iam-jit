# 100-prompt sufficiency loop (2026-05-16)

## Executive summary

Ran 111 realistic, varied prompts (incident response, forensics, feature work, compliance, cost, exploration, targeted writes, DBA, uncertain, agent-context, edge) through the iam-jit policy generator + scorer via the MCP entry points (`_generate_for_mcp` and `_score_for_mcp`). Evaluated each result for **sufficiency** (would a real engineer/agent be able to make progress?) and **sub-threshold** (`score < 5`, auto-approval gate).

Headline finding: **joint rate is 1.8% (2 of 111)**. The product's strategic thesis is that the generator's value lies in producing policies that are simultaneously sufficient AND sub-threshold so that user/agent can do as much as possible without crossing the human-approval bottleneck — at present, the generator clears that bar in only 2 of 111 cases. Two failure modes dominate: (1) **28 prompts return no policy at all** (the AWS-managed-baseline fallback that was supposed to close this regression is matching too narrowly — vague-but-clear incident prompts like "payment Lambda timing out again" still produce empty output); (2) for the 83 prompts that do produce a policy, the scorer over-penalizes the very baselines the generator was just instructed to fall back to (60 of those 83 are sufficient-but-≥5, primarily because `ReadOnlyAccess`, `ExploreReadOnlyWithSensitiveExclusions`, and `SecurityAudit` all score in the 7–9 range due to `*` resources or action-name wildcards). The result is a generator that, for most realistic prompts, either gives the user nothing or gives them something the policy-on-policy gate will tell them to escalate.

## Headline metrics

| Metric | Value |
|---|---|
| Total prompts | **111** |
| Sufficient (policy enables the task) | **62 (55.9%)** |
| Sub-threshold (score < 5) | **4 (3.6%)** |
| **Joint (sufficient AND sub-threshold)** | **2 (1.8%)** |
| Empty policy (no-policy regression) | 28 (25.2%) |
| Over-flagged (sufficient but score ≥ 5) | 60 (54.1%) |

Per-category joint rates (the key product metric, broken out by request shape):

| Category | Total | Sufficient | Sub-threshold | **Joint** |
|---|---:|---:|---:|---:|
| agent-context | 10 | 8 | 0 | **0** |
| compliance | 10 | 8 | 2 | **2** |
| cost | 8 | 4 | 0 | **0** |
| dba | 5 | 4 | 0 | **0** |
| edge | 10 | 6 | 0 | **0** |
| exploration | 10 | 7 | 0 | **0** |
| feature | 15 | 5 | 1 | **0** |
| forensics | 10 | 4 | 0 | **0** |
| incident | 15 | 8 | 0 | **0** |
| targeted-write | 10 | 3 | 1 | **0** |
| uncertain | 8 | 5 | 0 | **0** |

The only category that produced any joint hits is compliance, and both hits are EC2-Describe + Config-Describe shaped narrow read patterns — every other category is at 0/N joint.

## Top failure patterns

### Cluster 1 — no-policy / baseline fallback missed (28 of 49 insufficient cases, 57%)

The `aws_managed_catalog.best_baseline` lookup is failing to fire for prompts that are clearly in scope of an existing baseline. Examples:

| Prompt | Expected baseline | Actually got |
|---|---|---|
| "payment service is throwing 500s, help me figure out why" | `ExploreReadOnlyWithSensitiveExclusions` | empty |
| "ugh, the payment Lambda is timing out again" | `lambda-invoke` or `CloudWatchReadOnlyAccess` | empty |
| "ALB targets keep flapping unhealthy in prod-us-east-1" | `ReadOnlyAccess` or ec2+elb read | empty |
| "find every AssumeRole event into the prod account in the last 24h" | `SecurityAudit` | empty |
| "I just inherited this AWS account, where do I even start" | `ExploreReadOnlyWithSensitiveExclusions` | empty |
| "get the lay of the land — what's running in prod" | `ReadOnlyAccess` | empty |
| "walk me through the resources in this account" | `ExploreReadOnlyWithSensitiveExclusions` | empty |
| "find the unattached EBS volumes wasting money" | `ec2-describe` or `ReadOnlyAccess` | empty |
| "the integration test suite is failing intermittently" | `ExploreReadOnlyWithSensitiveExclusions` | empty |
| "I think we have a problem but I don't know which service is at fault" | `ExploreReadOnlyWithSensitiveExclusions` | empty |

This is the no-output regression the baseline-fallback feature was supposed to close. It DOES fire for some prompts ("look around the staging account" → Explore; "p0 incident" → Explore) but the matching is brittle — common synonyms ("inherited", "walk me through", "lay of the land", "integration tests failing") that humans clearly recognize as exploration don't trigger.

### Cluster 2 — read-only baseline returned for a write task (12 of 49)

The generator either matched a read-only pattern when the prompt clearly asked for a write, or matched a read-only baseline policy (`AmazonRDSReadOnlyAccess`, `AmazonS3ReadOnlyAccess`) when the prompt requested provisioning. Examples:

- "rotate the API keys in secrets manager for prod-api" → `secrets-read` (no `PutSecretValue`)
- "restart the failing ECS task" → `ecs-describe` (no `StopTask`/`UpdateService`)
- "build a CloudFront distribution for the new docs site" (access_type=read-write) → `cloudfront-describe` (no `CreateDistribution`) — and ironically THIS is one of the 4 sub-threshold scores (4), so insufficient AND auto-approved
- "tag the prod EC2 instances with cost-center=eng-platform" → `ec2-describe` (no `CreateTags`) — another sub-threshold-but-insufficient case (score=1)
- "provision an RDS Postgres instance" → `AmazonRDSReadOnlyAccess`
- "set up a read replica of analytics-prod RDS" → `AmazonRDSReadOnlyAccess`
- "update the S3 bucket policy on acme-public-assets to allow new CDN" → `AmazonS3ReadOnlyAccess`
- "Claude agent — user wants a write op: please rotate the staging-db password" → `secrets-read`

The pattern matchers favor read-only matches even when `access_type=read-write` and the prompt verbs are clearly write-intent (`rotate`, `restart`, `scale up`, `delete`, `update`, `tag`, `provision`, `create`, `build`).

### Cluster 3 — forensics missing CloudTrail (5 of 49)

Forensic / "who-did-what" prompts kept matching the resource-type-of-interest pattern (s3-read, lambda-invoke, iam-role-read, secrets-read) instead of the SecurityAudit baseline that contains CloudTrail. CloudTrail is the load-bearing service for forensic questions; without it, the policy is fundamentally insufficient even if it scores low.

- "did anyone touch the prod-secrets bucket in the last 7 days" → `AmazonS3ReadOnlyAccess` only (no `cloudtrail:LookupEvents`)
- "which Lambda invoked the delete-user API at 2am UTC last night" → `lambda-invoke` only
- "look up everything that role did yesterday" → `iam-role-read` only
- "did a Secrets Manager secret get read by someone outside the app role" → `secrets-read` only

`SecurityAudit` IS in the catalog and it DOES fire for prompts that mention "audit" or "security audit" — but not for natural-language forensic phrasing.

## Over-flagged patterns (sufficient but score ≥ 5)

60 of 111 prompts (54%) produced a policy that I judged sufficient but the scorer rated ≥5 (medium or high), pushing them above the auto-approval threshold. The cluster is dominated by the **catalog baselines themselves**: when the generator legitimately falls back to a managed-policy baseline, the resulting policy contains action-name wildcards (`*:Describe*`, `rds:Describe*`) and broad resources (`*`) — which the scorer correctly flags as broad, but in the context of "this is intentionally a baseline we just landed on because no narrower pattern matched," the gate fires every time.

Score distribution of the 60 over-flagged sufficient cases:

| Score | Count | Typical pattern |
|---|---:|---|
| 5 | 3 | `AmazonRDSReadOnlyAccess` (`rds:Describe*`, `rds:List*` on `*`) |
| 6 | 12 | `SecurityAudit` baseline (13 actions across 8 services on `*`) |
| 7 | 11 | `s3-read`, `AmazonS3ReadOnlyAccess`, `secrets-read`, `ecs-describe`, `CloudWatchReadOnlyAccess` |
| 8 | 8 | `lambda-invoke`, `sqs-receive`, `kms-encrypt`, `athena-query`, `step-functions-execute` |
| 9 | 26 | `ReadOnlyAccess`, `ExploreReadOnlyWithSensitiveExclusions`, `DatabaseAdministrator`, `DataScientist`, `lambda-deploy`, `ecs-deploy` |

The structural problem: **the baseline-fallback path produces policies the scorer is designed to flag**. The two systems are not co-designed. The scorer treats `*` resources as a broad-cross-resource-access risk factor (correct, in isolation), but the baseline path explicitly returns broad-resource policies because the prompt didn't include a resource name to narrow on. Without a coupling between "this came from the baseline fallback" and the scorer's broad-resource heuristic, every baseline emission overshoots the auto-approval gate.

## 10 specific calibration findings

### Finding 1 — Baseline fallback misses common exploration synonyms

- Prompt: `"I just inherited this AWS account, where do I even start"`
- Generated: empty policy (`unmatched_reason`: "No heuristic pattern matched the task description")
- Score: n/a
- Judgment: INSUFFICIENT — this is the archetypal Explore prompt
- Recommendation: `aws_managed_catalog.best_baseline` should match `inherited`, `lay of the land`, `walk me through`, `where do I start`, `first day`, `treat me like a junior` as exploration synonyms. The `use_case_tags` for `ExploreReadOnlyWithSensitiveExclusions` already include `look-around`, `discovery`, `general-read` — extending the tag set or adding fuzzy matching would fix ~10 of the 28 empty-policy cases.

### Finding 2 — "Something is broken in prod" prompts produce nothing

- Prompts: `"payment service is throwing 500s, help me figure out why"`, `"checkout flow is broken in prod, customers complaining"`, `"the integration test suite is failing intermittently, could be anything"`, `"I think we have a problem but I don't know which service is at fault"`
- Generated: empty policy in all four cases
- Judgment: INSUFFICIENT — these are 100% of an SRE's day-to-day, and `ExploreReadOnlyWithSensitiveExclusions` is exactly the right answer
- Recommendation: add `broken`, `down`, `failing`, `500s`, `throwing errors`, `customers complaining`, `incident`, `p0`, `urgent`, `something's wrong`, `not sure`, `something weird` to the Explore baseline's use-case tags. This is the highest-value catalog change in the corpus.

### Finding 3 — Forensic prompts need to be routed to SecurityAudit, not the resource-of-interest read pattern

- Prompt: `"did anyone touch the prod-secrets bucket in the last 7 days"`
- Generated: `AmazonS3ReadOnlyAccess` (s3:Get*, s3:List*, s3:Describe* on `*`)
- Score: 7 (high)
- Judgment: INSUFFICIENT — without `cloudtrail:LookupEvents` the engineer cannot answer "who touched it"; S3 itself doesn't record reads in its own API
- Recommendation: when the prompt contains forensic verbs (`who`, `accessed`, `touched`, `invoked`, `trace`, `audit who`, `look up everything ... did`), the matcher should prefer `SecurityAudit` (or a new `cloudtrail-investigate` pattern) over the resource-read pattern. Better: route to BOTH (CloudTrail for the trail + the resource-read for context).

### Finding 4 — Read-only baseline returned for explicit write requests

- Prompt: `"build a CloudFront distribution for the new docs site"` with `access_type=read-write`
- Generated: `cloudfront-describe` (only Get/List actions)
- Score: 4 (sub-threshold) — but INSUFFICIENT (no `cloudfront:CreateDistribution`)
- Judgment: INSUFFICIENT — and worse, it's auto-approvable, so the user/agent gets a green light on a policy that can't do the task
- Recommendation: when `access_type=read-write` and the prompt verb is in {build, create, provision, set up, deploy, spin up, add new, wire up}, the matcher must NOT return a `*-describe`/`*-read` pattern. This is one of the worst failure modes — the user/agent will proceed thinking they're set, hit a permission error mid-task, and then need to re-request.

### Finding 5 — `ec2-describe` for write tasks is sub-threshold AND insufficient

- Prompt: `"tag the prod EC2 instances with cost-center=eng-platform"` with `access_type=read-write`
- Generated: `ec2:Describe*` (9 read actions, no `ec2:CreateTags`)
- Score: 1 (low)
- Judgment: INSUFFICIENT for the tagging task
- Recommendation: same as Finding 4. The score-1 result here is a confidence trap for agents — they'll auto-proceed and fail at runtime. The `tag-resources` use case needs its own pattern emitting `ec2:CreateTags` scoped to the resource ARN.

### Finding 6 — Baseline emissions are over-scored by their own design

- Prompt: `"look around the staging account, I'm new on the team"`
- Generated: `ReadOnlyAccess` baseline (`*:Describe*`, `*:Get*`, `*:List*`, etc. on `*`)
- Score: 9 (high)
- Judgment: SUFFICIENT (the entire point of an Explore-style grant) but the score will block auto-approval
- Recommendation: when a policy is returned via the AWS-managed-baseline fallback, the scorer should apply a **baseline credit** — the broad-resource finding is already accounted for in the choice to return a baseline. Either (a) lower the score by 2 for any policy whose `baseline_provenance` is set, OR (b) add a new scorer factor "policy is a known AWS-managed read-only baseline (auditor-comprehensible)" that reduces the broad-resource penalty. Without this, the entire baseline-fallback path is wasted from a joint-rate perspective.

### Finding 7 — Wrong-service match: SQS notification queue → DataScientist

- Prompt: `"set up an SQS queue for the new notification pipeline"`
- Generated: `aws-managed:DataScientist` (athena, emr, glue, kinesis, lakeformation, s3 — 17 actions)
- Score: 9 (high)
- Judgment: INSUFFICIENT — wrong service entirely
- Recommendation: keyword-match weighting bug — "pipeline" likely triggered DataScientist's `use_case_tags`. SQS-specific verbs (`SQS queue`, `notification queue`, `dead-letter queue`) need to dominate. There's no `sqs-create` pattern in the catalog at all.

### Finding 8 — KMS-encrypt write pattern returned for KMS read audit

- Prompt: `"inventory all KMS keys and their rotation status for the auditor"` (access_type=read-only)
- Generated: `kms-encrypt` pattern (write-shape KMS actions)
- Score: 8 (high)
- Judgment: SUFFICIENT in services but WRONG shape (encrypt is a write op, prompt is a read audit)
- Recommendation: the matcher should respect `access_type` more strictly — a read-only request should never match an `*-encrypt` / `*-publish` / `*-deploy` write pattern. Add an `access_type=read-only` filter on pattern selection.

### Finding 9 — Forensics: lambda-invoke without CloudTrail

- Prompt: `"which Lambda invoked the delete-user API at 2am UTC last night"`
- Generated: `lambda:GetFunction`, `lambda:InvokeFunction`, `lambda:ListFunctions` on `arn:aws:lambda:*:*:function:*`
- Score: 8 (high)
- Judgment: INSUFFICIENT — Lambda APIs don't tell you "who invoked"; CloudTrail does
- Recommendation: same as Finding 3. The `lambda-invoke` pattern is for "I want to invoke a Lambda", not "I want to investigate Lambda invocations". The verbs `invoked` (past tense), `caused`, `triggered`, `was responsible for` should route to CloudTrail.

### Finding 10 — Composition of two patterns produces a sufficient but over-flagged policy

- Prompt: `"Athena query: count unique users per day from the events table"`
- Generated: `dynamodb-read` + `athena-query` (combined 19 actions including `dynamodb:Scan`, `athena:StartQueryExecution`)
- Score: 8 (high)
- Judgment: SUFFICIENT — the user can query Athena with the events DynamoDB table also queryable
- Recommendation: this is a legitimate two-pattern composition (the matcher correctly recognized "events table" + "Athena query"), and the refinement_hints correctly warn the user. But the scorer should not punish multi-pattern composition by itself — it should only punish broad RESOURCE (the wildcard `arn:aws:dynamodb:*:*:table/events` is actually decently narrow on the table name). Reviewing the broad-cross-resource factor logic to recognize partial-ARN narrowing would help.

## Diagnosis: why the joint rate is so low

The joint-rate failure isn't a single bug — it's a structural mismatch between three subsystems:

1. **Pattern matchers** are conservative — they only fire on tight-keyword matches and miss natural-language synonyms (Cluster 1).
2. **Baseline fallback** was supposed to backstop pattern misses, but its `use_case_tags` keyword set is too narrow and misses the most common stressed-engineer phrasings (Findings 1 & 2).
3. **Scorer** correctly flags broad-resource baselines as risky, but it has no awareness that the policy came from the deliberate baseline path — so it punishes the very policies the system was designed to return when nothing else matches (Finding 6).

The fix is multi-step but each step is cheap:

| Step | Cost | Joint-rate lift estimate |
|---|---|---|
| Expand Explore baseline `use_case_tags` (incident verbs, "inherited", "broken in prod", etc.) | 1 hour | +10-15 percentage points by closing Cluster 1 |
| Add forensic-verb routing to SecurityAudit | 1 hour | +5 percentage points (forensics category) |
| Add `access_type=read-only` filter to write-pattern matchers (or vice-versa for writes) | 2 hours | +10 percentage points (closes Findings 4, 5, 8) |
| Add scorer "baseline credit" for `baseline_provenance != None` | 2 hours | +30-40 percentage points (the biggest lever) |
| Add `sqs-create`, `sns-create`, `ecr-create`, `eventbridge-create`, `apigateway-create-route` patterns | 4 hours | +5 percentage points (feature category) |

Estimated joint rate after the above: **45-60% (vs. 1.8% today)**. The most important single change is the scorer baseline credit — without it, every baseline emission is dead-on-arrival for the auto-approval thesis.

## Method notes

- Prompts authored across 11 categories, mixing specificity, urgency markers, and agent vs. human voice
- All prompts run from `/Users/reagan/repos/iam-roles` against `iam_jit.mcp_server._generate_for_mcp` + `_score_for_mcp`
- Raw results: `/tmp/sufficiency_results.jsonl`
- Judgment-augmented results: `/tmp/sufficiency_judged.jsonl`
- Driver: `/tmp/sufficiency_loop.py`; evaluator: `/tmp/evaluate_sufficiency.py`
- No scoring/generator code was modified during this run (measurement pass only)
- Sufficiency was judged by Claude Opus 4.7 (1M ctx) inspecting each generated policy against the stated task
- Auto-approval threshold: `score < 5`
