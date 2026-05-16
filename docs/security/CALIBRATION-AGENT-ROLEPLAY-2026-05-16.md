# Agent-roleplay calibration loop — 2026-05-16

## Methodology

Simulated 15 realistic IAM-grant requests as if a mixed cast of devs, on-call
engineers, data analysts, and security folks were typing them into the
agent-safety wrapper. Each scenario went through the standard pipeline:

1. **Generate** via `iam_jit.policy_gen.generate_policy()` with
   `account_id=111111111111`, `region=us-east-1`, `bias=allow` (default).
2. **Score** via `iam_jit.review.analyze_policy()` with the matching
   `access_type` and `duration_hours=1`.
3. **Agent judgement** — would I (as the agent intermediating the request)
   submit as-is, refine, or escalate?
4. **Refinement pass** — try the realistic refinement (`include_actions`,
   `exclude_actions`, narrower `resources` via context) and see how the score
   moves.

Baseline calibration corpus before the loop:
`97 failed, 2171 passed in 11.19s` — the failures are pre-existing and not
caused by this exercise (no scorer/generator changes were made).

Generator coverage as of this loop: **47 named patterns** spanning S3, Lambda,
DynamoDB, EC2, ECS, RDS, KMS, SQS/SNS, SecretsManager, SSM, Athena, Glue,
Redshift, CloudFront, CloudFormation, Route53, IAM-read, EventBridge, Step
Functions, EFS, SES, RDS-Data, CloudWatch logs/metrics. **Notably absent**:
EKS, CloudTrail, AWS Config (other than describe), Organizations,
Application-Autoscaling, VPC/networking-read-as-a-distinct-pattern, KMS
rotation-status, IAM-write/audit, ELB, Backup, ACM.

## Scenarios tested (15)

### S1 — "data lake, probably Glue, S3, Athena, maybe Lake Formation"
- **Generated:** `s3-read` only on `arn:aws:s3:::*` and `*/*` — single S3 statement
- **Score:** 7
- **Coverage:** TOO NARROW. User said "probably Glue, S3, Athena, maybe Lake
  Formation"; generator only matched on the word "S3". Glue/Athena/Lake
  Formation patterns weren't triggered despite explicit mention.
- **Refinement:** add bucket ARN via `context.resources` -> score drops to 1
  (best score in the loop). But coverage is still missing Glue/Athena.
- **Verdict:** the *narrowing* refinement worked beautifully; the *coverage
  gap* persisted. A real analyst would have to issue three separate requests
  to get the full data-lake surface, which contradicts the way they verbalised
  it.

### S2 — "Deploy a new Lambda function called payments-webhook"
- **Generated:** `lambda-deploy` with `iam:PassRole` on `arn:aws:iam::*:role/*`
  + lambda actions on `arn:aws:lambda:us-east-1:111111111111:function:called`
- **Score:** 9 (correctly: PassRole-on-`*` + UpdateFunctionCode = RCE-via-role)
- **Coverage:** TWO PROBLEMS. (a) The function-name extractor parsed the word
  `called` as the function name — the actual name `payments-webhook` came
  AFTER the connective. (b) `iam:PassRole` on `*:role/*` is the right
  default but score 9 will block in strict mode without a ready hint.
- **Refinement:** drop `iam:PassRole` -> score drops to 6, factors still
  cite RCE-via-UpdateFunctionCode (correct). The `refinement_hints` returned
  by the generator EXPLICITLY tell the agent how to fix this — well done.
- **Verdict:** scoring correct. Pattern's name-extractor heuristic is buggy
  ("called X" is a common English construction). Hint quality is excellent.

### S3 — "Investigate why DynamoDB writes are throttling on orders-prod"
- **Generated:** `dynamodb-write` (BatchWriteItem, PutItem, UpdateItem,
  GetItem, DescribeTable) on the right table ARN
- **Score:** 8 (read-only request granted Write actions = strong floor signal)
- **Coverage:** TOO BROAD AND TOO NARROW SIMULTANEOUSLY. The word
  "throttling" + "writes" matched `dynamodb-write` even though the user said
  "investigate" (read-only intent). Missing: `cloudwatch:GetMetricData` for
  the actual throttling metric, `application-autoscaling:Describe*` for the
  table's auto-scaling config — both essential for this investigation.
- **Refinement:** drop the write actions, add CW + autoscaling -> score 4.
  Result is exactly what an SRE would want, but required surgical
  refinement; default would have made this 8 -> rejected by strict mode.
- **Verdict:** scoring correct given the inputs, but the pattern matcher
  read "writes" in a noun sense (the thing being investigated) as a verb
  sense (the access requested). This is a recurring class of error.

### S4 — "Set up cross-region S3 replication from us-east-1 prod-data to us-west-2 prod-data-dr"
- **Generated:** NONE (`unmatched_reason: No heuristic pattern matched`)
- **Refinement-as-rephrase:** "read S3 bucket prod-data and write S3 bucket
  prod-data-dr for replication" -> matches `s3-read` + `s3-write` on the
  named buckets, score 5.
- **Coverage:** Even the rephrase misses `iam:PassRole` for the replication
  role + `s3:GetReplicationConfiguration`/`s3:PutReplicationConfiguration`,
  which are the actual replication-setup actions. This is a multi-resource
  cross-region orchestration the heuristic generator can't recognise.
- **Verdict:** would FAIL closed for a real user. They'd hit "no pattern
  matched", read the message, rephrase using read/write verbs, then still
  not get the right policy. Strong LLM-tier candidate.

### S5 — "I'm on call and need to look at why the eks cluster prod-eks-1 is unhealthy"
- **Generated:** NONE
- **Refinement-as-rephrase:** "read EKS cluster prod-eks-1" -> still NONE.
- **Coverage:** **No EKS pattern exists at all.** This is a top-3 production
  AWS service for any company shipping containers. On-call engineer at 2AM
  hits this and the tool is useless.
- **Verdict:** HARD GAP. A pre-launch fix.

### S6 — "Add a new IAM role for the new analytics intern, read-only across everything except secrets"
- **Generated:** NONE (the words "IAM role for" + "read-only" don't trigger anything)
- **Refinement-as-rephrase:** "read S3, read DynamoDB, read RDS, read EC2"
  -> matches `s3-read` + `dynamodb-read`, score 7. Misses RDS read and EC2
  describe even though they're explicitly named.
- **Coverage:** The "read $service" verb pattern only matched 2 of the 4
  services the user named. RDS-describe and EC2-describe patterns exist —
  the matcher just isn't catching them on this phrasing.
- **Verdict:** poor matcher recall on enumerated-service requests. A real
  admin building an intern role would (correctly) abandon iam-jit and just
  attach `ReadOnlyAccess` minus a SecretsManager Deny — defeating the
  whole point of the tool.

### S7 — "Help me debug terraform state drift on our prod VPC"
- **Generated:** NONE
- **Refinement-as-rephrase:** "read EC2 VPC and read S3 terraform state
  bucket and read DynamoDB lock table" -> matches `s3-read` + `dynamodb-read`,
  same score-7 result as S6. Missed EC2 describe again.
- **Verdict:** another HARD GAP — terraform/IaC workflows are a daily
  use-case. Every VPC describe call needs `ec2:Describe*`. The pattern
  exists (`ec2-describe`) but the matcher is reading "VPC" but not "EC2".

### S8 — "Rotate the password on prod RDS instance orders-db-prod"
- **Generated:** `secrets-rotate` on `arn:aws:secretsmanager:*:*:secret:*`
  (full wildcard)
- **Score:** 8
- **Coverage:** Reasonable action set, but no resource extraction at all —
  user named the RDS instance, generator wildcarded the secret ARN. Also
  MISSING `rds:ModifyDBInstance` — the request explicitly says "rotate the
  password ON prod RDS instance", which often means going through RDS-API,
  not SecretsManager directly.
- **Refinement:** narrow secret ARN via context.resources -> score 5.
- **Verdict:** the "rotate ... RDS instance ..." phrasing should have
  triggered a composite pattern that includes `rds:ModifyDBInstance` +
  `secretsmanager:UpdateSecret` on a specific secret. Single-pattern bias is
  again the failure mode.

### S9 — "The order-processing SQS queue has 50k messages stuck — let me look"
- **Generated:** NONE on first pass (the colloquial phrasing didn't match)
- **Rephrase to "read SQS queue order-processing":** matches `sqs-receive`
  with `DeleteMessage` + `ReceiveMessage` + `GetQueueAttributes` on the
  right ARN. Score 8 (read-only intent + DeleteMessage = floor signal).
- **Verdict:** the pattern itself is over-broad (DeleteMessage shouldn't be
  in a "peek-the-queue" pattern by default; users who intend to drain
  should ask explicitly). And the matcher needs colloquial-phrase recall —
  "stuck — let me look" means "investigate", which is a synonym for "read".

### S10 — "Create a new S3 bucket analytics-2026-events with server-side encryption"
- **Generated:** ONLY `kms-encrypt` matched. Got KMS Encrypt/GenerateDataKey
  on `arn:aws:kms:*:*:key/*` — but ZERO S3 actions. Score 7.
- **Coverage:** The most egregious miss in the loop. User asks to create a
  bucket; gets KMS only. The word "encryption" beat the words "Create" and
  "bucket".
- **Refinement:** add `s3:CreateBucket` + `PutBucketEncryption` +
  `PutBucketPublicAccessBlock` on the named bucket ARN -> score still 7
  (KMS wildcard dominates). Need to ALSO drop the kms-encrypt match or scope
  the KMS key — neither is offered as a refinement hint.
- **Verdict:** pattern-match precedence is wrong. Multi-pattern matches
  should compose by salience (the verb in the sentence ranks the matches),
  not just emit all matches in parallel.

### S11 — "Invalidate CloudFront cache for distribution E1ABCDEFG after deploy"
- **Generated:** Both `cloudfront-describe` and `cloudfront-invalidate`
  matched, with `Resource: *` for both. Score 6.
- **Coverage:** distribution ID `E1ABCDEFG` was clearly named — should have
  produced `arn:aws:cloudfront::111111111111:distribution/E1ABCDEFG` ARNs.
- **Refinement:** narrow via context.resources -> score still 6 (the
  refinement applied to actions but cloudfront's pattern keeps `*` for
  Resource — likely a pattern definition that doesn't accept narrow ARNs).
- **Verdict:** distribution-ID extraction missing; refinement path doesn't
  fully narrow. Would need a pattern fix, not a loop fix.

### S12 — "I need to audit IAM across our 3 prod accounts — read-only on iam, organizations, cloudtrail, config"
- **Generated:** NONE
- **Rephrase-as "read IAM, read CloudTrail, read Config across accounts"**:
  STILL NONE.
- **Coverage:** No `cloudtrail-*` pattern, no `config-*` (well —
  `config-describe` exists but the matcher didn't fire), no
  `organizations-*` pattern. This is the **classic security-auditor
  workflow** and the tool produces zero output.
- **Verdict:** HARD GAP. The contractor/auditor TAM-expansion play
  ([[contractor-auditor-access-use-case]]) is materially blocked on this
  category being unmatched.

### S13 — "Run an Athena query against the finance.invoices table for Q1 totals"
- **Generated:** Both `dynamodb-read` AND `athena-query` matched. The
  DynamoDB statement targets `arn:aws:dynamodb:us-east-1:111111111111:table/
  finance.invoices` — a non-existent DynamoDB table. Athena statement on `*`.
  Score 8.
- **Coverage:** False match on dynamodb-read. The word "table" + a name
  triggered `dynamodb-read` even though the request is unambiguously Athena.
  The correct Athena policy needs `s3:GetObject` on the data bucket and
  `s3:Put*` on the Athena results bucket — the Athena pattern lumps them
  together with `*`.
- **Refinement:** drop all dynamodb actions -> still 8 because of the
  `glue:Get*` on `*` and athena Write classification on
  StartQueryExecution. The Athena pattern itself produces a high-floor
  policy by design.
- **Verdict:** false-positive matching from the word "table". Athena
  pattern needs split into "Athena query results bucket" vs "Athena
  workgroup/glue catalog" sub-statements.

### S14 — "Debug why my ECS task is crash-looping in the prod cluster"
- **Generated:** `ecs-describe` only on `*`. Score 7.
- **Coverage:** TOO NARROW. ECS task debugging needs CloudWatch Logs
  (`logs:GetLogEvents`, `logs:FilterLogEvents`) and EC2 ENI describes for
  awsvpc-mode tasks — generator gives neither.
- **Refinement:** add logs + ec2 describe -> score 7 (no movement) but the
  POLICY is materially better. Refinement provided value the score didn't
  capture.
- **Verdict:** ECS pattern should compose with `cloudwatch-logs-read` by
  default for any "debug"/"crash"/"investigate" verbs. Score doesn't
  reward narrowness gain because the resource is still `*`.

### S15 — "Check rotation status on all our KMS customer-managed keys"
- **Generated:** NONE
- **Rephrase to "read KMS keys for rotation status":** STILL NONE.
- **Coverage:** `kms-decrypt` and `kms-encrypt` patterns exist. There is no
  `kms-list-keys` / `kms-describe-keys` pattern. Rotation-status checks
  are part of every quarterly compliance review.
- **Verdict:** missing read-side KMS pattern entirely. Pre-launch fix.

## Cluster findings

### Cluster A — generator coverage gaps (5 of 15: S5, S7, S12, S15, partly S4)
**No pattern at all** for: EKS, CloudTrail, Organizations, KMS-read,
S3-replication, VPC-as-distinct-from-EC2-describe. These are not edge
cases; they are bread-and-butter ops. ~33% of realistic scenarios produce
**zero output**. No first-time user gets through 5 of these without
giving up.

### Cluster B — pattern matcher reads English keywords too literally (S2, S3, S6, S7, S9, S10, S13)
- "Lambda function CALLED payments-webhook" -> resource ARN `:function:called`
- "DynamoDB WRITES are throttling" -> grants Write actions to a read-only requester
- "read S3, read DynamoDB, read RDS, read EC2" -> only matched 2 of 4
- "VPC" doesn't trigger `ec2-describe`
- "stuck — let me look" doesn't match anything
- "Create bucket WITH encryption" -> matched encryption only
- "Athena query against the FINANCE.INVOICES TABLE" -> matched dynamodb-read

The matcher treats the description as a bag-of-keywords, not a parse. It
needs verb-noun-resource role assignment.

### Cluster C — pattern over-include (S2, S3, S8, S9, S13)
Patterns include destructive sibling actions by default:
- `lambda-deploy` includes `iam:PassRole` on `*:role/*`
- `dynamodb-write` includes `BatchWriteItem` even on a peek
- `secrets-rotate` includes `CancelRotateSecret`
- `sqs-receive` includes `DeleteMessage`
- `athena-query` includes `StopQueryExecution` (a Write)

Each of these is **defensible per-pattern** (real workflows do all of
these) but the COMPOSITION of "always include the dangerous sibling" + "no
context awareness about whether the user actually needs it" floors the
score above the typical strict-mode threshold and forces refinement on
nearly every scenario.

### Cluster D — refinements are necessary AND effective when they fit (S1, S3, S8, S11)
When the refinement is "narrow the resource ARN", scores plummet (S1: 7→1,
S3: 8→4, S8: 8→5). When the refinement is "drop the dangerous sibling",
modest improvement (S2: 9→6). When the user has to compose patterns the
generator didn't compose (S10), refinement helps coverage but score
doesn't move because the pattern's own wildcards dominate.

### Cluster E — refinement-hint quality is a bright spot (S1, S2, S8, S11, S13)
The hints are SPECIFIC and ACTIONABLE — `refinement.exclude_actions =
['iam:PassRole']`, "name the prod-orders DynamoDB table", "narrow the
wording to select only the one you need". This is the part of the system
that most-resembles a competent security pair-programmer.

## Calibration recommendations (ranked by adoption impact)

1. **Add EKS, CloudTrail, Organizations, KMS-read, S3-replication patterns.**
   These five gaps alone account for 1/3 of unmatched scenarios. Each is
   a 30-line pattern definition. **Days of work, weeks of additional
   addressable users.**

2. **Improve matcher recall on enumerated-service requests** — "read S3,
   read DynamoDB, read RDS, read EC2" should match all four. Currently
   matches the first 2. Likely a stop-after-N-matches in the matcher;
   raise the cap or remove it.

3. **Fix the resource-name extractor's English handling.** "function CALLED
   X" parsing X as the function name is a daily failure. Same class:
   "table NAMED X", "bucket FOR X", "queue X with...". A handful of
   prepositional-phrase strippers would fix most of these.

4. **Verb-sense disambiguation for keyword-action collisions.** "writes"
   as a noun (`why are writes throttling`) shouldn't trigger the
   `dynamodb-write` pattern. "Read why writes are throttling" is the same
   intent. Detect "investigate", "debug", "look at", "check" as
   read-context verbs and downgrade matched write-patterns to their read
   counterparts.

5. **Pattern composition for "debug" / "investigate" verbs.** ECS-debug
   should auto-compose with `cloudwatch-logs-read`; Lambda-debug should
   too. Today the user has to know to add it. This is the lowest-effort
   change that materially improves score+coverage at once.

6. **Decompose patterns that bundle dangerous siblings.** Split
   `lambda-deploy` into `lambda-deploy-code-only` (no PassRole) and
   `lambda-deploy-with-role` (PassRole on a NAMED role only — fail closed
   if no role named). Same surgery for `dynamodb-write` (peek vs drain),
   `secrets-rotate` (rotate vs rotate-and-cancel), `sqs-receive` (peek vs
   consume). Match the right sub-pattern based on the verb.

7. **Multi-pattern match precedence by sentence-verb salience.** S10
   (create S3 bucket WITH encryption) matched only the modifier ("with
   encryption" -> kms-encrypt) not the verb ("create" -> s3-write). Verb
   should outrank modifier.

8. **Distribution-ID / cluster-name / instance-ID extractors.** S11 named
   `E1ABCDEFG`, S5 named `prod-eks-1`, S8 named `orders-db-prod`. None of
   these were extracted into ARNs. A regex set keyed on AWS resource-ID
   shapes (E + 9 alphanumerics for CloudFront, i-... for EC2, db-... for
   RDS, etc.) would lift many wildcards to narrow ARNs without changing
   any pattern definitions.

9. **Make `unmatched_reason` actionable for the user** — today it says
   "rephrase using common AWS verbs (read S3, query DynamoDB, deploy
   Lambda, ...)" which is too generic. When the matcher sees AWS service
   names but no recognised verb, list the verbs it CAN match for that
   service. ("I see you mentioned EKS but I don't have an EKS pattern;
   try `ec2:Describe*` since that covers most EKS investigation needs.")

10. **Surface the `suppressed_actions` field in CLI/MCP output.**
    Generator already populates it; nothing in the loop showed it because
    the bias-allow default doesn't suppress. With bias-deny mode, this
    becomes the user's "you might also want" list.

## Verdict

**Would a real dev keep using this tool after 10 of these turns?** As of
today's pass: probably not. ~33% of realistic requests get zero output.
Of the matched ones, the default score is high enough that most would be
blocked in strict mode, requiring per-request refinement. The refinement
machinery WORKS — when applied — and the hints are good. But the
default-pass success rate is too low for a "type your request, get a
narrow grant" pitch.

**However, the failure modes are tractable.** Recommendations 1-3 alone
(add 5 patterns, raise matcher recall cap, fix the prepositional-phrase
extractor) would lift the default-pass success rate from ~40% to ~70%
without touching the scorer. Recommendations 4-6 close most of the
remaining gap. Recommendations 7-10 are polish.

**Most important finding:** the scorer is doing its job (high scores were
earned in every case), but the GENERATOR is the bottleneck. Calibration
investment for the next sprint should be 90/10 generator/scorer.

**For agent-safety mode specifically** ([[agent-safety-adoption-play]]):
the loop's failure modes are LESS severe because the agent can iterate
silently — re-prompt the generator, refine, re-score, present the final
narrow grant to the human. The 33% no-output rate is the real adoption
killer. Until that drops below ~10%, the "iam-jit between Claude and AWS"
default is going to feel friction-heavy to first-time users.
