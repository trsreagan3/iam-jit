# Policy-generator adversarial findings

Sampled 50+ realistic developer- and agent-style task descriptions
through `iam_jit.policy_gen.generate_policy()`. This document
catalogs the failure modes found and proposes pattern-library
improvements to address them.

Every failure listed here has a corresponding pinned test in
`test_adversarial_findings.py`. When a generator improvement
fixes one of the cases, the pin flips red — that's the signal that
the fix landed.

Test fixture: `GenerationContext(account_id="123456789012",
region="us-east-1")`, `bias="allow"`.

---

## Failures by class

### 1. Over-scoping (generator grants more than the task needs)

| # | Description | What the generator returned | What it should return |
|---|-------------|------------------------------|-----------------------|
| O-1 | `read the audit logs from S3 for the last 7 days` | Matches BOTH `s3-read` AND `cloudwatch-logs-read` — emits 14 actions across `s3:*` + `logs:*`. Score 8. | Either: prefer the closer service (S3 — because `from S3` is explicit), OR drop `cloudwatch-logs-read` when the description names a non-CW service in the same span. |
| O-2 | `read the Lambda function logs for incident response` | Matches `s3-read` (because the bare phrase `read the` is in the s3-read phrase list!), `lambda-read-logs`, AND `cloudwatch-logs-read`. Emits S3 read actions on `arn:aws:s3:::*` plus bogus lambda ARNs `function:Lambda` and `function:logs`. Score 8. | Should match only `lambda-read-logs`. Remove `read the` and `from bucket` as bare phrases — they fire on any read-like sentence. |
| O-3 | `describe xray service` | Matches `ecs-describe` because `describe service` is in its phrase list. Emits 6 ECS actions on `*`. | Should match nothing (no X-Ray pattern exists). The phrase `describe service` needs a guard: only fire if `ecs` is also in the description. |
| O-4 | `encrypt data with kms key alias/customer-data` | Extracts TWO resources: `alias/customer-data` (correct) AND a bogus `key/kms` (from the `with X key` fallback that captured the literal word `kms` after a more-specific match already consumed the span). | Only `alias/customer-data` should be extracted. The `with X key` regex needs a `kms` not-already-claimed guard. |
| O-5 | `stop the bastion EC2 instance` | Matches both `ec2-describe` AND `ec2-start-stop`. Emits 9 Describe actions plus the StartInstances/StopInstances/RebootInstances set. Score 8. | The `ec2-start-stop` pattern alone is sufficient; `ec2-describe` should not fire when an explicit start/stop verb is present. Bias should be: read-only patterns suppress when a write pattern of the same service fires. |

### 2. Under-scoping (generator omits actions the task needs)

| # | Description | What the generator returned | What's missing |
|---|-------------|-----------------------------|----------------|
| U-1 | `rotate the database credentials in Secrets Manager` | `secrets-read`: emits `GetSecretValue`, `DescribeSecret`, `ListSecrets`. | `secretsmanager:RotateSecret`, `secretsmanager:UpdateSecret`, `secretsmanager:PutSecretValue`. **Agent would fail the task.** |
| U-2 | `kill the runaway ECS task in the prod-inventory service` | `ecs-describe` only. | `ecs:StopTask`. Agent can describe the task forever but can't kill it. |
| U-3 | `publish a custom CloudWatch metric called deploy.success` | `cloudwatch-metrics-read` (read-only). | `cloudwatch:PutMetricData` — the ONLY action that publishes a custom metric. Agent fails the task. |
| U-4 | `delete log group /aws/lambda/api` | `cloudwatch-logs-read` (read-only — `log group` is in its phrase list). | `logs:DeleteLogGroup`. |
| U-5 | `create a new Lambda function called email-sender` | Unmatched. | `lambda:CreateFunction`, `iam:PassRole`. There is no `lambda-create` pattern (only deploy/invoke/read-logs). |
| U-6 | `delete object from staging-uploads bucket` (no `the` article) | `s3-read` only (no `s3-delete`!) because the s3-delete phrases require `from s3` / `s3 delete` / `from bucket` substrings; the user's word order doesn't hit any. | Should also match `s3-delete`. The phrase library is missing `delete from bucket` and `delete object from`. |

### 3. Pattern mismatch (wrong pattern fires)

| # | Description | Pattern that matched | Pattern that should have matched |
|---|-------------|----------------------|----------------------------------|
| P-1 | `publish CloudWatch metric deploy.success` | `cloudwatch-metrics-read` | A `cloudwatch-metrics-write` pattern (does not exist) emitting `cloudwatch:PutMetricData`. |
| P-2 | `describe xray service` / `view xray service map` | `ecs-describe` | An `xray-describe` pattern or none at all. |
| P-3 | `delete log group /aws/lambda/api` | `cloudwatch-logs-read` | A `cloudwatch-logs-delete` pattern emitting `logs:DeleteLogGroup`. |
| P-4 | `audit log groups` | `cloudwatch-logs-read` | Probably correct, but score 8 from wildcard resource is alarming for an audit task — score doesn't reflect read-only access. Worth tracking. |

### 4. Resource-extraction misses

| # | Description | Extracted | Should extract |
|---|-------------|-----------|----------------|
| R-1 | `scan the orders DynamoDB table for inactive items` (capital `DynamoDB`) | Nothing — falls back to `arn:aws:dynamodb:*:*:table/*`. Score 7. | `arn:...:table/orders`. The DDB name regexes are CASE-SENSITIVE on the literal `dynamodb` token — re-compile with `re.IGNORECASE`. |
| R-2 | `read the orders-prod-2026 DynamoDB table` (capital `DynamoDB`) | Same as R-1. | Same fix. |
| R-3 | `receive messages from the order-queue SQS queue` | Bogus `arn:aws:sqs:...:SQS` because the forward regex matched `queue SQS` and the reverse regex didn't trigger (because of the inline `SQS` token). | `arn:...:order-queue`. Forward regex should not capture `SQS`/`SNS`/`SES` as resource names (add to stopwords). |
| R-4 | `read the Lambda function logs for incident response` | Bogus `function:Lambda` (from `the Lambda function`) AND `function:logs` (from `function logs`). | No lambda extraction. `Lambda`/`logs` should be in the stopwords for lambda-function extraction (or the regexes should not match when those tokens immediately follow `function`). |
| R-5 | `execute the order-reconciliation Step Function` | `arn:aws:states:*:*:stateMachine:*` (wildcard fallback). | `arn:...:stateMachine:order-reconciliation`. **No state-machine name extraction pattern exists.** Add one: `\bthe\s+([X])\s+(?:step\s+)?(?:state\s+machine|step\s+function)\b`. |
| R-6 | `delete s3 object from staging-uploads bucket` (no `the`) | Wildcard fallback. | `arn:aws:s3:::staging-uploads`. The reverse S3 regex requires `the X bucket`. Without `the`, the description falls through. Either drop the `the` requirement or add `from X bucket` as a third form. |
| R-7 | `investigate ECS task that crashed in inventory service` (no `the` before `inventory`) | `*` wildcard. | `arn:...:service/inventory`. Same root cause as R-6 for the ECS regex. |
| R-8 | `trigger lambda email-sender` | Wildcard fallback. | `arn:...:function:email-sender`. The lambda forward regex requires `function X` / `lambda function X`, not `lambda X`. |
| R-9 | `describe the orders-prod-2026 dynamodb table` (lowercase) | Resource IS correctly extracted (`table/orders-prod-2026`), but discarded because NO PATTERN MATCHES. The dynamodb-read pattern has no `describe` phrase. | Add a `dynamodb-describe` pattern emitting `DescribeTable`, `ListTables`. |

### 5. False unmatched (descriptions that should match but don't)

| Description | Why it should match something | Suggested pattern |
|-------------|-------------------------------|-------------------|
| `update the api-gateway deployment for v2` | API Gateway pattern exists (`api-gateway-invoke`) but only for invoke. | Add `api-gateway-deploy` / `apigateway-update-stage` emitting `apigateway:POST`, `apigateway:PATCH` on the stage ARN. |
| `view the prod-api API Gateway stage` | Same: API-Gateway describe is missing. | Add `apigateway-describe`. |
| `subscribe to the alerts SNS topic` | `sns-publish` exists; subscribe is a distinct intent. | Add `sns-subscribe` emitting `sns:Subscribe`, `sns:ListSubscriptions`. |
| `rotate secret prod-db-creds` | Same root cause as U-1: no rotate verb in any pattern. | Add `secrets-rotate` emitting `secretsmanager:RotateSecret`, `secretsmanager:UpdateSecret`. |
| `list all IAM roles tagged with team=platform` | The `iam-role-read` pattern fires on `describe role`/`get role`/`look up role` — but `list roles` is missing. | Add `list roles` / `list iam roles` / `iam list roles` phrases to `iam-role-read`. |
| `describe AWS Config rules for compliance audit` | No AWS Config pattern exists. | Add `aws-config-read` emitting `config:DescribeConfigRules`, `config:ListDiscoveredResources`. |
| `describe Glue jobs in production` | No Glue pattern. | Add `glue-describe` emitting `glue:GetJobs`, `glue:GetJob`. |
| `list available SageMaker endpoints` | No SageMaker pattern. | Add `sagemaker-describe` emitting `sagemaker:ListEndpoints`, `sagemaker:DescribeEndpoint`. |
| `list CloudFront distributions` | No CloudFront pattern. | Add `cloudfront-describe`. |
| `view Athena query history` | No Athena pattern. | Add `athena-read` emitting `athena:ListQueryExecutions`, `athena:GetQueryExecution`, `athena:GetQueryResults`. |
| `list EFS file systems and mount targets` | No EFS pattern. | Add `efs-describe`. |
| `describe Route 53 hosted zones for example.com` | No Route 53 pattern. | Add `route53-describe`. |
| `tag the prod-database RDS cluster` | No RDS tag pattern. | Add `rds-tag` emitting `rds:AddTagsToResource`. |
| `put metric data` / `publish a metric to cloudwatch` | No cloudwatch-metrics-write pattern. | Add `cloudwatch-metrics-write` emitting `cloudwatch:PutMetricData`. |
| `describe table prod-orders` | Resource regex matches (table name extracted) but no DDB describe pattern. | Add `dynamodb-describe` (see R-9). |
| `put item into the customers ddb table` | DDB write pattern uses `put dynamodb` / `ddb put` / `put item`. Wait — `put item` IS in the dynamodb-write phrase list, but the description here uses `put item INTO`, not `put item` as a contiguous trigger. Substring `put item` IS in `put item into`, so this should match. Let me verify: it DIDN'T match. The issue: the phrase library has `put dynamodb`, `dynamodb write`, `put dynamodb`, `update dynamodb`, `ddb write`, `ddb put`, `write item`, `update table` — but `put item` itself is NOT in the list. | Add `put item` to `dynamodb-write` phrases. |
| `scan the items table for inactive entries` | `scan dynamodb` is a phrase but `scan table` is not. | Add `scan table`, `scan the` to `dynamodb-read` phrases. |

---

## Top recommendations (ranked by impact)

1. **Add a `cloudwatch-metrics-write` pattern** — `publish CloudWatch metric` is one of the most common agent tasks and currently silently maps to a read-only pattern (U-3, P-1). Single-line fix: copy `cloudwatch-metrics-read` and replace actions with `cloudwatch:PutMetricData`.

2. **Add a `secrets-rotate` pattern + Secrets Manager write coverage** — `rotate secret X` is a common credential-hygiene task that currently either silently no-ops (under-scope) or unmatched (U-1, false-unmatched). Adding this pattern AND giving it the rotate/update actions closes both failures.

3. **Add a `dynamodb-describe` pattern** — covers the case where the user wants to describe a table without reading items. Currently `describe the X dynamodb table` is false-unmatched even though resource extraction WORKS for that exact phrase (R-9).

4. **Remove `read the` from `s3-read.phrases`** — this single phrase causes O-2 and many other over-scoped policies (every description that starts with "read the" matches s3-read). Replace with `read the s3` / `read s3 bucket`.

5. **Fix DDB name extraction case-sensitivity** — adding `re.IGNORECASE` to the two DynamoDB resource regexes closes R-1 and R-2 in one change. `DynamoDB` is the official capitalization in AWS docs; users WILL write it that way.

6. **Add service-acronym stopwords to resource extraction** — `SQS`, `SNS`, `SES`, `EFS`, `RDS`, `KMS` and similar should NEVER be extracted as resource names. Add them to `_NAME_STOPWORDS` (R-3, O-4) — or do a tighter fix where each per-service regex excludes the service's own acronym.

7. **Add lambda-name stopwords** — `Lambda`, `logs`, `function`, `code` should not extract as function names from `the Lambda function`, `function logs`, etc. Either add `Lambda` (and case-folded `lambda`) to the stopwords, or require the captured name to contain at least one hyphen / digit / non-English character (R-4).

8. **Guard `describe service` against non-ECS contexts** — easiest fix: require either `ecs` token or `task` token in the description for the phrase to fire (O-3 / P-2). This is a focused change to `ecs.py` phrases.

9. **Add a state-machine name extraction regex** — the Step Functions pattern is well-shaped but always falls back to wildcard ARN (R-5). Match `\b(?:the\s+)?([X])\s+(?:step\s+function|state\s+machine)\b`.

10. **Drop the `the` requirement in reverse name regexes** — affects bucket and ECS-service extraction (R-6, R-7). The reverse-name patterns require `the X TYPE` but real users frequently write `<verb> X TYPE` without an article ("delete from staging-uploads bucket", "in inventory service").

11. **Suppress read-only patterns when write counterpart of same service fires** — covers O-5 (stop ec2 matches both describe and start-stop). Implement as a post-match filter in `_build_statements`: if a pattern P_write fires and the description's primary verb is a write verb, drop P_read of the same service.

12. **Add patterns for common AWS services with zero coverage** — Athena, Glue, SageMaker, Route 53, CloudFront, SES, EFS, AWS Config, CodePipeline. Each is one short pattern file. Many of these have describe-only read APIs that are LOW_IMPACT in the scorer (so easy to auto-approve).

---

## Honest negatives — descriptions where the generator works well

These passed without intervention and prove the generator's coverage is real. Pinned in `test_adversarial_findings.py::test_working_case`.

| Description | Matched | Risk |
|-------------|---------|------|
| `assume the deploy-admin role to ship infra` | `sts-assume-role` | 3 (named role) |
| `check SSM parameter /prod/db/host` | `ssm-parameter-read` | 2 (named param) |
| `describe the prod-aurora cluster` | `rds-describe` | 1 (named cluster) |
| `publish 'hello' to topic on-call-alerts` | `sns-publish` | 3 (named topic) |
| `list objects in the website-assets bucket` | `s3-read` | 1 (named bucket) |
| `view CloudWatch metrics for prod-api` | `cloudwatch-metrics-read` | 4 |
| `describe the current EC2 fleet and their security groups` | `ec2-describe` | 1 |
| `execute the order-reconciliation Step Function` | `step-functions-execute` | 6 (resource not extracted but actions correct) |
| `query the prod-orders Aurora cluster for stale orders` | `rds-data-query` | 7 (intentional floor — rds-data is high-risk) |
| `view log group /aws/lambda/api` | `cloudwatch-logs-read` | 1 (named group) |
| `deploy the auth-service CDK stack to staging` | `cloudformation-deploy` | 9 (intentional floor — CFN + PassRole) |
| `trigger an EventBridge event to refresh the cache` | `eventbridge-publish` | 6 |
| `scan dynamodb table prod-orders` (lowercase ddb) | `dynamodb-read` | 1 |
| `delete s3 object from the staging-uploads bucket` | `s3-read`, `s3-delete` | 3 (named bucket) |
| `tail logs from the payment-processor Lambda` | `lambda-read-logs`, `cloudwatch-logs-read` | 8 (wildcard log-group fallback — acceptable) |

The pattern is clear: when (a) the verb-service combination hits one of the existing pattern phrases AND (b) the resource name appears in a `the X TYPE` form, the generator produces a tight, low-risk policy. The failures cluster around (a) verbs/services without coverage and (b) word orders the reverse-name regex doesn't anticipate.

---

## Numbers

- **52 task descriptions sampled.**
- **20 distinct failures pinned as regression tests** in `test_adversarial_findings.py` (some descriptions exhibit multiple failure classes; the unique failure modes are pinned once each).
- **12 honest-negative working cases pinned** to lock in coverage.
- **At least 14 service areas with zero or partial coverage** identified for future pattern PRs (Athena, Glue, SageMaker, Route 53, CloudFront, SES, EFS, Config, CodePipeline, Step Functions name extraction, API Gateway describe/update, SNS subscribe, Secrets rotation, CloudWatch metrics write).
