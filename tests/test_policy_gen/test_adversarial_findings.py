"""Adversarial regression suite — generator over-/under-scoping cases.

Each case PINS a known failure mode of `generate_policy()` so that
fixing the generator (in the patterns or resource extractor) will
flip the corresponding xfail/skip-marker assertion into a green
test. The cases were discovered by sampling realistic developer- and
agent-style task descriptions and comparing the generated policy to
what the task ACTUALLY needs.

Failure classes (see ADVERSARIAL-FINDINGS.md for details):
  1. over-scope     — generator includes actions the task does not need
  2. under-scope    — generator omits actions the task does need
  3. pattern-mismatch — wrong pattern fires
  4. resource-miss  — named resource in description not extracted
  5. false-unmatched — description should match a pattern but doesn't

Every case here is asserted in its CURRENT (failing) form. When a
generator improvement makes a case pass, replace the
`expected_*_current` assertion with the desired behavior — that's
the "fix landed" signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from iam_jit.policy_gen import (
    GenerationContext,
    GenerationRequest,
    generate_policy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DEFAULT_CTX = GenerationContext(account_id="123456789012", region="us-east-1")


def _run(description: str, bias: str = "allow") -> tuple[list[str], list[str], list[str], int | None]:
    """Generate, returning (matched_patterns, actions, resources, risk)."""
    r = generate_policy(GenerationRequest(
        task_description=description,
        context=DEFAULT_CTX,
        bias=bias,
    ))
    actions: list[str] = []
    resources: list[str] = []
    if r.policy:
        for s in r.policy["Statement"]:
            a = s["Action"]
            if isinstance(a, str):
                actions.append(a)
            else:
                actions.extend(a)
            res = s["Resource"]
            if isinstance(res, str):
                resources.append(res)
            else:
                resources.extend(res)
    return r.matched_patterns, actions, resources, r.scored_risk


# ---------------------------------------------------------------------------
# Class 1: OVER-SCOPING — generator grants more than the task needs
# ---------------------------------------------------------------------------

def test_over_scope_s3_read_the_lambda_function_logs() -> None:
    """`read the Lambda function logs` triggers s3-read in addition to
    cloudwatch-logs and lambda-read-logs.

    Cause: the s3-read pattern has the bare phrase "read the" in its
    phrase list. ANY description starting "read the X" matches s3-read
    regardless of whether S3 is involved.

    Impact: grants 6 unrelated S3 actions plus s3:*/* wildcard
    resource on a task that should be log-read-only.
    """
    matched, actions, _resources, _risk = _run(
        "read the Lambda function logs for incident response"
    )
    # FIXED — bare 'read the' removed from s3-read.phrases. S3 should
    # NOT match a Lambda-logs description.
    assert "s3-read" not in matched, (
        f"s3-read still matching 'read the Lambda function logs': {matched!r}"
    )
    assert "s3:GetObject" not in actions


def test_over_scope_audit_logs_from_s3_double_match() -> None:
    """`read the audit logs from S3` matches BOTH s3-read AND
    cloudwatch-logs-read because "logs" triggers the CW pattern even
    though the user clearly means S3 log FILES.

    The doc accepts this as a known case — see
    docs/agent-access.md lines 90-92. Pinning so we notice if it
    changes.
    """
    matched, actions, _resources, _risk = _run(
        "read the audit logs from S3 for the last 7 days"
    )
    assert "s3-read" in matched
    assert "cloudwatch-logs-read" in matched
    # Both action sets present
    assert "s3:GetObject" in actions
    assert "logs:GetLogEvents" in actions


def test_over_scope_xray_service_map_matches_ecs() -> None:
    """`describe xray service` matches `ecs-describe` because the
    substring 'describe service' fires the ECS pattern.

    Pattern mismatch + over-scope: the user asked about X-Ray, the
    generator grants 6 ECS Describe actions.
    """
    matched, actions, _resources, _risk = _run("describe xray service")
    assert "ecs-describe" in matched, (
        "pinned: 'describe service' substring triggers ecs-describe "
        "even when the description is about X-Ray. The ECS pattern's "
        "'describe service' phrase needs to require a 'ecs' token "
        "nearby."
    )
    assert "ecs:DescribeServices" in actions


def test_over_scope_bogus_function_arns_from_function_logs() -> None:
    """`read the Lambda function logs` builds two bogus lambda ARNs:
        arn:aws:lambda:*:*:function:Lambda  (from "the Lambda function")
        arn:aws:lambda:*:*:function:logs    (from "function logs")
    Neither names a real function. Cause: the lambda-name regex
    greedily binds to common English words after 'function'/'the' (and
    'Lambda' is not in the stopword list because it's a service name,
    not an article).
    """
    _matched, _actions, resources, _risk = _run(
        "read the Lambda function logs for incident response"
    )
    bogus = [
        "arn:aws:lambda:us-east-1:123456789012:function:Lambda",
        "arn:aws:lambda:us-east-1:123456789012:function:logs",
    ]
    found_bogus = [r for r in bogus if r in resources]
    assert found_bogus, (
        f"resource extractor no longer emits bogus function ARNs from "
        f"'the Lambda function logs' — if intentional, remove this pin. "
        f"Resources were: {resources}"
    )


def test_over_scope_kms_extracts_two_keys() -> None:
    """`encrypt data with kms key alias/customer-data` extracts BOTH
    `alias/customer-data` AND a bogus `key/kms` (from `with kms key`).

    Cause: the `with X key` fallback regex captures 'kms' as if it
    were a key name when the real form is `kms key <name>` already
    matched by the more-specific regex.
    """
    _matched, _actions, resources, _risk = _run(
        "encrypt data with kms key alias/customer-data"
    )
    assert (
        "arn:aws:kms:us-east-1:123456789012:alias/customer-data"
        in resources
    )
    # FIXED — bogus 'with X key' over-extraction now filtered by
    # negative lookahead. 'kms' must not be captured as a key name.
    bogus = "arn:aws:kms:us-east-1:123456789012:key/kms"
    assert bogus not in resources


# ---------------------------------------------------------------------------
# Class 2: UNDER-SCOPING — generator omits actions the task DOES need
# ---------------------------------------------------------------------------

def test_under_scope_rotate_secret_returns_only_read() -> None:
    """`rotate the database credentials in Secrets Manager` matches
    `secrets-read` and only emits Get/Describe/List. It does NOT
    include `secretsmanager:RotateSecret`, `secretsmanager:UpdateSecret`
    or `secretsmanager:PutSecretValue` — the actions that ACTUALLY
    rotate a secret.

    An agent acting on this policy would fail at the task: it could
    read the secret but not rotate it. Worst-case scenario: agent
    silently reads the credential without rotating, leaving the
    pretense of "rotation" complete.
    """
    matched, actions, _resources, _risk = _run(
        "rotate the database credentials in Secrets Manager"
    )
    # FIXED — secrets-rotate pattern added. Verifies rotation actions
    # are now emitted.
    assert "secrets-rotate" in matched
    assert "secretsmanager:RotateSecret" in actions


def test_under_scope_kill_ecs_task_returns_describe_only() -> None:
    """`kill the runaway ECS task in the prod-inventory service` matches
    `ecs-describe` only. It does NOT include `ecs:StopTask` — the
    action that actually kills the task.

    The agent could describe the task forever but couldn't kill it.
    """
    matched, actions, _resources, _risk = _run(
        "kill the runaway ECS task in the prod-inventory service"
    )
    # FIXED — ecs-stop-task pattern added. Verifies StopTask present.
    assert "ecs-stop-task" in matched
    assert "ecs:StopTask" in actions


def test_under_scope_publish_cloudwatch_metric_no_put_action() -> None:
    """`publish a custom CloudWatch metric called deploy.success` matches
    `cloudwatch-metrics-read` because the phrase "cloudwatch metric"
    fires the READ pattern. It misses `cloudwatch:PutMetricData`,
    which is the ONLY action that publishes a custom metric.

    Agent fails the task: it can list metric data but cannot write it.
    """
    matched, actions, _resources, _risk = _run(
        "publish a custom CloudWatch metric called deploy.success"
    )
    # FIXED — cloudwatch-metrics-write pattern added.
    assert "cloudwatch-metrics-write" in matched
    assert "cloudwatch:PutMetricData" in actions


def test_under_scope_delete_log_group_only_reads() -> None:
    """`delete log group` matches `cloudwatch-logs-read` (because
    'log group' is in the read pattern's phrase list) and emits only
    read actions. `logs:DeleteLogGroup` is missing.
    """
    matched, actions, _resources, _risk = _run("delete log group /aws/lambda/api")
    assert "cloudwatch-logs-read" in matched
    assert "logs:DeleteLogGroup" not in actions


def test_under_scope_create_lambda_unmatched() -> None:
    """`create a new Lambda function called email-sender` doesn't match
    `lambda-deploy`. The deploy pattern phrases are 'deploy lambda',
    'update function code', etc. — none cover the create case.

    A user reasonably expects this to map to `lambda:CreateFunction`.
    Currently it falls into the false-unmatched bucket.
    """
    matched, _actions, _resources, _risk = _run(
        "create a new Lambda function called email-sender"
    )
    assert matched == [], (
        "lambda-create pattern landed — if so, this pin is the "
        "regression signal: replace with an action-subset assertion."
    )


# ---------------------------------------------------------------------------
# Class 3: PATTERN MISMATCH — wrong pattern fires
# ---------------------------------------------------------------------------

def test_pattern_mismatch_publish_cloudwatch_metric() -> None:
    """Originally pinned: 'publish CloudWatch metric' matched only the
    read pattern (under-scoping bug). FIXED by adding the
    `cloudwatch-metrics-write` pattern — verifies the verb 'publish'
    now produces `cloudwatch:PutMetricData`.
    """
    matched, actions, _resources, _risk = _run(
        "publish CloudWatch metric deploy.success"
    )
    assert "cloudwatch-metrics-write" in matched
    assert "cloudwatch:PutMetricData" in actions


def test_pattern_mismatch_view_xray_matches_ecs() -> None:
    """X-Ray task description matches ECS pattern.

    Same root cause as test_over_scope_xray_service_map_matches_ecs;
    duplicated here as the pattern-mismatch class pin.
    """
    matched, _actions, _resources, _risk = _run("describe xray service")
    # Wrong pattern fires; no x-ray pattern exists.
    assert "ecs-describe" in matched


# ---------------------------------------------------------------------------
# Class 4: RESOURCE EXTRACTION MISSES
# ---------------------------------------------------------------------------

def test_resource_miss_dynamodb_case_sensitive_capitalisation() -> None:
    """Originally pinned: regex was case-sensitive on `dynamodb` so
    `DynamoDB` (official capitalization) didn't extract. FIXED by
    adding re.IGNORECASE to the DynamoDB name patterns. Verifies
    both casings now produce the narrow ARN.
    """
    desired = "arn:aws:dynamodb:us-east-1:123456789012:table/orders"
    for desc in (
        "scan the orders DynamoDB table for inactive items",
        "scan the orders dynamodb table",
        "scan the orders DYNAMODB table",
    ):
        _matched, _actions, resources, _risk = _run(desc)
        assert desired in resources, f"case-insensitive extraction failed for: {desc!r}"


def test_resource_miss_sqs_forward_eats_service_acronym() -> None:
    """Originally pinned: regex extracted 'SQS' (the service acronym)
    as the queue name. FIXED by adding a negative lookahead that
    rejects `sqs` (case-insensitive) as the captured name. Verifies
    bogus extraction is gone."""
    _matched, _actions, resources, _risk = _run(
        "receive messages from the order-queue SQS queue"
    )
    bogus = "arn:aws:sqs:us-east-1:123456789012:SQS"
    assert bogus not in resources, "service acronym 'SQS' still captured as resource name"


def test_resource_miss_step_function_name_not_extracted() -> None:
    """`execute the order-reconciliation Step Function` does not
    extract `order-reconciliation` as the state machine name. There is
    no name-extraction pattern for Step Functions / state machines, so
    the generator always falls back to the wildcard ARN
    `arn:aws:states:*:*:stateMachine:*`.

    Score floors high (~6) on the wildcard ARN. With name extraction
    the score would drop substantially.
    """
    _matched, _actions, resources, _risk = _run(
        "execute the order-reconciliation Step Function"
    )
    assert resources == ["arn:aws:states:*:*:stateMachine:*"]
    expected_if_fixed = (
        "arn:aws:states:us-east-1:123456789012:stateMachine:order-reconciliation"
    )
    assert expected_if_fixed not in resources


def test_resource_miss_bucket_without_the_prefix() -> None:
    """`delete s3 object from staging-uploads bucket` — no `the`
    article before the bucket name — fails to extract `staging-uploads`.

    The reverse S3 regex requires `the X bucket`. Without `the`, only
    the forward `bucket X` form would catch it, but here the word
    order is `X bucket`, which is the reverse-only path.

    With `the` added the bucket IS extracted correctly (see
    delete-s3-object-from-the-staging-uploads). This is a tight
    natural-language miss.
    """
    _matched, _actions, resources_no_the, _risk = _run(
        "delete s3 object from staging-uploads bucket"
    )
    _matched, _actions, resources_with_the, _risk = _run(
        "delete s3 object from the staging-uploads bucket"
    )
    # Without `the`: wildcard fallback (may appear twice — s3-read and
    # s3-delete each produce a statement, both with the wildcard ARNs)
    assert "arn:aws:s3:::*" in resources_no_the
    assert "arn:aws:s3:::*/*" in resources_no_the
    assert "arn:aws:s3:::staging-uploads" not in resources_no_the
    # With `the`: name extracted
    assert "arn:aws:s3:::staging-uploads" in resources_with_the


def test_resource_miss_dynamodb_no_described_table_pattern() -> None:
    """`describe the orders-prod-2026 dynamodb table` extracts the
    table name (lowercase `dynamodb` works) — but NO PATTERN MATCHES
    so the extracted name is discarded.

    The dynamodb-read pattern's phrases are 'read dynamodb',
    'query dynamodb', 'scan dynamodb', 'read table', etc. — none of
    them include the verb 'describe'. So a describe-only DDB request
    yields no policy at all.
    """
    matched, _actions, _resources, _risk = _run(
        "describe the orders-prod-2026 dynamodb table"
    )
    assert matched == [], (
        "a dynamodb describe pattern was added — replace this pin "
        "with an action-subset / extracted-ARN assertion."
    )


def test_resource_miss_ecs_service_without_the() -> None:
    """`investigate ECS task that crashed in inventory service` —
    no `the` before `inventory` — fails to extract `inventory` as
    the ECS service name. Reverse regex requires `the X service`.

    Result: wildcard `Resource: "*"` and risk 7+.
    """
    _matched, _actions, resources, _risk = _run(
        "investigate ECS task that crashed in inventory service"
    )
    assert resources == ["*"]


# ---------------------------------------------------------------------------
# Class 5: FALSE UNMATCHED — descriptions that SHOULD match a pattern
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("desc", [
    # API Gateway: pattern only fires on 'invoke api gateway' / 'call
    # api gateway' / 'execute api'. `update the api-gateway deployment
    # for v2` and `view the prod-api API Gateway stage` are both
    # clearly API-Gateway tasks that should match an API-Gateway
    # describe/update pattern.
    "update the api-gateway deployment for v2",
    "view the prod-api API Gateway stage",
    # SNS subscribe — only sns-publish exists; subscribing to a topic
    # is a different action set (sns:Subscribe, sns:ListSubscriptions).
    "subscribe to the alerts SNS topic",
    "subscribe to sns topic",
    # NB: removed entries that now match a pattern post-fix:
    #   "rotate secret prod-db-creds" → secrets-rotate (added)
    #   "list all IAM roles tagged ..." → iam-list-roles (added)
    #   "list iam roles" → iam-list-roles (added)
    #   "put metric data" → cloudwatch-metrics-write (added)
    #   "publish a metric to cloudwatch" → cloudwatch-metrics-write
    # Each removed entry now has a positive case pinning the new
    # behavior in test_corpus.py or below.
    # AWS Config — no config pattern exists.
    "describe AWS Config rules for compliance audit",
    "list config rules",
    # Other services with NO pattern at all yet — listed here so the
    # adversarial doc can quantify the coverage gap. These are NOT
    # bugs in the existing patterns; they're the coverage gap.
    "describe Glue jobs in production",
    "list available SageMaker endpoints",
    "list CloudFront distributions",
    "view Athena query history",
    "list EFS file systems and mount targets",
    "describe Route 53 hosted zones for example.com",
    "create a new SES email identity",
    "create a CodePipeline release pipeline",
    # DynamoDB describe — covered separately in
    # test_resource_miss_dynamodb_no_described_table_pattern.
    "describe table prod-orders",
    "put item into the customers ddb table",  # ddb pattern uses
                                              # 'ddb put' not 'put ... ddb'
    "scan the items table for inactive entries",  # phrase 'scan table' not in pattern
    # RDS tag — no rds-tag pattern.
    "tag the prod-database RDS cluster",
])
def test_false_unmatched(desc: str) -> None:
    """A description that should reasonably match a pattern but
    currently returns 'unmatched'. Pinning so adding the relevant
    pattern flips this red.

    When you add a pattern that covers one of these, remove it from
    the parameter list — the test failure for the now-matched case
    is the "fix landed" signal.
    """
    matched, _actions, _resources, _risk = _run(desc)
    assert matched == [], (
        f"description now matches: {matched!r}. If this is the new "
        f"pattern landing, remove {desc!r} from the parametrize list."
    )


# ---------------------------------------------------------------------------
# Honest negatives — cases the generator handles WELL
# ---------------------------------------------------------------------------
#
# These prove coverage: the generator IS doing the right thing for
# many realistic descriptions. Listed here so a future generator
# regression that breaks the easy cases is caught immediately.

@dataclass
class WorkingCase:
    name: str
    description: str
    expected_pattern: str
    expected_action: str
    expected_resource_substring: str | None = None
    max_risk: int = 10


WORKING_CASES: list[WorkingCase] = [
    WorkingCase(
        name="assume-role-named",
        description="assume the deploy-admin role to ship infra",
        expected_pattern="sts-assume-role",
        expected_action="sts:AssumeRole",
        expected_resource_substring=":role/deploy-admin",
        max_risk=4,
    ),
    WorkingCase(
        name="ssm-parameter-path",
        description="check SSM parameter /prod/db/host",
        expected_pattern="ssm-parameter-read",
        expected_action="ssm:GetParameter",
        expected_resource_substring=":parameter/prod/db/host",
        max_risk=2,
    ),
    WorkingCase(
        name="rds-describe-named",
        description="describe the prod-aurora cluster",
        expected_pattern="rds-describe",
        expected_action="rds:DescribeDBClusters",
        expected_resource_substring=":cluster:prod-aurora",
        max_risk=2,
    ),
    WorkingCase(
        name="sns-publish-named-via-topic-syntax",
        description="publish 'hello' to topic on-call-alerts",
        expected_pattern="sns-publish",
        expected_action="sns:Publish",
        expected_resource_substring=":on-call-alerts",
        max_risk=4,
    ),
    WorkingCase(
        name="s3-list-named-bucket",
        description="list objects in the website-assets bucket",
        expected_pattern="s3-read",
        expected_action="s3:ListBucket",
        expected_resource_substring=":website-assets",
        max_risk=2,
    ),
    WorkingCase(
        name="cloudwatch-metric-read-narrow",
        description="view CloudWatch metrics for prod-api",
        expected_pattern="cloudwatch-metrics-read",
        expected_action="cloudwatch:GetMetricData",
        max_risk=5,
    ),
    WorkingCase(
        name="ec2-describe-fleet",
        description="describe the current EC2 fleet and their security groups",
        expected_pattern="ec2-describe",
        expected_action="ec2:DescribeSecurityGroups",
        max_risk=2,
    ),
    WorkingCase(
        name="step-functions-unnamed",
        description="execute the order-reconciliation Step Function",
        expected_pattern="step-functions-execute",
        expected_action="states:StartExecution",
        # NB: resource extraction misses the name (see
        # test_resource_miss_step_function_name_not_extracted) — so
        # this case is "pattern works, resource doesn't" — but the
        # generated policy is still actionable for the agent.
        max_risk=8,
    ),
    WorkingCase(
        name="aurora-data-api-named-cluster",
        description="query the prod-orders Aurora cluster for stale orders",
        expected_pattern="rds-data-query",
        expected_action="rds-data:ExecuteStatement",
        expected_resource_substring=":cluster:",
        max_risk=8,
    ),
    WorkingCase(
        name="logs-search-log-group-path",
        description="view log group /aws/lambda/api",
        expected_pattern="cloudwatch-logs-read",
        expected_action="logs:GetLogEvents",
        expected_resource_substring="log-group:/aws/lambda/api",
        max_risk=2,
    ),
    WorkingCase(
        name="cdk-deploy-stack",
        description="deploy the auth-service CDK stack to staging",
        expected_pattern="cloudformation-deploy",
        expected_action="cloudformation:CreateStack",
        max_risk=10,  # 9 by scorer's CFN+PassRole floor; allowed range
    ),
    WorkingCase(
        name="eventbridge-publish",
        description="trigger an EventBridge event to refresh the cache",
        expected_pattern="eventbridge-publish",
        expected_action="events:PutEvents",
        max_risk=8,
    ),
]


@pytest.mark.parametrize(
    "case",
    [pytest.param(c, id=c.name) for c in WORKING_CASES],
)
def test_working_case(case: WorkingCase) -> None:
    """Honest-negative — the generator handles this case correctly."""
    matched, actions, resources, risk = _run(case.description)
    assert case.expected_pattern in matched, (
        f"{case.name}: expected pattern {case.expected_pattern!r} "
        f"not in {matched!r}"
    )
    assert case.expected_action in actions, (
        f"{case.name}: expected action {case.expected_action!r} "
        f"not in {actions!r}"
    )
    if case.expected_resource_substring is not None:
        assert any(case.expected_resource_substring in r for r in resources), (
            f"{case.name}: expected resource substring "
            f"{case.expected_resource_substring!r} in {resources!r}"
        )
    if risk is not None:
        assert risk <= case.max_risk, (
            f"{case.name}: risk {risk} > max {case.max_risk}"
        )
