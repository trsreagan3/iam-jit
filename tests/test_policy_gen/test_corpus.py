"""Generation-corpus regression suite.

Pins down the input → output mapping for representative task
descriptions. A failure means either:
  - The generator's behavior changed (intentional or not).
  - The scorer changed in a way that affects the generated policy's
    score.

Add a new entry when a new pattern lands or a new test description
should be permanently regression-protected. Keep the test data
inline (not YAML files) so a developer reviewing this file can see
both the input and the expected mapping in one place.

For each entry:
  - `description`: the task as a user would type it
  - `expected_patterns`: at least one of these must match
  - `expected_actions_subset`: every action listed must appear in the
    generated policy
  - `expected_score_max`: scored risk must be ≤ this (catches
    accidental broadening)
  - `expected_score_min`: scored risk must be ≥ this (catches
    accidental narrowing)
  - `context`: optional GenerationContext override
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from iam_jit.policy_gen import (
    GenerationContext,
    GenerationRequest,
    generate_policy,
)


@dataclass
class CorpusCase:
    name: str
    description: str
    expected_patterns: list[str]
    expected_actions_subset: list[str] = field(default_factory=list)
    expected_score_max: int = 10
    expected_score_min: int = 1
    bias: str = "allow"
    context: GenerationContext | None = None


CORPUS: list[CorpusCase] = [
    # ---- S3 ----
    CorpusCase(
        name="s3-read-named-bucket",
        description="get S3 data from the prod-data bucket",
        expected_patterns=["s3-read"],
        expected_actions_subset=["s3:GetObject", "s3:ListBucket"],
        expected_score_max=2,
    ),
    CorpusCase(
        name="s3-read-no-bucket",
        description="read S3 data",
        expected_patterns=["s3-read"],
        expected_actions_subset=["s3:GetObject"],
        expected_score_min=4,  # broad-resource → human review
    ),
    CorpusCase(
        name="s3-write-narrow",
        description="upload to bucket archive-2026",
        expected_patterns=["s3-write"],
        expected_actions_subset=["s3:PutObject"],
        # s3:PutObject is a high-impact mutation; floor 5 even on
        # narrow bucket ARN. Acceptable — write to an explicit bucket
        # is the right risk band.
        expected_score_max=5,
    ),

    # ---- Lambda ----
    CorpusCase(
        name="lambda-invoke-named",
        description="invoke the api-handler lambda function",
        expected_patterns=["lambda-invoke"],
        expected_actions_subset=["lambda:InvokeFunction"],
        expected_score_max=4,
    ),
    CorpusCase(
        name="lambda-deploy-with-role",
        description="deploy lambda function api-handler with role app-runtime-role",
        expected_patterns=["lambda-deploy"],
        expected_actions_subset=["lambda:UpdateFunctionCode", "iam:PassRole"],
        # Code-exec + PassRole composition floors at 9 even on narrow
        # ARN — that's the scorer's rule, not a bug. Deploy = inherent
        # risk; the generator's job is to make the resources narrow so
        # the human reviewer can OK the inherent risk with full info.
        expected_score_min=8,
    ),

    # ---- DynamoDB ----
    CorpusCase(
        name="dynamodb-query-named-table",
        description="query DynamoDB table prod-orders",
        expected_patterns=["dynamodb-read"],
        expected_actions_subset=["dynamodb:Query"],
        expected_score_max=2,
    ),

    # ---- CloudWatch Logs ----
    CorpusCase(
        name="logs-read-named-group",
        description="read log group /aws/lambda/api-prod",
        expected_patterns=["cloudwatch-logs-read"],
        expected_actions_subset=["logs:GetLogEvents"],
        expected_score_max=4,
    ),

    # ---- SSM ----
    CorpusCase(
        name="ssm-parameter-read",
        description="get SSM parameter /app/db/password",
        expected_patterns=["ssm-parameter-read"],
        expected_actions_subset=["ssm:GetParameter"],
        expected_score_max=4,
    ),

    # ---- Secrets Manager ----
    CorpusCase(
        name="secrets-read-named",
        description="read secret prod-db-creds",
        expected_patterns=["secrets-read"],
        expected_actions_subset=["secretsmanager:GetSecretValue"],
        expected_score_max=4,
    ),

    # ---- KMS ----
    CorpusCase(
        name="kms-decrypt-named-key",
        description="decrypt with kms key prod-encryption-key",
        expected_patterns=["kms-decrypt"],
        expected_actions_subset=["kms:Decrypt"],
        expected_score_max=4,
    ),

    # ---- Composition: read + decrypt ----
    CorpusCase(
        name="s3-and-kms-decrypt",
        description="read S3 from the prod-data bucket and decrypt with kms-prod key",
        expected_patterns=["s3-read", "kms-decrypt"],
        expected_actions_subset=["s3:GetObject", "kms:Decrypt"],
        expected_score_max=4,
    ),

    # ---- ECS describe ----
    CorpusCase(
        name="ecs-debug-named-service",
        description="debug the prod-inventory ECS service",
        expected_patterns=["ecs-describe"],
        expected_actions_subset=["ecs:DescribeServices"],
        expected_score_max=8,  # ecs:DescribeTasks is secret-bearing
    ),

    # ---- SQS ----
    CorpusCase(
        name="sqs-send-named-queue",
        description="send message to queue order-events",
        expected_patterns=["sqs-send"],
        expected_actions_subset=["sqs:SendMessage"],
        expected_score_max=4,
    ),

    # ---- EC2 ----
    CorpusCase(
        name="ec2-describe",
        description="describe ec2 instances and their statuses",
        expected_patterns=["ec2-describe"],
        expected_actions_subset=["ec2:DescribeInstances"],
        expected_score_max=4,
    ),
    CorpusCase(
        name="ec2-start-stop",
        description="start ec2 instance for testing",
        expected_patterns=["ec2-start-stop"],
        expected_actions_subset=["ec2:StartInstances"],
        # No instance ID extracted → wildcard ARN → HIGH_IMPACT-broad
        # floor 8. Refinement hint should suggest naming the specific
        # instance. The score correctly reflects the actual scope.
        expected_score_max=8,
    ),

    # ---- API Gateway / EventBridge / Step Functions ----
    CorpusCase(
        name="eventbridge-publish",
        description="publish event to eventbridge",
        expected_patterns=["eventbridge-publish"],
        expected_actions_subset=["events:PutEvents"],
        expected_score_max=8,  # Broad event-bus = HIGH_IMPACT-broad
    ),
    CorpusCase(
        name="step-functions-execute",
        description="start state machine execution for order-pipeline",
        expected_patterns=["step-functions-execute"],
        expected_actions_subset=["states:StartExecution"],
        expected_score_max=8,
    ),

    # ---- CloudFormation ----
    CorpusCase(
        name="cloudformation-describe",
        description="list cloudformation stacks",
        expected_patterns=["cloudformation-describe"],
        expected_actions_subset=["cloudformation:ListStacks"],
        expected_score_max=4,
    ),
    CorpusCase(
        name="cloudformation-deploy",
        description="deploy cloudformation stack",
        expected_patterns=["cloudformation-deploy"],
        expected_actions_subset=["cloudformation:CreateStack", "iam:PassRole"],
        # CFN is in CODE_EXECUTION_PRIMITIVES + IAM:PassRole → 9
        expected_score_min=8,
    ),
]


@pytest.mark.parametrize(
    "case",
    [pytest.param(c, id=c.name) for c in CORPUS],
)
def test_corpus_case(case: CorpusCase) -> None:
    """Run one corpus case end-to-end."""
    ctx = case.context or GenerationContext(
        account_id="123456789012", region="us-east-1",
    )
    result = generate_policy(GenerationRequest(
        task_description=case.description,
        context=ctx,
        bias=case.bias,
    ))

    failures: list[str] = []

    if result.policy is None:
        failures.append(f"no policy generated: {result.unmatched_reason}")

    # Pattern check
    for expected in case.expected_patterns:
        if expected not in result.matched_patterns:
            failures.append(
                f"expected pattern {expected!r} to match; "
                f"got {result.matched_patterns!r}"
            )

    # Action subset
    if result.policy:
        all_actions: list[str] = []
        for stmt in result.policy["Statement"]:
            a = stmt["Action"]
            if isinstance(a, str):
                all_actions.append(a)
            else:
                all_actions.extend(a)
        for expected_action in case.expected_actions_subset:
            if expected_action not in all_actions:
                failures.append(
                    f"expected action {expected_action!r} in output; "
                    f"got {all_actions!r}"
                )

    # Score band
    if result.scored_risk is not None:
        if result.scored_risk < case.expected_score_min:
            failures.append(
                f"scored risk {result.scored_risk} below expected min "
                f"{case.expected_score_min}"
            )
        if result.scored_risk > case.expected_score_max:
            failures.append(
                f"scored risk {result.scored_risk} above expected max "
                f"{case.expected_score_max}"
            )

    if failures:
        report = f"\nCorpus case {case.name!r} ({case.description!r}):\n"
        for f in failures:
            report += f"  - {f}\n"
        if result.policy:
            import json
            report += "\nActual policy:\n" + json.dumps(result.policy, indent=2)
        pytest.fail(report)
