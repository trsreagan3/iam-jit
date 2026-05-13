"""CloudFormation / CDK / infra task patterns.

NOTE: Most CloudFormation actions are HIGH_IMPACT or CATASTROPHIC in
the scorer. Patterns here intentionally surface that — the generator
produces policies that score 7+ for any non-trivial CF operation,
routing them to human review. The point isn't to make CF auto-approve
easy; it's to make the JIT request CONCRETE so reviewers can approve
informed.
"""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="cloudformation-describe",
        phrases=(
            "describe cloudformation", "list cloudformation", "list stacks",
            "describe stack", "cloudformation status", "view stack",
            "check stack",
        ),
        allow_actions=(
            "cloudformation:DescribeStacks",
            "cloudformation:DescribeStackEvents",
            "cloudformation:DescribeStackResources",
            "cloudformation:ListStacks",
            "cloudformation:ListStackResources",
            "cloudformation:GetTemplate",
            "cloudformation:GetTemplateSummary",
        ),
        deny_actions=("cloudformation:DescribeStacks",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="read",
    ),
    Pattern(
        name="cloudformation-deploy",
        phrases=(
            "deploy cloudformation", "deploy stack", "create stack",
            "update stack", "cloudformation deploy", "cdk deploy",
            "deploy infrastructure", "deploy cdk", "provision stack",
        ),
        allow_actions=(
            "cloudformation:CreateStack",
            "cloudformation:UpdateStack",
            "cloudformation:CreateChangeSet",
            "cloudformation:ExecuteChangeSet",
            "cloudformation:DescribeStacks",
            "cloudformation:DescribeStackEvents",
            "cloudformation:GetTemplateSummary",
            "iam:PassRole",        # CFN passes a service role for execution
        ),
        deny_actions=("cloudformation:UpdateStack", "cloudformation:CreateChangeSet"),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="write",
    ),
]
