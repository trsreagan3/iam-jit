"""API Gateway / EventBridge / Step Functions task patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="api-gateway-invoke",
        phrases=(
            "invoke api gateway", "call api gateway", "api gateway invoke",
            "execute api", "call rest api",
        ),
        allow_actions=(
            "execute-api:Invoke",
            "execute-api:ManageConnections",
        ),
        deny_actions=("execute-api:Invoke",),
        resource_kinds=(),
        wildcard_resources=("arn:aws:execute-api:*:*:*",),
        access_hint="read-write",
    ),
    Pattern(
        name="eventbridge-publish",
        phrases=(
            "publish eventbridge", "put events", "eventbridge event",
            "send eventbridge", "trigger eventbridge", "publish event",
        ),
        allow_actions=(
            "events:PutEvents",
            "events:DescribeRule",
            "events:ListRules",
        ),
        deny_actions=("events:PutEvents",),
        resource_kinds=(),
        wildcard_resources=("arn:aws:events:*:*:event-bus/*",),
        access_hint="write",
    ),
    Pattern(
        name="step-functions-execute",
        phrases=(
            "start state machine", "execute state machine", "step function",
            "stepfunctions", "start execution", "run workflow",
        ),
        allow_actions=(
            "states:StartExecution",
            "states:StartSyncExecution",
            "states:DescribeExecution",
            "states:ListExecutions",
            "states:GetExecutionHistory",
        ),
        deny_actions=("states:StartExecution",),
        resource_kinds=(),
        wildcard_resources=("arn:aws:states:*:*:stateMachine:*",),
        access_hint="read-write",
    ),
]
