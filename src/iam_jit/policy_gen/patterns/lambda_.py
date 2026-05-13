"""Lambda task patterns.

The filename has a trailing underscore because `lambda` is a Python
reserved word.
"""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="lambda-invoke",
        phrases=(
            "invoke lambda", "invoke function", "call lambda", "run lambda",
            "execute lambda", "lambda invoke", "trigger lambda",
        ),
        allow_actions=(
            "lambda:InvokeFunction",
            "lambda:GetFunction",
            "lambda:ListFunctions",
        ),
        deny_actions=("lambda:InvokeFunction",),
        resource_kinds=("lambda-function",),
        wildcard_resources=("arn:aws:lambda:*:*:function:*",),
        access_hint="read-write",
    ),
    Pattern(
        name="lambda-deploy",
        phrases=(
            "deploy lambda", "update lambda", "update function code",
            "publish lambda", "deploy function", "redeploy lambda",
            "ship lambda",
        ),
        allow_actions=(
            "lambda:UpdateFunctionCode",
            "lambda:UpdateFunctionConfiguration",
            "lambda:GetFunction",
            "lambda:PublishVersion",
            "lambda:ListVersionsByFunction",
            "lambda:UpdateAlias",
            "iam:PassRole",        # required to assign execution role on update
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogStreams",
        ),
        deny_actions=("lambda:UpdateFunctionCode",),
        resource_kinds=("lambda-function",),
        wildcard_resources=("arn:aws:lambda:*:*:function:*",),
        access_hint="write",
    ),
    Pattern(
        name="lambda-read-logs",
        phrases=(
            "read lambda logs", "lambda logs", "function logs", "view lambda output",
            "tail lambda",
        ),
        allow_actions=(
            "lambda:GetFunction",
            "logs:GetLogEvents",
            "logs:FilterLogEvents",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams",
        ),
        deny_actions=("logs:GetLogEvents", "logs:DescribeLogStreams"),
        resource_kinds=("lambda-function", "logs-group"),
        wildcard_resources=(
            "arn:aws:lambda:*:*:function:*",
            "arn:aws:logs:*:*:log-group:/aws/lambda/*",
        ),
        access_hint="read",
    ),
]
