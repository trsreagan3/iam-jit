"""DynamoDB task patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="dynamodb-read",
        phrases=(
            "read dynamodb", "dynamodb read", "query dynamodb", "scan dynamodb",
            "get from dynamodb", "read table", "query table", "ddb read",
            "ddb query", "dynamodb item",
        ),
        allow_actions=(
            "dynamodb:GetItem",
            "dynamodb:BatchGetItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:DescribeTable",
            "dynamodb:ListTables",
        ),
        deny_actions=("dynamodb:GetItem", "dynamodb:Query"),
        resource_kinds=("dynamodb-table",),
        wildcard_resources=("arn:aws:dynamodb:*:*:table/*",),
        access_hint="read",
    ),
    Pattern(
        name="dynamodb-write",
        phrases=(
            "write dynamodb", "dynamodb write", "put dynamodb",
            "update dynamodb", "ddb write", "ddb put", "write item",
            "update table",
        ),
        allow_actions=(
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:BatchWriteItem",
            "dynamodb:DescribeTable",
            "dynamodb:GetItem",     # often read-after-write
        ),
        deny_actions=("dynamodb:PutItem",),
        resource_kinds=("dynamodb-table",),
        wildcard_resources=("arn:aws:dynamodb:*:*:table/*",),
        access_hint="write",
    ),
]
