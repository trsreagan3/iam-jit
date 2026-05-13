"""SSM Parameter Store + Secrets Manager task patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="ssm-parameter-read",
        phrases=(
            "read ssm", "ssm parameter", "get parameter", "parameter store",
            "read parameter", "ssm get",
        ),
        allow_actions=(
            "ssm:GetParameter",
            "ssm:GetParameters",
            "ssm:GetParametersByPath",
            "ssm:DescribeParameters",
        ),
        deny_actions=("ssm:GetParameter",),
        resource_kinds=("ssm-parameter",),
        wildcard_resources=("arn:aws:ssm:*:*:parameter/*",),
        access_hint="read",
    ),
    Pattern(
        name="secrets-read",
        phrases=(
            "read secret", "get secret", "secrets manager", "secret value",
            "fetch secret", "retrieve secret",
        ),
        allow_actions=(
            "secretsmanager:GetSecretValue",
            "secretsmanager:DescribeSecret",
            "secretsmanager:ListSecrets",
        ),
        deny_actions=("secretsmanager:GetSecretValue",),
        resource_kinds=("secretsmanager-secret",),
        wildcard_resources=("arn:aws:secretsmanager:*:*:secret:*",),
        access_hint="read",
    ),
    Pattern(
        name="secrets-rotate",
        phrases=(
            "rotate secret", "rotate credentials", "rotate database credentials",
            "rotate password", "secret rotation",
        ),
        allow_actions=(
            "secretsmanager:RotateSecret",
            "secretsmanager:UpdateSecret",
            "secretsmanager:PutSecretValue",
            "secretsmanager:DescribeSecret",
            "secretsmanager:CancelRotateSecret",
        ),
        deny_actions=("secretsmanager:RotateSecret",),
        resource_kinds=("secretsmanager-secret",),
        wildcard_resources=("arn:aws:secretsmanager:*:*:secret:*",),
        access_hint="write",
    ),
    Pattern(
        name="ssm-parameter-write",
        phrases=(
            "write ssm", "put ssm", "set parameter", "update parameter",
            "create parameter", "ssm put", "store parameter",
        ),
        allow_actions=(
            "ssm:PutParameter",
            "ssm:DeleteParameter",
            "ssm:DescribeParameters",
            "ssm:LabelParameterVersion",
        ),
        deny_actions=("ssm:PutParameter",),
        resource_kinds=("ssm-parameter",),
        wildcard_resources=("arn:aws:ssm:*:*:parameter/*",),
        access_hint="write",
    ),
]
