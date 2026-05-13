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
]
