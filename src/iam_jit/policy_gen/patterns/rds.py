"""RDS / Aurora / database task patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="rds-describe",
        phrases=(
            "describe rds", "describe cluster", "rds status",
            "check rds", "inspect rds", "view rds", "list rds",
        ),
        allow_actions=(
            "rds:DescribeDBClusters",
            "rds:DescribeDBInstances",
            "rds:DescribeDBSnapshots",
            "rds:DescribeDBParameterGroups",
        ),
        deny_actions=("rds:DescribeDBClusters",),
        resource_kinds=("rds-cluster",),
        wildcard_resources=("*",),
        access_hint="read",
    ),
    Pattern(
        name="rds-data-query",
        phrases=(
            "query aurora", "rds data api", "execute sql", "run sql",
            "aurora data api", "sql query",
        ),
        # Note: rds-data:ExecuteStatement is in HIGH_RISK_ACTIONS in
        # the scorer. The generator suggests it; the scorer floors the
        # output at 7+ which routes to human review. Intentional.
        allow_actions=(
            "rds-data:ExecuteStatement",
            "rds-data:BatchExecuteStatement",
            "rds:DescribeDBClusters",
        ),
        deny_actions=("rds-data:ExecuteStatement",),
        resource_kinds=("rds-cluster",),
        wildcard_resources=("arn:aws:rds:*:*:cluster:*",),
        access_hint="read-write",
    ),
]
