"""Athena / Glue / Redshift / data-lake task patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="athena-query",
        phrases=(
            "athena query", "athena run", "query athena", "run athena",
            "athena start", "athena execution", "athena results",
            "run sql", "execute sql",
        ),
        # Athena queries can read whatever the workgroup permits. The
        # generator should suggest scoping by workgroup ARN; the
        # scorer floors execution-class actions appropriately.
        allow_actions=(
            "athena:StartQueryExecution",
            "athena:GetQueryExecution",
            "athena:GetQueryResults",
            "athena:GetWorkGroup",
            "athena:ListQueryExecutions",
            "athena:StopQueryExecution",
            # Athena queries hit S3 results bucket + Glue catalog
            "s3:GetObject",
            "s3:ListBucket",
            "glue:GetTable",
            "glue:GetTables",
            "glue:GetDatabase",
            "glue:GetDatabases",
            "glue:GetPartitions",
        ),
        deny_actions=("athena:StartQueryExecution", "athena:GetQueryResults"),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="read-write",
    ),
    Pattern(
        name="glue-describe",
        phrases=(
            "describe glue", "list glue", "glue catalog", "glue table",
            "glue database", "describe glue job", "glue inventory",
        ),
        allow_actions=(
            "glue:GetTable",
            "glue:GetTables",
            "glue:GetDatabase",
            "glue:GetDatabases",
            "glue:GetPartitions",
            "glue:GetJob",
            "glue:GetJobs",
            "glue:GetJobRun",
            "glue:GetJobRuns",
        ),
        deny_actions=("glue:GetTable",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="read",
    ),
    Pattern(
        name="redshift-describe",
        phrases=(
            "describe redshift", "list redshift", "redshift cluster",
            "redshift status",
        ),
        allow_actions=(
            "redshift:DescribeClusters",
            "redshift:DescribeClusterParameters",
            "redshift:DescribeClusterSubnetGroups",
            "redshift:DescribeClusterSnapshots",
        ),
        deny_actions=("redshift:DescribeClusters",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="read",
    ),
]
