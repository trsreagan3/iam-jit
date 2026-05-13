"""CloudWatch Logs task patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="cloudwatch-logs-read",
        phrases=(
            "read logs", "read log", "read cloudwatch", "cloudwatch logs",
            "view logs", "tail logs", "search logs", "log search",
            "get log events", "filter logs", "log query", "view log group",
            "log group", "watch log",
        ),
        allow_actions=(
            "logs:GetLogEvents",
            "logs:FilterLogEvents",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams",
            "logs:DescribeMetricFilters",
            "logs:StartQuery",
            "logs:GetQueryResults",
            "logs:StopQuery",
        ),
        deny_actions=("logs:GetLogEvents", "logs:DescribeLogStreams"),
        resource_kinds=("logs-group",),
        wildcard_resources=("arn:aws:logs:*:*:log-group:*",),
        access_hint="read",
    ),
    Pattern(
        name="cloudwatch-metrics-read",
        phrases=(
            "read metrics", "cloudwatch metrics", "get metric data",
            "view metric", "metric statistics", "watch metric",
        ),
        allow_actions=(
            "cloudwatch:GetMetricData",
            "cloudwatch:GetMetricStatistics",
            "cloudwatch:ListMetrics",
            "cloudwatch:DescribeAlarms",
        ),
        deny_actions=("cloudwatch:GetMetricData",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="read",
    ),
    Pattern(
        name="cloudwatch-metrics-write",
        phrases=(
            "publish metric", "put metric", "emit metric", "write metric",
            "publish custom metric", "send metric", "report metric",
            "metric data",
        ),
        allow_actions=(
            "cloudwatch:PutMetricData",
            "cloudwatch:ListMetrics",
        ),
        deny_actions=("cloudwatch:PutMetricData",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="write",
    ),
]
