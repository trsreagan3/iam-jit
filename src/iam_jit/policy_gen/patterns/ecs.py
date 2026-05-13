"""ECS / EKS / container task patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="ecs-describe",
        phrases=(
            "describe ecs", "describe task", "describe service", "list tasks",
            "ecs status", "check ecs", "view ecs", "inspect ecs",
            "debug ecs", "debug service", "debug the service",
            "investigate ecs", "inspect service", "troubleshoot ecs",
            "ecs service",
        ),
        allow_actions=(
            "ecs:DescribeTasks",
            "ecs:DescribeServices",
            "ecs:DescribeClusters",
            "ecs:ListTasks",
            "ecs:ListServices",
            "ecs:ListClusters",
        ),
        deny_actions=("ecs:DescribeTasks", "ecs:ListTasks"),
        resource_kinds=("ecs-service",),
        wildcard_resources=("*",),
        access_hint="read",
    ),
    Pattern(
        name="ecs-deploy",
        phrases=(
            "deploy ecs", "update service", "redeploy ecs", "update task",
            "rolling deploy",
        ),
        allow_actions=(
            "ecs:UpdateService",
            "ecs:RegisterTaskDefinition",
            "ecs:DescribeServices",
            "ecs:DescribeTasks",
            "iam:PassRole",
        ),
        deny_actions=("ecs:UpdateService",),
        resource_kinds=("ecs-service",),
        wildcard_resources=("*",),
        access_hint="write",
    ),
    Pattern(
        name="ecs-stop-task",
        phrases=(
            "stop ecs task", "kill ecs task", "kill the runaway", "kill runaway",
            "terminate ecs task", "stop task", "ecs stop task",
        ),
        allow_actions=(
            "ecs:StopTask",
            "ecs:DescribeTasks",
            "ecs:ListTasks",
        ),
        deny_actions=("ecs:StopTask",),
        resource_kinds=("ecs-service",),
        wildcard_resources=("*",),
        access_hint="write",
    ),
]
