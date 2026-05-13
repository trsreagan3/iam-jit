"""IAM-related task patterns.

WARNING: these patterns deliberately do NOT include IAM mutation
actions like `iam:AttachRolePolicy`, `iam:CreateRole`, or
`iam:PassRole` standalone. Those are catastrophic-tier in the scorer
and should never be generated from a casual task description.

The only IAM action we generate is `iam:GetRole` for the
read-pattern. PassRole is included as a dependency in patterns that
need it (e.g. `lambda-deploy`) — never as a top-level pattern of
its own.
"""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="iam-role-read",
        phrases=(
            "describe role", "get role", "read iam role", "look up role",
            "inspect role",
        ),
        allow_actions=(
            "iam:GetRole",
            "iam:GetRolePolicy",
            "iam:ListRolePolicies",
            "iam:ListAttachedRolePolicies",
        ),
        deny_actions=("iam:GetRole",),
        resource_kinds=("iam-role",),
        wildcard_resources=("arn:aws:iam::*:role/*",),
        access_hint="read",
    ),
]
