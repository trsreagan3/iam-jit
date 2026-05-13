"""EC2 task patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="ec2-describe",
        phrases=(
            "describe ec2", "list ec2", "ec2 status", "list instances",
            "describe instance", "check ec2", "view ec2", "inspect ec2",
            "ec2 instance",
        ),
        allow_actions=(
            "ec2:DescribeInstances",
            "ec2:DescribeInstanceStatus",
            "ec2:DescribeImages",
            "ec2:DescribeSnapshots",
            "ec2:DescribeVolumes",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeSubnets",
            "ec2:DescribeVpcs",
        ),
        deny_actions=("ec2:DescribeInstances",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="read",
    ),
    Pattern(
        name="ec2-start-stop",
        phrases=(
            "start ec2", "stop ec2", "reboot ec2", "restart ec2",
            "start instance", "stop instance", "ec2 start", "ec2 stop",
        ),
        allow_actions=(
            "ec2:StartInstances",
            "ec2:StopInstances",
            "ec2:RebootInstances",
            "ec2:DescribeInstances",
        ),
        deny_actions=("ec2:StartInstances", "ec2:StopInstances"),
        resource_kinds=(),
        wildcard_resources=("arn:aws:ec2:*:*:instance/*",),
        access_hint="write",
    ),
    Pattern(
        name="ec2-ssm-session",
        phrases=(
            "ssm session", "session manager", "ssm connect",
            "shell into ec2", "ec2 shell", "interactive ec2",
        ),
        # NB: ssm:StartSession is CATASTROPHIC in the scorer — the
        # generated policy will score 9. Intentional: SSM Session
        # Manager grants interactive RCE on the target instance.
        allow_actions=(
            "ssm:StartSession",
            "ssm:DescribeInstanceInformation",
            "ec2:DescribeInstances",
        ),
        deny_actions=("ssm:StartSession",),
        resource_kinds=(),
        wildcard_resources=("arn:aws:ec2:*:*:instance/*",),
        access_hint="read-write",
    ),
]
