"""SES email + EFS file system patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="ses-send",
        phrases=(
            "send email", "ses send", "send mail", "email send",
            "send via ses", "send transactional email",
        ),
        # ses:SendEmail is in CROSS_ACCOUNT_EXFIL — phishing-as-org
        # primitive. Generator emits the action; scorer flags broad use.
        allow_actions=(
            "ses:SendEmail",
            "ses:SendRawEmail",
            "ses:SendTemplatedEmail",
            "ses:GetSendStatistics",
            "ses:GetSendQuota",
        ),
        deny_actions=("ses:SendEmail",),
        resource_kinds=(),
        wildcard_resources=("arn:aws:ses:*:*:identity/*",),
        access_hint="write",
    ),
    Pattern(
        name="ses-describe",
        phrases=(
            "describe ses", "list ses", "list identities",
            "ses identities", "ses verified",
        ),
        allow_actions=(
            "ses:ListIdentities",
            "ses:GetIdentityVerificationAttributes",
            "ses:GetSendStatistics",
            "ses:GetSendQuota",
        ),
        deny_actions=("ses:ListIdentities",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="read",
    ),
    Pattern(
        name="efs-describe",
        phrases=(
            "describe efs", "list efs", "efs file system",
            "list file systems",
        ),
        allow_actions=(
            "elasticfilesystem:DescribeFileSystems",
            "elasticfilesystem:DescribeMountTargets",
            "elasticfilesystem:DescribeAccessPoints",
            "elasticfilesystem:DescribeFileSystemPolicy",
        ),
        deny_actions=("elasticfilesystem:DescribeFileSystems",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="read",
    ),
    Pattern(
        name="config-describe",
        phrases=(
            "aws config", "config rules", "list config",
            "describe config", "compliance status",
        ),
        allow_actions=(
            "config:DescribeConfigRules",
            "config:GetComplianceDetailsByConfigRule",
            "config:GetComplianceDetailsByResource",
            "config:DescribeConfigurationRecorders",
            "config:DescribeDeliveryChannels",
        ),
        deny_actions=("config:DescribeConfigRules",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="read",
    ),
]
