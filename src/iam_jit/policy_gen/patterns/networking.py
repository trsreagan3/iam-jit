"""Route 53 / CloudFront / API Gateway / networking patterns."""

from __future__ import annotations

from . import Pattern

PATTERNS: list[Pattern] = [
    Pattern(
        name="route53-describe",
        phrases=(
            "describe route 53", "describe route53", "list hosted zones",
            "route 53 zone", "route53 zone", "dns zone", "hosted zone",
            "list route53",
        ),
        allow_actions=(
            "route53:ListHostedZones",
            "route53:GetHostedZone",
            "route53:ListResourceRecordSets",
            "route53:GetChange",
        ),
        deny_actions=("route53:ListHostedZones",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="read",
    ),
    Pattern(
        name="route53-change-records",
        phrases=(
            "change route 53", "update route 53", "modify route53",
            "change record set", "update dns", "add dns record",
            "update record set",
        ),
        # route53:ChangeResourceRecordSets is in HIGH_IMPACT — the
        # generator surfaces it but the scorer routes to human review.
        allow_actions=(
            "route53:ChangeResourceRecordSets",
            "route53:GetChange",
            "route53:ListResourceRecordSets",
            "route53:GetHostedZone",
        ),
        deny_actions=("route53:ChangeResourceRecordSets",),
        resource_kinds=(),
        wildcard_resources=("arn:aws:route53:::hostedzone/*",),
        access_hint="write",
    ),
    Pattern(
        name="cloudfront-describe",
        phrases=(
            "describe cloudfront", "list cloudfront", "list distributions",
            "cloudfront distribution",
        ),
        allow_actions=(
            "cloudfront:GetDistribution",
            "cloudfront:ListDistributions",
            "cloudfront:GetDistributionConfig",
            "cloudfront:ListInvalidations",
        ),
        deny_actions=("cloudfront:GetDistribution",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="read",
    ),
    Pattern(
        name="cloudfront-invalidate",
        phrases=(
            "invalidate cloudfront", "cloudfront invalidate",
            "cache invalidation", "invalidate cache", "purge cache",
            "purge cloudfront",
        ),
        allow_actions=(
            "cloudfront:CreateInvalidation",
            "cloudfront:GetInvalidation",
            "cloudfront:ListInvalidations",
            "cloudfront:GetDistribution",
        ),
        deny_actions=("cloudfront:CreateInvalidation",),
        resource_kinds=(),
        wildcard_resources=("*",),
        access_hint="write",
    ),
]
