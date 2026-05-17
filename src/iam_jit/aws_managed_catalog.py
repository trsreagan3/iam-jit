"""Curated catalog of AWS-managed IAM policies used as recommender
baselines.

Per [[no-nl-synthesis]] (Stage 2, 2026-05-16): the fuzzy-match
functions that used to live here (`match_baseline`, `best_baseline`,
etc.) were deleted because they were part of the joint-
sufficiency failure mode. The catalog itself + browse API
(`list_entries`, `get_entry`) is the surviving surface.

What this module captures per entry:

- The policy's identity (name, ARN)
- One-line summary
- Service coverage (which AWS services it touches)
- Access-type alignment (read-only / read-write / admin)
- Use-case tags for browse-time filtering (e.g. "audit",
  "incident-response") — exposed via `list_entries(tag=...)`
- A representative policy SHAPE (action list, scoping pattern)
  the scorer can grade

When an agent picks a template via `get_entry(name)`, they get
the full policy_shape ready to score / narrow / submit per the
agent-driven reduction loop (see docs/AGENTS.md). No fuzzy
matching — the agent picks by name + optional filter.

Pre-launch ships a SMALL initial catalog (~10 most-common policies).
Full catalog + parameterized task templates + org-curated /
personal-recurring tiers per [[evolving-preset-library]] are
post-launch.
"""

from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass(frozen=True)
class ManagedPolicyEntry:
    """One AWS-managed policy + the metadata the recommender needs."""

    name: str
    arn: str
    summary: str
    services: tuple[str, ...]       # canonical AWS service names
    access_type: str                # "read-only" | "read-write" | "admin"
    use_case_tags: tuple[str, ...]  # kebab-case browse-filter tags ("audit", "incident-response", etc.)
    policy_shape: dict[str, Any]    # representative policy JSON


# Catalog: 10 most-deployed AWS-managed policies + key job-function
# policies. Each `policy_shape` is a representative skeleton, not the
# verbatim AWS policy (those are AWS's to maintain; we link to ARN for
# the canonical version).
_CATALOG: tuple[ManagedPolicyEntry, ...] = (
    # ---- Read-only baselines ----
    ManagedPolicyEntry(
        name="ReadOnlyAccess",
        arn="arn:aws:iam::aws:policy/ReadOnlyAccess",
        summary=(
            "Read-only access to ALL AWS services in the account. "
            "AWS's most-broad read role — typical for auditors, "
            "investigators, on-call read-access."
        ),
        services=("*",),
        access_type="read-only",
        use_case_tags=(
            "read-only", "audit", "investigation", "on-call",
            "explore", "look-around", "everything-read",
            "compliance-read",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "*:Describe*", "*:Get*", "*:List*",
                        "*:View*", "*:Lookup*", "*:Search*",
                    ],
                    "Resource": "*",
                }
            ],
        },
    ),
    ManagedPolicyEntry(
        name="SecurityAudit",
        arn="arn:aws:iam::aws:policy/SecurityAudit",
        summary=(
            "Read-only across security-relevant services (IAM, "
            "CloudTrail, Config, KMS, Network ACLs, etc.). "
            "Compliance-auditor baseline."
        ),
        services=(
            "iam", "cloudtrail", "config", "kms", "ec2",
            "rds", "s3", "logs", "organizations",
        ),
        access_type="read-only",
        use_case_tags=(
            "security-audit", "compliance", "auditor",
            "soc2", "pci", "iso", "security-review",
            "iam-audit", "config-audit", "cloudtrail-audit",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:Get*", "iam:List*",
                        "cloudtrail:Describe*", "cloudtrail:Get*",
                        "config:Describe*", "config:Get*",
                        "kms:List*", "kms:Describe*",
                        "ec2:Describe*",
                        "rds:Describe*",
                        "s3:GetBucket*", "s3:ListAllMyBuckets",
                        "logs:Describe*",
                    ],
                    "Resource": "*",
                }
            ],
        },
    ),
    ManagedPolicyEntry(
        name="AmazonS3ReadOnlyAccess",
        arn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
        summary="Read-only across S3 — list buckets + get objects.",
        services=("s3",),
        access_type="read-only",
        use_case_tags=(
            "s3-read", "s3-readonly", "bucket-read", "object-read",
            "data-read", "log-read", "artifact-read",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:Get*", "s3:List*", "s3:Describe*",
                    ],
                    "Resource": "*",
                }
            ],
        },
    ),
    ManagedPolicyEntry(
        name="CloudWatchReadOnlyAccess",
        arn="arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess",
        summary="Read CloudWatch metrics, alarms, logs.",
        services=("cloudwatch", "logs"),
        access_type="read-only",
        use_case_tags=(
            "cloudwatch", "metrics", "logs-read", "log-investigation",
            "monitoring", "observability", "alarms-read",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "cloudwatch:Describe*", "cloudwatch:Get*",
                        "cloudwatch:List*",
                        "logs:Describe*", "logs:Get*", "logs:FilterLogEvents",
                    ],
                    "Resource": "*",
                }
            ],
        },
    ),
    ManagedPolicyEntry(
        name="AmazonRDSReadOnlyAccess",
        arn="arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess",
        summary="Read-only across RDS — describe instances, snapshots, clusters.",
        services=("rds",),
        access_type="read-only",
        use_case_tags=(
            "rds-read", "database-read", "db-investigation",
            "rds-describe", "rds-audit",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["rds:Describe*", "rds:List*"],
                    "Resource": "*",
                }
            ],
        },
    ),
    # ---- Broad-read-with-sensitive-exclusions (the "I'm not sure" baseline) ----
    # Per [[broad-read-fallback-ux]]: when the user is uncertain
    # which resources they need AND would otherwise be guessing
    # narrow scopes that turn out to be insufficient, this gives
    # them broad visibility with the sensitive bits excluded.
    # Not technically an AWS-managed policy — it's composed from
    # `ReadOnlyAccess` minus a denylist for secrets + KMS decrypt
    # + conventionally-named sensitive S3 buckets.
    ManagedPolicyEntry(
        name="ExploreReadOnlyWithSensitiveExclusions",
        arn="iam-jit:catalog/ExploreReadOnlyWithSensitiveExclusions",
        summary=(
            "Read across the entire environment EXCEPT secrets, "
            "KMS decrypt, and conventionally-named sensitive S3 "
            "buckets. The 'I'm investigating, not sure what I "
            "need' baseline — broader than a narrow guess, "
            "safer than admin."
        ),
        services=("*",),
        access_type="read-only",
        use_case_tags=(
            "explore", "investigate", "investigating", "diagnose",
            "diagnosing", "debug", "debugging",
            "not-sure", "look-around", "uncertain", "discovery",
            "general-read", "broad-read", "incident-investigation",
            "post-mortem", "what-changed", "drift", "compare",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadEverything",
                    "Effect": "Allow",
                    "Action": [
                        "*:Describe*", "*:Get*", "*:List*",
                        "*:View*", "*:Lookup*", "*:Search*",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "ExcludeSensitiveReads",
                    "Effect": "Deny",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "ssm:GetParameter",
                        "ssm:GetParameters",
                        "ssm:GetParametersByPath",
                        "kms:Decrypt",
                        "kms:GenerateDataKey",
                        "kms:ReEncryptFrom",
                        "kms:ReEncryptTo",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "ExcludeSensitiveBucketReads",
                    "Effect": "Deny",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [
                        "arn:aws:s3:::*-secrets/*",
                        "arn:aws:s3:::*-sensitive/*",
                        "arn:aws:s3:::*-pii/*",
                        "arn:aws:s3:::*-customer-data/*",
                        "arn:aws:s3:::*-secrets",
                        "arn:aws:s3:::*-sensitive",
                        "arn:aws:s3:::*-pii",
                        "arn:aws:s3:::*-customer-data",
                    ],
                },
            ],
        },
    ),
    # ---- Job-function baselines (read-write) ----
    ManagedPolicyEntry(
        name="DatabaseAdministrator",
        arn="arn:aws:iam::aws:policy/job-function/DatabaseAdministrator",
        summary=(
            "DBA-style access: RDS / DynamoDB / Redshift / "
            "ElastiCache / KMS for encryption keys. Read + most write."
        ),
        services=(
            "rds", "dynamodb", "redshift", "elasticache", "kms",
            "cloudwatch", "logs", "kinesis",
        ),
        access_type="read-write",
        use_case_tags=(
            "dba", "database-admin", "rds-admin", "dynamodb-admin",
            "redshift-admin", "schema-migration", "db-snapshot",
            "db-restore",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "rds:*", "dynamodb:*", "redshift:*",
                        "elasticache:*",
                        "kms:Describe*", "kms:List*",
                        "cloudwatch:Describe*", "cloudwatch:Get*",
                        "logs:Describe*", "logs:Get*", "logs:FilterLogEvents",
                    ],
                    "Resource": "*",
                }
            ],
        },
    ),
    ManagedPolicyEntry(
        name="DataScientist",
        arn="arn:aws:iam::aws:policy/job-function/DataScientist",
        summary=(
            "Athena / EMR / Glue / SageMaker / S3 / Kinesis read+write "
            "for data-lake / ML workflows."
        ),
        services=(
            "athena", "emr", "glue", "sagemaker", "s3",
            "kinesis", "lake-formation",
        ),
        access_type="read-write",
        use_case_tags=(
            "data-lake", "data-lake-read", "data-lake-write",
            "data-scientist", "athena", "glue", "lake-formation",
            "sagemaker", "ml-workflow", "data-pipeline", "etl",
            "data-analyst", "data-engineer",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "athena:*",
                        "glue:Get*", "glue:List*", "glue:Search*",
                        "glue:BatchGet*",
                        "s3:Get*", "s3:List*", "s3:Put*",
                        "lakeformation:Get*", "lakeformation:List*",
                        "emr:Describe*", "emr:List*",
                        "sagemaker:Describe*", "sagemaker:List*",
                        "kinesis:Describe*", "kinesis:List*", "kinesis:Get*",
                    ],
                    "Resource": "*",
                }
            ],
        },
    ),
    ManagedPolicyEntry(
        name="NetworkAdministrator",
        arn="arn:aws:iam::aws:policy/job-function/NetworkAdministrator",
        summary=(
            "VPC / Route 53 / Direct Connect / VPN admin. Networking-focused."
        ),
        services=(
            "ec2", "route53", "directconnect", "elasticloadbalancing",
            "logs", "cloudwatch",
        ),
        access_type="read-write",
        use_case_tags=(
            "network-admin", "vpc", "vpc-admin", "route53",
            "direct-connect", "vpn", "subnet", "security-groups",
            "elb", "alb", "nlb", "network-topology",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:*Vpc*", "ec2:*Subnet*", "ec2:*Route*",
                        "ec2:*Gateway*", "ec2:*NetworkAcl*",
                        "ec2:*SecurityGroup*", "ec2:Describe*",
                        "route53:*",
                        "directconnect:*",
                        "elasticloadbalancing:*",
                    ],
                    "Resource": "*",
                }
            ],
        },
    ),
    # ---- Admin baselines (high-tier, for explicit admin requests) ----
    ManagedPolicyEntry(
        name="PowerUserAccess",
        arn="arn:aws:iam::aws:policy/PowerUserAccess",
        summary=(
            "Full access to everything EXCEPT IAM and Organizations "
            "management. The 'developer' admin baseline."
        ),
        services=("*",),
        access_type="admin",
        use_case_tags=(
            "power-user", "developer-admin", "everything-except-iam",
            "dev-account-admin", "non-iam-admin",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": [
                        "iam:*", "organizations:*", "account:*",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:CreateServiceLinkedRole", "iam:DeleteServiceLinkedRole",
                        "iam:ListRoles", "organizations:DescribeOrganization",
                        "account:ListRegions", "account:GetAccountInformation",
                    ],
                    "Resource": "*",
                },
            ],
        },
    ),
    ManagedPolicyEntry(
        name="AdministratorAccess",
        arn="arn:aws:iam::aws:policy/AdministratorAccess",
        summary="Full admin to every service. The 'break-glass' baseline.",
        services=("*",),
        access_type="admin",
        use_case_tags=(
            "admin", "administrator", "full-admin", "root-equivalent",
            "break-glass", "emergency", "incident-response-admin",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}
            ],
        },
    ),
    # Per [[admin-minus-sensitive-baseline]] (task #154) — the
    # recommended-default admin-class baseline. Broad authority MINUS
    # secret data reads, KMS decrypt, sensitive-named S3 buckets, and
    # audit-infrastructure destruction. Default presentation in the
    # template browser when an admin-class request is needed; raw
    # AdministratorAccess is shown as the "I really need everything"
    # escape hatch.
    ManagedPolicyEntry(
        name="AdminLikeWithSensitiveExclusions",
        arn="iam-jit:catalog/AdminLikeWithSensitiveExclusions",
        summary=(
            "Broad admin power minus the things most admin tasks "
            "don't actually need: secret data reads, KMS decrypt, "
            "sensitive-pattern S3 buckets, audit-infra destruction "
            "+ tampering. Recommended default over raw "
            "AdministratorAccess for incident response, "
            "infrastructure work, and most admin-class tasks. "
            "Customer can tune the denylist per-deployment. "
            "NOTE: this policy DOES NOT block IAM principal-pivot "
            "(Allow `iam:*` + `sts:*` lets the principal create a "
            "new role + assume it, evading the Denies). For full "
            "containment, pair with a Permissions Boundary."
        ),
        services=("*",),
        access_type="admin",
        use_case_tags=(
            "admin", "safe-admin", "admin-default",
            "admin-minus-secrets", "incident-response", "infra-admin",
            "investigate-with-power", "broad-but-safer",
        ),
        policy_shape={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "BroadAdmin",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
                {
                    # LOW-19-03 closure: use wildcards for the ssm read
                    # family (covers GetParameterHistory + future variants)
                    # + add BatchGetSecretValue (added by AWS 2024-01).
                    "Sid": "DenySecretData",
                    "Effect": "Deny",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:BatchGetSecretValue",
                        "ssm:GetParameter*",
                        "kms:Decrypt",
                        "kms:GenerateDataKey",
                        "kms:ReEncrypt*",
                    ],
                    "Resource": "*",
                },
                {
                    # MED-19-01 closure: s3:ListBucket operates on the
                    # BUCKET-level ARN (no trailing /*); object-level
                    # actions need the /* form. Sibling
                    # ExploreReadOnlyWithSensitiveExclusions gets this
                    # right — both forms are needed.
                    "Sid": "DenySensitiveBucketReads",
                    "Effect": "Deny",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:ListBucket",
                    ],
                    "Resource": [
                        "arn:aws:s3:::*-secrets",
                        "arn:aws:s3:::*-secrets/*",
                        "arn:aws:s3:::*-sensitive",
                        "arn:aws:s3:::*-sensitive/*",
                        "arn:aws:s3:::*-pii",
                        "arn:aws:s3:::*-pii/*",
                        "arn:aws:s3:::*-customer-data",
                        "arn:aws:s3:::*-customer-data/*",
                    ],
                },
                {
                    # MED-19-02 closure: use wildcards + cover audit-
                    # tampering (not just destruction).
                    # cloudtrail:UpdateTrail alone is sufficient for
                    # audit evasion (redirect logs to attacker bucket).
                    # cloudtrail:PutEventSelectors filters attacker
                    # activity out of the log. config:Stop*Recorder
                    # silently stops recording. guardduty:UpdateDetector
                    # can disable findings. logs:DeleteLogGroup wipes
                    # custom application logs.
                    "Sid": "DenyAuditInfraDestructionOrTampering",
                    "Effect": "Deny",
                    "Action": [
                        # CloudTrail: destruction + tampering
                        "cloudtrail:Stop*",
                        "cloudtrail:Delete*",
                        "cloudtrail:Update*",
                        "cloudtrail:PutEventSelectors",
                        "cloudtrail:PutInsightSelectors",
                        # Config: destruction + tampering
                        "config:Stop*",
                        "config:Delete*",
                        # GuardDuty: destruction + tampering
                        "guardduty:Delete*",
                        "guardduty:Disassociate*",
                        "guardduty:Update*",
                        # CloudWatch Logs: destruction
                        "logs:DeleteLogGroup",
                        "logs:DeleteLogStream",
                        # KMS: key destruction
                        "kms:ScheduleKeyDeletion",
                        "kms:DisableKey",
                    ],
                    "Resource": "*",
                },
            ],
        },
    ),
)


# ---------------------------------------------------------------------------
# Browse API (per [[no-nl-synthesis]]) — exact-lookup, no fuzzy match.
#
# These functions back the new MCP tools list_templates + get_template.
# They EXPOSE the catalog without doing any keyword reasoning. The agent
# (or human) picks an entry by name; no fuzzy auto-fire (which is the
# pattern being deleted in #149 Stage 2).
# ---------------------------------------------------------------------------


def _entry_to_summary_dict(entry: ManagedPolicyEntry) -> dict[str, Any]:
    """Catalog-listing shape — NO inlined policy_shape (use get_entry)."""
    return {
        "name": entry.name,
        "arn": entry.arn,
        "source": "aws-managed",  # only source pre-launch; org/personal post-launch
        "summary": entry.summary,
        "services": list(entry.services),
        "access_type": entry.access_type,
        "tags": list(entry.use_case_tags),
    }


def _entry_to_full_dict(entry: ManagedPolicyEntry) -> dict[str, Any]:
    """Single-entry shape including the full policy_shape."""
    return {
        **_entry_to_summary_dict(entry),
        "policy": entry.policy_shape,
    }


def list_entries(
    *,
    access_type: str | None = None,
    service: str | None = None,
    source: str | None = None,
    query: str | None = None,
    tag: str | None = None,
) -> list[dict[str, Any]]:
    """Browse the catalog. Returns metadata only (no policy_shape).

    Filters:
    - access_type: 'read-only' | 'read-write' | 'admin' — exact match
    - service: AWS service prefix (e.g. 's3') — matches if entry.services
      contains the service or contains '*' (catch-all baselines)
    - source: 'aws-managed' | 'org-curated' | 'personal-recurring' — pre-launch
      only 'aws-managed' returns entries; the other two are reserved
    - query: case-insensitive substring on entry.name — NO fuzzy match
    - tag: exact match against an entry's use_case_tags (e.g. 'audit',
      'incident-response', 'explore'). Case-insensitive. NO fuzzy match.
    """
    out: list[ManagedPolicyEntry] = list(_CATALOG)
    if access_type is not None:
        out = [e for e in out if e.access_type == access_type]
    if service is not None:
        svc_lc = service.lower()
        out = [
            e for e in out
            if "*" in e.services or any(s.lower() == svc_lc for s in e.services)
        ]
    if source is not None and source != "aws-managed":
        # Pre-launch: only aws-managed source. org-curated / personal-recurring
        # are valid filter values but return nothing until those tiers land.
        return []
    if query is not None and query.strip():
        q = query.strip().lower()
        out = [e for e in out if q in e.name.lower()]
    if tag is not None and tag.strip():
        t = tag.strip().lower()
        out = [e for e in out if any(tg.lower() == t for tg in e.use_case_tags)]
    return [_entry_to_summary_dict(e) for e in out]


def get_entry(name: str) -> dict[str, Any] | None:
    """Fetch one entry by EXACT name match. Returns full policy_shape."""
    if not isinstance(name, str) or not name:
        return None
    for entry in _CATALOG:
        if entry.name == name:
            return _entry_to_full_dict(entry)
    return None
