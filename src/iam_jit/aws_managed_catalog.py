"""Curated catalog of AWS-managed IAM policies used as recommender
baselines.

Per [[aws-managed-baseline-strategy]] — for many user requests
(especially vague ones like "data lake access"), the right answer
is to START from a known AWS-managed policy and narrow it, not
synthesize from scratch.

This module is the registry + the fuzzy-match function. It does NOT
hard-code the actual policy JSON (those are AWS's to maintain and
some are large) — instead it captures:

- The policy's identity (name, ARN)
- One-line summary
- Service coverage (which AWS services it touches)
- Access-type alignment (read-only / read-write)
- Use-case tags for keyword matching against user prompts
- A representative policy SHAPE (action list, scoping pattern) the
  scorer can grade — this is what the recommender emits as the
  starting point.

When the catalog match succeeds, the recommender returns:

    {
        "policy": {...},          # the representative shape
        "provenance": {
            "baseline": "AmazonS3ReadOnlyAccess",
            "baseline_arn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
            "reductions": [],     # populated by the narrowing step
            "match_confidence": "high" | "medium" | "low",
            "matched_tags": [...],
        },
    }

Pre-launch ships a SMALL initial catalog (~10 most-common policies).
Full catalog is post-launch.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any


@dataclasses.dataclass(frozen=True)
class ManagedPolicyEntry:
    """One AWS-managed policy + the metadata the recommender needs."""

    name: str
    arn: str
    summary: str
    services: tuple[str, ...]       # canonical AWS service names
    access_type: str                # "read-only" | "read-write" | "admin"
    use_case_tags: tuple[str, ...]  # kebab-case keywords for fuzzy match
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
)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


_WORD_SPLIT_RE = re.compile(r"[\s,;_\-/()]+")


def _tokenize(text: str) -> list[str]:
    """Lowercase, split on common separators, strip empty."""
    return [t for t in _WORD_SPLIT_RE.split(text.lower()) if t]


def _score_match(entry: ManagedPolicyEntry, prompt_tokens: list[str]) -> int:
    """Score how well `entry` matches the prompt. Higher = better.

    Each use_case_tag token that appears in the prompt scores 2;
    each service name that appears scores 1.
    """
    score = 0
    prompt_set = set(prompt_tokens)
    # Build a token set from the entry's tags (split kebab-case).
    entry_tag_tokens: set[str] = set()
    for tag in entry.use_case_tags:
        for tok in tag.split("-"):
            if tok:
                entry_tag_tokens.add(tok)
    for tok in entry_tag_tokens:
        if tok in prompt_set:
            score += 2
    for svc in entry.services:
        if svc != "*" and svc in prompt_set:
            score += 1
    return score


def match_baseline(
    prompt: str,
    *,
    access_type: str = "read-only",
    top_k: int = 3,
) -> list[tuple[ManagedPolicyEntry, int]]:
    """Return up to top_k catalog entries ranked by match score.

    Filters by `access_type` first — a read-only request prefers
    read-only baselines, falls back to read-write only if no
    read-only matched. Admin baselines only surface when access_type
    is "admin" or the prompt explicitly contains admin keywords.
    """
    prompt_tokens = _tokenize(prompt)

    # Filter by access_type with permissive fallback.
    if access_type in ("read-only", "read"):
        filtered = [e for e in _CATALOG if e.access_type == "read-only"]
        if not filtered:
            filtered = [e for e in _CATALOG if e.access_type != "admin"]
    elif access_type == "admin":
        filtered = list(_CATALOG)
    else:  # read-write
        filtered = [e for e in _CATALOG if e.access_type != "admin"]

    scored = [(e, _score_match(e, prompt_tokens)) for e in filtered]
    # Only return entries with at least one match signal.
    matched = [(e, s) for e, s in scored if s > 0]
    matched.sort(key=lambda x: x[1], reverse=True)
    return matched[:top_k]


def confidence_label(score: int) -> str:
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    if score >= 1:
        return "low"
    return "none"


def best_baseline(
    prompt: str, *, access_type: str = "read-only",
) -> dict[str, Any] | None:
    """Return the single best match as the recommender's
    starting-point output, or None if no match scored above zero.
    """
    candidates = match_baseline(prompt, access_type=access_type, top_k=1)
    if not candidates:
        return None
    entry, score = candidates[0]
    return {
        "policy": entry.policy_shape,
        "provenance": {
            "baseline": entry.name,
            "baseline_arn": entry.arn,
            "summary": entry.summary,
            "services": list(entry.services),
            "access_type": entry.access_type,
            "match_score": score,
            "match_confidence": confidence_label(score),
            "reductions": [],  # populated by narrowing step (post-launch)
        },
    }
