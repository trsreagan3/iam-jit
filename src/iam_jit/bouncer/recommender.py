"""Observation-based rule recommender (Slice D of
[[proxy-smart-defaults-and-task-scope]] + [[bouncer-learn-then-recommend]]
+ [[apply-little-snitch-principles]]).

Reads the bouncer's decision audit log over a specified window and
synthesizes a draft ruleset. Closes the loop on lean-permissive
LEARN-mode-first defaults: observe for N days, get a recommendation,
adjust, apply. Without this, the path from learn to enforce was
"stare at thousands of audit-log lines and write rules by hand."

Per [[apply-little-snitch-principles]]: the recommendation is
structured Research-Assistant-style — each suggested rule carries
WHY (frequency + ARN-pattern rationale) + curated typical-use
explanation, so the agent / admin doesn't have to look up what
each AWS action does to review the recommendation.

Per [[scorer-is-ground-truth]]: synthesis is deterministic +
transparent. Frequency + ARN-prefix detection; no LLM in the
synthesis path. The agent always reviews + decides; nothing
auto-applies.
"""

from __future__ import annotations

import dataclasses
from collections import Counter, defaultdict
from typing import Any

from .rules import Effect, ProxyRule


# ---------------------------------------------------------------------------
# Research Assistant — curated typical-use notes for common AWS actions
# ---------------------------------------------------------------------------


# Per [[apply-little-snitch-principles]] Research Assistant pattern:
# common AWS actions get a one-line "what does this do" + "typical
# use" so the agent/admin reading a recommendation doesn't have to
# look up every action separately. Coverage is INTENTIONALLY narrow
# — the most common 30-40 actions cover ~80% of typical observed
# traffic; the rest fall back to a generic "no curated note."
KNOWN_ACTIONS: dict[str, dict[str, str]] = {
    "s3:GetObject": {
        "summary": "Read object data from an S3 bucket.",
        "typical_use": (
            "Fetching files for analysis, download, or display. "
            "Common in agent workflows that read training data, "
            "config, or reports."
        ),
    },
    "s3:PutObject": {
        "summary": "Write object data to an S3 bucket.",
        "typical_use": (
            "Uploading reports, checkpoints, build artifacts. "
            "WRITE — narrows to specific bucket prefix is recommended."
        ),
    },
    "s3:DeleteObject": {
        "summary": "Delete an object from an S3 bucket.",
        "typical_use": (
            "Cleanup workflows. DESTRUCTIVE — narrow to specific "
            "prefix; avoid wildcard ARN scope."
        ),
    },
    "s3:ListBucket": {
        "summary": "List objects in a bucket.",
        "typical_use": "Discovery / pagination over bucket contents.",
    },
    "s3:HeadObject": {
        "summary": "Check object metadata without reading content.",
        "typical_use": "Existence / size checks before download.",
    },
    "sts:GetCallerIdentity": {
        "summary": "Returns the principal making the call.",
        "typical_use": (
            "Boto3 / aws-cli often calls this automatically at startup. "
            "Allowing it broadly is safe; it leaks no data."
        ),
    },
    "sts:AssumeRole": {
        "summary": "Switch into a different role's credentials.",
        "typical_use": (
            "Cross-account access or privilege elevation. Narrow to "
            "specific target role ARNs; broad scope is escalation risk."
        ),
    },
    "ec2:DescribeInstances": {
        "summary": "Read EC2 instance metadata.",
        "typical_use": "Discovery; often called by ops scripts and monitoring.",
    },
    "ec2:DescribeSecurityGroups": {
        "summary": "Read security group definitions.",
        "typical_use": "Audit / inventory; safe to allow broadly.",
    },
    "ec2:RunInstances": {
        "summary": "Launch a new EC2 instance.",
        "typical_use": (
            "Provisioning. EXPENSIVE; narrow to specific AMI / "
            "instance-type / region; require explicit allow."
        ),
    },
    "ec2:TerminateInstances": {
        "summary": "Stop and delete EC2 instances.",
        "typical_use": (
            "Cleanup. DESTRUCTIVE; narrow to specific instance ARNs."
        ),
    },
    "iam:GetRole": {
        "summary": "Read IAM role metadata.",
        "typical_use": "Often called by SDKs to resolve trust policies; safe to allow.",
    },
    "iam:PassRole": {
        "summary": "Allow a service to assume a role on the caller's behalf.",
        "typical_use": (
            "Required by services like EKS / Lambda / ECS. Narrow to "
            "specific role ARNs; broad scope is privilege escalation."
        ),
    },
    "iam:CreateRole": {
        "summary": "Create a new IAM role.",
        "typical_use": (
            "Provisioning. HIGH RISK — principal-pivot vector. "
            "Should be denied in most workflows."
        ),
    },
    "iam:DeleteRole": {
        "summary": "Delete an IAM role.",
        "typical_use": "Cleanup. DESTRUCTIVE; usually deny.",
    },
    "secretsmanager:GetSecretValue": {
        "summary": "Read a secret's value from Secrets Manager.",
        "typical_use": (
            "Loading credentials. SENSITIVE — only allow for specific "
            "secret ARNs the workload actually needs."
        ),
    },
    "ssm:GetParameter": {
        "summary": "Read a Systems Manager parameter.",
        "typical_use": (
            "Config retrieval. SecureString parameters are sensitive; "
            "narrow to specific parameter names."
        ),
    },
    "kms:Decrypt": {
        "summary": "Decrypt a KMS-encrypted value.",
        "typical_use": (
            "Required to read encrypted S3 / RDS / EBS data. Narrow "
            "to specific KMS key ARNs; broad scope is data-exposure risk."
        ),
    },
    "dynamodb:GetItem": {
        "summary": "Read a single item from DynamoDB.",
        "typical_use": "Key-based lookup; narrow to specific table ARNs.",
    },
    "dynamodb:Query": {
        "summary": "Query items from a DynamoDB table.",
        "typical_use": "Range-based read; narrow to specific table ARNs.",
    },
    "dynamodb:PutItem": {
        "summary": "Write an item to DynamoDB.",
        "typical_use": "WRITE; narrow to specific table ARNs.",
    },
    "lambda:InvokeFunction": {
        "summary": "Call a Lambda function.",
        "typical_use": (
            "Common in event-driven flows. Narrow to specific function "
            "ARNs; broad scope is privilege escalation."
        ),
    },
    "logs:GetLogEvents": {
        "summary": "Read log events from CloudWatch Logs.",
        "typical_use": "Debugging / observability; usually safe to allow broadly.",
    },
    "logs:DescribeLogGroups": {
        "summary": "List log groups.",
        "typical_use": "Discovery; usually safe.",
    },
    "cloudwatch:GetMetricStatistics": {
        "summary": "Read CloudWatch metrics.",
        "typical_use": "Monitoring queries; usually safe.",
    },
    "eks:DescribeCluster": {
        "summary": "Read EKS cluster metadata.",
        "typical_use": "Required by kubectl + most agents working with EKS.",
    },
    "eks:UpdateClusterVersion": {
        "summary": "Upgrade an EKS cluster's Kubernetes version.",
        "typical_use": (
            "Maintenance. DESTRUCTIVE; narrow to specific cluster ARN."
        ),
    },
    "rds:DescribeDBInstances": {
        "summary": "Read RDS instance metadata.",
        "typical_use": "Discovery / monitoring; safe to allow broadly.",
    },
    "rds:DeleteDBInstance": {
        "summary": "Delete an RDS instance.",
        "typical_use": "DESTRUCTIVE — irreversible; usually deny.",
    },
    "cloudformation:CreateStack": {
        "summary": "Create a new CloudFormation stack.",
        "typical_use": (
            "Infrastructure provisioning. Narrow to specific stack-name "
            "patterns where possible."
        ),
    },
    "cloudformation:DeleteStack": {
        "summary": "Delete a CloudFormation stack and its resources.",
        "typical_use": "DESTRUCTIVE — cascades to all stack resources.",
    },
}


def research_note(service: str, action: str) -> dict[str, str] | None:
    """Look up the curated explanation for service:action. Returns
    None if not in the catalog (the recommendation just won't have
    a typical_use field)."""
    return KNOWN_ACTIONS.get(f"{service}:{action}")


# ---------------------------------------------------------------------------
# RuleRecommendation
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class RuleRecommendation:
    """One suggested rule + the WHY data the agent / admin needs to
    review it. Per [[apply-little-snitch-principles]] Research
    Assistant pattern: never just "here's a rule," always "here's
    the rule + the observation that justified it + what it does."
    """

    proposed_rule: ProxyRule
    support_count: int  # how many observed calls matched this group
    hit_rate: float  # fraction of all observed calls in the window
    arn_pattern_rationale: str | None  # e.g. "92% hit arn:aws:s3:::reports-*"
    region_pattern_rationale: str | None  # e.g. "all calls in us-east-1"
    research_note: dict[str, str] | None  # curated typical-use note if available

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposed_rule": self.proposed_rule.to_dict(),
            "support_count": self.support_count,
            "hit_rate": round(self.hit_rate, 4),
            "arn_pattern_rationale": self.arn_pattern_rationale,
            "region_pattern_rationale": self.region_pattern_rationale,
            "research_note": self.research_note,
        }


# ---------------------------------------------------------------------------
# Pattern detection helpers
# ---------------------------------------------------------------------------


def _longest_common_prefix(strings: list[str]) -> str:
    """Standard longest common prefix among a list of strings."""
    if not strings:
        return ""
    prefix = strings[0]
    for s in strings[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix


def _detect_arn_prefix(
    arns: list[str | None], min_coverage: float = 0.8
) -> tuple[str | None, str | None]:
    """Detect a useful ARN prefix that covers at least `min_coverage`
    of the non-None ARNs. Returns (prefix_glob, rationale_string).

    Returns (None, None) if too few ARNs share a meaningful prefix.
    Useful prefix = at least the partition + service segments
    (`arn:aws:s3:::`) — shorter prefixes are noise.
    """
    real_arns = [a for a in arns if a]
    if len(real_arns) < 2:
        return None, None

    # Group by common prefixes; find the longest prefix shared by at
    # least min_coverage of arns.
    sorted_arns = sorted(real_arns)
    n = len(sorted_arns)
    threshold = max(2, int(n * min_coverage))

    # Try shrinking the LCP across the largest covered subset.
    # Simple approach: take LCP of the full set, fall back to LCP of
    # subset if too short.
    full_lcp = _longest_common_prefix(sorted_arns)
    if len(full_lcp) >= len("arn:aws:s3:::"):
        # Trim trailing partial-segment characters that don't end at
        # a delimiter — keep at the last `:` or `/`. Otherwise prefix
        # like `arn:aws:s3:::reports-2026-q` looks too specific.
        prefix = full_lcp
        # Anchor on a sensible boundary
        for delim in ["/", ":"]:
            if delim in prefix:
                idx = prefix.rfind(delim)
                if idx > len("arn:aws:") - 1:
                    prefix = prefix[: idx + 1]
                    break
        glob = prefix + "*" if not prefix.endswith("*") else prefix
        return glob, (
            f"{n} of {n} observed ARNs share the prefix {prefix!r} (100%)"
        )

    # No useful full-set LCP. Try to find a majority subset with one.
    # Cluster ARNs by the ARN service-prefix (`arn:partition:service:`)
    # so e.g. S3 ARNs cluster together separately from EC2 ARNs. Then
    # check if the largest cluster has a usable LCP.
    def _service_prefix(a: str) -> str:
        # ARN format: arn:partition:service:region:account:resource
        # First 3 colons separate the first 4 fields; cluster on those.
        parts = a.split(":", 3)
        return ":".join(parts[:3]) if len(parts) >= 3 else a
    clusters: dict[str, list[str]] = defaultdict(list)
    for a in sorted_arns:
        clusters[_service_prefix(a)].append(a)
    best_key, best_group = max(clusters.items(), key=lambda kv: len(kv[1]))
    if len(best_group) >= threshold:
        cluster_lcp = _longest_common_prefix(best_group)
        if len(cluster_lcp) >= len("arn:aws:s3:::"):
            prefix = cluster_lcp
            for delim in ["/", ":"]:
                if delim in prefix:
                    idx = prefix.rfind(delim)
                    if idx > len("arn:aws:") - 1:
                        prefix = prefix[: idx + 1]
                        break
            glob = prefix + "*" if not prefix.endswith("*") else prefix
            pct = round(100.0 * len(best_group) / n)
            return glob, (
                f"{len(best_group)} of {n} observed ARNs ({pct}%) "
                f"share the prefix {prefix!r}"
            )

    return None, None


def _detect_region_pattern(
    regions: list[str | None], min_coverage: float = 0.9
) -> tuple[str | None, str | None]:
    """If 90%+ of observed calls were in a single region, return
    that region as a scope + rationale."""
    real_regions = [r for r in regions if r]
    if not real_regions:
        return None, None
    counts = Counter(real_regions)
    most_common_region, count = counts.most_common(1)[0]
    if count / len(real_regions) >= min_coverage:
        pct = round(100.0 * count / len(real_regions))
        return most_common_region, (
            f"{count} of {len(real_regions)} calls in {most_common_region} ({pct}%)"
        )
    return None, None


# ---------------------------------------------------------------------------
# Main synthesis function
# ---------------------------------------------------------------------------


def synthesize_rules(
    decisions: list[dict[str, Any]],
    *,
    min_support: int = 3,
    arn_prefix_threshold: float = 0.8,
    region_threshold: float = 0.9,
) -> list[RuleRecommendation]:
    """Build a draft ruleset from observed decisions.

    Algorithm:
    1. Group decisions by (service, action).
    2. For each group with support >= min_support:
       - Detect ARN prefix pattern (if a useful prefix exists).
       - Detect region pattern (if 90%+ calls were in one region).
       - Construct ALLOW rule with the detected scopes.
       - Attach Research Assistant note if the action is in KNOWN_ACTIONS.
    3. Sparse groups (support < min_support) are skipped — the agent
       will see those as default-deny in enforce mode + can decide
       whether to add explicit rules.

    Returns recommendations sorted by support DESC (most-observed
    first; agent reviewing can prioritize the high-impact rules).
    """
    if not decisions:
        return []

    # Group: (service, action) -> list of records
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for d in decisions:
        service = d.get("service")
        action = d.get("action")
        if not service or not action:
            continue
        groups[(service.lower(), action)].append(d)

    total = sum(len(g) for g in groups.values())
    if total == 0:
        return []

    recs: list[RuleRecommendation] = []
    for (service, action), group_decisions in groups.items():
        support = len(group_decisions)
        if support < min_support:
            continue

        arns = [d.get("arn") for d in group_decisions]
        regions = [d.get("region") for d in group_decisions]

        arn_scope, arn_rationale = _detect_arn_prefix(
            arns, min_coverage=arn_prefix_threshold
        )
        region_scope, region_rationale = _detect_region_pattern(
            regions, min_coverage=region_threshold
        )

        pattern = f"{service}:{action}"
        rule = ProxyRule(
            pattern=pattern,
            effect=Effect.ALLOW,
            arn_scope=arn_scope,
            region_scope=region_scope,
            note=f"recommended from {support} observed calls",
            origin="recommendation",
        )

        recs.append(RuleRecommendation(
            proposed_rule=rule,
            support_count=support,
            hit_rate=support / total,
            arn_pattern_rationale=arn_rationale,
            region_pattern_rationale=region_rationale,
            research_note=research_note(service, action),
        ))

    # Sort by support DESC, then by service+action for stable output
    recs.sort(key=lambda r: (-r.support_count, r.proposed_rule.pattern))
    return recs


def summarize_window(
    decisions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return aggregate stats for the observation window: total
    calls, distinct services + actions, decision breakdown, time
    range. Useful as the leading paragraph of a `recommend` output."""
    if not decisions:
        return {
            "total_calls": 0,
            "distinct_services": 0,
            "distinct_actions": 0,
            "allow_count": 0,
            "deny_count": 0,
            "prompt_count": 0,
            "window_start": None,
            "window_end": None,
        }
    services = {d.get("service") for d in decisions if d.get("service")}
    actions = {
        (d.get("service"), d.get("action")) for d in decisions
        if d.get("service") and d.get("action")
    }
    return {
        "total_calls": len(decisions),
        "distinct_services": len(services),
        "distinct_actions": len(actions),
        "allow_count": sum(1 for d in decisions if d.get("decision") == "allow"),
        "deny_count": sum(1 for d in decisions if d.get("decision") == "deny"),
        "prompt_count": sum(1 for d in decisions if d.get("decision") == "prompt"),
        "window_start": min((d.get("at") for d in decisions if d.get("at")), default=None),
        "window_end": max((d.get("at") for d in decisions if d.get("at")), default=None),
    }
