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
import datetime as _dt
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
# Severity vocabulary (WB28 LOW-28-02 closure). Structured field on
# every catalog entry so UI / agent / CLI consumers can sort, filter,
# render in color. `None` = "safe / low-risk."
#
# - destructive: irreversible deletes or destroys data (DeleteObject,
#   TerminateInstances, DeleteRole, DeleteDBInstance, DeleteStack,
#   UpdateClusterVersion-on-prod).
# - sensitive: returns secrets, credentials, or encrypted data
#   (GetSecretValue, Decrypt, SecureString-class GetParameter).
# - write: changes state without being immediately destructive
#   (PutObject, PutItem).
# - expensive: incurs material cost beyond audit-log noise
#   (RunInstances, CreateStack).
# - high_risk: principal-pivot or escalation vectors
#   (AssumeRole-broad, PassRole-broad, CreateRole, InvokeFunction-broad).
# - None: low-risk / typically safe to allow broadly (reads / lists /
#   discovery / GetCallerIdentity).
#
# WB28 LOW-28-05 closure: every entry carries `last_reviewed` so the
# review-cadence drift is visible. Quarterly hygiene = bump these +
# re-check prose against AWS docs.
_CATALOG_LAST_REVIEWED = "2026-05"

KNOWN_ACTIONS: dict[str, dict[str, Any]] = {
    "s3:GetObject": {
        "summary": "Read object data from an S3 bucket.",
        "typical_use": (
            "Fetching files for analysis, download, or display. "
            "Common in agent workflows that read training data, "
            "config, or reports."
        ),
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "s3:PutObject": {
        "summary": "Write object data to an S3 bucket.",
        "typical_use": (
            "Uploading reports, checkpoints, build artifacts. "
            "Narrow to specific bucket prefix is recommended."
        ),
        "severity": "write",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "s3:DeleteObject": {
        "summary": "Delete an object from an S3 bucket.",
        "typical_use": (
            "Cleanup workflows. Narrow to specific prefix; avoid "
            "wildcard ARN scope."
        ),
        "severity": "destructive",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "s3:ListBucket": {
        "summary": "List objects in a bucket.",
        "typical_use": "Discovery / pagination over bucket contents.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "s3:HeadObject": {
        "summary": "Check object metadata without reading content.",
        "typical_use": "Existence / size checks before download.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "sts:GetCallerIdentity": {
        "summary": "Returns the principal making the call.",
        "typical_use": (
            "Boto3 / aws-cli often calls this automatically at startup. "
            "Allowing it broadly is safe; it leaks no data."
        ),
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "sts:AssumeRole": {
        "summary": "Switch into a different role's credentials.",
        "typical_use": (
            "Cross-account access or privilege elevation. Narrow to "
            "specific target role ARNs; broad scope is escalation risk."
        ),
        "severity": "high_risk",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "ec2:DescribeInstances": {
        "summary": "Read EC2 instance metadata.",
        "typical_use": "Discovery; often called by ops scripts and monitoring.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "ec2:DescribeSecurityGroups": {
        "summary": "Read security group definitions.",
        "typical_use": "Audit / inventory; safe to allow broadly.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "ec2:RunInstances": {
        "summary": "Launch a new EC2 instance.",
        "typical_use": (
            "Provisioning. Narrow to specific AMI / instance-type / "
            "region; require explicit allow."
        ),
        "severity": "expensive",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "ec2:TerminateInstances": {
        "summary": "Stop and delete EC2 instances.",
        "typical_use": "Cleanup. Narrow to specific instance ARNs.",
        "severity": "destructive",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "iam:GetRole": {
        "summary": "Read IAM role metadata.",
        "typical_use": "Often called by SDKs to resolve trust policies; safe to allow.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "iam:PassRole": {
        "summary": "Allow a service to assume a role on the caller's behalf.",
        "typical_use": (
            "Required by services like EKS / Lambda / ECS. Narrow to "
            "specific role ARNs; broad scope is privilege escalation."
        ),
        "severity": "high_risk",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "iam:CreateRole": {
        "summary": "Create a new IAM role.",
        "typical_use": (
            "Provisioning. Principal-pivot vector. Should be denied "
            "in most workflows."
        ),
        "severity": "high_risk",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "iam:DeleteRole": {
        "summary": "Delete an IAM role.",
        "typical_use": "Cleanup. Usually deny.",
        "severity": "destructive",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "secretsmanager:GetSecretValue": {
        "summary": "Read a secret's value from Secrets Manager.",
        "typical_use": (
            "Loading credentials. Only allow for specific secret ARNs "
            "the workload actually needs."
        ),
        "severity": "sensitive",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "ssm:GetParameter": {
        "summary": "Read a Systems Manager parameter.",
        "typical_use": (
            "Config retrieval. SecureString parameters are sensitive; "
            "narrow to specific parameter names."
        ),
        "severity": "sensitive",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "kms:Decrypt": {
        "summary": "Decrypt a KMS-encrypted value.",
        "typical_use": (
            "Required to read encrypted S3 / RDS / EBS data. Narrow "
            "to specific KMS key ARNs; broad scope is data-exposure risk."
        ),
        "severity": "sensitive",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "dynamodb:GetItem": {
        "summary": "Read a single item from DynamoDB.",
        "typical_use": "Key-based lookup; narrow to specific table ARNs.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "dynamodb:Query": {
        "summary": "Query items from a DynamoDB table.",
        "typical_use": "Range-based read; narrow to specific table ARNs.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "dynamodb:PutItem": {
        "summary": "Write an item to DynamoDB.",
        "typical_use": "Narrow to specific table ARNs.",
        "severity": "write",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "lambda:InvokeFunction": {
        "summary": "Call a Lambda function.",
        "typical_use": (
            "Common in event-driven flows. Narrow to specific function "
            "ARNs; broad scope is privilege escalation."
        ),
        "severity": "high_risk",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "logs:GetLogEvents": {
        "summary": "Read log events from CloudWatch Logs.",
        "typical_use": "Debugging / observability; usually safe to allow broadly.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "logs:DescribeLogGroups": {
        "summary": "List log groups.",
        "typical_use": "Discovery; usually safe.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "cloudwatch:GetMetricStatistics": {
        "summary": "Read CloudWatch metrics.",
        "typical_use": "Monitoring queries; usually safe.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "eks:DescribeCluster": {
        "summary": "Read EKS cluster metadata.",
        "typical_use": "Required by kubectl + most agents working with EKS.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "eks:UpdateClusterVersion": {
        "summary": "Upgrade an EKS cluster's Kubernetes version.",
        "typical_use": "Maintenance. Narrow to specific cluster ARN.",
        "severity": "destructive",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "rds:DescribeDBInstances": {
        "summary": "Read RDS instance metadata.",
        "typical_use": "Discovery / monitoring; safe to allow broadly.",
        "severity": None,
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "rds:DeleteDBInstance": {
        "summary": "Delete an RDS instance.",
        "typical_use": "Irreversible; usually deny.",
        "severity": "destructive",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "cloudformation:CreateStack": {
        "summary": "Create a new CloudFormation stack.",
        "typical_use": (
            "Infrastructure provisioning. Narrow to specific stack-name "
            "patterns where possible."
        ),
        "severity": "expensive",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
    "cloudformation:DeleteStack": {
        "summary": "Delete a CloudFormation stack and its resources.",
        "typical_use": "Cascades to all stack resources.",
        "severity": "destructive",
        "last_reviewed": _CATALOG_LAST_REVIEWED,
    },
}


def research_note(service: str, action: str) -> dict[str, Any] | None:
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
    research_note: dict[str, Any] | None  # curated typical-use note if available

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


def _anchor_arn_prefix(lcp: str) -> str:
    """WB28 HIGH-28-01 helper. Trim an ARN LCP to a sensible boundary
    WITHIN the resource segment, never below the resource-segment
    start.

    ARN structure: arn:partition:service:region:account:resource
    (5 colons separate 6 fields). The resource-segment start is the
    position after the 5th colon.

    Boundary preference: anchor on `/`, `-`, `_` within the resource
    segment (these are meaningful for bucket names + key prefixes
    + identifier patterns). If none of those exist in the resource
    segment portion of the LCP, KEEP the LCP as-is (rather than
    backing up to the resource-segment start and producing a
    service-wide wildcard).

    Examples:
      arn:aws:s3:::reports-2026-q   → arn:aws:s3:::reports-2026-  (anchor on `-`)
      arn:aws:s3:::data/q1/         → arn:aws:s3:::data/q1/       (already ends on `/`)
      arn:aws:s3:::single-bucket    → arn:aws:s3:::single-bucket  (no internal boundary; keep as-is)
      arn:aws:iam::111:role/admin   → arn:aws:iam::111:role/      (anchor on `/`)
    """
    # Locate the resource-segment start (after the 5th colon)
    colon_count = 0
    resource_start = -1
    for i, ch in enumerate(lcp):
        if ch == ":":
            colon_count += 1
            if colon_count == 5:
                resource_start = i + 1
                break
    if resource_start < 0:
        # LCP doesn't even reach the resource segment (degenerate);
        # return as-is.
        return lcp

    resource_part = lcp[resource_start:]
    if not resource_part:
        # LCP ends exactly at the resource-segment start; nothing to
        # anchor within the resource. Return as-is (caller's glob
        # `arn:...account:*` will match all resources in this account).
        return lcp

    # Find the LAST occurrence of any anchor char within the
    # resource segment.
    best_idx = -1
    for delim in ["/", "-", "_"]:
        idx = resource_part.rfind(delim)
        if idx > best_idx:
            best_idx = idx
    if best_idx >= 0:
        # Trim to the anchor (inclusive); keeps the segment meaningful.
        return lcp[: resource_start + best_idx + 1]
    # No internal boundary found in the resource segment. Keep the
    # full LCP — better to risk a slightly-too-specific prefix than
    # to collapse to a service-wide wildcard.
    return lcp


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


# WB28 MED-28-01 closure: fraction-of-support gate. Don't infer a
# scope (ARN or region) unless at least this fraction of the
# group's decisions have observable data for that dimension.
# Without this, 8 calls with arn=None + 2 calls with arn=secret-
# bucket/* would produce a rule scoped to secret-bucket/* — and in
# ENFORCE mode, the 8 None-arn calls would now fail-closed.
ARN_INFER_MIN_FRACTION = 0.5
REGION_INFER_MIN_FRACTION = 0.5


def _detect_arn_prefix(
    arns: list[str | None],
    min_coverage: float = 0.8,
    *,
    total_group_size: int | None = None,
) -> tuple[str | None, str | None]:
    """Detect a useful ARN prefix that covers at least `min_coverage`
    of the non-None ARNs. Returns (prefix_glob, rationale_string).

    Returns (None, None) if too few ARNs share a meaningful prefix.
    Useful prefix = at least the partition + service segments
    (`arn:aws:s3:::`) — shorter prefixes are noise.

    `total_group_size` (WB28 LOW-28-01) is the full group size
    including None-ARN decisions; rationale strings render it so the
    reader sees "2 of 10 calls had observable ARN data" instead of
    the misleading "2 of 2."
    """
    real_arns = [a for a in arns if a]
    n_arns_total = len(arns)
    grp_total = total_group_size if total_group_size is not None else n_arns_total
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
        # WB28 HIGH-28-01 closure: anchor INSIDE the resource segment.
        # Previously the anchor walked back to `:` for any LCP whose
        # tail didn't have a `/`, collapsing e.g. `arn:aws:s3:::reports-
        # 2026-q` (3 distinct buckets sharing a name prefix) to
        # `arn:aws:s3:::` (all S3) — massive over-broadening hidden
        # behind a "100% of ARNs share this prefix" rationale.
        #
        # Correct behavior:
        # 1. Determine the resource-segment start (5th colon, after
        #    arn:partition:service:region:account:).
        # 2. Anchor on `/`, `-`, `_` WITHIN the resource segment —
        #    these are meaningful boundaries for bucket names + keys.
        # 3. Never back up past the resource-segment start (that would
        #    drop to the service-wide wildcard).
        prefix = _anchor_arn_prefix(full_lcp)
        glob = prefix + "*" if not prefix.endswith("*") else prefix
        return glob, _arn_rationale(
            covered=n, observable=n, total=grp_total, prefix=prefix
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
            prefix = _anchor_arn_prefix(cluster_lcp)
            glob = prefix + "*" if not prefix.endswith("*") else prefix
            return glob, _arn_rationale(
                covered=len(best_group),
                observable=n,
                total=grp_total,
                prefix=prefix,
            )

    return None, None


def _arn_rationale(
    *, covered: int, observable: int, total: int, prefix: str
) -> str:
    """Build an ARN-rationale string that honestly surfaces the
    observable-vs-total distinction (WB28 LOW-28-01)."""
    if observable == total:
        pct = round(100.0 * covered / observable) if observable else 0
        return (
            f"{covered} of {observable} observed ARNs share the prefix "
            f"{prefix!r} ({pct}%)"
        )
    # Group has decisions with arn=None; surface that explicitly
    pct = round(100.0 * covered / observable) if observable else 0
    return (
        f"{observable} of {total} calls had observable ARN data; "
        f"of those, {covered} ({pct}%) share the prefix {prefix!r}"
    )


def _detect_region_pattern(
    regions: list[str | None],
    min_coverage: float = 0.9,
    *,
    total_group_size: int | None = None,
) -> tuple[str | None, str | None]:
    """If 90%+ of observed calls were in a single region, return
    that region as a scope + rationale.

    `total_group_size` (WB28 LOW-28-01) — see `_detect_arn_prefix`.
    """
    real_regions = [r for r in regions if r]
    grp_total = total_group_size if total_group_size is not None else len(regions)
    if not real_regions:
        return None, None
    counts = Counter(real_regions)
    most_common_region, count = counts.most_common(1)[0]
    if count / len(real_regions) >= min_coverage:
        if len(real_regions) == grp_total:
            pct = round(100.0 * count / len(real_regions))
            return most_common_region, (
                f"{count} of {len(real_regions)} calls in "
                f"{most_common_region} ({pct}%)"
            )
        pct = round(100.0 * count / len(real_regions))
        return most_common_region, (
            f"{len(real_regions)} of {grp_total} calls had observable "
            f"region; of those, {count} ({pct}%) in {most_common_region}"
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
    include_task_scoped: bool = False,
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

    # WB28 CRIT-28-01 closure: ONLY allow-decisions count toward
    # recommendations. Previously, denied + prompted decisions were
    # aggregated into ALLOW rule recommendations — flipping enforce
    # mode on would have AUTHORIZED previously-blocked calls. The
    # premise of "observe traffic → recommend → enforce" requires
    # that "observed traffic" means "what was allowed and worked,"
    # not "what was attempted including blocked attempts."
    #
    # Sparse-attempt denies are NOT evidence of legitimate use; they
    # may be prompt-injection probing, agent confusion, or
    # exploratory failures. None of those should turn into an
    # ALLOW rule.
    #
    # Decisions without an explicit `decision` field (defensive
    # default) are skipped — the audit log always populates this
    # field, so missing it indicates a malformed row.

    # Group: (service, action) -> list of records
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for d in decisions:
        if d.get("decision") != "allow":
            continue  # WB28 CRIT-28-01: deny/prompt are NOT endorsement
        # WB28 MED-28-05 closure: task-scoped decisions are explicitly
        # "one-off declared sessions" (Slice C). They should not roll
        # up into a permanent global rule recommendation by default.
        # Caller passes `include_task_scoped=True` only when they
        # explicitly want both.
        if not include_task_scoped and d.get("task_id"):
            continue
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

        # WB28 MED-28-01 closure: don't infer a scope from sparse
        # observable data. If <50% of the group's decisions have an
        # ARN, ship the rule without ARN scope rather than scoping
        # to a prefix that the majority of historical traffic
        # wouldn't have matched. Same gate for region.
        arn_observable = sum(1 for a in arns if a)
        region_observable = sum(1 for r in regions if r)
        if arn_observable >= ARN_INFER_MIN_FRACTION * support:
            arn_scope, arn_rationale = _detect_arn_prefix(
                arns,
                min_coverage=arn_prefix_threshold,
                total_group_size=support,
            )
        else:
            arn_scope = None
            arn_rationale = (
                f"only {arn_observable} of {support} calls had observable "
                f"ARN data; not narrowing by ARN scope"
            ) if arn_observable > 0 else None
        if region_observable >= REGION_INFER_MIN_FRACTION * support:
            region_scope, region_rationale = _detect_region_pattern(
                regions,
                min_coverage=region_threshold,
                total_group_size=support,
            )
        else:
            region_scope = None
            region_rationale = (
                f"only {region_observable} of {support} calls had observable "
                f"region; not narrowing by region scope"
            ) if region_observable > 0 else None

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


def filter_decisions_by_window(
    decisions: list[dict[str, Any]],
    *,
    since: str | None,
    until: str | None,
) -> list[dict[str, Any]]:
    """WB28 LOW-28-04 closure: parse `since`/`until` as ISO-8601
    datetimes so mixed-timezone input (e.g. `+00:00` vs `Z`) is
    compared semantically, not lexicographically.

    Falls back to lexicographic compare if a bound is unparseable —
    no exception raised, since the bounds come from user input via
    CLI/MCP and an opaque parse failure would be a worse UX than
    silent fallback to the previous behavior.
    """
    def _parse(s: str | None) -> _dt.datetime | None:
        if not s:
            return None
        try:
            # `fromisoformat` accepts `+00:00` natively; replace `Z`
            # with `+00:00` so Z-suffix also parses.
            return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    since_dt = _parse(since)
    until_dt = _parse(until)
    if since is not None and since_dt is None:
        # Unparseable — fall through to string compare for backward
        # compat with anyone passing exotic input.
        since_dt = None
    if until is not None and until_dt is None:
        until_dt = None

    out: list[dict[str, Any]] = []
    for d in decisions:
        at_raw = d.get("at")
        if at_raw and (since_dt is not None or until_dt is not None):
            at_dt = _parse(at_raw)
            if at_dt is not None:
                if since_dt is not None and at_dt < since_dt:
                    continue
                if until_dt is not None and at_dt > until_dt:
                    continue
                out.append(d)
                continue
        # Fall back to lexicographic
        if since is not None and not (at_raw and at_raw >= since):
            continue
        if until is not None and not (at_raw and at_raw <= until):
            continue
        out.append(d)
    return out


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
    allow = sum(1 for d in decisions if d.get("decision") == "allow")
    deny = sum(1 for d in decisions if d.get("decision") == "deny")
    prompt = sum(1 for d in decisions if d.get("decision") == "prompt")
    total = len(decisions)
    # WB28 LOW-28-03 closure: surface decisions with missing or
    # unrecognized `decision` field so total = allow+deny+prompt+other.
    other = total - allow - deny - prompt
    return {
        "total_calls": total,
        "distinct_services": len(services),
        "distinct_actions": len(actions),
        "allow_count": allow,
        "deny_count": deny,
        "prompt_count": prompt,
        "other_count": other,
        "window_start": min((d.get("at") for d in decisions if d.get("at")), default=None),
        "window_end": max((d.get("at") for d in decisions if d.get("at")), default=None),
    }
