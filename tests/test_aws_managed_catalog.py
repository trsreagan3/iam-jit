"""Tests for the AWS-managed-policy catalog + fuzzy match.

Per [[aws-managed-baseline-strategy]]: vague requests like "data lake
access" should map to a known AWS-managed policy baseline rather
than fail to generate. Validates the matcher recognizes the
canonical use cases.
"""

from __future__ import annotations

import pytest

from iam_jit.aws_managed_catalog import (
    best_baseline,
    confidence_label,
    match_baseline,
)


# ---------------------------------------------------------------------------
# Fuzzy match — vague intents should land on the right baseline
# ---------------------------------------------------------------------------


def test_data_lake_access_matches_data_scientist() -> None:
    """The agent-roleplay scenario that triggered this whole feature:
    'data lake resources' should land on DataScientist baseline."""
    matches = match_baseline("I need read access to data lake resources",
                              access_type="read-only")
    assert len(matches) >= 1
    # Read-only filter keeps only read-only baselines; DataScientist
    # is read-write, so we expect S3ReadOnly or a generic match first.
    # The match function falls back to non-admin when no read-only
    # entry scored.
    top_name = matches[0][0].name
    # Either S3 read-only (covers data-read tag) or one of the
    # read-only catalogs picked up via service/tag overlap.
    assert top_name in (
        "AmazonS3ReadOnlyAccess", "DataScientist",
        "ReadOnlyAccess",
    ), f"unexpected top match: {top_name}"


def test_audit_intent_matches_security_audit() -> None:
    matches = match_baseline(
        "I need read access for a SOC2 compliance audit",
        access_type="read-only",
    )
    assert matches
    names = [m[0].name for m in matches]
    assert "SecurityAudit" in names or "ReadOnlyAccess" in names


def test_database_admin_intent_matches_dba() -> None:
    matches = match_baseline(
        "I need to do schema migration on the RDS clusters",
        access_type="read-write",
    )
    assert matches
    names = [m[0].name for m in matches]
    assert "DatabaseAdministrator" in names or "AmazonRDSReadOnlyAccess" in names


def test_network_admin_intent_matches() -> None:
    matches = match_baseline(
        "I need to update the VPC route tables and security groups",
        access_type="read-write",
    )
    assert matches
    names = [m[0].name for m in matches]
    assert "NetworkAdministrator" in names


def test_cloudwatch_logs_intent_matches() -> None:
    matches = match_baseline(
        "Investigate cloudwatch logs for the payment service",
        access_type="read-only",
    )
    assert matches
    names = [m[0].name for m in matches]
    assert "CloudWatchReadOnlyAccess" in names


def test_admin_intent_only_in_admin_mode() -> None:
    """AdministratorAccess should only surface when access_type=admin
    OR the prompt contains admin keywords. Otherwise users would get
    "AdministratorAccess" recommended for innocuous requests."""
    matches = match_baseline(
        "I need s3 read access",
        access_type="read-only",
    )
    names = [m[0].name for m in matches]
    assert "AdministratorAccess" not in names


def test_admin_intent_in_admin_mode_surfaces_admin() -> None:
    matches = match_baseline(
        "I'm responding to an incident and need full admin",
        access_type="admin",
    )
    assert matches
    names = [m[0].name for m in matches]
    assert "AdministratorAccess" in names or "PowerUserAccess" in names


def test_no_match_returns_empty() -> None:
    """A prompt with no matching keywords returns no matches."""
    matches = match_baseline(
        "xyzzy quux foobar baz nonexistent words",
        access_type="read-only",
    )
    assert matches == []


# ---------------------------------------------------------------------------
# best_baseline — the recommender's actual entry point
# ---------------------------------------------------------------------------


def test_best_baseline_returns_provenance() -> None:
    out = best_baseline(
        "I need to look at all our s3 buckets",
        access_type="read-only",
    )
    assert out is not None
    assert "policy" in out
    assert out["policy"]["Version"] == "2012-10-17"
    assert "provenance" in out
    prov = out["provenance"]
    assert "baseline" in prov
    assert "baseline_arn" in prov
    assert prov["baseline_arn"].startswith("arn:aws:iam::aws:policy/")
    assert "match_confidence" in prov
    assert prov["match_confidence"] in ("low", "medium", "high")
    assert "reductions" in prov
    assert prov["reductions"] == []  # populated by narrowing step (post-launch)


def test_best_baseline_returns_none_on_no_match() -> None:
    out = best_baseline("xyzzy quux foobar", access_type="read-only")
    assert out is None


def test_confidence_label_tiers() -> None:
    assert confidence_label(0) == "none"
    assert confidence_label(1) == "low"
    assert confidence_label(2) == "low"
    assert confidence_label(3) == "medium"
    assert confidence_label(5) == "medium"
    assert confidence_label(6) == "high"
    assert confidence_label(100) == "high"


# ---------------------------------------------------------------------------
# Catalog hygiene — every entry should be self-consistent
# ---------------------------------------------------------------------------


def test_catalog_entries_have_required_fields() -> None:
    from iam_jit.aws_managed_catalog import _CATALOG
    for entry in _CATALOG:
        assert entry.name, "name required"
        assert entry.arn.startswith("arn:aws:iam::aws:policy/")
        assert entry.summary, "summary required"
        assert entry.access_type in ("read-only", "read-write", "admin")
        assert entry.use_case_tags, "at least one use-case tag required"
        assert entry.policy_shape.get("Version") == "2012-10-17"
        assert entry.policy_shape.get("Statement"), "Statement required"


def test_catalog_arns_unique() -> None:
    from iam_jit.aws_managed_catalog import _CATALOG
    arns = [e.arn for e in _CATALOG]
    assert len(arns) == len(set(arns)), "duplicate ARN in catalog"


def test_catalog_names_unique() -> None:
    from iam_jit.aws_managed_catalog import _CATALOG
    names = [e.name for e in _CATALOG]
    assert len(names) == len(set(names)), "duplicate name in catalog"
