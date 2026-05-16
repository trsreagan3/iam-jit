"""Tests for the AWS-managed-policy catalog.

Stage 2 of [[no-nl-synthesis]] (#149) deleted the fuzzy-match
functions (`match_baseline`, `best_baseline`, `confidence_label`,
`_score_match`, `_tokenize`). The catalog itself + the
browse-API (`list_entries`, `get_entry`) stay. This file tests
the surviving surfaces.

The browse API is exercised more thoroughly via the MCP
dispatch tests in `test_mcp_template_tools.py`. The tests here
cover catalog data hygiene + direct calls into the browse
functions.
"""

from __future__ import annotations

from iam_jit.aws_managed_catalog import (
    _CATALOG,
    ManagedPolicyEntry,
    get_entry,
    list_entries,
)


# ---------------------------------------------------------------------------
# Catalog hygiene — every entry must be self-consistent
# ---------------------------------------------------------------------------


def test_catalog_entries_have_required_fields() -> None:
    for entry in _CATALOG:
        assert entry.name, "name required"
        # ARN is either an AWS-managed policy OR an iam-jit-internal
        # composed baseline (e.g. ExploreReadOnlyWithSensitiveExclusions
        # which composes Allow + Deny — not a verbatim AWS-managed shape).
        assert (
            entry.arn.startswith("arn:aws:iam::aws:policy/")
            or entry.arn.startswith("iam-jit:catalog/")
        ), f"unexpected ARN shape on {entry.name}: {entry.arn}"
        assert entry.summary, "summary required"
        assert entry.access_type in ("read-only", "read-write", "admin")
        assert entry.use_case_tags, "at least one use-case tag required"
        assert entry.policy_shape.get("Version") == "2012-10-17"
        assert entry.policy_shape.get("Statement"), "Statement required"


def test_catalog_arns_unique() -> None:
    arns = [e.arn for e in _CATALOG]
    assert len(arns) == len(set(arns)), "duplicate ARN in catalog"


def test_catalog_names_unique() -> None:
    names = [e.name for e in _CATALOG]
    assert len(names) == len(set(names)), "duplicate name in catalog"


def test_explore_baseline_excludes_secrets_in_policy_shape() -> None:
    """The Explore baseline MUST deny secretsmanager:GetSecretValue
    and kms:Decrypt — that's the whole point of the pattern.
    Pre-launch sentinel for the broad-read-with-denylist UX."""
    explore = next(
        e for e in _CATALOG
        if e.name == "ExploreReadOnlyWithSensitiveExclusions"
    )
    stmts = explore.policy_shape["Statement"]
    # First statement: broad Allow on read verbs
    assert stmts[0]["Effect"] == "Allow"
    # Subsequent statements: Deny on sensitive
    deny_actions: list[str] = []
    for s in stmts[1:]:
        assert s["Effect"] == "Deny"
        action_list = s["Action"] if isinstance(s["Action"], list) else [s["Action"]]
        deny_actions.extend(action_list)
    assert "secretsmanager:GetSecretValue" in deny_actions
    assert "kms:Decrypt" in deny_actions


# ---------------------------------------------------------------------------
# AdminLikeWithSensitiveExclusions (task #154) — third baseline in the
# broad-with-denylist family. Pre-launch sentinel that confirms each
# of the four deny categories is present + the wildcard Allow is intact.
# ---------------------------------------------------------------------------


def test_admin_like_baseline_present_in_catalog() -> None:
    """The AdminLikeWithSensitiveExclusions baseline must exist as
    a catalog entry — it's the recommended-default for admin-class
    requests per [[admin-minus-sensitive-baseline]]."""
    names = {e.name for e in _CATALOG}
    assert "AdminLikeWithSensitiveExclusions" in names


def test_admin_like_baseline_has_broad_allow_and_three_deny_statements() -> None:
    entry = next(
        e for e in _CATALOG
        if e.name == "AdminLikeWithSensitiveExclusions"
    )
    assert entry.access_type == "admin"
    assert entry.arn.startswith("iam-jit:catalog/")
    stmts = entry.policy_shape["Statement"]
    # Statement 0 is the broad Allow
    assert stmts[0]["Effect"] == "Allow"
    assert stmts[0]["Action"] == "*"
    assert stmts[0]["Resource"] == "*"
    # Statements 1-3 are the three deny-category blocks (audit-infra
    # destruction + kms-key destruction are combined into one block).
    deny_stmts = [s for s in stmts[1:] if s["Effect"] == "Deny"]
    assert len(deny_stmts) == 3
    deny_sids = {s.get("Sid") for s in deny_stmts}
    assert deny_sids == {
        "DenySecretData",
        "DenySensitiveBucketReads",
        "DenyAuditInfraDestruction",
    }


def test_admin_like_baseline_denies_secret_data() -> None:
    entry = next(
        e for e in _CATALOG
        if e.name == "AdminLikeWithSensitiveExclusions"
    )
    deny_actions: list[str] = []
    for s in entry.policy_shape["Statement"][1:]:
        actions = s["Action"] if isinstance(s["Action"], list) else [s["Action"]]
        deny_actions.extend(actions)
    # Critical secret-reads must be in the deny list
    for action in ["secretsmanager:GetSecretValue", "ssm:GetParameter",
                   "kms:Decrypt", "kms:GenerateDataKey"]:
        assert action in deny_actions, f"missing critical deny: {action}"


def test_admin_like_baseline_denies_sensitive_s3_patterns() -> None:
    entry = next(
        e for e in _CATALOG
        if e.name == "AdminLikeWithSensitiveExclusions"
    )
    # Find the sensitive-bucket-deny statement
    sensitive_deny = next(
        s for s in entry.policy_shape["Statement"]
        if s.get("Sid") == "DenySensitiveBucketReads"
    )
    resources = sensitive_deny["Resource"]
    for pattern in ["*-secrets/*", "*-sensitive/*", "*-pii/*", "*-customer-data/*"]:
        assert any(pattern in r for r in resources), f"missing pattern: {pattern}"


def test_admin_like_baseline_denies_audit_infra_destruction() -> None:
    """Even with broad admin power, the audit trail must survive
    a (hypothetical) compromise — cloudtrail/config/guardduty are
    pinned + KMS key destruction is blocked."""
    entry = next(
        e for e in _CATALOG
        if e.name == "AdminLikeWithSensitiveExclusions"
    )
    audit_deny = next(
        s for s in entry.policy_shape["Statement"]
        if s.get("Sid") == "DenyAuditInfraDestruction"
    )
    actions = audit_deny["Action"]
    for action in ["cloudtrail:StopLogging", "config:DeleteConfigRule",
                   "guardduty:DeleteDetector", "kms:ScheduleKeyDeletion"]:
        assert action in actions, f"missing audit-infra-destruction deny: {action}"


def test_admin_like_baseline_filterable_by_admin_access_type() -> None:
    """Browsing admin-tier templates should include AdminLikeWithSensitiveExclusions."""
    admin_entries = list_entries(access_type="admin")
    names = {e["name"] for e in admin_entries}
    assert "AdminLikeWithSensitiveExclusions" in names
    assert "AdministratorAccess" in names


def test_admin_like_baseline_get_entry_returns_policy() -> None:
    """get_entry should fetch the AdminLike baseline's full body."""
    entry = get_entry("AdminLikeWithSensitiveExclusions")
    assert entry is not None
    assert entry["access_type"] == "admin"
    assert entry["policy"]["Statement"][0]["Effect"] == "Allow"


# ---------------------------------------------------------------------------
# Browse API — list_entries with various filters
# ---------------------------------------------------------------------------


def test_list_entries_no_filters_returns_everything() -> None:
    out = list_entries()
    assert len(out) == len(_CATALOG)
    # Spot-check: at least one well-known entry present
    names = {e["name"] for e in out}
    assert "AdministratorAccess" in names
    assert "ExploreReadOnlyWithSensitiveExclusions" in names


def test_list_entries_filter_by_access_type() -> None:
    read_only = list_entries(access_type="read-only")
    assert all(e["access_type"] == "read-only" for e in read_only)
    admin = list_entries(access_type="admin")
    assert all(e["access_type"] == "admin" for e in admin)
    names = {e["name"] for e in admin}
    assert "AdministratorAccess" in names


def test_list_entries_filter_by_service() -> None:
    """A service filter should match entries that include the service
    AND catch-all entries with services=['*']."""
    out = list_entries(service="s3")
    names = {e["name"] for e in out}
    assert "AmazonS3ReadOnlyAccess" in names
    assert "AdministratorAccess" in names  # catch-all
    assert "ReadOnlyAccess" in names  # catch-all


def test_list_entries_filter_source_aws_managed() -> None:
    out = list_entries(source="aws-managed")
    assert len(out) >= 1
    assert all(e["source"] == "aws-managed" for e in out)


def test_list_entries_filter_source_org_curated_empty_pre_launch() -> None:
    """Pre-launch only aws-managed source returns entries; org-curated
    and personal-recurring are reserved for post-launch when those
    tiers ship."""
    assert list_entries(source="org-curated") == []
    assert list_entries(source="personal-recurring") == []


def test_list_entries_filter_by_query_substring_case_insensitive() -> None:
    """The `query` filter is an exact case-insensitive substring on
    `name`. NOT a fuzzy match — that's the deleted code path."""
    out = list_entries(query="ReadOnly")
    assert all("readonly" in e["name"].lower() for e in out)
    # Query that matches nothing returns empty
    assert list_entries(query="ThisStringIsNotInAnyTemplateName") == []


def test_list_entries_filter_by_tag_exact_match() -> None:
    """Tag filter is an exact case-insensitive match against the
    entry's use_case_tags list. NOT fuzzy."""
    # SecurityAudit has 'security-audit' + 'auditor' + 'compliance' tags
    out = list_entries(tag="security-audit")
    names = {e["name"] for e in out}
    assert "SecurityAudit" in names
    # Tag the catalog doesn't have returns empty
    assert list_entries(tag="not-a-real-tag-xyz") == []


def test_list_entries_filter_by_tag_case_insensitive() -> None:
    """Same tag lookup as above but with uppercase input — should
    match regardless of case."""
    out = list_entries(tag="SECURITY-AUDIT")
    names = {e["name"] for e in out}
    assert "SecurityAudit" in names


def test_list_entries_summary_shape_includes_tags_excludes_policy_body() -> None:
    """The listing endpoint MUST NOT inline policy_shape — that would
    bloat MCP responses. Use get_entry() for the full body. The
    summary DOES include tags so agents can filter on subsequent calls."""
    for entry in list_entries():
        assert "policy" not in entry
        assert "policy_shape" not in entry
        assert "tags" in entry
        assert isinstance(entry["tags"], list)
        assert len(entry["tags"]) >= 1


# ---------------------------------------------------------------------------
# Browse API — get_entry by exact name
# ---------------------------------------------------------------------------


def test_get_entry_returns_full_shape_by_name() -> None:
    entry = get_entry("AdministratorAccess")
    assert entry is not None
    assert entry["name"] == "AdministratorAccess"
    assert "policy" in entry
    assert entry["policy"]["Version"] == "2012-10-17"


def test_get_entry_unknown_returns_none() -> None:
    assert get_entry("NotARealTemplate") is None


def test_get_entry_empty_or_non_string_returns_none() -> None:
    assert get_entry("") is None
    assert get_entry(None) is None  # type: ignore[arg-type]


def test_get_entry_exact_match_not_fuzzy() -> None:
    """get_entry requires the EXACT name. Case-sensitive."""
    assert get_entry("AdministratorAccess") is not None
    assert get_entry("administratoraccess") is None


# ---------------------------------------------------------------------------
# Dataclass hygiene
# ---------------------------------------------------------------------------


def test_managed_policy_entry_is_frozen() -> None:
    """Frozen dataclass — entries can't be mutated at runtime."""
    import dataclasses
    entry = ManagedPolicyEntry(
        name="x", arn="iam-jit:catalog/x", summary="",
        services=("s3",), access_type="read-only",
        use_case_tags=("x",), policy_shape={"Version": "2012-10-17", "Statement": []},
    )
    import pytest
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.name = "y"  # type: ignore[misc]
