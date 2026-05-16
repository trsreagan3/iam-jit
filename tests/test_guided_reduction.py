"""Tests for the guided-reduction walkthrough OSS scaffolding (#156).

Per [[ui-guided-reduction-pro-tier]]: the OSS foundation ships a
static curated checklist + apply-selections function. The Enterprise
plugin (post-launch, proprietary) adds customer-configurable
checklists + LLM-driven branching on top of this.
"""

from __future__ import annotations

import pytest

from iam_jit.guided_reduction import (
    DEFAULT_CHECKLIST,
    ReductionChecklistItem,
    apply_selections,
    get_checklist,
)
from iam_jit.mcp_server import (
    _apply_reduction_checklist_for_mcp,
    _get_reduction_checklist_for_mcp,
    _handle_request,
)


def _admin_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }


# ---------------------------------------------------------------------------
# Static checklist data
# ---------------------------------------------------------------------------


def test_checklist_has_curated_size() -> None:
    """Per user direction 2026-05-16: 8-12 items, not exhaustive."""
    assert 8 <= len(DEFAULT_CHECKLIST) <= 12


def test_checklist_ids_are_unique() -> None:
    ids = [item.id for item in DEFAULT_CHECKLIST]
    assert len(ids) == len(set(ids)), "duplicate item IDs in checklist"


def test_checklist_has_pre_checked_sensitive_denies() -> None:
    """The sensitive-deny set (secrets, IAM admin, org/billing) should
    be pre-checked-by-default so users see them as 'don't unselect'."""
    pre_checked_ids = {item.id for item in DEFAULT_CHECKLIST if item.default_checked}
    # Critical denies that should be pre-checked
    assert "deny-secrets" in pre_checked_ids
    assert "deny-iam-admin" in pre_checked_ids


def test_checklist_items_serialize_to_dict() -> None:
    for item in DEFAULT_CHECKLIST:
        d = item.to_dict()
        assert d["id"] == item.id
        assert d["label"]
        assert d["description"]
        assert d["reduction_axis"]
        assert isinstance(d["reduction_values"], list)
        assert isinstance(d["default_checked"], bool)


def test_get_checklist_returns_all_items_as_dicts() -> None:
    out = get_checklist()
    assert len(out) == len(DEFAULT_CHECKLIST)
    assert all(isinstance(i, dict) for i in out)


# ---------------------------------------------------------------------------
# apply_selections — pure function
# ---------------------------------------------------------------------------


def test_apply_selections_empty_returns_unchanged_policy() -> None:
    out = apply_selections(_admin_policy(), selected_item_ids=[])
    assert out["recipe"] == []
    assert out["selected_item_ids"] == []


def test_apply_selections_one_item_adds_one_deny() -> None:
    out = apply_selections(_admin_policy(), selected_item_ids=["deny-rds"])
    # The policy now has a Deny statement
    denies = [s for s in out["policy"]["Statement"] if s["Effect"] == "Deny"]
    assert len(denies) == 1
    assert "rds:*" in denies[0]["Action"]
    # Recipe records what was applied
    assert len(out["recipe"]) == 1
    assert out["recipe"][0]["axis"] == "deny_services"
    assert out["selected_item_ids"] == ["deny-rds"]


def test_apply_selections_multiple_items_aggregated_into_one_deny() -> None:
    """Multiple selected items with deny_services axis are aggregated
    into one Deny statement (not separate Denies per item)."""
    out = apply_selections(
        _admin_policy(),
        selected_item_ids=["deny-rds", "deny-dynamodb", "deny-cloudformation"],
    )
    denies = [s for s in out["policy"]["Statement"] if s["Effect"] == "Deny"]
    assert len(denies) == 1  # all aggregated
    deny_actions = denies[0]["Action"]
    assert "rds:*" in deny_actions
    assert "dynamodb:*" in deny_actions
    assert "cloudformation:*" in deny_actions


def test_apply_selections_unknown_id_silently_ignored() -> None:
    """Forward-compat for Enterprise plugin checklists that may add
    items the OSS core doesn't know about."""
    out = apply_selections(
        _admin_policy(),
        selected_item_ids=["deny-rds", "not-a-real-item", "another-unknown"],
    )
    # rds is still applied; unknowns dropped from selected_item_ids
    assert "deny-rds" in out["selected_item_ids"]
    assert "not-a-real-item" not in out["selected_item_ids"]
    assert "another-unknown" not in out["selected_item_ids"]


def test_apply_selections_with_account_narrowing() -> None:
    out = apply_selections(
        _admin_policy(),
        selected_item_ids=["deny-rds"],
        narrow_to_accounts=["111111111111"],
    )
    # Two recipe entries: deny_services + narrow_to_accounts
    axes = [e["axis"] for e in out["recipe"]]
    assert "deny_services" in axes
    assert "narrow_to_accounts" in axes
    # Allow statement has the ResourceAccount condition (CRIT-20-01 closure)
    allow = next(s for s in out["policy"]["Statement"] if s["Effect"] == "Allow")
    cond = allow["Condition"]["StringEquals"]
    assert cond["aws:ResourceAccount"] == ["111111111111"]


def test_apply_selections_with_region_narrowing() -> None:
    out = apply_selections(
        _admin_policy(),
        selected_item_ids=[],
        narrow_to_regions=["us-east-1", "us-west-2"],
    )
    allow = next(s for s in out["policy"]["Statement"] if s["Effect"] == "Allow")
    cond = allow["Condition"]["StringEquals"]
    assert set(cond["aws:RequestedRegion"]) == {"us-east-1", "us-west-2"}


def test_apply_selections_non_list_selections_treated_as_empty() -> None:
    """Defensive: if a malformed payload sends a non-list, treat as []
    rather than crashing."""
    out = apply_selections(_admin_policy(), selected_item_ids="not-a-list")  # type: ignore[arg-type]
    assert out["selected_item_ids"] == []


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


def test_mcp_get_reduction_checklist_returns_full_list() -> None:
    out = _get_reduction_checklist_for_mcp({})
    assert out["total"] == len(DEFAULT_CHECKLIST)
    assert len(out["items"]) == len(DEFAULT_CHECKLIST)


def test_mcp_apply_reduction_checklist_round_trip() -> None:
    out = _apply_reduction_checklist_for_mcp({
        "policy": _admin_policy(),
        "selected_item_ids": ["deny-rds"],
    })
    assert "policy" in out
    assert "recipe" in out
    assert "selected_item_ids" in out
    denies = [s for s in out["policy"]["Statement"] if s["Effect"] == "Deny"]
    assert any("rds:*" in s["Action"] for s in denies)


def test_mcp_apply_reduction_checklist_rejects_non_dict_policy() -> None:
    out = _apply_reduction_checklist_for_mcp({
        "policy": "not-a-dict",
        "selected_item_ids": ["deny-rds"],
    })
    assert "error" in out
    assert out["policy"] is None


def test_mcp_apply_reduction_checklist_rejects_non_list_selected() -> None:
    out = _apply_reduction_checklist_for_mcp({
        "policy": _admin_policy(),
        "selected_item_ids": "not-a-list",
    })
    assert "error" in out


def test_mcp_apply_reduction_checklist_rejects_non_list_account_filter() -> None:
    out = _apply_reduction_checklist_for_mcp({
        "policy": _admin_policy(),
        "selected_item_ids": [],
        "narrow_to_accounts": "not-a-list",
    })
    assert "error" in out


# ---------------------------------------------------------------------------
# Full dispatch round-trip
# ---------------------------------------------------------------------------


def test_dispatch_get_reduction_checklist() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "get_reduction_checklist", "arguments": {}},
    })
    sc = resp["result"]["structuredContent"]
    assert sc["total"] >= 8


def test_dispatch_apply_reduction_checklist() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "apply_reduction_checklist",
            "arguments": {
                "policy": _admin_policy(),
                "selected_item_ids": ["deny-rds", "deny-iam-admin"],
            },
        },
    })
    sc = resp["result"]["structuredContent"]
    assert "policy" in sc
    denies = [s for s in sc["policy"]["Statement"] if s["Effect"] == "Deny"]
    assert len(denies) == 1  # aggregated into one
    deny_actions = denies[0]["Action"]
    assert "rds:*" in deny_actions
    assert "iam:*" in deny_actions


def test_two_new_tools_in_tools_list() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "get_reduction_checklist" in names
    assert "apply_reduction_checklist" in names


# ---------------------------------------------------------------------------
# WB21 closures — description-vs-implementation trust gap
# ---------------------------------------------------------------------------


def _action_blocked_by(action: str, policy: dict, deny_must_match_action: bool = True) -> bool:
    """Return True if `action` is denied by at least one Deny statement
    in `policy`. Honors `*` glob in deny Action strings."""
    import fnmatch

    for s in policy.get("Statement", []):
        if not isinstance(s, dict):
            continue
        if s.get("Effect") != "Deny":
            continue
        deny_actions = s.get("Action", [])
        if isinstance(deny_actions, str):
            deny_actions = [deny_actions]
        for pattern in deny_actions:
            if fnmatch.fnmatchcase(action, pattern):
                return True
    return False


# WB21 MED-21-03 closure: for each checklist item, assert that what
# the description CLAIMS gets blocked is actually blocked in the
# output policy. This is the test that would have failed on
# HIGH-21-01 (deny-s3-writes no-op) and MED-21-01 (deny-secrets
# partial) at PR time.
#
# Map: item_id → list of (action, expect_blocked) tuples that reflect
# what each description promises.
CHECKLIST_BLOCK_CLAIMS: dict[str, list[tuple[str, bool]]] = {
    "deny-secrets": [
        ("secretsmanager:GetSecretValue", True),
        ("secretsmanager:BatchGetSecretValue", True),
        ("ssm:GetParameter", True),
        ("ssm:GetParameters", True),
        ("ssm:GetParametersByPath", True),
        # description explicitly says KMS Decrypt is NOT blocked here
        ("kms:Decrypt", False),
        # reads of non-secret S3 objects should NOT be blocked
        ("s3:GetObject", False),
    ],
    "deny-iam-admin": [
        # the CreateRole-pivot path the description claims to close
        ("iam:CreateRole", True),
        ("iam:PutRolePolicy", True),
        ("iam:PassRole", True),
        ("iam:AttachRolePolicy", True),
        # description honestly says sts:AssumeRole is NOT blocked
        ("sts:AssumeRole", False),
        # description honestly says other-pivot vectors are NOT blocked
        ("kms:CreateGrant", False),
        ("lambda:AddPermission", False),
    ],
    "deny-org-billing": [
        ("organizations:CreateAccount", True),
        ("account:CloseAccount", True),
        ("billing:GetBillingData", True),
    ],
    "deny-rds": [
        ("rds:CreateDBInstance", True),
        ("rds:DeleteDBInstance", True),
        ("rds:DescribeDBInstances", True),
    ],
    "deny-dynamodb": [
        ("dynamodb:PutItem", True),
        ("dynamodb:Scan", True),
    ],
    "deny-s3-writes": [
        # writes that the description promises to block
        ("s3:PutObject", True),
        ("s3:DeleteObject", True),
        ("s3:CreateBucket", True),
        # description says read access is KEPT
        ("s3:GetObject", False),
        ("s3:ListBucket", False),
    ],
    "deny-cloudformation": [
        ("cloudformation:CreateStack", True),
        ("cloudformation:DeleteStack", True),
    ],
    "deny-ecs-eks": [
        ("ecs:RunTask", True),
        ("eks:CreateCluster", True),
    ],
    "deny-lambda-deploy": [
        ("lambda:CreateFunction", True),
        ("lambda:UpdateFunctionCode", True),
        ("lambda:InvokeFunction", True),
    ],
}


@pytest.mark.parametrize("item", DEFAULT_CHECKLIST, ids=lambda i: i.id)
def test_each_checklist_item_description_matches_implementation(item) -> None:
    """For each curated checklist item, the actions its description
    promises to block must actually be blocked when the item is
    selected, AND the actions the description promises NOT to block
    must not be blocked. Caught WB21 HIGH-21-01 + MED-21-01 + MED-21-02
    at PR time."""
    claims = CHECKLIST_BLOCK_CLAIMS.get(item.id)
    assert claims is not None, (
        f"checklist item {item.id} is missing from CHECKLIST_BLOCK_CLAIMS — "
        "add description-vs-implementation expectations alongside any new "
        "item to keep the trust-gap audit honest."
    )
    out = apply_selections(_admin_policy(), selected_item_ids=[item.id])
    # Selected items with non-empty values should be reported as applied.
    if item.reduction_values:
        assert item.id in out["applied_item_ids"], (
            f"{item.id} has values but didn't fire — likely an unknown axis"
        )
    for action, expect_blocked in claims:
        actually_blocked = _action_blocked_by(action, out["policy"])
        assert actually_blocked is expect_blocked, (
            f"{item.id}: action {action!r} expected blocked={expect_blocked} "
            f"but got {actually_blocked}. Description and implementation "
            f"disagree — fix one or the other."
        )


def test_applied_item_ids_distinguishes_selected_from_fired() -> None:
    """WB21 LOW-21-02: a known item whose axis is supported should
    appear in BOTH selected_item_ids and applied_item_ids; an unknown
    item should appear in neither."""
    out = apply_selections(
        _admin_policy(),
        selected_item_ids=["deny-rds", "not-a-real-item"],
    )
    assert "deny-rds" in out["selected_item_ids"]
    assert "deny-rds" in out["applied_item_ids"]
    assert "not-a-real-item" not in out["selected_item_ids"]
    assert "not-a-real-item" not in out["applied_item_ids"]


def test_apply_selections_handles_none_policy() -> None:
    """WB21 LOW-21-03: direct (non-MCP) callers shouldn't get an
    opaque AttributeError. apply_selections returns a structured
    error shape instead."""
    out = apply_selections(None, selected_item_ids=["deny-rds"])  # type: ignore[arg-type]
    assert out["policy"] is None
    assert out["applied_item_ids"] == []
    assert "error" in out


def test_deny_secrets_and_deny_s3_writes_aggregate_into_one_deny_actions() -> None:
    """Both items use deny_actions axis — should produce one Deny
    statement with the union of action globs."""
    out = apply_selections(
        _admin_policy(),
        selected_item_ids=["deny-secrets", "deny-s3-writes"],
    )
    denies = [s for s in out["policy"]["Statement"] if s["Effect"] == "Deny"]
    # One Deny for deny_actions axis (aggregated), since neither item
    # contributed deny_services values.
    assert len(denies) == 1
    deny_actions = denies[0]["Action"]
    # Both items' action globs are present
    assert "secretsmanager:GetSecretValue" in deny_actions
    assert "s3:Put*" in deny_actions


def test_mixed_axes_produce_two_separate_denies() -> None:
    """deny-rds (deny_services) + deny-secrets (deny_actions) should
    produce TWO Deny statements — one per axis."""
    out = apply_selections(
        _admin_policy(),
        selected_item_ids=["deny-rds", "deny-secrets"],
    )
    denies = [s for s in out["policy"]["Statement"] if s["Effect"] == "Deny"]
    assert len(denies) == 2
    axes = {e["axis"] for e in out["recipe"]}
    assert axes == {"deny_services", "deny_actions"}
