"""Tests for the deterministic policy reduction primitives (#155).

Per [[aws-managed-baseline-strategy]] + [[agent-driven-reduction-loop]]:
the reduction loop is the core of the agent's narrowing flow. Pure
functions are tested in isolation here; the MCP tool wiring is
tested via _handle_request dispatch.
"""

from __future__ import annotations

import pytest

from iam_jit.mcp_server import _handle_request, _reduce_policy_for_mcp
from iam_jit.reductions import (
    ReductionEntry,
    ReductionResult,
    apply_reductions,
    deny_services,
    narrow_to_accounts,
    narrow_to_regions,
)


def _admin_policy() -> dict:
    """A simple broad-admin shape that's easy to reduce."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
        ],
    }


# ---------------------------------------------------------------------------
# deny_services
# ---------------------------------------------------------------------------


def test_deny_services_appends_deny_statement() -> None:
    policy, entry = deny_services(_admin_policy(), ["rds", "secretsmanager"])
    # Original Allow preserved
    assert any(s["Effect"] == "Allow" for s in policy["Statement"])
    # New Deny appended
    denies = [s for s in policy["Statement"] if s["Effect"] == "Deny"]
    assert len(denies) == 1
    assert denies[0]["Action"] == ["rds:*", "secretsmanager:*"]
    assert denies[0]["Resource"] == "*"
    # Recipe entry recorded
    assert entry == ReductionEntry(axis="deny_services", values=("rds", "secretsmanager"))


def test_deny_services_empty_list_no_op() -> None:
    original = _admin_policy()
    policy, entry = deny_services(original, [])
    assert policy == original  # unchanged
    assert entry is None


def test_deny_services_ignores_non_string_items() -> None:
    policy, entry = deny_services(_admin_policy(), ["rds", 42, None, "secretsmanager"])
    denies = [s for s in policy["Statement"] if s["Effect"] == "Deny"]
    assert denies[0]["Action"] == ["rds:*", "secretsmanager:*"]
    assert entry.values == ("rds", "secretsmanager")


def test_deny_services_handles_single_dict_statement_form() -> None:
    """AWS permits Statement as a single dict (not just a list)."""
    single_dict = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"},
    }
    policy, _ = deny_services(single_dict, ["rds"])
    # Normalized to list + deny appended
    assert isinstance(policy["Statement"], list)
    assert len(policy["Statement"]) == 2
    assert any(s["Effect"] == "Deny" for s in policy["Statement"])


def test_deny_services_does_not_mutate_input() -> None:
    original = _admin_policy()
    original_copy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    deny_services(original, ["rds"])
    assert original == original_copy


# ---------------------------------------------------------------------------
# narrow_to_accounts
# ---------------------------------------------------------------------------


def test_narrow_to_accounts_adds_condition_to_allow() -> None:
    policy, entry = narrow_to_accounts(_admin_policy(), ["111111111111"])
    allow = policy["Statement"][0]
    assert allow["Condition"]["StringEquals"]["aws:RequestedAccount"] == ["111111111111"]
    assert entry == ReductionEntry(axis="narrow_to_accounts", values=("111111111111",))


def test_narrow_to_accounts_rejects_non_12_digit() -> None:
    """AWS account IDs must be exactly 12 digits — non-conforming
    silently dropped (return policy unchanged)."""
    policy, entry = narrow_to_accounts(_admin_policy(), ["not-an-account-id", "123"])
    assert policy == _admin_policy()
    assert entry is None


def test_narrow_to_accounts_does_not_touch_deny_statements() -> None:
    """Conditions are added to ALLOW statements only — Denies should
    still fire regardless of which account is targeted."""
    policy_with_deny = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
        ],
    }
    policy, _ = narrow_to_accounts(policy_with_deny, ["111111111111"])
    # Allow gets condition
    assert "Condition" in policy["Statement"][0]
    # Deny does NOT
    assert "Condition" not in policy["Statement"][1]


def test_narrow_to_accounts_merges_with_existing_condition_values() -> None:
    """If a statement already has a Condition with RequestedAccount,
    merge values rather than overwriting."""
    policy_with_existing = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringEquals": {"aws:RequestedAccount": "222222222222"}
            },
        }],
    }
    policy, _ = narrow_to_accounts(policy_with_existing, ["111111111111"])
    accounts = policy["Statement"][0]["Condition"]["StringEquals"]["aws:RequestedAccount"]
    assert set(accounts) == {"111111111111", "222222222222"}


def test_narrow_to_accounts_empty_no_op() -> None:
    policy, entry = narrow_to_accounts(_admin_policy(), [])
    assert policy == _admin_policy()
    assert entry is None


# ---------------------------------------------------------------------------
# narrow_to_regions
# ---------------------------------------------------------------------------


def test_narrow_to_regions_adds_condition_to_allow() -> None:
    policy, entry = narrow_to_regions(_admin_policy(), ["us-east-1", "us-west-2"])
    cond = policy["Statement"][0]["Condition"]["StringEquals"]
    assert set(cond["aws:RequestedRegion"]) == {"us-east-1", "us-west-2"}
    assert entry.axis == "narrow_to_regions"


def test_narrow_to_regions_does_not_touch_deny_statements() -> None:
    policy_with_deny = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
        ],
    }
    policy, _ = narrow_to_regions(policy_with_deny, ["us-east-1"])
    assert "Condition" in policy["Statement"][0]
    assert "Condition" not in policy["Statement"][1]


def test_narrow_to_regions_empty_no_op() -> None:
    policy, entry = narrow_to_regions(_admin_policy(), [])
    assert policy == _admin_policy()
    assert entry is None


# ---------------------------------------------------------------------------
# apply_reductions — compose multiple
# ---------------------------------------------------------------------------


def test_apply_reductions_all_three_axes() -> None:
    result = apply_reductions(
        _admin_policy(),
        deny_services_list=["rds"],
        narrow_to_accounts_list=["111111111111"],
        narrow_to_regions_list=["us-east-1"],
    )
    # Three recipe entries (one per axis)
    assert len(result.recipe) == 3
    axes = [e.axis for e in result.recipe]
    assert axes == ["deny_services", "narrow_to_accounts", "narrow_to_regions"]
    # Policy reflects all three
    allow = result.policy["Statement"][0]
    assert "Condition" in allow
    cond = allow["Condition"]["StringEquals"]
    assert cond["aws:RequestedAccount"] == ["111111111111"]
    assert cond["aws:RequestedRegion"] == ["us-east-1"]
    # Deny was appended
    denies = [s for s in result.policy["Statement"] if s["Effect"] == "Deny"]
    assert len(denies) == 1
    assert denies[0]["Action"] == ["rds:*"]


def test_apply_reductions_no_op_returns_empty_recipe() -> None:
    result = apply_reductions(_admin_policy())
    assert result.recipe == ()
    assert result.policy == _admin_policy()


def test_apply_reductions_summary_describes_what_was_reduced() -> None:
    result = apply_reductions(
        _admin_policy(),
        deny_services_list=["rds", "secretsmanager"],
        narrow_to_accounts_list=["111111111111"],
    )
    summary = result.to_dict()["summary"]
    assert "rds" in summary
    assert "secretsmanager" in summary
    assert "111111111111" in summary


# ---------------------------------------------------------------------------
# MCP tool — reduce_policy
# ---------------------------------------------------------------------------


def test_mcp_reduce_policy_round_trip() -> None:
    result = _reduce_policy_for_mcp({
        "policy": _admin_policy(),
        "deny_services": ["rds"],
        "narrow_to_accounts": ["111111111111"],
    })
    assert "policy" in result
    assert "recipe" in result
    assert "summary" in result
    # 2 recipe entries (one per axis with input)
    assert len(result["recipe"]) == 2


def test_mcp_reduce_policy_rejects_non_dict_policy() -> None:
    result = _reduce_policy_for_mcp({"policy": "not-a-dict"})
    assert "error" in result
    assert result["policy"] is None


def test_mcp_reduce_policy_rejects_non_list_filters() -> None:
    """Each reduction axis must be a list if provided."""
    for field in ("deny_services", "narrow_to_accounts", "narrow_to_regions"):
        result = _reduce_policy_for_mcp({
            "policy": _admin_policy(),
            field: "not-a-list",
        })
        assert "error" in result
        assert field in result["error"]


def test_mcp_reduce_policy_dispatch_round_trip() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "reduce_policy",
            "arguments": {
                "policy": _admin_policy(),
                "deny_services": ["rds"],
            },
        },
    })
    sc = resp["result"]["structuredContent"]
    assert sc["recipe"][0]["axis"] == "deny_services"
    assert sc["recipe"][0]["values"] == ["rds"]


def test_reduce_policy_appears_in_tools_list() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "reduce_policy" in names
