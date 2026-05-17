"""Tests for the bouncer MCP tool surface (Lens A per
[[agent-friendly-not-bypassable]])."""

from __future__ import annotations

import pytest

from iam_jit.mcp_server import (
    _bouncer_add_rule_for_mcp,
    _bouncer_apply_preset_for_mcp,
    _bouncer_decide_for_mcp,
    _bouncer_list_presets_for_mcp,
    _bouncer_list_rules_for_mcp,
    _bouncer_remove_rule_for_mcp,
    _bouncer_show_preset_for_mcp,
    _bouncer_tail_decisions_for_mcp,
    _bouncer_tail_events_for_mcp,
    _handle_request,
)


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch, tmp_path):
    """Point every MCP-bouncer call at a per-test SQLite so they
    don't share state with each other or the user's real DB."""
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "state.db"))
    monkeypatch.setenv("IAM_JIT_BOUNCER_ACTOR", "test-agent")
    yield


# ---------------------------------------------------------------------------
# list_rules + add_rule + remove_rule round-trip
# ---------------------------------------------------------------------------


def test_list_rules_empty() -> None:
    out = _bouncer_list_rules_for_mcp({})
    assert out["count"] == 0
    assert out["rules"] == []


def test_add_rule_happy_path() -> None:
    out = _bouncer_add_rule_for_mcp({
        "pattern": "s3:GetObject",
        "effect": "allow",
        "note": "agent read access",
    })
    assert "error" not in out
    assert out["rule_id"] >= 1
    assert out["audit_event_kind"] == "rule_added"
    # Verify it's now visible
    assert _bouncer_list_rules_for_mcp({})["count"] == 1


def test_add_rule_validates_pattern() -> None:
    out = _bouncer_add_rule_for_mcp({"pattern": "no-colon-here"})
    assert "error" in out
    assert "hint" in out


def test_add_rule_rejects_invalid_effect() -> None:
    out = _bouncer_add_rule_for_mcp({"pattern": "s3:Get*", "effect": "perhaps"})
    assert "error" in out


def test_add_rule_missing_pattern() -> None:
    out = _bouncer_add_rule_for_mcp({})
    assert "error" in out


def test_remove_rule_happy_path() -> None:
    added = _bouncer_add_rule_for_mcp({"pattern": "s3:GetObject"})
    out = _bouncer_remove_rule_for_mcp({"rule_id": added["rule_id"]})
    assert out["removed"] is True
    assert out["audit_event_kind"] == "rule_removed"


def test_remove_rule_unknown_id() -> None:
    out = _bouncer_remove_rule_for_mcp({"rule_id": 99999})
    assert "error" in out


def test_remove_rule_rejects_non_int() -> None:
    out = _bouncer_remove_rule_for_mcp({"rule_id": "1"})
    assert "error" in out


def test_remove_rule_rejects_bool() -> None:
    """bool is subclass of int — explicitly reject."""
    out = _bouncer_remove_rule_for_mcp({"rule_id": True})
    assert "error" in out


# ---------------------------------------------------------------------------
# decide
# ---------------------------------------------------------------------------


def test_decide_no_rules_default_deny() -> None:
    out = _bouncer_decide_for_mcp({
        "service": "ec2",
        "action": "DescribeInstances",
    })
    assert out["decision"] == "deny"
    assert "default-deny" in out["reason"]
    assert "how_to_allow" in out
    assert "bouncer_add_rule" in out["how_to_allow"]


def test_decide_explicit_allow() -> None:
    _bouncer_add_rule_for_mcp({"pattern": "s3:GetObject", "effect": "allow"})
    out = _bouncer_decide_for_mcp({
        "service": "s3",
        "action": "GetObject",
    })
    assert out["decision"] == "allow"
    assert out["matched_rule_id"] == 1
    assert "how_to_allow" not in out  # don't suggest a fix when it allowed


def test_decide_explicit_deny() -> None:
    _bouncer_add_rule_for_mcp({"pattern": "iam:Delete*", "effect": "deny"})
    out = _bouncer_decide_for_mcp({
        "service": "iam",
        "action": "DeleteRole",
    })
    assert out["decision"] == "deny"
    assert out["matched_rule_id"] == 1


def test_decide_learn_mode_never_denies() -> None:
    _bouncer_add_rule_for_mcp({"pattern": "iam:*", "effect": "deny"})
    out = _bouncer_decide_for_mcp({
        "service": "iam",
        "action": "DeleteRole",
        "mode": "learn",
    })
    assert out["decision"] == "allow"


def test_decide_validation_errors() -> None:
    assert "error" in _bouncer_decide_for_mcp({})
    assert "error" in _bouncer_decide_for_mcp({"service": "s3"})
    assert "error" in _bouncer_decide_for_mcp({"action": "X"})
    assert "error" in _bouncer_decide_for_mcp({
        "service": "s3", "action": "X", "mode": "what"
    })


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------


def test_list_presets_returns_all() -> None:
    out = _bouncer_list_presets_for_mcp({})
    assert out["count"] == 4
    names = {p["name"] for p in out["presets"]}
    assert names == {
        "readonly",
        "admin-minus-sensitive",
        "prod-deny-destructive",
        "deny-iam-admin",
    }
    # Rule arrays trimmed from listing (only count survives)
    for p in out["presets"]:
        assert "rules" not in p
        assert "rule_count" in p


def test_show_preset_returns_full_rules() -> None:
    out = _bouncer_show_preset_for_mcp({"preset_name": "readonly"})
    assert "error" not in out
    assert "rules" in out
    assert len(out["rules"]) > 0


def test_show_preset_unknown_name() -> None:
    out = _bouncer_show_preset_for_mcp({"preset_name": "not-a-real-preset"})
    assert "error" in out


def test_apply_preset_adds_rules_and_logs_event() -> None:
    out = _bouncer_apply_preset_for_mcp({"preset_name": "deny-iam-admin"})
    assert "error" not in out
    assert out["rules_added"] > 0
    assert out["audit_event_kind"] == "preset_applied"
    # Verify rules are now in the store
    rules = _bouncer_list_rules_for_mcp({})
    assert rules["count"] == out["rules_added"]
    # Verify the preset_applied event is in the audit log
    events = _bouncer_tail_events_for_mcp({"kind": "preset_applied"})
    assert events["count"] == 1


def test_apply_preset_unknown_name() -> None:
    out = _bouncer_apply_preset_for_mcp({"preset_name": "fake"})
    assert "error" in out


# ---------------------------------------------------------------------------
# Audit logs — both decision and config event
# ---------------------------------------------------------------------------


def test_tail_events_empty() -> None:
    out = _bouncer_tail_events_for_mcp({})
    assert out["count"] == 0


def test_tail_events_captures_add_remove_cycle() -> None:
    added = _bouncer_add_rule_for_mcp({"pattern": "s3:GetObject"})
    _bouncer_remove_rule_for_mcp({"rule_id": added["rule_id"]})
    out = _bouncer_tail_events_for_mcp({})
    assert out["count"] == 2  # one rule_added + one rule_removed
    kinds = {e["kind"] for e in out["events"]}
    assert kinds == {"rule_added", "rule_removed"}


def test_tail_events_kind_filter() -> None:
    _bouncer_apply_preset_for_mcp({"preset_name": "deny-iam-admin"})
    out = _bouncer_tail_events_for_mcp({"kind": "preset_applied"})
    assert out["count"] == 1
    assert out["events"][0]["kind"] == "preset_applied"


def test_tail_events_limit_validation() -> None:
    assert "error" in _bouncer_tail_events_for_mcp({"limit": 0})
    assert "error" in _bouncer_tail_events_for_mcp({"limit": "many"})
    assert "error" in _bouncer_tail_events_for_mcp({"limit": True})


def test_tail_decisions_returns_recorded_decisions() -> None:
    # No tooling path in this commit writes to the decisions table
    # via MCP (Stage 2 proxy will), but the read tool should still
    # work on an empty table.
    out = _bouncer_tail_decisions_for_mcp({})
    assert out["count"] == 0


def test_tail_decisions_invalid_decision_filter() -> None:
    assert "error" in _bouncer_tail_decisions_for_mcp({"decision": "perhaps"})


# ---------------------------------------------------------------------------
# Full MCP dispatch round-trip (verify tools/list includes bouncer tools)
# ---------------------------------------------------------------------------


def test_dispatch_bouncer_list_presets() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "bouncer_list_presets", "arguments": {}},
    })
    sc = resp["result"]["structuredContent"]
    assert sc["count"] == 4


def test_dispatch_bouncer_decide() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "bouncer_decide",
            "arguments": {"service": "s3", "action": "GetObject"},
        },
    })
    sc = resp["result"]["structuredContent"]
    assert sc["decision"] == "deny"
    assert "how_to_allow" in sc


def test_all_bouncer_tools_in_tools_list() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    expected = {
        "bouncer_list_rules",
        "bouncer_add_rule",
        "bouncer_remove_rule",
        "bouncer_decide",
        "bouncer_list_presets",
        "bouncer_show_preset",
        "bouncer_apply_preset",
        "bouncer_tail_events",
        "bouncer_tail_decisions",
    }
    assert expected.issubset(names)


# ---------------------------------------------------------------------------
# Audit-chain invariant: there is no MCP tool that disables the bouncer
# or skips audit. The audit chain has no holes.
# ---------------------------------------------------------------------------


def test_lens_b_no_silent_bypass_mcp_tool() -> None:
    """Per [[agent-friendly-not-bypassable]] Lens B: there must be
    NO MCP tool that disables the bouncer, skips audit, or otherwise
    silently bypasses the gate. Audit the tool list."""
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    bouncer_tools = {
        t["name"] for t in resp["result"]["tools"] if t["name"].startswith("bouncer_")
    }
    forbidden = {
        "bouncer_disable", "bouncer_stop", "bouncer_skip", "bouncer_clear_audit",
        "bouncer_purge_events", "bouncer_set_silent",
    }
    assert not (bouncer_tools & forbidden), (
        f"WB23 closure invariant violated: forbidden bypass tools present: "
        f"{bouncer_tools & forbidden}"
    )


# ---------------------------------------------------------------------------
# Bounce-suite rename (2026-05-17): every `bouncer_*` tool has an
# `ibounce_*` alias; both names dispatch to the same handler.
# ---------------------------------------------------------------------------


def test_tools_list_exposes_ibounce_aliases_for_every_bouncer_tool() -> None:
    """Every `bouncer_*` tool gets an `ibounce_*` alias in the
    `tools/list` response so agents discover the canonical v1.0 names."""
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    bouncer_names = {n for n in names if n.startswith("bouncer_")}
    assert bouncer_names, "expected at least one bouncer_* tool"
    for n in bouncer_names:
        alias = "ibounce_" + n[len("bouncer_"):]
        assert alias in names, f"missing ibounce_* alias for {n}"


def test_bouncer_tool_descriptions_carry_deprecation_note() -> None:
    """Every legacy `bouncer_*` description must carry the
    `(DEPRECATED — use ibounce_* in v1.1)` prefix so agents see the
    new naming on every `tools/list` response."""
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    for t in resp["result"]["tools"]:
        if t["name"].startswith("bouncer_"):
            assert "DEPRECATED" in t["description"], (
                f"bouncer_* tool {t['name']!r} missing deprecation note"
            )


def test_ibounce_alias_dispatches_to_same_handler() -> None:
    """Calling `ibounce_list_rules` returns the same shape as
    `bouncer_list_rules` (they dispatch through the same code path)."""
    legacy = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "bouncer_list_rules", "arguments": {}},
    })
    canonical = _handle_request({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "ibounce_list_rules", "arguments": {}},
    })
    # Same structuredContent payload regardless of which name the
    # agent calls — the alias must not add or remove fields.
    assert legacy["result"]["structuredContent"] == canonical["result"]["structuredContent"]
