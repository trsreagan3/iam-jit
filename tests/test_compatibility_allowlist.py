"""Tests for the admin compatibility allowlist (#166 Slice 2).

Per [[iam-jit-inapplicable-cases]]: Slice 1 ships the curated
known-incompatible catalog; Slice 2 adds an admin-controlled
override layer so orgs can declare "for account X + workload Y,
return verdict Z." Wires the USE_BOUNCER + CANNOT_HELP verdicts
that Slice 1 reserved.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml
from click.testing import CliRunner

from iam_jit.cli import main as iam_jit_main
from iam_jit.compatibility import (
    Compatibility,
    CompatibilityIntent,
    WorkloadType,
    check_compatibility,
)
from iam_jit.compatibility_allowlist import (
    AllowlistRule,
    FileAllowlistStore,
    InMemoryAllowlistStore,
    InvalidRule,
    RuleNotFound,
    build_rule,
    default_allowlist_path,
    match_intent,
)


# ---------------------------------------------------------------------------
# build_rule validation
# ---------------------------------------------------------------------------


def test_build_rule_valid_account_workload_proceed() -> None:
    r = build_rule(
        account_id="111111111111",
        workload="k8s_pod",
        verdict="proceed",
        reason="trust this account",
        created_by="admin",
    )
    assert r.account_id == "111111111111"
    assert r.workload == WorkloadType.K8S_POD
    assert r.verdict == Compatibility.PROCEED
    assert r.rule_id  # auto-generated


def test_build_rule_use_existing_requires_arn() -> None:
    with pytest.raises(InvalidRule, match="requires existing_role_arn"):
        build_rule(
            account_id="111111111111", workload="k8s_pod",
            verdict="use_existing", reason="x", created_by="admin",
        )


def test_build_rule_use_existing_with_valid_arn() -> None:
    r = build_rule(
        account_id="111111111111", workload="k8s_pod",
        verdict="use_existing",
        existing_role_arn="arn:aws:iam::111111111111:role/shared-ml",
        reason="shared ML cluster", created_by="admin",
    )
    assert r.verdict == Compatibility.USE_EXISTING
    assert r.existing_role_arn == "arn:aws:iam::111111111111:role/shared-ml"


def test_build_rule_use_existing_rejects_bad_arn() -> None:
    with pytest.raises(InvalidRule, match="not a valid IAM role ARN"):
        build_rule(
            account_id="111111111111", workload="k8s_pod",
            verdict="use_existing", existing_role_arn="haha not an arn",
            reason="x", created_by="admin",
        )


def test_build_rule_non_use_existing_rejects_arn() -> None:
    """Defensive: providing an ARN for a verdict that doesn't use it
    is an admin mistake; surface it rather than silently drop."""
    with pytest.raises(InvalidRule, match="only valid with verdict=use_existing"):
        build_rule(
            account_id="111111111111", workload="k8s_pod",
            verdict="proceed", existing_role_arn="arn:aws:iam::111111111111:role/x",
            reason="x", created_by="admin",
        )


def test_build_rule_rejects_bad_account_id() -> None:
    for bad in ["not-digits", "12345", "1234567890123", "ABCDEFGHIJKL"]:
        with pytest.raises(InvalidRule, match="account_id must be exactly 12 digits"):
            build_rule(
                account_id=bad, workload=None, verdict="proceed",
                reason="x", created_by="admin",
            )


def test_build_rule_account_none_means_wildcard() -> None:
    r = build_rule(
        account_id=None, workload="k8s_pod", verdict="cannot_help",
        reason="org-wide compliance restriction", created_by="admin",
    )
    assert r.account_id is None


def test_build_rule_workload_none_means_wildcard() -> None:
    r = build_rule(
        account_id="111111111111", workload=None, verdict="cannot_help",
        reason="entire account out-of-scope", created_by="admin",
    )
    assert r.workload is None


def test_build_rule_requires_reason() -> None:
    with pytest.raises(InvalidRule, match="reason is required"):
        build_rule(
            account_id=None, workload=None, verdict="proceed",
            reason="", created_by="admin",
        )


def test_build_rule_unknown_workload_rejected() -> None:
    with pytest.raises(InvalidRule):
        build_rule(
            account_id=None, workload="made-up-workload", verdict="proceed",
            reason="x", created_by="admin",
        )


def test_build_rule_unknown_verdict_rejected() -> None:
    with pytest.raises(InvalidRule):
        build_rule(
            account_id=None, workload=None, verdict="maybe",
            reason="x", created_by="admin",
        )


# ---------------------------------------------------------------------------
# Rule.matches
# ---------------------------------------------------------------------------


def _rule(**kw) -> AllowlistRule:
    defaults = {
        "account_id": None, "workload": None, "verdict": "proceed",
        "reason": "test", "created_by": "test",
    }
    defaults.update(kw)
    return build_rule(**defaults)


def _intent(**kw) -> CompatibilityIntent:
    defaults = {"workload": WorkloadType.K8S_POD}
    defaults.update(kw)
    return CompatibilityIntent(**defaults)


def test_rule_matches_specific_account_and_workload() -> None:
    r = _rule(account_id="111111111111", workload="k8s_pod")
    assert r.matches(_intent(target_account_id="111111111111", workload=WorkloadType.K8S_POD))
    assert not r.matches(_intent(target_account_id="222222222222", workload=WorkloadType.K8S_POD))
    assert not r.matches(_intent(target_account_id="111111111111", workload=WorkloadType.EC2_INSTANCE))


def test_rule_matches_account_wildcard() -> None:
    r = _rule(account_id=None, workload="k8s_pod")
    assert r.matches(_intent(target_account_id="111111111111", workload=WorkloadType.K8S_POD))
    assert r.matches(_intent(target_account_id=None, workload=WorkloadType.K8S_POD))


def test_rule_matches_workload_wildcard() -> None:
    r = _rule(account_id="111111111111", workload=None)
    assert r.matches(_intent(target_account_id="111111111111", workload=WorkloadType.K8S_POD))
    assert r.matches(_intent(target_account_id="111111111111", workload=WorkloadType.EC2_INSTANCE))


def test_rule_matches_full_wildcard() -> None:
    r = _rule(account_id=None, workload=None)
    assert r.matches(_intent())
    assert r.matches(_intent(target_account_id="999999999999", workload=WorkloadType.OTHER))


# ---------------------------------------------------------------------------
# InMemoryAllowlistStore CRUD
# ---------------------------------------------------------------------------


def test_in_memory_store_add_and_list() -> None:
    s = InMemoryAllowlistStore()
    r = _rule(reason="test")
    s.add(r)
    assert len(s.list()) == 1
    assert s.list()[0].rule_id == r.rule_id


def test_in_memory_store_get_by_id() -> None:
    s = InMemoryAllowlistStore()
    r = _rule()
    s.add(r)
    assert s.get(r.rule_id).rule_id == r.rule_id


def test_in_memory_store_get_unknown_raises() -> None:
    s = InMemoryAllowlistStore()
    with pytest.raises(RuleNotFound):
        s.get("not-a-real-id")


def test_in_memory_store_remove() -> None:
    s = InMemoryAllowlistStore()
    r = s.add(_rule())
    s.remove(r.rule_id)
    assert s.list() == []


def test_in_memory_store_remove_unknown_raises() -> None:
    s = InMemoryAllowlistStore()
    with pytest.raises(RuleNotFound):
        s.remove("not-a-real-id")


def test_in_memory_store_duplicate_rule_id_rejected() -> None:
    s = InMemoryAllowlistStore()
    r = _rule(rule_id="manual-id-1")
    s.add(r)
    with pytest.raises(InvalidRule, match="duplicate"):
        s.add(_rule(rule_id="manual-id-1"))


# ---------------------------------------------------------------------------
# FileAllowlistStore (YAML on disk)
# ---------------------------------------------------------------------------


def test_file_store_round_trip(tmp_path) -> None:
    path = tmp_path / "allowlist.yaml"
    s = FileAllowlistStore(path)
    r = build_rule(
        account_id="111111111111", workload="k8s_pod",
        verdict="use_existing",
        existing_role_arn="arn:aws:iam::111111111111:role/shared",
        reason="shared ML cluster", created_by="admin",
    )
    s.add(r)
    # Re-open from disk
    s2 = FileAllowlistStore(path)
    listed = s2.list()
    assert len(listed) == 1
    assert listed[0].rule_id == r.rule_id
    assert listed[0].existing_role_arn == r.existing_role_arn


def test_file_store_empty_file_returns_no_rules(tmp_path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text("")
    s = FileAllowlistStore(path)
    assert s.list() == []


def test_file_store_missing_file_returns_no_rules(tmp_path) -> None:
    s = FileAllowlistStore(tmp_path / "does-not-exist.yaml")
    assert s.list() == []


def test_file_store_skips_malformed_rows(tmp_path) -> None:
    """A YAML file with one bad rule + one good rule lists the good
    one and skips the bad (mirrors WB23 MED-23-01 pattern)."""
    path = tmp_path / "allowlist.yaml"
    path.write_text(yaml.safe_dump({
        "version": 1,
        "rules": [
            {  # malformed: bad account ID
                "rule_id": "bad-1",
                "account_id": "not-digits",
                "workload": "k8s_pod",
                "verdict": "proceed",
                "reason": "test",
                "created_by": "admin",
                "created_at": "2026-05-17T15:00:00Z",
            },
            {  # valid
                "rule_id": "good-1",
                "account_id": "111111111111",
                "workload": "k8s_pod",
                "verdict": "proceed",
                "reason": "test",
                "created_by": "admin",
                "created_at": "2026-05-17T15:00:00Z",
            },
        ],
    }))
    s = FileAllowlistStore(path)
    listed = s.list()
    assert len(listed) == 1
    assert listed[0].rule_id == "good-1"


def test_file_store_remove_persists(tmp_path) -> None:
    path = tmp_path / "allowlist.yaml"
    s = FileAllowlistStore(path)
    r1 = s.add(_rule())
    r2 = s.add(_rule(reason="second"))
    s.remove(r1.rule_id)
    # Re-open and confirm
    s2 = FileAllowlistStore(path)
    listed = s2.list()
    assert len(listed) == 1
    assert listed[0].rule_id == r2.rule_id


# ---------------------------------------------------------------------------
# default_allowlist_path env override
# ---------------------------------------------------------------------------


def test_default_path_respects_env_var(monkeypatch, tmp_path) -> None:
    custom = tmp_path / "custom.yaml"
    monkeypatch.setenv("IAM_JIT_ALLOWLIST_PATH", str(custom))
    assert default_allowlist_path() == custom


# ---------------------------------------------------------------------------
# match_intent + check_compatibility integration
# ---------------------------------------------------------------------------


def test_match_intent_returns_first_match() -> None:
    store = InMemoryAllowlistStore()
    # Two rules that BOTH match (specific then wildcard)
    r1 = store.add(build_rule(
        account_id="111111111111", workload="k8s_pod",
        verdict="use_existing",
        existing_role_arn="arn:aws:iam::111111111111:role/specific",
        reason="specific cluster", created_by="admin",
    ))
    store.add(build_rule(
        account_id=None, workload="k8s_pod",
        verdict="cannot_help",
        reason="generic k8s deny", created_by="admin",
    ))
    matched = match_intent(
        _intent(target_account_id="111111111111", workload=WorkloadType.K8S_POD),
        store,
    )
    assert matched is not None
    assert matched.rule_id == r1.rule_id


def test_match_intent_returns_none_when_no_match() -> None:
    store = InMemoryAllowlistStore()
    store.add(build_rule(
        account_id="111111111111", workload="k8s_pod",
        verdict="proceed", reason="x", created_by="admin",
    ))
    assert match_intent(
        _intent(target_account_id="222222222222", workload=WorkloadType.EC2_INSTANCE),
        store,
    ) is None


def test_check_compatibility_uses_allowlist_when_provided() -> None:
    """Allowlist USE_EXISTING wins over catalog PROCEED for
    agent_local_dev (catalog default)."""
    store = InMemoryAllowlistStore()
    store.add(build_rule(
        account_id="111111111111",
        workload="agent_local_dev",
        verdict="use_existing",
        existing_role_arn="arn:aws:iam::111111111111:role/dev-sandbox",
        reason="dev sandbox uses shared role", created_by="admin",
    ))
    result = check_compatibility(
        _intent(target_account_id="111111111111", workload=WorkloadType.AGENT_LOCAL_DEV),
        allowlist=store,
    )
    assert result.verdict == Compatibility.USE_EXISTING
    assert result.existing_role_arn == "arn:aws:iam::111111111111:role/dev-sandbox"
    assert result.matched_pattern.startswith("allowlist:")


def test_check_compatibility_falls_through_to_catalog_when_no_allowlist_match() -> None:
    store = InMemoryAllowlistStore()
    store.add(build_rule(
        account_id="111111111111",
        workload="agent_local_dev",
        verdict="cannot_help",
        reason="restricted dev account", created_by="admin",
    ))
    # Intent doesn't match the rule (different account); fall through to catalog
    result = check_compatibility(
        _intent(target_account_id="222222222222", workload=WorkloadType.K8S_POD),
        allowlist=store,
    )
    assert result.verdict == Compatibility.USE_EXISTING  # catalog default for k8s
    assert result.matched_pattern == "k8s-irsa-fixed-role"


def test_check_compatibility_allowlist_can_return_cannot_help() -> None:
    """Slice 2 wires the CANNOT_HELP verdict that was reserved in Slice 1."""
    store = InMemoryAllowlistStore()
    store.add(build_rule(
        account_id="111111111111",
        workload=None,
        verdict="cannot_help",
        reason="compliance environment; named-role-only",
        created_by="admin",
    ))
    result = check_compatibility(
        _intent(target_account_id="111111111111", workload=WorkloadType.AGENT_LOCAL_DEV),
        allowlist=store,
    )
    assert result.verdict == Compatibility.CANNOT_HELP


def test_check_compatibility_allowlist_can_return_use_bouncer() -> None:
    """Slice 2 wires the USE_BOUNCER verdict that was reserved in Slice 1."""
    store = InMemoryAllowlistStore()
    store.add(build_rule(
        account_id="111111111111",
        workload=None,
        verdict="use_bouncer",
        reason="prefer bouncer to issuance for this account",
        created_by="admin",
    ))
    result = check_compatibility(
        _intent(target_account_id="111111111111", workload=WorkloadType.AGENT_LOCAL_DEV),
        allowlist=store,
    )
    assert result.verdict == Compatibility.USE_BOUNCER
    assert result.bouncer_recommended is True


def test_check_compatibility_allowlist_failure_degrades_to_catalog() -> None:
    """A broken allowlist must not crash the check; degrade silently."""
    class BrokenStore:
        def list(self):
            raise RuntimeError("disk failure")

    result = check_compatibility(
        _intent(workload=WorkloadType.K8S_POD),
        allowlist=BrokenStore(),
    )
    assert result.verdict == Compatibility.USE_EXISTING  # catalog default
    assert result.matched_pattern == "k8s-irsa-fixed-role"


def test_check_compatibility_allowlist_audit_records_source() -> None:
    """The audit event distinguishes allowlist hits from catalog hits."""
    store = InMemoryAllowlistStore()
    store.add(build_rule(
        account_id="111111111111", workload="k8s_pod",
        verdict="proceed", reason="trusted account", created_by="admin",
    ))
    recorded: list[dict] = []

    class Sink:
        def record(self, *, kind, actor, summary, detail=None):
            recorded.append({"kind": kind, "summary": summary, "detail": detail})

    check_compatibility(
        _intent(target_account_id="111111111111", workload=WorkloadType.K8S_POD),
        allowlist=store, audit_sink=Sink(), actor="test-agent",
    )
    assert len(recorded) == 1
    assert recorded[0]["detail"]["source"] == "allowlist"


def test_check_compatibility_catalog_audit_records_source() -> None:
    """When NO allowlist rule matches, audit log marks source=catalog."""
    recorded: list[dict] = []

    class Sink:
        def record(self, *, kind, actor, summary, detail=None):
            recorded.append({"kind": kind, "summary": summary, "detail": detail})

    check_compatibility(
        _intent(workload=WorkloadType.K8S_POD),
        allowlist=InMemoryAllowlistStore(),  # empty
        audit_sink=Sink(), actor="test",
    )
    assert len(recorded) == 1
    assert recorded[0]["detail"]["source"] == "catalog"


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_env(monkeypatch, tmp_path):
    """Point CLI commands at a per-test allowlist file + bouncer DB."""
    monkeypatch.setenv("IAM_JIT_ALLOWLIST_PATH", str(tmp_path / "allowlist.yaml"))
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "bouncer.db"))
    monkeypatch.setenv("IAM_JIT_BOUNCER_ACTOR", "cli-test")
    return tmp_path


def test_cli_allowlist_list_empty(cli_env) -> None:
    result = CliRunner().invoke(iam_jit_main, ["allowlist", "list"])
    assert result.exit_code == 0
    assert "no allowlist rules" in result.output


def test_cli_allowlist_add_and_list(cli_env) -> None:
    runner = CliRunner()
    add = runner.invoke(iam_jit_main, [
        "allowlist", "add",
        "--account", "111111111111",
        "--workload", "k8s_pod",
        "--verdict", "use_existing",
        "--role-arn", "arn:aws:iam::111111111111:role/shared",
        "--reason", "shared ML cluster",
    ])
    assert add.exit_code == 0, add.output
    list_out = runner.invoke(iam_jit_main, ["allowlist", "list"])
    assert "use_existing" in list_out.output
    assert "111111111111" in list_out.output
    assert "shared ML cluster" in list_out.output


def test_cli_allowlist_add_rejects_invalid(cli_env) -> None:
    result = CliRunner().invoke(iam_jit_main, [
        "allowlist", "add",
        "--account", "not-digits",
        "--verdict", "proceed",
        "--reason", "x",
    ])
    assert result.exit_code != 0
    assert "rejected" in result.output


def test_cli_allowlist_remove(cli_env) -> None:
    runner = CliRunner()
    runner.invoke(iam_jit_main, [
        "allowlist", "add",
        "--account", "111111111111", "--workload", "k8s_pod",
        "--verdict", "proceed", "--reason", "test",
    ])
    list_out = runner.invoke(iam_jit_main, ["allowlist", "list", "--json"])
    import json
    rules = json.loads(list_out.output)
    rule_id = rules[0]["rule_id"]

    rm = runner.invoke(iam_jit_main, ["allowlist", "remove", rule_id])
    assert rm.exit_code == 0
    assert "removed" in rm.output


def test_cli_allowlist_remove_unknown(cli_env) -> None:
    result = CliRunner().invoke(iam_jit_main, ["allowlist", "remove", "not-real"])
    assert result.exit_code != 0


def test_cli_allowlist_show(cli_env) -> None:
    runner = CliRunner()
    add = runner.invoke(iam_jit_main, [
        "allowlist", "add",
        "--account", "111111111111", "--workload", "k8s_pod",
        "--verdict", "proceed", "--reason", "test",
    ])
    import json
    list_out = runner.invoke(iam_jit_main, ["allowlist", "list", "--json"])
    rule_id = json.loads(list_out.output)[0]["rule_id"]
    show = runner.invoke(iam_jit_main, ["allowlist", "show", rule_id])
    assert show.exit_code == 0
    parsed = json.loads(show.output)
    assert parsed["account_id"] == "111111111111"


def test_cli_allowlist_add_writes_audit_event(cli_env) -> None:
    """Per Lens B: every mutation writes to the bouncer's config_events."""
    runner = CliRunner()
    runner.invoke(iam_jit_main, [
        "allowlist", "add",
        "--account", "111111111111", "--workload", "k8s_pod",
        "--verdict", "proceed", "--reason", "test",
    ])
    from iam_jit.bouncer.store import BouncerStore
    store = BouncerStore()
    try:
        events = store.list_config_events(kind_filter="allowlist_rule_added")
        assert len(events) == 1
        assert events[0]["actor"] == "cli-test"
    finally:
        store.close()


# ---------------------------------------------------------------------------
# MCP tool surface
# ---------------------------------------------------------------------------


def test_mcp_list_compatibility_overrides_empty(cli_env) -> None:
    from iam_jit.mcp_server import _list_compatibility_overrides_for_mcp

    out = _list_compatibility_overrides_for_mcp({})
    assert out["count"] == 0


def test_mcp_list_compatibility_overrides_reflects_cli_add(cli_env) -> None:
    runner = CliRunner()
    runner.invoke(iam_jit_main, [
        "allowlist", "add",
        "--account", "111111111111", "--workload", "k8s_pod",
        "--verdict", "proceed", "--reason", "trusted",
    ])
    from iam_jit.mcp_server import _list_compatibility_overrides_for_mcp

    out = _list_compatibility_overrides_for_mcp({})
    assert out["count"] == 1
    assert out["rules"][0]["account_id"] == "111111111111"


def test_mcp_check_compatibility_consults_allowlist(cli_env) -> None:
    """End-to-end: admin adds an override via CLI; the MCP checker
    returns the override's verdict instead of the catalog default."""
    runner = CliRunner()
    runner.invoke(iam_jit_main, [
        "allowlist", "add",
        "--account", "111111111111",
        "--workload", "agent_local_dev",
        "--verdict", "cannot_help",
        "--reason", "out of scope for this env",
    ])
    from iam_jit.mcp_server import _check_compatibility_for_mcp

    out = _check_compatibility_for_mcp({
        "workload": "agent_local_dev",
        "target_account_id": "111111111111",
    })
    assert out["verdict"] == "cannot_help"
    assert out["matched_pattern"].startswith("allowlist:")


def test_mcp_no_mutation_tool_for_allowlist(cli_env) -> None:
    """Per [[agent-friendly-not-bypassable]] Lens B: there's no MCP
    tool that lets agents mutate the allowlist (would let them
    grant themselves access). Verify the surface."""
    from iam_jit.mcp_server import _handle_request

    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    forbidden = {
        "add_compatibility_override", "create_compatibility_override",
        "remove_compatibility_override", "delete_compatibility_override",
        "allowlist_add", "allowlist_remove",
    }
    assert not (names & forbidden), (
        f"forbidden mutation tools present in MCP surface: {names & forbidden}"
    )
    # But the read-only listing is allowed
    assert "list_compatibility_overrides" in names
