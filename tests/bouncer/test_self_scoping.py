"""Tests for the self-scoping composer (#174 / Slice E).

Per [[self-scoping-without-interaction]]: one-shot 'scope me for
this task' that wires compatibility check + bouncer task creation
+ JIT role submission atomically. Tests cover the five terminal
states + the effective-scope read tool + the "return to baseline"
guarantee after task end.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.self_scoping import (
    EffectiveScope,
    SelfScopeResult,
    SelfScopeStatus,
    get_effective_scope,
    scope_self_for_task,
)
from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer_cli import main


@pytest.fixture(autouse=True)
def isolated_bouncer_db(monkeypatch, tmp_path):
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "self_scope.db"))
    # Critical: also isolate the allowlist path so CANNOT_HELP test
    # doesn't pollute the user's real allowlist file AND vice-versa.
    monkeypatch.setenv("IAM_JIT_ALLOWLIST_PATH", str(tmp_path / "allowlist.yaml"))
    monkeypatch.setenv("IAM_JIT_BOUNCER_ACTOR", "test-agent")
    yield


# ---------------------------------------------------------------------------
# scope_self_for_task: bouncer-only paths
# ---------------------------------------------------------------------------


def test_scope_self_returns_scoped_bouncer_only_when_no_workload() -> None:
    """No workload → compatibility check is skipped; if
    submit_jit_role=False, we don't try to submit; return
    SCOPED_BOUNCER_ONLY."""
    result = scope_self_for_task(
        description="exploratory work",
        allow_rules=[{"pattern": "eks:Describe*"}],
        submit_jit_role=False,
    )
    assert result.status == SelfScopeStatus.SCOPED_BOUNCER_ONLY
    assert result.task_id is not None
    assert result.jit_role_arn is None
    assert "Bouncer task active" in result.next_action_hint


def test_scope_self_returns_scoped_bouncer_only_for_fixed_role_workload() -> None:
    """workload=k8s_pod → compatibility says USE_EXISTING → composer
    skips JIT role; bouncer task still active."""
    result = scope_self_for_task(
        description="staging EKS read",
        allow_rules=[{"pattern": "eks:Describe*"}],
        workload="k8s_pod",
    )
    assert result.status == SelfScopeStatus.SCOPED_BOUNCER_ONLY
    assert result.task_id is not None
    assert result.compatibility_verdict == "use_existing"


def test_scope_self_no_jit_submission_when_target_account_missing() -> None:
    """JIT role submission requires target_account_id. Without it,
    bouncer task still creates; result is SCOPED_BOUNCER_ONLY (or
    NEEDS_HUMAN depending on the JIT path's error semantics)."""
    result = scope_self_for_task(
        description="local dev test",
        allow_rules=[{"pattern": "s3:GetObject"}],
        workload="agent_local_dev",  # compat = PROCEED
        # no target_account_id
        submit_jit_role=True,
    )
    # JIT submit fails for missing account → NEEDS_HUMAN with error
    assert result.status == SelfScopeStatus.NEEDS_HUMAN
    assert result.task_id is not None
    assert result.error is not None


# ---------------------------------------------------------------------------
# scope_self_for_task: failure paths
# ---------------------------------------------------------------------------


def test_scope_self_fails_when_active_task_exists() -> None:
    """Two scope_self calls without an end_task in between for the
    same owner → second one returns FAILED (per Slice C per-owner
    single-active invariant)."""
    first = scope_self_for_task(
        description="first task",
        allow_rules=[{"pattern": "eks:*"}],
        submit_jit_role=False,
    )
    assert first.status == SelfScopeStatus.SCOPED_BOUNCER_ONLY

    second = scope_self_for_task(
        description="second task",
        allow_rules=[{"pattern": "s3:*"}],
        submit_jit_role=False,
    )
    assert second.status == SelfScopeStatus.FAILED
    assert "End any concurrent active task" in second.next_action_hint
    assert second.task_id is None


def test_scope_self_concurrent_different_owners_both_succeed() -> None:
    """Two scope_self calls with DIFFERENT owners → both succeed
    (per Slice C per-owner concurrent task support)."""
    a = scope_self_for_task(
        description="agent A task",
        allow_rules=[{"pattern": "eks:*"}],
        owner="agent-A",
        submit_jit_role=False,
    )
    b = scope_self_for_task(
        description="agent B task",
        allow_rules=[{"pattern": "s3:*"}],
        owner="agent-B",
        submit_jit_role=False,
    )
    assert a.status == SelfScopeStatus.SCOPED_BOUNCER_ONLY
    assert b.status == SelfScopeStatus.SCOPED_BOUNCER_ONLY


def test_scope_self_validation_failure_returns_failed() -> None:
    """Invalid task input → bouncer task creation fails → FAILED."""
    result = scope_self_for_task(
        description="",  # empty description
        allow_rules=[{"pattern": "eks:*"}],
        submit_jit_role=False,
    )
    assert result.status == SelfScopeStatus.FAILED
    assert "validation" in (result.error or "").lower()


def test_scope_self_empty_allow_rules_fails() -> None:
    """build_task_scope rejects a task with zero rules."""
    result = scope_self_for_task(
        description="test",
        allow_rules=[],
        submit_jit_role=False,
    )
    assert result.status == SelfScopeStatus.FAILED


# ---------------------------------------------------------------------------
# scope_self_for_task: CANNOT_HELP path
# ---------------------------------------------------------------------------


def test_scope_self_returns_cannot_help_when_allowlist_says_so() -> None:
    """If admin allowlist explicitly says CANNOT_HELP for an account,
    don't even create a bouncer task — escalate."""
    # allowlist commands live on the main iam-jit CLI, not the
    # bouncer CLI. Use the right entry point.
    from iam_jit.cli import main as iam_jit_main
    runner = CliRunner()
    add = runner.invoke(iam_jit_main, [
        "allowlist", "add",
        "--account", "111111111111",
        "--verdict", "cannot_help",
        "--reason", "out-of-scope compliance env",
    ])
    assert add.exit_code == 0, f"allowlist add failed: {add.output}"

    result = scope_self_for_task(
        description="test",
        allow_rules=[{"pattern": "eks:Describe*"}],
        workload="agent_local_dev",
        target_account_id="111111111111",
    )
    assert result.status == SelfScopeStatus.CANNOT_HELP
    assert result.task_id is None  # didn't create the bouncer task
    assert "Escalate to a human" in result.next_action_hint


# ---------------------------------------------------------------------------
# Return to baseline (after task end)
# ---------------------------------------------------------------------------


def test_baseline_restored_after_task_ends() -> None:
    """Per user direction 2026-05-17: 'the proxy should also be able
    to go back to its baseline setting once the task is over.' After
    end_task, effective scope should show has_active_task=False."""
    result = scope_self_for_task(
        description="test",
        allow_rules=[{"pattern": "eks:*"}],
        submit_jit_role=False,
    )
    assert result.status == SelfScopeStatus.SCOPED_BOUNCER_ONLY
    task_id = result.task_id

    # During: scope has active task
    during = get_effective_scope()
    assert during.has_active_task is True
    assert during.active_task_id == task_id

    # End the task
    import os
    store = BouncerStore(db_path=os.environ["IAM_JIT_BOUNCER_DB"])
    try:
        store.end_task(task_id, actor="test-agent")
    finally:
        store.close()

    # After: baseline (no active task)
    after = get_effective_scope()
    assert after.has_active_task is False
    assert after.active_task_id is None


def test_baseline_restored_after_task_auto_expires() -> None:
    """Same invariant via auto-expiry path."""
    import datetime as _dt
    import os

    result = scope_self_for_task(
        description="test",
        allow_rules=[{"pattern": "eks:*"}],
        submit_jit_role=False,
        duration_minutes=1,
    )
    task_id = result.task_id

    # Backdate the task's expiry to force auto-expire on next query
    store = BouncerStore(db_path=os.environ["IAM_JIT_BOUNCER_DB"])
    try:
        past = _dt.datetime.now(_dt.UTC) - _dt.timedelta(minutes=10)
        store._conn.execute(
            "UPDATE tasks SET expires_at = ? WHERE task_id = ?",
            (past.strftime("%Y-%m-%dT%H:%M:%SZ"), task_id),
        )
    finally:
        store.close()

    # Auto-expire fires on get_effective_scope's get_active_task call
    after = get_effective_scope()
    assert after.has_active_task is False


# ---------------------------------------------------------------------------
# Self-scoping does NOT mutate global state
# ---------------------------------------------------------------------------


def test_scope_self_does_not_add_global_rules() -> None:
    """Per [[agent-friendly-not-bypassable]] Lens B + the 'return to
    baseline' guarantee: scope_self_for_task MUST NOT add anything
    to the global ruleset. All narrowing lives in the ephemeral
    task scope."""
    import os
    store = BouncerStore(db_path=os.environ["IAM_JIT_BOUNCER_DB"])
    try:
        rules_before = len(store.list_rules())
    finally:
        store.close()

    scope_self_for_task(
        description="test",
        allow_rules=[
            {"pattern": "eks:DescribeCluster"},
            {"pattern": "ec2:DescribeInstances"},
            {"pattern": "s3:GetObject"},
        ],
        submit_jit_role=False,
    )

    store = BouncerStore(db_path=os.environ["IAM_JIT_BOUNCER_DB"])
    try:
        rules_after = len(store.list_rules())
    finally:
        store.close()
    assert rules_after == rules_before  # NO global rules added


# ---------------------------------------------------------------------------
# get_effective_scope
# ---------------------------------------------------------------------------


def test_effective_scope_empty_state() -> None:
    scope = get_effective_scope()
    assert scope.has_active_task is False
    assert scope.global_rule_count == 0


def test_effective_scope_with_global_rules() -> None:
    """When global rules exist but no task is active, those rules
    ARE the effective scope."""
    import os
    runner = CliRunner()
    runner.invoke(main, [
        "rules", "add", "s3:GetObject",
        "--db", os.environ["IAM_JIT_BOUNCER_DB"],
    ])
    scope = get_effective_scope()
    assert scope.has_active_task is False
    assert scope.global_rule_count == 1


def test_effective_scope_with_active_task() -> None:
    scope_self_for_task(
        description="test",
        allow_rules=[
            {"pattern": "eks:*"},
            {"pattern": "ec2:Describe*"},
        ],
        deny_rules=[{"pattern": "*", "arn_scope": "arn:aws:*:*:999:*"}],
        submit_jit_role=False,
    )
    scope = get_effective_scope()
    assert scope.has_active_task is True
    assert scope.active_task_allow_rule_count == 2
    assert scope.active_task_deny_rule_count == 1


def test_effective_scope_per_owner() -> None:
    scope_self_for_task(
        description="A's task",
        allow_rules=[{"pattern": "eks:*"}],
        owner="agent-A",
        submit_jit_role=False,
    )
    a_scope = get_effective_scope(owner="agent-A")
    b_scope = get_effective_scope(owner="agent-B")
    assert a_scope.has_active_task is True
    assert b_scope.has_active_task is False  # different owner


# ---------------------------------------------------------------------------
# Result serialization
# ---------------------------------------------------------------------------


def test_result_to_dict_includes_all_fields() -> None:
    result = scope_self_for_task(
        description="test",
        allow_rules=[{"pattern": "eks:*"}],
        submit_jit_role=False,
    )
    d = result.to_dict()
    for key in [
        "status", "next_action_hint", "task_id", "task_expires_at",
        "compatibility_verdict", "compatibility_reasoning",
        "jit_request_id", "jit_role_arn", "jit_score",
        "jit_auto_approved", "review_url", "error",
    ]:
        assert key in d


# ---------------------------------------------------------------------------
# MCP tool surface
# ---------------------------------------------------------------------------


def test_mcp_scope_self_happy_path_bouncer_only() -> None:
    from iam_jit.mcp_server import _scope_self_for_task_for_mcp
    out = _scope_self_for_task_for_mcp({
        "description": "test",
        "allow_rules": [{"pattern": "eks:*"}],
        "submit_jit_role": False,
    })
    assert out["status"] == "scoped_bouncer_only"
    assert out["task_id"] is not None


def test_mcp_scope_self_validates_inputs() -> None:
    from iam_jit.mcp_server import _scope_self_for_task_for_mcp
    # missing description
    assert "error" in _scope_self_for_task_for_mcp({
        "allow_rules": [{"pattern": "eks:*"}],
    })
    # empty allow_rules
    assert "error" in _scope_self_for_task_for_mcp({
        "description": "x", "allow_rules": [],
    })
    # bad pattern entry
    assert "error" in _scope_self_for_task_for_mcp({
        "description": "x", "allow_rules": [{}],
    })
    # bool submit_jit_role
    assert "error" in _scope_self_for_task_for_mcp({
        "description": "x", "allow_rules": [{"pattern": "eks:*"}],
        "submit_jit_role": "yes",
    })


def test_mcp_effective_scope_returns_baseline_when_no_task() -> None:
    from iam_jit.mcp_server import _effective_scope_for_mcp
    out = _effective_scope_for_mcp({})
    assert out["has_active_task"] is False


def test_mcp_effective_scope_reflects_active_task() -> None:
    from iam_jit.mcp_server import _effective_scope_for_mcp, _scope_self_for_task_for_mcp
    _scope_self_for_task_for_mcp({
        "description": "x",
        "allow_rules": [{"pattern": "eks:*"}],
        "submit_jit_role": False,
    })
    out = _effective_scope_for_mcp({})
    assert out["has_active_task"] is True


def test_mcp_both_tools_in_tools_list() -> None:
    from iam_jit.mcp_server import _handle_request
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "iam_jit_scope_self_for_task" in names
    assert "bouncer_effective_scope" in names


# ---------------------------------------------------------------------------
# CLI: iam-jit-bouncer effective-scope
# ---------------------------------------------------------------------------


def test_cli_effective_scope_baseline(tmp_path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "effective-scope", "--db", str(tmp_path / "cli.db"),
    ])
    assert result.exit_code == 0
    assert "no active task" in result.output or "at baseline" in result.output


def test_cli_effective_scope_with_task(tmp_path) -> None:
    runner = CliRunner()
    db = str(tmp_path / "cli2.db")
    runner.invoke(main, [
        "tasks", "start",
        "--description", "test",
        "--allow", "eks:*",
        "--db", db,
    ])
    result = runner.invoke(main, ["effective-scope", "--db", db])
    assert result.exit_code == 0
    assert "active task:" in result.output


def test_cli_effective_scope_json(tmp_path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "effective-scope",
        "--db", str(tmp_path / "cli3.db"),
        "--json",
    ])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert "has_active_task" in parsed
    assert "global_rule_count" in parsed


def test_effective_scope_surfaces_live_proxy_state(monkeypatch) -> None:
    """NUC-F regression: `effective-scope` ('what's gating me RIGHT NOW')
    must surface the running proxy's mode/profile/pause — during a pause it
    previously looked identical to full enforcement."""
    import iam_jit.posture.bouncers as pb

    monkeypatch.setattr(
        pb, "detect_ibounce",
        lambda: {"running": True, "mode": "transparent", "enforcing": True,
                 "active_profile": "safe-default",
                 "pause": {"pause_id": 3, "ends_at": "2026-06-03T10:00:00Z"}},
    )
    res = CliRunner().invoke(main, ["effective-scope", "--json"], catch_exceptions=False)
    assert res.exit_code == 0, res.output
    out = json.loads(res.output)
    assert out["proxy"]["mode"] == "transparent"
    assert out["proxy"]["active_profile"] == "safe-default"
    assert out["proxy"]["pause"]["pause_id"] == 3
