"""Tests for the bouncer task scope (#168 Slice B).

Per [[proxy-smart-defaults-and-task-scope]]: agent declares a task
scope ("upgrade EKS staging cluster"); bouncer narrows behavior for
the duration; audit chain captures the lifecycle.
"""

from __future__ import annotations

import datetime as _dt
import json
import time

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.decisions import (
    Decision,
    DefaultPolicy,
    Mode,
    decide,
)
from iam_jit.bouncer.rules import Effect, ProxyRule, RuleSet
from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer.tasks import (
    TaskScope,
    TaskStatus,
    TaskValidationError,
    build_task_scope,
)
from iam_jit.bouncer_cli import main


# ---------------------------------------------------------------------------
# build_task_scope validation
# ---------------------------------------------------------------------------


def test_build_task_scope_minimal_valid() -> None:
    s = build_task_scope(
        description="upgrade EKS staging",
        allow_rules=[{"pattern": "eks:*"}],
        started_by="agent",
    )
    assert s.description == "upgrade EKS staging"
    assert len(s.allow_rules) == 1
    assert s.allow_rules[0].effect == Effect.ALLOW
    assert s.allow_rules[0].pattern == "eks:*"
    assert s.task_id  # auto-generated


def test_build_task_scope_rejects_empty_description() -> None:
    with pytest.raises(TaskValidationError, match="description is required"):
        build_task_scope(
            description="", allow_rules=[{"pattern": "eks:*"}], started_by="x",
        )


def test_build_task_scope_rejects_zero_duration() -> None:
    with pytest.raises(TaskValidationError, match="duration_minutes"):
        build_task_scope(
            description="x", allow_rules=[{"pattern": "eks:*"}],
            duration_minutes=0, started_by="x",
        )


def test_build_task_scope_rejects_excessive_duration() -> None:
    with pytest.raises(TaskValidationError, match="max is 1440"):
        build_task_scope(
            description="x", allow_rules=[{"pattern": "eks:*"}],
            duration_minutes=1500, started_by="x",
        )


def test_build_task_scope_requires_at_least_one_rule() -> None:
    """A task with neither allow nor deny rules has no effect — reject
    rather than create a no-op task that confuses the audit chain."""
    with pytest.raises(TaskValidationError, match="at least one"):
        build_task_scope(
            description="x", allow_rules=[], deny_rules=[], started_by="x",
        )


def test_build_task_scope_accepts_deny_only() -> None:
    """Deny-only task scope is valid (e.g. 'for the next 30min, NO
    prod, but the rest of my work is governed by global rules')."""
    s = build_task_scope(
        description="don't touch prod for 30min",
        allow_rules=[],
        deny_rules=[{"pattern": "*", "arn_scope": "arn:aws:*::222:*"}],
        started_by="agent",
    )
    assert len(s.deny_rules) == 1


def test_build_task_scope_rejects_malformed_pattern() -> None:
    with pytest.raises(TaskValidationError, match="malformed"):
        build_task_scope(
            description="x",
            allow_rules=[{"pattern": "not-a-valid-pattern"}],
            started_by="x",
        )


def test_build_task_scope_rejects_non_dict_non_rule_input() -> None:
    with pytest.raises(TaskValidationError, match="must be a dict"):
        build_task_scope(
            description="x", allow_rules=["s3:GetObject"], started_by="x",
        )


def test_build_task_scope_forces_allow_effect() -> None:
    """A rule passed into allow_rules with effect=DENY should be
    forced back to ALLOW — the list it's in determines the effect."""
    rule_with_wrong_effect = ProxyRule(pattern="eks:*", effect=Effect.DENY)
    s = build_task_scope(
        description="x", allow_rules=[rule_with_wrong_effect], started_by="x",
    )
    assert s.allow_rules[0].effect == Effect.ALLOW


def test_build_task_scope_forces_deny_effect() -> None:
    rule_with_wrong_effect = ProxyRule(pattern="*:Delete*", effect=Effect.ALLOW)
    s = build_task_scope(
        description="x", deny_rules=[rule_with_wrong_effect], started_by="x",
    )
    assert s.deny_rules[0].effect == Effect.DENY


# ---------------------------------------------------------------------------
# TaskScope.is_expired
# ---------------------------------------------------------------------------


def test_is_expired_false_for_active_future_task() -> None:
    s = build_task_scope(
        description="x", allow_rules=[{"pattern": "eks:*"}],
        duration_minutes=60, started_by="x",
    )
    assert not s.is_expired()


def test_is_expired_true_when_passed() -> None:
    """Backdate the task so its expiry is in the past."""
    s = build_task_scope(
        description="x", allow_rules=[{"pattern": "eks:*"}],
        duration_minutes=1, started_by="x",
    )
    # Construct a future "now" past the expiry
    future = _dt.datetime.now(_dt.UTC) + _dt.timedelta(minutes=2)
    assert s.is_expired(now=future)


def test_is_expired_false_for_non_active_status() -> None:
    """Even if the wall-clock is past expiry, a task that already
    ended shouldn't report as expired (it's done — different state)."""
    base = build_task_scope(
        description="x", allow_rules=[{"pattern": "eks:*"}],
        duration_minutes=1, started_by="x",
    )
    import dataclasses
    completed = dataclasses.replace(base, status=TaskStatus.COMPLETED)
    future = _dt.datetime.now(_dt.UTC) + _dt.timedelta(minutes=10)
    assert not completed.is_expired(now=future)


# ---------------------------------------------------------------------------
# Decision integration: task-deny wins
# ---------------------------------------------------------------------------


def _empty_global() -> RuleSet:
    return RuleSet(rules=[])


def _admin_minus_sensitive_global() -> RuleSet:
    return RuleSet(rules=[
        ProxyRule(pattern="iam:Delete*", effect=Effect.DENY),
        ProxyRule(pattern="*", effect=Effect.ALLOW),
    ])


def test_decide_task_deny_wins_over_global_allow() -> None:
    """Agent says 'no prod'; global allows; deny wins."""
    task = build_task_scope(
        description="staging EKS upgrade",
        allow_rules=[{"pattern": "eks:*"}],
        deny_rules=[{"pattern": "*", "arn_scope": "arn:aws:*:*:222222222222:*"}],
        started_by="agent",
    )
    record = decide(
        _admin_minus_sensitive_global(),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="eks", action="UpdateClusterVersion",
        arn="arn:aws:eks:us-east-1:222222222222:cluster/prod",
        active_task=task,
    )
    assert record.decision == Decision.DENY
    assert "task-explicit-deny" in record.reason


def test_decide_task_deny_wins_over_learn_mode() -> None:
    """LEARN normally never denies — but task-deny is the "no prod"
    contract from the agent and MUST hold even in learn mode."""
    task = build_task_scope(
        description="staging EKS upgrade",
        allow_rules=[{"pattern": "eks:*"}],
        deny_rules=[{"pattern": "*", "arn_scope": "arn:aws:*:*:222222222222:*"}],
        started_by="agent",
    )
    record = decide(
        _empty_global(),
        mode=Mode.LEARN,
        default_policy=DefaultPolicy.ALLOW,
        service="eks", action="UpdateClusterVersion",
        arn="arn:aws:eks:us-east-1:222222222222:cluster/prod",
        active_task=task,
    )
    assert record.decision == Decision.DENY


def test_decide_task_allow_matches_in_scope() -> None:
    """Agent's declared allow rule matches → ALLOW."""
    task = build_task_scope(
        description="staging EKS upgrade",
        allow_rules=[{"pattern": "eks:*",
                      "arn_scope": "arn:aws:eks:us-east-1:111111111111:cluster/staging"}],
        started_by="agent",
    )
    record = decide(
        _empty_global(),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="eks", action="UpdateClusterVersion",
        arn="arn:aws:eks:us-east-1:111111111111:cluster/staging",
        active_task=task,
    )
    assert record.decision == Decision.ALLOW
    assert "task-allow" in record.reason


def test_decide_unmatched_by_task_with_global_allow_falls_through() -> None:
    """A call that the task didn't declare but global rules allow
    (e.g. sts:GetCallerIdentity that the SDK calls automatically)
    should ALLOW — layered composition. The reason notes that the
    call wasn't in the task scope but the global allow blessed it."""
    task = build_task_scope(
        description="staging EKS upgrade",
        allow_rules=[{"pattern": "eks:*"}],
        started_by="agent",
    )
    record = decide(
        _admin_minus_sensitive_global(),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="sts", action="GetCallerIdentity",
        active_task=task,
    )
    assert record.decision == Decision.ALLOW
    assert "not declared in task" in record.reason


def test_decide_unmatched_by_task_and_global_denies() -> None:
    """A call unmatched by task AND not allowed by global → DENY.
    The catches-prompt-injection case: task is for EKS; mid-task
    'also touch random S3 bucket' fails because S3 isn't in task
    scope and global default is deny."""
    task = build_task_scope(
        description="staging EKS upgrade",
        allow_rules=[{"pattern": "eks:*"}],
        started_by="agent",
    )
    record = decide(
        _empty_global(),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="s3", action="GetObject",
        active_task=task,
    )
    assert record.decision == Decision.DENY
    assert "out-of-task-scope" in record.reason


def test_decide_global_explicit_deny_wins_over_task_allow() -> None:
    """Global admin-minus-sensitive denies iam:Delete*; even if the
    agent's task scope says 'allow iam:*', the global deny wins.
    Task scope NARROWS within global guardrails; doesn't lift them."""
    task = build_task_scope(
        description="re-create staging role",
        allow_rules=[{"pattern": "iam:*"}],
        started_by="agent",
    )
    record = decide(
        _admin_minus_sensitive_global(),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.ALLOW,
        service="iam", action="DeleteRole",
        active_task=task,
    )
    assert record.decision == Decision.DENY
    assert record.reason == "explicit-deny rule"


def test_decide_no_active_task_unchanged_behavior() -> None:
    """Without an active task, the decision logic must behave exactly
    as before Slice B (regression check)."""
    record = decide(
        _admin_minus_sensitive_global(),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="iam", action="DeleteRole",
        active_task=None,
    )
    assert record.decision == Decision.DENY
    record2 = decide(
        _admin_minus_sensitive_global(),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="s3", action="GetObject",
        active_task=None,
    )
    assert record2.decision == Decision.ALLOW


# ---------------------------------------------------------------------------
# Store CRUD
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path) -> BouncerStore:
    s = BouncerStore(db_path=tmp_path / "state.db")
    yield s
    s.close()


def _scope(**kw) -> TaskScope:
    defaults = {
        "description": "test task",
        "allow_rules": [{"pattern": "eks:*"}],
        "started_by": "test",
    }
    defaults.update(kw)
    return build_task_scope(**defaults)


def test_store_add_task_and_get_active(store: BouncerStore) -> None:
    s = _scope()
    store.add_task(s)
    active = store.get_active_task()
    assert active is not None
    assert active.task_id == s.task_id
    assert active.description == s.description


def test_store_get_active_returns_none_when_no_task(store: BouncerStore) -> None:
    assert store.get_active_task() is None


def test_store_end_task_clears_active(store: BouncerStore) -> None:
    s = _scope()
    store.add_task(s)
    assert store.end_task(s.task_id, actor="admin", end_reason="manually ended")
    assert store.get_active_task() is None


def test_store_end_task_returns_false_for_unknown(store: BouncerStore) -> None:
    assert not store.end_task("does-not-exist", actor="admin")


def test_store_end_task_returns_false_for_already_ended(store: BouncerStore) -> None:
    s = _scope()
    store.add_task(s)
    store.end_task(s.task_id, actor="admin")
    assert not store.end_task(s.task_id, actor="admin")  # second call: no-op


def test_store_get_active_auto_expires(store: BouncerStore) -> None:
    """A task whose wall-clock expiry has passed is auto-ended on
    next get_active_task call."""
    import dataclasses
    # Create a task that's already expired
    base = _scope(duration_minutes=1)
    past_expiry = _dt.datetime.now(_dt.UTC) - _dt.timedelta(minutes=2)
    expired_at_creation = dataclasses.replace(
        base,
        expires_at=past_expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    store.add_task(expired_at_creation)
    # Active query returns None + auto-marks expired
    assert store.get_active_task() is None
    # Verify the row is now status='expired'
    retrieved = store.get_task(expired_at_creation.task_id)
    assert retrieved is not None
    assert retrieved.status == TaskStatus.EXPIRED


def test_store_list_tasks_newest_first(store: BouncerStore) -> None:
    s1 = _scope(description="first")
    store.add_task(s1)
    time.sleep(0.01)  # ensure distinct timestamps
    s2 = _scope(description="second")
    store.add_task(s2)
    listed = store.list_tasks()
    assert len(listed) == 2
    assert listed[0].description == "second"


def test_store_list_tasks_status_filter(store: BouncerStore) -> None:
    s1 = _scope()
    store.add_task(s1)
    store.end_task(s1.task_id, actor="admin")
    s2 = _scope(description="active one")
    store.add_task(s2)
    active = store.list_tasks(status_filter="active")
    assert len(active) == 1
    assert active[0].description == "active one"


def test_store_add_task_writes_task_started_event(store: BouncerStore) -> None:
    s = _scope()
    store.add_task(s, actor="agent")
    events = store.list_config_events(kind_filter="task_started")
    assert len(events) == 1
    assert events[0]["actor"] == "agent"
    assert events[0]["detail"]["task_id"] == s.task_id


def test_store_end_task_writes_task_ended_event(store: BouncerStore) -> None:
    s = _scope()
    store.add_task(s)
    store.end_task(s.task_id, actor="admin", end_reason="manually ended")
    events = store.list_config_events(kind_filter="task_ended")
    assert len(events) == 1


def test_store_record_decision_with_task_id(store: BouncerStore) -> None:
    """decisions table now carries task_id alongside the call."""
    from iam_jit.bouncer.decisions import DecisionRecord

    s = _scope()
    store.add_task(s)
    rec = DecisionRecord(
        decision=Decision.ALLOW, mode=Mode.ENFORCE,
        service="eks", action="DescribeCluster",
        arn=None, region=None, matched_rule=None, reason="task-allow",
    )
    store.record_decision(rec, task_id=s.task_id)
    decisions = store.list_decisions()
    assert decisions[0]["task_id"] == s.task_id


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_db(tmp_path):
    return str(tmp_path / "cli_state.db")


def test_cli_tasks_start_and_active(cli_db: str) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "tasks", "start",
        "--description", "upgrade EKS staging cluster",
        "--allow", "eks:*@arn:aws:eks:us-east-1:111:cluster/staging",
        "--deny", "*@arn:aws:*::222:*",
        "--duration", "30",
        "--db", cli_db,
    ])
    assert result.exit_code == 0
    assert "started task" in result.output

    active = runner.invoke(main, ["tasks", "active", "--db", cli_db])
    assert active.exit_code == 0
    assert "upgrade EKS staging cluster" in active.output
    assert "eks:*" in active.output


def test_cli_tasks_start_rejects_duplicate_active(cli_db: str) -> None:
    runner = CliRunner()
    runner.invoke(main, [
        "tasks", "start", "--description", "first",
        "--allow", "eks:*", "--db", cli_db,
    ])
    result = runner.invoke(main, [
        "tasks", "start", "--description", "second",
        "--allow", "eks:*", "--db", cli_db,
    ])
    assert result.exit_code != 0
    assert "already active" in result.output


def test_cli_tasks_end(cli_db: str) -> None:
    runner = CliRunner()
    runner.invoke(main, [
        "tasks", "start", "--description", "x",
        "--allow", "eks:*", "--db", cli_db,
    ])
    list_out = runner.invoke(main, ["tasks", "list", "--json", "--db", cli_db])
    tasks = json.loads(list_out.output)
    task_id = tasks[0]["task_id"]

    end = runner.invoke(main, ["tasks", "end", task_id, "--db", cli_db])
    assert end.exit_code == 0
    assert "ended task" in end.output
    active = runner.invoke(main, ["tasks", "active", "--db", cli_db])
    assert "no active task" in active.output


def test_cli_tasks_end_unknown(cli_db: str) -> None:
    result = CliRunner().invoke(main, ["tasks", "end", "not-real", "--db", cli_db])
    assert result.exit_code != 0


def test_cli_decide_uses_active_task(cli_db: str) -> None:
    """The decide CLI now consults the active task scope."""
    runner = CliRunner()
    runner.invoke(main, ["init", "--db", cli_db, "--no-default"])
    runner.invoke(main, [
        "tasks", "start", "--description", "staging upgrade",
        "--allow", "eks:DescribeCluster@arn:aws:eks:us-east-1:111:cluster/staging",
        "--db", cli_db,
    ])
    # Call matching task scope → ALLOW
    in_scope = runner.invoke(main, [
        "decide", "--service", "eks", "--action", "DescribeCluster",
        "--arn", "arn:aws:eks:us-east-1:111:cluster/staging",
        "--db", cli_db,
    ])
    assert "decision: allow" in in_scope.output
    assert "task-allow" in in_scope.output

    # Call NOT matching task scope → DENY (out of scope)
    out_of_scope = runner.invoke(main, [
        "decide", "--service", "s3", "--action", "GetObject",
        "--db", cli_db,
    ])
    assert "decision: deny" in out_of_scope.output
    assert "out-of-task-scope" in out_of_scope.output


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolate_bouncer_db(monkeypatch, tmp_path):
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "bouncer_mcp.db"))
    monkeypatch.setenv("IAM_JIT_BOUNCER_ACTOR", "test-agent")
    yield


def test_mcp_start_task_happy_path() -> None:
    from iam_jit.mcp_server import _bouncer_start_task_for_mcp

    out = _bouncer_start_task_for_mcp({
        "description": "upgrade EKS staging",
        "allow_rules": [
            {"pattern": "eks:*",
             "arn_scope": "arn:aws:eks:us-east-1:111:cluster/staging"},
        ],
        "deny_rules": [
            {"pattern": "*", "arn_scope": "arn:aws:*::222:*"},
        ],
        "duration_minutes": 30,
    })
    assert "task_id" in out
    assert out["allow_rule_count"] == 1
    assert out["deny_rule_count"] == 1
    assert out["audit_event_kind"] == "task_started"


def test_mcp_start_task_missing_description() -> None:
    from iam_jit.mcp_server import _bouncer_start_task_for_mcp

    out = _bouncer_start_task_for_mcp({"allow_rules": [{"pattern": "eks:*"}]})
    assert "error" in out


def test_mcp_start_task_rejects_concurrent() -> None:
    from iam_jit.mcp_server import _bouncer_start_task_for_mcp

    _bouncer_start_task_for_mcp({
        "description": "first", "allow_rules": [{"pattern": "eks:*"}],
    })
    out = _bouncer_start_task_for_mcp({
        "description": "second", "allow_rules": [{"pattern": "eks:*"}],
    })
    assert "error" in out
    assert "already active" in out["error"]
    assert "active_task_id" in out


def test_mcp_end_task_happy_path() -> None:
    from iam_jit.mcp_server import (
        _bouncer_end_task_for_mcp, _bouncer_start_task_for_mcp,
    )

    started = _bouncer_start_task_for_mcp({
        "description": "x", "allow_rules": [{"pattern": "eks:*"}],
    })
    out = _bouncer_end_task_for_mcp({"task_id": started["task_id"]})
    assert out["ended"] is True


def test_mcp_end_task_idempotent_returns_error() -> None:
    from iam_jit.mcp_server import (
        _bouncer_end_task_for_mcp, _bouncer_start_task_for_mcp,
    )

    started = _bouncer_start_task_for_mcp({
        "description": "x", "allow_rules": [{"pattern": "eks:*"}],
    })
    _bouncer_end_task_for_mcp({"task_id": started["task_id"]})
    out = _bouncer_end_task_for_mcp({"task_id": started["task_id"]})
    assert "error" in out


def test_mcp_active_task() -> None:
    from iam_jit.mcp_server import (
        _bouncer_active_task_for_mcp, _bouncer_start_task_for_mcp,
    )

    # No active task initially
    out = _bouncer_active_task_for_mcp({})
    assert out["active"] is None

    started = _bouncer_start_task_for_mcp({
        "description": "x", "allow_rules": [{"pattern": "eks:*"}],
    })
    active = _bouncer_active_task_for_mcp({})
    assert active["active"]["task_id"] == started["task_id"]


def test_mcp_three_task_tools_in_tools_list() -> None:
    from iam_jit.mcp_server import _handle_request

    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "bouncer_start_task" in names
    assert "bouncer_end_task" in names
    assert "bouncer_active_task" in names
