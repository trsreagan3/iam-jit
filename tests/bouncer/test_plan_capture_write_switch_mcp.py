"""MCP tool tests for bouncer_plan_pending_write_prompt (#145)
+ extensions to bouncer_plan_session_summary.

The new MCP tool lets an agent introspect "should I wait for operator
approval before continuing?" in a plan-capture session running under
--write-switch-notify=manual. DETERMINISTIC — pure SQL via the store's
get_pending_plan_write_prompt + get_plan_session_phase helpers.

Per [[agent-friendly-not-bypassable]] this is a READ surface; agents
introspect but do not answer the prompt (the operator answers via
`ibounce prompts answer ID --kind plan-write --decision X`).
"""

from __future__ import annotations

import pytest

from iam_jit.bouncer.plan_capture import (
    reset_session_for_tests,
    set_session_id,
)
from iam_jit.bouncer.store import BouncerStore


@pytest.fixture(autouse=True)
def _isolate_session_slot():
    reset_session_for_tests()
    yield
    reset_session_for_tests()


def _seed_session(db_path, *, session_id: str, with_prompt: bool = False) -> int:
    """Seed a plan-capture session, optionally with a pending plan-write
    prompt. Returns the prompt id (or 0 when not seeded)."""
    store = BouncerStore(db_path=str(db_path))
    try:
        store.ensure_plan_session(
            session_id=session_id, started_by="test", note="",
        )
        if with_prompt:
            store.transition_plan_session_phase(
                session_id,
                new_phase="write_pending",
                first_write_at="2026-05-18T01:02:03Z",
            )
            return store.add_plan_write_prompt(
                session_id=session_id,
                service="iam", action="CreateRole",
                arn=None, region=None,
            )
        return 0
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_plan_pending_write_prompt_tool_listed():
    """Both canonical + ibounce_ alias should appear in TOOLS."""
    from iam_jit.mcp_server import TOOLS
    names = {t["name"] for t in TOOLS}
    assert "bouncer_plan_pending_write_prompt" in names
    assert "ibounce_plan_pending_write_prompt" in names


# ---------------------------------------------------------------------------
# Returns pending prompt when one exists
# ---------------------------------------------------------------------------


def test_returns_pending_prompt_for_session_with_one(tmp_path, monkeypatch):
    from iam_jit.mcp_server import _bouncer_plan_pending_write_prompt_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    sid = "plan-with-prompt-1"
    pid = _seed_session(tmp_path / "b.db", session_id=sid, with_prompt=True)
    out = _bouncer_plan_pending_write_prompt_for_mcp({"session_id": sid})
    assert out["session_id"] == sid
    assert out["phase"] == "write_pending"
    assert out["write_switch_notify"] == "manual"
    assert out["first_write_at"] == "2026-05-18T01:02:03Z"
    assert out["pending"] is not None
    assert out["pending"]["id"] == pid
    assert out["pending"]["kind"] == "plan-write"
    assert out["pending"]["service"] == "iam"
    assert out["pending"]["action"] == "CreateRole"


def test_returns_null_pending_for_read_only_session(tmp_path, monkeypatch):
    """A session that hasn't crossed read->write yet has no pending
    plan-write prompt; the tool returns pending=null + phase=read_only."""
    from iam_jit.mcp_server import _bouncer_plan_pending_write_prompt_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    sid = "plan-read-only-1"
    _seed_session(tmp_path / "b.db", session_id=sid, with_prompt=False)
    out = _bouncer_plan_pending_write_prompt_for_mcp({"session_id": sid})
    assert out["session_id"] == sid
    assert out["phase"] == "read_only"
    assert out["pending"] is None


# ---------------------------------------------------------------------------
# Uses current session when omitted
# ---------------------------------------------------------------------------


def test_uses_current_session_when_no_arg(tmp_path, monkeypatch):
    from iam_jit.mcp_server import _bouncer_plan_pending_write_prompt_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    sid = "plan-current-session"
    set_session_id(sid)
    _seed_session(tmp_path / "b.db", session_id=sid, with_prompt=True)
    out = _bouncer_plan_pending_write_prompt_for_mcp({})
    assert out["session_id"] == sid
    assert out["pending"] is not None


# ---------------------------------------------------------------------------
# Error shapes
# ---------------------------------------------------------------------------


def test_unknown_session_returns_error(tmp_path, monkeypatch):
    from iam_jit.mcp_server import _bouncer_plan_pending_write_prompt_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    out = _bouncer_plan_pending_write_prompt_for_mcp(
        {"session_id": "no-such-session"},
    )
    assert "error" in out
    assert "no plan-capture session" in out["error"]


def test_no_session_resolvable_returns_error(tmp_path, monkeypatch):
    from iam_jit.mcp_server import _bouncer_plan_pending_write_prompt_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    reset_session_for_tests()
    out = _bouncer_plan_pending_write_prompt_for_mcp({})
    assert "error" in out
    assert "no session_id" in out["error"]


def test_non_string_session_id_returns_error(tmp_path, monkeypatch):
    from iam_jit.mcp_server import _bouncer_plan_pending_write_prompt_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    out = _bouncer_plan_pending_write_prompt_for_mcp({"session_id": 123})
    assert out == {"error": "session_id must be a string if provided"}


# ---------------------------------------------------------------------------
# bouncer_plan_session_summary extension: includes phase + read/write split
# ---------------------------------------------------------------------------


def test_summary_includes_phase_and_read_write_split(tmp_path, monkeypatch):
    from iam_jit.mcp_server import _bouncer_plan_session_summary_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    sid = "plan-summary-145"
    pid = _seed_session(tmp_path / "b.db", session_id=sid, with_prompt=True)
    # Add a couple of plan_calls so summary has something to roll up
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        store.record_plan_call(
            session_id=sid, method="GET", host="s3.amazonaws.com",
            path="/b/x", service="s3", action="GetObject",
            region="us-east-1", arn=None, verdict="allow",
            would_have_called="s3:GetObject",
            would_have_returned={}, supported=True,
        )
        store.record_plan_call(
            session_id=sid, method="POST", host="iam.amazonaws.com",
            path="/", service="iam", action="CreateRole",
            region=None, arn=None, verdict="allow",
            would_have_called="iam:CreateRole",
            would_have_returned={}, supported=True,
        )
    finally:
        store.close()

    out = _bouncer_plan_session_summary_for_mcp({"session_id": sid})
    assert out["session_id"] == sid
    # Phase + write-switch fields surfaced
    assert out["phase"] == "write_pending"
    assert out["write_switch_notify"] == "manual"
    assert out["first_write_at"] == "2026-05-18T01:02:03Z"
    # Read/write split
    assert out["read_count"] == 1
    assert out["write_count"] == 1
    # Prompt id (resolvable via the separate tool, but the summary
    # should NOT silently embed it — agents that want the prompt id
    # call bouncer_plan_pending_write_prompt explicitly so the LLM
    # surface stays narrow. We assert the pid var so the test
    # mentions it for grep-ability.)
    assert pid > 0
