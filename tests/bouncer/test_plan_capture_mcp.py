"""MCP tool tests for bouncer_plan_session_summary (#132)."""

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


def _seed_session(
    db_path,
    *,
    session_id: str,
    verdicts: tuple[str, ...] = ("allow", "allow", "deny"),
) -> None:
    store = BouncerStore(db_path=str(db_path))
    try:
        store.ensure_plan_session(session_id=session_id, started_by="test", note="")
        for verdict in verdicts:
            store.record_plan_call(
                session_id=session_id,
                method="POST",
                host="iam.amazonaws.com",
                path="/",
                service="iam",
                action="CreateRole",
                region=None,
                arn=None,
                verdict=verdict,
                would_have_called="iam:CreateRole",
                would_have_returned={"RoleName": "test"},
                supported=True,
            )
    finally:
        store.close()


def test_tool_listed_with_canonical_and_alias_names(tmp_path) -> None:
    """Both `bouncer_plan_session_summary` and the ibounce_-prefixed
    alias should appear in the TOOLS catalog so agents on either
    name discover the tool."""
    from iam_jit.mcp_server import TOOLS

    names = {t["name"] for t in TOOLS}
    assert "bouncer_plan_session_summary" in names
    assert "ibounce_plan_session_summary" in names


def test_summary_returns_per_verdict_counts(tmp_path, monkeypatch) -> None:
    from iam_jit.mcp_server import _bouncer_plan_session_summary_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    sid = "plan-20260518T010101Z-abc123"
    _seed_session(tmp_path / "b.db", session_id=sid)

    out = _bouncer_plan_session_summary_for_mcp({"session_id": sid})
    assert out["session_id"] == sid
    assert out["call_count"] == 3
    assert out["allow_count"] == 2
    assert out["deny_count"] == 1
    assert out["services"] == ["iam"]
    assert out["would_have_called"] == ["iam:CreateRole"]


def test_summary_uses_current_session_when_no_arg(tmp_path, monkeypatch) -> None:
    """When the agent omits session_id, the tool falls back to the
    in-process slot (what `serve --mode plan-capture` sets)."""
    from iam_jit.mcp_server import _bouncer_plan_session_summary_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    sid = "plan-current-session-1"
    set_session_id(sid)
    _seed_session(tmp_path / "b.db", session_id=sid, verdicts=("allow",))

    out = _bouncer_plan_session_summary_for_mcp({})
    assert out["session_id"] == sid
    assert out["call_count"] == 1


def test_summary_returns_error_for_unknown_session(tmp_path, monkeypatch) -> None:
    from iam_jit.mcp_server import _bouncer_plan_session_summary_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    out = _bouncer_plan_session_summary_for_mcp({"session_id": "no-such"})
    assert "error" in out
    assert "no plan-capture session" in out["error"]


def test_summary_returns_error_when_no_session_resolvable(
    tmp_path, monkeypatch,
) -> None:
    from iam_jit.mcp_server import _bouncer_plan_session_summary_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    reset_session_for_tests()
    out = _bouncer_plan_session_summary_for_mcp({})
    assert "error" in out
    assert "no session_id" in out["error"]


def test_summary_rejects_non_string_session_id(tmp_path, monkeypatch) -> None:
    from iam_jit.mcp_server import _bouncer_plan_session_summary_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    out = _bouncer_plan_session_summary_for_mcp({"session_id": 123})
    assert out == {"error": "session_id must be a string if provided"}


def test_active_mode_surfaces_plan_capture(monkeypatch) -> None:
    """The agent-facing `bouncer_active_mode` MCP tool already exists;
    after #132 it should be able to report plan-capture too."""
    from iam_jit.mcp_server import _bouncer_active_mode_for_mcp

    monkeypatch.setenv("IAM_JIT_BOUNCER_MODE", "plan-capture")
    out = _bouncer_active_mode_for_mcp({})
    assert out == {"mode": "plan-capture", "source": "env"}
