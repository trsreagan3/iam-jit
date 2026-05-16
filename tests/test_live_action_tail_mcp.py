"""Tests for the `tail_grant` MCP tool wiring (#157)."""

from __future__ import annotations

import os
import pathlib

import pytest
import yaml

from iam_jit.live_action_tail import (
    InMemoryLiveActionTailSource,
    LiveActionEvent,
    set_default_source,
)
from iam_jit.mcp_server import _handle_request, _tail_grant_for_mcp


def _ev(**overrides) -> LiveActionEvent:
    defaults: dict = {
        "event_time": "2026-05-17T14:23:18Z",
        "event_name": "GetObject",
        "event_source": "s3.amazonaws.com",
        "aws_region": "us-east-1",
        # WB22 CRIT-22-01: filter is on role_name; role_session_name
        # is audit display only.
        "role_name": "iam-jit-grant-1",
        "role_session_name": "alice-laptop",
    }
    defaults.update(overrides)
    return LiveActionEvent(**defaults)


def _grant_yaml() -> dict:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": "grant-1",
            "requester": {"name": "Alice Tester", "email": "alice@example.com"},
            "created_at": "2026-05-17T14:00:00Z",
        },
        "spec": {
            "access_type": "read-only",
            "description": "test grant for live-action tail",
            "accounts": [{"account_id": "111111111111"}],
            "duration": {"duration_hours": 1},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}],
            },
        },
        "status": {
            "state": "active",
            "history": [
                {"to_state": "active", "at": "2026-05-17T14:00:00Z"},
            ],
            "provisioned": {
                "role_arn": "arn:aws:iam::111111111111:role/iam-jit/iam-jit-grant-1",
                "role_name": "iam-jit-grant-1",
                "account_id": "111111111111",
                "session_name": "iam-jit-provision-grant-1",
                "expires_at": "2026-05-17T20:00:00Z",
            },
        },
    }


@pytest.fixture
def grant_store(tmp_path, monkeypatch):
    """Filesystem-backed request store with one provisioned grant."""
    req_dir = tmp_path / "requests"
    req_dir.mkdir()
    (req_dir / "grant-1.yaml").write_text(yaml.safe_dump(_grant_yaml()))
    monkeypatch.setenv("IAM_JIT_REQUESTS_DIR", str(req_dir))
    # Make sure DDB/S3 backends aren't selected
    monkeypatch.delenv("IAM_JIT_REQUESTS_TABLE", raising=False)
    monkeypatch.delenv("IAM_JIT_STATE_BUCKET", raising=False)
    yield req_dir


@pytest.fixture
def stub_source():
    """Inject an InMemory source for the test, reset on teardown."""
    src = InMemoryLiveActionTailSource(events=[
        _ev(event_name="GetObject"),
        _ev(event_name="HeadBucket", error_code="AccessDenied"),
    ])
    set_default_source(src)
    yield src
    set_default_source(None)


# ---------------------------------------------------------------------------
# _tail_grant_for_mcp — validation
# ---------------------------------------------------------------------------


def test_missing_grant_id_returns_error() -> None:
    out = _tail_grant_for_mcp({})
    assert "error" in out
    assert out["events"] == []


def test_non_string_grant_id_returns_error() -> None:
    out = _tail_grant_for_mcp({"grant_id": 123})
    assert "error" in out


def test_empty_grant_id_returns_error() -> None:
    out = _tail_grant_for_mcp({"grant_id": ""})
    assert "error" in out


def test_invalid_only_errors_type() -> None:
    out = _tail_grant_for_mcp({"grant_id": "g", "only_errors": "yes"})
    assert "error" in out


def test_invalid_max_events_type() -> None:
    out = _tail_grant_for_mcp({"grant_id": "g", "max_events": "100"})
    assert "error" in out


def test_invalid_max_events_zero() -> None:
    out = _tail_grant_for_mcp({"grant_id": "g", "max_events": 0})
    assert "error" in out


def test_bool_max_events_rejected() -> None:
    """bool is a subclass of int — explicitly reject."""
    out = _tail_grant_for_mcp({"grant_id": "g", "max_events": True})
    assert "error" in out


def test_invalid_since_type() -> None:
    out = _tail_grant_for_mcp({"grant_id": "g", "since": 123})
    assert "error" in out


# ---------------------------------------------------------------------------
# _tail_grant_for_mcp — store lookup failures
# ---------------------------------------------------------------------------


def test_nonexistent_grant_returns_error(grant_store) -> None:
    out = _tail_grant_for_mcp({"grant_id": "does-not-exist"})
    assert "error" in out
    assert "could not load grant" in out["error"]


def test_unprovisioned_grant_returns_error(tmp_path, monkeypatch) -> None:
    req_dir = tmp_path / "requests"
    req_dir.mkdir()
    grant = _grant_yaml()
    grant["status"].pop("provisioned", None)
    (req_dir / "grant-1.yaml").write_text(yaml.safe_dump(grant))
    monkeypatch.setenv("IAM_JIT_REQUESTS_DIR", str(req_dir))
    monkeypatch.delenv("IAM_JIT_REQUESTS_TABLE", raising=False)
    monkeypatch.delenv("IAM_JIT_STATE_BUCKET", raising=False)

    out = _tail_grant_for_mcp({"grant_id": "grant-1"})
    assert "error" in out
    assert "no provisioned role" in out["error"]


# ---------------------------------------------------------------------------
# _tail_grant_for_mcp — happy path
# ---------------------------------------------------------------------------


def test_returns_events_via_configured_source(grant_store, stub_source) -> None:
    out = _tail_grant_for_mcp({"grant_id": "grant-1"})
    # WB22 MED-22-03 closure: top-level error is now None on success
    assert out.get("error") is None
    assert out["ok"] is True
    assert out["grant_id"] == "grant-1"
    assert out["role_name"] == "iam-jit-grant-1"
    assert out["role_session_provision_name"] == "iam-jit-provision-grant-1"
    assert out["account_id"] == "111111111111"
    assert out["event_count"] == 2
    assert len(out["events"]) == 2
    assert len(out["summaries"]) == 2
    assert "in-memory" in out["source"]


def test_only_errors_filters_through_source(grant_store, stub_source) -> None:
    out = _tail_grant_for_mcp({"grant_id": "grant-1", "only_errors": True})
    assert out["event_count"] == 1
    assert out["events"][0]["error_code"] == "AccessDenied"


def test_max_events_is_capped_at_1000(grant_store, monkeypatch) -> None:
    """Requesting more than 1000 should silently cap, not error."""
    src = InMemoryLiveActionTailSource(events=[
        _ev(event_time=f"2026-05-17T14:{i // 60:02d}:{i % 60:02d}Z", event_name=f"E{i}")
        for i in range(50)
    ])
    set_default_source(src)
    try:
        out = _tail_grant_for_mcp({"grant_id": "grant-1", "max_events": 999_999})
        assert out["ok"] is True
        # Source only had 50 events; result reflects that
        assert out["event_count"] == 50
    finally:
        set_default_source(None)


def test_summaries_are_human_readable(grant_store, stub_source) -> None:
    out = _tail_grant_for_mcp({"grant_id": "grant-1", "only_errors": False})
    assert any("OK" in s for s in out["summaries"])
    assert any("FAIL[AccessDenied]" in s for s in out["summaries"])


def test_tail_read_appends_audit_log_entry(grant_store, stub_source) -> None:
    """WB22 HIGH-22-01 closure: tail reads write to status.history
    so the audit chain isn't broken."""
    import yaml
    _tail_grant_for_mcp({"grant_id": "grant-1"})
    # Re-read grant from disk to confirm the history entry persisted
    grant_path = grant_store / "grant-1.yaml"
    grant = yaml.safe_load(grant_path.read_text())
    history = grant["status"]["history"]
    tail_entries = [e for e in history if e.get("kind") == "tail_read"]
    assert len(tail_entries) == 1
    assert tail_entries[0]["event_count"] == 2
    assert tail_entries[0]["result_ok"] is True


def test_source_error_propagated_to_mcp_response(grant_store) -> None:
    """WB22 MED-22-03 closure: when the source returns ok=False,
    MCP response surfaces ok=False + error message."""
    from iam_jit.live_action_tail import TailResult

    class _FailingSource(InMemoryLiveActionTailSource):
        def fetch_events(self, query):
            return TailResult(events=(), ok=False, error="simulated failure")

        def describe(self) -> str:
            return "failing source"

    set_default_source(_FailingSource())
    try:
        out = _tail_grant_for_mcp({"grant_id": "grant-1"})
        assert out["ok"] is False
        assert out["error"] == "simulated failure"
    finally:
        set_default_source(None)


# ---------------------------------------------------------------------------
# Full dispatch round-trip
# ---------------------------------------------------------------------------


def test_dispatch_tail_grant(grant_store, stub_source) -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "tail_grant",
            "arguments": {"grant_id": "grant-1"},
        },
    })
    sc = resp["result"]["structuredContent"]
    assert sc["grant_id"] == "grant-1"
    assert sc["event_count"] == 2


def test_tail_grant_appears_in_tools_list() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "tail_grant" in names
