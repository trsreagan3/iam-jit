"""MRR-2 F3 — structured JSON-RPC catch-all in the MCP server.

Closes the CRYPTIC -32603 catch-all
(``mcp_server.py:6475`` per docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md
commit 4cc6435).

Per ``docs/CONTRIBUTING.md`` state-verification convention: every
assertion verifies the **observable** response payload AND the
server-side log carries a correlatable error_id — not just that
``error.code == -32603``. Inner exception text MUST stay server-side
(info-disclosure mitigation; an MCP agent may forward the response
verbatim to a user-facing chat surface).
"""

from __future__ import annotations

import io
import json
import logging

import pytest

from iam_jit import mcp_server


_SECRET_INNER_MARKER = "INNER_EXCEPTION_TEXT_THAT_MUST_NOT_LEAK_CAFED00D"


def _drive_main_with_handler_raising(
    monkeypatch: pytest.MonkeyPatch,
    *,
    req_id: int = 42,
    method: str = "tools/call",
) -> dict:
    """Force ``_handle_request`` to raise the marker exception and
    drive ``mcp_server.main()`` against a one-line stdin so we exercise
    the actual MRR-2 F3 catch-all (not just the helper in isolation)."""

    def _boom(_req):
        raise RuntimeError(_SECRET_INNER_MARKER)

    monkeypatch.setattr(mcp_server, "_handle_request", _boom)

    req_line = json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": {},
    }) + "\n"

    stdin = io.StringIO(req_line)
    stdout = io.StringIO()
    monkeypatch.setattr(mcp_server.sys, "stdin", stdin)
    monkeypatch.setattr(mcp_server.sys, "stdout", stdout)

    rc = mcp_server.main()
    assert rc == 0

    raw = stdout.getvalue().strip()
    assert raw, "MCP server produced no response on stdout"
    return json.loads(raw)


def test_synthetic_handler_error_returns_structured_data_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 1 — trigger synthetic tool error → JSON-RPC response has
    structured data block + error_id + recommended_action."""
    resp = _drive_main_with_handler_raising(monkeypatch)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 42
    err = resp["error"]
    assert err["code"] == -32603  # JSON-RPC internal error per spec
    assert err["message"] == "internal error"
    data = err["data"]
    assert isinstance(data, dict), f"error.data must be a dict: {err!r}"
    # Required structured fields per MRR-2 F3.
    assert "error_id" in data
    assert "error_code" in data
    assert "method" in data
    assert "recommended_action" in data
    error_id = data["error_id"]
    assert error_id.startswith("err_"), error_id
    # 26 chars Crockford base32 body (ULID shape).
    assert len(error_id[len("err_"):]) == 26
    assert data["error_code"] == "UNHANDLED_EXCEPTION"
    assert data["method"] == "tools/call"
    assert error_id in data["recommended_action"]


def test_log_line_carries_matching_error_id(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test 2 — server-side log line has the same error_id + full
    traceback so support can correlate the agent's id with the
    actual exception."""
    caplog.set_level(logging.ERROR, logger="iam_jit.mcp_server")
    resp = _drive_main_with_handler_raising(monkeypatch)
    error_id = resp["error"]["data"]["error_id"]
    log_text = "\n".join(rec.getMessage() for rec in caplog.records)
    assert error_id in log_text, (
        f"error_id {error_id!r} not found in server logs; correlation "
        f"impossible. Log lines: {log_text!r}"
    )
    exc_info_records = [r for r in caplog.records if r.exc_info]
    assert exc_info_records, (
        "no LogRecord carried exc_info — traceback was not captured "
        "server-side; operator has no way to debug"
    )


def test_inner_exception_text_does_not_leak_to_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 3 — inner exception text MUST NOT appear anywhere in the
    client-facing JSON payload. Info-disclosure mitigation."""
    resp = _drive_main_with_handler_raising(monkeypatch)
    raw = json.dumps(resp)
    assert _SECRET_INNER_MARKER not in raw, (
        f"inner exception text leaked into JSON-RPC response: {raw!r}"
    )
    assert "RuntimeError" not in raw
    assert "Traceback" not in raw
    # The legacy bad shape was ``message="internal error: <e>"``;
    # the MRR-2 F3 fix uses ``message="internal error"`` with no
    # exception text suffix. Verify the bad shape is gone.
    assert resp["error"]["message"] == "internal error"
    assert ":" not in resp["error"]["message"]


def test_err_structured_helper_is_self_consistent() -> None:
    """White-box: the helper returns a well-formed JSON-RPC error
    envelope without needing a real exception in flight (used so the
    fix is composable from any future catch site without re-implementing
    the shape)."""
    # Trigger from inside a real except block so logger.exception has
    # context to attach (matches production call-site shape).
    try:
        raise ValueError("standalone helper test")
    except Exception:
        resp = mcp_server._err_structured(req_id_placeholder := 99, method="tools/list")
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == req_id_placeholder
    assert resp["error"]["code"] == -32603
    data = resp["error"]["data"]
    assert data["error_code"] == "UNHANDLED_EXCEPTION"
    assert data["method"] == "tools/list"
    assert data["error_id"].startswith("err_")
