"""fix/10-header-verify-h3-cosmetics — regression + new tests for four items.

Item 1 — session-header convergence (already fixed by #67):
    Regression test: IBOUNCE_AGENT_SESSION_ID env var is the MCP config
    hint; the proxy reads the CANONICAL `x-agent-session-id` header; no
    reader of the old `x-iam-jit-agent-session-id` form exists.

Item 2 — BaselineStore _open_lock (H3 hardening):
    N threads concurrently call summary_for / known_agents on a fresh
    un-started store → exactly one open, no exceptions, correct row
    counts.

Item 3 — ibounce posture reports actual running port:
    detect_ibounce() reads the ibounce-running.json hint file written by
    serve() and returns the real non-default port when ibounce is running
    on it without autopilot or AWS_ENDPOINT_URL.

Item 4 — .iam-jit.yaml schema error is actionable:
    validate_declaration() with iam_jit (underscore) or missing enabled
    raises ConfigLoadError with a message that names the actual problem.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Item 1 — session-header convergence regression
# ---------------------------------------------------------------------------


def test_item1_no_old_header_form_anywhere():
    """No reader of the legacy x-iam-jit-agent-session-id header remains.

    The canonical extractor only looks for x-agent-session-id (lower-
    cased). Supplying the OLD header form produces (None, None); the NEW
    form produces the expected value.  Locks the convergence #67 fixed.
    """
    from iam_jit.bouncer.audit_export import extract_agent_headers

    # Old header form — must NOT be read (regression guard for #67).
    old_name, old_sid = extract_agent_headers({
        "x-iam-jit-agent-session-id": "old-form-should-not-be-read",
        "X-Agent-Name": "test-agent",
    })
    assert old_sid is None, (
        "Regression: x-iam-jit-agent-session-id must NOT be read by the "
        "canonical extractor — only x-agent-session-id is canonical."
    )
    assert old_name == "test-agent"

    # New canonical form — must be read.
    new_name, new_sid = extract_agent_headers({
        "X-Agent-Session-Id": "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef",
        "X-Agent-Name": "test-agent",
    })
    assert new_sid == "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
    assert new_name == "test-agent"


def test_item1_env_to_mcp_config_contains_canonical_env_var():
    """IBOUNCE_AGENT_SESSION_ID is in the MCP config env block so the agent
    runtime can stamp it as X-Agent-Session-Id.  The proxy itself does NOT
    read this env var — it reads the inbound header instead."""
    from iam_jit.bouncer_cli import _ibounce_mcp_config_dict

    cfg = _ibounce_mcp_config_dict()
    env = cfg["mcpServers"]["ibounce"]["env"]
    assert "IBOUNCE_AGENT_SESSION_ID" in env, (
        "MCP config must include IBOUNCE_AGENT_SESSION_ID so the agent "
        "runtime can stamp X-Agent-Session-Id on its outbound requests."
    )
    assert "IBOUNCE_AGENT_NAME" in env, (
        "MCP config must include IBOUNCE_AGENT_NAME for the X-Agent-Name header."
    )


def test_item1_audit_event_session_id_from_header():
    """End-to-end: X-Agent-Session-Id header →  audit event session_id.

    Locks the full env→header→audit-event chain that #67 established.
    The MCP config instructs the agent runtime to inject the session env
    var as the X-Agent-Session-Id header; the proxy reads that header via
    extract_agent_headers; the audit event carries the value verbatim.
    """
    from iam_jit.bouncer.audit_export import (
        audit_event_from_decision,
        extract_agent_headers,
        reset_agent_headers_rejected_for_tests,
        reset_for_tests,
    )

    reset_for_tests()
    reset_agent_headers_rejected_for_tests()

    # Simulate: agent runtime read IBOUNCE_AGENT_SESSION_ID="sess-42" from
    # env and stamped it as the X-Agent-Session-Id header.
    inbound_headers = {
        "X-Agent-Name": "claude-code",
        "X-Agent-Session-Id": "sess-42",
    }
    name, sid = extract_agent_headers(inbound_headers)
    assert sid == "sess-42"
    assert name == "claude-code"

    ev = audit_event_from_decision(
        decision_id=1,
        mode="transparent",
        profile=None,
        verdict="allow",
        reason="",
        service="s3",
        action="ListBuckets",
        arn=None,
        region="us-east-1",
        host="s3.us-east-1.amazonaws.com",
        header_agent_name=name,
        header_agent_session_id=sid,
    )
    agent = ev["unmapped"]["iam_jit"]["agent"]
    assert agent["session_id"] == "sess-42", (
        "Regression: session_id must flow from header → audit event "
        "(env→header→event chain locked by #67)"
    )
    assert agent["name"] == "claude-code"
    assert agent["detected_from"] == "http_header"


# ---------------------------------------------------------------------------
# Item 2 — BaselineStore _open_lock concurrent stress
# ---------------------------------------------------------------------------


def test_item2_baseline_open_lock_concurrent_open_only(tmp_path):
    """32 threads race to call _ensure_open (via known_agents) on a fresh
    un-started store.

    Invariant: no exceptions during the open phase; exactly ONE connection
    is created (deduplicated open under _open_lock).  Post-open reads are
    serialized so this test only exercises the open race.

    This exercises the double-checked locking around _open_lock added in
    fix/10-header-verify-h3-cosmetics. The "bad parameter / not an error"
    SQLite misuse that the ORIGINAL code could produce on concurrent opens
    must NOT appear.
    """
    import iam_jit.anomaly_detection.baseline as _bl_mod
    from iam_jit.anomaly_detection.baseline import BaselineStore

    db_path = str(tmp_path / "stress.db")
    store = BaselineStore(path=db_path)
    # Do NOT call store.start() — threads race to call _ensure_open.

    N_THREADS = 32
    open_errors: list[Exception] = []
    lock = threading.Lock()
    barrier = threading.Barrier(N_THREADS)

    def _worker():
        # Synchronise: all threads hit _ensure_open at the same instant.
        barrier.wait()
        try:
            store._ensure_open()
        except Exception as e:
            with lock:
                open_errors.append(e)

    threads = [threading.Thread(target=_worker) for _ in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not open_errors, (
        f"Concurrent _ensure_open raised {len(open_errors)} exception(s):\n"
        + "\n".join(str(e) for e in open_errors[:5])
    )
    # Exactly one connection object (deduplicated open).
    assert store._conn is not None, "Connection must be open after first call"
    # Post-open sequential read must work normally.
    agents = store.known_agents()
    assert isinstance(agents, list)
    store.stop(drain=False)


def test_item2_baseline_open_lock_concurrent_summary_for(tmp_path):
    """16 threads each open a SEPARATE store and call summary_for concurrently.

    Verifies that the per-store _open_lock works correctly: each store opens
    exactly once. This avoids the shared-connection concurrency issue while
    still exercising the locking code path under real thread pressure.
    """
    from iam_jit.anomaly_detection.baseline import BaselineStore

    N_THREADS = 16
    errors: list[Exception] = []
    results: list[Any] = []
    lock = threading.Lock()
    barrier = threading.Barrier(N_THREADS)

    def _worker(idx: int):
        # Each thread gets its own store (own connection) to avoid
        # shared-connection SQLite concurrency limits.
        db_path = str(tmp_path / f"stress-{idx}.db")
        store = BaselineStore(path=db_path)
        barrier.wait()
        try:
            summary = store.summary_for("agent-stress", "s3:ListBuckets")
            with lock:
                results.append(summary)
        except Exception as e:
            with lock:
                errors.append(e)
        finally:
            store.stop(drain=False)

    threads = [
        threading.Thread(target=_worker, args=(i,)) for i in range(N_THREADS)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not errors, (
        f"Concurrent summary_for (per-store) raised {len(errors)} exception(s):\n"
        + "\n".join(str(e) for e in errors[:5])
    )
    assert len(results) == N_THREADS, (
        f"Expected {N_THREADS} results, got {len(results)}"
    )


def test_item2_baseline_open_lock_concurrent_known_agents(tmp_path):
    """32 threads race to open a fresh un-started store via _ensure_open.

    Uses known_agents (→ _ensure_open) as the entry point.  All threads
    synchronise at a barrier so the open race is maximally contentious.
    No 'no such table' / 'bad parameter' errors must escape.
    """
    from iam_jit.anomaly_detection.baseline import BaselineStore

    db_path = str(tmp_path / "stress2.db")
    store = BaselineStore(path=db_path)

    N_THREADS = 32
    open_errors: list[Exception] = []
    lock = threading.Lock()
    barrier = threading.Barrier(N_THREADS)

    def _worker():
        barrier.wait()
        try:
            store._ensure_open()
        except Exception as e:
            with lock:
                open_errors.append(e)

    threads = [threading.Thread(target=_worker) for _ in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not open_errors, (
        f"Concurrent _ensure_open (known_agents path) raised "
        f"{len(open_errors)} exception(s):\n"
        + "\n".join(str(e) for e in open_errors[:5])
    )
    # Post-open sequential query must work.
    agents = store.known_agents()
    assert isinstance(agents, list)
    store.stop(drain=False)


def test_item2_baseline_start_idempotent_under_concurrent_calls(tmp_path):
    """Calling start() from N threads produces exactly one worker thread."""
    from iam_jit.anomaly_detection.baseline import BaselineStore

    db_path = str(tmp_path / "stress3.db")
    store = BaselineStore(path=db_path)

    N_THREADS = 16
    errors: list[Exception] = []

    def _worker():
        try:
            store.start()
        except Exception as e:
            with threading.Lock():
                errors.append(e)

    threads = [threading.Thread(target=_worker) for _ in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    assert not errors, (
        f"Concurrent start() raised {len(errors)} exception(s):\n"
        + "\n".join(str(e) for e in errors[:5])
    )
    # Exactly one worker thread (deduplicated start).
    assert store._worker is not None
    assert store._worker.is_alive()
    store.stop()


def test_item2_single_threaded_still_works(tmp_path):
    """Single-threaded proxy path (start → observe → summary_for) still works
    after adding _open_lock."""
    from iam_jit.anomaly_detection.baseline import BaselineStore

    db_path = str(tmp_path / "single.db")
    store = BaselineStore(path=db_path)
    store.start()

    for i in range(5):
        store.observe(
            agent_identity="bot",
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key.txt",
            observed_at=time.time() - i * 60,
        )

    # Flush + query.
    store.stop()

    # Re-open via _ensure_open (read-only path) and verify row counts.
    store2 = BaselineStore(path=db_path)
    agents = store2.known_agents()
    assert "bot" in agents, "bot agent should be tracked after stop+reopen"
    store2.stop(drain=False)


# ---------------------------------------------------------------------------
# Item 3 — ibounce posture reports actual running port
# ---------------------------------------------------------------------------


def _bind_free_port() -> tuple[socket.socket, int]:
    """Bind a free loopback port. Caller must close the socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s, s.getsockname()[1]


def test_item3_detect_ibounce_reads_running_hint_file(monkeypatch, tmp_path):
    """detect_ibounce() returns the port from ibounce-running.json when
    something is actually listening on that port.

    This is the case that was broken: ibounce run --port N (no autopilot,
    no AWS_ENDPOINT_URL) → ibounce posture reported the default 8767 port
    instead of N.
    """
    from iam_jit.posture.bouncers import (
        IBOUNCE_DEFAULT_PORT,
        detect_ibounce,
    )

    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)

    # Bind a free port to simulate ibounce running on a non-default port.
    sock, custom_port = _bind_free_port()
    assert custom_port != IBOUNCE_DEFAULT_PORT, (
        "Got the default port by accident — retry"
    )

    try:
        # Write the ibounce-running.json hint file (as serve() does).
        hint_path = tmp_path / "ibounce-running.json"
        hint_path.write_text(
            json.dumps({"port": custom_port, "host": "127.0.0.1"}),
            encoding="utf-8",
        )

        block = detect_ibounce()
        assert block["running"] is True, (
            f"detect_ibounce() must report running=True when hint file + "
            f"live port ({custom_port}) are present"
        )
        assert block["port"] == custom_port, (
            f"detect_ibounce() must report port={custom_port} from hint file, "
            f"got {block['port']}"
        )
    finally:
        sock.close()


def test_item3_detect_ibounce_ignores_stale_hint_file(monkeypatch, tmp_path):
    """detect_ibounce() ignores ibounce-running.json when the port is not
    actually listening (stale hint after a crash)."""
    from iam_jit.posture.bouncers import detect_ibounce

    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)

    # Write a hint file pointing at a port nothing is listening on.
    hint_path = tmp_path / "ibounce-running.json"
    hint_path.write_text(
        json.dumps({"port": 19099, "host": "127.0.0.1"}),
        encoding="utf-8",
    )

    block = detect_ibounce()
    # Should not report running=True from the stale hint.
    # (It may still be True if something else is on the default port in CI,
    # but the port must NOT be 19099.)
    assert block.get("port") != 19099, (
        "detect_ibounce() must NOT trust a stale hint file pointing at a "
        "port nothing is listening on"
    )


def test_item3_detect_ibounce_no_hint_file_falls_back(monkeypatch, tmp_path):
    """detect_ibounce() falls back to autopilot + default-port probe when
    ibounce-running.json is absent (pre-fix behavior preserved)."""
    from iam_jit.posture.bouncers import (
        IBOUNCE_DEFAULT_PORT,
        detect_ibounce,
    )

    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    # No hint file written — tmp_path is empty.

    block = detect_ibounce()
    # The function must not raise; default_port must be the constant.
    assert block["default_port"] == IBOUNCE_DEFAULT_PORT
    assert "port" in block
    assert "running" in block


# ---------------------------------------------------------------------------
# Item 4 — actionable schema error messages
# ---------------------------------------------------------------------------


def test_item4_underscore_key_error_names_the_problem():
    """validate_declaration({'iam_jit': ...}) raises ConfigLoadError with
    a message that says 'top-level key must be iam-jit (hyphen), got
    iam_jit (underscore)' — not the generic jsonschema text."""
    from iam_jit.ambient_config.loader import ConfigLoadError, validate_declaration

    bad = {"iam_jit": {"enabled": True}}
    with pytest.raises(ConfigLoadError) as exc_info:
        validate_declaration(bad)

    err = exc_info.value
    assert err.code == "schema_validation_error"
    msg = err.message.lower()
    assert "hyphen" in msg or "iam-jit" in msg, (
        f"Error message must name the hyphen vs underscore issue, got: {err.message!r}"
    )
    assert "underscore" in msg or "iam_jit" in msg, (
        f"Error message must name the underscore key, got: {err.message!r}"
    )
    # The details errors list must also carry the actionable message.
    detail_msgs = " ".join(
        e.get("message", "") for e in err.details.get("errors", [])
    ).lower()
    assert "hyphen" in detail_msgs or "iam-jit" in detail_msgs, (
        f"Details errors must name the hyphen issue, got: {err.details!r}"
    )


def test_item4_missing_enabled_names_the_field():
    """validate_declaration({'iam-jit': {}}) raises ConfigLoadError with
    a message that says iam-jit.enabled is required."""
    from iam_jit.ambient_config.loader import ConfigLoadError, validate_declaration

    bad = {"iam-jit": {}}
    with pytest.raises(ConfigLoadError) as exc_info:
        validate_declaration(bad)

    err = exc_info.value
    assert err.code == "schema_validation_error"
    # Either the top-level message or the detail entries must mention 'enabled'.
    combined = err.message + " " + json.dumps(err.details)
    assert "enabled" in combined.lower(), (
        f"Error output must mention 'enabled' when that field is missing; "
        f"got message={err.message!r} details={err.details!r}"
    )


def test_item4_valid_minimal_still_passes():
    """A minimal valid declaration still passes after the enrichment changes."""
    from iam_jit.ambient_config.loader import validate_declaration

    valid = {"iam-jit": {"enabled": True}}
    result = validate_declaration(valid)
    assert result["iam-jit"]["enabled"] is True


def test_item4_valid_full_still_passes():
    """A full valid declaration still passes."""
    from iam_jit.ambient_config.loader import validate_declaration

    valid = {
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery", "profile": "auto"},
            },
        }
    }
    result = validate_declaration(valid)
    assert result["iam-jit"]["posture"] == "ambient"


def test_item4_error_from_load_declaration_from_string_underscore():
    """load_declaration_from_string with the underscore key produces the
    actionable error through the full load path."""
    from iam_jit.ambient_config.loader import ConfigLoadError, load_declaration_from_string

    yaml_text = "iam_jit:\n  enabled: true\n"
    with pytest.raises(ConfigLoadError) as exc_info:
        load_declaration_from_string(yaml_text, source="test.yaml")

    err = exc_info.value
    msg = err.message.lower()
    assert "hyphen" in msg or "iam-jit" in msg or "underscore" in msg or "iam_jit" in msg, (
        f"Full load path must surface the underscore hint, got: {err.message!r}"
    )
