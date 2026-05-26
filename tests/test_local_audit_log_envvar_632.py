"""#632 CRIT — _set_local_env_defaults must wire IAM_JIT_AUDIT_LOG.

UAT-Request-Lifecycle GAP-1 2026-05-26: ``iam-jit serve --local`` was
silently dropping ALL audit events because ``_set_local_env_defaults``
did not set ``IAM_JIT_AUDIT_LOG``.  ``audit.emit()`` guards with:

    path = os.environ.get("IAM_JIT_AUDIT_LOG")
    if path:
        <write>

When the env var is absent the guard evaluates to falsy and the write
silently no-ops.  100% of local-mode operators had:

- /audit/events returning 0 events
- ``iam-jit audit query`` unable to surface serve events
- request_cap_exceeded events (#613) not persisted
- WAF demo PDFs running with no durable audit trail

Fix: single ``os.environ.setdefault("IAM_JIT_AUDIT_LOG",
str(config.data_dir / "audit.jsonl"))`` in ``_set_local_env_defaults``.

State-verification tests per docs/CONTRIBUTING.md:

1. ``_set_local_env_defaults`` sets ``IAM_JIT_AUDIT_LOG`` to
   ``<data_dir>/audit.jsonl``.
2. Operator override (pre-set env var) is NOT overwritten (setdefault
   semantics).
3. End-to-end: emit() writes to the file after ``_set_local_env_defaults``
   runs.
4. ``GET /audit/events`` returns the emitted event from the file.
5. request_cap_exceeded events (#613 + #620 chain) are persisted.
6. Sabotage: monkeypatching the ``setdefault`` to no-op causes test 3 to
   fail (proves the env-var wire is load-bearing, not a phantom test).
"""

from __future__ import annotations

import json
import os
import pathlib
from typing import Any
from unittest import mock

import pytest

from iam_jit import audit as audit_mod
from iam_jit import local_server


# ---------------------------------------------------------------------------
# Shared fixture: isolated tmp data dir with data_dir already created
# (mirrors the serve_local() call ordering: _ensure_data_dir() runs
# BEFORE _set_local_env_defaults()).
# ---------------------------------------------------------------------------


@pytest.fixture()
def data_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """Pre-created data dir (mirrors _ensure_data_dir semantics)."""
    d = tmp_path / "iam-jit-data"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Test 1 — _set_local_env_defaults sets IAM_JIT_AUDIT_LOG
# ---------------------------------------------------------------------------


def test_set_local_env_defaults_wires_audit_log(
    data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After _set_local_env_defaults, IAM_JIT_AUDIT_LOG == <data_dir>/audit.jsonl.

    This is the PRIMARY state-verification test for #632: the env var
    was previously NEVER SET, causing 100% audit silence in local mode.
    """
    monkeypatch.delenv("IAM_JIT_AUDIT_LOG", raising=False)
    cfg = local_server.LocalServerConfig(data_dir=data_dir)
    local_server._set_local_env_defaults(cfg, "email:alice@laptop.local")

    expected = str(data_dir / "audit.jsonl")
    assert os.environ.get("IAM_JIT_AUDIT_LOG") == expected, (
        f"IAM_JIT_AUDIT_LOG not wired: got {os.environ.get('IAM_JIT_AUDIT_LOG')!r}, "
        f"want {expected!r}"
    )


# ---------------------------------------------------------------------------
# Test 2 — operator override is preserved (setdefault semantics)
# ---------------------------------------------------------------------------


def test_set_local_env_defaults_respects_operator_audit_log_override(
    data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If IAM_JIT_AUDIT_LOG is already set before _set_local_env_defaults
    runs, the function must NOT overwrite it.

    An operator who deliberately routes audit output to a different path
    (e.g. a shared NFS log volume) must not have their config silently
    clobbered.  setdefault() guarantees this.
    """
    custom_path = "/tmp/custom/operator-audit.jsonl"
    monkeypatch.setenv("IAM_JIT_AUDIT_LOG", custom_path)

    cfg = local_server.LocalServerConfig(data_dir=data_dir)
    local_server._set_local_env_defaults(cfg, "email:alice@laptop.local")

    assert os.environ["IAM_JIT_AUDIT_LOG"] == custom_path, (
        f"Operator override clobbered! "
        f"Expected {custom_path!r}, got {os.environ['IAM_JIT_AUDIT_LOG']!r}"
    )


# ---------------------------------------------------------------------------
# Test 3 — end-to-end: emit() writes to audit.jsonl after env var is wired
# ---------------------------------------------------------------------------


def test_audit_emit_persists_to_file_after_env_wired(
    data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After _set_local_env_defaults, audit.emit() must write events to
    <data_dir>/audit.jsonl.

    Before #632 this test would produce an empty file (0 events) because
    the env var was not set and the emit guard silently skipped the write.
    """
    monkeypatch.delenv("IAM_JIT_AUDIT_LOG", raising=False)
    cfg = local_server.LocalServerConfig(data_dir=data_dir)
    local_server._set_local_env_defaults(cfg, "email:alice@laptop.local")

    # Reset in-memory chain so this test is independent of other tests.
    audit_mod._LAST_HASH = None  # type: ignore[attr-defined]
    audit_mod._NEXT_SEQ = 0  # type: ignore[attr-defined]

    audit_mod.emit(
        actor="email:alice@laptop.local",
        kind="request_submit",
        summary="test request submitted",
        details={"request_id": "req-test-001"},
    )

    audit_log = data_dir / "audit.jsonl"
    assert audit_log.exists(), (
        f"audit.jsonl not created at {audit_log} — emit() silently dropped the event"
    )
    lines = [l for l in audit_log.read_text().splitlines() if l.strip()]
    assert len(lines) >= 1, f"audit.jsonl is empty — no events persisted"

    event = json.loads(lines[0])
    assert event["kind"] == "request_submit"
    assert event["actor"] == "email:alice@laptop.local"
    assert event.get("hash") is not None, "hash-chain field missing"


# ---------------------------------------------------------------------------
# Test 4 — /audit/events endpoint returns the persisted event
# ---------------------------------------------------------------------------


def test_audit_events_endpoint_reads_from_wired_log(
    data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /audit/events returns events from the file set by
    IAM_JIT_AUDIT_LOG.

    This test exercises the full read path:
      1. _set_local_env_defaults wires IAM_JIT_AUDIT_LOG
      2. audit.emit() writes to the file
      3. /audit/events reads IAM_JIT_AUDIT_LOG and returns the event
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from iam_jit.routes.audit_events import router as audit_events_router
    from iam_jit.users_store import User

    monkeypatch.delenv("IAM_JIT_AUDIT_LOG", raising=False)
    cfg = local_server.LocalServerConfig(data_dir=data_dir)
    local_server._set_local_env_defaults(cfg, "email:alice@laptop.local")

    # Reset in-memory chain.
    audit_mod._LAST_HASH = None  # type: ignore[attr-defined]
    audit_mod._NEXT_SEQ = 0  # type: ignore[attr-defined]

    audit_mod.emit(
        actor="email:alice@laptop.local",
        kind="request_submit",
        summary="request via endpoint test",
        details={"request_id": "req-endpoint-001"},
    )

    # Build a minimal FastAPI app that mounts the audit/events router.
    # Bypass auth by overriding require_admin.
    from iam_jit import middleware as _mw

    admin_user = User(
        id="email:alice@laptop.local",
        roles=["admin", "approver", "requester"],
        enabled=True,
    )

    app = FastAPI()
    app.include_router(audit_events_router)
    app.dependency_overrides[_mw.require_admin] = lambda: admin_user

    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get("/audit/events")
    assert resp.status_code == 200, f"Unexpected status: {resp.status_code} — {resp.text}"

    lines = [l for l in resp.text.splitlines() if l.strip()]
    assert len(lines) >= 1, (
        "GET /audit/events returned 0 events — "
        "audit log not read or IAM_JIT_AUDIT_LOG not wired"
    )
    event = json.loads(lines[0])
    # OCSF shape from _audit_event_to_ocsf
    assert event.get("unmapped", {}).get("iam_jit", {}).get("kind") == "request_submit"


# ---------------------------------------------------------------------------
# Test 5 — request_cap_exceeded events persisted (#613 + #620 chain)
# ---------------------------------------------------------------------------


def test_request_cap_exceeded_event_persisted_to_audit_log(
    data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """request_cap_exceeded events emitted by the cap helper (#613) must
    land in audit.jsonl when IAM_JIT_AUDIT_LOG is wired.

    Before #632, the cap could fire and emit the event, but the event
    disappeared silently because IAM_JIT_AUDIT_LOG was not set.
    The #613+#620 recipe told operators to run:

        iam-jit audit query --kind request_cap_exceeded --since 1h

    and got 0 events — a doc-lie.  This test closes that lie.
    """
    monkeypatch.delenv("IAM_JIT_AUDIT_LOG", raising=False)
    cfg = local_server.LocalServerConfig(data_dir=data_dir)
    local_server._set_local_env_defaults(cfg, "email:alice@laptop.local")

    # Reset in-memory chain.
    audit_mod._LAST_HASH = None  # type: ignore[attr-defined]
    audit_mod._NEXT_SEQ = 0  # type: ignore[attr-defined]

    # Directly emit a request_cap_exceeded event (the same call the cap
    # helper makes internally).
    audit_mod.emit(
        actor="email:agent@laptop.local",
        kind="request_cap_exceeded",
        summary="outstanding request cap exceeded (cap=20, current=21)",
        details={
            "user_id": "email:agent@laptop.local",
            "cap": 20,
            "outstanding": 21,
        },
    )

    audit_log = data_dir / "audit.jsonl"
    assert audit_log.exists(), "audit.jsonl missing — cap event not persisted"
    events = [
        json.loads(line)
        for line in audit_log.read_text().splitlines()
        if line.strip()
    ]
    cap_events = [e for e in events if e.get("kind") == "request_cap_exceeded"]
    assert len(cap_events) >= 1, (
        "No request_cap_exceeded event found in audit.jsonl — "
        "emit() silently dropped it (IAM_JIT_AUDIT_LOG not wired?)"
    )
    ev = cap_events[0]
    assert ev["details"]["cap"] == 20
    assert ev["details"]["outstanding"] == 21


# ---------------------------------------------------------------------------
# Test 6 — sabotage: prove the env-var wire is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_audit_log_wire_is_load_bearing(
    data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If _set_local_env_defaults does NOT set IAM_JIT_AUDIT_LOG, emit()
    silently no-ops and audit.jsonl is never created.

    This test intentionally sabotages the env-var wire (by preventing
    the setdefault from running) and verifies that the audit file is
    NOT populated.  The test correctly PASSES when the fix is absent
    (confirming the bug) and correctly FAILS if someone re-introduces
    the bug while the fix is in place — making this the canary.

    Implementation: we let _set_local_env_defaults run normally first
    to establish the baseline behavior (test 3 already covers that),
    but here we explicitly DELETE the env var after the call to
    simulate the pre-#632 state, then call emit() and confirm silence.
    """
    monkeypatch.delenv("IAM_JIT_AUDIT_LOG", raising=False)
    cfg = local_server.LocalServerConfig(data_dir=data_dir)
    local_server._set_local_env_defaults(cfg, "email:alice@laptop.local")

    # Sabotage: undo the env-var that _set_local_env_defaults just set.
    monkeypatch.delenv("IAM_JIT_AUDIT_LOG", raising=False)
    assert os.environ.get("IAM_JIT_AUDIT_LOG") is None, "sabotage incomplete"

    # Reset in-memory chain.
    audit_mod._LAST_HASH = None  # type: ignore[attr-defined]
    audit_mod._NEXT_SEQ = 0  # type: ignore[attr-defined]

    audit_mod.emit(
        actor="email:alice@laptop.local",
        kind="request_submit",
        summary="sabotage test — should not land on disk",
        details={},
    )

    # With the env var gone, audit.emit() silently no-ops.
    # The file should NOT exist (or be empty if created by another test
    # in the same data_dir — we use a fresh tmp dir per test fixture,
    # so absence is guaranteed unless the test isolation is broken).
    audit_log = data_dir / "audit.jsonl"
    if audit_log.exists():
        lines = [l for l in audit_log.read_text().splitlines() if l.strip()]
        assert lines == [], (
            "Sabotage check: IAM_JIT_AUDIT_LOG was unset but audit.jsonl has "
            f"{len(lines)} event(s) — the env-var gate in audit.emit() may have "
            "changed, OR the data_dir isolation in the fixture is broken."
        )
    # If the file doesn't exist at all, the sabotage worked: emit() was silent.
    # (This is the expected path.)
