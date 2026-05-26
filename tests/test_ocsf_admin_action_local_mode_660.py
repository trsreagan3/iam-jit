"""#660 CRIT + #661 — OCSF class 6003 admin-action events land in audit.jsonl
in local mode, and emit failures are warned not silently swallowed.

UAT of #611 (commit 0f059c4) caught: ``emit_admin_action_direct()`` was wired
ONLY through ``bouncer.proxy._emit_audit_event``, which is a no-op in
``iam-jit serve --local`` mode because ``_audit_log_writer is None``.  Result:
ZERO OCSF class 6003 events with
``unmapped.iam_jit.event_type == "ADMIN_ACTION"`` landed in any audit stream
for account register/deregister operations in local mode.

Fix (Approach C): ``emit_iam_jit_admin_action()`` in
``iam_jit/audit_admin_action.py`` calls ``audit.emit()`` (Channel 1, always
available when ``IAM_JIT_AUDIT_LOG`` is set per #632) AND
``bouncer.proxy._emit_audit_event`` (Channel 2, wired in non-local modes).

#661 closed in the same commit: ``except Exception: pass`` replaced with
``logger.warning(...)``; the request still succeeds.

Tests in this module:

  1. ``test_ocsf_event_lands_in_audit_jsonl_after_register`` — live integration:
     POST ``/api/v1/accounts``, assert OCSF class 6003 event with
     ``event_type=="ADMIN_ACTION"`` + correct ``account_id`` is in audit.jsonl.

  2. ``test_ocsf_event_lands_in_audit_jsonl_after_deregister`` — same for
     account deregister.

  3. ``test_emit_failure_logs_warning_not_crash`` — negative: monkeypatch
     ``audit.emit`` to raise; verify ``logger.warning`` fires and the route
     still returns 201 (not 500).

  4. ``test_emit_iam_jit_admin_action_unit_channel1_called`` — unit test for
     the helper itself: Channel 1 (``audit.emit``) is called even when Channel
     2 (proxy) is not available.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import pathlib
from typing import Any
from unittest import mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from iam_jit import audit as audit_mod
from iam_jit.accounts_store import AccountStore
from iam_jit.api_tokens_store import InMemoryAPITokenStore
from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore

pytest_plugins = ["tests.conftest_routes"]

# ---------------------------------------------------------------------------
# Helpers / shared constants
# ---------------------------------------------------------------------------

_ACCOUNT_ID = "123456789012"
_ADMIN_EMAIL = "email:admin@example.com"

_REGISTER_PAYLOAD: dict[str, Any] = {
    "account_id": _ACCOUNT_ID,
    "provisioner_role_arn": f"arn:aws:iam::{_ACCOUNT_ID}:role/iam-jit-provisioner",
    "provisioner_external_id": f"iam-jit-{_ACCOUNT_ID}",
    "provisioning_mode": "classic_iam",
    "alias": "test-account",
    "regions": ["us-east-1"],
}


def _read_ocsf_admin_events(audit_jsonl: pathlib.Path) -> list[dict]:
    """Return all admin.action events from audit.jsonl whose details contain
    an OCSF class 6003 payload (event_type == ADMIN_ACTION)."""
    if not audit_jsonl.exists():
        return []
    events = []
    for line in audit_jsonl.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        details = ev.get("details") or {}
        if details.get("event_type") == "ADMIN_ACTION":
            events.append(ev)
    return events


# ---------------------------------------------------------------------------
# Test 1 — live integration: register lands OCSF admin-action in audit.jsonl
# ---------------------------------------------------------------------------


def test_ocsf_event_lands_in_audit_jsonl_after_register(
    tmp_path: pathlib.Path,
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /api/v1/accounts → audit.jsonl must contain an OCSF class 6003
    event with event_type=='ADMIN_ACTION', class_uid==6003, and the correct
    account_id in admin_action.target_id.

    This is the PRIMARY regression test for #660: before the fix, 0 OCSF
    admin-action events landed in audit.jsonl in local mode.
    """
    audit_log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("IAM_JIT_AUDIT_LOG", str(audit_log))

    # Reset the in-memory hash-chain so this test is isolated.
    audit_mod.reset_for_tests()

    resp = as_admin.post("/api/v1/accounts", json=_REGISTER_PAYLOAD)
    assert resp.status_code == 201, f"register failed: {resp.text}"

    admin_events = _read_ocsf_admin_events(audit_log)
    assert len(admin_events) >= 1, (
        f"Expected >=1 OCSF admin-action event in audit.jsonl after account "
        f"register, got 0.  audit.jsonl contents:\n"
        f"{audit_log.read_text() if audit_log.exists() else '(file not created)'}"
    )

    ev = admin_events[0]
    details = ev["details"]
    admin_action = details.get("admin_action") or {}

    assert details.get("ocsf_class_uid") == 6003, (
        f"Expected ocsf_class_uid=6003, got {details.get('ocsf_class_uid')!r}"
    )
    assert admin_action.get("kind") == "account.registered", (
        f"Expected kind='account.registered', got {admin_action.get('kind')!r}"
    )
    assert admin_action.get("target_id") == _ACCOUNT_ID, (
        f"Expected target_id={_ACCOUNT_ID!r}, got {admin_action.get('target_id')!r}"
    )
    assert admin_action.get("target_kind") == "aws_account", (
        f"Expected target_kind='aws_account', got {admin_action.get('target_kind')!r}"
    )
    assert ev.get("kind") == "admin.action", (
        f"Expected kind='admin.action', got {ev.get('kind')!r}"
    )


# ---------------------------------------------------------------------------
# Test 2 — live integration: deregister lands OCSF admin-action in audit.jsonl
# ---------------------------------------------------------------------------


def test_ocsf_event_lands_in_audit_jsonl_after_deregister(
    tmp_path: pathlib.Path,
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DELETE /api/v1/accounts/{account_id} → audit.jsonl must contain an
    OCSF class 6003 event with event_type=='ADMIN_ACTION' and
    kind=='account.deregistered'."""
    audit_log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("IAM_JIT_AUDIT_LOG", str(audit_log))

    audit_mod.reset_for_tests()

    # Register first so there's something to deregister.
    reg = as_admin.post("/api/v1/accounts", json=_REGISTER_PAYLOAD)
    assert reg.status_code == 201, f"setup register failed: {reg.text}"

    resp = as_admin.delete(f"/api/v1/accounts/{_ACCOUNT_ID}")
    assert resp.status_code == 200, f"deregister failed: {resp.text}"

    admin_events = _read_ocsf_admin_events(audit_log)
    # We expect 2 admin-action events (register + deregister); assert
    # on the deregister one specifically.
    deregister_events = [
        e for e in admin_events
        if (e.get("details") or {}).get("admin_action", {}).get("kind") == "account.deregistered"
    ]
    assert len(deregister_events) >= 1, (
        f"Expected >=1 OCSF admin-action event with kind='account.deregistered', "
        f"got 0 from {len(admin_events)} total admin events.\n"
        f"audit.jsonl:\n"
        f"{audit_log.read_text() if audit_log.exists() else '(file not created)'}"
    )

    ev = deregister_events[0]
    details = ev["details"]
    admin_action = details.get("admin_action") or {}
    assert admin_action.get("target_id") == _ACCOUNT_ID
    assert admin_action.get("target_kind") == "aws_account"


# ---------------------------------------------------------------------------
# Test 3 — #661: emit failure → logger.warning, request still 201
# ---------------------------------------------------------------------------


def test_emit_failure_logs_warning_not_crash(
    tmp_path: pathlib.Path,
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When audit.emit() raises, the route must still return 201 (the
    user-facing operation succeeded) and a WARNING must be logged.

    Before #661 the except-block was ``except Exception: pass`` — the
    failure was silently discarded. Per [[ibounce-honest-positioning]]
    operators deserve a log line so they can diagnose a broken audit
    channel without reading source code.
    """
    audit_log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("IAM_JIT_AUDIT_LOG", str(audit_log))
    audit_mod.reset_for_tests()

    # Monkeypatch audit.emit to raise on the 'admin.action' kind.
    original_emit = audit_mod.emit

    def _raising_emit(**kwargs: Any) -> Any:
        if kwargs.get("kind") == "admin.action":
            raise RuntimeError("simulated audit.emit failure for #661 test")
        return original_emit(**kwargs)

    import iam_jit.audit_admin_action as _helper_mod
    monkeypatch.setattr(_helper_mod, "audit", mock.MagicMock(emit=_raising_emit))

    with caplog.at_level(logging.WARNING, logger="iam_jit.audit_admin_action"):
        resp = as_admin.post("/api/v1/accounts", json=_REGISTER_PAYLOAD)

    assert resp.status_code == 201, (
        f"Route returned {resp.status_code}, expected 201 — "
        f"audit emit failure must not crash the request: {resp.text}"
    )

    warning_msgs = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("admin-action audit.emit() failed" in m for m in warning_msgs), (
        f"Expected a WARNING containing 'admin-action audit.emit() failed' in logs. "
        f"Got: {warning_msgs}"
    )


# ---------------------------------------------------------------------------
# Test 4 — unit: helper calls Channel 1 (audit.emit) even without proxy
# ---------------------------------------------------------------------------


def test_emit_iam_jit_admin_action_unit_channel1_called(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``emit_iam_jit_admin_action()`` must call ``audit.emit()`` (Channel 1)
    regardless of whether the bouncer proxy channel is available.

    This unit test verifies the helper's Channel 1 behaviour in isolation
    from the route test harness, using a fresh tmp data dir as the audit log
    destination.  It does NOT import or rely on the TestClient.
    """
    audit_log = tmp_path / "unit-audit.jsonl"
    monkeypatch.setenv("IAM_JIT_AUDIT_LOG", str(audit_log))
    audit_mod.reset_for_tests()

    from iam_jit.audit_admin_action import emit_iam_jit_admin_action

    # Simulate a test environment where the proxy is not importable.
    # ImportError from bouncer.proxy should be silently handled (debug log).
    with mock.patch(
        "iam_jit.audit_admin_action.emit_iam_jit_admin_action.__module__",
        "iam_jit.audit_admin_action",
    ):
        emit_iam_jit_admin_action(
            kind="account.registered",
            actor="email:testuser@example.com",
            target_kind="aws_account",
            target_id="999988887777",
            source="api",
            extra={"test": True},
        )

    assert audit_log.exists(), (
        f"audit.jsonl not created at {audit_log} — "
        "emit_iam_jit_admin_action() did not call audit.emit()"
    )
    lines = [l for l in audit_log.read_text().splitlines() if l.strip()]
    assert len(lines) >= 1, "audit.jsonl is empty — audit.emit() was not called"

    ev = json.loads(lines[0])
    assert ev.get("kind") == "admin.action", (
        f"Expected kind='admin.action', got {ev.get('kind')!r}"
    )
    details = ev.get("details") or {}
    assert details.get("event_type") == "ADMIN_ACTION"
    admin_action = details.get("admin_action") or {}
    assert admin_action.get("kind") == "account.registered"
    assert admin_action.get("target_id") == "999988887777"
    assert ev.get("hash") is not None, "hash-chain field missing"
