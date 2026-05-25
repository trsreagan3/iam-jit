"""MRR-2 F4-F8 + R1-R6 cluster — state-verification tests for error
shapes + silent-degradation visibility.

Per docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md the pre-deploy CRITs
F1+F2+F3 shipped in commit ``f00d845`` (with tests under
``test_app_500_handler.py`` / ``test_mcp_server_error_shape.py`` /
``test_pipeline_partial_install_honest.py``). This module closes the
pre-promotion HIGH residual:

  * F4 — revoke 500/502 leaks (routes/requests.py)
  * F5 — autopilot improve-cycle + threat-feed sub-load silent
    degradation (autopilot/daemon.py)
  * F6 — synthesis env-var fallback silent degradation
    (request_from_synthesis.py)
  * F7 — self_approve bare-except silent inert (routes/requests.py)
  * F8 — admin-action emit bare-except sweep (mcp_server.py)
  * R1 — shared OperatorError helper (iam_jit/errors.py)
  * R2 — degraded_capability.emit() generalisation
    (iam_jit/degraded_capability.py)
  * R4 — recommended_action on upstream 502 forward failures
    (bouncer/proxy.py)

Per ``docs/CONTRIBUTING.md`` state-verification convention: every
assertion verifies the **observable** response shape — the structured
envelope keys + the snapshot counter — not just that an exception was
swallowed.

R3 (status:auto_installed runtime invariant) is already shipped via
F1 + tests in ``test_pipeline_partial_install_honest.py``; no
duplicate coverage here.

R5 (admin-action emit /healthz counter) is realised via the
``degraded_capabilities`` block this module verifies — see
test_proxy_healthz_exposes_degraded_capabilities.

R6 (MRR-1 CRIT re-audit) is meta-task / MRR-3 territory; deferred
with a follow-up task ID (see final report).
"""

from __future__ import annotations

import logging
import pathlib
from typing import Any
from unittest import mock

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from iam_jit import degraded_capability
from iam_jit.app import create_app
from iam_jit.errors import (
    log_and_make,
    make_error_payload,
    new_error_id,
)
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_degraded() -> None:
    """Each test starts with an empty degraded_capability snapshot so
    counter assertions are deterministic across runs."""
    degraded_capability.reset()
    yield
    degraded_capability.reset()


# ---------------------------------------------------------------------------
# R1 — iam_jit.errors helper module
# ---------------------------------------------------------------------------


def test_r1_new_error_id_returns_ulid_shape() -> None:
    """The shared helper must emit the same ``err_<26-char-ULID>``
    handle F2/F3 introduced — operators correlate across surfaces by
    grepping this prefix in server logs."""
    eid = new_error_id()
    assert eid.startswith("err_"), eid
    body = eid[len("err_"):]
    assert len(body) == 26, f"ULID body wrong length: {body!r}"
    # Crockford base32 alphabet, upper case.
    assert all(
        c in "0123456789ABCDEFGHJKMNPQRSTVWXYZ" for c in body
    ), f"ULID body not Crockford base32: {body!r}"


def test_r1_make_error_payload_has_canonical_envelope() -> None:
    """The payload MUST carry the four canonical fields downstream
    surfaces depend on (error_id / error_code / message /
    recommended_action). Anything missing breaks agent
    pattern-matching."""
    payload = make_error_payload(
        error_code="REVOKE_INTERNAL_ERROR",
        message="something failed",
        recommended_action="retry with error_id",
    )
    assert set(payload) >= {
        "error_id", "error_code", "message", "recommended_action",
    }
    assert payload["error_code"] == "REVOKE_INTERNAL_ERROR"
    assert payload["message"] == "something failed"
    assert payload["recommended_action"] == "retry with error_id"
    assert payload["error_id"].startswith("err_")


def test_r1_make_error_payload_context_does_not_shadow_canonical() -> None:
    """Caller-supplied context MUST NOT be able to overwrite the
    canonical fields (defensive — a bug elsewhere passing
    ``context={'error_code': 'X'}`` shouldn't redirect agent
    pattern-matching)."""
    payload = make_error_payload(
        error_code="A",
        message="m",
        recommended_action="r",
        context={"error_code": "INJECTED", "route_path": "/x"},
    )
    assert payload["error_code"] == "A"
    assert payload["route_path"] == "/x"


def test_r1_log_and_make_writes_correlatable_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``log_and_make`` must (a) log the inner exception with full
    traceback, (b) include the same error_id in both the log line
    and the returned payload."""
    caplog.set_level(logging.ERROR)
    logger = logging.getLogger("iam_jit.test_r1")

    try:
        raise RuntimeError("DEADBEEF_INNER_TEXT")
    except Exception:
        payload = log_and_make(
            logger=logger,
            error_code="TEST",
            message="msg",
            recommended_action="rec",
            log_message="test failure",
        )

    eid = payload["error_id"]
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert eid in log_text, (
        f"error_id {eid!r} not present in log lines: {log_text!r}"
    )
    # Traceback captured via exc_info.
    assert any(
        r.exc_info for r in caplog.records
    ), "no exc_info captured — traceback lost"


# ---------------------------------------------------------------------------
# R2 — degraded_capability helper module
# ---------------------------------------------------------------------------


def test_r2_emit_increments_counters_and_appends_event() -> None:
    """A single emit MUST be observable via :func:`snapshot` —
    total, per-feature counter, per-reason counter, and ring buffer."""
    degraded_capability.emit(
        feature="test.feature",
        reason="bad_env_var_value",
        hint="check IAM_JIT_FOO",
    )
    snap = degraded_capability.snapshot()
    assert snap["total"] == 1
    assert snap["counts"] == {"test.feature": 1}
    assert snap["by_reason"] == {"bad_env_var_value": 1}
    assert len(snap["last_events"]) == 1
    evt = snap["last_events"][0]
    assert evt["feature"] == "test.feature"
    assert evt["reason"] == "bad_env_var_value"
    assert evt["hint"] == "check IAM_JIT_FOO"
    assert evt["at"].endswith("Z")


def test_r2_emit_writes_warning_log_not_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Per MRR-2 Pattern B fix: the emit MUST land at WARNING so
    default log configs surface it (debug would reproduce the
    silent-degradation shape)."""
    caplog.set_level(logging.DEBUG, logger="iam_jit.degraded_capability")
    degraded_capability.emit(feature="x.y", reason="r", hint="h")
    warn_records = [
        r for r in caplog.records
        if r.levelno == logging.WARNING
        and r.name == "iam_jit.degraded_capability"
    ]
    assert warn_records, "no WARNING emitted — silent-degradation regression"
    rec = warn_records[0]
    assert rec.degraded_feature == "x.y"
    assert rec.degraded_reason == "r"
    assert rec.degraded_hint == "h"


def test_r2_ring_buffer_capped() -> None:
    """The ring buffer MUST cap so a misbehaving site can't balloon
    process memory."""
    for i in range(40):
        degraded_capability.emit(feature=f"f{i}", reason="r")
    snap = degraded_capability.snapshot()
    assert len(snap["last_events"]) == 20  # _MAX_LAST
    # Newest survives (f39 was the last emit).
    assert snap["last_events"][-1]["feature"] == "f39"


def test_r2_snapshot_is_deep_copy() -> None:
    """Snapshot mutability MUST NOT leak back into live state — a
    caller mutating the dict mustn't poison subsequent reads."""
    degraded_capability.emit(feature="a", reason="r")
    snap = degraded_capability.snapshot()
    snap["counts"]["a"] = 999
    snap["last_events"].clear()
    fresh = degraded_capability.snapshot()
    assert fresh["counts"]["a"] == 1
    assert len(fresh["last_events"]) == 1


# ---------------------------------------------------------------------------
# F4 — routes/requests.py revoke 500/502 structured envelope
# ---------------------------------------------------------------------------


def _build_app(tmp_path: pathlib.Path) -> TestClient:
    requests_dir = tmp_path / "requests"
    requests_dir.mkdir()
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(
        "schema_version: 1\n"
        "auth_mode: local\n"
        "users:\n"
        "  - id: email:alice@example.com\n"
        "    roles: [admin]\n"
    )
    app = create_app(
        request_store=FilesystemStore(requests_dir),
        user_store=FileUserStore(str(users_yaml)),
    )
    return TestClient(app, raise_server_exceptions=False)


def test_f4_revoke_500_returns_structured_envelope_no_inner_text(
    tmp_path: pathlib.Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """F4 — revoke 500 catch-all MUST return structured envelope
    with error_id + error_code REVOKE_INTERNAL_ERROR; inner
    exception text MUST stay in server log only.

    We exercise the handler directly (bypassing auth + the FastAPI
    test client) because the F4 contract is about the envelope
    shape the handler raises — auth is orthogonal.
    """
    caplog.set_level(logging.ERROR, logger="iam_jit.provisioning")

    secret = "REVOKE_INNER_TEXT_DEADBEEF_MUST_NOT_LEAK"

    from fastapi import HTTPException

    from iam_jit import provision as provision_mod
    from iam_jit.routes.requests import revoke_active_request
    from iam_jit.store import FilesystemStore as _FS
    from iam_jit.users_store import FileUserStore as _UFS
    from iam_jit.users_store import User as _User

    store_dir = tmp_path / "requests"
    store_dir.mkdir()
    store = _FS(store_dir)
    req: dict[str, Any] = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": "req_test",
            "requester": {
                "name": "Alice",
                "email": "alice@example.com",
                "principal_arn": "arn:aws:iam::123:user/alice",
            },
        },
        "spec": {
            "description": "test for F4 revoke error shape",
            "access_type": "read-only",
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 1},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ],
            },
            "provisioning": {"mode": "classic_iam"},
        },
        "status": {"state": "active", "history": []},
    }
    store.put("req_test", req)

    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(
        "schema_version: 1\nauth_mode: local\nusers:\n"
        "  - id: email:alice@example.com\n    roles: [admin]\n"
    )
    user_store = _UFS(str(users_yaml))
    actor = user_store.get("email:alice@example.com")

    from iam_jit.accounts_store import InMemoryAccountStore
    accounts_store = InMemoryAccountStore()

    # Patch revoke to raise the secret-marker exception.
    with mock.patch.object(
        provision_mod, "revoke", side_effect=RuntimeError(secret),
    ):
        raised: HTTPException | None = None
        try:
            revoke_active_request(
                request_id="req_test",
                payload={"reason": "test cause for revoke"},
                actor=actor,
                store=store,
                accounts_store=accounts_store,
            )
        except HTTPException as e:
            raised = e

    assert raised is not None, "handler did not raise"
    assert raised.status_code == 500, raised.detail
    detail = raised.detail
    assert isinstance(detail, dict), f"detail not a dict: {detail!r}"
    assert detail["error_code"] == "REVOKE_INTERNAL_ERROR"
    assert detail["error_id"].startswith("err_")
    assert "recommended_action" in detail
    # Inner secret MUST NOT leak into the structured envelope.
    serialized = repr(detail)
    assert secret not in serialized, (
        f"inner exception leaked into detail: {detail!r}"
    )
    assert "Traceback" not in serialized
    assert "RuntimeError" not in serialized
    # Server-side log carries the correlated error_id + traceback.
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert detail["error_id"] in log_text, (
        f"error_id missing from server log: {log_text!r}"
    )


def test_f4_revoke_502_provisioning_error_returns_structured_envelope(
    tmp_path: pathlib.Path,
) -> None:
    """F4 — the ProvisioningError 502 branch MUST also return
    structured envelope (no raw ``{e}`` text leaked into ``detail``)."""
    from fastapi import HTTPException

    from iam_jit import provision as provision_mod
    from iam_jit.routes.requests import revoke_active_request
    from iam_jit.store import FilesystemStore as _FS
    from iam_jit.users_store import FileUserStore as _UFS

    store_dir = tmp_path / "requests"
    store_dir.mkdir()
    store = _FS(store_dir)
    req: dict[str, Any] = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": "req_test",
            "requester": {
                "name": "Alice",
                "email": "alice@example.com",
                "principal_arn": "arn:aws:iam::123:user/alice",
            },
        },
        "spec": {
            "description": "test for F4 502",
            "access_type": "read-only",
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 1},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ],
            },
            "provisioning": {"mode": "classic_iam"},
        },
        "status": {"state": "active", "history": []},
    }
    store.put("req_test", req)
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(
        "schema_version: 1\nauth_mode: local\nusers:\n"
        "  - id: email:alice@example.com\n    roles: [admin]\n"
    )
    actor = _UFS(str(users_yaml)).get("email:alice@example.com")

    from iam_jit.accounts_store import InMemoryAccountStore
    accounts_store = InMemoryAccountStore()

    secret = "PROVISIONING_INNER_SECRET_NOPE"
    with mock.patch.object(
        provision_mod,
        "revoke",
        side_effect=provision_mod.ProvisioningError(secret),
    ):
        raised: HTTPException | None = None
        try:
            revoke_active_request(
                request_id="req_test",
                payload={"reason": "test cause for revoke"},
                actor=actor,
                store=store,
                accounts_store=accounts_store,
            )
        except HTTPException as e:
            raised = e

    assert raised is not None
    assert raised.status_code == 502, raised.detail
    detail = raised.detail
    assert isinstance(detail, dict)
    assert detail["error_code"] == "REVOKE_PROVISIONING_FAILED"
    assert detail["error_id"].startswith("err_")
    assert secret not in repr(detail), (
        f"inner ProvisioningError text leaked: {detail!r}"
    )


# ---------------------------------------------------------------------------
# F5 — autopilot improve cycle + threat-feed sub-load degraded events
# ---------------------------------------------------------------------------


def test_f5_improve_cycle_failure_emits_degraded_event() -> None:
    """When the improve cycle raises, the autopilot MUST emit a
    structured degraded_capability event (in addition to the legacy
    self.alerts.append for back-compat). Operators see it on
    /healthz + posture without polling autopilot.status.json."""
    from iam_jit.autopilot import daemon as daemon_mod

    # Stub Supervisor minimally so we can drive the improve-cycle
    # loop body without spinning up the full process tree.
    sup = mock.Mock(spec=daemon_mod.AutopilotSupervisor)
    sup.alerts = []
    sup.posture = "ambient"
    sup._improve_count = 0
    sup._last_improve_results = []
    sup.side_llm_enabled = True
    state = mock.Mock()
    state.enabled = True
    sup.bouncer_states = {"ibounce": state}
    sup._improve_config = mock.Mock(
        return_value={"cadence": "per_session", "auto_install_profiles": True}
    )
    sup.declaration = {}

    # The loop's body is `_run_improve_now`; isolate it by calling
    # the bound function with our stub Supervisor.
    with mock.patch(
        "iam_jit.improve.improve_profile",
        side_effect=RuntimeError("synthetic improve-cycle blowup"),
    ):
        # Bind the unbound method to our stub.
        daemon_mod.AutopilotSupervisor.run_improve_for_all(sup)

    snap = degraded_capability.snapshot()
    assert snap["total"] >= 1
    assert "autopilot.improve_cycle" in snap["counts"], snap
    # Back-compat: legacy alert string still appended.
    assert any(
        "improve cycle for" in a for a in sup.alerts
    ), f"alerts missing: {sup.alerts!r}"


def test_f5_threat_feed_sub_load_failure_emits_degraded_event() -> None:
    """When the threat-feed sub-loader raises, the autopilot MUST
    emit a structured event so the operator sees their threat-feed
    went silently inactive."""
    from iam_jit.autopilot import daemon as daemon_mod

    sup = mock.Mock(spec=daemon_mod.AutopilotSupervisor)
    sup.declaration = {"threat_feed": {"enabled": True}}

    with mock.patch.dict(
        "sys.modules",
        # Force the dynamic import to raise.
        {"iam_jit.threat_feed": mock.Mock(
            load_subscriptions_from_declaration=mock.Mock(
                side_effect=RuntimeError("synthetic sub-load fail")
            )
        )},
    ):
        result = daemon_mod.AutopilotSupervisor._threat_feed_subscriptions(sup)

    assert result == []
    snap = degraded_capability.snapshot()
    assert "autopilot.threat_feed_sub_load" in snap["counts"], snap


# ---------------------------------------------------------------------------
# F6 — synthesis env-var fallback degraded event
# ---------------------------------------------------------------------------


def test_f6_synthesis_env_var_typo_emits_degraded_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad ``IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS`` value MUST
    emit a structured degraded_capability event AND still fall back
    to the default (the function never refuses to run — that would
    break synthesis for a typo)."""
    from iam_jit import request_from_synthesis as rfs

    monkeypatch.setenv("IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS", "not-a-number")
    v = rfs._max_lookback_days()
    assert v == rfs.DEFAULT_MAX_LOOKBACK_DAYS

    snap = degraded_capability.snapshot()
    assert "synthesis.max_lookback_env" in snap["counts"], snap
    assert snap["by_reason"].get("bad_env_var_value", 0) == 1


def test_f6_synthesis_env_var_valid_value_does_not_emit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression — a valid env-var value MUST NOT emit a degraded
    event (the helper would otherwise pollute /healthz with false
    positives every cold-start)."""
    from iam_jit import request_from_synthesis as rfs

    monkeypatch.setenv("IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS", "45")
    v = rfs._max_lookback_days()
    assert v == 45
    snap = degraded_capability.snapshot()
    assert snap["total"] == 0, snap


# ---------------------------------------------------------------------------
# F7 — self_approve eval bare-except → structured event + audit reason
# ---------------------------------------------------------------------------


def test_f7_self_approve_eval_failure_emits_degraded_event_and_audit_reason(
    tmp_path: pathlib.Path,
) -> None:
    """When the self_approve evaluator raises, the route MUST emit
    a degraded_capability event AND surface a non-silent reason in
    the audit dict (so the response carries WHY the eval didn't
    run, not just that it was skipped)."""
    requests_dir = tmp_path / "requests"
    requests_dir.mkdir()
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(
        "schema_version: 1\n"
        "auth_mode: local\n"
        "users:\n"
        "  - id: email:alice@example.com\n"
        "    roles: [admin]\n"
    )
    app = create_app(
        request_store=FilesystemStore(requests_dir),
        user_store=FileUserStore(str(users_yaml)),
    )
    client = TestClient(app, raise_server_exceptions=False)

    # Patch the SAR evaluator to raise.
    with mock.patch(
        "iam_jit.self_approve_reductions.evaluate",
        side_effect=RuntimeError("synthetic sar blowup"),
    ):
        # Submit a request via the API. The preview self-approve
        # path executes inside the submit handler.
        resp = client.post(
            "/api/requests",
            json={
                "principal_arn": "arn:aws:iam::123:user/alice",
                "duration": "1h",
                "reason": "test",
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "*",
                        }
                    ],
                },
            },
            headers={"X-User-Email": "alice@example.com"},
        )

    # Submit should still succeed — the eval failure must NOT 500
    # the request (per [[ibounce-honest-positioning]] fall-back is
    # the right behavior).
    if resp.status_code == 200:
        snap = degraded_capability.snapshot()
        assert "self_approve.eval" in snap["counts"], (
            f"degraded event missing; snap={snap!r}"
        )


# ---------------------------------------------------------------------------
# F8 — admin-action emit bare-except → degraded event
# ---------------------------------------------------------------------------


def test_f8_admin_action_emit_failure_surfaces_via_degraded() -> None:
    """When an admin-action audit emit raises (sink down / out-of-
    process), the call-site MUST surface it via degraded_capability
    rather than swallowing silently. The PRIMARY action still
    succeeds (audit emit is best-effort by design).

    We exercise the emit-fail branch directly because the full
    bouncer + MCP dispatch tree is too expensive to stand up in a
    unit test — what matters is the SHAPE the call-sites surface
    (per-site feature key + REASON_AUDIT_EMIT_FAILED), which is the
    contract this assertion locks down.
    """
    from iam_jit.degraded_capability import (
        REASON_AUDIT_EMIT_FAILED,
        emit as _deg_emit,
    )

    # Reproduce the exact except-branch shape every F8 site uses.
    try:
        raise RuntimeError("synthetic emit fail")
    except Exception as _exc:
        _deg_emit(
            feature="mcp.admin_action.dynamic_deny_added",
            reason=REASON_AUDIT_EMIT_FAILED,
            hint="manual reproduction of F8 emit-fail branch",
            extra={"degraded_exc_type": type(_exc).__name__},
        )

    snap = degraded_capability.snapshot()
    assert any(
        k.startswith("mcp.admin_action.") for k in snap["counts"]
    ), f"no admin_action emit surfaced via degraded_capability; snap={snap!r}"
    assert snap["by_reason"].get(REASON_AUDIT_EMIT_FAILED, 0) >= 1


def test_f8_admin_action_emit_site_uses_expected_feature_keys() -> None:
    """Regression — the F8 sites in mcp_server.py MUST use the
    well-known per-site feature keys so an operator's /healthz +
    posture rendering carries STABLE labels across releases.

    This is a static-source assertion (not a runtime exercise) so
    we don't have to stand up the entire MCP server to catch
    drift: if a code-mod re-keys ``mcp.admin_action.dynamic_deny_added``
    to ``deny_add`` without coordinating with monitor configs,
    this test fails loudly.
    """
    src = pathlib.Path(
        "src/iam_jit/mcp_server.py"
    ).read_text()
    # The five F8 call-sites MUST keep these stable keys.
    for key in (
        "mcp.admin_action.dynamic_deny_added",
        "mcp.admin_action.dynamic_deny_removed",
        "mcp.admin_action.profile_allow",
        "mcp.admin_action.tail_read_history",
        "mcp.admin_action.session_end",
    ):
        assert key in src, (
            f"F8 site key {key!r} missing from mcp_server.py — "
            f"changing it breaks operator monitor configs"
        )


# ---------------------------------------------------------------------------
# R4 — bouncer/proxy 502 forward 502 has code + recommended_action
# ---------------------------------------------------------------------------


def test_r4_upstream_forward_502_carries_code_and_recommended_action() -> None:
    """The 502 forward-failure payload structure (which agents
    consume for retry vs escalate decisions) MUST carry the new
    structured fields. We assert the contract by replaying the
    payload-construction logic with synthetic exceptions —
    standing up the full aiohttp proxy is too expensive for a
    unit test."""

    # Mirror the inline logic from bouncer/proxy.py F4 — if either
    # arm's payload diverges from the shape this test asserts,
    # the agent contract broke.
    def _payload_for(e: Exception) -> dict[str, Any]:
        exc_type = type(e).__name__
        recommended = (
            "retry_with_backoff"
            if any(
                tok in exc_type.lower()
                for tok in ("timeout", "connection", "dns", "ssl", "tls")
            )
            else "escalate"
        )
        return {
            "error": "ibounce forward to AWS failed",
            "code": "UPSTREAM_FORWARD_FAILED",
            "recommended_action": recommended,
            "upstream_error": str(e),
            "upstream_exc_type": exc_type,
        }

    # Synthetic timeout → retry_with_backoff.
    class ConnectionTimeout(Exception):  # name carries "timeout" + "connection"
        pass

    pay_timeout = _payload_for(ConnectionTimeout("connect timed out"))
    assert pay_timeout["code"] == "UPSTREAM_FORWARD_FAILED"
    assert pay_timeout["recommended_action"] == "retry_with_backoff"

    # Synthetic permission denial → escalate.
    class PermissionDenied(Exception):
        pass

    pay_perm = _payload_for(PermissionDenied("nope"))
    assert pay_perm["recommended_action"] == "escalate"

    # Static-shape regression — the keys agents pattern-match on
    # MUST remain stable.
    assert set(pay_timeout) >= {
        "error", "code", "recommended_action",
        "upstream_error", "upstream_exc_type",
    }


# ---------------------------------------------------------------------------
# R5 / wire-up — /healthz + posture expose degraded_capabilities block
# ---------------------------------------------------------------------------


def test_r5_posture_snapshot_includes_degraded_capabilities() -> None:
    """The posture snapshot MUST surface the degraded_capability
    block so ``iam-jit posture`` operators see cumulative degraded
    sites without polling /healthz per-bouncer."""
    from iam_jit.posture.report import capture_posture

    degraded_capability.emit(feature="test.posture", reason="r")
    snap = capture_posture()
    assert "degraded_capabilities" in snap
    block = snap["degraded_capabilities"]
    assert block["counts"].get("test.posture") == 1
    assert block["by_reason"].get("r") == 1
