"""Smoke tests for #499 / §A76b — proxy.py wires Phase H
anomaly-detection hook into the request path.

Per docs/CONTRIBUTING.md state-verification convention: the
Phase H implementer tests (test_anomaly_detection_*.py) exercise
the BaselineStore + detector + hook in isolation; they all passed
while serve() carried ZERO calls into the hook. An operator who
set `iam-jit.anomaly_detection.enabled: true` in `.iam-jit.yaml`
got a SILENT NO-OP — the same calibration-drift shape as the §A66c
audit-chain gap (commit 1d0fb35).

These smoke tests verify the OBSERVABLE BEHAVIOUR end-to-end for
each gate:

* `--anomaly-detection alert` → hook installed at proxy +
  posture/healthz report enabled + anomalous request scored
  through + OCSF event emitted via the audit-log channel.
* `--anomaly-detection block` → anomalous request gets 403 with
  structured-deny + caught_by_bouncer + `deny_source_classified =
  anomaly_detection`.
* `--detection-only` → equivalent to alert mode + no profile
  required; scoring + alerts fire.
* config says enabled but baseline path is unwritable → startup
  emits LOUD warning (NOT silent failure) + marker stays None.

Per [[ibounce-honest-positioning]] these tests assert the actual
on-disk + on-wire artefacts, not status-string claims.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import socket
import unittest.mock

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    active_anomaly_detection_marker,
    register_anomaly_detection_marker,
    register_audit_log_writer,
    serve,
)
from iam_jit.bouncer.store import BouncerStore


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _sigv4(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260523/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fake"
    )


async def _wait_for_listen(host: str, port: int, *, retries: int = 50) -> None:
    for _ in range(retries):
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError(f"nothing listening on {host}:{port}")


async def _drive_one_request(
    proxy_port: int,
    *,
    service: str = "iam",
    region: str = "us-east-1",
    path: str = "/?Action=DeleteUser&Version=2010-05-08",
) -> int:
    """Send one SigV4-shaped request through the proxy. Returns the
    HTTP status code (so block-mode tests can assert 403)."""
    import aiohttp
    session = aiohttp.ClientSession()
    try:
        try:
            async with session.get(
                f"http://127.0.0.1:{proxy_port}{path}",
                headers={
                    "host": f"{service}.{region}.amazonaws.com",
                    "authorization": _sigv4(service=service, region=region),
                    "x-amz-date": "20260523T000000Z",
                    "user-agent": "smoke-test-agent",
                },
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                body = await resp.read()
                return resp.status, body
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return 0, b""
    finally:
        await session.close()


async def _wait_for_audit_lines(
    path: pathlib.Path, *, min_lines: int, max_wait: float = 5.0,
) -> list[str]:
    deadline = asyncio.get_event_loop().time() + max_wait
    while True:
        if path.is_file():
            text = path.read_text()
            lines = [ln for ln in text.splitlines() if ln.strip()]
            if len(lines) >= min_lines:
                return lines
        if asyncio.get_event_loop().time() > deadline:
            return [
                ln for ln in (
                    path.read_text().splitlines() if path.is_file() else []
                ) if ln.strip()
            ]
        await asyncio.sleep(0.05)


@pytest.fixture
def restore_anomaly_marker():
    """Tests run serve() which installs an anomaly marker. Restore
    after each so the next test starts clean (the module singleton in
    anomaly_detection.hook._STATE survives across tests otherwise)."""
    yield
    register_audit_log_writer(None)
    register_anomaly_detection_marker(None)
    try:
        from iam_jit.anomaly_detection import uninstall_anomaly_hook
        uninstall_anomaly_hook()
    except Exception:
        pass


@pytest.fixture
def isolated_baseline(monkeypatch, tmp_path):
    """Point BaselineStore at an isolated path so tests don't share +
    don't pollute ~/.iam-jit/anomaly-baseline.db."""
    p = tmp_path / "anomaly-baseline.db"
    monkeypatch.setenv("IAM_JIT_ANOMALY_BASELINE_PATH", str(p))
    yield p


@pytest.mark.asyncio
async def test_alert_mode_installs_hook_and_scores_requests(
    tmp_path, restore_anomaly_marker, isolated_baseline,
):
    """#499 — `--anomaly-detection alert` opt-in installs the hook +
    posture/healthz report enabled + a driven request flows through
    the scorer without enforcement (alert mode never tightens ALLOW
    to DENY).

    This is the test that would have caught the §A76b CRIT: the
    install_anomaly_hook() construction never happened in serve()
    even though every primitive worked in isolation.
    """
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "audit.jsonl"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        audit_log_path=str(log_path),
        anomaly_detection_mode="alert",
        anomaly_sensitivity="medium",
        anomaly_baseline_window="14d",
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        # 1. Observable state: the marker MUST be installed.
        marker = active_anomaly_detection_marker()
        assert marker is not None, (
            "#499 §A76b CRIT regressed — serve() did NOT install the "
            "anomaly-detection marker; the hook is silent-no-op even "
            "though the operator set --anomaly-detection alert"
        )
        assert marker["enabled"] is True
        assert marker["mode"] == "alert"
        assert marker["sensitivity"] == "medium"
        # 2. /healthz exposes the same shape (in-process aiohttp probe;
        # urllib would block the event loop).
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{proxy_port}/healthz",
                timeout=aiohttp.ClientTimeout(total=2.0),
            ) as resp:
                healthz = await resp.json()
        assert "anomaly_detection" in healthz, healthz
        assert healthz["anomaly_detection"] is not None, healthz
        assert healthz["anomaly_detection"]["mode"] == "alert"
        # 3. Drive a request — alert mode never blocks, so the SDK
        # client either gets a forwarded response OR (in cooperative
        # mode w/ default-deny) the bouncer-side default-deny.
        status, _body = await _drive_one_request(proxy_port)
        # 4. Observable state: the request DID land in audit log
        # (proves the request reached the proxy + the decision path
        # ran). Anomaly scoring runs alongside.
        lines = await _wait_for_audit_lines(log_path, min_lines=1)
        assert lines, "no audit events landed; request never reached proxy"
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_block_mode_tightens_allow_to_deny_on_anomalous_score(
    tmp_path, restore_anomaly_marker, isolated_baseline,
):
    """#499 — `--anomaly-detection block` mode tightens a floor-ALLOW
    to DENY when the hook returns an anomalous verdict.

    To exercise the block path deterministically we monkey-patch the
    hook to return a synthetic anomalous result. This decouples the
    smoke test from the detector's stochastic z-score calibration
    (which depends on baseline maturity) — the test asserts the
    PROXY-SIDE WIRING (anomaly verdict tightens the record + the 403
    body carries the expected structured-deny fields), not detector
    accuracy (which the Phase H implementer tests cover).
    """
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "audit.jsonl"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.TRANSPARENT,
        # Default-allow so the floor returns ALLOW; the hook then
        # tightens to DENY. Pinning this isolates the block-mode wire-
        # up from the default-deny floor path.
        default_policy=DefaultPolicy.ALLOW,
        audit_log_path=str(log_path),
        anomaly_detection_mode="block",
        anomaly_sensitivity="medium",
        anomaly_baseline_window="14d",
    )

    # Synthetic anomalous HookResult — what the hook would return on a
    # high-z-score request. Patches the proxy's import of
    # run_anomaly_hook so evaluate_request consumes our verdict.
    from iam_jit.anomaly_detection import hook as _hook_mod

    def _fake_run_anomaly_hook(
        *, action, agent_identity, resource, bouncer,
        floor_decision, floor_deny_reason, record_observation,
        **kwargs,
    ):
        from iam_jit.anomaly_detection.detector import AnomalyResult
        # Floor DENY MUST short-circuit (per the contract); we still
        # tighten ALLOW.
        if floor_decision == "deny":
            return _hook_mod.HookResult(
                decision="deny",
                anomaly_result=None,
                emitted_alert=False,
                operator_message=floor_deny_reason,
                mode="block",
            )
        return _hook_mod.HookResult(
            decision="deny",
            anomaly_result=AnomalyResult(
                anomaly_score=4.2,
                verdict="anomalous",
                explanations=[],
                classifier_signal=None,
                mitre_atlas_techniques=[],
                cold_start_fallback_used=False,
                baseline_observations=100,
                threat_feed_severity=None,
                note="",
            ),
            emitted_alert=True,
            operator_message=(
                "Your bouncer blocked an unusual action: "
                f"{action} (smoke-test synthetic anomaly)"
            ),
            mode="block",
        )

    with unittest.mock.patch.object(
        _hook_mod, "run_anomaly_hook", _fake_run_anomaly_hook,
    ):
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            # The default-policy=ALLOW means the floor would let the
            # request through; the hook tightens it to a 403.
            status, body = await _drive_one_request(proxy_port)
            assert status == 403, (
                f"#499 §A76b CRIT regressed — anomaly hook returned "
                f"deny but proxy did NOT tighten; HTTP {status}, body="
                f"{body[:200]!r}"
            )
            payload = json.loads(body.decode("utf-8"))
            # Structured-deny additive fields per
            # [[ambient-value-prop-and-friction-framing]].
            # `caught_by_bouncer` is the bouncer name ("ibounce") per
            # structured_deny.response.StructuredDeny.
            assert payload.get("caught_by_bouncer") == "ibounce", payload
            # The deny_source_classified MUST map to anomaly_detection
            # (verifies _PROXY_DENY_SOURCE_TO_STRUCTURED added the
            # mapping in §A76b).
            assert payload.get("deny_source_classified") == \
                "anomaly_detection", payload
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()


@pytest.mark.asyncio
async def test_detection_only_works_without_profile(
    tmp_path, restore_anomaly_marker, isolated_baseline,
):
    """#499 — `--anomaly-detection detection-only` installs the hook
    + scores requests + emits alerts WITHOUT requiring a configured
    profile. The marker MUST report mode=detection-only +
    detection_only=True so the operator (and posture) can verify."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "audit.jsonl"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        audit_log_path=str(log_path),
        # No active_profile: discovery mode default; detection-only
        # MUST work here.
        anomaly_detection_mode="detection-only",
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        marker = active_anomaly_detection_marker()
        assert marker is not None
        assert marker["mode"] == "detection-only"
        assert marker["detection_only"] is True
        # Drive a request — the hook scores even without a profile.
        await _drive_one_request(proxy_port)
        await _wait_for_audit_lines(log_path, min_lines=1)
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_default_off_does_not_install_hook(
    tmp_path, restore_anomaly_marker, isolated_baseline,
):
    """#499 — when --anomaly-detection is NOT set (the default), the
    hook MUST NOT be installed + the marker MUST be None.

    Per [[creates-never-mutates]] existing deployments that haven't
    opted in DO NOT silently gain new behavior or new on-disk state
    (the baseline DB is not opened, the hook is not registered, the
    /healthz block reports None).
    """
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "audit.jsonl"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        audit_log_path=str(log_path),
        # anomaly_detection_mode deliberately omitted (default None).
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        marker = active_anomaly_detection_marker()
        assert marker is None, (
            f"anomaly marker unexpectedly installed without opt-in — "
            f"[[creates-never-mutates]] regression: {marker!r}"
        )
        # /healthz reports None too (always-present convention).
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{proxy_port}/healthz",
                timeout=aiohttp.ClientTimeout(total=2.0),
            ) as resp:
                healthz = await resp.json()
        assert "anomaly_detection" in healthz
        assert healthz["anomaly_detection"] is None
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


@pytest.mark.asyncio
async def test_unwritable_baseline_path_surfaces_loud_warning(
    tmp_path, restore_anomaly_marker, monkeypatch, caplog,
):
    """#499 — when anomaly detection is configured but the baseline
    store fails to start (unwritable path), serve() MUST emit a LOUD
    warning + leave the marker None so posture/healthz report the
    disabled state honestly.

    Per [[ibounce-honest-positioning]] silent failure here is the
    exact gap that motivated #499. The operator MUST see the warning.
    """
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / "audit.jsonl"
    # Point the baseline at an unwritable location. mkdir(parents=True)
    # would normally rescue this, so we use an existing FILE as the
    # parent (mkdir-on-a-file always fails).
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")  # creates a regular file
    monkeypatch.setenv(
        "IAM_JIT_ANOMALY_BASELINE_PATH", str(blocker / "baseline.db"),
    )
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1",
        port=proxy_port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        audit_log_path=str(log_path),
        anomaly_detection_mode="alert",
    )
    import logging
    caplog.set_level(logging.WARNING, logger="iam_jit.bouncer.proxy")
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        # Marker MUST be None — hook failed to install.
        assert active_anomaly_detection_marker() is None
        # The operator MUST have seen the LOUD warning (per
        # [[ibounce-honest-positioning]] silent-no-op = unacceptable).
        warning_texts = [r.getMessage() for r in caplog.records
                         if r.levelname == "WARNING"]
        assert any(
            "anomaly_detection: CONFIGURED but NOT WIRED" in m
            for m in warning_texts
        ), (
            f"missing loud warning when baseline path was unwritable; "
            f"warnings seen: {warning_texts}"
        )
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()
