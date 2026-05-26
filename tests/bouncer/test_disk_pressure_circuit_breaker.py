"""Tests for the #424 / §A63 disk-pressure circuit-breaker policy layer.

Per [[deliberate-feature-completion]] every component of the §A63 spec
ships end-to-end:

  1. The disk_pressure_evaluate_and_react primitive (mode-specific reactions).
  2. The 60s periodic check loop (integration with serve()).
  3. The pause-requests refusal in _handle_request (proxy hot-path).
  4. The /healthz audit_log block (monitoring surface).
  5. The --stop-on-disk-critical alias = pause-requests mode (CLI).
  6. The OCSF disk_pressure.transition admin-action event.
  7. The posture integration (cross-product surface).
  8. The PRODUCTION-LOG-STORAGE.md doc-truth-up (#454).

These tests use the existing `statvfs` injection seam on
:func:`disk_status` to simulate disk-pressure transitions without
actually filling a filesystem. Per [[creates-never-mutates]] the
tests are additive — they don't redesign the rotation surface
shipped under #311.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import pathlib
import socket
from typing import Any
from unittest.mock import patch

import pytest

from iam_jit.bouncer.audit_export import (
    ADMIN_ACTION_DISK_PRESSURE_TRANSITION,
    DEFAULT_DISK_PRESSURE_MODE,
    DISK_PRESSURE_MODE_ARCHIVE_AND_PURGE,
    DISK_PRESSURE_MODE_PAUSE_REQUESTS,
    DISK_PRESSURE_MODE_ROTATE_AGGRESSIVELY,
    DiskPressureState,
    KNOWN_DISK_PRESSURE_MODES,
    PAUSE_REQUESTS_REFUSAL_REASON_TEMPLATE,
    disk_pressure_evaluate_and_react,
    healthz_audit_log_block,
    normalize_disk_pressure_mode,
)
from iam_jit.bouncer.audit_export.disk_pressure import (
    _compute_refuse_requests,
    _compute_status,
    _count_archives,
    _drop_oldest_archives,
    _resolve_log_dir,
)
from iam_jit.bouncer.audit_export.rotation import DiskStatus, disk_status
from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    active_disk_pressure_state,
    register_disk_pressure_state,
    serve,
)
from iam_jit.bouncer.store import BouncerStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


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


def _statvfs_at_pct(used_pct: float) -> tuple[int, int, int]:
    """Build a statvfs 3-tuple (total, used, free) that yields the
    desired used_pct under :func:`disk_status`."""
    total = 1_000_000
    used = int(total * used_pct / 100.0)
    return (total, used, total - used)


def _populate_archives(
    log_dir: pathlib.Path, count: int, *, prefix: str = "jsonl",
) -> list[pathlib.Path]:
    """Drop N rotated-style audit-*.jsonl.gz files in log_dir with
    increasing mtime so _drop_oldest_archives drops them in
    predictable order."""
    log_dir.mkdir(parents=True, exist_ok=True)
    suffix = ".jsonl.gz" if prefix == "jsonl" else ".db.gz"
    paths: list[pathlib.Path] = []
    for i in range(count):
        p = log_dir / f"audit-2026-05-23-1{i:02d}000{suffix}"
        with gzip.open(p, "wb") as f:
            f.write(b'{"event":' + str(i).encode() + b"}\n")
        # Stagger mtime so oldest goes first.
        import os
        os.utime(p, (1000 + i, 1000 + i))
        paths.append(p)
    return paths


# ---------------------------------------------------------------------------
# Unit tests: policy module primitives
# ---------------------------------------------------------------------------


def test_normalize_disk_pressure_mode_accepts_all_three() -> None:
    """All three documented mode strings must round-trip through
    normalize without ValueError."""
    for mode in KNOWN_DISK_PRESSURE_MODES:
        assert normalize_disk_pressure_mode(mode) == mode


def test_normalize_disk_pressure_mode_defaults_when_empty() -> None:
    """None + empty string + whitespace fall through to the
    compliance-heavy default."""
    assert normalize_disk_pressure_mode(None) == DEFAULT_DISK_PRESSURE_MODE
    assert normalize_disk_pressure_mode("") == DEFAULT_DISK_PRESSURE_MODE
    assert normalize_disk_pressure_mode(
        DEFAULT_DISK_PRESSURE_MODE
    ) == "pause-requests"


def test_normalize_disk_pressure_mode_rejects_typo() -> None:
    """A typo in apply-config YAML must fail loudly so the operator
    doesn't silently fall through to the default."""
    with pytest.raises(ValueError) as exc:
        normalize_disk_pressure_mode("pause_requests")  # underscore not dash
    assert "pause_requests" in str(exc.value)
    assert "pause-requests" in str(exc.value)


def test_compute_status_emergency_above_emergency_pct() -> None:
    snap = DiskStatus(
        status="critical", reason="x", used_pct=98.5,
        path="/tmp/x",
    )
    assert _compute_status(
        snap, warn_pct=85, crit_pct=95, emergency_pct=98,
    ) == "emergency"


def test_compute_status_critical_between_crit_and_emergency() -> None:
    snap = DiskStatus(
        status="critical", reason="x", used_pct=96.0,
        path="/tmp/x",
    )
    assert _compute_status(
        snap, warn_pct=85, crit_pct=95, emergency_pct=98,
    ) == "critical"


def test_compute_status_degraded_between_warn_and_crit() -> None:
    snap = DiskStatus(
        status="degraded", reason="x", used_pct=90.0,
        path="/tmp/x",
    )
    assert _compute_status(
        snap, warn_pct=85, crit_pct=95, emergency_pct=98,
    ) == "degraded"


def test_compute_status_ok_below_warn() -> None:
    snap = DiskStatus(
        status="ok", reason="x", used_pct=40.0,
        path="/tmp/x",
    )
    assert _compute_status(
        snap, warn_pct=85, crit_pct=95, emergency_pct=98,
    ) == "ok"


def test_compute_refuse_requests_pause_requests_at_critical() -> None:
    """Per the spec, pause-requests refuses at critical OR emergency
    and ONLY those two states."""
    assert _compute_refuse_requests(
        DISK_PRESSURE_MODE_PAUSE_REQUESTS, "critical"
    ) is True
    assert _compute_refuse_requests(
        DISK_PRESSURE_MODE_PAUSE_REQUESTS, "emergency"
    ) is True
    assert _compute_refuse_requests(
        DISK_PRESSURE_MODE_PAUSE_REQUESTS, "degraded"
    ) is False
    assert _compute_refuse_requests(
        DISK_PRESSURE_MODE_PAUSE_REQUESTS, "ok"
    ) is False


def test_compute_refuse_requests_rotate_and_archive_never_refuse() -> None:
    """rotate-aggressively + archive-and-purge react via rotation, not
    refusal. The /healthz block still shows critical / emergency in
    these modes but no 503 returns from the proxy hot path."""
    for mode in (
        DISK_PRESSURE_MODE_ROTATE_AGGRESSIVELY,
        DISK_PRESSURE_MODE_ARCHIVE_AND_PURGE,
    ):
        for status in ("ok", "degraded", "critical", "emergency"):
            assert _compute_refuse_requests(mode, status) is False, (
                f"mode={mode} status={status} unexpectedly refused"
            )


def test_resolve_log_dir_returns_parent_of_file_path() -> None:
    assert _resolve_log_dir("/tmp/foo/audit.jsonl") == "/tmp/foo"
    assert _resolve_log_dir(None) is None
    assert _resolve_log_dir("") is None


def test_count_archives_counts_only_rotated_files(tmp_path: pathlib.Path) -> None:
    # Active log NOT counted; rotated archives counted.
    (tmp_path / "audit.jsonl").write_text("active log\n")
    (tmp_path / "audit-2026-05-23-100000.jsonl.gz").write_bytes(b"\x1f\x8b\x08")
    (tmp_path / "audit-2026-05-23-110000.db.gz").write_bytes(b"\x1f\x8b\x08")
    (tmp_path / "random.txt").write_text("not an archive\n")
    count, total = _count_archives(str(tmp_path))
    assert count == 2
    assert total > 0


# ---------------------------------------------------------------------------
# Mode-behavior tests (the primary spec assertions)
# ---------------------------------------------------------------------------


def test_disk_pressure_mode_pause_requests_refuses_when_critical(
    tmp_path: pathlib.Path,
) -> None:
    """Per §A63 spec assertion 1: pause-requests flips
    state.refuse_requests=True at critical so the proxy hot path
    returns 503."""
    state = DiskPressureState(
        mode=DISK_PRESSURE_MODE_PAUSE_REQUESTS,
        log_dir=str(tmp_path),
        warn_pct=85, crit_pct=95, emergency_pct=98,
    )
    out = disk_pressure_evaluate_and_react(
        state,
        statvfs=_statvfs_at_pct(96.0),
    )
    assert out.current_status == "critical"
    assert out.refuse_requests is True
    assert "refusing new agent requests" in (out.last_action_taken or "")
    assert out.transitions_count == 1


def test_disk_pressure_mode_rotate_aggressively_drops_oldest_when_critical(
    tmp_path: pathlib.Path,
) -> None:
    """Per §A63 spec assertion 2: rotate-aggressively calls
    _drop_oldest_archives at critical. The test directory has 5
    archives; after the tick, archives count should be < 5 OR the
    last_action_taken should name the count dropped."""
    archives = _populate_archives(tmp_path, 5)
    assert len(archives) == 5
    state = DiskPressureState(
        mode=DISK_PRESSURE_MODE_ROTATE_AGGRESSIVELY,
        log_dir=str(tmp_path),
        warn_pct=85, crit_pct=95, emergency_pct=98,
    )
    # Force critical status; the dropper re-stats per iteration so
    # we need the statvfs to stay critical across drops (use a fixed
    # 96% always-critical view to exercise the loop's all-drop path).
    out = disk_pressure_evaluate_and_react(
        state,
        statvfs=_statvfs_at_pct(96.0),
    )
    assert out.current_status == "critical"
    assert out.refuse_requests is False, "rotate-aggressively must NOT refuse"
    # The dropper attempts to drop until headroom returns; with our
    # static statvfs it drops ALL archives. last_action_taken names
    # the count.
    assert out.last_action_taken is not None
    assert "dropped" in out.last_action_taken
    # Re-stat directly — all archives should be gone since statvfs
    # stayed critical.
    remaining_count, _ = _count_archives(str(tmp_path))
    assert remaining_count == 0, (
        f"rotate-aggressively should have dropped ALL archives under "
        f"sustained critical; {remaining_count} remain"
    )


def test_disk_pressure_mode_archive_and_purge_ships_to_s3_when_critical(
    tmp_path: pathlib.Path,
) -> None:
    """Per §A63 spec assertion 3: archive-and-purge drops oldest +
    emits operator hint that the #317 object-storage sink should ship
    before the next tick. The hint surfaces via last_action_taken;
    the actual S3 upload is decoupled (operator wires
    --audit-object-storage-* independently)."""
    _populate_archives(tmp_path, 4)
    state = DiskPressureState(
        mode=DISK_PRESSURE_MODE_ARCHIVE_AND_PURGE,
        log_dir=str(tmp_path),
        warn_pct=85, crit_pct=95, emergency_pct=98,
    )
    out = disk_pressure_evaluate_and_react(
        state,
        statvfs=_statvfs_at_pct(97.0),
    )
    assert out.current_status == "critical"
    assert out.refuse_requests is False
    assert "archive-and-purge" in (out.last_action_taken or "")
    assert "object-storage sink" in (out.last_action_taken or "")


# ---------------------------------------------------------------------------
# OCSF admin-action transition event
# ---------------------------------------------------------------------------


def test_disk_pressure_transition_emits_admin_action_ocsf_event(
    tmp_path: pathlib.Path,
) -> None:
    """Per §A63 spec assertion 4: each status transition emits an
    OCSF admin-action event with kind=disk_pressure.transition so
    SIEM dashboards see when the breaker fired."""
    events: list[dict] = []

    def _capture(evt: dict) -> None:
        events.append(evt)

    state = DiskPressureState(
        mode=DISK_PRESSURE_MODE_PAUSE_REQUESTS,
        log_dir=str(tmp_path),
        warn_pct=85, crit_pct=95, emergency_pct=98,
    )
    # First tick at ok — no transition (current_status starts at "ok").
    disk_pressure_evaluate_and_react(
        state, emit=_capture, statvfs=_statvfs_at_pct(40.0),
    )
    assert events == []
    # Second tick at critical — transitions ok -> critical.
    disk_pressure_evaluate_and_react(
        state, emit=_capture, statvfs=_statvfs_at_pct(96.0),
    )
    assert len(events) == 1
    evt = events[0]
    assert evt["class_uid"] == 6003, "must be OCSF API Activity class"
    unmapped = evt.get("unmapped", {}).get("iam_jit", {})
    aa = unmapped.get("admin_action", {})
    assert aa.get("kind") == ADMIN_ACTION_DISK_PRESSURE_TRANSITION
    # The target carries the from/to status pair.
    extra = aa.get("target", {}).get("extra", {})
    assert extra.get("from_status") == "ok"
    assert extra.get("to_status") == "critical"
    assert extra.get("mode") == DISK_PRESSURE_MODE_PAUSE_REQUESTS
    # Third tick back to ok — emits the recovery transition.
    disk_pressure_evaluate_and_react(
        state, emit=_capture, statvfs=_statvfs_at_pct(40.0),
    )
    assert len(events) == 2
    assert events[1]["unmapped"]["iam_jit"]["admin_action"][
        "target"]["extra"]["to_status"] == "ok"


def test_disk_pressure_emit_failure_does_not_break_tick(
    tmp_path: pathlib.Path,
) -> None:
    """Per [[deliberate-feature-completion]] fail-soft: an emit that
    raises must not propagate out of the policy tick. State still
    updates; the operator sees the transition in /healthz even when
    the SIEM emit fails."""
    def _broken_emit(_evt: dict) -> None:
        raise RuntimeError("emit channel down")

    state = DiskPressureState(
        mode=DISK_PRESSURE_MODE_PAUSE_REQUESTS,
        log_dir=str(tmp_path),
        warn_pct=85, crit_pct=95, emergency_pct=98,
    )
    out = disk_pressure_evaluate_and_react(
        state, emit=_broken_emit, statvfs=_statvfs_at_pct(96.0),
    )
    assert out.current_status == "critical"
    assert out.transitions_count == 1


# ---------------------------------------------------------------------------
# 60s periodic loop integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disk_pressure_60s_check_loop_periodic_invocation(
    tmp_path: pathlib.Path,
) -> None:
    """Per §A63 spec assertion 5: the periodic loop runs on a
    DISK_PRESSURE_CHECK_INTERVAL_SECONDS cadence (60s in production).
    The test asserts the INITIAL probe fires at serve() start so
    /healthz is honest immediately (operators don't see 60s of
    "unknown" after startup)."""
    audit_log_path = tmp_path / "audit" / "ibounce.jsonl"
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    audit_log_path.write_text("")
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        audit_log_path=str(audit_log_path),
        disk_pressure_mode=DISK_PRESSURE_MODE_PAUSE_REQUESTS,
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        # Give the initial-probe coroutine a moment to fire.
        await asyncio.sleep(0.2)
        state = active_disk_pressure_state()
        assert state is not None, (
            "disk-pressure state must be installed when audit_log_path is set"
        )
        # Initial probe should have populated last_observed.
        assert state.last_check_unix > 0
        assert state.last_observed is not None
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()
        # Clean up the state holder so other tests don't see stale.
        register_disk_pressure_state(None)


# ---------------------------------------------------------------------------
# --stop-on-disk-critical alias
# ---------------------------------------------------------------------------


def test_stop_on_disk_critical_flag_equivalent_to_pause_requests_mode() -> None:
    """Per §A63 spec + #455 ship-the-ghost-flag: --stop-on-disk-critical
    is a one-flag alias for --disk-pressure-mode=pause-requests. When
    present it overrides --disk-pressure-mode so operator intent is
    unambiguous."""
    from click.testing import CliRunner
    from iam_jit.bouncer_cli import main as bouncer_main

    runner = CliRunner()
    # --help shows the flag exists + is documented as the alias.
    result = runner.invoke(bouncer_main, ["run", "--help"])
    assert result.exit_code == 0, (
        f"bouncer run --help failed: {result.output}"
    )
    assert "--stop-on-disk-critical" in result.output
    assert "pause-requests" in result.output
    # And the canonical mode flag is also present.
    assert "--disk-pressure-mode" in result.output


# ---------------------------------------------------------------------------
# /healthz audit_log block
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_healthz_includes_audit_log_block(tmp_path: pathlib.Path) -> None:
    """Per §A63 spec assertion 6: /healthz always includes an
    audit_log block. When the bouncer is configured with
    --audit-log-path the block has real disk telemetry; otherwise it
    surfaces status=ok with disk_free_pct=null so monitoring parsers
    can branch on a single field.

    #625 — patch shutil.disk_usage to return a healthy (50%-used)
    snapshot so the test is stable regardless of the CI/dev-machine
    disk fill level.  Without the patch the initial probe fires against
    the real filesystem; on machines at or above the default crit_pct
    (95 %) the probe sets refuse_requests=True and the assertion fails.
    The contract under test is the /healthz block shape, not real-disk
    behaviour — real-disk reactions are covered by the mode-behaviour
    tests above which use the statvfs injection seam directly.
    """
    import collections
    _safe_usage = collections.namedtuple("usage", ["total", "used", "free"])(
        total=1_000_000,
        used=500_000,
        free=500_000,
    )
    audit_log_path = tmp_path / "audit" / "ibounce.jsonl"
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    audit_log_path.write_text("")
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        audit_log_path=str(audit_log_path),
        disk_pressure_mode=DISK_PRESSURE_MODE_PAUSE_REQUESTS,
    )
    with patch(
        "iam_jit.bouncer.audit_export.rotation.shutil.disk_usage",
        return_value=_safe_usage,
    ):
        task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", port)
            await asyncio.sleep(0.2)  # let initial probe fire
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{port}/healthz"
                ) as resp:
                    body = await resp.json()
            assert "audit_log" in body
            block = body["audit_log"]
            assert block["status"] in ("ok", "degraded", "critical", "emergency")
            assert block["disk_pressure_mode"] == DISK_PRESSURE_MODE_PAUSE_REQUESTS
            assert block["warn_pct"] == 85
            assert block["crit_pct"] == 95
            assert block["emergency_pct"] == 98
            assert block["path"] is not None
            assert block["refuse_requests"] is False
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            store.close()
            register_disk_pressure_state(None)


@pytest.mark.asyncio
async def test_healthz_audit_log_block_absent_when_no_log_path(
    tmp_path: pathlib.Path,
) -> None:
    """When audit logging is disabled, /healthz still surfaces the
    audit_log block (always-present convention) but with null disk
    telemetry + status=ok + a 'not configured' reason so monitoring
    parsers don't have to branch on block-presence."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(host="127.0.0.1", port=port)
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        await asyncio.sleep(0.1)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz"
            ) as resp:
                body = await resp.json()
        assert "audit_log" in body
        block = body["audit_log"]
        assert block["status"] == "ok"
        assert block["disk_free_pct"] is None
        assert block["disk_pressure_mode"] is None
        assert "not configured" in (block["reason"] or "")
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()
        register_disk_pressure_state(None)


def test_healthz_audit_log_status_transitions_warn_critical_emergency(
    tmp_path: pathlib.Path,
) -> None:
    """Per §A63 spec assertion 7: the /healthz block surfaces each
    state correctly across the four-tier scale. Direct call into
    healthz_audit_log_block + DiskPressureState avoids the serve()
    plumbing for a focused assertion."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    state = DiskPressureState(
        mode=DISK_PRESSURE_MODE_PAUSE_REQUESTS,
        log_dir=str(audit_dir),
        warn_pct=85, crit_pct=95, emergency_pct=98,
    )
    for used, expected in (
        (40.0, "ok"),
        (90.0, "degraded"),
        (96.0, "critical"),
        (99.0, "emergency"),
    ):
        # Reset transition count so each loop iteration is independent.
        state.current_status = "ok"
        out = disk_pressure_evaluate_and_react(
            state, statvfs=_statvfs_at_pct(used),
        )
        block = healthz_audit_log_block(out)
        assert block["status"] == expected, (
            f"at {used}% used, expected status={expected}, "
            f"got {block['status']}"
        )
        assert block["used_pct"] == round(used, 2)
        assert block["disk_free_pct"] == round(100.0 - used, 2)


# ---------------------------------------------------------------------------
# Proxy hot-path refusal (smoke 1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pause_requests_mode_refuses_proxy_request_at_critical(
    tmp_path: pathlib.Path,
) -> None:
    """End-to-end: in pause-requests mode, after the state flips to
    critical the proxy returns 503 with the
    PAUSE_REQUESTS_REFUSAL_REASON_TEMPLATE body. /healthz remains
    queryable so the operator can investigate."""
    audit_log_path = tmp_path / "audit" / "ibounce.jsonl"
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    audit_log_path.write_text("")
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        audit_log_path=str(audit_log_path),
        disk_pressure_mode=DISK_PRESSURE_MODE_PAUSE_REQUESTS,
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        await asyncio.sleep(0.2)
        # Force the state into refuse_requests=True directly (the
        # 60s loop would take a minute; we just flip the flag).
        state = active_disk_pressure_state()
        assert state is not None
        state.refuse_requests = True
        state.current_status = "critical"
        state.last_observed = DiskStatus(
            status="critical",
            reason="disk usage 96.5% >= critical threshold 95%",
            used_pct=96.5,
            path=str(audit_log_path.parent),
        )

        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/some/aws/path"
            ) as resp:
                assert resp.status == 503
                body = await resp.json()
                assert body["caught_by_bouncer"] is True
                assert "disk pressure" in body["deny_reason"].lower()
                assert body["deny_source"] == "disk_pressure"
                assert body["disk_pressure_mode"] == "pause-requests"
                assert "rotate-aggressively" in body["remediation"]
                assert resp.headers.get("retry-after") == "60"
            # /healthz still works.
            async with session.get(
                f"http://127.0.0.1:{port}/healthz"
            ) as resp:
                # Disk-critical flips /healthz to 503 (matches the
                # liveness-probe semantics in §A63).
                assert resp.status == 503
                body = await resp.json()
                assert body["audit_log"]["status"] == "critical"
                assert body["audit_log"]["refuse_requests"] is True
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()
        register_disk_pressure_state(None)


# ---------------------------------------------------------------------------
# Posture surface
# ---------------------------------------------------------------------------


def test_posture_surfaces_disk_pressure_state_per_bouncer(
    tmp_path: pathlib.Path,
) -> None:
    """Per §A63 spec assertion 8: `iam-jit posture` surfaces disk-
    pressure state per bouncer + recommends action if approaching
    critical. Uses an in-process DiskPressureState (no live serve())
    + invokes detect_ibounce directly."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    state = DiskPressureState(
        mode=DISK_PRESSURE_MODE_ROTATE_AGGRESSIVELY,
        log_dir=str(audit_dir),
        warn_pct=85, crit_pct=95, emergency_pct=98,
    )
    # Tick to populate last_observed at the degraded threshold so the
    # posture recommendation surfaces.
    disk_pressure_evaluate_and_react(
        state, statvfs=_statvfs_at_pct(90.0),
    )
    register_disk_pressure_state(state)
    try:
        from iam_jit.posture.bouncers import detect_ibounce
        block = detect_ibounce()
        assert "disk_pressure" in block
        dp = block["disk_pressure"]
        assert dp is not None
        assert dp["status"] == "degraded"
        assert dp["disk_pressure_mode"] == "rotate-aggressively"
        # Recommendation should surface at degraded.
        assert block.get("disk_pressure_recommendation") is not None
        assert "approaching threshold" in block["disk_pressure_recommendation"]
    finally:
        register_disk_pressure_state(None)


def test_posture_renders_disk_pressure_line(tmp_path: pathlib.Path) -> None:
    """The posture renderer surfaces the disk-pressure line per
    bouncer when the snapshot block carries it."""
    from iam_jit.posture.report import render_posture_human

    snapshot = {
        "snapshot_schema_version": 1,
        "captured_at": "2026-05-23T00:00:00Z",
        "bouncers": {
            "ibounce": {
                "running": True,
                "port": 8767,
                "default_port": 8767,
                "mode": "discovery",
                "mode_source": "default",
                "active_profile": "full-user",
                "disk_pressure": {
                    "status": "degraded",
                    "used_pct": 88.2,
                    "disk_pressure_mode": "pause-requests",
                    "current_archive_count": 47,
                },
                "disk_pressure_recommendation": (
                    "disk approaching threshold at 88.2% used. "
                    "Consider archiving older rotated logs."
                ),
            },
        },
        "effective": {},
        "tips": [],
    }
    out = render_posture_human(snapshot)
    assert "Disk: degraded" in out
    assert "88.2% used" in out
    assert "Mode: pause-requests" in out
    assert "Archives: 47" in out
    assert "DISK PRESSURE:" in out


# ---------------------------------------------------------------------------
# Doc-truth-up tests (#454)
# ---------------------------------------------------------------------------


def test_docs_production_log_storage_no_references_to_in_flight() -> None:
    """#454 + Phase F audit gap §3.1: PRODUCTION-LOG-STORAGE.md must
    not claim #311 is "in flight" after it shipped. The only allowed
    "in flight" references are about webhook drain (legitimate)."""
    doc = pathlib.Path(__file__).parents[2] / "docs" / "PRODUCTION-LOG-STORAGE.md"
    content = doc.read_text()
    # No occurrence of the exact problematic phrase.
    assert "#311 (in flight)" not in content
    assert "(in flight, #311)" not in content


def test_docs_production_log_storage_documents_stop_on_disk_critical_real() -> None:
    """#454 + #455 ship-the-ghost-flag: the doc must reference
    --stop-on-disk-critical as a REAL flag (not a ghost). Also asserts
    the 3-mode policy is documented."""
    doc = pathlib.Path(__file__).parents[2] / "docs" / "PRODUCTION-LOG-STORAGE.md"
    content = doc.read_text()
    # Real flag, documented in §5.1 example block.
    assert "--stop-on-disk-critical" in content
    # 3-mode policy spelled out.
    assert "pause-requests" in content
    assert "rotate-aggressively" in content
    assert "archive-and-purge" in content
    # /healthz audit_log block reference exists.
    assert "audit_log" in content
    assert "disk_pressure_mode" in content


def test_log_retention_md_still_documents_stop_on_disk_critical() -> None:
    """The ghost-flag also appeared in LOG-RETENTION.md (per Phase F
    audit). Now that the flag ships for real, those references must
    still work (not get deleted)."""
    doc = pathlib.Path(__file__).parents[2] / "docs" / "LOG-RETENTION.md"
    content = doc.read_text()
    assert "--stop-on-disk-critical" in content
