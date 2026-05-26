"""State-verification tests for 4 autopilot daemon gaps (#641–#644).

UAT-Autopilot 2026-05-26 findings:

  #641 CRIT — bouncers.*.running not corrected after SIGKILL when pid=null
  #642 MED  — ticks_at_exit reports _improve_count not sweep ticks
  #643 MED  — sig-verify failures not promoted to supervisor.alerts
  #644 MED  — no-traffic warning absent from autopilot daemon

Per docs/CONTRIBUTING.md every test targets OBSERVABLE STATE (what's on
disk / in-memory after the fix fires) rather than internal implementation
so a future regression where the fix is bypassed still fails loudly.

Sabotage checks (tests 5 + 6) prove the fixes are load-bearing.
"""

from __future__ import annotations

import json
import os
import pathlib
import datetime as _dt
from typing import Any

import pytest
import yaml

from iam_jit.autopilot import (
    AutopilotSupervisor,
    autopilot_start,
    autopilot_status,
)
from iam_jit.autopilot.daemon import (
    _atomic_write_status_dict,
    _check_no_traffic_warn,
    _is_pid_alive,
    _status_path,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_autopilot_dir(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    autopilot_dir = tmp_path / "autopilot-home"
    autopilot_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("IAM_JIT_AUTOPILOT_DIR", str(autopilot_dir))
    return autopilot_dir


@pytest.fixture
def write_config(tmp_path: pathlib.Path):
    def _w(body: dict) -> pathlib.Path:
        p = tmp_path / ".iam-jit.yaml"
        p.write_text(yaml.safe_dump(body))
        return p
    return _w


@pytest.fixture
def quiet_improve(monkeypatch: pytest.MonkeyPatch):
    def _fake(**kwargs):
        from iam_jit.improve import ImproveProfileResult
        return ImproveProfileResult(
            status="no_change",
            bouncer=kwargs.get("bouncer", "ibounce"),
            cadence_window="1h",
            posture=kwargs.get("posture", "ambient"),
        )
    monkeypatch.setattr("iam_jit.improve.improve_profile", _fake)


@pytest.fixture
def quiet_notify(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )


@pytest.fixture
def stub_ibounce_running(monkeypatch: pytest.MonkeyPatch):
    """ibounce reports running=True with no PID in posture block."""
    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_ibounce",
        lambda: {"running": True, "port": 8767, "mode": "discovery"},
    )
    for n in ("kbounce", "dbounce", "gbounce"):
        monkeypatch.setattr(
            f"iam_jit.posture.bouncers.detect_{n}",
            lambda: {"running": False, "port": 0},
        )


@pytest.fixture
def stub_all_bouncers_down(monkeypatch: pytest.MonkeyPatch):
    for n in ("ibounce", "kbounce", "dbounce", "gbounce"):
        monkeypatch.setattr(
            f"iam_jit.posture.bouncers.detect_{n}",
            lambda: {"running": False, "port": 0},
        )


@pytest.fixture
def stub_start_bouncer(monkeypatch: pytest.MonkeyPatch):
    def _fake(name, *, port, mode, profile, extra_args, execute):
        return {
            "name": name, "started": True, "pid": 12345,
            "command": [], "port": port or 8767, "mode": mode,
            "profile": profile,
        }
    monkeypatch.setattr(
        "iam_jit.ambient_config.setup._start_bouncer", _fake,
    )


def _read_status_file_json() -> dict[str, Any]:
    """Read status.json directly — not via autopilot_status() which
    auto-corrects. Used to verify what's actually on disk."""
    p = _status_path()
    if not p.exists():
        return {}
    return json.loads(p.read_text())


# ---------------------------------------------------------------------------
# Test 1 — #641 CRIT: post-SIGKILL bpid=null still resets nested running
# ---------------------------------------------------------------------------


def test_641_null_bpid_per_bouncer_reset_when_daemon_dead() -> None:
    """#641 CRIT — When the daemon is dead (top-level stale detect fires),
    ALL per-bouncer running fields MUST be set to False even when
    bpid is None (the common posture-probe case).

    Pre-fix: the isinstance(bpid, int) gate skipped correction when
    bpid=None, leaving bouncers.ibounce.running=true while top-level
    running=false — two contradictory answers for the same question.

    OBSERVABLE: autopilot_status() returns running:false at both top-
    level and nested, AND writes the correction to disk.
    """
    # Simulate post-SIGKILL disk state: dead PID at top level, bpid=None
    # for ibounce (typical posture-probe behaviour — no PID in block).
    dead_pid = 9999999
    assert not _is_pid_alive(dead_pid), "test precondition: PID must be dead"

    stale = {
        "schema_version": "1.1",
        "running": True,        # stale claim
        "pid": dead_pid,        # dead
        "bouncers": {
            "ibounce": {
                "name": "ibounce",
                "running": True,   # stale claim
                "pid": None,       # ← the common case (#641 root cause)
            },
            "kbounce": {
                "name": "kbounce",
                "running": True,   # stale claim
                "pid": None,       # ← also None
            },
        },
    }
    _atomic_write_status_dict(stale)

    out = autopilot_status()

    # Top-level must be false (this was correct before the fix too).
    assert out["running"] is False
    assert out["status"]["running"] is False

    # OBSERVABLE STATE: per-bouncer running MUST be false regardless of bpid.
    bouncers = out["status"]["bouncers"]
    assert bouncers["ibounce"]["running"] is False, (
        "#641 CRIT: ibounce.running stayed true after daemon-dead detect "
        "when bpid=None — the isinstance(bpid, int) gate is too narrow"
    )
    assert bouncers["kbounce"]["running"] is False, (
        "#641 CRIT: kbounce.running stayed true (same root cause)"
    )

    # Correction must be persisted to disk.
    persisted = _read_status_file_json()
    assert persisted["bouncers"]["ibounce"]["running"] is False
    assert persisted["bouncers"]["kbounce"]["running"] is False
    assert "stale_detected_at" in persisted


# ---------------------------------------------------------------------------
# Test 2 — #642 MED: ticks_at_exit == sweep ticks not _improve_count
# ---------------------------------------------------------------------------


def test_642_ticks_at_exit_equals_sweep_count(
    write_config,
    stub_all_bouncers_down,
    stub_start_bouncer,
    quiet_notify,
) -> None:
    """#642 MED — With improve.enabled:false and max_ticks=3, three
    sweeps run but the old code returned _improve_count (always 0)
    instead of the actual sweep count.

    OBSERVABLE: the dict returned by autopilot_start() has ticks_at_exit:3.
    """
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
            "improve": {"enabled": False},   # ← improve disabled
        }
    })
    result = autopilot_start(
        config_path=cfg,
        detach=False,
        notify_denies="none",
        sweep_interval_s=0.01,
        max_ticks=3,
    )

    assert result["ticks_at_exit"] == 3, (
        f"#642 MED: ticks_at_exit={result['ticks_at_exit']!r} "
        f"(expected 3, got improve-count=0 instead of sweep count)"
    )


def test_642_ticks_at_exit_equals_5_sweeps(
    write_config,
    stub_all_bouncers_down,
    stub_start_bouncer,
    quiet_notify,
) -> None:
    """ticks_at_exit matches sweep count for max_ticks=5, improve disabled."""
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {},
            "improve": {"enabled": False},
        }
    })
    result = autopilot_start(
        config_path=cfg,
        detach=False,
        notify_denies="none",
        sweep_interval_s=0.01,
        max_ticks=5,
    )
    assert result["ticks_at_exit"] == 5


# ---------------------------------------------------------------------------
# Test 3 — #643 MED: refused entries promote to supervisor.alerts
# ---------------------------------------------------------------------------


def test_643_refused_entries_promote_to_alerts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#643 MED — When a threat-feed result has refused>0 (sig-verify
    failures), supervisor.alerts MUST contain a threat_feed_integrity
    entry with the feed label + count + remediation hint.

    OBSERVABLE: after run_threat_feed_for_all(), self.alerts contains
    the structured alert.

    We construct the supervisor directly (bypassing schema validation)
    because the threat_feed block is a runtime field not in the
    declaration schema.
    """
    # Build declaration directly to bypass schema validator for threat_feed.
    declaration = {
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {},
            "improve": {"enabled": False},
            "threat_feed": {
                "enabled": True,
                "update_cadence": "daily",
                "subscriptions": [
                    {"url": "https://example.com/feed.json", "enabled": True}
                ],
            },
        }
    }

    sup = AutopilotSupervisor(
        declaration=declaration,
        config_source="test",
        sweep_interval_s=0.01,
        notify_denies="none",
    )
    sup.initialize()

    # Mock the internals so we get a controlled refused>0 result without
    # real HTTP or real threat-feed infrastructure.
    from unittest.mock import MagicMock, patch

    fake_sub = MagicMock()
    fake_sub.enabled = True
    fake_sub.url = "https://example.com/feed.json"
    fake_sub.label.return_value = "example-feed"

    fake_fetch = MagicMock()
    fake_fetch.feed = MagicMock()
    fake_fetch.feed.feed_id = "test-feed-id"
    fake_fetch.feed.publisher = "test-publisher"
    fake_fetch.feed.entries = ["e1", "e2"]
    fake_fetch.cached = False
    fake_fetch.http_status = 200
    fake_fetch.manifest_sha256 = "abc123"
    fake_fetch.error = None

    # Two entries: one refused (sig-verify failure), one applied.
    fake_outcome_refused = MagicMock()
    fake_outcome_refused.action = "refused_verification"
    fake_outcome_applied = MagicMock()
    fake_outcome_applied.action = "auto_apply"

    with (
        patch(
            "iam_jit.autopilot.daemon.AutopilotSupervisor._threat_feed_subscriptions",
            return_value=[fake_sub],
        ),
        patch(
            "iam_jit.threat_feed.load_subscriptions_from_declaration",
            return_value=([fake_sub], {}),
        ),
        patch("iam_jit.threat_feed.fetch_feed", return_value=fake_fetch),
        patch(
            "iam_jit.threat_feed.apply_feed_entries",
            return_value=[fake_outcome_refused, fake_outcome_applied],
        ),
    ):
        results = sup.run_threat_feed_for_all()

    # OBSERVABLE: result has refused=1, applied=1.
    assert len(results) == 1
    assert results[0]["refused"] == 1
    assert results[0]["applied"] == 1

    # OBSERVABLE: supervisor.alerts contains the threat_feed_integrity entry.
    threat_alerts = [
        a for a in sup.alerts
        if isinstance(a, dict) and a.get("category") == "threat_feed_integrity"
    ]
    assert len(threat_alerts) == 1, (
        f"#643 MED: expected 1 threat_feed_integrity alert; "
        f"got {len(threat_alerts)}. alerts={sup.alerts!r}"
    )
    alert = threat_alerts[0]
    assert alert["severity"] == "warn"
    assert "example-feed" in alert["message"], (
        "alert message must include feed label"
    )
    assert "1" in alert["message"], (
        "alert message must include the refused count"
    )
    assert "signature verification failed" in alert["message"], (
        "alert message must include a description of what happened"
    )
    assert "investigate feed integrity" in alert["message"], (
        "alert message must include a remediation hint"
    )
    assert "timestamp" in alert


def test_643_zero_refused_no_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When refused==0 no threat_feed_integrity alert is emitted."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {},
            "improve": {"enabled": False},
            "threat_feed": {
                "enabled": True,
                "update_cadence": "daily",
                "subscriptions": [
                    {"url": "https://example.com/feed.json", "enabled": True}
                ],
            },
        }
    }

    sup = AutopilotSupervisor(
        declaration=declaration,
        config_source="test",
        sweep_interval_s=0.01,
        notify_denies="none",
    )
    sup.initialize()

    from unittest.mock import MagicMock, patch

    fake_sub = MagicMock()
    fake_sub.enabled = True
    fake_sub.url = "https://example.com/feed.json"
    fake_sub.label.return_value = "example-feed"

    fake_fetch = MagicMock()
    fake_fetch.feed = MagicMock()
    fake_fetch.feed.feed_id = "test-feed-id"
    fake_fetch.feed.publisher = "test-publisher"
    fake_fetch.feed.entries = ["e1"]
    fake_fetch.cached = False
    fake_fetch.http_status = 200
    fake_fetch.manifest_sha256 = "abc123"
    fake_fetch.error = None

    fake_outcome_applied = MagicMock()
    fake_outcome_applied.action = "auto_apply"

    with (
        patch(
            "iam_jit.autopilot.daemon.AutopilotSupervisor._threat_feed_subscriptions",
            return_value=[fake_sub],
        ),
        patch(
            "iam_jit.threat_feed.load_subscriptions_from_declaration",
            return_value=([fake_sub], {}),
        ),
        patch("iam_jit.threat_feed.fetch_feed", return_value=fake_fetch),
        patch(
            "iam_jit.threat_feed.apply_feed_entries",
            return_value=[fake_outcome_applied],
        ),
    ):
        sup.run_threat_feed_for_all()

    threat_alerts = [
        a for a in sup.alerts
        if isinstance(a, dict) and a.get("category") == "threat_feed_integrity"
    ]
    assert len(threat_alerts) == 0, (
        f"zero refused → no threat_feed_integrity alert expected; "
        f"got {threat_alerts!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — #644 MED: no-traffic warning fires + under-threshold silent
# ---------------------------------------------------------------------------


def test_644_no_traffic_warn_over_threshold() -> None:
    """#644 MED — When a bouncer has been running > 1h with 0 decisions,
    _check_no_traffic_warn() MUST append a no_traffic_through_bouncer alert.

    We test the helper directly (it's the load-bearing unit) and also
    confirm integration via run_once() in test_644_no_traffic_warn_integration.
    """
    alerts: list[Any] = []
    # Simulate started_at 2 hours ago.
    started_2h_ago = (
        _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    healthz = {
        "decisions_count": 0,
        "started_at": started_2h_ago,
        "mode": "discovery",
    }
    _check_no_traffic_warn("ibounce", healthz, alerts)

    assert len(alerts) == 1, (
        f"#644 MED: expected 1 no-traffic alert; got {len(alerts)}. "
        f"alerts={alerts!r}"
    )
    alert = alerts[0]
    assert alert["severity"] == "warn"
    assert alert["category"] == "no_traffic_through_bouncer"
    assert alert["bouncer"] == "ibounce"
    assert "2.0h" in alert["message"] or "2." in alert["message"], (
        "alert message must include uptime hours"
    )
    assert "0 decisions" in alert["message"]
    assert "iam-jit doctor install-check" in alert["message"]
    assert "timestamp" in alert


def test_644_no_traffic_warn_under_threshold_silent() -> None:
    """Under threshold (30min uptime + 0 decisions) → no alert."""
    alerts: list[Any] = []
    started_30m_ago = (
        _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=30)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    healthz = {
        "decisions_count": 0,
        "started_at": started_30m_ago,
        "mode": "discovery",
    }
    _check_no_traffic_warn("ibounce", healthz, alerts)

    assert len(alerts) == 0, (
        f"under threshold → no alert expected; got {alerts!r}"
    )


def test_644_no_traffic_warn_with_decisions_silent() -> None:
    """Over threshold but has decisions → no alert."""
    alerts: list[Any] = []
    started_2h_ago = (
        _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    healthz = {
        "decisions_count": 5,   # traffic IS flowing
        "started_at": started_2h_ago,
    }
    _check_no_traffic_warn("ibounce", healthz, alerts)

    assert len(alerts) == 0, (
        f"has decisions → no no-traffic alert; got {alerts!r}"
    )


def test_644_no_traffic_missing_started_at_silent() -> None:
    """No started_at field → no alert (can't compute uptime)."""
    alerts: list[Any] = []
    healthz = {"decisions_count": 0}
    _check_no_traffic_warn("ibounce", healthz, alerts)
    assert len(alerts) == 0


def test_644_no_traffic_warn_integration(
    write_config,
    stub_start_bouncer,
    quiet_improve,
    quiet_notify,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Integration: run_once() surfaces the no-traffic alert when healthz
    reports uptime>1h + decisions=0.

    The supervisor's alerts list is checked because the per-tick alert
    accumulates there before being written to status.json.
    """
    started_2h_ago = (
        _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    # ibounce reports running=True.
    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_ibounce",
        lambda: {"running": True, "port": 8767, "mode": "discovery"},
    )
    for n in ("kbounce", "dbounce", "gbounce"):
        monkeypatch.setattr(
            f"iam_jit.posture.bouncers.detect_{n}",
            lambda: {"running": False, "port": 0},
        )

    # /healthz returns: 2h uptime, 0 decisions.
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon._poll_bouncer_healthz",
        lambda name, port: {
            "decisions_count": 0,
            "started_at": started_2h_ago,
            "mode": "discovery",
            "status": "ok",
        },
    )

    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
            "improve": {"enabled": False},
        }
    })
    from iam_jit.ambient_config import load_declaration
    declaration, src = load_declaration(cfg)

    sup = AutopilotSupervisor(
        declaration=declaration,
        config_source=src,
        sweep_interval_s=0.01,
        notify_denies="none",
    )
    sup.initialize()
    sup.run_once()

    no_traffic_alerts = [
        a for a in sup.alerts
        if isinstance(a, dict) and a.get("category") == "no_traffic_through_bouncer"
    ]
    assert len(no_traffic_alerts) >= 1, (
        f"#644 integration: expected at least 1 no_traffic_through_bouncer "
        f"alert; got {sup.alerts!r}"
    )
    assert no_traffic_alerts[0]["bouncer"] == "ibounce"


def test_644_no_traffic_under_threshold_integration(
    write_config,
    stub_start_bouncer,
    quiet_improve,
    quiet_notify,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Integration: 30min uptime → no no-traffic alert in run_once()."""
    started_30m_ago = (
        _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=30)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_ibounce",
        lambda: {"running": True, "port": 8767, "mode": "discovery"},
    )
    for n in ("kbounce", "dbounce", "gbounce"):
        monkeypatch.setattr(
            f"iam_jit.posture.bouncers.detect_{n}",
            lambda: {"running": False, "port": 0},
        )
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon._poll_bouncer_healthz",
        lambda name, port: {
            "decisions_count": 0,
            "started_at": started_30m_ago,
            "mode": "discovery",
        },
    )

    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
            "improve": {"enabled": False},
        }
    })
    from iam_jit.ambient_config import load_declaration
    declaration, src = load_declaration(cfg)

    sup = AutopilotSupervisor(
        declaration=declaration,
        config_source=src,
        sweep_interval_s=0.01,
        notify_denies="none",
    )
    sup.initialize()
    sup.run_once()

    no_traffic_alerts = [
        a for a in sup.alerts
        if isinstance(a, dict) and a.get("category") == "no_traffic_through_bouncer"
    ]
    assert len(no_traffic_alerts) == 0, (
        f"30min uptime → no no-traffic alert expected; got {sup.alerts!r}"
    )


# ---------------------------------------------------------------------------
# Test 5 — sabotage for #641: unconditional reset is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_641_unconditional_reset_is_load_bearing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage the #641 fix by reverting to the old isinstance(bpid, int)
    gate and confirming that nested per-bouncer running stays True even
    after top-level stale detect fires with bpid=None.

    This proves the unconditional reset is necessary: without it, the
    nested state lies.

    Approach: monkeypatch autopilot_status to inline the OLD (broken)
    per-bouncer correction logic so we can confirm the broken behaviour
    occurs, then verify the unpatched code does NOT exhibit it.
    """
    dead_pid = 9999999
    assert not _is_pid_alive(dead_pid)

    # Plant bpid=None in both bouncers (the #641 failure case).
    stale = {
        "schema_version": "1.1",
        "running": True,
        "pid": dead_pid,
        "bouncers": {
            "ibounce": {"name": "ibounce", "running": True, "pid": None},
            "kbounce": {"name": "kbounce", "running": True, "pid": None},
        },
    }
    _atomic_write_status_dict(stale)

    # Simulate OLD behavior: only correct per-bouncer entries with
    # isinstance(bpid, int) PID that is dead.
    from iam_jit.autopilot.daemon import (
        _read_status_dict,
        _now_iso,
        _atomic_write_status_dict as _awd,
    )
    status_blob = _read_status_dict()
    top_pid = status_blob.get("pid")
    corrected = False
    if isinstance(top_pid, int) and not _is_pid_alive(top_pid):
        status_blob["running"] = False
        status_blob["pid"] = None
        status_blob["stale_detected_at"] = _now_iso()
        corrected = True
    bouncers = status_blob.get("bouncers", {})
    # OLD (broken) logic:
    for entry in bouncers.values():
        bpid = entry.get("pid")
        if isinstance(bpid, int) and not _is_pid_alive(bpid):  # ← only int
            entry["running"] = False
            entry["pid"] = None

    # With old logic: top corrected but per-bouncer still true (bpid=None
    # skipped the isinstance(bpid, int) gate).
    assert status_blob["running"] is False, (
        "sabotage precondition: top-level should be corrected"
    )
    assert bouncers["ibounce"]["running"] is True, (
        "SABOTAGE CONFIRMED: old isinstance(bpid, int) gate leaves nested "
        "running=true when bpid=None — the fix IS necessary"
    )
    assert bouncers["kbounce"]["running"] is True

    # Now confirm the ACTUAL (fixed) code returns False for both.
    # Re-plant the stale state.
    _atomic_write_status_dict(stale)
    out = autopilot_status()
    assert out["status"]["bouncers"]["ibounce"]["running"] is False, (
        "The actual fixed autopilot_status() should return False for "
        "ibounce.running after the #641 fix"
    )
    assert out["status"]["bouncers"]["kbounce"]["running"] is False


# ---------------------------------------------------------------------------
# Test 6 — sabotage for #644: threshold check is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_644_threshold_check_is_load_bearing() -> None:
    """Sabotage the #644 threshold check by using a very large threshold
    value and confirm no alert fires — proving that without the threshold
    comparison the feature is suppressed.

    Then confirm the real threshold fires correctly.
    """
    from iam_jit import autopilot as _ap_mod
    import iam_jit.autopilot.daemon as _daemon_mod

    started_2h_ago = (
        _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    healthz = {
        "decisions_count": 0,
        "started_at": started_2h_ago,
    }

    # Sabotage: temporarily set the threshold to 1000h so no real uptime
    # can ever cross it.
    original_threshold = _daemon_mod._NO_TRAFFIC_WARN_HOURS
    _daemon_mod._NO_TRAFFIC_WARN_HOURS = 1000.0
    try:
        alerts_sabotaged: list[Any] = []
        _check_no_traffic_warn("ibounce", healthz, alerts_sabotaged)
        assert len(alerts_sabotaged) == 0, (
            "SABOTAGE CONFIRMED: with threshold=1000h the no-traffic check "
            "does NOT fire — proves the threshold IS load-bearing"
        )
    finally:
        _daemon_mod._NO_TRAFFIC_WARN_HOURS = original_threshold

    # Confirm the real threshold (1h) fires.
    alerts_real: list[Any] = []
    _check_no_traffic_warn("ibounce", healthz, alerts_real)
    assert len(alerts_real) == 1, (
        f"real threshold should fire for 2h uptime; got {alerts_real!r}"
    )
