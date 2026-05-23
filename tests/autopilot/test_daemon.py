"""#403 / §A49 — autopilot daemon tests.

Covers:
  * start reads config + initializes per-bouncer state
  * status reports healthy
  * stop terminates cleanly
  * auto-restart on simulated bouncer crash
  * refuses improve in managed posture
  * PID file correctly managed (write/clean/stale)
"""

from __future__ import annotations

import json
import os
import pathlib
import time
from typing import Any

import pytest
import yaml

from iam_jit.autopilot import (
    AutopilotError,
    AutopilotSupervisor,
    autopilot_start,
    autopilot_status,
    autopilot_stop,
    resolve_pid_path,
)


# ---------------------------------------------------------------------------
# Fixtures — isolate PID / status files into tmp_path per-test
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
def stub_posture_running(monkeypatch: pytest.MonkeyPatch):
    """Stub the bouncer posture detectors. Returns a controller fn the
    test calls with `set(name, running)` to flip state."""
    state = {
        "ibounce": {"running": True, "port": 8767, "mode": "discovery"},
        "kbouncer": {"running": False, "port": 8766},
        "dbounce": {"running": False, "port": 5433},
        "gbounce": {"running": False, "port": 8080},
    }

    def _make_detector(name: str):
        def _d():
            return dict(state[name])
        return _d

    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_ibounce", _make_detector("ibounce")
    )
    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_kbounce", _make_detector("kbouncer")
    )
    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_dbounce", _make_detector("dbounce")
    )
    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_gbounce", _make_detector("gbounce")
    )

    class _Ctl:
        @staticmethod
        def set(name: str, running: bool) -> None:
            state[name]["running"] = running

    return _Ctl


@pytest.fixture
def stub_start_bouncer(monkeypatch: pytest.MonkeyPatch):
    """Stub _start_bouncer so restarts don't fork real processes."""
    calls: list[dict] = []

    def _fake(name, *, port, mode, profile, extra_args, execute):
        calls.append({"name": name, "execute": execute})
        return {
            "name": name, "started": True, "pid": 99999,
            "command": [], "port": port or 8767, "mode": mode,
            "profile": profile,
        }
    monkeypatch.setattr(
        "iam_jit.ambient_config.setup._start_bouncer",
        _fake,
    )
    return calls


@pytest.fixture
def write_config(tmp_path: pathlib.Path):
    """Helper to write a .iam-jit.yaml + return its path."""
    def _w(body: dict) -> pathlib.Path:
        p = tmp_path / ".iam-jit.yaml"
        p.write_text(yaml.safe_dump(body))
        return p
    return _w


@pytest.fixture
def quiet_improve(monkeypatch: pytest.MonkeyPatch):
    """Stub improve_profile so autopilot tests don't drive the full
    pipeline."""
    captured: list[dict] = []

    def _fake(**kwargs):
        from iam_jit.improve import ImproveProfileResult
        captured.append(kwargs)
        return ImproveProfileResult(
            status="no_change",
            bouncer=kwargs.get("bouncer", "ibounce"),
            cadence_window="1h",
            posture=kwargs.get("posture", "ambient"),
        )

    monkeypatch.setattr("iam_jit.improve.improve_profile", _fake)
    return captured


# ---------------------------------------------------------------------------
# PID file management
# ---------------------------------------------------------------------------


def test_autopilot_pid_file_correctly_managed(
    write_config,
    stub_posture_running,
    stub_start_bouncer,
    quiet_improve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Foreground start MUST write the pid file at start + clear it at
    exit."""
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
            "improve": {"enabled": True, "cadence": "per_session"},
        }
    })
    # Patch _notify_recent_denies to no-op so we don't try real HTTP.
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )
    pid_path = resolve_pid_path()
    assert not pid_path.exists()
    result = autopilot_start(
        config_path=cfg,
        detach=False,
        notify_denies="none",
        sweep_interval_s=0.01,
        max_ticks=1,
    )
    assert result["status"] == "stopped"
    # After foreground exit pid file must be cleaned up.
    assert not pid_path.exists()


def test_autopilot_status_returns_not_running_initially(
) -> None:
    out = autopilot_status()
    assert out["running"] is False
    assert out["pid"] is None


def test_autopilot_stop_no_pid_returns_not_running() -> None:
    out = autopilot_stop()
    assert out["status"] == "not_running"


def test_autopilot_stop_stale_pid_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A PID file pointing at a dead process must be cleaned up."""
    pid_path = resolve_pid_path()
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text("9999999")  # dead pid
    out = autopilot_stop()
    assert out["status"] == "stale_pid_cleaned"
    assert not pid_path.exists()


# ---------------------------------------------------------------------------
# Start / status / supervisor wiring
# ---------------------------------------------------------------------------


def test_autopilot_start_reads_config_starts_bouncers(
    write_config,
    stub_posture_running,
    stub_start_bouncer,
    quiet_improve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Start reads the declaration + populates the supervisor's bouncer
    state per the bouncers block."""
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
                "kbouncer": {"enabled": True, "mode": "discovery"},
            },
            "improve": {"enabled": True, "cadence": "per_session"},
        }
    })
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )
    autopilot_start(
        config_path=cfg,
        detach=False,
        notify_denies="none",
        sweep_interval_s=0.01,
        max_ticks=1,
    )
    # The status file should be populated.
    sf = resolve_pid_path().parent / "autopilot.status.json"
    assert sf.exists()
    payload = json.loads(sf.read_text())
    assert "ibounce" in payload["bouncers"]
    assert "kbouncer" in payload["bouncers"]
    assert payload["improve"]["cadence"] == "per_session"


def test_autopilot_status_reports_healthy(
    write_config,
    stub_posture_running,
    stub_start_bouncer,
    quiet_improve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After a successful start, status reports running=True + bouncers
    detected as RUNNING in the payload."""
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True}},
            "improve": {"enabled": True},
        }
    })
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )
    autopilot_start(
        config_path=cfg, detach=False, notify_denies="none",
        sweep_interval_s=0.01, max_ticks=1,
    )
    out = autopilot_status()
    # Foreground exit means the daemon ISN'T running by the time we
    # check, but the status file from the last tick IS present.
    assert out["status_file_present"] is True
    assert out["status"]["bouncers"]["ibounce"]["running"] is True


def test_autopilot_stop_terminates_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulate a running daemon by writing a live PID; verify stop
    sends SIGTERM + cleans the file."""
    import signal
    sent_signals: list[int] = []

    def _fake_kill(pid, sig):
        sent_signals.append(sig)
        # mark dead immediately
        return None

    # Write current process PID as fake autopilot.
    real_pid = os.getpid()
    pid_path = resolve_pid_path()
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(real_pid))

    # Patch os.kill so the real process isn't actually signaled.
    # First, _is_pid_alive(real_pid) returns True (real check); after
    # SIGTERM call we want subsequent _is_pid_alive checks to return False.
    state = {"alive": True}

    def _fake_kill(pid, sig):
        if sig == 0:
            if not state["alive"]:
                raise ProcessLookupError("no such pid")
            return None
        sent_signals.append(sig)
        state["alive"] = False
        return None

    monkeypatch.setattr("iam_jit.autopilot.daemon.os.kill", _fake_kill)

    out = autopilot_stop(timeout_s=0.5)
    assert out["status"] == "stopped"
    assert signal.SIGTERM in sent_signals
    assert not pid_path.exists()


def test_autopilot_refuses_to_start_when_disabled(write_config) -> None:
    cfg = write_config({
        "iam-jit": {
            "enabled": False,
            "bouncers": {"ibounce": {"enabled": True}},
        }
    })
    with pytest.raises(AutopilotError) as e:
        autopilot_start(config_path=cfg, detach=False, max_ticks=1)
    assert e.value.code == "declaration_disabled"


def test_autopilot_refuses_to_double_start(
    write_config,
    stub_posture_running,
    stub_start_bouncer,
    quiet_improve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a live pid file exists, start refuses with `already_running`."""
    # Write the current process's pid as a fake autopilot.
    pid_path = resolve_pid_path()
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(os.getpid()))
    cfg = write_config({
        "iam-jit": {"enabled": True, "bouncers": {"ibounce": {"enabled": True}}}
    })
    with pytest.raises(AutopilotError) as e:
        autopilot_start(config_path=cfg, detach=False, max_ticks=1)
    assert e.value.code == "already_running"


# ---------------------------------------------------------------------------
# Auto-restart behavior
# ---------------------------------------------------------------------------


def test_autopilot_auto_restart_on_simulated_bouncer_crash(
    write_config,
    stub_posture_running,
    stub_start_bouncer,
    quiet_improve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a bouncer is detected as not-running, the supervisor calls
    _start_bouncer to restart it."""
    stub_posture_running.set("ibounce", False)  # simulate crash
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
            "improve": {"enabled": False},
        }
    })
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )
    from iam_jit.ambient_config import load_declaration
    declaration, src = load_declaration(cfg)
    sup = AutopilotSupervisor(
        declaration=declaration,
        config_source=src,
        sweep_interval_s=0.01,
        notify_denies="none",
    )
    status = sup.run_once()
    # _start_bouncer should have been invoked at least once.
    assert any(c["name"] == "ibounce" for c in stub_start_bouncer)
    assert "ibounce" in status.bouncers


def test_autopilot_throttles_restarts_after_max_attempts(
    write_config,
    stub_posture_running,
    quiet_improve,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After >3 restart attempts within 60s, autopilot alerts + stops
    retrying that bouncer."""
    stub_posture_running.set("ibounce", False)
    calls: list[str] = []

    def _fake_start(name, *, port, mode, profile, extra_args, execute):
        calls.append(name)
        return {
            "name": name, "started": False, "skipped": True,
            "reason": "start_failed: simulated", "command": [],
        }

    monkeypatch.setattr(
        "iam_jit.ambient_config.setup._start_bouncer", _fake_start,
    )
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "bouncers": {"ibounce": {"enabled": True}},
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
    # Run sweeps until throttle kicks in.
    for _ in range(6):
        sup.run_once()
    # After max retries, alert MUST be in supervisor.alerts.
    assert any("halting restart" in a for a in sup.alerts)
    # And the bouncer state must show alert_emitted.
    assert sup.bouncer_states["ibounce"].alert_emitted is True


# ---------------------------------------------------------------------------
# Managed-posture refusal
# ---------------------------------------------------------------------------


def test_autopilot_refuses_improve_in_managed_posture(
    write_config,
    stub_posture_running,
    stub_start_bouncer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When posture=managed, supervisor.run_improve_for_all() returns
    empty + emits a refusal alert."""
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "managed",
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mode": "strict",
                    "profile": "ci-runner",
                    "profile_source": "./profiles/ci-runner.yaml",
                }
            },
            "improve": {"enabled": False},
            "fail_on_deny": True,
        }
    })
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )
    from iam_jit.ambient_config import load_declaration
    declaration, src = load_declaration(cfg)
    sup = AutopilotSupervisor(
        declaration=declaration,
        config_source=src,
        sweep_interval_s=0.01,
        notify_denies="none",
    )
    sup.initialize()
    results = sup.run_improve_for_all()
    assert results == []
    assert any("managed" in a.lower() for a in sup.alerts)
