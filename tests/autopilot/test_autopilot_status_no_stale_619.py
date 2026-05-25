"""#619 HIGH — autopilot status.json must never carry a stale
``running: true`` after the daemon exits.

UAT-Cross 2026-05-25 (G1) finding shape:

  $ iam-jit autopilot start --max-ticks 2   # foreground; exits
  $ iam-jit autopilot status --json
  {
    "running": false,            # ← top-level correct
    "status": {
      "running": true,           # ← LIES (daemon exited)
      "pid": <dead-pid>,         # ← LIES
      "bouncers": {
        "ibounce": {
          "running": true,       # ← LIES
          "pid": null            # ← G2 MED: even when alive
        }
      }
    }
  }

Per `[[ibounce-honest-positioning]]` two values for the same question
= caller confusion. Same shape as #449 (which fixed top-level liveness
but left the nested ``status.*`` block lying). This test module is the
state-verification gate per ``docs/CONTRIBUTING.md`` — assertions
target the OBSERVABLE state (``status.json`` on disk + PID liveness
probe) rather than the function's return value, so a future regression
where the return is corrected but the file isn't (or vice-versa) still
fails loudly.
"""

from __future__ import annotations

import json
import os
import pathlib
import signal
import time
from typing import Any

import pytest
import yaml

from iam_jit.autopilot import (
    AutopilotSupervisor,
    autopilot_start,
    autopilot_status,
    autopilot_stop,
    resolve_pid_path,
)
from iam_jit.autopilot.daemon import (
    _atomic_write_status_dict,
    _is_pid_alive,
    _shutdown_cleanup_status_file,
    _status_path,
)


# ---------------------------------------------------------------------------
# Fixtures — isolated autopilot dir + stub bouncers + stub improve
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
def stub_bouncer_running(monkeypatch: pytest.MonkeyPatch):
    """Make ibounce posture detector report running=True (port-probe
    happy path) so we exercise the "running but block.pid=None" code
    path that #619 G2 cares about."""
    def _ibounce():
        return {"running": True, "port": 8767, "mode": "discovery"}
    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_ibounce", _ibounce,
    )
    for n in ("kbounce", "dbounce", "gbounce"):
        monkeypatch.setattr(
            f"iam_jit.posture.bouncers.detect_{n}",
            lambda: {"running": False, "port": 0},
        )


@pytest.fixture
def stub_start_bouncer(monkeypatch: pytest.MonkeyPatch):
    """_start_bouncer returns ``started=True, pid=12345`` so the
    supervisor's restart path captures that PID into ``state.last_pid``."""
    def _fake(name, *, port, mode, profile, extra_args, execute):
        return {
            "name": name, "started": True, "pid": 12345,
            "command": [], "port": port or 8767, "mode": mode,
            "profile": profile,
        }
    monkeypatch.setattr(
        "iam_jit.ambient_config.setup._start_bouncer", _fake,
    )


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
def write_config(tmp_path: pathlib.Path):
    def _w(body: dict) -> pathlib.Path:
        p = tmp_path / ".iam-jit.yaml"
        p.write_text(yaml.safe_dump(body))
        return p
    return _w


@pytest.fixture
def quiet_notify(monkeypatch: pytest.MonkeyPatch):
    """Skip the deny-notify HTTP fan-out so tests don't poll bouncers."""
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon.AutopilotSupervisor._notify_recent_denies",
        lambda self: None,
    )


def _read_status_file_json() -> dict[str, Any]:
    """Read status.json directly (NOT via the autopilot_status()
    auto-correcting reader). Used to verify what's actually persisted
    on disk."""
    p = _status_path()
    if not p.exists():
        return {}
    return json.loads(p.read_text())


# ---------------------------------------------------------------------------
# Test 1 — clean foreground stop must invalidate status.json everywhere
# ---------------------------------------------------------------------------


def test_status_after_clean_stop_shows_running_false_everywhere(
    write_config,
    stub_bouncer_running,
    stub_start_bouncer,
    quiet_improve,
    quiet_notify,
) -> None:
    """The #619 G1 shape: foreground start + clean exit. After the
    daemon exits, EVERY ``running`` field in status.json MUST read
    false; EVERY ``pid`` field MUST be None. No "two values for the
    same question.\""""
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
            "improve": {"enabled": True, "cadence": "per_session"},
        }
    })
    autopilot_start(
        config_path=cfg,
        detach=False,
        notify_denies="none",
        sweep_interval_s=0.01,
        max_ticks=2,
    )
    # OBSERVABLE STATE: read status.json directly from disk.
    persisted = _read_status_file_json()
    assert persisted, "status.json was not written"

    # Top-level invalidation.
    assert persisted["running"] is False, (
        f"status.json top-level running=true after clean exit "
        f"(this is the #619 shape); got: {persisted!r}"
    )
    assert persisted["pid"] is None, (
        f"status.json top-level pid={persisted['pid']!r} after clean "
        f"exit (must be None per #619)"
    )
    assert "stopped_at" in persisted, (
        "stopped_at timestamp must be set on shutdown cleanup"
    )

    # Per-bouncer invalidation — the G1 shape lied here too.
    bouncers = persisted.get("bouncers", {})
    assert "ibounce" in bouncers, (
        "ibounce entry must be preserved post-shutdown for operator "
        "introspection (only ``running`` + ``pid`` are nulled)"
    )
    assert bouncers["ibounce"]["running"] is False, (
        f"ibounce.running=true after clean exit (this is the #619 "
        f"per-bouncer shape); got: {bouncers['ibounce']!r}"
    )
    assert bouncers["ibounce"]["pid"] is None


# ---------------------------------------------------------------------------
# Test 2 — SIGTERM exit must also invalidate status.json
# ---------------------------------------------------------------------------


def test_status_after_sigterm_shows_running_false(
    write_config,
    stub_bouncer_running,
    stub_start_bouncer,
    quiet_improve,
    quiet_notify,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SIGTERM handler MUST also invalidate status.json. We can't
    actually SIGTERM the test process, so we exercise the handler
    directly via ``_handle_term`` (which is what the SIGTERM signal
    fires) and verify the on-disk effect."""
    cfg = write_config({
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
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
    sup.initialize()
    # First tick writes status.json with running=true.
    sup.run_once()
    pre_signal = _read_status_file_json()
    assert pre_signal["running"] is True, (
        "test precondition: status.json must claim running=true before "
        "we exercise the SIGTERM handler"
    )

    # Fire the signal handler (what SIGTERM/SIGINT both call).
    sup._handle_term()

    # OBSERVABLE STATE: status.json must now be invalidated.
    post_signal = _read_status_file_json()
    assert post_signal["running"] is False, (
        f"_handle_term did NOT invalidate status.json (this would "
        f"leak the #619 stale state on every SIGTERM exit); got: "
        f"{post_signal!r}"
    )
    assert post_signal["pid"] is None
    assert "stopped_at" in post_signal
    # And the supervisor's stopped flag is set so run_forever exits.
    assert sup.stopped is True


# ---------------------------------------------------------------------------
# Test 3 — crash-mid-shutdown: read path self-corrects + persists
# ---------------------------------------------------------------------------


def test_status_after_crash_self_corrects_on_read() -> None:
    """The defense-in-depth case: even if the shutdown handler missed
    (SIGKILL, OOM, power loss), ``autopilot_status()`` MUST self-
    correct from PID-liveness AND persist the correction so the next
    reader inherits it. This is the case the original #449 fix missed
    for the nested block."""
    # Synthesize the broken on-disk state: status.json claims running
    # with a dead PID. (PID 9999999 is reliably dead on every Unix.)
    dead_pid = 9999999
    assert not _is_pid_alive(dead_pid), (
        "test precondition: PID 9999999 is reliably dead"
    )
    pre_crash = {
        "schema_version": "1.1",
        "running": True,            # ← LIE (we're simulating post-crash)
        "pid": dead_pid,            # ← LIE
        "bouncers": {
            "ibounce": {
                "name": "ibounce",
                "running": True,    # ← LIE
                "pid": dead_pid,    # ← LIE
            }
        },
    }
    _atomic_write_status_dict(pre_crash)

    # First read MUST return corrected values.
    out = autopilot_status()
    assert out["running"] is False, (
        "autopilot_status() did NOT self-correct top-level running=true "
        "with dead PID (this is the #619 self-correction gap; the read "
        "path is the last line of defense after shutdown cleanup fails)"
    )
    assert out["status"]["running"] is False, (
        "nested status.running was NOT self-corrected — this is the "
        "exact UAT-Cross 2026-05-25 G1 shape (top-level false + nested "
        "true)"
    )
    assert out["status"]["pid"] is None
    assert out["status"]["bouncers"]["ibounce"]["running"] is False, (
        "per-bouncer running was NOT self-corrected on a dead PID"
    )
    assert out["status"]["bouncers"]["ibounce"]["pid"] is None
    assert "stale_detected_at" in out["status"]

    # OBSERVABLE STATE: the correction MUST be persisted to disk so
    # subsequent readers (curl /status.json, monitoring agents) also
    # see the truth — not just the in-process caller.
    persisted = _read_status_file_json()
    assert persisted["running"] is False, (
        "self-correction was returned but NOT persisted to status.json "
        "— a parallel reader would still see the stale lie"
    )
    assert persisted["bouncers"]["ibounce"]["running"] is False


# ---------------------------------------------------------------------------
# Test 4 — running=true + dead PID still self-corrects (no PID file path)
# ---------------------------------------------------------------------------


def test_status_validates_pid_alive() -> None:
    """When status.json has a running=true claim and the recorded PID
    is dead, the reader MUST flip running=false. Tests the PID-liveness
    gate in isolation from the per-bouncer gate."""
    dead_pid = 9999999
    _atomic_write_status_dict({
        "schema_version": "1.1",
        "running": True,
        "pid": dead_pid,
        "bouncers": {},
    })
    out = autopilot_status()
    assert out["status"]["running"] is False
    assert out["status"]["pid"] is None


# ---------------------------------------------------------------------------
# Test 5 — G2 MED: per-bouncer PIDs captured at spawn
# ---------------------------------------------------------------------------


def test_per_bouncer_pid_captured_at_spawn(
    write_config,
    stub_start_bouncer,
    quiet_improve,
    quiet_notify,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G2 MED from UAT-Cross 2026-05-25: even when the supervisor
    successfully spawns a bouncer, ``status.bouncers[ibounce].pid``
    reads null because the port-probe posture detector doesn't carry
    PID info. The fix: fall back to ``state.last_pid`` (captured at
    spawn) when block.pid is missing AND the captured PID is still
    alive."""
    # Posture detector reports ibounce running=False initially (forces
    # a restart attempt). After the restart, it flips to running=True
    # so we exercise the "running but no posture pid" code path.
    state = {"running": False}

    def _ibounce():
        return {"running": state["running"], "port": 8767, "mode": "discovery"}
    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_ibounce", _ibounce,
    )
    for n in ("kbounce", "dbounce", "gbounce"):
        monkeypatch.setattr(
            f"iam_jit.posture.bouncers.detect_{n}",
            lambda: {"running": False, "port": 0},
        )

    # Make the stub spawn return a PID we know is alive — use our own
    # PID so _is_pid_alive(captured_pid) returns True.
    alive_pid = os.getpid()

    def _fake_start(name, *, port, mode, profile, extra_args, execute):
        return {
            "name": name, "started": True, "pid": alive_pid,
            "command": [], "port": port or 8767, "mode": mode,
            "profile": profile,
        }
    monkeypatch.setattr(
        "iam_jit.ambient_config.setup._start_bouncer", _fake_start,
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

    # Tick 1: ibounce reports down → restart → captures alive_pid.
    sup.run_once()
    assert sup.bouncer_states["ibounce"].last_pid == alive_pid, (
        "supervisor did not capture pid at spawn"
    )

    # Tick 2: ibounce now reports running (port-probe happy) but the
    # posture block STILL doesn't carry PID. The supervisor MUST fall
    # back to state.last_pid.
    state["running"] = True
    status = sup.run_once()

    # OBSERVABLE STATE: per-bouncer pid is no longer null.
    persisted = _read_status_file_json()
    ibounce_entry = persisted["bouncers"]["ibounce"]
    assert ibounce_entry["running"] is True, (
        "ibounce should be running after the flip"
    )
    assert ibounce_entry["pid"] == alive_pid, (
        f"G2 MED: per-bouncer pid is {ibounce_entry['pid']!r} (expected "
        f"{alive_pid} from spawn capture). The port-probe posture "
        f"detector returns no pid; we MUST fall back to state.last_pid."
    )
    # And the in-memory status matches what we persisted.
    assert status.bouncers["ibounce"]["pid"] == alive_pid


# ---------------------------------------------------------------------------
# Test 6 — captured per-bouncer PID gets cleared when it dies
# ---------------------------------------------------------------------------


def test_per_bouncer_pid_cleared_on_dead(
    write_config,
    stub_start_bouncer,
    quiet_improve,
    quiet_notify,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If a bouncer's captured spawn PID dies between ticks, the next
    status entry MUST clear it (rather than reporting a dead PID as
    alive). Defense for the PID-reuse-window."""
    # Ibounce posture: always reports running=True (port still open
    # because some unrelated process bound it / port-probe stale).
    monkeypatch.setattr(
        "iam_jit.posture.bouncers.detect_ibounce",
        lambda: {"running": True, "port": 8767, "mode": "discovery"},
    )
    for n in ("kbounce", "dbounce", "gbounce"):
        monkeypatch.setattr(
            f"iam_jit.posture.bouncers.detect_{n}",
            lambda: {"running": False, "port": 0},
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
    # Plant a dead PID into state.last_pid (simulates: we spawned the
    # bouncer at tick 0, it died at tick 1, port-probe still says
    # running because something else picked up the port).
    dead_pid = 9999999
    assert not _is_pid_alive(dead_pid)
    sup.bouncer_states["ibounce"].last_pid = dead_pid

    sup.run_once()

    persisted = _read_status_file_json()
    ibounce_entry = persisted["bouncers"]["ibounce"]
    assert ibounce_entry["pid"] is None, (
        f"captured PID {dead_pid} is dead but status reports it as "
        f"alive ({ibounce_entry['pid']!r}); the read path MUST validate "
        f"liveness before using the captured PID"
    )
    # And the state.last_pid is cleared so we don't keep reporting it.
    assert sup.bouncer_states["ibounce"].last_pid is None


# ---------------------------------------------------------------------------
# Test 7 — atomic write: no partial JSON visible to a concurrent reader
# ---------------------------------------------------------------------------


def test_atomic_status_write_no_partial_state(tmp_path: pathlib.Path) -> None:
    """``_atomic_write_status_dict`` MUST use tempfile + rename so a
    concurrent reader never observes a half-written file. Verify by
    checking the writer never modifies the target path in-place
    (target is replaced via os.replace, which is atomic on POSIX)."""
    # Write an initial payload.
    initial = {"running": True, "pid": 12345, "bouncers": {}}
    _atomic_write_status_dict(initial)
    target = _status_path()
    initial_inode = os.stat(target).st_ino

    # Write a new payload — the file MUST be replaced (new inode on
    # systems where the rename creates a fresh inode).
    new_payload = {"running": False, "pid": None, "bouncers": {}}
    _atomic_write_status_dict(new_payload)

    # Whether the inode changes depends on filesystem; the strict
    # observable property is that:
    #   1. The .tmp sibling is NOT left behind (cleanup happened).
    #   2. The target reads back as well-formed JSON matching the new
    #      payload (no partial state observable).
    tmp_sibling = target.with_suffix(target.suffix + ".tmp")
    assert not tmp_sibling.exists(), (
        "atomic write left .tmp sibling behind — a concurrent reader "
        "discovering both files would not know which to trust"
    )
    on_disk = json.loads(target.read_text())
    assert on_disk == new_payload, (
        "atomic write did not result in the expected payload on disk"
    )
    # Re-stat just to anchor that the file is intact.
    assert os.stat(target).st_size > 0
    # Inode change is filesystem-dependent; not asserted strictly.
    _ = initial_inode


# ---------------------------------------------------------------------------
# Test 8 — sabotage check: if alive-check is gutted, test 3 fails
# ---------------------------------------------------------------------------


def test_sabotage_alive_check_is_load_bearing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per docs/CONTRIBUTING.md sabotage discipline: monkeypatch
    ``_is_pid_alive`` to always return True (the bug) and verify the
    self-correction tests would FAIL. This proves the alive-check is
    load-bearing: without it, dead PIDs would still pass through.

    We don't actually re-run test 3 here (pytest doesn't support nested
    test invocation cleanly); instead we replicate the assertion
    against the sabotaged helper and verify the broken behavior occurs.
    """
    dead_pid = 9999999
    # Sabotage: force alive-check to always return True.
    monkeypatch.setattr(
        "iam_jit.autopilot.daemon._is_pid_alive",
        lambda pid: True,
    )
    _atomic_write_status_dict({
        "schema_version": "1.1",
        "running": True,
        "pid": dead_pid,
        "bouncers": {
            "ibounce": {"name": "ibounce", "running": True, "pid": dead_pid},
        },
    })
    out = autopilot_status()
    # With the alive-check sabotaged, the self-correction in the read
    # path can no longer fire — the NESTED status block still claims
    # running=true even though we know the PID is dead. This is the
    # exact #619 G1 shape: top-level (driven by _read_pid_file → no
    # file → running=false) disagrees with nested (driven by the
    # status blob, which now goes uncorrected because alive-check lies).
    # If this assertion fails, the alive-check guard is NOT actually
    # gating the self-correction path and the self-correction tests
    # passed for the wrong reason.
    assert out["status"]["running"] is True, (
        "Sabotage of _is_pid_alive did NOT cause the nested status to "
        "stay running=true; the alive-check is not actually wired into "
        "the read path's self-correction guard."
    )
    assert out["status"]["bouncers"]["ibounce"]["running"] is True, (
        "Sabotage did not cause per-bouncer running to stay true either"
    )
    # And the persisted file still claims running=true (no correction
    # happened because the sabotaged check says PIDs are alive).
    persisted = _read_status_file_json()
    assert persisted["running"] is True
    assert persisted["bouncers"]["ibounce"]["running"] is True


# ---------------------------------------------------------------------------
# Test 9 — autopilot_stop also invalidates status.json (end-to-end)
# ---------------------------------------------------------------------------


def test_autopilot_stop_invalidates_status_when_no_pid(
) -> None:
    """``autopilot_stop`` with no PID file (the daemon already exited
    OR was never started) still invalidates a stale status.json. This
    closes the case where a prior crash left running=true + the
    operator runs ``stop`` to clean up."""
    # Plant stale state: status.json claims running with no PID file.
    _atomic_write_status_dict({
        "schema_version": "1.1",
        "running": True,
        "pid": 12345,
        "bouncers": {
            "ibounce": {"name": "ibounce", "running": True, "pid": 12345},
        },
    })
    assert not resolve_pid_path().exists()

    out = autopilot_stop()
    assert out["status"] == "not_running"

    # OBSERVABLE STATE: status.json is now honest.
    persisted = _read_status_file_json()
    assert persisted["running"] is False
    assert persisted["pid"] is None
    assert persisted["bouncers"]["ibounce"]["running"] is False
    assert persisted["bouncers"]["ibounce"]["pid"] is None


def test_autopilot_stop_with_stale_pid_invalidates_status() -> None:
    """``autopilot_stop`` with a stale PID file (PID dead) also
    invalidates status.json — same shape via a different code path."""
    pid_path = resolve_pid_path()
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text("9999999")  # dead

    _atomic_write_status_dict({
        "schema_version": "1.1",
        "running": True,
        "pid": 9999999,
        "bouncers": {
            "ibounce": {"name": "ibounce", "running": True, "pid": 9999999},
        },
    })

    out = autopilot_stop()
    assert out["status"] == "stale_pid_cleaned"
    assert not pid_path.exists()

    persisted = _read_status_file_json()
    assert persisted["running"] is False
    assert persisted["bouncers"]["ibounce"]["running"] is False


# ---------------------------------------------------------------------------
# Test 10 — public helper is callable + idempotent
# ---------------------------------------------------------------------------


def test_shutdown_cleanup_is_idempotent() -> None:
    """Multiple cleanup calls in a row MUST be safe (atexit may fire
    on top of the explicit cleanup in autopilot_start's finally
    block)."""
    _atomic_write_status_dict({
        "running": True, "pid": 12345, "bouncers": {},
    })
    _shutdown_cleanup_status_file()
    first = _read_status_file_json()
    _shutdown_cleanup_status_file()
    second = _read_status_file_json()
    assert first["running"] is False
    assert second["running"] is False
    # No fields lost between calls.
    assert "stopped_at" in second


def test_shutdown_cleanup_noop_when_no_status_file() -> None:
    """No status.json present → cleanup is a no-op (don't create an
    empty stub claiming the daemon exited when it never ran)."""
    assert not _status_path().exists()
    _shutdown_cleanup_status_file()
    assert not _status_path().exists(), (
        "cleanup should NOT create a status file when none exists"
    )
