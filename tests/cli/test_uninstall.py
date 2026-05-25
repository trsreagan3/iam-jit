"""#541 — `iam-jit uninstall` state-verification tests.

Per docs/CONTRIBUTING.md: every "removed" success claim is paired with
an observable post-check (file absent, PID absent, port-bound flag
flipped). The anti-pattern this avoids is "function returned status='ok'
but the file is still on disk" (the #326 / #463 / #475 shape).

Per [[ibounce-honest-positioning]]: partial-failure tests assert the
honest report — uninstall surfaces what was/wasn't done; tests verify
the surface matches reality.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from typing import Any
from unittest import mock

import pytest
from click.testing import CliRunner

import iam_jit.cli_uninstall as cu
from iam_jit.cli import main


# Capture real implementations BEFORE the autouse isolation fixture
# stubs them, so end-to-end tests can restore the real pipeline.
_REAL_PORT_BOUND = cu._port_bound
_REAL_LSOF_PIDS_ON_PORT = cu._lsof_pids_on_port
_REAL_READ_CMDLINE = cu._read_cmdline


# ---------------------------------------------------------------------------
# Isolation fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _default_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default-isolate every test from the dev machine's real bouncer
    processes + bound ports + go-bin dir. Tests override per-call when
    they care about a specific behavior.

    Without this, the dev machine's actually-running ibounce / gbounce
    would trip halt conditions on EVERY test that doesn't explicitly
    stub `_port_bound` + `_find_pids_for_process`.

    #574: also stub `_lsof_pids_on_port` + `_read_cmdline` since the
    inventory now cross-references bound-port owners back to PIDs.
    Without stubs, tests that set ``_port_bound=True`` would shell out
    to the dev machine's lsof + ps and pick up real bouncer PIDs.
    """
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": False)
    monkeypatch.setattr(cu, "_lsof_pids_on_port", lambda port: [])
    monkeypatch.setattr(cu, "_read_cmdline", lambda pid: "")


@pytest.fixture
def isolated_iam_jit_home(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    """Redirect every module-level path in cli_uninstall to a tmp dir.

    Mirrors test_cli_canary.py's `isolated_canary` fixture. Touches:
    IAM_JIT_HOME, VENV_DIR, BOUNCER_DIR, AUDIT_PATH, ANOMALY_BASELINE_PATH,
    CANARY_DIR. Tests then populate the tmp dir to mimic a real install.
    """
    fake_home = tmp_path / ".iam-jit"
    fake_home.mkdir()
    monkeypatch.setattr(cu, "IAM_JIT_HOME", fake_home)
    monkeypatch.setattr(cu, "VENV_DIR", fake_home / "venv")
    monkeypatch.setattr(cu, "BOUNCER_DIR", fake_home / "bouncer")
    monkeypatch.setattr(cu, "AUDIT_PATH", fake_home / "audit.jsonl")
    monkeypatch.setattr(
        cu, "ANOMALY_BASELINE_PATH", fake_home / "anomaly-baseline.db",
    )
    monkeypatch.setattr(cu, "CANARY_DIR", fake_home / "canary")
    return fake_home


def _seed_install(home: pathlib.Path) -> dict[str, pathlib.Path]:
    """Populate `home` to look like a real iam-jit install.

    Creates venv layout, audit-bearing files, canary state. Returns a
    map of path-name -> Path so tests can assert presence/absence by
    name.
    """
    paths: dict[str, pathlib.Path] = {}

    venv_bin = home / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    # Console scripts.
    for script in cu.CONSOLE_SCRIPTS:
        (venv_bin / script).write_text("#!/bin/sh\necho fake\n")
        (venv_bin / script).chmod(0o755)
        paths[f"console:{script}"] = venv_bin / script
    # A dummy pip script so cu._step_pip_uninstall's existence-check
    # passes without us actually shelling out (we mock subprocess below).
    pip = venv_bin / "pip"
    pip.write_text("#!/bin/sh\nexit 0\n")
    pip.chmod(0o755)
    paths["pip"] = pip

    bouncer_dir = home / "bouncer"
    bouncer_dir.mkdir()
    (bouncer_dir / "state.db").write_text("audit chain seed")
    (bouncer_dir / "state.db-wal").write_text("wal")
    (bouncer_dir / "state.db-shm").write_text("shm")
    (bouncer_dir / "profiles.yaml").write_text("default: {}")
    paths["state.db"] = bouncer_dir / "state.db"
    paths["state.db-wal"] = bouncer_dir / "state.db-wal"
    paths["profiles.yaml"] = bouncer_dir / "profiles.yaml"

    audit = home / "audit.jsonl"
    audit.write_text('{"seq":1,"event":"seed"}\n')
    paths["audit.jsonl"] = audit

    canary = home / "canary"
    canary.mkdir()
    (canary / "issues.jsonl").write_text(
        '{"ts":"2026-05-24T00:00:00Z","severity":"LOW"}\n'
    )
    (canary / "status.json").write_text('{"canary_day":1}')
    paths["canary/issues.jsonl"] = canary / "issues.jsonl"
    paths["canary/status.json"] = canary / "status.json"

    threat = home / "threat_feed"
    threat.mkdir()
    (threat / "publisher.ed25519.pem").write_text("fake key")
    paths["threat_feed/publisher.ed25519.pem"] = (
        threat / "publisher.ed25519.pem"
    )
    return paths


# ---------------------------------------------------------------------------
# Test 1 — dry-run reports plan + makes NO changes
# ---------------------------------------------------------------------------


def test_uninstall_dry_run_reports_plan_no_changes(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _seed_install(isolated_iam_jit_home)

    # Stub running bouncers + pip subprocess so dry-run doesn't actually
    # call them (dry-run should short-circuit before either).
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    # Isolate from the dev machine's actually-running bouncers.
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": False)
    result = cu.run_uninstall(dry_run=True)

    # Claim: status is dry_run.
    assert result["status"] == "dry_run"

    # Observable: nothing was removed. Every seeded path still exists.
    for name, p in paths.items():
        assert p.exists(), (
            f"dry-run unexpectedly removed {name} at {p}"
        )

    # Plan content: removed_paths is non-empty (the plan IS substantive).
    home_step = result["steps"]["remove_iam_jit_home"]
    assert home_step["removed_paths"], "dry-run should plan to remove things"


# ---------------------------------------------------------------------------
# Test 2 — --yes skips confirmation; clean removal
# ---------------------------------------------------------------------------


def test_uninstall_yes_flag_skips_confirmation_and_removes_state(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _seed_install(isolated_iam_jit_home)

    # No bouncers; pip stub returns success.
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="OK", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        runner = CliRunner()
        result = runner.invoke(main, ["uninstall", "--yes"])

    assert result.exit_code == 0, result.output

    # Observable: ~/.iam-jit/ is gone (or contains nothing).
    assert not isolated_iam_jit_home.exists() or not list(
        isolated_iam_jit_home.iterdir()
    )
    # Audit-bearing files removed (no --keep-audit-logs).
    assert not paths["audit.jsonl"].exists()
    assert not paths["state.db"].exists()


# ---------------------------------------------------------------------------
# Test 3 — removes iam-jit config dir (state verification on the path)
# ---------------------------------------------------------------------------


def test_uninstall_removes_iam_jit_config_dir(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    # Pre-condition: dir is observably populated.
    assert (isolated_iam_jit_home / "bouncer" / "state.db").exists()
    assert (isolated_iam_jit_home / "venv" / "bin" / "ibounce").exists()

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(dry_run=False)

    assert result["status"] == "ok", result

    # Observable: every child of the seeded home is gone.
    assert not (isolated_iam_jit_home / "bouncer").exists()
    assert not (isolated_iam_jit_home / "venv").exists()
    assert not (isolated_iam_jit_home / "audit.jsonl").exists()
    assert not (isolated_iam_jit_home / "canary").exists()
    assert not (isolated_iam_jit_home / "threat_feed").exists()


# ---------------------------------------------------------------------------
# Test 4 — stops running bouncers (sigterm reaper)
# ---------------------------------------------------------------------------


def test_uninstall_stops_running_bouncers(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Start a real dummy subprocess + verify uninstall reaps it.

    Per docs/CONTRIBUTING.md state-verification: the observable side of
    "bouncer stopped" is os.kill(pid, 0) raising ProcessLookupError.
    """
    _seed_install(isolated_iam_jit_home)

    # Spawn a long-sleeping child we can reap.
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"]
    )
    try:
        # Pre-condition: child is alive.
        assert cu._pid_alive(child.pid)

        # Pretend pgrep finds our child under the ibounce name.
        def fake_pgrep(name: str) -> list[int]:
            if name == "ibounce":
                return [child.pid]
            return []

        monkeypatch.setattr(cu, "_find_pids_for_process", fake_pgrep)
        monkeypatch.setattr(
            cu, "_resolve_go_bin_dir",
            lambda: isolated_iam_jit_home / "nogo",
        )

        fake_proc = subprocess.CompletedProcess(
            args=["pip"], returncode=0, stdout="", stderr="",
        )
        with mock.patch.object(subprocess, "run", return_value=fake_proc):
            result = cu.run_uninstall(dry_run=False)

        # Reap our own child to clear the zombie entry (in real usage
        # bouncers are re-parented to init/launchd which reaps for us).
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

        # Claim: stop_bouncers reports either sigterm or sigkill sent.
        # We don't require "reaped" here because our test child is a
        # zombie until pytest waitpid's it (production bouncers are
        # re-parented to init which reaps for us); the operator-visible
        # claim is that we sent SIGTERM/SIGKILL.
        stop = result["steps"]["stop_bouncers"]
        assert (
            child.pid in stop["sigterm_pids"]
            or child.pid in stop["sigkill_pids"]
            or child.pid in stop["reaped"]
        ), stop

        # Observable: the PID is no longer alive after we waitpid'd it.
        assert not cu._pid_alive(child.pid), (
            f"PID {child.pid} still alive after uninstall + waitpid"
        )
    finally:
        # Defensive cleanup.
        try:
            child.terminate()
            child.wait(timeout=2)
        except Exception:
            try:
                child.kill()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 5 — --keep-audit-logs preserves audit chain
# ---------------------------------------------------------------------------


def test_uninstall_keeps_audit_logs_when_flagged(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(dry_run=False, keep_audit_logs=True)

    assert result["status"] == "ok", result

    # Observable: every audit-bearing file is STILL present.
    assert paths["audit.jsonl"].exists()
    assert paths["state.db"].exists()
    assert paths["state.db-wal"].exists()
    assert paths["canary/issues.jsonl"].exists()

    # Observable: non-audit files were removed.
    assert not paths["profiles.yaml"].exists(), (
        "profiles.yaml is not audit-bearing; should have been removed"
    )
    assert not paths["threat_feed/publisher.ed25519.pem"].exists()
    assert not (isolated_iam_jit_home / "venv").exists()

    # Claim: post_check reports audit_logs_preserved.
    assert result["post_check"]["audit_logs_preserved"]


# ---------------------------------------------------------------------------
# Test 6 — --backup-dir preserves configs before removal
# ---------------------------------------------------------------------------


def test_uninstall_backup_dir_preserves_configs(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    paths = _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    backup_root = tmp_path / "backups"

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            dry_run=False, backup_dir=backup_root,
        )

    assert result["status"] == "ok", result

    # Observable: backup dir contains snapshots of every top-level child.
    assert backup_root.exists()
    assert (backup_root / "bouncer" / "state.db").exists()
    assert (backup_root / "bouncer" / "profiles.yaml").exists()
    assert (backup_root / "audit.jsonl").exists()
    assert (backup_root / "canary" / "issues.jsonl").exists()
    # Content of the backup matches what was on disk.
    assert (
        backup_root / "bouncer" / "state.db"
    ).read_text() == "audit chain seed"

    # Observable: originals are gone.
    assert not paths["state.db"].exists()
    assert not paths["audit.jsonl"].exists()


# ---------------------------------------------------------------------------
# Test 7 — halts on detected halt condition; no destructive steps
# ---------------------------------------------------------------------------


def test_uninstall_halts_on_unsafe_state(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inject a halt-worthy condition (bound port + no bouncer pid) +
    verify uninstall HALTS without touching state."""
    paths = _seed_install(isolated_iam_jit_home)

    # No bouncer PIDs visible.
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    # But bouncer ports are bound (a non-bouncer service holds them).
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": True)

    result = cu.run_uninstall(dry_run=False, force=False)

    # Claim: status is halted.
    assert result["status"] == "halted", result
    assert result["halts"], "halt condition must be surfaced"
    assert any(h["id"] == "U-1" for h in result["halts"])

    # Observable: nothing was removed.
    assert paths["state.db"].exists()
    assert paths["audit.jsonl"].exists()
    assert paths["console:ibounce"].exists()


# ---------------------------------------------------------------------------
# Test 8 — --force bypasses halt
# ---------------------------------------------------------------------------


def test_uninstall_force_bypasses_halt(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    # Bound ports trip U-1 halt, but inventory's first call is for the
    # pre-flight + the second is from the post-check. Both must see
    # bound ports during pre-flight; let the post-check report leftover
    # bound ports too (truthfully — they ARE still bound, it's an
    # external process).
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": True)

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(dry_run=False, force=True)

    # Claim: status records halts but executed the steps anyway.
    assert result["halts"], "halt conditions still surface under --force"
    # Post-check finds leftover state (bound ports) → status=incomplete,
    # which is the HONEST report per [[ibounce-honest-positioning]].
    assert result["status"] == "incomplete", result
    # Steps DID run despite halt.
    assert result["steps"]["remove_venv"]["removed"]
    assert not paths["state.db"].exists()
    assert not paths["audit.jsonl"].exists()


# ---------------------------------------------------------------------------
# Test 9 — partial failure honestly reported
# ---------------------------------------------------------------------------


def test_uninstall_partial_failure_reports_state(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inject a venv-removal failure + verify the failure is surfaced
    in `steps.remove_venv.failed` (not silently swallowed)."""
    paths = _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    original_rmtree = cu.shutil.rmtree

    def break_venv_rmtree(target, *args, **kwargs):
        target_path = pathlib.Path(target)
        if target_path == isolated_iam_jit_home / "venv":
            raise OSError("simulated permission denied")
        return original_rmtree(target, *args, **kwargs)

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(cu.shutil, "rmtree", side_effect=break_venv_rmtree):
        with mock.patch.object(subprocess, "run", return_value=fake_proc):
            result = cu.run_uninstall(dry_run=False)

    # Claim: venv removal failed.
    venv_step = result["steps"]["remove_venv"]
    assert venv_step["failed"] is not None
    assert "simulated permission denied" in venv_step["failed"]

    # Observable: venv is STILL present (the failure wasn't faked).
    assert (isolated_iam_jit_home / "venv").exists()

    # Top-level status is incomplete (post-check sees the venv leftover).
    assert result["status"] == "incomplete"


# ---------------------------------------------------------------------------
# Test 10 — idempotent second run is a no-op
# ---------------------------------------------------------------------------


def test_uninstall_idempotent(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        first = cu.run_uninstall(dry_run=False)
        assert first["status"] == "ok"

        # Second run should find nothing to do.
        second = cu.run_uninstall(dry_run=False)
        assert second["status"] == "ok"
        # Observable: inventory in second run is empty.
        inv2 = second["inventory"]
        assert not inv2["iam_jit_home_exists"]
        assert not inv2["venv_exists"]
        assert not inv2["running_bouncers"]
        assert not inv2["console_scripts_present"]
        assert not inv2["audit_bearing_files"]
        # No step did anything destructive.
        assert not second["steps"]["remove_venv"]["removed"]
        assert not second["steps"]["remove_iam_jit_home"]["removed_paths"]


# ---------------------------------------------------------------------------
# Test 11 — post-check verifies observably-clean state
# ---------------------------------------------------------------------------


def test_uninstall_post_check_verifies_clean_state(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": False)
    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(dry_run=False)

    assert result["status"] == "ok"
    post = result["post_check"]
    # Claim: clean.
    assert post["clean"] is True
    leftover = post["leftover"]
    # Observable: each field in leftover reports empty/false.
    assert not leftover["running_bouncers"]
    assert not leftover["bound_ports"]
    assert not leftover["venv_exists"]
    assert not leftover["console_scripts_present"]
    assert not leftover["iam_jit_home_exists"]


# ---------------------------------------------------------------------------
# Test 12 — sabotage check: monkey-patch stop_bouncers to no-op + verify
# test 4's "verify reaped" assertion would fire
# ---------------------------------------------------------------------------


def test_sabotage_no_op_stop_bouncers_is_detected(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage-check per the brief: prove that if _step_stop_bouncers
    silently no-ops, the state-verification assertion (PID still alive)
    actually fires. This is the meta-test that makes test 4 meaningful.
    """
    # Spawn a real child.
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"]
    )
    try:
        assert cu._pid_alive(child.pid)

        def fake_pgrep(name: str) -> list[int]:
            if name == "ibounce":
                return [child.pid]
            return []

        monkeypatch.setattr(cu, "_find_pids_for_process", fake_pgrep)

        # Sabotage: replace _step_stop_bouncers with a no-op that LIES
        # about reaping the PID.
        def sabotaged_stop(inventory, *, dry_run, grace_seconds=5.0):
            return {
                "sigterm_pids": [],
                "sigkill_pids": [],
                "reaped": [child.pid],  # claim reaped without touching it
                "failed": [],
            }

        monkeypatch.setattr(cu, "_step_stop_bouncers", sabotaged_stop)
        monkeypatch.setattr(
            cu, "_resolve_go_bin_dir",
            lambda: isolated_iam_jit_home / "nogo",
        )
        fake_proc = subprocess.CompletedProcess(
            args=["pip"], returncode=0, stdout="", stderr="",
        )
        with mock.patch.object(subprocess, "run", return_value=fake_proc):
            result = cu.run_uninstall(dry_run=False)

        # Claim: stop_bouncers reports reaped.
        assert child.pid in result["steps"]["stop_bouncers"]["reaped"]
        # Observable (the sabotage check): the PID is STILL ALIVE,
        # contradicting the claim.
        assert cu._pid_alive(child.pid), (
            "sabotage smoke: PID should still be alive (the no-op didn't "
            "actually kill it); if this fails, the sabotage isn't actually "
            "no-op and test 4's assertion isn't meaningful."
        )
    finally:
        try:
            child.terminate()
            child.wait(timeout=2)
        except Exception:
            try:
                child.kill()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test 13 — CLI exit code semantics
# ---------------------------------------------------------------------------


def test_uninstall_cli_exit_codes(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": False)

    # 1. --dry-run exits 0 + emits "dry_run" in JSON.
    runner = CliRunner()
    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = runner.invoke(main, ["uninstall", "--dry-run", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "dry_run"

    # 2. Halted exit code is 2.
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": True)
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = runner.invoke(main, ["uninstall", "--yes", "--json"])
    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "halted"


# ---------------------------------------------------------------------------
# Test 14 — manual reminders are surfaced (honest about what we DON'T do)
# ---------------------------------------------------------------------------


def test_uninstall_surfaces_manual_reminders(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per [[creates-never-mutates]] uninstall must SAY OUT LOUD what
    it will NOT touch (shell profiles, MCP config, browser CAs)."""
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    inv = cu._inventory_installed_state()
    reminders = inv.get("manual_reminders") or []
    # Each of the per-product caveats from MRR-4-UNINSTALL.md must be
    # represented.
    joined = " ".join(reminders).lower()
    assert "shell profile" in joined or "https_proxy" in joined
    assert "mcp" in joined
    assert "gbounce mitm ca" in joined or "truststore" in joined
    assert "systemd" in joined or "launchd" in joined


# ---------------------------------------------------------------------------
# #574 — port-owner cross-reference catches Python console-script bouncers
# that pgrep -x misses
# ---------------------------------------------------------------------------


def test_uninstall_dry_run_detects_python_module_invocation(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#574 root case: ibounce launched as `python -m iam_jit.bouncer_cli`
    is invisible to ``pgrep -x ibounce`` (kernel-reported basename is
    the Python interpreter). Cross-referencing bound-port owners via
    ``lsof -t`` then ``ps -p PID -o command=`` recovers the real PID.
    """
    _seed_install(isolated_iam_jit_home)

    # No matches via the pgrep path.
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    # Bouncer port 7401 is bound.
    monkeypatch.setattr(
        cu, "_port_bound",
        lambda port, host="127.0.0.1": port == 7401,
    )

    # lsof reveals PID 54321 as the owner.
    fake_pid = 54321
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: [fake_pid] if port == 7401 else [],
    )

    # ps -p PID -o command= reveals a `python ... ibounce run --port 7401`
    # invocation — exactly the shape that defeats `pgrep -x ibounce`.
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: (
            "/opt/homebrew/bin/python3.12 "
            "/Users/reagan/.iam-jit/venv/bin/ibounce run --port 7401"
            if pid == fake_pid else ""
        ),
    )

    # Observable: the plan's running_bouncers includes our PID under
    # the inferred bouncer name.
    inv = cu._inventory_installed_state()
    assert 7401 in inv["bound_ports"]
    assert "ibounce" in inv["running_bouncers"], (
        f"port-owner cross-reference failed to find PID {fake_pid} "
        f"behind bound port 7401; got running_bouncers={inv['running_bouncers']}"
    )
    assert fake_pid in inv["running_bouncers"]["ibounce"]
    # No unknown owners (this PID was positively identified as a bouncer).
    assert not inv.get("unknown_port_owners")

    # Observable: the dry-run plan's stop_bouncers step targets our PID.
    result = cu.run_uninstall(dry_run=True)
    assert result["status"] == "dry_run"
    stop = result["steps"]["stop_bouncers"]
    assert fake_pid in stop["sigterm_pids"], (
        f"dry-run plan did not enumerate PID {fake_pid} for SIGTERM; "
        f"got stop_bouncers={stop}"
    )


def test_uninstall_dry_run_port_owner_cross_referenced_multi_port(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#574 dev-machine shape: two ibounce instances on two ports
    (the founder's machine had PIDs 99225 on :7401 and 94660 on :8767).
    BOTH PIDs must appear in the plan.
    """
    _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    port_to_pid = {7401: 99225, 8767: 94660}
    monkeypatch.setattr(
        cu, "_port_bound",
        lambda port, host="127.0.0.1": port in port_to_pid,
    )
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: [port_to_pid[port]] if port in port_to_pid else [],
    )

    def fake_cmdline(pid: int) -> str:
        for p, owner_pid in port_to_pid.items():
            if pid == owner_pid:
                return (
                    f"/opt/homebrew/bin/python3.12 "
                    f"/Users/reagan/.iam-jit/venv/bin/ibounce run --port {p}"
                )
        return ""

    monkeypatch.setattr(cu, "_read_cmdline", fake_cmdline)

    inv = cu._inventory_installed_state()
    # Observable: BOTH PIDs appear under "ibounce".
    assert "ibounce" in inv["running_bouncers"]
    pids = inv["running_bouncers"]["ibounce"]
    assert 99225 in pids, f"PID 99225 (port 7401) missing; got {pids}"
    assert 94660 in pids, f"PID 94660 (port 8767) missing; got {pids}"

    # Observable: the stop plan targets both.
    result = cu.run_uninstall(dry_run=True)
    stop = result["steps"]["stop_bouncers"]
    assert 99225 in stop["sigterm_pids"]
    assert 94660 in stop["sigterm_pids"]


def test_uninstall_dry_run_detects_native_ibounce_binary(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#574 regression: native binary invocations (pgrep -x DOES match)
    keep working after the port-owner cross-reference is added.
    """
    _seed_install(isolated_iam_jit_home)

    # pgrep finds ibounce as the native binary (e.g. compiled console
    # script with argv[0] == "ibounce").
    monkeypatch.setattr(
        cu, "_find_pids_for_process",
        lambda name: [11111] if name == "ibounce" else [],
    )
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": False)
    monkeypatch.setattr(cu, "_lsof_pids_on_port", lambda port: [])
    monkeypatch.setattr(cu, "_read_cmdline", lambda pid: "")

    inv = cu._inventory_installed_state()
    assert inv["running_bouncers"].get("ibounce") == [11111]


def test_uninstall_dry_run_dedup_pid_from_both_methods(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#574: if BOTH pgrep AND port-owner cross-reference report the
    same PID, the inventory must deduplicate (no double-SIGTERM).
    """
    _seed_install(isolated_iam_jit_home)

    same_pid = 77777
    monkeypatch.setattr(
        cu, "_find_pids_for_process",
        lambda name: [same_pid] if name == "ibounce" else [],
    )
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    monkeypatch.setattr(
        cu, "_port_bound", lambda port, host="127.0.0.1": port == 7401,
    )
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: [same_pid] if port == 7401 else [],
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: f"ibounce run --port 7401" if pid == same_pid else "",
    )

    inv = cu._inventory_installed_state()
    # Observable: PID appears EXACTLY ONCE across all running_bouncers.
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    assert flat_pids.count(same_pid) == 1, (
        f"PID {same_pid} appeared {flat_pids.count(same_pid)}x — must be "
        f"deduped. running_bouncers={inv['running_bouncers']}"
    )

    # Observable: stop plan also lists once.
    result = cu.run_uninstall(dry_run=True)
    stop = result["steps"]["stop_bouncers"]
    assert stop["sigterm_pids"].count(same_pid) == 1


def test_uninstall_dry_run_excludes_unrelated_python_procs_on_ports(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#574 honest framing: a foreign python process holding a
    bouncer-typical port is NOT silently included in stop_bouncers
    (uninstall would SIGTERM a stranger's process). It's surfaced as
    an "unknown_port_owners" entry instead, and trips the U-2 halt.
    """
    _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    foreign_pid = 88888
    monkeypatch.setattr(
        cu, "_port_bound", lambda port, host="127.0.0.1": port == 7401,
    )
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: [foreign_pid] if port == 7401 else [],
    )
    # Cmdline does NOT match any bouncer pattern (unrelated python
    # web server on the same port).
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: (
            "python -m http.server 7401" if pid == foreign_pid else ""
        ),
    )

    inv = cu._inventory_installed_state()
    # Observable: foreign PID NOT in running_bouncers (no SIGTERM).
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    assert foreign_pid not in flat_pids, (
        f"foreign PID {foreign_pid} on port 7401 was silently included "
        f"in running_bouncers; got {inv['running_bouncers']}"
    )

    # Observable: foreign PID IS surfaced in unknown_port_owners with
    # its cmdline (so operator can investigate).
    unknowns = inv["unknown_port_owners"]
    assert len(unknowns) == 1
    assert unknowns[0]["pid"] == foreign_pid
    assert unknowns[0]["port"] == 7401
    assert "http.server" in unknowns[0]["cmdline"]

    # Observable: U-2 halt fires (the canonical "investigate before
    # --force" signal per [[ibounce-honest-positioning]]).
    halts = cu._check_halt_conditions(inv)
    halt_ids = [h["id"] for h in halts]
    assert "U-2" in halt_ids, f"U-2 halt missing; got halts={halts}"


def test_uninstall_sabotage_no_op_cross_reference_is_load_bearing(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage-check per CONTRIBUTING.md: prove the port-owner
    cross-reference is load-bearing. If we monkeypatch
    ``_lsof_pids_on_port`` to a no-op, the Python console-script
    bouncer at PID 54321 should disappear from the plan — proving the
    detection-via-port-owner code path is what's catching it (not some
    other coincidental path).
    """
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    monkeypatch.setattr(
        cu, "_port_bound", lambda port, host="127.0.0.1": port == 7401,
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: (
            "/opt/homebrew/bin/python3.12 "
            "/Users/reagan/.iam-jit/venv/bin/ibounce run --port 7401"
        ),
    )

    # Sabotage: _lsof_pids_on_port returns nothing despite port bound.
    monkeypatch.setattr(cu, "_lsof_pids_on_port", lambda port: [])

    inv = cu._inventory_installed_state()
    # The OBSERVABLE failure: ibounce is NOT in running_bouncers (the
    # bug we're fixing). If this assertion FAILS, the new code path
    # isn't the load-bearing one and another mechanism is finding the
    # PID — meaning the fix isn't isolated.
    assert "ibounce" not in inv["running_bouncers"], (
        "sabotage smoke: with _lsof_pids_on_port no-op, ibounce should "
        "NOT be detected. If it IS detected, some other mechanism "
        "(not the #574 fix) is finding it — the fix isn't isolated."
    )
    # And the port-bound-without-owner case still trips U-1 halt
    # (no foreign cmdline returned since lsof is no-op).
    halts = cu._check_halt_conditions(inv)
    assert any(h["id"] == "U-1" for h in halts)


def test_uninstall_dry_run_real_lsof_and_ps_end_to_end(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """#574 end-to-end smoke: spawn a real Python subprocess that
    binds a high port AND has an ibounce-like cmdline, then verify the
    REAL lsof + ps pipeline finds it (no stubs on _lsof_pids_on_port
    / _read_cmdline / _port_bound). This is the "actually-shells-out"
    version of the unit tests above.
    """
    if shutil.which("lsof") is None or shutil.which("ps") is None:
        pytest.skip("requires lsof + ps on PATH")

    # Reserve a free high port via ephemeral allocation; hand it to
    # the subprocess via SO_REUSEADDR so the kernel rebind succeeds.
    import socket as _socket
    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    test_port = sock.getsockname()[1]
    sock.close()

    # Pin the inventory to ONLY this port so we don't pick up other
    # bouncers on the dev machine.
    monkeypatch.setattr(cu, "BOUNCER_PORTS", (test_port,))
    # Restore the REAL helpers (default-isolation fixture stubs them
    # to no-ops); this test EXERCISES the real lsof + ps + TCP-probe
    # pipeline against our subprocess.
    monkeypatch.setattr(cu, "_port_bound", _REAL_PORT_BOUND)
    monkeypatch.setattr(cu, "_lsof_pids_on_port", _REAL_LSOF_PIDS_ON_PORT)
    monkeypatch.setattr(cu, "_read_cmdline", _REAL_READ_CMDLINE)

    # Write a fake "ibounce" launcher script + spawn it. The script
    # name in argv lets _read_cmdline -> ps see "ibounce run --port N".
    fake_ibounce = tmp_path / "ibounce"
    fake_ibounce.write_text(
        "#!/usr/bin/env python3\n"
        "import socket, sys, time\n"
        "port = int(sys.argv[sys.argv.index('--port') + 1])\n"
        "s = socket.socket()\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "s.bind(('127.0.0.1', port)); s.listen(1)\n"
        "sys.stdout.write('READY\\n'); sys.stdout.flush()\n"
        "time.sleep(60)\n"
    )
    fake_ibounce.chmod(0o755)

    proc = subprocess.Popen(
        [sys.executable, str(fake_ibounce), "run", "--port", str(test_port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        # Wait for READY signal (up to 5s) — use line buffering.
        ready_deadline = time.time() + 5.0
        ready = False
        while time.time() < ready_deadline:
            if proc.poll() is not None:
                break
            line = proc.stdout.readline() if proc.stdout else ""
            if "READY" in line:
                ready = True
                break
            if not line:
                time.sleep(0.05)
        if not ready:
            stderr = proc.stderr.read() if proc.stderr else ""
            pytest.skip(
                f"fake bouncer did not bind port {test_port} in time; "
                f"poll={proc.poll()} stderr={stderr[:300]}"
            )

        # Keep _find_pids_for_process stubbed so we don't pick up real
        # bouncers on the dev machine — we only want our subprocess.
        monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])

        inv = cu._inventory_installed_state()

        # Observable: the test_port shows in bound_ports (real TCP probe).
        assert test_port in inv["bound_ports"], (
            f"port {test_port} should be bound by our subprocess; "
            f"got {inv['bound_ports']}"
        )
        # Observable: our PID was cross-referenced via real lsof+ps
        # and identified as ibounce.
        all_detected = []
        for pids in inv["running_bouncers"].values():
            all_detected.extend(pids)
        assert proc.pid in all_detected, (
            f"end-to-end lsof+ps did NOT detect PID {proc.pid} on port "
            f"{test_port}; running_bouncers={inv['running_bouncers']}, "
            f"unknown_port_owners={inv.get('unknown_port_owners')}"
        )
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
