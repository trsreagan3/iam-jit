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
import subprocess
import sys
import time
from typing import Any
from unittest import mock

import pytest
from click.testing import CliRunner

import iam_jit.cli_uninstall as cu
from iam_jit.cli import main


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
    """
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": False)


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
