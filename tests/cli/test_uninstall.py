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
import socket
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

    #608: also stub posture.bouncers._loopback_port_open since the
    U-3 posture-uninstall parity halt calls into posture's detector;
    without a stub, posture would see the dev machine's running
    bouncers and fire U-3 in tests that intend a clean baseline.

    #614: also stub the multi-factor classifier helpers
    (_resolve_executable_path + _pid_owner_uid) so they don't shell
    out to lsof / ps on the dev machine. Default: path resolves under
    ``~/.iam-jit/venv/bin/<derived-from-cmdline>`` AND owner UID is
    current user — i.e. the "happy path" expected by pre-#614 tests
    that just want a positive classification. Tests that exercise the
    multi-factor logic itself override these.

    #617 HIGH-3: also stub the four cross-product artifact checkers
    (_check_path_binaries, _check_bouncer_config_dirs,
    _detect_shell_rc_lines, _check_mcp_entries) so they don't walk
    the dev machine's real PATH / filesystem / shell RCs / claude.json.
    Tests that exercise these checkers pass fixture overrides via
    ``claude_json_path`` or monkeypatch these stubs directly.
    """
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": False)
    monkeypatch.setattr(cu, "_lsof_pids_on_port", lambda port: [])
    monkeypatch.setattr(cu, "_read_cmdline", lambda pid: "")
    # #617 MED-2: also stub _all_listening_ports so the custom-port scan
    # doesn't shell out to the dev machine's lsof/ss. Default: empty list
    # (no custom-port bouncers visible). Tests that exercise custom-port
    # detection override this stub per-test.
    monkeypatch.setattr(cu, "_all_listening_ports", lambda: [])
    # #608: isolate posture's loopback probes too.
    from iam_jit.posture import bouncers as _posture_bouncers
    monkeypatch.setattr(
        _posture_bouncers,
        "_loopback_port_open",
        lambda port, host="127.0.0.1", timeout=0.25: False,
    )
    # #614: by default, multi-factor checks PASS for any port-owner
    # the test seeds (so existing tests that only stub _read_cmdline
    # continue to classify positively). The flag-signature check still
    # gates classification; tests that want a positive result must
    # provide a cmdline containing a real bouncer flag, OR override
    # these stubs.
    import pathlib as _pathlib
    fake_install_dir = _pathlib.Path.home() / ".iam-jit" / "venv" / "bin"
    def _fake_exe(pid: int) -> _pathlib.Path | None:
        # Map "obviously kbounce" / "obviously ibounce" cmdlines to a
        # binary under the install root. Caller may override with a
        # tighter monkeypatch.
        cmd = cu._read_cmdline(pid) or ""
        for k in ("kbouncer", "ibounce", "kbounce", "dbounce", "gbounce"):
            if k in cmd:
                return fake_install_dir / k
        # Default: pretend it's under the install root anyway, so the
        # flag-signature check is the deciding factor.
        return fake_install_dir / "ibounce"
    monkeypatch.setattr(cu, "_resolve_executable_path", _fake_exe)
    monkeypatch.setattr(cu, "_pid_owner_uid", lambda pid: os.geteuid())
    # #617 HIGH-3: stub cross-product artifact checkers so tests don't
    # walk the dev machine's real PATH / filesystem / shell RCs /
    # ~/.claude.json. Default: no artifacts found (clean baseline).
    monkeypatch.setattr(cu, "_check_path_binaries", lambda: [])
    monkeypatch.setattr(cu, "_check_bouncer_config_dirs", lambda: [])
    monkeypatch.setattr(cu, "_detect_shell_rc_lines", lambda: [])
    monkeypatch.setattr(
        cu, "_check_mcp_entries",
        lambda claude_json_path=None: [],
    )


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
    # #614: include a bouncer-specific flag signature so the multi-
    # factor classifier accepts it.
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: (
            "/opt/homebrew/bin/python3.12 "
            "/Users/testop/.iam-jit/venv/bin/ibounce run "
            "--mode discovery --proxy-port 7401"
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
                # #614: bouncer-specific flag (--proxy-port) required
                # for multi-factor classification.
                return (
                    f"/opt/homebrew/bin/python3.12 "
                    f"/Users/testop/.iam-jit/venv/bin/ibounce run "
                    f"--mode discovery --proxy-port {p}"
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
        lambda pid: (
            "ibounce run --mode discovery --proxy-port 7401"
            if pid == same_pid else ""
        ),
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
            "/Users/testop/.iam-jit/venv/bin/ibounce run "
            "--mode discovery --proxy-port 7401"
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
    # bouncers on the dev machine. #608: also pin
    # _BOUNCER_DEFAULT_PORTS (the per-bouncer map is the authoritative
    # scan list now, not BOUNCER_PORTS).
    monkeypatch.setattr(cu, "BOUNCER_PORTS", (test_port,))
    monkeypatch.setattr(
        cu, "_BOUNCER_DEFAULT_PORTS", {"ibounce": (test_port,)},
    )
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

    # #614: include bouncer-specific flag signature so the multi-
    # factor classifier accepts the subprocess. The real python
    # interpreter at sys.executable is NOT under a known install root,
    # so we override _resolve_executable_path to claim it IS under
    # ~/.iam-jit/venv/bin/ibounce for this specific PID (the rest of
    # the lsof + ps + TCP-probe pipeline stays REAL).
    proc = subprocess.Popen(
        [
            sys.executable, str(fake_ibounce),
            "run", "--port", str(test_port),
            "--mode", "discovery", "--proxy-port", str(test_port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # Override path-check to PASS for our spawned PID only (other PIDs
    # see real-lookup so a foreign process can't sneak in).
    spawned_pid = proc.pid
    fake_install_dir = pathlib.Path.home() / ".iam-jit" / "venv" / "bin"
    monkeypatch.setattr(
        cu, "_resolve_executable_path",
        lambda pid: (
            fake_install_dir / "ibounce" if pid == spawned_pid else None
        ),
    )
    monkeypatch.setattr(cu, "_pid_owner_uid", lambda pid: os.geteuid())
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


# ---------------------------------------------------------------------------
# #608 — cross-product parity: kbounce / dbounce / gbounce on their own
# default ports must be detected the same way #574 detects ibounce
# ---------------------------------------------------------------------------


def _fake_cmdline_for(kind: str, port: int) -> str:
    """Helper: cmdline shape that the multi-factor classifier (#614)
    will positively classify as ``kind``.

    Each kind needs at least ONE bouncer-specific flag signature from
    :data:`cu._BOUNCER_FLAG_SIGNATURES` to pass the flag-check.
    """
    flag_per_kind = {
        "ibounce": "--mode discovery --proxy-port 7401",
        "kbounce": "--apiserver-url https://kube.local",
        "kbouncer": "--apiserver-url https://kube.local",
        "dbounce": "--dialect postgres --upstream-conn-string ignored",
        "gbounce": "--http-mode --allow-host example.com",
    }
    flags = flag_per_kind.get(kind, "")
    return (
        f"/Users/op/go/bin/{kind} run --port {port} {flags}"
    )


def test_uninstall_detects_kbouncer_on_default_port(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#608 Gap D: kbounce on its default port :8766 must be detected
    via the port-owner cross-reference, the same way #574 catches
    ibounce on :7401 / :8767.
    """
    _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    # Only kbounce default port :8766 is bound.
    monkeypatch.setattr(
        cu, "_port_bound", lambda port, host="127.0.0.1": port == 8766,
    )
    fake_pid = 12345
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: [fake_pid] if port == 8766 else [],
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: _fake_cmdline_for("kbounce", 8766) if pid == fake_pid else "",
    )

    inv = cu._inventory_installed_state()
    assert 8766 in inv["bound_ports"], (
        f"kbounce default port :8766 not detected as bound; "
        f"bound_ports={inv['bound_ports']}"
    )
    assert "kbounce" in inv["running_bouncers"], (
        f"kbounce PID {fake_pid} on :8766 not detected via port-owner "
        f"cross-reference; got running_bouncers={inv['running_bouncers']}"
    )
    assert fake_pid in inv["running_bouncers"]["kbounce"]


def test_uninstall_detects_dbounce_on_default_ports(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#608 Gap D: dbounce on its default ports :5433 (wire) and
    :8768 (mgmt) must both be detected.
    """
    _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    port_to_pid = {5433: 22221, 8768: 22222}
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
                return _fake_cmdline_for("dbounce", p)
        return ""

    monkeypatch.setattr(cu, "_read_cmdline", fake_cmdline)

    inv = cu._inventory_installed_state()
    assert 5433 in inv["bound_ports"]
    assert 8768 in inv["bound_ports"]
    assert "dbounce" in inv["running_bouncers"]
    pids = inv["running_bouncers"]["dbounce"]
    assert 22221 in pids, f"dbounce :5433 owner missing; got {pids}"
    assert 22222 in pids, f"dbounce :8768 owner missing; got {pids}"


def test_uninstall_detects_gbounce_on_default_ports(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#608 Gap D: gbounce on its default ports :8080 (wire) and
    :8769 (mgmt) must both be detected.
    """
    _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    port_to_pid = {8080: 33331, 8769: 33332}
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
                return _fake_cmdline_for("gbounce", p)
        return ""

    monkeypatch.setattr(cu, "_read_cmdline", fake_cmdline)

    inv = cu._inventory_installed_state()
    assert 8080 in inv["bound_ports"]
    assert 8769 in inv["bound_ports"]
    assert "gbounce" in inv["running_bouncers"]
    pids = inv["running_bouncers"]["gbounce"]
    assert 33331 in pids, f"gbounce :8080 owner missing; got {pids}"
    assert 33332 in pids, f"gbounce :8769 owner missing; got {pids}"


def test_uninstall_all_4_bouncers_simultaneously_detected(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#608 Gap D: when all 4 bouncers are running on their default
    ports, the uninstall plan must enumerate ALL of them — not just
    ibounce (the #574 fix's regression direction).
    """
    _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    # Per-bouncer + per-port owner map.
    port_to_kind_pid: dict[int, tuple[str, int]] = {
        8767: ("ibounce", 41111),
        8766: ("kbounce", 42222),
        5433: ("dbounce", 43331),
        8768: ("dbounce", 43332),
        8080: ("gbounce", 44441),
        8769: ("gbounce", 44442),
    }
    monkeypatch.setattr(
        cu, "_port_bound",
        lambda port, host="127.0.0.1": port in port_to_kind_pid,
    )
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: (
            [port_to_kind_pid[port][1]] if port in port_to_kind_pid else []
        ),
    )

    def fake_cmdline(pid: int) -> str:
        for p, (kind, owner_pid) in port_to_kind_pid.items():
            if pid == owner_pid:
                return _fake_cmdline_for(kind, p)
        return ""

    monkeypatch.setattr(cu, "_read_cmdline", fake_cmdline)

    inv = cu._inventory_installed_state()
    detected_kinds = set(inv["running_bouncers"].keys())
    # Observable: ALL 4 bouncer kinds appear.
    for expected_kind in ("ibounce", "kbounce", "dbounce", "gbounce"):
        assert expected_kind in detected_kinds, (
            f"{expected_kind} missing from running_bouncers; "
            f"got {detected_kinds}"
        )
    # Observable: every PID we seeded appears in the plan.
    flat_pids = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    for _, expected_pid in port_to_kind_pid.values():
        assert expected_pid in flat_pids, (
            f"PID {expected_pid} missing; got flat_pids={flat_pids}"
        )

    # Observable: the stop_bouncers dry-run plan targets every PID.
    result = cu.run_uninstall(dry_run=True)
    stop = result["steps"]["stop_bouncers"]
    for _, expected_pid in port_to_kind_pid.values():
        assert expected_pid in stop["sigterm_pids"], (
            f"dry-run plan did not enumerate PID {expected_pid}; "
            f"stop_bouncers={stop}"
        )


def test_uninstall_posture_parity_check_detects_uninstall_blind_spot(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#608 U-3: when posture detects a bouncer that uninstall does
    NOT (the actual UAT-Admin-CLI Gap D shape), the parity check must
    fire and halt uninstall. This is defense-in-depth against future
    _BOUNCER_DEFAULT_PORTS drift.
    """
    _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    # Simulate uninstall's port-scan missing kbounce (e.g. because
    # _BOUNCER_DEFAULT_PORTS got mistakenly stripped).
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": False)

    # Simulate posture detecting kbounce on :8766 (its actual default).
    from iam_jit.posture import bouncers as _posture_bouncers
    monkeypatch.setattr(
        _posture_bouncers,
        "_loopback_port_open",
        lambda port, host="127.0.0.1", timeout=0.25: (
            port == _posture_bouncers.KBOUNCE_DEFAULT_PORT
        ),
    )

    inv = cu._inventory_installed_state()
    halts = cu._check_halt_conditions(inv)
    halt_ids = [h["id"] for h in halts]
    assert "U-3" in halt_ids, (
        f"posture sees kbounce on :8766 but uninstall doesn't — "
        f"U-3 halt should fire; got halts={halts}"
    )
    # Observable: the halt reason names the missing bouncer.
    u3 = next(h for h in halts if h["id"] == "U-3")
    assert "kbounce" in u3["reason"], (
        f"U-3 reason should name the missing bouncer; got {u3['reason']}"
    )


def test_uninstall_posture_parity_check_does_not_fire_when_aligned(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#608 U-3 negative case: when uninstall + posture agree, no
    parity halt fires. (Guards against false-positive U-3 noise.)
    """
    _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    # Uninstall sees kbounce.
    monkeypatch.setattr(
        cu, "_port_bound", lambda port, host="127.0.0.1": port == 8766,
    )
    fake_pid = 51234
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: [fake_pid] if port == 8766 else [],
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: _fake_cmdline_for("kbounce", 8766) if pid == fake_pid else "",
    )
    # Posture sees the same kbounce.
    from iam_jit.posture import bouncers as _posture_bouncers
    monkeypatch.setattr(
        _posture_bouncers,
        "_loopback_port_open",
        lambda port, host="127.0.0.1", timeout=0.25: (
            port == _posture_bouncers.KBOUNCE_DEFAULT_PORT
        ),
    )

    inv = cu._inventory_installed_state()
    halts = cu._check_halt_conditions(inv)
    halt_ids = [h["id"] for h in halts]
    assert "U-3" not in halt_ids, (
        f"U-3 should NOT fire when both surfaces agree on kbounce; "
        f"got halts={halts}"
    )


def test_uninstall_regression_ibounce_still_detected_after_608(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#608 regression: #574's original ibounce-on-:7401 detection
    path must still work after the per-bouncer port refactor.
    """
    _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    monkeypatch.setattr(
        cu, "_port_bound", lambda port, host="127.0.0.1": port == 7401,
    )
    fake_pid = 61234
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: [fake_pid] if port == 7401 else [],
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: (
            "/opt/homebrew/bin/python3.12 "
            "/Users/op/.iam-jit/venv/bin/ibounce run "
            "--mode discovery --proxy-port 7401"
            if pid == fake_pid else ""
        ),
    )

    inv = cu._inventory_installed_state()
    assert 7401 in inv["bound_ports"]
    assert "ibounce" in inv["running_bouncers"]
    assert fake_pid in inv["running_bouncers"]["ibounce"]


def test_uninstall_unknown_port_owner_includes_expected_bouncer(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#608: when a foreign process holds a bouncer-default port, the
    unknown_port_owners entry must include the expected bouncer name
    so the operator can investigate ("expected kbounce on :8766;
    found python http.server instead").
    """
    _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    monkeypatch.setattr(
        cu, "_port_bound", lambda port, host="127.0.0.1": port == 8766,
    )
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: [98765] if port == 8766 else [],
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: "python -m http.server 8766" if pid == 98765 else "",
    )

    inv = cu._inventory_installed_state()
    unknowns = inv["unknown_port_owners"]
    assert len(unknowns) == 1
    u = unknowns[0]
    assert u["pid"] == 98765
    assert u["port"] == 8766
    assert u["expected_bouncer"] == "kbounce", (
        f"expected_bouncer should be 'kbounce' for :8766; got {u}"
    )


def test_uninstall_sabotage_default_ports_strip_kbounce_loses_detection(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#608 sabotage-check per CONTRIBUTING.md: prove the
    _BOUNCER_DEFAULT_PORTS extension is load-bearing. If we
    monkeypatch the constant to strip kbounce's entry, a kbounce
    process on :8766 must DISAPPEAR from the inventory — proving the
    per-bouncer port set is what's catching it (not some other
    coincidental path).
    """
    _seed_install(isolated_iam_jit_home)

    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    fake_pid = 71234
    monkeypatch.setattr(
        cu, "_port_bound", lambda port, host="127.0.0.1": port == 8766,
    )
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: [fake_pid] if port == 8766 else [],
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: _fake_cmdline_for("kbounce", 8766),
    )

    # Sabotage: strip kbounce from the per-bouncer map. Now :8766 is
    # no longer scanned.
    sabotaged = {
        k: v for k, v in cu._BOUNCER_DEFAULT_PORTS.items()
        if k not in ("kbounce", "kbouncer")
    }
    monkeypatch.setattr(cu, "_BOUNCER_DEFAULT_PORTS", sabotaged)

    inv = cu._inventory_installed_state()
    assert "kbounce" not in inv["running_bouncers"], (
        "sabotage smoke: with kbounce stripped from "
        "_BOUNCER_DEFAULT_PORTS, kbounce on :8766 should NOT be "
        "detected. If it IS, some other code path (not the per-"
        "bouncer port map) is finding it — the #608 fix isn't isolated."
    )
    assert 8766 not in inv["bound_ports"], (
        f"sabotage smoke: :8766 should not be in bound_ports when "
        f"kbounce is stripped from _BOUNCER_DEFAULT_PORTS; "
        f"got bound_ports={inv['bound_ports']}"
    )


# ---------------------------------------------------------------------------
# #614 CRIT — multi-factor bouncer classification (path + flag + user)
#
# Per UAT-Lifecycle 2026-05-25 HIGH-2: substring-classification of a
# foreign /tmp/dbounce-test process led to SIGTERM outside iam-jit's
# domain. These tests prove the multi-factor check protects foreign
# processes per [[creates-never-mutates]].
# ---------------------------------------------------------------------------


def _seed_unknown_port_owner(
    monkeypatch: pytest.MonkeyPatch,
    *,
    port: int,
    pid: int,
    cmdline: str,
    exe_path: pathlib.Path | None,
    owner_uid: int | None,
) -> None:
    """Helper: wire up the four monkeypatches that drive multi-factor
    classification for ``pid`` on ``port``. Tests vary one factor at a
    time to drive specific failure paths."""
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_port_bound", lambda p, host="127.0.0.1": p == port,
    )
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda p: [pid] if p == port else [],
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda p: cmdline if p == pid else "",
    )
    monkeypatch.setattr(
        cu, "_resolve_executable_path",
        lambda p: exe_path if p == pid else None,
    )
    monkeypatch.setattr(
        cu, "_pid_owner_uid",
        lambda p: owner_uid if p == pid else None,
    )


def test_foreign_process_with_bouncer_name_in_cmdline_not_killed(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#614 CRIT: a foreign process whose cmdline incidentally contains
    "dbounce" (e.g. /tmp/dbounce-test from a different shell session)
    must NOT be classified as a real dbounce.

    Pre-#614: substring-match said "this is dbounce" → uninstall
    SIGTERM'd it. This is the EXACT scenario UAT-Lifecycle 2026-05-25
    HIGH-2 caught.
    """
    _seed_install(isolated_iam_jit_home)

    # /tmp/dbounce-test on port 5433 — cmdline contains "dbounce" but:
    #   - executable path is /tmp/dbounce-test (NOT under install root)
    #   - cmdline has no bouncer-specific flag signature
    foreign_pid = 99001
    _seed_unknown_port_owner(
        monkeypatch,
        port=5433,
        pid=foreign_pid,
        cmdline="/tmp/dbounce-test run --audit-log-path /tmp/foo.jsonl",
        # NOTE: --audit-log-path is an ibounce flag, not a dbounce flag.
        # Even though the cmdline contains "dbounce" (in the path) AND
        # an ibounce flag, the path-origin check must STILL fail
        # because /tmp/dbounce-test is not under any known install root.
        exe_path=pathlib.Path("/tmp/dbounce-test"),
        owner_uid=os.geteuid(),
    )

    inv = cu._inventory_installed_state()

    # Observable: NOT in running_bouncers.
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    assert foreign_pid not in flat_pids, (
        f"#614 CRIT: foreign /tmp/dbounce-test (pid={foreign_pid}) "
        f"silently classified as bouncer; running_bouncers="
        f"{inv['running_bouncers']}"
    )

    # Observable: IS in unknown_port_owners.
    unknown_pids = [u["pid"] for u in inv["unknown_port_owners"]]
    assert foreign_pid in unknown_pids, (
        f"#614 CRIT: foreign PID must surface in unknown_port_owners "
        f"for operator review; got {inv['unknown_port_owners']}"
    )
    # Observable: failed_checks field explains WHY classification failed.
    foreign_entry = next(
        u for u in inv["unknown_port_owners"] if u["pid"] == foreign_pid
    )
    assert foreign_entry.get("failed_checks"), (
        f"failed_checks must be present so operator sees why: {foreign_entry}"
    )
    failed_text = " ".join(foreign_entry["failed_checks"])
    assert "install root" in failed_text or "executable" in failed_text, (
        f"failed_checks should call out the path failure: {failed_text}"
    )

    # Observable: U-5 halt fires (refuses uninstall without --force).
    halts = cu._check_halt_conditions(inv)
    halt_ids = [h["id"] for h in halts]
    assert "U-5" in halt_ids, (
        f"#614 U-5 halt must fire when foreign process detected; "
        f"got halts={halts}"
    )

    # Observable end-to-end: run_uninstall halts (no destructive steps).
    result = cu.run_uninstall(dry_run=False, force=False)
    assert result["status"] == "halted"
    # Observable: the seeded install state is INTACT (nothing removed).
    assert (isolated_iam_jit_home / "bouncer" / "state.db").exists()
    assert (isolated_iam_jit_home / "venv" / "bin" / "ibounce").exists()


def test_real_bouncer_install_path_correctly_classified(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#614: a REAL dbounce at ~/go/bin/dbounce with --dialect postgres
    flag, owned by current user, must classify correctly (regression
    guard against over-tightening)."""
    _seed_install(isolated_iam_jit_home)

    real_pid = 99002
    real_exe = pathlib.Path.home() / "go" / "bin" / "dbounce"
    _seed_unknown_port_owner(
        monkeypatch,
        port=5433,
        pid=real_pid,
        cmdline=(
            f"{real_exe} run --dialect postgres "
            "--upstream-conn-string postgres://x"
        ),
        exe_path=real_exe,
        owner_uid=os.geteuid(),
    )

    inv = cu._inventory_installed_state()

    # Observable: classified as dbounce.
    assert "dbounce" in inv["running_bouncers"], (
        f"real dbounce at {real_exe} with --dialect postgres flag "
        f"should classify; got {inv['running_bouncers']} unknown="
        f"{inv['unknown_port_owners']}"
    )
    assert real_pid in inv["running_bouncers"]["dbounce"]
    # Observable: NOT in unknown_port_owners.
    unknown_pids = [u["pid"] for u in inv["unknown_port_owners"]]
    assert real_pid not in unknown_pids


def test_path_check_fails_defaults_to_unknown(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#614: when _resolve_executable_path returns None (permission
    denied / race / etc.) the safer default is to classify as
    unknown — never as bouncer-by-cmdline-alone."""
    _seed_install(isolated_iam_jit_home)

    unknown_pid = 99003
    _seed_unknown_port_owner(
        monkeypatch,
        port=8766,
        pid=unknown_pid,
        cmdline="kbounce run --apiserver-url https://kube.local",
        exe_path=None,  # path lookup failed
        owner_uid=os.geteuid(),
    )

    inv = cu._inventory_installed_state()
    # Observable: NOT classified despite a matching cmdline + flag.
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    assert unknown_pid not in flat_pids, (
        "path-check failure must default to unknown — never trust "
        "cmdline alone; got running_bouncers={inv['running_bouncers']}"
    )
    # Observable: surfaced in unknown_port_owners.
    assert unknown_pid in [u["pid"] for u in inv["unknown_port_owners"]]
    # Observable: failed_checks names the path failure.
    entry = next(
        u for u in inv["unknown_port_owners"] if u["pid"] == unknown_pid
    )
    failed_text = " ".join(entry["failed_checks"])
    assert "executable" in failed_text or "path" in failed_text


def test_cross_user_process_not_killed(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#614: a process owned by a different OS user must NEVER be
    classified as ours — cross-user destruction is the worst-case
    [[creates-never-mutates]] violation."""
    _seed_install(isolated_iam_jit_home)

    other_user_pid = 99004
    real_exe = pathlib.Path.home() / "go" / "bin" / "dbounce"
    # uid 0 = root; clearly NOT current user.
    _seed_unknown_port_owner(
        monkeypatch,
        port=5433,
        pid=other_user_pid,
        cmdline=f"{real_exe} run --dialect postgres",
        exe_path=real_exe,
        owner_uid=0,
    )

    inv = cu._inventory_installed_state()
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    assert other_user_pid not in flat_pids, (
        "cross-user PID must never be classified as ours per "
        "[[creates-never-mutates]]; got "
        f"running_bouncers={inv['running_bouncers']}"
    )
    assert other_user_pid in [
        u["pid"] for u in inv["unknown_port_owners"]
    ]
    entry = next(
        u for u in inv["unknown_port_owners"]
        if u["pid"] == other_user_pid
    )
    failed_text = " ".join(entry["failed_checks"])
    assert "uid" in failed_text or "owner" in failed_text


def test_bouncer_flag_signature_required(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#614: process at correct install path + correct user but WITHOUT
    a bouncer-specific flag signature must NOT classify. This catches
    the "someone built a script called ibounce at ~/go/bin/ibounce
    that does something else entirely" scenario."""
    _seed_install(isolated_iam_jit_home)

    impostor_pid = 99005
    real_exe = pathlib.Path.home() / "go" / "bin" / "ibounce"
    _seed_unknown_port_owner(
        monkeypatch,
        port=8767,
        pid=impostor_pid,
        # Path matches AND user matches BUT no bouncer flag — just
        # generic "run" + a non-bouncer flag.
        cmdline=f"{real_exe} run --some-other-flag",
        exe_path=real_exe,
        owner_uid=os.geteuid(),
    )

    inv = cu._inventory_installed_state()
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    assert impostor_pid not in flat_pids, (
        "process without bouncer flag signature must not classify; "
        f"got running_bouncers={inv['running_bouncers']}"
    )
    entry = next(
        u for u in inv["unknown_port_owners"] if u["pid"] == impostor_pid
    )
    failed_text = " ".join(entry["failed_checks"])
    assert "flag" in failed_text or "signature" in failed_text


def test_all_4_bouncers_with_proper_paths_classified(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#614: all 4 bouncers at correct install paths with correct flag
    signatures classify correctly (parity regression guard)."""
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])

    # Layout: each bouncer at ~/go/bin/<name>, port from
    # _BOUNCER_DEFAULT_PORTS, cmdline with a flag from
    # _BOUNCER_FLAG_SIGNATURES.
    go_bin = pathlib.Path.home() / "go" / "bin"
    layout: dict[int, tuple[str, int]] = {
        8767: ("ibounce", 51001),
        8766: ("kbounce", 52001),
        5433: ("dbounce", 53001),
        8080: ("gbounce", 54001),
    }
    cmdline_per_kind = {
        "ibounce": "--mode discovery --proxy-port 8767",
        "kbounce": "--apiserver-url https://kube.local",
        "dbounce": "--dialect postgres --upstream-conn-string ignored",
        "gbounce": "--http-mode --allow-host example.com",
    }
    exe_per_pid = {p: go_bin / k for (k, p) in layout.values()}
    cmdline_per_pid = {
        p: f"{go_bin / k} run {cmdline_per_kind[k]}"
        for (k, p) in layout.values()
    }
    monkeypatch.setattr(
        cu, "_port_bound",
        lambda port, host="127.0.0.1": port in layout,
    )
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: [layout[port][1]] if port in layout else [],
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: cmdline_per_pid.get(pid, ""),
    )
    monkeypatch.setattr(
        cu, "_resolve_executable_path",
        lambda pid: exe_per_pid.get(pid),
    )
    monkeypatch.setattr(cu, "_pid_owner_uid", lambda pid: os.geteuid())

    inv = cu._inventory_installed_state()
    detected = set(inv["running_bouncers"].keys())
    for kind in ("ibounce", "kbounce", "dbounce", "gbounce"):
        assert kind in detected, (
            f"#614 parity: {kind} not classified; running_bouncers="
            f"{inv['running_bouncers']} unknown={inv['unknown_port_owners']}"
        )
    # Observable: no foreign-process halt fires (all classified).
    halts = cu._check_halt_conditions(inv)
    halt_ids = [h["id"] for h in halts]
    assert "U-5" not in halt_ids, (
        f"U-5 should NOT fire when all 4 bouncers classify; got {halts}"
    )


def test_614_sabotage_path_check_made_lenient_breaks_foreign_protection(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#614 sabotage-check per CONTRIBUTING.md: prove the path-check is
    LOAD-BEARING. If we monkeypatch the path-check to always pass,
    the foreign /tmp/dbounce-test process MUST get classified — which
    would re-introduce the CRIT bug. The fact that classification flips
    when ONLY the path-check is sabotaged proves the path-check is
    doing the protection work (not some unrelated coincidence)."""
    _seed_install(isolated_iam_jit_home)

    foreign_pid = 99006
    # Set up the foreign-process scenario from
    # test_foreign_process_with_bouncer_name_in_cmdline_not_killed
    # BUT add a real ibounce flag so the flag-check passes (only the
    # path-check should be the gate).
    _seed_unknown_port_owner(
        monkeypatch,
        port=5433,
        pid=foreign_pid,
        cmdline=(
            "/tmp/dbounce-test run --dialect postgres "
            "--upstream-conn-string ignored"
        ),
        exe_path=pathlib.Path("/tmp/dbounce-test"),
        owner_uid=os.geteuid(),
    )

    # Baseline: foreign process is NOT classified (path-check failing).
    inv_real = cu._inventory_installed_state()
    flat_real: list[int] = []
    for pids in inv_real["running_bouncers"].values():
        flat_real.extend(pids)
    assert foreign_pid not in flat_real, (
        "baseline: foreign process should not be classified (path "
        "check is doing its job)"
    )

    # SABOTAGE: make path-check unconditionally pass.
    monkeypatch.setattr(
        cu, "_path_under_known_install_root", lambda p: True,
    )

    inv_sabotaged = cu._inventory_installed_state()
    flat_sabotaged: list[int] = []
    for pids in inv_sabotaged["running_bouncers"].values():
        flat_sabotaged.extend(pids)
    assert foreign_pid in flat_sabotaged, (
        "#614 sabotage: with the path-check stubbed to always pass, "
        "the foreign /tmp/dbounce-test SHOULD now classify (which is "
        "exactly the CRIT we're preventing). If it does NOT classify, "
        "some other check is doing the protection work — meaning the "
        "path-check isn't the load-bearing gate the brief claims."
    )


# ---------------------------------------------------------------------------
# #621 MED — extend bouncer-classifier install path roots (regression
# from #614). UAT-Cross 2026-05-25 (G7): #614 multi-factor classifier
# rejected venv-installed bouncers (.venv/bin/ibounce) as "foreign,"
# blocking uninstall for every venv-install operator. Fix: include
# ~/.local/bin (pip --user) + runtime-detected sys.executable parent
# when running in a venv. Tests must show:
#   * venv-installed bouncer NOW classifies correctly
#   * sys.executable detection is wired
#   * ~/.local/bin (pip --user) is recognized
# Regression tests must show:
#   * #614 foreign /tmp/dbounce-test STILL rejected
#   * cross-user venv binary STILL rejected
# ---------------------------------------------------------------------------


def test_621_venv_installed_bouncer_classified_correctly(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """#621 MED: a bouncer installed in a project-local .venv/bin/
    must classify correctly. Pre-#621: #614's static path list omitted
    venv patterns → ibounce at ``<project>/.venv/bin/ibounce`` was
    rejected as foreign → uninstall blocked for every venv-install
    operator (the STANDARD Python install pattern).
    """
    _seed_install(isolated_iam_jit_home)

    # Simulate iam-jit running inside a project-local .venv (the UAT
    # scenario). Point sys.executable at a synthetic venv layout so the
    # runtime-detection branch of _get_known_bouncer_paths kicks in.
    fake_venv = tmp_path / ".venv"
    fake_venv_bin = fake_venv / "bin"
    fake_venv_bin.mkdir(parents=True)
    fake_python = fake_venv_bin / "python"
    fake_python.write_text("#!/bin/sh\nexit 0\n")
    fake_python.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(fake_python))
    # Make sys look like it's in a venv (base_prefix != prefix).
    monkeypatch.setattr(sys, "prefix", str(fake_venv))
    monkeypatch.setattr(sys, "base_prefix", "/usr")

    # ibounce binary installed at the venv-detected bin/.
    venv_ibounce = fake_venv_bin / "ibounce"
    venv_ibounce.write_text("#!/bin/sh\nexit 0\n")
    venv_ibounce.chmod(0o755)

    venv_pid = 62101
    _seed_unknown_port_owner(
        monkeypatch,
        port=8767,
        pid=venv_pid,
        cmdline=f"{venv_ibounce} run --mode discovery --proxy-port 8767",
        exe_path=venv_ibounce,
        owner_uid=os.geteuid(),
    )

    inv = cu._inventory_installed_state()

    # Observable: classified as ibounce (NOT foreign).
    assert "ibounce" in inv["running_bouncers"], (
        f"#621: venv-installed ibounce at {venv_ibounce} should classify; "
        f"running_bouncers={inv['running_bouncers']} "
        f"unknown_port_owners={inv['unknown_port_owners']}"
    )
    assert venv_pid in inv["running_bouncers"]["ibounce"]
    # Observable: NOT in unknown_port_owners.
    unknown_pids = [u["pid"] for u in inv["unknown_port_owners"]]
    assert venv_pid not in unknown_pids
    # Observable: U-5 halt does NOT fire (no foreign processes).
    halts = cu._check_halt_conditions(inv)
    halt_ids = [h["id"] for h in halts]
    assert "U-5" not in halt_ids, (
        f"#621: U-5 must NOT fire for legitimate venv-installed bouncer; "
        f"got halts={halts}"
    )


def test_621_sys_executable_parent_recognized_as_install_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """#621: when running in a venv, _get_known_bouncer_paths must
    include the parent of sys.executable. Without this, any non-standard
    venv path (e.g. ``my_project/.venv/bin/``, ``~/envs/foo/bin/``) is
    invisible to the classifier."""
    fake_venv = tmp_path / "custom_env"
    fake_venv_bin = fake_venv / "bin"
    fake_venv_bin.mkdir(parents=True)
    fake_python = fake_venv_bin / "python"
    fake_python.write_text("#!/bin/sh\nexit 0\n")
    fake_python.chmod(0o755)

    monkeypatch.setattr(sys, "executable", str(fake_python))
    monkeypatch.setattr(sys, "prefix", str(fake_venv))
    monkeypatch.setattr(sys, "base_prefix", "/usr")

    paths = cu._get_known_bouncer_paths()
    # Observable: sys.executable's parent (the venv bin/) is in the list.
    assert fake_venv_bin in paths or fake_venv_bin.resolve() in [
        p.resolve() for p in paths if p.exists() or True
    ], (
        f"#621: sys.executable parent {fake_venv_bin} must appear in "
        f"_get_known_bouncer_paths(); got {paths}"
    )

    # Observable: a binary at that location passes the path-under-root check.
    fake_ibounce = fake_venv_bin / "ibounce"
    fake_ibounce.write_text("#!/bin/sh\nexit 0\n")
    fake_ibounce.chmod(0o755)
    assert cu._path_under_known_install_root(fake_ibounce), (
        f"#621: ibounce at {fake_ibounce} should pass path check via "
        f"sys.executable parent detection"
    )

    # Sabotage check: when NOT in a venv (base_prefix == prefix), the
    # runtime addition is skipped, and an arbitrary tmp path must NOT
    # pass.
    monkeypatch.setattr(sys, "base_prefix", str(fake_venv))  # not a venv
    monkeypatch.setattr(sys, "prefix", str(fake_venv))
    # Need a totally unrelated path that isn't under any static root.
    foreign_exe = tmp_path / "totally_unrelated" / "ibounce"
    foreign_exe.parent.mkdir(parents=True, exist_ok=True)
    foreign_exe.write_text("#!/bin/sh\nexit 0\n")
    foreign_exe.chmod(0o755)
    assert not cu._path_under_known_install_root(foreign_exe), (
        f"#621 sabotage: outside venv-detection, an arbitrary path "
        f"{foreign_exe} must NOT pass the install-root check (otherwise "
        f"the #614 foreign-process protection is broken)"
    )


def test_621_user_local_bin_recognized_as_install_root(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#621: a bouncer installed via ``pip install --user`` lands in
    ``~/.local/bin/``. The classifier must recognize that location."""
    _seed_install(isolated_iam_jit_home)

    user_local = pathlib.Path.home() / ".local" / "bin"
    user_local_ibounce = user_local / "ibounce"

    pid = 62301
    _seed_unknown_port_owner(
        monkeypatch,
        port=8767,
        pid=pid,
        cmdline=(
            f"{user_local_ibounce} run --mode discovery "
            "--proxy-port 8767"
        ),
        exe_path=user_local_ibounce,
        owner_uid=os.geteuid(),
    )

    # Observable: ~/.local/bin appears in _get_known_bouncer_paths().
    paths_str = [str(p) for p in cu._get_known_bouncer_paths()]
    assert str(user_local) in paths_str, (
        f"#621: ~/.local/bin must be in install-path roots; got {paths_str}"
    )

    inv = cu._inventory_installed_state()
    # Observable: classified as ibounce.
    assert "ibounce" in inv["running_bouncers"], (
        f"#621: pip --user installed ibounce at {user_local_ibounce} "
        f"should classify; running_bouncers={inv['running_bouncers']} "
        f"unknown={inv['unknown_port_owners']}"
    )
    assert pid in inv["running_bouncers"]["ibounce"]


def test_621_foreign_tmp_process_still_rejected_regression_614(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """#621 REGRESSION (#614): the venv-path extension must NOT undo
    #614's foreign-process protection. A process at /tmp/dbounce-test
    must STILL be classified as foreign — even when iam-jit is itself
    running in a venv (the new runtime-detection branch must not loosen
    classification for unrelated paths)."""
    _seed_install(isolated_iam_jit_home)

    # Simulate iam-jit running in a venv (so the runtime detection
    # path is active — proving it doesn't accidentally whitelist /tmp).
    fake_venv = tmp_path / ".venv"
    fake_venv_bin = fake_venv / "bin"
    fake_venv_bin.mkdir(parents=True)
    fake_python = fake_venv_bin / "python"
    fake_python.write_text("#!/bin/sh\nexit 0\n")
    fake_python.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(fake_python))
    monkeypatch.setattr(sys, "prefix", str(fake_venv))
    monkeypatch.setattr(sys, "base_prefix", "/usr")

    foreign_pid = 62401
    # The original #614 scenario — verbatim.
    _seed_unknown_port_owner(
        monkeypatch,
        port=5433,
        pid=foreign_pid,
        cmdline=(
            "/tmp/dbounce-test run --dialect postgres "
            "--upstream-conn-string ignored"
        ),
        exe_path=pathlib.Path("/tmp/dbounce-test"),
        owner_uid=os.geteuid(),
    )

    inv = cu._inventory_installed_state()

    # Observable: foreign PID is NOT in running_bouncers.
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    assert foreign_pid not in flat_pids, (
        f"#621 regression: #614 foreign /tmp/dbounce-test "
        f"(pid={foreign_pid}) was re-classified as bouncer by the "
        f"#621 venv-extension change. The #614 protection has been "
        f"broken. running_bouncers={inv['running_bouncers']}"
    )
    # Observable: foreign PID IS in unknown_port_owners.
    unknown_pids = [u["pid"] for u in inv["unknown_port_owners"]]
    assert foreign_pid in unknown_pids, (
        f"#621 regression: foreign PID must STILL surface in "
        f"unknown_port_owners; got {inv['unknown_port_owners']}"
    )
    # Observable: U-5 halt STILL fires.
    halts = cu._check_halt_conditions(inv)
    halt_ids = [h["id"] for h in halts]
    assert "U-5" in halt_ids, (
        f"#621 regression: U-5 halt must STILL fire for foreign "
        f"process even after #621 venv-extension; got halts={halts}"
    )


def test_621_cross_user_venv_still_rejected_regression_614(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """#621 REGRESSION (#614): a venv binary owned by a DIFFERENT OS
    user must STILL be rejected. Cross-user destruction was the
    worst-case #614 violation; the venv-path extension must NOT relax
    the same-user check for processes that just happen to live under a
    venv-shape path."""
    _seed_install(isolated_iam_jit_home)

    fake_venv = tmp_path / ".venv"
    fake_venv_bin = fake_venv / "bin"
    fake_venv_bin.mkdir(parents=True)
    fake_python = fake_venv_bin / "python"
    fake_python.write_text("#!/bin/sh\nexit 0\n")
    fake_python.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(fake_python))
    monkeypatch.setattr(sys, "prefix", str(fake_venv))
    monkeypatch.setattr(sys, "base_prefix", "/usr")

    venv_ibounce = fake_venv_bin / "ibounce"
    venv_ibounce.write_text("#!/bin/sh\nexit 0\n")
    venv_ibounce.chmod(0o755)

    cross_user_pid = 62501
    # owner_uid=0 (root) — clearly NOT current user.
    _seed_unknown_port_owner(
        monkeypatch,
        port=8767,
        pid=cross_user_pid,
        cmdline=f"{venv_ibounce} run --mode discovery --proxy-port 8767",
        exe_path=venv_ibounce,
        owner_uid=0,
    )

    inv = cu._inventory_installed_state()

    # Observable: cross-user PID NOT in running_bouncers even though
    # the path is now a recognized install root.
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    assert cross_user_pid not in flat_pids, (
        f"#621 regression: cross-user PID at recognized venv path "
        f"was classified as ours. #614 cross-user check broken. "
        f"running_bouncers={inv['running_bouncers']}"
    )
    # Observable: surfaced for operator review.
    assert cross_user_pid in [
        u["pid"] for u in inv["unknown_port_owners"]
    ]
    entry = next(
        u for u in inv["unknown_port_owners"] if u["pid"] == cross_user_pid
    )
    failed_text = " ".join(entry.get("failed_checks") or [])
    assert "uid" in failed_text or "owner" in failed_text, (
        f"#621 regression: failed_checks should still call out the "
        f"uid mismatch; got {entry}"
    )


def test_621_python_console_script_argv1_resolved(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """#621: when the resolved exe is a Python interpreter (the typical
    case for venv-installed console scripts on macOS), the classifier
    must extract the script path from argv[1] and check THAT against
    install roots — not the interpreter.

    The UAT scenario: ``Python .venv/bin/ibounce run --mode discovery``.
    Pre-fix: only the Homebrew Python path was checked → fail → foreign.
    Post-fix: argv[1] (.venv/bin/ibounce) is also checked + recognized
    via the runtime sys.executable parent detection.
    """
    _seed_install(isolated_iam_jit_home)

    fake_venv = tmp_path / ".venv"
    fake_venv_bin = fake_venv / "bin"
    fake_venv_bin.mkdir(parents=True)
    fake_python = fake_venv_bin / "python"
    fake_python.write_text("#!/bin/sh\nexit 0\n")
    fake_python.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(fake_python))
    monkeypatch.setattr(sys, "prefix", str(fake_venv))
    monkeypatch.setattr(sys, "base_prefix", "/usr")

    venv_ibounce = fake_venv_bin / "ibounce"
    venv_ibounce.write_text("#!/bin/sh\nexit 0\n")
    venv_ibounce.chmod(0o755)

    pid = 62701
    # Mimic the exact UAT-Cross G7 cmdline shape: kernel reports the
    # interpreter (Homebrew Python); argv[1] is the venv script.
    homebrew_python = pathlib.Path(
        "/opt/homebrew/Cellar/python@3.12/3.12.13_2/"
        "Frameworks/Python.framework/Versions/3.12/Resources/Python.app/"
        "Contents/MacOS/Python"
    )
    _seed_unknown_port_owner(
        monkeypatch,
        port=8767,
        pid=pid,
        cmdline=(
            f"{homebrew_python} {venv_ibounce} run --mode discovery "
            f"--port 8767"
        ),
        exe_path=homebrew_python,  # what lsof / /proc/exe reports
        owner_uid=os.geteuid(),
    )

    inv = cu._inventory_installed_state()

    # Observable: classified as ibounce despite exe being Homebrew Python.
    assert "ibounce" in inv["running_bouncers"], (
        f"#621: Python-console-script invocation must classify via "
        f"argv[1]; running_bouncers={inv['running_bouncers']} "
        f"unknown={inv['unknown_port_owners']}"
    )
    assert pid in inv["running_bouncers"]["ibounce"]


def test_621_argv1_flag_does_not_count_as_script_path(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#621 REGRESSION (#614): the argv[1]-extraction must NOT treat
    a flag (starts with ``-``) as a script path. The classic foreign
    case is ``Python -c <inline-code>`` — argv[1] is ``-c``, NOT a
    bouncer script. This must STILL classify as foreign."""
    _seed_install(isolated_iam_jit_home)

    foreign_pid = 62801
    homebrew_python = pathlib.Path(
        "/opt/homebrew/Cellar/python@3.12/3.12.13_2/"
        "Frameworks/Python.framework/Versions/3.12/Resources/Python.app/"
        "Contents/MacOS/Python"
    )
    # cmdline is `Python -c <script>` — the foreign process pattern.
    # Even though "ibounce" appears in the inline code (incidental
    # substring), neither the interpreter NOR argv[1]=='-c' resolves to
    # an install root.
    _seed_unknown_port_owner(
        monkeypatch,
        port=8767,
        pid=foreign_pid,
        cmdline=(
            f"{homebrew_python} -c "
            "import socket;s=socket.socket();s.bind(('ibounce-mimic',0))"
        ),
        exe_path=homebrew_python,
        owner_uid=os.geteuid(),
    )

    # Observable: _extract_script_path_from_cmdline returns None for
    # the flag argv[1].
    extracted = cu._extract_script_path_from_cmdline(
        f"{homebrew_python} -c some-script"
    )
    assert extracted is None, (
        f"#621: argv[1] starting with '-' must not be extracted as "
        f"a script path; got {extracted}"
    )

    inv = cu._inventory_installed_state()
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    assert foreign_pid not in flat_pids, (
        f"#621 regression: Python -c foreign process classified as "
        f"bouncer; running_bouncers={inv['running_bouncers']}"
    )
    assert foreign_pid in [u["pid"] for u in inv["unknown_port_owners"]]


# ---------------------------------------------------------------------------
# #615 — UAT-Lifecycle 2026-05-25 (HIGH-1): _lsof_pids_on_port must
# detect IPv4-only loopback binds (the default ``lsof -iTCP:PORT``
# invocation was IPv6-biased on some lsof versions and silently missed
# 127.0.0.1:PORT listeners, defeating every #574 / #608 / #614 halt).
# ---------------------------------------------------------------------------


def _spawn_bind(family: int, host: str, port: int) -> subprocess.Popen[str]:
    """Spawn a subprocess that binds + listens on (family, host, port)
    and idles for 60s. Returns the Popen handle; caller terminates."""
    script = (
        "import socket, sys, time, os\n"
        f"family = {family}\n"
        f"s = socket.socket(family, socket.SOCK_STREAM)\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"s.bind(({host!r}, {int(port)}))\n"
        "s.listen(1)\n"
        "sys.stdout.write('READY\\n'); sys.stdout.flush()\n"
        "time.sleep(60)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # Wait for READY (up to 3s) so the bind is observable when we probe.
    deadline = time.time() + 3.0
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        line = proc.stdout.readline() if proc.stdout else ""
        if "READY" in line:
            break
        if not line:
            time.sleep(0.05)
    return proc


def _pick_free_port(family: int = socket.AF_INET) -> int:
    """Reserve and release a free port; return it for the subprocess
    to rebind under SO_REUSEADDR. NOTE: import socket at the top of
    test module is already done."""
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_615_lsof_detects_ipv4_loopback_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#615 UAT-Lifecycle HIGH-1 REGRESSION (PRIMARY): an AF_INET
    socket bound to ``127.0.0.1:PORT`` (no dual-stack ``[::]``
    listener) MUST be detected by _lsof_pids_on_port. The pre-#615
    default ``lsof -iTCP:PORT`` silently missed this on IPv6-biased
    lsof versions, allowing foreign processes to bypass all uninstall
    halts.
    """
    if shutil.which("lsof") is None:
        pytest.skip("requires lsof on PATH")
    # Restore the real helper (autouse fixture stubs it).
    monkeypatch.setattr(cu, "_lsof_pids_on_port", _REAL_LSOF_PIDS_ON_PORT)

    port = _pick_free_port(socket.AF_INET)
    proc = _spawn_bind(socket.AF_INET, "127.0.0.1", port)
    try:
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            pytest.skip(f"subprocess failed to bind: {stderr[:300]}")

        pids = cu._lsof_pids_on_port(port)

        # Observable: the bound PID appears in the result. This is the
        # claim the production code makes; the assertion verifies the
        # claim against reality (real socket + real lsof).
        assert proc.pid in pids, (
            f"#615: IPv4-only loopback bind on 127.0.0.1:{port} not "
            f"detected — pid={proc.pid} missing from {pids}"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_615_lsof_detects_ipv4_wildcard_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#615 coverage: ``0.0.0.0:PORT`` (IPv4 wildcard) is the standard
    server-side bind shape. Must be detected the same as loopback."""
    if shutil.which("lsof") is None:
        pytest.skip("requires lsof on PATH")
    monkeypatch.setattr(cu, "_lsof_pids_on_port", _REAL_LSOF_PIDS_ON_PORT)

    port = _pick_free_port(socket.AF_INET)
    proc = _spawn_bind(socket.AF_INET, "0.0.0.0", port)
    try:
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            pytest.skip(f"subprocess failed to bind: {stderr[:300]}")

        pids = cu._lsof_pids_on_port(port)
        assert proc.pid in pids, (
            f"#615: IPv4 wildcard bind on 0.0.0.0:{port} not detected "
            f"— pid={proc.pid} missing from {pids}"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_615_lsof_detects_ipv6_loopback_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#615 coverage: ``[::1]:PORT`` (IPv6 loopback) — the pre-#615
    invocation also worked for this; the test pins parity so a future
    regression that drops -i6 selection is caught immediately."""
    if shutil.which("lsof") is None:
        pytest.skip("requires lsof on PATH")
    monkeypatch.setattr(cu, "_lsof_pids_on_port", _REAL_LSOF_PIDS_ON_PORT)

    port = _pick_free_port(socket.AF_INET)  # ephemeral port reserved on v4
    proc = _spawn_bind(socket.AF_INET6, "::1", port)
    try:
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            pytest.skip(f"subprocess failed to bind: {stderr[:300]}")

        pids = cu._lsof_pids_on_port(port)
        assert proc.pid in pids, (
            f"#615: IPv6 loopback bind on [::1]:{port} not detected "
            f"— pid={proc.pid} missing from {pids}"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_615_lsof_detects_ipv6_wildcard_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#615 coverage: ``[::]:PORT`` (IPv6 wildcard, the python
    http.server shape) — pre-#615 invocation worked here; pinned for
    parity."""
    if shutil.which("lsof") is None:
        pytest.skip("requires lsof on PATH")
    monkeypatch.setattr(cu, "_lsof_pids_on_port", _REAL_LSOF_PIDS_ON_PORT)

    port = _pick_free_port(socket.AF_INET)
    proc = _spawn_bind(socket.AF_INET6, "::", port)
    try:
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            pytest.skip(f"subprocess failed to bind: {stderr[:300]}")

        pids = cu._lsof_pids_on_port(port)
        assert proc.pid in pids, (
            f"#615: IPv6 wildcard bind on [::]:{port} not detected "
            f"— pid={proc.pid} missing from {pids}"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_615_lsof_no_match_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#615: a port with no listener returns ``[]`` (lsof exit code 1
    is normal here and must NOT be treated as an error)."""
    if shutil.which("lsof") is None:
        pytest.skip("requires lsof on PATH")
    monkeypatch.setattr(cu, "_lsof_pids_on_port", _REAL_LSOF_PIDS_ON_PORT)

    # Reserve + immediately release a port so nothing is listening.
    port = _pick_free_port(socket.AF_INET)

    pids = cu._lsof_pids_on_port(port)
    assert pids == [], (
        f"#615: no-listener port :{port} must return []; got {pids}"
    )


def test_615_lsof_missing_returns_empty_with_ss_fallback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """#615: when ``lsof`` is missing (slim Linux containers), the
    helper falls back to ``ss`` if present; if neither is present,
    returns [] without raising. We verify the "neither present" branch
    by stubbing shutil.which to None for both."""
    monkeypatch.setattr(cu, "_lsof_pids_on_port", _REAL_LSOF_PIDS_ON_PORT)

    def _no_tool(name: str) -> str | None:
        return None
    monkeypatch.setattr(cu.shutil, "which", _no_tool)

    pids = cu._lsof_pids_on_port(8767)
    assert pids == [], (
        f"#615: with no lsof + no ss, helper must return [] cleanly "
        f"(no exceptions, no false positives); got {pids}"
    )


def test_615_uninstall_detects_ipv4_foreign_process_in_halts(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#615 UAT-Lifecycle HIGH-1 REGRESSION (END-TO-END): the exact
    repro from the UAT report — spawn an IPv4-only foreign Python
    process on a bouncer-default port, then run uninstall --dry-run
    and assert the foreign PID surfaces in:
      * inventory.bound_ports (TCP probe sees it)
      * inventory.unknown_port_owners (multi-factor classifier rejects)
      * halts U-2 + U-5 (operator-visible refusal-to-touch)
    Per docs/CONTRIBUTING.md: each claim above is an observable state
    assertion, not a status-string check."""
    if shutil.which("lsof") is None or shutil.which("ps") is None:
        pytest.skip("requires lsof + ps on PATH")

    _seed_install(isolated_iam_jit_home)

    # Reserve a free port + pin _BOUNCER_DEFAULT_PORTS to it so the
    # inventory only scans this port (avoids picking up real dev-machine
    # bouncers). Using ibounce slot for parity with #614 classifier tests.
    port = _pick_free_port(socket.AF_INET)
    monkeypatch.setattr(cu, "BOUNCER_PORTS", (port,))
    monkeypatch.setattr(
        cu, "_BOUNCER_DEFAULT_PORTS", {"ibounce": (port,)},
    )
    # Restore REAL helpers (autouse fixture stubs them).
    monkeypatch.setattr(cu, "_port_bound", _REAL_PORT_BOUND)
    monkeypatch.setattr(cu, "_lsof_pids_on_port", _REAL_LSOF_PIDS_ON_PORT)
    monkeypatch.setattr(cu, "_read_cmdline", _REAL_READ_CMDLINE)
    # Suppress pgrep-name lookup so foreign-only PIDs come solely from
    # the lsof port-owner cross-reference (the surface under test).
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])

    proc = _spawn_bind(socket.AF_INET, "127.0.0.1", port)
    try:
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            pytest.skip(f"foreign subprocess failed to bind: {stderr[:300]}")

        inv = cu._inventory_installed_state()

        # 1. bound_ports: TCP probe sees the listener.
        assert port in inv["bound_ports"], (
            f"#615: foreign IPv4-only bind on :{port} missed by TCP "
            f"probe — bound_ports={inv['bound_ports']}"
        )

        # 2. unknown_port_owners: lsof cross-reference recovered the
        #    PID AND the multi-factor classifier (#614) rejected it
        #    (Python interpreter + no bouncer flag signature).
        unknown_pids = [u["pid"] for u in inv["unknown_port_owners"]]
        assert proc.pid in unknown_pids, (
            f"#615 PRIMARY FAILURE MODE: foreign IPv4-only PID "
            f"{proc.pid} on :{port} silently bypassed lsof detection. "
            f"unknown_port_owners={inv['unknown_port_owners']} "
            f"running_bouncers={inv['running_bouncers']}"
        )

        # 3. running_bouncers MUST NOT include the foreign PID (would
        #    mean the multi-factor classifier misfired and we're about
        #    to SIGTERM a cross-domain process per [[creates-never-mutates]]).
        all_running: list[int] = []
        for pids in inv["running_bouncers"].values():
            all_running.extend(pids)
        assert proc.pid not in all_running, (
            f"#615 CRIT: foreign PID {proc.pid} classified as a real "
            f"bouncer — multi-factor classifier defeated. "
            f"running_bouncers={inv['running_bouncers']}"
        )

        # 4. halts: U-2 (non-bouncer holding bouncer port) + U-5
        #    (foreign multi-factor reject) MUST fire. These are the
        #    operator-visible signals that uninstall is refusing to
        #    touch a foreign process.
        halts = cu._check_halt_conditions(inv)
        halt_ids = {h["id"] for h in halts}
        assert "U-2" in halt_ids, (
            f"#615: U-2 halt (non-bouncer on bouncer port) did NOT "
            f"fire despite foreign PID {proc.pid} on :{port}. "
            f"halts={halts}"
        )
        assert "U-5" in halt_ids, (
            f"#615: U-5 halt (foreign multi-factor reject) did NOT "
            f"fire despite foreign PID {proc.pid} on :{port}. "
            f"halts={halts}"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_615_sabotage_ipv4_skip_makes_primary_test_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#615 SABOTAGE CHECK per docs/CONTRIBUTING.md: prove the primary
    IPv4-loopback test is load-bearing by simulating the pre-#615
    failure mode — monkeypatch _lsof_pids_on_port to drop IPv4
    results. The primary test would then fail to detect the bind.

    This test asserts the inverse: with IPv4 filtered out, the helper
    returns [] for an IPv4-only bind — proving the detection actually
    depends on querying IPv4."""
    if shutil.which("lsof") is None:
        pytest.skip("requires lsof on PATH")

    # Build a stub that mimics the pre-#615 IPv6-biased lsof: it ONLY
    # queries -i6, not -i4. For an AF_INET bind, this returns [].
    def _ipv6_only_lsof(port: int) -> list[int]:
        try:
            proc = subprocess.run(
                ["lsof", "-nP", "-i6TCP:%d" % int(port),
                 "-sTCP:LISTEN", "-t"],
                capture_output=True, text=True, check=False, timeout=5.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        return [int(s) for s in proc.stdout.splitlines() if s.strip().isdigit()]

    port = _pick_free_port(socket.AF_INET)
    proc = _spawn_bind(socket.AF_INET, "127.0.0.1", port)
    try:
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            pytest.skip(f"subprocess failed to bind: {stderr[:300]}")

        # Sabotaged (IPv6-only) lookup MUST return [] for IPv4 bind.
        sabotaged = _ipv6_only_lsof(port)
        assert proc.pid not in sabotaged, (
            f"#615 sabotage smoke FAILED: the IPv6-only stub still "
            f"detected the IPv4 bind, which means the primary IPv4 "
            f"test is NOT load-bearing. pid={proc.pid} "
            f"sabotaged_result={sabotaged}"
        )

        # Real fixed helper MUST detect it (positive control).
        real = _REAL_LSOF_PIDS_ON_PORT(port)
        assert proc.pid in real, (
            f"#615 sabotage smoke (positive control): real helper "
            f"failed to detect IPv4 bind that sabotaged version "
            f"missed — pid={proc.pid} real={real}"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_621_relative_path_handled_safely(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#621 edge case: an executable path that comes in as a relative
    path (e.g. ``./ibounce`` from an unusual ps reading) must be
    handled cleanly without crashing. The resolver must not raise; the
    process simply lands in unknown_port_owners if it doesn't resolve
    to a known root."""
    _seed_install(isolated_iam_jit_home)

    edge_pid = 62601
    relative_path = pathlib.Path("./some_relative_dir/ibounce")

    _seed_unknown_port_owner(
        monkeypatch,
        port=8767,
        pid=edge_pid,
        cmdline=f"./some_relative_dir/ibounce run --mode discovery",
        exe_path=relative_path,
        owner_uid=os.geteuid(),
    )

    # Observable: inventory builds without raising.
    inv = cu._inventory_installed_state()

    # Observable: the path-check helper itself doesn't raise.
    # Result MAY be True or False (depends on cwd resolution); the
    # important property is "doesn't crash". Surfacing in
    # unknown_port_owners is the safe default if it doesn't resolve.
    result = cu._path_under_known_install_root(relative_path)
    assert isinstance(result, bool), (
        f"#621: _path_under_known_install_root must return bool even "
        f"for relative paths; got {type(result).__name__}={result!r}"
    )

    # Observable: PID is either correctly classified OR surfaced as
    # unknown. The crash-safety is the load-bearing property here.
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    unknown_pids = [u["pid"] for u in inv["unknown_port_owners"]]
    assert edge_pid in flat_pids or edge_pid in unknown_pids, (
        f"#621: edge-case relative path PID disappeared entirely. "
        f"running_bouncers={inv['running_bouncers']} "
        f"unknown={inv['unknown_port_owners']}"
    )


# ---------------------------------------------------------------------------
# #617 MED-2 — detect bouncers on custom (non-default) ports
#
# Per UAT-Lifecycle 2026-05-25: `iam-jit uninstall --dry-run` only probed
# BOUNCER_DEFAULT_PORTS. A bouncer started with `ibounce run --port 18767`
# (custom port) was invisible to inventory → orphan risk on uninstall.
#
# Fix: _all_listening_ports() enumerates ALL loopback TCP listeners owned
# by the current user; _classify_bouncer_pid_multifactor (#614) then gates
# which ones are actually ours. Custom-port bouncers appear in
# running_bouncers + bound_ports; foreign processes don't.
# ---------------------------------------------------------------------------


def _seed_custom_port_bouncer(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pid: int,
    port: int,
    bouncer_kind: str,
    cmdline: str,
) -> None:
    """Wire up monkeypatches to simulate a bouncer on a custom (non-default)
    port, visible ONLY through _all_listening_ports (not via _port_bound on
    the default port list).

    Per the #617 MED-2 fix: _all_listening_ports is the load-bearing path for
    custom-port detection. _port_bound + _lsof_pids_on_port remain stubbed to
    return nothing for this port (they're only called on default ports).

    Uses /Users/testop/ convention per #537 follow-up (test fixture paths
    must not leak real user paths).
    """
    fake_install_dir = pathlib.Path("/Users/testop/.iam-jit/venv/bin")
    exe_path = fake_install_dir / bouncer_kind

    # _all_listening_ports returns (pid, port) for the custom port.
    monkeypatch.setattr(
        cu, "_all_listening_ports",
        lambda: [(pid, port)],
    )
    # _read_cmdline returns the bouncer cmdline for this PID.
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda p: cmdline if p == pid else "",
    )
    # _resolve_executable_path: exe under a known install root.
    monkeypatch.setattr(
        cu, "_resolve_executable_path",
        lambda p: exe_path if p == pid else None,
    )
    # _pid_owner_uid: owned by current user.
    monkeypatch.setattr(
        cu, "_pid_owner_uid",
        lambda p: os.geteuid() if p == pid else None,
    )
    # Patch _path_under_known_install_root to accept /Users/testop/.iam-jit/venv/bin
    # by adding that root to _BOUNCER_INSTALL_PATH_ROOTS for the test.
    monkeypatch.setattr(
        cu, "_BOUNCER_INSTALL_PATH_ROOTS",
        cu._BOUNCER_INSTALL_PATH_ROOTS + (fake_install_dir,),
    )


def test_617_med2_ibounce_on_custom_port_18767_detected(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#617 MED-2: ibounce running on non-default port 18767 must appear
    in running_bouncers + bound_ports.

    Pre-fix: inventory only probed default ports (8767/7401/7402/7412).
    ibounce on 18767 was invisible → orphan risk per [[ibounce-honest-positioning]].
    """
    _seed_install(isolated_iam_jit_home)

    pid = 71801
    port = 18767
    _seed_custom_port_bouncer(
        monkeypatch,
        pid=pid,
        port=port,
        bouncer_kind="ibounce",
        cmdline=(
            "/Users/testop/.iam-jit/venv/bin/ibounce run "
            "--mode discovery --proxy-port 18767"
        ),
    )

    inv = cu._inventory_installed_state()

    # Observable: ibounce appears in running_bouncers.
    assert "ibounce" in inv["running_bouncers"], (
        f"#617 MED-2: ibounce on custom port {port} not in running_bouncers; "
        f"got {inv['running_bouncers']}"
    )
    assert pid in inv["running_bouncers"]["ibounce"], (
        f"#617 MED-2: pid={pid} not in running_bouncers['ibounce']; "
        f"got {inv['running_bouncers']['ibounce']}"
    )

    # Observable: custom port appears in bound_ports.
    assert port in inv["bound_ports"], (
        f"#617 MED-2: custom port {port} not in bound_ports; "
        f"got {inv['bound_ports']}"
    )

    # Observable: NOT in unknown_port_owners (it classified correctly).
    unknown_pids = [u["pid"] for u in inv["unknown_port_owners"]]
    assert pid not in unknown_pids, (
        f"#617 MED-2: correctly-classified ibounce pid={pid} must NOT "
        f"be in unknown_port_owners; got {inv['unknown_port_owners']}"
    )


def test_617_med2_kbouncer_on_custom_port_28766_detected(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#617 MED-2: kbouncer running on non-default port 28766 must appear
    in running_bouncers + bound_ports.

    Per [[cross-product-agent-parity]]: detection applies to all 4 bouncers;
    this test covers the Go binary (kbouncer) shape.
    """
    _seed_install(isolated_iam_jit_home)

    pid = 71802
    port = 28766
    _seed_custom_port_bouncer(
        monkeypatch,
        pid=pid,
        port=port,
        bouncer_kind="kbouncer",
        cmdline=(
            "/Users/testop/.iam-jit/venv/bin/kbouncer run "
            "--apiserver-url https://127.0.0.1:28766 --rbac-mode audit"
        ),
    )

    inv = cu._inventory_installed_state()

    # Observable: kbouncer appears in running_bouncers.
    assert "kbouncer" in inv["running_bouncers"], (
        f"#617 MED-2: kbouncer on custom port {port} not in running_bouncers; "
        f"got {inv['running_bouncers']}"
    )
    assert pid in inv["running_bouncers"]["kbouncer"], (
        f"#617 MED-2: pid={pid} not in running_bouncers['kbouncer']; "
        f"got {inv['running_bouncers']['kbouncer']}"
    )

    # Observable: custom port appears in bound_ports.
    assert port in inv["bound_ports"], (
        f"#617 MED-2: custom port {port} not in bound_ports; "
        f"got {inv['bound_ports']}"
    )

    # Observable: NOT in unknown_port_owners.
    unknown_pids = [u["pid"] for u in inv["unknown_port_owners"]]
    assert pid not in unknown_pids, (
        f"#617 MED-2: correctly-classified kbouncer pid={pid} must NOT "
        f"be in unknown_port_owners"
    )


def test_617_med2_default_port_detection_preserved_regression(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#617 MED-2 regression-pin: ibounce on default port 8767 is still
    detected via the existing _lsof_pids_on_port path (not broken by the
    custom-port addition).

    This test keeps the default-port path honest — _all_listening_ports
    returns empty, yet the default-port scan finds the bouncer.
    """
    _seed_install(isolated_iam_jit_home)

    pid = 71803
    port = 8767  # ibounce default port

    fake_install_dir = pathlib.Path("/Users/testop/.iam-jit/venv/bin")
    cmdline = (
        "/Users/testop/.iam-jit/venv/bin/ibounce run "
        "--mode discovery --proxy-port 8767"
    )

    # Simulate ibounce on default port 8767 via the standard path.
    monkeypatch.setattr(
        cu, "_port_bound",
        lambda p, host="127.0.0.1": p == port,
    )
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda p: [pid] if p == port else [],
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda p: cmdline if p == pid else "",
    )
    monkeypatch.setattr(
        cu, "_resolve_executable_path",
        lambda p: fake_install_dir / "ibounce" if p == pid else None,
    )
    monkeypatch.setattr(
        cu, "_pid_owner_uid",
        lambda p: os.geteuid() if p == pid else None,
    )
    monkeypatch.setattr(
        cu, "_BOUNCER_INSTALL_PATH_ROOTS",
        cu._BOUNCER_INSTALL_PATH_ROOTS + (fake_install_dir,),
    )
    # _all_listening_ports returns empty (already stubbed by autouse fixture).
    # Explicit for clarity:
    monkeypatch.setattr(cu, "_all_listening_ports", lambda: [])

    inv = cu._inventory_installed_state()

    # Observable: ibounce still found on default port.
    assert "ibounce" in inv["running_bouncers"], (
        f"#617 MED-2 regression: ibounce on default port {port} disappeared; "
        f"got {inv['running_bouncers']}"
    )
    assert pid in inv["running_bouncers"]["ibounce"]
    assert port in inv["bound_ports"]


def test_617_med2_foreign_process_on_custom_port_not_classified(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#617 MED-2 + #614: a foreign process on a custom non-default port
    (19999) must NOT be classified as a bouncer.

    The multi-factor classifier (#614) still gates: if the process doesn't
    have a bouncer-specific flag in its cmdline, it's neither in
    running_bouncers NOR in unknown_port_owners (since its cmdline is not
    bouncer-shaped, there's no signal to surface for the operator).

    Per [[creates-never-mutates]]: uninstall never SIGTERMs processes it
    cannot positively identify as its own.
    """
    _seed_install(isolated_iam_jit_home)

    foreign_pid = 71804
    foreign_port = 19999

    # Foreign process on a custom port — no bouncer flag signature.
    monkeypatch.setattr(
        cu, "_all_listening_ports",
        lambda: [(foreign_pid, foreign_port)],
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda p: "/usr/local/bin/nginx -g 'daemon off;'" if p == foreign_pid else "",
    )
    monkeypatch.setattr(
        cu, "_resolve_executable_path",
        lambda p: pathlib.Path("/usr/local/bin/nginx") if p == foreign_pid else None,
    )
    monkeypatch.setattr(
        cu, "_pid_owner_uid",
        lambda p: os.geteuid() if p == foreign_pid else None,
    )

    inv = cu._inventory_installed_state()

    # Observable: foreign PID NOT in running_bouncers.
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    assert foreign_pid not in flat_pids, (
        f"#617 MED-2 + #614: foreign nginx pid={foreign_pid} on port "
        f"{foreign_port} must NOT be in running_bouncers; "
        f"got {inv['running_bouncers']}"
    )

    # Observable: NOT in unknown_port_owners either (cmdline not bouncer-shaped).
    unknown_pids = [u["pid"] for u in inv["unknown_port_owners"]]
    assert foreign_pid not in unknown_pids, (
        f"#617 MED-2: nginx on custom port must not flood unknown_port_owners; "
        f"got {inv['unknown_port_owners']}"
    )

    # Observable: custom port NOT added to bound_ports.
    assert foreign_port not in inv["bound_ports"], (
        f"#617 MED-2: custom port {foreign_port} for nginx should not appear "
        f"in bound_ports; got {inv['bound_ports']}"
    )


def test_617_med2_halt_u1_u2_fire_on_custom_port_bouncer(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#617 MED-2: halt conditions U-1/U-2 fire correctly when a custom-port
    bouncer is in unknown_port_owners (bouncer-shaped cmdline but fails
    multi-factor — e.g. executable path outside install root).

    Verifies the halt machinery wires up correctly even when the port
    was discovered via _all_listening_ports (not the default-port list).
    """
    _seed_install(isolated_iam_jit_home)

    # Bouncer-shaped cmdline (has --proxy-port flag) but executable path
    # is outside install root → fails factor 1 → lands in unknown_port_owners.
    ambiguous_pid = 71805
    ambiguous_port = 28767  # custom non-default port
    ambiguous_cmdline = (
        "/tmp/ibounce-staging run --mode discovery --proxy-port 28767"
    )

    monkeypatch.setattr(
        cu, "_all_listening_ports",
        lambda: [(ambiguous_pid, ambiguous_port)],
    )
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda p: ambiguous_cmdline if p == ambiguous_pid else "",
    )
    # Executable path is outside install root → path check fails.
    monkeypatch.setattr(
        cu, "_resolve_executable_path",
        lambda p: pathlib.Path("/tmp/ibounce-staging") if p == ambiguous_pid else None,
    )
    monkeypatch.setattr(
        cu, "_pid_owner_uid",
        lambda p: os.geteuid() if p == ambiguous_pid else None,
    )

    inv = cu._inventory_installed_state()

    # Observable: ambiguous PID is in unknown_port_owners (bouncer-shaped
    # cmdline but failed path check → surfaced for operator review).
    unknown_pids = [u["pid"] for u in inv["unknown_port_owners"]]
    assert ambiguous_pid in unknown_pids, (
        f"#617 MED-2: ambiguous pid={ambiguous_pid} with bouncer-shaped "
        f"cmdline but wrong path should be in unknown_port_owners; "
        f"got {inv['unknown_port_owners']}"
    )

    # Observable: custom port IS in bound_ports (it was reported via
    # unknown_port_owners which adds it).
    assert ambiguous_port in inv["bound_ports"], (
        f"#617 MED-2: custom port {ambiguous_port} for ambiguous bouncer "
        f"should be in bound_ports; got {inv['bound_ports']}"
    )

    # Observable: U-2 halt fires (unknown port owners).
    halts = cu._check_halt_conditions(inv)
    halt_ids = [h["id"] for h in halts]
    assert "U-2" in halt_ids, (
        f"#617 MED-2: U-2 halt must fire for unknown_port_owners; "
        f"got halts={halts}"
    )

    # Observable: U-5 halt fires (foreign process classification refused).
    assert "U-5" in halt_ids, (
        f"#617 MED-2: U-5 halt must fire for ambiguous bouncer-path process; "
        f"got halts={halts}"
    )

    # Observable end-to-end: run_uninstall halts without --force.
    result = cu.run_uninstall(dry_run=False, force=False)
    assert result["status"] == "halted", (
        f"#617 MED-2: run_uninstall must halt when ambiguous process on "
        f"custom port is detected; got status={result['status']}"
    )


def test_617_med2_sabotage_all_listening_ports_proves_load_bearing(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#617 MED-2 sabotage check: monkeypatch _all_listening_ports to return
    only default ports (empty for the custom port), and confirm the
    custom-port bouncer is NOT detected.

    This proves _all_listening_ports is the load-bearing code path for
    custom-port detection — without it, the bouncer is invisible.
    """
    _seed_install(isolated_iam_jit_home)

    pid = 71806
    port = 18767  # custom non-default port

    fake_install_dir = pathlib.Path("/Users/testop/.iam-jit/venv/bin")
    cmdline = (
        "/Users/testop/.iam-jit/venv/bin/ibounce run "
        "--mode discovery --proxy-port 18767"
    )

    # Setup all the helpers that would classify this correctly IF
    # _all_listening_ports returned the custom port.
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda p: cmdline if p == pid else "",
    )
    monkeypatch.setattr(
        cu, "_resolve_executable_path",
        lambda p: fake_install_dir / "ibounce" if p == pid else None,
    )
    monkeypatch.setattr(
        cu, "_pid_owner_uid",
        lambda p: os.geteuid() if p == pid else None,
    )
    monkeypatch.setattr(
        cu, "_BOUNCER_INSTALL_PATH_ROOTS",
        cu._BOUNCER_INSTALL_PATH_ROOTS + (fake_install_dir,),
    )

    # SABOTAGE: _all_listening_ports returns empty (simulates only
    # default ports being visible — the pre-fix behavior).
    monkeypatch.setattr(cu, "_all_listening_ports", lambda: [])

    inv = cu._inventory_installed_state()

    # Sabotage observable: ibounce on custom port IS NOT detected.
    flat_pids: list[int] = []
    for pids in inv["running_bouncers"].values():
        flat_pids.extend(pids)
    assert pid not in flat_pids, (
        f"#617 MED-2 sabotage: expected custom-port ibounce pid={pid} to "
        f"be invisible when _all_listening_ports is sabotaged to return []; "
        f"got running_bouncers={inv['running_bouncers']}. "
        f"This would mean another code path is detecting custom ports "
        f"— investigate whether the fix is truly load-bearing."
    )
    assert port not in inv["bound_ports"], (
        f"#617 MED-2 sabotage: custom port {port} should NOT be in "
        f"bound_ports when _all_listening_ports is empty; "
        f"got bound_ports={inv['bound_ports']}"
    )
