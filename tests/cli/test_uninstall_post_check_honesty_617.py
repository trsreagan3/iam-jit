"""#617 HIGH-3 — `iam-jit uninstall` post-check honesty (state-verification).

UAT-Lifecycle 2026-05-25 found:

  ``iam-jit uninstall --keep-audit-logs`` returned
  ``post_check.iam_jit_home_exists: false`` even though the filesystem
  still contained ``~/.iam-jit/audit.jsonl`` + ``~/.iam-jit/bouncer/
  state.db`` (correctly preserved by the operator's flag).

The post-check was lying about disk state. Per
``[[ibounce-honest-positioning]]`` every state field must reflect
reality, not the operator's intent at flag-set time.

These tests pin the honest shape:

  * Clean wipe (no ``--keep-audit-logs``): ``iam_jit_home_exists:
    false`` + ``preserved_paths: []`` + ``clean: true``.
  * ``--keep-audit-logs`` preserves audit.jsonl: ``iam_jit_home_exists:
    true`` + ``preserved_paths`` lists the file + ``clean: true``.
  * ``--keep-audit-logs`` with nothing to preserve: full wipe
    behavior preserved.
  * ``--keep-audit-logs`` preserves bouncer/state.db variant.
  * Sabotage check: the path-exists probe IS load-bearing.
"""

from __future__ import annotations

import pathlib
import subprocess
from unittest import mock

import pytest

import iam_jit.cli_uninstall as cu


# ---------------------------------------------------------------------------
# Reuse the isolation fixtures from test_uninstall.py via import. pytest
# doesn't auto-pick fixtures across modules in this layout, so we
# duplicate the minimal subset we need here (per the existing pattern in
# tests/cli/).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _default_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mirror tests/cli/test_uninstall.py's default isolation.

    Prevents the dev machine's real bouncers / ports / go-bin from
    tripping halt conditions during these tests.
    """
    import os
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": False)
    monkeypatch.setattr(cu, "_lsof_pids_on_port", lambda port: [])
    monkeypatch.setattr(cu, "_read_cmdline", lambda pid: "")
    from iam_jit.posture import bouncers as _posture_bouncers
    monkeypatch.setattr(
        _posture_bouncers,
        "_loopback_port_open",
        lambda port, host="127.0.0.1", timeout=0.25: False,
    )
    fake_install_dir = pathlib.Path.home() / ".iam-jit" / "venv" / "bin"
    def _fake_exe(pid: int) -> pathlib.Path | None:
        return fake_install_dir / "ibounce"
    monkeypatch.setattr(cu, "_resolve_executable_path", _fake_exe)
    monkeypatch.setattr(cu, "_pid_owner_uid", lambda pid: os.geteuid())


@pytest.fixture
def isolated_iam_jit_home(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    """Redirect every module-level path in cli_uninstall to a tmp dir."""
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
    """Populate `home` to look like a real iam-jit install."""
    paths: dict[str, pathlib.Path] = {}

    venv_bin = home / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    for script in cu.CONSOLE_SCRIPTS:
        (venv_bin / script).write_text("#!/bin/sh\necho fake\n")
        (venv_bin / script).chmod(0o755)
        paths[f"console:{script}"] = venv_bin / script
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
    paths["state.db-shm"] = bouncer_dir / "state.db-shm"
    paths["profiles.yaml"] = bouncer_dir / "profiles.yaml"

    audit = home / "audit.jsonl"
    audit.write_text('{"seq":1,"event":"seed"}\n')
    paths["audit.jsonl"] = audit

    canary = home / "canary"
    canary.mkdir()
    (canary / "issues.jsonl").write_text(
        '{"ts":"2026-05-25T00:00:00Z","severity":"LOW"}\n'
    )
    (canary / "status.json").write_text('{"canary_day":1}')
    paths["canary/issues.jsonl"] = canary / "issues.jsonl"
    paths["canary/status.json"] = canary / "status.json"

    return paths


def _seed_no_audit(home: pathlib.Path) -> dict[str, pathlib.Path]:
    """Seed a fresh install with NO audit-bearing files yet.

    Mirrors the "ran the installer but never used the system" shape
    where ``--keep-audit-logs`` should still result in a full wipe
    because there's nothing to preserve.
    """
    paths: dict[str, pathlib.Path] = {}
    venv_bin = home / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    for script in cu.CONSOLE_SCRIPTS:
        (venv_bin / script).write_text("#!/bin/sh\necho fake\n")
        (venv_bin / script).chmod(0o755)
    pip = venv_bin / "pip"
    pip.write_text("#!/bin/sh\nexit 0\n")
    pip.chmod(0o755)
    paths["pip"] = pip

    bouncer_dir = home / "bouncer"
    bouncer_dir.mkdir()
    (bouncer_dir / "profiles.yaml").write_text("default: {}")
    paths["profiles.yaml"] = bouncer_dir / "profiles.yaml"
    return paths


# ---------------------------------------------------------------------------
# Test 1 — clean wipe: iam_jit_home_exists:false + preserved_paths:[]
# ---------------------------------------------------------------------------


def test_clean_wipe_reports_iam_jit_home_absent_and_no_preserves(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pre-fix sanity: in the no-flag path the field was already honest.

    This test pins the existing semantic so a future "fix" can't
    quietly change the wipe-path shape while addressing the
    keep-audit-logs lie.
    """
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(dry_run=False)

    assert result["status"] == "ok", result
    post = result["post_check"]
    assert post["clean"] is True
    leftover = post["leftover"]
    # Observable: directory is gone.
    assert not isolated_iam_jit_home.exists()
    # And the post-check reports the truth.
    assert leftover["iam_jit_home_exists"] is False
    assert leftover["preserved_paths"] == []


# ---------------------------------------------------------------------------
# Test 2 — --keep-audit-logs preserves audit.jsonl: honest report
# ---------------------------------------------------------------------------


def test_keep_audit_logs_reports_iam_jit_home_present_when_preserved(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#617 HIGH-3 regression pin.

    Pre-fix: iam_jit_home_exists returned False (LIE) while audit.jsonl
    + state.db remained on disk. Post-fix: iam_jit_home_exists reflects
    reality, AND preserved_paths enumerates what's still there.
    """
    paths = _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(dry_run=False, keep_audit_logs=True)

    assert result["status"] == "ok", result

    # Observable: audit-bearing files are STILL on disk.
    assert paths["audit.jsonl"].exists()
    assert paths["state.db"].exists()
    assert isolated_iam_jit_home.exists()
    # Non-audit content is gone.
    assert not paths["profiles.yaml"].exists()
    assert not (isolated_iam_jit_home / "venv").exists()

    post = result["post_check"]
    leftover = post["leftover"]

    # The honest shape — directory exists because we preserved files.
    assert leftover["iam_jit_home_exists"] is True, (
        "Pre-#617-fix bug: post-check claimed iam_jit_home_exists:false "
        "while the directory was on disk with preserved audit files"
    )

    # preserved_paths enumerates what's still on disk.
    preserved = leftover["preserved_paths"]
    assert any(p.endswith("audit.jsonl") for p in preserved), preserved
    assert any(p.endswith("state.db") for p in preserved), preserved

    # clean is still True because the leftover state is intentional.
    assert post["clean"] is True


# ---------------------------------------------------------------------------
# Test 3 — --keep-audit-logs with nothing to preserve = full wipe
# ---------------------------------------------------------------------------


def test_keep_audit_logs_with_no_audit_files_does_full_wipe(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When operator sets --keep-audit-logs but no audit-bearing files
    exist, behavior degrades to a full wipe and the post-check reports
    the directory as absent + no preserves.
    """
    _seed_no_audit(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(dry_run=False, keep_audit_logs=True)

    assert result["status"] == "ok", result
    # Observable: directory is fully gone (nothing was preserved
    # because nothing audit-bearing was present).
    assert not isolated_iam_jit_home.exists()

    post = result["post_check"]
    leftover = post["leftover"]
    assert leftover["iam_jit_home_exists"] is False
    assert leftover["preserved_paths"] == []
    assert post["clean"] is True


# ---------------------------------------------------------------------------
# Test 4 — --keep-audit-logs preserves bouncer/state.db variant
# ---------------------------------------------------------------------------


def test_keep_audit_logs_lists_state_db_variants_in_preserved_paths(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The full set of audit-bearing files (audit.jsonl,
    bouncer/state.db, bouncer/state.db-shm, bouncer/state.db-wal,
    canary/issues.jsonl) MUST each appear in preserved_paths when
    present on disk.
    """
    paths = _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(dry_run=False, keep_audit_logs=True)

    assert result["status"] == "ok"
    # Observable: all audit-bearing files still present.
    assert paths["state.db"].exists()
    assert paths["state.db-wal"].exists()
    assert paths["state.db-shm"].exists()
    assert paths["canary/issues.jsonl"].exists()

    preserved = result["post_check"]["leftover"]["preserved_paths"]

    # Each audit-bearing file is enumerated.
    assert any(p.endswith("state.db") for p in preserved), preserved
    assert any(p.endswith("state.db-wal") for p in preserved), preserved
    assert any(p.endswith("state.db-shm") for p in preserved), preserved
    assert any(
        p.endswith("issues.jsonl") for p in preserved
    ), preserved
    assert any(p.endswith("audit.jsonl") for p in preserved), preserved


# ---------------------------------------------------------------------------
# Test 5 — sabotage check: the path-exists probe is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_probe_always_false_re_introduces_pre_fix_lie(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Monkey-patch the inventory probe to always say the directory
    doesn't exist; assert that the post-check then RE-INTRODUCES the
    pre-fix lie (iam_jit_home_exists:false while files remain on disk).

    This proves the post-check truly relies on
    ``_inventory_installed_state``'s probe rather than on the operator's
    flag. If a future refactor short-circuits the probe + falls back to
    "trust the flag", this test will detect the regression.

    Calls ``_verify_clean_state`` directly (rather than going through
    the full ``run_uninstall``) so we can isolate the probe behavior
    without re-seeding state across an in-process uninstall.
    """
    _seed_install(isolated_iam_jit_home)
    assert (isolated_iam_jit_home / "audit.jsonl").exists()

    # Baseline: real probe sees the directory + audit file.
    post_real = cu._verify_clean_state(keep_audit_logs=True)
    assert post_real["leftover"]["iam_jit_home_exists"] is True
    assert any(
        p.endswith("audit.jsonl")
        for p in post_real["leftover"]["preserved_paths"]
    )

    # Sabotage: replace the inventory probe with one that lies about
    # the directory's existence. The directory is STILL on disk — only
    # the probe was tampered with.
    real_inventory = cu._inventory_installed_state

    def _lying_inventory() -> dict:
        inv = real_inventory()
        inv["iam_jit_home_exists"] = False  # the pre-fix lie
        return inv

    monkeypatch.setattr(cu, "_inventory_installed_state", _lying_inventory)

    post_lie = cu._verify_clean_state(keep_audit_logs=True)

    # Observable: the directory + audit.jsonl are STILL on disk.
    assert isolated_iam_jit_home.exists()
    assert (isolated_iam_jit_home / "audit.jsonl").exists()

    # But the sabotaged probe causes the post-check to LIE — exactly
    # the pre-fix behavior. This proves the real probe is load-bearing:
    # without it, the post-check returns to lying.
    assert post_lie["leftover"]["iam_jit_home_exists"] is False, (
        "Sabotage check: if the probe is bypassed, the post-check "
        "should re-acquire the pre-fix lying behavior; if it does "
        "NOT, the load-bearing path-check is somewhere else and "
        "needs to be re-pinned by this test"
    )
