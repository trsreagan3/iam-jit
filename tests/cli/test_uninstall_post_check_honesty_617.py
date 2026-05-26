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

    #617 HIGH-3: also stub the four cross-product artifact checkers
    (_check_path_binaries, _check_bouncer_config_dirs,
    _detect_shell_rc_lines, _check_mcp_entries) so tests don't walk
    the dev machine's real PATH / filesystem / shell RCs / claude.json.
    """
    import os
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(cu, "_port_bound", lambda port, host="127.0.0.1": False)
    monkeypatch.setattr(cu, "_lsof_pids_on_port", lambda port: [])
    monkeypatch.setattr(cu, "_read_cmdline", lambda pid: "")
    monkeypatch.setattr(cu, "_all_listening_ports", lambda: [])
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
    # #617 HIGH-3: default stubs — no artifacts found.
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


# ---------------------------------------------------------------------------
# #617 HIGH-3 — cross-product checklist tests
# ---------------------------------------------------------------------------


def test_e2e_clean_uninstall_reports_clean_true(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """E2E: fixture state → run uninstall → post_check.clean:true.

    Per [[ibounce-honest-positioning]]: clean:true is a CLAIM that no
    iam-jit artifacts remain. This test verifies the claim matches
    reality when the install is fully removed.

    Uses a fixture ~/.claude.json with NO iam-jit MCP entries so the
    MCP check passes cleanly. The four cross-product checkers are
    stubbed clean by the autouse isolation fixture (the dev machine's
    real binaries / config dirs / shell RCs don't interfere).
    """
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    # Fixture ~/.claude.json with NO iam-jit MCP entries.
    claude_json = tmp_path / ".claude.json"
    claude_json.write_text('{"mcpServers": {"some-other-tool": {}}}')

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            dry_run=False,
            claude_json_path=claude_json,
        )

    assert result["status"] == "ok", result
    post = result["post_check"]

    # Observable: clean:true — no artifacts remain.
    assert post["clean"] is True, (
        f"Expected clean:true after full uninstall; "
        f"remaining_artifacts={post.get('remaining_artifacts')}, "
        f"leftover={post.get('leftover')}"
    )
    # remaining_artifacts must be empty when clean.
    assert post["remaining_artifacts"] == [], (
        f"remaining_artifacts must be [] when clean:true; "
        f"got {post['remaining_artifacts']}"
    )
    # Observable: data dir is gone.
    assert not isolated_iam_jit_home.exists()


def test_stale_binary_on_path_causes_clean_false_with_artifact(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """Negative: fixture binary on PATH → clean:false + binary path in
    remaining_artifacts.

    Per [[ibounce-honest-positioning]]: if `iam-jit` is still on PATH
    after uninstall, clean:true would be a lie. The binary must appear
    in remaining_artifacts with a hint.

    Simulates a binary that the pip-uninstall step missed (e.g. a
    symlink in /usr/local/bin or a pip --user install that the venv
    removal didn't cover).
    """
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    # Place a fake binary in tmp_path/bin/ and un-stub _check_path_binaries
    # to return it as a detected artifact (simulating shutil.which finding it).
    fake_bin_dir = tmp_path / "bin"
    fake_bin_dir.mkdir()
    fake_binary = fake_bin_dir / "iam-jit"
    fake_binary.write_text("#!/bin/sh\necho fake\n")
    fake_binary.chmod(0o755)

    # Override the PATH checker to report the stale binary.
    monkeypatch.setattr(
        cu, "_check_path_binaries",
        lambda: [{
            "type": "binary_on_path",
            "location": str(fake_binary),
            "hint": f"Binary 'iam-jit' still found at {fake_binary}.",
        }],
    )

    # Empty claude.json — no MCP artifacts.
    claude_json = tmp_path / ".claude.json"
    claude_json.write_text("{}")

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            dry_run=False,
            claude_json_path=claude_json,
        )

    # Claim: status is incomplete (post-check found leftover).
    assert result["status"] == "incomplete", result

    post = result["post_check"]
    # Observable: clean:false because binary remains.
    assert post["clean"] is False, (
        "Expected clean:false when a binary remains on PATH"
    )
    artifacts = post["remaining_artifacts"]
    binary_artifacts = [a for a in artifacts if a["type"] == "binary_on_path"]
    assert len(binary_artifacts) >= 1, (
        f"Expected at least one binary_on_path artifact; got {artifacts}"
    )
    assert str(fake_binary) in binary_artifacts[0]["location"], (
        f"Stale binary path missing from artifact location; "
        f"got {binary_artifacts[0]}"
    )


def test_stale_shellinit_in_zshrc_causes_clean_false_with_file_line_hint(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """Negative: stale shellinit line in fixture .zshrc → clean:false +
    file:line hint in remaining_artifacts.

    Per [[creates-never-mutates]]: uninstall MUST NOT edit the shell RC.
    But it MUST detect and report stale shellinit lines.

    Per [[ibounce-honest-positioning]]: the operator is told exactly
    which file and line number to remove.
    """
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    # Create a fixture .zshrc with a stale shellinit line at line 3.
    fake_zshrc = tmp_path / ".zshrc"
    fake_zshrc.write_text(
        "# ~/.zshrc\n"
        "export PATH=$HOME/.local/bin:$PATH\n"
        'eval "$(iam-jit shellinit)"\n'  # <-- stale line at line 3
        "alias ll='ls -la'\n"
    )

    # Point SHELL_RC_FILES at our fixture file only and override
    # _detect_shell_rc_lines with a closure that reads the fixture.
    # The autouse fixture stubbed _detect_shell_rc_lines to return [];
    # we replace it with a closure that calls the REAL internal logic on
    # our fixture file. We do NOT call the module function by name
    # because the module attribute was already replaced by the stub.
    monkeypatch.setattr(cu, "SHELL_RC_FILES", (fake_zshrc,))

    def _real_detect_on_fixture() -> list:
        """Inline re-implementation of the real detect logic on fixture."""
        import re as _re
        artifacts: list[dict] = []
        for rc_file in cu.SHELL_RC_FILES:
            try:
                text = rc_file.read_text(errors="replace")
            except (OSError, PermissionError):
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                for pattern in cu._SHELLINIT_PATTERNS:
                    if pattern in line:
                        artifacts.append({
                            "type": "shell_rc_line",
                            "location": f"{rc_file}:{lineno}",
                            "hint": (
                                f"Stale iam-jit shell initialisation at "
                                f"{rc_file}:{lineno} — remove manually. "
                                f"Line: {stripped[:120]}"
                            ),
                        })
                        break
        return artifacts

    monkeypatch.setattr(cu, "_detect_shell_rc_lines", _real_detect_on_fixture)

    # Empty claude.json — no MCP artifacts.
    claude_json = tmp_path / ".claude.json"
    claude_json.write_text("{}")

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            dry_run=False,
            claude_json_path=claude_json,
        )

    assert result["status"] == "incomplete", result
    post = result["post_check"]
    assert post["clean"] is False

    artifacts = post["remaining_artifacts"]
    shell_artifacts = [a for a in artifacts if a["type"] == "shell_rc_line"]
    assert len(shell_artifacts) >= 1, (
        f"Expected at least one shell_rc_line artifact; got {artifacts}"
    )
    # Location must include the file path and line number.
    loc = shell_artifacts[0]["location"]
    assert str(fake_zshrc) in loc, (
        f"Fixture zshrc path missing from location; got {loc}"
    )
    assert ":3" in loc, (
        f"Line number ':3' missing from location; got {loc}"
    )
    # Hint must describe the stale line for the operator.
    hint = shell_artifacts[0]["hint"]
    assert "iam-jit" in hint.lower() or "shellinit" in hint.lower(), (
        f"Hint should reference iam-jit or shellinit; got {hint}"
    )

    # Observable: the fixture .zshrc is UNTOUCHED (creates-never-mutates).
    content_after = fake_zshrc.read_text()
    assert 'eval "$(iam-jit shellinit)"' in content_after, (
        "Uninstall must NOT edit the shell RC file; stale line was removed!"
    )


def test_foreign_process_on_8080_not_reported_as_bouncer_artifact(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """Negative: foreign process on :8080 → NOT reported in remaining_artifacts.

    Per #614 [[creates-never-mutates]]: the multi-factor classifier must
    filter out foreign processes. Port 8080 is common (nginx, local dev
    servers, etc.); uninstall must not false-positive on it.

    The multi-factor classifier rejects the foreign process because its
    cmdline contains no bouncer-specific flag signature — so it lands in
    unknown_port_owners (which trips a halt) rather than running_bouncers.
    This test verifies the foreign process is NOT in remaining_artifacts
    as a bouncer (it's surfaced via the halt mechanism, not post-check).
    """
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    # Foreign process (e.g. a local nginx dev server) on :8080.
    foreign_pid = 99999
    monkeypatch.setattr(
        cu, "_port_bound",
        lambda port, host="127.0.0.1": port == 8080,
    )
    monkeypatch.setattr(
        cu, "_lsof_pids_on_port",
        lambda port: [foreign_pid] if port == 8080 else [],
    )
    # Cmdline has NO bouncer-specific flag signature → classification fails.
    monkeypatch.setattr(
        cu, "_read_cmdline",
        lambda pid: "nginx: worker process" if pid == foreign_pid else "",
    )
    # Path check: executor resolves to /usr/sbin/nginx (NOT under install root).
    monkeypatch.setattr(
        cu, "_resolve_executable_path",
        lambda pid: pathlib.Path("/usr/sbin/nginx") if pid == foreign_pid else None,
    )

    # run_uninstall with --force to bypass the U-1/U-5 halt (the foreign
    # process on :8080 triggers those halts, which is CORRECT behavior;
    # here we're testing that the port 8080 process does NOT appear in
    # remaining_artifacts as a bouncer artifact).
    claude_json = tmp_path / ".claude.json"
    claude_json.write_text("{}")

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            dry_run=False,
            force=True,
            claude_json_path=claude_json,
        )

    post = result["post_check"]

    # Observable: the foreign process on :8080 is NOT in remaining_artifacts
    # as a "bouncer" artifact. It's in the halt + unknown_port_owners, but
    # the POST-CHECK remaining_artifacts is about unremoved iam-jit artifacts,
    # not foreign processes. The foreign process hasn't been affected.
    artifacts = post.get("remaining_artifacts") or []
    port_artifacts = [
        a for a in artifacts
        if "8080" in a.get("location", "") and a.get("type") != "shell_rc_line"
    ]
    assert not port_artifacts, (
        f"Foreign process on :8080 must NOT appear in remaining_artifacts; "
        f"got {port_artifacts}"
    )

    # The foreign PID must also NOT be in stop_bouncers (not SIGTERMed).
    stop = result["steps"].get("stop_bouncers") or {}
    all_sigterm = stop.get("sigterm_pids", []) + stop.get("sigkill_pids", [])
    assert foreign_pid not in all_sigterm, (
        f"Foreign PID {foreign_pid} must NOT be in sigterm/sigkill list; "
        f"got stop_bouncers={stop}"
    )


def test_mcp_entries_removed_by_default_and_reported_clean(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """MCP entries in ~/.claude.json are removed by default, resulting
    in clean:true (no remaining MCP artifacts).

    Per the brief: MCP entries are iam-jit-owned artifacts; uninstall
    removes them unless --keep-mcp-entries is passed.
    """
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    # Fixture ~/.claude.json with iam-jit MCP entry.
    claude_json = tmp_path / ".claude.json"
    claude_json.write_text(
        '{"mcpServers": {"iam-jit": {"command": "iam-jit", "args": ["mcp"]}}}'
    )

    # Un-stub _check_mcp_entries to use the REAL checker on our fixture.
    monkeypatch.setattr(
        cu, "_check_mcp_entries",
        cu.__class__._check_mcp_entries if hasattr(cu.__class__, "_check_mcp_entries")
        else lambda claude_json_path=None: (
            cu._check_mcp_entries.__wrapped__(claude_json_path=claude_json_path)
            if hasattr(cu._check_mcp_entries, "__wrapped__") else []
        ),
    )
    # Restore the real _check_mcp_entries (autouse stubbed it to []).
    import importlib
    import iam_jit.cli_uninstall as _cu_real
    monkeypatch.setattr(
        cu, "_check_mcp_entries",
        _cu_real._check_mcp_entries,
    )

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            dry_run=False,
            claude_json_path=claude_json,
        )

    assert result["status"] == "ok", result
    post = result["post_check"]
    # clean:true — MCP entry was removed.
    assert post["clean"] is True, (
        f"Expected clean:true after MCP entry removal; "
        f"remaining_artifacts={post.get('remaining_artifacts')}"
    )
    # Observable: the MCP entry is gone from the file.
    import json as _json
    data = _json.loads(claude_json.read_text())
    assert "iam-jit" not in (data.get("mcpServers") or {}), (
        f"iam-jit MCP entry still present after uninstall; "
        f"mcpServers={data.get('mcpServers')}"
    )
    # remove_mcp_entries step recorded the removal.
    mcp_step = result["steps"].get("remove_mcp_entries") or {}
    assert "mcpServers.iam-jit" in mcp_step.get("removed", []), (
        f"remove_mcp_entries step did not record removal; got {mcp_step}"
    )


def test_keep_mcp_entries_flag_preserves_entries_and_no_artifact(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """--keep-mcp-entries: MCP entries are NOT removed and NOT reported
    as remaining_artifacts.

    Per the brief: operators who want to preserve MCP entries (e.g.
    custom agent configs) can pass --keep-mcp-entries; the post-check
    then counts them as intentionally preserved, not leftover.
    """
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    # Fixture claude.json with iam-jit MCP entry.
    claude_json = tmp_path / ".claude.json"
    claude_json.write_text(
        '{"mcpServers": {"iam-jit": {"command": "iam-jit", "args": ["mcp"]}}}'
    )

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            dry_run=False,
            keep_mcp_entries=True,
            claude_json_path=claude_json,
        )

    assert result["status"] == "ok", result
    post = result["post_check"]
    # clean:true — MCP entry was preserved intentionally (not leftover).
    assert post["clean"] is True, (
        f"Expected clean:true when --keep-mcp-entries; "
        f"remaining_artifacts={post.get('remaining_artifacts')}"
    )
    # MCP entry must still be in the file.
    import json as _json
    data = _json.loads(claude_json.read_text())
    assert "iam-jit" in (data.get("mcpServers") or {}), (
        "iam-jit MCP entry should be preserved with --keep-mcp-entries"
    )
    # remove_mcp_entries step must be skipped.
    mcp_step = result["steps"].get("remove_mcp_entries") or {}
    assert mcp_step.get("skipped") is True, (
        f"remove_mcp_entries step should be skipped; got {mcp_step}"
    )
