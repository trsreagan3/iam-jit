"""#617 MED-3 / MED-4 / MED-5 — uninstall UX additions.

MED-3: Re-init hint after successful uninstall.
  After a clean or incomplete uninstall, stdout includes a "Tip:" line
  directing the operator to `iam-jit init`. Operators who chose
  --keep-audit-logs get a variant hinting at the preserved log location.

MED-4: Version-drift WARN in dry-run report.
  When the `iam-jit` binary on PATH reports a different version from
  `iam_jit.__version__` (installed Python package), the dry-run report
  includes a WARN entry (`version_drift_warn` in the result dict +
  visible in the CLI output). Matching versions → no warn.

MED-5: CANARY.md preservation.
  `_step_remove_iam_jit_home()` NEVER deletes CANARY.md files (under
  ``<data_dir>/canary/CANARY.md`` or ``<data_dir>/CANARY.md``). The
  post-check surfaces them in `remaining_artifacts` with a preserve-hint
  so the operator can review + remove manually.

Per [[tests-and-independent-uat-required]]: one test per MED, with a
sabotage check where the load-bearing code path is non-obvious.
Per [[scorer-is-ground-truth]]: tests don't tuned to pass —
they describe the behaviour we intend to ship.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
from unittest import mock

import pytest
from click.testing import CliRunner

import iam_jit.cli_uninstall as cu
from iam_jit.cli import main

# Capture real implementations BEFORE any autouse fixture replaces them
# with stubs. Tests that need the real logic restore the attribute via
# monkeypatch.setattr(cu, "...", _REAL_...).
_REAL_CHECK_VERSION_DRIFT = cu._check_version_drift
_REAL_DETECT_CANARY_MD_ARTIFACTS = cu._detect_canary_md_artifacts


# ---------------------------------------------------------------------------
# Isolation — mirror tests/cli/test_uninstall.py shape exactly
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _default_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent the dev machine's real state from tripping tests."""
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
    monkeypatch.setattr(
        cu, "_resolve_executable_path",
        lambda pid: fake_install_dir / "ibounce",
    )
    monkeypatch.setattr(cu, "_pid_owner_uid", lambda pid: os.geteuid())
    monkeypatch.setattr(cu, "_check_path_binaries", lambda: [])
    monkeypatch.setattr(cu, "_check_bouncer_config_dirs", lambda: [])
    monkeypatch.setattr(cu, "_detect_shell_rc_lines", lambda: [])
    monkeypatch.setattr(
        cu, "_check_mcp_entries", lambda claude_json_path=None: [],
    )
    # MED-4: stub _check_version_drift so it doesn't shell out to the
    # real `iam-jit` binary on the dev machine. Default: no drift.
    monkeypatch.setattr(cu, "_check_version_drift", lambda: None)
    # MED-5: stub _detect_canary_md_artifacts so tests that DON'T cover
    # MED-5 don't pick up real CANARY.md files on the dev machine.
    monkeypatch.setattr(
        cu, "_detect_canary_md_artifacts",
        lambda data_dir=None: [],
    )
    # MED-2: stub autopilot port reader so tests are hermetic.
    monkeypatch.setattr(
        cu, "_read_autopilot_ports",
        lambda data_dir=None: {},
    )
    monkeypatch.delenv(cu.IAM_JIT_DATA_DIR_ENV, raising=False)


@pytest.fixture
def isolated_iam_jit_home(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    """Redirect module-level paths to a tmp dir."""
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
    """Populate `home` with a minimal fake iam-jit install."""
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
    (bouncer_dir / "state.db").write_text("seed")
    paths["state.db"] = bouncer_dir / "state.db"

    audit = home / "audit.jsonl"
    audit.write_text('{"seq":1}\n')
    paths["audit.jsonl"] = audit

    canary_dir = home / "canary"
    canary_dir.mkdir()
    (canary_dir / "issues.jsonl").write_text('{"ts":"2026-05-26T00:00:00Z"}\n')
    paths["canary/issues.jsonl"] = canary_dir / "issues.jsonl"
    return paths


# ---------------------------------------------------------------------------
# MED-3: re-init hint after successful uninstall
# ---------------------------------------------------------------------------


def test_med3_reinit_hint_in_stdout_after_successful_uninstall(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MED-3: After a clean uninstall, CLI stdout includes the Tip: re-init
    hint so the operator knows `iam-jit init` is the path forward.

    Per [[ibounce-honest-positioning]]: uninstall must tell the operator
    what state they're in, not just what was removed.
    """
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    runner = CliRunner()
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = runner.invoke(main, ["uninstall", "--yes"])

    assert result.exit_code == 0, result.output

    # Observable: re-init hint string is present in stdout.
    assert "iam-jit init" in result.output, (
        f"MED-3: re-init hint 'iam-jit init' missing from post-uninstall "
        f"stdout:\n{result.output}"
    )
    assert "Tip:" in result.output, (
        f"MED-3: 'Tip:' marker missing from post-uninstall stdout:\n{result.output}"
    )
    assert "previous accounts/profiles/audit log have been removed" in result.output, (
        f"MED-3: state-cleared message missing:\n{result.output}"
    )


def test_med3_reinit_hint_keep_audit_logs_variant(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MED-3: When --keep-audit-logs is set, the re-init hint variant
    mentions that accounts/profiles have been removed (logs kept).
    """
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    runner = CliRunner()
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = runner.invoke(main, ["uninstall", "--yes", "--keep-audit-logs"])

    assert result.exit_code == 0, result.output

    # Observable: Tip still present with --keep-audit-logs variant.
    assert "iam-jit init" in result.output, (
        f"MED-3: re-init hint missing under --keep-audit-logs:\n{result.output}"
    )
    assert "Tip:" in result.output
    # Should mention accounts/profiles removed.
    assert "accounts" in result.output.lower() or "profiles" in result.output.lower(), (
        f"MED-3: --keep-audit-logs hint should mention accounts/profiles:\n{result.output}"
    )


def test_med3_hint_not_in_dry_run_output(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MED-3: The re-init hint must NOT appear in --dry-run output
    (nothing was actually removed).
    """
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    runner = CliRunner()
    result = runner.invoke(main, ["uninstall", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "previous accounts/profiles/audit log have been removed" not in result.output, (
        f"MED-3: re-init hint must NOT appear in --dry-run (nothing removed):\n{result.output}"
    )


# ---------------------------------------------------------------------------
# MED-4: version-drift WARN in dry-run report
# ---------------------------------------------------------------------------


def test_med4_version_drift_warn_in_result_when_versions_mismatch(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MED-4: When binary version != package version, run_uninstall()
    returns a version_drift_warn dict with 'pkg' + 'bin' keys.

    Monkeypatch _check_version_drift to simulate a mismatch.
    """
    # Restore real _check_version_drift (autouse fixture stubs it to None).
    monkeypatch.setattr(
        cu, "_check_version_drift",
        lambda: {"pkg": "1.0.0", "bin": "0.9.5"},
    )
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    result = cu.run_uninstall(dry_run=True)

    # Observable: version_drift_warn is populated.
    drift = result.get("version_drift_warn")
    assert drift is not None, (
        f"MED-4: version_drift_warn should be a dict when versions mismatch; "
        f"got {drift}"
    )
    assert drift["pkg"] == "1.0.0", f"MED-4: pkg version wrong: {drift}"
    assert drift["bin"] == "0.9.5", f"MED-4: bin version wrong: {drift}"


def test_med4_version_drift_warn_in_cli_output(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MED-4: The WARN is visible in CLI --dry-run output when drift is detected."""
    monkeypatch.setattr(
        cu, "_check_version_drift",
        lambda: {"pkg": "1.0.0", "bin": "0.9.5"},
    )
    _seed_install(isolated_iam_jit_home)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    runner = CliRunner()
    result = runner.invoke(main, ["uninstall", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "WARN" in result.output, (
        f"MED-4: WARN token missing from --dry-run output when version drift "
        f"is present:\n{result.output}"
    )
    assert "version drift" in result.output.lower(), (
        f"MED-4: 'version drift' text missing:\n{result.output}"
    )
    assert "0.9.5" in result.output, (
        f"MED-4: binary version '0.9.5' not in output:\n{result.output}"
    )


def test_med4_no_warn_when_versions_match(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MED-4: When versions match (or check is skipped), version_drift_warn is None."""
    # autouse fixture already stubs _check_version_drift -> None.
    result = cu.run_uninstall(dry_run=True)

    # Observable: no drift warn.
    assert result.get("version_drift_warn") is None, (
        f"MED-4: version_drift_warn should be None when versions match; "
        f"got {result.get('version_drift_warn')}"
    )
    # WARN must not appear in the JSON output.
    runner = CliRunner()
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    cli_result = runner.invoke(main, ["uninstall", "--dry-run", "--json"])
    payload = json.loads(cli_result.output)
    assert payload.get("version_drift_warn") is None, (
        f"MED-4: JSON output version_drift_warn should be null: {payload}"
    )


def test_med4_check_version_drift_logic_real_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MED-4 unit: _check_version_drift() returns a dict when binary
    version != package version, None when they match.

    Uses monkeypatching of shutil.which + subprocess.run in the
    cli_uninstall module namespace to avoid shelling out to the real
    `iam-jit` binary.

    NOTE: the autouse fixture stubs ``cu._check_version_drift`` to
    ``lambda: None``. To test the REAL logic we must restore the
    original function. We do this by re-patching cu._check_version_drift
    to the actual implementation sourced from the original module state
    (captured below before the fixture runs — but since this is a unit
    test that calls the implementation directly, we just test the
    internals in isolation by restoring them here).
    """
    import iam_jit as _pkg

    # Import the original module (not the monkeypatched attribute).
    # importlib.reload would be heavy; instead re-import the function
    # from source using importlib to bypass the existing module cache
    # attribute (which was patched by the autouse fixture).
    import importlib
    import sys
    # Remove the cached module to force reimport.
    _mod_name = "iam_jit.cli_uninstall"
    # We do NOT reload; instead we get the original function object
    # from the module by temporarily restoring the attribute.
    # The autouse fixture sets cu._check_version_drift = lambda: None.
    # We know the real function is in the module's original __dict__
    # BEFORE the monkeypatch ran. Since we can't get it back from the
    # module (monkeypatch already replaced it), we can test the
    # equivalent logic by restoring via the function's closure / source.
    #
    # Simplest approach: restore the REAL function via its known
    # importlib path, then patch the helpers it calls.
    #
    # We reload the module in isolation by importing it fresh into a
    # temp namespace.
    import importlib as _il
    _mod = _il.import_module("iam_jit.cli_uninstall")
    # After autouse fixture: cu._check_version_drift = lambda: None
    # BUT the actual function body still exists in the module's source.
    # Re-set the attribute from the module's original function via a
    # direct attribute lookup on the MODULE object (before the patching):
    # Actually, monkeypatch patches the module attribute, not the
    # function itself. So _mod._check_version_drift IS the lambda.
    # The only way to get the real function is to NOT let autouse patch
    # it for this test — but autouse runs first.
    #
    # WORKAROUND: declare the real implementation inline and test THAT.
    # This is valid because we're testing the semantic contract
    # (drift detection logic), not the exact function identity.

    pkg_ver = _pkg.__version__

    # Restore the real _check_version_drift by patching cu to use the
    # original source function. We do this by importing it before the
    # monkeypatch in the module scope — see `_REAL_CHECK_VERSION_DRIFT`
    # at module level below.
    #
    # For this test, we directly test via the `run_uninstall` + the
    # monkeypatched helpers approach, which IS the canonical MED-4 test
    # per the brief spec: "monkeypatch `iam-jit --version` stdout to
    # mismatch `iam_jit.__version__` → dry-run includes WARN".

    # Restore the real _check_version_drift function for this test by
    # setting it to a real implementation that calls the mocked helpers.
    # We patch shutil.which + subprocess.run in the module.
    monkeypatch.setattr(
        cu, "_check_version_drift",
        _REAL_CHECK_VERSION_DRIFT,
    )
    monkeypatch.setattr(
        cu.shutil, "which",
        lambda name: "/fake/iam-jit" if name == "iam-jit" else None,
    )

    # Simulate binary returning a DIFFERENT version.
    with mock.patch.object(
        subprocess,
        "run",
        return_value=subprocess.CompletedProcess(
            args=["/fake/iam-jit", "--version"],
            returncode=0,
            stdout="iam-jit, version 0.1.0",
            stderr="",
        ),
    ):
        drift = cu._check_version_drift()

    if pkg_ver != "0.1.0":
        assert drift is not None, (
            f"MED-4: expected drift dict when bin=0.1.0 != pkg={pkg_ver}"
        )
        assert drift["bin"] == "0.1.0", f"MED-4: bin version wrong: {drift}"
        assert drift["pkg"] == pkg_ver, f"MED-4: pkg version wrong: {drift}"
    else:
        # If package IS 0.1.0, the test is vacuously correct (no drift).
        assert drift is None

    # Simulate binary returning the SAME version as the package.
    with mock.patch.object(
        subprocess,
        "run",
        return_value=subprocess.CompletedProcess(
            args=["/fake/iam-jit", "--version"],
            returncode=0,
            stdout=f"iam-jit, version {pkg_ver}",
            stderr="",
        ),
    ):
        no_drift = cu._check_version_drift()

    assert no_drift is None, (
        f"MED-4: expected None when binary reports same version as package "
        f"({pkg_ver}); got {no_drift}"
    )


# ---------------------------------------------------------------------------
# MED-5: CANARY.md preservation
# ---------------------------------------------------------------------------


def test_med5_canary_md_not_deleted_by_uninstall(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MED-5: ``<data_dir>/canary/CANARY.md`` is NOT deleted by
    `_step_remove_iam_jit_home()`, even without --keep-audit-logs.

    This is the primary correctness test: the file must survive the wipe.
    """
    _seed_install(isolated_iam_jit_home)

    # Create the CANARY.md fixture.
    canary_dir = isolated_iam_jit_home / "canary"
    canary_dir.mkdir(exist_ok=True)
    canary_md = canary_dir / "CANARY.md"
    canary_md.write_text(
        "# Canary post-mortem\n"
        "Deploy 2026-05-24: ibounce crash under concurrent kbounce load.\n"
        "Root cause: TODO.\n"
    )
    assert canary_md.exists(), "pre-condition: CANARY.md must exist before test"

    # Run the removal step WITHOUT --keep-audit-logs.
    result = cu._step_remove_iam_jit_home(
        dry_run=False,
        keep_audit_logs=False,
        backup_dir=None,
        data_dir=isolated_iam_jit_home,
    )

    # Observable: CANARY.md is still on disk (NOT in removed_paths).
    assert canary_md.exists(), (
        f"MED-5: CANARY.md was deleted by uninstall — it must be preserved. "
        f"removed_paths={result['removed_paths']}"
    )
    assert str(canary_md) not in result["removed_paths"], (
        f"MED-5: CANARY.md path appears in removed_paths; it must be preserved. "
        f"removed_paths={result['removed_paths']}"
    )

    # Observable: CANARY.md appears in canary_md_preserved.
    preserved = result.get("canary_md_preserved") or []
    assert str(canary_md) in preserved, (
        f"MED-5: CANARY.md not in canary_md_preserved; got {preserved}"
    )


def test_med5_canary_md_in_remaining_artifacts(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MED-5: After uninstall, `_detect_canary_md_artifacts()` surfaces the
    CANARY.md in remaining_artifacts so the operator can review + remove.

    Restore the real _detect_canary_md_artifacts for this test (autouse
    fixture stubs it to `lambda: []`).
    """
    monkeypatch.setattr(cu, "_detect_canary_md_artifacts", _REAL_DETECT_CANARY_MD_ARTIFACTS)

    _seed_install(isolated_iam_jit_home)

    canary_dir = isolated_iam_jit_home / "canary"
    canary_dir.mkdir(exist_ok=True)
    canary_md = canary_dir / "CANARY.md"
    canary_md.write_text("# Canary post-mortem notes\n")
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            dry_run=False,
            data_dir=isolated_iam_jit_home,
        )

    # Observable: CANARY.md is in remaining_artifacts.
    remaining = result.get("post_check", {}).get("remaining_artifacts") or []
    canary_entries = [
        a for a in remaining
        if a.get("type") == "canary_md"
    ]
    assert canary_entries, (
        f"MED-5: canary_md entries missing from remaining_artifacts; "
        f"remaining_artifacts={remaining}"
    )
    assert any(str(canary_md) in e["location"] for e in canary_entries), (
        f"MED-5: CANARY.md path not in any canary_md artifact location; "
        f"canary_entries={canary_entries}"
    )

    # Observable: hint mentions reviewing/removing manually.
    hint = canary_entries[0].get("hint", "")
    assert "preserve" in hint.lower() or "review" in hint.lower() or "manually" in hint.lower(), (
        f"MED-5: canary_md hint should mention preservation; got hint={hint}"
    )

    # Observable: CANARY.md is still on disk.
    assert canary_md.exists(), (
        f"MED-5: CANARY.md was deleted despite being in remaining_artifacts"
    )


def test_med5_canary_md_does_not_cause_clean_false(
    isolated_iam_jit_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MED-5: CANARY.md is an intentional preserve — it must NOT flip
    `post_check.clean` from True to False when it's the only remaining
    file in the data dir.

    Per the spec: CANARY.md appears in remaining_artifacts for operator
    awareness but is NOT counted as a dirty leftover (like --keep-audit-logs
    preserved files).
    """
    monkeypatch.setattr(cu, "_detect_canary_md_artifacts", _REAL_DETECT_CANARY_MD_ARTIFACTS)

    _seed_install(isolated_iam_jit_home)

    # Create CANARY.md.
    canary_dir = isolated_iam_jit_home / "canary"
    canary_dir.mkdir(exist_ok=True)
    canary_md = canary_dir / "CANARY.md"
    canary_md.write_text("# Canary notes — must not force clean=False\n")

    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: isolated_iam_jit_home / "nogo",
    )
    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            dry_run=False,
            data_dir=isolated_iam_jit_home,
        )

    post = result.get("post_check") or {}

    # Observable: CANARY.md didn't flip clean to False.
    assert post.get("clean") is True, (
        f"MED-5: CANARY.md preservation must NOT set clean=False; "
        f"post_check={post}"
    )

    # Observable: CANARY.md still exists on disk.
    assert canary_md.exists(), (
        f"MED-5: CANARY.md was deleted even though it should be preserved"
    )

    # Observable: CANARY.md appears in remaining_artifacts (informational).
    remaining = post.get("remaining_artifacts") or []
    assert any(a.get("type") == "canary_md" for a in remaining), (
        f"MED-5: canary_md must appear in remaining_artifacts for operator "
        f"awareness even when clean=True; remaining={remaining}"
    )
