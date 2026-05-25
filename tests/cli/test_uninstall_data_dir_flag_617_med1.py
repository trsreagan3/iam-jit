"""#617 MED-1 — `iam-jit uninstall --data-dir` + `IAM_JIT_DATA_DIR` env.

UAT-Lifecycle 2026-05-25 found:

  ``iam-jit uninstall`` had no ``--data-dir`` flag. It always targeted
  ``~/.iam-jit/``. An operator who used ``--data-dir /opt/iam-jit-prod``
  (or ``IAM_JIT_DATA_DIR`` env) for ``iam-jit serve`` could not
  uninstall the same way without fragile HOME-redirect workarounds.

Per ``[[ibounce-honest-positioning]]``: CLI surfaces that target the
same state must be symmetric — operator can act on the same tree they
installed against. Per ``[[creates-never-mutates]]``: uninstall must
operate on the operator's actual data dir, not a guessed one.

These tests pin:

  1. Default home: no flag, no env -> targets ~/.iam-jit/.
  2. ``--data-dir /tmp/x`` -> targets /tmp/x; ~/.iam-jit/ untouched.
  3. ``IAM_JIT_DATA_DIR=/tmp/y`` env -> targets /tmp/y; ~/.iam-jit/
     untouched.
  4. CLI flag wins over env (precedence).
  5. Path expansion: ``--data-dir ~/foo`` resolves to $HOME/foo.
  6. ``post_check.iam_jit_home_exists`` honors data-dir (preserves
     #617 HIGH-3 honest-shape against the resolved tree).
  7. Output mentions the resolved path so operator can verify.
  8. Sabotage: monkeypatch ``resolve_data_dir`` to always return the
     default; confirm test 2 then INCORRECTLY scans ~/.iam-jit/ —
     proves the resolver is load-bearing.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
from unittest import mock

import pytest
from click.testing import CliRunner

import iam_jit.cli_uninstall as cu
from iam_jit.cli import main


# ---------------------------------------------------------------------------
# Isolation — mirror tests/cli/test_uninstall.py shape
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _default_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent the dev machine's real bouncers / ports / go-bin from
    tripping halt conditions during these tests.
    """
    monkeypatch.setattr(cu, "_find_pids_for_process", lambda name: [])
    monkeypatch.setattr(
        cu, "_port_bound", lambda port, host="127.0.0.1": False,
    )
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
    # Make sure env doesn't leak from the host into the tests that
    # explicitly want "no env set".
    monkeypatch.delenv(cu.IAM_JIT_DATA_DIR_ENV, raising=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_install(home: pathlib.Path) -> dict[str, pathlib.Path]:
    """Populate `home` to look like a real iam-jit install.

    Mirrors the helper in tests/cli/test_uninstall.py. Returns a map of
    name -> Path so tests can assert presence/absence by name.
    """
    home.mkdir(parents=True, exist_ok=True)
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
    paths["state.db"] = bouncer_dir / "state.db"

    audit = home / "audit.jsonl"
    audit.write_text('{"seq":1}\n')
    paths["audit.jsonl"] = audit
    return paths


# ---------------------------------------------------------------------------
# Test 1 — Default: no flag, no env -> targets ~/.iam-jit/
# ---------------------------------------------------------------------------


def test_default_home_no_flag_no_env_targets_module_default(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When neither --data-dir nor IAM_JIT_DATA_DIR is set, uninstall
    targets the module-level IAM_JIT_HOME (which existing tests
    monkeypatch to a tmp dir).
    """
    fake_home = tmp_path / ".iam-jit-default"
    fake_home.mkdir()
    monkeypatch.setattr(cu, "IAM_JIT_HOME", fake_home)
    monkeypatch.setattr(cu, "VENV_DIR", fake_home / "venv")
    monkeypatch.setattr(cu, "BOUNCER_DIR", fake_home / "bouncer")

    _seed_install(fake_home)
    # Programmatic call with data_dir=None mirrors the no-flag path.
    inv = cu._inventory_installed_state()
    assert inv["iam_jit_home_exists"] is True
    assert inv["data_dir"] == str(fake_home)
    # Console scripts probed under fake_home/venv/bin/.
    assert any("iam-jit" in p for p in inv["console_scripts_present"])


# ---------------------------------------------------------------------------
# Test 2 — --data-dir /tmp/x targets /tmp/x; default untouched
# ---------------------------------------------------------------------------


def test_data_dir_flag_targets_custom_path_and_leaves_default_untouched(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--data-dir /opt/iam-jit-prod (or any non-default path) makes the
    uninstall probe + destroy that tree, leaving the default
    ~/.iam-jit/ untouched.
    """
    # Set up TWO populated dirs: the default (which uninstall must NOT
    # touch when --data-dir points elsewhere) and the custom dir.
    default_home = tmp_path / ".iam-jit-default"
    custom_home = tmp_path / "opt" / "iam-jit-prod"

    monkeypatch.setattr(cu, "IAM_JIT_HOME", default_home)
    monkeypatch.setattr(cu, "VENV_DIR", default_home / "venv")
    monkeypatch.setattr(cu, "BOUNCER_DIR", default_home / "bouncer")

    default_paths = _seed_install(default_home)
    custom_paths = _seed_install(custom_home)

    # Programmatic call: pass data_dir to uninstall the custom tree.
    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="OK", stderr="",
    )
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(data_dir=custom_home)

    # Claim: status is ok/incomplete (not halted).
    assert result["status"] in ("ok", "incomplete"), result

    # Result records the resolved data_dir at the top level + in
    # inventory.
    assert result["data_dir"] == str(custom_home)
    assert result["inventory"]["data_dir"] == str(custom_home)

    # Observable: custom_home is gone (or empty).
    assert (
        not custom_home.exists()
        or not list(custom_home.iterdir())
    )
    assert not custom_paths["audit.jsonl"].exists()
    assert not custom_paths["state.db"].exists()

    # Critical: the DEFAULT home was NOT touched. Every seeded path
    # under default_home still exists.
    for name, p in default_paths.items():
        assert p.exists(), (
            f"--data-dir uninstall incorrectly touched default home: "
            f"{name} at {p} is missing"
        )


# ---------------------------------------------------------------------------
# Test 3 — IAM_JIT_DATA_DIR env targets the env-pointed path
# ---------------------------------------------------------------------------


def test_iam_jit_data_dir_env_targets_env_path_and_leaves_default_untouched(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IAM_JIT_DATA_DIR env var (without --data-dir flag) makes
    resolve_data_dir return the env-pointed path, and uninstall acts
    on it.
    """
    default_home = tmp_path / ".iam-jit-default"
    env_home = tmp_path / "env-pointed"

    monkeypatch.setattr(cu, "IAM_JIT_HOME", default_home)
    monkeypatch.setattr(cu, "VENV_DIR", default_home / "venv")
    monkeypatch.setattr(cu, "BOUNCER_DIR", default_home / "bouncer")

    default_paths = _seed_install(default_home)
    env_paths = _seed_install(env_home)

    monkeypatch.setenv(cu.IAM_JIT_DATA_DIR_ENV, str(env_home))

    # Verify the resolver picks up the env var.
    resolved = cu.resolve_data_dir()
    assert str(resolved) == str(env_home.resolve())

    # Drive the full CLI path (which calls resolve_data_dir internally).
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )
    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="OK", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        runner = CliRunner()
        cli_result = runner.invoke(main, ["uninstall", "--yes"])

    assert cli_result.exit_code == 0, cli_result.output

    # Observable: env-pointed dir is gone or empty.
    assert (
        not env_home.exists()
        or not list(env_home.iterdir())
    )
    assert not env_paths["audit.jsonl"].exists()

    # Critical: the DEFAULT home was NOT touched.
    for name, p in default_paths.items():
        assert p.exists(), (
            f"env-driven uninstall incorrectly touched default home: "
            f"{name} at {p}"
        )


# ---------------------------------------------------------------------------
# Test 4 — CLI flag precedence: flag wins over env
# ---------------------------------------------------------------------------


def test_cli_flag_wins_over_env(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When both --data-dir and IAM_JIT_DATA_DIR are set, the CLI flag
    takes precedence (matches the documented resolver precedence:
    flag > env > default).
    """
    flag_home = tmp_path / "flag-target"
    env_home = tmp_path / "env-target"

    monkeypatch.setenv(cu.IAM_JIT_DATA_DIR_ENV, str(env_home))

    # Resolver call: flag wins.
    resolved = cu.resolve_data_dir(cli_flag=flag_home)
    assert str(resolved) == str(flag_home.resolve())
    # The env-pointed path is NOT the resolved value.
    assert str(resolved) != str(env_home.resolve())


# ---------------------------------------------------------------------------
# Test 5 — Path expansion: --data-dir ~/foo resolves to $HOME/foo
# ---------------------------------------------------------------------------


def test_path_expansion_tilde_and_relative(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tilde-prefixed paths resolve to $HOME/...; relative paths
    resolve to an absolute path (resolve() output).
    """
    # Override HOME so the test is hermetic.
    fake_home_root = tmp_path / "fakehome"
    fake_home_root.mkdir()
    monkeypatch.setenv("HOME", str(fake_home_root))

    resolved = cu.resolve_data_dir(cli_flag="~/foo")
    expected = (fake_home_root / "foo").resolve()
    assert str(resolved) == str(expected), (
        f"~/foo should expand to {expected}, got {resolved}"
    )
    # Always returns an absolute path.
    assert resolved.is_absolute()


# ---------------------------------------------------------------------------
# Test 6 — post_check honors data-dir (preserves #617 HIGH-3 shape)
# ---------------------------------------------------------------------------


def test_post_check_iam_jit_home_exists_honors_resolved_data_dir(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#617 HIGH-3 introduced ``iam_jit_home_exists`` as an honest
    filesystem probe. This test pins that the probe targets the
    RESOLVED data dir, not the module-level default.

    Setup: --keep-audit-logs against a custom data dir; assert
    iam_jit_home_exists==True for the custom dir + preserved_paths
    enumerates the custom dir's audit files. Then re-check against a
    DIFFERENT custom dir (no files) — same probe must return False.
    """
    default_home = tmp_path / ".iam-jit-default"
    custom_home = tmp_path / "custom"
    empty_custom = tmp_path / "empty-custom"

    monkeypatch.setattr(cu, "IAM_JIT_HOME", default_home)

    _seed_install(custom_home)
    # empty_custom doesn't exist.

    # Probe custom_home: should see the seeded audit file.
    post_custom = cu._verify_clean_state(
        keep_audit_logs=True, data_dir=custom_home,
    )
    assert post_custom["leftover"]["iam_jit_home_exists"] is True
    assert any(
        p.endswith("audit.jsonl")
        for p in post_custom["leftover"]["preserved_paths"]
    )

    # Probe empty_custom: nothing there, must not lie + say True.
    post_empty = cu._verify_clean_state(
        keep_audit_logs=True, data_dir=empty_custom,
    )
    assert post_empty["leftover"]["iam_jit_home_exists"] is False
    assert post_empty["leftover"]["preserved_paths"] == []


# ---------------------------------------------------------------------------
# Test 7 — Output mentions the resolved data dir + source
# ---------------------------------------------------------------------------


def test_output_mentions_resolved_data_dir_and_source(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operator-trust per [[ibounce-honest-positioning]]: pre-check
    output must surface the resolved path + WHY (flag / env / default)
    so the operator can verify before confirming destruction.
    """
    default_home = tmp_path / ".iam-jit-default"
    custom_home = tmp_path / "custom"
    custom_home.mkdir()

    monkeypatch.setattr(cu, "IAM_JIT_HOME", default_home)
    monkeypatch.setattr(cu, "VENV_DIR", default_home / "venv")
    monkeypatch.setattr(cu, "BOUNCER_DIR", default_home / "bouncer")
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )

    runner = CliRunner()
    cli_result = runner.invoke(
        main,
        ["uninstall", "--dry-run", "--data-dir", str(custom_home)],
    )
    assert cli_result.exit_code == 0, cli_result.output
    out = cli_result.output

    # Resolved path is in the output.
    assert str(custom_home.resolve()) in out, (
        f"resolved path not in output:\n{out}"
    )
    # Source attribution is in the output.
    assert "--data-dir flag" in out, (
        f"source not in output:\n{out}"
    )


def test_output_attribution_env(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When only env is set (no flag), output attributes the source
    to the env var so operator can trace it.
    """
    default_home = tmp_path / ".iam-jit-default"
    env_home = tmp_path / "env-target"
    env_home.mkdir()

    monkeypatch.setattr(cu, "IAM_JIT_HOME", default_home)
    monkeypatch.setattr(cu, "VENV_DIR", default_home / "venv")
    monkeypatch.setattr(cu, "BOUNCER_DIR", default_home / "bouncer")
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )
    monkeypatch.setenv(cu.IAM_JIT_DATA_DIR_ENV, str(env_home))

    runner = CliRunner()
    cli_result = runner.invoke(main, ["uninstall", "--dry-run"])
    assert cli_result.exit_code == 0, cli_result.output
    out = cli_result.output

    assert str(env_home.resolve()) in out
    assert cu.IAM_JIT_DATA_DIR_ENV in out


# ---------------------------------------------------------------------------
# Test 8 — Sabotage: resolver is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_resolver_always_default_proves_resolver_is_load_bearing(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage: monkeypatch resolve_data_dir to always return the
    module-level default regardless of input. Confirm test 2's
    behavior breaks — uninstall now incorrectly targets the default
    home instead of the --data-dir-pointed path.

    This proves the resolver is load-bearing: if a future refactor
    bypasses it, this test detects the regression.
    """
    default_home = tmp_path / ".iam-jit-default"
    custom_home = tmp_path / "custom"

    monkeypatch.setattr(cu, "IAM_JIT_HOME", default_home)
    monkeypatch.setattr(cu, "VENV_DIR", default_home / "venv")
    monkeypatch.setattr(cu, "BOUNCER_DIR", default_home / "bouncer")

    default_paths = _seed_install(default_home)
    custom_paths = _seed_install(custom_home)

    # Baseline (no sabotage): resolver returns the custom path when
    # called with cli_flag.
    real_resolved = cu.resolve_data_dir(cli_flag=custom_home)
    assert str(real_resolved) == str(custom_home.resolve())

    # Sabotage: replace resolver with one that ignores its argument.
    monkeypatch.setattr(
        cu, "resolve_data_dir",
        lambda cli_flag=None, env_var=None, default=None: default_home,
    )

    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )
    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="OK", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        runner = CliRunner()
        cli_result = runner.invoke(
            main,
            ["uninstall", "--yes", "--data-dir", str(custom_home)],
        )
    # With the sabotaged resolver, the CLI should now incorrectly
    # destroy default_home (NOT custom_home). The audit.jsonl under
    # default_home should be GONE; under custom_home it should still
    # be PRESENT.
    #
    # If this assertion fails (i.e. custom_home was still targeted),
    # the resolver is NOT load-bearing and the actual targeting path
    # is somewhere else — re-pin via this test.
    assert cli_result.exit_code == 0, cli_result.output
    assert not default_paths["audit.jsonl"].exists(), (
        "sabotage check: with resolver returning default, the default "
        "home should have been destroyed (proving the resolver is "
        "the load-bearing decision point)"
    )
    assert custom_paths["audit.jsonl"].exists(), (
        "sabotage check: with resolver returning default, the custom "
        "home should have been LEFT ALONE (proving uninstall did not "
        "bypass the resolver via the --data-dir flag value)"
    )
