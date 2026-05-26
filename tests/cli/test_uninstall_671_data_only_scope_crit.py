"""#671 CRIT — `iam-jit uninstall --data-dir` MUST NOT destroy
machine-wide state.

The #671 brief documents the incident: UAT of #617 5 MEDs ran
``iam-jit uninstall --data-dir /tmp/fixture --yes`` and destroyed the
founder's live machine state — SIGTERM'd live ibounce on :8767, killed
live gbounce on :8080, wiped binaries from ``~/.local/bin/``, cleared
the ``mcpServers`` block in ``~/.claude.json``.

Per ``[[creates-never-mutates]]`` + the brief's three-layer fix:

  Layer 1: when ``--data-dir <X>`` is non-default (X != ~/.iam-jit),
  every machine-wide action must be SUPPRESSED. Process detection +
  binary removal + MCP entry removal + shell-rc detection are all
  scoped to the targeted data-dir.

  Layer 2: explicit operator override via ``--full-machine-cleanup``
  flag, which itself requires a long-form acknowledgement flag
  ``--yes-i-want-to-clean-other-iam-jit-installs-on-this-machine`` to
  actually do anything. Friction-as-feature per
  ``[[ambient-value-prop-and-friction-framing]]``.

  Layer 3: dogfood safety belt via ``IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE=1``
  env var + ``--allow-live-bouncers-killed`` flag for the
  live-bouncer-detected halt.

These tests pin all 9 cases listed in the brief.
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
# Isolation — mirror the existing data-dir test fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _default_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent the dev machine's real state from tripping halts.

    Mirrors test_uninstall_data_dir_flag_617_med1.py's isolation
    fixture but additionally accepts the new ``data_only_scope`` kwarg
    where the helpers were extended for #671.
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
    monkeypatch.delenv(cu.IAM_JIT_DATA_DIR_ENV, raising=False)
    monkeypatch.delenv(
        cu.IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE_ENV, raising=False,
    )
    # #671 CRIT — the artifact checkers must accept the new kwarg.
    monkeypatch.setattr(
        cu, "_check_path_binaries",
        lambda data_only_scope=False: [],
    )
    monkeypatch.setattr(
        cu, "_check_bouncer_config_dirs",
        lambda data_only_scope=False: [],
    )
    monkeypatch.setattr(
        cu, "_detect_shell_rc_lines",
        lambda data_only_scope=False: [],
    )
    monkeypatch.setattr(
        cu, "_check_mcp_entries",
        lambda claude_json_path=None, data_only_scope=False: [],
    )
    monkeypatch.setattr(cu, "_all_listening_ports", lambda: [])


def _seed_install(home: pathlib.Path) -> dict[str, pathlib.Path]:
    """Populate `home` to look like an iam-jit install."""
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
# Test 1 — --data-dir /tmp/fixture --yes does NOT kill any process whose
# cmdline doesn't reference /tmp/fixture
# ---------------------------------------------------------------------------


def test_671_data_dir_does_not_kill_unrelated_processes(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 1 — the #671 incident shape. A fixture uninstall MUST NOT
    SIGTERM live ibounce processes whose cmdline references the
    operator's REAL ~/.iam-jit install (not the fixture).
    """
    fixture_home = tmp_path / "fixture"
    fixture_home.mkdir()

    # Simulate a LIVE ibounce on the machine — pid 44674 (the #671
    # incident PID) — whose cmdline references the operator's REAL
    # ~/.iam-jit install, NOT the fixture.
    real_ibounce_cmdline = (
        "/Users/founder/.local/bin/ibounce run --mode discovery "
        "--proxy-port 8767"
    )

    sigterm_calls: list[int] = []

    def _record_kill(pid: int, sig: int) -> None:
        sigterm_calls.append(pid)

    monkeypatch.setattr(cu.os, "kill", _record_kill)

    # Inventory will report ibounce running at pid 44674 — same pid the
    # #671 incident hit. Drive it via inventory injection.
    fake_inventory = {
        "data_dir": str(fixture_home.resolve()),
        "iam_jit_home_exists": True,
        "venv_exists": False,
        "running_bouncers": {"ibounce": [44674]},
        "bound_ports": [8767],
        "unknown_port_owners": [],
        "console_scripts_present": [],
        "go_binaries_present": [],
        "audit_bearing_files": [],
        "manual_reminders": [],
    }
    monkeypatch.setattr(
        cu, "_inventory_installed_state",
        lambda data_dir=None: fake_inventory,
    )
    monkeypatch.setattr(
        cu, "_read_cmdline", lambda pid: real_ibounce_cmdline,
    )

    # Programmatic call: data_dir=fixture_home (non-default).
    result = cu.run_uninstall(
        data_dir=fixture_home,
        # No --allow-live-bouncers-killed — but our _port_bound stub
        # returns False so U-7 won't fire here. Test 9 covers U-7.
    )

    # OBSERVABLE: no os.kill calls happened. The data-only-scope guard
    # MUST suppress the machine-wide SIGTERM.
    assert 44674 not in sigterm_calls, (
        f"#671 CRIT: --data-dir fixture uninstall SIGTERM'd live PID "
        f"44674 (the #671 incident shape). os.kill calls: {sigterm_calls}"
    )
    # The step records the protection in `failed` so the operator sees it.
    stop = result["steps"]["stop_bouncers"]
    assert stop["skipped_data_only_scope"] is True, (
        f"stop_bouncers must record scope suppression; got {stop}"
    )


# ---------------------------------------------------------------------------
# Test 2 — --data-dir /tmp/fixture --yes does NOT remove ~/.local/bin binaries
# ---------------------------------------------------------------------------


def test_671_data_dir_does_not_remove_local_bin_binaries(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 2 — go-binary removal step MUST be a no-op in data-only scope.

    The #671 incident wiped binaries from ``~/.local/bin/`` and
    ``~/go/bin/``. Those are machine-global install dirs; a fixture
    uninstall has no business touching them.
    """
    fixture_home = tmp_path / "fixture"
    _seed_install(fixture_home)

    # Pretend the inventory found a machine-wide go binary.
    fake_inventory = {
        "data_dir": str(fixture_home.resolve()),
        "iam_jit_home_exists": True,
        "venv_exists": True,
        "running_bouncers": {},
        "bound_ports": [],
        "unknown_port_owners": [],
        "console_scripts_present": [],
        "go_binaries_present": ["/Users/founder/go/bin/gbounce"],
        "audit_bearing_files": [],
        "manual_reminders": [],
    }
    monkeypatch.setattr(
        cu, "_inventory_installed_state",
        lambda data_dir=None: fake_inventory,
    )

    # Spy on file removal — there should be NONE for ~/go/bin/gbounce.
    real_unlink = pathlib.Path.unlink
    unlinked: list[str] = []

    def _spy_unlink(self: pathlib.Path, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        unlinked.append(str(self))
        return real_unlink(self, *args, **kwargs) if self.exists() else None

    monkeypatch.setattr(pathlib.Path, "unlink", _spy_unlink)

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="OK", stderr="",
    )
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(data_dir=fixture_home)

    # Step output records scope-suppression.
    assert result["steps"]["remove_go_binaries"]["skipped_data_only_scope"] is True
    assert "/Users/founder/go/bin/gbounce" not in unlinked, (
        f"#671 CRIT: --data-dir fixture uninstall removed machine-wide "
        f"go binary. unlink calls: {unlinked}"
    )


# ---------------------------------------------------------------------------
# Test 3 — --data-dir /tmp/fixture --yes does NOT touch ~/.claude.json
# ---------------------------------------------------------------------------


def test_671_data_dir_does_not_touch_claude_json(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 3 — MCP-entry removal MUST be skipped in data-only scope.

    The #671 incident cleared the founder's ``mcpServers`` block (3
    entries gone). MCP entries are per-machine, not per-data-dir.
    """
    fixture_home = tmp_path / "fixture"
    _seed_install(fixture_home)

    # Set up a fake ~/.claude.json with iam-jit MCP entries to prove
    # they don't get touched.
    fake_claude_json = tmp_path / "fake-claude.json"
    fake_claude_json.write_text(
        '{"mcpServers": {"iam-jit": {"command": "iam-jit"}, '
        '"ibounce": {"command": "ibounce"}, '
        '"kbounce": {"command": "kbounce"}}}'
    )

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="OK", stderr="",
    )
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            data_dir=fixture_home,
            claude_json_path=fake_claude_json,
        )

    # Observable: file is unchanged on disk.
    text = fake_claude_json.read_text()
    assert "iam-jit" in text, (
        f"#671 CRIT: --data-dir fixture uninstall touched ~/.claude.json. "
        f"Resulting file: {text!r}"
    )
    assert "ibounce" in text
    assert "kbounce" in text
    # Step output records scope-suppression.
    step = result["steps"]["remove_mcp_entries"]
    assert step["skipped_data_only_scope"] is True


# ---------------------------------------------------------------------------
# Test 4 — --data-dir /tmp/fixture --yes DOES remove the fixture data-dir
# ---------------------------------------------------------------------------


def test_671_data_dir_does_remove_fixture_data_dir(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 4 — data-dir removal IS in scope. The fixture's own data-dir
    must be cleaned up so the test cycle is repeatable.
    """
    fixture_home = tmp_path / "fixture"
    paths = _seed_install(fixture_home)

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="OK", stderr="",
    )
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(data_dir=fixture_home)

    assert result["status"] in ("ok", "incomplete"), result
    # Observable: fixture's audit.jsonl is gone.
    assert not paths["audit.jsonl"].exists(), (
        "fixture data-dir's audit.jsonl should be removed"
    )
    assert not paths["state.db"].exists()


# ---------------------------------------------------------------------------
# Test 5 — Default `iam-jit uninstall --yes` STILL works end-to-end
# (regression bar for the happy path)
# ---------------------------------------------------------------------------


def test_671_default_data_dir_happy_path_still_works(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 5 — regression bar. The default happy path
    ``iam-jit uninstall --yes`` (no --data-dir, no special flags) must
    STILL work end-to-end after the #671 fix. Otherwise the fix
    regressed the bedrock case.
    """
    fake_home_root = tmp_path / "fakehome"
    fake_home_root.mkdir()
    monkeypatch.setenv("HOME", str(fake_home_root))

    fake_home = fake_home_root / ".iam-jit"
    fake_home.mkdir()
    monkeypatch.setattr(cu, "IAM_JIT_HOME", fake_home)
    monkeypatch.setattr(cu, "VENV_DIR", fake_home / "venv")
    monkeypatch.setattr(cu, "BOUNCER_DIR", fake_home / "bouncer")

    paths = _seed_install(fake_home)

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="OK", stderr="",
    )
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        # CLI path (no --data-dir). Use --keep-mcp-entries to avoid
        # the test fixture having to provide a claude.json override.
        runner = CliRunner()
        cli_result = runner.invoke(
            main,
            ["uninstall", "--yes", "--keep-mcp-entries"],
        )

    assert cli_result.exit_code == 0, cli_result.output
    assert not paths["audit.jsonl"].exists(), (
        "default-path uninstall must still remove ~/.iam-jit content"
    )


# ---------------------------------------------------------------------------
# Test 6 — --full-machine-cleanup WITHOUT the long ack flag REFUSES
# ---------------------------------------------------------------------------


def test_671_full_machine_cleanup_without_ack_refuses(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 6 — --full-machine-cleanup is the explicit opt-out from the
    data-only scope guard. Without the long-form acknowledgement flag,
    it MUST refuse (halt U-8) and exit non-zero.
    """
    fixture_home = tmp_path / "fixture"
    fixture_home.mkdir()

    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )
    runner = CliRunner()
    cli_result = runner.invoke(
        main,
        [
            "uninstall", "--yes",
            "--data-dir", str(fixture_home),
            "--full-machine-cleanup",
        ],
    )
    # U-8 halt -> exit code 2.
    assert cli_result.exit_code == 2, (
        f"--full-machine-cleanup without ack must refuse; got exit "
        f"{cli_result.exit_code}\noutput: {cli_result.output}"
    )
    assert "U-8" in cli_result.output or "yes-i-want-to-clean" in cli_result.output


# ---------------------------------------------------------------------------
# Test 7 — --full-machine-cleanup WITH the long ack flag DOES the cleanup
# ---------------------------------------------------------------------------


def test_671_full_machine_cleanup_with_long_ack_works(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 7 — when the operator passes BOTH --full-machine-cleanup
    AND --yes-i-want-to-clean-other-iam-jit-installs-on-this-machine,
    the machine-wide cleanup IS allowed to run (the data-only scope
    guard is lifted).
    """
    fixture_home = tmp_path / "fixture"
    _seed_install(fixture_home)

    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="OK", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            data_dir=fixture_home,
            full_machine_cleanup=True,
            yes_clean_other_iam_jit_installs=True,
        )

    # Status should NOT be halted on U-8 (the ack flag lifts the guard).
    halt_ids = [h["id"] for h in result["halts"]]
    assert "U-8" not in halt_ids, (
        f"U-8 should NOT fire when long ack is passed; halts: {result['halts']}"
    )
    # data_only_scope should now be False (the ack flipped it).
    assert result["data_only_scope"] is False


# ---------------------------------------------------------------------------
# Test 8 — IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE=1 REFUSES without long ack
# ---------------------------------------------------------------------------


def test_671_dogfood_safety_belt_refuses_without_long_ack(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 8 — when the dogfood safety-belt env var is set, a default-path
    uninstall MUST refuse without
    ``--yes-i-am-on-dogfood-machine-and-want-to-uninstall``.
    """
    fake_home_root = tmp_path / "fakehome"
    fake_home_root.mkdir()
    monkeypatch.setenv("HOME", str(fake_home_root))
    monkeypatch.setenv(
        cu.IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE_ENV, "1",
    )

    fake_home = fake_home_root / ".iam-jit"
    fake_home.mkdir()
    monkeypatch.setattr(cu, "IAM_JIT_HOME", fake_home)
    monkeypatch.setattr(cu, "VENV_DIR", fake_home / "venv")
    monkeypatch.setattr(cu, "BOUNCER_DIR", fake_home / "bouncer")

    _seed_install(fake_home)

    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )

    runner = CliRunner()
    cli_result = runner.invoke(main, ["uninstall", "--yes"])
    assert cli_result.exit_code == 2, (
        f"dogfood-belt: default uninstall must REFUSE without long ack; "
        f"got exit {cli_result.exit_code}\noutput: {cli_result.output}"
    )
    assert "U-6" in cli_result.output or "dogfood" in cli_result.output.lower()


def test_671_dogfood_safety_belt_proceeds_with_long_ack(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dogfood belt: with the long ack flag, uninstall proceeds."""
    fake_home_root = tmp_path / "fakehome"
    fake_home_root.mkdir()
    monkeypatch.setenv("HOME", str(fake_home_root))
    monkeypatch.setenv(
        cu.IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE_ENV, "1",
    )

    fake_home = fake_home_root / ".iam-jit"
    fake_home.mkdir()
    monkeypatch.setattr(cu, "IAM_JIT_HOME", fake_home)
    monkeypatch.setattr(cu, "VENV_DIR", fake_home / "venv")
    monkeypatch.setattr(cu, "BOUNCER_DIR", fake_home / "bouncer")

    paths = _seed_install(fake_home)

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
            [
                "uninstall", "--yes", "--keep-mcp-entries",
                "--yes-i-am-on-dogfood-machine-and-want-to-uninstall",
            ],
        )
    assert cli_result.exit_code == 0, cli_result.output
    assert not paths["audit.jsonl"].exists()


# ---------------------------------------------------------------------------
# Test 9 — Live-bouncer detection: if default-port bouncer is detected
# AND --data-dir is non-default, REFUSE without --allow-live-bouncers-killed
# ---------------------------------------------------------------------------


def test_671_live_bouncer_on_default_port_refuses_without_ack(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test 9 — when --data-dir is non-default AND a live bouncer is
    detected on a default port (e.g. ibounce on :8767), the U-7 halt
    fires and uninstall refuses without --allow-live-bouncers-killed.
    """
    fixture_home = tmp_path / "fixture"
    fixture_home.mkdir()

    # Simulate live ibounce on :8767 — _port_bound returns True for
    # 8767 only.
    def _fake_port_bound(port: int, host: str = "127.0.0.1") -> bool:
        return port == 8767

    monkeypatch.setattr(cu, "_port_bound", _fake_port_bound)

    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )

    runner = CliRunner()
    cli_result = runner.invoke(
        main,
        ["uninstall", "--yes", "--data-dir", str(fixture_home)],
    )
    # U-7 -> exit code 2.
    assert cli_result.exit_code == 2, (
        f"U-7 (live bouncer + non-default --data-dir) must refuse; "
        f"got exit {cli_result.exit_code}\noutput: {cli_result.output}"
    )
    assert "U-7" in cli_result.output or "live" in cli_result.output.lower()


def test_671_live_bouncer_proceeds_with_allow_flag(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """U-7 bypass: with --allow-live-bouncers-killed, the halt is
    skipped and uninstall proceeds (data-only-scope guard still
    suppresses machine-wide kills — the flag is a per-halt
    acknowledgement only).
    """
    fixture_home = tmp_path / "fixture"
    _seed_install(fixture_home)

    def _fake_port_bound(port: int, host: str = "127.0.0.1") -> bool:
        return port == 8767

    monkeypatch.setattr(cu, "_port_bound", _fake_port_bound)
    monkeypatch.setattr(
        cu, "_resolve_go_bin_dir", lambda: tmp_path / "nogo",
    )

    fake_proc = subprocess.CompletedProcess(
        args=["pip"], returncode=0, stdout="OK", stderr="",
    )
    with mock.patch.object(subprocess, "run", return_value=fake_proc):
        result = cu.run_uninstall(
            data_dir=fixture_home,
            allow_live_bouncers_killed=True,
        )
    halt_ids = [h["id"] for h in result["halts"]]
    assert "U-7" not in halt_ids, (
        f"U-7 should NOT fire with --allow-live-bouncers-killed; "
        f"halts: {result['halts']}"
    )
    # data_only_scope still True — the flag is just a halt ack.
    assert result["data_only_scope"] is True
