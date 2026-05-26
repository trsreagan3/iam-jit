"""#651 CRIT — `iam-jit init` MCP harness wiring.

Per [[tests-and-independent-uat-required]] + [[deliberate-feature-completion]]:
every new feature ships with state-verifying tests.

This module covers the three required test groups:

  A. --skip-mcp-install: init with that flag does NOT call any install
     subcommand and leaves the harness config untouched.

  B. Happy path: init with --harness=claude-code (default, no skip) writes
     both iam-jit AND every enabled-bouncer entry to the harness config file
     (a fixture ~/.claude.json).

  C. Failure isolation: if one bouncer's install command fails, that bouncer
     surfaces as a WARN row in the output but init still exits 0 and the
     other server(s) are installed.

Per [[scorer-is-ground-truth]] tests are NOT tuned to pass — they assert
real observable state (file contents, exit codes, stdout substrings).
Per [[push-policy-public-repo]] no personal paths, credentials, or env
details appear in this file.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest
from click.testing import CliRunner

from iam_jit import cli_init
from iam_jit.cli import main


# ---------------------------------------------------------------------------
# Fixtures shared across all groups
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_boto3(monkeypatch: pytest.MonkeyPatch) -> None:
    """Block boto3 STS calls so tests don't need real AWS credentials."""
    def _boom(*a: Any, **k: Any) -> None:
        raise RuntimeError("no aws creds in tests")
    monkeypatch.setattr("boto3.client", _boom)


@pytest.fixture(autouse=True)
def _no_home_pollution(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin HOME to tmp_path so harness-detection and default-data-dir
    can't escape the sandbox to the real ~/.iam-jit or ~/.claude.json."""
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))


@pytest.fixture
def isolated_data_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    return tmp_path / "iam-jit-data"


@pytest.fixture
def fake_claude_json(tmp_path: pathlib.Path) -> pathlib.Path:
    """Pre-create a minimal ~/.claude.json (Claude Code config file)
    so the install command has a target. Starts as an empty JSON object."""
    fake_home = tmp_path / "fake-home"
    target = fake_home / ".claude.json"
    target.write_text(json.dumps({}))
    return target


def _runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# Helper: build a subprocess.CompletedProcess-like mock for a given label
# ---------------------------------------------------------------------------


def _ok_proc(stdout: str = "OK") -> subprocess.CompletedProcess:  # type: ignore[type-arg]
    p: subprocess.CompletedProcess = MagicMock(spec=subprocess.CompletedProcess)  # type: ignore[type-arg]
    p.returncode = 0
    p.stdout = stdout
    p.stderr = ""
    return p


def _fail_proc(stderr: str = "ERROR") -> subprocess.CompletedProcess:  # type: ignore[type-arg]
    p: subprocess.CompletedProcess = MagicMock(spec=subprocess.CompletedProcess)  # type: ignore[type-arg]
    p.returncode = 1
    p.stdout = ""
    p.stderr = stderr
    return p


# ---------------------------------------------------------------------------
# Group A — --skip-mcp-install: no subprocess calls, harness config untouched
# ---------------------------------------------------------------------------


class TestSkipMcpInstall:
    """Group A: --skip-mcp-install prevents ANY install subprocess call."""

    def test_skip_flag_prevents_subprocess_call(
        self,
        isolated_data_dir: pathlib.Path,
        fake_claude_json: pathlib.Path,
    ) -> None:
        """With --skip-mcp-install, subprocess.run must never be called
        for MCP install commands. The config file must still be written."""
        with patch("subprocess.run") as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--skip-mcp-install",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output

        # No subprocess.run calls for MCP install.
        mock_run.assert_not_called()

        # But the config file was still written.
        assert (isolated_data_dir / "iam-jit.yaml").exists()

    def test_skip_flag_harness_config_not_modified(
        self,
        isolated_data_dir: pathlib.Path,
        fake_claude_json: pathlib.Path,
    ) -> None:
        """With --skip-mcp-install, the Claude Code config file content
        must remain exactly as it was before init ran."""
        original_content = fake_claude_json.read_text()

        with patch("subprocess.run") as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--skip-mcp-install",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        mock_run.assert_not_called()

        # Harness config unchanged.
        assert fake_claude_json.read_text() == original_content

    def test_skip_flag_summary_shows_manual_wire_text(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """When MCP install is skipped, the Next steps block must instruct
        the operator to wire manually (not claim servers were registered)."""
        with patch("subprocess.run"):
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--skip-mcp-install",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output

        # Must NOT say "we just registered" (that's the success path).
        assert "we just registered" not in result.output
        # Must tell operator to wire manually.
        assert "Wire MCP manually" in result.output or "show-config" in result.output

    def test_skip_flag_with_harness_none_is_noop(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """--harness=none with --skip-mcp-install: both agree not to
        install; output must never mention MCP registration."""
        with patch("subprocess.run") as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "none",
                    "--skip-mcp-install",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        mock_run.assert_not_called()
        assert "we just registered" not in result.output


# ---------------------------------------------------------------------------
# Group B — happy path: iam-jit + bouncer entries written to claude.json
# ---------------------------------------------------------------------------


class TestHappyPath:
    """Group B: both iam-jit and every enabled bouncer get MCP entries."""

    def test_claude_code_harness_installs_iam_jit_and_ibounce(
        self,
        isolated_data_dir: pathlib.Path,
        fake_claude_json: pathlib.Path,
    ) -> None:
        """With --harness=claude-code and --bouncers=ibounce (default),
        subprocess.run must be called twice: once for iam-jit and once
        for ibounce. Both must pass --path ~/.claude.json."""
        with patch("subprocess.run", return_value=_ok_proc()) as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--bouncers", "ibounce",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output

        calls = mock_run.call_args_list
        assert len(calls) == 2, (
            f"Expected 2 subprocess calls (iam-jit + ibounce); got {len(calls)}: "
            f"{calls}"
        )

        # Both calls must include mcp install-claude-code.
        for c in calls:
            cmd = c[0][0]  # positional first arg (list)
            assert "mcp" in cmd
            assert "install-claude-code" in cmd

        # iam-jit call.
        iam_jit_cmd = calls[0][0][0]
        assert iam_jit_cmd[0] == "iam-jit"
        assert "--path" in iam_jit_cmd

        # ibounce call.
        ibounce_cmd = calls[1][0][0]
        assert ibounce_cmd[0] == "ibounce"
        assert "--path" in ibounce_cmd

    def test_claude_code_path_contains_dot_claude_json(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """The --path argument passed to install-claude-code must be
        ~/.claude.json (per the #652 workaround — NOT the Claude Desktop
        path)."""
        with patch("subprocess.run", return_value=_ok_proc()) as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--bouncers", "ibounce",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output

        for c in mock_run.call_args_list:
            cmd = c[0][0]
            path_idx = cmd.index("--path")
            passed_path = cmd[path_idx + 1]
            assert passed_path.endswith(".claude.json"), (
                f"Expected --path to end with .claude.json (per #652 workaround); "
                f"got: {passed_path}"
            )

    def test_all_four_bouncers_get_install_calls(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """With --bouncers=ibounce,kbouncer,dbounce,gbounce, five
        subprocess calls must fire: one for iam-jit + one per bouncer."""
        with patch("subprocess.run", return_value=_ok_proc()) as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--bouncers", "ibounce,kbouncer,dbounce,gbounce",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output

        calls = mock_run.call_args_list
        assert len(calls) == 5, (
            f"Expected 5 subprocess calls (iam-jit + 4 bouncers); got {len(calls)}"
        )
        binaries = [c[0][0][0] for c in calls]
        assert binaries[0] == "iam-jit"
        assert set(binaries[1:]) == {"ibounce", "kbouncer", "dbounce", "gbounce"}

    def test_success_summary_mentions_registered_count(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """When all installs succeed, the Next steps block must say
        'N MCP server(s) we just registered' with the server names."""
        with patch("subprocess.run", return_value=_ok_proc("OK: added iam-jit")):
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--bouncers", "ibounce",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        # Must reference successful registration in the restart hint.
        assert "we just registered" in result.output
        assert "claude-code" in result.output

    def test_cursor_harness_uses_install_cursor_subcommand(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """cursor harness must call install-cursor (not install-claude-code)."""
        with patch("subprocess.run", return_value=_ok_proc()) as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "cursor",
                    "--bouncers", "ibounce",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output

        for c in mock_run.call_args_list:
            cmd = c[0][0]
            assert "install-cursor" in cmd, (
                f"Expected install-cursor in cmd; got: {cmd}"
            )
            assert "install-claude-code" not in cmd

    def test_harness_none_skips_all_install_calls(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """--harness=none must produce zero subprocess calls for MCP
        install (there's nothing to wire)."""
        with patch("subprocess.run") as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "none",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Group C — failure isolation: one bouncer fails → WARN row; exit 0
# ---------------------------------------------------------------------------


class TestFailureIsolation:
    """Group C: a bouncer install failure surfaces as WARN; init exits 0."""

    def test_one_bouncer_failure_surfaces_warn_and_exits_zero(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """If ibounce's install command fails, init must:
          1. Exit 0 (config was written; install-check is informational).
          2. Print a WARN row naming ibounce.
          3. Still report iam-jit as registered in the summary.
        """
        def _side_effect(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
            if cmd[0] == "iam-jit":
                return _ok_proc("OK: added iam-jit")
            # ibounce fails.
            return _fail_proc("ibounce: some transient error")

        with patch("subprocess.run", side_effect=_side_effect):
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--bouncers", "ibounce",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        # Exit 0 — config was written; install failure is a WARN, not fatal.
        assert result.exit_code == 0, result.output

        # WARN row for ibounce must appear.
        assert "WARN" in result.output
        assert "ibounce" in result.output

    def test_binary_not_found_surfaces_warn_not_crash(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """If a bouncer binary isn't on PATH (FileNotFoundError), init
        must still exit 0 and emit a WARN — not crash with a traceback."""
        def _side_effect(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
            if cmd[0] == "iam-jit":
                return _ok_proc()
            raise FileNotFoundError(f"{cmd[0]}: No such file or directory")

        with patch("subprocess.run", side_effect=_side_effect):
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--bouncers", "ibounce",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        assert "WARN" in result.output
        # Must name the gap (missing binary) so operator knows what to do.
        assert "not found on PATH" in result.output or "ibounce" in result.output

    def test_all_installs_fail_exits_zero_with_manual_hint(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """If ALL install commands fail, init must still exit 0 (config
        was written), emit WARN rows for each, and the Next steps block
        must show the manual wiring hint (not 'we just registered')."""
        with patch("subprocess.run", return_value=_fail_proc("network error")):
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--bouncers", "ibounce",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output

        # WARN rows for both failed installs.
        assert "WARN" in result.output

        # Config file was written.
        assert (isolated_data_dir / "iam-jit.yaml").exists()

        # Next steps must NOT claim servers were registered.
        assert "we just registered" not in result.output

    def test_second_bouncer_ok_when_first_fails(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """When the first bouncer fails but the second succeeds, the
        second install must still be attempted — failures are independent."""
        call_order: list[str] = []

        def _side_effect(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
            call_order.append(cmd[0])
            if cmd[0] == "kbouncer":
                return _fail_proc("kbouncer not found")
            return _ok_proc()

        with patch("subprocess.run", side_effect=_side_effect):
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--bouncers", "ibounce,kbouncer",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output

        # All three binaries were attempted (iam-jit, ibounce, kbouncer).
        assert "iam-jit" in call_order
        assert "ibounce" in call_order
        assert "kbouncer" in call_order

        # WARN for kbouncer; iam-jit + ibounce registered.
        assert "WARN" in result.output
        assert "kbouncer" in result.output


# ---------------------------------------------------------------------------
# Group D — codex / devin: print-only, no subprocess write
# ---------------------------------------------------------------------------


class TestPrintOnlyHarnesses:
    """Codex and Devin have no auto-install; they get a snippet + WARN."""

    def test_codex_harness_no_filesystem_write(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """codex harness must never write to any config file — only print
        the snippet. subprocess.run must NOT be called."""
        with patch("subprocess.run") as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "codex",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        mock_run.assert_not_called()

        # Snippet must appear in output.
        assert "mcpServers" in result.output or "iam-jit" in result.output

    def test_devin_harness_no_filesystem_write(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """devin harness must also print snippet without subprocess call."""
        with patch("subprocess.run") as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "devin",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Group E — unit tests for _run_harness_mcp_installs directly
# ---------------------------------------------------------------------------


class TestRunHarnessMcpInstalls:
    """Unit tests for the helper function, bypassing the full CLI."""

    def test_harness_none_returns_empty_list(self) -> None:
        results = cli_init._run_harness_mcp_installs(
            harness="none",
            bouncers=("ibounce",),
        )
        assert results == []

    def test_claude_code_calls_correct_subcommand(self) -> None:
        with patch("subprocess.run", return_value=_ok_proc()) as mock_run:
            results = cli_init._run_harness_mcp_installs(
                harness="claude-code",
                bouncers=("ibounce",),
                claude_code_path="/tmp/test-claude.json",
            )

        # iam-jit + ibounce = 2 calls.
        assert len(results) == 2
        assert all(r.ok for r in results), [r.detail for r in results]

        calls = mock_run.call_args_list
        assert calls[0][0][0] == ["iam-jit", "mcp", "install-claude-code",
                                   "--path", "/tmp/test-claude.json"]
        assert calls[1][0][0] == ["ibounce", "mcp", "install-claude-code",
                                   "--path", "/tmp/test-claude.json"]

    def test_cursor_calls_install_cursor(self) -> None:
        with patch("subprocess.run", return_value=_ok_proc()) as mock_run:
            results = cli_init._run_harness_mcp_installs(
                harness="cursor",
                bouncers=("ibounce",),
            )

        assert len(results) == 2
        for c in mock_run.call_args_list:
            cmd = c[0][0]
            assert "install-cursor" in cmd

    def test_file_not_found_becomes_failed_result(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError("no binary")):
            results = cli_init._run_harness_mcp_installs(
                harness="claude-code",
                bouncers=("ibounce",),
                claude_code_path="/tmp/x.json",
            )

        assert all(not r.ok for r in results)
        for r in results:
            assert "not found on PATH" in r.detail

    def test_codex_returns_failed_result_no_subprocess(self) -> None:
        with patch("subprocess.run") as mock_run:
            results = cli_init._run_harness_mcp_installs(
                harness="codex",
                bouncers=("ibounce",),
            )

        mock_run.assert_not_called()
        assert len(results) == 1
        assert not results[0].ok
        assert "manual" in results[0].detail.lower() or "paste" in results[0].detail.lower() or "snippet" in results[0].detail.lower()

    def test_cursor_path_override_plumbed_through(self) -> None:
        """cursor_path is forwarded as --path to install-cursor for both
        iam-jit and every enabled bouncer."""
        with patch("subprocess.run", return_value=_ok_proc()) as mock_run:
            results = cli_init._run_harness_mcp_installs(
                harness="cursor",
                bouncers=("ibounce",),
                cursor_path="/tmp/workspace/.cursor/mcp.json",
            )

        assert len(results) == 2
        assert all(r.ok for r in results), [r.detail for r in results]

        for c in mock_run.call_args_list:
            cmd = c[0][0]
            assert "install-cursor" in cmd
            assert "--path" in cmd
            path_idx = cmd.index("--path")
            assert cmd[path_idx + 1] == "/tmp/workspace/.cursor/mcp.json"


# ---------------------------------------------------------------------------
# Group F — #659: --claude-code-path and --cursor-path CLI flags
# ---------------------------------------------------------------------------


class TestPathOverrideFlags:
    """#659: --claude-code-path and --cursor-path are accepted by `init`
    and forwarded correctly to _run_harness_mcp_installs."""

    def test_claude_code_path_flag_accepted_with_skip(
        self,
        isolated_data_dir: pathlib.Path,
        tmp_path: pathlib.Path,
    ) -> None:
        """--claude-code-path + --skip-mcp-install does NOT crash on
        option parsing — the flag is accepted even when install is skipped."""
        fixture = tmp_path / "fixture.json"
        fixture.write_text(json.dumps({}))

        with patch("subprocess.run") as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--claude-code-path", str(fixture),
                    "--skip-mcp-install",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        # skip-mcp-install prevents any subprocess call.
        mock_run.assert_not_called()
        # Config was still written.
        assert (isolated_data_dir / "iam-jit.yaml").exists()

    def test_claude_code_path_flag_writes_to_fixture_not_home(
        self,
        isolated_data_dir: pathlib.Path,
        tmp_path: pathlib.Path,
    ) -> None:
        """--claude-code-path <fixture> routes the install subprocess call
        to the fixture path, NOT to ~/.claude.json."""
        fixture = tmp_path / "custom-claude.json"
        fixture.write_text(json.dumps({}))

        captured_cmds: list[list[str]] = []

        def _capture(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
            captured_cmds.append(cmd)
            return _ok_proc()

        with patch("subprocess.run", side_effect=_capture):
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--bouncers", "ibounce",
                    "--claude-code-path", str(fixture),
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        assert len(captured_cmds) == 2, f"Expected 2 calls; got {captured_cmds}"

        for cmd in captured_cmds:
            assert "--path" in cmd
            path_idx = cmd.index("--path")
            assert cmd[path_idx + 1] == str(fixture), (
                f"Expected --path {fixture}; got {cmd[path_idx + 1]}"
            )
            # Must NOT contain the real ~/.claude.json
            assert ".claude.json" not in cmd[path_idx + 1] or str(fixture) == cmd[path_idx + 1], (
                f"Install must target fixture, not real ~/.claude.json: {cmd}"
            )

    def test_claude_code_path_flag_default_behavior_unchanged(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """Omitting --claude-code-path preserves the default ~/.claude.json
        target (no regression from #651 behavior)."""
        with patch("subprocess.run", return_value=_ok_proc()) as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "claude-code",
                    "--bouncers", "ibounce",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output

        for c in mock_run.call_args_list:
            cmd = c[0][0]
            assert "--path" in cmd
            path_idx = cmd.index("--path")
            passed_path = cmd[path_idx + 1]
            assert passed_path.endswith(".claude.json"), (
                f"Default must end with .claude.json; got {passed_path}"
            )

    def test_cursor_path_flag_accepted_with_skip(
        self,
        isolated_data_dir: pathlib.Path,
        tmp_path: pathlib.Path,
    ) -> None:
        """--cursor-path + --skip-mcp-install does NOT crash on option
        parsing — the flag is accepted even when install is skipped."""
        fixture = tmp_path / "workspace" / ".cursor" / "mcp.json"
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(json.dumps({}))

        with patch("subprocess.run") as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "cursor",
                    "--cursor-path", str(fixture),
                    "--skip-mcp-install",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        mock_run.assert_not_called()
        assert (isolated_data_dir / "iam-jit.yaml").exists()

    def test_cursor_path_flag_routes_to_fixture(
        self,
        isolated_data_dir: pathlib.Path,
        tmp_path: pathlib.Path,
    ) -> None:
        """--cursor-path <fixture> routes the install subprocess call
        to the fixture path, NOT to ~/.cursor/mcp.json."""
        fixture = tmp_path / "myproject" / ".cursor" / "mcp.json"
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(json.dumps({}))

        captured_cmds: list[list[str]] = []

        def _capture(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
            captured_cmds.append(cmd)
            return _ok_proc()

        with patch("subprocess.run", side_effect=_capture):
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "cursor",
                    "--bouncers", "ibounce",
                    "--cursor-path", str(fixture),
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        assert len(captured_cmds) == 2, f"Expected 2 calls; got {captured_cmds}"

        for cmd in captured_cmds:
            assert "install-cursor" in cmd
            assert "--path" in cmd
            path_idx = cmd.index("--path")
            assert cmd[path_idx + 1] == str(fixture), (
                f"Expected --path {fixture}; got {cmd[path_idx + 1]}"
            )

    def test_cursor_path_flag_default_behavior_unchanged(
        self,
        isolated_data_dir: pathlib.Path,
    ) -> None:
        """Omitting --cursor-path preserves the default ~/.cursor/mcp.json
        target (no regression)."""
        with patch("subprocess.run", return_value=_ok_proc()) as mock_run:
            result = _runner().invoke(
                main,
                [
                    "init", "--non-interactive",
                    "--data-dir", str(isolated_data_dir),
                    "--harness", "cursor",
                    "--bouncers", "ibounce",
                    "--no-doctor-check",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output

        for c in mock_run.call_args_list:
            cmd = c[0][0]
            assert "--path" in cmd
            path_idx = cmd.index("--path")
            passed_path = cmd[path_idx + 1]
            assert passed_path.endswith(
                ".cursor/mcp.json"
            ) or passed_path.endswith(".cursor\\mcp.json"), (
                f"Default must end with .cursor/mcp.json; got {passed_path}"
            )
