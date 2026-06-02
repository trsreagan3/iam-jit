"""Integration tests for #737 — stale-binary detection.

Tests that the stale-binary detection logic:
  1. Fires (emits a warning) when the binary on PATH is simulated to be
     OLD (missing --settings-path).
  2. Stays silent when the binary is up-to-date (has --settings-path).

Methodology (per [[tests-and-independent-uat-required]]):
  - Uses a SHIM script that pretends to be `iam-jit`, responds to
    `mcp install-claude-code --help` with output that either INCLUDES
    or EXCLUDES `--settings-path`.
  - Injects the shim onto PATH via a temp directory.
  - Calls `_probe_binary_has_settings_path()` directly (unit path)
    AND exercises the full `warn_if_stale_binary()` output (integration path).
  - The subprocess shim approach matches the spec: "spawn a subprocess
    that simulates an old binary".

These tests are marked ``integration`` (they spawn real subprocesses +
write temp files) but do NOT require Docker, LocalStack, AWS creds, or
any live network — they are always runnable on a dev workstation.

Per [[permission-minimal-install]]: no sudo, no broad Bash, no --dangerously-*.
"""

from __future__ import annotations

import os
import pathlib
import stat
import subprocess
import sys
import textwrap

import pytest


# ---------------------------------------------------------------------------
# Helpers — build shim scripts that simulate old / new binary
# ---------------------------------------------------------------------------

_SHIM_OLD = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    # Simulates an OLD iam-jit binary (pre-PR #23).
    # Responds to `mcp install-claude-code --help` WITHOUT --settings-path.
    import sys

    args = sys.argv[1:]
    if args == ["mcp", "install-claude-code", "--help"]:
        print("Usage: iam-jit mcp install-claude-code [OPTIONS]")
        print()
        print("Options:")
        print("  --path PATH     Override the auto-detected Claude Code MCP config path.")
        print("  --dry-run       Show what would be written without modifying any file.")
        print("  --print-only    Just print the JSON snippet + the target path; don't write.")
        print("  --help          Show this message and exit.")
        sys.exit(0)

    # For any other invocation, exit 1 so the shim doesn't accidentally do real work.
    print(f"shim-old: not implemented: {args}", file=sys.stderr)
    sys.exit(1)
    """
)

_SHIM_NEW = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    # Simulates a NEW iam-jit binary (post-PR #23, has --settings-path).
    import sys

    args = sys.argv[1:]
    if args == ["mcp", "install-claude-code", "--help"]:
        print("Usage: iam-jit mcp install-claude-code [OPTIONS]")
        print()
        print("Options:")
        print("  --path PATH              Override the auto-detected Claude Code MCP config path.")
        print("  --dry-run                Show what would be written without modifying any file.")
        print("  --print-only             Just print the JSON snippet; don't write.")
        print("  --settings-path PATH     Override the Claude Code settings.json path for env-block writing.")
        print("  --no-env-block           Skip writing the bouncer env vars to settings.json.")
        print("  --help                   Show this message and exit.")
        sys.exit(0)

    print(f"shim-new: not implemented: {args}", file=sys.stderr)
    sys.exit(1)
    """
)


def _make_shim(tmp_dir: pathlib.Path, name: str, script: str) -> pathlib.Path:
    """Write a shim Python script to *tmp_dir* / *name*, make it executable."""
    shim = tmp_dir / name
    shim.write_text(script, encoding="utf-8")
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return shim


def _env_with_shim_first(shim_dir: pathlib.Path) -> dict[str, str]:
    """Return an env dict with *shim_dir* prepended to PATH."""
    env = dict(os.environ)
    env["PATH"] = str(shim_dir) + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# Unit tests: _probe_binary_has_settings_path
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestProbeBinaryHasSettingsPath:
    """Direct unit tests for the probe helper.

    These call `_probe_binary_has_settings_path` with a custom PATH so
    the shim is resolved instead of the real binary.  No subprocess of
    the CLI itself is spawned — just the shim.
    """

    def test_old_binary_returns_false(self, tmp_path: pathlib.Path) -> None:
        """When the binary on PATH is missing --settings-path, probe returns False."""
        shim_dir = tmp_path / "shim_old"
        shim_dir.mkdir()
        _make_shim(shim_dir, "iam-jit", _SHIM_OLD)

        # Patch PATH so our module picks up the shim.
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(shim_dir) + os.pathsep + old_path
        try:
            from iam_jit.cli_doctor_install_check import _probe_binary_has_settings_path
            has_flag, detail = _probe_binary_has_settings_path("iam-jit")
        finally:
            os.environ["PATH"] = old_path

        assert has_flag is False, (
            "Expected probe to return False for old binary (missing --settings-path).\n"
            f"  detail: {detail!r}"
        )
        assert "missing" in detail.lower() or "NOT" in detail or "without" in detail.lower() or "missing" in detail, (
            f"Expected detail to describe the stale state; got: {detail!r}"
        )

    def test_new_binary_returns_true(self, tmp_path: pathlib.Path) -> None:
        """When the binary on PATH has --settings-path, probe returns True."""
        shim_dir = tmp_path / "shim_new"
        shim_dir.mkdir()
        _make_shim(shim_dir, "iam-jit", _SHIM_NEW)

        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(shim_dir) + os.pathsep + old_path
        try:
            from iam_jit.cli_doctor_install_check import _probe_binary_has_settings_path
            has_flag, detail = _probe_binary_has_settings_path("iam-jit")
        finally:
            os.environ["PATH"] = old_path

        assert has_flag is True, (
            "Expected probe to return True for new binary (has --settings-path).\n"
            f"  detail: {detail!r}"
        )

    def test_binary_not_on_path_returns_true(self) -> None:
        """When no iam-jit binary is on PATH at all, probe returns True (safe default)."""
        old_path = os.environ.get("PATH", "")
        # Set PATH to an empty temp dir so no iam-jit is found.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            os.environ["PATH"] = td
            try:
                from iam_jit.cli_doctor_install_check import _probe_binary_has_settings_path
                has_flag, detail = _probe_binary_has_settings_path("iam-jit")
            finally:
                os.environ["PATH"] = old_path

        assert has_flag is True, (
            "When binary is not on PATH, probe should return True (assume up-to-date "
            "to avoid false-positive noise).\n"
            f"  detail: {detail!r}"
        )


# ---------------------------------------------------------------------------
# Integration tests: warn_if_stale_binary via subprocess
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestWarnIfStaleBinarySubprocess:
    """End-to-end subprocess tests: spawn a Python process that calls
    `warn_if_stale_binary` with a shim-injected PATH, capture stderr,
    assert presence/absence of warning.

    This is the "simulated old binary fires warning + new binary stays
    silent" check required by the task spec (Phase 3 — UAT).
    """

    def _run_warn_check(
        self,
        shim_dir: pathlib.Path,
        *,
        context: str = "mcp install-claude-code",
    ) -> subprocess.CompletedProcess[str]:
        """Run a subprocess that calls warn_if_stale_binary with the shim on PATH."""
        script = textwrap.dedent(
            f"""\
            import sys
            sys.path.insert(0, {str(pathlib.Path(__file__).parent.parent.parent / "src")!r})
            from iam_jit.cli_doctor_install_check import warn_if_stale_binary
            warn_if_stale_binary(context={context!r})
            """
        )
        env = dict(os.environ)
        env["PATH"] = str(shim_dir) + os.pathsep + env.get("PATH", "")

        return subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_old_binary_fires_warning_on_stderr(self, tmp_path: pathlib.Path) -> None:
        """The stale-binary warning MUST appear on stderr when the old shim is on PATH.

        Asserts:
          - Process exits 0 (warn_if_stale_binary never raises or exits non-zero).
          - stderr contains '[stale-binary-warning]'.
          - stderr contains 'pipx upgrade iam-jit' (the paste-ready fix).
          - stderr contains 'settings-path' or 'env-block' (the missing flags).
        """
        shim_dir = tmp_path / "old_shim"
        shim_dir.mkdir()
        _make_shim(shim_dir, "iam-jit", _SHIM_OLD)

        proc = self._run_warn_check(shim_dir)

        assert proc.returncode == 0, (
            f"warn_if_stale_binary subprocess exited {proc.returncode}.\n"
            f"  stdout: {proc.stdout!r}\n"
            f"  stderr: {proc.stderr!r}"
        )

        assert "[stale-binary-warning]" in proc.stderr, (
            "Expected '[stale-binary-warning]' in stderr when old binary is on PATH.\n"
            f"  stderr: {proc.stderr!r}"
        )

        assert "pipx upgrade iam-jit" in proc.stderr, (
            "Expected 'pipx upgrade iam-jit' in the warning message.\n"
            f"  stderr: {proc.stderr!r}"
        )

        # Check the message names the missing capability.
        has_capability_mention = (
            "settings-path" in proc.stderr
            or "--settings-path" in proc.stderr
            or "no-env-block" in proc.stderr
            or "--no-env-block" in proc.stderr
            or "env-block" in proc.stderr
        )
        assert has_capability_mention, (
            "Warning does not mention the missing flags (--settings-path / --no-env-block).\n"
            f"  stderr: {proc.stderr!r}"
        )

    def test_new_binary_stays_silent(self, tmp_path: pathlib.Path) -> None:
        """No warning must appear on stderr when the new binary (has --settings-path) is on PATH.

        Per [[lightweight-frictionless-principle]]: zero extra noise when current.
        """
        shim_dir = tmp_path / "new_shim"
        shim_dir.mkdir()
        _make_shim(shim_dir, "iam-jit", _SHIM_NEW)

        proc = self._run_warn_check(shim_dir)

        assert proc.returncode == 0, (
            f"warn_if_stale_binary subprocess exited {proc.returncode}.\n"
            f"  stdout: {proc.stdout!r}\n"
            f"  stderr: {proc.stderr!r}"
        )

        assert "[stale-binary-warning]" not in proc.stderr, (
            "Unexpected '[stale-binary-warning]' emitted for an up-to-date binary.\n"
            f"  stderr: {proc.stderr!r}\n"
            "Per [[lightweight-frictionless-principle]] the warning MUST be silent "
            "when the binary is current."
        )

    def test_context_appears_in_warning(self, tmp_path: pathlib.Path) -> None:
        """The 'context' parameter must appear in the warning so the operator
        knows which command to re-run after upgrading."""
        shim_dir = tmp_path / "old_ctx_shim"
        shim_dir.mkdir()
        _make_shim(shim_dir, "iam-jit", _SHIM_OLD)

        context = "init --harness=claude-code"
        proc = self._run_warn_check(shim_dir, context=context)

        assert proc.returncode == 0
        assert context in proc.stderr, (
            f"Context string {context!r} not found in the warning.\n"
            f"  stderr: {proc.stderr!r}\n"
            "The warning must name what the operator should re-run after upgrading."
        )


# ---------------------------------------------------------------------------
# Integration tests: check_stale_binary (doctor section helper)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCheckStaleBinarySection:
    """Verify check_stale_binary populates doctor Section correctly.

    Does NOT require a live binary or running bouncer — only shims.
    """

    def _run_check(
        self,
        shim_dir: pathlib.Path,
    ) -> dict[str, object]:
        """Run check_stale_binary via subprocess and return the section data as dict."""
        script = textwrap.dedent(
            f"""\
            import sys, json
            sys.path.insert(0, {str(pathlib.Path(__file__).parent.parent.parent / "src")!r})
            from iam_jit.cli_doctor_install_check import (
                _Section, _SEV_OK, _SEV_WARN, _SEV_ERR, check_stale_binary
            )
            s = _Section(num=2, total=8, title="Binary versions")
            check_stale_binary(s)
            print(json.dumps({{
                "worst_severity": s.worst_severity,
                "rows": [
                    {{"label": r.label, "severity": r.severity, "fix": r.fix}}
                    for r in s.rows
                ],
                "SEV_OK": _SEV_OK,
                "SEV_WARN": _SEV_WARN,
                "SEV_ERR": _SEV_ERR,
            }}))
            """
        )
        env = dict(os.environ)
        env["PATH"] = str(shim_dir) + os.pathsep + env.get("PATH", "")

        proc = subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 0, (
            f"check_stale_binary helper subprocess failed:\n"
            f"  stdout: {proc.stdout!r}\n"
            f"  stderr: {proc.stderr!r}"
        )

        import json
        return json.loads(proc.stdout.strip())

    def test_old_binary_produces_warn_row(self, tmp_path: pathlib.Path) -> None:
        """check_stale_binary must add a WARN row when the old shim is on PATH."""
        shim_dir = tmp_path / "section_old"
        shim_dir.mkdir()
        _make_shim(shim_dir, "iam-jit", _SHIM_OLD)

        data = self._run_check(shim_dir)

        sev_warn = data["SEV_WARN"]
        assert data["worst_severity"] == sev_warn, (
            f"Expected worst_severity == WARN ({sev_warn}) for old binary; "
            f"got {data['worst_severity']!r}.\n"
            f"Rows: {data['rows']!r}"
        )

        stale_rows = [r for r in data["rows"] if "STALE" in r["label"].upper()]
        assert stale_rows, (
            f"No STALE row found in section rows.\n"
            f"Rows: {data['rows']!r}"
        )

        # The fix must include upgrade instructions.
        fix = stale_rows[0]["fix"]
        assert "pipx upgrade" in fix or "pip install" in fix, (
            f"Row fix does not contain upgrade instructions.\n"
            f"Fix: {fix!r}"
        )

    def test_new_binary_produces_ok_row(self, tmp_path: pathlib.Path) -> None:
        """check_stale_binary must add an OK row when the new shim is on PATH."""
        shim_dir = tmp_path / "section_new"
        shim_dir.mkdir()
        _make_shim(shim_dir, "iam-jit", _SHIM_NEW)

        data = self._run_check(shim_dir)

        sev_ok = data["SEV_OK"]
        assert data["worst_severity"] == sev_ok, (
            f"Expected worst_severity == OK ({sev_ok}) for new binary; "
            f"got {data['worst_severity']!r}.\n"
            f"Rows: {data['rows']!r}"
        )

        ok_rows = [r for r in data["rows"] if r["severity"] == sev_ok]
        assert ok_rows, (
            f"No OK row found for up-to-date binary.\n"
            f"Rows: {data['rows']!r}"
        )


# ---------------------------------------------------------------------------
# Documentation reality check
# ---------------------------------------------------------------------------


class TestMcpRecipesDocumentation:
    """Verify docs/MCP-RECIPES.md covers the PR #23 install-bootstrap flow.

    These are pure-filesystem checks — no subprocesses, no live services.
    """

    @staticmethod
    def _read_mcp_recipes() -> str:
        repo_root = pathlib.Path(__file__).parent.parent.parent
        p = repo_root / "docs" / "MCP-RECIPES.md"
        if not p.exists():
            pytest.skip(f"docs/MCP-RECIPES.md not found at {p}")
        return p.read_text(encoding="utf-8")

    def test_install_claude_code_section_exists(self) -> None:
        """MCP-RECIPES.md must have an install-claude-code section."""
        content = self._read_mcp_recipes()
        assert "install-claude-code" in content, (
            "docs/MCP-RECIPES.md does not mention 'install-claude-code'. "
            "The Claude Code install section is required per #738."
        )

    def test_settings_json_documented(self) -> None:
        """MCP-RECIPES.md must document that install-claude-code writes env vars
        into ~/.claude/settings.json."""
        content = self._read_mcp_recipes()
        assert "settings.json" in content, (
            "docs/MCP-RECIPES.md does not mention 'settings.json'. "
            "The env-block write target must be documented per #738."
        )

    def test_aws_endpoint_url_documented(self) -> None:
        """MCP-RECIPES.md must document AWS_ENDPOINT_URL as the wired env var."""
        content = self._read_mcp_recipes()
        assert "AWS_ENDPOINT_URL" in content, (
            "docs/MCP-RECIPES.md does not mention 'AWS_ENDPOINT_URL'. "
            "The primary env var injected by install-claude-code must appear per #738."
        )

    def test_restart_requirement_documented(self) -> None:
        """MCP-RECIPES.md must document that a restart is required."""
        content = self._read_mcp_recipes()
        # Accept 'restart' or 'new session' (per emit_restart_required_message wording).
        has_restart = (
            "restart" in content.lower()
            or "new session" in content.lower()
        )
        assert has_restart, (
            "docs/MCP-RECIPES.md does not document the restart requirement. "
            "Operators must be told a new Claude Code session is needed per #738."
        )

    def test_attach_alternative_documented(self) -> None:
        """MCP-RECIPES.md must document iam-jit attach as the immediate alternative."""
        content = self._read_mcp_recipes()
        assert "iam-jit attach" in content or "attach" in content.lower(), (
            "docs/MCP-RECIPES.md does not document 'iam-jit attach' as the "
            "no-restart alternative. Required per #738."
        )

    def test_version_requirement_documented(self) -> None:
        """MCP-RECIPES.md must document that the env-block write requires a minimum version."""
        content = self._read_mcp_recipes()
        # Accept either a v1.0 mention or the --settings-path flag mention
        # (both signal version awareness).
        has_version_info = (
            "v1.0" in content
            or "--settings-path" in content
            or "PR #23" in content
        )
        assert has_version_info, (
            "docs/MCP-RECIPES.md does not document the version requirement for "
            "the env-block write. Operators with a stale binary need guidance per #738."
        )

    def test_env_vars_listed(self) -> None:
        """MCP-RECIPES.md must list the env vars that get injected."""
        content = self._read_mcp_recipes()
        has_proxy = "HTTP_PROXY" in content or "HTTPS_PROXY" in content
        assert has_proxy, (
            "docs/MCP-RECIPES.md does not list HTTP_PROXY / HTTPS_PROXY as injected "
            "env vars. The gbounce proxy wiring should be documented per #738."
        )
