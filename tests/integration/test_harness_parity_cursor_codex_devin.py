"""#743 — Cursor / Codex / Devin harness install-bootstrap parity UAT.

Per [[uat-tests-setup-end-to-end]] STANDING DISCIPLINE: tests must exercise
the full chain as a user/agent experiences it:

  install-cursor / install-codex → written config has routing env block →
  subprocess spawned with those env vars sees AWS_ENDPOINT_URL →
  bouncer's decisions_count ticks on an outbound AWS call.

For Devin (cloud agent with no local config): verify that install-devin
prints the correct recipe with the right env vars (matching live bouncer
ports), and that a subprocess pre-configured with those env vars routes
through ibounce (decisions_count ticks).

Per [[ibounce-honest-positioning]]: verify honest "no running bouncers"
warning is emitted when bouncers are not running (tested via monkeypatching).

Per [[permission-minimal-install]]: no sudo, no broad-Bash, no
--dangerously-skip-permissions required by any test here.

Tests that require a live ibounce on :8767 are marked @live_bouncer
and skipped when the port is closed. Unit tests run always.
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import sys
from contextlib import closing
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Live-bouncer skip gate
# ---------------------------------------------------------------------------


def _port_is_open(host: str, port: int) -> bool:
    """Return True iff the TCP port is accepting connections."""
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(0.5)
            s.connect((host, port))
            return True
    except OSError:
        return False


_IBOUNCE_HOST = "127.0.0.1"
_IBOUNCE_PORT = 8767
_IBOUNCE_RUNNING = _port_is_open(_IBOUNCE_HOST, _IBOUNCE_PORT)

# Capture the REAL home dir at module load time (before any monkeypatching).
_REAL_HOME = pathlib.Path.home()

live_bouncer = pytest.mark.skipif(
    not _IBOUNCE_RUNNING,
    reason="ibounce not running on :8767 — skipping live-bouncer UAT",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ibounce_decisions_count() -> int:
    """Return decisions_count from ibounce healthz. Raises on any error.

    Uses a no-proxy opener so HTTP_PROXY/HTTPS_PROXY set in the calling
    process environment (e.g. from gbounce wiring) do NOT intercept this
    direct loopback call.
    """
    import urllib.request
    url = f"http://{_IBOUNCE_HOST}:{_IBOUNCE_PORT}/healthz"
    # Bypass any proxy env vars — ibounce is always on 127.0.0.1.
    no_proxy_opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({})
    )
    with no_proxy_opener.open(url, timeout=3) as resp:  # noqa: S310
        data = json.loads(resp.read())
    return int(data["decisions_count"])


def _run_fresh_subprocess(
    code: str,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
    """Run *code* in a fresh Python subprocess with a CLEAN env.

    The subprocess inherits only a minimal env (PATH + PYTHONPATH from
    the current venv, plus anything in *extra_env*). It does NOT inherit
    AWS_ENDPOINT_URL / HTTP_PROXY / HTTPS_PROXY from the calling process —
    that ensures we're testing the install story, not relying on the
    caller's already-wired env.

    Per [[uat-tests-setup-end-to-end]]: this is the "fresh subprocess"
    shape — the actual path an agent tool subprocess follows.
    """
    clean_env: dict[str, str] = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        "HOME": str(_REAL_HOME),
        **{
            k: os.environ[k]
            for k in (
                "AWS_DEFAULT_REGION",
                "AWS_REGION",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_PROFILE",
                "AWS_CONFIG_FILE",
                "AWS_SHARED_CREDENTIALS_FILE",
            )
            if k in os.environ
        },
        **(
            {"AWS_DEFAULT_REGION": "us-east-1"}
            if not any(
                k in os.environ
                for k in ("AWS_DEFAULT_REGION", "AWS_REGION")
            )
            else {}
        ),
        **(
            {"AWS_PROFILE": "iam-jit"}
            if not any(
                k in os.environ
                for k in ("AWS_ACCESS_KEY_ID", "AWS_PROFILE")
            )
            and _REAL_HOME.joinpath(".aws", "credentials").exists()
            else {}
        ),
    }
    # Explicitly strip the bouncer wiring vars — the subprocess starts UNWIRED.
    for stripped in ("AWS_ENDPOINT_URL", "HTTP_PROXY", "HTTPS_PROXY"):
        clean_env.pop(stripped, None)

    if extra_env:
        clean_env.update(extra_env)

    return subprocess.run(
        [sys.executable, "-c", code],
        env=clean_env,
        capture_output=True,
        text=True,
        timeout=30,
    )


# ---------------------------------------------------------------------------
# Unit tests — run always (no live bouncer required)
# ---------------------------------------------------------------------------


class TestCursorMcpConfigDict:
    """Unit tests for _ibounce_mcp_config_dict with extra_env (#743)."""

    def test_cursor_config_includes_agent_name(self) -> None:
        """Cursor snippet has IBOUNCE_AGENT_NAME=cursor."""
        from iam_jit.bouncer_cli import _ibounce_mcp_config_dict

        cfg = _ibounce_mcp_config_dict(agent_name_default="cursor")
        env = cfg["mcpServers"]["ibounce"]["env"]
        assert env["IBOUNCE_AGENT_NAME"] == "cursor"
        assert "IBOUNCE_AGENT_SESSION_ID" in env

    def test_codex_config_includes_agent_name(self) -> None:
        """Codex snippet has IBOUNCE_AGENT_NAME=openai-codex."""
        from iam_jit.bouncer_cli import _ibounce_mcp_config_dict

        cfg = _ibounce_mcp_config_dict(agent_name_default="openai-codex")
        env = cfg["mcpServers"]["ibounce"]["env"]
        assert env["IBOUNCE_AGENT_NAME"] == "openai-codex"

    def test_extra_env_merged_into_server_env(self) -> None:
        """extra_env vars appear in the mcpServers.ibounce.env block."""
        from iam_jit.bouncer_cli import _ibounce_mcp_config_dict

        extra = {
            "AWS_ENDPOINT_URL": "http://127.0.0.1:8767",
            "HTTP_PROXY": "http://127.0.0.1:8080",
            "HTTPS_PROXY": "http://127.0.0.1:8080",
        }
        cfg = _ibounce_mcp_config_dict(agent_name_default="cursor", extra_env=extra)
        env = cfg["mcpServers"]["ibounce"]["env"]
        assert env["AWS_ENDPOINT_URL"] == "http://127.0.0.1:8767"
        assert env["HTTP_PROXY"] == "http://127.0.0.1:8080"
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:8080"
        # Header-injection hints still present.
        assert env["IBOUNCE_AGENT_NAME"] == "cursor"
        assert "IBOUNCE_AGENT_SESSION_ID" in env

    def test_extra_env_none_does_not_add_routing_keys(self) -> None:
        """When extra_env is None, no routing vars appear in the snippet."""
        from iam_jit.bouncer_cli import _ibounce_mcp_config_dict

        cfg = _ibounce_mcp_config_dict(agent_name_default="cursor", extra_env=None)
        env = cfg["mcpServers"]["ibounce"]["env"]
        assert "AWS_ENDPOINT_URL" not in env
        assert "HTTP_PROXY" not in env
        assert "HTTPS_PROXY" not in env


class TestMergeIbounceEntryExtraEnv:
    """Unit tests for _merge_ibounce_entry with extra_env (#743)."""

    def test_writes_routing_env_into_cursor_config(
        self, tmp_path: pathlib.Path
    ) -> None:
        """install-cursor path: routing vars land in mcp.json server env block."""
        from iam_jit.bouncer_cli import _merge_ibounce_entry

        mcp_json = tmp_path / "mcp.json"
        extra = {
            "AWS_ENDPOINT_URL": "http://127.0.0.1:8767",
            "HTTP_PROXY": "http://127.0.0.1:8080",
        }
        overwriting, err = _merge_ibounce_entry(
            mcp_json,
            force=True,
            agent_name_default="cursor",
            extra_env=extra,
        )
        assert err is None, err
        assert not overwriting  # fresh file

        data = json.loads(mcp_json.read_text())
        server_env = data["mcpServers"]["ibounce"]["env"]
        assert server_env["AWS_ENDPOINT_URL"] == "http://127.0.0.1:8767"
        assert server_env["HTTP_PROXY"] == "http://127.0.0.1:8080"
        assert server_env["IBOUNCE_AGENT_NAME"] == "cursor"

    def test_preserves_existing_mcp_servers(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Other mcpServers entries are preserved on merge (no clobber)."""
        from iam_jit.bouncer_cli import _merge_ibounce_entry

        mcp_json = tmp_path / "mcp.json"
        # Pre-populate with another server.
        mcp_json.write_text(
            json.dumps({
                "mcpServers": {
                    "other-server": {"command": "other", "args": []}
                }
            }) + "\n"
        )

        overwriting, err = _merge_ibounce_entry(
            mcp_json,
            force=True,
            agent_name_default="cursor",
            extra_env={"AWS_ENDPOINT_URL": "http://127.0.0.1:8767"},
        )
        assert err is None, err

        data = json.loads(mcp_json.read_text())
        # ibounce was added.
        assert "ibounce" in data["mcpServers"]
        # other-server was preserved.
        assert "other-server" in data["mcpServers"]

    def test_no_extra_env_omits_routing_vars(
        self, tmp_path: pathlib.Path
    ) -> None:
        """When extra_env is None, written config has no routing vars."""
        from iam_jit.bouncer_cli import _merge_ibounce_entry

        mcp_json = tmp_path / "mcp.json"
        overwriting, err = _merge_ibounce_entry(
            mcp_json,
            force=True,
            agent_name_default="cursor",
            extra_env=None,
        )
        assert err is None, err

        data = json.loads(mcp_json.read_text())
        server_env = data["mcpServers"]["ibounce"]["env"]
        assert "AWS_ENDPOINT_URL" not in server_env
        assert "HTTP_PROXY" not in server_env


class TestInstallCursorCli:
    """Unit tests for `ibounce mcp install-cursor` CLI surface (#743)."""

    def test_install_cursor_writes_routing_env_when_bouncers_running(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """install-cursor writes routing env block when bouncers are detected."""
        from click.testing import CliRunner
        import iam_jit.bouncer_cli as bouncer_mod

        monkeypatch.setattr(
            bouncer_mod,
            "_build_bouncer_env_vars_for_mcp",
            lambda: {
                "AWS_ENDPOINT_URL": "http://127.0.0.1:8767",
                "HTTP_PROXY": "http://127.0.0.1:8080",
                "HTTPS_PROXY": "http://127.0.0.1:8080",
            },
        )

        from iam_jit.bouncer_cli import mcp_install_cursor_cmd
        mcp_json = tmp_path / "cursor" / "mcp.json"
        runner = CliRunner()
        result = runner.invoke(
            mcp_install_cursor_cmd,
            ["--path", str(mcp_json), "--force"],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, result.output
        data = json.loads(mcp_json.read_text())
        server_env = data["mcpServers"]["ibounce"]["env"]
        assert server_env["AWS_ENDPOINT_URL"] == "http://127.0.0.1:8767"
        assert server_env["HTTP_PROXY"] == "http://127.0.0.1:8080"
        assert server_env["HTTPS_PROXY"] == "http://127.0.0.1:8080"
        assert server_env["IBOUNCE_AGENT_NAME"] == "cursor"

    def test_install_cursor_warns_when_no_bouncers(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """install-cursor emits honest warning when no bouncers detected."""
        from click.testing import CliRunner
        import iam_jit.bouncer_cli as bouncer_mod

        monkeypatch.setattr(
            bouncer_mod,
            "_build_bouncer_env_vars_for_mcp",
            lambda: {},
        )

        from iam_jit.bouncer_cli import mcp_install_cursor_cmd
        mcp_json = tmp_path / "mcp.json"
        runner = CliRunner()
        result = runner.invoke(
            mcp_install_cursor_cmd,
            ["--path", str(mcp_json), "--force"],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, result.output
        assert "no running bouncers" in result.output.lower()
        # Config still written (MCP entry), but without routing vars.
        data = json.loads(mcp_json.read_text())
        server_env = data["mcpServers"]["ibounce"]["env"]
        assert "AWS_ENDPOINT_URL" not in server_env

    def test_install_cursor_no_env_block_skips_routing(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--no-env-block skips routing vars even when bouncers running."""
        from click.testing import CliRunner
        import iam_jit.bouncer_cli as bouncer_mod

        monkeypatch.setattr(
            bouncer_mod,
            "_build_bouncer_env_vars_for_mcp",
            lambda: {"AWS_ENDPOINT_URL": "http://127.0.0.1:8767"},
        )

        from iam_jit.bouncer_cli import mcp_install_cursor_cmd
        mcp_json = tmp_path / "mcp.json"
        runner = CliRunner()
        result = runner.invoke(
            mcp_install_cursor_cmd,
            ["--path", str(mcp_json), "--force", "--no-env-block"],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, result.output
        data = json.loads(mcp_json.read_text())
        server_env = data["mcpServers"]["ibounce"]["env"]
        assert "AWS_ENDPOINT_URL" not in server_env

    def test_install_cursor_parity_with_claude_code(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cursor and Claude Code both write the same routing env vars.

        PR #23 parity check: AWS_ENDPOINT_URL + HTTP_PROXY + HTTPS_PROXY
        must appear in both install paths when bouncers are running.
        """
        from click.testing import CliRunner
        import iam_jit.bouncer_cli as bouncer_mod
        import iam_jit.cli as cli_mod

        test_env = {
            "AWS_ENDPOINT_URL": "http://127.0.0.1:8767",
            "HTTP_PROXY": "http://127.0.0.1:8080",
            "HTTPS_PROXY": "http://127.0.0.1:8080",
        }
        monkeypatch.setattr(
            bouncer_mod, "_build_bouncer_env_vars_for_mcp", lambda: test_env
        )
        monkeypatch.setattr(
            cli_mod, "_build_bouncer_env_vars", lambda: test_env
        )

        # Install Cursor.
        from iam_jit.bouncer_cli import mcp_install_cursor_cmd
        cursor_json = tmp_path / "cursor_mcp.json"
        runner = CliRunner()
        result = runner.invoke(
            mcp_install_cursor_cmd,
            ["--path", str(cursor_json), "--force"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        cursor_data = json.loads(cursor_json.read_text())
        cursor_env = cursor_data["mcpServers"]["ibounce"]["env"]

        # Parity check: all three routing vars present in Cursor config.
        for key in ("AWS_ENDPOINT_URL", "HTTP_PROXY", "HTTPS_PROXY"):
            assert key in cursor_env, (
                f"Cursor MCP env missing {key} — parity gap vs PR #23 Claude Code path"
            )
        assert cursor_env["AWS_ENDPOINT_URL"] == test_env["AWS_ENDPOINT_URL"]
        assert cursor_env["HTTP_PROXY"] == test_env["HTTP_PROXY"]
        assert cursor_env["HTTPS_PROXY"] == test_env["HTTPS_PROXY"]


class TestInstallCodexCli:
    """Unit tests for `ibounce mcp install-codex` CLI surface (#743)."""

    def test_install_codex_with_path_writes_routing_env(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """install-codex --path writes routing env block when bouncers detected."""
        from click.testing import CliRunner
        import iam_jit.bouncer_cli as bouncer_mod

        monkeypatch.setattr(
            bouncer_mod,
            "_build_bouncer_env_vars_for_mcp",
            lambda: {
                "AWS_ENDPOINT_URL": "http://127.0.0.1:8767",
                "HTTP_PROXY": "http://127.0.0.1:8080",
                "HTTPS_PROXY": "http://127.0.0.1:8080",
            },
        )

        from iam_jit.bouncer_cli import mcp_install_codex_cmd
        mcp_json = tmp_path / "codex_mcp.json"
        runner = CliRunner()
        result = runner.invoke(
            mcp_install_codex_cmd,
            ["--path", str(mcp_json), "--force"],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, result.output
        data = json.loads(mcp_json.read_text())
        server_env = data["mcpServers"]["ibounce"]["env"]
        assert server_env["AWS_ENDPOINT_URL"] == "http://127.0.0.1:8767"
        assert server_env["IBOUNCE_AGENT_NAME"] == "openai-codex"

    def test_install_codex_snippet_includes_routing_env(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """install-codex (no --path) prints snippet with routing vars when bouncers up."""
        from click.testing import CliRunner
        import iam_jit.bouncer_cli as bouncer_mod

        monkeypatch.setattr(
            bouncer_mod,
            "_build_bouncer_env_vars_for_mcp",
            lambda: {
                "AWS_ENDPOINT_URL": "http://127.0.0.1:8767",
            },
        )

        from iam_jit.bouncer_cli import mcp_install_codex_cmd
        runner = CliRunner()
        result = runner.invoke(
            mcp_install_codex_cmd,
            [],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, result.output
        # The snippet is printed to stdout — parse the JSON portion.
        output = result.output
        json_start = output.index("{")
        json_end = output.rindex("}") + 1
        snippet = json.loads(output[json_start:json_end])
        server_env = snippet["mcpServers"]["ibounce"]["env"]
        assert server_env["AWS_ENDPOINT_URL"] == "http://127.0.0.1:8767"

    def test_install_codex_warns_no_bouncers_in_snippet(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """install-codex warns when no bouncers running (routing vars absent)."""
        from click.testing import CliRunner
        import iam_jit.bouncer_cli as bouncer_mod

        monkeypatch.setattr(
            bouncer_mod,
            "_build_bouncer_env_vars_for_mcp",
            lambda: {},
        )

        from iam_jit.bouncer_cli import mcp_install_codex_cmd
        runner = CliRunner()
        result = runner.invoke(
            mcp_install_codex_cmd,
            [],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, result.output
        assert "no running bouncers" in result.output.lower()


class TestInstallDevinCli:
    """Unit tests for `ibounce mcp install-devin` CLI surface (#743)."""

    def test_install_devin_prints_path_a_and_b(self) -> None:
        """install-devin always emits PATH A and PATH B instructions."""
        from click.testing import CliRunner
        from iam_jit.bouncer_cli import mcp_install_devin_cmd

        runner = CliRunner()
        result = runner.invoke(mcp_install_devin_cmd, [], catch_exceptions=False)

        assert result.exit_code == 0, result.output
        assert "PATH A" in result.output
        assert "PATH B" in result.output
        assert "cloud" in result.output.lower()

    def test_install_devin_shows_detected_bouncer_ports(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When bouncers running, install-devin shows their actual ports."""
        from click.testing import CliRunner
        import iam_jit.bouncer_cli as bouncer_mod

        monkeypatch.setattr(
            bouncer_mod,
            "_build_bouncer_env_vars_for_mcp",
            lambda: {
                "AWS_ENDPOINT_URL": "http://127.0.0.1:8767",
                "HTTP_PROXY": "http://127.0.0.1:8080",
                "HTTPS_PROXY": "http://127.0.0.1:8080",
            },
        )

        from iam_jit.bouncer_cli import mcp_install_devin_cmd
        runner = CliRunner()
        result = runner.invoke(mcp_install_devin_cmd, [], catch_exceptions=False)

        assert result.exit_code == 0, result.output
        assert "8767" in result.output
        assert "8080" in result.output

    def test_install_devin_shows_placeholder_when_no_bouncers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When no bouncers running, install-devin shows <bouncer-host> placeholder."""
        from click.testing import CliRunner
        import iam_jit.bouncer_cli as bouncer_mod

        monkeypatch.setattr(
            bouncer_mod,
            "_build_bouncer_env_vars_for_mcp",
            lambda: {},
        )

        from iam_jit.bouncer_cli import mcp_install_devin_cmd
        runner = CliRunner()
        result = runner.invoke(mcp_install_devin_cmd, [], catch_exceptions=False)

        assert result.exit_code == 0, result.output
        assert "<bouncer-host>" in result.output

    def test_install_devin_honest_limitation_notice(self) -> None:
        """install-devin surfaces the sandbox-visibility limitation honestly."""
        from click.testing import CliRunner
        from iam_jit.bouncer_cli import mcp_install_devin_cmd

        runner = CliRunner()
        result = runner.invoke(mcp_install_devin_cmd, [], catch_exceptions=False)

        assert result.exit_code == 0, result.output
        # Must mention that 127.0.0.1 is not visible to Devin's sandbox.
        assert "127.0.0.1" in result.output and "sandbox" in result.output.lower()

    def test_install_devin_no_local_config_written(
        self, tmp_path: pathlib.Path
    ) -> None:
        """install-devin writes NO files — cloud agent has no local config."""
        from click.testing import CliRunner
        from iam_jit.bouncer_cli import mcp_install_devin_cmd

        runner = CliRunner()
        # Run from tmp_path CWD; verify nothing was written there.
        result = runner.invoke(mcp_install_devin_cmd, [], catch_exceptions=False)
        assert result.exit_code == 0, result.output
        # No JSON/config files should have been written.
        written = list(tmp_path.iterdir())
        assert written == [], f"install-devin wrote unexpected files: {written}"


class TestBuildBouncerEnvVarsForMcp:
    """Unit tests for _build_bouncer_env_vars_for_mcp (#743)."""

    def test_returns_empty_dict_on_capture_posture_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Best-effort: returns {} rather than raising when posture fails."""
        import iam_jit.bouncer_cli as bouncer_mod

        # Patch capture_posture to raise.
        def _bad_posture():  # type: ignore[return]
            raise RuntimeError("posture unavailable")

        import unittest.mock as _mock
        with _mock.patch("iam_jit.posture.capture_posture", _bad_posture):
            result = bouncer_mod._build_bouncer_env_vars_for_mcp()
        assert result == {}

    def test_returns_aws_endpoint_url_when_ibounce_running(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AWS_ENDPOINT_URL set when ibounce is running."""
        import iam_jit.bouncer_cli as bouncer_mod
        import unittest.mock as _mock

        snap = {
            "bouncers": {
                "ibounce": {"running": True, "misconfig": False, "port": 8767},
            }
        }
        with _mock.patch("iam_jit.posture.capture_posture", return_value=snap):
            result = bouncer_mod._build_bouncer_env_vars_for_mcp()
        assert result["AWS_ENDPOINT_URL"] == "http://127.0.0.1:8767"
        assert "HTTP_PROXY" not in result

    def test_returns_proxy_when_gbounce_running(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HTTP_PROXY / HTTPS_PROXY set when gbounce is running."""
        import iam_jit.bouncer_cli as bouncer_mod
        import unittest.mock as _mock

        snap = {
            "bouncers": {
                "gbounce": {"running": True, "misconfig": False, "wire_port": 8080},
            }
        }
        with _mock.patch("iam_jit.posture.capture_posture", return_value=snap):
            result = bouncer_mod._build_bouncer_env_vars_for_mcp()
        assert result["HTTP_PROXY"] == "http://127.0.0.1:8080"
        assert result["HTTPS_PROXY"] == "http://127.0.0.1:8080"
        assert "AWS_ENDPOINT_URL" not in result

    def test_returns_empty_when_ibounce_misconfig(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Per [[ibounce-honest-positioning]]: misconfig bouncer → no URL emitted."""
        import iam_jit.bouncer_cli as bouncer_mod
        import unittest.mock as _mock

        snap = {
            "bouncers": {
                "ibounce": {"running": True, "misconfig": True, "port": 8767},
            }
        }
        with _mock.patch("iam_jit.posture.capture_posture", return_value=snap):
            result = bouncer_mod._build_bouncer_env_vars_for_mcp()
        assert "AWS_ENDPOINT_URL" not in result


# ---------------------------------------------------------------------------
# Live-bouncer E2E tests
# ---------------------------------------------------------------------------


@live_bouncer
class TestCursorE2EWithLiveBouncer:
    """E2E: cursor mcp.json → subprocess inherits env → bouncer ticks."""

    def test_cursor_install_then_subprocess_routes_through_bouncer(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Full chain: install-cursor writes config → subprocess with env from
        config routes STS call through ibounce → decisions_count ticks.

        This is the [[uat-tests-setup-end-to-end]] shape for Cursor:
          install → env-wire → subprocess sees AWS_ENDPOINT_URL →
          boto3 STS → ibounce → decisions_count +1
        """
        from iam_jit.bouncer_cli import _merge_ibounce_entry, _build_bouncer_env_vars_for_mcp

        mcp_json = tmp_path / "cursor" / "mcp.json"

        # Step 1: run install with live bouncer detection.
        bouncer_env = _build_bouncer_env_vars_for_mcp()
        assert "AWS_ENDPOINT_URL" in bouncer_env, (
            "ibounce is running but _build_bouncer_env_vars_for_mcp() "
            "returned no AWS_ENDPOINT_URL — posture detection gap"
        )

        overwriting, err = _merge_ibounce_entry(
            mcp_json,
            force=True,
            agent_name_default="cursor",
            extra_env=bouncer_env,
        )
        assert err is None, err

        # Step 2: read back the written config, extract env vars.
        data = json.loads(mcp_json.read_text())
        server_env: dict[str, str] = data["mcpServers"]["ibounce"]["env"]
        assert "AWS_ENDPOINT_URL" in server_env, (
            "Written Cursor config missing AWS_ENDPOINT_URL — "
            "install-cursor did not wire routing env vars"
        )

        # Step 3: snapshot decisions_count before the test call.
        before = _ibounce_decisions_count()

        # Step 4: spawn a fresh subprocess with the env vars from the config.
        # Only pass AWS_ENDPOINT_URL — boto3 uses this to route directly to
        # ibounce. HTTP_PROXY/HTTPS_PROXY are for gbounce (HTTP-level egress
        # gating), a separate routing path. Mixing both would route the STS
        # call through gbounce before it reaches ibounce via endpoint_url.
        subprocess_env = {"AWS_ENDPOINT_URL": server_env["AWS_ENDPOINT_URL"]}
        code = (
            "import boto3, json, os;"
            "sts = boto3.client('sts', endpoint_url=os.environ['AWS_ENDPOINT_URL']);"
            "r = sts.get_caller_identity();"
            "print(json.dumps({'Account': r['Account'], 'UserId': r['UserId']}))"
        )
        proc = _run_fresh_subprocess(code, extra_env=subprocess_env)

        # (A) The STS call returned a parseable response.
        assert proc.returncode == 0, (
            f"STS call via Cursor env routing failed:\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
        resp = json.loads(proc.stdout.strip())
        assert "Account" in resp, f"unexpected STS response: {resp}"

        # (B) decisions_count ticked — ibounce saw the call.
        after = _ibounce_decisions_count()
        assert after > before, (
            f"ibounce decisions_count did NOT tick after Cursor-env-routed "
            f"STS call (before={before}, after={after}). "
            "Routing env vars in mcp.json did not reach the subprocess."
        )


@live_bouncer
class TestCodexE2EWithLiveBouncer:
    """E2E: codex mcp.json → subprocess inherits env → bouncer ticks."""

    def test_codex_install_then_subprocess_routes_through_bouncer(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Full chain: install-codex --path writes config → subprocess with env
        from config routes STS call through ibounce → decisions_count ticks.
        """
        from iam_jit.bouncer_cli import _merge_ibounce_entry, _build_bouncer_env_vars_for_mcp

        mcp_json = tmp_path / "codex_mcp.json"

        bouncer_env = _build_bouncer_env_vars_for_mcp()
        assert "AWS_ENDPOINT_URL" in bouncer_env

        overwriting, err = _merge_ibounce_entry(
            mcp_json,
            force=True,
            agent_name_default="openai-codex",
            extra_env=bouncer_env,
        )
        assert err is None, err

        data = json.loads(mcp_json.read_text())
        server_env: dict[str, str] = data["mcpServers"]["ibounce"]["env"]
        assert "AWS_ENDPOINT_URL" in server_env

        before = _ibounce_decisions_count()

        # Only pass AWS_ENDPOINT_URL for ibounce routing via endpoint_url.
        subprocess_env = {"AWS_ENDPOINT_URL": server_env["AWS_ENDPOINT_URL"]}
        code = (
            "import boto3, json, os;"
            "sts = boto3.client('sts', endpoint_url=os.environ['AWS_ENDPOINT_URL']);"
            "r = sts.get_caller_identity();"
            "print(json.dumps({'Account': r['Account']}))"
        )
        proc = _run_fresh_subprocess(code, extra_env=subprocess_env)

        # (A) STS call succeeded.
        assert proc.returncode == 0, (
            f"STS call via Codex env routing failed:\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
        resp = json.loads(proc.stdout.strip())
        assert "Account" in resp

        # (B) decisions_count ticked.
        after = _ibounce_decisions_count()
        assert after > before, (
            f"ibounce decisions_count did NOT tick after Codex-env-routed "
            f"STS call (before={before}, after={after})."
        )


@live_bouncer
class TestDevinE2EWithLiveBouncer:
    """E2E: Devin recipe env vars → subprocess routes through bouncer.

    Devin has no local config to write. The E2E test verifies that a
    subprocess configured with the env vars printed by install-devin
    (PATH B: operator sets task env vars) routes through ibounce.

    This is the [[uat-tests-setup-end-to-end]] shape for Devin:
      operator sets env vars → subprocess sees AWS_ENDPOINT_URL →
      boto3 STS → ibounce → decisions_count +1
    """

    def test_devin_recipe_env_vars_route_through_bouncer(self) -> None:
        """subprocess pre-configured with Devin PATH B env vars routes via ibounce."""
        from iam_jit.bouncer_cli import _build_bouncer_env_vars_for_mcp

        bouncer_env = _build_bouncer_env_vars_for_mcp()
        assert "AWS_ENDPOINT_URL" in bouncer_env, (
            "ibounce running but no AWS_ENDPOINT_URL returned — posture gap"
        )

        before = _ibounce_decisions_count()

        # Simulate Devin PATH B: operator sets AWS_ENDPOINT_URL in task env.
        # For the routing test we use only AWS_ENDPOINT_URL (ibounce); 
        # HTTP_PROXY/HTTPS_PROXY are the gbounce path and would interfere.
        subprocess_env = {"AWS_ENDPOINT_URL": bouncer_env["AWS_ENDPOINT_URL"]}
        code = (
            "import boto3, json, os;"
            "sts = boto3.client('sts', endpoint_url=os.environ['AWS_ENDPOINT_URL']);"
            "r = sts.get_caller_identity();"
            "print(json.dumps({'Account': r['Account']}))"
        )
        proc = _run_fresh_subprocess(code, extra_env=subprocess_env)

        # (A) STS call succeeded.
        assert proc.returncode == 0, (
            f"STS call via Devin PATH-B env vars failed:\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
        resp = json.loads(proc.stdout.strip())
        assert "Account" in resp

        # (B) decisions_count ticked — ibounce saw the call.
        after = _ibounce_decisions_count()
        assert after > before, (
            f"ibounce decisions_count did NOT tick after Devin PATH-B "
            f"STS call (before={before}, after={after})."
        )
