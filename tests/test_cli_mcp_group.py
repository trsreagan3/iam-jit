"""Tests for `iam-jit mcp show-config` + `iam-jit mcp install-claude-code`
(UAT-D B1 closure: the install path the README + serve banner reference
must actually exist + work).
"""

from __future__ import annotations

import json
import pathlib

from click.testing import CliRunner

from iam_jit.cli import main


def test_mcp_show_config_emits_valid_json() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "show-config"])
    assert result.exit_code == 0, result.output
    cfg = json.loads(result.output)
    assert "mcpServers" in cfg
    entry = cfg["mcpServers"]["iam-jit"]
    assert entry["command"] == "iam-jit"
    assert entry["args"] == ["mcp-server"]


def test_mcp_show_config_compact_mode() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "show-config", "--compact"])
    assert result.exit_code == 0
    # Compact = no newlines inside the JSON
    body = result.output.strip()
    assert "\n" not in body
    cfg = json.loads(body)
    assert cfg["mcpServers"]["iam-jit"]["command"] == "iam-jit"


def test_mcp_install_dry_run_does_not_write(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "claude_desktop_config.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code",
        "--path", str(target),
        "--dry-run",
    ])
    assert result.exit_code == 0, result.output
    assert "would write" in result.output
    assert "dry run" in result.output
    assert not target.exists(), "dry-run must not touch the file"


def test_mcp_install_creates_new_config(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "subdir" / "claude_desktop_config.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code", "--path", str(target),
    ])
    assert result.exit_code == 0, result.output
    assert target.exists()
    cfg = json.loads(target.read_text())
    assert cfg["mcpServers"]["iam-jit"]["command"] == "iam-jit"
    assert cfg["mcpServers"]["iam-jit"]["args"] == ["mcp-server"]


def test_mcp_install_preserves_existing_other_servers(tmp_path: pathlib.Path) -> None:
    """If the user already has other mcpServers configured, we must
    not clobber them — only add/update the iam-jit entry."""
    target = tmp_path / "claude_desktop_config.json"
    target.write_text(json.dumps({
        "mcpServers": {
            "filesystem": {"command": "npx", "args": ["fs-server"]},
            "fetch": {"command": "uvx", "args": ["mcp-fetch"]},
        },
        "otherSetting": "preserve me",
    }, indent=2))
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code", "--path", str(target),
    ])
    assert result.exit_code == 0, result.output
    cfg = json.loads(target.read_text())
    # iam-jit added
    assert cfg["mcpServers"]["iam-jit"]["command"] == "iam-jit"
    # Existing entries preserved
    assert cfg["mcpServers"]["filesystem"]["command"] == "npx"
    assert cfg["mcpServers"]["fetch"]["command"] == "uvx"
    # Top-level non-mcpServers keys preserved
    assert cfg["otherSetting"] == "preserve me"


def test_mcp_install_overwrites_existing_iam_jit_entry(tmp_path: pathlib.Path) -> None:
    """Re-installing iam-jit should overwrite the previous entry
    (e.g. after upgrading the iam-jit binary path)."""
    target = tmp_path / "claude_desktop_config.json"
    target.write_text(json.dumps({
        "mcpServers": {
            "iam-jit": {"command": "/old/path/iam-jit", "args": ["mcp-server"]},
        },
    }))
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code", "--path", str(target),
    ])
    assert result.exit_code == 0
    assert "updated" in result.output.lower()
    cfg = json.loads(target.read_text())
    assert cfg["mcpServers"]["iam-jit"]["command"] == "iam-jit"
    assert "/old/path" not in target.read_text()


def test_mcp_install_refuses_to_clobber_invalid_json(tmp_path: pathlib.Path) -> None:
    """If the existing config is corrupt JSON, refuse rather than
    overwriting silently."""
    target = tmp_path / "claude_desktop_config.json"
    target.write_text("this is not json {{{")
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code", "--path", str(target),
    ])
    assert result.exit_code != 0
    # Original content preserved
    assert "this is not json" in target.read_text()


def test_mcp_install_print_only_does_not_write(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "claude_desktop_config.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code", "--path", str(target), "--print-only",
    ])
    assert result.exit_code == 0
    assert "target config path" in result.output
    assert "would write" in result.output
    assert not target.exists()
