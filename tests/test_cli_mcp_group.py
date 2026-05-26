"""Tests for `iam-jit mcp show-config` + `iam-jit mcp install-claude-code`
(UAT-D B1 closure: the install path the README + serve banner reference
must actually exist + work).

#652 parity tests: default path detection ladder must match ibounce's:
  1. ~/.claude.json  (Claude Code, preferred)
  2. ~/.config/claude-code/mcp.json
  3. Platform Desktop fallback
"""

from __future__ import annotations

import json
import pathlib
import unittest.mock

from click.testing import CliRunner

from iam_jit.cli import main, _candidate_claude_code_paths, _pick_claude_code_default


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


# ---------------------------------------------------------------------------
# #652 — default path detection ladder parity with ibounce
# ---------------------------------------------------------------------------


def test_candidate_paths_first_entry_is_claude_json(tmp_path: pathlib.Path) -> None:
    """_candidate_claude_code_paths() MUST list ~/.claude.json first."""
    with unittest.mock.patch("pathlib.Path.home", return_value=tmp_path):
        candidates = _candidate_claude_code_paths()
    assert candidates[0] == tmp_path / ".claude.json"


def test_candidate_paths_second_entry_is_config_claude_code(tmp_path: pathlib.Path) -> None:
    """Second candidate MUST be ~/.config/claude-code/mcp.json."""
    with unittest.mock.patch("pathlib.Path.home", return_value=tmp_path):
        candidates = _candidate_claude_code_paths()
    assert candidates[1] == tmp_path / ".config" / "claude-code" / "mcp.json"


def test_pick_default_no_existing_files_returns_claude_json(tmp_path: pathlib.Path) -> None:
    """When NO candidate exists, default falls back to ~/.claude.json (slot 0)."""
    with unittest.mock.patch("pathlib.Path.home", return_value=tmp_path):
        default = _pick_claude_code_default()
    assert default == tmp_path / ".claude.json"


def test_pick_default_claude_json_exists_returns_it(tmp_path: pathlib.Path) -> None:
    """When ~/.claude.json EXISTS, _pick_claude_code_default must return it."""
    claude_json = tmp_path / ".claude.json"
    claude_json.touch()
    with unittest.mock.patch("pathlib.Path.home", return_value=tmp_path):
        default = _pick_claude_code_default()
    assert default == claude_json


def test_pick_default_only_config_claude_code_exists(tmp_path: pathlib.Path) -> None:
    """If only ~/.config/claude-code/mcp.json exists (not ~/.claude.json),
    _pick_claude_code_default picks it over the fallback Desktop path."""
    alt = tmp_path / ".config" / "claude-code" / "mcp.json"
    alt.parent.mkdir(parents=True)
    alt.touch()
    with unittest.mock.patch("pathlib.Path.home", return_value=tmp_path):
        default = _pick_claude_code_default()
    assert default == alt


def test_install_explicit_path_overrides_default(tmp_path: pathlib.Path) -> None:
    """Passing --path /tmp/foo.json MUST write there regardless of which
    candidate files exist."""
    target = tmp_path / "custom" / "mcp_config.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code", "--path", str(target),
    ])
    assert result.exit_code == 0, result.output
    assert target.exists()
    cfg = json.loads(target.read_text())
    assert cfg["mcpServers"]["iam-jit"]["command"] == "iam-jit"


def test_default_no_flag_targets_claude_json_when_no_files_exist(tmp_path: pathlib.Path) -> None:
    """When invoked without --path in a clean HOME (no candidate files),
    the command writes to ~/.claude.json (slot 0, the Claude Code default)
    rather than the Desktop path."""
    runner = CliRunner()
    # Patch home() so the detection ladder looks inside tmp_path.
    with unittest.mock.patch("pathlib.Path.home", return_value=tmp_path):
        result = runner.invoke(main, ["mcp", "install-claude-code"])
    assert result.exit_code == 0, result.output
    expected = tmp_path / ".claude.json"
    assert expected.exists(), (
        "With no candidate files present the command must default to "
        "~/.claude.json, not the Desktop path"
    )
    cfg = json.loads(expected.read_text())
    assert cfg["mcpServers"]["iam-jit"]["command"] == "iam-jit"


def test_default_no_flag_uses_existing_claude_json(tmp_path: pathlib.Path) -> None:
    """When ~/.claude.json already exists in HOME, the no-flag default
    picks it (adds the iam-jit entry, preserving any other content)."""
    claude_json = tmp_path / ".claude.json"
    claude_json.write_text(json.dumps({
        "mcpServers": {"other-tool": {"command": "other", "args": []}},
    }, indent=2))
    runner = CliRunner()
    with unittest.mock.patch("pathlib.Path.home", return_value=tmp_path):
        result = runner.invoke(main, ["mcp", "install-claude-code"])
    assert result.exit_code == 0, result.output
    cfg = json.loads(claude_json.read_text())
    assert cfg["mcpServers"]["iam-jit"]["command"] == "iam-jit"
    # Pre-existing entry preserved
    assert cfg["mcpServers"]["other-tool"]["command"] == "other"
