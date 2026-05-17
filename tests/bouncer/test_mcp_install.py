"""Tests for `ibounce mcp ...` install + show-config + list-tools (#228).

Launch-readiness Stage 5 closure: the agent-integration unlock command
group. One command from fresh install to a wired agent. Tests cover:

  - show-config emits valid JSON + YAML
  - list-tools formatting + filtering
  - install-claude-code merges with existing servers (preserves other keys)
  - install-claude-code atomic write (no half-merged file on failure)
  - install-claude-code overwrite prompt + --force bypass
  - install-claude-code refuses on corrupt JSON (no clobber)
  - install-cursor mirrors install-claude-code semantics
  - install-codex prints snippet by default, atomic-merges when --path given

The MCP server entry shape (`ibounce mcp serve`) is verified loadable
as a valid MCP-client config — same structure other MCP clients accept.
"""

from __future__ import annotations

import json
import pathlib

from click.testing import CliRunner

from iam_jit.bouncer_cli import main


# ---------------------------------------------------------------------------
# show-config
# ---------------------------------------------------------------------------


def test_show_config_emits_valid_json_with_ibounce_entry() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "show-config"])
    assert result.exit_code == 0, result.output
    # The snippet appears at the top; the "Wire it up" banner follows.
    # Find the JSON-object section by splitting on the banner line.
    parts = result.output.split("\nWire it up:", 1)
    assert len(parts) == 2
    cfg = json.loads(parts[0])
    assert "mcpServers" in cfg
    entry = cfg["mcpServers"]["ibounce"]
    assert entry["command"] == "ibounce"
    assert entry["args"] == ["mcp", "serve"]
    assert entry["env"] == {}


def test_show_config_yaml_shape() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "show-config", "--shape", "yaml"])
    assert result.exit_code == 0, result.output
    # YAML output should NOT be JSON-parseable (it lacks the surrounding
    # braces); but it MUST mention the ibounce server entry literally.
    assert "ibounce" in result.output
    assert "mcpServers" in result.output
    # And the banner still shows.
    assert "install-claude-code" in result.output


def test_show_config_mentions_all_three_installers() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "show-config"])
    assert result.exit_code == 0
    assert "install-claude-code" in result.output
    assert "install-cursor" in result.output
    assert "install-codex" in result.output


# ---------------------------------------------------------------------------
# list-tools
# ---------------------------------------------------------------------------


def test_list_tools_two_column_table() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "list-tools"])
    assert result.exit_code == 0, result.output
    # Header row present.
    assert "TOOL" in result.output
    assert "DESCRIPTION" in result.output
    # A representative ibounce tool is listed.
    assert "ibounce_list_rules" in result.output
    # Summary footer present.
    assert "tool(s)" in result.output


def test_list_tools_json_shape() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "list-tools", "--json"])
    assert result.exit_code == 0
    items = json.loads(result.output)
    assert isinstance(items, list) and len(items) > 0
    for it in items:
        assert "name" in it and "description" in it
    names = [it["name"] for it in items]
    assert "ibounce_list_rules" in names


def test_list_tools_prefix_filter() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "list-tools", "--prefix", "ibounce_"])
    assert result.exit_code == 0
    # Every printed tool starts with the prefix.
    for line in result.output.splitlines():
        if line.startswith("ibounce_") or line.startswith("bouncer_"):
            assert line.startswith("ibounce_"), line


# ---------------------------------------------------------------------------
# install-claude-code
# ---------------------------------------------------------------------------


def test_install_claude_code_creates_new_config(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "subdir" / "claude.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code", "--path", str(target),
    ])
    assert result.exit_code == 0, result.output
    assert target.exists()
    cfg = json.loads(target.read_text())
    assert cfg["mcpServers"]["ibounce"]["command"] == "ibounce"
    assert cfg["mcpServers"]["ibounce"]["args"] == ["mcp", "serve"]
    # Success messaging tells the operator how to verify.
    assert "/mcp" in result.output


def test_install_claude_code_preserves_existing_servers(tmp_path: pathlib.Path) -> None:
    """Other mcpServers entries + top-level keys MUST survive the merge.
    Audit-cadence check: merge-with-existing preservation."""
    target = tmp_path / "claude.json"
    target.write_text(json.dumps({
        "mcpServers": {
            "filesystem": {"command": "npx", "args": ["fs-server"]},
            "fetch": {"command": "uvx", "args": ["mcp-fetch"]},
        },
        "topLevelKeepMe": "yes",
    }, indent=2))
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code", "--path", str(target),
    ])
    assert result.exit_code == 0, result.output
    cfg = json.loads(target.read_text())
    # ibounce added
    assert cfg["mcpServers"]["ibounce"]["command"] == "ibounce"
    # Other servers preserved verbatim
    assert cfg["mcpServers"]["filesystem"]["command"] == "npx"
    assert cfg["mcpServers"]["fetch"]["command"] == "uvx"
    # Top-level keys preserved
    assert cfg["topLevelKeepMe"] == "yes"


def test_install_claude_code_force_overwrites_existing_ibounce(
    tmp_path: pathlib.Path,
) -> None:
    target = tmp_path / "claude.json"
    target.write_text(json.dumps({
        "mcpServers": {
            "ibounce": {"command": "/old/path/ibounce", "args": ["mcp", "serve"]},
        },
    }))
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code", "--path", str(target), "--force",
    ])
    assert result.exit_code == 0, result.output
    cfg = json.loads(target.read_text())
    assert cfg["mcpServers"]["ibounce"]["command"] == "ibounce"
    assert "/old/path" not in target.read_text()
    assert "updated existing" in result.output


def test_install_claude_code_overwrite_prompt_declined_keeps_file(
    tmp_path: pathlib.Path,
) -> None:
    """Without --force, prompts on overwrite. Declining (or running in
    non-tty without --force) MUST exit non-zero AND leave file untouched."""
    target = tmp_path / "claude.json"
    original_content = json.dumps({
        "mcpServers": {
            "ibounce": {"command": "/old/path/ibounce", "args": ["mcp", "serve"]},
        },
    }, indent=2)
    target.write_text(original_content)
    runner = CliRunner()
    # Simulate "n" on the prompt.
    result = runner.invoke(
        main,
        ["mcp", "install-claude-code", "--path", str(target)],
        input="n\n",
    )
    assert result.exit_code != 0, result.output
    # File untouched.
    assert target.read_text() == original_content


def test_install_claude_code_refuses_corrupt_json(tmp_path: pathlib.Path) -> None:
    """Corrupt-JSON target MUST NOT be clobbered (atomic-write check:
    we never touch the target unless the merge is valid)."""
    target = tmp_path / "claude.json"
    target.write_text("not json {{{")
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code", "--path", str(target),
    ])
    assert result.exit_code != 0
    # Original content preserved verbatim.
    assert target.read_text() == "not json {{{"


def test_install_claude_code_atomic_no_temp_leftover(tmp_path: pathlib.Path) -> None:
    """After a successful merge, NO tempfile (.tmp suffix) is left
    behind in the parent dir. Confirms the atomic-rename path
    cleans up after itself."""
    target = tmp_path / "claude.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-claude-code", "--path", str(target),
    ])
    assert result.exit_code == 0, result.output
    leftovers = [
        p for p in target.parent.iterdir() if p.name.endswith(".tmp")
    ]
    assert leftovers == []


# ---------------------------------------------------------------------------
# install-cursor
# ---------------------------------------------------------------------------


def test_install_cursor_creates_new_config(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "cursor" / "mcp.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-cursor", "--path", str(target),
    ])
    assert result.exit_code == 0, result.output
    assert target.exists()
    cfg = json.loads(target.read_text())
    assert cfg["mcpServers"]["ibounce"]["command"] == "ibounce"
    assert cfg["mcpServers"]["ibounce"]["args"] == ["mcp", "serve"]
    # Cursor-specific verify hint surfaced.
    assert "Cursor" in result.output


def test_install_cursor_preserves_existing_servers(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "mcp.json"
    target.write_text(json.dumps({
        "mcpServers": {"other": {"command": "x"}},
    }))
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-cursor", "--path", str(target),
    ])
    assert result.exit_code == 0
    cfg = json.loads(target.read_text())
    assert "ibounce" in cfg["mcpServers"]
    assert cfg["mcpServers"]["other"]["command"] == "x"


# ---------------------------------------------------------------------------
# install-codex
# ---------------------------------------------------------------------------


def test_install_codex_without_path_prints_snippet(tmp_path: pathlib.Path) -> None:
    """No --path: print JSON snippet + manual-install guidance. Do NOT
    guess a path (Codex config locations have shifted across releases —
    auto-detect risks clobbering an unrelated file)."""
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "install-codex"])
    assert result.exit_code == 0, result.output
    # Snippet is printed.
    assert '"command": "ibounce"' in result.output
    assert '"mcp"' in result.output
    assert '"serve"' in result.output
    # Manual-install guidance is present.
    assert "Paste" in result.output or "paste" in result.output
    assert "--path" in result.output


def test_install_codex_with_path_merges_atomically(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "codex" / "mcp.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "mcp", "install-codex", "--path", str(target), "--force",
    ])
    assert result.exit_code == 0, result.output
    assert target.exists()
    cfg = json.loads(target.read_text())
    assert cfg["mcpServers"]["ibounce"]["command"] == "ibounce"


# ---------------------------------------------------------------------------
# Snippet schema validation — the JSON we emit must match the shape
# every MCP client documents (mcpServers.<name>.command + .args).
# ---------------------------------------------------------------------------


def test_emitted_snippet_matches_mcp_client_schema() -> None:
    """The snippet ibounce writes / shows must be loadable by any
    standard MCP client. Validates the minimal shape every documented
    MCP client (Claude Code, Cursor, Codex) accepts: top-level
    mcpServers map → per-server object with `command` (string) and
    `args` (list of strings)."""
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "show-config"])
    assert result.exit_code == 0
    cfg = json.loads(result.output.split("\nWire it up:", 1)[0])
    assert isinstance(cfg, dict)
    assert "mcpServers" in cfg and isinstance(cfg["mcpServers"], dict)
    for name, entry in cfg["mcpServers"].items():
        assert isinstance(name, str) and name
        assert isinstance(entry, dict)
        assert isinstance(entry.get("command"), str) and entry["command"]
        assert isinstance(entry.get("args"), list)
        for arg in entry["args"]:
            assert isinstance(arg, str)
        # env is optional in the spec but, if present, must be a string map.
        if "env" in entry:
            assert isinstance(entry["env"], dict)
            for k, v in entry["env"].items():
                assert isinstance(k, str) and isinstance(v, str)
