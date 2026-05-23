"""#398 — MCP-tool surface (`iam_jit_setup_from_config`) tests.

Targets the MCP-handler shim `apply_config_for_mcp` directly. Full
MCP-protocol smoke is covered in mcp-server integration tests.
"""

from __future__ import annotations

import pathlib

from iam_jit.cli_apply_config import apply_config_for_mcp


def test_mcp_setup_inline_dict_dry_run() -> None:
    decl = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
        }
    }
    out = apply_config_for_mcp({
        "declaration": decl,
        "dry_run": True,
    })
    assert out["status"] == "ok"
    assert out["dry_run"] is True
    assert isinstance(out["bouncers_planned"], list)


def test_mcp_setup_inspect_returns_validated_shape() -> None:
    decl = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {"ibounce": {"enabled": True}},
        }
    }
    out = apply_config_for_mcp({
        "declaration": decl,
        "inspect": True,
    })
    assert out["status"] == "ok"
    assert out["validated"] is True
    assert out["declaration"]["iam-jit"]["enabled"] is True


def test_mcp_setup_invalid_declaration_returns_structured_error() -> None:
    decl = {"iam-jit": {"enabled": "maybe"}}  # not a boolean
    out = apply_config_for_mcp({"declaration": decl, "inspect": True})
    assert out["status"] == "error"
    assert out["code"] == "schema_validation_error"
    assert "errors" in out["details"]


def test_mcp_setup_path_input(tmp_path: pathlib.Path) -> None:
    p = tmp_path / ".iam-jit.yaml"
    p.write_text("iam-jit:\n  enabled: true\n")
    out = apply_config_for_mcp({
        "declaration": str(p),
        "dry_run": True,
    })
    assert out["status"] == "ok"


def test_mcp_setup_autodiscover(tmp_path: pathlib.Path) -> None:
    (tmp_path / ".iam-jit.yaml").write_text(
        "iam-jit:\n  enabled: true\n"
    )
    out = apply_config_for_mcp({
        "cwd": str(tmp_path),
        "dry_run": True,
    })
    assert out["status"] == "ok"


def test_mcp_setup_no_declaration_anywhere(tmp_path: pathlib.Path) -> None:
    out = apply_config_for_mcp({
        "cwd": str(tmp_path),
        "dry_run": True,
    })
    assert out["status"] == "error"
    assert out["code"] == "no_declaration_found"


def test_mcp_tool_listed_in_tools_array() -> None:
    """`iam_jit_setup_from_config` must be in the MCP TOOLS list so
    the agent can discover it via tools/list."""
    from iam_jit.mcp_server import TOOLS

    names = {t["name"] for t in TOOLS}
    assert "iam_jit_setup_from_config" in names


def test_mcp_tool_input_schema_documents_dry_run() -> None:
    from iam_jit.mcp_server import TOOLS

    tool = next(t for t in TOOLS if t["name"] == "iam_jit_setup_from_config")
    props = tool["inputSchema"]["properties"]
    assert "declaration" in props
    assert "dry_run" in props
    assert "inspect" in props


def test_mcp_setup_phase_b_warning_surfaces() -> None:
    decl = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {"ibounce": {"enabled": True}},
            "improve": {"enabled": True},
        }
    }
    out = apply_config_for_mcp({
        "declaration": decl,
        "dry_run": True,
    })
    joined = " ".join(out["warnings"])
    assert "Phase B" in joined or "#401" in joined
