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


# ---------------------------------------------------------------------------
# #561 — MCP tool schema MUST document `rollback_on_failure` so operators
# can opt out of B6 transactional rollback via the canonical MCP surface
# (not just the Python API).
# ---------------------------------------------------------------------------


def test_mcp_tool_input_schema_documents_rollback_on_failure() -> None:
    """#561: the MCP tool schema must expose `rollback_on_failure` so
    agents discover it via tools/list. Before this fix, operators
    could only opt out of #538 transactional rollback by importing
    `apply_declaration` directly in Python — not via the canonical
    MCP interface."""
    from iam_jit.mcp_server import TOOLS

    tool = next(t for t in TOOLS if t["name"] == "iam_jit_setup_from_config")
    props = tool["inputSchema"]["properties"]
    assert "rollback_on_failure" in props, (
        f"iam_jit_setup_from_config inputSchema missing "
        f"rollback_on_failure parameter; operators cannot opt out via "
        f"MCP. Properties: {sorted(props.keys())!r}"
    )
    rof = props["rollback_on_failure"]
    assert rof["type"] == "boolean", (
        f"rollback_on_failure should be boolean; got {rof['type']!r}"
    )
    assert rof["default"] is True, (
        f"rollback_on_failure default MUST be True to preserve B6 "
        f"transactional behavior for callers that don't pass it; "
        f"got default={rof.get('default')!r}"
    )
    # Operator-actionable description: must explain consequences.
    desc = rof.get("description", "")
    assert "#538" in desc or "rollback" in desc.lower(), (
        f"rollback_on_failure description doesn't explain what it "
        f"does: {desc!r}"
    )


def test_mcp_dispatch_passes_rollback_on_failure_to_apply_declaration(
    monkeypatch,
) -> None:
    """#561: when an MCP caller passes rollback_on_failure=False, the
    flag MUST flow through `apply_config_for_mcp` → `apply_declaration`.
    Before this fix the kwarg was silently dropped — apply_declaration
    always got the True default regardless of what the operator
    passed via MCP."""
    captured: dict = {}

    def _fake_apply_declaration(declaration, **kwargs):
        captured["kwargs"] = kwargs
        # Build a minimal SetupResult-shaped return for as_dict().
        from iam_jit.ambient_config.setup import SetupResult
        return SetupResult(
            dry_run=False,
            declaration_source=kwargs.get("source", "<test>"),
        )

    import iam_jit.cli_apply_config as cli_apply
    monkeypatch.setattr(cli_apply, "apply_declaration", _fake_apply_declaration)

    decl = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {"ibounce": {"enabled": True, "mode": "discovery"}},
        }
    }

    # Case 1: explicit opt-out flows through.
    apply_config_for_mcp({
        "declaration": decl,
        "rollback_on_failure": False,
    })
    assert captured["kwargs"].get("rollback_on_failure") is False, (
        f"MCP caller passed rollback_on_failure=False but it did NOT "
        f"reach apply_declaration; kwargs={captured['kwargs']!r}"
    )

    # Case 2: omitted defaults to True (preserves B6 behavior).
    captured.clear()
    apply_config_for_mcp({
        "declaration": decl,
    })
    assert captured["kwargs"].get("rollback_on_failure") is True, (
        f"MCP caller omitted rollback_on_failure; default should be "
        f"True to preserve B6 transactional behavior. Got "
        f"kwargs={captured['kwargs']!r}"
    )

    # Case 3: explicit True also flows through.
    captured.clear()
    apply_config_for_mcp({
        "declaration": decl,
        "rollback_on_failure": True,
    })
    assert captured["kwargs"].get("rollback_on_failure") is True


def test_mcp_dispatch_rollback_on_failure_ignored_for_dry_run(monkeypatch) -> None:
    """Backstop: dry_run uses plan_declaration which has no
    rollback_on_failure parameter. The MCP dispatch must NOT crash
    when rollback_on_failure is supplied alongside dry_run=True."""
    out = apply_config_for_mcp({
        "declaration": {
            "iam-jit": {
                "enabled": True,
                "bouncers": {"ibounce": {"enabled": True}},
            }
        },
        "dry_run": True,
        "rollback_on_failure": False,
    })
    assert out["status"] == "ok", (
        f"dry_run + rollback_on_failure crashed: {out!r}"
    )
