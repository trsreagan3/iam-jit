"""MCP-tool test for `list_audit_webhook_presets` (#259).

Confirms the agent-facing surface enumerates the same four presets
the CLI ships + returns a stable JSON shape suitable for cross-product
orchestration.
"""

from __future__ import annotations

from iam_jit.mcp_server import TOOLS, _handle_request


def _call_tool(name: str, arguments: dict | None = None) -> dict:
    resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    })
    assert resp is not None
    assert "result" in resp, resp
    return resp["result"]["structuredContent"]


def test_list_audit_webhook_presets_registered_in_tools_list() -> None:
    names = {t["name"] for t in TOOLS}
    assert "list_audit_webhook_presets" in names


def test_list_audit_webhook_presets_returns_four_presets() -> None:
    result = _call_tool("list_audit_webhook_presets")
    assert "presets" in result
    names = [p["name"] for p in result["presets"]]
    assert names == ["generic", "datadog", "splunk-hec", "sentinel"]


def test_each_preset_carries_required_descriptor_fields() -> None:
    result = _call_tool("list_audit_webhook_presets")
    for preset in result["presets"]:
        for field in (
            "description", "auth_header", "body_shape",
            "required_flags", "optional_flags",
        ):
            assert field in preset, f"preset {preset['name']!r} missing {field}"
        assert "--audit-webhook-url" in preset["required_flags"]
        assert "--audit-webhook-token" in preset["required_flags"]


def test_descriptor_carries_no_token_or_secret() -> None:
    """Per [[security-team-audit-export]] + [[self-host-zero-billing-
    dependency]]: the descriptor lists ONLY shape metadata. No real
    token, no real URL, no per-account context."""
    result = _call_tool("list_audit_webhook_presets")
    payload = repr(result).lower()
    # Forbidden: actual secret values, NOT header NAMES (descriptors
    # legitimately document the literal header `DD-API-KEY: <api_key>`).
    for bad in (
        "bearer abc", "password=", "secret=",
        "dd_api_key=", "splunk_token=", "shared_key=",
    ):
        assert bad not in payload, f"unexpected literal {bad!r} in descriptor"
