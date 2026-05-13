"""Tests for the MCP server's JSON-RPC dispatch.

The MCP transport is stdio + line-delimited JSON-RPC 2.0. These
tests exercise the dispatch layer directly (not through stdin/stdout)
since the round-tripping of bytes is trivial; the interesting logic
is in `_handle_request`.
"""

from __future__ import annotations

import json

from iam_jit.mcp_server import (
    MCP_PROTOCOL_VERSION,
    SERVER_NAME,
    SERVER_VERSION,
    TOOLS,
    _handle_request,
)


def test_initialize_returns_protocol_version():
    resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {},
    })
    assert resp is not None
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    result = resp["result"]
    assert result["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert result["serverInfo"]["name"] == SERVER_NAME
    assert result["serverInfo"]["version"] == SERVER_VERSION
    assert "tools" in result["capabilities"]


def test_tools_list_returns_generate_policy():
    resp = _handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tool_names = [t["name"] for t in resp["result"]["tools"]]
    assert "generate_iam_policy" in tool_names


def test_tools_call_generate_iam_policy_round_trips():
    resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "generate_iam_policy",
            "arguments": {
                "task": "read S3 from the prod-data bucket",
                "account_id": "123456789012",
                "region": "us-east-1",
            },
        },
    })
    assert "result" in resp
    content = resp["result"]["content"]
    assert len(content) == 1
    payload = json.loads(content[0]["text"])
    assert payload["policy"] is not None
    assert payload["scored_risk"] is not None
    assert payload["scored_risk"] <= 4
    # Structured content also populated
    sc = resp["result"]["structuredContent"]
    assert sc["policy"] == payload["policy"]


def test_tools_call_unknown_tool_returns_error():
    resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "nonexistent_tool", "arguments": {}},
    })
    assert "error" in resp
    assert resp["error"]["code"] == -32601


def test_unknown_method_returns_error():
    resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "no_such_method",
    })
    assert "error" in resp


def test_notification_returns_none():
    """JSON-RPC notifications (no `id`) get no response."""
    resp = _handle_request({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })
    assert resp is None


def test_missing_task_returns_error_payload():
    resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "generate_iam_policy",
            "arguments": {},  # missing task
        },
    })
    # The result still comes back as a tools/call response, but the
    # nested payload has the error.
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert "error" in payload
    assert payload["policy"] is None


def test_refinement_args_round_trip():
    """exclude_actions and rationale flow through to GenerationResult."""
    resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "generate_iam_policy",
            "arguments": {
                "task": "deploy lambda function api with role app-role",
                "account_id": "123456789012",
                "region": "us-east-1",
                "exclude_actions": ["iam:PassRole"],
                "rationale": "code-only deploy",
            },
        },
    })
    payload = resp["result"]["structuredContent"]
    assert payload["policy"] is not None
    # PassRole should be absent from the output
    all_actions = []
    for s in payload["policy"]["Statement"]:
        a = s["Action"]
        if isinstance(a, list):
            all_actions.extend(a)
        else:
            all_actions.append(a)
    assert "iam:PassRole" not in all_actions
    # Rationale flows into reasons
    assert any("code-only deploy" in r for r in payload["reasons"])


def test_tools_list_schema_well_formed():
    """The tool schema is valid JSON Schema with required `task` field."""
    tool = next(t for t in TOOLS if t["name"] == "generate_iam_policy")
    assert tool["inputSchema"]["type"] == "object"
    assert "task" in tool["inputSchema"]["required"]
    assert tool["inputSchema"]["properties"]["bias"]["enum"] == ["allow", "deny"]
