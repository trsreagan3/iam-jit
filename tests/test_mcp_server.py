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


def test_tools_call_generate_iam_policy_returns_tombstone():
    """Stage 3 of [[no-nl-synthesis]] (0.4.0): generate_iam_policy
    is a tombstone. Round-trip succeeds, but the response is the
    deprecation block + null policy + replacement_tools pointer."""
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
    # Tombstone: null policy + deprecation block + error string
    assert payload["policy"] is None
    assert "deprecation" in payload
    assert "0.4.0" in payload["deprecation"]["removed_in"]
    assert "list_templates" in payload["deprecation"]["replacement_tools"]
    # Structured content matches
    sc = resp["result"]["structuredContent"]
    assert sc["policy"] is None


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


def test_refinement_args_ignored_by_tombstone():
    """Stage 3 of [[no-nl-synthesis]] (0.4.0): refinement args
    (exclude_actions, rationale, etc.) used to flow through to
    GenerationResult. Now the tombstone ignores them and returns
    the same null-policy response regardless of input."""
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
    assert payload["policy"] is None
    assert "deprecation" in payload


def test_tools_list_schema_well_formed():
    """The tombstoned tool's schema is preserved for back-compat
    discovery (agents that cached the old name find it + read the
    DEPRECATED description). Schema still validates as JSON Schema."""
    tool = next(t for t in TOOLS if t["name"] == "generate_iam_policy")
    assert tool["inputSchema"]["type"] == "object"
    # Per Stage 3, the schema was trimmed when the tool became a
    # tombstone — required `task` field and `bias` enum no longer
    # apply; the tool returns the same tombstone regardless of args.
    # The schema being well-formed (i.e. a valid type:object) is
    # what tools/list needs.
