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


# =====================================================================
# bouncer_active_mode + bouncer_recommend_mode_for_task
#
# Mirrors kbouncer/internal/mcp/server_test.go cases (TestActiveMode_*,
# TestRecommendModeForTask_*) per [[cross-product-agent-parity]].
# Both tools are DETERMINISTIC — no LLM, no network calls.
# Fail-safe direction = cooperative (lean-permissive default,
# matching kbounce's `mode = proxy.ModeCooperative` initializer).
# =====================================================================


def _call_tool(name: str, arguments: dict[str, object] | None = None) -> dict:
    """Helper: invoke a tool via the JSON-RPC dispatch + return the
    structuredContent payload (the parsed dict, not the text blob)."""
    resp = _handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    })
    assert resp is not None
    assert "result" in resp, resp
    return resp["result"]["structuredContent"]


def test_bouncer_active_mode_registered_in_tools_list():
    names = {t["name"] for t in TOOLS}
    assert "bouncer_active_mode" in names
    assert "ibounce_active_mode" in names  # dual-aliased


def test_bouncer_recommend_mode_for_task_registered_in_tools_list():
    names = {t["name"] for t in TOOLS}
    assert "bouncer_recommend_mode_for_task" in names
    assert "ibounce_recommend_mode_for_task" in names  # dual-aliased


def test_bouncer_active_mode_returns_default(monkeypatch):
    """No env var, no session override -> cooperative + source=default.
    Matches kbounce's `mode = proxy.ModeCooperative` lean-permissive
    default per [[safety-mode-lean-permissive]]."""
    from iam_jit.bouncer import proxy as proxy_mod

    monkeypatch.delenv("IAM_JIT_BOUNCER_MODE", raising=False)
    proxy_mod.set_session_mode_override(None)
    got = _call_tool("bouncer_active_mode")
    assert got == {"mode": "cooperative", "source": "default"}


def test_bouncer_active_mode_returns_env_value(monkeypatch):
    """IAM_JIT_BOUNCER_MODE=transparent -> transparent + source=env."""
    from iam_jit.bouncer import proxy as proxy_mod

    proxy_mod.set_session_mode_override(None)
    monkeypatch.setenv("IAM_JIT_BOUNCER_MODE", "transparent")
    got = _call_tool("bouncer_active_mode")
    assert got["mode"] == "transparent"
    assert got["source"] == "env"


def test_bouncer_active_mode_env_off_value(monkeypatch):
    """`off` is a valid env value (mirrors kbounce's mode enum)."""
    from iam_jit.bouncer import proxy as proxy_mod

    proxy_mod.set_session_mode_override(None)
    monkeypatch.setenv("IAM_JIT_BOUNCER_MODE", "off")
    got = _call_tool("bouncer_active_mode")
    assert got == {"mode": "off", "source": "env"}


def test_bouncer_active_mode_typo_env_falls_back_to_default(monkeypatch):
    """Defensive: a typo'd env value MUST NOT crash the MCP server;
    falls back to cooperative + source=default."""
    from iam_jit.bouncer import proxy as proxy_mod

    proxy_mod.set_session_mode_override(None)
    monkeypatch.setenv("IAM_JIT_BOUNCER_MODE", "transpaernt")  # typo
    got = _call_tool("bouncer_active_mode")
    assert got == {"mode": "cooperative", "source": "default"}


def test_bouncer_active_mode_session_override_wins(monkeypatch):
    """Session override beats env var (in-process explicit decision
    > deployment-default env). Mirrors kbounce's behaviour where the
    proxy's bound mode (set at `kbouncer run --mode ...`) wins over
    later env mutations."""
    from iam_jit.bouncer import proxy as proxy_mod

    monkeypatch.setenv("IAM_JIT_BOUNCER_MODE", "transparent")
    proxy_mod.set_session_mode_override("cooperative")
    try:
        got = _call_tool("bouncer_active_mode")
        assert got == {"mode": "cooperative", "source": "session_override"}
    finally:
        proxy_mod.set_session_mode_override(None)


def test_ibounce_active_mode_alias_dispatches_to_same_handler(monkeypatch):
    """ibounce_* alias must produce the same payload as bouncer_*
    per [[cross-product-agent-parity]] + the existing dual-alias loop."""
    from iam_jit.bouncer import proxy as proxy_mod

    proxy_mod.set_session_mode_override(None)
    monkeypatch.setenv("IAM_JIT_BOUNCER_MODE", "transparent")
    via_legacy = _call_tool("bouncer_active_mode")
    via_canonical = _call_tool("ibounce_active_mode")
    assert via_legacy == via_canonical


def test_bouncer_recommend_mode_for_destroy_task():
    """Task description with destructive verb on a high-risk service
    (iam) -> transparent. Mirrors kbounce's
    TestRecommendModeForTask_ProdWritesReturnsTransparent shape."""
    got = _call_tool(
        "bouncer_recommend_mode_for_task",
        {"task_description": "delete the iam role for the old app"},
    )
    assert got["mode"] == "transparent"
    assert got["deterministic"] is True
    assert got["confidence"] == "high"


def test_bouncer_recommend_mode_for_prod_write():
    """targets_prod=true AND write verb -> transparent regardless
    of service riskiness. Mirrors kbounce's prodNS && hasWrites case."""
    got = _call_tool(
        "bouncer_recommend_mode_for_task",
        {
            "task_description": "delete s3 bucket prod-data",
            "targets_prod": True,
        },
    )
    assert got["mode"] == "transparent"
    assert got["deterministic"] is True


def test_bouncer_recommend_mode_for_read_task():
    """Read-only task -> cooperative."""
    got = _call_tool(
        "bouncer_recommend_mode_for_task",
        {"task_description": "list buckets in us-east-1"},
    )
    assert got["mode"] == "cooperative"
    assert got["deterministic"] is True
    assert got["confidence"] == "high"


def test_bouncer_recommend_mode_for_read_actions():
    """Explicit AWS actions, all reads -> cooperative."""
    got = _call_tool(
        "bouncer_recommend_mode_for_task",
        {"actions": ["s3:GetObject", "s3:ListBucket", "ec2:DescribeInstances"]},
    )
    assert got["mode"] == "cooperative"


def test_bouncer_recommend_mode_for_unknown_task():
    """Ambiguous task (no recognized verb, no actions) -> cooperative
    + confidence=low. Fail-safe direction matches kbounce's
    `mode = proxy.ModeCooperative` initializer per
    [[safety-mode-lean-permissive]]."""
    got = _call_tool(
        "bouncer_recommend_mode_for_task",
        {"task_description": "do stuff with EC2"},
    )
    assert got["mode"] == "cooperative"
    assert got["confidence"] == "low"
    assert got["deterministic"] is True


def test_bouncer_recommend_mode_empty_input_is_low_confidence():
    """Zero-signal input -> cooperative + confidence=low (don't crash;
    don't pretend to know)."""
    got = _call_tool("bouncer_recommend_mode_for_task", {})
    assert got["mode"] == "cooperative"
    assert got["confidence"] == "low"


def test_bouncer_recommend_mode_audit_only_overrides_prod_writes():
    """wants_audit_only=true forces cooperative even on prod-write +
    high-risk-service tasks. Mirrors kbounce's
    TestRecommendModeForTask_AuditOnlyAlwaysCooperative."""
    got = _call_tool(
        "bouncer_recommend_mode_for_task",
        {
            "task_description": "delete iam role in prod",
            "targets_prod": True,
            "wants_audit_only": True,
        },
    )
    assert got["mode"] == "cooperative"


def test_bouncer_recommend_mode_high_risk_iam_write_action():
    """Explicit iam:DeleteRole action -> transparent (high-risk
    service + write). Confirms the action-classification path
    separate from the keyword path."""
    got = _call_tool(
        "bouncer_recommend_mode_for_task",
        {"actions": ["iam:DeleteRole"]},
    )
    assert got["mode"] == "transparent"


def test_bouncer_recommend_mode_non_prod_low_risk_write():
    """Write verb on a non-prod, non-high-risk target -> cooperative
    (lean-permissive; covered by audit + admin pause). Mirrors
    kbounce's `case hasWrites: reason = cooperative...lean-permissive`."""
    got = _call_tool(
        "bouncer_recommend_mode_for_task",
        {"task_description": "create a new s3 bucket for dev testing"},
    )
    assert got["mode"] == "cooperative"


def test_bouncer_recommend_mode_invalid_actions_type_returns_error():
    """Defensive: non-list `actions` -> error payload, not a crash."""
    got = _call_tool(
        "bouncer_recommend_mode_for_task",
        {"actions": "s3:GetObject"},  # string, not list
    )
    assert "error" in got


def test_ibounce_recommend_mode_alias_matches_bouncer():
    """ibounce_recommend_mode_for_task produces the same payload as
    bouncer_recommend_mode_for_task — proves dual-aliasing wired up."""
    args = {"task_description": "delete iam role"}
    via_legacy = _call_tool("bouncer_recommend_mode_for_task", args)
    via_canonical = _call_tool("ibounce_recommend_mode_for_task", args)
    assert via_legacy == via_canonical
