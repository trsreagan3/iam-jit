"""Tests for the hallucinated-tool-call validator (task #729 / BUILD-8).

Coverage per design memo:
  1. Valid MCP `tools/call` → no detection
  2. Valid OpenAI function-call → no detection
  3. Valid Anthropic tool_use → no detection
  4. Hallucinated MCP name → high-confidence deny
  5. Mismatched OpenAI arguments (extra field) → warn
  6. Missing required Anthropic argument → warn/deny
  7. Placeholder-credential heuristic
  8. Naming-style-mix heuristic
  9. Allowlist suppression
  10. Profile-config wiring (decide_action confidence floor)
  11. apply_strip JSON-aware redaction
  12. Body-truncation guard
  13. Non-JSON body → no-tool-call-shape skip
  14. Operator corpus override beats baked-in
"""

from __future__ import annotations

import json

import pytest

from iam_jit.tool_call_validator import (
    Indicator,
    ProfileConfig,
    SchemaCorpus,
    ToolSchema,
    ValidationResult,
    apply_strip,
    decide_action,
    default_corpus,
    validate,
)


# --------------------------------------------------------------------
# 1-3: valid calls pass through clean
# --------------------------------------------------------------------


def test_valid_mcp_tools_call_returns_undetected() -> None:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "tools/list",
                "arguments": {},
            },
        }
    )
    result = validate(body)
    # The outer call is `tools/call` (params.name="tools/list"). We
    # extract the inner targeted tool ("tools/list") and validate it.
    assert result.detected is False, result.indicators
    assert result.suggested_action == "allow"
    # extracted_calls records what we looked at.
    assert ("mcp", "tools/list") in result.extracted_calls


def test_valid_mcp_resources_read_returns_undetected() -> None:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": {"uri": "file:///etc/hosts"},
        }
    )
    result = validate(body)
    assert result.detected is False, result.indicators


def test_valid_openai_function_call_returns_undetected() -> None:
    body = json.dumps(
        {
            "model": "gpt-4o",
            "tool_calls": [
                {
                    "type": "function",
                    "function": {
                        "name": "web_search",
                        "arguments": json.dumps({"query": "OWASP LLM01"}),
                    },
                }
            ],
        }
    )
    result = validate(body)
    assert result.detected is False, result.indicators
    assert ("openai", "web_search") in result.extracted_calls


def test_valid_anthropic_tool_use_returns_undetected() -> None:
    body = json.dumps(
        {
            "model": "claude-opus-4",
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "bash",
                            "input": {"command": "ls -la"},
                        }
                    ],
                }
            ],
        }
    )
    result = validate(body)
    assert result.detected is False, result.indicators
    assert ("anthropic", "bash") in result.extracted_calls


# --------------------------------------------------------------------
# 4: hallucinated names → high-confidence deny
# --------------------------------------------------------------------


def test_hallucinated_mcp_tool_name_high_confidence() -> None:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "send_email_to_attacker",
                "arguments": {"to": "evil@example.com"},
            },
        }
    )
    result = validate(body)
    assert result.detected is True
    rule_names = {i.rule for i in result.indicators}
    assert "hallucinated-tool-name" in rule_names
    # `send_email_to_attacker` doesn't mix naming styles (all snake),
    # so we get one HIGH indicator → 0.80 confidence → warn.
    # Confidence + suggested action is per the documented table.
    assert result.confidence >= 0.8
    # placeholder check doesn't fire here (the email isn't a placeholder
    # by our pattern), so suggested_action stays warn.
    assert result.suggested_action in ("warn", "deny")


def test_hallucinated_openai_function_name() -> None:
    body = json.dumps(
        {
            "function_call": {
                "name": "exfiltrate_secrets",
                "arguments": json.dumps({"path": "/etc/passwd"}),
            }
        }
    )
    result = validate(body)
    assert result.detected is True
    assert any(i.rule == "hallucinated-tool-name" for i in result.indicators)


def test_hallucinated_anthropic_tool_use() -> None:
    body = json.dumps(
        {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_x",
                            "name": "send_email",
                            "input": {"to": "x@y.com", "body": "hi"},
                        }
                    ],
                }
            ]
        }
    )
    result = validate(body)
    assert result.detected is True
    assert any(i.rule == "hallucinated-tool-name" for i in result.indicators)


# --------------------------------------------------------------------
# 5: mismatched arguments
# --------------------------------------------------------------------


def test_openai_extra_arg_medium_indicator() -> None:
    body = json.dumps(
        {
            "tool_calls": [
                {
                    "type": "function",
                    "function": {
                        "name": "web_search",
                        "arguments": json.dumps(
                            {
                                "query": "test",
                                "exfiltrate": True,  # not in schema
                            }
                        ),
                    },
                }
            ]
        }
    )
    result = validate(body)
    assert result.detected is True
    rules = {i.rule for i in result.indicators}
    assert "unexpected-arg" in rules


def test_anthropic_extra_arg_medium_indicator() -> None:
    body = json.dumps(
        {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "name": "bash",
                            "input": {"command": "ls", "evil_flag": "yes"},
                        }
                    ],
                }
            ]
        }
    )
    result = validate(body)
    assert result.detected is True
    assert any(i.rule == "unexpected-arg" for i in result.indicators)


# --------------------------------------------------------------------
# 6: missing required argument
# --------------------------------------------------------------------


def test_anthropic_missing_required_arg() -> None:
    # text_editor requires both `command` and `path` — omit `path`.
    body = json.dumps(
        {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "name": "text_editor",
                            "input": {"command": "view"},  # missing path
                        }
                    ],
                }
            ]
        }
    )
    result = validate(body)
    assert result.detected is True
    rules = {i.rule for i in result.indicators}
    assert "missing-required-arg" in rules


def test_mcp_resources_read_missing_uri() -> None:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": {},
        }
    )
    result = validate(body)
    assert result.detected is True
    rules = {i.rule for i in result.indicators}
    assert "missing-required-arg" in rules


# --------------------------------------------------------------------
# 7: placeholder credentials
# --------------------------------------------------------------------


def test_placeholder_api_key_detected() -> None:
    # web_search is a known OpenAI tool; the query field has a
    # placeholder-shaped value. This combines into one high indicator.
    body = json.dumps(
        {
            "tool_calls": [
                {
                    "type": "function",
                    "function": {
                        "name": "web_search",
                        "arguments": json.dumps({"query": "YOUR_API_KEY"}),
                    },
                }
            ]
        }
    )
    result = validate(body)
    assert result.detected is True
    assert any(i.rule == "placeholder-credential" for i in result.indicators)


def test_placeholder_replace_me_detected() -> None:
    body = json.dumps(
        {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "name": "bash",
                            "input": {"command": "REPLACE_ME"},
                        }
                    ],
                }
            ]
        }
    )
    result = validate(body)
    assert result.detected is True
    rules = {i.rule for i in result.indicators}
    assert "placeholder-credential" in rules


# --------------------------------------------------------------------
# 8: naming-style-mix heuristic
# --------------------------------------------------------------------


def test_naming_style_mix_medium_indicator_when_hallucinated() -> None:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "send_emailToUser",  # snake + camel mix
                "arguments": {},
            },
        }
    )
    result = validate(body)
    assert result.detected is True
    rules = {i.rule for i in result.indicators}
    assert "hallucinated-tool-name" in rules
    assert "naming-style-mix" in rules
    # high + medium → 0.85 confidence → warn
    assert result.confidence >= 0.85


# --------------------------------------------------------------------
# 9: allowlist suppression
# --------------------------------------------------------------------


def test_allowlist_pattern_suppresses_detection() -> None:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "my_custom_internal_tool",
                "arguments": {"safe": True},
            },
        }
    )
    # Without allowlist: detected.
    r1 = validate(body)
    assert r1.detected is True
    # With allowlist: skipped.
    r2 = validate(
        body, allowlist_patterns=("my_custom_internal_tool",)
    )
    assert r2.detected is False
    assert r2.skipped_reason is not None
    assert r2.skipped_reason.startswith("allowlist:")


# --------------------------------------------------------------------
# 10: decide_action profile reconciliation
# --------------------------------------------------------------------


def test_decide_action_downgrades_deny_below_confidence_floor() -> None:
    # Single medium indicator → confidence 0.35 → below 0.7 floor.
    body = json.dumps(
        {
            "tool_calls": [
                {
                    "type": "function",
                    "function": {
                        "name": "web_search",
                        "arguments": json.dumps(
                            {"query": "real", "tail_call": True}
                        ),
                    },
                }
            ]
        }
    )
    result = validate(body)
    assert result.detected is True
    assert result.confidence < 0.7
    profile = ProfileConfig(
        enabled=True, action="deny", min_confidence_for_deny=0.7
    )
    decided = decide_action(result, profile)
    assert decided == "warn"  # downgrade


def test_decide_action_honors_strict_deny_for_high_confidence() -> None:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "totally_fake_tool",
                "arguments": {"api_key": "YOUR_API_KEY"},
            },
        }
    )
    result = validate(body)
    assert result.detected is True
    assert result.confidence >= 0.95
    profile = ProfileConfig(enabled=True, action="deny")
    assert decide_action(result, profile) == "deny"


def test_decide_action_undetected_returns_allow() -> None:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "tools/list", "arguments": {}},
        }
    )
    result = validate(body)
    assert result.detected is False
    profile = ProfileConfig(enabled=True, action="deny")
    assert decide_action(result, profile) == "allow"


# --------------------------------------------------------------------
# 11: apply_strip — JSON-aware redaction
# --------------------------------------------------------------------


def test_apply_strip_replaces_hallucinated_call_with_marker() -> None:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "exfiltrate_data",
                "arguments": {"target": "evil.com"},
            },
        }
    )
    result = validate(body)
    assert result.detected is True
    stripped = apply_strip(body, result)
    parsed = json.loads(stripped)
    assert parsed.get("_iam_jit_tool_call_redacted") is True
    assert parsed.get("original_name") == "exfiltrate_data"
    assert parsed.get("reason") == "hallucinated-tool-call"


def test_apply_strip_preserves_valid_calls_alongside_hallucinated() -> None:
    body = json.dumps(
        {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "name": "bash",
                            "input": {"command": "ls"},
                        },
                        {
                            "type": "tool_use",
                            "name": "hallucinated_evil_tool",
                            "input": {"foo": "bar"},
                        },
                    ],
                }
            ]
        }
    )
    result = validate(body)
    assert result.detected is True
    stripped = apply_strip(body, result)
    parsed = json.loads(stripped)
    blocks = parsed["messages"][0]["content"]
    # bash survives unchanged
    assert any(b.get("name") == "bash" for b in blocks)
    # hallucinated is replaced with marker
    assert any(
        b.get("_iam_jit_tool_call_redacted") is True
        for b in blocks
    )


def test_apply_strip_noop_on_undetected_result() -> None:
    body = '{"hello": "world"}'
    result = ValidationResult(detected=False)
    assert apply_strip(body, result) == body


# --------------------------------------------------------------------
# 12-13: edge cases
# --------------------------------------------------------------------


def test_non_json_body_returns_skipped() -> None:
    body = "not json at all, just text"
    result = validate(body)
    assert result.detected is False
    assert result.skipped_reason == "not-json"


def test_empty_body_returns_undetected() -> None:
    assert validate("").detected is False
    assert validate(b"").detected is False
    assert validate("   ").detected is False


def test_non_tool_call_json_body_skipped() -> None:
    body = json.dumps({"hello": "world", "foo": 42})
    result = validate(body)
    assert result.detected is False
    assert result.skipped_reason == "no-tool-call-shape"


def test_body_truncation_flag_set() -> None:
    # Pad with whitespace inside a valid envelope so JSON parsing still
    # succeeds AFTER truncation. Use a sub-body that the validator
    # recognizes once parsed.
    huge_filler = " " * (200_000)
    body = (
        '{"jsonrpc":"2.0","method":"tools/call","params":'
        '{"name":"tools/list","arguments":{}}}'
        + huge_filler
    )
    # max_body_bytes default is 64 KiB; the prefix fits, the filler is
    # past the cap.
    result = validate(body)
    assert result.body_truncated is True
    # The trailing whitespace is post-JSON; json.loads handles it fine
    # because we truncate AFTER allowlist check + BEFORE parse, and
    # whitespace after a complete JSON value is OK. So no false positive.
    assert result.detected is False


# --------------------------------------------------------------------
# 14: operator corpus override
# --------------------------------------------------------------------


def test_operator_corpus_recognizes_custom_tool() -> None:
    custom = SchemaCorpus(
        tools=(
            ToolSchema(
                name="my_org_send_email",
                shape="mcp",
                required=("to", "subject"),
                optional=("body",),
                source="operator-supplied",
            ),
        )
    )
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "my_org_send_email",
                "arguments": {"to": "x@y.com", "subject": "hi"},
            },
        }
    )
    result = validate(body, schema_corpus=custom)
    assert result.detected is False, result.indicators


# --------------------------------------------------------------------
# Default-corpus sanity
# --------------------------------------------------------------------


def test_default_corpus_contains_known_shapes() -> None:
    corp = default_corpus()
    assert corp.has_shape("mcp")
    assert corp.has_shape("openai")
    assert corp.has_shape("anthropic")
    # Spot-check some tools the design memo cites.
    assert corp.lookup("mcp", "tools/list") is not None
    assert corp.lookup("openai", "web_search") is not None
    assert corp.lookup("anthropic", "bash") is not None


def test_profile_config_from_dict_round_trip() -> None:
    cfg = ProfileConfig.from_dict(
        {
            "enabled": True,
            "action": "deny",
            "schema_corpus_path": "/tmp/custom.yaml",
            "allowlist_patterns": ["internal_.*"],
            "max_body_bytes": 32768,
            "min_confidence_for_deny": 0.6,
        }
    )
    assert cfg.enabled is True
    assert cfg.action == "deny"
    assert cfg.schema_corpus_path == "/tmp/custom.yaml"
    assert cfg.allowlist_patterns == ("internal_.*",)
    assert cfg.max_body_bytes == 32768
    assert cfg.min_confidence_for_deny == 0.6


def test_profile_config_from_dict_invalid_action_falls_back_to_warn() -> None:
    cfg = ProfileConfig.from_dict({"enabled": True, "action": "nuke_everything"})
    assert cfg.action == "warn"


def test_profile_config_from_dict_empty_yields_defaults() -> None:
    cfg = ProfileConfig.from_dict(None)
    assert cfg.enabled is False
    assert cfg.action == "warn"
