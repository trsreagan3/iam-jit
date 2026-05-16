"""Tests for the score_iam_policy MCP tool.

Per user direction (2026-05-16): devs don't want to manually pipe
their terraform-generated policy through `iam-jit score`. The MCP
server now exposes `score_iam_policy` so agents (Claude Code,
Cursor) call it automatically before suggesting `terraform apply`.
"""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit.mcp_server import _handle_request, _score_for_mcp


def _mcp_call(name: str, arguments: dict) -> dict:
    """Helper: build + dispatch a tools/call request."""
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    return _handle_request(req)


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------


def test_tools_list_exposes_score_iam_policy() -> None:
    """tools/list MUST include score_iam_policy so agents discover it."""
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    resp = _handle_request(req)
    tool_names = {t["name"] for t in resp["result"]["tools"]}
    assert "score_iam_policy" in tool_names
    assert "generate_iam_policy" in tool_names  # existing tool stays


def test_tools_list_score_policy_description_pushes_proactive_use() -> None:
    """The description should tell the agent to USE THIS PROACTIVELY —
    not wait for the human to ask."""
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    resp = _handle_request(req)
    score_tool = next(
        t for t in resp["result"]["tools"] if t["name"] == "score_iam_policy"
    )
    desc_lc = score_tool["description"].lower()
    # Key phrases that push automatic / proactive use
    assert "proactively" in desc_lc
    assert "terraform" in desc_lc  # explicit mention of the workflow


# ---------------------------------------------------------------------------
# score_iam_policy results
# ---------------------------------------------------------------------------


def test_score_safe_policy_returns_low_tier_ok_to_proceed() -> None:
    """A narrow S3 read should score low and recommend OK_TO_PROCEED."""
    result = _score_for_mcp({
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::artifacts/release-notes.pdf",
                }
            ],
        },
        "access_type": "read-only",
    })
    assert result["score"] <= 3
    assert result["tier"] == "low"
    assert result["recommended_action"] == "OK_TO_PROCEED"


def test_score_dangerous_policy_returns_high_tier_decline() -> None:
    """Admin shape → high tier + DECLINE_TO_DEPLOY recommendation."""
    result = _score_for_mcp({
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        },
        "access_type": "read-write",
    })
    assert result["score"] >= 8
    assert result["tier"] == "high"
    assert result["recommended_action"] == "DECLINE_TO_DEPLOY_WITHOUT_EXPLICIT_CONFIRM"


def test_score_borderline_policy_returns_medium_or_high_tier() -> None:
    """A medium-risk shape should land in the SURFACE or DECLINE bucket.
    s3:* on Resource:* is the canonical "this should give the agent
    pause" shape — destructive action wildcard on a broad resource."""
    result = _score_for_mcp({
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
            ],
        },
        "access_type": "read-write",
    })
    # s3:* on * is destructive-wildcard territory — must be at least
    # medium-tier; in practice it's almost always high.
    assert result["score"] >= 5
    assert result["recommended_action"] in (
        "SURFACE_FACTORS_TO_USER", "DECLINE_TO_DEPLOY_WITHOUT_EXPLICIT_CONFIRM"
    )


def test_score_missing_policy_returns_error() -> None:
    result = _score_for_mcp({"access_type": "read-only"})
    assert result["score"] is None
    assert "error" in result
    assert "policy is required" in result["error"]


def test_score_non_dict_policy_returns_error() -> None:
    result = _score_for_mcp({"policy": "not a dict"})
    assert result["score"] is None
    assert "error" in result


def test_score_via_full_mcp_dispatch_returns_structured_content() -> None:
    """End-to-end: tools/call with score_iam_policy returns the MCP
    structuredContent shape the agent reads."""
    resp = _mcp_call("score_iam_policy", {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        },
        "access_type": "read-only",
    })
    assert "result" in resp
    structured = resp["result"]["structuredContent"]
    assert "score" in structured
    assert "tier" in structured
    assert "factors" in structured
    assert "recommended_action" in structured


def test_score_passes_context_through_for_audit() -> None:
    """The `context` arg is forwarded to the response so the audit
    log can capture WHY a policy was scored (which terraform module,
    which deployment, etc.)."""
    result = _score_for_mcp({
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        },
        "context": "terraform module: iam-role-buildkite-uploader",
    })
    assert result["context"] == "terraform module: iam-role-buildkite-uploader"
