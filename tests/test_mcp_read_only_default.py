"""Pinned tests for the MCP server's read-only default convention.

Per [[read-only-default]] memo. After Stage 3 of [[no-nl-synthesis]]
(iam-jit 0.4.0), the convention lives on `submit_policy` (the tool
agents actually use to submit grant requests). The legacy
`generate_iam_policy` is a tombstone.

The contract: when an agent invokes submit_policy without an
explicit access_type, it should default to read-only — the
foundational asymmetry that makes safety-mode work per
[[agent-driven-reduction-loop]] + [[read-only-default]].
"""

from __future__ import annotations

from iam_jit.mcp_server import TOOLS, _submit_policy_for_mcp


def _submit_tool() -> dict:
    return next(t for t in TOOLS if t["name"] == "submit_policy")


def _list_tool() -> dict:
    return next(t for t in TOOLS if t["name"] == "list_templates")


def test_submit_policy_access_type_param_mentions_read_only_default() -> None:
    """The submit_policy access_type parameter MUST explicitly
    reference the read-only-default convention so agents discover
    it via tools/list. This is the behavioral contract that makes
    safety mode work."""
    tool = _submit_tool()
    at = tool["inputSchema"]["properties"]["access_type"]
    desc = at["description"]
    assert "read-only" in desc.lower() or "[[read-only-default]]" in desc


def test_submit_policy_schema_includes_access_type_with_read_only_default() -> None:
    """access_type parameter must be in the submit_policy schema
    with `default: read-only`. This shapes the agent's tool-call
    structure even when the agent omits the field explicitly."""
    schema = _submit_tool()["inputSchema"]
    props = schema["properties"]
    assert "access_type" in props
    at = props["access_type"]
    assert at["default"] == "read-only"
    assert set(at["enum"]) == {"read-only", "read-write"}


def test_list_templates_access_type_filter_advertises_read_only_first() -> None:
    """list_templates also has access_type as a filter. The
    parameter description should nudge agents toward filtering on
    read-only first per [[read-only-default]]."""
    tool = _list_tool()
    at = tool["inputSchema"]["properties"]["access_type"]
    assert "read-only" in at["description"].lower()


def test_submit_policy_defaults_to_read_only_when_not_specified() -> None:
    """When the agent omits access_type, the submit_policy handler
    defaults to read-only in the would_submit payload (no backend
    configured — env vars empty)."""
    import os
    from unittest.mock import patch
    env_patch = {"IAM_JIT_URL": "", "IAM_JIT_TOKEN": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        result = _submit_policy_for_mcp({
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::artifacts/x.txt",
                }],
            },
            "description": "test",
            "accounts": ["111111111111"],
        })
    assert result["would_submit"]["spec"]["access_type"] == "read-only"


def test_submit_policy_honors_explicit_read_write() -> None:
    """When the agent explicitly passes read-write (because the
    user authorized a state-changing op), honor it."""
    import os
    from unittest.mock import patch
    env_patch = {"IAM_JIT_URL": "", "IAM_JIT_TOKEN": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        result = _submit_policy_for_mcp({
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:DeleteObject",
                    "Resource": "arn:aws:s3:::trash/x.txt",
                }],
            },
            "description": "delete old artifact",
            "accounts": ["111111111111"],
            "access_type": "read-write",
        })
    assert result["would_submit"]["spec"]["access_type"] == "read-write"


def test_submit_policy_coerces_invalid_access_type_to_read_only() -> None:
    """Defense: if Claude (or attacker) sends garbage in access_type,
    coerce to read-only — the safe default. Never silently accept
    read-write from a malformed argument."""
    import os
    from unittest.mock import patch
    env_patch = {"IAM_JIT_URL": "", "IAM_JIT_TOKEN": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        result = _submit_policy_for_mcp({
            "policy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::x/y",
                }],
            },
            "description": "test",
            "accounts": ["111111111111"],
            "access_type": "garbage-value-from-attacker",
        })
    assert result["would_submit"]["spec"]["access_type"] == "read-only"
