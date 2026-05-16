"""Tests for the new MCP tool triad introduced in iam-jit 0.3.0:
list_templates, get_template, submit_policy.

Per [[no-nl-synthesis]] (decision 2026-05-16): iam-jit removes
natural-language policy synthesis. The replacement is the
agent-driven reduction loop, which uses these three tools plus
the existing score_iam_policy. See docs/AGENTS.md.

Stage 1 of #149 is ADDITIVE — the old generate_iam_policy tool
still exists with a deprecation tombstone. These tests verify the
new tools work; Stage 2 will delete the deprecated path and adjust
those tests.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from iam_jit.mcp_server import (
    SERVER_VERSION,
    TOOLS,
    _get_template_for_mcp,
    _handle_request,
    _list_templates_for_mcp,
    _submit_policy_for_mcp,
)


# ---------------------------------------------------------------------------
# Tool discovery — list_templates / get_template / submit_policy must be
# discoverable via tools/list so MCP-aware agents auto-find them.
# ---------------------------------------------------------------------------


def test_server_version_bumped_for_new_triad() -> None:
    """0.3.0 marks the triad + deprecation."""
    assert SERVER_VERSION == "0.3.0"


def test_tools_list_includes_new_triad() -> None:
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    resp = _handle_request(req)
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "list_templates" in names
    assert "get_template" in names
    assert "submit_policy" in names
    # Existing tools still present
    assert "score_iam_policy" in names
    assert "generate_iam_policy" in names  # still present, tombstoned


def test_generate_iam_policy_description_is_deprecated() -> None:
    """The legacy tool's description must announce deprecation so
    MCP hosts surface the warning before agents call it."""
    gen = next(t for t in TOOLS if t["name"] == "generate_iam_policy")
    assert "DEPRECATED" in gen["description"]
    assert "list_templates" in gen["description"]
    assert "submit_policy" in gen["description"]


# ---------------------------------------------------------------------------
# list_templates
# ---------------------------------------------------------------------------


def test_list_templates_returns_full_catalog_with_no_filters() -> None:
    out = _list_templates_for_mcp({})
    assert "templates" in out
    assert out["total"] == len(out["templates"])
    assert not out["truncated"]
    # Spot-check known entries
    names = {t["name"] for t in out["templates"]}
    assert "AdministratorAccess" in names
    assert "ReadOnlyAccess" in names
    assert "ExploreReadOnlyWithSensitiveExclusions" in names


def test_list_templates_filters_by_access_type() -> None:
    out = _list_templates_for_mcp({"access_type": "read-only"})
    assert all(t["access_type"] == "read-only" for t in out["templates"])
    assert out["total"] >= 1


def test_list_templates_filters_by_admin() -> None:
    out = _list_templates_for_mcp({"access_type": "admin"})
    names = {t["name"] for t in out["templates"]}
    assert "AdministratorAccess" in names
    assert "PowerUserAccess" in names
    # Read-only baselines shouldn't appear in admin filter
    assert "ReadOnlyAccess" not in names


def test_list_templates_filters_by_service() -> None:
    """S3 filter should match S3-specific entries AND catch-all
    entries with services=['*']."""
    out = _list_templates_for_mcp({"service": "s3"})
    names = {t["name"] for t in out["templates"]}
    assert "AmazonS3ReadOnlyAccess" in names
    # Catch-all baselines have services=['*'] so they should also match
    assert "AdministratorAccess" in names
    assert "ReadOnlyAccess" in names


def test_list_templates_no_inlined_policy_shapes() -> None:
    """list_templates must NOT inline policy_shape — that would
    bloat MCP responses with hundreds of lines of JSON. Use
    get_template for the full body."""
    out = _list_templates_for_mcp({})
    for entry in out["templates"]:
        assert "policy" not in entry
        assert "policy_shape" not in entry
        # Required fields ARE present
        assert "name" in entry
        assert "arn" in entry
        assert "summary" in entry
        assert "services" in entry
        assert "access_type" in entry
        assert "source" in entry


def test_list_templates_query_is_exact_substring_not_fuzzy() -> None:
    """No fuzzy NL matching — query is plain substring on name only."""
    out = _list_templates_for_mcp({"query": "ReadOnly"})
    names = [t["name"] for t in out["templates"]]
    assert all("ReadOnly" in n for n in names)
    # 'audit' is a use-case tag of SecurityAudit but NOT in any
    # template name → fuzzy match would return SecurityAudit;
    # substring match must NOT.
    out2 = _list_templates_for_mcp({"query": "audit"})
    # Should match SecurityAudit by name substring (lowercase compare)
    names2 = [t["name"] for t in out2["templates"]]
    # Case-insensitive substring match on name only
    assert all("audit" in n.lower() for n in names2)


def test_list_templates_source_filter() -> None:
    """Pre-launch: aws-managed returns entries; org-curated /
    personal-recurring return empty (those tiers are post-launch)."""
    out_aws = _list_templates_for_mcp({"source": "aws-managed"})
    assert out_aws["total"] >= 1
    out_org = _list_templates_for_mcp({"source": "org-curated"})
    assert out_org["templates"] == []
    out_personal = _list_templates_for_mcp({"source": "personal-recurring"})
    assert out_personal["templates"] == []


# ---------------------------------------------------------------------------
# get_template
# ---------------------------------------------------------------------------


def test_get_template_returns_full_shape_by_name() -> None:
    out = _get_template_for_mcp({"name": "AdministratorAccess"})
    assert out["name"] == "AdministratorAccess"
    assert out["arn"].endswith("/AdministratorAccess")
    assert "policy" in out
    assert out["policy"]["Version"] == "2012-10-17"
    assert out["policy"]["Statement"]


def test_get_template_unknown_returns_error() -> None:
    out = _get_template_for_mcp({"name": "NotARealTemplate"})
    assert out["policy"] is None
    assert "template not found" in out["error"]


def test_get_template_missing_name_returns_error() -> None:
    out = _get_template_for_mcp({})
    assert out["policy"] is None
    assert "error" in out


def test_get_template_is_exact_match_not_fuzzy() -> None:
    """get_template requires the EXACT name — no fuzzy lookup."""
    out = _get_template_for_mcp({"name": "AdministratorAccess"})
    assert out["policy"] is not None
    # Lowercase variant should fail (case-sensitive exact match)
    out2 = _get_template_for_mcp({"name": "administratoraccess"})
    assert out2["policy"] is None


# ---------------------------------------------------------------------------
# submit_policy
# ---------------------------------------------------------------------------


def _safe_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::artifacts/build.tar.gz",
            }
        ],
    }


def _admin_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }


def test_submit_policy_without_backend_returns_would_submit_shape() -> None:
    """When IAM_JIT_URL + IAM_JIT_TOKEN are not set, submit_policy
    returns the request body the agent would have submitted, plus
    the local score. NO HTTP call is made."""
    # Ensure env vars are not set
    env_patch = {"IAM_JIT_URL": "", "IAM_JIT_TOKEN": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        result = _submit_policy_for_mcp({
            "policy": _safe_policy(),
            "description": "test grant",
            "accounts": ["123456789012"],
            "duration_hours": 1,
        })
    assert result["submitted"] is False
    assert result["request_id"] is None
    assert result["score"] is not None
    assert result["tier"] in {"low", "medium", "high"}
    assert "would_submit" in result
    assert result["would_submit"]["spec"]["policy"] == _safe_policy()
    assert result["would_submit"]["spec"]["accounts"] == ["123456789012"]
    assert "IAM_JIT_URL" in result["reason"]


def test_submit_policy_scores_admin_high() -> None:
    env_patch = {"IAM_JIT_URL": "", "IAM_JIT_TOKEN": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        result = _submit_policy_for_mcp({
            "policy": _admin_policy(),
            "description": "test admin",
            "accounts": ["123456789012"],
            "access_type": "read-write",
        })
    assert result["score"] >= 8
    assert result["tier"] == "high"
    assert result["recommended_action"] == "DECLINE_TO_DEPLOY_WITHOUT_EXPLICIT_CONFIRM"


def test_submit_policy_missing_policy_returns_error() -> None:
    result = _submit_policy_for_mcp({
        "description": "x",
        "accounts": ["123456789012"],
    })
    assert result["request_id"] is None
    assert "policy is required" in result["error"]


def test_submit_policy_missing_description_returns_error() -> None:
    result = _submit_policy_for_mcp({
        "policy": _safe_policy(),
        "accounts": ["123456789012"],
    })
    assert "description" in result["error"]


def test_submit_policy_missing_accounts_returns_error() -> None:
    result = _submit_policy_for_mcp({
        "policy": _safe_policy(),
        "description": "x",
    })
    assert "accounts" in result["error"]


def test_submit_policy_bad_duration_returns_error() -> None:
    result = _submit_policy_for_mcp({
        "policy": _safe_policy(),
        "description": "x",
        "accounts": ["123456789012"],
        "duration_hours": 9999,  # > 720
    })
    assert "duration_hours" in result["error"]


def test_submit_policy_invalid_access_type_coerces_to_read_only() -> None:
    """Per [[read-only-default]], unknown access_type values become
    read-only (the safe default), never read-write."""
    env_patch = {"IAM_JIT_URL": "", "IAM_JIT_TOKEN": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        result = _submit_policy_for_mcp({
            "policy": _safe_policy(),
            "description": "x",
            "accounts": ["123456789012"],
            "access_type": "made-up-type",
        })
    assert result["would_submit"]["spec"]["access_type"] == "read-only"


def test_submit_policy_truncates_long_description() -> None:
    env_patch = {"IAM_JIT_URL": "", "IAM_JIT_TOKEN": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        result = _submit_policy_for_mcp({
            "policy": _safe_policy(),
            "description": "x" * 5000,
            "accounts": ["123456789012"],
        })
    assert len(result["would_submit"]["spec"]["description"]) == 1024


# ---------------------------------------------------------------------------
# Full MCP dispatch round-trip
# ---------------------------------------------------------------------------


def _call(name: str, args: dict) -> dict:
    return _handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    })


def test_dispatch_list_templates() -> None:
    resp = _call("list_templates", {"access_type": "read-only"})
    assert "result" in resp
    sc = resp["result"]["structuredContent"]
    assert "templates" in sc


def test_dispatch_get_template() -> None:
    resp = _call("get_template", {"name": "ReadOnlyAccess"})
    assert "result" in resp
    sc = resp["result"]["structuredContent"]
    assert sc["name"] == "ReadOnlyAccess"
    assert "policy" in sc


def test_dispatch_submit_policy() -> None:
    env_patch = {"IAM_JIT_URL": "", "IAM_JIT_TOKEN": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        resp = _call("submit_policy", {
            "policy": _safe_policy(),
            "description": "x",
            "accounts": ["111111111111"],
        })
    assert "result" in resp
    sc = resp["result"]["structuredContent"]
    assert sc["submitted"] is False
    assert sc["score"] is not None


# ---------------------------------------------------------------------------
# Deprecation block on the legacy generate_iam_policy
# ---------------------------------------------------------------------------


def test_generate_iam_policy_emits_deprecation_block() -> None:
    """Legacy tool still works but emits a `deprecation` field
    pointing at the new triad."""
    from iam_jit.mcp_server import _generate_for_mcp
    result = _generate_for_mcp({"task": "read s3 bucket my-bucket"})
    assert "deprecation" in result
    dep = result["deprecation"]
    assert dep["deprecated"] is True
    assert dep["removed_in"] == "0.4.0"
    assert "list_templates" in dep["replacement_tools"]
    assert "submit_policy" in dep["replacement_tools"]


def test_generate_iam_policy_baseline_fallback_also_has_deprecation() -> None:
    """The baseline-fallback path (when synthesis returns empty)
    also includes the deprecation block."""
    from iam_jit.mcp_server import _generate_for_mcp
    # A prompt that the catalog will baseline-fallback on
    result = _generate_for_mcp({
        "task": "look around the staging account I just inherited",
        "access_type": "read-only",
    })
    # Either matched a baseline OR synthesized — either way deprecation present
    assert "deprecation" in result
