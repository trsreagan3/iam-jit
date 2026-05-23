"""#437 / §A71 — tests for the `bounce_deployment_targets_for_filter`
MCP tool backend."""

from __future__ import annotations

import textwrap

import pytest

from iam_jit.mcp_server import (
    _bounce_deployment_targets_for_filter_for_mcp,
)


@pytest.fixture
def declaration_path(tmp_path):
    body = textwrap.dedent(
        """
        iam-jit:
          enabled: true
          deployment_targets:
            prod-k8s:
              bouncer: kbouncer
              classifier:
                clusters: ["prod-east", "prod-west"]
                accounts: ["999988887777"]
            staging-k8s:
              bouncer: kbouncer
              classifier:
                clusters: ["staging-*"]
        """
    ).strip() + "\n"
    p = tmp_path / ".iam-jit.yaml"
    p.write_text(body)
    return p


def test_mcp_bounce_deployment_targets_for_filter_returns_classifier(
    declaration_path,
):
    """Calling the MCP tool with a target name returns the classifier
    dict the agent can pass straight into `bounce_query_audit_long_range`
    or `iam-jit audit query --scope-filter`."""
    payload = _bounce_deployment_targets_for_filter_for_mcp({
        "name": "prod-k8s",
        "config_path": str(declaration_path),
    })
    assert payload["status"] == "ok"
    assert payload["name"] == "prod-k8s"
    assert payload["bouncer"] == "kbouncer"
    assert payload["classifier"]["clusters"] == ["prod-east", "prod-west"]
    assert payload["classifier"]["accounts"] == ["999988887777"]


def test_mcp_bounce_deployment_targets_for_filter_lists_all_without_name(
    declaration_path,
):
    """When `name` is absent the tool returns the whole taxonomy
    (useful when an agent wants to choose between targets)."""
    payload = _bounce_deployment_targets_for_filter_for_mcp({
        "config_path": str(declaration_path),
    })
    assert payload["status"] == "ok"
    assert payload["count"] == 2
    names = {t["name"] for t in payload["targets"]}
    assert names == {"prod-k8s", "staging-k8s"}


def test_mcp_bounce_deployment_targets_for_filter_missing_target(
    declaration_path,
):
    payload = _bounce_deployment_targets_for_filter_for_mcp({
        "name": "does-not-exist",
        "config_path": str(declaration_path),
    })
    assert payload["status"] == "error"
    assert payload["code"] == "deployment_target_not_found"
