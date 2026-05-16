"""Tests for the iam-jit applicability framework (Slice 1).

Per [[iam-jit-inapplicable-cases]]: agents must get a clear "iam-jit
can't help here" signal upfront, with a concrete next-action, so they
don't waste cycles → reach for "disable iam-jit." Slice 1 ships the
data model + curated catalog + checker + MCP tools.
"""

from __future__ import annotations

import pytest

from iam_jit.compatibility import (
    CATALOG,
    Compatibility,
    CompatibilityIntent,
    CompatibilityResult,
    WorkloadType,
    check_compatibility,
    list_catalog,
)
from iam_jit.mcp_server import (
    _check_compatibility_for_mcp,
    _handle_request,
    _list_compatibility_catalog_for_mcp,
)


def _intent(**overrides) -> CompatibilityIntent:
    defaults: dict = {"workload": WorkloadType.AGENT_LOCAL_DEV}
    defaults.update(overrides)
    return CompatibilityIntent(**defaults)


# ---------------------------------------------------------------------------
# Catalog shape invariants
# ---------------------------------------------------------------------------


def test_catalog_covers_all_fixed_role_workloads() -> None:
    """The workloads where iam-jit fundamentally can't help (because
    the role is baked into the workload) MUST have catalog entries."""
    workloads_in_catalog: set[WorkloadType] = set()
    for entry in CATALOG:
        workloads_in_catalog.update(entry.workloads)
    required = {
        WorkloadType.K8S_POD,
        WorkloadType.EKS_POD_IDENTITY,
        WorkloadType.EC2_INSTANCE,
        WorkloadType.LAMBDA_FUNCTION,
        WorkloadType.ECS_TASK,
    }
    missing = required - workloads_in_catalog
    assert not missing, f"catalog missing entries for: {missing}"


def test_every_catalog_entry_has_next_action_hint() -> None:
    """Per [[agent-friendly-not-bypassable]]: no vague answers. Every
    entry must tell the agent what to do INSTEAD."""
    for entry in CATALOG:
        assert entry.next_action_hint, f"entry {entry.id!r} has no next_action_hint"
        assert len(entry.next_action_hint) > 20, (
            f"entry {entry.id!r} next_action_hint too short to be useful"
        )


def test_every_catalog_entry_has_reasoning() -> None:
    for entry in CATALOG:
        assert entry.reasoning
        assert len(entry.reasoning) > 30, f"entry {entry.id!r} reasoning too short"


def test_fixed_role_workloads_recommend_bouncer_or_explain_why_not() -> None:
    """For fixed-role workloads where USE_EXISTING is the verdict,
    bouncer_recommended should be True (the bouncer can still gate
    the calls) — EXCEPT inside Lambda runtime where the bouncer
    doesn't make sense (no local process to run it in)."""
    for entry in CATALOG:
        if entry.verdict != Compatibility.USE_EXISTING:
            continue
        if WorkloadType.LAMBDA_FUNCTION in entry.workloads:
            # Documented exception: bouncer can't run inside Lambda
            assert not entry.bouncer_recommended
        else:
            assert entry.bouncer_recommended, (
                f"USE_EXISTING entry {entry.id!r} should recommend bouncer "
                "as the gating fallback"
            )


# ---------------------------------------------------------------------------
# check_compatibility — per-workload verdicts
# ---------------------------------------------------------------------------


def test_k8s_pod_returns_use_existing() -> None:
    result = check_compatibility(_intent(workload=WorkloadType.K8S_POD))
    assert result.verdict == Compatibility.USE_EXISTING
    assert "IRSA" in result.reasoning or "pod" in result.reasoning.lower()
    assert result.bouncer_recommended is True
    assert result.next_action_hint
    assert result.matched_pattern == "k8s-irsa-fixed-role"


def test_eks_pod_identity_returns_use_existing() -> None:
    result = check_compatibility(_intent(workload=WorkloadType.EKS_POD_IDENTITY))
    assert result.verdict == Compatibility.USE_EXISTING


def test_ec2_instance_returns_use_existing_with_bouncer() -> None:
    result = check_compatibility(_intent(workload=WorkloadType.EC2_INSTANCE))
    assert result.verdict == Compatibility.USE_EXISTING
    assert result.bouncer_recommended is True


def test_lambda_returns_use_existing_no_bouncer() -> None:
    """Bouncer doesn't make sense inside Lambda runtime — verify the
    response doesn't recommend it."""
    result = check_compatibility(_intent(workload=WorkloadType.LAMBDA_FUNCTION))
    assert result.verdict == Compatibility.USE_EXISTING
    assert result.bouncer_recommended is False


def test_ecs_task_returns_use_existing() -> None:
    result = check_compatibility(_intent(workload=WorkloadType.ECS_TASK))
    assert result.verdict == Compatibility.USE_EXISTING


def test_ci_runner_returns_proceed() -> None:
    """CI runners are OIDC-federated — iam-jit can issue."""
    result = check_compatibility(_intent(workload=WorkloadType.CI_RUNNER))
    assert result.verdict == Compatibility.PROCEED


def test_agent_local_dev_returns_proceed() -> None:
    """Local agent dev is iam-jit's primary use case per
    [[agent-safety-adoption-play]]."""
    result = check_compatibility(_intent(workload=WorkloadType.AGENT_LOCAL_DEV))
    assert result.verdict == Compatibility.PROCEED
    assert result.bouncer_recommended is True


def test_human_cli_returns_proceed() -> None:
    result = check_compatibility(_intent(workload=WorkloadType.HUMAN_CLI))
    assert result.verdict == Compatibility.PROCEED


def test_other_workload_degrades_to_proceed_with_fallback_note() -> None:
    """Unknown workloads should default to PROCEED but flag the
    uncertainty so the agent has a fallback if iam-jit fails."""
    result = check_compatibility(_intent(workload=WorkloadType.OTHER))
    assert result.verdict == Compatibility.PROCEED
    # The note must mention falling back to existing role + bouncer
    assert "fall back" in result.reasoning.lower() or "switch to" in result.next_action_hint.lower()
    assert result.bouncer_recommended is True


# ---------------------------------------------------------------------------
# existing_role_hint is echoed back
# ---------------------------------------------------------------------------


def test_existing_role_hint_echoed_in_use_existing() -> None:
    """When the agent passes an existing-role hint AND the verdict is
    USE_EXISTING, the response includes the ARN so the agent has a
    single response to act on."""
    arn = "arn:aws:iam::111111111111:role/my-irsa-role"
    result = check_compatibility(_intent(
        workload=WorkloadType.K8S_POD,
        existing_role_hint=arn,
    ))
    assert result.existing_role_arn == arn


def test_existing_role_hint_not_echoed_when_proceed() -> None:
    """If the verdict is PROCEED, we don't echo the hint — iam-jit
    is going to issue a new role, not defer."""
    result = check_compatibility(_intent(
        workload=WorkloadType.AGENT_LOCAL_DEV,
        existing_role_hint="arn:aws:iam::111111111111:role/some-role",
    ))
    assert result.existing_role_arn is None


# ---------------------------------------------------------------------------
# CompatibilityResult shape
# ---------------------------------------------------------------------------


def test_to_dict_round_trip() -> None:
    result = check_compatibility(_intent(workload=WorkloadType.K8S_POD))
    d = result.to_dict()
    assert d["verdict"] == "use_existing"
    assert "reasoning" in d
    assert "next_action_hint" in d
    assert "bouncer_recommended" in d
    assert "matched_pattern" in d


# ---------------------------------------------------------------------------
# list_catalog
# ---------------------------------------------------------------------------


def test_list_catalog_returns_all_entries() -> None:
    out = list_catalog()
    assert len(out) == len(CATALOG)
    for entry in out:
        assert "id" in entry
        assert "workloads" in entry
        assert "verdict" in entry
        assert "reasoning" in entry
        assert "next_action_hint" in entry


# ---------------------------------------------------------------------------
# MCP tool — input validation
# ---------------------------------------------------------------------------


def test_mcp_check_missing_workload() -> None:
    assert "error" in _check_compatibility_for_mcp({})


def test_mcp_check_unknown_workload() -> None:
    out = _check_compatibility_for_mcp({"workload": "made-up-workload"})
    assert "error" in out
    assert "unknown workload" in out["error"]


def test_mcp_check_non_string_workload() -> None:
    assert "error" in _check_compatibility_for_mcp({"workload": 42})


def test_mcp_check_non_list_target_services() -> None:
    out = _check_compatibility_for_mcp({
        "workload": "agent_local_dev",
        "target_services": "s3",
    })
    assert "error" in out


def test_mcp_check_target_services_must_all_be_strings() -> None:
    out = _check_compatibility_for_mcp({
        "workload": "agent_local_dev",
        "target_services": ["s3", 42],
    })
    assert "error" in out


def test_mcp_check_non_string_description() -> None:
    out = _check_compatibility_for_mcp({
        "workload": "agent_local_dev",
        "description": 42,
    })
    assert "error" in out


# ---------------------------------------------------------------------------
# MCP tool — happy path
# ---------------------------------------------------------------------------


def test_mcp_check_k8s_pod_full_path() -> None:
    out = _check_compatibility_for_mcp({
        "workload": "k8s_pod",
        "target_account_id": "111111111111",
        "target_services": ["s3", "dynamodb"],
        "description": "ML pipeline reading training data + writing checkpoints",
        "existing_role_hint": "arn:aws:iam::111111111111:role/ml-pipeline",
    })
    assert "error" not in out
    assert out["verdict"] == "use_existing"
    assert out["existing_role_arn"] == "arn:aws:iam::111111111111:role/ml-pipeline"
    assert out["bouncer_recommended"] is True


def test_mcp_check_agent_local_dev() -> None:
    out = _check_compatibility_for_mcp({"workload": "agent_local_dev"})
    assert out["verdict"] == "proceed"


def test_mcp_list_catalog() -> None:
    out = _list_compatibility_catalog_for_mcp({})
    assert "entries" in out
    assert out["count"] == len(CATALOG)


# ---------------------------------------------------------------------------
# Full MCP dispatch round-trip
# ---------------------------------------------------------------------------


def test_dispatch_check_iam_jit_compatibility() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "check_iam_jit_compatibility",
            "arguments": {"workload": "k8s_pod"},
        },
    })
    sc = resp["result"]["structuredContent"]
    assert sc["verdict"] == "use_existing"


def test_dispatch_list_compatibility_catalog() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "list_compatibility_catalog", "arguments": {}},
    })
    sc = resp["result"]["structuredContent"]
    assert sc["count"] == len(CATALOG)


def test_both_tools_in_tools_list() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "check_iam_jit_compatibility" in names
    assert "list_compatibility_catalog" in names
