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
    the calls) — EXCEPT for managed-compute environments where there's
    no local process to run the bouncer in (Lambda runtime, Step
    Functions, Glue, SageMaker, CodeBuild, App Runner)."""
    # Documented exceptions: managed compute where a local bouncer
    # process can't run alongside the workload.
    MANAGED_COMPUTE_NO_BOUNCER = {
        WorkloadType.LAMBDA_FUNCTION,
        WorkloadType.CODEBUILD_PROJECT,
        WorkloadType.STEP_FUNCTIONS,
        WorkloadType.GLUE_JOB,
        WorkloadType.SAGEMAKER,
        WorkloadType.APP_RUNNER,
    }
    for entry in CATALOG:
        if entry.verdict != Compatibility.USE_EXISTING:
            continue
        managed = MANAGED_COMPUTE_NO_BOUNCER & set(entry.workloads)
        if managed:
            assert not entry.bouncer_recommended, (
                f"managed-compute entry {entry.id!r} ({managed}) shouldn't "
                "recommend bouncer (no local process to run it in)"
            )
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


# ---------------------------------------------------------------------------
# WB24 closures
# ---------------------------------------------------------------------------


# HIGH-24-02: catalog reasoning now accurate about IAM semantics
@pytest.mark.parametrize("workload,must_mention", [
    (WorkloadType.K8S_POD, "sts:AssumeRole"),
    (WorkloadType.EKS_POD_IDENTITY, "sts:AssumeRole"),
    (WorkloadType.EC2_INSTANCE, "sts:AssumeRole"),
    (WorkloadType.LAMBDA_FUNCTION, "sts:AssumeRole"),
    (WorkloadType.ECS_TASK, "sts:AssumeRole"),
])
def test_high_24_02_catalog_acknowledges_assume_role(workload, must_mention) -> None:
    """WB24 HIGH-24-02: catalog reasoning must acknowledge that
    sts:AssumeRole still works (BASE identity is fixed, assume-chain
    isn't). Previously the reasoning text claimed roles couldn't be
    changed at all, which is technically wrong."""
    result = check_compatibility(_intent(workload=workload))
    assert must_mention in result.reasoning, (
        f"workload {workload.value!r} reasoning doesn't acknowledge "
        f"assume-role: {result.reasoning!r}"
    )


# HIGH-24-01: submit_policy with USE_EXISTING workload is rejected
def test_high_24_01_submit_policy_refuses_use_existing_workload() -> None:
    from iam_jit.mcp_server import _submit_policy_for_mcp

    out = _submit_policy_for_mcp({
        "policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ]},
        "description": "ML pipeline reads",
        "accounts": ["111111111111"],
        "workload": "k8s_pod",
    })
    assert "error" in out
    assert "cannot issue" in out["error"]
    assert out["verdict"] == "use_existing"
    assert out["next_action_hint"]
    assert out["bouncer_recommended"] is True


def test_high_24_01_submit_policy_proceeds_for_proceed_workload() -> None:
    from iam_jit.mcp_server import _submit_policy_for_mcp

    out = _submit_policy_for_mcp({
        "policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ]},
        "description": "agent local dev session",
        "accounts": ["111111111111"],
        "workload": "agent_local_dev",
    })
    # No "cannot issue" error; should proceed to normal submission
    # (which returns either a real submission or a would-submit shape).
    assert out.get("error") != "iam-jit cannot issue a role for workload"  # no compat error


def test_high_24_01_submit_policy_without_workload_still_works() -> None:
    """Bypass-able (workload optional) but audit-logged."""
    from iam_jit.mcp_server import _submit_policy_for_mcp

    out = _submit_policy_for_mcp({
        "policy": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ]},
        "description": "no workload",
        "accounts": ["111111111111"],
    })
    # No compatibility-check error
    assert "verdict" not in out


# MED-24-01: compatibility check writes audit event via sink
def test_med_24_01_check_writes_audit_event_when_sink_provided() -> None:
    recorded: list[dict] = []

    class _Sink:
        def record(self, *, kind, actor, summary, detail=None):
            recorded.append({
                "kind": kind, "actor": actor, "summary": summary, "detail": detail,
            })

    check_compatibility(
        _intent(workload=WorkloadType.K8S_POD, description="test"),
        audit_sink=_Sink(),
        actor="test-agent",
    )
    assert len(recorded) == 1
    assert recorded[0]["kind"] == "compatibility_check"
    assert recorded[0]["actor"] == "test-agent"
    assert recorded[0]["detail"]["workload"] == "k8s_pod"
    assert recorded[0]["detail"]["verdict"] == "use_existing"
    # LOW-24-02: description IS plumbed through to audit detail now
    assert recorded[0]["detail"]["description"] == "test"


def test_med_24_01_check_no_sink_no_record() -> None:
    """No sink = no audit write (pure function)."""
    # Just verify it doesn't raise / produces the same result
    r1 = check_compatibility(_intent(workload=WorkloadType.K8S_POD))
    r2 = check_compatibility(
        _intent(workload=WorkloadType.K8S_POD), audit_sink=None,
    )
    assert r1.verdict == r2.verdict


def test_med_24_01_sink_failure_does_not_crash_check() -> None:
    """Best-effort logging: a broken sink doesn't bubble up."""
    class _BrokenSink:
        def record(self, **_):
            raise RuntimeError("storage down")

    result = check_compatibility(
        _intent(workload=WorkloadType.K8S_POD), audit_sink=_BrokenSink()
    )
    assert result.verdict == Compatibility.USE_EXISTING


# MED-24-02: existing_role_hint validated as ARN format
def test_med_24_02_valid_arn_echoed() -> None:
    arn = "arn:aws:iam::111111111111:role/my-pod-role"
    result = check_compatibility(_intent(
        workload=WorkloadType.K8S_POD, existing_role_hint=arn,
    ))
    assert result.existing_role_arn == arn
    assert result.existing_role_hint_invalid is False


def test_med_24_02_malformed_arn_rejected() -> None:
    result = check_compatibility(_intent(
        workload=WorkloadType.K8S_POD, existing_role_hint="haha not a real ARN",
    ))
    assert result.existing_role_arn is None
    assert result.existing_role_hint_invalid is True


def test_med_24_02_empty_string_hint_treated_as_none() -> None:
    result = check_compatibility(_intent(
        workload=WorkloadType.K8S_POD, existing_role_hint="",
    ))
    assert result.existing_role_arn is None
    assert result.existing_role_hint_invalid is False  # empty != invalid


@pytest.mark.parametrize("arn", [
    "arn:aws:iam::111111111111:role/my-role",
    "arn:aws-us-gov:iam::222222222222:role/gov-role",
    "arn:aws-cn:iam::333333333333:role/cn-role",
    "arn:aws:iam::444444444444:role/path/to/role-with-slash",
])
def test_med_24_02_valid_arn_partitions(arn: str) -> None:
    result = check_compatibility(_intent(
        workload=WorkloadType.K8S_POD, existing_role_hint=arn,
    ))
    assert result.existing_role_arn == arn
    assert result.existing_role_hint_invalid is False


# LOW-24-03: catalog structural invariants enforced by tests
def test_low_24_03_every_non_other_workload_has_catalog_entry() -> None:
    """Adding a new WorkloadType without a catalog entry should fail
    this test (closes the audit's question 9 gap)."""
    from iam_jit.compatibility import _CATALOG_BY_WORKLOAD

    expected_no_entry = {WorkloadType.OTHER}
    missing = {
        w for w in WorkloadType
        if w not in _CATALOG_BY_WORKLOAD and w not in expected_no_entry
    }
    assert not missing, f"workloads without catalog entry: {missing}"


def test_low_24_03_no_unintentional_workload_duplicates() -> None:
    """A future contributor adding a duplicate workload entry would
    silently shadow the first; this test catches it."""
    from collections import Counter

    counts = Counter(w for e in CATALOG for w in e.workloads)
    duplicates = {w: c for w, c in counts.items() if c > 1}
    # If we ever intentionally use first-match-wins specificity ordering,
    # add the workload to EXPECTED_DUPLICATES with a comment explaining.
    EXPECTED_DUPLICATES: set = set()
    assert set(duplicates.keys()) == EXPECTED_DUPLICATES, (
        f"unintentional duplicates: {duplicates}"
    )


# LOW-24-05: MCP input validation rejects bad account/service strings
def test_low_24_05_invalid_account_id_rejected() -> None:
    from iam_jit.mcp_server import _check_compatibility_for_mcp

    for bad in ["not-an-account", "", "123", "1234567890123", "ABC123456789"]:
        out = _check_compatibility_for_mcp({
            "workload": "k8s_pod", "target_account_id": bad,
        })
        assert "error" in out, f"should reject account id {bad!r}"


def test_low_24_05_valid_account_id_accepted() -> None:
    from iam_jit.mcp_server import _check_compatibility_for_mcp

    out = _check_compatibility_for_mcp({
        "workload": "agent_local_dev", "target_account_id": "111111111111",
    })
    assert "error" not in out


def test_low_24_05_invalid_service_prefix_rejected() -> None:
    from iam_jit.mcp_server import _check_compatibility_for_mcp

    out = _check_compatibility_for_mcp({
        "workload": "agent_local_dev",
        "target_services": ["s3", "Definitely Not A Service Name!"],
    })
    assert "error" in out


def test_low_24_05_service_prefix_normalized_to_lowercase() -> None:
    from iam_jit.mcp_server import _check_compatibility_for_mcp

    out = _check_compatibility_for_mcp({
        "workload": "agent_local_dev",
        "target_services": ["S3", "EC2 "],  # case + trailing space tolerated
    })
    assert "error" not in out


# LOW-24-01 partial: new catalog entries for Fargate-shaped workloads
@pytest.mark.parametrize("workload", [
    WorkloadType.CODEBUILD_PROJECT,
    WorkloadType.STEP_FUNCTIONS,
    WorkloadType.GLUE_JOB,
    WorkloadType.SAGEMAKER,
    WorkloadType.APP_RUNNER,
    WorkloadType.BATCH_JOB,
])
def test_low_24_01_new_workloads_return_use_existing(workload) -> None:
    result = check_compatibility(_intent(workload=workload))
    assert result.verdict == Compatibility.USE_EXISTING
    assert result.next_action_hint


def test_low_24_01_mcp_schema_includes_new_workloads() -> None:
    """The MCP tool's enum must list every WorkloadType so agents can
    pass the new values without inputSchema validation errors."""
    from iam_jit.mcp_server import TOOLS

    check_tool = next(t for t in TOOLS if t["name"] == "check_iam_jit_compatibility")
    enum = set(check_tool["inputSchema"]["properties"]["workload"]["enum"])
    expected = {w.value for w in WorkloadType}
    assert enum == expected, (
        f"MCP schema enum drift: missing={expected - enum}, extra={enum - expected}"
    )
