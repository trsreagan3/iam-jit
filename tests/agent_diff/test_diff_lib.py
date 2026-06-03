"""#722 / BUILD-1 — unit tests for the agent-diff pure-function core.

Covers the four sub-deltas + narrowing strategies. The integration
test in tests/integration/test_agent_diff_e2e.py covers the full
CLI / MCP path with realistic event windows.
"""

from __future__ import annotations

import typing

from iam_jit.agent_diff import (
    AgentDiff,
    build_narrowing_policy,
    compute_agent_diff,
    compute_behavioral_delta,
    compute_decision_delta,
    compute_permission_delta,
    compute_risk_delta,
)


_T_BASE = 1737590400000  # 2026-01-23T00:00:00Z


def _ev(
    action: str,
    *,
    resource: str | None = None,
    verdict: str | None = None,
    deny_reason: str | None = None,
    principal: str | None = None,
    host: str | None = None,
    anomaly_score: float | None = None,
    anomaly_verdict: str | None = None,
    bouncer: str = "ibounce",
    t_offset: int = 0,
) -> dict[str, typing.Any]:
    ev: dict[str, typing.Any] = {
        "_bouncer": bouncer,
        "time": _T_BASE + t_offset,
        "metadata": {"product": {"name": bouncer}},
        "api": {
            "operation": action,
            "service": {"name": action.split(":")[0]},
        },
    }
    if resource:
        ev["resources"] = [{"uid": resource, "name": resource}]
    unmapped: dict[str, typing.Any] = {}
    if verdict:
        unmapped["verdict"] = verdict
    if deny_reason:
        unmapped["deny_reason"] = deny_reason
    if anomaly_score is not None:
        unmapped["anomaly_score"] = anomaly_score
    if anomaly_verdict:
        unmapped["anomaly_verdict"] = anomaly_verdict
    if unmapped:
        ev["unmapped"] = {"iam_jit": unmapped}
    if principal:
        ev["actor"] = {"user": {"uid": principal}}
    if host:
        ev["dst_endpoint"] = {"hostname": host}
    return ev


# ---------------------------------------------------------------------------
# Permission delta
# ---------------------------------------------------------------------------


def test_permission_delta_empty_inputs() -> None:
    pd = compute_permission_delta([], [])
    assert pd.only_in_a == ()
    assert pd.only_in_b == ()
    assert pd.intersection == ()


def test_permission_delta_identical_sessions_intersection_only() -> None:
    a = [_ev("s3:GetObject", resource="arn:aws:s3:::bucket/k")]
    b = [_ev("s3:GetObject", resource="arn:aws:s3:::bucket/k")]
    pd = compute_permission_delta(a, b)
    assert pd.only_in_a == ()
    assert pd.only_in_b == ()
    assert len(pd.intersection) == 1
    assert pd.intersection[0].action == "s3:GetObject"
    assert pd.intersection[0].count_a == 1
    assert pd.intersection[0].count_b == 1


def test_permission_delta_disjoint_sessions() -> None:
    a = [_ev("s3:GetObject", resource="arn:aws:s3:::bucket/k")]
    b = [_ev("ec2:DescribeInstances", resource="*")]
    pd = compute_permission_delta(a, b)
    assert len(pd.only_in_a) == 1
    assert pd.only_in_a[0].action == "s3:GetObject"
    assert len(pd.only_in_b) == 1
    assert pd.only_in_b[0].action == "ec2:DescribeInstances"
    assert pd.intersection == ()


def test_permission_delta_intersection_preserves_per_side_resources() -> None:
    """Both sessions invoke s3:PutObject but with different resources.
    The intersection row must expose both sides so the operator can
    see the resource-scope difference."""
    a = [_ev("s3:PutObject", resource="arn:aws:s3:::reports/x")]
    b = [_ev("s3:PutObject", resource="arn:aws:s3:::*")]
    pd = compute_permission_delta(a, b)
    assert len(pd.intersection) == 1
    row = pd.intersection[0]
    assert row.resources_a == ("arn:aws:s3:::reports/x",)
    assert row.resources_b == ("arn:aws:s3:::*",)


def test_permission_delta_counts_aggregated_correctly() -> None:
    a = [
        _ev("s3:GetObject", resource="arn:aws:s3:::b/1"),
        _ev("s3:GetObject", resource="arn:aws:s3:::b/2"),
        _ev("s3:GetObject", resource="arn:aws:s3:::b/2"),
    ]
    pd = compute_permission_delta(a, [])
    assert pd.only_in_a[0].count == 3
    assert pd.only_in_a[0].resources == (
        "arn:aws:s3:::b/1",
        "arn:aws:s3:::b/2",
    )


# ---------------------------------------------------------------------------
# Decision delta
# ---------------------------------------------------------------------------


def test_decision_delta_allow_deny_counts() -> None:
    a = [
        _ev("s3:GetObject", verdict="allow"),
        _ev("s3:GetObject", verdict="allow"),
    ]
    b = [
        _ev("s3:GetObject", verdict="deny", deny_reason="org_policy:no-prod"),
        _ev("s3:PutObject", verdict="allow"),
    ]
    dd = compute_decision_delta(a, b)
    assert dd.a["allow_count"] == 2
    assert dd.a["deny_count"] == 0
    assert dd.b["allow_count"] == 1
    assert dd.b["deny_count"] == 1
    assert dd.delta["allow_count_delta"] == -1  # B - A
    assert dd.delta["deny_count_delta"] == 1
    assert dd.delta["deny_reasons_only_in_b"] == ["org_policy:no-prod"]
    assert dd.delta["deny_reasons_only_in_a"] == []


def test_decision_delta_deny_reasons_set_difference() -> None:
    a = [
        _ev("s3:GetObject", verdict="deny", deny_reason="r1"),
        _ev("s3:GetObject", verdict="deny", deny_reason="r2"),
    ]
    b = [
        _ev("s3:GetObject", verdict="deny", deny_reason="r2"),
        _ev("s3:GetObject", verdict="deny", deny_reason="r3"),
    ]
    dd = compute_decision_delta(a, b)
    assert dd.delta["deny_reasons_only_in_a"] == ["r1"]
    assert dd.delta["deny_reasons_only_in_b"] == ["r3"]


# ---------------------------------------------------------------------------
# Behavioral delta
# ---------------------------------------------------------------------------


def test_behavioral_delta_counts_distincts() -> None:
    a = [
        _ev("s3:GetObject",
            resource="arn:aws:s3:::b/k", principal="claude"),
    ]
    b = [
        _ev("s3:GetObject",
            resource="arn:aws:s3:::b/1", principal="codex"),
        _ev("s3:ListBucket",
            resource="arn:aws:s3:::b", principal="codex"),
        _ev("s3:PutObject",
            resource="arn:aws:s3:::b/2", principal="codex",
            host="s3.amazonaws.com"),
    ]
    bd = compute_behavioral_delta(a, b)
    assert bd.a == {
        "total_calls": 1,
        "distinct_actions": 1,
        "distinct_principals": 1,
        "distinct_resources": 1,
        "distinct_hosts": 0,
    }
    assert bd.b["total_calls"] == 3
    assert bd.b["distinct_actions"] == 3
    assert bd.b["distinct_resources"] == 3
    assert bd.delta["total_calls_delta"] == 2
    assert bd.delta["distinct_actions_delta"] == 2
    assert bd.delta["distinct_hosts_delta"] == 1


# ---------------------------------------------------------------------------
# Risk delta
# ---------------------------------------------------------------------------


def test_risk_delta_unavailable_when_no_scores() -> None:
    rd = compute_risk_delta([_ev("s3:GetObject")], [_ev("s3:PutObject")])
    assert rd.a is None
    assert rd.b is None
    assert rd.delta is None
    assert rd.reason == "anomaly_scoring_unavailable_for_protocol"


def test_risk_delta_one_side_lacks_scores() -> None:
    a = [_ev("s3:GetObject", anomaly_score=0.2, anomaly_verdict="normal")]
    b = [_ev("s3:PutObject")]
    rd = compute_risk_delta(a, b)
    assert rd.a is not None
    assert rd.b is None
    assert rd.delta is None
    assert rd.reason == "one_side_lacks_anomaly_scores"


def test_risk_delta_both_sides_scored_real_delta() -> None:
    a = [
        _ev("s3:GetObject", anomaly_score=0.2, anomaly_verdict="normal"),
        _ev("s3:GetObject", anomaly_score=0.3, anomaly_verdict="normal"),
    ]
    b = [
        _ev("iam:CreateUser",
            anomaly_score=0.85, anomaly_verdict="anomalous"),
        _ev("iam:PutUserPolicy",
            anomaly_score=0.75, anomaly_verdict="anomalous"),
    ]
    rd = compute_risk_delta(a, b)
    assert rd.reason is None
    assert rd.a == {
        "max_anomaly_score": 0.3,
        "mean_anomaly_score": 0.25,
        "anomalous_event_count": 0,
        "scored_event_count": 2,
    }
    assert rd.b["max_anomaly_score"] == 0.85
    assert rd.b["anomalous_event_count"] == 2
    assert rd.delta["max_score_delta"] == 0.55
    assert rd.delta["anomalous_count_delta"] == 2


# ---------------------------------------------------------------------------
# Narrowing
# ---------------------------------------------------------------------------


def test_narrow_intersection_empty_when_disjoint() -> None:
    a = [_ev("s3:GetObject", resource="arn:aws:s3:::b/k")]
    b = [_ev("ec2:DescribeInstances", resource="*")]
    nr = build_narrowing_policy(a, b, strategy="intersection")
    assert nr.strategy == "intersection"
    assert nr.policy == {"Version": "2012-10-17", "Statement": []}
    assert nr.action_count == 0
    assert nr.cannot_narrow_reason is not None
    assert "no overlapping actions" in nr.cannot_narrow_reason


def test_narrow_intersection_unions_resources() -> None:
    """Per the design spec the intersection strategy unions per-action
    resources from both sides so the resulting policy admits both
    sessions' observed behaviour."""
    a = [_ev("s3:PutObject", resource="arn:aws:s3:::reports/x")]
    b = [_ev("s3:PutObject", resource="arn:aws:s3:::reports/y")]
    nr = build_narrowing_policy(a, b, strategy="intersection")
    assert nr.action_count == 1
    stmt = nr.policy["Statement"][0]
    assert stmt["Action"] == ["s3:PutObject"]
    assert stmt["Resource"] == [
        "arn:aws:s3:::reports/x",
        "arn:aws:s3:::reports/y",
    ]


def test_narrow_union_covers_everything() -> None:
    a = [_ev("s3:GetObject", resource="arn:aws:s3:::b/k")]
    b = [_ev("ec2:DescribeInstances", resource="*")]
    nr = build_narrowing_policy(a, b, strategy="union")
    assert nr.action_count == 2
    actions = sorted(s["Action"][0] for s in nr.policy["Statement"])
    assert actions == ["ec2:DescribeInstances", "s3:GetObject"]
    assert nr.cannot_narrow_reason is None


def test_narrow_left_only_uses_a() -> None:
    a = [_ev("s3:GetObject", resource="arn:aws:s3:::b/k")]
    b = [_ev("ec2:DescribeInstances", resource="*")]
    nr = build_narrowing_policy(a, b, strategy="left")
    assert nr.action_count == 1
    assert nr.policy["Statement"][0]["Action"] == ["s3:GetObject"]


def test_narrow_right_only_uses_b() -> None:
    a = [_ev("s3:GetObject", resource="arn:aws:s3:::b/k")]
    b = [_ev("ec2:DescribeInstances", resource="*")]
    nr = build_narrowing_policy(a, b, strategy="right")
    assert nr.action_count == 1
    assert nr.policy["Statement"][0]["Action"] == ["ec2:DescribeInstances"]


def test_narrow_resource_missing_falls_back_to_star_and_notes() -> None:
    """When an event has NO resource, the narrowing policy MUST still
    be well-formed (Resource = ['*']) AND a note must surface so the
    operator knows the scope was observed broadly."""
    a = [_ev("ec2:DescribeRegions")]  # no resource
    nr = build_narrowing_policy(a, [], strategy="left")
    stmt = nr.policy["Statement"][0]
    assert stmt["Resource"] == ["*"]
    assert any("ec2:DescribeRegions" in n for n in nr.notes)


def test_narrow_drops_non_arn_hostname_resource() -> None:
    """UAT: the narrowed policy must never emit a non-ARN value (e.g. a dst
    hostname captured for an account-scope action) in an IAM Resource field —
    AWS rejects that. It must be normalized to '*' with an honest note."""
    # Account-scope action with only a dst hostname captured (no ARN).
    a = [_ev("s3:ListAllMyBuckets", host="s3.amazonaws.com")]
    nr = build_narrowing_policy(a, [], strategy="left")
    stmt = nr.policy["Statement"][0]
    # No hostname leaked into Resource; scoped to '*'.
    assert stmt["Resource"] == ["*"]
    assert all(r == "*" or r.startswith("arn:") for r in stmt["Resource"])
    assert any("not ARNs" in n and "s3.amazonaws.com" in n for n in nr.notes)


def test_narrow_keeps_real_arn_drops_hostname_when_mixed() -> None:
    """A real ARN is kept; a co-captured non-ARN value is dropped + noted."""
    a = [
        _ev("s3:GetObject", resource="arn:aws:s3:::bucket/key"),
        _ev("s3:GetObject", host="s3.amazonaws.com"),  # non-ARN, same action
    ]
    nr = build_narrowing_policy(a, [], strategy="left")
    stmt = nr.policy["Statement"][0]
    assert stmt["Resource"] == ["arn:aws:s3:::bucket/key"]
    assert all(r.startswith("arn:") for r in stmt["Resource"])


def test_narrow_rejects_unknown_strategy() -> None:
    import pytest
    with pytest.raises(ValueError):
        build_narrowing_policy([], [], strategy="closest_thing_to_sane")


# ---------------------------------------------------------------------------
# Top-level compose
# ---------------------------------------------------------------------------


def test_compute_agent_diff_returns_well_formed_doc() -> None:
    a = [
        _ev("s3:GetObject",
            resource="arn:aws:s3:::reports/x", verdict="allow"),
    ]
    b = [
        _ev("s3:GetObject",
            resource="arn:aws:s3:::reports/y", verdict="allow"),
        _ev("ec2:DescribeInstances",
            resource="*", verdict="deny",
            deny_reason="org_policy:no-ec2"),
    ]
    diff = compute_agent_diff(
        session_a_id="sess_a",
        events_a=a,
        session_b_id="sess_b",
        events_b=b,
        narrow="intersection",
    )
    assert isinstance(diff, AgentDiff)
    payload = diff.as_dict()
    # Top-level keys exist + match spec
    for key in (
        "sessions", "permission_delta", "decision_delta",
        "behavioral_delta", "risk_delta", "narrowing", "notes",
    ):
        assert key in payload
    assert payload["sessions"]["a"]["session_id"] == "sess_a"
    assert payload["sessions"]["b"]["events_analyzed"] == 2
    assert payload["narrowing"]["strategy"] == "intersection"
    # Intersection is s3:GetObject (both invoked it).
    assert payload["narrowing"]["action_count"] == 1
    stmt = payload["narrowing"]["policy"]["Statement"][0]
    assert stmt["Action"] == ["s3:GetObject"]
    # Decision delta surfaces the deny-reason that only B saw.
    assert payload["decision_delta"]["delta"][
        "deny_reasons_only_in_b"
    ] == ["org_policy:no-ec2"]


def test_compute_agent_diff_identical_sessions_yields_empty_deltas() -> None:
    e = [
        _ev("s3:GetObject",
            resource="arn:aws:s3:::b/k", verdict="allow"),
    ]
    diff = compute_agent_diff(
        session_a_id="sa",
        events_a=e,
        session_b_id="sb",
        events_b=e,
    )
    pd = diff.permission_delta
    assert pd.only_in_a == () and pd.only_in_b == ()
    assert len(pd.intersection) == 1
    assert diff.behavioral_delta.delta["total_calls_delta"] == 0
    # Identical sessions → no narrowing reason (intersection non-empty).
    assert diff.narrowing.cannot_narrow_reason is None
