"""#722 / BUILD-1 — integration tests for `iam-jit agent-diff`.

Covers four scenarios per the design memo's honesty bar:

1. Identical sessions — empty deltas, narrowing.intersection non-empty,
   intersection == union by action set.
2. Disjoint sessions — only_in_a + only_in_b populated; intersection
   empty; narrowing.policy.Statement empty; cannot_narrow_reason set.
3. Resource-scope difference — both sessions touch `s3:PutObject` but
   A uses `arn:aws:s3:::reports/*` while B wildcards. Intersection
   narrowing surfaces both resource sets in the row + unions them in
   the policy.
4. Risk delta meaningful — A's events baseline-normal; B's events
   carry anomalous scores. `risk_delta.delta.max_score_delta` surfaces
   the gap; when no scores present, reason field is set honestly.

Each scenario stubs the per-bouncer HTTP layer the same way the
profile-generate integration tests do, so the test does NOT require
live bouncer binaries. Asserts BOTH the output shape AND the content
per [[uat-tests-setup-end-to-end]].
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner

import iam_jit.cli_audit_query as _audit_query_mod
from iam_jit.cli_agent_diff import agent_diff_command


_T_BASE = 1737590400000  # 2026-01-23T00:00:00Z


def _ev(
    *,
    session: str,
    action: str,
    resource: str | None = None,
    verdict: str = "allow",
    deny_reason: str | None = None,
    principal: str = "agent",
    host: str | None = None,
    anomaly_score: float | None = None,
    anomaly_verdict: str | None = None,
    t_offset: int = 0,
) -> dict[str, Any]:
    """Minimal OCSF-shaped event the diff lib can read."""
    service, op = action.split(":", 1)
    ev: dict[str, Any] = {
        "_bouncer": "ibounce",
        "time": _T_BASE + t_offset,
        "metadata": {"product": {"name": "ibounce"}},
        "api": {"operation": action, "service": {"name": service}},
        "actor": {"user": {"uid": principal}},
        "unmapped": {"iam_jit": {
            "verdict": verdict,
            "agent": {"session_id": session, "name": principal},
        }},
    }
    if resource:
        ev["resources"] = [{"uid": resource, "name": resource}]
    if deny_reason:
        ev["unmapped"]["iam_jit"]["deny_reason"] = deny_reason
    if host:
        ev["dst_endpoint"] = {"hostname": host}
    if anomaly_score is not None:
        ev["unmapped"]["iam_jit"]["anomaly_score"] = anomaly_score
    if anomaly_verdict:
        ev["unmapped"]["iam_jit"]["anomaly_verdict"] = anomaly_verdict
    return ev


# ---------------------------------------------------------------------------
# Stub the per-bouncer urlopen: parses the ?filter=session_id= and
# returns only the matching events for that session. This makes the
# diff's per-session fan-out exercise the real session-id wiring.
# ---------------------------------------------------------------------------


def _install_urlopen_stub(monkeypatch, events_by_session: dict[str, list[dict]]):
    class _FakeResp:
        def __init__(self, body: bytes) -> None:
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self._body

    def _stub(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        # Parse the session_id filter out of the URL query string.
        match_session = None
        for piece in url.split("&"):
            if "filter=" in piece:
                # The fan-out sends
                # filter=unmapped.iam_jit.agent.session_id=<session>
                token = piece.split("filter=", 1)[1]
                from urllib.parse import unquote
                token = unquote(token)
                if "session_id=" in token:
                    match_session = token.split("session_id=", 1)[1]
                    break
        # Only the ibounce port (8767) responds; the other 3 default
        # bouncers return an empty NDJSON so the test exercises the
        # "unreachable-bouncer surfaces as empty side" path too.
        if ":8767" not in url:
            return _FakeResp(b"")
        events = events_by_session.get(match_session or "", [])
        body = "\n".join(json.dumps(e) for e in events).encode("utf-8")
        return _FakeResp(body)

    monkeypatch.setattr(_audit_query_mod, "_urlopen", _stub)


# ---------------------------------------------------------------------------
# Scenario 1 — identical sessions
# ---------------------------------------------------------------------------


def test_e2e_identical_sessions_yield_empty_deltas(monkeypatch) -> None:
    """Both sessions made the same calls; deltas are empty; the
    narrowed policy carries the shared actions."""
    sess_a = "sess_id_a"
    sess_b = "sess_id_b"
    shared_events_a = [
        _ev(session=sess_a, action="s3:GetObject",
            resource="arn:aws:s3:::reports/key1"),
        _ev(session=sess_a, action="dynamodb:GetItem",
            resource="arn:aws:dynamodb:us-east-1:111:table/data",
            t_offset=10),
    ]
    shared_events_b = [
        _ev(session=sess_b, action="s3:GetObject",
            resource="arn:aws:s3:::reports/key1"),
        _ev(session=sess_b, action="dynamodb:GetItem",
            resource="arn:aws:dynamodb:us-east-1:111:table/data",
            t_offset=10),
    ]
    _install_urlopen_stub(monkeypatch, {
        sess_a: shared_events_a,
        sess_b: shared_events_b,
    })

    runner = CliRunner()
    result = runner.invoke(
        agent_diff_command,
        [sess_a, sess_b, "--bouncer", "ibounce", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)

    # Shape
    assert payload["sessions"]["a"]["session_id"] == sess_a
    assert payload["sessions"]["b"]["session_id"] == sess_b
    assert payload["sessions"]["a"]["events_analyzed"] == 2
    assert payload["sessions"]["b"]["events_analyzed"] == 2

    # Permission delta — empty only_in_* + 2-row intersection
    pd = payload["permission_delta"]
    assert pd["only_in_a"] == []
    assert pd["only_in_b"] == []
    inter_actions = sorted(r["action"] for r in pd["intersection"])
    assert inter_actions == ["dynamodb:GetItem", "s3:GetObject"]

    # Behavioral delta — all zeros
    bd = payload["behavioral_delta"]["delta"]
    assert bd["total_calls_delta"] == 0
    assert bd["distinct_actions_delta"] == 0

    # Decisions — both sides allow, no denies
    dd = payload["decision_delta"]
    assert dd["a"]["allow_count"] == 2 and dd["a"]["deny_count"] == 0
    assert dd["b"]["allow_count"] == 2 and dd["b"]["deny_count"] == 0

    # Narrowing — non-empty + 2 actions
    n = payload["narrowing"]
    assert n["strategy"] == "intersection"
    assert n["action_count"] == 2
    assert n["cannot_narrow_reason"] is None
    actions_in_policy = sorted(s["Action"][0] for s in n["policy"]["Statement"])
    assert actions_in_policy == ["dynamodb:GetItem", "s3:GetObject"]


# ---------------------------------------------------------------------------
# Scenario 2 — disjoint sessions
# ---------------------------------------------------------------------------


def test_e2e_disjoint_sessions_full_divergence(monkeypatch) -> None:
    """Session A makes 5 calls, session B makes 5 different calls.
    only_in_a + only_in_b populated; intersection empty; narrowing
    surfaces honest cannot_narrow_reason."""
    sess_a = "sess_claude_div"
    sess_b = "sess_codex_div"
    events_a = [
        _ev(session=sess_a, action="s3:GetObject",
            resource=f"arn:aws:s3:::a-bucket/k{i}", t_offset=i)
        for i in range(3)
    ] + [
        _ev(session=sess_a, action="s3:ListBucket",
            resource="arn:aws:s3:::a-bucket", t_offset=5),
        _ev(session=sess_a, action="dynamodb:GetItem",
            resource="arn:aws:dynamodb:us-east-1:111:table/a", t_offset=6),
    ]
    events_b = [
        _ev(session=sess_b, action="ec2:DescribeInstances",
            resource="*", t_offset=i)
        for i in range(3)
    ] + [
        _ev(session=sess_b, action="ec2:DescribeRegions",
            resource="*", t_offset=4),
        _ev(session=sess_b, action="iam:ListRoles",
            resource="*", t_offset=5),
    ]
    _install_urlopen_stub(monkeypatch, {sess_a: events_a, sess_b: events_b})

    runner = CliRunner()
    result = runner.invoke(
        agent_diff_command,
        [sess_a, sess_b, "--bouncer", "ibounce", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)

    pd = payload["permission_delta"]
    a_only = sorted(r["action"] for r in pd["only_in_a"])
    b_only = sorted(r["action"] for r in pd["only_in_b"])
    assert a_only == ["dynamodb:GetItem", "s3:GetObject", "s3:ListBucket"]
    assert b_only == [
        "ec2:DescribeInstances", "ec2:DescribeRegions", "iam:ListRoles",
    ]
    assert pd["intersection"] == []

    # Narrowing strategy = intersection (default) → empty Statement +
    # honest reason set; the policy is still well-formed JSON.
    n = payload["narrowing"]
    assert n["action_count"] == 0
    assert n["policy"] == {"Version": "2012-10-17", "Statement": []}
    assert n["cannot_narrow_reason"]
    assert "no overlapping actions" in n["cannot_narrow_reason"]


def test_e2e_disjoint_sessions_union_narrowing_recovers(monkeypatch) -> None:
    """With --narrow union the same disjoint sessions yield a
    well-formed policy covering both sides — no cannot_narrow_reason."""
    sess_a = "sess_disjoint_u_a"
    sess_b = "sess_disjoint_u_b"
    events_a = [_ev(session=sess_a, action="s3:GetObject",
                    resource="arn:aws:s3:::a/k")]
    events_b = [_ev(session=sess_b, action="ec2:DescribeInstances",
                    resource="*")]
    _install_urlopen_stub(monkeypatch, {sess_a: events_a, sess_b: events_b})

    runner = CliRunner()
    result = runner.invoke(
        agent_diff_command,
        [
            sess_a, sess_b, "--bouncer", "ibounce",
            "--format", "json", "--narrow", "union",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    n = payload["narrowing"]
    assert n["strategy"] == "union"
    assert n["action_count"] == 2
    assert n["cannot_narrow_reason"] is None


# ---------------------------------------------------------------------------
# Scenario 3 — resource-scope difference (the narrowing-demo case)
# ---------------------------------------------------------------------------


def test_e2e_resource_scope_difference_intersection_surface(monkeypatch) -> None:
    """Both sessions invoke s3:PutObject; A scopes to a tight prefix
    while B wildcards. The intersection row surfaces both resource
    sets so the operator can see the difference + the narrowing
    policy unions them so the resulting policy admits both observed
    behaviours."""
    sess_a = "sess_tight"
    sess_b = "sess_wide"
    events_a = [
        _ev(session=sess_a, action="s3:PutObject",
            resource="arn:aws:s3:::reports/2026/q2/a.csv"),
        _ev(session=sess_a, action="s3:PutObject",
            resource="arn:aws:s3:::reports/2026/q2/b.csv"),
    ]
    events_b = [
        _ev(session=sess_b, action="s3:PutObject",
            resource="arn:aws:s3:::*"),
    ]
    _install_urlopen_stub(monkeypatch, {sess_a: events_a, sess_b: events_b})

    runner = CliRunner()
    result = runner.invoke(
        agent_diff_command,
        [sess_a, sess_b, "--bouncer", "ibounce", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)

    pd = payload["permission_delta"]
    assert len(pd["intersection"]) == 1
    row = pd["intersection"][0]
    assert row["action"] == "s3:PutObject"
    # Per-side resources are visible
    assert row["resources_a"] == [
        "arn:aws:s3:::reports/2026/q2/a.csv",
        "arn:aws:s3:::reports/2026/q2/b.csv",
    ]
    assert row["resources_b"] == ["arn:aws:s3:::*"]
    assert row["count_a"] == 2
    assert row["count_b"] == 1

    # Narrowing policy unions per-action resources so the result
    # admits both observed behaviours.
    n = payload["narrowing"]
    assert n["action_count"] == 1
    stmt = n["policy"]["Statement"][0]
    assert stmt["Action"] == ["s3:PutObject"]
    assert stmt["Resource"] == [
        "arn:aws:s3:::*",
        "arn:aws:s3:::reports/2026/q2/a.csv",
        "arn:aws:s3:::reports/2026/q2/b.csv",
    ]


# ---------------------------------------------------------------------------
# Scenario 4 — risk delta meaningful
# ---------------------------------------------------------------------------


def test_e2e_risk_delta_meaningful_when_scores_present(monkeypatch) -> None:
    """Session A is baseline-normal; session B carries anomalous
    scores. The risk-delta surfaces a real max_score_delta + a
    nonzero anomalous_count_delta."""
    sess_a = "sess_normal_baseline"
    sess_b = "sess_anomaly_spike"
    events_a = [
        _ev(session=sess_a, action="s3:GetObject",
            resource="arn:aws:s3:::reports/k",
            anomaly_score=0.15, anomaly_verdict="normal", t_offset=i)
        for i in range(3)
    ]
    events_b = [
        _ev(session=sess_b, action="iam:CreateUser",
            resource="arn:aws:iam::111:user/x",
            anomaly_score=0.91, anomaly_verdict="anomalous"),
        _ev(session=sess_b, action="iam:PutUserPolicy",
            resource="arn:aws:iam::111:user/x",
            anomaly_score=0.85, anomaly_verdict="anomalous", t_offset=1),
    ]
    _install_urlopen_stub(monkeypatch, {sess_a: events_a, sess_b: events_b})

    runner = CliRunner()
    result = runner.invoke(
        agent_diff_command,
        [sess_a, sess_b, "--bouncer", "ibounce", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)

    rd = payload["risk_delta"]
    assert rd["reason"] is None
    assert rd["a"]["max_anomaly_score"] == 0.15
    assert rd["a"]["anomalous_event_count"] == 0
    assert rd["b"]["max_anomaly_score"] == 0.91
    assert rd["b"]["anomalous_event_count"] == 2
    assert rd["delta"]["max_score_delta"] == pytest.approx(0.76, rel=1e-3)
    assert rd["delta"]["anomalous_count_delta"] == 2


def test_e2e_risk_delta_honest_when_no_scores(monkeypatch) -> None:
    """Per [[ibounce-honest-positioning]] + [[scorer-is-ground-truth]]:
    when neither side carries anomaly_score, the risk-delta surfaces
    a reason field — never invented scores."""
    sess_a = "sess_no_scores_a"
    sess_b = "sess_no_scores_b"
    events_a = [_ev(session=sess_a, action="s3:GetObject",
                    resource="arn:aws:s3:::a/k")]
    events_b = [_ev(session=sess_b, action="s3:GetObject",
                    resource="arn:aws:s3:::a/k")]
    _install_urlopen_stub(monkeypatch, {sess_a: events_a, sess_b: events_b})

    runner = CliRunner()
    result = runner.invoke(
        agent_diff_command,
        [sess_a, sess_b, "--bouncer", "ibounce", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    rd = payload["risk_delta"]
    assert rd["a"] is None and rd["b"] is None
    assert rd["reason"] == "anomaly_scoring_unavailable_for_protocol"


# ---------------------------------------------------------------------------
# Format coverage — markdown render carries the IAM policy + the
# narrowed-policy reason when empty.
# ---------------------------------------------------------------------------


def test_e2e_markdown_format_emits_real_iam_policy_block(monkeypatch) -> None:
    sess_a = "sess_md_a"
    sess_b = "sess_md_b"
    events_a = [_ev(session=sess_a, action="s3:GetObject",
                    resource="arn:aws:s3:::reports/x")]
    events_b = [_ev(session=sess_b, action="s3:GetObject",
                    resource="arn:aws:s3:::reports/x")]
    _install_urlopen_stub(monkeypatch, {sess_a: events_a, sess_b: events_b})

    runner = CliRunner()
    result = runner.invoke(
        agent_diff_command,
        [
            sess_a, sess_b, "--bouncer", "ibounce",
            "--format", "markdown",
        ],
    )
    assert result.exit_code == 0, result.output
    # Real json policy fenced block, real Allow + Action
    assert "```json" in result.output
    assert '"Version": "2012-10-17"' in result.output
    assert '"Action": [' in result.output
    assert "s3:GetObject" in result.output


# ---------------------------------------------------------------------------
# MCP backend parity — same scenarios surface the same payload shape.
# ---------------------------------------------------------------------------


def test_e2e_mcp_backend_payload_shape_matches_cli(monkeypatch) -> None:
    """The `iam_jit_agent_diff` MCP backend produces the same shape +
    sub-deltas as the CLI for the same input. Per
    [[cross-product-agent-parity]] this is a HARD invariant."""
    from iam_jit.mcp_server import _iam_jit_agent_diff_for_mcp

    sess_a = "sess_mcp_a"
    sess_b = "sess_mcp_b"
    events_a = [_ev(session=sess_a, action="s3:GetObject",
                    resource="arn:aws:s3:::a/k1")]
    events_b = [
        _ev(session=sess_b, action="s3:GetObject",
            resource="arn:aws:s3:::a/k2"),
        _ev(session=sess_b, action="s3:DeleteObject",
            resource="arn:aws:s3:::a/k2"),
    ]
    _install_urlopen_stub(monkeypatch, {sess_a: events_a, sess_b: events_b})

    payload = _iam_jit_agent_diff_for_mcp({
        "session_a": sess_a,
        "session_b": sess_b,
        "bouncer": "ibounce",
        "since": "1h",
    })
    assert payload["status"] == "ok"
    for key in (
        "sessions", "permission_delta", "decision_delta",
        "behavioral_delta", "risk_delta", "narrowing",
    ):
        assert key in payload, f"missing top-level key {key!r}"

    # Scope filter on MCP side too — only the requested sub-delta lands.
    scoped = _iam_jit_agent_diff_for_mcp({
        "session_a": sess_a,
        "session_b": sess_b,
        "bouncer": "ibounce",
        "scope": "permissions",
    })
    assert "permission_delta" in scoped
    assert "decision_delta" not in scoped
    assert "behavioral_delta" not in scoped


def test_e2e_mcp_backend_rejects_missing_session() -> None:
    from iam_jit.mcp_server import _iam_jit_agent_diff_for_mcp
    out = _iam_jit_agent_diff_for_mcp({"session_b": "x"})
    assert out["status"] == "error"
    assert out["code"] == "missing_session_a"
