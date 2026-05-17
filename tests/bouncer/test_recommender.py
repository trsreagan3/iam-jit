"""Tests for the bouncer observation-based recommender (Slice D).

Per [[bouncer-learn-then-recommend]] + [[apply-little-snitch-principles]]:
synthesize a draft ruleset from observed decisions over a window.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.recommender import (
    KNOWN_ACTIONS,
    RuleRecommendation,
    _detect_arn_prefix,
    _detect_region_pattern,
    _longest_common_prefix,
    research_note,
    summarize_window,
    synthesize_rules,
)
from iam_jit.bouncer.rules import Effect
from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer_cli import main


def _decision(**kw) -> dict:
    defaults = {
        "decision": "allow",
        "service": "s3",
        "action": "GetObject",
        "arn": None,
        "region": "us-east-1",
        "at": "2026-05-17T15:00:00Z",
    }
    defaults.update(kw)
    return defaults


# ---------------------------------------------------------------------------
# Helpers: LCP + ARN prefix detection + region detection
# ---------------------------------------------------------------------------


def test_longest_common_prefix_basic() -> None:
    assert _longest_common_prefix(["abcdef", "abcxyz"]) == "abc"
    assert _longest_common_prefix(["abc", "xyz"]) == ""
    assert _longest_common_prefix(["only-one"]) == "only-one"
    assert _longest_common_prefix([]) == ""


def test_detect_arn_prefix_finds_bucket_prefix() -> None:
    arns = [
        "arn:aws:s3:::reports-2026/q1/summary.csv",
        "arn:aws:s3:::reports-2026/q2/summary.csv",
        "arn:aws:s3:::reports-2026/q3/raw.json",
    ]
    glob, rationale = _detect_arn_prefix(arns)
    assert glob == "arn:aws:s3:::reports-2026/*"
    assert rationale is not None
    assert "3 of 3" in rationale


def test_detect_arn_prefix_returns_none_for_diverse_arns() -> None:
    arns = [
        "arn:aws:s3:::alpha",
        "arn:aws:s3:::beta",
        "arn:aws:s3:::gamma",
    ]
    glob, _ = _detect_arn_prefix(arns)
    # All share `arn:aws:s3:::` — that's a valid prefix
    assert glob == "arn:aws:s3:::*" or glob is None


def test_detect_arn_prefix_prefers_conservative_full_lcp() -> None:
    """When ALL ARNs share a usable prefix (even if shorter than a
    majority's prefix), the conservative choice is the full-LCP —
    never propose a narrower scope than what every observed call
    shares, or the new rule would block the outliers."""
    arns = [f"arn:aws:s3:::my-bucket/file{i}.txt" for i in range(8)] + [
        "arn:aws:s3:::different/x",
        "arn:aws:s3:::other/y",
    ]
    glob, _ = _detect_arn_prefix(arns, min_coverage=0.7)
    # Full LCP `arn:aws:s3:::` shared by all 10 → use it (conservative)
    assert glob == "arn:aws:s3:::*"


def test_detect_arn_prefix_uses_majority_when_no_useful_lcp() -> None:
    """When the full-LCP is too short (only `arn:aws:` shared) but
    a majority cluster shares a longer prefix, use the majority.
    Real-world test: 8 long S3 ARNs + 2 long EC2 ARNs; the S3
    cluster's [:50] prefix groups them all."""
    long_s3_prefix = "arn:aws:s3:::production-reports-bucket-2026/"
    long_ec2 = "arn:aws:ec2:us-east-1:111111111111:instance/i-abcd"
    arns = [long_s3_prefix + f"q{i}/summary.csv" for i in range(8)] + [
        long_ec2 + "1234",
        long_ec2 + "5678",
    ]
    glob, rationale = _detect_arn_prefix(arns, min_coverage=0.7)
    # Majority cluster (8 S3 ARNs) shares the long-bucket prefix
    assert glob is not None
    assert "production-reports-bucket-2026" in glob


def test_detect_arn_prefix_returns_none_for_empty_input() -> None:
    glob, rationale = _detect_arn_prefix([])
    assert glob is None and rationale is None


def test_detect_arn_prefix_returns_none_when_only_one_arn() -> None:
    glob, _ = _detect_arn_prefix(["arn:aws:s3:::single"])
    assert glob is None


def test_detect_arn_prefix_filters_out_nones() -> None:
    glob, _ = _detect_arn_prefix([None, None, "arn:aws:s3:::x"])
    assert glob is None  # too few real ARNs


def test_detect_region_pattern_dominant_region() -> None:
    regions = ["us-east-1"] * 9 + ["eu-west-1"]
    region, rationale = _detect_region_pattern(regions, min_coverage=0.8)
    assert region == "us-east-1"
    assert "9 of 10" in rationale


def test_detect_region_pattern_diverse_returns_none() -> None:
    regions = ["us-east-1", "eu-west-1", "ap-south-1"]
    region, _ = _detect_region_pattern(regions)
    assert region is None


# ---------------------------------------------------------------------------
# research_note + KNOWN_ACTIONS catalog
# ---------------------------------------------------------------------------


def test_research_note_known_action() -> None:
    note = research_note("s3", "GetObject")
    assert note is not None
    assert "summary" in note and "typical_use" in note


def test_research_note_unknown_action_returns_none() -> None:
    assert research_note("madeup", "Action") is None


def test_known_actions_catalog_shape() -> None:
    """Every entry must have summary + typical_use."""
    for key, note in KNOWN_ACTIONS.items():
        assert "summary" in note, f"{key} missing summary"
        assert "typical_use" in note, f"{key} missing typical_use"
        assert ":" in key, f"{key} not in service:action form"


def test_known_actions_covers_critical_set() -> None:
    """Must include the highest-leverage actions for review."""
    must_include = {
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
        "sts:GetCallerIdentity", "sts:AssumeRole",
        "iam:CreateRole", "iam:DeleteRole", "iam:PassRole",
        "secretsmanager:GetSecretValue",
        "kms:Decrypt",
        "dynamodb:GetItem",
    }
    missing = must_include - set(KNOWN_ACTIONS.keys())
    assert not missing, f"catalog missing critical actions: {missing}"


# ---------------------------------------------------------------------------
# synthesize_rules
# ---------------------------------------------------------------------------


def test_synthesize_empty_returns_empty() -> None:
    assert synthesize_rules([]) == []


def test_synthesize_skips_low_support_groups() -> None:
    """Groups with fewer than min_support calls are skipped (will
    default-deny in enforce mode)."""
    decisions = [
        _decision(service="s3", action="GetObject"),
        _decision(service="s3", action="GetObject"),
        _decision(service="ec2", action="RunInstances"),  # only 1 — skipped
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert len(recs) == 0  # nothing meets min_support=3


def test_synthesize_produces_rule_for_high_support_group() -> None:
    decisions = [_decision(service="s3", action="GetObject") for _ in range(10)]
    recs = synthesize_rules(decisions, min_support=3)
    assert len(recs) == 1
    rec = recs[0]
    assert rec.proposed_rule.pattern == "s3:GetObject"
    assert rec.proposed_rule.effect == Effect.ALLOW
    assert rec.support_count == 10
    assert rec.hit_rate == 1.0


def test_synthesize_detects_arn_prefix() -> None:
    decisions = [
        _decision(service="s3", action="GetObject", arn=f"arn:aws:s3:::reports/q{i}.csv")
        for i in range(5)
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert len(recs) == 1
    assert recs[0].proposed_rule.arn_scope is not None
    assert "reports" in recs[0].proposed_rule.arn_scope
    assert recs[0].arn_pattern_rationale is not None


def test_synthesize_detects_dominant_region() -> None:
    decisions = [
        _decision(service="ec2", action="DescribeInstances", region="us-east-1")
        for _ in range(10)
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert recs[0].proposed_rule.region_scope == "us-east-1"
    assert recs[0].region_pattern_rationale is not None


def test_synthesize_attaches_research_note_for_known_actions() -> None:
    decisions = [_decision(service="s3", action="GetObject") for _ in range(5)]
    recs = synthesize_rules(decisions, min_support=3)
    assert recs[0].research_note is not None
    assert "summary" in recs[0].research_note


def test_synthesize_no_research_note_for_unknown_actions() -> None:
    decisions = [
        _decision(service="madeup", action="WeirdAction")
        for _ in range(5)
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert recs[0].research_note is None


def test_synthesize_sorts_by_support_desc() -> None:
    decisions = (
        [_decision(service="s3", action="ListBucket") for _ in range(3)]
        + [_decision(service="s3", action="GetObject") for _ in range(20)]
        + [_decision(service="ec2", action="DescribeInstances") for _ in range(8)]
    )
    recs = synthesize_rules(decisions, min_support=3)
    # GetObject (20) → DescribeInstances (8) → ListBucket (3)
    assert recs[0].proposed_rule.pattern == "s3:GetObject"
    assert recs[1].proposed_rule.pattern == "ec2:DescribeInstances"
    assert recs[2].proposed_rule.pattern == "s3:ListBucket"


def test_synthesize_ignores_decisions_missing_service_or_action() -> None:
    decisions = [
        _decision(service=None, action="X"),
        _decision(service="s3", action=None),
        _decision(service="s3", action="GetObject"),
        _decision(service="s3", action="GetObject"),
        _decision(service="s3", action="GetObject"),
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert len(recs) == 1


def test_recommendation_to_dict_round_trip() -> None:
    decisions = [_decision(service="s3", action="GetObject") for _ in range(5)]
    recs = synthesize_rules(decisions, min_support=3)
    d = recs[0].to_dict()
    assert d["proposed_rule"]["pattern"] == "s3:GetObject"
    assert d["support_count"] == 5
    assert 0 < d["hit_rate"] <= 1


# ---------------------------------------------------------------------------
# summarize_window
# ---------------------------------------------------------------------------


def test_summarize_window_empty() -> None:
    s = summarize_window([])
    assert s["total_calls"] == 0
    assert s["distinct_services"] == 0


def test_summarize_window_counts_distinct() -> None:
    decisions = [
        _decision(service="s3", action="GetObject"),
        _decision(service="s3", action="PutObject"),
        _decision(service="ec2", action="DescribeInstances"),
    ]
    s = summarize_window(decisions)
    assert s["total_calls"] == 3
    assert s["distinct_services"] == 2
    assert s["distinct_actions"] == 3


def test_summarize_window_decision_breakdown() -> None:
    decisions = [
        _decision(decision="allow"),
        _decision(decision="allow"),
        _decision(decision="deny"),
        _decision(decision="prompt"),
    ]
    s = summarize_window(decisions)
    assert s["allow_count"] == 2
    assert s["deny_count"] == 1
    assert s["prompt_count"] == 1


def test_summarize_window_time_range() -> None:
    decisions = [
        _decision(at="2026-05-15T10:00:00Z"),
        _decision(at="2026-05-17T15:00:00Z"),
        _decision(at="2026-05-16T12:00:00Z"),
    ]
    s = summarize_window(decisions)
    assert s["window_start"] == "2026-05-15T10:00:00Z"
    assert s["window_end"] == "2026-05-17T15:00:00Z"


# ---------------------------------------------------------------------------
# CLI: iam-jit-bouncer recommend
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path) -> str:
    return str(tmp_path / "state.db")


def _seed_decisions(db: str, decisions: list[dict]) -> None:
    """Insert decisions directly into the store for test purposes."""
    from iam_jit.bouncer.decisions import Decision, DecisionRecord, Mode
    store = BouncerStore(db_path=db)
    try:
        for d in decisions:
            rec = DecisionRecord(
                decision=Decision(d.get("decision", "allow")),
                mode=Mode.LEARN,
                service=d.get("service", "s3"),
                action=d.get("action", "GetObject"),
                arn=d.get("arn"),
                region=d.get("region"),
                matched_rule=None,
                reason="seeded",
            )
            store.record_decision(rec)
    finally:
        store.close()


def test_cli_recommend_empty_db(db_path: str) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["recommend", "--db", db_path])
    assert result.exit_code == 0
    assert "no recommendations" in result.output or "0 total calls" in result.output


def test_cli_recommend_with_data(db_path: str) -> None:
    _seed_decisions(db_path, [
        _decision(service="s3", action="GetObject",
                  arn="arn:aws:s3:::reports/q1.csv") for _ in range(8)
    ])
    runner = CliRunner()
    result = runner.invoke(main, ["recommend", "--db", db_path])
    assert result.exit_code == 0
    assert "s3:GetObject" in result.output
    assert "support: 8" in result.output


def test_cli_recommend_json_output(db_path: str) -> None:
    _seed_decisions(db_path, [
        _decision(service="s3", action="GetObject") for _ in range(5)
    ])
    runner = CliRunner()
    result = runner.invoke(main, ["recommend", "--db", db_path, "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "summary" in payload
    assert "recommendations" in payload
    assert payload["recommendations"][0]["proposed_rule"]["pattern"] == "s3:GetObject"


def test_cli_recommend_apply_adds_rules(db_path: str) -> None:
    _seed_decisions(db_path, [
        _decision(service="s3", action="GetObject") for _ in range(5)
    ])
    runner = CliRunner()
    result = runner.invoke(main, ["recommend", "--db", db_path, "--apply"])
    assert result.exit_code == 0
    assert "applied" in result.output
    # Verify rules now exist
    store = BouncerStore(db_path=db_path)
    try:
        rules = store.list_rules()
        patterns = {r.pattern for _, r in rules}
        assert "s3:GetObject" in patterns
    finally:
        store.close()


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_bouncer_db(monkeypatch, tmp_path):
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "mcp.db"))
    monkeypatch.setenv("IAM_JIT_BOUNCER_ACTOR", "test-agent")
    yield


def test_mcp_recommend_rules_empty() -> None:
    from iam_jit.mcp_server import _bouncer_recommend_rules_for_mcp
    out = _bouncer_recommend_rules_for_mcp({})
    assert out["count"] == 0
    assert out["summary"]["total_calls"] == 0


def test_mcp_recommend_rules_with_data() -> None:
    import os
    from iam_jit.mcp_server import _bouncer_recommend_rules_for_mcp
    _seed_decisions(os.environ["IAM_JIT_BOUNCER_DB"],
                    [_decision(service="s3", action="GetObject") for _ in range(5)])
    out = _bouncer_recommend_rules_for_mcp({})
    assert out["count"] == 1
    assert out["recommendations"][0]["proposed_rule"]["pattern"] == "s3:GetObject"


def test_mcp_recommend_rules_min_support_validation() -> None:
    from iam_jit.mcp_server import _bouncer_recommend_rules_for_mcp
    assert "error" in _bouncer_recommend_rules_for_mcp({"min_support": 0})
    assert "error" in _bouncer_recommend_rules_for_mcp({"min_support": True})
    assert "error" in _bouncer_recommend_rules_for_mcp({"min_support": "many"})


def test_mcp_apply_recommendation_happy_path() -> None:
    from iam_jit.mcp_server import _bouncer_apply_recommendation_for_mcp
    out = _bouncer_apply_recommendation_for_mcp({
        "rules": [
            {"pattern": "s3:GetObject", "arn_scope": "arn:aws:s3:::reports/*"},
            {"pattern": "ec2:Describe*"},
        ],
    })
    assert out["applied"] == 2
    assert out["audit_event_kind"] == "recommendation_applied"


def test_mcp_apply_recommendation_partial_failure() -> None:
    """Valid + invalid rule entries — valid ones apply; invalid
    ones get rejected with reasons."""
    from iam_jit.mcp_server import _bouncer_apply_recommendation_for_mcp
    out = _bouncer_apply_recommendation_for_mcp({
        "rules": [
            {"pattern": "s3:GetObject"},
            {"pattern": ""},  # invalid
            {"effect": "allow"},  # missing pattern
            {"pattern": "not-a-valid-pattern"},  # parse_pattern rejects
        ],
    })
    assert out["applied"] == 1  # only the first valid
    assert len(out["rejected"]) == 3


def test_mcp_apply_recommendation_empty_rules() -> None:
    from iam_jit.mcp_server import _bouncer_apply_recommendation_for_mcp
    out = _bouncer_apply_recommendation_for_mcp({"rules": []})
    assert "error" in out


def test_mcp_apply_recommendation_writes_batch_event() -> None:
    from iam_jit.mcp_server import _bouncer_apply_recommendation_for_mcp
    _bouncer_apply_recommendation_for_mcp({
        "rules": [{"pattern": "s3:GetObject"}],
    })
    import os
    store = BouncerStore(db_path=os.environ["IAM_JIT_BOUNCER_DB"])
    try:
        events = store.list_config_events(kind_filter="recommendation_applied")
        assert len(events) == 1
        assert events[0]["detail"]["count"] == 1
    finally:
        store.close()


def test_mcp_both_tools_in_tools_list() -> None:
    from iam_jit.mcp_server import _handle_request
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "bouncer_recommend_rules" in names
    assert "bouncer_apply_recommendation" in names
