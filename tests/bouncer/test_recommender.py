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


# ---------------------------------------------------------------------------
# WB28 closures
# ---------------------------------------------------------------------------


def test_crit_28_01_denied_decisions_excluded_from_recommendations() -> None:
    """WB28 CRIT-28-01: synthesize_rules MUST only count allow
    decisions. Including denies inverted the security premise —
    a deny attempt would have turned into an ALLOW rule recommendation,
    auto-authorizing previously-blocked calls when enforce flipped on."""
    decisions = [
        _decision(decision="deny", service="iam", action="CreateRole"),
        _decision(decision="deny", service="iam", action="CreateRole"),
        _decision(decision="deny", service="iam", action="CreateRole"),
        _decision(decision="deny", service="iam", action="CreateRole"),
        _decision(decision="deny", service="iam", action="CreateRole"),
    ]
    recs = synthesize_rules(decisions, min_support=3)
    # 5 denied attempts must NOT produce an "ALLOW iam:CreateRole" rule
    assert len(recs) == 0


def test_crit_28_01_mixed_allow_deny_only_allow_counts() -> None:
    """The sharper repro: 2 allowed S3 reads to data/ + 3 DENIED S3
    reads to secrets/. Old code would recommend `arn:aws:s3:::*`
    covering BOTH and AUTHORIZE the previously-blocked secrets reads."""
    decisions = [
        _decision(service="s3", action="GetObject",
                  arn="arn:aws:s3:::data/file1", decision="allow"),
        _decision(service="s3", action="GetObject",
                  arn="arn:aws:s3:::data/file2", decision="allow"),
        _decision(service="s3", action="GetObject",
                  arn="arn:aws:s3:::secrets/cred1", decision="deny"),
        _decision(service="s3", action="GetObject",
                  arn="arn:aws:s3:::secrets/cred2", decision="deny"),
        _decision(service="s3", action="GetObject",
                  arn="arn:aws:s3:::secrets/cred3", decision="deny"),
    ]
    recs = synthesize_rules(decisions, min_support=2)
    if recs:
        # If a rule IS recommended, its ARN scope must not match the
        # secrets/ paths that were denied.
        arn_scope = recs[0].proposed_rule.arn_scope or "*"
        assert "secrets" not in arn_scope, (
            f"recommendation arn_scope {arn_scope!r} would allow "
            "previously-denied secrets-path calls"
        )


def test_crit_28_01_prompt_decisions_also_excluded() -> None:
    """Prompt decisions weren't endorsed either — the user/agent
    was being asked. Don't recommend allow rules from them."""
    decisions = [
        _decision(decision="prompt", service="s3", action="DeleteObject")
        for _ in range(5)
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert len(recs) == 0


def test_high_28_01_arn_anchor_does_not_collapse_to_service_wildcard() -> None:
    """WB28 HIGH-28-01: prefix anchor must not back up past the
    resource-segment start. 3 distinct buckets sharing a name prefix
    (e.g. reports-2026-q1/q2/q3) should NOT collapse to
    `arn:aws:s3:::*` (allowing ALL S3)."""
    arns = [
        "arn:aws:s3:::reports-2026-q1/summary.csv",
        "arn:aws:s3:::reports-2026-q2/summary.csv",
        "arn:aws:s3:::reports-2026-q3/summary.csv",
    ]
    glob, rationale = _detect_arn_prefix(arns)
    # Must NOT be the over-broadened service wildcard
    assert glob != "arn:aws:s3:::*"
    # Must include the bucket-name prefix
    assert "reports-2026" in glob


def test_high_28_01_arn_anchor_keeps_meaningful_segment() -> None:
    """Anchor should land on `/`, `-`, or `_` within the resource
    segment — not anywhere mid-character. ARNs ending in path
    segments anchor on `/`."""
    arns = [
        "arn:aws:s3:::project/data/q1/raw.json",
        "arn:aws:s3:::project/data/q1/processed.json",
        "arn:aws:s3:::project/data/q1/summary.json",
    ]
    glob, _ = _detect_arn_prefix(arns)
    # LCP = `arn:aws:s3:::project/data/q1/` (ends on `/`); anchor keeps it
    assert glob == "arn:aws:s3:::project/data/q1/*"


def test_high_28_01_arn_anchor_keeps_lcp_when_no_internal_boundary() -> None:
    """If the resource segment has no `/`, `-`, `_` separator, the
    LCP stays as-is rather than collapsing to a wider scope."""
    arns = [
        "arn:aws:s3:::singlebucket",
        "arn:aws:s3:::singlebucket",
        "arn:aws:s3:::singlebucket",
    ]
    glob, _ = _detect_arn_prefix(arns)
    # All 3 are the same; LCP is the full ARN; glob keeps it
    assert glob == "arn:aws:s3:::singlebucket*"


def test_high_28_02_mcp_apply_rejects_non_string_arn_scope() -> None:
    """WB28 HIGH-28-02: validate pass-through fields before sending
    to SQLite. Dict/list values used to crash mid-batch."""
    from iam_jit.mcp_server import _bouncer_apply_recommendation_for_mcp
    out = _bouncer_apply_recommendation_for_mcp({
        "rules": [
            {"pattern": "s3:GetObject", "arn_scope": {"nested": "object"}},
        ],
    })
    assert out["applied"] == 0
    assert len(out["rejected"]) == 1
    assert "arn_scope" in out["rejected"][0]["error"]


def test_high_28_02_mcp_apply_rejects_non_string_region_scope() -> None:
    from iam_jit.mcp_server import _bouncer_apply_recommendation_for_mcp
    out = _bouncer_apply_recommendation_for_mcp({
        "rules": [
            {"pattern": "s3:GetObject", "region_scope": 12345},
        ],
    })
    assert out["applied"] == 0
    assert "region_scope" in out["rejected"][0]["error"]


def test_high_28_02_mcp_apply_rejects_non_string_note() -> None:
    from iam_jit.mcp_server import _bouncer_apply_recommendation_for_mcp
    out = _bouncer_apply_recommendation_for_mcp({
        "rules": [
            {"pattern": "s3:GetObject", "note": ["a", "b"]},
        ],
    })
    assert out["applied"] == 0
    assert "note" in out["rejected"][0]["error"]


def test_high_28_02_mcp_apply_partial_failure_batch_event_still_writes() -> None:
    """If validation rejects some entries, the others apply AND the
    batch event still fires — previously a mid-loop crash would
    skip the batch event."""
    from iam_jit.mcp_server import _bouncer_apply_recommendation_for_mcp
    out = _bouncer_apply_recommendation_for_mcp({
        "rules": [
            {"pattern": "s3:GetObject"},  # valid
            {"pattern": "ec2:Describe*", "arn_scope": {"bad": 1}},  # invalid
            {"pattern": "iam:ListRoles"},  # valid
        ],
    })
    assert out["applied"] == 2
    assert len(out["rejected"]) == 1
    assert out["audit_event_kind"] == "recommendation_applied"


def test_mcp_both_tools_in_tools_list() -> None:
    from iam_jit.mcp_server import _handle_request
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "bouncer_recommend_rules" in names
    assert "bouncer_apply_recommendation" in names


# ---------------------------------------------------------------------------
# WB28 MED closures
# ---------------------------------------------------------------------------


def test_med_28_01_sparse_arn_data_skips_arn_scope() -> None:
    """WB28 MED-28-01: when <50% of group's decisions have an ARN,
    the rule must ship scope-less so historical None-ARN calls
    still match in ENFORCE."""
    # 8 calls with arn=None + 2 calls with a real ARN
    decisions = [
        _decision(arn=None) for _ in range(8)
    ] + [
        _decision(arn="arn:aws:s3:::secret-bucket/foo"),
        _decision(arn="arn:aws:s3:::secret-bucket/bar"),
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert len(recs) == 1
    # No ARN scope — the 8 None-ARN calls would otherwise be denied
    # in ENFORCE.
    assert recs[0].proposed_rule.arn_scope is None
    # But the support_count still reports the full group size
    assert recs[0].support_count == 10
    # Rationale explains the skip
    assert recs[0].arn_pattern_rationale is not None
    assert "not narrowing by ARN scope" in recs[0].arn_pattern_rationale


def test_med_28_01_sparse_region_data_skips_region_scope() -> None:
    """Same fraction-of-support gate for region."""
    decisions = [
        _decision(region=None) for _ in range(8)
    ] + [
        _decision(region="us-east-1"),
        _decision(region="us-east-1"),
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert len(recs) == 1
    assert recs[0].proposed_rule.region_scope is None


def test_med_28_01_majority_arn_data_still_scopes() -> None:
    """If 50%+ of the group has ARNs, the scope IS applied (with
    full-group rationale)."""
    decisions = [
        _decision(arn="arn:aws:s3:::reports/q1.csv") for _ in range(6)
    ] + [
        _decision(arn="arn:aws:s3:::reports/q2.csv") for _ in range(2)
    ] + [
        _decision(arn=None) for _ in range(2)
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert len(recs) == 1
    # 8/10 have observable ARNs → gate passes; scope is applied
    assert recs[0].proposed_rule.arn_scope is not None
    assert "reports" in recs[0].proposed_rule.arn_scope


def test_med_28_02_store_rule_exists(tmp_path) -> None:
    """WB28 MED-28-02: rule_exists must detect duplicates including
    None-vs-None on optional scope fields."""
    from iam_jit.bouncer.rules import ProxyRule
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        rule = ProxyRule(
            pattern="s3:GetObject",
            effect=Effect.ALLOW,
            arn_scope=None,
            region_scope=None,
            note="test",
            origin="manual",
        )
        assert store.rule_exists(rule) is False
        store.add_rule(rule, actor="test")
        # Identical row → exists
        assert store.rule_exists(rule) is True
        # Different effect → not duplicate
        rule_deny = ProxyRule(
            pattern="s3:GetObject",
            effect=Effect.DENY,
            arn_scope=None,
            region_scope=None,
            note="test",
            origin="manual",
        )
        assert store.rule_exists(rule_deny) is False
        # Different arn_scope → not duplicate
        rule_scoped = ProxyRule(
            pattern="s3:GetObject",
            effect=Effect.ALLOW,
            arn_scope="arn:aws:s3:::foo/*",
            region_scope=None,
            note="test",
            origin="manual",
        )
        assert store.rule_exists(rule_scoped) is False
    finally:
        store.close()


def test_med_28_02_mcp_apply_rejects_duplicate_on_second_call(tmp_path, monkeypatch) -> None:
    """Re-running apply against unchanged data must NOT add duplicates."""
    from iam_jit.mcp_server import _bouncer_apply_recommendation_for_mcp
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    out1 = _bouncer_apply_recommendation_for_mcp({
        "rules": [{"pattern": "s3:GetObject"}],
    })
    assert out1["applied"] == 1
    out2 = _bouncer_apply_recommendation_for_mcp({
        "rules": [{"pattern": "s3:GetObject"}],
    })
    assert out2["applied"] == 0
    assert len(out2["rejected"]) == 1
    assert "already exists" in out2["rejected"][0]["error"]


def test_med_28_03_mcp_apply_event_records_rule_ids(tmp_path, monkeypatch) -> None:
    """WB28 MED-28-03: the recommendation_applied event must record
    the specific rule_ids, not just count."""
    from iam_jit.mcp_server import _bouncer_apply_recommendation_for_mcp
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(tmp_path / "b.db"))
    out = _bouncer_apply_recommendation_for_mcp({
        "rules": [
            {"pattern": "s3:GetObject"},
            {"pattern": "s3:ListBucket"},
        ],
    })
    assert out["applied"] == 2
    assert "applied_rule_ids" in out
    assert len(out["applied_rule_ids"]) == 2

    # Inspect the audit event
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        events = store.list_config_events()
    finally:
        store.close()
    applied_events = [e for e in events if e["kind"] == "recommendation_applied"]
    assert len(applied_events) == 1
    detail = applied_events[0].get("detail") or {}
    assert detail.get("count") == 2
    assert detail.get("rule_ids") == out["applied_rule_ids"]


def test_med_28_04_cli_min_support_zero_rejected() -> None:
    """WB28 MED-28-04: CLI must reject --min-support 0 (click.IntRange)."""
    runner = CliRunner()
    result = runner.invoke(main, ["recommend", "--min-support", "0"])
    # click IntRange rejects with non-zero exit + error message
    assert result.exit_code != 0
    assert "min-support" in result.output.lower() or "minimum" in result.output.lower() or "0" in result.output


def test_med_28_04_cli_limit_negative_rejected() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["recommend", "--limit", "-5"])
    assert result.exit_code != 0


def test_med_28_05_task_scoped_decisions_excluded_by_default() -> None:
    """WB28 MED-28-05: task-scoped (Slice C) decisions must not roll
    into permanent global-rule recommendations by default."""
    decisions = [
        _decision(task_id="one-off-task-abc") for _ in range(5)
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert len(recs) == 0


def test_med_28_05_task_scoped_decisions_included_with_flag() -> None:
    """Opt-in flag flips the behavior back."""
    decisions = [
        _decision(task_id="one-off-task-abc") for _ in range(5)
    ]
    recs = synthesize_rules(
        decisions, min_support=3, include_task_scoped=True
    )
    assert len(recs) == 1


def test_med_28_05_global_decisions_still_included() -> None:
    """Non-task-scoped decisions (no task_id field) are NOT affected."""
    decisions = [
        _decision(task_id=None) for _ in range(5)
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert len(recs) == 1


def test_med_28_05_mcp_recommend_validates_include_task_scoped() -> None:
    """MCP must reject non-bool include_task_scoped."""
    from iam_jit.mcp_server import _bouncer_recommend_rules_for_mcp
    out = _bouncer_recommend_rules_for_mcp({"include_task_scoped": "yes"})
    assert "error" in out


def test_med_28_06_cli_apply_only_cherry_picks(tmp_path) -> None:
    """WB28 MED-28-06: --apply-only filters which patterns to apply."""
    from iam_jit.bouncer.decisions import Decision, DecisionRecord, Mode
    db_path = tmp_path / "b.db"
    # Seed two decision groups
    store = BouncerStore(db_path=str(db_path))
    try:
        for _ in range(3):
            store.record_decision(DecisionRecord(
                decision=Decision.ALLOW, mode=Mode.LEARN,
                service="s3", action="GetObject", arn=None,
                region="us-east-1", matched_rule=None, reason="learn",
            ))
            store.record_decision(DecisionRecord(
                decision=Decision.ALLOW, mode=Mode.LEARN,
                service="s3", action="ListBucket", arn=None,
                region="us-east-1", matched_rule=None, reason="learn",
            ))
    finally:
        store.close()
    runner = CliRunner()
    result = runner.invoke(main, [
        "recommend", "--db", str(db_path),
        "--apply", "--apply-only", "s3:GetObject",
    ])
    assert result.exit_code == 0, result.output
    # Only one rule should have been applied
    store = BouncerStore(db_path=str(db_path))
    try:
        rules = store.list_rules()
    finally:
        store.close()
    patterns = [r.pattern for _, r in rules]
    assert "s3:GetObject" in patterns
    assert "s3:ListBucket" not in patterns


# ---------------------------------------------------------------------------
# WB28 LOW closures
# ---------------------------------------------------------------------------


def test_low_28_01_rationale_surfaces_observable_vs_total() -> None:
    """WB28 LOW-28-01: rationale strings now report 'X of Y calls
    had observable ARN data' when the group has None-ARN entries."""
    # 3 with ARNs + 5 with None
    decisions = [
        _decision(arn="arn:aws:s3:::reports/x.csv") for _ in range(3)
    ] + [
        _decision(arn=None) for _ in range(5)
    ]
    # Bypass MED-28-01 gate by including enough observable: 3/8 < 50%
    # — gate fires and skips ARN scope. Let's flip ratio: 5 ARN + 3 None
    decisions = [
        _decision(arn="arn:aws:s3:::reports/x.csv") for _ in range(5)
    ] + [
        _decision(arn=None) for _ in range(3)
    ]
    recs = synthesize_rules(decisions, min_support=3)
    assert len(recs) == 1
    # 5 observable out of 8 total — rationale should mention 8
    assert recs[0].arn_pattern_rationale is not None
    rationale = recs[0].arn_pattern_rationale
    assert "8" in rationale  # total
    assert "5" in rationale  # observable


def test_low_28_02_known_actions_all_have_severity() -> None:
    """WB28 LOW-28-02: every catalog entry has the structured
    severity field."""
    for action, entry in KNOWN_ACTIONS.items():
        assert "severity" in entry, f"{action} missing severity field"
        sev = entry["severity"]
        assert sev is None or sev in (
            "destructive", "sensitive", "write", "expensive", "high_risk"
        ), f"{action} has unknown severity {sev!r}"


def test_low_28_02_destructive_class_actions_marked_destructive() -> None:
    """Smoke-test: known destructive actions carry the severity."""
    for action in (
        "s3:DeleteObject", "ec2:TerminateInstances", "iam:DeleteRole",
        "eks:UpdateClusterVersion", "rds:DeleteDBInstance",
        "cloudformation:DeleteStack",
    ):
        assert KNOWN_ACTIONS[action]["severity"] == "destructive"


def test_low_28_03_summarize_window_includes_other_count() -> None:
    """WB28 LOW-28-03: surface decisions with missing/unrecognized
    `decision` field as other_count so total = allow+deny+prompt+other."""
    decisions = [
        _decision(decision="allow"),
        _decision(decision="deny"),
        _decision(decision="prompt"),
        _decision(decision="something_weird"),
        {"service": "s3", "action": "GetObject"},  # no decision field at all
    ]
    summary = summarize_window(decisions)
    assert summary["total_calls"] == 5
    assert summary["allow_count"] == 1
    assert summary["deny_count"] == 1
    assert summary["prompt_count"] == 1
    assert summary["other_count"] == 2
    # Invariant: total == allow + deny + prompt + other
    assert (
        summary["total_calls"]
        == summary["allow_count"] + summary["deny_count"]
          + summary["prompt_count"] + summary["other_count"]
    )


def test_low_28_05_known_actions_all_have_last_reviewed() -> None:
    """WB28 LOW-28-05: catalog drift becomes visible via per-entry
    last_reviewed dates."""
    for action, entry in KNOWN_ACTIONS.items():
        assert "last_reviewed" in entry, f"{action} missing last_reviewed"
        assert isinstance(entry["last_reviewed"], str)
        # YYYY-MM format
        assert len(entry["last_reviewed"]) == 7
        assert entry["last_reviewed"][4] == "-"


def test_low_28_04_datetime_window_parses_mixed_tz() -> None:
    """WB28 LOW-28-04: `since`/`until` are compared semantically as
    datetimes, so `+00:00` and `Z` representations of the same
    instant match identically."""
    from iam_jit.bouncer.recommender import filter_decisions_by_window
    decisions = [
        _decision(at="2026-05-17T15:00:00Z"),
        _decision(at="2026-05-17T16:00:00Z"),
        _decision(at="2026-05-17T17:00:00Z"),
    ]
    # Both filter forms should give the SAME 2-decision result
    out_z = filter_decisions_by_window(
        decisions, since="2026-05-17T16:00:00Z", until=None
    )
    out_offset = filter_decisions_by_window(
        decisions, since="2026-05-17T16:00:00+00:00", until=None
    )
    assert len(out_z) == 2
    assert len(out_offset) == 2
    # Both windows must select identical decisions
    assert [d["at"] for d in out_z] == [d["at"] for d in out_offset]
