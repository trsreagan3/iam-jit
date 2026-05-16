"""Tests for the bouncer decision logic."""

from __future__ import annotations

import pytest

from iam_jit.bouncer.decisions import (
    Decision,
    DefaultPolicy,
    Mode,
    decide,
)
from iam_jit.bouncer.rules import Effect, ProxyRule, RuleSet


def _rs(*rules: ProxyRule) -> RuleSet:
    return RuleSet(rules=list(rules))


# ---------------------------------------------------------------------------
# LEARN mode invariants
# ---------------------------------------------------------------------------


def test_learn_mode_always_allows_when_no_rules() -> None:
    record = decide(
        _rs(),
        mode=Mode.LEARN,
        default_policy=DefaultPolicy.DENY,
        service="s3", action="DeleteObject",
    )
    assert record.decision == Decision.ALLOW
    assert "learn-mode" in record.reason


def test_learn_mode_allows_even_when_deny_rule_matches() -> None:
    """The CORE invariant: learn mode never denies. The matched-rule
    is preserved on the record so the user can preview what enforce
    would do."""
    record = decide(
        _rs(ProxyRule(pattern="s3:DeleteObject", effect=Effect.DENY)),
        mode=Mode.LEARN,
        default_policy=DefaultPolicy.DENY,
        service="s3", action="DeleteObject",
    )
    assert record.decision == Decision.ALLOW
    assert record.matched_rule is not None
    assert record.matched_rule.effect == Effect.DENY
    assert "would-deny" in record.reason


def test_learn_mode_records_would_allow_too() -> None:
    record = decide(
        _rs(ProxyRule(pattern="s3:GetObject", effect=Effect.ALLOW)),
        mode=Mode.LEARN,
        default_policy=DefaultPolicy.DENY,
        service="s3", action="GetObject",
    )
    assert record.decision == Decision.ALLOW
    assert "would-allow" in record.reason


# ---------------------------------------------------------------------------
# ENFORCE mode
# ---------------------------------------------------------------------------


def test_enforce_mode_allows_on_allow_rule_match() -> None:
    record = decide(
        _rs(ProxyRule(pattern="s3:GetObject", effect=Effect.ALLOW)),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="s3", action="GetObject",
    )
    assert record.decision == Decision.ALLOW
    assert "explicit-allow" in record.reason
    assert record.matched_rule is not None


def test_enforce_mode_denies_on_deny_rule_match() -> None:
    record = decide(
        _rs(ProxyRule(pattern="iam:Delete*", effect=Effect.DENY)),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.ALLOW,
        service="iam", action="DeleteRole",
    )
    assert record.decision == Decision.DENY
    assert "explicit-deny" in record.reason


def test_enforce_mode_default_deny_on_unmatched() -> None:
    record = decide(
        _rs(),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="ec2", action="DescribeInstances",
    )
    assert record.decision == Decision.DENY
    assert "default-deny" in record.reason


def test_enforce_mode_default_allow_on_unmatched() -> None:
    record = decide(
        _rs(),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.ALLOW,
        service="ec2", action="DescribeInstances",
    )
    assert record.decision == Decision.ALLOW
    assert "default-allow" in record.reason


def test_enforce_mode_explicit_deny_beats_allow_rule() -> None:
    """The blacklist precedent: explicit DENY wins."""
    record = decide(
        _rs(
            ProxyRule(pattern="s3:*", effect=Effect.ALLOW),
            ProxyRule(pattern="s3:DeleteObject", effect=Effect.DENY),
        ),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.ALLOW,
        service="s3", action="DeleteObject",
    )
    assert record.decision == Decision.DENY


# ---------------------------------------------------------------------------
# PROMPT mode
# ---------------------------------------------------------------------------


def test_prompt_mode_explicit_allow_passes() -> None:
    """When a rule explicitly matches in prompt mode, we don't prompt
    — we just apply the rule."""
    record = decide(
        _rs(ProxyRule(pattern="s3:GetObject", effect=Effect.ALLOW)),
        mode=Mode.PROMPT,
        default_policy=DefaultPolicy.DENY,
        service="s3", action="GetObject",
    )
    assert record.decision == Decision.ALLOW


def test_prompt_mode_explicit_deny_blocks() -> None:
    record = decide(
        _rs(ProxyRule(pattern="iam:*", effect=Effect.DENY)),
        mode=Mode.PROMPT,
        default_policy=DefaultPolicy.ALLOW,
        service="iam", action="CreateRole",
    )
    assert record.decision == Decision.DENY


def test_prompt_mode_unmatched_returns_prompt_decision() -> None:
    record = decide(
        _rs(),
        mode=Mode.PROMPT,
        default_policy=DefaultPolicy.DENY,  # ignored in prompt mode for unmatched
        service="ec2", action="DescribeInstances",
    )
    assert record.decision == Decision.PROMPT
    assert "prompt-mode" in record.reason
    assert "awaiting" in record.reason


# ---------------------------------------------------------------------------
# DecisionRecord shape
# ---------------------------------------------------------------------------


def test_record_serializes_to_dict() -> None:
    rule = ProxyRule(pattern="s3:GetObject", effect=Effect.ALLOW)
    record = decide(
        _rs(rule),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="s3", action="GetObject",
        arn="arn:aws:s3:::b/k", region="us-east-1",
    )
    d = record.to_dict()
    assert d["decision"] == "allow"
    assert d["mode"] == "enforce"
    assert d["service"] == "s3"
    assert d["action"] == "GetObject"
    assert d["arn"] == "arn:aws:s3:::b/k"
    assert d["region"] == "us-east-1"
    assert d["matched_rule"]["pattern"] == "s3:GetObject"


def test_record_dict_unmatched_rule_is_none() -> None:
    record = decide(
        _rs(),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="s3", action="GetObject",
    )
    assert record.to_dict()["matched_rule"] is None


# ---------------------------------------------------------------------------
# Scoping (ARN + region) flows through to decision
# ---------------------------------------------------------------------------


def test_arn_scoped_rule_applies_decision_when_arn_matches() -> None:
    rule = ProxyRule(
        pattern="s3:GetObject",
        effect=Effect.ALLOW,
        arn_scope="arn:aws:s3:::allowed-bucket/*",
    )
    # Matching ARN → allow
    rec1 = decide(
        _rs(rule),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="s3", action="GetObject",
        arn="arn:aws:s3:::allowed-bucket/x",
    )
    assert rec1.decision == Decision.ALLOW
    # Non-matching ARN → default deny
    rec2 = decide(
        _rs(rule),
        mode=Mode.ENFORCE,
        default_policy=DefaultPolicy.DENY,
        service="s3", action="GetObject",
        arn="arn:aws:s3:::other-bucket/x",
    )
    assert rec2.decision == Decision.DENY
