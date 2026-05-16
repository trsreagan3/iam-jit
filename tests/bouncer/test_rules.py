"""Tests for the bouncer rule matcher (#160 foundation slice)."""

from __future__ import annotations

import pytest

from iam_jit.bouncer.rules import (
    Effect,
    ProxyRule,
    RuleSet,
    parse_pattern,
    rule_matches,
)


# ---------------------------------------------------------------------------
# parse_pattern
# ---------------------------------------------------------------------------


def test_parse_pattern_valid_basic() -> None:
    assert parse_pattern("s3:GetObject") == ("s3", "GetObject")


def test_parse_pattern_lowercases_service() -> None:
    assert parse_pattern("S3:GetObject") == ("s3", "GetObject")


def test_parse_pattern_allows_action_wildcard() -> None:
    assert parse_pattern("s3:Put*") == ("s3", "Put*")
    assert parse_pattern("s3:*") == ("s3", "*")


def test_parse_pattern_accepts_full_service_wildcard() -> None:
    """`*:Action` and bare `*` are valid (WB23-closure expansion to
    match AWS IAM policy spec; supports cross-service DENY patterns
    like `*:Delete*` used in prod-deny-destructive preset)."""
    assert parse_pattern("*:GetObject") == ("*", "GetObject")
    assert parse_pattern("*:Delete*") == ("*", "Delete*")
    assert parse_pattern("*") == ("*", "*")


def test_parse_pattern_rejects_partial_service_wildcard() -> None:
    """Partial-wildcard service prefixes (e.g. `s*`) remain rejected —
    AWS service prefixes are flat strings, not globs."""
    assert parse_pattern("s*:GetObject") is None
    assert parse_pattern("ec*:Describe*") is None


def test_parse_pattern_rejects_missing_colon() -> None:
    assert parse_pattern("s3") is None
    assert parse_pattern("GetObject") is None


def test_parse_pattern_rejects_extra_colons() -> None:
    assert parse_pattern("s3:Get:Object") is None


def test_parse_pattern_rejects_empty_parts() -> None:
    assert parse_pattern(":GetObject") is None
    assert parse_pattern("s3:") is None


def test_parse_pattern_rejects_whitespace() -> None:
    assert parse_pattern("s3 :GetObject") is None
    assert parse_pattern("s3: GetObject") is None


def test_parse_pattern_handles_non_string() -> None:
    assert parse_pattern(None) is None  # type: ignore[arg-type]
    assert parse_pattern(42) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# rule_matches
# ---------------------------------------------------------------------------


def _r(pattern: str, **kw) -> ProxyRule:
    return ProxyRule(pattern=pattern, **kw)


def test_rule_matches_exact_action() -> None:
    assert rule_matches(
        _r("s3:GetObject"), service="s3", action="GetObject", arn=None, region=None
    )


def test_rule_matches_action_glob() -> None:
    assert rule_matches(
        _r("s3:Put*"), service="s3", action="PutObject", arn=None, region=None
    )
    assert rule_matches(
        _r("s3:Put*"), service="s3", action="PutBucketPolicy", arn=None, region=None
    )


def test_rule_matches_action_star_matches_anything() -> None:
    assert rule_matches(
        _r("iam:*"), service="iam", action="DeleteRole", arn=None, region=None
    )


def test_rule_does_not_match_wrong_service() -> None:
    assert not rule_matches(
        _r("s3:GetObject"), service="ec2", action="GetObject", arn=None, region=None
    )


def test_rule_service_compare_case_insensitive_on_request_side() -> None:
    assert rule_matches(
        _r("s3:GetObject"), service="S3", action="GetObject", arn=None, region=None
    )


def test_rule_action_compare_is_case_sensitive() -> None:
    """fnmatch.fnmatchcase is case-sensitive — IAM action names are
    PascalCase so this is the correct semantics."""
    assert not rule_matches(
        _r("s3:GetObject"), service="s3", action="getobject", arn=None, region=None
    )


def test_rule_arn_scope_narrows_match() -> None:
    rule = _r("s3:GetObject", arn_scope="arn:aws:s3:::my-bucket/*")
    assert rule_matches(
        rule, service="s3", action="GetObject",
        arn="arn:aws:s3:::my-bucket/file.txt", region=None,
    )
    assert not rule_matches(
        rule, service="s3", action="GetObject",
        arn="arn:aws:s3:::other-bucket/file.txt", region=None,
    )


def test_rule_arn_star_matches_anything() -> None:
    rule = _r("s3:GetObject", arn_scope="*")
    assert rule_matches(
        rule, service="s3", action="GetObject",
        arn="arn:aws:s3:::whatever", region=None,
    )


def test_rule_arn_scope_with_no_arn_in_request_does_not_match() -> None:
    """Conservative: if a rule scopes by ARN but the parsed request
    has no resolvable ARN, the rule must not match (avoids
    accidental allow on unresolvable resource hints)."""
    rule = _r("s3:GetObject", arn_scope="arn:aws:s3:::my-bucket")
    assert not rule_matches(
        rule, service="s3", action="GetObject", arn=None, region=None
    )


def test_rule_region_scope_narrows_match() -> None:
    rule = _r("ec2:DescribeInstances", region_scope="us-east-1")
    assert rule_matches(
        rule, service="ec2", action="DescribeInstances", arn=None, region="us-east-1"
    )
    assert not rule_matches(
        rule, service="ec2", action="DescribeInstances", arn=None, region="eu-west-1"
    )


def test_rule_region_glob() -> None:
    rule = _r("ec2:DescribeInstances", region_scope="us-*")
    assert rule_matches(
        rule, service="ec2", action="DescribeInstances", arn=None, region="us-west-2"
    )
    assert not rule_matches(
        rule, service="ec2", action="DescribeInstances", arn=None, region="ap-south-1"
    )


def test_malformed_rule_never_matches() -> None:
    rule = _r("not-a-valid-pattern")
    assert not rule_matches(
        rule, service="s3", action="GetObject", arn=None, region=None
    )


def test_cross_service_wildcard_matches_any_service() -> None:
    """A `*:Delete*` rule must match s3:DeleteObject, ec2:DeleteVpc,
    rds:DeleteDBInstance, etc. This is the prod-deny-destructive
    preset's main mechanism."""
    rule = _r("*:Delete*", effect=Effect.DENY)
    for svc, action in [
        ("s3", "DeleteObject"),
        ("ec2", "DeleteVpc"),
        ("rds", "DeleteDBInstance"),
        ("cloudformation", "DeleteStack"),
    ]:
        assert rule_matches(rule, service=svc, action=action, arn=None, region=None), (
            f"cross-service wildcard rule failed to match {svc}:{action}"
        )


def test_full_wildcard_matches_everything() -> None:
    rule = _r("*", effect=Effect.ALLOW)
    assert rule_matches(rule, service="s3", action="GetObject", arn=None, region=None)
    assert rule_matches(rule, service="iam", action="CreateRole", arn=None, region=None)


# ---------------------------------------------------------------------------
# RuleSet evaluation
# ---------------------------------------------------------------------------


def test_ruleset_returns_none_when_no_match() -> None:
    rs = RuleSet(rules=[_r("ec2:*", effect=Effect.ALLOW)])
    assert rs.evaluate(service="s3", action="GetObject") is None


def test_ruleset_allow_match() -> None:
    rs = RuleSet(rules=[_r("s3:GetObject", effect=Effect.ALLOW)])
    result = rs.evaluate(service="s3", action="GetObject")
    assert result is not None
    effect, rule = result
    assert effect == Effect.ALLOW


def test_ruleset_explicit_deny_beats_allow() -> None:
    """Per the blacklist precedent: explicit DENY wins even if an
    ALLOW also matches."""
    rs = RuleSet(rules=[
        _r("s3:*", effect=Effect.ALLOW),
        _r("s3:DeleteObject", effect=Effect.DENY),
    ])
    result = rs.evaluate(service="s3", action="DeleteObject")
    assert result is not None
    effect, rule = result
    assert effect == Effect.DENY
    assert rule.pattern == "s3:DeleteObject"


def test_ruleset_first_matching_allow_wins() -> None:
    """When multiple ALLOWs match, the first inserted one wins."""
    rs = RuleSet(rules=[
        _r("s3:*", effect=Effect.ALLOW, note="first"),
        _r("s3:Get*", effect=Effect.ALLOW, note="second"),
    ])
    result = rs.evaluate(service="s3", action="GetObject")
    assert result is not None
    _, rule = result
    assert rule.note == "first"


def test_ruleset_first_matching_deny_wins() -> None:
    rs = RuleSet(rules=[
        _r("iam:*", effect=Effect.DENY, note="first"),
        _r("iam:Delete*", effect=Effect.DENY, note="second"),
    ])
    result = rs.evaluate(service="iam", action="DeleteRole")
    assert result is not None
    _, rule = result
    assert rule.note == "first"


def test_ruleset_arn_and_region_scope_compose() -> None:
    rs = RuleSet(rules=[
        _r(
            "s3:GetObject",
            effect=Effect.ALLOW,
            arn_scope="arn:aws:s3:::my-bucket/*",
            region_scope="us-east-1",
        ),
    ])
    # Matches: right arn + right region
    assert rs.evaluate(
        service="s3", action="GetObject",
        arn="arn:aws:s3:::my-bucket/x", region="us-east-1",
    ) is not None
    # Wrong region: no match
    assert rs.evaluate(
        service="s3", action="GetObject",
        arn="arn:aws:s3:::my-bucket/x", region="eu-west-1",
    ) is None
    # Wrong arn: no match
    assert rs.evaluate(
        service="s3", action="GetObject",
        arn="arn:aws:s3:::other/x", region="us-east-1",
    ) is None
