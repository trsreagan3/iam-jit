"""Tests for profile ALLOW rules (#6b foundation).

Profiles can now carry ALLOW rules in addition to DENY layers. When a
profile is active, its allow_rules are merged into the rule engine
alongside global rules — same precedence as if the user had added
them as globals, but gated on the profile being active.

Also covers:
- YAML round-trip via profile_to_yaml_dict + load_profiles
- upsert_profile insert + replace semantics
- upsert_profile refuses to overwrite an org-distributed profile
- The org-source field round-trips correctly
"""

from __future__ import annotations

import socket

import pytest
import yaml

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.profiles import (
    Profile,
    ProfileAllowRule,
    load_profiles,
    profile_to_yaml_dict,
    upsert_profile,
)
from iam_jit.bouncer.proxy import ProxyMode, evaluate_request
from iam_jit.bouncer.store import BouncerStore


def _sigv4(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260517/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakefakefake"
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------------------------------------------------------------------
# YAML round-trip
# ---------------------------------------------------------------------------


def test_yaml_round_trip_preserves_allow_rules(tmp_path, monkeypatch) -> None:
    """profile_to_yaml_dict + load_profiles must round-trip cleanly so
    `--save-as-profile` writes survive a restart."""
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(tmp_path / "p.yaml"))
    original = Profile(
        name="my-debug",
        description="captured 2026-05-17",
        allow_rules=(
            ProfileAllowRule(pattern="s3:GetObject",
                             arn_scope="arn:aws:s3:::my-bucket/*"),
            ProfileAllowRule(pattern="s3:ListBucket", note="seen 12 times"),
            ProfileAllowRule(pattern="ec2:Describe*",
                             region_scope="us-east-1"),
        ),
    )
    path = upsert_profile(original)
    assert path.exists()

    profiles = load_profiles()
    assert "my-debug" in profiles
    loaded = profiles["my-debug"]
    assert loaded.description == "captured 2026-05-17"
    assert len(loaded.allow_rules) == 3
    assert loaded.allow_rules[0].pattern == "s3:GetObject"
    assert loaded.allow_rules[0].arn_scope == "arn:aws:s3:::my-bucket/*"
    assert loaded.allow_rules[1].note == "seen 12 times"
    assert loaded.allow_rules[2].region_scope == "us-east-1"
    assert loaded.source == "local"


def test_upsert_inserts_then_replaces(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(tmp_path / "p.yaml"))
    upsert_profile(Profile(name="x", description="v1"))
    upsert_profile(Profile(name="x", description="v2"))
    profs = load_profiles()
    assert profs["x"].description == "v2"


def test_upsert_refuses_org_distributed_profile(tmp_path, monkeypatch) -> None:
    """Profiles installed from an org URL are READ-ONLY at the CLI —
    engineers cannot edit them to bypass. The org-distribution flow
    sets `source` to the URL it came from."""
    target = tmp_path / "p.yaml"
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(target))
    # Simulate an org-installed profile
    target.write_text(yaml.safe_dump({
        "profiles": {
            "acme-staging": {
                "description": "Acme's curated staging guardrail",
                "source": "https://internal.acme.com/iam-jit-profiles/staging.yaml",
                "deny_keywords": ["prod"],
            },
        },
    }))
    with pytest.raises(ValueError, match="read-only"):
        upsert_profile(Profile(
            name="acme-staging",
            description="local override attempt",
        ))


def test_yaml_round_trip_preserves_source_field(tmp_path, monkeypatch) -> None:
    target = tmp_path / "p.yaml"
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(target))
    target.write_text(yaml.safe_dump({
        "profiles": {
            "org-x": {
                "description": "from org",
                "source": "https://example.com/profiles.yaml",
                "allow_rules": [{"pattern": "s3:GetObject"}],
            },
        },
    }))
    profs = load_profiles()
    assert profs["org-x"].source == "https://example.com/profiles.yaml"
    assert profs["org-x"].allow_rules[0].pattern == "s3:GetObject"


def test_allow_rules_yaml_validation_rejects_bad_shape(tmp_path, monkeypatch) -> None:
    target = tmp_path / "p.yaml"
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(target))
    target.write_text(yaml.safe_dump({
        "profiles": {
            "x": {"allow_rules": [{"arn_scope": "arn:aws:s3:::b"}]},  # missing pattern
        },
    }))
    with pytest.raises(ValueError, match="pattern"):
        load_profiles()


# ---------------------------------------------------------------------------
# Proxy integration: profile allow_rules feed the rule engine
# ---------------------------------------------------------------------------


def test_profile_allow_rule_grants_access_in_default_deny(tmp_path) -> None:
    """With default-policy=deny and NO global rules, a profile's
    allow_rules should be the thing that grants access. This is the
    core path for `bouncer recommend --save-as-profile`: capture what
    the agent needed → activate that profile → agent works."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    profile = Profile(
        name="dev-session",
        allow_rules=(
            ProfileAllowRule(pattern="s3:GetObject"),
            ProfileAllowRule(pattern="s3:ListBucket"),
        ),
    )

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/my-bucket/key",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        active_profile=profile,
    )
    assert obs.decision_verdict == "allow"
    store.close()


def test_profile_allow_does_NOT_bypass_global_deny(tmp_path) -> None:
    """Explicit-deny-beats-allow precedence is preserved: if the user
    explicitly DENIES something globally, a profile allow_rule must
    NOT silently override it."""
    from iam_jit.bouncer.rules import Effect, ProxyRule
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    store.add_rule(
        ProxyRule(pattern="s3:GetObject", effect=Effect.DENY,
                  arn_scope=None, region_scope=None,
                  note="globally forbidden", origin="manual"),
        actor="test",
    )
    profile = Profile(
        name="dev-session",
        allow_rules=(ProfileAllowRule(pattern="s3:GetObject"),),
    )

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/my-bucket/key",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        active_profile=profile,
    )
    # Global explicit DENY wins
    assert obs.decision_verdict == "deny"
    store.close()


def test_profile_deny_keywords_still_beat_profile_allow_rules(tmp_path) -> None:
    """The profile's own deny_keywords (hard floor) must beat the
    profile's own allow_rules. Otherwise `--save-as-profile` could
    accidentally elevate a profile that's supposed to be locked
    down."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    profile = Profile(
        name="mixed",
        deny_keywords=("prod",),
        keyword_targets=("arn", "resource_name"),
        allow_rules=(ProfileAllowRule(pattern="s3:GetObject"),),
    )

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/prod-bucket/sensitive",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        active_profile=profile,
    )
    assert obs.decision_verdict == "deny"
    assert "prod" in obs.decision_reason
    store.close()


def test_profile_allow_rule_with_arn_scope_narrows_match(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    profile = Profile(
        name="narrow",
        allow_rules=(
            ProfileAllowRule(pattern="s3:GetObject",
                             arn_scope="arn:aws:s3:::approved-bucket/*"),
        ),
    )

    obs_match = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/approved-bucket/key",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        active_profile=profile,
    )
    assert obs_match.decision_verdict == "allow"

    obs_miss = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/other-bucket/key",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        active_profile=profile,
    )
    assert obs_miss.decision_verdict == "deny"
    store.close()


def test_empty_profile_with_only_allow_rules_does_not_short_circuit_deny_layer(tmp_path) -> None:
    """A profile with only allow_rules (no deny_keywords/verbs/accounts)
    must NOT be treated as 'no profile' by the deny layer — but with
    nothing to deny, the deny layer must fall through, not short-
    circuit."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    profile = Profile(
        name="allow-only",
        allow_rules=(ProfileAllowRule(pattern="s3:GetObject"),),
    )
    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/some-bucket/key.txt",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        active_profile=profile,
    )
    assert obs.decision_verdict == "allow"
    store.close()
