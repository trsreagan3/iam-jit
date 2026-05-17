"""Tests for the env-profiles feature (AWS Slice 7).

Covers:
- Profile YAML loading (defaults + custom + malformed)
- Word-boundary keyword matching vs substring
- Exceptions list overrides keyword match
- only_account_ids hard restriction
- deny_verbs pattern matching
- ProfileVerdict composition (which rule fires first)
- resolve_active_profile resolution order (explicit > flag > env > 'full-user')
- Integration: profile DENY beats global ALLOW rule in evaluate_request
- Backward-compat: legacy 'none' + 'prod-readonly' names still resolve
  (post Bounce-suite rename 2026-05-17; removed in v1.1)
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.profiles import (
    ACTIVE_PROFILE_ENV,
    DEFAULT_PROFILES,
    Profile,
    ProfileVerdict,
    _glob_match,
    evaluate_profile,
    load_profiles,
    resolve_active_profile,
    resolve_profiles_path,
    write_default_profiles,
)
from iam_jit.bouncer.proxy import ProxyMode, evaluate_request
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import BouncerStore


def _sigv4(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260517/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakefakefake"
    )


# ---------------------------------------------------------------------------
# Profile YAML loading
# ---------------------------------------------------------------------------


def test_load_profiles_returns_defaults_when_file_absent(tmp_path, monkeypatch) -> None:
    """First-run path: profiles.yaml doesn't exist → defaults returned.

    Post Bounce-suite rename (2026-05-17), built-in defaults reduced
    to the cross-product general-purpose pair (`full-user` +
    `readonly`). Legacy names (`none`, `prod-readonly`) still appear
    as aliases for v1.0 backward-compat (removed in v1.1). The
    opinionated profiles (`dev-only`, `staging-work`,
    `incident-response`) moved to `tools/community-profiles/`.
    """
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(tmp_path / "absent.yaml"))
    profiles = load_profiles()
    # Canonical v1.0 defaults
    assert set(profiles.keys()) >= {"full-user", "readonly"}
    # Legacy aliases (deprecated; still resolve in v1.0)
    assert "none" in profiles and profiles["none"] is profiles["full-user"]
    assert "prod-readonly" in profiles and profiles["prod-readonly"] is profiles["readonly"]
    # Opinionated profiles no longer built-in
    assert "dev-only" not in profiles
    assert "staging-work" not in profiles
    assert "incident-response" not in profiles


def test_load_profiles_reads_custom_yaml(tmp_path, monkeypatch) -> None:
    custom = tmp_path / "profiles.yaml"
    custom.write_text(yaml.safe_dump({
        "profiles": {
            "custom-strict": {
                "description": "blocks anything",
                "deny_keywords": ["foo"],
                "keyword_targets": ["arn"],
            },
        },
    }))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(custom))
    profiles = load_profiles()
    assert "custom-strict" in profiles
    assert profiles["custom-strict"].deny_keywords == ("foo",)
    # 'full-user' (the v1.0 passthrough default) is always injected
    # even if user didn't define it; the legacy 'none' alias is
    # also injected for backward-compat.
    assert "full-user" in profiles
    assert "none" in profiles


def test_load_profiles_rejects_invalid_yaml(tmp_path, monkeypatch) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: valid:\n  yaml: -[\n")
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(bad))
    with pytest.raises(ValueError, match="not valid YAML"):
        load_profiles()


def test_load_profiles_rejects_wrong_root_shape(tmp_path, monkeypatch) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump(["not", "a", "dict"]))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(bad))
    with pytest.raises(ValueError):
        load_profiles()


def test_load_profiles_rejects_bad_keyword_match_mode(tmp_path, monkeypatch) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({
        "profiles": {"x": {"keyword_match": "regex"}},
    }))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(bad))
    with pytest.raises(ValueError, match="keyword_match"):
        load_profiles()


def test_write_default_profiles_idempotent(tmp_path, monkeypatch) -> None:
    target = tmp_path / "profiles.yaml"
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(target))
    p1 = write_default_profiles()
    snapshot = p1.read_bytes()
    p2 = write_default_profiles()
    assert p1 == p2
    assert p2.read_bytes() == snapshot  # not overwritten


def test_resolve_profiles_path_priority(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(tmp_path / "env.yaml"))
    # Explicit arg wins over env var
    assert resolve_profiles_path("/tmp/explicit.yaml") == pathlib.Path("/tmp/explicit.yaml")
    # Env var wins when no explicit
    assert resolve_profiles_path(None) == tmp_path / "env.yaml"


# ---------------------------------------------------------------------------
# Active profile resolution
# ---------------------------------------------------------------------------


def test_resolve_active_profile_cli_flag_wins(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(ACTIVE_PROFILE_ENV, "full-user")
    profiles = load_profiles()
    p = resolve_active_profile(cli_flag="readonly", profiles=profiles)
    assert p.name == "readonly"


def test_resolve_active_profile_env_var_used_when_no_flag(monkeypatch) -> None:
    monkeypatch.setenv(ACTIVE_PROFILE_ENV, "readonly")
    profiles = load_profiles()
    p = resolve_active_profile(cli_flag=None, profiles=profiles)
    assert p.name == "readonly"


def test_resolve_active_profile_defaults_to_full_user(monkeypatch) -> None:
    """Post Bounce-suite rename: the default-active profile is
    `full-user` (was `none`). `full-user` is still the passthrough
    (no rule-engine interference) — the rename is name-only."""
    monkeypatch.delenv(ACTIVE_PROFILE_ENV, raising=False)
    profiles = load_profiles()
    p = resolve_active_profile(cli_flag=None, profiles=profiles)
    assert p.name == "full-user"


def test_resolve_active_profile_legacy_none_alias_still_works(monkeypatch, capsys) -> None:
    """Backward-compat: `--profile none` keeps working in v1.0 (the
    user-facing alias maps to the canonical `full-user` profile) +
    emits a one-line stderr deprecation banner."""
    monkeypatch.delenv(ACTIVE_PROFILE_ENV, raising=False)
    profiles = load_profiles()
    p = resolve_active_profile(cli_flag="none", profiles=profiles)
    assert p.name == "full-user"  # canonical name on the Profile
    captured = capsys.readouterr()
    assert "deprecated" in captured.err
    assert "full-user" in captured.err


def test_resolve_active_profile_legacy_prod_readonly_alias_still_works(
    monkeypatch, capsys,
) -> None:
    """Backward-compat: `--profile prod-readonly` keeps working in
    v1.0 + maps to the canonical `readonly` (cross-product general-
    purpose name; "prod" connotation dropped per the
    bounce-default-profile-pattern memo)."""
    monkeypatch.delenv(ACTIVE_PROFILE_ENV, raising=False)
    profiles = load_profiles()
    p = resolve_active_profile(cli_flag="prod-readonly", profiles=profiles)
    assert p.name == "readonly"
    captured = capsys.readouterr()
    assert "deprecated" in captured.err
    assert "readonly" in captured.err


def test_resolve_active_profile_unknown_name_raises(monkeypatch) -> None:
    """Typo in --profile must FAIL loudly, not silently fall back to none.
    Silent fallback would disable a guardrail the user thought they enabled."""
    profiles = load_profiles()
    with pytest.raises(ValueError, match="not found"):
        resolve_active_profile(cli_flag="nonexistent-profile", profiles=profiles)


# ---------------------------------------------------------------------------
# evaluate_profile — keyword matching
# ---------------------------------------------------------------------------


def test_keyword_word_boundary_matches_dashes_underscores_dots() -> None:
    """word_boundary mode matches `prod` in `prod-cluster`, `cluster-prod`,
    `prod_app`, `prod.staging`."""
    profile = Profile(name="t", deny_keywords=("prod",), keyword_match="word_boundary",
                      keyword_targets=("arn",))
    for arn in [
        "arn:aws:s3:::prod-bucket",
        "arn:aws:s3:::cluster-prod",
        "arn:aws:s3:::prod_app",
        "arn:aws:s3:::prod.staging",
        "arn:aws:eks:us-east-1:111:cluster/prod",
    ]:
        verdict = evaluate_profile(profile, arn=arn)
        assert verdict.denied, f"expected DENY for {arn}"
        assert "prod" in verdict.reason


def test_keyword_word_boundary_does_NOT_match_substring_within_word() -> None:
    """word_boundary mode does NOT match `prod` in `productivity`,
    `reproduce`, `protocol` (no separator-boundary)."""
    profile = Profile(name="t", deny_keywords=("prod",), keyword_match="word_boundary",
                      keyword_targets=("arn",))
    for arn in [
        "arn:aws:s3:::eng-productivity-tooling",
        "arn:aws:s3:::reproduce-issue-12345",
        "arn:aws:s3:::protocol-traces",
    ]:
        verdict = evaluate_profile(profile, arn=arn)
        assert not verdict.denied, f"expected ALLOW for {arn} (false-positive avoid)"


def test_keyword_substring_mode_matches_everything() -> None:
    """substring mode is the stricter alternative; matches anywhere."""
    profile = Profile(name="t", deny_keywords=("prod",), keyword_match="substring",
                      keyword_targets=("arn",))
    for arn in ["arn:aws:s3:::eng-productivity-tooling", "arn:aws:s3:::prod"]:
        verdict = evaluate_profile(profile, arn=arn)
        assert verdict.denied, f"expected DENY for {arn} in substring mode"


def test_exceptions_override_keyword_match() -> None:
    """Per-profile exceptions list closes false-positive cases without
    weakening the rest of the keyword denylist."""
    profile = Profile(
        name="t", deny_keywords=("prod",), keyword_match="word_boundary",
        keyword_targets=("arn",),
        exceptions=("eng-productivity",),
    )
    # Even in substring would have matched, the exception wins
    verdict = evaluate_profile(
        profile, arn="arn:aws:s3:::eng-productivity-prod-bucket",
    )
    assert not verdict.denied


def test_keyword_targets_selects_which_fields_match() -> None:
    """Profile only checks the fields listed in keyword_targets."""
    profile = Profile(name="t", deny_keywords=("prod",),
                      keyword_targets=("resource_name",))
    # ARN has 'prod' but only resource_name is checked → no match
    verdict = evaluate_profile(profile, arn="arn:aws:s3:::prod-bucket",
                                resource_name="benign-data")
    assert not verdict.denied
    # When resource_name has it, deny
    verdict = evaluate_profile(profile, arn=None,
                                resource_name="arn:aws:s3:::prod-bucket")
    assert verdict.denied


# ---------------------------------------------------------------------------
# only_account_ids
# ---------------------------------------------------------------------------


def test_only_account_ids_denies_foreign_account() -> None:
    profile = Profile(name="t", only_account_ids=("111122223333",))
    # Wrong account → DENY
    verdict = evaluate_profile(profile, account_id="999988887777")
    assert verdict.denied
    assert "111122223333" in verdict.reason
    # Right account → no objection (other rules may decide)
    verdict = evaluate_profile(profile, account_id="111122223333")
    assert not verdict.denied
    # Unknown account → DENY (fail-closed)
    verdict = evaluate_profile(profile, account_id=None)
    assert verdict.denied


# ---------------------------------------------------------------------------
# deny_verbs
# ---------------------------------------------------------------------------


def test_deny_verbs_glob_matching() -> None:
    profile = Profile(name="t", deny_verbs=("s3:Delete*", "*:Terminate*"))
    assert evaluate_profile(profile, service="s3", action="DeleteObject").denied
    assert evaluate_profile(profile, service="s3", action="DeleteBucket").denied
    assert evaluate_profile(profile, service="ec2", action="TerminateInstances").denied
    # Not denied
    assert not evaluate_profile(profile, service="s3", action="GetObject").denied
    assert not evaluate_profile(profile, service="iam", action="CreateRole").denied


def test_glob_match_pattern_semantics() -> None:
    assert _glob_match("*", "anything")
    assert _glob_match("s3:*", "s3:Get")
    assert not _glob_match("s3:*", "iam:CreateRole")
    assert _glob_match("Delete*", "DeleteObject")
    assert not _glob_match("Delete*", "GetObject")


# ---------------------------------------------------------------------------
# Composition order — profile beats task/global allow
# ---------------------------------------------------------------------------


def test_profile_deny_beats_global_allow_via_evaluate_request(tmp_path) -> None:
    """The key load-bearing test: a global ALLOW rule for s3:* does NOT
    override a profile keyword-deny on the same ARN. Profile is a hard
    floor.

    Post Bounce-suite rename: the built-in `staging-work` profile
    moved to `tools/community-profiles/`; this test constructs an
    equivalent Profile inline to exercise the same composition
    invariant without depending on a community-profile install.
    """
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    # Add a global allow rule for everything in S3
    store.add_rule(
        ProxyRule(pattern="s3:*", effect=Effect.ALLOW,
                  arn_scope=None, region_scope=None,
                  note="permissive global", origin="manual"),
        actor="test",
    )
    # Construct a staging-work-shaped profile inline (was built-in
    # pre-rename; now lives in tools/community-profiles/staging-work.yaml)
    staging = Profile(
        name="staging-work",
        description="block prod-shaped resources",
        deny_keywords=("prod", "production", "uat", "live", "customer"),
        keyword_targets=("arn", "resource_name"),
        keyword_match="word_boundary",
    )

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/prod-customers-bucket/sensitive.csv",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None,
        query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        active_profile=staging,
    )
    # Profile must win — denied even with global allow
    assert obs.decision_verdict == "deny"
    assert "profile" in obs.decision_reason
    assert "prod" in obs.decision_reason
    store.close()


def test_profile_full_user_preserves_existing_behavior(tmp_path) -> None:
    """With profile='full-user' (was 'none' pre-rename), the existing
    rule engine drives the verdict — Slice 1/2 behavior unchanged."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    store.add_rule(
        ProxyRule(pattern="s3:*", effect=Effect.ALLOW,
                  arn_scope=None, region_scope=None,
                  note="permissive", origin="manual"),
        actor="test",
    )
    profiles = load_profiles()
    none_profile = profiles["full-user"]

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/prod-customers-bucket/sensitive.csv",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None,
        query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        active_profile=none_profile,
    )
    # Global allow drives the verdict; profile=full-user (passthrough)
    # doesn't interfere
    assert obs.decision_verdict == "allow"
    store.close()


def test_evaluate_request_without_profile_arg_works(tmp_path) -> None:
    """Backward compat: callers that don't pass active_profile (e.g.
    existing Slice 1/2 callers) still work."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        # no active_profile arg
    )
    # No rules, no profile → default-deny
    assert obs.decision_verdict == "deny"
    store.close()


# ---------------------------------------------------------------------------
# Default profiles sanity
# ---------------------------------------------------------------------------


def test_default_profiles_load_without_error() -> None:
    """Every default profile in DEFAULT_PROFILES must parse cleanly."""
    profiles = load_profiles()
    for name in DEFAULT_PROFILES.keys():
        assert name in profiles, f"default profile {name!r} missing"


def test_readonly_default_denies_writes() -> None:
    """End-to-end check that the shipped `readonly` default profile
    blocks write/destructive verbs. `readonly` is the v1.0 cross-
    product general-purpose write-blocker (renamed from
    `prod-readonly` per the bounce-default-profile-pattern memo).
    """
    profiles = load_profiles()
    readonly = profiles["readonly"]
    assert evaluate_profile(readonly, service="s3", action="DeleteObject").denied
    assert evaluate_profile(readonly, service="s3", action="PutObject").denied
    assert evaluate_profile(readonly, service="ec2", action="TerminateInstances").denied
    # Reads still allowed (no objection at profile layer)
    assert not evaluate_profile(readonly, service="s3", action="GetObject").denied


def test_legacy_prod_readonly_alias_points_at_readonly() -> None:
    """The deprecated `prod-readonly` name still resolves to the same
    Profile object as the canonical `readonly` (v1.0 backward-compat;
    alias removed in v1.1)."""
    profiles = load_profiles()
    assert profiles["prod-readonly"] is profiles["readonly"]
