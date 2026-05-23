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

    Post safe-default reshape (2026-05-17), built-in defaults remain
    the cross-product general-purpose pair (`full-user` +
    `safe-default`). Legacy names (`none`, `prod-readonly`,
    `readonly`) still appear as aliases for v1.0 backward-compat
    (removed in v1.1). The opinionated profiles (`dev-only`,
    `staging-work`, `incident-response`) moved to
    `tools/community-profiles/`.
    """
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(tmp_path / "absent.yaml"))
    profiles = load_profiles()
    # Canonical v1.0 defaults
    assert set(profiles.keys()) >= {"full-user", "safe-default"}
    # Legacy aliases (deprecated; still resolve in v1.0)
    assert "none" in profiles and profiles["none"] is profiles["full-user"]
    assert "prod-readonly" in profiles
    assert profiles["prod-readonly"] is profiles["safe-default"]
    assert "readonly" in profiles
    assert profiles["readonly"] is profiles["safe-default"]
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
    p = resolve_active_profile(cli_flag="safe-default", profiles=profiles)
    assert p.name == "safe-default"


def test_resolve_active_profile_env_var_used_when_no_flag(monkeypatch) -> None:
    monkeypatch.setenv(ACTIVE_PROFILE_ENV, "safe-default")
    profiles = load_profiles()
    p = resolve_active_profile(cli_flag=None, profiles=profiles)
    assert p.name == "safe-default"


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
    """Backward-compat: `--profile prod-readonly` (v1.0-alpha) keeps
    working in v1.0 + maps to the canonical `safe-default`
    (readonly-admin-minus name; per safe_default_is_readonly_admin_minus
    memo, 2026-05-17)."""
    monkeypatch.delenv(ACTIVE_PROFILE_ENV, raising=False)
    profiles = load_profiles()
    p = resolve_active_profile(cli_flag="prod-readonly", profiles=profiles)
    assert p.name == "safe-default"
    captured = capsys.readouterr()
    assert "deprecated" in captured.err
    assert "safe-default" in captured.err


def test_resolve_active_profile_legacy_readonly_alias_still_works(
    monkeypatch, capsys,
) -> None:
    """Backward-compat: `--profile readonly` (v1.0-alpha-2, post-rename
    batch 47b616a) keeps working in v1.0 + maps to the canonical
    `safe-default` (per safe_default_is_readonly_admin_minus, 2026-05-17)."""
    monkeypatch.delenv(ACTIVE_PROFILE_ENV, raising=False)
    profiles = load_profiles()
    p = resolve_active_profile(cli_flag="readonly", profiles=profiles)
    assert p.name == "safe-default"
    captured = capsys.readouterr()
    assert "deprecated" in captured.err
    assert "safe-default" in captured.err


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


def test_safe_default_denies_writes_via_baseline_classification() -> None:
    """End-to-end check that the shipped `safe-default` profile blocks
    write/destructive verbs via the policy_sentry-backed
    `allow_baseline: aws_managed_readonly_access` mechanism (NOT via
    enumerated deny_verbs anymore). Per safe_default_is_readonly_admin_minus
    (2026-05-17): the architectural pattern is "allow Read+List, deny
    everything else by construction" — Write-classified actions are
    structurally excluded from the baseline so they're denied at the
    first profile layer.
    """
    profiles = load_profiles()
    sd = profiles["safe-default"]
    assert evaluate_profile(sd, service="s3", action="DeleteObject").denied
    assert evaluate_profile(sd, service="s3", action="PutObject").denied
    assert evaluate_profile(sd, service="ec2", action="TerminateInstances").denied
    # Reads still allowed (no objection at profile layer)
    assert not evaluate_profile(sd, service="s3", action="GetObject").denied


def test_legacy_prod_readonly_alias_points_at_safe_default() -> None:
    """The deprecated `prod-readonly` name still resolves to the same
    Profile object as the canonical `safe-default` (v1.0 backward-compat;
    alias removed in v1.1). Per safe_default_is_readonly_admin_minus
    (2026-05-17)."""
    profiles = load_profiles()
    assert profiles["prod-readonly"] is profiles["safe-default"]


def test_legacy_readonly_alias_points_at_safe_default() -> None:
    """The post-47b616a-rename name `readonly` still resolves to the
    same Profile object as the canonical `safe-default` for v1.0
    backward-compat; alias removed in v1.1. Per
    safe_default_is_readonly_admin_minus (2026-05-17)."""
    profiles = load_profiles()
    assert profiles["readonly"] is profiles["safe-default"]


# ---------------------------------------------------------------------------
# safe-default architectural reshape (readonly-admin-minus framing)
# Per safe_default_is_readonly_admin_minus (2026-05-17)
# ---------------------------------------------------------------------------


def test_action_in_baseline_readonly_access_classifies_known_read_actions() -> None:
    """policy_sentry classifies these as Read/List → baseline accepts.

    These are universal SDK preflight / inspection actions that any
    agent operating under safe-default must be able to call."""
    from iam_jit.bouncer.profiles import _action_in_baseline
    assert _action_in_baseline("aws_managed_readonly_access", "sts", "GetCallerIdentity")
    assert _action_in_baseline("aws_managed_readonly_access", "iam", "SimulatePrincipalPolicy")
    assert _action_in_baseline("aws_managed_readonly_access", "ec2", "DescribeInstances")
    assert _action_in_baseline("aws_managed_readonly_access", "s3", "GetObject")
    assert _action_in_baseline("aws_managed_readonly_access", "iam", "GetUser")


def test_action_in_baseline_readonly_access_rejects_known_write_actions() -> None:
    """policy_sentry classifies these as Write/Permissions management
    → baseline rejects. These are the CRIT gaps the Opus audit found:
    every one of them passed through the old deny_verbs list. The new
    baseline-gate denies them structurally."""
    from iam_jit.bouncer.profiles import _action_in_baseline
    assert not _action_in_baseline("aws_managed_readonly_access", "sts", "AssumeRole")
    assert not _action_in_baseline("aws_managed_readonly_access", "lambda", "InvokeFunction")
    assert not _action_in_baseline("aws_managed_readonly_access", "ssm", "SendCommand")
    assert not _action_in_baseline("aws_managed_readonly_access", "iam", "CreateAccessKey")
    assert not _action_in_baseline("aws_managed_readonly_access", "iam", "PassRole")
    assert not _action_in_baseline("aws_managed_readonly_access", "iam", "AttachRolePolicy")


def test_action_in_baseline_unknown_service_fails_closed() -> None:
    """Brand-new AWS service not yet in policy_sentry data → unknown.
    Resolver must FAIL CLOSED (return False), since the safety
    invariant is "agent can only do reads we've classified as reads."
    """
    from iam_jit.bouncer.profiles import _action_in_baseline
    assert not _action_in_baseline(
        "aws_managed_readonly_access", "nonexistent-svc-9999", "GetSomething",
    )


def test_action_in_baseline_star_sentinel_allows_everything() -> None:
    """The "*" sentinel disables baseline gating entirely (used by
    profiles that want deny_actions on top of pure passthrough)."""
    from iam_jit.bouncer.profiles import _action_in_baseline
    assert _action_in_baseline("*", "anything", "Whatsoever")


def test_action_in_baseline_unknown_baseline_name_raises() -> None:
    from iam_jit.bouncer.profiles import _action_in_baseline
    with pytest.raises(ValueError, match="unknown allow_baseline"):
        _action_in_baseline("not-a-baseline", "s3", "GetObject")


def test_action_in_baseline_lru_cache_avoids_repeat_lookups() -> None:
    """policy_sentry lookup happens once per service per process; the
    second call hits the lru_cache and returns instantly. Validates by
    inspecting the cache_info after a warm-up call."""
    from iam_jit.bouncer.profiles import _service_read_list_actions
    _service_read_list_actions.cache_clear()
    _service_read_list_actions("s3")  # warmup
    info1 = _service_read_list_actions.cache_info()
    _service_read_list_actions("s3")  # cached
    _service_read_list_actions("s3")  # cached
    info2 = _service_read_list_actions.cache_info()
    assert info2.hits == info1.hits + 2
    assert info2.misses == info1.misses


# --- safe-default end-to-end CRIT-gap regression tests --------------------


def test_safe_default_baseline_denies_sts_assume_role() -> None:
    """CRIT-gap-I-1 from Opus audit: sts:AssumeRole bypassed the
    `*:Delete*` / `*:Put*` etc deny list. New baseline blocks it because
    policy_sentry classifies AssumeRole as Write, so it's never in the
    baseline."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(sd, service="sts", action="AssumeRole")
    assert v.denied
    assert "allow_baseline" in v.reason


def test_safe_default_baseline_denies_lambda_invoke_function() -> None:
    """CRIT-gap-I-2 from Opus audit: lambda:InvokeFunction lets the
    agent run arbitrary code under the function's role. Write-classified
    → not in baseline → denied."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(sd, service="lambda", action="InvokeFunction")
    assert v.denied
    assert "allow_baseline" in v.reason


def test_safe_default_baseline_denies_ssm_send_command() -> None:
    """CRIT-gap-I-3 from Opus audit: ssm:SendCommand is EC2 RCE.
    Write-classified → not in baseline → denied."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(sd, service="ssm", action="SendCommand")
    assert v.denied
    assert "allow_baseline" in v.reason


def test_safe_default_baseline_denies_iam_pass_role() -> None:
    """CRIT-gap-I-4 from Opus audit: iam:PassRole is privilege transfer.
    Permissions-management classified → not in baseline → denied."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(sd, service="iam", action="PassRole")
    assert v.denied
    assert "allow_baseline" in v.reason


def test_safe_default_baseline_denies_iam_attach_role_policy() -> None:
    """CRIT-gap-I-5 from Opus audit: iam:AttachRolePolicy grants
    privileges without `Put`/`Create` shape. Permissions-management
    classified → not in baseline → denied."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(sd, service="iam", action="AttachRolePolicy")
    assert v.denied
    assert "allow_baseline" in v.reason


# --- safe-default subtract list -------------------------------------------


def test_safe_default_subtract_list_denies_secretsmanager_get_secret_value() -> None:
    """secretsmanager:GetSecretValue is in the subtract list. Whether
    policy_sentry classifies it as Read (baseline-eligible) or Write
    (baseline-excluded), the explicit deny_actions entry guarantees
    denial."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(sd, service="secretsmanager", action="GetSecretValue")
    assert v.denied


def test_safe_default_subtract_list_denies_kms_decrypt() -> None:
    """kms:Decrypt is in the subtract list. policy_sentry currently
    classifies it as Write (so the baseline gate already denies it),
    but the explicit deny_actions entry is belt-and-suspenders defense
    against future policy_sentry reclassification."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(sd, service="kms", action="Decrypt")
    assert v.denied


def test_safe_default_subtract_list_denies_ssm_get_parameter_securestring_path() -> None:
    """ssm:GetParameter* can return SecureString values. policy_sentry
    classifies them as Read so they'd be baseline-allowed; the
    deny_actions subtract list takes them out."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v1 = evaluate_profile(sd, service="ssm", action="GetParameter")
    v2 = evaluate_profile(sd, service="ssm", action="GetParameters")
    v3 = evaluate_profile(sd, service="ssm", action="GetParametersByPath")
    assert v1.denied and v2.denied and v3.denied
    assert all("deny_actions" in v.reason for v in (v1, v2, v3))


def test_safe_default_subtract_list_denies_ec2_get_password_data() -> None:
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(sd, service="ec2", action="GetPasswordData")
    assert v.denied


def test_safe_default_subtract_list_denies_cognito_admin_get_user() -> None:
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(sd, service="cognito-idp", action="AdminGetUser")
    assert v.denied


# --- safe-default permits the universal preflight surface ----------------


def test_safe_default_allows_get_caller_identity() -> None:
    """False-positive-K-2 analog: every AWS SDK preflights with
    sts:GetCallerIdentity. safe-default MUST allow it (would otherwise
    break every agent before its first useful call)."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    assert not evaluate_profile(sd, service="sts", action="GetCallerIdentity").denied


def test_safe_default_allows_iam_simulate_principal_policy() -> None:
    """Used by agents to introspect their own grants before acting.
    Read-classified, NOT in subtract list → allowed."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    assert not evaluate_profile(
        sd, service="iam", action="SimulatePrincipalPolicy",
    ).denied


def test_safe_default_allows_iam_get_user() -> None:
    """Allowed by baseline. NOT a confidentiality boundary — we know
    this leaks IAM metadata; documented explicitly in the profile
    description's "WHAT IT DOES NOT COVER" callout."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    assert not evaluate_profile(sd, service="iam", action="GetUser").denied


def test_safe_default_allows_ec2_describe_instances() -> None:
    profiles = load_profiles()
    sd = profiles["safe-default"]
    assert not evaluate_profile(sd, service="ec2", action="DescribeInstances").denied


# --- safe-default conditional denies -------------------------------------


def test_safe_default_conditional_deny_blocks_sensitive_dynamodb_scan() -> None:
    """deny_actions_with_condition entry: dynamodb:Scan against tables
    matching `secrets-*` is denied via resource_pattern condition."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(
        sd, service="dynamodb", action="Scan",
        arn="arn:aws:dynamodb:us-east-1:111122223333:table/secrets-prod",
    )
    assert v.denied
    assert "conditional" in v.reason.lower()


def test_safe_default_conditional_deny_does_not_block_unrelated_dynamodb_scan() -> None:
    """dynamodb:Scan against a NON-secrets table is allowed (baseline-
    eligible Read; conditional deny doesn't fire because resource_pattern
    doesn't match)."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(
        sd, service="dynamodb", action="Scan",
        arn="arn:aws:dynamodb:us-east-1:111122223333:table/orders",
    )
    assert not v.denied


def test_safe_default_conditional_deny_with_missing_arn_abstains() -> None:
    """resource_pattern condition needs an ARN to evaluate; with no
    ARN it abstains (does not deny). Baseline still allows the action
    (dynamodb:Scan is Read-classified). Documented behavior."""
    profiles = load_profiles()
    sd = profiles["safe-default"]
    v = evaluate_profile(sd, service="dynamodb", action="Scan", arn=None)
    assert not v.denied


# --- composition with existing fields ------------------------------------


def test_existing_keyword_deny_still_works_when_baseline_set() -> None:
    """Composition: a profile combining allow_baseline + deny_keywords
    fires the baseline check FIRST (CRIT writes blocked structurally)
    then keyword check (additional resource-name guardrail)."""
    custom = Profile(
        name="t",
        allow_baseline="aws_managed_readonly_access",
        deny_keywords=("prod",),
        keyword_targets=("arn",),
    )
    # Write action denied by baseline regardless of keyword
    v = evaluate_profile(
        custom, service="s3", action="DeleteObject",
        arn="arn:aws:s3:::dev-bucket",
    )
    assert v.denied and "allow_baseline" in v.reason
    # Read action against prod-ARN denied by keyword (after baseline
    # passes)
    v = evaluate_profile(
        custom, service="s3", action="GetObject",
        arn="arn:aws:s3:::prod-bucket/file",
    )
    assert v.denied and "keyword" in v.reason
    # Read against non-prod ARN: allowed (baseline pass + keyword miss)
    v = evaluate_profile(
        custom, service="s3", action="GetObject",
        arn="arn:aws:s3:::dev-bucket/file",
    )
    assert not v.denied


def test_existing_allow_rules_still_work_when_baseline_set() -> None:
    """allow_rules sit OUTSIDE evaluate_profile (consumed by the
    proxy's composed rule list). evaluate_profile must not crash or
    mis-classify when a profile sets BOTH allow_rules + allow_baseline.
    """
    from iam_jit.bouncer.profiles import ProfileAllowRule
    custom = Profile(
        name="t",
        allow_baseline="aws_managed_readonly_access",
        allow_rules=(ProfileAllowRule(pattern="s3:GetObject"),),
    )
    # evaluate_profile only consults the baseline + deny layers; the
    # allow_rules path is exercised by the proxy. This test verifies
    # composition doesn't break the evaluator.
    assert not evaluate_profile(custom, service="s3", action="GetObject").denied
    assert evaluate_profile(custom, service="s3", action="DeleteObject").denied


def test_unconditional_deny_actions_with_condition_entry() -> None:
    """A deny_actions_with_condition entry with NO condition field
    reduces to an unconditional deny (validated by the parser's "any
    dict is allowed for condition" tolerance). Important: protects
    against operator typo where they omit `condition:` and expect
    the rule to still fire."""
    custom = Profile(
        name="t",
        deny_actions_with_condition=(
            {"action": "s3:GetObject", "condition": {}},
        ),
    )
    v = evaluate_profile(custom, service="s3", action="GetObject")
    assert v.denied


# --- YAML parsing of new fields -------------------------------------------


def test_load_profiles_rejects_unknown_allow_baseline(tmp_path, monkeypatch) -> None:
    """Profile-load-time validation catches typos in allow_baseline
    (silent fallthrough would be a security regression)."""
    bad = tmp_path / "p.yaml"
    bad.write_text(yaml.safe_dump({
        "profiles": {"x": {"allow_baseline": "readonly-access"}},
    }))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(bad))
    with pytest.raises(ValueError, match="allow_baseline"):
        load_profiles()


def test_load_profiles_rejects_malformed_deny_actions_with_condition(
    tmp_path, monkeypatch,
) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text(yaml.safe_dump({
        "profiles": {"x": {
            "deny_actions_with_condition": [{"no_action_field": True}],
        }},
    }))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(bad))
    with pytest.raises(ValueError, match="deny_actions_with_condition"):
        load_profiles()


def test_load_profiles_round_trips_new_fields(tmp_path, monkeypatch) -> None:
    """Custom profile with all three new fields parses + round-trips."""
    custom = tmp_path / "p.yaml"
    custom.write_text(yaml.safe_dump({
        "profiles": {
            "custom-safe": {
                "description": "test",
                "allow_baseline": "aws_managed_readonly_access",
                "deny_actions": ["kms:Decrypt", "secretsmanager:GetSecretValue"],
                "deny_actions_with_condition": [
                    {"action": "s3:GetObject",
                     "condition": {"resource_pattern": "arn:aws:s3:::secret-*"}},
                ],
            },
        },
    }))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(custom))
    profiles = load_profiles()
    p = profiles["custom-safe"]
    assert p.allow_baseline == "aws_managed_readonly_access"
    assert "kms:Decrypt" in p.deny_actions
    assert len(p.deny_actions_with_condition) == 1
    assert p.deny_actions_with_condition[0]["action"] == "s3:GetObject"


# ---------------------------------------------------------------------------
# §A39 #371 — only_regions top-level field (multi-region scope floor)
# Per [[multi-account-region-cluster-use-case]] this is the launch-blocker
# primitive for operators routinely working across staging/prod regions.
# ---------------------------------------------------------------------------


def test_evaluate_profile_only_regions_match_allowed() -> None:
    """A request whose region IS in only_regions falls through to
    downstream rules (the profile abstains)."""
    profile = Profile(name="t", only_regions=("us-east-1", "us-west-2"))
    verdict = evaluate_profile(profile, region="us-east-1")
    assert not verdict.denied
    verdict = evaluate_profile(profile, region="us-west-2")
    assert not verdict.denied


def test_evaluate_profile_only_regions_mismatch_denied() -> None:
    """THE FLOOR TEST: a profile generated from observing us-east-1
    MUST DENY a request to eu-west-1. Per
    [[profile-generation-quality-bar]] this is the launch-blocker.
    """
    profile = Profile(name="staging", only_regions=("us-east-1",))
    verdict = evaluate_profile(profile, region="eu-west-1")
    assert verdict.denied
    assert "profile_only_regions" in verdict.reason
    assert "us-east-1" in verdict.reason
    assert "eu-west-1" in verdict.reason
    assert verdict.source == "profile"


def test_evaluate_profile_only_regions_unknown_region_denied() -> None:
    """Fail-CLOSED: a request with no region (parser failure) is
    DENIED when only_regions is set. Same shape as only_account_ids."""
    profile = Profile(name="t", only_regions=("us-east-1",))
    verdict = evaluate_profile(profile, region=None)
    assert verdict.denied
    assert "unknown" in verdict.reason


def test_evaluate_profile_only_regions_empty_no_restriction() -> None:
    """Empty tuple (default) means no region restriction; any region
    falls through to downstream rules."""
    profile = Profile(name="t")
    assert profile.only_regions == ()
    verdict = evaluate_profile(profile, region="us-east-1")
    assert not verdict.denied
    verdict = evaluate_profile(profile, region="eu-west-1")
    assert not verdict.denied


def test_only_regions_composes_with_only_account_ids() -> None:
    """only_account_ids fires BEFORE only_regions; both deny in their
    own right."""
    profile = Profile(
        name="t",
        only_account_ids=("111122223333",),
        only_regions=("us-east-1",),
    )
    # Wrong account → DENY on account check (fires first)
    v = evaluate_profile(
        profile, account_id="999988887777", region="us-east-1",
    )
    assert v.denied
    assert "profile_only_account_ids" in v.reason
    # Right account, wrong region → DENY on region check
    v = evaluate_profile(
        profile, account_id="111122223333", region="eu-west-1",
    )
    assert v.denied
    assert "profile_only_regions" in v.reason
    # Right both → no objection
    v = evaluate_profile(
        profile, account_id="111122223333", region="us-east-1",
    )
    assert not v.denied


def test_profile_yaml_roundtrip_only_regions(tmp_path: pathlib.Path) -> None:
    """only_regions survives the YAML round-trip (write → load)."""
    from iam_jit.bouncer.profiles import (
        load_profiles, profile_to_yaml_dict, upsert_profile,
    )
    custom = tmp_path / "profiles.yaml"
    p = Profile(
        name="multi-region",
        description="staging in two regions",
        only_account_ids=("111122223333",),
        only_regions=("us-east-1", "us-west-2"),
    )
    upsert_profile(p, path=custom)
    body = profile_to_yaml_dict(p)
    assert body["only_regions"] == ["us-east-1", "us-west-2"]
    loaded = load_profiles(custom)
    assert "multi-region" in loaded
    lp = loaded["multi-region"]
    assert lp.only_regions == ("us-east-1", "us-west-2")
    assert lp.only_account_ids == ("111122223333",)


def test_translate_generator_shape_only_regions(tmp_path: pathlib.Path) -> None:
    """The generator-shape parser bridge passes only_regions through
    untouched (the field is not in the strip-list)."""
    from iam_jit.bouncer.profiles import load_profiles
    custom = tmp_path / "profiles.yaml"
    # Mimic the LLM-generator emit shape: top-level allows/denies +
    # scope fields alongside.
    custom.write_text(yaml.safe_dump({
        "profiles": {
            "audit-gen": {
                "schema_version": 1,
                "bouncer": "ibounce",
                "only_account_ids": ["111122223333"],
                "only_regions": ["us-east-1"],
                "allows": [
                    {
                        "target": "arn:aws:s3:::reports-bucket",
                        "actions": ["s3:GetObject"],
                        "reason": "observed read",
                    },
                ],
                "denies": [],
            },
        },
    }))
    profiles = load_profiles(custom)
    p = profiles["audit-gen"]
    assert p.only_account_ids == ("111122223333",)
    assert p.only_regions == ("us-east-1",)
    # The translator surfaced the action into deny_actions / allow_rules
    # as the schema bridge dictates; only_regions sits beside untouched.
    assert any(r.pattern == "s3:GetObject" for r in p.allow_rules)


def test_evaluate_profile_only_regions_profile_full_user_no_op() -> None:
    """Profile with only only_regions empty + nothing else set still
    short-circuits the no-op path."""
    profile = Profile(name="full-user")
    # No region passed; no fields set → no objection.
    verdict = evaluate_profile(profile)
    assert not verdict.denied
