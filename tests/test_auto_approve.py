"""Auto-approve decision logic + per-user quota guard.

Covers the four gates in `iam_jit.auto_approve.evaluate`:
  1. Feature gate (auto_approve_risk_below set)
  2. Threshold gate (score < threshold)
  3. Context gate (service/account blocklist)
  4. Quota gate (per-user sliding-window cap)

Plus the composability-attack regression: a stream of N+1
low-risk requests from one user → the (N+1)th is forced to
human review even though it scores low.
"""

from __future__ import annotations

import pytest

from iam_jit.auto_approve import evaluate
from iam_jit.rate_limit import InMemoryRateLimiter
from iam_jit.settings_store import Settings


# ---- Helpers ----


def _request(
    *,
    service: str = "s3",
    action: str = "s3:GetObject",
    account_id: str = "111111111111",
    access_type: str = "read-only",
) -> dict:
    return {
        "spec": {
            "accounts": [{"account_id": account_id}],
            "access_type": access_type,
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": action,
                        "Resource": f"arn:aws:{service}:::example/*",
                    }
                ],
            },
        },
    }


def _quota_limiter(cap: int = 100) -> InMemoryRateLimiter:
    """Build a rate limiter that allows `cap` requests in the window.
    The shared RateLimiter denies once count > soft_cap, so to express
    "allow N", set soft_cap=N. hard_cap stays well above to satisfy
    the constructor's soft < hard guard."""
    return InMemoryRateLimiter(
        soft_cap=cap, hard_cap=cap * 10 + 1, window_seconds=3600,
    )


# ---- Gate 1: feature disabled ----


def test_feature_disabled_when_threshold_unset() -> None:
    decision = evaluate(
        request=_request(),
        analysis_score=1,
        user_id="email:dev@example.com",
        settings=Settings(),  # default: threshold None
        quota_limiter=_quota_limiter(),
    )
    assert not decision.auto_approve
    assert decision.reason == "feature_disabled"


# ---- Gate 2: threshold ----


def test_below_threshold_auto_approves() -> None:
    decision = evaluate(
        request=_request(service="ec2", action="ec2:DescribeInstances"),
        analysis_score=2,
        user_id="email:dev@example.com",
        settings=Settings(auto_approve_risk_below=4),
        quota_limiter=_quota_limiter(),
    )
    assert decision.auto_approve
    assert decision.reason == "success"
    assert decision.details["score"] == 2
    assert decision.details["threshold"] == 4


def test_at_threshold_does_NOT_auto_approve() -> None:
    """Threshold is strict-less-than. Score exactly == threshold must
    route to human review — this is the calibration semantics
    documented in docs/USE-CASES.md."""
    decision = evaluate(
        request=_request(),
        analysis_score=4,
        user_id="email:dev@example.com",
        settings=Settings(auto_approve_risk_below=4),
        quota_limiter=_quota_limiter(),
    )
    assert not decision.auto_approve
    assert decision.reason == "above_threshold"


def test_above_threshold_does_not_auto_approve() -> None:
    decision = evaluate(
        request=_request(),
        analysis_score=8,
        user_id="email:dev@example.com",
        settings=Settings(auto_approve_risk_below=4),
        quota_limiter=_quota_limiter(),
    )
    assert not decision.auto_approve
    assert decision.reason == "above_threshold"


# ---- Gate 3: context (service/account blocklist) ----


def test_blocklisted_service_blocks_auto_approve() -> None:
    """A request that scores low but touches a sensitive service
    must route to human review regardless of score."""
    decision = evaluate(
        request=_request(service="iam", action="iam:GetRole"),
        analysis_score=1,
        user_id="email:dev@example.com",
        settings=Settings(
            auto_approve_risk_below=5,
            never_auto_approve_services=("iam",),
        ),
        quota_limiter=_quota_limiter(),
    )
    assert not decision.auto_approve
    assert decision.reason == "service_blocked"
    assert decision.details["service"] == "iam"


def test_blocklisted_account_blocks_auto_approve() -> None:
    """A request against a sensitive account (e.g. prod) bypasses
    auto-approve regardless of score."""
    decision = evaluate(
        request=_request(account_id="999999999999"),
        analysis_score=1,
        user_id="email:dev@example.com",
        settings=Settings(
            auto_approve_risk_below=5,
            never_auto_approve_accounts=("999999999999",),
        ),
        quota_limiter=_quota_limiter(),
    )
    assert not decision.auto_approve
    assert decision.reason == "account_blocked"
    assert decision.details["account_id"] == "999999999999"


def test_default_service_blocklist_protects_iam() -> None:
    """The default Settings() blocklists iam, organizations, sts,
    kms, secretsmanager. Lock that in so a refactor that loosens
    it fails this test."""
    s = Settings(auto_approve_risk_below=10)
    assert "iam" in s.never_auto_approve_services
    assert "kms" in s.never_auto_approve_services
    assert "secretsmanager" in s.never_auto_approve_services


# ---- Gate 4: per-user quota (composability attack) ----


def test_per_user_quota_caps_auto_approvals() -> None:
    """Composability-attack regression: a stream of N+1 low-risk
    auto-approve-eligible requests from ONE user must see the (N+1)th
    forced to human review. Even though each individual request
    scores low, the cumulative rate triggers the quota gate."""
    settings = Settings(
        auto_approve_risk_below=5,
        auto_approve_quota_per_hour=3,
    )
    quota = _quota_limiter(cap=3)

    user = "email:dev@example.com"
    decisions = []
    for i in range(5):
        d = evaluate(
            request=_request(),
            analysis_score=1,
            user_id=user,
            settings=settings,
            quota_limiter=quota,
        )
        decisions.append(d)

    approved = [d for d in decisions if d.auto_approve]
    blocked = [d for d in decisions if not d.auto_approve]
    assert len(approved) == 3, (
        f"first 3 should auto-approve; got {len(approved)}: "
        f"{[d.reason for d in decisions]}"
    )
    assert len(blocked) == 2, (
        f"4th and 5th should hit quota; got {[d.reason for d in decisions]}"
    )
    for d in blocked:
        assert d.reason == "over_quota"


def test_quota_is_per_user_not_global() -> None:
    """User A burning their quota must not affect user B."""
    settings = Settings(
        auto_approve_risk_below=5,
        auto_approve_quota_per_hour=2,
    )
    quota = _quota_limiter(cap=2)

    # User A consumes the quota.
    for _ in range(2):
        d = evaluate(
            request=_request(),
            analysis_score=1,
            user_id="email:alice@example.com",
            settings=settings,
            quota_limiter=quota,
        )
        assert d.auto_approve

    # User B's first request should still auto-approve.
    d = evaluate(
        request=_request(),
        analysis_score=1,
        user_id="email:bob@example.com",
        settings=settings,
        quota_limiter=quota,
    )
    assert d.auto_approve
    assert d.reason == "success"


# ---- Edge cases ----


def test_empty_policy_does_not_auto_approve() -> None:
    request = {"spec": {"policy": {"Version": "2012-10-17", "Statement": []}}}
    decision = evaluate(
        request=request,
        analysis_score=1,
        user_id="email:dev@example.com",
        settings=Settings(auto_approve_risk_below=5),
        quota_limiter=_quota_limiter(),
    )
    assert not decision.auto_approve
    assert decision.reason == "no_policy"


def test_threshold_zero_disables_feature() -> None:
    """A threshold of 0 means "auto-approve nothing" — score 1 is
    not less than 0. Defensive: even if an admin set this oddly,
    feature stays effectively off."""
    decision = evaluate(
        request=_request(),
        analysis_score=1,
        user_id="email:dev@example.com",
        settings=Settings(auto_approve_risk_below=0),
        quota_limiter=_quota_limiter(),
    )
    # auto_approve_enabled is False for threshold=None or threshold≤0
    assert not decision.auto_approve
    # The reason should be feature_disabled (matches Settings.auto_approve_enabled property)
    assert decision.reason == "feature_disabled"


def test_panic_switch_via_settings_dataclass() -> None:
    """An admin can disable auto-approve by setting threshold=None.
    Lock this in so a refactor doesn't introduce a different
    'disabled' representation that the evaluator misses."""
    s = Settings(auto_approve_risk_below=None)
    assert not s.auto_approve_enabled


# ---- Preset toggles ----


def test_force_review_toggle_routes_low_risk_to_human() -> None:
    """The 'do not auto-approve anything in production' toggle:
    when enabled, even a score-1 request against the prod account
    goes to human review."""
    from iam_jit.settings_store import PresetToggle

    settings = Settings(
        auto_approve_risk_below=10,
        never_auto_approve_services=(),
        preset_toggles=(
            PresetToggle(
                id="no_prod_auto",
                name="No auto-approve in production",
                description="prod must always go through human review",
                enabled=True,
                condition={"account_id": "999999999999"},
                action="force_review_if",
            ),
        ),
    )
    decision = evaluate(
        request=_request(account_id="999999999999"),
        analysis_score=1,
        user_id="email:dev@example.com",
        settings=settings,
        quota_limiter=_quota_limiter(),
    )
    assert not decision.auto_approve
    assert decision.reason == "toggle_force_review"
    assert decision.details["toggle_id"] == "no_prod_auto"


def test_force_review_toggle_disabled_lets_request_through() -> None:
    """A disabled toggle has no effect — the request flows through
    normal gates."""
    from iam_jit.settings_store import PresetToggle

    settings = Settings(
        auto_approve_risk_below=10,
        never_auto_approve_services=(),
        preset_toggles=(
            PresetToggle(
                id="no_prod_auto",
                name="No prod",
                description="",
                enabled=False,  # disabled
                condition={"account_id": "999999999999"},
                action="force_review_if",
            ),
        ),
    )
    decision = evaluate(
        request=_request(account_id="999999999999"),
        analysis_score=1,
        user_id="email:dev@example.com",
        settings=settings,
        quota_limiter=_quota_limiter(),
    )
    assert decision.auto_approve


def test_auto_approve_toggle_overrides_score_gate() -> None:
    """The 'approve all requests in development' toggle: when
    enabled, a request that scores ABOVE the normal threshold can
    still auto-approve via the toggle. Floors still apply (account/
    service blocklist)."""
    from iam_jit.settings_store import PresetToggle

    settings = Settings(
        auto_approve_risk_below=3,  # would normally reject score 6
        never_auto_approve_services=(),
        preset_toggles=(
            PresetToggle(
                id="dev_auto",
                name="Auto-approve all in development",
                description="dev sandbox — anything goes",
                enabled=True,
                condition={"account_id": "060392206767"},  # dev account
                action="auto_approve_if",
            ),
        ),
    )
    decision = evaluate(
        request=_request(account_id="060392206767"),
        analysis_score=6,  # above the threshold
        user_id="email:dev@example.com",
        settings=settings,
        quota_limiter=_quota_limiter(),
    )
    assert decision.auto_approve
    assert decision.reason == "success_via_toggle"
    assert decision.details["toggle_id"] == "dev_auto"


def test_auto_approve_toggle_still_blocked_by_floor_account() -> None:
    """Even an enabled auto_approve_if toggle cannot bypass the
    account blocklist floor. This is the safety: admin enables
    'approve all in dev' but accidentally targets the prod account
    — the floor refuses anyway."""
    from iam_jit.settings_store import PresetToggle

    settings = Settings(
        auto_approve_risk_below=3,
        never_auto_approve_accounts=("999999999999",),  # prod
        never_auto_approve_services=(),
        preset_toggles=(
            PresetToggle(
                id="approve_anything",
                name="DANGEROUS",
                description="",
                enabled=True,
                condition={"account_id": "999999999999"},
                action="auto_approve_if",
            ),
        ),
    )
    decision = evaluate(
        request=_request(account_id="999999999999"),
        analysis_score=1,
        user_id="email:dev@example.com",
        settings=settings,
        quota_limiter=_quota_limiter(),
    )
    assert not decision.auto_approve
    assert decision.reason == "account_blocked"


def test_readonly_toggle_matches_only_readonly_requests() -> None:
    """The 'approve all read-only in staging' toggle: an
    `access_type=read-only` request matches; an `access_type=
    read-write` request does NOT."""
    from iam_jit.settings_store import PresetToggle

    toggle = PresetToggle(
        id="readonly_staging",
        name="Auto-approve read-only in staging",
        description="",
        enabled=True,
        condition={"account_id": "111111111111", "access_type": "read-only"},
        action="auto_approve_if",
    )
    settings = Settings(
        auto_approve_risk_below=2,  # most requests above this
        never_auto_approve_services=(),
        preset_toggles=(toggle,),
    )

    # Read-only matches → auto-approve
    req_readonly = _request(account_id="111111111111")  # default read-only
    decision = evaluate(
        request=req_readonly,
        analysis_score=5,
        user_id="email:dev@example.com",
        settings=settings,
        quota_limiter=_quota_limiter(),
    )
    assert decision.auto_approve
    assert decision.reason == "success_via_toggle"

    # Read-write does NOT match → falls through to score gate → rejected
    req_readwrite = _request(account_id="111111111111")
    req_readwrite["spec"]["policy"]["Statement"][0]["Action"] = "s3:PutObject"
    # Manually flip access_type for this test
    req_readwrite_v = dict(req_readwrite)
    req_readwrite_v["spec"] = dict(req_readwrite_v["spec"])
    req_readwrite_v["spec"]["access_type"] = "read-write"
    decision = evaluate(
        request=req_readwrite_v,
        analysis_score=5,
        user_id="email:dev@example.com",
        settings=settings,
        quota_limiter=_quota_limiter(),
    )
    assert not decision.auto_approve
    assert decision.reason == "above_threshold"


def test_force_review_wins_over_auto_approve_when_both_match() -> None:
    """If a request matches BOTH a force_review_if AND an
    auto_approve_if toggle, the force_review wins. Conservative
    deny-side bias."""
    from iam_jit.settings_store import PresetToggle

    settings = Settings(
        auto_approve_risk_below=10,
        never_auto_approve_services=(),
        preset_toggles=(
            PresetToggle(
                id="no_iam",
                name="No IAM",
                description="",
                enabled=True,
                condition={"service": "iam"},
                action="force_review_if",
            ),
            PresetToggle(
                id="approve_dev",
                name="Approve all dev",
                description="",
                enabled=True,
                condition={"account_id": "060392206767"},
                action="auto_approve_if",
            ),
        ),
    )
    # Request targets dev account (auto_approve_if would match)
    # AND uses iam: (force_review_if would match). Deny wins.
    req = _request(action="iam:GetRole", account_id="060392206767")
    decision = evaluate(
        request=req,
        analysis_score=1,
        user_id="email:dev@example.com",
        settings=settings,
        quota_limiter=_quota_limiter(),
    )
    assert not decision.auto_approve
    assert decision.reason == "toggle_force_review"
    assert decision.details["toggle_id"] == "no_iam"


# ---- Floor enforcement ----


def test_floors_reject_loosened_threshold() -> None:
    """Admin can NEVER set auto_approve_risk_below higher than the
    deploy-time floor."""
    from iam_jit.settings_store import (
        Floors, Settings, validate_against_floors,
    )

    floors = Floors(max_auto_approve_risk_below=5)
    too_high = Settings(auto_approve_risk_below=8)
    errors = validate_against_floors(too_high, floors)
    assert errors
    assert any("exceeds floor of 5" in e for e in errors)


def test_floors_reject_removed_required_service() -> None:
    """Admin can ADD services to the blocklist but can NEVER remove
    one that's in RequiredServiceBlocklist."""
    from iam_jit.settings_store import (
        Floors, Settings, validate_against_floors,
    )

    floors = Floors(required_service_blocklist=("iam", "kms"))
    missing_iam = Settings(
        never_auto_approve_services=("kms",),  # iam removed
    )
    errors = validate_against_floors(missing_iam, floors)
    assert errors
    assert any("iam" in e for e in errors)


def test_floors_accept_tightened_settings() -> None:
    """Admin can set MORE restrictive values than the floor."""
    from iam_jit.settings_store import (
        Floors, Settings, validate_against_floors,
    )

    floors = Floors(
        max_auto_approve_risk_below=5,
        required_service_blocklist=("iam",),
    )
    tighter = Settings(
        auto_approve_risk_below=3,  # below 5 (more restrictive)
        never_auto_approve_services=("iam", "kms", "ec2"),  # superset of floor
    )
    errors = validate_against_floors(tighter, floors)
    assert not errors
