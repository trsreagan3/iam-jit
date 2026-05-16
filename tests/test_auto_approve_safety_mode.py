"""Pinned tests for safety-mode threshold wiring into auto_approve.

Per [[safety-mode-two-modes]] memo. The `effective_threshold`
parameter on `auto_approve.evaluate` lets the caller override
the deployment-wide setting based on safety mode + access_type.
"""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit import auto_approve, safety_mode
from iam_jit.rate_limit import InMemoryRateLimiter
from iam_jit.settings_store import Settings


def _request(score: int = 3) -> dict[str, Any]:
    return {
        "spec": {
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::x"}
                ],
            },
            "accounts": [{"account_id": "123456789012"}],
        },
    }


def _settings(threshold: int = 4) -> Settings:
    # never_auto_approve_services defaults to a real list; override
    # to empty for these tests so the service-blocklist gate
    # doesn't fire on our test S3 policy.
    return Settings(
        auto_approve_risk_below=threshold,
        auto_approve_quota_per_hour=100,
        never_auto_approve_services=(),
        never_auto_approve_accounts=(),
    )


def _limiter() -> InMemoryRateLimiter:
    return InMemoryRateLimiter(soft_cap=100, hard_cap=1000, window_seconds=3600)


# ---------------------------------------------------------------------------
# Default behavior (no effective_threshold provided)
# ---------------------------------------------------------------------------


def test_default_uses_settings_threshold() -> None:
    """Without effective_threshold, falls back to settings."""
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=3,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
    )
    assert decision.auto_approve is True


def test_default_blocks_at_settings_threshold() -> None:
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=7,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
    )
    assert decision.auto_approve is False
    assert decision.reason == "above_threshold"
    assert decision.details["threshold"] == 4


# ---------------------------------------------------------------------------
# effective_threshold override
# ---------------------------------------------------------------------------


def test_effective_threshold_overrides_settings() -> None:
    """Read-only in safety_mode=read_write_swap has threshold 9.
    A score of 7 should auto-approve even though settings has
    threshold 4."""
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=7,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=9,  # safety_mode read threshold
    )
    assert decision.auto_approve is True


def test_effective_threshold_can_be_tighter() -> None:
    """Write in safety_mode=strict has threshold 2. A score of 3
    should NOT auto-approve even though settings has threshold 4."""
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=3,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=2,  # safety_mode strict-write threshold
    )
    assert decision.auto_approve is False
    assert decision.details["threshold"] == 2  # the override, not 4


def test_effective_threshold_zero_distinct_from_none() -> None:
    """effective_threshold=0 means 'deny everything score >= 0',
    which is effectively 'no auto-approve.' Must be distinct from
    None (which falls back to settings)."""
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=1,
        user_id="alice",
        settings=_settings(threshold=10),  # would auto-approve at score 1
        quota_limiter=_limiter(),
        effective_threshold=0,
    )
    assert decision.auto_approve is False


# ---------------------------------------------------------------------------
# Composition with safety_mode helpers
# ---------------------------------------------------------------------------


def test_safety_mode_read_write_swap_read_threshold() -> None:
    """Verify the threshold from safety_mode helper matches expected."""
    threshold = safety_mode.auto_approve_threshold_for(
        "read_write_swap", access_type="read-only",
    )
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=8,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=threshold,
    )
    # threshold is 9; score 8 < 9 → auto-approve
    assert decision.auto_approve is True


def test_safety_mode_strict_write_threshold() -> None:
    """Strict mode + write = threshold 2."""
    threshold = safety_mode.auto_approve_threshold_for(
        "strict", access_type="read-write",
    )
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=3,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=threshold,
    )
    # threshold is 2; score 3 >= 2 → reject
    assert decision.auto_approve is False
    assert decision.details["threshold"] == 2


def test_safety_mode_strict_read_still_permissive() -> None:
    """Strict mode reads still auto-approve at moderate scores
    (threshold 5)."""
    threshold = safety_mode.auto_approve_threshold_for(
        "strict", access_type="read-only",
    )
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=3,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=threshold,
    )
    # threshold is 5; score 3 < 5 → auto-approve
    assert decision.auto_approve is True


# ---------------------------------------------------------------------------
# WB10-02: floor_max_auto_approve_risk_below clamps effective_threshold
# ---------------------------------------------------------------------------


def test_floor_clamps_effective_threshold_blocks_above_floor() -> None:
    """read_write_swap + read-only resolver hands back 9; floor=5
    clamps to 5; score=8 must be blocked (was auto-approved pre-fix)."""
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=8,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=9,  # safety-mode resolver output
        floor_max_auto_approve_risk_below=5,  # platform-team ceiling
    )
    assert decision.auto_approve is False
    assert decision.reason == "above_threshold"
    assert decision.details["threshold"] == 5
    assert decision.details["threshold_pre_clamp"] == 9
    assert decision.details["floor_max_auto_approve_risk_below"] == 5


def test_floor_does_not_clamp_when_threshold_already_below_floor() -> None:
    """Strict mode threshold=2 with floor=5 → no clamp, no clamp metadata."""
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=3,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=2,
        floor_max_auto_approve_risk_below=5,
    )
    assert decision.auto_approve is False
    assert decision.reason == "above_threshold"
    assert decision.details["threshold"] == 2
    assert "threshold_pre_clamp" not in decision.details


def test_floor_none_means_no_clamp() -> None:
    """When caller doesn't pass a floor (e.g., unit tests), no clamp."""
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=7,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=9,
        floor_max_auto_approve_risk_below=None,
    )
    # 7 < 9, no floor: auto-approves
    assert decision.auto_approve is True


# ---------------------------------------------------------------------------
# WB10-03: resolve_mode_for_accounts picks most-restrictive mode
# ---------------------------------------------------------------------------


class _StubAccount:
    def __init__(self, account_id: str, override: str | None) -> None:
        self.account_id = account_id
        self.safety_mode_override = override


class _StubStore:
    def __init__(self, by_id: dict[str, _StubAccount]) -> None:
        self._by_id = by_id

    def get(self, account_id: str) -> _StubAccount:
        return self._by_id[account_id]


def test_resolve_mode_for_accounts_strict_wins_over_default() -> None:
    """[dev (no override), prod (strict override)] must resolve as strict."""
    store = _StubStore({
        "111111111111": _StubAccount("111111111111", None),
        "222222222222": _StubAccount("222222222222", "strict"),
    })
    mode = safety_mode.resolve_mode_for_accounts(
        account_ids=["111111111111", "222222222222"],
        accounts_store=store,
    )
    assert mode == safety_mode.SAFETY_MODE_STRICT


def test_resolve_mode_for_accounts_all_default_stays_default() -> None:
    store = _StubStore({
        "111111111111": _StubAccount("111111111111", None),
        "222222222222": _StubAccount("222222222222", None),
    })
    mode = safety_mode.resolve_mode_for_accounts(
        account_ids=["111111111111", "222222222222"],
        accounts_store=store,
    )
    assert mode == safety_mode.SAFETY_MODE_READ_WRITE_SWAP


def test_resolve_mode_for_accounts_empty_falls_back() -> None:
    mode = safety_mode.resolve_mode_for_accounts(
        account_ids=[],
        accounts_store=None,
    )
    assert mode == safety_mode.SAFETY_MODE_READ_WRITE_SWAP


def test_resolve_mode_for_accounts_session_override_strictest() -> None:
    """Session-supplied --strict beats account-level read_write_swap."""
    store = _StubStore({
        "111111111111": _StubAccount("111111111111", None),
    })
    mode = safety_mode.resolve_mode_for_accounts(
        account_ids=["111111111111"],
        accounts_store=store,
        session_override="strict",
    )
    assert mode == safety_mode.SAFETY_MODE_STRICT


# ---------------------------------------------------------------------------
# WB10-04: SafetyModeThresholds.allow_action_wildcards +
# allow_admin_fallback are wired into auto_approve.evaluate.
# ---------------------------------------------------------------------------


def _strict_thresholds() -> safety_mode.SafetyModeThresholds:
    return safety_mode.thresholds_for(safety_mode.SAFETY_MODE_STRICT)


def _permissive_thresholds() -> safety_mode.SafetyModeThresholds:
    return safety_mode.thresholds_for(safety_mode.SAFETY_MODE_READ_WRITE_SWAP)


def _request_with(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "spec": {
            "policy": policy,
            "accounts": [{"account_id": "123456789012"}],
        },
    }


def test_strict_mode_blocks_action_wildcard() -> None:
    """strict.allow_action_wildcards=False → s3:Get* forces review."""
    decision = auto_approve.evaluate(
        request=_request_with({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}
            ],
        }),
        analysis_score=1,  # would otherwise pass threshold
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=4,
        safety_thresholds=_strict_thresholds(),
    )
    assert decision.auto_approve is False
    assert decision.reason == "strict_mode_action_wildcard"
    assert decision.details["offending_action"] == "s3:Get*"


def test_strict_mode_blocks_question_wildcard() -> None:
    """`?` is also an IAM wildcard primitive — must trip the gate."""
    decision = auto_approve.evaluate(
        request=_request_with({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObjec?", "Resource": "*"}
            ],
        }),
        analysis_score=1,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=4,
        safety_thresholds=_strict_thresholds(),
    )
    assert decision.auto_approve is False
    assert decision.reason == "strict_mode_action_wildcard"


def test_strict_mode_blocks_admin_fallback() -> None:
    """strict.allow_admin_fallback=False → Action:* + Resource:* forces review."""
    decision = auto_approve.evaluate(
        request=_request_with({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}
            ],
        }),
        analysis_score=1,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=4,
        safety_thresholds=_strict_thresholds(),
    )
    # Wildcard gate fires first (Action="*" is also a wildcard).
    assert decision.auto_approve is False
    assert decision.reason in (
        "strict_mode_action_wildcard",
        "strict_mode_admin_fallback",
    )


def test_permissive_mode_allows_action_wildcard() -> None:
    """read_write_swap.allow_action_wildcards=True → s3:Get* passes the gate."""
    decision = auto_approve.evaluate(
        request=_request_with({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::x"}
            ],
        }),
        analysis_score=1,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=4,
        safety_thresholds=_permissive_thresholds(),
    )
    assert decision.auto_approve is True


def test_no_safety_thresholds_skips_strict_gates() -> None:
    """When caller doesn't pass safety_thresholds, strict gates are skipped
    (backwards compat for older call sites)."""
    decision = auto_approve.evaluate(
        request=_request_with({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}
            ],
        }),
        analysis_score=1,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=4,
        safety_thresholds=None,
    )
    # Strict gates skipped → would auto-approve (only score gate applies)
    assert decision.auto_approve is True


# ---------------------------------------------------------------------------
# WB11-01: per-account safety_mode_override cannot DOWNGRADE the
# deployment default. Most-restrictive of (account, deployment) wins.
# ---------------------------------------------------------------------------


def test_account_override_cannot_downgrade_strict_deployment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deployment is strict; one account has override read_write_swap.
    Single-account request must STILL resolve as strict — overrides
    can strengthen, never weaken. Pre-fix: account override won.
    """
    monkeypatch.setenv("IAM_JIT_SAFETY_MODE", "strict")

    class _StubAccount:
        safety_mode_override = "read_write_swap"

    class _StubStore:
        def get(self, account_id: str) -> _StubAccount:
            return _StubAccount()

    mode = safety_mode.resolve_mode(
        account_id="111111111111", accounts_store=_StubStore(),
    )
    assert mode == safety_mode.SAFETY_MODE_STRICT


def test_account_override_can_strengthen_default_deployment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deployment is read_write_swap; one account has override strict.
    The single-account request resolves as strict (override-up allowed).
    """
    monkeypatch.delenv("IAM_JIT_SAFETY_MODE", raising=False)

    class _StubAccount:
        safety_mode_override = "strict"

    class _StubStore:
        def get(self, account_id: str) -> _StubAccount:
            return _StubAccount()

    mode = safety_mode.resolve_mode(
        account_id="111111111111", accounts_store=_StubStore(),
    )
    assert mode == safety_mode.SAFETY_MODE_STRICT


def test_no_account_override_uses_deployment_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_SAFETY_MODE", "strict")

    class _StubAccount:
        safety_mode_override = None

    class _StubStore:
        def get(self, account_id: str) -> _StubAccount:
            return _StubAccount()

    mode = safety_mode.resolve_mode(
        account_id="111111111111", accounts_store=_StubStore(),
    )
    assert mode == safety_mode.SAFETY_MODE_STRICT


# ---------------------------------------------------------------------------
# WB11-02: NotAction in an Allow statement counts as wildcard
# expansion under the strict-mode action-wildcard gate.
# ---------------------------------------------------------------------------


def test_strict_mode_blocks_not_action_allow() -> None:
    """`Effect: Allow, NotAction: "iam:*"` = "everything except IAM"
    — an unbounded action set. Strict mode must route to review.
    """
    decision = auto_approve.evaluate(
        request=_request_with({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "iam:*",
                    "Resource": "*",
                }
            ],
        }),
        analysis_score=1,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=4,
        safety_thresholds=_strict_thresholds(),
    )
    assert decision.auto_approve is False
    assert decision.reason == "strict_mode_action_wildcard"
    assert decision.details["offending_action"].startswith("NotAction:")


def test_strict_mode_blocks_not_action_array_allow() -> None:
    decision = auto_approve.evaluate(
        request=_request_with({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": ["iam:DeleteUser", "iam:DeleteRole"],
                    "Resource": "*",
                }
            ],
        }),
        analysis_score=1,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=4,
        safety_thresholds=_strict_thresholds(),
    )
    assert decision.auto_approve is False
    assert decision.reason == "strict_mode_action_wildcard"


def test_strict_mode_does_not_block_not_action_in_deny() -> None:
    """`Effect: Deny, NotAction:` is a perfectly valid allow-list pattern
    (deny everything except a small set). The strict gate only fires on
    Allow statements."""
    decision = auto_approve.evaluate(
        request=_request_with({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::x",
                },
                {
                    "Effect": "Deny",
                    "NotAction": ["s3:GetObject"],
                    "Resource": "*",
                },
            ],
        }),
        analysis_score=1,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=4,
        safety_thresholds=_strict_thresholds(),
    )
    assert decision.auto_approve is True


# WB11-11 regression: Unicode wildcard lookalikes trip the strict gate.
@pytest.mark.parametrize("lookalike", ["＊", "？", "⁎", "✱", "∗"])
def test_strict_mode_blocks_unicode_wildcard_lookalikes(lookalike: str) -> None:
    decision = auto_approve.evaluate(
        request=_request_with({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": f"s3:Get{lookalike}", "Resource": "*"}
            ],
        }),
        analysis_score=1,
        user_id="alice",
        settings=_settings(threshold=4),
        quota_limiter=_limiter(),
        effective_threshold=4,
        safety_thresholds=_strict_thresholds(),
    )
    assert decision.auto_approve is False
    assert decision.reason == "strict_mode_action_wildcard"


# WB11-17 regression: when both threshold inputs are None, return
# feature_disabled instead of TypeError on `score >= None`.
def test_evaluate_no_threshold_returns_feature_disabled() -> None:
    decision = auto_approve.evaluate(
        request=_request(),
        analysis_score=5,
        user_id="alice",
        settings=Settings(
            auto_approve_risk_below=None,
            auto_approve_quota_per_hour=10,
            never_auto_approve_services=(),
            never_auto_approve_accounts=(),
        ),
        quota_limiter=_limiter(),
        effective_threshold=None,
    )
    assert decision.auto_approve is False
    assert decision.reason == "feature_disabled"
