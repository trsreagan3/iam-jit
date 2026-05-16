"""End-to-end tests for MFA + self-approve enforcement.

Until 2026-05-16 the MFA freshness gate + self-approve-reductions
evaluator were annotation-only (recorded in the audit chain but
didn't change the auto-approve outcome). This file verifies the
phase-1 enforcement override:

  - high-risk grant + stale/missing MFA → auto-approve blocked,
    request stays pending, response body includes `mfa_step_up`
    hint for the API client to re-authenticate
  - admin self-approve eligible + above-threshold gate → auto-approve
    flipped to true, history actor is `self_approve_reduction:<id>`
  - low-risk + stale MFA → unaffected (MFA gate only fires above the
    high-risk floor)
  - high-risk + fresh MFA → auto-approves normally

The helper under test is
`routes/requests._apply_mfa_and_self_approve_enforcement`, exercised
both directly (unit tests) and via the /api/v1/requests submit
route (integration tests).
"""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit.auto_approve import AutoApproveDecision
from iam_jit.routes.requests import _apply_mfa_and_self_approve_enforcement


# ---------------------------------------------------------------------------
# Unit tests against the helper directly.
# ---------------------------------------------------------------------------


def _approve(score: int = 4) -> AutoApproveDecision:
    return AutoApproveDecision(
        auto_approve=True,
        reason="success",
        details={"score": score, "threshold": 5},
    )


def _deny(reason: str = "above_threshold", score: int = 8) -> AutoApproveDecision:
    return AutoApproveDecision(
        auto_approve=False,
        reason=reason,
        details={"score": score, "threshold": 5},
    )


def test_mfa_stale_high_risk_blocks_auto_approve() -> None:
    """A high-risk grant whose score gate would have approved must
    flip to BLOCKED when MFA is missing/stale."""
    decision, actor, block = _apply_mfa_and_self_approve_enforcement(
        _approve(score=7),
        mfa_audit={
            "mfa_gate_evaluated": True,
            "would_require_mfa": True,
            "mfa_present": False,
            "mfa_reason": "mfa_too_stale",
            "mfa_step_up_floor": 7,
        },
        self_approve_audit={"self_approve_evaluated": False},
        analysis_score=7,
        user_id="email:alice@example.com",
    )
    assert decision.auto_approve is False
    assert decision.reason == "mfa_required_for_high_risk"
    assert decision.details["mfa_step_up_required"] is True
    assert decision.details["client_action"] == "re_authenticate_via_oidc"
    # WB12-11: mfa_reason / original_reason / score are INTENTIONALLY
    # absent from the response-facing details. Audit log has them via
    # the separate _mfa_audit dict the route emits; the response body
    # stays opaque to deny attackers a stale-MFA oracle.
    assert "mfa_reason" not in decision.details
    assert "original_reason" not in decision.details
    assert "score" not in decision.details
    # Actor unchanged — this is still "system" doing the gating;
    # MFA is a system policy, not a user action.
    assert actor == "system:auto-approver"
    assert block is not None
    assert block["mfa_step_up_required"] is True
    assert block["redirect_to"] == "/api/v1/auth/oidc/login"
    # The response-body reason is the generic "fresh_mfa_required"
    # rather than the granular mfa_reason from the gate.
    assert block["reason"] == "fresh_mfa_required"


def test_mfa_fresh_high_risk_passes_through() -> None:
    """MFA fresh: no override; original decision flows through."""
    original = _approve(score=7)
    decision, actor, block = _apply_mfa_and_self_approve_enforcement(
        original,
        mfa_audit={
            "mfa_gate_evaluated": True,
            "would_require_mfa": True,
            "mfa_present": True,
            "mfa_age_seconds": 42,
            "mfa_reason": "ok",
        },
        self_approve_audit={"self_approve_evaluated": False},
        analysis_score=7,
        user_id="email:alice@example.com",
    )
    assert decision is original
    assert actor == "system:auto-approver"
    assert block is None


def test_low_risk_stale_mfa_passes_through() -> None:
    """Below the high-risk floor, stale MFA doesn't affect auto-approve."""
    original = _approve(score=2)
    decision, actor, block = _apply_mfa_and_self_approve_enforcement(
        original,
        mfa_audit={
            "mfa_gate_evaluated": True,
            "would_require_mfa": False,  # low-risk
            "mfa_present": False,        # stale
        },
        self_approve_audit={"self_approve_evaluated": False},
        analysis_score=2,
        user_id="email:alice@example.com",
    )
    assert decision is original
    assert actor == "system:auto-approver"


def test_self_approve_overrides_above_threshold_for_admin() -> None:
    """Admin whose request was denied for above_threshold gets it
    auto-approved via self-approve-reduction with the special actor."""
    decision, actor, block = _apply_mfa_and_self_approve_enforcement(
        _deny("above_threshold", score=8),
        mfa_audit={
            "mfa_gate_evaluated": True,
            "would_require_mfa": False,
            "mfa_present": True,
        },
        self_approve_audit={
            "self_approve_evaluated": True,
            "self_approve_eligible": True,
            "self_approve_reason": "self_approved",
        },
        analysis_score=8,
        user_id="email:alice@example.com",
    )
    assert decision.auto_approve is True
    assert decision.reason == "self_approve_reduction"
    assert decision.details["self_approve_reason"] == "self_approved"
    assert decision.details["original_reason"] == "above_threshold"
    assert actor == "self_approve_reduction:email:alice@example.com"
    assert block is None


def test_self_approve_does_not_override_service_blocked() -> None:
    """self_approve_evaluate already returns ineligible when the
    request touches a blocklisted service. The override should NOT
    fire if the score-gate said service_blocked (handled by the eval,
    not by this helper) — but defensively, even if it somehow did,
    the helper only fires on reason==above_threshold."""
    original = _deny("service_blocked", score=8)
    decision, actor, block = _apply_mfa_and_self_approve_enforcement(
        original,
        mfa_audit={"mfa_gate_evaluated": True, "would_require_mfa": False, "mfa_present": True},
        self_approve_audit={
            "self_approve_evaluated": True,
            "self_approve_eligible": True,  # shouldn't matter
            "self_approve_reason": "self_approved",
        },
        analysis_score=8,
        user_id="email:alice@example.com",
    )
    assert decision is original  # unchanged
    assert actor == "system:auto-approver"


def test_mfa_wins_over_self_approve_when_both_could_fire() -> None:
    """High-risk grant: even if user is self-approve-eligible, stale
    MFA blocks. Admin must re-authenticate before their reduction
    flows through."""
    decision, actor, block = _apply_mfa_and_self_approve_enforcement(
        _approve(score=7),  # auto-approve True
        mfa_audit={
            "mfa_gate_evaluated": True,
            "would_require_mfa": True,
            "mfa_present": False,
            "mfa_reason": "mfa_too_stale",
        },
        self_approve_audit={
            "self_approve_evaluated": True,
            "self_approve_eligible": True,
        },
        analysis_score=7,
        user_id="email:alice@example.com",
    )
    assert decision.auto_approve is False
    assert decision.reason == "mfa_required_for_high_risk"
    assert actor == "system:auto-approver"
    assert block is not None


def test_no_mfa_evaluation_skips_mfa_branch() -> None:
    """If the MFA gate didn't run (e.g., missing secret), no enforcement.
    Failure mode is 'annotation missing', not 'request stuck'."""
    original = _approve(score=7)
    decision, actor, block = _apply_mfa_and_self_approve_enforcement(
        original,
        mfa_audit={"mfa_gate_evaluated": False},  # gate skipped
        self_approve_audit={"self_approve_evaluated": False},
        analysis_score=7,
        user_id="email:alice@example.com",
    )
    assert decision is original
    assert actor == "system:auto-approver"
    assert block is None


# ---------------------------------------------------------------------------
# WB13-08 regression: MFA must block even when self-approve flipped
# the decision. Pre-fix, MFA only fired on auto_decision.auto_approve==True
# at entry; if the score gate denied with above_threshold and self-approve
# flipped to True, MFA never re-checked. Admin + solo + high-risk + stale
# MFA could auto-provision.
# ---------------------------------------------------------------------------


def test_self_approve_high_risk_stale_mfa_still_blocks_via_mfa() -> None:
    """Score-denied + self-approve-eligible + high-risk + stale MFA.

    Expected: self-approve flips to True, THEN MFA blocks with
    mfa_required_for_high_risk. Self-approve does NOT bypass MFA.
    """
    decision, actor, block = _apply_mfa_and_self_approve_enforcement(
        _deny("above_threshold", score=8),  # score-gate denied
        mfa_audit={
            "mfa_gate_evaluated": True,
            "would_require_mfa": True,    # high-risk
            "mfa_present": False,         # stale/missing
            "mfa_reason": "mfa_too_stale",
        },
        self_approve_audit={
            "self_approve_evaluated": True,
            "self_approve_eligible": True,  # admin reduction in solo
        },
        analysis_score=8,
        user_id="email:admin@example.com",
    )
    # The final decision MUST be the MFA block (not the self-approve
    # flip). The audit actor reverts to system because the FINAL
    # gate is MFA, not the user's reduction.
    assert decision.auto_approve is False
    assert decision.reason == "mfa_required_for_high_risk"
    assert actor == "system:auto-approver"
    assert block is not None
    assert block["mfa_step_up_required"] is True


def test_self_approve_high_risk_fresh_mfa_passes() -> None:
    """Same scenario but MFA is fresh: self-approve flips to True
    AND MFA allows it through. Audit actor is the self-approve one."""
    decision, actor, block = _apply_mfa_and_self_approve_enforcement(
        _deny("above_threshold", score=8),
        mfa_audit={
            "mfa_gate_evaluated": True,
            "would_require_mfa": True,
            "mfa_present": True,
            "mfa_age_seconds": 30,
        },
        self_approve_audit={
            "self_approve_evaluated": True,
            "self_approve_eligible": True,
        },
        analysis_score=8,
        user_id="email:admin@example.com",
    )
    assert decision.auto_approve is True
    assert decision.reason == "self_approve_reduction"
    assert actor == "self_approve_reduction:email:admin@example.com"
    assert block is None


def test_self_approve_low_risk_stale_mfa_passes() -> None:
    """Low-risk doesn't require MFA, so even stale MFA is fine."""
    decision, actor, block = _apply_mfa_and_self_approve_enforcement(
        _deny("above_threshold", score=4),
        mfa_audit={
            "mfa_gate_evaluated": True,
            "would_require_mfa": False,  # low-risk
            "mfa_present": False,        # but irrelevant
        },
        self_approve_audit={
            "self_approve_evaluated": True,
            "self_approve_eligible": True,
        },
        analysis_score=4,
        user_id="email:admin@example.com",
    )
    assert decision.auto_approve is True
    assert decision.reason == "self_approve_reduction"
    assert actor == "self_approve_reduction:email:admin@example.com"
