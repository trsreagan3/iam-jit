"""Unit tests covering the F15 solo-mode auto-approve probe path (#705).

Regression guard for the HIGH-3 finding: in solo deployment mode a
low-risk request whose policy contains ONLY non-blocked services must
auto-approve via the self-approve-reductions gate.

Root cause of the original CI failure (#705):
  - The F9 stack-2 submission includes iam:CreateRole / iam:PutRolePolicy
    / iam:PassRole. `iam` is in the required_service_blocklist so the
    self-approve gate returns service_blocked regardless of deployment
    mode. The F9 body CANNOT auto-approve — that is the correct, secure
    behaviour, not a regression.
  - F15 was erroneously checking the F9 body state (which is always
    pending for an iam:-containing policy) instead of submitting a
    separate probe with only non-blocked services.

These unit tests verify the underlying gate logic:
  1. self_approve_reductions blocks when ANY action touches a blocked service.
  2. self_approve_reductions approves in solo mode for non-blocked services.
  3. The _auto_approve_helpers chain self-approves a feature_disabled
     base decision when self-approve is eligible.
  4. The chain does NOT self-approve when service is blocked.
"""

from __future__ import annotations

import pytest

from iam_jit.auto_approve import AutoApproveDecision
from iam_jit._auto_approve_helpers import apply_mfa_and_self_approve_enforcement
from iam_jit.self_approve_reductions import evaluate as sar_evaluate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IAM_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateRole",
                "iam:PutRolePolicy",
                "iam:PassRole",
                "lambda:CreateFunction",
                "apigateway:CreateRestApi",
            ],
            "Resource": "*",
        }
    ],
}

_LAMBDA_APIGW_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:GetFunction",
                "lambda:ListFunctions",
                "apigateway:GET",
            ],
            "Resource": "*",
        }
    ],
}

_DEFAULT_BLOCKED_SERVICES = (
    "iam", "organizations", "sts", "kms", "secretsmanager",
)


def _req(policy: dict) -> dict:
    return {
        "spec": {
            "access_type": "read-only",
            "accounts": [{"account_id": "111111111111"}],
            "policy": policy,
        },
        "metadata": {"id": "test-req-705"},
        "status": {"owner": "email:admin@local", "state": "pending"},
    }


def _feature_disabled() -> AutoApproveDecision:
    return AutoApproveDecision(
        auto_approve=False,
        reason="feature_disabled",
        details={"threshold": None, "reason_detail": "no_threshold_configured"},
    )


def _mfa_low_risk() -> dict:
    """MFA audit dict for a low-risk score that doesn't trigger the gate."""
    return {
        "mfa_gate_evaluated": True,
        "mfa_source": "absent",
        "mfa_step_up_floor": 9,
        "would_require_mfa": False,   # score is low — gate doesn't fire
        "mfa_present": False,
        "mfa_age_seconds": None,
        "mfa_reason": "no_mfa_cookie",
    }


# ---------------------------------------------------------------------------
# 1. sar_evaluate blocks when iam:* is in the policy
# ---------------------------------------------------------------------------

def test_sar_blocks_iam_service_in_stack2_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stack 2's policy (includes iam:*) is blocked even in solo mode."""
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    req = _req(_IAM_POLICY)
    result = sar_evaluate(
        request=req,
        user_id="email:admin@local",
        user_is_admin=True,
        blocked_services=_DEFAULT_BLOCKED_SERVICES,
    )
    # self_approve_reductions must block on the iam service
    assert not result.self_approved, (
        f"expected self_approved=False for iam-containing policy; "
        f"got reason={result.reason!r}"
    )
    assert result.reason == "service_blocked"
    assert (result.details or {}).get("service") == "iam"


# ---------------------------------------------------------------------------
# 2. sar_evaluate approves for non-blocked services in solo mode
# ---------------------------------------------------------------------------

def test_sar_approves_lambda_apigw_probe_in_solo_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F15 probe policy (lambda + apigateway only) self-approves in solo mode."""
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")
    req = _req(_LAMBDA_APIGW_POLICY)
    result = sar_evaluate(
        request=req,
        user_id="email:admin@local",
        user_is_admin=True,
        blocked_services=_DEFAULT_BLOCKED_SERVICES,
    )
    assert result.self_approved, (
        f"expected self_approved=True for lambda/apigateway probe in solo mode; "
        f"got reason={result.reason!r} details={result.details}"
    )
    assert result.reason == "self_approved"


# ---------------------------------------------------------------------------
# 3. Full enforcement chain self-approves non-blocked probe
# ---------------------------------------------------------------------------

def test_enforcement_chain_self_approves_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """apply_mfa_and_self_approve_enforcement flips feature_disabled → approve
    when self-approve is eligible (non-blocked policy, solo, admin)."""
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")

    req = _req(_LAMBDA_APIGW_POLICY)
    sar_result = sar_evaluate(
        request=req,
        user_id="email:admin@local",
        user_is_admin=True,
        blocked_services=_DEFAULT_BLOCKED_SERVICES,
    )
    self_approve_audit = {
        "self_approve_evaluated": True,
        "self_approve_eligible": sar_result.self_approved,
        "self_approve_reason": sar_result.reason,
    }
    effective, actor, mfa_block = apply_mfa_and_self_approve_enforcement(
        _feature_disabled(),
        mfa_audit=_mfa_low_risk(),
        self_approve_audit=self_approve_audit,
        analysis_score=2,
        user_id="email:admin@local",
    )
    assert effective.auto_approve, (
        f"expected auto_approve=True after self-approve flip; "
        f"reason={effective.reason!r}"
    )
    assert effective.reason == "self_approve_reduction"
    assert mfa_block is None  # low-risk score, no MFA block


# ---------------------------------------------------------------------------
# 4. Full enforcement chain does NOT self-approve iam-containing policy
# ---------------------------------------------------------------------------

def test_enforcement_chain_does_not_approve_blocked_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """apply_mfa_and_self_approve_enforcement does NOT flip feature_disabled
    when self-approve is ineligible (service_blocked on iam:* actions)."""
    monkeypatch.setenv("IAM_JIT_DEPLOYMENT_MODE", "solo")

    req = _req(_IAM_POLICY)
    sar_result = sar_evaluate(
        request=req,
        user_id="email:admin@local",
        user_is_admin=True,
        blocked_services=_DEFAULT_BLOCKED_SERVICES,
    )
    self_approve_audit = {
        "self_approve_evaluated": True,
        "self_approve_eligible": sar_result.self_approved,   # False
        "self_approve_reason": sar_result.reason,            # service_blocked
    }
    effective, actor, mfa_block = apply_mfa_and_self_approve_enforcement(
        _feature_disabled(),
        mfa_audit=_mfa_low_risk(),
        self_approve_audit=self_approve_audit,
        analysis_score=5,
        user_id="email:admin@local",
    )
    assert not effective.auto_approve, (
        "iam-containing policy must NOT auto-approve via self-approve path"
    )
    # reason must be the original feature_disabled, not self_approve_reduction
    assert effective.reason == "feature_disabled"
    assert mfa_block is None


# ---------------------------------------------------------------------------
# 5. sar_evaluate is ineligible outside solo mode without the per-user flag
# ---------------------------------------------------------------------------

def test_sar_not_eligible_outside_solo_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """self_approve_reductions gate does not fire in non-solo mode without flag."""
    monkeypatch.delenv("IAM_JIT_DEPLOYMENT_MODE", raising=False)
    req = _req(_LAMBDA_APIGW_POLICY)
    result = sar_evaluate(
        request=req,
        user_id="email:admin@local",
        user_is_admin=True,
        blocked_services=_DEFAULT_BLOCKED_SERVICES,
        user_self_approve_flag=False,  # explicit: no per-user flag
    )
    assert not result.self_approved
    assert result.reason == "mode_not_enabled"
