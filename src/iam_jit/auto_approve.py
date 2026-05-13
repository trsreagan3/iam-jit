"""Auto-approve decision logic.

Called from the request-submission path after the deterministic
risk score is computed. Returns an `AutoApproveDecision` that the
route handler uses to either:

  - auto-transition pending → approved with actor `system:auto-approver`
  - leave the request in pending for human review (default)

Composes four gates, in evaluation order. Any single FAIL routes
to human review even if other gates pass:

  1. Feature gate: settings.auto_approve_risk_below must be set.
  2. Threshold gate: analysis_score < auto_approve_risk_below.
  3. Context gate: no statement targets a blocklisted service or
     account.
  4. Quota gate: user hasn't exceeded their per-hour cap.

The audit chain captures the gate that fired so a reviewer
debugging "why didn't this auto-approve?" can immediately see
the answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .rate_limit import RateLimiter, RateDecision


@dataclass(frozen=True)
class AutoApproveDecision:
    """Outcome of the auto-approve evaluation."""

    auto_approve: bool
    reason: str
    """One of:
      'success'              — all gates passed; auto-approve
      'feature_disabled'     — settings.auto_approve_risk_below is None
      'above_threshold'      — score >= threshold
      'service_blocked'      — statement touches a blocklisted service
      'account_blocked'      — request targets a blocklisted account
      'over_quota'           — user hit per-hour cap
      'no_policy'            — request has no policy (shouldn't reach here)
    """
    details: dict[str, Any]
    """Structured detail for the audit log + admin UI.
       Examples:
         {"score": 2, "threshold": 4}
         {"service": "iam", "action": "iam:PassRole"}
         {"account_id": "123456789012"}
         {"used": 5, "limit": 5, "window_seconds": 3600}
    """


def evaluate(
    *,
    request: dict[str, Any],
    analysis_score: int,
    user_id: str,
    settings: "Settings",  # type: ignore[name-defined]
    quota_limiter: RateLimiter,
) -> AutoApproveDecision:
    """Decide whether to auto-approve `request`. Pure function except
    for the quota_limiter side-effect (which is intentional — the
    counter only advances on a successful auto-approve, so the
    function must call check() rather than peek())."""
    # Toggle gate fires FIRST — admin-curated toggles short-circuit
    # both directions. Two toggle actions evaluated in this order:
    #   1. force_review_if: any matching enabled toggle → review
    #      (always wins; deny side is conservative)
    #   2. auto_approve_if: any matching enabled toggle → approve
    #      (subject to floors — service/account blocklists still
    #      apply since those are deploy-time floors)
    for toggle in settings.preset_toggles:
        if not toggle.enabled:
            continue
        if toggle.action == "force_review_if" and toggle.matches(request):
            return AutoApproveDecision(
                auto_approve=False,
                reason="toggle_force_review",
                details={
                    "toggle_id": toggle.id,
                    "toggle_name": toggle.name,
                    "matched_condition": toggle.condition,
                },
            )

    # auto_approve_if toggles run separately AFTER force_review_if so
    # a single enabled "no prod" toggle wins over an enabled "approve
    # all" toggle when both could apply.
    auto_approve_via_toggle: "PresetToggle | None" = None  # type: ignore[name-defined]
    for toggle in settings.preset_toggles:
        if not toggle.enabled or toggle.action != "auto_approve_if":
            continue
        if toggle.matches(request):
            auto_approve_via_toggle = toggle
            break

    if not settings.auto_approve_enabled and auto_approve_via_toggle is None:
        return AutoApproveDecision(
            auto_approve=False,
            reason="feature_disabled",
            details={"threshold": settings.auto_approve_risk_below},
        )

    # If an auto_approve_if toggle matched, skip the score gate —
    # but still run the floor checks below (service/account
    # blocklists). The toggle is a "this shape is pre-vetted"
    # statement, not a "ignore safety checks" override.
    threshold = settings.auto_approve_risk_below  # type: ignore[assignment]
    if auto_approve_via_toggle is None:
        if analysis_score >= threshold:
            return AutoApproveDecision(
                auto_approve=False,
                reason="above_threshold",
                details={"score": analysis_score, "threshold": threshold},
            )

    spec = request.get("spec") or {}
    policy = spec.get("policy") or {}
    statements = policy.get("Statement") or []
    if not statements:
        return AutoApproveDecision(
            auto_approve=False,
            reason="no_policy",
            details={},
        )

    # Service blocklist: any action in any Allow statement that
    # touches a blocked service forces review.
    blocked_services = set(settings.never_auto_approve_services)
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if not isinstance(action, str) or ":" not in action:
                continue
            service = action.split(":", 1)[0]
            if service in blocked_services:
                return AutoApproveDecision(
                    auto_approve=False,
                    reason="service_blocked",
                    details={
                        "service": service,
                        "action": action,
                    },
                )

    # Account blocklist: any target account in the request that's on
    # the never-auto-approve list forces review.
    blocked_accounts = set(settings.never_auto_approve_accounts)
    for acct in spec.get("accounts") or []:
        if isinstance(acct, dict) and acct.get("account_id") in blocked_accounts:
            return AutoApproveDecision(
                auto_approve=False,
                reason="account_blocked",
                details={"account_id": acct.get("account_id")},
            )

    # Quota: per-user cap on auto-approvals in a sliding window.
    # This is THE defense against the composability attack — chained
    # low-risk requests that individually pass but combine to do
    # damage. The (N+1)th auto-approval from the same user is
    # forced to human review even if score qualifies.
    quota_decision = quota_limiter.check(user_id, kind="auto_approve")
    if not quota_decision.allowed:
        return AutoApproveDecision(
            auto_approve=False,
            reason="over_quota",
            details={
                "count_in_window": quota_decision.count,
                "window_seconds": quota_decision.window_seconds,
                "hard_cap": quota_decision.hard_cap,
                "retry_after_seconds": quota_decision.retry_after_seconds,
            },
        )

    # All gates passed.
    if auto_approve_via_toggle is not None:
        return AutoApproveDecision(
            auto_approve=True,
            reason="success_via_toggle",
            details={
                "score": analysis_score,
                "threshold": threshold,
                "toggle_id": auto_approve_via_toggle.id,
                "toggle_name": auto_approve_via_toggle.name,
            },
        )
    return AutoApproveDecision(
        auto_approve=True,
        reason="success",
        details={"score": analysis_score, "threshold": threshold},
    )
