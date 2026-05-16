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
      'success'                       — all gates passed; auto-approve
      'feature_disabled'              — settings.auto_approve_risk_below is None
      'above_threshold'               — score >= threshold
      'service_blocked'               — statement touches a blocklisted service
      'account_blocked'               — request targets a blocklisted account
      'over_quota'                    — user hit per-hour cap
      'no_policy'                     — request has no policy (shouldn't reach here)
      'strict_mode_action_wildcard'   — strict mode disallows action wildcards
      'strict_mode_admin_fallback'    — strict mode disallows the *:* admin shape
    """
    details: dict[str, Any]
    """Structured detail for the audit log + admin UI.
       Examples:
         {"score": 2, "threshold": 4}
         {"service": "iam", "action": "iam:PassRole"}
         {"account_id": "123456789012"}
         {"used": 5, "limit": 5, "window_seconds": 3600}
    """


def _statement_has_action_wildcard(statements: list[dict[str, Any]]) -> str | None:
    """Return the first wildcard-bearing Action seen in any Allow
    statement, or None. Used by the strict-mode wildcard gate.

    Matches `*` and `?` per AWS IAM's wildcard primitives, plus the
    degenerate `Action: "*"`. Also scans `NotAction` (WB11-02
    closure) — `Effect: Allow, NotAction: "iam:*", Resource: "*"`
    is the canonical NotAction-bypass shape and must trip the gate
    in strict mode. Any presence of NotAction in an Allow is
    inherently a wildcard expansion ("everything except X") and
    treated as wildcard regardless of value.
    """
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        # NotAction in an Allow statement is itself an
        # "all-actions-except" wildcard. The strict gate treats
        # ANY NotAction as forbidden because the effective
        # action set is unbounded by definition.
        not_actions = stmt.get("NotAction")
        if not_actions:
            if isinstance(not_actions, str):
                return f"NotAction:{not_actions}"
            if isinstance(not_actions, list) and not_actions:
                return f"NotAction:{not_actions[0]}"

        actions = stmt.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if not isinstance(action, str):
                continue
            if "*" in action or "?" in action:
                return action
    return None


def _statement_is_admin_fallback(statements: list[dict[str, Any]]) -> bool:
    """The admin-fallback shape: a single Allow with Action=`*` and
    Resource=`*` (the "iam admin" preset). Strict mode forbids it
    because admin-fallback defeats the purpose of JIT scoping.
    """
    if len(statements) != 1:
        return False
    stmt = statements[0]
    if stmt.get("Effect") != "Allow":
        return False
    actions = stmt.get("Action") or []
    if isinstance(actions, str):
        actions = [actions]
    resources = stmt.get("Resource") or []
    if isinstance(resources, str):
        resources = [resources]
    return "*" in actions and "*" in resources


def evaluate(
    *,
    request: dict[str, Any],
    analysis_score: int,
    user_id: str,
    settings: "Settings",  # type: ignore[name-defined]
    quota_limiter: RateLimiter,
    effective_threshold: int | None = None,
    floor_max_auto_approve_risk_below: int | None = None,
    safety_thresholds: "SafetyModeThresholds | None" = None,  # type: ignore[name-defined]
) -> AutoApproveDecision:
    """Decide whether to auto-approve `request`. Pure function except
    for the quota_limiter side-effect (which is intentional — the
    counter only advances on a successful auto-approve, so the
    function must call check() rather than peek()).

    `effective_threshold` (per [[safety-mode-two-modes]] memo) lets
    the caller override `settings.auto_approve_risk_below` based on
    safety-mode + access_type. When None (default), the
    deployment-wide setting is used. When provided, it takes
    precedence — None vs 0 distinction matters since 0 is a valid
    threshold (deny everything).
    """
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
    # WB-safety-mode wiring: prefer the caller-supplied
    # `effective_threshold` (which incorporates safety mode +
    # access_type) over the deployment-wide setting.
    threshold = (
        effective_threshold
        if effective_threshold is not None
        else settings.auto_approve_risk_below
    )  # type: ignore[assignment]
    # WB10-02 clamp: the safety-mode resolver can hand back a
    # threshold (e.g., read_write_swap + read-only → 9) that exceeds
    # the platform-team-owned floor. The floor is the iam-jit
    # equivalent of an AWS SCP — admins cannot loosen above it. The
    # PATCH validator enforces this for settings-derived thresholds;
    # we also enforce it here for resolver-derived thresholds.
    threshold_was_clamped = False
    pre_clamp_threshold = threshold
    if (
        threshold is not None
        and floor_max_auto_approve_risk_below is not None
        and threshold > floor_max_auto_approve_risk_below
    ):
        threshold = floor_max_auto_approve_risk_below
        threshold_was_clamped = True
    if auto_approve_via_toggle is None:
        if analysis_score >= threshold:
            details: dict[str, Any] = {
                "score": analysis_score,
                "threshold": threshold,
            }
            if threshold_was_clamped:
                details["threshold_pre_clamp"] = pre_clamp_threshold
                details["floor_max_auto_approve_risk_below"] = (
                    floor_max_auto_approve_risk_below
                )
            return AutoApproveDecision(
                auto_approve=False,
                reason="above_threshold",
                details=details,
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

    # WB10-04 strict-mode gates: wire `allow_action_wildcards` and
    # `allow_admin_fallback` from SafetyModeThresholds. Without these
    # the strict-mode docstring made promises the code didn't enforce.
    if safety_thresholds is not None:
        if not safety_thresholds.allow_action_wildcards:
            offending = _statement_has_action_wildcard(statements)
            if offending is not None:
                return AutoApproveDecision(
                    auto_approve=False,
                    reason="strict_mode_action_wildcard",
                    details={
                        "mode": safety_thresholds.mode,
                        "offending_action": offending,
                    },
                )
        if not safety_thresholds.allow_admin_fallback:
            if _statement_is_admin_fallback(statements):
                return AutoApproveDecision(
                    auto_approve=False,
                    reason="strict_mode_admin_fallback",
                    details={
                        "mode": safety_thresholds.mode,
                    },
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
