"""Auto-approve evaluation dispatch for newly-created requests.

Single entry point — `evaluate_and_apply_for_new_request` — that both
the API submit handler in `routes/requests.py` AND the web paste-form
handler in `routes/web.py` call after a request is persisted in
`pending` state. Centralising this keeps the two paths from drifting
per [[cross-product-agent-parity]]; the silent gap closed by #598 was
exactly that drift in the first place (the web form created the
request but never invoked the auto-approve gate, so every web-submit
landed in pending even when the deterministic scorer would have
auto-approved).

This module is the deliberate sibling of `approval_notifier`:
  - `approval_notifier.notify_approvers_for_new_request` fires when
    the request lands in pending (i.e., did NOT auto-approve).
  - `evaluate_and_apply_for_new_request` runs BEFORE that, deciding
    whether the request lands in pending in the first place.

Discipline:
  - Honest degradation (per [[ibounce-honest-positioning]]): if the
    auto-approve evaluation raises for any reason, the request stays
    in pending — the operator's human-approval path is the fallback,
    and a bug in the gate code must never block submission. The
    helper logs a WARNING so the operator can chase the gate failure
    out-of-band.

  - Idempotent: safe to call any number of times on the same request.
    The state-change only fires when the current state is `pending`;
    a second call is a no-op (the request has already moved past
    pending).

  - Scorer is ground truth (per [[scorer-is-ground-truth]]): this
    module does NOT compute the score, the threshold, or the safety
    mode — it consumes them via the canonical helpers in
    `settings_store`, `safety_mode`, and `auto_approve`. The only
    decision this module makes is "given those inputs, mutate the
    request state into the next state."
"""

from __future__ import annotations

import logging
import os
from typing import Any

from ._auto_approve_helpers import (
    apply_mfa_and_self_approve_enforcement as _apply_mfa_and_self_approve,
    attempt_provisioning as _attempt_provisioning_helper,
    safe_mark_failed as _safe_mark_failed_helper,
)

logger = logging.getLogger("iam_jit.auto_approve_evaluator")


def _now_iso_z() -> str:
    """Same format the routes' own _now_iso_z helper uses. Inlined
    here so this module has no cross-package coupling on routes."""
    import datetime as _dt
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def evaluate_and_apply_for_new_request(
    *,
    request: dict[str, Any],
    user: Any,
    accounts_store: Any,
    cookie_value: str | None = None,
    api_token_record: Any = None,
) -> dict[str, Any]:
    """Evaluate the auto-approve gate for a newly-persisted request and
    apply the state change if it qualifies.

    Args:
      request: the request dict, already initialised via
        `lifecycle.init_status(req, owner=user)` and validated. Must
        be in `pending` state with a review block populated under
        `status.review`.
      user: the authenticated requester (has `.id`, `.is_admin`).
      accounts_store: the deployment's accounts store (used for safety-
        mode resolution). May be None in deployments without an
        accounts store.
      cookie_value: the session-MFA cookie value, if any. None when
        the call is from a context that has no cookies (CLI, MCP,
        non-cookie API client). The MFA gate evaluates this against
        the deployment's MFA freshness window.

    Returns:
      A `status` dict carrying the auto-approve decision for the
      route to splat into its response body:
        {
          "auto_decision": AutoApproveDecision | None,
          "mfa_block_response": dict | None,
        }
      Both fields may be None if the gate didn't fire (no review
      block, no policy, or evaluator failure).

    Side effects:
      - Mutates `request["status"]` in place when auto-approve fires:
        sets state to "provisioning", appends a history entry with
        actor `system:auto-approver` (or `self_approve_reduction:<id>`
        when the self-approve override fired), and synchronously
        provisions the role.
      - Emits an audit event (`request.auto_approved` or
        `request.auto_approve_skipped`) capturing the gate that
        fired, the safety mode, and the decision details.

    Honest degradation: any exception during evaluation is logged
    and swallowed. The request stays in pending and the operator
    can chase the gate failure via the human-approval path per
    [[ibounce-honest-positioning]].
    """
    try:
        return _evaluate_and_apply_inner(
            request=request,
            user=user,
            accounts_store=accounts_store,
            cookie_value=cookie_value,
            api_token_record=api_token_record,
        )
    except Exception as e:
        # Honest degradation: an evaluator bug must NEVER block
        # request creation. The request is already persisted in
        # pending; the operator's human-approval path is the
        # fallback. Log loudly so the operator can chase the gate
        # failure out-of-band.
        logger.warning(
            "auto-approve evaluation failed (request stays pending): %s", e
        )
        return {"auto_decision": None, "mfa_block_response": None}


def _evaluate_and_apply_inner(
    *,
    request: dict[str, Any],
    user: Any,
    accounts_store: Any,
    cookie_value: str | None,
    api_token_record: Any,
) -> dict[str, Any]:
    """The actual evaluation. Mirrors the inline logic that used to
    live in `routes/requests.py submit_request` before #598 extracted
    it. Kept structurally identical so post-#598 behaviour on the API
    path is bit-for-bit the same as pre-#598; the new web path now
    rides the same code so the two paths cannot diverge.
    """
    # Lazy imports to avoid making `routes/web.py` pull in the full
    # auto-approve stack just because it imports this module.
    from . import (
        audit as audit_mod,
        auto_approve as auto_approve_mod,
        lifecycle,
        provision as provision_mod,
        safety_mode as _safety_mode,
        self_approve_reductions as _sar,
        settings_store as settings_mod,
        rate_limit as rate_limit_mod,
        mfa_gate as _mfa_gate,
        assume as assume_mod,
    )
    from .middleware import _get_secret as _auth_secret_getter

    review_block = (request.get("status") or {}).get("review")
    metadata = request.get("metadata") or {}
    request_id = metadata.get("id") or ""
    if not review_block:
        return {"auto_decision": None, "mfa_block_response": None}

    settings = settings_mod.get_default_store().get()
    quota = rate_limit_mod.get_default_limiter()

    # Safety-mode threshold resolution per [[safety-mode-two-modes]].
    # Multi-account requests use the MOST RESTRICTIVE mode across the
    # set (WB10-03); threshold is clamped to the platform-team floor
    # (WB10-02).
    spec = request.get("spec") or {}
    access_type = (spec.get("access_type") or "read-write").strip()
    accts = spec.get("accounts") or []
    account_ids = [
        a.get("account_id") for a in accts
        if isinstance(a, dict) and a.get("account_id")
    ]
    mode = _safety_mode.resolve_mode_for_accounts(
        account_ids=account_ids,
        accounts_store=accounts_store,
    )
    effective_threshold = _safety_mode.auto_approve_threshold_for(
        mode, access_type=access_type,
    )
    safety_thresholds = _safety_mode.thresholds_for(mode)
    floors = settings_mod.Floors.from_env()

    # MFA + self-approve evaluation runs BEFORE auto_decision so the
    # enforcement override can use both verdicts. Each block is wrapped
    # in try/except so a bug in the gate code never blocks a grant —
    # failure mode is "annotation missing", not "request stuck".
    #
    # FAIL-CLOSED on MFA per [[ibounce-honest-positioning]] + #599: the
    # initial mfa_audit MUST set `would_require_mfa: True` so that if
    # `_mfa_gate.evaluate_for_route` raises, the downstream enforcement
    # in `_apply_mfa_and_self_approve` treats the request as if it
    # required MFA — which routes high-risk requests to the human-
    # approval path rather than silently auto-approving them. The pre-
    # #599 default of `{"mfa_gate_evaluated": False}` left
    # `would_require_mfa` absent, which `bool(...get(...))` coerced to
    # False, which silently bypassed MFA enforcement on gate crash. The
    # success path below OVERWRITES mfa_audit with the real gate result,
    # so the fail-CLOSED default only applies when evaluation crashes.
    mfa_audit: dict[str, Any] = {
        "mfa_gate_evaluated": False,
        "would_require_mfa": True,
        "mfa_present": False,
        "mfa_reason": "evaluator_init_default_fail_closed",
    }
    try:
        mfa_audit = _mfa_gate.evaluate_for_route(
            cookie_value=cookie_value,
            secret=_auth_secret_getter(),
            user_id=user.id,
            risk_score=review_block.get("risk_score", 0),
            api_token_record=api_token_record,
        )
    except Exception:
        # #599 fail-CLOSED: log the exception so SecOps can chase the
        # gate failure out-of-band. mfa_audit retains the fail-CLOSED
        # default initialised above, which forces high-risk requests
        # through human approval. Silent pass would mean a gate crash
        # auto-approves without MFA verification.
        logger.exception(
            "auto_approve_evaluator: mfa_gate.evaluate_for_route raised; "
            "retaining fail-CLOSED defaults (would_require_mfa=True, "
            "mfa_present=False) so high-risk requests route to human "
            "approval (request_id=%s, user_id=%s)",
            request_id, user.id,
        )

    self_approve_audit: dict[str, Any] = {"self_approve_evaluated": False}
    try:
        sar_decision = _sar.evaluate(
            request=request,
            user_id=user.id,
            user_is_admin=getattr(user, "is_admin", False),
            blocked_services=tuple(settings.never_auto_approve_services),
        )
        self_approve_audit = {
            "self_approve_evaluated": True,
            "self_approve_eligible": sar_decision.self_approved,
            "self_approve_reason": sar_decision.reason,
        }
    except Exception:
        # #599: log so SecOps can see self-approve gate failures.
        # self_approve_audit retains `{"self_approve_evaluated": False}`
        # which makes the override fall through (i.e., the request goes
        # through normal score-gate evaluation, not via self-approve).
        logger.exception(
            "auto_approve_evaluator: self_approve_reductions.evaluate "
            "raised; self-approve override will not fire for this "
            "request (request_id=%s, user_id=%s)",
            request_id, user.id,
        )

    auto_decision = auto_approve_mod.evaluate(
        request=request,
        analysis_score=review_block.get("risk_score", 10),
        user_id=user.id,
        effective_threshold=effective_threshold,
        settings=settings,
        quota_limiter=quota,
        floor_max_auto_approve_risk_below=floors.max_auto_approve_risk_below,
        safety_thresholds=safety_thresholds,
    )

    # Apply MFA + self-approve enforcement on top of the score-gate
    # decision. Implementation lives in `_auto_approve_helpers` (leaf
    # module) so this module + `routes/requests.py` share one source
    # of truth — closes the #601 HIGH-4 "structurally identical twin"
    # finding from the 2026-05-25 independent code review.
    #
    # The module-level alias `_apply_mfa_and_self_approve` lets the
    # sabotage test in `tests/test_auto_approve_evaluator_mfa_fail_closed.py`
    # monkeypatch the call site (proves the fail-CLOSED default is
    # load-bearing).
    auto_decision, audit_actor, mfa_block_response = (
        _apply_mfa_and_self_approve(
            auto_decision,
            mfa_audit=mfa_audit,
            self_approve_audit=self_approve_audit,
            analysis_score=review_block.get("risk_score", 10),
            user_id=user.id,
        )
    )

    # Audit emission — wrap to keep evaluator failure-tolerant.
    try:
        mode_source = (
            "safety_mode_resolver"
            if effective_threshold is not None
            else "deployment_setting"
        )
        audit_mod.emit(
            actor=audit_actor,
            kind=(
                "request.auto_approved"
                if auto_decision.auto_approve
                else "request.auto_approve_skipped"
            ),
            summary=(
                f"auto-approve evaluated for {request_id}: "
                f"{auto_decision.reason} "
                f"(mode={mode}, actor={audit_actor})"
            ),
            details={
                "request_id": request_id,
                "owner_id": user.id,
                "safety_mode": mode,
                "mode_source": mode_source,
                "allow_action_wildcards": safety_thresholds.allow_action_wildcards,
                "allow_admin_fallback": safety_thresholds.allow_admin_fallback,
                "floor_max_auto_approve_risk_below": floors.max_auto_approve_risk_below,
                **mfa_audit,
                **self_approve_audit,
                **auto_decision.details,
            },
        )
    except Exception:
        # #599: audit-emit failure must NOT block the decision flow
        # (the request's auto-approve verdict is already computed), but
        # it MUST be visible — a silent audit-emit failure means the
        # operator's audit trail is missing entries.
        logger.exception(
            "auto_approve_evaluator: audit.emit for the auto-approve "
            "verdict raised; audit trail may be missing this entry "
            "(request_id=%s, user_id=%s, auto_approve=%s)",
            request_id, user.id, auto_decision.auto_approve,
        )

    # Shadow mode: when IAM_JIT_SHADOW_MODE=1 the scorer runs and the
    # decision is recorded in the audit trail, but the request state
    # stays at `pending` regardless of the auto-approve verdict. Use
    # this to deploy iam-jit alongside a customer's existing approval
    # workflow — they observe the scorer's verdicts for N weeks before
    # turning it on for real.
    if os.environ.get("IAM_JIT_SHADOW_MODE") == "1":
        try:
            audit_mod.emit(
                actor="system:shadow-mode",
                kind=(
                    "shadow.would_auto_approve"
                    if auto_decision.auto_approve
                    else "shadow.would_route_to_review"
                ),
                summary=(
                    f"shadow-mode decision for {request_id}: "
                    f"would_auto_approve={auto_decision.auto_approve}; "
                    f"score={review_block.get('risk_score') if review_block else None}; "
                    f"reason={auto_decision.reason}"
                ),
                details={
                    "request_id": request_id,
                    "owner_id": user.id,
                    "would_auto_approve": auto_decision.auto_approve,
                    "would_reason": auto_decision.reason,
                    "would_details": auto_decision.details,
                    "shadow_mode": True,
                },
            )
        except Exception:
            # #599: shadow-mode audit-emit failure is the same shape as
            # the production audit-emit failure above — the request
            # stays in pending regardless (shadow mode never mutates),
            # but the operator needs visibility into the failure so the
            # shadow-mode evaluation can be re-run.
            logger.exception(
                "auto_approve_evaluator: shadow-mode audit.emit raised; "
                "shadow trail may be missing this entry (request_id=%s, "
                "user_id=%s, would_auto_approve=%s)",
                request_id, user.id, auto_decision.auto_approve,
            )
        # IMPORTANT: do NOT mutate state. The request stays at `pending`.
        return {
            "auto_decision": auto_decision,
            "mfa_block_response": mfa_block_response,
        }

    if auto_decision.auto_approve:
        # Bypass the lifecycle.transition() check (which would require
        # an "approver" actor distinct from the owner). System-driven
        # approval has its own audit actor and doesn't carry the
        # separation-of-duties invariant — there's no human approver
        # to puppet here.
        status = request.setdefault("status", {})
        status["state"] = "provisioning"
        history = status.setdefault("history", [])
        history.append({
            "actor": audit_actor,
            "action": "auto_approve",
            "to_state": "provisioning",
            "at": _now_iso_z(),
            "reason": auto_decision.reason,
            "details": auto_decision.details,
        })
        try:
            _attempt_provisioning_helper(
                request,
                accounts_store=accounts_store,
                provision_mod=provision_mod,
                assume_mod=assume_mod,
                lifecycle=lifecycle,
            )
        except Exception as e:  # pragma: no cover — defense in depth
            _safe_mark_failed_helper(
                request,
                f"auto-approve provisioning crashed: {e}",
                lifecycle=lifecycle,
            )

    return {
        "auto_decision": auto_decision,
        "mfa_block_response": mfa_block_response,
    }


# #601 (2026-05-25): the local twins `_apply_mfa_and_self_approve`,
# `_attempt_provisioning`, and `_safe_mark_failed` were extracted to
# `_auto_approve_helpers` (leaf module) so that this module and
# `routes/requests.py` share one source of truth. The module-level
# alias `_apply_mfa_and_self_approve` at the top of this file is the
# monkeypatch surface for
# `tests/test_auto_approve_evaluator_mfa_fail_closed.py`.
