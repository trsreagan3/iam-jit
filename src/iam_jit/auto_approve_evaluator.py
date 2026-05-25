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
    mfa_audit: dict[str, Any] = {"mfa_gate_evaluated": False}
    try:
        mfa_audit = _mfa_gate.evaluate_for_route(
            cookie_value=cookie_value,
            secret=_auth_secret_getter(),
            user_id=user.id,
            risk_score=review_block.get("risk_score", 0),
            api_token_record=api_token_record,
        )
    except Exception:
        pass

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
        pass

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
    # decision. Implemented inline so this module has no inbound
    # dependency on routes/* (would create a circular import); kept
    # structurally identical to routes/requests.py
    # `_apply_mfa_and_self_approve_enforcement`.
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
        pass

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
            pass
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
            _attempt_provisioning(
                request,
                accounts_store=accounts_store,
                provision_mod=provision_mod,
                assume_mod=assume_mod,
                lifecycle=lifecycle,
            )
        except Exception as e:  # pragma: no cover — defense in depth
            _safe_mark_failed(
                request,
                f"auto-approve provisioning crashed: {e}",
                lifecycle=lifecycle,
            )

    return {
        "auto_decision": auto_decision,
        "mfa_block_response": mfa_block_response,
    }


def _apply_mfa_and_self_approve(
    auto_decision: Any,
    *,
    mfa_audit: dict[str, Any],
    self_approve_audit: dict[str, Any],
    analysis_score: int,
    user_id: str,
) -> tuple[Any, str, dict[str, Any] | None]:
    """Apply MFA + self-approve enforcement on top of the score-gate
    decision. Structurally identical to the routes/requests.py helper
    of the same name — kept in sync deliberately. See that function's
    docstring for the enforcement-ordering rationale (WB12-04 +
    WB12-08 + WB12-11 + WB13-08 + WB13-09 closures).
    """
    would_require_mfa = bool(mfa_audit.get("would_require_mfa"))
    mfa_present = bool(mfa_audit.get("mfa_present"))
    self_approve_eligible = bool(self_approve_audit.get("self_approve_eligible"))

    effective_decision = auto_decision
    audit_actor = "system:auto-approver"

    override_eligible_reasons = ("above_threshold", "feature_disabled")
    if (
        not bool(getattr(effective_decision, "auto_approve", False))
        and getattr(effective_decision, "reason", "") in override_eligible_reasons
        and self_approve_eligible
    ):
        original_reason = getattr(effective_decision, "reason", "")
        from .auto_approve import AutoApproveDecision
        from . import self_approve_reductions as _sar_mod
        effective_decision = AutoApproveDecision(
            auto_approve=True,
            reason="self_approve_reduction",
            details={
                "score": analysis_score,
                "original_reason": original_reason,
                "self_approve_reason": self_approve_audit.get("self_approve_reason"),
                "details_pre_override": dict(getattr(auto_decision, "details", {}) or {}),
            },
        )
        audit_actor = _sar_mod.audit_actor_for(user_id)

    if (
        bool(getattr(effective_decision, "auto_approve", False))
        and would_require_mfa
        and not mfa_present
    ):
        from .auto_approve import AutoApproveDecision
        blocked = AutoApproveDecision(
            auto_approve=False,
            reason="mfa_required_for_high_risk",
            details={
                "mfa_step_up_required": True,
                "mfa_step_up_at_score": mfa_audit.get("mfa_step_up_floor"),
                "client_action": "re_authenticate_via_oidc",
            },
        )
        block_response = {
            "mfa_step_up_required": True,
            "reason": "fresh_mfa_required",
            "redirect_to": "/api/v1/auth/oidc/login",
        }
        return blocked, "system:auto-approver", block_response

    return effective_decision, audit_actor, None


def _attempt_provisioning(
    req: dict[str, Any],
    *,
    accounts_store: Any,
    provision_mod: Any,
    assume_mod: Any,
    lifecycle: Any,
) -> None:
    """Synchronously provision after auto-approve, persist result/error.

    Same guarantee as the routes/requests.py twin: NEVER raises. The
    request is left in one of: 'active' (success), 'provisioning_failed'
    (failure), or unchanged.

    The duplication here vs routes/requests.py is deliberate — pulling
    that helper out of routes/* would create a circular dependency
    (routes → evaluator → routes). The two implementations are
    structurally identical and any future divergence should be
    triaged as a parity bug (per [[cross-product-agent-parity]]).
    """
    logger_p = logging.getLogger("iam_jit.provisioning")
    try:
        result = provision_mod.provision(req, accounts_store=accounts_store)
    except provision_mod.ProvisioningError as e:
        logger_p.warning("provisioning failed: %s", e)
        _safe_mark_failed(req, str(e), lifecycle=lifecycle)
        return
    except Exception as e:
        logger_p.exception("unexpected error during provisioning")
        _safe_mark_failed(req, f"unexpected error: {e}", lifecycle=lifecycle)
        return

    try:
        instructions = assume_mod.render_instructions(
            req,
            role_arn=result.role_arn,
            external_id=result.external_id,
        )
        provisioned = {
            "role_arn": result.role_arn,
            "role_name": result.role_name,
            "account_id": result.account_id,
            "external_id": result.external_id,
            "assumer_principal_arn": result.assumer_principal_arn,
            "session_name": result.session_name,
            "expires_at": result.expires_at,
            "assume_instructions": instructions["assume_instructions"],
            "aws_cli_replay": list(result.aws_cli_replay),
            "creation_succeeded": True,
            "embedded_dynamic_denies": list(
                getattr(result, "embedded_dynamic_denies", []) or []
            ),
        }
    except Exception as e:
        logger_p.exception("post-provision result rendering failed")
        _safe_mark_failed(
            req,
            f"role created but result rendering failed: {e}. "
            "Check audit log; manual cleanup may be needed.",
            lifecycle=lifecycle,
        )
        return

    try:
        lifecycle.mark_provisioned(req, provisioned=provisioned)
    except Exception as e:
        logger_p.exception("mark_provisioned failed")
        _safe_mark_failed(
            req, f"role created but state transition failed: {e}",
            lifecycle=lifecycle,
        )


def _safe_mark_failed(
    req: dict[str, Any], error: str, *, lifecycle: Any
) -> None:
    """Set state=provisioning_failed without ever raising. Twin of the
    routes/requests.py helper of the same name (deliberate duplication
    per the _attempt_provisioning rationale)."""
    logger_p = logging.getLogger("iam_jit.provisioning")
    try:
        lifecycle.mark_provisioning_failed(req, error=error)
    except lifecycle.IllegalTransition:
        try:
            req.setdefault("status", {})["provisioning_error"] = error
        except Exception:
            logger_p.exception("failed to record provisioning error on request")
    except Exception:
        logger_p.exception("mark_provisioning_failed itself raised")
        try:
            req.setdefault("status", {})["provisioning_error"] = error
            req["status"]["state"] = "provisioning_failed"
        except Exception:
            pass
