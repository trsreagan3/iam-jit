"""Shared MFA-enforcement + provisioning-attempt helpers.

These were previously duplicated between `routes/requests.py` (the API
submit + approver paths) and `auto_approve_evaluator.py` (the centralised
gate that both web paste-form and API submit dispatch through). Per
`[[cross-product-agent-parity]]` the duplication was a "kept-in-sync-
by-discipline" twin — comments in both files noted the duplication
existed only to avoid a circular import (routes → evaluator → routes).

This module is a LEAF — it imports from `iam_jit.auto_approve`,
`iam_jit.self_approve_reductions`, and the provisioning / lifecycle /
assume modules, but it does NOT import from `routes/*` or from
`auto_approve_evaluator`. That makes the cited circular-import concern
structurally impossible: both callers depend on this module, this
module depends on neither caller.

Per `[[ibounce-honest-positioning]]`: if the two call sites need to
differ in behavior, expose that as a parameter or wrap the helper —
NEVER fork the implementation. The shape that landed here is the more-
parameterised one (the evaluator's `_attempt_provisioning` took its
provisioning / lifecycle / assume modules as kwargs); the previous
routes/* shape was the lazy form that closed over module-level imports.

Test discipline (per `docs/CONTRIBUTING.md`):
  - Test changes via BOTH call sites' regression suites
  - Neither caller should re-export these as public API (the
    underscore-prefixed names communicate intent)
  - The state-verification parity tests in
    `tests/test_auto_approve_helpers_parity.py` assert observable
    extraction state (imports wired, no local twins, sabotage-check
    proves the wire is load-bearing).

#601 (independent code review 2026-05-25 HIGH-4).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("iam_jit.auto_approve_helpers")


def apply_mfa_and_self_approve_enforcement(
    auto_decision: Any,
    *,
    mfa_audit: dict[str, Any],
    self_approve_audit: dict[str, Any],
    analysis_score: int,
    user_id: str,
) -> tuple[Any, str, dict[str, Any] | None]:
    """Apply MFA + self-approve enforcement on top of the score-gate decision.

    Returns `(effective_decision, audit_actor, mfa_block_response)` where
      - `effective_decision` is the (possibly-overridden) AutoApproveDecision
        the caller should treat as authoritative.
      - `audit_actor` is the string written to the audit log
        ("system:auto-approver" by default; "self_approve_reduction:<id>"
        when the self-approve override fired).
      - `mfa_block_response` is a dict with structured fields the route
        can splat into the response body so the API client knows to
        re-authenticate. None when no MFA override fired.

    Enforcement order is deliberate:

    1. Self-approve override runs FIRST. If the user qualifies as an admin
       doing a reduction of their OWN authority, flip auto_decision to
       approve here. The MFA gate (stage 2) will then run against this
       FLIPPED decision so a self-approved high-risk request still
       requires fresh MFA.

       Override-eligible auto_approve reasons (the cases where the user
       would otherwise be deadlocked into human review):
         - "above_threshold"  — score-gate denial; self-approve flips it
         - "feature_disabled" — auto-approve disabled or unconfigured
           (the solo-mode default: `auto_approve_risk_below` is None).
           Without this, the solo-founder UX deadlocks: admin submits
           reduction, lands in pending, four-eyes refuses approver==
           owner. The self-approve gate's whole purpose is to short-
           circuit that case for admins reducing their own authority.

       WB13-08 closure: previously MFA ran first and only fired when
       auto_decision.auto_approve was originally True. Score-gate
       denial bypassed MFA, then self-approve flipped to True
       unconditionally — an admin with stale MFA could auto-provision
       a high-risk role. Reordering self-approve → MFA closes that
       gap so MFA is the final word regardless of intermediate flips.

       NOT override-eligible (platform-team floors / explicit denies):
         - strict_mode_action_wildcard, strict_mode_admin_fallback —
           deploy-time policy ceiling admins cannot individually override
           (per WB12-08).
         - toggle_force_review — admin-curated "always send to review"
           toggle; flipping would defeat its purpose.
         - service_blocked, account_blocked — blocklist floors. The SAR
           gate already enforces service_blocked (returns not-eligible);
           account_blocked is enforced here.
         - over_quota — anti-composability defense; chained low-risk
           reductions should still surface at the cap.
         - no_policy — nothing to grant; not actionable.

    2. MFA enforcement runs on the (possibly self-approve-flipped) decision.
       If the effective decision is approve AND the request is high-risk
       AND MFA is missing/stale → BLOCK with mfa_required_for_high_risk.
       Audit actor reverts to system since MFA is a system gate (not a
       user action).

    WB12-04 closure: use truthy-vs-falsy comparison rather than
    `is True` / `is False`. Any falsy / truthy values returned by the
    audit dicts (e.g., a future mfa_gate that returns a bool-like
    object, or a missing key returning None) are handled safely.

    WB12-11 closure: do NOT leak the original (would-have-been) reason
    or score back to the caller. A stale-MFA attacker probing for "what
    was the score" by submitting variations benefits from the oracle.
    Audit chain still captures everything; the response body strips it.

    WB13-09 closure: `mfa_step_up_at_score` is the score-floor at or
    above which MFA is required, not a duration. Was mis-labeled
    `_max_age_seconds` previously (copy/paste from the cookie max-age
    field).
    """
    _would_require_mfa = bool(mfa_audit.get("would_require_mfa"))
    _mfa_present = bool(mfa_audit.get("mfa_present"))
    _self_approve_eligible = bool(self_approve_audit.get("self_approve_eligible"))

    # Track the audit actor through the override chain.
    effective_decision = auto_decision
    audit_actor = "system:auto-approver"

    # STAGE 1: Self-approve override.
    _override_eligible_reasons = ("above_threshold", "feature_disabled")
    if (
        not bool(getattr(effective_decision, "auto_approve", False))
        and getattr(effective_decision, "reason", "") in _override_eligible_reasons
        and _self_approve_eligible
    ):
        _original_reason = getattr(effective_decision, "reason", "")
        from .auto_approve import AutoApproveDecision
        from . import self_approve_reductions as _sar_mod
        effective_decision = AutoApproveDecision(
            auto_approve=True,
            reason="self_approve_reduction",
            details={
                "score": analysis_score,
                "original_reason": _original_reason,
                "self_approve_reason": self_approve_audit.get("self_approve_reason"),
                "details_pre_override": dict(getattr(auto_decision, "details", {}) or {}),
            },
        )
        audit_actor = _sar_mod.audit_actor_for(user_id)

    # STAGE 2: MFA enforcement on the (possibly-flipped) decision.
    if (
        bool(getattr(effective_decision, "auto_approve", False))
        and _would_require_mfa
        and not _mfa_present
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
        # Actor reverts to system: MFA is a platform gate, not a user
        # decision. Even if self-approve fired first, the MFA block
        # takes precedence in the actor field.
        return blocked, "system:auto-approver", block_response

    return effective_decision, audit_actor, None


def attempt_provisioning(
    req: dict[str, Any],
    *,
    accounts_store: Any,
    provision_mod: Any,
    assume_mod: Any,
    lifecycle: Any,
) -> None:
    """Synchronously provision after approval / auto-approve, persist
    result/error.

    GUARANTEE: this function NEVER raises. The state of the request
    after this returns is one of:
      - 'active' (provisioning succeeded, provisioned details populated)
      - 'provisioning_failed' (with provisioning_error set in status)
      - unchanged (only if the request wasn't in 'provisioning' to begin
        with, which means apply_transition didn't move it — that's fine)

    The all-failures-must-land-somewhere guarantee is what keeps requests
    from getting stuck in 'provisioning' and forces the UI to surface
    the failure to the approver. Callers MUST be able to call
    store.put() after this returns and rely on the state being terminal-
    or-actionable.

    Module dependencies are passed in (not imported here) because the
    two call sites — `routes/requests.py` and `auto_approve_evaluator.py`
    — already have their own canonical references to these modules and
    the leaf-module discipline forbids inbound imports from either
    caller. Passing as kwargs also makes test stubbing trivial.
    """
    logger_p = logging.getLogger("iam_jit.provisioning")
    try:
        result = provision_mod.provision(req, accounts_store=accounts_store)
    except provision_mod.ProvisioningError as e:
        logger_p.warning("provisioning failed: %s", e)
        safe_mark_failed(req, str(e), lifecycle=lifecycle)
        return
    except Exception as e:
        logger_p.exception("unexpected error during provisioning")
        safe_mark_failed(req, f"unexpected error: {e}", lifecycle=lifecycle)
        return

    # Result-building can also raise (template render, dataclass access).
    # Belt and suspenders.
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
            # #324f — surface embedded dynamic-deny rule ids so the
            # UI / `iam-jit show` / audit replay sees which rules
            # contributed to the role's policy without re-parsing the
            # inline policy JSON.
            "embedded_dynamic_denies": list(
                getattr(result, "embedded_dynamic_denies", []) or []
            ),
        }
    except Exception as e:
        logger_p.exception("post-provision result rendering failed")
        safe_mark_failed(
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
        safe_mark_failed(
            req,
            f"role created but state transition failed: {e}",
            lifecycle=lifecycle,
        )


def safe_mark_failed(
    req: dict[str, Any], error: str, *, lifecycle: Any
) -> None:
    """Set state=provisioning_failed without ever raising.

    If the request isn't in 'provisioning' state (e.g., a bug elsewhere
    advanced it already), we can't transition — but we can still record
    the error in status.provisioning_error so the UI sees something.

    Per #599 the last-resort fallback (after both `mark_provisioning_failed`
    and the manual dict mutation fail) logs loudly. The contract is
    "NEVER raises" so we can't propagate, but a silent pass leaves
    operators blind to a fully-broken request dict.
    """
    logger_p = logging.getLogger("iam_jit.provisioning")
    try:
        lifecycle.mark_provisioning_failed(req, error=error)
    except lifecycle.IllegalTransition:
        # Already moved past 'provisioning'. Record the error anyway.
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
            # #599: last-resort fallback after both transition + manual
            # dict mutation failed. Cannot raise (caller contract is
            # "NEVER raises"), but the silent pass that used to live
            # here meant a totally broken request dict left zero
            # operator trace. Log loudly even though we can't recover.
            logger_p.exception(
                "_auto_approve_helpers: last-resort manual status mutation "
                "in safe_mark_failed also raised; the request dict is in "
                "an indeterminate state (error_message=%r)",
                error,
            )
