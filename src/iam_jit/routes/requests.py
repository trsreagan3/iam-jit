"""Request lifecycle endpoints — the core of the iam-jit API.

POST   /api/v1/requests                       Submit a new request
GET    /api/v1/requests                       List (filtered by role/owner)
GET    /api/v1/requests/{id}                  Read full request
PATCH  /api/v1/requests/{id}                  Edit own pending request
POST   /api/v1/requests/{id}/approve          Approver action
POST   /api/v1/requests/{id}/reject           Approver action
POST   /api/v1/requests/{id}/request-changes  Approver action
POST   /api/v1/requests/{id}/cancel           Owner action
POST   /api/v1/requests/{id}/comments         Post a comment

Authorization is enforced in two layers: middleware (authenticated, role)
and the lifecycle module (state machine + ownership).
"""

from __future__ import annotations

import datetime as _dt
import io
import json
import os
import secrets
from typing import Annotated, Any


def _now_iso_z() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from .. import assume as assume_mod, audit as audit_mod, bans as bans_mod, lifecycle, narrow, prompt_injection, provision as provision_mod, review, schema
from ..lifecycle import IllegalTransition, NotAuthorized
from ..middleware import (
    current_user,
    get_accounts_store,
    get_request_store,
    require_admin,
    require_approver,
    require_requester,
)
from ..store import NotFoundError, RequestStore, VersionConflict
from ..users_store import User

router = APIRouter(prefix="/api/v1/requests", tags=["requests"])


# ---- Submission ----


def _generate_id() -> str:
    return secrets.token_urlsafe(8).lower().replace("_", "").replace("-", "")[:12] or secrets.token_urlsafe(8)


def _apply_mfa_and_self_approve_enforcement(
    auto_decision: "Any",  # AutoApproveDecision; quoted to dodge late-binding
    *,
    mfa_audit: dict[str, Any],
    self_approve_audit: dict[str, Any],
    analysis_score: int,
    user_id: str,
):
    """Apply MFA + self-approve enforcement on top of the score-gate decision.

    Returns `(effective_decision, audit_actor, mfa_block_response)` where
      - `effective_decision` is the (possibly-overridden) AutoApproveDecision
        the rest of the route should treat as authoritative.
      - `audit_actor` is the string written to the audit log
        ("system:auto-approver" by default; "self_approve_reduction:<id>"
        when the self-approve override fired).
      - `mfa_block_response` is a dict with structured fields the route
        can splat into the response body so the API client knows to
        re-authenticate. None when no MFA override fired.

    Enforcement order is deliberate:

    1. MFA freshness gate runs FIRST. A high-risk grant requires recent
       MFA regardless of whether the user is otherwise an admin who
       could self-approve. Admin self-approval is a reduction-of-
       authority gate, not a "skip security checks" gate.

    2. Self-approve override runs SECOND. If MFA didn't block AND the
       score gate said "above_threshold" AND the user qualifies for
       self-approve-reductions (admin + owns request + not blocklisted),
       flip auto_decision to approve with actor
       `self_approve_reduction:<user.id>`.

    3. Otherwise return the original decision unchanged.
    """
    # WB12-04 closure: use truthy-vs-falsy comparison rather than
    # `is True` / `is False`. Any falsy / truthy values returned by
    # the audit dicts (e.g., a future mfa_gate that returns a
    # bool-like object, or a missing key returning None) are handled
    # safely. Old `is True` check would reject any non-True truthy.
    _would_require_mfa = bool(mfa_audit.get("would_require_mfa"))
    _mfa_present = bool(mfa_audit.get("mfa_present"))
    _self_approve_eligible = bool(self_approve_audit.get("self_approve_eligible"))

    # Track the audit actor through the override chain.
    effective_decision = auto_decision
    audit_actor = "system:auto-approver"

    # ------------------------------------------------------------------
    # STAGE 1: Self-approve override. If the score gate said
    # above_threshold AND the user qualifies as an admin doing a
    # reduction, flip to approve here. The MFA gate (stage 2) will
    # then run against this FLIPPED decision so a self-approved
    # high-risk request still requires fresh MFA.
    #
    # WB13-08 closure: previously MFA ran first and only fired when
    # auto_decision.auto_approve was originally True. Score-gate
    # denial bypassed MFA, then self-approve flipped to True
    # unconditionally — an admin with stale MFA could auto-provision
    # a high-risk role. Reordering self-approve → MFA closes that
    # gap so MFA is the final word regardless of intermediate flips.
    #
    # NOTE: strict-mode-blocked reasons (strict_mode_action_wildcard,
    # strict_mode_admin_fallback) are NOT eligible for self-approve.
    # Strict mode is a deploy-time policy ceiling that admins cannot
    # individually override — by design. WB12-08.
    # ------------------------------------------------------------------
    if (
        not bool(getattr(effective_decision, "auto_approve", False))
        and getattr(effective_decision, "reason", "") == "above_threshold"
        and _self_approve_eligible
    ):
        from ..auto_approve import AutoApproveDecision
        from .. import self_approve_reductions as _sar_mod
        effective_decision = AutoApproveDecision(
            auto_approve=True,
            reason="self_approve_reduction",
            details={
                "score": analysis_score,
                "original_reason": "above_threshold",
                "self_approve_reason": self_approve_audit.get("self_approve_reason"),
                "details_pre_override": dict(getattr(auto_decision, "details", {}) or {}),
            },
        )
        audit_actor = _sar_mod.audit_actor_for(user_id)

    # ------------------------------------------------------------------
    # STAGE 2: MFA enforcement. Runs on the (possibly self-approve-
    # flipped) decision. If the effective decision is approve AND the
    # request is high-risk AND MFA is missing/stale → BLOCK with
    # mfa_required_for_high_risk. Audit actor reverts to system since
    # MFA is a system gate (not a user action).
    # ------------------------------------------------------------------
    if (
        bool(getattr(effective_decision, "auto_approve", False))
        and _would_require_mfa
        and not _mfa_present
    ):
        from ..auto_approve import AutoApproveDecision
        # WB12-11 closure: do NOT leak the original (would-have-been)
        # reason or score back to the caller. A stale-MFA attacker
        # probing for "what was the score" by submitting variations
        # benefits from the oracle. Audit chain still captures
        # everything; the response body strips it.
        blocked = AutoApproveDecision(
            auto_approve=False,
            reason="mfa_required_for_high_risk",
            details={
                "mfa_step_up_required": True,
                # WB13-09 closure: this field is the score-floor at
                # or above which MFA is required, not a duration. Was
                # mis-labeled `_max_age_seconds` previously (copy/paste
                # from the cookie max-age field).
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


def _scan_submission_for_injection(
    user: User, **fields: str
) -> HTTPException | None:
    """Scan each named field for prompt-injection. Mirrors the chat
    enforcement: high-confidence → ban + 403; medium-confidence → 400
    rejection without ban. Audit-logs every detection with the field
    name so an admin reviewing the ban knows where the bad text lived.
    """
    for field_name, value in fields.items():
        if not value:
            continue
        verdict = prompt_injection.detect(str(value))
        if not verdict.detected:
            continue
        try:
            audit_mod.emit(
                actor=user.id,
                kind="security.prompt_injection",
                summary=f"prompt-injection in submission/{field_name} ({verdict.confidence})",
                details={
                    "field": field_name,
                    "reasons": verdict.reasons,
                    "snippets": verdict.snippets,
                    "confidence": verdict.confidence,
                },
            )
        except Exception:
            pass
        if verdict.confidence == "high":
            try:
                bans_mod.ban_for_injection(
                    store=bans_mod.get_default_store(),
                    user_id=user.id,
                    reasons=verdict.reasons,
                    snippets=verdict.snippets,
                    confidence=verdict.confidence,
                    is_admin=user.is_admin,
                )
            except Exception:
                pass
            return HTTPException(
                status_code=403,
                detail=(
                    f"submission rejected and account suspended for "
                    f"prompt-injection text in field {field_name!r}"
                ),
            )
        return HTTPException(
            status_code=400,
            detail=(
                f"submission rejected: field {field_name!r} contains "
                f"text classified as a prompt-injection attempt"
            ),
        )
    return None


def _auto_name(req: dict[str, Any]) -> str:
    """Synthesize a human-readable name from the request when none is set.

    Format: '<verb> <services> in <account/alias> (<duration>h)'
    Falls back to the first ~70 chars of the description if we can't
    construct anything cleaner.

    DEFENSIVE: this runs BEFORE schema validation in the submit path
    (so the validator sees the auto-named request and can flag a
    metadata.name issue alongside whatever else is wrong). That means
    every field this function reads can be the wrong type or missing.
    Caught during the round-2 UX test (2026-05-16): a `spec.duration`
    sent as a string crashed `.get("duration_hours")` and produced a
    500 instead of the schema 400 the user expected. Guard each
    accessor; on any unexpected shape, return the safe fallback.
    """
    try:
        spec = req.get("spec") or {}
        if not isinstance(spec, dict):
            return "iam-jit request"
        description = (spec.get("description") or "").strip() if isinstance(spec.get("description"), str) else ""
        services_raw = spec.get("services") or (
            spec.get("task_intent", {}).get("services")
            if isinstance(spec.get("task_intent"), dict)
            else None
        ) or []
        services = services_raw if isinstance(services_raw, list) else []
        accounts = spec.get("accounts") or []
        account_alias = ""
        if isinstance(accounts, list) and accounts and isinstance(accounts[0], dict):
            account_alias = (
                accounts[0].get("alias")
                or accounts[0].get("account_id")
                or ""
            )
        # WB-UX-2 closure: `spec.duration` may be a string, None, or
        # any other shape in malformed input. Only treat it as a
        # source of `duration_hours` when it's actually a dict.
        duration_block = spec.get("duration")
        duration = None
        if isinstance(duration_block, dict):
            duration = duration_block.get("duration_hours")
        access_type = spec.get("access_type")
        if not isinstance(access_type, str):
            access_type = ""

        parts: list[str] = []
        if access_type:
            parts.append(access_type)
        if services:
            parts.append("/".join(s for s in services if isinstance(s, str))[:30])
        if account_alias:
            parts.append(f"in {account_alias}")
        if duration:
            parts.append(f"({duration}h)")
        candidate = " ".join(parts).strip()
        if len(candidate) < 8:
            candidate = description[:80]
        return candidate[:80] or "iam-jit request"
    except Exception:
        # Last-resort safety net so a crash here can never produce
        # a 500 in the submit path. The schema validator will reject
        # the request shortly with the actual diagnostic.
        return "iam-jit request"


def _validate_or_400(req: dict[str, Any]) -> None:
    errors = schema.validate_request(req)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": errors},
        )


def _admin_risk_context() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Pull org-specific risk context from settings.

    Returns (extra_sensitive_services, extra_high_impact_actions).
    Admin-curated; refreshes from the settings store on each call
    (the settings store caches with a 10s TTL so this is cheap).
    See docs/TUNING-RISK.md.
    """
    try:
        from .. import settings_store
        s = settings_store.get_default_store().get()
        return (
            s.additional_sensitive_services,
            s.additional_high_impact_actions,
        )
    except Exception:
        return (), ()


def _build_review_block(req: dict[str, Any]) -> dict[str, Any] | None:
    """Compute and attach the risk-review block.

    The deterministic scorer runs UNCONDITIONALLY when a policy is
    present — it has no LLM dependency, and the resulting score
    drives auto-approve. Suppressing the score in NoAI mode would
    break the auto-approve gate (no score → no decision → request
    stuck at `pending` indefinitely in single-admin / sandbox
    deployments where self-approve is forbidden).

    The LLM-narrative side of the review is OPTIONAL: when no
    backend is configured, `analyze_policy` returns
    `llm_narrative=None` and the deterministic suggestions stand
    on their own. That gating happens inside `analyze_policy`
    based on the `backend` argument — we don't pass one here at
    submit time today (narrative generation is an async UI feature
    that runs separately), so the result is purely deterministic.

    Returns None only when there's no policy to score.
    """
    _spec_for_policy = req.get("spec")
    policy = _spec_for_policy.get("policy") if isinstance(_spec_for_policy, dict) else None
    if not policy:
        return None
    extra_services, extra_actions = _admin_risk_context()
    analysis = review.analyze_policy(
        policy, req,
        extra_sensitive_services=extra_services,
        extra_high_impact_actions=extra_actions,
    )
    block = analysis.to_dict()
    req.setdefault("status", {})["review"] = block
    return block


@router.post("/preview")
def preview_request(
    request: Request,
    payload: dict[str, Any],
    user: Annotated[User, Depends(require_requester)],
) -> dict[str, Any]:
    """Evaluate a candidate request WITHOUT submitting it.

    Returns the same risk + auto-approve verdict the submit endpoint
    would produce, plus an explicit `would_auto_approve` boolean so
    the UI can show a dial: "your current score is X; threshold is
    Y; would auto-approve = yes/no". The agent / user iterates on
    the policy, re-calls /preview after each tightening, and learns
    in real-time which changes drop the score below threshold —
    incentivizing least-privilege requests.

    Critical: NO state is mutated. No request is stored. No quota
    counter advances. No audit event is emitted. Quota is reported
    as a SIMULATION (what would happen IF the user submitted now).

    Identical input → identical output (modulo time-window quota
    state which is independent of this call).
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    # Per-user rate limit on /preview. The endpoint is cheap (no
    # state mutation, no LLM call today) but the roadmap calls for
    # LLM-driven advice that would be expensive. Guard now so a
    # rogue / buggy client iterating in a tight loop can't DoS the
    # Lambda's concurrency or rack up LLM bills.
    from .. import rate_limit as _rate_limit_mod
    _decision = _rate_limit_mod.get_default_limiter().check(
        user.id, kind="preview"
    )
    if not _decision.allowed:
        raise HTTPException(
            status_code=429,
            detail=(
                f"too many /preview calls; retry in "
                f"{_decision.retry_after_seconds}s. "
                f"Preview is meant for interactive iteration — "
                f"if you're scripting, batch the changes and submit "
                f"once."
            ),
            headers={"Retry-After": str(max(1, _decision.retry_after_seconds))},
        )

    # Stamp the same server-controlled fields the real submit would,
    # so the analyzer sees the same shape. Avoid mutating the caller's
    # payload.
    req = dict(payload)
    _metadata_raw = req.get("metadata"); metadata = dict(_metadata_raw) if isinstance(_metadata_raw, dict) else {}
    metadata["id"] = "preview-no-id"
    metadata["requester"] = {
        "email": user.id.removeprefix("email:") if user.id.startswith("email:") else user.id,
        "name": user.display_name or user.id,
    }
    req["metadata"] = metadata
    req["status"] = {}

    # Validate (don't 400 on invalid — surface the validation errors
    # alongside the risk verdict so the UI can show "fix these AND
    # bring the score down").
    schema_errors = schema.validate_request(req)

    _spec_for_policy = req.get("spec")
    policy = _spec_for_policy.get("policy") if isinstance(_spec_for_policy, dict) else None
    analysis_dict = None
    auto_decision = None
    threshold = None

    if policy:
        extra_services, extra_actions = _admin_risk_context()
        analysis = review.analyze_policy(
            policy, req,
            extra_sensitive_services=extra_services,
            extra_high_impact_actions=extra_actions,
        )
        analysis_dict = analysis.to_dict()

        from .. import auto_approve as auto_approve_mod
        from .. import settings_store as settings_mod
        from .. import rate_limit as rate_limit_mod

        settings = settings_mod.get_default_store().get()
        threshold = settings.auto_approve_risk_below
        # IMPORTANT: use a TEMPORARY in-memory rate limiter that's
        # initialized fresh on every call. Otherwise calling /preview
        # repeatedly would burn the user's actual quota.
        sim_quota = rate_limit_mod.InMemoryRateLimiter(
            soft_cap=settings.auto_approve_quota_per_hour,
            hard_cap=settings.auto_approve_quota_per_hour * 10 + 1,
            window_seconds=3600,
        )
        # Safety-mode threshold resolution: pick the right threshold
        # based on safety mode (read_write_swap vs strict) and
        # access_type (read vs write). Per [[safety-mode-two-modes]]
        # + [[read-only-default]] memos. For multi-account requests
        # we pick the MOST RESTRICTIVE mode across the set so a
        # mixed [dev, prod-strict] request cannot weaken the prod
        # policy (WB10-03).
        from .. import safety_mode as _safety_mode
        from .. import settings_store as _settings_store_mod
        _spec = req.get("spec") or {}
        _access_type = (_spec.get("access_type") or "read-write").strip()
        _accounts = _spec.get("accounts") or []
        _account_ids = [
            a.get("account_id") for a in _accounts
            if isinstance(a, dict) and a.get("account_id")
        ]
        _accounts_store = getattr(request.app.state, "accounts_store", None)
        _mode = _safety_mode.resolve_mode_for_accounts(
            account_ids=_account_ids, accounts_store=_accounts_store,
        )
        _effective_threshold = _safety_mode.auto_approve_threshold_for(
            _mode, access_type=_access_type,
        )
        _safety_thresholds = _safety_mode.thresholds_for(_mode)
        _floors = _settings_store_mod.Floors.from_env()
        auto_decision = auto_approve_mod.evaluate(
            request=req,
            analysis_score=analysis.risk_score,
            user_id=user.id,
            settings=settings,
            quota_limiter=sim_quota,
            effective_threshold=_effective_threshold,
            floor_max_auto_approve_risk_below=(
                _floors.max_auto_approve_risk_below
            ),
            safety_thresholds=_safety_thresholds,
        )

        # Apply the SAME MFA + self-approve enforcement on preview
        # that we apply on submit. Otherwise preview tells the user
        # "this WILL auto-approve" but submit later blocks because
        # MFA is stale — a frustrating false-positive. Compute the
        # gate annotations the same way submit does, then run the
        # helper.
        _preview_mfa_audit: dict[str, Any] = {"mfa_gate_evaluated": False}
        try:
            from .. import mfa_gate as _mfa_gate
            from ..middleware import _get_secret as _auth_secret_getter  # type: ignore[attr-defined]
            _mfa_cookie = request.cookies.get("iam_jit_session_mfa") if hasattr(request, "cookies") else None
            _preview_mfa_audit = _mfa_gate.evaluate_for_route(
                cookie_value=_mfa_cookie,
                secret=_auth_secret_getter(),
                user_id=user.id,
                risk_score=analysis.risk_score,
                api_token_record=getattr(
                    getattr(request, "state", None), "api_token_record", None,
                ),
            )
        except Exception:
            pass

        _preview_sar_audit: dict[str, Any] = {"self_approve_evaluated": False}
        try:
            from .. import self_approve_reductions as _sar
            _sar_dec = _sar.evaluate(
                request=req,
                user_id=user.id,
                user_is_admin=getattr(user, "is_admin", False),
                blocked_services=tuple(settings.never_auto_approve_services),
            )
            _preview_sar_audit = {
                "self_approve_evaluated": True,
                "self_approve_eligible": _sar_dec.self_approved,
                "self_approve_reason": _sar_dec.reason,
            }
        except Exception:
            pass

        auto_decision, _, _ = _apply_mfa_and_self_approve_enforcement(
            auto_decision,
            mfa_audit=_preview_mfa_audit,
            self_approve_audit=_preview_sar_audit,
            analysis_score=analysis.risk_score,
            user_id=user.id,
        )

    # Surface concrete advice on how to reduce risk. The deterministic
    # scorer already returns `suggestions` in the analysis; we
    # supplement with auto-approve specific guidance the UI can show
    # next to the dial.
    advice: list[str] = []
    if analysis_dict:
        advice.extend(analysis_dict.get("suggestions", []))
        if threshold is None:
            advice.append(
                "Auto-approve is disabled on this deployment. All "
                "requests route to human review. Ask an admin to "
                "enable it via PATCH /api/v1/admin/auto-approve/settings."
            )
        elif analysis_dict["risk_score"] >= threshold:
            gap = analysis_dict["risk_score"] - threshold + 1
            advice.append(
                f"Score is {analysis_dict['risk_score']}; auto-approve "
                f"threshold is < {threshold}. Drop the score by {gap}+ "
                f"to qualify. Try: tightening the resource scope, "
                f"removing wildcard actions, shortening the duration, "
                f"or splitting into multiple smaller requests."
            )
        elif auto_decision and not auto_decision.auto_approve:
            advice.append(
                f"Score qualifies ({analysis_dict['risk_score']} < "
                f"{threshold}) but `{auto_decision.reason}` blocks "
                f"auto-approve. Details: {auto_decision.details}."
            )

    return {
        "schema_errors": schema_errors,
        "review": analysis_dict,
        "auto_approve_threshold": threshold,
        "would_auto_approve": (
            auto_decision.auto_approve if auto_decision else False
        ),
        "auto_approve_decision": (
            {
                "auto_approve": auto_decision.auto_approve,
                "reason": auto_decision.reason,
                "details": auto_decision.details,
            } if auto_decision else None
        ),
        "advice": advice,
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def submit_request(
    request: Request,
    payload: dict[str, Any],
    user: Annotated[User, Depends(require_requester)],
    store: Annotated[RequestStore, Depends(get_request_store)],
    accounts_store: Annotated[Any, Depends(get_accounts_store)],
) -> dict[str, Any]:
    """Submit a new role request.

    Body is the full request YAML/JSON; the server stamps:
      - metadata.id (if not provided)
      - status.state = pending
      - status.owner = user.id
      - status.review = computed risk analysis
      - status.history = [submit event]

    Returns the stored request plus narrowing questions for the agent / UI
    to surface to the user.
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    # Defense in depth: scan free-form text fields for prompt-injection
    # patterns BEFORE we accept the submission. These fields all flow
    # back into the LLM (review block, memory store, agent prompts) or
    # into the approver's UI — both attack surfaces for indirect
    # injection. High-confidence detection bans the user.
    # WB-UX-2 closure: defend against malformed `spec` / `metadata` /
    # `requester` shapes from the client. The injection-scan + the
    # downstream metadata stamping both call `.get()` on these blocks;
    # if a client sends `spec: 42`, those crashes produce 5xx instead
    # of the schema 400 the user expected. Coerce non-dicts to empty
    # dicts here; `_validate_or_400` below will produce the actual
    # schema diagnostic.
    spec_in_raw = payload.get("spec")
    spec_in = spec_in_raw if isinstance(spec_in_raw, dict) else {}
    metadata_in_raw = payload.get("metadata")
    metadata_in = metadata_in_raw if isinstance(metadata_in_raw, dict) else {}
    requester_in_raw = metadata_in.get("requester")
    requester_in = requester_in_raw if isinstance(requester_in_raw, dict) else {}

    def _safe_str(d: dict, key: str) -> str:
        v = d.get(key)
        return v if isinstance(v, str) else ""

    refused = _scan_submission_for_injection(
        user,
        description=_safe_str(spec_in, "description"),
        ticket=_safe_str(spec_in, "ticket"),
        requester_name=_safe_str(requester_in, "name"),
        request_name=_safe_str(metadata_in, "name"),
    )
    if refused is not None:
        raise refused

    # Stamp identification + ownership; never trust the client to set
    # the request id, requester identity, status, or review fields —
    # all of those are server-controlled. A bug elsewhere that lets a
    # client-supplied value through must not be able to forge identity
    # or collide with another user's request id.
    req = dict(payload)
    _metadata_raw = req.get("metadata"); metadata = dict(_metadata_raw) if isinstance(_metadata_raw, dict) else {}
    # Always assign a fresh server-generated id. Refuse client-supplied
    # ids: even if they pass schema validation, accepting them lets a
    # client overwrite an existing request by guessing or reusing an id.
    metadata["id"] = _generate_id()
    if not metadata.get("name"):
        metadata["name"] = _auto_name(req)
    # Requester block is also server-stamped. The client may include a
    # `requester` field for completeness but the email/principal_arn are
    # always pulled from the authenticated user — keeping a client-supplied
    # email would let an attacker file requests "as" another user.
    auth_email = (
        user.id.removeprefix("email:") if user.id.startswith("email:") else user.id
    )
    incoming_requester = dict(metadata.get("requester") or {})
    requester: dict[str, Any] = {
        "email": auth_email,
        "name": user.display_name or incoming_requester.get("name") or auth_email,
    }
    if incoming_requester.get("principal_arn"):
        # principal_arn is the only field a caller can legitimately
        # supply (CI runner ARN, instance profile, etc.) — but pass it
        # through the same injection scan as other free-form fields.
        requester["principal_arn"] = incoming_requester["principal_arn"]
    metadata["requester"] = requester
    req["metadata"] = metadata
    req["status"] = {}  # server owns status — drop any client-supplied review

    _validate_or_400(req)

    # Enforce admin-configured org-wide max duration BEFORE init.
    # Done after schema validation so the operator sees schema errors
    # first if both apply. The check is structural — it walks the
    # request's `spec.duration` block and compares to the admin
    # setting.
    from .. import settings_store as _settings_mod
    _settings = _settings_mod.get_default_store().get()
    if _settings.max_role_duration_hours is not None:
        spec_block = req.get("spec") or {}
        req_duration = (spec_block.get("duration") or {}).get("duration_hours")
        if (
            isinstance(req_duration, (int, float))
            and req_duration > _settings.max_role_duration_hours
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"requested duration {req_duration}h exceeds the admin-"
                    f"configured max of {_settings.max_role_duration_hours}h. "
                    f"Request a shorter window, or ask an admin to raise "
                    f"the cap via PATCH /api/v1/admin/auto-approve/settings."
                ),
            )

    lifecycle.init_status(req, owner=user)
    review_block = _build_review_block(req)
    questions = []
    _spec_for_policy = req.get("spec")
    policy = _spec_for_policy.get("policy") if isinstance(_spec_for_policy, dict) else None
    if policy:
        questions = [
            q.__dict__ if hasattr(q, "__dict__") else q
            for q in narrow.detect_broadness(policy, req)
        ]

    # Auto-approve gate. Composes four checks: feature enabled,
    # score < threshold, no blocklisted service/account, user under
    # per-hour quota. Any failure leaves the request in pending for
    # human review. Audit captures the gate that fired so a reviewer
    # can answer "why didn't this auto-approve?" in one click.
    auto_decision = None
    _mfa_block_response: dict[str, Any] | None = None
    _auto_audit_actor = "system:auto-approver"
    if review_block:
        from .. import auto_approve as auto_approve_mod
        from .. import settings_store as settings_mod
        from .. import rate_limit as rate_limit_mod

        settings = settings_mod.get_default_store().get()
        quota = rate_limit_mod.get_default_limiter()
        # Safety-mode threshold resolution per [[safety-mode-two-modes]].
        # Mirrors the preview-route logic above. Multi-account requests
        # use the MOST RESTRICTIVE mode across the set (WB10-03);
        # threshold is clamped to the platform-team floor (WB10-02).
        from .. import safety_mode as _safety_mode
        _submit_spec = req.get("spec") or {}
        _submit_access_type = (_submit_spec.get("access_type") or "read-write").strip()
        _submit_accounts = _submit_spec.get("accounts") or []
        _submit_account_ids = [
            a.get("account_id") for a in _submit_accounts
            if isinstance(a, dict) and a.get("account_id")
        ]
        _submit_accounts_store = getattr(request.app.state, "accounts_store", None)
        _submit_mode = _safety_mode.resolve_mode_for_accounts(
            account_ids=_submit_account_ids,
            accounts_store=_submit_accounts_store,
        )
        _submit_effective_threshold = _safety_mode.auto_approve_threshold_for(
            _submit_mode, access_type=_submit_access_type,
        )
        _submit_safety_thresholds = _safety_mode.thresholds_for(_submit_mode)
        _submit_floors = settings_mod.Floors.from_env()

        # MFA + self-approve evaluation runs BEFORE auto_decision so
        # the enforcement override can use both verdicts. Each block
        # is wrapped in try/except so a bug in the gate code never
        # blocks a grant — failure mode is "annotation missing", not
        # "request stuck".
        _mfa_audit: dict[str, Any] = {"mfa_gate_evaluated": False}
        try:
            from .. import mfa_gate as _mfa_gate
            from ..middleware import _get_secret as _auth_secret_getter  # type: ignore[attr-defined]
            mfa_cookie = request.cookies.get("iam_jit_session_mfa") if hasattr(request, "cookies") else None
            _mfa_audit = _mfa_gate.evaluate_for_route(
                cookie_value=mfa_cookie,
                secret=_auth_secret_getter(),
                user_id=user.id,
                risk_score=review_block.get("risk_score", 0),
                api_token_record=getattr(
                    getattr(request, "state", None), "api_token_record", None,
                ),
            )
        except Exception:
            pass

        _self_approve_audit: dict[str, Any] = {"self_approve_evaluated": False}
        try:
            from .. import self_approve_reductions as _sar
            sar_decision = _sar.evaluate(
                request=req,
                user_id=user.id,
                user_is_admin=getattr(user, "is_admin", False),
                blocked_services=tuple(settings.never_auto_approve_services),
            )
            _self_approve_audit = {
                "self_approve_evaluated": True,
                "self_approve_eligible": sar_decision.self_approved,
                "self_approve_reason": sar_decision.reason,
            }
        except Exception:
            pass

        auto_decision = auto_approve_mod.evaluate(
            request=req,
            analysis_score=review_block.get("risk_score", 10),
            user_id=user.id,
            effective_threshold=_submit_effective_threshold,
            settings=settings,
            quota_limiter=quota,
            floor_max_auto_approve_risk_below=(
                _submit_floors.max_auto_approve_risk_below
            ),
            safety_thresholds=_submit_safety_thresholds,
        )

        # Apply MFA + self-approve enforcement on top of the score-gate
        # decision. MFA stale + high-risk → block (downgrade to review).
        # Admin self-approve eligible + above-threshold → flip to approve
        # with actor `self_approve_reduction:<user.id>`.
        auto_decision, _auto_audit_actor, _mfa_block_response = (
            _apply_mfa_and_self_approve_enforcement(
                auto_decision,
                mfa_audit=_mfa_audit,
                self_approve_audit=_self_approve_audit,
                analysis_score=review_block.get("risk_score", 10),
                user_id=user.id,
            )
        )

        try:
            # WB10-05: include safety-mode context so a compliance
            # auditor can prove a grant was made under strict mode
            # (or wasn't). `mode_source` says whether the effective
            # threshold came from the resolver (per-account /
            # safety-mode) or the deployment-wide setting.
            _mode_source = (
                "safety_mode_resolver"
                if _submit_effective_threshold is not None
                else "deployment_setting"
            )
            audit_mod.emit(
                actor=_auto_audit_actor,
                kind=(
                    "request.auto_approved"
                    if auto_decision.auto_approve
                    else "request.auto_approve_skipped"
                ),
                summary=(
                    f"auto-approve evaluated for {metadata['id']}: "
                    f"{auto_decision.reason} "
                    f"(mode={_submit_mode}, actor={_auto_audit_actor})"
                ),
                details={
                    "request_id": metadata["id"],
                    "owner_id": user.id,
                    "safety_mode": _submit_mode,
                    "mode_source": _mode_source,
                    "allow_action_wildcards": (
                        _submit_safety_thresholds.allow_action_wildcards
                    ),
                    "allow_admin_fallback": (
                        _submit_safety_thresholds.allow_admin_fallback
                    ),
                    "floor_max_auto_approve_risk_below": (
                        _submit_floors.max_auto_approve_risk_below
                    ),
                    **_mfa_audit,
                    **_self_approve_audit,
                    **auto_decision.details,
                },
            )
        except Exception:
            pass

        # Shadow mode: when IAM_JIT_SHADOW_MODE=1 the scorer runs
        # and the decision is recorded in the audit trail, but
        # the request state stays at `pending` regardless of the
        # auto-approve verdict. Use this to deploy iam-jit
        # alongside a customer's existing approval workflow —
        # they observe the scorer's verdicts for N weeks before
        # turning it on for real. Critical gate to enterprise
        # adoption (security teams won't trust auto-approve they
        # haven't watched in action).
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
                        f"shadow-mode decision for {metadata['id']}: "
                        f"would_auto_approve="
                        f"{auto_decision.auto_approve}; "
                        f"score={review_block.get('risk_score') if review_block else None}; "
                        f"reason={auto_decision.reason}"
                    ),
                    details={
                        "request_id": metadata["id"],
                        "owner_id": user.id,
                        "would_auto_approve": auto_decision.auto_approve,
                        "would_reason": auto_decision.reason,
                        "would_details": auto_decision.details,
                        "shadow_mode": True,
                    },
                )
            except Exception:
                pass
            # IMPORTANT: do NOT mutate state. The request stays
            # at `pending` and will be reviewed by a human via the
            # customer's existing process. Skip directly to store.put.

        elif auto_decision.auto_approve:
            # Bypass the lifecycle.transition() check (which would
            # require an "approver" actor distinct from the owner).
            # System-driven approval has its own audit actor and
            # doesn't carry the separation-of-duties invariant —
            # there's no human approver to puppet here.
            #
            # Target state is `provisioning` (the same state a
            # manual approve would land in via lifecycle's pending
            # → provisioning transition). After the state flip we
            # immediately call _attempt_provisioning so the role
            # is created synchronously; the request lands at
            # `active` (success) or `provisioning_failed`
            # (failure). The legacy code wrote state="approved"
            # which was NOT a valid state in lifecycle's state
            # machine — it left auto-approved requests stuck
            # outside the normal flow with no provisioned role.
            status = req["status"]
            status["state"] = "provisioning"
            history = status.setdefault("history", [])
            history.append({
                "actor": _auto_audit_actor,
                "action": "auto_approve",
                "to_state": "provisioning",
                "at": _now_iso_z(),
                "reason": auto_decision.reason,
                "details": auto_decision.details,
            })
            try:
                _attempt_provisioning(req, accounts_store=accounts_store)
            except Exception as e:  # pragma: no cover — defense in depth
                _safe_mark_failed(
                    req, f"auto-approve provisioning crashed: {e}",
                )

    store.put(metadata["id"], req)

    # Fire-and-forget Slack approval-card post when the request lands
    # in pending state (i.e., did NOT auto-approve). Failures are
    # logged and SWALLOWED — a Slack outage must not block iam-jit
    # submissions.
    if req.get("status", {}).get("state") == "pending":
        try:
            from .. import slack_bot

            slack_cfg = slack_bot.SlackConfig.from_env()
            if slack_cfg is not None:
                slack_bot.post_approval_message(
                    request=req,
                    config=slack_cfg,
                    deployment_url=os.environ.get("IAM_JIT_PUBLIC_URL"),
                )
        except Exception as e:
            import logging
            logging.getLogger("iam_jit.routes.requests").warning(
                "slack approval post failed (request still submitted): %s", e
            )

    response: dict[str, Any] = {
        "request": req,
        "review": review_block,
        "narrowing_questions": questions,
        "auto_approve_decision": (
            {
                "auto_approve": auto_decision.auto_approve,
                "reason": auto_decision.reason,
                "details": auto_decision.details,
            } if auto_decision else None
        ),
    }
    # MFA enforcement signal: when the gate downgraded auto-approve
    # to review because MFA was missing/stale on a high-risk grant,
    # surface the structured re-auth hint so the API client can
    # bounce the user through OIDC and resubmit.
    if _mfa_block_response is not None:
        response["mfa_step_up"] = _mfa_block_response
        # Phase 3 (minimal): fire-and-forget Slack DM nudge to the
        # human authorizer. They click the link, re-auth via OIDC,
        # then the agent resubmits and MFA freshness passes. Failures
        # are swallowed — never block iam-jit's own response on a
        # Slack outage.
        try:
            from .. import slack_bot as _slack_bot
            _slack_cfg = _slack_bot.SlackConfig.from_env()
            if _slack_cfg is not None and _slack_cfg.bot_token:
                # Resolve the user's slack_user_id from the user store
                # if available (most user records carry the mapping).
                _slack_uid = getattr(user, "slack_user_id", None)
                if _slack_uid:
                    _slack_bot.post_mfa_step_up_nudge(
                        user_id=user.id,
                        slack_user_id=_slack_uid,
                        request_id=metadata["id"],
                        config=_slack_cfg,
                        deployment_url=os.environ.get("IAM_JIT_PUBLIC_URL"),
                        reason=_mfa_block_response.get("reason", "fresh_mfa_required"),
                    )
        except Exception:
            pass
    return response


# ---- Listing + reading ----


def _load_or_404(store: RequestStore, request_id: str) -> dict[str, Any]:
    try:
        return store.get(request_id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail=f"request {request_id} not found")
    except ValueError:
        # Reject malformed request_id (path traversal attempts, NUL
        # bytes, length overflow, etc.) with a clean 404 — don't leak
        # the validator regex or "invalid id" hint to the caller, since
        # that would help an attacker probe the validation.
        raise HTTPException(status_code=404, detail="request not found")


_LIST_PAGE_DEFAULT = 100
_LIST_PAGE_MAX = 500


@router.get("")
def list_requests(
    user: Annotated[User, Depends(current_user)],
    store: Annotated[RequestStore, Depends(get_request_store)],
    state_filter: Annotated[str | None, Query(alias="state")] = None,
    owner_filter: Annotated[str | None, Query(alias="owner")] = None,
    hide_cancelled: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=_LIST_PAGE_MAX)] = _LIST_PAGE_DEFAULT,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    """List requests visible to the caller.

    Requesters see only their own; approvers and admins see all.
    Optional `state` and `owner` query params narrow the result.

    `hide_cancelled=true` filters out cancelled requests entirely. The
    default keeps them so agents using the API can still see their own
    cancellation history; flip the flag to suppress noise.

    Pagination: `limit` (1..500) and `offset`. Defaults return the
    first 100. `total` in the response gives the unpaginated count so
    callers can detect when more pages exist. The hard cap exists so
    a deployment with 50k requests doesn't get loaded into memory by
    a single GET — that would be both slow and an OOM risk.
    """
    matched: list[dict[str, Any]] = []
    for rid in store.list_ids():
        try:
            req = store.get(rid)
        except Exception:
            continue
        if not lifecycle.can_view(req, user):
            continue
        state = lifecycle.get_state(req)
        if state_filter and state != state_filter:
            continue
        if owner_filter and lifecycle.get_owner(req) != owner_filter:
            continue
        if hide_cancelled and state == "cancelled":
            continue
        matched.append(lifecycle.summarize(req))
    total = len(matched)
    page = matched[offset : offset + limit]
    return {
        "requests": page,
        "count": len(page),
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/{request_id}")
def get_request(
    request_id: str,
    user: Annotated[User, Depends(current_user)],
    store: Annotated[RequestStore, Depends(get_request_store)],
) -> dict[str, Any]:
    req = _load_or_404(store, request_id)
    if not lifecycle.can_view(req, user):
        raise HTTPException(status_code=403, detail="not authorized to view this request")
    return req


# ---- Edits + transitions ----


@router.patch("/{request_id}")
def edit_request(
    request_id: str,
    payload: dict[str, Any],
    user: Annotated[User, Depends(require_requester)],
    store: Annotated[RequestStore, Depends(get_request_store)],
) -> dict[str, Any]:
    """Edit a request the caller owns. Allowed only in `pending` or
    `needs_changes` state. Edit re-runs the review block."""
    req = _load_or_404(store, request_id)
    if not lifecycle.is_owner(req, user):
        raise HTTPException(status_code=403, detail="only the owner can edit this request")
    state = lifecycle.get_state(req)
    if state not in {"pending", "needs_changes"}:
        raise HTTPException(
            status_code=409,
            detail=f"cannot edit a request in state {state!r}",
        )

    # Apply the patch over the existing spec; the client cannot mutate
    # metadata.id, status, or apiVersion.
    spec = dict(req.get("spec") or {})
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")
    incoming_spec = payload.get("spec")
    if isinstance(incoming_spec, dict):
        spec.update(incoming_spec)
    req["spec"] = spec

    _validate_or_400(req)
    review_block = _build_review_block(req)
    try:
        lifecycle.apply_transition(req, action="edit", actor=user)
    except (IllegalTransition, NotAuthorized) as e:
        raise HTTPException(status_code=409, detail=str(e))
    store.put(request_id, req)
    return {"request": req, "review": review_block}


def _transition_endpoint(action: str, *, role: str):
    """Factory for the four approver-/owner-driven state transitions.

    The factory builds a route function that the router calls; FastAPI
    handles dependency injection per call.

    The `approve` action is special: after the pending→provisioning
    transition, we synchronously call the provisioning module to actually
    create the IAM role in the destination account. Success advances the
    state to `active` with the provisioned details + assume snippet.
    Failure stores the error and lands at `provisioning_failed`.
    """

    if role == "approver":
        actor_dep = Depends(require_approver)
    else:
        actor_dep = Depends(current_user)

    def endpoint(
        request_id: str,
        payload: dict[str, Any] | None = None,
        actor: User = actor_dep,
        store: RequestStore = Depends(get_request_store),
        accounts_store: Any = Depends(get_accounts_store),
    ) -> dict[str, Any]:
        req = _load_or_404(store, request_id)
        body = payload or {}
        reason = body.get("reason") or body.get("comment")
        extra = {}
        if action == "request_changes":
            suggestions = body.get("suggestions") or []
            if suggestions:
                extra["suggestions"] = list(suggestions)
        try:
            lifecycle.apply_transition(req, action=action, actor=actor, reason=reason, extra=extra)
        except IllegalTransition as e:
            raise HTTPException(status_code=409, detail=str(e))
        except NotAuthorized as e:
            raise HTTPException(status_code=403, detail=str(e))
        # Optional approver/requester comment as part of the action.
        if body.get("comment"):
            lifecycle.add_comment(req, author=actor, message=body["comment"])

        if action == "approve":
            try:
                _attempt_provisioning(req, accounts_store=accounts_store)
            except Exception as e:  # pragma: no cover — defense in depth
                # _attempt_provisioning is supposed to never raise. If it
                # does anyway, force the request to provisioning_failed
                # rather than leaving it stuck.
                _safe_mark_failed(req, f"provisioning crashed: {e}")

        # ALWAYS persist the post-transition state — even if something
        # above went sideways, the user should never see a request stuck
        # in 'provisioning' indefinitely.
        store.put(request_id, req)
        return {"request": req}

    endpoint.__name__ = f"transition_{action}"
    return endpoint


def _attempt_provisioning(
    req: dict[str, Any],
    *,
    accounts_store: Any,
) -> None:
    """Synchronously provision after approval, persist result/error.

    GUARANTEE: this function NEVER raises. The state of the request
    after this returns is one of:
      - 'active' (provisioning succeeded, provisioned details populated)
      - 'provisioning_failed' (with provisioning_error set in status)
      - unchanged (only if the request wasn't in 'provisioning' to begin
        with, which means apply_transition didn't move it — that's fine)

    The all-failures-must-land-somewhere guarantee is what keeps requests
    from getting stuck in 'provisioning' and forces the UI to surface
    the failure to the approver. Callers (the approve route) MUST be
    able to call store.put() after this returns and rely on the state
    being terminal-or-actionable.
    """
    import logging

    logger = logging.getLogger("iam_jit.provisioning")
    try:
        result = provision_mod.provision(req, accounts_store=accounts_store)
    except provision_mod.ProvisioningError as e:
        logger.warning("provisioning failed: %s", e)
        _safe_mark_failed(req, str(e))
        return
    except Exception as e:
        logger.exception("unexpected error during provisioning")
        _safe_mark_failed(req, f"unexpected error: {e}")
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
        }
    except Exception as e:
        logger.exception("post-provision result rendering failed")
        _safe_mark_failed(
            req,
            f"role created but result rendering failed: {e}. "
            "Check audit log; manual cleanup may be needed.",
        )
        return

    try:
        lifecycle.mark_provisioned(req, provisioned=provisioned)
    except Exception as e:
        logger.exception("mark_provisioned failed")
        _safe_mark_failed(req, f"role created but state transition failed: {e}")


def _safe_mark_failed(req: dict[str, Any], error: str) -> None:
    """Set state=provisioning_failed without ever raising.

    If the request isn't in 'provisioning' state (e.g., a bug elsewhere
    advanced it already), we can't transition — but we can still record
    the error in status.provisioning_error so the UI sees something."""
    import logging

    logger = logging.getLogger("iam_jit.provisioning")
    try:
        lifecycle.mark_provisioning_failed(req, error=error)
    except lifecycle.IllegalTransition:
        # Already moved past 'provisioning'. Record the error anyway.
        try:
            req.setdefault("status", {})["provisioning_error"] = error
        except Exception:
            logger.exception("failed to record provisioning error on request")
    except Exception:
        logger.exception("mark_provisioning_failed itself raised")
        try:
            req.setdefault("status", {})["provisioning_error"] = error
            req["status"]["state"] = "provisioning_failed"
        except Exception:
            pass


@router.post("/{request_id}/retry-provisioning")
def retry_provisioning(
    request_id: str,
    actor: Annotated[User, Depends(require_approver)],
    store: Annotated[RequestStore, Depends(get_request_store)],
    accounts_store: Annotated[Any, Depends(get_accounts_store)],
) -> dict[str, Any]:
    """Move a provisioning_failed request back to provisioning and try
    again. Useful when the failure was transient (account just got
    registered, AWS API hiccup) — the approver doesn't have to start
    a new request from scratch.
    """
    req = _load_or_404(store, request_id)
    try:
        lifecycle.apply_transition(
            req, action="retry", actor=actor, reason="re-running provisioning"
        )
    except IllegalTransition as e:
        raise HTTPException(status_code=409, detail=str(e))
    except NotAuthorized as e:
        raise HTTPException(status_code=403, detail=str(e))
    _attempt_provisioning(req, accounts_store=accounts_store)
    store.put(request_id, req)
    return {"request": req}


@router.post("/{request_id}/revoke")
def revoke_active_request(
    request_id: str,
    actor: Annotated[User, Depends(require_admin)],
    store: Annotated[RequestStore, Depends(get_request_store)],
    accounts_store: Annotated[Any, Depends(get_accounts_store)],
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Admin-only revoke of an active or recently-failed grant.

    Tears down the IAM role in the destination account and transitions
    the request to `revoked`. Idempotent at the AWS layer (already-gone
    role is fine), but the lifecycle transition itself only fires once
    — calling /revoke on an already-revoked request returns 409.

    Reason is required so the audit trail explains *why* a grant was
    pulled before its expiry. Without it, ops/compliance has no signal
    distinguishing a revoke for cause from a revoke by accident.
    """
    req = _load_or_404(store, request_id)
    body = payload or {}
    reason = (body.get("reason") or "").strip()
    if not reason or len(reason) < 4:
        raise HTTPException(
            status_code=400,
            detail="revoke requires a non-empty 'reason' (>=4 chars) for the audit trail",
        )

    state = lifecycle.get_state(req)
    if state not in {"active", "provisioning_failed"}:
        raise HTTPException(
            status_code=409,
            detail=f"cannot revoke from state {state!r}; only 'active' or 'provisioning_failed' grants can be revoked",
        )

    import logging

    logger = logging.getLogger("iam_jit.provisioning")
    try:
        result = provision_mod.revoke(req, accounts_store=accounts_store)
    except provision_mod.DestinationAccessDenied as e:
        logger.warning("revoke blocked by access denied: %s", e)
        raise HTTPException(
            status_code=502,
            detail={
                "error": "destination_access_denied",
                "operation": e.operation,
                "message": str(e),
            },
        )
    except provision_mod.ProvisioningError as e:
        logger.warning("revoke failed: %s", e)
        raise HTTPException(status_code=502, detail=f"revoke failed: {e}")
    except Exception as e:
        logger.exception("unexpected error during revoke")
        raise HTTPException(status_code=500, detail=f"unexpected error during revoke: {e}")

    revocation = {
        "role_arn": result.role_arn,
        "role_name": result.role_name,
        "account_id": result.account_id,
        "revoked_at": result.revoked_at,
        "revoked_by": actor.id,
        "reason": reason,
        "role_existed": result.role_existed,
        "inline_policies_deleted": list(result.inline_policies_deleted),
        "aws_cli_replay": list(result.aws_cli_replay),
    }
    try:
        lifecycle.mark_revoked(req, revoked_by=actor.id, revocation=revocation)
    except lifecycle.IllegalTransition as e:
        raise HTTPException(status_code=409, detail=str(e))
    store.put(request_id, req)
    return {"request": req, "revocation": revocation}


router.post("/{request_id}/approve")(_transition_endpoint("approve", role="approver"))
router.post("/{request_id}/reject")(_transition_endpoint("reject", role="approver"))
router.post("/{request_id}/request-changes")(
    _transition_endpoint("request_changes", role="approver")
)
router.post("/{request_id}/cancel")(_transition_endpoint("cancel", role="owner"))


# ---- Comments ----


@router.get("/{request_id}/assume")
def assume_instructions(
    request_id: str,
    user: Annotated[User, Depends(current_user)],
    store: Annotated[RequestStore, Depends(get_request_store)],
) -> dict[str, Any]:
    """Return the copy-paste assume-role snippet for a provisioned request.

    Returns 200 even when the request hasn't been provisioned yet — in that
    case the response carries `provisioned: false` plus the resolved
    assumer principal (or a hint that one is missing) so the agent can
    prompt the user before proceeding.
    """
    req = _load_or_404(store, request_id)
    if not lifecycle.can_view(req, user):
        raise HTTPException(status_code=403, detail="not authorized to view this request")
    provisioned = (req.get("status") or {}).get("provisioned")
    if provisioned and provisioned.get("assume_instructions"):
        return {
            "request_id": request_id,
            "provisioned": True,
            "assumer_principal_arn": provisioned.get("assumer_principal_arn"),
            "session_name": provisioned.get("session_name"),
            "role_arn": provisioned.get("role_arn"),
            "expires_at": provisioned.get("expires_at"),
            "external_id": provisioned.get("external_id"),
            "instructions": provisioned["assume_instructions"],
        }
    return {
        "request_id": request_id,
        "provisioned": False,
        "state": (req.get("status") or {}).get("state"),
        "assumer_principal_arn": assume_mod.resolve_assumer_principal(req),
        "session_name": assume_mod.resolve_session_name(req),
        "needs_assumer_principal": assume_mod.resolve_assumer_principal(req) is None,
    }


@router.get("/{request_id}/download", response_class=Response)
def download_request(
    request_id: str,
    user: Annotated[User, Depends(current_user)],
    store: Annotated[RequestStore, Depends(get_request_store)],
    fmt: Annotated[str, Query(alias="as", pattern="^(yaml|json)$")] = "yaml",
    mode: Annotated[str, Query(pattern="^(full|template)$")] = "template",
) -> Response:
    """Download a request as YAML or JSON.

    `mode=template` (default): just the parts useful for re-submission.
    `mode=full`: the entire stored record including status/history/review.

    Use this to archive what you submitted, or as a starting point for a
    similar future request — modify a field or two and POST it back to
    /api/v1/requests.
    """
    from fastapi.responses import Response as FastResponse

    req = _load_or_404(store, request_id)
    if not lifecycle.can_view(req, user):
        raise HTTPException(status_code=403, detail="not authorized to view this request")
    body_obj: dict[str, Any] = (
        lifecycle.to_template(req) if mode == "template" else req
    )
    if fmt == "json":
        # Convert ruamel TimeStamp / CommentedMap → plain types via default=str.
        text = json.dumps(body_obj, indent=2, default=str)
        media = "application/json"
    else:
        from ruamel.yaml import YAML

        ydump = YAML()
        ydump.indent(mapping=2, sequence=4, offset=2)
        ydump.preserve_quotes = True
        buf = io.StringIO()
        ydump.dump(body_obj, buf)
        text = buf.getvalue()
        media = "application/yaml"
    filename = f"iam-jit-{request_id}{'-template' if mode == 'template' else ''}.{fmt}"
    return FastResponse(
        content=text,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{request_id}/comments", status_code=201)
def post_comment(
    request_id: str,
    payload: dict[str, Any],
    user: Annotated[User, Depends(current_user)],
    store: Annotated[RequestStore, Depends(get_request_store)],
) -> dict[str, Any]:
    req = _load_or_404(store, request_id)
    if not lifecycle.can_view(req, user):
        raise HTTPException(status_code=403, detail="not authorized to comment on this request")
    message = (payload or {}).get("message")
    if not isinstance(message, str) or not message.strip():
        raise HTTPException(status_code=400, detail="message is required")
    # Cap comment length defensively. The schema doesn't enforce a max
    # because comments use additionalProperties=true, so we enforce
    # here. Cap of 4 KiB matches the description maxLength order of
    # magnitude — comments meant for review notes, not novellas.
    if len(message) > 4096:
        raise HTTPException(
            status_code=400,
            detail="comment exceeds maximum length (4096 chars)",
        )
    # Comments flow into the audit detail and into the approver's UI.
    # Run the same prompt-injection scan as submission text.
    refused = _scan_submission_for_injection(user, comment_message=message)
    if refused is not None:
        raise refused
    comment = lifecycle.add_comment(
        req,
        author=user,
        message=message.strip(),
        suggested_constraints=(payload or {}).get("suggested_constraints"),
    )
    store.put(request_id, req)
    return {"comment": comment}
