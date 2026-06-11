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

from .. import assume as assume_mod, audit as audit_mod, bans as bans_mod, lifecycle, prompt_injection, provision as provision_mod, review, schema
from .._auto_approve_helpers import (
    apply_mfa_and_self_approve_enforcement as _apply_mfa_and_self_approve_enforcement,
    attempt_provisioning as _attempt_provisioning_helper,
    safe_mark_failed as _safe_mark_failed_helper,
)
from .._outstanding_request_cap import check_outstanding_cap as _check_outstanding_cap
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


def _request_bouncer_session_id(req: dict[str, Any]) -> str:
    """#726 — the bouncer/agent session id this request belongs to.

    Optional `metadata.bouncer_session_id`. Absent (the common case
    for deployments that haven't wired the bouncer into iam-jit's
    presence channel) → empty string, which the presence gate treats
    as not-applicable (never blocks)."""
    md = req.get("metadata") or {}
    sid = md.get("bouncer_session_id")
    return str(sid) if sid else ""


def _apply_presence_gate(req: dict[str, Any], *, actor: User) -> None:
    """#726 / BUILD-5 — bouncer-presence verification at role-issuance.

    Evaluates whether the bouncer for this request's agent session is
    still present. On an off-the-leash gap: emits the OCSF presence-gap
    event + an iam-jit audit entry (neutral language, signal-not-proof),
    and — only when IAM_JIT_REQUIRE_BOUNCER_PRESENCE is enabled —
    refuses issuance with HTTP 409.

    Per [[safety-mode-lean-permissive]] the default is advisory: the
    signal is surfaced but issuance proceeds.
    """
    from .. import presence as presence_mod

    session_id = _request_bouncer_session_id(req)
    decision = presence_mod.presence_gate(session_id)
    # Two reasons the gate can refuse / want surfacing:
    #   1. an OFF_THE_LEASH gap (the original #726 signal), or
    #   2. (#55) a present-but-UNVERIFIED beat the enforce gate refuses
    #      to trust under the hardened posture (role-binding on).
    # Anything that is neither off-the-leash nor a refusal is a clean
    # allow and needs no audit/event.
    if not decision.verdict.is_off_the_leash and decision.allow:
        return
    # Off the leash or a refused unverified beat: surface the signal
    # regardless of enforce mode.
    verdict = decision.verdict
    # The OCSF presence-gap event only makes sense for a genuine gap.
    # A present-but-unverified refusal (#55) is a trust decision, not a
    # silence gap — use the decision reason for the audit summary so the
    # log isn't misleading.
    if verdict.is_off_the_leash:
        try:
            ocsf = presence_mod.make_off_the_leash_event(verdict)
        except Exception:  # pragma: no cover — never let alerting break issuance
            ocsf = {}
        summary = verdict.to_dict()["message"]
        kind = "bouncer.presence_gap"
    else:
        ocsf = {}
        summary = decision.reason
        kind = "bouncer.presence_unverified"
    try:
        audit_mod.emit(
            actor=getattr(actor, "email", "") or getattr(actor, "id", "") or "system",
            kind=kind,
            summary=summary,
            details={
                "request_id": (req.get("metadata") or {}).get("id") or "",
                "session_id": session_id,
                "enforced": decision.enforced,
                "issuance_allowed": decision.allow,
                "presence": verdict.to_dict(),
                "ocsf": ocsf,
                "signal_not_proof": True,
            },
        )
    except Exception:  # noqa: SD-1 — audit emit is best-effort; a logging-sink failure must never break role-issuance (fail-soft, matches the prompt-injection audit pattern above)
        pass
    if not decision.allow:
        raise HTTPException(status_code=409, detail=decision.reason)


# ---- Submission ----


def _generate_id() -> str:
    return secrets.token_urlsafe(8).lower().replace("_", "").replace("-", "")[:12] or secrets.token_urlsafe(8)


# #601 (2026-05-25): the local `_apply_mfa_and_self_approve_enforcement`
# was extracted to `iam_jit._auto_approve_helpers` (leaf module) so this
# module and `auto_approve_evaluator.py` share one source of truth. The
# module-level alias imported at the top of this file preserves the name
# `_apply_mfa_and_self_approve_enforcement` for downstream test imports
# (e.g., `tests/test_mfa_self_approve_enforcement.py`).


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
        except Exception as _sar_exc:
            # MRR-2 F7 (HIGH from
            # docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md): the bare
            # ``except: pass`` made the self-approve gate silently
            # go inert — the response carried
            # ``self_approve_evaluated: False`` with no diagnostic,
            # so an operator couldn't tell "this user isn't eligible"
            # from "the evaluator crashed". Emit a structured event
            # to /healthz + posture AND surface a reason in the
            # audit dict so the response is honest about WHY the
            # eval didn't run.
            from ..degraded_capability import (
                REASON_EVAL_RAISED,
                emit as _deg_emit,
            )
            _deg_emit(
                feature="self_approve.eval",
                reason=REASON_EVAL_RAISED,
                hint=(
                    "the self-approve evaluator raised — the request "
                    "fell back to ``self_approve_evaluated=False`` "
                    "and will follow the normal approval flow. "
                    "Inspect the server log traceback."
                ),
                extra={"degraded_exc_type": type(_sar_exc).__name__},
            )
            _preview_sar_audit = {
                "self_approve_evaluated": False,
                "self_approve_eval_error": "eval_raised",
            }

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

    # BB3-09 fix: HTML-escape the schema-error strings before returning. They
    # can echo the user's raw input (jsonschema includes offending values), and
    # while the JSON Content-Type stops a browser rendering it, a downstream
    # markdown log viewer / Slack relay / error-tracking SaaS might. Escaping
    # <,>,& neutralizes the reflected-XSS class without losing the error text.
    import html as _html

    return {
        "schema_errors": [_html.escape(str(e)) for e in schema_errors],
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

    # #613 — per-user outstanding-request cap. Refuse BEFORE any
    # expensive work (injection scan, schema validation, scorer,
    # compatibility gate) so a runaway agent loop cannot waste cycles
    # AND cannot fill the approver queue. Per
    # [[cross-product-agent-parity]]: the same shared helper runs in
    # routes/web.py new_paste_submit so web + API paths see identical
    # cap behavior. Per [[ibounce-honest-positioning]]: 429 body
    # names the cap, the count, the user, the cap source, a recovery
    # hint, and the list of currently-blocking requests. Per
    # [[ambient-value-prop-and-friction-framing]]: the cap-fire emits
    # an audit event so the operator sees "your iam-jit caught a
    # runaway agent" as a positive signal.
    _cap_result = _check_outstanding_cap(user, store)
    if _cap_result.would_exceed:
        raise HTTPException(
            status_code=429,
            detail=_cap_result.to_response_body(),
            headers={"Retry-After": "60"},
        )

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

    # #166 Slice 3: compatibility-framework gate. When the requester
    # includes a metadata.compatibility block, run the same check
    # MCP submit_policy already enforces (per WB24 closure) and refuse
    # non-PROCEED verdicts BEFORE persisting the request — so an
    # admin can't approve a request iam-jit will never be able to
    # fulfill, and the requester sees the next-action hint
    # immediately. When the block is omitted, behavior is unchanged
    # (legacy submissions keep working).
    _compat_block = metadata.get("compatibility")
    if isinstance(_compat_block, dict):
        from ..compatibility import (
            Compatibility,
            CompatibilityIntent,
            WorkloadType,
        )

        _workload_raw = _compat_block.get("workload")
        if not isinstance(_workload_raw, str) or not _workload_raw.strip():
            raise HTTPException(
                status_code=400,
                detail="metadata.compatibility.workload is required and must be a string",
            )
        try:
            _workload_enum = WorkloadType(_workload_raw.strip())
        except ValueError:
            _valid = ", ".join(w.value for w in WorkloadType)
            raise HTTPException(
                status_code=400,
                detail=(
                    f"unknown workload {_workload_raw!r}; must be one of: {_valid}"
                ),
            )

        # WB29 HIGH-29-01 closure: if the caller didn't pin a specific
        # target_account_id, check EVERY account in spec.accounts and
        # refuse on the most-restrictive verdict (same pattern as
        # WB10-03 safety-mode resolution). Otherwise an admin can
        # set "for account X, use_existing" and the gate would sail
        # through on account Y while still ALSO issuing for X.
        _explicit_target_account_id = _compat_block.get("target_account_id")
        if _explicit_target_account_id is not None:
            _accounts_to_check = [_explicit_target_account_id]
        else:
            _spec_for_compat = req.get("spec") or {}
            _accounts_for_compat = _spec_for_compat.get("accounts") or []
            _accounts_to_check = [
                a.get("account_id")
                for a in _accounts_for_compat
                if isinstance(a, dict) and a.get("account_id")
            ]
            if not _accounts_to_check:
                _accounts_to_check = [None]  # check without account scope

        # WB29 MED-29-02 closure: lowercase + strip target_services
        # so HTTP gate matches the MCP path's normalization at
        # mcp_server.py:_parse_compatibility_intent.
        _target_services_raw = _compat_block.get("target_services")
        if _target_services_raw is None:
            _target_services = ()
        elif isinstance(_target_services_raw, list):
            _normalized: list[str] = []
            for _svc in _target_services_raw:
                if not isinstance(_svc, str):
                    raise HTTPException(
                        status_code=400,
                        detail="metadata.compatibility.target_services items must be strings",
                    )
                _normalized.append(_svc.strip().lower())
            _target_services = tuple(_normalized)
        else:
            raise HTTPException(
                status_code=400,
                detail="metadata.compatibility.target_services must be a list if provided",
            )

        from ..compatibility import (
            check_compatibility,
            default_audit_sink,
        )
        try:
            from ..compatibility_allowlist import build_default_store
            _compat_allowlist = build_default_store()
        except Exception:
            _compat_allowlist = None
        # WB29 MED-29-01 closure: prefix actor with surface so
        # post-hoc audit-log review can distinguish HTTP submissions
        # from MCP / CLI calls under the same email.
        _compat_email = (
            user.id.removeprefix("email:") if user.id.startswith("email:") else user.id
        )
        _compat_actor = f"http:{_compat_email}"
        # WB29 HIGH-29-02 closure: pass audit_sink so refusal events
        # land in the audit chain — was missing on HTTP + CLI
        # surfaces, regressing WB24 MED-24-01 closure.
        _compat_sink = default_audit_sink()

        # Refuse on the FIRST non-PROCEED verdict; iterate so a
        # multi-account refusal isn't masked by a permissive first
        # account.
        for _acct in _accounts_to_check:
            _compat_intent = CompatibilityIntent(
                workload=_workload_enum,
                target_account_id=_acct,
                target_services=_target_services,
                description=_compat_block.get("description")
                if isinstance(_compat_block.get("description"), str) else None,
                existing_role_hint=_compat_block.get("existing_role_hint")
                if isinstance(_compat_block.get("existing_role_hint"), str) else None,
            )
            _compat_result = check_compatibility(
                _compat_intent,
                allowlist=_compat_allowlist,
                audit_sink=_compat_sink,
                actor=_compat_actor,
            )
            if _compat_result.verdict in (
                Compatibility.USE_EXISTING,
                Compatibility.USE_BOUNCER,
                Compatibility.CANNOT_HELP,
            ):
                # 422 Unprocessable Entity — request is syntactically
                # valid but iam-jit can't act on it.
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": (
                            f"iam-jit cannot issue a role for workload "
                            f"{_workload_enum.value!r}"
                            + (f" on account {_acct}" if _acct else "")
                            + f": {_compat_result.reasoning}"
                        ),
                        "verdict": _compat_result.verdict.value,
                        "next_action_hint": _compat_result.next_action_hint,
                        "matched_pattern": _compat_result.matched_pattern,
                        "bouncer_recommended": _compat_result.bouncer_recommended,
                        "account_id": _acct,
                    },
                )

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
    # narrow.detect_broadness removed in Stage 4 of [[no-nl-synthesis]];
    # narrowing-questions surface deleted along with suggest/refine.
    # Agents now iterate via score_iam_policy's per-factor breakdown.
    _spec_for_policy = req.get("spec")
    policy = _spec_for_policy.get("policy") if isinstance(_spec_for_policy, dict) else None
    if policy:
        questions = []

    # Auto-approve gate. Composes four checks: feature enabled,
    # score < threshold, no blocklisted service/account, user under
    # per-hour quota. Any failure leaves the request in pending for
    # human review. Audit captures the gate that fired so a reviewer
    # can answer "why didn't this auto-approve?" in one click.
    #
    # #598 — both API and web paste-form submit paths flow through
    # the SAME shared helper per [[cross-product-agent-parity]]. The
    # helper mutates `req["status"]` in place when the gate fires
    # (state→provisioning + history entry + sync provisioning) and
    # returns the structured decision + MFA block response for the
    # API to splat into its response body.
    from .. import auto_approve_evaluator
    _eval_result = auto_approve_evaluator.evaluate_and_apply_for_new_request(
        request=req,
        user=user,
        accounts_store=accounts_store,
        cookie_value=(
            request.cookies.get("iam_jit_session_mfa")
            if hasattr(request, "cookies") else None
        ),
        api_token_record=getattr(
            getattr(request, "state", None), "api_token_record", None,
        ),
    )
    auto_decision = _eval_result["auto_decision"]
    _mfa_block_response = _eval_result["mfa_block_response"]

    store.put(metadata["id"], req)

    # Fire-and-forget approver-notification dispatch when the request
    # lands in pending state (i.e., did NOT auto-approve). The helper
    # logs + swallows channel failures — a Slack outage must not
    # block iam-jit submissions. #596: the web paste-form submit path
    # in routes/web.py calls the SAME helper to guarantee parity.
    if req.get("status", {}).get("state") == "pending":
        from .. import approval_notifier
        approval_notifier.notify_approvers_for_new_request(req)

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
            # #726 / BUILD-5 — "off the leash" presence gate. Before we
            # issue a role, verify the bouncer for this request's agent
            # session is still checking in. Advisory by default (surface
            # the signal, don't block); refuses issuance only when the
            # operator opted into IAM_JIT_REQUIRE_BOUNCER_PRESENCE.
            _apply_presence_gate(req, actor=actor)
            try:
                _attempt_provisioning_helper(
                    req,
                    accounts_store=accounts_store,
                    provision_mod=provision_mod,
                    assume_mod=assume_mod,
                    lifecycle=lifecycle,
                )
            except Exception as e:  # pragma: no cover — defense in depth
                # _attempt_provisioning is supposed to never raise. If it
                # does anyway, force the request to provisioning_failed
                # rather than leaving it stuck.
                _safe_mark_failed_helper(
                    req,
                    f"provisioning crashed: {e}",
                    lifecycle=lifecycle,
                )

        # ALWAYS persist the post-transition state — even if something
        # above went sideways, the user should never see a request stuck
        # in 'provisioning' indefinitely.
        store.put(request_id, req)
        return {"request": req}

    endpoint.__name__ = f"transition_{action}"
    return endpoint


# #601 (2026-05-25): the local `_attempt_provisioning` and
# `_safe_mark_failed` were extracted to `iam_jit._auto_approve_helpers`
# (leaf module). Both call sites in this file now import them with the
# `_helper` suffix to avoid name shadowing during the migration. The
# leaf helpers also incorporate the #599 last-resort logging
# improvement (the pre-extraction routes/* version used silent `pass`
# in the last-resort manual-mutation fallback; the leaf version logs
# loudly so a fully-broken request dict leaves operator trace).


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
    _attempt_provisioning_helper(
        req,
        accounts_store=accounts_store,
        provision_mod=provision_mod,
        assume_mod=assume_mod,
        lifecycle=lifecycle,
    )
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

    # GitHubTokenRequest: revoke the scoped installation token (DELETE
    # /installation/token) instead of tearing down an IAM role. Same /revoke
    # endpoint, same lifecycle transition.
    if (req.get("kind") or "RoleRequest") == "GitHubTokenRequest":
        return _revoke_github_request(req, request_id, store=store, actor=actor, reason=reason)

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
        # MRR-2 F4 (HIGH from docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md):
        # the previous shape leaked raw exception text into the HTTP
        # response body (info-disclosure for the work-AWS deploy where
        # compliance teams + proxy logs capture response bodies). The
        # ProvisioningError carries useful operator context (op + msg)
        # but it goes via the structured envelope now; the bare ``e``
        # stays in the server log only.
        from ..errors import log_and_make
        logger.warning("revoke failed via ProvisioningError: %s", e)
        payload = log_and_make(
            logger=logger,
            error_code="REVOKE_PROVISIONING_FAILED",
            message=(
                "revoke failed at the IAM provisioning layer; the role "
                "may still exist in the destination account."
            ),
            recommended_action=(
                "Re-attempt the revoke once the provisioning condition "
                "clears (e.g. AWS API throttling); if it still fails, "
                "contact your iam-jit operator with the error_id so "
                "they can correlate the server-side traceback."
            ),
            log_message="revoke 502 — ProvisioningError",
            context={"phase": "provisioning"},
            exc_info=False,
        )
        raise HTTPException(status_code=502, detail=payload)
    except Exception:
        # MRR-2 F4 — same structured-envelope shape for the 500 catch-
        # all. The inner exception text is logged server-side
        # (logger.exception attaches the traceback via exc_info=True
        # by default — log_and_make=True here) and correlated by
        # error_id; it is NEVER returned to the client.
        from ..errors import log_and_make
        payload = log_and_make(
            logger=logger,
            error_code="REVOKE_INTERNAL_ERROR",
            message="unexpected error during revoke",
            recommended_action=(
                "Re-attempt the revoke; if it still fails, contact "
                "your iam-jit operator with the error_id so they can "
                "correlate the server-side traceback."
            ),
            log_message="revoke 500 — unhandled exception",
            context={"phase": "internal"},
        )
        raise HTTPException(status_code=500, detail=payload)

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


def _revoke_github_request(
    req: dict[str, Any],
    request_id: str,
    *,
    store: RequestStore,
    actor: User,
    reason: str,
) -> dict[str, Any]:
    """Revoke an active GitHubTokenRequest: DELETE the installation token (if
    still held) and transition to revoked. Idempotent at the GitHub layer
    (an already-expired token is treated as revoked)."""
    import logging

    from .. import github_scope
    from ..github_installations import default_registry_path

    logger = logging.getLogger("iam_jit.provisioning")
    status = req.get("status") or {}
    gh_prov = (status.get("provisioned") or {}).get("github") or {}
    token = status.get("_secret_github_token")
    org = gh_prov.get("org", "")
    if token and org:
        try:
            path = getattr(store, "github_installations_path", None) or default_registry_path()
            github_scope.revoke_github_token(installations_path=path, org=org, token=token)
        except Exception as e:  # noqa: BLE001 — idempotent best-effort
            logger.warning("github token revoke best-effort failed (continuing): %s", e)

    revocation = {
        "github": {
            "org": org,
            "repositories": list(gh_prov.get("repositories") or []),
            "access": gh_prov.get("access"),
        },
        "revoked_at": _now_iso_z(),
        "revoked_by": actor.id,
        "reason": reason,
    }
    # Clear the secret + flip token_active before the transition.
    req.setdefault("status", {}).pop("_secret_github_token", None)
    if gh_prov:
        gh_prov["token_active"] = False
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
