"""Admin-only endpoints for ops/audit:

  POST /api/v1/admin/rediscover         Reconcile request store with AWS state
  GET  /api/v1/admin/provisioned        List currently-active iam-jit grants
  POST /api/v1/admin/force-delete-role  Manually delete a stale iam-jit role

Rediscover and provisioned are read-only. Force-delete is the only
mutating endpoint here — it goes through a strict name-AND-tag safety
gate so iam-jit can never delete a role it didn't create. The audit
log records the actor, role, and reason.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import (
    audit as audit_mod,
    bans as bans_mod,
    calibration as calibration_mod,
    cidr_store,
    log_retention as log_retention_mod,
    rediscover,
    security_posture,
    settings_store as settings_mod,
    token_sweep,
)
from ..settings_store import Settings
from ..api_tokens_store import APITokenStore
from ..accounts_store import AccountNotFound
from ..middleware import (
    get_accounts_store,
    get_api_tokens_store,
    get_request_store,
    get_user_store,
    require_admin,
)
from ..store import RequestStore
from ..users_store import User, UserNotFound, UserStore


router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.post("/rediscover")
def rediscover_endpoint(
    actor: Annotated[User, Depends(require_admin)],
    accounts_store: Annotated[Any, Depends(get_accounts_store)],
    request_store: Annotated[RequestStore, Depends(get_request_store)],
    deployment_filter: Annotated[
        str | None,
        Query(
            description=(
                "Only count roles whose `iam-jit-deployment` tag matches this "
                "value. Defaults to no filter (all iam-jit roles regardless "
                "of source deployment)."
            )
        ),
    ] = None,
) -> dict[str, Any]:
    """Sweep every registered destination account, list the iam-jit-managed
    roles AWS actually holds, and reconcile against the request store.

    Returns three reconciliation buckets:
      - **known**: AWS role + matching active request — steady state.
      - **orphans**: AWS role with NO matching request — disaster
        recovery hint or different-deployment overlap.
      - **zombies**: request claims active+provisioned but AWS shows
        no role — manual deletion / failed sweep.

    Plus per-account success/failure breakdown so the operator knows
    which accounts iam-jit could even reach.
    """
    report = rediscover.reconcile(
        accounts_store=accounts_store,
        request_store=request_store,
        deployment_filter=deployment_filter,
    )
    return _serialize_report(report)


@router.get("/provisioned")
def list_provisioned_endpoint(
    actor: Annotated[User, Depends(require_admin)],
    request_store: Annotated[RequestStore, Depends(get_request_store)],
    include_revoked: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    """List every request that has a provisioned grant on record.

    Read against the local store — fast, no AWS calls. Use /rediscover
    when you need the AWS-side ground truth instead.
    """
    rows: list[dict[str, Any]] = []
    for rid in request_store.list_ids():
        try:
            req = request_store.get(rid)
        except Exception:
            continue
        provisioned = (req.get("status") or {}).get("provisioned") or {}
        if not provisioned.get("role_arn"):
            continue
        state = (req.get("status") or {}).get("state") or ""
        if state == "revoked" and not include_revoked:
            continue
        metadata = req.get("metadata") or {}
        rows.append(
            {
                "request_id": rid,
                "name": metadata.get("name") or "",
                "owner": (req.get("status") or {}).get("owner") or "",
                "role_arn": provisioned.get("role_arn"),
                "role_name": provisioned.get("role_name"),
                "account_id": provisioned.get("account_id"),
                "expires_at": provisioned.get("expires_at"),
                "assumer_principal_arn": provisioned.get("assumer_principal_arn"),
                "state": state,
            }
        )
    rows.sort(key=lambda r: r.get("expires_at") or "")
    return {"count": len(rows), "provisioned": rows}


@router.post("/force-delete-role")
def force_delete_role_endpoint(
    actor: Annotated[User, Depends(require_admin)],
    accounts_store: Annotated[Any, Depends(get_accounts_store)],
    request_store: Annotated[RequestStore, Depends(get_request_store)],
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Manually delete a stale iam-jit role when the periodic cleanup
    sweep is failing.

    Body:
      {
        "account_id": "...",
        "role_name": "iam-jit-grant-...",
        "role_arn":  "arn:aws:iam::...:role/iam-jit/iam-jit-grant-...",
        "tags":      {"managed-by": "iam-jit", ...},
        "reason":    "expiry sweep failing for 3 days"
      }

    Refuses to act on any role whose name OR tag does not identify it
    as iam-jit-managed — both checks must pass. This is intentional:
    it means iam-jit has zero capability to delete IAM roles outside
    its own namespace, even if an admin tries to point it at one.
    """
    role_arn = (payload.get("role_arn") or "").strip()
    role_name = (payload.get("role_name") or "").strip()
    account_id = (payload.get("account_id") or "").strip()
    tags = payload.get("tags") or {}
    reason = (payload.get("reason") or "").strip()

    if not reason or len(reason) < 4:
        raise HTTPException(
            status_code=400,
            detail="force-delete requires a non-empty 'reason' for the audit trail",
        )

    try:
        account = accounts_store.get(account_id)
    except (AccountNotFound, KeyError) as e:
        raise HTTPException(status_code=404, detail=f"account not registered: {e}")

    try:
        result = rediscover.force_delete_stale_role(
            account=account,
            role_name=role_name,
            role_arn=role_arn,
            tags=tags,
        )
    except rediscover.CleanupSafetyError as e:
        # Refused at the safety gate — never the caller's mistake to
        # absorb silently. 422 with a precise message.
        raise HTTPException(status_code=422, detail=str(e))
    except rediscover.DestinationAccessDenied as e:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "destination_access_denied",
                "operation": e.operation,
                "message": str(e),
            },
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"force-delete failed: {e}")

    try:
        audit_mod.emit(
            actor=actor.id,
            kind="role.force_delete",
            summary=f"force-delete {role_name} in {account_id}",
            details={
                "role_arn": role_arn,
                "role_name": role_name,
                "account_id": account_id,
                "reason": reason,
                "deleted": result.get("deleted"),
                "inline_deleted": result.get("inline_deleted"),
            },
        )
    except Exception:
        pass

    return {"result": result, "actor": actor.id, "reason": reason}


@router.post("/sweep-inactive-tokens")
def sweep_inactive_tokens_endpoint(
    actor: Annotated[User, Depends(require_admin)],
    tokens_store: Annotated[APITokenStore | None, Depends(get_api_tokens_store)],
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Auto-revoke API tokens unused for the configured inactivity window
    (default 180 days = ~6 months).

    Body:
      {
        "dry_run": false,         // optional, default false
        "inactivity_days": 180    // optional, default 180
      }

    The same operation is meant to run on a daily schedule (the SAM
    template's scheduled-expiry Lambda calls into this code path). This
    endpoint exists so an admin can verify what *would* happen
    (dry_run=true) and force a one-off sweep when needed.
    """
    if tokens_store is None:
        raise HTTPException(
            status_code=500, detail="api_tokens_store is not configured"
        )
    body = payload or {}
    dry_run = bool(body.get("dry_run", False))
    days_raw = body.get("inactivity_days", token_sweep.DEFAULT_INACTIVITY_DAYS)
    try:
        inactivity_days = int(days_raw)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="inactivity_days must be an integer",
        )
    if inactivity_days < 1 or inactivity_days > 3650:
        raise HTTPException(
            status_code=400,
            detail="inactivity_days must be between 1 and 3650",
        )

    result = token_sweep.sweep_inactive_tokens(
        tokens_store=tokens_store,
        inactivity_days=inactivity_days,
        dry_run=dry_run,
    )
    if not dry_run and result.revoked:
        try:
            audit_mod.emit(
                actor=actor.id,
                kind="security.tokens_swept",
                summary=(
                    f"swept {len(result.revoked)} token(s) inactive for "
                    f"≥{inactivity_days}d"
                ),
                details={
                    "revoked_count": len(result.revoked),
                    "inactivity_days": inactivity_days,
                    "users": sorted({s.user_id for s in result.revoked}),
                },
            )
        except Exception:
            pass
    return {
        "dry_run": result.dry_run,
        "inactivity_days": result.inactivity_days,
        "cutoff_epoch": result.cutoff_epoch,
        "scanned": result.scanned,
        "revoked_count": len(result.revoked),
        "skipped_count": len(result.skipped),
        "revoked": [
            {
                "token_hash_prefix": s.token_hash[:8] + "...",
                "user_id": s.user_id,
                "label": s.label,
                "last_activity_at": s.last_activity_at,
                "days_inactive": s.days_inactive,
            }
            for s in result.revoked
        ],
    }


@router.get("/network/cidrs")
def list_cidrs(
    actor: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Return the current runtime CIDR allowlist."""
    entries = cidr_store.get_default_store().list()
    return {
        "count": len(entries),
        "cidrs": [
            {
                "cidr": e.cidr,
                "note": e.note,
                "added_by": e.added_by,
                "added_at": e.added_at,
            }
            for e in entries
        ],
    }


@router.post("/network/cidrs", status_code=201)
def add_cidr(
    actor: Annotated[User, Depends(require_admin)],
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Add a CIDR / IP to the runtime allowlist.

    Body:
      { "cidr": "203.0.113.0/24", "note": "office WAN" }

    Bare IPs auto-promote to /32 or /128. Existing entry with the
    same CIDR is replaced (note/added_by updated). On the next
    request the new entry is enforced — no redeploy needed."""
    import time

    raw = (payload or {}).get("cidr") or ""
    note = (payload or {}).get("note") or ""
    normalized = cidr_store.normalize_cidr(raw)
    if not normalized:
        raise HTTPException(
            status_code=400,
            detail=f"invalid CIDR or IP: {raw!r}",
        )
    if not isinstance(note, str) or len(note) > 200:
        raise HTTPException(
            status_code=400,
            detail="note must be a string ≤200 chars",
        )
    entry = cidr_store.CIDREntry(
        cidr=normalized,
        note=note.strip(),
        added_by=actor.id,
        added_at=int(time.time()),
    )
    cidr_store.get_default_store().add(entry)
    try:
        audit_mod.emit(
            actor=actor.id,
            kind="security.cidr_added",
            summary=f"added {normalized} to network allowlist",
            details={"cidr": normalized, "note": entry.note},
        )
    except Exception:
        pass
    return {"cidr": entry.cidr, "note": entry.note, "added_by": entry.added_by}


@router.delete("/network/cidrs/{cidr:path}")
def remove_cidr(
    cidr: str,
    actor: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Remove a CIDR from the runtime allowlist.

    Refuses to remove the LAST entry — that would silently turn off
    all enforcement and lock the operator into a false sense of
    security. Use POST /api/v1/admin/network/cidrs/clear (which we
    don't expose) only by clearing entries one at a time.
    """
    store = cidr_store.get_default_store()
    entries = store.list()
    if len(entries) <= 1 and any(e.cidr == (cidr_store.normalize_cidr(cidr) or "") for e in entries):
        raise HTTPException(
            status_code=409,
            detail=(
                "refusing to remove the only remaining CIDR — that would "
                "disable runtime enforcement. Add a replacement first, "
                "then remove this one."
            ),
        )
    removed = store.remove(cidr)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"CIDR {cidr!r} is not in the allowlist",
        )
    try:
        audit_mod.emit(
            actor=actor.id,
            kind="security.cidr_removed",
            summary=f"removed {cidr} from network allowlist",
            details={"cidr": cidr},
        )
    except Exception:
        pass
    return {"removed": True, "cidr": cidr}


@router.get("/bans")
def list_bans(
    actor: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Show every currently-banned user.

    The middleware-level ban check is what actually keeps a banned
    user out of the system; this endpoint exists so an admin can
    audit who's banned and unban accidental hits.
    """
    store = bans_mod.get_default_store()
    return {
        "count": len(store.list_all()),
        "bans": [
            {
                "user_id": b.user_id,
                "banned_at": b.banned_at,
                "reasons": list(b.reasons),
                "snippets": list(b.snippets),
                "confidence": b.confidence,
                "actor": b.actor,
                "notes": b.notes,
            }
            for b in store.list_all()
        ],
    }


@router.post("/users/{user_id:path}/revoke-tokens")
def revoke_user_tokens(
    user_id: str,
    actor: Annotated[User, Depends(require_admin)],
    tokens_store: Annotated[APITokenStore | None, Depends(get_api_tokens_store)],
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Revoke every API token a user holds.

    Used when an admin disables a user, bans someone, or downgrades
    their role and wants to make sure no surviving bearer token can
    keep accessing the system. Banning alone already blocks tokens
    via the middleware ban-check, but explicit revocation makes the
    state visible in the tokens table — important if you later
    unban the user (their old tokens would otherwise come back to
    life)."""
    body = payload or {}
    reason = (body.get("reason") or "").strip()
    if not reason or len(reason) < 4:
        raise HTTPException(
            status_code=400,
            detail="revoke-tokens requires a non-empty 'reason' for the audit trail",
        )
    if user_id == actor.id:
        # Admin can't bulk-revoke their own tokens via this endpoint —
        # they'd lock themselves out of any session they're using
        # right now. Use DELETE /api/v1/tokens/{hash} for self-revoke
        # of specific tokens.
        raise HTTPException(
            status_code=403,
            detail="use DELETE /api/v1/tokens/{hash} to revoke your own tokens",
        )
    if tokens_store is None:
        raise HTTPException(
            status_code=500, detail="api_tokens_store is not configured"
        )

    revoked: list[str] = []
    for record in tokens_store.list_for_user(user_id):
        try:
            tokens_store.delete(record.token_hash)
            revoked.append(record.token_hash[:8] + "...")
        except Exception:
            import logging

            logging.getLogger("iam_jit.tokens").exception(
                "delete token %s for user %s failed", record.token_hash, user_id
            )
    try:
        audit_mod.emit(
            actor=actor.id,
            kind="security.tokens_revoked",
            summary=f"revoked {len(revoked)} tokens for {user_id}",
            details={"user_id": user_id, "count": len(revoked), "reason": reason},
        )
    except Exception:
        pass
    return {
        "user_id": user_id,
        "revoked_count": len(revoked),
        "revoked_token_prefixes": revoked,
        "by": actor.id,
        "reason": reason,
    }


@router.post("/bans/{user_id:path}/unban")
def unban_user(
    user_id: str,
    actor: Annotated[User, Depends(require_admin)],
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Lift a ban. Admin-only, but explicitly refuses self-unban —
    if an admin's session was abused to inject (which the system
    refused to ban anyway), separately, an admin who somehow ends up
    banned must be unbanned by a *different* admin. This forces a
    second-pair-of-eyes step for any reinstatement.

    The path uses `:path` so user IDs containing `:` (e.g.
    `email:dev@example.com`) survive routing as-is.
    """
    if user_id == actor.id:
        raise HTTPException(
            status_code=403,
            detail=(
                "you cannot unban yourself; another admin must lift this "
                "ban so a second pair of eyes is involved"
            ),
        )

    body = payload or {}
    reason = (body.get("reason") or "").strip()
    if not reason or len(reason) < 4:
        raise HTTPException(
            status_code=400,
            detail="unban requires a non-empty 'reason' for the audit trail",
        )

    store = bans_mod.get_default_store()
    if not store.is_banned(user_id):
        raise HTTPException(status_code=404, detail=f"user {user_id} is not banned")

    store.remove(user_id)
    try:
        audit_mod.emit(
            actor=actor.id,
            kind="security.unban",
            summary=f"unbanned {user_id}",
            details={"user_id": user_id, "reason": reason},
        )
    except Exception:
        pass
    return {"unbanned": user_id, "by": actor.id, "reason": reason}


def _serialize_report(report: rediscover.ReconciliationReport) -> dict[str, Any]:
    return {
        "generated_at": report.generated_at,
        "accounts": [
            {
                "account_id": a.account_id,
                "alias": a.alias,
                "success": a.success,
                "error": a.error,
                "role_count": len(a.roles),
            }
            for a in report.accounts
        ],
        "known": list(report.known),
        "stale": list(report.stale),
        "orphans": list(report.orphans),
        "zombies": list(report.zombies),
        "errors": list(report.errors),
        "inaccessible_accounts": list(report.inaccessible_accounts),
        "summary": {
            "accounts_scanned": len(report.accounts),
            "accounts_failed": sum(1 for a in report.accounts if not a.success),
            "known": len(report.known),
            "stale": len(report.stale),
            "orphans": len(report.orphans),
            "zombies": len(report.zombies),
            "incomplete": bool(report.errors),
            "incomplete_reason": (
                "one or more destination accounts could not be enumerated; "
                "buckets above are partial — re-run after access is restored"
                if report.errors
                else ""
            ),
        },
    }


# ---- Security posture + dismissable warnings ----


@router.get("/security-posture")
def get_security_posture(
    actor: Annotated[User, Depends(require_admin)],
    user_store: Annotated[UserStore, Depends(get_user_store)],
) -> dict[str, Any]:
    """Posture summary with per-admin dismissal applied.

    Filters out warnings this admin has dismissed (via
    POST /api/v1/admin/dismiss-warning). The unfiltered posture is
    still on /healthz for agents — dismissal is a UI convenience for
    the admin reviewing the same warning every day, not a way to
    hide it from automation."""
    posture = security_posture.compute()
    # Read the latest user record (the actor came from auth middleware
    # which may have a stale copy if dismissals raced; refetch to be
    # safe).
    try:
        fresh = user_store.get(actor.id)
        notes = fresh.notes
    except UserNotFound:
        notes = actor.notes
    posture["issues_undismissed"] = [
        i for i in posture["issues"]
        if not security_posture.warning_dismissed_by(notes, i["id"])
    ]
    return posture


@router.post("/dismiss-warning")
def dismiss_warning(
    payload: dict[str, Any],
    actor: Annotated[User, Depends(require_admin)],
    user_store: Annotated[UserStore, Depends(get_user_store)],
) -> dict[str, Any]:
    """Mark a security-posture warning as dismissed for this admin.

    Per-admin dismissal — other admins still see the warning.
    Dismissals are stored as `dismissed_warning:<id>=<iso-ts>` lines
    appended to the user's `notes` field; re-dismissing the same id
    re-stamps but doesn't duplicate.

    The dismissal does NOT change the underlying posture
    (`/healthz` still surfaces the issue to agents); it only hides
    the banner in this admin's UI."""
    import dataclasses
    import datetime as _dt

    warning_id = (payload or {}).get("warning_id")
    if not isinstance(warning_id, str) or not warning_id.strip():
        raise HTTPException(status_code=400, detail="warning_id is required")
    warning_id = warning_id.strip()

    # Validate the warning_id actually corresponds to a current
    # posture issue. Prevents storing arbitrary marker strings via
    # this endpoint.
    posture = security_posture.compute()
    valid_ids = {i["id"] for i in posture["issues"]}
    if warning_id not in valid_ids:
        raise HTTPException(
            status_code=400,
            detail=(
                f"unknown warning_id={warning_id!r}; current posture "
                f"has: {sorted(valid_ids)}"
            ),
        )

    fresh = user_store.get(actor.id)
    when = _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    updated_notes = security_posture.append_dismissal(
        fresh.notes, warning_id, when
    )
    user_store.put(dataclasses.replace(fresh, notes=updated_notes))

    try:
        audit_mod.emit(
            actor=actor.id,
            kind="admin.dismiss_warning",
            summary=f"{actor.id} dismissed security warning {warning_id}",
            details={"warning_id": warning_id, "at": when},
        )
    except Exception:
        pass

    return {"dismissed": True, "warning_id": warning_id, "at": when}


# ---- Auto-approve settings ----


@router.get("/auto-approve/settings")
def get_auto_approve_settings(
    _: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Return the current auto-approve configuration.

    Auto-approve is OFF by default (auto_approve_risk_below=None).
    To enable, PATCH the settings with a numeric threshold (1-10).
    Recommended starting value: 3, per the calibration table in
    docs/USE-CASES.md.
    """
    s = settings_mod.get_default_store().get()
    floors = settings_mod.Floors.from_env()
    return {
        "settings": s.to_dict(),
        "enabled": s.auto_approve_enabled,
        "floors": floors.to_dict(),
        "floors_explainer": (
            "Floors are set at deploy time by the platform team via SAM "
            "parameters (MaxAutoApproveRiskBelow, RequiredServiceBlocklist, "
            "RequiredAccountBlocklist, MaxAutoApproveQuotaPerHour). Admins "
            "can tighten settings beyond these floors but cannot loosen "
            "below them. Any PATCH that would violate a floor is refused "
            "with HTTP 400."
        ),
        "panic_switch_env_var": "IAM_JIT_AUTO_APPROVE_FORCE_OFF",
        "calibration_doc": "docs/USE-CASES.md",
    }


@router.patch("/auto-approve/settings")
def update_auto_approve_settings(
    payload: dict[str, Any],
    actor: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Update the auto-approve settings. Partial-update semantics:
    fields not in the payload keep their current values.

    Settable fields:
      - auto_approve_risk_below: int 1-10 OR null (null disables)
      - auto_approve_quota_per_hour: int ≥ 1
      - never_auto_approve_services: list[str] (e.g. ["iam","kms"])
      - never_auto_approve_accounts: list[str] (12-digit ids)
      - notes: free-form admin context

    The audit log captures every change with the admin's actor id
    and a diff vs the prior settings.
    """
    store = settings_mod.get_default_store()
    current = store.get()
    new_data = current.to_dict()

    # Validate threshold
    if "auto_approve_risk_below" in payload:
        v = payload["auto_approve_risk_below"]
        if v is None:
            new_data["auto_approve_risk_below"] = None
        elif isinstance(v, int) and 1 <= v <= 10:
            new_data["auto_approve_risk_below"] = v
        else:
            raise HTTPException(
                status_code=400,
                detail="auto_approve_risk_below must be null or an integer in [1, 10]",
            )

    if "auto_approve_quota_per_hour" in payload:
        v = payload["auto_approve_quota_per_hour"]
        if not isinstance(v, int) or v < 1 or v > 1000:
            raise HTTPException(
                status_code=400,
                detail="auto_approve_quota_per_hour must be an integer in [1, 1000]",
            )
        new_data["auto_approve_quota_per_hour"] = v

    for list_field in ("never_auto_approve_services", "never_auto_approve_accounts"):
        if list_field in payload:
            v = payload[list_field]
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise HTTPException(
                    status_code=400,
                    detail=f"{list_field} must be a list of strings",
                )
            new_data[list_field] = v

    for list_field in (
        "additional_sensitive_services",
        "additional_high_impact_actions",
    ):
        if list_field in payload:
            v = payload[list_field]
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise HTTPException(
                    status_code=400,
                    detail=f"{list_field} must be a list of strings",
                )
            new_data[list_field] = v

    if "max_role_duration_hours" in payload:
        v = payload["max_role_duration_hours"]
        if v is None:
            new_data["max_role_duration_hours"] = None
        elif isinstance(v, int) and 1 <= v <= 24 * 365 * 5:
            new_data["max_role_duration_hours"] = v
        else:
            raise HTTPException(
                status_code=400,
                detail=(
                    "max_role_duration_hours must be null or an integer in "
                    "[1, 43800] (1 hour up to 5 years)"
                ),
            )

    if "notes" in payload:
        v = payload["notes"]
        if v is not None and not isinstance(v, str):
            raise HTTPException(status_code=400, detail="notes must be a string")
        new_data["notes"] = v or ""

    updated = Settings.from_dict(new_data)

    # Floor enforcement: reject any update that loosens below the
    # deploy-time hard limits. The platform team owns floors at
    # deploy via SAM params; admins can tighten but not loosen.
    # See docs/security-notes.md § E4g for the threat model.
    floors = settings_mod.Floors.from_env()
    floor_errors = settings_mod.validate_against_floors(updated, floors)
    if floor_errors:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "settings would loosen below deploy-time floor",
                "violations": floor_errors,
                "floors": floors.to_dict(),
            },
        )

    store.put(updated)

    try:
        audit_mod.emit(
            actor=actor.id,
            kind="admin.auto_approve_settings_updated",
            summary=f"{actor.id} updated auto-approve settings",
            details={
                "previous": current.to_dict(),
                "updated": updated.to_dict(),
            },
        )
    except Exception:
        pass

    return {
        "settings": updated.to_dict(),
        "enabled": updated.auto_approve_enabled,
    }


@router.post("/auto-approve/disable")
def disable_auto_approve(
    actor: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Panic switch: immediately disable auto-approve. Equivalent to
    PATCH-ing settings with `auto_approve_risk_below: null`, but
    surfaced as a separate endpoint so it shows up loudly in audit
    logs and admin training material as "the way to turn it off
    fast." For an even faster off, set the env var
    IAM_JIT_AUTO_APPROVE_FORCE_OFF=1 (bypasses the settings store
    entirely; survives admin actions until the env is changed).
    """
    store = settings_mod.get_default_store()
    current = store.get()
    if not current.auto_approve_enabled:
        return {
            "disabled": True,
            "already_disabled": True,
        }
    import dataclasses
    updated = dataclasses.replace(
        current,
        auto_approve_risk_below=None,
        notes=(current.notes + " [disabled via panic switch]").strip(),
    )
    store.put(updated)
    try:
        audit_mod.emit(
            actor=actor.id,
            kind="admin.auto_approve_disabled",
            summary=f"{actor.id} disabled auto-approve via panic switch",
            details={"previous_threshold": current.auto_approve_risk_below},
        )
    except Exception:
        pass
    return {"disabled": True, "previous_threshold": current.auto_approve_risk_below}


# ---- Log retention (compliance / audit) -----------------------------
#
# Two endpoints:
#   GET  /api/v1/admin/log-retention  — current CloudWatch retention
#                                       + the deploy-time floor.
#   PATCH                              — apply a new retention. Refuses
#                                       any value below the floor;
#                                       refuses values CloudWatch won't
#                                       accept.
#
# The Lambda role is granted `logs:PutRetentionPolicy` scoped to its
# OWN log group only, so a compromised admin can never shorten logs
# from any other log group. The floor (`MinLogRetentionDays` SAM
# param) protects against evidence-destruction attacks where the same
# admin shortens retention to bury audit trails.


def _logs_client() -> Any:
    """Lazy boto3 client so tests can monkeypatch. Production uses
    the default Lambda credentials (the function role)."""
    import boto3

    return boto3.client("logs")


# Tests inject via this module-level reference. Production reads it
# at request time so the lazy import above runs in the Lambda.
get_logs_client = _logs_client


@router.get("/log-retention")
def get_log_retention(
    _: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Current CloudWatch retention on the iam-jit log group, plus
    the deploy-time floor and the list of valid retention windows."""
    floor = log_retention_mod.RetentionFloor.from_env()
    try:
        current = log_retention_mod.get_current_retention(
            get_logs_client(), floor.log_group_name,
        )
        error = None
    except log_retention_mod.RetentionError as e:
        current = None
        error = str(e)
    return {
        "current_days": current,
        "current_days_meaning": (
            "null = CloudWatch default (never expire). Set a finite "
            "value to enforce automated expiry."
            if current is None
            else f"logs older than {current} days are deleted by CloudWatch."
        ),
        "floor": floor.to_dict(),
        "valid_retention_days": list(log_retention_mod.VALID_RETENTION_DAYS),
        "floor_explainer": (
            "Floor is set at deploy time via the MinLogRetentionDays "
            "SAM parameter. Admins can only EXTEND retention beyond "
            "this floor. Shortening below the floor requires a redeploy "
            "with platform-team PR review. Protects against evidence-"
            "destruction attacks (see security-notes.md § E5)."
        ),
        "describe_error": error,
    }


@router.patch("/log-retention")
def update_log_retention(
    payload: dict[str, Any],
    actor: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Set CloudWatch retention. Payload: `{"retention_days": int}`.

    Refused with HTTP 400 if:
      - `retention_days` is not in `VALID_RETENTION_DAYS`
      - `retention_days` is below the deploy-time floor
    """
    if "retention_days" not in payload:
        raise HTTPException(
            status_code=400, detail="payload must include retention_days",
        )
    v = payload["retention_days"]
    if not isinstance(v, int):
        raise HTTPException(
            status_code=400, detail="retention_days must be an integer",
        )

    floor = log_retention_mod.RetentionFloor.from_env()
    errors = log_retention_mod.validate_retention(v, floor)
    if errors:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "retention_days rejected",
                "violations": errors,
                "floor": floor.to_dict(),
                "valid_retention_days": list(
                    log_retention_mod.VALID_RETENTION_DAYS
                ),
            },
        )

    try:
        previous = log_retention_mod.get_current_retention(
            get_logs_client(), floor.log_group_name,
        )
    except log_retention_mod.RetentionError:
        previous = None

    try:
        log_retention_mod.set_retention(
            get_logs_client(), floor.log_group_name, v, floor,
        )
    except log_retention_mod.RetentionError as e:
        raise HTTPException(status_code=500, detail=str(e))

    try:
        audit_mod.emit(
            actor=actor.id,
            kind="admin.log_retention_updated",
            summary=(
                f"{actor.id} updated CloudWatch retention on "
                f"{floor.log_group_name} from {previous} → {v} days"
            ),
            details={
                "previous_days": previous,
                "new_days": v,
                "log_group_name": floor.log_group_name,
                "floor_min_days": floor.min_days,
            },
        )
    except Exception:
        pass

    return {
        "current_days": v,
        "previous_days": previous,
        "floor": floor.to_dict(),
    }


# ---- Scorer calibration (evolve-the-scorer scaffolding) ------------
#
# The deterministic scorer's verdict is recorded with every request
# (status.review.risk_score) and every human approve/reject decision
# lands in the request history. This endpoint walks the store and
# computes scorer-vs-human disagreement statistics so admins can
# tune the scorer over time. See docs/EVOLVING-THE-SCORER.md.


@router.get("/calibration")
def get_calibration(
    _: Annotated[User, Depends(require_admin)],
    request_store: Annotated[RequestStore, Depends(get_request_store)],
    since_days: Annotated[
        int | None,
        Query(
            ge=1, le=3653,
            description=(
                "Only include requests submitted within this many days "
                "ago. Default: no time filter."
            ),
        ),
    ] = None,
    early_revoke_minutes: Annotated[
        int,
        Query(
            ge=1, le=24 * 60,
            description=(
                "Threshold below which a revoke is counted as 'early', "
                "i.e. a potential 'scorer was too permissive' signal."
            ),
        ),
    ] = 15,
) -> dict[str, Any]:
    """Disagreement stats between the deterministic scorer and humans.

    Returns the aggregate counts, score distributions, and a notes
    list calling out signals to investigate. Pair this with the
    process in docs/EVOLVING-THE-SCORER.md to drive the calibration
    loop.

    The endpoint scans every request in the store (cap your store
    size or filter via `since_days` for large deployments). All
    computation is local — no LLM call, no AWS API call.
    """
    import datetime as _dt

    since: _dt.datetime | None = None
    if since_days is not None:
        since = _dt.datetime.now(_dt.UTC) - _dt.timedelta(days=since_days)

    # Resolve the current threshold so we can compute over/undershoot.
    settings = settings_mod.get_default_store().get()
    threshold = settings.auto_approve_risk_below

    # Pull every request. For a small / steady-state deployment this
    # is fine; for high-volume deployments it'd want a CloudWatch
    # query or DDB scan with a time-range filter. Out of scope today.
    ids = request_store.list_ids()
    requests = []
    for rid in ids:
        try:
            req = request_store.get(rid)
            requests.append(req)
        except Exception:
            # A request that fails to load is a known-bad row; skip
            # it rather than fail the whole report. Surface in notes.
            continue

    report = calibration_mod.analyze(
        requests,
        threshold=threshold,
        early_revoke_minutes=early_revoke_minutes,
        since=since,
    )

    body = report.to_dict()
    body["window"] = {
        "since_days": since_days,
        "early_revoke_minutes": early_revoke_minutes,
        "threshold_at_analysis_time": threshold,
    }
    body["doc"] = "docs/EVOLVING-THE-SCORER.md"
    return body
