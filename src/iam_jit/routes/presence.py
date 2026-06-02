"""Bouncer-presence routes — "off the leash" detection (#726 / BUILD-5).

Two endpoints:

  * POST /api/v1/presence/check-in  (authenticated; bouncer-bound)
      The bouncer proves it is in an agent's path. Body:
        {"session_id": "...", "idle": false}
      `idle=true` is the bouncer saying "I'm in the path but have
      nothing to gate right now" — keeps the session out of the
      off-the-leash bucket (we distinguish idle from gone).
      #55 / BUILD-5: the beat is bound to the authenticated principal.
      With IAM_JIT_REQUIRE_BOUNCER_ROLE=1 the caller MUST hold the
      `bouncer` role (a distinct machine identity), so a plain agent
      token cannot forge a beat; a beat is only TRUSTED by the enforce
      gate when attributed to a bouncer-role principal.

  * GET  /api/v1/presence/status    (admin)
      Operator-visibility surface: which tracked agent sessions are
      PRESENT vs OFF_THE_LEASH, the TTL, and whether the gate is
      enforced. Honest framing per [[ibounce-honest-positioning]] — a
      gap is a SIGNAL, never "BYPASS DETECTED".

Per [[safety-mode-lean-permissive]] the gate is advisory by default;
enforcement (refuse issuance on a gap) is opt-in via
IAM_JIT_REQUIRE_BOUNCER_PRESENCE.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException

from ..middleware import current_user, require_admin
from ..users_store import User

router = APIRouter(prefix="/api/v1/presence", tags=["presence"])


@router.post("/check-in")
def check_in(  # noqa: SD-2 — `actor` is a FastAPI auth dependency (enforces Bearer auth); referenced below to bind the beat to the calling identity
    payload: dict[str, Any] | None = None,
    actor: User = Depends(current_user),
) -> dict[str, Any]:
    """Record a bouncer presence beat for an agent session.

    #55 / BUILD-5 — identity binding. The presence record is keyed by
    session_id so the role-issuance gate can later confirm "is the
    bouncer for THIS session still flowing through me?", and the beat is
    bound to the AUTHENTICATED principal that sent it so a plain agent
    token cannot forge a *trusted* beat:

      * When `IAM_JIT_REQUIRE_BOUNCER_ROLE=1`, the caller MUST hold the
        `bouncer` role — a narrow machine identity distinct from the
        agent/requester token. A non-bouncer caller is rejected 403, so
        the forge path is closed at the door.
      * The beat is recorded as VERIFIED only when the caller holds the
        `bouncer` role (attributed to `actor.id`). A beat from a
        non-bouncer caller (only possible in the default back-compat
        posture where the role is not required) is recorded UNVERIFIED;
        the enforce gate will not trust it to clear an off-the-leash
        verdict (see presence.py).
    """
    from .. import presence as presence_mod

    # #55 — close the door when the operator opts in. Default-off so
    # deployments that have not provisioned a bouncer identity keep
    # working (those beats are recorded UNVERIFIED below).
    if presence_mod.require_bouncer_role() and not actor.is_bouncer:
        raise HTTPException(
            status_code=403,
            detail=(
                "bouncer role required: presence check-in must come from a "
                "principal provisioned as a bouncer identity "
                "(IAM_JIT_REQUIRE_BOUNCER_ROLE is enabled)."
            ),
        )

    body = payload or {}
    session_id = str(body.get("session_id") or "").strip()
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id is required")
    idle = bool(body.get("idle", False))
    # A beat is VERIFIED iff it is attributed to a `bouncer`-role
    # principal. In back-compat mode a non-bouncer caller's beat is
    # recorded with verifier_principal=None (unverified).
    verifier_principal = actor.id if actor.is_bouncer else None
    presence_mod.record_check_in(
        session_id, idle=idle, verifier_principal=verifier_principal
    )
    verdict = presence_mod.evaluate_session(session_id)
    return {"recorded": True, "presence": verdict.to_dict()}


@router.post("/forget")
def forget(  # noqa: SD-2 — `actor` is a FastAPI auth dependency (enforces Bearer auth); not referenced in body by design
    payload: dict[str, Any] | None = None,
    actor: User = Depends(current_user),
) -> dict[str, Any]:
    """Drop a session's presence record (deliberate session end).

    A post-session silence is not "off the leash" — the operator told
    us the session is over, mirroring the bouncer's heartbeat stop()
    clearing its gap flag."""
    from .. import presence as presence_mod

    body = payload or {}
    session_id = str(body.get("session_id") or "").strip()
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id is required")
    presence_mod.forget_session(session_id)
    return {"forgotten": True, "session_id": session_id}


@router.get("/status")
def status(  # noqa: SD-2 — `actor` is a FastAPI admin-auth dependency (enforces require_admin); not referenced in body by design
    actor: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Operator-visibility snapshot of bouncer presence across all
    tracked agent sessions. Admin-gated (mirrors security-posture)."""
    from .. import presence as presence_mod

    return presence_mod.presence_status()
