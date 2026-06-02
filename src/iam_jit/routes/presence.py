"""Bouncer-presence routes — "off the leash" detection (#726 / BUILD-5).

Two endpoints:

  * POST /api/v1/presence/check-in  (authenticated)
      The bouncer proves it is in an agent's path. Body:
        {"session_id": "...", "idle": false}
      `idle=true` is the bouncer saying "I'm in the path but have
      nothing to gate right now" — keeps the session out of the
      off-the-leash bucket (we distinguish idle from gone).

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
def check_in(  # noqa: SD-2 — `actor` is a FastAPI auth dependency (enforces Bearer auth); not referenced in body by design
    payload: dict[str, Any] | None = None,
    actor: User = Depends(current_user),
) -> dict[str, Any]:
    """Record a bouncer presence beat for an agent session.

    Any authenticated caller (the bouncer authenticates with its API
    token) may check in. The presence record is keyed by session_id so
    the role-issuance gate can later confirm "is the bouncer for THIS
    session still flowing through me?".
    """
    from .. import presence as presence_mod

    body = payload or {}
    session_id = str(body.get("session_id") or "").strip()
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id is required")
    idle = bool(body.get("idle", False))
    presence_mod.record_check_in(session_id, idle=idle)
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
