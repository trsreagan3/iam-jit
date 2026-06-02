"""Health check route. Unauthenticated by design — used by load balancers,
deployment smoke tests, and `iam-jit serve` boot verification.
"""

from __future__ import annotations

import os

from fastapi import APIRouter

from .. import __version__

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict:
    """Health summary.

    BB-13 / BB3-03 closure: `/healthz` is now a minimal liveness
    response only. The previous version returned the full
    `security_posture` block (auth_mode, user_config_source,
    llm_backend, network ACL status, etc.) unauthenticated — that
    accelerates targeted attacker recon. Operators who need the
    posture object should hit `/api/v1/admin/security-posture`
    (admin-gated).
    """
    # #726 / BUILD-5 — "off the leash" monitoring booleans. A SIEM /
    # load-balancer / uptime probe polls these to learn "is any agent
    # session whose bouncer WAS checking in now silent past the TTL?".
    # Recon-safe: counts + booleans only, NO session ids (the detailed
    # per-session view lives behind admin auth on
    # GET /api/v1/presence/status). Honest framing — off_the_leash is a
    # SIGNAL, not proof of bypass.
    try:
        from .. import presence as _presence

        ps = _presence.presence_status()
        bouncer_presence = {
            "enforced": ps["enforced"],
            # #55 — whether the check-in route requires a distinct
            # `bouncer` identity. Recon-safe boolean.
            "role_required": ps["role_required"],
            "ttl_seconds": ps["ttl_seconds"],
            "tracked_sessions": ps["tracked_sessions"],
            "off_the_leash_count": ps["off_the_leash_count"],
            "off_the_leash_detected": ps["off_the_leash_detected"],
        }
    except Exception:  # pragma: no cover — /healthz must never 500
        bouncer_presence = None
    return {
        "status": "ok",
        "version": __version__,
        "bouncer_presence": bouncer_presence,
    }
