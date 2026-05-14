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
    return {"status": "ok", "version": __version__}
