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
    """Health summary + security posture.

    The `security_posture` block is included unauthenticated so
    agents that integrate with iam-jit can detect a degraded
    deploy (open SG + HTTP-only is the worst combo) before they
    submit any request. The block contains no secrets — just
    boolean flags and severity classifiers."""
    from .. import security_posture

    return {
        "status": "ok",
        "version": __version__,
        "auth_mode": os.environ.get("IAM_JIT_AUTH_MODE", "local"),
        "user_config_source": os.environ.get("IAM_JIT_USER_CONFIG_SOURCE", "dynamodb"),
        "llm_backend": os.environ.get("IAM_JIT_LLM", "none"),
        "security_posture": security_posture.compute(),
    }
