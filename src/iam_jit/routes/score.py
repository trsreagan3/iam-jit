"""Standalone scoring API — the launch feature.

`POST /api/v1/score` accepts an IAM policy + minimal request
context and returns the deterministic risk verdict plus the
optional LLM narrative. This is the endpoint pipelines, CI/CD,
GitHub Actions, and AI agents call to "get a score for an IAM
policy" without going through the full iam-jit request lifecycle.

Distinguished from `POST /api/v1/requests` (the full submission
endpoint) by:

  - **No authentication required by default** — scoring is a
    read-only stateless operation. Production deployments add
    API-key auth via `IAM_JIT_SCORE_API_KEY` env (any non-empty
    value requires the same value in the `Authorization: Bearer`
    header). Self-hosted dev deployments leave it unset.

  - **No state mutation** — nothing is stored, no role is
    provisioned, no audit event emitted (audit lives in the
    customer's CI logs, not in iam-jit). The endpoint is purely
    "policy in, score out."

  - **Rate-limited per IP** to prevent abuse. The default cap is
    high enough for CI workflows but stops scraping. Override via
    `IAM_JIT_SCORE_RATE_PER_MINUTE` (default 60/min/IP).

  - **Stable response schema** — designed for programmatic
    consumption. Versioned via the URL path; breaking changes go
    to /api/v2/score.

Response shape (`ScoreResponse`):

```json
{
  "score": 4,
  "tier": "medium",
  "would_auto_approve_at_threshold_5": true,
  "factors": ["..."],
  "suggestions": ["..."],
  "llm_narrative": null,
  "analyzer": "deterministic",
  "policy_fingerprint": "sha256:..."
}
```

Score-to-tier mapping: 1-3 = low, 4-5 = medium, 6-10 = high.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Annotated, Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from .. import review


router = APIRouter(prefix="/api/v1", tags=["score"])


# ---- Request / response models ---------------------------------------


class ScoreRequest(BaseModel):
    """Minimal payload for scoring an IAM policy.

    The only required field is `policy`. Everything else has a
    sensible default that matches the most common CI/agent use
    case (read-only, 1h duration, no admin context overrides)."""

    policy: dict[str, Any] = Field(
        ...,
        description=(
            "AWS IAM policy document. Standard shape: "
            "{Version, Statement: [...]}. Validated server-side; "
            "malformed policies return HTTP 400 with details."
        ),
    )
    access_type: str = Field(
        default="read-only",
        description=(
            "'read-only' or 'read-write'. Affects scoring — read-only "
            "with state-changing actions scores higher (it's a "
            "mislabeled request, which is its own risk signal)."
        ),
    )
    duration_hours: int = Field(
        default=1,
        ge=1, le=8760,  # 1h to 1 year
        description=(
            "How long the grant would be active. Longer durations "
            "amplify medium-risk policies (more blast-radius hours)."
        ),
    )
    description: str | None = Field(
        default=None,
        max_length=500,
        description=(
            "Optional one-line context the LLM narrative can "
            "reference. Not used by the deterministic scorer."
        ),
    )

    # Optional admin context to override the scorer's built-in
    # sensitive-services / high-impact-actions sets. Maps to the
    # same fields on iam_jit.settings_store.Settings.
    additional_sensitive_services: list[str] | None = None
    additional_high_impact_actions: list[str] | None = None


class ScoreResponse(BaseModel):
    """Programmatic-consumption response shape.

    Stable schema. Changes to this go through a versioned URL path
    (/api/v2/score) or additive fields only — no removals or
    semantic changes within /api/v1/score."""

    score: int = Field(..., ge=1, le=10)
    tier: str = Field(..., description="low | medium | high")
    would_auto_approve_at_threshold_5: bool = Field(
        ...,
        description=(
            "Convenience flag: at the recommended default auto-"
            "approve threshold of 5, would THIS request fire? "
            "Equivalent to (score < 5). Callers tune their own "
            "threshold; this is a hint."
        ),
    )
    factors: list[str] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list)
    llm_narrative: str | None = None
    analyzer: str = Field(..., description="deterministic | deterministic+<llm>")
    policy_fingerprint: str = Field(
        ...,
        description=(
            "sha256 of the canonical-JSON policy. Use this to "
            "deduplicate scoring across CI runs of the same PR."
        ),
    )
    api_version: str = Field(default="v1")


# ---- Rate limiting ---------------------------------------------------
#
# Simple sliding-window per-IP rate limit. Process-local; per-Lambda-
# instance in production. Each Lambda concurrent instance has its own
# counter, so the effective rate-per-customer is `instances * rate`.
# That's a safe overestimate — abusers ARE rate-limited even if
# they get unlucky with instance routing.


class _RateLimiter:
    def __init__(self) -> None:
        self.cap = int(os.environ.get("IAM_JIT_SCORE_RATE_PER_MINUTE", "60"))
        self.window_seconds = 60
        self._counts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, ip: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            q = self._counts[ip]
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.cap:
                # When does the oldest entry age out?
                retry = int(self.window_seconds - (now - q[0])) + 1
                return False, max(1, retry)
            q.append(now)
            return True, 0


_limiter = _RateLimiter()


def _reset_limiter_for_tests() -> None:
    """Reset module-local rate-limiter state. Wired into the
    autouse test fixture so per-IP counts don't leak between
    tests."""
    global _limiter
    _limiter = _RateLimiter()


# ---- Helpers ---------------------------------------------------------


def _tier_for(score: int) -> str:
    if score <= 3:
        return "low"
    if score <= 5:
        return "medium"
    return "high"


def _policy_fingerprint(policy: dict[str, Any]) -> str:
    """Deterministic content hash of the policy. Used by callers to
    deduplicate scoring across CI runs / PR revisions."""
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _require_api_key(authorization: str | None) -> None:
    """If IAM_JIT_SCORE_API_KEY is set in the env, require the
    same value in the Authorization header. Otherwise (dev /
    public-API deployments), no auth required."""
    expected = (os.environ.get("IAM_JIT_SCORE_API_KEY") or "").strip()
    if not expected:
        return  # No key configured = open API
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header. This deployment requires an API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Accept "Bearer <key>" OR just "<key>"
    token = authorization.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _client_ip(request: Request) -> str:
    """Best-effort client IP. Trusts X-Forwarded-For when iam-jit's
    middleware says it should (ALB / Function URL deployments)."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---- The endpoint ----------------------------------------------------


@router.post("/score", response_model=ScoreResponse)
def score_policy(
    payload: ScoreRequest,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> ScoreResponse:
    """Score an IAM policy. The launch feature.

    Stateless. Idempotent. Same input → same output. No data is
    stored on the server; the policy itself is processed in
    memory and discarded after the response is built.

    Quotas are per-source-IP, 60 requests/min by default
    (configurable via `IAM_JIT_SCORE_RATE_PER_MINUTE`). Returns
    HTTP 429 with `Retry-After` header when exceeded.

    If `IAM_JIT_SCORE_API_KEY` env var is set, the same value
    must appear in the `Authorization: Bearer <key>` header.
    Otherwise the endpoint is open (suitable for OSS self-hosted
    deployments behind a firewall).
    """
    _require_api_key(authorization)

    ip = _client_ip(request)
    allowed, retry = _limiter.check(ip)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded for {ip}. Retry in {retry}s. "
                "Default is 60 req/min; for higher quotas, "
                "configure your deployment or use the hosted SaaS."
            ),
            headers={"Retry-After": str(retry)},
        )

    # Validate the policy shape lightly. Heavy validation (resource
    # ARNs, action names) is the caller's responsibility — we want
    # to score even policies that won't deploy cleanly so a CI run
    # can flag "your policy is unsafe AND malformed" in one call.
    if not isinstance(payload.policy, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="policy must be a JSON object",
        )
    if "Statement" not in payload.policy:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="policy must include 'Statement' key (AWS IAM policy shape)",
        )

    # Build the minimum request shape the scorer expects. Strip
    # description if None so the scorer doesn't see "None" as text.
    request_shape: dict[str, Any] = {
        "spec": {
            "access_type": payload.access_type,
            "duration": {"duration_hours": payload.duration_hours},
            "resource_constraints": [],
        }
    }
    if payload.description:
        request_shape["spec"]["description"] = payload.description

    extra_services = tuple(payload.additional_sensitive_services or ())
    extra_actions = tuple(payload.additional_high_impact_actions or ())

    try:
        analysis = review.analyze_policy(
            payload.policy, request_shape,
            extra_sensitive_services=extra_services,
            extra_high_impact_actions=extra_actions,
        )
    except Exception as e:
        # The scorer is supposed to be defensive — but if it crashes,
        # return 400 with the error rather than 500 (the caller's
        # policy is most likely malformed).
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"could not score policy: {type(e).__name__}: {e}",
        )

    return ScoreResponse(
        score=analysis.risk_score,
        tier=_tier_for(analysis.risk_score),
        would_auto_approve_at_threshold_5=analysis.risk_score < 5,
        factors=list(analysis.risk_factors),
        suggestions=list(analysis.suggestions),
        llm_narrative=analysis.llm_narrative,
        analyzer=analysis.analyzer,
        policy_fingerprint=_policy_fingerprint(payload.policy),
    )
