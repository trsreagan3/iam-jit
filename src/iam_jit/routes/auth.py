"""Authentication endpoints (local mode).

POST /api/v1/auth/magic-link  Request a magic link by email
GET  /api/v1/auth/callback    Verify the magic-link token and set a session cookie
POST /api/v1/auth/logout      Clear the session cookie

In `aws_iam` mode these endpoints aren't used — the Function URL handles
auth at the SigV4 layer. They still exist (returning 400 for unsupported
mode) so callers see a consistent error shape.
"""

from __future__ import annotations

import os
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature

from .. import (
    auth as auth_mod,
    bans as bans_mod,
    magic_link_delivery,
    magic_link_nonces,
    public_url as public_url_mod,
)
from ..middleware import _get_secret, get_user_store
from ..users_store import UserNotFound, UserStore


_EMAIL_API_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def _safe_email(raw: str) -> str | None:
    """Strict email validation for the JSON auth API.

    Refuses CR/LF/NUL (header-injection vector for SES) and obviously-
    malformed input. Returns the lowercased trimmed email or None."""
    if not isinstance(raw, str):
        return None
    if "\n" in raw or "\r" in raw or "\x00" in raw:
        return None
    candidate = raw.strip().lower()
    if not candidate or len(candidate) > 254:
        return None
    if not _EMAIL_API_RE.match(candidate):
        return None
    return candidate

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


_magic_link_ip_limiter = None


def _get_magic_link_ip_limiter():
    """Per-IP rate limiter for the magic-link issuance route — guards
    SES quota and email-domain reputation at launch. Separate from the
    chat/intake limiter so its caps can be tighter."""
    global _magic_link_ip_limiter
    from .. import rate_limit

    if _magic_link_ip_limiter is None:
        soft = int(os.environ.get("IAM_JIT_MAGIC_LINK_IP_SOFT_CAP", "5"))
        hard = int(os.environ.get("IAM_JIT_MAGIC_LINK_IP_HARD_CAP", "15"))
        _magic_link_ip_limiter = rate_limit.InMemoryRateLimiter(
            soft_cap=soft, hard_cap=hard
        )
    return _magic_link_ip_limiter


def _reset_magic_link_ip_limiter_for_tests() -> None:
    """Reset the per-IP limiter between tests."""
    global _magic_link_ip_limiter
    _magic_link_ip_limiter = None


def _magic_link_client_ip(request: Request) -> str:
    """Same trust posture as score._client_ip — XFF only when peer is
    a configured trusted proxy. For the magic-link route, source-IP
    accuracy matters less (we just want a per-IP bucket); we fall back
    to peer.host directly when no trusted proxy is configured."""
    try:
        return request.client.host if request.client else "unknown"
    except Exception:
        return "unknown"


@router.post("/magic-link", status_code=status.HTTP_202_ACCEPTED)
def issue_magic_link(
    request: Request,
    payload: dict[str, Any],
    user_store: Annotated[UserStore, Depends(get_user_store)],
) -> dict[str, str]:
    """Issue a magic-link token for the given email.

    For an unknown email we return 202 anyway to avoid leaking whether an
    address is registered. The link is only sent (or, in dev mode,
    surfaced in the response body) for known + enabled users.
    """
    if (os.environ.get("IAM_JIT_AUTH_MODE") or "local").lower() != "local":
        raise HTTPException(status_code=400, detail="magic-link auth is only available in local mode")

    # MAGIC-LINK-REPLAY-MULTI-INSTANCE closure: if we're running in
    # Lambda (multi-instance possible) AND no DynamoDB-backed nonce
    # store is configured AND the operator hasn't explicitly opted
    # in to the in-memory store, refuse. The in-memory store can't
    # enforce single-use across Lambda instances, so a captured
    # link replays. Opt-out env var: IAM_JIT_ALLOW_INSECURE_NONCES=1
    # (e.g. single-instance dev / RC=1 deployments).
    _in_lambda = bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
    _has_ddb_nonces = bool(
        (os.environ.get("IAM_JIT_MAGIC_LINK_NONCES_TABLE") or "").strip()
    )
    _allow_insecure = (
        os.environ.get("IAM_JIT_ALLOW_INSECURE_NONCES", "").lower()
        in {"1", "true", "yes"}
    )
    if _in_lambda and not _has_ddb_nonces and not _allow_insecure:
        raise HTTPException(
            status_code=503,
            detail=(
                "multi-instance magic-link replay protection is not "
                "configured. Set IAM_JIT_MAGIC_LINK_NONCES_TABLE to a "
                "DynamoDB table (recommended), or "
                "IAM_JIT_ALLOW_INSECURE_NONCES=1 if you've capped the "
                "Lambda to a single instance (reserved concurrency=1)."
            ),
        )

    # Per-IP rate limit (BB-09 / launch-day SES quota guard). 5
    # req/min/IP soft, 15 hard. Uniform 429 regardless of email so
    # the limit doesn't double as a registration oracle.
    ip = _magic_link_client_ip(request)
    decision = _get_magic_link_ip_limiter().check(ip, kind="magic_link")
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail="too many magic-link requests; try again later",
            headers={"Retry-After": str(max(1, decision.retry_after_seconds))},
        )

    # BB-12 closure: refuse universally before email lookup when no
    # delivery channel is configured. Refusing here is uniform across
    # known/unknown emails so we don't leak registration status. The
    # operator gets a loud 503 at launch instead of silently dropping
    # auth attempts (and instead of logging the full link URL).
    if magic_link_delivery.decide().channel == "none":
        raise HTTPException(
            status_code=503,
            detail=(
                "magic-link delivery is not configured. Set "
                "IAM_JIT_SES_SENDER to a verified SES address (prod), "
                "or IAM_JIT_ALLOW_LOG_CHANNEL=1 (small-team CloudWatch "
                "out-of-band delivery), or IAM_JIT_DEV_INSECURE_SECRET=1 "
                "(local dev)."
            ),
        )

    email_raw = (payload or {}).get("email")
    safe = _safe_email(email_raw if isinstance(email_raw, str) else "")
    if safe is None:
        # Uniform 202 — never reveal that the input was malformed
        # (would let an attacker enumerate which inputs we accept).
        return {"status": "if the email is registered, a link has been sent"}
    email = safe

    user_id = f"email:{email}"
    # Refuse banned users at the link-issuance step too. They wouldn't
    # be able to sign in anyway, but emitting a fresh link to them is
    # noise — and could be used as a side channel ("oh, my old account
    # still gets emails, so the ban must be lifted").
    if bans_mod.get_default_store().is_banned(user_id):
        return {"status": "if the email is registered, a link has been sent"}
    try:
        user = user_store.get(user_id)
        known_user = user.enabled
    except UserNotFound:
        known_user = False

    response: dict[str, str] = {"status": "if the email is registered, a link has been sent"}
    if known_user:
        token = auth_mod.sign_magic_link(_get_secret(), user_id)
        link = _link_for(token, request=request)
        decision = magic_link_delivery.deliver(
            email=email, user_id=user_id, link=link
        )
        # Only the in_response (dev) channel returns the link to the
        # caller. `email` and `log` channels deliver out-of-band so the
        # 202 body stays uniform.
        if decision.show_in_response:
            response["dev_link"] = link
    return response


def _link_for(token: str, *, request: Request | None = None) -> str:
    base = public_url_mod.base_for(request)
    return f"{base}/api/v1/auth/callback?token={token}"


@router.get("/callback", response_class=Response)
def magic_link_callback(token: str) -> Response:
    if (os.environ.get("IAM_JIT_AUTH_MODE") or "local").lower() != "local":
        raise HTTPException(status_code=400, detail="magic-link auth is only available in local mode")
    try:
        user_id = auth_mod.verify_magic_link(_get_secret(), token)
    except BadSignature:
        raise HTTPException(status_code=400, detail="invalid or expired magic link")

    # Single-use: refuse to reissue a session for a token that has
    # already been consumed.
    try:
        magic_link_nonces.get_default_store().consume_or_reject(
            auth_mod.magic_link_token_id(token)
        )
    except magic_link_nonces.TokenAlreadyUsed:
        raise HTTPException(status_code=400, detail="magic-link token already used")

    # Banned users can't sign in via this surface either.
    if bans_mod.get_default_store().is_banned(user_id):
        raise HTTPException(
            status_code=403,
            detail="account suspended; contact your iam-jit administrator",
        )

    cookie_value = auth_mod.sign_session(_get_secret(), user_id)
    redirect_to = os.environ.get("IAM_JIT_POST_LOGIN_REDIRECT") or "/"
    response = RedirectResponse(url=redirect_to, status_code=303)
    response.set_cookie(
        key="iam_jit_session",
        value=cookie_value,
        httponly=True,
        secure=os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") != "1",
        samesite="strict",
        path="/",
        max_age=24 * 60 * 60,
    )
    return response


@router.post("/logout", response_class=Response)
def logout(request: Request) -> Response:
    from fastapi.responses import JSONResponse
    from .. import session_revocation as _sr

    # BB3-01 closure: server-side revocation. Clear the cookie in
    # the caller's browser AND add the cookie hash to the revocation
    # list so any other client that saved the same value can't
    # continue to use it until the cookie's natural TTL expires.
    cookie = request.cookies.get("iam_jit_session")
    if cookie:
        try:
            _sr.get_default_store().revoke(cookie, ttl_seconds=24 * 60 * 60)
        except Exception:
            import logging
            logging.getLogger("iam_jit.session_revocation").exception(
                "failed to revoke session on logout"
            )
    resp = JSONResponse(content={"status": "logged out"})
    resp.delete_cookie("iam_jit_session", path="/")
    return resp
