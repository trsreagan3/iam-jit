"""OIDC SSO routes — generic (multi-provider) authorization-code flow.

  GET  /api/v1/auth/oidc/login     redirect to provider
  GET  /api/v1/auth/oidc/callback  validate ID token, set session cookie
  POST /api/v1/auth/logout         already-existing endpoint clears the cookie

Configuration via env vars; see `iam_jit.oidc.OIDCProviderConfig.from_env()`.

Security checks (must all pass — fails closed):
  1. State cookie matches query param (CSRF)
  2. Nonce cookie matches ID token claim (replay)
  3. Signed cookie within max_age (replay window)
  4. ID token signature against provider's JWKS
  5. iss / aud / exp / iat claims valid
  6. email_verified == true
  7. Provider-specific: Google `hd`, Okta groups
  8. Resolved iam-jit User exists + is enabled

Failure modes return HTTP 401 with a generic message. The detail
goes to logs, NOT to the caller — never echo back internal state
to an attacker probing for valid sign-in paths.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, TimestampSigner

from .. import auth as auth_mod, oidc as oidc_mod
from ..middleware import _get_secret
from ..users_store import UserNotFound

logger = logging.getLogger("iam_jit.routes.oidc")

router = APIRouter(prefix="/api/v1/auth/oidc", tags=["auth", "oidc"])


# State cookie TTL: 10 minutes. Long enough for user to authenticate
# at the provider; short enough to bound replay window.
_STATE_COOKIE_TTL = 600
_STATE_COOKIE_NAME = "iam_jit_oidc_state"
_NONCE_COOKIE_NAME = "iam_jit_oidc_nonce"


def _signer(salt: str) -> TimestampSigner:
    return TimestampSigner(_get_secret(), salt=salt)


def _config_or_503() -> oidc_mod.OIDCProviderConfig:
    """Load OIDC config from env. 503 if not configured."""
    try:
        cfg = oidc_mod.OIDCProviderConfig.from_env()
    except oidc_mod.ConfigError as e:
        logger.error("oidc misconfiguration: %s", e)
        raise HTTPException(status_code=503, detail="OIDC misconfigured")
    if cfg is None:
        raise HTTPException(
            status_code=503,
            detail="OIDC SSO is not configured on this deployment.",
        )
    return cfg


# Module-level JWKS cache shared across requests in the same Lambda
# instance. Auto-refreshes per the cache's TTL + on unknown kid.
_jwks_cache: oidc_mod.JWKSCache | None = None
# WB9-04 closure: endpoints cache previously had no TTL — first
# discovery fetch was held for Lambda lifetime, so a poisoned first
# fetch (or a rotated jwks_uri on the provider side) would persist
# indefinitely. Cache now has the same 1-hour TTL as JWKS so
# provider rotations propagate within an hour.
_ENDPOINTS_CACHE_TTL = 3600
_endpoints_cache: dict[str, tuple[float, oidc_mod.DiscoveredEndpoints]] = {}


def _get_jwks_cache() -> oidc_mod.JWKSCache:
    global _jwks_cache
    if _jwks_cache is None:
        _jwks_cache = oidc_mod.JWKSCache(oidc_mod.HttpxClient())
    return _jwks_cache


def _get_endpoints(config: oidc_mod.OIDCProviderConfig) -> oidc_mod.DiscoveredEndpoints:
    """Discovery doc is fetched + cached with a 1-hour TTL.

    WB9-04 closure: TTL prevents a poisoned first fetch from
    persisting indefinitely + lets provider endpoint rotations
    (rare but possible) propagate.
    """
    import time as _time

    key = config.discovery_endpoint()
    cached = _endpoints_cache.get(key)
    now = _time.time()
    if cached is not None and cached[0] > now:
        return cached[1]
    endpoints = oidc_mod.discover(config, oidc_mod.HttpxClient())
    _endpoints_cache[key] = (now + _ENDPOINTS_CACHE_TTL, endpoints)
    return endpoints


def _reset_caches_for_tests() -> None:
    global _jwks_cache
    _jwks_cache = None
    _endpoints_cache.clear()


# ---------------------------------------------------------------------------
# /login — redirect to provider.
# ---------------------------------------------------------------------------


@router.get("/login")
def oidc_login(request: Request) -> RedirectResponse:
    """Start the OIDC authorization-code flow.

    Generates state + nonce, sets them as signed cookies, and
    redirects to the provider's authorization endpoint.
    """
    config = _config_or_503()
    try:
        endpoints = _get_endpoints(config)
    except oidc_mod.ConfigError as e:
        logger.error("oidc discovery failed: %s", e)
        raise HTTPException(status_code=503, detail="OIDC discovery failed")

    session = oidc_mod.new_auth_session()
    auth_url = oidc_mod.build_authorization_url(config, endpoints, session)

    resp = RedirectResponse(url=auth_url, status_code=303)

    # Sign + set the state + nonce cookies. They get verified on
    # /callback. Cookie scope is path=/api/v1/auth/oidc/ so they
    # don't leak to other paths.
    state_signed = _signer("oidc-state").sign(session.state.encode()).decode()
    nonce_signed = _signer("oidc-nonce").sign(session.nonce.encode()).decode()

    cookie_kwargs = {
        "httponly": True,
        "secure": _cookie_secure(),
        "samesite": "lax",
        "path": "/api/v1/auth/oidc/",
        "max_age": _STATE_COOKIE_TTL,
    }
    resp.set_cookie(_STATE_COOKIE_NAME, state_signed, **cookie_kwargs)
    resp.set_cookie(_NONCE_COOKIE_NAME, nonce_signed, **cookie_kwargs)
    return resp


# ---------------------------------------------------------------------------
# /callback — validate ID token + set session.
# ---------------------------------------------------------------------------


@router.get("/callback")
def oidc_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> Response:
    """Handle the OIDC provider's callback.

    Validates state, exchanges code for ID token, validates the ID
    token end-to-end, resolves the verified email to an iam-jit
    User, sets a session cookie.

    On any failure, returns 401 with a generic message. Details
    go to logs only — never echoed to the caller.
    """
    config = _config_or_503()

    if error:
        # Provider rejected the user (e.g., they declined consent
        # OR the workspace policy refused). Log + return generic.
        logger.warning(
            "oidc callback: provider returned error=%s description=%s",
            error, (error_description or "")[:200],
        )
        raise HTTPException(status_code=401, detail="sign-in failed")

    if not code or not state:
        logger.warning("oidc callback: missing code or state param")
        raise HTTPException(status_code=400, detail="missing parameters")

    # State CSRF check — query param must match signed cookie.
    state_cookie = request.cookies.get(_STATE_COOKIE_NAME)
    nonce_cookie = request.cookies.get(_NONCE_COOKIE_NAME)
    if not state_cookie or not nonce_cookie:
        logger.warning("oidc callback: missing state/nonce cookies")
        raise HTTPException(status_code=401, detail="sign-in failed")

    try:
        cookie_state = _signer("oidc-state").unsign(
            state_cookie.encode(), max_age=_STATE_COOKIE_TTL,
        ).decode()
    except BadSignature as e:
        logger.warning("oidc callback: state cookie invalid: %s", e)
        raise HTTPException(status_code=401, detail="sign-in failed")
    if cookie_state != state:
        logger.warning("oidc callback: state mismatch (CSRF?)")
        raise HTTPException(status_code=401, detail="sign-in failed")

    try:
        cookie_nonce = _signer("oidc-nonce").unsign(
            nonce_cookie.encode(), max_age=_STATE_COOKIE_TTL,
        ).decode()
    except BadSignature as e:
        logger.warning("oidc callback: nonce cookie invalid: %s", e)
        raise HTTPException(status_code=401, detail="sign-in failed")

    # Endpoint discovery + token exchange.
    try:
        endpoints = _get_endpoints(config)
    except oidc_mod.ConfigError as e:
        logger.error("oidc callback: discovery failed: %s", e)
        raise HTTPException(status_code=503, detail="OIDC discovery failed")

    try:
        id_token = oidc_mod.exchange_code_for_id_token(
            code, config, endpoints, oidc_mod.HttpxClient(),
        )
    except oidc_mod.TokenExchangeError as e:
        logger.warning("oidc callback: token exchange failed: %s", e)
        raise HTTPException(status_code=401, detail="sign-in failed")

    # Validate ID token end-to-end.
    try:
        identity = oidc_mod.validate_id_token(
            id_token, config, endpoints,
            expected_nonce=cookie_nonce,
            jwks_cache=_get_jwks_cache(),
        )
    except oidc_mod.WorkspaceRejected as e:
        logger.warning("oidc callback: workspace rejected: %s", e)
        raise HTTPException(status_code=403, detail="workspace not allowed")
    except oidc_mod.TokenValidationError as e:
        logger.warning("oidc callback: token validation failed: %s", e)
        raise HTTPException(status_code=401, detail="sign-in failed")

    # Resolve email → iam-jit User.
    user_store = getattr(request.app.state, "user_store", None)
    if user_store is None:
        logger.error("oidc callback: user_store not on app.state")
        raise HTTPException(status_code=500, detail="server misconfigured")

    user_id = f"email:{identity.email}"
    try:
        user = user_store.get(user_id)
    except (UserNotFound, KeyError):
        logger.info(
            "oidc callback: authenticated %s but no iam-jit user exists",
            identity.email,
        )
        # 403 here makes the failure mode clearer than 401 — they
        # ARE authenticated; they just lack an iam-jit account.
        raise HTTPException(
            status_code=403,
            detail=(
                "You authenticated successfully but no iam-jit user "
                "exists for this email. Ask an admin to register you."
            ),
        )

    if not getattr(user, "enabled", True):
        logger.info("oidc callback: user %s is disabled", user.id)
        raise HTTPException(status_code=403, detail="account disabled")

    # All checks passed. Issue iam-jit session cookie + record
    # MFA presence for downstream AssumeRole.
    session_cookie = auth_mod.sign_session(_get_secret(), user.id)

    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        "iam_jit_session",
        session_cookie,
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path="/",
    )
    if identity.mfa:
        # Per [[mfa-compliance-strategy]] — record MFA assertion
        # for downstream `aws:MultiFactorAuthPresent` propagation.
        # WB9-01 closure: bind the MFA assertion to the specific
        # user.id. Previously the signed payload was just b"true",
        # which means a captured MFA cookie from user A could be
        # transplanted onto user B's session. Binding to user.id
        # makes the cookie only valid for the same user.
        mfa_payload = f"mfa:{user.id}".encode()
        mfa_signed = _signer("oidc-mfa").sign(mfa_payload).decode()
        resp.set_cookie(
            "iam_jit_session_mfa",
            mfa_signed,
            httponly=True,
            secure=_cookie_secure(),
            samesite="lax",
            path="/",
        )

    # Clear the transient OIDC cookies.
    for name in (_STATE_COOKIE_NAME, _NONCE_COOKIE_NAME):
        resp.delete_cookie(name, path="/api/v1/auth/oidc/")

    # Audit.
    try:
        from .. import audit
        audit.emit(
            actor=user.id,
            kind="auth.signin",
            summary=f"OIDC sign-in via {identity.provider}",
            details={
                "provider": identity.provider,
                "sub": identity.sub,
                "mfa": identity.mfa,
                "issued_at": identity.issued_at,
            },
        )
    except Exception:
        pass  # audit best-effort

    return resp


def _cookie_secure() -> bool:
    """Cookies marked Secure unless running in dev/test mode.

    WB9-07 closure: delegate to the canonical
    `auth.is_dev_insecure_active()` rather than reading the env var
    directly, so the single-source-of-truth gate from
    [[adversarial-loop-process]] applies uniformly. Previously a
    direct env read bypassed the auth-module's centralized check
    (which has additional defensive logic — see auth.py).
    """
    return not auth_mod.is_dev_insecure_active()
