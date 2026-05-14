"""FastAPI dependency injection for authentication and authorization.

Routes declare what role they need via a `Depends(...)` parameter; the
middleware extracts the current user (or raises 401) and verifies the
required role (or raises 403). All HTTP error shapes are uniform JSON.
"""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature

import time

from .api_tokens_store import APITokenNotFound, APITokenStore
from .auth import extract_iam_principal, hash_token, normalize_iam_id, verify_session
from .users_store import User, UserNotFound, UserStore


def get_user_store(request: Request) -> UserStore:
    """Pull the configured UserStore off the FastAPI app state."""
    store = getattr(request.app.state, "user_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="user_store is not configured",
        )
    return store


def get_api_tokens_store(request: Request) -> APITokenStore | None:
    """Return the API tokens store if configured. Bearer-token auth requires it."""
    return getattr(request.app.state, "api_tokens_store", None)


def get_request_store(request: Request) -> Any:
    store = getattr(request.app.state, "request_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="request_store is not configured",
        )
    return store


def get_accounts_store(request: Request) -> Any:
    store = getattr(request.app.state, "accounts_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="accounts_store is not configured",
        )
    return store


def _get_secret() -> str:
    """Return the magic-link / session signing secret.

    Round-5 WB CRIT closure: the prior implementation returned a
    hard-coded, repo-committed string when
    `IAM_JIT_DEV_INSECURE_SECRET=1` was set and the real secret
    was missing. That string is public on GitHub. An attacker who
    sees `IAM_JIT_DEV_INSECURE_SECRET=1` in a deployed prod env
    (the `.env.example` bleed scenario the round-4 audit explicitly
    modeled) could forge magic-links + session cookies + API
    tokens. Full account takeover.

    Closure: the dev-insecure fallback now gates on
    `auth.is_dev_insecure_active()` — same single-source-of-truth
    helper that gates CSRF + Secure-cookie + magic-link delivery.
    Refuses to fall back in Lambda environments unless the operator
    explicitly opted in via `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1`.
    And the dev fallback no longer uses a fixed string — it derives
    a per-process random secret on first use, so even with the dev
    flag on in Lambda (explicit opt-in), an attacker reading the
    repo doesn't already have your signing key.
    """
    secret = os.environ.get("IAM_JIT_MAGIC_LINK_SECRET")
    if secret:
        return secret

    from .auth import is_dev_insecure_active

    if is_dev_insecure_active():
        return _ephemeral_dev_secret()

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="IAM_JIT_MAGIC_LINK_SECRET is not configured",
    )


_EPHEMERAL_DEV_SECRET: str | None = None


def _ephemeral_dev_secret() -> str:
    """Generate (once per process) a random dev secret. Replaces
    the previous repo-committed fallback string. Sessions / magic
    links signed with this secret survive the lifetime of the
    Python process and no longer — adequate for local-dev / tests
    where the operator explicitly opted into dev-insecure mode."""
    global _EPHEMERAL_DEV_SECRET
    if _EPHEMERAL_DEV_SECRET is None:
        import secrets as _secrets

        _EPHEMERAL_DEV_SECRET = _secrets.token_hex(32)
    return _EPHEMERAL_DEV_SECRET


def _reset_ephemeral_dev_secret_for_tests() -> None:
    """Test helper — clear the cached per-process dev secret so
    each test starts fresh."""
    global _EPHEMERAL_DEV_SECRET
    _EPHEMERAL_DEV_SECRET = None


def _identify_user(request: Request, user_store: UserStore) -> User:
    auth_mode = (os.environ.get("IAM_JIT_AUTH_MODE") or "local").lower()

    # 1. Try Authorization: Bearer <api-token>
    auth_header = request.headers.get("authorization") or ""
    if auth_header.lower().startswith("bearer "):
        raw = auth_header.split(" ", 1)[1].strip()
        if not raw.startswith("iamjit_"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid bearer token format",
                headers={"WWW-Authenticate": "Bearer"},
            )
        tokens_store = get_api_tokens_store(request)
        if tokens_store is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="api_tokens_store is not configured",
            )
        try:
            record = tokens_store.get_by_hash(hash_token(raw))
        except APITokenNotFound:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="bearer token not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            user = user_store.get(record.user_id)
        except UserNotFound:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"token's user {record.user_id} is no longer in the iam-jit user list",
            )
        if not user.enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"token's user {record.user_id} is disabled",
            )
        # Best-effort last-used update.
        tokens_store.touch_last_used(record.token_hash, epoch_seconds=int(time.time()))
        return user

    # 2. aws_iam mode — Function URL has already validated SigV4.
    if auth_mode == "aws_iam":
        scope = request.scope.get("aws.event") if "aws.event" in request.scope else None
        principal = extract_iam_principal(scope or {})
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="aws_iam mode requires a SigV4-signed request",
            )
        user_id = normalize_iam_id(principal)
        try:
            return user_store.get(user_id)
        except UserNotFound:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"IAM principal {user_id} is not in the iam-jit user list",
            )

    # 3. local mode — signed session cookie.
    cookie = request.cookies.get("iam_jit_session")
    if not cookie:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not authenticated",
        )
    try:
        user_id = verify_session(_get_secret(), cookie)
    except BadSignature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="session expired or invalid",
        )
    # BB3-01 closure: check the server-side revocation list. A
    # cookie value that was logged out / explicitly revoked is no
    # longer accepted, even if its signature is still valid.
    try:
        from . import session_revocation as _sr

        if _sr.get_default_store().is_revoked(cookie):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="session has been revoked",
            )
    except HTTPException:
        raise
    except Exception:
        # SESSION-REVOCATION-FAIL-OPEN-SILENT-BYPASS (round 4 WB
        # HIGH) closure: matches the BANS_FAIL_OPEN treatment.
        # Default 503; the `IAM_JIT_SESSION_REVOCATION_FAIL_OPEN=1`
        # opt-out is preserved BUT every bypass invocation now
        # emits CRITICAL so any SIEM / alarm catches the silent
        # enforcement skip.
        import logging as _logging
        import os as _os

        _logging.getLogger("iam_jit.session_revocation").exception(
            "session-revocation check failed for user_id=%s", user_id
        )
        if (
            _os.environ.get("IAM_JIT_SESSION_REVOCATION_FAIL_OPEN") or ""
        ).lower() in {"1", "true", "yes"}:
            _logging.getLogger("iam_jit.session_revocation").critical(
                "SESSION_REVOCATION_FAIL_OPEN bypass invoked for "
                "user_id=%s — store error, but revocation enforcement "
                "was skipped because IAM_JIT_SESSION_REVOCATION_FAIL_"
                "OPEN=1 is set. ALARM ON THIS LOG.",
                user_id,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "session revocation check is temporarily "
                    "unavailable; please retry."
                ),
            )
    try:
        user = user_store.get(user_id)
    except UserNotFound:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"user {user_id} is no longer in the iam-jit user list",
        )
    if not user.enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"user {user_id} is disabled",
        )
    return user


def current_user(
    request: Request, user_store: Annotated[UserStore, Depends(get_user_store)]
) -> User:
    """Inject the authenticated user. Raises 401 if not authenticated.

    Banned users are also rejected here with 403 — the ban check
    happens for every authenticated route. We deliberately don't tell
    the user *why* they were banned (that would let an attacker probe
    the rules); the audit log carries the reason."""
    user = _identify_user(request, user_store)
    try:
        from . import bans as bans_mod

        if bans_mod.get_default_store().is_banned(user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="account suspended due to a detected policy violation",
            )
    except HTTPException:
        raise
    except Exception:
        # BAN-CHECK-FAIL-OPEN closure: fail CLOSED on bans-store
        # failures. Default behavior is 503. Operator opt-out via
        # `IAM_JIT_BANS_FAIL_OPEN=1` — but BANS-DDB-FAIL-OPEN-VIA-
        # ENV (round 3 WB MED) closure requires the opt-out to be
        # *loud*: every fail-open invocation emits a CRITICAL log
        # line so any SIEM / alarm picks it up. The default-quiet
        # fail-open posture is what made the round-1 finding
        # invisible to monitoring; this preserves the operator
        # escape hatch but kills the silent-bypass shape.
        import logging
        import os as _os

        logging.getLogger("iam_jit.bans").exception(
            "ban check in middleware failed for user_id=%s", user.id
        )
        if (_os.environ.get("IAM_JIT_BANS_FAIL_OPEN") or "").lower() in {
            "1", "true", "yes"
        }:
            logging.getLogger("iam_jit.bans").critical(
                "BANS_FAIL_OPEN bypass invoked for user_id=%s — store "
                "error, but enforcement was skipped because "
                "IAM_JIT_BANS_FAIL_OPEN=1 is set. ALARM ON THIS LOG.",
                user.id,
            )
            return user
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "ban-status check is temporarily unavailable; please "
                "retry. Operators: set IAM_JIT_BANS_FAIL_OPEN=1 to "
                "prefer availability over enforcement."
            ),
        )
    return user


def require_requester(
    user: Annotated[User, Depends(current_user)],
) -> User:
    if not user.is_requester:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="requester role required")
    return user


def require_approver(
    user: Annotated[User, Depends(current_user)],
) -> User:
    if not user.is_approver:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="approver role required")
    return user


def require_admin(
    user: Annotated[User, Depends(current_user)],
) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    return user
