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
    secret = os.environ.get("IAM_JIT_MAGIC_LINK_SECRET")
    if not secret:
        # Allow local-dev fallback ONLY if the dev override flag is set;
        # production must always have the real secret configured.
        if os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") == "1":
            return "dev-only-insecure-secret-do-not-use-in-prod"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="IAM_JIT_MAGIC_LINK_SECRET is not configured",
        )
    return secret


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
        # failures. The previous fail-open path silently re-enabled
        # banned users during a transient outage — the detection log
        # still fired, but enforcement did not. Now: 503 so the
        # operator's alarm catches it and a real investigation
        # starts. Override via `IAM_JIT_BANS_FAIL_OPEN=1` for the
        # rare case where availability is preferred over enforcement.
        import logging
        import os as _os

        logging.getLogger("iam_jit.bans").exception(
            "ban check in middleware failed for user_id=%s", user.id
        )
        if (_os.environ.get("IAM_JIT_BANS_FAIL_OPEN") or "").lower() not in {
            "1", "true", "yes"
        }:
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
