"""Per-user API tokens.

POST   /api/v1/tokens         Mint a new token for the caller
GET    /api/v1/tokens         List the caller's tokens (no raw values shown)
DELETE /api/v1/tokens/{hash}  Revoke a token by its hash

Tokens are HMAC-keyed bearer credentials. The raw token value is shown
exactly once at creation; subsequent reads return only the metadata.
"""

from __future__ import annotations

import os
import threading
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..api_tokens_store import APITokenNotFound, APITokenRecord, APITokenStore
from ..auth import issue_api_token
from ..middleware import current_user, get_api_tokens_store
from ..users_store import User

router = APIRouter(prefix="/api/v1/tokens", tags=["tokens"])

_DEFAULT_TOKEN_CAP_PER_USER = 50

# TOKENS-PER-USER-CAP-TOCTOU (round 3 WB MED) closure + round-4
# regression fix: previous version used a defaulting dict that
# was NOT atomic on the cold path — two concurrent first-mints
# for the same user_id could each construct their own Lock and
# bypass mutual exclusion. Now uses `dict.setdefault` which IS
# atomic under the CPython GIL, so two racers get the SAME Lock
# object on first-create.
_PER_USER_MINT_LOCKS_REGISTRY: dict[str, threading.Lock] = {}


def _per_user_lock(user_id: str) -> threading.Lock:
    """Return the canonical per-user Lock for `user_id`, creating
    it idempotently."""
    fresh = threading.Lock()
    existing = _PER_USER_MINT_LOCKS_REGISTRY.setdefault(user_id, fresh)
    return existing


def _per_user_cap() -> int:
    raw = (os.environ.get("IAM_JIT_API_TOKEN_CAP_PER_USER") or "").strip()
    if not raw:
        return _DEFAULT_TOKEN_CAP_PER_USER
    try:
        n = int(raw)
        return max(1, n)
    except ValueError:
        return _DEFAULT_TOKEN_CAP_PER_USER


def _store_or_500(request: Request) -> APITokenStore:
    store = get_api_tokens_store(request)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="api_tokens_store is not configured",
        )
    return store


@router.post("", status_code=status.HTTP_201_CREATED)
def create_token(
    request: Request,
    payload: dict[str, Any] | None,
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    store = _store_or_500(request)
    label = (payload or {}).get("label")
    if label is not None and not isinstance(label, str):
        raise HTTPException(status_code=400, detail="label must be a string")

    # BB2-05 closure: per-user soft cap on active tokens. Operators
    # who genuinely need more can raise IAM_JIT_API_TOKEN_CAP_PER_USER.
    # The list_for_user → cap check → put sequence is wrapped in a
    # per-user lock to close the round-3 WB TOCTOU race (within a
    # single Lambda instance).
    cap = _per_user_cap()
    with _per_user_lock(user.id):
        existing = store.list_for_user(user.id)
        if len(existing) >= cap:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"per-user token cap reached ({cap}). Revoke unused "
                    f"tokens via DELETE /api/v1/tokens/{{hash}}, or raise "
                    f"IAM_JIT_API_TOKEN_CAP_PER_USER."
                ),
            )

        issued = issue_api_token(user.id, label=label)

        # Phase-1 MFA-at-issuance propagation (per
        # [[mfa-compliance-strategy]] PCI §8.6): if the human
        # authorizer's iam_jit_session_mfa cookie is valid + fresh
        # at this moment, stamp the timestamp onto the token record.
        # The per-action MFA gate later checks freshness against THIS
        # field for bearer-authenticated requests. Agent inherits
        # the human's MFA assertion as long as the token is fresher
        # than the deployment's IAM_JIT_MFA_STEP_UP_MAX_AGE_SECONDS.
        mfa_at_issuance: int | None = None
        try:
            from .. import mfa_gate as _mfa_gate
            from ..middleware import _get_secret as _auth_secret_getter
            mfa_cookie = request.cookies.get("iam_jit_session_mfa")
            if mfa_cookie:
                # Use a generous max_age here — we just want to know
                # if MFA was asserted at all in the recent past; the
                # per-action gate later does its own short-window
                # freshness check.
                mfa_result = _mfa_gate.verify(
                    cookie_value=mfa_cookie,
                    secret=_auth_secret_getter(),
                    expected_user_id=user.id,
                    max_age_seconds=24 * 3600,
                )
                if mfa_result.present:
                    mfa_at_issuance = int(issued.created_at)
        except Exception:
            # Best-effort — never let the MFA stamp block token mint.
            # The token still works; it just lacks MFA evidence and
            # high-risk grants will be blocked until the user
            # re-authenticates and mints a new token.
            pass

        record = APITokenRecord(
            token_hash=issued.hash,
            user_id=issued.user_id,
            created_at=issued.created_at,
            label=issued.label,
            mfa_at_issuance=mfa_at_issuance,
        )
        store.put(record)
    return {
        "token": issued.raw,  # shown once
        "token_hash": issued.hash,
        "user_id": issued.user_id,
        "created_at": issued.created_at,
        "label": issued.label,
        "mfa_at_issuance": mfa_at_issuance,
        "warning": (
            "This token is shown only once. Store it now — there's no way to retrieve "
            "it later. Use it as `Authorization: Bearer <token>` against the iam-jit API."
        ),
        "mfa_note": (
            "Token carries MFA-at-issuance evidence — high-risk grants will "
            "be auto-approved up to IAM_JIT_MFA_STEP_UP_MAX_AGE_SECONDS after "
            "issuance, then require token re-mint."
            if mfa_at_issuance is not None
            else "Token was minted WITHOUT a fresh MFA assertion in the "
            "user's session. High-risk grants from this token will be "
            "blocked. Re-authenticate via OIDC and mint a new token to "
            "carry MFA evidence."
        ),
    }


@router.get("")
def list_my_tokens(
    request: Request,
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    store = _store_or_500(request)
    records = store.list_for_user(user.id)
    return {
        "tokens": [
            {
                "token_hash": r.token_hash,
                "label": r.label,
                "created_at": r.created_at,
                "last_used_at": r.last_used_at,
            }
            for r in records
        ],
        "count": len(records),
    }


@router.delete("/{token_hash}")
def revoke_token(
    token_hash: str,
    request: Request,
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    store = _store_or_500(request)
    try:
        record = store.get_by_hash(token_hash)
    except APITokenNotFound:
        # Idempotent: revoking a non-existent token is fine.
        return {"revoked": False, "reason": "not_found"}
    if record.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="cannot revoke another user's token")
    store.delete(token_hash)
    return {"revoked": True, "token_hash": token_hash}
