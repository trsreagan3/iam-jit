"""Per-user API tokens.

POST   /api/v1/tokens         Mint a new token for the caller
GET    /api/v1/tokens         List the caller's tokens (no raw values shown)
DELETE /api/v1/tokens/{hash}  Revoke a token by its hash

Tokens are HMAC-keyed bearer credentials. The raw token value is shown
exactly once at creation; subsequent reads return only the metadata.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..api_tokens_store import APITokenNotFound, APITokenRecord, APITokenStore
from ..auth import issue_api_token
from ..middleware import current_user, get_api_tokens_store
from ..users_store import User

router = APIRouter(prefix="/api/v1/tokens", tags=["tokens"])


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
    issued = issue_api_token(user.id, label=label)
    record = APITokenRecord(
        token_hash=issued.hash,
        user_id=issued.user_id,
        created_at=issued.created_at,
        label=issued.label,
    )
    store.put(record)
    return {
        "token": issued.raw,  # shown once
        "token_hash": issued.hash,
        "user_id": issued.user_id,
        "created_at": issued.created_at,
        "label": issued.label,
        "warning": (
            "This token is shown only once. Store it now — there's no way to retrieve "
            "it later. Use it as `Authorization: Bearer <token>` against the iam-jit API."
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
