"""User management endpoints (admin-only, plus the self GET).

GET    /api/v1/users/me           Current user info (any authenticated)
GET    /api/v1/users              List all users (admin)
POST   /api/v1/users              Create / replace a user (admin)
PATCH  /api/v1/users/{user_id}    Partial update (admin)
DELETE /api/v1/users/{user_id}    Disable or delete (admin)

In `file` mode (UserConfigSource=file), write operations return 409 — the
admin must edit the YAML and re-upload. The middleware fixes user lookups
through the same store either way.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from ..middleware import current_user, get_user_store, require_admin
from ..users_store import StoreReadOnly, User, UserNotFound, UserStore

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get("/me")
def me(user: Annotated[User, Depends(current_user)]) -> dict[str, Any]:
    """Return the calling user's identity + a small self-describing
    block telling agents how to mint their own API tokens and where to
    submit requests. The hints are stable contract — agents may rely on
    them to bootstrap without reading the README."""
    return {
        "id": user.id,
        "display_name": user.display_name,
        "roles": list(user.roles),
        "enabled": user.enabled,
        "agent_hints": {
            "mint_token": {
                "method": "POST",
                "path": "/api/v1/tokens",
                "body": {"label": "<descriptive label, e.g. 'claude-code laptop'>"},
                "auth": (
                    "Authorization: Bearer <existing-token>  OR  "
                    "Cookie: iam_jit_session=<session-cookie-from-magic-link>"
                ),
                "notes": (
                    "Token is returned in the response as 'token' — shown ONCE. "
                    "Store it; iam-jit only keeps the sha256 hash. "
                    "Use as 'Authorization: Bearer <token>' on all subsequent calls."
                ),
            },
            "list_my_tokens": {
                "method": "GET",
                "path": "/api/v1/tokens",
                "notes": "Returns hashes only; raw values are never recoverable.",
            },
            "revoke_token": {
                "method": "DELETE",
                "path": "/api/v1/tokens/<token_hash>",
            },
            "submit_request_structured": {
                "method": "POST",
                "path": "/api/v1/requests",
                "schema": "schemas/request.schema.json",
                "notes": (
                    "Pass a fully-formed request body. Server stamps id, "
                    "owner, history, runs schema validation + risk review."
                ),
            },
            "agent_mcp_workflow": {
                "method": "MCP",
                "transport": "stdio",
                "tools": [
                    "list_templates",
                    "get_template",
                    "score_iam_policy",
                    "submit_policy",
                ],
                "notes": (
                    "Agents author policies via the iam-jit MCP server "
                    "with their own LLM + codebase context, then submit "
                    "via submit_policy. The conversational intake API "
                    "(/api/v1/intake/turn) was removed in 0.4.0 — see "
                    "docs/AGENTS.md for the agent-driven reduction loop."
                ),
            },
            "list_my_requests": {
                "method": "GET",
                "path": "/api/v1/requests",
                "query": {
                    "state": "<filter by state>",
                    "hide_cancelled": "true to suppress cancelled requests",
                },
            },
            "assume_instructions": {
                "method": "GET",
                "path": "/api/v1/requests/<id>/assume",
                "notes": (
                    "After approval, returns the aws sts assume-role snippet, "
                    "profile block, and AI-tool usage hints."
                ),
            },
            "rate_limit": "none yet",
        },
    }


@router.get("")
def list_users(
    user_store: Annotated[UserStore, Depends(get_user_store)],
    _: Annotated[User, Depends(require_admin)],
    include_disabled: bool = False,
) -> dict[str, Any]:
    users = user_store.list(include_disabled=include_disabled)
    return {
        "users": [_serialize(u) for u in users],
        "count": len(users),
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def create_or_replace_user(
    payload: dict[str, Any],
    user_store: Annotated[UserStore, Depends(get_user_store)],
    _: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    new_user = _user_from_payload(payload)
    try:
        user_store.put(new_user)
    except StoreReadOnly as e:
        raise HTTPException(status_code=409, detail=str(e))
    return _serialize(new_user)


@router.patch("/{user_id}")
def update_user(
    user_id: str,
    payload: dict[str, Any],
    user_store: Annotated[UserStore, Depends(get_user_store)],
    acting_admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    try:
        existing = user_store.get(user_id)
    except UserNotFound:
        raise HTTPException(status_code=404, detail=f"user {user_id} not found")

    roles = payload.get("roles")
    enabled = payload.get("enabled")
    display_name = payload.get("display_name")
    notes = payload.get("notes")

    # BB2-10 closure (round 2 MED, escalated round 5 HIGH after
    # being open 3+ rounds): refuse self-demotion AND refuse the
    # last-admin transition. A single CSRF click or admin lapse
    # used to be able to drop the deployment into a no-admin
    # state that required data-plane recovery.
    had_admin_role = "admin" in existing.roles
    target_after_roles = tuple(roles) if roles is not None else existing.roles
    will_have_admin_role = "admin" in target_after_roles
    will_be_disabled = (
        not bool(enabled) if enabled is not None else not existing.enabled
    )

    losing_admin = had_admin_role and (
        not will_have_admin_role or will_be_disabled
    )

    if losing_admin and existing.id == acting_admin.id:
        raise HTTPException(
            status_code=409,
            detail=(
                "refusing self-demotion: an admin cannot remove their own "
                "admin role or disable their own account. Ask another "
                "admin to make this change."
            ),
        )

    if losing_admin:
        # Count remaining admins after the change. If zero, refuse.
        try:
            all_users = list(user_store.list(include_disabled=False))
        except Exception:
            # Store doesn't support listing — fail closed for
            # safety. The self-demote guard above already covers
            # the most common no-admin-left scenario (admin
            # demoting themselves); this remaining branch protects
            # the cross-admin demotion case. If the store can't
            # enumerate, an admin can still recover by promoting
            # another user first.
            raise HTTPException(
                status_code=409,
                detail=(
                    "cannot verify admin count via the user store; "
                    "refusing role-removal as a safety measure. "
                    "Promote another user to admin first, then "
                    "retry."
                ),
            )
        remaining_admins = [
            u
            for u in all_users
            if "admin" in u.roles
            and u.enabled
            and u.id != existing.id
        ]
        if not remaining_admins:
            raise HTTPException(
                status_code=409,
                detail=(
                    "refusing last-admin demotion: at least one enabled "
                    "admin must remain. Promote another user to admin "
                    "first, then retry."
                ),
            )

    updated = User(
        id=existing.id,
        roles=target_after_roles,
        enabled=bool(enabled) if enabled is not None else existing.enabled,
        display_name=display_name if display_name is not None else existing.display_name,
        notes=notes if notes is not None else existing.notes,
    )
    try:
        user_store.put(updated)
    except StoreReadOnly as e:
        raise HTTPException(status_code=409, detail=str(e))
    return _serialize(updated)


@router.delete("/{user_id}")
def delete_user(
    user_id: str,
    user_store: Annotated[UserStore, Depends(get_user_store)],
    _: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    try:
        user_store.delete(user_id)
    except StoreReadOnly as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {"deleted": True, "user_id": user_id}


def _serialize(u: User) -> dict[str, Any]:
    return {
        "id": u.id,
        "roles": list(u.roles),
        "enabled": u.enabled,
        "display_name": u.display_name,
        "notes": u.notes,
    }


def _user_from_payload(payload: dict[str, Any]) -> User:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")
    user_id = payload.get("id")
    roles = payload.get("roles") or []
    if not isinstance(user_id, str) or not (
        user_id.startswith("email:") or user_id.startswith("iam:")
    ):
        raise HTTPException(status_code=400, detail="id must start with 'email:' or 'iam:'")
    if not isinstance(roles, list) or not roles:
        raise HTTPException(status_code=400, detail="roles must be a non-empty list")
    valid_roles = {"requester", "approver", "admin"}
    for r in roles:
        if r not in valid_roles:
            raise HTTPException(status_code=400, detail=f"invalid role: {r!r}")
    return User(
        id=user_id,
        roles=tuple(roles),
        enabled=bool(payload.get("enabled", True)),
        display_name=payload.get("display_name"),
        notes=payload.get("notes"),
    )
