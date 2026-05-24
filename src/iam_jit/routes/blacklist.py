"""Admin API for managing the action blacklist.

Endpoints (all require admin auth via the existing iam-jit auth
middleware):

  GET    /api/v1/admin/blacklist            list current rules
  POST   /api/v1/admin/blacklist            add or replace a rule
  DELETE /api/v1/admin/blacklist/{rule_id}  remove a rule
  POST   /api/v1/admin/blacklist/templates/{template_name}
                                            install all rules from a template

The store is the module-level singleton in `iam_jit.blacklist` (set
via `blacklist.set_blacklist_store`). Pre-2026-05-24 this singleton
lived in `iam_jit.routes.score`; it moved when the hosted scoring
Lambda was dropped per [[no-hosted-saas]] restoration.
"""

from __future__ import annotations

import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .. import audit, blacklist
from ..middleware import current_user
from ..users_store import User

router = APIRouter(prefix="/api/v1/admin/blacklist", tags=["admin", "blacklist"])


def _require_admin(user: User) -> None:
    if not getattr(user, "is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Blacklist management requires admin role.",
        )


class BlacklistRuleIn(BaseModel):
    rule_id: str = Field(
        ..., min_length=3, max_length=64,
        pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$",
        description=(
            "Stable short identifier. Lower-case alphanumeric + hyphens. "
            "Used in audit logs."
        ),
    )
    pattern: str = Field(
        ..., min_length=3, max_length=128,
        description="Glob pattern on the `service:Action` form. Bare `*` is rejected.",
    )
    reason: str = Field(
        ..., min_length=20, max_length=500,
        description=(
            "Human-readable explanation for the rule. Surfaces in audit "
            "logs and (for authenticated callers) in the rejection "
            "response. Required to be non-trivial — short reasons aren't "
            "actionable for the operator triaging audit alerts."
        ),
    )


class BlacklistRuleOut(BaseModel):
    rule_id: str
    pattern: str
    reason: str
    added_by: str
    added_at: int


def _rule_to_out(r: blacklist.BlacklistRule) -> BlacklistRuleOut:
    return BlacklistRuleOut(
        rule_id=r.rule_id, pattern=r.pattern, reason=r.reason,
        added_by=r.added_by, added_at=r.added_at,
    )


@router.get("", response_model=list[BlacklistRuleOut])
def list_blacklist(
    user: Annotated[User, Depends(current_user)],
) -> list[BlacklistRuleOut]:
    _require_admin(user)
    store = blacklist.get_blacklist_store()
    return [_rule_to_out(r) for r in store.list_rules()]


@router.post("", response_model=BlacklistRuleOut, status_code=status.HTTP_201_CREATED)
def add_blacklist_rule(
    payload: BlacklistRuleIn,
    user: Annotated[User, Depends(current_user)],
) -> BlacklistRuleOut:
    _require_admin(user)
    store = blacklist.get_blacklist_store()
    rule = blacklist.BlacklistRule(
        rule_id=payload.rule_id,
        pattern=payload.pattern,
        reason=payload.reason,
        added_by=user.id,
        added_at=int(time.time()),
    )
    try:
        store.put_rule(rule)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    try:
        audit.emit(
            actor=user.id,
            kind="admin.blacklist.rule_added",
            summary=f"blacklist rule {rule.rule_id!r} added by {user.id}",
            details={
                "rule_id": rule.rule_id,
                "pattern": rule.pattern,
                "reason": rule.reason,
            },
        )
    except Exception:
        pass
    return _rule_to_out(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_blacklist_rule(
    rule_id: str,
    user: Annotated[User, Depends(current_user)],
) -> None:
    _require_admin(user)
    store = blacklist.get_blacklist_store()
    store.delete_rule(rule_id)
    try:
        audit.emit(
            actor=user.id,
            kind="admin.blacklist.rule_deleted",
            summary=f"blacklist rule {rule_id!r} deleted by {user.id}",
            details={"rule_id": rule_id},
        )
    except Exception:
        pass


@router.post("/templates/{template_name}", response_model=list[BlacklistRuleOut])
def install_template(
    template_name: str,
    user: Annotated[User, Depends(current_user)],
) -> list[BlacklistRuleOut]:
    """Install all rules from a named starter template.

    Templates available: ban-catastrophic-actions, ban-credential-minting,
    ban-iam-escalation-primitives, ban-audit-evasion.

    Existing rules with the same rule_id are overwritten (idempotent).
    """
    _require_admin(user)
    if template_name not in blacklist.TEMPLATES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Unknown template {template_name!r}. Available: "
                + ", ".join(sorted(blacklist.TEMPLATES))
            ),
        )
    store = blacklist.get_blacklist_store()
    factory = blacklist.TEMPLATES[template_name]
    installed: list[blacklist.BlacklistRule] = []
    for rule in factory():
        # Tag the installer in `added_by` so audit logs know who applied
        # the template (not just "template:...").
        rule_with_actor = blacklist.BlacklistRule(
            rule_id=rule.rule_id,
            pattern=rule.pattern,
            reason=rule.reason,
            added_by=f"{user.id} via {rule.added_by}",
            added_at=int(time.time()),
        )
        store.put_rule(rule_with_actor)
        installed.append(rule_with_actor)
    try:
        audit.emit(
            actor=user.id,
            kind="admin.blacklist.template_installed",
            summary=(
                f"blacklist template {template_name!r} installed "
                f"by {user.id} ({len(installed)} rules)"
            ),
            details={
                "template": template_name,
                "rule_ids": [r.rule_id for r in installed],
            },
        )
    except Exception:
        pass
    return [_rule_to_out(r) for r in installed]


@router.get("/templates", response_model=list[str])
def list_templates(
    user: Annotated[User, Depends(current_user)],
) -> list[str]:
    """List the names of available starter templates."""
    _require_admin(user)
    return sorted(blacklist.TEMPLATES.keys())
