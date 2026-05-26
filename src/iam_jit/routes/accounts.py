"""Account onboarding + registry routes.

iam-jit cannot bootstrap roles into a destination AWS account on its
own — that would require pre-existing privileged access there, which is
the chicken-and-egg this whole tool is trying to avoid. These routes
return the artifacts the human (or agent acting on their behalf) needs
to run themselves; once they've deployed the CFN stack, they `POST` the
resulting ARNs back here and iam-jit starts treating the account as a
valid destination.

Endpoints:
  POST   /api/v1/accounts/onboarding/preview   Render artifact set (no state).
  POST   /api/v1/accounts                      Register an account.
  GET    /api/v1/accounts                      List registered accounts.
  GET    /api/v1/accounts/{account_id}         Read one account.
  DELETE /api/v1/accounts/{account_id}         Deregister.

All write endpoints (and listing) are admin-only.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import audit, onboarding
from ..audit_admin_action import emit_iam_jit_admin_action
from ..accounts_store import (
    Account,
    AccountAlreadyExists,
    AccountNotFound,
    AccountStore,
    AccountStoreReadOnly,
    utcnow_iso,
)
from ..middleware import get_accounts_store, require_admin
from ..users_store import User

router = APIRouter(prefix="/api/v1/accounts", tags=["accounts"])


# ---- Onboarding preview (no registry write) ----


class OnboardingPreviewRequest(BaseModel):
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    region: str = "us-east-1"
    account_alias: str | None = None
    hub_account_id: str | None = Field(
        default=None,
        pattern=r"^[0-9]{12}$",
        description="Defaults to IAM_JIT_HUB_ACCOUNT_ID env var.",
    )
    hub_lambda_role_name: str = "iam-jit-lambda-execution"
    provisioner_role_name: str = "iam-jit-provisioner"
    discovery_role_name: str = "iam-jit-discovery"
    enable_discovery: bool = True
    provisioning_mode: str = Field(default="classic_iam", pattern="^(classic_iam|identity_center|both)$")
    allowed_permission_set_arns: list[str] | None = None


@router.post("/onboarding/preview")
def preview_onboarding(
    body: OnboardingPreviewRequest,
    _: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Render the artifact set for adding a new AWS account.

    Returns the CloudFormation template, a Terraform skeleton, the CLI
    command sequence, the expected role ARNs/ExternalIds, and the
    post-deploy registration payload. iam-jit does not run any of these —
    they are returned for the caller (human or agent) to execute.
    """
    try:
        plan = onboarding.render_plan(**body.model_dump(exclude_none=True))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return plan.to_dict()


# ---- Registry CRUD ----


class RegisterAccountRequest(BaseModel):
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    provisioner_role_arn: str = Field(pattern=r"^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$")
    provisioner_external_id: str = Field(min_length=1)
    provisioning_mode: str = Field(pattern="^(classic_iam|identity_center|both)$")
    alias: str | None = None
    regions: list[str] = Field(default_factory=list)
    discovery_role_arn: str | None = Field(
        default=None, pattern=r"^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$"
    )
    discovery_external_id: str | None = None
    notes: str | None = None
    enabled: bool = True


def _to_response(a: Account) -> dict[str, Any]:
    return {
        "account_id": a.account_id,
        "alias": a.alias,
        "regions": list(a.regions),
        "provisioner_role_arn": a.provisioner_role_arn,
        "provisioner_external_id": a.provisioner_external_id,
        "discovery_role_arn": a.discovery_role_arn,
        "discovery_external_id": a.discovery_external_id,
        "provisioning_mode": a.provisioning_mode,
        "registered_at": a.registered_at,
        "registered_by": a.registered_by,
        "notes": a.notes,
        "enabled": a.enabled,
    }


@router.post("", status_code=201)
def register_account(
    body: RegisterAccountRequest,
    user: Annotated[User, Depends(require_admin)],
    store: Annotated[AccountStore, Depends(get_accounts_store)],
) -> dict[str, Any]:
    """Register a new destination account.

    Call this AFTER deploying the CloudFormation stack returned by
    /onboarding/preview. The role ARNs and ExternalIds in the body must
    match the stack outputs — iam-jit does not call AWS to verify them.
    Verification (sts:AssumeRole) happens lazily on the first provision.
    """
    if body.account_id in {a.account_id for a in store.list(include_disabled=True)}:
        raise HTTPException(
            status_code=409,
            detail=f"account {body.account_id} is already registered",
        )
    account = Account(
        account_id=body.account_id,
        provisioner_role_arn=body.provisioner_role_arn,
        provisioner_external_id=body.provisioner_external_id,
        provisioning_mode=body.provisioning_mode,
        alias=body.alias,
        regions=tuple(body.regions),
        discovery_role_arn=body.discovery_role_arn,
        discovery_external_id=body.discovery_external_id,
        registered_at=utcnow_iso(),
        registered_by=user.id,
        notes=body.notes,
        enabled=body.enabled,
    )
    try:
        store.put(account)
    except AccountStoreReadOnly as e:
        raise HTTPException(status_code=409, detail=str(e))
    except OSError as e:
        raise HTTPException(
            status_code=500,
            detail=f"account registry write failed: {e}",
        )
    audit.emit(
        actor=user.id,
        kind="account.registered",
        summary=f"registered account {account.account_id}",
        details={
            "account_id": account.account_id,
            "alias": account.alias,
            "provisioning_mode": account.provisioning_mode,
            "has_discovery": account.has_discovery,
        },
    )
    # OCSF v1.1.0 class 6003 admin-action event (#278 / #660).
    # #660: replaced bouncer.proxy-only emit with emit_iam_jit_admin_action()
    # so the OCSF event also lands in audit.jsonl in local mode (per #632).
    # #661: logger.warning on failure instead of silent except-pass.
    emit_iam_jit_admin_action(
        kind="account.registered",
        actor=user.id,
        target_kind="aws_account",
        target_id=account.account_id,
        source="api",
        extra={
            "alias": account.alias,
            "provisioning_mode": account.provisioning_mode,
            "has_discovery": account.has_discovery,
        },
    )
    return _to_response(account)


@router.get("")
def list_accounts(
    _: Annotated[User, Depends(require_admin)],
    store: Annotated[AccountStore, Depends(get_accounts_store)],
    include_disabled: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    """List registered accounts."""
    accounts = store.list(include_disabled=include_disabled)
    return {"accounts": [_to_response(a) for a in accounts], "count": len(accounts)}


@router.get("/{account_id}")
def get_account(
    account_id: str,
    _: Annotated[User, Depends(require_admin)],
    store: Annotated[AccountStore, Depends(get_accounts_store)],
) -> dict[str, Any]:
    try:
        return _to_response(store.get(account_id))
    except AccountNotFound:
        raise HTTPException(status_code=404, detail=f"no account registered with id {account_id}")


@router.delete("/{account_id}")
def deregister_account(
    account_id: str,
    user: Annotated[User, Depends(require_admin)],
    store: Annotated[AccountStore, Depends(get_accounts_store)],
) -> dict[str, Any]:
    """Deregister a destination account from iam-jit.

    This does NOT delete the IAM roles in the destination account — the
    same agent/human who deployed the CFN stack is responsible for
    deleting it. Deregistering here just stops iam-jit from treating the
    account as a valid target.
    """
    try:
        store.delete(account_id)
    except AccountNotFound:
        raise HTTPException(status_code=404, detail=f"no account registered with id {account_id}")
    except AccountStoreReadOnly as e:
        raise HTTPException(status_code=409, detail=str(e))
    except OSError as e:
        raise HTTPException(
            status_code=500,
            detail=f"account registry write failed: {e}",
        )
    audit.emit(
        actor=user.id,
        kind="account.deregistered",
        summary=f"deregistered account {account_id}",
        details={"account_id": account_id},
    )
    # OCSF v1.1.0 class 6003 admin-action event (#278 / #660).
    # #660: replaced bouncer.proxy-only emit with emit_iam_jit_admin_action()
    # so the OCSF event also lands in audit.jsonl in local mode (per #632).
    # #661: logger.warning on failure instead of silent except-pass.
    emit_iam_jit_admin_action(
        kind="account.deregistered",
        actor=user.id,
        target_kind="aws_account",
        target_id=account_id,
        source="api",
    )
    return {"deregistered": True, "account_id": account_id}
