"""Cross-account role rediscovery.

For each registered destination account, assume its ProvisionerRole and
list every IAM role under `/iam-jit/` (the path-prefix iam-jit uses for
everything it provisions). Reconcile the AWS-side reality against
iam-jit's request store and return three buckets:

SECURITY NOTE — name+tag spoofing:

  iam-jit identifies "its own" roles by the combination of (a) IAM
  path `/iam-jit/`, (b) role name pattern `iam-jit-grant-<id>`, and
  (c) the `managed-by=iam-jit` tag. Any IAM principal in a
  destination account that already has `iam:CreateRole` and
  `iam:TagRole` CAN forge a role that satisfies all three conditions.
  If they do, iam-jit will:

    - report it as 'orphan' (or 'stale' if the synthetic expires-at
      is in the past) in the rediscovery report, AND
    - allow an admin to force-delete it through this module.

  The realistic threat model: an attacker with destination-account
  IAM-write access doesn't need to bait iam-jit — they already have
  enough privilege to do anything. So the spoofing surface buys them
  nothing they can't already do directly. We document it because
  operators sometimes confuse "scoped by name+tag" with "scoped by
  cryptographic provenance" — it isn't. The destination account's
  IAM admin is in the trust boundary; if you don't trust them, the
  problem is bigger than iam-jit.

  Operators who want stronger isolation can additionally bind the
  destination ProvisionerRole's IAM policy to a condition that the
  caller's session matches a known iam-jit deployment ARN — see
  infrastructure/destination-account.yaml.

  - **known**: a row for every iam-jit role found in AWS that the local
    request store also knows about (matched on the `request-id` tag).
  - **orphans**: roles tagged `managed-by=iam-jit` that exist in AWS but
    have NO matching request in the store. Either the store was lost
    (disaster recovery), the role was provisioned by a different
    iam-jit deployment writing to the same account, or someone hand-
    crafted a role under our path. Operator must decide whether to
    delete the role, import it, or leave it.
  - **zombies**: requests in the store with `state=active` and a
    populated `status.provisioned.role_arn`, but the IAM role no longer
    exists in AWS. Either someone hand-deleted the role or our expiry
    sweep ran but the lifecycle transition didn't persist.

This is a read-only operation. No state changes. The caller (the admin
endpoint) gets a report and decides what to do.

Why scan account-by-account: ResourceGroupsTaggingAPI requires
`tag:GetResources` in every region, and IAM is global anyway. We use
`iam:ListRoles --path-prefix /iam-jit/` which is exactly one paginated
call per account — cheap and bounded.
"""

from __future__ import annotations

import datetime as _dt
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from .accounts_store import Account, AccountStore
from .provision import (
    DestinationAccessDenied,
    ProvisionerAssumeFailed,
    _assume_provisioner_role,
    _is_access_denied,
)
from .store import RequestStore


logger = logging.getLogger("iam_jit.rediscover")


_REQUEST_ID_TAG = "request-id"
_MANAGED_BY_TAG = "managed-by"


@dataclass(frozen=True)
class DiscoveredRole:
    """One iam-jit-managed role observed in AWS."""

    account_id: str
    role_name: str
    role_arn: str
    request_id: str
    """Empty string when the role has no `request-id` tag (an orphan
    where the tag was stripped or never set)."""
    expires_at: str
    """Empty string when missing — admin should treat that as "no
    expiry signal", not "expired"."""
    requester: str
    deployment: str
    tags: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AccountReconciliation:
    """Per-account reconciliation result."""

    account_id: str
    alias: str
    success: bool
    error: str = ""
    """Populated only when success=False — typed error class name and
    short message, e.g. 'DestinationAccessDenied: iam:ListRoles ...'."""
    roles: list[DiscoveredRole] = field(default_factory=list)


@dataclass(frozen=True)
class ReconciliationReport:
    """Full output of a rediscovery sweep across all registered accounts.

    Five buckets:
      - **known**: AWS role + matching active request — steady state.
      - **stale**: AWS role still exists, request says active OR
        revoked, but the role is past its `expires-at` tag — cleanup
        should have deleted this and didn't. Surface to admin so they
        can force-delete.
      - **orphans**: AWS role with NO matching request in the store.
        Either disaster-recovery loss or different-deployment overlap.
      - **zombies**: request claims active+provisioned but AWS role is
        gone. Manual deletion or a sweep that didn't persist.
      - **errors**: per-account failures (lost access, STS denied,
        unexpected exception). When this list is non-empty, every
        bucket above is INCOMPLETE — agents and humans must understand
        that absence-of-evidence is not evidence-of-absence."""

    generated_at: str
    accounts: list[AccountReconciliation]
    known: list[dict[str, Any]] = field(default_factory=list)
    stale: list[dict[str, Any]] = field(default_factory=list)
    orphans: list[dict[str, Any]] = field(default_factory=list)
    zombies: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    inaccessible_accounts: list[dict[str, Any]] = field(default_factory=list)
    """Accounts where iam-jit could not enumerate roles — these are
    blind spots. Same data as `errors` but pre-classified for the
    notification UX."""


def discover_roles_in_account(
    *,
    account: Account,
    sts_client: Any | None = None,
    iam_client_factory: Any | None = None,
) -> list[DiscoveredRole]:
    """List every iam-jit-managed role in `account`.

    Filters to `Path=/iam-jit/` AND `Tags[managed-by=iam-jit]` — both
    checks because (a) the path prefix may collect non-iam-jit roles
    if an operator hand-creates one for testing, and (b) tags alone are
    too easy to spoof.
    """
    if sts_client is None:
        import boto3

        sts_client = boto3.client("sts")
    creds = _assume_provisioner_role(
        sts_client, account, session_name=f"iam-jit-rediscover-{account.account_id}"[:64]
    )
    if iam_client_factory is None:
        def _default_factory(c: dict[str, str]) -> Any:
            import boto3 as _boto3

            return _boto3.client("iam", **c)

        iam_client_factory = _default_factory
    iam = iam_client_factory(creds)

    out: list[DiscoveredRole] = []
    paginator_marker: str | None = None
    while True:
        kwargs: dict[str, Any] = {"PathPrefix": "/iam-jit/"}
        if paginator_marker:
            kwargs["Marker"] = paginator_marker
        try:
            page = iam.list_roles(**kwargs)
        except Exception as e:
            if _is_access_denied(e):
                raise DestinationAccessDenied(
                    f"ProvisionerRole in account {account.account_id} cannot "
                    f"list roles under /iam-jit/: {e}",
                    operation="iam:ListRoles",
                ) from e
            raise

        for r in page.get("Roles") or []:
            role_name = r["RoleName"]
            try:
                tagged = iam.list_role_tags(RoleName=role_name)
            except Exception as e:
                if _is_access_denied(e):
                    raise DestinationAccessDenied(
                        f"ProvisionerRole in account {account.account_id} cannot "
                        f"list tags on role {role_name}: {e}",
                        operation="iam:ListRoleTags",
                    ) from e
                raise

            tags = {t["Key"]: t["Value"] for t in (tagged.get("Tags") or [])}
            if tags.get(_MANAGED_BY_TAG) != "iam-jit":
                continue
            out.append(
                DiscoveredRole(
                    account_id=account.account_id,
                    role_name=role_name,
                    role_arn=r["Arn"],
                    request_id=tags.get(_REQUEST_ID_TAG, ""),
                    expires_at=tags.get("expires-at", ""),
                    requester=tags.get("requester", ""),
                    deployment=tags.get("iam-jit-deployment", "default"),
                    tags=tags,
                )
            )

        if not page.get("IsTruncated"):
            break
        paginator_marker = page.get("Marker")
        if not paginator_marker:
            break
    return out


def reconcile(
    *,
    accounts_store: AccountStore,
    request_store: RequestStore,
    sts_client: Any | None = None,
    iam_client_factory: Any | None = None,
    deployment_filter: str | None = None,
) -> ReconciliationReport:
    """Run the full sweep: discover in every account, cross-reference
    against the request store, return a report.

    `deployment_filter`: when set, only roles whose `iam-jit-deployment`
    tag matches are counted as 'ours'. Defaults to None (count all
    iam-jit roles regardless of which deployment created them — useful
    for an unfiltered audit, but operators usually want to filter to
    their own deployment).
    """
    now = _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    accounts = accounts_store.list(include_disabled=False)

    # Step 1: hit each account.
    per_account: list[AccountReconciliation] = []
    errors: list[dict[str, Any]] = []
    discovered_by_arn: dict[str, DiscoveredRole] = {}
    for account in accounts:
        try:
            roles = discover_roles_in_account(
                account=account,
                sts_client=sts_client,
                iam_client_factory=iam_client_factory,
            )
        except DestinationAccessDenied as e:
            err = f"DestinationAccessDenied: {e.operation} — {e}"
            logger.warning(
                "rediscover account=%s denied: %s", account.account_id, err
            )
            per_account.append(
                AccountReconciliation(
                    account_id=account.account_id,
                    alias=account.alias or "",
                    success=False,
                    error=err,
                )
            )
            errors.append({"account_id": account.account_id, "error": err})
            continue
        except ProvisionerAssumeFailed as e:
            err = f"ProvisionerAssumeFailed: {e}"
            logger.warning("rediscover account=%s assume failed: %s", account.account_id, err)
            per_account.append(
                AccountReconciliation(
                    account_id=account.account_id,
                    alias=account.alias or "",
                    success=False,
                    error=err,
                )
            )
            errors.append({"account_id": account.account_id, "error": err})
            continue
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            logger.exception("rediscover account=%s unexpected error", account.account_id)
            per_account.append(
                AccountReconciliation(
                    account_id=account.account_id,
                    alias=account.alias or "",
                    success=False,
                    error=err,
                )
            )
            errors.append({"account_id": account.account_id, "error": err})
            continue

        if deployment_filter:
            roles = [r for r in roles if r.deployment == deployment_filter]
        per_account.append(
            AccountReconciliation(
                account_id=account.account_id,
                alias=account.alias or "",
                success=True,
                roles=roles,
            )
        )
        for r in roles:
            discovered_by_arn[r.role_arn] = r

    inaccessible = [
        {
            "account_id": e["account_id"],
            "error": e["error"],
            "remediation": (
                "iam-jit cannot enumerate roles in this account. The roles "
                "iam-jit previously created here are NOT visible in this "
                "report. Once access is restored (typically by redeploying "
                "the destination CloudFormation), re-run /api/v1/admin/"
                "rediscover to pick up the missing state."
            ),
        }
        for e in errors
    ]

    # Step 2: cross-reference with the request store.
    now_dt = _dt.datetime.now(_dt.UTC)
    known: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    orphans: list[dict[str, Any]] = []
    zombies: list[dict[str, Any]] = []

    discovered_by_request_id: dict[str, DiscoveredRole] = {
        r.request_id: r for r in discovered_by_arn.values() if r.request_id
    }
    seen_request_ids: set[str] = set()

    for rid in request_store.list_ids():
        try:
            req = request_store.get(rid)
        except Exception:
            logger.exception("rediscover: failed to load request %s", rid)
            continue
        provisioned = (req.get("status") or {}).get("provisioned") or {}
        role_arn = provisioned.get("role_arn") or ""
        state = (req.get("status") or {}).get("state") or ""
        if not role_arn:
            continue
        seen_request_ids.add(rid)
        if role_arn in discovered_by_arn or rid in discovered_by_request_id:
            disc = discovered_by_arn.get(role_arn) or discovered_by_request_id.get(rid)
            assert disc is not None
            row = {
                "request_id": rid,
                "role_arn": disc.role_arn,
                "role_name": disc.role_name,
                "account_id": disc.account_id,
                "expires_at": disc.expires_at,
                "state": state,
            }
            expiry_dt = _parse_iso_z(disc.expires_at)
            is_stale = (
                expiry_dt is not None
                and expiry_dt < now_dt
                and state in {"active", "revoked", "expired", "provisioning_failed"}
            )
            if is_stale:
                row["note"] = (
                    "role still exists in AWS past its expires-at tag — "
                    "expiry sweep failed; admin should force-delete"
                )
                stale.append(row)
            else:
                known.append(row)
        else:
            # Request says active+provisioned, but no matching AWS role.
            if state in {"active", "provisioning_failed"}:
                zombies.append(
                    {
                        "request_id": rid,
                        "role_arn": role_arn,
                        "account_id": provisioned.get("account_id") or "",
                        "state": state,
                        "expires_at": provisioned.get("expires_at") or "",
                        "note": "request claims provisioned but role not found in AWS",
                    }
                )
            # If state is revoked/expired/cancelled, missing role is fine —
            # that's the expected steady state.

    # Step 3: orphan = AWS role with no matching request in the store.
    for arn, disc in discovered_by_arn.items():
        if disc.request_id and disc.request_id in seen_request_ids:
            continue
        # Also check: maybe the request exists but its provisioned.role_arn
        # is missing or different (still call this an orphan from AWS PoV).
        orphans.append(
            {
                "role_arn": arn,
                "role_name": disc.role_name,
                "account_id": disc.account_id,
                "request_id": disc.request_id,
                "expires_at": disc.expires_at,
                "deployment": disc.deployment,
                "tags": disc.tags,
            }
        )

    # Step 4: orphans that look stale (past expires-at) deserve their own
    # row in `stale` too, since the cleanup obligation is the same.
    extra_stale: list[dict[str, Any]] = []
    surviving_orphans: list[dict[str, Any]] = []
    for o in orphans:
        expiry_dt = _parse_iso_z(o.get("expires_at") or "")
        if expiry_dt is not None and expiry_dt < now_dt:
            o = dict(o)
            o["note"] = (
                "orphan role past its expires-at tag — admin should "
                "force-delete after confirming it isn't owned by another "
                "iam-jit deployment"
            )
            extra_stale.append(o)
        else:
            surviving_orphans.append(o)
    stale.extend(extra_stale)

    return ReconciliationReport(
        generated_at=now,
        accounts=per_account,
        known=known,
        stale=stale,
        orphans=surviving_orphans,
        zombies=zombies,
        errors=errors,
        inaccessible_accounts=inaccessible,
    )


def _parse_iso_z(value: str) -> _dt.datetime | None:
    if not value:
        return None
    try:
        return _dt.datetime.strptime(
            value.rstrip("Z"), "%Y-%m-%dT%H:%M:%S"
        ).replace(tzinfo=_dt.UTC)
    except ValueError:
        return None


_SAFE_ARN = re.compile(
    r"^arn:aws:iam::\d{12}:role/iam-jit/iam-jit-grant-[A-Za-z0-9_-]{1,64}$"
)
_SAFE_NAME = re.compile(r"^iam-jit-grant-[A-Za-z0-9_-]{1,64}$")


def is_safe_iam_jit_arn(role_arn: str) -> bool:
    """Defense-in-depth check before any cleanup action: confirm the
    ARN is shaped like an iam-jit-managed role.

    Two separate restrictions enforced together:
      1. Path is `/iam-jit/` (iam-jit's reserved namespace).
      2. Role name starts with `iam-jit-grant-` followed by an
         alphanumeric request id.

    A role that satisfies (1) but not (2) — e.g. someone hand-creates
    `/iam-jit/manual-role` — is rejected. Combined with the tag check
    in `validate_role_for_cleanup`, this guarantees iam-jit can never
    delete a role it didn't create.
    """
    return bool(_SAFE_ARN.match(role_arn))


def is_safe_iam_jit_role_name(role_name: str) -> bool:
    return bool(_SAFE_NAME.match(role_name))


class CleanupSafetyError(Exception):
    """Refused to act on a role that doesn't pass the
    name-and-tag-must-both-match-iam-jit safety gate."""


def validate_role_for_cleanup(
    *, role_arn: str, role_name: str, tags: dict[str, str]
) -> None:
    """Hard gate before any cleanup operation deletes a role.

    BOTH of these must hold:
      - role name matches `iam-jit-grant-<id>` AND ARN is under `/iam-jit/`
      - tag `managed-by` equals exactly `iam-jit`

    Either alone is insufficient. A role with the right name but no tag
    might be a hand-crafted impersonation; a role with the tag but a
    different name might have been imported from another tool. We refuse
    both rather than guessing.

    NOTE: this gate is bypassable by anyone with destination-account
    IAM-write access — they could fabricate both a matching name AND
    the `managed-by=iam-jit` tag. See module docstring for the threat
    model. The gate's purpose is to prevent iam-jit from being
    accidentally pointed at a non-iam-jit role, not to defend against
    a privileged adversary inside the destination account.

    Raises CleanupSafetyError describing exactly which check failed so
    the operator can see why the request was refused.
    """
    issues: list[str] = []
    if not is_safe_iam_jit_arn(role_arn):
        issues.append(
            f"role ARN {role_arn!r} does not match the iam-jit pattern "
            "(must be arn:aws:iam::<account>:role/iam-jit/iam-jit-grant-<id>)"
        )
    if not is_safe_iam_jit_role_name(role_name):
        issues.append(
            f"role name {role_name!r} does not match iam-jit-grant-<id>"
        )
    if (tags or {}).get("managed-by") != "iam-jit":
        issues.append(
            "role does not carry the managed-by=iam-jit tag — "
            "iam-jit refuses to delete roles it did not create"
        )
    if issues:
        raise CleanupSafetyError(
            "refusing cleanup on this role; safety gate failed: "
            + "; ".join(issues)
        )


def force_delete_stale_role(
    *,
    account: Account,
    role_name: str,
    role_arn: str,
    tags: dict[str, str],
    sts_client: Any | None = None,
    iam_client_factory: Any | None = None,
) -> dict[str, Any]:
    """Delete a single stale iam-jit role on demand.

    Used by the admin "force-delete" endpoint when the periodic expiry
    sweep is failing or when an orphan needs to be cleaned up manually.
    Goes through the same safety gate as everywhere else — name AND tag
    must both identify the role as iam-jit-owned.

    Returns a dict suitable for direct JSON serialization in the API
    response: {role_arn, role_name, deleted: bool, inline_deleted,
    aws_cli_replay}.
    """
    validate_role_for_cleanup(role_arn=role_arn, role_name=role_name, tags=tags)

    if sts_client is None:
        import boto3

        sts_client = boto3.client("sts")
    creds = _assume_provisioner_role(
        sts_client, account, session_name=f"iam-jit-force-delete-{role_name}"[:64]
    )
    if iam_client_factory is None:
        def _default_factory(c: dict[str, str]) -> Any:
            import boto3 as _boto3

            return _boto3.client("iam", **c)

        iam_client_factory = _default_factory
    iam = iam_client_factory(creds)

    inline_deleted: list[str] = []
    deleted = True
    try:
        listed = iam.list_role_policies(RoleName=role_name)
        policy_names = listed.get("PolicyNames") or []
    except Exception as e:
        if "NoSuchEntity" in str(e):
            return {
                "role_arn": role_arn,
                "role_name": role_name,
                "deleted": False,
                "note": "role already gone before delete",
                "inline_deleted": [],
                "aws_cli_replay": [],
            }
        if _is_access_denied(e):
            raise DestinationAccessDenied(
                f"cannot list inline policies on {role_name}: {e}",
                operation="iam:ListRolePolicies",
            ) from e
        raise

    for pname in policy_names:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            inline_deleted.append(pname)
        except Exception as e:
            if _is_access_denied(e):
                raise DestinationAccessDenied(
                    f"cannot delete inline policy {pname} on {role_name}: {e}",
                    operation="iam:DeleteRolePolicy",
                ) from e
            raise

    try:
        iam.delete_role(RoleName=role_name)
    except Exception as e:
        if "NoSuchEntity" in str(e):
            deleted = False
        elif _is_access_denied(e):
            raise DestinationAccessDenied(
                f"cannot delete role {role_name}: {e}",
                operation="iam:DeleteRole",
            ) from e
        else:
            raise

    import shlex

    cli = [
        f"aws iam delete-role-policy --role-name {shlex.quote(role_name)} "
        f"--policy-name {shlex.quote(p)}"
        for p in policy_names
    ]
    cli.append(f"aws iam delete-role --role-name {shlex.quote(role_name)}")

    return {
        "role_arn": role_arn,
        "role_name": role_name,
        "deleted": deleted,
        "inline_deleted": inline_deleted,
        "aws_cli_replay": cli,
    }
