"""Phase 2 — provisioning a time-bound IAM role into a destination account.

Given an approved request and a registered destination account (from
`accounts_store`), this module:

  1. Assumes the destination account's ProvisionerRole using its
     ExternalId. The hub Lambda's IAM role is the only thing AWS allows
     to make this call.
  2. Creates an IAM role in the destination account with:
     - a trust policy locking the role to `spec.assume_by.principal_arn`
       (or, when set to '__from_login__', to the requester's principal
       resolved from `metadata.requester.principal_arn`)
     - an embedded **time-condition** on the trust AND on every inline
       policy statement (`DateLessThan aws:CurrentTime <expires_at>`).
       Defense in depth: even if the expiry sweep fails to delete the
       role on time, AWS will deny use after the timestamp.
     - tags: managed-by=iam-jit, request-id, requester, expires-at,
       provisioning-mode (so the cleanup sweep can find these later).
  3. Attaches the spec.policy as an inline role policy, augmented with
     the time-condition so even direct-attach exceptions can't outlive
     the grant.

Returns a `ProvisioningResult` describing what was created. The caller
(lifecycle / Lambda handler) is responsible for persisting the result
into `status.provisioned` and rendering the assume-role snippet via
`assume.render_instructions()`.

Errors are typed:
  - `AccountNotRegistered`: the spec's account isn't in iam-jit's registry
  - `AssumerPrincipalMissing`: trust policy can't be locked down — refuse
  - `ProvisionerAssumeFailed`: STS denied the cross-account assume
  - `IAMCreateFailed`: any IAM API failure during role/policy creation

This module never touches the request store or lifecycle directly — it
operates on a parsed `Request` dict and returns data. The lifecycle
machinery decides what to do with the result.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from .accounts_store import Account, AccountStore, AccountNotFound

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# #324f — dynamic-deny recommender Deny-injection
# ---------------------------------------------------------------------------
#
# Env-var gate (mirrors the per-product convention from
# `[[enterprise-profile-distribution]]` + the ProxyConfig dynamic-deny
# fields). Defaults to enabled because the loader is a no-op when
# there's no YAML file on disk; operators who don't use dynamic
# denies pay zero cost, operators who DO use them get defense-in-
# depth without an extra flag flip.
DYNAMIC_DENIES_RECOMMENDER_ENV = "IAM_JIT_DYNAMIC_DENIES_RECOMMENDER"
"""Env var name. Set to ``0`` / ``false`` / ``no`` / ``off`` to disable
the recommender's Deny-injection pass. Anything else (including unset)
leaves it enabled per the design doc + per
``[[deliberate-feature-completion]]``."""

_DISABLED_VALUES = frozenset({"0", "false", "no", "off"})


def _dynamic_denies_recommender_enabled() -> bool:
    """Resolve the master switch from the env var. Defaults to True.

    Separate function (not a module-level constant) so tests that
    monkeypatch the env see fresh values per call — the bouncer's
    ProxyConfig holds the analog field with the same default but
    callers here re-resolve every issuance so a SIGHUP-style env
    refresh works without a process restart.
    """
    raw = (os.environ.get(DYNAMIC_DENIES_RECOMMENDER_ENV) or "").strip().lower()
    if not raw:
        return True
    return raw not in _DISABLED_VALUES


def _load_active_dynamic_denies() -> "Any":
    """Read the on-disk dynamic-denies YAML + return the active
    :class:`RuleSet`. Returns an empty RuleSet on ANY load failure —
    issuance must never crash on a malformed denies file (the
    bouncer-side watcher surfaces parse errors via its own admin-
    action channel; the recommender's job is to embed what's
    AVAILABLE, not to second-guess upstream parsing).

    Lazy-imports the dynamic_denies package so a deployment that
    strips it for size reasons still imports provision.py cleanly.
    """
    try:
        from .dynamic_denies import load_file, resolve_default_path
        from .dynamic_denies.types import RuleSet
    except Exception as e:
        logger.debug(
            "dynamic_denies package not importable; skipping "
            "recommender Deny-injection: %s", e,
        )
        return None
    try:
        path = resolve_default_path()
    except Exception as e:
        logger.debug("dynamic_denies path resolve failed: %s", e)
        return RuleSet.empty()
    if not path:
        return RuleSet.empty()
    try:
        return load_file(path)
    except Exception as e:
        # Parse / schema error — log + return empty so issuance proceeds.
        # The bouncer-side watcher emits the admin-action event for this
        # condition; we don't double-emit here.
        logger.warning(
            "dynamic-denies file unreadable at %s; embedding 0 rules "
            "into issued role policy: %s", path, e,
        )
        try:
            return RuleSet.empty(source_path=path)
        except Exception:
            return None


class ProvisioningError(Exception):
    """Base class for provisioning failures."""


class AccountNotRegistered(ProvisioningError):
    """The request's account is not in iam-jit's registered destination list."""


class AssumerPrincipalMissing(ProvisioningError):
    """Trust policy can't be locked down — request must specify the
    principal that will assume the role."""


class ProvisionerAssumeFailed(ProvisioningError):
    """sts:AssumeRole into the destination's ProvisionerRole failed."""


class IAMCreateFailed(ProvisioningError):
    """The destination IAM role / policy creation failed."""


class DestinationAccessDenied(ProvisioningError):
    """The ProvisionerRole exists but lacks the IAM permission needed
    for the operation we tried (CreateRole, DeleteRole, PutRolePolicy,
    DeleteRolePolicy, ListRolePolicies, ListRoles, GetRole, TagRole).

    This is distinct from `ProvisionerAssumeFailed` (sts:AssumeRole was
    refused) — here we *did* assume, but the role's inline policy on the
    destination side has drifted away from what iam-jit expects. The
    remediation is to redeploy the destination CloudFormation template,
    not to fiddle with the hub.

    Surface this as a 502 in the API and, in the UI, link the operator
    to the bootstrap docs."""

    def __init__(self, message: str, *, operation: str = "") -> None:
        super().__init__(message)
        self.operation = operation


def _is_access_denied(exc: Exception) -> bool:
    """Best-effort detection of an AccessDenied/AuthorizationError from
    boto3 — works against ClientError, moto exceptions, or plain str
    representations from custom backends."""
    msg = str(exc)
    if (
        "AccessDenied" in msg
        or "AuthorizationError" in msg
        or "is not authorized to perform" in msg
        or "AccessDeniedException" in msg
    ):
        return True
    err = getattr(exc, "response", None) or {}
    code = (err.get("Error") or {}).get("Code") or ""
    return code in {"AccessDenied", "AccessDeniedException", "AuthorizationError"}


_REMEDIATION_HINT = (
    "Redeploy the destination CloudFormation template "
    "(infrastructure/destination-account.yaml) to restore the "
    "ProvisionerRole's IAM policy. The role needs: iam:CreateRole, "
    "iam:DeleteRole, iam:PutRolePolicy, iam:DeleteRolePolicy, "
    "iam:ListRolePolicies, iam:ListRoles, iam:GetRole, iam:TagRole "
    "— all scoped to /iam-jit/."
)


@dataclass(frozen=True)
class ProvisioningResult:
    role_arn: str
    role_name: str
    account_id: str
    assumer_principal_arn: str
    expires_at: str
    external_id: str | None = None
    session_name: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    aws_cli_replay: list[str] = field(default_factory=list)
    """Equivalent AWS CLI command sequence for what we executed.

    Each string is a complete `aws ...` command that, run with the
    appropriate destination-account credentials, would reproduce the IAM
    state we created via boto3. Surfaced on the request detail page for
    auditability and as a copy-paste fallback if an admin ever needs to
    replay the provisioning by hand."""

    embedded_dynamic_denies: list[str] = field(default_factory=list)
    """#324f — list of dynamic-deny rule ids (``dd_<ULID>``) the
    recommender embedded as explicit ``Deny`` statements into the
    issued role's inline policy. Empty when:
      * Dynamic-denies recommender is disabled
        (:data:`DYNAMIC_DENIES_RECOMMENDER_ENV` set to off).
      * No on-disk denies file or it's empty / unreadable.
      * No active rule has ``applied_to`` containing ``ibounce`` AND
        ``applies_to_recommender`` true AND a non-expired
        ``expires_at`` AND at least one AWS-ARN-shaped target.

    Surfaces in the audit emission (per the §324f spec) under
    ``unmapped.iam_jit.ext.embedded_dynamic_denies`` so operators
    can verify their dynamic-deny rules actually shaped the issued
    role without manually inspecting AWS."""


def _isoformat_z(dt: _dt.datetime) -> str:
    return dt.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_expires_at(spec: dict[str, Any]) -> str:
    """Compute the absolute expiry timestamp from `spec.duration`.

    Schema guarantees one of `duration_hours` or `not_after`. Returns an
    ISO-8601 UTC timestamp ('YYYY-MM-DDTHH:MM:SSZ').
    """
    duration = spec.get("duration") or {}
    if duration.get("not_after"):
        return duration["not_after"]
    hours = int(duration.get("duration_hours") or 24)
    return _isoformat_z(_dt.datetime.now(_dt.UTC) + _dt.timedelta(hours=hours))


_FORBIDDEN_ASSUMER_PATTERNS = (
    "*",
    "arn:aws:iam::*:root",
)


def _validate_assumer_arn(arn: str) -> None:
    """Refuse assumer ARNs that grant trust too widely.

    Specifically rejected:
      - `*` (any principal — would let anyone in any AWS account
        assume the role)
      - `arn:aws:iam::<account>:root` (the root user of an account is
        a sentinel meaning "anyone in that account with sts:AssumeRole
        permission" — too broad for an iam-jit grant)
      - empty / non-string

    These checks run BEFORE we put anything in the trust policy, so a
    forbidden ARN never ends up in AWS at all. Approvers also see the
    refusal at preview-time via `provision.preview()`.
    """
    if not isinstance(arn, str) or not arn:
        raise AssumerPrincipalMissing("assumer principal ARN is empty")
    if "*" in arn:
        raise AssumerPrincipalMissing(
            f"refusing wildcard assumer ARN {arn!r} — iam-jit grants must "
            "lock to a specific principal"
        )
    # `:root` ends the ARN with literal :root or :root/...
    if arn.endswith(":root") or arn.endswith(":root/"):
        raise AssumerPrincipalMissing(
            f"refusing account-root assumer ARN {arn!r} — that grants "
            "any principal in the account"
        )
    if not arn.startswith("arn:aws"):
        raise AssumerPrincipalMissing(
            f"assumer principal must be an ARN (got {arn!r})"
        )


def _resolve_assumer(request: dict[str, Any]) -> str:
    """Pick the principal that will assume the provisioned role."""
    spec = request.get("spec") or {}
    assume_by = spec.get("assume_by") or {}
    explicit = assume_by.get("principal_arn") or ""
    if explicit and explicit != "__from_login__":
        _validate_assumer_arn(explicit)
        return explicit
    metadata = request.get("metadata") or {}
    requester = metadata.get("requester") or {}
    inferred = requester.get("principal_arn") or ""
    if inferred:
        _validate_assumer_arn(inferred)
        return inferred
    raise AssumerPrincipalMissing(
        "request has no assume_by.principal_arn and no requester.principal_arn — "
        "set one before approval"
    )


def _build_trust_policy(
    assumer_arn: str, expires_at: str, session_name_hint: str
) -> dict[str, Any]:
    """Trust policy locked to `assumer_arn` with a time-condition.

    The DateLessThan condition makes the role useless after expires_at
    regardless of whether iam-jit's cleanup runs. Combined with
    `MaxSessionDuration` on the role, this bounds blast radius hard."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowApprovedPrincipal",
                "Effect": "Allow",
                "Principal": {"AWS": assumer_arn},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "DateLessThan": {"aws:CurrentTime": expires_at},
                },
            }
        ],
    }


def _augment_policy_with_time_condition(
    policy: dict[str, Any], expires_at: str
) -> dict[str, Any]:
    """Return a copy of `policy` where every Statement has a
    DateLessThan time-condition on aws:CurrentTime.

    If a Statement already has Conditions, we merge — preserving the
    original conditions but adding the time bound. This is the
    defense-in-depth piece: even if the role isn't deleted, every
    permission denies after the timestamp."""
    out: dict[str, Any] = {"Version": policy.get("Version", "2012-10-17")}
    statements_in = policy.get("Statement") or []
    statements_out: list[dict[str, Any]] = []
    for s in statements_in:
        s2 = dict(s)
        existing = dict(s.get("Condition") or {})
        date_cond = dict(existing.get("DateLessThan") or {})
        # Don't overwrite an existing aws:CurrentTime value (caller may
        # have set a tighter bound) — only add when missing.
        date_cond.setdefault("aws:CurrentTime", expires_at)
        existing["DateLessThan"] = date_cond
        s2["Condition"] = existing
        statements_out.append(s2)
    out["Statement"] = statements_out
    return out


def _build_issued_policy(
    raw_policy: dict[str, Any],
    *,
    expires_at: str,
) -> tuple[dict[str, Any], list[str]]:
    """#324f — assemble the inline policy iam-jit puts on a newly-issued
    role + return the embedded dynamic-deny rule ids.

    Pipeline:
      1. Augment the operator's requested policy with the
         DateLessThan time-condition on every statement (existing
         :func:`_augment_policy_with_time_condition` behavior).
      2. If the dynamic-denies recommender is enabled, load the
         active rule set + append one explicit-Deny statement per
         eligible rule.

    Returns ``(inline_policy, embedded_rule_ids)`` so the caller can
    propagate the rule-id list into the audit event without re-running
    the eligibility check.

    Per ``[[creates-never-mutates]]`` neither input is mutated. The
    dynamic-deny load path swallows every exception (logging only)
    so issuance never fails because of a malformed denies file —
    the bouncer-side watcher is responsible for surfacing parse
    errors via its own admin-action emit.
    """
    with_time = _augment_policy_with_time_condition(raw_policy, expires_at)
    if not _dynamic_denies_recommender_enabled():
        return with_time, []
    ruleset = _load_active_dynamic_denies()
    if ruleset is None or not getattr(ruleset, "rules", ()):
        return with_time, []
    try:
        from .dynamic_denies.recommender import (
            build_deny_statements,
            embedded_rule_ids,
        )
    except Exception as e:
        # If for some reason the recommender module is unimportable,
        # log + continue without embedding. Defensive — the
        # `dynamic_denies` package is shipped wholesale.
        logger.warning(
            "dynamic_denies.recommender unimportable; skipping "
            "Deny-injection: %s", e,
        )
        return with_time, []
    extra_statements = build_deny_statements(ruleset)
    ids = embedded_rule_ids(ruleset)
    if not extra_statements:
        return with_time, []
    out = {
        "Version": with_time.get("Version", "2012-10-17"),
        "Statement": list(with_time.get("Statement") or []) + extra_statements,
    }
    return out, ids


def _assume_provisioner_role(
    sts_client: Any,
    account: Account,
    *,
    session_name: str,
) -> dict[str, str]:
    """Cross-account assume into the destination's ProvisionerRole.

    Returns the temporary credentials dict ready for boto3 client kwargs.
    """
    try:
        resp = sts_client.assume_role(
            RoleArn=account.provisioner_role_arn,
            RoleSessionName=session_name,
            ExternalId=account.provisioner_external_id,
            DurationSeconds=3600,
        )
    except Exception as e:
        raise ProvisionerAssumeFailed(
            f"sts:AssumeRole into {account.provisioner_role_arn} failed: {e}"
        ) from e
    creds = resp["Credentials"]
    return {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }


def _role_name(request_id: str) -> str:
    """Build the destination IAM role name.

    Format: `iam-jit-grant-<request_id>`. Globally-unique because the
    role ARN includes the destination account ID and the iam-jit path
    prefix; the request_id (12 chars of base64 entropy) keeps the name
    unique within the deployment.

    Why 'iam-jit-grant-' and not just 'iam-jit-': leaves room for
    future iam-jit-managed resource types (groups, policies, instance
    profiles) without colliding on names."""
    return f"iam-jit-grant-{request_id}"


def _resource_path(request_id: str) -> str:
    """All iam-jit roles live under `/iam-jit/`. The destination account's
    ProvisionerRole policy scopes IAM:CreateRole / IAM:DeleteRole to
    that path so iam-jit can never create or delete a role outside its
    own namespace, even if the Lambda is compromised."""
    return "/iam-jit/"


def _last_approver(request: dict[str, Any]) -> str | None:
    """Return the user_id of the most recent 'approve' transition, or
    None if the request hasn't been approved yet."""
    history = (request.get("status") or {}).get("history") or []
    for event in reversed(history):
        if event.get("action") == "approve":
            by = event.get("by")
            if isinstance(by, str) and by:
                return by
    return None


def _deployment_name() -> str:
    """Identifier for THIS iam-jit deployment.

    From `IAM_JIT_DEPLOYMENT_NAME` env var. Defaults to 'default'.
    Tagged on every role so an admin running multiple iam-jit
    installations into the same destination account can distinguish
    which one owns which role.

    Stable string — don't include version, hostname, or anything that
    rotates. Rename it only when intentionally splitting deployments.
    """
    return (os.environ.get("IAM_JIT_DEPLOYMENT_NAME") or "default")[:64]


def _build_tags(
    *,
    request_id: str,
    requester_email: str,
    approver_id: str | None,
    expires_at: str,
    provisioned_at: str,
    access_type: str,
) -> dict[str, str]:
    """Tag every role with audit-friendly fields.

    Standard query patterns these support:

      # All iam-jit-managed roles in a destination account:
      aws resourcegroupstaggingapi get-resources \\
        --tag-filters Key=managed-by,Values=iam-jit \\
        --resource-type-filters iam:role

      # Roles created by a specific deployment:
      aws resourcegroupstaggingapi get-resources \\
        --tag-filters Key=iam-jit-deployment,Values=<name>

      # Roles approved by a specific user:
      aws resourcegroupstaggingapi get-resources \\
        --tag-filters Key=approver,Values=<user-id>

      # Roles past their expiry that haven't been cleaned up yet:
      aws iam list-roles --path-prefix /iam-jit/ \\
        --query "Roles[?Tags[?Key=='expires-at' && Value < '$(date -u +%FT%TZ)']]"
    """
    from . import __version__

    tags: dict[str, str] = {
        "managed-by": "iam-jit",
        "iam-jit-deployment": _deployment_name(),
        "iam-jit-version": __version__,
        "request-id": request_id,
        "requester": requester_email or "unknown",
        "expires-at": expires_at,
        "provisioned-at": provisioned_at,
        "access-type": access_type or "read-only",
    }
    if approver_id:
        tags["approver"] = approver_id
    # AWS tag values are limited to 256 chars; clamp defensively.
    return {k: v[:256] for k, v in tags.items() if v}


@dataclass(frozen=True)
class ProvisioningPreview:
    """What `provision()` would do, computed without making AWS calls.

    Surfaced in the request detail page before approval so reviewers
    can see the exact CLI commands the system will run when they click
    Approve. Same shape used post-approval for the audit replay — only
    difference is whether the role actually exists yet."""

    role_arn: str
    role_name: str
    account_id: str
    assumer_principal_arn: str
    expires_at: str
    external_id: str | None
    session_name: str
    tags: dict[str, str]
    aws_cli_replay: list[str]
    blocking_issues: list[str]
    """Anything the preview surfaced that would prevent provisioning.

    Examples: 'account not registered', 'no assumer principal'. Empty
    list means the request would succeed if approved right now."""


def preview(
    request: dict[str, Any],
    *,
    accounts_store: AccountStore,
) -> ProvisioningPreview:
    """Compute what would happen if the request were approved, without
    talking to AWS.

    Same logic as `provision()` for building the trust policy, inline
    policy, tags, and CLI replay — but no STS, no IAM API calls. If the
    account isn't registered or the assumer principal can't be resolved,
    the issue is reported in `blocking_issues` instead of raised."""
    metadata = request.get("metadata") or {}
    spec = request.get("spec") or {}
    request_id = metadata.get("id") or "<no-id>"
    blocking: list[str] = []

    accounts_in_spec = spec.get("accounts") or []
    target_account_id = (
        accounts_in_spec[0].get("account_id") if accounts_in_spec else ""
    )
    if not target_account_id:
        blocking.append("spec.accounts[0].account_id is missing")

    account: Account | None = None
    external_id: str | None = None
    if target_account_id:
        try:
            account = accounts_store.get(target_account_id)
            external_id = account.provisioner_external_id
            if not account.enabled:
                blocking.append(
                    f"account {target_account_id} is registered but disabled"
                )
        except AccountNotFound:
            blocking.append(
                f"account {target_account_id} is not registered with iam-jit"
            )

    assumer_arn = ""
    try:
        assumer_arn = _resolve_assumer(request)
    except AssumerPrincipalMissing as e:
        blocking.append(str(e))

    expires_at = _resolve_expires_at(spec)
    role_name = _role_name(request_id)
    role_path = _resource_path(request_id)
    session_name = f"iam-jit-provision-{request_id}"[:64]

    raw_policy = spec.get("policy") or {"Version": "2012-10-17", "Statement": []}
    if not isinstance(raw_policy, dict) or not raw_policy.get("Statement"):
        blocking.append("spec.policy is empty or malformed")
        inline_policy = {"Version": "2012-10-17", "Statement": []}
    else:
        # #324f — augment with time-condition AND embed dynamic-deny
        # Deny statements from the active rule set.
        inline_policy, _ = _build_issued_policy(
            raw_policy, expires_at=expires_at,
        )

    trust = _build_trust_policy(
        assumer_arn or "<assumer-principal-arn>",
        expires_at,
        session_name,
    )

    requester_id = (metadata.get("requester") or {}).get("email") or "unknown"
    approver_id = _last_approver(request)
    tags = _build_tags(
        request_id=request_id,
        requester_email=requester_id,
        approver_id=approver_id,
        expires_at=expires_at,
        provisioned_at="<not-yet-provisioned>",
        access_type=spec.get("access_type") or "read-only",
    )
    cli_replay = _build_cli_replay(
        role_name=role_name,
        role_path=role_path,
        trust=trust,
        inline_policy=inline_policy,
        tags=tags,
        expires_at=expires_at,
        request_id=request_id,
    )
    role_arn = (
        f"arn:aws:iam::{target_account_id or '<account-id>'}:role{role_path}{role_name}"
    )
    return ProvisioningPreview(
        role_arn=role_arn,
        role_name=role_name,
        account_id=target_account_id or "",
        assumer_principal_arn=assumer_arn,
        expires_at=expires_at,
        external_id=external_id,
        session_name=session_name,
        tags=tags,
        aws_cli_replay=cli_replay,
        blocking_issues=blocking,
    )


def provision(
    request: dict[str, Any],
    *,
    accounts_store: AccountStore,
    sts_client: Any | None = None,
    iam_client_factory: Any | None = None,
) -> ProvisioningResult:
    """Provision the role for an approved request.

    `sts_client` and `iam_client_factory` are injected so tests can
    pass moto-backed clients. In production, callers leave them None
    and we build clients via boto3.

    `iam_client_factory(creds)` returns a boto3 IAM client configured
    with the destination-account credentials.
    """
    metadata = request.get("metadata") or {}
    spec = request.get("spec") or {}
    request_id = metadata.get("id") or ""
    if not request_id:
        raise ProvisioningError("request is missing metadata.id")

    accounts_in_spec = spec.get("accounts") or []
    if not accounts_in_spec:
        raise ProvisioningError("request has no spec.accounts")
    target_account_id = accounts_in_spec[0].get("account_id")
    if not target_account_id:
        raise ProvisioningError("spec.accounts[0].account_id is empty")

    try:
        account = accounts_store.get(target_account_id)
    except AccountNotFound as e:
        raise AccountNotRegistered(
            f"account {target_account_id} is not registered with iam-jit; "
            "deploy the destination CloudFormation and POST /api/v1/accounts first"
        ) from e
    if not account.enabled:
        raise AccountNotRegistered(
            f"account {target_account_id} is registered but disabled"
        )

    assumer_arn = _resolve_assumer(request)
    expires_at = _resolve_expires_at(spec)
    role_name = _role_name(request_id)
    role_path = _resource_path(request_id)
    session_name = f"iam-jit-provision-{request_id}"[:64]

    # Build clients
    if sts_client is None:
        import boto3

        sts_client = boto3.client("sts")
    creds = _assume_provisioner_role(
        sts_client, account, session_name=session_name
    )
    if iam_client_factory is None:
        def _default_factory(c: dict[str, str]) -> Any:
            import boto3 as _boto3

            return _boto3.client("iam", **c)

        iam_client_factory = _default_factory
    iam = iam_client_factory(creds)

    # Build the trust policy + scoped inline policy
    trust = _build_trust_policy(assumer_arn, expires_at, session_name)
    raw_policy = spec.get("policy") or {"Version": "2012-10-17", "Statement": []}
    if not isinstance(raw_policy, dict) or not raw_policy.get("Statement"):
        raise ProvisioningError("spec.policy is empty or malformed")
    # #324f — augment with time-condition AND embed dynamic-deny
    # Deny statements from the active rule set. Returns the embedded
    # rule ids so we can surface them in the audit emit + on the
    # ProvisioningResult.
    inline_policy, embedded_dd_ids = _build_issued_policy(
        raw_policy, expires_at=expires_at,
    )

    requester_id = (metadata.get("requester") or {}).get("email") or "unknown"
    approver_id = _last_approver(request)
    provisioned_at = _isoformat_z(_dt.datetime.now(_dt.UTC))
    tags = _build_tags(
        request_id=request_id,
        requester_email=requester_id,
        approver_id=approver_id,
        expires_at=expires_at,
        provisioned_at=provisioned_at,
        access_type=spec.get("access_type") or "read-only",
    )

    try:
        iam.create_role(
            RoleName=role_name,
            Path=role_path,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description=(
                # IAM's role-description regex permits only ASCII printable
                # plus Latin-1 Supplement; in particular no em-dash
                # (U+2014) or other curly punctuation. Use plain ASCII
                # "-" in any generated text written into Description.
                f"iam-jit grant for request {request_id} - "
                f"expires {expires_at}"
            ),
            MaxSessionDuration=3600,
            Tags=[{"Key": k, "Value": v} for k, v in tags.items()],
        )
    except Exception as e:
        # If a previous provisioning attempt for THIS request already
        # created the role (concurrent approve race, or a retry after a
        # transient failure), treat it as success: the role is exactly
        # what we'd have created. Idempotency keeps double-approves
        # from leaving the request in `provisioning_failed` after the
        # role is already live.
        msg = str(e)
        if "EntityAlreadyExists" not in msg and "already exists" not in msg:
            if _is_access_denied(e):
                raise DestinationAccessDenied(
                    f"ProvisionerRole in account {target_account_id} cannot create "
                    f"role {role_name}: {e}. {_REMEDIATION_HINT}",
                    operation="iam:CreateRole",
                ) from e
            raise IAMCreateFailed(
                f"creating role {role_name} in account {target_account_id} failed: {e}"
            ) from e

    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"iam-jit-grant-{request_id}",
            PolicyDocument=json.dumps(inline_policy),
        )
    except Exception as e:
        if _is_access_denied(e):
            raise DestinationAccessDenied(
                f"ProvisionerRole in account {target_account_id} cannot put "
                f"inline policy on role {role_name}: {e}. {_REMEDIATION_HINT}",
                operation="iam:PutRolePolicy",
            ) from e
        raise IAMCreateFailed(
            f"attaching inline policy to {role_name} in account {target_account_id} failed: {e}"
        ) from e

    role_arn = (
        f"arn:aws:iam::{target_account_id}:role{role_path}{role_name}"
    )
    cli_replay = _build_cli_replay(
        role_name=role_name,
        role_path=role_path,
        trust=trust,
        inline_policy=inline_policy,
        tags=tags,
        expires_at=expires_at,
        request_id=request_id,
    )

    # #324f — best-effort audit emission for embedded dynamic-deny rules.
    # The provisioning route handler (routes/requests.py) will also see
    # the embedded ids via `ProvisioningResult.embedded_dynamic_denies`
    # and surface them in `status.provisioned`; we additionally emit a
    # standalone audit event here so a SIEM filter on
    # `kind:request.provisioned_with_dynamic_denies` catches the
    # cross-product correlation point without parsing the request
    # detail. Best-effort: a broken audit sink never fails the
    # issuance per [[creates-never-mutates]].
    if embedded_dd_ids:
        try:
            from . import audit as _audit_mod
            _audit_mod.emit(
                actor="system",
                kind="request.provisioned_with_dynamic_denies",
                summary=(
                    f"role {role_name} issued with {len(embedded_dd_ids)} "
                    f"embedded dynamic-deny rule(s)"
                ),
                details={
                    "request_id": request_id,
                    "role_arn": role_arn,
                    "unmapped": {
                        "iam_jit": {
                            "ext": {
                                "embedded_dynamic_denies": list(embedded_dd_ids),
                                "embedded_dynamic_denies_count": len(
                                    embedded_dd_ids
                                ),
                            },
                        },
                    },
                },
            )
        except Exception:
            logger.exception(
                "best-effort audit emit for embedded_dynamic_denies failed"
            )

    return ProvisioningResult(
        role_arn=role_arn,
        role_name=role_name,
        account_id=target_account_id,
        assumer_principal_arn=assumer_arn,
        expires_at=expires_at,
        external_id=account.provisioner_external_id,
        session_name=session_name,
        tags=tags,
        aws_cli_replay=cli_replay,
        embedded_dynamic_denies=list(embedded_dd_ids),
    )


@dataclass(frozen=True)
class RevocationResult:
    """What `revoke()` accomplished. Stored under `status.revocation`."""

    role_arn: str
    role_name: str
    account_id: str
    revoked_at: str
    aws_cli_replay: list[str]
    inline_policies_deleted: list[str] = field(default_factory=list)
    role_existed: bool = True
    """False if the role was already gone (idempotent revoke after a
    manual delete or successful expiry sweep)."""


def revoke(
    request: dict[str, Any],
    *,
    accounts_store: AccountStore,
    sts_client: Any | None = None,
    iam_client_factory: Any | None = None,
) -> RevocationResult:
    """Tear down an iam-jit-provisioned role on demand.

    Mirror of `provision()`: assumes the destination's ProvisionerRole,
    detaches every inline policy on the role, then deletes the role
    itself. Idempotent — if the role is already gone (manual deletion,
    or the expiry sweep beat us to it) we return a result with
    `role_existed=False` rather than raising.

    The request must already have `status.provisioned` populated — that's
    where we read `role_name` and `account_id`. Calling revoke() on a
    request that was never provisioned raises ProvisioningError.
    """
    metadata = request.get("metadata") or {}
    request_id = metadata.get("id") or ""
    if not request_id:
        raise ProvisioningError("request is missing metadata.id")

    provisioned = (request.get("status") or {}).get("provisioned") or {}
    role_name = provisioned.get("role_name") or ""
    target_account_id = provisioned.get("account_id") or ""
    role_arn = provisioned.get("role_arn") or ""
    if not role_name or not target_account_id:
        raise ProvisioningError(
            "request has no status.provisioned.role_name / account_id; "
            "nothing to revoke"
        )

    try:
        account = accounts_store.get(target_account_id)
    except AccountNotFound as e:
        raise AccountNotRegistered(
            f"account {target_account_id} is no longer registered with iam-jit; "
            "cannot revoke"
        ) from e

    session_name = f"iam-jit-revoke-{request_id}"[:64]
    if sts_client is None:
        import boto3

        sts_client = boto3.client("sts")
    creds = _assume_provisioner_role(sts_client, account, session_name=session_name)
    if iam_client_factory is None:
        def _default_factory(c: dict[str, str]) -> Any:
            import boto3 as _boto3

            return _boto3.client("iam", **c)

        iam_client_factory = _default_factory
    iam = iam_client_factory(creds)

    revoked_at = _isoformat_z(_dt.datetime.now(_dt.UTC))
    inline_deleted: list[str] = []
    role_existed = True

    try:
        listed = iam.list_role_policies(RoleName=role_name)
        policy_names = listed.get("PolicyNames") or []
    except Exception as e:
        msg = str(e)
        if "NoSuchEntity" in msg or "NoSuchEntityException" in msg:
            role_existed = False
            policy_names = []
        elif _is_access_denied(e):
            raise DestinationAccessDenied(
                f"ProvisionerRole in account {target_account_id} cannot list "
                f"inline policies on {role_name}: {e}. {_REMEDIATION_HINT}",
                operation="iam:ListRolePolicies",
            ) from e
        else:
            raise IAMCreateFailed(
                f"listing inline policies on {role_name} failed: {e}"
            ) from e

    for pname in policy_names:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            inline_deleted.append(pname)
        except Exception as e:
            if _is_access_denied(e):
                raise DestinationAccessDenied(
                    f"ProvisionerRole in account {target_account_id} cannot "
                    f"delete inline policy {pname} on {role_name}: {e}. "
                    f"{_REMEDIATION_HINT}",
                    operation="iam:DeleteRolePolicy",
                ) from e
            raise IAMCreateFailed(
                f"deleting inline policy {pname} on {role_name} failed: {e}"
            ) from e

    if role_existed:
        try:
            iam.delete_role(RoleName=role_name)
        except Exception as e:
            msg = str(e)
            if "NoSuchEntity" in msg:
                role_existed = False
            elif _is_access_denied(e):
                raise DestinationAccessDenied(
                    f"ProvisionerRole in account {target_account_id} cannot "
                    f"delete role {role_name}: {e}. {_REMEDIATION_HINT}",
                    operation="iam:DeleteRole",
                ) from e
            else:
                raise IAMCreateFailed(
                    f"deleting role {role_name} in account {target_account_id} failed: {e}"
                ) from e

    cli_replay = _build_revocation_cli_replay(
        role_name=role_name, inline_policy_names=policy_names
    )
    return RevocationResult(
        role_arn=role_arn,
        role_name=role_name,
        account_id=target_account_id,
        revoked_at=revoked_at,
        aws_cli_replay=cli_replay,
        inline_policies_deleted=inline_deleted,
        role_existed=role_existed,
    )


def _build_revocation_cli_replay(
    *, role_name: str, inline_policy_names: list[str]
) -> list[str]:
    """The aws-cli sequence equivalent to what `revoke()` did. Each
    command stands alone so an admin can copy any one of them
    individually if a partial revoke is needed."""
    import shlex

    out: list[str] = []
    for pname in inline_policy_names:
        out.append(
            f"aws iam delete-role-policy "
            f"--role-name {shlex.quote(role_name)} "
            f"--policy-name {shlex.quote(pname)}"
        )
    out.append(f"aws iam delete-role --role-name {shlex.quote(role_name)}")
    return out


def _build_cli_replay(
    *,
    role_name: str,
    role_path: str,
    trust: dict[str, Any],
    inline_policy: dict[str, Any],
    tags: dict[str, str],
    expires_at: str,
    request_id: str,
) -> list[str]:
    """Return the aws-cli command sequence equivalent to what we
    executed. Strings are intentionally one-line and valid as-is so
    they can be pasted into a shell with `--profile <destination>` set
    in the environment.

    Policy documents are inlined as single-quoted JSON. We use the
    explicit `--region us-east-1` because IAM is global; we just want
    something deterministic for the replay."""
    import shlex

    trust_json = json.dumps(trust, separators=(",", ":"))
    policy_json = json.dumps(inline_policy, separators=(",", ":"))
    tag_args = " ".join(
        f"Key={shlex.quote(k)},Value={shlex.quote(v)}" for k, v in tags.items()
    )
    # Match the actual create_role call above: ASCII-only, no em-dash.
    desc = f"iam-jit grant for request {request_id} - expires {expires_at}"

    create_role = (
        f"aws iam create-role "
        f"--role-name {shlex.quote(role_name)} "
        f"--path {shlex.quote(role_path)} "
        f"--assume-role-policy-document {shlex.quote(trust_json)} "
        f"--description {shlex.quote(desc)} "
        f"--max-session-duration 3600 "
        f"--tags {tag_args}"
    )
    put_policy = (
        f"aws iam put-role-policy "
        f"--role-name {shlex.quote(role_name)} "
        f"--policy-name {shlex.quote(f'iam-jit-grant-{request_id}')} "
        f"--policy-document {shlex.quote(policy_json)}"
    )
    return [create_role, put_policy]
