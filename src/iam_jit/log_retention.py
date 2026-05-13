"""CloudWatch Logs retention as a compliance / audit control.

iam-jit is an access-grant audit tool — every action it logs is
privileged, and the retention window an auditor or incident
responder needs is measured in months-to-years. A malicious or
compromised admin shortening retention to bury evidence is a
direct anti-audit attack (see security-notes.md § E5).

This module exposes two responsibilities:

  - Read the current CloudWatch retention for the iam-jit log group.
  - Set retention, with floor enforcement: admins can extend
    retention beyond the deploy-time floor (`MinLogRetentionDays`
    SAM param, surfaced as `IAM_JIT_MIN_LOG_RETENTION_DAYS` env),
    but NEVER shorten it below.

Data stores (DDB tables, S3 state bucket) use CloudFormation
`DeletionPolicy: Retain` to survive stack delete — that's the
deletion-protection half of the compliance story. This module
covers the retention half on the CloudWatch side.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


# The discrete retention windows CloudWatch Logs accepts. Other
# values are rejected at the AWS API. Keep this in sync with the
# `AllowedValues` on the SAM `LogRetentionDays` / `MinLogRetentionDays`
# parameters.
VALID_RETENTION_DAYS: tuple[int, ...] = (
    1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180,
    365, 400, 545, 731, 1827, 3653,
)


@dataclass(frozen=True)
class RetentionFloor:
    """The minimum retention an admin can configure at runtime.

    Set at deploy via `MinLogRetentionDays` SAM param. The runtime
    PATCH refuses any value below this. Defaults to 545 (~1.5 years)
    which exceeds PCI DSS (1y) and matches SOC 2 norms.
    """

    min_days: int = 545
    configured_at_deploy_days: int = 545
    log_group_name: str = "/aws/lambda/iam-jit"

    @classmethod
    def from_env(cls) -> "RetentionFloor":
        def _int(name: str, default: int) -> int:
            raw = (os.environ.get(name) or "").strip()
            try:
                return int(raw) if raw else default
            except ValueError:
                return default

        return cls(
            min_days=_int("IAM_JIT_MIN_LOG_RETENTION_DAYS", 545),
            configured_at_deploy_days=_int("IAM_JIT_LOG_RETENTION_DAYS", 545),
            log_group_name=(
                os.environ.get("IAM_JIT_LOG_GROUP_NAME") or "/aws/lambda/iam-jit"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_days": self.min_days,
            "configured_at_deploy_days": self.configured_at_deploy_days,
            "log_group_name": self.log_group_name,
        }


class RetentionError(Exception):
    """Anything that prevents the admin from changing retention."""


def get_current_retention(
    logs_client: Any, log_group_name: str
) -> int | None:
    """Return the currently-applied retention in days for the named
    CloudWatch log group. `None` means "never expire" (CloudWatch
    treats an unset RetentionInDays as infinite retention).

    Raises `RetentionError` if the log group doesn't exist or
    `logs:DescribeLogGroups` is denied. CloudWatch returns the
    full list; we filter by exact name.
    """
    try:
        resp = logs_client.describe_log_groups(
            logGroupNamePrefix=log_group_name, limit=50,
        )
    except Exception as e:
        raise RetentionError(
            f"describe_log_groups({log_group_name}) failed: {e}"
        ) from e
    for lg in resp.get("logGroups") or []:
        if lg.get("logGroupName") == log_group_name:
            # `retentionInDays` may be absent → never expire
            return lg.get("retentionInDays")
    raise RetentionError(
        f"log group not found: {log_group_name}. The Lambda may have "
        "never been invoked (the log group is auto-created on first "
        "invoke) or the name is misconfigured."
    )


def validate_retention(days: int, floor: RetentionFloor) -> list[str]:
    """Return human-readable error messages if `days` is invalid OR
    would violate the floor. Empty list means OK."""
    errors: list[str] = []
    if days not in VALID_RETENTION_DAYS:
        errors.append(
            f"retention_days={days} is not a valid CloudWatch retention "
            f"window. Valid values: {list(VALID_RETENTION_DAYS)}."
        )
    if days < floor.min_days:
        errors.append(
            f"retention_days={days} is below the deploy-time floor of "
            f"{floor.min_days} days (set via MinLogRetentionDays SAM "
            "parameter). Floors protect against evidence-destruction "
            "attacks (see security-notes.md § E5). To shorten retention, "
            "lower the floor by redeploying with a smaller value — that "
            "change is gated by your platform team's PR review."
        )
    return errors


def set_retention(
    logs_client: Any,
    log_group_name: str,
    days: int,
    floor: RetentionFloor,
) -> None:
    """Apply `days` retention to the named log group. Refuses if the
    value violates the floor, isn't a valid CloudWatch window, OR if
    the log group name doesn't match the floor's configured iam-jit
    log group.

    The log-group-name check is defense-in-depth: the IAM policy
    already restricts `logs:PutRetentionPolicy` to iam-jit's own log
    group ARN, but enforcing it in the handler too means we fail
    EARLY with a clear error rather than at the AWS API boundary,
    and protects against IAM-policy drift (future template edits
    that accidentally widen the resource scope).

    Does NOT short-circuit on "already set to this value" — re-applying
    is harmless and keeps the audit trail honest (admin re-asserted
    the policy at this time).
    """
    errors = validate_retention(days, floor)
    if errors:
        raise RetentionError("; ".join(errors))
    if log_group_name != floor.log_group_name:
        # An attacker-controlled or buggy caller cannot redirect the
        # API call at a foreign log group. The IAM policy would
        # reject it too, but raising here gives a clear "you tried
        # to touch the wrong log group" error instead of an opaque
        # AccessDenied from CloudWatch.
        raise RetentionError(
            f"refusing to modify retention on log group "
            f"{log_group_name!r}: iam-jit may only manage retention "
            f"on its own log group ({floor.log_group_name!r}). This "
            "is enforced both here AND in the IAM policy (see "
            "template Policies → self-log-retention → "
            "DenyRetentionOnForeignLogGroups)."
        )
    try:
        logs_client.put_retention_policy(
            logGroupName=log_group_name, retentionInDays=days,
        )
    except Exception as e:
        raise RetentionError(
            f"put_retention_policy({log_group_name}, {days}) failed: {e}. "
            "Lambda role may be missing logs:PutRetentionPolicy on the "
            "log group ARN (see template Policies → self-log-retention)."
        ) from e
