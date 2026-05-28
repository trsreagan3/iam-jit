"""Orphan-request reconciliation (#698 LOW-2).

Periodically walks every `active` request, calls `iam:GetRole` against
the provisioned role's ARN, and — if the role no longer exists in AWS
(`NoSuchEntity`) — transitions the request to `revoked` with a
canonical reason string. This closes the drift gap where an operator
deletes a grant role out-of-band (via the AWS console, terraform,
manual aws-cli) and iam-jit's view stays stuck at `active` forever.

Per `[[ibounce-honest-positioning]]`: the reconciler does NOT fight
against ground-truth (the AWS API answer is always authoritative). It
just propagates the truth back into iam-jit's state machine.

Per `[[creates-never-mutates]]`: this module NEVER creates or modifies
IAM roles. The only AWS calls it makes are `iam:GetRole` (read-only)
and the request store updates are pure-Python.

Failure handling: any per-request failure (account not registered,
ProvisionerRole missing, IAM throttling, etc.) is logged + skipped.
The next reconcile interval retries. The reconciler NEVER crashes the
serve loop.

Started by `local_server.run()` as a background asyncio task; killed
on server shutdown. The cadence is configurable via
`--reconcile-interval-seconds` (default 60). Set to 0 to disable.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
from typing import Any

logger = logging.getLogger("iam_jit.reconciler")


def _isoformat_z(dt: _dt.datetime) -> str:
    """ISO-8601 with `Z` suffix for canonical AWS-compatible timestamps."""
    return dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_iam_client_factory(creds: dict[str, str]) -> Any:
    """Construct a boto3 IAM client from temporary credentials. Used as
    the default `iam_client_factory` when the caller doesn't inject one."""
    import boto3
    return boto3.client("iam", **creds)


def _default_sts_client() -> Any:
    """Build a boto3 STS client from the boto3 default credential chain.
    Used as the default `sts_client` when the caller doesn't inject one."""
    import boto3
    return boto3.client("sts")


def reconcile_once(
    *,
    store: Any,
    accounts_store: Any,
    provision_mod: Any,
    lifecycle: Any,
    sts_client: Any | None = None,
    iam_client_factory: Any | None = None,
    actor: str = "system:reconciler",
) -> dict[str, int]:
    """Run one reconciliation pass over every active request.

    Returns a small stats dict:
        {"checked": N, "revoked": N, "skipped": N, "errors": N}

    Never raises. Each request is processed independently — a failure
    on one request never blocks the others.
    """
    stats = {"checked": 0, "revoked": 0, "skipped": 0, "errors": 0}

    # Lazy-initialize the AWS clients so a reconcile pass with zero
    # active requests doesn't pay the boto3-import cost.
    _sts = sts_client
    _iam_factory = iam_client_factory or _default_iam_client_factory

    try:
        request_ids = store.list_ids()
    except Exception as e:
        logger.warning("reconciler: list_ids failed: %s", e)
        return stats

    for rid in request_ids:
        try:
            req = store.get(rid)
        except Exception as e:
            logger.debug(
                "reconciler: skipping %s (load failed: %s)", rid, e,
            )
            stats["errors"] += 1
            continue

        state = lifecycle.get_state(req)
        if state != "active":
            continue
        stats["checked"] += 1

        provisioned = (req.get("status") or {}).get("provisioned") or {}
        role_arn = provisioned.get("role_arn")
        role_name = provisioned.get("role_name")
        account_id = provisioned.get("account_id")
        if not (role_arn and role_name and account_id):
            # Pre-#698 provisioned blocks may lack one of these; skip
            # rather than risk a false revoke.
            stats["skipped"] += 1
            continue

        try:
            account = accounts_store.get(account_id)
        except Exception:
            # Account was deregistered after provisioning. Can't probe
            # without the provisioner role; skip + log.
            logger.debug(
                "reconciler: account %s for request %s not registered",
                account_id, rid,
            )
            stats["skipped"] += 1
            continue

        try:
            if _sts is None:
                _sts = _default_sts_client()
            creds = provision_mod._assume_provisioner_role(
                _sts, account,
                # session-name is informational; reconciler distinguishes
                # itself from operator-driven sessions for audit.
                session_name=f"iam-jit-reconciler-{rid[:32]}",
            )
        except Exception as e:
            logger.debug(
                "reconciler: assume failed for %s: %s", account_id, e,
            )
            stats["errors"] += 1
            continue

        # Probe via iam:GetRole — the canonical existence check that
        # raises NoSuchEntity / NoSuchEntityException when the role is
        # gone. boto3 surfaces this as a ClientError; we string-match
        # for portability across botocore versions.
        try:
            iam = _iam_factory(creds)
            iam.get_role(RoleName=role_name)
            # Role still exists — nothing to do.
            continue
        except Exception as e:
            msg = str(e)
            if "NoSuchEntity" not in msg:
                logger.debug(
                    "reconciler: get_role probe failed for %s: %s",
                    role_arn, e,
                )
                stats["errors"] += 1
                continue
            # Role really is gone. Transition to revoked.
            revocation = {
                "role_arn": role_arn,
                "role_name": role_name,
                "account_id": account_id,
                "revoked_at": _isoformat_z(_dt.datetime.now(_dt.UTC)),
                "revoked_by": actor,
                "reason": "RECONCILED — IAM role no longer exists",
                "role_existed": False,
                "inline_policies_deleted": [],
                "aws_cli_replay": [],
            }
            try:
                lifecycle.mark_revoked(
                    req, revoked_by=actor, revocation=revocation,
                )
                store.put(rid, req)
                logger.info(
                    "reconciler: marked request %s as revoked "
                    "(role %s gone in account %s)",
                    rid, role_arn, account_id,
                )
                stats["revoked"] += 1
            except Exception as e:
                logger.warning(
                    "reconciler: failed to mark %s revoked: %s", rid, e,
                )
                stats["errors"] += 1

    return stats


async def reconcile_loop(
    *,
    store: Any,
    accounts_store: Any,
    provision_mod: Any,
    lifecycle: Any,
    interval_seconds: int = 60,
    actor: str = "system:reconciler",
    stop_event: asyncio.Event | None = None,
    sts_client: Any | None = None,
    iam_client_factory: Any | None = None,
) -> None:
    """Run `reconcile_once` every `interval_seconds` until `stop_event`
    fires (or the task is cancelled).

    `interval_seconds <= 0` disables the loop — useful when an operator
    explicitly wants to opt out (debugging, single-shot scripts). The
    function returns immediately in that case.

    Designed to be spawned as an asyncio background task from the
    serve loop. The reconciler runs in the SAME event loop as the
    FastAPI app; CPU cost is dominated by the boto3 IAM call per
    active request which is async-IO-bound.
    """
    if interval_seconds <= 0:
        logger.info(
            "reconciler: disabled (interval_seconds=%s)", interval_seconds,
        )
        return

    logger.info(
        "reconciler: starting loop with interval=%ss", interval_seconds,
    )
    stop = stop_event or asyncio.Event()
    while not stop.is_set():
        try:
            # The reconcile pass is sync (uses boto3); run it in a
            # thread so it doesn't block the event loop while IAM
            # calls are in flight.
            stats = await asyncio.to_thread(
                reconcile_once,
                store=store,
                accounts_store=accounts_store,
                provision_mod=provision_mod,
                lifecycle=lifecycle,
                sts_client=sts_client,
                iam_client_factory=iam_client_factory,
                actor=actor,
            )
            if stats.get("revoked", 0) > 0:
                logger.info("reconciler: pass complete %s", stats)
            else:
                logger.debug("reconciler: pass complete %s", stats)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # Top-level guard: an unhandled exception in reconcile_once
            # should not break the loop. The next iteration retries.
            logger.warning("reconciler: pass crashed: %s", e)

        try:
            await asyncio.wait_for(
                stop.wait(), timeout=interval_seconds,
            )
        except asyncio.TimeoutError:
            continue  # next pass
        except asyncio.CancelledError:
            raise
