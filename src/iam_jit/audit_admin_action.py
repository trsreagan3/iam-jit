"""OCSF v1.1.0 class 6003 admin-action emit helper for iam-jit routes.

Closes #660 CRIT: ``emit_admin_action_direct()`` was wired ONLY through
``bouncer.proxy._emit_audit_event`` — which is None in ``iam-jit serve
--local`` mode (the canonical v1.0 deployment shape, per
[[no-hosted-saas]]).  Result: ZERO OCSF class 6003 events with
``unmapped.iam_jit.event_type == "ADMIN_ACTION"`` landed in any audit
stream for account register/deregister operations in local mode.  The
plain ``account.registered`` / ``account.deregistered`` rows emitted via
``audit.emit()`` DID persist (per #632), but SIEM parsers consuming the
OCSF stream got incomplete data.

This module provides ``emit_iam_jit_admin_action()``, a two-channel emit
helper that:

  1. Always calls ``audit.emit()`` — the hash-chained JSONL log wired by
     #632 via ``IAM_JIT_AUDIT_LOG``. Works in both local mode and any
     deployment shape that sets the env var. The OCSF event is embedded
     in ``details`` so the JSONL log carries the full class 6003 payload.

  2. Also calls ``bouncer.proxy._emit_audit_event`` when that channel is
     live (non-local / fully-deployed modes). This is a best-effort
     call — if the proxy channel is not wired, the import returns None
     and the call is skipped.

  3. Logs a WARNING (not a crash) on any emit failure. Per
     [[ibounce-honest-positioning]] the user-facing operation already
     succeeded before this is called; audit emission is secondary. But
     silent swallow per ``except Exception: pass`` (the pre-#660 shape)
     is also wrong: operators deserve a log line so they can diagnose a
     misconfigured audit channel without reading source code.

This closes #661 (silent-swallow -> logger.warning) in the same commit.

Per [[creates-never-mutates]] this module contains NO enforcement logic.
Per [[deliberate-feature-completion]] only the account register/deregister
admin-action sites are refactored here; other OCSF emit sites are
out of scope.
"""

from __future__ import annotations

import logging
from typing import Any

from . import audit

logger = logging.getLogger("iam_jit.audit_admin_action")


def emit_iam_jit_admin_action(
    *,
    kind: str,
    actor: str,
    target_kind: str = "",
    target_id: str = "",
    source: str = "api",
    extra: dict[str, Any] | None = None,
) -> None:
    """Emit an OCSF v1.1.0 class 6003 admin-action event via BOTH
    audit channels available in local mode and non-local modes.

    Channel 1 (always): ``audit.emit()`` → ``IAM_JIT_AUDIT_LOG`` JSONL.
    Channel 2 (when wired): ``bouncer.proxy._emit_audit_event`` → the
    proxy audit channel (JSONL writer + webhook + Security Lake).

    Failures on either channel are caught, logged as WARNING, and NOT
    re-raised.  The caller's request has already succeeded; audit
    emission is secondary.  Per [[ibounce-honest-positioning]] we DO
    surface failures — we do NOT silently swallow them.

    Parameters
    ----------
    kind
        Admin-action kind string, e.g. ``"account.registered"``.
    actor
        Actor identity (user.id, email, OIDC sub).
    target_kind
        Human-readable label for the affected entity type,
        e.g. ``"aws_account"``.
    target_id
        Identifier of the affected entity, e.g. the AWS account ID.
    source
        Where the action originated. Defaults to ``"api"``.
    extra
        Optional per-event context dict. Token-leak keys are stripped
        by ``make_admin_action_event`` before landing on the wire.
    """
    # Build the OCSF class 6003 event dict once; both channels receive
    # the same object so the wire shape is identical regardless of which
    # channel is live.
    ocsf_event: dict[str, Any] | None = None
    try:
        from .bouncer.audit_export.admin_action import make_admin_action_event
        ocsf_event = make_admin_action_event(
            kind=kind,
            actor=actor,
            target_kind=target_kind,
            target_id=target_id,
            source=source,
            extra=extra,
        )
    except Exception as exc:
        logger.warning(
            "iam_jit admin-action OCSF event build failed for kind=%s actor=%s: %s",
            kind, actor, exc,
        )

    # Channel 1: audit.emit() — always available when IAM_JIT_AUDIT_LOG
    # is set (wired by _set_local_env_defaults in local_server.py per #632).
    # The OCSF event is embedded in details so the JSONL log carries the
    # full class 6003 payload alongside the hash-chained metadata.
    try:
        audit.emit(
            actor=actor,
            kind="admin.action",
            summary=f"OCSF admin-action {kind!r} on {target_kind} {target_id!r}",
            details={
                "ocsf_class_uid": 6003,
                "event_type": "ADMIN_ACTION",
                "admin_action": {
                    "kind": kind,
                    "actor": actor,
                    "target_kind": target_kind,
                    "target_id": target_id,
                    "source": source,
                    **(extra or {}),
                },
                # Embed the full OCSF dict when available so SIEM
                # parsers can consume it from the JSONL stream without
                # a separate channel.
                **({"ocsf_event": ocsf_event} if ocsf_event is not None else {}),
            },
        )
    except Exception as exc:
        logger.warning(
            "iam_jit admin-action audit.emit() failed for kind=%s actor=%s: %s",
            kind, actor, exc,
        )

    # Channel 2: bouncer.proxy._emit_audit_event — wired in non-local /
    # fully-deployed modes. _emit_audit_event itself guards on
    # _audit_log_writer being set (per _emit_audit_event_raw), so calling
    # it in local mode (where _audit_log_writer is None) is already a
    # no-op at the transport level. Best-effort: if the proxy module is
    # not importable (test isolation), skip with a debug log — this is
    # expected in unit-test environments that don't import the full proxy.
    if ocsf_event is not None:
        try:
            from .bouncer.proxy import _emit_audit_event as _proxy_emit
            _proxy_emit(ocsf_event)
        except ImportError:
            # Proxy not available (test environment or stripped install).
            logger.debug(
                "iam_jit admin-action: bouncer.proxy not importable, "
                "skipping proxy emit for kind=%s", kind,
            )
        except Exception as exc:
            logger.warning(
                "iam_jit admin-action proxy emit failed for kind=%s actor=%s: %s",
                kind, actor, exc,
            )
