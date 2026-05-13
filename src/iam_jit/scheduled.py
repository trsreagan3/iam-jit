"""Scheduled-task entry point.

Single function the production scheduled-Lambda calls on each EventBridge
firing. Aggregates every periodic chore iam-jit needs to run:

  - inactive-token sweep (180-day default, ~6 months)
  - (future) expired-grant cleanup
  - (future) draft-store TTL cleanup
  - (future) audit-log integrity checkpoint

Returns a structured result so the handler can log a single line per
sweep — both for operator visibility and for the integrity checkpoint
to fingerprint.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from . import token_sweep
from .api_tokens_store import APITokenStore


logger = logging.getLogger("iam_jit.scheduled")


def _read_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        v = int(raw)
        return v if v > 0 else default
    except ValueError:
        return default


def run_scheduled_tasks(
    *,
    tokens_store: APITokenStore | None,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    """Run every periodic task once.

    `tokens_store=None` (e.g., misconfigured deployment) skips the
    token sweep cleanly rather than crashing the Lambda; the result
    payload reports the skip so an operator can fix it.

    `now_epoch` is for tests — production lets the function read the
    wall clock.
    """
    now = int(now_epoch if now_epoch is not None else time.time())
    out: dict[str, Any] = {"timestamp": now, "tasks": {}}

    # ---- Token sweep ----
    if tokens_store is None:
        out["tasks"]["token_sweep"] = {"status": "skipped", "reason": "no tokens_store"}
    else:
        days = _read_int_env(
            "IAM_JIT_TOKEN_INACTIVITY_DAYS",
            token_sweep.DEFAULT_INACTIVITY_DAYS,
        )
        try:
            result = token_sweep.sweep_inactive_tokens(
                tokens_store=tokens_store,
                inactivity_days=days,
                now_epoch=now,
            )
            out["tasks"]["token_sweep"] = {
                "status": "ok",
                "inactivity_days": days,
                "scanned": result.scanned,
                "revoked": len(result.revoked),
                "skipped": len(result.skipped),
            }
            if result.revoked:
                logger.info(
                    "token sweep revoked %d token(s) inactive ≥%dd",
                    len(result.revoked), days,
                )
        except Exception as e:
            logger.exception("token sweep failed")
            out["tasks"]["token_sweep"] = {
                "status": "error",
                "error": f"{type(e).__name__}: {e}",
            }

    return out
