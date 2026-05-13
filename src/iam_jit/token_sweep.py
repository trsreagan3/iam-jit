"""Inactive-token sweep.

Auto-revokes API tokens that haven't been used in N days (default
180 = ~6 months). The sweep is idempotent — running it twice on the
same store produces the same result. Intended call sites:

  - the scheduled-expiry Lambda (production)
  - POST /api/v1/admin/sweep-inactive-tokens (admin-on-demand,
    typically used to verify what *would* happen via dry_run=True)

What counts as "last used":
  - `last_used_at` if present (set on every authenticated request the
    middleware processes)
  - else `created_at` (so a never-used token gets swept exactly the
    same as a used-once-then-abandoned token, which is the right
    behavior — both are equally stale)

We never delete a token that's been used or created within the cutoff
window. Tokens with malformed timestamps are SKIPPED, not deleted —
the sweep should never destroy data because of bad metadata.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from .api_tokens_store import APITokenRecord, APITokenStore


logger = logging.getLogger("iam_jit.token_sweep")


# 6 months ≈ 180 days. Not 183 (half a year) because aligning to a
# round number reads more naturally in audit summaries.
DEFAULT_INACTIVITY_DAYS = 180


@dataclass(frozen=True)
class SweptToken:
    token_hash: str
    user_id: str
    label: str | None
    last_activity_at: int
    """The epoch-seconds value the sweep used as the "last activity"
    decision input — `last_used_at` if set, else `created_at`."""
    days_inactive: int


@dataclass(frozen=True)
class SweepResult:
    inactivity_days: int
    cutoff_epoch: int
    scanned: int
    revoked: list[SweptToken]
    skipped: list[dict]
    """Each entry: {token_hash, user_id, reason}. Reasons:
    'malformed_timestamp', 'within_window'."""
    dry_run: bool


def _last_activity(record: APITokenRecord) -> int | None:
    """The decision-input timestamp. None if neither timestamp is a
    sane epoch-seconds integer."""
    candidate = record.last_used_at if record.last_used_at is not None else record.created_at
    if not isinstance(candidate, (int, float)):
        return None
    candidate_int = int(candidate)
    # Reject obviously-bogus values: negative, before iam-jit existed
    # (epoch < 2024-01-01), or further than a year in the future.
    if candidate_int < 1_704_067_200:
        return None
    if candidate_int > int(time.time()) + 365 * 86400:
        return None
    return candidate_int


def sweep_inactive_tokens(
    *,
    tokens_store: APITokenStore,
    inactivity_days: int = DEFAULT_INACTIVITY_DAYS,
    now_epoch: int | None = None,
    dry_run: bool = False,
) -> SweepResult:
    """Revoke every token whose last activity is older than
    `inactivity_days` ago.

    `dry_run=True` reports what would be revoked without deleting. Use
    when verifying the sweep against a production store before running
    for real.
    """
    if inactivity_days < 1:
        raise ValueError("inactivity_days must be >= 1")
    now = int(now_epoch if now_epoch is not None else time.time())
    cutoff = now - inactivity_days * 86400

    all_tokens = tokens_store.list_all()
    revoked: list[SweptToken] = []
    skipped: list[dict] = []

    for record in all_tokens:
        ts = _last_activity(record)
        if ts is None:
            skipped.append(
                {
                    "token_hash": record.token_hash,
                    "user_id": record.user_id,
                    "reason": "malformed_timestamp",
                }
            )
            continue
        if ts >= cutoff:
            skipped.append(
                {
                    "token_hash": record.token_hash,
                    "user_id": record.user_id,
                    "reason": "within_window",
                }
            )
            continue
        days_inactive = max(0, (now - ts) // 86400)
        revoked.append(
            SweptToken(
                token_hash=record.token_hash,
                user_id=record.user_id,
                label=record.label,
                last_activity_at=ts,
                days_inactive=days_inactive,
            )
        )

    if not dry_run:
        for swept in revoked:
            try:
                tokens_store.delete(swept.token_hash)
            except Exception:
                logger.exception(
                    "delete token %s for user %s during sweep failed",
                    swept.token_hash,
                    swept.user_id,
                )

    logger.info(
        "token sweep: scanned=%d revoked=%d skipped=%d dry_run=%s "
        "inactivity_days=%d",
        len(all_tokens),
        len(revoked),
        len(skipped),
        dry_run,
        inactivity_days,
    )
    return SweepResult(
        inactivity_days=inactivity_days,
        cutoff_epoch=cutoff,
        scanned=len(all_tokens),
        revoked=revoked,
        skipped=skipped,
        dry_run=dry_run,
    )
