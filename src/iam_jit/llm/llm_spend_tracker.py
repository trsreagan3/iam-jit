"""§A102+ / MRR-5 M3 — per-process daily LLM-spend tracker.

Process-local counter for bouncer-side LLM USD spend. Surfaces a
structured ``llm_budget`` block on ``/healthz`` so the operator (and
external monitoring) can detect approaching cost-cap exhaustion
without scraping ``autopilot.status.json`` ``.alerts``.

Per ``[[ibounce-honest-positioning]]`` the block reports honestly:

  * ``IAM_JIT_ENABLE_SIDE_LLM`` unset (the default per
    ``[[bouncer-zero-llm-when-agent-in-loop]]``) → ``{"enabled": false}``.
    The bouncer is in local-dev / agent-in-loop mode; the agent owns
    LLM cost accounting via its own backend.
  * ``IAM_JIT_ENABLE_SIDE_LLM`` set → ``{"enabled": true, ...}`` with
    used/cap/remaining/percent/approaching_limit fields. The cap reads
    from ``IAM_JIT_LLM_BUDGET_USD_PER_DAY`` (default 5.00 USD/day —
    matched to the autopilot-side conservative starter cap).

Counter state lives in process memory + reset on day boundary (UTC).
This is intentional: the canonical durable record is the audit log
(each LLM call emits a structured event audit shipping captures).
For multi-process aggregation, the operator's monitor sums across
bouncer ``/healthz`` endpoints.

Cross-references:

  * ``[[launch-infra-vs-pricing-audit]]`` — the per-customer LLM
    budget cap discipline this honors.
  * ``docs/MRR-5-MONITORING-RUNBOOK.md`` §6 task M3 — the closure
    for the C7 ``LLM cost-cap breach`` halt-condition's
    monitoring-surface gap.
  * ``iam_jit.llm.report_skip`` — sibling pattern; both are
    cross-cutting trackers for LLM-augmented sites with structured
    snapshots for ``/healthz``.
"""

from __future__ import annotations

import datetime as _dt
import os
import threading
from typing import Any


# ---------------------------------------------------------------------------
# Env-var names + defaults
# ---------------------------------------------------------------------------

ENV_SIDE_LLM_OPT_IN = "IAM_JIT_ENABLE_SIDE_LLM"
"""Operator-side opt-in for bouncer-side LLM. Mirrors the env-var
checked in :mod:`iam_jit.llm.profile_generator` +
:mod:`iam_jit.structured_deny.response` so the four LLM-augmented
sites + this tracker all agree on "is side-LLM on?"."""

ENV_BUDGET_USD_PER_DAY = "IAM_JIT_LLM_BUDGET_USD_PER_DAY"
"""Per-day USD cap. Operator can raise / lower per deployment. None
or 'unlimited' / '-1' disables the cap (block reports enabled but
no cap)."""

DEFAULT_BUDGET_USD_PER_DAY = 5.00
"""Conservative starter cap — matches the
``[[launch-infra-vs-pricing-audit]]`` per-customer budget shape;
operator raises via env on production deployments."""

APPROACHING_LIMIT_PCT = 80.0
"""Threshold at which ``approaching_limit: true`` flips. 80% gives
the operator ~20% headroom to react before the cap hits."""


# ---------------------------------------------------------------------------
# Counter state (process-local, thread-safe)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_spend_by_day: dict[str, float] = {}
"""``{YYYY-MM-DD (UTC): cumulative USD spent that day}``. Only the
current day is read; prior-day entries fall off after 7 days to keep
memory bounded under pathological clock-skew."""

_MAX_DAYS_RETAINED = 7
"""Cap on prior-day entries. Used by the trim helper."""


def _side_llm_enabled() -> bool:
    """True iff operator EXPLICITLY enabled bouncer-side LLM via
    ``IAM_JIT_ENABLE_SIDE_LLM=1|true|yes|on``. Mirrors
    :func:`iam_jit.llm.profile_generator._side_llm_enabled` so the
    tracker + the call-sites agree."""
    raw = (os.environ.get(ENV_SIDE_LLM_OPT_IN) or "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _budget_cap_usd() -> float | None:
    """Resolve the configured per-day USD cap. Returns ``None`` when
    the operator explicitly disabled the cap (``none`` / ``unlimited``
    / ``-1`` / ``""``); otherwise returns a non-negative float."""
    raw = (os.environ.get(ENV_BUDGET_USD_PER_DAY) or "").strip()
    if not raw:
        return DEFAULT_BUDGET_USD_PER_DAY
    if raw.lower() in ("none", "unlimited", "-1"):
        return None
    try:
        v = float(raw)
        if v < 0:
            return None
        return v
    except ValueError:
        return DEFAULT_BUDGET_USD_PER_DAY


def _current_day_utc() -> str:
    """``YYYY-MM-DD`` in UTC. Day boundary defines the spend window."""
    now = _dt.datetime.now(_dt.timezone.utc)
    return f"{now.year:04d}-{now.month:02d}-{now.day:02d}"


def _trim_locked() -> None:
    """Trim ``_spend_by_day`` to the last ``_MAX_DAYS_RETAINED`` days.
    Caller must hold ``_lock``."""
    if len(_spend_by_day) <= _MAX_DAYS_RETAINED:
        return
    # Drop oldest entries (string-sort works for YYYY-MM-DD).
    sorted_keys = sorted(_spend_by_day.keys())
    for k in sorted_keys[: len(sorted_keys) - _MAX_DAYS_RETAINED]:
        del _spend_by_day[k]


def record_spend(usd: float) -> None:
    """Record ``usd`` spend against the current UTC day.

    Call sites: every bouncer-side LLM caller (deny_classifier,
    autopilot improve cycle, profile_generator, enterprise proposal)
    after a successful backend call. Cost figures come from the
    backend's ``estimate_cost_per_1k`` * token counts.

    Negative values are clamped to 0 (defence against backend
    estimators that misreport — silently accepting a negative would
    make the tracker lie about remaining budget)."""
    if usd is None:
        return
    try:
        usd_f = float(usd)
    except (TypeError, ValueError):
        return
    if usd_f < 0:
        usd_f = 0.0
    day = _current_day_utc()
    with _lock:
        _spend_by_day[day] = _spend_by_day.get(day, 0.0) + usd_f
        _trim_locked()


def spend_snapshot() -> dict[str, Any]:
    """Return the ``/healthz.llm_budget`` block contents.

    Shape when side-LLM is OFF (the default):

      {"enabled": false}

    Shape when side-LLM is ON and a cap is set:

      {
        "enabled": true,
        "used_today_usd": float,
        "cap_per_day_usd": float,
        "remaining_usd": float,
        "percent_consumed": float,   # 0..100+
        "approaching_limit": bool,   # true at >= 80% (or over-cap)
      }

    Shape when side-LLM is ON but the operator disabled the cap
    (``IAM_JIT_LLM_BUDGET_USD_PER_DAY=none``):

      {
        "enabled": true,
        "used_today_usd": float,
        "cap_per_day_usd": null,
        "remaining_usd": null,
        "percent_consumed": null,
        "approaching_limit": false,
      }

    Safe to call from any thread; returns a new dict (callers may
    mutate freely without affecting tracker state).
    """
    if not _side_llm_enabled():
        return {"enabled": False}
    day = _current_day_utc()
    with _lock:
        used = _spend_by_day.get(day, 0.0)
    cap = _budget_cap_usd()
    if cap is None:
        return {
            "enabled": True,
            "used_today_usd": round(used, 6),
            "cap_per_day_usd": None,
            "remaining_usd": None,
            "percent_consumed": None,
            "approaching_limit": False,
        }
    if cap == 0:
        # Cap of 0 is a deliberate "block all spend" posture. Any
        # spend AT ALL is over-cap; percent is meaningless (would be
        # division by zero) so report a sentinel 100.0 and flag
        # approaching.
        return {
            "enabled": True,
            "used_today_usd": round(used, 6),
            "cap_per_day_usd": 0.0,
            "remaining_usd": 0.0,
            "percent_consumed": 100.0 if used > 0 else 0.0,
            "approaching_limit": used > 0,
        }
    pct = (used / cap) * 100.0
    remaining = max(0.0, cap - used)
    return {
        "enabled": True,
        "used_today_usd": round(used, 6),
        "cap_per_day_usd": round(cap, 6),
        "remaining_usd": round(remaining, 6),
        "percent_consumed": round(pct, 2),
        "approaching_limit": pct >= APPROACHING_LIMIT_PCT,
    }


def reset_for_tests() -> None:
    """Reset all spend state. Test-only — production code must not
    call this (in-process state is the truth; the audit log is the
    durable record)."""
    with _lock:
        _spend_by_day.clear()


__all__ = [
    "APPROACHING_LIMIT_PCT",
    "DEFAULT_BUDGET_USD_PER_DAY",
    "ENV_BUDGET_USD_PER_DAY",
    "ENV_SIDE_LLM_OPT_IN",
    "record_spend",
    "reset_for_tests",
    "spend_snapshot",
]
