"""MRR-2 R2 — generalised silent-degradation visibility helper.

Closes Pattern B from ``docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md``:

    try:
        do_thing()
    except Exception as e:
        logger.warning("X failed: %s", e)   # or logger.debug(...)
        return fallback_default()

The fallback IS the right behaviour per
``[[ibounce-honest-positioning]]`` (refusing to run is worse than
running degraded). But the operator never tails the warning log, so
the failure is invisible — exactly the silent-degradation shape MRR-1
caught as finding #5 (LLM-call-site audit) and that
``llm/report_skip.py`` already closes for the LLM surface.

This module lifts the same pattern to a generic
``emit(feature=..., reason=..., extra={...})`` so EVERY
silent-fallback site has a single observable place the operator + the
agent can see it:

  * ``/healthz`` exposes the snapshot under ``degraded_capabilities``.
  * ``iam-jit posture`` surfaces the same snapshot.
  * Each emit also writes a ``logging.WARNING`` (not debug) so log
    aggregators with default config catch it.

Counters live in process memory. They reset on process restart — same
trade-off as ``llm/report_skip.py``: a long-lived counter would
conflate "this run degraded N times" with "we ever degraded N times".
For persistent counting use the audit log (each emit goes out at
WARNING, which audit shipping captures).

Public API:

  * :func:`emit`     — record a degradation event.
  * :func:`snapshot` — return ``{counts, by_reason, last_events,
    total}`` for /healthz + posture.
  * :func:`reset`    — test-only.

Distinct from :mod:`iam_jit.llm.report_skip`:

  * ``llm.report_skip`` is specific to LLM-call-site skips where
    "ran deterministic-only" is the EXPECTED local-dev shape. Its
    log message is intentionally framed as "this is correct" so
    operators don't panic at every entry.
  * ``degraded_capability.emit`` is for sites where a feature
    actually FAILED to run as intended (env-var typo, missing
    sub-module, audit-emit died, etc.) and the operator should
    investigate.

The two snapshots compose under /healthz (separate top-level blocks).
"""

from __future__ import annotations

import datetime as _dt
import logging
import threading
from typing import Any

logger = logging.getLogger("iam_jit.degraded_capability")


# ---------------------------------------------------------------------------
# Reasons (canonical short strings). Free-form reasons are still
# accepted — these are the well-known ones so observers can branch
# deterministically.
# ---------------------------------------------------------------------------

REASON_BAD_ENV_VAR_VALUE = "bad_env_var_value"
"""Operator-supplied env var couldn't be parsed (typo / wrong type).
Site falls back to its default rather than refusing to run."""

REASON_SUB_LOAD_FAILED = "sub_load_failed"
"""Failed to import / resolve a sub-feature (threat-feed subscriptions,
classifier hook, etc.). Site degrades to "feature unavailable" rather
than crashing the autopilot loop."""

REASON_EVAL_RAISED = "eval_raised"
"""Inner evaluation raised an unexpected exception. Site falls back
to a deterministic no-op verdict rather than 500-ing the request."""

REASON_AUDIT_EMIT_FAILED = "audit_emit_failed"
"""Admin-action / structured-deny audit emit raised (sink down,
permissions, etc.). The PRIMARY action succeeded but its audit-trail
witness is missing. Cumulatively this is the #475 shape."""

REASON_CYCLE_RAISED = "cycle_raised"
"""A daemon-loop body (autopilot improve cycle, threat-feed tick, etc.)
raised; the supervisor continues the loop but THIS iteration is lost."""


# ---------------------------------------------------------------------------
# Counter state (process-local, thread-safe)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_counts: dict[str, int] = {}
"""``{feature: count}`` — incremented on every :func:`emit` call."""

_count_by_reason: dict[str, int] = {}
"""``{reason: count}`` — same shape, keyed by ``reason``."""

_last_events: list[dict[str, Any]] = []
"""Ring buffer of the most recent N events. Read by ``/healthz`` so
operators see recent degradations without trawling the log."""

_MAX_LAST = 20
"""Cap on ``_last_events`` length. Older entries fall off so a
misbehaving site can't balloon process memory."""


def emit(
    *,
    feature: str,
    reason: str,
    hint: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    """Record that ``feature`` ran in degraded mode.

    Emits a ``logging.WARNING`` (NOT debug — operators must be able to
    grep their logs for these), increments the session counter, and
    appends to the ring buffer.

    Stable structured fields the warning carries (consumed by audit
    shipping + downstream log queries):

      * ``degraded_feature`` — the feature name
      * ``degraded_reason`` — the reason string
      * ``degraded_hint``   — operator-language remediation hint

    Args:
      feature: short stable identifier of the call-site
        (``autopilot.improve_cycle`` / ``synthesis.max_lookback_env`` /
        ``self_approve.eval`` / etc.). Used as the primary counter key.
      reason: one of the ``REASON_*`` constants or a free-form short
        string. Used as the secondary counter key.
      hint: optional operator-language remediation pointer. Empty
        string means "no specific hint" — the feature name + reason
        are enough.
      extra: optional structured fields appended to the log record's
        ``extra`` dict. MUST NOT carry credentials / PII per
        ``[[mitm-beta-pii-pci-concern]]``.
    """
    feature = (feature or "unknown").strip() or "unknown"
    reason = (reason or "unknown").strip() or "unknown"
    hint = (hint or "").strip()

    if hint:
        msg = (
            f"feature={feature} degraded (reason={reason}). {hint}"
        )
    else:
        msg = f"feature={feature} degraded (reason={reason})."

    log_extra: dict[str, Any] = {
        "degraded_feature": feature,
        "degraded_reason": reason,
        "degraded_hint": hint,
    }
    if extra:
        # Shallow-copy so callers can't mutate our extras post-call.
        # Only the well-known prefix gets through to keep audit
        # shipping clean (matches llm.report_skip's same guard).
        log_extra.update({
            k: v for k, v in extra.items() if k.startswith("degraded_")
        })

    logger.warning(msg, extra=log_extra)

    event = {
        "at": _dt.datetime.now(_dt.timezone.utc)
            .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "feature": feature,
        "reason": reason,
        "hint": hint,
    }
    with _lock:
        _counts[feature] = _counts.get(feature, 0) + 1
        _count_by_reason[reason] = _count_by_reason.get(reason, 0) + 1
        _last_events.append(event)
        if len(_last_events) > _MAX_LAST:
            del _last_events[: len(_last_events) - _MAX_LAST]


def snapshot() -> dict[str, Any]:
    """Return a snapshot of the degraded-capability counters.

    Shape:

      {
        "total": int,                       # sum across all features
        "counts": {feature: int, ...},
        "by_reason": {reason: int, ...},
        "last_events": [{at, feature, reason, hint}, ...],
      }

    Consumed by ``/healthz`` (proxy) + ``iam-jit posture``. Safe to
    call from any thread; returns a deep-copy snapshot (callers can
    mutate freely without affecting live state).
    """
    with _lock:
        return {
            "total": sum(_counts.values()),
            "counts": dict(_counts),
            "by_reason": dict(_count_by_reason),
            "last_events": list(_last_events),
        }


def reset() -> None:
    """Reset all counters. Test-only — production code must not call
    this (in-process state is the truth; the audit log is the durable
    record)."""
    with _lock:
        _counts.clear()
        _count_by_reason.clear()
        _last_events.clear()


__all__ = [
    "REASON_AUDIT_EMIT_FAILED",
    "REASON_BAD_ENV_VAR_VALUE",
    "REASON_CYCLE_RAISED",
    "REASON_EVAL_RAISED",
    "REASON_SUB_LOAD_FAILED",
    "emit",
    "reset",
    "snapshot",
]
