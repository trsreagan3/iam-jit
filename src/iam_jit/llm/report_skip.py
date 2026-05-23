"""§A93 / #509 Phase 2 — structured LLM-skip helper.

Cross-cutting tracker for every code path that WOULD have called an
LLM (deny classification / improve cycle / NL→profile / enterprise
proposal / etc.) but instead ran deterministic-only because no LLM
backend was configured.

Per [[bouncer-zero-llm-when-agent-in-loop]] the right behavior in
local-dev (agent-in-loop) is to RUN DETERMINISTIC + delegate the
intelligent work to the agent via MCP. That is NOT a failure — it's
the intended shape — but it MUST be observable so:

  * operators can confirm "yes, my bouncer is in local-dev mode and
    intelligently deferring to my agent" rather than silently losing
    LLM-augmented signal
  * agents can introspect /healthz + ``iam-jit posture`` and notice
    "this site has N skipped-LLM events; you should call MCP enrichment
    tools to fill the gap"
  * the calibration-drift / silent-degradation failure mode the
    [[deliberate-feature-completion]] audits keep catching is closed

Public API:

  * ``report_skip(feature, reason="no_llm_backend", mode_hint=...)``
    — emit a structured WARNING + increment the session counter.
  * ``skip_counter_snapshot()`` — return ``{counts: {...},
    last_skips: [...], total: N}`` for ``/healthz`` + ``iam-jit posture``.
  * ``reset_skip_counter()`` — test-only.

Counters live in process memory. They reset on process restart — this
is intentional: a long-lived counter would conflate "this run skipped
N times" with "we ever skipped N times across the daemon's lifetime".
For persistent counting use the audit log (each skip emits a structured
WARNING that audit shipping captures).
"""

from __future__ import annotations

import datetime as _dt
import logging
import threading
from typing import Any

logger = logging.getLogger("iam_jit.llm.skip")


# ---------------------------------------------------------------------------
# Reasons (canonical short strings). Free-form ``reason`` strings are
# still accepted — these are just the well-known ones so callers /
# observers can branch deterministically.
# ---------------------------------------------------------------------------

REASON_NO_LLM_BACKEND = "no_llm_backend"
"""Default: no LLM credentials configured. Local-dev / agent-in-loop
shape. Operator action: NONE REQUIRED — the agent is the LLM."""

REASON_NO_SIDE_LLM_ENABLED = "no_side_llm_enabled"
"""Operator did not set ``--enable-side-llm`` (autopilot daemon /
standalone-mode opt-in flag). Same outcome as no_llm_backend but
distinct provenance: this site intentionally requires opt-in even
when an LLM is configured."""

REASON_BUDGET_EXCEEDED = "budget_exceeded"
"""Per-call budget cap (e.g. classifier) refused to spend more. The
LLM IS configured; we just chose not to call it for this specific
request."""

REASON_BACKEND_UNAVAILABLE = "backend_unavailable"
"""Backend is configured but didn't respond (network / auth /
parse). Different from no_llm_backend: operator likely wanted LLM
but their backend is down. Operator action: check backend connectivity."""

REASON_RESPONSE_INVALID = "response_invalid"
"""Backend returned a response we couldn't parse. Operator action:
check model selection / prompt template; usually a backend rev mismatch."""


# Default operator-language hint string referenced by the canonical
# message template. Kept module-level so tests can assert it.
DEFAULT_MODE_HINT = (
    "Set --enable-side-llm + IAM_JIT_LLM=anthropic|openai|bedrock|ollama "
    "for standalone-mode LLM enrichment."
)


# ---------------------------------------------------------------------------
# Counter state (process-local, thread-safe)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_counts: dict[str, int] = {}
"""``{feature: count}`` — every report_skip() call increments
``_counts[feature]`` by 1."""

_count_by_reason: dict[str, int] = {}
"""``{reason: count}`` — same shape, keyed by ``reason`` string."""

_last_skips: list[dict[str, Any]] = []
"""Ring buffer of the most recent N skips (newest last). Used by
``/healthz`` so an operator opening the endpoint sees the last few
skips without scrolling the audit log."""

_MAX_LAST = 20
"""Cap on ``_last_skips`` length. Tuned so a misbehaving site can't
balloon process memory; older entries fall off."""


def report_skip(
    *,
    feature: str,
    reason: str = REASON_NO_LLM_BACKEND,
    mode_hint: str = DEFAULT_MODE_HINT,
    extra: dict[str, Any] | None = None,
) -> None:
    """Record that ``feature`` ran deterministic-only because no LLM was
    available.

    Emits a ``logging.WARNING`` (NOT debug — operators must be able to
    grep their logs for these), increments the session counter, and
    appends to the ring buffer.

    Stable structured fields the warning carries (consumed by audit
    shipping + downstream log queries):

      * ``llm_skip_feature`` — the feature name
      * ``llm_skip_reason`` — the reason enum value
      * ``llm_skip_mode_hint`` — operator-language remediation hint

    Example output (formatted message):

      WARNING iam_jit.llm.skip: feature=structured_deny.classify:
      ran deterministic-only (no_llm_backend). This is correct for
      local-dev/agent-in-loop mode. Set --enable-side-llm +
      IAM_JIT_LLM=anthropic|openai|bedrock|ollama for standalone-mode
      LLM enrichment.

    Args:
      feature: short stable identifier of the call-site
        (``structured_deny.classify`` / ``autopilot.improve_cycle`` /
        ``profile_generator.from_audit`` / etc.). Used as the
        primary counter key.
      reason: one of the ``REASON_*`` constants or a free-form
        string for new sites.
      mode_hint: operator-language remediation pointer; defaults to
        the standard opt-in instructions. Pass a feature-specific
        hint when the standard one would be misleading.
      extra: optional structured fields appended to the log record's
        ``extra`` dict (audit shipping picks them up). Never carries
        credentials / PII per [[mitm-beta-pii-pci-concern]].
    """
    feature = (feature or "unknown").strip() or "unknown"
    reason = (reason or REASON_NO_LLM_BACKEND).strip() or REASON_NO_LLM_BACKEND
    hint = (mode_hint or DEFAULT_MODE_HINT).strip()

    msg = (
        f"feature={feature}: ran deterministic-only ({reason}). "
        f"This is correct for local-dev/agent-in-loop mode. {hint}"
    )

    log_extra: dict[str, Any] = {
        "llm_skip_feature": feature,
        "llm_skip_reason": reason,
        "llm_skip_mode_hint": hint,
    }
    if extra:
        # Shallow-copy so callers can't mutate our extras post-call.
        log_extra.update({k: v for k, v in extra.items() if k.startswith("llm_skip_")})

    # WARNING level: per the brief operators MUST see these. Debug would
    # be invisible to default log configs (the silent-degradation shape
    # we're closing).
    logger.warning(msg, extra=log_extra)

    with _lock:
        _counts[feature] = _counts.get(feature, 0) + 1
        _count_by_reason[reason] = _count_by_reason.get(reason, 0) + 1
        _last_skips.append({
            "at": _dt.datetime.now(_dt.timezone.utc)
                .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "feature": feature,
            "reason": reason,
        })
        if len(_last_skips) > _MAX_LAST:
            # Trim from the front so newest survives.
            del _last_skips[: len(_last_skips) - _MAX_LAST]


def skip_counter_snapshot() -> dict[str, Any]:
    """Return a snapshot of the skip counter state.

    Shape:

      {
        "total": int,                  # sum across all features
        "counts": {feature: int, ...}, # per-feature counter
        "by_reason": {reason: int, ...},
        "last_skips": [{at, feature, reason}, ...],
      }

    Consumed by ``/healthz`` (proxy) + ``iam-jit posture`` + autopilot
    status. Safe to call from any thread; returns a deep-copy snapshot
    (callers can mutate freely without affecting the live state).
    """
    with _lock:
        return {
            "total": sum(_counts.values()),
            "counts": dict(_counts),
            "by_reason": dict(_count_by_reason),
            "last_skips": list(_last_skips),
        }


def reset_skip_counter() -> None:
    """Reset all counters. Test-only — production code must not call
    this (in-process state is the truth; the audit log is the durable
    record)."""
    with _lock:
        _counts.clear()
        _count_by_reason.clear()
        _last_skips.clear()


__all__ = [
    "DEFAULT_MODE_HINT",
    "REASON_BACKEND_UNAVAILABLE",
    "REASON_BUDGET_EXCEEDED",
    "REASON_NO_LLM_BACKEND",
    "REASON_NO_SIDE_LLM_ENABLED",
    "REASON_RESPONSE_INVALID",
    "report_skip",
    "reset_skip_counter",
    "skip_counter_snapshot",
]
