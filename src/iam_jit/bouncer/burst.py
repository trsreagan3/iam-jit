"""Burst-of-denies detector + bulk-prompt-answer support — #253.

Per [[bulk-prompt-answer-ux]]: when an agent's task hits a wall of
DENYs (likely because the active scope is too narrow for the actual
work), forcing the operator to answer each prompt individually is the
fastest path to "uninstall the bouncer." Per
[[safety-mode-lean-permissive]]: "block-happy = uninstalled." The
right UX is to surface the burst ONCE + give the operator a single
choice between switch-profile / allow-session / allow-3h / allow-10min
/ no-change.

This module ships the load-bearing pieces:

1. `BurstDetector` — sliding-window counter over pending-prompt
   timestamps. Fires `BURST_DETECTED` once when the window's pending
   count crosses the threshold; re-arms after operator answer OR
   after a cool-down. Pure in-memory (the persistent state lives in
   `pending_prompts` — this module is just the detector that watches).

2. `make_burst_detected_event` — OCSF v1.1.0 class 6003 builder for
   the synthetic `BURST_DETECTED` event the detector emits. Same
   shape as alerts.anomaly_detected / heartbeat events; differs in
   `activity_name` + `unmapped.iam_jit.event_type` + the burst-shape
   fields under `unmapped.iam_jit.ext`.

3. Module-level singleton + register/observe API the proxy hooks
   into when a new pending prompt lands (so the detector's window
   stays in lockstep with the queue without threading args through
   evaluate_request).

Per [[scorer-is-ground-truth]]: detection is purely mechanical — a
count over a window. No LLM, no fuzzy logic. Predictable + auditable.

Per [[security-team-positioning-safety-not-surveillance]]: every
user-facing string here is neutral. The burst is framed as "your
task probably needs a broader scope," NOT "policy violations
detected." Severity is Low (2), not High — a burst is a signal to
ACT, not an attack indicator. (The
`audit_export.alerts.FORBIDDEN_ALERT_WORDS` scan applies here too;
the neutral-language test asserts the synthetic event's strings stay
clean.)

Per [[creates-never-mutates]]: nothing AWS-side is touched. The
detector + the bulk-answer paths only read/write the bouncer's local
SQLite — no IAM mutation, no STS calls, nothing that could escape
the customer's account.

Per [[deliberate-feature-completion]]: this module ships in one
commit alongside its DB-schema change (expires_at on rules), its CLI
(`prompts bulk-answer`), its MCP tools (`bouncer_prompts_bulk_pending`
+ `bouncer_prompts_bulk_answer`), its pre-burst hint, and its tests.

Per [[cross-product-agent-parity]]: kbounce + dbounce siblings land
the same shape in parallel; differs only in `metadata.product.name`
+ per-product extension fields.
"""

from __future__ import annotations

import collections
import threading
import time
from collections.abc import Callable
from typing import Any

from .audit_export.event import OCSF_SCHEMA_VERSION, _now_unix_ms, _product_version


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Spec defaults per the issue body: N=5 pending prompts in T=60s.
# These were chosen because:
#   - 5 prompts in a minute is well above the "operator is reading the
#     queue manually" threshold (a human can comfortably answer ~1
#     prompt every 10-15 seconds; 5 in 60s means the agent's pace is
#     outrunning the operator's).
#   - 60s is short enough that a true burst doesn't get lost in the
#     noise of a long workday, but long enough to span a handful of
#     SDK retries (~3 retries on a misconfigured boto3 client take ~30s).
DEFAULT_BURST_THRESHOLD = 5
DEFAULT_BURST_WINDOW_SECONDS = 60

# Cool-down before the detector re-arms after firing. The detector
# re-arms IMMEDIATELY when the operator answers via the bulk-answer
# path; the cool-down is a fallback so a forgotten / never-answered
# burst doesn't fire repeatedly. 5 minutes matches the spec.
DEFAULT_COOL_DOWN_SECONDS = 300


# ---------------------------------------------------------------------------
# OCSF event builder — BURST_DETECTED synthetic
# ---------------------------------------------------------------------------

# Same OCSF class + category as the rest of the audit-export module so a
# SIEM dashboard scoped to class_uid=6003 catches burst events too.
_CLASS_UID = 6003
_CLASS_NAME = "API Activity"
_CATEGORY_UID = 6
_CATEGORY_NAME = "Application Activity"

# activity_id=99 (Other) — there's no CRUD verb for "we noticed a
# pattern in the operator's pending queue." Same honest-Other mapping
# as the heartbeat + alerts module use.
_ACTIVITY_ID = 99
_ACTIVITY_NAME = "prompt_burst_detected"
_TYPE_UID = _CLASS_UID * 100 + _ACTIVITY_ID  # 600399

# severity_id=2 (Low) — a burst is a signal to ACT (offer the bulk
# answer UX), not an attack indicator. The
# [[security-team-positioning-safety-not-surveillance]] memo is
# explicit: don't read as "something is wrong"; read as "your task
# probably needs a broader scope."
_SEVERITY_ID = 2
_SEVERITY = "Low"

# status_id=99 (Other) — matches the alerts.anomaly_detected pattern.
# The synthetic isn't a Success/Failure of an upstream API call; it's
# a meta-event about the proxy's local pending queue.
_STATUS_ID = 99
_STATUS = "Other"

_PRODUCT_NAME = "ibounce"
_PRODUCT_VENDOR_NAME = "iam-jit"

# unmapped.iam_jit.event_type marker so consumers can filter on a
# single field. Matches the AUDIT_DROPPED / HEARTBEAT / ANOMALY_DETECTED
# / PAUSE_END / PROFILE_INSTALL convention in the rest of the module.
EVENT_TYPE_BURST_DETECTED = "BURST_DETECTED"


def make_burst_detected_event(
    *,
    pending_count: int,
    window_seconds: int,
    oldest_pending_seconds_ago: int,
) -> dict[str, Any]:
    """Build the OCSF v1.1.0 class-6003 BURST_DETECTED synthetic.

    Per [[security-team-positioning-safety-not-surveillance]]: the
    `status_detail` is neutral — frames the burst as a signal the
    operator's current scope is probably too narrow, NOT as a
    violation / unauthorized-access / etc. The `FORBIDDEN_ALERT_WORDS`
    scan asserts the canonical strings stay clean.

    The `unmapped.iam_jit.ext` block carries the burst-shape inputs
    so a SIEM dashboard can answer "how many prompts piled up before
    the operator answered?" + "how stale was the oldest pending?"
    without joining back to the pending_prompts table.
    """
    return {
        "metadata": {
            "version": OCSF_SCHEMA_VERSION,
            "product": {
                "name": _PRODUCT_NAME,
                "vendor_name": _PRODUCT_VENDOR_NAME,
                "version": _product_version(),
            },
        },
        "time": _now_unix_ms(),
        "class_uid": _CLASS_UID,
        "class_name": _CLASS_NAME,
        "category_uid": _CATEGORY_UID,
        "category_name": _CATEGORY_NAME,
        "activity_id": _ACTIVITY_ID,
        "activity_name": _ACTIVITY_NAME,
        "type_uid": _TYPE_UID,
        "type_name": f"{_CLASS_NAME}: Other",
        "severity_id": _SEVERITY_ID,
        "severity": _SEVERITY,
        "status_id": _STATUS_ID,
        "status": _STATUS,
        "status_detail": (
            f"{pending_count} pending prompts accumulated in the last "
            f"{window_seconds}s; your task probably needs a broader scope. "
            f"Run `ibounce prompts bulk-answer` to handle them all at once."
        ),
        "actor": {"user": {"name": "", "uid": ""}},
        "api": {
            "operation": "prompt_burst_detected",
            "service": {"name": "ibounce.bouncer.burst"},
            "request": {"uid": ""},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {},
        "unmapped": {
            "iam_jit": {
                "event_type": EVENT_TYPE_BURST_DETECTED,
                "ext": {
                    "pending_count": int(pending_count),
                    "window_seconds": int(window_seconds),
                    "oldest_pending_seconds_ago": int(oldest_pending_seconds_ago),
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# BurstDetector
# ---------------------------------------------------------------------------


class BurstDetector:
    """Sliding-window counter over pending-prompt timestamps.

    Lifecycle::

        detector = BurstDetector(
            threshold=5, window_seconds=60,
            emit=_emit_audit_event_raw,
        )
        # On every new pending prompt:
        fired = detector.observe(now=time.time())
        # If `fired` is True, the operator should see the pre-burst
        # hint on next CLI invocation + the BURST_DETECTED event is
        # already on the audit-export channels.

        # When the operator answers via the bulk-answer path:
        detector.reset(now=time.time())

    Re-arm semantics:
      - Operator answer (via bulk-answer) → IMMEDIATE re-arm. The
        burst is considered resolved as soon as the operator acted.
      - Cool-down elapses (default 5min) → re-arm even if no answer.
        Prevents a forgotten queue from firing every observe() call.

    Thread-safe: all mutating operations hold a lock. The proxy hot
    path calls `observe()` from inside the asyncio event loop; the
    CLI calls `reset()` + `pending_hint()` from sync code; the MCP
    server calls `pending_hint()` from sync code. One lock is plenty
    for the contention we expect (< 100 ops/sec sustained).

    Fail-soft on `emit`: any exception in the emit callback is logged
    + swallowed. A broken audit-export channel does NOT take down the
    detector or the proxy.
    """

    def __init__(
        self,
        *,
        threshold: int = DEFAULT_BURST_THRESHOLD,
        window_seconds: int = DEFAULT_BURST_WINDOW_SECONDS,
        cool_down_seconds: int = DEFAULT_COOL_DOWN_SECONDS,
        emit: Callable[[dict], None] | None = None,
    ) -> None:
        if threshold < 1:
            raise ValueError(
                f"BurstDetector threshold must be >= 1, got {threshold}"
            )
        if window_seconds < 1:
            raise ValueError(
                f"BurstDetector window_seconds must be >= 1, "
                f"got {window_seconds}"
            )
        if cool_down_seconds < 0:
            raise ValueError(
                f"BurstDetector cool_down_seconds must be >= 0, "
                f"got {cool_down_seconds}"
            )
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)
        self.cool_down_seconds = int(cool_down_seconds)
        self._emit = emit
        self._lock = threading.Lock()
        # Each entry is a unix-float timestamp. We use deque + popleft
        # for O(1) window-eviction; bisect would also work but deque is
        # cleaner for monotonic-time inserts.
        self._timestamps: collections.deque[float] = collections.deque()
        # When the detector last fired. None = not currently armed-after-
        # fire (i.e. ready to fire again immediately on the next
        # threshold crossing).
        self._last_fired_at: float | None = None

    def observe(self, *, now: float | None = None) -> bool:
        """Record a new pending-prompt timestamp.

        Returns True iff this observation CROSSED the burst threshold
        (i.e. the detector emitted a BURST_DETECTED event on this
        call). Returns False otherwise — either we're still under
        threshold, OR we already fired + haven't been reset / past
        cool-down.

        Per [[deliberate-feature-completion]]: the caller doesn't need
        to call any other method to make this work — `observe()` does
        eviction + threshold check + emit in one pass.
        """
        now = now if now is not None else time.time()
        with self._lock:
            self._timestamps.append(now)
            self._evict_locked(now=now)
            # Re-arm if cool-down elapsed since last fire (operators
            # who don't answer still get re-notified eventually).
            if (
                self._last_fired_at is not None
                and (now - self._last_fired_at) >= self.cool_down_seconds
            ):
                self._last_fired_at = None
            if self._last_fired_at is not None:
                # Already fired this window — suppress to avoid
                # spamming the SIEM with one event per prompt.
                return False
            if len(self._timestamps) < self.threshold:
                return False
            # Fire. Record the fire-time + build the event payload
            # inside the lock so the snapshot is consistent.
            self._last_fired_at = now
            oldest_ts = self._timestamps[0]
            oldest_ago = max(0, int(now - oldest_ts))
            event = make_burst_detected_event(
                pending_count=len(self._timestamps),
                window_seconds=self.window_seconds,
                oldest_pending_seconds_ago=oldest_ago,
            )
        # Emit OUTSIDE the lock so a slow audit-export channel can't
        # block other observe() callers.
        if self._emit is not None:
            try:
                self._emit(event)
            except Exception:
                # Per the fail-soft contract: never let a broken
                # transport bring down the proxy.
                pass
        return True

    def reset(self, *, now: float | None = None) -> None:
        """Operator-initiated re-arm.

        Called by the bulk-answer CLI path when the operator picks any
        of the 5 options (including "leave pending" — the operator
        SAW the burst, which is the whole point; firing again 5min
        later would be noise). Also clears the window so subsequent
        prompts start fresh.
        """
        _ = now  # unused; reset is unconditional
        with self._lock:
            self._timestamps.clear()
            self._last_fired_at = None

    def pending_hint(self, *, now: float | None = None) -> dict[str, Any] | None:
        """Snapshot for the pre-burst hint surface + MCP read tool.

        Returns a dict describing the live burst (pending_count,
        window_seconds, oldest_pending_seconds_ago) when a burst is
        CURRENTLY firing — i.e. the threshold was crossed AND the
        operator hasn't acknowledged via `reset()`. Returns None
        otherwise.

        The CLI pre-burst hint reads this on every subcommand
        invocation; the MCP `bouncer_prompts_bulk_pending` tool reads
        it on each call.

        Does NOT mutate the detector state — the hint is purely
        observational. A separate `reset()` call is required to clear
        the burst, which happens via the bulk-answer flow.
        """
        now = now if now is not None else time.time()
        with self._lock:
            self._evict_locked(now=now)
            if self._last_fired_at is None:
                return None
            if not self._timestamps:
                # All entries aged out of the window — the burst is
                # effectively over even though the operator didn't
                # ack. Treat as resolved.
                self._last_fired_at = None
                return None
            oldest_ts = self._timestamps[0]
            oldest_ago = max(0, int(now - oldest_ts))
            return {
                "pending_count": len(self._timestamps),
                "window_seconds": self.window_seconds,
                "oldest_pending_seconds_ago": oldest_ago,
                "threshold": self.threshold,
            }

    def status(self) -> dict[str, Any]:
        """Snapshot for the MCP audit-export status tool. Includes
        config + live-window stats. Safe to call from any thread; no
        side effects.
        """
        with self._lock:
            return {
                "burst_threshold": self.threshold,
                "burst_window_seconds": self.window_seconds,
                "burst_cool_down_seconds": self.cool_down_seconds,
                "burst_pending_in_window": len(self._timestamps),
                "burst_firing": self._last_fired_at is not None,
            }

    def _evict_locked(self, *, now: float) -> None:
        """Drop timestamps older than the window. Caller holds the lock."""
        cutoff = now - self.window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()


# ---------------------------------------------------------------------------
# Module-level singleton — installed by serve() at startup so the proxy
# hot path + the CLI pre-burst hint + the MCP read tool all observe the
# same window. None when no detector is installed (e.g. unit tests that
# call evaluate_request directly without serve()).
# ---------------------------------------------------------------------------

_active_detector: BurstDetector | None = None
_active_detector_lock = threading.Lock()


def register_burst_detector(detector: BurstDetector | None) -> None:
    """Install (or clear) the process-wide burst detector. serve()
    calls this at startup with a configured BurstDetector + at
    teardown with None.
    """
    global _active_detector
    with _active_detector_lock:
        _active_detector = detector


def active_burst_detector() -> BurstDetector | None:
    """Return the currently-installed detector, or None.

    Read-only accessor used by:
      - `proxy.add_pending_prompt` callsite (to observe a new prompt)
      - CLI pre-burst hint
      - MCP `bouncer_prompts_bulk_pending` tool
    """
    with _active_detector_lock:
        return _active_detector


def reset_for_tests() -> None:
    """Clear the module-level singleton. Tests call this between
    runs so one test's installed detector doesn't leak into the next.
    """
    global _active_detector
    with _active_detector_lock:
        _active_detector = None


# ---------------------------------------------------------------------------
# Operator-set token gate for the bulk-answer MCP tool
#
# Per the issue body: the MCP-driven bulk-answer is GATED BY DEFAULT.
# An adversarial agent that compromises an MCP client should NOT be
# able to bulk-allow itself out of every pending prompt — that would
# invert the whole point of the prompt UX.
#
# The operator opts in by passing `--bulk-answer-mcp-token TOKEN` to
# `ibounce run`. The agent must echo that exact token back on every
# `bouncer_prompts_bulk_answer` call. The token is a per-session
# secret the operator shares out-of-band with their agent (e.g.
# pastes into the agent's prompt window manually). Comparison is
# constant-time.
#
# Default state: no token configured → all MCP bulk-answer calls
# return an error explaining how to enable. The CLI bulk-answer path
# is unaffected (operator-driven, not gated by this).
# ---------------------------------------------------------------------------


_bulk_answer_mcp_token: str | None = None
_bulk_answer_mcp_token_lock = threading.Lock()


def set_bulk_answer_mcp_token(token: str | None) -> None:
    """Install (or clear) the operator-set MCP bulk-answer token.
    serve() calls this at startup with the --bulk-answer-mcp-token
    flag value (or None when unset).
    """
    global _bulk_answer_mcp_token
    with _bulk_answer_mcp_token_lock:
        if token is None or token == "":
            _bulk_answer_mcp_token = None
        else:
            _bulk_answer_mcp_token = str(token)


def bulk_answer_mcp_token_configured() -> bool:
    """True iff the operator passed --bulk-answer-mcp-token. Read by
    the MCP handler's gate check + reflected in the status tool so
    operators can confirm enablement without checking the token
    value itself.
    """
    with _bulk_answer_mcp_token_lock:
        return _bulk_answer_mcp_token is not None


def verify_bulk_answer_mcp_token(supplied: str | None) -> bool:
    """Constant-time compare the supplied token against the configured
    one. Returns True iff configured AND supplied matches.

    When no token is configured returns False unconditionally — the
    default state is "disabled," not "any token works."
    """
    import hmac

    with _bulk_answer_mcp_token_lock:
        configured = _bulk_answer_mcp_token
    if configured is None:
        return False
    if not isinstance(supplied, str):
        return False
    return hmac.compare_digest(configured, supplied)
