"""#725 — the cost circuit breaker itself.

Per-session sliding-window accumulator over two dimensions:

  * gated-call COUNT (exact)
  * estimated USD COST (coarse — see :mod:`.cost_estimator`)

When a session's count OR cost reaches its configured cap inside the
window, the breaker TRIPS for that session: subsequent gated calls are
DENIED (block mode) or alerted-but-allowed (alert mode), an OCSF
``COST_CIRCUIT_TRIPPED`` event fires once, and the trip auto-resets
after ``cool_down`` of inactivity (or on an explicit reset).

Cap semantics: the breaker trips at ``calls >= max_calls_per_window``
(likewise ``est_usd >= max_usd_per_window``). I.e. the cap-th gated
call is the one that TRIPS — it is allowed, and the breaker is then
OPEN so the *next* gated call is the first that gets denied (block
mode). Not "(N+1)th": the operator's mental model should be "the
max_calls_per_window-th call trips the breaker."

Memory is bounded: the per-session window map is an LRU capped at
``_MAX_TRACKED_SESSIONS`` distinct keys (oldest-touched evicted), and
empty windows whose ``last_activity`` is older than
``window + cool_down`` are garbage-collected on every ``observe`` /
``status``. A client rotating an unbounded number of distinct session
keys can therefore never grow this map without bound.

Structure deliberately mirrors :mod:`iam_jit.bouncer.burst` (sliding
window + OCSF emit + process-singleton register/observe + /healthz
status) so operators + maintainers reason about one shape across both
detectors. It is wholly independent of the LLM-budget modules.

Per ``[[ambient-value-prop-and-friction-framing]]`` +
``[[security-team-positioning-safety-not-surveillance]]`` every
user-facing string is neutral: the trip is framed as "this session's
activity rate looks like a runaway; further calls are paused" — a
SAFETY action — NOT "violation"/"unauthorized" (those words are in
``audit_export.alerts.FORBIDDEN_ALERT_WORDS`` and the test asserts the
event stays clean). Severity is High (4): a tripped cost breaker is a
genuine "stop the bleeding" security signal, distinct from the burst
detector's Low "you probably need a broader scope" nudge.
"""

from __future__ import annotations

import collections
import dataclasses
import threading
import time
from collections.abc import Callable
from typing import Any

from ..bouncer.audit_export.event import (
    OCSF_SCHEMA_VERSION,
    _now_unix_ms,
    _product_version,
)
from .config import CircuitBreakerConfig
from .cost_estimator import estimate_call_cost_usd


# ---------------------------------------------------------------------------
# OCSF event builder — COST_CIRCUIT_TRIPPED synthetic
# ---------------------------------------------------------------------------

_CLASS_UID = 6003
_CLASS_NAME = "API Activity"
_CATEGORY_UID = 6
_CATEGORY_NAME = "Application Activity"

# activity_id=99 (Other) — there's no CRUD verb for "the breaker
# tripped." Same honest-Other mapping the burst + anomaly synthetics
# use.
_ACTIVITY_ID = 99
_ACTIVITY_NAME = "cost_circuit_tripped"
_TYPE_UID = _CLASS_UID * 100 + _ACTIVITY_ID  # 600399

# severity_id=4 (High). A tripped cost breaker is a real-time security
# signal — a session burning resources at runaway rate. Higher than
# the burst detector's Low because this is "stop the bleeding," not
# "consider a broader scope."
_SEVERITY_ID = 4
_SEVERITY = "High"

_STATUS_ID = 99
_STATUS = "Other"

_PRODUCT_NAME = "ibounce"
_PRODUCT_VENDOR_NAME = "iam-jit"

EVENT_TYPE_COST_CIRCUIT_TRIPPED = "COST_CIRCUIT_TRIPPED"

# Hard cap on the number of distinct per-session windows retained at
# once. An LRU bound (oldest-touched evicted) so a client rotating
# session keys — e.g. a rotating User-Agent — can NEVER exhaust memory.
# 10k windows * a small deque each is a few MB worst case; far above
# the count of real concurrent sessions any single proxy sees.
_MAX_TRACKED_SESSIONS = 10_000


def make_cost_circuit_tripped_event(
    *,
    session_id: str,
    dimension: str,             # "calls" | "cost"
    mode: str,                  # "block" | "alert"
    calls_in_window: int,
    estimated_usd_in_window: float,
    max_calls_per_window: int | None,
    max_usd_per_window: float | None,
    window_seconds: int,
    agent_name: str | None = None,
) -> dict[str, Any]:
    """Build the OCSF v1.1.0 class-6003 COST_CIRCUIT_TRIPPED synthetic.

    ``status_detail`` is neutral + leads with the SAFETY frame. The
    dollar figure is explicitly labelled an ESTIMATE per
    ``[[ibounce-honest-positioning]]``.
    """
    if dimension == "cost":
        crossed = (
            f"estimated ~${estimated_usd_in_window:.4f} (estimate) crossed "
            f"the ${max_usd_per_window} cap"
        )
    else:
        crossed = (
            f"{calls_in_window} gated calls crossed the "
            f"{max_calls_per_window}-call cap"
        )
    detail = (
        f"Cost circuit breaker tripped for session "
        f"{session_id or '(unattributed)'}: {crossed} within "
        f"{window_seconds}s. Further gated calls for this session are "
        f"{'paused' if mode == 'block' else 'flagged (alert mode; still allowed)'} "
        f"until the rate settles."
    )
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
        "status_detail": detail,
        "actor": {"user": {"name": agent_name or "", "uid": session_id or ""}},
        "api": {
            "operation": "cost_circuit_tripped",
            "service": {"name": "ibounce.circuit_breaker"},
            "request": {"uid": session_id or ""},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {},
        "unmapped": {
            "iam_jit": {
                "event_type": EVENT_TYPE_COST_CIRCUIT_TRIPPED,
                "ext": {
                    "session_id": session_id or "",
                    "trip_dimension": dimension,
                    "mode": mode,
                    "calls_in_window": int(calls_in_window),
                    # Labelled estimated_* so a SIEM dashboard never
                    # mistakes this for a billed figure.
                    "estimated_usd_in_window": round(
                        float(estimated_usd_in_window), 6
                    ),
                    "estimated_usd_is_estimate": True,
                    "max_calls_per_window": max_calls_per_window,
                    "max_usd_per_window": max_usd_per_window,
                    "window_seconds": int(window_seconds),
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# Per-session trip state
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class TripState:
    """Result of one :meth:`CostCircuitBreaker.observe` call.

    ``tripped`` is True iff the breaker is currently OPEN for this
    session (either it crossed on this very call, or it crossed
    earlier in the window and hasn't reset). ``should_deny`` is True
    only when ``tripped`` AND the breaker is in block mode — the
    proxy tightens ALLOW→DENY on that. ``fired`` is True only on the
    single call that CROSSED the threshold (so the proxy emits the
    OCSF event + friendly message exactly once).
    """

    tripped: bool
    should_deny: bool
    fired: bool
    dimension: str | None  # "calls" | "cost" | None
    calls_in_window: int
    estimated_usd_in_window: float
    operator_message: str
    event: dict[str, Any] | None


class _SessionWindow:
    """Sliding window of (timestamp, cost) for one session."""

    __slots__ = ("entries", "tripped_at", "last_activity")

    def __init__(self) -> None:
        # deque of (ts, est_cost_usd). Count = len(entries).
        self.entries: collections.deque[tuple[float, float]] = collections.deque()
        self.tripped_at: float | None = None
        self.last_activity: float = 0.0


class CostCircuitBreaker:
    """Per-session sliding-window cost/call circuit breaker.

    Thread-safe. The proxy hot path calls :meth:`observe` from the
    asyncio loop; the CLI / MCP read :meth:`status` from sync code.
    Fail-soft on ``emit`` — a broken audit transport never takes down
    the breaker or the proxy.
    """

    def __init__(
        self,
        config: CircuitBreakerConfig,
        *,
        emit: Callable[[dict], None] | None = None,
    ) -> None:
        self.config = config
        self._emit = emit
        self._lock = threading.Lock()
        # OrderedDict so we can evict the least-recently-touched window
        # when the map hits _MAX_TRACKED_SESSIONS — a hard LRU bound on
        # memory regardless of how many distinct session keys arrive.
        self._sessions: collections.OrderedDict[str, _SessionWindow] = (
            collections.OrderedDict()
        )
        # How many distinct sessions have tripped since process start
        # (surfaced on /healthz so monitors can alert on it).
        self._trips_total = 0

    # -- core --------------------------------------------------------

    def observe(
        self,
        *,
        session_id: str | None,
        service: str | None,
        action: str | None,
        now: float | None = None,
    ) -> TripState:
        """Record one gated call for ``session_id`` and return the
        current :class:`TripState`.

        Disabled config → always a no-op pass-through (tripped=False).
        """
        if not self.config.enabled:
            return TripState(
                tripped=False, should_deny=False, fired=False,
                dimension=None, calls_in_window=0,
                estimated_usd_in_window=0.0, operator_message="", event=None,
            )

        now = now if now is not None else time.time()
        sid = session_id or "__unattributed__"
        cost = estimate_call_cost_usd(service, action)

        fired = False
        dimension: str | None = None
        with self._lock:
            # GC empty/stale windows first so a flood of one-shot keys
            # doesn't accumulate; keeps the map small under churn.
            self._gc_stale_locked(now=now)

            win = self._sessions.get(sid)
            if win is None:
                win = _SessionWindow()
                self._sessions[sid] = win
            else:
                # Touch LRU recency so a still-active session isn't the
                # one we evict under pressure.
                self._sessions.move_to_end(sid)

            # Enforce the LRU bound. Never evict the window we just
            # touched (it's at the end); pop from the front (oldest).
            while len(self._sessions) > _MAX_TRACKED_SESSIONS:
                self._sessions.popitem(last=False)

            # Auto-reset a tripped session after cool_down of inactivity.
            if (
                win.tripped_at is not None
                and (now - win.last_activity) >= self.config.cool_down_seconds
            ):
                win.entries.clear()
                win.tripped_at = None

            win.last_activity = now
            win.entries.append((now, cost))
            self._evict_locked(win, now=now)

            calls = len(win.entries)
            est_usd = sum(c for _, c in win.entries)

            already_tripped = win.tripped_at is not None
            if not already_tripped:
                cap_calls = self.config.max_calls_per_window
                cap_usd = self.config.max_usd_per_window
                if cap_calls is not None and calls >= cap_calls:
                    dimension = "calls"
                elif cap_usd is not None and est_usd >= cap_usd:
                    dimension = "cost"
                if dimension is not None:
                    win.tripped_at = now
                    fired = True
                    self._trips_total += 1

            tripped = win.tripped_at is not None
            # Build the event inside the lock for a consistent snapshot.
            event: dict[str, Any] | None = None
            if fired:
                event = make_cost_circuit_tripped_event(
                    session_id=session_id or "",
                    dimension=dimension or "calls",
                    mode=self.config.mode,
                    calls_in_window=calls,
                    estimated_usd_in_window=est_usd,
                    max_calls_per_window=self.config.max_calls_per_window,
                    max_usd_per_window=self.config.max_usd_per_window,
                    window_seconds=self.config.window_seconds,
                )

        # Emit OUTSIDE the lock; fail-soft.
        if fired and event is not None and self._emit is not None:
            try:
                self._emit(event)
            except Exception:
                pass

        should_deny = tripped and self.config.mode == "block"
        msg = ""
        if tripped:
            msg = self._friendly_message(
                session_id=session_id, dimension=dimension,
                calls=calls, est_usd=est_usd,
            )
        return TripState(
            tripped=tripped,
            should_deny=should_deny,
            fired=fired,
            dimension=dimension,
            calls_in_window=calls,
            estimated_usd_in_window=round(est_usd, 6),
            operator_message=msg,
            event=event,
        )

    def reset(self, session_id: str | None = None) -> None:
        """Manually reset a tripped session (or ALL sessions when
        ``session_id`` is None). Used by an operator who has handled
        the runaway + wants to re-arm without waiting for cool-down."""
        with self._lock:
            if session_id is None:
                self._sessions.clear()
                return
            self._sessions.pop(session_id or "__unattributed__", None)

    # -- introspection ----------------------------------------------

    def status(self) -> dict[str, Any]:
        """/healthz snapshot. Always present so monitors can branch on
        a single field. Honest per ``[[ibounce-honest-positioning]]``:
        reports ``enabled: false`` rather than omitting when disabled."""
        if not self.config.enabled:
            return {"enabled": False}
        now = time.time()
        with self._lock:
            # Drop empty/stale windows so /healthz also bounds the map.
            self._gc_stale_locked(now=now)
            tripped_sessions = []
            active_sessions = 0
            for sid, win in self._sessions.items():
                self._evict_locked(win, now=now)
                if win.entries:
                    active_sessions += 1
                if win.tripped_at is not None:
                    tripped_sessions.append(sid)
            return {
                "enabled": True,
                "mode": self.config.mode,
                "window_seconds": self.config.window_seconds,
                "cool_down_seconds": self.config.cool_down_seconds,
                "max_calls_per_window": self.config.max_calls_per_window,
                # Labelled as estimate-driven so operators know the
                # USD dimension is coarse.
                "max_usd_per_window": self.config.max_usd_per_window,
                "usd_is_estimated": True,
                "active_sessions": active_sessions,
                "tripped_sessions": sorted(tripped_sessions),
                "tripped_sessions_count": len(tripped_sessions),
                "trips_total": self._trips_total,
            }

    # -- internals --------------------------------------------------

    def _evict_locked(self, win: _SessionWindow, *, now: float) -> None:
        cutoff = now - self.config.window_seconds
        while win.entries and win.entries[0][0] < cutoff:
            win.entries.popleft()

    def _gc_stale_locked(self, *, now: float) -> None:
        """Remove whole windows that carry no live state and haven't
        seen activity within ``window + cool_down``. Such a window can
        no longer trip (its entries are all evicted) and is not in a
        cool-down hold, so retaining it only wastes memory. Caller holds
        ``self._lock``.

        This is what makes memory bounded under key churn: a client that
        rotates session keys leaves behind windows that go empty after
        ``window`` seconds and are reaped here on the next observe/status.
        """
        stale_after = self.config.window_seconds + self.config.cool_down_seconds
        cutoff = now - stale_after
        to_drop: list[str] = []
        for sid, win in self._sessions.items():
            # Prune expired entries so an idle-but-not-yet-GC'd window
            # reports its true (likely empty) state.
            self._evict_locked(win, now=now)
            if not win.entries and win.tripped_at is None and win.last_activity < cutoff:
                to_drop.append(sid)
        for sid in to_drop:
            self._sessions.pop(sid, None)

    def _friendly_message(
        self,
        *,
        session_id: str | None,
        dimension: str | None,
        calls: int,
        est_usd: float,
    ) -> str:
        verb = "paused" if self.config.mode == "block" else "flagged"
        if dimension == "cost":
            what = (
                f"estimated ~${est_usd:.4f} (estimate) of upstream cost in "
                f"the last {self.config.window_seconds}s"
            )
        else:
            what = f"{calls} gated calls in the last {self.config.window_seconds}s"
        return (
            f"This session's activity looks like a runaway: {what}. "
            f"Further calls are {verb} until the rate settles "
            f"(auto-resets after {self.config.cool_down_seconds}s idle)."
        )


# ---------------------------------------------------------------------------
# Process-wide singleton — installed by serve() so the proxy hot path +
# the CLI + the MCP read tool all observe the same windows. None when no
# breaker is installed (unit tests that drive observe() directly, or the
# default disabled posture).
# ---------------------------------------------------------------------------

_active_breaker: CostCircuitBreaker | None = None
_active_breaker_lock = threading.Lock()


def register_cost_circuit_breaker(breaker: CostCircuitBreaker | None) -> None:
    """Install (or clear) the process-wide breaker. serve() calls this
    at startup with a configured breaker (or None when disabled)."""
    global _active_breaker
    with _active_breaker_lock:
        _active_breaker = breaker


def active_cost_circuit_breaker() -> CostCircuitBreaker | None:
    """Return the currently-installed breaker, or None."""
    with _active_breaker_lock:
        return _active_breaker


def reset_for_tests() -> None:
    """Clear the module-level singleton between tests."""
    global _active_breaker
    with _active_breaker_lock:
        _active_breaker = None


__all__ = [
    "CostCircuitBreaker",
    "EVENT_TYPE_COST_CIRCUIT_TRIPPED",
    "TripState",
    "active_cost_circuit_breaker",
    "make_cost_circuit_tripped_event",
    "register_cost_circuit_breaker",
    "reset_for_tests",
]
