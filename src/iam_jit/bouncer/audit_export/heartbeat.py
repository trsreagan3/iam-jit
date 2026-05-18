"""Heartbeat emitter + gap detector — #264.

Per [[prompt-injection-disable-bouncer-threat]]: the bouncer cannot
PREVENT a prompt-injected agent from killing the proxy (`pkill ibounce`
+ a shell wrapper an agent can run) — that's an honest limitation of
any LOCAL safety-rail process. What the bouncer CAN do is make the
disable DETECTABLE, so a security team that's watching the audit
stream sees the silence + can react.

This module ships two halves of that observability:

1. `HeartbeatEmitter` — opt-in background asyncio task that emits an
   OCSF v1.1.0 class-6003 event every N seconds while the proxy is
   running. The event rides the SAME audit-export channels as
   decision events (JSONL log + HTTPS webhook). When the process
   dies, the heartbeat stops; downstream SIEM consumers see the gap.

2. `heartbeat_gap` rule (lives in `alerts.py`'s BUILTIN_RULES) — when
   the rule engine observes 2+ consecutive missed heartbeats, it
   fires a HIGH-severity anomaly + populates a module-level
   `heartbeat_gap_detected` flag the proxy's /healthz handler reads
   to flip 200 → 503. The rule ALSO writes to stderr directly: the
   audit-export channel itself may be the reason heartbeats stopped
   (broken disk, webhook collector down + queue full + dropping), so
   alerting through the same channel isn't reliable.

Per [[security-team-positioning-safety-not-surveillance]]: heartbeats
are an AVAILABILITY signal, not surveillance. Default is OFF (zero
phone-home preserved); the recommendation is Enterprise + every 30s.
Strings stay neutral — a missing heartbeat does not mean someone "did
something wrong"; it means "the bouncer disappeared during a session
and your monitoring should look."

Per [[scorer-is-ground-truth]]: the heartbeat emitter is purely
mechanical (sleep N seconds, build event, emit). No LLM. No scoring.
No conditional logic about whether to emit.

Per [[deliberate-feature-completion]]: the emitter, the rule, the
status surface, the /healthz wiring + the tests all land in one
commit.

Per [[cross-product-agent-parity]]: kbounce + dbounce siblings emit
the same event shape; differs only in `metadata.product.name` +
`unmapped.iam_jit.ext` per-product extensions.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
from collections.abc import Callable
from typing import Any

from .event import (
    OCSF_SCHEMA_VERSION,
    _now_unix_ms,
    _product_version,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OCSF constants
# ---------------------------------------------------------------------------

# OCSF class 6003 = "API Activity" under category 6 "Application
# Activity". activity_id=99 (Other) is the honest mapping for an
# internal meta-event like "the proxy is still alive" — there's no
# CRUD verb that says "we exist."
_CLASS_UID = 6003
_CLASS_NAME = "API Activity"
_CATEGORY_UID = 6
_CATEGORY_NAME = "Application Activity"
_ACTIVITY_ID = 99
_ACTIVITY_NAME = "heartbeat"
_TYPE_UID = _CLASS_UID * 100 + _ACTIVITY_ID  # 600399

# severity_id=1 Informational. Heartbeats are baseline noise — they
# should NEVER read as "something is wrong" in a SIEM dashboard.
# (The HEARTBEAT_GAP anomaly is what raises severity when the noise
# stops.)
_SEVERITY_ID = 1
_SEVERITY = "Informational"

# status_id=1 Success. The heartbeat itself is a "we successfully
# emitted a check-in" event. The gap event uses Other (matches the
# rest of the alert-engine convention).
_STATUS_ID = 1
_STATUS = "Success"

# Same product identity strings as event.py / alerts.py so a SIEM
# dashboard scoped to product.name=="ibounce" catches heartbeats too.
_PRODUCT_NAME = "ibounce"
_PRODUCT_VENDOR_NAME = "iam-jit"

# unmapped.iam_jit.event_type marker so consumers can filter on a
# single field (matches AUDIT_DROPPED / ADMIN_FALLBACK_GRANT / ... in
# the rest of the audit-export module).
EVENT_TYPE_HEARTBEAT = "HEARTBEAT"


# ---------------------------------------------------------------------------
# Module-level state surfaced to /healthz + the MCP status tool.
#
# Per [[audit-export-failure-visibility]]: when the gap rule fires it
# flips a module-level flag the proxy's /healthz reads to flip status
# from 200 to 503. We keep this OUT of the RuleEngine.status() shape
# because the engine isn't always installed (it's Enterprise-gated)
# whereas /healthz is on every tier — the flag needs to be reachable
# without the engine.
# ---------------------------------------------------------------------------
_state_lock = threading.Lock()
_heartbeat_enabled: bool = False
_heartbeat_interval_seconds: int = 0
_heartbeat_last_emit_unix: float | None = None
_heartbeat_gap_detected: bool = False


def reset_for_tests() -> None:
    """Clear module-level state. Tests call this in setup/teardown so
    one test's gap-detected flag doesn't leak into the next."""
    global _heartbeat_enabled, _heartbeat_interval_seconds
    global _heartbeat_last_emit_unix, _heartbeat_gap_detected
    with _state_lock:
        _heartbeat_enabled = False
        _heartbeat_interval_seconds = 0
        _heartbeat_last_emit_unix = None
        _heartbeat_gap_detected = False


def _set_enabled(enabled: bool, interval_seconds: int) -> None:
    """Internal: HeartbeatEmitter calls this on start/stop so the
    status surface reflects whether a heartbeat task is currently
    expected to be ticking."""
    global _heartbeat_enabled, _heartbeat_interval_seconds
    with _state_lock:
        _heartbeat_enabled = bool(enabled)
        _heartbeat_interval_seconds = int(interval_seconds) if enabled else 0
        if not enabled:
            # On stop, clear the gap flag — the next start() begins
            # with a clean slate. A genuine post-stop gap is "the
            # operator stopped the proxy" which is not an anomaly.
            global _heartbeat_gap_detected, _heartbeat_last_emit_unix
            _heartbeat_gap_detected = False
            _heartbeat_last_emit_unix = None


def _record_emit(now_unix: float) -> None:
    """Internal: called by HeartbeatEmitter on every successful emit.
    Also clears any previously-set gap flag because a fresh heartbeat
    is the canonical signal that the gap closed."""
    global _heartbeat_last_emit_unix, _heartbeat_gap_detected
    with _state_lock:
        _heartbeat_last_emit_unix = now_unix
        _heartbeat_gap_detected = False


def mark_gap_detected() -> None:
    """Called by the heartbeat_gap rule when it fires. Sets the
    module-level flag /healthz reads to return 503. Public because
    alerts.py imports it explicitly from this module."""
    global _heartbeat_gap_detected
    with _state_lock:
        _heartbeat_gap_detected = True


def heartbeat_status() -> dict[str, Any]:
    """Snapshot for the MCP `bouncer_audit_export_status` tool +
    the /healthz handler. Safe to call from any thread.

    Returns a stable shape regardless of whether the emitter is
    installed so consumers branch on `heartbeat_enabled` rather than
    KeyError-ing on missing fields.

    `heartbeat_last_emit_seconds_ago` is computed from wall-clock at
    call time — when no heartbeat has been emitted yet this is None
    rather than a misleading "ages ago" value.
    """
    with _state_lock:
        enabled = _heartbeat_enabled
        interval = _heartbeat_interval_seconds
        last = _heartbeat_last_emit_unix
        gap = _heartbeat_gap_detected
    if last is None:
        seconds_ago: int | None = None
    else:
        # Clamp to int seconds. A clock-jump backwards leaves this
        # negative; clamp at 0 so monitors don't see absurd values.
        delta = max(0, int(time.time() - last))
        seconds_ago = delta
    return {
        "heartbeat_enabled": enabled,
        "heartbeat_interval_seconds": interval,
        "heartbeat_last_emit_seconds_ago": seconds_ago,
        "heartbeat_gap_detected": gap,
    }


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------


def make_heartbeat_event(
    *,
    uptime_seconds: int,
    interval_seconds: int,
) -> dict[str, Any]:
    """Build one OCSF v1.1.0 class-6003 heartbeat event.

    The shape matches the spec exactly so a SIEM that's already
    indexing audit-export decision events can dashboard heartbeats
    with no schema changes.

    Why activity_id=99 (Other) + status_id=1 (Success)? "We are still
    alive" is not a CRUD verb (so Other is honest) but it IS a
    successful emission of a check-in event (so Success is correct).
    Same convention as the AUDIT_DROPPED synthetic + the rule engine's
    anomaly_detected events.
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
        "status_detail": "bouncer alive",
        "actor": {"user": {"name": "", "uid": ""}},
        "api": {
            "operation": "heartbeat",
            "service": {"name": "ibounce.audit_export.heartbeat"},
            "request": {"uid": ""},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {},
        "unmapped": {
            "iam_jit": {
                "event_type": EVENT_TYPE_HEARTBEAT,
                "uptime_seconds": int(uptime_seconds),
                "interval_seconds": int(interval_seconds),
            },
        },
    }


# ---------------------------------------------------------------------------
# Async emitter
# ---------------------------------------------------------------------------


class HeartbeatEmitter:
    """Background asyncio task that emits a heartbeat every N seconds.

    Lifecycle::

        emitter = HeartbeatEmitter(interval_seconds=30, emit=_emit_audit_event_raw)
        await emitter.start()
        # ... proxy runs ...
        await emitter.stop()

    The `emit` callback receives a heartbeat event dict and is
    expected to push it through the audit-export transport (the same
    `_emit_audit_event_raw` the decision path uses). The emitter does
    NOT call into the rule engine directly — heartbeats ride the
    shared transport like every other event so the engine observes
    them via its normal path.

    Per [[deliberate-feature-completion]]: the emitter NEVER blocks
    the proxy hot-path. It's its own task, it sleeps with
    `asyncio.sleep`, and its `emit` enqueues (the transport channels
    are bounded queues per Slice 1).

    Fail-soft: any exception in the emit callback is logged +
    swallowed. The next tick still fires. A broken audit-export
    channel does NOT take down the proxy.
    """

    def __init__(
        self,
        *,
        interval_seconds: int,
        emit: Callable[[dict], None],
        # Test hooks.
        _sleep: Callable[[float], Any] | None = None,
        _now: Callable[[], float] | None = None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError(
                f"HeartbeatEmitter interval_seconds must be > 0, "
                f"got {interval_seconds}"
            )
        self.interval_seconds = int(interval_seconds)
        self._emit = emit
        self._sleep = _sleep or asyncio.sleep
        self._now = _now or time.time
        self._task: asyncio.Task | None = None
        self._stop_event: asyncio.Event | None = None
        self._started_at: float | None = None

    async def start(self) -> None:
        """Spawn the heartbeat task. Idempotent: a second start() is a
        no-op so test-suite double-installs don't get two tasks."""
        if self._task is not None:
            return
        self._started_at = self._now()
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(
            self._loop(), name="ibounce-heartbeat-emitter",
        )
        _set_enabled(True, self.interval_seconds)
        logger.info(
            "audit-export heartbeat enabled: interval=%ss",
            self.interval_seconds,
        )

    async def stop(self) -> None:
        """Signal the loop + await the task. Idempotent."""
        if self._task is None:
            return
        if self._stop_event is not None:
            self._stop_event.set()
        # Cancel as a fallback so we don't hang on shutdown if the
        # task is wedged in a long sleep.
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("heartbeat emitter exited with %s", e)
        self._task = None
        self._stop_event = None
        _set_enabled(False, 0)

    async def _loop(self) -> None:
        """Emit-then-sleep loop. Emits IMMEDIATELY on start (so a
        consumer doesn't have to wait one full interval before seeing
        the first heartbeat — useful for fast tests + for proving the
        emitter is wired up at process start). Subsequent emits happen
        every interval_seconds."""
        assert self._stop_event is not None
        assert self._started_at is not None
        try:
            while True:
                try:
                    self._emit_one()
                except Exception as e:
                    # Per [[deliberate-feature-completion]]: a buggy
                    # transport must not kill the emitter loop.
                    logger.warning("heartbeat emit failed: %s", e)
                # Sleep with cancellation responsiveness: wait on the
                # stop event with a timeout = interval. If the stop
                # event fires, exit cleanly; otherwise the timeout
                # elapses and we loop back to emit.
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=self.interval_seconds,
                    )
                    # Stop signalled — exit loop.
                    return
                except asyncio.TimeoutError:
                    # Normal interval elapsed; loop back to emit.
                    continue
        except asyncio.CancelledError:
            # Task cancelled from outside (e.g. process shutdown).
            # Don't re-raise into the loop's worker — `stop()` awaits
            # us and catches CancelledError explicitly.
            return

    def _emit_one(self) -> None:
        """Build + emit a single heartbeat. Called on every tick."""
        now = self._now()
        assert self._started_at is not None
        uptime = max(0, int(now - self._started_at))
        event = make_heartbeat_event(
            uptime_seconds=uptime,
            interval_seconds=self.interval_seconds,
        )
        # Record BEFORE emit so a transport failure doesn't make the
        # "last emit" timestamp lie — we DID build + attempt to emit a
        # heartbeat at this tick.
        _record_emit(now)
        self._emit(event)


# ---------------------------------------------------------------------------
# heartbeat_gap rule (lives in alerts.BUILTIN_RULES via import there)
# ---------------------------------------------------------------------------

# Default: alert after 2 consecutive missed heartbeats. Operators
# raise this for noisy networks where the occasional missed beat is
# normal (e.g. webhook collector occasionally returning 500 + the
# pusher's bounded queue drops a beat). 2 is the spec default.
DEFAULT_HEARTBEAT_MISSING_COUNT = 2


def heartbeat_gap_stderr_message(
    *,
    missing_count: int,
    last_emit_seconds_ago: int | None,
    interval_seconds: int,
) -> str:
    """The neutral-language stderr message the heartbeat_gap rule
    writes when it fires. Exported so the alert pattern + tests can
    import the canonical string.

    Per [[security-team-positioning-safety-not-surveillance]]: no
    forbidden words. Frames the gap as "look at this" not "someone
    did something."
    """
    last_str = (
        f"{last_emit_seconds_ago}s ago"
        if last_emit_seconds_ago is not None
        else "never"
    )
    return (
        f"ibounce heartbeat gap detected: "
        f"{missing_count} consecutive heartbeats missing "
        f"(interval={interval_seconds}s, last emit {last_str}). "
        f"bouncer may have been killed; investigate process status "
        f"+ recent admin-action events."
    )


def write_heartbeat_gap_stderr(
    *,
    missing_count: int,
    last_emit_seconds_ago: int | None,
    interval_seconds: int,
) -> None:
    """Write the gap-detected message to stderr. The heartbeat_gap
    rule calls this in ADDITION to its normal alert-channel emit
    because the audit-export channel itself may be why heartbeats
    stopped (broken webhook collector + full queue = dropped events,
    including the gap alert we just produced).

    Per [[audit-export-failure-visibility]]: stderr is the always-
    available channel a supervisord / systemd / docker logs setup
    will capture even when the structured audit channel is broken.
    """
    msg = heartbeat_gap_stderr_message(
        missing_count=missing_count,
        last_emit_seconds_ago=last_emit_seconds_ago,
        interval_seconds=interval_seconds,
    )
    try:
        # Direct stderr write so the message lands even if the
        # logging module's handlers have been mis-configured.
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except Exception:
        # Last resort — never raise out of a fail-soft alert path.
        pass
