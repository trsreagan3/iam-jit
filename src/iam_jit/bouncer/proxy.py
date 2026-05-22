"""Bouncer Stage 2 — transparent HTTP proxy that intercepts AWS SDK
calls via ``AWS_ENDPOINT_URL=http://127.0.0.1:<port>``.

Slices 1 + 2 of the proxy work (per http-proxy-pre-launch):
  - Slice 1: aiohttp-based HTTP server, SigV4 request parsing,
    per-request audit logging, mode enum + advisory-vs-enforce
    decision shaping
  - Slice 2: SigV4-preserving forwarding to real AWS endpoints,
    streaming responses, connection pooling

Per bouncer-both-modes-first-class: the server supports both
cooperative (advisory) and transparent (enforce) modes as first-
class user choices. Per `bouncer-mode-selection-for-agents`:
  - Cooperative + ALLOW: forward; log
  - Cooperative + DENY:  forward (advisory); log the would-be-deny
  - Transparent + ALLOW: forward; log
  - Transparent + DENY:  return 403 with iam-jit reason; don't forward

SigV4 forwarding rules (LOAD-BEARING):
  - The proxy NEVER re-signs requests. The client already signed
    with their secret key; we don't have (and don't want) access to
    that key. We forward the request verbatim, preserving headers,
    body, and the Authorization header that contains the SigV4
    signature.
  - The client signs against the ORIGINAL AWS Host header (e.g.
    s3.us-east-1.amazonaws.com), even though it connects to the
    proxy at 127.0.0.1:8767. We forward to the host the client
    signed against — the SigV4 signature validates correctly at
    AWS because Host matches.
  - The proxy listens on plain HTTP (no MITM TLS in Slice 2; that's
    Slice 4). The OUTBOUND forward is always HTTPS to real AWS.

What this module does NOT do yet (later slices):
  - MITM TLS for HTTPS-only SDK clients (Slice 4)
  - Connection-pool tuning + advanced streaming (Slice 5)
  - bouncer_active_mode / bouncer_recommend_mode_for_task MCP
    tools (Slices 3 + 6)
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import pathlib
import threading
import time

# HIGH-32-05 mitigation counter: pause-lookup failures are caught
# + logged but the proxy continues to enforce. Without surfacing
# this, an operator who typed `pause start` thinks they have a
# bypass window, but the proxy keeps 403ing because the lookup
# silently fails. Counter is exposed on /healthz so monitors can
# alert on a non-zero value.
_pause_lookup_errors_lock = threading.Lock()
_pause_lookup_errors_total = 0


def _bump_pause_lookup_error_counter() -> None:
    global _pause_lookup_errors_total
    with _pause_lookup_errors_lock:
        _pause_lookup_errors_total += 1


def _pause_lookup_error_count() -> int:
    with _pause_lookup_errors_lock:
        return _pause_lookup_errors_total


def _reset_pause_lookup_error_counter_for_tests() -> None:
    """Reset hook for tests. Not part of the public surface."""
    global _pause_lookup_errors_total
    with _pause_lookup_errors_lock:
        _pause_lookup_errors_total = 0


# #270 Slice 2 — pause-end transition detection. Mirrors the kbounce
# hot-path observation pattern (commit 82a8ef2): each pause lookup
# compares the currently-seen pause-id against the LAST id observed.
# On a transition (last_seen present + current is None OR a different
# id), the previous pause has just closed (either via `ibounce pause
# stop` OR via the lazy auto-expiry in _active_pause_locked). We emit
# a synthetic PAUSE_END event into the rule engine so the pause_long
# alert rule can evaluate `ext.duration_seconds` against its threshold.
#
# Why hot-path detection rather than an explicit emit in `end_pause`?
# Two reasons:
#   1. Auto-expiry has no explicit call site — the lazy GC inside
#      _active_pause_locked is what flips end_kind='expired'. A
#      hot-path detector catches BOTH explicit stop AND auto-expiry
#      with one mechanism.
#   2. The dbounce + kbounce siblings landed this shape (the
#      observation pattern from the spec) so cross-product behavior
#      stays parallel — same audit events on the same triggers.
_last_seen_pause_id_lock = threading.Lock()
_last_seen_pause: dict[str, Any] | None = None


def _reset_last_seen_pause_for_tests() -> None:
    """Reset hook for tests. Not part of the public surface."""
    global _last_seen_pause
    with _last_seen_pause_id_lock:
        _last_seen_pause = None


# ---------------------------------------------------------------------------
# #203 — synchronous deny-prompt wakeup registry.
#
# When --sync-prompt-on-deny is set + a transparent-mode DENY fires, the
# proxy: (1) enqueues a pending_prompts row with a fresh sync_wait_id
# UUID, (2) registers an asyncio.Event in this in-process dict keyed by
# that UUID, (3) awaits `event.wait()` with `asyncio.wait_for(...,
# timeout=sync_prompt_timeout_seconds)`. The CLI `prompts answer` path
# (or any other answer surface) calls `wake_sync_pending_prompt(...)`
# which sets the Event + records the decision so the proxy coroutine
# can resume.
#
# Why an in-process registry (vs polling the DB)?
# - Polling adds latency (operator answers at t=2s, proxy returns at
#   t=2s + poll-interval). Events are O(microseconds).
# - SQLite has no NOTIFY/LISTEN. We'd reimplement it badly.
# - The proxy is single-process by design (per [[local-only-safety-
#   mode]]); inter-process coordination isn't needed.
#
# Crash safety: if the proxy crashes mid-wait, the pending_prompts row
# stays in the DB with sync_wait_id set, but no Event exists for the
# next process. The MCP tool `bouncer_pending_sync_prompts` filters to
# the in-process registered set so stale rows don't appear "waiting"
# forever. Operator can mark them ignored via the normal answer path.
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _SyncWaitSlot:
    """One waiting request blocked behind a sync deny-prompt.

    `event` is signaled when the answer arrives (or never, in which
    case asyncio.wait_for raises TimeoutError + the proxy falls
    through to `sync_prompt_default_decision`).

    `decision` is set to 'allow' or 'deny' by the wake path BEFORE
    `event.set()`; the awakened proxy coroutine reads it after the
    wait returns. None means "no answer recorded" (the timeout path
    leaves this None + the proxy applies the default).
    """
    event: Any  # asyncio.Event; typed `Any` to avoid asyncio import at module load
    decision: str | None = None
    answered_by: str | None = None
    answer_kind: str | None = None


_sync_wait_registry: dict[str, _SyncWaitSlot] = {}
_sync_wait_lock = threading.Lock()


def register_sync_wait(sync_wait_id: str) -> _SyncWaitSlot:
    """Create + register a wait slot. Returns the slot so the caller
    (the proxy coroutine) can `await slot.event.wait()`.

    Idempotent on `sync_wait_id`: re-registering the same id returns
    the existing slot. This matters because `add_sync_pending_prompt`
    is idempotent on `decision_id`; a retry of the same denied
    request returns the SAME sync_wait_id, and we want the second
    waiter to attach to the same Event as the first (one answer
    wakes both — though in practice only one proxy coroutine waits
    at a time per decision_id).
    """
    with _sync_wait_lock:
        prior = _sync_wait_registry.get(sync_wait_id)
        if prior is not None:
            return prior
        slot = _SyncWaitSlot(event=asyncio.Event())
        _sync_wait_registry[sync_wait_id] = slot
        return slot


def wake_sync_pending_prompt(
    sync_wait_id: str,
    *,
    decision: str,
    answered_by: str | None = None,
    answer_kind: str | None = None,
) -> bool:
    """Signal the registered Event for `sync_wait_id` with the
    operator's decision. Returns True iff a slot was found + waked;
    False when no slot is registered (the typical "answer came in
    after the proxy already timed out + unregistered" case).

    `decision` must be 'allow' or 'deny'. The proxy coroutine reads
    this after its wait returns + behaves accordingly:
      - 'allow' → forward to upstream + return upstream's response
      - 'deny'  → return the original 403/error

    Thread-safe: takes the registry lock to mutate the slot. The
    Event.set() call itself is asyncio-thread-safe per CPython
    docs (set() is callable from any thread that holds the event-
    loop reference; we rely on the registry lock + the single-loop
    invariant of the proxy process to keep this simple).
    """
    if decision not in ("allow", "deny"):
        raise ValueError(
            f"wake_sync_pending_prompt: decision must be 'allow' or "
            f"'deny' (got {decision!r})"
        )
    with _sync_wait_lock:
        slot = _sync_wait_registry.get(sync_wait_id)
        if slot is None:
            return False
        slot.decision = decision
        slot.answered_by = answered_by
        slot.answer_kind = answer_kind
        # Set OUTSIDE the registry lock would be safer if the event
        # loop ever held the lock; in practice the lock is held only
        # for sub-microsecond critical sections + Event.set() is
        # itself non-blocking, so this is safe.
        slot.event.set()
        return True


def unregister_sync_wait(sync_wait_id: str) -> None:
    """Remove the slot. Called by the proxy coroutine in a `finally`
    so a timed-out wait doesn't leak slot dicts forever. Safe to
    call on an already-unregistered id."""
    with _sync_wait_lock:
        _sync_wait_registry.pop(sync_wait_id, None)


def _registered_sync_wait_ids() -> list[str]:
    """Snapshot of currently-registered ids. Used by the MCP tool
    `bouncer_pending_sync_prompts` to filter pending_prompts rows to
    just the ones the LIVE proxy is actually waiting on."""
    with _sync_wait_lock:
        return list(_sync_wait_registry.keys())


def _reset_sync_wait_registry_for_tests() -> None:
    """Test hook — clear the registry between tests so a leftover
    slot from one test doesn't bleed into the next. Not part of the
    public surface."""
    with _sync_wait_lock:
        _sync_wait_registry.clear()
import datetime as _dt
import enum
import logging
from typing import TYPE_CHECKING, Any

from .decisions import DecisionRecord, DefaultPolicy, Mode, decide
from .request_parser import parse_request
from .rules import RuleSet

if TYPE_CHECKING:
    from .store import BouncerStore

logger = logging.getLogger(__name__)


# Env var consulted by `resolve_active_mode` to surface the proxy's
# current effective mode to the agent-facing MCP tool. Lets a user
# script `IAM_JIT_BOUNCER_MODE=transparent ibounce run …` and have
# the same value introspectable via `bouncer_active_mode` without
# the MCP server having to peek at the running proxy's ProxyConfig
# (which lives in a separate process). Per
# [[bouncer-mode-selection-for-agents]] this is a READ surface only;
# agents do not flip it.
ACTIVE_MODE_ENV = "IAM_JIT_BOUNCER_MODE"

# Per-session override slot. The CLI (or a test) can call
# `set_session_mode_override("transparent")` to declare "for this
# Python session, the effective mode is X" — overrides the env var.
# Wins over the env var because it represents an explicit in-process
# decision (e.g. `ibounce run --mode transparent` setting the slot
# at startup), whereas the env var is the user's deployment default.
_session_mode_override: str | None = None


# ---------------------------------------------------------------------------
# #252 Slice 1 — audit-export channel registry.
#
# Per [[security-team-audit-export]]: every proxy decision is mirrored
# to one or both of (a) a JSONL log file and (b) an HTTPS webhook.
# Both channels are async-queued so the proxy hot-path never blocks.
#
# This module-level registry lets evaluate_request() emit the event
# WITHOUT every test having to wire two extra args through (matches
# the `_session_mode_override` pattern above). The CLI's serve()
# instantiates the channels at startup and calls register_audit_*();
# unit tests that exercise evaluate_request directly inject a fake
# via the same hooks.
#
# Per [[ibounce-honest-positioning]]: the audit channel is operator-
# visibility, NOT adversary defense. An adversarial agent can still
# bypass the bouncer entirely (per [[bouncer-positioning-locked-iam]]);
# the audit catches the post-hoc + the BYPASS events.
# ---------------------------------------------------------------------------
_audit_log_writer: Any | None = None
_audit_webhook_pusher: Any | None = None
# #280 — per-org notification routing engine. Same registry pattern as
# the single-webhook pusher above. When set, the engine handles all
# webhook dispatch + the single-webhook pusher is left unwired (per
# the memo's "existing --audit-webhook-url ignored when --alert-routes
# is set"). The JSONL log + Security Lake adapters stay independent.
_audit_routes_engine: Any | None = None
# #258 — AWS Security Lake adapter. Same module-level registry shape
# as the JSONL log + webhook channels above so evaluate_request feeds
# every wired channel without threading args through every call site.
# Per [[no-hosted-saas]] the bucket is the operator's; iam-jit-the-
# company never receives the data.
_audit_security_lake_writer: Any | None = None
# #285 — per-session NDJSON tee. Default OFF; the operator opts in via
# `--record-sessions-dir PATH` on `ibounce run`. When wired, every
# event the bouncer emits is additionally appended to the per-session
# file at `{dir}/{agent.session_id}.ndjson`. Events without a resolvable
# session_id are silently dropped by the recorder itself.
_session_recorder: Any | None = None
# #262 Slice 2 — alert rule engine. Same module-level registry shape
# as the two transport channels above so evaluate_request feeds it
# without threading args through every call site. Enterprise-gated
# via gate_alerts_license at CLI parse + serve() start (defense in
# depth, matches the webhook gate).
_audit_rule_engine: Any | None = None
# #267 — audit_export_degraded /healthz flag. Mirrors the heartbeat
# pattern: when the audit_export_degraded rule fires it flips this
# bool, which /healthz reads to return 503. Independent of the
# heartbeat-gap flag; either-or causes the 503 (per spec).
_audit_export_degraded_lock = threading.Lock()
_audit_export_degraded_detected: bool = False


def mark_audit_export_degraded() -> None:
    """#267 — set the /healthz audit_export degraded flag. Called by
    the audit_export_degraded alert rule when it fires; /healthz reads
    the flag via `is_audit_export_degraded()` and returns 503 when set.

    Public so the alert rule (in audit_export.alerts) can import +
    call it without a circular import."""
    global _audit_export_degraded_detected
    with _audit_export_degraded_lock:
        _audit_export_degraded_detected = True


def clear_audit_export_degraded() -> None:
    """#267 — reset the /healthz audit_export degraded flag. Called
    when the underlying health-section computation shows everything
    is healthy again (writes_ok + consecutive_failures back below
    threshold + drops cleared). Same self-clearing pattern as the
    heartbeat-gap flag (cleared on a fresh successful heartbeat)."""
    global _audit_export_degraded_detected
    with _audit_export_degraded_lock:
        _audit_export_degraded_detected = False


def is_audit_export_degraded() -> bool:
    """#267 — read the /healthz audit_export degraded flag. Public
    so /healthz + tests can introspect without a circular import."""
    with _audit_export_degraded_lock:
        return _audit_export_degraded_detected


def register_audit_log_writer(writer: Any | None) -> None:
    """Install the JSONL audit-log writer. Pass None to clear.
    The writer must already be `await writer.start()`-ed before
    registration so writes don't silently no-op."""
    global _audit_log_writer
    _audit_log_writer = writer


def register_audit_webhook_pusher(pusher: Any | None) -> None:
    """Install the HTTPS audit-webhook pusher. Pass None to clear."""
    global _audit_webhook_pusher
    _audit_webhook_pusher = pusher


def register_audit_routes_engine(engine: Any | None) -> None:
    """#280 — install the per-org notification routing engine. Pass
    None to clear. When set, the single-webhook pusher is ignored on
    every emit (the routing engine is the multi-destination
    replacement)."""
    global _audit_routes_engine
    _audit_routes_engine = engine


def register_audit_security_lake_writer(writer: Any | None) -> None:
    """#258 — install the AWS Security Lake parquet writer. Pass None
    to clear. The writer must already be `writer.start()`-ed before
    registration so the first event's batch doesn't no-op."""
    global _audit_security_lake_writer
    _audit_security_lake_writer = writer


def register_session_recorder(recorder: Any | None) -> None:
    """#285 — install the per-session NDJSON recorder. Pass None to
    clear. The recorder must already be `recorder.start()`-ed before
    registration so the first event's open doesn't no-op."""
    global _session_recorder
    _session_recorder = recorder


def register_audit_rule_engine(engine: Any | None) -> None:
    """#262 Slice 2 — install the suspicious-activity alert engine.
    Pass None to clear. The engine's `emit` callback should point at
    `_emit_audit_event_raw` so fired alerts ride the same transport
    as decision events. Re-entry guard in `RuleEngine.observe` keeps
    the engine from firing on its own output."""
    global _audit_rule_engine
    _audit_rule_engine = engine


def _emit_audit_event_raw(event: dict) -> None:
    """Push `event` to BOTH transport channels (JSONL + webhook) and
    NOTHING else. The rule engine's emit callback points here so
    fired alerts ride the existing transport without re-entering the
    engine — RuleEngine's re-entry guard handles the case where an
    alert event would otherwise trigger another rule.

    Split out from `_emit_audit_event` so the rule engine + the
    decision path both call it without the engine observing its own
    output via the public emitter.
    """
    if _audit_log_writer is not None:
        try:
            _audit_log_writer.write(event)
        except Exception as e:
            logger.warning("audit log writer enqueue failed: %s", e)
    # #280 — per-org routing engine takes precedence over the single-
    # webhook pusher. The CLI parse-time gate refuses both being wired
    # simultaneously to avoid surprise; the registration paths in
    # serve() also enforce mutual exclusion.
    if _audit_routes_engine is not None:
        try:
            _audit_routes_engine.push(event)
        except Exception as e:
            logger.warning("audit routes engine enqueue failed: %s", e)
    elif _audit_webhook_pusher is not None:
        try:
            _audit_webhook_pusher.push(event)
        except Exception as e:
            logger.warning("audit webhook pusher enqueue failed: %s", e)
    # #258 — AWS Security Lake parquet writer. In-memory append; the
    # background rotator flushes per the rotation interval / size cap.
    # Fail-soft so a credential rotation failure on the writer's worker
    # never raises into the proxy hot path.
    if _audit_security_lake_writer is not None:
        try:
            _audit_security_lake_writer.write(event)
        except Exception as e:
            logger.warning("audit security-lake writer enqueue failed: %s", e)
    # #285 — per-session NDJSON tee. Synchronous (one append + no
    # network); fail-soft like every other emitter so a disk-full state
    # never raises into the proxy hot path.
    if _session_recorder is not None:
        try:
            _session_recorder.record(event)
        except Exception as e:
            logger.warning("session recorder enqueue failed: %s", e)


def _emit_audit_event(event: dict) -> None:
    """Hand `event` to both audit channels if configured AND to the
    rule engine (if installed). Both calls are non-blocking
    enqueues; exceptions are swallowed + logged — the audit channel
    is a feature, not a hard dependency of correctness; a broken
    disk should not turn the proxy into a 500-machine.

    #262 Slice 2: when an alert engine is installed, observe() is
    called AFTER the transport enqueue. The engine's emit callback
    pushes any fired alerts back through `_emit_audit_event_raw`
    (NOT this function) so the engine doesn't see its own output.
    """
    _emit_audit_event_raw(event)
    if _audit_rule_engine is not None:
        try:
            _audit_rule_engine.observe(event)
        except Exception as e:
            logger.warning("audit rule engine observe failed: %s", e)


def _observe_pause_transition(current_pause: dict | None) -> None:
    """#270 Slice 2 — detect a pause-window close (explicit `pause
    stop` OR auto-expiry detected on a `_active_pause_locked` call)
    and emit a synthetic PAUSE_END event so the pause_long alert rule
    can evaluate the closed window's duration against its threshold.

    Compares `current_pause` (what the proxy just looked up) against
    `_last_seen_pause` (what the previous lookup saw). A close is
    detected when:
      * last_seen present AND (current is None OR a different id)

    The pause's duration_seconds is computed from `started_at` to NOW
    (wall-clock) rather than from `started_at` to `ends_at`. Reason:
    `ends_at` is the planned expiry; the actual window may have been
    cut short by an explicit stop. The wall-clock distance from
    started_at to the detection moment matches the operator's
    intuition of "how long was the proxy permissive."

    end_kind is derived from the same row when available so the
    downstream alert event carries the kind the operator's audit log
    will show (`expired` vs `resumed_early`).

    Fail-soft: any exception inside the emit path is logged + swallowed
    (same posture as `_emit_audit_event`). The rule engine's re-entry
    guard handles the case where the emitted event would re-enter
    observe().
    """
    global _last_seen_pause
    with _last_seen_pause_id_lock:
        prior = _last_seen_pause
        # Decide if we observed a close: prior present + (current is
        # None OR a different id).
        prior_id = prior.get("id") if isinstance(prior, dict) else None
        current_id = (
            current_pause.get("id") if isinstance(current_pause, dict) else None
        )
        closed = prior_id is not None and (
            current_id is None or current_id != prior_id
        )
        # Update last-seen BEFORE emitting so a slow / crashing emit
        # path doesn't cause repeated re-fires on the next lookup.
        # If we just observed a close + a new pause is now active,
        # the new pause becomes the next "last seen" — we'll fire
        # the close detection for IT when IT later closes.
        _last_seen_pause = current_pause if current_id is not None else None
        if not closed or not isinstance(prior, dict):
            return
        closed_pause = prior
    # Outside the lock: compute duration + build + emit. Lazy import
    # keeps the alerts module out of proxy's eager import set (matches
    # the existing pattern for audit_event_from_decision).
    try:
        from .audit_export import make_pause_end_event
        started_at = closed_pause.get("started_at")
        try:
            started_dt = _dt.datetime.fromisoformat(
                str(started_at).replace("Z", "+00:00")
            )
            duration_seconds = int(
                (_dt.datetime.now(_dt.UTC) - started_dt).total_seconds()
            )
            if duration_seconds < 0:
                duration_seconds = 0
        except Exception:
            # Malformed timestamp: fall back to 0 so the event still
            # emits + the operator sees the close in the audit chain;
            # pause_long won't fire on duration=0 (which is the
            # correct outcome on a malformed row).
            duration_seconds = 0
        # Re-read the row to pick up end_kind written by either
        # `end_pause` (resumed_early) OR the lazy GC in
        # `_active_pause_locked` (expired). We don't have a store
        # handle here, so we read what we cached at observation time
        # plus a best-effort post-read; if neither is available we
        # default to 'resumed_early' as the safer label (an explicit
        # stop is the more common path).
        end_kind = str(closed_pause.get("end_kind") or "resumed_early")
        started_by = str(closed_pause.get("started_by") or "")
        evt = make_pause_end_event(
            pause_id=closed_pause.get("id"),
            duration_seconds=duration_seconds,
            end_kind=end_kind,
            started_by=started_by,
        )
        _emit_audit_event(evt)
    except Exception as e:
        logger.warning("pause-end synthetic emit failed: %s", e)


# Imported lazily inside _observe_pause_transition; declared at module
# scope so the proxy file doesn't pay the import cost when no pause
# is ever opened. Kept here as a comment so the dependency is visible
# to grep + greppable in audits.
# from .audit_export import make_pause_end_event  # noqa


def audit_export_status() -> dict[str, Any]:
    """Snapshot of both audit-export channels for the MCP status tool.

    Returns a stable shape regardless of which channels are installed
    so the agent's structured-content consumer can branch on the
    `configured` flags rather than `KeyError`-ing on missing fields.

    #262 Slice 2: also surfaces the alert-engine status fields
    (`alerts_enabled`, `alerts_fired_count`, `last_alert_pattern`)
    at the top level so an agent can answer "did the alert engine
    fire anything?" with a single field read.
    """
    if _audit_log_writer is not None:
        log_status = _audit_log_writer.status()
    else:
        log_status = {"configured": False}
    if _audit_webhook_pusher is not None:
        webhook_status = _audit_webhook_pusher.status()
    else:
        webhook_status = {"configured": False}
    if _audit_security_lake_writer is not None:
        security_lake_status = _audit_security_lake_writer.status()
    else:
        security_lake_status = {"configured": False}
    if _audit_rule_engine is not None:
        engine_status = _audit_rule_engine.status()
    else:
        engine_status = {
            "alerts_enabled": False,
            "alerts_fired_count": 0,
            "last_alert_pattern": None,
            "last_alert_at_unix": None,
            "active_rules": [],
        }
    # #264 — heartbeat state. Always queryable (the heartbeat module's
    # status snapshot returns a stable shape even when the emitter
    # isn't installed) so MCP consumers can branch on the
    # `heartbeat_enabled` bool rather than KeyError-ing.
    from .audit_export.heartbeat import heartbeat_status as _heartbeat_status
    hb_status = _heartbeat_status()
    return {
        "log": log_status,
        "webhook": webhook_status,
        "security_lake": security_lake_status,
        # Convenience aggregates so an agent can answer "are we losing
        # events?" with a single field read instead of summing two.
        "total_events": (
            log_status.get("total_events", 0)
            + webhook_status.get("total_events", 0)
        ),
        "dropped_events": (
            log_status.get("dropped_events", 0)
            + webhook_status.get("dropped_events", 0)
        ),
        "last_error": (
            webhook_status.get("last_error")
            or log_status.get("last_error")
        ),
        # #262 Slice 2 — alert engine surface. Top-level so agents
        # don't need a nested `alerts.alerts_enabled` lookup.
        "alerts_enabled": engine_status.get("alerts_enabled", False),
        "alerts_fired_count": engine_status.get("alerts_fired_count", 0),
        "last_alert_pattern": engine_status.get("last_alert_pattern"),
        "alerts": engine_status,
        # #264 — heartbeat surface. Top-level so an agent can answer
        # "is the bouncer-availability check working?" with a single
        # field read. `heartbeat_gap_detected` is the load-bearing
        # bool external monitoring polls (matches what /healthz uses
        # to flip to 503).
        "heartbeat_enabled": hb_status["heartbeat_enabled"],
        "heartbeat_interval_seconds": hb_status["heartbeat_interval_seconds"],
        "heartbeat_last_emit_seconds_ago": (
            hb_status["heartbeat_last_emit_seconds_ago"]
        ),
        "heartbeat_gap_detected": hb_status["heartbeat_gap_detected"],
    }


# #267 — /healthz 503-trigger thresholds for the audit_export section.
# Spec'd in the [[audit-export-failure-visibility]] memo:
#   * log_writes_ok == False               → 503
#   * webhook_consecutive_failures > 3     → 503
#   * webhook_last_success_seconds_ago > 5min (webhook configured but
#     silent) → 503
# The audit_export_degraded alert rule uses LOOSER thresholds (>5
# consecutive / drops>10 in 5min / writes_ok=False) — the rule is
# operator-action signal, /healthz is the more aggressive monitoring
# probe.
HEALTHZ_AUDIT_WEBHOOK_CONSECUTIVE_FAILURE_THRESHOLD = 3
HEALTHZ_AUDIT_WEBHOOK_SILENCE_SECONDS_THRESHOLD = 300


def audit_export_health_section() -> dict[str, Any]:
    """#267 — assemble the /healthz `audit_export` block + compute
    the boolean degradation signal external monitoring polls.

    Returns a dict with the spec-shaped fields plus a derived
    `degraded` bool the /healthz handler reads to decide 503 vs 200.
    Re-used by the `ibounce audit-export health` CLI subcommand so
    both surfaces report identical values (no divergence between
    "what the probe sees" and "what the operator sees on the CLI").

    Per [[security-team-positioning-safety-not-surveillance]]: the
    webhook URL is MASKED via the existing mask_url_userinfo helper
    (token-in-userinfo is the load-bearing exfil case); the bearer
    token NEVER appears anywhere in this output (we don't even read
    it — the pusher's status() returns mask_token() already).
    """
    import time as _time

    # Log channel — convert the writer's stats into the spec-shape.
    if _audit_log_writer is not None:
        log_stats = _audit_log_writer.status()
        log_section = {
            "configured": True,
            "log_writes_ok": bool(log_stats.get("writes_ok", True)),
            "log_path": log_stats.get("path", ""),
            "log_last_error": log_stats.get("last_error"),
            "log_last_error_at_unix": log_stats.get("last_error_at_unix"),
            "log_total_events": log_stats.get("total_events", 0),
            "log_dropped_events": log_stats.get("dropped_events", 0),
        }
    else:
        log_section = {
            "configured": False,
            "log_writes_ok": True,  # not configured = nothing failing
            "log_path": None,
            "log_last_error": None,
            "log_last_error_at_unix": None,
            "log_total_events": 0,
            "log_dropped_events": 0,
        }

    # Webhook channel — convert the pusher's stats into the spec-shape.
    now = _time.time()
    if _audit_webhook_pusher is not None:
        webhook_stats = _audit_webhook_pusher.status()
        last_success_unix = webhook_stats.get("last_success_unix")
        last_attempt_unix = webhook_stats.get("last_attempt_unix")
        last_success_seconds_ago = (
            int(now - last_success_unix)
            if last_success_unix is not None
            else None
        )
        last_attempt_seconds_ago = (
            int(now - last_attempt_unix)
            if last_attempt_unix is not None
            else None
        )
        webhook_section = {
            "webhook_configured": True,
            "webhook_url_masked": webhook_stats.get("url", ""),
            "webhook_last_success_seconds_ago": last_success_seconds_ago,
            "webhook_last_attempt_seconds_ago": last_attempt_seconds_ago,
            "webhook_last_status_code": webhook_stats.get("last_status_code"),
            "webhook_consecutive_failures": webhook_stats.get(
                "consecutive_failures", 0,
            ),
            "webhook_last_error": webhook_stats.get("last_error"),
            "webhook_last_error_at_unix": webhook_stats.get(
                "last_error_at_unix",
            ),
            "queue_depth": webhook_stats.get("queue_depth", 0),
            "queue_capacity": webhook_stats.get("queue_maxsize", 0),
            "dropped_count_since_start": webhook_stats.get(
                "dropped_events", 0,
            ),
        }
    else:
        webhook_section = {
            "webhook_configured": False,
            "webhook_url_masked": None,
            "webhook_last_success_seconds_ago": None,
            "webhook_last_attempt_seconds_ago": None,
            "webhook_last_status_code": None,
            "webhook_consecutive_failures": 0,
            "webhook_last_error": None,
            "webhook_last_error_at_unix": None,
            "queue_depth": 0,
            "queue_capacity": 0,
            "dropped_count_since_start": 0,
        }

    section: dict[str, Any] = {}
    section.update(log_section)
    section.update(webhook_section)

    # Compute degraded bool. ANY of the three spec conditions trips it.
    # We DELIBERATELY OR the conditions so an operator dashboard can
    # check `degraded` as a single field but still surface the
    # individual signals for "why is this degraded?" forensics.
    degraded_reasons: list[str] = []
    if log_section["configured"] and not log_section["log_writes_ok"]:
        degraded_reasons.append("log_writes_ok=false")
    if webhook_section["webhook_configured"]:
        if (
            webhook_section["webhook_consecutive_failures"]
            > HEALTHZ_AUDIT_WEBHOOK_CONSECUTIVE_FAILURE_THRESHOLD
        ):
            degraded_reasons.append(
                f"webhook_consecutive_failures="
                f"{webhook_section['webhook_consecutive_failures']}"
                f" (threshold "
                f"{HEALTHZ_AUDIT_WEBHOOK_CONSECUTIVE_FAILURE_THRESHOLD})"
            )
        last_ok = webhook_section["webhook_last_success_seconds_ago"]
        # "Configured but silent": if last_success_seconds_ago > 5min
        # AND we've actually attempted something (last_attempt is not
        # None). A pristine boot before the first send shouldn't fire
        # this — that's covered by the "last_attempt is not None"
        # guard. After the first attempt, last_ok==None means we
        # never succeeded which IS the failure mode.
        last_attempt = webhook_section["webhook_last_attempt_seconds_ago"]
        if last_attempt is not None:
            if (
                last_ok is None
                or last_ok > HEALTHZ_AUDIT_WEBHOOK_SILENCE_SECONDS_THRESHOLD
            ):
                degraded_reasons.append(
                    "webhook_last_success_seconds_ago="
                    f"{last_ok} "
                    f"(threshold "
                    f"{HEALTHZ_AUDIT_WEBHOOK_SILENCE_SECONDS_THRESHOLD})"
                )

    section["degraded"] = bool(degraded_reasons)
    section["degraded_reasons"] = degraded_reasons
    return section


_session_profile_override: Any = None
"""#253 — in-process active-profile override. Set by the bulk-answer
CLI / MCP tool (option 1 "switch profile") so a hot-swap takes effect
on the very next decision WITHOUT requiring a proxy restart.

Resolution: when set, takes precedence over `ProxyConfig.active_profile`.
The serve() process owns this singleton; cross-process flips don't
work (the CLI in a separate shell would set its own copy + serve
wouldn't see it). Cross-process flip is a v1.1 / SaaS feature; the
local-only safety-mode covers single-process which is the dominant
deployment.
"""


def set_session_profile_override(profile: Any) -> None:
    """#253 — install (or clear with None) the in-process active-profile
    override. Called by `prompts bulk-answer` when the operator picks
    option 1.
    """
    global _session_profile_override
    _session_profile_override = profile


def active_profile_override() -> Any:
    """Read accessor for callers that want the override snapshot."""
    return _session_profile_override


def set_session_mode_override(mode: str | None) -> None:
    """Set the in-process active-mode override. Pass None to clear.

    Called by `ibounce run` after parsing `--mode` so that any MCP
    tool spawned by the same process surfaces the same value. Tests
    use this to exercise the override-wins path without mutating
    the env.
    """
    global _session_mode_override
    if mode is None:
        _session_mode_override = None
        return
    normalized = str(mode).strip().lower()
    if normalized not in ("cooperative", "transparent", "off", "plan-capture"):
        raise ValueError(
            f"set_session_mode_override: invalid mode {mode!r}; "
            "expected one of cooperative | transparent | off | plan-capture"
        )
    _session_mode_override = normalized


def resolve_active_mode() -> dict[str, str]:
    """Return the bouncer's currently effective mode + where it came from.

    Resolution order (highest precedence first):
      1. Session override (set via `set_session_mode_override`) ->
         source="session_override"
      2. `IAM_JIT_BOUNCER_MODE` env var (case-insensitive; accepts
         cooperative | transparent | off) -> source="env"
      3. Default = "cooperative" (matches `ProxyConfig.mode` default
         + the [[safety-mode-lean-permissive]] guidance) ->
         source="default"

    Unknown env values fall through to the default + source="default"
    (we don't crash the MCP server on a typo'd env). Returned dict
    matches the shape `bouncer_active_mode` / `ibounce_active_mode`
    MCP tools surface to agents.
    """
    if _session_mode_override is not None:
        return {"mode": _session_mode_override, "source": "session_override"}
    raw = os.environ.get(ACTIVE_MODE_ENV, "").strip().lower()
    if raw in ("cooperative", "transparent", "off", "plan-capture"):
        return {"mode": raw, "source": "env"}
    return {"mode": "cooperative", "source": "default"}


class ProxyMode(str, enum.Enum):
    """Which kind of guardrail the proxy runs.

    Per bouncer-both-modes-first-class these are first-class user
    choices, not v1.0/v1.1 phases. The user picks at deployment
    time; per-task scope can override.
    """

    COOPERATIVE = "cooperative"
    """Advisory mode. Every call is parsed + logged + a verdict is
    computed, but every call is ALSO forwarded to AWS (Slice 2)
    regardless of the verdict. Useful for: solo dev iterating fast,
    debugging the bouncer itself, observability without enforcement,
    pre-flip preview of what TRANSPARENT mode would block."""

    TRANSPARENT = "transparent"
    """Enforcement mode. DENY verdicts return 403 to the SDK client
    without forwarding. ALLOW verdicts forward verbatim. PROMPT
    verdicts block + interactive prompt (later slices). Useful for:
    locked-down-IAM-dev environments, compliance-sensitive deploys,
    agent-safety-critical sessions."""

    PLAN_CAPTURE = "plan-capture"
    """Plan-mode capture (#132). Every call is parsed + audited +
    RETURNED-WITH-SYNTHETIC-SUCCESS — NEVER forwarded to AWS. The
    operator gets a recorded call graph the agent INTENDED to make
    (terraform-plan-for-any-AWS-touching-agent-task) before any
    state change. Per [[ibounce-honest-positioning]]: this is an
    operator PREVIEW (deterrent), not a security boundary — an
    adversarial agent can detect plan-capture mode + behave
    differently. Per [[creates-never-mutates]]: synthetic
    responses are FAKE; we never touch AWS in this mode."""


@dataclasses.dataclass(frozen=True)
class ProxyConfig:
    """Runtime config for the proxy server. Built from CLI flags +
    env + ProxyMode."""

    host: str = "127.0.0.1"
    port: int = 8767
    mode: ProxyMode = ProxyMode.COOPERATIVE
    default_policy: DefaultPolicy = DefaultPolicy.DENY
    forward_scheme: str = "https"
    """Outbound scheme for forwarding allowed requests. Defaults to
    HTTPS (real AWS endpoints). Tests pass "http" to forward to a
    local mock-AWS server. #300 — also set from the scheme of the
    operator's --upstream URL when that flag is passed."""
    forward_host_override: str | None = None
    """#300 — when set, the outbound forward goes to THIS host:port
    instead of the inbound Host header. Used to point ibounce at a
    LocalStack / mock-AWS endpoint (e.g. `127.0.0.1:4566`) without
    requiring the SDK client to set a non-AWS Host header. The
    SigV4 signature is over the inbound Host (which boto3 derives
    from AWS_ENDPOINT_URL), so this override + LocalStack's lax
    signature validation is the standard LocalStack flow. The
    CRIT-32-01 outbound-host allowlist still gates the override
    target (loopback / .amazonaws.com / operator-supplied
    EXTRA_HOSTS). Default None = forward to the signed Host
    (existing real-AWS behaviour)."""
    active_profile: Any = None
    """Slice 7: the resolved Profile object whose denies act as a
    hard floor above task/global rules. None or `Profile(name='full-user')`
    means no profile-level rules fire (existing behavior; `none` also
    resolves here for v1.0 backward-compat — see DEPRECATED_PROFILE_ALIASES
    in profiles.py)."""
    account_id: str | None = None
    account_alias: str | None = None
    """Account-id / alias used by profile.only_account_ids checks
    and keyword_targets that include 'account_alias'. Optional;
    profile rules that target these fields simply don't match when
    the values are None."""
    prompt_on_deny: bool = False
    """#5 v1.0 (async): when True, transparent-mode DENYs also
    write a pending_prompts row so the operator can later answer
    (always-allow / add-to-profile / ignore) via the `bouncer
    prompts` CLI. Async — the agent gets DENIED immediately; the
    operator's answer takes effect on the NEXT call of the same
    shape. v1.1 adds `sync_prompt_on_deny` below for a synchronous
    mode where the proxy briefly waits for an answer before
    returning; the two flags are mutually exclusive."""
    sync_prompt_on_deny: bool = False
    """#203 v1.1 (sync): when True, transparent-mode DENYs ENQUEUE
    a pending_prompts row + BLOCK the request for up to
    `sync_prompt_timeout_seconds` seconds awaiting an operator
    answer via `ibounce prompts answer`. Answer kind=always|profile
    → forward to upstream + return upstream's actual response.
    Answer kind=ignore (DENY) OR timeout → return the original
    403/error.

    Per [[ibounce-honest-positioning]] this is a DETERRENT UX for
    legitimate human-in-loop workflows, not adversarial defense —
    an adversarial agent can detect the blocking + behave
    differently. Per [[creates-never-mutates]]: nothing AWS-side
    is mutated; we only append to the audit log + (on allow)
    forward verbatim. Per [[scorer-is-ground-truth]]: the DENY
    decision still comes from the same scorer — sync just changes
    the operator-side UX of how the DENY is handled.

    Mutually exclusive with `prompt_on_deny`; the CLI enforces
    this at parse time. Only fires in TRANSPARENT mode; pauses
    supersede (already-bypassed). Cooperative-mode DENYs are
    advisory + still don't block."""
    sync_prompt_timeout_seconds: int = 30
    """How long the proxy will block on a sync deny-prompt before
    falling through to `sync_prompt_default_decision`. Range
    5..300 enforced at CLI parse time."""
    sync_prompt_default_decision: str = "deny"
    """Decision applied when `sync_prompt_timeout_seconds` elapses
    with no answer. Either 'allow' (forward to upstream) or 'deny'
    (return the original 403/error). Default 'deny' matches the
    safer fail-closed posture; operators who want fail-open can
    pass --sync-prompt-default=allow."""
    plan_session_id: str | None = None
    """#132 plan-capture: session id every intercepted call is
    bound to for the lifetime of this serve() invocation. None
    means "the proxy isn't in plan-capture mode" OR "the proxy
    didn't get an explicit --plan-session-id and the serve() entry
    point will mint one at startup." Only consulted when
    `mode == ProxyMode.PLAN_CAPTURE`."""
    plan_write_switch_notify: str = "manual"
    """#145 plan-capture read->write switch UX. Configures what
    happens on the FIRST write call in a plan-capture session
    (read_only -> write_pending|writes_approved|writes_rejected).

      - 'manual' (default): transition to write_pending + enqueue a
        plan-write prompt; the operator answers approve/reject via
        `ibounce prompts answer ID --kind plan-write --decision X`.
        The write call still gets the synthetic-success response —
        plan-capture NEVER forwards regardless. The decision controls
        whether SUBSEQUENT writes get success (approve) or rejection
        synthetic (reject).
      - 'auto-approve': transition silently to writes_approved on the
        first write; no prompt. Operator sees the phase + first_write
        timestamp on `plan show` at session end.
      - 'reject': transition straight to writes_rejected on the first
        write; subsequent writes get a PlanCaptureWritesRejected
        synthetic error (not a success).

    Per [[ibounce-honest-positioning]]: this is a deterrent UX helper,
    NOT a security boundary. An adversarial agent can call writes
    without preceding reads; we still flip the phase + still surface
    the prompt, but plan-capture's actual safety property is
    "synthetic responses, never AWS" (which is identical regardless
    of the write-switch decision)."""
    # Don't bind to 0.0.0.0 by default — proxy is a LOCAL-ONLY
    # thing per the local-only-safety-mode + no-hosted-saas memos.
    # Binding externally would silently expose a credential-handling
    # surface to the network.

    # #252 Slice 1 — security-team audit-export transport.
    # Both channels are OFF by default; the operator opts in via the
    # CLI flags. The webhook channel is also license-gated at CLI
    # parse time (see `gate_webhook_license` in audit_export.webhook).
    audit_log_path: str | None = None
    """Filesystem path for the JSONL audit log. None disables the
    channel. Per [[security-team-audit-export]]: append-only; no
    rotation built in — operators point logrotate / Fluent Bit /
    Vector at the path."""
    record_sessions_dir: str | None = None
    """#285 — per-session NDJSON recording directory. When set, the
    proxy additionally tees every event into
    `{dir}/{agent.session_id}.ndjson`. Replayable via the cross-
    product `iam-jit session replay <FILE>`. Default None = recorder
    disabled (zero overhead on the hot path)."""
    audit_log_fsync: bool = False
    """Opt-in fsync after every JSONL write. Off by default for
    throughput; on for compliance-grade durability. The trade-off is
    documented in the CLI --help text."""
    audit_webhook_url: str | None = None
    """HTTPS URL of the operator's audit collector. None disables
    the channel. SSRF-gated at start (RFC1918 / loopback /
    .internal / .local denylist unless --allow-internal-webhook
    is set)."""
    audit_webhook_token: str | None = None
    """Bearer token sent in the Authorization header. NEVER appears
    in the startup banner / /healthz / log file / error messages —
    masked as '***' wherever a value would otherwise leak."""
    audit_webhook_batch_size: int = 1
    """Number of events per HTTP POST. Default 1 (every-decision);
    set higher for high-throughput orgs that prefer fewer, larger
    requests."""
    audit_webhook_allow_internal: bool = False
    """Opt-out of the SSRF gate. Required to ship to a hostname
    that matches an intranet suffix OR resolves to an RFC1918 /
    loopback / link-local IP. Off by default; flipping this is a
    deliberate operator decision for an intranet collector on a
    trusted network segment."""
    audit_webhook_preset: str = "generic"
    """#257 — webhook body/headers shape. `generic` (default) is
    byte-identical to the pre-#257 wire format (Bearer token + NDJSON).
    `datadog` / `splunk-hec` / `sentinel` are vendor-shaped for
    one-click SIEM ingest. Same Enterprise license gate fires
    regardless of preset (per [[audit-webhook-presets]])."""
    audit_webhook_tags: str = ""
    """#257 — free-form tag string appended to Datadog `ddtags`.
    Format: `key:value,key:value`. Ignored by other presets but
    surfaced in the startup banner for operator clarity."""
    audit_webhook_sentinel_table: str = "IamJitBouncer"
    """#257 — name of the Microsoft Sentinel Log Analytics custom
    table this data lands in. Sent as the `Log-Type` header. Ignored
    by other presets."""

    # #262 Slice 2 — suspicious-activity alert rule engine.
    alert_rules_path: str | None = None
    """Path to the --alert-rules YAML file. None = no alert engine.
    Empty string = engine with all built-in defaults (no YAML to
    load). Enterprise license-gated at CLI parse + serve() start
    via gate_alerts_license (per [[enterprise-self-host-only]]).
    See `audit_export.alerts.load_alerts_config` for the YAML
    schema."""

    # #280 — per-org notification routing.
    alert_routes_path: str | None = None
    """Path to the --alert-routes YAML file. None = single-webhook
    backward-compat path (the existing audit_webhook_* fields). Set
    to a YAML path = multi-destination routing engine activates;
    single-webhook is ignored. Enterprise license-gated at CLI parse
    + serve() start via gate_routes_license (per
    [[enterprise-self-host-only]]). See `audit_export.routes.
    load_routes_config` for the YAML schema."""

    # #264 — heartbeat events for prompt-injection-disable-bouncer-threat.
    heartbeat_interval_seconds: int = 0
    """How often (in seconds) the heartbeat emitter publishes an OCSF
    activity_id=99 'heartbeat' event through the audit-export channels.
    0 = OFF (default; zero phone-home preserved per
    [[security-team-positioning-safety-not-surveillance]]). Recommended
    30 for Enterprise deployments where the SIEM can watch for gaps.
    The heartbeat itself ships on every tier; the heartbeat_gap rule
    that fires on missed heartbeats rides the Enterprise-gated alert
    engine (see alert_heartbeat_missing_count)."""
    alert_heartbeat_missing_count: int = 2
    """#264 — heartbeat_gap rule threshold. Fire after this many
    consecutive missed heartbeats (where 'missed' = elapsed time since
    last heartbeat > interval * count). Default 2 catches one missed
    beat + the detection scan that follows. Surfaced as a separate
    flag so operators can raise it for noisy networks without editing
    the --alert-rules YAML. Operationally meaningful only when both
    heartbeat_interval_seconds > 0 AND alert_rules_path is not None
    (otherwise nothing reads it)."""

    # #253 — bulk-prompt-answer UX (burst detector + bulk-answer MCP
    # tool token). Both fields default to safe values so a v1.0 user
    # who doesn't pass either flag gets the documented behavior (5
    # prompts in 60s fires the burst hint; MCP bulk-answer disabled).
    burst_threshold: int = 5
    """Pending-prompt count over `burst_window_seconds` that fires the
    BURST_DETECTED OCSF event + the pre-burst hint surface. Defaults
    to 5; tune up for noisy environments where occasional flurries
    are expected. Per [[safety-mode-lean-permissive]]: a low default
    catches the block-happy failure mode early. Validation range
    1..1000 (anything higher is a sign the operator wants the
    detector disabled — use a very large window instead)."""
    burst_window_seconds: int = 60
    """Sliding-window length the burst detector counts over. Defaults
    to 60s. Range 1..3600. A 60s window catches the typical SDK
    retry-loop pattern (3 retries ~ 30s, 5 retries ~ 60s); larger
    windows are appropriate when the operator expects intentional
    pacing between agent calls."""
    bulk_answer_mcp_token: str | None = None
    """Per the issue body: operator-set token that GATES the MCP
    `bouncer_prompts_bulk_answer` tool. Default None = MCP bulk-answer
    DISABLED (every call returns an error explaining how to enable).
    When set, agents must echo the exact token on every bulk-answer
    call. Comparison is constant-time. The operator shares the token
    out-of-band with the agent (e.g. pastes into the agent's prompt).
    This prevents an adversarial agent from bulk-allowing itself out
    of every pending prompt — which would invert the whole point of
    the prompt UX. Per [[bulk-prompt-answer-ux]]'s "Don't" list."""

    # #258 — AWS Security Lake adapter (Channel 4). All fields OFF
    # by default. Per [[no-hosted-saas]] + [[self-host-zero-billing-
    # dependency]] the bucket lives in the operator's AWS account;
    # iam-jit-the-company never receives the data. The adapter
    # writes OCSF events as parquet files into the Security-Lake-
    # compatible S3 layout (region=<r>/eventday=<YYYYMMDD>/
    # eventhour=<HH>/api_activity-<unix-ms>.parquet); Security Lake
    # auto-ingests via its custom-source crawler.
    security_lake_bucket: str | None = None
    security_lake_region: str | None = None
    security_lake_role_arn: str | None = None
    security_lake_rotation_seconds: int = 300

    audit_events_token: str | None = None
    """#271 — bearer token required on GET /audit/events when the
    proxy is bound off-loopback. None + loopback bind = no auth (the
    loopback bind is itself the trust anchor); None + external bind =
    the CLI refuses to start. When set, requests must carry
    `Authorization: Bearer <token>`. Powers the cross-bouncer
    `iam-jit audit query` CLI that fans queries across every reachable
    bouncer in parallel."""


@dataclasses.dataclass
class RequestObservation:
    """What the proxy observed + decided about one inbound HTTP
    request. Slice 1 surfaces this so callers (tests + future
    forwarding layer) can inspect verdicts without parsing logs."""

    at: str
    method: str
    host: str
    path: str
    parsed_service: str | None
    parsed_action: str | None
    parsed_region: str | None
    parsed_arn: str | None
    decision_verdict: str
    decision_reason: str
    mode_at_decision: str
    enforced: bool
    """In COOPERATIVE mode, even a DENY verdict has enforced=False
    (advisory only). In TRANSPARENT mode, DENY verdicts have
    enforced=True (would 403 the SDK client). Useful for the
    audit-log + the eventual recommender."""
    decision_id: int = 0
    """#203 — the decisions table id assigned to this observation
    (0 when audit-write failed or when the request was so
    unclassifiable it never reached the decide() call). The sync
    deny-prompt path uses this to look up the pending_prompts row
    on wake. Defaults to 0 for backward-compat with callers
    constructing RequestObservation in tests."""
    active_pause_id: int | None = None
    """#203 — id of the pause window active at decision time, or
    None. Surfaced so the proxy hot-path can apply 'pause supersedes
    sync prompt' without re-querying the store."""


def _build_observation(
    *,
    method: str,
    host: str,
    path: str,
    parsed,  # ParsedRequest | None
    record: DecisionRecord,
    mode: ProxyMode,
    decision_id: int = 0,
    active_pause_id: int | None = None,
) -> RequestObservation:
    """Compose the observation surfaced to callers + audit log."""
    enforced = (
        mode == ProxyMode.TRANSPARENT
        and record.decision.value in ("deny", "prompt")
    )
    return RequestObservation(
        at=_dt.datetime.now(_dt.UTC).isoformat().replace("+00:00", "Z"),
        method=method,
        host=host,
        path=path,
        parsed_service=parsed.service if parsed else None,
        parsed_action=parsed.action if parsed else None,
        parsed_region=parsed.region if parsed else None,
        parsed_arn=getattr(parsed, "arn", None) if parsed else None,
        decision_verdict=record.decision.value,
        decision_reason=record.reason,
        mode_at_decision=mode.value,
        enforced=enforced,
        decision_id=decision_id,
        active_pause_id=active_pause_id,
    )


def evaluate_request(
    *,
    method: str,
    host: str,
    path: str,
    headers: dict[str, str],
    body: bytes | str | None,
    query: dict[str, str] | None,
    store: BouncerStore,
    mode: ProxyMode,
    default_policy: DefaultPolicy = DefaultPolicy.DENY,
    active_profile=None,  # type: profiles.Profile | None
    account_id: str | None = None,
    account_alias: str | None = None,
    prompt_on_deny: bool = False,
) -> RequestObservation:
    # #266 — agent identity. The User-Agent header (case-insensitive)
    # feeds the per-call detection path in the audit-export event
    # builder. Extracted here once so every audit_event_from_decision
    # call below threads the same value through (MCP-session detection
    # at the same level is module-global state inside agent_context
    # so doesn't need a parameter).
    user_agent = None
    if headers:
        for k, v in headers.items():
            if k.lower() == "user-agent":
                user_agent = v
                break
    """Pure-function evaluation of one inbound proxy request.

    Slice 1's core unit: given the HTTP request parts, parse it,
    run it through the bouncer's rule engine, and return a
    RequestObservation that captures verdict + whether it would be
    ENFORCED in the current mode.

    The forwarding layer (Slice 2) consumes this observation:
    - mode=COOPERATIVE + any verdict → always forward
    - mode=TRANSPARENT + ALLOW → forward
    - mode=TRANSPARENT + DENY → return 403 to client
    - mode=TRANSPARENT + PROMPT → block, surface to user (later)

    Side effect: writes the decision to the store's audit log just
    like `ibounce decide --record` does, so post-hoc review
    of "what was the proxy doing 10 minutes ago?" works the same
    way `tasks review` does.
    """
    parsed = parse_request(
        method=method, host=host, path=path,
        headers=headers, body=body, query=query,
    )
    if parsed is None:
        # Bouncer can't classify (no SigV4 auth header) — this is
        # not a normal AWS SDK request. Surface a synthetic deny
        # observation so the forwarding layer can refuse.
        from .decisions import Decision  # local import: small enum, avoid module-load cycle risk
        # Always Mode.ENFORCE in the decision record so the verdict
        # surfaced matches the unified "compute as if enforcing"
        # semantics in evaluate_request below. `enforced` (set in
        # _build_observation) is what tells callers whether the
        # transparent-mode 403 actually fires.
        synthetic = DecisionRecord(
            decision=Decision.DENY,
            mode=Mode.ENFORCE,
            service="",
            action="",
            arn=None,
            region=None,
            matched_rule=None,
            reason="unclassifiable request — no SigV4 auth header",
        )
        # HIGH-32-01 closure: persist the unclassifiable-deny to the
        # audit log too. Otherwise an operator running `bouncer logs
        # tail` sees nothing for traffic that the proxy refused —
        # making it harder to spot scanners / probe traffic / mis-
        # configured clients.
        try:
            store.record_decision(
                synthetic, matched_rule_id=None, task_id=None,
            )
        except Exception as e:
            logger.warning(
                "bouncer-proxy unclassifiable audit-write failed: %s", e,
            )
        # #252 Slice 1 — mirror the unclassifiable-deny to the
        # audit-export channels (if configured). Operators want to see
        # probe/scanner traffic in the audit stream as much as the
        # SQLite log, since a sudden burst of unclassifiable requests
        # is a useful signal (port-scan, mis-signed agent, etc).
        try:
            from .audit_export import audit_event_from_decision
            _emit_audit_event(audit_event_from_decision(
                decision_id=0,
                mode=mode.value,
                profile=(
                    active_profile.name if active_profile is not None else None
                ),
                verdict=synthetic.decision.value,
                reason=synthetic.reason,
                service="",
                action="",
                arn=None,
                region=None,
                host=host,
                upstream=None,
                enforced=(mode == ProxyMode.TRANSPARENT),
                user_agent=user_agent,
            ))
        except Exception as e:
            logger.warning("audit-export emit (unclassifiable) failed: %s", e)
        return _build_observation(
            method=method, host=host, path=path,
            parsed=None, record=synthetic, mode=mode,
        )

    # AWS Slice 7: profile is the HARD FLOOR. Evaluate BEFORE the
    # rule engine so a permissive task scope or global allow rule
    # CANNOT override a profile deny. Per the env-profiles spec:
    # profile keyword denies + only_account_ids + deny_verbs all
    # fire here; if a profile denies, short-circuit with
    # decision_source=profile so post-hoc audit can distinguish
    # profile-fired denies from task/global-fired denies.
    if active_profile is not None:
        from .decisions import Decision  # local import to avoid cycle
        from .profiles import evaluate_profile
        # The request_parser puts the synthesized AWS ARN on
        # `resource_hint` (not `arn`) — that's the field we feed
        # to the profile keyword check. Fall back to .arn if
        # present for forward-compat with parsers that set both.
        arn_for_profile = (
            getattr(parsed, "resource_hint", None)
            or getattr(parsed, "arn", None)
        )
        prof_verdict = evaluate_profile(
            active_profile,
            arn=arn_for_profile,
            resource_name=arn_for_profile,
            account_id=account_id,
            account_alias=account_alias,
            service=parsed.service,
            action=parsed.action,
        )
        if prof_verdict.denied:
            short_circuit = DecisionRecord(
                decision=Decision.DENY,
                mode=Mode.ENFORCE,
                service=parsed.service,
                action=parsed.action,
                arn=getattr(parsed, "arn", None),
                region=parsed.region,
                matched_rule=None,
                reason=prof_verdict.reason,
            )
            short_circuit_decision_id = 0
            try:
                short_circuit_decision_id = store.record_decision(
                    short_circuit, matched_rule_id=None, task_id=None,
                )
            except Exception as e:
                logger.warning("bouncer-proxy audit-write failed: %s", e)
            # #252 Slice 1 — mirror profile-fired denies to the
            # audit-export channels. Profile denies are the operator's
            # hard floor; security teams especially want these visible
            # in the audit stream.
            try:
                from .audit_export import audit_event_from_decision
                _emit_audit_event(audit_event_from_decision(
                    decision_id=short_circuit_decision_id,
                    mode=mode.value,
                    profile=active_profile.name,
                    verdict=short_circuit.decision.value,
                    reason=short_circuit.reason,
                    service=parsed.service,
                    action=parsed.action,
                    arn=getattr(parsed, "arn", None),
                    region=parsed.region,
                    host=host,
                    upstream=None,
                    enforced=(mode == ProxyMode.TRANSPARENT),
                    extra={"decision_source": "profile"},
                    user_agent=user_agent,
                ))
            except Exception as e:
                logger.warning("audit-export emit (profile-deny) failed: %s", e)
            return _build_observation(
                method=method, host=host, path=path,
                parsed=parsed, record=short_circuit, mode=mode,
            )

    # Compose the active ruleset (global rules + active profile's
    # allow_rules + active task scope). Profile allow_rules sit at
    # the SAME precedence as global rules — they're "global rules
    # that are gated on this profile being active." They do NOT
    # bypass profile DENY layers above (already short-circuited by
    # this point if any fired). The profile-allow rules are appended
    # AFTER the global ruleset so a global DENY beats a profile
    # ALLOW (mirrors AWS IAM explicit-deny semantics).
    # #253 — `list_active_rules` filters out time-bounded grants whose
    # expires_at has passed. Defense-in-depth alongside the 30s sweeper
    # task (the sweeper writes the audit transition events; this
    # read-time filter ensures the active RuleSet excludes expired rules
    # IMMEDIATELY at decision time without waiting for the next tick).
    id_tagged = store.list_active_rules()
    composed_rules = [r for _, r in id_tagged]
    if active_profile is not None and active_profile.allow_rules:
        from .rules import Effect, ProxyRule
        for par in active_profile.allow_rules:
            composed_rules.append(ProxyRule(
                pattern=par.pattern,
                effect=Effect.ALLOW,
                arn_scope=par.arn_scope,
                region_scope=par.region_scope,
                note=par.note or f"from profile {active_profile.name}",
                origin="profile",
            ))
    ruleset = RuleSet(rules=composed_rules)
    active_task = store.get_active_task()

    # ALWAYS compute the verdict with ENFORCE semantics. The
    # COOPERATIVE-vs-TRANSPARENT distinction lives entirely in the
    # `enforced` flag (set by _build_observation) + the forwarding
    # layer (Slice 2) consults that flag to decide whether to 403
    # the client or just log + forward.
    #
    # Why not use LEARN mode internally? LEARN auto-allows
    # everything by design — useful for the original "watch what
    # happens" workflow, but DEFEATS the cooperative-mode use
    # case where the user wants to PREVIEW what transparent mode
    # would deny without flipping the switch. With ENFORCE
    # semantics here, cooperative-mode logs show real deny verdicts
    # the user can act on; the actual forwarding still happens
    # because `enforced` is False.
    # Resolve the ARN to feed into rule-matching. The request parser
    # places synthesized AWS ARNs on `resource_hint`; only the
    # explicit-IAM API parsers set `arn`. Prefer arn when present,
    # fall back to resource_hint so global rules + profile allow_rules
    # with arn_scope can actually match against S3/EC2/DynamoDB paths.
    resolved_arn = (
        getattr(parsed, "arn", None)
        or getattr(parsed, "resource_hint", None)
    )
    record = decide(
        ruleset,
        mode=Mode.ENFORCE,
        default_policy=default_policy,
        service=parsed.service,
        action=parsed.action,
        arn=resolved_arn,
        region=parsed.region,
        active_task=active_task,
    )

    # #6a — timed bypass / "pause." If an operator-initiated pause is
    # active, the proxy demotes effective behavior to COOPERATIVE for
    # this decision: the verdict text is preserved (so audit reviewers
    # see what WOULD have been denied) but enforcement is suspended.
    # The pause_id is recorded on the audit row so reviewers can ask
    # "what calls happened inside the pause window the operator
    # opened?" with a single SQL filter.
    #
    # Safety-mode-lean-permissive: the audit trail does the work; the
    # bypass is acceptable precisely because every decision during it
    # is recorded with pause_id linkage + the pause itself is its own
    # audit row. There is intentionally no "stealth pause" — every
    # pause has start/end audit rows.
    active_pause: dict | None = None
    try:
        active_pause = store.get_active_pause()
    except Exception as e:
        # HIGH-32-05 closure: bump a counter that /healthz exposes
        # so the operator's monitor can alert on "pause is supposedly
        # active but my proxy can't see it." Without this, the proxy
        # silently enforces through a window the operator thought
        # they had opened.
        _bump_pause_lookup_error_counter()
        logger.warning("bouncer-proxy pause-lookup failed: %s", e)
    # #270 Slice 2 — observe pause-window transitions on every
    # lookup so the pause_long alert rule sees the close (auto-expiry
    # OR explicit `pause stop`). No-op when no transition occurred.
    # Keep this BEFORE the effective-mode demotion below so the
    # detection sees the same `active_pause` value the rest of the
    # function consumes.
    _observe_pause_transition(active_pause)
    effective_mode = mode
    if active_pause is not None and mode == ProxyMode.TRANSPARENT:
        effective_mode = ProxyMode.COOPERATIVE

    # Audit log every proxy decision (always; both modes).
    matched_rule_id: int | None = None
    if record.matched_rule is not None:
        for rid, r in id_tagged:
            if r == record.matched_rule:
                matched_rule_id = rid
                break
    decision_id: int = 0
    try:
        decision_id = store.record_decision(
            record,
            matched_rule_id=matched_rule_id,
            task_id=active_task.task_id if active_task is not None else None,
            pause_id=active_pause["id"] if active_pause is not None else None,
        )
    except Exception as e:
        # Audit-write failure is a high-priority signal; log it but
        # don't crash the proxy. (The opt-in-feedback pipeline can
        # report this category when enabled per opt-in-feedback-pipeline.)
        logger.warning("bouncer-proxy audit-write failed: %s", e)

    # #252 Slice 1 — mirror the decision to the audit-export channels
    # AFTER the SQLite write (so decision_id is populated) and AFTER
    # the pause-demotion logic (so `enforced` reflects the actual
    # behavior, not what would have happened without the pause).
    # Per [[scorer-is-ground-truth]]: NO LLM-derived risk scores get
    # smuggled into Slice 1 events; the scorer can flag separately.
    try:
        from .audit_export import audit_event_from_decision
        _emit_audit_event(audit_event_from_decision(
            decision_id=decision_id,
            mode=effective_mode.value,
            profile=(
                active_profile.name if active_profile is not None else None
            ),
            verdict=record.decision.value,
            reason=record.reason,
            service=parsed.service,
            action=parsed.action,
            arn=resolved_arn,
            region=parsed.region,
            host=host,
            upstream=None,
            enforced=(
                effective_mode == ProxyMode.TRANSPARENT
                and record.decision.value in ("deny", "prompt")
            ),
            active_pause_id=(
                active_pause["id"] if active_pause is not None else None
            ),
            extra={
                "matched_rule_id": matched_rule_id,
                "active_task_id": (
                    active_task.task_id if active_task is not None else None
                ),
            },
            user_agent=user_agent,
        ))
    except Exception as e:
        logger.warning("audit-export emit (decision) failed: %s", e)

    # #270 Slice 2 — admin-fallback synthetic. Fires when a request
    # would have been DENIED in transparent mode but a pause window
    # is open, so the proxy demoted it to COOPERATIVE + the call
    # proceeds. The admin_fallback_burst rule counts these in a 5-min
    # window so the operator sees "your pauses are routinely needed"
    # as a signal to ship a broader profile rather than rely on the
    # fallback. Kept here AFTER the decision-event emit so the
    # decision_id is populated + the alert event can reference it
    # via the source_decision_id linkage in the rule engine.
    if (
        active_pause is not None
        and mode == ProxyMode.TRANSPARENT
        and record.decision.value in ("deny", "prompt")
    ):
        try:
            from .audit_export import make_admin_fallback_grant_event
            # Principal identity is the pause initiator — that's the
            # operator whose decision (open the window) is being
            # exercised. Matches the kbounce sibling's actor shape.
            principal = str(active_pause.get("started_by") or "")
            _emit_audit_event(make_admin_fallback_grant_event(
                principal=principal,
                grant_id=decision_id,
                mode=mode.value,
            ))
        except Exception as e:
            logger.warning(
                "audit-export emit (admin_fallback_grant) failed: %s", e,
            )

    # #287 — burst detector observes EVERY transparent-mode DENY,
    # not just the prompt-on-deny path. Pre-fix the burst detector only
    # fired when `--prompt-on-deny` was set (its observe() lived inside
    # the add_pending_prompt branch below). That made the BURST_DETECTED
    # event invisible to operators running ibounce in plain transparent
    # mode (no prompt-on-deny flag), which is the default for the
    # safety-mode-lean-permissive deployment shape. Per
    # [[scorer-is-ground-truth]] the user-facing intent of "burst = lots
    # of denies" must hold REGARDLESS of which prompt-flag the operator
    # picked.
    if (
        decision_id > 0
        and mode == ProxyMode.TRANSPARENT
        and record.decision.value == "deny"
        and active_pause is None  # pauses already bypass enforcement
    ):
        try:
            from .burst import active_burst_detector
            _detector = active_burst_detector()
            if _detector is not None:
                _detector.observe()
        except Exception as e:
            logger.warning("bouncer-proxy burst-detector observe failed: %s", e)

    # #5 v1.0 (async): if operator opted into prompt-on-deny AND
    # this was a transparent-mode DENY (the only mode where DENY
    # actually blocks the agent), enqueue a pending prompt so the
    # operator can later answer (always-allow / add-to-profile /
    # ignore) via `bouncer prompts`. The agent has already been
    # denied; the answer takes effect on the NEXT call of the same
    # shape. v1.1 will add a synchronous flow.
    if (
        prompt_on_deny
        and decision_id > 0
        and mode == ProxyMode.TRANSPARENT
        and record.decision.value == "deny"
        and active_pause is None  # pauses already bypass enforcement
    ):
        try:
            store.add_pending_prompt(
                decision_id=decision_id,
                service=parsed.service,
                action=parsed.action,
                arn=resolved_arn,
                region=parsed.region,
                deny_reason=record.reason,
            )
        except Exception as e:
            logger.warning("bouncer-proxy prompt-enqueue failed: %s", e)

    return _build_observation(
        method=method, host=host, path=path,
        parsed=parsed, record=record, mode=effective_mode,
        decision_id=decision_id,
        active_pause_id=active_pause["id"] if active_pause is not None else None,
    )


# ---------------------------------------------------------------------------
# aiohttp server (Slice 1: observability-only; Slice 2 adds forwarding)
# ---------------------------------------------------------------------------


class UpstreamUrlError(ValueError):
    """#300 — raised when the operator's --upstream URL can't be
    parsed into a scheme + host:port. The CLI catches + surfaces
    this to the operator at startup so a misconfigured upstream
    fails fast (before any agent traffic lands)."""


def parse_upstream_url(url: str) -> tuple[str, str]:
    """#300 — parse an operator-supplied upstream URL into
    (scheme, host_with_optional_port).

    Validates:
      - URL is non-empty
      - Scheme is one of {http, https} (rejects ftp://, file://,
        bare hostnames without a scheme, etc.)
      - Host component is non-empty

    Returns a tuple ready to plug into ProxyConfig.forward_scheme +
    ProxyConfig.forward_host_override. Raises UpstreamUrlError with
    a human-readable message on any validation failure — the CLI
    surfaces this verbatim so the operator fixes the flag once.

    Examples:
      parse_upstream_url("http://127.0.0.1:4566")  -> ("http", "127.0.0.1:4566")
      parse_upstream_url("https://api.example.com") -> ("https", "api.example.com")
      parse_upstream_url("ftp://invalid")           -> UpstreamUrlError
      parse_upstream_url("127.0.0.1:4566")          -> UpstreamUrlError (no scheme)
    """
    if not url or not isinstance(url, str):
        raise UpstreamUrlError(
            "upstream URL is empty; pass a URL like "
            "'http://127.0.0.1:4566' (LocalStack) or "
            "'https://s3.us-east-1.amazonaws.com'."
        )
    from urllib.parse import urlparse
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        # Cover both the no-scheme case (urlparse stuffs the whole
        # thing into `.path` when there's no `://`) and the wrong-
        # scheme case (ftp, file, ws, etc.).
        if not scheme:
            raise UpstreamUrlError(
                f"upstream URL {url!r} has no scheme; expected "
                f"'http://...' or 'https://...'. Refusing to default "
                f"to https because the operator likely meant http (the "
                f"common LocalStack mistake). #300."
            )
        raise UpstreamUrlError(
            f"upstream URL {url!r} has unsupported scheme {scheme!r}; "
            f"ibounce only forwards http or https. #300."
        )
    # urlparse handles `host:port` correctly inside netloc.
    if not parsed.netloc:
        raise UpstreamUrlError(
            f"upstream URL {url!r} has no host; expected something "
            f"like 'http://127.0.0.1:4566' (host:port required)."
        )
    return scheme, parsed.netloc


def _forward_url(host: str, path_qs: str, scheme: str = "https") -> str:
    """Build the outbound URL for forwarding.

    The client's SigV4 signature is over the ORIGINAL AWS Host header
    (e.g. `s3.us-east-1.amazonaws.com`). The client connects to the
    proxy at 127.0.0.1:PORT but signed with the AWS host. We forward
    to the AWS host so the signature validates downstream.

    `scheme` defaults to https because real AWS endpoints are HTTPS.
    Tests can pass scheme="http" to forward to a local mock-AWS.
    """
    # `host` may already include `:port`; preserve as-is.
    return f"{scheme}://{host}{path_qs}"


# CRIT-32-01 closure: outbound Host allowlist. The proxy receives
# its destination from the inbound Host header, which is attacker-
# controllable. Without this check, a compromised agent can set
# Host: attacker.example.com on its proxy connection and the proxy
# faithfully forwards the SigV4-signed body + AccessKeyId there.
# That makes the bouncer an exfil channel — the inverse of its
# promise.
#
# Allowlist strategy: accept the canonical AWS endpoint TLDs (cover
# commercial + GovCloud + China + .dev). Extra hosts can be added
# via IAM_JIT_BOUNCER_EXTRA_HOSTS (comma-separated suffix list) for
# LocalStack, tests, or special-purpose deployments. Test code
# passes `localhost` / `127.0.0.1:PORT` for the mock-AWS server;
# those match via the loopback exception below.
_AWS_HOST_SUFFIXES = (
    ".amazonaws.com",        # commercial AWS
    ".amazonaws.com.cn",     # AWS China
    ".amazonaws.us",         # AWS GovCloud
    ".api.aws",              # newer service domains
    ".aws.dev",              # AWS developer / preview domains
)


def _is_allowed_forward_host(host: str) -> bool:
    """True iff `host` is an AWS endpoint (or test loopback, or in
    the operator's IAM_JIT_BOUNCER_EXTRA_HOSTS allowlist).

    Strips an optional `:port` suffix; the comparison is on the
    bare DNS host. Case-insensitive (AWS endpoints are lowercase
    canonically but the SigV4 signature is normalized; some
    legitimate clients send mixed-case hosts).
    """
    if not host:
        return False
    bare = host.split(":", 1)[0].lower().rstrip(".")
    if not bare:
        return False
    # Loopback exception — tests + LocalStack default deploy use this
    if bare in ("127.0.0.1", "localhost", "::1"):
        return True
    if bare.startswith("127.") and bare.replace(".", "").isdigit():
        return True
    # AWS canonical TLDs
    for suffix in _AWS_HOST_SUFFIXES:
        if bare.endswith(suffix):
            return True
    # Operator-supplied extras (comma-separated suffix list)
    extras_env = os.environ.get("IAM_JIT_BOUNCER_EXTRA_HOSTS", "")
    for raw_suffix in extras_env.split(","):
        suffix = raw_suffix.strip().lower().lstrip(".")
        if not suffix:
            continue
        # Compare with leading dot so "evil.example.com" doesn't slip
        # past a "vil.example.com" allowlist entry by mistake.
        suffix_with_dot = "." + suffix
        if bare == suffix or bare.endswith(suffix_with_dot):
            return True
    return False


_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
})


def _strip_hop_headers(headers):
    """Remove RFC 7230 hop-by-hop headers + headers the upstream
    library will recompute. Returns a NEW container of the same
    shape (dict-in → dict-out, list-of-tuples-in → list-of-tuples-out).
    Doesn't mutate input.

    HIGH-32-04 (multi-value headers): callers should prefer the
    list-of-tuples form so duplicate header keys round-trip. The
    dict form is kept for backward compatibility with existing
    Slice 2 tests + tools.

    Hop-by-hop headers (RFC 7230 §6.1) must not be forwarded. The
    Host header is preserved because the client signed against it.
    Content-Length is dropped because aiohttp recomputes it from
    the body bytes.
    """
    if isinstance(headers, dict):
        return {
            k: v for k, v in headers.items()
            if k.lower() not in _HOP_HEADERS
        }
    # list-of-tuples / CIMultiDict.items() / other iterable
    return [
        (k, v) for (k, v) in headers
        if k.lower() not in _HOP_HEADERS
    ]


async def _forward_to_aws(
    *,
    method: str,
    host: str,
    path_qs: str,
    headers: dict[str, str],
    body: bytes,
    forward_scheme: str = "https",
    session,  # aiohttp.ClientSession
    timeout_s: float = 30.0,
):
    """Forward a SigV4-signed request to the real AWS endpoint and
    return (status, response_headers, response_body_bytes).

    LOAD-BEARING invariants:
    - Authorization header (SigV4 signature) is forwarded verbatim.
    - Host header is preserved.
    - Body bytes are forwarded as-is.
    - Hop-by-hop headers are stripped per RFC 7230.
    - Outbound scheme is HTTPS by default; tests override with HTTP.
    - The proxy NEVER re-signs the request. We don't have the
      client's secret key + don't want it.

    Returns response data tuple. Slice 2 reads the full response
    into memory; Slice 5 will add streaming for large objects.
    """
    import aiohttp

    forward_headers = _strip_hop_headers(headers)
    url = _forward_url(host, path_qs, scheme=forward_scheme)

    timeout = aiohttp.ClientTimeout(total=timeout_s)
    async with session.request(
        method=method,
        url=url,
        headers=forward_headers,
        data=body,
        timeout=timeout,
        allow_redirects=False,
        # Don't auto-decompress; client expects raw bytes.
        auto_decompress=False,
    ) as resp:
        resp_body = await resp.read()
        resp_headers = dict(resp.headers)
    return resp.status, resp_headers, resp_body


async def _plan_capture_response(
    *,
    request,
    body: bytes,
    obs: RequestObservation,
    store: BouncerStore,
    config: ProxyConfig,
):
    """Build + return a synthetic SDK-shaped response and persist a
    plan_calls row. Called from `_handle_request` when
    `config.mode == ProxyMode.PLAN_CAPTURE`. Never forwards anything.

    #145 layer: this is also where the read->write switch UX fires.
    Every plan-capture call is classified read/write via the policy_
    sentry-backed classifier; the FIRST write in a session transitions
    the session's phase per --write-switch-notify
    (manual → write_pending + prompt; auto-approve → writes_approved
    silently; reject → writes_rejected). Once the session is in
    writes_rejected, subsequent writes get a PlanCaptureWritesRejected
    synthetic error instead of a success synthetic. The
    creates-never-mutates invariant is unchanged: NOTHING reaches AWS
    in any phase.

    Two failure modes are surfaced inline (not raised) so the proxy
    stays alive under malformed inbound traffic:
      - Unclassifiable request (no SigV4) → unsupported-op error
        for service='' action='' so the operator sees the entry in
        the transcript instead of a silent drop.
      - Op not in the synthetics registry → SDK-shaped 400 with
        `PlanCaptureUnsupportedOperation` so the operator knows to
        switch modes if they need the call to execute.
    """
    from aiohttp import web

    from .plan_capture import (
        PlanCaptureSynthetic,
        UNSUPPORTED_OP_SHAPE,
        build_writes_rejected_response,
        classify_action,
        current_session_id,
        synthesize_response,
    )

    # Session-id resolution order:
    #   1. ProxyConfig.plan_session_id (operator's --plan-session-id flag)
    #   2. plan_capture.current_session_id() (the in-process slot the
    #      `serve()` entry installed at startup)
    #   3. literal "plan-default" — only hit when a caller invokes the
    #      handler outside the serve() lifecycle (e.g. unit tests
    #      poking _handle_request directly). The synthesizers don't
    #      care about the value beyond it being a stable key.
    session_id = (
        config.plan_session_id
        or current_session_id()
        or "plan-default"
    )
    # Lazy-ensure the session row exists. ensure_plan_session is
    # idempotent so we don't need to track whether `serve()` already
    # created it.
    try:
        store.ensure_plan_session(
            session_id=session_id,
            started_by=os.environ.get("USER", "local"),
            note="auto-created by plan-capture proxy",
        )
    except Exception as e:
        # An audit-store write failure is high-priority but we don't
        # crash the proxy — same posture as decisions.record_decision
        # in evaluate_request above. Log + carry on with the synthesis;
        # the operator notices the missing transcript and investigates.
        logger.warning("plan-capture ensure_session failed: %s", e)

    # Pin the notify mode for this session if not already set. Idempotent
    # via the UPDATE — we don't track whether `serve()` set it first.
    # Catch errors so a transient DB blip doesn't drop the call; the
    # phase logic below will fall through to the default ('manual')
    # via get_plan_session_phase()'s defaulting.
    try:
        store.set_plan_session_write_switch_notify(
            session_id, config.plan_write_switch_notify,
        )
    except (ValueError, Exception) as e:
        logger.warning("plan-capture set_write_switch_notify failed: %s", e)

    service = obs.parsed_service or ""
    action = obs.parsed_action or ""
    host_header = request.headers.get("host", "")

    # #145 — phase resolution + transition. Done BEFORE building the
    # synthetic response so the writes_rejected branch can swap in the
    # rejection synthetic. classify_action is policy_sentry-backed
    # (Read/List → 'read'; Write/Tagging/Permissions-management →
    # 'write'); unknown actions classify as 'unknown' which we treat
    # as write per the conservative-default policy in is_write().
    action_class = classify_action(service, action) if (service and action) else "unknown"
    is_write_call = action_class != "read"  # unknown counts as write
    # Read current phase (or default for fresh sessions).
    try:
        phase_row = store.get_plan_session_phase(session_id)
    except Exception as e:
        logger.warning("plan-capture get_plan_session_phase failed: %s", e)
        phase_row = None
    current_phase = (phase_row or {}).get("phase", "read_only")
    effective_notify = (
        (phase_row or {}).get("write_switch_notify")
        or config.plan_write_switch_notify
        or "manual"
    )
    # Default: build the registered synthetic. Overridden below for the
    # writes-rejected branch (subsequent writes in a rejected session).
    synth: PlanCaptureSynthetic = synthesize_response(
        service=service,
        action=action,
        host=host_header,
        path=request.path_qs,
        body=body,
        query=dict(request.query),
    )
    # Phase machine — only writes drive transitions; reads NEVER move
    # the phase forward. The state diagram:
    #
    #   read_only  --write+manual-->       write_pending
    #   read_only  --write+auto-approve--> writes_approved
    #   read_only  --write+reject-->       writes_rejected
    #   write_pending   --write-->         write_pending  (stays)
    #   writes_approved --write-->         writes_approved (stays)
    #   writes_rejected --write-->         writes_rejected (subsequent writes
    #                                       get the rejection synthetic)
    if is_write_call and service and action:
        if current_phase == "read_only":
            if effective_notify == "auto-approve":
                try:
                    store.transition_plan_session_phase(
                        session_id,
                        new_phase="writes_approved",
                        decision="approve",
                        decided_by="auto-approve",
                        first_write_at=obs.at,
                    )
                except Exception as e:
                    logger.warning(
                        "plan-capture phase-transition (auto-approve) failed: %s", e,
                    )
            elif effective_notify == "reject":
                try:
                    store.transition_plan_session_phase(
                        session_id,
                        new_phase="writes_rejected",
                        decision="reject",
                        decided_by="auto-reject",
                        first_write_at=obs.at,
                    )
                except Exception as e:
                    logger.warning(
                        "plan-capture phase-transition (reject) failed: %s", e,
                    )
                # Swap to the rejection synthetic so the SDK surfaces a
                # typed PlanCaptureWritesRejected error.
                synth = build_writes_rejected_response(
                    service=service, action=action,
                )
            else:  # manual
                try:
                    store.transition_plan_session_phase(
                        session_id,
                        new_phase="write_pending",
                        first_write_at=obs.at,
                    )
                except Exception as e:
                    logger.warning(
                        "plan-capture phase-transition (write_pending) failed: %s", e,
                    )
                try:
                    store.add_plan_write_prompt(
                        session_id=session_id,
                        service=service,
                        action=action,
                        arn=obs.parsed_arn,
                        region=obs.parsed_region,
                    )
                except Exception as e:
                    logger.warning(
                        "plan-capture add_plan_write_prompt failed: %s", e,
                    )
        elif current_phase == "writes_rejected":
            # Subsequent writes in a rejected session get the rejection
            # synthetic; we don't re-prompt or re-transition.
            synth = build_writes_rejected_response(
                service=service, action=action,
            )

    supported = (
        synth.would_have_returned.get("kind") not in (
            UNSUPPORTED_OP_SHAPE, "writes_rejected",
        )
        and bool(service) and bool(action)
    )
    # Verdict on the plan-call row reflects what happened. We distinguish
    # 'writes_rejected' from 'unsupported' on the row so post-hoc readers
    # can see "the operator rejected" vs "the synthetic registry had no
    # shape." The existing 4-value verdict enum (allow/deny/prompt/
    # unsupported) gains 'writes_rejected' here without a schema change
    # (the column is plain TEXT).
    if synth.would_have_returned.get("kind") == "writes_rejected":
        verdict = "writes_rejected"
    elif supported:
        verdict = obs.decision_verdict
    else:
        verdict = "unsupported"
    would_have_called = (
        f"{service}:{action}" if (service or action) else "unknown:unknown"
    )
    try:
        store.record_plan_call(
            session_id=session_id,
            method=request.method,
            host=host_header,
            path=request.path_qs,
            service=service,
            action=action,
            region=obs.parsed_region,
            arn=obs.parsed_arn,
            verdict=verdict,
            would_have_called=would_have_called,
            would_have_returned=synth.would_have_returned,
            supported=supported,
        )
    except Exception as e:
        logger.warning("plan-capture record_plan_call failed: %s", e)

    # Always tag the synthetic response with bouncer headers so an
    # operator running curl / mitmproxy / a debug client can tell
    # this came from plan-capture, never AWS. Matches the existing
    # x-iam-jit-bouncer-* surface used in transparent + cooperative.
    out_headers = dict(synth.headers)
    out_headers["x-iam-jit-bouncer-mode"] = ProxyMode.PLAN_CAPTURE.value
    out_headers["x-iam-jit-bouncer-verdict"] = verdict
    out_headers["x-iam-jit-bouncer-plan-session"] = session_id
    # #145 — surface the phase so operators sniffing wire traffic can
    # tell at a glance which side of the read->write switch each call
    # landed on. Re-read after the transition so the header reflects
    # the POST-transition phase, not the value we read pre-transition.
    try:
        post_row = store.get_plan_session_phase(session_id)
        out_headers["x-iam-jit-bouncer-plan-phase"] = (
            (post_row or {}).get("phase") or "read_only"
        )
    except Exception:
        out_headers["x-iam-jit-bouncer-plan-phase"] = "read_only"
    return web.Response(body=synth.body, status=synth.status, headers=out_headers)


# #250 — cross-process poll cadence (seconds). The proxy races the
# in-process asyncio.Event against a DB poll on this interval so that
# answers from a DIFFERENT process (the typical `ibounce serve` +
# `ibounce prompts answer` operator workflow, where the two run in
# different Python processes + thus different in-process registries)
# still wake the blocked request. Operator-perceived latency on the
# cross-process path is bounded by this cadence. 200ms is the same
# value dbounce shipped in d82ded9 — small enough to feel instant on
# a human-in-the-loop answer, large enough that a long
# --sync-prompt-timeout (the 300s ceiling) costs ~1500 SELECTs total
# on the indexed sync_wait_id column (sub-millisecond each).
_SYNC_PROMPT_POLL_INTERVAL_SECONDS = 0.2


def _answer_to_decision(row: dict) -> str:
    """Map a pending_prompts row's answer fields to a sync decision.

    The CLI `prompts answer` path persists `answer_kind` ∈
    {always, profile, ignore} on the row. The proxy's sync path needs
    a binary 'allow' | 'deny'. Mirrors the mapping in `bouncer_cli`
    (kind=always|profile -> allow forwards to upstream; kind=ignore
    -> deny returns the original 403).

    Returns 'deny' as the safe fallback for any unrecognized /
    missing kind, so a malformed row never lets a denied request
    silently forward.
    """
    kind = row.get("answer_kind")
    if kind in ("always", "profile"):
        return "allow"
    return "deny"


async def _await_sync_deny_decision(
    *, obs: RequestObservation, store: BouncerStore, config: ProxyConfig,
) -> str:
    """#203 + #250 — enqueue a sync pending-prompt row, register an
    asyncio.Event, and block until either the operator answers via
    `ibounce prompts answer` (in-process Event wake OR cross-process
    DB-status change) or `sync_prompt_timeout_seconds` elapses.

    Cross-process semantics (#250): the in-process registry only sees
    wakes from the SAME Python process. The typical operator workflow
    runs `ibounce serve` and `ibounce prompts answer` in DIFFERENT
    terminals + thus different processes; without a fallback the
    answerer's wake fires into a registry the proxy can't see, and
    the proxy blocks until --sync-prompt-default fires. We race the
    in-process Event against a 200ms-cadence DB poll on the
    pending_prompts.sync_wait_id row; either wins, whichever fires
    first. Operator-perceived latency on the cross-process path is
    ≤200ms after their answer commits. Mirrors dbounce d82ded9.

    Returns 'allow' or 'deny' — never raises. On timeout, returns
    `config.sync_prompt_default_decision`. On enqueue/registration
    failure (e.g. DB busy), returns 'deny' (fail-closed) + logs;
    the operator sees nothing in their queue, the agent sees the
    original 403, and the operator's monitor (via /healthz audit-
    write counter) flags the underlying DB problem.

    The slot is unregistered in a `finally` so a timed-out wait
    doesn't leak a dict entry forever.

    Per [[ibounce-honest-positioning]]: this is a DETERRENT UX,
    not a security boundary. Per [[creates-never-mutates]]:
    nothing AWS-side is mutated by this path — we only block the
    proxy + (on allow) forward verbatim.
    """
    try:
        prompt_id, sync_wait_id = store.add_sync_pending_prompt(
            decision_id=obs.decision_id,
            service=obs.parsed_service or "",
            action=obs.parsed_action or "",
            arn=obs.parsed_arn,
            region=obs.parsed_region,
            deny_reason=obs.decision_reason,
        )
        # #253 — feed the burst detector for sync deny-prompts too.
        # Same shape as the async branch in evaluate_request; a wall of
        # sync denies + an absent operator is the worst-case
        # block-happy experience and the burst hint should fire just as
        # eagerly.
        from .burst import active_burst_detector
        _detector = active_burst_detector()
        if _detector is not None:
            _detector.observe()
    except Exception as e:
        logger.warning(
            "bouncer-proxy sync-deny-prompt enqueue failed: %s "
            "(falling back to original 403)", e,
        )
        return "deny"
    slot = register_sync_wait(sync_wait_id)
    logger.info(
        "ibounce sync-deny-prompt #%d enqueued (sync_wait_id=%s, "
        "timeout=%ds, default=%s); waiting for operator answer",
        prompt_id, sync_wait_id, config.sync_prompt_timeout_seconds,
        config.sync_prompt_default_decision,
    )
    try:
        timeout_seconds = float(config.sync_prompt_timeout_seconds)
        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # Wall-clock timeout — fall through to default below.
                break
            wait_for = min(_SYNC_PROMPT_POLL_INTERVAL_SECONDS, remaining)
            try:
                await asyncio.wait_for(slot.event.wait(), timeout=wait_for)
            except asyncio.TimeoutError:
                # No in-process wake this tick; check the DB for a
                # cross-process answer. Any exception from the store
                # (rare; SQLite is in-process) is logged + treated as
                # "no answer yet" so the poll loop keeps running until
                # the wall-clock timeout fires.
                try:
                    row = store.get_pending_prompt_by_sync_wait_id(
                        sync_wait_id,
                    )
                except Exception as e:
                    logger.warning(
                        "ibounce sync-deny-prompt #%d poll lookup "
                        "failed: %s (continuing to wait)", prompt_id, e,
                    )
                    row = None
                if row is not None and row.get("status") == "answered":
                    decision = _answer_to_decision(row)
                    logger.info(
                        "ibounce sync-deny-prompt #%d answered "
                        "cross-process by %s (kind=%s) -> %s",
                        prompt_id, row.get("answered_by") or "unknown",
                        row.get("answer_kind") or "unknown", decision,
                    )
                    return decision
                # Otherwise keep looping until either the in-process
                # Event fires OR the wall-clock deadline elapses.
                continue
            # In-process Event fired — same-process wake path.
            decision = slot.decision or "deny"
            logger.info(
                "ibounce sync-deny-prompt #%d answered by %s "
                "(kind=%s) -> %s",
                prompt_id, slot.answered_by or "unknown",
                slot.answer_kind or "unknown", decision,
            )
            return decision if decision in ("allow", "deny") else "deny"
        # Wall-clock timeout reached.
        decision = config.sync_prompt_default_decision
        logger.info(
            "ibounce sync-deny-prompt #%d timed out after %ds; "
            "applying default=%s",
            prompt_id, config.sync_prompt_timeout_seconds, decision,
        )
        return decision if decision in ("allow", "deny") else "deny"
    finally:
        unregister_sync_wait(sync_wait_id)


async def _forward_after_sync_allow(
    *, request, body: bytes, obs: RequestObservation,
    config: ProxyConfig, session,
):
    """Forward to upstream + return upstream's actual response, after
    a sync deny-prompt was answered ALLOW (or timed out with
    --sync-prompt-default=allow). Mirrors the ALLOW branch of
    `_handle_request` but tags the response with an extra
    `x-iam-jit-bouncer-sync` header so wire-debug shows the
    sync-allow provenance.

    Reuses `_is_allowed_forward_host` for the CRIT-32-01 outbound
    host allowlist — operator approval does NOT bypass the
    exfil-protection check. An ALLOW answer means "let this
    SigV4-signed request reach the AWS endpoint the client signed
    for"; it does NOT mean "forward anywhere the inbound Host header
    points."
    """
    from aiohttp import web

    host_header = request.headers.get("host", "")
    if not host_header:
        return web.json_response(
            {
                "error": "ibounce cannot forward sync-allowed request",
                "decision_reason": (
                    "sync deny-prompt answered allow but inbound Host "
                    "header is missing; can't determine AWS endpoint to "
                    "forward to."
                ),
            },
            status=400,
            headers={
                "x-iam-jit-bouncer-verdict": "allow",
                "x-iam-jit-bouncer-sync": "allow",
            },
        )
    if not _is_allowed_forward_host(host_header):
        logger.warning(
            "ibounce sync-allow refused forward to non-AWS host %r "
            "(service=%s action=%s)",
            host_header, obs.parsed_service, obs.parsed_action,
        )
        return web.json_response(
            {
                "error": "ibounce DENY (forward-host-mismatch)",
                "decision_reason": (
                    f"refused to forward to {host_header!r}: not an AWS "
                    f"endpoint. CRIT-32-01 protection still applies even "
                    f"to sync-allowed requests."
                ),
                "service": obs.parsed_service,
                "action": obs.parsed_action,
                "attempted_host": host_header,
            },
            status=403,
            headers={
                "x-iam-jit-bouncer-verdict": "deny",
                "x-iam-jit-bouncer-sync": "allow",
                "x-iam-jit-bouncer-refusal": "forward-host-mismatch",
            },
        )
    # #300 — operator-supplied upstream host override (e.g.
    # `--upstream http://127.0.0.1:4566` for LocalStack). When unset,
    # forward to the SigV4-signed Host header (real-AWS behaviour).
    forward_target_host = config.forward_host_override or host_header
    try:
        status, resp_headers, resp_body = await _forward_to_aws(
            method=request.method,
            host=forward_target_host,
            path_qs=request.path_qs,
            headers=list(request.headers.items()),
            body=body,
            forward_scheme=config.forward_scheme,
            session=session,
        )
    except Exception as e:
        logger.warning("ibounce sync-allow forward failed: %s", e)
        return web.json_response(
            {
                "error": "ibounce forward to AWS failed",
                "upstream_error": str(e),
                "service": obs.parsed_service,
                "action": obs.parsed_action,
            },
            status=502,
            headers={
                "x-iam-jit-bouncer-verdict": obs.decision_verdict,
                "x-iam-jit-bouncer-sync": "allow",
                "x-iam-jit-bouncer-forward-error": "true",
            },
        )
    out_headers = _strip_hop_headers(resp_headers)
    out_headers["x-iam-jit-bouncer-verdict"] = obs.decision_verdict
    out_headers["x-iam-jit-bouncer-mode"] = obs.mode_at_decision
    # Distinguish sync-allow from the cooperative-advisory "would-deny-
    # in-transparent" header. Both can appear on a forwarded response;
    # they carry different operator intent.
    out_headers["x-iam-jit-bouncer-sync"] = "allow"
    return web.Response(body=resp_body, status=status, headers=out_headers)


async def _handle_request(request, *, store, config: ProxyConfig, session):
    """aiohttp handler for inbound proxy requests.

    Slice 2 behavior:
      ALLOW (cooperative or transparent) → forward to AWS, return
        the AWS response verbatim
      DENY + TRANSPARENT → return 403 with iam-jit reason, no forward
      DENY + COOPERATIVE → forward anyway (advisory verdict logged,
        no enforcement at the wire)
      PROMPT (any mode) → Slice 2 treats as DENY for now; Slice 3
        will add interactive prompt UX

    #132 plan-capture behavior:
      ANY verdict + PLAN_CAPTURE → never forward; return a synthetic
        SDK-shaped success (or unsupported-op error if the registry
        doesn't know the op). The verdict the bouncer would have
        assigned in transparent mode is recorded on the plan-call
        row so the operator's transcript shows what would have been
        blocked, alongside what the agent would have done.
    """
    from aiohttp import web

    body = await request.read()
    # #253 — let an in-process profile override (installed by
    # `prompts bulk-answer` option 1) supersede the startup profile so
    # a hot-swap takes effect on the very next decision.
    effective_profile = (
        active_profile_override()
        if active_profile_override() is not None
        else config.active_profile
    )
    obs = evaluate_request(
        method=request.method,
        host=request.headers.get("host", ""),
        path=request.path_qs,
        headers=dict(request.headers),
        body=body,
        query=dict(request.query),
        store=store,
        mode=config.mode,
        default_policy=config.default_policy,
        active_profile=effective_profile,
        account_id=config.account_id,
        account_alias=config.account_alias,
        prompt_on_deny=config.prompt_on_deny,
    )

    # #132 plan-capture short-circuit. Runs BEFORE the obs.enforced
    # 403 branch + BEFORE the forwarding allowlist, since
    # plan-capture's load-bearing invariant is "never forward." Per
    # [[creates-never-mutates]]: synthetic responses never reach AWS.
    # Per [[scorer-is-ground-truth]]: we keep the bouncer's verdict
    # (allow/deny/prompt) on the plan-call row even though no 403
    # is returned, so the operator sees what would have been blocked.
    if config.mode == ProxyMode.PLAN_CAPTURE:
        return await _plan_capture_response(
            request=request, body=body, obs=obs,
            store=store, config=config,
        )

    if obs.enforced:
        # #203 — synchronous deny-prompt path. Only fires when:
        #   - operator opted in via --sync-prompt-on-deny
        #   - decision is a TRANSPARENT-mode DENY (the only case where
        #     blocking actually changes anything; cooperative DENYs
        #     don't 403 anyway, plan-capture short-circuits earlier,
        #     and pauses already demoted to cooperative above so
        #     obs.enforced would be False here)
        #   - no pause is active (defense-in-depth — the
        #     pause-supersedes check already demoted effective_mode in
        #     evaluate_request; this is the second gate)
        #   - the request was classified enough to have a decision_id
        #     (unclassifiable denies skip the sync path; they always
        #     return the original 403 because there's no shape to
        #     act on)
        # Verdict shapes: 'deny' triggers; 'prompt' does NOT (prompt is
        # a future Slice 3 concept; sync deny-prompt is verdict=deny only).
        if (
            config.sync_prompt_on_deny
            and obs.decision_verdict == "deny"
            and obs.active_pause_id is None
            and obs.decision_id > 0
            and obs.parsed_service
            and obs.parsed_action
        ):
            sync_decision = await _await_sync_deny_decision(
                obs=obs, store=store, config=config,
            )
            if sync_decision == "allow":
                # Operator answered allow (or default=allow on timeout).
                # Fall through to the forwarding path below by setting
                # a sentinel + breaking out of the if-block — we use
                # a function-local flag instead of restructuring the
                # whole handler. The forwarding allowlist + the
                # _forward_to_aws call execute as normal; the response
                # surfaces an additional x-iam-jit-bouncer-sync header.
                return await _forward_after_sync_allow(
                    request=request, body=body, obs=obs,
                    config=config, session=session,
                )
            # Otherwise fall through to the original 403 below.
        # Transparent + (deny or prompt) → 403 without forwarding.
        # Body is ibounce-shaped JSON the SDK client won't parse as
        # an AWS error — that's intentional; the SDK will surface
        # the unparseable response as a client error. Slice 3 will
        # add an AWS-error-shaped body so SDK clients see a clean
        # AccessDenied with the iam-jit reason.
        return web.json_response(
            {
                "error": "ibounce DENY",
                "decision_verdict": obs.decision_verdict,
                "decision_reason": obs.decision_reason,
                "service": obs.parsed_service,
                "action": obs.parsed_action,
                "arn": obs.parsed_arn,
                "mode": obs.mode_at_decision,
            },
            status=403,
            # Wire-protocol response headers retain the
            # `x-iam-jit-bouncer-*` prefix for v1.0 to keep agents +
            # tooling that grep on them working unchanged. Renamed in
            # v1.1 alongside the env-var alignment pass.
            headers={"x-iam-jit-bouncer-verdict": obs.decision_verdict},
        )

    # Unclassifiable + cooperative mode is a tricky case — we can't
    # forward because we don't know where to forward to (no SigV4
    # host header to trust). Return 400.
    host_header = request.headers.get("host", "")
    if not obs.parsed_service or not host_header:
        return web.json_response(
            {
                "error": "ibounce cannot forward unclassifiable request",
                "decision_reason": obs.decision_reason,
                "hint": (
                    "request has no SigV4 Authorization header or no Host header; "
                    "the proxy can't determine the AWS endpoint to forward to."
                ),
            },
            status=400,
            headers={"x-iam-jit-bouncer-verdict": obs.decision_verdict},
        )

    # CRIT-32-01 closure: outbound Host allowlist. The Host header is
    # attacker-controllable; without this check, a compromised agent
    # can point the proxy at attacker.example.com and exfil the
    # SigV4-signed body + AccessKeyId.
    if not _is_allowed_forward_host(host_header):
        logger.warning(
            "ibounce refused forward to non-AWS host %r "
            "(service=%s action=%s)",
            host_header, obs.parsed_service, obs.parsed_action,
        )
        return web.json_response(
            {
                "error": "ibounce DENY (forward-host-mismatch)",
                "decision_reason": (
                    f"refused to forward to {host_header!r}: not an AWS "
                    f"endpoint. CRIT-32-01 protection. Set "
                    f"IAM_JIT_BOUNCER_EXTRA_HOSTS for legitimate non-AWS "
                    f"targets (LocalStack etc)."
                ),
                "service": obs.parsed_service,
                "action": obs.parsed_action,
                "attempted_host": host_header,
            },
            status=403,
            headers={
                "x-iam-jit-bouncer-verdict": "deny",
                "x-iam-jit-bouncer-refusal": "forward-host-mismatch",
            },
        )

    # ALLOW (either mode) OR cooperative+DENY → forward to AWS
    # HIGH-32-04 closure: aiohttp's request.headers is a CIMultiDict;
    # converting via dict() collapses duplicate keys to the last
    # value, which can break legitimate clients sending multi-value
    # headers (e.g. multiple `Forwarded:` headers via a proxy chain).
    # Pass as list-of-tuples instead so multi-values round-trip.
    # #300 — operator-supplied upstream host override (e.g.
    # `--upstream http://127.0.0.1:4566` for LocalStack). When unset,
    # forward to the SigV4-signed Host header (real-AWS behaviour).
    forward_target_host = config.forward_host_override or host_header
    try:
        status, resp_headers, resp_body = await _forward_to_aws(
            method=request.method,
            host=forward_target_host,
            path_qs=request.path_qs,
            headers=list(request.headers.items()),
            body=body,
            forward_scheme=config.forward_scheme,
            session=session,
        )
    except Exception as e:
        # Forward failed (timeout, DNS, TLS, etc). Return 502 with
        # ibounce-shaped explanation.
        logger.warning("ibounce forward failed: %s", e)
        return web.json_response(
            {
                "error": "ibounce forward to AWS failed",
                "upstream_error": str(e),
                "service": obs.parsed_service,
                "action": obs.parsed_action,
            },
            status=502,
            headers={
                "x-iam-jit-bouncer-verdict": obs.decision_verdict,
                "x-iam-jit-bouncer-forward-error": "true",
            },
        )

    # Strip hop-by-hop from the AWS response too (RFC 7230) +
    # surface the bouncer's verdict in a debug header so users
    # debugging can see what the bouncer decided.
    out_headers = _strip_hop_headers(resp_headers)
    out_headers["x-iam-jit-bouncer-verdict"] = obs.decision_verdict
    out_headers["x-iam-jit-bouncer-mode"] = obs.mode_at_decision
    if obs.decision_verdict == "deny" and not obs.enforced:
        # Cooperative-mode advisory: surface that the bouncer WOULD
        # have denied this call in transparent mode.
        out_headers["x-iam-jit-bouncer-advisory"] = "would-deny-in-transparent"

    return web.Response(body=resp_body, status=status, headers=out_headers)


async def serve(config: ProxyConfig, *, store: BouncerStore) -> None:
    """Run the proxy server until cancelled.

    Slices 1 + 2: aiohttp app with one catch-all handler. The
    handler now FORWARDS allowed requests to real AWS (or to the
    forward_scheme'd endpoint for tests). A pooled aiohttp
    ClientSession is created at startup + reused for all forwards.
    """
    try:
        import aiohttp
        from aiohttp import web
    except ImportError as e:
        raise RuntimeError(
            "aiohttp is required for the bouncer HTTP proxy. "
            "Install it: pip install 'aiohttp>=3.9'"
        ) from e

    # Pooled session reused for all outbound forwards. Slice 5 will
    # tune the connector + add streaming response handling for
    # large objects (S3 GetObject of multi-GB files).
    connector = aiohttp.TCPConnector(limit=100, ttl_dns_cache=300)
    session = aiohttp.ClientSession(connector=connector)
    app = web.Application()

    # #132 plan-capture: ensure the in-process session slot is set so
    # every intercepted call records into the same logical transcript.
    # If the operator passed --plan-session-id we honour that;
    # otherwise mint a fresh id (`plan-YYYYMMDDTHHMMSSZ-...`) and
    # log it so they can find the transcript via `ibounce plan show`.
    # Only fires in PLAN_CAPTURE mode — other modes leave the slot
    # alone so concurrent processes don't collide.
    if config.mode == ProxyMode.PLAN_CAPTURE:
        from . import plan_capture as _plan_capture_pkg
        # Resolution priority: explicit config flag > existing in-
        # process slot (the CLI's `run_cmd` may have set this so the
        # operator could see the id BEFORE serve() starts) > mint a
        # fresh one. The last branch is the natural test-only path
        # (a test calls serve() directly without going through CLI).
        resolved_session_id = (
            config.plan_session_id
            or _plan_capture_pkg.current_session_id()
        )
        if resolved_session_id:
            _plan_capture_pkg.set_session_id(resolved_session_id)
        else:
            resolved_session_id = _plan_capture_pkg.new_session_id()
        # Persist the header row eagerly so `ibounce plan list`
        # shows the session even if zero calls land before stop.
        try:
            store.ensure_plan_session(
                session_id=resolved_session_id,
                started_by=os.environ.get("USER", "local"),
                note="ibounce serve --mode plan-capture",
            )
        except Exception as e:
            logger.warning(
                "plan-capture serve: failed to persist session header: %s", e,
            )
        # #145 — pin the write-switch notify mode for this session at
        # startup so per-call code reads the SAME value the operator
        # configured at process start (resilient to a future hot-reload
        # of ProxyConfig). Validation lives in
        # set_plan_session_write_switch_notify; we surface its error
        # via logger.warning so a typo'd flag (caught by Click's
        # Choice already, but defense in depth) doesn't crash serve().
        try:
            store.set_plan_session_write_switch_notify(
                resolved_session_id, config.plan_write_switch_notify,
            )
        except ValueError as e:
            logger.warning(
                "plan-capture serve: invalid write_switch_notify value "
                "(%s); leaving session at default 'manual'",
                e,
            )
        except Exception as e:
            logger.warning(
                "plan-capture serve: failed to pin write_switch_notify: %s", e,
            )
        logger.info(
            "plan-capture mode active; session_id=%s "
            "write_switch_notify=%s "
            "(every call is parsed + audited + returned-with-synthetic; "
            "nothing forwards to AWS)",
            resolved_session_id, config.plan_write_switch_notify,
        )

    async def handler(request):
        return await _handle_request(
            request, store=store, config=config, session=session,
        )

    async def healthz_handler(request):
        # Liveness probe. Bypasses proxy evaluation entirely (never
        # parses as a request, never writes to the audit log) so
        # monitor traffic doesn't pollute the operator's "what just
        # happened" view in `ibounce logs tail`. Mirrors
        # kbouncer's /healthz shape for cross-product symmetry.
        active_profile = getattr(config, "active_profile", None)
        try:
            decision_count = store.count_decisions()
            status_str = "ok"
        except Exception:
            decision_count = 0
            status_str = "degraded"
        # #6a — surface pause state so monitoring can flag a window
        # that's still open (e.g. ops left it on overnight by mistake)
        # without us having to invent a separate probe endpoint.
        # HIGH-33-02 closure: truncate operator-supplied free text +
        # strip control chars so a maliciously-crafted reason can't
        # break monitor parsers (newlines splitting the JSON line,
        # NULL bytes confusing C parsers, etc).
        pause_payload = None
        try:
            active_pause = store.get_active_pause()
            if active_pause is not None:
                reason = active_pause["reason"] or ""
                # Strip control chars + cap length
                reason = "".join(
                    ch for ch in reason if ch == " " or (32 <= ord(ch) < 127)
                )[:200]
                pause_payload = {
                    "id": active_pause["id"],
                    "started_at": active_pause["started_at"],
                    "ends_at": active_pause["ends_at"],
                    "reason": reason,
                }
        except Exception:
            pass
        pause_errs = _pause_lookup_error_count()
        if pause_errs > 0 and status_str == "ok":
            # HIGH-32-05 mitigation: a non-zero count means the proxy
            # has been silently enforcing through a window the operator
            # thought they had opened. Flip status so monitor probes
            # alert before the operator wonders why their pause "isn't
            # working."
            status_str = "degraded"
        # #264 — heartbeat state + gap detection. When heartbeats are
        # enabled, /healthz mirrors the heartbeat module's snapshot
        # under a top-level `heartbeat` block AND flips response to
        # 503 when the gap flag is set OR the elapsed time since the
        # last heartbeat exceeds the gap threshold. The independent
        # /healthz check (NOT just the rule-firing path) closes the
        # case where the audit-export channel itself is broken — the
        # rule may not even get an event to observe; an external
        # monitor polling /healthz still sees the gap.
        from .audit_export.heartbeat import heartbeat_status as _hb_status
        hb = _hb_status()
        heartbeat_payload = None
        http_status_code = 200
        if hb["heartbeat_enabled"]:
            interval = hb["heartbeat_interval_seconds"]
            last_ago = hb["heartbeat_last_emit_seconds_ago"]
            gap_threshold = interval * getattr(
                config, "alert_heartbeat_missing_count", 2,
            )
            # Compute gap state from BOTH the rule-set flag (fired
            # via the alert engine) AND the elapsed-time direct check
            # (catches the case where the alert engine isn't installed
            # — e.g. Free tier with heartbeats on for self-monitoring).
            gap_now = bool(hb["heartbeat_gap_detected"])
            if not gap_now and last_ago is not None and gap_threshold > 0:
                gap_now = last_ago >= gap_threshold
            heartbeat_payload = {
                "enabled": True,
                "interval_seconds": interval,
                "last_emit_seconds_ago": last_ago,
                "gap_detected": gap_now,
            }
            if gap_now:
                # 503 Service Unavailable — operator's monitoring
                # treats this as an alert that the proxy is not
                # healthy even if process-level liveness looks fine.
                # Status string also flips so a human reading the body
                # sees the condition without parsing the HTTP code.
                http_status_code = 503
                if status_str == "ok":
                    status_str = "degraded"
        # #267 — audit_export failure-visibility block. Independent of
        # the heartbeat 503 trigger above; either-or causes 503 (per
        # [[audit-export-failure-visibility]]). The audit_export block
        # ALWAYS appears (configured or not), so external monitoring
        # parsers can branch on `audit_export.degraded` as a single
        # bool without branching on "is the audit channel set up?"
        # first.
        audit_export_section = audit_export_health_section()
        if audit_export_section["degraded"]:
            http_status_code = 503
            if status_str == "ok":
                status_str = "degraded"
        else:
            # Self-clear the persistent rule-set flag when conditions
            # are healthy again. Without this, a degradation that
            # fired the alert rule + then healed (e.g. webhook
            # collector came back up) would leave /healthz stuck at
            # 503 until the next observe() runs the rule's clear
            # branch.
            if is_audit_export_degraded():
                clear_audit_export_degraded()
        return web.json_response({
            "status": status_str,
            "mode": config.mode.value,
            "default_policy": config.default_policy.value,
            "active_profile": active_profile.name if active_profile else "",
            "decisions_count": decision_count,
            "pause": pause_payload,
            "pause_lookup_errors_total": pause_errs,
            "heartbeat": heartbeat_payload,
            "audit_export": audit_export_section,
        }, status=http_status_code)

    # /healthz registered BEFORE the catch-all so it wins route
    # precedence; aiohttp dispatches in registration order.
    app.router.add_route("GET", "/healthz", healthz_handler)
    # #271 — GET /audit/events ships the headless audit-tail query
    # surface. Same filter language as `ibounce audit tail --filter`;
    # the cross-bouncer `iam-jit audit query` CLI calls this endpoint
    # in parallel against each reachable bouncer to produce a single
    # merged stream. Reads the same JSONL file `audit tail` reads, so
    # the endpoint returns nothing until --audit-log-path is set + the
    # writer has produced at least one event.
    from .audit_export.events_endpoint import register_audit_events_route
    register_audit_events_route(
        app,
        audit_log_path=(
            pathlib.Path(config.audit_log_path)
            if config.audit_log_path else None
        ),
        require_bearer=config.audit_events_token,
    )
    # #272 — GET / serves the minimal live audit-stream web UI. The
    # page polls /audit/events every 2 s; it shares the same auth
    # model as that endpoint (loopback → no auth; external bind →
    # bearer token, supplied via `#token=...` URL fragment). The
    # rendered HTML never embeds the token, matching the no-secret-
    # shape constraint from the spec. Registered alongside /healthz
    # + /audit/events so the catch-all "/{tail:.*}" below doesn't
    # swallow the root path.
    from .audit_export.events_ui import register_audit_events_ui_route
    # AWS SDK calls at GET / (e.g. S3 ListBuckets) MUST reach the
    # proxy handler instead of the operator UI. The UI route still
    # wins for browser visits; AWS-shaped requests delegate to
    # `handler` defined above so the proxy verdict + plan-capture
    # synthetic response paths run unchanged. Without this, the UI
    # silently shadows root-path AWS operations.
    register_audit_events_ui_route(
        app,
        bouncer_name="ibounce",
        require_bearer=config.audit_events_token,
        proxy_fallback=handler,
    )
    # #276 — GET /schemas/config serves the embedded
    # ibounce-config.schema.json. Agents that want to validate a
    # proposed `ibounce config import` payload against the LIVE
    # bouncer's accepted shape fetch this rather than relying on a
    # stale GitHub URL. Per [[cross-product-agent-parity]]: kbounce
    # + dbounce + gbounce ship the same endpoint with their own
    # product schema. READ-ONLY; no auth (matches /healthz — the
    # schema is non-sensitive metadata).
    from .schema_endpoint import register_config_schema_route
    register_config_schema_route(app)
    app.router.add_route("*", "/{tail:.*}", handler)

    # #252 Slice 1 — bring up the audit-export channels (if any).
    # Both channels run as background asyncio tasks owned by serve();
    # the registry hooks (register_audit_log_writer /
    # register_audit_webhook_pusher) plug them into evaluate_request
    # without threading args through every callsite. Failures here
    # are FATAL — if the operator asked for an audit channel and we
    # can't bring it up (SSRF rejection, license refusal, unwritable
    # path), serve() should refuse to start rather than silently
    # running without the channel.
    audit_log_writer = None
    audit_webhook_pusher = None
    audit_routes_engine = None  # #280 — per-org routing engine.
    audit_rule_engine = None
    session_recorder = None
    audit_security_lake_writer = None
    # #285 — per-session NDJSON recording. Default OFF; only initialised
    # when the operator passed `--record-sessions-dir`. start() is
    # synchronous (matches the recorder's synchronous record() path).
    # Failure is fatal so an operator who asked for recordings sees the
    # unwritable-dir error immediately rather than post-incident.
    if config.record_sessions_dir:
        from .audit_export import SessionRecorder
        session_recorder = SessionRecorder(
            dir=config.record_sessions_dir,
            bouncer_product="ibounce",
        )
        session_recorder.start()
        register_session_recorder(session_recorder)
        logger.info(
            "session recorder enabled: dir=%s",
            config.record_sessions_dir,
        )
    if config.audit_log_path:
        from .audit_export import AuditLogWriter
        audit_log_writer = AuditLogWriter(
            path=config.audit_log_path,
            fsync=config.audit_log_fsync,
        )
        await audit_log_writer.start()
        register_audit_log_writer(audit_log_writer)
        logger.info(
            "audit-export JSONL log enabled: path=%s fsync=%s",
            config.audit_log_path, config.audit_log_fsync,
        )
    # #258 — Security Lake adapter. Default OFF; only constructed when
    # the operator passed --security-lake-bucket. start() probes
    # credentials (default chain or AssumeRole if --security-lake-role-
    # arn is set) and refuses to start with a clear error if none are
    # reachable. Per [[no-hosted-saas]] the bucket lives in the
    # operator's AWS account; iam-jit-the-company never sees the data.
    if config.security_lake_bucket:
        from .audit_export import SecurityLakeWriter
        audit_security_lake_writer = SecurityLakeWriter(
            bucket=config.security_lake_bucket,
            region=config.security_lake_region or "us-east-1",
            role_arn=config.security_lake_role_arn,
            rotation_seconds=config.security_lake_rotation_seconds,
        )
        audit_security_lake_writer.start()
        register_audit_security_lake_writer(audit_security_lake_writer)
        sl_status = audit_security_lake_writer.status()
        logger.info(
            "audit-export Security Lake enabled: bucket=%s region=%s "
            "account=%s caller=%s role_arn=%s rotation=%ss",
            config.security_lake_bucket,
            config.security_lake_region,
            sl_status.get("account_id", ""),
            sl_status.get("caller_arn", ""),
            config.security_lake_role_arn or "(default-chain)",
            config.security_lake_rotation_seconds,
        )

    # #280 — per-org notification routing engine. When configured, the
    # routing engine handles all webhook dispatch + the single-webhook
    # pusher block below is skipped (the CLI parse-time gate already
    # warned the operator if both were set). Defense in depth: the
    # license gate fires here AGAIN so a license file that disappeared
    # between parse + start doesn't quietly grant routing capability.
    if config.alert_routes_path is not None:
        from .audit_export import (
            RoutesConfigError,
            RoutesEngine,
            RoutesLicenseError,
            gate_routes_license,
            load_routes_config,
        )
        try:
            gate_routes_license(None)
        except RoutesLicenseError:
            # Fatal at serve() time. The CLI parse-time gate has
            # already printed the friendly error message; here we let
            # serve() refuse to start.
            raise
        try:
            routes_config = load_routes_config(
                config.alert_routes_path, product="ibounce",
            )
        except RoutesConfigError:
            raise
        _engine = RoutesEngine(
            config=routes_config, product="ibounce",
        )
        await _engine.start()
        register_audit_routes_engine(_engine)
        audit_routes_engine = _engine
        # Startup banner — masked secrets only. The operator sees which
        # env vars were resolved + the first-8-char prefix of each so
        # they can confirm "yes, the right secret is loaded" without the
        # value ever appearing in logs.
        secrets = routes_config.secrets_used()
        logger.info(
            "audit-export per-org routing engine enabled: routes=%d "
            "destinations=%d",
            len(routes_config.routes),
            sum(len(r.destinations) for r in routes_config.routes),
        )
        for env_name, masked in secrets:
            logger.info("  secret %s (%s)", env_name, masked)
    elif config.audit_webhook_url and config.audit_webhook_token:
        from .audit_export import Preset, WebhookPusher
        audit_webhook_pusher = WebhookPusher(
            url=config.audit_webhook_url,
            token=config.audit_webhook_token,
            batch_size=config.audit_webhook_batch_size,
            allow_internal=config.audit_webhook_allow_internal,
            preset=Preset(config.audit_webhook_preset),
            tags=config.audit_webhook_tags,
            sentinel_table=config.audit_webhook_sentinel_table,
        )
        await audit_webhook_pusher.start()
        register_audit_webhook_pusher(audit_webhook_pusher)
        # NEVER log the token. Use the masked URL helper.
        from .audit_export.webhook import mask_url_userinfo
        logger.info(
            "audit-export HTTPS webhook enabled: url=%s preset=%s batch=%s "
            "allow_internal=%s",
            mask_url_userinfo(config.audit_webhook_url),
            config.audit_webhook_preset,
            config.audit_webhook_batch_size,
            config.audit_webhook_allow_internal,
        )
    # #262 Slice 2 — alert rule engine. License gate fires here AGAIN
    # (defense in depth — CLI already gated at parse time, but the
    # license file could have rotated between parse + start). When no
    # --alert-rules path is configured, the engine doesn't load at
    # all; the transport still works (Slice 1 unchanged).
    if config.alert_rules_path is not None:
        import dataclasses as _dc

        from .audit_export import (
            AlertsConfig,
            AlertsLicenseError,
            RuleEngine,
            gate_alerts_license,
            load_alerts_config,
        )
        try:
            gate_alerts_license(None)
        except AlertsLicenseError:
            # Fatal at serve() time — operator asked for alerts + we
            # can't honor it; refusing is safer than silent no-op.
            # The CLI parse-time gate already prints a friendly error
            # message; here we just let the exception propagate so
            # serve() refuses to start.
            raise
        if config.alert_rules_path == "":
            alerts_config = AlertsConfig.default()
        else:
            alerts_config = load_alerts_config(config.alert_rules_path)
        # #264 — propagate the CLI's --alert-heartbeat-missing-count
        # into the engine config. The YAML loader honours the same
        # key under `heartbeat_missing_count`; the CLI flag wins so
        # an operator who doesn't curate YAML can still tune the
        # gap threshold from the command line.
        if config.alert_heartbeat_missing_count != alerts_config.heartbeat_missing_count:
            alerts_config = _dc.replace(
                alerts_config,
                heartbeat_missing_count=config.alert_heartbeat_missing_count,
            )
        audit_rule_engine = RuleEngine(
            config=alerts_config,
            emit=_emit_audit_event_raw,
        )
        register_audit_rule_engine(audit_rule_engine)
        logger.info(
            "audit-export alert engine enabled: rules=%s",
            audit_rule_engine.status()["active_rules"],
        )

    # #253 — bulk-prompt-answer UX. Install the burst detector + the
    # operator's MCP bulk-answer token so:
    #   1. Every `add_pending_prompt` from the proxy hot path feeds the
    #      detector (via `active_burst_detector()` from burst.py).
    #   2. The MCP `bouncer_prompts_bulk_answer` tool gate consults the
    #      installed token (default None → tool returns the standard
    #      disabled-error response).
    # Both registrations are no-ops on tests that call serve() with
    # the defaults; the detector still arms but no event fires until
    # the threshold crosses.
    from .burst import (
        BurstDetector,
        register_burst_detector,
        set_bulk_answer_mcp_token,
    )
    burst_detector = BurstDetector(
        threshold=config.burst_threshold,
        window_seconds=config.burst_window_seconds,
        emit=_emit_audit_event_raw,
    )
    register_burst_detector(burst_detector)
    set_bulk_answer_mcp_token(config.bulk_answer_mcp_token)
    logger.info(
        "bulk-prompt-answer UX: burst_threshold=%d burst_window=%ds "
        "mcp_bulk_answer_enabled=%s",
        config.burst_threshold,
        config.burst_window_seconds,
        bool(config.bulk_answer_mcp_token),
    )

    # #253 — rule-expiry sweeper. 30s tick. The list_active_rules
    # filter at evaluate_request time already hides expired rules from
    # the active RuleSet; this sweeper exists to emit the per-rule
    # `rule_expired` audit event exactly once per transition, so the
    # audit chain shows when each time-bounded grant aged out without
    # waiting for the next operator-driven list_rules call.
    async def _rule_expiry_sweeper_loop() -> None:
        # 30s matches the spec; granularity small enough that operators
        # don't see a noticeable gap between expires_at and the audit
        # event, large enough that this isn't a meaningful load.
        SWEEP_INTERVAL = 30
        try:
            while True:
                await asyncio.sleep(SWEEP_INTERVAL)
                try:
                    expired = store.expire_rules_at()
                    if expired:
                        logger.info(
                            "ibounce rule-expiry sweeper: %d rule(s) "
                            "transitioned to expired (ids=%s); rows "
                            "preserved in DB for audit",
                            len(expired), expired,
                        )
                except Exception as e:
                    # Per [[deliberate-feature-completion]] fail-soft:
                    # a sweeper failure must not bring down the proxy.
                    # The active-rules filter still hides expired rules
                    # at decision time; we just lose the per-tick audit
                    # event (operators see it on the next successful
                    # sweep).
                    logger.warning(
                        "ibounce rule-expiry sweeper tick failed: %s", e,
                    )
        except asyncio.CancelledError:
            return

    rule_expiry_task = asyncio.create_task(
        _rule_expiry_sweeper_loop(), name="ibounce-rule-expiry-sweeper",
    )

    # #270 Slice 2 — pending-audit-events drainer. Profile-install
    # synthetics enqueue from a separate process (the `ibounce profile
    # install` CLI invocation has its OWN BouncerStore handle, then
    # exits); this loop in the serve process picks them up + delivers
    # them to the rule engine + the JSONL/webhook transports so the
    # non_org_profile_install rule can fire. Mirrors the dbounce
    # 24eca0c SQLite-queue pattern. 1s cadence matches the spec.
    #
    # No-op when the rule engine is not installed (the drainer still
    # runs, but observe() is a no-op without a registered engine — the
    # event still rides the transports if those are wired). Fail-soft:
    # any error in a single iteration is logged + the loop continues.
    async def _pending_audit_events_drain_loop() -> None:
        DRAIN_INTERVAL = 1.0
        try:
            while True:
                await asyncio.sleep(DRAIN_INTERVAL)
                try:
                    rows = store.drain_pending_audit_events(limit=100)
                except Exception as e:
                    logger.warning(
                        "ibounce pending-audit-events drain query "
                        "failed: %s", e,
                    )
                    continue
                if not rows:
                    continue
                # Import inside the loop to keep the alerts module
                # out of serve()'s eager-import set when no events
                # ever land — matches the lazy-import pattern used in
                # evaluate_request for audit_event_from_decision.
                import json as _json_local
                from .audit_export import (
                    EVENT_TYPE_ADMIN_ACTION,
                    admin_action_event_from_payload,
                    make_profile_install_event,
                )
                from .audit_export.alerts import EVENT_TYPE_PROFILE_INSTALL
                for row in rows:
                    try:
                        evt_type = row["event_type"]
                        if evt_type == EVENT_TYPE_PROFILE_INSTALL:
                            payload = _json_local.loads(row["payload_json"])
                            evt = make_profile_install_event(
                                profile_name=str(payload.get("profile_name") or ""),
                                source_url=str(payload.get("source_url") or ""),
                                installed_by=str(payload.get("installed_by") or ""),
                            )
                            _emit_audit_event(evt)
                        elif evt_type == EVENT_TYPE_ADMIN_ACTION:
                            # #278 — admin-action drain. Materialise
                            # the OCSF event from the JSON payload
                            # enqueued by a CLI subcommand and push
                            # it through the same emit channel as
                            # decisions + the existing synthetics so
                            # JSONL log + webhook + rule engine all
                            # see one canonical shape.
                            evt = admin_action_event_from_payload(
                                row["payload_json"]
                            )
                            _emit_audit_event(evt)
                        else:
                            # Unknown event_type — log + skip. The
                            # row is already deleted (drain pops),
                            # so we don't loop on a malformed row
                            # forever; the operator just sees the
                            # warning.
                            logger.warning(
                                "ibounce pending-audit-events drain: "
                                "unknown event_type %r; skipping "
                                "(row id=%s)",
                                evt_type, row["id"],
                            )
                            continue
                    except Exception as e:
                        logger.warning(
                            "ibounce pending-audit-events drain delivery "
                            "failed for row id=%s: %s",
                            row.get("id"), e,
                        )
        except asyncio.CancelledError:
            return

    pending_audit_drain_task = asyncio.create_task(
        _pending_audit_events_drain_loop(),
        name="ibounce-pending-audit-events-drain",
    )

    # #264 — heartbeat emitter. Default OFF (interval_seconds=0); the
    # operator opts in via --heartbeat-interval. Runs on every tier
    # (Free + Pro + Enterprise); the gap-detection rule that watches
    # for missed heartbeats is Enterprise-gated (via the alert engine
    # block above) but the EMITTER itself is unrestricted because the
    # /healthz handler does its own gap check independent of the rule
    # engine (so a Free-tier operator can still detect their own
    # bouncer dying).
    audit_heartbeat_emitter = None
    if config.heartbeat_interval_seconds > 0:
        from .audit_export import HeartbeatEmitter
        audit_heartbeat_emitter = HeartbeatEmitter(
            interval_seconds=config.heartbeat_interval_seconds,
            emit=_emit_audit_event_raw,
        )
        await audit_heartbeat_emitter.start()
        logger.info(
            "audit-export heartbeat enabled: interval=%ss "
            "gap-threshold=%s consecutive misses",
            config.heartbeat_interval_seconds,
            config.alert_heartbeat_missing_count,
        )

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, config.host, config.port)
    await site.start()
    logger.info(
        "ibounce proxy listening on http://%s:%s (mode=%s)",
        config.host, config.port, config.mode.value,
    )
    logger.info(
        "Point your SDK at it: AWS_ENDPOINT_URL=http://%s:%s "
        "(Slice 2: forwards allowed requests to AWS verbatim; "
        "SigV4 signatures preserved)",
        config.host, config.port,
    )

    # Block forever (until task cancellation)
    try:
        await asyncio.Event().wait()
    finally:
        await session.close()
        await runner.cleanup()
        # Tear down audit-export channels in reverse-install order so
        # an in-flight webhook send drains before the log writer's fd
        # closes. We catch + log here so a worker that exits with an
        # exception doesn't mask the original cancellation.
        # #264 — heartbeat emitter teardown. Stop BEFORE the alert
        # engine / transport channels close so a final emit doesn't
        # try to push through a torn-down pusher.
        if audit_heartbeat_emitter is not None:
            try:
                await audit_heartbeat_emitter.stop()
            except Exception as e:
                logger.warning("audit-heartbeat emitter stop failed: %s", e)
        if audit_rule_engine is not None:
            # #262 Slice 2 — engine has no async worker (observe is
            # synchronous), so teardown is just clearing the
            # registry slot so the next process doesn't see a stale
            # reference.
            register_audit_rule_engine(None)
        # #280 — routes engine teardown drains its bounded queue + closes
        # the shared aiohttp session. Mirrors the single-webhook teardown
        # pattern above.
        if audit_routes_engine is not None:
            try:
                await audit_routes_engine.stop()
            except Exception as e:
                logger.warning("audit-routes engine stop failed: %s", e)
            register_audit_routes_engine(None)
        if audit_webhook_pusher is not None:
            try:
                await audit_webhook_pusher.stop()
            except Exception as e:
                logger.warning("audit-webhook pusher stop failed: %s", e)
            register_audit_webhook_pusher(None)
        # #258 — Security Lake teardown flushes every pending parquet
        # batch synchronously (per the spec) so a shutdown doesn't
        # drop in-memory rows.
        if audit_security_lake_writer is not None:
            try:
                audit_security_lake_writer.stop()
            except Exception as e:
                logger.warning(
                    "audit-export Security Lake writer stop failed: %s", e,
                )
            register_audit_security_lake_writer(None)
        if audit_log_writer is not None:
            try:
                await audit_log_writer.stop()
            except Exception as e:
                logger.warning("audit-log writer stop failed: %s", e)
            register_audit_log_writer(None)
        # #285 — session recorder teardown drops the .partial suffix on
        # every still-open session via atomic rename. Catch + log so a
        # fd-close failure never masks the cancellation that brought us
        # here.
        if session_recorder is not None:
            try:
                session_recorder.stop()
            except Exception as e:
                logger.warning("session recorder stop failed: %s", e)
            register_session_recorder(None)
        # #253 — rule-expiry sweeper + burst detector teardown. Cancel
        # the sweeper task FIRST so it doesn't try to write to a torn-
        # down audit channel on its way out. Then clear the burst-
        # detector singleton + the bulk-answer token so the next
        # process doesn't see stale state.
        try:
            rule_expiry_task.cancel()
            try:
                await rule_expiry_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.warning("rule-expiry sweeper teardown failed: %s", e)
        except Exception as e:
            logger.warning("rule-expiry sweeper cancel failed: %s", e)
        # #270 Slice 2 — pending-audit-events drainer teardown. Cancel
        # AFTER the rule-expiry sweeper for symmetry with the start
        # order; both are independent and cancelling either first is
        # safe (no shared state between them).
        try:
            pending_audit_drain_task.cancel()
            try:
                await pending_audit_drain_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.warning(
                    "pending-audit-events drain teardown failed: %s", e,
                )
        except Exception as e:
            logger.warning(
                "pending-audit-events drain cancel failed: %s", e,
            )
        register_burst_detector(None)
        set_bulk_answer_mcp_token(None)
