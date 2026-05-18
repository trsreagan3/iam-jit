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


def _emit_audit_event(event: dict) -> None:
    """Hand `event` to both audit channels if configured. Both calls
    are non-blocking enqueues (the channels own their own worker
    tasks). Exceptions are swallowed + logged — the audit channel is
    a feature, not a hard dependency of correctness; a broken disk
    should not turn the proxy into a 500-machine.
    """
    if _audit_log_writer is not None:
        try:
            _audit_log_writer.write(event)
        except Exception as e:
            logger.warning("audit log writer enqueue failed: %s", e)
    if _audit_webhook_pusher is not None:
        try:
            _audit_webhook_pusher.push(event)
        except Exception as e:
            logger.warning("audit webhook pusher enqueue failed: %s", e)


def audit_export_status() -> dict[str, Any]:
    """Snapshot of both audit-export channels for the MCP status tool.

    Returns a stable shape regardless of which channels are installed
    so the agent's structured-content consumer can branch on the
    `configured` flags rather than `KeyError`-ing on missing fields.
    """
    if _audit_log_writer is not None:
        log_status = _audit_log_writer.status()
    else:
        log_status = {"configured": False}
    if _audit_webhook_pusher is not None:
        webhook_status = _audit_webhook_pusher.status()
    else:
        webhook_status = {"configured": False}
    return {
        "log": log_status,
        "webhook": webhook_status,
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
    }


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
    local mock-AWS server."""
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
    id_tagged = store.list_rules()
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
        ))
    except Exception as e:
        logger.warning("audit-export emit (decision) failed: %s", e)

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
    try:
        status, resp_headers, resp_body = await _forward_to_aws(
            method=request.method,
            host=host_header,
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
        active_profile=config.active_profile,
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
    try:
        status, resp_headers, resp_body = await _forward_to_aws(
            method=request.method,
            host=host_header,
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
        return web.json_response({
            "status": status_str,
            "mode": config.mode.value,
            "default_policy": config.default_policy.value,
            "active_profile": active_profile.name if active_profile else "",
            "decisions_count": decision_count,
            "pause": pause_payload,
            "pause_lookup_errors_total": pause_errs,
        })

    # /healthz registered BEFORE the catch-all so it wins route
    # precedence; aiohttp dispatches in registration order.
    app.router.add_route("GET", "/healthz", healthz_handler)
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
    if config.audit_webhook_url and config.audit_webhook_token:
        from .audit_export import WebhookPusher
        audit_webhook_pusher = WebhookPusher(
            url=config.audit_webhook_url,
            token=config.audit_webhook_token,
            batch_size=config.audit_webhook_batch_size,
            allow_internal=config.audit_webhook_allow_internal,
        )
        await audit_webhook_pusher.start()
        register_audit_webhook_pusher(audit_webhook_pusher)
        # NEVER log the token. Use the masked URL helper.
        from .audit_export.webhook import mask_url_userinfo
        logger.info(
            "audit-export HTTPS webhook enabled: url=%s batch=%s "
            "allow_internal=%s",
            mask_url_userinfo(config.audit_webhook_url),
            config.audit_webhook_batch_size,
            config.audit_webhook_allow_internal,
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
        if audit_webhook_pusher is not None:
            try:
                await audit_webhook_pusher.stop()
            except Exception as e:
                logger.warning("audit-webhook pusher stop failed: %s", e)
            register_audit_webhook_pusher(None)
        if audit_log_writer is not None:
            try:
                await audit_log_writer.stop()
            except Exception as e:
                logger.warning("audit-log writer stop failed: %s", e)
            register_audit_log_writer(None)
