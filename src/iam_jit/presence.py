"""Bouncer-presence verification — "off the leash" detection (#726 / BUILD-5).

Per the Agent-as-a-Proxy bypass (arXiv 2602.05066): a *cooperative*
bouncer only sees the traffic an agent chooses to send through it. A
prompt-injected (or simply misconfigured) agent can route AROUND the
bouncer — operate "off the leash" — and the operator still believes
the bouncer is gating every call. The bouncer's own /healthz says
"I'm alive", but that proves the *process* is up, not that the
*agent* is actually flowing through it.

BUILD-5 turns the passive heartbeat gap-detector
(`bouncer.audit_export.heartbeat`, #264) into ACTIVE presence
verification on the iam-jit (role-issuer) side:

  * A bouncer "checks in" with iam-jit (a presence beat) every time
    it proves it is in an agent's path — e.g. on mgmt-port sign-in or
    on a periodic self-check it emits while a session is live.
  * iam-jit records the last check-in PER AGENT SESSION.
  * "Expected presence" = a check-in within a configured TTL
    (default 5 minutes, per the spec). Inside the TTL the bouncer is
    `PRESENT`. Past the TTL, after we HAD seen it, the session is
    `OFF_THE_LEASH` — a SIGNAL, not proof, that the agent may be
    bypassing the bouncer.
  * If a session never checked in at all it is `NEVER_SEEN` — that's
    distinct from off-the-leash (we have no evidence the bouncer was
    ever in the path, so "it went silent" is the wrong story).

Honest framing per [[ibounce-honest-positioning]]: a presence gap is
a SIGNAL, not "BYPASS DETECTED". The agent may legitimately be idle
(no AWS calls to gate right now). We distinguish IDLE from GONE where
we can: a session that explicitly told us "I'm idle" (a paused /
quiescent beat) is not flagged; only a session that was actively
checking in and then went *silent* past the TTL is flagged. Even then
the language is "the bouncer hasn't checked in for N — verify the
agent is still routed through it", never an accusation.

Default sane per [[v1-scope-bar]] / [[safety-mode-lean-permissive]]:
the presence gate is ADVISORY by default. A gap raises an
"off-the-leash" signal (OCSF audit event + /healthz + CLI/MCP) but
does NOT block role-issuance. An operator who wants the stronger
guarantee opts in via `IAM_JIT_REQUIRE_BOUNCER_PRESENCE=1`, which
makes iam-jit refuse new role-issuance for a session whose bouncer
has gone off the leash (the spec's "refuse new role-issuance on
heartbeat miss" behaviour, behind an explicit opt-in).

Per [[scorer-is-ground-truth]]: no LLM, no scoring. This is pure
mechanical bookkeeping (record a timestamp, compare to a TTL).

Per [[creates-never-mutates]]: this module never touches AWS. It
only gates whether iam-jit will CREATE a short-lived role.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .bouncer.audit_export.event import (
    OCSF_SCHEMA_VERSION,
    _now_unix_ms,
    _product_version,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Default expected-presence TTL. A bouncer that checked in within this
# many seconds is PRESENT. The spec calls for 5 minutes.
DEFAULT_PRESENCE_TTL_SECONDS = 300

# Env-var names. All default to the conservative / non-disruptive
# posture so an operator who sets nothing gets advisory-only signals.
_ENV_TTL = "IAM_JIT_BOUNCER_PRESENCE_TTL_SECONDS"
_ENV_REQUIRE = "IAM_JIT_REQUIRE_BOUNCER_PRESENCE"

_TRUE_VALUES = {"1", "true", "yes", "on"}


def presence_ttl_seconds() -> int:
    """Effective expected-presence TTL.

    Read from `IAM_JIT_BOUNCER_PRESENCE_TTL_SECONDS` (seconds). Invalid
    or non-positive values fall back to the 5-minute default rather
    than disabling the feature on a typo.
    """
    raw = os.environ.get(_ENV_TTL)
    if raw is None:
        return DEFAULT_PRESENCE_TTL_SECONDS
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_PRESENCE_TTL_SECONDS
    return val if val > 0 else DEFAULT_PRESENCE_TTL_SECONDS


def require_bouncer_presence() -> bool:
    """Whether presence is ENFORCED (refuse issuance on a gap) vs
    merely advisory.

    Default OFF per [[safety-mode-lean-permissive]] — a gap is a
    signal, and blocking every role on a possibly-idle agent would be
    the wrong default. Opt in with `IAM_JIT_REQUIRE_BOUNCER_PRESENCE=1`.
    """
    return (os.environ.get(_ENV_REQUIRE) or "").strip().lower() in _TRUE_VALUES


# ---------------------------------------------------------------------------
# Presence state
# ---------------------------------------------------------------------------


class PresenceState(str, Enum):
    """The presence verdict for one agent session.

    PRESENT      — checked in within the TTL; the bouncer is (as far
                   as we can tell) still in the agent's path.
    OFF_THE_LEASH— checked in BEFORE but has gone silent past the TTL.
                   A signal worth verifying, NOT proof of bypass.
    IDLE         — the bouncer explicitly told us it's quiescent
                   (paused / no traffic to gate). Not flagged.
    NEVER_SEEN   — no check-in on record for this session. We have no
                   evidence the bouncer was ever in the path, so this
                   is distinct from "it went silent".
    """

    PRESENT = "present"
    OFF_THE_LEASH = "off_the_leash"
    IDLE = "idle"
    NEVER_SEEN = "never_seen"


@dataclass(frozen=True)
class PresenceVerdict:
    """Result of evaluating one session's presence."""

    session_id: str
    state: PresenceState
    last_check_in_seconds_ago: int | None
    ttl_seconds: int

    @property
    def is_present(self) -> bool:
        return self.state in (PresenceState.PRESENT, PresenceState.IDLE)

    @property
    def is_off_the_leash(self) -> bool:
        return self.state is PresenceState.OFF_THE_LEASH

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "state": self.state.value,
            "last_check_in_seconds_ago": self.last_check_in_seconds_ago,
            "ttl_seconds": self.ttl_seconds,
            # Honest, neutral one-liner the UI / CLI / MCP can show
            # verbatim. Never an accusation.
            "message": _verdict_message(self),
        }


def _verdict_message(v: "PresenceVerdict") -> str:
    """Neutral-language one-liner per [[ibounce-honest-positioning]].

    A gap is "verify routing", never "BYPASS DETECTED".
    """
    if v.state is PresenceState.PRESENT:
        ago = (
            f"{v.last_check_in_seconds_ago}s ago"
            if v.last_check_in_seconds_ago is not None
            else "just now"
        )
        return f"bouncer checked in {ago}; presence confirmed."
    if v.state is PresenceState.IDLE:
        return "bouncer reported idle; no traffic to gate right now."
    if v.state is PresenceState.NEVER_SEEN:
        return (
            f"no bouncer check-in on record for session {v.session_id!r}; "
            "cannot confirm a bouncer is in this agent's path."
        )
    # OFF_THE_LEASH
    ago = (
        f"{v.last_check_in_seconds_ago}s ago"
        if v.last_check_in_seconds_ago is not None
        else "an unknown time ago"
    )
    return (
        f"bouncer last checked in {ago} (> {v.ttl_seconds}s ttl) for "
        f"session {v.session_id!r}; verify the agent is still routed "
        f"through the bouncer — this is a signal, not proof of bypass."
    )


# ---------------------------------------------------------------------------
# In-process presence registry
#
# Keyed by agent-session id. Each entry records the last check-in
# wall-clock + whether the bouncer said it was idle. The registry is
# in-process: in a single-process `iam-jit serve` / Lambda invocation
# the bouncer check-ins and the issuance gate share the same memory.
# Multi-process deployments would back this with the shared store; the
# spec keeps BUILD-5 self-contained, so the in-process registry is the
# v1 surface + the gate degrades safely (NEVER_SEEN) when a check-in
# landed in a different process.
# ---------------------------------------------------------------------------

_lock = threading.Lock()
# session_id -> (last_check_in_unix, idle_flag)
_check_ins: dict[str, tuple[float, bool]] = {}


def reset_for_tests() -> None:
    """Clear the registry. Tests call this in setup/teardown."""
    with _lock:
        _check_ins.clear()


def record_check_in(
    session_id: str,
    *,
    idle: bool = False,
    now: float | None = None,
) -> None:
    """Record that a bouncer proved presence for `session_id`.

    Called when the bouncer signs in via the mgmt-port or emits a
    periodic presence beat while a session is live.

    `idle=True` is the bouncer explicitly saying "I'm in the path but
    have nothing to gate right now" — that keeps the session out of
    OFF_THE_LEASH (we distinguish idle from gone).
    """
    if not session_id:
        return
    ts = time.time() if now is None else now
    with _lock:
        _check_ins[session_id] = (ts, bool(idle))


def forget_session(session_id: str) -> None:
    """Drop a session's presence record — e.g. when the operator
    deliberately ends the session so a post-session gap isn't flagged
    as off-the-leash (matches heartbeat.py's stop() clearing the gap
    flag: a deliberate stop is not an anomaly)."""
    with _lock:
        _check_ins.pop(session_id, None)


def evaluate_session(
    session_id: str,
    *,
    ttl_seconds: int | None = None,
    now: float | None = None,
) -> PresenceVerdict:
    """Compute the presence verdict for one session.

    NEVER_SEEN when there's no check-in on record; PRESENT when the
    last check-in is within the TTL; IDLE when the bouncer reported
    idle on its last beat; OFF_THE_LEASH when an active session went
    silent past the TTL.
    """
    ttl = presence_ttl_seconds() if ttl_seconds is None else ttl_seconds
    nowt = time.time() if now is None else now
    with _lock:
        entry = _check_ins.get(session_id)
    if entry is None:
        return PresenceVerdict(
            session_id=session_id,
            state=PresenceState.NEVER_SEEN,
            last_check_in_seconds_ago=None,
            ttl_seconds=ttl,
        )
    last, idle = entry
    # Clamp a backwards clock-jump to 0 so we never report a negative
    # age (matches heartbeat_status()).
    ago = max(0, int(nowt - last))
    if ago <= ttl:
        state = PresenceState.IDLE if idle else PresenceState.PRESENT
    else:
        # Past the TTL. An idle session that's been silent past the TTL
        # is still off-the-leash from our perspective — "idle" only
        # suppresses the flag while the idle beat itself is fresh. Once
        # even the idle beats stop, we've lost contact.
        state = PresenceState.OFF_THE_LEASH
    return PresenceVerdict(
        session_id=session_id,
        state=state,
        last_check_in_seconds_ago=ago,
        ttl_seconds=ttl,
    )


def list_sessions(
    *,
    ttl_seconds: int | None = None,
    now: float | None = None,
) -> list[PresenceVerdict]:
    """Verdicts for every session with a check-in on record."""
    with _lock:
        ids = list(_check_ins.keys())
    return [
        evaluate_session(sid, ttl_seconds=ttl_seconds, now=now) for sid in ids
    ]


# ---------------------------------------------------------------------------
# Issuance gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PresenceGateDecision:
    """Outcome of the role-issuance presence gate."""

    allow: bool
    enforced: bool
    verdict: PresenceVerdict
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow": self.allow,
            "enforced": self.enforced,
            "reason": self.reason,
            "presence": self.verdict.to_dict(),
        }


def presence_gate(
    session_id: str | None,
    *,
    ttl_seconds: int | None = None,
    now: float | None = None,
) -> PresenceGateDecision:
    """Decide whether iam-jit should issue a role given bouncer
    presence for `session_id`.

    Default (advisory) posture per [[safety-mode-lean-permissive]]:
    ALWAYS allow; an off-the-leash session is surfaced as a signal but
    issuance proceeds. With `IAM_JIT_REQUIRE_BOUNCER_PRESENCE=1` the
    gate REFUSES issuance for an OFF_THE_LEASH session (the spec's
    "refuse new role-issuance on heartbeat miss").

    A session with no `session_id` at all, or one that was NEVER_SEEN,
    is NOT blocked even in enforce mode: enforcement is about a bouncer
    that *was* present and then went silent, not about callers that
    never wired up presence beats. Blocking NEVER_SEEN would break
    every deployment that hasn't opted the bouncer into check-ins —
    the wrong default for a [[lightweight-frictionless-principle]] tool.
    """
    enforced = require_bouncer_presence()
    if not session_id:
        verdict = PresenceVerdict(
            session_id="",
            state=PresenceState.NEVER_SEEN,
            last_check_in_seconds_ago=None,
            ttl_seconds=presence_ttl_seconds() if ttl_seconds is None else ttl_seconds,
        )
        return PresenceGateDecision(
            allow=True,
            enforced=enforced,
            verdict=verdict,
            reason="no session id supplied; presence gate not applicable.",
        )
    verdict = evaluate_session(session_id, ttl_seconds=ttl_seconds, now=now)
    if verdict.is_off_the_leash and enforced:
        return PresenceGateDecision(
            allow=False,
            enforced=True,
            verdict=verdict,
            reason=(
                "IAM_JIT_REQUIRE_BOUNCER_PRESENCE is set and the bouncer "
                f"has not checked in within {verdict.ttl_seconds}s for "
                f"session {session_id!r}; refusing new role-issuance until "
                "the bouncer's presence is re-confirmed."
            ),
        )
    if verdict.is_off_the_leash:
        return PresenceGateDecision(
            allow=True,
            enforced=False,
            verdict=verdict,
            reason=(
                "presence gap detected (advisory); issuance proceeds. "
                "set IAM_JIT_REQUIRE_BOUNCER_PRESENCE=1 to enforce."
            ),
        )
    return PresenceGateDecision(
        allow=True,
        enforced=enforced,
        verdict=verdict,
        reason="bouncer presence confirmed.",
    )


# ---------------------------------------------------------------------------
# OCSF off-the-leash event
#
# Builds on the heartbeat (#264) OCSF conventions: class 6003 API
# Activity, activity_id=99 (Other — "the bouncer may be off the leash"
# is not a CRUD verb). Higher severity than a plain heartbeat (this is
# the "the noise stopped" event) but framed neutrally.
# ---------------------------------------------------------------------------

_CLASS_UID = 6003
_CLASS_NAME = "API Activity"
_CATEGORY_UID = 6
_CATEGORY_NAME = "Application Activity"
_ACTIVITY_ID = 99
_ACTIVITY_NAME = "presence_gap"
_TYPE_UID = _CLASS_UID * 100 + _ACTIVITY_ID  # 600399

# severity_id=4 High: the bouncer was in the path and went silent —
# worth a SIEM operator's attention. NOT Critical: it's a signal, not
# a confirmed breach (per [[ibounce-honest-positioning]]).
_SEVERITY_ID = 4
_SEVERITY = "High"

# status_id=99 Other — matches the alert-engine convention for
# synthetic anomaly events (it's neither a Success nor a Failure of a
# request; it's a meta-observation).
_STATUS_ID = 99
_STATUS = "Other"

_PRODUCT_NAME = "ibounce"
_PRODUCT_VENDOR_NAME = "iam-jit"

# unmapped marker so a SIEM can filter on one field, mirroring
# heartbeat.py's EVENT_TYPE_HEARTBEAT.
EVENT_TYPE_OFF_THE_LEASH = "BOUNCER_PRESENCE_GAP"


def make_off_the_leash_event(verdict: PresenceVerdict) -> dict[str, Any]:
    """Build one OCSF v1.1.0 class-6003 "off-the-leash" / presence-gap
    event for `verdict`.

    Same schema family as `heartbeat.make_heartbeat_event` so a SIEM
    already indexing ibounce events dashboards this with no mapping
    changes. The `status_detail` + `unmapped` carry the honest,
    neutral framing.
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
        # Honest one-liner, no forbidden words / no accusation.
        "status_detail": _verdict_message(verdict),
        "actor": {"user": {"name": "", "uid": ""}},
        "api": {
            "operation": "presence_gap",
            "service": {"name": "iam_jit.presence"},
            "request": {"uid": verdict.session_id},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {},
        "unmapped": {
            "iam_jit": {
                "event_type": EVENT_TYPE_OFF_THE_LEASH,
                "session_id": verdict.session_id,
                "presence_state": verdict.state.value,
                "last_check_in_seconds_ago": verdict.last_check_in_seconds_ago,
                "ttl_seconds": verdict.ttl_seconds,
                # Explicit honesty marker so consumers never read this
                # as a confirmed bypass.
                "signal_not_proof": True,
            },
        },
    }


# ---------------------------------------------------------------------------
# Status surface for /healthz + CLI + MCP
# ---------------------------------------------------------------------------


def presence_status(
    *,
    ttl_seconds: int | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Snapshot for /healthz + the CLI/MCP query.

    Stable shape regardless of whether any session has checked in.
    `off_the_leash_count` is the load-bearing field external monitoring
    polls to learn "is any tracked agent silent past the TTL?".
    """
    verdicts = list_sessions(ttl_seconds=ttl_seconds, now=now)
    off = [v for v in verdicts if v.is_off_the_leash]
    return {
        "enforced": require_bouncer_presence(),
        "ttl_seconds": presence_ttl_seconds() if ttl_seconds is None else ttl_seconds,
        "tracked_sessions": len(verdicts),
        "off_the_leash_count": len(off),
        # True iff at least one tracked session is off the leash — the
        # single bool a monitor / /healthz reads.
        "off_the_leash_detected": bool(off),
        "sessions": [v.to_dict() for v in verdicts],
    }
