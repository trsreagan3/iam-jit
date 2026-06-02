# #723 / BUILD-2 — Agent flight recorder: cross-bouncer correlation
# timeline assembly (pure-function core; no I/O).
"""Stitch ONE agent session across all four bouncers (AWS / K8s / SQL /
HTTP) plus the iam-jit serve surface into a single ordered TIMELINE.

This module is the testable, I/O-free CORE. The CLI
(:mod:`iam_jit.cli_flight_recorder`) fetches the events via the SAME
cross-bouncer fan-out the rest of the audit-adjacent family uses
(:func:`iam_jit.agent_diff.fetch_session_events_via_fanout` →
``iam-jit audit query``'s per-bouncer fetcher) and hands the merged
event list + per-bouncer notes to :func:`assemble_timeline` here.

Why this is defensible (PDF §A-Compete, differentiation 5/5): AgentOps
records an agent's LLM reasoning chain, but nobody correlates an
agent's EXTERNAL ACTIONS across four protocols. We do, because the
Bounce suite already stamps ``unmapped.iam_jit.agent.session_id`` on
every protocol's OCSF audit event — the correlation key is shared.

Honesty (per [[ibounce-honest-positioning]]): a timeline that quietly
dropped an unreachable bouncer would imply completeness it can't
promise. So the assembled timeline carries a ``coverage`` block that
names every bouncer probed, which ones answered, which were
unreachable (with the operator-readable reason), and a ``partial``
flag + ``gaps`` list. The replay UI surfaces these so the operator
never mistakes "no events from kbounce" for "kbounce wasn't reachable".

Field extraction REUSES the agent-diff event-walk helpers
(:func:`iam_jit.agent_diff.diff._event_action` etc.) so the timeline's
notion of action / resource / verdict / reason / principal matches the
rest of the suite exactly and the two can never drift.

Closed-field discipline (same as ABOM, per
[[opt-in-feedback-pipeline]] sanitizer posture): the per-step view is
built from a FIXED allow-list of OCSF fields — action, decision,
reason, resources, principal, status, bouncer, protocol, timestamp.
Free-form event bodies are NOT echoed into the step, so a secret that
landed in some exotic event field can't leak through the timeline.
"""

from __future__ import annotations

import datetime as _dt
import typing

from .agent_diff.diff import (
    _event_action,
    _event_deny_reason,
    _event_principal,
    _event_resources,
    _event_verdict,
    _walk,
)

# Map the fan-out's ``_bouncer`` stamp to the protocol the bouncer
# guards. Used for the UI's "which protocol" column + the per-protocol
# coverage summary. iam-jit serve is the control-plane surface (#620),
# not a wire protocol, so it gets its own label.
_BOUNCER_PROTOCOL: dict[str, str] = {
    "ibounce": "AWS",
    "kbounce": "K8s",
    "dbounce": "SQL",
    "gbounce": "HTTP",
    "iam-jit-serve": "iam-jit",
}

TIMELINE_SCHEMA_VERSION = "flight-recorder/1"


def _protocol_for(bouncer: str) -> str:
    """Best-effort protocol label for a bouncer name. Unknown names
    (custom ``name=URL`` overrides) fall through to the raw name so the
    UI shows *something* honest rather than mislabeling the protocol."""
    return _BOUNCER_PROTOCOL.get(bouncer, bouncer or "unknown")


def _event_time_ms(ev: dict[str, typing.Any]) -> int | None:
    """Normalize an OCSF event's ``time`` to integer epoch
    milliseconds. The suite emits ``time`` as either a number (already
    ms) or an ISO-8601 / RFC-3339 string. Returns ``None`` when the
    field is missing or unparseable — those events sort LAST and are
    flagged in the timeline gaps (per the honesty bar, a step with no
    timestamp is surfaced, not silently dropped)."""
    t = ev.get("time")
    if isinstance(t, bool):  # bool is an int subclass — reject explicitly
        return None
    if isinstance(t, (int, float)):
        return int(t)
    if isinstance(t, str) and t.strip():
        s = t.strip()
        # OCSF uses RFC-3339; Python <3.11 chokes on trailing 'Z'.
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = _dt.datetime.fromisoformat(s)
        except ValueError:
            return None  # noqa: SD-4 unparseable time is INTENTIONALLY conflated with missing time — both mean "no usable timestamp"; the step is kept, flagged has_timestamp=False, sorted LAST, and surfaced in coverage.gaps (honest, never silently dropped)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return int(dt.timestamp() * 1000)
    return None


def _iso_ms(ms: int | None) -> str | None:
    """Render epoch-ms back to a UTC ISO-8601 string for display."""
    if ms is None:
        return None
    dt = _dt.datetime.fromtimestamp(ms / 1000.0, tz=_dt.timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _event_session_id(ev: dict[str, typing.Any]) -> str | None:
    sid = _walk(ev, "unmapped.iam_jit.agent.session_id")
    if isinstance(sid, str) and sid.strip():
        return sid.strip()
    return None


def _event_status(ev: dict[str, typing.Any]) -> str | None:
    """OCSF ``status`` (Success / Failure / ...) — the outcome of the
    underlying call as the bouncer observed it, distinct from the
    allow/deny DECISION. Falls back to the numeric status_id label."""
    s = ev.get("status")
    if isinstance(s, str) and s.strip():
        return s.strip()
    sid = ev.get("status_id")
    if isinstance(sid, int):
        return {0: "Unknown", 1: "Success", 2: "Failure"}.get(sid, f"status_id={sid}")
    return None


def _event_iam_context(ev: dict[str, typing.Any]) -> str | None:
    """The IAM / role context the action ran under, for the per-step
    detail pane. Closed-field: only the role-ish identifiers, never the
    whole actor block (which can carry arbitrary unmapped values)."""
    for path in (
        "unmapped.iam_jit.role",
        "unmapped.iam_jit.role_arn",
        "actor.user.uid",
        "actor.session.issuer",
    ):
        v = _walk(ev, path)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _normalize_step(ev: dict[str, typing.Any], *, index: int) -> dict[str, typing.Any]:
    """Project ONE OCSF event into a fixed-shape timeline step.

    Closed-field allow-list: every key here is an explicitly chosen,
    operator-meaningful field. The raw event body is intentionally NOT
    attached, so no exotic unmapped field can leak a secret through the
    timeline (same discipline as the ABOM exporter)."""
    bouncer = str(ev.get("_bouncer") or "unknown")
    decision = _event_verdict(ev)  # "allow" | "deny" | None
    ms = _event_time_ms(ev)
    return {
        "index": index,
        "bouncer": bouncer,
        "protocol": _protocol_for(bouncer),
        "time_ms": ms,
        "time": _iso_ms(ms),
        "action": _event_action(ev) or _action_fallback(ev),
        "decision": decision or "unknown",
        "reason": _event_deny_reason(ev),
        "resources": _event_resources(ev),
        "principal": _event_principal(ev),
        "iam_context": _event_iam_context(ev),
        "status": _event_status(ev),
        "has_timestamp": ms is not None,
    }


def _action_fallback(ev: dict[str, typing.Any]) -> str:
    """When the canonical ``service:Action`` form isn't present, fall
    back to OCSF ``api.operation`` / ``activity_name`` so the step still
    names *what happened* rather than showing a blank."""
    op = _walk(ev, "api.operation")
    if isinstance(op, str) and op.strip():
        return op.strip()
    act = ev.get("activity_name")
    if isinstance(act, str) and act.strip():
        return act.strip()
    return "(unknown action)"


def _stable_sort_key(step: dict[str, typing.Any]) -> tuple[int, int, str, int]:
    """Order by timestamp ascending; timeless steps sort LAST. Stable
    tiebreak so identical-timestamp steps across bouncers keep a
    deterministic order regardless of fan-out completion order:
    (has_time, time_ms, bouncer, original_index)."""
    has_time = 0 if step["has_timestamp"] else 1  # timestamped first
    ms = step["time_ms"] if step["time_ms"] is not None else 0
    return (has_time, ms, step["bouncer"], step["index"])


def assemble_timeline(
    *,
    session_id: str,
    events: typing.Sequence[dict[str, typing.Any]],
    notes_by_bouncer: typing.Mapping[str, str],
    since: str | None = None,
    until: str | None = None,
) -> dict[str, typing.Any]:
    """Assemble the normalized, ordered cross-bouncer timeline.

    ``events`` is the merged list returned by
    :func:`iam_jit.agent_diff.fetch_session_events_via_fanout` (each
    event carries the ``_bouncer`` stamp). ``notes_by_bouncer`` is the
    SECOND return value of that fan-out:
    ``{bouncer_name: error_message_or_empty}`` — an empty string means
    the bouncer answered, a non-empty string is the operator-readable
    unreachable / HTTP-error reason.

    Returns a JSON-serializable dict with two top-level pieces:

    * ``steps`` — the ordered list of normalized per-step views.
    * ``coverage`` / ``meta`` — the honesty block: which bouncers were
      probed, which answered, which were unreachable + why, whether the
      timeline is ``partial``, and the ``gaps`` list.
    """
    sid = (session_id or "").strip()

    steps: list[dict[str, typing.Any]] = []
    for i, ev in enumerate(events):
        # Defensive: the fan-out is server-side-filtered by session, but
        # a buggy / permissive bouncer could echo a non-matching event.
        # Drop anything whose own session id contradicts the query so a
        # cross-session leak can't pollute the replay. Events with NO
        # session id are kept (some surfaces don't stamp it) but flagged.
        ev_sid = _event_session_id(ev)
        if ev_sid is not None and sid and ev_sid != sid:
            continue
        steps.append(_normalize_step(ev, index=i))

    steps.sort(key=_stable_sort_key)
    # Re-index after sort so ``index`` is the timeline position (what the
    # UI scrubber addresses), and stash the original arrival order for
    # debugging the tiebreak.
    for pos, step in enumerate(steps):
        step["arrival_index"] = step["index"]
        step["index"] = pos

    # ---- Coverage / honesty block --------------------------------------
    reachable: list[str] = []
    unreachable: list[dict[str, str]] = []
    for bouncer in sorted(notes_by_bouncer):
        err = notes_by_bouncer[bouncer]
        if err:
            unreachable.append({"bouncer": bouncer, "reason": err})
        else:
            reachable.append(bouncer)

    contributing = sorted({s["bouncer"] for s in steps})
    # A reachable bouncer that returned zero events is honest signal too:
    # the operator should see "kbounce: reachable, 0 events" so they know
    # the gap is genuine, not a probe failure.
    reachable_no_events = sorted(
        b for b in reachable if b not in set(contributing)
    )

    gaps: list[str] = []
    for u in unreachable:
        gaps.append(
            f"{u['bouncer']} unreachable ({u['reason']}) — its slice of "
            f"the session is MISSING from this timeline"
        )
    for b in reachable_no_events:
        gaps.append(
            f"{b} reachable but returned 0 events for this session "
            f"(genuine gap, not a probe failure)"
        )
    timeless = [s for s in steps if not s["has_timestamp"]]
    if timeless:
        gaps.append(
            f"{len(timeless)} step(s) had no parseable timestamp and are "
            f"ordered LAST (their true position in the session is unknown)"
        )

    per_protocol: dict[str, int] = {}
    for s in steps:
        per_protocol[s["protocol"]] = per_protocol.get(s["protocol"], 0) + 1

    first_ms = next((s["time_ms"] for s in steps if s["has_timestamp"]), None)
    last_ms = next(
        (s["time_ms"] for s in reversed(steps) if s["has_timestamp"]), None
    )

    coverage = {
        "bouncers_probed": sorted(notes_by_bouncer),
        "bouncers_reachable": reachable,
        "bouncers_unreachable": unreachable,
        "bouncers_contributing": contributing,
        "bouncers_reachable_no_events": reachable_no_events,
        # The timeline is PARTIAL whenever any probed bouncer didn't
        # answer — we cannot claim to have the whole session.
        "partial": bool(unreachable),
        "gaps": gaps,
    }

    return {
        "schema": TIMELINE_SCHEMA_VERSION,
        "session_id": sid,
        "step_count": len(steps),
        "steps": steps,
        "coverage": coverage,
        "meta": {
            "since": since,
            "until": until,
            "events_analyzed": len(events),
            "protocols_represented": sorted(per_protocol),
            "steps_per_protocol": per_protocol,
            "first_step_time": _iso_ms(first_ms),
            "last_step_time": _iso_ms(last_ms),
        },
    }
