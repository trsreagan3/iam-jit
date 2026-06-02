# #722 / BUILD-1 — pure-function differential audit.
"""Pure-function diff between two OCSF event streams.

No I/O, no LLM, no inference. Every metric in the output is countable
off the input event stream; every IAM policy emitted is a real
``Version: 2012-10-17`` document or an honestly-empty placeholder with
a ``cannot_narrow_reason`` field set.

The module is intentionally a single file so the import graph stays
trivial (the audit-extract module imports it laterally for the
permission-aggregate shape) and the test harness can reach every
helper without crossing package boundaries.
"""

from __future__ import annotations

import dataclasses
import typing


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SessionSummary:
    """High-level descriptor of one session's contribution."""

    session_id: str
    events_analyzed: int
    bouncers_observed: tuple[str, ...]
    time_window: dict[str, str]

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "session_id": self.session_id,
            "events_analyzed": self.events_analyzed,
            "bouncers_observed": list(self.bouncers_observed),
            "time_window": dict(self.time_window),
        }


@dataclasses.dataclass(frozen=True)
class PermissionDeltaRow:
    """One action that appeared in exactly one session."""

    action: str
    resources: tuple[str, ...]
    count: int

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "action": self.action,
            "resources": list(self.resources),
            "count": self.count,
        }


@dataclasses.dataclass(frozen=True)
class PermissionIntersectionRow:
    """One action that both sessions invoked. Surfaces per-side
    resources + counts so resource-scope narrowing is visible."""

    action: str
    resources_a: tuple[str, ...]
    resources_b: tuple[str, ...]
    count_a: int
    count_b: int

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "action": self.action,
            "resources_a": list(self.resources_a),
            "resources_b": list(self.resources_b),
            "count_a": self.count_a,
            "count_b": self.count_b,
        }


@dataclasses.dataclass(frozen=True)
class PermissionDelta:
    only_in_a: tuple[PermissionDeltaRow, ...]
    only_in_b: tuple[PermissionDeltaRow, ...]
    intersection: tuple[PermissionIntersectionRow, ...]

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "only_in_a": [r.as_dict() for r in self.only_in_a],
            "only_in_b": [r.as_dict() for r in self.only_in_b],
            "intersection": [r.as_dict() for r in self.intersection],
        }


@dataclasses.dataclass(frozen=True)
class DecisionDelta:
    a: dict[str, typing.Any]
    b: dict[str, typing.Any]
    delta: dict[str, typing.Any]

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "a": dict(self.a),
            "b": dict(self.b),
            "delta": dict(self.delta),
        }


@dataclasses.dataclass(frozen=True)
class BehavioralDelta:
    a: dict[str, int]
    b: dict[str, int]
    delta: dict[str, int]

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "a": dict(self.a),
            "b": dict(self.b),
            "delta": dict(self.delta),
        }


@dataclasses.dataclass(frozen=True)
class RiskDelta:
    """Per-side anomaly summary + delta, or ``unavailable`` with a
    reason. Per [[scorer-is-ground-truth]] we never tune the scorer to
    make the delta look better; if it can't score, we say so."""

    a: dict[str, typing.Any] | None
    b: dict[str, typing.Any] | None
    delta: dict[str, typing.Any] | None
    reason: str | None = None
    """When non-None, scoring was not available (e.g. no baseline for
    this bouncer's protocol). Honest signal per
    [[ibounce-honest-positioning]]."""

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "a": dict(self.a) if self.a is not None else None,
            "b": dict(self.b) if self.b is not None else None,
            "delta": dict(self.delta) if self.delta is not None else None,
            "reason": self.reason,
        }


@dataclasses.dataclass(frozen=True)
class NarrowingResult:
    strategy: str
    policy: dict[str, typing.Any]
    action_count: int
    cannot_narrow_reason: str | None
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "strategy": self.strategy,
            "policy": dict(self.policy),
            "action_count": self.action_count,
            "cannot_narrow_reason": self.cannot_narrow_reason,
            "notes": list(self.notes),
        }


@dataclasses.dataclass(frozen=True)
class AgentDiff:
    sessions: dict[str, SessionSummary]
    permission_delta: PermissionDelta
    decision_delta: DecisionDelta
    behavioral_delta: BehavioralDelta
    risk_delta: RiskDelta
    narrowing: NarrowingResult
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "sessions": {k: v.as_dict() for k, v in self.sessions.items()},
            "permission_delta": self.permission_delta.as_dict(),
            "decision_delta": self.decision_delta.as_dict(),
            "behavioral_delta": self.behavioral_delta.as_dict(),
            "risk_delta": self.risk_delta.as_dict(),
            "narrowing": self.narrowing.as_dict(),
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Event-walking helpers (lifted from audit_extract.extractor so the diff
# module has no hard dep on it; the two pieces of behaviour drift
# independently)
# ---------------------------------------------------------------------------


def _walk(ev: dict[str, typing.Any], path: str) -> typing.Any:
    cur: typing.Any = ev
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def _event_action(ev: dict[str, typing.Any]) -> str | None:
    """Return ``service:Action`` form. Mirrors
    :func:`iam_jit.audit_extract.extractor._event_action`."""
    op = _walk(ev, "api.operation")
    if isinstance(op, str) and ":" in op:
        return op
    service = _walk(ev, "api.service.name")
    if isinstance(op, str) and isinstance(service, str) and op:
        return f"{service}:{op}"
    return None


def _event_resources(ev: dict[str, typing.Any]) -> list[str]:
    """Best-effort resource extraction. Mirrors the audit-extract
    helper so the agent-diff resource shape matches the resource
    aggregates surfaced by ``bounce_extract_permissions_from_audit``."""
    out: list[str] = []
    resources = ev.get("resources")
    if isinstance(resources, list):
        for r in resources:
            if not isinstance(r, dict):
                continue
            cand = r.get("uid") or r.get("name")
            if isinstance(cand, str) and cand:
                out.append(cand)
    if out:
        return out
    # Also check api.resources (some bouncers nest under api.)
    api_resources = _walk(ev, "api.resources")
    if isinstance(api_resources, list):
        for r in api_resources:
            if not isinstance(r, dict):
                continue
            cand = r.get("uid") or r.get("name")
            if isinstance(cand, str) and cand:
                out.append(cand)
    if out:
        return out
    dst = ev.get("dst_endpoint")
    if isinstance(dst, dict):
        host = dst.get("hostname") or dst.get("ip")
        if isinstance(host, str) and host:
            out.append(host)
    return out


def _event_verdict(ev: dict[str, typing.Any]) -> str | None:
    v = _walk(ev, "unmapped.iam_jit.verdict")
    if isinstance(v, str):
        v = v.strip().lower()
        if v in ("allow", "deny"):
            return v
    return None


def _event_deny_reason(ev: dict[str, typing.Any]) -> str | None:
    """Best-effort deny-reason extraction. Bouncers populate one of a
    handful of paths; we try them in order. Returned ``None`` when no
    reason field is present (silent deny — the diff just doesn't
    contribute that side a reason)."""
    for path in (
        "unmapped.iam_jit.deny_reason",
        "unmapped.iam_jit.reason",
        "finding_info.title",
    ):
        v = _walk(ev, path)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _event_principal(ev: dict[str, typing.Any]) -> str | None:
    """Distinct-principal counter input. Tries the canonical OCSF
    fields ``actor.user.uid`` / ``actor.user.name`` before falling
    back to the unmapped agent block."""
    for path in (
        "actor.user.uid",
        "actor.user.name",
        "unmapped.iam_jit.agent.name",
        "unmapped.iam_jit.principal",
    ):
        v = _walk(ev, path)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _event_host(ev: dict[str, typing.Any]) -> str | None:
    h = _walk(ev, "dst_endpoint.hostname")
    if isinstance(h, str) and h.strip():
        return h.strip()
    return None


def _event_bouncer(ev: dict[str, typing.Any]) -> str | None:
    """The fan-out stamps ``_bouncer`` on every event so the merge
    layer can group by source bouncer without re-walking metadata."""
    b = ev.get("_bouncer")
    if isinstance(b, str) and b.strip():
        return b.strip()
    name = _walk(ev, "metadata.product.name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return None


# ---------------------------------------------------------------------------
# Per-section computation
# ---------------------------------------------------------------------------


def _aggregate_by_action(
    events: typing.Sequence[dict[str, typing.Any]],
) -> dict[str, dict[str, typing.Any]]:
    """Return ``{action: {resources: set, count: int}}``. Used by both
    permission delta and narrowing; lifted out so the two paths see
    the same aggregation."""
    out: dict[str, dict[str, typing.Any]] = {}
    for ev in events:
        action = _event_action(ev)
        if not action:
            continue
        bucket = out.setdefault(action, {"resources": set(), "count": 0})
        bucket["count"] += 1
        for r in _event_resources(ev):
            bucket["resources"].add(r)
    return out


def compute_permission_delta(
    events_a: typing.Sequence[dict[str, typing.Any]],
    events_b: typing.Sequence[dict[str, typing.Any]],
) -> PermissionDelta:
    """Pure: actions per side, only-in-X, intersection with per-side
    resources + counts.

    Output ordering is deterministic (alphabetical on action,
    resources) so the result is snapshot-testable. Empty sides surface
    as empty tuples — never None, never invented filler rows.
    """
    agg_a = _aggregate_by_action(events_a)
    agg_b = _aggregate_by_action(events_b)
    actions_a = set(agg_a.keys())
    actions_b = set(agg_b.keys())

    only_a_actions = sorted(actions_a - actions_b)
    only_b_actions = sorted(actions_b - actions_a)
    inter_actions = sorted(actions_a & actions_b)

    only_in_a = tuple(
        PermissionDeltaRow(
            action=a,
            resources=tuple(sorted(agg_a[a]["resources"])),
            count=int(agg_a[a]["count"]),
        )
        for a in only_a_actions
    )
    only_in_b = tuple(
        PermissionDeltaRow(
            action=a,
            resources=tuple(sorted(agg_b[a]["resources"])),
            count=int(agg_b[a]["count"]),
        )
        for a in only_b_actions
    )
    intersection = tuple(
        PermissionIntersectionRow(
            action=a,
            resources_a=tuple(sorted(agg_a[a]["resources"])),
            resources_b=tuple(sorted(agg_b[a]["resources"])),
            count_a=int(agg_a[a]["count"]),
            count_b=int(agg_b[a]["count"]),
        )
        for a in inter_actions
    )
    return PermissionDelta(
        only_in_a=only_in_a,
        only_in_b=only_in_b,
        intersection=intersection,
    )


def _decision_summary(
    events: typing.Sequence[dict[str, typing.Any]],
) -> dict[str, typing.Any]:
    allow = 0
    deny = 0
    reasons: set[str] = set()
    for ev in events:
        v = _event_verdict(ev)
        if v == "allow":
            allow += 1
        elif v == "deny":
            deny += 1
            r = _event_deny_reason(ev)
            if r:
                reasons.add(r)
    return {
        "allow_count": allow,
        "deny_count": deny,
        "distinct_deny_reasons": sorted(reasons),
    }


def compute_decision_delta(
    events_a: typing.Sequence[dict[str, typing.Any]],
    events_b: typing.Sequence[dict[str, typing.Any]],
) -> DecisionDelta:
    """Allow/deny counts + symmetric difference on deny-reason sets."""
    sa = _decision_summary(events_a)
    sb = _decision_summary(events_b)
    set_a = set(sa["distinct_deny_reasons"])
    set_b = set(sb["distinct_deny_reasons"])
    delta = {
        "allow_count_delta": sb["allow_count"] - sa["allow_count"],
        "deny_count_delta": sb["deny_count"] - sa["deny_count"],
        "deny_reasons_only_in_a": sorted(set_a - set_b),
        "deny_reasons_only_in_b": sorted(set_b - set_a),
    }
    return DecisionDelta(a=sa, b=sb, delta=delta)


def _behavioral_summary(
    events: typing.Sequence[dict[str, typing.Any]],
) -> dict[str, int]:
    """Pure: countable behavioral fingerprint metrics. Per
    [[ibounce-honest-positioning]] every metric here is derivable
    directly from the event stream; we never invent "efficiency"
    or "intent" — those are operator judgements."""
    actions: set[str] = set()
    principals: set[str] = set()
    resources: set[str] = set()
    hosts: set[str] = set()
    total = 0
    for ev in events:
        total += 1
        a = _event_action(ev)
        if a:
            actions.add(a)
        p = _event_principal(ev)
        if p:
            principals.add(p)
        for r in _event_resources(ev):
            resources.add(r)
        h = _event_host(ev)
        if h:
            hosts.add(h)
    return {
        "total_calls": total,
        "distinct_actions": len(actions),
        "distinct_principals": len(principals),
        "distinct_resources": len(resources),
        "distinct_hosts": len(hosts),
    }


def compute_behavioral_delta(
    events_a: typing.Sequence[dict[str, typing.Any]],
    events_b: typing.Sequence[dict[str, typing.Any]],
) -> BehavioralDelta:
    sa = _behavioral_summary(events_a)
    sb = _behavioral_summary(events_b)
    delta = {k + "_delta": sb[k] - sa[k] for k in sa}
    return BehavioralDelta(a=sa, b=sb, delta=delta)


def _risk_summary_from_events(
    events: typing.Sequence[dict[str, typing.Any]],
) -> dict[str, typing.Any] | None:
    """Read pre-scored anomaly fields off events.

    The diff module does NOT call the scorer itself — that would
    require materialising a baseline, which is bouncer-specific state.
    Instead we read the score off events that already carry it (set
    by the per-bouncer anomaly-detection hook per #469 Phase H).
    Events without a pre-computed score don't contribute.

    Returns ``None`` when zero events carry an anomaly_score — signals
    the risk-delta caller to surface
    ``reason: "anomaly_scoring_unavailable_for_protocol"``.
    """
    scores: list[float] = []
    anomalous = 0
    for ev in events:
        score = _walk(ev, "unmapped.iam_jit.anomaly_score")
        if isinstance(score, (int, float)):
            scores.append(float(score))
            verdict = _walk(ev, "unmapped.iam_jit.anomaly_verdict")
            if isinstance(verdict, str) and verdict.lower() == "anomalous":
                anomalous += 1
    if not scores:
        return None
    return {
        "max_anomaly_score": round(max(scores), 4),
        "mean_anomaly_score": round(sum(scores) / len(scores), 4),
        "anomalous_event_count": anomalous,
        "scored_event_count": len(scores),
    }


def compute_risk_delta(
    events_a: typing.Sequence[dict[str, typing.Any]],
    events_b: typing.Sequence[dict[str, typing.Any]],
) -> RiskDelta:
    """Risk delta from pre-scored events. When neither side has any
    pre-scored events, surface ``reason`` instead of inventing scores.
    """
    sa = _risk_summary_from_events(events_a)
    sb = _risk_summary_from_events(events_b)
    if sa is None and sb is None:
        return RiskDelta(
            a=None, b=None, delta=None,
            reason="anomaly_scoring_unavailable_for_protocol",
        )
    # When one side has scores and the other doesn't, we still report
    # the side that does — the delta is just None + a note.
    if sa is None or sb is None:
        return RiskDelta(
            a=sa, b=sb, delta=None,
            reason="one_side_lacks_anomaly_scores",
        )
    delta = {
        "max_score_delta": round(
            sb["max_anomaly_score"] - sa["max_anomaly_score"], 4,
        ),
        "mean_score_delta": round(
            sb["mean_anomaly_score"] - sa["mean_anomaly_score"], 4,
        ),
        "anomalous_count_delta": (
            sb["anomalous_event_count"] - sa["anomalous_event_count"]
        ),
    }
    return RiskDelta(a=sa, b=sb, delta=delta, reason=None)


# ---------------------------------------------------------------------------
# Narrowing — real IAM JSON or honest empty
# ---------------------------------------------------------------------------


_NARROW_STRATEGIES = frozenset({"intersection", "union", "left", "right"})


def build_narrowing_policy(
    events_a: typing.Sequence[dict[str, typing.Any]],
    events_b: typing.Sequence[dict[str, typing.Any]],
    *,
    strategy: str = "intersection",
) -> NarrowingResult:
    """Build a real IAM policy document per the requested strategy.

    Strategies:

    * ``intersection`` — actions touched by both sessions; per-action
      resources are the UNION of (resources_a ∪ resources_b) so the
      resulting policy still admits both sides' real behaviour. This
      is the operator-friendly default because narrowing to
      ``resources_a ∩ resources_b`` regularly produces an empty
      resource list when the two sides used different bucket prefixes.
    * ``union`` — every action from either session; resources = union.
    * ``left`` — only A's actions + resources.
    * ``right`` — only B's actions + resources.

    Empty result → ``policy.Statement = []`` +
    ``cannot_narrow_reason`` set (never an invented Allow). Per
    [[ibounce-honest-positioning]] + [[no-nl-synthesis]] we never
    sketch a "probably tight" policy.
    """
    if strategy not in _NARROW_STRATEGIES:
        raise ValueError(
            f"unknown narrowing strategy {strategy!r}; "
            f"choose one of {sorted(_NARROW_STRATEGIES)}",
        )
    agg_a = _aggregate_by_action(events_a)
    agg_b = _aggregate_by_action(events_b)
    actions_a = set(agg_a.keys())
    actions_b = set(agg_b.keys())

    if strategy == "intersection":
        chosen = sorted(actions_a & actions_b)
    elif strategy == "union":
        chosen = sorted(actions_a | actions_b)
    elif strategy == "left":
        chosen = sorted(actions_a)
    else:  # right
        chosen = sorted(actions_b)

    statements: list[dict[str, typing.Any]] = []
    notes: list[str] = []
    for action in chosen:
        if strategy in ("intersection", "union"):
            res_set: set[str] = set()
            if action in agg_a:
                res_set |= agg_a[action]["resources"]
            if action in agg_b:
                res_set |= agg_b[action]["resources"]
        elif strategy == "left":
            res_set = set(agg_a[action]["resources"])
        else:
            res_set = set(agg_b[action]["resources"])
        # Resources may be empty when an event had no named resource.
        # Surface "*" honestly so the policy is well-formed; flag the
        # action in notes so the operator knows resource-scope was
        # observed broadly.
        if not res_set:
            res_set = {"*"}
            notes.append(
                f"{action}: no specific resource observed in either "
                "session; resource scoped as '*'"
            )
        statements.append({
            "Effect": "Allow",
            "Action": [action],
            "Resource": sorted(res_set),
        })

    cannot_narrow_reason: str | None = None
    if not statements:
        if strategy == "intersection":
            cannot_narrow_reason = (
                "no overlapping actions between sessions; "
                "use --narrow union to cover either side"
            )
        elif strategy == "union":
            cannot_narrow_reason = "no actions observed in either session"
        else:
            cannot_narrow_reason = (
                f"no actions observed in session {strategy!r}"
            )

    policy = {
        "Version": "2012-10-17",
        "Statement": statements,
    }
    return NarrowingResult(
        strategy=strategy,
        policy=policy,
        action_count=len(statements),
        cannot_narrow_reason=cannot_narrow_reason,
        notes=tuple(notes),
    )


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------


def _summarise_session(
    session_id: str,
    events: typing.Sequence[dict[str, typing.Any]],
    *,
    time_window: dict[str, str] | None = None,
) -> SessionSummary:
    bouncers: set[str] = set()
    for ev in events:
        b = _event_bouncer(ev)
        if b:
            bouncers.add(b)
    return SessionSummary(
        session_id=session_id,
        events_analyzed=len(events),
        bouncers_observed=tuple(sorted(bouncers)),
        time_window=dict(time_window or {"from": "", "to": ""}),
    )


def compute_agent_diff(
    *,
    session_a_id: str,
    events_a: typing.Sequence[dict[str, typing.Any]],
    session_b_id: str,
    events_b: typing.Sequence[dict[str, typing.Any]],
    narrow: str = "intersection",
    time_window_a: dict[str, str] | None = None,
    time_window_b: dict[str, str] | None = None,
    notes: typing.Sequence[str] = (),
) -> AgentDiff:
    """Compose the four sub-deltas + narrowing into one ``AgentDiff``.

    Pure function — no I/O. The CLI / MCP wrappers fetch events via
    :func:`fetch_session_events_via_fanout` and pass them in.
    """
    summary_a = _summarise_session(
        session_a_id, events_a, time_window=time_window_a,
    )
    summary_b = _summarise_session(
        session_b_id, events_b, time_window=time_window_b,
    )
    return AgentDiff(
        sessions={"a": summary_a, "b": summary_b},
        permission_delta=compute_permission_delta(events_a, events_b),
        decision_delta=compute_decision_delta(events_a, events_b),
        behavioral_delta=compute_behavioral_delta(events_a, events_b),
        risk_delta=compute_risk_delta(events_a, events_b),
        narrowing=build_narrowing_policy(
            events_a, events_b, strategy=narrow,
        ),
        notes=tuple(notes),
    )
