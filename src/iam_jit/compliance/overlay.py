# ADOPT-2 / #716 — compliance overlay projection (pure functions).
"""Project a merged OCSF event stream for one session into:

* an **overlay** — every decision event tagged with the
  ``compliance_tags`` it touches (e.g.
  ``["OWASP-AGENTIC-T01", "MITRE-T1078", "NIST-AC-6", ...]``), and
* a **coverage report** — per-framework rollup of which controls the
  session's activity touched, how many events touched each, and the
  honest partial-coverage note.

No I/O, no LLM, no inference. The event-walking helpers mirror
:mod:`iam_jit.agent_diff.diff` and :mod:`iam_jit.abom.builder` so the
overlay's notion of an action / verdict / protocol matches every other
audit surface (no divergent extraction). The CLI / MCP wrappers fetch
the merged stream via
:func:`iam_jit.agent_diff.fetch_session_events_via_fanout` and hand it
to :func:`build_overlay`.

Honesty per [[ibounce-honest-positioning]]: an empty session yields an
empty-but-valid report with ``is_partial=True``; per-framework
coverage gaps are stated, never hidden; tags are emitted ONLY where a
mapping rule genuinely fired.
"""

from __future__ import annotations

import dataclasses
import typing

# Lateral reuse: the SAME event-walking the agent-diff surface uses.
from ..agent_diff.diff import (
    _event_action,
    _event_resources,
    _event_verdict,
    _walk,
)
from . import mapping
from .mapping import (
    FRAMEWORK_IDS,
    MAPPING_RULES,
    SIGNAL_ACTION_RE,
    SIGNAL_ALLOW,
    SIGNAL_ANOMALOUS,
    SIGNAL_ANY,
    SIGNAL_DENY,
    SIGNAL_MFA_GATED,
    MappingRule,
)


# ---------------------------------------------------------------------------
# Signal detectors (pure; one event in)
# ---------------------------------------------------------------------------


def _event_protocol(ev: dict[str, typing.Any]) -> str:
    """Best-effort protocol classification: ``aws`` / ``k8s`` / ``sql``
    / ``http`` / ``unknown``.

    Used only to label the overlay (rules currently fire cross-protocol
    via their action regexes). Detection mirrors the field paths the
    ABOM builder probes so the protocol notion does not drift.
    """
    # Explicit bouncer/product stamp wins when present.
    b = ev.get("_bouncer")
    if isinstance(b, str):
        bl = b.strip().lower()
        if bl in ("ibounce", "iam-jit", "iam_jit"):
            return "aws"
        if bl == "kbounce":
            return "k8s"
        if bl == "dbounce":
            return "sql"
        if bl == "gbounce":
            return "http"
    # Structural fallbacks.
    if _walk(ev, "unmapped.iam_jit.database") or _walk(ev, "dst_endpoint.svc_name"):
        return "sql"
    if _walk(ev, "unmapped.iam_jit.namespace") or _walk(ev, "unmapped.iam_jit.cluster"):
        return "k8s"
    if _walk(ev, "http_request.http_method"):
        return "http"
    action = _event_action(ev)
    if isinstance(action, str) and action.startswith(
        ("iam:", "sts:", "s3:", "ec2:", "dynamodb:", "kms:",
         "secretsmanager:", "ssm:")
    ):
        return "aws"
    if _walk(ev, "dst_endpoint.hostname"):
        return "http"
    return "unknown"


def _event_anomalous(ev: dict[str, typing.Any]) -> bool:
    """True when the event carries a pre-computed anomalous verdict
    (set by the per-bouncer anomaly hook, #469 Phase H). The overlay
    does NOT score — it reads the verdict the same way agent-diff's
    risk delta does, per [[scorer-is-ground-truth]]."""
    v = _walk(ev, "unmapped.iam_jit.anomaly_verdict")
    return isinstance(v, str) and v.strip().lower() == "anomalous"


def _event_mfa_present(ev: dict[str, typing.Any]) -> bool:
    """True when the event records an MFA-present assertion for the
    grant. Probes the canonical iam-jit field + the AWS condition-key
    shape some bouncers copy through."""
    for path in (
        "unmapped.iam_jit.mfa_present",
        "unmapped.iam_jit.mfa",
        "unmapped.aws.MultiFactorAuthPresent",
    ):
        v = _walk(ev, path)
        if isinstance(v, bool):
            if v:
                return True
        elif isinstance(v, str) and v.strip().lower() in ("true", "yes", "1"):
            return True
    return False


def _rule_fires(rule: MappingRule, ev: dict[str, typing.Any]) -> bool:
    """Pure predicate: does ``rule`` apply to this event?

    Protocol restriction (when the rule names protocols) is applied
    first, then the signal-kind match. ``action_regex`` rules require a
    non-None action that the compiled pattern matches.
    """
    if rule.protocols:
        if _event_protocol(ev) not in rule.protocols:
            return False
    verdict = _event_verdict(ev)
    if rule.signal == SIGNAL_ANY:
        # "any recorded decision" — require a verdict so we don't tag
        # heartbeats / non-decision telemetry.
        return verdict in ("allow", "deny")
    if rule.signal == SIGNAL_ALLOW:
        return verdict == "allow"
    if rule.signal == SIGNAL_DENY:
        return verdict == "deny"
    if rule.signal == SIGNAL_ANOMALOUS:
        return _event_anomalous(ev)
    if rule.signal == SIGNAL_MFA_GATED:
        return _event_mfa_present(ev)
    if rule.signal == SIGNAL_ACTION_RE:
        # Action-shape rules describe a gated DECISION's action; require
        # a recorded verdict so we don't tag non-decision telemetry
        # (consistent with the SIGNAL_ANY/ALLOW/DENY rules — "tagged
        # events == decisions").
        if verdict not in ("allow", "deny"):
            return False
        action = _event_action(ev)
        if not isinstance(action, str) or not action:
            return False
        return rule.action_pattern is not None and bool(
            rule.action_pattern.search(action)
        )
    return False


def tags_for_event(
    ev: dict[str, typing.Any],
    *,
    framework: str | None = None,
) -> tuple[list[str], list[str]]:
    """Return ``(compliance_tags, categories)`` for one event.

    ``compliance_tags`` is the sorted, de-duplicated list of control
    tags every firing rule maps to (filtered to ``framework`` when
    given). ``categories`` is the sorted list of the firing rules'
    operator-facing categories. Both empty when no rule fires.
    """
    tags: set[str] = set()
    categories: set[str] = set()
    for rule in MAPPING_RULES:
        if not _rule_fires(rule, ev):
            continue
        categories.add(rule.category)
        for c in rule.controls:
            if framework is None or mapping.CONTROLS[c].framework == framework:
                tags.add(c)
    return sorted(tags), sorted(categories)


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class TaggedEvent:
    """One audit event reduced to the overlay shape (we deliberately do
    NOT echo the whole raw event — the overlay is a tag projection, and
    re-emitting raw events risks leaking payload PII)."""

    action: str | None
    verdict: str | None
    protocol: str
    resources: tuple[str, ...]
    compliance_tags: tuple[str, ...]
    categories: tuple[str, ...]

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "action": self.action,
            "verdict": self.verdict,
            "protocol": self.protocol,
            "resources": list(self.resources),
            "compliance_tags": list(self.compliance_tags),
            "categories": list(self.categories),
        }


@dataclasses.dataclass(frozen=True)
class ControlCoverage:
    """How a session's activity touched one control."""

    control: str
    title: str
    framework: str
    event_count: int
    rationale: str

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "control": self.control,
            "title": self.title,
            "framework": self.framework,
            "event_count": self.event_count,
            "rationale": self.rationale,
        }


@dataclasses.dataclass(frozen=True)
class FrameworkCoverage:
    """Per-framework rollup."""

    framework: str
    name: str
    version: str
    controls_touched: tuple[ControlCoverage, ...]
    controls_touched_count: int
    controls_in_catalog: int
    partial_coverage_note: str
    # Catalog controls the session did NOT exercise — enumerated by id+title
    # so an auditor sees the GAPS by name, not just a count (UAT finding: a
    # ratio like "3 of 5 touched" hid which two controls were the gaps).
    controls_not_touched: tuple[dict[str, str], ...] = ()

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "framework": self.framework,
            "name": self.name,
            "version": self.version,
            "controls_touched": [c.as_dict() for c in self.controls_touched],
            "controls_touched_count": self.controls_touched_count,
            "controls_in_catalog": self.controls_in_catalog,
            "controls_not_touched": [dict(c) for c in self.controls_not_touched],
            "partial_coverage_note": self.partial_coverage_note,
        }


@dataclasses.dataclass(frozen=True)
class ComplianceOverlay:
    """The full overlay + coverage report for one session."""

    session_id: str
    events_analyzed: int
    framework_filter: str | None
    overlay: tuple[TaggedEvent, ...]
    coverage: tuple[FrameworkCoverage, ...]
    is_partial: bool
    partial_reasons: tuple[str, ...]
    disclaimer: str
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "session_id": self.session_id,
            "events_analyzed": self.events_analyzed,
            "framework_filter": self.framework_filter,
            "overlay": [e.as_dict() for e in self.overlay],
            "coverage": [c.as_dict() for c in self.coverage],
            "is_partial": self.is_partial,
            "partial_reasons": list(self.partial_reasons),
            "disclaimer": self.disclaimer,
            "notes": list(self.notes),
        }


_DISCLAIMER = (
    "This overlay maps ONLY the agent activity observed in the iam-jit "
    "audit log for this session+window to the framework controls that "
    "activity TOUCHES. It is a compliance EVIDENCE ON-RAMP, NOT a "
    "certification — evidence of technical-control exercise, NOT a "
    "compliance certification and NOT a proof of completeness. "
    "iam-jit-the-company holds no third-party attestations at v1.0 "
    "(see docs/compliance/COMPLIANCE-MAPPING.md). Audit gaps, short "
    "windows, or unreachable bouncers can omit real activity; "
    "per-framework controls outside the observable audit surface are "
    "out of scope (see each framework's partial_coverage_note)."
)


# ---------------------------------------------------------------------------
# Top-level builder
# ---------------------------------------------------------------------------


def build_overlay(
    *,
    session_id: str,
    events: typing.Sequence[dict[str, typing.Any]],
    framework: str | None = None,
    notes: typing.Sequence[str] = (),
) -> ComplianceOverlay:
    """Build the overlay + per-framework coverage report for a session.

    Pure function — ``events`` is the already-merged OCSF stream from
    the cross-bouncer fan-out. ``framework`` (when given) is one of
    :data:`iam_jit.compliance.mapping.FRAMEWORK_IDS`; it filters BOTH
    the per-event tags and the coverage report to that framework.

    Returns a :class:`ComplianceOverlay`. An empty session yields an
    empty overlay + zero-coverage frameworks, explicitly flagged
    ``is_partial`` per [[ibounce-honest-positioning]].
    """
    if framework is not None and framework not in mapping.FRAMEWORKS:
        raise ValueError(
            f"unknown framework {framework!r}; choose one of "
            f"{list(FRAMEWORK_IDS)}"
        )

    target_frameworks: tuple[str, ...] = (
        (framework,) if framework is not None else FRAMEWORK_IDS
    )

    tagged: list[TaggedEvent] = []
    # control -> count of events that touched it (within filter).
    control_counts: dict[str, int] = {}
    events_analyzed = 0

    for ev in events:
        if not isinstance(ev, dict):
            continue
        events_analyzed += 1
        tags, categories = tags_for_event(ev, framework=framework)
        if not tags:
            # No mapped control touched — still a real event, but it
            # carries no compliance tag. We omit it from the overlay
            # array (the overlay is the tagged-events view) but it
            # counted toward events_analyzed.
            continue
        for t in tags:
            control_counts[t] = control_counts.get(t, 0) + 1
        tagged.append(
            TaggedEvent(
                action=_event_action(ev),
                verdict=_event_verdict(ev),
                protocol=_event_protocol(ev),
                resources=tuple(_event_resources(ev)),
                compliance_tags=tuple(tags),
                categories=tuple(categories),
            )
        )

    # Per-framework coverage rollup.
    coverage: list[FrameworkCoverage] = []
    for fw in target_frameworks:
        catalog = mapping.controls_for_framework(fw)
        touched: list[ControlCoverage] = []
        not_touched: list[dict[str, str]] = []
        for ref in catalog:
            cnt = control_counts.get(ref.control, 0)
            if cnt <= 0:
                not_touched.append({"control": ref.control, "title": ref.title})
                continue
            touched.append(
                ControlCoverage(
                    control=ref.control,
                    title=ref.title,
                    framework=ref.framework,
                    event_count=cnt,
                    rationale=ref.rationale,
                )
            )
        meta = mapping.framework_meta(fw)
        coverage.append(
            FrameworkCoverage(
                framework=fw,
                name=meta["name"],
                version=meta["version"],
                controls_touched=tuple(touched),
                controls_touched_count=len(touched),
                controls_in_catalog=len(catalog),
                controls_not_touched=tuple(not_touched),
                partial_coverage_note=mapping.PARTIAL_COVERAGE_NOTES.get(fw, ""),
            )
        )

    # Honesty / partial-data determination.
    partial_reasons: list[str] = []
    if events_analyzed == 0:
        partial_reasons.append(
            "no_events_observed: the audit log returned zero events for "
            "this session in the queried window — this overlay maps "
            "nothing observed, NOT a proof the agent did nothing"
        )
    note_list = [n for n in notes if isinstance(n, str) and n.strip()]
    if note_list:
        partial_reasons.append(
            "bouncer_gaps: one or more bouncers were unreachable or "
            "errored during the query; their activity (if any) is "
            "absent from this overlay"
        )
    is_partial = bool(partial_reasons)

    return ComplianceOverlay(
        session_id=session_id,
        events_analyzed=events_analyzed,
        framework_filter=framework,
        overlay=tuple(tagged),
        coverage=tuple(coverage),
        is_partial=is_partial,
        partial_reasons=tuple(partial_reasons),
        disclaimer=_DISCLAIMER,
        notes=tuple(note_list),
    )


# ---------------------------------------------------------------------------
# Human summary renderer
# ---------------------------------------------------------------------------


def format_summary(result: ComplianceOverlay) -> str:
    """Operator-readable summary of the coverage report."""
    lines: list[str] = []
    lines.append(f"Compliance overlay — session {result.session_id}")
    lines.append(f"Events analyzed: {result.events_analyzed}")
    lines.append(f"Tagged events:   {len(result.overlay)}")
    if result.framework_filter:
        lines.append(f"Framework filter: {result.framework_filter}")
    lines.append("")
    if not result.coverage or all(
        fc.controls_touched_count == 0 for fc in result.coverage
    ):
        lines.append("No mapped controls were touched by this session's "
                     "observed activity.")
    for fc in result.coverage:
        lines.append(
            f"{fc.name} ({fc.version}) — "
            f"{fc.controls_touched_count} of {fc.controls_in_catalog} "
            f"mapped controls touched"
        )
        for c in fc.controls_touched:
            lines.append(f"  + {c.control}  ({c.event_count}x)  {c.title}")
        if fc.partial_coverage_note:
            lines.append(f"  coverage: {fc.partial_coverage_note}")
        lines.append("")
    if result.is_partial:
        lines.append("PARTIAL — this overlay is incomplete:")
        for r in result.partial_reasons:
            lines.append(f"  ! {r}")
        lines.append("")
    for n in result.notes:
        lines.append(f"note: {n}")
    lines.append("")
    lines.append(result.disclaimer)
    return "\n".join(lines) + "\n"


__all__ = [
    "ComplianceOverlay",
    "ControlCoverage",
    "FrameworkCoverage",
    "TaggedEvent",
    "build_overlay",
    "format_summary",
    "tags_for_event",
]
