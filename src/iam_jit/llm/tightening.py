"""Phase 13 — ``iam_jit_consider_tightening`` core.

Per ``docs/PROFILE-GENERATION-DESIGN.md`` §6 Phase 13 + §10.3 + §11.2
and memory ``[[progressive-tightening-as-injection-detector]]``: a
single MCP tool produces TWO parallel output dimensions from the same
audit-window + profile + history data flow:

* ``narrowing_proposals[]`` — candidate profile tightenings (reuses
  the Phase 8 friction-budget-aware ``improve_profile`` pipeline; the
  same refusal logic carries through).
* ``suspect_patterns[]`` — prompt-injection-AWARE signals per the §11
  catalogue (7 shapes mapped to detection sketches + recommended
  action triage).

Architectural placement per memory:

* ``[[bouncer-zero-llm-when-agent-in-loop]]`` — this is a deterministic
  signal-surfacing tool; the operator's agent reasons over both blocks
  and proposes actions. No bouncer-side LLM credit is spent here.
* ``[[ibounce-honest-positioning]]`` — suspect-pattern surfacing is
  *prompt-injection-AWARE*, NEVER *prompt-injection-PROOF*. The
  response carries a provenance block + a calibration warning whenever
  the suspect-pattern dimension is exercised; calibration corpus
  follow-up is filed (mirror of Phase 10 work for narrowing).
* ``[[scorer-is-ground-truth]]`` — thresholds (``sudden_friction_spike``
  baseline multiplier, ``velocity_anomaly`` percentile, attack-chain
  window) are tuned for honest signal-to-noise; per §9.1 they are
  guesses pending the Phase 16 calibration corpus and are surfaced as
  such via ``provenance.warnings``.
* ``[[ambient-mode-progressive-tightening]]`` — narrowings are
  *optional*; if the operator's audit window is too sparse or too
  variable the tool emits an empty / mostly-empty narrowing block AND
  surfaces that via ``provenance.history_depth_warning``.
* ``[[creates-never-mutates]]`` — this tool is READ-ONLY. It surfaces
  proposals; nothing is installed or mutated. The agent / operator
  acts via ``iam_jit_improve_profile`` (narrowings) and
  ``bounce_deny_add`` (BLOCK_PROACTIVELY suspects).

State-verification per ``docs/CONTRIBUTING.md``: the test suite in
``tests/llm/test_consider_tightening.py`` asserts observable state of
the response — per-shape ``suspect_patterns`` content, per-narrowing
``refused_narrowings`` carry-through, ``operator_attention_required``
boolean math, and a sabotage-check that monkeypatches
``is_known_adversarial`` to prove the pattern detection is
load-bearing rather than coincidentally green.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import math
import statistics
from typing import Any, Literal

from ..deny_classifier.classifier import is_known_adversarial

# ---------------------------------------------------------------------------
# Public dataclasses — frozen so callers cannot mutate the response in place
# (matches the simulator + grading shape; serialization helpers below).
# ---------------------------------------------------------------------------


SuspectShape = Literal[
    "sudden_friction_spike",
    "unprecedented_action",
    "resource_pattern_drift",
    "known_adversarial_pattern_match",
    "velocity_anomaly",
    "time_of_day_anomaly",
    "attack_chain_signature",
]


RecommendedAction = Literal[
    "INVESTIGATE_NOW",
    "LOG_AND_OBSERVE",
    "BLOCK_PROACTIVELY",
]


# Per design §11.3 — MITRE ATLAS-shaped tags. These are the rough
# mappings between detection shapes and adversarial-tactic IDs the
# operator can correlate with their existing threat-model framework.
# The mapping is INTENTIONALLY conservative (no precise sub-technique
# IDs claimed) so the catalogue can be refined by the Phase 16
# calibration corpus without breaking consumers. Per
# ``[[ibounce-honest-positioning]]`` we do NOT claim ATLAS coverage we
# can't defend; the tag is a starting point for operator correlation.
_DEFAULT_MITRE_TAGS: dict[str, str] = {
    "sudden_friction_spike": "TA0001",  # Initial Access / behavior shift
    "unprecedented_action": "TA0004",  # Privilege Escalation / discovery
    "resource_pattern_drift": "TA0009",  # Collection / exploration
    "known_adversarial_pattern_match": "T1078",  # Valid Accounts (abuse)
    "velocity_anomaly": "TA0040",  # Impact / rapid exfil
    "time_of_day_anomaly": "TA0005",  # Defense Evasion / off-hours
    "attack_chain_signature": "TA0011",  # Command and Control / chain
}


@dataclasses.dataclass(frozen=True)
class SuspectPattern:
    """One suspect-pattern signal surfaced from the audit window.

    Per design §11.2: shape + confidence + supporting events +
    recommended action + MITRE ATLAS tag. Per
    ``[[ibounce-honest-positioning]]`` ``confidence`` is uncalibrated
    pending the Phase 16 corpus; the caller MUST treat it as advisory
    and the tool's ``provenance.warnings`` surfaces this honestly.
    """

    shape: SuspectShape
    confidence: float
    events: list[dict[str, Any]]
    recommended_action: RecommendedAction
    mitre_atlas_tag: str
    rationale: str


@dataclasses.dataclass(frozen=True)
class NarrowingProposal:
    """One candidate profile narrowing the operator's agent can apply.

    Mirrors the ``improve_profile`` ``proposed_removals`` shape with a
    confidence/rationale wrapper so the agent sees per-proposal
    triage signal. ``expected_friction_delta`` is best-effort: it
    reflects the simulator's per-narrowing impact estimate when one is
    available (e.g. when ``friction_budget`` is supplied) and 0 when
    no estimate ran.
    """

    rule_to_add: dict[str, Any]
    expected_friction_delta: int
    confidence: float
    rationale: str


@dataclasses.dataclass(frozen=True)
class TighteningResponse:
    """Phase 13 MCP response. Two output dimensions:

    * ``narrowing_proposals`` — profile-tightening candidates (from
      the Phase 8 ``improve_profile`` pipeline).
    * ``suspect_patterns`` — prompt-injection-AWARE signals (§11).

    Plus ``operator_attention_required`` (a single boolean the
    operator's agent can pivot on) and a ``provenance`` block that
    surfaces calibration state per
    ``[[ibounce-honest-positioning]]``.
    """

    bouncer_kind: str
    profile_name: str
    audit_window_start: str
    audit_window_end: str
    narrowing_proposals: list[NarrowingProposal]
    suspect_patterns: list[SuspectPattern]
    operator_attention_required: bool
    provenance: dict[str, Any]


# ---------------------------------------------------------------------------
# Event-field lifters — small, tolerant; the audit-shape varies per
# bouncer + per ingestion path so we duck-type the same way the
# simulator does.
# ---------------------------------------------------------------------------


def _event_action(ev: dict[str, Any]) -> str:
    """Extract a canonical ``service:Operation`` (or bare verb) string
    from an OCSF / iam-jit audit event. Tolerant — never raises on a
    malformed event."""
    if not isinstance(ev, dict):
        return ""
    api = ev.get("api") or {}
    op = str(api.get("operation") or "")
    svc = (api.get("service") or {}).get("name") or ""
    if svc and op:
        return f"{svc}:{op}"
    if op:
        return op
    ext = (ev.get("unmapped") or {}).get("iam_jit") or {}
    if isinstance(ext, dict):
        return str(ext.get("action") or "")
    return ""


def _event_resource(ev: dict[str, Any]) -> str:
    if not isinstance(ev, dict):
        return ""
    api = ev.get("api") or {}
    resources = api.get("resources") or []
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            return str(first.get("name") or first.get("uid") or "")
        return str(first)
    ext = (ev.get("unmapped") or {}).get("iam_jit") or {}
    if isinstance(ext, dict):
        return str(ext.get("resource") or "")
    return ""


def _event_time_ms(ev: dict[str, Any]) -> int | None:
    """Return event time in ms-since-epoch or None when missing /
    unparseable. The audit-export pipeline emits ms-since-epoch ints
    in ``time``; we accept floats too."""
    if not isinstance(ev, dict):
        return None
    t = ev.get("time")
    if isinstance(t, (int, float)) and t > 0:
        return int(t)
    return None


def _event_outcome(ev: dict[str, Any]) -> str:
    """Return the audit event's outcome — ``allow`` / ``deny`` / ``"".

    Per the OCSF events the bouncers emit, the outcome is carried as
    ``metadata.event_code`` (``"allow"`` / ``"deny"``). The audit
    pipeline also uses ``status_code`` on some shapes; we accept
    either."""
    if not isinstance(ev, dict):
        return ""
    meta = ev.get("metadata") or {}
    code = meta.get("event_code") or ev.get("status_code") or ""
    return str(code).lower()


def _event_session_id(ev: dict[str, Any]) -> str:
    """Best-effort session-id lift so the attack-chain detector can
    group events by the agent session. Falls back to ``""``."""
    if not isinstance(ev, dict):
        return ""
    ext = (ev.get("unmapped") or {}).get("iam_jit") or {}
    if isinstance(ext, dict):
        sid = ext.get("agent_session_id") or ext.get("session_id")
        if sid:
            return str(sid)
    return str(ev.get("agent_session_id") or "")


# ---------------------------------------------------------------------------
# Suspect-pattern detectors.
#
# Each returns ``list[SuspectPattern]`` (possibly empty). They are
# deliberately small + pure so the calibration-corpus work can swap
# any one out without touching the orchestrator.
#
# Per ``[[scorer-is-ground-truth]]``: thresholds below are honest
# starting points NOT optimised for any demo. The provenance block
# surfaces "suspect_pattern_calibrated: False" so consumers know to
# treat scores as advisory until the Phase 16 corpus lands.
# ---------------------------------------------------------------------------


# Detection knobs (§9.1 calibration guesses; calibration corpus
# follow-up is filed separately so the values land in one place).
_FRICTION_SPIKE_MULTIPLIER = 3.0
_FRICTION_SPIKE_MIN_BASELINE_DENIES = 1
_VELOCITY_ANOMALY_MULTIPLIER = 5.0
_ATTACK_CHAIN_WINDOW_SECONDS = 60
_ATTACK_CHAIN_MIN_HITS = 2  # 2+ KNOWN_ADVERSARIAL within window
_TIME_OF_DAY_OFF_HOURS = (1, 5)  # midnight-light hours treated as off


def _detect_known_adversarial(
    *,
    audit_events: list[dict[str, Any]],
    bouncer_kind: str,
) -> list[SuspectPattern]:
    """Direct catalogue match against KNOWN_ADVERSARIAL_PATTERNS. Per
    design §11.3: this is the ONLY shape that can yield
    ``BLOCK_PROACTIVELY`` because the catalogue is the deterministic
    safety floor + already trustworthy at calibration time."""
    out: list[SuspectPattern] = []
    for ev in audit_events:
        action = _event_action(ev)
        resource = _event_resource(ev)
        if not action:
            continue
        if is_known_adversarial(action, bouncer=bouncer_kind, resource=resource):
            out.append(
                SuspectPattern(
                    shape="known_adversarial_pattern_match",
                    confidence=0.95,
                    events=[ev],
                    recommended_action="BLOCK_PROACTIVELY",
                    mitre_atlas_tag=_DEFAULT_MITRE_TAGS[
                        "known_adversarial_pattern_match"
                    ],
                    rationale=(
                        f"action {action!r} (resource={resource!r}) "
                        f"matches the deterministic safety-floor "
                        f"KNOWN_ADVERSARIAL_PATTERNS catalogue per "
                        f"design §2.3 + §7 safeguard #2"
                    ),
                )
            )
    return out


def _detect_sudden_friction_spike(
    *,
    audit_events: list[dict[str, Any]],
    history_events: list[dict[str, Any]],
) -> list[SuspectPattern]:
    """Current-window denial rate vs trailing-history baseline.

    Per §11.3: "Rolling-7d legit-deny rate; current window > 5×
    baseline → fire". We use a 3× floor (less greedy by default;
    calibration sets the final number) AND require a minimum non-zero
    baseline so a no-history operator doesn't immediately fire on the
    first deny.
    """
    if not audit_events:
        return []
    history_denies = sum(
        1 for ev in history_events if _event_outcome(ev) == "deny"
    )
    window_denies = sum(
        1 for ev in audit_events if _event_outcome(ev) == "deny"
    )
    # Normalise to per-event rates so window-size differences don't
    # warp the comparison. ``rate = denies / total_events``.
    history_total = max(len(history_events), 1)
    window_total = max(len(audit_events), 1)
    history_rate = history_denies / history_total
    window_rate = window_denies / window_total
    if history_denies < _FRICTION_SPIKE_MIN_BASELINE_DENIES:
        # No meaningful baseline → don't fire (would be 100% false-pos
        # for a fresh deployment per §11.5 honest framing).
        return []
    if history_rate <= 0:
        return []
    if window_rate < history_rate * _FRICTION_SPIKE_MULTIPLIER:
        return []
    # Confidence rises with the ratio but caps at 0.85 because this
    # shape is the noisiest (operator workflow shifts also fire it).
    ratio = window_rate / history_rate if history_rate > 0 else 0.0
    confidence = min(0.85, 0.4 + 0.1 * ratio)
    deny_events = [
        ev for ev in audit_events if _event_outcome(ev) == "deny"
    ]
    return [
        SuspectPattern(
            shape="sudden_friction_spike",
            confidence=round(confidence, 3),
            events=deny_events,
            recommended_action="INVESTIGATE_NOW",
            mitre_atlas_tag=_DEFAULT_MITRE_TAGS["sudden_friction_spike"],
            rationale=(
                f"window deny-rate={window_rate:.3f} is "
                f"{ratio:.1f}x trailing-history baseline "
                f"({history_rate:.3f}) — exceeds "
                f"{_FRICTION_SPIKE_MULTIPLIER}x floor; could be "
                f"workflow shift or injection-driven action storm"
            ),
        )
    ]


def _detect_unprecedented_actions(
    *,
    audit_events: list[dict[str, Any]],
    history_events: list[dict[str, Any]],
) -> list[SuspectPattern]:
    """Actions with zero prior occurrence in the trailing-history
    window. Per §11.3: "Action absent from
    ``bounce_extract_permissions_from_audit`` historical window →
    fire". Per ``[[ibounce-honest-positioning]]`` noisy-by-design:
    LOG_AND_OBSERVE is the default action."""
    if not history_events:
        # Operator is brand-new → no precedent set. Don't fire en
        # masse (§11.5 honest framing — false-positive storm risk).
        return []
    history_actions = {_event_action(ev) for ev in history_events}
    history_actions.discard("")
    seen_now: dict[str, list[dict[str, Any]]] = {}
    for ev in audit_events:
        action = _event_action(ev)
        if not action or action in history_actions:
            continue
        seen_now.setdefault(action, []).append(ev)
    out: list[SuspectPattern] = []
    for action, evs in seen_now.items():
        out.append(
            SuspectPattern(
                shape="unprecedented_action",
                confidence=0.4,  # low — exploration is also unprecedented
                events=evs,
                recommended_action="LOG_AND_OBSERVE",
                mitre_atlas_tag=_DEFAULT_MITRE_TAGS["unprecedented_action"],
                rationale=(
                    f"action {action!r} not observed in trailing "
                    f"history window (history={len(history_events)} "
                    f"events); could be new workflow or "
                    f"injection-driven discovery"
                ),
            )
        )
    return out


def _detect_resource_pattern_drift(
    *,
    audit_events: list[dict[str, Any]],
    history_events: list[dict[str, Any]],
) -> list[SuspectPattern]:
    """Resource never accessed before by this profile. Per §11.3:
    "Resource ARN / path / table never observed for this action → fire".

    We pair (action, resource) so a known action on a new resource
    still surfaces — e.g. ``s3:GetObject`` on a never-touched bucket.
    """
    if not history_events:
        return []
    history_pairs = {
        (_event_action(ev), _event_resource(ev))
        for ev in history_events
    }
    history_pairs.discard(("", ""))
    drift: dict[str, list[dict[str, Any]]] = {}
    for ev in audit_events:
        action = _event_action(ev)
        resource = _event_resource(ev)
        if not resource:
            continue
        if (action, resource) in history_pairs:
            continue
        # Only fire when the *resource* is new; if the action is also
        # new it surfaces via unprecedented_action anyway. We check
        # by looking at whether THIS action has touched ANY resource
        # in history.
        action_history_resources = {
            r for (a, r) in history_pairs if a == action and r
        }
        if not action_history_resources:
            # New action entirely → handled by unprecedented_action.
            continue
        drift.setdefault(action, []).append(ev)
    out: list[SuspectPattern] = []
    for action, evs in drift.items():
        resources = sorted({_event_resource(ev) for ev in evs})
        out.append(
            SuspectPattern(
                shape="resource_pattern_drift",
                confidence=0.5,
                events=evs,
                recommended_action="LOG_AND_OBSERVE",
                mitre_atlas_tag=_DEFAULT_MITRE_TAGS["resource_pattern_drift"],
                rationale=(
                    f"action {action!r} touched novel resource(s) "
                    f"{resources!r} not in history; could be new "
                    f"workflow scope or injection-driven exploration"
                ),
            )
        )
    return out


def _detect_velocity_anomaly(
    *,
    audit_events: list[dict[str, Any]],
    history_events: list[dict[str, Any]],
) -> list[SuspectPattern]:
    """Per-action throughput exceeds historical rate by >Nx. Per §11.3:
    "Reuses Phase H z-score baseline for actions/min". The Phase H
    baseline store is per-operator + lives outside this call's input;
    here we compute a per-window vs trailing-history per-action rate
    so the tool works with just the events the agent supplies (and the
    fuller Phase H baseline can override when wired)."""
    if not audit_events or not history_events:
        return []
    # Per-action counts.
    win_counts: dict[str, int] = {}
    hist_counts: dict[str, int] = {}
    for ev in audit_events:
        win_counts[_event_action(ev)] = win_counts.get(_event_action(ev), 0) + 1
    for ev in history_events:
        hist_counts[_event_action(ev)] = hist_counts.get(_event_action(ev), 0) + 1
    # Per-event rates normalise window-size away.
    win_total = max(len(audit_events), 1)
    hist_total = max(len(history_events), 1)
    out: list[SuspectPattern] = []
    for action, w_n in win_counts.items():
        if not action:
            continue
        h_n = hist_counts.get(action, 0)
        if h_n == 0:
            # Brand-new action → unprecedented_action handles it.
            continue
        win_rate = w_n / win_total
        hist_rate = h_n / hist_total
        if hist_rate <= 0:
            continue
        ratio = win_rate / hist_rate
        if ratio < _VELOCITY_ANOMALY_MULTIPLIER:
            continue
        confidence = min(0.75, 0.35 + 0.05 * ratio)
        evs = [ev for ev in audit_events if _event_action(ev) == action]
        out.append(
            SuspectPattern(
                shape="velocity_anomaly",
                confidence=round(confidence, 3),
                events=evs,
                recommended_action="INVESTIGATE_NOW",
                mitre_atlas_tag=_DEFAULT_MITRE_TAGS["velocity_anomaly"],
                rationale=(
                    f"action {action!r} fired {w_n}x in window "
                    f"(per-event rate={win_rate:.3f}) vs historical "
                    f"per-event rate={hist_rate:.3f} → {ratio:.1f}x "
                    f"(exceeds {_VELOCITY_ANOMALY_MULTIPLIER}x floor)"
                ),
            )
        )
    return out


def _detect_time_of_day_anomaly(
    *,
    audit_events: list[dict[str, Any]],
    operator_signals: dict[str, Any] | None,
) -> list[SuspectPattern]:
    """Event hours outside the operator's typical activity hours. Per
    §11.3: "Reuses Phase H z-score baseline for hour-of-day
    distribution".

    Without a Phase H baseline, we fall back to an
    operator-supplied ``typical_hours`` range in ``operator_signals``
    (e.g. ``{"typical_hours": [9, 18]}`` for 9am-6pm) OR a default
    "off-hours = 1am-5am UTC" heuristic. When ``typical_hours`` is
    declared, the response confidence rises (operator-supplied context
    is high-trust per ``[[ambient-mode-progressive-tightening]]``)."""
    if not audit_events:
        return []
    typical = (operator_signals or {}).get("typical_hours") or []
    if isinstance(typical, list) and len(typical) == 2:
        try:
            lo, hi = int(typical[0]), int(typical[1])
        except (TypeError, ValueError):
            lo, hi = _TIME_OF_DAY_OFF_HOURS
        operator_supplied = True
    else:
        lo, hi = _TIME_OF_DAY_OFF_HOURS
        operator_supplied = False

    out_events: list[dict[str, Any]] = []
    for ev in audit_events:
        t_ms = _event_time_ms(ev)
        if t_ms is None:
            continue
        hour = _dt.datetime.fromtimestamp(
            t_ms / 1000, tz=_dt.timezone.utc,
        ).hour
        if operator_supplied:
            # Anything OUTSIDE typical hours is anomalous.
            if not (lo <= hour <= hi):
                out_events.append(ev)
        else:
            # Default off-hours window — anything WITHIN [lo, hi] is
            # the anomaly (e.g. 1am-5am UTC = "weird").
            if lo <= hour <= hi:
                out_events.append(ev)
    if not out_events:
        return []
    confidence = 0.6 if operator_supplied else 0.4
    return [
        SuspectPattern(
            shape="time_of_day_anomaly",
            confidence=confidence,
            events=out_events,
            recommended_action="LOG_AND_OBSERVE",
            mitre_atlas_tag=_DEFAULT_MITRE_TAGS["time_of_day_anomaly"],
            rationale=(
                f"{len(out_events)} event(s) outside "
                f"{'operator-supplied' if operator_supplied else 'default'} "
                f"typical hours ({lo}-{hi}); could be batch job, "
                f"different timezone, or off-hours injection"
            ),
        )
    ]


def _detect_attack_chain(
    *,
    audit_events: list[dict[str, Any]],
    bouncer_kind: str,
) -> list[SuspectPattern]:
    """Sequence match: 2+ KNOWN_ADVERSARIAL within N seconds on the
    same session. Per §11.3: "Sequence match: 2+
    KNOWN_ADVERSARIAL_PATTERNS within N minutes on same session"."""
    if not audit_events:
        return []
    by_session: dict[str, list[dict[str, Any]]] = {}
    for ev in audit_events:
        action = _event_action(ev)
        resource = _event_resource(ev)
        if not action or not is_known_adversarial(
            action, bouncer=bouncer_kind, resource=resource,
        ):
            continue
        by_session.setdefault(_event_session_id(ev), []).append(ev)
    out: list[SuspectPattern] = []
    for session, hits in by_session.items():
        if len(hits) < _ATTACK_CHAIN_MIN_HITS:
            continue
        # Time-order them + check window.
        timed = [(ev, _event_time_ms(ev) or 0) for ev in hits]
        timed.sort(key=lambda x: x[1])
        # Walk a sliding-window of size MIN_HITS over timed.
        win = _ATTACK_CHAIN_WINDOW_SECONDS * 1000
        for i in range(len(timed) - _ATTACK_CHAIN_MIN_HITS + 1):
            head = timed[i][1]
            tail = timed[i + _ATTACK_CHAIN_MIN_HITS - 1][1]
            if head and tail and (tail - head) <= win:
                # Found a chain. Confidence is high: KNOWN_ADVERSARIAL
                # patterns are already calibrated + the temporal
                # clustering is meaningful.
                chain = [ev for ev, _ in timed[i : i + _ATTACK_CHAIN_MIN_HITS]]
                out.append(
                    SuspectPattern(
                        shape="attack_chain_signature",
                        confidence=0.9,
                        events=chain,
                        recommended_action="INVESTIGATE_NOW",
                        mitre_atlas_tag=_DEFAULT_MITRE_TAGS[
                            "attack_chain_signature"
                        ],
                        rationale=(
                            f"{len(chain)} KNOWN_ADVERSARIAL hits in "
                            f"session={session!r} within "
                            f"{_ATTACK_CHAIN_WINDOW_SECONDS}s — "
                            f"recon→escalate→exfil pattern; review "
                            f"agent context before continuing"
                        ),
                    )
                )
                break  # one chain per session is enough for the surface
    return out


# ---------------------------------------------------------------------------
# Narrowing-proposal generator — reuses Phase 8 improve_profile.
# ---------------------------------------------------------------------------


def _compute_narrowings(
    *,
    profile: dict[str, Any],
    audit_events: list[dict[str, Any]],
    bouncer_kind: str,
    friction_budget: int | dict[str, Any] | None,
) -> tuple[list[NarrowingProposal], list[str]]:
    """Delegate to the Phase 8 ``improve_profile`` pipeline + lift its
    ``proposed_removals`` (post-refusal) into ``NarrowingProposal``
    dataclasses. Refused narrowings (friction-budget gate) are
    INTENTIONALLY left out of the response per design §10.3 — the
    operator sees them via ``improve_profile`` directly when they
    invoke that tool; here we want the actionable subset.

    Returns ``(proposals, warnings)``. The warnings list carries
    upstream simulator + improve-pipeline warnings so the operator
    sees the same honesty surface they would via ``improve_profile``.
    """
    try:
        from ..improve.pipeline import improve_profile
    except Exception as e:  # pragma: no cover
        return [], [
            f"narrowing pipeline unavailable ({e}); "
            f"narrowing_proposals empty"
        ]

    # The profile we receive is generator-shape OR ibounce-production
    # shape. ``improve_profile`` loads profiles by name from the
    # bouncer profile store, so when we receive an inline dict we use
    # ``apply=False`` (dry-run) + pass events directly. The pipeline
    # handles the rest.
    profile_name = str(
        profile.get("profile_name") or profile.get("name") or "active"
    )
    try:
        result = improve_profile(
            bouncer=bouncer_kind,
            apply=False,
            events=audit_events,
            profile_name=profile_name,
            friction_budget=friction_budget,
        )
    except Exception as e:  # pragma: no cover
        return [], [
            f"narrowing pipeline raised {type(e).__name__}: {e}; "
            f"narrowing_proposals empty"
        ]

    proposals: list[NarrowingProposal] = []
    for removal in result.proposed_removals or []:
        action = removal.get("action", "")
        target = removal.get("target")
        # The improve pipeline's narrowing is a candidate REMOVAL of
        # an allow rule — the operator's tighten action is to drop
        # that rule from the profile. We carry the (action, target)
        # in ``rule_to_add`` for symmetry with the generator-shape
        # the agent already understands.
        proposals.append(
            NarrowingProposal(
                rule_to_add={
                    "operation": "remove_allow_rule",
                    "action": action,
                    "target": target,
                },
                expected_friction_delta=0,  # populated below if available
                confidence=0.5,
                rationale=(
                    f"action {action!r} (target={target or '*'}) "
                    f"not observed in audit window; profile-tightening "
                    f"candidate per Phase 8 improve_profile pipeline"
                ),
            )
        )

    # If friction_budget was supplied + the pipeline surfaced a
    # baseline -> if_applied delta, lift the per-narrowing impact.
    if friction_budget is not None:
        if_applied = getattr(result, "friction_metrics_if_applied", {}) or {}
        baseline = getattr(result, "friction_metrics_baseline", {}) or {}
        delta = int(
            round(
                if_applied.get("effective_extra_weekly_denies_vs_baseline", 0)
            )
        )
        if proposals and delta:
            # Distribute the cumulative delta evenly across proposals
            # for surfacing (the per-proposal split lives in
            # improve_profile's verbose output; this tool is an
            # advisory summary).
            per = max(1, delta // max(len(proposals), 1))
            proposals = [
                dataclasses.replace(p, expected_friction_delta=per)
                for p in proposals
            ]

    warnings = list(getattr(result, "warnings", []) or [])
    return proposals, warnings


# ---------------------------------------------------------------------------
# Public entry point.
# ---------------------------------------------------------------------------


def consider_tightening(
    *,
    profile: dict[str, Any],
    audit_events: list[dict[str, Any]],
    bouncer_kind: str,
    friction_budget: int | dict[str, Any] | None = None,
    history_depth_days: int = 30,
    history_events: list[dict[str, Any]] | None = None,
    operator_signals: dict[str, Any] | None = None,
) -> TighteningResponse:
    """Analyse one audit window + profile + (optional) operator
    signals; emit narrowing_proposals + suspect_patterns.

    Per ``[[bouncer-zero-llm-when-agent-in-loop]]``: deterministic.
    Per ``[[ibounce-honest-positioning]]``: provenance surfaces the
    suspect-pattern dimension's NOT-YET-CALIBRATED state — operators
    must treat it as advisory.

    Args:
        profile: parsed profile dict (generator-shape OR production
            shape; the narrowing pipeline normalises).
        audit_events: events for the current audit window (the one
            being analysed for tightening + suspect signals).
        bouncer_kind: ``ibounce`` / ``kbouncer`` / ``dbounce`` /
            ``gbounce``.
        friction_budget: passed through to the Phase 8 narrowing
            pipeline; refused narrowings carry their rationale per
            ``[[ibounce-honest-positioning]]``.
        history_depth_days: declared trailing-history depth (operator
            attests to having ``history_events`` covering this span).
        history_events: trailing-history events the detector compares
            against. When ``None`` the suspect-pattern detectors that
            require a baseline (friction-spike / unprecedented /
            resource-drift / velocity) STAY SILENT — surfaced via a
            ``provenance.history_depth_warning``.
        operator_signals: optional context dict from the operator
            (typical_hours, workflow declarations, friction tolerance,
            etc.) per ``[[ambient-mode-progressive-tightening]]`` §10.6.

    Returns:
        :class:`TighteningResponse` — caller serialises via
        :func:`serialize_tightening_response` for MCP transport.
    """
    profile = profile or {}
    bouncer_kind = (bouncer_kind or "").strip()
    audit_events = list(audit_events or [])
    history_events = list(history_events or [])

    # 1. Narrowing proposals — Phase 8 pipeline (reused).
    narrowing_proposals, narrowing_warnings = _compute_narrowings(
        profile=profile,
        audit_events=audit_events,
        bouncer_kind=bouncer_kind,
        friction_budget=friction_budget,
    )

    # 2. Suspect-pattern detectors. The KNOWN_ADVERSARIAL_PATTERNS
    #    detector ALWAYS runs (it's the deterministic safety floor +
    #    needs no history). Every other detector falls back silently
    #    on missing-history per §11.5 honest framing.
    suspect_patterns: list[SuspectPattern] = []
    suspect_patterns.extend(
        _detect_known_adversarial(
            audit_events=audit_events,
            bouncer_kind=bouncer_kind,
        )
    )
    suspect_patterns.extend(
        _detect_attack_chain(
            audit_events=audit_events,
            bouncer_kind=bouncer_kind,
        )
    )
    if history_events:
        suspect_patterns.extend(
            _detect_sudden_friction_spike(
                audit_events=audit_events,
                history_events=history_events,
            )
        )
        suspect_patterns.extend(
            _detect_unprecedented_actions(
                audit_events=audit_events,
                history_events=history_events,
            )
        )
        suspect_patterns.extend(
            _detect_resource_pattern_drift(
                audit_events=audit_events,
                history_events=history_events,
            )
        )
        suspect_patterns.extend(
            _detect_velocity_anomaly(
                audit_events=audit_events,
                history_events=history_events,
            )
        )
    suspect_patterns.extend(
        _detect_time_of_day_anomaly(
            audit_events=audit_events,
            operator_signals=operator_signals,
        )
    )

    # 3. operator_attention_required boolean math per design §6 Step 5.
    operator_attention_required = _operator_attention_required(
        suspect_patterns=suspect_patterns,
        narrowing_proposals=narrowing_proposals,
    )

    # 4. Provenance — honest about calibration state.
    provenance = _build_provenance(
        history_events=history_events,
        history_depth_days=history_depth_days,
        audit_events=audit_events,
        narrowing_warnings=narrowing_warnings,
        suspect_patterns=suspect_patterns,
    )

    audit_window_start, audit_window_end = _audit_window_bounds(audit_events)

    return TighteningResponse(
        bouncer_kind=bouncer_kind,
        profile_name=str(
            profile.get("profile_name") or profile.get("name") or ""
        ),
        audit_window_start=audit_window_start,
        audit_window_end=audit_window_end,
        narrowing_proposals=narrowing_proposals,
        suspect_patterns=suspect_patterns,
        operator_attention_required=operator_attention_required,
        provenance=provenance,
    )


def _operator_attention_required(
    *,
    suspect_patterns: list[SuspectPattern],
    narrowing_proposals: list[NarrowingProposal],
) -> bool:
    """Per design §6 Step 5:

    * any ``BLOCK_PROACTIVELY`` suspect → True
    * any ``INVESTIGATE_NOW`` suspect with confidence >= 0.7 → True
    * narrowing_proposals count > 5 → True (operator should review)

    Anything else (LOG_AND_OBSERVE only, single small narrowing) → False.
    """
    for sp in suspect_patterns:
        if sp.recommended_action == "BLOCK_PROACTIVELY":
            return True
        if (
            sp.recommended_action == "INVESTIGATE_NOW"
            and sp.confidence >= 0.7
        ):
            return True
    if len(narrowing_proposals) > 5:
        return True
    return False


def _audit_window_bounds(
    audit_events: list[dict[str, Any]],
) -> tuple[str, str]:
    times = [_event_time_ms(ev) for ev in audit_events]
    times = [t for t in times if t is not None]
    if not times:
        return "", ""
    lo = _dt.datetime.fromtimestamp(min(times) / 1000, tz=_dt.timezone.utc)
    hi = _dt.datetime.fromtimestamp(max(times) / 1000, tz=_dt.timezone.utc)
    return (
        lo.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        hi.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )


def _build_provenance(
    *,
    history_events: list[dict[str, Any]],
    history_depth_days: int,
    audit_events: list[dict[str, Any]],
    narrowing_warnings: list[str],
    suspect_patterns: list[SuspectPattern],
) -> dict[str, Any]:
    """Per ``[[ibounce-honest-positioning]]``: surface BOTH
    calibration-state booleans (narrowing_calibrated +
    suspect_pattern_calibrated) so consumers can decide how much weight
    to assign.

    Narrowing is calibrated (Phase 10 corpus shipped 2026-05-24).
    Suspect-pattern detection is NOT YET calibrated — the warning
    surfaces that explicitly + cites the §9.1 guess list."""
    warnings: list[str] = []
    history_depth_warning: str | None = None

    if history_depth_days > 0:
        # Span the supplied history covers.
        hist_times = [_event_time_ms(ev) for ev in history_events]
        hist_times = [t for t in hist_times if t is not None]
        if len(hist_times) >= 2:
            span_days = (max(hist_times) - min(hist_times)) / (
                1000 * 60 * 60 * 24
            )
        else:
            span_days = 0.0
        if span_days < max(history_depth_days * 0.5, 1.0):
            history_depth_warning = (
                f"declared history_depth_days={history_depth_days} but "
                f"supplied history_events span only {span_days:.2f} "
                f"days — suspect-pattern detectors that compare against "
                f"the baseline are running with REDUCED CONFIDENCE; "
                f"treat their output as advisory until history matches "
                f"declared depth per [[ibounce-honest-positioning]]"
            )
            warnings.append(history_depth_warning)

    # Narrowing pipeline warnings carry through.
    warnings.extend(narrowing_warnings)

    suspect_pattern_calibrated = False
    # NOTE: when the Phase 16 corpus lands + this module is rev'd to
    # consume it, flip ``suspect_pattern_calibrated`` to True and drop
    # the warning below.
    if suspect_patterns:
        warnings.append(
            "suspect-pattern detection is NEW + NOT corpus-validated "
            "(Phase 16 calibration is a follow-up; thresholds for "
            "sudden_friction_spike multiplier, velocity_anomaly "
            "multiplier, attack_chain_signature window are §9.1 "
            "guesses per docs/PROFILE-GENERATION-DESIGN.md). Treat "
            "every suspect_pattern as ADVISORY; verify before action. "
            "Per [[progressive-tightening-as-injection-detector]]: "
            "this surface is prompt-injection-AWARE, NEVER "
            "prompt-injection-PROOF."
        )

    return {
        "engine": "consider-tightening-python",
        "engine_version": "1.0.0",
        "history_depth_days_declared": history_depth_days,
        "history_event_count": len(history_events),
        "audit_event_count": len(audit_events),
        "narrowing_calibrated": True,  # Phase 10 corpus shipped
        "suspect_pattern_calibrated": suspect_pattern_calibrated,
        "history_depth_warning": history_depth_warning,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Serialisation — the MCP wrapper hands the result to ``json.dumps``.
# ---------------------------------------------------------------------------


def serialize_tightening_response(resp: TighteningResponse) -> dict[str, Any]:
    """JSON-safe dict form of :class:`TighteningResponse`. Mirrors
    :func:`iam_jit.llm.simulator.serialize_simulation_verdicts` so the
    MCP layer can hand the dict straight to ``json.dumps``."""
    return {
        "bouncer_kind": resp.bouncer_kind,
        "profile_name": resp.profile_name,
        "audit_window_start": resp.audit_window_start,
        "audit_window_end": resp.audit_window_end,
        "narrowing_proposals": [
            {
                "rule_to_add": dict(n.rule_to_add),
                "expected_friction_delta": n.expected_friction_delta,
                "confidence": n.confidence,
                "rationale": n.rationale,
            }
            for n in resp.narrowing_proposals
        ],
        "suspect_patterns": [
            {
                "shape": s.shape,
                "confidence": s.confidence,
                "events": list(s.events),
                "recommended_action": s.recommended_action,
                "mitre_atlas_tag": s.mitre_atlas_tag,
                "rationale": s.rationale,
            }
            for s in resp.suspect_patterns
        ],
        "operator_attention_required": resp.operator_attention_required,
        "provenance": dict(resp.provenance),
    }


def consider_tightening_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """MCP backend for ``iam_jit_consider_tightening``.

    Accepted args:

      * profile: dict (REQUIRED)
      * audit_events: list[dict] (REQUIRED)
      * bouncer_kind: str (REQUIRED — ibounce/kbouncer/dbounce/gbounce)
      * friction_budget: int | dict (optional; same shape as
        ``iam_jit_improve_profile``)
      * history_depth_days: int (default 30)
      * history_events: list[dict] (optional trailing-history)
      * operator_signals: dict (optional; typical_hours etc.)

    Returns the serialised :class:`TighteningResponse` dict.
    """
    try:
        resp = consider_tightening(
            profile=args.get("profile") or {},
            audit_events=list(args.get("audit_events") or []),
            bouncer_kind=str(args.get("bouncer_kind") or ""),
            friction_budget=args.get("friction_budget"),
            history_depth_days=int(args.get("history_depth_days", 30)),
            history_events=list(args.get("history_events") or []) or None,
            operator_signals=args.get("operator_signals") or None,
        )
    except Exception as e:  # pragma: no cover — handler must not crash MCP
        return {
            "status": "error",
            "code": "consider_tightening_failed",
            "message": f"{type(e).__name__}: {e}",
        }
    return serialize_tightening_response(resp)


__all__ = [
    "NarrowingProposal",
    "RecommendedAction",
    "SuspectPattern",
    "SuspectShape",
    "TighteningResponse",
    "consider_tightening",
    "consider_tightening_for_mcp",
    "serialize_tightening_response",
]
