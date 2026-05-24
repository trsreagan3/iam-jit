"""Profile simulator core — Phase 4 of profile-generation design.

Per ``docs/PROFILE-GENERATION-DESIGN.md`` §6 Phase 4 + §3 Simulation
preview MCP tool: extracts a reusable callable
``evaluate_profile_against_events(profile, events, bouncer_kind, ...)``
that replays a list of audit events through a generator-shape profile
(``{allows: [...], denies: [...]}``) and emits per-event verdicts +
friction metrics.

This is the engine that:

* Phase 5 grading (``bounce_grade_profile_for_workflow``) feeds off
  to score profiles against an audit window + friction budget.
* Phase 6 recipe ``audit-to-effective-profile.md`` invokes between
  ``bounce_profile_generate_from_audit`` and ``bounce_profile_save``
  to give the operator a dry-run.
* The new ``bounce_simulate_profile`` MCP tool wraps with
  schema-shaped input/output for agents to call.

Honest provenance per [[ibounce-honest-positioning]]:

The simulator is a **pure-Python evaluator over the generator-shape
profile dict** (the rich ``allows: [{target, actions, reason}]`` /
``denies: [{target, actions, reason}]`` shape the lean-permissive
fallback emits). It is NOT the production rule engine for any
bouncer:

* **ibounce** production uses the
  ``src/iam_jit/bouncer/profiles.py::evaluate_profile`` AWS-form
  evaluator over ``Profile`` dataclasses (deny_actions / allow_rules /
  allow_baseline / deny_keywords). The simulator's allow/deny
  matching uses the same intent (deny-overrides-allow + first-match)
  but operates on the generator-shape — divergences exist
  (no conditional-deny / no allow_baseline / no keyword-match).
* **kbouncer / dbounce / gbounce** production is Go-side. The
  simulator implements pure-Python rule matching for the same
  generator-shape rules; it has NEVER been compared head-to-head
  against the Go engines in this commit.

``provenance.engine`` is therefore ``"simulation-python"`` for all
four bouncers and ``provenance.warnings`` enumerates the known
divergence shapes per bouncer so operators see this isn't
production parity. The intent matches [[scorer-is-ground-truth]] —
don't tune the simulator to flatter profiles; surface the gap.

Friction-budget integration (Phase 3 plumbed kwarg, Phase 4 wires
it): when ``friction_budget`` is supplied, ``friction_metrics``
extrapolates observed deny count to a weekly rate using a
``span_days`` heuristic over the event timestamps + emits
``over_budget`` + ``over_budget_factor``.

State-verification per ``docs/CONTRIBUTING.md``: every test under
``tests/llm/test_simulator_core.py`` asserts the verdicts LIST
content (not just summary counts) so a regression that flips a
single verdict can't hide behind matching totals.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any, Literal

from ..deny_classifier.classifier import is_known_adversarial
from .profile_generator import _SAFETY_FLOOR_DENIES


VerdictLiteral = Literal["allow", "deny", "abstain"]


@dataclasses.dataclass(frozen=True)
class SimulationVerdict:
    """One event's per-rule decision."""

    event_idx: int
    event: dict[str, Any]
    verdict: VerdictLiteral
    reason: str
    matched_rule: str | None  # description of which rule fired (None on abstain)


@dataclasses.dataclass(frozen=True)
class SimulationVerdicts:
    """Full simulation output for a (profile, events) pair."""

    bouncer_kind: str
    profile_name: str
    verdicts: list[SimulationVerdict]
    summary: dict[str, int]
    friction_metrics: dict[str, Any]
    provenance: dict[str, Any]


# ---------------------------------------------------------------------------
# Per-bouncer engine divergence warnings — surfaced via
# provenance.warnings so the operator sees the honest gap.
# ---------------------------------------------------------------------------

_DIVERGENCE_WARNINGS: dict[str, list[str]] = {
    "ibounce": [
        "simulator evaluates generator-shape allows/denies (target+actions+reason); "
        "production ibounce evaluator additionally supports "
        "deny_keywords / allow_baseline / deny_actions_with_condition / "
        "only_account_ids / only_regions — those layers are NOT replayed here",
        "ARN glob matching uses simple `*` -> `.*` regex; AWS IAM glob syntax "
        "may differ on edge characters like `?` (production engine "
        "src/iam_jit/bouncer/rules.py covers `?` as single-char)",
    ],
    "kbounce": [
        "production kbouncer is Go-side; simulator is pure-Python over "
        "generator-shape rules and has NOT been head-to-head validated "
        "against the Go engine in this commit",
        "verb matching uses substring containment on action.operation; "
        "production engine may use Kubernetes RBAC-form verb sets",
    ],
    "dbounce": [
        "production dbounce is Go-side; simulator is pure-Python over "
        "generator-shape rules and has NOT been head-to-head validated "
        "against the Go engine in this commit",
        "SQL pattern matching uses case-insensitive substring; production "
        "engine may parse SQL via pg_query_go / vitess (per dbounce build "
        "plan) so identifiers + quoting may diverge",
    ],
    "gbounce": [
        "production gbounce is Go-side; simulator is pure-Python over "
        "generator-shape rules and has NOT been head-to-head validated "
        "against the Go engine in this commit",
        "host matching uses literal equality + simple glob; production "
        "engine may support CIDR / SNI / domain-suffix matching",
    ],
}


# ---------------------------------------------------------------------------
# Event -> (action, resource, ext_fields) extraction.
# ---------------------------------------------------------------------------


def _extract_event_fields(
    event: dict[str, Any], bouncer_kind: str,
) -> tuple[str, str, dict[str, Any]]:
    """Lift the bouncer-canonical (action, resource, ext_fields) tuple
    out of an OCSF event. Mirrors the shape used by
    :func:`iam_jit.llm.profile_generator._aggregate_events_for_bouncer`
    so simulator + generator agree on what "action" means for a given
    event."""
    ext = (event.get("unmapped") or {}).get("iam_jit") or {}
    if isinstance(ext, dict):
        ext_inner = ext.get("ext") or {}
    else:
        ext_inner = {}
    api = event.get("api") or {}
    op = str(api.get("operation") or ext.get("action") or "")
    svc = (api.get("service") or {}).get("name") or ext_inner.get("service") or ""
    action = f"{svc}:{op}" if svc and op else op

    resources = api.get("resources") or []
    resource = ""
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            resource = str(first.get("name") or first.get("uid") or "")
        else:
            resource = str(first)
    if not resource:
        resource = str(ext.get("resource") or "")

    fields: dict[str, Any] = {
        "service": svc,
        "operation": op,
        "ext": ext_inner,
        "dst_endpoint": event.get("dst_endpoint") or {},
    }
    return action, resource, fields


def _glob_match(pattern: str, candidate: str) -> bool:
    """Simple `*`/`?` glob matcher. `*` → `.*`, `?` → `.`. Case-sensitive."""
    if not pattern or pattern == "*":
        return True
    if not candidate:
        return False
    out_chars: list[str] = []
    for ch in pattern:
        if ch == "*":
            out_chars.append(".*")
        elif ch == "?":
            out_chars.append(".")
        else:
            out_chars.append(re.escape(ch))
    regex = re.compile(r"\A" + "".join(out_chars) + r"\Z")
    return regex.match(candidate) is not None


def _action_matches(rule_actions: list[str], event_action: str) -> str | None:
    """Return the rule-action string that matched (for matched_rule
    surfacing) or None if no rule action matched."""
    if not event_action:
        return None
    for ra in rule_actions:
        if not isinstance(ra, str) or not ra:
            continue
        if _glob_match(ra, event_action):
            return ra
        # dbounce / kbounce action shapes don't use `service:Action` —
        # the rule may carry the bare verb (e.g. `DELETE`) while the
        # event_action is `postgres:DELETE`. Try the post-colon tail.
        if ":" in event_action:
            tail = event_action.split(":", 1)[1]
            if _glob_match(ra, tail):
                return ra
        # And the reverse — rule may carry `service:Action` while a
        # bare verb event slipped through; check the rule's tail too.
        if ":" in ra:
            rtail = ra.split(":", 1)[1]
            if _glob_match(rtail, event_action):
                return ra
    return None


def _target_matches(rule_target: str | None, resource: str) -> bool:
    """A rule's `target` is an ARN-glob (ibounce), namespace path
    (kbounce), host pattern (gbounce), or SQL-shape (dbounce). Treat
    None / `*` as match-all to mirror the generator's intent."""
    if rule_target is None or rule_target == "" or rule_target == "*":
        return True
    return _glob_match(rule_target, resource)


def _evaluate_safety_floor(
    event_action: str,
    resource: str,
    bouncer_kind: str,
    host: str = "",
) -> tuple[bool, str | None]:
    """Check ``_SAFETY_FLOOR_DENIES`` for ``bouncer_kind``. Returns
    ``(deny, matched_floor_description)``."""
    floors = _SAFETY_FLOOR_DENIES.get(bouncer_kind, [])
    for floor in floors:
        actions = floor.get("actions") or []
        target = floor.get("target")
        sql_patterns = floor.get("sql_patterns") or []

        # ibounce / kbounce / gbounce: action-bearing floors.
        if actions:
            matched_action = _action_matches(list(actions), event_action)
            if matched_action and _target_matches(target, resource):
                return True, (
                    f"_SAFETY_FLOOR_DENIES[{bouncer_kind}]: "
                    f"action={matched_action} target={target} "
                    f"reason={floor.get('reason', '')}"
                )

        # kbouncer verb-form floors carry `verbs` + `resources` instead
        # of generator-shape `actions`.
        verbs = floor.get("verbs") or []
        if verbs:
            verb_tail = (
                event_action.split(":", 1)[1]
                if ":" in event_action
                else event_action
            )
            verb_match = any(
                v and v.lower() in verb_tail.lower() for v in verbs
            )
            res_match = True
            f_resources = floor.get("resources") or []
            if f_resources:
                res_match = any(
                    r and r.lower() in resource.lower() for r in f_resources
                )
            if verb_match and res_match:
                return True, (
                    f"_SAFETY_FLOOR_DENIES[{bouncer_kind}]: "
                    f"verbs={verbs} resources={f_resources} "
                    f"reason={floor.get('reason', '')}"
                )

        # dbounce SQL-pattern floors.
        if sql_patterns:
            haystack = f"{event_action} {resource}".upper()
            for pat in sql_patterns:
                pat_norm = pat.upper().replace("*", "")
                if pat_norm and pat_norm in haystack:
                    return True, (
                        f"_SAFETY_FLOOR_DENIES[{bouncer_kind}]: "
                        f"sql_pattern={pat} reason={floor.get('reason', '')}"
                    )

        # gbounce host-only floors. The target field can match either
        # the resource (e.g. URI) or the dst_endpoint.hostname (gbounce
        # extracts the host from there per _extract_scope_dimensions).
        if not actions and not verbs and not sql_patterns and target:
            target_l = target.lower()
            candidates = [resource.lower(), host.lower()]
            for c in candidates:
                if c and target_l in c:
                    return True, (
                        f"_SAFETY_FLOOR_DENIES[{bouncer_kind}]: "
                        f"host={target} reason={floor.get('reason', '')}"
                    )

    # Universal cross-bouncer hard floor: known adversarial patterns
    # always deny. Per design §2.3 + §7 safeguard #2.
    if event_action and is_known_adversarial(
        event_action, bouncer=bouncer_kind, resource=resource,
    ):
        return True, (
            f"KNOWN_ADVERSARIAL_PATTERNS[{bouncer_kind}]: "
            f"action={event_action} resource={resource}"
        )

    return False, None


def _evaluate_one_event(
    event_idx: int,
    event: dict[str, Any],
    allow_rules: list[dict[str, Any]],
    deny_rules: list[dict[str, Any]],
    bouncer_kind: str,
) -> SimulationVerdict:
    """Per-event rule evaluation: safety-floor FIRST, then explicit
    deny rules (deny-overrides-allow per bouncer/rules.py precedent),
    then allow rules, finally abstain."""
    event_action, resource, fields = _extract_event_fields(
        event, bouncer_kind,
    )
    host = str((fields.get("dst_endpoint") or {}).get("hostname") or "")

    # 1. Safety floor — universal hard floor; never opt-out.
    floor_deny, floor_reason = _evaluate_safety_floor(
        event_action, resource, bouncer_kind, host=host,
    )
    if floor_deny:
        return SimulationVerdict(
            event_idx=event_idx,
            event=event,
            verdict="deny",
            reason=floor_reason or "safety_floor",
            matched_rule=floor_reason,
        )

    # 2. Explicit deny rules from the profile (deny beats allow).
    for d_idx, drule in enumerate(deny_rules):
        if not isinstance(drule, dict):
            continue
        rule_actions = list(drule.get("actions") or [])
        target = drule.get("target")
        matched_action = _action_matches(rule_actions, event_action)
        if matched_action and _target_matches(target, resource):
            return SimulationVerdict(
                event_idx=event_idx,
                event=event,
                verdict="deny",
                reason=str(drule.get("reason") or "profile deny rule matched"),
                matched_rule=(
                    f"denies[{d_idx}]: target={target} "
                    f"action={matched_action}"
                ),
            )

    # 3. Allow rules from the profile (first match wins).
    for a_idx, arule in enumerate(allow_rules):
        if not isinstance(arule, dict):
            continue
        rule_actions = list(arule.get("actions") or [])
        target = arule.get("target")
        matched_action = _action_matches(rule_actions, event_action)
        if matched_action and _target_matches(target, resource):
            return SimulationVerdict(
                event_idx=event_idx,
                event=event,
                verdict="allow",
                reason=str(arule.get("reason") or "profile allow rule matched"),
                matched_rule=(
                    f"allows[{a_idx}]: target={target} "
                    f"action={matched_action}"
                ),
            )

    # 4. Nothing matched — abstain (caller / mode decides default).
    return SimulationVerdict(
        event_idx=event_idx,
        event=event,
        verdict="abstain",
        reason="no allow/deny rule matched + no safety-floor hit",
        matched_rule=None,
    )


# ---------------------------------------------------------------------------
# Friction-budget computation.
# ---------------------------------------------------------------------------


def _compute_friction_metrics(
    *,
    verdicts: list[SimulationVerdict],
    events: list[dict[str, Any]],
    friction_budget: int | dict[str, Any] | None,
) -> dict[str, Any]:
    """Extrapolate observed deny count to a weekly rate per the
    design §4.1 friction budget. ``friction_budget`` accepts either:

    * ``int`` — interpreted as ``max_legitimate_denies_per_week``
    * ``dict`` per §4.1 with ``max_legitimate_denies_per_week`` /
      ``max_legitimate_denies_per_day`` keys

    Returns empty dict when ``friction_budget is None`` per spec.

    Window extrapolation: if events span N days (computed from
    min/max ``time`` field in ms), ``estimated_weekly_denies =
    actual_denies * (7 / max(N, 1))``. Documented in
    ``provenance.warnings`` so operators see the assumption.
    """
    if friction_budget is None:
        return {}

    if isinstance(friction_budget, dict):
        budget_max = int(
            friction_budget.get("max_legitimate_denies_per_week")
            or friction_budget.get("max_legitimate_denies_per_day", 0) * 7
            or 0
        )
    else:
        budget_max = int(friction_budget)

    actual_denies = sum(1 for v in verdicts if v.verdict == "deny")

    # Span computation — time field is in ms in the event shape.
    times_ms: list[int] = []
    for ev in events:
        t = ev.get("time")
        if isinstance(t, (int, float)) and t > 0:
            times_ms.append(int(t))
    if len(times_ms) >= 2:
        span_ms = max(times_ms) - min(times_ms)
        span_days = max(span_ms / (1000 * 60 * 60 * 24), 1.0 / 24.0)
    elif times_ms:
        # Single timestamp: assume a 1-hour observation slice. Documented
        # in provenance.warnings by caller; this is the most conservative
        # assumption (smallest window → largest extrapolated weekly rate).
        span_days = 1.0 / 24.0
    else:
        # No timestamps at all: assume the events themselves are one
        # observation each over a 1-hour window (consistent with
        # default time_range="1h" in the generator).
        span_days = 1.0 / 24.0

    estimated_weekly = actual_denies * (7.0 / span_days)
    over_budget = budget_max > 0 and estimated_weekly > budget_max
    over_budget_factor = (
        (estimated_weekly / budget_max) if budget_max > 0 else 0.0
    )

    return {
        "budget_max_denies_per_week": budget_max,
        "actual_denies_in_window": actual_denies,
        "estimated_weekly_denies": round(estimated_weekly, 3),
        "over_budget": bool(over_budget),
        "over_budget_factor": round(over_budget_factor, 3),
        "observation_span_days": round(span_days, 6),
    }


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def evaluate_profile_against_events(
    profile: dict[str, Any],
    events: list[dict[str, Any]],
    bouncer_kind: str,
    friction_budget: int | dict[str, Any] | None = None,
) -> SimulationVerdicts:
    """Replay ``events`` through ``profile``'s allow / deny rules.

    Per :mod:`iam_jit.llm.simulator` module docstring — this is a
    pure-Python simulator over the generator-shape profile dict.
    ``provenance.engine == "simulation-python"`` for ALL four
    bouncers because no production rule engine is invoked.
    ``provenance.warnings`` enumerates per-bouncer divergence shapes.

    Per [[ibounce-honest-positioning]] the engine field must
    accurately reflect engine reality; per
    [[scorer-is-ground-truth]] the simulator must not be tuned to
    flatter profiles (Phase 5 grading consumes these verdicts).

    Args:
        profile: parsed profile YAML — generator-shape
            ``{"bouncer": ..., "allows": [...], "denies": [...]}``.
            Non-generator-shape profiles (ibounce production
            ``{deny_actions: [...], allow_rules: [...]}``) are
            translated by promoting ``deny_actions`` strings into
            ``denies: [{target:"*", actions:[...]}]`` so the
            simulator can replay both shapes uniformly.
        events: list of OCSF audit events (the shape
            :func:`iam_jit.cli_audit_query` emits).
        bouncer_kind: one of ``"ibounce"`` / ``"kbouncer"`` /
            ``"kbounce"`` / ``"dbounce"`` / ``"gbounce"``.
        friction_budget: optional integer (weekly cap) or dict per
            design §4.1. ``None`` → ``friction_metrics`` returns ``{}``.

    Returns:
        :class:`SimulationVerdicts` — ``verdicts`` carries per-event
        decisions in input order; ``summary`` aggregates allow/deny/
        abstain counts; ``friction_metrics`` populated when
        ``friction_budget`` is non-None; ``provenance`` always carries
        ``engine`` + ``version`` + ``warnings``.
    """
    profile = profile or {}
    bouncer_kind = (bouncer_kind or "").strip()

    # Promote ibounce production-shape deny_actions to generator-shape.
    raw_allows = list(profile.get("allows") or [])
    raw_denies = list(profile.get("denies") or [])
    promoted_warnings: list[str] = []

    legacy_deny_actions = profile.get("deny_actions")
    if isinstance(legacy_deny_actions, list) and legacy_deny_actions:
        raw_denies = list(raw_denies) + [{
            "target": "*",
            "actions": list(legacy_deny_actions),
            "reason": "promoted from profile.deny_actions for simulator replay",
        }]
        promoted_warnings.append(
            "promoted legacy `deny_actions` list to a generator-shape "
            "deny rule (target=`*`); production engine would also "
            "consult deny_actions_with_condition + allow_baseline + "
            "deny_keywords which the simulator does not replay"
        )

    legacy_allow_rules = profile.get("allow_rules")
    if isinstance(legacy_allow_rules, list) and legacy_allow_rules:
        for r in legacy_allow_rules:
            if not isinstance(r, dict):
                continue
            pattern = r.get("pattern")
            if not isinstance(pattern, str):
                continue
            raw_allows.append({
                "target": r.get("arn_scope") or "*",
                "actions": [pattern],
                "reason": str(r.get("note") or "promoted from allow_rules"),
            })
        promoted_warnings.append(
            "promoted legacy `allow_rules` entries to generator-shape "
            "allows; region_scope on the legacy rule is NOT enforced "
            "by the simulator"
        )

    verdicts = [
        _evaluate_one_event(
            event_idx=idx,
            event=ev,
            allow_rules=raw_allows,
            deny_rules=raw_denies,
            bouncer_kind=bouncer_kind,
        )
        for idx, ev in enumerate(events or [])
    ]

    summary = {
        "total": len(verdicts),
        "allow": sum(1 for v in verdicts if v.verdict == "allow"),
        "deny": sum(1 for v in verdicts if v.verdict == "deny"),
        "abstain": sum(1 for v in verdicts if v.verdict == "abstain"),
    }

    friction_metrics = _compute_friction_metrics(
        verdicts=verdicts,
        events=events or [],
        friction_budget=friction_budget,
    )

    warnings = list(_DIVERGENCE_WARNINGS.get(bouncer_kind, []))
    if not warnings:
        warnings.append(
            f"unknown bouncer_kind {bouncer_kind!r}; no per-bouncer "
            f"divergence catalogue available — simulator falls back to "
            f"generic generator-shape rule matching"
        )
    warnings.extend(promoted_warnings)
    if friction_budget is not None and friction_metrics:
        warnings.append(
            "friction_metrics.estimated_weekly_denies extrapolates "
            "observed deny count over min/max event-time span; "
            "shorter observation windows inflate the estimate "
            "(single-timestamp events assume a 1h slice)"
        )

    provenance = {
        "engine": "simulation-python",
        "engine_version": "1.0.0",
        "production_parity": False,
        "warnings": warnings,
    }

    return SimulationVerdicts(
        bouncer_kind=bouncer_kind,
        profile_name=str(profile.get("profile_name") or profile.get("bouncer") or ""),
        verdicts=verdicts,
        summary=summary,
        friction_metrics=friction_metrics,
        provenance=provenance,
    )


def serialize_simulation_verdicts(sv: SimulationVerdicts) -> dict[str, Any]:
    """JSON-safe dict form of :class:`SimulationVerdicts`. Used by the
    MCP tool wrapper so the dataclass + frozen-dataclass nesting does
    not leak ``__dataclass_fields__`` etc. into the protocol payload."""
    return {
        "bouncer_kind": sv.bouncer_kind,
        "profile_name": sv.profile_name,
        "verdicts": [
            {
                "event_idx": v.event_idx,
                "verdict": v.verdict,
                "reason": v.reason,
                "matched_rule": v.matched_rule,
                # The event itself is NOT echoed back by default — it
                # can be large + duplicates the input. Callers that
                # need the per-event payload re-correlate by event_idx.
            }
            for v in sv.verdicts
        ],
        "summary": dict(sv.summary),
        "friction_metrics": dict(sv.friction_metrics),
        "provenance": dict(sv.provenance),
    }
