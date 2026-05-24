"""Profile grading — Phase 5 of profile-generation design.

Per ``docs/PROFILE-GENERATION-DESIGN.md`` §6 Phase 5 + §4.2: scores a
profile against a workflow of audit events using a 5-flag rubric +
emits an overall verdict from the canonical
``MEANINGFUL / PARTIAL / THEATER / NEGATIVE-VALUE`` taxonomy borrowed
from `[[role-effectiveness-corpus]]`.

This module composes with Phase 4 :mod:`iam_jit.llm.simulator` — it
invokes ``evaluate_profile_against_events`` under the hood, then
scores the resulting ``SimulationVerdicts`` against the five rubric
flags per design §4.3 + Phase 4 prep notes:

* ``blocks_known_risk_shapes`` — TRUE iff every adversarial event
  (per :func:`iam_jit.deny_classifier.classifier.is_known_adversarial`)
  in the input received a ``deny`` verdict.
* ``under_friction_budget`` — TRUE iff
  ``SimulationVerdicts.friction_metrics.over_budget`` is False. If
  ``friction_budget`` is None the flag is N/A and reports
  ``rationale="no budget specified"`` (does NOT fail-by-default).
* ``allows_too_broad`` — TRUE (= pass) iff NO allow rule in the
  profile has both ``target == "*"`` AND any write-class action.
  Uses :class:`iam_jit.profile_heuristic.classify.ActionClass`.
* ``schema_parses`` — TRUE iff the profile dict round-trips through
  ``yaml.safe_dump`` → ``yaml.safe_load`` AND the loaded payload is a
  dict carrying generator-shape keys (``allows`` / ``denies`` lists
  of dicts when present, or a non-empty ``bouncer`` field). Honest
  per `[[ibounce-honest-positioning]]`: structural validation, not
  just ``isinstance(profile, dict)``. Per
  `[[cross-product-agent-parity]]`: rule-shape validation dispatches
  per-bouncer (see :data:`SCHEMA_VALIDATORS`) because each bouncer
  carries a different safety-floor rule shape — ibounce uses
  ``actions[]``, kbounce uses ``verbs[]+resources[]``, dbounce uses
  ``sql_patterns[]``, gbounce uses host-only ``target``/``host``/
  ``host_pattern``. Allow rules from the lean-permissive generator
  use the shared ``{target, actions}`` shape on every bouncer, so
  each validator accepts EITHER the bouncer-native deny shape OR
  the shared allow shape per rule.
* ``narrows_vs_admin_baseline`` — TRUE iff against the supplied
  ``events`` there exists at least one event where the
  admin-everything baseline (``allows: [{target: "*", actions:
  ["*"]}]``) would allow but the profile denies. Practical narrowing
  proof, not a structural diff.

Overall verdict per `[[role-effectiveness-corpus]]` 4-tier scale:

* ``MEANINGFUL``       — all 5 flags pass
* ``PARTIAL``          — 3-4 flags pass
* ``THEATER``          — 1-2 flags pass
* ``NEGATIVE-VALUE``   — 0 flags pass OR (``allows_too_broad`` FALSE
                         AND ``narrows_vs_admin_baseline`` FALSE)
                         (i.e. profile is broader than admin baseline
                         — actively dangerous)

Provenance honest per `[[ibounce-honest-positioning]]`: forwards the
simulator's ``production_parity`` field + warning list so operators
know the grading depends on the simulator's accuracy. The grading
report MUST surface the parity caveat — see :func:`_build_provenance`.

Per `[[scorer-is-ground-truth]]` + `[[calibration-quality-bar]]`: the
5-flag rubric is the calibration anchor for Phase 6 recipe + Phase 7
operator UX. Don't tune the rubric to make a generated profile look
better — flag conditions reflect what "good" means structurally, not
what's convenient.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Literal

import yaml

from ..deny_classifier.classifier import is_known_adversarial
from ..profile_heuristic.classify import ActionClass, classify_action
from . import simulator as _sim


GRADING_VERSION = "1.0.0"


# Phase 10 calibration-corpus provenance per
# ``docs/PROFILE-GENERATION-DESIGN.md`` §6 Phase 10 + §8 acceptance.
# Set to True once the 10-scenario corpus at
# ``tests/llm/profile_generation_corpus/`` is green — the rubric is
# defensible against rubric-edge scenarios spanning all four bouncers.
# Per [[calibration-quality-bar]]: this lift advertises to operators
# + auditors that the grading rubric has its own corpus, distinct
# from the iam-jit scorer corpus.
CALIBRATION_CORPUS_VALIDATED = True
CALIBRATION_CORPUS_VERSION = "1.0.0"
CALIBRATION_CORPUS_SIZE = 10


FlagName = Literal[
    "blocks_known_risk_shapes",
    "under_friction_budget",
    "allows_too_broad",
    "schema_parses",
    "narrows_vs_admin_baseline",
]


OverallVerdict = Literal[
    "MEANINGFUL", "PARTIAL", "THEATER", "NEGATIVE-VALUE",
]


@dataclasses.dataclass(frozen=True)
class GradingFlag:
    """One rubric flag's result.

    Fields:
        name: which of the 5 rubric flags this is.
        pass_: True iff the flag's condition is satisfied. (Trailing
            underscore avoids the Python ``pass`` keyword.)
        rationale: short operator-readable reason for the pass / fail.
        evidence: supporting verdict ids / matched_rule references /
            allow-rule descriptors. Empty list when nothing to cite
            (e.g. flag is N/A or all events trivially passed).
    """

    name: FlagName
    pass_: bool
    rationale: str
    evidence: list[str]


@dataclasses.dataclass(frozen=True)
class GradingReport:
    """Full grading output for a (profile, events, bouncer_kind) triple.

    Fields:
        bouncer_kind: e.g. ``"ibounce"`` / ``"kbouncer"`` / ``"dbounce"``
            / ``"gbounce"``. Echoes the input verbatim.
        profile_name: from ``profile["profile_name"]`` or
            ``profile["bouncer"]`` falling back to ``""``.
        overall: one of ``MEANINGFUL / PARTIAL / THEATER / NEGATIVE-VALUE``
            per the threshold logic in :func:`_compute_overall`.
        flags: per-flag results in canonical order (matches FlagName
            literal order).
        simulation_summary: passed through from
            ``SimulationVerdicts.summary`` — allow / deny / abstain
            counts + total.
        provenance: ``{grading_version, simulator_engine,
            simulator_engine_version, simulator_production_parity,
            warnings}`` — warnings merge simulator divergence catalogue
            with any grading-specific warnings (e.g. "schema invalid —
            other flags evaluated against best-effort parse").
    """

    bouncer_kind: str
    profile_name: str
    overall: OverallVerdict
    flags: list[GradingFlag]
    simulation_summary: dict[str, int]
    provenance: dict[str, Any]


# ---------------------------------------------------------------------------
# Flag computation helpers.
# ---------------------------------------------------------------------------


def _adversarial_event_indices(
    events: list[dict[str, Any]], bouncer_kind: str,
) -> list[int]:
    """Return the indices of events that match
    :func:`is_known_adversarial`. Pure predicate match — the same
    catalogue the simulator's safety floor consults so the grader
    can't disagree about what "adversarial" means."""
    out: list[int] = []
    for idx, ev in enumerate(events or []):
        action, resource, _fields = _sim._extract_event_fields(
            ev, bouncer_kind,
        )
        if action and is_known_adversarial(
            action, bouncer=bouncer_kind, resource=resource,
        ):
            out.append(idx)
    return out


def _flag_blocks_known_risk_shapes(
    verdicts: _sim.SimulationVerdicts,
    events: list[dict[str, Any]],
    bouncer_kind: str,
) -> GradingFlag:
    adv_indices = _adversarial_event_indices(events, bouncer_kind)
    if not adv_indices:
        # No adversarial shapes in input → vacuously TRUE; rationale
        # surfaces the N/A nature so an operator doesn't read "pass"
        # as "tested + blocked."
        return GradingFlag(
            name="blocks_known_risk_shapes",
            pass_=True,
            rationale=(
                "no KNOWN_ADVERSARIAL_PATTERNS in input event window — "
                "flag vacuously passes (nothing to block)"
            ),
            evidence=[],
        )

    failures: list[str] = []
    evidence: list[str] = []
    by_idx = {v.event_idx: v for v in verdicts.verdicts}
    for adv_idx in adv_indices:
        v = by_idx.get(adv_idx)
        if v is None:
            # Simulator didn't emit a verdict for this index — shouldn't
            # happen but flag conservatively.
            failures.append(
                f"event[{adv_idx}]: no simulator verdict produced"
            )
            continue
        if v.verdict != "deny":
            failures.append(
                f"event[{adv_idx}]: verdict={v.verdict} "
                f"(expected deny); matched_rule={v.matched_rule!r}"
            )
        else:
            evidence.append(
                f"event[{adv_idx}]: deny via {v.matched_rule!r}"
            )

    if failures:
        return GradingFlag(
            name="blocks_known_risk_shapes",
            pass_=False,
            rationale=(
                f"{len(failures)} of {len(adv_indices)} adversarial "
                f"event(s) NOT denied — profile + safety floor "
                f"failed to catch them"
            ),
            evidence=failures,
        )
    return GradingFlag(
        name="blocks_known_risk_shapes",
        pass_=True,
        rationale=(
            f"all {len(adv_indices)} adversarial event(s) denied via "
            f"profile or safety floor"
        ),
        evidence=evidence,
    )


def _flag_under_friction_budget(
    verdicts: _sim.SimulationVerdicts,
    friction_budget: int | dict[str, Any] | None,
) -> GradingFlag:
    if friction_budget is None:
        return GradingFlag(
            name="under_friction_budget",
            pass_=True,
            rationale="no budget specified",
            evidence=[],
        )
    fm = verdicts.friction_metrics or {}
    over = bool(fm.get("over_budget", False))
    factor = fm.get("over_budget_factor", 0.0)
    actual = fm.get("actual_denies_in_window", 0)
    budget = fm.get("budget_max_denies_per_week", 0)
    estimated = fm.get("estimated_weekly_denies", 0.0)
    if over:
        return GradingFlag(
            name="under_friction_budget",
            pass_=False,
            rationale=(
                f"over budget: estimated_weekly_denies={estimated} "
                f"exceeds budget={budget} by factor {factor}x "
                f"(actual_denies_in_window={actual})"
            ),
            evidence=[
                f"friction_metrics.over_budget={over}",
                f"friction_metrics.over_budget_factor={factor}",
                f"friction_metrics.estimated_weekly_denies={estimated}",
            ],
        )
    return GradingFlag(
        name="under_friction_budget",
        pass_=True,
        rationale=(
            f"under budget: estimated_weekly_denies={estimated} "
            f"<= budget={budget}"
        ),
        evidence=[
            f"friction_metrics.over_budget={over}",
            f"friction_metrics.estimated_weekly_denies={estimated}",
        ],
    )


# Action classes that count as "write" for the allows_too_broad
# determination. READ is the only class that's safe under a `target:*`
# allow per design §2.1.
_WRITE_CLASSES: tuple[ActionClass, ...] = (
    ActionClass.WRITE_DATA,
    ActionClass.ADMIN,
    ActionClass.DESTRUCTIVE_DATA,
)


def _allow_rule_is_broad_write(
    rule: dict[str, Any], bouncer_kind: str,
) -> tuple[bool, list[str]]:
    """Return (is_broad_write, write_class_actions) for the rule.

    "Broad write" iff ``target == "*"`` (or omitted / empty) AND
    rule includes at least one action whose ActionClass is in
    :data:`_WRITE_CLASSES`. A literal ``"*"`` action also counts as
    a write (matches everything including writes) — caught by treating
    UNKNOWN-when-target-is-star as broad to avoid the "all-actions
    wildcard inside an all-target wildcard escapes the rubric" gap.
    """
    if not isinstance(rule, dict):
        return False, []
    target = rule.get("target")
    target_is_star = (
        target is None or target == "" or target == "*"
    )
    if not target_is_star:
        return False, []

    actions = rule.get("actions") or []
    if not isinstance(actions, list):
        return False, []

    offending: list[str] = []
    for act in actions:
        if not isinstance(act, str):
            continue
        # Universal "*" action under "*" target → admin-equivalent =
        # broad write.
        if act == "*":
            offending.append(act)
            continue
        cls = classify_action(bouncer_kind, act, resource=None)
        if cls in _WRITE_CLASSES:
            offending.append(act)
    return (len(offending) > 0), offending


def _flag_allows_too_broad(
    profile: dict[str, Any], bouncer_kind: str,
) -> GradingFlag:
    allow_rules = profile.get("allows") or []
    if not isinstance(allow_rules, list):
        return GradingFlag(
            name="allows_too_broad",
            pass_=True,
            rationale="profile has no 'allows' list — vacuously narrow",
            evidence=[],
        )

    broad_evidence: list[str] = []
    for idx, rule in enumerate(allow_rules):
        is_broad, offending = _allow_rule_is_broad_write(rule, bouncer_kind)
        if is_broad:
            broad_evidence.append(
                f"allows[{idx}]: target='*' + write-class action(s) "
                f"{offending}"
            )

    if broad_evidence:
        return GradingFlag(
            name="allows_too_broad",
            pass_=False,
            rationale=(
                f"{len(broad_evidence)} allow rule(s) pair target='*' "
                f"with a write-class action — profile is too broad"
            ),
            evidence=broad_evidence,
        )
    return GradingFlag(
        name="allows_too_broad",
        pass_=True,
        rationale=(
            "no allow rule pairs target='*' with a write-class action; "
            "broad reads are allowed but writes are scoped"
        ),
        evidence=[],
    )


# Per-bouncer rule-shape acceptance per [[cross-product-agent-parity]].
# Each accepts a rule dict and returns (ok, error_msg). The shared
# allow-shape ``{target, actions}`` is accepted by every bouncer's
# validator because the lean-permissive generator emits allows in that
# shape on every bouncer (see ``_lean_permissive_fallback_profile``).
# Bouncer-native deny shapes (kbounce verbs+resources, dbounce
# sql_patterns, gbounce host-only target) are accepted ONLY by their
# own validator — that's the per-bouncer awareness #571 Finding B
# adds.


def _check_actions_field(rule: dict[str, Any], section: str, idx: int) -> str | None:
    """Validate the shared allow-shape ``actions[]`` field on a rule.

    Returns an error message when the field is malformed, or None
    when the rule carries a valid ``actions`` list. Returns a sentinel
    error when the field is missing so callers can decide whether
    that's fatal (ibounce) or merely "try the bouncer-native shape
    next" (k/d/gbounce)."""
    if "actions" not in rule:
        return f"{section}[{idx}] missing required 'actions' field"
    acts = rule["actions"]
    if not isinstance(acts, list):
        return (
            f"{section}[{idx}].actions must be a list, got "
            f"{type(acts).__name__}"
        )
    return None


def _validate_ibounce_rule(
    rule: dict[str, Any], section: str, idx: int,
) -> list[str]:
    """ibounce: every rule MUST carry an ``actions[]`` list. Target
    may be omitted = match-all per simulator semantics. Matches the
    pre-#571 ibounce-only behaviour exactly per
    [[ibounce-honest-positioning]] regression discipline."""
    err = _check_actions_field(rule, section, idx)
    return [err] if err else []


def _validate_kbounce_rule(
    rule: dict[str, Any], section: str, idx: int,
) -> list[str]:
    """kbounce: rule MUST carry EITHER ``actions[]`` (lean-permissive
    allows) OR ``verbs[]+resources[]`` (safety-floor denies). Mixed
    shapes within a single profile are valid because
    ``_lean_permissive_fallback_profile`` builds allows in the shared
    shape but injects ``_SAFETY_FLOOR_DENIES["kbounce"]`` denies in
    the verbs-form."""
    if "actions" in rule:
        err = _check_actions_field(rule, section, idx)
        return [err] if err else []
    # Try the kbounce-native verbs+resources shape.
    missing: list[str] = []
    if "verbs" not in rule:
        missing.append(f"{section}[{idx}] missing 'verbs' field")
    elif not isinstance(rule["verbs"], list):
        missing.append(
            f"{section}[{idx}].verbs must be a list, got "
            f"{type(rule['verbs']).__name__}"
        )
    if "resources" not in rule:
        missing.append(f"{section}[{idx}] missing 'resources' field")
    elif not isinstance(rule["resources"], list):
        missing.append(
            f"{section}[{idx}].resources must be a list, got "
            f"{type(rule['resources']).__name__}"
        )
    if missing:
        return [
            f"{section}[{idx}] kbounce rule has neither 'actions' nor "
            f"'verbs'+'resources' shape: " + "; ".join(missing)
        ]
    return []


def _validate_dbounce_rule(
    rule: dict[str, Any], section: str, idx: int,
) -> list[str]:
    """dbounce: rule MUST carry EITHER ``actions[]`` (lean-permissive
    allows) OR ``sql_patterns[]`` (safety-floor denies). Mirror
    structure of ``_validate_kbounce_rule`` per
    [[cross-product-agent-parity]] — same dispatch shape per bouncer."""
    if "actions" in rule:
        err = _check_actions_field(rule, section, idx)
        return [err] if err else []
    if "sql_patterns" not in rule:
        return [
            f"{section}[{idx}] dbounce rule has neither 'actions' nor "
            f"'sql_patterns' field"
        ]
    if not isinstance(rule["sql_patterns"], list):
        return [
            f"{section}[{idx}].sql_patterns must be a list, got "
            f"{type(rule['sql_patterns']).__name__}"
        ]
    return []


def _validate_gbounce_rule(
    rule: dict[str, Any], section: str, idx: int,
) -> list[str]:
    """gbounce: rule MUST carry EITHER ``actions[]`` (lean-permissive
    allows) OR a host-shape field (``target`` / ``host`` /
    ``host_pattern``). The gbounce safety floor emits host-only
    denies (e.g. ``{target: 169.254.169.254}``) — see
    ``_SAFETY_FLOOR_DENIES["gbounce"]``."""
    if "actions" in rule:
        err = _check_actions_field(rule, section, idx)
        return [err] if err else []
    # Host-shape acceptance. Any of target / host / host_pattern as a
    # non-empty string counts as a valid host identifier.
    for host_key in ("target", "host", "host_pattern"):
        v = rule.get(host_key)
        if isinstance(v, str) and v:
            return []
    return [
        f"{section}[{idx}] gbounce rule has neither 'actions' nor "
        f"a host field ('target' / 'host' / 'host_pattern')"
    ]


# Per-bouncer rule validators per [[cross-product-agent-parity]].
# Unknown bouncer_kind values fall through to a sentinel that fails
# the schema flag with an explicit rationale rather than silently
# accepting anything.
SCHEMA_VALIDATORS: dict[
    str,
    Any,  # Callable[[dict, str, int], list[str]] — kept loose to
          # avoid an extra import for Callable typing in <py3.10 mode.
] = {
    "ibounce": _validate_ibounce_rule,
    "kbounce": _validate_kbounce_rule,
    "dbounce": _validate_dbounce_rule,
    "gbounce": _validate_gbounce_rule,
}


def _flag_schema_parses(
    profile: dict[str, Any], bouncer_kind: str,
) -> GradingFlag:
    """Honest schema check per [[ibounce-honest-positioning]]: must
    YAML-round-trip AND carry generator-shape structure. Not just
    ``isinstance(profile, dict)``.

    #571 Finding B: per-bouncer rule-shape dispatch via
    :data:`SCHEMA_VALIDATORS`. Previously hard-coded ibounce's
    ``actions[]`` requirement, which incorrectly failed every
    kbounce / dbounce / gbounce profile whose safety-floor denies
    use the bouncer-native shape (verbs+resources / sql_patterns /
    host-only target)."""
    if not isinstance(profile, dict):
        return GradingFlag(
            name="schema_parses",
            pass_=False,
            rationale=f"profile is not a dict (got {type(profile).__name__})",
            evidence=[f"type={type(profile).__name__!r}"],
        )

    # Round-trip through YAML so any non-serializable values
    # (custom objects, sets, etc.) surface here. yaml.safe_dump
    # raises yaml.representer.RepresenterError on non-primitive
    # types; yaml.safe_load is the inverse.
    try:
        rendered = yaml.safe_dump(profile, sort_keys=False)
        loaded = yaml.safe_load(rendered)
    except Exception as exc:
        return GradingFlag(
            name="schema_parses",
            pass_=False,
            rationale=f"YAML round-trip failed: {type(exc).__name__}: {exc}",
            evidence=[f"exception={type(exc).__name__}: {exc}"],
        )

    if not isinstance(loaded, dict):
        return GradingFlag(
            name="schema_parses",
            pass_=False,
            rationale=(
                f"YAML round-trip produced a "
                f"{type(loaded).__name__} not a dict"
            ),
            evidence=[f"loaded_type={type(loaded).__name__!r}"],
        )

    # Per-bouncer rule validator dispatch per #571 Finding B.
    rule_validator = SCHEMA_VALIDATORS.get(bouncer_kind)
    if rule_validator is None:
        return GradingFlag(
            name="schema_parses",
            pass_=False,
            rationale=(
                f"no schema validator registered for "
                f"bouncer_kind={bouncer_kind!r}; supported kinds: "
                f"{sorted(SCHEMA_VALIDATORS.keys())}"
            ),
            evidence=[f"bouncer_kind={bouncer_kind!r}"],
        )

    # Generator-shape structural validation — list-of-dict containers
    # are universal; per-rule field requirements dispatch via
    # rule_validator.
    structural_errors: list[str] = []
    for key in ("allows", "denies"):
        val = loaded.get(key)
        if val is None:
            continue
        if not isinstance(val, list):
            structural_errors.append(
                f"profile.{key} must be a list, got {type(val).__name__}"
            )
            continue
        for i, item in enumerate(val):
            if not isinstance(item, dict):
                structural_errors.append(
                    f"profile.{key}[{i}] must be a dict, got "
                    f"{type(item).__name__}"
                )
                continue
            structural_errors.extend(rule_validator(item, key, i))

    # A profile that has neither allows nor denies AND no bouncer
    # field is structurally indistinguishable from {} — not a usable
    # profile.
    if (
        not loaded.get("allows")
        and not loaded.get("denies")
        and not loaded.get("bouncer")
    ):
        structural_errors.append(
            "profile has no allows, no denies, and no bouncer field — "
            "empty / unidentifiable profile"
        )

    if structural_errors:
        return GradingFlag(
            name="schema_parses",
            pass_=False,
            rationale=(
                f"profile YAML round-trips but {len(structural_errors)} "
                f"structural error(s) detected against "
                f"bouncer_kind={bouncer_kind!r} schema"
            ),
            evidence=structural_errors,
        )

    return GradingFlag(
        name="schema_parses",
        pass_=True,
        rationale=(
            f"profile YAML round-trips cleanly + carries valid "
            f"{bouncer_kind} rule shape"
        ),
        evidence=[],
    )


_ADMIN_BASELINE_PROFILE: dict[str, Any] = {
    "bouncer": "admin-baseline",
    "profile_name": "admin-everything",
    "allows": [
        {
            "target": "*",
            "actions": ["*"],
            "reason": "admin baseline — allow everything",
        },
    ],
    "denies": [],
}


def _flag_narrows_vs_admin_baseline(
    profile: dict[str, Any],
    events: list[dict[str, Any]],
    bouncer_kind: str,
    profile_verdicts: _sim.SimulationVerdicts,
) -> GradingFlag:
    """At least one event where the profile denies but the
    admin-everything baseline would allow. Direct evidence of
    narrowing — not a structural diff that could be spoofed by a
    semantically-equivalent rewrite."""

    # If we have no events to compare, narrowing is unprovable.
    if not events:
        return GradingFlag(
            name="narrows_vs_admin_baseline",
            pass_=False,
            rationale=(
                "no events supplied — cannot demonstrate narrowing "
                "vs admin baseline"
            ),
            evidence=[],
        )

    baseline_verdicts = _sim.evaluate_profile_against_events(
        profile=_ADMIN_BASELINE_PROFILE,
        events=events,
        bouncer_kind=bouncer_kind,
        friction_budget=None,
    )

    baseline_by_idx = {v.event_idx: v for v in baseline_verdicts.verdicts}
    narrowing_evidence: list[str] = []
    for v in profile_verdicts.verdicts:
        bv = baseline_by_idx.get(v.event_idx)
        if bv is None:
            continue
        if v.verdict == "deny" and bv.verdict == "allow":
            narrowing_evidence.append(
                f"event[{v.event_idx}]: profile=deny "
                f"({v.matched_rule!r}) but admin-baseline=allow"
            )
            if len(narrowing_evidence) >= 5:
                break

    if narrowing_evidence:
        return GradingFlag(
            name="narrows_vs_admin_baseline",
            pass_=True,
            rationale=(
                f"profile denies at least 1 event the admin baseline "
                f"would allow — narrowing demonstrated"
            ),
            evidence=narrowing_evidence,
        )
    return GradingFlag(
        name="narrows_vs_admin_baseline",
        pass_=False,
        rationale=(
            "profile denies no event that the admin baseline would "
            "allow — no narrowing vs admin demonstrated against this "
            "event window"
        ),
        evidence=[],
    )


# ---------------------------------------------------------------------------
# Overall verdict computation.
# ---------------------------------------------------------------------------


def _compute_overall(flags: list[GradingFlag]) -> OverallVerdict:
    by_name = {f.name: f for f in flags}
    pass_count = sum(1 for f in flags if f.pass_)

    # NEGATIVE-VALUE escalation per spec: a profile that's broader
    # than admin baseline (both `allows_too_broad` FAILS and
    # `narrows_vs_admin_baseline` FAILS) is actively dangerous.
    too_broad_pass = by_name["allows_too_broad"].pass_
    narrows_pass = by_name["narrows_vs_admin_baseline"].pass_
    if not too_broad_pass and not narrows_pass:
        return "NEGATIVE-VALUE"

    if pass_count == 0:
        return "NEGATIVE-VALUE"
    if pass_count == 5:
        return "MEANINGFUL"
    if pass_count >= 3:
        return "PARTIAL"
    return "THEATER"


# ---------------------------------------------------------------------------
# Provenance.
# ---------------------------------------------------------------------------


def _build_provenance(
    sim_verdicts: _sim.SimulationVerdicts,
    grading_warnings: list[str],
) -> dict[str, Any]:
    """Forward the simulator's engine + parity caveats into the
    grading report's provenance per [[ibounce-honest-positioning]].

    When ``production_parity is False`` (currently always per Phase 4)
    a top-of-list grading warning makes that dependency explicit so an
    operator can't read the grading verdict without seeing that it's
    only as good as the simulator."""
    sim_prov = sim_verdicts.provenance or {}
    merged_warnings: list[str] = []
    if sim_prov.get("production_parity") is False:
        # Per Phase 10 (calibration-corpus): when the corpus is
        # validated, soften the GRADING DEPENDS warning so it
        # reflects what's actually true — the rubric is corpus-
        # calibrated but the simulator's production parity is still
        # pending head-to-head Go-engine validation. Honesty per
        # [[ibounce-honest-positioning]]: the warning shift must
        # reflect which dimensions are calibrated vs which are not.
        if CALIBRATION_CORPUS_VALIDATED:
            merged_warnings.append(
                f"Rubric validated against {CALIBRATION_CORPUS_SIZE}-"
                f"scenario calibration corpus v"
                f"{CALIBRATION_CORPUS_VERSION} per Phase 10; "
                f"simulator production_parity=False — grading verdicts "
                f"are corpus-calibrated but the simulator engine has "
                f"NOT been validated head-to-head against the "
                f"production Go bouncers in this commit"
            )
        else:
            merged_warnings.append(
                "GRADING DEPENDS ON SIMULATOR ACCURACY: simulator "
                "production_parity=False per Phase 4 — grading verdicts "
                "are only as good as the simulator's rule-evaluation "
                "engine, which has NOT been validated head-to-head against "
                "the production bouncers in this commit"
            )
    merged_warnings.extend(sim_prov.get("warnings") or [])
    merged_warnings.extend(grading_warnings)
    return {
        "grading_version": GRADING_VERSION,
        "simulator_engine": sim_prov.get("engine", "unknown"),
        "simulator_engine_version": sim_prov.get(
            "engine_version", "unknown",
        ),
        "simulator_production_parity": bool(
            sim_prov.get("production_parity", False)
        ),
        "calibration_corpus_validated": CALIBRATION_CORPUS_VALIDATED,
        "calibration_corpus_version": CALIBRATION_CORPUS_VERSION,
        "calibration_corpus_size": CALIBRATION_CORPUS_SIZE,
        "warnings": merged_warnings,
    }


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def grade_profile_for_workflow(
    profile: dict[str, Any],
    events: list[dict[str, Any]],
    bouncer_kind: str,
    friction_budget: int | dict[str, Any] | None = None,
) -> GradingReport:
    """Grade a profile against a workflow of audit events.

    Runs :func:`iam_jit.llm.simulator.evaluate_profile_against_events`
    under the hood and scores the resulting verdicts against the
    5-flag rubric per ``docs/PROFILE-GENERATION-DESIGN.md`` §7
    (Phase 5 spec).

    Args:
        profile: parsed profile dict — generator-shape (`allows /
            denies / bouncer / ...`) emitted by
            ``bounce_profile_generate_from_audit``.
        events: list of OCSF audit events.
        bouncer_kind: which bouncer's rule semantics apply.
        friction_budget: optional. Int = max legitimate denies per
            week. Dict per design §4.1 with
            ``max_legitimate_denies_per_day`` /
            ``max_legitimate_denies_per_week``. ``None`` makes the
            friction flag N/A (rationale="no budget specified");
            doesn't fail-by-default per spec.

    Returns:
        :class:`GradingReport` — overall verdict in ``overall``;
        per-flag results in ``flags`` (canonical FlagName order);
        ``simulation_summary`` mirrors
        :attr:`SimulationVerdicts.summary`; ``provenance`` surfaces
        the simulator's parity caveat.
    """
    profile = profile or {}
    events = events or []
    bouncer_kind = (bouncer_kind or "").strip()

    # Run the simulator once — the profile + events evaluation feeds
    # multiple flags (blocks_known_risk + under_friction + narrows).
    sim_verdicts = _sim.evaluate_profile_against_events(
        profile=profile,
        events=events,
        bouncer_kind=bouncer_kind,
        friction_budget=friction_budget,
    )

    grading_warnings: list[str] = []

    # Evaluate flags in canonical order. Per #571 Finding B
    # schema_parses dispatches per-bouncer through SCHEMA_VALIDATORS.
    schema_flag = _flag_schema_parses(profile, bouncer_kind)
    if not schema_flag.pass_:
        grading_warnings.append(
            "profile schema_parses flag FAILED — other flags were "
            "evaluated against the best-effort parse; rerun grading "
            "after fixing schema for accurate results"
        )

    flags: list[GradingFlag] = [
        _flag_blocks_known_risk_shapes(
            sim_verdicts, events, bouncer_kind,
        ),
        _flag_under_friction_budget(sim_verdicts, friction_budget),
        _flag_allows_too_broad(profile, bouncer_kind),
        schema_flag,
        _flag_narrows_vs_admin_baseline(
            profile, events, bouncer_kind, sim_verdicts,
        ),
    ]

    overall = _compute_overall(flags)

    provenance = _build_provenance(sim_verdicts, grading_warnings)

    profile_name = str(
        profile.get("profile_name")
        or profile.get("bouncer")
        or ""
    )

    return GradingReport(
        bouncer_kind=bouncer_kind,
        profile_name=profile_name,
        overall=overall,
        flags=flags,
        simulation_summary=dict(sim_verdicts.summary),
        provenance=provenance,
    )


def serialize_grading_report(report: GradingReport) -> dict[str, Any]:
    """JSON-safe dict form. Used by the MCP tool wrapper so the
    dataclass nesting does not leak ``__dataclass_fields__`` etc. into
    the protocol payload."""
    return {
        "bouncer_kind": report.bouncer_kind,
        "profile_name": report.profile_name,
        "overall": report.overall,
        "flags": [
            {
                "name": f.name,
                "pass": f.pass_,
                "rationale": f.rationale,
                "evidence": list(f.evidence),
            }
            for f in report.flags
        ],
        "simulation_summary": dict(report.simulation_summary),
        "provenance": dict(report.provenance),
    }


__all__ = [
    "GRADING_VERSION",
    "GradingFlag",
    "GradingReport",
    "grade_profile_for_workflow",
    "serialize_grading_report",
]
