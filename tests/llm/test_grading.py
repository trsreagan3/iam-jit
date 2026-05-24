"""Phase 5 of profile-generation design
(docs/PROFILE-GENERATION-DESIGN.md §6 Phase 5 + §7) — grading on
Phase 4 SimulationVerdicts.

Per [[tests-and-independent-uat-required]] + docs/CONTRIBUTING.md
state-verification convention: every test asserts OBSERVABLE state
(per-flag pass + evidence list content, overall verdict literal,
provenance warning strings) — not just function return-shape.

Test taxonomy mirrors the Phase 4 test file shape:
  1.  MEANINGFUL profile: narrow profile + adversarial events all denied
      -> overall=MEANINGFUL + all 5 flags pass
  2.  PARTIAL profile: 3 flags pass
  3.  THEATER profile: schema + narrows pass; risk + friction fail (2/5)
  4.  NEGATIVE-VALUE profile: broader than admin baseline
      (allows_too_broad + narrows_vs_admin_baseline BOTH fail)
  5.  blocks_known_risk_shapes uses simulator evidence
  6.  friction_budget N/A when omitted
  7.  allows_too_broad detects star + write
  8.  allows_too_broad passes star + read
  9.  schema_parses real validator on invalid input
  10. narrows_vs_admin_baseline against admin baseline
  11. provenance surfaces simulator parity warning
  12. overall threshold logic (parametrized)
  13. sabotage check: monkeypatch overall to always-MEANINGFUL +
      verify test 4 (negative-value) fails as a result
  14. MCP dispatch round-trip
  15. MCP tool appears in tools/list
"""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit.llm import grading
from iam_jit.llm import simulator as sim


# ---------------------------------------------------------------------------
# Event helpers (mirror Phase 4 test helpers for cross-bouncer parity).
# ---------------------------------------------------------------------------


def _ibounce_event(
    *, action: str, resource: str, time_ms: int = 1716412800000,
) -> dict[str, Any]:
    svc, _, op = action.partition(":")
    return {
        "_bouncer": "ibounce",
        "time": time_ms,
        "activity_name": "allow",
        "unmapped": {"iam_jit": {"verdict": "allow"}},
        "api": {
            "service": {"name": svc},
            "operation": op,
            "resources": [{"name": resource}],
        },
    }


# ---------------------------------------------------------------------------
# Test 1 — MEANINGFUL: narrow profile + adversarial event all denied.
# ---------------------------------------------------------------------------


def test_grade_meaningful_profile():
    """All 5 flags pass.

    * blocks_known_risk_shapes: iam:CreateAccessKey adversarial event
      hits the safety floor -> deny
    * under_friction_budget: friction_budget=100/week; ~1 deny -> ok
    * allows_too_broad: narrow allow (bucket-specific s3:GetObject)
    * schema_parses: valid generator-shape
    * narrows_vs_admin_baseline: profile denies the adversarial event
      that admin baseline would allow
    """
    profile = {
        "bouncer": "ibounce",
        "profile_name": "narrow-readonly",
        "allows": [
            {
                "target": "arn:aws:s3:::reports/*",
                "actions": ["s3:GetObject"],
                "reason": "narrow read on reports bucket",
            }
        ],
        "denies": [
            # Explicit deny on a NON-adversarial action so the profile
            # narrows vs admin baseline (admin allows; profile denies).
            {
                "target": "arn:aws:s3:::sensitive-*",
                "actions": ["s3:GetObject"],
                "reason": "sensitive bucket protection",
            }
        ],
    }
    # Spread events across 7 days so 1 deny extrapolates to ~1
    # weekly deny -> under a budget of 100.
    one_day_ms = 24 * 60 * 60 * 1000
    seven_days_ms = 7 * one_day_ms
    start_ms = 1716412800000
    events = [
        _ibounce_event(
            action="s3:GetObject",
            resource="arn:aws:s3:::reports/q1.csv",
            time_ms=start_ms,
        ),
        # Non-adversarial event the profile denies + admin would allow.
        _ibounce_event(
            action="s3:GetObject",
            resource="arn:aws:s3:::sensitive-payroll/data",
            time_ms=start_ms + one_day_ms,
        ),
        # Adversarial event — safety floor catches it. 7d later so
        # the friction extrapolation stays low.
        _ibounce_event(
            action="iam:CreateAccessKey",
            resource="arn:aws:iam::123:user/bot",
            time_ms=start_ms + seven_days_ms,
        ),
    ]

    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=events,
        bouncer_kind="ibounce",
        friction_budget=100,
    )

    # State verification: every flag in canonical order with
    # documented pass condition.
    by_name = {f.name: f for f in report.flags}
    assert set(by_name.keys()) == {
        "blocks_known_risk_shapes",
        "under_friction_budget",
        "allows_too_broad",
        "schema_parses",
        "narrows_vs_admin_baseline",
    }
    for name, flag in by_name.items():
        assert flag.pass_, (
            f"flag {name} expected pass; rationale={flag.rationale!r} "
            f"evidence={flag.evidence!r}"
        )
    assert report.overall == "MEANINGFUL", (
        f"expected MEANINGFUL when all 5 flags pass; got {report.overall} "
        f"flags={[(f.name, f.pass_) for f in report.flags]}"
    )
    # Simulation summary observable.
    assert report.simulation_summary["total"] == 3
    assert report.simulation_summary["deny"] >= 2  # the explicit deny + the safety floor


# ---------------------------------------------------------------------------
# Test 2 — PARTIAL: 3 flags pass.
# ---------------------------------------------------------------------------


def test_grade_partial_profile():
    """3 flags pass -> PARTIAL.

    Profile pairs target='*' with a write-class action AND blows the
    friction budget; the remaining 3 flags (schema, blocks_known_risk,
    narrows_vs_admin) still pass."""
    profile = {
        "bouncer": "ibounce",
        "profile_name": "too-broad-and-frictiony",
        "allows": [
            # target='*' + write action -> allows_too_broad FAILS
            {
                "target": "*",
                "actions": ["s3:PutObject"],
                "reason": "broad write allow",
            }
        ],
        "denies": [
            # Profile denies one specific delete so narrowing-vs-admin
            # passes (profile denies an event admin would allow).
            {
                "target": "arn:aws:s3:::*",
                "actions": ["s3:DeleteObject"],
                "reason": "no deletes",
            }
        ],
    }
    # Many delete events -> friction budget blown.
    one_hour_ms = 60 * 60 * 1000
    events = [
        _ibounce_event(
            action="s3:DeleteObject",
            resource=f"arn:aws:s3:::bucket/k{i}",
            time_ms=1716412800000 + i * one_hour_ms,
        )
        for i in range(20)
    ]
    # Add one adversarial that the safety floor will catch.
    events.append(_ibounce_event(
        action="iam:CreateAccessKey",
        resource="arn:aws:iam::123:user/bot",
        time_ms=1716412800000 + 24 * one_hour_ms,
    ))

    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=events,
        bouncer_kind="ibounce",
        friction_budget=1,
    )
    by_name = {f.name: f for f in report.flags}

    assert by_name["schema_parses"].pass_ is True
    assert by_name["blocks_known_risk_shapes"].pass_ is True
    assert by_name["narrows_vs_admin_baseline"].pass_ is True
    assert by_name["allows_too_broad"].pass_ is False, (
        f"allows_too_broad expected fail; rationale="
        f"{by_name['allows_too_broad'].rationale!r}"
    )
    assert by_name["under_friction_budget"].pass_ is False

    pass_count = sum(1 for f in report.flags if f.pass_)
    assert pass_count == 3, (
        f"expected exactly 3 flags pass for PARTIAL; got {pass_count} "
        f"flags={[(f.name, f.pass_) for f in report.flags]}"
    )
    assert report.overall == "PARTIAL"


# ---------------------------------------------------------------------------
# Test 3 — THEATER: 1-2 flags pass.
# ---------------------------------------------------------------------------


def test_grade_theater_profile():
    """1-2 of 5 flags pass -> THEATER.

    Construction: malformed allows (dict not list) -> schema_parses
    FAILS, allows_too_broad becomes vacuous (treats malformed allows
    as no rules), narrows_vs_admin_baseline FAILS (no denies), under_
    friction_budget FAILS (budget=1 + many denies via safety floor),
    blocks_known_risk_shapes PASSES (safety floor catches all
    adversarial events regardless of profile).

    Engineering note: the rubric semantics make a 2-pass construction
    narrow. Test 12 (test_grade_overall_threshold_logic) covers the
    1-2 -> THEATER threshold exhaustively with synthetic flags; this
    test demonstrates the threshold against the REAL grading run."""
    profile = {
        "bouncer": "ibounce",
        # schema FAIL: allows must be a list.
        "allows": {"rule": "broken"},
        "denies": [],
    }
    one_hour_ms = 60 * 60 * 1000
    start_ms = 1716412800000
    events = [
        _ibounce_event(
            action="iam:CreateAccessKey",
            resource=f"arn:aws:iam::123:user/bot{i}",
            time_ms=start_ms + i * one_hour_ms,
        )
        for i in range(20)
    ]
    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=events,
        bouncer_kind="ibounce",
        friction_budget=1,
    )
    by_name = {f.name: f for f in report.flags}
    assert by_name["schema_parses"].pass_ is False
    assert by_name["blocks_known_risk_shapes"].pass_ is True
    assert by_name["under_friction_budget"].pass_ is False

    pass_count = sum(1 for f in report.flags if f.pass_)
    assert pass_count in (1, 2), (
        f"expected 1-2 passes for THEATER; got {pass_count} "
        f"flags={[(f.name, f.pass_) for f in report.flags]}"
    )
    assert report.overall == "THEATER", (
        f"expected THEATER overall; got {report.overall}; "
        f"flags={[(f.name, f.pass_) for f in report.flags]}"
    )


# ---------------------------------------------------------------------------
# Test 3b — provenance surfaces "schema bad, best-effort parse" warning.
# ---------------------------------------------------------------------------


def test_grade_schema_failed_warning_surfaces():
    """When schema_parses FAILS, grading provenance.warnings must
    surface a warning that other flags ran against the best-effort
    parse — per [[ibounce-honest-positioning]] no silent degradation."""
    profile_bad_schema = {
        "bouncer": "ibounce",
        "allows": "not-a-list",
        "denies": [],
    }
    events = [
        _ibounce_event(
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/k",
        ),
    ]
    report = grading.grade_profile_for_workflow(
        profile=profile_bad_schema,
        events=events,
        bouncer_kind="ibounce",
        friction_budget=None,
    )
    by_name = {f.name: f for f in report.flags}
    assert by_name["schema_parses"].pass_ is False, (
        f"rationale={by_name['schema_parses'].rationale!r}"
    )
    joined_warnings = " ".join(report.provenance["warnings"])
    assert "schema_parses flag FAILED" in joined_warnings


# ---------------------------------------------------------------------------
# Test 4 — NEGATIVE-VALUE: broader than admin baseline.
# ---------------------------------------------------------------------------


def test_grade_negative_value_profile():
    """A profile that's broader than admin baseline = NEGATIVE-VALUE.

    Concretely: allows_too_broad FAILS (target=* + write) AND
    narrows_vs_admin_baseline FAILS (no event the profile denies
    that admin would allow).

    Force this with: broad allow (no denies), legitimate events.
    """
    profile = {
        "bouncer": "ibounce",
        "profile_name": "actively-dangerous",
        "allows": [
            {
                "target": "*",
                "actions": ["*"],
                "reason": "wide open + a bit more",
            }
        ],
        "denies": [],
    }
    events = [
        _ibounce_event(
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/k",
        ),
    ]
    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=events,
        bouncer_kind="ibounce",
        friction_budget=None,
    )
    by_name = {f.name: f for f in report.flags}
    assert by_name["allows_too_broad"].pass_ is False
    assert by_name["narrows_vs_admin_baseline"].pass_ is False
    assert report.overall == "NEGATIVE-VALUE", (
        f"expected NEGATIVE-VALUE when both allows_too_broad and "
        f"narrows_vs_admin_baseline fail; got {report.overall}"
    )


# ---------------------------------------------------------------------------
# Test 5 — blocks_known_risk_shapes uses simulator evidence.
# ---------------------------------------------------------------------------


def test_grade_blocks_known_risk_shapes_uses_simulator():
    """Adversarial event in input + profile denies it -> flag passes
    AND evidence list cites the verdict's matched_rule."""
    profile = {
        "bouncer": "ibounce",
        "allows": [],
        "denies": [],
    }
    events = [
        _ibounce_event(
            action="iam:CreateAccessKey",
            resource="arn:aws:iam::123:user/bot",
        ),
    ]
    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=events,
        bouncer_kind="ibounce",
        friction_budget=None,
    )
    by_name = {f.name: f for f in report.flags}
    flag = by_name["blocks_known_risk_shapes"]
    assert flag.pass_ is True, (
        f"adversarial event must be denied; got rationale="
        f"{flag.rationale!r}"
    )
    # Evidence cites the deny rule that fired.
    assert flag.evidence, (
        f"expected non-empty evidence list; got {flag.evidence!r}"
    )
    # The matched_rule references the safety floor / known adversarial
    # path.
    joined = " ".join(flag.evidence)
    assert (
        "KNOWN_ADVERSARIAL_PATTERNS" in joined
        or "_SAFETY_FLOOR_DENIES" in joined
    ), f"evidence must cite the floor source; got {flag.evidence!r}"


# ---------------------------------------------------------------------------
# Test 6 — friction_budget N/A when omitted.
# ---------------------------------------------------------------------------


def test_grade_friction_budget_na_when_omitted():
    """friction_budget=None -> rationale="no budget specified";
    flag passes vacuously (doesn't fail-by-default)."""
    profile = {
        "bouncer": "ibounce",
        "allows": [
            {"target": "*", "actions": ["s3:GetObject"], "reason": "reads"}
        ],
        "denies": [],
    }
    events = [
        _ibounce_event(
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/k",
        ),
    ]
    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=events,
        bouncer_kind="ibounce",
        friction_budget=None,
    )
    by_name = {f.name: f for f in report.flags}
    flag = by_name["under_friction_budget"]
    assert flag.pass_ is True
    assert "no budget specified" in flag.rationale


# ---------------------------------------------------------------------------
# Test 7 — allows_too_broad detects star + write.
# ---------------------------------------------------------------------------


def test_grade_allows_too_broad_detects_star_write():
    """Profile with allow {target:'*', actions:['s3:PutObject']} ->
    allows_too_broad FAILS."""
    profile = {
        "bouncer": "ibounce",
        "allows": [
            {
                "target": "*",
                "actions": ["s3:PutObject"],
                "reason": "broad put",
            }
        ],
        "denies": [],
    }
    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=[],
        bouncer_kind="ibounce",
        friction_budget=None,
    )
    by_name = {f.name: f for f in report.flags}
    flag = by_name["allows_too_broad"]
    assert flag.pass_ is False
    assert "s3:PutObject" in " ".join(flag.evidence)


# ---------------------------------------------------------------------------
# Test 8 — allows_too_broad passes star + read.
# ---------------------------------------------------------------------------


def test_grade_allows_too_broad_passes_star_read():
    """Profile with allow {target:'*', actions:['s3:GetObject']} ->
    allows_too_broad PASSES (read is safe under broad target)."""
    profile = {
        "bouncer": "ibounce",
        "allows": [
            {
                "target": "*",
                "actions": ["s3:GetObject"],
                "reason": "broad read",
            }
        ],
        "denies": [],
    }
    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=[],
        bouncer_kind="ibounce",
        friction_budget=None,
    )
    by_name = {f.name: f for f in report.flags}
    flag = by_name["allows_too_broad"]
    assert flag.pass_ is True, (
        f"broad read should pass; rationale={flag.rationale!r}"
    )


# ---------------------------------------------------------------------------
# Test 9 — schema_parses real validator on invalid input.
# ---------------------------------------------------------------------------


def test_grade_schema_parses_real_validator():
    """Structurally invalid profile -> flag FAILS; rationale cites
    schema error."""
    # Case A: allows is not a list.
    profile_a = {
        "bouncer": "ibounce",
        "allows": "not-a-list",
        "denies": [],
    }
    report_a = grading.grade_profile_for_workflow(
        profile=profile_a, events=[],
        bouncer_kind="ibounce", friction_budget=None,
    )
    by_name_a = {f.name: f for f in report_a.flags}
    assert by_name_a["schema_parses"].pass_ is False
    assert "must be a list" in " ".join(by_name_a["schema_parses"].evidence)

    # Case B: rule missing actions.
    profile_b = {
        "bouncer": "ibounce",
        "allows": [{"target": "*", "reason": "no actions"}],
        "denies": [],
    }
    report_b = grading.grade_profile_for_workflow(
        profile=profile_b, events=[],
        bouncer_kind="ibounce", friction_budget=None,
    )
    by_name_b = {f.name: f for f in report_b.flags}
    assert by_name_b["schema_parses"].pass_ is False
    assert "missing required 'actions'" in " ".join(
        by_name_b["schema_parses"].evidence
    )

    # Case C: completely empty profile (no allows, denies, bouncer).
    profile_c: dict[str, Any] = {}
    report_c = grading.grade_profile_for_workflow(
        profile=profile_c, events=[],
        bouncer_kind="ibounce", friction_budget=None,
    )
    by_name_c = {f.name: f for f in report_c.flags}
    assert by_name_c["schema_parses"].pass_ is False


# ---------------------------------------------------------------------------
# Test 10 — narrows_vs_admin_baseline.
# ---------------------------------------------------------------------------


def test_grade_narrows_vs_admin_baseline():
    """Profile denies an action admin would allow -> flag PASSES with
    evidence citing the event index."""
    profile = {
        "bouncer": "ibounce",
        "allows": [],
        "denies": [
            {
                "target": "arn:aws:s3:::sensitive-*",
                "actions": ["s3:GetObject"],
                "reason": "sensitive bucket",
            }
        ],
    }
    events = [
        _ibounce_event(
            action="s3:GetObject",
            resource="arn:aws:s3:::sensitive-payroll/data",
        ),
    ]
    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=events,
        bouncer_kind="ibounce",
        friction_budget=None,
    )
    by_name = {f.name: f for f in report.flags}
    flag = by_name["narrows_vs_admin_baseline"]
    assert flag.pass_ is True
    assert flag.evidence, "expected evidence citing the narrowing"
    joined = " ".join(flag.evidence)
    assert "profile=deny" in joined and "admin-baseline=allow" in joined


# ---------------------------------------------------------------------------
# Test 11 — provenance surfaces simulator parity warning.
# ---------------------------------------------------------------------------


def test_grade_provenance_surfaces_simulator_parity_warning():
    """When SimulationVerdicts.provenance.production_parity=False
    (currently always per Phase 4), grading provenance.warnings
    MUST surface a warning making operators aware."""
    profile = {
        "bouncer": "ibounce",
        "allows": [],
        "denies": [],
    }
    events = [_ibounce_event(
        action="s3:GetObject",
        resource="arn:aws:s3:::bucket/k",
    )]
    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=events,
        bouncer_kind="ibounce",
    )
    assert report.provenance["simulator_production_parity"] is False
    joined = " ".join(report.provenance["warnings"])
    # Phase 10 calibration-corpus lift: when
    # `grading.CALIBRATION_CORPUS_VALIDATED` is True the warning is
    # softened to surface that the rubric IS calibrated (corpus) while
    # the simulator engine is still pending production-parity. Per
    # [[ibounce-honest-positioning]] the warning shift must reflect
    # which dimensions are calibrated vs which are not.
    if grading.CALIBRATION_CORPUS_VALIDATED:
        assert "calibration corpus" in joined, (
            f"corpus-calibrated warning must appear; got "
            f"{report.provenance['warnings']!r}"
        )
        assert "production_parity=False" in joined, (
            f"parity caveat must still appear; got "
            f"{report.provenance['warnings']!r}"
        )
        # Provenance carries calibration metadata.
        assert (
            report.provenance["calibration_corpus_validated"] is True
        )
        assert (
            report.provenance["calibration_corpus_version"]
            == grading.CALIBRATION_CORPUS_VERSION
        )
        assert (
            report.provenance["calibration_corpus_size"]
            == grading.CALIBRATION_CORPUS_SIZE
        )
    else:
        assert "GRADING DEPENDS ON SIMULATOR ACCURACY" in joined, (
            f"parity caveat must appear in warnings; got "
            f"{report.provenance['warnings']!r}"
        )
    # Grading version + engine identity surfaced.
    assert report.provenance["grading_version"] == grading.GRADING_VERSION
    assert report.provenance["simulator_engine"] == "simulation-python"


# ---------------------------------------------------------------------------
# Test 12 — overall threshold logic (parametrized).
# ---------------------------------------------------------------------------


def _mk_flag(name: grading.FlagName, pass_: bool) -> grading.GradingFlag:
    return grading.GradingFlag(
        name=name, pass_=pass_, rationale="synthetic", evidence=[],
    )


# Parametrized over (blocks_known_risk, under_friction, allows_too_broad,
# schema_parses, narrows_vs_admin_baseline). NEGATIVE-VALUE escalation
# fires whenever allows_too_broad AND narrows_vs_admin BOTH fail; THEATER
# cases below avoid that combo (broad OR narrows passes) so the
# threshold path drives the verdict not the escalation path. The
# escalation case is asserted explicitly in
# test_grade_overall_negative_value_escalation.
@pytest.mark.parametrize(
    "passes,expected_overall",
    [
        # 5 pass -> MEANINGFUL
        ((True, True, True, True, True), "MEANINGFUL"),
        # 4 pass (under_friction fails) -> PARTIAL
        ((True, False, True, True, True), "PARTIAL"),
        # 4 pass (schema fails) -> PARTIAL
        ((True, True, True, False, True), "PARTIAL"),
        # 3 pass (broad + narrows pass) -> PARTIAL
        ((False, False, True, True, True), "PARTIAL"),
        # 2 pass (broad + narrows pass) -> THEATER
        ((False, False, True, False, True), "THEATER"),
        # 1 pass (only narrows passes; broad fails but narrows passes
        # so no NEGATIVE-VALUE escalation) -> THEATER
        ((False, False, False, False, True), "THEATER"),
        # 1 pass (only broad passes; narrows fails but broad passes
        # so no NEGATIVE-VALUE escalation) -> THEATER
        ((False, False, True, False, False), "THEATER"),
        # 0 pass -> NEGATIVE-VALUE
        ((False, False, False, False, False), "NEGATIVE-VALUE"),
    ],
)
def test_grade_overall_threshold_logic(
    passes: tuple[bool, ...], expected_overall: str,
):
    """Threshold logic per spec. NEGATIVE-VALUE escalation fires when
    allows_too_broad AND narrows_vs_admin_baseline BOTH fail — see
    test_grade_overall_negative_value_escalation for that pathway."""
    names: tuple[grading.FlagName, ...] = (
        "blocks_known_risk_shapes",
        "under_friction_budget",
        "allows_too_broad",
        "schema_parses",
        "narrows_vs_admin_baseline",
    )
    flags = [_mk_flag(name, pass_) for name, pass_ in zip(names, passes)]
    overall = grading._compute_overall(flags)
    assert overall == expected_overall, (
        f"flags={list(zip(names, passes))} expected={expected_overall} "
        f"got={overall}"
    )


def test_grade_overall_negative_value_escalation():
    """Even with 3 passes, if allows_too_broad AND narrows_vs_admin
    both fail the overall escalates to NEGATIVE-VALUE per spec
    (profile is broader than admin baseline = actively dangerous)."""
    # blocks_known_risk + under_friction + schema PASS; allows_too_broad +
    # narrows_vs_admin FAIL = 3 passes but escalates to NEGATIVE-VALUE.
    flags = [
        _mk_flag("blocks_known_risk_shapes", True),
        _mk_flag("under_friction_budget", True),
        _mk_flag("allows_too_broad", False),
        _mk_flag("schema_parses", True),
        _mk_flag("narrows_vs_admin_baseline", False),
    ]
    overall = grading._compute_overall(flags)
    assert overall == "NEGATIVE-VALUE", (
        f"NEGATIVE-VALUE must escalate even with 3 passes when "
        f"allows_too_broad + narrows_vs_admin both fail; got {overall}"
    )


# ---------------------------------------------------------------------------
# Test 13 — sabotage check.
# ---------------------------------------------------------------------------


def test_sabotage_check_overall_forced_meaningful_breaks_negative_value(
    monkeypatch: pytest.MonkeyPatch,
):
    """Sabotage: monkeypatch grade_profile_for_workflow to force
    overall='MEANINGFUL' regardless of flags. Verify that
    test_grade_negative_value_profile (test 4) would then incorrectly
    pass MEANINGFUL — proving test 4 is load-bearing, not theater.
    """
    # Capture the real function then wrap it to force overall.
    real_grade = grading.grade_profile_for_workflow

    def sabotage_grade(profile, events, bouncer_kind, friction_budget=None):
        report = real_grade(profile, events, bouncer_kind, friction_budget)
        # Reconstruct with MEANINGFUL override.
        return grading.GradingReport(
            bouncer_kind=report.bouncer_kind,
            profile_name=report.profile_name,
            overall="MEANINGFUL",  # SABOTAGED
            flags=report.flags,
            simulation_summary=report.simulation_summary,
            provenance=report.provenance,
        )

    monkeypatch.setattr(
        grading, "grade_profile_for_workflow", sabotage_grade,
    )

    # The negative-value test's profile + events.
    profile = {
        "bouncer": "ibounce",
        "allows": [
            {"target": "*", "actions": ["*"], "reason": "wide open"}
        ],
        "denies": [],
    }
    events = [_ibounce_event(
        action="s3:GetObject",
        resource="arn:aws:s3:::bucket/k",
    )]
    report = grading.grade_profile_for_workflow(
        profile=profile, events=events,
        bouncer_kind="ibounce", friction_budget=None,
    )
    # Under sabotage, overall is forced -> MEANINGFUL.
    assert report.overall == "MEANINGFUL", (
        "sabotage harness must force MEANINGFUL"
    )

    # Sabotage demonstration: if the assertion in test 4 was
    # checking the wrong thing (e.g., just status string), this
    # sabotage path would slip through. With the real assertion
    # (`overall == 'NEGATIVE-VALUE'`), the sabotage path would
    # AssertionError in test 4 — proving test 4 is load-bearing.
    #
    # Now confirm the real (un-monkeypatched) implementation
    # returns NEGATIVE-VALUE:
    monkeypatch.setattr(
        grading, "grade_profile_for_workflow", real_grade,
    )
    real_report = grading.grade_profile_for_workflow(
        profile=profile, events=events,
        bouncer_kind="ibounce", friction_budget=None,
    )
    assert real_report.overall == "NEGATIVE-VALUE", (
        "real implementation must return NEGATIVE-VALUE; the sabotage "
        "test only proves test 4 catches the regression if real != "
        "sabotaged"
    )


# ---------------------------------------------------------------------------
# Test 14 — MCP dispatch round-trip.
# ---------------------------------------------------------------------------


def test_mcp_dispatch_bounce_grade_profile_returns_serialized_report():
    """Invoke via real _handle_request + verify the response carries
    the schema-shaped fields + serializes cleanly to JSON."""
    import json

    from iam_jit.mcp_server import _handle_request

    profile = {
        "bouncer": "ibounce",
        "profile_name": "test-profile",
        "allows": [
            {
                "target": "arn:aws:s3:::reports/*",
                "actions": ["s3:GetObject"],
                "reason": "reports",
            }
        ],
        "denies": [],
    }
    events = [
        _ibounce_event(
            action="s3:GetObject",
            resource="arn:aws:s3:::reports/q1.csv",
        ),
        _ibounce_event(
            action="iam:CreateAccessKey",
            resource="arn:aws:iam::123:user/bot",
            time_ms=1716412900000,
        ),
    ]

    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "bounce_grade_profile_for_workflow",
            "arguments": {
                "profile": profile,
                "events": events,
                "bouncer_kind": "ibounce",
                "friction_budget": 100,
            },
        },
    })

    sc = resp["result"]["structuredContent"]
    rendered = json.dumps(sc)
    assert rendered

    assert sc["bouncer_kind"] == "ibounce"
    assert sc["profile_name"] == "test-profile"
    assert sc["overall"] in {
        "MEANINGFUL", "PARTIAL", "THEATER", "NEGATIVE-VALUE",
    }
    assert isinstance(sc["flags"], list)
    assert len(sc["flags"]) == 5
    flag_names = {f["name"] for f in sc["flags"]}
    assert flag_names == {
        "blocks_known_risk_shapes",
        "under_friction_budget",
        "allows_too_broad",
        "schema_parses",
        "narrows_vs_admin_baseline",
    }
    for f in sc["flags"]:
        assert "pass" in f
        assert isinstance(f["pass"], bool)
        assert "rationale" in f
        assert "evidence" in f
    assert "simulation_summary" in sc
    assert "provenance" in sc
    assert sc["provenance"]["simulator_engine"] == "simulation-python"
    # Parity warning surfaced. Phase 10 lift: when
    # `CALIBRATION_CORPUS_VALIDATED` is True the warning is the
    # softened "rubric calibrated; engine parity pending" form.
    joined = " ".join(sc["provenance"]["warnings"])
    if grading.CALIBRATION_CORPUS_VALIDATED:
        assert "calibration corpus" in joined
        assert "production_parity=False" in joined
        assert sc["provenance"]["calibration_corpus_validated"] is True
        assert (
            sc["provenance"]["calibration_corpus_size"]
            == grading.CALIBRATION_CORPUS_SIZE
        )
    else:
        assert "GRADING DEPENDS ON SIMULATOR ACCURACY" in joined


def test_mcp_tool_appears_in_tools_list():
    """bounce_grade_profile_for_workflow MUST surface in tools/list."""
    from iam_jit.mcp_server import _handle_request

    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "bounce_grade_profile_for_workflow" in names, (
        f"new MCP tool missing from tools/list; got "
        f"{sorted(n for n in names if 'grade' in n.lower())}"
    )


# ---------------------------------------------------------------------------
# Tests 16-27 — #571 Finding B: per-bouncer schema validators.
# State-verification per docs/CONTRIBUTING.md asserts BOTH the pass_
# value AND the rationale / evidence so a regression that flips one
# without the other is caught loudly.
# ---------------------------------------------------------------------------


def _grade_schema_only(
    profile: dict[str, Any], bouncer_kind: str,
) -> grading.GradingFlag:
    """Invoke the full grader (which is the supported entry point —
    `_flag_schema_parses` is private) and return the schema_parses
    flag. Asserting via the public surface guards against accidental
    drift between the private helper and the public dispatch path."""
    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=[],
        bouncer_kind=bouncer_kind,
        friction_budget=None,
    )
    by_name = {f.name: f for f in report.flags}
    return by_name["schema_parses"]


def test_schema_parses_ibounce_valid():
    """ibounce profile with `actions[]` on every rule -> pass."""
    profile = {
        "bouncer": "ibounce",
        "allows": [
            {"target": "arn:aws:s3:::r/*", "actions": ["s3:GetObject"]},
        ],
        "denies": [
            {"target": "arn:aws:iam::*:*", "actions": ["iam:CreateAccessKey"]},
        ],
    }
    flag = _grade_schema_only(profile, "ibounce")
    assert flag.pass_ is True, (
        f"ibounce with actions[] must pass; rationale={flag.rationale!r}"
    )
    assert "ibounce" in flag.rationale
    # Observable rationale carries the bouncer kind so an operator
    # debugging a regression knows which validator ran.
    assert flag.evidence == []


def test_schema_parses_ibounce_missing_actions():
    """ibounce profile with deny rule missing actions -> fail with
    rationale citing the offending field."""
    profile = {
        "bouncer": "ibounce",
        "allows": [],
        "denies": [
            # Missing 'actions' — this is the historical ibounce shape
            # requirement that was hard-coded pre-#571 + that #571
            # Finding B preserves for ibounce specifically.
            {"target": "arn:aws:iam::*:*", "reason": "no actions"},
        ],
    }
    flag = _grade_schema_only(profile, "ibounce")
    assert flag.pass_ is False
    joined = " ".join(flag.evidence)
    assert "missing required 'actions' field" in joined, (
        f"rationale must cite the missing actions field; "
        f"evidence={flag.evidence!r}"
    )
    assert "ibounce" in flag.rationale


def test_schema_parses_kbounce_native_verbs_resources_shape_passes():
    """kbounce profile carrying the safety-floor shape
    `{target, verbs, resources}` (no actions[]) -> pass per #571
    Finding B."""
    profile = {
        "bouncer": "kbounce",
        "allows": [
            # Lean-permissive allow shape — uses actions[] on every
            # bouncer.
            {"target": "app-prod/pod-0", "actions": ["k8s:get"]},
        ],
        "denies": [
            # Safety floor shape per
            # _SAFETY_FLOOR_DENIES["kbounce"][0].
            {
                "target": "cluster",
                "verbs": ["delete", "deletecollection"],
                "resources": [
                    "namespaces", "nodes",
                    "clusterroles", "clusterrolebindings",
                ],
                "reason": "cluster-scoped destruction requires human approval",
            },
        ],
    }
    flag = _grade_schema_only(profile, "kbounce")
    assert flag.pass_ is True, (
        f"kbounce verbs+resources deny must pass post-#571; "
        f"rationale={flag.rationale!r} evidence={flag.evidence!r}"
    )
    assert "kbounce" in flag.rationale


def test_schema_parses_kbounce_missing_both_actions_and_verbs():
    """kbounce rule with neither actions nor verbs+resources -> fail
    with rationale that names both rejected shapes."""
    profile = {
        "bouncer": "kbounce",
        "allows": [],
        "denies": [
            # Neither actions nor verbs+resources.
            {"target": "cluster", "reason": "incomplete"},
        ],
    }
    flag = _grade_schema_only(profile, "kbounce")
    assert flag.pass_ is False
    joined = " ".join(flag.evidence)
    assert "kbounce rule" in joined
    assert "actions" in joined
    assert "verbs" in joined


def test_schema_parses_kbounce_missing_resources_only():
    """kbounce rule with verbs but missing resources -> fail with
    rationale citing the missing resources field."""
    profile = {
        "bouncer": "kbounce",
        "allows": [],
        "denies": [
            {"target": "cluster", "verbs": ["delete"], "reason": "half"},
        ],
    }
    flag = _grade_schema_only(profile, "kbounce")
    assert flag.pass_ is False
    joined = " ".join(flag.evidence)
    assert "resources" in joined


def test_schema_parses_dbounce_native_sql_patterns_shape_passes():
    """dbounce profile carrying the safety-floor shape
    `{sql_patterns: [...]}` (no actions[]) -> pass per #571 Finding B."""
    profile = {
        "bouncer": "dbounce",
        "allows": [
            {"target": "public.events", "actions": ["postgres:SELECT"]},
        ],
        "denies": [
            # Safety floor shape per
            # _SAFETY_FLOOR_DENIES["dbounce"][0].
            {
                "sql_patterns": [
                    "GRANT * TO PUBLIC",
                    "GRANT ALL PRIVILEGES TO PUBLIC",
                ],
                "reason": "GRANT TO PUBLIC is silent privilege escalation",
            },
        ],
    }
    flag = _grade_schema_only(profile, "dbounce")
    assert flag.pass_ is True, (
        f"dbounce sql_patterns deny must pass post-#571; "
        f"rationale={flag.rationale!r} evidence={flag.evidence!r}"
    )
    assert "dbounce" in flag.rationale


def test_schema_parses_dbounce_missing_sql_patterns_and_actions():
    """dbounce rule with neither actions nor sql_patterns -> fail with
    rationale citing the missing fields."""
    profile = {
        "bouncer": "dbounce",
        "allows": [],
        "denies": [
            {"reason": "no actionable field"},
        ],
    }
    flag = _grade_schema_only(profile, "dbounce")
    assert flag.pass_ is False
    joined = " ".join(flag.evidence)
    assert "dbounce rule" in joined
    assert "sql_patterns" in joined


def test_schema_parses_gbounce_host_target_passes():
    """gbounce profile carrying the safety-floor shape
    `{target: <host>}` (no actions[]) -> pass per #571 Finding B."""
    profile = {
        "bouncer": "gbounce",
        "allows": [],
        "denies": [
            # Safety floor shape per
            # _SAFETY_FLOOR_DENIES["gbounce"][0].
            {
                "target": "169.254.169.254",
                "reason": "IMDS access from agent context is credential exfiltration",
            },
        ],
    }
    flag = _grade_schema_only(profile, "gbounce")
    assert flag.pass_ is True, (
        f"gbounce host-target deny must pass post-#571; "
        f"rationale={flag.rationale!r} evidence={flag.evidence!r}"
    )
    assert "gbounce" in flag.rationale


def test_schema_parses_gbounce_host_pattern_field_passes():
    """gbounce rule using the alternative `host_pattern` field -> pass
    (host / host_pattern / target are all accepted host-shape fields
    per the gbounce validator)."""
    profile = {
        "bouncer": "gbounce",
        "allows": [],
        "denies": [
            {"host_pattern": "*.dns.google", "reason": "DoH egress"},
        ],
    }
    flag = _grade_schema_only(profile, "gbounce")
    assert flag.pass_ is True, (
        f"gbounce host_pattern deny must pass; "
        f"rationale={flag.rationale!r} evidence={flag.evidence!r}"
    )


def test_schema_parses_gbounce_missing_actions_and_host():
    """gbounce rule with neither actions nor any host field -> fail."""
    profile = {
        "bouncer": "gbounce",
        "allows": [],
        "denies": [
            {"reason": "no host or actions"},
        ],
    }
    flag = _grade_schema_only(profile, "gbounce")
    assert flag.pass_ is False
    joined = " ".join(flag.evidence)
    assert "gbounce rule" in joined
    assert "host" in joined or "target" in joined


def test_schema_parses_unknown_bouncer_kind_fails():
    """Unknown bouncer_kind -> fail with rationale listing supported
    kinds so the operator knows how to fix it."""
    profile = {
        "bouncer": "unknown-product",
        "allows": [
            {"target": "*", "actions": ["whatever:Op"]},
        ],
        "denies": [],
    }
    flag = _grade_schema_only(profile, "unknown-product")
    assert flag.pass_ is False
    assert "no schema validator registered" in flag.rationale
    # Surfaces the supported kinds so an operator can map their
    # typo to a real bouncer name.
    for k in ("ibounce", "kbounce", "dbounce", "gbounce"):
        assert k in flag.rationale, (
            f"rationale must list supported bouncer kinds; "
            f"missing {k!r} in {flag.rationale!r}"
        )


def test_schema_parses_regression_scenario_01_corpus_profile_still_passes():
    """Regression: an ibounce profile generated from the scenario-01
    corpus shape (broad target, actions[] on every rule) still passes
    schema_parses. Guards against #571 Finding B accidentally
    loosening ibounce's strict actions[] requirement."""
    profile = {
        "bouncer": "ibounce",
        "profile_name": "narrow-readonly",
        "allows": [
            {
                "target": "arn:aws:s3:::reports/*",
                "actions": ["s3:GetObject"],
                "reason": "narrow read",
            }
        ],
        # Include the ibounce safety-floor shape that exists in
        # production. Pre-#571 this already passed; #571 must not
        # regress it.
        "denies": [
            {
                "target": "arn:aws:iam::*:*",
                "actions": [
                    "iam:CreateAccessKey", "iam:CreateUser",
                ],
                "reason": "agents must not create credentials",
            },
        ],
    }
    flag = _grade_schema_only(profile, "ibounce")
    assert flag.pass_ is True, (
        f"regression: ibounce corpus-shape profile must pass; "
        f"rationale={flag.rationale!r} evidence={flag.evidence!r}"
    )


def test_schema_parses_kbounce_rejects_verbs_resources_under_ibounce_dispatch():
    """Bouncer dispatch is load-bearing — the same `{verbs, resources}`
    rule that passes under kbounce dispatch MUST fail under ibounce
    dispatch (which doesn't accept that shape). Proves the dispatch
    distinguishes per-bouncer rather than silently accepting any
    known shape on every bouncer."""
    profile = {
        "bouncer": "kbounce",
        "allows": [],
        "denies": [
            {
                "target": "cluster",
                "verbs": ["delete"],
                "resources": ["namespaces"],
            },
        ],
    }
    # Same profile, opposite bouncer_kind -> must fail because ibounce
    # validator only accepts actions[].
    flag_under_ibounce = _grade_schema_only(profile, "ibounce")
    assert flag_under_ibounce.pass_ is False, (
        f"ibounce dispatch must reject verbs+resources shape; "
        f"rationale={flag_under_ibounce.rationale!r}"
    )
    # And the same profile under correct kbounce dispatch passes —
    # asserts the dispatch is the discriminator, not the rule shape.
    flag_under_kbounce = _grade_schema_only(profile, "kbounce")
    assert flag_under_kbounce.pass_ is True, (
        f"kbounce dispatch must accept verbs+resources shape; "
        f"rationale={flag_under_kbounce.rationale!r}"
    )
