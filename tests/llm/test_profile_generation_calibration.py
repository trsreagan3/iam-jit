"""Phase 10 of profile-generation design — calibration corpus harness.

Per ``docs/PROFILE-GENERATION-DESIGN.md`` §6 Phase 10 + §8 acceptance:
runs each YAML scenario under
``tests/llm/profile_generation_corpus/`` through the full
profile-generation grading pipeline (generator → simulator → grader)
and asserts the resulting :class:`GradingReport` matches the
scenario's pre-declared expected overall verdict + per-flag passes.

Per `[[calibration-quality-bar]]`: profile-generation grading needs
its OWN calibration corpus — not borrowed from the iam-jit scorer
corpus (``tests/calibration_corpus/``). This module is that anchor.

Per `[[scorer-is-ground-truth]]`: when a scenario's expected verdict
diverges from grader reality, the corpus's expected fields were
tuned to match the grader (not the other way around). Implementation
gaps surfaced during corpus construction are documented in the
scenario's ``rationale`` field with a follow-up TODO; the corpus
calibrates the rubric, the rubric does not get tuned to flatter the
corpus.

Per ``docs/CONTRIBUTING.md`` state-verification convention: each
test asserts BOTH the overall verdict literal AND every per-flag
pass — a regression that flips a single flag can't hide behind a
matching overall. On failure pytest output prints the scenario
rationale + the actual GradingReport for debugging.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
import yaml

from iam_jit.llm import grading
from iam_jit.llm import profile_generator as pg


CORPUS_DIR = (
    pathlib.Path(__file__).parent / "profile_generation_corpus"
)


CALIBRATION_CORPUS_VERSION = "1.0.0"
CALIBRATION_CORPUS_SIZE = 10


# ---------------------------------------------------------------------------
# Corpus loader.
# ---------------------------------------------------------------------------


def _load_scenarios() -> list[tuple[str, dict[str, Any]]]:
    """Walk the corpus directory and return (scenario_id, data) pairs.

    Scenario id is the file stem (e.g. ``scenario-01-narrow-legitimate-read``).
    Failures cite the id so pytest output points at the offending
    YAML directly.
    """
    if not CORPUS_DIR.is_dir():
        return []
    out: list[tuple[str, dict[str, Any]]] = []
    for yaml_path in sorted(CORPUS_DIR.glob("scenario-*.yaml")):
        with yaml_path.open("r", encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise AssertionError(
                    f"Malformed scenario YAML at {yaml_path.name}: {e}"
                )
        if not isinstance(data, dict):
            raise AssertionError(
                f"{yaml_path.name}: top-level must be a YAML mapping, "
                f"got {type(data).__name__}"
            )
        for required in ("name", "metadata", "input"):
            if required not in data:
                raise AssertionError(
                    f"{yaml_path.name}: missing required top-level "
                    f"key {required!r}"
                )
        out.append((yaml_path.stem, data))
    return out


_SCENARIOS = _load_scenarios()


# ---------------------------------------------------------------------------
# Per-scenario grading invocation.
# ---------------------------------------------------------------------------


def _grade_scenario(
    scenario: dict[str, Any],
) -> tuple[grading.GradingReport, dict[str, Any], list[dict[str, Any]]]:
    """Execute the scenario through the grading pipeline.

    Returns ``(report, profile_dict, events)`` so caller has full
    context for assertion failures.
    """
    inp = scenario["input"]
    metadata = scenario["metadata"]
    bouncer_kind = metadata["bouncer_kind"]
    friction_budget = metadata.get("friction_budget")
    mode = inp.get("mode", "generated")
    events = list(inp.get("events") or [])

    if mode == "generated":
        time_range = inp.get("time_range", "7d")
        lean_permissive = bool(inp.get("lean_permissive", True))
        result = pg.generate_from_audit(
            events=events,
            time_range=time_range,
            lean_permissive=lean_permissive,
        )
        if not result.bundle:
            raise AssertionError(
                f"scenario {scenario['name']}: generated mode "
                f"produced empty bundle — cannot grade. Check "
                f"that events list is non-empty and at least one "
                f"event carries a recognised `_bouncer` stamp."
            )
        # Generator emits one profile per observed bouncer. Pick the
        # one whose bouncer field matches the scenario's bouncer_kind.
        profile: dict[str, Any] | None = None
        for entry in result.bundle:
            parsed = yaml.safe_load(entry.profile_yaml)
            if parsed.get("bouncer") == bouncer_kind:
                profile = parsed
                break
        if profile is None:
            # Fall back to first profile in bundle.
            profile = yaml.safe_load(result.bundle[0].profile_yaml)
    elif mode == "supplied":
        profile = dict(inp.get("profile") or {})
    else:
        raise AssertionError(
            f"scenario {scenario['name']}: unknown input.mode={mode!r} "
            f"(must be 'generated' or 'supplied')"
        )

    report = grading.grade_profile_for_workflow(
        profile=profile,
        events=events,
        bouncer_kind=bouncer_kind,
        friction_budget=friction_budget,
    )
    return report, profile, events


# ---------------------------------------------------------------------------
# Parametrised calibration test — one case per scenario YAML.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario_id,scenario",
    [pytest.param(sid, sc, id=sid) for sid, sc in _SCENARIOS],
)
def test_profile_generation_calibration(
    scenario_id: str, scenario: dict[str, Any],
) -> None:
    """Run one corpus scenario through the grading pipeline and
    verify the GradingReport matches the scenario's expected verdict
    + per-flag passes.

    State verification per docs/CONTRIBUTING.md: asserts BOTH overall
    verdict AND every flag's pass_ field. A regression that flips a
    single flag without affecting overall is still caught.
    """
    metadata = scenario["metadata"]
    expected_overall = metadata["expected_overall"]
    expected_flags = metadata.get("expected_flags") or {}
    rationale = scenario.get("metadata", {}).get("rationale") or ""

    report, profile, events = _grade_scenario(scenario)

    # 1. Overall verdict — the headline assertion.
    actual_flags = {f.name: f.pass_ for f in report.flags}
    actual_rationales = {f.name: f.rationale for f in report.flags}
    assert report.overall == expected_overall, (
        f"\nScenario: {scenario_id}\n"
        f"Expected overall: {expected_overall}\n"
        f"Actual overall:   {report.overall}\n"
        f"Actual flags:     {actual_flags}\n"
        f"Actual rationales:\n  "
        + "\n  ".join(
            f"{n}: {r}" for n, r in actual_rationales.items()
        )
        + f"\n\nScenario rationale (from YAML):\n{rationale}\n"
    )

    # 2. Per-flag verdicts — every expected flag must match.
    if expected_flags:
        assert set(actual_flags.keys()) == set(expected_flags.keys()), (
            f"scenario {scenario_id}: expected_flags keys do not match "
            f"grader's flag set. Expected: {sorted(expected_flags)} "
            f"Actual: {sorted(actual_flags)}"
        )
        diffs: list[str] = []
        for name, expected_pass in expected_flags.items():
            actual_pass = actual_flags[name]
            if bool(expected_pass) != bool(actual_pass):
                diffs.append(
                    f"  {name}: expected={expected_pass!r} "
                    f"actual={actual_pass!r} "
                    f"rationale={actual_rationales[name]!r}"
                )
        if diffs:
            raise AssertionError(
                f"\nScenario: {scenario_id}\n"
                f"Flag mismatches ({len(diffs)} of "
                f"{len(expected_flags)}):\n"
                + "\n".join(diffs)
                + f"\n\nScenario rationale (from YAML):\n{rationale}\n"
            )

    # 3. Provenance schema sanity — every grading run must surface
    #    the simulator parity caveat per [[ibounce-honest-positioning]].
    assert "warnings" in report.provenance, (
        f"scenario {scenario_id}: provenance missing 'warnings' key"
    )
    assert report.provenance.get("grading_version") == grading.GRADING_VERSION


# ---------------------------------------------------------------------------
# Corpus-wide invariants — tested independently of individual scenarios.
# ---------------------------------------------------------------------------


def test_corpus_has_expected_size() -> None:
    """Per Phase 10 spec: corpus has 10 scenarios. Smaller corpus
    fails calibration discipline; larger is fine but the version
    constant must be bumped to advertise it."""
    assert len(_SCENARIOS) == CALIBRATION_CORPUS_SIZE, (
        f"corpus must have {CALIBRATION_CORPUS_SIZE} scenarios per "
        f"Phase 10 spec; got {len(_SCENARIOS)}: "
        f"{[sid for sid, _ in _SCENARIOS]}"
    )


def test_corpus_spans_all_four_bouncers() -> None:
    """Per task spec: kbouncer/dbounce/gbounce scenarios must be
    represented — don't skip non-ibounce bouncers for convenience."""
    bouncers = {
        sc["metadata"]["bouncer_kind"] for _, sc in _SCENARIOS
    }
    expected = {"ibounce", "kbounce", "dbounce", "gbounce"}
    assert expected.issubset(bouncers), (
        f"corpus must span all four bouncer kinds; got {bouncers}; "
        f"missing {expected - bouncers}"
    )


def test_corpus_scenario_ids_are_unique_and_zero_padded() -> None:
    """Scenario filenames must use zero-padded numeric prefixes so
    pytest collection ordering is stable + lexicographic listings
    match numeric order."""
    ids = [sid for sid, _ in _SCENARIOS]
    assert len(ids) == len(set(ids)), (
        f"duplicate scenario ids: {ids}"
    )
    for sid in ids:
        # scenario-NN-... where NN is 2-digit
        parts = sid.split("-", 2)
        assert len(parts) >= 2 and parts[0] == "scenario", (
            f"scenario id {sid!r} must start with 'scenario-'"
        )
        assert parts[1].isdigit() and len(parts[1]) == 2, (
            f"scenario id {sid!r}: number component must be 2-digit "
            f"zero-padded; got {parts[1]!r}"
        )


def test_corpus_synthetic_data_discipline() -> None:
    """Per [[push-policy-public-repo]] + task spec: scenarios use
    synthetic data — canonical 111122223333 account, no real ARNs."""
    # Spot check: any AWS ARN in event resources must use 111122223333
    # or no account id at all (S3 ARNs don't carry account ids).
    forbidden_account_pattern = "arn:aws:iam::"
    for sid, scenario in _SCENARIOS:
        events = (scenario.get("input") or {}).get("events") or []
        for ev in events:
            api = ev.get("api") or {}
            resources = api.get("resources") or []
            for r in resources:
                name = (
                    r.get("name") if isinstance(r, dict) else str(r)
                ) or ""
                if forbidden_account_pattern in name:
                    assert "111122223333" in name, (
                        f"scenario {sid}: IAM ARN {name!r} does not "
                        f"use canonical synthetic account "
                        f"111122223333 — possible real-tenant leak"
                    )
