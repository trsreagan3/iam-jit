"""Phase 4 production-parity harness tests (#562).

Per :mod:`iam_jit.llm.simulator_parity` module docstring +
[[ibounce-honest-positioning]] + [[scorer-is-ground-truth]] +
[[calibration-quality-bar]]:

* ibounce parity is exercised against the Python production engine
  (``iam_jit.bouncer.profiles.evaluate_profile``) directly. Lifted to
  True per #562 when 100% of canonical fixtures pass.
* kbounce / dbounce / gbounce parity is exercised against the Go
  binaries' CLI ``decide --json`` path. As of cfdd110 NONE of the Go
  bouncers expose that subcommand in the (profile, event)-tuple shape
  the harness expects — the harness SKIPs them with a structured
  ``skipped_reason``. Tests assert that gradient honestly.

State-verification per ``docs/CONTRIBUTING.md``: every test below
asserts the observable ``ParityResult`` fields (not just a pass/fail
boolean) so a regression where the harness silently misses a
divergence can't sneak through.
"""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit.llm import simulator as sim
from iam_jit.llm import simulator_parity as sp


# ---------------------------------------------------------------------------
# Test 1 — ibounce: all canonical fixtures pass.
# ---------------------------------------------------------------------------


def test_parity_ibounce_all_fixtures_pass():
    """The ibounce canonical corpus MUST pass 100%. Per
    [[calibration-quality-bar]]: lifting production_parity to True for
    a bouncer requires its harness to pass on the same calibration
    discipline used for the scorer itself."""
    result = sp.validate_parity("ibounce")

    # State verification: every observable counter agrees.
    assert result.bouncer_kind == "ibounce"
    assert result.scenarios_run > 0, (
        "ibounce corpus is empty — no parity validation actually ran"
    )
    assert result.scenarios_run == result.scenarios_passed, (
        f"ibounce parity FAILED: passed={result.scenarios_passed} "
        f"of run={result.scenarios_run}; "
        f"failures={result.failure_details!r}"
    )
    assert result.scenarios_failed == 0
    assert result.failure_details == []
    assert result.skipped_reason == ""


# ---------------------------------------------------------------------------
# Test 2-4 — Go bouncer subprocess invocation surface.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["kbounce", "dbounce", "gbounce"])
def test_parity_go_bouncer_subprocess_handling(kind: str):
    """For each Go bouncer the harness must:

    * SKIP cleanly with a structured ``skipped_reason`` when the
      binary is absent or the CLI doesn't expose a (profile, event)-
      shaped decide subcommand
    * record the probe details in ``failure_details`` with a
      ``divergence_shape`` of cli-decide-missing / no-event-adapter

    As of cfdd110 this means scenarios_run == 0 + skipped_reason
    populated for every Go bouncer. When a Go bouncer's CLI gains the
    decide path the assertion shape inverts naturally."""
    result = sp.validate_parity(kind)
    assert result.bouncer_kind == kind

    # If the binary isn't installed at all, skipped_reason names that
    # AND scenarios_run is zero.
    if "not found" in result.skipped_reason:
        assert result.scenarios_run == 0
        assert result.scenarios_passed == 0
        assert result.scenarios_failed == 0
        return

    # The binary IS callable. The harness probed decide; record what
    # it found.
    assert result.scenarios_run == 0, (
        f"{kind} CLI suddenly exposes a (profile, event)-shape decide "
        f"path; this test must be inverted to assert all fixtures pass "
        f"+ lift production_parity[{kind}] to True. "
        f"result={result!r}"
    )
    # skipped_reason names WHY the harness can't validate parity.
    assert result.skipped_reason, (
        f"{kind} harness skipped silently; skipped_reason must name "
        f"the gap (e.g. cli-decide-missing / no-event-adapter)"
    )
    # failure_details carries the probe row.
    assert result.failure_details, (
        f"{kind} probe must record a structured row in failure_details"
    )
    probe = result.failure_details[0]
    assert probe.get("divergence_shape") in (
        "cli-decide-missing", "no-event-adapter",
    ), f"unexpected probe shape: {probe!r}"


# ---------------------------------------------------------------------------
# Test 5 — simulator provenance reflects per-bouncer parity.
# ---------------------------------------------------------------------------


def test_simulator_provenance_reflects_per_bouncer_parity():
    """After Phase 4 parity validation, simulator.provenance.
    production_parity must be a per-bouncer DICT (not a single bool).
    ibounce is True; Go bouncers are False until their harness lifts."""
    sim._reset_parity_map_cache_for_tests()
    result = sim.evaluate_profile_against_events(
        profile={"bouncer": "ibounce", "allows": [], "denies": []},
        events=[],
        bouncer_kind="ibounce",
    )

    parity = result.provenance["production_parity"]
    assert isinstance(parity, dict), (
        f"production_parity must be per-bouncer dict; got "
        f"{type(parity).__name__}: {parity!r}"
    )
    assert parity["ibounce"] is True, (
        f"ibounce parity lifted by #562 — must be True; got {parity!r}"
    )
    # Honest gradient — Go bouncers stay False until their CLI lifts.
    assert parity["kbounce"] is False
    assert parity["gbounce"] is False


# ---------------------------------------------------------------------------
# Test 6 — provenance remains False for an unvalidated (hypothetical)
# bouncer kind.
# ---------------------------------------------------------------------------


def test_simulator_provenance_remains_false_when_parity_unvalidated(
    monkeypatch: pytest.MonkeyPatch,
):
    """When the parity harness has not validated a bouncer (e.g. a
    hypothetical future ``rbounce``), production_parity for it stays
    False. Locks in the [[calibration-quality-bar]] discipline: no
    silent True without a passing harness."""
    sim._reset_parity_map_cache_for_tests()
    # Monkey-patch the per-bouncer parity map to inject a synthetic
    # rbounce entry, exercising the "unvalidated bouncer" path.
    original = sp.compute_per_bouncer_parity_map

    def _faked_map() -> dict[str, bool]:
        out = original()
        out["rbounce"] = False
        return out

    monkeypatch.setattr(sp, "compute_per_bouncer_parity_map", _faked_map)
    sim._reset_parity_map_cache_for_tests()

    result = sim.evaluate_profile_against_events(
        profile={"bouncer": "rbounce", "allows": [], "denies": []},
        events=[],
        bouncer_kind="rbounce",
    )
    parity = result.provenance["production_parity"]
    assert parity.get("rbounce") is False, (
        f"unvalidated bouncer must stay False; got {parity!r}"
    )


# ---------------------------------------------------------------------------
# Test 7 — failure records divergence shape.
# ---------------------------------------------------------------------------


def test_parity_failure_records_divergence_shape():
    """Inject a fixture whose expected verdict diverges from what the
    simulator + production engine actually emit. ParityResult.
    failure_details MUST record the divergence with simulator_verdict
    + production_verdict + divergence_shape so an operator can
    debug."""
    # This fixture's expected verdict is "deny" but simulator +
    # production both emit "allow" (allow rule matches s3:GetObject;
    # no deny rule + no safety-floor hit). The fixture is INTENTIONALLY
    # wrong to exercise the fixture-expectation-mismatch divergence
    # shape — protects [[calibration-quality-bar]].
    bad_fixture = {
        "name": "deliberately-wrong-expectation",
        "profile": {
            "bouncer": "ibounce",
            "allows": [{
                "target": "*",
                "actions": ["s3:GetObject"],
                "reason": "allows the read",
            }],
            "denies": [],
        },
        "events": [{
            "_bouncer": "ibounce",
            "time": 1716412800000,
            "activity_name": "allow",
            "unmapped": {"iam_jit": {"verdict": "allow"}},
            "api": {
                "service": {"name": "s3"},
                "operation": "GetObject",
                "resources": [{"name": "arn:aws:s3:::ok/k"}],
            },
        }],
        "expected_verdicts": ["deny"],  # intentionally wrong
    }
    result = sp.validate_parity("ibounce", fixtures=[bad_fixture])
    assert result.scenarios_run == 1
    assert result.scenarios_failed == 1
    assert result.scenarios_passed == 0
    assert len(result.failure_details) == 1
    failure = result.failure_details[0]
    assert failure["divergence_shape"] == "fixture-expectation-mismatch"
    assert failure["simulator_verdict"] == "allow"
    assert failure["production_verdict"] == "allow"
    assert failure["scenario_name"] == "deliberately-wrong-expectation"
    # The reason field should NOT be empty — operators need it to
    # debug.
    assert failure["simulator_reason"], (
        "simulator_reason must be populated on a divergence row"
    )


# ---------------------------------------------------------------------------
# Test 8 — parity corpus version surfaced in provenance.
# ---------------------------------------------------------------------------


def test_parity_corpus_versioned():
    """provenance.parity_corpus_version MUST be present + match the
    module constant so consumers can pin against it."""
    sim._reset_parity_map_cache_for_tests()
    result = sim.evaluate_profile_against_events(
        profile={"bouncer": "ibounce", "allows": [], "denies": []},
        events=[],
        bouncer_kind="ibounce",
    )
    assert (
        result.provenance.get("parity_corpus_version")
        == sp.PARITY_CORPUS_VERSION
    )


# ---------------------------------------------------------------------------
# Test 9 — sabotage-check: monkeypatch production to mirror simulator
# output; verify divergence detection still works.
# ---------------------------------------------------------------------------


def test_parity_sabotage_check_simulator_not_self_compared(
    monkeypatch: pytest.MonkeyPatch,
):
    """Sabotage-check per the #562 spec: monkeypatch the ibounce
    production engine call so it returns whatever the simulator
    returns. The "all fixtures pass" assertion would still pass under
    this sabotage if the harness were secretly checking sim==sim.

    The test injects a deliberately divergent fixture AND a sabotaged
    production engine that returns "allow" for every event; the
    simulator returns "deny" because of an explicit deny rule. A
    properly-implemented parity harness MUST surface this divergence.
    """
    bad_fixture = {
        "name": "sabotage-check",
        "profile": {
            "bouncer": "ibounce",
            "allows": [],
            "denies": [{
                "target": "*",
                "actions": ["s3:DeleteObject"],
                "reason": "no deletes",
            }],
        },
        "events": [{
            "_bouncer": "ibounce",
            "time": 1716412800000,
            "activity_name": "deny",
            "unmapped": {"iam_jit": {"verdict": "deny"}},
            "api": {
                "service": {"name": "s3"},
                "operation": "DeleteObject",
                "resources": [{"name": "arn:aws:s3:::ok/k"}],
            },
        }],
    }

    # Sabotage: production verdict is hard-coded to "allow" regardless
    # of input. Simulator's deny rule will fire + produce "deny", so
    # parity MUST surface verdict-mismatch.
    def _fake_production(profile, event):
        return "allow", "sabotaged production engine"

    monkeypatch.setattr(
        sp, "_ibounce_production_verdict", _fake_production,
    )
    result = sp.validate_parity("ibounce", fixtures=[bad_fixture])

    assert result.scenarios_run == 1
    assert result.scenarios_failed == 1, (
        f"sabotage-check FAILED — harness silently passed sim-vs-sim. "
        f"result={result!r}"
    )
    assert len(result.failure_details) == 1
    f = result.failure_details[0]
    assert f["divergence_shape"] == "verdict-mismatch"
    assert f["simulator_verdict"] == "deny"
    assert f["production_verdict"] == "allow"


# ---------------------------------------------------------------------------
# Test 10 — load_corpus + structure.
# ---------------------------------------------------------------------------


def test_parity_corpus_structure_per_bouncer():
    """Per-bouncer corpus directory must exist with at least one
    fixture for each bouncer kind (locks in [[calibration-quality-bar]]
    — every bouncer has a non-empty corpus, even if Go-bouncer parity
    is still gated)."""
    for kind in ("ibounce", "kbounce", "dbounce", "gbounce"):
        fixtures = sp.load_corpus(kind)
        assert fixtures, (
            f"parity corpus for {kind} is empty — at minimum one "
            f"fixture per bouncer per [[calibration-quality-bar]]"
        )
        for fx in fixtures:
            assert "profile" in fx, f"{kind} fixture missing profile"
            assert "events" in fx, f"{kind} fixture missing events"


# ---------------------------------------------------------------------------
# Test 11 — _passes_all helper enforces lift discipline.
# ---------------------------------------------------------------------------


def test_passes_all_rejects_empty_corpus():
    """A bouncer whose corpus runs zero scenarios MUST NOT count as
    "passing" — locks in [[calibration-quality-bar]]: lifting requires
    real evidence, not absence of failures."""
    empty = sp.ParityResult(
        bouncer_kind="rbounce", scenarios_run=0,
        scenarios_passed=0, scenarios_failed=0,
        failure_details=[],
    )
    assert sp._passes_all(empty) is False
