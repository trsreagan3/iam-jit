"""Phase 3 prerequisite — state-verification tests for
``profile_heuristic.confidence``.

Per CONTRIBUTING.md state-verification convention: the band IS the
observable state. Tests assert (a) the band value, (b) the rationale
mentions the specific count + resource counts (so operators can see WHY
they got the band — the "diagnostic explainer" requirement of
``[[ibounce-honest-positioning]]``), and (c) the threshold constants
themselves are stable so downstream callers can rely on them.

The thresholds are guesses per design §9 / ``[[calibration-quality-bar]]``;
the tests pin the CURRENT behavior so any tuning to the thresholds in a
later phase is visible in the diff.
"""

from __future__ import annotations

import pytest

from iam_jit.audit_extract.extractor import PermissionAggregate
from iam_jit.profile_heuristic import (
    Confidence,
    ConfidenceResult,
    confidence_band,
)
from iam_jit.profile_heuristic.confidence import (
    MEDIUM_MAX_COUNT,
    MEDIUM_MIN_COUNT,
    STRONG_MIN_COUNT,
    STRONG_MIN_DISTINCT_RESOURCES,
)


def _agg(count: int, distinct_resources: int) -> PermissionAggregate:
    """Build a PermissionAggregate with the requested shape.

    Resource ARNs are synthetic — the band classifier only cares about
    len(resources) and count, not the specific resource strings.
    """
    resources = tuple(f"arn:aws:s3:::bucket-{i}" for i in range(distinct_resources))
    return PermissionAggregate(
        action="s3:GetObject",
        resources=resources,
        count=count,
    )


# ---------------------------------------------------------------------------
# STRONG band — count >= 5 AND distinct_resources >= 2
# ---------------------------------------------------------------------------


def test_strong_band_minimum_threshold() -> None:
    """count == 5 AND distinct_resources == 2 is the boundary case;
    must classify STRONG per design §2.2."""
    result = confidence_band(_agg(count=5, distinct_resources=2))
    assert isinstance(result, ConfidenceResult)
    assert result.band is Confidence.STRONG
    # State-verification: rationale must cite both gates so the operator
    # can see WHY they got STRONG (not just "STRONG because the code
    # said so").
    assert "5 observations" in result.rationale
    assert "2 distinct resources" in result.rationale


def test_strong_band_well_above_threshold() -> None:
    """Larger observation count + more distinct resources stays STRONG.

    Verifies the band classifier doesn't accidentally downgrade at some
    arbitrary high count."""
    result = confidence_band(_agg(count=100, distinct_resources=10))
    assert result.band is Confidence.STRONG
    assert "100 observations" in result.rationale
    assert "10 distinct resources" in result.rationale


def test_strong_band_count_10_resources_5() -> None:
    """A typical "lots of observations" case — count=10, resources=5."""
    result = confidence_band(_agg(count=10, distinct_resources=5))
    assert result.band is Confidence.STRONG


# ---------------------------------------------------------------------------
# MEDIUM band — count in [2, 4] OR (count >= 5 but distinct_resources < 2)
# ---------------------------------------------------------------------------


def test_medium_band_count_5_single_resource_failed_distinct_gate() -> None:
    """The "5+ observations on one resource" edge case the design calls
    out: STRONG threshold passes on count but FAILS on distinct
    resources. Must downgrade to MEDIUM and the rationale must say so
    (per state-verification + diagnostic-explainer discipline)."""
    result = confidence_band(_agg(count=5, distinct_resources=1))
    assert result.band is Confidence.MEDIUM
    # Rationale must mention the failed distinct-resources gate
    # specifically — the operator needs to know WHY they didn't get
    # STRONG so they can decide whether to broaden traffic generation
    # for that resource or accept the MEDIUM disposition.
    assert "distinct-resources gate" in result.rationale
    assert "5 observations" in result.rationale


def test_medium_band_count_3_two_resources() -> None:
    """Typical MEDIUM case: a few observations across a handful of
    resources. count=3, distinct=2."""
    result = confidence_band(_agg(count=3, distinct_resources=2))
    assert result.band is Confidence.MEDIUM
    assert "3 observations" in result.rationale


def test_medium_band_count_at_max_boundary() -> None:
    """count == MEDIUM_MAX_COUNT (4) is MEDIUM; count == 5 with 2+
    resources flips to STRONG. Pin the boundary."""
    assert confidence_band(_agg(count=4, distinct_resources=2)).band is Confidence.MEDIUM
    assert confidence_band(_agg(count=4, distinct_resources=10)).band is Confidence.MEDIUM


def test_medium_band_count_at_min_boundary() -> None:
    """count == MEDIUM_MIN_COUNT (2) is MEDIUM; count == 1 is WEAK."""
    assert confidence_band(_agg(count=2, distinct_resources=1)).band is Confidence.MEDIUM
    assert confidence_band(_agg(count=2, distinct_resources=2)).band is Confidence.MEDIUM


def test_medium_band_count_high_zero_distinct_after_filter() -> None:
    """count == 7, distinct_resources == 1 — high count, single resource
    — must classify MEDIUM via the failed-distinct-gate branch."""
    result = confidence_band(_agg(count=7, distinct_resources=1))
    assert result.band is Confidence.MEDIUM
    assert "distinct-resources gate" in result.rationale


# ---------------------------------------------------------------------------
# WEAK band — count == 1
# ---------------------------------------------------------------------------


def test_weak_band_single_observation() -> None:
    """Single observation is WEAK per design §2.2."""
    result = confidence_band(_agg(count=1, distinct_resources=1))
    assert result.band is Confidence.WEAK
    assert "1 observation" in result.rationale
    # State-verification: rationale should explain this is the
    # single-observation case so operators see why the
    # write/admin/destructive skip disposition will apply.
    assert "single-observation pattern" in result.rationale


# ---------------------------------------------------------------------------
# Edge — count == 0 is INVALID
# ---------------------------------------------------------------------------


def test_count_zero_raises_value_error() -> None:
    """An aggregate with count==0 should never reach the band classifier
    — the extractor only emits aggregates for actions observed >= 1
    time. Raise ValueError to surface the upstream bug."""
    with pytest.raises(ValueError) as exc:
        confidence_band(_agg(count=0, distinct_resources=0))
    # State-verification: error message must mention the invalid count
    # so callers can debug the upstream extractor.
    assert "count > 0" in str(exc.value)


def test_count_negative_raises_value_error() -> None:
    """Negative counts are also invalid input."""
    with pytest.raises(ValueError):
        confidence_band(_agg(count=-1, distinct_resources=1))


# ---------------------------------------------------------------------------
# Threshold constants — pinned for downstream consumers
# ---------------------------------------------------------------------------


def test_threshold_constants_match_design() -> None:
    """Per design §2.2 + §7 safeguard #1 the thresholds are
    inspectable constants. Pin them so any future tuning to the
    Phase 10 calibration corpus shows up in the diff."""
    assert STRONG_MIN_COUNT == 5
    assert STRONG_MIN_DISTINCT_RESOURCES == 2
    assert MEDIUM_MIN_COUNT == 2
    assert MEDIUM_MAX_COUNT == 4


# ---------------------------------------------------------------------------
# Pure-function discipline — same inputs always produce same output
# ---------------------------------------------------------------------------


def test_pure_function_stable_across_repeats() -> None:
    """Per the classifier discipline in CONTRIBUTING.md — pure
    function. State-verification: identity-stable result across many
    calls catches accidental caches keying on the wrong dimension."""
    agg = _agg(count=5, distinct_resources=2)
    results = [confidence_band(agg) for _ in range(50)]
    assert all(r.band is Confidence.STRONG for r in results)
    assert all(r.rationale == results[0].rationale for r in results)


# ---------------------------------------------------------------------------
# Type errors — defensive against non-aggregate inputs
# ---------------------------------------------------------------------------


def test_non_aggregate_input_raises_type_error() -> None:
    """An object without .count / .resources is invalid input. Raise
    TypeError with an actionable message."""
    with pytest.raises(TypeError) as exc:
        confidence_band(object())
    assert ".count" in str(exc.value) and ".resources" in str(exc.value)


def test_as_dict_round_trips_band_value() -> None:
    """The as_dict serialiser is used by downstream tools to surface
    confidence in MCP responses. Pin the keys + value shape."""
    result = confidence_band(_agg(count=5, distinct_resources=3))
    d = result.as_dict()
    assert d == {"band": "strong", "rationale": result.rationale}
