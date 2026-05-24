# Phase 3 prerequisite — confidence-band classifier per design §2.2.
"""Confidence-band classifier for ``PermissionAggregate`` observations.

Per ``docs/PROFILE-GENERATION-DESIGN.md`` §2.2 the lean-permissive
heuristic uses a three-band confidence signal to decide auto-include vs
review-flag vs skip:

* ``STRONG``  — count >= 5 AND across >= 2 distinct resources
* ``MEDIUM``  — count between 2 and 4 (inclusive)
* ``WEAK``    — count == 1

The thresholds (``5``, ``2``) are guesses pending calibration per
``[[calibration-quality-bar]]`` — the design's §9 calls them out
explicitly. This module is the single source of truth for the bands so
the Phase 3 generator, the Phase 5 simulator, and the Phase 7 grader
all read from the same place.

Pure data + a pure function. No LLM, no I/O.

See ``docs/PROFILE-GENERATION-DESIGN.md`` §2.2 for the disposition each
band drives downstream (broad allow vs flagged-for-review vs skipped).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


# Threshold constants are module-level so they're inspectable per design
# §7 safeguard #1 ("heuristic thresholds are inspectable; not hardcoded
# inside an LLM prompt") and so downstream tests + docs can cite the
# same source.
STRONG_MIN_COUNT: int = 5
STRONG_MIN_DISTINCT_RESOURCES: int = 2
MEDIUM_MIN_COUNT: int = 2
MEDIUM_MAX_COUNT: int = 4


class Confidence(Enum):
    """Confidence band for a ``PermissionAggregate`` observation.

    Per ``docs/PROFILE-GENERATION-DESIGN.md`` §2.2:

    * ``STRONG`` — auto-include per class disposition.
    * ``MEDIUM`` — include with ``flagged_for_review`` note.
    * ``WEAK``   — Read: include + flag. Write/admin/destructive: SKIP.
    """

    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"


@dataclass(frozen=True)
class ConfidenceResult:
    """Banded confidence result with an operator-readable rationale.

    The rationale is plain text the Phase 3 generator emits into
    ``flagged_for_review`` / ``skipped`` notes so the operator can see
    WHY a pattern was bucketed where it was — no opaque magic numbers.
    Per ``[[ibounce-honest-positioning]]`` every confidence call is
    inspectable + auditable, not just the band.
    """

    band: Confidence
    rationale: str

    def as_dict(self) -> dict[str, Any]:
        return {"band": self.band.value, "rationale": self.rationale}


def confidence_band(aggregate: Any) -> ConfidenceResult:
    """Classify a ``PermissionAggregate``'s confidence per design §2.2.

    Pure function — same inputs always produce the same output. No I/O.

    Args:
        aggregate: any object exposing ``count`` (int) and ``resources``
            (sized iterable). Typed as ``Any`` rather than the concrete
            ``PermissionAggregate`` to avoid a hard cycle with
            :mod:`iam_jit.audit_extract.extractor` — the confidence
            module is consumed by the extractor in some flows, so
            structural typing keeps the import graph one-way.

    Returns:
        :class:`ConfidenceResult` with the band + an operator-readable
        rationale citing the observed count + distinct resources.

    Raises:
        ValueError: if ``aggregate.count`` is zero (invalid input — an
            aggregate without any observations should never reach this
            classifier; producing one means the upstream extractor has
            a bug and silent classification would mask it).
        TypeError: if ``aggregate`` lacks ``count`` / ``resources``.
    """
    try:
        count = int(aggregate.count)
        resources = aggregate.resources
    except AttributeError as e:
        raise TypeError(
            f"confidence_band requires an object with .count and "
            f".resources (got {type(aggregate).__name__})"
        ) from e

    distinct_resources = len(resources)

    if count <= 0:
        # Per the §2.2 acceptance: a count==0 aggregate is invalid. The
        # extractor only emits aggregates for actions that were
        # observed at least once; a zero would indicate a bug upstream.
        raise ValueError(
            f"confidence_band requires count > 0 (got {count}); "
            "an aggregate with no observations is invalid input"
        )

    if (
        count >= STRONG_MIN_COUNT
        and distinct_resources >= STRONG_MIN_DISTINCT_RESOURCES
    ):
        rationale = (
            f"{count} observations across {distinct_resources} "
            f"distinct resources (>= {STRONG_MIN_COUNT} obs AND "
            f">= {STRONG_MIN_DISTINCT_RESOURCES} resources required for "
            f"STRONG)"
        )
        return ConfidenceResult(band=Confidence.STRONG, rationale=rationale)

    if MEDIUM_MIN_COUNT <= count <= MEDIUM_MAX_COUNT:
        # Distinguish the "almost-strong" case (count >= 5 but only one
        # resource) so the rationale tells operators WHY they didn't
        # get the broad-include disposition.
        rationale = (
            f"{count} observations across {distinct_resources} "
            f"distinct resource(s) (MEDIUM band: count in "
            f"[{MEDIUM_MIN_COUNT},{MEDIUM_MAX_COUNT}])"
        )
        return ConfidenceResult(band=Confidence.MEDIUM, rationale=rationale)

    if count >= STRONG_MIN_COUNT and distinct_resources < STRONG_MIN_DISTINCT_RESOURCES:
        # The "5+ observations on a single resource" edge case. Per
        # design §2.2 this is MEDIUM — the failed distinct-resources
        # gate is the load-bearing reason and we surface it.
        rationale = (
            f"{count} observations but only on {distinct_resources} "
            f"distinct resource (failed >= {STRONG_MIN_DISTINCT_RESOURCES} "
            f"distinct-resources gate; downgraded STRONG -> MEDIUM)"
        )
        return ConfidenceResult(band=Confidence.MEDIUM, rationale=rationale)

    # count == 1 — WEAK. Phase 3 disposition: Read class includes +
    # flags; Write/Admin/Destructive skip.
    rationale = (
        f"{count} observation on {distinct_resources} distinct "
        f"resource(s) (single-observation pattern; WEAK band)"
    )
    return ConfidenceResult(band=Confidence.WEAK, rationale=rationale)


__all__ = [
    "Confidence",
    "ConfidenceResult",
    "confidence_band",
    "STRONG_MIN_COUNT",
    "STRONG_MIN_DISTINCT_RESOURCES",
    "MEDIUM_MIN_COUNT",
    "MEDIUM_MAX_COUNT",
]
