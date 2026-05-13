"""Data-driven calibration corpus.

Walks `tests/calibration_corpus/**/*.yaml`, loads each as a
calibration example, and runs it through `review.analyze_policy()`.
Fails CI if any example moves outside its expected verdict.

Adding a calibration example is editing one YAML file — no Python
code change needed. See `tests/calibration_corpus/README.md` for
the file format.

This corpus replaces the inline-Python examples that previously
lived in `test_review_calibration.py`. The inline tests are kept
for backwards compatibility and for cases that need Python logic
(e.g. parametrized over admin context permutations), but new
calibration examples should be added as YAML files here.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
import yaml

from iam_jit.review import analyze_policy


CORPUS_ROOT = pathlib.Path(__file__).parent / "calibration_corpus"


def _load_examples() -> list[tuple[str, dict[str, Any]]]:
    """Walk the corpus tree and return (test_id, example_dict) pairs.

    The test_id is a slash-separated relative path so failures
    point straight at the offending YAML file."""
    out: list[tuple[str, dict[str, Any]]] = []
    if not CORPUS_ROOT.is_dir():
        return out
    for yaml_path in sorted(CORPUS_ROOT.rglob("*.yaml")):
        if yaml_path.name.startswith("_"):
            continue  # Convention: leading underscore = WIP/disabled
        rel = yaml_path.relative_to(CORPUS_ROOT)
        test_id = str(rel).replace("\\", "/").replace(".yaml", "")
        with yaml_path.open("r", encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise AssertionError(
                    f"Malformed calibration YAML at {rel}: {e}"
                )
        if not isinstance(data, dict):
            raise AssertionError(
                f"{rel}: top-level must be a YAML mapping, got "
                f"{type(data).__name__}"
            )
        if "policy" not in data or "expected" not in data:
            raise AssertionError(
                f"{rel}: must define 'policy' and 'expected' keys"
            )
        out.append((test_id, data))
    return out


# Module-level fixture data. Build once at collection time so
# pytest-xdist can parallelize across the corpus cleanly.
_EXAMPLES = _load_examples()


@pytest.mark.parametrize(
    "example",
    [pytest.param(e[1], id=e[0]) for e in _EXAMPLES],
)
def test_calibration_example(example: dict[str, Any]) -> None:
    """Run one corpus example through the scorer and verify the
    expected constraints hold.

    Each constraint is checked independently and failures collect
    so a single test run surfaces ALL problems with one example
    (not just the first)."""
    policy = example["policy"]
    request = example.get("request") or {"spec": {"access_type": "read-only"}}
    expected = example["expected"]
    admin_context = example.get("admin_context") or {}

    extra_services = tuple(admin_context.get("additional_sensitive_services") or ())
    extra_actions = tuple(admin_context.get("additional_high_impact_actions") or ())

    analysis = analyze_policy(
        policy, request,
        extra_sensitive_services=extra_services,
        extra_high_impact_actions=extra_actions,
    )

    failures: list[str] = []

    # Score range
    if "score_min" in expected:
        if analysis.risk_score < expected["score_min"]:
            failures.append(
                f"risk_score={analysis.risk_score} is below expected "
                f"minimum of {expected['score_min']}"
            )
    if "score_max" in expected:
        if analysis.risk_score > expected["score_max"]:
            failures.append(
                f"risk_score={analysis.risk_score} is above expected "
                f"maximum of {expected['score_max']}"
            )

    # Required substrings in risk_factors
    required = expected.get("required_factors_containing") or []
    if required:
        joined = " | ".join(analysis.risk_factors).lower()
        for needle in required:
            if needle.lower() not in joined:
                failures.append(
                    f"required factor substring {needle!r} not found "
                    f"in risk_factors={analysis.risk_factors}"
                )

    # Forbidden substrings — used for regression-protecting
    # "this used to be falsely flagged" cases.
    forbidden = expected.get("forbidden_factors_containing") or []
    if forbidden:
        joined = " | ".join(analysis.risk_factors).lower()
        for needle in forbidden:
            if needle.lower() in joined:
                failures.append(
                    f"forbidden factor substring {needle!r} appeared "
                    f"in risk_factors={analysis.risk_factors}"
                )

    # Auto-approve check at default threshold of 5. Some examples
    # leave this null because they're tier-boundary cases where
    # the auto-approve verdict isn't pinned.
    must_auto_approve = expected.get("must_auto_approve")
    if must_auto_approve is not None:
        DEFAULT_THRESHOLD = 5  # mirrors src/iam_jit/settings_store.py
        would_auto_approve = analysis.risk_score < DEFAULT_THRESHOLD
        if must_auto_approve and not would_auto_approve:
            failures.append(
                f"example must auto-approve at threshold {DEFAULT_THRESHOLD} "
                f"but score={analysis.risk_score} >= threshold"
            )
        if not must_auto_approve and would_auto_approve:
            failures.append(
                f"example must NOT auto-approve at threshold "
                f"{DEFAULT_THRESHOLD} but score={analysis.risk_score} "
                f"< threshold"
            )

    if failures:
        pytest.fail(
            "\n".join(
                ["calibration corpus check failed:"] +
                [f"  - {f}" for f in failures] +
                [f"  scored_at: {analysis.risk_score}",
                 f"  risk_factors: {analysis.risk_factors}"]
            )
        )


def test_corpus_is_nonempty() -> None:
    """Sanity check: if the corpus directory is missing or empty,
    fail loudly. A silent empty corpus is worse than a noisy
    error because it means scorer regressions slip through CI."""
    assert _EXAMPLES, (
        f"Calibration corpus is empty. Expected YAML files under "
        f"{CORPUS_ROOT}. See the README in that directory for the "
        f"file format."
    )
    assert len(_EXAMPLES) >= 8, (
        f"Calibration corpus has only {len(_EXAMPLES)} examples — "
        f"that's not enough to meaningfully gate scorer changes. "
        f"Aim for at least 20."
    )
