"""Calibration check for the curated examples library.

Each policy in `examples/policies/<band>/` has a sidecar
`<name>.expected.yaml` declaring the score range we expect.
This test scores every policy and asserts the deterministic
scorer returns a value in the declared range.

If you change the scorer and a curated example drifts:
  1. STOP. The curated examples are intentional anchors —
     drift here means the calibration corpus probably also
     drifts in unintended ways.
  2. Look at the policy. Does the sidecar's `why:` paragraph
     still match the score?
  3. If the sidecar is correct and the scorer is wrong, fix
     the scorer.
  4. If the scorer is correct and the sidecar is wrong, fix
     the sidecar (and update `why:` to reflect the new reasoning).
  5. Never just bump min/max to make tests pass.

See `examples/policies/README.md` for the full policy.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest
from ruamel.yaml import YAML

from iam_jit.review import analyze_policy


_yaml = YAML(typ="safe")
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_POLICIES_DIR = _REPO_ROOT / "examples" / "policies"


def _enumerate_examples() -> list[tuple[pathlib.Path, dict[str, Any]]]:
    """Yield (json_path, expected_dict) for every example with a sidecar."""
    out: list[tuple[pathlib.Path, dict[str, Any]]] = []
    for band_dir in ("safe", "borderline", "dangerous"):
        for json_path in sorted((_POLICIES_DIR / band_dir).glob("*.json")):
            sidecar = json_path.with_suffix(".expected.yaml")
            if not sidecar.exists():
                # Allow .json examples without sidecars during initial
                # authoring. Test below will skip them with a warning.
                out.append((json_path, {}))
                continue
            expected = _yaml.load(sidecar.read_text())
            out.append((json_path, expected))
    return out


def _example_id(item: tuple[pathlib.Path, dict[str, Any]]) -> str:
    p, _ = item
    return f"{p.parent.name}/{p.stem}"


@pytest.mark.parametrize(
    "example", _enumerate_examples(), ids=_example_id,
)
def test_curated_example_scores_in_expected_band(
    example: tuple[pathlib.Path, dict[str, Any]],
) -> None:
    json_path, expected = example
    if not expected:
        pytest.skip(
            f"{json_path.name}: no .expected.yaml sidecar yet"
        )

    policy = json.loads(json_path.read_text())
    # analyze_policy needs a request shell for context (access_type,
    # accounts, duration). For library-shape calibration we use a
    # neutral default that doesn't bias the score.
    request_shell = {
        "spec": {
            "policy": policy,
            "access_type": "read-write",
            "duration_hours": 1,
            "accounts": [{"account_id": "123456789012"}],
        },
    }
    analysis = analyze_policy(policy, request_shell)
    score = analysis.risk_score

    lo = expected.get("expected_score_min")
    hi = expected.get("expected_score_max")
    assert isinstance(lo, int) and isinstance(hi, int), (
        f"{json_path.name}: sidecar must declare expected_score_min "
        f"and expected_score_max as integers"
    )
    assert lo <= score <= hi, (
        f"{json_path.name}: expected score in [{lo}, {hi}] "
        f"but got {score}.\n"
        f"  category: {expected.get('category')}\n"
        f"  why: {expected.get('why', '').strip()[:200]}\n"
        f"  scorer factors: {analysis.risk_factors}\n"
        f"\n"
        f"  If the scorer is right: update the sidecar's "
        f"expected_score_{'min' if score < lo else 'max'} and "
        f"explain in `why:`. NEVER just bump the band silently."
    )


def test_every_example_has_sidecar() -> None:
    """Every .json under examples/policies/ must have a sidecar.

    Examples without sidecars don't earn calibration credit and
    aren't useful as anchors. This test makes the rule explicit
    so reviewers catch missing sidecars in PR.
    """
    missing: list[str] = []
    for band_dir in ("safe", "borderline", "dangerous"):
        for json_path in (_POLICIES_DIR / band_dir).glob("*.json"):
            if not json_path.with_suffix(".expected.yaml").exists():
                missing.append(str(json_path.relative_to(_REPO_ROOT)))
    assert not missing, (
        "These curated examples are missing .expected.yaml sidecars:\n"
        + "\n".join(f"  - {m}" for m in missing)
    )


def test_every_sidecar_declares_required_fields() -> None:
    """Every sidecar must declare name, category, expected_score_*, why."""
    bad: list[str] = []
    required = {"name", "category", "expected_score_min", "expected_score_max", "why"}
    for sidecar in _POLICIES_DIR.rglob("*.expected.yaml"):
        data = _yaml.load(sidecar.read_text()) or {}
        missing = required - set(data.keys())
        if missing:
            bad.append(f"{sidecar.relative_to(_REPO_ROOT)}: missing {sorted(missing)}")
    assert not bad, "Sidecars failing schema:\n" + "\n".join(f"  - {b}" for b in bad)


def test_categories_match_band_directory() -> None:
    """The sidecar's category MUST match the directory it lives in."""
    bad: list[str] = []
    for sidecar in _POLICIES_DIR.rglob("*.expected.yaml"):
        band_from_dir = sidecar.parent.name
        category = (_yaml.load(sidecar.read_text()) or {}).get("category")
        if category != band_from_dir:
            bad.append(
                f"{sidecar.relative_to(_REPO_ROOT)}: directory says "
                f"'{band_from_dir}' but sidecar says '{category}'"
            )
    assert not bad, "\n".join(bad)
