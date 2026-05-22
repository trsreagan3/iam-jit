"""Tests for `scripts/random_policy_fuzz.py`.

The script lives outside the `src/iam_jit/` import path; loaded as a
file-relative module so the test suite can exercise it without
polluting package namespaces — same pattern as
`tests/scripts/test_aws_usage_builder.py`.

No LLM calls. Pure deterministic generation + iam-jit scorer.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "random_policy_fuzz.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "random_policy_fuzz_under_test", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def script(tmp_path: Path) -> Any:
    """Fresh module per test with output redirected into `tmp_path`."""
    module = _load_module()
    # Redirect global output dir so test runs never touch the real corpus.
    module.OUTPUT_DIR = tmp_path / "random_composites"
    return module


def test_seed_and_count_are_deterministic(script: Any, tmp_path: Path) -> None:
    """Same seed + same count → identical composite YAMLs (reproducible)."""
    out_a = tmp_path / "run_a"
    out_b = tmp_path / "run_b"
    produced_a = script.generate(count=10, seed=42, output_dir=out_a)
    produced_b = script.generate(count=10, seed=42, output_dir=out_b)

    assert len(produced_a) == 10
    assert len(produced_b) == 10

    files_a = sorted((tmp_path / "run_a").glob("composite-*.yaml"))
    files_b = sorted((tmp_path / "run_b").glob("composite-*.yaml"))
    assert len(files_a) == 10
    assert len(files_b) == 10

    for a, b in zip(files_a, files_b, strict=True):
        # Same name + same content → byte-equal files.
        assert a.name == b.name
        assert a.read_text(encoding="utf-8") == b.read_text(encoding="utf-8")


def test_dedupe_skips_repeated_source_tuples(
    script: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same source-tuple → only one composite (content-hash dedupe).

    We pin the corpus to a tiny 5-policy sub-set so the cohort sampler
    is forced to collide: there are only `C(5,2) + C(5,3) + C(5,4) +
    C(5,5) = 10 + 10 + 5 + 1 = 26` distinct source-tuples possible,
    and after exhausting them every new attempt MUST hash to an
    existing composite. The dedupe contract is: re-attempting an
    already-seen source-tuple produces zero additional files.
    """
    # Carve a tiny corpus by symlinking the first 5 sorted aws_managed
    # YAMLs into a fresh dir + redirecting the script at it.
    tiny_corpus = tmp_path / "tiny_corpus"
    tiny_corpus.mkdir()
    real_corpus = (
        REPO_ROOT / "tests" / "calibration_corpus" / "aws_managed"
    )
    for src in sorted(real_corpus.glob("*.yaml"))[:5]:
        (tiny_corpus / src.name).symlink_to(src)

    out_dir = tmp_path / "dedupe_run"

    # Generate the maximum number of unique source-tuples (26 with k=2..5
    # over 5 policies). Request 26 + 50 extra; dedupe must cap the
    # produced count at 26 — every extra attempt collides.
    monkeypatch.setattr(script, "AWS_MANAGED_DIR", tiny_corpus)
    produced = script.generate(
        count=76, seed=42, output_dir=out_dir, aws_managed_dir=tiny_corpus
    )

    # All produced composites have unique source-tuple hashes.
    hashes = [c.source_hash for c in produced]
    assert len(hashes) == len(set(hashes)), "dedupe failed within a single run"
    # Cap at the 26 possible distinct tuples.
    assert len(produced) <= 26
    assert len(produced) >= 10  # we should land at least the pair-only tier

    # A second run starting from the same on-disk corpus picks up the
    # prior hashes via `_existing_source_hashes` and writes zero new
    # files — every draw collides.
    before = sorted((out_dir).glob("composite-*.yaml"))
    second = script.generate(
        count=20, seed=99, output_dir=out_dir, aws_managed_dir=tiny_corpus
    )
    after = sorted((out_dir).glob("composite-*.yaml"))
    # Either zero new (full exhaustion), or every produced composite's
    # source_hash is genuinely novel. Both are correct dedupe behavior.
    produced_hashes = {c.source_hash for c in second}
    existing_hashes = set()
    for p in before:
        with p.open("r", encoding="utf-8") as f:
            existing_hashes.add((yaml.safe_load(f) or {}).get("source_hash"))
    assert produced_hashes.isdisjoint(existing_hashes), (
        "dedupe failed across runs — second run re-wrote a source-tuple "
        "already on disk"
    )
    # Total files on disk ≤ the 26 possible distinct tuples.
    assert len(after) <= 26


def test_det_score_populated_on_every_composite(script: Any, tmp_path: Path) -> None:
    """`scores.det_score` is a valid 1-10 integer on every output."""
    out_dir = tmp_path / "score_run"
    produced = script.generate(count=15, seed=123, output_dir=out_dir)
    assert len(produced) == 15

    for path in sorted(out_dir.glob("composite-*.yaml")):
        with path.open("r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        scores = doc.get("scores") or {}
        det = scores.get("det_score")
        assert isinstance(det, int), f"{path.name}: det_score not int → {det!r}"
        assert 1 <= det <= 10, f"{path.name}: det_score out of range → {det}"
        # Opus fields are seeded null + classification pending — that's
        # part of the file format contract the oracle phase relies on.
        assert scores.get("opus_score") is None
        assert scores.get("opus_factors") is None
        assert scores.get("opus_reasoning") is None
        assert scores.get("gap_classification") == "pending"
        # Source provenance is recorded.
        assert isinstance(doc.get("source_policies"), list)
        assert 2 <= len(doc["source_policies"]) <= 5
