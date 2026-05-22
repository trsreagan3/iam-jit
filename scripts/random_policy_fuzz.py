"""Random-policy-fuzz generator (founder direction 2026-05-22).

Generates composite IAM policies by sampling 2-5 AWS-managed policies
uniformly at random, concatenating their Statement blocks, and
LOCALLY scoring each composite via `iam_jit.review.analyze_policy(...)`.

This script does NOT call any LLM. The Opus oracle judgment is a
separate phase (see `scripts/random_policy_fuzz_oracle_prompt.md`)
that the founder runs in a Claude Max session; this script just
produces the candidate YAMLs and the deterministic scores.

Cohort distribution (per founder direction):

    50% pairs   (k=2)
    30% triples (k=3)
    15% quads   (k=4)
     5% pentuples (k=5)

Reproducibility:

  - A single `--seed` drives BOTH the cohort-size draw and the
    AWS-managed-policy selection at each step. Same seed + same
    count + same corpus → same output.
  - Dedupe is content-based: the SHA-256 of the sorted tuple of
    source filenames keys each composite. Re-running with the same
    seed produces zero new files; running with a different seed
    only writes a composite if its source-tuple hash is new.

Output:

  `tests/calibration_corpus/random_composites/composite-NNNN-{seed}.yaml`

Each composite YAML carries:

  - `name`, `source_policies`, `policy` (composite doc)
  - `request` (sampled from a small fixed pool)
  - `scores.det_score` + `scores.det_factors`
  - `scores.opus_*` fields set to null (filled in later by the
    oracle phase; see `random_policy_fuzz_oracle_prompt.md`)
  - `scores.gap_classification: pending`

Constraints honored:

  - `[[scorer-is-ground-truth]]` — does NOT tune the scorer
  - `[[creates-never-mutates]]` — does NOT modify the aws_managed
    source corpus; only reads
  - `[[calibration-quality-bar]]` — sampling + dedupe are
    deterministic; methodology is defensible
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = REPO_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

# Imported after sys.path manipulation so the script works without
# the package being pip-installed.
from iam_jit.review import analyze_policy  # noqa: E402


AWS_MANAGED_DIR = REPO_ROOT / "tests" / "calibration_corpus" / "aws_managed"
OUTPUT_DIR = REPO_ROOT / "tests" / "calibration_corpus" / "random_composites"


# Cohort distribution: cumulative thresholds over [0, 1).
# 50% pairs, 30% triples, 15% quads, 5% pentuples.
_COHORT_BREAKS: list[tuple[float, int]] = [
    (0.50, 2),
    (0.80, 3),
    (0.95, 4),
    (1.00, 5),
]


# Small fixed pool of plausible request contexts. Each entry is a
# (user, justification) tuple. Duration is sampled separately from
# `_DURATION_POOL` so we exercise both 1h and longer-running shapes.
_USER_JUSTIFICATION_POOL: list[tuple[str, str]] = [
    ("ci-bot", "deploy via terraform-cloud agent"),
    ("ci-bot", "rotate signing key via CI pipeline"),
    ("dev-alice", "debug staging incident PROD-1417"),
    ("dev-bob", "reproduce customer ticket #4422 locally"),
    ("sre-carol", "scale-out emergency for us-east-1 outage"),
    ("sre-dave", "post-incident audit pull"),
    ("agent-claude", "scoped-tool execution for end-user task"),
    ("agent-claude", "background reconciliation loop"),
    ("auditor-erin", "SOC 2 controls evidence collection"),
    ("contractor-frank", "60-day integration project read access"),
]


_DURATION_POOL: list[int] = [1, 1, 1, 2, 4, 8]  # weighted toward short


@dataclass
class Composite:
    seed: int
    index: int
    source_paths: list[Path]
    policy: dict[str, Any]
    request: dict[str, Any]
    det_score: int
    det_factors: list[str]

    @property
    def source_hash(self) -> str:
        names = sorted(p.name for p in self.source_paths)
        return hashlib.sha256("|".join(names).encode("utf-8")).hexdigest()[:16]

    @property
    def name(self) -> str:
        return f"composite-{self.index:04d}-{self.seed}"

    @property
    def out_path(self) -> Path:
        return OUTPUT_DIR / f"{self.name}.yaml"


def _draw_cohort_size(rng: random.Random) -> int:
    r = rng.random()
    for cutoff, k in _COHORT_BREAKS:
        if r < cutoff:
            return k
    return _COHORT_BREAKS[-1][1]


def _list_aws_managed() -> list[Path]:
    return sorted(AWS_MANAGED_DIR.glob("*.yaml"))


def _load_policy_doc(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        doc = data.get("policy")
        if not isinstance(doc, dict):
            return None
        # `Statement` is sometimes a single dict in AWS land; normalize
        # to a list so concat is uniform.
        stmt = doc.get("Statement")
        if isinstance(stmt, dict):
            doc = {**doc, "Statement": [stmt]}
        elif not isinstance(stmt, list):
            return None
        return doc
    except Exception:
        return None


def _statement_fingerprint(stmt: dict[str, Any]) -> str:
    """Stable hash for exact-dup detection across source statements."""
    try:
        # Strip Sid so two statements differing only in identifier dedupe.
        copy = {k: v for k, v in stmt.items() if k != "Sid"}
        canonical = json.dumps(copy, sort_keys=True, default=str)
    except Exception:
        canonical = repr(stmt)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compose_policy(source_docs: list[dict[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    statements: list[dict[str, Any]] = []
    for src in source_docs:
        for stmt in src.get("Statement", []):
            if not isinstance(stmt, dict):
                continue
            fp = _statement_fingerprint(stmt)
            if fp in seen:
                continue
            seen.add(fp)
            statements.append(stmt)
    return {"Version": "2012-10-17", "Statement": statements}


def _sample_request(rng: random.Random) -> dict[str, Any]:
    user, justification = rng.choice(_USER_JUSTIFICATION_POOL)
    hours = rng.choice(_DURATION_POOL)
    return {
        "spec": {
            "access_type": "read-write",
            "duration": {"duration_hours": hours},
            "resource_constraints": [],
        },
        "user": user,
        "justification": justification,
    }


def _score_with_iam_jit(
    policy: dict[str, Any], request: dict[str, Any]
) -> tuple[int, list[str]]:
    # `analyze_policy` consumes only `request["spec"]`; the extra `user` /
    # `justification` fields ride along on the YAML record for the oracle
    # phase but don't influence the deterministic score.
    analysis = analyze_policy(policy, request)
    return int(analysis.risk_score), list(analysis.risk_factors)


def _composite_yaml_doc(c: Composite) -> dict[str, Any]:
    return {
        "name": c.name,
        "source_policies": [f"aws_managed/{p.name}" for p in c.source_paths],
        "source_hash": c.source_hash,
        "policy": c.policy,
        "request": c.request,
        "scores": {
            "det_score": c.det_score,
            "det_factors": c.det_factors,
            "opus_score": None,
            "opus_factors": None,
            "opus_reasoning": None,
            "gap_classification": "pending",
        },
    }


def _write_yaml(path: Path, doc: dict[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, sort_keys=False, width=120)


def _existing_source_hashes() -> set[str]:
    """Read previously emitted composites to build a dedupe set.

    Re-running with the same seed yields the same source picks, so
    the in-memory `seen_hashes` set covers single-run dedupe. This
    helper extends dedupe ACROSS runs (different seeds may collide
    on the same source tuple) which is part of the founder spec.
    """
    if not OUTPUT_DIR.exists():
        return set()
    hashes: set[str] = set()
    for p in OUTPUT_DIR.glob("composite-*.yaml"):
        try:
            with p.open("r", encoding="utf-8") as f:
                d = yaml.safe_load(f) or {}
            h = d.get("source_hash")
            if isinstance(h, str) and h:
                hashes.add(h)
        except Exception:
            continue
    return hashes


def generate(
    count: int,
    seed: int,
    *,
    output_dir: Path | None = None,
    aws_managed_dir: Path | None = None,
    skip_existing: bool = True,
) -> list[Composite]:
    """Generate up to `count` composites.

    Returns the list of NEW composites actually written. Composites
    whose source-tuple is already present on disk (or generated
    earlier in the same run) are skipped per the dedupe rule.
    """
    global OUTPUT_DIR, AWS_MANAGED_DIR
    if output_dir is not None:
        OUTPUT_DIR = output_dir
    if aws_managed_dir is not None:
        AWS_MANAGED_DIR = aws_managed_dir

    rng = random.Random(seed)
    sources = _list_aws_managed()
    if len(sources) < 5:
        raise RuntimeError(
            f"Need at least 5 AWS-managed policies; found {len(sources)} in {AWS_MANAGED_DIR}"
        )

    seen_hashes = _existing_source_hashes() if skip_existing else set()
    produced: list[Composite] = []

    # We try up to `count * 10` attempts to land `count` new composites.
    # In practice the source corpus is large enough (1,489 files) that
    # collisions are vanishingly rare for sub-1000 batches.
    max_attempts = count * 10
    attempts = 0
    while len(produced) < count and attempts < max_attempts:
        attempts += 1
        k = _draw_cohort_size(rng)
        # `random.sample` without replacement — no policy appears twice
        # within a single composite.
        picks = rng.sample(sources, k)
        source_hash_check = hashlib.sha256(
            "|".join(sorted(p.name for p in picks)).encode("utf-8")
        ).hexdigest()[:16]
        if source_hash_check in seen_hashes:
            continue

        docs = [d for d in (_load_policy_doc(p) for p in picks) if d is not None]
        if len(docs) != k:
            # At least one source failed to parse; skip + try again. The
            # corpus is curated so this should essentially never fire.
            continue

        policy = _compose_policy(docs)
        if not policy.get("Statement"):
            continue

        request = _sample_request(rng)
        try:
            score, factors = _score_with_iam_jit(policy, request)
        except Exception as exc:
            # Defensive: if a freakish composite shape breaks the
            # scorer we surface it for inspection but don't abort the
            # batch.
            print(f"[warn] scoring failed for {[p.name for p in picks]}: {exc}", file=sys.stderr)
            continue

        c = Composite(
            seed=seed,
            index=len(produced) + 1,
            source_paths=picks,
            policy=policy,
            request=request,
            det_score=score,
            det_factors=factors,
        )
        seen_hashes.add(c.source_hash)
        produced.append(c)
        _write_yaml(c.out_path, _composite_yaml_doc(c))

    return produced


def _summary(produced: list[Composite]) -> dict[str, Any]:
    score_dist: dict[int, int] = {i: 0 for i in range(1, 11)}
    cohort_dist: dict[int, int] = {2: 0, 3: 0, 4: 0, 5: 0}
    for c in produced:
        score_dist[c.det_score] = score_dist.get(c.det_score, 0) + 1
        k = len(c.source_paths)
        cohort_dist[k] = cohort_dist.get(k, 0) + 1
    return {
        "count": len(produced),
        "score_distribution": score_dist,
        "cohort_distribution": cohort_dist,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=100, help="number of composites to generate")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for reproducibility")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="override output directory (default: tests/calibration_corpus/random_composites)",
    )
    parser.add_argument(
        "--no-skip-existing",
        action="store_true",
        help="do not skip composites whose source-tuple already exists on disk",
    )
    args = parser.parse_args(argv)

    produced = generate(
        count=args.count,
        seed=args.seed,
        output_dir=args.output_dir,
        skip_existing=not args.no_skip_existing,
    )
    s = _summary(produced)
    print(f"[ok] wrote {s['count']} new composites to {OUTPUT_DIR}")
    print(f"     cohort distribution: {s['cohort_distribution']}")
    print(f"     score distribution:  {s['score_distribution']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
