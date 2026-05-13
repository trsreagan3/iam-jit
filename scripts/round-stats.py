#!/usr/bin/env python3
"""Per-round gap-distribution stats for the adversarial corpus.

Run after every round closure to see if findings are trending toward
zero gap-≥3. The convergence signal is "max_gap stays below 3 for
two consecutive rounds AND the round's findings are esoteric edge
cases rather than common attack vectors."

Usage:
  python scripts/round-stats.py
  python scripts/round-stats.py --json   # machine-readable

Output: one row per round with:
  - total YAMLs collected for that round-range
  - closed (gap ≤ 0; scorer meets the agent's expectation)
  - gap-1-2 (calibration drift; not architectural)
  - gap-≥3 (architectural gap; real bypass class)
  - max_gap (highest-severity finding in the round)
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import yaml  # noqa: E402

from iam_jit.review import analyze_policy  # noqa: E402

CORPUS = REPO_ROOT / "tests" / "calibration_corpus" / "agent_discovered"

ROUNDS = [
    ("R1 BB",   range(1, 31)),
    ("R2 BB",   range(31, 58)),
    ("R3 BB",   range(58, 96)),
    ("R5 BB",   range(96, 148)),
    ("R6 BB",   range(148, 194)),
    ("R6 WB",   range(200, 248)),
    ("R7 BB",   range(300, 329)),
    ("R7 WB",   range(400, 430)),
    ("R8 BB",   range(500, 600)),
    ("R8 WB",   range(600, 700)),
    ("R9 BB",   range(700, 800)),
    ("R9 WB",   range(800, 900)),
    ("R10 BB",  range(900, 1000)),
    ("R10 WB",  range(1000, 1100)),
    ("R11 BB",  range(1100, 1200)),
    ("R11 WB",  range(1200, 1300)),
    ("R12 BB",  range(1300, 1400)),
    ("R12 WB",  range(1400, 1500)),
]


def _stats_for_range(rng: range) -> dict | None:
    gaps: list[int] = []
    yaml_count = 0
    for p in sorted(CORPUS.glob("agent-*.yaml")):
        m = re.match(r"agent-(\d+)-", p.name)
        if not m:
            continue
        n = int(m.group(1))
        if n not in rng:
            continue
        yaml_count += 1
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            policy = data.get("policy") or {}
            request = data.get("request") or {"spec": {"access_type": "read-only"}}
            expected = data.get("expected") or {}
            score_min = expected.get("score_min")
            if not isinstance(score_min, int):
                continue
            analysis = analyze_policy(policy, request)
            gaps.append(score_min - analysis.risk_score)
        except Exception:
            continue
    if not gaps:
        return None
    return {
        "total": yaml_count,
        "scored": len(gaps),
        "closed": sum(1 for g in gaps if g <= 0),
        "gap_1_2": sum(1 for g in gaps if 1 <= g <= 2),
        "gap_ge_3": sum(1 for g in gaps if g >= 3),
        "max_gap": max(gaps),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--json", action="store_true",
                   help="Emit JSON instead of the formatted table.")
    args = p.parse_args()

    rows = []
    for label, rng in ROUNDS:
        stats = _stats_for_range(rng)
        if stats is None:
            continue
        rows.append({"round": label, **stats})

    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    print()
    print(f"{'round':<10} {'total':>5} {'closed':>7} {'gap1-2':>7} {'gap≥3':>6} {'max_gap':>8}")
    print("─" * 50)
    for r in rows:
        marker = ""
        if r["max_gap"] == 0:
            marker = "  ✓ fully closed"
        elif r["max_gap"] <= 2:
            marker = "  · calibration only"
        elif r["max_gap"] >= 5:
            marker = "  ⚠ severe gap"
        print(
            f"{r['round']:<10} "
            f"{r['total']:>5} "
            f"{r['closed']:>7} "
            f"{r['gap_1_2']:>7} "
            f"{r['gap_ge_3']:>6} "
            f"{r['max_gap']:>8}"
            f"{marker}"
        )
    print()

    # Convergence verdict — look at the LATEST round only.
    if rows:
        latest = rows[-1]
        print(f"Latest round: {latest['round']}")
        if latest["max_gap"] == 0:
            print("  Convergence: this round is FULLY CLOSED (max_gap=0).")
        elif latest["max_gap"] <= 2:
            print("  Convergence: calibration-drift only (max_gap ≤ 2). "
                  "Consider the loop converged for this round.")
        else:
            print(f"  Convergence: NOT converged — {latest['gap_ge_3']} "
                  f"architectural findings remain (max_gap={latest['max_gap']}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
