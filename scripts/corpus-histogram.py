#!/usr/bin/env python3
"""Score every YAML in tests/calibration_corpus/ and print a
terminal histogram of the resulting risk-score distribution.

Usage:
  python scripts/corpus-histogram.py           # overall histogram
  python scripts/corpus-histogram.py --by-dir  # also break down by
                                                  corpus subdirectory
"""
from __future__ import annotations

import argparse
import pathlib
import sys
from collections import Counter, defaultdict

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from iam_jit.review import analyze_policy  # noqa: E402

CORPUS_ROOT = REPO_ROOT / "tests" / "calibration_corpus"
BAR_WIDTH = 50

BAND_LABELS = {
    1: "1  trivial",
    2: "2  very-low",
    3: "3  low",
    4: "4  low-medium",
    5: "5  medium",
    6: "6  medium-high",
    7: "7  high",
    8: "8  very-high",
    9: "9  critical",
    10: "10 catastrophic",
}


def score_file(path: pathlib.Path) -> int | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict) or "policy" not in data:
        return None
    policy = data["policy"]
    request = data.get("request") or {"spec": {"access_type": "read-only"}}
    admin_ctx = data.get("admin_context") or {}
    try:
        analysis = analyze_policy(
            policy, request,
            extra_sensitive_services=tuple(admin_ctx.get("additional_sensitive_services") or ()),
            extra_high_impact_actions=tuple(admin_ctx.get("additional_high_impact_actions") or ()),
        )
    except Exception as e:
        print(f"  ! {path.relative_to(CORPUS_ROOT)}: scoring failed ({e})", file=sys.stderr)
        return None
    return int(analysis.risk_score)


def render_histogram(counts: Counter[int], title: str) -> None:
    total = sum(counts.values())
    if total == 0:
        print(f"\n{title}: no examples")
        return
    peak = max(counts.values()) if counts else 1
    print(f"\n{title}  (n={total})")
    print("─" * 70)
    for band in range(1, 11):
        n = counts.get(band, 0)
        bar_len = round(BAR_WIDTH * n / peak) if peak else 0
        bar = "█" * bar_len
        pct = (100.0 * n / total) if total else 0.0
        print(f"  {BAND_LABELS[band]:<16} │ {bar:<{BAR_WIDTH}} {n:>4}  ({pct:4.1f}%)")
    print("─" * 70)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--by-dir", action="store_true",
                   help="Also show a per-subdirectory breakdown.")
    args = p.parse_args()

    if not CORPUS_ROOT.is_dir():
        print(f"corpus root not found: {CORPUS_ROOT}", file=sys.stderr)
        return 1

    overall: Counter[int] = Counter()
    per_dir: dict[str, Counter[int]] = defaultdict(Counter)
    skipped = 0

    for path in sorted(CORPUS_ROOT.rglob("*.yaml")):
        if path.name.startswith("_"):
            continue
        score = score_file(path)
        if score is None:
            skipped += 1
            continue
        overall[score] += 1
        rel = path.relative_to(CORPUS_ROOT)
        bucket = rel.parts[0] if len(rel.parts) > 1 else "(root)"
        per_dir[bucket][score] += 1

    render_histogram(overall, "Overall corpus risk-score distribution")
    if skipped:
        print(f"  (skipped {skipped} unscoreable files)")

    if args.by_dir:
        for bucket in sorted(per_dir):
            render_histogram(per_dir[bucket], f"by subdir: {bucket}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
