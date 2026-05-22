"""Random-policy-fuzz comparison (oracle vs deterministic).

Reads composites under `tests/calibration_corpus/random_composites/`
that have BOTH `det_score` + `opus_score` populated, classifies the
gap per the founder rubric, writes the classification back into
each composite YAML, and emits a results doc.

Rubric (founder direction 2026-05-22):

    |gap| ≤ 1  → CALIBRATED
    |gap| = 2  → DRIFT
    |gap| = 3  → UNDER_FLAG (det < opus) or OVER_FLAG (det > opus)
    |gap| ≥ 4  → LIKELY_BUG

This script makes NO LLM calls. It's read + classify + write.

Output:

  - In-place update of `scores.gap_classification` on each
    composite YAML (was `pending`)
  - `docs/RANDOM-FUZZ-RESULTS-{YYYY-MM-DD}.md` with per-class
    counts + the top 10 LIKELY_BUG cases inlined verbatim

Per `[[scorer-is-ground-truth]]`, this script does NOT modify the
scorer or promote any composite to `bug_regressions/`. Promotion
is a deliberate manual step.
"""

from __future__ import annotations

import argparse
import datetime as _dt
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSITES_DIR = REPO_ROOT / "tests" / "calibration_corpus" / "random_composites"
DOCS_DIR = REPO_ROOT / "docs"


def classify(det_score: int, opus_score: int) -> str:
    """Return one of CALIBRATED / DRIFT / UNDER_FLAG / OVER_FLAG / LIKELY_BUG.

    UNDER_FLAG means iam-jit scored LOWER than Opus (det < opus →
    iam-jit missed risk). OVER_FLAG means iam-jit scored HIGHER
    than Opus (iam-jit hallucinated risk Opus didn't see).
    """
    gap = det_score - opus_score
    abs_gap = abs(gap)
    if abs_gap <= 1:
        return "CALIBRATED"
    if abs_gap == 2:
        return "DRIFT"
    if abs_gap == 3:
        return "UNDER_FLAG" if gap < 0 else "OVER_FLAG"
    return "LIKELY_BUG"


def _load_composites() -> list[tuple[Path, dict[str, Any]]]:
    out: list[tuple[Path, dict[str, Any]]] = []
    if not COMPOSITES_DIR.exists():
        return out
    for p in sorted(COMPOSITES_DIR.glob("composite-*.yaml")):
        try:
            with p.open("r", encoding="utf-8") as f:
                doc = yaml.safe_load(f) or {}
        except Exception:
            continue
        out.append((p, doc))
    return out


def _is_judged(doc: dict[str, Any]) -> bool:
    s = doc.get("scores") or {}
    return (
        isinstance(s.get("det_score"), int)
        and isinstance(s.get("opus_score"), int)
    )


def _write_back(path: Path, doc: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, sort_keys=False, width=120)


def _gap(doc: dict[str, Any]) -> int:
    s = doc["scores"]
    return abs(int(s["det_score"]) - int(s["opus_score"]))


def _format_results_doc(
    entries: list[tuple[Path, dict[str, Any], str]],
    unjudged: list[Path],
) -> str:
    """Render the per-class summary + top-10 LIKELY_BUG cases."""
    today = _dt.date.today().isoformat()
    total_judged = len(entries)
    total_unjudged = len(unjudged)

    counts: dict[str, int] = {
        "CALIBRATED": 0,
        "DRIFT": 0,
        "UNDER_FLAG": 0,
        "OVER_FLAG": 0,
        "LIKELY_BUG": 0,
    }
    for _, _, cls in entries:
        counts[cls] = counts.get(cls, 0) + 1

    lines: list[str] = []
    lines.append(f"# Random-policy-fuzz results — {today}")
    lines.append("")
    lines.append(
        f"- **Composites with both scores:** {total_judged}"
    )
    lines.append(
        f"- **Composites still pending Opus judgment:** {total_unjudged}"
    )
    lines.append(
        "- **Generator:** `scripts/random_policy_fuzz.py`"
    )
    lines.append(
        "- **Oracle prompt:** `scripts/random_policy_fuzz_oracle_prompt.md`"
    )
    lines.append(
        "- **Methodology:** `docs/RANDOM-FUZZ-METHODOLOGY-2026-05-22.md`"
    )
    lines.append("")

    lines.append("## Per-class counts")
    lines.append("")
    lines.append("| Class | Count | Share |")
    lines.append("|---|---|---|")
    for cls in ("CALIBRATED", "DRIFT", "UNDER_FLAG", "OVER_FLAG", "LIKELY_BUG"):
        n = counts.get(cls, 0)
        pct = (n / total_judged * 100.0) if total_judged else 0.0
        lines.append(f"| {cls} | {n} | {pct:.1f}% |")
    lines.append("")

    lines.append("## Rubric reminder")
    lines.append("")
    lines.append("| |score gap| | class |")
    lines.append("|---|---|")
    lines.append("| ≤ 1 | CALIBRATED |")
    lines.append("| = 2 | DRIFT |")
    lines.append("| = 3, det < opus | UNDER_FLAG |")
    lines.append("| = 3, det > opus | OVER_FLAG |")
    lines.append("| ≥ 4 | LIKELY_BUG |")
    lines.append("")

    # Top-10 LIKELY_BUG cases inline (largest absolute gap first).
    bugs = [(p, d) for (p, d, c) in entries if c == "LIKELY_BUG"]
    bugs.sort(key=lambda pair: _gap(pair[1]), reverse=True)
    top_bugs = bugs[:10]

    lines.append("## Top 10 LIKELY_BUG cases")
    lines.append("")
    if not top_bugs:
        lines.append(
            "*(none — no judged composite has |gap| ≥ 4 against the oracle)*"
        )
        lines.append("")
    for path, doc in top_bugs:
        s = doc["scores"]
        det = s["det_score"]
        op = s["opus_score"]
        gap = det - op
        direction = "iam-jit OVER-flagged" if gap > 0 else "iam-jit UNDER-flagged"
        lines.append(f"### {doc.get('name', path.stem)}")
        lines.append("")
        lines.append(
            f"- **det_score:** {det}"
            f"  **opus_score:** {op}"
            f"  **gap:** {gap:+d} ({direction})"
        )
        lines.append(f"- **Source file:** `{path.relative_to(REPO_ROOT)}`")
        lines.append("")
        lines.append("```yaml")
        lines.append(yaml.safe_dump(doc, sort_keys=False, width=120).rstrip())
        lines.append("```")
        lines.append("")

    lines.append("## Next step")
    lines.append("")
    lines.append(
        "Per `[[scorer-is-ground-truth]]`, this report does NOT alter the "
        "scorer. The founder reviews each LIKELY_BUG case manually and "
        "decides whether to hand-author a `bug_regressions/NN-...yaml` "
        "entry per `tests/calibration_corpus/README.md`. Only confirmed "
        "scorer bugs become permanent regression tests."
    )
    lines.append("")

    return "\n".join(lines)


def run(
    composites_dir: Path | None = None,
    docs_dir: Path | None = None,
    write: bool = True,
) -> dict[str, Any]:
    global COMPOSITES_DIR, DOCS_DIR
    if composites_dir is not None:
        COMPOSITES_DIR = composites_dir
    if docs_dir is not None:
        DOCS_DIR = docs_dir

    composites = _load_composites()
    entries: list[tuple[Path, dict[str, Any], str]] = []
    unjudged: list[Path] = []
    for path, doc in composites:
        if not _is_judged(doc):
            unjudged.append(path)
            continue
        s = doc["scores"]
        cls = classify(int(s["det_score"]), int(s["opus_score"]))
        s["gap_classification"] = cls
        entries.append((path, doc, cls))
        if write:
            _write_back(path, doc)

    content = _format_results_doc(entries, unjudged)
    today = _dt.date.today().isoformat()
    out_path = DOCS_DIR / f"RANDOM-FUZZ-RESULTS-{today}.md"
    if write:
        DOCS_DIR.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            f.write(content)

    return {
        "judged": len(entries),
        "unjudged": len(unjudged),
        "doc_path": out_path,
        "doc_content": content,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--composites-dir", type=Path, default=None,
        help="override composites dir",
    )
    parser.add_argument(
        "--docs-dir", type=Path, default=None,
        help="override docs output dir",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="do not write the doc or in-place classifications",
    )
    args = parser.parse_args(argv)

    result = run(
        composites_dir=args.composites_dir,
        docs_dir=args.docs_dir,
        write=not args.dry_run,
    )
    print(
        f"[ok] judged={result['judged']} pending={result['unjudged']} "
        f"-> {result['doc_path']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
