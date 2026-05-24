"""aggregate.py — read UAT lifecycle results.jsonl + produce summary.

Produces TWO outputs:
* summary.md  — operator-readable matrix (scenarios × recent runs)
* summary.jsonl — agent-readable; one line per scenario with the
                  most-recent run + 30-day status counts

Per docs/UAT-LIFECYCLE/HARNESS-SPEC.md:
* Append-only on the input; this aggregator NEVER mutates
  results.jsonl.
* Sanitizes operator-identifying paths in evidence values before
  writing the markdown output (per [[push-policy-public-repo]]).
* Output paths default under ~/.iam-jit/uat-lifecycle/.

Usage:
    python aggregate.py
    python aggregate.py --results <path> --out-md <path> --out-jsonl <path>
    python aggregate.py --window-days 30
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone


SCENARIO_IDS = [f"L{i}" for i in range(1, 16)]
SCENARIO_TITLES = {
    "L1": "Fresh install on clean system",
    "L2": "Bootstrap declaration → discovery-mode bring-up",
    "L3": "Update mechanism end-to-end",
    "L4": "Update FAILURE recovery",
    "L5": "Profile lifecycle (discovery → install → enforce → revert)",
    "L6": "Threat-feed lifecycle",
    "L7": "Crash recovery (SIGKILL)",
    "L8": "Disk pressure circuit breaker",
    "L9": "Audit log rotation lifecycle",
    "L10": "Multi-machine config portability",
    "L11": "Clean uninstall",
    "L12": "Cross-bouncer update consistency",
    "L13": "LLM credential rotation (standalone)",
    "L14": "AWS credential rotation through ibounce",
    "L15": "Dynamic-deny lifecycle",
}

_HOME_PAT = re.compile(r"/Users/[^/\s\"]+")
_MARKER_PATS = [
    re.compile(r"\bReagan\b", re.IGNORECASE),
    re.compile(r"\bOmise\b", re.IGNORECASE),
    re.compile(r"\btrsreagan3\b", re.IGNORECASE),
]


def _sanitize_string(value: str) -> str:
    """Strip operator-identifying markers from a free-form string."""
    out = _HOME_PAT.sub("/HOME/<operator>", value)
    for pat in _MARKER_PATS:
        out = pat.sub("<operator>", out)
    return out


def _sanitize_value(value):
    if isinstance(value, str):
        return _sanitize_string(value)
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _sanitize_value(v) for k, v in value.items()}
    return value


def _parse_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def _load_results(path: pathlib.Path) -> list[dict]:
    out = []
    if not path.exists():
        return out
    with path.open("r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                sys.stderr.write(
                    f"aggregate.py: skipping unparseable line: {e}\n"
                )
    return out


def _group_by_scenario(results: list[dict]) -> dict[str, list[dict]]:
    grouped = {sid: [] for sid in SCENARIO_IDS}
    for r in results:
        sid = r.get("scenario_id")
        if sid in grouped:
            grouped[sid].append(r)
    for sid in grouped:
        grouped[sid].sort(key=lambda r: r.get("ts", ""))
    return grouped


def _status_counts(runs: list[dict], window_days: int) -> dict[str, int]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    counts: Counter[str] = Counter()
    for r in runs:
        try:
            ts = _parse_ts(r.get("ts", ""))
        except Exception:
            continue
        if ts < cutoff:
            continue
        counts[r.get("status", "ERROR")] += 1
    return dict(counts)


def _render_md(grouped: dict[str, list[dict]], window_days: int) -> str:
    lines: list[str] = []
    lines.append("# UAT Lifecycle — Summary")
    lines.append("")
    lines.append(
        f"Generated {datetime.now(timezone.utc).isoformat()}; "
        f"window={window_days}d."
    )
    lines.append("")
    lines.append(
        "Per docs/UAT-LIFECYCLE/HARNESS-SPEC.md this file is "
        "regenerated from `results.jsonl` on every aggregator run; "
        "evidence strings are sanitized for operator markers per "
        "`[[push-policy-public-repo]]`. NEVER edit this file by hand."
    )
    lines.append("")
    lines.append("## Matrix")
    lines.append("")
    lines.append("| Scenario | Title | Last run | Last status | "
                 "PASS | FAIL | SKIP | ERROR |")
    lines.append("|---|---|---|---|---:|---:|---:|---:|")
    for sid in SCENARIO_IDS:
        runs = grouped.get(sid, [])
        counts = _status_counts(runs, window_days)
        last = runs[-1] if runs else None
        last_ts = last.get("ts", "—") if last else "—"
        last_status = last.get("status", "—") if last else "—"
        lines.append(
            f"| {sid} | {SCENARIO_TITLES[sid]} | {last_ts} | "
            f"{last_status} | {counts.get('PASS', 0)} | "
            f"{counts.get('FAIL', 0)} | {counts.get('SKIP', 0)} | "
            f"{counts.get('ERROR', 0)} |"
        )
    lines.append("")
    lines.append("## Recent failures")
    lines.append("")
    any_fail = False
    for sid in SCENARIO_IDS:
        for run in reversed(grouped.get(sid, [])):
            if run.get("status") == "FAIL":
                any_fail = True
                sanitized = _sanitize_value(run.get("evidence", {}))
                lines.append(f"### {sid} @ {run.get('ts', '?')}")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(sanitized, indent=2, sort_keys=True))
                lines.append("```")
                lines.append("")
                break
    if not any_fail:
        lines.append("_No recent failures._")
        lines.append("")
    return "\n".join(lines) + "\n"


def _render_jsonl(
    grouped: dict[str, list[dict]], window_days: int
) -> str:
    out_lines: list[str] = []
    for sid in SCENARIO_IDS:
        runs = grouped.get(sid, [])
        last = runs[-1] if runs else None
        record = {
            "scenario_id": sid,
            "title": SCENARIO_TITLES[sid],
            "last_run": _sanitize_value(last) if last else None,
            "window_days": window_days,
            "counts": _status_counts(runs, window_days),
        }
        out_lines.append(json.dumps(record, sort_keys=True))
    return "\n".join(out_lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_root = pathlib.Path.home() / ".iam-jit" / "uat-lifecycle"
    parser.add_argument(
        "--results",
        type=pathlib.Path,
        default=default_root / "results.jsonl",
    )
    parser.add_argument(
        "--out-md", type=pathlib.Path, default=default_root / "summary.md"
    )
    parser.add_argument(
        "--out-jsonl",
        type=pathlib.Path,
        default=default_root / "summary.jsonl",
    )
    parser.add_argument("--window-days", type=int, default=30)
    args = parser.parse_args()

    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_jsonl.parent.mkdir(parents=True, exist_ok=True)

    results = _load_results(args.results)
    grouped = _group_by_scenario(results)

    args.out_md.write_text(_render_md(grouped, args.window_days))
    args.out_jsonl.write_text(_render_jsonl(grouped, args.window_days))

    sys.stderr.write(
        f"aggregate.py: wrote {args.out_md} + {args.out_jsonl} "
        f"({len(results)} input rows, "
        f"{sum(1 for sid in SCENARIO_IDS if grouped.get(sid))} "
        f"scenarios with runs)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
