"""
CLI entry point: ``python -m silent_degradation_linter [paths...] [options]``

Usage
-----
  python -m silent_degradation_linter                    # scan default paths
  python -m silent_degradation_linter src/iam_jit/       # specific dir
  python -m silent_degradation_linter --format=json      # JSON output
  python -m silent_degradation_linter --format=github    # GitHub annotations
  python -m silent_degradation_linter --rules SD-1,SD-4  # subset of rules
  python -m silent_degradation_linter --baseline-update  # update baseline.json

Exit codes
----------
  0   no (new) findings
  1   one or more (new) findings detected
  2   internal error
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .lint import (
    DEFAULT_SCAN_PATHS,
    Finding,
    format_findings,
    load_baseline,
    new_findings,
    save_baseline,
    scan_paths,
)

# Canonical baseline location relative to this file's directory
_HERE = Path(__file__).parent
BASELINE_PATH = _HERE / "baseline.json"


def _repo_root() -> Path:
    """Walk up from this file to find the git root (contains pyproject.toml)."""
    candidate = _HERE
    for _ in range(10):
        if (candidate / "pyproject.toml").exists():
            return candidate
        candidate = candidate.parent
    return Path.cwd()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="silent_degradation_linter",
        description="Flag silent-degradation patterns (SD-1, SD-2, SD-4).",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help=(
            "Files or directories to scan. "
            f"Defaults to: {list(DEFAULT_SCAN_PATHS)}"
        ),
    )
    parser.add_argument(
        "--format",
        choices=["pretty", "json", "github"],
        default="pretty",
        dest="fmt",
        help="Output format (default: pretty)",
    )
    parser.add_argument(
        "--rules",
        default="SD-1,SD-2,SD-4",
        help="Comma-separated rules to enforce (default: SD-1,SD-2,SD-4)",
    )
    parser.add_argument(
        "--baseline",
        default=str(BASELINE_PATH),
        help="Path to baseline.json (default: tools/silent_degradation_linter/baseline.json)",
    )
    parser.add_argument(
        "--baseline-update",
        action="store_true",
        help="Write ALL current findings to the baseline file (ratchet reset)",
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="Ignore baseline; report ALL findings (useful for first-run exploration)",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Override repo root detection",
    )

    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root) if args.repo_root else _repo_root()
    rules = [r.strip().upper() for r in args.rules.split(",") if r.strip()]
    scan_dirs = args.paths if args.paths else list(DEFAULT_SCAN_PATHS)
    baseline_path = Path(args.baseline)

    try:
        findings = scan_paths(scan_dirs, repo_root, rules)
    except Exception as exc:
        print(f"ERROR: scan failed: {exc}", file=sys.stderr)
        return 2

    if args.baseline_update:
        save_baseline(baseline_path, findings)
        print(
            f"Baseline updated: {len(findings)} finding(s) written to {baseline_path}",
            file=sys.stderr,
        )
        return 0

    if args.no_baseline:
        active = findings
    else:
        baseline = load_baseline(baseline_path)
        active = new_findings(findings, baseline)

    output = format_findings(active, args.fmt)
    print(output, end="")

    return 1 if active else 0


if __name__ == "__main__":
    sys.exit(main())
