"""
Ratchet test: runs the silent-degradation linter against the live codebase.

Existing findings are tracked in:
  tools/silent_degradation_linter/baseline.json

New findings (not in the baseline) fail this test.  Existing debt is
allowed — new debt is not.

To add new findings to the baseline (after a deliberate decision):
  python -m silent_degradation_linter --baseline-update

See docs/SILENT-DEGRADATION-LINTER.md for the full workflow.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure tools/ is importable regardless of where pytest is invoked from
_REPO_ROOT = Path(__file__).parent.parent
_TOOLS_DIR = _REPO_ROOT / "tools"
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from silent_degradation_linter.lint import (
    DEFAULT_SCAN_PATHS,
    Finding,
    load_baseline,
    new_findings,
    scan_paths,
)

_BASELINE_PATH = _TOOLS_DIR / "silent_degradation_linter" / "baseline.json"
_RULES = ("SD-1", "SD-2", "SD-4")


def test_no_new_silent_degradation_findings():
    """
    Scan src/iam_jit/ + tests/ for SD-1/SD-2/SD-4 patterns.
    Only findings NOT in baseline.json are treated as failures.

    If this test fails:
      1. Review the new finding and fix the code (preferred), OR
      2. If the finding is intentional / false-positive, add a
         ``# noqa: SD-N <reason>`` comment on the offending line, OR
      3. If it's legacy debt you're consciously accepting, run:
             python -m silent_degradation_linter --baseline-update
         and commit the updated baseline.json.

    Never add to baseline without a human decision — that defeats the ratchet.
    """
    all_findings = scan_paths(
        list(DEFAULT_SCAN_PATHS),
        repo_root=_REPO_ROOT,
        rules=_RULES,
    )

    baseline = load_baseline(_BASELINE_PATH)
    fresh = new_findings(all_findings, baseline)

    if not fresh:
        return  # clean

    # Format a readable failure message
    by_rule: dict[str, list[Finding]] = {}
    for f in fresh:
        by_rule.setdefault(f.rule, []).append(f)

    lines = [
        f"\n{len(fresh)} NEW silent-degradation finding(s) detected!\n",
        "Fix the code, add `# noqa: SD-N <reason>`, or update the baseline.\n",
        "See docs/SILENT-DEGRADATION-LINTER.md\n",
    ]
    for rule in sorted(by_rule):
        lines.append(f"\n  [{rule}]")
        for f in by_rule[rule]:
            lines.append(f"    {f.path}:{f.line}  {f.message}")
            if f.snippet:
                lines.append(f"      | {f.snippet}")

    pytest.fail("\n".join(lines))
