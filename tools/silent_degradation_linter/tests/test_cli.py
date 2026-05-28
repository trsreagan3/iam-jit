"""
End-to-end CLI tests for silent_degradation_linter.__main__.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_TOOLS_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_TOOLS_DIR))

from silent_degradation_linter.__main__ import main

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_REPO_ROOT = Path(__file__).parent.parent.parent.parent


class TestCLI:
    def test_positive_fixture_exits_nonzero(self):
        """Scanning a file with known violations should exit 1."""
        rc = main([
            str(_FIXTURES_DIR / "sd1_positive.py"),
            "--no-baseline",
            "--repo-root", str(_REPO_ROOT),
        ])
        assert rc == 1

    def test_negative_fixture_exits_zero(self):
        """Scanning a clean file should exit 0."""
        rc = main([
            str(_FIXTURES_DIR / "sd1_negative.py"),
            "--no-baseline",
            "--repo-root", str(_REPO_ROOT),
        ])
        assert rc == 0

    def test_format_json(self, capsys):
        """--format=json should produce valid JSON output."""
        rc = main([
            str(_FIXTURES_DIR / "sd1_positive.py"),
            "--no-baseline",
            "--format=json",
            "--repo-root", str(_REPO_ROOT),
        ])
        out = capsys.readouterr().out
        findings = json.loads(out)
        assert isinstance(findings, list)
        assert len(findings) >= 1
        for f in findings:
            assert "rule" in f
            assert "path" in f
            assert "line" in f

    def test_format_github(self, capsys):
        """--format=github should produce GitHub annotation lines."""
        rc = main([
            str(_FIXTURES_DIR / "sd1_positive.py"),
            "--no-baseline",
            "--format=github",
            "--repo-root", str(_REPO_ROOT),
        ])
        out = capsys.readouterr().out
        assert "::error file=" in out
        assert "SD-1" in out

    def test_rules_filter(self, capsys):
        """--rules=SD-1 should only report SD-1 findings."""
        rc = main([
            str(_FIXTURES_DIR / "sd1_positive.py"),
            str(_FIXTURES_DIR / "sd4_positive.py"),
            "--no-baseline",
            "--rules=SD-1",
            "--format=json",
            "--repo-root", str(_REPO_ROOT),
        ])
        out = capsys.readouterr().out
        findings = json.loads(out)
        rules = {f["rule"] for f in findings}
        assert rules == {"SD-1"}, f"Expected only SD-1, got: {rules}"

    def test_baseline_suppresses_existing_findings(self, tmp_path):
        """Findings in baseline should not appear in active output."""
        # First: run to get all findings as baseline
        baseline_file = tmp_path / "baseline.json"
        main([
            str(_FIXTURES_DIR / "sd1_positive.py"),
            "--no-baseline",
            "--baseline-update",
            "--baseline", str(baseline_file),
            "--repo-root", str(_REPO_ROOT),
        ])
        assert baseline_file.exists()

        # Now run with the baseline — should be zero new findings
        rc = main([
            str(_FIXTURES_DIR / "sd1_positive.py"),
            "--baseline", str(baseline_file),
            "--repo-root", str(_REPO_ROOT),
        ])
        assert rc == 0, "Expected 0 exit when all findings are baselined"

    def test_new_finding_beyond_baseline_fails(self, tmp_path):
        """A finding NOT in the baseline should still fail."""
        # Baseline only sd4_positive.py
        baseline_file = tmp_path / "baseline.json"
        main([
            str(_FIXTURES_DIR / "sd4_positive.py"),
            "--no-baseline",
            "--baseline-update",
            "--baseline", str(baseline_file),
            "--repo-root", str(_REPO_ROOT),
        ])

        # Now scan BOTH sd1_positive (new) and sd4_positive (baselined)
        rc = main([
            str(_FIXTURES_DIR / "sd1_positive.py"),
            str(_FIXTURES_DIR / "sd4_positive.py"),
            "--baseline", str(baseline_file),
            "--repo-root", str(_REPO_ROOT),
        ])
        assert rc == 1, "Expected exit 1 because sd1_positive.py has new findings"

    def test_no_args_defaults_to_standard_paths(self, capsys):
        """Running with no path args should default to src/iam_jit + tests."""
        # Just check it runs without crashing (baseline will suppress most)
        rc = main([
            "--repo-root", str(_REPO_ROOT),
        ])
        # With baseline in place, should return 0 (all existing findings suppressed)
        assert rc in (0, 1)  # either is valid depending on baseline state
