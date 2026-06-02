# ADOPT-7 / #721 — `iam-jit pii scan` tests that REQUIRE the presidio
# optional extra. Skipped cleanly in CI; run locally.
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from iam_jit.cli import main

pytest.importorskip("presidio_analyzer")


VALID_CFG = (
    "schema_version: 1\n"
    "entities:\n"
    "  - name: EMP_BADGE\n"
    "    description: employee badge\n"
    "    patterns: [\"EMP-\\\\d{5}\"]\n"
    "    score: 0.8\n"
)


def _write(tmp_path, text=VALID_CFG):
    p = tmp_path / "detectors.yaml"
    p.write_text(text)
    return str(p)


def test_scan_detects_and_redacts(tmp_path) -> None:
    cfg = _write(tmp_path)
    res = CliRunner().invoke(
        main, ["pii", "scan", "-c", cfg, "--text", "my badge EMP-12345 ok"]
    )
    assert res.exit_code == 0, res.output
    assert "EMP_BADGE" in res.output
    assert "[REDACTED:EMP_BADGE]" in res.output
    assert "false positive" in res.output.lower()


def test_scan_json_output(tmp_path) -> None:
    cfg = _write(tmp_path)
    res = CliRunner().invoke(
        main, ["pii", "scan", "-c", cfg, "--text", "EMP-12345", "--json"]
    )
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["match_count"] == 1
    assert data["matches"][0]["entity"] == "EMP_BADGE"
    assert "[REDACTED:EMP_BADGE]" in data["redacted"]
    assert "false positive" in data["caveat"].lower()


def test_scan_no_match(tmp_path) -> None:
    cfg = _write(tmp_path)
    res = CliRunner().invoke(
        main, ["pii", "scan", "-c", cfg, "--text", "nothing here"]
    )
    assert res.exit_code == 0, res.output
    assert "No custom PII detected" in res.output
