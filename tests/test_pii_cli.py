# ADOPT-7 / #721 — `iam-jit pii {scan,validate}` CLI tests.
from __future__ import annotations

import json

from click.testing import CliRunner

from iam_jit.cli import main


def _write(tmp_path, text):
    p = tmp_path / "detectors.yaml"
    p.write_text(text)
    return str(p)


VALID_CFG = (
    "schema_version: 1\n"
    "entities:\n"
    "  - name: EMP_BADGE\n"
    "    description: employee badge\n"
    "    patterns: [\"EMP-\\\\d{5}\"]\n"
    "    score: 0.8\n"
)


# --- validate: no presidio required ----------------------------------------


def test_validate_ok(tmp_path) -> None:
    cfg = _write(tmp_path, VALID_CFG)
    res = CliRunner().invoke(main, ["pii", "validate", "-c", cfg])
    assert res.exit_code == 0, res.output
    assert "OK: 1 entity" in res.output
    assert "EMP_BADGE" in res.output


def test_validate_json(tmp_path) -> None:
    cfg = _write(tmp_path, VALID_CFG)
    res = CliRunner().invoke(main, ["pii", "validate", "-c", cfg, "--json"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["entities"][0]["name"] == "EMP_BADGE"


def test_validate_bad_config_exit_2(tmp_path) -> None:
    cfg = _write(tmp_path, "schema_version: 1\nentities: []\n")
    res = CliRunner().invoke(main, ["pii", "validate", "-c", cfg])
    assert res.exit_code == 2
    assert "INVALID" in res.output


def test_scan_presidio_absent_exit_3(tmp_path, monkeypatch) -> None:
    # Force the optional-dep guard to report absent → clean no-op exit 3.
    import iam_jit.pii.recognizers as rec

    monkeypatch.setattr(rec, "presidio_available", lambda: False)
    cfg = _write(tmp_path, VALID_CFG)
    res = CliRunner().invoke(
        main, ["pii", "scan", "-c", cfg, "--text", "EMP-12345"]
    )
    assert res.exit_code == 3
    assert "presidio-analyzer is not installed" in res.output
    assert "pip install 'iam-jit[pii]'" in res.output
