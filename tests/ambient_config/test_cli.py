"""#400 — `iam-jit doctor apply-config` CLI tests."""

from __future__ import annotations

import json
import pathlib

from click.testing import CliRunner

from iam_jit.cli import main


def _write(path: pathlib.Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)


# ---------------------------------------------------------------------------
# Default discovery + dry-run + inspect surfaces
# ---------------------------------------------------------------------------


def test_doctor_apply_config_reads_iam_jit_yaml_in_cwd(
    tmp_path: pathlib.Path,
) -> None:
    """Operator runs `iam-jit doctor apply-config --dry-run` from a
    directory containing `.iam-jit.yaml`; the loader auto-discovers."""
    _write(
        tmp_path / ".iam-jit.yaml",
        """iam-jit:
  enabled: true
  bouncers:
    ibounce:
      enabled: true
      mode: discovery
""",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "doctor",
            "apply-config",
            "--cwd",
            str(tmp_path),
            "--dry-run",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["dry_run"] is True
    # bouncers_planned contains ibounce
    names = [r["name"] for r in payload["bouncers_planned"]]
    assert "ibounce" in names


def test_doctor_apply_config_dry_run_does_not_execute(
    tmp_path: pathlib.Path,
) -> None:
    """Dry-run MUST NOT start any subprocesses (no PIDs in result)."""
    _write(
        tmp_path / ".iam-jit.yaml",
        "iam-jit:\n  enabled: true\n  bouncers:\n    ibounce: {enabled: true}\n",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "doctor",
            "apply-config",
            "--cwd",
            str(tmp_path),
            "--dry-run",
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["bouncers_started"] == []
    assert payload["audit_event_ids"] == []
    for record in payload["bouncers_planned"]:
        assert "pid" not in record  # never executed


def test_doctor_apply_config_inspect_validates_only(
    tmp_path: pathlib.Path,
) -> None:
    """--inspect validates the declaration but does NOT plan or
    execute. Returns a parsed shape."""
    _write(
        tmp_path / ".iam-jit.yaml",
        """iam-jit:
  enabled: true
  posture: ambient
  bouncers:
    ibounce: {enabled: true, mode: discovery}
""",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "doctor",
            "apply-config",
            "--cwd",
            str(tmp_path),
            "--inspect",
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["validated"] is True
    assert payload["declaration"]["iam-jit"]["posture"] == "ambient"
    # No plan in --inspect mode
    assert "bouncers_planned" not in payload


def test_doctor_apply_config_rejects_invalid_declaration(
    tmp_path: pathlib.Path,
) -> None:
    _write(
        tmp_path / ".iam-jit.yaml",
        "iam-jit:\n  enabled: yes-please\n",  # not a boolean
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "doctor",
            "apply-config",
            "--cwd",
            str(tmp_path),
            "--inspect",
            "--json",
        ],
    )
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["status"] == "error"
    assert payload["code"] == "schema_validation_error"


def test_doctor_apply_config_no_declaration_found(
    tmp_path: pathlib.Path,
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "doctor",
            "apply-config",
            "--cwd",
            str(tmp_path),
            "--dry-run",
            "--json",
        ],
    )
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["code"] == "no_declaration_found"


def test_doctor_apply_config_explicit_config_path(
    tmp_path: pathlib.Path,
) -> None:
    """--config PATH overrides auto-discovery."""
    p = tmp_path / "subdir" / "my.iam-jit.yaml"
    _write(p, "iam-jit:\n  enabled: true\n")
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "doctor",
            "apply-config",
            "--config",
            str(p),
            "--inspect",
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "ok"


def test_doctor_apply_config_human_renderer(tmp_path: pathlib.Path) -> None:
    """Human renderer (no --json) prints a recognizable banner."""
    _write(
        tmp_path / ".iam-jit.yaml",
        "iam-jit:\n  enabled: true\n  bouncers:\n    ibounce: {enabled: true}\n",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "doctor",
            "apply-config",
            "--cwd",
            str(tmp_path),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "DRY-RUN PLAN" in result.output
    assert "ibounce" in result.output
    assert "AWS_ENDPOINT_URL" in result.output


def test_doctor_apply_config_disabled_master_switch(
    tmp_path: pathlib.Path,
) -> None:
    _write(tmp_path / ".iam-jit.yaml", "iam-jit:\n  enabled: false\n")
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "doctor",
            "apply-config",
            "--cwd",
            str(tmp_path),
            "--dry-run",
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "disabled"


def test_doctor_apply_config_reads_codeblock_from_md(
    tmp_path: pathlib.Path,
) -> None:
    _write(
        tmp_path / "CLAUDE.md",
        """# Notes

```iam-jit-config
iam-jit:
  enabled: true
  bouncers:
    ibounce: {enabled: true}
```
""",
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "doctor",
            "apply-config",
            "--cwd",
            str(tmp_path),
            "--inspect",
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert "CLAUDE.md" in payload["source"]
