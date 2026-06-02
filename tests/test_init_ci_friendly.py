"""#744 — CI-friendly `iam-jit init` flags: --quiet, --format json,
structured stderr, exit-code discipline.

Per [[uat-tests-setup-end-to-end]]: every exit code has a test;
--quiet --non-interactive --format json works in a true non-TTY
context; JSON output is machine-parsable.

Exit-code contract (#744):
  0  = success
  2  = invalid args
  10 = config conflict (existing setup; use --overwrite)
  11 = bouncer-start failure  (reserved; see docs)
  12 = harness write failure  (reserved; see docs)
  13 = network/install failure (managed-mode fetch failures)

Per [[tests-and-independent-uat-required]]: independent from the
implementer; state-verified (asserts observable file content / JSON
output, not just exit codes).
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest
from click.testing import CliRunner

from iam_jit import cli_init
from iam_jit.cli_init import (
    EXIT_CONFLICT,
    EXIT_HARNESS_FAIL,  # noqa: F401 — imported to prove it's exported
    EXIT_INVALID_ARGS,
    EXIT_NETWORK_FAIL,
    EXIT_OK,
    _ConfigConflictError,
    _build_json_result,
    _emit_json_error,
)
from iam_jit.cli import main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_boto3(monkeypatch: pytest.MonkeyPatch) -> None:
    """Block boto3 STS calls — no real AWS creds needed in unit tests."""
    def _boom(*a, **k):  # noqa: ANN001, ARG001
        raise RuntimeError("no aws in tests")
    monkeypatch.setattr("boto3.client", _boom)


@pytest.fixture(autouse=True)
def _isolated_home(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin HOME so harness-detection + data-dir defaults stay in tmp."""
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))


@pytest.fixture
def data_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """Fresh per-test data dir."""
    return tmp_path / "iam-jit-data"


def _runner() -> CliRunner:
    # Click 8.x CliRunner does not support mix_stderr — stderr is mixed
    # into output by default; tests that need stderr use result.output.
    return CliRunner()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _run(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    input: str | None = None,  # noqa: A002
) -> tuple[int, str, str]:
    """Invoke the init command and return (exit_code, output, output).

    Click 8.x mixes stderr into output; we return output twice so call
    sites that capture stderr get consistent results — the combined
    output is the right place to search for both banners and JSON errors.
    """
    runner = _runner()
    result = runner.invoke(
        main,
        args,
        env=env,
        input=input,
        catch_exceptions=False,
    )
    return result.exit_code, result.output, result.output


# ---------------------------------------------------------------------------
# EXIT_OK = 0
# ---------------------------------------------------------------------------


def test_exit_0_success_non_interactive(
    data_dir: pathlib.Path,
) -> None:
    """Happy-path non-interactive returns 0; config file written."""
    code, stdout, _ = _run([
        "init",
        "--non-interactive",
        "--data-dir", str(data_dir),
        "--harness", "none",
        "--skip-mcp-install",
        "--no-doctor-check",
    ])
    assert code == EXIT_OK, f"expected 0, got {code}\nstdout={stdout}"
    cfg = data_dir / "iam-jit.yaml"
    assert cfg.exists(), "config file must exist after successful init"


def test_exit_0_quiet_suppresses_banners(data_dir: pathlib.Path) -> None:
    """--quiet + success: no human banners on stdout; exit 0."""
    code, stdout, stderr = _run([
        "init",
        "--non-interactive",
        "--quiet",
        "--data-dir", str(data_dir),
        "--harness", "none",
        "--skip-mcp-install",
        "--no-doctor-check",
    ])
    assert code == EXIT_OK, f"expected 0, got {code}\nstdout={stdout}"
    # Quiet mode must suppress the "[ok] wrote" banner.
    assert "[ok]" not in stdout
    assert "iam-jit init: summary" not in stdout
    # Config still gets written.
    assert (data_dir / "iam-jit.yaml").exists()


def test_exit_0_format_json_emits_envelope(data_dir: pathlib.Path) -> None:
    """--format json emits a valid JSON envelope to stdout on success."""
    code, stdout, _ = _run([
        "init",
        "--non-interactive",
        "--format", "json",
        "--data-dir", str(data_dir),
        "--harness", "none",
        "--skip-mcp-install",
        "--no-doctor-check",
    ])
    assert code == EXIT_OK, f"expected 0, got {code}\nstdout={stdout}"
    # Last line of stdout must be the JSON envelope.
    lines = [l for l in stdout.splitlines() if l.strip()]
    json_line = lines[-1]
    payload = json.loads(json_line)
    assert payload["status"] == "ok"
    assert "version" in payload
    assert "harness" in payload
    assert "bouncers_started" in payload
    assert "config_path" in payload
    assert "env_vars_set" in payload
    assert "warnings" in payload
    assert "errors" in payload


def test_exit_0_quiet_format_json_combo(data_dir: pathlib.Path) -> None:
    """--quiet + --format json: no human text; clean JSON on stdout."""
    code, stdout, stderr = _run([
        "init",
        "--non-interactive",
        "--quiet",
        "--format", "json",
        "--data-dir", str(data_dir),
        "--harness", "none",
        "--skip-mcp-install",
        "--no-doctor-check",
    ])
    assert code == EXIT_OK, f"expected 0, got {code}"
    # stdout should be just the JSON line (no banners).
    assert "[ok]" not in stdout
    lines = [l for l in stdout.splitlines() if l.strip()]
    assert lines, "stdout must not be empty — JSON envelope required"
    payload = json.loads(lines[-1])
    assert payload["status"] == "ok"


def test_exit_0_env_var_quiet(data_dir: pathlib.Path) -> None:
    """IAM_JIT_INIT_QUIET=1 is honored as alternative to --quiet."""
    code, stdout, _ = _run(
        [
            "init",
            "--non-interactive",
            "--data-dir", str(data_dir),
            "--harness", "none",
            "--skip-mcp-install",
            "--no-doctor-check",
        ],
        env={"IAM_JIT_INIT_QUIET": "1"},
    )
    assert code == EXIT_OK, f"expected 0, got {code}"
    assert "[ok]" not in stdout
    assert "iam-jit init: summary" not in stdout


def test_exit_0_env_var_format_json(data_dir: pathlib.Path) -> None:
    """IAM_JIT_INIT_FORMAT=json is honored as alternative to --format json."""
    code, stdout, _ = _run(
        [
            "init",
            "--non-interactive",
            "--data-dir", str(data_dir),
            "--harness", "none",
            "--skip-mcp-install",
            "--no-doctor-check",
        ],
        env={"IAM_JIT_INIT_FORMAT": "json"},
    )
    assert code == EXIT_OK, f"expected 0, got {code}"
    lines = [l for l in stdout.splitlines() if l.strip()]
    payload = json.loads(lines[-1])
    assert payload["status"] == "ok"


# ---------------------------------------------------------------------------
# EXIT_INVALID_ARGS = 2
# ---------------------------------------------------------------------------


def test_exit_2_invalid_args_via_click() -> None:
    """Passing an unknown flag exits 2 (Click's conventional bad-arg code)."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["init", "--unknown-flag-that-does-not-exist"],
        catch_exceptions=False,
    )
    assert result.exit_code == EXIT_INVALID_ARGS, (
        f"expected 2, got {result.exit_code}"
    )


def test_exit_2_invalid_bouncers_json_mode(data_dir: pathlib.Path) -> None:
    """--format json + invalid --bouncers emits JSON error to stderr, exits 2."""
    runner = _runner()
    result = runner.invoke(
        main,
        [
            "init",
            "--non-interactive",
            "--format", "json",
            "--data-dir", str(data_dir),
            "--bouncers", "not-a-real-bouncer",
            "--harness", "none",
            "--no-doctor-check",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == EXIT_INVALID_ARGS, (
        f"expected 2, got {result.exit_code}"
    )
    # stderr must carry structured JSON error.
    stderr_text = result.stderr if hasattr(result, "stderr") and result.stderr else result.output
    # Try to find JSON in stderr or output.
    found_json = False
    for candidate in [
        getattr(result, "stderr", None) or "",
        result.output or "",
    ]:
        for line in candidate.splitlines():
            if line.strip().startswith("{"):
                try:
                    payload = json.loads(line)
                    if payload.get("status") == "error":
                        found_json = True
                        assert "error_code" in payload
                        break
                except json.JSONDecodeError:
                    pass
        if found_json:
            break
    assert found_json, (
        f"Expected JSON error in stderr/output. output={result.output!r}"
    )


# ---------------------------------------------------------------------------
# EXIT_CONFLICT = 10
# ---------------------------------------------------------------------------


def test_exit_10_config_conflict(data_dir: pathlib.Path) -> None:
    """Pre-existing config without --overwrite exits 10."""
    # First run succeeds.
    code, _, _ = _run([
        "init",
        "--non-interactive",
        "--data-dir", str(data_dir),
        "--harness", "none",
        "--skip-mcp-install",
        "--no-doctor-check",
    ])
    assert code == EXIT_OK

    # Second run hits the conflict; exit 10.
    code2, stdout2, stderr2 = _run([
        "init",
        "--non-interactive",
        "--data-dir", str(data_dir),
        "--harness", "none",
        "--skip-mcp-install",
        "--no-doctor-check",
    ])
    assert code2 == EXIT_CONFLICT, (
        f"expected 10, got {code2}\nstdout={stdout2}\nstderr={stderr2}"
    )
    # The conflict path always emits JSON to stderr (quiet-mode behaviour).
    found_json = False
    combined = (stderr2 or "") + (stdout2 or "")
    for line in combined.splitlines():
        if line.strip().startswith("{"):
            try:
                payload = json.loads(line)
                if payload.get("error_code") == "INIT_CONFIG_CONFLICT":
                    found_json = True
            except json.JSONDecodeError:
                pass
    assert found_json, (
        "Expected INIT_CONFIG_CONFLICT JSON error in output. "
        f"stdout={stdout2!r}, stderr={stderr2!r}"
    )


def test_exit_0_overwrite_resolves_conflict(data_dir: pathlib.Path) -> None:
    """--overwrite resolves the conflict; second run exits 0."""
    # First run.
    _run([
        "init", "--non-interactive",
        "--data-dir", str(data_dir),
        "--harness", "none",
        "--skip-mcp-install", "--no-doctor-check",
    ])
    # Second run with --overwrite.
    code, _, _ = _run([
        "init", "--non-interactive", "--overwrite",
        "--data-dir", str(data_dir),
        "--harness", "none",
        "--skip-mcp-install", "--no-doctor-check",
    ])
    assert code == EXIT_OK


def test_exit_10_conflict_json_mode(data_dir: pathlib.Path) -> None:
    """--format json on conflict: exit 10."""
    _run([
        "init", "--non-interactive",
        "--data-dir", str(data_dir),
        "--harness", "none",
        "--skip-mcp-install", "--no-doctor-check",
    ])
    result_code, _, _ = _run([
        "init", "--non-interactive", "--format", "json",
        "--data-dir", str(data_dir),
        "--harness", "none",
        "--skip-mcp-install", "--no-doctor-check",
    ])
    assert result_code == EXIT_CONFLICT


# ---------------------------------------------------------------------------
# EXIT_NETWORK_FAIL = 13
# ---------------------------------------------------------------------------


def test_exit_13_managed_missing_org_policy_flag(
    data_dir: pathlib.Path,
) -> None:
    """--managed without --org-policy exits 2 (invalid-args gate)."""
    code, _, _ = _run([
        "init",
        "--managed",
        "--non-interactive",
        "--data-dir", str(data_dir),
        "--no-doctor-check",
    ])
    # Missing --org-policy is an arg validation failure → exit 2.
    assert code == EXIT_INVALID_ARGS, f"expected 2, got {code}"


def test_exit_13_managed_network_fail(
    data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--managed with bad org-policy URL exits 13 via SSRF gate + JSON error."""
    import iam_jit.cli_init as _mod

    def _boom_fetch(*a, **k):  # noqa: ANN001, ARG001
        from iam_jit.cli_init import ManagedPolicyError
        raise ManagedPolicyError("simulated network failure")

    monkeypatch.setattr(_mod, "_fetch_managed_policy", _boom_fetch)

    code, output, _ = _run([
        "init",
        "--managed",
        "--non-interactive",
        "--quiet",
        "--format", "json",
        "--data-dir", str(data_dir),
        "--org-policy", "https://example.com/fake-policy.yaml",
        "--no-doctor-check",
    ])
    assert code == EXIT_NETWORK_FAIL, (
        f"expected 13, got {code}\noutput={output!r}"
    )
    # output (which contains stderr in Click 8.x) must carry JSON.
    found_json = False
    for line in output.splitlines():
        if line.strip().startswith("{"):
            try:
                payload = json.loads(line)
                if payload.get("status") == "error":
                    found_json = True
            except json.JSONDecodeError:
                pass
    assert found_json, (
        "Expected JSON error in output. "
        f"output={output!r}"
    )


# ---------------------------------------------------------------------------
# _emit_json_error unit tests (validates the helper directly)
# ---------------------------------------------------------------------------


def test_emit_json_error_exits_with_code(capsys: pytest.CaptureFixture) -> None:
    """_emit_json_error writes JSON to stderr and calls sys.exit."""
    with pytest.raises(SystemExit) as exc_info:
        _emit_json_error(
            code="TEST_ERROR",
            message="test message",
            exit_code=EXIT_CONFLICT,
        )
    assert exc_info.value.code == EXIT_CONFLICT
    captured = capsys.readouterr()
    payload = json.loads(captured.err)
    assert payload["status"] == "error"
    assert payload["error_code"] == "TEST_ERROR"
    assert payload["message"] == "test message"


def test_emit_json_error_includes_context(capsys: pytest.CaptureFixture) -> None:
    """_emit_json_error includes extra context fields."""
    with pytest.raises(SystemExit):
        _emit_json_error(
            code="CTX_TEST",
            message="msg",
            exit_code=EXIT_INVALID_ARGS,
            context={"config_path": "/tmp/x.yaml"},
        )
    captured = capsys.readouterr()
    payload = json.loads(captured.err)
    assert payload["config_path"] == "/tmp/x.yaml"


# ---------------------------------------------------------------------------
# _build_json_result unit tests
# ---------------------------------------------------------------------------


def test_build_json_result_structure(tmp_path: pathlib.Path) -> None:
    """_build_json_result returns the expected schema."""
    from iam_jit.cli_init import _InterviewResult

    iresult = _InterviewResult(
        shape="local-solo",
        mode="discovery",
        bouncers=("ibounce",),
        harness="claude-code",
        accounts_detected=(),
        data_dir=tmp_path,
    )
    payload = _build_json_result(
        result=iresult,
        config_path=tmp_path / "iam-jit.yaml",
        bouncers_started=["ibounce"],
        env_vars_set={"AWS_ENDPOINT_URL": "http://localhost:8767"},
        warnings=["warn1"],
    )
    assert payload["status"] == "ok"
    assert payload["harness"] == "claude-code"
    assert payload["bouncers_started"] == ["ibounce"]
    assert "AWS_ENDPOINT_URL" in payload["env_vars_set"]
    assert payload["warnings"] == ["warn1"]
    assert payload["errors"] == []
    assert "version" in payload
    assert "config_path" in payload


def test_build_json_result_none_result(tmp_path: pathlib.Path) -> None:
    """_build_json_result with result=None (managed mode) uses 'none' harness."""
    payload = _build_json_result(result=None, config_path=tmp_path / "p.yaml")
    assert payload["status"] == "ok"
    assert payload["harness"] == "none"


# ---------------------------------------------------------------------------
# Exit-code constants are exported
# ---------------------------------------------------------------------------


def test_exit_code_constants_values() -> None:
    """Exit codes have the documented values."""
    assert cli_init.EXIT_OK == 0
    assert cli_init.EXIT_INVALID_ARGS == 2
    assert cli_init.EXIT_CONFLICT == 10
    assert cli_init.EXIT_BOUNCER_FAIL == 11
    assert cli_init.EXIT_HARNESS_FAIL == 12
    assert cli_init.EXIT_NETWORK_FAIL == 13


# ---------------------------------------------------------------------------
# Non-TTY context test (simulates CI without a PTY)
# ---------------------------------------------------------------------------


def test_non_tty_quiet_format_json(data_dir: pathlib.Path) -> None:
    """Full non-TTY path: --quiet --non-interactive --format json exits 0
    and emits clean JSON.  CliRunner does not allocate a PTY — this is
    the closest unit-level proxy for a CI container without /dev/tty."""
    code, stdout, stderr = _run([
        "init",
        "--non-interactive",
        "--quiet",
        "--format", "json",
        "--data-dir", str(data_dir),
        "--harness", "none",
        "--skip-mcp-install",
        "--no-doctor-check",
    ])
    assert code == EXIT_OK, f"expected 0, got {code}\nstdout={stdout}"
    lines = [l for l in stdout.splitlines() if l.strip()]
    assert lines, "must have JSON output on stdout"
    payload = json.loads(lines[-1])
    assert payload["status"] == "ok"
    # Config must be written (state-verification per CONTRIBUTING.md).
    assert (data_dir / "iam-jit.yaml").exists()
