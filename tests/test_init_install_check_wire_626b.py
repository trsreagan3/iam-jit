"""State-verification tests for #626 Phase 2 — `iam-jit init` /
`init-solo` / `serve --local` wire `doctor install-check` at end-of-
bootstrap so operators see install gaps immediately.

Per founder dogfood 2026-05-26: pre-fix, init succeeded silently while
the install was actually broken. The fix surfaces the install-check
verdict (condensed FAIL/WARN rows + paste-ready fixes) at end-of-init
so the operator's first chance to see green-or-not is right there.

Tests cover:
  1. `init --non-interactive` runs install-check at the end + surfaces
     FAIL rows for an unconfigured machine.
  2. `init --no-doctor-check` suppresses the install-check pass.
  3. `init-solo` runs install-check at the end (parity).
  4. `init-solo --no-doctor-check` suppresses it.
  5. install-check verdict does NOT change init's exit code (init still
     succeeds; doctor is informational post-write).
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
from click.testing import CliRunner

from iam_jit.cli import main


@pytest.fixture(autouse=True)
def _pinned_home(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    home = tmp_path / "fake-home"
    home.mkdir()
    data_dir = home / ".iam-jit"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(data_dir))
    return data_dir


@pytest.fixture(autouse=True)
def _no_boto3(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a, **k):  # noqa: ANN001, ARG001
        raise RuntimeError("no aws creds in tests")
    monkeypatch.setattr("boto3.client", _boom)


@pytest.fixture(autouse=True)
def _no_bouncers_running(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force loopback probes to always return False so install-check
    sees a stopped-bouncer machine — predictable test signal."""
    monkeypatch.setattr(
        "iam_jit.posture.bouncers._loopback_port_open",
        lambda *a, **kw: False,
    )


@pytest.fixture(autouse=True)
def _cleared_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "AWS_ENDPOINT_URL", "KUBECONFIG", "PGHOST", "PGPORT",
        "HTTP_PROXY", "HTTPS_PROXY",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _empty_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop PATH so install-check sees the missing-binary case."""
    monkeypatch.setenv("PATH", "/this/does/not/exist")


# ---------------------------------------------------------------------------
# Test 1 — `init` runs install-check at end by default
# ---------------------------------------------------------------------------


def test_init_runs_install_check_at_end(
    _pinned_home: pathlib.Path, tmp_path: pathlib.Path,
) -> None:
    """After init's standard summary block, the condensed install-check
    verdict appears + names the FAIL rows."""
    data_dir = tmp_path / "iam-jit"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["init", "--non-interactive", "--data-dir", str(data_dir)],
        catch_exceptions=False,
    )
    # init itself succeeded (config-write).
    assert result.exit_code == 0, result.output
    config_path = data_dir / "iam-jit.yaml"
    assert config_path.exists()

    # install-check verdict block follows the standard summary.
    assert "install-check:" in result.output
    # FAIL rows for missing binaries are surfaced.
    assert "iam-jit NOT on PATH" in result.output
    assert "FAIL row(s)" in result.output
    # Operator pointed at the full report.
    assert "iam-jit doctor install-check" in result.output


# ---------------------------------------------------------------------------
# Test 2 — `init --no-doctor-check` suppresses install-check
# ---------------------------------------------------------------------------


def test_init_no_doctor_check_suppresses_install_check(
    tmp_path: pathlib.Path,
) -> None:
    data_dir = tmp_path / "iam-jit"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "init", "--non-interactive", "--no-doctor-check",
            "--data-dir", str(data_dir),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    # install-check section is absent.
    assert "install-check:" not in result.output


# ---------------------------------------------------------------------------
# Test 3 — `init-solo` runs install-check at end
# ---------------------------------------------------------------------------


def test_init_solo_runs_install_check_at_end(
    tmp_path: pathlib.Path,
) -> None:
    data_dir = tmp_path / "iam-jit-solo"
    runner = CliRunner()
    result = runner.invoke(
        main,
        # --account-id bypasses boto3 STS which is mocked out in _no_boto3.
        # Without it, init-solo exits 2 on "no aws creds" before ever
        # reaching the install-check block (#698 MED-1 strict resolution).
        ["init-solo", "--data-dir", str(data_dir), "--account-id", "123456789012"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    # install-check verdict follows init-solo's "Next steps".
    assert "install-check:" in result.output
    assert "iam-jit NOT on PATH" in result.output


# ---------------------------------------------------------------------------
# Test 4 — `init-solo --no-doctor-check` suppresses install-check
# ---------------------------------------------------------------------------


def test_init_solo_no_doctor_check_suppresses_install_check(
    tmp_path: pathlib.Path,
) -> None:
    data_dir = tmp_path / "iam-jit-solo"
    runner = CliRunner()
    result = runner.invoke(
        main,
        # --account-id bypasses boto3 STS which is mocked out in _no_boto3.
        ["init-solo", "--no-doctor-check", "--data-dir", str(data_dir),
         "--account-id", "123456789012"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "install-check:" not in result.output


# ---------------------------------------------------------------------------
# Test 5 — install-check does NOT change init's exit code
# ---------------------------------------------------------------------------


def test_install_check_failure_does_not_fail_init(
    tmp_path: pathlib.Path,
) -> None:
    """Even with a maximally-broken install (PATH empty, no bouncers,
    no env wiring), init returns 0 because the config-write succeeded.
    Per [[ibounce-honest-positioning]] we NAME the gap but don't lie
    about whether init's narrow contract was satisfied."""
    data_dir = tmp_path / "iam-jit"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["init", "--non-interactive", "--data-dir", str(data_dir)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    # But the install-check verdict surfaces FAIL.
    assert "FAIL row(s)" in result.output


# ---------------------------------------------------------------------------
# Test 6 — install-check failure inside the probe degrades silently
# ---------------------------------------------------------------------------


def test_install_check_internal_failure_does_not_break_init(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If `run_install_check` itself raises (e.g. an unexpected
    import-time error after a partial install), init still completes
    + reports config-write success per the best-effort contract."""
    def _boom(*a, **k):  # noqa: ANN001, ARG001
        raise RuntimeError("synthesized failure")
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.run_install_check", _boom,
    )
    data_dir = tmp_path / "iam-jit"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["init", "--non-interactive", "--data-dir", str(data_dir)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    # No crash; install-check block absent (best-effort fail-soft).
    assert "FAIL row(s)" not in result.output
