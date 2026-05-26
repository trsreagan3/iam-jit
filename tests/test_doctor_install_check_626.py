"""State-verification tests for #626 — `iam-jit doctor install-check`.

Per founder dogfood 2026-05-26: install story broken at multiple
layers (PATH gap, Go-install gap, AWS_ENDPOINT_URL never wired,
dev-venv shadowing the production console-script).

Per [[tests-and-independent-uat-required]] every feature ships with
tests + an independent UAT pass. Per CONTRIBUTING.md every reported
success status MUST also assert observable state.

Tests cover the spec sections:

  1. All-green machine -> exit 0 + every section reports OK.
  2. Missing PATH entries -> exit 2 + FAIL rows + remediation hints.
  3. Stopped bouncers -> running-bouncer rows downgrade to INFO; other
     sections still run.
  4. Routing self-test fails when AWS_ENDPOINT_URL not set -> exit 2
     + a clear hint pointing at shellinit.
  5. ``--no-routing-test`` honored.
  6. ``--json`` output is well-formed + carries the same severity roll-up
     as the human render.
  7. SABOTAGE — monkeypatch ``_check_path`` so it always rows OK without
     consulting ``shutil.which``. Then assert that the no-binary case
     (which should fail) now WRONGLY passes — proves the
     real ``shutil.which``-driven probe is load-bearing.
"""

from __future__ import annotations

import json
import pathlib
import shutil
from typing import Any

import pytest
from click.testing import CliRunner

from iam_jit import cli_doctor_install_check as dic
from iam_jit.cli import main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _pinned_home(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    """Pin HOME + IAM_JIT_DATA_DIR to tmp_path so the tests can't see
    the operator's real ~/.iam-jit + can't pollute it."""
    home = tmp_path / "fake-home"
    home.mkdir()
    data_dir = home / ".iam-jit"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(data_dir))
    return data_dir


@pytest.fixture
def empty_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop PATH to a single empty tmpdir so no binaries resolve."""
    monkeypatch.setenv("PATH", "/this/does/not/exist")


@pytest.fixture
def stub_all_binaries(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    """Drop a fake bin dir on PATH with stub scripts for every binary
    iam-jit's install-check probes. The stubs each print a plausible
    version string so section 2 passes too."""
    bindir = tmp_path / "fake-bin"
    bindir.mkdir()
    for name in ("iam-jit", "ibounce", "kbounce", "dbounce", "gbounce"):
        p = bindir / name
        p.write_text(
            "#!/bin/sh\n"
            f'echo "{name} 1.0.0-stub"\n',
        )
        p.chmod(0o755)
    monkeypatch.setenv(
        "PATH",
        f"{bindir}:{__import__('os').environ.get('PATH', '')}",
    )
    return bindir


@pytest.fixture
def cleared_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove the env vars that posture.capture_posture decodes so the
    routing self-test sees a clean slate."""
    for var in (
        "AWS_ENDPOINT_URL", "KUBECONFIG", "PGHOST", "PGPORT",
        "HTTP_PROXY", "HTTPS_PROXY",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def _no_bouncers_running(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the loopback-port probe to always return False so the
    test isn't a flake based on whatever the host has running."""
    monkeypatch.setattr(
        "iam_jit.posture.bouncers._loopback_port_open",
        lambda *a, **kw: False,
    )


def _invoke(*extra: str) -> Any:
    runner = CliRunner()
    return runner.invoke(
        main, ["doctor", "install-check", *extra],
        catch_exceptions=False,
    )


# ---------------------------------------------------------------------------
# Test 1 — all-green machine
# ---------------------------------------------------------------------------


def test_all_green_machine_exits_zero(
    stub_all_binaries: pathlib.Path,
    cleared_env: None,
    _pinned_home: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When every binary is on PATH, ibounce is "running", and
    AWS_ENDPOINT_URL is wired, install-check exits 0 + every section
    is OK or INFO. We synthesize the running-bouncer state by faking
    the loopback probe + the AWS env var."""
    # Pretend the ibounce default port is open.
    def _open_only_8767(port: int, host: str = "127.0.0.1", **kw: Any) -> bool:
        return port == 8767
    monkeypatch.setattr(
        "iam_jit.posture.bouncers._loopback_port_open", _open_only_8767,
    )
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:8767")
    # Seed the data dir + config files so section 6/7 pass.
    _pinned_home.mkdir(parents=True, exist_ok=True)
    (_pinned_home / "accounts.yaml").write_text("accounts: []\n")
    (_pinned_home / "users.yaml").write_text("users: []\n")

    result = _invoke()
    assert result.exit_code == 0, (
        f"expected exit 0 (all-green) but got {result.exit_code}\n"
        f"--- output ---\n{result.output}"
    )
    # Every section heading is present.
    for n in range(1, 9):
        assert f"[{n}/8]" in result.output
    # Spot-checks: PATH section shows OK rows, env wiring shows OK row.
    assert "[OK] iam-jit on PATH" in result.output
    assert "[OK] ibounce env wire OK" in result.output


# ---------------------------------------------------------------------------
# Test 2 — missing PATH entries on a bare machine
# ---------------------------------------------------------------------------


def test_missing_path_entries_exit_2_with_remediation(
    empty_path: None,
    cleared_env: None,
    _no_bouncers_running: None,
) -> None:
    """Founder's case: no iam-jit / no ibounce / no Go bouncers. The
    Python-side binaries must fail HARD; the Go-side must WARN. Every
    failure row carries a paste-ready Fix hint."""
    result = _invoke()
    assert result.exit_code == 2, (
        f"expected exit 2 (errors) but got {result.exit_code}\n"
        f"--- output ---\n{result.output}"
    )
    # Required Python binaries failed.
    assert "[FAIL] iam-jit NOT on PATH" in result.output
    assert "[FAIL] ibounce NOT on PATH" in result.output
    # Remediation present + concrete.
    assert "pip install --user iam-jit" in result.output
    # Go bouncers warned, not failed.
    assert "[WARN] kbounce NOT on PATH" in result.output
    assert "go install github.com/trsreagan3/kbouncer@latest" in result.output
    # Overall verdict surfaces NOT PROTECTING.
    assert "Overall: NOT PROTECTING" in result.output


# ---------------------------------------------------------------------------
# Test 3 — stopped bouncers degrade gracefully
# ---------------------------------------------------------------------------


def test_stopped_bouncers_degrade_to_info(
    stub_all_binaries: pathlib.Path,
    cleared_env: None,
    _no_bouncers_running: None,
    _pinned_home: pathlib.Path,
) -> None:
    """With every binary on PATH but no bouncer actually listening,
    section 3 issues an ERROR row (no bouncers running) + section 4
    skips wire-check + section 5 fails routing test. Section 1/2 stay
    OK because binaries ARE installed."""
    result = _invoke()
    # Section 1 + 2 still pass.
    assert "[OK] iam-jit on PATH" in result.output
    assert "[OK] iam-jit version" in result.output
    # Section 3 surfaces the no-bouncers ERROR.
    assert "no bouncers running" in result.output
    # Section 4 skipped (no running bouncers to wire).
    assert "env-var wiring" in result.output
    assert "[--] env-var wiring" in result.output
    # Section 5 fails routing test (no AWS_ENDPOINT_URL + no bouncer).
    assert "AWS_ENDPOINT_URL not set" in result.output
    # Overall verdict reflects errors.
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Test 4 — routing self-test FAIL with concrete hint
# ---------------------------------------------------------------------------


def test_routing_self_test_failure_points_at_shellinit(
    stub_all_binaries: pathlib.Path,
    cleared_env: None,
    monkeypatch: pytest.MonkeyPatch,
    _pinned_home: pathlib.Path,
) -> None:
    """The founder's exact failure mode: ibounce running on :8767 but
    AWS_ENDPOINT_URL not set. install-check must point them at
    shellinit (or a paste-ready export)."""
    def _open_only_8767(port: int, host: str = "127.0.0.1", **kw: Any) -> bool:
        return port == 8767
    monkeypatch.setattr(
        "iam_jit.posture.bouncers._loopback_port_open", _open_only_8767,
    )
    # AWS_ENDPOINT_URL deliberately NOT set.

    result = _invoke()
    assert result.exit_code == 2
    # Section 4: ibounce running but unwired.
    assert "ibounce running but NOT wired" in result.output
    # Section 5: routing self-test failed + points at shellinit.
    assert "routing self-test FAILED" in result.output
    assert "shellinit" in result.output


# ---------------------------------------------------------------------------
# Test 5 — --no-routing-test honored
# ---------------------------------------------------------------------------


def test_no_routing_test_flag_skips_section_5(
    empty_path: None, cleared_env: None, _no_bouncers_running: None,
) -> None:
    result = _invoke("--no-routing-test")
    assert "routing self-test SKIPPED" in result.output
    # Sections 1+ still ran.
    assert "[1/8] PATH check" in result.output
    assert "[5/8] Routing self-test" in result.output


# ---------------------------------------------------------------------------
# Test 6 — --json output well-formed + matches human verdict
# ---------------------------------------------------------------------------


def test_json_output_matches_exit_code(
    empty_path: None, cleared_env: None, _no_bouncers_running: None,
) -> None:
    result = _invoke("--json")
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1.0"
    assert payload["overall_severity"] == "FAIL"
    assert payload["exit_code"] == 2
    sections = payload["sections"]
    assert len(sections) == 8
    # Section 1 has rows + at least one is FAIL.
    s1 = sections[0]
    assert s1["title"] == "PATH check"
    assert any(r["severity"] == "FAIL" for r in s1["rows"])
    # Every section carries its title + number.
    titles = [s["title"] for s in sections]
    assert titles == [
        "PATH check",
        "Binary versions",
        "Running bouncer detection",
        "Env-var wiring",
        "Routing self-test",
        "Config files",
        "Audit log writability",
        "Posture summary",
    ]


# ---------------------------------------------------------------------------
# Test 7 — SABOTAGE: prove _check_path is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_check_path_proves_probe_is_load_bearing(
    empty_path: None, cleared_env: None, _no_bouncers_running: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If we monkeypatch _check_path to always row OK, the test 2
    machine-shape (no binaries) suddenly passes section 1. This proves
    the real shutil.which-driven probe IS load-bearing per
    CONTRIBUTING.md anti-theater guidance.

    Caught failure mode: a future refactor that loses the
    `shutil.which` call would silently pass install-check even when
    nothing is installed.
    """
    def _fake_check_path(section: dic._Section) -> None:
        section.add(label="iam-jit on PATH", severity=dic._SEV_OK)
    monkeypatch.setattr(dic, "_check_path", _fake_check_path)

    result = _invoke()
    # Without the real probe, section 1 no longer fails.
    assert "[FAIL] iam-jit NOT on PATH" not in result.output
    # Sections 3-5 still surface ERRORs (no running bouncer + no env
    # wire), so overall exit still 2 — that's expected. The
    # narrow assertion: section 1 itself stopped failing.
    s1_marker = "[1/8] PATH check"
    s2_marker = "[2/8]"
    s1_chunk = result.output.split(s1_marker, 1)[1].split(s2_marker, 1)[0]
    assert "[FAIL]" not in s1_chunk, (
        "sabotaged _check_path should suppress section-1 FAILs; "
        "if this assertion fires, the test-2 shape is reaching a "
        "different code path and the load-bearing claim is unproven."
    )
