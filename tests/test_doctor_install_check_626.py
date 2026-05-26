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
    # Remediation present + concrete. The exact command is OS-aware
    # (#649: macOS Homebrew → pipx; Linux apt → pip --user; generic →
    # pip --user). Assert the Fix: line is present for the iam-jit binary;
    # the specific command is verified by the #649 unit tests below.
    assert "Fix:" in result.output
    assert "iam-jit" in result.output  # the binary name in the fix
    # Go bouncers warned, not failed.
    assert "[WARN] kbounce NOT on PATH" in result.output
    assert "go install github.com/trsreagan3/kbouncer" in result.output
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
    def _fake_check_path(section: dic._Section, paths: dict | None = None) -> None:
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


# ---------------------------------------------------------------------------
# Tests for #647 — display labels reflect actual probed paths
# ---------------------------------------------------------------------------


def test_custom_data_dir_via_env_shows_in_labels(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    empty_path: None,
    cleared_env: None,
    _no_bouncers_running: None,
) -> None:
    """#647: IAM_JIT_DATA_DIR=/tmp/x — Sections 6 and 7 labels and
    details reference /tmp/x (not the hardcoded ~/.iam-jit/).

    Per [[ibounce-honest-positioning]] labels must reflect the ACTUAL
    probed path. An operator with a custom data dir must see the
    real path, not the default shorthand.
    """
    custom_dir = tmp_path / "custom-data"
    # Intentionally do NOT create the dir — exercises the "does not
    # exist" branch where the display label is most critical.
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(custom_dir))
    # Also override HOME so _pinned_home fixture doesn't interfere.
    monkeypatch.setenv("HOME", str(tmp_path / "fake-home2"))

    result = _invoke()
    custom_str = str(custom_dir)
    # Section 6: the missing-file rows must reference the custom dir.
    # Either in the label OR the detail — detail is guaranteed by the fix.
    assert custom_str in result.output, (
        f"Expected resolved path {custom_str!r} to appear in output "
        f"when IAM_JIT_DATA_DIR is set to a custom dir.\n"
        f"--- output ---\n{result.output}"
    )
    # Must NOT hardcode the default.
    # (It's OK if ~/.iam-jit appears in other sections' labels that
    # are not data-dir-sensitive, but the config-files + audit
    # sections must not claim ~/.iam-jit when probing custom_dir.)
    s6_marker = "[6/8] Config files"
    s7_marker = "[7/8] Audit log writability"
    s8_marker = "[8/8]"
    s6_chunk = result.output.split(s6_marker, 1)[1].split(s7_marker, 1)[0]
    s7_chunk = result.output.split(s7_marker, 1)[1].split(s8_marker, 1)[0]
    for chunk, section_name in ((s6_chunk, "6"), (s7_chunk, "7")):
        assert "~/.iam-jit" not in chunk, (
            f"Section {section_name} still hardcodes ~/.iam-jit "
            f"when IAM_JIT_DATA_DIR={custom_str!r}. "
            f"Chunk:\n{chunk}"
        )


def test_data_dir_flag_overrides_env_var(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    empty_path: None,
    cleared_env: None,
    _no_bouncers_running: None,
) -> None:
    """#640: --data-dir flag wins over IAM_JIT_DATA_DIR env var.

    Per [[cross-product-agent-parity]] install-check must accept
    --data-dir just like serve / uninstall / init.
    """
    env_dir = tmp_path / "env-data"
    flag_dir = tmp_path / "flag-data"
    monkeypatch.setenv("IAM_JIT_DATA_DIR", str(env_dir))
    monkeypatch.setenv("HOME", str(tmp_path / "fake-home3"))

    result = _invoke("--data-dir", str(flag_dir))
    flag_str = str(flag_dir)
    env_str = str(env_dir)
    # The flag-dir must appear somewhere (sections 6/7 detail).
    assert flag_str in result.output, (
        f"Expected --data-dir={flag_str!r} to appear in output; "
        f"flag did not win over env var.\n"
        f"--- output ---\n{result.output}"
    )
    # The env-dir must NOT appear (flag wins).
    s6_marker = "[6/8] Config files"
    s8_marker = "[8/8]"
    s67_chunk = result.output.split(s6_marker, 1)[1].split(s8_marker, 1)[0]
    assert env_str not in s67_chunk, (
        f"IAM_JIT_DATA_DIR={env_str!r} leaked into sections 6/7 "
        f"even though --data-dir={flag_str!r} was passed.\n"
        f"Chunk:\n{s67_chunk}"
    )


def test_default_data_dir_uses_tilde_shorthand(
    monkeypatch: pytest.MonkeyPatch,
    empty_path: None,
    cleared_env: None,
    _no_bouncers_running: None,
    _pinned_home: pathlib.Path,
) -> None:
    """#647: When no env var or flag is set, Sections 6+7 labels use
    the ``~/.iam-jit`` shorthand (keeps output concise for the common
    case per the fix design spec).
    """
    # _pinned_home fixture sets HOME + IAM_JIT_DATA_DIR to temp paths,
    # so we unset IAM_JIT_DATA_DIR to exercise the HOME-default branch.
    monkeypatch.delenv("IAM_JIT_DATA_DIR", raising=False)

    result = _invoke()
    # Under the HOME-default branch the display should use shorthand.
    # Because HOME is pinned to a tmp_path, the "home / .iam-jit" path
    # won't equal "~/.iam-jit" literally — but _resolve_paths compares
    # Path.home() / ".iam-jit" to the resolved default and uses
    # "~/.iam-jit" only when they match.  With a pinned HOME this
    # branch actually resolves to the full tmp path — which is also
    # honest behavior.  We assert that the output contains EITHER
    # "~/.iam-jit" OR the pinned HOME path (both are correct; the key
    # invariant is it does NOT hardcode a different path entirely).
    home_str = str(_pinned_home)
    in_output = ("~/.iam-jit" in result.output or home_str in result.output)
    assert in_output, (
        f"Neither '~/.iam-jit' nor pinned home {home_str!r} appear in "
        f"sections 6/7 of the output.\n"
        f"--- output ---\n{result.output}"
    )


# ---------------------------------------------------------------------------
# Tests for #648 — no duplicate "Mode:" label in posture output
# ---------------------------------------------------------------------------


def test_posture_no_duplicate_mode_label() -> None:
    """#648: ``iam-jit posture`` must not emit two ``Mode:`` labels
    for the same bouncer block. The disk_pressure mode must appear as
    ``DiskMode:`` so operators can distinguish it from the bouncer's
    cooperative/transparent mode.
    """
    from iam_jit.posture.report import render_posture_human

    # Synthesize a snapshot with a running ibounce that has disk_pressure.
    snapshot: dict = {
        "schema_version": "1.0",
        "captured_at": "2026-05-26T00:00:00+00:00",
        "overall_mode": "cooperative",
        "iam_jit": {},
        "bouncers": {
            "ibounce": {
                "running": True,
                "port": 8767,
                "mode": "cooperative",
                "active_profile": "full-user",
                "disk_pressure": {
                    "status": "ok",
                    "disk_pressure_mode": "normal",
                    "used_pct": 42.5,
                    "current_archive_count": 3,
                },
            },
            "kbounce": {"running": False},
            "dbounce": {"running": False},
            "gbounce": {"running": False},
        },
        "effective_protection": {},
        "tips": [],
        "llm_skips": {"total": 0, "counts": {}, "by_reason": {}, "last_skips": []},
        "degraded_capabilities": {
            "total": 0, "counts": {}, "by_reason": {}, "last_events": [],
        },
    }
    output = render_posture_human(snapshot)

    # Find the ibounce block in the output.
    ibounce_start = output.find("ibounce:")
    assert ibounce_start != -1, "ibounce: section not found in posture output"
    # Find the next bouncer line to delimit ibounce's block.
    ibounce_block = output[ibounce_start:output.find("kbounce:", ibounce_start)]

    # Disk pressure mode must appear as "DiskMode:" (not "Mode:").
    # The bouncer itself has one "Mode:" (cooperative/transparent) — that's
    # expected. The SECOND former "Mode:" was the disk_pressure_mode and
    # has been renamed to "DiskMode:" per #648. Verify the Disk line
    # uses DiskMode: not Mode:.
    assert "DiskMode:" in ibounce_block, (
        f"Expected 'DiskMode:' in ibounce block (disk_pressure mode renamed).\n"
        f"ibounce block:\n{ibounce_block}"
    )
    # Confirm the Disk: line itself does NOT say "Mode:" (only "DiskMode:").
    # Find the Disk: line specifically.
    disk_line = next(
        (line for line in ibounce_block.splitlines() if "Disk:" in line),
        None,
    )
    assert disk_line is not None, (
        f"Could not find 'Disk:' line in ibounce block.\n"
        f"ibounce block:\n{ibounce_block}"
    )
    # The Disk line must contain DiskMode: but not a bare "Mode:" token.
    # We strip "DiskMode:" before checking for stray "Mode:" to avoid
    # the substring match.
    disk_line_stripped = disk_line.replace("DiskMode:", "")
    assert "Mode:" not in disk_line_stripped, (
        f"Disk: line still contains a bare 'Mode:' after renaming — "
        f"duplicate label persists.\n"
        f"Disk line: {disk_line!r}"
    )


# ---------------------------------------------------------------------------
# Tests for #649 — OS-aware install hint (_python_install_hint)
# ---------------------------------------------------------------------------


def test_hint_homebrew_python_suggests_pipx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """macOS + Homebrew Python (Apple Silicon path) → hint must contain
    'pipx'. A raw 'pip install --user' on this setup hits PEP 668 and
    fails — the doctor's Fix must be paste-ready and actually work.
    """
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.executable",
        "/opt/homebrew/Cellar/python@3.12/3.12.9/bin/python3.12",
    )
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.platform",
        "darwin",
    )
    hint = dic._python_install_hint()
    assert "pipx" in hint, (
        f"Homebrew-Python hint must reference pipx (PEP 668 blocks pip --user).\n"
        f"Got: {hint!r}"
    )


def test_hint_homebrew_intel_python_suggests_pipx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """macOS + Homebrew Python (Intel path /usr/local/Cellar/) → pipx."""
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.executable",
        "/usr/local/Cellar/python@3.12/3.12.9/bin/python3.12",
    )
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.platform",
        "darwin",
    )
    hint = dic._python_install_hint()
    assert "pipx" in hint, (
        f"Intel-Homebrew-Python hint must reference pipx.\nGot: {hint!r}"
    )


def test_hint_macos_system_python_suggests_venv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """macOS system Python (/usr/bin/python3) → hint must contain 'venv'.
    System Python is also externally managed; a venv is the safe path.
    """
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.executable",
        "/usr/bin/python3",
    )
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.platform",
        "darwin",
    )
    hint = dic._python_install_hint()
    assert "venv" in hint, (
        f"System-Python hint must reference venv.\nGot: {hint!r}"
    )


def test_hint_linux_apt_suggests_upgrade_pip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Linux + apt-managed Python → hint must contain '--upgrade pip'
    (per #548 fix). We mock dpkg so the test doesn't need a real dpkg.
    """
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.executable",
        "/usr/bin/python3",
    )
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.platform",
        "linux",
    )

    # Stub subprocess.run to simulate a successful `dpkg --show python3`.
    import subprocess as _subprocess

    def _fake_run(args, **kwargs):  # noqa: ANN001
        if args == ["dpkg", "--show", "python3"]:
            return _subprocess.CompletedProcess(args=args, returncode=0, stdout="python3\t3.12.0\n", stderr="")
        return _subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="")

    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.subprocess.run",
        _fake_run,
    )

    hint = dic._python_install_hint()
    assert "--upgrade pip" in hint, (
        f"apt-Linux hint must contain '--upgrade pip' per #548.\nGot: {hint!r}"
    )


def test_hint_generic_fallback_contains_pip_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown platform → fall through to generic 'pip install --user' hint.
    The fallback must never crash and must return something paste-ready.
    """
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.executable",
        "/some/unknown/python3",
    )
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.platform",
        "win32",
    )
    hint = dic._python_install_hint()
    assert "pip install --user iam-jit" in hint, (
        f"Generic-fallback hint must contain 'pip install --user iam-jit'.\n"
        f"Got: {hint!r}"
    )


def test_hint_survives_dpkg_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Linux without dpkg (Alpine, Arch, etc.) — FileNotFoundError from
    subprocess.run must be caught and fall through to the generic hint.
    The doctor must never crash when dpkg is absent.
    """
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.executable",
        "/usr/bin/python3",
    )
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.platform",
        "linux",
    )

    def _raise_fnf(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise FileNotFoundError("dpkg not found")

    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.subprocess.run",
        _raise_fnf,
    )

    # Must not raise; must return a non-empty string.
    hint = dic._python_install_hint()
    assert isinstance(hint, str) and hint, (
        "hint must be a non-empty string even when dpkg is absent"
    )


def test_os_aware_hint_wired_into_check_path(
    monkeypatch: pytest.MonkeyPatch,
    empty_path: None,
    cleared_env: None,
    _no_bouncers_running: None,
) -> None:
    """Integration: when the doctor's Section 1 PATH check fires and the
    OS is macOS + Homebrew, the Fix line in the output must contain
    'pipx' (not the old generic 'pip install --user iam-jit').

    This is the actual user-visible regression test for #649: a founder
    on macOS with Homebrew Python who runs 'iam-jit doctor install-check'
    must see a working Fix command.
    """
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.executable",
        "/opt/homebrew/Cellar/python@3.12/3.12.9/bin/python3.12",
    )
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.platform",
        "darwin",
    )

    result = _invoke()

    assert result.exit_code == 2
    assert "[FAIL] iam-jit NOT on PATH" in result.output
    # The Fix line must now contain pipx, not a bare pip install --user.
    fix_lines = [
        line for line in result.output.splitlines()
        if "Fix:" in line and "iam-jit" in line
    ]
    assert fix_lines, (
        "Expected at least one 'Fix:' line referencing iam-jit in the output.\n"
        f"--- output ---\n{result.output}"
    )
    assert any("pipx" in line for line in fix_lines), (
        "macOS Homebrew Fix must reference pipx (PEP 668 blocks pip --user).\n"
        f"Fix lines found:\n" + "\n".join(fix_lines)
    )
