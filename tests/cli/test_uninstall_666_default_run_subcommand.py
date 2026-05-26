"""Tests for #666 CRIT — default-launch subcommand patterns missing from
_BOUNCER_FLAG_SIGNATURES.

Bug: when ibounce (or any bouncer) is launched via the canonical bare
subcommand (`ibounce run` / `kbounce run` / etc.) with no additional CLI
flags, Factor 2 of the multi-factor classifier had no matching signature.
Result: classifier returned None (unknown_port_owner) → U-2/U-5/U-3 halt
fired → clean non-forced uninstall blocked even when the bouncer IS ours.

Fix: add " run", " serve", " mcp" subcommand patterns to each bouncer's
_BOUNCER_FLAG_SIGNATURES entry (leading space enforces word-boundary).

Per [[tests-and-independent-uat-required]]: unit tests verify:
  1. Positive: canonical `<python> <install-path>/<bouncer> run` → classified
  2. Negative: `<python> /usr/bin/random_script.py run` → NOT classified
     (Factor 1 fails; the new pattern must not false-positive on random "run")
  3. Cross-product: same shape for kbounce/gbounce/dbounce
"""

from __future__ import annotations

import os
import pathlib
import unittest.mock as mock

import pytest

import iam_jit.cli_uninstall as cu


def _my_uid() -> int:
    try:
        return os.geteuid()
    except AttributeError:
        return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _local_bin(name: str) -> pathlib.Path:
    """Canonical install path under ~/.local/bin (pip --user installs)."""
    return pathlib.Path.home() / ".local" / "bin" / name


def _venv_bin(name: str) -> pathlib.Path:
    """Canonical install path under ~/.iam-jit/venv/bin/."""
    return pathlib.Path.home() / ".iam-jit" / "venv" / "bin" / name


# ---------------------------------------------------------------------------
# ibounce — canonical `ibounce run` launch (the #666 bug reproducer)
# ---------------------------------------------------------------------------


def test_666_ibounce_run_subcommand_classified_as_ibounce() -> None:
    """#666 CRIT: `<python> /Users/<user>/.local/bin/ibounce run` must be
    classified as 'ibounce'.

    This is the EXACT cmdline shape from the founder's PID 44674
    (ibounce on :8767 launched via `nohup ibounce run`). Before the fix
    the classifier returned None (unknown_port_owner) → U-5 CRIT halt
    fired; after the fix " run" matches Factor 2.

    Factor 1: script path ~/.local/bin/ibounce is under a known install root.
    Factor 2: " run" in _BOUNCER_FLAG_SIGNATURES['ibounce'] → flag_ok.
    Factor 3: same-user → user_ok.
    """
    script_path = _local_bin("ibounce")
    # Simulate the real macOS cmdline: Python interpreter is argv[0],
    # ibounce script is argv[1], subcommand is argv[2].
    cmdline = f"/opt/homebrew/bin/python3 {script_path} run"
    pid = 44674
    my_uid = _my_uid()

    with (
        mock.patch.object(
            cu, "_resolve_executable_path",
            return_value=pathlib.Path("/opt/homebrew/bin/python3"),
        ),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind == "ibounce", (
        f"#666: ibounce run must classify as 'ibounce'; "
        f"got kind={kind!r}, failed={failed}. "
        f"Cmdline: {cmdline!r}"
    )
    assert failed == [], (
        f"#666: expected no failed checks; got failed={failed}"
    )


def test_666_ibounce_run_from_venv_classified() -> None:
    """#666: ibounce run from venv install path also classifies correctly.

    Covers `<venv-python> ~/.iam-jit/venv/bin/ibounce run` which is
    the `iam-jit init` installed launch shape.
    """
    script_path = _venv_bin("ibounce")
    cmdline = f"/Users/testuser/.iam-jit/venv/bin/python3 {script_path} run"
    pid = 12345
    my_uid = _my_uid()

    with (
        mock.patch.object(
            cu, "_resolve_executable_path",
            return_value=pathlib.Path("/Users/testuser/.iam-jit/venv/bin/python3"),
        ),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind == "ibounce", (
        f"#666: ibounce run from venv must classify as 'ibounce'; "
        f"got kind={kind!r}, failed={failed}"
    )


def test_666_ibounce_run_with_port_flag_still_classified() -> None:
    """#666: ibounce run with a port flag (non-default port) still classifies.

    `ibounce run --port 18767` — the " run" signature must match even
    when additional flags follow.
    """
    script_path = _local_bin("ibounce")
    cmdline = f"/opt/homebrew/bin/python3 {script_path} run --port 18767"
    pid = 55000
    my_uid = _my_uid()

    with (
        mock.patch.object(
            cu, "_resolve_executable_path",
            return_value=pathlib.Path("/opt/homebrew/bin/python3"),
        ),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind == "ibounce", (
        f"#666: ibounce run --port N must classify as 'ibounce'; "
        f"got kind={kind!r}, failed={failed}"
    )


# ---------------------------------------------------------------------------
# Negative test — the " run" pattern must NOT false-positive
# ---------------------------------------------------------------------------


def test_666_random_script_run_not_classified_as_bouncer() -> None:
    """#666 negative: `python3 /usr/bin/random_script.py run` must NOT
    classify as any bouncer.

    Factor 1 fails: /usr/bin/random_script.py is not under any known
    install root. Factor 2 would match " run" but is never reached for
    the right kind because Factor 1 failed and the path-basename
    "random_script.py" doesn't match any bouncer name. Combined result: None.

    This proves the " run" pattern doesn't over-trigger on arbitrary
    processes that happen to use a "run" subcommand.
    """
    cmdline = "python3 /usr/bin/random_script.py run"
    pid = 99999
    my_uid = _my_uid()

    with (
        mock.patch.object(
            cu, "_resolve_executable_path",
            return_value=pathlib.Path("/usr/bin/python3"),
        ),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind is None, (
        f"#666 negative: random_script.py run must NOT classify as a bouncer; "
        f"got kind={kind!r}. The ' run' pattern must only fire after Factor 1 "
        f"(path check) confirms the binary is ours."
    )
    assert any("path" in f or "install root" in f for f in failed), (
        f"#666 negative: expected a path-origin failure; got failed={failed}"
    )


def test_666_tmp_ibounce_test_run_not_classified() -> None:
    """#666 negative regression (#614 shape): `/tmp/ibounce-test run` must
    NOT classify as ibounce — the #614 foreign-process protection is intact.

    Even though the cmdline contains " run", the exe path /tmp/ibounce-test
    is not under any known install root, so Factor 1 fails.
    """
    cmdline = "/tmp/ibounce-test run --port 8767"
    pid = 88888
    my_uid = _my_uid()

    with (
        mock.patch.object(
            cu, "_resolve_executable_path",
            return_value=pathlib.Path("/tmp/ibounce-test"),
        ),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind is None, (
        f"#666 negative (#614 non-regression): /tmp/ibounce-test run must NOT "
        f"classify as ibounce; got kind={kind!r}. "
        f"The #614 cross-domain SIGTERM protection must remain intact."
    )


# ---------------------------------------------------------------------------
# Cross-product: kbounce default launch
# ---------------------------------------------------------------------------


def test_666_kbounce_run_subcommand_classified_as_kbounce() -> None:
    """#666 cross-product: `kbounce run` (Go binary) must classify as 'kbounce'.

    kbounce is a Go binary so the kernel reports it directly in argv[0].
    The exe path resolves to ~/go/bin/kbounce (a known install root).
    """
    script_path = pathlib.Path.home() / "go" / "bin" / "kbounce"
    cmdline = f"{script_path} run --apiserver-url https://127.0.0.1:6443"
    pid = 22001
    my_uid = _my_uid()

    with (
        mock.patch.object(
            cu, "_resolve_executable_path",
            return_value=script_path,
        ),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind == "kbounce", (
        f"#666: kbounce run must classify as 'kbounce'; "
        f"got kind={kind!r}, failed={failed}"
    )


def test_666_kbounce_bare_run_no_flags_classified() -> None:
    """#666 cross-product: `kbounce run` with NO additional flags must
    classify as 'kbounce' (the pure default-launch case).

    Before the fix: no signatures matched bare `run` → None.
    After the fix: " run" in kbounce's signatures → flag_ok.
    """
    script_path = pathlib.Path.home() / "go" / "bin" / "kbounce"
    cmdline = f"{script_path} run"
    pid = 22002
    my_uid = _my_uid()

    with (
        mock.patch.object(
            cu, "_resolve_executable_path",
            return_value=script_path,
        ),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind == "kbounce", (
        f"#666: kbounce bare run must classify as 'kbounce'; "
        f"got kind={kind!r}, failed={failed}"
    )


# ---------------------------------------------------------------------------
# Cross-product: dbounce default launch
# ---------------------------------------------------------------------------


def test_666_dbounce_run_subcommand_classified_as_dbounce() -> None:
    """#666 cross-product: `dbounce run` must classify as 'dbounce'."""
    script_path = pathlib.Path.home() / "go" / "bin" / "dbounce"
    cmdline = f"{script_path} run"
    pid = 33001
    my_uid = _my_uid()

    with (
        mock.patch.object(
            cu, "_resolve_executable_path",
            return_value=script_path,
        ),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind == "dbounce", (
        f"#666: dbounce run must classify as 'dbounce'; "
        f"got kind={kind!r}, failed={failed}"
    )


# ---------------------------------------------------------------------------
# Cross-product: gbounce default launch
# ---------------------------------------------------------------------------


def test_666_gbounce_run_subcommand_classified_as_gbounce() -> None:
    """#666 cross-product: `gbounce run` must classify as 'gbounce'."""
    script_path = pathlib.Path.home() / "go" / "bin" / "gbounce"
    cmdline = f"{script_path} run"
    pid = 44001
    my_uid = _my_uid()

    with (
        mock.patch.object(
            cu, "_resolve_executable_path",
            return_value=script_path,
        ),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind == "gbounce", (
        f"#666: gbounce run must classify as 'gbounce'; "
        f"got kind={kind!r}, failed={failed}"
    )


# ---------------------------------------------------------------------------
# Verify _BOUNCER_FLAG_SIGNATURES contains the expected subcommand patterns
# ---------------------------------------------------------------------------


def test_666_signatures_contain_run_for_all_bouncers() -> None:
    """#666 structural: _BOUNCER_FLAG_SIGNATURES must contain ' run' for
    every bouncer kind (the canonical default-launch subcommand across all
    four bouncers in the Bounce suite).
    """
    for kind in ("ibounce", "kbounce", "kbouncer", "dbounce", "gbounce"):
        sigs = cu._BOUNCER_FLAG_SIGNATURES.get(kind, ())
        assert " run" in sigs, (
            f"#666: _BOUNCER_FLAG_SIGNATURES['{kind}'] must contain ' run'; "
            f"got sigs={sigs}"
        )


def test_666_run_pattern_has_leading_space_word_boundary() -> None:
    """#666 structural: the subcommand patterns must have a leading space.

    Without the leading space, 'run' would match tokens containing 'run'
    as a substring (e.g. `--upstream-runner`, `--dry-run`). The leading
    space acts as a word-boundary guard.

    This test detects the anti-pattern: a bare 'run' (no leading space)
    being present in signatures alongside a correct ' run' entry.
    """
    for kind in cu._BOUNCER_FLAG_SIGNATURES:
        sigs = cu._BOUNCER_FLAG_SIGNATURES[kind]
        for sig in sigs:
            # Detect bare "run" (no leading space) — the unsafe form.
            # Note: sig == "run" (not sig.strip() == "run") so we only
            # flag the truly-bare form, not the correctly-spaced " run".
            if sig == "run":
                pytest.fail(
                    f"#666: _BOUNCER_FLAG_SIGNATURES['{kind}'] contains 'run' "
                    f"(bare, no leading space) — this would match 'run' anywhere "
                    f"in the cmdline including within longer tokens like "
                    f"'--upstream-runner'. Use ' run' (with leading space) "
                    f"for word-boundary safety."
                )
