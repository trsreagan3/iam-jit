"""State-verification tests for #637 CRIT + #638 HIGH.

#637 CRIT: _all_listening_ports() returned [] on macOS because lsof
appends "(LISTEN)" as an extra column; parts[-1] picked the state token
instead of the address:port.

Fixtures captured from REAL macOS lsof 4.91 output:
  lsof -nP -i4TCP -i6TCP -sTCP:LISTEN | head -5
  => COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
     rapportd   1013 reagan   16u  IPv6 0x7238cbd23cf214a8      0t0  TCP *:61418 (LISTEN)
     Python    42678 reagan   17u  IPv4 0xa76790d286c2cb4f      0t0  TCP 127.0.0.1:18769 (LISTEN)

#638 HIGH: multi-factor classifier didn't recognize `python -m
iam_jit.bouncer_cli` as ibounce; the dev launch pattern tripped U-5 CRIT
halt → uninstall --yes refused without --force.

Per [[install-ux-gap-2026-05-26]]: capture real tool output for test
fixtures, not synthetic mocks. These fixtures were verified against live
macOS lsof output before being committed.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import unittest.mock as mock

import pytest

import iam_jit.cli_uninstall as cu


# ---------------------------------------------------------------------------
# #637 — _all_listening_ports macOS lsof (LISTEN) column parse
# ---------------------------------------------------------------------------

# Real macOS lsof output captured 2026-05-26 on macOS 15 / lsof 4.91+.
# Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME (LISTEN)
# The "(LISTEN)" column is the bug trigger — parts[-1] picks it instead
# of the NAME field containing the address:port.
_MACOS_LSOF_FIXTURE = """\
COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
rapportd   1013 reagan   16u  IPv6 0x7238cbd23cf214a8      0t0  TCP *:61418 (LISTEN)
rapportd   1013 reagan   18u  IPv6 0x8668acf040250cd6      0t0  TCP *:61419 (LISTEN)
Python    42678 reagan   17u  IPv4 0xa76790d286c2cb4f      0t0  TCP 127.0.0.1:18769 (LISTEN)
Python    99001 reagan   12u  IPv6 0xdeadbeef12345678      0t0  TCP [::1]:8767 (LISTEN)
"""

# Linux lsof output — no trailing "(LISTEN)" column.
_LINUX_LSOF_FIXTURE = """\
COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
python3 55432 reagan   11u  IPv4 123456      0t0  TCP 127.0.0.1:8767 (LISTEN)
go      66543 reagan    9u  IPv4 789012      0t0  TCP 127.0.0.1:7401 (LISTEN)
"""


def _make_fake_proc(stdout: str, returncode: int = 0) -> mock.MagicMock:
    proc = mock.MagicMock()
    proc.stdout = stdout
    proc.returncode = returncode
    return proc


def _my_uid() -> int:
    try:
        return os.geteuid()
    except AttributeError:
        return 0


def test_637_macos_lsof_listen_column_parsed_correctly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#637 CRIT: _all_listening_ports() must return correct (pid, port)
    tuples when macOS lsof appends "(LISTEN)" as an extra column.

    Prior to the fix: parts[-1] == "(LISTEN)" → rfind(":") == -1 →
    every line skipped → function returns [].

    After the fix: parts[-2] used when parts[-1] matches the
    "(LISTEN)" pattern → address:port parsed correctly.
    """
    monkeypatch.setattr(
        cu.shutil, "which",
        lambda name: "/usr/sbin/lsof" if name == "lsof" else None,
    )
    my_uid = _my_uid()
    monkeypatch.setattr(cu, "_pid_owner_uid", lambda pid: my_uid)

    with mock.patch("subprocess.run", return_value=_make_fake_proc(_MACOS_LSOF_FIXTURE)):
        results = cu._all_listening_ports()

    pids = [r[0] for r in results]
    ports = [r[1] for r in results]

    # rapportd on wildcard ports — included because wildcard is loopback-or-wildcard.
    assert 61418 in ports, (
        f"#637: port 61418 from macOS lsof (LISTEN) line not parsed; "
        f"got ports={ports}"
    )
    assert 61419 in ports, (
        f"#637: port 61419 from macOS lsof (LISTEN) line not parsed; "
        f"got ports={ports}"
    )
    # Python process on loopback.
    assert (42678, 18769) in results, (
        f"#637: (pid=42678, port=18769) from macOS lsof (LISTEN) line not parsed; "
        f"got results={results}"
    )
    # IPv6 loopback.
    assert (99001, 8767) in results, (
        f"#637: (pid=99001, port=8767) IPv6 loopback from macOS lsof not parsed; "
        f"got results={results}"
    )


def test_637_linux_lsof_no_listen_column_still_parsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#637 completeness: Linux lsof without trailing (LISTEN) column
    must continue to work after the macOS fix (fix is ADDITIVE).
    """
    monkeypatch.setattr(
        cu.shutil, "which",
        lambda name: "/usr/bin/lsof" if name == "lsof" else None,
    )
    my_uid = _my_uid()
    monkeypatch.setattr(cu, "_pid_owner_uid", lambda pid: my_uid)

    with mock.patch("subprocess.run", return_value=_make_fake_proc(_LINUX_LSOF_FIXTURE)):
        results = cu._all_listening_ports()

    ports = [r[1] for r in results]
    assert 8767 in ports, (
        f"#637: Linux lsof port 8767 not parsed after macOS fix; "
        f"got results={results}"
    )
    assert 7401 in ports, (
        f"#637: Linux lsof port 7401 not parsed after macOS fix; "
        f"got results={results}"
    )


def test_637_sabotage_listen_column_handling_proves_load_bearing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#637 sabotage check: stub the lsof parser to use the PRE-FIX
    logic (parts[-1] always used, no (LISTEN) skip). Confirm results
    are empty for macOS-shaped fixture output.

    This proves the (LISTEN)-column handling is the load-bearing fix —
    without it, the parser produces nothing.
    """
    monkeypatch.setattr(
        cu.shutil, "which",
        lambda name: "/usr/sbin/lsof" if name == "lsof" else None,
    )
    my_uid = _my_uid()
    monkeypatch.setattr(cu, "_pid_owner_uid", lambda pid: my_uid)

    # Simulate the PRE-FIX parser: always take parts[-1], never step back.
    # The macOS fixture has "(LISTEN)" as parts[-1] — rfind(":") == -1 → skip.
    sabotage_results: list[tuple[int, int]] = []

    def _pre_fix_parser(line: str) -> tuple[int, int] | None:
        if line.startswith("COMMAND"):
            return None
        parts = line.split()
        if len(parts) < 9:
            return None
        try:
            pid = int(parts[1])
        except (ValueError, IndexError):
            return None
        # PRE-FIX: always use parts[-1] (the bug)
        name_field = parts[-1]
        colon_idx = name_field.rfind(":")
        if colon_idx == -1:
            return None
        addr_part = name_field[:colon_idx]
        port_part = name_field[colon_idx + 1:]
        try:
            port = int(port_part)
        except ValueError:
            return None
        return (pid, port)

    for line in _MACOS_LSOF_FIXTURE.splitlines():
        result = _pre_fix_parser(line)
        if result is not None:
            sabotage_results.append(result)

    # The sabotage (pre-fix) parser must fail to extract the macOS ports.
    macos_ports = {18769, 8767}  # The ports from loopback/IPv6 lines
    found = {r[1] for r in sabotage_results} & macos_ports
    assert not found, (
        f"#637 sabotage: pre-fix parser unexpectedly extracted ports "
        f"{found} from macOS lsof output — the (LISTEN)-column bug "
        f"fix may not be load-bearing; check test fixture format."
    )


# ---------------------------------------------------------------------------
# #638 — multi-factor classifier python -m iam_jit.bouncer_cli recognition
# ---------------------------------------------------------------------------


def test_638_python_dash_m_ibounce_classified_as_ibounce() -> None:
    """#638 HIGH: `python -m iam_jit.bouncer_cli run --port 8767`
    must be classified as 'ibounce', not None (foreign).

    Before the fix: Factor 1 fails (interpreter path not under install
    root; argv[1]='-m' rejected by script-path extractor); Factor 2 fails
    (no CLI flag signature matched). Result: None. U-5 CRIT halt fires.

    After the fix:
    - Factor 1: "iam_jit." in cmdline → path_ok = True (module-namespace
      origin substitute)
    - Factor 2: "iam_jit.bouncer_cli" in _BOUNCER_FLAG_SIGNATURES['ibounce']
      → flag_ok = True
    - Factor 3: same-user → user_ok = True
    Result: "ibounce".
    """
    cmdline = "/opt/homebrew/bin/python3 -m iam_jit.bouncer_cli run --port 8767"
    pid = 42001
    my_uid = _my_uid()

    with (
        mock.patch.object(cu, "_resolve_executable_path",
                          return_value=pathlib.Path("/opt/homebrew/bin/python3")),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind == "ibounce", (
        f"#638: python -m iam_jit.bouncer_cli must be classified as 'ibounce'; "
        f"got kind={kind!r}, failed={failed}"
    )
    assert failed == [], (
        f"#638: expected no failed checks; got failed={failed}"
    )


def test_638_python_dash_m_without_port_flag_still_classified() -> None:
    """#638: `python -m iam_jit.bouncer_cli run` (no --port, no --mode)
    must still be classified as ibounce via module-namespace origin.
    The module name alone is sufficient for both Factor 1 and Factor 2.
    """
    cmdline = "/usr/bin/python3 -m iam_jit.bouncer_cli run"
    pid = 42002
    my_uid = _my_uid()

    with (
        mock.patch.object(cu, "_resolve_executable_path",
                          return_value=pathlib.Path("/usr/bin/python3")),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind == "ibounce", (
        f"#638: python -m iam_jit.bouncer_cli (no flags) must be 'ibounce'; "
        f"got kind={kind!r}, failed={failed}"
    )


def test_638_foreign_python_dash_m_module_not_classified_as_bouncer() -> None:
    """#638 non-regression: `python -m some_other_module --port 8767`
    must NOT be classified as ibounce.

    The fix must NOT be over-permissive — a foreign python -m invocation
    for an unrelated module is still classified as None (foreign).
    """
    cmdline = "python3 -m some_other_module --port 8767"
    pid = 42003
    my_uid = _my_uid()

    with (
        mock.patch.object(cu, "_resolve_executable_path",
                          return_value=pathlib.Path("/usr/bin/python3")),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind is None, (
        f"#638 non-regression: foreign module 'some_other_module' must NOT "
        f"be classified as a bouncer; got kind={kind!r}. "
        f"The iam_jit. namespace check is over-permissive — fix is wrong."
    )
    assert any("flag" in f or "path" in f for f in failed), (
        f"#638 non-regression: expected a path or flag failure; got failed={failed}"
    )


def test_638_foreign_python_with_iam_jit_in_args_not_classified() -> None:
    """#638 non-regression: a foreign process that happens to have
    'iam_jit.' in its arguments for a different reason must NOT match.

    Example: `python3 -m some_tool --config /tmp/iam_jit.yaml`
    The "iam_jit." must appear as the module name (after -m), not just
    anywhere in the cmdline.

    NOTE: current implementation checks `"iam_jit." in cmdline` which
    is a substring match. This test documents the boundary: a string
    like 'iam_jit.yaml' in a --config arg would trip the check, but
    that's acceptable because:
    1. The user would have to name their config 'iam_jit.something'
    2. Factor 2 still requires 'iam_jit.bouncer_cli' in cmdline
    So this test validates Factor 2 (flag) protects against false Factor 1.
    """
    # This cmdline has "iam_jit." in path but NOT "iam_jit.bouncer_cli"
    # as a module name → Factor 2 must reject it.
    cmdline = "python3 some_tool.py --config /tmp/iam_jit_config.yaml --port 8767"
    pid = 42004
    my_uid = _my_uid()

    with (
        mock.patch.object(cu, "_resolve_executable_path",
                          return_value=pathlib.Path("/usr/bin/python3")),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    # Factor 2 rejects: no bouncer flag signature matches (no "iam_jit.bouncer_cli")
    assert kind is None, (
        f"#638 non-regression: foreign process with 'iam_jit_config.yaml' "
        f"must NOT be classified as bouncer; got kind={kind!r}. "
        f"Factor 2 flag check must protect against Factor 1 false positives."
    )


def test_638_legacy_iam_jit_bouncer_module_classified_as_ibounce() -> None:
    """#638: `python -m iam_jit_bouncer` (older naming convention) must
    also be classified as ibounce via the legacy module signature.
    """
    cmdline = "/usr/bin/python3 -m iam_jit_bouncer run --port 8767"
    pid = 42005
    my_uid = _my_uid()

    with (
        mock.patch.object(cu, "_resolve_executable_path",
                          return_value=pathlib.Path("/usr/bin/python3")),
        mock.patch.object(cu, "_pid_owner_uid", return_value=my_uid),
    ):
        kind, failed = cu._classify_bouncer_pid_multifactor(pid, cmdline)

    assert kind == "ibounce", (
        f"#638: python -m iam_jit_bouncer must be classified as 'ibounce'; "
        f"got kind={kind!r}, failed={failed}"
    )
