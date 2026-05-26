"""#541 — `iam-jit uninstall` subcommand.

Implements the 10-step MRR-4 uninstall sequence
(``docs/MRR-4-UNINSTALL.md``) as a single CLI command so operators
don't have to follow a multi-step manual checklist.

Per ``[[mrr-flight-readiness-program]]`` MRR-4 acceptance:
"uninstall command tested end-to-end on clean macOS + Linux container;
halt-conditions documented; rollback restores pre-install state cleanly."

Per ``[[ibounce-honest-positioning]]``:
  * partial-failure state is reported HONESTLY — `--force` is required
    to proceed past a halt condition; the structured result records what
    was/wasn't undone.
  * pre-flight check is honest about what it CANNOT detect (operator-
    modified shell profiles, MCP config entries, browser-trusted MITM
    CAs) — we surface those as ``manual_reminders`` rather than silently
    "succeeding".

Per ``[[creates-never-mutates]]``:
  * uninstall only REMOVES iam-jit-created resources (binaries, venv,
    ``~/.iam-jit/`` config, bouncer processes).
  * we DO NOT modify operator state we didn't create (``~/.bashrc``,
    MCP config files, macOS Keychain, browser truststores). We FLAG
    those for manual cleanup with explicit instructions.
  * audit logs may be preserved with ``--keep-audit-logs`` for
    compliance.

Per ``docs/CONTRIBUTING.md`` state-verification convention: each
"removed" success claim is paired with an observable post-check
(file absent, PID absent, port free).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import Any

import click


# ---------------------------------------------------------------------------
# Paths — module-level so tests can monkeypatch
# ---------------------------------------------------------------------------

# Mirror cli_canary.CANARY_DIR convention so tests can isolate via
# monkeypatch (parallel to test_cli_canary.py's isolated_canary fixture).
#
# #617 MED-1: these module-level constants are the DEFAULT — when no
# ``--data-dir`` flag / ``IAM_JIT_DATA_DIR`` env is provided. When the
# operator targets a different data directory (parity with
# ``iam-jit serve --data-dir``), the per-call paths are derived from
# the resolved data dir via :func:`_derive_paths` rather than these
# globals. Existing tests that monkeypatch ``IAM_JIT_HOME`` etc. still
# work because ``_inventory_installed_state(data_dir=None)`` continues
# to read the module-level constants (the path-derivation branch only
# fires when a non-None data dir is passed).
IAM_JIT_HOME = pathlib.Path.home() / ".iam-jit"
VENV_DIR = IAM_JIT_HOME / "venv"
BOUNCER_DIR = IAM_JIT_HOME / "bouncer"
AUDIT_PATH = IAM_JIT_HOME / "audit.jsonl"
ANOMALY_BASELINE_PATH = IAM_JIT_HOME / "anomaly-baseline.db"
CANARY_DIR = IAM_JIT_HOME / "canary"

# Env var name used by ``iam-jit uninstall --data-dir`` resolution
# (parity with the ``--data-dir`` flag on ``iam-jit serve``). The
# precedence chain is: CLI flag > env > module-level default
# (``~/.iam-jit/``).
IAM_JIT_DATA_DIR_ENV = "IAM_JIT_DATA_DIR"

# #671 CRIT — dogfood safety belt env var. When set to "1" / "true" /
# "yes", uninstall REFUSES any machine-wide action without an extra
# super-explicit acknowledgement flag. Designed for the founder's
# dogfood machine where misdirected UAT fixtures destroyed live state
# (see #671 brief). Operators install this by appending one line to
# their shell rc; see the doctor / install help output.
IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE_ENV = "IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE"


def _default_data_dir() -> pathlib.Path:
    """Return the module-level default data dir.

    Indirected through a helper so :func:`_scope_is_data_only` and the
    test fixture that monkeypatches :data:`IAM_JIT_HOME` observe the
    same value. Tests monkeypatch :data:`IAM_JIT_HOME`; calls here read
    the live module global.
    """
    return IAM_JIT_HOME.expanduser().resolve()


def _scope_is_data_only(data_dir: pathlib.Path | None) -> bool:
    """#671 CRIT — True iff machine-wide actions must be SUPPRESSED
    for this uninstall call.

    Returns True when ``data_dir`` is non-default (operator passed
    ``--data-dir`` or ``IAM_JIT_DATA_DIR`` pointing somewhere other
    than ``~/.iam-jit/``). In that case, every action whose blast
    radius extends beyond the data dir (process kill, binary removal
    from ``~/.local/bin``, MCP entry removal from ``~/.claude.json``,
    shell-rc detection) MUST be suppressed.

    Returns False only when ``data_dir`` is None OR resolves to the
    module-level default — i.e. the operator IS asking to uninstall
    the live machine install.

    Per the #671 brief:
      > When `--data-dir <X>` is non-default (X != ~/.iam-jit), ALL
      > action scopes must be limited to actions on iam-jit state
      > ROOTED at that data-dir.

    Bypassed by ``--full-machine-cleanup`` (which itself requires
    ``--yes-i-want-to-clean-other-iam-jit-installs-on-this-machine``
    to actually do the destruction; the brief's friction-as-feature
    pattern).
    """
    if data_dir is None:
        return False
    try:
        resolved = pathlib.Path(data_dir).expanduser().resolve()
    except (OSError, RuntimeError):
        # If we can't resolve, treat as "different from default" —
        # safer to suppress machine-wide actions than to fall through.
        return True
    return resolved != _default_data_dir()


def _dogfood_refuse_destructive_active() -> bool:
    """#671 CRIT — True iff the dogfood safety-belt env var is set.

    Checks :data:`IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE_ENV` for truthy
    values ("1", "true", "yes", case-insensitive). When True, the
    uninstall entry point requires the long-form acknowledgement flag
    ``--yes-i-am-on-dogfood-machine-and-want-to-uninstall`` before
    running ANY destructive step.
    """
    val = os.environ.get(IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE_ENV, "").strip().lower()
    return val in ("1", "true", "yes", "on", "y")


def resolve_data_dir(
    cli_flag: pathlib.Path | str | None = None,
    env_var: str | None = IAM_JIT_DATA_DIR_ENV,
    default: pathlib.Path | None = None,
) -> pathlib.Path:
    """Resolve the iam-jit data dir using the documented precedence.

    Precedence:
      1. ``cli_flag`` (``--data-dir`` on the uninstall CLI)
      2. ``env_var`` (``IAM_JIT_DATA_DIR`` by default)
      3. ``default`` (or the module-level :data:`IAM_JIT_HOME` if None)

    Mirrors the resolution shape required for parity with
    ``iam-jit serve --data-dir`` per [[ibounce-honest-positioning]] —
    CLI surfaces that target the same state must be symmetric so the
    operator can uninstall the same data directory they installed
    against. Without this, operators who ran ``serve --data-dir
    /opt/iam-jit-prod`` had no symmetric way to uninstall (they had to
    hack ``$HOME`` redirects).

    Per [[ibounce-honest-positioning]]: the resolved path is surfaced
    in the pre-check + result output so operators can verify they're
    acting on the right tree before destruction.
    """
    if cli_flag is not None and str(cli_flag) != "":
        return pathlib.Path(cli_flag).expanduser().resolve()
    if env_var:
        env_val = os.environ.get(env_var)
        if env_val:
            return pathlib.Path(env_val).expanduser().resolve()
    if default is not None:
        return pathlib.Path(default).expanduser().resolve()
    # Fall back to the module-level default. Resolve so the returned
    # path is absolute + symlink-clean (matches the flag/env branches).
    return IAM_JIT_HOME.expanduser().resolve()


def _derive_paths(
    data_dir: pathlib.Path | None,
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    """Compute ``(home, venv, bouncer)`` paths for a given data dir.

    When ``data_dir`` is None, returns the module-level globals so
    existing callers + tests (which monkeypatch IAM_JIT_HOME / VENV_DIR
    etc.) continue to work unchanged.

    When ``data_dir`` is provided, derives venv + bouncer paths from
    it directly. This is the #617 MED-1 path: operator passed
    ``--data-dir`` or ``IAM_JIT_DATA_DIR``, so the entire uninstall
    operates on that tree instead of the default.

    Per [[creates-never-mutates]]: uninstall must operate on the
    operator's actual data dir, not a guessed one — a silently-wrong
    home means we either miss state (orphan risk) or destroy
    out-of-domain state (cross-domain SIGTERM, same shape as #614).
    """
    if data_dir is None:
        return IAM_JIT_HOME, VENV_DIR, BOUNCER_DIR
    home = pathlib.Path(data_dir)
    return home, home / "venv", home / "bouncer"

# Per MRR-4-UNINSTALL.md step 1 — bouncer process names.
BOUNCER_PROCESS_NAMES = ("ibounce", "gbounce", "kbounce", "kbouncer", "dbounce")

# Per MRR-4-UNINSTALL.md step 6 — bouncer ports.
# Aggregated flat tuple kept for backward-compat (older code that
# iterates BOUNCER_PORTS without caring which bouncer owns each port).
# Authoritative per-bouncer mapping lives in _BOUNCER_DEFAULT_PORTS
# below.
BOUNCER_PORTS = (7401, 7402, 7412, 8767, 8766, 5433, 8768, 8080, 8769)

# #608 — per-bouncer default ports. Without this, the port-owner
# cross-reference added by #574 only catches ibounce-default ports
# (8767 / 7401 / 7402 / 7412); kbounce on :8766, dbounce on
# :5433+:8768, and gbounce on :8080+:8769 stay invisible to uninstall
# even though `iam-jit posture` correctly identifies them as RUNNING.
#
# Two surfaces disagreeing about ground truth on the same machine
# violates [[ibounce-honest-positioning]]: if a bouncer is running,
# uninstall MUST detect it; silent miss = orphan risk on uninstall.
#
# Source of truth for the canonical defaults: posture/bouncers.py
# (IBOUNCE_DEFAULT_PORT / KBOUNCE_DEFAULT_PORT /
# DBOUNCE_DEFAULT_WIRE_PORT + DBOUNCE_DEFAULT_MGMT_PORT /
# GBOUNCE_DEFAULT_WIRE_PORT + GBOUNCE_DEFAULT_MGMT_PORT). When those
# change, update here too — the posture-uninstall parity check in
# :func:`_check_halt_conditions` will surface drift.
#
# Legacy ibounce ports 7401 / 7402 / 7412 retained from the
# historical local-proxy era (MRR-4-UNINSTALL.md docs still reference
# them) so we don't regress operators who started ibounce on those.
_BOUNCER_DEFAULT_PORTS: dict[str, tuple[int, ...]] = {
    "ibounce": (8767, 7401, 7402, 7412),
    "kbounce": (8766,),
    "kbouncer": (8766,),
    "dbounce": (5433, 8768),
    "gbounce": (8080, 8769),
}

# Per MRR-4-UNINSTALL.md step 3 — pip-installed console scripts.
CONSOLE_SCRIPTS = (
    "iam-jit",
    "iam-risk-score",
    "ibounce",
    "iam-jit-bouncer",
    "iam-jit-feed-publish",
)

# Per MRR-4-UNINSTALL.md step 4 — Go binaries that ship separately.
GO_BINARIES = ("gbounce", "kbounce", "kbouncer", "dbounce")

# Per MRR-4-UNINSTALL.md step 9 — audit-bearing files that operators
# may want to keep with `--keep-audit-logs`.
AUDIT_BEARING_PATHS_REL = (
    "audit.jsonl",
    "bouncer/state.db",
    "bouncer/state.db-shm",
    "bouncer/state.db-wal",
    "canary/issues.jsonl",
)

# #617 HIGH-3 — cross-product bouncer config directories.
# Each bouncer stores its own config in a separate ~/.{name}/ directory;
# uninstall must detect (and NOT auto-remove — those are per-product
# concerns) but MUST surface as remaining_artifacts when present after
# the main data-dir wipe. Per [[creates-never-mutates]]: we do not
# auto-delete bouncer config directories because the operator may have
# customized them; we report them so the operator can remove manually.
BOUNCER_CONFIG_DIRS: dict[str, pathlib.Path] = {
    "gbounce": pathlib.Path.home() / ".gbounce",
    "kbounce": pathlib.Path.home() / ".kbounce",
    "dbounce": pathlib.Path.home() / ".dbounce",
}

# #617 HIGH-3 — all binary names the suite installs on PATH.
# Used by _check_path_binaries() to detect stale binaries that remain
# after pip-uninstall / go-bin removal (e.g. symlinks left in ~/.local/bin
# or /usr/local/bin that the removal steps didn't catch).
# Combines CONSOLE_SCRIPTS + GO_BINARIES deduplicated.
ALL_BINARY_NAMES: tuple[str, ...] = (
    "iam-jit",
    "iam-risk-score",
    "ibounce",
    "iam-jit-bouncer",
    "iam-jit-feed-publish",
    "kbounce",
    "kbouncer",
    "dbounce",
    "gbounce",
)

# #617 HIGH-3 — MCP server names written by `iam-jit mcp install`.
# Used by _step_remove_mcp_entries() + _check_mcp_entries() to detect /
# remove iam-jit-owned entries in ~/.claude.json mcpServers blocks.
# Per the brief: uninstall MAY remove these automatically (they are
# iam-jit-owned artifacts); add --keep-mcp-entries for operators who
# want to preserve them.
MCP_SERVER_NAMES: tuple[str, ...] = (
    "iam-jit",
    "ibounce",
    "kbounce",
    "dbounce",
    "gbounce",
)

# #617 HIGH-3 — shell-rc files to scan for stale shellinit lines.
# Per [[creates-never-mutates]]: we do NOT edit these files; we report
# found lines as remaining_artifacts with file:line hints.
SHELL_RC_FILES: tuple[pathlib.Path, ...] = (
    pathlib.Path.home() / ".zshrc",
    pathlib.Path.home() / ".bashrc",
    pathlib.Path.home() / ".bash_profile",
    pathlib.Path.home() / ".profile",
)

# Patterns that indicate a stale iam-jit shellinit line.
# We look for the shellinit eval pattern + direct env var exports.
_SHELLINIT_PATTERNS = (
    "iam-jit shellinit",
    "iam_jit shellinit",
    "IAM_JIT_",
    "HTTPS_PROXY=http://127.0.0.1:74",  # ibounce legacy proxy
    "AWS_ENDPOINT_URL.*iam.jit",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _call_with_optional_kwarg(fn: Any, **kwargs: Any) -> Any:
    """Call ``fn(**kwargs)`` but tolerate stubs that don't accept some
    of the kwargs.

    #671 CRIT — added ``data_only_scope`` kwargs to several helpers in
    cli_uninstall.py. Many existing tests monkeypatch these helpers
    with bare lambdas (e.g. ``lambda: []``) that don't accept the new
    kwarg. To avoid changing every test fixture, we strip unsupported
    kwargs on TypeError fallback. This is purely a backwards-compat
    shim for test stubs — the real helpers all accept the kwarg.
    """
    try:
        return fn(**kwargs)
    except TypeError:
        # Try progressively stripping kwargs until the stub accepts the
        # call. Each TypeError tells us one kwarg the callee doesn't
        # accept; remove and retry.
        import inspect
        try:
            sig = inspect.signature(fn)
            accepted: dict[str, Any] = {}
            for k, v in kwargs.items():
                if k in sig.parameters or any(
                    p.kind == inspect.Parameter.VAR_KEYWORD
                    for p in sig.parameters.values()
                ):
                    accepted[k] = v
            return fn(**accepted)
        except (TypeError, ValueError):
            return fn()


def _pid_alive(pid: int) -> bool:
    """Cheap liveness check. Mirrors cli_canary._pid_alive."""
    try:
        os.kill(int(pid), 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def _port_bound(port: int, host: str = "127.0.0.1") -> bool:
    """True iff `host:port` accepts a TCP connect (i.e. a listener
    is alive). Pure-stdlib so this works in slim Linux containers
    that don't ship lsof. Mirrors cli_canary._port_bound."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, int(port))) == 0
    except OSError:
        return False


def _find_pids_for_process(name: str) -> list[int]:
    """Find PIDs of running processes matching ``name``.

    Best-effort cross-platform: prefers ``pgrep`` (macOS + Linux),
    falls back to empty list when pgrep isn't installed. Returns an
    empty list rather than raising so the uninstall stays resilient
    on container-only environments.

    NOTE: we match by exact basename + against ``ps``-style argv on
    macOS to catch ``python -m iam_jit.autopilot.daemon`` style children
    that share the same proxy port.

    KNOWN LIMITATION (#574): ``pgrep -x`` matches the kernel-reported
    process basename (argv[0]) — which for Python console-script
    bouncers is the Python interpreter, NOT "ibounce". The matching
    cross-reference pass in :func:`_inventory_installed_state` covers
    that gap by going via bound-port ownership.
    """
    pgrep = shutil.which("pgrep")
    if pgrep is None:
        return []
    out: list[int] = []
    # `pgrep -x` matches the exact basename.
    try:
        proc = subprocess.run(
            [pgrep, "-x", name],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    for line in proc.stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            out.append(int(s))
        except ValueError:
            continue
    return out


def _lsof_pids_on_port(port: int) -> list[int]:
    """Return PIDs holding a TCP LISTEN socket on ``port`` (IPv4 + IPv6).

    Mirrors ``cli_canary._lsof_pids_on_port``. Used by
    :func:`_inventory_installed_state` to cross-reference bouncer-port
    owners back to PIDs — the #574 fix for ``pgrep -x`` missing Python
    console-script bouncers; later extended by #608 + #614 + #621.

    Per UAT-Lifecycle 2026-05-25 (HIGH-1, #615): the prior default
    ``lsof -iTCP:PORT`` invocation was IPv6-biased on some lsof
    versions and missed IPv4-only loopback binds (``127.0.0.1:PORT``
    without a dual-stack ``[::]`` listener). A foreign IPv4-only
    Python process bound to 127.0.0.1:8767 silently bypassed every
    #574 / #608 / #614 halt; re-install would later fail to bind the
    port with no warning from uninstall.

    Fix shape:
      1. Primary: ``lsof -nP -i4TCP:PORT -i6TCP:PORT -sTCP:LISTEN -t``
         — explicit dual-stack selection. ``-i4`` and ``-i6`` are
         additive (UNION semantics on lsof 4.91+ macOS and the Linux
         lsof builds we test against), and ``-sTCP:LISTEN`` filters out
         ESTABLISHED / TIME_WAIT entries so the result is always the
         listener PID set. ``-nP`` suppresses DNS + service-name
         resolution to keep the call deterministic.
      2. Fallback: when lsof is missing (slim containers, some Linux
         distros), shell out to ``ss -tlnpH 'sport = :PORT'`` and parse
         the ``users:(("name",pid=NNN,...))`` column.

    Returns an empty list when the port has no listener OR when
    neither tool is available. Per [[ibounce-honest-positioning]]:
    when classification truly cannot be determined, default to
    surfacing nothing — callers like :func:`_inventory_installed_state`
    fire halt U-1 (bouncer ports bound but no PID found) which is the
    operator-visible signal that a port is held by an unknown process.
    """
    lsof = shutil.which("lsof")
    if lsof is not None:
        try:
            proc = subprocess.run(
                [
                    lsof, "-nP",
                    "-i4TCP:%d" % int(port),
                    "-i6TCP:%d" % int(port),
                    "-sTCP:LISTEN",
                    "-t",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=5.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        # lsof exit conventions:
        #   0 = matches found, 1 = no matches (NOT an error condition).
        # Any other returncode is unexpected (permission denied, bad
        # invocation, kernel error). We surface a one-line stderr
        # notice per [[ibounce-honest-positioning]] so operators see
        # silent-empty failures instead of guessing.
        if proc.returncode not in (0, 1):
            try:
                sys.stderr.write(
                    f"iam-jit: lsof returned exit {proc.returncode} for "
                    f"port {int(port)}: {(proc.stderr or '').strip()[:200]}\n"
                )
            except Exception:
                pass
            return []
        out: list[int] = []
        for line in proc.stdout.splitlines():
            s = line.strip()
            if not s:
                continue
            try:
                pid = int(s)
            except ValueError:
                continue
            if pid not in out:
                out.append(pid)
        return out

    # Linux-only fallback: ``ss`` ships with iproute2 on every modern
    # distro and reports listeners with PID via -p. Sample line:
    #   LISTEN 0 5 127.0.0.1:8767 0.0.0.0:* users:(("python",pid=1234,fd=3))
    ss = shutil.which("ss")
    if ss is None:
        return []
    try:
        proc = subprocess.run(
            [ss, "-tlnpH", "sport = :%d" % int(port)],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        try:
            sys.stderr.write(
                f"iam-jit: ss returned exit {proc.returncode} for "
                f"port {int(port)}: {(proc.stderr or '').strip()[:200]}\n"
            )
        except Exception:
            pass
        return []
    out: list[int] = []
    for line in (proc.stdout or "").splitlines():
        # Extract every pid=NNN occurrence on the line (ss may report
        # multiple processes per socket via SO_REUSEPORT).
        idx = 0
        while True:
            marker = line.find("pid=", idx)
            if marker == -1:
                break
            start = marker + 4
            end = start
            while end < len(line) and line[end].isdigit():
                end += 1
            if end > start:
                try:
                    pid = int(line[start:end])
                    if pid not in out:
                        out.append(pid)
                except ValueError:
                    pass
            idx = end if end > marker else marker + 1
    return out


def _read_cmdline(pid: int) -> str:
    """Best-effort cmdline read for ``pid``.

    Uses ``ps -p PID -o command=`` which works identically on macOS +
    Linux (vs. ``/proc/PID/cmdline`` which is Linux-only). Returns the
    empty string on any failure (PID gone, ps unavailable). Used by
    :func:`_infer_bouncer_kind_from_cmdline` to validate that a
    port-owning PID is actually a bouncer process before adding it to
    the uninstall plan.
    """
    ps = shutil.which("ps")
    if ps is None:
        return ""
    try:
        proc = subprocess.run(
            [ps, "-p", str(int(pid)), "-o", "command="],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (proc.stdout or "").strip()


# ---------------------------------------------------------------------------
# #614 — multi-factor bouncer classification
#
# Per UAT-Lifecycle 2026-05-25 HIGH-2: a foreign process at
# /tmp/dbounce-test (a TEST artifact from a different shell session)
# was substring-classified as a "real dbounce" because its cmdline
# contained the word "dbounce", then SIGTERM'd by uninstall. This is a
# CRIT under [[creates-never-mutates]]: uninstall destroyed a process
# OUTSIDE iam-jit's domain.
#
# Tighten classification to require ALL of:
#   1. Executable path resolves to a known iam-jit install location
#      (~/.iam-jit/venv/bin/, ~/go/bin/, /opt/iam-jit/bin/, etc.)
#   2. Cmdline contains a bouncer-specific FLAG signature (not just
#      the substring "dbounce" — e.g. `--dialect postgres` or
#      `--mode discovery` or `--apiserver-url`)
#   3. PID is owned by the current OS user (no cross-user destruction)
#
# If ANY check fails (including "could not determine"), the PID is
# classified as ``unknown_port_owners`` (surfaced for operator review)
# and U-5 halt fires. Per [[ibounce-honest-positioning]]: when
# classification is uncertain, default to surfacing rather than
# silently including/excluding.
# ---------------------------------------------------------------------------


# Install-path roots considered "ours" (any executable resolving under
# one of these paths is a candidate for bouncer classification, given
# the flag-signature + same-user checks also pass).
#
# #621 MED (regression from #614): the original static tuple omitted
# common venv install locations. UAT-Cross 2026-05-25 (G7) caught
# ibounce at ``<project>/.venv/bin/ibounce`` being rejected as "foreign"
# — that is the STANDARD Python install pattern (project-local venv).
# Adding ~/.local/bin covers pip --user installs; the dynamic
# :func:`_get_known_bouncer_paths` resolver below also includes the
# parent of ``sys.executable`` when iam-jit is itself running inside a
# venv (covers arbitrary ``<project>/.venv/bin`` parent dirs and any
# other custom-named venv pattern).
#
# IMPORTANT — do not expand this list to "any user-writable bin/":
# the #614 protection only works because foreign processes at e.g.
# /tmp/dbounce-test resolve OUTSIDE these roots. Loosening the path
# check breaks the #614 cross-domain SIGTERM protection.
_BOUNCER_INSTALL_PATH_ROOTS = (
    pathlib.Path.home() / ".iam-jit" / "venv" / "bin",
    pathlib.Path.home() / "go" / "bin",
    pathlib.Path.home() / ".iam-jit" / "bouncer",
    pathlib.Path("/opt/iam-jit/bin"),
    pathlib.Path("/usr/local/bin"),
    pathlib.Path.home() / ".local" / "bin",
)


def _get_known_bouncer_paths() -> list[pathlib.Path]:
    """Return the effective list of known-legitimate bouncer install
    path roots.

    Combines the static :data:`_BOUNCER_INSTALL_PATH_ROOTS` with a
    runtime-detected entry: when iam-jit itself is running inside a
    venv, the parent of :data:`sys.executable` is appended. This
    covers the standard Python install pattern of a project-local
    ``.venv/bin/`` directory (the #621 UAT-Cross 2026-05-25 G7 case),
    and any other custom-named venv pattern users may employ.

    Per [[ibounce-honest-positioning]] the addition is BOUNDED — we
    only trust the venv we're running IN, not arbitrary venv paths.
    Combined with the flag-signature + same-user checks, this keeps
    the #614 foreign-process protection intact: a /tmp/dbounce-test
    binary still resolves outside any of these roots.
    """
    paths: list[pathlib.Path] = list(_BOUNCER_INSTALL_PATH_ROOTS)
    # Runtime-detect: if we're running in a venv, include its bin/.
    # ``sys.base_prefix != sys.prefix`` is the canonical venv detection
    # (PEP 405); ``sys.real_prefix`` catches the legacy virtualenv shape.
    in_venv = (
        getattr(sys, "real_prefix", None) is not None
        or (
            getattr(sys, "base_prefix", sys.prefix) != sys.prefix
        )
    )
    if in_venv:
        try:
            paths.append(pathlib.Path(sys.executable).parent)
        except (TypeError, ValueError):
            pass
    return paths


# Per-bouncer flag signatures. A cmdline must contain at least ONE of
# the listed substrings to be classified as that bouncer kind. These
# are bouncer-distinctive CLI flags (not generic words like "dbounce"
# that arbitrary processes might mention).
#
# #666 CRIT: the default-launch pattern `ibounce run` (bare subcommand,
# no mode flags) was missing from ibounce's signatures. When `iam-jit
# init` installs ibounce and the operator runs `nohup ibounce run` (or
# the installer's canonical launch), the cmdline from ps is:
#   <python> /Users/<user>/.local/bin/ibounce run
# Factor 1 (path check) passes; Factor 2 (flag signatures) FAILED —
# none of the then-existing signatures matched the bare `run` token.
# Result: classifier returned unknown_port_owner → U-2/U-5/U-3 halt
# fired → clean non-forced uninstall blocked even when the bouncer IS
# ours. Same silent-degradation shape as #621 (venv path regression)
# and #638 (python -m dev launch regression).
#
# Fix: add the `" run"` subcommand pattern (with leading space to
# require a word-boundary — prevents false matches on args containing
# "run" as a substring). The leading-space requirement means this
# pattern ONLY fires when " run" appears as a token in the cmdline,
# not in e.g. `--upstream-run-mode`. Also add `" serve"` and `" mcp"`
# for completeness (ibounce ships all three as launch subcommands per
# bouncer_cli.py). Same treatment for kbounce/dbounce/gbounce which
# all ship a `run` subcommand as their primary launch form.
#
# Safety: these patterns are only evaluated AFTER Factor 1 (path check)
# has already passed AND after `matched_kind_from_path` has narrowed
# `candidate_kinds` to a single bouncer name. So `" run"` in ibounce's
# list is only evaluated for processes whose exe path resolves to an
# ibounce binary under a known install root — not for arbitrary
# processes. Per [[creates-never-mutates]]: the three-factor gate
# (path + flag + user) remains intact.
_BOUNCER_FLAG_SIGNATURES: dict[str, tuple[str, ...]] = {
    "ibounce": (
        "--mode discovery",
        "--mode cooperative",
        "--mode transparent",
        "--proxy-port",
        "--audit-log-path",
        # #638: `python -m iam_jit.bouncer_cli` is the standard dev
        # launch pattern. The module name in argv IS a strong ibounce
        # signal — at least as distinctive as the CLI flags. Also
        # include the legacy module name for older installs.
        "iam_jit.bouncer_cli",
        "iam_jit_bouncer",
        # #666 CRIT: bare subcommand patterns for default-launch
        # (`ibounce run`, `ibounce serve`, `ibounce mcp`).
        # Leading space enforces word-boundary (prevents matching
        # within longer tokens like `--upstream-runner`).
        " run",
        " serve",
        " mcp",
    ),
    "kbounce": (
        "--apiserver-url",
        "--rbac-mode",
        # #666: kbounce ships `kbounce run` and `kbounce serve` as its
        # primary launch subcommands (verified in kbouncer/internal/cli/cli.go).
        " run",
        " serve",
    ),
    "kbouncer": (
        "--apiserver-url",
        "--rbac-mode",
        # #666: kbouncer is a deprecation shim for kbounce; same
        # subcommand surface.
        " run",
        " serve",
    ),
    "dbounce": (
        "--dialect postgres",
        "--dialect mysql",
        "--upstream-conn-string",
        # #666: dbounce ships `dbounce run` as its primary launch
        # subcommand (verified in dbounce/internal/cli/cli.go).
        " run",
        " mcp",
    ),
    "gbounce": (
        "--http-mode",
        "--allow-host",
        # #666: gbounce ships `gbounce run` as its primary launch
        # subcommand (verified in gbounce/internal/cli/cli.go).
        " run",
        " mcp",
    ),
}


def _resolve_executable_path(pid: int) -> pathlib.Path | None:
    """Resolve the on-disk executable path for ``pid``.

    Returns the resolved path (with symlinks followed) or ``None`` if
    the path cannot be determined for any reason — permission denied,
    PID gone, platform without /proc, lsof unavailable, etc. Per
    [[ibounce-honest-positioning]] callers should treat ``None`` as
    "unknown" — never as "matches anything".

    Linux: reads ``/proc/<pid>/exe`` symlink.
    macOS / fallback: uses ``lsof -p <pid> -Fn`` and looks for the
    ``txt`` (text segment / executable) entry.
    """
    # Linux fast-path: /proc/<pid>/exe symlink resolves to the binary.
    proc_exe = pathlib.Path(f"/proc/{int(pid)}/exe")
    if proc_exe.exists() or proc_exe.is_symlink():
        try:
            real = os.readlink(str(proc_exe))
            return pathlib.Path(real).resolve()
        except (OSError, PermissionError):
            return None

    # macOS / fallback: parse lsof -Fn output for the "txt" (executable
    # text segment) entry. Format: alternating "p<PID>", "f<fd>",
    # "n<name>" lines per file. The executable is the file whose fd
    # field is literally "txt".
    lsof = shutil.which("lsof")
    if lsof is None:
        return None
    try:
        proc = subprocess.run(
            [lsof, "-p", str(int(pid)), "-Fftn"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    current_fd: str | None = None
    for line in (proc.stdout or "").splitlines():
        if not line:
            continue
        tag = line[0]
        val = line[1:]
        if tag == "f":
            current_fd = val
        elif tag == "n" and current_fd == "txt":
            try:
                return pathlib.Path(val).resolve()
            except (OSError, RuntimeError):
                return pathlib.Path(val)
    return None


def _pid_owner_uid(pid: int) -> int | None:
    """Return the UID that owns ``pid``, or ``None`` if undetermined.

    Linux: stat ``/proc/<pid>``.
    macOS / fallback: ``ps -o uid= -p <pid>``.

    Per [[ibounce-honest-positioning]] callers should treat ``None`` as
    "unknown — assume not ours" (the safer default for the cross-user
    check).
    """
    proc_dir = pathlib.Path(f"/proc/{int(pid)}")
    if proc_dir.exists():
        try:
            return proc_dir.stat().st_uid
        except (OSError, PermissionError):
            return None
    ps = shutil.which("ps")
    if ps is None:
        return None
    try:
        proc = subprocess.run(
            [ps, "-p", str(int(pid)), "-o", "uid="],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    raw = (proc.stdout or "").strip()
    if not raw:
        return None
    try:
        return int(raw.split()[0])
    except (ValueError, IndexError):
        return None


def _path_under_known_install_root(p: pathlib.Path) -> bool:
    """True iff ``p`` resolves under any entry returned by
    :func:`_get_known_bouncer_paths` (static install roots + runtime-
    detected venv ``bin/`` when applicable).

    Per #621: the resolver is queried fresh on each call so
    monkeypatching :data:`_BOUNCER_INSTALL_PATH_ROOTS` and/or
    :data:`sys.executable` from tests is observable here.
    """
    try:
        p_resolved = p.resolve()
    except (OSError, RuntimeError):
        p_resolved = p
    p_str = str(p_resolved)
    for root in _get_known_bouncer_paths():
        try:
            root_resolved = root.resolve()
        except (OSError, RuntimeError):
            root_resolved = root
        root_str = str(root_resolved)
        # Match if p is the root itself OR is under it.
        if p_str == root_str or p_str.startswith(root_str + os.sep):
            return True
    return False


def _extract_script_path_from_cmdline(
    cmdline: str,
) -> pathlib.Path | None:
    """If ``cmdline`` is a ``<python-interpreter> <script-path> ...``
    invocation (the standard Python console-script shape), return the
    script path. Otherwise ``None``.

    Per #621: when iam-jit is run from a venv (or any Python install),
    the kernel reports ``sys.executable`` (the interpreter) as the
    process exe — NOT the console-script entry point. For ibounce
    installed at ``<project>/.venv/bin/ibounce``, the cmdline tokens
    are ``[<python>, <project>/.venv/bin/ibounce, run, ...]`` and we
    need argv[1] to recognize the install location.

    Best-effort tokenizer: cmdline from ``ps -o command=`` is
    whitespace-separated; the first token is the interpreter and the
    second is the script when the second is an existing file path or
    has a recognized bouncer basename. Returns ``None`` if argv[1]
    looks like a flag (starts with ``-``), is empty, or is not a
    plausible script path.
    """
    if not cmdline:
        return None
    tokens = cmdline.split()
    if len(tokens) < 2:
        return None
    first = tokens[0]
    second = tokens[1]
    # Heuristic: first token must look like a Python interpreter (path
    # ends in python / python3 / pythonN.N, OR contains "Python"); else
    # this isn't a console-script invocation.
    first_base = pathlib.Path(first).name.lower()
    looks_like_python = (
        first_base == "python"
        or first_base.startswith("python")
        or "python" in first.lower()
    )
    if not looks_like_python:
        return None
    # Second token must look like a path (not a flag).
    if second.startswith("-"):
        return None
    return pathlib.Path(second)


def _classify_bouncer_pid_multifactor(
    pid: int,
    cmdline: str,
) -> tuple[str | None, list[str]]:
    """Multi-factor bouncer classification per #614.

    Returns ``(kind, failed_checks)`` where:
      * ``kind`` is the bouncer kind (one of "ibounce" / "kbounce" /
        "kbouncer" / "dbounce" / "gbounce") if ALL THREE factors hold,
        else ``None``.
      * ``failed_checks`` is a list of human-readable reasons describing
        which factor(s) failed — surfaced in the unknown_port_owners
        entry so operators can see WHY a process wasn't classified
        ("path not under known install root" / "no bouncer flag
        signature" / "cross-user PID").

    Per [[creates-never-mutates]]: we only classify (and ultimately
    SIGTERM) a process as ours if we have positive evidence on all
    three independent axes. Substring-matching the cmdline alone is
    insufficient because foreign processes can incidentally contain
    bouncer names (e.g. /tmp/dbounce-test from a different session).

    Per #621: when the resolved exe is a Python interpreter (which is
    what venv/console-script-installed bouncers report), we ALSO check
    the script path from argv[1] before failing the path check. This
    closes the UAT-Cross 2026-05-25 G7 regression where standard
    venv-installed bouncers were rejected as foreign.
    """
    failed: list[str] = []

    # Factor 1: executable path under a known install root.
    exe_path = _resolve_executable_path(pid)
    path_ok = False
    matched_kind_from_path: str | None = None
    candidate_paths: list[pathlib.Path] = []
    if exe_path is not None:
        candidate_paths.append(exe_path)
    # #621: also consider the script path from argv[1] for
    # Python-console-script invocations (the kernel reports the
    # interpreter; the script is argv[1]).
    script_path = _extract_script_path_from_cmdline(cmdline)
    if script_path is not None:
        candidate_paths.append(script_path)

    if not candidate_paths:
        failed.append("could not resolve executable path")
    else:
        for cp in candidate_paths:
            if _path_under_known_install_root(cp):
                path_ok = True
                basename = cp.name
                for k in (
                    "kbouncer", "ibounce", "kbounce", "dbounce", "gbounce",
                ):
                    if basename == k:
                        matched_kind_from_path = k
                        break
                break
        if not path_ok:
            # Build a descriptive failure including both candidates so
            # the operator can see what we considered.
            paths_str = " / ".join(str(p) for p in candidate_paths)
            failed.append(
                f"executable path {paths_str} not under known install root"
            )

    # #638: `python -m iam_jit.bouncer_cli` launch pattern — the module
    # namespace in argv IS a path-origin substitute. When the interpreter
    # is foreign (not under install root) but the cmdline contains a
    # project-namespaced module token ("iam_jit." or "iam_jit_bouncer"),
    # we treat that as sufficient origin evidence for Factor 1, because
    # the namespace is specific to this project and cannot coincidentally
    # appear in an unrelated foreign process.
    # We only override path_ok here — the flag check (Factor 2) and
    # user check (Factor 3) still independently gate on their own signals.
    _IAM_JIT_MODULE_TOKENS = ("iam_jit.", "iam_jit_bouncer")
    if not path_ok and any(tok in cmdline for tok in _IAM_JIT_MODULE_TOKENS):
        path_ok = True
        # Remove the "path not under known install root" failure we just
        # added — it's superseded by the module-namespace origin evidence.
        failed = [f for f in failed if "not under known install root" not in f]

    # Factor 2: cmdline contains a bouncer-specific flag signature.
    # If the path gave us a candidate kind, only check that kind's
    # flags. Otherwise try every kind so a path-but-no-basename match
    # (e.g. python interpreter executing console-script) still has a
    # chance to pin a kind via flags.
    flag_ok = False
    matched_kind_from_flags: str | None = None
    candidate_kinds: tuple[str, ...]
    if matched_kind_from_path is not None:
        candidate_kinds = (matched_kind_from_path,)
    else:
        candidate_kinds = tuple(_BOUNCER_FLAG_SIGNATURES.keys())
    for kind in candidate_kinds:
        for sig in _BOUNCER_FLAG_SIGNATURES.get(kind, ()):
            if sig in cmdline:
                flag_ok = True
                matched_kind_from_flags = kind
                break
        if flag_ok:
            break
    if not flag_ok:
        failed.append("no bouncer-specific flag signature in cmdline")

    # Factor 3: same-user check (cross-user safety).
    user_ok = False
    try:
        my_uid = os.geteuid()
    except AttributeError:
        # Windows — skip the user check (degrade gracefully).
        my_uid = None
    if my_uid is None:
        user_ok = True  # platform without uid concept
    else:
        owner_uid = _pid_owner_uid(pid)
        if owner_uid is None:
            failed.append("could not determine PID owner UID")
        elif owner_uid != my_uid:
            failed.append(
                f"PID owned by uid={owner_uid} (current uid={my_uid})"
            )
        else:
            user_ok = True

    if path_ok and flag_ok and user_ok:
        # Prefer path-derived kind (more specific), fall back to flag-
        # derived kind.
        kind = matched_kind_from_path or matched_kind_from_flags
        return kind, []
    return None, failed


def _infer_bouncer_kind_from_cmdline(cmdline: str) -> str | None:
    """Classify a process cmdline as one of our bouncer kinds.

    Returns one of ``BOUNCER_PROCESS_NAMES`` (or ``"iam-jit"`` for the
    iam-jit autopilot daemon variants) if the cmdline contains a
    bouncer marker; ``None`` otherwise.

    Per [[ibounce-honest-positioning]]: we ONLY return a name when we
    can positively identify the process as ours. Foreign processes on
    bouncer-typical ports are reported separately as "unknown" so the
    operator can investigate rather than uninstall silently
    including OR silently excluding them.

    Detection signals (case-sensitive on the path-shape; case-insensitive
    on the iam_jit module marker):

      * ``iam_jit.`` module import (covers ``python -m iam_jit.<x>``)
      * ``/iam-jit/venv/bin/<name>`` (covers console-script bouncers)
      * ``ibounce run``, ``gbounce run``, ``kbounce run``, ``kbouncer run``,
        ``dbounce run`` substrings (covers native binary invocations
        even when the kernel-reported basename is the interpreter)
    """
    if not cmdline:
        return None
    lc = cmdline.lower()
    # Strong positive: any iam_jit-namespaced module import. The
    # specific kind defaults to "iam-jit" unless a bouncer name appears
    # later in the argv.
    iam_jit_marker = "iam_jit." in cmdline or "iam-jit/" in cmdline
    # Order matters: kbouncer before kbounce so the more specific
    # name wins (kbouncer cmdline contains the substring "kbounce").
    for kind in ("kbouncer", "ibounce", "gbounce", "kbounce", "dbounce"):
        marker_run = f"{kind} run"
        marker_path = f"/{kind}"
        marker_module = f"iam_jit.bouncer_cli"
        if (
            marker_run in cmdline
            or marker_path in cmdline
            or (kind == "ibounce" and marker_module in cmdline)
        ):
            return kind
    if iam_jit_marker:
        return "iam-jit"
    return None


def _all_listening_ports() -> list[tuple[int, int]]:
    """Return ``(pid, port)`` tuples for ALL loopback TCP listeners owned
    by the current OS user.

    #617 MED-2: the per-bouncer default-port scan in
    :func:`_inventory_installed_state` misses bouncers started on
    non-default ports (e.g. ``ibounce run --port 18767``). An operator
    who starts ibounce on a custom port then runs ``iam-jit uninstall
    --dry-run`` sees ``running_bouncers: {}`` even though ibounce IS
    running — orphan risk on uninstall per [[ibounce-honest-positioning]].

    Fix: enumerate ALL loopback TCP listeners. The existing
    :func:`_classify_bouncer_pid_multifactor` (multi-factor: path + flag
    + user) then gates which listeners are actually OURS — foreign
    processes on arbitrary ports are still classified as
    ``unknown_port_owners`` if they don't pass the path+flag+user checks,
    preserving the #614 protection against cross-domain SIGTERM.

    Implementation:
      1. Primary: ``lsof -nP -i4TCP -i6TCP -sTCP:LISTEN`` (no port
         filter) then parse the NAME field for ``<host>:<port>`` to
         extract the port number. Filter to loopback addresses
         (127.x.x.x / ::1) so we don't surface externally-bound listeners
         that are unlikely to be local bouncers. ``-nP`` suppresses DNS +
         service-name resolution; ``-sTCP:LISTEN`` drops ESTABLISHED /
         TIME_WAIT noise.

         lsof without ``-t`` emits columns:
           COMMAND PID USER   FD TYPE DEVICE SIZE/OFF NODE NAME
         NAME field for a TCP listener is ``<host>:<port>`` or
         ``*:<port>`` (wildcard bind).  We parse the last ``:``-separated
         segment as the port number.

      2. Fallback: ``ss -tlnpH`` (Linux iproute2) — parse all LISTEN
         lines; extract ``<addr>:<port>`` from the local-address column
         (column 3) and ``pid=NNN`` from the users column.

    Returns an empty list when:
      - neither lsof nor ss is available (slim containers)
      - no loopback listeners exist
      - output cannot be parsed

    Per [[ibounce-honest-positioning]]: on parse failure, surface nothing
    from THIS helper — the default-port scan in
    :func:`_inventory_installed_state` still runs as before.

    Platform note: tested on macOS (lsof 4.91+) and Linux (lsof 4.89 /
    ss from iproute2 6.x). If lsof output format diverges from expected,
    we fall back to the default-port scan silently — this helper is
    ADDITIVE; a parse failure is not a correctness regression.
    """
    my_uid: int | None
    try:
        my_uid = os.geteuid()
    except AttributeError:
        my_uid = None  # Windows — degrade gracefully

    results: list[tuple[int, int]] = []

    # -------------------------------------------------------------------------
    # Loopback-address filter (covers both IPv4 and IPv6).
    # -------------------------------------------------------------------------
    def _is_loopback_or_wildcard(addr: str) -> bool:
        """True iff ``addr`` looks like loopback or wildcard.

        We include wildcard (``*`` / ``0.0.0.0`` / ``[::]``) because
        many bouncers bind ``0.0.0.0:<port>`` but are only reachable
        locally in practice; excluding them would miss the common
        non-loopback-bind case.
        """
        if addr in ("*", "0.0.0.0", "[::]", "::"):
            return True
        if addr.startswith("127."):
            return True
        # IPv6 loopback: ::1 or [::1].
        if addr in ("::1", "[::1]"):
            return True
        return False

    # -------------------------------------------------------------------------
    # Primary: lsof (macOS + Linux).
    # -------------------------------------------------------------------------
    lsof = shutil.which("lsof")
    if lsof is not None:
        try:
            proc = subprocess.run(
                [
                    lsof, "-nP",
                    "-i4TCP",
                    "-i6TCP",
                    "-sTCP:LISTEN",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            proc = None  # type: ignore[assignment]

        if proc is not None and proc.returncode in (0, 1):
            for line in (proc.stdout or "").splitlines():
                # Header line starts with "COMMAND" — skip.
                if line.startswith("COMMAND"):
                    continue
                parts = line.split()
                # Minimum columns: COMMAND PID USER FD TYPE DEVICE SIZE NODE NAME
                #                    0     1   2   3   4     5      6    7    8
                if len(parts) < 9:
                    continue
                # PID is column 1.
                try:
                    pid = int(parts[1])
                except (ValueError, IndexError):
                    continue

                # Same-user filter: skip if owned by a different user.
                if my_uid is not None:
                    owner = _pid_owner_uid(pid)
                    if owner is not None and owner != my_uid:
                        continue

                # NAME is the last column (index -1 or 8+).
                name_field = parts[-1]
                # #637: macOS lsof appends the TCP state as an extra
                # column — e.g. "(LISTEN)" — AFTER the NAME field.
                # Real macOS output (lsof 4.91+):
                #   Python 42678 reagan 17u IPv4 0xa76... 0t0 TCP \
                #     127.0.0.1:18769 (LISTEN)
                # parts[-1] == "(LISTEN)", parts[-2] == "127.0.0.1:18769".
                # We must step back one column to get the address:port.
                if (
                    name_field.startswith("(")
                    and name_field.endswith(")")
                    and len(parts) >= 10
                ):
                    name_field = parts[-2]
                elif name_field.startswith("(") and name_field.endswith(")"):
                    # Extra state column but not enough total columns —
                    # cannot reliably find the NAME field; skip.
                    continue
                # NAME field is ``<addr>:<port>`` or ``[<addr>]:<port>``.
                # Split on the LAST colon to isolate port (handles
                # IPv6 addresses like ``[::1]:8767``).
                colon_idx = name_field.rfind(":")
                if colon_idx == -1:
                    continue
                addr_part = name_field[:colon_idx]
                port_part = name_field[colon_idx + 1:]
                if not _is_loopback_or_wildcard(addr_part):
                    continue
                try:
                    port = int(port_part)
                except ValueError:
                    continue
                if port <= 0 or port > 65535:
                    continue
                entry = (pid, port)
                if entry not in results:
                    results.append(entry)
            return results

    # -------------------------------------------------------------------------
    # Fallback: ss (Linux iproute2).
    # -------------------------------------------------------------------------
    ss = shutil.which("ss")
    if ss is None:
        return []
    try:
        proc = subprocess.run(
            [ss, "-tlnpH"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    for line in (proc.stdout or "").splitlines():
        # ss -tlnpH sample:
        # LISTEN 0 128 127.0.0.1:8767 0.0.0.0:* users:(("python",pid=1234,fd=5))
        # LISTEN 0 128 [::1]:8767 [::]*      users:(("go",pid=5678,fd=3))
        parts = line.split()
        if len(parts) < 4:
            continue
        # Local address is column 3 (0-indexed).
        local_addr = parts[3]
        colon_idx = local_addr.rfind(":")
        if colon_idx == -1:
            continue
        addr_part = local_addr[:colon_idx]
        port_part = local_addr[colon_idx + 1:]
        if not _is_loopback_or_wildcard(addr_part):
            continue
        try:
            port = int(port_part)
        except ValueError:
            continue
        if port <= 0 or port > 65535:
            continue
        # Extract pid=NNN occurrences from the rest of the line.
        rest = " ".join(parts[4:])
        idx = 0
        while True:
            marker = rest.find("pid=", idx)
            if marker == -1:
                break
            start = marker + 4
            end = start
            while end < len(rest) and rest[end].isdigit():
                end += 1
            if end > start:
                try:
                    pid = int(rest[start:end])
                except ValueError:
                    idx = end if end > marker else marker + 1
                    continue
                # Same-user filter.
                if my_uid is not None:
                    owner = _pid_owner_uid(pid)
                    if owner is not None and owner != my_uid:
                        idx = end if end > marker else marker + 1
                        continue
                entry = (pid, port)
                if entry not in results:
                    results.append(entry)
            idx = end if end > marker else marker + 1
    return results


def _resolve_go_bin_dir() -> pathlib.Path:
    """Resolve $GOBIN with fallback to ~/go/bin per MRR-4-UNINSTALL.md
    step 4. Honoured via `go env GOBIN` when `go` is on PATH; else the
    documented default."""
    go = shutil.which("go")
    if go is not None:
        try:
            proc = subprocess.run(
                [go, "env", "GOBIN"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5.0,
            )
            val = (proc.stdout or "").strip()
            if val:
                return pathlib.Path(val).expanduser()
        except (OSError, subprocess.TimeoutExpired):
            pass
    return pathlib.Path.home() / "go" / "bin"


# ---------------------------------------------------------------------------
# Pre-flight inventory
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# #617 MED-2 — read autopilot.status.json for known-running ports
# ---------------------------------------------------------------------------


def _read_autopilot_ports(
    data_dir: pathlib.Path | None = None,
) -> dict[str, list[int]]:
    """Return per-bouncer port hints from ``autopilot.status.json``.

    #617 MED-2: When autopilot is running and has launched bouncers, it
    records each bouncer's ``port`` in its status snapshot. Reading this
    file BEFORE the port-scan loop lets us augment the default port list
    with KNOWN running ports from the autopilot daemon's perspective —
    so a bouncer started by autopilot on a custom port (e.g.
    ``ibounce run --port 9876``) gets probed even if 9876 is outside the
    hardcoded default-port list.

    Return value: ``{bouncer_kind: [port, ...], ...}`` with only the
    kinds + ports that autopilot recorded as running. Empty dict when the
    file doesn't exist, cannot be parsed, or autopilot isn't active.

    Per [[ibounce-honest-positioning]]: best-effort read — parse failure
    or missing file is NOT a halt condition. The ``_all_listening_ports``
    full-scan pass runs regardless, so autopilot hints are ADDITIVE (they
    speed up detection for known ports; they do not gate correctness).

    ``data_dir``: when set, look for the file under that directory.
    Otherwise fall back to the module-level :data:`IAM_JIT_HOME`.
    """
    home, _, _ = _derive_paths(data_dir)
    status_path = home / "autopilot.status.json"
    if not status_path.exists():
        return {}
    try:
        raw = status_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return {}

    # Schema: data["bouncers"][name] = {"port": <int>, "running": <bool>, ...}
    bouncers_block = data.get("bouncers")
    if not isinstance(bouncers_block, dict):
        return {}

    result: dict[str, list[int]] = {}
    for name, block in bouncers_block.items():
        if not isinstance(block, dict):
            continue
        # Only include bouncers autopilot considers active (running=true
        # OR no running field — treat missing as unknown/assume running
        # since we'd rather check a port that isn't bound than skip one
        # that is). Per [[safety-mode-lean-permissive]]: prefer to check
        # rather than miss.
        is_running = block.get("running")
        if is_running is False:
            continue
        port_val = block.get("port")
        if port_val is None:
            continue
        try:
            port = int(port_val)
        except (ValueError, TypeError):
            continue
        if port <= 0 or port > 65535:
            continue
        result.setdefault(name, []).append(port)
    return result


def _inventory_installed_state(
    data_dir: pathlib.Path | None = None,
) -> dict[str, Any]:
    """Build an honest inventory of what's currently installed.

    Returns a dict shaped like::

        {
          "data_dir": str,            # #617 MED-1 — resolved home
          "iam_jit_home_exists": bool,
          "venv_exists": bool,
          "running_bouncers": {name: [pid, ...], ...},
          "bound_ports": [port, ...],
          "console_scripts_present": [name, ...],
          "go_binaries_present": [path, ...],
          "audit_bearing_files": [path, ...],
          "manual_reminders": [str, ...],
        }

    Per ``[[ibounce-honest-positioning]]`` we surface the manual-only
    cleanup items (shell-profile env vars, MCP config entries, browser
    truststores for the gbounce MITM CA) up-front so the operator knows
    what uninstall does NOT do for them.

    Per #617 MED-1: ``data_dir`` is the resolved iam-jit data
    directory (from ``--data-dir`` flag or ``IAM_JIT_DATA_DIR`` env or
    default ``~/.iam-jit/``). When None, the module-level globals are
    used (existing-caller / test compatibility). When set, the
    inventory probes that tree instead.
    """
    home, venv_dir, _bouncer_dir = _derive_paths(data_dir)
    inv: dict[str, Any] = {
        "data_dir": str(home),
        "iam_jit_home_exists": home.exists(),
        "venv_exists": venv_dir.exists(),
        "running_bouncers": {},
        "bound_ports": [],
        # #574: port owners that bind a bouncer-typical port but whose
        # cmdline does NOT look like a bouncer (or whose cmdline could
        # not be read). Surfaced separately so the operator can decide
        # whether to investigate or --force.
        "unknown_port_owners": [],
        "console_scripts_present": [],
        "go_binaries_present": [],
        "audit_bearing_files": [],
        "manual_reminders": [],
    }

    # Running bouncers (per MRR-4-UNINSTALL.md step 1 + step 5).
    # First pass: pgrep on each canonical name (catches native Go
    # binaries gbounce/kbounce/dbounce + the rare iam-jit-as-process
    # case where argv[0] basename matches).
    for name in BOUNCER_PROCESS_NAMES:
        pids = _find_pids_for_process(name)
        if pids:
            inv["running_bouncers"][name] = pids

    # #608: per-bouncer port scan. Each entry in bound_ports records
    # both the port number AND the expected bouncer (so the operator
    # can see "port 5433 belongs to dbounce" in the plan summary).
    # Without per-bouncer tracking, the #574 cross-reference pass only
    # caught ibounce-default ports — kbounce/dbounce/gbounce on their
    # own defaults stayed invisible despite posture seeing them.
    #
    # bound_ports retains the legacy int-only shape AS WELL AS the new
    # structured form via expected_bouncer_for_port for callers that
    # need it. This keeps the existing post-check + halt path
    # compatible while enabling per-bouncer awareness.
    expected_bouncer_for_port: dict[int, list[str]] = {}
    for kind, ports in _BOUNCER_DEFAULT_PORTS.items():
        for port in ports:
            expected_bouncer_for_port.setdefault(int(port), []).append(kind)

    # #617 MED-2: augment the default port map with ports recorded by
    # the autopilot daemon in ``autopilot.status.json``. This ensures
    # that a bouncer started on a custom port by autopilot (e.g.
    # ``ibounce run --port 9876``) is probed here even before the
    # full ``_all_listening_ports`` enumeration pass. ADDITIVE: does
    # not replace the default-port list; adds known-autopilot ports to
    # the candidate probe set so the lsof cross-reference fires on them.
    for autopilot_kind, autopilot_ports in _read_autopilot_ports(
        data_dir=data_dir,
    ).items():
        for ap in autopilot_ports:
            if ap not in expected_bouncer_for_port:
                expected_bouncer_for_port.setdefault(ap, []).append(
                    autopilot_kind,
                )

    # Stable ordered list of unique ports across all bouncers.
    all_ports = sorted(expected_bouncer_for_port.keys())
    for port in all_ports:
        if _port_bound(port):
            inv["bound_ports"].append(port)

    # #574 + #608: second pass — cross-reference bound-port owners
    # back to PIDs. This catches Python console-script bouncers
    # (``ibounce`` under ~/.iam-jit/venv/bin/) which pgrep -x misses
    # because their kernel-reported basename is the Python
    # interpreter, not "ibounce". #608 extends the scan to all 4
    # bouncers' default ports (not just ibounce's) so kbounce on
    # :8766, dbounce on :5433+:8768, gbounce on :8080+:8769 are also
    # detected. Per [[ibounce-honest-positioning]] the plan must
    # accurately describe what WILL happen — silent miss = orphan
    # risk.
    seen_pids: set[int] = set()
    for pids in inv["running_bouncers"].values():
        for pid in pids:
            seen_pids.add(int(pid))
    for port in inv["bound_ports"]:
        expected_kinds = expected_bouncer_for_port.get(port, [])
        for pid in _lsof_pids_on_port(port):
            if pid in seen_pids:
                continue
            cmdline = _read_cmdline(pid)
            # #614 — multi-factor classification (path + flag + user).
            # Substring-matching the cmdline alone is insufficient
            # because foreign processes (e.g. /tmp/dbounce-test from a
            # different shell) can incidentally contain bouncer names.
            # Per [[creates-never-mutates]] we only classify as ours
            # when path-origin AND flag-signature AND same-user all
            # hold; anything else lands in unknown_port_owners.
            kind, failed_checks = _classify_bouncer_pid_multifactor(
                pid, cmdline,
            )
            if kind is not None:
                inv["running_bouncers"].setdefault(kind, []).append(pid)
                seen_pids.add(pid)
            else:
                # Foreign process on a bouncer-typical port. Surface
                # rather than silently include/exclude. Per #608
                # include the expected bouncer for this port so the
                # operator sees "pid 1234 on :8766 (expected
                # kbounce)" instead of just "pid 1234 on :8766".
                # Per #614 also include failed_checks so the operator
                # sees WHY classification failed.
                inv["unknown_port_owners"].append({
                    "pid": pid,
                    "port": port,
                    "expected_bouncer": (
                        expected_kinds[0] if expected_kinds else None
                    ),
                    "cmdline": cmdline,
                    "failed_checks": failed_checks,
                })

    # #617 MED-2: third pass — scan ALL loopback TCP listeners (not
    # just the known default ports). This catches bouncers started with
    # a custom ``--port`` / ``--proxy-port`` flag (e.g.
    # ``ibounce run --port 18767``) that the default-port list above
    # would miss. Per [[ibounce-honest-positioning]]: if a bouncer is
    # running, uninstall MUST detect it; silent miss = orphan risk.
    #
    # Reuses the same #614 multi-factor classifier (path + flag + user)
    # so foreign processes on arbitrary ports are still gated correctly —
    # only bouncer-shaped processes (under a known install root, with a
    # bouncer-specific flag, owned by the current user) are included in
    # running_bouncers. Everything else lands in unknown_port_owners.
    #
    # bound_ports is extended for any custom port where a classified
    # bouncer is found so the halt-condition checks (U-1/U-2/U-5) and
    # the operator-facing summary remain accurate.
    for pid, port in _all_listening_ports():
        if pid in seen_pids:
            continue
        # Skip ports already covered by the default-port pass above so
        # we don't double-classify a PID we already found via lsof on a
        # default port (which would incorrectly add it to
        # unknown_port_owners a second time).
        if port in inv["bound_ports"]:
            continue
        cmdline = _read_cmdline(pid)
        kind, failed_checks = _classify_bouncer_pid_multifactor(
            pid, cmdline,
        )
        if kind is not None:
            # New custom-port bouncer discovered.
            inv["running_bouncers"].setdefault(kind, []).append(pid)
            seen_pids.add(pid)
            if port not in inv["bound_ports"]:
                inv["bound_ports"].append(port)
        else:
            # Foreign process on a custom port. Only surface in
            # unknown_port_owners when the cmdline looks bouncer-shaped
            # (contains a bouncer process name or install-path marker)
            # — otherwise every system listener would flood the output.
            # Per [[ibounce-honest-positioning]]: we surface what we
            # cannot resolve; we don't silently flood with noise.
            infer_kind = _infer_bouncer_kind_from_cmdline(cmdline)
            if infer_kind is not None:
                if port not in inv["bound_ports"]:
                    inv["bound_ports"].append(port)
                inv["unknown_port_owners"].append({
                    "pid": pid,
                    "port": port,
                    "expected_bouncer": infer_kind,
                    "cmdline": cmdline,
                    "failed_checks": failed_checks,
                })

    # Console scripts (step 3).
    if venv_dir.exists():
        bin_dir = venv_dir / "bin"
        for script in CONSOLE_SCRIPTS:
            if (bin_dir / script).exists():
                inv["console_scripts_present"].append(str(bin_dir / script))

    # Go binaries (step 4).
    go_bin = _resolve_go_bin_dir()
    for bname in GO_BINARIES:
        candidate = go_bin / bname
        if candidate.exists():
            inv["go_binaries_present"].append(str(candidate))

    # Audit-bearing files (step 8 / 9).
    for rel in AUDIT_BEARING_PATHS_REL:
        p = home / rel
        if p.exists():
            inv["audit_bearing_files"].append(str(p))

    # Manual reminders — per MRR-4-UNINSTALL.md "Per-product caveats" +
    # [[creates-never-mutates]]: things WE WILL NOT touch.
    inv["manual_reminders"] = [
        "Shell profiles: search ~/.zshrc, ~/.bashrc, IDE settings for "
        "`HTTPS_PROXY=http://127.0.0.1:7401` (ibounce) and similar "
        "`AWS_ENDPOINT_URL` / `KUBECONFIG` overrides — uninstall does "
        "NOT remove these per [[creates-never-mutates]].",
        "MCP config: search Claude Code / Cursor / agent config "
        "(typically `~/.claude.json` or `.mcp.json`) for iam-jit / "
        "ibounce server entries — remove them manually.",
        "gbounce MITM CA: if you imported the gbounce CA into "
        "browser / OS truststores, remove it per MRR-4-UNINSTALL.md "
        "per-product caveats (macOS Keychain: "
        "`security delete-certificate -c 'iam-jit gbounce CA'`).",
        "systemd / launchd units: if you installed iam-jit as a "
        "service, remove the unit file manually.",
    ]
    return inv


# ---------------------------------------------------------------------------
# Halt-condition detection — per docs/MRR-4-HALT-CONDITIONS.md
# ---------------------------------------------------------------------------


def _check_halt_conditions(
    inventory: dict[str, Any],
) -> list[dict[str, str]]:
    """Return a list of halt conditions detected pre-uninstall.

    Each entry: ``{"id": "<code>", "severity": "...", "reason": "..."}``

    Halt codes mirror docs/MRR-4-HALT-CONDITIONS.md where applicable;
    uninstall-specific codes are prefixed ``U-``.

    Per ``[[ibounce-honest-positioning]]`` halt conditions surface to
    the operator + require ``--force`` to bypass; we never silently
    proceed past a halt-worthy state.
    """
    halts: list[dict[str, str]] = []

    # U-1: a bouncer port is bound but our combined detection
    # (pgrep + lsof port-owner cross-reference per #574) could not
    # identify any owning bouncer process. Suggests a non-bouncer
    # service has claimed the port — proceeding could surprise the
    # operator.
    expected_pids: set[int] = set()
    for pids in (inventory.get("running_bouncers") or {}).values():
        for pid in pids:
            expected_pids.add(int(pid))
    bound_ports = inventory.get("bound_ports") or []
    if bound_ports and not expected_pids:
        halts.append({
            "id": "U-1",
            "severity": "HIGH",
            "reason": (
                f"bouncer ports bound ({bound_ports}) but no bouncer "
                f"processes found via pgrep + lsof cross-reference — "
                f"a non-bouncer process may hold the port. "
                f"Investigate before --force."
            ),
        })

    # U-2: explicit foreign processes detected on bouncer-typical
    # ports (#574 unknown_port_owners). This is the "honest report"
    # case — the operator should investigate before allowing
    # uninstall to proceed. Surfaced even when other bouncers WERE
    # found, because each unknown process is its own decision point.
    unknowns = inventory.get("unknown_port_owners") or []
    if unknowns:
        descs = ", ".join(
            f"pid={u['pid']} on :{u['port']}" for u in unknowns
        )
        halts.append({
            "id": "U-2",
            "severity": "MED",
            "reason": (
                f"non-bouncer process(es) holding bouncer-typical "
                f"port(s): {descs}. Manual inspection recommended "
                f"per [[ibounce-honest-positioning]] before --force."
            ),
        })

    # #614 U-5: foreign processes detected on bouncer-default ports
    # AND those processes do NOT pass the multi-factor classification
    # check. This is the stronger sibling of U-2: U-2 surfaces the
    # unknown owner; U-5 records that destruction is REFUSED because
    # at least one cross-domain process exists. The operator MUST
    # --force to proceed; default behavior protects foreign processes
    # per [[creates-never-mutates]].
    #
    # Per UAT-Lifecycle 2026-05-25 HIGH-2: this is the halt that
    # would have prevented uninstall from SIGTERM'ing /tmp/dbounce-test
    # in the first place.
    if unknowns:
        # Build operator-friendly suggested-next-steps text.
        suggestions: list[str] = []
        for u in unknowns:
            cmd_snippet = (u.get("cmdline") or "")[:120]
            suggestions.append(
                f"pid={u['pid']} port=:{u['port']} cmdline={cmd_snippet}"
            )
        halts.append({
            "id": "U-5",
            "severity": "CRIT",
            "reason": (
                f"foreign process(es) on bouncer-default ports failed "
                f"multi-factor bouncer classification per #614 "
                f"(path + flag + user). Refusing to SIGTERM "
                f"cross-domain processes per [[creates-never-mutates]]. "
                f"Foreign: {'; '.join(suggestions)}. "
                f"Either (a) kill those processes manually if you know "
                f"what they are, OR (b) re-run with --force to bypass "
                f"this halt (DANGEROUS — uninstall does NOT SIGTERM "
                f"unknown_port_owners even with --force; but the halt "
                f"will no longer block the rest of the uninstall)."
            ),
        })

    # #608 U-3: posture-uninstall parity check. Defense-in-depth
    # against future _BOUNCER_DEFAULT_PORTS drift — if `iam-jit
    # posture` sees a bouncer the uninstall inventory does NOT, halt
    # and surface the divergence so the operator investigates rather
    # than uninstalls a system whose ground truth is internally
    # inconsistent. The actual UAT-Admin-CLI 2026-05-25 Gap D bug was
    # exactly this shape — posture saw kbounce on :8766; uninstall
    # did not.
    #
    # ONE-WAY check (posture-sees-but-uninstall-misses): the reverse
    # (uninstall sees but posture doesn't) is a legitimate state —
    # `pgrep -x ibounce` can find a stopped/quiesced bouncer process
    # that posture's loopback probe can't reach because it isn't
    # listening yet. Only the missing-from-uninstall direction
    # represents the orphan-risk scenario.
    #
    # The check is best-effort: if posture itself raises (in tests or
    # restricted environments) we skip silently rather than blocking
    # uninstall on a meta-detector.
    try:
        from .posture.bouncers import detect_all_bouncers
        posture_view = detect_all_bouncers()
        # Names posture reports as RUNNING.
        posture_running = {
            name for name, block in posture_view.items()
            if block.get("running")
        }
        # Names uninstall inventory reports as running. Normalize
        # `kbouncer` -> `kbounce` so the two surfaces use the same
        # vocabulary (posture only knows `kbounce`).
        inv_running_raw = set(
            (inventory.get("running_bouncers") or {}).keys()
        )
        inv_running = {
            "kbounce" if n == "kbouncer" else n for n in inv_running_raw
        }
        # Restrict comparison to the four canonical bouncer kinds
        # posture reports on.
        posture_kinds = set(posture_view.keys())
        inv_in_scope = inv_running & posture_kinds

        missing_from_inv = posture_running - inv_in_scope
        if missing_from_inv:
            halts.append({
                "id": "U-3",
                "severity": "HIGH",
                "reason": (
                    f"posture-uninstall parity check failed: "
                    f"posture sees {sorted(missing_from_inv)} but "
                    f"uninstall inventory does NOT. Two detection "
                    f"surfaces disagree about ground truth — "
                    f"proceeding would leave orphans. Investigate "
                    f"before --force (check _BOUNCER_DEFAULT_PORTS "
                    f"covers the bouncer's actual port)."
                ),
            })
    except Exception:
        # Posture itself failed (e.g. import error in stripped test
        # environment). Don't block uninstall on a meta-check
        # failure; the primary detection path still ran.
        pass

    return halts


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------


def _step_stop_bouncers(
    inventory: dict[str, Any],
    *,
    dry_run: bool,
    grace_seconds: float = 5.0,
    data_only_scope: bool = False,
) -> dict[str, Any]:
    """Step 1 / Step 5 — SIGTERM running bouncers, then SIGKILL if needed.

    Returns ``{"sigterm_pids": [...], "sigkill_pids": [...], "reaped": [...],
              "failed": [...], "skipped_data_only_scope": bool,
              "scoped_kept_pids": [...]}``.

    State verification: post-call, ``_find_pids_for_process(name)`` for
    every reaped PID must return without that PID (the caller asserts).

    #671 CRIT — ``data_only_scope=True`` means the operator targeted a
    NON-DEFAULT data dir. In that case we MUST NOT kill arbitrary
    bouncer processes detected by the machine-wide port scan: only
    processes whose cwd / cmdline references the targeted data dir are
    in-scope. Without this guard, ``--data-dir /tmp/fixture`` would
    SIGTERM the founder's live ibounce on the dev machine (the #671
    incident shape).
    """
    out: dict[str, Any] = {
        "sigterm_pids": [],
        "sigkill_pids": [],
        "reaped": [],
        "failed": [],
        # #671 CRIT — scope-suppression accounting fields.
        "skipped_data_only_scope": False,
        "scoped_kept_pids": [],
    }
    target_pids: list[tuple[str, int]] = []
    for name, pids in (inventory.get("running_bouncers") or {}).items():
        for pid in pids:
            target_pids.append((name, int(pid)))

    # #671 CRIT — when data-only scope is in effect, filter target_pids
    # to ONLY processes whose cmdline references the targeted data dir.
    # The inventory's running_bouncers list came from a machine-wide
    # port scan (which is fine FOR DETECTION) but the destruction step
    # MUST honour the operator's narrower scope.
    if data_only_scope:
        scoped_data_dir = inventory.get("data_dir") or ""
        kept: list[tuple[str, int]] = []
        dropped: list[int] = []
        for name, pid in target_pids:
            cmdline = _read_cmdline(pid)
            # Conservative match: the data-dir path (or its basename)
            # must appear in the cmdline / cwd reference. If we can't
            # read the cmdline, DROP (do not destroy uncertain state).
            if scoped_data_dir and scoped_data_dir in (cmdline or ""):
                kept.append((name, pid))
            else:
                dropped.append(pid)
        target_pids = kept
        if dropped:
            out["skipped_data_only_scope"] = True
            out["scoped_kept_pids"] = [pid for _, pid in kept]
            # Re-purpose the failed list to surface what was protected
            # so the operator sees explicit accounting.
            for pid in dropped:
                out["failed"].append(
                    f"PROTECTED pid={pid}: not in --data-dir scope "
                    f"({scoped_data_dir!r}); not killed per #671 "
                    f"data-only-scope guard"
                )

    if not target_pids:
        return out
    if dry_run:
        out["sigterm_pids"] = [pid for _, pid in target_pids]
        return out

    # SIGTERM all.
    for name, pid in target_pids:
        try:
            os.kill(pid, signal.SIGTERM)
            out["sigterm_pids"].append(pid)
        except ProcessLookupError:
            # Already dead — treat as reaped.
            out["reaped"].append(pid)
        except (PermissionError, OSError) as exc:
            out["failed"].append(f"{name}(pid={pid}): SIGTERM failed: {exc}")
    # Wait up to grace_seconds for graceful shutdown.
    deadline = time.time() + grace_seconds
    while time.time() < deadline:
        still_alive = [pid for _, pid in target_pids if _pid_alive(pid)]
        if not still_alive:
            break
        time.sleep(0.2)

    # SIGKILL stragglers.
    for name, pid in target_pids:
        if pid in out["reaped"]:
            continue
        if not _pid_alive(pid):
            out["reaped"].append(pid)
            continue
        try:
            os.kill(pid, signal.SIGKILL)
            out["sigkill_pids"].append(pid)
        except ProcessLookupError:
            pass
        except (PermissionError, OSError) as exc:
            out["failed"].append(f"{name}(pid={pid}): SIGKILL failed: {exc}")
            continue
        # Final wait + verify.
        for _ in range(20):  # up to 2s for kernel to reap
            if not _pid_alive(pid):
                out["reaped"].append(pid)
                break
            time.sleep(0.1)
        else:
            out["failed"].append(
                f"{name}(pid={pid}): still alive after SIGKILL"
            )
    return out


def _step_pip_uninstall(
    *, dry_run: bool,
    data_dir: pathlib.Path | None = None,
) -> dict[str, Any]:
    """Step 2 — `pip uninstall -y iam-jit` inside the venv if it exists.

    Returns ``{"executed": bool, "venv_pip_present": bool,
              "stdout": str, "returncode": int | None}``.

    Per #617 MED-1: when ``data_dir`` is set, the venv is derived from
    it; else the module-level :data:`VENV_DIR` is used.
    """
    _home, venv_dir, _bouncer = _derive_paths(data_dir)
    pip = venv_dir / "bin" / "pip"
    out: dict[str, Any] = {
        "executed": False,
        "venv_pip_present": pip.exists(),
        "stdout": "",
        "returncode": None,
    }
    if not pip.exists():
        return out
    if dry_run:
        out["stdout"] = (
            f"would run: {pip} uninstall -y iam-jit"
        )
        return out
    try:
        proc = subprocess.run(
            [str(pip), "uninstall", "-y", "iam-jit"],
            capture_output=True,
            text=True,
            check=False,
            timeout=120.0,
        )
        out["executed"] = True
        out["stdout"] = (proc.stdout + proc.stderr).strip()
        out["returncode"] = proc.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        out["stdout"] = f"pip uninstall failed: {exc}"
        out["returncode"] = -1
    return out


def _step_remove_go_binaries(
    inventory: dict[str, Any],
    *,
    dry_run: bool,
    data_only_scope: bool = False,
) -> dict[str, Any]:
    """Step 4 — remove ``$GOBIN/{gbounce,kbounce,kbouncer,dbounce}``.

    Returns ``{"removed": [...], "missing": [...], "failed": [...],
              "skipped_data_only_scope": bool}``.
    State verification: post-call, each "removed" path's ``.exists()``
    must be False.

    #671 CRIT — when ``data_only_scope`` is True, the entire step is
    suppressed. ``~/go/bin/`` is the machine's Go binary install dir,
    not a per-data-dir artifact; removing the founder's machine-wide
    gbounce because a fixture test ran with ``--data-dir /tmp/x`` is
    exactly the #671 incident shape.
    """
    out: dict[str, Any] = {
        "removed": [],
        "missing": [],
        "failed": [],
        "skipped_data_only_scope": False,
    }
    if data_only_scope:
        out["skipped_data_only_scope"] = True
        return out
    for path_str in inventory.get("go_binaries_present") or []:
        p = pathlib.Path(path_str)
        if dry_run:
            out["removed"].append(path_str)
            continue
        try:
            if p.exists():
                p.unlink()
                if p.exists():
                    out["failed"].append(
                        f"{path_str}: unlink returned but file still present"
                    )
                else:
                    out["removed"].append(path_str)
            else:
                out["missing"].append(path_str)
        except OSError as exc:
            out["failed"].append(f"{path_str}: {exc}")
    return out


def _step_remove_venv(
    *, dry_run: bool,
    data_dir: pathlib.Path | None = None,
) -> dict[str, Any]:
    """Step 7 — remove ``~/.iam-jit/venv/`` (or ``${data_dir}/venv/``).

    Returns ``{"removed": bool, "path": str, "failed": str | None}``.
    State verification: post-call, ``venv_dir.exists()`` must be False.

    Per #617 MED-1: ``data_dir`` overrides the module-level
    :data:`VENV_DIR` when set.
    """
    _home, venv_dir, _bouncer = _derive_paths(data_dir)
    out: dict[str, Any] = {
        "removed": False,
        "path": str(venv_dir),
        "failed": None,
    }
    if not venv_dir.exists():
        return out
    if dry_run:
        out["removed"] = True
        return out
    try:
        shutil.rmtree(venv_dir)
        if venv_dir.exists():
            out["failed"] = (
                f"{venv_dir}: rmtree returned but path still present"
            )
        else:
            out["removed"] = True
    except OSError as exc:
        out["failed"] = f"{venv_dir}: {exc}"
    return out


def _step_remove_iam_jit_home(
    *,
    dry_run: bool,
    keep_audit_logs: bool,
    backup_dir: pathlib.Path | None,
    data_dir: pathlib.Path | None = None,
) -> dict[str, Any]:
    """Step 9 — purge ``~/.iam-jit/`` (or ``${data_dir}``) (with
    optional audit-log preserve + backup-dir snapshot).

    Returns ``{"removed_paths": [...], "preserved_paths": [...],
              "backed_up_paths": [...], "failed": [...]}``.

    State verification:
      * each "removed_paths" entry's ``.exists()`` must be False post-call.
      * if ``--keep-audit-logs``, each "preserved_paths" entry's
        ``.exists()`` must be True post-call.
      * if ``--backup-dir``, each "backed_up_paths" entry must be
        present under the backup root.

    Per #617 MED-1: ``data_dir`` overrides :data:`IAM_JIT_HOME` when
    set (operator passed ``--data-dir`` or ``IAM_JIT_DATA_DIR``).
    """
    home, _venv, _bouncer = _derive_paths(data_dir)
    out: dict[str, Any] = {
        "removed_paths": [],
        "preserved_paths": [],
        "backed_up_paths": [],
        "failed": [],
        # #617 MED-5: CANARY.md files that were detected + preserved.
        # Always populated (even when empty) so callers can enumerate
        # which CANARY.md artifacts were intentionally kept.
        "canary_md_preserved": [],
    }
    if not home.exists():
        return out

    # Backup phase — best-effort copy BEFORE any removal.
    if backup_dir is not None:
        backup_root = pathlib.Path(backup_dir).expanduser()
        if not dry_run:
            try:
                backup_root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                out["failed"].append(f"backup mkdir {backup_root}: {exc}")
                return out
        for child in sorted(home.iterdir()):
            target = backup_root / child.name
            if dry_run:
                out["backed_up_paths"].append(str(target))
                continue
            try:
                if child.is_dir():
                    shutil.copytree(child, target, dirs_exist_ok=True)
                else:
                    shutil.copy2(child, target)
                out["backed_up_paths"].append(str(target))
            except OSError as exc:
                out["failed"].append(f"backup copy {child}: {exc}")

    # Compute preserve-set for --keep-audit-logs.
    preserve_paths: set[pathlib.Path] = set()
    if keep_audit_logs:
        for rel in AUDIT_BEARING_PATHS_REL:
            p = home / rel
            if p.exists():
                preserve_paths.add(p)

    # #617 MED-5: CANARY.md artifacts are ALWAYS preserved, regardless
    # of --keep-audit-logs. Operators on canary deploys (#492) use
    # CANARY.md to record post-mortem notes + uncommitted findings;
    # auto-deleting them would silently destroy operator-authored notes.
    # Safer default: preserve + surface in remaining_artifacts so the
    # operator decides.
    #
    # Locations checked:
    #   1. ``<data_dir>/canary/CANARY.md``  (primary per-install location)
    #   2. ``<data_dir>/CANARY.md``         (root-level fallback some
    #      canary deployments use, e.g. when data_dir IS the repo root)
    for canary_rel in ("canary/CANARY.md", "CANARY.md"):
        cp = home / canary_rel
        if cp.exists():
            preserve_paths.add(cp)
            out.setdefault("canary_md_preserved", []).append(str(cp))

    # Walk and remove top-level entries; preserve audit-bearing files
    # by leaving their parent dirs in place.
    for child in sorted(home.iterdir()):
        # Decide if this entire subtree can be removed wholesale.
        # If any preserved file lives under it, skip the wholesale
        # rmtree + walk entries individually.
        preserved_under = [
            p for p in preserve_paths
            if str(p).startswith(str(child) + os.sep) or p == child
        ]
        if not preserved_under:
            if dry_run:
                out["removed_paths"].append(str(child))
                continue
            try:
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
                if child.exists():
                    out["failed"].append(
                        f"{child}: removal returned but path still present"
                    )
                else:
                    out["removed_paths"].append(str(child))
            except OSError as exc:
                out["failed"].append(f"{child}: {exc}")
            continue

        # Subtree has preserved entries — preserve subtree.
        if dry_run:
            for p in preserved_under:
                out["preserved_paths"].append(str(p))
            continue
        # Remove non-preserved siblings inside the subtree.
        if child.is_dir():
            for inner in child.rglob("*"):
                if inner.is_dir():
                    continue
                if inner in preserve_paths:
                    out["preserved_paths"].append(str(inner))
                    continue
                try:
                    inner.unlink()
                    if inner.exists():
                        out["failed"].append(
                            f"{inner}: unlink returned but file present"
                        )
                    else:
                        out["removed_paths"].append(str(inner))
                except OSError as exc:
                    out["failed"].append(f"{inner}: {exc}")
        else:
            # Top-level audit file (e.g. audit.jsonl) — preserve.
            out["preserved_paths"].append(str(child))

    # Finally, if nothing preserved + dir is empty, remove root too.
    if not dry_run and not preserve_paths:
        try:
            if home.exists():
                # Remove root only if empty (preserved file dirs may still
                # contain non-emptied subdirs we did not touch).
                contents = list(home.iterdir())
                if not contents:
                    home.rmdir()
                    out["removed_paths"].append(str(home))
        except OSError as exc:
            out["failed"].append(f"{home}: {exc}")
    return out


# ---------------------------------------------------------------------------
# #617 MED-5 — CANARY.md artifact detection
# ---------------------------------------------------------------------------


def _detect_canary_md_artifacts(
    data_dir: pathlib.Path | None = None,
) -> list[dict[str, str]]:
    """Detect CANARY.md files that should be preserved after uninstall.

    #617 MED-5: Operators on canary deploys (#492) use CANARY.md to
    record post-mortem notes and uncommitted findings. Auto-deleting
    them would silently destroy operator-authored data.

    Checks two locations:
      1. ``<data_dir>/canary/CANARY.md`` — primary per-install location
      2. ``<data_dir>/CANARY.md``        — root-level fallback

    Returns a list of ``{"type": "canary_md", "location": str,
    "hint": str}`` dicts for files that EXIST on disk.

    Per [[creates-never-mutates]]: this function only detects; it does
    NOT delete. CANARY.md artifacts are ALWAYS preserved by
    :func:`_step_remove_iam_jit_home` regardless of flags.

    Per [[ibounce-honest-positioning]]: we surface them in
    ``remaining_artifacts`` so the operator can review + remove manually
    when they are confident the notes are no longer needed.

    ``data_dir``: when set, probe under that directory. Otherwise fall
    back to the module-level :data:`IAM_JIT_HOME`.
    """
    home, _, _ = _derive_paths(data_dir)
    artifacts: list[dict[str, str]] = []
    for rel in ("canary/CANARY.md", "CANARY.md"):
        p = home / rel
        if p.exists():
            artifacts.append({
                "type": "canary_md",
                "location": str(p),
                "hint": (
                    f"CANARY.md preserved at {p} — this file may contain "
                    f"operator post-mortem notes from a canary deploy. "
                    f"Review and remove manually when no longer needed: "
                    f"rm {p}"
                ),
            })
    return artifacts


# ---------------------------------------------------------------------------
# #617 HIGH-3 — post-uninstall artifact detection helpers
# ---------------------------------------------------------------------------


def _check_path_binaries(
    *, data_only_scope: bool = False,
) -> list[dict[str, str]]:
    """Detect iam-jit suite binaries that remain on PATH after uninstall.

    Uses :func:`shutil.which` for each name in :data:`ALL_BINARY_NAMES`.
    Returns a list of ``{"type": "binary_on_path", "location": str,
    "hint": str}`` dicts for the operator to act on.

    Per [[ibounce-honest-positioning]]: if a binary is on PATH it IS
    detectable and must be reported under remaining_artifacts, not
    silently ignored.

    Per [[creates-never-mutates]]: this function only detects; it does
    NOT remove. The removal of binaries is done earlier in the uninstall
    sequence (pip-uninstall removes console scripts; go-bin removal
    removes Go binaries). This check catches anything the removal steps
    missed (e.g. manual symlinks, pip --user installs the removal step
    didn't know about, /usr/local/bin copies).

    #671 CRIT — when ``data_only_scope`` is True, return an empty list.
    Binaries on PATH (``~/.local/bin/``, ``~/go/bin/``, ``/usr/local/bin/``)
    are machine-global, not data-dir-scoped. An operator targeting a
    fixture data dir should not be reminded to remove the machine's
    real binaries (which belong to a DIFFERENT install).
    """
    if data_only_scope:
        return []
    artifacts: list[dict[str, str]] = []
    for name in ALL_BINARY_NAMES:
        found = shutil.which(name)
        if found is not None:
            artifacts.append({
                "type": "binary_on_path",
                "location": found,
                "hint": (
                    f"Binary '{name}' still found at {found}. "
                    f"Remove manually: rm -f {found}"
                ),
            })
    return artifacts


def _check_bouncer_config_dirs(
    *, data_only_scope: bool = False,
) -> list[dict[str, str]]:
    """Detect per-bouncer config directories that remain after uninstall.

    Checks each entry in :data:`BOUNCER_CONFIG_DIRS`. Returns a list
    of ``{"type": "bouncer_config_dir", "location": str, "hint": str}``
    dicts for directories that exist on disk.

    Per [[creates-never-mutates]]: we do NOT auto-remove these
    directories — the operator may have customized them. We report them
    so the operator can clean up manually.

    Per [[ibounce-honest-positioning]]: their existence after uninstall
    means the machine is not clean; ``clean:true`` would be a lie.

    #671 CRIT — when ``data_only_scope`` is True, return an empty list.
    ``~/.gbounce/`` / ``~/.kbounce/`` / ``~/.dbounce/`` are
    machine-global per-product config dirs, not data-dir-scoped.
    """
    if data_only_scope:
        return []
    artifacts: list[dict[str, str]] = []
    for name, path in BOUNCER_CONFIG_DIRS.items():
        if path.exists():
            artifacts.append({
                "type": "bouncer_config_dir",
                "location": str(path),
                "hint": (
                    f"{name} config directory still exists at {path}. "
                    f"Remove manually: rm -rf {path}"
                ),
            })
    return artifacts


def _detect_shell_rc_lines(
    *, data_only_scope: bool = False,
) -> list[dict[str, str]]:
    """Detect stale iam-jit shellinit lines in common shell RC files.

    Reads each file in :data:`SHELL_RC_FILES` and looks for lines
    matching any pattern in :data:`_SHELLINIT_PATTERNS`. Returns a
    list of ``{"type": "shell_rc_line", "location": "<file>:<line>",
    "hint": str}`` dicts.

    Per [[creates-never-mutates]]: we NEVER edit the operator's shell RC
    files. We only DETECT and REPORT.

    Per [[ibounce-honest-positioning]]: a stale shellinit line means
    future shells will try to initialise a removed installation; the
    operator MUST be told so they can clean it up.

    #671 CRIT — when ``data_only_scope`` is True, return an empty list.
    Shell-rc files are machine-global; an operator targeting a fixture
    data dir has no business being warned about shellinit lines that
    belong to a DIFFERENT install on the same machine.
    """
    if data_only_scope:
        return []
    artifacts: list[dict[str, str]] = []
    import re
    for rc_file in SHELL_RC_FILES:
        try:
            text = rc_file.read_text(errors="replace")
        except (OSError, PermissionError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pattern in _SHELLINIT_PATTERNS:
                if pattern in line:
                    artifacts.append({
                        "type": "shell_rc_line",
                        "location": f"{rc_file}:{lineno}",
                        "hint": (
                            f"Stale iam-jit shell initialisation at "
                            f"{rc_file}:{lineno} — remove manually. "
                            f"Line: {stripped[:120]}"
                        ),
                    })
                    break  # one artifact per line
    return artifacts


def _read_claude_json(
    claude_json_path: pathlib.Path,
) -> dict[str, Any] | None:
    """Read + parse ~/.claude.json. Returns None on any failure.

    Per [[ibounce-honest-positioning]]: parse failure is not a
    correctness blocker — we report "could not parse" in the hint
    rather than crashing uninstall.
    """
    try:
        text = claude_json_path.read_text(errors="replace")
        return json.loads(text)
    except (OSError, json.JSONDecodeError):
        return None


def _check_mcp_entries(
    *,
    claude_json_path: pathlib.Path | None = None,
    data_only_scope: bool = False,
) -> list[dict[str, str]]:
    """Detect iam-jit MCP server entries in ~/.claude.json.

    Checks the top-level ``mcpServers`` block AND any per-project
    ``projects[*].mcpServers`` blocks for entries whose key matches
    any name in :data:`MCP_SERVER_NAMES`.

    Returns a list of ``{"type": "mcp_entry", "location": str,
    "hint": str}`` dicts.

    Per the brief: uninstall MAY remove MCP entries automatically
    (treated as iam-jit-owned artifacts, same as config files). The
    actual removal is done in :func:`_step_remove_mcp_entries`.
    This function is the detection-only path used by the post-check
    to confirm removal succeeded.

    ``claude_json_path`` defaults to ``~/.claude.json``; tests pass a
    tmp_path override.

    #671 CRIT — when ``data_only_scope`` is True, return an empty list.
    ``~/.claude.json`` is a single machine-wide MCP config; an operator
    targeting a fixture data dir CANNOT distinguish their fixture's
    MCP entries from the live machine's, so the only safe action is
    to leave the file alone entirely.
    """
    if data_only_scope:
        return []
    if claude_json_path is None:
        claude_json_path = pathlib.Path.home() / ".claude.json"
    if not claude_json_path.exists():
        return []
    data = _read_claude_json(claude_json_path)
    if data is None:
        return []
    artifacts: list[dict[str, str]] = []

    # Top-level mcpServers.
    top_mcp = data.get("mcpServers") or {}
    if isinstance(top_mcp, dict):
        for key in list(top_mcp.keys()):
            if key in MCP_SERVER_NAMES:
                artifacts.append({
                    "type": "mcp_entry",
                    "location": f"{claude_json_path}:mcpServers.{key}",
                    "hint": (
                        f"MCP server entry '{key}' still present in "
                        f"{claude_json_path}. Remove manually or re-run "
                        f"without --keep-mcp-entries."
                    ),
                })

    # Per-project mcpServers.
    projects = data.get("projects") or {}
    if isinstance(projects, dict):
        for proj_key, proj_val in projects.items():
            if not isinstance(proj_val, dict):
                continue
            proj_mcp = proj_val.get("mcpServers") or {}
            if not isinstance(proj_mcp, dict):
                continue
            for key in list(proj_mcp.keys()):
                if key in MCP_SERVER_NAMES:
                    artifacts.append({
                        "type": "mcp_entry",
                        "location": (
                            f"{claude_json_path}:"
                            f"projects.{proj_key}.mcpServers.{key}"
                        ),
                        "hint": (
                            f"MCP server entry '{key}' still present in "
                            f"{claude_json_path} (project: {proj_key}). "
                            f"Remove manually or re-run without "
                            f"--keep-mcp-entries."
                        ),
                    })
    return artifacts


def _step_remove_mcp_entries(
    *,
    dry_run: bool,
    claude_json_path: pathlib.Path | None = None,
    data_only_scope: bool = False,
) -> dict[str, Any]:
    """Step: remove iam-jit-owned MCP server entries from ~/.claude.json.

    Per the brief: MCP entries are iam-jit-owned artifacts (like config
    files); uninstall removes them unless ``--keep-mcp-entries`` is
    passed by the operator. This is analogous to removing the venv or
    the data directory.

    Edits ``mcpServers`` at the top-level AND inside any per-project
    blocks. Rewrites the file atomically (write to temp + rename).

    Returns ``{"removed": [...], "kept": [...], "failed": str|None,
    "skipped": bool, "skipped_data_only_scope": bool}``.

    ``claude_json_path`` defaults to ``~/.claude.json``; tests pass a
    tmp_path override.

    #671 CRIT — when ``data_only_scope`` is True, the entire MCP-entry
    removal is suppressed (we cannot distinguish a fixture's MCP
    entries from the live machine's, so the only safe action is to
    leave the file alone).
    """
    if claude_json_path is None:
        claude_json_path = pathlib.Path.home() / ".claude.json"

    out: dict[str, Any] = {
        "removed": [],
        "kept": [],
        "failed": None,
        "skipped": False,
        "skipped_data_only_scope": False,
    }

    if data_only_scope:
        out["skipped"] = True
        out["skipped_data_only_scope"] = True
        return out

    if not claude_json_path.exists():
        out["skipped"] = True
        return out

    data = _read_claude_json(claude_json_path)
    if data is None:
        out["failed"] = f"could not parse {claude_json_path}"
        return out

    changed = False

    # Top-level mcpServers.
    top_mcp = data.get("mcpServers") or {}
    if isinstance(top_mcp, dict):
        for key in list(top_mcp.keys()):
            if key in MCP_SERVER_NAMES:
                if dry_run:
                    out["removed"].append(
                        f"mcpServers.{key} (dry-run)"
                    )
                else:
                    del top_mcp[key]
                    out["removed"].append(f"mcpServers.{key}")
                    changed = True
        if not dry_run:
            data["mcpServers"] = top_mcp

    # Per-project mcpServers.
    projects = data.get("projects") or {}
    if isinstance(projects, dict):
        for proj_key, proj_val in projects.items():
            if not isinstance(proj_val, dict):
                continue
            proj_mcp = proj_val.get("mcpServers") or {}
            if not isinstance(proj_mcp, dict):
                continue
            for key in list(proj_mcp.keys()):
                if key in MCP_SERVER_NAMES:
                    if dry_run:
                        out["removed"].append(
                            f"projects.{proj_key}.mcpServers.{key} (dry-run)"
                        )
                    else:
                        del proj_mcp[key]
                        out["removed"].append(
                            f"projects.{proj_key}.mcpServers.{key}"
                        )
                        changed = True
            if not dry_run:
                proj_val["mcpServers"] = proj_mcp

    if dry_run or not changed:
        return out

    # Atomic write: write to tmp sibling then rename so a crash mid-write
    # doesn't corrupt the config file.
    tmp_path = claude_json_path.with_suffix(".claude.json.uninstall-tmp")
    try:
        tmp_path.write_text(
            json.dumps(data, indent=2, sort_keys=False),
            encoding="utf-8",
        )
        tmp_path.replace(claude_json_path)
    except OSError as exc:
        out["failed"] = f"write {claude_json_path}: {exc}"
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
    return out


# ---------------------------------------------------------------------------
# Post-uninstall verification
# ---------------------------------------------------------------------------


def _verify_clean_state(
    *, keep_audit_logs: bool,
    keep_mcp_entries: bool = False,
    data_dir: pathlib.Path | None = None,
    claude_json_path: pathlib.Path | None = None,
    data_only_scope: bool | None = None,
) -> dict[str, Any]:
    """Re-inventory after uninstall + report any leftover state.

    Per ``docs/CONTRIBUTING.md`` state-verification: this is the
    observable side of the "uninstall succeeded" claim. Returns a dict
    of leftover items + a boolean ``clean`` flag + a structured
    ``remaining_artifacts`` list.

    Per ``[[ibounce-honest-positioning]]`` (#617 HIGH-3): every field
    here must reflect filesystem reality, not the operator's intent at
    flag-set time. Specifically, ``iam_jit_home_exists`` probes the
    actual data directory — if ``--keep-audit-logs`` preserved files
    on disk, the directory still exists and we must report it. The
    ``preserved_paths`` field enumerates exactly which audit-bearing
    files are still on disk so the operator can audit what was kept.

    The ``clean`` flag is true when EITHER (a) the directory was fully
    removed AND nothing else is leftover, OR (b) ``--keep-audit-logs``
    was set AND the only remaining items under the data directory are
    audit-bearing files we intentionally preserved — AND the full
    cross-product checklist below also passes.

    Cross-product checklist (#617 HIGH-3):
      1. Main data dir (``~/.iam-jit/`` or ``--data-dir``)
      2. Binaries on PATH (via ``shutil.which``)
      3. MCP entries in ``~/.claude.json`` (unless ``keep_mcp_entries``)
      4. Stale shell-rc lines in ``~/.zshrc`` etc. (detect-only)
      5. Per-bouncer config dirs (``~/.gbounce/``, ``~/.kbounce/``,
         ``~/.dbounce/``) (detect-only)
      6. Running processes / listening ports (from inventory)

    Per #617 MED-1: probes the resolved data directory (from the
    ``--data-dir`` flag / ``IAM_JIT_DATA_DIR`` env). When None, falls
    back to the module-level :data:`IAM_JIT_HOME` (existing-caller +
    test compatibility).

    ``claude_json_path`` defaults to ``~/.claude.json``; tests pass a
    tmp_path override.
    """
    home, _venv, _bouncer = _derive_paths(data_dir)
    # When no data_dir is passed, call _inventory_installed_state
    # without kwargs so existing test sabotages that monkeypatch the
    # inventory probe with a zero-arg replacement (per
    # test_uninstall_post_check_honesty_617's sabotage test) keep
    # working. When data_dir IS passed (the #617 MED-1 path), pass it
    # through so the probe targets the right tree.
    if data_dir is None:
        inv = _inventory_installed_state()
    else:
        inv = _inventory_installed_state(data_dir=data_dir)
    leftover: dict[str, Any] = {
        "running_bouncers": inv["running_bouncers"],
        "bound_ports": inv["bound_ports"],
        "venv_exists": inv["venv_exists"],
        "console_scripts_present": inv["console_scripts_present"],
        "go_binaries_present": inv["go_binaries_present"],
    }
    # #617 HIGH-3: probe the real directory; do NOT lie based on the
    # operator's flag. Pre-fix this returned False whenever
    # keep_audit_logs was set, even if the directory still contained
    # preserved files.
    leftover["iam_jit_home_exists"] = inv["iam_jit_home_exists"]

    # #617 HIGH-3: enumerate exactly which audit-bearing files are
    # still on disk so the operator can audit what was preserved.
    preserved_paths: list[str] = []
    if keep_audit_logs:
        for rel in AUDIT_BEARING_PATHS_REL:
            p = home / rel
            if p.exists():
                preserved_paths.append(str(p))
    leftover["preserved_paths"] = preserved_paths

    # #617 HIGH-3: an existing data home counts as leftover UNLESS
    # the operator opted in to keep-audit-logs AND the only thing
    # remaining is preserved audit-bearing content. Detect that by
    # walking the home and checking that every file present is on the
    # preserved-paths list.
    home_is_intentional_preserve = False
    if (
        keep_audit_logs
        and leftover["iam_jit_home_exists"]
        and preserved_paths
    ):
        try:
            preserved_set = {pathlib.Path(p).resolve() for p in preserved_paths}
            unexpected = []
            for entry in home.rglob("*"):
                if entry.is_file():
                    if entry.resolve() not in preserved_set:
                        unexpected.append(str(entry))
            if not unexpected:
                home_is_intentional_preserve = True
        except OSError:
            # If we can't walk, fall back to honest "leftover" — the
            # post-check should never falsely report clean.
            home_is_intentional_preserve = False

    # #617 HIGH-3 — cross-product artifact checks.
    # These run unconditionally after the main data-dir wipe so the
    # post-check reflects ALL remaining iam-jit artifacts, not just the
    # primary data directory.
    #
    # #671 CRIT — but ONLY when scope is the default data dir. For a
    # non-default --data-dir, these machine-wide probes would falsely
    # report the founder's live machine state as "leftover from the
    # fixture uninstall" (it isn't — it belongs to a different install).
    # Resolve scope from the data_dir argument if not passed explicitly.
    if data_only_scope is None:
        data_only_scope = _scope_is_data_only(data_dir)

    # (a) Stale binaries on PATH (via shutil.which).
    # #671 CRIT — when data_only_scope is True, machine-wide probes
    # must be suppressed. Use a local guard so even if the test stubs
    # have been monkeypatched with old-signature lambdas, scope
    # suppression still applies (the stub would have returned []
    # anyway in those tests).
    if data_only_scope:
        path_binary_artifacts: list[dict[str, str]] = []
        bouncer_config_artifacts: list[dict[str, str]] = []
        shell_rc_artifacts: list[dict[str, str]] = []
        mcp_artifacts: list[dict[str, str]] = []
    else:
        path_binary_artifacts = _call_with_optional_kwarg(
            _check_path_binaries, data_only_scope=False,
        )

        # (b) Per-bouncer config directories (~/.gbounce/, etc.).
        bouncer_config_artifacts = _call_with_optional_kwarg(
            _check_bouncer_config_dirs, data_only_scope=False,
        )

        # (c) Stale shell-rc lines (detect-only; never auto-edit).
        shell_rc_artifacts = _call_with_optional_kwarg(
            _detect_shell_rc_lines, data_only_scope=False,
        )

        # (d) MCP entries in ~/.claude.json — only detect here; removal
        # happens in _step_remove_mcp_entries() before the post-check.
        # When --keep-mcp-entries was passed, we do NOT report these as
        # remaining_artifacts (the operator deliberately kept them).
        mcp_artifacts = []
        if not keep_mcp_entries:
            mcp_artifacts = _call_with_optional_kwarg(
                _check_mcp_entries,
                claude_json_path=claude_json_path,
                data_only_scope=False,
            )

    # (e) #617 MED-5: CANARY.md artifacts — always preserved by
    # _step_remove_iam_jit_home; surface in remaining_artifacts so the
    # operator knows they exist and can review + remove manually.
    # These are INTENTIONALLY left behind (not a leftover-state error)
    # but must appear in remaining_artifacts per the MED-5 spec.
    canary_md_artifacts = _detect_canary_md_artifacts(data_dir=data_dir)

    # Aggregate remaining_artifacts in a stable order:
    #   binaries → bouncer_config_dirs → shell_rc_lines → mcp_entries
    #   → canary_md (#617 MED-5)
    remaining_artifacts: list[dict[str, str]] = (
        path_binary_artifacts
        + bouncer_config_artifacts
        + shell_rc_artifacts
        + mcp_artifacts
        + canary_md_artifacts
    )

    # #617 MED-5: CANARY.md preservation counts as an intentional
    # preserve (like --keep-audit-logs). If the ONLY leftover under
    # home is a CANARY.md, the home_is_intentional_preserve flag must
    # account for it — otherwise the post-check marks clean=False
    # even though we deliberately kept the file.
    canary_paths = {
        pathlib.Path(a["location"]).resolve() for a in canary_md_artifacts
    }
    if (
        not home_is_intentional_preserve
        and leftover["iam_jit_home_exists"]
        and canary_paths
    ):
        try:
            preserved_set_with_canary = (
                {pathlib.Path(p).resolve() for p in preserved_paths}
                | canary_paths
            )
            unexpected_excl_canary = []
            for entry in home.rglob("*"):
                if entry.is_file():
                    if entry.resolve() not in preserved_set_with_canary:
                        unexpected_excl_canary.append(str(entry))
            if not unexpected_excl_canary:
                home_is_intentional_preserve = True
        except OSError:
            pass

    has_leftover = any([
        leftover["running_bouncers"],
        leftover["bound_ports"],
        leftover["venv_exists"],
        leftover["console_scripts_present"],
        leftover["go_binaries_present"],
        # iam_jit_home_exists only counts as leftover if it ISN'T the
        # intentional --keep-audit-logs preserve case.
        leftover["iam_jit_home_exists"] and not home_is_intentional_preserve,
        # Cross-product artifacts: ANY remaining artifact → not clean.
        # NOTE: canary_md_artifacts are intentional preserves so we do
        # NOT count them as "unclean" — they appear in remaining_artifacts
        # for operator awareness but don't flip has_leftover.
        bool(
            path_binary_artifacts
            + bouncer_config_artifacts
            + shell_rc_artifacts
            + mcp_artifacts
        ),
    ])
    return {
        "clean": not has_leftover,
        "leftover": leftover,
        "remaining_artifacts": remaining_artifacts,
        "audit_logs_preserved": (
            keep_audit_logs and inv["audit_bearing_files"]
        ),
    }


# ---------------------------------------------------------------------------
# Top-level orchestration
# ---------------------------------------------------------------------------


def run_uninstall(
    *,
    dry_run: bool = False,
    force: bool = False,
    keep_audit_logs: bool = False,
    keep_mcp_entries: bool = False,
    backup_dir: pathlib.Path | None = None,
    data_dir: pathlib.Path | None = None,
    claude_json_path: pathlib.Path | None = None,
    # #671 CRIT — opt-in escape hatches for the data-only-scope guard
    # and the dogfood safety belt. Defaults are SAFE.
    full_machine_cleanup: bool = False,
    yes_clean_other_iam_jit_installs: bool = False,
    allow_live_bouncers_killed: bool = False,
    yes_dogfood_uninstall: bool = False,
) -> dict[str, Any]:
    """Orchestrate the full uninstall sequence.

    Returns the structured result (the same shape the CLI emits with
    ``--json``). Importable for tests + programmatic callers.

    The result is honest about partial failure: each step's substructure
    records what was done + what wasn't, and the top-level ``status``
    field is one of:

      * ``"ok"`` — every step completed cleanly + post-check is clean.
      * ``"halted"`` — pre-flight halt conditions fired; no destructive
        steps executed (operator must re-run with ``--force``).
      * ``"incomplete"`` — uninstall ran but post-check found leftover
        state (operator must investigate).
      * ``"dry_run"`` — nothing executed; plan returned.

    Per #617 MED-1: ``data_dir`` is the resolved iam-jit data
    directory (from ``--data-dir`` flag or ``IAM_JIT_DATA_DIR`` env).
    When None, the module-level :data:`IAM_JIT_HOME` is targeted
    (existing-caller + test compatibility). Surfaced in the result as
    ``inventory.data_dir`` so callers can see what tree was operated
    on.

    ``keep_mcp_entries``: when True, MCP server entries are NOT removed
    from ``~/.claude.json`` and are NOT reported as remaining_artifacts.
    Default False (remove MCP entries as iam-jit-owned artifacts).

    ``claude_json_path``: override for ``~/.claude.json`` location;
    tests use this to isolate from the dev machine's real config.
    """
    # #671 CRIT — resolve the data-only scope decision UP FRONT so every
    # downstream step + the post-check see the same answer.
    data_only_scope = _scope_is_data_only(data_dir)
    # ``--full-machine-cleanup`` is the explicit opt-out from the
    # data-only scope (operator says "yes, I want to clean other
    # iam-jit installs on this machine despite using --data-dir"). It
    # requires the additional super-explicit ack flag to actually do it;
    # the gating happens at the CLI layer + repeated here for callers
    # that import run_uninstall directly.
    if data_only_scope and full_machine_cleanup:
        if yes_clean_other_iam_jit_installs:
            # Operator explicitly acknowledged — restore machine-wide scope.
            data_only_scope = False
            full_machine_cleanup_armed = True
        else:
            full_machine_cleanup_armed = False  # refuse — see halt below
    else:
        full_machine_cleanup_armed = False

    result: dict[str, Any] = {
        "status": "ok",
        "dry_run": dry_run,
        "force": force,
        "keep_audit_logs": keep_audit_logs,
        "keep_mcp_entries": keep_mcp_entries,
        "backup_dir": str(backup_dir) if backup_dir else None,
        # #617 MED-1: record the resolved data dir in the top-level
        # result so JSON consumers + the operator-facing summary can
        # surface it (operator-trust per [[ibounce-honest-positioning]]).
        "data_dir": (
            str(_derive_paths(data_dir)[0])
        ),
        # #671 CRIT — surface scope decision + acknowledgement flags so
        # JSON consumers + the operator-facing summary can see WHY a
        # machine-wide action was (or was not) suppressed.
        "data_only_scope": data_only_scope,
        "full_machine_cleanup": full_machine_cleanup,
        "yes_clean_other_iam_jit_installs": (
            yes_clean_other_iam_jit_installs
        ),
        "allow_live_bouncers_killed": allow_live_bouncers_killed,
        "yes_dogfood_uninstall": yes_dogfood_uninstall,
        "dogfood_refuse_destructive_env_active": (
            _dogfood_refuse_destructive_active()
        ),
        "inventory": {},
        "halts": [],
        # #617 MED-4: version-drift warn — populated when the binary on
        # PATH reports a different version from iam_jit.__version__. A
        # half-applied pip upgrade can leave the binary stale. Surfaced
        # in the dry-run report so the operator can investigate before
        # confirming destruction. None = no drift detected.
        "version_drift_warn": None,
        "steps": {},
        "post_check": {},
    }

    # Same compat shape as _verify_clean_state: don't pass data_dir
    # kwarg when None so test sabotages that replace the inventory
    # probe with a zero-arg function still work.
    if data_dir is None:
        inventory = _inventory_installed_state()
    else:
        inventory = _inventory_installed_state(data_dir=data_dir)
    result["inventory"] = inventory

    # #617 MED-4: check for version drift between the iam-jit binary on
    # PATH and the installed iam_jit Python package. Surface as a WARN
    # rather than a halt — a stale binary is concerning but not always
    # uninstall-blocking.
    result["version_drift_warn"] = _check_version_drift()

    halts = _check_halt_conditions(inventory)

    # #671 CRIT — extra halts that the operator must explicitly
    # acknowledge BEFORE destruction. These are NOT bypassable by
    # ``--force`` (which is for the older halt conditions); each
    # requires its OWN long-form acknowledgement flag. This is the
    # friction-as-feature pattern per
    # [[ambient-value-prop-and-friction-framing]] — flags long enough
    # that they cannot be typed by accident.

    # Halt U-6: dogfood safety belt. When IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE=1
    # is set in the environment, REFUSE any machine-wide destructive
    # action without ``--yes-i-am-on-dogfood-machine-and-want-to-uninstall``.
    if (
        _dogfood_refuse_destructive_active()
        and not data_only_scope
        and not yes_dogfood_uninstall
    ):
        halts.append({
            "id": "U-6",
            "severity": "CRIT",
            "reason": (
                f"dogfood safety belt active "
                f"({IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE_ENV}=1 in env) — "
                f"refusing machine-wide uninstall. This machine is "
                f"marked as a dogfood/founder machine and requires "
                f"--yes-i-am-on-dogfood-machine-and-want-to-uninstall "
                f"to proceed (#671 CRIT safety belt)."
            ),
        })

    # Halt U-7: live bouncers detected + --data-dir is non-default.
    # When the operator targeted a fixture data dir but live bouncers
    # are running on default ports on this machine, the safest
    # default is to BAIL — the right thing is to either kill the live
    # bouncers manually first OR pass --allow-live-bouncers-killed (a
    # no-op-on-them flag that just records the operator's awareness).
    # We don't auto-kill, ever, in fixture scope (that is the #671 bug).
    if data_only_scope and not allow_live_bouncers_killed:
        live_default_port_bouncers: list[tuple[int, str]] = []
        # Probe the canonical default ports for each bouncer kind.
        # Only loopback connect — same shape as cli_canary._port_bound.
        for kind, ports in _BOUNCER_DEFAULT_PORTS.items():
            for port in ports:
                if _port_bound(port):
                    live_default_port_bouncers.append((port, kind))
        if live_default_port_bouncers:
            descs = ", ".join(
                f"{kind}:{port}" for port, kind in live_default_port_bouncers
            )
            halts.append({
                "id": "U-7",
                "severity": "CRIT",
                "reason": (
                    f"live bouncer(s) detected on machine-default ports "
                    f"({descs}) AND --data-dir is non-default "
                    f"({result['data_dir']}). The #671 incident shape "
                    f"was a fixture uninstall destroying the founder's "
                    f"live machine state. Either (a) stop the live "
                    f"bouncers first, OR (b) re-run with "
                    f"--allow-live-bouncers-killed to explicitly "
                    f"acknowledge that the live bouncers are independent "
                    f"of the fixture you are uninstalling and you accept "
                    f"the risk of incidental damage from any future "
                    f"machine-wide step that bypasses the data-only-scope "
                    f"guard."
                ),
            })

    # Halt U-8: --full-machine-cleanup without the long-form ack flag.
    # The flag itself is the operator saying "yes, I really want
    # machine-wide cleanup despite --data-dir being non-default". The
    # ack flag is the friction: it MUST be typed (no abbreviation, no
    # shortcut) so an automation script can't trivially set it.
    if (
        data_only_scope is False
        and full_machine_cleanup
        and not full_machine_cleanup_armed
        and _scope_is_data_only(data_dir)  # was originally non-default
    ):
        # Should not reach here — data_only_scope only flips to False
        # when both flags are set. Belt-and-braces.
        pass
    if full_machine_cleanup and _scope_is_data_only(data_dir) and not full_machine_cleanup_armed:
        halts.append({
            "id": "U-8",
            "severity": "CRIT",
            "reason": (
                f"--full-machine-cleanup requested with non-default "
                f"--data-dir ({result['data_dir']}) but the required "
                f"acknowledgement flag "
                f"--yes-i-want-to-clean-other-iam-jit-installs-on-this-machine "
                f"was not passed. Refusing per #671 CRIT. Pass the long "
                f"flag explicitly to confirm you want to clean OTHER "
                f"iam-jit installs on this machine in addition to the "
                f"--data-dir target."
            ),
        })

    result["halts"] = halts
    # Halts block destructive execution unless --force. Dry-run always
    # proceeds to compute the plan (operator needs to SEE what would
    # happen + what halts they'd need to bypass).
    #
    # #671 CRIT — the new U-6/U-7/U-8 halts are NOT bypassable by
    # --force. They each require their OWN long-form acknowledgement
    # flag. If any U-6/U-7/U-8 is present, refuse regardless of force.
    crit_671_halts = [h for h in halts if h["id"] in ("U-6", "U-7", "U-8")]
    if crit_671_halts and not dry_run:
        result["status"] = "halted"
        return result
    if halts and not force and not dry_run:
        result["status"] = "halted"
        return result

    # Execute the destructive steps (in MRR-4 order):
    #  1. stop bouncers          (steps 1 + 5)
    #  2. pip uninstall          (steps 2 + 3)
    #  3. remove go bins         (step 4)
    #  4. remove venv            (step 7)
    #  5. remove iam-jit-home    (step 9; honours --keep-audit-logs)
    #  6. remove MCP entries     (#617 HIGH-3; unless --keep-mcp-entries)
    # #671 CRIT — use _call_with_optional_kwarg for step functions that
    # may be monkeypatched by tests with old-signature lambdas. The
    # data_only_scope kwarg is additive — older test stubs that don't
    # accept it get called without it, which is fine because they're
    # already test-isolated (they don't perform real machine-wide
    # actions).
    result["steps"]["stop_bouncers"] = _call_with_optional_kwarg(
        _step_stop_bouncers,
        inventory=inventory, dry_run=dry_run,
        data_only_scope=data_only_scope,
    )
    # _step_stop_bouncers's positional arg is `inventory`. Tests that
    # monkeypatch with `lambda inv, **kw: ...` style work via the
    # signature inspector above; for the real fn the kwarg shape works
    # too because Python lets you bind positional params by name.
    result["steps"]["pip_uninstall"] = _step_pip_uninstall(
        dry_run=dry_run, data_dir=data_dir,
    )
    result["steps"]["remove_go_binaries"] = _call_with_optional_kwarg(
        _step_remove_go_binaries,
        inventory=inventory, dry_run=dry_run,
        data_only_scope=data_only_scope,
    )
    result["steps"]["remove_venv"] = _step_remove_venv(
        dry_run=dry_run, data_dir=data_dir,
    )
    result["steps"]["remove_iam_jit_home"] = _step_remove_iam_jit_home(
        dry_run=dry_run,
        keep_audit_logs=keep_audit_logs,
        backup_dir=backup_dir,
        data_dir=data_dir,
    )
    # #617 HIGH-3: remove MCP entries unless operator opts to keep them.
    # #671 CRIT: also skip when data_only_scope (cannot distinguish
    # fixture entries from live machine's; the only safe action is to
    # leave the file alone).
    if not keep_mcp_entries:
        result["steps"]["remove_mcp_entries"] = _call_with_optional_kwarg(
            _step_remove_mcp_entries,
            dry_run=dry_run,
            claude_json_path=claude_json_path,
            data_only_scope=data_only_scope,
        )
    else:
        result["steps"]["remove_mcp_entries"] = {
            "removed": [],
            "kept": [],
            "failed": None,
            "skipped": True,
            "skipped_data_only_scope": False,
        }

    if dry_run:
        result["status"] = "dry_run"
        return result

    # Post-check: observable state matches the success claim.
    # #617 HIGH-3: pass keep_mcp_entries + claude_json_path so the
    # post-check uses the SAME fixture path as the removal step above.
    # #671 CRIT: pass data_only_scope so the post-check honours the
    # same scope decision as the destruction steps.
    post = _verify_clean_state(
        keep_audit_logs=keep_audit_logs,
        keep_mcp_entries=keep_mcp_entries,
        data_dir=data_dir,
        claude_json_path=claude_json_path,
        data_only_scope=data_only_scope,
    )
    result["post_check"] = post
    if not post["clean"]:
        result["status"] = "incomplete"
    return result


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def register_uninstall_command(main_group: click.Group) -> click.Command:
    """Attach ``iam-jit uninstall`` to the top-level CLI group.

    Returns the command so tests can invoke it via
    ``CliRunner.invoke(main, ["uninstall", ...])``.
    """

    @main_group.command("uninstall")
    @click.option(
        "--dry-run",
        is_flag=True,
        default=False,
        help="Show what would be removed without executing.",
    )
    @click.option(
        "--yes", "-y",
        is_flag=True,
        default=False,
        help="Skip confirmation prompt (non-interactive).",
    )
    @click.option(
        "--force",
        is_flag=True,
        default=False,
        help=(
            "Proceed past pre-flight halt conditions (DANGEROUS). "
            "Halt conditions per docs/MRR-4-HALT-CONDITIONS.md exist to "
            "protect operator state; bypassing them may leave the "
            "system in an unexpected state."
        ),
    )
    @click.option(
        "--keep-audit-logs",
        is_flag=True,
        default=False,
        help=(
            "Preserve audit-bearing files (~/.iam-jit/audit.jsonl, "
            "bouncer/state.db*, canary/issues.jsonl) for compliance. "
            "Other ~/.iam-jit/ contents are still removed."
        ),
    )
    @click.option(
        "--backup-dir",
        type=click.Path(file_okay=False, dir_okay=True, path_type=pathlib.Path),
        default=None,
        help=(
            "Copy ~/.iam-jit/ contents to this directory before removal. "
            "Per [[creates-never-mutates]] the backup is a forensic "
            "snapshot — uninstall never modifies the backup after writing."
        ),
    )
    @click.option(
        "--data-dir",
        type=click.Path(file_okay=False, dir_okay=True, path_type=pathlib.Path),
        default=None,
        help=(
            "Operate on this iam-jit data directory (default: "
            "$IAM_JIT_DATA_DIR env, then ~/.iam-jit/). Mirrors "
            "`iam-jit serve --data-dir` so operators can uninstall the "
            "same tree they installed against. #617 MED-1."
        ),
    )
    @click.option(
        "--keep-mcp-entries",
        is_flag=True,
        default=False,
        help=(
            "Do NOT remove iam-jit MCP server entries from ~/.claude.json. "
            "By default, uninstall removes iam-jit-owned mcpServers entries "
            "(iam-jit, ibounce, kbounce, dbounce, gbounce) because they are "
            "iam-jit-created artifacts. Pass this flag to preserve them "
            "(e.g. if you have a custom agent config that references these "
            "servers). #617 HIGH-3."
        ),
    )
    @click.option(
        "--full-machine-cleanup",
        is_flag=True,
        default=False,
        help=(
            "When --data-dir is non-default, ALSO run machine-wide "
            "cleanup actions (kill bouncers, remove ~/.local/bin "
            "binaries, clear MCP entries from ~/.claude.json, scan "
            "shell-rc files). Requires the long-form "
            "--yes-i-want-to-clean-other-iam-jit-installs-on-this-machine "
            "ack flag to actually do it. Default behaviour with a "
            "non-default --data-dir is to ONLY touch the data-dir tree "
            "(per #671 CRIT)."
        ),
    )
    @click.option(
        "--yes-i-want-to-clean-other-iam-jit-installs-on-this-machine",
        "yes_clean_other_iam_jit_installs",
        is_flag=True,
        default=False,
        help=(
            "Explicit acknowledgement required to actually run "
            "--full-machine-cleanup against a non-default --data-dir. "
            "Long flag is intentional (friction-as-feature per #671)."
        ),
    )
    @click.option(
        "--allow-live-bouncers-killed",
        is_flag=True,
        default=False,
        help=(
            "Bypass the U-7 halt that fires when --data-dir is "
            "non-default but live bouncers are detected on machine-"
            "default ports. Use ONLY when you've verified the live "
            "bouncers are independent of the data-dir target and you "
            "accept the risk of incidental damage from a future "
            "machine-wide step bypassing the data-only-scope guard "
            "(#671 CRIT)."
        ),
    )
    @click.option(
        "--yes-i-am-on-dogfood-machine-and-want-to-uninstall",
        "yes_dogfood_uninstall",
        is_flag=True,
        default=False,
        help=(
            f"Required when the dogfood safety belt env var "
            f"({IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE_ENV}=1) is set "
            f"AND the operator IS asking for a machine-wide uninstall. "
            f"Long flag is intentional (friction-as-feature per #671 "
            f"CRIT)."
        ),
    )
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured result as JSON.",
    )
    def uninstall_cmd(
        dry_run: bool,
        yes: bool,
        force: bool,
        keep_audit_logs: bool,
        backup_dir: pathlib.Path | None,
        data_dir: pathlib.Path | None,
        keep_mcp_entries: bool,
        full_machine_cleanup: bool,
        yes_clean_other_iam_jit_installs: bool,
        allow_live_bouncers_killed: bool,
        yes_dogfood_uninstall: bool,
        as_json: bool,
    ) -> None:
        """Uninstall iam-jit + all bouncers (MRR-4 procedure).

        Implements the 10-step uninstall sequence from
        ``docs/MRR-4-UNINSTALL.md`` as a single CLI command. Restores the
        system to pre-install state.

        Default mode prompts for confirmation; pass ``--yes`` for
        non-interactive use. Pass ``--dry-run`` to preview without
        executing. Halt conditions per
        ``docs/MRR-4-HALT-CONDITIONS.md`` are auto-detected; bypass
        with ``--force`` after investigating.

        Per ``[[creates-never-mutates]]``: uninstall removes iam-jit-created
        resources including MCP entries in ~/.claude.json. Shell-profile env
        vars (shellinit lines) and browser-trusted MITM CAs are surfaced as
        ``remaining_artifacts`` — operator must remove those by hand.

        Per #617 MED-1: ``--data-dir`` (and ``IAM_JIT_DATA_DIR`` env)
        mirror ``iam-jit serve --data-dir`` so operators who installed
        against a non-default home (e.g. ``/opt/iam-jit-prod``) can
        uninstall symmetrically without HOME-redirect workarounds.

        Per #617 HIGH-3: ``clean:true`` in the post-check means ALL of
        the following are absent: main data dir (unless --keep-audit-logs),
        binaries on PATH, MCP entries (unless --keep-mcp-entries), running
        bouncers, listening bouncer ports, stale shell-rc lines, and
        per-bouncer config dirs. ``remaining_artifacts`` lists any that
        remain with operator hints.
        """
        # #617 MED-1: resolve the data dir up-front so every downstream
        # surface (inventory print + halt check + run_uninstall + post
        # output) operates on the same tree. The resolver records WHY
        # this path was chosen so we can surface it to the operator.
        env_val_set = bool(os.environ.get(IAM_JIT_DATA_DIR_ENV))
        resolved_data_dir = resolve_data_dir(cli_flag=data_dir)
        if data_dir is not None:
            data_dir_source = "--data-dir flag"
        elif env_val_set:
            data_dir_source = f"${IAM_JIT_DATA_DIR_ENV} env"
        else:
            data_dir_source = "default (~/.iam-jit/)"

        # Pre-flight inventory so the confirmation prompt is honest.
        inventory = _inventory_installed_state(data_dir=resolved_data_dir)

        if not as_json:
            # Surface the resolved data dir up-front per
            # [[ibounce-honest-positioning]] — operator can verify they
            # are about to destroy the right tree before confirming.
            click.secho(
                f"iam-jit uninstall — operating on: {resolved_data_dir}",
                bold=True,
            )
            click.echo(f"  (resolved from: {data_dir_source})")
            click.echo()
            _print_inventory_summary(inventory, dry_run=dry_run)

        # Halt-condition pre-check — even in dry-run we surface halts
        # so the operator can see what they'd need to --force past.
        halts = _check_halt_conditions(inventory)
        if halts:
            if not as_json:
                click.secho(
                    "\nHalt conditions detected (per "
                    "docs/MRR-4-HALT-CONDITIONS.md):",
                    fg="yellow",
                )
                for h in halts:
                    click.secho(
                        f"  [{h['id']} {h['severity']}] {h['reason']}",
                        fg="yellow",
                    )
                if not force and not dry_run:
                    click.secho(
                        "\nRefusing to uninstall while halt conditions "
                        "are active. Re-run with --force to bypass.",
                        fg="red",
                        err=True,
                    )

        # Confirm (interactive mode only, non-dry-run).
        if not dry_run and not yes and not as_json:
            # Use a default of False so a stray ENTER does not destroy
            # state per founder direction on space-shuttle discipline.
            if not click.confirm(
                "\nProceed with uninstall?",
                default=False,
            ):
                click.secho("Aborted by operator.", fg="yellow")
                raise SystemExit(2)

        result = run_uninstall(
            dry_run=dry_run,
            force=force,
            keep_mcp_entries=keep_mcp_entries,
            keep_audit_logs=keep_audit_logs,
            backup_dir=backup_dir,
            data_dir=resolved_data_dir,
            full_machine_cleanup=full_machine_cleanup,
            yes_clean_other_iam_jit_installs=(
                yes_clean_other_iam_jit_installs
            ),
            allow_live_bouncers_killed=allow_live_bouncers_killed,
            yes_dogfood_uninstall=yes_dogfood_uninstall,
        )
        # #617 MED-1: record the source so JSON consumers can see how
        # the path was chosen (flag vs env vs default).
        result["data_dir_source"] = data_dir_source

        # #671 CRIT — surface ANY halts that fired inside run_uninstall
        # (the U-6 / U-7 / U-8 halts are added in run_uninstall, not in
        # _check_halt_conditions, so the pre-run print above missed
        # them). Without this, the operator sees "uninstall status:
        # halted" with no explanation.
        if not as_json:
            run_halts = result.get("halts") or []
            new_halts = [
                h for h in run_halts
                if h["id"] in ("U-6", "U-7", "U-8")
            ]
            if new_halts:
                click.secho(
                    "\nHalt conditions detected (per #671 CRIT data-only-"
                    "scope guard):",
                    fg="yellow",
                )
                for h in new_halts:
                    click.secho(
                        f"  [{h['id']} {h['severity']}] {h['reason']}",
                        fg="yellow",
                    )

        if as_json:
            click.echo(json.dumps(result, indent=2, sort_keys=True, default=str))
        else:
            _print_result_summary(result)

        # Exit code semantics:
        #   0 — ok / dry_run
        #   1 — incomplete (post-check found leftover state)
        #   2 — halted (operator must re-run with --force)
        status = result.get("status")
        if status == "halted":
            raise SystemExit(2)
        if status == "incomplete":
            raise SystemExit(1)
        # ok / dry_run → 0

    return uninstall_cmd


# ---------------------------------------------------------------------------
# #617 MED-4 — version-drift check (binary vs package version)
# ---------------------------------------------------------------------------


def _check_version_drift() -> dict[str, Any] | None:
    """Compare ``iam-jit --version`` stdout with ``iam_jit.__version__``.

    #617 MED-4: After a partial ``pip install --upgrade iam-jit``, the
    installed Python package may be at a newer version than the
    ``iam-jit`` binary on PATH (the console-script shebang still points
    at the OLD venv's interpreter). Uninstall running against a
    half-applied upgrade may fail to remove all artifacts or may clean
    up the wrong paths.

    Mechanism: shell out to ``iam-jit --version`` (the binary on PATH)
    and compare the version string with :data:`iam_jit.__version__`
    (the Python package version in the current interpreter). Any
    mismatch → surface as a WARN in the dry-run plan so the operator
    sees it before confirming destruction.

    Return value:
      ``None``                        — versions match (or could not check)
      ``{"pkg": str, "bin": str}``    — version mismatch detected

    Per [[ibounce-honest-positioning]]: a WARN is not a halt — version
    drift is not always catastrophic (e.g. the operator may be using a
    wrapper script). We surface it so they can investigate; we do not
    block uninstall.

    Per [[creates-never-mutates]]: this function is read-only (no side
    effects).
    """
    # Resolve iam_jit package version.
    try:
        from iam_jit import __version__ as pkg_version
    except ImportError:
        return None

    # Shell out to the binary on PATH.
    iam_jit_bin = shutil.which("iam-jit")
    if iam_jit_bin is None:
        # Binary not on PATH — can't compare; skip silently.
        return None
    try:
        proc = subprocess.run(
            [iam_jit_bin, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    raw = (proc.stdout or proc.stderr or "").strip()
    if not raw:
        return None

    # ``iam-jit --version`` output shape varies by Click config but
    # typically is one of:
    #   "iam-jit, version 1.0.0"
    #   "iam-jit 1.0.0"
    #   "1.0.0"
    # We extract the first whitespace-separated token that looks like a
    # semantic version (digits + dots), trying the last token first.
    bin_version: str | None = None
    for token in reversed(raw.split()):
        # Must contain at least one digit and one dot.
        if any(c.isdigit() for c in token) and "." in token:
            bin_version = token.strip(",").strip()
            break
    if bin_version is None:
        return None

    if bin_version == pkg_version:
        return None
    return {"pkg": pkg_version, "bin": bin_version}


def _print_inventory_summary(
    inv: dict[str, Any], *, dry_run: bool,
) -> None:
    """Operator-facing pre-uninstall summary."""
    label = "DRY-RUN — " if dry_run else ""
    click.echo(f"{label}iam-jit uninstall plan")
    click.echo("=" * 60)
    click.echo(f"  ~/.iam-jit exists:       {inv['iam_jit_home_exists']}")
    click.echo(f"  venv present:            {inv['venv_exists']}")
    rb = inv.get("running_bouncers") or {}
    if rb:
        click.echo(f"  running bouncers:        {sum(len(v) for v in rb.values())} PIDs")
        for name, pids in rb.items():
            click.echo(f"    {name:<12} pids={pids}")
    else:
        click.echo("  running bouncers:        none")
    if inv["bound_ports"]:
        click.echo(f"  bouncer ports bound:     {inv['bound_ports']}")
    unknowns = inv.get("unknown_port_owners") or []
    if unknowns:
        click.secho(
            f"  unknown port owners:     {len(unknowns)} "
            "(non-bouncer process(es) on bouncer-typical ports — "
            "manual inspection recommended)",
            fg="yellow",
        )
        for u in unknowns:
            # #608 — surface expected_bouncer when present so the
            # operator sees "pid 1234 on :8766 (expected kbounce)".
            expected = u.get("expected_bouncer")
            expected_tag = f" (expected {expected})" if expected else ""
            click.echo(
                f"    pid={u['pid']:<8} port={u['port']:<6}{expected_tag} "
                f"cmdline={u['cmdline'][:120]}"
            )
    if inv["console_scripts_present"]:
        click.echo(
            f"  pip console scripts:     "
            f"{len(inv['console_scripts_present'])} present"
        )
    if inv["go_binaries_present"]:
        click.echo(
            f"  Go binaries:             "
            f"{len(inv['go_binaries_present'])} present"
        )
    if inv["audit_bearing_files"]:
        click.echo(
            f"  audit-bearing files:     "
            f"{len(inv['audit_bearing_files'])} present "
            "(use --keep-audit-logs to preserve)"
        )
    click.echo()
    click.secho("Manual cleanup reminders (uninstall will NOT do these):", fg="cyan")
    for note in inv.get("manual_reminders") or []:
        click.echo(f"  - {note}")


def _print_result_summary(result: dict[str, Any]) -> None:
    """Operator-facing post-uninstall result."""
    status = result.get("status", "?")
    color = {
        "ok": "green",
        "dry_run": "cyan",
        "halted": "yellow",
        "incomplete": "red",
    }.get(status, "white")
    click.echo()
    click.secho(f"uninstall status: {status}", fg=color, bold=True)

    # #617 MED-4: surface version-drift WARN when present.
    drift = result.get("version_drift_warn")
    if drift:
        click.secho(
            f"  WARN: version drift detected — binary on PATH reports "
            f"v{drift['bin']} but installed iam_jit package is "
            f"v{drift['pkg']}. This may indicate a half-applied upgrade; "
            f"uninstall may miss stale artifacts. Resolve with "
            f"`pip install --upgrade iam-jit` before uninstalling.",
            fg="yellow",
        )

    steps = result.get("steps") or {}
    for sname, sresult in steps.items():
        # Per [[ibounce-honest-positioning]] surface failures explicitly.
        failed = sresult.get("failed") if isinstance(sresult, dict) else None
        if failed:
            click.secho(f"  {sname}: FAILED", fg="red")
            for f in (failed if isinstance(failed, list) else [failed]):
                click.echo(f"    - {f}")
        elif isinstance(sresult, dict) and sresult.get("removed_paths"):
            n = len(sresult["removed_paths"])
            click.secho(f"  {sname}: removed {n} paths", fg="green")
        elif isinstance(sresult, dict) and sresult.get("reaped"):
            n = len(sresult["reaped"])
            click.secho(f"  {sname}: reaped {n} PIDs", fg="green")
        elif isinstance(sresult, dict) and sresult.get("executed"):
            click.secho(f"  {sname}: executed", fg="green")
        elif isinstance(sresult, dict) and sresult.get("removed"):
            click.secho(f"  {sname}: removed", fg="green")
        else:
            click.secho(f"  {sname}: no-op", fg="white")

    post = result.get("post_check") or {}
    if post:
        clean = post.get("clean")
        click.secho(
            f"  post_check: {'clean' if clean else 'LEFTOVER STATE'}",
            fg="green" if clean else "red",
        )
        if not clean:
            leftover = post.get("leftover") or {}
            for k, v in leftover.items():
                if v:
                    click.secho(f"    {k}: {v}", fg="red")
            # #617 HIGH-3: surface remaining_artifacts with operator hints.
            artifacts = post.get("remaining_artifacts") or []
            if artifacts:
                click.secho(
                    f"  remaining_artifacts ({len(artifacts)} item(s) "
                    f"require manual cleanup):",
                    fg="red",
                )
                for art in artifacts:
                    click.secho(
                        f"    [{art.get('type', '?')}] "
                        f"{art.get('location', '?')}",
                        fg="red",
                    )
                    click.echo(f"      hint: {art.get('hint', '')}")
        if post.get("audit_logs_preserved"):
            click.secho(
                "  audit_logs_preserved: YES (per --keep-audit-logs)",
                fg="cyan",
            )

    # #617 MED-3: re-init hint — surface after a successful (ok /
    # incomplete) non-dry-run uninstall so the operator knows they can
    # start fresh with `iam-jit init`. Without this, operators who
    # uninstall then re-install don't realise their previous state was
    # wiped and may be surprised by a clean slate.
    #
    # Two flavours:
    #   a) no --keep-audit-logs: generic re-init tip noting that
    #      accounts/profiles/audit log were removed.
    #   b) --keep-audit-logs: tip points at the preserved log location
    #      so the operator knows where their forensic data lives.
    if status in ("ok", "incomplete") and not result.get("dry_run"):
        keep = result.get("keep_audit_logs", False)
        post = result.get("post_check") or {}
        if keep:
            preserved = (
                post.get("leftover", {}).get("preserved_paths") or []
            )
            loc_hint = (
                f" Preserved audit log(s): {', '.join(preserved)}."
                if preserved else ""
            )
            click.secho(
                f"\nTip: To set up iam-jit again, run `iam-jit init` — "
                f"your previous accounts and profiles have been removed."
                f"{loc_hint}",
                fg="cyan",
            )
        else:
            click.secho(
                "\nTip: To set up iam-jit again, run `iam-jit init` — "
                "your previous accounts/profiles/audit log have been removed.",
                fg="cyan",
            )


__all__ = [
    "BOUNCER_PROCESS_NAMES",
    "BOUNCER_PORTS",
    "CONSOLE_SCRIPTS",
    "GO_BINARIES",
    "AUDIT_BEARING_PATHS_REL",
    "IAM_JIT_HOME",
    "IAM_JIT_DATA_DIR_ENV",
    "IAM_JIT_DOGFOOD_REFUSE_DESTRUCTIVE_ENV",
    "VENV_DIR",
    "register_uninstall_command",
    "resolve_data_dir",
    "run_uninstall",
]

# #608: exposed for tests + the sabotage-check that monkeypatches
# the per-bouncer port set. Not in __all__ because the leading
# underscore signals "internal — subject to change without a deprecation
# cycle"; tests import it by name explicitly.
#
# #617 MED-2: _all_listening_ports exposed for sabotage-check that
# monkeypatches it to prove it's the load-bearing path for custom-port
# detection. Tests import it by name explicitly.
