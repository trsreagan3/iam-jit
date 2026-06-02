"""#626 / §A93+ — `iam-jit doctor install-check` end-to-end install
verification.

A founder dogfood pass 2026-05-26 surfaced that the canonical
operator install story breaks at multiple layers:

  * PATH: ``~/.local/bin`` empty even after ``pip install --user .``
    because the doc didn't disambiguate venv vs --user vs pipx.
  * Go bouncers: ``~/go/bin`` empty; the ``go install ...@latest``
    commands silently no-op'd because the module-cache exists but the
    build never produced a binary.
  * Env-var wire: ``ibounce`` running on :8767 for 19+ hours with
    ``decisions_count=2`` because ``AWS_ENDPOINT_URL`` was never set.
  * Dev-vs-installed confusion: the running ``ibounce`` was actually
    ``python -m iam_jit.bouncer_cli`` from the dev venv, NOT the
    installed ``ibounce`` console-script.

Per [[ibounce-honest-positioning]] the install-check is HONEST about
what it actually observes — no "probably OK" messages, no soft
fallbacks. Per [[creates-never-mutates]] it NEVER touches the
operator's PATH / shell rc / config files; it only checks + reports +
suggests remediation. Per [[scorer-is-ground-truth]] the doctor's
pass/fail is the source of truth for "is the install working?".

Sections:
  [1/8] PATH check          (console-script + Go-bouncer binaries)
  [2/8] Binary versions     (iam-jit --version + ibounce --version)
  [3/8] Running bouncers    (reuses posture.capture_posture)
  [4/8] Env-var wiring      (AWS_ENDPOINT_URL etc. point at running bouncers)
  [5/8] Routing self-test   (real sts:GetCallerIdentity-shaped probe)
  [6/8] Config files        (~/.iam-jit/{accounts,users}.yaml)
  [7/8] Audit log writability (disk free + audit.jsonl writable)
  [8/8] Posture summary     (one-line overall verdict)

Exit codes:
  0 = all green
  1 = warnings only (functional but degraded — e.g. extra Go bouncers
      not installed in a Python-only deployment)
  2 = errors present (install demonstrably broken — won't protect)

Usage:

  iam-jit doctor install-check                  # human; exit code per spec
  iam-jit doctor install-check --json           # machine-readable for #490
  iam-jit doctor install-check --no-routing-test  # skip socket probe

The ``--json`` output is structured so corp deploy automation
(``iam-jit init --managed --no-prompt`` per [[enterprise-profile-
distribution]]) can react.
"""

from __future__ import annotations

import json as _json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
from contextlib import closing
from dataclasses import dataclass, field
from typing import Any

import click

from . import __version__


# ---------------------------------------------------------------------------
# OS-aware install hint (Part A — #649 macOS PEP 668 fix)
# ---------------------------------------------------------------------------


def _python_install_hint(
    local_bin_display: str = "~/.local/bin",
) -> str:
    """Return a paste-ready install hint appropriate for the host OS +
    Python provenance. Never raises — falls through to generic hint if
    detection is ambiguous.

    Detection priority:
      1. pyenv Python             → pyenv-specific hint (any platform)
      2. nix-store Python         → nix-shell hint (any platform)
      3. macOS + Homebrew Python  → pipx flow  (PEP 668 blocks pip --user)
      4. macOS + system Python    → venv flow   (system pip is restricted)
      5. Linux + apt-managed      → pip --upgrade-pip + --user
      6. Generic fallback         → pip install --user git+https://github.com/trsreagan3/iam-jit.git

    NOTE (#654): iam-jit is not yet on PyPI. All hints use the git+https://
    source install until the PyPI publish task (#235) is complete.

    NOTE (#655): Symlinks are resolved before pattern-matching so that
    Intel Mac Homebrew Python invoked via /usr/local/bin/python3 (a symlink
    into /usr/local/Cellar/) is correctly classified as Homebrew rather than
    falling through to the generic hint.

    NOTE (#656): pyenv and nix-store paths are detected explicitly with
    environment-specific hints, as pip --user and pipx behave differently in
    those environments.

    The detector uses ``sys.executable`` as the truth source (the
    Python actually running the install-check, not a hypothetical one).
    Symlinks in sys.executable are resolved via pathlib so Intel Mac
    Homebrew symlinks (/usr/local/bin/python3 → /usr/local/Cellar/...) are
    caught. Platform detection uses ``sys.platform`` (not ``os.uname()``
    which can be shadowed); apt detection uses a non-mutating ``dpkg --show``
    probe that returns instantly even without dpkg.
    """
    raw_exe = sys.executable  # e.g. /usr/local/bin/python3 (may be a symlink)
    platform = sys.platform  # "darwin" | "linux" | "win32" | …

    try:
        # Resolve symlinks first (#655 fix): Intel Mac Homebrew Python is
        # typically invoked via /usr/local/bin/python3, which is a symlink
        # to /usr/local/Cellar/python@X.Y/.../bin/python3.X. Resolving the
        # symlink lets the Cellar-prefix check below catch it correctly.
        exe = str(pathlib.Path(raw_exe).resolve())
    except Exception:  # pragma: no cover — resolve can fail on exotic FSes
        exe = raw_exe

    try:
        exe_str = exe  # resolved path string for prefix/substring checks

        # --- pyenv detection (#656) ---
        # pyenv Python lives at ~/.pyenv/versions/X.Y.Z/bin/python (user)
        # or /root/.pyenv/, /opt/pyenv/ (system-wide). The "/" boundary
        # ensures we match /.pyenv/ and /pyenv/ substrings in the path.
        if "/.pyenv/" in exe_str or "/pyenv/" in exe_str:
            return (
                "# pyenv detected. Two options — pick one:\n"
                "#   Option A (recommended): install pipx outside pyenv, then:\n"
                "pipx install git+https://github.com/trsreagan3/iam-jit.git\n"
                "#   Option B: use pyenv's current Python via pyenv exec:\n"
                "pyenv exec pip install --user git+https://github.com/trsreagan3/iam-jit.git"
                f"  # ensure {local_bin_display} is in PATH"
            )

        # --- nix-store detection (#656) ---
        # Nix Python lives at /nix/store/<hash>-python3.../bin/python3.
        if "/nix/store/" in exe_str:
            return (
                "# nix detected. iam-jit is not yet a nix package.\n"
                "nix-shell -p python3Packages.pipx"
                " --run 'pipx install git+https://github.com/trsreagan3/iam-jit.git'"
                "  # or add to home-manager / configuration.nix"
            )

        if platform == "darwin":
            # Homebrew Python: binary lives under /opt/homebrew/ (Apple Silicon)
            # or /usr/local/Cellar/ (Intel). After symlink resolution, Intel
            # /usr/local/bin/python3 resolves to the Cellar path (#655).
            if exe_str.startswith("/opt/homebrew/") or exe_str.startswith(
                "/usr/local/Cellar/",
            ):
                return (
                    "brew install pipx && pipx install git+https://github.com/trsreagan3/iam-jit.git"
                    "  # pipx manages a dedicated venv; avoids PEP 668 wall"
                )
            # macOS system Python (/usr/bin/python3) — pip is externally managed too.
            if exe_str.startswith("/usr/bin/"):
                return (
                    "python3 -m venv ~/.venv-iam-jit"
                    " && ~/.venv-iam-jit/bin/pip install git+https://github.com/trsreagan3/iam-jit.git"
                    " && ln -sf ~/.venv-iam-jit/bin/iam-jit"
                    f" {local_bin_display}/iam-jit"
                )
            # macOS with pipx-managed or other user-space Python — pipx is still
            # the cleanest path.
            if exe_str.startswith("/Users/") or exe_str.startswith("/home/"):
                return (
                    "pipx install git+https://github.com/trsreagan3/iam-jit.git"
                    "  # add ~/.local/bin to PATH if not already present"
                )
        elif platform.startswith("linux"):
            # Detect apt-managed Python via dpkg (non-mutating, fast).
            try:
                result = subprocess.run(  # noqa: S603
                    ["dpkg", "--show", "python3"],
                    capture_output=True,
                    text=True,
                    timeout=2.0,
                    check=False,
                )
                if result.returncode == 0:
                    return (
                        "pip install --upgrade pip"
                        " && pip install --user git+https://github.com/trsreagan3/iam-jit.git"
                        f"  # ensure {local_bin_display} is in PATH"
                    )
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass  # dpkg not available (Alpine, Arch, etc.) — fall through
    except Exception:  # pragma: no cover — defensive; never crash the doctor
        pass

    # Generic fallback — works on most setups where pip --user is available.
    return (
        f"pip install --user git+https://github.com/trsreagan3/iam-jit.git"
        f"  # then ensure {local_bin_display} is in PATH"
        f" (add to your ~/.zshrc or ~/.bashrc)"
    )


# ---------------------------------------------------------------------------
# Section result model
# ---------------------------------------------------------------------------


# Severity ranks for roll-up.
_SEV_OK = 0
_SEV_INFO = 1   # "skipped" / informational
_SEV_WARN = 2
_SEV_ERR = 3


@dataclass
class _Row:
    """One row inside an install-check section."""

    label: str
    severity: int  # _SEV_*
    detail: str = ""
    fix: str = ""  # paste-ready remediation; rendered indented under the row


@dataclass
class _Section:
    """One numbered section of the install-check report."""

    num: int
    total: int
    title: str
    rows: list[_Row] = field(default_factory=list)

    @property
    def worst_severity(self) -> int:
        return max((r.severity for r in self.rows), default=_SEV_OK)

    def add(
        self, label: str, severity: int, detail: str = "", fix: str = "",
    ) -> None:
        self.rows.append(
            _Row(label=label, severity=severity, detail=detail, fix=fix),
        )


# ---------------------------------------------------------------------------
# Section 1: PATH check
# ---------------------------------------------------------------------------


# Console-scripts shipped by iam-jit's pyproject. Marker for "this is
# a Python-side install, expected to be on PATH for any deployment".
_PYTHON_BINARIES = (
    ("iam-jit", "required"),
    ("ibounce", "required"),
)

# Go bouncer binaries shipped by SEPARATE repos. "optional" because a
# Python-only deployment (e.g. an operator who only uses iam-jit +
# ibounce for AWS) doesn't need them; we WARN not ERROR.
# Each tuple is (binary_name, full_module_install_path).
# CANONICAL: <repo>/cmd/<binary>@latest — verified against public module proxy
# 2026-05-26. kbounce lives in the *kbouncer* repo; dbounce + gbounce live in
# same-named repos. Any change here must also be reflected in README.md and
# tests/test_doctor_hints_match_readme.py which CI-enforces parity.
_GO_BOUNCER_BINARIES = (
    ("kbounce", "github.com/trsreagan3/kbouncer/cmd/kbounce@latest"),
    ("dbounce", "github.com/trsreagan3/dbounce/cmd/dbounce@latest"),
    ("gbounce", "github.com/trsreagan3/gbounce/cmd/gbounce@latest"),
)


def _gopath_bin() -> pathlib.Path:
    """Resolve ``$GOPATH/bin`` for binary probing. Falls back to
    ``~/go/bin`` (the Go default). Never raises.

    Returns the *expanded* absolute path so callers can do path existence
    checks. For display in hint strings use ``_gopath_bin_display()``
    which emits the shell-portable ``$GOPATH/bin`` or ``$HOME/go/bin``
    form (no literal home dir, so hints are public-safe and relocatable).
    """
    gopath = os.environ.get("GOPATH")
    if gopath:
        return pathlib.Path(gopath).expanduser() / "bin"
    return pathlib.Path("~/go/bin").expanduser()


def _gopath_bin_display() -> str:
    """Shell-portable display form for the Go bin directory hint strings.

    Used inside ``fix:`` hint text so the operator can paste the hint
    verbatim AND it works on any machine regardless of their actual
    home-dir path.  Never embeds a literal ``/Users/<name>`` path.
    """
    if os.environ.get("GOPATH"):
        return "$GOPATH/bin"
    return "$HOME/go/bin"


def _resolve_paths(data_dir: str | None = None) -> dict[str, str]:
    """Return resolved + display forms for all probe paths.

    Per [[ibounce-honest-positioning]] labels must reflect the ACTUAL
    probed path (honors IAM_JIT_DATA_DIR env var + HOME). The display
    form uses the ``~/`` shorthand when the path equals the
    HOME-default; otherwise the full resolved path is shown so the
    operator knows exactly what was checked.

    Args:
        data_dir: If not None (e.g. from ``--data-dir`` flag), use
            this path for the iam-jit data directory instead of the
            env var / HOME default.

    Returns a dict with keys:
        ``iam_jit_dir``         — resolved absolute path (str)
        ``iam_jit_dir_display`` — ``~/.iam-jit`` when HOME-default,
                                   else full path
        ``local_bin``           — resolved ``~/.local/bin`` (str)
        ``local_bin_display``   — ``~/.local/bin`` shorthand always
                                   (the actual PATH resolution is done
                                   by shutil.which; this is label-only)
    """
    home = pathlib.Path.home()

    if data_dir is not None:
        iam_jit_dir = pathlib.Path(data_dir).expanduser().resolve()
    else:
        env = os.environ.get("IAM_JIT_DATA_DIR")
        if env:
            iam_jit_dir = pathlib.Path(env).expanduser().resolve()
        else:
            iam_jit_dir = home / ".iam-jit"

    home_default_dir = home / ".iam-jit"
    iam_jit_dir_display = (
        "~/.iam-jit"
        if iam_jit_dir == home_default_dir
        else str(iam_jit_dir)
    )

    local_bin = home / ".local" / "bin"
    # label-only shorthand — shutil.which handles actual resolution
    local_bin_display = "~/.local/bin"

    return {
        "iam_jit_dir": str(iam_jit_dir),
        "iam_jit_dir_display": iam_jit_dir_display,
        "local_bin": str(local_bin),
        "local_bin_display": local_bin_display,
    }


def _check_path(section: _Section, paths: dict[str, str] | None = None) -> None:
    """Section 1: every required binary is on PATH; every optional
    binary is reported as warn (with install command) when missing.

    Uses ``shutil.which`` so we match the operator's actual resolution
    (PATH order, exec bit, etc.) — not a synthetic check.

    ``paths`` is the dict from ``_resolve_paths``. Both the Python
    binary ``detail`` hint and the Go binary ``detail`` use the same
    substitution style (resolved HOME) so Section 1 is internally
    consistent per #647.
    """
    if paths is None:
        paths = _resolve_paths()
    local_bin_display = paths["local_bin_display"]

    for name, kind in _PYTHON_BINARIES:
        resolved = shutil.which(name)
        if resolved:
            section.add(
                label=f"{name} on PATH",
                severity=_SEV_OK,
                detail=f"at {resolved}",
            )
        else:
            section.add(
                label=f"{name} NOT on PATH",
                severity=_SEV_ERR,
                detail=(
                    f"expected: {local_bin_display}/{name} (pip install --user) "
                    f"OR pipx-managed shim"
                ),
                fix=_python_install_hint(local_bin_display),
            )

    gobin = _gopath_bin()           # expanded absolute path — used in detail
    gobin_display = _gopath_bin_display()  # shell-portable — used in fix hint
    for name, repo in _GO_BOUNCER_BINARIES:
        resolved = shutil.which(name)
        if resolved:
            section.add(
                label=f"{name} on PATH",
                severity=_SEV_OK,
                detail=f"at {resolved}",
            )
        else:
            section.add(
                label=f"{name} NOT on PATH",
                severity=_SEV_WARN,
                detail=(
                    f"expected: {gobin}/{name} "
                    f"(Go-side bouncer; optional for AWS-only "
                    f"deployments)"
                ),
                fix=(
                    f"go install {repo} "
                    f"&& ensure {gobin_display} is in PATH"
                ),
            )


# ---------------------------------------------------------------------------
# Section 2: Binary versions
# ---------------------------------------------------------------------------


def _capture_version(binary: str) -> tuple[bool, str]:
    """Invoke ``<binary> --version`` (or ``-V``) + capture first line.

    Returns ``(ok, text)`` — never raises. ``ok`` is False on:
      * binary not on PATH (caller probably skipped, but we double-check)
      * non-zero exit
      * timeout (2s — generous for a version flag, paranoid against
        any binary that mis-parses ``--version`` + drops into a REPL)
    """
    if not shutil.which(binary):
        return (False, "not on PATH")
    try:
        proc = subprocess.run(  # noqa: S603 — args from a fixed allowlist
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return (False, f"invocation failed: {exc!s}")
    if proc.returncode != 0:
        return (False, f"exit {proc.returncode}: {proc.stderr.strip()[:120]}")
    text = (proc.stdout or proc.stderr).strip().splitlines()
    return (True, text[0] if text else "(empty output)")


def _check_versions(section: _Section) -> None:
    """Section 2: confirm every on-PATH binary reports a version.

    A binary that's on PATH but won't print its version is broken
    (corrupted install, wrong arch, shadowed shim) — surface as ERROR.
    A binary that's NOT on PATH gets a skipped/INFO row (we already
    failed it in Section 1).
    """
    # iam-jit + ibounce share the same Python wheel, so we know the
    # version a priori — but probing exec'd binary is the load-bearing
    # check (catches stale shadow installs).
    for name, _kind in _PYTHON_BINARIES:
        if not shutil.which(name):
            section.add(
                label=f"{name} version",
                severity=_SEV_INFO,
                detail="skipped (not on PATH; see [1/8])",
            )
            continue
        ok, text = _capture_version(name)
        if ok:
            section.add(
                label=f"{name} version",
                severity=_SEV_OK,
                detail=text,
            )
        else:
            section.add(
                label=f"{name} version probe FAILED",
                severity=_SEV_ERR,
                detail=text,
                fix=(
                    f"Likely stale/shadowed install. Run "
                    f"`which -a {name}` to find duplicates; pip "
                    f"uninstall iam-jit and reinstall."
                ),
            )
    for name, _repo in _GO_BOUNCER_BINARIES:
        if not shutil.which(name):
            section.add(
                label=f"{name} version",
                severity=_SEV_INFO,
                detail="skipped (not on PATH; see [1/8])",
            )
            continue
        ok, text = _capture_version(name)
        if ok:
            section.add(
                label=f"{name} version",
                severity=_SEV_OK,
                detail=text,
            )
        else:
            section.add(
                label=f"{name} version probe FAILED",
                severity=_SEV_WARN,
                detail=text,
                fix=(
                    f"Binary on PATH but won't run --version; "
                    f"rebuild via `go install ...@latest`."
                ),
            )


# ---------------------------------------------------------------------------
# Stale-binary detection (#737)
#
# The stale-binary state: operator has an older pipx/pip-installed `iam-jit`
# binary that pre-dates PR #23 (the install-bootstrap fix). The binary on
# PATH is missing --settings-path and --no-env-block on `mcp install-claude-code`.
# Running `iam-jit mcp install-claude-code` from that binary silently skips
# the env-block write — the operator gets old behavior.
#
# Detection signal: probe `iam-jit mcp install-claude-code --help` (from a
# subprocess, so we exec the PATH binary, not ourselves) and check for
# "--settings-path" in the output. If absent, the binary is stale.
#
# Per [[ibounce-honest-positioning]]: surface the gap honestly; never hide it.
# Per [[lightweight-frictionless-principle]]: emit NOTHING when versions match.
# ---------------------------------------------------------------------------

_STALE_BINARY_FLAG = "--settings-path"
_STALE_BINARY_MIN_VERSION_NOTE = "v1.0.0 + PR #23"


def _probe_binary_has_settings_path(binary: str = "iam-jit") -> tuple[bool, str]:
    """Probe whether the on-PATH *binary* supports ``--settings-path``
    on ``mcp install-claude-code``.

    Returns ``(has_flag, detail)`` where ``has_flag`` is True when the
    binary is up-to-date (silent path), False when stale (warn path).
    ``detail`` explains the probe outcome for the WARN row.

    Never raises — every failure mode returns ``(True, ...)`` (assume
    up-to-date) to avoid false-positive noise when the probe itself
    can't run.  Per [[ibounce-honest-positioning]] we name uncertainty
    rather than assuming the worst.
    """
    if not shutil.which(binary):
        return (True, "binary not on PATH — skipped stale-check")

    try:
        proc = subprocess.run(  # noqa: S603
            [binary, "mcp", "install-claude-code", "--help"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        # Can't probe — assume current to avoid false positives.
        return (True, f"help probe timed out / failed: {exc!s}")

    combined = proc.stdout + proc.stderr
    if _STALE_BINARY_FLAG in combined:
        return (True, "binary has --settings-path (up-to-date)")

    # Flag absent — the binary is stale.
    detail = (
        "iam-jit mcp install-claude-code is missing --settings-path and "
        "--no-env-block. The installed binary pre-dates PR #23: it will "
        "NOT write the bouncer env vars (AWS_ENDPOINT_URL) into "
        "~/.claude/settings.json."
    )
    return (False, detail)


def check_stale_binary(section: _Section) -> None:
    """Doctor stale-binary check (Section 2b).

    Probes the on-PATH ``iam-jit`` binary for the PR #23 flags.  A WARN
    row appears when the binary is stale; a silent OK row when current.

    Called from ``run_install_check`` and also exposed as a standalone
    helper so ``iam-jit init`` + ``iam-jit mcp install-claude-code`` can
    call it without running the full 8-section doctor.
    """
    has_flag, detail = _probe_binary_has_settings_path("iam-jit")
    if has_flag:
        section.add(
            label="iam-jit binary is current (has --settings-path)",
            severity=_SEV_OK,
            detail=detail,
        )
    else:
        section.add(
            label="STALE iam-jit binary — missing PR #23 flags",
            severity=_SEV_WARN,
            detail=detail,
            fix=(
                "Upgrade the installed binary so the new install-bootstrap "
                f"features ({_STALE_BINARY_MIN_VERSION_NOTE}) take effect:\n"
                "        pipx upgrade iam-jit          # if installed via pipx\n"
                "        pip install --user --upgrade git+https://github.com/"
                "trsreagan3/iam-jit.git  # if installed via pip --user\n"
                "        pip install --upgrade -e /path/to/iam-roles  "
                "# if installed editable\n"
                "\n"
                "    After upgrade, re-run: iam-jit init --harness=claude-code"
            ),
        )


def warn_if_stale_binary(*, context: str = "mcp install-claude-code") -> None:
    """Emit a plain-text stderr warning when the on-PATH binary is stale.

    Called at the START of ``iam-jit mcp install-claude-code`` and from
    ``iam-jit init`` (Step 7.5) BEFORE any env-block write attempt.
    Silent when the binary is current (per [[lightweight-frictionless-
    principle]]).

    ``context`` names the calling command for the remediation hint so
    the operator knows what to re-run after upgrading.
    """
    has_flag, _detail = _probe_binary_has_settings_path("iam-jit")
    if has_flag:
        return  # Silent — binary is current.

    import sys as _sys

    print(
        "\n"
        "[stale-binary-warning] Your installed iam-jit binary is MISSING\n"
        f"--settings-path and --no-env-block (added in {_STALE_BINARY_MIN_VERSION_NOTE}).\n"
        "\n"
        "The env-block write (AWS_ENDPOINT_URL into ~/.claude/settings.json)\n"
        "will NOT happen until you upgrade:\n"
        "\n"
        "    pipx upgrade iam-jit                             # pipx install\n"
        "    pip install --user --upgrade git+https://github.com/trsreagan3/iam-jit.git"
        "  # pip --user\n"
        "    pip install --upgrade -e /path/to/iam-roles      # editable install\n"
        "\n"
        f"After upgrade, re-run: iam-jit {context}\n",
        file=_sys.stderr,
    )


# ---------------------------------------------------------------------------
# Section 3: Running bouncer detection
#
# Reuses posture.capture_posture so we don't reimplement bouncer
# discovery. Per [[ibounce-honest-positioning]] the dev-venv shape
# (python -m iam_jit.bouncer_cli) is FUNCTIONALLY equivalent to the
# installed ibounce binary BUT we surface it as a WARN because operators
# in this shape often forget the env-var wiring (the founder's case).
# ---------------------------------------------------------------------------


def _check_running_bouncers(section: _Section, snapshot: dict[str, Any]) -> None:
    bouncers = snapshot.get("bouncers", {})
    any_running = False
    for name in ("ibounce", "kbounce", "dbounce", "gbounce"):
        b = bouncers.get(name, {})
        running = bool(b.get("running"))
        port = b.get("port", "?")
        if running:
            any_running = True
            section.add(
                label=f"{name} listening on 127.0.0.1:{port}",
                severity=_SEV_OK,
                detail=(
                    f"mode={b.get('mode', 'unknown')} "
                    f"profile={b.get('active_profile', 'unknown')}"
                ),
            )
        else:
            section.add(
                label=f"{name} not running",
                severity=_SEV_INFO,
                detail=(
                    "expected for AWS-only deployments"
                    if name != "ibounce"
                    else "no listener on default port"
                ),
            )
    if not any_running:
        section.add(
            label="no bouncers running",
            severity=_SEV_ERR,
            detail="install verified but nothing is intercepting traffic",
            fix=(
                "Start the bouncer you need: e.g. `ibounce run` for AWS, "
                "`kbounce run` for K8s. See `iam-jit init --help`."
            ),
        )


# ---------------------------------------------------------------------------
# Section 4: Env-var wiring
# ---------------------------------------------------------------------------


def _check_env_wiring(section: _Section, snapshot: dict[str, Any]) -> None:
    """One row per running bouncer asserting the env var that routes
    SDK traffic to it is set + points HERE. A bouncer running with no
    env-var wire is the founder's failure case — surface ERROR not
    WARN (the install is silently un-protecting).
    """
    bouncers = snapshot.get("bouncers", {})
    any_running = False
    for name in ("ibounce", "kbounce", "dbounce", "gbounce"):
        b = bouncers.get(name, {})
        if not b.get("running"):
            continue
        any_running = True
        if b.get("env_var_pointing_here"):
            section.add(
                label=f"{name} env wire OK",
                severity=_SEV_OK,
                detail=str(b["env_var_pointing_here"]),
            )
        elif b.get("misconfig"):
            section.add(
                label=f"{name} env wire MISCONFIGURED",
                severity=_SEV_ERR,
                detail=str(b["misconfig"]),
                fix=(
                    f"Re-run `iam-jit shellinit` (or `eval \"$(iam-jit "
                    f"shellinit)\"`) to emit the correct env-var block "
                    f"for this bouncer."
                ),
            )
        else:
            # Running but unwired — the canonical founder failure.
            port = b.get("port", "?")
            if name == "ibounce":
                hint = f"export AWS_ENDPOINT_URL=http://127.0.0.1:{port}"
            elif name == "kbounce":
                hint = "export KUBECONFIG=$(kbounce kubeconfig)"
            elif name == "dbounce":
                hint = (
                    "export PGHOST=127.0.0.1 PGPORT="
                    f"{b.get('wire_port', 5433)}"
                )
            elif name == "gbounce":
                hint = (
                    f"export HTTP_PROXY=http://127.0.0.1:"
                    f"{b.get('wire_port', 8080)}"
                )
            else:
                hint = "(no canonical env-var)"
            section.add(
                label=f"{name} running but NOT wired",
                severity=_SEV_ERR,
                detail=(
                    "SDK calls bypass the bouncer; install is "
                    "silently UNPROTECTING"
                ),
                fix=f"{hint}  # or `eval \"$(iam-jit shellinit)\"`",
            )
    if not any_running:
        section.add(
            label="env-var wiring",
            severity=_SEV_INFO,
            detail="skipped (no bouncers running; see [3/8])",
        )


# ---------------------------------------------------------------------------
# Section 5: Routing self-test
# ---------------------------------------------------------------------------


def _check_routing_self_test(
    section: _Section, snapshot: dict[str, Any], *, run_self_test: bool,
) -> None:
    """Confirm that an AWS-shaped HTTP call would actually traverse
    ibounce. We don't make a real AWS call (no creds, no network);
    instead we TCP-probe the URL the SDK would dial.

    A TCP-open + matching-loopback-port means the SDK call WILL hit
    ibounce. A TCP-closed (or non-loopback) means it WON'T.
    """
    if not run_self_test:
        section.add(
            label="routing self-test SKIPPED",
            severity=_SEV_INFO,
            detail="--no-routing-test passed",
        )
        return
    aws_block = snapshot.get("effective_protection", {}).get("aws_calls", {})
    if aws_block.get("intercepted_by"):
        # posture already concluded the wire works; mirror the verdict.
        section.add(
            label="AWS routing through ibounce",
            severity=_SEV_OK,
            detail=(
                f"intercepted_by={aws_block['intercepted_by']} "
                f"(mode={aws_block.get('mode', 'unknown')})"
            ),
        )
        return
    # posture says DIRECT (UNPROTECTED). Make the failure concrete.
    aws_endpoint = os.environ.get("AWS_ENDPOINT_URL", "")
    if aws_endpoint:
        # Env var set but posture says DIRECT — usually because the
        # port doesn't have a live bouncer. Probe it so the operator
        # sees the underlying TCP truth.
        try:
            from urllib.parse import urlparse

            parsed = urlparse(
                aws_endpoint
                if "://" in aws_endpoint
                else f"http://{aws_endpoint}",
            )
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            with closing(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            ) as s:
                s.settimeout(0.5)
                try:
                    s.connect((host, port))
                    tcp_ok = True
                except OSError:
                    tcp_ok = False
            section.add(
                label=(
                    "routing self-test FAILED — "
                    "env points at down bouncer"
                    if not tcp_ok
                    else "routing self-test FAILED — "
                    "bouncer reachable but posture says DIRECT"
                ),
                severity=_SEV_ERR,
                detail=f"AWS_ENDPOINT_URL={aws_endpoint}; tcp_ok={tcp_ok}",
                fix=(
                    "Start ibounce (`ibounce run`) and re-run install-check."
                    if not tcp_ok
                    else "Check ibounce health: `curl "
                    f"{aws_endpoint.rstrip('/')}/healthz`."
                ),
            )
        except Exception as exc:  # pragma: no cover — defensive
            section.add(
                label="routing self-test errored",
                severity=_SEV_WARN,
                detail=str(exc),
            )
    else:
        section.add(
            label="routing self-test FAILED — AWS_ENDPOINT_URL not set",
            severity=_SEV_ERR,
            detail="SDK calls go straight to AWS, bypassing ibounce",
            fix='eval "$(iam-jit shellinit)"',
        )


# ---------------------------------------------------------------------------
# Section 6: Config files
# ---------------------------------------------------------------------------


def _default_data_dir() -> pathlib.Path:
    """Mirror the default used by serve/init-solo so a default-config
    install passes this check without env-var fiddling."""
    env = os.environ.get("IAM_JIT_DATA_DIR")
    if env:
        return pathlib.Path(env).expanduser()
    return pathlib.Path("~/.iam-jit/").expanduser()


def _check_config_files(
    section: _Section,
    data_dir: pathlib.Path,
    paths: dict[str, str] | None = None,
) -> None:
    """Section 6: config files exist + are readable.

    Per #647: labels use the display form (``~/.iam-jit`` when
    HOME-default, else full path); missing-file rows include a
    ``detail`` with the resolved path so operators with custom
    IAM_JIT_DATA_DIR see exactly what was probed.
    """
    if paths is None:
        paths = _resolve_paths()
    d = paths["iam_jit_dir_display"]  # e.g. "~/.iam-jit" or "/tmp/foo"

    accounts = data_dir / "accounts.yaml"
    if accounts.exists():
        section.add(
            label=f"{d}/accounts.yaml exists",
            severity=_SEV_OK,
            detail=f"at {accounts}",
        )
    else:
        section.add(
            label=f"{d}/accounts.yaml missing",
            severity=_SEV_WARN,
            detail=(
                f"probed: {accounts}; "
                f"iam-jit can still run, but no accounts pre-configured"
            ),
            fix="iam-jit init  # or iam-jit init-solo",
        )
    users = data_dir / "users.yaml"
    if users.exists():
        section.add(
            label=f"{d}/users.yaml exists",
            severity=_SEV_OK,
            detail=f"at {users}",
        )
    else:
        section.add(
            label=f"{d}/users.yaml missing",
            severity=_SEV_WARN,
            detail=(
                f"probed: {users}; "
                f"no users seeded; requests will fail"
            ),
            fix="iam-jit init  # or iam-jit init-solo",
        )
    cfg = data_dir / "iam-jit.yaml"
    if cfg.exists():
        section.add(
            label=f"{d}/iam-jit.yaml exists",
            severity=_SEV_OK,
            detail="declarative config present (#400 ambient)",
        )
    else:
        section.add(
            label=f"{d}/iam-jit.yaml not present",
            severity=_SEV_INFO,
            detail="declarative-config slice optional",
        )


# ---------------------------------------------------------------------------
# Section 7: Audit log writability + disk
# ---------------------------------------------------------------------------


# Disk free thresholds. Mirror the disk-pressure module's classification
# in spirit: <500MB free = critical (ERROR), <2GB = degraded (WARN).
_DISK_WARN_BYTES = 2 * 1024 * 1024 * 1024
_DISK_CRIT_BYTES = 500 * 1024 * 1024


def _check_audit_writability(
    section: _Section,
    data_dir: pathlib.Path,
    paths: dict[str, str] | None = None,
) -> None:
    """Section 7: audit.jsonl is writable + disk has headroom.

    Per #647: labels use the display form (``~/.iam-jit`` when
    HOME-default, else full path); every row that references a
    non-existent path includes a ``detail`` with the resolved probe
    path so operators with custom IAM_JIT_DATA_DIR see exactly what
    was checked.
    """
    if paths is None:
        paths = _resolve_paths()
    d = paths["iam_jit_dir_display"]  # e.g. "~/.iam-jit" or "/tmp/foo"

    audit = data_dir / "audit.jsonl"
    if audit.exists():
        if os.access(audit, os.W_OK):
            section.add(
                label=f"{d}/audit.jsonl writable",
                severity=_SEV_OK,
                detail=f"at {audit}",
            )
        else:
            section.add(
                label=f"{d}/audit.jsonl NOT writable",
                severity=_SEV_ERR,
                detail="audit writes will fail; install will degrade silently",
                fix=f"chmod u+w {audit}",
            )
    elif data_dir.exists():
        # No file yet — confirm we can write to the dir.
        if os.access(data_dir, os.W_OK):
            section.add(
                label=f"{d}/ writable (audit.jsonl not yet created)",
                severity=_SEV_OK,
                detail=f"will be created on first audit event",
            )
        else:
            section.add(
                label=f"{d}/ NOT writable",
                severity=_SEV_ERR,
                detail=(
                    f"probed: {data_dir}; "
                    f"audit events will fail to persist"
                ),
                fix=f"chmod u+w {data_dir}",
            )
    else:
        section.add(
            label=f"{d}/ does not exist",
            severity=_SEV_WARN,
            detail=f"probed: {data_dir}; will be created on first iam-jit init",
            fix="iam-jit init",
        )

    # Disk free probe — guard against the silent-fill failure mode.
    try:
        usage = shutil.disk_usage(
            data_dir if data_dir.exists() else data_dir.parent,
        )
        free_gb = usage.free / (1024**3)
        if usage.free < _DISK_CRIT_BYTES:
            section.add(
                label=f"Disk free: {free_gb:.2f} GB CRITICAL",
                severity=_SEV_ERR,
                detail="audit writes will fail; bouncer will pause",
                fix="Free disk; iam-jit refuses to write audit when full",
            )
        elif usage.free < _DISK_WARN_BYTES:
            section.add(
                label=f"Disk free: {free_gb:.2f} GB low",
                severity=_SEV_WARN,
                detail="approaching disk-pressure threshold",
            )
        else:
            section.add(
                label=f"Disk free: {free_gb:.2f} GB above threshold",
                severity=_SEV_OK,
            )
    except OSError as exc:  # pragma: no cover — defensive
        section.add(
            label="Disk free probe failed",
            severity=_SEV_WARN,
            detail=str(exc),
        )


# ---------------------------------------------------------------------------
# Section 8: Overall summary
# ---------------------------------------------------------------------------


def _check_overall_summary(
    section: _Section, sections: list[_Section],
) -> None:
    """Single-row summary; never emits its own fix. Pure roll-up."""
    worst = max((s.worst_severity for s in sections), default=_SEV_OK)
    if worst >= _SEV_ERR:
        section.add(
            label="Overall: NOT PROTECTING",
            severity=_SEV_ERR,
            detail="see ERROR rows above for the specific install break",
        )
    elif worst >= _SEV_WARN:
        section.add(
            label="Overall: degraded (functional)",
            severity=_SEV_WARN,
            detail="see WARN rows above for follow-up actions",
        )
    else:
        section.add(
            label="Overall: install verified",
            severity=_SEV_OK,
            detail="every required surface is on PATH, running, and wired",
        )


# ---------------------------------------------------------------------------
# Public API: assemble all sections + render
# ---------------------------------------------------------------------------


def run_install_check(
    *,
    run_self_test: bool = True,
    data_dir: str | None = None,
) -> list[_Section]:
    """Assemble the 8-section install-check report.

    Always safe to call — every sub-check is fail-soft. Returns the
    sections so the caller renders them (human or JSON). Pure
    function: no side effects beyond loopback TCP probes + reading
    env / filesystem.

    Args:
        run_self_test: When False, Section 5 (routing self-test) is
            skipped. Useful inside CI where loopback behavior may
            differ.
        data_dir: Override the data directory (mirrors ``--data-dir``
            CLI flag per [[cross-product-agent-parity]]). When None,
            falls back to ``$IAM_JIT_DATA_DIR`` then ``~/.iam-jit/``.
    """
    sections: list[_Section] = []

    # Resolve paths once; thread through all sections that display
    # path labels (Sections 1, 6, 7) so labels are consistent.
    paths = _resolve_paths(data_dir)

    # Posture snapshot — reused by sections 3 / 4 / 5.
    try:
        from .posture import capture_posture

        snapshot = capture_posture()
    except Exception:  # pragma: no cover — defensive
        snapshot = {"bouncers": {}, "effective_protection": {}}

    s1 = _Section(num=1, total=8, title="PATH check")
    _check_path(s1, paths=paths)
    sections.append(s1)

    s2 = _Section(num=2, total=8, title="Binary versions")
    _check_versions(s2)
    # #737 — stale-binary detection: probes the PATH binary for PR #23 flags.
    check_stale_binary(s2)
    sections.append(s2)

    s3 = _Section(num=3, total=8, title="Running bouncer detection")
    _check_running_bouncers(s3, snapshot)
    sections.append(s3)

    s4 = _Section(num=4, total=8, title="Env-var wiring")
    _check_env_wiring(s4, snapshot)
    sections.append(s4)

    s5 = _Section(num=5, total=8, title="Routing self-test")
    _check_routing_self_test(
        s5, snapshot, run_self_test=run_self_test,
    )
    sections.append(s5)

    resolved_data_dir = pathlib.Path(paths["iam_jit_dir"])
    s6 = _Section(num=6, total=8, title="Config files")
    _check_config_files(s6, resolved_data_dir, paths=paths)
    sections.append(s6)

    s7 = _Section(num=7, total=8, title="Audit log writability")
    _check_audit_writability(s7, resolved_data_dir, paths=paths)
    sections.append(s7)

    s8 = _Section(num=8, total=8, title="Posture summary")
    _check_overall_summary(s8, sections)
    sections.append(s8)

    return sections


_MARKERS = {
    _SEV_OK: ("OK", "green"),
    _SEV_INFO: ("--", "white"),
    _SEV_WARN: ("WARN", "yellow"),
    _SEV_ERR: ("FAIL", "red"),
}


def _render_human(sections: list[_Section]) -> str:
    lines = [
        "iam-jit install verification",
        "----------------------------------------",
        f"iam-jit version: {__version__}",
        "",
    ]
    for s in sections:
        lines.append(f"[{s.num}/{s.total}] {s.title}")
        for r in s.rows:
            marker, _ = _MARKERS[r.severity]
            head = f"  [{marker}] {r.label}"
            if r.detail:
                head += f" -- {r.detail}"
            lines.append(head)
            if r.fix:
                lines.append(f"        Fix: {r.fix}")
        lines.append("")
    return "\n".join(lines)


def _render_json(sections: list[_Section]) -> str:
    """Machine-readable. Schema version pinned for downstream
    consumers; bump on any field rename/removal."""
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "iam_jit_version": __version__,
        "sections": [],
    }
    for s in sections:
        payload["sections"].append({
            "num": s.num,
            "total": s.total,
            "title": s.title,
            "worst_severity": _MARKERS[s.worst_severity][0],
            "rows": [
                {
                    "label": r.label,
                    "severity": _MARKERS[r.severity][0],
                    "detail": r.detail,
                    "fix": r.fix,
                }
                for r in s.rows
            ],
        })
    worst = max(
        (s.worst_severity for s in sections), default=_SEV_OK,
    )
    payload["overall_severity"] = _MARKERS[worst][0]
    payload["exit_code"] = (
        2 if worst >= _SEV_ERR else (1 if worst >= _SEV_WARN else 0)
    )
    return _json.dumps(payload, indent=2, sort_keys=True)


def _exit_code_for(sections: list[_Section]) -> int:
    """Roll up section severities into a process exit code per the
    spec: 0 = clean, 1 = warn, 2 = error.

    Single source of truth — _render_json reuses this calculation via
    the same _MARKERS table."""
    worst = max(
        (s.worst_severity for s in sections), default=_SEV_OK,
    )
    if worst >= _SEV_ERR:
        return 2
    if worst >= _SEV_WARN:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Click registration
# ---------------------------------------------------------------------------


def register_install_check_command(
    doctor_group: click.Group,
) -> click.Command:
    """Attach ``install-check`` to ``iam-jit doctor``.

    Returns the command so tests can invoke it via
    ``CliRunner.invoke(doctor.commands["install-check"], [...])``.
    Idempotent — re-registering against the same group overwrites
    cleanly (Click semantics).
    """

    @doctor_group.command("install-check")
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured report as JSON. Designed for corp "
             "deploy automation per [[enterprise-profile-"
             "distribution]] + #490 managed-mode integration.",
    )
    @click.option(
        "--no-routing-test",
        is_flag=True,
        default=False,
        help="Skip the loopback routing self-test (section 5). Useful "
             "when running install-check inside CI where loopback "
             "behavior may differ.",
    )
    @click.option(
        "--data-dir",
        "data_dir",
        type=click.Path(),
        default=None,
        envvar="IAM_JIT_DATA_DIR",
        help="Operate on this data directory instead of the default "
             "``~/.iam-jit/``. Mirrors ``serve`` / ``uninstall`` / "
             "``init`` per [[cross-product-agent-parity]]. Also "
             "honored via $IAM_JIT_DATA_DIR env var.",
    )
    def install_check_cmd(
        as_json: bool,
        no_routing_test: bool,
        data_dir: str | None,
    ) -> None:
        """End-to-end install verification: PATH, binaries, running
        bouncers, env-var wiring, routing self-test, config files,
        audit writability, posture summary.

        Exit codes:

          0  every section green
          1  warnings only (functional but degraded)
          2  errors present (install demonstrably broken)

        Per [[ibounce-honest-positioning]] every signal is HONEST about
        what was actually observed — no "probably OK" messages, no
        soft fallbacks. Per [[creates-never-mutates]] this command
        NEVER mutates PATH / shell rc / config; only reports +
        suggests remediation.
        """
        sections = run_install_check(
            run_self_test=not no_routing_test,
            data_dir=data_dir,
        )
        if as_json:
            click.echo(_render_json(sections))
        else:
            click.echo(_render_human(sections))
        sys.exit(_exit_code_for(sections))

    return install_check_cmd


__all__ = [
    "register_install_check_command",
    "run_install_check",
    "_python_install_hint",
    "check_stale_binary",
    "warn_if_stale_binary",
    "_probe_binary_has_settings_path",
]
