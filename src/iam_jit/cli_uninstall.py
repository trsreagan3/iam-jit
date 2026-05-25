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
IAM_JIT_HOME = pathlib.Path.home() / ".iam-jit"
VENV_DIR = IAM_JIT_HOME / "venv"
BOUNCER_DIR = IAM_JIT_HOME / "bouncer"
AUDIT_PATH = IAM_JIT_HOME / "audit.jsonl"
ANOMALY_BASELINE_PATH = IAM_JIT_HOME / "anomaly-baseline.db"
CANARY_DIR = IAM_JIT_HOME / "canary"

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    """Best-effort PID discovery for a TCP-listening port via ``lsof``.

    Mirrors ``cli_canary._lsof_pids_on_port``. Returns an empty list on
    any error / when ``lsof`` is not installed (slim Linux containers).
    Used by :func:`_inventory_installed_state` to cross-reference
    bouncer-port owners back to PIDs — the #574 fix for ``pgrep -x``
    missing Python console-script bouncers.
    """
    if shutil.which("lsof") is None:
        return []
    try:
        proc = subprocess.run(
            ["lsof", "-nP", "-iTCP:%d" % int(port), "-sTCP:LISTEN", "-t"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    out: list[int] = []
    for line in proc.stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            out.append(int(s))
        except ValueError:
            continue
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


def _inventory_installed_state() -> dict[str, Any]:
    """Build an honest inventory of what's currently installed.

    Returns a dict shaped like::

        {
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
    """
    inv: dict[str, Any] = {
        "iam_jit_home_exists": IAM_JIT_HOME.exists(),
        "venv_exists": VENV_DIR.exists(),
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
            kind = _infer_bouncer_kind_from_cmdline(cmdline)
            if kind is not None:
                inv["running_bouncers"].setdefault(kind, []).append(pid)
                seen_pids.add(pid)
            else:
                # Foreign process on a bouncer-typical port. Surface
                # rather than silently include/exclude. Per #608
                # include the expected bouncer for this port so the
                # operator sees "pid 1234 on :8766 (expected
                # kbounce)" instead of just "pid 1234 on :8766".
                inv["unknown_port_owners"].append({
                    "pid": pid,
                    "port": port,
                    "expected_bouncer": (
                        expected_kinds[0] if expected_kinds else None
                    ),
                    "cmdline": cmdline,
                })

    # Console scripts (step 3).
    if VENV_DIR.exists():
        bin_dir = VENV_DIR / "bin"
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
        p = IAM_JIT_HOME / rel
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
) -> dict[str, Any]:
    """Step 1 / Step 5 — SIGTERM running bouncers, then SIGKILL if needed.

    Returns ``{"sigterm_pids": [...], "sigkill_pids": [...], "reaped": [...],
              "failed": [...]}``.

    State verification: post-call, ``_find_pids_for_process(name)`` for
    every reaped PID must return without that PID (the caller asserts).
    """
    out: dict[str, Any] = {
        "sigterm_pids": [],
        "sigkill_pids": [],
        "reaped": [],
        "failed": [],
    }
    target_pids: list[tuple[str, int]] = []
    for name, pids in (inventory.get("running_bouncers") or {}).items():
        for pid in pids:
            target_pids.append((name, int(pid)))
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
) -> dict[str, Any]:
    """Step 2 — `pip uninstall -y iam-jit` inside the venv if it exists.

    Returns ``{"executed": bool, "venv_pip_present": bool,
              "stdout": str, "returncode": int | None}``.
    """
    pip = VENV_DIR / "bin" / "pip"
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
) -> dict[str, Any]:
    """Step 4 — remove ``$GOBIN/{gbounce,kbounce,kbouncer,dbounce}``.

    Returns ``{"removed": [...], "missing": [...], "failed": [...]}``.
    State verification: post-call, each "removed" path's ``.exists()``
    must be False.
    """
    out: dict[str, Any] = {"removed": [], "missing": [], "failed": []}
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
) -> dict[str, Any]:
    """Step 7 — remove ``~/.iam-jit/venv/``.

    Returns ``{"removed": bool, "path": str, "failed": str | None}``.
    State verification: post-call, ``VENV_DIR.exists()`` must be False.
    """
    out: dict[str, Any] = {
        "removed": False,
        "path": str(VENV_DIR),
        "failed": None,
    }
    if not VENV_DIR.exists():
        return out
    if dry_run:
        out["removed"] = True
        return out
    try:
        shutil.rmtree(VENV_DIR)
        if VENV_DIR.exists():
            out["failed"] = (
                f"{VENV_DIR}: rmtree returned but path still present"
            )
        else:
            out["removed"] = True
    except OSError as exc:
        out["failed"] = f"{VENV_DIR}: {exc}"
    return out


def _step_remove_iam_jit_home(
    *,
    dry_run: bool,
    keep_audit_logs: bool,
    backup_dir: pathlib.Path | None,
) -> dict[str, Any]:
    """Step 9 — purge ``~/.iam-jit/`` (with optional audit-log preserve
    + backup-dir snapshot).

    Returns ``{"removed_paths": [...], "preserved_paths": [...],
              "backed_up_paths": [...], "failed": [...]}``.

    State verification:
      * each "removed_paths" entry's ``.exists()`` must be False post-call.
      * if ``--keep-audit-logs``, each "preserved_paths" entry's
        ``.exists()`` must be True post-call.
      * if ``--backup-dir``, each "backed_up_paths" entry must be
        present under the backup root.
    """
    out: dict[str, Any] = {
        "removed_paths": [],
        "preserved_paths": [],
        "backed_up_paths": [],
        "failed": [],
    }
    if not IAM_JIT_HOME.exists():
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
        for child in sorted(IAM_JIT_HOME.iterdir()):
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
            p = IAM_JIT_HOME / rel
            if p.exists():
                preserve_paths.add(p)

    # Walk and remove top-level entries; preserve audit-bearing files
    # by leaving their parent dirs in place.
    for child in sorted(IAM_JIT_HOME.iterdir()):
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
            if IAM_JIT_HOME.exists():
                # Remove root only if empty (preserved file dirs may still
                # contain non-emptied subdirs we did not touch).
                contents = list(IAM_JIT_HOME.iterdir())
                if not contents:
                    IAM_JIT_HOME.rmdir()
                    out["removed_paths"].append(str(IAM_JIT_HOME))
        except OSError as exc:
            out["failed"].append(f"{IAM_JIT_HOME}: {exc}")
    return out


# ---------------------------------------------------------------------------
# Post-uninstall verification
# ---------------------------------------------------------------------------


def _verify_clean_state(
    *, keep_audit_logs: bool,
) -> dict[str, Any]:
    """Re-inventory after uninstall + report any leftover state.

    Per ``docs/CONTRIBUTING.md`` state-verification: this is the
    observable side of the "uninstall succeeded" claim. Returns a dict
    of leftover items + a boolean ``clean`` flag.
    """
    inv = _inventory_installed_state()
    leftover: dict[str, Any] = {
        "running_bouncers": inv["running_bouncers"],
        "bound_ports": inv["bound_ports"],
        "venv_exists": inv["venv_exists"],
        "console_scripts_present": inv["console_scripts_present"],
        "go_binaries_present": inv["go_binaries_present"],
    }
    # In keep-audit-logs mode, IAM_JIT_HOME existing is EXPECTED.
    leftover["iam_jit_home_exists"] = (
        inv["iam_jit_home_exists"] if not keep_audit_logs else False
    )
    has_leftover = any([
        leftover["running_bouncers"],
        leftover["bound_ports"],
        leftover["venv_exists"],
        leftover["console_scripts_present"],
        leftover["go_binaries_present"],
        leftover["iam_jit_home_exists"],
    ])
    return {
        "clean": not has_leftover,
        "leftover": leftover,
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
    backup_dir: pathlib.Path | None = None,
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
    """
    result: dict[str, Any] = {
        "status": "ok",
        "dry_run": dry_run,
        "force": force,
        "keep_audit_logs": keep_audit_logs,
        "backup_dir": str(backup_dir) if backup_dir else None,
        "inventory": {},
        "halts": [],
        "steps": {},
        "post_check": {},
    }

    inventory = _inventory_installed_state()
    result["inventory"] = inventory

    halts = _check_halt_conditions(inventory)
    result["halts"] = halts
    # Halts block destructive execution unless --force. Dry-run always
    # proceeds to compute the plan (operator needs to SEE what would
    # happen + what halts they'd need to bypass).
    if halts and not force and not dry_run:
        result["status"] = "halted"
        return result

    # Execute the 4 destructive steps (in MRR-4 order):
    #  1. stop bouncers   (steps 1 + 5)
    #  2. pip uninstall   (steps 2 + 3)
    #  3. remove go bins  (step 4)
    #  4. remove venv     (step 7)
    #  5. remove iam-jit-home  (step 9; honours --keep-audit-logs)
    result["steps"]["stop_bouncers"] = _step_stop_bouncers(
        inventory, dry_run=dry_run,
    )
    result["steps"]["pip_uninstall"] = _step_pip_uninstall(dry_run=dry_run)
    result["steps"]["remove_go_binaries"] = _step_remove_go_binaries(
        inventory, dry_run=dry_run,
    )
    result["steps"]["remove_venv"] = _step_remove_venv(dry_run=dry_run)
    result["steps"]["remove_iam_jit_home"] = _step_remove_iam_jit_home(
        dry_run=dry_run,
        keep_audit_logs=keep_audit_logs,
        backup_dir=backup_dir,
    )

    if dry_run:
        result["status"] = "dry_run"
        return result

    # Post-check: observable state matches the success claim.
    post = _verify_clean_state(keep_audit_logs=keep_audit_logs)
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

        Per ``[[creates-never-mutates]]``: uninstall only removes
        iam-jit-created resources. Shell-profile env vars, MCP config
        entries, and browser-trusted MITM CAs are surfaced as
        ``manual_reminders`` — operator must remove those by hand.
        """
        # Pre-flight inventory so the confirmation prompt is honest.
        inventory = _inventory_installed_state()

        if not as_json:
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
            keep_audit_logs=keep_audit_logs,
            backup_dir=backup_dir,
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
        if post.get("audit_logs_preserved"):
            click.secho(
                "  audit_logs_preserved: YES (per --keep-audit-logs)",
                fg="cyan",
            )


__all__ = [
    "BOUNCER_PROCESS_NAMES",
    "BOUNCER_PORTS",
    "CONSOLE_SCRIPTS",
    "GO_BINARIES",
    "AUDIT_BEARING_PATHS_REL",
    "IAM_JIT_HOME",
    "VENV_DIR",
    "register_uninstall_command",
    "run_uninstall",
]

# #608: exposed for tests + the sabotage-check that monkeypatches
# the per-bouncer port set. Not in __all__ because the leading
# underscore signals "internal — subject to change without a deprecation
# cycle"; tests import it by name explicitly.
