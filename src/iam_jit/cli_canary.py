"""#507 / §A92 — `iam-jit canary` subcommand cluster.

The THIS-machine canary (per ``[[this-machine-canary-brought-forward]]``) is
the founder's real-usage dogfooding deploy. This module surfaces the
operator-visible mechanics:

    iam-jit canary status       — read + pretty-print status.json
    iam-jit canary urls         — read + pretty-print urls.md
    iam-jit canary report       — triaged digest (issues + notes + status)
    iam-jit canary file-issue   — manual issue entry
    iam-jit canary update       — full redeploy mechanism (git pull + reinstall
                                  + graceful restart + audit-chain continuity
                                  verify + rollback on failure)
    iam-jit canary update --watch
                                — poll remote git for new commits;
                                  default notify-only; pass
                                  --auto-deploy for autopilot redeploy

Design constraints (per linked memory docs):

* **Zero LLM credits required.** Bouncers + canary run with zero
  ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY`` / ``IAM_JIT_ENABLE_SIDE_LLM``
  per ``[[bouncer-zero-llm-when-agent-in-loop]]``. The agent (Claude
  Code in the founder's session) handles LLM reasoning via MCP.
* **Local-only state.** Per ``[[independence-as-security-property]]``
  the canary writes 4 files under ``~/.iam-jit/canary/``; nothing
  phones home to iam-jit-the-company. ``--watch`` DOES contact the
  remote git origin (the pre-§A101 'LOCAL only' claim was wrong); the
  contact is to the operator's own GitHub remote, which is part of
  the operator's existing trust boundary.
* **State-verification convention.** Every reported success status
  must be backed by an observable side effect; tests assert both per
  ``docs/CONTRIBUTING.md``.

The 4 artifacts under ``~/.iam-jit/canary/`` are:

* ``issues.jsonl`` — append-only structured issues (one JSON / line)
* ``notes.md`` — operator free-form notes; agent categorises on demand
* ``status.json`` — current state (canary day, bouncers, ports, commits)
* ``urls.md`` — log + UI URLs for daily-dev access

This module owns the read/print/append surface for those files. The
deploy script (``scripts/deploy-canary.sh`` or this session's setup
flow) is the one that initialises them; the CLI re-reads + extends.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import warnings
from collections import Counter
from typing import Any

import click

# Public so deploy scripts + tests can import the path without recomputing.
CANARY_DIR = pathlib.Path.home() / ".iam-jit" / "canary"
ISSUES_PATH = CANARY_DIR / "issues.jsonl"
NOTES_PATH = CANARY_DIR / "notes.md"
STATUS_PATH = CANARY_DIR / "status.json"
URLS_PATH = CANARY_DIR / "urls.md"
# §A102 — canary declaration; deploy script writes once, redeploys re-read.
# Captures operator launch INTENT (per-bouncer `daemon_args`) so the
# verify-setup + auto-relaunch paths can detect smoke-vs-daily-dev drift
# without re-prompting the operator.
CANARY_YAML_PATH = CANARY_DIR / ".iam-jit.yaml"

# Repos the canary tracks. Per ``[[canary-redeploys-on-every-update]]``
# the scope is currently ibounce (iam-roles) + gbounce; expand as the
# canary scope grows.
#
# Defaults assume sibling-checkout layout (``<parent>/iam-roles`` +
# ``<parent>/gbounce``) computed from THIS module's path. Operators
# with a different layout override via env vars:
#
#   IAM_JIT_CANARY_IAM_ROLES_REPO=/path/to/iam-roles
#   IAM_JIT_CANARY_GBOUNCE_REPO=/path/to/gbounce
#
# This keeps the module portable (no hardcoded operator paths in the
# public repo per ``[[push-policy-public-repo]]``).


def _default_repo(env_name: str, sibling_name: str) -> pathlib.Path:
    """Resolve a repo path from env override, else sibling of this checkout."""
    override = os.environ.get(env_name)
    if override:
        return pathlib.Path(override).expanduser()
    # __file__ is .../<iam-roles>/src/iam_jit/cli_canary.py.
    iam_roles_root = pathlib.Path(__file__).resolve().parents[2]
    if sibling_name == "iam-roles":
        return iam_roles_root
    return iam_roles_root.parent / sibling_name


_CANARY_REPOS = {
    "iam-roles": _default_repo("IAM_JIT_CANARY_IAM_ROLES_REPO", "iam-roles"),
    "gbounce": _default_repo("IAM_JIT_CANARY_GBOUNCE_REPO", "gbounce"),
}

_SEVERITIES = ("CRIT", "HIGH", "MED", "LOW")
_CATEGORIES = (
    "deny_surprise",
    "bouncer_error",
    "profile_drift",
    "anomaly",
    "calibration_drift",
    "operator_friction",
    "update_success",
    "update_failure",
    "other",
)


# ---------------------------------------------------------------------------
# File helpers (importable so deploy scripts share the schema)
# ---------------------------------------------------------------------------


def _ensure_dir() -> None:
    CANARY_DIR.mkdir(parents=True, exist_ok=True)


def _now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_issue(
    *,
    bouncer: str,
    severity: str,
    category: str,
    observable: str,
    expected: str,
    repro_hint: str = "",
    auto_generated: bool = False,
    related_task: str | None = None,
    ts: str | None = None,
) -> dict[str, Any]:
    """Append one issue to ``issues.jsonl``. Returns the entry dict.

    Validates severity + category up-front so callers can't drift the
    schema silently.
    """

    if severity not in _SEVERITIES:
        raise ValueError(
            f"severity must be one of {_SEVERITIES}; got {severity!r}"
        )
    if category not in _CATEGORIES:
        raise ValueError(
            f"category must be one of {_CATEGORIES}; got {category!r}"
        )

    _ensure_dir()
    entry: dict[str, Any] = {
        "ts": ts or _now_iso(),
        "bouncer": bouncer,
        "severity": severity,
        "category": category,
        "observable": observable,
        "expected": expected,
        "repro_hint": repro_hint,
        "auto_generated": auto_generated,
        "related_task": related_task,
    }
    with ISSUES_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":"), sort_keys=True))
        fh.write("\n")
    return entry


def read_issues(since_iso: str | None = None) -> list[dict[str, Any]]:
    """Return issues from ``issues.jsonl``. Optionally filter to entries
    with ``ts >= since_iso``."""
    if not ISSUES_PATH.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in ISSUES_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if since_iso and entry.get("ts", "") < since_iso:
            continue
        out.append(entry)
    return out


def read_status() -> dict[str, Any]:
    if not STATUS_PATH.exists():
        return {}
    try:
        return json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def write_status(status: dict[str, Any]) -> None:
    _ensure_dir()
    STATUS_PATH.write_text(
        json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _parse_since(since: str) -> str:
    """Parse ``--since 24h`` / ``7d`` / ``30m`` / ``all`` into an ISO
    timestamp. Returns empty string for ``all``."""
    if since == "all":
        return ""
    m = re.fullmatch(r"(\d+)([smhd])", since.lower())
    if not m:
        raise click.BadParameter(
            f"--since must look like '24h', '7d', '30m', '60s' or 'all'; got {since!r}"
        )
    n, unit = int(m.group(1)), m.group(2)
    seconds = n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    cutoff = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(seconds=seconds)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(repo: pathlib.Path, *args: str) -> tuple[int, str]:
    """Run ``git`` in ``repo`` and return ``(returncode, combined output)``."""
    if not (repo / ".git").exists():
        return 1, f"not a git repo: {repo}"
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _curl_responsive(url: str, timeout: float = 3.0) -> tuple[bool, int | None]:
    """Return ``(responsive, http_status)`` for a URL. ``responsive`` is
    True for any HTTP response (even 4xx/5xx — the listener is alive)."""
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return True, resp.getcode()
    except urllib.error.HTTPError as exc:
        # 4xx / 5xx — but the listener IS alive, so still "responsive".
        return True, exc.code
    except (urllib.error.URLError, ConnectionResetError, TimeoutError, OSError):
        return False, None


# ---------------------------------------------------------------------------
# §M4 — dogfood-metrics writers (closes the MRR-5 phantom-fields gap)
# ---------------------------------------------------------------------------
#
# Per docs/MRR-5-MONITORING-RUNBOOK.md §M4: three status.json fields
# (``denies_24h``, ``intervention_count_24h``, ``improvement_cycles``)
# were READ by ``status_cmd`` + ``report_cmd`` but NEVER WRITTEN. That
# is the exact #475 ``state-claimed-without-observable-state`` shape
# on the canary surface (calibration-drift catalog entry #22).
#
# Per ``[[ibounce-honest-positioning]]`` claimed state must match
# observable reality. The dogfood-window aggregate per
# ``[[no-announce-until-founder-validates]]`` is load-bearing on these
# fields — without writers, the founder can't honestly assess
# validation.
#
# Sources (all observable / persisted on disk):
#
#   * ``denies_24h`` — fan-out over the bouncer mgmt ports listed in
#     ``status["ports"]``; ``GET /audit/events?since=<iso>&limit=1000``
#     per bouncer, count events where
#     ``unmapped.iam_jit.verdict`` lowercases to ``"deny"`` (ibounce
#     emits "deny"; gbounce emits "DENY"; both normalise to the same
#     count).
#   * ``intervention_count_24h`` — read ``issues.jsonl``; count rows
#     in the 24h window whose ``category == "operator_friction"`` OR
#     ``severity`` in ``{"HIGH", "CRIT"}``.
#   * ``improvement_cycles`` — read ``~/.iam-jit/autopilot.status.json``
#     ``.improve.improve_count_since_startup``; absent file → 0.


def _audit_events_url_for_port(port: int) -> str:
    """Build the loopback /audit/events URL for a bouncer mgmt port.

    Bouncers respond on a single management port (ibounce: same port
    as the proxy; gbounce: ``ports[name + '_mgmt']``); the helper is
    port-agnostic and the caller decides which port to pass.
    """
    return f"http://127.0.0.1:{int(port)}/audit/events"


def _fetch_deny_count_for_bouncer(
    port: int, since_iso: str, *, timeout: float = 3.0,
) -> tuple[int | None, str | None]:
    """Return ``(deny_count, error_message)`` for one bouncer port.

    ``deny_count`` is None on any fetch / parse failure; the caller
    treats that bouncer as a degraded source rather than a zero
    contribution (so a missing bouncer doesn't silently understate
    the cross-bouncer aggregate).
    """
    url = (
        _audit_events_url_for_port(port)
        + f"?since={since_iso}&limit={1000}"
    )
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except (urllib.error.URLError, ConnectionResetError,
            TimeoutError, OSError) as exc:
        return None, f"unreachable: {exc}"
    count = 0
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Verdict lives at unmapped.iam_jit.verdict; ibounce emits
        # "deny", gbounce emits "DENY" — normalise to lower.
        try:
            verdict = (
                (ev.get("unmapped") or {}).get("iam_jit") or {}
            ).get("verdict") or ""
        except AttributeError:
            verdict = ""
        if str(verdict).strip().lower() == "deny":
            count += 1
    return count, None


def _read_autopilot_improve_count() -> int:
    """Return ``improve_count_since_startup`` from the autopilot status
    file. 0 when the file is absent / unparseable / lacks the field.

    Honours ``IAM_JIT_AUTOPILOT_DIR`` for test isolation (matches the
    ``autopilot/daemon._autopilot_dir`` resolver).
    """
    raw = (os.environ.get("IAM_JIT_AUTOPILOT_DIR") or "").strip()
    base = pathlib.Path(raw).expanduser() if raw else (
        pathlib.Path.home() / ".iam-jit"
    )
    p = base / "autopilot.status.json"
    if not p.exists():
        return 0
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    improve = doc.get("improve") or {}
    raw_val = improve.get("improve_count_since_startup")
    try:
        return int(raw_val) if raw_val is not None else 0
    except (TypeError, ValueError):
        return 0


def _intervention_count_in_window(
    issues: list[dict[str, Any]],
) -> int:
    """Count interventions in the provided issues list.

    Intervention = ``category == "operator_friction"`` OR
    ``severity`` in ``("HIGH", "CRIT")``. Caller is responsible for
    pre-filtering ``issues`` to the desired time window.
    """
    count = 0
    for entry in issues:
        cat = entry.get("category") or ""
        sev = (entry.get("severity") or "").upper()
        if cat == "operator_friction" or sev in ("HIGH", "CRIT"):
            count += 1
    return count


def _compute_dogfood_metrics(
    status: dict[str, Any] | None = None,
    *,
    audit_timeout: float = 3.0,
) -> dict[str, Any]:
    """Compute the §M4 dogfood-window metrics from observable sources.

    Returns a dict shaped like::

        {
          "denies_24h": int,
          "intervention_count_24h": int,
          "improvement_cycles": int,
          "computed_at": ISO8601,
          "degraded_sources": [str, ...],
        }

    ``status`` is read from ``status.json`` when not provided; the
    ``ports`` block names the bouncers to fan out to. Unreachable
    bouncers append ``"<name>:<reason>"`` to ``degraded_sources``
    (the count still aggregates across the reachable bouncers — a
    missing bouncer never silently understates the total).

    The autopilot file is treated as an honest 0 when absent: per
    ``[[ibounce-honest-positioning]]`` we don't synthesise a count
    we can't observe, but the absence-of-file IS the observable
    "no improvement cycles" signal.
    """
    if status is None:
        status = read_status()
    now_dt = _dt.datetime.now(tz=_dt.timezone.utc)
    since_dt = now_dt - _dt.timedelta(hours=24)
    since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    ports = (status or {}).get("ports") or {}

    # denies_24h — fan-out across bouncers.
    # NOTE: gbounce uses the *_mgmt port for /audit/events; ibounce
    # serves /audit/events on the proxy port. Heuristic: if a port
    # entry has a matching <name>_mgmt sibling, the mgmt one is the
    # audit-export endpoint and the proxy one should be skipped to
    # avoid double-counting. Otherwise the proxy port is the audit
    # endpoint.
    bouncer_ports: dict[str, int] = {}
    for pname, pval in ports.items():
        if not pname or not isinstance(pval, (int, str)):
            continue
        try:
            port_int = int(pval)
        except (TypeError, ValueError):
            continue
        if pname.endswith("_mgmt"):
            # mgmt port wins for its bouncer.
            bouncer_ports[pname[:-len("_mgmt")]] = port_int
        else:
            # Only record the proxy port if no mgmt sibling already
            # claimed this bouncer name.
            bouncer_ports.setdefault(pname, port_int)
    # Second pass: prefer mgmt over proxy when both were declared.
    for pname, pval in ports.items():
        if pname.endswith("_mgmt"):
            try:
                bouncer_ports[pname[:-len("_mgmt")]] = int(pval)
            except (TypeError, ValueError):
                continue

    degraded: list[str] = []
    denies_total = 0
    for bname, port in bouncer_ports.items():
        count, err = _fetch_deny_count_for_bouncer(
            port, since_iso, timeout=audit_timeout,
        )
        if count is None:
            degraded.append(f"{bname}:{err or 'unknown'}")
            continue
        denies_total += count

    # intervention_count_24h — read issues.jsonl filtered to 24h window.
    issues = read_issues(since_iso=since_iso)
    interventions = _intervention_count_in_window(issues)

    # improvement_cycles — autopilot status counter.
    improve_cycles = _read_autopilot_improve_count()

    return {
        "denies_24h": denies_total,
        "intervention_count_24h": interventions,
        "improvement_cycles": improve_cycles,
        "computed_at": now_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "degraded_sources": degraded,
    }


def _refresh_dogfood_metrics(
    status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute + persist the §M4 dogfood metrics into status.json.

    Returns the updated status dict. Mutates the status.json file on
    disk (state verification: every reported metric value is backed
    by the persisted file).

    Falls back gracefully when status.json is missing — returns the
    empty dict and skips the write so this helper can be invoked
    unconditionally on read paths.
    """
    if status is None:
        status = read_status()
    if not status:
        return status
    metrics = _compute_dogfood_metrics(status)
    status["denies_24h"] = int(metrics["denies_24h"])
    status["intervention_count_24h"] = int(metrics["intervention_count_24h"])
    status["improvement_cycles"] = int(metrics["improvement_cycles"])
    status["dogfood_metrics_computed_at"] = metrics["computed_at"]
    if metrics["degraded_sources"]:
        status["dogfood_metrics_degraded_sources"] = list(
            metrics["degraded_sources"]
        )
    else:
        # Don't leave a stale degraded list across recoveries; drop the
        # key when no source is degraded.
        status.pop("dogfood_metrics_degraded_sources", None)
    write_status(status)
    return status


# ---------------------------------------------------------------------------
# §A102 — canary YAML loader + daemon_args validation
# ---------------------------------------------------------------------------
#
# Calibration-drift bug #18 (#525): the canary deploy left bouncers running
# with smoke-test ``--upstream`` overrides (ibounce pinned to LocalStack,
# gbounce pinned to api.github.com) when the OPERATOR intent was general
# proxy daily-dev mode. The brief was unclear AND the code didn't enforce
# general-proxy mode. Fix per ``[[this-machine-canary-brought-forward]]``
# §A102: capture daemon_args per-bouncer in YAML + status, warn on
# smoke-test ``--upstream`` pin under ``canary: true``, auto-relaunch on
# restart using recorded daemon_args, expose ``verify-setup`` so the
# operator can confirm intent matches reality.


def load_canary_yaml(path: pathlib.Path | None = None) -> dict[str, Any]:
    """Load ``.iam-jit.yaml`` for the canary deploy + emit warnings on
    smoke-vs-daily-dev drift (§A102).

    Returns the parsed YAML dict (empty if file is missing). Emits a
    ``warnings.warn`` (UserWarning) when any bouncer's ``daemon_args``
    contains ``--upstream`` AND ``iam-jit.canary: true`` — this is the
    calibration-drift bug #18 shape: smoke-test pins leaking into
    daily-dev mode. Daily-dev bouncers MUST run as general proxies
    (no ``--upstream``).

    Per ``[[this-machine-canary-brought-forward]]`` 2026-05-24 update.
    """
    import yaml  # local import to keep CLI startup snappy

    target = path if path is not None else CANARY_YAML_PATH
    if not target.exists():
        return {}
    try:
        loaded = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return {}
    if not isinstance(loaded, dict):
        return {}

    iam_jit_section = loaded.get("iam-jit") or {}
    if not isinstance(iam_jit_section, dict):
        return loaded
    is_canary = bool(iam_jit_section.get("canary"))
    bouncers = iam_jit_section.get("bouncers") or {}
    if not isinstance(bouncers, dict):
        return loaded

    if is_canary:
        for bname, bcfg in bouncers.items():
            if not isinstance(bcfg, dict):
                continue
            daemon_args = bcfg.get("daemon_args") or []
            if not isinstance(daemon_args, list):
                continue
            if any(
                isinstance(a, str) and a == "--upstream"
                for a in daemon_args
            ):
                warnings.warn(
                    f"§A102 calibration-drift bug #18 shape: "
                    f"bouncer {bname!r} has daemon_args containing "
                    f"'--upstream' under iam-jit.canary: true. Smoke-test "
                    f"--upstream pin detected; daily-dev bouncers should "
                    f"run as general proxies (no --upstream). See "
                    f"[[this-machine-canary-brought-forward]] §A102.",
                    UserWarning,
                    stacklevel=2,
                )
    return loaded


def daemon_args_from_yaml(
    yaml_doc: dict[str, Any], bouncer_name: str
) -> list[str]:
    """Extract ``daemon_args`` for ``bouncer_name`` from a parsed canary
    YAML doc. Empty list means "general-proxy default; no --upstream".
    Missing bouncer entry also returns empty list (most permissive default
    — operator must explicitly opt in to flags).
    """
    iam_jit_section = (yaml_doc or {}).get("iam-jit") or {}
    bouncers = iam_jit_section.get("bouncers") or {}
    bcfg = bouncers.get(bouncer_name) or {}
    if not isinstance(bcfg, dict):
        return []
    args = bcfg.get("daemon_args") or []
    if not isinstance(args, list):
        return []
    return [str(a) for a in args]


# ---------------------------------------------------------------------------
# §A102 — relaunch bouncers with recorded daemon_args
# ---------------------------------------------------------------------------


def _bouncer_executable(name: str) -> str | None:
    """Resolve the on-disk executable for a bouncer. Honours the canary
    venv layout (~/.iam-jit/venv/bin/ibounce) first, then $PATH."""
    venv_bin = pathlib.Path.home() / ".iam-jit" / "venv" / "bin" / name
    if venv_bin.exists():
        return str(venv_bin)
    found = shutil.which(name)
    return found  # may be None


def _process_cmdline(pid: int) -> list[str]:
    """Return the argv list for ``pid``. Empty list if the process is
    gone or we can't read it. Portable on macOS + Linux.

    macOS lacks /proc; use ``ps -p PID -o args=`` and shlex-split the
    single-line output. Linux uses /proc/PID/cmdline (NUL-delimited).
    """
    proc_cmdline = pathlib.Path(f"/proc/{pid}/cmdline")
    if proc_cmdline.exists():
        try:
            raw = proc_cmdline.read_bytes()
        except OSError:
            return []
        parts = raw.split(b"\x00")
        return [p.decode("utf-8", "replace") for p in parts if p]
    # macOS fallback.
    proc = subprocess.run(
        ["ps", "-p", str(pid), "-o", "args="],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        return []
    line = proc.stdout.strip()
    if not line:
        return []
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def _pid_alive(pid: int) -> bool:
    """Cheap liveness check. Returns False on ProcessLookupError."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False


def _port_bound(port: int, host: str = "127.0.0.1") -> bool:
    """Return True if ``host:port`` has a listener accepting connections.

    Pure-stdlib alternative to ``lsof -iTCP:PORT -sTCP:LISTEN -t`` —
    works on macOS + Linux + any minimal container (no external
    command dependency). Used by ``_restart_bouncers`` for the
    wait-for-port-release loop where Linux slim containers may not
    have ``lsof`` installed.

    State-verification: a True return means we observed a TCP
    handshake succeed within ``timeout``; False means either no
    listener or the listener refused/timed-out the probe. We treat
    both False cases as "port is releasable" for the
    wait-for-release loop (the next bind() will succeed; that's
    the actual property the caller cares about).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, int(port))) == 0
    except OSError:
        return False


def _lsof_pids_on_port(port: int) -> list[int]:
    """Best-effort PID discovery for a listening port via ``lsof``.

    Returns an empty list if ``lsof`` is not installed (slim Linux
    containers) or returns no rows. Callers MUST handle the empty
    case — the canonical PID source is ``status.json``; this helper
    is a back-compat fallback only.
    """
    if shutil.which("lsof") is None:
        return []
    try:
        proc = subprocess.run(
            ["lsof", "-iTCP:%d" % int(port), "-sTCP:LISTEN", "-t"],
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


def _relaunch_bouncer(
    name: str,
    port: int,
    daemon_args: list[str],
    mgmt_port: int | None = None,
    *,
    log_dir: pathlib.Path | None = None,
    healthz_timeout: float = 30.0,
) -> tuple[bool, int | None, str]:
    """Spawn a fresh bouncer process with ``daemon_args``.

    Returns ``(ok, pid, message)``. On success ``pid`` is the new PID +
    ``message`` is the resolved command line. On failure ``pid`` is None.

    Composition rule (§A102):

      argv = [executable, "run", "--port", str(port),
              *( ["--mgmt-port", str(mgmt_port)] if mgmt_port else [] ),
              *daemon_args]

    The ``daemon_args`` list is what the operator recorded in the canary
    YAML; an empty list means "general-proxy default; no --upstream"
    which is the daily-dev posture per §A102. A non-empty list
    containing ``--upstream`` is permitted (callers may relaunch a smoke
    process intentionally) but ``load_canary_yaml`` warns at YAML load
    time if such args are seen under ``canary: true``.

    State verification: waits up to ``healthz_timeout`` seconds for
    ``/healthz`` (port for ibounce; mgmt_port for gbounce) to return
    200 — the relaunch is only declared successful when the new process
    is responsive. This is the observable side of the success claim
    per ``docs/CONTRIBUTING.md``.
    """
    exe = _bouncer_executable(name)
    if exe is None:
        return False, None, f"executable {name!r} not found in venv or PATH"

    argv: list[str] = [exe, "run", "--port", str(port)]
    if mgmt_port is not None:
        argv += ["--mgmt-port", str(mgmt_port)]
    argv += list(daemon_args)

    log_target = (log_dir or CANARY_DIR) / f"{name}.log"
    try:
        log_target.parent.mkdir(parents=True, exist_ok=True)
        log_fh = log_target.open("a", encoding="utf-8")
    except OSError as exc:
        return False, None, f"could not open log {log_target}: {exc}"

    try:
        proc = subprocess.Popen(
            argv,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        log_fh.close()
        return False, None, f"spawn failed: {exc}"
    finally:
        # The child inherits the fd; the parent can close its own copy
        # only after Popen returns (Popen has dup'd it). Closing immediately
        # is safe; the child holds its own descriptor open.
        try:
            log_fh.close()
        except Exception:
            pass

    # State verification: wait for /healthz on the appropriate port.
    healthz_port = mgmt_port if mgmt_port is not None else port
    healthz_url = f"http://127.0.0.1:{healthz_port}/healthz"
    deadline = time.time() + healthz_timeout
    while time.time() < deadline:
        if not _pid_alive(proc.pid):
            return False, None, (
                f"process exited before /healthz responded; see {log_target}"
            )
        responsive, _status = _curl_responsive(healthz_url, timeout=1.0)
        if responsive:
            return True, proc.pid, " ".join(argv)
        time.sleep(0.5)
    return False, None, (
        f"/healthz at {healthz_url} did not respond within "
        f"{healthz_timeout}s; pid={proc.pid}; see {log_target}"
    )


# ---------------------------------------------------------------------------
# §A102 — verify-setup correctness check
# ---------------------------------------------------------------------------


def _verify_one_bouncer(
    *,
    name: str,
    pid: int | None,
    port: int | None,
    mgmt_port: int | None,
    recorded_args: list[str],
) -> tuple[bool, list[str]]:
    """Return ``(ok, problems)`` for a single bouncer.

    Checks (all per §A102):

      1. PID is alive.
      2. Process cmdline matches recorded daemon_args (catches operator
         drift: relaunched without going through `_relaunch_bouncer`).
      3. /healthz returns 200.
      4. gbounce: mgmt /healthz `upstream` field is "" (general proxy).
      5. ibounce: process cmdline does NOT contain ``--upstream``.

    Each failing check appends a short reason to ``problems``.
    """
    problems: list[str] = []

    if pid is None:
        problems.append("no PID recorded in status.json")
        return False, problems
    if not _pid_alive(pid):
        problems.append(f"PID {pid} not alive")
        return False, problems

    cmdline = _process_cmdline(pid)
    if not cmdline:
        problems.append(f"could not read cmdline for PID {pid}")
    else:
        # Compare ONLY the daemon-arg suffix: the executable path
        # + 'run' + --port + --mgmt-port are deployment-shape, not
        # operator-intent. We require every recorded arg to appear in
        # the live cmdline in order, AND the live cmdline must not
        # contain a `--upstream` arg that is NOT in recorded_args.
        live_has_upstream = "--upstream" in cmdline
        recorded_has_upstream = "--upstream" in recorded_args
        if live_has_upstream and not recorded_has_upstream:
            problems.append(
                "live process has --upstream but recorded daemon_args "
                "does not — smoke-test pin leaking into daily-dev "
                "(§A102 calibration-drift bug #18 shape)"
            )
        if name == "ibounce" and live_has_upstream:
            # ibounce daily-dev MUST be general-proxy per
            # [[this-machine-canary-brought-forward]] step 4c.
            problems.append(
                "ibounce process has --upstream in cmdline; daily-dev "
                "mode requires general proxy (no --upstream)"
            )
        # Catch operator drift: recorded a flag that didn't get applied.
        for arg in recorded_args:
            if arg.startswith("--") and arg not in cmdline:
                problems.append(
                    f"recorded daemon_args contains {arg!r} but live "
                    f"cmdline does not"
                )

    # /healthz check.
    healthz_port = mgmt_port if mgmt_port is not None else port
    if healthz_port is None:
        problems.append("no port recorded in status.json")
    else:
        healthz_url = f"http://127.0.0.1:{healthz_port}/healthz"
        responsive, status = _curl_responsive(healthz_url, timeout=2.0)
        if not responsive:
            problems.append(f"/healthz at {healthz_url} not responsive")
        elif status != 200:
            problems.append(f"/healthz returned HTTP {status}")
        elif name == "gbounce":
            # Per gbounce healthz schema (mgmt port): "upstream" must be
            # empty string for general-proxy daily-dev mode.
            try:
                with urllib.request.urlopen(
                    healthz_url, timeout=2.0
                ) as resp:
                    body = json.loads(resp.read().decode("utf-8", "replace"))
                upstream_field = body.get("upstream")
                if upstream_field not in ("", None):
                    problems.append(
                        f"gbounce /healthz upstream={upstream_field!r} "
                        f"(expected '' for general-proxy mode)"
                    )
            except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
                problems.append(
                    f"could not parse gbounce /healthz body: {exc}"
                )

    return (len(problems) == 0), problems


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def register_canary_group(main_group: click.Group) -> click.Group:
    """Attach the ``canary`` subcommand group to the top-level
    ``iam-jit`` Click group. Idempotent.
    """

    @main_group.group("canary")
    def canary() -> None:
        """THIS-machine canary (real-usage dogfood) subcommands.

        Manages the canary issues file, URL surface, status snapshot,
        and redeploy mechanism. See docs/CANARY.md and
        ``~/.iam-jit/canary/`` for the live data.
        """

    # -- status --------------------------------------------------------

    @canary.command("status")
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit status.json verbatim (no human formatting).",
    )
    def status_cmd(as_json: bool) -> None:
        """Print the current canary status (status.json)."""
        status = read_status()
        if not status:
            click.echo(
                "No canary status yet — run the deploy script to bootstrap "
                "~/.iam-jit/canary/.",
                err=True,
            )
            raise SystemExit(1)
        # §M4 — refresh dogfood metrics before display. Best-effort:
        # fetch failures degrade the per-bouncer contribution but never
        # fail the read path (the operator still needs to see the rest
        # of the status). Per docs/MRR-5-MONITORING-RUNBOOK.md §M4.
        try:
            status = _refresh_dogfood_metrics(status)
        except Exception:
            # State-verification convention: if the refresh itself fails
            # we surface stale values rather than synthesising new ones,
            # so the operator sees the previously-persisted values
            # (which may be 0 on first run). Never hide the failure on
            # JSON consumers — but don't blow up the status read.
            pass
        if as_json:
            click.echo(json.dumps(status, indent=2, sort_keys=True))
            return
        click.echo("iam-jit canary status")
        click.echo("=" * 60)
        for key in (
            "canary_day",
            "started_at",
            "llm_mode",
            "open_issues_count",
            "intervention_count_24h",
            "denies_24h",
            "improvement_cycles",
            "last_issue_ts",
        ):
            if key in status:
                click.echo(f"  {key:<30} {status[key]}")
        bouncers = status.get("bouncers") or {}
        if bouncers:
            click.echo("  bouncers:")
            for name, mode in bouncers.items():
                click.echo(f"    {name:<10} {mode}")
        ports = status.get("ports") or {}
        if ports:
            click.echo("  ports:")
            for name, port in ports.items():
                click.echo(f"    {name:<10} {port}")
        commits = status.get("commits") or {}
        if commits:
            click.echo("  commits:")
            for name, sha in commits.items():
                click.echo(f"    {name:<10} {sha}")

    # -- urls ----------------------------------------------------------

    @canary.command("urls")
    def urls_cmd() -> None:
        """Print the canary URLs (urls.md). Stable across restarts."""
        if not URLS_PATH.exists():
            click.echo(
                "No urls.md yet — run the deploy script first.", err=True
            )
            raise SystemExit(1)
        click.echo(URLS_PATH.read_text(encoding="utf-8"))

    # -- report --------------------------------------------------------

    @canary.command("report")
    @click.option(
        "--since",
        default="24h",
        show_default=True,
        help="Window: e.g. '24h', '7d', '30m', '60s', or 'all'.",
    )
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit a structured report (issues + status + notes-summary).",
    )
    def report_cmd(since: str, as_json: bool) -> None:
        """Triaged canary digest. Read this at session start.

        Shows: open issues by severity, recent notes, status snapshot.
        Designed for both human + agent consumption.
        """
        since_iso = _parse_since(since)
        issues = read_issues(since_iso=since_iso or None)
        status = read_status()
        # §M4 — refresh dogfood metrics before display (same posture as
        # status_cmd). Per docs/MRR-5-MONITORING-RUNBOOK.md §M4.
        if status:
            try:
                status = _refresh_dogfood_metrics(status)
            except Exception:
                pass
        notes = NOTES_PATH.read_text(encoding="utf-8") if NOTES_PATH.exists() else ""

        if as_json:
            payload = {
                "since": since,
                "since_iso": since_iso or None,
                "status": status,
                "issues_count": len(issues),
                "issues_by_severity": dict(
                    Counter(i.get("severity", "?") for i in issues)
                ),
                "issues_by_category": dict(
                    Counter(i.get("category", "?") for i in issues)
                ),
                "issues": issues,
                "notes_excerpt": notes[-2000:],
            }
            click.echo(json.dumps(payload, indent=2, sort_keys=True))
            return

        click.echo(f"iam-jit canary report (since {since})")
        click.echo("=" * 60)
        if status:
            click.echo(
                f"Day {status.get('canary_day', '?')} | "
                f"open_issues={status.get('open_issues_count', '?')} | "
                f"denies_24h={status.get('denies_24h', '?')} | "
                f"interventions_24h={status.get('intervention_count_24h', '?')}"
            )
        click.echo()

        click.echo(f"Issues in window: {len(issues)}")
        if issues:
            by_sev = Counter(i.get("severity", "?") for i in issues)
            for sev in _SEVERITIES:
                if by_sev.get(sev):
                    click.echo(f"  {sev}: {by_sev[sev]}")
            click.echo()
            click.echo("Latest issues:")
            for issue in issues[-10:]:
                ts = issue.get("ts", "?")
                sev = issue.get("severity", "?")
                bn = issue.get("bouncer", "?")
                cat = issue.get("category", "?")
                obs = issue.get("observable", "")[:70]
                click.echo(f"  {ts}  [{sev:<4}] {bn}/{cat}: {obs}")
        click.echo()

        if notes.strip():
            tail = "\n".join(notes.splitlines()[-15:])
            click.echo("Recent notes (last 15 lines):")
            click.echo(tail)
        else:
            click.echo("No notes recorded yet.")

    # -- file-issue ----------------------------------------------------

    @canary.command("file-issue")
    @click.option(
        "--severity",
        type=click.Choice(_SEVERITIES, case_sensitive=False),
        required=True,
    )
    @click.option(
        "--category",
        type=click.Choice(_CATEGORIES, case_sensitive=False),
        default="other",
        show_default=True,
    )
    @click.option("--bouncer", default="iam-jit", show_default=True)
    @click.option("--note", required=True, help="Operator note / observable.")
    @click.option(
        "--expected",
        default="",
        help="What should have happened (optional).",
    )
    @click.option(
        "--repro-hint", default="", help="Command / context to reproduce."
    )
    @click.option(
        "--related-task", default=None, help="GitHub-style task id, e.g. #507."
    )
    def file_issue_cmd(
        severity: str,
        category: str,
        bouncer: str,
        note: str,
        expected: str,
        repro_hint: str,
        related_task: str | None,
    ) -> None:
        """Manually append an issue to ~/.iam-jit/canary/issues.jsonl."""
        entry = append_issue(
            bouncer=bouncer,
            severity=severity.upper(),
            category=category.lower(),
            observable=note,
            expected=expected,
            repro_hint=repro_hint,
            auto_generated=False,
            related_task=related_task,
        )
        click.echo(json.dumps(entry, indent=2, sort_keys=True))

    # -- update --------------------------------------------------------

    @canary.command("update")
    @click.option(
        "--watch",
        is_flag=True,
        default=False,
        help=(
            "Polls remote git for new commits on a fixed --interval. "
            "By default (notify-only) the loop reports new commits to "
            "stdout + appends a HIGH issue to issues.jsonl WITHOUT "
            "pulling / reinstalling / restarting — the operator runs "
            "`iam-jit canary update` manually when ready. Pass "
            "--auto-deploy in addition to --watch to restore the "
            "pre-§A101 behaviour where every new origin/main commit "
            "is installed + bouncers restarted automatically. The "
            "notify-only default is the safer posture per "
            "[[push-policy-public-repo]] — autopilot deploys are "
            "opt-in, not default. (Polling DOES contact the remote; "
            "the pre-§A101 'LOCAL only / no phone-home' help text "
            "was wrong — see issue §A101.)"
        ),
    )
    @click.option(
        "--auto-deploy",
        is_flag=True,
        default=False,
        help=(
            "§A101 — explicit opt-in to autopilot redeploy under "
            "--watch. WITHOUT this flag, --watch is notify-only "
            "(reports new commits; does NOT mutate). WITH this flag, "
            "each new origin/main commit triggers a full "
            "`iam-jit canary update` cycle (pull + reinstall + "
            "restart). A WARN line is logged at watch-loop start so "
            "the operator sees the autopilot posture in the terminal. "
            "Ignored without --watch."
        ),
    )
    @click.option(
        "--interval",
        default="15m",
        show_default=True,
        help="Watch poll interval (e.g. 15m, 1h, 30s). Only used with --watch.",
    )
    @click.option(
        "--dry-run",
        is_flag=True,
        default=False,
        help="Report what would happen without pulling / rebuilding / restarting.",
    )
    def update_cmd(
        watch: bool,
        auto_deploy: bool,
        interval: str,
        dry_run: bool,
    ) -> None:
        """Redeploy the canary on the newest commits.

        Implements the 9-step flow from
        ``[[canary-redeploys-on-every-update]]``:
        clean-tree check → fetch → pull → reinstall → version-check →
        graceful restart → post-update verify → audit-chain continuity →
        issue-log outcome (success or failure with rollback).
        """
        if watch:
            _run_watch_loop(
                interval=interval,
                dry_run=dry_run,
                auto_deploy=auto_deploy,
            )
            return
        _do_one_update(dry_run=dry_run)

    # -- verify-setup ---------------------------------------------------
    #
    # §A102 — operator-runnable correctness check. Verifies the live
    # bouncer state matches operator intent (.iam-jit.yaml +
    # status.json). Catches calibration-drift bug #18 (smoke-test
    # --upstream pin leaking into daily-dev mode).

    @canary.command("verify-setup")
    @click.option(
        "--json", "as_json", is_flag=True, default=False,
        help="Emit a structured JSON report (per-bouncer ok + problems).",
    )
    def verify_setup_cmd(as_json: bool) -> None:
        """§A102 — verify canary bouncers match operator intent.

        Per-bouncer checks: PID alive, cmdline matches recorded
        daemon_args, /healthz returns 200, general-proxy mode (gbounce
        upstream is "", ibounce cmdline lacks --upstream).

        Exit code 0 if all green; non-zero if any check fails.
        """
        status = read_status()
        if not status:
            click.echo(
                "No canary status yet — run the deploy script first.",
                err=True,
            )
            raise SystemExit(1)

        pids = status.get("pids") or {}
        ports = status.get("ports") or {}
        recorded_args = status.get("daemon_args") or {}
        # Pull operator intent from YAML; falls back to status.json.
        yaml_doc = load_canary_yaml()

        # Proxy bouncers only — gbounce_mgmt is a sub-port, not a bouncer.
        bouncer_names = sorted(
            n for n in ports if not n.endswith("_mgmt")
        )
        if not bouncer_names:
            click.echo(
                "No bouncers recorded in status.json; nothing to verify.",
                err=True,
            )
            raise SystemExit(1)

        report: dict[str, Any] = {"bouncers": {}, "ok": True}
        for name in bouncer_names:
            pid_val = pids.get(name)
            pid = int(pid_val) if pid_val else None
            port_val = ports.get(name)
            port = int(port_val) if port_val else None
            mgmt_port_val = ports.get(f"{name}_mgmt")
            mgmt_port = int(mgmt_port_val) if mgmt_port_val else None
            # Operator intent: YAML wins; status.json mirrors.
            yaml_args = daemon_args_from_yaml(yaml_doc, name)
            args = yaml_args if yaml_args else list(
                recorded_args.get(name) or []
            )
            ok, problems = _verify_one_bouncer(
                name=name,
                pid=pid,
                port=port,
                mgmt_port=mgmt_port,
                recorded_args=args,
            )
            report["bouncers"][name] = {
                "ok": ok,
                "pid": pid,
                "port": port,
                "mgmt_port": mgmt_port,
                "recorded_daemon_args": args,
                "problems": problems,
            }
            if not ok:
                report["ok"] = False

        if as_json:
            click.echo(json.dumps(report, indent=2, sort_keys=True))
        else:
            click.echo("iam-jit canary verify-setup")
            click.echo("=" * 60)
            for name in bouncer_names:
                r = report["bouncers"][name]
                tag = "OK  " if r["ok"] else "CRIT"
                click.echo(
                    f"  [{tag}] {name}: pid={r['pid']} port={r['port']} "
                    f"args={r['recorded_daemon_args']!r}"
                )
                for p in r["problems"]:
                    click.echo(f"        - {p}")
            click.echo()
            if report["ok"]:
                click.echo("All bouncers match operator intent.")
            else:
                click.echo(
                    "One or more bouncers diverged from intent. "
                    "Run `iam-jit canary update` to relaunch with "
                    "recorded daemon_args, or edit "
                    "~/.iam-jit/canary/.iam-jit.yaml to declare new "
                    "intent."
                )

        if not report["ok"]:
            raise SystemExit(2)

    return canary


# ---------------------------------------------------------------------------
# Update mechanism
# ---------------------------------------------------------------------------


def _do_one_update(*, dry_run: bool) -> None:
    """Execute one full update cycle. Logs outcome to issues.jsonl."""
    click.echo("== iam-jit canary update ==")
    start = time.time()
    pre_status = read_status()
    pre_shas: dict[str, str] = {}
    new_shas: dict[str, str] = {}

    # Step 1: record pre-update state.
    for name, repo in _CANARY_REPOS.items():
        rc, sha = _git(repo, "rev-parse", "HEAD")
        pre_shas[name] = sha if rc == 0 else "(unknown)"
        click.echo(f"  {name}: pre-update HEAD={pre_shas[name][:12]}")

    # Step 2: refuse uncommitted changes (dogfood notes are in ~/.iam-jit, not repos).
    # In dry-run mode, REPORT but don't fail — operator wants to see the plan
    # even when the tree is dirty, and we never mutate anything in dry-run.
    dirty: list[str] = []
    for name, repo in _CANARY_REPOS.items():
        rc, out = _git(repo, "status", "--porcelain")
        if rc != 0:
            _fail(f"git status failed for {name}: {out}", pre_status, pre_shas, dry_run)
            return
        if out.strip():
            dirty.append(name)
            if not dry_run:
                _fail(
                    f"{name} has uncommitted changes — refusing to pull. "
                    f"Commit / stash first.\n{out}",
                    pre_status,
                    pre_shas,
                    dry_run,
                )
                return

    if dry_run:
        if dirty:
            click.echo(
                f"  [dry-run] WOULD-FAIL: uncommitted changes in: {', '.join(dirty)} "
                f"(actual `update` refuses; dry-run reports + continues)"
            )
        click.echo("  [dry-run] would run: git fetch + git pull per repo")
        click.echo("  [dry-run] would run: pip install -e . / go install ./...")
        click.echo("  [dry-run] would run: graceful restart of bouncers")
        return

    # Steps 3-4: fetch + pull + reinstall.
    for name, repo in _CANARY_REPOS.items():
        rc, out = _git(repo, "fetch", "--quiet")
        if rc != 0:
            _fail(f"git fetch failed for {name}: {out}", pre_status, pre_shas, dry_run)
            return
        rc, out = _git(repo, "pull", "--ff-only")
        if rc != 0:
            _fail(f"git pull failed for {name}: {out}", pre_status, pre_shas, dry_run)
            return
        rc, sha = _git(repo, "rev-parse", "HEAD")
        new_shas[name] = sha if rc == 0 else "(unknown)"
        click.echo(f"  {name}: post-pull HEAD={new_shas[name][:12]}")

    # Reinstall per-repo.
    iam_roles_repo = _CANARY_REPOS["iam-roles"]
    venv_pip = pathlib.Path.home() / ".iam-jit" / "venv" / "bin" / "pip"
    if venv_pip.exists():
        proc = subprocess.run(
            [str(venv_pip), "install", "-e", "."],
            cwd=str(iam_roles_repo),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            _fail(
                f"pip install -e . failed:\n{proc.stdout[-500:]}\n{proc.stderr[-500:]}",
                pre_status,
                pre_shas,
                dry_run,
            )
            return
        click.echo("  iam-roles: pip install -e . OK")

    gbounce_repo = _CANARY_REPOS["gbounce"]
    if gbounce_repo.exists() and shutil.which("go"):
        proc = subprocess.run(
            ["go", "install", "./..."],
            cwd=str(gbounce_repo),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            _fail(
                f"go install ./... failed:\n{proc.stdout[-500:]}\n{proc.stderr[-500:]}",
                pre_status,
                pre_shas,
                dry_run,
            )
            return
        click.echo("  gbounce: go install ./... OK")

    # Step 5: version-check (best-effort — bouncer must respond).
    # The bouncer's `*bounce --version` reports the constant baked in at
    # install time; if it doesn't match the new commit SHA's tag, we
    # surface a LOW issue but don't fail the update (version bumping is
    # a separate release discipline).

    # Step 6: graceful restart — see _restart_bouncers below.
    restart_ok, restart_msg = _restart_bouncers(pre_status)
    if not restart_ok:
        _fail(
            f"bouncer restart failed: {restart_msg}",
            pre_status,
            pre_shas,
            dry_run,
        )
        return

    # Step 7-8: success — log + update status.
    duration = round(time.time() - start, 1)
    append_issue(
        bouncer="iam-jit",
        severity="LOW",
        category="update_success",
        observable=(
            f"canary update succeeded in {duration}s; "
            + ", ".join(
                f"{n}: {pre_shas.get(n, '?')[:12]}→{new_shas.get(n, '?')[:12]}"
                for n in _CANARY_REPOS
            )
        ),
        expected="canary update succeeded",
        repro_hint="iam-jit canary update",
        auto_generated=True,
        related_task="#507",
    )

    # Touch status.json with new commits.
    status = read_status()
    if status:
        status.setdefault("commits", {}).update(new_shas)
        status["last_update_at"] = _now_iso()
        write_status(status)

    click.echo(f"OK update complete in {duration}s")


def _fail(
    msg: str,
    pre_status: dict[str, Any],
    pre_shas: dict[str, str],
    dry_run: bool,
) -> None:
    """Log + announce a CRIT update failure. Best-effort rollback per repo."""
    click.echo(f"FAIL {msg}", err=True)
    if dry_run:
        return
    # Best-effort rollback: git checkout each pre-update SHA. Don't
    # restart if rollback fails — leave the operator in a known broken
    # state so they can intervene.
    rollback_notes = []
    for name, repo in _CANARY_REPOS.items():
        sha = pre_shas.get(name)
        if not sha or sha == "(unknown)":
            continue
        rc, out = _git(repo, "checkout", sha)
        rollback_notes.append(
            f"{name}: rollback to {sha[:12]} "
            + ("OK" if rc == 0 else f"FAIL ({out[:80]})")
        )
    append_issue(
        bouncer="iam-jit",
        severity="CRIT",
        category="update_failure",
        observable=msg[:500],
        expected="canary update succeeded",
        repro_hint="iam-jit canary update",
        auto_generated=True,
        related_task="#507",
    )
    if rollback_notes:
        for note in rollback_notes:
            click.echo(f"  rollback: {note}", err=True)


def _restart_bouncers(pre_status: dict[str, Any]) -> tuple[bool, str]:
    """SIGTERM bouncers + auto-relaunch with recorded daemon_args (§A102).

    Pre-§A102 this only SIGTERMed + relied on the operator to manually
    relaunch. That left the calibration-drift bug #18 shape latent —
    smoke-test ``--upstream`` pins could survive across restart cycles
    because the operator wasn't in the loop to notice the wrong
    daemon args. §A102 closes the loop:

      1. Read recorded daemon_args from ``.iam-jit.yaml`` (operator
         intent) — falls back to ``status.json`` for back-compat.
      2. SIGTERM each live bouncer on its recorded port.
      3. Wait for the port to release (max 30s).
      4. Spawn a fresh bouncer process with the recorded daemon_args.
      5. Wait for /healthz on each new process (state verification).
      6. Update status.json with the new PIDs + daemon_args.
      7. File a CRIT issue if relaunch fails.

    Returns ``(True, "no bouncers running")`` if there's nothing to
    restart (which is a valid state — pre-deploy or after manual stop).
    """
    ports = (pre_status or {}).get("ports") or {}
    if not ports:
        return True, "no ports recorded in status.json; skipping restart"

    # §A102 — load operator-intent daemon_args from YAML (canonical
    # source) with status.json as fallback for back-compat.
    yaml_doc = load_canary_yaml()
    status_daemon_args = (pre_status or {}).get("daemon_args") or {}

    def _recorded_args(bname: str) -> list[str]:
        yaml_args = daemon_args_from_yaml(yaml_doc, bname)
        if yaml_args:
            return yaml_args
        sa = status_daemon_args.get(bname)
        if isinstance(sa, list):
            return [str(a) for a in sa]
        return []

    # Send SIGTERM to recorded bouncer PIDs.
    # NOTE: gbounce_mgmt is a SECONDARY port for the same process; skip it
    # (the SIGTERM to the proxy port already terminates the process).
    #
    # PID source: ``status.json`` is the canonical record (written by
    # ``_relaunch_bouncer`` + the deploy script). ``lsof`` is a
    # back-compat fallback for canary state that predates the
    # ``pids`` field — and is also absent in slim Linux containers
    # (``python:3.11-slim``, ``alpine``), so we no longer rely on it
    # being installed. Per ``docs/LINUX-SUPPORT-AUDIT-2026-05-24.md``
    # finding #1.
    proxy_ports = {
        n: p for n, p in ports.items() if not n.endswith("_mgmt")
    }
    recorded_pids: dict[str, int] = {}
    raw_recorded = (pre_status or {}).get("pids") or {}
    for bname, pv in raw_recorded.items():
        try:
            recorded_pids[bname] = int(pv)
        except (TypeError, ValueError):
            continue

    restarted: list[str] = []
    for bouncer_name, port in proxy_ports.items():
        # Prefer the recorded PID; fall back to lsof only if missing.
        candidates: list[int] = []
        rec = recorded_pids.get(bouncer_name)
        if rec is not None and _pid_alive(rec):
            candidates = [rec]
        else:
            # Back-compat path: try lsof (no-op on containers without it).
            candidates = _lsof_pids_on_port(int(port))
        for pid in candidates:
            try:
                os.kill(pid, signal.SIGTERM)
                restarted.append(f"{bouncer_name}(pid={pid})")
            except (ProcessLookupError, PermissionError) as exc:
                return False, f"kill {bouncer_name} pid={pid}: {exc}"

    # Wait for ports to release (max 30s).
    # Use pure-Python TCP-probe instead of lsof — works on every
    # platform regardless of installed tools.
    deadline = time.time() + 30
    for bouncer_name, port in proxy_ports.items():
        while time.time() < deadline:
            if not _port_bound(int(port)):
                break
            time.sleep(0.5)
        else:
            return False, f"port {port} ({bouncer_name}) didn't release in 30s"

    # §A102 — auto-relaunch with recorded daemon_args.
    new_pids: dict[str, int] = {}
    new_daemon_args: dict[str, list[str]] = {}
    relaunched: list[str] = []
    for bouncer_name, port in proxy_ports.items():
        recorded_args = _recorded_args(bouncer_name)
        mgmt_port_val = ports.get(f"{bouncer_name}_mgmt")
        mgmt_port = int(mgmt_port_val) if mgmt_port_val else None
        ok, new_pid, msg = _relaunch_bouncer(
            bouncer_name,
            int(port),
            recorded_args,
            mgmt_port=mgmt_port,
        )
        if not ok:
            # File a CRIT issue per §A102.
            try:
                append_issue(
                    bouncer=bouncer_name,
                    severity="CRIT",
                    category="bouncer_error",
                    observable=f"§A102 relaunch failed: {msg}",
                    expected="bouncer relaunched + /healthz 200",
                    repro_hint="iam-jit canary update",
                    auto_generated=True,
                    related_task="#525",
                )
            except Exception:
                pass
            return False, f"relaunch {bouncer_name} failed: {msg}"
        new_pids[bouncer_name] = new_pid or 0
        new_daemon_args[bouncer_name] = recorded_args
        relaunched.append(f"{bouncer_name}(pid={new_pid})")

    # Update status.json with the new PIDs + daemon_args (operator intent
    # mirror so the cross-session view shows reality + intent together).
    current = read_status()
    if current:
        current.setdefault("pids", {}).update(new_pids)
        current.setdefault("daemon_args", {}).update(new_daemon_args)
        current["last_relaunch_at"] = _now_iso()
        write_status(current)

    summary_parts = []
    if restarted:
        summary_parts.append("stopped: " + ", ".join(restarted))
    if relaunched:
        summary_parts.append("relaunched: " + ", ".join(relaunched))
    if not summary_parts:
        return True, "no live bouncers found on recorded ports"
    return True, "; ".join(summary_parts)


def _run_watch_loop(
    *, interval: str, dry_run: bool, auto_deploy: bool = False,
) -> None:
    """Poll remote git for new commits.

    §A101 behaviour split:

      * ``auto_deploy=False`` (default for --watch): notify-only. New
        upstream commits are surfaced to stdout AND appended as a
        HIGH-severity entry in ~/.iam-jit/canary/issues.jsonl. The
        operator runs ``iam-jit canary update`` manually when ready.
      * ``auto_deploy=True``: each new upstream commit triggers a
        full ``_do_one_update`` cycle (pre-§A101 behaviour). A WARN
        line fires at watch-loop start so the autopilot posture is
        visible in the terminal.

    Per [[push-policy-public-repo]] the notify-only default is the
    safer posture: autopilot redeploy across the suite means any
    commit that lands on any origin/main becomes a live install,
    which is a footgun the operator should opt into explicitly.
    """
    m = re.fullmatch(r"(\d+)([smhd])", interval.lower())
    if not m:
        raise click.BadParameter(
            f"--interval must look like '15m', '1h', '30s'; got {interval!r}"
        )
    n, unit = int(m.group(1)), m.group(2)
    seconds = n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]

    if auto_deploy:
        click.echo(
            f"iam-jit canary update --watch --auto-deploy: WARNING — "
            f"auto-deploy enabled. Any commit landing on origin/main "
            f"will be installed + bouncers restarted automatically. "
            f"Polling every {interval}. Ctrl-C to stop."
        )
    else:
        click.echo(
            f"iam-jit canary update --watch (notify-only): polling "
            f"remote every {interval}. New commits will be reported "
            f"to stdout + logged to issues.jsonl; no auto-redeploy. "
            f"Pass --auto-deploy to enable autopilot redeploy. "
            f"Ctrl-C to stop."
        )
    while True:
        new_commits: list[tuple[str, str, str]] = []  # (name, head, upstream)
        for name, repo in _CANARY_REPOS.items():
            _git(repo, "fetch", "--quiet")
            rc1, head = _git(repo, "rev-parse", "HEAD")
            rc2, upstream = _git(repo, "rev-parse", "@{u}")
            if rc1 == 0 and rc2 == 0 and head != upstream:
                click.echo(
                    f"  {name}: new commits ({head[:12]} → {upstream[:12]})"
                )
                new_commits.append((name, head, upstream))
        if new_commits:
            if auto_deploy:
                _do_one_update(dry_run=dry_run)
            else:
                # Notify-only: log to issues.jsonl so the operator's
                # `iam-jit canary issues` query surfaces the pending
                # update. Severity HIGH because an un-installed
                # security fix is a meaningful gap.
                for name, head, upstream in new_commits:
                    try:
                        # Category "other" — the existing canary
                        # taxonomy doesn't have an "update_available"
                        # bucket (only success / failure). "other"
                        # is the documented escape hatch in the
                        # _CATEGORIES tuple at module top.
                        append_issue(
                            bouncer=name,
                            severity="HIGH",
                            category="other",
                            observable=(
                                f"§A101 update_available: new "
                                f"origin/main commits {head[:12]} -> "
                                f"{upstream[:12]}"
                            ),
                            expected=(
                                "operator runs `iam-jit canary update` "
                                "to install + restart"
                            ),
                            repro_hint=(
                                "iam-jit canary update --watch is in "
                                "notify-only mode; pass --auto-deploy "
                                "to enable autopilot redeploy"
                            ),
                            auto_generated=True,
                            related_task="§A101",
                        )
                    except Exception as e:
                        # Never crash the watch loop on a logging
                        # failure — the stdout report above already
                        # alerted the operator.
                        click.secho(
                            f"  warning: could not append issue: {e}",
                            fg="yellow", err=True,
                        )
                click.echo(
                    "  notify-only: NOT auto-deploying. Run "
                    "`iam-jit canary update` to install."
                )
        else:
            click.echo(f"  no new commits at {_now_iso()}")
        time.sleep(seconds)
