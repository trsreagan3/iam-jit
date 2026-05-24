"""`iam_jit_setup_from_config` core: plan + (optionally) execute a
declaration.

Inputs:
  * A validated declaration (dict) — produced by ``loader.load_declaration``.
  * A posture snapshot (dict) — produced by ``iam_jit.posture.capture_posture``.
  * An ``execute`` flag — when False (the default for MCP/dry-run callers)
    we plan but never start anything.

Outputs:
  ``SetupResult`` — a dataclass mirroring the spec'd return shape:

      {
        bouncers_started: [str],
        bouncers_already_running: [str],
        bouncers_skipped: [{name, reason}],     # honest about heuristics
        env_vars_to_set: {AWS_ENDPOINT_URL, KUBECONFIG, PGHOST, ...},
        profiles_installed: [{bouncer, profile_name, source}],
        posture_after: dict,                    # iam_jit_posture snapshot
        audit_event_ids: [str],
        warnings: [str],
      }

Per [[creates-never-mutates]] this never overwrites operator profiles
or configs without consent: when a bouncer is already running but the
declaration asks for a different mode/profile, we emit a warning + skip
(NOT silently restart). When the declaration's `profile: auto`
resolves to an already-installed profile, that profile is reused; we
do NOT generate a new one in Phase A (Phase B's `iam_jit_improve_profile`
is the profile-generation surface).

Per [[ibounce-honest-positioning]] every `when_X_present` heuristic
resolves with its inputs visible: the result block records what the
detector saw (e.g., `"kbouncer: enabled=when_kubeconfig_present →
KUBECONFIG=/Users/x/.kube/config → enabled=true"`).
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import closing
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# #538 — transactional setup support (UC-20 / RB-B6)
# ---------------------------------------------------------------------------
#
# Per docs/MRR-4-ROLLBACK-RUNBOOK.md RB-B6: pre-#538 a partial-install in
# `iam_jit_setup_from_config` left an orphan state — some bouncers
# started, others mid-install, the operator had to manually inspect
# `status.json` vs `.iam-jit.yaml` and reconcile.
#
# #538 adds an OPT-OUT-able transactional path:
#
#   * `_capture_setup_state()` — snapshot the operator-owned state
#     directory (config files + a synthetic process inventory derived
#     from posture) BEFORE apply_declaration mutates anything.
#   * `_restore_setup_state(snapshot, new_pids)` — SIGTERM newly-started
#     bouncers + restore the config snapshot files; emits a verification
#     re-snapshot and reports any drift that survived rollback.
#   * `apply_declaration(..., rollback_on_failure=True)` — the default
#     for #538-aware callers. When any bouncer step is recorded as
#     "skipped" mid-apply (the partial-install surface), rollback runs
#     automatically + the result's `rollback_outcome` field describes
#     what happened.
#
# Per [[ibounce-honest-positioning]] the rollback always reports what
# it observed; it never silently "succeeds" past a discrepancy.

# Directories whose CONFIG state we snapshot. We deliberately skip
# `~/.iam-jit/canary/` (operator-curated; restoring would clobber the
# `.iam-jit.yaml` the operator is iterating on) and any *.db file
# (audit + chain integrity per [[creates-never-mutates]] — DBs must
# never be restored by setup rollback; if they need to be reverted
# the operator runs `ibounce restore` explicitly).
_SETUP_SNAPSHOT_CONFIG_FILES = (
    pathlib.Path("~/.iam-jit/bouncer/profiles.yaml"),
    pathlib.Path("~/.iam-jit/bouncer/profiles_state.yaml"),
)


# ---------------------------------------------------------------------------
# /healthz probe (#433) — distinguish "iam-jit bouncer is listening" from
# "some other process took the port". Returns one of:
#   ("bouncer", "ibounce" | "kbounce" | ...)  — port belongs to a bouncer
#   ("non_bouncer", "<reason>")                — port is in use but the
#                                                  response did not identify
#                                                  as a bouncer; the reason
#                                                  string is operator-
#                                                  facing (e.g. "connection
#                                                  closed without an HTTP
#                                                  response" or "GET /healthz
#                                                  returned 404").
#   ("free", "")                              — nothing listening on the port
# ---------------------------------------------------------------------------


def _probe_bouncer_healthz(
    port: int,
    *,
    expected_kind: str,
    host: str = "127.0.0.1",
    timeout: float = 0.5,
) -> tuple[str, str]:
    """Probe ``http://host:port/healthz`` and report whether the
    listener is an iam-jit bouncer of the expected kind.

    Resolution:
      * TCP connect refused → ("free", "")
      * HTTP 200 + JSON body with ``bouncer_kind`` matching expected →
        ("bouncer", bouncer_kind)
      * HTTP 200 + JSON body with a DIFFERENT bouncer_kind → ("bouncer",
        that_kind) — the caller decides what to do (in practice "wrong
        bouncer on this port" is a misconfig the operator must resolve).
      * Anything else (timeout, non-JSON body, no bouncer_kind, HTTP
        error code, ...) → ("non_bouncer", <reason>).

    Never raises — every failure mode maps to a tuple. Cheap loopback
    call (< 500ms in the worst case).
    """
    # Fast-path: TCP-connect check. If the port is closed there's no
    # point doing the HTTP request (urlopen would be slower).
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except OSError:
            return ("free", "")
    url = f"http://{host}:{port}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — loopback only
            status = resp.status
            body = resp.read(8192)  # cap to avoid pathological responses
    except urllib.error.HTTPError as e:
        return (
            "non_bouncer",
            f"GET {url} returned HTTP {e.code}; not an iam-jit bouncer",
        )
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return (
            "non_bouncer",
            f"GET {url} failed: {e}; port is in use but not by a "
            "bouncer (or bouncer is not responding to /healthz)",
        )
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return (
            "non_bouncer",
            f"GET {url} returned non-JSON body; not an iam-jit bouncer",
        )
    kind = payload.get("bouncer_kind") if isinstance(payload, dict) else None
    if not isinstance(kind, str) or not kind.strip():
        return (
            "non_bouncer",
            f"GET {url} returned a response without `bouncer_kind`; "
            "not an iam-jit bouncer",
        )
    _ = status  # accepted; status non-200 with parseable bouncer_kind
    # body still means a bouncer (e.g. degraded → 503).
    return ("bouncer", kind.strip().lower())


# ---------------------------------------------------------------------------
# Per-bouncer defaults — mirror posture.bouncers + bouncer_cli `run`
# ---------------------------------------------------------------------------

# Each entry describes how to (a) detect the bouncer, (b) start it,
# (c) emit the env-var advisory the agent should propagate to its
# subprocesses.
BOUNCER_DEFAULTS: dict[str, dict[str, Any]] = {
    "ibounce": {
        "default_port": 8767,
        "binary_candidates": ("ibounce",),
        "env_advice_template": "AWS_ENDPOINT_URL=http://127.0.0.1:{port}",
        "env_var_name": "AWS_ENDPOINT_URL",
        "detection_field": "ibounce",
    },
    "kbouncer": {
        "default_port": 8766,
        "binary_candidates": ("kbouncer", "kbounce"),
        "env_advice_template": "KUBECONFIG=~/.kube/kbouncer-{port}.yaml",
        "env_var_name": "KUBECONFIG",
        "detection_field": "kbounce",  # posture field name; cross-product rename
    },
    "dbounce": {
        "default_port": 5433,
        "default_mgmt_port": 8768,
        "binary_candidates": ("dbounce",),
        "env_advice_template": "PGHOST=127.0.0.1 PGPORT={port}",
        "env_var_name": "PGHOST",
        "detection_field": "dbounce",
    },
    "gbounce": {
        "default_port": 8080,
        "default_mgmt_port": 8769,
        "binary_candidates": ("gbounce",),
        "env_advice_template": "HTTPS_PROXY=http://127.0.0.1:{port}",
        "env_var_name": "HTTPS_PROXY",
        "detection_field": "gbounce",
    },
}

# Aliases — the declaration field "kbouncer" maps to the posture-snapshot
# field "kbounce" (legacy naming asymmetry that we don't have license
# to fix here per the v1-scope-bar).
DECLARATION_TO_POSTURE_KEY = {
    "ibounce": "ibounce",
    "kbouncer": "kbounce",
    "dbounce": "dbounce",
    "gbounce": "gbounce",
}


# #434 — mode-naming alias between declaration vocabulary + runtime
# (ibounce ProxyMode) vocabulary. The declaration calls the
# "observe + audit + always-forward" mode `discovery` per
# [[discovery-first-default]]; the runtime proxy calls it `cooperative`
# (the historical name; semantics are pass-through-forward). Per the
# UAT finding this caused declaration→posture asymmetry where
# `mode: discovery` in the declaration surfaced as `mode: cooperative`
# in posture + apply-config warnings, breaking operator confidence
# that the declaration was actually applied.
#
# Per the brief we ship option (c): document the alias explicitly +
# always surface the DECLARED name in operator-facing messages, with
# the runtime name in parentheses where it matters for debugging.
# This avoids touching the ProxyMode enum (which would ripple through
# /healthz, audit events, the CLI flag, and dozens of tests).
#
# `declared_runtime_alias(mode)` returns the runtime equivalent;
# `runtime_declared_alias(mode)` returns the declared equivalent.
# Both round-trip on inputs they don't recognize (pass-through).
DECLARATION_MODE_TO_RUNTIME = {
    "discovery": "cooperative",   # discovery in declaration = cooperative runtime
    "cooperative": "cooperative", # operator who literally writes "cooperative" → no change
    "strict": "transparent",      # strict in declaration = transparent runtime
}

RUNTIME_MODE_TO_DECLARED = {
    "cooperative": "discovery",   # runtime cooperative = discovery in declaration vocab
    "transparent": "strict",
    "plan-capture": "plan-capture",
    "off": "off",
}


def declared_runtime_alias(declared_mode: str | None) -> str:
    """Translate a declaration-mode string to the runtime ProxyMode
    string. Pass-through for unknowns."""
    if not isinstance(declared_mode, str):
        return "cooperative"
    return DECLARATION_MODE_TO_RUNTIME.get(
        declared_mode.strip().lower(), declared_mode.strip().lower(),
    )


def runtime_declared_alias(runtime_mode: str | None) -> str:
    """Translate a runtime ProxyMode string to the declaration vocab.
    Pass-through for unknowns (e.g. `plan-capture`)."""
    if not isinstance(runtime_mode, str):
        return "unknown"
    return RUNTIME_MODE_TO_DECLARED.get(
        runtime_mode.strip().lower(), runtime_mode.strip().lower(),
    )


def _modes_match(declared: str | None, runtime: str | None) -> bool:
    """True iff the declared mode resolves to the running runtime mode
    (e.g. declared=discovery + running=cooperative → True; declared=
    strict + running=transparent → True). Unknown on either side
    yields True (we can't claim mismatch on missing info)."""
    if not declared or not runtime:
        return True
    if str(runtime).lower() == "unknown":
        return True
    expected_runtime = declared_runtime_alias(declared)
    return expected_runtime.lower() == str(runtime).lower()


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class SetupResult:
    """Structured return of ``apply_declaration`` / ``plan_declaration``."""

    schema_version: str = "1.0"
    status: str = "ok"  # ok | disabled | error
    dry_run: bool = True
    declaration_source: str = ""
    bouncers_started: list[str] = field(default_factory=list)
    bouncers_already_running: list[str] = field(default_factory=list)
    bouncers_skipped: list[dict[str, Any]] = field(default_factory=list)
    bouncers_planned: list[dict[str, Any]] = field(default_factory=list)
    env_vars_to_set: dict[str, str] = field(default_factory=dict)
    profiles_installed: list[dict[str, Any]] = field(default_factory=list)
    posture_before: dict[str, Any] = field(default_factory=dict)
    posture_after: dict[str, Any] = field(default_factory=dict)
    audit_event_ids: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    resolved_conditionals: list[dict[str, Any]] = field(default_factory=list)
    # #434 — declared-mode → runtime-mode mapping for every enabled
    # bouncer in the declaration. Surfaces the alias so apply-config /
    # MCP structuredContent show the operator both vocabularies.
    # #435 — `mode_source` per bouncer attributes the provenance of
    # the effective mode (declaration / cli_flag / env_var / default).
    bouncer_mode_resolutions: list[dict[str, Any]] = field(
        default_factory=list
    )
    # #538 — transactional rollback bookkeeping. None when rollback was
    # not invoked (happy path OR rollback_on_failure=False). When set,
    # carries the rollback verdict + per-step observations so the
    # operator-facing result mirrors the on-disk side effects per
    # docs/CONTRIBUTING.md state-verification convention.
    rollback_outcome: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _capture_setup_state(
    posture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Snapshot the operator-owned state surface that `apply_declaration`
    can mutate (#538).

    Returns a dict shaped like::

        {
          "captured_at": <ts>,
          "config_files": {
            "<expanded_path>": {"exists": bool, "content": bytes | None,
                                "mode": int | None},
            ...
          },
          "posture_pids": {<bouncer>: <pid_or_None>, ...},
          "posture_ports": {<bouncer>: <port_or_None>, ...},
        }

    The snapshot is a pure-Python dict (no on-disk artefact) — the
    caller passes it to ``_restore_setup_state`` for revert.
    """
    config_files: dict[str, dict[str, Any]] = {}
    for raw in _SETUP_SNAPSHOT_CONFIG_FILES:
        path = raw.expanduser()
        entry: dict[str, Any] = {"exists": path.exists(), "content": None,
                                  "mode": None}
        if path.exists() and path.is_file():
            try:
                entry["content"] = path.read_bytes()
                entry["mode"] = path.stat().st_mode & 0o7777
            except OSError as exc:
                logger.warning("snapshot read failed for %s: %s", path, exc)
        config_files[str(path)] = entry

    posture_snap = posture if posture is not None else _capture_posture_safe()
    pids: dict[str, int | None] = {}
    ports: dict[str, int | None] = {}
    for name, block in (posture_snap.get("bouncers") or {}).items():
        if not isinstance(block, dict):
            continue
        pid_val = block.get("pid")
        try:
            pids[name] = int(pid_val) if pid_val is not None else None
        except (TypeError, ValueError):
            pids[name] = None
        port_val = block.get("port")
        try:
            ports[name] = int(port_val) if port_val is not None else None
        except (TypeError, ValueError):
            ports[name] = None
    return {
        "captured_at": time.time(),
        "config_files": config_files,
        "posture_pids": pids,
        "posture_ports": ports,
    }


def _restore_setup_state(
    snapshot: dict[str, Any],
    *,
    new_pids: dict[str, int],
) -> dict[str, Any]:
    """Revert mutations applied since ``snapshot`` was captured (#538).

    Steps:
      1. SIGTERM every PID in ``new_pids`` that was NOT present in the
         snapshot's posture_pids (new processes only — pre-existing
         bouncers are left alone per [[creates-never-mutates]]).
      2. Restore config files: when the snapshot recorded
         ``exists: True`` we rewrite content + mode; when the snapshot
         recorded ``exists: False`` we delete the file if present.
      3. Re-capture state + diff against snapshot.

    Returns a dict shaped like::

        {
          "status": "ok" | "incomplete",
          "killed_pids": [int, ...],
          "files_restored": [str, ...],
          "files_deleted": [str, ...],
          "verification_drift": [str, ...],  # diffs vs snapshot
        }

    The caller treats ``status == "incomplete"`` as a CRIT-worthy event
    (the operator's state is not provably back to pre-install shape).
    """
    outcome: dict[str, Any] = {
        "status": "ok",
        "killed_pids": [],
        "files_restored": [],
        "files_deleted": [],
        "verification_drift": [],
        "kill_failures": [],
        "restore_failures": [],
    }

    snap_pids = set(
        pid for pid in (snapshot.get("posture_pids") or {}).values()
        if pid is not None
    )

    # Step 1: SIGTERM newly-started PIDs only.
    for name, pid in (new_pids or {}).items():
        if not pid or pid in snap_pids:
            continue
        try:
            os.kill(int(pid), signal.SIGTERM)
            outcome["killed_pids"].append(int(pid))
        except ProcessLookupError:
            # Already dead — count as success (rollback goal met).
            outcome["killed_pids"].append(int(pid))
        except (PermissionError, OSError) as exc:
            outcome["kill_failures"].append(f"{name}(pid={pid}): {exc}")
            outcome["status"] = "incomplete"

    # Step 2: Restore config files.
    for path_str, entry in (snapshot.get("config_files") or {}).items():
        path = pathlib.Path(path_str)
        try:
            if entry.get("exists"):
                # Restore prior content + mode.
                path.parent.mkdir(parents=True, exist_ok=True)
                content = entry.get("content")
                if content is not None:
                    path.write_bytes(content)
                    if entry.get("mode") is not None:
                        try:
                            path.chmod(int(entry["mode"]))
                        except OSError:
                            pass
                    outcome["files_restored"].append(path_str)
            else:
                # Snapshot says file didn't exist; ensure it doesn't now.
                if path.exists():
                    path.unlink()
                    outcome["files_deleted"].append(path_str)
        except OSError as exc:
            outcome["restore_failures"].append(f"{path_str}: {exc}")
            outcome["status"] = "incomplete"

    # Step 3: verification — re-snapshot + diff config files. We do NOT
    # re-capture posture (pid liveness is racy + the SIGTERM may need
    # >1s to take effect; the kill_failures list is the authoritative
    # signal for that surface).
    for path_str, entry in (snapshot.get("config_files") or {}).items():
        path = pathlib.Path(path_str)
        if entry.get("exists"):
            if not path.exists():
                outcome["verification_drift"].append(
                    f"{path_str}: expected restored but file is missing"
                )
                outcome["status"] = "incomplete"
                continue
            try:
                current = path.read_bytes()
            except OSError as exc:
                outcome["verification_drift"].append(
                    f"{path_str}: read failed after restore ({exc})"
                )
                outcome["status"] = "incomplete"
                continue
            if current != (entry.get("content") or b""):
                outcome["verification_drift"].append(
                    f"{path_str}: content mismatch after restore"
                )
                outcome["status"] = "incomplete"
        else:
            if path.exists():
                outcome["verification_drift"].append(
                    f"{path_str}: snapshot said absent; still present after delete"
                )
                outcome["status"] = "incomplete"
    return outcome


# ---------------------------------------------------------------------------
# Heuristic resolution for `enabled: when_X_present`
# ---------------------------------------------------------------------------


def _kubeconfig_visible(env: dict[str, str]) -> tuple[bool, str]:
    """True iff KUBECONFIG points at an existing file OR
    ``~/.kube/config`` exists. Returns (resolved, evidence)."""
    val = (env.get("KUBECONFIG") or "").strip()
    if val:
        # KUBECONFIG can be a colon-separated list; the first existing
        # entry counts.
        for chunk in val.split(":"):
            if chunk and pathlib.Path(chunk).expanduser().is_file():
                return True, f"KUBECONFIG={val} (file exists)"
        return False, f"KUBECONFIG={val} (no file in the list exists)"
    default = pathlib.Path("~/.kube/config").expanduser()
    if default.is_file():
        return True, f"~/.kube/config exists"
    return False, "no KUBECONFIG set + ~/.kube/config absent"


def _db_env_visible(env: dict[str, str]) -> tuple[bool, str]:
    """True iff any of PGHOST/PGDATABASE/DATABASE_URL/MYSQL_HOST is set."""
    for var in ("PGHOST", "PGDATABASE", "DATABASE_URL", "MYSQL_HOST"):
        val = (env.get(var) or "").strip()
        if val:
            return True, f"{var}={val}"
    return False, "no PG/MySQL/DATABASE env var set"


def _proxy_env_visible(env: dict[str, str]) -> tuple[bool, str]:
    """True iff HTTPS_PROXY or HTTP_PROXY is set."""
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        val = (env.get(var) or "").strip()
        if val:
            return True, f"{var}={val}"
    return False, "no HTTP(S)_PROXY env var set"


def _aws_env_visible(env: dict[str, str]) -> tuple[bool, str]:
    """True iff AWS credentials are exposed via env or ~/.aws/credentials."""
    for var in (
        "AWS_ACCESS_KEY_ID",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_SESSION_TOKEN",
    ):
        val = (env.get(var) or "").strip()
        if val:
            return True, f"{var} present"
    creds = pathlib.Path("~/.aws/credentials").expanduser()
    if creds.is_file():
        return True, "~/.aws/credentials exists"
    config = pathlib.Path("~/.aws/config").expanduser()
    if config.is_file():
        return True, "~/.aws/config exists"
    return False, "no AWS creds / ~/.aws/credentials"


_CONDITIONAL_RESOLVERS = {
    "when_kubeconfig_present": _kubeconfig_visible,
    "when_db_env_present": _db_env_visible,
    "when_proxy_env_present": _proxy_env_visible,
    "when_aws_env_present": _aws_env_visible,
}


def _resolve_enabled(
    raw: bool | str,
    *,
    env: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Resolve a bouncer block's `enabled` value to a boolean +
    human-readable evidence string.
    """
    env = env if env is not None else dict(os.environ)
    if isinstance(raw, bool):
        return raw, f"declared {raw} (explicit)"
    if not isinstance(raw, str):  # pragma: no cover — schema rejects
        return False, f"unexpected type {type(raw).__name__}"
    resolver = _CONDITIONAL_RESOLVERS.get(raw)
    if resolver is None:
        return False, f"unknown conditional {raw!r}"
    resolved, evidence = resolver(env)
    return resolved, f"{raw} → {evidence} → enabled={resolved}"


# ---------------------------------------------------------------------------
# Planning + execution
# ---------------------------------------------------------------------------


def _capture_posture_safe() -> dict[str, Any]:
    """Pull a fresh posture snapshot. Never raises — returns an empty
    dict if posture can't be captured for any reason."""
    try:
        from ..posture import capture_posture

        return capture_posture(sanitize=True)
    except Exception as e:
        logger.warning("apply_declaration: posture capture failed: %s", e)
        return {}


def _find_binary(candidates: tuple[str, ...]) -> str | None:
    """Return the first candidate found on PATH, or None.

    For ibounce specifically, fall back to ``sys.executable -m
    iam_jit.bouncer_cli`` when the ``ibounce`` console-script isn't on
    PATH (common in dev / wheel-only installs). Other bouncers
    (kbouncer, dbounce, gbounce) are separate binaries with no
    sys.executable fallback.
    """
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None


def _start_bouncer(
    name: str,
    *,
    port: int | None,
    mode: str,
    profile: str,
    extra_args: list[str] | None,
    execute: bool,
) -> dict[str, Any]:
    """Return a planned-start record. When ``execute`` is True, attempt
    the actual start (subprocess.Popen, detached).

    Honest failure mode: if the binary isn't on PATH we record a
    ``binary_not_found`` warning + skip; we do NOT block the rest of
    the setup.
    """
    defaults = BOUNCER_DEFAULTS[name]
    resolved_port = port or defaults["default_port"]
    binary = _find_binary(defaults["binary_candidates"])

    # ibounce-specific fallback: invoke the in-tree CLI via python -m.
    if binary is None and name == "ibounce":
        binary = sys.executable
        cmd = [binary, "-m", "iam_jit.bouncer_cli", "run"]
    elif binary is None:
        return {
            "name": name,
            "started": False,
            "skipped": True,
            "reason": (
                f"binary not found on PATH (looked for: "
                f"{','.join(defaults['binary_candidates'])})"
            ),
        }
    else:
        cmd = [binary, "run"]

    cmd.extend(["--port", str(resolved_port)])
    # Mode mapping: declaration's `discovery` is the bouncer's default
    # (no `--profile` flag). `cooperative` + `strict` map to ibounce's
    # ProxyMode of `cooperative` / `transparent` respectively (other
    # bouncers ship similar mode flags; we pass through verbatim and
    # let the bouncer reject if it doesn't understand the flag).
    if name == "ibounce":
        if mode == "strict":
            cmd.extend(["--mode", "transparent"])
        elif mode == "cooperative":
            cmd.extend(["--mode", "cooperative"])
        # discovery → no --mode flag (bouncer default per
        # [[discovery-first-default]])
    elif mode != "discovery":
        # Other bouncers — pass --mode through verbatim. If the bouncer
        # doesn't accept it, the operator will see a clear error in
        # the bouncer's own startup log.
        cmd.extend(["--mode", mode])

    # Profile selection. `auto` = no flag (use whatever's currently
    # active). Named profile = pass --profile NAME.
    if profile and profile != "auto":
        cmd.extend(["--profile", profile])

    if extra_args:
        cmd.extend(extra_args)

    # #434 — record BOTH the declared mode (the operator's vocabulary,
    # what they wrote in `.iam-jit.yaml`) AND the runtime alias
    # (cooperative/transparent/...), so dry-run / JSON output keeps
    # the declaration→posture mapping transparent. The `mode` field
    # stays the declared value for backward-compat with existing
    # callers.
    record: dict[str, Any] = {
        "name": name,
        "started": False,
        "skipped": False,
        "command": cmd,
        "port": resolved_port,
        "mode": mode,
        "mode_declared": mode,
        "mode_runtime": declared_runtime_alias(mode),
        "profile": profile,
    }

    if not execute:
        record["note"] = "dry-run: would execute the command above"
        return record

    # Actually start. We detach the subprocess so the bouncer outlives
    # this process. Stdout / stderr go to /dev/null per the bouncer's
    # own conventions (operator inspects via `bounce posture` or the
    # bouncer's audit log).
    #
    # #435 — propagate IAM_JIT_BOUNCER_MODE + IAM_JIT_MODE_SOURCE into
    # the child env so the bouncer's `resolve_active_mode` returns
    # source="declaration" when its mode was picked by the operator's
    # `.iam-jit.yaml`. We always set both; even when the mode is the
    # default "discovery"/"cooperative" the attribution matters
    # (operator wants posture to say "declaration", not "default").
    child_env = dict(os.environ)
    runtime_mode = declared_runtime_alias(mode)
    if name == "ibounce":
        # ibounce reads IAM_JIT_BOUNCER_MODE; other bouncers have their
        # own env-var conventions and ignore these.
        child_env["IAM_JIT_BOUNCER_MODE"] = runtime_mode
        child_env["IAM_JIT_MODE_SOURCE"] = "declaration"
    try:
        proc = subprocess.Popen(  # noqa: S603 — args are non-shell
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
            env=child_env,
        )
        record["started"] = True
        record["pid"] = proc.pid
        # Give the process a moment to bind its port. We do NOT block
        # on a healthz probe here — the caller's posture-recapture
        # below is the truthful check.
        time.sleep(0.20)
    except (OSError, FileNotFoundError) as e:
        record["started"] = False
        record["skipped"] = True
        record["reason"] = f"subprocess.Popen failed: {e}"

    return record


def _env_var_for(
    name: str,
    *,
    port: int,
) -> tuple[str, str]:
    """Return ``(env_var_name, env_var_value_advice)`` for a bouncer."""
    defaults = BOUNCER_DEFAULTS[name]
    template: str = defaults["env_advice_template"]
    rendered = template.format(port=port)
    # The template is "VAR=value" form; split into a tuple for the
    # env_vars_to_set dict.
    env_name, _, value = rendered.partition("=")
    return env_name.strip(), value.strip()


def _emit_setup_audit(
    *,
    name: str,
    posture_before: dict[str, Any],
    posture_after: dict[str, Any],
    declaration_block: dict[str, Any],
    source: str,
    execute: bool,
) -> str | None:
    """Best-effort admin-action emit for ``admin_action.setup.applied``.

    Returns the audit event ID (or None if the audit channel is not
    reachable from this process — the CLI is out-of-process from the
    bouncer's serve loop, so this is almost always None in the CLI
    path; the MCP-tool path inside the serve loop will get a real
    event ID).

    Per the admin-action layer's KNOWN_ADMIN_ACTION_KINDS gate the
    string ``setup.applied`` is NOT in the canonical set; we still emit
    it as an extra-kind event (the audit-export layer accepts arbitrary
    kinds under `kind` per the OCSF unmapped.iam_jit.admin_action
    block; the KNOWN set is the routing whitelist for SQLite-replay,
    which doesn't affect best-effort direct emit).
    """
    if not execute:
        return None
    try:
        from ..bouncer.audit_export.admin_action import emit_admin_action_direct
        from ..bouncer.proxy import _emit_audit_event
    except Exception:
        return None
    try:
        emit_admin_action_direct(
            _emit_audit_event,
            kind="setup.applied",
            actor=os.environ.get("USER") or "operator",
            target_kind="bouncer",
            target_id=name,
            source="cli_apply_config",
            extra={
                "declaration_source": source,
                "declaration_block": declaration_block,
                "posture_before_running": (
                    posture_before.get("bouncers", {})
                    .get(DECLARATION_TO_POSTURE_KEY.get(name, name), {})
                    .get("running")
                ),
                "posture_after_running": (
                    posture_after.get("bouncers", {})
                    .get(DECLARATION_TO_POSTURE_KEY.get(name, name), {})
                    .get("running")
                ),
            },
        )
    except Exception as e:  # pragma: no cover
        logger.warning("setup audit emit failed for %s: %s", name, e)
        return None
    return f"setup-applied-{name}-{int(time.time() * 1000)}"


# ---------------------------------------------------------------------------
# Public entrypoints
# ---------------------------------------------------------------------------


def plan_declaration(
    declaration: dict[str, Any],
    *,
    source: str = "<inline>",
    posture: dict[str, Any] | None = None,
    env: dict[str, str] | None = None,
) -> SetupResult:
    """Compute what ``apply_declaration`` WOULD do without executing.
    Pure planner: no subprocess starts, no env mutations, no audit
    emits. Used by ``dry_run=True`` callers + by the MCP `--inspect`
    surface.
    """
    return apply_declaration(
        declaration,
        source=source,
        posture=posture,
        env=env,
        execute=False,
    )


def apply_declaration(
    declaration: dict[str, Any],
    *,
    source: str = "<inline>",
    posture: dict[str, Any] | None = None,
    env: dict[str, str] | None = None,
    execute: bool = False,
    rollback_on_failure: bool = True,
) -> SetupResult:
    """Apply (or plan) a declaration.

    Args:
      declaration: validated config dict (`{"iam-jit": {...}}`).
      source: where the declaration came from; surfaced in audit + warnings.
      posture: optional pre-captured posture snapshot; we capture fresh
               via ``iam_jit.posture.capture_posture`` when None.
      env: optional env-var dict override; defaults to ``os.environ``.
           Used by tests to drive the `when_X_present` resolvers.
      execute: when False (default), pure plan; when True, attempt to
               start bouncers + emit audit events.
      rollback_on_failure: when True (#538 default), a partial-install
               (any bouncer fails to start mid-apply) triggers
               transactional rollback — SIGTERM the bouncers that DID
               start + restore the pre-apply config-file snapshot. The
               result's ``rollback_outcome`` field describes what the
               rollback observed. Pass False to keep pre-#538 semantics
               (leave partial state for operator inspection). Only
               meaningful with ``execute=True``.

    Returns SetupResult (dict-serializable via .as_dict()).
    """
    env_map = env if env is not None else dict(os.environ)
    block = declaration.get("iam-jit") or {}
    result = SetupResult(dry_run=not execute, declaration_source=source)

    # #538 — pre-apply snapshot. Captured even when rollback_on_failure
    # is False so the result can still surface the pre-apply state for
    # operator inspection (cheap; in-memory only).
    state_snapshot: dict[str, Any] | None = None
    if execute:
        state_snapshot = _capture_setup_state(posture=posture)

    # Cross-field warnings stashed by validate_declaration (e.g.
    # ambient + fail_on_deny=true). Surface them up front so the
    # operator sees the friendly nudge before any setup happens.
    for w in declaration.get("__posture_warnings__", []) or []:
        result.warnings.append(w)

    # Master switch: enabled: false → no-op.
    if not block.get("enabled", False):
        result.status = "disabled"
        result.warnings.append(
            "iam-jit.enabled is false; setup is a no-op. "
            "Flip to true to install + start bouncers."
        )
        result.posture_before = posture or _capture_posture_safe()
        result.posture_after = result.posture_before
        return result

    # Capture posture BEFORE we change anything.
    result.posture_before = posture or _capture_posture_safe()

    # Phase B forward-compat warning.
    improve = block.get("improve") or {}
    if improve.get("enabled"):
        result.warnings.append(
            "improve.enabled is true in the declaration but Phase B "
            "(iam_jit_improve_profile, #401) is not shipped yet; the "
            "improve.* block is accepted for forward-compat and will be "
            "wired in v1.1.1. Phase A is setup-only."
        )

    # Walk each bouncer block in a stable order so dry-run output is
    # deterministic.
    bouncers = block.get("bouncers") or {}
    for name in ("ibounce", "kbouncer", "dbounce", "gbounce"):
        bcfg = bouncers.get(name)
        if bcfg is None:
            # Not declared → skip silently (the operator opted out by
            # omission; this is a legit posture).
            continue

        raw_enabled = bcfg.get("enabled")
        resolved, evidence = _resolve_enabled(raw_enabled, env=env_map)
        result.resolved_conditionals.append({
            "bouncer": name,
            "enabled_raw": raw_enabled,
            "enabled_resolved": resolved,
            "evidence": evidence,
        })

        if not resolved:
            if isinstance(raw_enabled, str):
                # `when_X_present` that came back false — record a
                # transparent skip per [[ibounce-honest-positioning]].
                # #538 — `kind: conditional_false` distinguishes this
                # from start-failure skips so the rollback trigger
                # doesn't fire on legitimate "you don't have a
                # KUBECONFIG" skips.
                result.bouncers_skipped.append({
                    "name": name,
                    "reason": (
                        f"conditional `{raw_enabled}` resolved to false: "
                        f"{evidence}"
                    ),
                    "kind": "conditional_false",
                })
            # explicit false → no skip record, just don't act.
            continue

        # The bouncer should be active. Check posture first.
        posture_key = DECLARATION_TO_POSTURE_KEY.get(name, name)
        pbouncer = (result.posture_before.get("bouncers") or {}).get(
            posture_key, {}
        )
        already_running = bool(pbouncer.get("running"))

        mode = bcfg.get("mode") or "discovery"
        profile = bcfg.get("profile") or "auto"
        port = bcfg.get("port")
        extra_args = list(bcfg.get("extra_args") or [])
        # #424 / §A63 — translate the declarative disk_pressure_mode
        # field into the bouncer's CLI flag. Operator-supplied
        # extra_args win on conflict (per [[creates-never-mutates]]
        # the operator's explicit args are authoritative); we only
        # append our flag pair when the operator hasn't already passed
        # it via extra_args. Each Bounce reads the same wire field per
        # [[cross-product-agent-parity]]; only ibounce wires it today
        # (kbouncer/dbouncer/gbouncer follow-up tasks).
        _dp_mode_decl = bcfg.get("disk_pressure_mode")
        if _dp_mode_decl and not any(
            a == "--disk-pressure-mode" or a.startswith("--disk-pressure-mode=")
            for a in extra_args
        ):
            extra_args.extend(["--disk-pressure-mode", _dp_mode_decl])

        # #434 + #435 — record the declared→runtime mapping + the
        # provenance attribution per bouncer. The declaration is the
        # operator's explicit input; surfacing both vocabularies +
        # `mode_source: declaration` keeps `apply-config` output
        # symmetric with `posture` output.
        result.bouncer_mode_resolutions.append({
            "bouncer": name,
            "mode_declared": mode,
            "mode_runtime": declared_runtime_alias(mode),
            "mode_source": "declaration",
        })

        # #433 — probe /healthz to confirm the listener really IS an
        # iam-jit bouncer of the expected kind before we claim
        # "already running". A bare TCP probe (posture's mechanism)
        # cannot tell us whether nc/redis/whatever happens to be on
        # the port. Run only when posture says the port is bound.
        if already_running:
            probe_port = int(
                pbouncer.get("port")
                or port
                or BOUNCER_DEFAULTS[name]["default_port"]
            )
            probe_kind, probe_detail = _probe_bouncer_healthz(
                probe_port,
                expected_kind=name,
            )
            if probe_kind == "non_bouncer":
                # The TCP port is occupied but the listener is NOT a
                # bouncer. Don't claim "already running"; warn loudly.
                # #538 — `kind: port_conflict` is operator-actionable
                # but NOT a partial-install signal (we never started
                # this bouncer).
                result.bouncers_skipped.append({
                    "name": name,
                    "reason": (
                        f"port {probe_port} already occupied by a "
                        f"non-iam-jit process. {probe_detail} "
                        f"Specify a different port for {name} via the "
                        f"declaration's `port:` field or stop the "
                        f"existing process."
                    ),
                    "kind": "port_conflict",
                })
                result.warnings.append(
                    f"{name}: port {probe_port} is in use by a process "
                    f"that does NOT identify as an iam-jit bouncer. "
                    f"{probe_detail} The setup will NOT start {name} "
                    f"on this port (would conflict). Either stop the "
                    f"existing process or set `bouncers.{name}.port:` "
                    f"to a free port in your declaration."
                )
                # Don't add to bouncers_already_running and don't
                # advertise an env var pointing at the wrong process.
                continue
            if probe_kind == "bouncer" and probe_detail not in (
                name,
                # kbouncer's posture key is "kbounce" but the bouncer
                # may identify as either; accept the kbouncer/kbounce
                # symmetry per the existing alias map.
                DECLARATION_TO_POSTURE_KEY.get(name, name),
            ):
                # A DIFFERENT bouncer is on the port we wanted —
                # transparent warning + skip per
                # [[ibounce-honest-positioning]]. #538: `kind:
                # port_conflict` (operator-actionable, not a
                # partial-install signal).
                result.bouncers_skipped.append({
                    "name": name,
                    "reason": (
                        f"port {probe_port} is occupied by a different "
                        f"iam-jit bouncer (`{probe_detail}`); cannot "
                        f"start {name} here. Choose a different port "
                        f"or stop the other bouncer."
                    ),
                    "kind": "port_conflict",
                })
                result.warnings.append(
                    f"{name}: port {probe_port} is occupied by another "
                    f"iam-jit bouncer (`{probe_detail}`). Setting "
                    f"`bouncers.{name}.port:` to a free port resolves "
                    f"this."
                )
                continue
            # probe_kind == "free" is impossible here (posture said
            # running) but handle it conservatively — treat as "no
            # confirmation; fall through to legacy path".

        if already_running:
            # Per [[creates-never-mutates]]: do NOT restart a running
            # bouncer to apply a different mode/profile without explicit
            # consent. Warn + skip.
            running_mode = pbouncer.get("mode", "unknown")
            running_profile = pbouncer.get("active_profile", "unknown")
            running_port = pbouncer.get("port")
            # #434 — compare using the alias-aware helper so a
            # declaration-mode `discovery` does NOT trip a "mismatch"
            # against a runtime mode `cooperative` (they're the same
            # thing under different vocabularies).
            mode_mismatch = (
                running_mode not in ("unknown", "")
                and not _modes_match(mode, running_mode)
            )
            profile_mismatch = (
                profile != "auto"
                and running_profile not in ("unknown", profile)
            )
            port_mismatch = (
                port is not None
                and running_port is not None
                and int(port) != int(running_port)
            )
            if mode_mismatch or profile_mismatch or port_mismatch:
                # Surface the running mode in DECLARED vocabulary so the
                # operator can compare apples-to-apples with their
                # `.iam-jit.yaml`. The runtime form is included in
                # parentheses so a curious operator can map back to the
                # ibounce CLI flag.
                running_mode_declared = runtime_declared_alias(running_mode)
                result.warnings.append(
                    f"{name} is already running with "
                    f"mode={running_mode_declared!r} "
                    f"(runtime: {running_mode!r}) "
                    f"profile={running_profile!r} "
                    f"port={running_port!r}; the declaration asks for "
                    f"mode={mode!r} profile={profile!r} port={port!r}. "
                    f"Per [[creates-never-mutates]] we will NOT restart "
                    f"a running bouncer without explicit operator action. "
                    f"Stop the bouncer manually (`ibounce stop` / `kill "
                    f"<pid>`) and re-run setup to apply the declared "
                    f"config."
                )
            result.bouncers_already_running.append(name)
            # Still record the env-var advisory — the agent's
            # subprocesses still need to be pointed at the bouncer.
            env_name, env_val = _env_var_for(
                name, port=int(running_port or port or BOUNCER_DEFAULTS[name]["default_port"])
            )
            result.env_vars_to_set.setdefault(env_name, env_val)
            continue

        # Not running — start it (or plan to).
        record = _start_bouncer(
            name,
            port=port,
            mode=mode,
            profile=profile,
            extra_args=extra_args,
            execute=execute,
        )
        result.bouncers_planned.append(record)
        if record.get("skipped"):
            # #538 — mark this skip as a START-FAILURE (vs the conditional-
            # false skip path above). The rollback trigger fires only when
            # at least one declared bouncer was started AND at least one
            # was a start-failure (true partial-install signal).
            result.bouncers_skipped.append({
                "name": name,
                "reason": record.get("reason", "skipped"),
                "kind": "start_failure",
            })
            continue
        if record.get("started"):
            result.bouncers_started.append(name)
        # Env-var advisory regardless (planned start should still tell
        # the agent what env to use).
        env_name, env_val = _env_var_for(
            name,
            port=record.get("port", BOUNCER_DEFAULTS[name]["default_port"]),
        )
        result.env_vars_to_set.setdefault(env_name, env_val)

        # Track profile reuse vs install. Phase A NEVER installs a new
        # profile — `auto` reuses whatever's there, and a named profile
        # MUST already exist in profiles.yaml. We surface this as a
        # warning when the named profile isn't found (operator likely
        # forgot to install it).
        if profile and profile != "auto":
            # #560 — `load_profiles()` returns `dict[str, Profile]`. The
            # previous code did `{p.name for p in profiles}` which
            # iterated the dict's KEYS (already strings) and then tried
            # `.name` on each one, raising AttributeError; the outer
            # `except Exception: pass` swallowed it. Net effect: declaring
            # a non-existent profile produced ZERO warning — exact MRR-2
            # Pattern B (silently-degraded operator hint). Now: use
            # `set(profiles)` directly to get the name set, and catch
            # only the specific load-time errors load_profiles can
            # raise (per its docstring: FileNotFoundError-equivalents +
            # ValueError on malformed YAML). Unexpected exceptions
            # propagate so future regressions don't re-hide.
            try:
                from ..bouncer.profiles import load_profiles
                profiles = load_profiles()
                names = set(profiles) if profiles else set()
                if profile not in names:
                    result.warnings.append(
                        f"{name}: declaration pinned profile={profile!r} "
                        f"but that profile is not in profiles.yaml "
                        f"(available: {sorted(names)}). The bouncer "
                        f"will reject the --profile flag at startup. "
                        f"Install the profile first with `iam-jit "
                        f"profile generate-from-audit` or add it "
                        f"manually to profiles.yaml."
                    )
                else:
                    result.profiles_installed.append({
                        "bouncer": name,
                        "profile_name": profile,
                        "source": "declared",
                    })
            except (FileNotFoundError, ValueError, OSError) as e:
                # Specific exceptions only — don't swallow the
                # AttributeError class of bug again.
                result.warnings.append(
                    f"{name}: profile presence check failed for "
                    f"profile={profile!r}: {e}. Cannot confirm whether "
                    f"the bouncer will accept the --profile flag at "
                    f"startup; inspect profiles.yaml manually."
                )

    # Recapture posture AFTER any startups so the caller sees the new
    # state. When execute=False we still emit a fresh capture (cheap)
    # but it'll equal posture_before.
    result.posture_after = _capture_posture_safe()

    # Per-bouncer audit emit (best-effort).
    for name in result.bouncers_started:
        ev = _emit_setup_audit(
            name=name,
            posture_before=result.posture_before,
            posture_after=result.posture_after,
            declaration_block=bouncers.get(name) or {},
            source=source,
            execute=execute,
        )
        if ev:
            result.audit_event_ids.append(ev)

    # If notify_on_deny was declared, surface it as advisory only — we
    # don't have a notification daemon to configure in Phase A; this is
    # planned for Phase B (#403 autopilot).
    if block.get("notify_on_deny") is False:
        result.warnings.append(
            "notify_on_deny=false in the declaration: deny notifications "
            "will NOT surface in your terminal. Per the founder direction "
            "the deny-obviousness surface should stay on by default."
        )

    # #538 — transactional rollback trigger. Partial-install signal is:
    # we both STARTED at least one bouncer AND had at least one
    # `start_failure` skip. (Conditional-false skips or port-conflict
    # skips are operator-actionable but not partial-install events;
    # see the comments at each skip-emit site.)
    if execute and rollback_on_failure and state_snapshot is not None:
        start_failures = [
            s for s in result.bouncers_skipped
            if (s.get("kind") or "") == "start_failure"
        ]
        if result.bouncers_started and start_failures:
            # Collect newly-started PIDs from the planned records (every
            # _start_bouncer record stamps `pid` on success).
            new_pids: dict[str, int] = {}
            for rec in result.bouncers_planned:
                if rec.get("started") and rec.get("pid"):
                    try:
                        new_pids[rec["name"]] = int(rec["pid"])
                    except (TypeError, ValueError):
                        continue
            rollback = _restore_setup_state(
                state_snapshot, new_pids=new_pids,
            )
            failed_names = ", ".join(s["name"] for s in start_failures)
            rollback["trigger_reason"] = (
                f"partial-install detected (#538): started="
                f"{result.bouncers_started!r} but start-failures="
                f"{failed_names!r}"
            )
            result.rollback_outcome = rollback
            # Mark the overall status so callers can branch on it.
            result.status = (
                "rolled_back" if rollback["status"] == "ok"
                else "rollback_incomplete"
            )
            result.warnings.append(
                f"#538 partial-install rollback fired: "
                f"{rollback['trigger_reason']}. "
                f"Killed PIDs: {rollback['killed_pids']!r}. "
                f"Files restored: {len(rollback['files_restored'])}. "
                f"Verification status: {rollback['status']}."
            )
            # Side-effect honesty: the bouncers we just SIGTERMd are no
            # longer running; clear them from `bouncers_started` so the
            # operator-facing result doesn't claim they're live.
            killed_pid_set = set(rollback["killed_pids"])
            still_running: list[str] = []
            for name in result.bouncers_started:
                # Find the planned record's PID + check if we killed it.
                for rec in result.bouncers_planned:
                    if (
                        rec.get("name") == name
                        and rec.get("pid")
                        and int(rec["pid"]) in killed_pid_set
                    ):
                        break
                else:
                    still_running.append(name)
                    continue
                # Bouncer was killed by rollback — DON'T keep in started.
            result.bouncers_started = still_running

            # CRIT-like warning if rollback verification itself failed.
            if rollback["status"] != "ok":
                result.warnings.append(
                    f"#538 rollback INCOMPLETE: kill_failures="
                    f"{rollback['kill_failures']!r}, restore_failures="
                    f"{rollback['restore_failures']!r}, "
                    f"verification_drift="
                    f"{rollback['verification_drift']!r}. The operator's "
                    f"state may not match the pre-apply snapshot; manual "
                    f"inspection required per docs/MRR-4-ROLLBACK-RUNBOOK.md "
                    f"RB-B6."
                )

    return result


__all__ = [
    "BOUNCER_DEFAULTS",
    "DECLARATION_TO_POSTURE_KEY",
    "SetupResult",
    "_capture_setup_state",
    "_restore_setup_state",
    "apply_declaration",
    "plan_declaration",
]
