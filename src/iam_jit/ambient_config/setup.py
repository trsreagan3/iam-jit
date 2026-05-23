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

import logging
import os
import pathlib
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


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

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


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

    record: dict[str, Any] = {
        "name": name,
        "started": False,
        "skipped": False,
        "command": cmd,
        "port": resolved_port,
        "mode": mode,
        "profile": profile,
    }

    if not execute:
        record["note"] = "dry-run: would execute the command above"
        return record

    # Actually start. We detach the subprocess so the bouncer outlives
    # this process. Stdout / stderr go to /dev/null per the bouncer's
    # own conventions (operator inspects via `bounce posture` or the
    # bouncer's audit log).
    try:
        proc = subprocess.Popen(  # noqa: S603 — args are non-shell
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
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

    Returns SetupResult (dict-serializable via .as_dict()).
    """
    env_map = env if env is not None else dict(os.environ)
    block = declaration.get("iam-jit") or {}
    result = SetupResult(dry_run=not execute, declaration_source=source)

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
                result.bouncers_skipped.append({
                    "name": name,
                    "reason": (
                        f"conditional `{raw_enabled}` resolved to false: "
                        f"{evidence}"
                    ),
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
        extra_args = bcfg.get("extra_args") or []

        if already_running:
            # Per [[creates-never-mutates]]: do NOT restart a running
            # bouncer to apply a different mode/profile without explicit
            # consent. Warn + skip.
            running_mode = pbouncer.get("mode", "unknown")
            running_profile = pbouncer.get("active_profile", "unknown")
            running_port = pbouncer.get("port")
            mode_mismatch = (
                running_mode not in ("unknown", mode)
                and not (mode == "strict" and running_mode == "transparent")
                and not (mode == "discovery" and running_mode == "discovery")
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
                result.warnings.append(
                    f"{name} is already running with "
                    f"mode={running_mode!r} profile={running_profile!r} "
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
            result.bouncers_skipped.append({
                "name": name,
                "reason": record.get("reason", "skipped"),
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
            try:
                from ..bouncer.profiles import load_profiles
                profiles = load_profiles()
                names = {p.name for p in profiles} if profiles else set()
                if profile not in names:
                    result.warnings.append(
                        f"{name}: declaration pinned profile={profile!r} "
                        f"but that profile is not in profiles.yaml. The "
                        f"bouncer will reject the --profile flag at "
                        f"startup. Install the profile first with "
                        f"`iam-jit profile generate-from-audit` or add "
                        f"it manually to profiles.yaml."
                    )
                else:
                    result.profiles_installed.append({
                        "bouncer": name,
                        "profile_name": profile,
                        "source": "declared",
                    })
            except Exception as e:  # pragma: no cover
                logger.debug("profile presence check failed: %s", e)

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

    return result


__all__ = [
    "BOUNCER_DEFAULTS",
    "DECLARATION_TO_POSTURE_KEY",
    "SetupResult",
    "apply_declaration",
    "plan_declaration",
]
