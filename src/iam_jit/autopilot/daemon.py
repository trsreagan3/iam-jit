"""``iam-jit autopilot`` daemon supervisor (#403).

Design notes:

  * The supervisor uses simple polling — no asyncio runloop — because we
    want the daemon to also work via ``--no-detach`` foreground mode for
    tests + the smoke test. Polling cadence is 5s for posture sweeps;
    improve cycles run on the declared cadence (per_session = once at
    startup + every 30 minutes; daily / weekly use real-time windows).
  * PID file at ``~/.iam-jit/autopilot.pid``. Stale-PID detection: if
    the file exists but the PID is dead, we delete it on next start.
  * Restart policy: per-bouncer counter of restart attempts within a
    rolling 60-second window; >3 attempts triggers an alert (stderr +
    audit emit) + skip future restarts of that bouncer until next
    operator intervention.

Per [[ibounce-honest-positioning]] each operator-facing surface
(status / stop / start) reports the truth — if a bouncer keeps
crashing we say so loudly rather than retrying silently.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import logging
import os
import pathlib
import signal
import subprocess
import sys
import time
from typing import Any

import click

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Path helpers + file locations
# ---------------------------------------------------------------------------


_AUTOPILOT_DIR_ENV = "IAM_JIT_AUTOPILOT_DIR"
_PID_FILENAME = "autopilot.pid"
_STATUS_FILENAME = "autopilot.status.json"


def _autopilot_dir() -> pathlib.Path:
    """Return the directory used to hold PID + status files.

    Default: ``~/.iam-jit/``. Tests override via the
    ``IAM_JIT_AUTOPILOT_DIR`` env var.
    """
    raw = (os.environ.get(_AUTOPILOT_DIR_ENV) or "").strip()
    if raw:
        return pathlib.Path(raw).expanduser()
    return pathlib.Path.home() / ".iam-jit"


def resolve_pid_path() -> pathlib.Path:
    return _autopilot_dir() / _PID_FILENAME


def _status_path() -> pathlib.Path:
    return _autopilot_dir() / _STATUS_FILENAME


# ---------------------------------------------------------------------------
# Errors + status dataclass
# ---------------------------------------------------------------------------


class AutopilotError(RuntimeError):
    """Structured autopilot error."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


@dataclasses.dataclass
class AutopilotStatus:
    """One snapshot of autopilot's view of the world."""

    schema_version: str = "1.0"
    running: bool = False
    pid: int | None = None
    started_at: str | None = None
    config_source: str = ""
    posture: str = "ambient"
    bouncers: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
    improve: dict[str, Any] = dataclasses.field(default_factory=dict)
    alerts: list[str] = dataclasses.field(default_factory=list)
    last_improve_at: str | None = None
    last_sweep_at: str | None = None
    notes: list[str] = dataclasses.field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# PID utilities
# ---------------------------------------------------------------------------


def _is_pid_alive(pid: int) -> bool:
    """Return True iff ``pid`` corresponds to a living process.

    Uses ``os.kill(pid, 0)`` which only signals existence, not delivery.
    Raises no exceptions — broken kills (perms, ESRCH) yield False.
    """
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def _read_pid_file() -> int | None:
    p = resolve_pid_path()
    if not p.exists():
        return None
    try:
        raw = p.read_text().strip()
        return int(raw) if raw else None
    except (OSError, ValueError):
        return None


def _write_pid_file(pid: int) -> None:
    p = resolve_pid_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(str(pid))
    try:
        p.chmod(0o600)
    except OSError:
        pass


def _remove_pid_file() -> None:
    p = resolve_pid_path()
    try:
        p.unlink()
    except FileNotFoundError:
        pass


def _read_status_file() -> dict[str, Any] | None:
    p = _status_path()
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _write_status_file(status: AutopilotStatus) -> None:
    p = _status_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(status.as_dict(), indent=2, default=str))
    try:
        p.chmod(0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Supervisor — the loop body
# ---------------------------------------------------------------------------


_DEFAULT_SWEEP_INTERVAL_S = 5.0
_DEFAULT_IMPROVE_INTERVAL_S = 30 * 60  # 30 minutes for per_session
_RESTART_WINDOW_S = 60.0
_MAX_RESTARTS_PER_WINDOW = 3


@dataclasses.dataclass
class _BouncerSupervisorState:
    name: str
    enabled: bool = True
    restart_attempts: list[float] = dataclasses.field(default_factory=list)
    alert_emitted: bool = False
    last_seen_running: bool = False
    last_pid: int | None = None
    config: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class AutopilotSupervisor:
    """Single-process autopilot loop driver.

    Used both by ``iam-jit autopilot start --no-detach`` (foreground)
    and by the detached subprocess path. Tests can drive
    :meth:`run_once` to exercise one tick without sleeping.
    """

    declaration: dict[str, Any]
    config_source: str
    sweep_interval_s: float = _DEFAULT_SWEEP_INTERVAL_S
    improve_interval_s: float = _DEFAULT_IMPROVE_INTERVAL_S
    notify_denies: str = "stderr"  # stderr | webhook | none
    bouncer_states: dict[str, _BouncerSupervisorState] = dataclasses.field(
        default_factory=dict
    )
    started_at: float = dataclasses.field(default_factory=time.time)
    last_improve_at: float = 0.0
    last_sweep_at: float = 0.0
    stopped: bool = False
    alerts: list[str] = dataclasses.field(default_factory=list)
    _improve_count: int = 0

    @property
    def posture(self) -> str:
        block = (self.declaration or {}).get("iam-jit") or {}
        return str(block.get("posture") or "ambient")

    def _block(self) -> dict[str, Any]:
        return (self.declaration or {}).get("iam-jit") or {}

    def _bouncer_configs(self) -> dict[str, dict[str, Any]]:
        return self._block().get("bouncers") or {}

    def _improve_config(self) -> dict[str, Any]:
        return self._block().get("improve") or {}

    def initialize(self) -> None:
        """Populate ``bouncer_states`` from the declaration. Idempotent."""
        for name, cfg in self._bouncer_configs().items():
            if name not in self.bouncer_states:
                self.bouncer_states[name] = _BouncerSupervisorState(
                    name=name,
                    enabled=True,
                    config=dict(cfg) if isinstance(cfg, dict) else {},
                )
            else:
                self.bouncer_states[name].config = dict(cfg or {})

    # ------------------------------------------------------------------
    # Per-bouncer health check + restart logic
    # ------------------------------------------------------------------

    def _bouncer_running(self, name: str) -> tuple[bool, dict[str, Any]]:
        """Return (running, posture_block) for one bouncer using the
        existing posture machinery."""
        try:
            from ..posture.bouncers import (
                detect_dbounce,
                detect_gbounce,
                detect_ibounce,
                detect_kbounce,
            )
        except Exception:  # pragma: no cover
            return False, {}
        detector = {
            "ibounce": detect_ibounce,
            "kbouncer": detect_kbounce,
            "dbounce": detect_dbounce,
            "gbounce": detect_gbounce,
        }.get(name)
        if not detector:
            return False, {}
        try:
            block = detector()
        except Exception as e:  # pragma: no cover
            logger.warning("autopilot: posture probe failed for %s: %s", name, e)
            return False, {}
        running = bool(block.get("running"))
        return running, block

    def _attempt_restart(self, name: str, state: _BouncerSupervisorState) -> str:
        """Try to (re)start a bouncer. Returns one of:
        ``"started"`` / ``"binary_not_found"`` / ``"throttled"`` /
        ``"start_failed"``.
        """
        now = time.time()
        # Prune restart attempts older than the rolling window.
        state.restart_attempts = [
            t for t in state.restart_attempts if (now - t) <= _RESTART_WINDOW_S
        ]
        if len(state.restart_attempts) >= _MAX_RESTARTS_PER_WINDOW:
            return "throttled"
        # Reuse the apply-config _start_bouncer path so behavior parity
        # with manual `iam-jit doctor apply-config` is preserved.
        from ..ambient_config.setup import _start_bouncer
        cfg = state.config or {}
        record = _start_bouncer(
            name,
            port=cfg.get("port"),
            mode=cfg.get("mode") or "discovery",
            profile=cfg.get("profile") or "auto",
            extra_args=cfg.get("extra_args") or None,
            execute=True,
        )
        state.restart_attempts.append(now)
        if record.get("started"):
            state.last_pid = record.get("pid")
            return "started"
        reason = record.get("reason", "")
        if "binary_not_found" in reason or "binary not found" in reason.lower():
            return "binary_not_found"
        return "start_failed"

    # ------------------------------------------------------------------
    # Improve cycle
    # ------------------------------------------------------------------

    def _improve_due(self) -> bool:
        """Return True if it's time to run the next improve cycle."""
        improve_cfg = self._improve_config()
        if not improve_cfg.get("enabled"):
            return False
        if self.posture == "managed":
            return False
        if self.last_improve_at <= 0.0:
            return True
        cadence = str(improve_cfg.get("cadence") or "per_session")
        interval = {
            "per_session": self.improve_interval_s,
            "daily": 86400.0,
            "weekly": 604800.0,
            "never": float("inf"),
        }.get(cadence, self.improve_interval_s)
        return (time.time() - self.last_improve_at) >= interval

    def run_improve_for_all(self) -> list[dict[str, Any]]:
        """Run one improve cycle for each enabled bouncer. Returns the
        list of result dicts (one per bouncer)."""
        if self.posture == "managed":
            # Explicit refusal per the brief — also surfaces in alerts
            # so the operator sees we tried + chose not to.
            msg = (
                "autopilot improve cycle refused: posture=managed "
                "(reproducibility mode). Switch to posture=ambient "
                "to enable autonomous improvement."
            )
            self.alerts.append(msg)
            return []
        try:
            from ..improve import improve_profile
        except Exception as e:  # pragma: no cover
            self.alerts.append(f"improve module load failed: {e}")
            return []
        improve_cfg = self._improve_config()
        cadence = str(improve_cfg.get("cadence") or "per_session")
        threshold = float(
            improve_cfg.get("require_operator_approval_above_change_threshold")
            or 0.30
        )
        auto_install = bool(improve_cfg.get("auto_install_profiles", True))
        results = []
        for name, state in self.bouncer_states.items():
            if not state.enabled:
                continue
            try:
                r = improve_profile(
                    bouncer=name,
                    cadence=cadence,
                    threshold=threshold,
                    auto_install=auto_install,
                    apply=True,
                    posture=self.posture,
                    source="autopilot",
                )
                results.append(r.as_dict())
            except Exception as e:
                self.alerts.append(
                    f"improve cycle for {name} raised: {e}"
                )
        self.last_improve_at = time.time()
        self._improve_count += 1
        return results

    # ------------------------------------------------------------------
    # One sweep tick — health-check every bouncer + maybe improve
    # ------------------------------------------------------------------

    def run_once(self) -> AutopilotStatus:
        """Perform one supervisor tick: health-check every bouncer +
        restart if needed + maybe run improve cycle.

        Returns the current :class:`AutopilotStatus`.
        """
        self.initialize()
        now = _now_iso()
        per_bouncer: dict[str, dict[str, Any]] = {}
        for name, state in self.bouncer_states.items():
            running, block = self._bouncer_running(name)
            entry: dict[str, Any] = {
                "name": name,
                "running": running,
                "config": state.config,
                "restart_attempts_in_window": len(state.restart_attempts),
                "alert_emitted": state.alert_emitted,
            }
            if running:
                state.last_seen_running = True
                state.alert_emitted = False  # reset alert on healthy
                entry["pid"] = block.get("pid")
                entry["port"] = block.get("port")
            else:
                # Not running — try to restart (subject to throttle).
                if state.alert_emitted:
                    entry["status"] = "alerted_no_restart"
                else:
                    outcome = self._attempt_restart(name, state)
                    entry["restart_outcome"] = outcome
                    if outcome == "throttled":
                        state.alert_emitted = True
                        msg = (
                            f"autopilot: {name} failed to restart "
                            f">={_MAX_RESTARTS_PER_WINDOW} times in "
                            f"{int(_RESTART_WINDOW_S)}s; halting restart "
                            f"attempts. Operator intervention required."
                        )
                        self.alerts.append(msg)
                        sys.stderr.write(msg + "\n")
                    elif outcome == "binary_not_found":
                        state.alert_emitted = True
                        msg = (
                            f"autopilot: {name} binary not on PATH; "
                            f"will not retry."
                        )
                        self.alerts.append(msg)
                        sys.stderr.write(msg + "\n")
            per_bouncer[name] = entry
        self.last_sweep_at = time.time()

        # Improve cycle (independent cadence from sweep).
        improve_results: list[dict[str, Any]] = []
        if self._improve_due():
            improve_results = self.run_improve_for_all()

        # Deny notification surface — per the brief, this is a
        # placeholder hook for #389 (full notification daemon ships
        # separately). For now, when notify_denies != "none" we tail
        # the existing /denies surface and write to stderr.
        if self.notify_denies != "none":
            try:
                self._notify_recent_denies()
            except Exception as e:  # pragma: no cover
                logger.debug("autopilot deny notify failed: %s", e)

        status = AutopilotStatus(
            running=True,
            pid=os.getpid(),
            started_at=_dt.datetime.fromtimestamp(
                self.started_at, tz=_dt.timezone.utc
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            config_source=self.config_source,
            posture=self.posture,
            bouncers=per_bouncer,
            improve={
                "enabled": bool(self._improve_config().get("enabled")),
                "cadence": str(self._improve_config().get("cadence") or "per_session"),
                "auto_install": bool(
                    self._improve_config().get("auto_install_profiles", True)
                ),
                "threshold": float(
                    self._improve_config().get(
                        "require_operator_approval_above_change_threshold"
                    ) or 0.30
                ),
                "improve_count_since_startup": self._improve_count,
                "last_results": improve_results,
            },
            alerts=list(self.alerts),
            last_improve_at=(
                _dt.datetime.fromtimestamp(
                    self.last_improve_at, tz=_dt.timezone.utc
                ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                if self.last_improve_at
                else None
            ),
            last_sweep_at=now,
            notes=[
                f"sweep_interval_s={self.sweep_interval_s}",
                f"improve_interval_s={self.improve_interval_s}",
                f"max_restarts_per_window={_MAX_RESTARTS_PER_WINDOW}",
            ],
        )
        _write_status_file(status)
        return status

    def _notify_recent_denies(self) -> None:
        """Probe each bouncer's /denies endpoint via the #345 fetcher
        and surface a short note per new deny since the last sweep.
        Placeholder for the #389 notification daemon.

        Per #413 / [[ambient-value-prop-and-friction-framing]]:

          * ``stderr``  — short "Your bouncer caught X" line + a
            classification-aware recommendation (halt+escalate vs
            allow-if-legit). NEVER leads with "ERROR" / "DENIED".
          * ``webhook`` — POST a Slack/Discord-card-shaped JSON payload
            to ``IAM_JIT_AUTOPILOT_DENY_WEBHOOK_URL`` (env var; webhooks
            often carry secrets in their URLs so we DO NOT take it from
            a CLI flag — env var only per
            [[push-policy-public-repo]]).
        """
        try:
            from ..profile_allow.denies import fetch_recent_denies
            from ..structured_deny import build_structured_deny
        except Exception:
            return
        # Only sweep 30 seconds back to avoid spamming on every tick.
        rows, _notes = fetch_recent_denies(since="30s", limit=10)
        if not rows:
            return

        for row in rows:
            structured = build_structured_deny(
                bouncer=row.bouncer or "unknown",
                action=row.action or "",
                resource=row.resource or "",
                deny_reason=row.deny_reason or "",
                deny_source=row.deny_source or "",
                rule_id_if_dynamic=row.rule_id_if_dynamic,
                suggested_allow_command=row.suggested_allow_command or "",
                agent_session_id=row.agent_session_id or "",
                when=row.when or "",
            )
            if self.notify_denies == "stderr":
                self._notify_stderr(structured)
            elif self.notify_denies == "webhook":
                self._notify_webhook(structured)
            # `none` is unreachable (we gate on != "none" in run_once)

    def _notify_stderr(self, sd: Any) -> None:
        """Write a one-line caught-framing summary to stderr per
        [[ambient-value-prop-and-friction-framing]].

        Adversarial classifications still escalate per
        [[ibounce-honest-positioning]]: the recommended halt is loud,
        not whispered, so an operator can't miss it."""
        cls = sd.is_likely_injection_classification
        tag = {
            "appears_adversarial": "(!)",
            "ambiguous": "(?)",
            "appears_legitimate": "(*)",
        }.get(cls, "(?)")
        line = (
            f"[autopilot] {tag} Your {sd.caught_by_bouncer} bouncer caught: "
            f"{sd.action or '(unknown)'} on {sd.resource or '(unknown)'} "
            f"(why: {sd.deny_source}). "
        )
        if cls == "appears_adversarial":
            line += "Recommended: halt + escalate — do NOT auto-allow."
        elif sd.suggested_allow_command:
            line += f"Allow if legit: {sd.suggested_allow_command}"
        sys.stderr.write(line + "\n")

    def _notify_webhook(self, sd: Any) -> None:
        """POST a Slack/Discord-shaped JSON card to the webhook URL.

        Per [[ambient-value-prop-and-friction-framing]] the card LEADS
        with the caught-framing; the payload is also explicit about
        whether the classifier flagged this as worth halting.

        Failure paths are silent (logger.debug) per
        [[ibounce-honest-positioning]] — we don't surface webhook
        flakiness as a deny-notification outage; the operator can
        always fall back to `iam-jit denies recent`.
        """
        webhook_url = os.environ.get("IAM_JIT_AUTOPILOT_DENY_WEBHOOK_URL", "").strip()
        if not webhook_url:
            logger.debug(
                "autopilot webhook notify skipped: IAM_JIT_AUTOPILOT_DENY_WEBHOOK_URL unset"
            )
            return
        payload = _structured_deny_to_webhook_card(sd)
        try:
            import urllib.request
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # Best-effort 3-second timeout — webhook delivery latency
            # must not stall the supervisor loop.
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                resp.read()
        except Exception as e:
            logger.debug("autopilot webhook notify failed: %s", e)

    def run_forever(
        self,
        *,
        max_ticks: int | None = None,
    ) -> None:
        """Foreground supervisor loop. Blocks until SIGTERM / SIGINT
        OR ``max_ticks`` ticks (test hook) have elapsed.
        """
        installed = self._install_signal_handlers()
        ticks = 0
        try:
            while not self.stopped:
                self.run_once()
                ticks += 1
                if max_ticks is not None and ticks >= max_ticks:
                    break
                if self.stopped:
                    break
                time.sleep(self.sweep_interval_s)
        finally:
            if installed:
                self._restore_signal_handlers()

    _prior_sigterm = None
    _prior_sigint = None

    def _install_signal_handlers(self) -> bool:
        try:
            self._prior_sigterm = signal.getsignal(signal.SIGTERM)
            self._prior_sigint = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGTERM, self._handle_term)
            signal.signal(signal.SIGINT, self._handle_term)
            return True
        except (ValueError, OSError):
            return False

    def _restore_signal_handlers(self) -> None:
        try:
            if self._prior_sigterm is not None:
                signal.signal(signal.SIGTERM, self._prior_sigterm)
            if self._prior_sigint is not None:
                signal.signal(signal.SIGINT, self._prior_sigint)
        except (ValueError, OSError):
            pass

    def _handle_term(self, *_args: Any) -> None:
        self.stopped = True


# ---------------------------------------------------------------------------
# Webhook-card composer for `--notify-denies webhook` (#413 / §A57).
#
# Slack + Discord both accept a simple text-with-attachments payload;
# we ship that as the canonical shape. Lead with "Your bouncer caught"
# per [[ambient-value-prop-and-friction-framing]]. Adversarial
# classifications surface a ``color: danger`` attachment color so the
# Slack UI surfaces them as red-bar; legit/ambiguous use ``good`` /
# ``warning`` respectively. Keeps the operator's eye-scan loud where it
# matters, quiet where it doesn't.
# ---------------------------------------------------------------------------


def _structured_deny_to_webhook_card(sd: Any) -> dict[str, Any]:
    """Return a Slack/Discord-compatible incoming-webhook payload.

    The exact shape (top-level ``text`` + ``attachments`` array) is the
    Slack legacy incoming-webhook contract; Discord accepts a superset
    and renders ``text`` directly. Operators using other webhook
    targets (Teams, etc.) can post-process via a transformation proxy;
    we explicitly do NOT proliferate per-vendor shapes pre-launch.
    """
    cls = getattr(sd, "is_likely_injection_classification", "ambiguous")
    color = {
        "appears_adversarial": "danger",
        "ambiguous": "warning",
        "appears_legitimate": "good",
    }.get(cls, "warning")
    bouncer = getattr(sd, "caught_by_bouncer", "bouncer")
    action = getattr(sd, "action", "") or "(unknown action)"
    resource = getattr(sd, "resource", "") or "(unknown resource)"
    reason = getattr(sd, "deny_reason", "") or getattr(sd, "deny_source", "")
    recommended = getattr(sd, "recommended_action", "easy-allow")
    suggested = getattr(sd, "suggested_allow_command", "")
    deny_event_id = getattr(sd, "deny_event_id", "")

    fields = [
        {"title": "Agent tried", "value": f"{action} on {resource}", "short": False},
        {"title": "Why caught", "value": reason or "(no reason supplied)", "short": False},
        {"title": "Classification", "value": cls, "short": True},
        {"title": "Recommended action", "value": recommended, "short": True},
    ]
    if suggested:
        fields.append({
            "title": "Suggested allow command",
            "value": f"`{suggested}`",
            "short": False,
        })
    if deny_event_id:
        fields.append({
            "title": "Deny event id",
            "value": deny_event_id,
            "short": False,
        })

    text = f"Your {bouncer} bouncer caught something."
    if cls == "appears_adversarial":
        text += " Recommended action: halt + escalate (do NOT auto-allow)."

    return {
        "text": text,
        "attachments": [
            {
                "color": color,
                "fallback": (
                    f"Your {bouncer} bouncer caught {action} on {resource}"
                ),
                "title": "iam-jit autopilot notification",
                "fields": fields,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Process-level start / stop / status entrypoints
# ---------------------------------------------------------------------------


def autopilot_start(
    *,
    config_path: pathlib.Path | None = None,
    cwd: pathlib.Path | None = None,
    detach: bool = False,
    notify_denies: str = "stderr",
    sweep_interval_s: float = _DEFAULT_SWEEP_INTERVAL_S,
    improve_interval_s: float = _DEFAULT_IMPROVE_INTERVAL_S,
    max_ticks: int | None = None,
) -> dict[str, Any]:
    """Start the autopilot daemon.

    When ``detach=True`` we ``subprocess.Popen`` a child running this
    same module (``python -m iam_jit.autopilot.daemon``) and return
    immediately. When False (default in tests), we run the supervisor
    loop in the calling process and return when ``max_ticks`` is hit
    or a TERM signal arrives.

    Raises :class:`AutopilotError` if an autopilot is already running
    (per [[ibounce-honest-positioning]]) or the declaration is invalid.
    """
    # Detect an existing autopilot.
    existing = _read_pid_file()
    if existing and _is_pid_alive(existing):
        raise AutopilotError(
            f"autopilot already running (pid={existing}); stop it first "
            f"with `iam-jit autopilot stop`.",
            code="already_running",
        )
    if existing and not _is_pid_alive(existing):
        # Stale — remove + continue.
        _remove_pid_file()

    # Load + validate the declaration.
    try:
        from ..ambient_config import load_declaration
    except Exception as e:  # pragma: no cover
        raise AutopilotError(
            f"could not import ambient_config: {e}",
            code="ambient_config_load_failed",
        ) from e

    try:
        declaration, source_label = load_declaration(
            config_path if config_path else None,
            cwd=cwd,
        )
    except Exception as e:
        raise AutopilotError(
            f"could not load declaration: {e}",
            code="declaration_load_failed",
        ) from e

    block = declaration.get("iam-jit") or {}
    if not block.get("enabled"):
        raise AutopilotError(
            "declaration has iam-jit.enabled=false; autopilot has "
            "nothing to do. Set enabled=true to opt in.",
            code="declaration_disabled",
        )

    if detach:
        # Spawn a child that re-invokes this command without --detach.
        return _spawn_detached(
            config_path=config_path,
            cwd=cwd,
            notify_denies=notify_denies,
            source_label=source_label,
        )

    # Foreground / in-process loop.
    supervisor = AutopilotSupervisor(
        declaration=declaration,
        config_source=source_label,
        sweep_interval_s=sweep_interval_s,
        improve_interval_s=improve_interval_s,
        notify_denies=notify_denies,
    )
    supervisor.initialize()
    _write_pid_file(os.getpid())
    try:
        supervisor.run_forever(max_ticks=max_ticks)
    finally:
        _remove_pid_file()
    final = supervisor.run_once()
    return {
        "status": "stopped",
        "pid": os.getpid(),
        "config_source": source_label,
        "ticks_at_exit": supervisor._improve_count,
        "final_status": final.as_dict(),
    }


def _spawn_detached(
    *,
    config_path: pathlib.Path | None,
    cwd: pathlib.Path | None,
    notify_denies: str,
    source_label: str,
) -> dict[str, Any]:
    """Spawn a detached child process that runs the supervisor loop."""
    cmd = [
        sys.executable,
        "-m",
        "iam_jit.autopilot.daemon",
        "--foreground",
    ]
    if config_path:
        cmd.extend(["--config", str(config_path)])
    if cwd:
        cmd.extend(["--cwd", str(cwd)])
    if notify_denies and notify_denies != "stderr":
        cmd.extend(["--notify-denies", notify_denies])
    try:
        proc = subprocess.Popen(  # noqa: S603 — non-shell, known args
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as e:
        raise AutopilotError(
            f"could not spawn detached autopilot: {e}",
            code="spawn_failed",
        ) from e
    # Give the child a beat to write its PID file.
    for _ in range(40):
        if _read_pid_file() == proc.pid:
            break
        time.sleep(0.05)
    return {
        "status": "started",
        "pid": proc.pid,
        "detached": True,
        "config_source": source_label,
    }


def autopilot_status() -> dict[str, Any]:
    """Return the current autopilot status (combines the PID + the
    last-written status file)."""
    pid = _read_pid_file()
    alive = bool(pid and _is_pid_alive(pid))
    status_blob = _read_status_file() or {}
    return {
        "running": alive,
        "pid": pid if alive else None,
        "status_file_present": _status_path().exists(),
        "status": status_blob,
        "pid_file": str(resolve_pid_path()),
    }


def autopilot_stop(
    *,
    timeout_s: float = 5.0,
) -> dict[str, Any]:
    """Signal the autopilot to shut down + wait for the PID file to
    clear. Returns a dict with ``status`` and ``previous_pid``.
    """
    pid = _read_pid_file()
    if not pid:
        return {"status": "not_running", "previous_pid": None}
    if not _is_pid_alive(pid):
        _remove_pid_file()
        return {"status": "stale_pid_cleaned", "previous_pid": pid}
    try:
        os.kill(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError) as e:
        return {"status": "kill_failed", "previous_pid": pid, "error": str(e)}
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not _is_pid_alive(pid):
            break
        time.sleep(0.1)
    if _is_pid_alive(pid):
        # Force.
        try:
            os.kill(pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    _remove_pid_file()
    return {
        "status": "stopped",
        "previous_pid": pid,
    }


# ---------------------------------------------------------------------------
# Click CLI registration
# ---------------------------------------------------------------------------


def register_autopilot_command(parent_group: click.Group) -> click.Group:
    """Attach the ``autopilot`` subgroup to the iam-jit CLI."""

    @parent_group.group("autopilot")
    def autopilot() -> None:
        """One-command background daemon (#403).

        Reads `.iam-jit.yaml` declaration, starts the bouncers,
        monitors them, runs improve cycles. Subcommands:

        \b
          start  — start the daemon (foreground unless --detach)
          status — current status
          stop   — shut down
        """

    @autopilot.command("start")
    @click.option(
        "--config",
        "config_path",
        type=click.Path(dir_okay=False, path_type=pathlib.Path),
        default=None,
        help="Explicit path to a .iam-jit.yaml; defaults to cwd auto-discovery.",
    )
    @click.option(
        "--cwd",
        type=click.Path(file_okay=False, dir_okay=True, path_type=pathlib.Path),
        default=None,
        help="Override cwd for auto-discovery.",
    )
    @click.option(
        "--detach",
        is_flag=True,
        default=False,
        help="Spawn a detached child + return immediately.",
    )
    @click.option(
        "--notify-denies",
        type=click.Choice(["stderr", "webhook", "none"]),
        default="stderr",
        help="Where to surface denies caught by bouncers.",
    )
    @click.option(
        "--max-ticks",
        type=int,
        default=None,
        help="Stop after N supervisor sweeps. Foreground / test mode.",
    )
    @click.option(
        "--sweep-interval",
        type=float,
        default=_DEFAULT_SWEEP_INTERVAL_S,
        help="Seconds between bouncer health-check sweeps.",
    )
    @click.option(
        "--improve-interval",
        type=float,
        default=_DEFAULT_IMPROVE_INTERVAL_S,
        help="Seconds between improve cycles when cadence=per_session.",
    )
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="JSON output.",
    )
    def autopilot_start_cmd(
        config_path: pathlib.Path | None,
        cwd: pathlib.Path | None,
        detach: bool,
        notify_denies: str,
        max_ticks: int | None,
        sweep_interval: float,
        improve_interval: float,
        as_json: bool,
    ) -> None:
        """Start the autopilot daemon."""
        try:
            result = autopilot_start(
                config_path=config_path,
                cwd=cwd,
                detach=detach,
                notify_denies=notify_denies,
                sweep_interval_s=sweep_interval,
                improve_interval_s=improve_interval,
                max_ticks=max_ticks,
            )
        except AutopilotError as e:
            payload = {
                "status": "error",
                "code": e.code,
                "message": str(e),
            }
            if as_json:
                click.echo(json.dumps(payload, indent=2))
            else:
                click.secho(
                    f"autopilot start refused: {e}",
                    fg="yellow",
                    err=True,
                )
            sys.exit(2)
        if as_json:
            click.echo(json.dumps(result, indent=2, default=str))
        else:
            kind = result.get("status", "ok")
            click.secho(
                f"Autopilot {kind} (pid={result.get('pid')})",
                fg="green",
            )

    @autopilot.command("status")
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="JSON output.",
    )
    def autopilot_status_cmd(as_json: bool) -> None:
        """Show autopilot status."""
        out = autopilot_status()
        if as_json:
            click.echo(json.dumps(out, indent=2, default=str))
            return
        if not out["running"]:
            click.secho("Autopilot is NOT running.", fg="yellow")
            return
        click.secho(
            f"Autopilot RUNNING (pid={out['pid']})",
            fg="green",
        )
        status = out.get("status") or {}
        improve = status.get("improve") or {}
        click.echo(
            f"  posture: {status.get('posture')}  "
            f"improve.cadence: {improve.get('cadence')}  "
            f"auto_install: {improve.get('auto_install')}  "
            f"threshold: {improve.get('threshold')}"
        )
        for name, b in (status.get("bouncers") or {}).items():
            status_str = "RUNNING" if b.get("running") else "DOWN"
            click.echo(
                f"  - {name}: {status_str}"
                + (
                    f" (alert: restart throttled)"
                    if b.get("alert_emitted")
                    else ""
                )
            )
        for alert in status.get("alerts") or []:
            click.secho(f"  ! {alert}", fg="yellow")

    @autopilot.command("stop")
    @click.option(
        "--timeout",
        type=float,
        default=5.0,
        help="Seconds to wait for graceful shutdown.",
    )
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="JSON output.",
    )
    def autopilot_stop_cmd(timeout: float, as_json: bool) -> None:
        """Stop the autopilot daemon."""
        out = autopilot_stop(timeout_s=timeout)
        if as_json:
            click.echo(json.dumps(out, indent=2, default=str))
            return
        status = out.get("status", "")
        if status == "stopped":
            click.secho(
                f"Autopilot stopped (was pid={out['previous_pid']})",
                fg="green",
            )
        elif status == "not_running":
            click.secho("Autopilot was not running.", fg="yellow")
        elif status == "stale_pid_cleaned":
            click.secho(
                f"Removed stale PID file (was pid={out['previous_pid']})",
                fg="yellow",
            )
        else:
            click.secho(f"autopilot stop: {status}", fg="yellow")
            if out.get("error"):
                click.secho(f"  error: {out['error']}", err=True)

    return autopilot


# ---------------------------------------------------------------------------
# Module entry — for `python -m iam_jit.autopilot.daemon --foreground`
# (used by the detached-spawn path)
# ---------------------------------------------------------------------------


def _main_entry() -> None:
    """Entry point invoked by the detached-spawn path."""
    import argparse

    parser = argparse.ArgumentParser(prog="iam_jit.autopilot.daemon")
    parser.add_argument("--foreground", action="store_true", default=False)
    parser.add_argument("--config", type=pathlib.Path, default=None)
    parser.add_argument("--cwd", type=pathlib.Path, default=None)
    parser.add_argument("--notify-denies", type=str, default="stderr")
    parser.add_argument("--sweep-interval", type=float, default=_DEFAULT_SWEEP_INTERVAL_S)
    parser.add_argument("--improve-interval", type=float, default=_DEFAULT_IMPROVE_INTERVAL_S)
    args = parser.parse_args()
    try:
        autopilot_start(
            config_path=args.config,
            cwd=args.cwd,
            detach=False,
            notify_denies=args.notify_denies,
            sweep_interval_s=args.sweep_interval,
            improve_interval_s=args.improve_interval,
        )
    except AutopilotError as e:
        sys.stderr.write(f"autopilot: {e}\n")
        sys.exit(2)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":  # pragma: no cover
    _main_entry()


__all__ = [
    "AutopilotError",
    "AutopilotStatus",
    "AutopilotSupervisor",
    "autopilot_start",
    "autopilot_status",
    "autopilot_stop",
    "register_autopilot_command",
    "resolve_pid_path",
]
