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
    """One snapshot of autopilot's view of the world.

    Schema (v1.1) documented per #453 (§A49b) for the #412 weekly
    digest consumer + any external monitoring that subscribes to
    ``~/.iam-jit/autopilot.status.json``:

      * ``schema_version`` — "1.1" (incremented from 1.0 when #453
        added ``denies_recent_count`` + per-bouncer healthz fields).
      * ``running`` — autopilot daemon liveness.
      * ``pid`` — autopilot PID when running, else None.
      * ``started_at`` — ISO 8601 UTC start time.
      * ``config_source`` — path / source label of the loaded
        declaration.
      * ``posture`` — declaration's ``posture`` (``ambient`` |
        ``managed``).
      * ``bouncers`` — map of ``name`` → per-bouncer block:
          ``{name, running, config, restart_attempts_in_window,
            alert_emitted, pid?, port?, status?, restart_outcome?,
            healthz?: {decisions_count, mode, default_policy,
            active_profile, status, dynamic_denies, …}}``
        The ``healthz`` sub-block is populated when the bouncer's
        /healthz endpoint responds within the per-poll timeout
        (#453); the #412 weekly digest reads
        ``bouncers[name].healthz.decisions_count`` for activity
        counting.
      * ``improve`` — improve-cycle metadata:
          ``{enabled, cadence, auto_install, threshold,
            improve_count_since_startup, last_results}``
        ``last_results`` is the PRESERVED result list from the most
        recent improve cycle (#453 fix: previously this cleared to
        ``[]`` on every sweep tick where improve didn't run).
      * ``denies_recent_count`` — top-level aggregate count of denies
        observed across all bouncers in the last 5 minutes (#453
        required for #412 weekly digest consumption). 0 when the
        fetcher couldn't reach the bouncers OR when no denies fired.
      * ``alerts`` — supervisor-emitted alerts (restart throttles,
        binary-missing, managed-posture-refused, etc.).
      * ``last_improve_at`` — ISO 8601 UTC of last improve cycle, or
        None if no cycle has run.
      * ``last_sweep_at`` — ISO 8601 UTC of last sweep tick.
      * ``notes`` — tuning constants for the operator's reference.
    """

    schema_version: str = "1.1"
    running: bool = False
    pid: int | None = None
    started_at: str | None = None
    config_source: str = ""
    posture: str = "ambient"
    bouncers: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
    improve: dict[str, Any] = dataclasses.field(default_factory=dict)
    # #411 / §A55 — threat-feed tick block. Mirrors the shape of
    # ``improve`` so a future schema 1.2 bump unifies the wire shape
    # but DOES NOT REQUIRE one — the field defaults to empty so older
    # readers ignore it gracefully.
    threat_feed: dict[str, Any] = dataclasses.field(default_factory=dict)
    denies_recent_count: int = 0
    alerts: list[str] = dataclasses.field(default_factory=list)
    last_improve_at: str | None = None
    last_sweep_at: str | None = None
    notes: list[str] = dataclasses.field(default_factory=list)
    # §A93 / #509 Phase 2 — LLM-skip surface per
    # [[bouncer-zero-llm-when-agent-in-loop]]. ``side_llm_enabled``
    # reflects whether the operator opted into bouncer-side LLM via
    # ``--enable-side-llm``; ``llm_skips`` is the cross-feature counter
    # snapshot (also exposed via /healthz on each bouncer + iam-jit
    # posture). Default empty so older readers ignore gracefully.
    side_llm_enabled: bool = False
    llm_skips: dict[str, Any] = dataclasses.field(default_factory=dict)

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


def _skip_counter_snapshot_safe() -> dict[str, Any]:
    """Wrap :func:`iam_jit.llm.report_skip.skip_counter_snapshot` with
    a best-effort guard so a missing helper doesn't poison the status
    JSON. Returns an empty-but-typed dict on failure (matches the
    schema older readers expect)."""
    try:
        from ..llm.report_skip import skip_counter_snapshot
        return skip_counter_snapshot()
    except Exception:  # pragma: no cover
        return {"total": 0, "counts": {}, "by_reason": {}, "last_skips": []}


def _validate_side_llm_creds_or_raise() -> None:
    """§A93 / #509 Phase 2 — fail loudly at autopilot-start when the
    operator opted in to bouncer-side LLM via ``--enable-side-llm``
    but didn't configure a backend.

    Detection rules (matches the pluggable backend selector in
    :mod:`iam_jit.llm.registry`):

      * IAM_JIT_LLM in (anthropic, openai, bedrock, ollama)
      * Per-provider credential expected:
          - anthropic → ANTHROPIC_API_KEY
          - openai → OPENAI_API_KEY
          - bedrock → IAM_JIT_BEDROCK_MODEL  (boto3 picks up creds)
          - ollama → OLLAMA_HOST OR localhost default
        Missing → raise :class:`AutopilotError`.
      * If IAM_JIT_LLM is unset → raise (same shape).

    Per [[ibounce-honest-positioning]] this is the loud-failure
    pattern: operator's explicit opt-in deserves a clear error rather
    than a quiet downgrade to deterministic-only."""
    backend = (os.environ.get("IAM_JIT_LLM") or "").strip().lower()
    if not backend:
        raise AutopilotError(
            "--enable-side-llm requires IAM_JIT_LLM=anthropic|openai|"
            "bedrock|ollama to be set. Local-dev / agent-in-loop "
            "shouldn't set --enable-side-llm at all — the agent's "
            "LLM handles the improve cycle via the "
            "iam_jit_improve_profile MCP tool.",
            code="side_llm_no_backend",
        )
    creds = {
        "anthropic": ("ANTHROPIC_API_KEY", "Anthropic API key"),
        "openai": ("OPENAI_API_KEY", "OpenAI API key"),
        "bedrock": ("IAM_JIT_BEDROCK_MODEL", "AWS Bedrock model id"),
        "ollama": ("OLLAMA_HOST", "Ollama host"),
    }
    if backend not in creds:
        raise AutopilotError(
            f"--enable-side-llm: IAM_JIT_LLM={backend!r} is not one of "
            f"the supported backends "
            f"({', '.join(sorted(creds))}).",
            code="side_llm_unknown_backend",
        )
    env_name, label = creds[backend]
    if backend == "ollama":
        # Ollama defaults to localhost:11434 if OLLAMA_HOST is unset;
        # don't fail-fast on that. Same convention as
        # iam_jit.llm._core.OllamaBackend.
        return
    if not (os.environ.get(env_name) or "").strip():
        raise AutopilotError(
            f"--enable-side-llm: IAM_JIT_LLM={backend!r} requires "
            f"{env_name} ({label}) to be set. Either set it or "
            f"remove --enable-side-llm.",
            code="side_llm_missing_credential",
        )


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
    # §A93 / #509 Phase 2 — opt-in to the synchronous bouncer-side LLM
    # for improve cycles. Default OFF per
    # [[bouncer-zero-llm-when-agent-in-loop]]: local-dev / agent-in-loop
    # autopilot runs the improve cycle in deterministic-only mode
    # (event-derived allows + safety-floor denies) and lets the agent
    # call iam_jit_improve_profile via MCP for LLM-augmented
    # suggestions using ITS OWN LLM. When True, the supervisor reads
    # IAM_JIT_LLM=anthropic|openai|bedrock|ollama + creds and runs the
    # generator with the configured backend.
    side_llm_enabled: bool = False
    # #412 / §A56 — weekly digest webhook delivery. ``False`` skips
    # entirely. ``True`` opts in; the URL itself is read from
    # ``IAM_JIT_AUTOPILOT_DIGEST_WEBHOOK_URL`` per the deny-webhook
    # security model (webhooks carry secrets, never accept via CLI flag
    # arg per [[push-policy-public-repo]]).
    digest_webhook_enabled: bool = False
    digest_interval_s: float = 7 * 86400.0  # weekly
    bouncer_states: dict[str, _BouncerSupervisorState] = dataclasses.field(
        default_factory=dict
    )
    started_at: float = dataclasses.field(default_factory=time.time)
    last_improve_at: float = 0.0
    last_sweep_at: float = 0.0
    last_digest_at: float = 0.0
    # #411 / §A55 — threat-feed fetch+apply cadence. Anchored off
    # supervisor start so a restart doesn't immediately re-fetch.
    last_threat_feed_at: float = 0.0
    threat_feed_interval_s: float = 86400.0  # default daily
    _last_threat_feed_results: list[dict[str, Any]] = dataclasses.field(
        default_factory=list
    )
    stopped: bool = False
    alerts: list[str] = dataclasses.field(default_factory=list)
    _improve_count: int = 0
    # #453 (§A49b) — preserve the last improve cycle's results across
    # ticks so the operator (+ #412 weekly digest) can read what
    # changed even when the most recent sweep tick didn't run improve.
    _last_improve_results: list[dict[str, Any]] = dataclasses.field(
        default_factory=list
    )

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
        list of result dicts (one per bouncer).

        §A93 / #509 Phase 2 — when ``side_llm_enabled=False`` (the
        local-dev / agent-in-loop default per
        [[bouncer-zero-llm-when-agent-in-loop]]), each cycle emits a
        structured ``report_skip`` (once per supervisor session) so
        operators can see autopilot is running in deterministic-only
        mode. The deterministic event-derived rules still install;
        the agent can call ``iam_jit_improve_profile`` via MCP to
        contribute LLM-augmented suggestions using its OWN LLM."""
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
        # §A93 / #509 Phase 2 — when side-LLM is NOT opted in, emit
        # report_skip once per cycle so operators see the deferral.
        # The generator pipeline ALSO falls back to deterministic
        # event-derived rules when no backend is reachable; we surface
        # the deferral up-front so the deferral is visible in posture +
        # /healthz even when the cycle ends up "no_change".
        if not self.side_llm_enabled:
            try:
                from ..llm.report_skip import (
                    REASON_NO_SIDE_LLM_ENABLED,
                    report_skip,
                )
                report_skip(
                    feature="autopilot.improve_cycle",
                    reason=REASON_NO_SIDE_LLM_ENABLED,
                    mode_hint=(
                        "Local-dev / agent-in-loop default: autopilot "
                        "runs improve in deterministic-only mode. Your "
                        "agent can call iam_jit_improve_profile via MCP "
                        "to contribute LLM-augmented suggestions using "
                        "its own LLM. To run the synchronous bouncer-"
                        "side generator (standalone / CI deployments), "
                        "restart with --enable-side-llm + IAM_JIT_LLM="
                        "anthropic|openai|bedrock|ollama with credentials."
                    ),
                )
            except Exception:  # pragma: no cover
                pass
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
                # MRR-2 F5 (HIGH from
                # docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md): the
                # alert previously was the ONLY visible signal of
                # an improve-cycle blow-up — operators had to poll
                # /healthz autopilot.alerts to notice. The alert
                # stays for back-compat (existing monitors read
                # it), but we ALSO emit a structured
                # degraded_capability event so /healthz top-level
                # ``degraded_capabilities`` + ``iam-jit posture``
                # surface the failure with a stable
                # ``feature=autopilot.improve_cycle`` key the agent
                # can pattern-match on.
                from ..degraded_capability import (
                    REASON_CYCLE_RAISED,
                    emit as _deg_emit,
                )
                _deg_emit(
                    feature="autopilot.improve_cycle",
                    reason=REASON_CYCLE_RAISED,
                    hint=(
                        f"bouncer={name}: this cycle's improvements "
                        "were lost; the next scheduled cycle will "
                        "retry. Inspect autopilot.status.json + "
                        "server log for the traceback."
                    ),
                    extra={
                        "degraded_bouncer": name,
                        "degraded_exc_type": type(e).__name__,
                    },
                )
                self.alerts.append(
                    f"improve cycle for {name} raised: {e}"
                )
        self.last_improve_at = time.time()
        self._improve_count += 1
        # #453 (§A49b) — preserve so subsequent status writes between
        # cycles still surface the last cycle's outcomes; #412 weekly
        # digest reads this directly.
        self._last_improve_results = list(results)
        return results

    # ------------------------------------------------------------------
    # #411 / §A55 — threat-feed fetch + apply tick
    # ------------------------------------------------------------------

    def _threat_feed_config(self) -> dict[str, Any]:
        """Return the declarative `threat_feed` block (or empty dict)."""
        return self._block().get("threat_feed") or {}

    def _threat_feed_subscriptions(self) -> list[Any]:
        """Resolve subscriptions from the declaration. Returns ``[]``
        on any config error (the alert is emitted from the apply path
        so the operator sees it loudly, not silently — per
        [[ibounce-honest-positioning]])."""
        try:
            from ..threat_feed import load_subscriptions_from_declaration

            subs, _block = load_subscriptions_from_declaration(self.declaration)
            return list(subs)
        except Exception as e:
            # MRR-2 F5 (HIGH from
            # docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md): the
            # previous ``logger.debug`` was invisible to default log
            # config — the operator's threat-feed went silently
            # inactive after a declaration typo / module move. Emit
            # a structured degraded_capability event so /healthz +
            # posture surface it.
            from ..degraded_capability import (
                REASON_SUB_LOAD_FAILED,
                emit as _deg_emit,
            )
            _deg_emit(
                feature="autopilot.threat_feed_sub_load",
                reason=REASON_SUB_LOAD_FAILED,
                hint=(
                    "threat-feed subscriptions failed to load — "
                    "threat-feed updates will NOT apply this tick. "
                    "Check the ``threat_feed:`` block in your "
                    "declaration for syntax / module-path errors."
                ),
                extra={"degraded_exc_type": type(e).__name__},
            )
            logger.debug("threat-feed sub load failed: %s", e)
            return []

    def _cadence_to_seconds(self, cadence: str) -> float:
        return {
            "per_session": self.improve_interval_s,
            "hourly": 3600.0,
            "daily": 86400.0,
            "weekly": 604800.0,
            "on_demand": float("inf"),
        }.get(cadence, 86400.0)

    def _threat_feed_due(self) -> bool:
        """Return True iff it's time to fetch + apply pinned feeds."""
        block = self._threat_feed_config()
        if not block or not block.get("enabled"):
            return False
        if not self._threat_feed_subscriptions():
            return False
        cadence = str(block.get("update_cadence") or "daily")
        interval = self._cadence_to_seconds(cadence)
        self.threat_feed_interval_s = interval
        if self.last_threat_feed_at <= 0.0:
            # First tick: defer until cadence elapses past supervisor
            # start, so a daemon restart doesn't re-fetch every feed
            # immediately.
            return (time.time() - self.started_at) >= interval
        return (time.time() - self.last_threat_feed_at) >= interval

    def run_threat_feed_for_all(self) -> list[dict[str, Any]]:
        """Fetch + verify + apply every pinned feed once. Returns one
        per-feed result dict (always — even when fetch fails — so the
        status surfaces the failure)."""
        from ..threat_feed import (
            SubscriptionConfigError,
            apply_feed_entries,
            fetch_feed,
        )
        from ..threat_feed import (
            load_subscriptions_from_declaration as _load_subs,
        )

        try:
            subs, _block = _load_subs(self.declaration)
        except SubscriptionConfigError as e:
            msg = f"threat_feed config invalid: {e}"
            self.alerts.append(msg)
            sys.stderr.write(f"[autopilot] {msg}\n")
            self.last_threat_feed_at = time.time()
            return []

        results: list[dict[str, Any]] = []
        for sub in subs:
            if not sub.enabled:
                results.append({
                    "url": sub.url,
                    "label": sub.label(),
                    "status": "paused",
                    "applied": 0,
                    "refused": 0,
                    "pending": 0,
                    "informational": 0,
                    "managed_refused": 0,
                })
                continue
            try:
                fetch = fetch_feed(sub.url)
            except Exception as e:
                msg = (
                    f"threat-feed fetch raised for {sub.label()}: {e}"
                )
                self.alerts.append(msg)
                results.append({
                    "url": sub.url,
                    "label": sub.label(),
                    "status": "fetch_error",
                    "error": str(e),
                })
                continue
            if fetch.feed is None:
                msg = (
                    f"threat-feed unavailable for {sub.label()}: "
                    f"{fetch.error}"
                )
                self.alerts.append(msg)
                results.append({
                    "url": sub.url,
                    "label": sub.label(),
                    "status": "unavailable",
                    "error": fetch.error,
                    "http_status": fetch.http_status,
                })
                continue

            outcomes = apply_feed_entries(
                fetch.feed,
                sub,
                posture=self.posture,
            )
            counts: dict[str, int] = {
                "applied": 0,
                "refused": 0,
                "pending": 0,
                "informational": 0,
                "managed_refused": 0,
                "already_applied": 0,
            }
            for o in outcomes:
                if o.action in ("auto_apply", "auto_apply_notify"):
                    counts["applied"] += 1
                elif o.action == "refused_verification":
                    counts["refused"] += 1
                elif o.action == "pending_approval":
                    counts["pending"] += 1
                elif o.action == "informational":
                    counts["informational"] += 1
                elif o.action == "managed_refused":
                    counts["managed_refused"] += 1
                elif o.action == "refused_already_applied":
                    counts["already_applied"] += 1
            results.append({
                "url": sub.url,
                "label": sub.label(),
                "status": "ok" if not fetch.cached else "ok_cached",
                "cached": fetch.cached,
                "http_status": fetch.http_status,
                "manifest_sha256": fetch.manifest_sha256,
                "feed_id": fetch.feed.feed_id,
                "publisher": fetch.feed.publisher,
                "entry_count": len(fetch.feed.entries),
                **counts,
            })

        self.last_threat_feed_at = time.time()
        self._last_threat_feed_results = list(results)
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
                # #453 (§A49b) — pull /healthz on each tick to surface
                # per-bouncer decisions_count + active-profile + mode.
                # Best-effort: a slow / unreachable healthz must NOT
                # stall the supervisor loop.
                healthz = _poll_bouncer_healthz(
                    name, block.get("port") or 0,
                )
                if healthz is not None:
                    entry["healthz"] = healthz
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

        # Improve cycle (independent cadence from sweep). Per #453
        # (§A49b) fix: when the current tick didn't run improve, we
        # PRESERVE the most recent cycle's results so the status
        # JSON's ``improve.last_results`` doesn't flap empty between
        # cycles — the #412 weekly digest relies on this field being
        # populated whenever improve has run at least once.
        if self._improve_due():
            improve_results = self.run_improve_for_all()
        else:
            improve_results = list(self._last_improve_results)

        # #411 / §A55 — threat-feed fetch + apply tick. Independent
        # cadence from improve; same posture-gate (managed posture
        # REFUSES auto-apply). Failures (network, malformed feeds)
        # surface as alerts; the local cache backs the next attempt
        # so a transient outage doesn't drop protection.
        if self._threat_feed_due():
            try:
                threat_feed_results = self.run_threat_feed_for_all()
            except Exception as e:
                self.alerts.append(f"threat-feed tick raised: {e}")
                threat_feed_results = list(self._last_threat_feed_results)
        else:
            threat_feed_results = list(self._last_threat_feed_results)

        # #453 (§A49b) — aggregate top-level denies_recent_count for
        # the #412 weekly digest consumer. fetch_recent_denies fans
        # out to every bouncer's /audit/events; failures degrade to
        # zero (per [[ibounce-honest-positioning]] we don't fabricate
        # counts when the channel is broken).
        denies_recent_count = _count_recent_denies()

        # Deny notification surface — per the brief, this is a
        # placeholder hook for #389 (full notification daemon ships
        # separately). For now, when notify_denies != "none" we tail
        # the existing /denies surface and write to stderr.
        if self.notify_denies != "none":
            try:
                self._notify_recent_denies()
            except Exception as e:  # pragma: no cover
                logger.debug("autopilot deny notify failed: %s", e)

        # #412 / §A56 — weekly digest webhook delivery (opt-in via
        # --digest-webhook flag + IAM_JIT_AUTOPILOT_DIGEST_WEBHOOK_URL
        # env var). Cadence is weekly; the first delivery fires after
        # ``digest_interval_s`` since supervisor start so an operator
        # restarting the daemon doesn't spam their channel.
        if self.digest_webhook_enabled:
            try:
                self._maybe_deliver_digest_webhook()
            except Exception as e:  # pragma: no cover
                logger.debug("autopilot digest webhook failed: %s", e)

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
            threat_feed={
                "enabled": bool(self._threat_feed_config().get("enabled")),
                "subscription_count": len(self._threat_feed_subscriptions()),
                "cadence": str(
                    self._threat_feed_config().get("update_cadence")
                    or "daily"
                ),
                "last_run_at": (
                    _dt.datetime.fromtimestamp(
                        self.last_threat_feed_at, tz=_dt.timezone.utc
                    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                    if self.last_threat_feed_at
                    else None
                ),
                "last_results": threat_feed_results,
            },
            denies_recent_count=denies_recent_count,
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
            side_llm_enabled=bool(self.side_llm_enabled),
            llm_skips=_skip_counter_snapshot_safe(),
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

    def _maybe_deliver_digest_webhook(self) -> None:
        """Deliver a weekly digest card to the webhook URL if it's due.

        Cadence: every ``digest_interval_s`` (default 7 days). First
        delivery fires after the interval since supervisor start
        (NOT on first tick — that would spam an operator restarting the
        daemon).

        URL source: ``IAM_JIT_AUTOPILOT_DIGEST_WEBHOOK_URL`` env var only.
        Per [[push-policy-public-repo]] webhook URLs frequently embed
        secrets so we don't take them as a CLI arg.

        Failures degrade silently per [[ibounce-honest-positioning]] —
        the operator can always run ``iam-jit digest`` interactively.
        """
        now = time.time()
        # Anchor first delivery off supervisor start so a restart doesn't
        # immediately re-fire. If last_digest_at is 0 we treat the
        # interval boundary as ``started_at + digest_interval_s``.
        if self.last_digest_at <= 0.0:
            if (now - self.started_at) < self.digest_interval_s:
                return
        elif (now - self.last_digest_at) < self.digest_interval_s:
            return

        webhook_url = os.environ.get(
            "IAM_JIT_AUTOPILOT_DIGEST_WEBHOOK_URL", "",
        ).strip()
        if not webhook_url:
            logger.debug(
                "autopilot digest webhook skipped: "
                "IAM_JIT_AUTOPILOT_DIGEST_WEBHOOK_URL unset"
            )
            # Mark anyway so we don't re-check on every tick — operator
            # who sets the var later starts the clock from then.
            self.last_digest_at = now
            return
        try:
            from ..digest import build_digest
            from ..digest.render import build_webhook_payload
        except Exception as e:  # pragma: no cover
            logger.debug("autopilot digest import failed: %s", e)
            return
        try:
            # Per [[ibounce-honest-positioning]] §A56c (#462) the scheduled
            # autopilot digest must honor IAM_JIT_AUDIT_EVENTS_TOKEN — a
            # deployment that locks down /audit/events with a bearer token
            # would otherwise see "0 denies" forever in its weekly webhook.
            _ev_tok = (os.environ.get("IAM_JIT_AUDIT_EVENTS_TOKEN") or "").strip()
            data = build_digest(
                since="1w",
                audit_events_token=_ev_tok or None,
            )
            payload = build_webhook_payload(data)
        except Exception as e:
            logger.debug("autopilot digest build failed: %s", e)
            return
        try:
            import urllib.request
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                resp.read()
        except Exception as e:
            logger.debug("autopilot digest webhook post failed: %s", e)
            return
        self.last_digest_at = now

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
    digest_webhook: bool = False,
    digest_interval_s: float = 7 * 86400.0,
    max_ticks: int | None = None,
    enable_side_llm: bool = False,
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

    # §A93 / #509 Phase 2 — fail loudly when opt-in flag is set but
    # the operator forgot to configure a backend. The opposite of
    # silent-degradation: if you ASKED for bouncer-side LLM, you
    # deserve a clear error rather than a daemon that quietly runs
    # deterministic-only despite your flag.
    if enable_side_llm:
        _validate_side_llm_creds_or_raise()

    if detach:
        # Spawn a child that re-invokes this command without --detach.
        return _spawn_detached(
            config_path=config_path,
            cwd=cwd,
            notify_denies=notify_denies,
            source_label=source_label,
            digest_webhook=digest_webhook,
            enable_side_llm=enable_side_llm,
        )

    # Foreground / in-process loop.
    supervisor = AutopilotSupervisor(
        declaration=declaration,
        config_source=source_label,
        sweep_interval_s=sweep_interval_s,
        improve_interval_s=improve_interval_s,
        notify_denies=notify_denies,
        digest_webhook_enabled=digest_webhook,
        digest_interval_s=digest_interval_s,
        side_llm_enabled=enable_side_llm,
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
    digest_webhook: bool = False,
    enable_side_llm: bool = False,
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
    if digest_webhook:
        cmd.append("--digest-webhook")
    if enable_side_llm:
        cmd.append("--enable-side-llm")
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
        "--digest-webhook",
        is_flag=True,
        default=False,
        help="Opt in to weekly digest webhook delivery. URL is read "
             "from IAM_JIT_AUTOPILOT_DIGEST_WEBHOOK_URL env var per "
             "webhook-secret hygiene; cadence is 7 days from supervisor "
             "start.",
    )
    @click.option(
        "--enable-side-llm",
        is_flag=True,
        default=False,
        help="§A93 / #509 Phase 2 — opt in to the synchronous "
             "bouncer-side LLM for the improve cycle. Default OFF per "
             "[[bouncer-zero-llm-when-agent-in-loop]] — local-dev / "
             "agent-in-loop deployments leave this unset and let the "
             "agent call iam_jit_improve_profile via MCP with its OWN "
             "LLM (Claude Max / ChatGPT / etc.). Only set this for "
             "standalone / CI / cron deployments where no agent is in "
             "the loop. Requires IAM_JIT_LLM=anthropic|openai|bedrock|"
             "ollama + the corresponding credential; autopilot REFUSES "
             "TO START if set without a usable backend.",
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
        digest_webhook: bool,
        enable_side_llm: bool,
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
                digest_webhook=digest_webhook,
                max_ticks=max_ticks,
                enable_side_llm=enable_side_llm,
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
    parser.add_argument("--digest-webhook", action="store_true", default=False)
    parser.add_argument("--enable-side-llm", action="store_true", default=False)
    args = parser.parse_args()
    try:
        autopilot_start(
            config_path=args.config,
            cwd=args.cwd,
            detach=False,
            notify_denies=args.notify_denies,
            sweep_interval_s=args.sweep_interval,
            improve_interval_s=args.improve_interval,
            digest_webhook=args.digest_webhook,
            enable_side_llm=args.enable_side_llm,
        )
    except AutopilotError as e:
        sys.stderr.write(f"autopilot: {e}\n")
        sys.exit(2)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# #453 (§A49b) — per-bouncer /healthz polling + cross-bouncer denies count
# ---------------------------------------------------------------------------


_HEALTHZ_TIMEOUT_S = 2.0
"""Per-bouncer /healthz HTTP timeout. Short — supervisor must NOT
stall on a slow bouncer. Failures degrade to ``None`` (no healthz block
in the status entry)."""


# Project the subset of /healthz the autopilot status JSON needs.
# Keeping this list small means the status file stays small + stable
# for the #412 weekly digest consumer; the bouncer's /healthz can add
# new fields without breaking the digest.
_HEALTHZ_PROJECTED_FIELDS = (
    "bouncer_kind",
    "status",
    "mode",
    "default_policy",
    "active_profile",
    "decisions_count",
)


def _poll_bouncer_healthz(name: str, port: int) -> dict[str, Any] | None:
    """Best-effort GET ``http://127.0.0.1:<port>/healthz``.

    Returns the projected sub-dict on 2xx; ``None`` on any failure
    (timeout, refused, non-2xx, parse error, port=0). Never raises —
    per [[ibounce-honest-positioning]] we don't fabricate metrics when
    the channel is broken; the absent ``healthz`` key tells the
    consumer "couldn't reach the bouncer this tick.\""""
    if not port:
        return None
    url = f"http://127.0.0.1:{int(port)}/healthz"
    try:
        import urllib.request
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=_HEALTHZ_TIMEOUT_S) as resp:
            if resp.status < 200 or resp.status >= 300:
                return None
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        logger.debug("autopilot healthz poll failed for %s: %s", name, e)
        return None
    try:
        body = json.loads(raw)
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    out: dict[str, Any] = {
        k: body[k] for k in _HEALTHZ_PROJECTED_FIELDS if k in body
    }
    # The dynamic_denies sub-block has its own stable schema; carry it
    # whole so the #412 digest can surface "rules_count went up by N".
    dd = body.get("dynamic_denies")
    if isinstance(dd, dict):
        out["dynamic_denies"] = dd
    return out


def _count_recent_denies() -> int:
    """Return the count of deny rows observed across all default
    bouncers in the last 5 minutes. Returns ``0`` on any error.

    Per [[ibounce-honest-positioning]] we degrade silently on
    failures — a fetcher error is NOT a deny event; surfacing it as
    one would mislead the #412 weekly digest consumer.
    """
    try:
        from ..profile_allow.denies import fetch_recent_denies
    except Exception:
        return 0
    try:
        rows, _notes = fetch_recent_denies(since="5m", limit=200)
    except Exception as e:
        logger.debug("autopilot denies-count fetch failed: %s", e)
        return 0
    return len(rows)


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
