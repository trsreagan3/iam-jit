"""§A78 #470 + §A79 #471 — bouncer-side anomaly detection glue.

Bridges the anomaly detector to the existing bouncer plumbing:

  * A single :class:`AnomalyHook` lives in this module's process
    state. The bouncer's request path observes every request
    (mirrors the audit-export tap), scores it, and the hook decides
    whether to:
      - alert mode: let the request through + emit an OCSF
        ``anomaly_detected`` synthetic to the existing alerts surface
      - block mode: return a structured-deny payload + emit the
        same synthetic + bump the deny counter
  * Detection-only deployment (§A79 #471): the hook still scores +
    emits + does NOT need a profile loaded. The CLI ``bounce run
    --detection-only`` flag wires the bouncer up with this posture
    (no enforcement; only anomaly scoring).

Per ``[[scorer-is-ground-truth]]``: when the deterministic deny floor
already said DENY for this request, this hook is a NO-OP (we don't
double-count). When the floor said ALLOW + the anomaly hook fires
in block mode → the hook's deny shape WINS (it's strictly more
restrictive). When in alert mode + floor said ALLOW → we let through
+ alert.

Per ``[[ambient-value-prop-and-friction-framing]]`` alert-mode
emissions use the "your bouncer noticed something unusual" frame; we
NEVER emit "ANOMALY DETECTED" / "VIOLATION".
"""

from __future__ import annotations

import dataclasses
import logging
import threading
from typing import Any, Callable

from .baseline import BaselineStore
from .config import AnomalyDetectionConfig
from .detector import AnomalyResult, score_anomaly

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hook state
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class HookResult:
    """Per-request outcome from :func:`run_anomaly_hook`.

    Fields:
      * ``decision`` — ``"allow"`` (or floor's verdict pass-through)
        OR ``"block"`` (anomaly hook chose to deny).
      * ``anomaly_result`` — full :class:`AnomalyResult` (always
        populated when the hook ran; ``None`` if hook disabled).
      * ``emitted_alert`` — True when the OCSF anomaly synthetic was
        emitted (alert mode + verdict in {anomalous}).
      * ``operator_message`` — friendly framing for stderr / structured
        deny, per ``[[ambient-value-prop-and-friction-framing]]``.
      * ``mode`` — "alert" | "block" | "detection-only" | "disabled"
        — surfaced to callers so the structured-deny builder can
        annotate ``caught_by_bouncer`` correctly.
    """

    decision: str
    anomaly_result: AnomalyResult | None
    emitted_alert: bool
    operator_message: str
    mode: str


class _HookState:
    """Singleton container for the bouncer-side hook installation."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._config: AnomalyDetectionConfig | None = None
        self._store: BaselineStore | None = None
        self._alert_emitter: Callable[[dict[str, Any]], None] | None = None
        self._detection_only: bool = False

    def install(
        self,
        *,
        config: AnomalyDetectionConfig,
        store: BaselineStore,
        alert_emitter: Callable[[dict[str, Any]], None] | None = None,
        detection_only: bool = False,
    ) -> None:
        with self._lock:
            self._config = config
            self._store = store
            self._alert_emitter = alert_emitter
            self._detection_only = bool(detection_only)

    def uninstall(self) -> None:
        with self._lock:
            self._config = None
            self._store = None
            self._alert_emitter = None
            self._detection_only = False

    @property
    def config(self) -> AnomalyDetectionConfig | None:
        return self._config

    @property
    def store(self) -> BaselineStore | None:
        return self._store

    @property
    def alert_emitter(self) -> Callable[[dict[str, Any]], None] | None:
        return self._alert_emitter

    @property
    def detection_only(self) -> bool:
        return self._detection_only


_STATE = _HookState()


def install_anomaly_hook(
    *,
    config: AnomalyDetectionConfig,
    store: BaselineStore,
    alert_emitter: Callable[[dict[str, Any]], None] | None = None,
    detection_only: bool = False,
) -> None:
    """Install the hook. Call this once during bouncer bootstrap when
    ``iam-jit.anomaly_detection.enabled`` is True.

    ``alert_emitter`` is an optional callable that receives the OCSF
    ``anomaly_detected`` event dict; the bouncer wires this to the
    existing ``audit_export/alerts.py`` engine so SIEM forwarding is
    free. When ``None`` we log to the standard logger only (test
    helper)."""
    _STATE.install(
        config=config,
        store=store,
        alert_emitter=alert_emitter,
        detection_only=detection_only,
    )


def uninstall_anomaly_hook() -> None:
    """Remove the hook. Used by tests + the bouncer shutdown path."""
    _STATE.uninstall()


# ---------------------------------------------------------------------------
# Per-request entry point
# ---------------------------------------------------------------------------


def _build_ocsf_anomaly_event(
    *,
    bouncer: str,
    action: str,
    resource: str,
    agent_identity: str,
    anomaly: AnomalyResult,
    mode: str,
    detection_only: bool,
) -> dict[str, Any]:
    """Compose a minimal OCSF-shaped event. The bouncer's
    ``audit_export/alerts.py`` engine produces the canonical class-6003
    event in production; this helper exists so unit tests + the CLI
    smoke surface have a stable shape independent of the recorder.
    """
    return {
        "metadata": {"product": {"name": bouncer or "ibounce",
                                   "vendor_name": "iam-jit"}},
        "class_uid": 6003,
        "class_name": "API Activity",
        "activity_id": 99,
        "activity_name": "anomaly_detected",
        "severity_id": 4 if anomaly.verdict == "anomalous" else 2,
        "severity": "High" if anomaly.verdict == "anomalous" else "Low",
        "status_id": 99,
        "status": "Other",
        "actor": {"user": {"name": agent_identity or "anonymous"}},
        "api": {
            "operation": "anomaly_detected",
            "service": {"name": "iam_jit.anomaly_detection"},
        },
        "unmapped": {
            "iam_jit": {
                "event_type": "anomaly_detected",
                "anomaly": anomaly.to_dict(),
                "mode": mode,
                "detection_only": detection_only,
                "action": action,
                "resource": resource,
            }
        },
    }


def _friendly_summary(action: str, anomaly: AnomalyResult, mode: str) -> str:
    """Per ``[[ambient-value-prop-and-friction-framing]]``: lead with
    "your bouncer noticed something unusual" rather than "ANOMALY"."""
    contributing = [e.dimension for e in anomaly.explanations if e.contributing]
    if mode == "block":
        head = "Your bouncer blocked an unusual action"
    else:
        head = "Your bouncer noticed something unusual"
    parts = [
        f"{head}: {action}",
        f"  score: {anomaly.anomaly_score:.2f}",
        f"  baseline observations: {anomaly.baseline_observations}",
    ]
    if anomaly.cold_start_fallback_used:
        parts.append("  cold-start: classifier fallback fired (baseline too small)")
    if anomaly.threat_feed_severity:
        parts.append(f"  threat-feed match: severity={anomaly.threat_feed_severity}")
    if contributing:
        parts.append(f"  contributing dimensions: {', '.join(contributing)}")
    if anomaly.mitre_atlas_techniques:
        ids = [t["id"] for t in anomaly.mitre_atlas_techniques]
        parts.append(f"  MITRE: {', '.join(ids)}")
    return "\n".join(parts)


def run_anomaly_hook(
    *,
    action: str,
    agent_identity: str,
    resource: str | None = None,
    bouncer: str = "ibounce",
    observed_hour: int | None = None,
    threat_feed_entries: list[dict[str, Any]] | None = None,
    floor_decision: str = "allow",
    floor_deny_reason: str = "",
    record_observation: bool = True,
) -> HookResult:
    """Score one request through the installed hook + apply the
    operator-configured mode.

    ``floor_decision`` is the deterministic scorer's decision —
    "allow" / "deny". When the floor already denied this request we
    short-circuit (don't double-count); the structured-deny builder
    already surfaces the right reason.

    Returns a :class:`HookResult` even when the hook is disabled (so
    callers can splat the result into their decision pipeline without
    branching).
    """
    cfg = _STATE.config
    store = _STATE.store
    if cfg is None or store is None or not cfg.enabled:
        return HookResult(
            decision=floor_decision,
            anomaly_result=None,
            emitted_alert=False,
            operator_message="",
            mode="disabled",
        )

    mode = cfg.mode if not _STATE.detection_only else "alert"

    # Always observe (the baseline learns regardless of decision).
    if record_observation:
        try:
            store.observe(
                agent_identity=agent_identity,
                action=action,
                resource=resource,
            )
        except Exception as e:  # pragma: no cover
            logger.debug("anomaly observe failed: %s", e)

    # When the floor already denied, we don't run scoring — the deny
    # path owns the user-facing surface.
    if floor_decision == "deny" and not _STATE.detection_only:
        return HookResult(
            decision="deny",
            anomaly_result=None,
            emitted_alert=False,
            operator_message=floor_deny_reason or "deny floor fired",
            mode=mode,
        )

    summary = store.summary_for(agent_identity, action, resource)
    anomaly = score_anomaly(
        action=action,
        agent_identity=agent_identity,
        baseline_summary=summary,
        config=cfg,
        resource=resource,
        observed_hour=observed_hour,
        threat_feed_entries=threat_feed_entries,
    )

    if anomaly.verdict != "anomalous":
        return HookResult(
            decision=floor_decision,
            anomaly_result=anomaly,
            emitted_alert=False,
            operator_message="",
            mode=mode,
        )

    emitted = False
    if _STATE.alert_emitter is not None:
        try:
            _STATE.alert_emitter(
                _build_ocsf_anomaly_event(
                    bouncer=bouncer,
                    action=action,
                    resource=resource or "*",
                    agent_identity=agent_identity,
                    anomaly=anomaly,
                    mode=mode,
                    detection_only=_STATE.detection_only,
                ),
            )
            emitted = True
        except Exception as e:  # pragma: no cover
            logger.warning("anomaly alert emit failed: %s", e)

    friendly = _friendly_summary(action, anomaly, mode)
    decision = floor_decision
    if mode == "block" and not _STATE.detection_only:
        decision = "deny"
    return HookResult(
        decision=decision,
        anomaly_result=anomaly,
        emitted_alert=emitted,
        operator_message=friendly,
        mode=mode,
    )


__all__ = [
    "HookResult",
    "install_anomaly_hook",
    "run_anomaly_hook",
    "uninstall_anomaly_hook",
]
