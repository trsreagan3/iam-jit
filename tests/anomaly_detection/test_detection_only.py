"""§A79 #471 — detection-only deployment shape tests.

The detection-only shape is: bouncer runs with NO profile (or an
observation profile) + anomaly_detection enabled. All requests pass
through (no enforcement) + anomalies still get detected + emitted.

This deployment shape is what observation-only / SIEM-feed shops use
to evaluate iam-jit without committing to enforcement.
"""

from __future__ import annotations

import pathlib
from typing import Any, Iterator

import pytest

from iam_jit.anomaly_detection import (
    AnomalyDetectionConfig,
    BaselineStore,
    install_anomaly_hook,
    run_anomaly_hook,
    uninstall_anomaly_hook,
)


@pytest.fixture
def baseline(tmp_path: pathlib.Path) -> Iterator[BaselineStore]:
    s = BaselineStore(
        path=str(tmp_path / "do.db"),
        flush_interval_seconds=0.05,
    )
    s.start()
    yield s
    s.stop()


@pytest.fixture(autouse=True)
def _clean() -> Iterator[None]:
    uninstall_anomaly_hook()
    yield
    uninstall_anomaly_hook()


def test_detection_only_no_profile_enforcement_anomaly_still_detected(
    baseline: BaselineStore,
) -> None:
    """detection-only: even with mode='block' in config, requests pass
    through; only the alert is emitted. Matches the §A79 spec.
    """
    emitted: list[dict[str, Any]] = []
    # Config DECLARES block mode, but detection_only=True forces alert.
    cfg = AnomalyDetectionConfig(
        enabled=True, mode="block", sensitivity="medium",
        cold_start_fallback=True, min_actions_for_baseline=50,
    )
    install_anomaly_hook(
        config=cfg, store=baseline, alert_emitter=emitted.append,
        detection_only=True,
    )
    result = run_anomaly_hook(
        action="iam:CreateAccessKey",
        agent_identity="agent-a", resource="x",
        floor_decision="allow",
    )
    # MUST pass through — detection-only never denies.
    assert result.decision == "allow"
    # Mode reported as alert because detection-only overrides block.
    assert result.mode == "alert"
    # Anomaly still detected + emitted.
    assert result.anomaly_result is not None
    assert result.anomaly_result.verdict == "anomalous"
    assert result.emitted_alert is True
    assert len(emitted) == 1
    # OCSF event records the detection-only flag.
    assert emitted[0]["unmapped"]["iam_jit"]["detection_only"] is True


def test_detection_only_normal_requests_pass_silently(
    baseline: BaselineStore,
) -> None:
    """Normal (non-anomalous) requests don't emit anything in
    detection-only — the alert surface stays clean."""
    emitted: list[dict[str, Any]] = []
    # Seed a baseline so scoring is meaningful
    for _ in range(60):
        baseline.observe(
            agent_identity="agent-a", action="s3:GetObject",
            resource="arn:aws:s3:::data",
        )
    cfg = AnomalyDetectionConfig(
        enabled=True, mode="alert", min_actions_for_baseline=50,
    )
    install_anomaly_hook(
        config=cfg, store=baseline, alert_emitter=emitted.append,
        detection_only=True,
    )
    result = run_anomaly_hook(
        action="s3:GetObject", agent_identity="agent-a",
        resource="arn:aws:s3:::data", floor_decision="allow",
    )
    assert result.decision == "allow"
    assert result.emitted_alert is False
    assert emitted == []
    # But the anomaly_result IS populated — the operator can inspect
    # the score for normal traffic too.
    assert result.anomaly_result is not None
    assert result.anomaly_result.verdict in ("normal", "insufficient_data")


def test_detection_only_composes_with_audit_export_presets(
    baseline: BaselineStore, tmp_path: pathlib.Path,
) -> None:
    """The OCSF anomaly event the hook emits has the same shape the
    audit-export presets (#257) consume — confirm the unmapped.iam_jit
    block carries the required fields.
    """
    emitted: list[dict[str, Any]] = []
    cfg = AnomalyDetectionConfig(
        enabled=True, mode="alert", cold_start_fallback=True,
    )
    install_anomaly_hook(
        config=cfg, store=baseline, alert_emitter=emitted.append,
        detection_only=True,
    )
    run_anomaly_hook(
        action="iam:CreateAccessKey", agent_identity="agent-a",
        resource="x", floor_decision="allow",
    )
    assert len(emitted) == 1
    evt = emitted[0]
    # OCSF top-level fields the audit-export presets pivot on
    for k in (
        "class_uid", "class_name", "activity_id", "activity_name",
        "severity_id", "status_id", "actor", "api", "metadata",
    ):
        assert k in evt, f"missing OCSF field {k!r}"
    # iam-jit unmapped block
    ij = evt["unmapped"]["iam_jit"]
    for k in ("event_type", "anomaly", "mode", "detection_only", "action"):
        assert k in ij, f"missing unmapped.iam_jit.{k!r}"
    # The full anomaly payload (F.1 explanations + F.5 MITRE) survives.
    anomaly = ij["anomaly"]
    assert "explanations" in anomaly
    assert "mitre_atlas_techniques" in anomaly
    assert "cold_start_fallback_used" in anomaly


def test_detection_only_no_observation_blocks_request_path() -> None:
    """Smoke: even with no baseline-write side effects, the
    detection-only path returns a HookResult cleanly."""
    cfg = AnomalyDetectionConfig(enabled=True, cold_start_fallback=True)
    # Use an in-memory baseline so there's nothing to write to.
    bs = BaselineStore(path=":memory:")
    bs.start()
    install_anomaly_hook(config=cfg, store=bs, detection_only=True)
    try:
        result = run_anomaly_hook(
            action="s3:GetObject", agent_identity="a",
            resource="x", floor_decision="allow",
            record_observation=False,
        )
        assert result.decision == "allow"
    finally:
        bs.stop()
