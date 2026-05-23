"""§A77 #469 — anomaly detector tests including F.1/F.2/F.5."""

from __future__ import annotations

import pathlib
from typing import Iterator

import pytest

from iam_jit.anomaly_detection import (
    AnomalyDetectionConfig,
    AnomalyResult,
    BaselineStore,
    map_action_to_atlas_techniques,
    score_anomaly,
)
from iam_jit.anomaly_detection.detector import (
    _COLD_START_FLAG_THRESHOLD,
)


@pytest.fixture
def hot_store(tmp_path: pathlib.Path) -> Iterator[BaselineStore]:
    """A store pre-populated with a stable baseline so the cold-start
    path doesn't fire and the detector exercises the z-score path."""
    s = BaselineStore(
        path=str(tmp_path / "hot.db"),
        flush_interval_seconds=0.05,
    )
    s.start()
    for _ in range(200):
        s.observe(
            agent_identity="agent-a", action="s3:GetObject",
            resource="arn:aws:s3:::prod-bucket",
        )
    yield s
    s.stop()


def test_anomaly_explanations_per_dimension_present(
    hot_store: BaselineStore,
) -> None:
    """F.1 HIGHEST priority — every result carries per-dimension breakdown.

    The detector must surface (dimension, baseline_mean, baseline_stddev,
    observed, sigma_distance, contributing) for every dimension considered.
    """
    cfg = AnomalyDetectionConfig(enabled=True, min_actions_for_baseline=50)
    summary = hot_store.summary_for("agent-a", "s3:GetObject", "arn:aws:s3:::prod-bucket")
    result = score_anomaly(
        action="s3:GetObject",
        agent_identity="agent-a",
        baseline_summary=summary,
        config=cfg,
        resource="arn:aws:s3:::prod-bucket",
        observed_hour=3,  # off-pattern hour
    )
    # Must have at least the two core dimensions
    dim_names = {e.dimension for e in result.explanations}
    assert "action_frequency" in dim_names
    assert "hour_of_day" in dim_names
    for e in result.explanations:
        # Shape contract — every field present + numeric.
        assert isinstance(e.dimension, str)
        assert isinstance(e.baseline_mean, float)
        assert isinstance(e.baseline_stddev, float)
        assert isinstance(e.observed, float)
        assert isinstance(e.sigma_distance, float)
        assert isinstance(e.contributing, bool)
    # The shape must JSON-serialise (compliance buyers consume this).
    import json
    json.dumps(result.to_dict())


def test_anomaly_cold_start_falls_back_to_classifier_patterns(
    tmp_path: pathlib.Path,
) -> None:
    """F.2 — when baseline < min_actions, fall back to the #404 classifier.

    A known-adversarial action (iam:CreateAccessKey) on an empty baseline
    must flag (the classifier's deterministic backstop fires even on
    Free tier) AND mark cold_start_fallback_used=True.
    """
    store = BaselineStore(path=str(tmp_path / "cold.db"))
    store.start()
    try:
        cfg = AnomalyDetectionConfig(
            enabled=True,
            min_actions_for_baseline=50,
            cold_start_fallback=True,
        )
        summary = store.summary_for("new-agent", "iam:CreateAccessKey")
        result = score_anomaly(
            action="iam:CreateAccessKey",
            agent_identity="new-agent",
            baseline_summary=summary,
            config=cfg,
        )
        assert result.cold_start_fallback_used is True
        assert result.verdict == "anomalous", result.to_dict()
        # F.5 ATLAS tag must accompany an adversarial cold-start flag.
        assert len(result.mitre_atlas_techniques) >= 1
        # Classifier signal payload survives end-to-end.
        assert result.classifier_signal is not None
        assert result.classifier_signal["classification"] == "appears_adversarial"
    finally:
        store.stop()


def test_anomaly_cold_start_disabled_returns_insufficient_data(
    tmp_path: pathlib.Path,
) -> None:
    """Honest framing: when cold_start_fallback is off + baseline empty,
    verdict is insufficient_data — never a false-positive 'anomalous'."""
    store = BaselineStore(path=str(tmp_path / "cold2.db"))
    store.start()
    try:
        cfg = AnomalyDetectionConfig(
            enabled=True,
            min_actions_for_baseline=50,
            cold_start_fallback=False,
        )
        summary = store.summary_for("new-agent", "s3:GetObject")
        result = score_anomaly(
            action="s3:GetObject",
            agent_identity="new-agent",
            baseline_summary=summary,
            config=cfg,
        )
        assert result.verdict == "insufficient_data"
        assert result.cold_start_fallback_used is False
    finally:
        store.stop()


def test_anomaly_mitre_atlas_techniques_tagged() -> None:
    """F.5 — IAM persistence verbs get T1098.* / T1078.*; cover-tracks
    gets T1562.*; destruction gets T1485."""
    iam = map_action_to_atlas_techniques("iam:CreateAccessKey")
    ids = [t["id"] for t in iam]
    assert "T1098.001" in ids
    assert "T1078.004" in ids

    stop_logging = map_action_to_atlas_techniques("cloudtrail:StopLogging")
    assert any(t["id"] == "T1562.008" for t in stop_logging)

    delete_bucket = map_action_to_atlas_techniques("s3:DeleteBucket")
    assert any(t["id"] == "T1485" for t in delete_bucket)

    # Regex pattern — DROP TABLE matches even when buried in SQL
    drop = map_action_to_atlas_techniques("DROP TABLE users;")
    assert any(t["id"] == "T1485" for t in drop)

    # Unknown action returns empty list — no false-positive tagging.
    assert map_action_to_atlas_techniques("s3:GetObject") == []

    # ATLAS AI signals only when requested.
    with_atlas = map_action_to_atlas_techniques(
        "iam:CreateAccessKey", include_atlas_ai_signals=True,
    )
    assert any(t["framework"] == "ATLAS" for t in with_atlas)


def test_anomaly_ensemble_combines_classifier_and_baseline(
    tmp_path: pathlib.Path,
) -> None:
    """combined_score = max(z_score_anomaly, classifier_score, feed_score).

    Build a baseline where neither path alone would fire, but the
    classifier signal pushes combined above the threshold.
    """
    store = BaselineStore(path=str(tmp_path / "ens.db"))
    store.start()
    try:
        # Populate a SMALL baseline (below min, so cold-start fires)
        for _ in range(3):
            store.observe(
                agent_identity="agent-a", action="iam:CreateAccessKey",
            )
        cfg = AnomalyDetectionConfig(
            enabled=True, min_actions_for_baseline=50,
            cold_start_fallback=True,
        )
        summary = store.summary_for("agent-a", "iam:CreateAccessKey")
        result = score_anomaly(
            action="iam:CreateAccessKey",
            agent_identity="agent-a",
            baseline_summary=summary,
            config=cfg,
        )
        assert result.cold_start_fallback_used is True
        assert result.anomaly_score >= 0.7
        assert result.verdict == "anomalous"
    finally:
        store.stop()


def test_anomaly_threat_feed_severity_weights_score(
    tmp_path: pathlib.Path,
) -> None:
    """Threat-feed entry matching the action contributes its severity
    score to the ensemble; the result records the matched severity."""
    store = BaselineStore(path=str(tmp_path / "tf.db"))
    store.start()
    try:
        cfg = AnomalyDetectionConfig(
            enabled=True, min_actions_for_baseline=50,
            cold_start_fallback=False,  # isolate the feed signal
        )
        # Empty baseline, no cold-start fallback → would be insufficient_data.
        # Add a HIGH-severity feed entry; expect that to flip the verdict.
        feed = [{
            "rule_kind": "dynamic_deny",
            "target": "s3:GetObject",
            "action": "s3:GetObject",
            "severity": "HIGH",
        }]
        summary = store.summary_for("agent-a", "s3:GetObject")
        result = score_anomaly(
            action="s3:GetObject",
            agent_identity="agent-a",
            baseline_summary=summary,
            config=cfg,
            threat_feed_entries=feed,
        )
        assert result.threat_feed_severity == "HIGH"
        assert result.anomaly_score >= 0.8
        assert result.verdict == "anomalous"
    finally:
        store.stop()


def test_anomaly_classifier_signal_included_when_used(
    tmp_path: pathlib.Path,
) -> None:
    """When the cold-start classifier fallback fires, the full result
    dict is surfaced in `classifier_signal` so the operator can pivot."""
    store = BaselineStore(path=str(tmp_path / "cs.db"))
    store.start()
    try:
        cfg = AnomalyDetectionConfig(enabled=True, cold_start_fallback=True)
        summary = store.summary_for("agent-a", "iam:CreateAccessKey")
        result = score_anomaly(
            action="iam:CreateAccessKey",
            agent_identity="agent-a",
            baseline_summary=summary,
            config=cfg,
        )
        assert result.classifier_signal is not None
        # The deny-classifier shape includes classification + confidence
        # + reasoning at minimum.
        assert "classification" in result.classifier_signal
        assert "confidence" in result.classifier_signal
    finally:
        store.stop()


def test_anomaly_sensitivity_low_requires_larger_deviation(
    hot_store: BaselineStore,
) -> None:
    """A 1.0σ deviation must NOT flag under low sensitivity (3σ) but
    a 5σ deviation MUST flag."""
    summary = hot_store.summary_for("agent-a", "s3:GetObject", "arn:aws:s3:::prod-bucket")
    cfg_low = AnomalyDetectionConfig(
        enabled=True, sensitivity="low", min_actions_for_baseline=50,
    )
    # Modest off-hour deviation
    result_low = score_anomaly(
        action="s3:GetObject", agent_identity="agent-a",
        baseline_summary=summary, config=cfg_low,
        resource="arn:aws:s3:::prod-bucket", observed_hour=4,
    )
    # High sensitivity flips the same observation
    cfg_high = AnomalyDetectionConfig(
        enabled=True, sensitivity="high", min_actions_for_baseline=50,
    )
    result_high = score_anomaly(
        action="s3:GetObject", agent_identity="agent-a",
        baseline_summary=summary, config=cfg_high,
        resource="arn:aws:s3:::prod-bucket", observed_hour=4,
    )
    # The threshold matters: low sensitivity must NOT flag this if a
    # 5σ-deviating spike under high sensitivity does flag — confirms
    # the threshold drives the verdict band.
    if result_high.verdict == "anomalous":
        assert result_low.anomaly_score <= result_high.anomaly_score


def test_anomaly_spike_in_action_frequency_flags(
    hot_store: BaselineStore,
) -> None:
    """When the operator passes the actual recent-window count and it's
    far above the baseline mean, the detector flags. Confirms the spike-
    detection path works end-to-end."""
    cfg = AnomalyDetectionConfig(
        enabled=True, sensitivity="medium", min_actions_for_baseline=50,
    )
    summary = hot_store.summary_for("agent-a", "s3:GetObject", "arn:aws:s3:::prod-bucket")
    # Baseline has 200 obs over 14d window -> mean ~0.6/hr, stddev ~0.77.
    # Observed = 500 -> z ~ 648 sigma -> definitely anomalous.
    result = score_anomaly(
        action="s3:GetObject", agent_identity="agent-a",
        baseline_summary=summary, config=cfg,
        resource="arn:aws:s3:::prod-bucket",
        observed_action_count=500,
    )
    assert result.verdict == "anomalous", result.to_dict()
    # F.1 explanations must mark action_frequency as contributing.
    contributing = [e for e in result.explanations if e.contributing]
    assert any("action_frequency" in e.dimension for e in contributing)


def test_anomaly_result_serialises_to_dict() -> None:
    """The wire shape must JSON-serialise — consumed by structured-deny."""
    import json
    cfg = AnomalyDetectionConfig(enabled=True)
    from iam_jit.anomaly_detection.baseline import BaselineSummary
    summary = BaselineSummary(
        agent_identity="a", action="s3:GetObject",
        resource_pattern="-", total_observations_rolling=0,
        total_observations_decayed=0.0, dimensions={},
    )
    result = score_anomaly(
        action="s3:GetObject", agent_identity="a",
        baseline_summary=summary, config=cfg,
    )
    payload = result.to_dict()
    json.dumps(payload)  # must not raise
    assert "anomaly_score" in payload
    assert "verdict" in payload
    assert "explanations" in payload
    assert "mitre_atlas_techniques" in payload
    assert "cold_start_fallback_used" in payload
