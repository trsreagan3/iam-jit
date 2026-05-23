"""§A78 #470 — config validation + block-vs-alert mode tests."""

from __future__ import annotations

import json
import pathlib
from typing import Any, Iterator

import pytest

from iam_jit.anomaly_detection import (
    AnomalyDetectionConfig,
    BaselineStore,
    ConfigError,
    HookResult,
    install_anomaly_hook,
    load_config,
    run_anomaly_hook,
    uninstall_anomaly_hook,
)


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def test_schema_anomaly_detection_block_valid() -> None:
    """Validate a full anomaly_detection block via the ambient schema.

    The block lives under iam-jit.anomaly_detection; the ambient
    schema's additionalProperties: False contract means a typo'd key
    would FAIL validation — this test confirms the well-formed block
    is accepted by jsonschema.
    """
    import jsonschema

    from iam_jit.ambient_config.schema import IAM_JIT_CONFIG_SCHEMA

    payload: dict[str, Any] = {
        "iam-jit": {
            "enabled": True,
            "anomaly_detection": {
                "enabled": True,
                "mode": "block",
                "sensitivity": "high",
                "baseline_window": "30d",
                "baseline_decay_rate": 0.9,
                "min_actions_for_baseline": 100,
                "cold_start_fallback": True,
            },
        },
    }
    jsonschema.validate(payload, IAM_JIT_CONFIG_SCHEMA)


def test_schema_anomaly_detection_block_rejects_unknown_key() -> None:
    """A typo'd field MUST fail (additionalProperties: False contract)."""
    import jsonschema

    from iam_jit.ambient_config.schema import IAM_JIT_CONFIG_SCHEMA

    payload = {
        "iam-jit": {
            "enabled": True,
            "anomaly_detection": {
                "enabled": True,
                "sensitive": "high",  # typo: should be "sensitivity"
            },
        },
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, IAM_JIT_CONFIG_SCHEMA)


def test_load_config_defaults() -> None:
    cfg = load_config(None)
    assert cfg.enabled is False
    assert cfg.mode == "alert"
    assert cfg.sensitivity == "medium"


def test_load_config_explicit_block() -> None:
    cfg = load_config({
        "enabled": True, "mode": "block", "sensitivity": "high",
        "baseline_window": "7d", "baseline_decay_rate": 0.5,
        "min_actions_for_baseline": 25, "cold_start_fallback": False,
    })
    assert cfg.enabled is True
    assert cfg.mode == "block"
    assert cfg.sensitivity == "high"
    assert cfg.baseline_window_seconds == 7 * 86400
    assert cfg.baseline_decay_rate == 0.5
    assert cfg.min_actions_for_baseline == 25
    assert cfg.cold_start_fallback is False
    # sigma_threshold derived from sensitivity preset
    assert cfg.sigma_threshold == 1.5


def test_load_config_rejects_invalid_mode() -> None:
    with pytest.raises(ConfigError):
        load_config({"mode": "panic"})


def test_load_config_rejects_invalid_sensitivity() -> None:
    with pytest.raises(ConfigError):
        load_config({"sensitivity": "ludicrous"})


def test_load_config_rejects_bad_decay_rate() -> None:
    with pytest.raises(ConfigError):
        load_config({"baseline_decay_rate": 0.0})
    with pytest.raises(ConfigError):
        load_config({"baseline_decay_rate": 1.5})


def test_load_config_rejects_unknown_key() -> None:
    with pytest.raises(ConfigError):
        load_config({"sensitive": "high"})  # typo


def test_load_config_parses_duration_units() -> None:
    assert load_config({"baseline_window": "30d"}).baseline_window_seconds == 30 * 86400
    assert load_config({"baseline_window": "12h"}).baseline_window_seconds == 12 * 3600
    assert load_config({"baseline_window": "60m"}).baseline_window_seconds == 60 * 60
    assert load_config({"baseline_window": "3600s"}).baseline_window_seconds == 3600
    assert load_config({"baseline_window": 86400}).baseline_window_seconds == 86400


# ---------------------------------------------------------------------------
# Hook + mode tests
# ---------------------------------------------------------------------------


@pytest.fixture
def baseline(tmp_path: pathlib.Path) -> Iterator[BaselineStore]:
    s = BaselineStore(
        path=str(tmp_path / "hook.db"),
        flush_interval_seconds=0.05,
    )
    s.start()
    yield s
    s.stop()


@pytest.fixture(autouse=True)
def _clean_hook_state() -> Iterator[None]:
    """Every test starts + ends with no installed hook (state singleton)."""
    uninstall_anomaly_hook()
    yield
    uninstall_anomaly_hook()


def test_hook_disabled_returns_pass_through(baseline: BaselineStore) -> None:
    """No hook installed -> decision passes through floor + no anomaly."""
    result = run_anomaly_hook(
        action="s3:GetObject", agent_identity="a", resource="*",
        floor_decision="allow",
    )
    assert result.decision == "allow"
    assert result.mode == "disabled"
    assert result.anomaly_result is None
    assert result.emitted_alert is False


def test_block_mode_returns_503_with_structured_deny_and_explanations(
    baseline: BaselineStore,
) -> None:
    """Block-mode flips an anomalous request to a DENY. Operator gets
    the per-dimension explanation surface so the deny is actionable.
    The "503" naming in the test title is per the spec; we return
    decision='deny' so the bouncer's wrapper can render the appropriate
    HTTP status."""
    emitted: list[dict[str, Any]] = []

    cfg = AnomalyDetectionConfig(
        enabled=True, mode="block", sensitivity="medium",
        cold_start_fallback=True, min_actions_for_baseline=50,
    )
    install_anomaly_hook(
        config=cfg, store=baseline,
        alert_emitter=emitted.append,
    )
    # Known-adversarial cold-start path
    result = run_anomaly_hook(
        action="iam:CreateAccessKey",
        agent_identity="agent-a",
        resource="arn:aws:iam::123:user/x",
        floor_decision="allow",
    )
    assert result.decision == "deny", result
    assert result.mode == "block"
    assert result.anomaly_result is not None
    assert result.anomaly_result.verdict == "anomalous"
    # F.1 explanations preserved on the wire
    assert isinstance(result.anomaly_result.explanations, list)
    # Alert was emitted
    assert result.emitted_alert is True
    assert len(emitted) == 1
    # OCSF shape sanity
    evt = emitted[0]
    assert evt["activity_name"] == "anomaly_detected"
    assert evt["unmapped"]["iam_jit"]["mode"] == "block"


def test_alert_mode_lets_through_and_emits_notification(
    baseline: BaselineStore,
) -> None:
    """Alert mode keeps the floor's decision but ALWAYS emits the alert."""
    emitted: list[dict[str, Any]] = []

    cfg = AnomalyDetectionConfig(
        enabled=True, mode="alert", sensitivity="medium",
        cold_start_fallback=True, min_actions_for_baseline=50,
    )
    install_anomaly_hook(
        config=cfg, store=baseline,
        alert_emitter=emitted.append,
    )
    result = run_anomaly_hook(
        action="iam:CreateAccessKey",
        agent_identity="agent-a",
        resource="arn:aws:iam::123:user/x",
        floor_decision="allow",
    )
    assert result.decision == "allow"  # NOT denied — alert-mode lets through
    assert result.mode == "alert"
    assert result.emitted_alert is True
    assert len(emitted) == 1


def test_floor_deny_short_circuits_hook(baseline: BaselineStore) -> None:
    """When the deterministic scorer already denied, the hook is a
    no-op (don't double-count, don't emit twice)."""
    emitted: list[dict[str, Any]] = []
    cfg = AnomalyDetectionConfig(
        enabled=True, mode="block", cold_start_fallback=True,
    )
    install_anomaly_hook(
        config=cfg, store=baseline, alert_emitter=emitted.append,
    )
    result = run_anomaly_hook(
        action="iam:CreateAccessKey",
        agent_identity="agent-a", resource="x",
        floor_decision="deny",
        floor_deny_reason="profile dynamic_deny matched",
    )
    assert result.decision == "deny"
    assert result.anomaly_result is None
    assert result.emitted_alert is False
    assert emitted == []


def test_anomaly_does_not_replace_scorer_on_conflict(
    baseline: BaselineStore,
) -> None:
    """Per [[scorer-is-ground-truth]]: anomaly is ADVISORY. When
    floor says ALLOW and anomaly mode is alert -> allow stands.
    When floor says ALLOW and anomaly mode is block -> the more
    restrictive verdict (deny) wins. Either way the floor's DENY is
    NEVER overridden by the anomaly hook."""
    cfg_alert = AnomalyDetectionConfig(
        enabled=True, mode="alert", cold_start_fallback=True,
    )
    install_anomaly_hook(config=cfg_alert, store=baseline)
    r1 = run_anomaly_hook(
        action="iam:CreateAccessKey", agent_identity="agent-a",
        resource="x", floor_decision="allow",
    )
    assert r1.decision == "allow"  # alert never blocks
    uninstall_anomaly_hook()

    cfg_block = AnomalyDetectionConfig(
        enabled=True, mode="block", cold_start_fallback=True,
    )
    install_anomaly_hook(config=cfg_block, store=baseline)
    r2 = run_anomaly_hook(
        action="iam:CreateAccessKey", agent_identity="agent-a",
        resource="x", floor_decision="allow",
    )
    assert r2.decision == "deny"  # block tightens
    # Floor DENY always stays DENY regardless of mode.
    r3 = run_anomaly_hook(
        action="iam:CreateAccessKey", agent_identity="agent-a",
        resource="x", floor_decision="deny", floor_deny_reason="profile",
    )
    assert r3.decision == "deny"


def test_managed_posture_friction_framing_in_summary(
    baseline: BaselineStore,
) -> None:
    """Operator-facing summary uses the [[ambient-value-prop-and-
    friction-framing]] wording ('your bouncer noticed...' / 'your
    bouncer blocked an unusual action'). Never 'VIOLATION'."""
    cfg = AnomalyDetectionConfig(
        enabled=True, mode="alert", cold_start_fallback=True,
    )
    install_anomaly_hook(config=cfg, store=baseline)
    result = run_anomaly_hook(
        action="iam:CreateAccessKey", agent_identity="a",
        resource="x", floor_decision="allow",
    )
    assert "your bouncer" in result.operator_message.lower()
    assert "violation" not in result.operator_message.lower()
    assert "denied" not in result.operator_message.lower()
