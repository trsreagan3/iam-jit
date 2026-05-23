"""§A78 #470 — anomaly_detection declarative config.

Loads + validates the ``iam-jit.anomaly_detection`` block from
``.iam-jit.yaml``. The block is extension-only: ambient declarations
written before Phase H continue to validate.

Shape::

    iam-jit:
      anomaly_detection:
        enabled: true
        mode: alert            # alert | block
        sensitivity: medium    # low | medium | high
        baseline_window: 14d
        baseline_decay_rate: 0.96
        min_actions_for_baseline: 50
        cold_start_fallback: true   # F.2

The sensitivity presets resolve to z-score thresholds:

    low    -> 3.0σ
    medium -> 2.0σ
    high   -> 1.5σ

Per ``[[ambient-value-prop-and-friction-framing]]`` block-mode under a
managed posture emits a warning (operator should know they're flipping
on enforcement); refusal vs warning is left to the consumer (the proxy
emits a warning + honors the request).

Per ``[[ibounce-honest-positioning]]`` defaults are conservative
(mode=alert, sensitivity=medium, cold-start fallback on).
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any


class ConfigError(ValueError):
    """Raised when ``anomaly_detection`` config is malformed."""


SENSITIVITY_PRESETS: dict[str, float] = {
    "low": 3.0,
    "medium": 2.0,
    "high": 1.5,
}

_DEFAULT_WINDOW = "14d"
_DEFAULT_DECAY_RATE = 0.96
_DEFAULT_MIN_ACTIONS = 50
_DEFAULT_MODE = "alert"
_DEFAULT_SENSITIVITY = "medium"


# Accept "30d" / "12h" / "60m" / raw seconds
_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "": 1}


def _parse_duration_to_seconds(raw: Any, *, field: str) -> int:
    if isinstance(raw, int):
        if raw <= 0:
            raise ConfigError(f"{field} must be > 0; got {raw}")
        return raw
    if not isinstance(raw, str):
        raise ConfigError(
            f"{field} must be a duration string like '14d' or "
            f"positive integer seconds; got {type(raw).__name__}"
        )
    m = _DURATION_RE.match(raw)
    if not m:
        raise ConfigError(
            f"{field} must be like '14d' / '12h' / '60m' / '3600s'; "
            f"got {raw!r}"
        )
    n = int(m.group(1))
    unit = m.group(2) or "s"
    seconds = n * _DURATION_UNITS[unit]
    if seconds <= 0:
        raise ConfigError(f"{field} must be > 0; got {raw!r}")
    return seconds


@dataclasses.dataclass(frozen=True)
class AnomalyDetectionConfig:
    """Validated anomaly-detection config."""

    enabled: bool = False
    mode: str = _DEFAULT_MODE
    sensitivity: str = _DEFAULT_SENSITIVITY
    baseline_window_seconds: int = 14 * 86400
    baseline_decay_rate: float = _DEFAULT_DECAY_RATE
    min_actions_for_baseline: int = _DEFAULT_MIN_ACTIONS
    cold_start_fallback: bool = True

    @property
    def sigma_threshold(self) -> float:
        """Return the z-score threshold the detector flags above."""
        return SENSITIVITY_PRESETS[self.sensitivity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "sensitivity": self.sensitivity,
            "baseline_window_seconds": self.baseline_window_seconds,
            "baseline_decay_rate": self.baseline_decay_rate,
            "min_actions_for_baseline": self.min_actions_for_baseline,
            "cold_start_fallback": self.cold_start_fallback,
            "sigma_threshold": self.sigma_threshold,
        }


def load_config(block: Any) -> AnomalyDetectionConfig:
    """Validate + return an :class:`AnomalyDetectionConfig` from a parsed
    ambient YAML ``anomaly_detection`` block.

    ``block`` may be ``None`` (returns the disabled default) or a dict.
    Anything else raises :class:`ConfigError`.
    """
    if block is None:
        return AnomalyDetectionConfig(enabled=False)
    if not isinstance(block, dict):
        raise ConfigError(
            f"anomaly_detection must be a mapping; got {type(block).__name__}"
        )

    enabled = bool(block.get("enabled", False))
    mode = str(block.get("mode", _DEFAULT_MODE)).strip().lower()
    if mode not in ("alert", "block"):
        raise ConfigError(
            f"anomaly_detection.mode must be 'alert' or 'block'; got {mode!r}"
        )
    sensitivity = str(block.get("sensitivity", _DEFAULT_SENSITIVITY)).strip().lower()
    if sensitivity not in SENSITIVITY_PRESETS:
        raise ConfigError(
            f"anomaly_detection.sensitivity must be one of "
            f"{sorted(SENSITIVITY_PRESETS)}; got {sensitivity!r}"
        )
    window_seconds = _parse_duration_to_seconds(
        block.get("baseline_window", _DEFAULT_WINDOW),
        field="anomaly_detection.baseline_window",
    )
    decay_rate = float(block.get("baseline_decay_rate", _DEFAULT_DECAY_RATE))
    if not (0.0 < decay_rate <= 1.0):
        raise ConfigError(
            f"anomaly_detection.baseline_decay_rate must be in (0, 1]; "
            f"got {decay_rate}"
        )
    min_actions = int(block.get("min_actions_for_baseline", _DEFAULT_MIN_ACTIONS))
    if min_actions < 0:
        raise ConfigError(
            f"anomaly_detection.min_actions_for_baseline must be >= 0; "
            f"got {min_actions}"
        )
    cold_start = bool(block.get("cold_start_fallback", True))

    # Reject any unknown keys for the same reason ambient schema uses
    # additionalProperties: False — typos must not silently no-op.
    allowed = {
        "enabled", "mode", "sensitivity", "baseline_window",
        "baseline_decay_rate", "min_actions_for_baseline",
        "cold_start_fallback",
    }
    extra = set(block) - allowed
    if extra:
        raise ConfigError(
            f"anomaly_detection has unknown key(s) {sorted(extra)}; "
            f"allowed: {sorted(allowed)}"
        )

    return AnomalyDetectionConfig(
        enabled=enabled,
        mode=mode,
        sensitivity=sensitivity,
        baseline_window_seconds=window_seconds,
        baseline_decay_rate=decay_rate,
        min_actions_for_baseline=min_actions,
        cold_start_fallback=cold_start,
    )


__all__ = [
    "AnomalyDetectionConfig",
    "ConfigError",
    "SENSITIVITY_PRESETS",
    "load_config",
]
