"""#725 — cost-circuit-breaker declarative config.

Loads + validates the ``iam-jit.cost_circuit_breaker`` block from
``.iam-jit.yaml`` (and accepts the same dict from the CLI
``--cost-circuit-breaker-rule`` JSON). Extension-only: ambient
declarations written before this feature continue to validate.

Shape::

    iam-jit:
      cost_circuit_breaker:
        enabled: true
        mode: block               # block | alert
        window: 1h                # sliding window per session
        max_calls_per_window: 5000
        max_usd_per_window: 50.0   # ESTIMATE — see cost_estimator
        cool_down: 5m              # auto-reset after this idle gap

Per ``[[ibounce-honest-positioning]]`` defaults are conservative:
disabled by default, and when enabled the thresholds are GENEROUS
(5000 calls / $50 per hour) so a legitimate busy session never trips
by surprise. Per ``[[safety-mode-lean-permissive]]`` ``mode`` defaults
to ``block`` only once the operator opted in by setting ``enabled``;
the generous threshold is what keeps it from being block-happy.

At least one of ``max_calls_per_window`` / ``max_usd_per_window`` must
resolve to a positive cap; a config with ``enabled: true`` but both
caps unset/zero is rejected (it would be a silent no-op breaker).

Cap semantics: the breaker trips when ``calls >= max_calls_per_window``
(likewise for the USD cap). The ``max_calls_per_window``-th gated call
within the window is the one that TRIPS the breaker — that call is
allowed, and in ``block`` mode the *next* gated call for the session is
the first one denied. (Not "the (N+1)th call trips.")
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any


class ConfigError(ValueError):
    """Raised when ``cost_circuit_breaker`` config is malformed."""


_DEFAULT_WINDOW = "1h"
_DEFAULT_COOL_DOWN = "5m"
_DEFAULT_MODE = "block"
# Generous defaults per [[ibounce-honest-positioning]]: a busy CI
# session can easily make a few thousand AWS calls/hour legitimately,
# so 5000 is well above normal but still catches a true retry-loop
# (which produces tens of thousands/hour). $50/hr matches the
# autopilot-side conservative starter cap shape.
_DEFAULT_MAX_CALLS = 5000
_DEFAULT_MAX_USD = 50.0

# Accept "30d" / "12h" / "60m" / "3600s" / raw int seconds — mirrors
# anomaly_detection.config so operators learn one duration grammar.
_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "": 1}


def _parse_duration_to_seconds(raw: Any, *, field: str) -> int:
    if isinstance(raw, bool):  # bool is an int subclass; reject explicitly
        raise ConfigError(f"{field} must be a duration, not a boolean")
    if isinstance(raw, int):
        if raw <= 0:
            raise ConfigError(f"{field} must be > 0; got {raw}")
        return raw
    if not isinstance(raw, str):
        raise ConfigError(
            f"{field} must be a duration string like '1h' or positive "
            f"integer seconds; got {type(raw).__name__}"
        )
    m = _DURATION_RE.match(raw)
    if not m:
        raise ConfigError(
            f"{field} must be like '1h' / '30m' / '90s' / '1d'; got {raw!r}"
        )
    seconds = int(m.group(1)) * _DURATION_UNITS[m.group(2) or "s"]
    if seconds <= 0:
        raise ConfigError(f"{field} must be > 0; got {raw!r}")
    return seconds


def _coerce_cap(raw: Any, *, field: str, numeric: type) -> Any:
    """Coerce + validate a cap. ``None`` / unset = no cap on this
    dimension. Negative is rejected. Zero is treated as "no cap" (the
    operator can drop a dimension by setting it to 0)."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ConfigError(f"{field} must be a number, not a boolean")
    try:
        val = numeric(raw)
    except (TypeError, ValueError) as e:
        raise ConfigError(f"{field} must be a {numeric.__name__}; got {raw!r}") from e
    if val < 0:
        raise ConfigError(f"{field} must be >= 0; got {val}")
    return val if val > 0 else None


@dataclasses.dataclass(frozen=True)
class CircuitBreakerConfig:
    """Validated cost-circuit-breaker config."""

    enabled: bool = False
    mode: str = _DEFAULT_MODE  # block | alert
    window_seconds: int = 3600
    cool_down_seconds: int = 300
    max_calls_per_window: int | None = _DEFAULT_MAX_CALLS
    max_usd_per_window: float | None = _DEFAULT_MAX_USD

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "window_seconds": self.window_seconds,
            "cool_down_seconds": self.cool_down_seconds,
            "max_calls_per_window": self.max_calls_per_window,
            "max_usd_per_window": self.max_usd_per_window,
        }


def load_config(block: Any) -> CircuitBreakerConfig:
    """Validate + return a :class:`CircuitBreakerConfig` from a parsed
    ambient YAML ``cost_circuit_breaker`` block (or the equivalent dict
    from ``--cost-circuit-breaker-rule``).

    ``block`` may be ``None`` (returns the disabled default) or a dict.
    Anything else raises :class:`ConfigError`.
    """
    if block is None:
        return CircuitBreakerConfig(enabled=False)
    if not isinstance(block, dict):
        raise ConfigError(
            f"cost_circuit_breaker must be a mapping; got {type(block).__name__}"
        )

    allowed = {
        "enabled", "mode", "window", "cool_down",
        "max_calls_per_window", "max_usd_per_window",
    }
    extra = set(block) - allowed
    if extra:
        raise ConfigError(
            f"cost_circuit_breaker has unknown key(s) {sorted(extra)}; "
            f"allowed: {sorted(allowed)}"
        )

    enabled = bool(block.get("enabled", False))
    mode = str(block.get("mode", _DEFAULT_MODE)).strip().lower()
    if mode not in ("block", "alert"):
        raise ConfigError(
            f"cost_circuit_breaker.mode must be 'block' or 'alert'; got {mode!r}"
        )
    window_seconds = _parse_duration_to_seconds(
        block.get("window", _DEFAULT_WINDOW),
        field="cost_circuit_breaker.window",
    )
    cool_down_seconds = _parse_duration_to_seconds(
        block.get("cool_down", _DEFAULT_COOL_DOWN),
        field="cost_circuit_breaker.cool_down",
    )
    # Caps: a key that is PRESENT uses its value; a key that is ABSENT
    # falls back to the generous default. Setting a present key to 0
    # drops that dimension.
    max_calls = _coerce_cap(
        block["max_calls_per_window"] if "max_calls_per_window" in block
        else _DEFAULT_MAX_CALLS,
        field="cost_circuit_breaker.max_calls_per_window",
        numeric=int,
    )
    max_usd = _coerce_cap(
        block["max_usd_per_window"] if "max_usd_per_window" in block
        else _DEFAULT_MAX_USD,
        field="cost_circuit_breaker.max_usd_per_window",
        numeric=float,
    )

    if enabled and max_calls is None and max_usd is None:
        raise ConfigError(
            "cost_circuit_breaker.enabled is true but neither "
            "max_calls_per_window nor max_usd_per_window resolves to a "
            "positive cap — the breaker would be a silent no-op. Set at "
            "least one cap (or set enabled: false)."
        )

    return CircuitBreakerConfig(
        enabled=enabled,
        mode=mode,
        window_seconds=window_seconds,
        cool_down_seconds=cool_down_seconds,
        max_calls_per_window=max_calls,
        max_usd_per_window=max_usd,
    )


__all__ = [
    "CircuitBreakerConfig",
    "ConfigError",
    "load_config",
]
