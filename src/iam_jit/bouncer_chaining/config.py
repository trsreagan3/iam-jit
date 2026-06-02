"""#724 — bouncer-chaining declarative config (opt-in, default OFF).

Loads the ``iam-jit.bouncer_chaining`` block from ``.iam-jit.yaml``.
Per ``[[v1-scope-bar]]`` + ``[[independence-as-security-property]]``
chaining is DISABLED by default — an operator must explicitly opt in.

Shape::

    iam-jit:
      bouncer_chaining:
        enabled: true
        mode: block            # block | alert  (default block once enabled)
        chains_dir: ~/.iam-jit/chains   # optional override
        signal_db: ~/.iam-jit/chaining/signals.db  # optional override

``mode``:
  * ``block`` — a triggered chain rule TIGHTENS ALLOW->DENY (the real
    cross-protocol defense). Default once enabled.
  * ``alert`` — the consumer records that a chain WOULD tighten + emits
    the audit event, but does NOT change the verdict. Lets an operator
    observe the chain firing before enforcing.

Extension-only: an ambient config written before this feature
continues to validate (the block is simply absent -> disabled).
"""

from __future__ import annotations

import dataclasses
from typing import Any


class ConfigError(ValueError):
    """Raised when the ``bouncer_chaining`` config block is malformed."""


_DEFAULT_MODE = "block"
_KNOWN_MODES = {"block", "alert"}


@dataclasses.dataclass(frozen=True)
class ChainingConfig:
    """Validated bouncer-chaining config."""

    enabled: bool = False
    mode: str = _DEFAULT_MODE
    chains_dir: str | None = None
    signal_db: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "chains_dir": self.chains_dir,
            "signal_db": self.signal_db,
        }


def load_config(block: Any) -> ChainingConfig:
    """Validate + return a :class:`ChainingConfig` from a parsed ambient
    YAML ``bouncer_chaining`` block.

    ``block`` may be ``None`` (returns the disabled default) or a dict.
    Anything else raises :class:`ConfigError`."""
    if block is None:
        return ChainingConfig(enabled=False)
    if not isinstance(block, dict):
        raise ConfigError(
            f"bouncer_chaining must be a mapping; got {type(block).__name__}"
        )

    allowed = {"enabled", "mode", "chains_dir", "signal_db"}
    extra = set(block) - allowed
    if extra:
        raise ConfigError(
            f"bouncer_chaining has unknown key(s) {sorted(extra)}; "
            f"allowed: {sorted(allowed)}"
        )

    enabled = bool(block.get("enabled", False))
    mode = str(block.get("mode", _DEFAULT_MODE)).strip().lower()
    if mode not in _KNOWN_MODES:
        raise ConfigError(
            f"bouncer_chaining.mode must be 'block' or 'alert'; got {mode!r}"
        )

    chains_dir = block.get("chains_dir")
    if chains_dir is not None and not isinstance(chains_dir, str):
        raise ConfigError("bouncer_chaining.chains_dir must be a string path")
    signal_db = block.get("signal_db")
    if signal_db is not None and not isinstance(signal_db, str):
        raise ConfigError("bouncer_chaining.signal_db must be a string path")

    return ChainingConfig(
        enabled=enabled,
        mode=mode,
        chains_dir=chains_dir or None,
        signal_db=signal_db or None,
    )


__all__ = [
    "ChainingConfig",
    "ConfigError",
    "load_config",
]
