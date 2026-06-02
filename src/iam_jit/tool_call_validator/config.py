"""Profile-config dataclass for the hallucinated-tool-call validator.

Mirrors the YAML key names exactly so operators can grep between this
file + their profile.yaml without translation. Defaults are SAFE-OFF
(disabled) per [[ibounce-honest-positioning]] — we don't auto-enable
detection with any false-positive footprint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


Action = Literal["warn", "strip", "deny", "allow"]
_VALID_ACTIONS: frozenset[str] = frozenset(("warn", "strip", "deny", "allow"))


@dataclass(frozen=True)
class ProfileConfig:
    """Per-profile hallucinated-tool-call-validator configuration.

    Fields mirror `validate_tool_calls:` YAML keys exactly. Frozen so
    callers can cache the dataclass safely.
    """

    enabled: bool = False

    # Action mode for detected calls. `warn` adds a header + audit;
    # `strip` removes hallucinated call entries from the forwarded
    # body; `deny` returns 422 Unprocessable Entity.
    action: Action = "warn"

    # Optional path (or URL) to an operator-supplied schema-corpus
    # override file. Empty string = baked-in corpus only. When
    # present, operator entries are unioned with the baked-in set;
    # operator entries WIN on name collision.
    schema_corpus_path: str = ""

    # Allowlist regex strings. If any matches the request body, the
    # validator skips. Same shape as BUILD-9 for operator consistency.
    allowlist_patterns: tuple[str, ...] = field(default_factory=tuple)

    # Skip / truncate bodies larger than this. Mirrors BUILD-9's
    # ReDoS cap. Tool-call request bodies are tiny relative to the
    # MITM body cap, so 64 KiB is generous.
    max_body_bytes: int = 64 * 1024

    # Below this confidence, `deny` action is downgraded to `warn`.
    # Default 0.7 matches BUILD-9 — operators who want strict deny
    # set this to 0.
    min_confidence_for_deny: float = 0.7

    @classmethod
    def from_dict(cls, raw: dict | None) -> "ProfileConfig":
        """Build from a YAML-loaded dict. Missing keys → defaults.

        Unknown keys are IGNORED — a config written against a newer
        schema doesn't crash an older bouncer.
        """
        if not raw:
            return cls()
        enabled = bool(raw.get("enabled", False))
        action = raw.get("action", "warn")
        if action not in _VALID_ACTIONS:
            action = "warn"
        schema_corpus_path = str(raw.get("schema_corpus_path") or "")
        allowlist = raw.get("allowlist_patterns") or ()
        if not isinstance(allowlist, (list, tuple)):
            allowlist = ()
        allowlist_tuple = tuple(str(p) for p in allowlist)
        max_body_bytes = int(raw.get("max_body_bytes", 64 * 1024))
        if max_body_bytes <= 0:
            max_body_bytes = 64 * 1024
        if max_body_bytes > 1 << 20:
            max_body_bytes = 1 << 20
        min_conf = float(raw.get("min_confidence_for_deny", 0.7))
        if min_conf < 0.0:
            min_conf = 0.0
        if min_conf > 1.0:
            min_conf = 1.0
        return cls(
            enabled=enabled,
            action=action,  # type: ignore[arg-type]
            schema_corpus_path=schema_corpus_path,
            allowlist_patterns=allowlist_tuple,
            max_body_bytes=max_body_bytes,
            min_confidence_for_deny=min_conf,
        )
