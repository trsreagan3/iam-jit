"""Profile-config dataclass for the injection scanner.

Operators configure per-bouncer-profile via YAML; the bouncer's profile
loader hands the parsed dict to `ProfileConfig.from_dict`. The dataclass
is frozen so any downstream caching is safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


Action = Literal["warn", "strip", "deny", "allow"]
_VALID_ACTIONS: frozenset[str] = frozenset(("warn", "strip", "deny", "allow"))


@dataclass(frozen=True)
class ProfileConfig:
    """Per-profile injection-scanner configuration.

    Fields mirror the YAML key names exactly so operators can grep
    between this file + their profile.yaml without translation.

    All defaults are SAFE-OFF: the scanner is disabled out of the box
    because (a) MITM mode is required for response inspection on
    gbounce, and per [[mitm-beta-pii-pci-concern]] MITM ships BETA,
    and (b) per [[ibounce-honest-positioning]] we don't auto-enable
    detection that has any false-positive footprint.
    """

    enabled: bool = False

    # Action mode applied to detected responses. `warn` adds a
    # response header + audit event but passes the body through;
    # `strip` redacts matching regions; `deny` returns 403.
    action: Action = "warn"

    # Operator-supplied regexes that suppress detection when the
    # response (or its URL / content-type) matches. Stored as a
    # tuple of compiled-pattern STRINGS so the dataclass stays
    # hashable / serializable; compilation happens once inside the
    # scanner.
    allowlist_patterns: tuple[str, ...] = field(default_factory=tuple)

    # Skip scanning bodies larger than this. Mirrors the input-side
    # ReDoS cap from `iam_jit.prompt_injection`.
    max_body_bytes: int = 64 * 1024

    # Confidence threshold below which `deny` action is downgraded
    # to `warn`. Operators who want strict deny set this to 0; the
    # default 0.7 reflects "two indicators or one high-signal one".
    min_confidence_for_deny: float = 0.7

    @classmethod
    def from_dict(cls, raw: dict | None) -> "ProfileConfig":
        """Build from a YAML-loaded dict. Missing keys → defaults.

        Unknown keys are IGNORED rather than raising so a config
        written for a newer schema doesn't crash an older bouncer.
        """
        if not raw:
            return cls()
        enabled = bool(raw.get("enabled", False))
        action = raw.get("action", "warn")
        if action not in _VALID_ACTIONS:
            # Unknown action → safest fallback. Logged at the
            # bouncer's profile-load step (not here — this is a
            # pure dataclass).
            action = "warn"
        allowlist = raw.get("allowlist_patterns") or ()
        if not isinstance(allowlist, (list, tuple)):
            allowlist = ()
        allowlist_tuple = tuple(str(p) for p in allowlist)
        max_body_bytes = int(raw.get("max_body_bytes", 64 * 1024))
        # Clamp to a sane range. Bodies bigger than 1 MiB hit the
        # bouncer's snapshot cap anyway.
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
            allowlist_patterns=allowlist_tuple,
            max_body_bytes=max_body_bytes,
            min_confidence_for_deny=min_conf,
        )
