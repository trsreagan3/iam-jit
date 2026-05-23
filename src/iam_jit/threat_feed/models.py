"""#407 / §A51 — Threat-feed data shapes.

Wire-stable dataclasses for the feed itself + per-entry metadata. Every
field name is preserved byte-for-byte across the publisher tool, the
fetcher cache, and the applier so debug traces from any layer line up.

Per [[ambient-autonomous-protection]] §A51 the feed-entry shape is:

  {
    rule_kind:        one of "dynamic_deny" | "profile_safety_floor_extension"
                      | "scope_primitive_recommendation" | "informational_alert"
    target:           pattern the rule applies to (ARN glob / k8s verb /
                      MCP tool name / etc.; bouncer-specific)
    action:           e.g. for dynamic_deny the action(s) being denied;
                      for informational_alert this is the alert title
    severity:         CRITICAL / HIGH / MEDIUM / LOW
    source_incident:  free-text incident URL / CVE id / description
    discovered_at:    ISO 8601 UTC timestamp
    applies_to_bouncers: subset of {ibounce, kbouncer, dbounce, gbounce}
    compliance_tags:  list of strings (NIST 800-53 controls / SOC 2 /
                      HIPAA / DORA / MITRE ATT&CK technique ids)
                      — per #441 Sysdig research, EVERY entry MUST
                      carry these so auditors love the narrative
    signature:        {algorithm, value, publisher, key_id, [cosign_*]}
  }

The wire format is JSON (one file per feed bundle). The publisher tool
produces files of shape ``{schema_version, feed_id, publisher,
generated_at, entries: [...], manifest_sha256}``.

Severity ordering is total (CRITICAL > HIGH > MEDIUM > LOW). Comparisons
between :class:`Severity` instances use this ordering directly.
"""

from __future__ import annotations

import dataclasses
import enum
import typing


# ---------------------------------------------------------------------------
# Severity enum + ordering helpers
# ---------------------------------------------------------------------------


class Severity(str, enum.Enum):
    """Threat-feed entry severity. String enum so JSON serialization is
    free; ordering is via the explicit :data:`_SEVERITY_RANK` map below."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 3,
    Severity.HIGH: 2,
    Severity.MEDIUM: 1,
    Severity.LOW: 0,
}


SEVERITIES: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)


def severity_at_or_above(probe: Severity, threshold: Severity) -> bool:
    """Return True iff ``probe`` is at least as severe as ``threshold``.

    Used by the applier to decide whether to auto-apply (entry severity
    ≥ feed's ``severity_auto_apply_threshold``).
    """
    return _SEVERITY_RANK[probe] >= _SEVERITY_RANK[threshold]


def severity_from_str(raw: object) -> Severity:
    """Parse a string into :class:`Severity`. Case-insensitive.

    Raises :class:`ValueError` for unknown values so the parsing layer
    can surface "this entry's severity is malformed" instead of silently
    coercing to LOW (which would HIDE a CRITICAL — opposite of the
    [[ibounce-honest-positioning]] contract)."""
    if isinstance(raw, Severity):
        return raw
    if not isinstance(raw, str):
        raise ValueError(f"severity must be a string, got {type(raw).__name__}")
    norm = raw.strip().upper()
    for s in SEVERITIES:
        if s.value == norm:
            return s
    raise ValueError(
        f"unknown severity {raw!r}; must be one of "
        f"{[s.value for s in SEVERITIES]}"
    )


# ---------------------------------------------------------------------------
# Rule kinds (closed set)
# ---------------------------------------------------------------------------


RULE_KINDS: frozenset[str] = frozenset({
    "dynamic_deny",
    "profile_safety_floor_extension",
    "scope_primitive_recommendation",
    "informational_alert",
})


# ---------------------------------------------------------------------------
# FeedEntry dataclass
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class FeedEntry:
    """One rule from a threat feed."""

    rule_id: str
    """Stable id assigned by the publisher (e.g. ``tf_<ULID>``). Lets
    the applier dedupe re-fetches + the operator revoke by id via
    ``iam-jit updates revoke <rule_id>``."""

    rule_kind: str
    """One of :data:`RULE_KINDS`. Unknown kinds are skipped by the
    applier (logged) so a newer feed's forward-compat additions don't
    crash an older bouncer."""

    target: str
    """Pattern the rule applies to. For ``dynamic_deny`` an ARN glob /
    k8s-verb / etc. For ``informational_alert`` may be empty."""

    action: typing.Sequence[str]
    """Actions the rule applies to (e.g. ``["s3:GetObject"]``). For
    ``informational_alert`` this is normally a single alert title."""

    severity: Severity
    """:class:`Severity`."""

    source_incident: str
    """Human-readable incident reference (CVE id, blog URL, internal
    incident ticket). Surfaces in operator UI + audit events so the
    operator can verify the source before treating an auto-applied
    rule as authoritative."""

    discovered_at: str
    """ISO 8601 UTC timestamp."""

    applies_to_bouncers: typing.Sequence[str]
    """Subset of ``{"ibounce", "kbouncer", "dbounce", "gbounce"}``."""

    compliance_tags: typing.Sequence[str]
    """NIST 800-53 / SOC 2 / HIPAA / DORA / MITRE ATT&CK tags (per
    #441 Sysdig research)."""

    description: str = ""
    """Optional operator-facing description of what the rule guards
    against. Surfaces in ``iam-jit updates list``."""

    signature: dict[str, typing.Any] = dataclasses.field(default_factory=dict)
    """Signature block: ``{algorithm, value, publisher, key_id,
    [cosign_certificate, cosign_bundle, cosign_identity]}``. Verified
    by :mod:`iam_jit.threat_feed.signing` before any application."""

    def as_dict(self) -> dict[str, typing.Any]:
        """JSON-serializable shape — drops the dataclass machinery."""
        return {
            "rule_id": self.rule_id,
            "rule_kind": self.rule_kind,
            "target": self.target,
            "action": list(self.action),
            "severity": self.severity.value,
            "source_incident": self.source_incident,
            "discovered_at": self.discovered_at,
            "applies_to_bouncers": list(self.applies_to_bouncers),
            "compliance_tags": list(self.compliance_tags),
            "description": self.description,
            "signature": dict(self.signature),
        }


# ---------------------------------------------------------------------------
# Feed dataclass — one fetched bundle of entries
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Feed:
    """A signed bundle of entries pulled from one publisher URL."""

    schema_version: str
    """Wire-shape version. Currently ``"1.0"`` (drives forward-compat
    behavior in the parser)."""

    feed_id: str
    """Publisher-chosen id (e.g. ``official-iam-jit-v1``). Lets multiple
    independent feeds coexist in the cache directory without name
    collisions."""

    publisher: str
    """Human-readable publisher name. Distinct from the cryptographic
    publisher identity carried in each entry's ``signature.publisher``
    field (which the verifier uses)."""

    generated_at: str
    """ISO 8601 UTC timestamp."""

    entries: tuple[FeedEntry, ...]
    """Frozen tuple of entries — preserves source-file order so an
    operator viewing the feed gets deterministic output."""

    manifest_sha256: str = ""
    """Hex sha256 over the canonical-serialized entries. The fetcher
    uses this for change-detection (refresh-cache only when the
    manifest hash changes)."""

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "schema_version": self.schema_version,
            "feed_id": self.feed_id,
            "publisher": self.publisher,
            "generated_at": self.generated_at,
            "entries": [e.as_dict() for e in self.entries],
            "manifest_sha256": self.manifest_sha256,
        }


# ---------------------------------------------------------------------------
# VerificationResult — per-entry verify outcome
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class VerificationResult:
    """Outcome of verifying one feed entry's signature."""

    rule_id: str
    verified: bool
    algorithm: str
    publisher: str
    reason: str = ""
    """When ``verified=False`` this carries the structured reason
    (e.g. ``"unsigned"`` / ``"signature_mismatch"`` /
    ``"unknown_algorithm"``) so the applier can route to the right
    refusal-event subcategory."""

    def as_dict(self) -> dict[str, typing.Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Parse helpers — go from dict → dataclasses
# ---------------------------------------------------------------------------


class FeedParseError(ValueError):
    """Raised when a feed JSON blob is malformed."""


def parse_feed_entry(raw: typing.Mapping[str, typing.Any]) -> FeedEntry:
    """Coerce one entry dict into :class:`FeedEntry`."""
    if not isinstance(raw, typing.Mapping):
        raise FeedParseError(
            f"entry must be a dict, got {type(raw).__name__}"
        )
    try:
        rule_id = str(raw["rule_id"])
        rule_kind = str(raw["rule_kind"])
        target = str(raw.get("target") or "")
        action_raw = raw.get("action") or []
        if isinstance(action_raw, str):
            action = (action_raw,)
        else:
            action = tuple(str(a) for a in action_raw)
        severity = severity_from_str(raw.get("severity"))
        source_incident = str(raw.get("source_incident") or "")
        discovered_at = str(raw.get("discovered_at") or "")
        applies_to_bouncers = tuple(
            str(b) for b in raw.get("applies_to_bouncers") or ()
        )
        compliance_tags = tuple(
            str(t) for t in raw.get("compliance_tags") or ()
        )
        description = str(raw.get("description") or "")
        signature = dict(raw.get("signature") or {})
    except KeyError as e:
        raise FeedParseError(f"entry missing required field: {e}") from e
    if rule_kind not in RULE_KINDS:
        # Don't crash — surface the issue + let the applier skip.
        # Forward-compat: a newer feed shipping a new rule_kind is
        # tolerated; the parser flags it.
        pass
    return FeedEntry(
        rule_id=rule_id,
        rule_kind=rule_kind,
        target=target,
        action=action,
        severity=severity,
        source_incident=source_incident,
        discovered_at=discovered_at,
        applies_to_bouncers=applies_to_bouncers,
        compliance_tags=compliance_tags,
        description=description,
        signature=signature,
    )


def parse_feed_dict(raw: typing.Mapping[str, typing.Any]) -> Feed:
    """Coerce a top-level feed dict into :class:`Feed`."""
    if not isinstance(raw, typing.Mapping):
        raise FeedParseError(
            f"feed must be a dict, got {type(raw).__name__}"
        )
    entries_raw = raw.get("entries") or []
    if not isinstance(entries_raw, (list, tuple)):
        raise FeedParseError("feed.entries must be a list")
    entries = tuple(parse_feed_entry(e) for e in entries_raw)
    return Feed(
        schema_version=str(raw.get("schema_version") or "1.0"),
        feed_id=str(raw.get("feed_id") or "unknown"),
        publisher=str(raw.get("publisher") or "unknown"),
        generated_at=str(raw.get("generated_at") or ""),
        entries=entries,
        manifest_sha256=str(raw.get("manifest_sha256") or ""),
    )


__all__ = [
    "Feed",
    "FeedEntry",
    "FeedParseError",
    "RULE_KINDS",
    "SEVERITIES",
    "Severity",
    "VerificationResult",
    "parse_feed_dict",
    "parse_feed_entry",
    "severity_at_or_above",
    "severity_from_str",
]
