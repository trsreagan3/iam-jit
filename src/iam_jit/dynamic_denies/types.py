# #324a — shared dataclasses for the dynamic-deny ibounce slice.
"""Dataclasses shared between ``loader.py``, ``matcher.py`` and
``watcher.py``.

Field names mirror the on-disk YAML shape byte-for-byte so a future
round-trip writer (#324e) can serialise the same struct back without
a translation layer. Empty / missing optional fields are normalised
to ``None`` (preserves schema-roundtrip) and explicit ``"permanent"``
durations carry ``expires_at = None``.

Per ``[[cross-product-agent-parity]]`` the wire shape here matches
gbounce's ``internal/dynamicdeny/types.go::Rule`` byte-for-byte —
debugging a cross-bouncer routing question doesn't need a translation
table.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
from typing import Any


@dataclasses.dataclass(frozen=True)
class Rule:
    """One dynamic-deny rule, deserialised from the YAML file +
    filtered for ibounce applicability.

    Field names match ``docs/schemas/dynamic-denies-v1.json`` exactly.
    The loader normalises types (timestamps -> ``datetime``,
    optional fields -> ``None``) before constructing the frozen
    instance.
    """

    id: str
    """ULID-suffixed id (``dd_<26-char Crockford base32>``). Surfaces in
    the verdict audit event as
    ``unmapped.iam_jit.ext.dynamic_deny_rule_id`` so an analyst can
    pivot from a 403 to the rule that fired it."""

    targets: tuple[str, ...]
    """Target patterns. For ibounce these are AWS ARN globs (the loader
    pre-filters non-ARN targets — kbouncer / dbounce / gbounce see
    their own slice)."""

    reason: str
    """Operator free-text — surfaces verbatim in the 403 `deny_reason`
    body + the OCSF audit event so the next operator sees `why`
    without context-switching."""

    duration: str
    """Either a duration string (``30m`` / ``3h`` / ``7d``) or the
    literal ``permanent``. Anchors :attr:`expires_at` at write time."""

    added_by: str
    """Audit-trail metadata; resolved via the writer's
    ``resolve_operator()`` so even unidentified callers carry the
    ``local-operator`` fallback (mirrors
    ``admin_action.resolve_operator``)."""

    added_at: _dt.datetime
    """When the rule was created — wall-clock at the authoring host
    (NOT the reading host). See ``DYNAMIC-DENY-RULES.md`` →
    "clock skew" for the ±30s tolerance contract."""

    expires_at: _dt.datetime | None
    """Auto-removal timestamp. ``None`` when ``duration == 'permanent'``
    OR when the writer omitted the field (loader normalises both to
    ``None`` so downstream comparisons branch on a single sentinel)."""

    applied_to: tuple[str, ...]
    """Which bouncer(s) the rule routes to. The loader filters the
    file to entries containing ``"ibounce"``; this tuple preserves
    every entry so the audit / mgmt-port introspection paths can
    surface the full routing decision the writer made."""

    applies_to_recommender: bool = True
    """Per #324f the iam-jit recommender embeds an explicit ``Deny``
    statement matching the rule's targets into any role issued during
    the rule's lifetime when this flag is true. ibounce ignores it on
    the request-time path but preserves it so a round-trip writer
    doesn't lose data."""

    source: str = "cli"
    """Provenance: ``cli`` / ``mcp`` / ``org-distributed`` / ``imported``.
    ``org-distributed`` rules cannot be loosened by personal
    ``deny remove`` per the design doc's Conflict-resolution section
    (the gate lands in #324e; ibounce's reader just preserves the
    field)."""

    org_distributed_url: str | None = None
    """When :attr:`source` is ``org-distributed`` this is the HTTPS
    URL the rule was installed from. Used by the sync path (#324e) to
    refresh; ibounce surfaces it in mgmt-port responses for operator
    introspection."""

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable dict shape (timestamps -> ISO 8601 Z,
        tuples -> lists). Used by the ``/admin/dynamic-denies/reload``
        endpoint response + the audit-event ``ext`` block."""
        return {
            "id": self.id,
            "targets": list(self.targets),
            "reason": self.reason,
            "duration": self.duration,
            "added_by": self.added_by,
            "added_at": _iso_z(self.added_at),
            "expires_at": _iso_z(self.expires_at) if self.expires_at else None,
            "applied_to": list(self.applied_to),
            "applies_to_recommender": self.applies_to_recommender,
            "source": self.source,
            "org_distributed_url": self.org_distributed_url,
        }


def _iso_z(dt: _dt.datetime) -> str:
    """Format a datetime as ISO 8601 UTC with Z suffix. Naive datetimes
    are treated as UTC (matches the writer's contract — :py:class:`Rule`
    is constructed with UTC-aware datetimes by the loader)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    else:
        dt = dt.astimezone(_dt.timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


@dataclasses.dataclass(frozen=True)
class RuleSet:
    """In-memory snapshot the proxy consults on every request.

    Atomically swapped by the watcher on reload — the proxy hot-path
    holds a reference to the OLD snapshot through the request, so a
    mid-request reload never produces a torn read.
    """

    rules: tuple[Rule, ...] = ()
    """Filtered + active rules (``applied_to`` contains ``"ibounce"``
    AND not expired at load time). Order is preserved from the on-disk
    file for deterministic match ordering."""

    source_path: str = ""
    """File path the rules were loaded from. Surfaces in the startup
    banner + the ``/healthz`` + ``/admin/dynamic-denies/reload`` payload
    so an operator with a non-default ``IAM_JIT_DYNAMIC_DENIES_PATH``
    sees it confirmed back."""

    loaded_at: _dt.datetime | None = None
    """Wall-clock the snapshot was built. Surfaces in introspection
    payloads so the operator can see "last successful reload was N
    seconds ago"."""

    total_rules_in_file: int = 0
    """How many rules were in the source file BEFORE the ibounce-lane
    filter. Banner emits both numbers so an operator running a single
    rule that routes to gbounce sees the file is non-empty even though
    ibounce's applied count is 0."""

    @classmethod
    def empty(cls, source_path: str = "") -> "RuleSet":
        """Sentinel for "no rules loaded" — initial-state placeholder +
        the value returned by the loader for a missing file (an operator
        who hasn't installed any dynamic denies still wants the proxy
        to start cleanly)."""
        return cls(
            rules=(),
            source_path=source_path,
            loaded_at=_dt.datetime.now(_dt.timezone.utc),
            total_rules_in_file=0,
        )

    def rule_by_id(self, rule_id: str) -> Rule | None:
        """Lookup a rule by its ``dd_<ULID>`` id. Returns ``None`` when
        the id isn't in the active (post-filter, post-expiry) set —
        useful for audit-replay paths that want to surface the
        rule-as-of-decision-time."""
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None
