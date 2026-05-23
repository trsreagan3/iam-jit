"""Compliance retention tiering — #428 / §A67.

Closes the LAUNCH-BLOCKER §A67 gap that until this slice landed,
audit-log retention was a single-window policy
(``--audit-log-max-age-days`` for JSONL archives;
``--audit-db-retention-days`` for SQLite archives). Compliance
frameworks (PCI-DSS, HIPAA, SOX, GDPR) require multi-tier
retention — hot for fast query, warm for compressed local access,
cold for offsite/archival, with explicit PURGE semantics for
GDPR right-to-be-forgotten + jurisdictional minimums.

Per the §A67 spec the declarative shape in ``.iam-jit.yaml`` is::

    iam-jit:
      retention:
        compliance: pci         # pci | hipaa | sox | gdpr | custom
        hot_days: 30            # locally queryable
        warm_days: 90           # archived locally, compressed
        cold_days: 365          # archived to S3 / object-storage
        purge_after_days: 2555  # 7 years for SOX; null = never purge
        gdpr_pii_purge: true    # scrub PII fields after hot_days

Per-framework defaults (selected by the ``compliance:`` field):

    PCI-DSS: hot 30d / warm 90d  / cold 365d  / no purge
             — PCI minimum is 1 year; we keep indefinitely by default.
    HIPAA:   hot 30d / warm 180d / cold 2190d / purge after 2190d
             — HIPAA 6-year retention; explicit purge after to bound
             liability beyond the regulated window.
    SOX:     hot 30d / warm 365d / cold 2555d / no purge
             — SOX 7-year retention; SOX has no upper bound so we
             default to "keep indefinitely" past the cold threshold.
    GDPR:    hot 30d / warm 90d  / cold 365d  / gdpr_pii_purge: true
             — GDPR cares about PII inside the audit log; the audit
             decision itself is retained for accountability but PII
             fields are scrubbed after the hot window.

Per ``[[v1-scope-bar]]`` this slice is THIN: declarative policy +
write-time enforcement (PII scrub before disk) + a transition
helper that moves rotated archives across tiers. The S3 archival
itself is delegated to the existing #317 object-storage writer —
this module emits hints + tracks which archives are eligible for
cold-tier upload; it does NOT re-implement S3 transport.

Per ``[[creates-never-mutates]]`` archive-tier transitions are
RENAMES, not data-destructive operations. Purges (the only
destructive operation) require ``purge_after_days`` to be set AND
the file to be older than that threshold — two-key safety. PII
scrubs replace credential-shaped + PII-shaped patterns with
placeholders; the rest of the event is preserved verbatim.

Per ``[[mitm-beta-pii-pci-concern]]`` the default PII redaction
strips CREDENTIAL-SHAPED patterns (bearer tokens, AWS keys,
HMAC signatures); PHI/PCI/PII-specific redaction stays
opt-in via the ``custom`` framework + ``redact_patterns`` extension.
Operators in regulated workloads MUST configure their own
redaction; we don't claim to redact everything by default.

Composes with #424 disk-pressure: retention tiering DRIVES the
rotation/archive policy that disk-pressure consults. When disk-
pressure transitions to critical in archive-and-purge mode, the
oldest cold-tier files are the natural drop candidates.

Composes with #317 S3 sink: cold-tier eligibility = "ready to be
shipped by the object-storage writer + safe to drop locally once
shipped." The S3 sink owns the actual upload cadence; this module
owns the "is X eligible" decision.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import gzip
import json
import logging
import os
import pathlib
import re
import shutil
import time
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Framework constants + defaults
# ---------------------------------------------------------------------------

FRAMEWORK_PCI = "pci"
FRAMEWORK_HIPAA = "hipaa"
FRAMEWORK_SOX = "sox"
FRAMEWORK_GDPR = "gdpr"
FRAMEWORK_CUSTOM = "custom"

KNOWN_FRAMEWORKS: frozenset[str] = frozenset({
    FRAMEWORK_PCI,
    FRAMEWORK_HIPAA,
    FRAMEWORK_SOX,
    FRAMEWORK_GDPR,
    FRAMEWORK_CUSTOM,
})

# Per-framework defaults. Each tuple is
# ``(hot_days, warm_days, cold_days, purge_after_days, gdpr_pii_purge)``.
# These are CUMULATIVE age thresholds (NOT phase durations) so the
# operator-facing mental model is "after Y days in the log, the
# event has aged into tier X". Tier transitions fire when the file
# crosses the threshold; ``purge_after_days`` purges at or past it.
# ``purge_after_days = None`` means "keep indefinitely past cold".
_FRAMEWORK_DEFAULTS: dict[str, tuple[int, int, int, int | None, bool]] = {
    # PCI: hot ≤ 30d, warm 30-120d, cold 120-365d, no purge.
    # Operator-visible window: keep all rows queryable up to 1 year +
    # archive-grade indefinitely.
    FRAMEWORK_PCI: (30, 120, 365, None, False),
    # HIPAA: hot ≤ 30d, warm 30-210d, cold 210-2190d, purge at 2190d
    # (6 years — the HIPAA minimum retention).
    FRAMEWORK_HIPAA: (30, 210, 2190, 2190, False),
    # SOX: hot ≤ 30d, warm 30-395d, cold 395-2555d, no purge (SOX has
    # no upper retention bound; default to "keep" past cold).
    FRAMEWORK_SOX: (30, 395, 2555, None, False),
    # GDPR: hot ≤ 30d, warm 30-120d, cold 120-365d + write-time PII purge.
    FRAMEWORK_GDPR: (30, 120, 365, None, True),
    # Custom: same shape as PCI but operator overrides every field.
    FRAMEWORK_CUSTOM: (30, 120, 365, None, False),
}

# Tier names. Used in archive filename prefixes + admin-action events
# so SIEM rules can pattern-match on tier transitions.
TIER_HOT = "hot"
TIER_WARM = "warm"
TIER_COLD = "cold"

# Archive filename prefixes per tier. Active log = audit.jsonl;
# rotated (hot) = audit-{ts}.jsonl.gz; warm = warm-{ts}.jsonl.gz;
# cold = cold-{ts}.jsonl.gz. Filename prefix lets a `ls` show the
# tier at a glance + lets purge_by_policy distinguish without
# re-stat'ing every file.
WARM_PREFIX = "warm-"
COLD_PREFIX = "cold-"

# Default PII redaction patterns. Per the docstring [[mitm-beta-pii-
# pci-concern]] we redact CREDENTIAL-SHAPED patterns only by default.
# Operators in regulated workloads layer their own patterns via the
# custom framework's ``redact_patterns`` extension.
DEFAULT_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # AWS-shaped credentials. AKIA/ASIA prefix + 16 chars.
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    # AWS secret access key (40 char base64-ish).
    ("aws_secret_access_key", re.compile(
        r"\b[A-Za-z0-9/+]{40}\b"
    )),
    # Bearer tokens in Authorization-header-shaped strings.
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]+")),
    # JWT-ish three-part dot-separated base64url tokens.
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"
    )),
    # Email addresses (basic PII).
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
)

REDACTION_PLACEHOLDER = "[REDACTED:{kind}]"


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class RetentionPolicy:
    """Declarative retention policy. Built from a declaration block
    OR via :func:`policy_for_framework` to pull in framework defaults.

    The fields map 1:1 to the .iam-jit.yaml ``retention:`` block.
    """

    compliance: str
    """One of KNOWN_FRAMEWORKS. The framework's defaults seed any
    field the operator didn't override."""

    hot_days: int
    """Cumulative age threshold (in days) at or below which an
    archive remains in the hot tier. Must be > 0. A row aged
    >hot_days transitions to the warm tier."""

    warm_days: int
    """Cumulative age threshold at or below which a warm-tier
    archive stays warm. Must be >= hot_days. A row aged
    >warm_days transitions to the cold tier. Set warm_days ==
    hot_days to skip the warm tier."""

    cold_days: int
    """Cumulative age threshold at or below which a cold-tier
    archive stays cold (eligible for S3 archival). Must be >=
    warm_days. Rows aged >cold_days remain cold-eligible until
    purge_after_days fires (or indefinitely when null)."""

    purge_after_days: int | None
    """Cumulative age threshold at which an archive is unconditionally
    purged. None = keep indefinitely past cold. When set, MUST be
    >= cold_days so the retention window declared by the tiers is
    never shortened by an over-aggressive purge."""

    gdpr_pii_purge: bool
    """When True, run :func:`redact_event_pii` at write time + scrub
    PII fields from rotated archives at the hot→warm transition.
    True by default for the GDPR framework."""

    redact_patterns: tuple[tuple[str, re.Pattern[str]], ...] = (
        DEFAULT_PII_PATTERNS
    )
    """Tuples of (kind, regex) for PII scrubbing. Operators extend
    via the custom framework's `redact_patterns` declaration field."""

    def total_retention_days(self) -> int:
        """The maximum age (in days) at which an event is still in
        an active tier. Equals cold_days under cumulative semantics."""
        return self.cold_days


def policy_for_framework(
    framework: str,
    *,
    hot_days: int | None = None,
    warm_days: int | None = None,
    cold_days: int | None = None,
    purge_after_days: int | None = None,
    gdpr_pii_purge: bool | None = None,
) -> RetentionPolicy:
    """Build a RetentionPolicy from a framework name + optional
    overrides. Raises ValueError on unknown framework OR an invalid
    purge_after_days (smaller than total retention window).
    """
    f = framework.strip().lower()
    if f not in KNOWN_FRAMEWORKS:
        raise ValueError(
            f"unknown compliance framework {framework!r}; "
            f"expected one of {sorted(KNOWN_FRAMEWORKS)}"
        )
    defaults = _FRAMEWORK_DEFAULTS[f]
    h = defaults[0] if hot_days is None else hot_days
    w = defaults[1] if warm_days is None else warm_days
    c = defaults[2] if cold_days is None else cold_days
    p = defaults[3] if purge_after_days is None else purge_after_days
    g = defaults[4] if gdpr_pii_purge is None else gdpr_pii_purge
    if h <= 0:
        raise ValueError("hot_days must be > 0")
    if w < h:
        raise ValueError(
            f"warm_days ({w}) must be >= hot_days ({h}); use "
            "warm_days == hot_days to skip the warm tier"
        )
    if c < w:
        raise ValueError(
            f"cold_days ({c}) must be >= warm_days ({w}); use "
            "cold_days == warm_days to skip the cold tier"
        )
    if p is not None:
        if p < c:
            raise ValueError(
                f"purge_after_days ({p}) must be >= cold_days "
                f"({c}) so data within the declared cold-tier "
                "retention window is never purged"
            )
    return RetentionPolicy(
        compliance=f,
        hot_days=h,
        warm_days=w,
        cold_days=c,
        purge_after_days=p,
        gdpr_pii_purge=bool(g),
    )


def default_policy() -> RetentionPolicy:
    """Conservative default when the operator hasn't picked a
    framework: PCI shape (hot 30 / warm 90 / cold 365 / no purge)."""
    return policy_for_framework(FRAMEWORK_PCI)


# ---------------------------------------------------------------------------
# Write-time PII redaction
# ---------------------------------------------------------------------------


def redact_event_pii(
    event: dict[str, Any],
    policy: RetentionPolicy,
) -> dict[str, Any]:
    """Walk ``event`` recursively, replacing values matching the
    policy's redact_patterns with placeholders.

    Returns the SAME event dict (mutated in place) for chaining.
    No-ops when ``policy.gdpr_pii_purge`` is False — the caller
    is responsible for checking this; we expose the function
    unconditionally so tests can exercise both paths.

    Per ``[[creates-never-mutates]]`` redaction is shape-preserving:
    we don't drop fields or restructure the event, only rewrite
    string values that match a credential/PII pattern.
    """
    if not policy.gdpr_pii_purge:
        return event
    _redact_in_place(event, policy.redact_patterns)
    return event


def _redact_in_place(
    obj: Any,
    patterns: tuple[tuple[str, re.Pattern[str]], ...],
) -> None:
    """Recursive walk + in-place rewrite."""
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if isinstance(v, str):
                new_v = v
                for kind, regex in patterns:
                    new_v = regex.sub(
                        REDACTION_PLACEHOLDER.format(kind=kind), new_v,
                    )
                obj[k] = new_v
            else:
                _redact_in_place(v, patterns)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                new_v = v
                for kind, regex in patterns:
                    new_v = regex.sub(
                        REDACTION_PLACEHOLDER.format(kind=kind), new_v,
                    )
                obj[i] = new_v
            else:
                _redact_in_place(v, patterns)


# ---------------------------------------------------------------------------
# Tier transitions + purge
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class TierTransition:
    """One file's tier transition. Returned by apply_retention so the
    caller can emit admin-action events + surface to /healthz."""

    path: str
    from_tier: str
    to_tier: str
    age_days: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "from_tier": self.from_tier,
            "to_tier": self.to_tier,
            "age_days": round(self.age_days, 2),
        }


@dataclasses.dataclass(frozen=True)
class RetentionApplyResult:
    """Aggregate of one ``apply_retention`` run."""

    transitions: list[TierTransition]
    purged: list[str]
    cold_eligible: list[str]
    """Cold-tier archives eligible for S3 shipping. The #317
    object-storage writer (or operator-driven `iam-jit logs ship-to`
    command) consumes this list."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "transitions": [t.to_dict() for t in self.transitions],
            "purged": list(self.purged),
            "cold_eligible": list(self.cold_eligible),
        }


def _tier_of(path: pathlib.Path) -> str:
    """Determine tier from filename prefix. Active log = hot. Rotated
    audit-* = hot. Warm-prefixed = warm. Cold-prefixed = cold."""
    n = path.name
    if n.startswith(COLD_PREFIX):
        return TIER_COLD
    if n.startswith(WARM_PREFIX):
        return TIER_WARM
    return TIER_HOT


def _age_days(path: pathlib.Path, now: float) -> float:
    """Age in days from mtime."""
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return 0.0
    return (now - mtime) / 86400.0


def _atomic_rename(src: pathlib.Path, dst: pathlib.Path) -> None:
    """Atomic move within the same filesystem; safe under POSIX."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    os.rename(str(src), str(dst))


def apply_retention(
    log_dir: str | os.PathLike,
    policy: RetentionPolicy,
    *,
    now: float | None = None,
) -> RetentionApplyResult:
    """Walk ``log_dir``, transitioning rotated archives between
    tiers according to ``policy`` + collecting purge candidates.

    The active ``audit.jsonl`` / ``audit.db`` is never touched — this
    function only acts on already-rotated files (``audit-*.jsonl.gz``,
    ``warm-*.jsonl.gz``, ``cold-*.jsonl.gz``).

    Transitions are RENAMES (atomic). Purges respect the two-key
    safety: ``purge_after_days`` must be set AND the file must be
    older than that threshold. The third arm, ``gdpr_pii_purge``,
    triggers a re-pass of warm-tier files through the PII scrubber
    when the policy's gdpr_pii_purge flag is True.

    Per ``[[ibounce-honest-positioning]]`` cold-tier files
    eligible for S3 archival are RETURNED to the caller (not
    deleted) — the caller's S3 writer is responsible for upload.
    This module never destroys data the operator hasn't told it
    to destroy.
    """
    n = now if now is not None else time.time()
    d = pathlib.Path(log_dir)
    if not d.is_dir():
        return RetentionApplyResult(
            transitions=[], purged=[], cold_eligible=[],
        )
    transitions: list[TierTransition] = []
    purged: list[str] = []
    cold_eligible: list[str] = []
    for child in sorted(d.iterdir()):
        name = child.name
        # Only consider rotated archives. Active log + state files +
        # backup tarballs are out of scope.
        if not (
            (name.startswith("audit-") and name.endswith(".jsonl.gz"))
            or (name.startswith(WARM_PREFIX) and name.endswith(".jsonl.gz"))
            or (name.startswith(COLD_PREFIX) and name.endswith(".jsonl.gz"))
        ):
            continue
        tier = _tier_of(child)
        age = _age_days(child, n)
        # First: purge check (highest priority + only destructive
        # action). Two-key: must have purge_after_days set AND must
        # be past the cumulative purge age. The framework validator
        # already guarantees purge_after_days >= cold_days so this
        # is the only check needed here.
        if (
            policy.purge_after_days is not None
            and age >= policy.purge_after_days
        ):
            try:
                child.unlink()
                purged.append(str(child))
            except OSError as e:
                logger.warning("retention purge failed for %s: %s", child, e)
            continue
        # Tier transition cascade based on CUMULATIVE age thresholds:
        # hot if age <= hot_days, warm if age <= warm_days, cold
        # otherwise. The tier-prefix on the filename signals current
        # tier; we transition by renaming with the new prefix.
        if tier == TIER_HOT and age > policy.hot_days and policy.warm_days > policy.hot_days:
            new_name = WARM_PREFIX + name[len("audit-"):]
            dst = child.parent / new_name
            try:
                # Optional PII scrub when transitioning to warm under
                # the GDPR policy.
                if policy.gdpr_pii_purge:
                    _scrub_archive_pii(child, dst, policy)
                else:
                    _atomic_rename(child, dst)
                transitions.append(TierTransition(
                    path=str(dst),
                    from_tier=TIER_HOT,
                    to_tier=TIER_WARM,
                    age_days=age,
                ))
            except OSError as e:
                logger.warning("retention hot→warm failed for %s: %s", child, e)
        elif tier == TIER_WARM and age > policy.warm_days and policy.cold_days > policy.warm_days:
            # warm → cold: rename only; the cold-tier filename signals
            # eligibility for S3 archival.
            new_name = COLD_PREFIX + name[len(WARM_PREFIX):]
            dst = child.parent / new_name
            try:
                _atomic_rename(child, dst)
                transitions.append(TierTransition(
                    path=str(dst),
                    from_tier=TIER_WARM,
                    to_tier=TIER_COLD,
                    age_days=age,
                ))
                cold_eligible.append(str(dst))
            except OSError as e:
                logger.warning("retention warm→cold failed for %s: %s", child, e)
        elif tier == TIER_COLD:
            # Cold-tier files are always eligible for S3 archival
            # (the S3 writer dedupes on bucket-side filename).
            cold_eligible.append(str(child))
    return RetentionApplyResult(
        transitions=transitions,
        purged=purged,
        cold_eligible=cold_eligible,
    )


def _scrub_archive_pii(
    src: pathlib.Path,
    dst: pathlib.Path,
    policy: RetentionPolicy,
) -> None:
    """Decompress src, scrub PII per policy, recompress to dst,
    unlink src. Used by GDPR-policy hot→warm transitions.

    Streaming: read line-by-line so a multi-GB archive doesn't load
    into RAM. The scrubbed warm archive is the SAME shape as the
    hot archive (one JSON event per gzipped line); only string
    values matching the policy's patterns differ.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(src, "rt", encoding="utf-8") as fin, gzip.open(
        dst, "wt", encoding="utf-8", compresslevel=6,
    ) as fout:
        for line in fin:
            if not line.strip():
                fout.write(line)
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # Preserve the line verbatim — operator may want it
                # for forensics; scrubbing a non-JSON line risks
                # mangling a partial-write recovery candidate.
                fout.write(line)
                continue
            redact_event_pii(event, policy)
            fout.write(json.dumps(event, ensure_ascii=False) + "\n")
    src.unlink()


# ---------------------------------------------------------------------------
# Declaration parsing
# ---------------------------------------------------------------------------


def policy_from_declaration(
    block: dict[str, Any] | None,
) -> RetentionPolicy:
    """Build a RetentionPolicy from a parsed ``retention:`` block of
    .iam-jit.yaml. None / missing block returns the default policy.

    Raises ValueError on framework-name typos or invalid
    purge_after_days; the apply-config CLI bubbles this up as a
    structured error so the operator sees the typo at config-apply
    time, not at write time.
    """
    if not block:
        return default_policy()
    framework = block.get("compliance", FRAMEWORK_PCI)
    return policy_for_framework(
        framework,
        hot_days=block.get("hot_days"),
        warm_days=block.get("warm_days"),
        cold_days=block.get("cold_days"),
        purge_after_days=block.get("purge_after_days"),
        gdpr_pii_purge=block.get("gdpr_pii_purge"),
    )


__all__ = [
    "COLD_PREFIX",
    "DEFAULT_PII_PATTERNS",
    "FRAMEWORK_CUSTOM",
    "FRAMEWORK_GDPR",
    "FRAMEWORK_HIPAA",
    "FRAMEWORK_PCI",
    "FRAMEWORK_SOX",
    "KNOWN_FRAMEWORKS",
    "REDACTION_PLACEHOLDER",
    "RetentionApplyResult",
    "RetentionPolicy",
    "TIER_COLD",
    "TIER_HOT",
    "TIER_WARM",
    "TierTransition",
    "WARM_PREFIX",
    "apply_retention",
    "default_policy",
    "policy_for_framework",
    "policy_from_declaration",
    "redact_event_pii",
]
