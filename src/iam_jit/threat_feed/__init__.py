"""#407-#411 / §A51-§A55 — Threat-feed subscription mechanic (Phase C).

This package implements the threat-feed subscription cluster from
[[ambient-autonomous-protection]] Phase C — the v1.0 mechanism that
delivers on the "your bouncer silently gets better over time via
curated threat intelligence" value prop.

Architecture (all OPERATOR-PINNED, no phone-home per
[[independence-as-security-property]] + [[no-hosted-saas]]):

  * ``models``       — Feed / FeedEntry / VerificationResult dataclasses
                       + severity ordering. Wire shape stable for the
                       publisher tool + fetcher.
  * ``signing``      — Ed25519 verify (canonical) + cosign keyless verify
                       (additive per #441 Sysdig research). Operator
                       chooses per-feed; unsigned entries are REFUSED.
  * ``fetcher``      — HTTP GET with local on-disk cache; falls back to
                       cached copy on network failure (graceful degrade
                       per [[ibounce-honest-positioning]] — surfaces the
                       failure as an admin_action OCSF event, never
                       silently fabricates a feed).
  * ``subscription`` — Subscription registry built from the declarative
                       config's ``threat_feed`` block.
  * ``applier``      — Severity-graded auto-apply: CRITICAL auto + log,
                       HIGH auto + notify, MEDIUM → pending queue, LOW
                       informational. Managed posture REFUSES auto-apply
                       (CI requires explicit PR review).
  * ``publisher``    — Publisher-side keypair gen + entry sign + bundle
                       + verify. Sibling CLI in ``cli_publisher.py``
                       (entry point ``iam-jit-feed-publish``).

Operator surfaces (CLI: ``iam-jit updates``; MCP: ``bounce_updates_*``)
live in :mod:`iam_jit.cli_updates` so the registration follows the same
pattern as the other ambient surfaces.

Per [[scorer-is-ground-truth]] threat-feed rules are ADVISORY — they
add denies / allow-rule pendings / informational alerts. They DO NOT
modify the deterministic scorer.

Per [[creates-never-mutates]] applied feed rules are ADDITIVE to the
operator's existing config; never overwrites operator-authored rules.
"""

from .applier import (
    ApplyOutcome,
    apply_feed_entries,
    classify_apply_action,
)
from .fetcher import (
    FeedFetchError,
    FeedFetchResult,
    fetch_feed,
    load_cached_feed,
    resolve_cache_dir,
)
from .models import (
    SEVERITIES,
    Feed,
    FeedEntry,
    Severity,
    VerificationResult,
    parse_feed_dict,
    parse_feed_entry,
)
from .signing import (
    SigningError,
    VerificationFailed,
    canonical_payload_bytes,
    cosign_verify_entry,
    ed25519_keygen,
    ed25519_sign_entry,
    ed25519_verify_entry,
)
from .subscription import (
    Subscription,
    SubscriptionConfigError,
    load_subscriptions_from_declaration,
)

__all__ = [
    "ApplyOutcome",
    "Feed",
    "FeedEntry",
    "FeedFetchError",
    "FeedFetchResult",
    "SEVERITIES",
    "Severity",
    "SigningError",
    "Subscription",
    "SubscriptionConfigError",
    "VerificationFailed",
    "VerificationResult",
    "apply_feed_entries",
    "canonical_payload_bytes",
    "classify_apply_action",
    "cosign_verify_entry",
    "ed25519_keygen",
    "ed25519_sign_entry",
    "ed25519_verify_entry",
    "fetch_feed",
    "load_cached_feed",
    "load_subscriptions_from_declaration",
    "parse_feed_dict",
    "parse_feed_entry",
    "resolve_cache_dir",
]
