"""#407 / §A51 — Operator-pinned feed subscription registry.

Builds a list of :class:`Subscription` from the declarative config's
``threat_feed`` block (lives under ``iam-jit.threat_feed``). Each
subscription pairs a feed URL with the pinned publisher pubkey + the
per-feed auto-apply-severity threshold + verification mode.

Per [[independence-as-security-property]] every subscription is
OPERATOR-PINNED: the operator owns the trust decision (URL + pubkey).
The default :data:`OFFICIAL_FEED_URL` + :data:`OFFICIAL_FEED_PUBKEY`
are SUGGESTED defaults that ship in this repo; the operator still has
to opt in by listing them in the declarative config.

Per [[no-hosted-saas]] this module never reads from any centralized
operator-state store — the source of truth is the operator's own YAML.
"""

from __future__ import annotations

import dataclasses
import typing

from .models import Severity, severity_from_str


# ---------------------------------------------------------------------------
# Suggested defaults (operator must still opt in)
# ---------------------------------------------------------------------------


OFFICIAL_FEED_URL = "https://updates.iam-jit.com/feed/v1/official"
"""Suggested default feed URL — founder-curated entries. The operator
opts in by adding this URL to their declarative config's
``threat_feed.feeds`` list; the bouncer does NOT auto-subscribe."""


OFFICIAL_FEED_PUBKEY = ""
"""Founder pubkey for the official feed. EMPTY at v1.0 — the founder
will publish the pubkey when feed publishing goes live. Operators who
want to subscribe before then must pin a community-curated feed or
publish their own."""


_DEFAULT_CADENCE = "daily"
_VALID_CADENCES: frozenset[str] = frozenset(
    {"per_session", "hourly", "daily", "weekly", "on_demand"}
)
_DEFAULT_THRESHOLD = Severity.HIGH


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SubscriptionConfigError(ValueError):
    """Raised when the operator's ``threat_feed`` block is malformed."""


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Subscription:
    """One pinned feed subscription."""

    url: str
    """Feed source URL (HTTPS recommended; ``file://`` accepted for
    air-gapped operators + tests). The fetcher refuses ``http://``
    URLs by default to prevent MITM (override via the fetcher's
    ``allow_insecure_http`` flag — operators who use plain HTTP
    explicitly opt in)."""

    publisher_pubkey: str
    """For Ed25519: PEM or ``ed25519:<b64>`` form. For cosign keyless:
    EMPTY (cosign verifies via expected_identity + expected_issuer,
    not a fixed pubkey)."""

    verification_mode: str = "ed25519"
    """One of ``"ed25519"`` / ``"cosign-keyless"``. Drives which
    verifier the applier dispatches to."""

    severity_auto_apply_threshold: Severity = _DEFAULT_THRESHOLD
    """Minimum severity for auto-apply. Entries below this threshold
    route to the pending queue (MEDIUM) or informational-only (LOW)
    regardless of this knob."""

    cosign_identity: str = ""
    """Required when ``verification_mode == "cosign-keyless"`` — pins
    the OIDC subject that the cert chain must match."""

    cosign_issuer: str = ""
    """Required when ``verification_mode == "cosign-keyless"`` — pins
    the OIDC issuer (e.g. ``https://accounts.google.com``)."""

    enabled: bool = True
    """Allows the operator to keep a subscription pinned but pause
    auto-fetch (e.g. for incident response). Disabled subscriptions
    still surface in ``iam-jit updates last-fetch`` so the operator
    has a single inventory."""

    nickname: str = ""
    """Optional human label for log readability. Falls back to
    ``url``."""

    def label(self) -> str:
        """Best human-readable label for log lines."""
        return self.nickname or self.url


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------


def load_subscriptions_from_declaration(
    declaration: typing.Mapping[str, typing.Any] | None,
) -> tuple[list[Subscription], dict[str, typing.Any]]:
    """Return ``(subscriptions, threat_feed_block)`` from a loaded
    declarative config.

    Returns ``([], {})`` when the declaration is None / disabled /
    has no threat_feed block — this is the no-op path for operators
    who haven't opted in. Per [[ambient-autonomous-protection]] threat
    feed is an OPT-IN.
    """
    if not declaration:
        return [], {}
    block = (declaration.get("iam-jit") or {}).get("threat_feed") or {}
    if not block:
        return [], {}
    if block.get("enabled") is False:
        return [], block
    feeds_raw = block.get("feeds") or []
    if not isinstance(feeds_raw, (list, tuple)):
        raise SubscriptionConfigError(
            "threat_feed.feeds must be a list"
        )
    subs: list[Subscription] = []
    for idx, raw in enumerate(feeds_raw):
        if not isinstance(raw, typing.Mapping):
            raise SubscriptionConfigError(
                f"threat_feed.feeds[{idx}] must be a dict"
            )
        url = str(raw.get("url") or "").strip()
        if not url:
            raise SubscriptionConfigError(
                f"threat_feed.feeds[{idx}].url is required"
            )
        mode = str(raw.get("verification_mode") or "ed25519").strip()
        if mode not in ("ed25519", "cosign-keyless"):
            raise SubscriptionConfigError(
                f"threat_feed.feeds[{idx}].verification_mode must be "
                f"'ed25519' or 'cosign-keyless'; got {mode!r}"
            )
        pubkey = str(raw.get("publisher_pubkey") or "").strip()
        cosign_identity = str(raw.get("cosign_identity") or "").strip()
        cosign_issuer = str(raw.get("cosign_issuer") or "").strip()
        if mode == "ed25519" and not pubkey:
            raise SubscriptionConfigError(
                f"threat_feed.feeds[{idx}] (verification_mode=ed25519) "
                f"requires publisher_pubkey"
            )
        if mode == "cosign-keyless" and not (
            cosign_identity and cosign_issuer
        ):
            raise SubscriptionConfigError(
                f"threat_feed.feeds[{idx}] (verification_mode=cosign-keyless) "
                f"requires cosign_identity + cosign_issuer"
            )
        threshold_raw = raw.get("severity_auto_apply_threshold")
        if threshold_raw is None:
            threshold = _DEFAULT_THRESHOLD
        else:
            try:
                threshold = severity_from_str(threshold_raw)
            except ValueError as e:
                raise SubscriptionConfigError(
                    f"threat_feed.feeds[{idx}].severity_auto_apply_threshold: {e}"
                ) from e
        subs.append(Subscription(
            url=url,
            publisher_pubkey=pubkey,
            verification_mode=mode,
            severity_auto_apply_threshold=threshold,
            cosign_identity=cosign_identity,
            cosign_issuer=cosign_issuer,
            enabled=bool(raw.get("enabled", True)),
            nickname=str(raw.get("nickname") or ""),
        ))
    cadence = str(block.get("update_cadence") or _DEFAULT_CADENCE)
    if cadence not in _VALID_CADENCES:
        raise SubscriptionConfigError(
            f"threat_feed.update_cadence must be one of "
            f"{sorted(_VALID_CADENCES)}; got {cadence!r}"
        )
    return subs, block


__all__ = [
    "OFFICIAL_FEED_PUBKEY",
    "OFFICIAL_FEED_URL",
    "Subscription",
    "SubscriptionConfigError",
    "load_subscriptions_from_declaration",
]
