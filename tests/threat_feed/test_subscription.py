"""#407 / §A51 — Subscription parsing tests."""

from __future__ import annotations

import pytest

from iam_jit.threat_feed import (
    Severity,
    SubscriptionConfigError,
    load_subscriptions_from_declaration,
)


def test_no_threat_feed_block_returns_empty():
    subs, block = load_subscriptions_from_declaration({"iam-jit": {}})
    assert subs == []
    assert block == {}


def test_disabled_returns_empty():
    subs, _ = load_subscriptions_from_declaration({
        "iam-jit": {"threat_feed": {"enabled": False, "feeds": [{
            "url": "https://x", "publisher_pubkey": "ed25519:abc",
        }]}},
    })
    assert subs == []


def test_single_ed25519_subscription_parses():
    subs, block = load_subscriptions_from_declaration({
        "iam-jit": {"threat_feed": {
            "enabled": True,
            "update_cadence": "daily",
            "feeds": [{
                "url": "https://updates.iam-jit.com/v1/official",
                "publisher_pubkey": "ed25519:abc",
                "severity_auto_apply_threshold": "HIGH",
            }],
        }},
    })
    assert len(subs) == 1
    s = subs[0]
    assert s.url == "https://updates.iam-jit.com/v1/official"
    assert s.verification_mode == "ed25519"
    assert s.severity_auto_apply_threshold == Severity.HIGH
    assert block.get("update_cadence") == "daily"


def test_cosign_keyless_requires_identity_and_issuer():
    with pytest.raises(SubscriptionConfigError) as exc:
        load_subscriptions_from_declaration({
            "iam-jit": {"threat_feed": {
                "enabled": True,
                "feeds": [{
                    "url": "https://x",
                    "verification_mode": "cosign-keyless",
                }],
            }},
        })
    assert "cosign_identity" in str(exc.value)


def test_cosign_keyless_parses_when_complete():
    subs, _ = load_subscriptions_from_declaration({
        "iam-jit": {"threat_feed": {
            "enabled": True,
            "feeds": [{
                "url": "https://x",
                "verification_mode": "cosign-keyless",
                "cosign_identity": "trsreagan3@gmail.com",
                "cosign_issuer": "https://accounts.google.com",
            }],
        }},
    })
    assert len(subs) == 1
    assert subs[0].verification_mode == "cosign-keyless"
    assert subs[0].cosign_identity == "trsreagan3@gmail.com"


def test_ed25519_requires_pubkey():
    with pytest.raises(SubscriptionConfigError) as exc:
        load_subscriptions_from_declaration({
            "iam-jit": {"threat_feed": {
                "enabled": True,
                "feeds": [{
                    "url": "https://x",
                }],
            }},
        })
    assert "publisher_pubkey" in str(exc.value)


def test_invalid_cadence_rejected():
    with pytest.raises(SubscriptionConfigError):
        load_subscriptions_from_declaration({
            "iam-jit": {"threat_feed": {
                "enabled": True,
                "update_cadence": "yearly",
                "feeds": [{
                    "url": "https://x",
                    "publisher_pubkey": "ed25519:abc",
                }],
            }},
        })


def test_invalid_severity_threshold_rejected():
    with pytest.raises(SubscriptionConfigError):
        load_subscriptions_from_declaration({
            "iam-jit": {"threat_feed": {
                "enabled": True,
                "feeds": [{
                    "url": "https://x",
                    "publisher_pubkey": "ed25519:abc",
                    "severity_auto_apply_threshold": "URGENT",
                }],
            }},
        })
