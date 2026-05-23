"""#407 / §A51 — Ed25519 signing + verification tests.

Covers:
  * keygen produces a valid pair
  * sign + verify round-trip
  * tampered payload yields signature_mismatch
  * wrong pubkey yields signature_mismatch
  * unsigned entry yields ``unsigned``
  * algorithm mismatch yields ``algorithm_mismatch_*``
  * malformed signature yields ``signature_value_not_base64``
  * malformed pubkey yields ``pubkey_parse_failed:*``
  * canonical_payload_bytes is deterministic
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from iam_jit.threat_feed import (
    Severity,
    canonical_payload_bytes,
    ed25519_keygen,
    ed25519_sign_entry,
    ed25519_verify_entry,
)
from iam_jit.threat_feed.models import FeedEntry


def _make_entry() -> FeedEntry:
    return FeedEntry(
        rule_id="tf_01HXYZ",
        rule_kind="dynamic_deny",
        target="arn:aws:iam::*:role/agent-attempts-priv-esc",
        action=("iam:AttachRolePolicy",),
        severity=Severity.CRITICAL,
        source_incident="CVE-2025-XYZ",
        discovered_at="2026-05-23T10:00:00Z",
        applies_to_bouncers=("ibounce",),
        compliance_tags=("NIST-AC-6", "SOC2-CC6.1", "MITRE-T1078"),
        description="Block agent attempts to attach admin policy",
    )


def test_ed25519_keygen_produces_pem_pair():
    priv, pub = ed25519_keygen()
    assert "BEGIN PRIVATE KEY" in priv
    assert "BEGIN PUBLIC KEY" in pub


def test_sign_verify_roundtrip():
    priv, pub = ed25519_keygen()
    entry = _make_entry()
    signed = ed25519_sign_entry(entry, private_key_pem=priv, publisher="test")
    assert signed.signature["algorithm"] == "ed25519"
    assert signed.signature["publisher"] == "test"
    result = ed25519_verify_entry(signed, publisher_pubkey=pub)
    assert result.verified is True
    assert result.reason == "ok"


def test_verify_tampered_payload_fails():
    priv, pub = ed25519_keygen()
    entry = _make_entry()
    signed = ed25519_sign_entry(entry, private_key_pem=priv, publisher="test")
    # Mutate target after signing.
    tampered = dataclasses.replace(signed, target="arn:aws:iam::*:role/different")
    result = ed25519_verify_entry(tampered, publisher_pubkey=pub)
    assert result.verified is False
    assert result.reason == "signature_mismatch"


def test_verify_wrong_pubkey_fails():
    priv, _pub = ed25519_keygen()
    _priv2, pub2 = ed25519_keygen()
    entry = _make_entry()
    signed = ed25519_sign_entry(entry, private_key_pem=priv, publisher="test")
    result = ed25519_verify_entry(signed, publisher_pubkey=pub2)
    assert result.verified is False
    assert result.reason == "signature_mismatch"


def test_verify_unsigned_entry():
    entry = _make_entry()
    _priv, pub = ed25519_keygen()
    result = ed25519_verify_entry(entry, publisher_pubkey=pub)
    assert result.verified is False
    assert result.reason == "unsigned"


def test_verify_algorithm_mismatch():
    entry = _make_entry()
    entry = dataclasses.replace(entry, signature={
        "algorithm": "rsa-2048",
        "value": "x",
        "publisher": "test",
    })
    _priv, pub = ed25519_keygen()
    result = ed25519_verify_entry(entry, publisher_pubkey=pub)
    assert result.verified is False
    assert "algorithm_mismatch" in result.reason


def test_verify_malformed_signature_value():
    entry = _make_entry()
    entry = dataclasses.replace(entry, signature={
        "algorithm": "ed25519",
        "value": "!!!notbase64!!!",
        "publisher": "test",
    })
    _priv, pub = ed25519_keygen()
    result = ed25519_verify_entry(entry, publisher_pubkey=pub)
    assert result.verified is False
    assert result.reason == "signature_value_not_base64"


def test_verify_malformed_pubkey():
    priv, _pub = ed25519_keygen()
    entry = _make_entry()
    signed = ed25519_sign_entry(entry, private_key_pem=priv, publisher="test")
    result = ed25519_verify_entry(signed, publisher_pubkey="not-a-key")
    assert result.verified is False
    assert "pubkey_parse_failed" in result.reason


def test_canonical_payload_deterministic():
    entry = _make_entry()
    b1 = canonical_payload_bytes(entry)
    b2 = canonical_payload_bytes(entry)
    assert b1 == b2
    parsed = json.loads(b1.decode("utf-8"))
    # signature should NOT be included
    assert "signature" not in parsed


def test_pubkey_short_form_accepted():
    """Pubkey accepted as the short form `ed25519:<b64>` (the form
    operators paste into their declarative config)."""
    from cryptography.hazmat.primitives import serialization
    import base64

    priv, pub = ed25519_keygen()
    # Build short-form from pubkey.
    pk = serialization.load_pem_public_key(pub.encode("ascii"))
    raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    short_form = "ed25519:" + base64.b64encode(raw).decode("ascii")
    entry = _make_entry()
    signed = ed25519_sign_entry(entry, private_key_pem=priv, publisher="test")
    result = ed25519_verify_entry(signed, publisher_pubkey=short_form)
    assert result.verified is True
