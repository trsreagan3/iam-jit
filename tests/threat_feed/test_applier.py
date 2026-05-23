"""#407 + #411 / §A51 + §A55 — Applier tests.

Covers:
  * severity → action classification (per posture + threshold)
  * managed posture REFUSES all severities
  * unsigned/invalid entries → refused_verification + recorded in ledger
  * CRITICAL with valid signature → auto_apply (writes a dynamic_deny)
  * HIGH below threshold → pending_approval
  * MEDIUM → pending_approval (queue write happens)
  * LOW → informational (ledger only)
  * dry_run skips state mutation
  * skip_already_applied dedupes on rule_id
  * revoke removes from dynamic_denies + appends "revoked" record
"""

from __future__ import annotations

import dataclasses
import json
import pathlib

from iam_jit.threat_feed import (
    Severity,
    Subscription,
    apply_feed_entries,
    classify_apply_action,
    ed25519_keygen,
    ed25519_sign_entry,
)
from iam_jit.threat_feed.applier import (
    load_ledger,
    remove_from_ledger,
    resolve_ledger_path,
)
from iam_jit.threat_feed.models import Feed, FeedEntry


def _entry(rule_id: str, severity: Severity = Severity.CRITICAL, kind: str = "dynamic_deny") -> FeedEntry:
    return FeedEntry(
        rule_id=rule_id,
        rule_kind=kind,
        target="arn:aws:iam::*:role/agent-*",
        action=("iam:AttachRolePolicy",),
        severity=severity,
        source_incident="TEST-INCIDENT",
        discovered_at="2026-05-23T10:00:00Z",
        applies_to_bouncers=("ibounce",),
        compliance_tags=("NIST-AC-6", "SOC2-CC6.1"),
        description="test entry",
    )


def _signed_feed(entries: list[FeedEntry], priv_pem: str, pub_pem: str) -> tuple[Feed, Subscription]:
    signed = [
        ed25519_sign_entry(e, private_key_pem=priv_pem, publisher="test")
        for e in entries
    ]
    feed = Feed(
        schema_version="1.0",
        feed_id="test-v1",
        publisher="test",
        generated_at="2026-05-23T10:00:00Z",
        entries=tuple(signed),
        manifest_sha256="x",
    )
    sub = Subscription(
        url="file:///tmp/test",
        publisher_pubkey=pub_pem,
        verification_mode="ed25519",
        severity_auto_apply_threshold=Severity.HIGH,
    )
    return feed, sub


# ---------------------------------------------------------------------------
# Classification (pure function)
# ---------------------------------------------------------------------------


def test_classify_managed_always_refused():
    for s in Severity:
        assert classify_apply_action(s, threshold=Severity.LOW, posture="managed") == "managed_refused"


def test_classify_critical_auto_apply():
    assert classify_apply_action(Severity.CRITICAL, threshold=Severity.HIGH, posture="ambient") == "auto_apply"


def test_classify_high_with_high_threshold_auto_notify():
    assert classify_apply_action(Severity.HIGH, threshold=Severity.HIGH, posture="ambient") == "auto_apply_notify"


def test_classify_high_with_critical_threshold_pending():
    assert classify_apply_action(Severity.HIGH, threshold=Severity.CRITICAL, posture="ambient") == "pending_approval"


def test_classify_medium_always_pending():
    assert classify_apply_action(Severity.MEDIUM, threshold=Severity.LOW, posture="ambient") == "pending_approval"
    assert classify_apply_action(Severity.MEDIUM, threshold=Severity.CRITICAL, posture="ambient") == "pending_approval"


def test_classify_low_always_informational():
    assert classify_apply_action(Severity.LOW, threshold=Severity.LOW, posture="ambient") == "informational"


# ---------------------------------------------------------------------------
# End-to-end apply
# ---------------------------------------------------------------------------


def test_unsigned_entry_refused_and_recorded(tmp_path):
    entries = [_entry("tf_UNSIGNED")]
    feed = Feed(
        schema_version="1.0",
        feed_id="test",
        publisher="test",
        generated_at="2026-05-23T10:00:00Z",
        entries=tuple(entries),
    )
    _priv, pub = ed25519_keygen()
    sub = Subscription(url="file:///x", publisher_pubkey=pub)
    outcomes = apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    assert outcomes[0].action == "refused_verification"
    assert outcomes[0].verified is False
    assert outcomes[0].verification_reason == "unsigned"
    # Ledger received a refused record.
    records = load_ledger()
    assert any(
        r["rule_id"] == "tf_UNSIGNED" and r["status"] == "refused_verification"
        for r in records
    )


def test_critical_signed_entry_auto_applies():
    priv, pub = ed25519_keygen()
    entries = [_entry("tf_CRIT", severity=Severity.CRITICAL)]
    feed, sub = _signed_feed(entries, priv, pub)
    outcomes = apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    assert outcomes[0].action == "auto_apply"
    assert outcomes[0].verified
    assert outcomes[0].applied_artifact_id.startswith("dd_")


def test_high_signed_entry_auto_applies_with_notify():
    priv, pub = ed25519_keygen()
    entries = [_entry("tf_HIGH", severity=Severity.HIGH)]
    feed, sub = _signed_feed(entries, priv, pub)
    outcomes = apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    assert outcomes[0].action == "auto_apply_notify"


def test_medium_entry_pending_approval():
    priv, pub = ed25519_keygen()
    entries = [_entry("tf_MED", severity=Severity.MEDIUM)]
    feed, sub = _signed_feed(entries, priv, pub)
    outcomes = apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    assert outcomes[0].action == "pending_approval"
    assert outcomes[0].pending_entry_id.startswith("pa_")


def test_low_entry_informational_only():
    priv, pub = ed25519_keygen()
    entries = [_entry("tf_LOW", severity=Severity.LOW, kind="informational_alert")]
    feed, sub = _signed_feed(entries, priv, pub)
    outcomes = apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    assert outcomes[0].action == "informational"
    assert outcomes[0].applied_artifact_id == ""


def test_managed_posture_refuses_all_severities():
    priv, pub = ed25519_keygen()
    entries = [
        _entry("tf_C", severity=Severity.CRITICAL),
        _entry("tf_H", severity=Severity.HIGH),
        _entry("tf_M", severity=Severity.MEDIUM),
    ]
    feed, sub = _signed_feed(entries, priv, pub)
    outcomes = apply_feed_entries(feed, sub, posture="managed", skip_fanout=True)
    for o in outcomes:
        assert o.action == "managed_refused"


def test_dry_run_skips_state_mutation():
    priv, pub = ed25519_keygen()
    entries = [_entry("tf_DR", severity=Severity.CRITICAL)]
    feed, sub = _signed_feed(entries, priv, pub)
    outcomes = apply_feed_entries(feed, sub, posture="ambient", dry_run=True, skip_fanout=True)
    assert outcomes[0].action == "auto_apply"
    # Ledger should still be empty.
    assert load_ledger() == []


def test_dedupe_already_applied():
    priv, pub = ed25519_keygen()
    entries = [_entry("tf_DUPE", severity=Severity.CRITICAL)]
    feed, sub = _signed_feed(entries, priv, pub)
    apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    # Re-apply.
    outcomes = apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    assert outcomes[0].action == "refused_already_applied"


def test_revoke_removes_from_ledger_and_records():
    priv, pub = ed25519_keygen()
    entries = [_entry("tf_REVOKE", severity=Severity.CRITICAL)]
    feed, sub = _signed_feed(entries, priv, pub)
    apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    prior = remove_from_ledger("tf_REVOKE")
    assert prior is not None
    # Ledger has both the apply + the revoke record.
    records = load_ledger()
    statuses = [r["status"] for r in records if r.get("rule_id") == "tf_REVOKE"]
    assert "applied" in statuses
    assert "revoked" in statuses


def test_compliance_tags_carried_through_to_ledger():
    priv, pub = ed25519_keygen()
    entries = [_entry("tf_TAGS", severity=Severity.CRITICAL)]
    feed, sub = _signed_feed(entries, priv, pub)
    apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)
    records = load_ledger()
    rec = [r for r in records if r.get("rule_id") == "tf_TAGS"][0]
    assert "NIST-AC-6" in rec["compliance_tags"]
    assert "SOC2-CC6.1" in rec["compliance_tags"]
