"""#407 / §A51 — Threat-feed dataclass + parsing tests."""

from __future__ import annotations

import pytest

from iam_jit.threat_feed import Severity
from iam_jit.threat_feed.models import (
    FeedParseError,
    parse_feed_dict,
    parse_feed_entry,
    severity_at_or_above,
    severity_from_str,
)


def test_severity_ordering_total():
    assert severity_at_or_above(Severity.CRITICAL, Severity.LOW)
    assert severity_at_or_above(Severity.HIGH, Severity.HIGH)
    assert not severity_at_or_above(Severity.LOW, Severity.MEDIUM)
    assert not severity_at_or_above(Severity.MEDIUM, Severity.HIGH)


def test_severity_from_str_case_insensitive():
    assert severity_from_str("critical") == Severity.CRITICAL
    assert severity_from_str("  HIGH  ") == Severity.HIGH
    assert severity_from_str(Severity.LOW) == Severity.LOW


def test_severity_from_str_rejects_unknown():
    with pytest.raises(ValueError):
        severity_from_str("URGENT")


def test_parse_feed_entry_minimum_fields():
    raw = {
        "rule_id": "tf_X",
        "rule_kind": "dynamic_deny",
        "severity": "MEDIUM",
    }
    e = parse_feed_entry(raw)
    assert e.rule_id == "tf_X"
    assert e.severity == Severity.MEDIUM
    assert e.target == ""
    assert tuple(e.action) == ()


def test_parse_feed_entry_with_full_fields():
    raw = {
        "rule_id": "tf_Y",
        "rule_kind": "dynamic_deny",
        "target": "arn:aws:s3:::x",
        "action": ["s3:DeleteObject"],
        "severity": "CRITICAL",
        "source_incident": "CVE-2025-XYZ",
        "discovered_at": "2026-05-23T10:00:00Z",
        "applies_to_bouncers": ["ibounce"],
        "compliance_tags": ["NIST-AC-6", "SOC2-CC6.1"],
        "description": "test",
        "signature": {"algorithm": "ed25519", "value": "x"},
    }
    e = parse_feed_entry(raw)
    assert e.target == "arn:aws:s3:::x"
    assert tuple(e.action) == ("s3:DeleteObject",)
    assert tuple(e.compliance_tags) == ("NIST-AC-6", "SOC2-CC6.1")
    assert e.signature["algorithm"] == "ed25519"


def test_parse_feed_entry_rejects_non_dict():
    with pytest.raises(FeedParseError):
        parse_feed_entry([])  # type: ignore[arg-type]


def test_parse_feed_dict_smoke():
    raw = {
        "schema_version": "1.0",
        "feed_id": "test-v1",
        "publisher": "test-publisher",
        "generated_at": "2026-05-23T10:00:00Z",
        "entries": [
            {
                "rule_id": "tf_A",
                "rule_kind": "informational_alert",
                "severity": "LOW",
            },
        ],
        "manifest_sha256": "abc",
    }
    feed = parse_feed_dict(raw)
    assert feed.feed_id == "test-v1"
    assert len(feed.entries) == 1


def test_parse_feed_dict_rejects_bad_entries_list():
    raw = {
        "schema_version": "1.0",
        "feed_id": "test",
        "entries": "not-a-list",
    }
    with pytest.raises(FeedParseError):
        parse_feed_dict(raw)
