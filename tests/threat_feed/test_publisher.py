"""#409 / §A53 — Publisher tooling tests.

Per [[push-policy-public-repo]] the private key is only ever
generated under ``tmp_path`` (auto-cleaned, outside the repo).
"""

from __future__ import annotations

import json
import pathlib

import pytest

from iam_jit.threat_feed import Severity
from iam_jit.threat_feed.publisher import (
    PublisherError,
    bundle_entries,
    publisher_init,
    sign_rule_file,
    verify_bundle,
    write_bundle,
)


def test_publisher_init_writes_keypair(tmp_path: pathlib.Path):
    res = publisher_init(out_dir=tmp_path / "keys", publisher="test-publisher")
    assert res.private_pem_path.exists()
    assert res.public_pem_path.exists()
    assert res.public_short_path.exists()
    assert res.short_form_pubkey.startswith("ed25519:")
    # Private key permissions should be tight.
    import stat
    perm = stat.S_IMODE(res.private_pem_path.stat().st_mode)
    assert perm & 0o077 == 0  # group/other have no perms


def test_publisher_init_refuses_overwrite_without_flag(tmp_path: pathlib.Path):
    publisher_init(out_dir=tmp_path / "keys", publisher="p1")
    with pytest.raises(PublisherError):
        publisher_init(out_dir=tmp_path / "keys", publisher="p2")


def test_publisher_init_overwrite_flag_allowed(tmp_path: pathlib.Path):
    publisher_init(out_dir=tmp_path / "keys", publisher="p1")
    res = publisher_init(out_dir=tmp_path / "keys", publisher="p2", overwrite=True)
    assert res.publisher == "p2"


def test_sign_rule_file_json(tmp_path: pathlib.Path):
    res = publisher_init(out_dir=tmp_path / "keys", publisher="test-pub")
    priv_pem = res.private_pem_path.read_text()
    rule_file = tmp_path / "rule.json"
    rule_file.write_text(json.dumps({
        "rule_id": "tf_A",
        "rule_kind": "dynamic_deny",
        "target": "arn:aws:s3:::x",
        "action": ["s3:DeleteObject"],
        "severity": "HIGH",
        "source_incident": "CVE-2025-X",
        "discovered_at": "2026-05-23T10:00:00Z",
        "applies_to_bouncers": ["ibounce"],
        "compliance_tags": ["NIST-AC-6"],
    }))
    signed = sign_rule_file(
        rule_file, private_key_pem=priv_pem, publisher="test-pub",
    )
    assert signed.signature["algorithm"] == "ed25519"
    assert signed.signature["publisher"] == "test-pub"
    assert signed.severity == Severity.HIGH


def test_sign_rule_file_yaml(tmp_path: pathlib.Path):
    res = publisher_init(out_dir=tmp_path / "keys", publisher="test-pub")
    priv_pem = res.private_pem_path.read_text()
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(
        "rule_id: tf_B\n"
        "rule_kind: dynamic_deny\n"
        "target: 'arn:aws:s3:::x'\n"
        "action:\n  - s3:DeleteObject\n"
        "severity: CRITICAL\n"
        "compliance_tags:\n  - SOC2-CC6.1\n"
    )
    signed = sign_rule_file(rule_file, private_key_pem=priv_pem, publisher="test-pub")
    assert signed.severity == Severity.CRITICAL


def test_bundle_and_verify_roundtrip(tmp_path: pathlib.Path):
    res = publisher_init(out_dir=tmp_path / "keys", publisher="test-pub")
    priv_pem = res.private_pem_path.read_text()
    pub_pem = res.public_pem_path.read_text()
    # Create two rules.
    rule_files = []
    for i in range(2):
        rf = tmp_path / f"rule_{i}.json"
        rf.write_text(json.dumps({
            "rule_id": f"tf_{i}",
            "rule_kind": "dynamic_deny",
            "target": f"arn:aws:s3:::bucket-{i}",
            "action": ["s3:DeleteObject"],
            "severity": "HIGH",
            "compliance_tags": ["NIST-AC-6"],
        }))
        rule_files.append(rf)
    signed = [
        sign_rule_file(rf, private_key_pem=priv_pem, publisher="test-pub")
        for rf in rule_files
    ]
    feed = bundle_entries(signed, feed_id="test-feed-v1", publisher="test-pub")
    bundle_path = tmp_path / "feed.json"
    write_bundle(feed, bundle_path)
    assert bundle_path.exists()
    result = verify_bundle(bundle_path, pubkey=pub_pem)
    assert result.all_verified
    assert result.verified == 2
    assert result.failed == 0


def test_verify_bundle_with_wrong_pubkey_fails(tmp_path: pathlib.Path):
    res = publisher_init(out_dir=tmp_path / "keys-a", publisher="pub-a")
    res2 = publisher_init(out_dir=tmp_path / "keys-b", publisher="pub-b")
    priv_pem = res.private_pem_path.read_text()
    pub_pem_other = res2.public_pem_path.read_text()
    rf = tmp_path / "r.json"
    rf.write_text(json.dumps({
        "rule_id": "tf_X",
        "rule_kind": "dynamic_deny",
        "severity": "HIGH",
        "compliance_tags": [],
    }))
    signed = sign_rule_file(rf, private_key_pem=priv_pem, publisher="pub-a")
    feed = bundle_entries([signed], feed_id="f", publisher="pub-a")
    bp = tmp_path / "b.json"
    write_bundle(feed, bp)
    result = verify_bundle(bp, pubkey=pub_pem_other)
    assert not result.all_verified
    assert result.failed == 1
