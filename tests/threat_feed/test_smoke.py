"""#407-#411 / §A51-§A55 — End-to-end Phase C smoke test.

Exercises the full publish → sign → pin → dry-run → apply → autopilot →
managed-refusal flow in a single test so a future PR that breaks any
joint surfaces it immediately.

Per the brief's "Smoke tests" section. Hermetic — uses an ephemeral
publisher keypair + a file:// feed URL so no network is required.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from iam_jit.autopilot.daemon import AutopilotSupervisor
from iam_jit.threat_feed import (
    Severity,
    apply_feed_entries,
    ed25519_keygen,
    ed25519_sign_entry,
    fetch_feed,
    load_subscriptions_from_declaration,
)
from iam_jit.threat_feed.applier import load_ledger, remove_from_ledger
from iam_jit.threat_feed.models import Feed, FeedEntry
from iam_jit.threat_feed.publisher import (
    bundle_entries,
    publisher_init,
    sign_rule_file,
    verify_bundle,
    write_bundle,
)


def test_full_phase_c_flow(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    # 1. Publisher init (ephemeral keypair under tmp_path).
    keypair = publisher_init(out_dir=tmp_path / "keys", publisher="smoke-test")
    priv_pem = keypair.private_pem_path.read_text()
    short_pub = keypair.short_form_pubkey

    # 2. Author 3 rule files (CRITICAL / HIGH / MEDIUM).
    rules = [
        ("crit.json", "tf_SMOKE_CRIT", "CRITICAL", "iam:AttachRolePolicy"),
        ("high.json", "tf_SMOKE_HIGH", "HIGH", "s3:PutBucketAcl"),
        ("med.json", "tf_SMOKE_MED", "MEDIUM", "logs:DeleteLogGroup"),
    ]
    signed_paths = []
    for fname, rid, sev, action in rules:
        rf = tmp_path / fname
        rf.write_text(json.dumps({
            "rule_id": rid,
            "rule_kind": "dynamic_deny",
            "target": "arn:aws:iam::*:role/agent-*",
            "action": [action],
            "severity": sev,
            "source_incident": "SMOKE-INCIDENT",
            "discovered_at": "2026-05-23T10:00:00Z",
            "applies_to_bouncers": ["ibounce"],
            "compliance_tags": ["NIST-AC-6", "SOC2-CC6.1"],
        }))
        signed = sign_rule_file(rf, private_key_pem=priv_pem, publisher="smoke-test")
        sp = tmp_path / f"signed_{fname}"
        sp.write_text(json.dumps(signed.as_dict(), indent=2))
        signed_paths.append(sp)

    # 3. Bundle and write to a feed.json.
    from iam_jit.threat_feed.models import parse_feed_entry
    signed_entries = [
        parse_feed_entry(json.loads(p.read_text())) for p in signed_paths
    ]
    feed = bundle_entries(
        signed_entries, feed_id="smoke-v1", publisher="smoke-test",
    )
    feed_path = tmp_path / "feed.json"
    write_bundle(feed, feed_path)

    # 4. Verify bundle.
    result = verify_bundle(feed_path, pubkey=short_pub)
    assert result.all_verified
    assert result.verified == 3

    # 5. "Pin" — build a declaration manually pointing at the file:// URL.
    declaration = {
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {},
            "threat_feed": {
                "enabled": True,
                "update_cadence": "daily",
                "feeds": [{
                    "url": f"file://{feed_path}",
                    "publisher_pubkey": short_pub,
                    "severity_auto_apply_threshold": "HIGH",
                    "nickname": "smoke",
                }],
            },
        },
    }
    subs, _ = load_subscriptions_from_declaration(declaration)
    assert len(subs) == 1

    # 6. Dry-run via the applier.
    fetch_result = fetch_feed(subs[0].url)
    assert fetch_result.feed is not None
    dry_outcomes = apply_feed_entries(
        fetch_result.feed, subs[0], posture="ambient",
        dry_run=True, skip_fanout=True,
    )
    assert {o.action for o in dry_outcomes} == {
        "auto_apply",  # CRITICAL
        "auto_apply_notify",  # HIGH
        "pending_approval",  # MEDIUM
    }
    # Ledger should still be empty (dry-run).
    assert load_ledger() == []

    # 7. Apply for real.
    outcomes = apply_feed_entries(
        fetch_result.feed, subs[0], posture="ambient", skip_fanout=True,
    )
    assert len(outcomes) == 3
    ledger = load_ledger()
    rids = {r["rule_id"]: r for r in ledger if r["status"] == "applied"}
    assert "tf_SMOKE_CRIT" in rids
    assert "tf_SMOKE_HIGH" in rids
    # CRITICAL + HIGH should have artifact_ids (real dd_ rules).
    assert rids["tf_SMOKE_CRIT"]["applied_artifact_id"].startswith("dd_")
    assert rids["tf_SMOKE_HIGH"]["applied_artifact_id"].startswith("dd_")
    # MEDIUM goes through pending queue.
    med_rec = [r for r in ledger if r.get("rule_id") == "tf_SMOKE_MED" and r["status"] == "applied"][0]
    assert med_rec["action"] == "pending_approval"
    assert med_rec["pending_entry_id"].startswith("pa_")
    # Compliance tags carried through.
    assert "NIST-AC-6" in med_rec["compliance_tags"]

    # 8. Autopilot tick exercises the same path (cadence-safe via
    # zeroing the timers).
    sup = AutopilotSupervisor(
        declaration=declaration,
        config_source="smoke",
        sweep_interval_s=0.01,
    )
    sup.started_at = 0.0
    sup.last_threat_feed_at = 0.0
    results = sup.run_threat_feed_for_all()
    assert len(results) == 1
    # Already-applied entries should be deduped.
    assert results[0]["already_applied"] == 3

    # 9. Managed-posture flow REFUSES auto-apply.
    sup_mgr = AutopilotSupervisor(
        declaration={**declaration, "iam-jit": {**declaration["iam-jit"], "posture": "managed"}},
        config_source="smoke-managed",
        sweep_interval_s=0.01,
    )
    sup_mgr.started_at = 0.0
    sup_mgr.last_threat_feed_at = 0.0
    # Use a fresh feed so we're not blocked by already-applied dedupe.
    rules2 = [
        ("crit2.json", "tf_SMOKE_MGR_CRIT", "CRITICAL", "iam:AttachRolePolicy"),
    ]
    signed_paths2 = []
    for fname, rid, sev, action in rules2:
        rf = tmp_path / fname
        rf.write_text(json.dumps({
            "rule_id": rid,
            "rule_kind": "dynamic_deny",
            "target": "arn:aws:iam::*:role/agent-*",
            "action": [action],
            "severity": sev,
            "source_incident": "MGR-SMOKE",
            "discovered_at": "2026-05-23T10:00:00Z",
            "applies_to_bouncers": ["ibounce"],
            "compliance_tags": ["NIST-AC-6"],
        }))
        signed = sign_rule_file(rf, private_key_pem=priv_pem, publisher="smoke-test")
        sp = tmp_path / f"signed_{fname}"
        sp.write_text(json.dumps(signed.as_dict(), indent=2))
        signed_paths2.append(sp)
    signed_entries2 = [
        parse_feed_entry(json.loads(p.read_text())) for p in signed_paths2
    ]
    feed2 = bundle_entries(
        signed_entries2, feed_id="smoke-v1-mgr", publisher="smoke-test",
    )
    feed2_path = tmp_path / "feed_mgr.json"
    write_bundle(feed2, feed2_path)
    declaration_mgr = {
        "iam-jit": {
            "enabled": True,
            "posture": "managed",
            "bouncers": {},
            "threat_feed": {
                "enabled": True,
                "update_cadence": "daily",
                "feeds": [{
                    "url": f"file://{feed2_path}",
                    "publisher_pubkey": short_pub,
                    "severity_auto_apply_threshold": "HIGH",
                }],
            },
        },
    }
    sup_mgr.declaration = declaration_mgr
    results_mgr = sup_mgr.run_threat_feed_for_all()
    assert len(results_mgr) == 1
    assert results_mgr[0]["managed_refused"] >= 1
    assert results_mgr[0]["applied"] == 0


def test_bootstrap_feed_verifies_with_pinned_pubkey():
    """The committed `feeds/official-v1.json` must verify against the
    committed `feeds/official-v1.pubkey`. Lets us catch a botched
    rebuild before it lands."""
    import pathlib
    bundle = pathlib.Path(__file__).resolve().parents[2] / "feeds" / "official-v1.json"
    pubkey_file = bundle.parent / "official-v1.pubkey"
    if not (bundle.exists() and pubkey_file.exists()):
        pytest.skip("bootstrap feed not present")
    pubkey = pubkey_file.read_text().strip()
    result = verify_bundle(bundle, pubkey=pubkey)
    assert result.all_verified, (
        f"bootstrap bundle {bundle} failed verification: "
        f"{result.failed}/{result.entry_count} entries failed; "
        f"sample failures: {result.failures[:3]}"
    )
    # Spot-check: every entry carries at least one compliance tag.
    raw = json.loads(bundle.read_text())
    for entry in raw["entries"]:
        assert entry["compliance_tags"], (
            f"entry {entry['rule_id']} has no compliance_tags; per #441 Sysdig "
            f"research every entry MUST carry them"
        )
