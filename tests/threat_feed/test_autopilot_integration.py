"""#411 / §A55 — Autopilot threat-feed integration tests."""

from __future__ import annotations

import json
import pathlib

import pytest

from iam_jit.autopilot.daemon import AutopilotSupervisor
from iam_jit.threat_feed import (
    Severity,
    ed25519_keygen,
    ed25519_sign_entry,
)
from iam_jit.threat_feed.models import FeedEntry
from iam_jit.threat_feed.publisher import bundle_entries, write_bundle


def _build_signed_feed_file(tmp_path: pathlib.Path) -> tuple[pathlib.Path, str]:
    """Build a tiny signed feed bundle on disk + return (path, pubkey)."""
    priv, pub = ed25519_keygen()
    entry = FeedEntry(
        rule_id="tf_AUTOPILOT_TEST",
        rule_kind="dynamic_deny",
        target="arn:aws:iam::*:role/agent-*",
        action=("iam:AttachRolePolicy",),
        severity=Severity.CRITICAL,
        source_incident="TEST",
        discovered_at="2026-05-23T10:00:00Z",
        applies_to_bouncers=("ibounce",),
        compliance_tags=("NIST-AC-6",),
    )
    signed = ed25519_sign_entry(entry, private_key_pem=priv, publisher="test")
    feed = bundle_entries([signed], feed_id="autopilot-test", publisher="test")
    feed_path = tmp_path / "feed.json"
    write_bundle(feed, feed_path)
    return feed_path, pub


def _supervisor(declaration: dict, *, posture: str = "ambient") -> AutopilotSupervisor:
    declaration.setdefault("iam-jit", {})
    declaration["iam-jit"].setdefault("enabled", True)
    declaration["iam-jit"].setdefault("posture", posture)
    declaration["iam-jit"].setdefault("bouncers", {})
    return AutopilotSupervisor(
        declaration=declaration,
        config_source="test",
        sweep_interval_s=0.01,
    )


def test_no_threat_feed_block_returns_empty(tmp_path):
    sup = _supervisor({"iam-jit": {}})
    assert sup._threat_feed_due() is False
    assert sup.run_threat_feed_for_all() == []


def test_threat_feed_disabled_skipped(tmp_path):
    feed_path, pub = _build_signed_feed_file(tmp_path)
    sup = _supervisor({"iam-jit": {"threat_feed": {
        "enabled": False,
        "feeds": [{"url": f"file://{feed_path}", "publisher_pubkey": pub}],
    }}})
    assert sup._threat_feed_due() is False


def test_threat_feed_first_tick_deferred_until_cadence_elapses(tmp_path):
    feed_path, pub = _build_signed_feed_file(tmp_path)
    sup = _supervisor({"iam-jit": {"threat_feed": {
        "enabled": True,
        "update_cadence": "weekly",
        "feeds": [{"url": f"file://{feed_path}", "publisher_pubkey": pub}],
    }}})
    # First tick: not due yet (anchored off start).
    assert sup._threat_feed_due() is False


def test_threat_feed_runs_with_on_demand_zero_cadence(tmp_path):
    """on_demand has infinite interval — never auto-due."""
    feed_path, pub = _build_signed_feed_file(tmp_path)
    sup = _supervisor({"iam-jit": {"threat_feed": {
        "enabled": True,
        "update_cadence": "on_demand",
        "feeds": [{"url": f"file://{feed_path}", "publisher_pubkey": pub}],
    }}})
    assert sup._threat_feed_due() is False


def test_threat_feed_force_run_applies_critical(tmp_path):
    feed_path, pub = _build_signed_feed_file(tmp_path)
    sup = _supervisor({"iam-jit": {"threat_feed": {
        "enabled": True,
        "feeds": [{
            "url": f"file://{feed_path}",
            "publisher_pubkey": pub,
            "severity_auto_apply_threshold": "HIGH",
        }],
    }}})
    results = sup.run_threat_feed_for_all()
    assert len(results) == 1
    r = results[0]
    assert r["status"] in ("ok", "ok_cached")
    assert r["applied"] >= 1


def test_threat_feed_managed_posture_refused(tmp_path):
    feed_path, pub = _build_signed_feed_file(tmp_path)
    sup = _supervisor(
        {"iam-jit": {"threat_feed": {
            "enabled": True,
            "feeds": [{
                "url": f"file://{feed_path}",
                "publisher_pubkey": pub,
                "severity_auto_apply_threshold": "HIGH",
            }],
        }}},
        posture="managed",
    )
    results = sup.run_threat_feed_for_all()
    assert len(results) == 1
    r = results[0]
    assert r["managed_refused"] >= 1
    assert r["applied"] == 0


def test_threat_feed_fetch_failure_recorded(tmp_path):
    sup = _supervisor({"iam-jit": {"threat_feed": {
        "enabled": True,
        "feeds": [{
            "url": f"file://{tmp_path}/nonexistent.json",
            "publisher_pubkey": "ed25519:not-a-real-key",
        }],
    }}})
    results = sup.run_threat_feed_for_all()
    assert len(results) == 1
    r = results[0]
    assert r["status"] in ("unavailable", "fetch_error")


def test_threat_feed_status_surfaces_in_run_once(tmp_path, monkeypatch):
    # Don't try to start any bouncers — empty bouncer config.
    feed_path, pub = _build_signed_feed_file(tmp_path)
    sup = _supervisor({"iam-jit": {"threat_feed": {
        "enabled": True,
        "feeds": [{"url": f"file://{feed_path}", "publisher_pubkey": pub}],
    }}})
    # Force the threat-feed to run by zeroing the timer.
    sup.last_threat_feed_at = 0.0
    sup.started_at = 0.0  # makes _threat_feed_due() return True immediately

    # Stub posture detectors so health check doesn't try real probes.
    for name in ("detect_ibounce", "detect_kbounce", "detect_dbounce", "detect_gbounce"):
        monkeypatch.setattr(
            f"iam_jit.posture.bouncers.{name}",
            lambda: {"running": False},
        )

    status = sup.run_once()
    assert status.threat_feed["enabled"] is True
    assert status.threat_feed["subscription_count"] == 1
    assert isinstance(status.threat_feed["last_results"], list)
    assert len(status.threat_feed["last_results"]) == 1
