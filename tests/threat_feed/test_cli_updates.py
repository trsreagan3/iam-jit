"""#408 / §A52 — CLI + MCP surface tests for `iam-jit updates`."""

from __future__ import annotations

import json
import pathlib

import pytest
from click.testing import CliRunner

from iam_jit.cli import main
from iam_jit.cli_updates import update_status_for_mcp, updates_recent_for_mcp
from iam_jit.threat_feed import (
    Severity,
    Subscription,
    apply_feed_entries,
    ed25519_keygen,
    ed25519_sign_entry,
)
from iam_jit.threat_feed.models import Feed, FeedEntry


def _entry(rule_id: str, severity: Severity = Severity.CRITICAL) -> FeedEntry:
    return FeedEntry(
        rule_id=rule_id,
        rule_kind="dynamic_deny",
        target="arn:aws:iam::*:role/agent-*",
        action=("iam:AttachRolePolicy",),
        severity=severity,
        source_incident="CVE-X",
        discovered_at="2026-05-23T10:00:00Z",
        applies_to_bouncers=("ibounce",),
        compliance_tags=("NIST-AC-6",),
    )


def _populate_ledger(rule_id: str = "tf_LEDGER", severity: Severity = Severity.CRITICAL) -> None:
    priv, pub = ed25519_keygen()
    signed = ed25519_sign_entry(_entry(rule_id, severity), private_key_pem=priv, publisher="t")
    feed = Feed(
        schema_version="1.0",
        feed_id="test",
        publisher="t",
        generated_at="2026-05-23T10:00:00Z",
        entries=(signed,),
    )
    sub = Subscription(
        url="file:///tmp/x",
        publisher_pubkey=pub,
        severity_auto_apply_threshold=Severity.HIGH,
    )
    apply_feed_entries(feed, sub, posture="ambient", skip_fanout=True)


def test_cli_updates_list_empty():
    runner = CliRunner()
    res = runner.invoke(main, ["updates", "list", "--json"])
    assert res.exit_code == 0
    payload = json.loads(res.output)
    assert payload["count"] == 0


def test_cli_updates_list_after_apply():
    _populate_ledger("tf_CLI_LIST")
    runner = CliRunner()
    res = runner.invoke(main, ["updates", "list", "--json"])
    assert res.exit_code == 0
    payload = json.loads(res.output)
    assert payload["count"] >= 1
    assert any(r["rule_id"] == "tf_CLI_LIST" for r in payload["records"])


def test_cli_updates_list_severity_filter():
    _populate_ledger("tf_CRIT_X", severity=Severity.CRITICAL)
    runner = CliRunner()
    res = runner.invoke(main, ["updates", "list", "--severity", "HIGH", "--json"])
    payload = json.loads(res.output)
    assert all(r["severity"] in ("CRITICAL", "HIGH") for r in payload["records"])


def test_cli_updates_pin_emits_yaml_snippet():
    runner = CliRunner()
    res = runner.invoke(main, ["updates", "pin", "https://x", "ed25519:abc", "--json"])
    assert res.exit_code == 0
    payload = json.loads(res.output)
    feeds = payload["iam-jit"]["threat_feed"]["feeds"]
    assert feeds[0]["url"] == "https://x"
    assert feeds[0]["publisher_pubkey"] == "ed25519:abc"


def test_cli_updates_last_fetch_lists_subscriptions():
    runner = CliRunner()
    # No declaration in cwd -> empty subscriptions.
    res = runner.invoke(main, ["updates", "last-fetch", "--json"])
    assert res.exit_code == 0
    payload = json.loads(res.output)
    assert payload["feeds"] == []


def test_cli_updates_revoke_unknown_id():
    runner = CliRunner()
    res = runner.invoke(main, ["updates", "revoke", "tf_DOES_NOT_EXIST"])
    assert res.exit_code != 0


def test_mcp_updates_recent_returns_records():
    _populate_ledger("tf_MCP_R")
    payload = updates_recent_for_mcp({})
    assert payload["status"] == "ok"
    assert any(r["rule_id"] == "tf_MCP_R" for r in payload["records"])


def test_mcp_update_status_no_subscriptions():
    payload = update_status_for_mcp({})
    assert payload["status"] == "ok"
    assert payload["feeds"] == []
