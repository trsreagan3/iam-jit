"""#408 / §A52 — CLI + MCP surface tests for `iam-jit updates`."""

from __future__ import annotations

import json
import pathlib
import typing

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
from iam_jit.threat_feed.applier import load_ledger
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


# ---------------------------------------------------------------------------
# §A51b CRIT (#463) — happy + order-of-operations + failure paths.
# Pre-fix: ledger said "revoked" but dynamic-denies.yaml still held the
# rule because remove_rules() was called with kwarg ids= (real arg is
# rule_ids=) so the call raised + the embedded error was hidden behind a
# green "OK revoked" banner. The three tests below pin all three sides
# (state, ordering, error reporting).
# ---------------------------------------------------------------------------


def _dynamic_denies_path(tmp_path: pathlib.Path) -> pathlib.Path:
    # Mirrors the conftest fixture's IAM_JIT_DYNAMIC_DENIES_PATH env.
    return tmp_path / "dynamic-denies.yaml"


def test_cli_updates_revoke_real_ledger_entry_removes_from_dynamic_denies(
    _isolate_threat_feed_dirs: pathlib.Path,
):
    tmp_path = _isolate_threat_feed_dirs
    _populate_ledger("tf_REVOKE_HAPPY")

    # Sanity: the YAML really has a rule attributable to the threat-feed
    # entry before revoke (the apply path writes through to YAML).
    denies_yaml = _dynamic_denies_path(tmp_path).read_text(encoding="utf-8")
    assert "threat-feed:tf_REVOKE_HAPPY" in denies_yaml, (
        f"apply path did not write a rule to YAML; got:\n{denies_yaml!r}"
    )

    runner = CliRunner()
    res = runner.invoke(main, ["updates", "revoke", "tf_REVOKE_HAPPY", "--json"])
    assert res.exit_code == 0, f"unexpected exit {res.exit_code}: {res.output}"

    payload = json.loads(res.output)
    assert payload["ledger_updated"] is True
    assert payload["bouncer_remove"]["removed_count"] == 1, (
        f"expected exactly 1 rule removed from YAML; got: "
        f"{payload['bouncer_remove']!r}"
    )

    # The YAML must now be free of the rule. This is the §A51b smoke
    # signal — operator must be able to undo an applied threat-feed
    # entry.
    after = _dynamic_denies_path(tmp_path).read_text(encoding="utf-8")
    assert "threat-feed:tf_REVOKE_HAPPY" not in after, (
        f"YAML still contains the rule after revoke; got:\n{after!r}"
    )

    # Ledger has both apply + revoke records (append-only).
    statuses = [
        r["status"] for r in load_ledger()
        if r.get("rule_id") == "tf_REVOKE_HAPPY"
    ]
    assert "applied" in statuses
    assert "revoked" in statuses


def test_cli_updates_revoke_human_output_has_no_embedded_error(
    monkeypatch: pytest.MonkeyPatch,
    _isolate_threat_feed_dirs: pathlib.Path,
):
    # Pre-fix the human-readable path printed:
    #   OK  revoked tf_X
    #     bouncer remove: {'error': "remove_rules() got an unexpected
    #         keyword argument 'ids'"}
    # i.e. green OK banner masking an internal traceback. Pin that the
    # success path never leaks Python-internal error patterns in the
    # human output. We monkey-patch fanout_reload to return [] so the
    # honest "downstream bouncer unreachable" notice (legitimate per
    # [[ibounce-honest-positioning]]) doesn't fight this assertion.
    from iam_jit.dynamic_denies import fanout

    monkeypatch.setattr(fanout, "fanout_reload", lambda *a, **k: [])

    _populate_ledger("tf_REVOKE_HUMAN")
    runner = CliRunner()
    res = runner.invoke(main, ["updates", "revoke", "tf_REVOKE_HUMAN"])
    assert res.exit_code == 0, f"unexpected exit {res.exit_code}: {res.output}"
    combined = (res.output + (res.stderr or "")).lower()
    # Specific patterns that the pre-fix bug surfaced:
    assert "unexpected keyword argument" not in combined
    assert "traceback" not in combined
    assert "exception" not in combined
    # The dict-leak from the legacy `{'error': ...}` shape.
    assert "{'error'" not in combined
    # No bare "error:" prefix in the success path.
    assert "error:" not in combined


def test_cli_updates_revoke_ledger_only_records_after_bouncer_remove_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    _isolate_threat_feed_dirs: pathlib.Path,
):
    # Per [[ibounce-honest-positioning]] the ledger must NEVER advertise
    # status=revoked when the bouncer-side removal blew up. Force a
    # failure by monkey-patching remove_rules to raise + verify the
    # ledger has no `revoked` record afterwards.
    _populate_ledger("tf_REVOKE_ORDER")

    from iam_jit.dynamic_denies import operations as ops

    def _boom(*_args: typing.Any, **_kwargs: typing.Any) -> typing.NoReturn:
        raise ops.DenyOperationError("simulated bouncer write failure", code="boom")

    monkeypatch.setattr(ops, "remove_rules", _boom)

    runner = CliRunner()
    res = runner.invoke(main, ["updates", "revoke", "tf_REVOKE_ORDER"])
    assert res.exit_code != 0, (
        f"failure path must exit non-zero; got {res.exit_code}: {res.output}"
    )

    # Ledger has the apply record but NOT a revoked record.
    statuses = [
        r["status"] for r in load_ledger()
        if r.get("rule_id") == "tf_REVOKE_ORDER"
    ]
    assert "applied" in statuses
    assert "revoked" not in statuses, (
        f"ledger falsely shows 'revoked' after bouncer removal failed; "
        f"violates [[ibounce-honest-positioning]]; statuses={statuses!r}"
    )


def test_cli_updates_revoke_bouncer_failure_emits_clear_error_no_ledger_update(
    monkeypatch: pytest.MonkeyPatch,
    _isolate_threat_feed_dirs: pathlib.Path,
):
    # Same setup as the ordering test, but verify the operator-facing
    # output explicitly says revoke was aborted + the rule is still
    # active — no green "OK" banner.
    _populate_ledger("tf_REVOKE_FAIL")

    from iam_jit.dynamic_denies import operations as ops

    def _boom(*_args: typing.Any, **_kwargs: typing.Any) -> typing.NoReturn:
        raise ops.DenyOperationError("simulated bouncer write failure", code="boom")

    monkeypatch.setattr(ops, "remove_rules", _boom)

    runner = CliRunner()
    res = runner.invoke(
        main,
        ["updates", "revoke", "tf_REVOKE_FAIL", "--json"],
    )
    assert res.exit_code != 0
    payload = json.loads(res.output)
    assert payload["ledger_updated"] is False
    assert "simulated bouncer write failure" in payload["error"]


def test_cli_updates_revoke_no_artifact_still_records_revoke(
    _isolate_threat_feed_dirs: pathlib.Path,
):
    # When the prior action wasn't an auto-apply (e.g. pending_approval
    # / informational) there's no dynamic-deny artifact to remove. The
    # revoke should still mark the ledger so the operator can clear the
    # queue without us pretending a bouncer mutation happened.
    _populate_ledger("tf_REVOKE_INFO", severity=Severity.LOW)
    runner = CliRunner()
    res = runner.invoke(main, ["updates", "revoke", "tf_REVOKE_INFO", "--json"])
    assert res.exit_code == 0, f"unexpected exit: {res.output}"
    payload = json.loads(res.output)
    assert payload["ledger_updated"] is True
    assert payload["bouncer_remove"] == {}


def test_mcp_updates_recent_returns_records():
    _populate_ledger("tf_MCP_R")
    payload = updates_recent_for_mcp({})
    assert payload["status"] == "ok"
    assert any(r["rule_id"] == "tf_MCP_R" for r in payload["records"])


def test_mcp_update_status_no_subscriptions():
    payload = update_status_for_mcp({})
    assert payload["status"] == "ok"
    assert payload["feeds"] == []
