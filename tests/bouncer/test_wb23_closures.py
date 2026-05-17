"""Tests for WB23 audit-finding closures + the agent-friendly layer.

Per user direction 2026-05-17: combined audit closures (CRIT-23-01
S3 vhost parser, HIGH-23-01 sub-resource table, HIGH-23-02 matched_rule_id
drop, MEDs, LOWs) with the [[agent-friendly-not-bypassable]] layer
(presets, config-event audit log, MCP tools) in one commit so both
get verified together.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.presets import PRESETS, get_preset, list_preset_names
from iam_jit.bouncer.request_parser import (
    _split_s3_bucket_and_key,
    extract_service_and_region,
    parse_request,
)
from iam_jit.bouncer.rules import _aws_glob_match, _glob_to_regex
from iam_jit.bouncer.store import BouncerStore, InvalidRuleError
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer_cli import main


@pytest.fixture
def db_path(tmp_path) -> str:
    return str(tmp_path / "state.db")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# CRIT-23-01: S3 vhost bucket parser splits on `.s3` substring
# ---------------------------------------------------------------------------


def test_crit_23_01_bucket_with_dots3_in_name() -> None:
    """Regression: buckets containing `.s3` in the name must extract
    correctly, not get truncated at the first `.s3` substring."""
    bucket, key = _split_s3_bucket_and_key(
        host="my.s3.bucket-name.s3.us-east-1.amazonaws.com", path="/key"
    )
    assert bucket == "my.s3.bucket-name"
    assert key == "key"


def test_crit_23_01_attacker_controlled_pseudo_bucket() -> None:
    """The attack vector the audit described: a bucket name whose
    extracted-prefix would have matched a user's allow rule must
    NOT extract that way anymore."""
    bucket, key = _split_s3_bucket_and_key(
        host="my-data.s3.attacker-bucket.s3.us-east-1.amazonaws.com",
        path="/key",
    )
    # Bucket is the FULL string before the S3 vhost suffix
    assert bucket == "my-data.s3.attacker-bucket"


def test_crit_23_01_dualstack_endpoint() -> None:
    bucket, key = _split_s3_bucket_and_key(
        host="my-bucket.s3.dualstack.us-east-1.amazonaws.com", path="/k"
    )
    assert bucket == "my-bucket"
    assert key == "k"


def test_crit_23_01_accelerate_endpoint() -> None:
    bucket, key = _split_s3_bucket_and_key(
        host="my-bucket.s3-accelerate.amazonaws.com", path="/k"
    )
    assert bucket == "my-bucket"


def test_crit_23_01_fips_endpoint() -> None:
    bucket, key = _split_s3_bucket_and_key(
        host="my-bucket.s3-fips.us-east-1.amazonaws.com", path="/k"
    )
    assert bucket == "my-bucket"


def test_crit_23_01_path_style_with_s3_in_path_unchanged() -> None:
    """Path-style requests where the bucket is in the path were
    already correct; verify regression-safe."""
    bucket, key = _split_s3_bucket_and_key(
        host="s3.amazonaws.com", path="/my.s3.bucket-name/key"
    )
    assert bucket == "my.s3.bucket-name"


# ---------------------------------------------------------------------------
# HIGH-23-01: S3 sub-resource table expansion
# ---------------------------------------------------------------------------


def _sigv4(service: str = "s3", region: str = "us-east-1") -> str:
    return (
        f"AWS4-HMAC-SHA256 "
        f"Credential=KEY/20260517/{region}/{service}/aws4_request, "
        f"SignedHeaders=host, Signature=x"
    )


@pytest.mark.parametrize("sub_resource,expected_action", [
    ("tagging", "PutBucketTagging"),
    ("cors", "PutBucketCORS"),
    ("notification", "PutBucketNotification"),
    ("logging", "PutBucketLogging"),
    ("website", "PutBucketWebsite"),
    ("replication", "PutReplicationConfiguration"),
    ("inventory", "PutInventoryConfiguration"),
    ("accelerate", "PutAccelerateConfiguration"),
    ("publicAccessBlock", "PutBucketPublicAccessBlock"),
    ("ownershipControls", "PutBucketOwnershipControls"),
])
def test_high_23_01_s3_sub_resources_resolve_to_put_actions(
    sub_resource: str, expected_action: str,
) -> None:
    out = parse_request(
        method="PUT",
        host="s3.amazonaws.com",
        path="/my-bucket",
        headers={"Authorization": _sigv4()},
        query={sub_resource: ""},
    )
    assert out is not None
    assert out.action == expected_action, (
        f"sub-resource ?{sub_resource} → expected {expected_action}, "
        f"got {out.action}"
    )


def test_high_23_01_object_tagging_via_subresource() -> None:
    out = parse_request(
        method="PUT",
        host="s3.amazonaws.com",
        path="/my-bucket/key.txt",
        headers={"Authorization": _sigv4()},
        query={"tagging": ""},
    )
    assert out is not None
    assert out.action == "PutObjectTagging"


def test_high_23_01_delete_bucket_website() -> None:
    out = parse_request(
        method="DELETE",
        host="s3.amazonaws.com",
        path="/my-bucket",
        headers={"Authorization": _sigv4()},
        query={"website": ""},
    )
    assert out is not None
    assert out.action == "DeleteBucketWebsite"


# ---------------------------------------------------------------------------
# HIGH-23-02: CLI decide --record must persist matched_rule_id
# ---------------------------------------------------------------------------


def test_high_23_02_decide_record_persists_matched_rule_id(
    runner: CliRunner, db_path: str
) -> None:
    runner.invoke(main, ["rules", "add", "s3:GetObject", "--db", db_path])
    runner.invoke(main, [
        "decide", "--service", "s3", "--action", "GetObject",
        "--db", db_path, "--record",
    ])
    store = BouncerStore(db_path=db_path)
    try:
        decisions = store.list_decisions()
        assert len(decisions) == 1
        # The rule id (1, since it was the first rule added) should
        # be persisted — NOT NULL.
        assert decisions[0]["matched_rule_id"] == 1, (
            "WB23 HIGH-23-02 regression: CLI decide --record dropped "
            "the matched_rule_id; audit log records NULL even when "
            "an explicit rule matched."
        )
    finally:
        store.close()


# ---------------------------------------------------------------------------
# MED-23-01: malformed effect doesn't crash list_rules
# ---------------------------------------------------------------------------


def test_med_23_01_malformed_effect_row_is_skipped_not_crashed(tmp_path) -> None:
    """Insert a row with bogus effect directly (simulating a future
    migration or manual DB edit) and confirm list_rules skips it
    instead of crashing the whole listing."""
    import sqlite3
    db = tmp_path / "state.db"
    store = BouncerStore(db_path=db)
    store.add_rule(ProxyRule(pattern="s3:GetObject", effect=Effect.ALLOW))
    # Bypass the store API to inject a corrupt row:
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "INSERT INTO rules(pattern, effect, arn_scope, region_scope, note, origin, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("s3:PutObject", "wat", None, None, None, "user", "2026-05-17T00:00:00Z"),
        )
        conn.commit()
    finally:
        conn.close()
    # list_rules should return the 1 valid row, skipping the bad one
    rules = store.list_rules()
    assert len(rules) == 1
    assert rules[0][1].pattern == "s3:GetObject"
    store.close()


# ---------------------------------------------------------------------------
# MED-23-02: malformed pattern rejected at add time
# ---------------------------------------------------------------------------


def test_med_23_02_store_add_rule_rejects_malformed_pattern(tmp_path) -> None:
    store = BouncerStore(db_path=tmp_path / "x.db")
    with pytest.raises(InvalidRuleError):
        store.add_rule(ProxyRule(pattern="no-colon-here", effect=Effect.ALLOW))
    # Rule was NOT inserted
    assert store.list_rules() == []
    store.close()


def test_med_23_02_cli_rules_add_rejects_malformed(
    runner: CliRunner, db_path: str
) -> None:
    result = runner.invoke(
        main, ["rules", "add", "not-a-valid-pattern", "--db", db_path]
    )
    assert result.exit_code != 0
    assert "rejected" in result.output or "rejected" in (result.stderr or "")


# ---------------------------------------------------------------------------
# MED-23-03: SigV4a recognized
# ---------------------------------------------------------------------------


def test_med_23_03_sigv4a_authorization_parsed() -> None:
    """AWS4-ECDSA-P256-SHA256 (SigV4a) used by S3 Multi-Region Access
    Points must be recognized, not return None."""
    sigv4a = (
        "AWS4-ECDSA-P256-SHA256 "
        "Credential=KEY/20260517/us-east-1/s3/aws4_request, "
        "SignedHeaders=host, Signature=x"
    )
    out = extract_service_and_region(sigv4a)
    assert out == ("s3", "us-east-1")


# ---------------------------------------------------------------------------
# MED-23-04: presigned URL signature in query parameters
# ---------------------------------------------------------------------------


def test_med_23_04_presigned_url_parsed_from_query_params() -> None:
    """Presigned S3 URLs carry the SigV4 in X-Amz-* query params, not
    the Authorization header. Must be classified, not return None."""
    out = extract_service_and_region(
        authorization=None,
        query={
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": "KEY/20260517/us-east-1/s3/aws4_request",
            "X-Amz-Signature": "abc123",
        },
    )
    assert out == ("s3", "us-east-1")


def test_med_23_04_presigned_via_parse_request_end_to_end() -> None:
    out = parse_request(
        method="GET",
        host="my-bucket.s3.amazonaws.com",
        path="/file.txt",
        headers={},
        query={
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": "KEY/20260517/us-east-1/s3/aws4_request",
            "X-Amz-Signature": "abc123",
        },
    )
    assert out is not None
    assert out.service == "s3"
    assert out.action == "GetObject"


def test_med_23_04_anonymous_still_returns_none() -> None:
    """Distinguishing 'truly anonymous' from 'we couldn't parse it'
    is critical for the Stage-2 caller; verify anonymous returns None."""
    out = extract_service_and_region(authorization=None, query={})
    assert out is None


# ---------------------------------------------------------------------------
# LOW-23-02: AWS-glob matching (no fnmatch character classes)
# ---------------------------------------------------------------------------


def test_low_23_02_glob_matches_star() -> None:
    assert _aws_glob_match("GetObject", "Get*")
    assert _aws_glob_match("GetObject", "*")
    assert not _aws_glob_match("PutObject", "Get*")


def test_low_23_02_glob_matches_single_char_qmark() -> None:
    assert _aws_glob_match("Get1Object", "Get?Object")
    assert not _aws_glob_match("Get12Object", "Get?Object")


def test_low_23_02_glob_treats_brackets_as_literal() -> None:
    """fnmatch would have treated [Aa] as a character class — AWS
    glob spec doesn't. Verify literal-bracket semantics."""
    # Literal [Aa] should match only the literal string "[Aa]"
    assert _aws_glob_match("[Aa]", "[Aa]")
    assert not _aws_glob_match("A", "[Aa]")
    assert not _aws_glob_match("a", "[Aa]")


# ---------------------------------------------------------------------------
# Lens B: config-event audit log
# ---------------------------------------------------------------------------


def test_lensb_add_rule_writes_config_event(tmp_path) -> None:
    store = BouncerStore(db_path=tmp_path / "x.db")
    store.add_rule(
        ProxyRule(pattern="s3:GetObject", effect=Effect.ALLOW),
        actor="test-agent",
    )
    events = store.list_config_events()
    assert len(events) == 1
    assert events[0]["kind"] == "rule_added"
    assert events[0]["actor"] == "test-agent"
    assert "s3:GetObject" in events[0]["summary"]
    store.close()


def test_lensb_remove_rule_writes_config_event_with_prior_content(tmp_path) -> None:
    store = BouncerStore(db_path=tmp_path / "x.db")
    rid = store.add_rule(
        ProxyRule(pattern="s3:GetObject", effect=Effect.ALLOW, note="dev access"),
        actor="alice",
    )
    store.remove_rule(rid, actor="bob")
    events = store.list_config_events(kind_filter="rule_removed")
    assert len(events) == 1
    assert events[0]["actor"] == "bob"
    # Prior content captured in detail so audit chain isn't broken
    # by the deletion itself
    assert events[0]["detail"]["pattern"] == "s3:GetObject"
    assert events[0]["detail"]["note"] == "dev access"
    store.close()


def test_lensb_mode_change_writes_config_event(tmp_path) -> None:
    store = BouncerStore(db_path=tmp_path / "x.db")
    store.record_mode_change(
        old_mode="learn", new_mode="enforce", actor="admin", reason="prod ready",
    )
    events = store.list_config_events(kind_filter="mode_changed")
    assert len(events) == 1
    assert "learn -> enforce" in events[0]["summary"]
    assert events[0]["detail"]["reason"] == "prod ready"
    store.close()


def test_lensb_preset_apply_writes_config_event(tmp_path) -> None:
    store = BouncerStore(db_path=tmp_path / "x.db")
    store.record_preset_applied(
        preset_name="readonly", rules_added=23, actor="alice",
    )
    events = store.list_config_events(kind_filter="preset_applied")
    assert len(events) == 1
    assert "readonly" in events[0]["summary"]
    store.close()


def test_lensb_list_config_events_hard_caps_limit(tmp_path) -> None:
    """Cap on extreme limit values, matches list_decisions behavior."""
    store = BouncerStore(db_path=tmp_path / "x.db")
    store.record_mode_change(old_mode="learn", new_mode="enforce", actor="x")
    events = store.list_config_events(limit=10**9)
    assert len(events) == 1
    store.close()


# ---------------------------------------------------------------------------
# Lens A: presets
# ---------------------------------------------------------------------------


def test_presets_list_includes_all_four() -> None:
    names = set(list_preset_names())
    assert names == {
        "readonly",
        "admin-minus-sensitive",
        "prod-deny-destructive",
        "deny-iam-admin",
    }


def test_get_preset_returns_none_for_unknown() -> None:
    assert get_preset("not-a-preset") is None


def test_all_preset_rules_pass_validation(tmp_path) -> None:
    """Every preset rule must be parseable — otherwise applying the
    preset surfaces InvalidRuleError, which would be embarrassing."""
    store = BouncerStore(db_path=tmp_path / "x.db")
    for preset in PRESETS.values():
        for rule in preset.rules:
            try:
                store.add_rule(rule, actor="test")
            except InvalidRuleError as e:
                pytest.fail(f"preset {preset.name!r} rule invalid: {rule.pattern!r}: {e}")
    store.close()


def test_cli_presets_list(runner: CliRunner) -> None:
    result = runner.invoke(main, ["presets", "list"])
    assert result.exit_code == 0
    assert "readonly" in result.output
    assert "admin-minus-sensitive" in result.output


def test_cli_presets_show(runner: CliRunner) -> None:
    result = runner.invoke(main, ["presets", "show", "readonly"])
    assert result.exit_code == 0
    assert "s3:Get*" in result.output


def test_cli_presets_apply_audit_logged(runner: CliRunner, db_path: str) -> None:
    # `--no-default` keeps the audit log slim; this test asserts on a
    # specific preset-apply event, not on every preset event ever.
    runner.invoke(main, ["init", "--db", db_path, "--no-default"])
    result = runner.invoke(
        main, ["presets", "apply", "deny-iam-admin", "--db", db_path]
    )
    assert result.exit_code == 0
    # Verify the deny-iam-admin event specifically (regardless of any
    # other preset events that may exist from the smart default).
    store = BouncerStore(db_path=db_path)
    try:
        events = store.list_config_events(kind_filter="preset_applied")
        deny_iam_events = [e for e in events if e["detail"]["preset_name"] == "deny-iam-admin"]
        assert len(deny_iam_events) == 1
    finally:
        store.close()


def test_cli_init_with_preset(runner: CliRunner, db_path: str) -> None:
    result = runner.invoke(
        main, ["init", "--preset", "readonly", "--db", db_path]
    )
    assert result.exit_code == 0
    assert "applied preset 'readonly'" in result.output
    # Verify rules were added
    store = BouncerStore(db_path=db_path)
    try:
        assert len(store.list_rules()) > 0
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Lens A: CLI events tail command
# ---------------------------------------------------------------------------


def test_cli_events_tail_shows_rule_additions(runner: CliRunner, db_path: str) -> None:
    runner.invoke(main, ["rules", "add", "s3:GetObject", "--db", db_path])
    result = runner.invoke(main, ["events", "tail", "--db", db_path])
    assert result.exit_code == 0
    assert "rule_added" in result.output


def test_cli_events_tail_filter_by_kind(runner: CliRunner, db_path: str) -> None:
    runner.invoke(main, ["init", "--preset", "readonly", "--db", db_path])
    runner.invoke(main, ["rules", "add", "ec2:DescribeInstances", "--db", db_path])
    result = runner.invoke(
        main, ["events", "tail", "--db", db_path, "--kind", "preset_applied"]
    )
    assert result.exit_code == 0
    assert "preset_applied" in result.output
    assert "rule_added" not in result.output


# ---------------------------------------------------------------------------
# LOW-23-04: `iam-jit bouncer` gentle pointer (smoke; full coverage in main test_cli)
# ---------------------------------------------------------------------------


def test_low_23_04_iam_jit_bouncer_subcommand_points_at_standalone() -> None:
    from iam_jit.cli import main as iam_jit_main
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["bouncer"])
    # Should exit non-zero with a pointer to the standalone binary
    assert result.exit_code != 0
    assert "iam-jit-bouncer" in (result.output + (result.stderr or ""))
