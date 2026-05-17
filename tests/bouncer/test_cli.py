"""Tests for the iam-jit-bouncer CLI surface."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer_cli import main


@pytest.fixture
def db_path(tmp_path) -> str:
    return str(tmp_path / "state.db")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def test_init_creates_db(runner: CliRunner, db_path: str) -> None:
    result = runner.invoke(main, ["init", "--db", db_path])
    assert result.exit_code == 0
    assert "bouncer initialized at" in result.output


# ---------------------------------------------------------------------------
# Smart-default behavior — per [[proxy-smart-defaults-and-task-scope]]
# ---------------------------------------------------------------------------


def test_init_applies_protective_default_on_fresh_store(
    runner: CliRunner, db_path: str
) -> None:
    """Fresh install gets admin-minus-sensitive baseline (deny on
    secrets / IAM admin / billing / audit-infra destruction)."""
    result = runner.invoke(main, ["init", "--db", db_path])
    assert result.exit_code == 0
    assert "applied protective default" in result.output
    assert "admin-minus-sensitive" in result.output
    # Verify rules actually loaded
    store = BouncerStore(db_path=db_path)
    rules = store.list_rules()
    assert len(rules) > 0
    # The deny set should be present
    patterns = {r.pattern for _, r in rules}
    assert "iam:DeleteRole" in patterns
    assert "secretsmanager:GetSecretValue" in patterns


def test_init_no_default_skips_baseline(runner: CliRunner, db_path: str) -> None:
    result = runner.invoke(main, ["init", "--db", db_path, "--no-default"])
    assert result.exit_code == 0
    assert "skipped protective default" in result.output
    store = BouncerStore(db_path=db_path)
    assert len(store.list_rules()) == 0


def test_init_with_explicit_preset_skips_default(
    runner: CliRunner, db_path: str
) -> None:
    """An explicit --preset overrides the default — agent gets exactly
    what they asked for, not default + extras."""
    result = runner.invoke(main, [
        "init", "--db", db_path, "--preset", "readonly",
    ])
    assert result.exit_code == 0
    assert "applied preset 'readonly'" in result.output
    # admin-minus-sensitive rules should NOT have been added
    store = BouncerStore(db_path=db_path)
    patterns = {r.pattern for _, r in store.list_rules()}
    # readonly preset doesn't have iam:* deny patterns like admin-minus-sensitive does
    assert "iam:DeleteRole" not in patterns


def test_init_on_non_empty_store_is_default_noop(
    runner: CliRunner, db_path: str
) -> None:
    """Re-running init after rules already exist preserves them and
    skips the protective default."""
    # First call seeds the default
    runner.invoke(main, ["init", "--db", db_path])
    store = BouncerStore(db_path=db_path)
    first_count = len(store.list_rules())
    store.close()
    # Second call should be a no-op (no duplicate seeding)
    result = runner.invoke(main, ["init", "--db", db_path])
    assert result.exit_code == 0
    assert "store already has" in result.output
    store2 = BouncerStore(db_path=db_path)
    assert len(store2.list_rules()) == first_count


def test_init_default_logs_preset_applied_audit_event(
    runner: CliRunner, db_path: str
) -> None:
    """Lens B: the auto-applied protective default IS audit-logged.
    No silent defaults."""
    runner.invoke(main, ["init", "--db", db_path])
    store = BouncerStore(db_path=db_path)
    events = store.list_config_events(kind_filter="preset_applied")
    assert len(events) == 1
    assert events[0]["detail"]["preset_name"] == "admin-minus-sensitive"


# ---------------------------------------------------------------------------
# rules add / list / remove
# ---------------------------------------------------------------------------


def test_rules_add_creates_rule(runner: CliRunner, db_path: str) -> None:
    result = runner.invoke(
        main, ["rules", "add", "s3:GetObject", "--db", db_path]
    )
    assert result.exit_code == 0
    assert "added rule" in result.output

    store = BouncerStore(db_path=db_path)
    assert len(store.list_rules()) == 1


def test_rules_add_with_full_scoping(runner: CliRunner, db_path: str) -> None:
    result = runner.invoke(main, [
        "rules", "add", "s3:Put*",
        "--effect", "deny",
        "--arn", "arn:aws:s3:::sensitive/*",
        "--region", "us-east-1",
        "--note", "block writes to sensitive",
        "--db", db_path,
    ])
    assert result.exit_code == 0
    store = BouncerStore(db_path=db_path)
    rules = store.list_rules()
    assert len(rules) == 1
    _, rule = rules[0]
    assert rule.effect.value == "deny"
    assert rule.arn_scope == "arn:aws:s3:::sensitive/*"
    assert rule.region_scope == "us-east-1"
    assert rule.note == "block writes to sensitive"


def test_rules_list_empty(runner: CliRunner, db_path: str) -> None:
    result = runner.invoke(main, ["rules", "list", "--db", db_path])
    assert result.exit_code == 0
    assert "no rules configured" in result.output


def test_rules_list_text(runner: CliRunner, db_path: str) -> None:
    runner.invoke(main, ["rules", "add", "s3:GetObject", "--db", db_path])
    runner.invoke(main, ["rules", "add", "iam:*", "--effect", "deny", "--db", db_path])
    result = runner.invoke(main, ["rules", "list", "--db", db_path])
    assert result.exit_code == 0
    assert "s3:GetObject" in result.output
    assert "iam:*" in result.output
    assert "deny" in result.output


def test_rules_list_json(runner: CliRunner, db_path: str) -> None:
    runner.invoke(main, ["rules", "add", "s3:GetObject", "--db", db_path])
    result = runner.invoke(main, ["rules", "list", "--db", db_path, "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert len(parsed) == 1
    assert parsed[0]["pattern"] == "s3:GetObject"


def test_rules_remove_success(runner: CliRunner, db_path: str) -> None:
    runner.invoke(main, ["rules", "add", "s3:GetObject", "--db", db_path])
    store = BouncerStore(db_path=db_path)
    rid = store.list_rules()[0][0]
    result = runner.invoke(main, ["rules", "remove", str(rid), "--db", db_path])
    assert result.exit_code == 0
    assert "removed rule" in result.output


def test_rules_remove_missing_exits_nonzero(runner: CliRunner, db_path: str) -> None:
    result = runner.invoke(main, ["rules", "remove", "99999", "--db", db_path])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# logs tail
# ---------------------------------------------------------------------------


def test_logs_tail_empty(runner: CliRunner, db_path: str) -> None:
    result = runner.invoke(main, ["logs", "tail", "--db", db_path])
    assert result.exit_code == 0
    assert "no decisions logged yet" in result.output


def test_logs_tail_shows_recorded_decisions(runner: CliRunner, db_path: str) -> None:
    runner.invoke(main, ["rules", "add", "s3:GetObject", "--db", db_path])
    runner.invoke(main, [
        "decide", "--service", "s3", "--action", "GetObject",
        "--db", db_path, "--record",
    ])
    result = runner.invoke(main, ["logs", "tail", "--db", db_path])
    assert result.exit_code == 0
    assert "s3:GetObject" in result.output
    assert "allow" in result.output


def test_logs_tail_filter_by_decision(runner: CliRunner, db_path: str) -> None:
    runner.invoke(main, ["rules", "add", "iam:*", "--effect", "deny", "--db", db_path])
    runner.invoke(main, [
        "decide", "--service", "iam", "--action", "CreateRole",
        "--db", db_path, "--record",
    ])
    runner.invoke(main, [
        "decide", "--service", "s3", "--action", "GetObject",
        "--db", db_path, "--record",
        "--default-policy", "allow",
    ])
    result = runner.invoke(main, ["logs", "tail", "--db", db_path, "--decision", "deny"])
    assert result.exit_code == 0
    assert "iam:CreateRole" in result.output
    assert "s3:GetObject" not in result.output


# ---------------------------------------------------------------------------
# decide (dry-run)
# ---------------------------------------------------------------------------


def test_decide_unmatched_default_deny(runner: CliRunner, db_path: str) -> None:
    # `--no-default` because the test asserts an EMPTY ruleset; the
    # smart-default behavior (per [[proxy-smart-defaults-and-task-scope]])
    # would otherwise seed admin-minus-sensitive on a fresh store.
    runner.invoke(main, ["init", "--db", db_path, "--no-default"])
    result = runner.invoke(main, [
        "decide", "--service", "ec2", "--action", "DescribeInstances", "--db", db_path,
    ])
    assert result.exit_code == 0
    assert "decision: deny" in result.output
    assert "default-deny" in result.output


def test_decide_explicit_allow_rule(runner: CliRunner, db_path: str) -> None:
    runner.invoke(main, ["rules", "add", "s3:GetObject", "--db", db_path])
    result = runner.invoke(main, [
        "decide", "--service", "s3", "--action", "GetObject", "--db", db_path,
    ])
    assert result.exit_code == 0
    assert "decision: allow" in result.output
    assert "explicit-allow" in result.output


def test_decide_learn_mode_never_denies(runner: CliRunner, db_path: str) -> None:
    runner.invoke(main, ["rules", "add", "s3:*", "--effect", "deny", "--db", db_path])
    result = runner.invoke(main, [
        "decide", "--service", "s3", "--action", "DeleteObject",
        "--mode", "learn", "--db", db_path,
    ])
    assert result.exit_code == 0
    assert "decision: allow" in result.output
    assert "learn-mode" in result.output


def test_decide_record_persists_to_audit_log(runner: CliRunner, db_path: str) -> None:
    runner.invoke(main, ["init", "--db", db_path])
    runner.invoke(main, [
        "decide", "--service", "ec2", "--action", "Foo",
        "--db", db_path, "--record",
    ])
    store = BouncerStore(db_path=db_path)
    assert store.count_decisions() == 1


def test_decide_no_record_does_not_persist(runner: CliRunner, db_path: str) -> None:
    runner.invoke(main, ["init", "--db", db_path])
    runner.invoke(main, [
        "decide", "--service", "ec2", "--action", "Foo", "--db", db_path,
    ])
    store = BouncerStore(db_path=db_path)
    assert store.count_decisions() == 0


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


def test_inspect_s3_get_object(runner: CliRunner) -> None:
    auth = (
        "AWS4-HMAC-SHA256 Credential=KEY/20260517/us-east-1/s3/aws4_request, "
        "SignedHeaders=host, Signature=x"
    )
    result = runner.invoke(main, [
        "inspect",
        "--method", "GET",
        "--host", "s3.amazonaws.com",
        "--path", "/my-bucket/file.txt",
        "--header", f"Authorization: {auth}",
    ])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["service"] == "s3"
    assert parsed["action"] == "GetObject"


def test_inspect_unclassifiable_exits_nonzero(runner: CliRunner) -> None:
    result = runner.invoke(main, [
        "inspect",
        "--method", "GET",
        "--host", "s3.amazonaws.com",
        "--path", "/b",
    ])
    assert result.exit_code != 0
    assert "could not classify" in result.output


def test_inspect_bad_header_format_exits_nonzero(runner: CliRunner) -> None:
    result = runner.invoke(main, [
        "inspect",
        "--method", "GET",
        "--host", "s3.amazonaws.com",
        "--header", "MalformedHeaderNoColon",
    ])
    assert result.exit_code != 0
