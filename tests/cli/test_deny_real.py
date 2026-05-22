"""#324e — `iam-jit deny` real-impl tests.

Replaces ``test_deny_skeleton.py``'s "must exit 2 with structured
'not implemented' payload" pins with the live behavior pins:

  * ``deny add`` resolves targets, writes the YAML atomically,
    fans out to bouncer reload endpoints, exits 0.
  * ``deny list`` reads the YAML + emits a table or JSON.
  * ``deny remove`` rewrites the YAML + re-fans-out.
  * ``deny show`` returns one rule.
  * Resolver classifies ARN / k8s / RDS / hostname / URL.
  * Fan-out failures are surfaced honestly + DON'T abort the CLI.

Per ``[[ibounce-honest-positioning]]`` we test BOTH the happy path
+ the "bouncer is down" honest-surface path.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from iam_jit.cli import main
from iam_jit.dynamic_denies import fanout as fanout_module
from iam_jit.dynamic_denies.fanout import ReloadResult
from iam_jit.dynamic_denies.resolver import (
    classify_one,
    resolve_targets,
)
from iam_jit.dynamic_denies.store import (
    DynamicDenyWriteError,
    build_rule_dict,
    new_rule_id,
    parse_duration,
)


@pytest.fixture
def tmp_yaml_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the YAML store at a temp file; reset HOME so the test
    doesn't touch the developer's real ~/.iam-jit/."""
    p = tmp_path / "dynamic-denies.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(p))
    monkeypatch.setenv("HOME", str(tmp_path))
    return p


@pytest.fixture
def quiet_fanout(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stub the fan-out so tests don't hit real network. Records the
    bouncer names called for assertion."""
    calls: list[str] = []

    def _fake_fanout(affected, *, overrides=None, timeout=5.0):
        out: list[ReloadResult] = []
        for b in affected:
            calls.append(b)
            url = (overrides or {}).get(b) or f"http://127.0.0.1:{b}-mgmt"
            out.append(ReloadResult(
                bouncer=b,
                url=url,
                reloaded=True,
                status_code=200,
                rules_count=1,
                rules_applied_to_self=1,
                error=None,
            ))
        return out

    monkeypatch.setattr(
        "iam_jit.dynamic_denies.operations.fanout_reload",
        _fake_fanout,
    )
    return calls


# ---------------------------------------------------------------------
# Helpers / utility tests
# ---------------------------------------------------------------------


def test_new_rule_id_matches_schema_pattern() -> None:
    pat = re.compile(r"^dd_[0-9A-HJKMNP-TV-Z]{26}$")
    for _ in range(20):
        rid = new_rule_id()
        assert pat.match(rid), f"id {rid!r} fails schema regex"


def test_parse_duration_examples() -> None:
    assert parse_duration("30m").total_seconds() == 30 * 60
    assert parse_duration("3h").total_seconds() == 3 * 60 * 60
    assert parse_duration("7d").total_seconds() == 7 * 24 * 60 * 60
    assert parse_duration("1w").total_seconds() == 7 * 24 * 60 * 60
    assert parse_duration("permanent") is None
    with pytest.raises(ValueError):
        parse_duration("3 hours")
    with pytest.raises(ValueError):
        parse_duration("0m")
    with pytest.raises(ValueError):
        parse_duration("")


def test_build_rule_dict_computes_expires_at() -> None:
    rule = build_rule_dict(
        targets=["arn:aws:s3:::prod-*"],
        reason="incident",
        duration="2h",
        applied_to=["ibounce"],
    )
    assert rule["id"].startswith("dd_")
    assert rule["applied_to"] == ["ibounce"]
    assert rule["expires_at"].endswith("Z")
    assert rule["applies_to_recommender"] is True


def test_build_rule_dict_permanent_has_null_expiry() -> None:
    rule = build_rule_dict(
        targets=["arn:aws:s3:::*"],
        reason="perma",
        duration="permanent",
        applied_to=["ibounce"],
    )
    assert rule["expires_at"] is None


# ---------------------------------------------------------------------
# Resolver tests — cross-protocol routing matrix
# ---------------------------------------------------------------------


@pytest.mark.parametrize("target,expected", [
    ("arn:aws:s3:::prod-*", ("ibounce",)),
    ("arn:aws-cn:s3:::prod-*", ("ibounce",)),
    ("arn:aws-us-gov:iam::123:role/foo", ("ibounce",)),
    ("secret:prod/db-creds", ("ibounce",)),
    ("namespace:prod", ("kbouncer",)),
    ("cluster:prod-east", ("kbouncer",)),
    ("rds:payments-db-prod", ("dbounce", "gbounce")),
    ("https://api.openai.com/v1/chat", ("gbounce",)),
    ("http://10.0.0.5:8080/", ("gbounce",)),
    ("api.openai.com", ("gbounce",)),
    ("10.0.0.0/24", ("gbounce",)),
    ("192.168.1.1", ("gbounce",)),
    ("payments-db-prod.us-east-1.rds.amazonaws.com",
        ("dbounce", "gbounce")),
    ("postgres-replica.example.com", ("dbounce", "gbounce")),
    ("kube-system", ("kbouncer",)),
])
def test_classify_one_routing(target: str, expected: tuple) -> None:
    cls = classify_one(target)
    assert cls.applied_to == expected, (
        f"{target} -> {cls.applied_to}, expected {expected}; "
        f"rationale: {cls.rationale}"
    )


def test_classify_one_unclassifiable_returns_empty_applied_to() -> None:
    cls = classify_one("@@nothing@@")
    assert cls.applied_to == ()
    assert "no shape matched" in cls.rationale


def test_resolve_targets_union_and_unclassifiable() -> None:
    result = resolve_targets([
        "arn:aws:s3:::prod-*",
        "namespace:prod",
        "@@junk@@",
    ])
    assert "ibounce" in result.applied_to
    assert "kbouncer" in result.applied_to
    assert result.unclassifiable_targets == ("@@junk@@",)


def test_resolve_targets_with_override_covers_unclassifiable() -> None:
    result = resolve_targets(
        ["@@junk@@"],
        bouncer_overrides=["ibounce"],
    )
    assert result.applied_to == ("ibounce",)
    assert result.unclassifiable_targets == ()


# ---------------------------------------------------------------------
# CLI: `iam-jit deny add` happy path
# ---------------------------------------------------------------------


def test_deny_add_writes_yaml_and_fans_out(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "incident triage",
        "--duration", "3h",
    ])
    assert result.exit_code == 0, result.output
    assert tmp_yaml_path.exists(), "YAML file must be written"
    # Fan-out called ibounce (matches the ARN target).
    assert "ibounce" in quiet_fanout
    # Stdout shows the routing.
    assert "ibounce" in result.stdout
    assert "incident triage" in result.stdout
    # Permission floor.
    if sys.platform != "win32":
        mode = tmp_yaml_path.stat().st_mode & 0o777
        assert mode == 0o600, f"file mode is {oct(mode)}; must be 0o600"


def test_deny_add_json_shape(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "namespace:prod",
        "--reason", "k8s lockout",
        "--duration", "30m",
        "--json",
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["id"].startswith("dd_")
    assert payload["applied_to"] == ["kbouncer"]
    assert payload["routing_explanation"]
    assert payload["written_to"] == str(tmp_yaml_path)
    assert "kbouncer" in quiet_fanout


def test_deny_add_multi_target_fanout(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--target", "namespace:prod",
        "--reason", "incident triage",
        "--duration", "1h",
    ])
    assert result.exit_code == 0, result.output
    # Both bouncers got the reload.
    assert "ibounce" in quiet_fanout
    assert "kbouncer" in quiet_fanout


def test_deny_add_unclassifiable_fails_without_override(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "@@total-junk@@",
        "--reason", "test",
        "--duration", "1h",
    ])
    assert result.exit_code == 1
    combined = (result.stdout + result.stderr).lower()
    assert (
        "could be classified" in combined
        or "unclassifiable" in combined
        or "no_routing" in combined
    )


def test_deny_add_with_explicit_bouncer_override(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "@@unusual-target@@",
        "--reason", "test",
        "--duration", "1h",
        "--bouncer", "ibounce",
    ])
    assert result.exit_code == 0, result.output
    assert "ibounce" in quiet_fanout


# ---------------------------------------------------------------------
# CLI: `iam-jit deny list` / `show`
# ---------------------------------------------------------------------


def test_deny_list_empty(tmp_yaml_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["deny", "list"])
    assert result.exit_code == 0
    assert "no active dynamic deny rules" in result.stdout


def test_deny_list_after_add(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    runner = CliRunner()
    r1 = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "incident",
        "--duration", "1h",
        "--json",
    ])
    assert r1.exit_code == 0
    rule_id = json.loads(r1.stdout)["id"]

    r2 = runner.invoke(main, ["deny", "list", "--json"])
    assert r2.exit_code == 0
    payload = json.loads(r2.stdout)
    assert payload["count"] == 1
    assert payload["rules"][0]["id"] == rule_id


def test_deny_show_returns_rule_detail(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    runner = CliRunner()
    add_res = runner.invoke(main, [
        "deny", "add",
        "--target", "namespace:prod",
        "--reason", "test",
        "--duration", "1h",
        "--json",
    ])
    rule_id = json.loads(add_res.stdout)["id"]

    show_res = runner.invoke(main, ["deny", "show", rule_id, "--json"])
    assert show_res.exit_code == 0
    payload = json.loads(show_res.stdout)
    assert payload["rule"]["id"] == rule_id
    assert payload["rule"]["applied_to"] == ["kbouncer"]


def test_deny_show_missing_id_returns_error(
    tmp_yaml_path: Path,
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["deny", "show", "dd_00000000000000000000000000"])
    assert result.exit_code == 1


# ---------------------------------------------------------------------
# CLI: `iam-jit deny remove`
# ---------------------------------------------------------------------


def test_deny_remove_by_id(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    runner = CliRunner()
    add_res = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "incident",
        "--duration", "1h",
        "--json",
    ])
    rule_id = json.loads(add_res.stdout)["id"]
    quiet_fanout.clear()

    rm_res = runner.invoke(main, ["deny", "remove", rule_id])
    assert rm_res.exit_code == 0, rm_res.output
    # The remove fans out to the previously-affected bouncer.
    assert "ibounce" in quiet_fanout

    list_res = runner.invoke(main, ["deny", "list", "--json"])
    assert json.loads(list_res.stdout)["count"] == 0


def test_deny_remove_by_reason_match(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    runner = CliRunner()
    runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "incident-4711",
        "--duration", "1h",
    ])
    runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::staging-*",
        "--reason", "staging-test",
        "--duration", "1h",
    ])

    rm_res = runner.invoke(main, [
        "deny", "remove", "--reason-match", "incident-",
    ])
    assert rm_res.exit_code == 0, rm_res.output

    list_res = runner.invoke(main, ["deny", "list", "--json"])
    rules = json.loads(list_res.stdout)["rules"]
    assert len(rules) == 1
    assert "staging-test" in rules[0]["reason"]


def test_deny_remove_not_found(
    tmp_yaml_path: Path,
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["deny", "remove", "dd_00000000000000000000000000"],
    )
    assert result.exit_code == 1


# ---------------------------------------------------------------------
# Fan-out honest-failure path
# ---------------------------------------------------------------------


def test_deny_add_succeeds_when_bouncer_unreachable(
    tmp_yaml_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per [[ibounce-honest-positioning]]: a downed bouncer is
    surfaced + does NOT abort the write. YAML is the source of truth;
    the watcher picks it up on next start."""

    def _fail_fanout(affected, *, overrides=None, timeout=5.0):
        return [
            ReloadResult(
                bouncer=b,
                url=f"http://127.0.0.1:0/{b}",
                reloaded=False,
                status_code=None,
                rules_count=None,
                rules_applied_to_self=None,
                error="unreachable: <fake>",
            )
            for b in affected
        ]

    monkeypatch.setattr(
        "iam_jit.dynamic_denies.operations.fanout_reload",
        _fail_fanout,
    )

    runner = CliRunner()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "test",
        "--duration", "1h",
    ])
    # YAML write succeeded → exit 0.
    assert result.exit_code == 0, result.output
    # Warning surfaced.
    assert "WARN" in result.stdout or "unreachable" in result.stdout
    # YAML on disk.
    assert tmp_yaml_path.exists()


# ---------------------------------------------------------------------
# MCP tool shape
# ---------------------------------------------------------------------


def test_mcp_bounce_deny_add_round_trip(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    from iam_jit.mcp_server import _bounce_deny_add_for_mcp

    payload = _bounce_deny_add_for_mcp({
        "targets": ["arn:aws:s3:::prod-*"],
        "reason": "operator: prod lockout",
        "duration": "3h",
    })
    assert payload["status"] == "ok"
    assert payload["id"].startswith("dd_")
    assert payload["applied_to"] == ["ibounce"]
    assert "Added " in payload["summary"]
    assert "ibounce" in quiet_fanout


def test_mcp_bounce_deny_list_returns_rules(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    from iam_jit.mcp_server import (
        _bounce_deny_add_for_mcp,
        _bounce_deny_list_for_mcp,
    )

    _bounce_deny_add_for_mcp({
        "targets": ["namespace:prod"],
        "reason": "test",
        "duration": "1h",
    })
    listing = _bounce_deny_list_for_mcp({})
    assert listing["status"] == "ok"
    assert listing["count"] == 1
    assert listing["rules"][0]["applied_to"] == ["kbouncer"]


def test_mcp_bounce_deny_remove_round_trip(
    tmp_yaml_path: Path,
    quiet_fanout: list[str],
) -> None:
    from iam_jit.mcp_server import (
        _bounce_deny_add_for_mcp,
        _bounce_deny_list_for_mcp,
        _bounce_deny_remove_for_mcp,
    )

    add = _bounce_deny_add_for_mcp({
        "targets": ["arn:aws:s3:::prod-*"],
        "reason": "incident",
        "duration": "1h",
    })
    assert add["status"] == "ok"
    rid = add["id"]

    rm = _bounce_deny_remove_for_mcp({"id": rid})
    assert rm["status"] == "ok"
    assert rm["removed"] is True

    listing = _bounce_deny_list_for_mcp({})
    assert listing["count"] == 0


def test_mcp_bounce_deny_add_missing_targets_returns_error(
    tmp_yaml_path: Path,
) -> None:
    from iam_jit.mcp_server import _bounce_deny_add_for_mcp

    payload = _bounce_deny_add_for_mcp({
        "reason": "test",
        "duration": "1h",
    })
    assert payload["status"] == "error"
    assert payload["code"] == "missing_targets"


def test_mcp_tools_listed_in_TOOLS() -> None:
    """tools/list MUST surface the three bounce_deny_* tools so an
    MCP client discovers them on `tools/list`."""
    from iam_jit.mcp_server import TOOLS

    names = {t["name"] for t in TOOLS}
    assert "bounce_deny_add" in names
    assert "bounce_deny_list" in names
    assert "bounce_deny_remove" in names
