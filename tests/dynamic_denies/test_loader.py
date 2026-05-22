# #324a — tests for the dynamic-deny YAML loader.
"""Unit tests for ``iam_jit.dynamic_denies.loader``.

Covers:
  * Happy-path load of a schema-valid file.
  * Schema violations (missing fields, wrong types, invalid IDs).
  * Cross-bouncer filtering (non-ibounce `applied_to` entries skipped).
  * Non-AWS-ARN target filtering (host patterns, k8s namespaces).
  * Already-expired rules dropped at load time.
  * ARN pattern matching: exact, glob, multi-component wildcards,
    service-only forms, ``secret:NAME`` shorthand.
  * Negative match cases.

Per ``[[deliberate-feature-completion]]`` the test set covers every
slice deliverable in the #324a contract.
"""

from __future__ import annotations

import datetime as _dt
import pathlib

import pytest

from iam_jit.dynamic_denies import (
    DynamicDenyLoadError,
    Rule,
    RuleSet,
    load_file,
    match_arn,
    resolve_default_path,
)
from iam_jit.dynamic_denies.loader import BOUNCER_NAME


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_yaml(tmp_path: pathlib.Path, contents: str) -> str:
    p = tmp_path / "dynamic-denies.yaml"
    p.write_text(contents, encoding="utf-8")
    return str(p)


def _future_iso(offset_hours: int = 3) -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        + _dt.timedelta(hours=offset_hours)
    ).isoformat().replace("+00:00", "Z")


def _past_iso(offset_hours: int = 3) -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        - _dt.timedelta(hours=offset_hours)
    ).isoformat().replace("+00:00", "Z")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


VALID_RULE_ID_1 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"
VALID_RULE_ID_2 = "dd_01HZ8WPRBZ6CGQRSTVWXYZ0AB1"
VALID_RULE_ID_3 = "dd_01HZ8XPQRSTVWXYZAB23456789"


# ---------------------------------------------------------------------------
# Loader — happy path
# ---------------------------------------------------------------------------


def test_loads_valid_yaml(tmp_path):
    """A schema-valid file with one ibounce-routed rule produces a
    RuleSet containing that rule."""
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
product: iam-jit-dynamic-denies
exported_at: "{_now_iso()}"
denies:
  - id: {VALID_RULE_ID_1}
    targets:
      - "arn:aws:s3:::prod-*"
    reason: "incident #4711 lockout"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    expires_at: "{_future_iso(3)}"
    applied_to:
      - ibounce
    source: cli
""")
    rs = load_file(path)
    assert isinstance(rs, RuleSet)
    assert len(rs.rules) == 1
    assert rs.total_rules_in_file == 1
    r = rs.rules[0]
    assert isinstance(r, Rule)
    assert r.id == VALID_RULE_ID_1
    assert r.targets == ("arn:aws:s3:::prod-*",)
    assert r.reason == "incident #4711 lockout"
    assert r.duration == "3h"
    assert r.added_by == "ops@example.com"
    assert r.applies_to_recommender is True  # default
    assert r.source == "cli"
    assert r.applied_to == ("ibounce",)


def test_missing_file_returns_empty_ruleset(tmp_path):
    """An operator without any installed dynamic denies still gets
    the proxy to start cleanly — missing file -> empty set, not an
    error."""
    rs = load_file(str(tmp_path / "absent.yaml"))
    assert isinstance(rs, RuleSet)
    assert len(rs.rules) == 0


def test_empty_path_returns_empty_ruleset():
    """None path is treated like missing — used when config disables
    the watcher path."""
    assert len(load_file(None).rules) == 0
    assert len(load_file("").rules) == 0


def test_empty_yaml_file_returns_empty_ruleset(tmp_path):
    """`> dynamic-denies.yaml` (empty file) is a legitimate clear-all
    state — distinguished from missing-file but produces the same
    empty RuleSet."""
    path = _write_yaml(tmp_path, "")
    rs = load_file(path)
    assert len(rs.rules) == 0


def test_explicitly_empty_denies_list(tmp_path):
    """`denies: []` (operator cleared all rules) parses cleanly."""
    path = _write_yaml(tmp_path, """
schema_version: "1.0"
denies: []
""")
    rs = load_file(path)
    assert len(rs.rules) == 0
    assert rs.total_rules_in_file == 0


def test_resolve_default_path_honors_env(monkeypatch):
    """`IAM_JIT_DYNAMIC_DENIES_PATH` overrides the home-dir default."""
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", "/tmp/custom.yaml")
    assert resolve_default_path() == "/tmp/custom.yaml"


def test_resolve_default_path_falls_back_to_home(monkeypatch):
    monkeypatch.delenv("IAM_JIT_DYNAMIC_DENIES_PATH", raising=False)
    path = resolve_default_path()
    assert path.endswith(".iam-jit/dynamic-denies.yaml")


# ---------------------------------------------------------------------------
# Loader — schema violations
# ---------------------------------------------------------------------------


def test_rejects_missing_schema_version(tmp_path):
    path = _write_yaml(tmp_path, """
denies: []
""")
    with pytest.raises(DynamicDenyLoadError) as exc_info:
        load_file(path)
    assert "schema_version" in str(exc_info.value)


def test_rejects_wrong_schema_version(tmp_path):
    path = _write_yaml(tmp_path, """
schema_version: "0.9"
denies: []
""")
    with pytest.raises(DynamicDenyLoadError) as exc_info:
        load_file(path)
    assert "schema_version" in str(exc_info.value).lower()


def test_rejects_wrong_product_magic(tmp_path):
    """A misrouted `ibounce-config.yaml` would have the wrong
    `product` discriminator + must be refused at parse."""
    path = _write_yaml(tmp_path, """
schema_version: "1.0"
product: iam-jit-bouncer-config
denies: []
""")
    with pytest.raises(DynamicDenyLoadError) as exc_info:
        load_file(path)
    assert "product" in str(exc_info.value)


def test_rejects_invalid_rule_id(tmp_path):
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: "bad-id"
    targets: ["arn:aws:s3:::prod-*"]
    reason: "test"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    with pytest.raises(DynamicDenyLoadError) as exc_info:
        load_file(path)
    assert "id" in str(exc_info.value).lower()


def test_rejects_missing_required_field(tmp_path):
    """Missing `reason` triggers structural validation."""
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets: ["arn:aws:s3:::prod-*"]
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    with pytest.raises(DynamicDenyLoadError) as exc_info:
        load_file(path)
    assert "reason" in str(exc_info.value)


def test_rejects_invalid_duration(tmp_path):
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets: ["arn:aws:s3:::prod-*"]
    reason: "test"
    duration: "forever"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    with pytest.raises(DynamicDenyLoadError) as exc_info:
        load_file(path)
    assert "duration" in str(exc_info.value).lower()


def test_rejects_empty_targets(tmp_path):
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets: []
    reason: "test"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    with pytest.raises(DynamicDenyLoadError) as exc_info:
        load_file(path)
    assert "target" in str(exc_info.value).lower()


def test_rejects_duplicate_rule_ids(tmp_path):
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets: ["arn:aws:s3:::prod-1"]
    reason: "test"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
  - id: {VALID_RULE_ID_1}
    targets: ["arn:aws:s3:::prod-2"]
    reason: "test"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    with pytest.raises(DynamicDenyLoadError) as exc_info:
        load_file(path)
    assert "duplicate" in str(exc_info.value).lower()


def test_rejects_unrecognised_source(tmp_path):
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets: ["arn:aws:s3:::prod-*"]
    reason: "test"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
    source: "smuggled"
""")
    with pytest.raises(DynamicDenyLoadError):
        load_file(path)


# ---------------------------------------------------------------------------
# Loader — filtering behaviour
# ---------------------------------------------------------------------------


def test_filters_non_ibounce_applied_to(tmp_path):
    """Rules routed only to kbouncer/dbounce/gbounce don't land in
    the ibounce snapshot."""
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets: ["arn:aws:s3:::prod-*"]
    reason: "ibounce-lane"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
  - id: {VALID_RULE_ID_2}
    targets: ["arn:aws:s3:::prod-*"]
    reason: "kbounce-lane"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [kbounce]
""")
    rs = load_file(path)
    assert len(rs.rules) == 1
    assert rs.rules[0].id == VALID_RULE_ID_1
    assert rs.total_rules_in_file == 2


def test_filters_non_aws_arn_targets(tmp_path):
    """Targets that aren't AWS ARNs (host patterns, k8s namespaces,
    URLs) get dropped from the ibounce lane even when applied_to
    includes ibounce. The rule itself is dropped when no targets
    survive."""
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets:
      - "api.openai.com"
      - "kube-system"
    reason: "wrong-lane targets"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    rs = load_file(path)
    # No AWS-ARN targets survive -> rule dropped entirely.
    assert len(rs.rules) == 0


def test_keeps_aws_arn_drops_non_arn_targets_within_rule(tmp_path):
    """A multi-target rule with both ARN + host targets keeps the
    ARN one + drops the host (when routed to ibounce)."""
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets:
      - "arn:aws:s3:::prod-*"
      - "api.openai.com"
    reason: "mixed targets"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce, gbounce]
""")
    rs = load_file(path)
    assert len(rs.rules) == 1
    assert rs.rules[0].targets == ("arn:aws:s3:::prod-*",)


def test_supports_aws_cn_and_govcloud_partitions(tmp_path):
    """The loader accepts arn:aws-cn:* + arn:aws-us-gov:* targets so
    operators in those partitions aren't excluded."""
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets:
      - "arn:aws-cn:s3:::prod-*"
      - "arn:aws-us-gov:s3:::prod-*"
    reason: "partition coverage"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    rs = load_file(path)
    assert len(rs.rules) == 1
    assert set(rs.rules[0].targets) == {
        "arn:aws-cn:s3:::prod-*",
        "arn:aws-us-gov:s3:::prod-*",
    }


def test_supports_secret_shorthand_target(tmp_path):
    """The `secret:NAME` shorthand is a valid ibounce target."""
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets:
      - "secret:prod-db-creds"
    reason: "secret-lock"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    rs = load_file(path)
    assert len(rs.rules) == 1
    assert rs.rules[0].targets == ("secret:prod-db-creds",)


def test_expired_rules_filtered_at_load(tmp_path):
    """A rule whose expires_at has already passed gets dropped before
    the matcher ever sees it."""
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets: ["arn:aws:s3:::prod-*"]
    reason: "fresh"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    expires_at: "{_future_iso(3)}"
    applied_to: [ibounce]
  - id: {VALID_RULE_ID_2}
    targets: ["arn:aws:s3:::stale-*"]
    reason: "stale"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_past_iso(6)}"
    expires_at: "{_past_iso(1)}"
    applied_to: [ibounce]
""")
    rs = load_file(path)
    assert len(rs.rules) == 1
    assert rs.rules[0].id == VALID_RULE_ID_1


def test_permanent_duration_carries_null_expires_at(tmp_path):
    """A `permanent` rule keeps its expires_at as None — the matcher
    never schedules a removal for it."""
    path = _write_yaml(tmp_path, f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID_1}
    targets: ["arn:aws:s3:::prod-*"]
    reason: "always-on"
    duration: permanent
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    rs = load_file(path)
    assert len(rs.rules) == 1
    assert rs.rules[0].expires_at is None


# ---------------------------------------------------------------------------
# Matcher — ARN pattern matching
# ---------------------------------------------------------------------------


def _ruleset_from(*targets_per_rule: tuple[str, ...]) -> RuleSet:
    rules = []
    now = _dt.datetime.now(_dt.timezone.utc)
    base_ids = [VALID_RULE_ID_1, VALID_RULE_ID_2, VALID_RULE_ID_3]
    for idx, tgts in enumerate(targets_per_rule):
        rules.append(Rule(
            id=base_ids[idx],
            targets=tgts,
            reason=f"test rule {idx}",
            duration="3h",
            added_by="ops@example.com",
            added_at=now,
            expires_at=None,
            applied_to=(BOUNCER_NAME,),
        ))
    return RuleSet(
        rules=tuple(rules),
        source_path="<test>",
        loaded_at=now,
        total_rules_in_file=len(rules),
    )


@pytest.mark.parametrize("pattern,arn", [
    # Exact match
    ("arn:aws:s3:::prod-data", "arn:aws:s3:::prod-data"),
    # Glob on resource
    ("arn:aws:s3:::prod-*", "arn:aws:s3:::prod-data-bucket"),
    ("arn:aws:s3:::prod-*", "arn:aws:s3:::prod-"),
    # Wildcard on account
    ("arn:aws:iam::*:role/AdminRole",
     "arn:aws:iam::123456789012:role/AdminRole"),
    # Multi-component wildcards
    ("arn:aws:*:*:*:*", "arn:aws:s3:us-east-1:111:bucket/foo"),
    # Question-mark wildcard
    ("arn:aws:s3:::prod-?",
     "arn:aws:s3:::prod-1"),
    # GovCloud partition match
    ("arn:aws-us-gov:s3:::prod-*",
     "arn:aws-us-gov:s3:::prod-data"),
    # Service-only short form expands
    ("arn:aws:iam:*", "arn:aws:iam::123:role/Foo"),
])
def test_arn_pattern_matches(pattern, arn):
    rs = _ruleset_from((pattern,))
    m = match_arn(rs, arn)
    assert m is not None
    assert m.target_pattern == pattern


@pytest.mark.parametrize("pattern,arn", [
    # Different bucket
    ("arn:aws:s3:::prod-*", "arn:aws:s3:::staging-data"),
    # Different service
    ("arn:aws:s3:::prod-*", "arn:aws:dynamodb:us-east-1:111:table/prod-T"),
    # Different partition
    ("arn:aws-cn:s3:::prod-*", "arn:aws:s3:::prod-data"),
    # Question-mark requires exactly one char
    ("arn:aws:s3:::prod-?", "arn:aws:s3:::prod-12"),
])
def test_arn_pattern_no_match(pattern, arn):
    rs = _ruleset_from((pattern,))
    assert match_arn(rs, arn) is None


def test_match_returns_first_rule(tmp_path):
    """First-match semantics — the earlier rule wins when multiple
    match the same ARN."""
    rs = _ruleset_from(
        ("arn:aws:s3:::prod-*",),
        ("arn:aws:s3:::*",),
    )
    m = match_arn(rs, "arn:aws:s3:::prod-data")
    assert m is not None
    assert m.rule_id == VALID_RULE_ID_1


def test_match_against_none_arn():
    """A None / empty ARN never matches; the dynamic-deny path is a
    no-op for ARN-less calls (some legacy STS calls)."""
    rs = _ruleset_from(("arn:aws:*",))
    assert match_arn(rs, None) is None
    assert match_arn(rs, "") is None


def test_match_against_empty_ruleset():
    rs = RuleSet.empty()
    assert match_arn(rs, "arn:aws:s3:::prod-data") is None


def test_secret_shorthand_matches_secrets_manager_arn():
    """`secret:my-app-creds` matches an SM ARN with that name +
    the AWS-randomised suffix."""
    rs = _ruleset_from(("secret:prod-db-creds",))
    m = match_arn(
        rs,
        "arn:aws:secretsmanager:us-east-1:123:secret:prod-db-creds-A1b2C3",
    )
    assert m is not None
    assert m.target_pattern == "secret:prod-db-creds"


def test_secret_shorthand_glob_matches():
    """The secret-name part of the shorthand is itself a glob."""
    rs = _ruleset_from(("secret:prod-*",))
    m = match_arn(
        rs,
        "arn:aws:secretsmanager:us-east-1:123:secret:prod-db-creds-A1b2C3",
    )
    assert m is not None


def test_secret_shorthand_does_not_match_non_secret_arn():
    rs = _ruleset_from(("secret:prod-*",))
    assert match_arn(rs, "arn:aws:s3:::prod-data") is None
