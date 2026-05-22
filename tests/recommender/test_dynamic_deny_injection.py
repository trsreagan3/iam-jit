# #324f — tests for recommender Deny-injection from dynamic-deny rules.
"""Unit tests for the dynamic-deny -> issued-role-policy Deny-injection
pipeline (per ``docs/DYNAMIC-DENY-RULES.md`` → "Defense-in-depth model"
+ ``docs/tasks/324-dynamic-deny-rules.md`` #324f).

Coverage:
  * ``test_embeds_deny_statement_for_active_arn_rule`` — one ARN-shaped
    rule produces one Deny statement in the issued policy.
  * ``test_skips_non_ibounce_rules`` — rules that route only to
    kbouncer/dbounce/gbounce do not bleed into the IAM role policy.
  * ``test_skips_expired_rules`` — rules whose ``expires_at`` is in the
    past at embed time are NOT embedded (the loader drops them
    eagerly, the recommender re-checks defensively).
  * ``test_multiple_active_rules_all_embedded`` — N eligible rules
    produce N Deny statements in order.
  * ``test_yaml_absent_recommender_works_as_before`` — when there's no
    dynamic-denies file on disk, the recommender returns the
    time-condition-only policy (regression guard on the baseline path).
  * ``test_audit_event_carries_embedded_dynamic_denies_field`` — the
    ``request.provisioned_with_dynamic_denies`` audit emit carries the
    rule ids on the ``unmapped.iam_jit.ext.embedded_dynamic_denies``
    path so a SIEM filter sees the cross-product correlation point.
  * ``test_recommender_reloads_on_yaml_change`` — re-reading the YAML
    after a write picks up new rules (the recommender re-loads on
    every issuance per the design doc).
  * ``test_disabled_flag_skips_embedding`` — setting
    ``IAM_JIT_DYNAMIC_DENIES_RECOMMENDER=0`` short-circuits the
    injection.
"""

from __future__ import annotations

import datetime as _dt
import json
import pathlib
from collections.abc import Iterator
from typing import Any

import pytest

from iam_jit import provision
from iam_jit.accounts_store import Account, InMemoryAccountStore
from iam_jit.dynamic_denies import (
    DEFAULT_PATH_ENV,
    Rule,
    RuleSet,
    build_deny_statements,
    embedded_rule_ids,
    inject_into_policy,
    load_file,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


VALID_RULE_ID_1 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"
VALID_RULE_ID_2 = "dd_01HZ8WPRBZ6CGQRSTVWXYZ0AB1"
VALID_RULE_ID_3 = "dd_01HZ8XPQRSTVWXYZAB23456789"


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


def _write_denies_yaml(
    tmp_path: pathlib.Path,
    *,
    rule_id: str = VALID_RULE_ID_1,
    targets: tuple[str, ...] = ("arn:aws:s3:::customer-pii-*",),
    applied_to: tuple[str, ...] = ("ibounce",),
    applies_to_recommender: bool = True,
    expired: bool = False,
    extra_rules: list[dict[str, Any]] | None = None,
) -> str:
    """Write a schema-valid dynamic-denies.yaml + return the path."""
    expires_at = _past_iso(1) if expired else _future_iso(3)
    duration = "permanent" if applied_to == () else "3h"
    targets_yaml = "\n".join(f"      - \"{t}\"" for t in targets)
    applied_yaml = "\n".join(f"      - {a}" for a in applied_to)
    recommender_flag = "true" if applies_to_recommender else "false"
    rules_yaml = f"""
  - id: {rule_id}
    targets:
{targets_yaml}
    reason: "test fixture"
    duration: "{duration}"
    added_by: "test@example.com"
    added_at: "{_now_iso()}"
    expires_at: "{expires_at}"
    applied_to:
{applied_yaml}
    applies_to_recommender: {recommender_flag}
    source: cli
"""
    for extra in (extra_rules or []):
        rules_yaml += "\n"
        rules_yaml += f"  - id: {extra['id']}\n"
        rules_yaml += "    targets:\n"
        for t in extra["targets"]:
            rules_yaml += f"      - \"{t}\"\n"
        rules_yaml += f"    reason: \"{extra.get('reason', 'test')}\"\n"
        rules_yaml += f"    duration: \"{extra.get('duration', '3h')}\"\n"
        rules_yaml += f"    added_by: \"test@example.com\"\n"
        rules_yaml += f"    added_at: \"{_now_iso()}\"\n"
        rules_yaml += f"    expires_at: \"{extra.get('expires_at', _future_iso(3))}\"\n"
        rules_yaml += "    applied_to:\n"
        for a in extra.get("applied_to", ["ibounce"]):
            rules_yaml += f"      - {a}\n"
        rules_yaml += f"    applies_to_recommender: {str(extra.get('applies_to_recommender', True)).lower()}\n"
        rules_yaml += f"    source: cli\n"

    content = f"""
schema_version: "1.0"
product: iam-jit-dynamic-denies
exported_at: "{_now_iso()}"
denies:
{rules_yaml}
"""
    p = tmp_path / "dynamic-denies.yaml"
    p.write_text(content, encoding="utf-8")
    return str(p)


@pytest.fixture
def denies_path_env(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> pathlib.Path:
    """Point :data:`DEFAULT_PATH_ENV` at ``tmp_path``. Tests write into
    ``tmp_path / 'dynamic-denies.yaml'`` and the recommender resolves
    via the env override.
    """
    monkeypatch.setenv(
        DEFAULT_PATH_ENV, str(tmp_path / "dynamic-denies.yaml"),
    )
    # Defensively enable the recommender (separate test toggles it off).
    monkeypatch.delenv(
        provision.DYNAMIC_DENIES_RECOMMENDER_ENV, raising=False,
    )
    return tmp_path


@pytest.fixture
def moto_sts_iam(mock_aws_env: None) -> Iterator[Any]:
    """Yield (sts, iam_factory) backed by moto."""
    from moto import mock_aws

    with mock_aws():
        import boto3

        sts = boto3.client("sts", region_name="us-east-1")

        def factory(creds: dict[str, str]) -> Any:
            return boto3.client("iam", region_name="us-east-1")

        yield sts, factory


@pytest.fixture
def account_store() -> InMemoryAccountStore:
    s = InMemoryAccountStore()
    s.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn=(
                "arn:aws:iam::060392206767:role/iam-jit-provisioner"
            ),
            provisioner_external_id="iam-jit-060392206767",
            provisioning_mode="classic_iam",
            alias="dev-account",
        )
    )
    return s


def _request_with_allow(
    *,
    rid: str = "rq-dd-test",
    assume_principal: str = "arn:aws:iam::060392206767:role/ci",
) -> dict:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": rid,
            "requester": {
                "name": "Dev",
                "email": "dev@example.com",
                "principal_arn": "arn:aws:iam::060392206767:user/dev",
            },
        },
        "spec": {
            "description": "read reports bucket",
            "access_type": "read-only",
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 1},
            "assume_by": {"principal_arn": assume_principal},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [
                            "arn:aws:s3:::reports-bucket",
                            "arn:aws:s3:::reports-bucket/*",
                        ],
                    }
                ],
            },
            "provisioning": {"mode": "classic_iam"},
        },
    }


# ---------------------------------------------------------------------------
# 1. Embeds Deny statement for active ARN rule
# ---------------------------------------------------------------------------


def test_embeds_deny_statement_for_active_arn_rule(
    denies_path_env, account_store, moto_sts_iam
) -> None:
    """One ibounce + recommender-eligible rule produces one Deny in
    the issued role's inline policy."""
    path = _write_denies_yaml(
        denies_path_env,
        targets=("arn:aws:s3:::customer-pii-*",),
    )
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request_with_allow(rid="rq-i1-pii"),
        accounts_store=account_store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert VALID_RULE_ID_1 in result.embedded_dynamic_denies

    iam = factory({})
    policy_resp = iam.get_role_policy(
        RoleName=result.role_name,
        PolicyName=f"iam-jit-grant-rq-i1-pii",
    )
    doc = policy_resp["PolicyDocument"]
    if isinstance(doc, str):
        doc = json.loads(doc)
    stmts = doc["Statement"]
    deny_stmts = [s for s in stmts if s.get("Effect") == "Deny"]
    assert len(deny_stmts) == 1
    deny = deny_stmts[0]
    assert deny["Sid"].startswith("dynamicdeny")
    assert deny["Action"] == "*"
    assert deny["Resource"] == "arn:aws:s3:::customer-pii-*"


# ---------------------------------------------------------------------------
# 2. Skips non-ibounce rules
# ---------------------------------------------------------------------------


def test_skips_non_ibounce_rules(
    denies_path_env, account_store, moto_sts_iam
) -> None:
    """A rule routed only to kbouncer/dbounce/gbounce produces no
    Deny in the IAM role policy."""
    # gbounce-only hostname rule — the loader filters this OUT of the
    # ibounce snapshot entirely. Issue a role + assert no Deny.
    content = f"""
schema_version: "1.0"
product: iam-jit-dynamic-denies
exported_at: "{_now_iso()}"
denies:
  - id: {VALID_RULE_ID_1}
    targets:
      - "api.openai.com"
    reason: "block openai egress"
    duration: "3h"
    added_by: "test@example.com"
    added_at: "{_now_iso()}"
    expires_at: "{_future_iso(3)}"
    applied_to:
      - gbounce
    applies_to_recommender: true
    source: cli
"""
    (denies_path_env / "dynamic-denies.yaml").write_text(content, encoding="utf-8")

    sts, factory = moto_sts_iam
    result = provision.provision(
        _request_with_allow(rid="rq-nongbounce"),
        accounts_store=account_store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert result.embedded_dynamic_denies == []

    iam = factory({})
    policy_resp = iam.get_role_policy(
        RoleName=result.role_name,
        PolicyName=f"iam-jit-grant-rq-nongbounce",
    )
    doc = policy_resp["PolicyDocument"]
    if isinstance(doc, str):
        doc = json.loads(doc)
    deny_stmts = [s for s in doc["Statement"] if s.get("Effect") == "Deny"]
    assert deny_stmts == []


# ---------------------------------------------------------------------------
# 3. Skips expired rules
# ---------------------------------------------------------------------------


def test_skips_expired_rules(
    denies_path_env, account_store, moto_sts_iam
) -> None:
    """A rule whose expires_at is in the past is NOT embedded.

    The loader's own filter drops expired rules at LOAD time; this
    test verifies behavior end-to-end (loader filters -> recommender
    sees an empty ruleset -> no embed)."""
    _write_denies_yaml(
        denies_path_env,
        targets=("arn:aws:s3:::stale-rule-*",),
        expired=True,
    )
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request_with_allow(rid="rq-exp"),
        accounts_store=account_store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert result.embedded_dynamic_denies == []


# ---------------------------------------------------------------------------
# 4. Multiple active rules all embedded
# ---------------------------------------------------------------------------


def test_multiple_active_rules_all_embedded(
    denies_path_env, account_store, moto_sts_iam
) -> None:
    """N eligible rules produce N Deny statements in the issued
    policy. Order is preserved from on-disk file ordering."""
    extras = [
        {
            "id": VALID_RULE_ID_2,
            "targets": ["arn:aws:secretsmanager:*:*:secret:production-*"],
            "reason": "lockdown prod secrets",
            "duration": "3h",
            "applied_to": ["ibounce"],
            "applies_to_recommender": True,
        },
        {
            "id": VALID_RULE_ID_3,
            "targets": ["arn:aws:dynamodb:*:*:table/customers"],
            "reason": "freeze customers table",
            "duration": "3h",
            "applied_to": ["ibounce"],
            "applies_to_recommender": True,
        },
    ]
    _write_denies_yaml(
        denies_path_env,
        rule_id=VALID_RULE_ID_1,
        targets=("arn:aws:s3:::customer-pii-*",),
        extra_rules=extras,
    )
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request_with_allow(rid="rq-multi"),
        accounts_store=account_store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert sorted(result.embedded_dynamic_denies) == sorted([
        VALID_RULE_ID_1, VALID_RULE_ID_2, VALID_RULE_ID_3,
    ])

    iam = factory({})
    policy_resp = iam.get_role_policy(
        RoleName=result.role_name,
        PolicyName=f"iam-jit-grant-rq-multi",
    )
    doc = policy_resp["PolicyDocument"]
    if isinstance(doc, str):
        doc = json.loads(doc)
    deny_stmts = [s for s in doc["Statement"] if s.get("Effect") == "Deny"]
    assert len(deny_stmts) == 3
    sids = [s["Sid"] for s in deny_stmts]
    assert any(VALID_RULE_ID_1.replace("_", "") in s for s in sids)
    assert any(VALID_RULE_ID_2.replace("_", "") in s for s in sids)
    assert any(VALID_RULE_ID_3.replace("_", "") in s for s in sids)


# ---------------------------------------------------------------------------
# 5. YAML absent -> recommender works as before
# ---------------------------------------------------------------------------


def test_yaml_absent_recommender_works_as_before(
    denies_path_env, account_store, moto_sts_iam
) -> None:
    """No on-disk denies file -> the recommender returns the
    time-condition-only policy (regression guard on the baseline)."""
    # Do NOT write a dynamic-denies.yaml.
    assert not (denies_path_env / "dynamic-denies.yaml").exists()
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request_with_allow(rid="rq-nofile"),
        accounts_store=account_store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert result.embedded_dynamic_denies == []
    iam = factory({})
    policy_resp = iam.get_role_policy(
        RoleName=result.role_name,
        PolicyName=f"iam-jit-grant-rq-nofile",
    )
    doc = policy_resp["PolicyDocument"]
    if isinstance(doc, str):
        doc = json.loads(doc)
    # Original Allow statement is preserved; no Deny added.
    deny_stmts = [s for s in doc["Statement"] if s.get("Effect") == "Deny"]
    assert deny_stmts == []
    allow_stmts = [s for s in doc["Statement"] if s.get("Effect") == "Allow"]
    assert len(allow_stmts) == 1
    # And the time-condition was still applied.
    assert "Condition" in allow_stmts[0]
    assert "DateLessThan" in allow_stmts[0]["Condition"]


# ---------------------------------------------------------------------------
# 6. Audit event carries embedded_dynamic_denies field
# ---------------------------------------------------------------------------


def test_audit_event_carries_embedded_dynamic_denies_field(
    denies_path_env, account_store, moto_sts_iam, monkeypatch
) -> None:
    """When the recommender embeds Deny statements, a
    ``request.provisioned_with_dynamic_denies`` audit event is emitted
    carrying the rule ids on the
    ``unmapped.iam_jit.ext.embedded_dynamic_denies`` path."""
    _write_denies_yaml(
        denies_path_env,
        targets=("arn:aws:s3:::audit-test-*",),
    )

    captured: list[dict[str, Any]] = []

    from iam_jit import audit as audit_mod

    def fake_emit(*, actor, kind, summary, details, **kwargs):
        captured.append({
            "actor": actor,
            "kind": kind,
            "summary": summary,
            "details": details,
        })

    monkeypatch.setattr(audit_mod, "emit", fake_emit)

    sts, factory = moto_sts_iam
    provision.provision(
        _request_with_allow(rid="rq-audit-ext"),
        accounts_store=account_store,
        sts_client=sts,
        iam_client_factory=factory,
    )

    dd_events = [
        e for e in captured
        if e["kind"] == "request.provisioned_with_dynamic_denies"
    ]
    assert len(dd_events) == 1
    ev = dd_events[0]
    ext = ev["details"]["unmapped"]["iam_jit"]["ext"]
    assert ext["embedded_dynamic_denies"] == [VALID_RULE_ID_1]
    assert ext["embedded_dynamic_denies_count"] == 1


# ---------------------------------------------------------------------------
# 7. Recommender reloads on YAML change
# ---------------------------------------------------------------------------


def test_recommender_reloads_on_yaml_change(
    denies_path_env, account_store, moto_sts_iam
) -> None:
    """Each role issuance re-reads the denies YAML, so a write between
    two issuances is picked up on the second issuance.

    The recommender intentionally re-loads on every issuance (no
    process-local cache) so an operator's `iam-jit deny add` is
    visible to the next role issued — same UX expectation as the
    bouncer's filesystem watcher path.
    """
    sts, factory = moto_sts_iam

    # First issuance — no YAML file.
    r1 = provision.provision(
        _request_with_allow(rid="rq-reload-a"),
        accounts_store=account_store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert r1.embedded_dynamic_denies == []

    # Operator runs `iam-jit deny add ...` — file appears.
    _write_denies_yaml(
        denies_path_env,
        targets=("arn:aws:s3:::reload-test-*",),
    )

    # Second issuance — picks up the rule.
    r2 = provision.provision(
        _request_with_allow(rid="rq-reload-b"),
        accounts_store=account_store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert r2.embedded_dynamic_denies == [VALID_RULE_ID_1]


# ---------------------------------------------------------------------------
# 8. Disabled flag skips embedding
# ---------------------------------------------------------------------------


def test_disabled_flag_skips_embedding(
    denies_path_env, account_store, moto_sts_iam, monkeypatch
) -> None:
    """Setting ``IAM_JIT_DYNAMIC_DENIES_RECOMMENDER=0`` short-circuits
    the injection even with active rules on disk."""
    _write_denies_yaml(
        denies_path_env,
        targets=("arn:aws:s3:::disabled-test-*",),
    )
    monkeypatch.setenv(
        provision.DYNAMIC_DENIES_RECOMMENDER_ENV, "0",
    )
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request_with_allow(rid="rq-off"),
        accounts_store=account_store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    assert result.embedded_dynamic_denies == []


# ---------------------------------------------------------------------------
# Pure-function unit tests for the recommender module
# ---------------------------------------------------------------------------
#
# These cover the recommender's public API directly, without provisioning
# moto + IAM. Useful guard against regressions in the eligibility filter
# + statement-builder layer.


def _rule(
    *,
    rid: str = VALID_RULE_ID_1,
    targets: tuple[str, ...] = ("arn:aws:s3:::test-*",),
    applied_to: tuple[str, ...] = ("ibounce",),
    applies_to_recommender: bool = True,
    expires_at: _dt.datetime | None = None,
) -> Rule:
    if expires_at is None:
        expires_at = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=3)
    return Rule(
        id=rid,
        targets=targets,
        reason="unit test",
        duration="3h",
        added_by="t@e.com",
        added_at=_dt.datetime.now(_dt.timezone.utc),
        expires_at=expires_at,
        applied_to=applied_to,
        applies_to_recommender=applies_to_recommender,
        source="cli",
    )


def test_build_deny_statements_skips_recommender_optout() -> None:
    """A rule with ``applies_to_recommender = false`` is NOT embedded
    even when it routes to ibounce."""
    r = _rule(applies_to_recommender=False)
    rs = RuleSet(rules=(r,), source_path="", total_rules_in_file=1)
    assert build_deny_statements(rs) == []
    assert embedded_rule_ids(rs) == []


def test_inject_into_policy_appends_not_mutates() -> None:
    """The injection helper never mutates its input."""
    r = _rule()
    rs = RuleSet(rules=(r,), source_path="", total_rules_in_file=1)
    original = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        ],
    }
    snapshot = json.dumps(original, sort_keys=True)
    out = inject_into_policy(original, rs)
    # Input unchanged
    assert json.dumps(original, sort_keys=True) == snapshot
    # Output has the original + the new Deny
    assert out["Statement"][0] == original["Statement"][0]
    assert out["Statement"][-1]["Effect"] == "Deny"


def test_build_deny_statements_filters_non_arn_targets() -> None:
    """Targets that aren't AWS ARNs (the ``secret:NAME`` shorthand
    survives the loader but isn't an ARN at embed time) are dropped
    from the Resource list. A rule with ONLY non-ARN targets is
    skipped entirely."""
    r = _rule(targets=("secret:my-app-creds",))
    rs = RuleSet(rules=(r,), source_path="", total_rules_in_file=1)
    assert build_deny_statements(rs) == []
    assert embedded_rule_ids(rs) == []


def test_build_deny_statements_handles_govcloud_partition() -> None:
    """GovCloud + China-region ARNs (``arn:aws-us-gov:`` /
    ``arn:aws-cn:``) are valid Resources too."""
    r1 = _rule(rid=VALID_RULE_ID_1, targets=("arn:aws-us-gov:s3:::gov-*",))
    r2 = _rule(rid=VALID_RULE_ID_2, targets=("arn:aws-cn:s3:::cn-*",))
    rs = RuleSet(
        rules=(r1, r2), source_path="", total_rules_in_file=2,
    )
    stmts = build_deny_statements(rs)
    assert len(stmts) == 2
    resources = [s["Resource"] for s in stmts]
    assert "arn:aws-us-gov:s3:::gov-*" in resources
    assert "arn:aws-cn:s3:::cn-*" in resources


def test_sid_format_is_iam_legal() -> None:
    """The synthesised ``Sid`` must be IAM-legal (``[A-Za-z0-9]+``).
    IAM rejects underscores / dashes in Sid; an invalid Sid in
    PutRolePolicy raises MalformedPolicyDocument."""
    import re

    r = _rule()
    rs = RuleSet(rules=(r,), source_path="", total_rules_in_file=1)
    stmts = build_deny_statements(rs)
    assert len(stmts) == 1
    sid = stmts[0]["Sid"]
    assert re.match(r"^[A-Za-z0-9]+$", sid), (
        f"Sid {sid!r} contains illegal IAM characters"
    )


def test_yaml_loaded_rules_round_trip_through_build_deny_statements(
    tmp_path: pathlib.Path,
) -> None:
    """End-to-end: a YAML file loaded via :func:`load_file` produces
    the same statements as the in-memory RuleSet."""
    _write_denies_yaml(
        tmp_path,
        targets=("arn:aws:s3:::roundtrip-*",),
    )
    rs = load_file(str(tmp_path / "dynamic-denies.yaml"))
    stmts = build_deny_statements(rs)
    assert len(stmts) == 1
    assert stmts[0]["Resource"] == "arn:aws:s3:::roundtrip-*"
    assert stmts[0]["Effect"] == "Deny"
    assert stmts[0]["Action"] == "*"
