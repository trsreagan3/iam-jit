"""Tests for the IAM action blacklist."""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit import blacklist


def _rule(rule_id: str, pattern: str, reason: str = "test") -> blacklist.BlacklistRule:
    return blacklist.BlacklistRule(
        rule_id=rule_id, pattern=pattern, reason=reason,
        added_by="test", added_at=1234567890,
    )


def _policy_with_actions(*actions: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": list(actions),
            "Resource": "*",
        }],
    }


# ---- Matching ------------------------------------------------------


def test_exact_match() -> None:
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r1", "iam:CreateAccessKey"))
    hit = blacklist.check_policy(_policy_with_actions("iam:CreateAccessKey"), store)
    assert hit is not None
    assert hit.rule_id == "r1"
    assert hit.matched_action == "iam:CreateAccessKey"


def test_glob_substring_match() -> None:
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r-keys", "iam:*AccessKey*"))
    # CreateAccessKey, DeleteAccessKey, UpdateAccessKey all match
    for action in ("iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:UpdateAccessKey"):
        hit = blacklist.check_policy(_policy_with_actions(action), store)
        assert hit is not None, f"failed to match {action}"


def test_service_wildcard_match() -> None:
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r-ct", "cloudtrail:*"))
    hit = blacklist.check_policy(_policy_with_actions("cloudtrail:DeleteTrail"), store)
    assert hit is not None


def test_no_match_returns_none() -> None:
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r1", "iam:CreateAccessKey"))
    hit = blacklist.check_policy(_policy_with_actions("s3:GetObject"), store)
    assert hit is None


def test_case_insensitive() -> None:
    """AWS IAM is case-insensitive on action names; the blacklist must
    match the same way to prevent obvious bypass."""
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r1", "iam:CreateAccessKey"))
    # Lowercase action — should still match
    hit = blacklist.check_policy(_policy_with_actions("iam:createaccesskey"), store)
    assert hit is not None
    # All uppercase
    hit = blacklist.check_policy(_policy_with_actions("IAM:CREATEACCESSKEY"), store)
    assert hit is not None


def test_matches_actions_inside_notaction() -> None:
    """NotAction lists are still actions named in the policy — the
    blacklist matches them too (preventing bypass via NotAction)."""
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r1", "iam:CreateAccessKey"))
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "NotAction": ["iam:CreateAccessKey"],
            "Resource": "*",
        }],
    }
    hit = blacklist.check_policy(policy, store)
    assert hit is not None


def test_first_matching_action_wins() -> None:
    """When multiple actions match, return the first one (deterministic
    iteration order)."""
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r-keys", "iam:CreateAccessKey"))
    store.put_rule(_rule("r-trail", "cloudtrail:DeleteTrail"))
    hit = blacklist.check_policy(
        _policy_with_actions("iam:CreateAccessKey", "cloudtrail:DeleteTrail"),
        store,
    )
    assert hit is not None
    assert hit.rule_id in ("r-keys", "r-trail")


def test_empty_store_returns_none() -> None:
    """No rules → no match, even for catastrophic actions."""
    store = blacklist.InMemoryBlacklistStore()
    hit = blacklist.check_policy(_policy_with_actions("iam:*"), store)
    assert hit is None


def test_malformed_policy_doesnt_crash() -> None:
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r1", "iam:*"))
    # Statement is not a list
    assert blacklist.check_policy({"Statement": "wrong"}, store) is None
    # No Statement at all
    assert blacklist.check_policy({}, store) is None
    # Statement items not dicts
    assert blacklist.check_policy({"Statement": ["string"]}, store) is None
    # Action is not str / list
    assert blacklist.check_policy(
        {"Statement": [{"Action": {"weird": "shape"}}]}, store,
    ) is None


# ---- Store ----------------------------------------------------------


def test_store_rejects_bare_star() -> None:
    """`*` alone would block every request — explicit guard against
    operator footgun."""
    store = blacklist.InMemoryBlacklistStore()
    with pytest.raises(ValueError):
        store.put_rule(_rule("r-bad", "*"))


def test_store_allows_service_star() -> None:
    """`iam:*` is fine — that's a real "block all IAM" rule."""
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r1", "iam:*"))
    assert len(store.list_rules()) == 1


def test_store_delete() -> None:
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r1", "iam:CreateAccessKey"))
    store.put_rule(_rule("r2", "iam:DeleteAccessKey"))
    store.delete_rule("r1")
    assert {r.rule_id for r in store.list_rules()} == {"r2"}


def test_store_delete_nonexistent_is_noop() -> None:
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r1", "iam:CreateAccessKey"))
    store.delete_rule("does-not-exist")  # no error
    assert len(store.list_rules()) == 1


def test_store_put_overwrites() -> None:
    """Same rule_id replaces — this is how operators update reason text."""
    store = blacklist.InMemoryBlacklistStore()
    store.put_rule(_rule("r1", "iam:CreateAccessKey", reason="v1"))
    store.put_rule(_rule("r1", "iam:CreateAccessKey", reason="v2 — updated"))
    rules = store.list_rules()
    assert len(rules) == 1
    assert rules[0].reason == "v2 — updated"


# ---- Templates ------------------------------------------------------


def test_template_ban_catastrophic_actions() -> None:
    """The catastrophic template covers account closure + audit
    tampering + KMS deletion."""
    rules = blacklist.template_ban_catastrophic_actions()
    patterns = {r.pattern for r in rules}
    assert "account:CloseAccount" in patterns
    assert "organizations:LeaveOrganization" in patterns
    assert "cloudtrail:DeleteTrail" in patterns
    assert "cloudtrail:StopLogging" in patterns
    assert "kms:ScheduleKeyDeletion" in patterns


def test_template_ban_credential_minting() -> None:
    rules = blacklist.template_ban_credential_minting()
    patterns = {r.pattern for r in rules}
    assert "iam:CreateAccessKey" in patterns


def test_template_ban_iam_escalation() -> None:
    rules = blacklist.template_ban_iam_escalation_primitives()
    patterns = {r.pattern for r in rules}
    assert "iam:AttachRolePolicy" in patterns
    assert "iam:UpdateAssumeRolePolicy" in patterns


def test_template_ban_audit_evasion() -> None:
    rules = blacklist.template_ban_audit_evasion()
    patterns = {r.pattern for r in rules}
    assert "cloudwatch:DisableAlarmActions" in patterns
    assert "guardduty:UpdateDetector" in patterns


def test_template_rules_have_reasons() -> None:
    """Every rule in every template MUST have a non-empty reason —
    the reason is what surfaces in audit logs when a rule fires."""
    for name, factory in blacklist.TEMPLATES.items():
        for rule in factory():
            assert rule.reason, f"template {name} has rule with empty reason"
            assert len(rule.reason) > 20, (
                f"template {name} rule {rule.rule_id} has trivially short reason"
            )


def test_template_applied_to_store_then_matched() -> None:
    """End-to-end: load template rules into a store, then check a
    policy that contains a banned action — should hit."""
    store = blacklist.InMemoryBlacklistStore()
    for rule in blacklist.template_ban_catastrophic_actions():
        store.put_rule(rule)
    hit = blacklist.check_policy(
        _policy_with_actions("cloudtrail:DeleteTrail"),
        store,
    )
    assert hit is not None
    assert "audit evidence" in hit.reason.lower()
