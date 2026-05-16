"""Tests for the bouncer SQLite store."""

from __future__ import annotations

import pathlib

import pytest

from iam_jit.bouncer.decisions import Decision, DecisionRecord, Mode
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import BouncerStore, default_db_path


@pytest.fixture
def store(tmp_path) -> BouncerStore:
    db = tmp_path / "state.db"
    s = BouncerStore(db_path=db)
    yield s
    s.close()


def _rule(**overrides) -> ProxyRule:
    defaults = {"pattern": "s3:GetObject", "effect": Effect.ALLOW}
    defaults.update(overrides)
    return ProxyRule(**defaults)


def _decision(**overrides) -> DecisionRecord:
    defaults = {
        "decision": Decision.ALLOW,
        "mode": Mode.ENFORCE,
        "service": "s3",
        "action": "GetObject",
        "arn": None,
        "region": None,
        "matched_rule": None,
        "reason": "explicit-allow rule",
    }
    defaults.update(overrides)
    return DecisionRecord(**defaults)


# ---------------------------------------------------------------------------
# Initialization + schema
# ---------------------------------------------------------------------------


def test_init_creates_db_file(tmp_path) -> None:
    db = tmp_path / "x" / "y" / "state.db"
    BouncerStore(db_path=db)
    assert db.exists()


def test_default_db_path_respects_env_var(monkeypatch, tmp_path) -> None:
    custom = tmp_path / "custom.db"
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(custom))
    assert default_db_path() == custom


def test_default_db_path_falls_back_to_home(monkeypatch) -> None:
    monkeypatch.delenv("IAM_JIT_BOUNCER_DB", raising=False)
    path = default_db_path()
    assert path.name == "state.db"
    assert "bouncer" in str(path)


def test_init_is_idempotent(tmp_path) -> None:
    """Opening the same DB twice should not raise nor wipe data."""
    db = tmp_path / "state.db"
    s1 = BouncerStore(db_path=db)
    s1.add_rule(_rule(pattern="s3:GetObject"))
    s1.close()
    s2 = BouncerStore(db_path=db)
    try:
        assert len(s2.list_rules()) == 1
    finally:
        s2.close()


# ---------------------------------------------------------------------------
# Rules CRUD
# ---------------------------------------------------------------------------


def test_add_rule_returns_id(store: BouncerStore) -> None:
    rid = store.add_rule(_rule())
    assert rid > 0


def test_list_rules_empty(store: BouncerStore) -> None:
    assert store.list_rules() == []


def test_list_rules_returns_in_insertion_order(store: BouncerStore) -> None:
    store.add_rule(_rule(pattern="s3:GetObject"))
    store.add_rule(_rule(pattern="iam:*", effect=Effect.DENY))
    rules = store.list_rules()
    assert len(rules) == 2
    assert rules[0][1].pattern == "s3:GetObject"
    assert rules[1][1].pattern == "iam:*"
    assert rules[1][1].effect == Effect.DENY


def test_get_rule_round_trip(store: BouncerStore) -> None:
    rid = store.add_rule(_rule(
        pattern="s3:GetObject",
        arn_scope="arn:aws:s3:::my-bucket/*",
        region_scope="us-east-1",
        note="dev access",
    ))
    r = store.get_rule(rid)
    assert r is not None
    assert r.pattern == "s3:GetObject"
    assert r.arn_scope == "arn:aws:s3:::my-bucket/*"
    assert r.region_scope == "us-east-1"
    assert r.note == "dev access"


def test_get_rule_nonexistent_returns_none(store: BouncerStore) -> None:
    assert store.get_rule(99999) is None


def test_remove_rule_returns_true_on_success(store: BouncerStore) -> None:
    rid = store.add_rule(_rule())
    assert store.remove_rule(rid) is True
    assert store.get_rule(rid) is None


def test_remove_rule_returns_false_when_not_found(store: BouncerStore) -> None:
    assert store.remove_rule(99999) is False


# ---------------------------------------------------------------------------
# Decisions / audit log
# ---------------------------------------------------------------------------


def test_record_decision_returns_id(store: BouncerStore) -> None:
    rid = store.record_decision(_decision())
    assert rid > 0


def test_count_decisions(store: BouncerStore) -> None:
    assert store.count_decisions() == 0
    store.record_decision(_decision())
    store.record_decision(_decision())
    assert store.count_decisions() == 2


def test_list_decisions_newest_first(store: BouncerStore) -> None:
    store.record_decision(_decision(action="A"))
    store.record_decision(_decision(action="B"))
    store.record_decision(_decision(action="C"))
    rows = store.list_decisions()
    assert [r["action"] for r in rows] == ["C", "B", "A"]


def test_list_decisions_respects_limit(store: BouncerStore) -> None:
    for i in range(20):
        store.record_decision(_decision(action=f"A{i}"))
    rows = store.list_decisions(limit=5)
    assert len(rows) == 5


def test_list_decisions_hard_caps_extremely_large_limit(store: BouncerStore) -> None:
    """Defensive: don't materialize a million rows on a typo."""
    store.record_decision(_decision())
    rows = store.list_decisions(limit=10**9)
    assert len(rows) == 1  # only 1 in DB; cap doesn't error


def test_list_decisions_filter_by_decision(store: BouncerStore) -> None:
    store.record_decision(_decision(decision=Decision.ALLOW, action="A"))
    store.record_decision(_decision(decision=Decision.DENY, action="B"))
    store.record_decision(_decision(decision=Decision.ALLOW, action="C"))
    denies = store.list_decisions(decision_filter=Decision.DENY)
    assert len(denies) == 1
    assert denies[0]["action"] == "B"


def test_record_decision_persists_matched_rule_id(store: BouncerStore) -> None:
    rid = store.add_rule(_rule(pattern="s3:GetObject", note="allow reads"))
    store.record_decision(_decision(), matched_rule_id=rid)
    rows = store.list_decisions()
    assert rows[0]["matched_rule_id"] == rid


def test_record_decision_unmatched_rule_is_null(store: BouncerStore) -> None:
    store.record_decision(_decision())
    rows = store.list_decisions()
    assert rows[0]["matched_rule_id"] is None
