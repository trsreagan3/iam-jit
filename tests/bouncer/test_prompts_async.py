"""Tests for `bouncer prompts` — async deny-prompt UX (#5 v1.0 subset).

Async means: agent gets DENIED immediately; operator sees the pending
prompt later + answers; future calls use the new rule. The
synchronous flow where the proxy briefly waits is v1.1.

Covers:
- proxy with prompt_on_deny=False does NOT enqueue prompts
- proxy with prompt_on_deny=True enqueues on transparent-mode DENY
- prompt_on_deny=True does NOT enqueue on ALLOW or on cooperative-mode DENY
- prompt_on_deny=True does NOT enqueue when a pause is active (already bypassed)
- add_pending_prompt is idempotent per decision_id
- list_pending_prompts filters by status
- answer_pending_prompt records the answer + marks status='answered'
- answer_pending_prompt is a no-op for already-answered prompts
- answer kind validation rejects unknown values
"""

from __future__ import annotations

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import ProxyMode, evaluate_request
from iam_jit.bouncer.store import BouncerStore


def _sigv4(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260517/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fake"
    )


def _make_call(store, *, mode=ProxyMode.TRANSPARENT, prompt_on_deny=False,
                path="/my-bucket/x"):
    return evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path=path,
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4(service="s3", region="us-east-1"),
        },
        body=None, query=None,
        store=store,
        mode=mode,
        default_policy=DefaultPolicy.DENY,
        prompt_on_deny=prompt_on_deny,
    )


def test_no_enqueue_when_flag_off(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    _make_call(store, prompt_on_deny=False)
    assert store.list_pending_prompts(status="pending") == []
    store.close()


def test_enqueues_on_transparent_deny(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    _make_call(store, mode=ProxyMode.TRANSPARENT, prompt_on_deny=True)
    rows = store.list_pending_prompts(status="pending")
    assert len(rows) == 1
    assert rows[0]["service"] == "s3"
    assert rows[0]["action"] == "GetObject"
    assert rows[0]["status"] == "pending"
    store.close()


def test_does_not_enqueue_on_cooperative_deny(tmp_path) -> None:
    """Cooperative mode never actually 403s the agent; the deny is
    only advisory. Prompting here would be noise — the agent's call
    succeeded upstream."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    _make_call(store, mode=ProxyMode.COOPERATIVE, prompt_on_deny=True)
    assert store.list_pending_prompts(status="pending") == []
    store.close()


def test_does_not_enqueue_on_allow(tmp_path) -> None:
    from iam_jit.bouncer.rules import Effect, ProxyRule
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    store.add_rule(
        ProxyRule(pattern="s3:GetObject", effect=Effect.ALLOW,
                  arn_scope=None, region_scope=None,
                  note="permissive", origin="manual"),
        actor="t",
    )
    _make_call(store, mode=ProxyMode.TRANSPARENT, prompt_on_deny=True)
    assert store.list_pending_prompts(status="pending") == []
    store.close()


def test_does_not_enqueue_when_paused(tmp_path) -> None:
    """A pause already bypasses enforcement — the agent isn't being
    denied; no prompt to surface."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    store.start_pause(duration_seconds=600, reason="", started_by="t")
    _make_call(store, mode=ProxyMode.TRANSPARENT, prompt_on_deny=True)
    assert store.list_pending_prompts(status="pending") == []
    store.close()


def test_add_pending_prompt_idempotent_per_decision(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    p1 = store.add_pending_prompt(
        decision_id=42, service="s3", action="GetObject",
        arn="arn:aws:s3:::b", region="us-east-1", deny_reason="t",
    )
    p2 = store.add_pending_prompt(
        decision_id=42, service="s3", action="GetObject",
        arn="arn:aws:s3:::b", region="us-east-1", deny_reason="t",
    )
    assert p1 == p2  # Same id returned
    assert len(store.list_pending_prompts()) == 1
    store.close()


def test_list_filters_by_status(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    pid = store.add_pending_prompt(
        decision_id=1, service="s3", action="GetObject",
        arn=None, region=None, deny_reason="t",
    )
    assert len(store.list_pending_prompts(status="pending")) == 1
    assert len(store.list_pending_prompts(status="answered")) == 0
    store.answer_pending_prompt(
        pid, answer_kind="ignore", answer_target=None, answered_by="t",
    )
    assert len(store.list_pending_prompts(status="pending")) == 0
    assert len(store.list_pending_prompts(status="answered")) == 1
    store.close()


def test_answer_pending_prompt_records_fields(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    pid = store.add_pending_prompt(
        decision_id=1, service="s3", action="GetObject",
        arn=None, region=None, deny_reason="t",
    )
    ok = store.answer_pending_prompt(
        pid, answer_kind="profile", answer_target="my-prof",
        answered_by="alice",
    )
    assert ok is True
    row = store.get_pending_prompt(pid)
    assert row["status"] == "answered"
    assert row["answer_kind"] == "profile"
    assert row["answer_target"] == "my-prof"
    assert row["answered_by"] == "alice"
    assert row["answered_at"] is not None
    store.close()


def test_answer_idempotent_no_op_on_already_answered(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    pid = store.add_pending_prompt(
        decision_id=1, service="s3", action="GetObject",
        arn=None, region=None, deny_reason="t",
    )
    store.answer_pending_prompt(
        pid, answer_kind="ignore", answer_target=None, answered_by="t1",
    )
    # Second call returns False — no row was updated
    ok = store.answer_pending_prompt(
        pid, answer_kind="always", answer_target=None, answered_by="t2",
    )
    assert ok is False
    # Original answer preserved
    row = store.get_pending_prompt(pid)
    assert row["answer_kind"] == "ignore"
    assert row["answered_by"] == "t1"
    store.close()


def test_answer_kind_validation(tmp_path) -> None:
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    pid = store.add_pending_prompt(
        decision_id=1, service="s3", action="GetObject",
        arn=None, region=None, deny_reason="t",
    )
    with pytest.raises(ValueError, match="answer_kind"):
        store.answer_pending_prompt(
            pid, answer_kind="bogus", answer_target=None, answered_by="t",
        )
    store.close()


def test_decision_id_links_back_to_decisions_row(tmp_path) -> None:
    """The pending_prompts.decision_id is supposed to JOIN cleanly to
    the decisions.id. If the linkage broke, post-hoc review couldn't
    tell which exact request triggered each prompt."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    _make_call(store, mode=ProxyMode.TRANSPARENT, prompt_on_deny=True)
    rows = store.list_pending_prompts()
    decision_id = rows[0]["decision_id"]
    cur = store._conn.execute(
        "SELECT service, action FROM decisions WHERE id = ?",
        (decision_id,),
    )
    decision_row = cur.fetchone()
    assert decision_row is not None
    assert decision_row[0] == "s3"
    assert decision_row[1] == "GetObject"
    store.close()
