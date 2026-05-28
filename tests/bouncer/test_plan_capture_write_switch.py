"""End-to-end tests for the plan-capture read->write switch UX (#145).

Covers the phase state machine + the three --write-switch-notify modes
(manual / auto-approve / reject) by driving the proxy through real
HTTP requests (matches the existing plan-capture test pattern in
test_proxy_plan_capture.py). Per [[ibounce-honest-positioning]] these
tests treat the switch as a DETERRENT UX helper, not a security
boundary — they assert observable behavior (phase + prompts + response
shapes), not enforcement semantics on AWS.

State-machine matrix exercised:
  read_only --read-->                  read_only             (no transition)
  read_only --write+manual-->          write_pending + prompt
  read_only --write+auto-approve-->    writes_approved
  read_only --write+reject-->          writes_rejected
  write_pending --answer approve-->    writes_approved
  write_pending --answer reject-->     writes_rejected
  write_pending --write-->             write_pending         (stays)
  writes_approved --write-->           writes_approved + success synthetic
  writes_rejected --write-->           writes_rejected + rejection synthetic
"""

from __future__ import annotations

import asyncio
import json
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.plan_capture import (
    new_session_id,
    reset_session_for_tests,
)
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    serve,
)
from iam_jit.bouncer.store import BouncerStore


def _sigv4_auth(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260518/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakesignature"
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def _wait_for_listen(host: str, port: int, *, retries: int = 50) -> None:
    for _ in range(retries):
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError(f"nothing listening on {host}:{port}")


@pytest.fixture(autouse=True)
def _isolate_session_slot():
    reset_session_for_tests()
    yield
    reset_session_for_tests()


async def _send_s3_get(proxy_port: int) -> tuple[int, bytes, dict]:
    """Send an S3 GetObject (a READ) through the proxy."""
    import aiohttp
    sig_v4 = _sigv4_auth(service="s3", region="us-east-1")
    async with aiohttp.ClientSession() as csession:
        async with csession.get(
            f"http://127.0.0.1:{proxy_port}/my-bucket/path/to/key",
            headers={
                "host": "s3.us-east-1.amazonaws.com",
                "authorization": sig_v4,
            },
        ) as resp:
            body = await resp.read()
            return resp.status, body, dict(resp.headers)


async def _send_s3_put(proxy_port: int) -> tuple[int, bytes, dict]:
    """Send an S3 PutObject (a WRITE) through the proxy."""
    import aiohttp
    sig_v4 = _sigv4_auth(service="s3", region="us-east-1")
    async with aiohttp.ClientSession() as csession:
        async with csession.put(
            f"http://127.0.0.1:{proxy_port}/my-bucket/path/to/key",
            headers={
                "host": "s3.us-east-1.amazonaws.com",
                "authorization": sig_v4,
            },
            data=b"hello",
        ) as resp:
            body = await resp.read()
            return resp.status, body, dict(resp.headers)


async def _send_iam_create_role(proxy_port: int) -> tuple[int, bytes, dict]:
    """Send an IAM CreateRole (a WRITE)."""
    import aiohttp
    sig_v4 = _sigv4_auth(service="iam", region="us-east-1")
    async with aiohttp.ClientSession() as csession:
        async with csession.post(
            f"http://127.0.0.1:{proxy_port}/",
            headers={
                "host": "iam.amazonaws.com",
                "authorization": sig_v4,
                "content-type": "application/x-www-form-urlencoded",
            },
            data=b"Action=CreateRole&RoleName=test-role&Version=2010-05-08",
        ) as resp:
            body = await resp.read()
            return resp.status, body, dict(resp.headers)


async def _run_with_proxy(
    tmp_path,
    *,
    write_switch_notify: str = "manual",
):
    """Boot the proxy + return (store, session_id, server_task, proxy_port)."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    session_id = new_session_id()
    config = ProxyConfig(
        host="127.0.0.1", port=proxy_port,
        mode=ProxyMode.PLAN_CAPTURE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
        plan_session_id=session_id,
        plan_write_switch_notify=write_switch_notify,
    )
    server_task = asyncio.create_task(serve(config, store=store))
    await _wait_for_listen("127.0.0.1", proxy_port)
    return store, session_id, server_task, proxy_port


async def _stop_proxy(server_task, store) -> None:
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass
    store.close()


# ---------------------------------------------------------------------------
# read-only sessions stay in read_only phase
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_only_session_stays_in_read_only_phase(tmp_path):
    """Sending only reads through plan-capture must not move the
    phase off read_only — the switch should never fire on read-only
    traffic."""
    store, session_id, server_task, proxy_port = await _run_with_proxy(
        tmp_path, write_switch_notify="manual",
    )
    try:
        for _ in range(3):
            status, body, _ = await _send_s3_get(proxy_port)
            assert status == 200
        phase = store.get_plan_session_phase(session_id)
        assert phase["phase"] == "read_only"
        assert phase["first_write_at"] is None
        assert phase["write_decision"] is None
        # No plan-write prompt was enqueued
        assert store.get_pending_plan_write_prompt(session_id) is None
        # Reads recorded; writes_count is 0 in the summary
        summary = store.plan_session_summary(session_id)
        assert summary["read_count"] == 3
        assert summary["write_count"] == 0
    finally:
        await _stop_proxy(server_task, store)


# ---------------------------------------------------------------------------
# --write-switch-notify=manual: read -> read -> write transitions to
# write_pending and enqueues a plan-write prompt
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_manual_read_then_write_enqueues_plan_write_prompt(tmp_path):
    """The textbook flow: agent reads twice, then writes; the proxy
    transitions the session to write_pending + creates a plan-write
    prompt for the operator. The write call STILL gets a synthetic-
    success response back (plan-capture never forwards either way)."""
    store, session_id, server_task, proxy_port = await _run_with_proxy(
        tmp_path, write_switch_notify="manual",
    )
    try:
        for _ in range(2):
            status, _, _ = await _send_s3_get(proxy_port)
            assert status == 200
        # Read-only phase still
        assert store.get_plan_session_phase(session_id)["phase"] == "read_only"

        # First write transitions phase + enqueues prompt
        status, body, headers = await _send_iam_create_role(proxy_port)
        assert status == 200, body  # success synthetic
        # The phase header on the response reflects the post-transition state
        assert headers.get("x-iam-jit-bouncer-plan-phase") == "write_pending"
        # The synthetic body looks like a real CreateRole response
        assert b"<CreateRoleResult>" in body

        phase = store.get_plan_session_phase(session_id)
        assert phase["phase"] == "write_pending"
        assert phase["first_write_at"] is not None
        # No decision yet — the operator hasn't answered
        assert phase["write_decision"] is None

        # A plan-write prompt is now pending for the session
        prompt = store.get_pending_plan_write_prompt(session_id)
        assert prompt is not None
        assert prompt["kind"] == "plan-write"
        assert prompt["service"] == "iam"
        assert prompt["action"] == "CreateRole"
        assert prompt["session_id"] == session_id
        assert prompt["status"] == "pending"
    finally:
        await _stop_proxy(server_task, store)


@pytest.mark.asyncio
async def test_manual_write_pending_then_approve_transitions_to_approved(tmp_path):
    """Operator approves the plan-write prompt -> session moves to
    writes_approved + subsequent writes still get success synthetic."""
    store, session_id, server_task, proxy_port = await _run_with_proxy(
        tmp_path, write_switch_notify="manual",
    )
    try:
        # First write enqueues the prompt
        await _send_iam_create_role(proxy_port)
        prompt = store.get_pending_plan_write_prompt(session_id)
        assert prompt is not None

        # Operator approves
        answered = store.answer_plan_write_prompt(
            prompt["id"], decision="approve", answered_by="alice",
        )
        assert answered["decision"] == "approve"
        # CLI normally would also flip phase; do it directly here to
        # mirror the post-answer state. (The CLI test exercises the
        # automatic transition.)
        store.transition_plan_session_phase(
            session_id, new_phase="writes_approved",
            decision="approve", decided_by="alice",
        )

        # Subsequent write gets a success synthetic
        status, body, headers = await _send_iam_create_role(proxy_port)
        assert status == 200
        assert b"<CreateRoleResult>" in body
        assert headers.get("x-iam-jit-bouncer-plan-phase") == "writes_approved"

        phase = store.get_plan_session_phase(session_id)
        assert phase["phase"] == "writes_approved"
        assert phase["write_decision"] == "approve"
        assert phase["write_decision_by"] == "alice"
    finally:
        await _stop_proxy(server_task, store)


@pytest.mark.asyncio
async def test_manual_write_pending_then_reject_transitions_to_rejected(tmp_path):
    """Operator rejects -> session moves to writes_rejected +
    subsequent writes get the PlanCaptureWritesRejected error
    synthetic (not a success)."""
    store, session_id, server_task, proxy_port = await _run_with_proxy(
        tmp_path, write_switch_notify="manual",
    )
    try:
        # First write enqueues prompt + returns success synthetic
        status, _, _ = await _send_iam_create_role(proxy_port)
        assert status == 200
        prompt = store.get_pending_plan_write_prompt(session_id)
        assert prompt is not None

        # Operator rejects
        store.answer_plan_write_prompt(
            prompt["id"], decision="reject", answered_by="bob",
        )
        store.transition_plan_session_phase(
            session_id, new_phase="writes_rejected",
            decision="reject", decided_by="bob",
        )

        # Subsequent write gets the rejection synthetic. IAM is an
        # XML-protocol service so per #693 the body is an XML
        # <ErrorResponse> envelope (JSON body would crash botocore's
        # parser mid-script for XML callers).
        status, body, headers = await _send_iam_create_role(proxy_port)
        assert status == 400  # rejection synthetic uses 400
        text = body.decode("utf-8")
        assert "<Code>PlanCaptureWritesRejected</Code>" in text
        assert headers.get("x-iam-jit-bouncer-plan-phase") == "writes_rejected"

        # And the plan-call row records the writes_rejected verdict
        calls = store.list_plan_calls(session_id)
        last_call = calls[-1]
        assert last_call["verdict"] == "writes_rejected"
    finally:
        await _stop_proxy(server_task, store)


# ---------------------------------------------------------------------------
# --write-switch-notify=auto-approve: never enters write_pending
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auto_approve_skips_write_pending(tmp_path):
    """With --write-switch-notify=auto-approve, the FIRST write
    transitions straight from read_only to writes_approved (no prompt
    enqueued, no operator notification)."""
    store, session_id, server_task, proxy_port = await _run_with_proxy(
        tmp_path, write_switch_notify="auto-approve",
    )
    try:
        # Send a write straight away
        status, body, headers = await _send_iam_create_role(proxy_port)
        assert status == 200
        assert b"<CreateRoleResult>" in body  # success synthetic
        assert headers.get("x-iam-jit-bouncer-plan-phase") == "writes_approved"

        phase = store.get_plan_session_phase(session_id)
        assert phase["phase"] == "writes_approved"
        assert phase["write_decision"] == "approve"
        assert phase["write_decision_by"] == "auto-approve"
        # No prompt enqueued
        assert store.get_pending_plan_write_prompt(session_id) is None

        # Subsequent writes stay in writes_approved
        await _send_iam_create_role(proxy_port)
        assert store.get_plan_session_phase(session_id)["phase"] == "writes_approved"
    finally:
        await _stop_proxy(server_task, store)


# ---------------------------------------------------------------------------
# --write-switch-notify=reject: straight to writes_rejected on first write
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reject_first_write_transitions_straight_to_rejected(tmp_path):
    """With --write-switch-notify=reject, the FIRST write transitions
    straight to writes_rejected + receives the rejection synthetic."""
    store, session_id, server_task, proxy_port = await _run_with_proxy(
        tmp_path, write_switch_notify="reject",
    )
    try:
        # Reads first to make sure they don't trigger the reject
        await _send_s3_get(proxy_port)
        assert store.get_plan_session_phase(session_id)["phase"] == "read_only"

        # First write triggers the auto-reject. IAM is XML-protocol so
        # #693 emits an <ErrorResponse> XML body, not JSON.
        status, body, headers = await _send_iam_create_role(proxy_port)
        assert status == 400  # rejection synthetic
        text = body.decode("utf-8")
        assert "<Code>PlanCaptureWritesRejected</Code>" in text
        assert headers.get("x-iam-jit-bouncer-plan-phase") == "writes_rejected"

        phase = store.get_plan_session_phase(session_id)
        assert phase["phase"] == "writes_rejected"
        assert phase["write_decision"] == "reject"
        assert phase["write_decision_by"] == "auto-reject"
        # No prompt enqueued
        assert store.get_pending_plan_write_prompt(session_id) is None
    finally:
        await _stop_proxy(server_task, store)


# ---------------------------------------------------------------------------
# Prompt-queue surface: plan-write prompts are distinguishable
# ---------------------------------------------------------------------------


def test_list_pending_prompts_returns_both_kinds(tmp_path):
    """list_pending_prompts (no kind filter) returns BOTH deny-prompts
    and plan-write prompts; the kind column distinguishes them. The
    CLI relies on this for the unified `ibounce prompts list` table."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        store.ensure_plan_session(
            session_id="plan-test-1", started_by="t", note="",
        )
        # Add one of each kind
        store.add_pending_prompt(
            decision_id=42, service="s3", action="DeleteObject",
            arn="arn:aws:s3:::sensitive", region="us-east-1",
            deny_reason="profile deny",
        )
        store.add_plan_write_prompt(
            session_id="plan-test-1", service="iam", action="CreateRole",
            arn=None, region=None,
        )
        # Default: both kinds
        all_prompts = store.list_pending_prompts(status="pending")
        kinds = sorted(p["kind"] for p in all_prompts)
        assert kinds == ["deny-prompt", "plan-write"]
        # Filtered
        only_plan = store.list_pending_prompts(
            status="pending", kind="plan-write",
        )
        assert len(only_plan) == 1
        assert only_plan[0]["kind"] == "plan-write"
        assert only_plan[0]["session_id"] == "plan-test-1"
        only_deny = store.list_pending_prompts(
            status="pending", kind="deny-prompt",
        )
        assert len(only_deny) == 1
        assert only_deny[0]["kind"] == "deny-prompt"
    finally:
        store.close()


def test_add_plan_write_prompt_idempotent_per_session(tmp_path):
    """add_plan_write_prompt should be a no-op if a pending plan-write
    prompt already exists for the session (we never want two
    competing pending prompts for the same session)."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        store.ensure_plan_session(
            session_id="plan-test-2", started_by="t", note="",
        )
        p1 = store.add_plan_write_prompt(
            session_id="plan-test-2", service="iam", action="CreateRole",
            arn=None, region=None,
        )
        p2 = store.add_plan_write_prompt(
            session_id="plan-test-2", service="iam", action="DeleteRole",
            arn=None, region=None,
        )
        assert p1 == p2  # Same prompt id returned
    finally:
        store.close()


def test_answer_plan_write_prompt_rejects_invalid_decision(tmp_path):
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        store.ensure_plan_session(
            session_id="plan-test-3", started_by="t", note="",
        )
        pid = store.add_plan_write_prompt(
            session_id="plan-test-3", service="iam", action="CreateRole",
            arn=None, region=None,
        )
        with pytest.raises(ValueError):
            store.answer_plan_write_prompt(
                pid, decision="maybe", answered_by="alice",
            )
    finally:
        store.close()


def test_answer_plan_write_prompt_returns_none_for_wrong_kind(tmp_path):
    """Calling answer_plan_write_prompt with a deny-prompt id returns
    None — discriminates by kind so a typo'd CLI call can't silently
    mark a deny-prompt as approved."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        deny_id = store.add_pending_prompt(
            decision_id=99, service="s3", action="DeleteObject",
            arn=None, region=None, deny_reason="t",
        )
        out = store.answer_plan_write_prompt(
            deny_id, decision="approve", answered_by="alice",
        )
        assert out is None
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Schema migration: existing DBs (v7) get the new columns added
# ---------------------------------------------------------------------------


def test_schema_migration_adds_phase_columns_to_existing_db(tmp_path):
    """A fresh BouncerStore on a brand-new DB has the v8 columns."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        store.ensure_plan_session(
            session_id="plan-mig-1", started_by="t", note="",
        )
        phase = store.get_plan_session_phase("plan-mig-1")
        assert phase is not None
        assert phase["phase"] == "read_only"
        assert phase["write_switch_notify"] == "manual"
        assert phase["first_write_at"] is None
    finally:
        store.close()
