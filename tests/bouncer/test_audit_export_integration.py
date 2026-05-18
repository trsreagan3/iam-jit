"""Integration: proxy.evaluate_request mirrors decisions to BOTH the
JSONL log writer and the HTTPS webhook pusher in the shared schema
(#252 Slice 1).

Per [[security-team-audit-export]]: the same helper builds the event
both channels consume, so a security team that subscribes to both
channels can reconcile them byte-for-byte.
"""

from __future__ import annotations

import asyncio
import json
import logging
import pathlib

import pytest

from iam_jit.bouncer.audit_export import (
    AuditLogWriter,
    WebhookPusher,
)
from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyMode,
    audit_export_status,
    evaluate_request,
    register_audit_log_writer,
    register_audit_webhook_pusher,
)
from iam_jit.bouncer.store import BouncerStore


# Re-use the fake session from the webhook test module.
from tests.bouncer.test_audit_export_webhook import (
    TEST_WEBHOOK_TOKEN_VALUE,
    _FakeSession,
)


def _sigv4_auth_header(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260518/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakefakefake"
    )


@pytest.fixture
def store(tmp_path: pathlib.Path):
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    yield s
    s.close()


@pytest.fixture
def restore_registry():
    """Tests in this module mutate the module-level audit-export
    registry. This fixture restores it after each test so the rest of
    the suite isn't polluted."""
    yield
    register_audit_log_writer(None)
    register_audit_webhook_pusher(None)


@pytest.mark.asyncio
async def test_evaluate_request_mirrors_to_both_channels_in_shared_schema(
    tmp_path: pathlib.Path, store, restore_registry,
) -> None:
    """One evaluate_request call → one event in the JSONL log AND one
    POST to the webhook, both carrying the same canonical event."""
    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path)
    await writer.start()
    register_audit_log_writer(writer)

    session = _FakeSession(statuses=[200])
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_WEBHOOK_TOKEN_VALUE,
        allow_internal=True,
        _session_factory=lambda: session,
    )
    await pusher.start()
    register_audit_webhook_pusher(pusher)

    try:
        # Fire a single SDK-shaped request; expect a DENY (no rules +
        # default deny).
        obs = evaluate_request(
            method="GET",
            host="s3.us-east-1.amazonaws.com",
            path="/my-bucket/file.txt",
            headers={
                "host": "s3.us-east-1.amazonaws.com",
                "authorization": _sigv4_auth_header(service="s3", region="us-east-1"),
                "x-amz-date": "20260518T000000Z",
            },
            body=None,
            query=None,
            store=store,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
        )
        assert obs.decision_verdict == "deny"

        # Drain.
        for _ in range(100):
            wrote = writer.status()["total_events"] >= 1
            posted = len(session.posts) >= 1
            if wrote and posted:
                break
            await asyncio.sleep(0.02)
    finally:
        await pusher.stop()
        await writer.stop()

    # JSONL channel.
    lines = log_path.read_text().splitlines()
    assert len(lines) == 1
    log_event = json.loads(lines[0])
    # Webhook channel.
    assert len(session.posts) == 1
    webhook_event = json.loads(session.posts[0]["data"])

    # The two channels emit the SAME event (`ts` will be identical
    # because audit_event_from_decision is called ONCE per decision).
    assert log_event == webhook_event

    # Shape checks against the shared schema.
    assert log_event["product"] == "ibounce"
    assert log_event["event_type"] == "proxy.decision"
    assert log_event["verdict"] == "deny"
    assert log_event["service"] == "s3"
    assert log_event["mode"] == "transparent"
    assert log_event["ext"]["enforced"] is True


@pytest.mark.asyncio
async def test_audit_export_status_aggregates_both_channels(
    tmp_path: pathlib.Path, store, restore_registry,
) -> None:
    """The MCP `bouncer_audit_export_status` tool surfaces both
    channels' counters in one snapshot."""
    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path)
    await writer.start()
    register_audit_log_writer(writer)

    session = _FakeSession(statuses=[200])
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_WEBHOOK_TOKEN_VALUE,
        allow_internal=True,
        _session_factory=lambda: session,
    )
    await pusher.start()
    register_audit_webhook_pusher(pusher)

    try:
        # Two evaluate_request calls.
        for _ in range(2):
            evaluate_request(
                method="GET",
                host="s3.us-east-1.amazonaws.com",
                path="/my-bucket/file.txt",
                headers={
                    "host": "s3.us-east-1.amazonaws.com",
                    "authorization": _sigv4_auth_header(service="s3", region="us-east-1"),
                    "x-amz-date": "20260518T000000Z",
                },
                body=None,
                query=None,
                store=store,
                mode=ProxyMode.TRANSPARENT,
                default_policy=DefaultPolicy.DENY,
            )
        # Drain.
        for _ in range(100):
            if (
                writer.status()["total_events"] >= 2
                and len(session.posts) >= 2
            ):
                break
            await asyncio.sleep(0.02)

        status = audit_export_status()
        assert status["log"]["configured"] is True
        assert status["webhook"]["configured"] is True
        assert status["log"]["total_events"] == 2
        assert status["webhook"]["total_events"] == 2
        # Token is masked in the status snapshot.
        assert status["webhook"]["token"] == "***"
        assert TEST_WEBHOOK_TOKEN_VALUE not in json.dumps(status)
    finally:
        await pusher.stop()
        await writer.stop()


@pytest.mark.asyncio
async def test_status_when_no_channels_configured(restore_registry) -> None:
    """When no channels are installed, status() still returns a
    well-shaped object (no KeyErrors at the MCP layer)."""
    register_audit_log_writer(None)
    register_audit_webhook_pusher(None)
    status = audit_export_status()
    assert status["log"]["configured"] is False
    assert status["webhook"]["configured"] is False
    assert status["total_events"] == 0
    assert status["dropped_events"] == 0


@pytest.mark.asyncio
async def test_evaluate_request_never_raises_on_log_writer_failure(
    tmp_path, store, restore_registry, caplog,
) -> None:
    """If the audit log writer raises during write(), evaluate_request
    still returns a valid observation — audit channel failures must
    never crash the proxy hot-path."""
    class _ExplodingWriter:
        def write(self, event):
            raise RuntimeError("disk on fire")

        def status(self):
            return {"configured": True, "exploding": True}

    register_audit_log_writer(_ExplodingWriter())

    with caplog.at_level(logging.WARNING):
        obs = evaluate_request(
            method="GET",
            host="s3.us-east-1.amazonaws.com",
            path="/my-bucket/file.txt",
            headers={
                "host": "s3.us-east-1.amazonaws.com",
                "authorization": _sigv4_auth_header(service="s3", region="us-east-1"),
                "x-amz-date": "20260518T000000Z",
            },
            body=None,
            query=None,
            store=store,
            mode=ProxyMode.TRANSPARENT,
        )

    assert obs.decision_verdict == "deny"
    # The proxy logs SOMETHING about the failure but the request still
    # got its observation (no exception leaked out of evaluate_request).
    assert any(
        "audit" in r.message.lower() or "disk on fire" in r.message
        for r in caplog.records
    )
