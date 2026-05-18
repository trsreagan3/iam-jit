"""#271 — GET /audit/events HTTP endpoint tests for ibounce.

Sibling of the gbounce / kbounce / dbounce audit_events tests; covers
the same set of request shapes (filter / limit / time-bounds / format /
auth) to keep cross-product parity verifiable per
``[[cross-product-agent-parity]]``.

The handler reads the JSONL audit log written by :class:`AuditLogWriter`;
the tests seed a temp file with a fixed event set + drive the handler
via aiohttp's in-process TestClient so we don't bind a real port.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
import pathlib
import time as _time
from collections.abc import Iterator
from typing import Any

import pytest


def _ev(
    *,
    seconds_ago: int,
    operation: str,
    actor: str = "alice",
    severity_id: int = 1,
    event_type: str = "DECISION",
    verdict: str = "ALLOW",
    region: str = "us-east-1",
) -> dict[str, Any]:
    """Build one OCSF v1.1.0 class 6003 event dict matching the wire
    shape AuditLogWriter emits. Time is Unix ms per OCSF."""
    now_ms = int(_time.time() * 1000)
    return {
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "iam-jit-bouncer", "vendor_name": "iam-jit"},
        },
        "time": now_ms - seconds_ago * 1000,
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "activity_id": 2,
        "activity_name": "Read",
        "severity_id": severity_id,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "actor": {"user": {"name": actor}},
        "api": {"operation": operation, "service": {"name": "iam-jit-bouncer"}},
        "resources": [],
        "unmapped": {
            "iam_jit": {
                "verdict": verdict,
                "mode": "cooperative",
                "event_type": event_type,
                "ext": {"aws_region": region},
            },
        },
    }


@pytest.fixture
def seeded_audit_log(tmp_path: pathlib.Path) -> Iterator[pathlib.Path]:
    """Write a JSONL audit log to a temp path + return the path."""
    log = tmp_path / "audit.jsonl"
    events = [
        _ev(seconds_ago=300, operation="s3:GetObject", actor="alice"),
        _ev(seconds_ago=200, operation="ec2:DescribeInstances", actor="bob", severity_id=3),
        _ev(seconds_ago=100, operation="s3:PutObject", actor="alice", verdict="DENY"),
    ]
    with log.open("w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    yield log


def _make_app(audit_log_path: pathlib.Path, require_bearer: str | None = None):
    """Build a fresh aiohttp.web.Application with /audit/events
    registered. Must be created inside the same event-loop as
    TestServer.setup runs in, so we build per-call rather than as a
    fixture (aiohttp pins the app to ONE loop)."""
    pytest.importorskip("aiohttp")
    from aiohttp import web

    from iam_jit.bouncer.audit_export.events_endpoint import (
        register_audit_events_route,
    )
    app = web.Application()
    register_audit_events_route(
        app, audit_log_path=audit_log_path, require_bearer=require_bearer,
    )
    return app


async def _request_in_loop(
    audit_log_path: pathlib.Path,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    require_bearer: str | None = None,
):
    """Run one HTTP request against a fresh app inside the active
    event loop + return (status, body, headers)."""
    from aiohttp.test_utils import TestClient, TestServer
    app = _make_app(audit_log_path, require_bearer=require_bearer)
    async with TestClient(TestServer(app)) as client:
        async with client.get(path, headers=headers or {}) as resp:
            return resp.status, await resp.text(), dict(resp.headers)


def _run(audit_log_path, path, headers=None, require_bearer=None):
    """Synchronous wrapper: create a fresh event loop + drive the
    request to completion. Tests call this; no async fixtures needed."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            _request_in_loop(
                audit_log_path, path,
                headers=headers, require_bearer=require_bearer,
            ),
        )
    finally:
        loop.close()


def test_get_returns_jsonl(seeded_audit_log):
    status, body, headers = _run(seeded_audit_log, "/audit/events?limit=10")
    assert status == 200, body
    assert "application/x-ndjson" in headers.get("Content-Type", "")
    lines = [line for line in body.split("\n") if line.strip()]
    assert len(lines) == 3, lines
    for line in lines:
        json.loads(line)


def test_filter_by_actor_matches(seeded_audit_log):
    status, body, _ = _run(
        seeded_audit_log, "/audit/events?filter=actor.user.name=alice",
    )
    assert status == 200, body
    lines = [line for line in body.split("\n") if line.strip()]
    assert len(lines) == 2, "expected 2 alice events"


def test_filter_by_severity_numeric(seeded_audit_log):
    status, body, _ = _run(
        seeded_audit_log, "/audit/events?filter=severity_id>=3",
    )
    assert status == 200, body
    lines = [line for line in body.split("\n") if line.strip()]
    assert len(lines) == 1, "expected 1 severity>=3 event"


def test_bad_filter_returns_400(seeded_audit_log):
    status, body, _ = _run(
        seeded_audit_log, "/audit/events?filter=no_operator_here",
    )
    assert status == 400, body
    assert "filter" in json.loads(body)["error"].lower()


def test_limit_caps_results(seeded_audit_log):
    status, body, _ = _run(seeded_audit_log, "/audit/events?limit=1")
    assert status == 200
    lines = [line for line in body.split("\n") if line.strip()]
    assert len(lines) == 1


def test_limit_over_max_rejected(seeded_audit_log):
    status, body, _ = _run(seeded_audit_log, "/audit/events?limit=10000")
    assert status == 400
    assert "exceeds max" in json.loads(body)["error"]


def test_since_until_bounds_work(seeded_audit_log):
    future = (_dt.datetime.now(_dt.UTC) + _dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    status, body, _ = _run(seeded_audit_log, f"/audit/events?since={future}")
    assert status == 200
    lines = [line for line in body.split("\n") if line.strip()]
    assert len(lines) == 0
    past = (_dt.datetime.now(_dt.UTC) - _dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    status2, body2, _ = _run(seeded_audit_log, f"/audit/events?since={past}")
    assert status2 == 200
    lines2 = [line for line in body2.split("\n") if line.strip()]
    assert len(lines2) == 3


def test_bad_time_bound_returns_400(seeded_audit_log):
    status, body, _ = _run(seeded_audit_log, "/audit/events?since=not-a-time")
    assert status == 400
    assert "since" in json.loads(body)["error"]


def test_ocsf_bundle_format(seeded_audit_log):
    status, body, headers = _run(
        seeded_audit_log, "/audit/events?format=ocsf-bundle&limit=10",
    )
    assert status == 200, body
    assert "application/json" in headers.get("Content-Type", "")
    bundle = json.loads(body)
    assert bundle["class_uid"] == 2004
    assert bundle["class_name"] == "Detection Finding"
    # ibounce's build_ocsf_bundle nests events under finding.evidence
    # per the [[ocsf-audit-schema]] memo.
    events = bundle["finding"]["evidence"]["events"]
    assert len(events) == 3


def test_unknown_format_returns_400(seeded_audit_log):
    status, body, _ = _run(seeded_audit_log, "/audit/events?format=wat")
    assert status == 400
    assert "format" in json.loads(body)["error"]


def test_auth_token_missing_returns_401(seeded_audit_log):
    status, body, _ = _run(
        seeded_audit_log, "/audit/events", require_bearer="secret-token",
    )
    assert status == 401, body


def test_auth_token_wrong_returns_403(seeded_audit_log):
    status, body, _ = _run(
        seeded_audit_log, "/audit/events",
        headers={"Authorization": "Bearer wrong-token"},
        require_bearer="secret-token",
    )
    assert status == 403, body


def test_auth_token_correct_returns_200(seeded_audit_log):
    status, body, _ = _run(
        seeded_audit_log, "/audit/events",
        headers={"Authorization": "Bearer secret-token"},
        require_bearer="secret-token",
    )
    assert status == 200, body
