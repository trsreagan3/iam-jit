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


# ---------------------------------------------------------------------------
# §A31 / #360 — SQLite-fallback tests.
#
# The pre-§A31 handler ONLY read JSONL. When the operator never set
# --audit-log-path the file was missing and /audit/events returned []
# even though the SQLite decisions table had rows. Result: cross-bouncer
# fan-out silently excluded ibounce. Fix: when no JSONL is available,
# read from the BouncerStore and reconstruct OCSF events from rows.
# ---------------------------------------------------------------------------


def _seed_store_with_decisions(tmp_path: pathlib.Path):
    """Build a BouncerStore with a handful of recorded decisions."""
    from iam_jit.bouncer.decisions import Decision, DecisionRecord, Mode
    from iam_jit.bouncer.store import BouncerStore

    db = tmp_path / "bouncer.sqlite"
    store = BouncerStore(db_path=db)
    decs = [
        DecisionRecord(
            decision=Decision.ALLOW, mode=Mode.ENFORCE,
            service="s3", action="GetObject",
            arn="arn:aws:s3:::example-bucket/key",
            region="us-east-1", matched_rule=None,
            reason="profile allow",
        ),
        DecisionRecord(
            decision=Decision.DENY, mode=Mode.ENFORCE,
            service="iam", action="CreateUser",
            arn=None, region="us-east-1", matched_rule=None,
            reason="safe-default deny",
        ),
        DecisionRecord(
            decision=Decision.ALLOW, mode=Mode.LEARN,
            service="ec2", action="DescribeInstances",
            arn=None, region="us-west-2", matched_rule=None,
            reason="learn-mode allow",
        ),
    ]
    for d in decs:
        store.record_decision(d)
    return store


def _make_app_with_store(
    audit_log_path: pathlib.Path | None,
    store,
    require_bearer: str | None = None,
):
    """Variant of _make_app that wires the optional store fallback."""
    pytest.importorskip("aiohttp")
    from aiohttp import web

    from iam_jit.bouncer.audit_export.events_endpoint import (
        register_audit_events_route,
    )
    app = web.Application()
    register_audit_events_route(
        app,
        audit_log_path=audit_log_path,
        require_bearer=require_bearer,
        store=store,
    )
    return app


async def _request_with_store(
    audit_log_path: pathlib.Path | None,
    store,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    require_bearer: str | None = None,
):
    from aiohttp.test_utils import TestClient, TestServer
    app = _make_app_with_store(audit_log_path, store, require_bearer)
    async with TestClient(TestServer(app)) as client:
        async with client.get(path, headers=headers or {}) as resp:
            return resp.status, await resp.text(), dict(resp.headers)


def _run_with_store(audit_log_path, store, path, headers=None, require_bearer=None):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            _request_with_store(
                audit_log_path, store, path,
                headers=headers, require_bearer=require_bearer,
            ),
        )
    finally:
        loop.close()


def test_audit_events_endpoint_serves_from_sqlite_when_no_jsonl_configured(
    tmp_path,
):
    """§A31 core fix: no JSONL, store has decisions → events returned."""
    store = _seed_store_with_decisions(tmp_path)
    try:
        status, body, headers = _run_with_store(
            None, store, "/audit/events?limit=10",
        )
        assert status == 200, body
        assert "application/x-ndjson" in headers.get("Content-Type", "")
        lines = [line for line in body.split("\n") if line.strip()]
        assert len(lines) == 3, (
            "expected 3 reconstructed events from store; got " + body
        )
        # Spot-check the OCSF shape: every event MUST carry the wire-
        # contract fields a cross-bouncer consumer relies on.
        for line in lines:
            ev = json.loads(line)
            assert ev["class_uid"] == 6003, ev
            assert ev["class_name"] == "API Activity"
            assert "metadata" in ev
            assert "unmapped" in ev and "iam_jit" in ev["unmapped"]
            iam_block = ev["unmapped"]["iam_jit"]
            assert iam_block["verdict"] in {"allow", "deny", "prompt"}
            assert iam_block["mode"] in {"enforce", "learn", "prompt"}
    finally:
        store.close()


def test_audit_events_endpoint_prefers_jsonl_when_both_configured(
    tmp_path, seeded_audit_log,
):
    """§A31 backward-compat: JSONL takes precedence over the store.

    Operators who already configured --audit-log-path get exactly the
    same wire shape they did before (rich OCSF including agent
    identity); the store is only a fallback for the no-JSONL case.
    """
    store = _seed_store_with_decisions(tmp_path)
    try:
        status, body, _ = _run_with_store(
            seeded_audit_log, store, "/audit/events?limit=20",
        )
        assert status == 200, body
        lines = [line for line in body.split("\n") if line.strip()]
        # Both sources have 3 entries; we expect ONLY the JSONL rows
        # (3 events), not 6. JSONL events carry the actor.user.name
        # the fixture set; store-reconstructed events don't.
        assert len(lines) == 3, lines
        actors = {
            json.loads(line).get("actor", {}).get("user", {}).get("name")
            for line in lines
        }
        # Fixture actors are alice + bob; store rows would have no
        # actor.user.name (we didn't persist principal).
        assert actors == {"alice", "bob"}, (
            f"expected JSONL actors only; got {actors}"
        )
    finally:
        store.close()


def test_audit_events_endpoint_filters_apply_to_store_path(tmp_path):
    """§A31 — the same filter language works against the store path."""
    store = _seed_store_with_decisions(tmp_path)
    try:
        status, body, _ = _run_with_store(
            None, store,
            "/audit/events?filter=unmapped.iam_jit.verdict=deny",
        )
        assert status == 200, body
        lines = [line for line in body.split("\n") if line.strip()]
        assert len(lines) == 1, "expected 1 deny event from store"
        ev = json.loads(lines[0])
        assert ev["unmapped"]["iam_jit"]["verdict"] == "deny"
    finally:
        store.close()


def test_audit_events_endpoint_empty_when_no_jsonl_and_no_store(tmp_path):
    """§A31 — preserve the no-config no-data shape (return []).

    An operator with neither --audit-log-path nor a registered store
    still gets a 200 with an empty body, not a 500 or 404. Matches
    the legacy pre-§A31 behaviour for the no-config case.
    """
    missing = tmp_path / "no-such-file.jsonl"
    status, body, _ = _run_with_store(missing, None, "/audit/events")
    assert status == 200, body
    assert body.strip() == ""


def test_audit_events_endpoint_store_ocsf_bundle_format(tmp_path):
    """§A31 — ?format=ocsf-bundle wraps store events in a Detection
    Finding the same way the JSONL path does."""
    store = _seed_store_with_decisions(tmp_path)
    try:
        status, body, headers = _run_with_store(
            None, store, "/audit/events?format=ocsf-bundle",
        )
        assert status == 200, body
        assert "application/json" in headers.get("Content-Type", "")
        bundle = json.loads(body)
        assert bundle["class_uid"] == 2004
        assert bundle["class_name"] == "Detection Finding"
        evs = bundle["finding"]["evidence"]["events"]
        assert len(evs) == 3
    finally:
        store.close()


def test_audit_events_endpoint_returns_events_after_init_solo(tmp_path):
    """§A31 — the operator-flow regression test.

    Mirrors the operator path: `init-solo` provisions a store; the
    proxy records a decision into it; `/audit/events` MUST return the
    decision instead of an empty list (the pre-§A31 bug).
    """
    from iam_jit.bouncer.decisions import Decision, DecisionRecord, Mode
    from iam_jit.bouncer.store import BouncerStore

    # Step 1: provision a store (stand-in for `init-solo`).
    db = tmp_path / "post-init-solo.sqlite"
    store = BouncerStore(db_path=db)
    try:
        # Step 2: a proxy request lands and writes a decision.
        store.record_decision(DecisionRecord(
            decision=Decision.ALLOW, mode=Mode.ENFORCE,
            service="sts", action="GetCallerIdentity",
            arn=None, region="us-east-1", matched_rule=None,
            reason="readonly safe-default allow",
        ))
        # Step 3: cross-bouncer fan-out queries /audit/events.
        status, body, _ = _run_with_store(
            None, store, "/audit/events?limit=100",
        )
        assert status == 200, body
        lines = [line for line in body.split("\n") if line.strip()]
        assert len(lines) == 1, (
            "operator flow: a request was driven → exactly 1 event "
            f"must surface on /audit/events. Got: {body!r}"
        )
        ev = json.loads(lines[0])
        assert ev["api"]["operation"] == "sts:GetCallerIdentity"
        assert ev["unmapped"]["iam_jit"]["verdict"] == "allow"
    finally:
        store.close()


def test_cross_bouncer_fan_out_includes_ibounce_by_default(tmp_path):
    """§A31 — verifies the user-facing story: cross-bouncer fan-out
    finds ibounce decisions without the operator setting
    --audit-log-path. Integration-style: drive a decision, then query
    /audit/events the way `iam-jit audit query` would, and assert
    ibounce events surface."""
    from iam_jit.bouncer.decisions import Decision, DecisionRecord, Mode
    from iam_jit.bouncer.store import BouncerStore

    store = BouncerStore(db_path=tmp_path / "ib.sqlite")
    try:
        # Two decisions of mixed verdict so the cross-bouncer aggregator
        # sees both an allow and a deny from this bouncer.
        for d in (
            DecisionRecord(
                decision=Decision.ALLOW, mode=Mode.ENFORCE,
                service="s3", action="ListBuckets",
                arn=None, region=None, matched_rule=None,
                reason="profile allow",
            ),
            DecisionRecord(
                decision=Decision.DENY, mode=Mode.ENFORCE,
                service="iam", action="DeleteRole",
                arn=None, region=None, matched_rule=None,
                reason="safe-default deny",
            ),
        ):
            store.record_decision(d)

        # The `iam-jit audit query` CLI calls the endpoint with no
        # extra config — operator never configured --audit-log-path.
        status, body, _ = _run_with_store(None, store, "/audit/events")
        assert status == 200, body
        lines = [line for line in body.split("\n") if line.strip()]
        assert len(lines) == 2, (
            "cross-bouncer fan-out MUST include ibounce decisions; "
            f"got {len(lines)} events instead of 2"
        )
        # The cross-bouncer aggregator keys on
        # metadata.product.vendor_name to identify ibounce; verify it.
        vendors = {
            json.loads(line)["metadata"]["product"]["vendor_name"]
            for line in lines
        }
        assert vendors == {"iam-jit"}, vendors
        products = {
            json.loads(line)["metadata"]["product"]["name"]
            for line in lines
        }
        assert products == {"ibounce"}, products
    finally:
        store.close()
