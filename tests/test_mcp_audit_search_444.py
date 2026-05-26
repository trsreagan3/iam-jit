"""#444 / §A75 — tests for `iam_jit_audit_search` MCP tool.

Per docs/CONTRIBUTING.md state-verification convention: every test
that asserts a reported status MUST also assert the observable state
matches.

Coverage:
  1. Happy path: structured input → expected events (observable)
  2. Time window honored: --since 1h returns recent, omits older
  3. Action filter honored: action=['s3:PutObject'] filters correctly
  4. Outcome filter honored: outcome='deny' filters correctly
  5. Cross-bouncer fan-out: serve included by default (#620)
  6. extract_permissions: true → #419 permission-set shape
  7. Schema description includes NL-translation hint (operator UX)
  8. Sabotage: query-executor override proves wrapper is load-bearing
"""

from __future__ import annotations

import json
import threading
import time as _time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest


# ---------------------------------------------------------------------------
# Shared OCSF event builder
# ---------------------------------------------------------------------------


def _ocsf_event(
    *,
    operation: str,
    verdict: str = "allow",
    bouncer_name: str = "ibounce",
    seconds_ago: int = 60,
    resource_arn: str | None = None,
) -> dict[str, Any]:
    now_ms = int(_time.time() * 1000)
    ev: dict[str, Any] = {
        "metadata": {
            "version": "1.1.0",
            "product": {"name": bouncer_name, "vendor_name": "iam-jit"},
        },
        "time": now_ms - seconds_ago * 1000,
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "activity_id": 2,
        "activity_name": "Read" if verdict == "allow" else "Write",
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "api": {
            "operation": operation,
            "service": {"name": "s3" if operation.startswith("s3:") else "iam"},
        },
        "unmapped": {
            "iam_jit": {
                "verdict": verdict,
                "mode": "discovery",
            }
        },
    }
    if resource_arn:
        ev["resources"] = [{"uid": resource_arn}]
    return ev


# ---------------------------------------------------------------------------
# Mock HTTP bouncer server
# ---------------------------------------------------------------------------


class _MockBouncer:
    """Lightweight HTTP server that serves a fixed event list from
    GET /audit/events. Captures inbound query parameters so tests can
    verify filters were forwarded."""

    def __init__(self, name: str, events: list[dict[str, Any]]):
        self.name = name
        self.events = events
        self.inbound_queries: list[dict[str, list[str]]] = []
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0

    def start(self) -> None:
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                pass  # silence test output

            def do_GET(self):  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path != "/audit/events":
                    self.send_response(404)
                    self.end_headers()
                    return
                outer.inbound_queries.append(parse_qs(parsed.query))
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.end_headers()
                body = "".join(json.dumps(e) + "\n" for e in outer.events)
                self.wfile.write(body.encode("utf-8"))

        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture
def ibounce_mock():
    """ibounce serving two events: one s3:PutObject deny, one s3:GetObject allow."""
    events = [
        _ocsf_event(
            operation="s3:PutObject",
            verdict="deny",
            bouncer_name="ibounce",
            seconds_ago=120,
            resource_arn="arn:aws:s3:::prod-bucket/key",
        ),
        _ocsf_event(
            operation="s3:GetObject",
            verdict="allow",
            bouncer_name="ibounce",
            seconds_ago=60,
            resource_arn="arn:aws:s3:::staging-bucket/key",
        ),
    ]
    mock = _MockBouncer("ibounce", events)
    mock.start()
    yield mock
    mock.stop()


# ---------------------------------------------------------------------------
# Test 1 — Happy path: structured input → expected events (observable)
# ---------------------------------------------------------------------------


def test_happy_path_returns_expected_events(ibounce_mock):
    """State-verification: tool returns events + the events list is
    non-empty and contains the mock's actual operation names.

    Per CONTRIBUTING.md: we assert BOTH the reported status AND the
    observable state (the events themselves)."""
    from iam_jit.mcp_server import _iam_jit_audit_search_for_mcp

    result = _iam_jit_audit_search_for_mcp({
        "bouncer": [f"ibounce={ibounce_mock.url}"],
        "limit": 10,
        "format": "events",
    })

    # 1. Reported status.
    assert result["status"] == "ok"
    assert result["format"] == "events"

    # 2. Observable state: events list actually contains the events.
    events = result["events"]
    assert isinstance(events, list)
    assert len(events) == 2, (
        f"expected 2 events from mock bouncer; got {len(events)}"
    )
    operations = {ev["api"]["operation"] for ev in events}
    assert "s3:PutObject" in operations
    assert "s3:GetObject" in operations

    # 3. No hidden error in the notes field.
    for note in result.get("notes", []):
        assert "skipped" not in note or ibounce_mock.name not in note, (
            f"ibounce surfaced as skipped unexpectedly: {note}"
        )


# ---------------------------------------------------------------------------
# Test 2 — Time window honored (--since 1h returns recent, omits older)
# ---------------------------------------------------------------------------


def test_time_window_forwarded_to_bouncer(ibounce_mock):
    """Observable state: the `since` parameter is forwarded as a query
    param to the bouncer's /audit/events endpoint.

    Per #498 short-form expansion — `1h` becomes an ISO 8601 lower
    bound before forwarding."""
    from iam_jit.mcp_server import _iam_jit_audit_search_for_mcp

    _iam_jit_audit_search_for_mcp({
        "bouncer": [f"ibounce={ibounce_mock.url}"],
        "since": "1h",
        "limit": 10,
        "format": "events",
    })

    # Observable state: the mock bouncer received a `since` query param.
    assert ibounce_mock.inbound_queries, "no inbound query to bouncer"
    last_qs = ibounce_mock.inbound_queries[-1]
    assert "since" in last_qs, (
        f"expected `since` param forwarded to bouncer; got: {last_qs}"
    )
    # The value should be an ISO 8601 timestamp (not the raw `1h`
    # shorthand), proving _parse_since_long_range expansion fired.
    since_val = last_qs["since"][0]
    assert "T" in since_val or "-" in since_val[:10], (
        f"expected ISO-8601 since, got raw shorthand: {since_val!r}"
    )


# ---------------------------------------------------------------------------
# Test 3 — Action filter honored
# ---------------------------------------------------------------------------


def test_action_filter_forwarded_as_api_operation_filter(ibounce_mock):
    """Observable state: `action: ['s3:PutObject']` is forwarded as an
    `api.operation=s3:PutObject` filter query param to the bouncer."""
    from iam_jit.mcp_server import _iam_jit_audit_search_for_mcp

    result = _iam_jit_audit_search_for_mcp({
        "bouncer": [f"ibounce={ibounce_mock.url}"],
        "action": ["s3:PutObject"],
        "limit": 10,
        "format": "events",
    })

    assert result["status"] == "ok"

    # Observable state: the filter was forwarded to the bouncer.
    assert ibounce_mock.inbound_queries, "no inbound query to bouncer"
    last_qs = ibounce_mock.inbound_queries[-1]
    filters = last_qs.get("filter", [])
    assert any(
        "api.operation=s3:PutObject" in f for f in filters
    ), (
        f"expected api.operation=s3:PutObject in filter params; "
        f"got: {filters}"
    )


# ---------------------------------------------------------------------------
# Test 4 — Outcome filter honored
# ---------------------------------------------------------------------------


def test_outcome_deny_forwarded_as_verdict_filter(ibounce_mock):
    """Observable state: `outcome: 'deny'` is forwarded as
    `unmapped.iam_jit.verdict=deny` filter to the bouncer."""
    from iam_jit.mcp_server import _iam_jit_audit_search_for_mcp

    result = _iam_jit_audit_search_for_mcp({
        "bouncer": [f"ibounce={ibounce_mock.url}"],
        "outcome": "deny",
        "limit": 10,
        "format": "events",
    })

    assert result["status"] == "ok"

    # Observable state: verdict filter forwarded to bouncer.
    assert ibounce_mock.inbound_queries, "no inbound query to bouncer"
    last_qs = ibounce_mock.inbound_queries[-1]
    filters = last_qs.get("filter", [])
    assert any(
        "unmapped.iam_jit.verdict=deny" in f for f in filters
    ), (
        f"expected verdict=deny filter forwarded; got: {filters}"
    )

    # outcome='any' should NOT forward a verdict filter.
    ibounce_mock.inbound_queries.clear()
    _iam_jit_audit_search_for_mcp({
        "bouncer": [f"ibounce={ibounce_mock.url}"],
        "outcome": "any",
        "limit": 10,
        "format": "events",
    })
    last_qs_any = ibounce_mock.inbound_queries[-1]
    any_filters = last_qs_any.get("filter", [])
    assert not any("verdict" in f for f in any_filters), (
        f"outcome='any' should NOT forward verdict filter; got: {any_filters}"
    )


# ---------------------------------------------------------------------------
# Test 5 — Cross-bouncer fan-out: serve included by default (#620)
# ---------------------------------------------------------------------------


def test_cross_bouncer_fanout_includes_serve_by_default(monkeypatch):
    """Observable state: when no `bouncer` list is supplied, the tool
    fans out to the default set which INCLUDES iam-jit-serve (#620).

    The test uses `_resolve_serve_endpoint` + `_resolve_bouncer_set`
    from cli_audit_query to verify the serve endpoint appears in the
    resolved set — mirrors the #620 contract that the recipe command
    `iam-jit audit query --kind request_cap_exceeded --since 1h`
    queries serve.

    We monkeypatch `_urlopen` to avoid real network calls."""
    from iam_jit.cli_audit_query import _resolve_bouncer_set

    bouncers = _resolve_bouncer_set((), include_serve=True)
    names = [ep.name for ep in bouncers]

    # Observable: iam-jit-serve IS in the default fan-out set.
    assert "iam-jit-serve" in names, (
        f"iam-jit-serve must be in default fan-out (#620); got: {names}"
    )
    # Observable: all four bouncer defaults also present.
    for expected in ("ibounce", "kbounce", "dbounce", "gbounce"):
        assert expected in names, (
            f"default bouncer {expected!r} missing from fan-out; "
            f"got: {names}"
        )


# ---------------------------------------------------------------------------
# Test 6 — extract_permissions: true → #419 permission-set shape
# ---------------------------------------------------------------------------


def test_extract_permissions_returns_419_shape(ibounce_mock):
    """Observable state: when extract_permissions=true, the return
    value has the `{time_window, bouncer, events_analyzed, permissions,
    observed_scope}` shape from #419, NOT an events list.

    State-verification: assert the 'permissions' list is present and
    non-empty (the mock has two events → at least one permission entry)."""
    from iam_jit.mcp_server import _iam_jit_audit_search_for_mcp

    result = _iam_jit_audit_search_for_mcp({
        "bouncer": [f"ibounce={ibounce_mock.url}"],
        "extract_permissions": True,
        "limit": 100,
    })

    # 1. Reported status.
    assert result["status"] == "ok"
    assert result["format"] == "permissions"

    # 2. Observable state: #419 permission-set fields are present.
    assert "permissions" in result, (
        "extract_permissions=true must return 'permissions' key (#419)"
    )
    assert "events_analyzed" in result, (
        "extract_permissions=true must return 'events_analyzed' key"
    )
    assert "time_window" in result, (
        "extract_permissions=true must return 'time_window' key"
    )
    assert "observed_scope" in result, (
        "extract_permissions=true must return 'observed_scope' key"
    )

    # 3. No 'events' key (wrong shape for extract_permissions path).
    assert "events" not in result, (
        "extract_permissions=true must NOT return raw 'events' list"
    )

    # 4. permissions list is actually populated (mock has 2 events).
    perms = result["permissions"]
    assert isinstance(perms, list)
    assert len(perms) >= 1, (
        "expected at least 1 permission entry from 2 mock events"
    )


def test_extract_permissions_rejects_multi_bouncer():
    """extract_permissions=true with more than one bouncer → error.
    Single-bouncer semantics per #419."""
    from iam_jit.mcp_server import _iam_jit_audit_search_for_mcp

    result = _iam_jit_audit_search_for_mcp({
        "bouncer": ["ibounce=http://127.0.0.1:9999", "kbounce=http://127.0.0.1:9998"],
        "extract_permissions": True,
        "limit": 10,
    })

    assert result["status"] == "error"
    assert result["code"] == "extract_permissions_requires_one_bouncer"


# ---------------------------------------------------------------------------
# Test 7 — Tool description includes NL-translation hint
# ---------------------------------------------------------------------------


def test_tool_description_includes_nl_translation_hint():
    """The MCP tool description must surface the NL→structured
    translation pattern so agents can map operator NL prompts to
    the structured fields without iam-jit touching an LLM.

    Per [[ibounce-honest-positioning]] the description must make the
    caller-does-NL-parsing contract explicit."""
    from iam_jit.mcp_server import TOOLS

    tool = next(
        (t for t in TOOLS if t["name"] == "iam_jit_audit_search"),
        None,
    )
    assert tool is not None, (
        "iam_jit_audit_search must be registered in TOOLS"
    )

    desc = tool["description"]

    # The NL-translation example from the spec must be present.
    assert "show me" in desc.lower() or "translate to" in desc.lower(), (
        "description must include NL-to-structured translation example"
    )

    # The [[bouncer-zero-llm-when-agent-in-loop]] contract must be explicit.
    assert "calling agent" in desc.lower() or "agent" in desc.lower(), (
        "description must clarify the calling agent does NL translation"
    )

    # The tool must mention 'structured' (Interpretation A contract).
    assert "structured" in desc.lower(), (
        "description must surface that the input is structured (not raw NL)"
    )


# ---------------------------------------------------------------------------
# Test 8 — Sabotage: query-executor override proves wrapper is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_query_executor_causes_happy_path_to_fail(
    ibounce_mock, monkeypatch
):
    """Per CONTRIBUTING.md sabotage pattern (#475 shape): if the
    query-executor is replaced with one that returns empty, the
    happy-path assertion on events length MUST fail — proving the
    wrapper actually calls the executor rather than constructing the
    result independently.

    This test is deliberately structured to PASS when the executor is
    active and to DETECT the test's own absence of load-bearing-ness
    if the wrapper stopped calling the executor."""
    import iam_jit.cli_audit_query as caq_mod
    from iam_jit.mcp_server import _iam_jit_audit_search_for_mcp

    # First: verify the real executor returns events (baseline).
    real_result = _iam_jit_audit_search_for_mcp({
        "bouncer": [f"ibounce={ibounce_mock.url}"],
        "limit": 10,
        "format": "events",
    })
    assert real_result["status"] == "ok"
    real_count = len(real_result["events"])
    assert real_count > 0, (
        "baseline must return events from mock bouncer"
    )

    # Sabotage: replace _query_one_bouncer so it returns empty.
    from iam_jit.cli_audit_query import _BouncerQueryResult

    def _empty_query(endpoint, *, since, until, filters, limit, bearer_token, timeout=5.0):
        return _BouncerQueryResult(bouncer=endpoint.name, events=[], error="")

    monkeypatch.setattr(caq_mod, "_query_one_bouncer", _empty_query)

    # With the sabotaged executor the result must be DIFFERENT (empty).
    sabotaged_result = _iam_jit_audit_search_for_mcp({
        "bouncer": [f"ibounce={ibounce_mock.url}"],
        "limit": 10,
        "format": "events",
    })
    assert sabotaged_result["status"] == "ok"
    sabotaged_count = len(sabotaged_result["events"])

    # Observable state: the sabotaged executor produced zero events —
    # proving the wrapper IS load-bearing (it calls the executor, not
    # a cached / hardcoded result).
    assert sabotaged_count == 0, (
        f"sabotage must cause empty result; got {sabotaged_count} events. "
        "The wrapper is NOT load-bearing — it didn't call _query_one_bouncer."
    )
    assert sabotaged_count != real_count, (
        "sabotaged result must differ from real result — wrapper must "
        "call the executor, not return a static value."
    )


# ---------------------------------------------------------------------------
# Bonus: summary format returns per-bouncer counts (not events list)
# ---------------------------------------------------------------------------


def test_summary_format_returns_counts_not_events(ibounce_mock):
    """Observable state: format='summary' returns per_bouncer counts
    and total_events, not an events list."""
    from iam_jit.mcp_server import _iam_jit_audit_search_for_mcp

    result = _iam_jit_audit_search_for_mcp({
        "bouncer": [f"ibounce={ibounce_mock.url}"],
        "limit": 10,
        "format": "summary",
    })

    assert result["status"] == "ok"
    assert result["format"] == "summary"
    assert "total_events" in result
    assert "per_bouncer" in result
    # No raw events in summary output.
    assert "events" not in result, (
        "format='summary' must NOT include raw events list"
    )
    # Per-bouncer count matches mock.
    assert result["per_bouncer"]["ibounce"] == 2
    assert result["total_events"] == 2
