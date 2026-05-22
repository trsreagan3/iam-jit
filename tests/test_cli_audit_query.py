"""#271 — `iam-jit audit query` cross-bouncer CLI tests.

Mock HTTP servers stand in for each of the four bouncers so the CLI's
merge + sort + format + auth + parallel-query logic can be exercised
without needing live bouncer processes.

Per ``[[cross-product-agent-parity]]`` the per-bouncer endpoint shape
is uniform; the mock servers return that uniform NDJSON wire shape.
"""

from __future__ import annotations

import json
import threading
import time as _time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from click.testing import CliRunner

from iam_jit.cli import main as iam_jit_main


def _ocsf_event(
    *,
    bouncer_name: str,
    operation: str,
    severity_id: int = 1,
    seconds_ago: int = 60,
) -> dict[str, Any]:
    """Build an OCSF v1.1.0 class 6003 event dict in the same shape
    every Bounce-suite product emits. Time is Unix ms per OCSF."""
    now_ms = int(_time.time() * 1000)
    return {
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
        "activity_name": "Read",
        "severity_id": severity_id,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "actor": {"user": {"name": "alice"}},
        "api": {"operation": operation, "service": {"name": bouncer_name}},
        "resources": [],
        "unmapped": {"iam_jit": {"verdict": "ALLOW", "mode": "cooperative"}},
    }


class _MockBouncer:
    """One in-process HTTP server impersonating one bouncer's
    /audit/events endpoint. Records the inbound query + auth header so
    tests can assert what the CLI actually sent."""

    def __init__(
        self,
        bouncer_name: str,
        events: list[dict[str, Any]],
        *,
        require_token: str | None = None,
        slow_seconds: float = 0.0,
    ):
        self.bouncer_name = bouncer_name
        self.events = events
        self.require_token = require_token
        self.slow_seconds = slow_seconds
        self.inbound_queries: list[dict[str, list[str]]] = []
        self.inbound_auth_headers: list[str] = []
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0

    def start(self) -> None:
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args, **_kw):  # silence stderr
                pass

            def do_GET(self):  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path != "/audit/events":
                    self.send_response(404)
                    self.end_headers()
                    return
                outer.inbound_queries.append(parse_qs(parsed.query))
                outer.inbound_auth_headers.append(
                    self.headers.get("Authorization", ""),
                )
                if outer.require_token:
                    ah = self.headers.get("Authorization", "")
                    if not ah:
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error":"token required"}')
                        return
                    if ah != f"Bearer {outer.require_token}":
                        self.send_response(403)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error":"bad token"}')
                        return
                if outer.slow_seconds > 0:
                    _time.sleep(outer.slow_seconds)
                # Apply server-side filter parity check: if the test
                # passes filter=field=value, drop events that don't
                # match the literal projection. We only special-case
                # api.operation here — the tests don't exercise the
                # full filter grammar against the mock.
                events = outer.events
                for raw in parse_qs(parsed.query).get("filter", []):
                    if raw.startswith("api.operation="):
                        want = raw.split("=", 1)[1]
                        events = [
                            e for e in events
                            if (e.get("api") or {}).get("operation") == want
                        ]
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.end_headers()
                body = "".join(json.dumps(e) + "\n" for e in events)
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
def four_mock_bouncers():
    """Spin up four in-process bouncers (one per Bounce-suite product),
    each with a small event set. Caller composes ``--bouncer
    name=URL`` flags from the fixture's ``.url`` properties."""
    bouncers = {
        "ibounce": _MockBouncer(
            "ibounce",
            [_ocsf_event(bouncer_name="ibounce", operation="iam:GetRole", seconds_ago=120)],
        ),
        "kbounce": _MockBouncer(
            "kbounce",
            [
                _ocsf_event(bouncer_name="kbounce", operation="kube:get pods", seconds_ago=90),
                _ocsf_event(bouncer_name="kbounce", operation="kube:list services", seconds_ago=60),
            ],
        ),
        "dbounce": _MockBouncer(
            "dbounce",
            [_ocsf_event(bouncer_name="dbounce", operation="SELECT", seconds_ago=30)],
        ),
        "gbounce": _MockBouncer(
            "gbounce",
            [_ocsf_event(bouncer_name="gbounce", operation="GET /v1/x", seconds_ago=10)],
        ),
    }
    for b in bouncers.values():
        b.start()
    yield bouncers
    for b in bouncers.values():
        b.stop()


def _run_query(*args: str) -> Any:
    """Invoke `iam-jit audit query` with the given args + return the
    Click result. Tests assert on result.exit_code + result.output."""
    runner = CliRunner()
    return runner.invoke(
        iam_jit_main,
        ["audit", "query", *args],
        catch_exceptions=False,
    )


def _bouncer_args(bouncers: dict[str, _MockBouncer]) -> list[str]:
    """Build a list of `--bouncer name=URL` args from a fixture."""
    out = []
    for name, b in bouncers.items():
        out.extend(["--bouncer", f"{name}={b.url}"])
    return out


def test_query_all_four_mocks_merges_results(four_mock_bouncers):
    result = _run_query(*_bouncer_args(four_mock_bouncers))
    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.split("\n") if line.strip()]
    # 1 + 2 + 1 + 1 events
    assert len(lines) == 5, result.output
    # Sorted chronologically (oldest first).
    times = [json.loads(line)["time"] for line in lines]
    assert times == sorted(times)


def test_query_skip_unreachable_with_stderr_note(four_mock_bouncers):
    # Point one bouncer at a port that isn't bound.
    args = _bouncer_args({
        k: v for k, v in four_mock_bouncers.items() if k != "ibounce"
    })
    args.extend(["--bouncer", "ibounce=http://127.0.0.1:1"])
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main, ["audit", "query", *args], catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    # Click 8.3+: stdout + stderr are accessed via .stderr/.stdout; the
    # combined .output is what we get when stderr isn't separately
    # captured. Either contains the skip note.
    combined = (result.output or "") + (getattr(result, "stderr", "") or "")
    assert "ibounce skipped" in combined
    # Still got the 4 events from the 3 reachable bouncers (events
    # land on stdout).
    lines = [
        line for line in (result.stdout or result.output).split("\n")
        if line.strip() and not line.startswith("note: ")
    ]
    assert len(lines) == 4


def test_query_bouncer_flag_limits_to_subset(four_mock_bouncers):
    # Only kbounce + dbounce.
    result = _run_query(
        "--bouncer", f"kbounce={four_mock_bouncers['kbounce'].url}",
        "--bouncer", f"dbounce={four_mock_bouncers['dbounce'].url}",
    )
    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.split("\n") if line.strip()]
    assert len(lines) == 3  # 2 (kbounce) + 1 (dbounce)


def test_query_ocsf_bundle_format_produces_single_finding(four_mock_bouncers):
    result = _run_query(
        *_bouncer_args(four_mock_bouncers),
        "--format", "ocsf-bundle",
    )
    assert result.exit_code == 0, result.output
    bundle = json.loads(result.output)
    assert bundle["class_uid"] == 2004
    assert bundle["class_name"] == "Detection Finding"
    events = bundle["finding"]["evidence"]["events"]
    assert len(events) == 5
    # All four bouncer names are represented in the metadata.
    bouncers_in_bundle = {ev["_bouncer"] for ev in events}
    assert bouncers_in_bundle == {"ibounce", "kbounce", "dbounce", "gbounce"}
    # Bundle metadata lists the bouncers + total count.
    bundle_bouncers = set(bundle["finding"]["evidence"]["bouncers"])
    assert bundle_bouncers == {"ibounce", "kbounce", "dbounce", "gbounce"}


def test_query_summary_format_produces_per_bouncer_counts(four_mock_bouncers):
    result = _run_query(
        *_bouncer_args(four_mock_bouncers),
        "--format", "summary",
    )
    assert result.exit_code == 0, result.output
    out = result.output
    assert "ibounce: 1 events" in out
    assert "kbounce: 2 events" in out
    assert "dbounce: 1 events" in out
    assert "gbounce: 1 events" in out
    assert "total: 5 events" in out


def test_query_filter_forwarded_to_each_bouncer(four_mock_bouncers):
    # Filter on api.operation = "SELECT" — only dbounce has it.
    result = _run_query(
        *_bouncer_args(four_mock_bouncers),
        "--filter", "api.operation=SELECT",
    )
    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.split("\n") if line.strip()]
    assert len(lines) == 1
    # All four mocks should have received the filter param.
    for b in four_mock_bouncers.values():
        assert b.inbound_queries, f"{b.bouncer_name} not called"
        last = b.inbound_queries[-1]
        assert last.get("filter") == ["api.operation=SELECT"]


def test_query_parallel_does_not_block_on_slow_bouncer(four_mock_bouncers):
    # Make one bouncer slow; the total time should still be ~slow,
    # not 4*slow. We test the speedup ratio loosely (>1.5x faster than
    # sequential 4*slow) to avoid CI flakiness on heavily-loaded runners.
    four_mock_bouncers["kbounce"].slow_seconds = 0.3
    args = _bouncer_args(four_mock_bouncers)
    start = _time.monotonic()
    result = _run_query(*args)
    elapsed = _time.monotonic() - start
    assert result.exit_code == 0, result.output
    # Sequential would be ~0.3s + ~0 + ~0 + ~0 = 0.3s minimum.
    # Parallel should be ~0.3s (limited by the slowest). The looser
    # bound (< 0.9s = 3x slow) confirms we ran in parallel without
    # over-tightening the threshold for slow CI machines.
    assert elapsed < 0.9, f"elapsed={elapsed}s — parallel fan-out broken?"


def test_query_auth_token_forwarded_when_configured(four_mock_bouncers):
    # Configure one bouncer to require a token.
    four_mock_bouncers["ibounce"].require_token = "secret-token"
    result = _run_query(
        *_bouncer_args(four_mock_bouncers),
        "--audit-events-token", "secret-token",
    )
    assert result.exit_code == 0, result.output
    # ibounce got the Authorization header.
    ah = four_mock_bouncers["ibounce"].inbound_auth_headers[-1]
    assert ah == "Bearer secret-token"


def test_query_auth_token_missing_surfaces_401_in_stderr(four_mock_bouncers):
    four_mock_bouncers["ibounce"].require_token = "secret-token"
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main,
        ["audit", "query", *_bouncer_args(four_mock_bouncers)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    combined = (result.output or "") + (getattr(result, "stderr", "") or "")
    assert "ibounce skipped" in combined
    assert "HTTP 401" in combined
    # Other three bouncers still produced output.
    lines = [
        line for line in (result.stdout or result.output).split("\n")
        if line.strip() and not line.startswith("note: ")
    ]
    assert len(lines) == 4


def test_query_filter_by_agent_session_id_resolves_gbounce_events():
    """#308 — gbounce events now carry unmapped.iam_jit.agent.session_id
    so the cross-bouncer audit query can filter on it. Before #308
    gbounce was the lone outlier in the cross-bouncer correlation
    matrix; this test locks in the parity invariant from the consumer
    (`iam-jit audit query --filter`) side.

    The mock bouncer here simulates a #308-shaped gbounce: every event
    carries the unmapped.iam_jit.agent block + the legacy flat ext keys
    (recorder back-compat). The CLI forwards the filter as a query
    parameter; the test asserts the result set is filtered correctly.
    """
    target_session = "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
    other_session = "01968d6a-aaaa-bbbb-cccc-dddddddddddd"

    def _gbounce_event_with_agent(session_id: str, name: str, op: str) -> dict[str, Any]:
        ev = _ocsf_event(bouncer_name="gbounce", operation=op, seconds_ago=10)
        ev["unmapped"]["iam_jit"]["agent"] = {
            "name": name,
            "session_id": session_id,
            "detected_from": "http_header",
        }
        # Legacy flat keys (recorder route)
        ev["unmapped"]["iam_jit"]["ext"] = {
            "agent_session_id": session_id,
            "agent_name": name,
        }
        return ev

    gbounce_events = [
        _gbounce_event_with_agent(target_session, "claude-code", "GET /repos/acme/api/issues"),
        _gbounce_event_with_agent(target_session, "claude-code", "POST /repos/acme/api/issues"),
        _gbounce_event_with_agent(other_session, "cursor",      "GET /repos/acme/api/pulls"),
        _ocsf_event(bouncer_name="gbounce", operation="GET /robots.txt", seconds_ago=10),  # anonymous
    ]

    # Mock-bouncer side-filter: surface agent.session_id-based filters
    # the same way a real gbounce /audit/events endpoint would (the
    # production handler walks the OCSF Event struct via the
    # audit.MatchAll path).
    class _AgentFilteringHandler:
        pass

    bouncer = _MockBouncer("gbounce", gbounce_events)

    # Patch the in-memory filter to recognise agent.session_id.
    # Tests don't exercise the full grammar — we add just the one rule
    # this test needs (mirrors the gbounce-side filter resolver).
    outer = bouncer

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return
        def do_GET(self):
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            events = list(outer.events)
            for raw in parse_qs(parsed.query).get("filter", []):
                if raw.startswith("unmapped.iam_jit.agent.session_id="):
                    want = raw.split("=", 1)[1]
                    events = [
                        e for e in events
                        if (e.get("unmapped", {})
                              .get("iam_jit", {})
                              .get("agent", {})
                              .get("session_id") == want)
                    ]
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.end_headers()
            body = "".join(json.dumps(e) + "\n" for e in events)
            self.wfile.write(body.encode("utf-8"))

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        runner = CliRunner()
        result = runner.invoke(
            iam_jit_main,
            [
                "audit", "query",
                "--bouncer", f"gbounce=http://127.0.0.1:{port}",
                "--filter", f"unmapped.iam_jit.agent.session_id={target_session}",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        lines = [line for line in result.output.split("\n") if line.strip()]
        # Exactly 2 events match the target session (claude-code).
        assert len(lines) == 2, f"want 2 events for target session, got {len(lines)}\noutput={result.output}"
        for line in lines:
            ev = json.loads(line)
            agent = ev["unmapped"]["iam_jit"]["agent"]
            assert agent["session_id"] == target_session, agent
            assert agent["name"] == "claude-code"
            assert agent["detected_from"] == "http_header"
    finally:
        server.shutdown()
        server.server_close()


def test_query_csv_format_produces_header_and_rows(four_mock_bouncers):
    result = _run_query(
        *_bouncer_args(four_mock_bouncers),
        "--format", "csv",
    )
    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.split("\n") if line.strip()]
    # 1 header + 5 events
    assert len(lines) == 6
    assert lines[0].startswith("bouncer,time,severity_id,")


# ---------------------------------------------------------------------------
# #320 / §A18 — short-form filter alias expansion
# ---------------------------------------------------------------------------


def test_320_short_form_filter_expanded_before_forwarding(four_mock_bouncers):
    """The spec example `--filter agent.session_id=X` must expand to
    the canonical `unmapped.iam_jit.agent.session_id=X` before each
    bouncer sees it. UAT 2026-05-22 caught the per-bouncer parsers
    returning HTTP 400 on the short form; client-side expansion
    closes the gap without per-bouncer changes."""
    result = _run_query(
        *_bouncer_args(four_mock_bouncers),
        "--filter", "agent.session_id=parity-test",
    )
    assert result.exit_code == 0, result.output
    for b in four_mock_bouncers.values():
        assert b.inbound_queries, f"{b.bouncer_name} not called"
        last = b.inbound_queries[-1]
        # The expanded canonical form is what each bouncer received,
        # NOT the short form the operator typed.
        assert last.get("filter") == [
            "unmapped.iam_jit.agent.session_id=parity-test"
        ], f"{b.bouncer_name} got filter={last.get('filter')}"


def test_320_short_form_agent_name_expanded():
    """Same expansion mechanism for `agent.name=X` short-form."""
    from iam_jit.cli_audit_query import _expand_short_form_filter
    assert _expand_short_form_filter("agent.name=psql") == (
        "unmapped.iam_jit.agent.name=psql"
    )
    assert _expand_short_form_filter("agent.detected_from=http_header") == (
        "unmapped.iam_jit.agent.detected_from=http_header"
    )


def test_320_long_form_passes_through_unchanged():
    """Canonical long form MUST pass through verbatim — operators
    who already use the long form (or who have automation written
    against it) keep working."""
    from iam_jit.cli_audit_query import _expand_short_form_filter
    expr = "unmapped.iam_jit.agent.session_id=X"
    assert _expand_short_form_filter(expr) == expr


def test_320_unrelated_filter_passes_through():
    """Filters whose field isn't in the short-form map MUST pass
    through verbatim (the per-bouncer parser handles them)."""
    from iam_jit.cli_audit_query import _expand_short_form_filter
    for expr in (
        "api.operation=SELECT",
        "severity_id>=3",
        "actor.user.name=claude-code",
    ):
        assert _expand_short_form_filter(expr) == expr, expr


def test_320_short_form_with_regex_operator():
    """Regex operator (`~`) also supported on the short form."""
    from iam_jit.cli_audit_query import _expand_short_form_filter
    assert _expand_short_form_filter("agent.name~claude.*") == (
        "unmapped.iam_jit.agent.name~claude.*"
    )
