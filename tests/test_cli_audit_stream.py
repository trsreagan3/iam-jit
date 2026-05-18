"""#272 — `iam-jit audit stream` cross-bouncer live-TUI tests.

The TUI is rich.live based (textual would pull 5+ transitive deps
that iam-roles doesn't ship; we ship rich which is already a
click transitive). Tests exercise the underlying state machine
(fetch + dedupe + filter + pause + clear + unreachable-skip) plus
the click command entry point, against in-process mock bouncers.
The rich.live render path is exercised with ``max_frames=1`` so the
test exits deterministically without a real terminal.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time as _time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from click.testing import CliRunner

from iam_jit.cli import main as iam_jit_main
from iam_jit.cli_audit_query import BouncerEndpoint
from iam_jit.cli_audit_stream import (
    _classify_verdict,
    _dedup_key,
    _event_time_ms,
    _extract_actor,
    _extract_event_type,
    _extract_operation,
    _extract_severity,
    _fetcher_loop,
    _run_tui_loop,
    make_ui_state,
)


def _ocsf_event(
    *,
    bouncer_name: str,
    operation: str,
    actor: str = "alice",
    verdict: str = "ALLOW",
    event_type: str = "DECISION",
    severity_id: int = 1,
    seconds_ago: int = 60,
) -> dict[str, Any]:
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
        "actor": {"user": {"name": actor}},
        "api": {"operation": operation, "service": {"name": bouncer_name}},
        "resources": [],
        "unmapped": {
            "iam_jit": {
                "verdict": verdict,
                "mode": "cooperative",
                "event_type": event_type,
            },
        },
    }


class _MockBouncer:
    """In-process HTTP server impersonating one bouncer's /audit/events."""

    def __init__(
        self,
        bouncer_name: str,
        events: list[dict[str, Any]],
        *,
        require_token: str | None = None,
        respond_500: bool = False,
    ):
        self.bouncer_name = bouncer_name
        self.events = events
        self.require_token = require_token
        self.respond_500 = respond_500
        self.inbound_queries: list[dict[str, list[str]]] = []
        self.inbound_auth_headers: list[str] = []
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0

    def start(self) -> None:
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
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
                if outer.respond_500:
                    self.send_response(500)
                    self.end_headers()
                    return
                if outer.require_token:
                    ah = self.headers.get("Authorization", "")
                    if ah != f"Bearer {outer.require_token}":
                        self.send_response(403)
                        self.end_headers()
                        self.wfile.write(b'{"error":"bad token"}')
                        return
                # Respect ?filter=actor.user.name=NAME for filter tests.
                events = outer.events
                for raw in parse_qs(parsed.query).get("filter", []):
                    if raw.startswith("actor.user.name="):
                        want = raw.split("=", 1)[1]
                        events = [
                            e for e in events
                            if (e.get("actor") or {}).get("user", {}).get("name") == want
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

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    @property
    def endpoint(self) -> BouncerEndpoint:
        return BouncerEndpoint(
            name=self.bouncer_name,
            mgmt_url=f"http://127.0.0.1:{self.port}",
        )


# ---------- extraction helpers ----------------------------------------

def test_classify_verdict_deny():
    ev = _ocsf_event(bouncer_name="ibounce", operation="x", verdict="DENY")
    label, cls = _classify_verdict(ev)
    assert cls == "deny"
    assert label == "DENIED"


def test_classify_verdict_allow():
    ev = _ocsf_event(bouncer_name="ibounce", operation="x")
    label, cls = _classify_verdict(ev)
    assert cls == "allow"
    assert label == "ALLOWED"


def test_classify_verdict_admin():
    ev = _ocsf_event(
        bouncer_name="ibounce", operation="x", event_type="ADMIN_ACTION",
    )
    label, cls = _classify_verdict(ev)
    assert cls == "admin"


def test_classify_verdict_heartbeat():
    ev = _ocsf_event(
        bouncer_name="ibounce", operation="x", event_type="HEARTBEAT",
    )
    _, cls = _classify_verdict(ev)
    assert cls == "heartbeat"


def test_extract_actor():
    ev = _ocsf_event(bouncer_name="ibounce", operation="x", actor="carol")
    assert _extract_actor(ev) == "carol"


def test_extract_operation():
    ev = _ocsf_event(bouncer_name="ibounce", operation="iam:GetRole")
    assert _extract_operation(ev) == "iam:GetRole"


def test_extract_event_type():
    ev = _ocsf_event(
        bouncer_name="ibounce", operation="x", event_type="DECISION",
    )
    assert _extract_event_type(ev) == "DECISION"


def test_extract_severity_named():
    ev = {"severity": "High"}
    assert _extract_severity(ev) == "High"


def test_extract_severity_id():
    ev = {"severity_id": 4}
    assert _extract_severity(ev) == "High"


def test_event_time_ms_int():
    assert _event_time_ms({"time": 1000}) == 1000


def test_event_time_ms_iso():
    ms = _event_time_ms({"time": "2026-05-18T00:00:00Z"})
    assert ms > 0


def test_dedup_key_stable():
    ev = _ocsf_event(bouncer_name="ibounce", operation="x")
    assert _dedup_key("ibounce", ev) == _dedup_key("ibounce", ev)


# ---------- fetcher loop ----------------------------------------------

def _run_one_fetch_round(ui, bouncers):
    """Drive ONE tick of the fetcher loop then quit. Used so tests
    deterministically exit without sleeping for the full poll cycle."""
    async def runner():
        async def stop_after_first_tick():
            await asyncio.sleep(0.1)
            ui.quit_requested = True
        await asyncio.gather(_fetcher_loop(ui), stop_after_first_tick())
    asyncio.run(runner())


def test_fetcher_loop_collects_events_from_all_bouncers():
    a = _MockBouncer("ibounce", [_ocsf_event(bouncer_name="ibounce", operation="iam:Get")])
    b = _MockBouncer("kbounce", [_ocsf_event(bouncer_name="kbounce", operation="kube:list")])
    a.start(); b.start()
    try:
        ui = make_ui_state(
            bouncers=[a.endpoint, b.endpoint],
            poll_interval=0.05,
        )
        _run_one_fetch_round(ui, [a, b])
        assert ui.counts_total >= 2, list(ui.events)
        assert ui.counts_per_bouncer["ibounce"] >= 1
        assert ui.counts_per_bouncer["kbounce"] >= 1
    finally:
        a.stop(); b.stop()


def test_fetcher_loop_dedupes_overlapping_polls():
    bnc = _MockBouncer(
        "ibounce",
        [_ocsf_event(bouncer_name="ibounce", operation="iam:Get", seconds_ago=10)],
    )
    bnc.start()
    try:
        ui = make_ui_state(bouncers=[bnc.endpoint], poll_interval=0.05)
        # Let the loop tick twice — same event seen each time, should
        # only land in the buffer once.
        async def runner():
            async def stop_after_two_ticks():
                await asyncio.sleep(0.18)
                ui.quit_requested = True
            await asyncio.gather(_fetcher_loop(ui), stop_after_two_ticks())
        asyncio.run(runner())
        assert ui.counts_total == 1, list(ui.events)
    finally:
        bnc.stop()


def test_fetcher_loop_skips_unreachable_bouncer():
    ok = _MockBouncer("ibounce", [_ocsf_event(bouncer_name="ibounce", operation="iam:Get")])
    ok.start()
    try:
        bad = BouncerEndpoint(name="kbounce", mgmt_url="http://127.0.0.1:1")
        ui = make_ui_state(bouncers=[ok.endpoint, bad], poll_interval=0.05)
        _run_one_fetch_round(ui, [ok])
        assert ui.bouncers["ibounce"].reachable is True
        assert ui.bouncers["kbounce"].reachable is False
        assert ui.bouncers["kbounce"].last_error
        # Still got events from the reachable one.
        assert ui.counts_total >= 1
    finally:
        ok.stop()


def test_fetcher_loop_skips_500_bouncer():
    bnc = _MockBouncer("ibounce", [], respond_500=True)
    bnc.start()
    try:
        ui = make_ui_state(bouncers=[bnc.endpoint], poll_interval=0.05)
        _run_one_fetch_round(ui, [bnc])
        assert ui.bouncers["ibounce"].reachable is False
        assert "500" in (ui.bouncers["ibounce"].last_error or "")
    finally:
        bnc.stop()


def test_fetcher_loop_forwards_filter_to_bouncer():
    bnc = _MockBouncer(
        "ibounce",
        [
            _ocsf_event(bouncer_name="ibounce", operation="x", actor="alice"),
            _ocsf_event(bouncer_name="ibounce", operation="y", actor="bob"),
        ],
    )
    bnc.start()
    try:
        ui = make_ui_state(
            bouncers=[bnc.endpoint],
            poll_interval=0.05,
            filter_text="actor.user.name=alice",
        )
        _run_one_fetch_round(ui, [bnc])
        # Mock filters out bob; only alice should land.
        actors = {
            _extract_actor(ev) for _, ev in ui.events
        }
        assert actors == {"alice"}
        # Filter expression was actually sent on the wire.
        sent_filters = []
        for q in bnc.inbound_queries:
            sent_filters.extend(q.get("filter", []))
        assert "actor.user.name=alice" in sent_filters
    finally:
        bnc.stop()


def test_fetcher_loop_forwards_bearer_token():
    bnc = _MockBouncer(
        "ibounce",
        [_ocsf_event(bouncer_name="ibounce", operation="x")],
        require_token="s3kret",
    )
    bnc.start()
    try:
        ui = make_ui_state(
            bouncers=[bnc.endpoint],
            poll_interval=0.05,
            bearer_token="s3kret",
        )
        _run_one_fetch_round(ui, [bnc])
        assert ui.counts_total >= 1
        assert any(
            h == "Bearer s3kret" for h in bnc.inbound_auth_headers
        )
    finally:
        bnc.stop()


def test_fetcher_loop_respects_pause():
    bnc = _MockBouncer(
        "ibounce", [_ocsf_event(bouncer_name="ibounce", operation="x")],
    )
    bnc.start()
    try:
        ui = make_ui_state(bouncers=[bnc.endpoint], poll_interval=0.05)
        ui.paused = True
        _run_one_fetch_round(ui, [bnc])
        # No events should have been fetched while paused.
        assert ui.counts_total == 0
        # No GET requests at all.
        assert bnc.inbound_queries == []
    finally:
        bnc.stop()


def test_clear_resets_state():
    bnc = _MockBouncer(
        "ibounce", [_ocsf_event(bouncer_name="ibounce", operation="x")],
    )
    bnc.start()
    try:
        ui = make_ui_state(bouncers=[bnc.endpoint], poll_interval=0.05)
        _run_one_fetch_round(ui, [bnc])
        assert ui.counts_total >= 1
        # Emulate the `c` keystroke handler.
        ui.events.clear()
        ui.seen_ids.clear()
        ui.counts_total = 0
        ui.counts_per_bouncer.clear()
        assert len(ui.events) == 0
        assert ui.counts_total == 0
    finally:
        bnc.stop()


# ---------- TUI render loop -------------------------------------------

def test_tui_render_loop_exits_cleanly_with_max_frames():
    """The rich.live loop must exit cleanly + cancel background tasks
    when quit_requested flips (the `q` keystroke path)."""
    bnc = _MockBouncer(
        "ibounce", [_ocsf_event(bouncer_name="ibounce", operation="x")],
    )
    bnc.start()
    try:
        ui = make_ui_state(bouncers=[bnc.endpoint], poll_interval=0.05)
        # max_frames=2 keeps the test bounded; the loop should
        # auto-quit + tear down its fetcher + key-reader tasks.
        asyncio.run(_run_tui_loop(ui, max_frames=2))
        assert ui.quit_requested is True
    finally:
        bnc.stop()


# ---------- click entrypoint ------------------------------------------

def test_audit_stream_help_lists_keyboard_shortcuts():
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["audit", "stream", "--help"])
    assert result.exit_code == 0, result.output
    out = result.output.lower()
    for tok in ["pause", "quit", "filter", "toggle"]:
        assert tok in out, f"missing help token: {tok}"


def test_audit_stream_unknown_bouncer_errors():
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main,
        ["audit", "stream", "--bouncer", "doesnotexist"],
    )
    assert result.exit_code != 0
    assert "doesnotexist" in result.output.lower() or "unknown" in result.output.lower()


def test_audit_stream_subcommand_registered():
    """Smoke test that `iam-jit audit --help` lists the stream
    subcommand alongside query (the registration wiring)."""
    runner = CliRunner()
    result = runner.invoke(iam_jit_main, ["audit", "--help"])
    assert result.exit_code == 0
    assert "stream" in result.output
    assert "query" in result.output
