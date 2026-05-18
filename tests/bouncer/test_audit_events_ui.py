"""#272 — minimal web UI tests for ibounce.

Drives the GET / handler the same way the events-endpoint tests drive
GET /audit/events: in-process aiohttp TestClient, no network bind.

The HTML body is intentionally generic across bouncers per
``[[cross-product-agent-parity]]`` so the assertions focus on
structural elements (title, table head, polling JS, no embedded
secrets) rather than pixel-level rendering.
"""

from __future__ import annotations

import asyncio
import re

import pytest


def _make_app(*, require_bearer: str | None = None, bouncer_name: str = "ibounce"):
    pytest.importorskip("aiohttp")
    from aiohttp import web
    from iam_jit.bouncer.audit_export.events_ui import (
        register_audit_events_ui_route,
    )
    app = web.Application()
    register_audit_events_ui_route(
        app,
        bouncer_name=bouncer_name,
        require_bearer=require_bearer,
    )
    return app


async def _request_in_loop(
    *,
    require_bearer: str | None = None,
    bouncer_name: str = "ibounce",
    headers: dict[str, str] | None = None,
    path: str = "/",
):
    from aiohttp.test_utils import TestClient, TestServer
    app = _make_app(require_bearer=require_bearer, bouncer_name=bouncer_name)
    async with TestClient(TestServer(app)) as client:
        async with client.get(path, headers=headers or {}) as resp:
            return resp.status, await resp.text(), dict(resp.headers)


def _run(**kwargs):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_request_in_loop(**kwargs))
    finally:
        loop.close()


def test_get_root_returns_html():
    status, body, headers = _run()
    assert status == 200, body
    assert headers.get("Content-Type", "").startswith("text/html"), headers
    assert body.lstrip().lower().startswith("<!doctype html>"), body[:200]


def test_html_contains_title_with_bouncer_name():
    _, body, _ = _run()
    assert "<title>ibounce - live audit stream</title>" in body


def test_html_title_reflects_custom_bouncer_name():
    _, body, _ = _run(bouncer_name="kbounce")
    assert "<title>kbounce - live audit stream</title>" in body


def test_bouncer_name_is_html_escaped():
    _, body, _ = _run(bouncer_name="<script>alert(1)</script>")
    # No raw <script>alert tag should appear in the title.
    assert "<script>alert(1)" not in body
    assert "&lt;script&gt;alert(1)" in body


def test_html_has_table_head_with_required_columns():
    _, body, _ = _run()
    # Required columns per the #272 spec.
    for col in ["time", "severity", "event type", "actor", "operation", "verdict"]:
        assert col in body.lower(), f"missing column header: {col}"


def test_html_embeds_audit_events_url():
    _, body, _ = _run()
    # The JS must hit the existing /audit/events endpoint.
    assert "/audit/events" in body


def test_html_has_filter_pause_clear_controls():
    _, body, _ = _run()
    assert 'id="filter"' in body
    assert 'id="pause-btn"' in body
    assert 'id="clear-btn"' in body


def test_html_contains_event_counters():
    _, body, _ = _run()
    for el_id in [
        "count-total", "count-allow", "count-deny",
        "count-admin", "count-heartbeat",
    ]:
        assert el_id in body, f"missing counter id: {el_id}"


def test_html_does_not_embed_token():
    """Per the no-secret-shape constraint, the served HTML must NOT
    contain the configured bearer token regardless of auth mode."""
    secret = "TOKEN-SHOULD-NOT-APPEAR-IN-HTML-AAAA1234"
    _, body, _ = _run(require_bearer=secret)
    assert secret not in body


def test_html_has_no_external_resources():
    """Per [[self-host-zero-billing-dependency]] — no CDN, no Google
    Fonts, no external CSS, no analytics."""
    _, body, _ = _run()
    forbidden = [
        "googleapis.com",
        "gstatic.com",
        "cloudflare",
        "cdn.",
        "googletagmanager",
        "google-analytics",
        "fonts.google",
        "//unpkg.com",
        "//cdnjs.",
        "//jsdelivr.",
    ]
    low = body.lower()
    for needle in forbidden:
        assert needle not in low, f"external dependency leaked: {needle}"


def test_html_uses_safety_not_surveillance_language():
    """Per [[security-team-positioning-safety-not-surveillance]] — no
    'violation' / 'infraction' / 'unauthorized' labels."""
    _, body, _ = _run()
    low = body.lower()
    forbidden_terms = ["violation", "infraction", "unauthorized"]
    for term in forbidden_terms:
        # Use word-boundary check to avoid false positives inside long
        # identifiers (none expected, but be defensive).
        if re.search(r"\b" + re.escape(term) + r"\b", low):
            pytest.fail(f"forbidden surveillance term in UI: {term}")


def test_html_is_read_only_no_mutating_controls():
    """Per [[creates-never-mutates]] — UI is a viewer, not a controller.
    No POST / DELETE / PUT verbs anywhere; no buttons whose label
    suggests state mutation (kill / delete / approve / revoke)."""
    _, body, _ = _run()
    low = body.lower()
    for term in [
        "kill session", "revoke session", "delete profile",
        "approve request", "deny request", "pause profile",
    ]:
        assert term not in low, f"mutating control leaked: {term}"
    # Method strings — the JS uses only GET via XMLHttpRequest.
    assert "method=\"post\"" not in low
    assert "method=\"delete\"" not in low
    assert "method=\"put\"" not in low


def test_html_has_strict_csp_header():
    _, _, headers = _run()
    csp = headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    # No remote sources allowed.
    assert "http://" not in csp
    assert "https://" not in csp


def test_html_under_500_lines():
    """Per spec — under 500 lines of HTML+CSS+JS."""
    _, body, _ = _run()
    n_lines = len(body.splitlines())
    assert n_lines < 500, f"HTML grew to {n_lines} lines (cap 500)"


def test_loopback_root_no_auth_required():
    """When require_bearer=None the page renders without any header."""
    status, body, _ = _run(require_bearer=None)
    assert status == 200
    assert "<title>" in body


def test_external_root_accepts_correct_bearer():
    status, body, _ = _run(
        require_bearer="s3kret",
        headers={"Authorization": "Bearer s3kret"},
    )
    assert status == 200
    assert "<title>" in body


def test_external_root_rejects_wrong_bearer():
    status, _, _ = _run(
        require_bearer="s3kret",
        headers={"Authorization": "Bearer wrong"},
    )
    assert status == 403


def test_external_root_serves_html_without_header():
    """When no Authorization header is sent at all (browser visit) the
    page still loads so the JS can render the 'auth required' banner.
    This is intentional — the HTML body is harmless + token-free."""
    status, body, _ = _run(require_bearer="s3kret")
    assert status == 200
    assert "<title>" in body
    assert "s3kret" not in body
