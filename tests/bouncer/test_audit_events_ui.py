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
import json
import re
import shutil
import subprocess

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


def test_html_under_1500_lines():
    """Per #425/§A64 — page bumps the original #272 500-line cap to 1500.

    The launch-blocker adds first-class time-range / verdict / session /
    action-regex / reason-search controls + CSV/JSON/OCSF export
    buttons + 10K-row virtualization. The original 500-line target was
    a #272 minimum-surface goal; the Phase F audit explicitly enlarged
    the surface so the cap moves with the scope (1500 leaves headroom
    for one more iteration without making the test brittle)."""
    _, body, _ = _run()
    n_lines = len(body.splitlines())
    assert n_lines < 1500, f"HTML grew to {n_lines} lines (cap 1500)"


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


# ---------------------------------------------------------------------------
# #425 / §A64 — UI query depth (per-bouncer filter surface + export).
#
# Per the Phase F audit (#431) the per-bouncer UI already shipped a
# freeform filter input + pause/clear. Launch-blocker adds first-class
# time-range / verdict / session / action-regex / reason-search inputs
# + CSV/JSON/OCSF export buttons + 10K-row virtualization. Tests check
# the rendered HTML carries the controls + the JS that wires them.
#
# Per [[unified-ui-link-page]] this surface lives on the PER-BOUNCER
# UI, not on the suite link page. (#298 link page stays a link page.)
# ---------------------------------------------------------------------------


def test_events_ui_time_range_filter_5m_1h_24h_custom():
    """Header bar exposes 5m / 1h / 24h / all + a custom-window button."""
    _, body, _ = _run()
    # Each preset button is wired by data-range attribute.
    for window in ("5m", "1h", "24h", "all"):
        assert f'data-range="{window}"' in body, f"missing range button: {window}"
    # Custom window is a dedicated button (not a data-range preset).
    assert 'id="range-custom"' in body
    # Range display reads back the current window state.
    assert 'id="range-display"' in body


def test_events_ui_action_resource_pattern_filter():
    """Action / resource regex input is present + plumbed client-side."""
    _, body, _ = _run()
    assert 'id="filter-action"' in body
    # The JS extracts the operation AND the first resource UID so a
    # single regex matches either column.
    assert "extractResourceUid" in body
    assert "extractOperation" in body
    # The action/resource regex is now one branch of the unified live
    # client-side gate (passesAllFilters), applied to rendered rows.
    assert "passesAllFilters" in body


def test_events_ui_agent_session_id_filter():
    """Session id input fans out to the canonical filter expression."""
    _, body, _ = _run()
    assert 'id="filter-session"' in body
    # The JS expands the input to the canonical long-form filter
    # field per [[cross-product-agent-parity]] §A18 — agents + UI
    # share the same fully-qualified path.
    assert "unmapped.iam_jit.agent.session_id=" in body


def test_events_ui_verdict_filter_allow_deny():
    """Verdict toggle exposes both / allow / deny modes."""
    _, body, _ = _run()
    for verdict in ("", "allow", "deny"):
        assert f'data-verdict="{verdict}"' in body, f"missing verdict btn: {verdict}"
    # Plumbed to the server's verdict=ALLOW / verdict=DENY filter
    # shortcut (which tail.get_path expands to
    # unmapped.iam_jit.verdict).
    assert "verdict=ALLOW" in body
    assert "verdict=DENY" in body


def test_events_ui_free_text_reason_search():
    """Reason-search input runs as a client-side regex over the
    decision's reason field (and falls back to status_detail)."""
    _, body, _ = _run()
    assert 'id="filter-reason"' in body
    assert "extractReason" in body
    # Both fallback fields are checked.
    assert "u.reason" in body or "ev.status_detail" in body


def test_events_ui_export_csv_json_ocsf():
    """Three export buttons (CSV / JSON / OCSF NDJSON) issue a
    one-shot fetch with the current filter set + trigger a download."""
    _, body, _ = _run()
    for el_id in ("export-csv", "export-json", "export-ocsf"):
        assert f'id="{el_id}"' in body, f"missing export button: {el_id}"
    # Each export hits /audit/events?format=... with the SAME filter
    # set + the AUDIT_EVENTS_MAX_LIMIT (1000) cap.
    assert "format=csv" in body or 'doExport("csv"' in body
    assert 'doExport("jsonl"' in body
    # Suggested download filenames so a SIEM ingest doesn't see
    # browser-default `download` names.
    assert "audit-events.csv" in body
    assert "audit-events.ocsf.ndjson" in body


def test_events_ui_pagination_virtualized_10k_events():
    """Page caps rendered rows at 10K with FIFO eviction so the
    browser doesn't crash on 100K-event loads. The shown / total
    counter surfaces how many were kept vs how many were seen."""
    _, body, _ = _run()
    # 10K cap is a load-bearing constant — explicit + searchable.
    assert "MAX_ROWS = 10000" in body
    # Shown / total counter surfaces the windowing.
    assert 'id="count-shown"' in body
    assert "updateShownCount" in body


def test_events_ui_filterbar_renders_outside_link_page():
    """The PER-BOUNCER UI carries these filters; the suite link page
    (#298) MUST NOT — per [[unified-ui-link-page]] the link page stays
    a link page. This is the negative-control: assert the filter bar
    block we render is the per-bouncer surface, not a re-purposed
    link page (which lives in gbounce/internal/proxy/suite_handler.go,
    not here)."""
    _, body, _ = _run()
    assert 'class="filterbar"' in body or 'id="filterbar"' in body
    # No mention of cross-bouncer aggregation on this surface.
    low = body.lower()
    assert "aggregator" not in low
    assert "cross-bouncer" not in low


def test_events_ui_export_buttons_carry_filter_state():
    """Export endpoint URL includes the SAME filter params as the
    poll — otherwise the operator's filtered view + their downloaded
    CSV diverge silently. The JS uses one buildQueryParams helper for
    both code paths."""
    _, body, _ = _run()
    assert "buildQueryParams" in body
    # Both poll + export call the helper.
    assert "buildQueryParams({" in body


def test_events_ui_export_csv_uses_format_csv_param():
    """The CSV export hits /audit/events?format=csv — the server-side
    AUDIT_EVENTS_FORMAT_CSV path the endpoint shipped per #425."""
    _, body, _ = _run()
    # The doExport call site passes "csv" as the format argument; the
    # server then renders DEFAULT_CSV_COLUMNS with the PII guard.
    assert 'doExport("csv"' in body


# ---------------------------------------------------------------------------
# Live audit-UI filter — the regression this fix closes.
#
# The bug: the filter controls only changed what the NEXT /audit/events
# poll fetched (server-side `filter=`), so already-rendered rows stayed
# on screen — typing/changing a filter did NOT re-filter the visible
# table. The fix makes every row-level filter (freeform / session /
# verdict / action / reason) a LIVE client-side toggle over the rendered
# rows, and stops sending those filters on the live poll (export still
# sends them server-side).
#
# Two layers, mirroring the gbounce reference (PR #6):
#   1. BEHAVIOURAL — the exact `_AUDIT_FILTER_MATCH_JS` source is run
#      under `node` and its verdict asserted across the whole grammar.
#      The old tests only string-matched the HTML and never ran the JS,
#      which is why the dead filter shipped silently.
#   2. CONTRACT — string assertions on the rendered page pin the DOM
#      wiring that broke (live `input` bind, applied on append, matcher
#      token substituted) and guard the live-poll-vs-export split.
# ---------------------------------------------------------------------------


_FILTER_HARNESS = r"""
%s
var input = "";
process.stdin.on("data", function (d) { input += d; });
process.stdin.on("end", function () {
  var payload = JSON.parse(input);
  var out = auditFilterMatch(payload.fields, payload.query);
  process.stdout.write(out ? "true" : "false");
});
"""


def _run_filter_js(fields: dict, query: str) -> bool:
    """Execute the production `_AUDIT_FILTER_MATCH_JS` under node and
    return its boolean verdict for (fields, query).

    Skips gracefully where node is absent (local dev without it) but
    MUST run in CI — GitHub Actions ubuntu runners ship node, and the
    point of this test is that the matcher grammar can never silently
    rot again behind string-only HTML assertions.
    """
    node = shutil.which("node")
    if node is None:  # pragma: no cover - only on node-less hosts
        pytest.skip("node not available to execute _AUDIT_FILTER_MATCH_JS")
    from iam_jit.bouncer.audit_export.events_ui import _AUDIT_FILTER_MATCH_JS

    script = _FILTER_HARNESS % _AUDIT_FILTER_MATCH_JS
    proc = subprocess.run(
        [node, "-e", script],
        input=json.dumps({"fields": fields, "query": query}),
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 0, (
        f"node failed: rc={proc.returncode}\nstdout={proc.stdout!r}\n"
        f"stderr={proc.stderr!r}"
    )
    assert proc.stdout in ("true", "false"), (
        f"unexpected matcher output: {proc.stdout!r} (stderr={proc.stderr!r})"
    )
    return proc.stdout == "true"


def _deny_row() -> dict:
    return {
        "time": "2026-06-02 12:00:00",
        "severity": "High",
        "type": "PROXY_DECISION",
        "actor": "claude-code",
        "op": "GET /repos/foo",
        "verdict": "DENIED",
    }


def _allow_row() -> dict:
    return {
        "time": "2026-06-02 12:00:01",
        "severity": "Info",
        "type": "PROXY_DECISION",
        "actor": "anonymous",
        "op": "POST /v1/messages",
        "verdict": "ALLOWED",
    }


@pytest.mark.parametrize(
    ("row_fn", "query", "want"),
    [
        # Empty / whitespace filter matches everything (the live
        # default — a broken matcher that hides rows by default would
        # fail here, which is exactly the silent-degradation shape).
        (_deny_row, "", True),
        (_allow_row, "", True),
        (_deny_row, "   ", True),
        # Plain substring across all columns, case-insensitive.
        (_deny_row, "denied", True),
        (_deny_row, "claude", True),
        (_deny_row, "CLAUDE-CODE", True),
        (_allow_row, "claude", False),
        (_allow_row, "/v1/messages", True),
        # field=value -> substring on that column only.
        (_deny_row, "verdict=denied", True),
        (_allow_row, "verdict=denied", False),
        # "deny" is NOT a substring of "denied" — guards against a
        # naive prefix match silently dropping denied rows.
        (_deny_row, "verdict=deny", False),
        (_deny_row, "actor=claude", True),
        (_allow_row, "actor=claude", False),
        (_deny_row, "sev=high", True),
        (_deny_row, "et=proxy_decision", True),
        (_deny_row, "operation=GET", True),
        (_allow_row, "v=allow", True),
        (_deny_row, "VERDICT=DENIED", True),
        # field= must not bleed across columns.
        (_deny_row, "actor=DENIED", False),
        # field~regex -> case-insensitive regex on that column.
        (_deny_row, "op~^GET", True),
        (_allow_row, "op~^GET", False),
        (_allow_row, "verdict~allow|denied", True),
        # Invalid regex must NOT throw — returns false, no crash.
        (_deny_row, "op~[", False),
        # Unknown field falls back to whole-string substring so a typo
        # never blanks the table.
        (_deny_row, "nope=claude", False),
    ],
)
def test_audit_filter_match_grammar_executed_under_node(row_fn, query, want):
    """BEHAVIOURAL: run the real matcher JS and assert the full grammar.

    This is the test that would have caught the dead filter — it runs
    the matcher the same way the browser does, not just string-matches
    the HTML.
    """
    got = _run_filter_js(row_fn(), query)
    assert got is want, f"auditFilterMatch(row, {query!r}) = {got}; want {want}"


def test_audit_filter_match_narrows_a_visible_set_under_node():
    """BEHAVIOURAL: the matcher narrows a concrete rendered set — the
    end-to-end 'typing a filter shows fewer rows' guarantee, row by
    row, executed under node."""
    rows = [_deny_row(), _allow_row(), _deny_row()]

    def visible(q):
        return sum(1 for r in rows if _run_filter_js(r, q))

    assert visible("") == 3
    assert visible("verdict=denied") == 2
    assert visible("verdict=allowed") == 1
    assert visible("zzz-no-match") == 0


def test_filter_matcher_token_substituted_and_present():
    """CONTRACT: the {{FILTER_JS}} token is substituted (matcher
    present) and no stray token leaks into the page."""
    _, body, _ = _run()
    assert "{{FILTER_JS}}" not in body
    assert "function auditFilterMatch(" in body


def test_filter_bound_to_live_input_not_change_only():
    """CONTRACT: the freeform filter is bound to the LIVE 'input' event
    (not the old change-only re-fetch that left stale rows)."""
    _, body, _ = _run()
    assert 'elFilter.addEventListener("input"' in body
    # The dead change-handler that forced a re-fetch must be gone.
    assert 'elFilter.addEventListener("change"' not in body


def test_filter_applied_from_append_path():
    """CONTRACT: rows are re-filtered on every append + the unified
    client-side gate evaluates the rendered rows."""
    _, body, _ = _run()
    assert "applyClientFilters()" in body
    assert "passesAllFilters(tr._ev, tr._fields)" in body
    # Each rendered row stashes its event + fields for live re-eval.
    assert "tr._fields =" in body
    assert "tr._ev = ev" in body


def test_live_poll_omits_row_filters_but_export_keeps_them():
    """CONTRACT + REGRESSION GUARD: the live poll must NOT push the
    row-level filters (freeform / session / verdict `filter=`) to the
    server — that was the root cause (filtering only the next fetch
    left stale rows). Export MUST still send them server-side so the
    download matches the filtered view. The split is gated on the
    `serverFilter` opts flag."""
    _, body, _ = _run()
    # The shared builder gates the server-side filters behind the flag.
    assert "if (opts.serverFilter)" in body
    # Live poll passes serverFilter:false; export passes true.
    assert "serverFilter: false" in body
    assert "serverFilter: true" in body
    # The freeform `filter=` push still exists (for export) but only
    # inside the serverFilter branch — assert it sits AFTER the gate.
    gate = body.index("if (opts.serverFilter)")
    filter_push = body.index('qs.push("filter=" + encodeURIComponent(f))')
    assert filter_push > gate, (
        "freeform filter= push is outside the serverFilter gate — "
        "the live poll would narrow the fetch again (regression to "
        "the old bug)"
    )


def test_verdict_and_session_filters_are_live_not_refetch():
    """CONTRACT: the verdict toggle + session input drive
    applyClientFilters (live), not a forced poll()/re-fetch."""
    _, body, _ = _run()
    # Session input bound live.
    assert "wireLiveFilter(elFilterSession)" in body
    # passesAllFilters combines session + verdict client-side.
    assert "extractSessionId" in body
    assert 'verdictMode === "allow"' in body
