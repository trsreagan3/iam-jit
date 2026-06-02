"""#272 — minimal web UI served at GET / on the bouncer's mgmt port.

The page is a single self-contained HTML+CSS+JS file (no build step,
no external CDN, no Google Fonts, no analytics) that connects to
the existing ``GET /audit/events`` endpoint (#271) and renders a live-
updating table.

Wire choice
-----------

The page LONG-POLLS ``/audit/events?since=<last>&limit=100`` every
two seconds rather than using Server-Sent Events. SSE requires
streaming response semantics that ibounce's aiohttp handler doesn't
ship today, and the operator experience is identical at 2 s tick.
A future bump can swap the JS polling loop for an ``EventSource``
without touching the server contract. The kbounce / dbounce /
gbounce ports serve the same HTML for cross-product parity.

#425 / §A64 extensions
----------------------

Per the Phase F audit (#431) the original #272 UI shipped one freeform
``filter`` text input + pause/clear/counts. Operator UAT showed
muscle-memory friction for the common slices, so the launch-blocker
adds first-class controls that fan out into the same
``parse_filter_expr`` server-side grammar:

  * **Time-range buttons** (5m / 1h / 24h / custom). Custom prompts for
    an ISO 8601 / RFC 3339 ``since`` so an operator investigating an
    incident can scope to the exact window. Translates to the server's
    ``?since=`` parameter (already #271-shipped).
  * **Action / resource pattern filter** — regex against
    ``api.operation`` ORed with the first ``resources[].uid`` so a
    single input matches either column.
  * **Agent session id filter** — shortcut for
    ``unmapped.iam_jit.agent.session_id=<value>``.
  * **Verdict filter** (allow / deny / both). When set, expands to a
    server-side ``filter=verdict=<value>`` (the same shortcut the
    ``tail.get_path`` helper supports).
  * **Free-text reason search** — regex against
    ``unmapped.iam_jit.reason`` AND ``status_detail`` so the operator
    finds the deny reason text regardless of which field the writer
    used.
  * **Export buttons** (CSV / JSON / OCSF NDJSON). Each issues a
    one-shot ``/audit/events?format=<fmt>&limit=1000`` against the
    SAME filter set, then triggers a browser download. CSV uses the
    ``DEFAULT_CSV_COLUMNS`` PII guard; OCSF NDJSON is the same JSONL
    wire format SIEM ingest expects (one OCSF event per line).
  * **Pagination + virtualized rows** — soft cap at 10K rendered rows
    with FIFO eviction (oldest dropped). Keeps the page responsive
    when an operator loads a wide window. The "shown / total seen"
    counter surfaces in the header.

Auth model
----------

Same as :mod:`events_endpoint`:
  * loopback bind (default) → no Authorization header required
  * external bind → caller must supply ``Authorization: Bearer
    <audit-events-token>`` (a query-string ``?token=`` fallback is
    accepted so the browser can open the URL without a header tool;
    the token is NEVER embedded in the served HTML).

Per ``[[creates-never-mutates]]`` the UI is read-only — no buttons
that mutate bouncer state. Per ``[[self-host-zero-billing-
dependency]]`` no CDN dependencies; everything inline + offline-
ready. Per ``[[security-team-positioning-safety-not-surveillance]]``
labels use "deny" / "allow" / "policy mismatch", never
"violation" / "infraction" / "unauthorized". Per
``[[unified-ui-link-page]]`` this is the PER-BOUNCER query surface;
the #298 link page stays a link page (no aggregator UI here).
"""

from __future__ import annotations

import html as _html
import logging

logger = logging.getLogger(__name__)


# Default bouncer name shown in the title bar + product badge. Override
# per-product so the operator sees "ibounce" / "kbounce" / etc. when
# they land on the page. The other three bouncers (kbouncer / dbounce
# / gbounce) ship the SAME HTML body shape with their own product name
# baked in; this Python copy is the ibounce flavour.
BOUNCER_NAME = "ibounce"


# _AUDIT_FILTER_MATCH_JS is the single source of truth for the live
# client-side freeform-filter matcher. It is injected into the page
# (replacing the ``{{FILTER_JS}}`` token) AND executed verbatim by the
# node-driven test in tests/bouncer/test_audit_events_ui.py, so the
# filter grammar can never silently rot again (the old tests only
# string-matched the HTML and never ran the JS). Grammar mirrors
# gbounce's ``auditFilterMatchJS``:
#
#     ""            -> matches everything
#     field=value   -> case-insensitive substring on that column
#     field~regex   -> case-insensitive regex on that column
#     anything else -> case-insensitive substring across all columns
#
# Recognised fields: time, severity, type (event_type/et), actor,
# op (operation), verdict (v). An unknown field name falls back to a
# whole-string substring match so a typo never hides every row.
_AUDIT_FILTER_MATCH_JS = r"""
  function auditFilterFieldList(f) {
    return [f.time, f.severity, f.type, f.actor, f.op, f.verdict];
  }
  function auditFilterMatch(f, query) {
    f = f || {};
    var q = (query == null ? "" : String(query)).trim();
    if (!q) { return true; }
    var m = /^([A-Za-z_]+)\s*([=~])\s*([\s\S]*)$/.exec(q);
    if (m) {
      var aliases = {
        time: "time", severity: "severity", sev: "severity",
        type: "type", event_type: "type", et: "type",
        actor: "actor", op: "op", operation: "op",
        verdict: "verdict", v: "verdict"
      };
      var key = aliases[m[1].toLowerCase()];
      if (key) {
        var hay = String(f[key] == null ? "" : f[key]);
        var val = m[3];
        if (m[2] === "=") {
          return hay.toLowerCase().indexOf(val.trim().toLowerCase()) !== -1;
        }
        try { return new RegExp(val, "i").test(hay); }
        catch (e) { return false; }
      }
    }
    var all = auditFilterFieldList(f).map(function (v) {
      return v == null ? "" : String(v);
    }).join(" ␟ ").toLowerCase();
    return all.indexOf(q.toLowerCase()) !== -1;
  }
"""


def render_audit_events_ui(*, bouncer_name: str = BOUNCER_NAME) -> str:
    """Return the rendered HTML page for GET /.

    ``bouncer_name`` is HTML-escaped before substitution so an
    operator who runs ibounce under an exotic instance name can't
    inject script via the rendered title.

    The trusted ``{{FILTER_JS}}`` block is substituted FIRST so an
    escaped product name can never smuggle a ``{{FILTER_JS}}`` token of
    its own into the page.
    """
    out = _TEMPLATE.replace("{{FILTER_JS}}", _AUDIT_FILTER_MATCH_JS)
    safe = _html.escape(bouncer_name)
    return out.replace("{{BOUNCER_NAME}}", safe)


# The HTML template is kept inline as a single triple-quoted constant
# so the file ships zero on-disk dependencies. Per the #272 spec the
# rendered page is < 500 lines of HTML+CSS+JS, vanilla JS only, no
# framework, no build step.
_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{BOUNCER_NAME}} - live audit stream</title>
<style>
:root {
  --bg: #0d1117;
  --panel: #161b22;
  --line: #30363d;
  --text: #c9d1d9;
  --muted: #8b949e;
  --allow: #2ea043;
  --deny: #f85149;
  --admin: #58a6ff;
  --heartbeat: #6e7681;
  --warn: #d29922;
  --accent: #f0883e;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--text);
  font: 13px/1.45 ui-monospace, SFMono-Regular, "SF Mono", Menlo,
        Consolas, "Liberation Mono", monospace;
}
header {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 18px;
  align-items: center;
  padding: 10px 14px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  position: sticky;
  top: 0;
  z-index: 10;
}
header .brand {
  font-weight: 700;
  font-size: 15px;
  letter-spacing: 0.3px;
}
header .brand .dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 6px;
  vertical-align: middle;
  background: var(--allow);
  box-shadow: 0 0 6px var(--allow);
}
header .brand .dot.stale { background: var(--warn); box-shadow: 0 0 6px var(--warn); }
header .brand .dot.err { background: var(--deny); box-shadow: 0 0 6px var(--deny); }
header .counts {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  color: var(--muted);
  font-size: 12px;
}
header .counts b { color: var(--text); }
header .controls {
  display: flex;
  gap: 8px;
  margin-left: auto;
  flex-wrap: wrap;
}
header input[type="text"] {
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 5px 8px;
  font: inherit;
  width: 240px;
}
header input[type="text"]::placeholder { color: var(--muted); }
header button {
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 5px 10px;
  font: inherit;
  cursor: pointer;
}
header button:hover { border-color: var(--accent); }
header button.active { border-color: var(--accent); color: var(--accent); }
.filterbar {
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  padding: 8px 14px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.filterbar-row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
}
.filterbar-label {
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.4px;
  margin-right: 2px;
}
.filterbar-display {
  color: var(--muted);
  font-size: 11px;
  margin-left: 6px;
}
.filterbar-input {
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 4px 7px;
  font: inherit;
  font-size: 12px;
  width: 180px;
}
.filterbar-input::placeholder { color: var(--muted); }
.range-btn, .verdict-btn, .export-btn {
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 3px 8px;
  font: inherit;
  font-size: 12px;
  cursor: pointer;
}
.range-btn:hover, .verdict-btn:hover, .export-btn:hover {
  border-color: var(--accent);
}
.range-btn.active, .verdict-btn.active {
  border-color: var(--accent);
  color: var(--accent);
}
main { padding: 0; }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12.5px;
}
thead th {
  text-align: left;
  font-weight: 600;
  background: var(--panel);
  color: var(--muted);
  border-bottom: 1px solid var(--line);
  padding: 6px 10px;
  position: sticky;
  top: 49px;
  z-index: 5;
  letter-spacing: 0.4px;
  text-transform: uppercase;
  font-size: 11px;
}
tbody tr { border-bottom: 1px solid #1d232b; }
tbody tr:hover { background: #1a2029; }
tbody td {
  padding: 6px 10px;
  vertical-align: top;
  word-break: break-word;
}
.verdict {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 3px;
  font-weight: 700;
  font-size: 11px;
  letter-spacing: 0.5px;
  border: 1px solid transparent;
}
.verdict.allow { color: var(--allow); border-color: var(--allow); }
.verdict.deny { color: var(--deny); border-color: var(--deny); }
.verdict.admin { color: var(--admin); border-color: var(--admin); }
.verdict.heartbeat { color: var(--heartbeat); border-color: var(--heartbeat); }
.verdict.unknown { color: var(--muted); border-color: var(--muted); }
tr.row-deny td { background: rgba(248, 81, 73, 0.05); }
tr.row-allow td { /* default; no tint */ }
tr.row-admin td { background: rgba(88, 166, 255, 0.05); }
tr.row-heartbeat td { color: var(--muted); }
.empty {
  padding: 40px 20px;
  text-align: center;
  color: var(--muted);
}
.err-banner {
  padding: 8px 14px;
  background: rgba(248, 81, 73, 0.12);
  border-bottom: 1px solid var(--deny);
  color: var(--deny);
  font-size: 12px;
}
.err-banner:empty { display: none; }
footer {
  padding: 8px 14px;
  color: var(--muted);
  font-size: 11px;
  border-top: 1px solid var(--line);
  text-align: center;
}
@media (max-width: 720px) {
  header .controls { width: 100%; margin-left: 0; }
  header input[type="text"] { flex: 1 1 auto; width: auto; }
  thead th { top: 0; position: static; }
  table { font-size: 12px; }
  tbody td { padding: 5px 6px; }
}
</style>
</head>
<body>
<header>
  <div class="brand"><span class="dot" id="status-dot"></span>{{BOUNCER_NAME}} <span style="color: var(--muted); font-weight: 400;">- live audit stream</span></div>
  <div class="counts">
    <span>shown <b id="count-shown">0</b> / total <b id="count-total">0</b></span>
    <span>allow <b id="count-allow">0</b></span>
    <span>deny <b id="count-deny">0</b></span>
    <span>admin <b id="count-admin">0</b></span>
    <span>heartbeat <b id="count-heartbeat">0</b></span>
  </div>
  <div class="controls">
    <input type="text" id="filter" placeholder="filter: field=value or field~regex">
    <button type="button" id="pause-btn">pause</button>
    <button type="button" id="clear-btn">clear</button>
  </div>
</header>
<div class="filterbar" id="filterbar">
  <div class="filterbar-row">
    <span class="filterbar-label">time:</span>
    <button type="button" class="range-btn" data-range="5m">5m</button>
    <button type="button" class="range-btn" data-range="1h">1h</button>
    <button type="button" class="range-btn" data-range="24h">24h</button>
    <button type="button" class="range-btn" data-range="all">all</button>
    <button type="button" class="range-btn" id="range-custom">custom&hellip;</button>
    <span id="range-display" class="filterbar-display"></span>
  </div>
  <div class="filterbar-row">
    <span class="filterbar-label">verdict:</span>
    <button type="button" class="verdict-btn active" data-verdict="">both</button>
    <button type="button" class="verdict-btn" data-verdict="allow">allow only</button>
    <button type="button" class="verdict-btn" data-verdict="deny">deny only</button>
  </div>
  <div class="filterbar-row">
    <span class="filterbar-label">session:</span>
    <input type="text" id="filter-session" placeholder="agent.session_id" class="filterbar-input">
    <span class="filterbar-label">action / resource:</span>
    <input type="text" id="filter-action" placeholder="regex (s3:Get.*  |  prod-.*)" class="filterbar-input">
    <span class="filterbar-label">reason search:</span>
    <input type="text" id="filter-reason" placeholder="free text (regex)" class="filterbar-input">
  </div>
  <div class="filterbar-row">
    <span class="filterbar-label">export:</span>
    <button type="button" class="export-btn" id="export-csv">CSV</button>
    <button type="button" class="export-btn" id="export-json">JSON</button>
    <button type="button" class="export-btn" id="export-ocsf">OCSF NDJSON</button>
    <span class="filterbar-display">exports include the SAME filters; capped at 1000 events / call</span>
  </div>
</div>
<div class="err-banner" id="err-banner"></div>
<main>
<table>
<thead>
<tr>
  <th style="width: 168px;">time</th>
  <th style="width: 80px;">severity</th>
  <th style="width: 140px;">event type</th>
  <th style="width: 160px;">actor</th>
  <th>operation</th>
  <th style="width: 110px;">verdict</th>
</tr>
</thead>
<tbody id="events-body">
<tr class="empty-row"><td colspan="6" class="empty">waiting for events&hellip;</td></tr>
</tbody>
</table>
</main>
<footer>read-only viewer - <a href="/healthz" style="color: var(--muted);">/healthz</a> | <a href="/audit/events?limit=10" style="color: var(--muted);">/audit/events</a></footer>
<script>
"use strict";
(function () {
{{FILTER_JS}}
  var POLL_MS = 2000;
  // #425 / §A64: 10K hard cap on rendered rows (virtualized FIFO).
  // The "shown" counter surfaces how many we kept vs how many we saw
  // so an operator who loads a huge window knows the table is windowed.
  var MAX_ROWS = 10000;
  // Per-call cap on the export endpoint. The server's
  // AUDIT_EVENTS_MAX_LIMIT (1000) is the upper bound; we ask for it
  // explicitly so the operator's download contains the full slice
  // their filters select (not just the polling window).
  var EXPORT_LIMIT = 1000;
  var token = null;
  try {
    var m = window.location.hash.match(/[#&]token=([^&]+)/);
    if (m) { token = decodeURIComponent(m[1]); }
  } catch (e) { /* ignore */ }

  var elBody = document.getElementById("events-body");
  var elFilter = document.getElementById("filter");
  var elPause = document.getElementById("pause-btn");
  var elClear = document.getElementById("clear-btn");
  var elErr = document.getElementById("err-banner");
  var elDot = document.getElementById("status-dot");
  var elCountTotal = document.getElementById("count-total");
  var elCountShown = document.getElementById("count-shown");
  var elCountAllow = document.getElementById("count-allow");
  var elCountDeny = document.getElementById("count-deny");
  var elCountAdmin = document.getElementById("count-admin");
  var elCountHeartbeat = document.getElementById("count-heartbeat");

  // #425 / §A64 extended filter controls.
  var elFilterSession = document.getElementById("filter-session");
  var elFilterAction = document.getElementById("filter-action");
  var elFilterReason = document.getElementById("filter-reason");
  var elRangeDisplay = document.getElementById("range-display");
  var elExportCsv = document.getElementById("export-csv");
  var elExportJson = document.getElementById("export-json");
  var elExportOcsf = document.getElementById("export-ocsf");

  var counts = { total: 0, allow: 0, deny: 0, admin: 0, heartbeat: 0 };
  var seenIds = Object.create(null);
  var paused = false;
  var lastTimeMs = 0;
  var pollHandle = null;
  // Currently-selected time-range; "all" disables `since=` entirely.
  // Anything else is a relative-window keyword the JS converts to an
  // ISO 8601 lower bound at request time.
  var rangeMode = "all";
  var rangeCustomIso = null;
  var verdictMode = "";

  function setErr(msg) { elErr.textContent = msg || ""; }
  function setDot(state) {
    elDot.classList.remove("stale", "err");
    if (state === "stale") elDot.classList.add("stale");
    if (state === "err") elDot.classList.add("err");
  }

  function fmtTime(ms) {
    if (!ms) return "-";
    var d = new Date(typeof ms === "number" ? ms : Date.parse(ms));
    if (isNaN(d.getTime())) return String(ms);
    var pad = function (n) { return n < 10 ? "0" + n : "" + n; };
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
           " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  function classifyVerdict(ev) {
    var u = ev && ev.unmapped && ev.unmapped.iam_jit || {};
    var v = (u.verdict || ev.verdict || "").toString().toUpperCase();
    var et = (u.event_type || ev.event_type || ev.class_name || "").toString().toUpperCase();
    if (et.indexOf("HEARTBEAT") !== -1) return { label: "HEARTBEAT", cls: "heartbeat" };
    if (et.indexOf("ADMIN") !== -1) return { label: et.replace(/[_-]/g, " "), cls: "admin" };
    if (v === "DENY" || v === "DENIED") return { label: "DENIED", cls: "deny" };
    if (v === "ALLOW" || v === "ALLOWED") return { label: "ALLOWED", cls: "allow" };
    if (v) return { label: v, cls: "unknown" };
    return { label: "-", cls: "unknown" };
  }

  function extractSeverity(ev) {
    if (ev.severity) return String(ev.severity);
    if (ev.severity_id != null) {
      var map = { 1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical" };
      return map[ev.severity_id] || ("sev=" + ev.severity_id);
    }
    return "-";
  }

  function extractActor(ev) {
    var u = ev && ev.unmapped && ev.unmapped.iam_jit || {};
    if (ev.actor && ev.actor.user && ev.actor.user.name) return ev.actor.user.name;
    if (u.actor) return String(u.actor);
    if (u.agent && u.agent.name) return String(u.agent.name);
    return "-";
  }

  function extractOperation(ev) {
    if (ev.api && ev.api.operation) return ev.api.operation;
    var u = ev && ev.unmapped && ev.unmapped.iam_jit || {};
    if (u.operation) return String(u.operation);
    if (ev.activity_name) return String(ev.activity_name);
    return "-";
  }

  function extractEventType(ev) {
    var u = ev && ev.unmapped && ev.unmapped.iam_jit || {};
    if (u.event_type) return String(u.event_type);
    if (ev.event_type) return String(ev.event_type);
    if (ev.class_name) return String(ev.class_name);
    return "-";
  }

  function eventId(ev) {
    // Stable-enough id: time + actor + operation. The endpoint
    // doesn't ship a uuid per event today; this is good enough for
    // dedupe across overlapping polls.
    return [ev.time || "", extractActor(ev), extractOperation(ev), extractEventType(ev)].join("|");
  }

  function eventTimeMs(ev) {
    var t = ev.time;
    if (typeof t === "number") return t;
    if (typeof t === "string") {
      var n = Date.parse(t);
      if (!isNaN(n)) return n;
    }
    return Date.now();
  }

  function bump(cls) {
    counts.total += 1;
    if (cls === "allow") counts.allow += 1;
    else if (cls === "deny") counts.deny += 1;
    else if (cls === "admin") counts.admin += 1;
    else if (cls === "heartbeat") counts.heartbeat += 1;
    elCountTotal.textContent = counts.total;
    elCountAllow.textContent = counts.allow;
    elCountDeny.textContent = counts.deny;
    elCountAdmin.textContent = counts.admin;
    elCountHeartbeat.textContent = counts.heartbeat;
    updateShownCount();
  }

  function updateShownCount() {
    if (elCountShown) {
      var rendered = elBody.querySelectorAll("tr:not(.empty-row)").length;
      elCountShown.textContent = String(rendered);
    }
  }

  function renderRow(ev) {
    var v = classifyVerdict(ev);
    var tr = document.createElement("tr");
    tr.className = "row-" + v.cls;
    var cells = [
      fmtTime(eventTimeMs(ev)),
      extractSeverity(ev),
      extractEventType(ev),
      extractActor(ev),
      extractOperation(ev),
    ];
    cells.forEach(function (text) {
      var td = document.createElement("td");
      td.textContent = text;
      tr.appendChild(td);
    });
    var tdv = document.createElement("td");
    var span = document.createElement("span");
    span.className = "verdict " + v.cls;
    span.textContent = v.label;
    tdv.appendChild(span);
    tr.appendChild(tdv);
    // Stash the event + the freeform-matcher field set on the row so
    // every filter can re-evaluate the already-rendered row live,
    // without re-fetching from the server (the bug this fixes: the old
    // code only changed what the NEXT poll fetched, leaving stale rows
    // on screen).
    tr._ev = ev;
    tr._fields = {
      time: cells[0], severity: cells[1], type: cells[2],
      actor: cells[3], op: cells[4], verdict: v.label
    };
    return tr;
  }

  function appendEvents(events) {
    if (!events.length) return;
    var empty = elBody.querySelector(".empty-row");
    if (empty) empty.remove();
    events.forEach(function (ev) {
      var id = eventId(ev);
      if (seenIds[id]) return;
      // ALL row-level filters are now client-side + live (see
      // applyClientFilters). We render every fetched row and let the
      // filter toggle its visibility, so broadening a filter reveals
      // rows that were already fetched instead of leaving stale ones.
      seenIds[id] = true;
      var tms = eventTimeMs(ev);
      if (tms > lastTimeMs) lastTimeMs = tms;
      var v = classifyVerdict(ev);
      bump(v.cls);
      elBody.appendChild(renderRow(ev));
    });
    // #425 / §A64: virtualized cap at MAX_ROWS (10K). FIFO eviction
    // so the operator sees the most recent slice without the page
    // crashing the browser on 100K+-event loads.
    while (elBody.children.length > MAX_ROWS) {
      elBody.removeChild(elBody.firstChild);
    }
    // Re-run the active filters over the (now larger) rendered set so
    // newly appended rows obey whatever filter is currently typed.
    applyClientFilters();
    window.scrollTo(0, document.body.scrollHeight);
  }

  function compileRegex(raw) {
    if (!raw) return null;
    try { return new RegExp(raw); }
    catch (e) { return null; }
  }

  function extractResourceUid(ev) {
    var rs = ev && ev.resources;
    if (!rs || !rs.length) return "";
    var first = rs[0];
    if (first && typeof first === "object") {
      return String(first.uid || first.name || "");
    }
    return "";
  }

  function extractReason(ev) {
    var u = ev && ev.unmapped && ev.unmapped.iam_jit || {};
    if (u.reason) return String(u.reason);
    if (ev && ev.status_detail) return String(ev.status_detail);
    if (u.status_detail) return String(u.status_detail);
    return "";
  }

  function extractSessionId(ev) {
    var u = ev && ev.unmapped && ev.unmapped.iam_jit || {};
    if (u.agent && u.agent.session_id) return String(u.agent.session_id);
    if (u.session_id) return String(u.session_id);
    return "";
  }

  // passesAllFilters is the single client-side gate for one event. It
  // combines EVERY row-level control so the rendered table reacts to
  // every filter live, independent of the poll cursor:
  //   * freeform input  -> the shared auditFilterMatch grammar
  //   * session input    -> substring on agent.session_id
  //   * verdict toggle   -> allow / deny / both
  //   * action input     -> regex over operation OR first resource uid
  //   * reason input     -> regex over the decision reason
  // (Time-range stays a server-side FETCH WINDOW; see buildQueryParams.)
  function passesAllFilters(ev, fields) {
    fields = fields || {};
    // Freeform matcher (shared with the node-executed test).
    if (!auditFilterMatch(fields, (elFilter.value || ""))) return false;
    // Session id substring.
    var sess = (elFilterSession.value || "").trim();
    if (sess) {
      var sid = extractSessionId(ev);
      if (sid.toLowerCase().indexOf(sess.toLowerCase()) === -1) return false;
    }
    // Verdict toggle (allow / deny / both).
    if (verdictMode === "allow" || verdictMode === "deny") {
      var v = classifyVerdict(ev).cls;
      if (v !== verdictMode) return false;
    }
    // Action / resource regex over operation OR first resource uid.
    var actionRe = compileRegex((elFilterAction.value || "").trim());
    if (actionRe) {
      var op = extractOperation(ev);
      var resUid = extractResourceUid(ev);
      if (!actionRe.test(op) && !actionRe.test(resUid)) return false;
    }
    // Reason regex.
    var reasonRe = compileRegex((elFilterReason.value || "").trim());
    if (reasonRe) {
      if (!reasonRe.test(extractReason(ev))) return false;
    }
    return true;
  }

  // applyClientFilters iterates ALL rendered rows, toggles each row's
  // visibility through passesAllFilters, and updates the "shown"
  // counter. Filtering is purely client-side over the rendered set —
  // it never depends on the poll cursor, so changing any control
  // narrows/broadens the visible table immediately.
  function applyClientFilters() {
    var rows = elBody.children;
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var tr = rows[i];
      if (!tr._fields) { continue; } // empty / cleared placeholder row
      if (passesAllFilters(tr._ev, tr._fields)) {
        tr.style.display = "";
        shown += 1;
      } else {
        tr.style.display = "none";
      }
    }
    var anyFilter = !!(
      (elFilter.value || "").trim() ||
      (elFilterSession.value || "").trim() ||
      (elFilterAction.value || "").trim() ||
      (elFilterReason.value || "").trim() ||
      verdictMode
    );
    elFilter.classList.toggle("active", !!(elFilter.value || "").trim());
    if (elCountShown) elCountShown.textContent = String(anyFilter ? shown : rows.length);
  }

  function parseNdjson(text) {
    var out = [];
    if (!text) return out;
    var lines = text.split(/\\r?\\n/);
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i].trim();
      if (!ln) continue;
      try { out.push(JSON.parse(ln)); }
      catch (e) { /* skip malformed */ }
    }
    return out;
  }

  function computeRangeSinceIso() {
    if (rangeMode === "all") return null;
    if (rangeMode === "custom") return rangeCustomIso;
    var ms = parseRangeMs(rangeMode);
    if (!ms) return null;
    return new Date(Date.now() - ms).toISOString();
  }

  function parseRangeMs(raw) {
    var m = /^(\\d+)([smhd])$/.exec(raw);
    if (!m) return 0;
    var n = parseInt(m[1], 10);
    var unit = m[2];
    if (unit === "s") return n * 1000;
    if (unit === "m") return n * 60 * 1000;
    if (unit === "h") return n * 60 * 60 * 1000;
    if (unit === "d") return n * 24 * 60 * 60 * 1000;
    return 0;
  }

  function buildQueryParams(opts) {
    // Shared server-side parameter builder for poll + export. opts:
    //   { limit, format, livePoll, serverFilter }
    // livePoll=true uses the polling cursor (since=<lastTimeMs+1>);
    // livePoll=false uses the range-window since.
    //
    // serverFilter splits the two callers apart and is the heart of
    // this fix. The LIVE POLL (serverFilter=false) deliberately does
    // NOT push the row-level filters (freeform / session / verdict) to
    // the server: those are applied client-side by applyClientFilters
    // so broadening a filter immediately reveals already-fetched rows
    // instead of waiting for a re-fetch (the bug). EXPORT
    // (serverFilter=true) DOES push them so the downloaded file
    // matches the operator's filtered view. The time-range `since`
    // is the one legitimate fetch window and is sent for BOTH.
    var qs = [];
    qs.push("limit=" + (opts.limit || 200));
    if (opts.format) qs.push("format=" + encodeURIComponent(opts.format));
    if (opts.livePoll) {
      if (lastTimeMs) {
        qs.push("since=" + encodeURIComponent(new Date(lastTimeMs + 1).toISOString()));
      }
    } else {
      var rangeIso = computeRangeSinceIso();
      if (rangeIso) qs.push("since=" + encodeURIComponent(rangeIso));
    }
    if (opts.serverFilter) {
      // Server-side filter slot 1: the freeform input.
      var f = (elFilter.value || "").trim();
      if (f) qs.push("filter=" + encodeURIComponent(f));
      // Server-side filter slot 2: session id shortcut.
      var sess = (elFilterSession.value || "").trim();
      if (sess) {
        qs.push("filter=" + encodeURIComponent(
          "unmapped.iam_jit.agent.session_id=" + sess,
        ));
      }
      // Server-side filter slot 3: verdict.
      if (verdictMode === "allow") {
        qs.push("filter=" + encodeURIComponent("verdict=ALLOW"));
      } else if (verdictMode === "deny") {
        qs.push("filter=" + encodeURIComponent("verdict=DENY"));
      }
    }
    return qs.join("&");
  }

  function buildUrl() {
    // Live poll: time-range fetch window only. The row-level filters
    // (freeform / session / verdict) are applied client-side, never
    // pushed to the server, so they re-filter rendered rows live.
    return "/audit/events?" + buildQueryParams({
      limit: 200,
      livePoll: true,
      serverFilter: false,
    });
  }

  function poll() {
    if (paused) { schedulePoll(); return; }
    var req = new XMLHttpRequest();
    req.open("GET", buildUrl(), true);
    req.setRequestHeader("Accept", "application/x-ndjson");
    if (token) req.setRequestHeader("Authorization", "Bearer " + token);
    req.timeout = 10000;
    req.onload = function () {
      if (req.status === 200) {
        setDot("ok");
        setErr("");
        appendEvents(parseNdjson(req.responseText));
      } else if (req.status === 401 || req.status === 403) {
        setDot("err");
        setErr("auth required - append #token=YOUR_TOKEN to the URL");
      } else {
        setDot("stale");
        setErr("/audit/events returned " + req.status);
      }
      schedulePoll();
    };
    req.onerror = function () {
      setDot("err");
      setErr("network error - bouncer unreachable");
      schedulePoll();
    };
    req.ontimeout = function () {
      setDot("stale");
      setErr("/audit/events poll timed out");
      schedulePoll();
    };
    req.send();
  }

  function schedulePoll() {
    if (pollHandle) clearTimeout(pollHandle);
    pollHandle = setTimeout(poll, POLL_MS);
  }

  elPause.addEventListener("click", function () {
    paused = !paused;
    elPause.classList.toggle("active", paused);
    elPause.textContent = paused ? "resume" : "pause";
  });
  elClear.addEventListener("click", function () {
    elBody.innerHTML = "";
    seenIds = Object.create(null);
    counts = { total: 0, allow: 0, deny: 0, admin: 0, heartbeat: 0 };
    elCountTotal.textContent = "0";
    if (elCountShown) elCountShown.textContent = "0";
    elCountAllow.textContent = "0";
    elCountDeny.textContent = "0";
    elCountAdmin.textContent = "0";
    elCountHeartbeat.textContent = "0";
    var tr = document.createElement("tr");
    tr.className = "empty-row";
    var td = document.createElement("td");
    td.colSpan = 6;
    td.className = "empty";
    td.textContent = "cleared - waiting for events\\u2026";
    tr.appendChild(td);
    elBody.appendChild(tr);
  });
  // Bind EVERY row-level filter to the LIVE input so it re-filters the
  // already-rendered rows immediately (no forced re-fetch). This is the
  // fix: the old code only changed what the NEXT poll fetched, leaving
  // stale rows on screen.
  elFilter.addEventListener("input", applyClientFilters);

  function wireLiveFilter(el) {
    if (!el) return;
    el.addEventListener("input", applyClientFilters);
  }
  wireLiveFilter(elFilterSession);
  wireLiveFilter(elFilterAction);
  wireLiveFilter(elFilterReason);

  // Time-range buttons. Multi-selection guard: exactly one active.
  var rangeButtons = document.querySelectorAll(".range-btn[data-range]");
  function setActiveRange(mode) {
    rangeMode = mode;
    rangeButtons.forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-range") === mode);
    });
    // Reset the polling cursor so the new window's existing events
    // are pulled on the next tick (otherwise since=<recent> would
    // silently exclude everything older than the polling cursor).
    lastTimeMs = 0;
    seenIds = Object.create(null);
    elBody.innerHTML = "";
    counts = { total: 0, allow: 0, deny: 0, admin: 0, heartbeat: 0 };
    elCountTotal.textContent = "0";
    if (elCountShown) elCountShown.textContent = "0";
    elCountAllow.textContent = "0";
    elCountDeny.textContent = "0";
    elCountAdmin.textContent = "0";
    elCountHeartbeat.textContent = "0";
    elRangeDisplay.textContent = mode === "all"
      ? "window: all events"
      : mode === "custom"
        ? "window: since " + (rangeCustomIso || "<not set>")
        : "window: last " + mode;
    poll();
  }
  rangeButtons.forEach(function (b) {
    b.addEventListener("click", function () {
      var mode = b.getAttribute("data-range");
      if (mode === "custom") return;  // handled by range-custom button
      setActiveRange(mode);
    });
  });
  var elRangeCustom = document.getElementById("range-custom");
  if (elRangeCustom) {
    elRangeCustom.addEventListener("click", function () {
      var raw = window.prompt(
        "Custom time window: enter an ISO 8601 / RFC 3339 lower bound\\n" +
        "(e.g. 2026-05-23T14:00:00Z) — events at or after this time will be shown.",
        ""
      );
      if (!raw) return;
      rangeCustomIso = raw.trim();
      rangeButtons.forEach(function (b) {
        b.classList.toggle("active", b.getAttribute("data-range") === "custom");
      });
      // range-custom isn't in the data-range buttons; toggle it explicitly.
      elRangeCustom.classList.add("active");
      setActiveRange("custom");
    });
  }
  setActiveRange("all");

  // Verdict buttons.
  var verdictButtons = document.querySelectorAll(".verdict-btn[data-verdict]");
  verdictButtons.forEach(function (b) {
    b.addEventListener("click", function () {
      verdictMode = b.getAttribute("data-verdict") || "";
      verdictButtons.forEach(function (other) {
        other.classList.toggle("active", other === b);
      });
      // Verdict is now a live client-side filter, not a re-fetch.
      applyClientFilters();
    });
  });

  // Export buttons. Each triggers a one-shot fetch with the current
  // filter set + a download. CSV uses the DEFAULT_CSV_COLUMNS PII
  // guard (no email/phone/credential/token in the default schema);
  // JSON + OCSF NDJSON are byte-identical to what `iam-jit audit
  // query --format jsonl` would emit so SIEM ingest is the same.
  function doExport(format, suggestedFilename, mime) {
    var url = "/audit/events?" + buildQueryParams({
      limit: EXPORT_LIMIT,
      format: format,
      livePoll: false,
      serverFilter: true,
    });
    var req = new XMLHttpRequest();
    req.open("GET", url, true);
    req.responseType = "blob";
    if (token) req.setRequestHeader("Authorization", "Bearer " + token);
    req.timeout = 30000;
    req.onload = function () {
      if (req.status !== 200) {
        setErr("export failed: HTTP " + req.status);
        return;
      }
      var blob = req.response;
      // Force the desired MIME so the browser saves with the right
      // extension hint even when the server sent the same bytes
      // under a generic Content-Type.
      if (mime) {
        try { blob = new Blob([blob], { type: mime }); }
        catch (e) { /* ignore */ }
      }
      var downloadUrl = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = downloadUrl;
      a.download = suggestedFilename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(downloadUrl); }, 1000);
    };
    req.onerror = function () { setErr("export failed: network error"); };
    req.ontimeout = function () { setErr("export failed: timed out"); };
    req.send();
  }
  if (elExportCsv) {
    elExportCsv.addEventListener("click", function () {
      doExport("csv", "audit-events.csv", "text/csv");
    });
  }
  if (elExportJson) {
    elExportJson.addEventListener("click", function () {
      doExport("jsonl", "audit-events.json", "application/json");
    });
  }
  if (elExportOcsf) {
    elExportOcsf.addEventListener("click", function () {
      doExport("jsonl", "audit-events.ocsf.ndjson", "application/x-ndjson");
    });
  }

  poll();
})();
</script>
</body>
</html>
"""


def _looks_like_browser_visit(request) -> bool:
    """Return True when the request shape matches a browser visiting
    the UI, i.e. ``Accept: text/html`` is present.

    The proxy and the audit-stream UI share GET / on a single port
    (per the #272 design comment that originally assumed a dedicated
    mgmt port). AWS S3 ListBuckets + several other root-level AWS
    operations also hit GET /, and so do unclassifiable inbound
    requests the cooperative-mode proxy needs to 400 on. Serving HTML
    to either of those cases is wrong, so we narrow "render the UI"
    to requests that explicitly advertise an HTML preference. SDK
    clients send ``Accept: */*``; browsers send
    ``Accept: text/html,application/xhtml+xml,...``. The check is
    case-insensitive substring on the Accept header.
    """
    accept = request.headers.get("Accept", "") or request.headers.get("accept", "")
    return "text/html" in accept.lower()


def register_audit_events_ui_route(
    app,
    *,
    bouncer_name: str = BOUNCER_NAME,
    require_bearer: str | None = None,
    proxy_fallback=None,
) -> None:
    """Register GET / on the aiohttp app to serve the audit-stream UI.

    The HTML itself is the same whether or not auth is required —
    the page contains NO embedded token (per the no-secret-shape
    constraint); operators in external-bind mode pass the token via
    ``#token=...`` URL fragment which the page extracts client-side.

    ``require_bearer`` is the same token the events_endpoint enforces;
    we accept the same Bearer header (or a ``?token=`` query param) on
    the HTML page itself when set so an operator who visits without a
    token doesn't get an empty / confusing page. The HTML body never
    contains the token regardless.

    ``proxy_fallback`` is the AWS-proxy handler used when an AWS SDK
    request arrives at GET / (e.g. S3 ListBuckets). The UI route is
    registered ahead of the catch-all "/{tail:.*}" handler so the
    proxy can never see those requests via normal routing; this
    callable is the explicit hand-off path. Passing ``None`` (the
    default) preserves the original UI-only behaviour for callers
    outside the bouncer ``serve()`` lifecycle (the cross-bouncer
    parity ports + standalone unit tests of the UI itself).
    """
    try:
        from aiohttp import web
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "aiohttp is required for the / audit-stream UI",
        ) from e

    body = render_audit_events_ui(bouncer_name=bouncer_name)

    async def handler(request):
        # Non-browser requests at GET / (S3 ListBuckets, unclassifiable
        # proxy traffic, opaque SDK calls) must reach the proxy
        # handler — not the operator UI. We narrow the UI to requests
        # that explicitly advertise ``Accept: text/html`` so browser
        # visits keep landing on the page while anything else flows to
        # the proxy verdict path. Per [[creates-never-mutates]] the
        # delegation is one-way (UI never mutates proxy state); per
        # [[scorer-is-ground-truth]] the delegated request retains
        # its full verdict path.
        if proxy_fallback is not None and not _looks_like_browser_visit(request):
            return await proxy_fallback(request)
        if request.method != "GET":
            return web.json_response(
                {"error": "only GET is supported"}, status=405,
            )
        if require_bearer:
            ah = request.headers.get("Authorization", "")
            tok_q = request.query.get("token", "")
            ok = False
            if ah:
                parts = ah.split(None, 1)
                if len(parts) == 2 and parts[0].lower() == "bearer":
                    ok = parts[1].strip() == require_bearer
            if not ok and tok_q:
                ok = tok_q == require_bearer
            # When external-bound we STILL serve the HTML to a
            # browser visit without a token so the operator sees the
            # "auth required - append #token=..." banner the JS
            # renders; the page itself is harmless and contains no
            # secret shape. Refuse only if a wrong Bearer header was
            # supplied — that's a programmatic call deserving 403.
            if ah and not ok:
                return web.json_response(
                    {"error": "bearer token rejected"}, status=403,
                )
        return web.Response(
            body=body,
            status=200,
            content_type="text/html",
            charset="utf-8",
            headers={
                # Defence-in-depth: a strict CSP that allows our own
                # inline script + inline style but blocks any
                # external fetch. The UI never touches anything
                # outside the same origin.
                "Content-Security-Policy": (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data:; "
                    "connect-src 'self'; "
                    "frame-ancestors 'none'; "
                    "base-uri 'none'; "
                    "form-action 'none'"
                ),
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            },
        )

    app.router.add_route("GET", "/", handler)
