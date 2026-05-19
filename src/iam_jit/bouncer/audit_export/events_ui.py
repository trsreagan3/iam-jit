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
"violation" / "infraction" / "unauthorized".
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


def render_audit_events_ui(*, bouncer_name: str = BOUNCER_NAME) -> str:
    """Return the rendered HTML page for GET /.

    ``bouncer_name`` is HTML-escaped before substitution so an
    operator who runs ibounce under an exotic instance name can't
    inject script via the rendered title.
    """
    safe = _html.escape(bouncer_name)
    return _TEMPLATE.replace("{{BOUNCER_NAME}}", safe)


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
    <span>total <b id="count-total">0</b></span>
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
  var POLL_MS = 2000;
  var MAX_ROWS = 500;
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
  var elCountAllow = document.getElementById("count-allow");
  var elCountDeny = document.getElementById("count-deny");
  var elCountAdmin = document.getElementById("count-admin");
  var elCountHeartbeat = document.getElementById("count-heartbeat");

  var counts = { total: 0, allow: 0, deny: 0, admin: 0, heartbeat: 0 };
  var seenIds = Object.create(null);
  var paused = false;
  var lastTimeMs = 0;
  var pollHandle = null;

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
    return tr;
  }

  function appendEvents(events) {
    if (!events.length) return;
    var empty = elBody.querySelector(".empty-row");
    if (empty) empty.remove();
    events.forEach(function (ev) {
      var id = eventId(ev);
      if (seenIds[id]) return;
      seenIds[id] = true;
      var tms = eventTimeMs(ev);
      if (tms > lastTimeMs) lastTimeMs = tms;
      var v = classifyVerdict(ev);
      bump(v.cls);
      elBody.appendChild(renderRow(ev));
    });
    // Cap row count to keep the page snappy.
    while (elBody.children.length > MAX_ROWS) {
      elBody.removeChild(elBody.firstChild);
    }
    window.scrollTo(0, document.body.scrollHeight);
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

  function buildUrl() {
    var qs = ["limit=200"];
    if (lastTimeMs) {
      qs.push("since=" + encodeURIComponent(new Date(lastTimeMs + 1).toISOString()));
    }
    var f = (elFilter.value || "").trim();
    if (f) qs.push("filter=" + encodeURIComponent(f));
    return "/audit/events?" + qs.join("&");
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
  elFilter.addEventListener("change", function () {
    // Force a re-fetch from the same since cursor; rows we already
    // rendered stay on screen, but new poll uses the new filter.
    poll();
  });

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
