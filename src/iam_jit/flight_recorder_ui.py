# #723 / BUILD-2 — scrubbable replay UI for the agent flight recorder.
"""A single self-contained HTML+CSS+JS page (no build step, no external
CDN, no Google Fonts, no analytics) served on iam-jit's web surface at
``GET /flight-recorder``. It loads the cross-bouncer timeline JSON from
``GET /flight-recorder/timeline?session=SID`` and lets the operator
SCRUB (a range slider + step controls) through the agent's session,
Wireshark-style: each step shows action / decision (allow/deny) /
reason / IAM context / status / which bouncer+protocol / timestamp.

Pattern + honesty bar follow the existing bouncer monitoring UI
(:mod:`iam_jit.bouncer.audit_export.events_ui`):

* The scrub/step/render logic lives in one extractable JS constant
  (:data:`_TIMELINE_RENDER_JS`) substituted into the page AND executed
  verbatim by the node-driven test in
  ``tests/test_flight_recorder_ui.py`` — so the scrub logic can never
  silently rot behind string-only HTML assertions (the filter-bug
  lesson).
* Read-only viewer (per [[creates-never-mutates]]): NO POST / PUT /
  DELETE, no mutating controls. Just a slider, step buttons, and a
  detail pane.
* Strict CSP, zero external deps (per [[self-host-zero-billing-
  dependency]]).
* Honesty (per [[ibounce-honest-positioning]] + [[gbounce-ui-purpose-
  driven]]): the page renders the timeline's ``coverage`` block as a
  prominent banner — unreachable bouncers, partial-coverage warning,
  and gaps are shown UP FRONT so the operator never mistakes the
  replay for a complete record of the session.
* Safety-not-surveillance language: "allow" / "deny" / "policy
  mismatch", never "violation" / "infraction" / "unauthorized".
"""

from __future__ import annotations

import html as _html


# _TIMELINE_RENDER_JS is the single source of truth for the core
# scrub/step/render-view logic. It is injected into the page (replacing
# the ``{{RENDER_JS}}`` token) AND executed verbatim by the node-driven
# test, so the view a given step produces is asserted behaviourally, not
# just string-matched.
#
# It exposes three pure functions (no DOM, no fetch) the test drives:
#   * clampStep(idx, count)            -> a valid 0-based step index
#   * stepView(timeline, idx)          -> the per-step detail object the
#                                          UI renders for step `idx`
#   * coverageSummary(timeline)        -> the honesty banner model
# The DOM-binding code below calls these; the test calls them directly.
_TIMELINE_RENDER_JS = r"""
  function clampStep(idx, count) {
    // Keep the scrubber within [0, count-1]; empty timeline -> -1.
    if (!count || count < 1) { return -1; }
    var n = parseInt(idx, 10);
    if (isNaN(n)) { return 0; }
    if (n < 0) { return 0; }
    if (n > count - 1) { return count - 1; }
    return n;
  }

  function decisionLabel(decision) {
    var d = (decision == null ? "" : String(decision)).toLowerCase();
    if (d === "allow") { return { label: "ALLOW", cls: "allow" }; }
    if (d === "deny") { return { label: "DENY", cls: "deny" }; }
    return { label: "UNKNOWN", cls: "unknown" };
  }

  function stepView(timeline, idx) {
    // Build the per-step detail view the UI shows for step `idx`.
    // Returns a fixed-shape object (closed field set) — no raw event
    // body, so nothing exotic can leak into the rendered pane.
    var steps = (timeline && timeline.steps) || [];
    var i = clampStep(idx, steps.length);
    if (i < 0) {
      return {
        empty: true,
        position: "0 / 0",
        action: "(no steps)",
        decision: decisionLabel(null),
        protocol: "-", bouncer: "-", time: "-", status: "-",
        reason: "", iamContext: "", resources: []
      };
    }
    var s = steps[i] || {};
    return {
      empty: false,
      index: i,
      position: (i + 1) + " / " + steps.length,
      action: s.action || "(unknown action)",
      decision: decisionLabel(s.decision),
      protocol: s.protocol || "-",
      bouncer: s.bouncer || "-",
      time: s.time || (s.has_timestamp === false ? "(no timestamp)" : "-"),
      status: s.status || "-",
      reason: s.reason || "",
      iamContext: s.iam_context || "",
      resources: Array.isArray(s.resources) ? s.resources : []
    };
  }

  function coverageSummary(timeline) {
    // The honesty banner model. Surfaces partial coverage + every gap
    // so the operator can't mistake the replay for a complete record.
    var cov = (timeline && timeline.coverage) || {};
    var meta = (timeline && timeline.meta) || {};
    var unreachable = cov.bouncers_unreachable || [];
    return {
      partial: !!cov.partial,
      probed: cov.bouncers_probed || [],
      contributing: cov.bouncers_contributing || [],
      unreachable: unreachable,
      gaps: cov.gaps || [],
      protocols: meta.protocols_represented || [],
      stepCount: (timeline && timeline.step_count) || 0,
      // The headline honesty string the banner renders.
      headline: (!!cov.partial)
        ? ("PARTIAL TIMELINE — " + unreachable.length +
           " bouncer(s) unreachable; this is NOT the complete session")
        : ("complete probe — all " + (cov.bouncers_probed || []).length +
           " probed bouncer(s) answered")
    };
  }
"""


def render_flight_recorder_ui() -> str:
    """Return the rendered HTML page for ``GET /flight-recorder``.

    The trusted ``{{RENDER_JS}}`` block is substituted with
    :data:`_TIMELINE_RENDER_JS`. The page contains NO secrets and NO
    session id — the operator supplies the session id in the page's
    input box (or via the ``?session=`` query the page reads from
    ``window.location``)."""
    return _TEMPLATE.replace("{{RENDER_JS}}", _TIMELINE_RENDER_JS)


# Inline single-constant template — zero on-disk / CDN dependencies.
_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>iam-jit flight recorder - session replay</title>
<style>
:root {
  --bg: #0d1117; --panel: #161b22; --line: #30363d; --text: #c9d1d9;
  --muted: #8b949e; --allow: #2ea043; --deny: #f85149; --accent: #f0883e;
  --warn: #d29922;
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0; background: var(--bg); color: var(--text);
  font: 13px/1.45 ui-monospace, SFMono-Regular, "SF Mono", Menlo,
        Consolas, "Liberation Mono", monospace;
}
header {
  display: flex; flex-wrap: wrap; gap: 12px 18px; align-items: center;
  padding: 10px 14px; background: var(--panel);
  border-bottom: 1px solid var(--line); position: sticky; top: 0; z-index: 10;
}
header .brand { font-weight: 700; font-size: 15px; letter-spacing: 0.3px; }
header input[type="text"] {
  background: var(--bg); color: var(--text); border: 1px solid var(--line);
  border-radius: 4px; padding: 5px 8px; font: inherit; width: 320px;
}
header input[type="text"]::placeholder { color: var(--muted); }
header button {
  background: var(--bg); color: var(--text); border: 1px solid var(--line);
  border-radius: 4px; padding: 5px 10px; font: inherit; cursor: pointer;
}
header button:hover { border-color: var(--accent); }
.coverage {
  padding: 8px 14px; background: var(--panel);
  border-bottom: 1px solid var(--line); font-size: 12px; color: var(--muted);
}
.coverage.partial { background: rgba(210, 153, 34, 0.10); color: var(--warn); }
.coverage b { color: var(--text); }
.coverage .gaps { margin: 6px 0 0; padding-left: 18px; }
.coverage .gaps li { color: var(--warn); }
.scrubber {
  padding: 12px 14px; background: var(--panel);
  border-bottom: 1px solid var(--line); display: flex; gap: 12px;
  align-items: center; flex-wrap: wrap;
}
.scrubber input[type="range"] { flex: 1 1 320px; min-width: 240px; }
.scrubber .pos { color: var(--muted); min-width: 90px; text-align: right; }
.detail { padding: 16px 14px; }
.detail .row { display: flex; gap: 10px; padding: 5px 0;
  border-bottom: 1px solid #1d232b; }
.detail .row .k { width: 130px; color: var(--muted);
  text-transform: uppercase; font-size: 11px; letter-spacing: 0.4px; }
.detail .row .v { flex: 1; word-break: break-word; }
.decision {
  display: inline-block; padding: 1px 8px; border-radius: 3px;
  font-weight: 700; font-size: 11px; letter-spacing: 0.5px;
  border: 1px solid transparent;
}
.decision.allow { color: var(--allow); border-color: var(--allow); }
.decision.deny { color: var(--deny); border-color: var(--deny); }
.decision.unknown { color: var(--muted); border-color: var(--muted); }
.proto-badge {
  display: inline-block; padding: 1px 7px; border-radius: 3px;
  border: 1px solid var(--accent); color: var(--accent); font-size: 11px;
}
.err-banner {
  padding: 8px 14px; background: rgba(248, 81, 73, 0.12);
  border-bottom: 1px solid var(--deny); color: var(--deny); font-size: 12px;
}
.err-banner:empty { display: none; }
.empty { padding: 40px 20px; text-align: center; color: var(--muted); }
footer {
  padding: 8px 14px; color: var(--muted); font-size: 11px;
  border-top: 1px solid var(--line); text-align: center;
}
</style>
</head>
<body>
<header>
  <div class="brand">iam-jit flight recorder <span style="color: var(--muted); font-weight: 400;">- session replay</span></div>
  <input type="text" id="session-input" placeholder="agent session id (e.g. 019687ef-...)">
  <button type="button" id="load-btn">load timeline</button>
  <span id="status" style="color: var(--muted);"></span>
</header>
<div class="err-banner" id="err-banner"></div>
<div class="coverage" id="coverage"></div>
<div class="scrubber">
  <button type="button" id="prev-btn">&#9664; prev</button>
  <input type="range" id="scrub" min="0" max="0" value="0" step="1" disabled>
  <button type="button" id="next-btn">next &#9654;</button>
  <span class="pos" id="pos">0 / 0</span>
</div>
<main>
<div class="detail" id="detail">
  <div class="empty" id="detail-empty">enter a session id and load a timeline to begin&hellip;</div>
  <div id="detail-rows" style="display:none;">
    <div class="row"><div class="k">action</div><div class="v" id="d-action">-</div></div>
    <div class="row"><div class="k">decision</div><div class="v"><span class="decision" id="d-decision">-</span></div></div>
    <div class="row"><div class="k">protocol</div><div class="v"><span class="proto-badge" id="d-protocol">-</span> <span id="d-bouncer" style="color: var(--muted);"></span></div></div>
    <div class="row"><div class="k">timestamp</div><div class="v" id="d-time">-</div></div>
    <div class="row"><div class="k">status</div><div class="v" id="d-status">-</div></div>
    <div class="row"><div class="k">reason</div><div class="v" id="d-reason">-</div></div>
    <div class="row"><div class="k">iam context</div><div class="v" id="d-iam">-</div></div>
    <div class="row"><div class="k">resources</div><div class="v" id="d-resources">-</div></div>
  </div>
</div>
</main>
<footer>read-only viewer - <a href="/healthz" style="color: var(--muted);">/healthz</a> | timeline source: <a href="/flight-recorder/timeline" style="color: var(--muted);">/flight-recorder/timeline</a></footer>
<script>
"use strict";
(function () {
{{RENDER_JS}}

  var elSession = document.getElementById("session-input");
  var elLoad = document.getElementById("load-btn");
  var elStatus = document.getElementById("status");
  var elErr = document.getElementById("err-banner");
  var elCoverage = document.getElementById("coverage");
  var elScrub = document.getElementById("scrub");
  var elPrev = document.getElementById("prev-btn");
  var elNext = document.getElementById("next-btn");
  var elPos = document.getElementById("pos");
  var elDetailEmpty = document.getElementById("detail-empty");
  var elDetailRows = document.getElementById("detail-rows");

  var timeline = null;
  var current = 0;

  function setErr(msg) { elErr.textContent = msg || ""; }

  function setText(id, text) {
    var el = document.getElementById(id);
    if (el) { el.textContent = text == null ? "" : String(text); }
  }

  function renderCoverage() {
    if (!timeline) { elCoverage.textContent = ""; return; }
    var cov = coverageSummary(timeline);
    elCoverage.classList.toggle("partial", cov.partial);
    var parts = [];
    parts.push("<b>" + escapeHtml(cov.headline) + "</b>");
    parts.push("probed: " + escapeHtml((cov.probed || []).join(", ") || "(none)"));
    parts.push("contributing: " + escapeHtml((cov.contributing || []).join(", ") || "(none)"));
    parts.push("protocols: " + escapeHtml((cov.protocols || []).join(", ") || "(none)"));
    parts.push("steps: " + escapeHtml(String(cov.stepCount)));
    var html = parts.join(" &nbsp;|&nbsp; ");
    if (cov.gaps && cov.gaps.length) {
      html += "<ul class=\"gaps\">";
      for (var i = 0; i < cov.gaps.length; i++) {
        html += "<li>" + escapeHtml(cov.gaps[i]) + "</li>";
      }
      html += "</ul>";
    }
    elCoverage.innerHTML = html;
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function renderStep() {
    if (!timeline || !(timeline.steps || []).length) {
      elDetailEmpty.style.display = "";
      elDetailRows.style.display = "none";
      elPos.textContent = "0 / 0";
      return;
    }
    var view = stepView(timeline, current);
    elDetailEmpty.style.display = "none";
    elDetailRows.style.display = "";
    elPos.textContent = view.position;
    setText("d-action", view.action);
    var dEl = document.getElementById("d-decision");
    dEl.textContent = view.decision.label;
    dEl.className = "decision " + view.decision.cls;
    setText("d-protocol", view.protocol);
    setText("d-bouncer", view.bouncer === "-" ? "" : "(" + view.bouncer + ")");
    setText("d-time", view.time);
    setText("d-status", view.status);
    setText("d-reason", view.reason || "(none)");
    setText("d-iam", view.iamContext || "(none)");
    setText("d-resources", (view.resources && view.resources.length)
      ? view.resources.join(", ") : "(none)");
  }

  function gotoStep(idx) {
    if (!timeline) { return; }
    var count = (timeline.steps || []).length;
    current = clampStep(idx, count);
    if (current < 0) { current = 0; }
    elScrub.value = String(current);
    renderStep();
  }

  function loadTimeline() {
    var sid = (elSession.value || "").trim();
    if (!sid) { setErr("enter a session id first"); return; }
    setErr("");
    elStatus.textContent = "loading\\u2026";
    var url = "/flight-recorder/timeline?session=" + encodeURIComponent(sid);
    var req = new XMLHttpRequest();
    req.open("GET", url, true);
    req.setRequestHeader("Accept", "application/json");
    req.timeout = 30000;
    req.onload = function () {
      if (req.status !== 200) {
        setErr("/flight-recorder/timeline returned " + req.status);
        elStatus.textContent = "";
        return;
      }
      try { timeline = JSON.parse(req.responseText); }
      catch (e) { setErr("could not parse timeline JSON"); elStatus.textContent = ""; return; }
      var count = (timeline.steps || []).length;
      elScrub.max = String(Math.max(0, count - 1));
      elScrub.disabled = count < 1;
      elStatus.textContent = count + " step(s)";
      current = 0;
      elScrub.value = "0";
      renderCoverage();
      renderStep();
    };
    req.onerror = function () { setErr("network error - iam-jit unreachable"); elStatus.textContent = ""; };
    req.ontimeout = function () { setErr("timeline request timed out"); elStatus.textContent = ""; };
    req.send();
  }

  elLoad.addEventListener("click", loadTimeline);
  elSession.addEventListener("keydown", function (e) {
    if (e.key === "Enter") { loadTimeline(); }
  });
  elScrub.addEventListener("input", function () { gotoStep(elScrub.value); });
  elPrev.addEventListener("click", function () { gotoStep(current - 1); });
  elNext.addEventListener("click", function () { gotoStep(current + 1); });

  // Auto-load when the page is opened with ?session=SID.
  (function () {
    try {
      var m = window.location.search.match(/[?&]session=([^&]+)/);
      if (m) {
        elSession.value = decodeURIComponent(m[1]);
        loadTimeline();
      }
    } catch (e) { /* ignore */ }
  })();
})();
</script>
</body>
</html>
"""
