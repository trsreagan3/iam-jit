# #723 / BUILD-2 — scrubbable replay UI tests for the flight recorder.
"""Two layers, mirroring the gbounce filter-fix reference (the
filter-bug lesson — string-only HTML assertions let a dead filter ship
silently):

1. BEHAVIOURAL — the exact ``_TIMELINE_RENDER_JS`` source is executed
   under ``node`` and its ``stepView`` / ``clampStep`` / ``coverageSummary``
   verdicts asserted. Skips cleanly when node is absent.
2. CONTRACT / STRUCTURAL — the rendered page is self-contained (no
   external deps), CSP-strict, read-only (no mutating controls), the
   render token is substituted, and the route serves the page +
   timeline JSON.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from iam_jit.flight_recorder_ui import (
    _TIMELINE_RENDER_JS,
    render_flight_recorder_ui,
)


def _body() -> str:
    return render_flight_recorder_ui()


# --------------------------------------------------------------------------
# Structural / contract assertions
# --------------------------------------------------------------------------


def test_render_token_substituted():
    body = _body()
    assert "{{RENDER_JS}}" not in body
    assert "function stepView(" in body
    assert "function clampStep(" in body
    assert "function coverageSummary(" in body


def test_page_is_html_doctype():
    assert _body().lstrip().lower().startswith("<!doctype html>")


def test_loads_timeline_endpoint():
    body = _body()
    assert "/flight-recorder/timeline?session=" in body


def test_has_scrub_controls():
    body = _body()
    assert 'id="scrub"' in body
    assert 'type="range"' in body
    assert 'id="prev-btn"' in body
    assert 'id="next-btn"' in body


def test_no_external_resources():
    """Per [[self-host-zero-billing-dependency]] — no CDN / fonts /
    analytics."""
    low = _body().lower()
    for needle in [
        "googleapis.com", "gstatic.com", "cloudflare", "cdn.",
        "googletagmanager", "google-analytics", "fonts.google",
        "//unpkg.com", "//cdnjs.", "//jsdelivr.", "http://", "https://",
    ]:
        assert needle not in low, f"external dependency leaked: {needle}"


def test_read_only_no_mutating_controls():
    """Per [[creates-never-mutates]] — viewer only. No POST/PUT/DELETE,
    no mutation-suggesting buttons."""
    low = _body().lower()
    for term in [
        "kill session", "revoke", "delete", "approve request",
        "deny request", "method=\"post\"", "method=\"put\"",
        "method=\"delete\"", "xmlhttprequest().open(\"post",
    ]:
        assert term not in low, f"mutating control leaked: {term}"
    # The single fetch uses GET.
    assert 'req.open("GET"' in _body()
    assert 'req.open("POST"' not in _body()


def test_safety_not_surveillance_language():
    low = _body().lower()
    for term in ["violation", "infraction", "unauthorized"]:
        if re.search(r"\b" + re.escape(term) + r"\b", low):
            pytest.fail(f"forbidden surveillance term in UI: {term}")


def test_no_embedded_session_or_secret():
    """The page is generic — no session id, no token baked in."""
    body = _body()
    # No hardcoded session-id-looking value or token shape.
    assert "AKIA" not in body
    assert "Bearer " not in body


def test_surfaces_coverage_honesty_block():
    body = _body()
    # The coverage banner + the honesty headline must be wired.
    assert 'id="coverage"' in body
    assert "coverageSummary" in body
    assert "PARTIAL TIMELINE" in body


def test_page_under_line_cap():
    n = len(_body().splitlines())
    assert n < 800, f"flight-recorder UI grew to {n} lines (cap 800)"


# --------------------------------------------------------------------------
# BEHAVIOURAL — execute the real render JS under node
# --------------------------------------------------------------------------


_HARNESS = r"""
%s
var input = "";
process.stdin.on("data", function (d) { input += d; });
process.stdin.on("end", function () {
  var payload = JSON.parse(input);
  var fn = payload.fn;
  var out;
  if (fn === "clampStep") {
    out = clampStep(payload.idx, payload.count);
  } else if (fn === "stepView") {
    out = stepView(payload.timeline, payload.idx);
  } else if (fn === "coverageSummary") {
    out = coverageSummary(payload.timeline);
  } else {
    out = {error: "unknown fn"};
  }
  process.stdout.write(JSON.stringify(out));
});
"""


def _run_js(fn: str, **kwargs):
    node = shutil.which("node")
    if node is None:  # pragma: no cover - only on node-less hosts
        pytest.skip("node not available to execute _TIMELINE_RENDER_JS")
    script = _HARNESS % _TIMELINE_RENDER_JS
    payload = {"fn": fn, **kwargs}
    proc = subprocess.run(
        [node, "-e", script],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 0, (
        f"node failed: rc={proc.returncode}\nstdout={proc.stdout!r}\n"
        f"stderr={proc.stderr!r}"
    )
    return json.loads(proc.stdout)


def _timeline():
    return {
        "schema": "flight-recorder/1",
        "session_id": "S1",
        "step_count": 3,
        "steps": [
            {
                "index": 0, "bouncer": "ibounce", "protocol": "AWS",
                "time": "2026-06-03T10:00:01Z", "action": "s3:GetObject",
                "decision": "deny", "reason": "not in granted policy",
                "resources": ["arn:aws:s3:::b/k"], "principal": "claude",
                "iam_context": "jit-readonly", "status": "Failure",
                "has_timestamp": True,
            },
            {
                "index": 1, "bouncer": "dbounce", "protocol": "SQL",
                "time": "2026-06-03T10:00:02Z", "action": "SELECT",
                "decision": "allow", "reason": None, "resources": [],
                "principal": "claude", "iam_context": None,
                "status": "Success", "has_timestamp": True,
            },
            {
                "index": 2, "bouncer": "gbounce", "protocol": "HTTP",
                "time": "2026-06-03T10:00:03Z", "action": "POST /v1/messages",
                "decision": "allow", "reason": None, "resources": [],
                "principal": "claude", "iam_context": None,
                "status": "Success", "has_timestamp": True,
            },
        ],
        "coverage": {
            "bouncers_probed": ["dbounce", "gbounce", "ibounce", "kbounce"],
            "bouncers_contributing": ["dbounce", "gbounce", "ibounce"],
            "bouncers_unreachable": [
                {"bouncer": "kbounce", "reason": "connection refused"}
            ],
            "partial": True,
            "gaps": ["kbounce unreachable (connection refused) — its slice "
                     "of the session is MISSING from this timeline"],
        },
        "meta": {"protocols_represented": ["AWS", "HTTP", "SQL"]},
    }


@pytest.mark.parametrize(
    ("idx", "count", "want"),
    [
        (0, 3, 0), (2, 3, 2), (5, 3, 2),   # clamp high
        (-1, 3, 0),                          # clamp low
        ("1", 3, 1),                         # string coerced
        ("x", 3, 0),                         # NaN -> 0
        (0, 0, -1),                          # empty timeline
    ],
)
def test_clamp_step_under_node(idx, count, want):
    got = _run_js("clampStep", idx=idx, count=count)
    assert got == want, f"clampStep({idx},{count}) = {got}; want {want}"


def test_step_view_renders_correct_step_under_node():
    tl = _timeline()
    v0 = _run_js("stepView", timeline=tl, idx=0)
    assert v0["action"] == "s3:GetObject"
    assert v0["decision"]["label"] == "DENY"
    assert v0["decision"]["cls"] == "deny"
    assert v0["protocol"] == "AWS"
    assert v0["bouncer"] == "ibounce"
    assert v0["reason"] == "not in granted policy"
    assert v0["iamContext"] == "jit-readonly"
    assert v0["status"] == "Failure"
    assert v0["resources"] == ["arn:aws:s3:::b/k"]
    assert v0["position"] == "1 / 3"

    v2 = _run_js("stepView", timeline=tl, idx=2)
    assert v2["action"] == "POST /v1/messages"
    assert v2["decision"]["label"] == "ALLOW"
    assert v2["protocol"] == "HTTP"
    assert v2["position"] == "3 / 3"


def test_step_view_scrub_past_end_clamps_under_node():
    # Scrubbing past the last step shows the last step (not a crash /
    # blank) — the scrub-bar end behaviour.
    v = _run_js("stepView", timeline=_timeline(), idx=99)
    assert v["position"] == "3 / 3"
    assert v["action"] == "POST /v1/messages"


def test_step_view_empty_timeline_under_node():
    empty = {"step_count": 0, "steps": [], "coverage": {}, "meta": {}}
    v = _run_js("stepView", timeline=empty, idx=0)
    assert v["empty"] is True
    assert v["position"] == "0 / 0"
    assert v["decision"]["cls"] == "unknown"


def test_coverage_summary_partial_headline_under_node():
    cov = _run_js("coverageSummary", timeline=_timeline())
    assert cov["partial"] is True
    assert "PARTIAL TIMELINE" in cov["headline"]
    assert cov["unreachable"][0]["bouncer"] == "kbounce"
    assert cov["protocols"] == ["AWS", "HTTP", "SQL"]
    assert cov["stepCount"] == 3
    assert len(cov["gaps"]) == 1


def test_coverage_summary_complete_headline_under_node():
    tl = _timeline()
    tl["coverage"]["partial"] = False
    tl["coverage"]["bouncers_unreachable"] = []
    tl["coverage"]["gaps"] = []
    cov = _run_js("coverageSummary", timeline=tl)
    assert cov["partial"] is False
    assert "complete probe" in cov["headline"]


def test_decision_unknown_renders_unknown_under_node():
    tl = _timeline()
    tl["steps"][0]["decision"] = "unknown"
    v = _run_js("stepView", timeline=tl, idx=0)
    assert v["decision"]["label"] == "UNKNOWN"
    assert v["decision"]["cls"] == "unknown"


# --------------------------------------------------------------------------
# Route serving (FastAPI TestClient)
# --------------------------------------------------------------------------


def _client():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from iam_jit.app import create_app

    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _admin_user():
    from iam_jit.users_store import User

    return User(id="u1", roles=("admin", "approver", "requester"), enabled=True)


def _requester_user():
    """A low-priv, NON-admin authenticated user — the IDOR threat
    actor. ``is_admin`` is False; ``require_admin`` must reject."""
    from iam_jit.users_store import User

    return User(id="u2", roles=("requester",), enabled=True)


def _override_identity(app, user):
    """Inject ``user`` as the authenticated identity by overriding the
    ``current_user`` SUB-dependency only. The REAL ``require_admin``
    still runs its ``is_admin`` role check against ``user`` — so a
    non-admin user genuinely produces the route's 403. (Overriding
    ``require_admin`` itself would bypass the very check under test.)"""
    from iam_jit import middleware as _mw

    app.dependency_overrides[_mw.current_user] = lambda: user
    return app


def _override_anon(app):
    """Simulate an unauthenticated request: ``current_user`` raises the
    real 401 it raises when no valid session cookie is present, so the
    require_admin-gated routes reject anon with 401."""
    from fastapi import HTTPException, status
    from iam_jit import middleware as _mw

    def _raise_401():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
        )

    app.dependency_overrides[_mw.current_user] = _raise_401
    return app


def test_route_serves_page_with_strict_csp():
    # Admin (passes require_admin) → page renders.
    client = _client()
    _override_identity(client.app, _admin_user())
    resp = client.get("/flight-recorder")
    assert resp.status_code == 200, resp.text
    assert resp.headers.get("content-type", "").startswith("text/html")
    body = resp.text
    assert body.lstrip().lower().startswith("<!doctype html>")
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "http://" not in csp and "https://" not in csp
    # The page's inline script needs script-src 'unsafe-inline'.
    assert "'unsafe-inline'" in csp


def test_route_anon_rejected():
    # IDOR closure: anonymous (no session) → 401 from current_user
    # under require_admin. No timeline page leaks.
    client = _client()
    _override_anon(client.app)
    resp = client.get("/flight-recorder", follow_redirects=False)
    assert resp.status_code == 401


def test_page_route_non_admin_requester_forbidden():
    # IDOR closure: a logged-in, low-priv requester must NOT be able to
    # load the cross-bouncer replay UI → 403 from the real require_admin.
    client = _client()
    _override_identity(client.app, _requester_user())
    resp = client.get("/flight-recorder")
    assert resp.status_code == 403, resp.text


def test_timeline_route_non_admin_requester_forbidden():
    # IDOR closure (PRIMARY): a logged-in, low-priv requester GETting an
    # arbitrary session's timeline must be rejected BEFORE any fan-out.
    # Session ids are not capability secrets — this is the cross-session
    # read the gate exists to stop. 403 from the real require_admin.
    client = _client()
    _override_identity(client.app, _requester_user())
    resp = client.get("/flight-recorder/timeline?session=victim-session")
    assert resp.status_code == 403, resp.text


def test_timeline_route_anon_rejected():
    # Anonymous timeline read → 401, no session leak.
    client = _client()
    _override_anon(client.app)
    resp = client.get("/flight-recorder/timeline?session=victim-session")
    assert resp.status_code == 401


def test_timeline_route_requires_session():
    client = _client()
    _override_identity(client.app, _admin_user())
    resp = client.get("/flight-recorder/timeline")
    assert resp.status_code == 400


def test_timeline_route_returns_timeline_json(monkeypatch):
    """The timeline route reuses the fan-out; stub it so the test runs
    without live bouncers + assert the assembled shape comes back."""
    from iam_jit import agent_diff as ad_mod

    def _fake_fanout(*, session_id, since=None, until=None,  # noqa: SD-2 stub mirrors the real fetch_session_events_via_fanout signature so the route's call site is exercised verbatim; the window args are intentionally unused by the canned response
                     audit_events_token=None, **kw):
        events = [{
            "_bouncer": "ibounce",
            "time": "2026-06-03T10:00:01Z",
            "api": {"operation": "s3:GetObject"},
            "unmapped": {"iam_jit": {"verdict": "deny",
                                     "agent": {"session_id": session_id}}},
        }]
        notes = {"ibounce": "", "kbounce": "connection refused",
                 "dbounce": "", "gbounce": ""}
        return events, notes

    monkeypatch.setattr(ad_mod, "fetch_session_events_via_fanout", _fake_fanout)
    client = _client()
    _override_identity(client.app, _admin_user())
    resp = client.get("/flight-recorder/timeline?session=S1")
    assert resp.status_code == 200, resp.text
    tl = resp.json()
    assert tl["session_id"] == "S1"
    assert tl["step_count"] == 1
    assert tl["steps"][0]["protocol"] == "AWS"
    assert tl["steps"][0]["decision"] == "deny"
    assert tl["coverage"]["partial"] is True
