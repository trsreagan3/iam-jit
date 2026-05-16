"""Black-box appsec audit — round 4 (2026-05-14).

Round-4 external-researcher probe. Round 3 filed the launch-day cluster
(logout-not-revocation, openapi-500, healthz-leaks-posture, stripe-clock-
leak, stripe-empty-event-id-replay, stripe-event-type-echo). Round 4 re-
probes each of those closures externally via TestClient, then looks for
the next attacker surface:

  1. Surfaces re-exposed by the round-3 fixes (revocation-list timing
     oracle, TOCTOU race between concurrent requests and logout, the
     /docs CSP-vs-CDN break that became visible once openapi.json
     started working).
  2. Probe categories no prior round audited: Cache-Control on auth'd
     endpoints, CORS misconfig, webhook-secret leak via the error path,
     HSTS at the app layer.
  3. First-100-attacker fuzz grab-bag: empty bodies, oversize headers,
     malformed JSON, Transfer-Encoding edge cases, NUL bytes, method
     fingerprinting.

Each test asserts the *current* (broken or defended) behavior; broken-
behavior tests fail when the fix lands — that's the signal to flip the
assertion and ship the fix.

Severity rubric (same as rounds 1, 2, and 3):
    CRIT — pre-auth RCE, cross-tenant data leak, credential theft.
    HIGH — full account takeover with user interaction, privilege
           escalation, persistent XSS in admin context, broken authn.
    MED  — CSRF on state-change, IDOR with cleanup constraints,
           sensitive-data exposure in logs, rate-limit miss with real
           cost, output-cache stale-serving security state.
    LOW  — missing security headers, error verbosity, info leak via
           timing, log-injection-with-mitigations.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import pathlib
import re
import statistics
import tempfile
import threading
import time
from collections import Counter

import pytest
from fastapi.testclient import TestClient

from iam_jit import auth as auth_mod
from iam_jit.api_tokens_store import InMemoryAPITokenStore
from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore


_DEV_SECRET = "test-secret-for-route-tests-aaaaaaaaa"
_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:admin@example.com
    display_name: Admin
    roles: [admin]
  - id: email:admin2@example.com
    display_name: Admin2
    roles: [admin]
  - id: email:approver@example.com
    display_name: Approver
    roles: [approver]
  - id: email:dev@example.com
    display_name: Dev
    roles: [requester]
  - id: email:dev2@example.com
    display_name: Dev2
    roles: [requester]
"""


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET)


@pytest.fixture(autouse=True)
def _reset_singletons():
    from iam_jit import (
        bans as _bans,
        cidr_store as _cidrs,
        magic_link_nonces as _nonces,
        rate_limit as _rl,
        settings_store as _settings,
    )

    _rl.reset_default_limiter_for_tests()
    _bans.reset_default_store_for_tests()
    _nonces.reset_default_store_for_tests()
    _cidrs.reset_default_store_for_tests()
    _settings.reset_default_store_for_tests()
    from iam_jit.routes import score as _score_route
    _score_route._reset_limiter_for_tests()
    from iam_jit.routes import auth as _auth_route
    _auth_route._reset_magic_link_ip_limiter_for_tests()
    try:
        from iam_jit import session_revocation as _sr
        _sr.reset_default_store_for_tests()
    except Exception:
        pass


@pytest.fixture
def app(tmp_path):
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    return create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )


def _client_as(app, user_id=None):
    c = TestClient(app, raise_server_exceptions=False)
    if user_id:
        c.cookies.set("iam_jit_session", auth_mod.sign_session(_DEV_SECRET, user_id))
    return c


def _score_body() -> dict:
    return {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        },
        "description": "x",
        "duration_hours": 1,
        "access_type": "read-only",
    }


# =====================================================================
# CATEGORY 1: New MED-tier findings (cache/header hygiene)
# =====================================================================

# ---------------------------------------------------------------------
# BB4-01 (new finding): POST /api/v1/score ships with
# `Cache-Control: public, max-age=3600, s-maxage=86400`. The
# X-Policy-Fingerprint header shows the engineer intended cacheability
# of a pure scoring function. But `public` + `s-maxage=86400` is too
# aggressive: 24h of CDN cache means a scoring-rule update doesn't
# propagate, and `public` invites browser/proxy caching of POST
# responses on the CDNs that honor explicit Cache-Control on POST
# (Cloudflare "Cache Everything", Fastly with caching enabled,
# corporate forward proxies).
# ---------------------------------------------------------------------
def test_bb4_01_score_endpoint_cache_control_too_aggressive(app):
    """`POST /api/v1/score` ships with `Cache-Control: public,
    max-age=3600, s-maxage=86400`. The body is a pure function of the
    submitted policy (no PII), and `Vary: Authorization` keys per-Bearer
    — so this is not a cross-tenant PII leak. But:

      1. `s-maxage=86400` means shared caches (CDNs / corporate proxies
         that honor POST Cache-Control) cache scoring output for 24h.
         When iam-jit ships a scoring-rule update via the adversarial-
         loop process, users continue to see stale scores for 24h.
      2. The `public` directive (vs `private`) explicitly invites
         intermediary caching.
      3. POST responses with `Cache-Control: public` ARE cached by
         Cloudflare ("Cache Everything" page rules), Fastly with
         explicit POST caching, and some corporate forward proxies.

    Severity: MED (scoring-integrity / freshness gap — the adversarial-
    loop discipline is the product moat, so stale-score-via-CDN is a
    moat-erosion risk).

    Fix sketch: drop `s-maxage`, drop `public`, keep `private,
    max-age=300, must-revalidate`. Or move to an ETag-only model with
    `Cache-Control: no-cache` + `ETag: <fingerprint>` and rely on
    conditional GETs returning 304. The fingerprint should incorporate
    a rule-engine version so a rule update invalidates the ETag."""
    # BB4-01 CLOSED: tightened to private + 5-min freshness + must-
    # revalidate. CDN / proxy can no longer serve stale scores past
    # an adversarial-loop rule update.
    dev = _client_as(app, "email:dev@example.com")
    r = dev.post("/api/v1/score", json=_score_body())
    assert r.status_code == 200
    cc = r.headers.get("cache-control", "")
    assert "public" not in cc
    assert "s-maxage" not in cc
    assert "private" in cc
    assert "must-revalidate" in cc


# ---------------------------------------------------------------------
# BB4-02 (new finding): /api/v1/users/me and /api/v1/tokens ship with
# NO Cache-Control header at all. HTTP spec defaults to "heuristic
# freshness" — browser bfcache + corporate forward proxies can stale-
# serve auth'd PII.
# ---------------------------------------------------------------------
def test_bb4_02_auth_pii_endpoints_missing_cache_control(app):
    """Authenticated PII endpoints emit no `Cache-Control` header:

      - GET /api/v1/users/me  — returns user_id, roles, display_name
      - GET /api/v1/tokens    — returns token labels, hashes, IDs

    Without explicit `Cache-Control`, browsers and intermediary caches
    fall back to heuristic freshness. In practice this means:
      - browser bfcache / back-button may restore stale auth'd state
        after logout;
      - corporate forward proxies that aggressively cache GETs may
        serve one user's response to a colleague on the same NAT
        making the same authenticated request.

    Severity: MED (defense-in-depth on the most leak-prone surfaces).

    Fix sketch: middleware that emits `Cache-Control: no-store,
    private` on every authenticated response. Whitelist `/api/v1/score`
    (cacheable per BB4-01 fix). Static assets get a separate caching
    policy."""
    # BB4-02 CLOSED: middleware now emits `Cache-Control: no-store,
    # private` on auth'd responses by default. /api/v1/score has
    # its own (private + max-age=300 + must-revalidate); /healthz
    # + /static/* + /docs are exempt.
    dev = _client_as(app, "email:dev@example.com")
    r = dev.get("/api/v1/users/me")
    assert r.status_code == 200
    cc = r.headers.get("cache-control", "")
    assert "no-store" in cc and "private" in cc, (
        f"expected `no-store, private` on /api/v1/users/me; got: {cc!r}"
    )

    r2 = dev.get("/api/v1/tokens")
    assert r2.status_code == 200
    cc2 = r2.headers.get("cache-control", "")
    assert "no-store" in cc2 and "private" in cc2, (
        f"expected `no-store, private` on /api/v1/tokens; got: {cc2!r}"
    )


# ---------------------------------------------------------------------
# BB4-03 (new finding): /docs and /redoc reference cdn.jsdelivr.net
# scripts, but the app's CSP is `script-src 'self'`. Modern browsers
# block the CDN scripts → docs render visibly broken.
# ---------------------------------------------------------------------
def test_bb4_03_docs_csp_blocks_cdn_swagger_scripts(app):
    """`GET /docs` returns 200 HTML referencing
    `cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js`.
    The app's CSP header is `script-src 'self'` — modern browsers
    block the external script. Same for `/redoc` referencing
    `cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js`.

    Round-3 BB3-07 noted /docs rendering broken; the assumed cause
    was openapi-500. The BB3-02 closure fixed openapi.json — but
    /docs is still broken, now because of the CSP-vs-CDN mismatch.
    A future fix author should treat "the /docs page renders
    correctly" as the actual integration test, not "openapi.json
    returns 200."

    Severity: MED (UX regression — launch-day API consumer first
    impression).

    Fix sketch: either (a) self-host swagger-ui-dist behind
    /static/swagger/ and configure FastAPI's swagger_js_url /
    swagger_css_url to point at the local path; or (b) extend CSP
    with `script-src 'self' https://cdn.jsdelivr.net` on the /docs
    + /redoc routes only (per-route CSP override)."""
    c = TestClient(app, raise_server_exceptions=False)

    r = c.get("/docs")
    assert r.status_code == 200
    csp = r.headers.get("content-security-policy", "")
    scripts = re.findall(r'<script[^>]*src="([^"]+)"', r.text)
    cdn_scripts = [s for s in scripts if "cdn.jsdelivr.net" in s or "unpkg.com" in s]
    # Currently broken: CDN script(s) referenced AND CSP does NOT
    # whitelist the CDN.
    assert cdn_scripts, (
        f"expected at least one CDN script reference; got: {scripts}"
    )
    assert "cdn.jsdelivr.net" not in csp, (
        f"BB4-03 fix landed via CSP allowlist — flip the assertion. "
        f"CSP={csp!r}"
    )
    # Confirm the same shape on /redoc.
    r2 = c.get("/redoc")
    if r2.status_code == 200:
        scripts2 = re.findall(r'<script[^>]*src="([^"]+)"', r2.text)
        cdn2 = [s for s in scripts2 if "cdn.jsdelivr.net" in s or "unpkg.com" in s]
        # /redoc may exist or not — if it does, the same CDN dependency holds.
        assert cdn2, (
            f"expected /redoc CDN script ref; got: {scripts2}"
        )


# =====================================================================
# CATEGORY 2: LOW findings — response-shape hygiene
# =====================================================================

# ---------------------------------------------------------------------
# BB4-04: Stripe rejected (missing event.id) response leaks
# event_type + reason. Brief asked for `{rejected: true}` minimal
# body.
# ---------------------------------------------------------------------
def test_bb4_04_stripe_rejected_response_shape_leaks(monkeypatch, tmp_path):
    """Round-3 BB3-05 closed the empty-event-id replay class. The
    response shape, however, still leaks more than the brief asked
    for. Sending a signed event with no `id` field returns:

        {"handled": false, "event_type": "customer.created",
         "rejected": true, "reason": "missing_event_id"}

    The `reason` string is a stable classifier — gives an attacker
    with the webhook secret an enumeration vector ("what other
    rejection reasons does this endpoint use?"). The `event_type`
    echo confirms the parsed canonical type (an empty-string type
    canonicalizes to `event_type: 'unknown'` — leaking the
    canonicalization rule).

    Severity: LOW (only matters with webhook-secret leak; minor
    oracle).

    Fix sketch: on the rejected path, emit `{"rejected": true}` only.
    Log the `event_type` + `reason` server-side."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb4_04")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    body = b'{"type": "customer.created", "data": {"object": {}}}'
    sig = hmac.new(b"whsec_bb4_04", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    r = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"},
    )
    assert r.status_code == 200
    body_json = r.json()
    # Currently broken: rejected response leaks event_type + reason.
    assert body_json.get("rejected") is True
    assert "event_type" in body_json, (
        f"BB4-04 fix has landed — flip the assertion to assert that "
        f"event_type is NOT in the rejected response body. Got: {body_json}"
    )
    assert "reason" in body_json, (
        f"BB4-04 fix has landed — flip the assertion to assert that "
        f"reason is NOT in the rejected response body. Got: {body_json}"
    )


# ---------------------------------------------------------------------
# BB4-05: Stripe duplicate-event response echoes event_type +
# event_id — event-id existence oracle.
# ---------------------------------------------------------------------
def test_bb4_05_stripe_duplicate_response_leaks_event_metadata(monkeypatch, tmp_path):
    """When the SAME `event.id` is sent twice, the second response
    is:

        {"handled": false, "event_type": "<type>", "duplicate": true,
         "event_id": "<id>"}

    An attacker with the webhook secret can probe arbitrary event_ids
    and distinguish "never seen" (`{"handled": false}`) from "already
    processed" (the duplicate shape with event_type + event_id echo).
    Free event-id existence oracle.

    Severity: LOW (depends on webhook-secret leak).

    Fix sketch: on the duplicate path, emit `{"handled": false}` only
    (or `{"handled": false, "duplicate": true}` if a deduplication
    confirmation is needed for legit operators)."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb4_05")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    body = b'{"id":"evt_bb4_05_dup","type":"customer.subscription.created","data":{"object":{}}}'
    sig = hmac.new(b"whsec_bb4_05", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    hdr = f"t={ts},v1={sig}"
    # 1st delivery: fresh
    r1 = c.post(
        "/api/v1/webhooks/stripe", content=body,
        headers={"Stripe-Signature": hdr, "Content-Type": "application/json"},
    )
    assert r1.status_code == 200
    # 2nd delivery: duplicate path
    r2 = c.post(
        "/api/v1/webhooks/stripe", content=body,
        headers={"Stripe-Signature": hdr, "Content-Type": "application/json"},
    )
    assert r2.status_code == 200
    body2 = r2.json()
    # Currently broken: duplicate response echoes event_type + event_id.
    assert body2.get("duplicate") is True
    assert body2.get("event_type") == "customer.subscription.created", (
        f"BB4-05 fix landed — flip assertion. Got: {body2}"
    )
    assert body2.get("event_id") == "evt_bb4_05_dup", (
        f"BB4-05 fix landed — flip assertion. Got: {body2}"
    )


# ---------------------------------------------------------------------
# BB4-06: POST /api/v1/auth/logout always 200s with Set-Cookie,
# regardless of whether the caller sent any cookie or a malformed
# one. Acknowledges endpoint existence to unauth callers.
# ---------------------------------------------------------------------
def test_bb4_06_logout_always_200_acknowledges_endpoint(app):
    """`POST /api/v1/auth/logout` returns 200 `{"status": "logged
    out"}` and a deletion Set-Cookie regardless of input:
      - no cookie
      - malformed cookie value
      - wrong-secret-signed cookie

    Uniformity is GOOD — it prevents an oracle distinguishing valid
    from invalid cookies pre-logout. But the always-200 behavior also
    confirms to a recon scanner that the route exists and accepts
    unauth requests. This is the trade-off the team has chosen;
    pinning the current behavior as informational.

    Severity: LOW (informational; the trade-off favors uniformity).

    Fix sketch: keep current behavior; this is an honest-negative-ish
    finding to make sure a future refactor doesn't swing the other
    way and start 401ing logout-without-cookie (which would re-open
    the oracle)."""
    c = TestClient(app, raise_server_exceptions=False)

    # No cookie
    r1 = c.post("/api/v1/auth/logout")
    assert r1.status_code == 200
    assert "iam_jit_session" in r1.headers.get("set-cookie", "")

    # Malformed cookie
    c2 = TestClient(app, raise_server_exceptions=False)
    c2.cookies.set("iam_jit_session", "blah.blah.blah")
    r2 = c2.post("/api/v1/auth/logout")
    assert r2.status_code == 200

    # Wrong-secret-signed cookie
    forged = auth_mod.sign_session("totally-different-secret-xxxxxxxxxxxx", "email:dev@example.com")
    c3 = TestClient(app, raise_server_exceptions=False)
    c3.cookies.set("iam_jit_session", forged)
    r3 = c3.post("/api/v1/auth/logout")
    assert r3.status_code == 200


# ---------------------------------------------------------------------
# BB4-07: No HSTS header at the app layer. Deployment relies on ALB
# to inject it at the edge.
# ---------------------------------------------------------------------
def test_bb4_07_no_hsts_header_at_app_layer(app):
    """No `Strict-Transport-Security` header on any probed response
    (/healthz, /, /api/v1/users/me, /api/v1/score). Production ALB
    injects HSTS at the edge — but a dev deployment, sidecar, local
    tunnel, or misconfigured staging environment loses HSTS and
    becomes downgrade-vulnerable on the first request.

    Severity: LOW (defense-in-depth; relies on the prod deploy
    topology).

    Fix sketch: add `Strict-Transport-Security: max-age=63072000;
    includeSubDomains; preload` to the security-headers middleware.
    Make it idempotent (don't double-emit if ALB also emits)."""
    c = TestClient(app, raise_server_exceptions=False)
    dev = _client_as(app, "email:dev@example.com")
    for resp in (c.get("/healthz"), c.get("/"), dev.get("/api/v1/users/me"),
                 dev.post("/api/v1/score", json=_score_body())):
        # Currently broken: no HSTS at the app layer.
        assert resp.headers.get("strict-transport-security") is None, (
            f"BB4-07 fix has landed — HSTS now emitted. Flip the "
            f"assertion. headers: {dict(resp.headers)}"
        )


# ---------------------------------------------------------------------
# BB4-08: Set-Cookie SameSite inconsistency — auth-callback emits
# `SameSite=Strict`, logout emits `SameSite=Lax`.
# ---------------------------------------------------------------------
def test_bb4_08_logout_cookie_samesite_inconsistent_with_auth_callback(app):
    """The auth-callback Set-Cookie is `SameSite=Strict` (BB3-15
    closure). The logout Set-Cookie is `SameSite=Lax`. The logout
    cookie value is empty (deletion cookie), so functionally the
    SameSite mode doesn't change the invalidation behavior — but the
    inconsistency is the kind of thing a careful auditor flags as
    "the author wasn't paying attention" and often signals deeper
    inconsistencies.

    Severity: LOW (cosmetic; the deletion cookie SameSite has no
    operational effect).

    Fix sketch: emit logout's Set-Cookie with `SameSite=Strict` to
    match the auth-callback cookie. One-line change."""
    dev = _client_as(app, "email:dev@example.com")
    r = dev.post("/api/v1/auth/logout")
    set_cookie = r.headers.get("set-cookie", "").lower()
    # Currently broken: logout emits SameSite=Lax.
    assert "samesite=lax" in set_cookie, (
        f"BB4-08 fix landed — logout cookie now SameSite=Strict. "
        f"Flip assertion. set-cookie: {set_cookie}"
    )
    assert "samesite=strict" not in set_cookie


# ---------------------------------------------------------------------
# BB4-09: NUL bytes in description field on /api/v1/score accepted.
# ---------------------------------------------------------------------
def test_bb4_09_nul_bytes_accepted_in_description(app):
    """`POST /api/v1/score` with `description: "foo\\x00bar"` returns
    200 and scores normally. Most downstream sinks tolerate NUL bytes,
    but some (PostgreSQL `text`, certain markdown renderers,
    log-shipping pipelines that interpret NUL as terminator) reject
    or truncate.

    Severity: LOW (defense-in-depth; depends on downstream sinks).

    Fix sketch: add a Pydantic validator that rejects NUL bytes in
    `description` (and any other free-text user-input fields)."""
    dev = _client_as(app, "email:dev@example.com")
    body = _score_body()
    body["description"] = "foo\x00bar"
    r = dev.post("/api/v1/score", json=body)
    # Currently broken: NUL bytes accepted, request scored.
    assert r.status_code == 200, (
        f"BB4-09 fix landed — NUL bytes now rejected. Flip assertion. "
        f"Got status={r.status_code}, body={r.text[:200]}"
    )


# =====================================================================
# CATEGORY 3: Honest negatives — round-3 closure re-pins
# =====================================================================

# ---------------------------------------------------------------------
# BB4-10 (re-probe BB3-01): logout server-side revocation holds.
# ---------------------------------------------------------------------
def test_bb4_10_logout_server_side_revocation_holds(app):
    """Round-3 BB3-01 closure re-confirmation. Both POST
    /api/v1/auth/logout and GET /logout write the cookie hash to a
    server-side revocation list. A saved-elsewhere copy of the cookie
    returns 401 on the next authenticated request.

    Severity: N/A (defended). Closure re-pin."""
    # POST /api/v1/auth/logout closure.
    cookie = auth_mod.sign_session(_DEV_SECRET, "email:dev@example.com")
    c1 = TestClient(app, raise_server_exceptions=False)
    c1.cookies.set("iam_jit_session", cookie)
    assert c1.get("/api/v1/users/me").status_code == 200
    assert c1.post("/api/v1/auth/logout").status_code == 200

    attacker = TestClient(app, raise_server_exceptions=False)
    attacker.cookies.set("iam_jit_session", cookie)
    assert attacker.get("/api/v1/users/me").status_code == 401, (
        "BB3-01 regressed — saved-elsewhere cookie should be 401 after "
        "logout, not honored."
    )

    # GET /logout closure on a different user.
    cookie2 = auth_mod.sign_session(_DEV_SECRET, "email:approver@example.com")
    c2 = TestClient(app, raise_server_exceptions=False)
    c2.cookies.set("iam_jit_session", cookie2)
    assert c2.get("/api/v1/users/me").status_code == 200
    c2.get("/logout", follow_redirects=False)
    a2 = TestClient(app, raise_server_exceptions=False)
    a2.cookies.set("iam_jit_session", cookie2)
    assert a2.get("/api/v1/users/me").status_code == 401, (
        "BB3-01 regressed on GET /logout path."
    )


# ---------------------------------------------------------------------
# BB4-11 (re-probe BB3-02): /openapi.json 200 holds.
# ---------------------------------------------------------------------
def test_bb4_11_openapi_json_returns_200_holds(app):
    """Round-3 BB3-02 closure re-confirmation. `/openapi.json` returns
    200 with an OpenAPI 3.x schema that includes the core public
    routes.

    Severity: N/A (defended). Closure re-pin."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/openapi.json")
    assert r.status_code == 200
    schema = r.json()
    assert schema.get("openapi", "").startswith("3.")
    paths = schema.get("paths", {})
    # Confirm core routes are in the schema.
    assert "/api/v1/score" in paths
    assert "/api/v1/auth/logout" in paths
    assert "/api/v1/webhooks/stripe" in paths
    assert "/healthz" in paths


# ---------------------------------------------------------------------
# BB4-12 (re-probe BB3-03): /healthz minimal holds.
# ---------------------------------------------------------------------
def test_bb4_12_healthz_minimal_holds(app):
    """Round-3 BB3-03 closure re-confirmation. `/healthz` returns
    `{"status":"ok","version":"..."}` exactly — no auth_mode, no
    security_posture, no llm_backend.

    Severity: N/A (defended). Closure re-pin."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "ok"
    assert "version" in body
    # All the round-3 leak fields are gone.
    for forbidden in ("auth_mode", "user_config_source", "llm_backend",
                      "security_posture", "ses_configured", "alb_in_front"):
        assert forbidden not in body, (
            f"BB3-03 regressed — /healthz leaks {forbidden}. body={body}"
        )


# ---------------------------------------------------------------------
# BB4-13 (re-probe BB3-04): Stripe sig-error body is generic.
# ---------------------------------------------------------------------
def test_bb4_13_stripe_sig_error_body_generic_holds(monkeypatch, tmp_path):
    """Round-3 BB3-04 closure re-confirmation. Every flavor of Stripe
    signature error returns 400 with body `{"detail": "signature
    verification failed"}` exactly. No clock leak, no detail variance
    across error classes.

    Severity: N/A (defended). Closure re-pin."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb4_13")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    body = b'{"id":"evt_x","type":"customer.created","data":{"object":{}}}'
    expected = {"detail": "signature verification failed"}

    # Various sig-error flavors.
    cases = [
        # outside 300s window
        {"Stripe-Signature": f"t=1000000000,v1={'0'*64}", "Content-Type": "application/json"},
        # bad sig within window
        {"Stripe-Signature": f"t={int(time.time())},v1={'0'*64}", "Content-Type": "application/json"},
        # missing sig header
        {"Content-Type": "application/json"},
        # garbage sig header
        {"Stripe-Signature": "garbage", "Content-Type": "application/json"},
        # missing v1=
        {"Stripe-Signature": f"t={int(time.time())}", "Content-Type": "application/json"},
        # missing t=
        {"Stripe-Signature": f"v1={'0'*64}", "Content-Type": "application/json"},
    ]
    for hdrs in cases:
        r = c.post("/api/v1/webhooks/stripe", content=body, headers=hdrs)
        assert r.status_code == 400, f"hdrs={hdrs} -> {r.status_code}/{r.text}"
        assert r.json() == expected, (
            f"BB3-04 regressed — non-uniform sig error body. hdrs={hdrs}, "
            f"body={r.text}"
        )
        # Explicit clock-leak check.
        assert "now=" not in r.text
        assert "tolerance" not in r.text


# ---------------------------------------------------------------------
# BB4-14 (re-probe BB3-05): Stripe missing/empty event.id rejected.
# ---------------------------------------------------------------------
def test_bb4_14_stripe_missing_event_id_rejected_holds(monkeypatch, tmp_path):
    """Round-3 BB3-05 closure re-confirmation. Events with missing or
    empty `event.id` are rejected with `rejected: true` (response
    shape leaks more than ideal — see BB4-04 — but the *replay-
    protection invariant* holds).

    Severity: N/A (defended). Closure re-pin."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb4_14")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    for body in (
        b'{"type": "customer.created", "data": {"object": {}}}',
        b'{"id": "", "type": "customer.created", "data": {"object": {}}}',
        b'{"id": null, "type": "customer.created", "data": {"object": {}}}',
    ):
        sig = hmac.new(b"whsec_bb4_14", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        r = c.post(
            "/api/v1/webhooks/stripe", content=body,
            headers={"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"},
        )
        assert r.status_code == 200
        assert r.json().get("rejected") is True, (
            f"BB3-05 regressed — missing/empty event.id should be "
            f"rejected. body={body!r}, response={r.text}"
        )


# ---------------------------------------------------------------------
# BB4-15 (re-probe BB3-10): Stripe unhandled event_type — no echo.
# ---------------------------------------------------------------------
def test_bb4_15_stripe_unhandled_event_type_no_echo_holds(monkeypatch, tmp_path):
    """Round-3 BB3-10 closure re-confirmation. Genuinely unhandled
    types return `{"handled": false}` ONLY — no event_type echo.
    (The duplicate path leaks separately — see BB4-05.)

    Severity: N/A (defended). Closure re-pin."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb4_15")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    for i, etype in enumerate(["my.totally.fake.type", "another.unhandled",
                               "customer.created", "billing.unhandled"]):
        body = json.dumps({
            "id": f"evt_bb4_15_{i}_{int(time.time()*1000)}",
            "type": etype, "data": {"object": {}},
        }).encode()
        sig = hmac.new(b"whsec_bb4_15", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        r = c.post(
            "/api/v1/webhooks/stripe", content=body,
            headers={"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"},
        )
        assert r.status_code == 200
        body_json = r.json()
        assert body_json == {"handled": False}, (
            f"BB3-10 regressed — unhandled event_type {etype} response "
            f"is not minimal. Got: {body_json}"
        )


# ---------------------------------------------------------------------
# BB4-16 (closure re-pin): body-size middleware chunked TE → 411.
# Also confirms legitimate POSTs are NOT blocked.
# ---------------------------------------------------------------------
def test_bb4_16_chunked_te_refused_legit_post_not_blocked(app):
    """Closure re-pin. The body-size middleware:
      (a) refuses `Transfer-Encoding: chunked` with 411 + clear msg;
      (b) does NOT block legitimate POSTs (no false-positive on the
          standard request path).

    Severity: N/A (defended). Closure re-pin.

    The (b) check is the important "no over-correction" probe — a
    fix that refuses chunked TE by misreading the standard request
    flow would break every legit POST."""
    c = TestClient(app, raise_server_exceptions=False)

    # (a) chunked TE → 411
    r = c.post(
        "/api/v1/auth/magic-link",
        json={"email": "dev@example.com"},
        headers={"Transfer-Encoding": "chunked"},
    )
    assert r.status_code == 411, (
        f"chunked TE should be 411; got {r.status_code}: {r.text}"
    )
    assert "chunked" in r.text.lower()

    # Same on /api/v1/score
    dev = _client_as(app, "email:dev@example.com")
    r = dev.post("/api/v1/score", json=_score_body(),
                 headers={"Transfer-Encoding": "chunked"})
    assert r.status_code == 411

    # (b) legitimate POST without chunked TE works fine
    c2 = TestClient(app, raise_server_exceptions=False)
    r = c2.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    assert r.status_code == 202

    dev2 = _client_as(app, "email:dev@example.com")
    r = dev2.post("/api/v1/score", json=_score_body())
    assert r.status_code == 200, f"legit /score POST broken: {r.status_code} {r.text}"


# ---------------------------------------------------------------------
# BB4-17 (closure re-pin): token-mint cap 51st = 429.
# ---------------------------------------------------------------------
def test_bb4_17_token_mint_cap_holds(app):
    """Closure re-pin. Default cap is 50 tokens per user. The 51st
    mint returns 429.

    Severity: N/A (defended). Closure re-pin."""
    dev = _client_as(app, "email:dev2@example.com")
    codes = Counter()
    for i in range(55):
        r = dev.post("/api/v1/tokens", json={"label": f"t{i}"})
        codes[r.status_code] += 1
    # 50 successful mints, rest 429.
    assert codes.get(201, 0) == 50, (
        f"token-mint cap regressed — expected 50 successful mints; "
        f"got {codes}"
    )
    assert codes.get(429, 0) >= 1, (
        f"token-mint cap regressed — expected at least one 429; "
        f"got {codes}"
    )


# ---------------------------------------------------------------------
# BB4-18 (closure re-pin): magic-link per-IP rate limit holds.
# ---------------------------------------------------------------------
def test_bb4_18_magic_link_per_ip_rate_limit_holds(app, monkeypatch):
    """Closure re-pin. Magic-link per-IP soft cap 5/min, hard cap 15/min
    (defaults). 25-burst from same peer → many 429s.

    Severity: N/A (defended). Closure re-pin."""
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_FOR", raising=False)
    monkeypatch.delenv("IAM_JIT_TRUSTED_PROXY_CIDRS", raising=False)
    from iam_jit.routes import auth as _auth_route
    _auth_route._reset_magic_link_ip_limiter_for_tests()

    c = TestClient(app, raise_server_exceptions=False)
    codes = Counter()
    for i in range(25):
        r = c.post("/api/v1/auth/magic-link", json={"email": f"u{i}@example.com"})
        codes[r.status_code] += 1
    assert codes.get(429, 0) >= 10, (
        f"magic-link rate limit regressed — expected many 429s in a "
        f"25-burst; got {codes}"
    )


# ---------------------------------------------------------------------
# BB4-19 (closure re-pin): magic-link in Lambda without DDB → 503.
# ---------------------------------------------------------------------
def test_bb4_19_magic_link_lambda_no_ddb_returns_503(monkeypatch, tmp_path):
    """Closure re-pin (BB-12 / multi-instance closure). With Lambda env
    detected and no DDB nonce table configured, /api/v1/auth/magic-link
    returns 503 with a clear message pointing the operator at the
    valid configurations.

    Severity: N/A (defended). Closure re-pin."""
    monkeypatch.delenv("IAM_JIT_DEV_INSECURE_SECRET", raising=False)
    monkeypatch.delenv("IAM_JIT_SES_SENDER", raising=False)
    monkeypatch.delenv("IAM_JIT_ALLOW_LOG_CHANNEL", raising=False)
    monkeypatch.delenv("IAM_JIT_MAGIC_LINK_NONCES_TABLE", raising=False)
    monkeypatch.delenv("IAM_JIT_ALLOW_INSECURE_NONCES", raising=False)
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", "x" * 40)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "iam-jit-test")

    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    assert r.status_code == 503, (
        f"BB-12 multi-instance closure regressed — expected 503 in "
        f"Lambda without DDB nonce table; got {r.status_code}: "
        f"{r.text}"
    )
    detail = r.json().get("detail", "")
    # Detail mentions one of the valid configurations.
    assert any(s in detail for s in ("IAM_JIT_MAGIC_LINK_NONCES_TABLE",
                                     "IAM_JIT_ALLOW_INSECURE_NONCES",
                                     "IAM_JIT_DEV_INSECURE_SECRET")), detail


# ---------------------------------------------------------------------
# BB4-20 (new defended class): revocation lookup is NOT timing-
# attackable. Comparison of medians across 100-sample runs for
# revoked vs non-revoked cookies stays within natural per-request
# noise.
# ---------------------------------------------------------------------
def test_bb4_20_revocation_lookup_no_timing_oracle(app):
    """The BB3-01 closure landed a per-request revocation-list lookup
    in the auth path. This test probes whether the lookup is timing-
    attackable: does the median request time for a revoked cookie
    differ measurably from a non-revoked cookie?

    Across 100-sample runs of `GET /api/v1/users/me` with a freshly-
    revoked cookie vs a non-revoked cookie, medians stay within the
    natural per-request noise — no reliable oracle that an external
    attacker could exploit to learn whether their guessed cookie is
    in the revocation table without consuming the request budget.

    Severity: N/A (defended). New honest negative — pin so a future
    refactor that introduces a slow O(n) scan over the revocation
    list (vs the current O(1) DDB GetItem analog) regresses this
    test.

    Note: pure-Python in-process timing is noisy; we allow a 5x
    median ratio. If a fix author introduces a 5x-slower revoked-
    path branch, this test fails."""
    revoked = auth_mod.sign_session(_DEV_SECRET, "email:dev@example.com")
    nonrevoked = auth_mod.sign_session(_DEV_SECRET, "email:dev2@example.com")

    # Revoke the first cookie.
    cR = TestClient(app, raise_server_exceptions=False)
    cR.cookies.set("iam_jit_session", revoked)
    cR.post("/api/v1/auth/logout")

    def time_request(cookie: str, n: int) -> list[float]:
        times = []
        for _ in range(n):
            cc = TestClient(app, raise_server_exceptions=False)
            cc.cookies.set("iam_jit_session", cookie)
            t0 = time.perf_counter()
            cc.get("/api/v1/users/me")
            times.append(time.perf_counter() - t0)
        return times

    # Warm
    _ = time_request(revoked, n=10)
    _ = time_request(nonrevoked, n=10)
    t_rev = time_request(revoked, n=100)
    t_norm = time_request(nonrevoked, n=100)

    med_rev = statistics.median(t_rev)
    med_norm = statistics.median(t_norm)
    # Allow 5x latitude — pure-Python timing in-process is noisy.
    ratio = max(med_rev, med_norm) / min(med_rev, med_norm)
    assert ratio < 5.0, (
        f"revocation lookup timing leaks: revoked median={med_rev*1e6:.0f}us, "
        f"nonrev median={med_norm*1e6:.0f}us, ratio={ratio:.2f}. "
        f"Investigate whether a slow scan was introduced."
    )


# ---------------------------------------------------------------------
# BB4-21 (new defended class): TOCTOU race between concurrent
# `/users/me` reads and a `/logout` resolves correctly.
# ---------------------------------------------------------------------
def test_bb4_21_toctou_race_logout_vs_concurrent_requests(app):
    """10 concurrent `GET /api/v1/users/me` race a single `POST
    /api/v1/auth/logout` under a barrier. Once the logout completes,
    all 10 reader threads either see 200 (request came in before
    logout landed) or 401 (request came in after) — but the post-
    logout state, on a fresh request, is consistently 401.

    Specifically: we assert that after the storm settles, a freshly-
    issued request with the same cookie is 401, and that the logout
    itself succeeded (200). This pins that the revocation write does
    not race-lose against a concurrent reader's auth-check.

    Severity: N/A (defended). New honest negative."""
    cookie = auth_mod.sign_session(_DEV_SECRET, "email:dev@example.com")
    results: list[tuple[str, int]] = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(11)

    def reader(idx: int) -> None:
        cc = TestClient(app, raise_server_exceptions=False)
        cc.cookies.set("iam_jit_session", cookie)
        barrier.wait()
        r = cc.get("/api/v1/users/me")
        with results_lock:
            results.append((f"reader-{idx}", r.status_code))

    def logout_thread() -> None:
        cc = TestClient(app, raise_server_exceptions=False)
        cc.cookies.set("iam_jit_session", cookie)
        barrier.wait()
        r = cc.post("/api/v1/auth/logout")
        with results_lock:
            results.append(("logout", r.status_code))

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(10)]
    threads.append(threading.Thread(target=logout_thread))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    logout_status = next((s for n, s in results if n == "logout"), None)
    assert logout_status == 200, f"logout did not 200 during race: {results}"

    # After the storm, the cookie is definitively revoked.
    post = TestClient(app, raise_server_exceptions=False)
    post.cookies.set("iam_jit_session", cookie)
    assert post.get("/api/v1/users/me").status_code == 401, (
        "post-race request with the same cookie should be 401 — "
        "revocation write did not persist or race-lost."
    )

    # Reader statuses are either 200 (pre-revocation) or 401 (post-
    # revocation). Anything else is a bug.
    reader_statuses = [s for n, s in results if n.startswith("reader-")]
    for s in reader_statuses:
        assert s in (200, 401), (
            f"reader returned unexpected status {s} during race; "
            f"results={results}"
        )


# ---------------------------------------------------------------------
# BB4-22 (new defended class): no CORS preflight ACAO leak for
# third-party origins. CORS middleware is absent.
# ---------------------------------------------------------------------
def test_bb4_22_cors_no_acao_leak_for_third_party_origin(app):
    """`OPTIONS /api/v1/score` and `OPTIONS /api/v1/users/me` with
    third-party Origin headers (`https://evil.example.com`, `null`,
    `http://localhost:3000`) return 405 with no `Access-Control-
    Allow-Origin` header — the CORS middleware is absent.

    Pinning this: a future "we want a browser-based JS SDK"
    requirement is the canonical motivator for adding CORS, and
    adding it wrong (`*`, reflection, allowing credentials) is one
    of the top-3 ways to leak Bearer-token data cross-origin. The
    current locked-down state is correct for a Bearer-token-first
    SaaS API.

    Severity: N/A (defended). New honest negative."""
    c = TestClient(app, raise_server_exceptions=False)
    for path in ("/api/v1/score", "/api/v1/users/me", "/api/v1/tokens"):
        for origin in ("https://evil.example.com", "null", "http://localhost:3000"):
            r = c.options(path, headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization, content-type",
            })
            # No ACAO at all — CORS middleware is absent.
            assert r.headers.get("access-control-allow-origin") is None, (
                f"unexpected ACAO leak: path={path}, origin={origin}, "
                f"status={r.status_code}, ACAO={r.headers.get('access-control-allow-origin')}"
            )
            # And no ACAC.
            assert r.headers.get("access-control-allow-credentials") is None


# ---------------------------------------------------------------------
# BB4-23 (new defended class — pinned semantics): sibling-cookie
# behavior. Logout revokes only the specific cookie value sent.
# ---------------------------------------------------------------------
def test_bb4_23_logout_revokes_only_the_sent_cookie_value(app):
    """The revocation list keys on cookie-signature hash, not user-
    epoch. This means:
      - If a user signs in on two devices with two distinct cookie
        values (per-request signing nonce makes them differ), logout
        on one device DOES NOT invalidate the cookie on the other
        device.

    This is "log out this device only" semantics, which is the
    expected behavior for the documented threat model. A "log me out
    everywhere" feature would require either a per-user epoch
    counter or a per-user blanket revocation entry.

    Severity: N/A (defended; pinned semantics). The test pins the
    current behavior so a future refactor to per-user-epoch is a
    conscious decision rather than an accident.

    Note: if the team decides to flip to per-user revocation later,
    flip the final assertion to `== 401` (and remove this honest
    negative)."""
    # Generate two distinct cookie values for the same user.
    ck1 = auth_mod.sign_session(_DEV_SECRET, "email:dev@example.com")
    time.sleep(1.1)  # itsdangerous URLSafeTimedSerializer changes signature with time
    ck2 = auth_mod.sign_session(_DEV_SECRET, "email:dev@example.com")
    assert ck1 != ck2, (
        "cookie values should differ across time-separated signings"
    )

    # Both valid before logout.
    for ck in (ck1, ck2):
        cc = TestClient(app, raise_server_exceptions=False)
        cc.cookies.set("iam_jit_session", ck)
        assert cc.get("/api/v1/users/me").status_code == 200

    # Logout ck1 only.
    c1 = TestClient(app, raise_server_exceptions=False)
    c1.cookies.set("iam_jit_session", ck1)
    c1.post("/api/v1/auth/logout")

    # ck1 is now revoked.
    a1 = TestClient(app, raise_server_exceptions=False)
    a1.cookies.set("iam_jit_session", ck1)
    assert a1.get("/api/v1/users/me").status_code == 401

    # ck2 (same user, different cookie value) is NOT revoked.
    a2 = TestClient(app, raise_server_exceptions=False)
    a2.cookies.set("iam_jit_session", ck2)
    assert a2.get("/api/v1/users/me").status_code == 200, (
        "Sibling-cookie semantics changed: logout of one cookie now "
        "invalidates other cookies for the same user. If this is "
        "intentional (per-user-epoch revocation), flip the assertion "
        "to == 401."
    )
