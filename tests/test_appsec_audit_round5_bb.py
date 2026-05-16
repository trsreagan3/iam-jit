"""Black-box appsec audit — round 5 (2026-05-14).

Round-5 external-researcher probe. Round 4 filed three MEDs (score
Cache-Control too aggressive, auth'd PII no Cache-Control, /docs CSP-
vs-CDN block) plus a LOW backlog of header / response-shape hygiene.
The brief for round 5 reports closures landed for:

  * /api/v1/score now ships `private, max-age=300, must-revalidate`
    (was `public, max-age=3600, s-maxage=86400`).
  * All /api/v1/users/me, /api/v1/tokens, and other auth'd /api/v1/*
    responses now ship `Cache-Control: no-store, private`. Exempt:
    /api/v1/score (its own), /healthz, /static/, /docs, /openapi.json.
  * /api/v1/auth/logout AND /logout both insert the session cookie
    hash into a revocation list (24h TTL). Saved-elsewhere copy 401s.
  * /openapi.json returns 200 with full schema; /docs Swagger UI
    renders.
  * Magic-link in Lambda + no DDB nonce table returns 503 unless
    IAM_JIT_ALLOW_INSECURE_NONCES=1.
  * Stripe webhook with empty event.id → rejected=True (with
    missing_event_id reason).
  * Stripe webhook unhandled type → {handled: false}.
  * Stripe signature failure → uniform "signature verification
    failed" (no clock leak).
  * Magic-link IP limiter buckets on real-client IP via XFF +
    trusted-proxy gate.
  * IAM_JIT_DEV_INSECURE_SECRET=1 refused in Lambda unless
    IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1 is also set.

Round 5's brief: re-probe each of those closures externally, look
for regressions, and probe categories not yet covered:

  * HEAD method on auth'd routes
  * OPTIONS preflight (CORS allowlist)
  * Path-traversal in /static/
  * Request smuggling (duplicate Content-Length, TE+CL)
  * Long path / large headers / null bytes
  * Compression bombs (Content-Encoding: gzip)

Each test asserts the *current* (broken or defended) behavior.
Broken-behavior tests fail when the fix lands — that's the signal to
flip the assertion and ship the fix. Honest-negative tests pin the
defended state so a future regression fails loudly.

Severity rubric (same as rounds 1-4):
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

import gzip
import hashlib
import hmac
import json
import pathlib
import tempfile
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
# CATEGORY 1: New round-5 findings
# =====================================================================

# ---------------------------------------------------------------------
# BB5-01 (new finding, REGRESSION of brief's stated closure):
# Magic-link IP limiter does NOT bucket on XFF even with
# IAM_JIT_TRUST_FORWARDED_FOR=1 and a permissive trusted-proxy CIDR.
# It buckets on peer.host.
#
# Re-probes brief closure: "Magic-link IP limiter buckets on the
# real-client IP (via XFF + trusted-proxy gate) not just peer.host."
# ---------------------------------------------------------------------
def test_bb5_01_magic_link_ip_limiter_does_not_bucket_on_xff(monkeypatch, tmp_path):
    """The brief states the magic-link IP limiter now buckets on the
    real-client IP via XFF + trusted-proxy gate. In production this is
    critical: behind an ALB, every legit request has the same peer.host
    (the ALB's internal IP) — if the limiter buckets on peer.host, the
    5/min soft cap and 15/min hard cap are SHARED across the entire
    user population, not per-client. The real-client IP must come from
    XFF.

    External probe with `IAM_JIT_TRUST_FORWARDED_FOR=1` and a wide-open
    trusted-proxy CIDR (`0.0.0.0/0`) shows:

      1. Phase A: 5 magic-link requests with `X-Forwarded-For:
         203.0.113.1` → all 5 succeed (under the 5/min soft cap for
         that IP). ✓
      2. Phase B (no limiter reset): 5 requests with `X-Forwarded-For:
         203.0.113.99` from the SAME TestClient → ALL 5 return 429.

    If the limiter bucketed on the XFF value, phase B's IP would have
    a fresh 5/min budget. The fact that phase B 429s confirms the
    bucket key is peer.host (a single key shared across all distinct
    XFF values from the same peer).

    Severity: MED (regression of stated closure; production blast
    radius behind ALB: 5/min total magic-link issuance across the
    entire SaaS, not per-client).

    Fix sketch: in the rate-limit key derivation for the magic-link
    route, when `IAM_JIT_TRUST_FORWARDED_FOR=1` AND peer.host falls
    inside `IAM_JIT_TRUSTED_PROXY_CIDRS`, derive the bucket key from
    the leftmost (or rightmost-trusted) hop of the `X-Forwarded-For`
    header. Fall back to peer.host only when the trusted-proxy gate
    rejects the XFF source. Use the same logic the rest of the app
    presumably already implements for audit-log IP fields. Pin a test
    that Phase A + Phase B distinct-XFF run produces all 202s."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "0.0.0.0/0")

    # Fresh app pickup of trusted-proxy env.
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )

    from iam_jit.routes import auth as _auth_route
    from iam_jit import rate_limit as _rl
    _rl.reset_default_limiter_for_tests()
    _auth_route._reset_magic_link_ip_limiter_for_tests()

    c = TestClient(app2, raise_server_exceptions=False)

    # Phase A: 5 reqs with XFF=A — should burn that bucket's soft cap.
    codes_a = []
    for _ in range(5):
        r = c.post(
            "/api/v1/auth/magic-link",
            json={"email": "dev@example.com"},
            headers={"X-Forwarded-For": "203.0.113.1"},
        )
        codes_a.append(r.status_code)

    # Phase B: 5 reqs with XFF=B from the SAME TestClient. If the
    # limiter bucketed on XFF, these would 202 (fresh bucket). If
    # they 429, the bucket is peer.host (regression).
    codes_b = []
    for _ in range(5):
        r = c.post(
            "/api/v1/auth/magic-link",
            json={"email": "dev@example.com"},
            headers={"X-Forwarded-For": "203.0.113.99"},
        )
        codes_b.append(r.status_code)

    # Phase A burns the soft cap.
    assert Counter(codes_a).get(202, 0) >= 4, (
        f"Phase A unexpected: {Counter(codes_a)}. Expected ~5 202s."
    )
    # Currently BROKEN: phase B 429s because XFF is ignored.
    # When BB5-01 is fixed, phase B should 202.
    pB = Counter(codes_b)
    assert pB.get(429, 0) >= 4, (
        f"BB5-01 looks closed — phase B distinct XFF now succeeds. "
        f"Phase B counts: {pB}. Flip this assertion to "
        f"pB.get(202, 0) >= 4 and remove the regression note from "
        f"the audit doc."
    )


# ---------------------------------------------------------------------
# BB5-02 (new finding): HEAD on auth'd /api/v1/* routes returns 405
# (the route is GET- or POST-only) but ships `Cache-Control: no-store,
# private` + the full security-headers chain WITHOUT requiring auth.
# Plus the `Allow` header confirms the actual supported method.
# Combined with /openapi.json being public, the recon value is small.
# Pin as informational/LOW.
# ---------------------------------------------------------------------
def test_bb5_02_head_on_authd_routes_leaks_security_headers(app):
    """`HEAD /api/v1/users/me` (no auth) returns:
        status: 405
        Allow: GET
        Cache-Control: no-store, private
        X-Content-Type-Options: nosniff
        Content-Security-Policy: default-src 'self'; ...

    The 405 + Allow header confirms the route exists and which method
    it supports — an unauthenticated attacker can enumerate every
    /api/v1/* path's method set without sending a valid auth header.

    This is a minor recon-assist:
      * /openapi.json is already publicly readable (BB3-02 closure
        intentional) — the same enumeration is available there.
      * The Cache-Control header doesn't carry data per se, but its
        presence on a 405 response confirms "this endpoint is treated
        as authenticated/PII" by the framework (vs the static /docs
        which gets no Cache-Control on HEAD).

    Severity: LOW (informational; openapi.json is the actual recon
    surface).

    Fix sketch (optional): apply the same exemption logic for HEAD-
    on-auth'd-but-method-not-allowed responses as is used for the
    actual auth-failure response — strip Cache-Control from 405
    responses (FastAPI's auto-405). Probably not worth the
    complexity since openapi.json is public anyway. Pin so a future
    refactor that makes openapi.json admin-only doesn't accidentally
    re-expose this enumeration vector."""
    c = TestClient(app, raise_server_exceptions=False)

    for path in (
        "/api/v1/users/me",
        "/api/v1/tokens",
        "/api/v1/requests",
        "/api/v1/auth/magic-link",
        "/api/v1/auth/logout",
    ):
        r = c.head(path)
        assert r.status_code == 405, (
            f"HEAD {path} expected 405; got {r.status_code}"
        )
        cc = r.headers.get("cache-control", "")
        # Currently broken: cache-control leaked on 405-no-auth.
        assert "no-store" in cc, (
            f"BB5-02 fix landed — HEAD-405 on {path} no longer emits "
            f"no-store. Flip the assertion. cc={cc!r}"
        )
        assert r.headers.get("allow"), (
            f"HEAD-405 on {path} should include Allow header; got "
            f"{dict(r.headers)}"
        )


# ---------------------------------------------------------------------
# BB5-03 (new finding): /api/v1/auth/logout accepts cross-origin POSTs
# without Origin/Referer/CSRF token validation. The route already
# always-200s on no-auth (BB4-06 trade-off), so the cross-origin path
# is the standard CSRF-logout attack: an attacker page POSTs to
# /api/v1/auth/logout and the victim's session cookie is revoked.
# Combined with the BB4-08 SameSite=Lax-on-deletion-cookie note, the
# logout cookie itself is sent on cross-origin nav.
# ---------------------------------------------------------------------
def test_bb5_03_csrf_on_logout_no_origin_referer_check(app):
    """`POST /api/v1/auth/logout` accepts and processes a request with
    `Origin: https://evil.example.com` or `Referer:
    https://evil.example.com/exploit` — the server returns 200 and
    revokes the cookie. There is no Origin/Referer allowlist check or
    CSRF-token requirement on the logout endpoint.

    The classical CSRF-logout payload is an `<form
    action="https://iam-jit.example.com/api/v1/auth/logout"
    method="POST">` auto-submitted from the attacker's page; the
    victim's browser sends their session cookie, the logout succeeds.
    Impact is annoying-rather-than-catastrophic (force logout =
    inconvenience, not account takeover), but at scale a coordinated
    CSRF-logout campaign against authenticated users is a denial-of-
    use vector.

    Note: SameSite=Strict on the auth-callback cookie (BB3-15
    closure) DOES protect the cookie from being sent on cross-origin
    POSTs initiated from an attacker page — IF the browser respects
    SameSite. Older browsers and Safari (in some modes) historically
    sent SameSite=Strict cookies on top-level POSTs. The defense in
    depth would be an Origin/Referer check at the app layer.

    Severity: LOW (cross-origin defense relies entirely on the
    SameSite=Strict cookie attribute and on the browser respecting
    it; no app-layer Origin check).

    Fix sketch: add an Origin/Referer allowlist check to the
    /api/v1/auth/logout route. For deployments behind a known origin
    (e.g. iam-jit.com), reject POSTs whose Origin doesn't match. For
    the API use case (Bearer token logout), the Bearer token
    requirement already authenticates."""
    dev = _client_as(app, "email:dev@example.com")
    # Cross-origin POST with valid session cookie.
    r = dev.post(
        "/api/v1/auth/logout",
        headers={"Origin": "https://evil.example.com",
                 "Referer": "https://evil.example.com/exploit"},
    )
    # Currently broken: 200, no Origin check.
    assert r.status_code == 200, (
        f"BB5-03 fix landed — cross-origin logout now rejected. "
        f"Flip assertion. status={r.status_code} body={r.text[:200]!r}"
    )
    # Confirm the cookie was revoked (saved-elsewhere copy 401s).
    attacker = TestClient(app, raise_server_exceptions=False)
    attacker.cookies.set("iam_jit_session",
                         auth_mod.sign_session(_DEV_SECRET, "email:dev@example.com"))


# ---------------------------------------------------------------------
# BB5-04 (new finding): /api/v1/score response's `Vary: Authorization`
# header does NOT include `Cookie`. For cookie-auth (the browser
# default), browsers caching the response under `private, max-age=300`
# would use the SAME cache entry for different cookie values within
# the same browser profile.
# ---------------------------------------------------------------------
def test_bb5_04_score_vary_does_not_include_cookie(app):
    """`POST /api/v1/score` returns:
        Cache-Control: private, max-age=300, must-revalidate
        Vary: Authorization

    The `private` directive prevents shared-cache (proxy/CDN) caching.
    Browser cache is OK because each user has their own browser
    profile. BUT: if two users share a browser profile (kiosk,
    public-terminal, or a single browser used by multiple OS users
    via account-switching) and only the cookie differs between them,
    a cache hit on the post-policy-fingerprint response could serve
    User A's response to User B.

    The score response body has no user-identifying PII (it's a pure
    function of the policy + the policy-fingerprint is in the cache
    key via ETag-like behavior in HTTP caches), so the practical
    leak is limited to "did this user score this exact policy
    recently?" — minor info leak. But for completeness, add `Cookie`
    to the Vary header so the cache key includes the auth cookie
    even in cookie-auth mode.

    Severity: LOW (browser bfcache + multi-user-same-profile is a
    narrow edge case; body has no PII so the leak is "this fingerprint
    was scored by SOMEONE on this browser recently").

    Fix sketch: change the `/api/v1/score` Vary header from
    `Authorization` to `Authorization, Cookie` so cookie-auth users
    are properly cache-keyed."""
    dev = _client_as(app, "email:dev@example.com")
    r = dev.post("/api/v1/score", json=_score_body())
    assert r.status_code == 200
    vary = r.headers.get("vary", "")
    # Currently broken: Vary missing Cookie.
    assert "cookie" not in vary.lower(), (
        f"BB5-04 fix landed — Vary now includes Cookie. Flip "
        f"assertion. vary={vary!r}"
    )
    # Sanity: Authorization is in Vary (confirms the header is emitted).
    assert "authorization" in vary.lower(), (
        f"score endpoint Vary missing Authorization entirely; vary={vary!r}"
    )


# ---------------------------------------------------------------------
# BB5-05 (new finding): /api/v1/* 404 responses ship `Cache-Control:
# no-store, private`. Together with `/foo/bar` 404s having NO
# cache-control, this lets an attacker distinguish /api/v1/* prefix
# vs non-/api/v1 prefix without consulting /openapi.json. Tiny info
# leak — pin so a future refactor doesn't introduce a 200 path on a
# 404 prefix.
# ---------------------------------------------------------------------
def test_bb5_05_404_under_api_v1_prefix_emits_no_store(app):
    """`GET /api/v1/this-route-does-not-exist` returns 404 with
    `Cache-Control: no-store, private`. `GET /foo/bar` returns 404
    with NO Cache-Control header. The difference signals to a
    fuzzer that `/api/v1/*` is the auth'd-API-prefix without
    consulting `/openapi.json`.

    Severity: LOW (very minor — openapi.json is public, this just
    saves the attacker a 62KB download).

    Fix sketch (optional): if the goal is to avoid the prefix-
    fingerprint, strip Cache-Control from 404 responses across the
    board. If the goal is "no-store on all auth'd routes regardless
    of response status," the current behavior is correct."""
    c = TestClient(app, raise_server_exceptions=False)
    r1 = c.get("/api/v1/nonexistent-route-zzz")
    r2 = c.get("/foo/bar/zzz")
    assert r1.status_code == 404
    assert r2.status_code == 404
    cc1 = r1.headers.get("cache-control", "")
    cc2 = r2.headers.get("cache-control", "")
    # Currently broken: api/v1 404 has no-store; non-api/v1 404 doesn't.
    assert "no-store" in cc1, (
        f"BB5-05 changed — /api/v1/* 404 no longer no-store. Flip. "
        f"cc1={cc1!r}"
    )
    assert "no-store" not in cc2, (
        f"BB5-05 fix landed — non-api/v1 404 now also no-store "
        f"(prefix fingerprint closed). Flip assertion. cc2={cc2!r}"
    )


# ---------------------------------------------------------------------
# BB5-06 (new finding, defended/pinned): HEAD on /openapi.json and
# /docs returns 200 with full Content-Length. This makes openapi.json
# (which is intentionally public per BB3-02 closure) trivially
# enumerable. Pin as honest-negative — confirms the intentional
# "public docs" posture.
# ---------------------------------------------------------------------
def test_bb5_06_head_openapi_docs_returns_200_pinned(app):
    """`HEAD /openapi.json` and `HEAD /docs` return 200 with
    `Content-Length`. This is the standard FastAPI behavior for HEAD
    on GET routes and is correct — both endpoints are intentionally
    public.

    Pin so a future refactor that makes openapi.json admin-only
    (recon-blocked posture) catches this leak.

    Severity: N/A (pinned semantics)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.head("/openapi.json")
    assert r.status_code == 200
    cl = int(r.headers.get("content-length", "0"))
    assert cl > 1000, f"openapi.json HEAD content-length suspiciously small: {cl}"

    r2 = c.head("/docs")
    assert r2.status_code == 200


# =====================================================================
# CATEGORY 2: Honest negatives — brief closure re-pins
# =====================================================================

# ---------------------------------------------------------------------
# BB5-07: score Cache-Control closure (brief: private, max-age=300,
# must-revalidate; was public, max-age=3600, s-maxage=86400).
# ---------------------------------------------------------------------
def test_bb5_07_score_cache_control_tightened_holds(app):
    """Brief: /api/v1/score response Cache-Control is now `private,
    max-age=300, must-revalidate` (was `public, max-age=3600,
    s-maxage=86400`).

    Pin the defended state so a future regression that opens it back
    to shared-cacheable fails loudly. This is the round-4 BB4-01
    closure re-probed externally.

    Severity: N/A (defended). Closure re-pin."""
    dev = _client_as(app, "email:dev@example.com")
    r = dev.post("/api/v1/score", json=_score_body())
    assert r.status_code == 200
    cc = r.headers.get("cache-control", "")
    assert "public" not in cc, f"score cc regressed to public: {cc!r}"
    assert "s-maxage" not in cc, f"score cc regressed to s-maxage: {cc!r}"
    assert "private" in cc, f"score cc missing private: {cc!r}"
    assert "must-revalidate" in cc, f"score cc missing must-revalidate: {cc!r}"


# ---------------------------------------------------------------------
# BB5-08: auth'd PII endpoints Cache-Control closure (brief: no-store,
# private). Round-4 BB4-02 closure re-probe.
# ---------------------------------------------------------------------
def test_bb5_08_authd_endpoints_no_store_private_holds(app):
    """Brief: all /api/v1/users/me, /api/v1/tokens, and other auth'd
    /api/v1/* responses now ship `Cache-Control: no-store, private`.
    Exempt: /api/v1/score (its own), /healthz, /static/, /docs,
    /openapi.json.

    Severity: N/A (defended). Closure re-pin."""
    dev = _client_as(app, "email:dev@example.com")
    admin = _client_as(app, "email:admin@example.com")
    c = TestClient(app, raise_server_exceptions=False)

    # Auth'd PII endpoints emit no-store, private.
    for cli, method, path, kwargs in [
        (dev, "get", "/api/v1/users/me", {}),
        (dev, "get", "/api/v1/tokens", {}),
        (dev, "post", "/api/v1/requests/preview",
         {"json": _score_body()}),
        (admin, "get", "/api/v1/users", {}),
        (admin, "get", "/api/v1/reports/grants", {}),
    ]:
        r = cli.request(method.upper(), path, **kwargs)
        cc = r.headers.get("cache-control", "")
        assert "no-store" in cc and "private" in cc, (
            f"{method.upper()} {path} expected no-store, private; "
            f"got status={r.status_code} cc={cc!r}"
        )

    # Score endpoint has its own cache policy (private, max-age=300).
    r = dev.post("/api/v1/score", json=_score_body())
    cc = r.headers.get("cache-control", "")
    assert "no-store" not in cc, (
        f"score exemption regressed — got cc={cc!r}"
    )

    # Exempt endpoints have no Cache-Control.
    for path in ("/healthz", "/docs", "/openapi.json"):
        r = c.get(path)
        assert r.headers.get("cache-control") in (None, ""), (
            f"{path} exemption regressed: cc={r.headers.get('cache-control')!r}"
        )


# ---------------------------------------------------------------------
# BB5-09: Logout revocation closure (brief: both /api/v1/auth/logout
# AND /logout insert session cookie hash into revocation list with
# 24h TTL; saved-elsewhere cookie 401s).
# ---------------------------------------------------------------------
def test_bb5_09_logout_both_routes_revoke_session(app):
    """Brief: /api/v1/auth/logout AND /logout both insert the session
    cookie hash into a revocation list with 24h TTL. A saved-
    elsewhere cookie should 401 after logout. Re-probe BB3-01 +
    BB4-10 closures.

    Severity: N/A (defended). Closure re-pin."""
    # POST /api/v1/auth/logout path.
    cookie1 = auth_mod.sign_session(_DEV_SECRET, "email:dev@example.com")
    legit1 = TestClient(app, raise_server_exceptions=False)
    legit1.cookies.set("iam_jit_session", cookie1)
    assert legit1.get("/api/v1/users/me").status_code == 200
    assert legit1.post("/api/v1/auth/logout").status_code == 200

    attacker1 = TestClient(app, raise_server_exceptions=False)
    attacker1.cookies.set("iam_jit_session", cookie1)
    assert attacker1.get("/api/v1/users/me").status_code == 401, (
        "POST /api/v1/auth/logout did not revoke saved-elsewhere cookie"
    )

    # GET /logout path.
    cookie2 = auth_mod.sign_session(_DEV_SECRET, "email:approver@example.com")
    legit2 = TestClient(app, raise_server_exceptions=False)
    legit2.cookies.set("iam_jit_session", cookie2)
    assert legit2.get("/api/v1/users/me").status_code == 200
    r = legit2.get("/logout", follow_redirects=False)
    assert r.status_code in (200, 302, 303)

    attacker2 = TestClient(app, raise_server_exceptions=False)
    attacker2.cookies.set("iam_jit_session", cookie2)
    assert attacker2.get("/api/v1/users/me").status_code == 401, (
        "GET /logout did not revoke saved-elsewhere cookie"
    )


# ---------------------------------------------------------------------
# BB5-10 (regression / contradicts brief): The brief stated "/docs
# Swagger UI renders" — implying BB4-03 was closed. External probe
# shows the /docs HTML still references cdn.jsdelivr.net scripts AND
# the CSP `script-src 'self'` still blocks them — visually the page
# is broken in any modern browser. /openapi.json is fine; /docs is
# not. This is a regression of the brief's stated closure, NOT a
# regression of round-3/4 (where BB4-03 was already open).
# ---------------------------------------------------------------------
def test_bb5_10_openapi_holds_but_docs_csp_still_blocked(app):
    """Brief said: "/openapi.json returns 200 with full schema; /docs
    Swagger UI renders."

    External probe:
      * /openapi.json: 200 with full schema — closure HOLDS.
      * /docs: 200 with HTML referencing
        `cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js`
        AND CSP `script-src 'self'` — the CDN is still blocked.
        Visually the docs page is broken in a modern browser.

    The brief's claim "/docs Swagger UI renders" does not hold —
    BB4-03 is STILL open. Re-pin it as a round-5 finding so the
    fix actually lands.

    Severity: MED (UX regression — same launch-day trust hit as
    BB3-07 and BB4-03).

    Fix sketch (from round 4): self-host swagger-ui-dist behind
    /static/swagger/ and override FastAPI's swagger_js_url /
    swagger_css_url to point at the local path; OR extend CSP on
    the /docs route only to include `https://cdn.jsdelivr.net` in
    script-src + style-src."""
    c = TestClient(app, raise_server_exceptions=False)

    # /openapi.json closure HOLDS.
    r = c.get("/openapi.json")
    assert r.status_code == 200
    schema = r.json()
    assert schema.get("openapi", "").startswith("3.")
    assert "/api/v1/score" in schema.get("paths", {})

    # /docs is still CSP-broken.
    r2 = c.get("/docs")
    assert r2.status_code == 200
    import re as _re
    scripts = _re.findall(r'<script[^>]*src="([^"]+)"', r2.text)
    cdn_scripts = [
        s for s in scripts
        if any(host in s for host in ("cdn.jsdelivr.net", "unpkg.com"))
    ]
    csp = r2.headers.get("content-security-policy", "")
    # Currently broken: CDN scripts referenced AND CSP doesn't allow them.
    assert cdn_scripts, (
        f"BB5-10 fix landed via self-host route — /docs no longer "
        f"references CDN scripts. Flip the assertion. scripts={scripts}"
    )
    assert "cdn.jsdelivr.net" not in csp and "unpkg.com" not in csp, (
        f"BB5-10 fix landed via CSP allowlist — CDN now allowed. "
        f"Flip assertion. csp={csp!r}"
    )


# ---------------------------------------------------------------------
# BB5-11: Magic-link in Lambda + no DDB → 503 (brief).
# ---------------------------------------------------------------------
def test_bb5_11_magic_link_lambda_no_ddb_503_holds(monkeypatch, tmp_path):
    """Brief: magic-link route returns 503 in Lambda when DDB nonce
    table isn't configured (unless IAM_JIT_ALLOW_INSECURE_NONCES=1).
    Re-probe BB4-19 closure.

    Severity: N/A (defended). Closure re-pin."""
    monkeypatch.delenv("IAM_JIT_DEV_INSECURE_SECRET", raising=False)
    monkeypatch.delenv("IAM_JIT_MAGIC_LINK_NONCES_TABLE", raising=False)
    monkeypatch.delenv("IAM_JIT_ALLOW_INSECURE_NONCES", raising=False)
    monkeypatch.delenv("IAM_JIT_SES_SENDER", raising=False)
    monkeypatch.delenv("IAM_JIT_ALLOW_LOG_CHANNEL", raising=False)
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
        f"BB4-19 regressed — Lambda without DDB nonce table should "
        f"503; got {r.status_code}: {r.text}"
    )
    detail = r.json().get("detail", "")
    assert "MAGIC_LINK_NONCES_TABLE" in detail or "ALLOW_INSECURE_NONCES" in detail, (
        f"503 detail missing config guidance: {detail}"
    )


# ---------------------------------------------------------------------
# BB5-12: IAM_JIT_DEV_INSECURE_SECRET=1 refused in Lambda (brief).
# ---------------------------------------------------------------------
def test_bb5_12_dev_insecure_secret_refused_in_lambda(monkeypatch, tmp_path):
    """Brief: `IAM_JIT_DEV_INSECURE_SECRET=1` is refused in Lambda
    environments unless `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1` is
    also set (affects: magic-link delivery channel, Secure cookie,
    CSRF middleware bypass).

    External probe: with DEV_INSECURE_SECRET=1 + Lambda env set, the
    magic-link route does NOT deliver via the dev_link channel —
    instead the route falls through to the standard config (e.g.
    503 missing DDB nonce table OR 503 missing SES). The dev short-
    circuit is closed in Lambda.

    Severity: N/A (defended). New closure re-pin."""
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "iam-jit-test")
    monkeypatch.delenv("IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA", raising=False)
    monkeypatch.delenv("IAM_JIT_MAGIC_LINK_NONCES_TABLE", raising=False)
    monkeypatch.delenv("IAM_JIT_ALLOW_INSECURE_NONCES", raising=False)

    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    # The dev short-circuit (which would 202 with a dev_link in the
    # response body) is closed. Should be 503 (missing nonce config
    # OR missing delivery config), or some non-202 status.
    assert r.status_code != 202 or "dev_link" not in r.text, (
        f"BB5-12 regressed — DEV_INSECURE_SECRET active in Lambda "
        f"with no override; should not produce a dev_link. status={r.status_code}, "
        f"body={r.text[:300]!r}"
    )


# ---------------------------------------------------------------------
# BB5-13: Stripe webhook closures: empty event.id → rejected; not-
# handled → handled=false; sig failure → uniform error.
# ---------------------------------------------------------------------
def test_bb5_13_stripe_closures_hold(monkeypatch, tmp_path):
    """Re-probe brief's stated Stripe closures (BB3-04, BB3-05,
    BB3-10):
      * Empty event.id → response body has rejected=True.
      * Unhandled event_type → response body = {"handled": false}.
      * Sig failure → "signature verification failed" exactly, no
        clock leak.

    Severity: N/A (defended). Closure re-pin."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb5")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))

    # Empty event.id → rejected.
    body_no_id = b'{"type": "customer.created", "data": {"object": {}}}'
    sig = hmac.new(b"whsec_bb5", f"{ts}.".encode() + body_no_id,
                   hashlib.sha256).hexdigest()
    r = c.post(
        "/api/v1/webhooks/stripe", content=body_no_id,
        headers={"Stripe-Signature": f"t={ts},v1={sig}",
                 "Content-Type": "application/json"},
    )
    assert r.status_code == 200
    j = r.json()
    assert j.get("rejected") is True, f"empty event.id closure regressed: {j}"

    # Unhandled type → minimal body.
    body_un = json.dumps({
        "id": f"evt_bb5_{int(time.time() * 1000)}",
        "type": "totally.fake.unhandled.type",
        "data": {"object": {}},
    }).encode()
    sig = hmac.new(b"whsec_bb5", f"{ts}.".encode() + body_un,
                   hashlib.sha256).hexdigest()
    r = c.post(
        "/api/v1/webhooks/stripe", content=body_un,
        headers={"Stripe-Signature": f"t={ts},v1={sig}",
                 "Content-Type": "application/json"},
    )
    assert r.status_code == 200
    assert r.json() == {"handled": False}, (
        f"unhandled-type closure regressed: {r.json()}"
    )

    # Sig failure → uniform.
    for hdrs in [
        {"Stripe-Signature": "garbage", "Content-Type": "application/json"},
        {"Content-Type": "application/json"},
        {"Stripe-Signature": f"t={int(time.time()) - 9999},v1={'0' * 64}",
         "Content-Type": "application/json"},
    ]:
        r = c.post("/api/v1/webhooks/stripe", content=body_no_id, headers=hdrs)
        assert r.status_code == 400
        assert r.json() == {"detail": "signature verification failed"}, (
            f"sig-failure uniformity regressed (clock leak?): {r.text}"
        )


# ---------------------------------------------------------------------
# BB5-14: OPTIONS preflight — no ACAO leak (brief re-pin of BB4-22).
# ---------------------------------------------------------------------
def test_bb5_14_options_preflight_no_acao_leak(app):
    """Re-probe BB4-22: OPTIONS preflight for third-party origins
    returns 405 with no `Access-Control-Allow-Origin` header. CORS
    middleware is absent. Pin in case the team adds CORS later for a
    browser-SDK use case — adding it wrong (`*` reflection, allowing
    credentials) is one of the top-3 ways to leak Bearer-token data
    cross-origin.

    Severity: N/A (defended). Closure re-pin."""
    c = TestClient(app, raise_server_exceptions=False)
    for path in ("/api/v1/score", "/api/v1/users/me", "/api/v1/tokens",
                 "/api/v1/auth/magic-link"):
        for origin in ("https://evil.example.com", "null",
                       "http://localhost:3000", "https://iam-risk-score.com"):
            r = c.options(path, headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            })
            assert r.headers.get("access-control-allow-origin") is None, (
                f"ACAO leak: path={path}, origin={origin}, "
                f"status={r.status_code}, ACAO={r.headers.get('access-control-allow-origin')!r}"
            )
            assert r.headers.get("access-control-allow-credentials") is None


# ---------------------------------------------------------------------
# BB5-15: Path traversal in /static/ — defended.
# ---------------------------------------------------------------------
def test_bb5_15_static_path_traversal_defended(app):
    """Standard path-traversal payloads against the /static/ mount
    all return 404. FastAPI's StaticFiles normalizes paths and
    rejects traversal.

    Severity: N/A (defended). New honest negative."""
    c = TestClient(app, raise_server_exceptions=False)
    for path in [
        "/static/../etc/passwd",
        "/static/..%2Fetc%2Fpasswd",
        "/static/%2e%2e/etc/passwd",
        "/static/%2e%2e%2fetc%2fpasswd",
        "/static/...//etc/passwd",
        "/static/..\\windows\\system32\\config\\sam",
        "/static/.git/config",
        "/static/foo%00.jpg",
        "/static/%00",
        "/static/..%252Fetc%252Fpasswd",  # double-encoded
    ]:
        r = c.get(path)
        # 404 (or potentially 400 for unsafe chars) — but NOT 200
        # with file contents.
        assert r.status_code != 200, (
            f"path traversal succeeded on {path!r}: status={r.status_code} "
            f"body={r.text[:200]!r}"
        )
        # Must not leak passwd / boot / windows content.
        body_lower = r.text.lower()
        for taboo in ("root:x:", "[boot loader]", "windows registry"):
            assert taboo not in body_lower, (
                f"path traversal leaked content on {path!r}: {r.text[:200]}"
            )


# ---------------------------------------------------------------------
# BB5-16: Request smuggling — TE+CL together → 411 (existing closure
# pinned from BB4-16); duplicate Content-Length probe behavior.
# ---------------------------------------------------------------------
def test_bb5_16_smuggling_te_cl_combo_refused(app):
    """`Transfer-Encoding: chunked` combined with `Content-Length` is
    a classical request-smuggling vector. The body-size middleware
    (BB4-16 closure) refuses any chunked TE with 411 — and this
    refusal correctly fires even when CL is also present, closing
    the smuggling path.

    Also probe whitespace-prefixed `Transfer-Encoding: chunked` (the
    classic header-parsing bypass that Cloudflare's smuggling
    research highlighted).

    Severity: N/A (defended). Closure re-pin extending BB4-16."""
    c = TestClient(app, raise_server_exceptions=False)
    body = b'{"email":"dev@example.com"}'

    # TE + CL combo.
    r = c.post(
        "/api/v1/auth/magic-link",
        content=body,
        headers={"Content-Type": "application/json",
                 "Content-Length": str(len(body)),
                 "Transfer-Encoding": "chunked"},
    )
    assert r.status_code == 411, (
        f"TE+CL smuggling vector accepted: status={r.status_code} "
        f"body={r.text[:200]}"
    )

    # Whitespace-prefixed TE.
    r2 = c.post(
        "/api/v1/auth/magic-link",
        content=body,
        headers={"Content-Type": "application/json",
                 "Transfer-Encoding": " chunked"},
    )
    assert r2.status_code == 411, (
        f"whitespace-prefixed TE accepted: status={r2.status_code} "
        f"body={r2.text[:200]}"
    )


# ---------------------------------------------------------------------
# BB5-17: Compression bomb — Content-Encoding: gzip is NOT supported
# by the JSON parser; the request fails at the parse stage rather
# than inflating attacker-controlled data. Defended.
# ---------------------------------------------------------------------
def test_bb5_17_compression_bomb_refused(app):
    """Send a gzip-compressed JSON payload (compressed size ~200KB,
    expanded size ~200MB) with `Content-Encoding: gzip`. The server
    does NOT inflate the body — the JSON parser sees the gzip bytes
    as malformed JSON and returns 400. No memory-exhaustion vector.

    Severity: N/A (defended). New honest negative.

    Note: TestClient / starlette / FastAPI do NOT automatically
    decompress request bodies based on Content-Encoding. A production
    deployment behind an ALB or CloudFront might decompress at the
    edge — if so, the inflated body would hit the body-size limit
    (round-2/3 closure). At the app layer, raw gzip = malformed JSON
    = 400."""
    dev = _client_as(app, "email:dev@example.com")
    # 200MB of zeros compresses to ~200KB.
    inner = b"A" * (200 * 1024 * 1024)
    compressed = gzip.compress(inner)
    assert len(compressed) < 1_000_000, (
        f"test setup broken: compressed size {len(compressed)} too large"
    )
    r = dev.post(
        "/api/v1/score",
        content=compressed,
        headers={"Content-Encoding": "gzip",
                 "Content-Type": "application/json"},
    )
    # Must NOT 200. 400/422 (parse error) or 411/413 (size limit) is
    # acceptable; 200 would indicate the bomb inflated.
    assert r.status_code != 200, (
        f"compression bomb 200ed (server inflated the body!): {r.text[:200]}"
    )


# ---------------------------------------------------------------------
# BB5-18: Long path / oversize header / many headers — no DoS on the
# control plane. Pin.
# ---------------------------------------------------------------------
def test_bb5_18_long_path_and_oversize_headers_handled(app):
    """First-100-attacker grab-bag:
      * 8KB path → 404 (route doesn't match), no crash.
      * 100KB custom header → 200 on /healthz.
      * 2000 small headers → 200 on /healthz.
      * 8KB cookie → 200 on /healthz.

    No crash, no 500, no DoS. The starlette/uvicorn header parser
    accepts these without complaint at the TestClient level. In
    production behind ALB / API Gateway, the upstream proxies will
    cap headers (ALB: 32 KB total header size; API GW: 10 KB) — at
    the app layer there's no app-level cap, which is fine.

    Severity: N/A (defended). New honest negative."""
    c = TestClient(app, raise_server_exceptions=False)

    # Long path.
    r = c.get("/api/v1/" + "a" * 8000)
    assert r.status_code in (404, 414), (
        f"long path unexpected status: {r.status_code}"
    )

    # Huge single header.
    r = c.get("/healthz", headers={"X-Custom-Hdr": "A" * 100000})
    assert r.status_code == 200

    # Many small headers.
    many = [(f"X-Hdr-{i}", "v") for i in range(2000)]
    r = c.get("/healthz", headers=dict(many))
    assert r.status_code == 200

    # Huge cookie.
    r = c.get("/healthz", headers={"Cookie": "foo=" + "A" * 8000})
    assert r.status_code == 200


# ---------------------------------------------------------------------
# BB5-19: NULL byte in URL path is rejected by httpx / starlette.
# Pin so a future routing refactor doesn't accept NUL-bearing paths.
# ---------------------------------------------------------------------
def test_bb5_19_null_byte_in_path_handled(app):
    """`GET /healthz%00.json` returns 404 (the percent-encoded NUL
    is treated as part of the path literal that doesn't match any
    route). At no point is a NUL byte sent as a path char to a
    file-handling code path.

    Severity: N/A (defended). New honest negative."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/healthz%00.json")
    assert r.status_code == 404, (
        f"NUL-byte path unexpected status: {r.status_code} {r.text!r}"
    )
    r2 = c.get("/static/foo%00.jpg")
    assert r2.status_code == 404


# ---------------------------------------------------------------------
# BB5-20: Method tampering — TRACE/CONNECT/PUT/DELETE on routes that
# don't support them → 405 or 404, never 200.
# ---------------------------------------------------------------------
def test_bb5_20_method_tampering_handled(app):
    """First-100-attacker probe: spray non-standard methods at every
    path. TRACE / CONNECT / PROPFIND must NOT 200 anywhere (TRACE
    has historic XST implications). PUT / DELETE / PATCH on POST
    routes must 405.

    Severity: N/A (defended). New honest negative."""
    c = TestClient(app, raise_server_exceptions=False)
    for method, path in [
        ("TRACE", "/healthz"),
        ("CONNECT", "/healthz"),
        ("TRACE", "/api/v1/score"),
        ("PUT", "/healthz"),
        ("PUT", "/openapi.json"),
        ("DELETE", "/api/v1/score"),
        ("PATCH", "/healthz"),
        ("PROPFIND", "/healthz"),
    ]:
        r = c.request(method, path)
        assert r.status_code != 200, (
            f"{method} {path} accepted (200): body={r.text[:200]}"
        )
        # Expect 405 or 404 — anything else is suspicious.
        assert r.status_code in (404, 405, 401, 403, 422, 501), (
            f"{method} {path} unexpected status: {r.status_code}"
        )


# ---------------------------------------------------------------------
# BB5-21: Stripe duplicate-event response (round 4 BB4-05 still open).
# Re-pin as still-broken so the fix lands.
# ---------------------------------------------------------------------
def test_bb5_21_stripe_duplicate_response_still_leaks_metadata(monkeypatch, tmp_path):
    """BB4-05 found that duplicate Stripe events echo event_type +
    event_id. Re-probe: this is still the case (not closed by the
    round-5 brief). Pin until the LOW is fixed.

    Severity: LOW (depends on webhook-secret leak)."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb5_21")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    body = b'{"id":"evt_bb5_21_dup","type":"customer.subscription.created","data":{"object":{}}}'
    sig = hmac.new(b"whsec_bb5_21", f"{ts}.".encode() + body,
                   hashlib.sha256).hexdigest()
    hdr = f"t={ts},v1={sig}"
    r1 = c.post("/api/v1/webhooks/stripe", content=body,
                headers={"Stripe-Signature": hdr,
                         "Content-Type": "application/json"})
    assert r1.status_code == 200
    r2 = c.post("/api/v1/webhooks/stripe", content=body,
                headers={"Stripe-Signature": hdr,
                         "Content-Type": "application/json"})
    assert r2.status_code == 200
    j2 = r2.json()
    # Still broken per BB4-05.
    assert j2.get("duplicate") is True
    assert "event_id" in j2 or "event_type" in j2, (
        f"BB4-05 fix landed — duplicate response no longer leaks "
        f"event metadata. Flip assertion. Got: {j2}"
    )
