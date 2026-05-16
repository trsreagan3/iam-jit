"""Black-box appsec audit — round 3 (2026-05-14).

Round-3 external-researcher probe. Launch-day focus: the first 100
attackers hitting the public URL after launch — what do they probe in
the first hour, what unauth surfaces have unbounded resource cost, what
free-tier user actions spike cost.

Rounds 1 + 2 closed (or pinned) the CSRF, magic-link-log, XFF-trust,
and Stripe-idempotency clusters. Round 3 looks for:

  1. Surfaces re-exposed by the round-1/2 fixes themselves (logout
     handler that sets Set-Cookie but doesn't blacklist server-side,
     /openapi.json route that broke during a refactor).
  2. Surfaces no prior round probed in depth (Stripe error verbosity,
     event-id edge cases, score-rate-limit-keying).
  3. Public recon surfaces (healthz, openapi, docs, error bodies).
  4. Re-confirmation of round-1/2 closures via TestClient.

Each test asserts the *current* (broken or defended) behavior; broken-
behavior tests fail when the fix lands — that's the signal to flip the
assertion and ship the fix.

Severity rubric (same as rounds 1 and 2):
    CRIT — pre-auth RCE, cross-tenant data leak, credential theft.
    HIGH — full account takeover with user interaction, privilege
           escalation, persistent XSS in admin context, broken authn.
    MED  — CSRF on state-change, IDOR with cleanup constraints,
           sensitive-data exposure in logs, rate-limit miss with real
           cost.
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
    from iam_jit import session_revocation as _sr
    _sr.reset_default_store_for_tests()


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


def _mk_request(client, description="ordinary request") -> str:
    r = client.post(
        "/api/v1/requests",
        json={
            "apiVersion": "iam-jit.dev/v1alpha1",
            "kind": "RoleRequest",
            "metadata": {"requester": {"name": "Dev", "email": "dev@example.com"}},
            "spec": {
                "description": description,
                "access_type": "read-only",
                "task_intent": {"services": ["s3"], "actions": ["read"]},
                "accounts": [{"account_id": "060392206767", "regions": ["us-east-1"]}],
                "duration": {"duration_hours": 24},
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
                },
                "provisioning": {"mode": "identity_center"},
            },
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["request"]["metadata"]["id"]


# =====================================================================
# CATEGORY 1: New launch-critical findings
# =====================================================================

# ---------------------------------------------------------------------
# BB3-01: POST /api/v1/auth/logout is client-side only — the server
#         returns Set-Cookie: Max-Age=0 (which clears the cookie in the
#         caller's browser), but the cookie VALUE itself is still a
#         valid signed-timed token and works for ~24 hours in any other
#         client that has saved a copy.
# ---------------------------------------------------------------------
def test_bb3_01_logout_does_not_invalidate_cookie_server_side(app):
    """`POST /api/v1/auth/logout` (and the HTML `GET /logout`) issue a
    Set-Cookie with `Max-Age=0` that clears the cookie in the browser
    that clicked "sign out". But the signed-timed cookie VALUE is still
    a valid bearer-token for any other client that had saved a copy.

    Threat model: an attacker exfiltrated the cookie value before the
    user noticed (XSS on a co-located subdomain, packet sniff on a
    downgraded HTTP request, ALB access log, shared device, browser
    extension). The user clicks "Sign out". Today, the attacker's saved
    copy continues to work for up to 24 hours (the cookie's TTL). The
    user has no recourse short of waiting out the TTL.

    Severity: HIGH (broken authn — logout is the user-visible
    revocation primitive and it doesn't actually revoke).

    Fix sketch: maintain a session-blacklist (DynamoDB table with TTL =
    cookie TTL). On logout, insert `(cookie_signature, expires_at)`.
    The auth middleware checks the blacklist (one GetItem) before
    honoring a cookie. Alternative: per-user epoch counter; logout
    bumps the counter; cookies older than the current counter are
    rejected."""
    cookie_value = auth_mod.sign_session(_DEV_SECRET, "email:dev@example.com")

    # Confirm the cookie is valid (sanity check).
    c1 = TestClient(app, raise_server_exceptions=False)
    c1.cookies.set("iam_jit_session", cookie_value)
    assert c1.get("/api/v1/users/me").status_code == 200

    # The user "signs out" via the JSON logout endpoint.
    r = c1.post("/api/v1/auth/logout")
    assert r.status_code == 200, r.text
    set_cookie = r.headers.get("set-cookie", "")
    assert "iam_jit_session" in set_cookie
    assert "Max-Age=0" in set_cookie

    # Attacker (saved the cookie value before the user clicked
    # BB3-01 CLOSED: server-side revocation list. The saved-elsewhere
    # cookie copy is rejected with 401 after logout, not honored.
    attacker = TestClient(app, raise_server_exceptions=False)
    attacker.cookies.set("iam_jit_session", cookie_value)
    r = attacker.get("/api/v1/users/me")
    assert r.status_code == 401, (
        f"expected server-side invalidation (401) after logout; got "
        f"{r.status_code}: {r.text[:200]}"
    )

    # Same closure on the HTML GET /logout flow. Use a different
    # user so the cookie value (which encodes the user_id) hashes
    # to a fresh slot in the revocation list.
    fresh_cookie = auth_mod.sign_session(_DEV_SECRET, "email:approver@example.com")
    c2 = TestClient(app, raise_server_exceptions=False)
    c2.cookies.set("iam_jit_session", fresh_cookie)
    assert c2.get("/api/v1/users/me").status_code == 200
    c2.get("/logout", follow_redirects=False)
    attacker2 = TestClient(app, raise_server_exceptions=False)
    attacker2.cookies.set("iam_jit_session", fresh_cookie)
    assert attacker2.get("/api/v1/users/me").status_code == 401


# ---------------------------------------------------------------------
# BB3-02: GET /openapi.json returns 500 — pydantic ForwardRef
#         (Response) unresolved at schema-build time.
# ---------------------------------------------------------------------
def test_bb3_02_openapi_json_returns_500(app):
    """`GET /openapi.json` returns 500 on every request. The underlying
    pydantic error is `TypeAdapter[Annotated[ForwardRef('Response'),
    ...]] is not fully defined`. Something in a route's return-type
    annotation references `Response` without a `model_rebuild()` /
    resolved typing namespace.

    Severity: HIGH at launch.
      - functional outage: API consumers (MCP server, GitHub Action,
        SDK generators, OpenAPI Generator) cannot fetch the schema;
      - downstream UX: `GET /docs` returns Swagger HTML 200 but the UI
        fetches /openapi.json client-side and renders 'Failed to load
        API definition' (see BB3-07);
      - recon signal: an attacker hitting /openapi.json and seeing 500
        immediately knows the deployment has unhandled exceptions on a
        critical public route. Probes harder.

    Fix sketch: find the route or pydantic model with the unresolved
    `Response` ForwardRef. Either call `Model.model_rebuild()` at app
    startup, or annotate with the resolved `starlette.responses.
    Response` type."""
    # BB3-02 CLOSED: routes with `-> Response` got an explicit
    # `response_class=Response` to skip pydantic's body-schema
    # inference, and `response: Response` parameters were refactored
    # away. /openapi.json now returns 200.
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/openapi.json")
    assert r.status_code == 200, (
        f"/openapi.json should return 200; got {r.status_code}. "
        f"The pydantic ForwardRef issue may have regressed."
    )
    schema = r.json()
    assert schema.get("openapi", "").startswith("3."), (
        "expected an OpenAPI 3.x schema body"
    )
    # /api/v1/score is the core public route — its presence proves the
    # schema generation reaches the real endpoints.
    assert "/api/v1/score" in schema.get("paths", {})


# ---------------------------------------------------------------------
# BB3-03: /healthz STILL leaks the full security_posture object —
#         BB-13 (round 1, LOW) was not fixed; round 3 retest bumps to
#         MED because the issues[].detail strings now include
#         operational hints like 'the link appears in any browser that
#         observes the response, including via shoulder-surfing or
#         browser history'.
# ---------------------------------------------------------------------
def test_bb3_03_healthz_leaks_full_security_posture(app):
    """Round-1 BB-13 asked for `/healthz` to shrink to
    `{"status":"ok"}`. Today the endpoint still returns auth_mode,
    user_config_source, llm_backend, security_posture.alb_in_front,
    security_posture.ses_configured, security_posture.network_acl_
    active, AND the full issues array with `detail` and `fix` strings.

    Severity: MED (recon — the issues[].detail/fix strings tell the
    attacker exactly which attack to run against the deployment).

    Fix sketch: return `{"status":"ok"}` for `/healthz` and serve the
    posture at the admin-gated `/api/v1/admin/security-posture` (which
    already exists)."""
    # BB3-03 / BB-13 — CLOSED. /healthz is a bare liveness response.
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "ok"
    assert "version" in body
    assert "auth_mode" not in body
    assert "user_config_source" not in body
    assert "llm_backend" not in body
    assert "security_posture" not in body
    # The original test continues below — short-circuit by
    # returning here since the closure path is now the asserted
    # behavior.
    return
    posture = body.get("security_posture") or {}
    if posture.get("issues"):
        sample = posture["issues"][0]
        assert "detail" in sample or "fix" in sample


# ---------------------------------------------------------------------
# BB3-04: Stripe webhook signature-error response echoes the server's
#         current wall-clock epoch — `now=<epoch>` in the 400 body.
# ---------------------------------------------------------------------
def test_bb3_04_stripe_error_echoes_server_now(monkeypatch, tmp_path):
    """When Stripe signature verification fails on the timestamp
    tolerance, the response body includes
        'Stripe-Signature timestamp <ts> is outside the 300s tolerance
         window (now=<server-epoch>)'

    The `now=<server-epoch>` is the server's wall-clock. An attacker
    pings the webhook with a deliberately bad signature and gets a
    free clock-sync gadget — useful for synchronizing time-windowed
    replay attacks across instances.

    Severity: MED (info leak; combined with time-windowed tokens
    elsewhere this is a coordination gadget).

    Fix sketch: keep the detailed error in server logs; return only
    `{"detail": "signature verification failed"}` to the caller."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb3_04")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    # Send a signed event with a 2001 timestamp — well outside the
    # 300s tolerance.
    ts = "1000000000"  # year 2001
    body = b'{"id":"evt_x","type":"customer.created","data":{"object":{}}}'
    sig = hmac.new(b"whsec_bb3_04", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    r = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"},
    )
    # BB3-04 CLOSED: response body is now generic. The detailed
    # reason (server clock, timestamp, tolerance window) lives in
    # server logs only — no clock-sync gadget for attackers.
    assert r.status_code == 400
    detail = r.json().get("detail", "")
    assert "now=" not in detail, (
        f"server clock should not be echoed to the caller; got: {detail}"
    )
    assert detail == "signature verification failed"


# ---------------------------------------------------------------------
# BB3-05: Stripe webhook with empty / missing `event.id` is
#         indefinitely replayable — the atomic-claim short-circuit
#         does not catch this case.
# ---------------------------------------------------------------------
def test_bb3_05_stripe_idempotency_skipped_for_missing_event_id(monkeypatch, tmp_path):
    """The round-2 BB2-04 fix landed `processed_events_store.claim
    (event_id)` as the gatekeeper. Probe shows that when the event
    body has `"id": ""` (empty) OR omits the `id` field, the webhook
    returns 200 every time with no `duplicate=True` — three
    consecutive replays all yield {handled: False, event_type:
    "customer.created"} with no duplicate marker.

    Severity: MED (billing-integrity gap waiting to fire — small
    today because no handler runs for these events, but any future
    handler will trigger N times for N retries).

    Fix sketch: at the top of `dispatch_event`, reject events with
    `not event_id` (treat None / "" as malformed) with 400. Stripe
    always populates event.id; rejecting empties is safe."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb3_05")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    # Body has no `id` field at all.
    body = b'{"type": "customer.created", "data": {"object": {}}}'
    sig = hmac.new(b"whsec_bb3_05", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    hdr = f"t={ts},v1={sig}"
    responses = []
    for _ in range(3):
        r = c.post(
            "/api/v1/webhooks/stripe",
            content=body,
            headers={"Stripe-Signature": hdr, "Content-Type": "application/json"},
        )
        responses.append(r.json())

    # BB3-05 CLOSED: events missing event.id are now refused with
    # rejected=True and never reach the idempotency store. Stripe
    # always populates event.id; missing-id requests are malformed
    # or malicious. Reject all three.
    rejected_count = sum(1 for r in responses if r.get("rejected") is True)
    assert rejected_count == 3, (
        f"expected all 3 missing-event-id deliveries to be rejected; "
        f"got {rejected_count}. Responses: {responses}"
    )

    # Same for `id: ""` empty string.
    body2 = b'{"id": "", "type": "customer.created", "data": {"object": {}}}'
    sig2 = hmac.new(b"whsec_bb3_05", f"{ts}.".encode() + body2, hashlib.sha256).hexdigest()
    hdr2 = f"t={ts},v1={sig2}"
    responses2 = []
    for _ in range(3):
        r = c.post(
            "/api/v1/webhooks/stripe",
            content=body2,
            headers={"Stripe-Signature": hdr2, "Content-Type": "application/json"},
        )
        responses2.append(r.json())
    rejected_count2 = sum(1 for r in responses2 if r.get("rejected") is True)
    assert rejected_count2 == 3, (
        f"expected all 3 empty-event-id deliveries to be rejected; "
        f"got {rejected_count2}. Responses: {responses2}"
    )


# ---------------------------------------------------------------------
# BB3-06: HTML POST /tokens still mints a token on cookie-only POST
#         from cross-origin headers — round-1 BB-02 retest. The
#         session cookie is now SameSite=Strict (BB3-15 closure)
#         which mitigates the bulk of the threat in modern browsers,
#         but the surface is still unauthenticated against the CSRF
#         token primitive.
# ---------------------------------------------------------------------
def test_bb3_06_html_token_mint_still_csrf_on_cookie_only(app):
    """Round-1 BB-02 filed HTML token-mint CSRF as HIGH. Round-3
    retest: the HTML POST /tokens endpoint still mints a token on a
    cookie-only request that arrives with cross-origin Referer + Origin
    headers. No anti-CSRF token, no double-submit-cookie check, no
    Origin validation.

    Severity: MED (downgraded from round-1 HIGH because the session
    cookie's new SameSite=Strict (BB3-15) blocks the simple form-post
    CSRF in modern browsers. But: the endpoint accepts the request
    when the cookie IS sent — i.e. a same-site attacker chain still
    works, and SameSite=Strict is bypassed by any flow that triggers
    same-site JS after a top-level navigation to iam-jit).

    Fix sketch: same as round-1 BB-02 — anti-CSRF token middleware
    or hard cross-origin Origin/Referer reject on HTML state-changing
    POSTs."""
    dev = _client_as(app, "email:dev@example.com")
    before = dev.get("/api/v1/tokens").json()["count"]
    r = dev.post(
        "/tokens",
        data={"label": "csrf-still-works"},
        headers={
            "Referer": "https://evil.example.com/",
            "Origin": "https://evil.example.com",
        },
        follow_redirects=False,
    )
    after = dev.get("/api/v1/tokens").json()["count"]
    # Currently broken: token minted despite cross-origin Referer+Origin.
    assert r.status_code == 200, r.text
    assert after == before + 1, (
        f"expected cross-origin CSRF to be rejected; instead a token "
        f"was minted ({before} -> {after}). Round-1 BB-02 is still open."
    )


# =====================================================================
# CATEGORY 2: LOW findings — output handling / recon hardening
# =====================================================================

# ---------------------------------------------------------------------
# BB3-07: /docs renders against the broken /openapi.json — pair
#         finding to BB3-02.
# ---------------------------------------------------------------------
def test_bb3_07_docs_swagger_references_broken_openapi(app):
    """`GET /docs` returns the Swagger HTML 200. The embedded swagger
    UI fetches `/openapi.json` client-side and renders 'Failed to
    load API definition' (because BB3-02). Until BB3-02 is fixed,
    launch-day API consumers visiting /docs see a broken page.

    Severity: LOW (UX / first-impression).

    This test pins the current behavior: /docs returns Swagger HTML
    that references /openapi.json. When BB3-02 is fixed and openapi
    returns 200, the docs page will work — and this test will still
    pass (the HTML reference stays correct). The test is really a
    canary for `/openapi.json` being referenced in the Swagger HTML."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/docs")
    assert r.status_code == 200
    # The Swagger HTML references /openapi.json as the source.
    assert "openapi.json" in r.text


# ---------------------------------------------------------------------
# BB3-08: Score endpoint rate-limit keys on peer IP — authenticated
#         users behind shared NAT share the bucket.
# ---------------------------------------------------------------------
def test_bb3_08_score_rate_limit_per_ip_not_per_user(app):
    """`POST /api/v1/score` rate-limits by peer IP. Two authenticated
    users behind the same corporate NAT / consumer CGNAT share the
    bucket. A noisy neighbor (or an attacker who knows the target's
    egress IP) can pin the bucket at 429 for everyone behind that
    IP.

    Severity: LOW (DoS-of-scoring; recoverable on next minute).

    Probe: dev user bursts 100 score calls and exhausts the bucket.
    A SECOND user (admin) issuing a request from the same client IP
    via Bearer token also gets 429 — sharing the bucket.

    Fix sketch: authenticated requests rate-limit by (user_id, IP)
    tuple; unauthenticated by IP only. Add a per-user soft cap
    independent of the per-IP cap."""
    dev = _client_as(app, "email:dev@example.com")
    body = {
        "policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
        "description": "x",
        "duration_hours": 1,
        "access_type": "read-only",
    }
    cnt = Counter()
    for _ in range(80):
        r = dev.post("/api/v1/score", json=body)
        cnt[r.status_code] += 1
    assert cnt[429] > 0, f"expected some 429s after the burst; got {cnt}"

    # Different user via Bearer token, SAME client IP.
    admin = _client_as(app, "email:admin@example.com")
    admin_tok = admin.post("/api/v1/tokens", json={"label": "x"}).json()["token"]
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post(
        "/api/v1/score",
        json=body,
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    # Currently broken: the new user is also 429 because they share
    # the IP bucket.
    assert r.status_code == 429, (
        f"expected per-IP bucket sharing (current broken behavior); "
        f"got {r.status_code}. If this is now 200, the score rate-"
        f"limiter has been split per-user and this test should be "
        f"flipped."
    )


# ---------------------------------------------------------------------
# BB3-09: /api/v1/requests/preview reflects raw user input in JSON
#         error body — not a browser-side XSS (Content-Type is JSON)
#         but a downstream-log-renderer risk.
# ---------------------------------------------------------------------
def test_bb3_09_preview_reflects_raw_user_input_in_error(app):
    """`POST /api/v1/requests/preview` with a malformed body returns
    200 with a `schema_errors` array. The error strings include the
    user's raw input (e.g. `{'description': '<script>alert(1)</
    script>'} is not valid under any of the given schemas`). The
    Content-Type is application/json so a browser won't render the
    <script>, but downstream consumers (markdown-rendering admin
    log viewer, Slack webhook relay, error-tracking SaaS) might.

    Severity: LOW (defense-in-depth; depends on downstream rendering).

    Fix sketch: don't echo the user's value in the schema-error
    string — emit `field 'description' is invalid` without the
    value, OR escape <,>,& in error bodies."""
    dev = _client_as(app, "email:dev@example.com")
    payload = {"spec": {"description": "<script>alert(1)</script>"}}
    r = dev.post("/api/v1/requests/preview", json=payload)
    assert r.status_code == 200
    body_text = r.text
    # Currently broken: the raw <script> tag round-trips.
    assert "<script>alert(1)</script>" in body_text, (
        f"expected raw input reflection (current broken behavior); "
        f"body: {body_text[:500]}"
    )


# ---------------------------------------------------------------------
# BB3-10: Stripe webhook handled=False response reveals the
#         event_type the attacker sent — free event-type enumeration
#         oracle.
# ---------------------------------------------------------------------
def test_bb3_10_stripe_webhook_echoes_event_type(monkeypatch, tmp_path):
    """An attacker with the webhook URL (which they get from /docs
    or by guessing the Stripe webhook path) can submit signed events
    (if the webhook secret leaks at all — common via CI logs, .env
    commits) and the response confirms each event_type they tried.
    Combined with BB3-05 (no event.id required), this is a free
    enumeration of which event types the deployment handles.

    Severity: LOW (depends on adjacent leaks).

    Fix sketch: don't echo the attacker's event_type in the
    response. Emit `{"handled": false}` only."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb3_10")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    body = b'{"id":"evt_bb3_10","type":"my.totally.fake.event","data":{"object":{}}}'
    sig = hmac.new(b"whsec_bb3_10", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    r = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"},
    )
    # BB3-10 CLOSED: response body no longer echoes the attacker's
    # event_type on the not-handled path. Just `{"handled": false}`.
    assert r.status_code == 200
    body_json = r.json()
    assert "event_type" not in body_json, (
        f"event_type should not leak to webhook caller on not-handled "
        f"path; got {body_json}"
    )
    assert body_json.get("handled") is False


# =====================================================================
# CATEGORY 3: Honest negatives — defended classes
# =====================================================================

# ---------------------------------------------------------------------
# BB3-11: Stripe atomic-claim under concurrent replay (BB2-04 retest)
# ---------------------------------------------------------------------
def test_bb3_11_stripe_atomic_claim_under_concurrent_replay(monkeypatch, tmp_path):
    """BB2-04 retest. 5 concurrent threads racing the SAME signed
    event under a barrier should yield exactly 1 fresh handler-run
    and 4 `duplicate: True` short-circuits. The round-2 atomic-claim
    fix correctly serializes the claim() call.

    Severity: N/A (defended). Honest negative."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb3_11")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    body = b'{"id":"evt_bb3_11_concurrent","type":"customer.subscription.created","data":{"object":{"id":"sub_x"}}}'
    sig = hmac.new(b"whsec_bb3_11", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    hdr = f"t={ts},v1={sig}"

    results: list = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(5)

    def hit() -> None:
        barrier.wait()
        r = c.post(
            "/api/v1/webhooks/stripe",
            content=body,
            headers={"Stripe-Signature": hdr, "Content-Type": "application/json"},
        )
        with results_lock:
            results.append(r.json())

    threads = [threading.Thread(target=hit) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    duplicates = sum(1 for r in results if r.get("duplicate") is True)
    assert duplicates == 4, (
        f"expected 4 atomic-claim losers + 1 winner; got "
        f"{duplicates} duplicates in 5 results: {results}"
    )


# ---------------------------------------------------------------------
# BB3-12: Magic-link rate-limiter not bypassable via XFF spoofing
#         when XFF-trust is default-off.
# ---------------------------------------------------------------------
def test_bb3_12_magic_link_ip_limiter_immune_to_xff_spoof(app, monkeypatch):
    """With `IAM_JIT_TRUST_FORWARDED_FOR` default-off (BB2-02
    closure), an unauthenticated burst against /api/v1/auth/magic-
    link with rotating X-Forwarded-For headers still gets 429 after
    the configured cap. The limiter correctly keys on the peer
    (testclient / 127.0.0.1), not the spoofed XFF.

    Severity: N/A (defended). Honest negative against XFF-spoof
    regression on the magic-link surface."""
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_FOR", raising=False)
    monkeypatch.delenv("IAM_JIT_TRUSTED_PROXY_CIDRS", raising=False)
    monkeypatch.setenv("IAM_JIT_ALLOW_LOG_CHANNEL", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_IP_SOFT_CAP", "3")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_IP_HARD_CAP", "5")
    from iam_jit.routes import auth as _auth_route
    _auth_route._reset_magic_link_ip_limiter_for_tests()

    c = TestClient(app, raise_server_exceptions=False)
    statuses = []
    for i in range(10):
        r = c.post(
            "/api/v1/auth/magic-link",
            json={"email": f"u{i}@example.com"},
            headers={"X-Forwarded-For": f"203.0.113.{i}"},
        )
        statuses.append(r.status_code)
    cnt = Counter(statuses)
    assert cnt.get(429, 0) >= 5, (
        f"expected ≥5 429s (XFF spoof did not bypass the per-IP "
        f"limiter); got {cnt}"
    )


# ---------------------------------------------------------------------
# BB3-13: Tampered cookie still rejected — itsdangerous signature
#         verification holds (BB-22 round-1 retest).
# ---------------------------------------------------------------------
def test_bb3_13_cookie_tampering_still_rejected(app):
    """Round-1 BB-22 honest negative. Tampered cookie value → 401.
    Wrong-secret-signed cookie → 401. Unsigned plaintext → 401.
    Round-3 retest confirms still holding.

    Severity: N/A (defended). Honest negative."""
    valid = auth_mod.sign_session(_DEV_SECRET, "email:dev@example.com")
    tampered = valid[:-2] + ("AB" if valid[-2:] != "AB" else "CD")

    c = TestClient(app, raise_server_exceptions=False)
    c.cookies.set("iam_jit_session", tampered)
    assert c.get("/api/v1/users/me").status_code == 401

    forged = auth_mod.sign_session("not-the-real-secret-1234567890abcd", "email:admin@example.com")
    c.cookies.set("iam_jit_session", forged)
    assert c.get("/api/v1/users/me").status_code == 401

    c.cookies.set("iam_jit_session", "email:admin@example.com")
    assert c.get("/api/v1/users/me").status_code == 401


# ---------------------------------------------------------------------
# BB3-14: HTML POST /requests/new/chat refuses cookie-only POST —
#         CSRF surface partially fixed on this specific HTML route.
# ---------------------------------------------------------------------
def test_bb3_14_requests_new_chat_refuses_cross_origin_post(app):
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
# ---------------------------------------------------------------------
# BB3-15: Session cookie ships with SameSite=Strict on auth callback.
#         Round-1 noted SameSite=Lax; this is a silent upgrade.
# ---------------------------------------------------------------------
def test_bb3_15_session_cookie_samesite_strict(app):
    """The cookie set by `/api/v1/auth/callback` now ships with
    `SameSite=strict`. Round-1 BB-07 noted `SameSite=Lax`. This is
    a silent upgrade (not announced in either prior audit doc) that
    meaningfully shrinks the CSRF window for top-level cross-origin
    form posts in modern browsers.

    Severity: N/A (defended). Honest negative — pin this so a future
    refactor doesn't accidentally regress to Lax."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    link = r.json().get("dev_link") or ""
    assert link, f"expected dev_link for the magic-link response; got: {r.json()}"
    token = link.split("token=")[1]
    r2 = c.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    cookie_hdr = r2.headers.get("set-cookie", "")
    assert "iam_jit_session" in cookie_hdr
    # SameSite=strict (case-insensitive — Starlette emits lowercase).
    assert "samesite=strict" in cookie_hdr.lower(), (
        f"expected SameSite=Strict on session cookie; got: "
        f"{cookie_hdr}"
    )


# =====================================================================
# CATEGORY 4: Round-1 / Round-2 retests — closures confirmed externally
# =====================================================================

# ---------------------------------------------------------------------
# BB3-16: BB-12 magic-link log channel — fingerprint-only emit
# ---------------------------------------------------------------------
def test_bb3_16_magic_link_log_channel_fingerprint_only(caplog, monkeypatch, tmp_path):
    """Round-1 BB-12 / round-2 BB2-08. With no SES sender and no
    explicit ALLOW_LOG_CHANNEL, /api/v1/auth/magic-link returns 503.
    With ALLOW_LOG_CHANNEL=1, the log line emits a fingerprint
    (sha256 prefix) but never the full URL.

    Severity: N/A (defended). Round-3 closure retest."""
    monkeypatch.delenv("IAM_JIT_DEV_INSECURE_SECRET", raising=False)
    monkeypatch.delenv("IAM_JIT_SES_SENDER", raising=False)
    monkeypatch.delenv("IAM_JIT_ALLOW_LOG_CHANNEL", raising=False)
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", "x" * 40)
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)
    caplog.set_level(logging.WARNING, logger="iam_jit.auth")

    # Default fail-closed: 503, no token in logs.
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    assert r.status_code == 503
    msgs = [rec.getMessage() for rec in caplog.records]
    assert not any("token=" in m for m in msgs)

    # Opt-in log channel.
    monkeypatch.setenv("IAM_JIT_ALLOW_LOG_CHANNEL", "1")
    from iam_jit.routes import auth as _auth_route
    _auth_route._reset_magic_link_ip_limiter_for_tests()
    caplog.clear()
    r2 = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    assert r2.status_code == 202
    msgs2 = [rec.getMessage() for rec in caplog.records]
    assert not any("token=" in m for m in msgs2), (
        f"log channel must redact the token URL; got: {msgs2}"
    )
    assert any("link_fingerprint=" in m for m in msgs2)


# ---------------------------------------------------------------------
# BB3-17: BB2-04 retest — Stripe atomic-claim store API behaves
#         atomically at the unit level too.
# ---------------------------------------------------------------------
def test_bb3_17_stripe_processed_events_store_atomic_claim(monkeypatch):
    """Unit-level closure retest: InMemoryProcessedEventsStore.claim
    is atomic. Mirrors the round-2 BB2-04 unit probe; pins behavior
    so a future refactor that loses atomicity will fail this test.

    Severity: N/A (defended). Round-3 closure retest."""
    from iam_jit.stripe_webhook import InMemoryProcessedEventsStore

    store = InMemoryProcessedEventsStore()
    event_id = "evt_bb3_17_atomic"
    barrier = threading.Barrier(4)
    results: dict[str, bool] = {}
    results_lock = threading.Lock()

    def attempt(name: str) -> None:
        barrier.wait()
        won = store.claim(event_id)
        with results_lock:
            results[name] = won

    threads = [threading.Thread(target=attempt, args=(f"t{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [n for n, won in results.items() if won]
    assert len(winners) == 1, (
        f"expected exactly one winner under 4-way contention; got "
        f"{results}"
    )


# ---------------------------------------------------------------------
# BB3-18: BB2-09 retest — magic-link XFH host-header poisoning
#         remains closed.
# ---------------------------------------------------------------------
def test_bb3_18_magic_link_xfh_poisoning_remains_closed(monkeypatch, tmp_path):
    """Round-2 BB2-09 closure retest. Even with XFH-trust enabled
    via `IAM_JIT_TRUST_FORWARDED_HOST=1` and an allowlist, an
    attacker hitting from a non-trusted-proxy peer cannot poison
    the magic-link host because their peer IP is not in the trusted
    proxy CIDR set AND the spoofed host is not in the public-host
    allowlist.

    Severity: N/A (defended). Round-3 closure retest."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_HOST", "1")
    monkeypatch.setenv("IAM_JIT_ALLOWED_PUBLIC_HOSTS", "iam-risk-score.com")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET)
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    r = c.post(
        "/api/v1/auth/magic-link",
        json={"email": "dev@example.com"},
        headers={"X-Forwarded-Host": "evil.attacker.example"},
    )
    assert r.status_code == 202
    link = r.json().get("dev_link") or ""
    assert "evil.attacker.example" not in link, (
        f"BB2-09 regressed: XFH poisoning produced an attacker-host "
        f"link: {link}"
    )
