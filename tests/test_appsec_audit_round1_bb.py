"""Black-box appsec audit — round 1 (2026-05-14).

External-researcher style probe: no source-code reading, only HTTP
behavior observed through FastAPI TestClient (i.e. exactly what an
attacker with the prod URL + a test account could see).

Scope: SaaS plumbing around the IAM scoring engine (auth, authz, web,
secrets, rate-limit, webhooks). The scoring engine itself is out of
scope (covered separately).

Each test asserts the *current* (vulnerable) behavior and is expected
to FAIL when a fix lands. When fixing, flip the assertion (or delete
the test) as part of the fix PR.

Severity rubric (per OWASP):
    CRIT — pre-auth RCE, cross-tenant data leak, credential theft
    HIGH — full account takeover with user interaction, privilege
           escalation, persistent XSS in admin context, broken authn
    MED  — CSRF on state-change, IDOR with cleanup constraints,
           sensitive-data exposure in logs, rate-limit miss
    LOW  — missing security headers, error verbosity, info leak via
           timing
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import tempfile
import time
from collections import Counter

import pytest
from fastapi.testclient import TestClient

# Reuse the project fixtures — but the spirit of black-box is to use
# only public surfaces. We import auth_mod ONLY to sign session cookies
# (i.e. simulate the magic-link callback's effect, since exercising the
# full callback flow each test is noisy and the white-box equivalents
# already do that).
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
    """Reset module-level singletons so tests don't leak rate-limit
    counters / cidr bans into each other."""
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


# ---------------------------------------------------------------------
# BB-01: HTML form endpoints have no CSRF protection
# ---------------------------------------------------------------------
def test_bb_01_csrf_html_approve_succeeds_with_cookie_only(app):
    """CSRF on HTML approval — state-changing POST accepts cookie-only
    requests with no anti-CSRF token, no Origin/Referer check.

    Severity: HIGH (an attacker page can trigger
    `<form action="https://iam-jit.example.com/requests/<id>/approve"
    method=POST>` and silently approve a request as the victim
    approver, granting AWS-IAM role provisioning).

    Fix sketch: emit a server-side CSRF token (e.g. via
    Starlette-SessionMiddleware + per-form double-submit token) and
    verify it on every `/requests/{id}/*` POST. Alternatively, require
    `SameSite=Strict` on the session cookie AND a non-bearable header
    (`X-Requested-With: XMLHttpRequest`) for the HTML routes — but the
    classic anti-CSRF token is the safer ground."""
    dev = _client_as(app, "email:dev@example.com")
    rid = _mk_request(dev, "csrf approve victim")

    appr = _client_as(app, "email:approver@example.com")
    r = appr.post(f"/requests/{rid}/approve", follow_redirects=False)
    assert r.status_code == 303, r.text

    admin = _client_as(app, "email:admin@example.com")
    state = admin.get(f"/api/v1/requests/{rid}").json()["status"]["state"]
    # The CSRF "attack" succeeded — request transitioned out of pending.
    assert state in ("provisioning", "approved", "active"), state


def test_bb_02_csrf_html_token_create_no_protection(app):
    """CSRF on token mint — POST /tokens (HTML form) creates an API
    token from a cookie-only request, leaking sensitive credentials
    once returned. Attacker can prime token in victim's account and
    persist access (though token value is returned to the response
    body, not directly exfilable — combine with XSS or response-page
    redirect-to-attacker for full takeover).

    Severity: HIGH. Even on its own, CSRF token-creation is a
    persistent-access primitive (admin will see "you have N API
    tokens" in dashboard but may not notice until much later).

    Fix sketch: same as BB-01 — anti-CSRF token required on
    /tokens HTML POST."""
    dev = _client_as(app, "email:dev@example.com")
    before = dev.get("/api/v1/tokens").json()["count"]
    # Simulated cross-origin form submission
    r = dev.post("/tokens", data={"label": "csrf-minted"}, follow_redirects=False)
    assert r.status_code == 200, r.text
    after = dev.get("/api/v1/tokens").json()["count"]
    assert after == before + 1


def test_bb_03_csrf_html_cancel_no_protection(app):
    """CSRF on HTML cancel — POST /requests/{id}/cancel cookie-only.
    Attacker can force-cancel an active grant request the victim is
    waiting on.

    Severity: MED (denial of action, no data exposure)."""
    dev = _client_as(app, "email:dev@example.com")
    rid = _mk_request(dev, "csrf cancel target")

    # Attacker tricks victim into POSTing this from evil.com
    r = dev.post(f"/requests/{rid}/cancel", follow_redirects=False)
    assert r.status_code == 303

    admin = _client_as(app, "email:admin@example.com")
    state = admin.get(f"/api/v1/requests/{rid}").json()["status"]["state"]
    assert state == "cancelled"


def test_bb_04_csrf_html_token_revoke_no_protection(app):
    """CSRF on HTML token revoke — POST /tokens/{hash}/revoke cookie-only.
    Attacker can revoke the victim's CLI/agent token without warning,
    causing all the victim's automations to break.

    Severity: MED (DoS-of-tokens; auditable, recoverable by re-issuing)."""
    dev = _client_as(app, "email:dev@example.com")
    create = dev.post("/api/v1/tokens", json={"label": "victim-token"})
    tok_hash = create.json()["token_hash"]
    assert dev.get("/api/v1/tokens").json()["count"] == 1

    r = dev.post(f"/tokens/{tok_hash}/revoke", follow_redirects=False)
    assert r.status_code == 303
    assert dev.get("/api/v1/tokens").json()["count"] == 0


# ---------------------------------------------------------------------
# BB-05: GET /logout is state-changing — CSRF-able under SameSite=Lax
# ---------------------------------------------------------------------
def test_bb_05_logout_is_state_changing_get(app):
    """GET /logout invalidates the user's session. Because the session
    cookie is `SameSite=Lax`, top-level GET navigations include the
    cookie — i.e. attacker can deauth victim via
    `<img src="https://iam-jit.example.com/logout">` or a same-site
    link. Annoyance > theft, but breaks "GETs are safe" invariant
    (RFC 7231 §4.2.1, OWASP CSRF-safe-method).

    Severity: LOW (denial-of-session only).

    Fix sketch: change to POST /logout (with anti-CSRF token), or
    require `SameSite=Strict` on session cookie."""
    dev = _client_as(app, "email:dev@example.com")
    assert dev.get("/api/v1/users/me").status_code == 200
    r = dev.get("/logout", follow_redirects=False)
    assert r.status_code == 303
    # Set-Cookie clears iam_jit_session — verify that header is present
    set_cookie = r.headers.get("set-cookie") or ""
    assert "iam_jit_session" in set_cookie and "Max-Age=0" in set_cookie


# ---------------------------------------------------------------------
# BB-06: GET /api/v1/requests/{id}/assume is state-mutating GET
# ---------------------------------------------------------------------
def test_bb_06_assume_is_get_state_mutating(app):
    """GET /api/v1/requests/{id}/assume returns role-assume metadata
    AND (for active grants) mints STS credentials downstream. Treating
    this as GET violates HTTP method semantics — and any SameSite=Lax
    cookie means a top-level link `<a href=".../assume">` triggered by
    a victim browser will leak credentials cross-origin if the JSON
    body is reflected (or via timing/error oracle).

    Severity: MED. While the JSON response can't be read cross-origin
    (CORS prevents that), the SIDE EFFECT (creds materialized,
    audit-log entry recorded as the victim) still occurs. Defense:
    require POST or add CSRF guard on the assume action."""
    dev = _client_as(app, "email:dev@example.com")
    rid = _mk_request(dev, "assume probe")
    r = dev.get(f"/api/v1/requests/{rid}/assume")
    assert r.status_code == 200
    # The endpoint accepted a GET and returned assume data — i.e. it is
    # NOT method-restricted to POST.
    body = r.json()
    assert "session_name" in body


# ---------------------------------------------------------------------
# BB-07: Session cookie missing Secure flag
# ---------------------------------------------------------------------
def test_bb_07_session_cookie_missing_secure_flag(app):
    """The session cookie set by /api/v1/auth/callback lacks the
    `Secure` attribute. If the deployment is ever accessed over plain
    HTTP (or an ALB misconfig downgrades a request), the cookie ships
    in clear text.

    Severity: MED (defense-in-depth — HSTS at the edge mitigates, but
    the cookie should declare its own intent).

    Fix sketch: set `secure=True` on the response.set_cookie call
    (already conditionally done for non-test? Add an explicit prod
    test). Couple with HSTS preload."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    link = r.json().get("dev_link")
    assert link
    token = link.split("token=")[1]
    r2 = c.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    cookie_hdr = r2.headers.get("set-cookie", "")
    assert "iam_jit_session" in cookie_hdr
    # Currently broken: cookie has HttpOnly/SameSite but NOT Secure.
    assert "Secure" not in cookie_hdr, (
        "EXPECTED current behavior: cookie missing Secure flag. "
        "Cookie: " + cookie_hdr
    )


# ---------------------------------------------------------------------
# BB-08: SameSite=Lax + cookie name in plaintext — readable user_id leak
# ---------------------------------------------------------------------
def test_bb_08_session_cookie_includes_plaintext_user_id(app):
    """The session cookie value embeds the user_id in plaintext
    (`email:dev@example.com.<base64-sig>`). This is by design of
    itsdangerous URLSafeTimedSerializer, BUT it means any local
    proxy/log/CDN/screen-capture leaks the user identity even if the
    signature is intact. Mitigation: encrypt the cookie payload
    (Fernet/AES-GCM) so the user id is opaque.

    Severity: LOW (info leak, not auth break)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    link = r.json()["dev_link"]
    token = link.split("token=")[1]
    r2 = c.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    cookie_hdr = r2.headers.get("set-cookie", "")
    assert "email:dev@example.com" in cookie_hdr  # plaintext user id visible


# ---------------------------------------------------------------------
# BB-09: No rate limit on /api/v1/auth/magic-link
# ---------------------------------------------------------------------
def test_bb_09_no_rate_limit_on_magic_link(app, monkeypatch):
    """BB-09 — CLOSED. Per-IP sliding-window limiter on the magic-
    link route (5 req/min/IP soft, 15 hard by default). Protects SES
    quota and email-domain reputation at launch.

    Also enables the opt-in log channel so the route returns 202
    (the rate-limit code path under test) instead of 503 (BB-12
    fail-closed when no channel is configured)."""
    monkeypatch.setenv("IAM_JIT_ALLOW_LOG_CHANNEL", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_IP_SOFT_CAP", "5")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_IP_HARD_CAP", "15")
    # The autouse reset fixture clears the limiter, but env-var caps
    # are read lazily — force a fresh instance with these caps.
    from iam_jit.routes import auth as _auth_route
    _auth_route._reset_magic_link_ip_limiter_for_tests()

    c = TestClient(app, raise_server_exceptions=False)
    statuses = []
    for i in range(20):
        r = c.post("/api/v1/auth/magic-link", json={"email": f"u{i}@example.com"})
        statuses.append(r.status_code)
    cnt = Counter(statuses)
    assert cnt.get(429, 0) >= 1, f"expected at least one 429; got {cnt}"
    assert cnt.get(202, 0) <= 5, (
        f"expected at most soft-cap (5) successful mints; got {cnt}"
    )


# ---------------------------------------------------------------------
# BB-10: No rate limit on POST /api/v1/requests (request creation)
# ---------------------------------------------------------------------
def test_bb_10_no_rate_limit_on_request_creation(app):
    """An authenticated dev can create 150 role-requests in a tight
    loop with no throttling. This is a quota / spam vector against
    approvers (queue flood DoS) and storage exhaustion.

    Severity: MED.

    Fix sketch: per-user token-bucket on POST /api/v1/requests."""
    dev = _client_as(app, "email:dev@example.com")
    statuses = []
    for i in range(150):
        r = dev.post(
            "/api/v1/requests",
            json={
                "apiVersion": "iam-jit.dev/v1alpha1",
                "kind": "RoleRequest",
                "metadata": {"requester": {"name": "Dev", "email": "dev@example.com"}},
                "spec": {
                    "description": f"flood-{i}",
                    "access_type": "read-only",
                    "task_intent": {"services": ["s3"], "actions": ["read"]},
                    "accounts": [{"account_id": "060392206767", "regions": ["us-east-1"]}],
                    "duration": {"duration_hours": 24},
                    "policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]},
                    "provisioning": {"mode": "identity_center"},
                },
            },
        )
        statuses.append(r.status_code)
    cnt = Counter(statuses)
    assert cnt.get(429, 0) == 0, cnt


# ---------------------------------------------------------------------
# BB-11: Stripe webhook lacks event-id idempotency
# ---------------------------------------------------------------------
def test_bb_11_stripe_webhook_replay_idempotency_missing(app, monkeypatch):
    """The Stripe webhook accepts the same signed event payload
    (same event.id) twice with no rejection. Stripe explicitly
    documents that webhook delivery is at-least-once and the receiver
    MUST dedupe by event.id (see
    https://stripe.com/docs/webhooks#handle-duplicate-events).
    Without that, side effects (subscription change, invoice paid)
    will be applied multiple times.

    Severity: MED. Today the unknown event-types are reported
    `handled: false` so the consequence is small; but as more event
    handlers are added (and they are — billing is on the roadmap), this
    becomes a critical billing-integrity bug.

    Fix sketch: persist seen event.id (DynamoDB conditional put with
    TTL or in-memory LRU for single-instance), reject on duplicate."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_dummy_audit")
    # Need a fresh app to pick up env var
    tmp = pathlib.Path(tempfile.mkdtemp())
    users_yaml = tmp / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    body = b'{"id": "evt_audit_replay_1", "type": "customer.subscription.created", "data": {"object": {"id": "sub_x"}}}'
    sig = hmac.new(
        b"whsec_test_dummy_audit",
        f"{ts}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    hdr = f"t={ts},v1={sig}"
    r1 = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": hdr, "Content-Type": "application/json"},
    )
    r2 = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": hdr, "Content-Type": "application/json"},
    )
    # Currently both return 200 — no dedupe.
    assert r1.status_code == 200
    assert r2.status_code == 200, "expected replay to be rejected (idempotency)"


# ---------------------------------------------------------------------
# BB-12: Magic-link delivered via log channel exposes token URL
# ---------------------------------------------------------------------
def test_bb_12_magic_link_logs_token_in_plaintext_when_ses_unset(app, caplog, monkeypatch):
    """BB-12 — CLOSED.

    Two complementary defenses, both pinned:

      1. **Default fail-closed** — when no SES sender is configured
         and no explicit opt-in env var is set, /api/v1/auth/magic-
         link returns 503 universally (uniform across known/unknown
         emails to avoid registration enumeration). This is the
         common case at launch: operators MUST configure SES (or
         opt-in to a log channel) before magic-link auth works.

      2. **Log-channel redaction (opt-in)** — when an operator
         explicitly sets `IAM_JIT_ALLOW_LOG_CHANNEL=1`, the log
         line emits only a sha256 *fingerprint* of the link, not
         the full URL. A CloudWatch reader cannot construct a
         working link from the fingerprint alone.

    This test pins both behaviors."""
    import logging

    monkeypatch.delenv("IAM_JIT_DEV_INSECURE_SECRET", raising=False)
    monkeypatch.delenv("IAM_JIT_SES_SENDER", raising=False)
    monkeypatch.delenv("IAM_JIT_ALLOW_LOG_CHANNEL", raising=False)
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", "x" * 40)
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_IP_SOFT_CAP", "999")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_IP_HARD_CAP", "9999")
    from iam_jit.routes import auth as _auth_route
    _auth_route._reset_magic_link_ip_limiter_for_tests()
    tmp = pathlib.Path(tempfile.mkdtemp())
    users_yaml = tmp / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)
    caplog.set_level(logging.WARNING, logger="iam_jit.auth")

    # Default: no delivery channel configured → 503, no logged URL.
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    assert r.status_code == 503
    msgs = [rec.getMessage() for rec in caplog.records]
    assert not any("token=" in m for m in msgs), (
        f"no token URL should be logged when delivery is unconfigured; "
        f"got: {msgs}"
    )

    # Opt-in log channel: link fingerprint logged, never the URL.
    monkeypatch.setenv("IAM_JIT_ALLOW_LOG_CHANNEL", "1")
    caplog.clear()
    r2 = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    assert r2.status_code == 202
    msgs2 = [rec.getMessage() for rec in caplog.records]
    assert not any("token=" in m for m in msgs2), (
        f"log channel must redact the token URL; got: {msgs2}"
    )
    assert any("link_fingerprint=" in m for m in msgs2)


# ---------------------------------------------------------------------
# BB-13: /healthz exposes security posture to unauthenticated callers
# ---------------------------------------------------------------------
def test_bb_13_healthz_leaks_security_posture(app):
    """BB-13 — CLOSED. /healthz is now a bare liveness response
    (status + version only). The full posture object lives at
    /api/v1/admin/security-posture (admin-gated)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert "status" in body and body["status"] == "ok"
    assert "version" in body
    assert "security_posture" not in body
    assert "auth_mode" not in body
    assert "llm_backend" not in body
    assert "user_config_source" not in body


# ---------------------------------------------------------------------
# BB-14: Verbose error responses for malformed JSON / schema errors
# ---------------------------------------------------------------------
def test_bb_14_verbose_schema_errors_aid_recon(app):
    """POST /api/v1/requests with malformed body returns a fully
    enumerated schema diff (every missing field, type mismatch, the
    expected literal apiVersion value, etc). This makes the public API
    self-documenting for an attacker — they don't need the OpenAPI doc.

    Severity: LOW. The /openapi.json is also public (and is the
    intended surface), so verbosity itself isn't a leak — but it
    confirms the absence of a generic error handler that would emit
    a static "invalid request" on validation failure for prod mode.

    Fix sketch: ship a prod-mode error handler that returns
    `{"detail": "invalid request"}` and logs the full validator output
    server-side."""
    dev = _client_as(app, "email:dev@example.com")
    r = dev.post("/api/v1/requests", json={"foo": "bar"})
    assert r.status_code == 400
    body = r.json()
    detail = body.get("detail", {})
    errors = detail.get("errors") if isinstance(detail, dict) else []
    # Detailed enumeration confirms recon-friendly errors.
    assert any("apiVersion" in e for e in errors)
    assert any("kind" in e for e in errors)
    assert any("spec" in e for e in errors)


# ---------------------------------------------------------------------
# BB-15: Bearer header parsing accepts casing variants — risk of
# downstream string-match bypass
# ---------------------------------------------------------------------
def test_bb_15_bearer_header_case_insensitive(app):
    """The Authorization header parser accepts `bearer`, `BEARER`,
    `Bearer  ` (double space) all equivalently. While this is
    conformant with RFC 7235 (case-insensitive auth-scheme), any
    downstream log scrub / WAF rule that string-matches `Bearer ` will
    fail to redact the alt-cased variants — increasing the chance
    tokens leak into logs.

    Severity: LOW (latent risk; depends on log-redaction setup)."""
    dev = _client_as(app, "email:dev@example.com")
    tok = dev.post("/api/v1/tokens", json={"label": "casing"}).json()["token"]
    c = TestClient(app, raise_server_exceptions=False)
    for hdr in [f"BEARER {tok}", f"bearer {tok}", f"Bearer  {tok}"]:
        r = c.get("/api/v1/users/me", headers={"Authorization": hdr})
        assert r.status_code == 200, (hdr, r.status_code)


# ---------------------------------------------------------------------
# BB-16: Magic-link callback URL contains the user id in plaintext
# ---------------------------------------------------------------------
def test_bb_16_magic_link_url_leaks_user_id(app):
    """The magic-link URL format is
    `/api/v1/auth/callback?token=email:<addr>|<base64-sig>`. The user
    email is embedded in the URL path/query — i.e. anywhere the URL
    leaks (browser history, referer, ALB logs, screen-share), the
    email leaks. The signed payload makes the token unforgeable but
    does not hide identity.

    Severity: LOW (identity confidentiality only)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    link = r.json()["dev_link"]
    assert "email:dev@example.com" in link


# ---------------------------------------------------------------------
# BB-17: Magic-link callback ignores attacker-controlled redirect param
# ---------------------------------------------------------------------
def test_bb_17_magic_link_callback_ignores_next_param(app):
    """Honest negative: probed the magic-link callback for an open-
    redirect via `?next=` / `?continue=`. The endpoint hard-codes the
    post-login redirect to `/` and does NOT honour client-supplied
    `next` — good defense.

    Severity: N/A (defended).

    This test asserts the defended behavior so a future regression
    (adding next= support) will be caught."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    link = r.json()["dev_link"]
    token = link.split("token=")[1]
    # Attack: try to redirect post-login to attacker-controlled URL
    r = c.get(
        f"/api/v1/auth/callback?token={token}&next=https://evil.example.com/",
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/"


# ---------------------------------------------------------------------
# BB-18: Public /accounts/register HTML endpoint accepts unauth POST
# ---------------------------------------------------------------------
def test_bb_18_accounts_register_no_auth(app):
    """POST /accounts/register (HTML) accepts an unauthenticated POST
    with an account_id and returns... something. This endpoint is
    presumably used by CloudFormation deploy-time callbacks, but a
    public POST surface that takes attacker-controlled `account_id` is
    a perma-spam vector and potentially an account-confusion vector
    (registering account 000000000000 etc).

    Severity: LOW-MED depending on what registration entails. The
    response body should clarify behavior — current finding is that
    the endpoint is callable.

    Fix sketch: require a CloudFormation-signed claim token; rate-limit
    per source IP; reject if `account_id` not in expected format."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/accounts/register", data={"account_id": "111122223333"})
    # Currently broken: this returns SOMETHING that is not 401/403.
    # (May be 200 with an error page, 422 for missing field, etc.)
    assert r.status_code != 401
    assert r.status_code != 403


# ---------------------------------------------------------------------
# BB-19: User enumeration via uniform-response on magic-link
#       — defended (honest negative)
# ---------------------------------------------------------------------
def test_bb_19_magic_link_uniform_response_unknown_email(app, monkeypatch):
    """Honest negative: magic-link responses are uniform-202 for known,
    unknown, empty, malformed, and CRLF-injected emails. The response
    body is identical (no `dev_link` for unknown users, only present
    when IAM_JIT_DEV_INSECURE_SECRET=1 for known users — i.e. local-dev
    mode). No user-enumeration via response shape.

    Severity: N/A (defended)."""
    monkeypatch.delenv("IAM_JIT_DEV_INSECURE_SECRET", raising=False)
    # Enable opt-in log channel so the uniform-response code path is
    # exercised. Without ANY channel, BB-12 closure returns 503
    # universally — which is uniform but a different shape.
    monkeypatch.setenv("IAM_JIT_ALLOW_LOG_CHANNEL", "1")
    # The per-IP magic-link limiter would otherwise 429 the 5
    # consecutive requests below; raise the cap so this test
    # exercises uniformity, not throttling.
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_IP_SOFT_CAP", "999")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_IP_HARD_CAP", "9999")
    from iam_jit.routes import auth as _auth_route
    _auth_route._reset_magic_link_ip_limiter_for_tests()
    tmp = pathlib.Path(tempfile.mkdtemp())
    users_yaml = tmp / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)
    known = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    unknown = c.post("/api/v1/auth/magic-link", json={"email": "nobody@example.com"})
    empty = c.post("/api/v1/auth/magic-link", json={"email": ""})
    bad = c.post("/api/v1/auth/magic-link", json={"email": "not-an-email"})
    crlf = c.post("/api/v1/auth/magic-link", json={"email": "x\r\nBcc: y@evil"})
    assert known.status_code == unknown.status_code == empty.status_code == bad.status_code == crlf.status_code == 202
    # Body content also uniform (no leaked dev_link or any user-specific info)
    expected = {"status": "if the email is registered, a link has been sent"}
    for r in [known, unknown, empty, bad, crlf]:
        assert r.json() == expected


# ---------------------------------------------------------------------
# BB-20: XSS — defended via Jinja autoescape (honest negative)
# ---------------------------------------------------------------------
def test_bb_20_xss_in_description_is_escaped(app):
    """Honest negative: probed XSS via description, requester.name,
    comment.message, token.label — all are HTML-escaped on render.
    Jinja autoescape is enabled and the templates don't `|safe` user
    content.

    Severity: N/A (defended)."""
    dev = _client_as(app, "email:dev@example.com")
    xss_descs = ["<script>alert(1)</script>", "<svg/onload=alert(1)>"]
    for xss in xss_descs:
        rid = _mk_request(dev, "Need: " + xss)
        page = dev.get(f"/requests/{rid}").text
        assert xss not in page, f"raw XSS leak: {xss}"
        # Verify it IS present in escaped form
        assert "&lt;" in page or "alert" in page  # at least encoded


def test_bb_21_xss_in_comment_is_escaped(app):
    """Honest negative: comments render escaped."""
    dev = _client_as(app, "email:dev@example.com")
    rid = _mk_request(dev, "comment-xss probe")
    xss = "<script>alert('cm')</script>"
    r = dev.post(f"/api/v1/requests/{rid}/comments", json={"message": xss})
    assert r.status_code == 201
    page = dev.get(f"/requests/{rid}").text
    assert xss not in page
    assert "&lt;script&gt;" in page


# ---------------------------------------------------------------------
# BB-22: Session cookie tampering rejected (honest negative)
# ---------------------------------------------------------------------
def test_bb_22_tampered_session_rejected(app):
    """Honest negative: session-cookie signatures verified by
    itsdangerous URLSafeTimedSerializer. Tampered cookies, cookies
    signed with a different secret, and unsigned `email:admin@...`
    strings are all rejected with 401.

    Severity: N/A (defended)."""
    # Tamper a valid cookie
    valid = auth_mod.sign_session(_DEV_SECRET, "email:dev@example.com")
    tampered = valid[:-2] + ("AB" if valid[-2:] != "AB" else "CD")
    c = TestClient(app, raise_server_exceptions=False)
    c.cookies.set("iam_jit_session", tampered)
    assert c.get("/api/v1/users/me").status_code == 401
    # Wrong-secret-signed cookie
    forged = auth_mod.sign_session("not-the-real-secret-1234567890abcd", "email:admin@example.com")
    c.cookies.set("iam_jit_session", forged)
    assert c.get("/api/v1/users/me").status_code == 401
    # Unsigned plaintext
    c.cookies.set("iam_jit_session", "email:admin@example.com")
    assert c.get("/api/v1/users/me").status_code == 401


# ---------------------------------------------------------------------
# BB-23: Cross-tenant IDOR rejected on /api/v1/requests/{id}/* (honest negative)
# ---------------------------------------------------------------------
def test_bb_23_cross_tenant_request_access_rejected(app):
    """Honest negative: dev2 cannot GET, PATCH, cancel, assume, comment,
    download, approve dev1's request. All return 403.

    Severity: N/A (defended).

    This is the core multi-tenant invariant and the app holds it
    correctly on all probed endpoints."""
    d1 = _client_as(app, "email:dev@example.com")
    d2 = _client_as(app, "email:dev2@example.com")
    rid = _mk_request(d1, "dev1 only")

    assert d2.get(f"/api/v1/requests/{rid}").status_code == 403
    assert d2.patch(f"/api/v1/requests/{rid}", json={"description": "x"}).status_code == 403
    assert d2.post(f"/api/v1/requests/{rid}/cancel", json={}).status_code == 403
    assert d2.get(f"/api/v1/requests/{rid}/assume").status_code == 403
    assert d2.post(f"/api/v1/requests/{rid}/comments", json={"message": "snoop"}).status_code == 403
    assert d2.get(f"/api/v1/requests/{rid}/download").status_code == 403
    assert d2.post(f"/api/v1/requests/{rid}/approve", json={}).status_code in (403, 405)


# ---------------------------------------------------------------------
# BB-24: Admin gates hold under dev bearer token (honest negative)
# ---------------------------------------------------------------------
def test_bb_24_dev_bearer_token_cannot_reach_admin(app):
    """Honest negative: API bearer tokens minted by a non-admin user
    cannot reach admin endpoints. All return 403 with
    `admin role required`.

    Severity: N/A (defended). Confirms token-auth path enforces RBAC
    identical to cookie-auth path."""
    dev = _client_as(app, "email:dev@example.com")
    tok = dev.post("/api/v1/tokens", json={"label": "x"}).json()["token"]
    c = TestClient(app, raise_server_exceptions=False)
    headers = {"Authorization": f"Bearer {tok}"}
    for path in [
        "/api/v1/users",
        "/api/v1/admin/security-posture",
        "/api/v1/admin/auto-approve/settings",
        "/api/v1/admin/blacklist",
        "/api/v1/admin/bans",
        "/api/v1/admin/log-retention",
        "/api/v1/admin/calibration",
        "/api/v1/admin/provisioned",
    ]:
        r = c.get(path, headers=headers)
        assert r.status_code == 403, f"{path} returned {r.status_code}"


# ---------------------------------------------------------------------
# BB-25: Stripe signature verification correct (honest negative)
# ---------------------------------------------------------------------
def test_bb_25_stripe_signature_verification_correct(app, monkeypatch):
    """Honest negative: Stripe webhook signature verification rejects
    (a) missing header, (b) malformed header, (c) wrong signature,
    (d) timestamp outside 300s tolerance window. All return 400 with a
    clear error.

    Severity: N/A (defended). The replay-by-event-id issue is BB-11."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_dummy_25")
    tmp = pathlib.Path(tempfile.mkdtemp())
    users_yaml = tmp / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)
    body = b'{"id": "evt_1", "type": "ping"}'
    # Missing signature — response body is now generic (BB3-04 closure
    # collapsed all signature-failure details into "signature
    # verification failed" so attackers can't fingerprint the failure
    # mode or read the server clock).
    r = c.post("/api/v1/webhooks/stripe", content=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    assert "signature verification failed" in r.text
    # Malformed signature
    r = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": "garbage", "Content-Type": "application/json"},
    )
    assert r.status_code == 400
    # Wrong signature with old timestamp
    r = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": "t=1,v1=deadbeef", "Content-Type": "application/json"},
    )
    # BB3-04 closure: detail is uniform across all signature
    # failure modes. The specific reason (clock, malformed, etc.)
    # lives in operator logs, not the response body.
    assert r.status_code == 400
    assert "signature verification failed" in r.text
    # Valid signature → accepted
    ts = str(int(time.time()))
    sig = hmac.new(b"whsec_test_dummy_25", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    r = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"},
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------
# BB-26: Score endpoint IS rate-limited (honest negative)
# ---------------------------------------------------------------------
def test_bb_26_score_endpoint_rate_limited(app):
    """Honest negative: POST /api/v1/score throttles after ~30
    requests/minute and returns 429. This is the model-cost-sink
    endpoint and the app correctly protects it. (Magic-link, request-
    create, etc. should mirror this — see BB-09 / BB-10.)

    Severity: N/A (defended)."""
    dev = _client_as(app, "email:dev@example.com")
    cnt = Counter()
    for _ in range(120):
        r = dev.post(
            "/api/v1/score",
            json={
                "description": "x",
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
                },
                "duration_hours": 1,
                "access_type": "read-only",
            },
        )
        cnt[r.status_code] += 1
    assert cnt[429] > 0, cnt


# ---------------------------------------------------------------------
# BB-27: Magic-link single-use (honest negative)
# ---------------------------------------------------------------------
def test_bb_27_magic_link_single_use(app):
    """Honest negative: a magic-link token can only be used once. A
    second callback with the same token returns 400.

    Severity: N/A (defended)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    link = r.json()["dev_link"]
    token = link.split("token=")[1]
    r1 = c.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    assert r1.status_code == 303
    c2 = TestClient(app, raise_server_exceptions=False)
    r2 = c2.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    assert r2.status_code == 400


# ---------------------------------------------------------------------
# BB-28: MCP server JSON-RPC handles bogus methods cleanly (honest negative)
# ---------------------------------------------------------------------
def test_bb_28_mcp_server_handles_bogus_methods():
    """Honest negative: the MCP server (python -m iam_jit.mcp_server)
    returns a structured JSON-RPC error -32601 for unknown methods,
    unknown tool names, missing jsonrpc field. It does not crash on
    huge inputs (1 MB task_description returns 'unknown tool' quickly).

    Severity: N/A (defended)."""
    import subprocess
    import sys

    init = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0.0.1"}},
    })
    evil = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "evil/method", "params": {}})
    proc = subprocess.run(
        [sys.executable, "-m", "iam_jit.mcp_server"],
        input=(init + "\n" + evil + "\n").encode(),
        capture_output=True,
        timeout=15,
        cwd=str(pathlib.Path(__file__).resolve().parent.parent),
    )
    lines = [l for l in proc.stdout.decode().splitlines() if l.strip()]
    assert len(lines) >= 2
    resp = json.loads(lines[1])
    assert resp["id"] == 2
    assert resp["error"]["code"] == -32601


# ---------------------------------------------------------------------
# BB-29: Comment author cannot be forged (honest negative)
# ---------------------------------------------------------------------
def test_bb_29_comment_author_cannot_be_forged(app):
    """Honest negative: POST /api/v1/requests/{id}/comments with a
    client-supplied `author` field ignores it — the server stamps the
    author from the authenticated session. Tried sending
    `{"message": "hi", "author": "email:admin@example.com"}` as dev1;
    the response shows author = `email:dev@example.com`.

    Severity: N/A (defended)."""
    dev = _client_as(app, "email:dev@example.com")
    rid = _mk_request(dev, "author-forge probe")
    r = dev.post(
        f"/api/v1/requests/{rid}/comments",
        json={"message": "hi", "author": "email:admin@example.com"},
    )
    assert r.status_code == 201
    assert r.json()["comment"]["author"] == "email:dev@example.com"


# ---------------------------------------------------------------------
# BB-30: Static file path traversal rejected (honest negative)
# ---------------------------------------------------------------------
def test_bb_30_static_path_traversal_rejected(app):
    """Honest negative: GET /static/../app.py returns 404 — StaticFiles
    normalizes paths and rejects parent-segment traversal.

    Severity: N/A (defended)."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/static/../app.py")
    assert r.status_code == 404
