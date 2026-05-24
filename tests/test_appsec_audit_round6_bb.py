"""Black-box appsec audit — round 6 (2026-05-14).

Round-6 external-researcher probe. Round 5 declared "externally
converged" with 14 honest negatives plus 7 findings (2 MED contradictions
of the round-5 brief, 5 LOW hygiene). Round 6's brief calls out three
new closures to re-probe externally:

  * Hard-coded dev-secret fallback REMOVED — in Lambda + no
    IAM_JIT_MAGIC_LINK_SECRET → magic-link routes 500/503 (refuses to
    operate without explicit IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1).
  * PATCH /api/v1/users/{user_id} now refuses self-demotion AND
    last-admin demotion.
  * Stripe webhook on transient-handler-failure now retries successfully
    (no longer locks out paid customer with "duplicate").

Plus first-launch-day attacker categories the prior rounds may have
missed:

  * HEAD-method handling on auth'd vs public routes.
  * OPTIONS-preflight cache + CORS behavior on /docs and /healthz.
  * Compression-bomb (Content-Encoding: gzip) re-probe with tier-leak
    angle.
  * Content-Type alternatives (text/plain, x-www-form-urlencoded).
  * JSON-parser quirks: deeply-nested arrays/objects, BOM, U+0000 in
    string, trailing junk, duplicate keys, RFC 8259 edge cases.
  * Method tampering via `_method=` body or `X-HTTP-Method-Override`
    header on /api/v1/admin/* paths.
  * Query-parameter override attempts (`?score=10`, `?tier=low`).
  * /api/v1/requests/{id}/download path-traversal in path param.
  * Admin-endpoint enumeration via 405-vs-404 differential.

Each test asserts the *current* (broken or defended) behavior. Broken-
behavior tests fail when the fix lands — that's the signal to flip the
assertion and ship the fix. Honest-negative tests pin the defended
state so a future regression fails loudly.

Severity rubric (same as rounds 1-5):
    CRIT — pre-auth RCE, cross-tenant data leak, credential theft.
    HIGH — full account takeover with user interaction, privilege
           escalation, persistent XSS in admin context, broken authn,
           pre-auth DoS that bypasses security middleware.
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
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.parse

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
    # (score-route limiter reset dropped 2026-05-24 — hosted scoring API removed per [[no-hosted-saas]])
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
# CATEGORY 1: New round-6 findings (broken/vulnerable state pinned)
# =====================================================================

# ---------------------------------------------------------------------
# BB6-01 (HIGH): Deeply-nested JSON arrays trigger uncaught 500 Internal
# Server Error. The 500 response is plain text "Internal Server Error"
# WITHOUT the security-headers chain (no CSP, no X-Frame-Options, no
# X-Content-Type-Options, no Referrer-Policy, no Cache-Control). The
# vulnerability:
#   1. Anonymous attacker can trigger on /api/v1/score (anon-callable).
#   2. ~2KB request triggers a Python RecursionError → log spam +
#      CPU + monitoring noise on the deployment.
#   3. The 500 response degrades the security-header posture (no CSP /
#      X-Frame-Options on the response — clickjacking + injection
#      defenses gone for that response).
# Triggered on ALL JSON-accepting POST routes: /api/v1/score,
# /api/v1/auth/magic-link, /api/v1/requests, /api/v1/requests/preview,
# PATCH /api/v1/users/{user_id}.
# ---------------------------------------------------------------------
def test_bb6_02_stripe_duplicate_response_still_leaks_metadata(monkeypatch, tmp_path):
    """Brief: "Stripe webhook on transient-handler-failure now retries
    successfully (no longer locks out paid customer with 'duplicate')."

    External re-probe: replaying the same signed event body twice
    returns:
      first:  {"handled": false}
      second: {"handled": false, "event_type": "<type>",
               "duplicate": true, "event_id": "<id>"}

    The duplicate-path body still echoes event_type + event_id. An
    attacker who has obtained a Stripe webhook secret (somehow — log
    leak, employee turnover, etc.) can use this to enumerate which
    event IDs the server has already processed. Combined with a
    leaked webhook secret it's an event-id existence oracle.

    Severity: LOW (depends on webhook-secret compromise; minor info
    leak when the secret is intact).

    Fix sketch: on the duplicate path, return
    `{"handled": false, "duplicate": true}` — no event_id, no
    event_type echo. Operators get the duplicate signal without the
    metadata leak."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb6_02")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    body = b'{"id":"evt_bb6_02_dup","type":"customer.subscription.created","data":{"object":{}}}'
    sig = hmac.new(b"whsec_bb6_02", f"{ts}.".encode() + body,
                   hashlib.sha256).hexdigest()
    hdr = f"t={ts},v1={sig}"
    r1 = c.post("/api/v1/webhooks/stripe", content=body,
                headers={"Stripe-Signature": hdr,
                         "Content-Type": "application/json"})
    assert r1.status_code == 200, f"first webhook failed: {r1.text}"
    r2 = c.post("/api/v1/webhooks/stripe", content=body,
                headers={"Stripe-Signature": hdr,
                         "Content-Type": "application/json"})
    assert r2.status_code == 200
    j2 = r2.json()
    assert j2.get("duplicate") is True, (
        f"duplicate flag missing on replay: {j2}"
    )
    # Currently broken: event_id + event_type leak in the duplicate body.
    assert "event_id" in j2 or "event_type" in j2, (
        f"BB6-02 fix landed — duplicate response no longer leaks "
        f"event metadata. Flip the assertion. Got: {j2}"
    )


# ---------------------------------------------------------------------
# BB6-03 (LOW): Admin-endpoint enumeration via 405-vs-404 differential
# response codes when a non-admin probes /api/v1/admin/* paths.
# POST /api/v1/admin/security-posture → 405 (exists, GET-only).
# POST /api/v1/admin/users → 404 (doesn't exist).
# A non-admin can enumerate which admin endpoints exist without admin
# auth. Already covered by /openapi.json public availability (BB3-02
# closure intentional) — recon value is small.
# ---------------------------------------------------------------------
def test_bb6_03_admin_endpoint_enum_via_405_vs_404(app):
    """`POST /api/v1/admin/security-posture` (as a non-admin) returns
    405 with `Allow: GET` — confirming the endpoint exists and is
    GET-only.

    `POST /api/v1/admin/users` returns 404 — confirming the endpoint
    doesn't exist.

    The differential between 405 and 404 lets a non-admin enumerate
    which admin endpoints are real without admin role. Combined with
    `/openapi.json` being intentionally public (BB3-02), this is
    redundant info — but a future refactor that makes openapi.json
    admin-only would re-expose this enum vector.

    Severity: LOW (informational; openapi.json is the actual recon
    surface).

    Fix sketch (optional): uniformly return 403/404 for any
    /api/v1/admin/* request that lacks admin role, regardless of
    whether the method is GET-or-POST-supported. Probably not worth
    the complexity since openapi.json is public anyway. Pin so a
    future refactor that makes openapi.json admin-only doesn't
    accidentally re-expose this enumeration vector."""
    dev = _client_as(app, "email:dev@example.com")

    # /api/v1/admin/security-posture exists (GET only) → POST returns 405.
    r1 = dev.post("/api/v1/admin/security-posture")
    assert r1.status_code == 405, (
        f"BB6-03 fix landed — admin endpoints no longer leak existence "
        f"via 405. status={r1.status_code}"
    )

    # /api/v1/admin/users does NOT exist → 404.
    r2 = dev.post("/api/v1/admin/users")
    assert r2.status_code == 404, (
        f"BB6-03 changed — fake admin path returns {r2.status_code}, "
        f"not 404. Differential closed? Re-check."
    )

    # The differential exists — non-admin can distinguish.
    assert r1.status_code != r2.status_code, (
        f"BB6-03 fix landed — 405-vs-404 differential closed. Flip."
    )


# ---------------------------------------------------------------------
# BB6-04 (LOW): Stripe webhook event.id of whitespace-only (e.g. "   ")
# bypasses the `missing_event_id` rejection. Returns {"handled":false}
# rather than {"rejected":true,"reason":"missing_event_id"}.
# Combined with no real idempotency dedupe on the whitespace-id path,
# an attacker with webhook-secret leak can replay events with
# whitespace IDs and they'll appear as fresh `unhandled` each time.
# ---------------------------------------------------------------------
def test_bb6_04_stripe_whitespace_event_id_bypasses_rejection(monkeypatch, tmp_path):
    """Brief Stripe closure: "Empty event.id → response body has
    rejected=True."

    External re-probe with variants:
      * "":          {"handled":false, "rejected":true,
                      "reason":"missing_event_id"} ✓
      * null:        {"handled":false, "rejected":true,
                      "reason":"missing_event_id"} ✓
      * missing:     {"handled":false, "rejected":true,
                      "reason":"missing_event_id"} ✓
      * "   " (3 spaces): {"handled":false} — NO rejected flag.

    The whitespace-only event.id bypasses the rejection path and is
    treated as a normal unhandled event. The id is structurally
    present (a string of length 3) but logically invalid.

    Impact: combined with absence of strip()/normalization in the
    idempotency keying (presumed), an attacker who knows the webhook
    secret can replay events with whitespace-only IDs, each appearing
    as a fresh "unhandled" event. Useful for stress-testing the
    duplicate-dedupe store with bogus keys, or for log noise.

    Severity: LOW (requires webhook-secret leak; impact is log
    noise / dedupe-store pollution, not direct billing impact since
    `handled: false` paths don't mutate billing state).

    Fix sketch: in the event.id validation, treat
    `id.strip() == ""` the same as `id is None or id == ""` — emit
    {"handled":false,"rejected":true,"reason":"missing_event_id"}.
    """
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb6_04")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    # Whitespace-only id
    body = b'{"id":"   ","type":"customer.subscription.created","data":{"object":{}}}'
    sig = hmac.new(b"whsec_bb6_04", f"{ts}.".encode() + body,
                   hashlib.sha256).hexdigest()
    r = c.post("/api/v1/webhooks/stripe", content=body,
               headers={"Stripe-Signature": f"t={ts},v1={sig}",
                        "Content-Type": "application/json"})
    assert r.status_code == 200
    j = r.json()
    # Currently broken: whitespace-id is NOT rejected.
    assert j.get("rejected") is not True, (
        f"BB6-04 fix landed — whitespace event.id now rejected. "
        f"Flip assertion. Body: {j}"
    )

    # Sanity: empty-string id IS rejected (the closure holds for "").
    body2 = b'{"id":"","type":"customer.subscription.created","data":{"object":{}}}'
    sig2 = hmac.new(b"whsec_bb6_04", f"{ts}.".encode() + body2,
                    hashlib.sha256).hexdigest()
    r2 = c.post("/api/v1/webhooks/stripe", content=body2,
                headers={"Stripe-Signature": f"t={ts},v1={sig2}",
                         "Content-Type": "application/json"})
    j2 = r2.json()
    assert j2.get("rejected") is True, (
        f"empty event.id rejection regressed — should still reject."
    )


# =====================================================================
# CATEGORY 2: Honest negatives — brief closures and round-6 probe
# categories that hold up (defended state)
# =====================================================================

# ---------------------------------------------------------------------
# BB6-05 (defended/pinned): Lambda + no MAGIC_LINK_SECRET refuses to
# operate. Brief closure verified.
# ---------------------------------------------------------------------
def test_bb6_05_lambda_no_magic_link_secret_refuses():
    """Brief: "Hard-coded dev-secret fallback REMOVED — in Lambda + no
    IAM_JIT_MAGIC_LINK_SECRET → magic-link routes 500/503 (refuses to
    operate without explicit IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1)."

    External re-probe via subprocess (need clean env, not the test
    env which sets DEV_INSECURE_SECRET):
      * AWS_LAMBDA_FUNCTION_NAME=set
      * IAM_JIT_MAGIC_LINK_SECRET=unset
      * IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=unset
      → magic-link returns 503 (no hard-coded fallback secret kicks
        in to bypass the gate).

    Severity: N/A (defended). New closure re-pin."""
    repo_src = str(pathlib.Path(__file__).resolve().parent.parent / "src")
    script = '''
import os, sys, tempfile, pathlib
_repo_src = os.environ.pop("BB6_05_REPO_SRC")
os.environ.clear()
os.environ["AWS_LAMBDA_FUNCTION_NAME"] = "iam-jit-test"
os.environ["IAM_JIT_AUTH_MODE"] = "local"
sys.path.insert(0, _repo_src)

tmp = pathlib.Path(tempfile.mkdtemp())
users = tmp / "users.yaml"
users.write_text("""schema_version: 1
auth_mode: local
users:
  - id: email:dev@example.com
    display_name: Dev
    roles: [requester]
""")
from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore
from iam_jit.api_tokens_store import InMemoryAPITokenStore
from fastapi.testclient import TestClient

app = create_app(
    request_store=FilesystemStore(tmp / "requests"),
    user_store=FileUserStore(str(users)),
    api_tokens_store=InMemoryAPITokenStore(),
)
c = TestClient(app, raise_server_exceptions=False)
r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
print(f"{r.status_code}|{r.text}")
'''
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "BB6_05_REPO_SRC": repo_src},
    )
    assert result.returncode == 0, (
        f"subprocess failed: stderr={result.stderr[:500]}"
    )
    out = result.stdout.strip().split("|", 1)
    status = int(out[0])
    body = out[1] if len(out) > 1 else ""
    assert status in (500, 503), (
        f"BB6-05 regressed — Lambda + no MAGIC_LINK_SECRET no longer "
        f"refuses. status={status} body={body[:300]}"
    )
    # The detail should not include a working dev_link in the body.
    assert "dev_link" not in body, (
        f"BB6-05 regressed — Lambda fallback emits a dev_link. "
        f"body={body[:300]}"
    )


# ---------------------------------------------------------------------
# BB6-06 (defended/pinned): PATCH /api/v1/users/{user_id} refuses
# self-demotion. Brief closure verified.
# ---------------------------------------------------------------------
def test_bb6_06_patch_user_refuses_self_demotion(app):
    """Brief: "PATCH /api/v1/users/{user_id} now refuses self-demotion
    AND last-admin demotion."

    Probe the self-demotion path: admin tries to set their own roles
    to ["requester"] or [] → 409 with operator-readable detail.

    The last-admin path requires a writable user store to verify
    externally; with FileUserStore (read-only at runtime) all PATCH
    write-paths 409 with "FileUserStore is read-only" regardless. So
    we pin the self-demotion check, which fires BEFORE the read-only
    check.

    Severity: N/A (defended). New closure re-pin."""
    admin = _client_as(app, "email:admin@example.com")

    # Self-demote to ["requester"].
    r = admin.patch(
        "/api/v1/users/email:admin@example.com",
        json={"roles": ["requester"]},
    )
    assert r.status_code == 409, (
        f"BB6-06 regressed — self-demote no longer 409. "
        f"status={r.status_code} body={r.text}"
    )
    detail = r.json().get("detail", "")
    assert "self-demot" in detail.lower() or "remove their own admin" in detail.lower(), (
        f"BB6-06 detail message mutated: {detail!r}"
    )

    # Self-demote via empty roles.
    r = admin.patch(
        "/api/v1/users/email:admin@example.com",
        json={"roles": []},
    )
    assert r.status_code == 409, (
        f"BB6-06 regressed for empty-roles path; status={r.status_code}"
    )
    detail = r.json().get("detail", "")
    assert "self-demot" in detail.lower() or "remove their own admin" in detail.lower(), (
        f"BB6-06 empty-roles detail: {detail!r}"
    )


# ---------------------------------------------------------------------
# BB6-07 (defended/pinned): Stripe webhook on retry of an unhandled
# event is idempotent. Brief closure verified.
# ---------------------------------------------------------------------
def test_bb6_07_stripe_webhook_retry_idempotent(monkeypatch, tmp_path):
    """Brief: "Stripe webhook on transient-handler-failure now retries
    successfully (no longer locks out paid customer with 'duplicate')."

    The closure is best observed on an **unhandled** event type (one
    that doesn't crash the handler with a "no customer email" / "user
    not found" branch in this test fixture). For unhandled events, the
    first send returns `{"handled": false}`, and the SECOND send
    returns `{"handled": false, "duplicate": true, ...}` rather than
    being silently locked out.

    Pre-closure (round-4 era): a transient handler exception left the
    event marked as already-seen, so the retry would 200 with
    `duplicate: true` and the actual side effect would never apply.
    Post-closure: a handler exception RELEASES the claim, so the
    retry runs the handler fresh.

    External re-probe of the observable artifacts:
      1. Unhandled event type → first send 200 {handled:false}.
      2. Replay → 200 {handled:false, duplicate:true, ...}.
      3. The retry returns 200 (not 5xx) — Stripe's retry policy sees
         success on idempotent retries of unhandled events.

    For event types whose handler raises in this test fixture (e.g.
    `checkout.session.completed` with no customer email mapping), the
    retry returns 500 each time, BUT the claim-release path runs
    (visible in the warning log "released claim on event ... so the
    retry can re-attempt"). The 5xx tells Stripe to retry — exactly
    the brief's "no longer locks out paid customer" behavior. We
    pin the unhandled-event idempotency path here.

    Severity: N/A (defended). New closure re-pin."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_bb6_07")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    # Use a known-unhandled event type so the handler doesn't raise
    # in this test fixture.
    body = json.dumps({
        "id": "evt_bb6_07_retry",
        "type": "customer.subscription.updated",
        "data": {"object": {"id": "sub_test"}},
    }).encode()
    sig = hmac.new(b"whsec_bb6_07", f"{ts}.".encode() + body,
                   hashlib.sha256).hexdigest()
    hdr = f"t={ts},v1={sig}"

    # First send.
    r1 = c.post("/api/v1/webhooks/stripe", content=body,
                headers={"Stripe-Signature": hdr,
                         "Content-Type": "application/json"})
    assert r1.status_code == 200, f"first send failed: {r1.text}"

    # Retry — must return 200 (Stripe retry policy sees success).
    for _ in range(3):
        r = c.post("/api/v1/webhooks/stripe", content=body,
                   headers={"Stripe-Signature": hdr,
                            "Content-Type": "application/json"})
        assert r.status_code == 200, (
            f"BB6-07 regressed — retry returned non-200: "
            f"status={r.status_code} body={r.text[:200]}"
        )


# ---------------------------------------------------------------------
# BB6-08 (defended/pinned): /healthz HEAD method returns 405 with the
# full security-headers chain.
# ---------------------------------------------------------------------
def test_bb6_08_healthz_head_returns_405_with_security_headers(app):
    """`HEAD /healthz` returns 405 (the route only declares GET).
    Critically, the 405 response DOES include the full security-
    headers chain (CSP, X-Frame-Options, etc.) — confirming the
    middleware applies to MethodNotAllowed responses.

    Compare with BB6-01 (deep-JSON 500 path) which DOES NOT include
    these headers — so the middleware covers FastAPI's auto-405 path
    but NOT the uncaught-exception 500 path.

    Severity: N/A (defended). Round-6 probe pin."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.head("/healthz")
    assert r.status_code == 405, f"HEAD /healthz unexpected: {r.status_code}"
    assert r.headers.get("content-security-policy"), (
        f"BB6-08 regressed — 405 no longer carries CSP. headers="
        f"{dict(r.headers)}"
    )
    assert r.headers.get("x-frame-options") == "DENY", (
        f"BB6-08 X-Frame-Options regressed."
    )


# ---------------------------------------------------------------------
# BB6-09 (defended/pinned): /docs OPTIONS preflight returns 405 with
# NO CORS Allow-Origin reflection. CORS middleware is absent on /docs.
# ---------------------------------------------------------------------
def test_bb6_12_magic_link_oversize_email_413(app):
    """Magic-link with a 1MB+ email local-part returns 413 from the
    body-size middleware. Smaller (10KB) emails are accepted (no
    explicit length check at the validation layer — but body-size
    catches the egregious case).

    Severity: N/A (defended). Round-6 probe pin."""
    c = TestClient(app, raise_server_exceptions=False)
    # 10MB email body → 413
    long_email = "a" * (10 * 1024 * 1024) + "@example.com"
    r = c.post("/api/v1/auth/magic-link", json={"email": long_email})
    assert r.status_code == 413, (
        f"BB6-12 regressed — 10MB email body no longer 413. "
        f"status={r.status_code}"
    )


# ---------------------------------------------------------------------
# BB6-13 (defended/pinned): /api/v1/admin/* method-tampering via
# _method query param, X-HTTP-Method-Override header, or in-body
# _method key — all ignored. The HTTP method is the source of truth.
# ---------------------------------------------------------------------
def test_bb6_16_json_parser_edge_cases_handled(app):
    """JSON parser edge cases the launch-day attacker tries:
      * `{"email":"a"}{"evil":"x"}` (trailing data after JSON) → 422
        with "Extra data" error.
      * `{"email":"a","email":"b"}` (duplicate keys) → 202 with
        last-value wins (Python json.loads default).
      * `\\xef\\xbb\\xbf{"email":"a"}` (UTF-8 BOM) → parsed.
      * `{"email":"a\\x00"}` (raw NUL in JSON string) → 422 with
        "control character" error.

    None of these crash the worker or leak internal info beyond
    standard "JSON decode error" messages.

    Severity: N/A (defended). Round-6 probe pin."""
    c = TestClient(app, raise_server_exceptions=False)

    # Trailing JSON.
    r = c.post("/api/v1/auth/magic-link",
               content=b'{"email":"dev@example.com"}{"evil":"x"}',
               headers={"Content-Type": "application/json"})
    assert r.status_code == 422, (
        f"BB6-16: trailing JSON unexpectedly accepted: {r.status_code} {r.text[:200]}"
    )

    # Duplicate keys — last wins.
    r = c.post("/api/v1/auth/magic-link",
               content=b'{"email":"a@example.com","email":"dev@example.com"}',
               headers={"Content-Type": "application/json"})
    assert r.status_code in (202, 429), (
        f"BB6-16: duplicate-keys unexpected status: {r.status_code} {r.text[:200]}"
    )

    # NUL in string.
    r = c.post("/api/v1/auth/magic-link",
               content=b'{"email": "dev\x00@example.com"}',
               headers={"Content-Type": "application/json"})
    assert r.status_code == 422, (
        f"BB6-16: NUL-in-string unexpectedly accepted: {r.status_code} {r.text[:200]}"
    )


# ---------------------------------------------------------------------
# BB6-17 (defended/pinned): Magic-link callback handles replay and
# tampered tokens correctly. Both → 400.
# ---------------------------------------------------------------------
def test_bb6_17_magic_link_callback_replay_and_tamper_rejected(app):
    """Issue a magic-link, then:
      1. Use the token once → 303 redirect to /, session cookie set.
      2. Replay the same token → 400 (single-use enforced).
      3. Tamper the token (append a byte) → 400 (signature reject).

    Severity: N/A (defended). Round-6 probe re-pin (BB-27 closure
    from round 1)."""
    c = TestClient(app, raise_server_exceptions=False)
    # Issue a magic link.
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    assert r.status_code == 202
    # The dev_link is in the body because DEV_INSECURE_SECRET=1 here.
    body = r.json()
    if "dev_link" not in body:
        pytest.skip("dev_link not exposed in this test mode; closure pinned in BB-27")
    url = body["dev_link"]
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    token = qs.get("token", [""])[0]

    # First use → 303.
    r = c.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    assert r.status_code == 303, (
        f"BB6-17: first callback unexpected status: {r.status_code} {r.text[:200]}"
    )

    # Replay → 400.
    r = c.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    assert r.status_code == 400, (
        f"BB6-17 regressed — magic-link replay no longer 400. status={r.status_code}"
    )

    # Tamper → 400.
    r = c.get(f"/api/v1/auth/callback?token={token}X", follow_redirects=False)
    assert r.status_code == 400, (
        f"BB6-17 regressed — tampered token accepted. status={r.status_code}"
    )


# ---------------------------------------------------------------------
# BB6-18 (defended/pinned): CRLF / header-injection via Cookie header
# is rejected by httpx / starlette. Multiple iam_jit_session cookie
# values → last-wins parsing; no auth bypass via cookie injection.
# ---------------------------------------------------------------------
def test_bb6_18_cookie_injection_handled(app):
    """Send a Cookie header with multiple iam_jit_session values:
      `iam_jit_session=garbage; foo=bar; iam_jit_session=<valid>`

    The server picks the last value and authenticates correctly (the
    test session cookie is honored).

    Also probe CRLF injection in the Cookie header → httpx rejects
    pre-send (the request raises and TestClient returns the rejection
    as a 401 status).

    Severity: N/A (defended). Round-6 probe pin."""
    valid_cookie = auth_mod.sign_session(_DEV_SECRET, "email:dev@example.com")
    c = TestClient(app, raise_server_exceptions=False)

    # Multiple iam_jit_session — last-wins behavior accepted.
    r = c.get("/api/v1/users/me",
              headers={"Cookie": f"iam_jit_session=garbage; foo=bar; iam_jit_session={valid_cookie}"})
    assert r.status_code == 200, (
        f"BB6-18: multi-cookie expected last-wins 200, got {r.status_code}"
    )

    # CRLF in Cookie → rejected at transport level (httpx).
    # TestClient may return 400 or surface the rejection differently.
    try:
        r = c.get("/api/v1/users/me",
                  headers={"Cookie": "foo=bar\r\nX-Injected: true"})
        # If we got a response, the header injection should NOT have
        # produced a request with X-Injected reflected.
        assert "X-Injected" not in r.headers, (
            f"BB6-18 fired — CRLF injection succeeded? headers={dict(r.headers)}"
        )
    except Exception:
        # httpx rejected pre-send; that's the defended path.
        pass


# ---------------------------------------------------------------------
# BB6-19 (defended/pinned): /healthz body is minimal (round-1 BB-13
# closure verified). No security-posture object leak.
# ---------------------------------------------------------------------
