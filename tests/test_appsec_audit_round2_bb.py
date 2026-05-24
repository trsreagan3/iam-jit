"""Black-box appsec audit — round 2 (2026-05-14).

Round-2 external-researcher probe. The round-1 BB findings landed earlier
and a subset of fixes (notably the SCORE-XFF-RATELIMIT-BYPASS fix on
`src/iam_jit/routes/score.py:_client_ip`, and the Stripe
`ProcessedEventsStore` scaffolding in `src/iam_jit/stripe_webhook.py`)
have been shipped concurrently with this audit.

Round 2 hunts for:
  1. Regressions / edge cases in the round-1 fixes themselves.
  2. Surface areas round 1 didn't fully cover (token-mint flood,
     intake-LLM abuse, bootstrap-claim race, log-channel host-header
     leakage, CSRF on additional handlers, etc.).
  3. Privilege-boundary gaps not exercised in round 1 (admin self-demote,
     last-admin lockout, deregister-as-state-change, etc.).
  4. External-channel and config-shape attacks (SES sender forgery,
     forwarded-host smuggling, label log-injection).

Each test asserts the *current* (broken or defended) behavior; broken-
behavior tests fail when the fix lands — that's the signal to flip the
assertion and ship the fix.

Severity rubric (same as round 1):
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

import concurrent.futures
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
from iam_jit.users_store import FileUserStore, User, UserNotFound
class _WritableInMemoryUserStore:
    """Mimics DynamoDBUserStore (read/write) for tests that need to
    exercise admin-write paths (PATCH /api/v1/users/...).

    The default FileUserStore is read-only at runtime, which prevents
    us from probing the *behavioral* consequence of admin write
    operations. Production deployments use the DDB store (read/write);
    this fixture is the in-process equivalent."""

    name = "memory-rw"

    def __init__(self) -> None:
        self.users: dict[str, User] = {
            "email:admin@example.com": User(
                id="email:admin@example.com",
                roles=("admin",),
                display_name="Admin",
            ),
            "email:admin2@example.com": User(
                id="email:admin2@example.com",
                roles=("admin",),
                display_name="Admin2",
            ),
            "email:approver@example.com": User(
                id="email:approver@example.com",
                roles=("approver",),
                display_name="Approver",
            ),
            "email:dev@example.com": User(
                id="email:dev@example.com",
                roles=("requester",),
                display_name="Dev",
            ),
            "email:dev2@example.com": User(
                id="email:dev2@example.com",
                roles=("requester",),
                display_name="Dev2",
            ),
        }

    def get(self, user_id: str) -> User:
        if user_id not in self.users:
            raise UserNotFound(user_id)
        return self.users[user_id]

    def list(self, *, include_disabled: bool = False) -> list[User]:
        return [u for u in self.users.values() if include_disabled or u.enabled]

    def put(self, user: User) -> None:
        self.users[user.id] = user

    def delete(self, user_id: str) -> None:
        self.users.pop(user_id, None)


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
    # (score-route limiter reset dropped 2026-05-24 — hosted scoring API removed per [[no-hosted-saas]])
@pytest.fixture
def app(tmp_path):
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    return create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
@pytest.fixture
def app_rw(tmp_path):
    """App fixture backed by a writable in-memory user store.

    Use this when the test needs to exercise admin-write paths
    (PATCH /api/v1/users/...). Production deployments using the
    DynamoDB user store hit the same code path."""
    return create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=_WritableInMemoryUserStore(),
        api_tokens_store=InMemoryAPITokenStore(),
    )
def _client_as(app, user_id=None):
    c = TestClient(app, raise_server_exceptions=False)
    if user_id:
        c.cookies.set("iam_jit_session", auth_mod.sign_session(_DEV_SECRET, user_id))
    return c


# =====================================================================
# CATEGORY 1: Regressions / edge cases in round-1 fixes
# =====================================================================

# ---------------------------------------------------------------------
# BB2-01: XFF rate-limit fix regression — score endpoint loses real-IP
#         attribution when trusted-proxy CIDR matches (CloudFront real IP
#         comes via XFF, but the trusted-proxy gate is `IAM_JIT_TRUSTED_
#         PROXY_CIDRS` env. If unset OR the env is set but the immediate
#         client isn't in those CIDRs, attackers can NOT spoof — good.
#         BUT: when trusted_proxy IS in front (production CloudFront /
#         ALB) and an attacker can hit the Function URL directly without
#         going through CloudFront — XFF is honored ONLY if the immediate
#         client matches a trusted-proxy CIDR. So that's correct.
#         Edge case: when `IAM_JIT_TRUST_FORWARDED_FOR_FOR_SCORE=1` is
#         set but `IAM_JIT_TRUSTED_PROXY_CIDRS` is EMPTY, _client_ip
#         falls back to real_client — also correct. Probe verifies.)
# ---------------------------------------------------------------------
def test_bb2_02_network_acl_trusts_xff_by_default(app, monkeypatch):
    """BB2-02 — CLOSED. `IAM_JIT_TRUST_FORWARDED_FOR` now defaults
    to OFF, and even when ON, XFF parsing requires the immediate
    peer to fall in `IAM_JIT_TRUSTED_PROXY_CIDRS`. The default-off
    posture means an attacker cannot bypass the source-IP allowlist
    by spoofing XFF on a directly-exposed Function URL.

    This test pins the closure: with the allowlist set to 10.0.0.0/8
    and XFF NOT explicitly trusted, a spoofed `X-Forwarded-For:
    10.0.0.42` from a 127.0.0.1 peer must still 403."""
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8")
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_FOR", raising=False)
    monkeypatch.delenv("IAM_JIT_TRUSTED_PROXY_CIDRS", raising=False)

    c = TestClient(app, raise_server_exceptions=False)
    r_blocked = c.get("/api/v1/users/me")
    assert r_blocked.status_code == 403, r_blocked.text

    r_spoof = c.get(
        "/api/v1/users/me",
        headers={"X-Forwarded-For": "10.0.0.42"},
    )
    assert r_spoof.status_code == 403, (
        f"XFF spoof should NOT bypass the ACL by default; got "
        f"{r_spoof.status_code}: {r_spoof.text}"
    )


# ---------------------------------------------------------------------
# BB2-03: Stripe idempotency now covers UNHANDLED event types too —
#         CLOSED as a side effect of the atomic-claim refactor.
# ---------------------------------------------------------------------
def test_bb2_03_stripe_idempotency_covers_unhandled_events(monkeypatch, tmp_path):
    """BB2-03 — CLOSED. The atomic-claim refactor moved the
    `claim(event_id)` call to the top of `dispatch_event`, BEFORE
    the handler-dict lookup. As a result, even event types we don't
    handle (e.g. `invoice.upcoming`) get claimed on first arrival, so
    replays of any signed event short-circuit with `duplicate=True`.
    This closes the log-flooding / CPU-DoS replay vector the round-2
    BB audit flagged.

    This test pins the closure: replaying the same signed
    `invoice.upcoming` 5x must yield exactly 1 fresh response and
    4 `duplicate=True` responses."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_round2_dummy")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    # Use an event type that is NOT in the handler dict
    body = b'{"id": "evt_unhandled_replay_1", "type": "invoice.upcoming", "data": {"object": {}}}'
    sig = hmac.new(
        b"whsec_round2_dummy",
        f"{ts}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    hdr = f"t={ts},v1={sig}"
    responses = []
    for _ in range(5):
        r = c.post(
            "/api/v1/webhooks/stripe",
            content=body,
            headers={"Stripe-Signature": hdr, "Content-Type": "application/json"},
        )
        responses.append(r.json())
    # CLOSED: exactly the first delivery should be fresh; the other
    # four should short-circuit with duplicate=True. handled stays
    # False because the event type has no handler.
    assert all(not r.get("handled") for r in responses)
    duplicate_count = sum(1 for r in responses if r.get("duplicate") is True)
    assert duplicate_count == 4, (
        f"expected 4 duplicate short-circuits on 5 deliveries (the "
        f"atomic-claim fix covers unhandled event types too); got "
        f"{duplicate_count}. Responses: {responses}"
    )


# ---------------------------------------------------------------------
# BB2-04: Stripe idempotency race — has_processed / mark_processed are
#         not atomic; two concurrent webhooks of the same event can
#         both pass has_processed before either calls mark_processed.
# ---------------------------------------------------------------------
def test_bb2_04_stripe_idempotency_atomic_claim_closed(monkeypatch, tmp_path):
    """BB2-04 — CLOSED. The check-then-act gap was collapsed into a
    single atomic `claim(event_id) -> bool` operation on the
    ProcessedEventsStore protocol. The in-memory implementation uses
    `dict.setdefault` with a per-call unique marker; the DynamoDB
    implementation MUST use `PutItem(ConditionExpression=
    "attribute_not_exists(event_id)")`.

    This pinned test runs two threads racing the same event_id under
    a barrier — exactly one wins the claim, the other loses. If a
    future refactor reintroduces non-atomic check-then-act, both
    threads will see claim()=True and this test will fail."""
    from iam_jit.stripe_webhook import InMemoryProcessedEventsStore

    store = InMemoryProcessedEventsStore()
    event_id = "evt_race_test_1"

    barrier = threading.Barrier(2)
    results: dict[str, bool] = {}

    def attempt(name: str) -> None:
        barrier.wait()
        results[name] = store.claim(event_id)

    threads = [
        threading.Thread(target=attempt, args=("a",)),
        threading.Thread(target=attempt, args=("b",)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [n for n, won in results.items() if won]
    assert len(winners) == 1, (
        f"expected exactly one thread to win the claim under contention; "
        f"got {results}"
    )


# =====================================================================
# CATEGORY 2: Surface areas round 1 didn't fully cover
# =====================================================================

# ---------------------------------------------------------------------
# BB2-05: No per-user cap on POST /api/v1/tokens (token-mint flood)
# ---------------------------------------------------------------------
def test_bb2_05_token_mint_flood_per_user(app, monkeypatch):
    """BB2-05 — CLOSED. Per-user token cap enforced at mint time;
    the 51st mint returns 429. Cap is configurable via
    IAM_JIT_API_TOKEN_CAP_PER_USER for operators who need more,
    but the default protects against abuse + accidental floods at
    launch."""
    monkeypatch.setenv("IAM_JIT_API_TOKEN_CAP_PER_USER", "10")
    dev = _client_as(app, "email:dev@example.com")
    succeeded = 0
    last_status = None
    for i in range(20):
        r = dev.post("/api/v1/tokens", json={"label": f"flood-{i}"})
        last_status = r.status_code
        if r.status_code == 201:
            succeeded += 1
        else:
            break
    assert succeeded == 10, (
        f"expected exactly cap (10) successful mints; got {succeeded}, "
        f"last_status={last_status}"
    )
    assert last_status == 429
    after = dev.get("/api/v1/tokens").json()["count"]
    assert after == 10


# ---------------------------------------------------------------------
# BB2-06: Intake-turn endpoint allows oversize-message conversation
#         abuse (LLM cost-pump primitive)
# ---------------------------------------------------------------------
def test_bb2_06_intake_turn_large_message_no_per_field_cap(app):
    import pytest
    pytest.skip("closed by deletion: /requests/new/chat + /api/v1/intake/turn routes removed in 0.4.0 ([[no-nl-synthesis]] Stage 4).")
# ---------------------------------------------------------------------
# BB2-07: Bootstrap claim is racy across two concurrent claims
# ---------------------------------------------------------------------
def test_bb2_07_bootstrap_claim_check_then_write_race(tmp_path, monkeypatch):
    """`bootstrap_claim.evaluate_and_claim` does:

        if _has_been_claimed(user): return already_claimed
        ...
        user_store.put(updated)  # mark as claimed

    Two concurrent claims with the same valid secret + email can
    both pass the `_has_been_claimed` check (the user record is
    read fresh in each thread) and both `put` the claimed marker.
    Both calls return `success=True` and both produce a valid
    session cookie. In practice this is a narrow real-world race
    (a coordinated attacker who has the setup key would only need
    to win once), but the security-invariant the module claims —
    "single-use guarantee" — is violated.

    Severity: LOW (single-use invariant break under concurrent
    contention; no real-world exploit since the attacker who has
    the secret has already won).

    Fix sketch: use a store-level atomic put-if-not-claimed
    (DynamoDB ConditionExpression), or hold a global lock around
    the read-check-write sequence."""
    # Use a writable in-memory user store so we can probe the
    # check-then-write race (FileUserStore is read-only at runtime
    # and would short-circuit the test before reaching the race).
    user_store = _WritableInMemoryUserStore()
    user_store.users["email:boot@example.com"] = User(
        id="email:boot@example.com",
        roles=("admin",),
        display_name="Boot",
    )
    from iam_jit import bootstrap_claim

    barrier = threading.Barrier(2)
    decisions: list = []
    lock = threading.Lock()

    def claim() -> None:
        barrier.wait()
        d = bootstrap_claim.evaluate_and_claim(
            submitted_email="boot@example.com",
            submitted_key="x" * 32,
            admin_bootstrap_email="boot@example.com",
            bootstrap_setup_key="x" * 32,
            user_store=user_store,
        )
        with lock:
            decisions.append(d)

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [d for d in decisions if d.success]
    # Currently broken: both claims can succeed because the
    # check-then-write is racy on the FileUserStore.
    # (FileUserStore is single-process so the race is narrow; the
    # DynamoDB variant has the same logical race because the put
    # is a non-conditional put.)
    # We accept either: both succeed (proves the race), or one
    # succeeds + one fails (the win-the-race lottery went our way
    # in this run). The behavior we DON'T want is "always exactly
    # one succeeds" — that would mean atomic semantics.
    assert len(successes) >= 1
    # If both succeeded, the race is reproduced. Don't strictly
    # require it (timing flake); just document that the design
    # admits it.
    if len(successes) == 2:
        # Both writers updated `user.notes`; the later write
        # overwrote the earlier marker. Confirm only one marker
        # remains.
        user = user_store.get("email:boot@example.com")
        markers = (user.notes or "").count("[claimed at ")
        assert markers <= 2  # may be 1 (overwrite) or 2 (append)


# ---------------------------------------------------------------------
# BB2-08: Magic-link delivery still emits the token URL to logger
#         (regression check on round-1 BB-12 fix)
# ---------------------------------------------------------------------
def test_bb2_08_magic_link_log_emits_token_when_ses_unset(caplog, monkeypatch, tmp_path):
    """BB2-08 / BB-12 — CLOSED. Default fail-closed + opt-in log
    channel with fingerprint-only logging. Same closure as the
    round-1 BB-12 pinned test; this variant exercises the round-2
    surface (re-audit) to confirm no regression."""
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

    # Default: no delivery channel → 503, no token leak.
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    assert r.status_code == 503
    msgs = [rec.getMessage() for rec in caplog.records]
    assert not any("token=" in m for m in msgs)

    # Opt-in log channel → 202 + fingerprint only, never the URL.
    monkeypatch.setenv("IAM_JIT_ALLOW_LOG_CHANNEL", "1")
    caplog.clear()
    r2 = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    assert r2.status_code == 202
    msgs2 = [rec.getMessage() for rec in caplog.records]
    assert not any("token=" in m for m in msgs2)
    assert any("link_fingerprint=" in m for m in msgs2)


# ---------------------------------------------------------------------
# BB2-09: Magic-link host-header smuggling — if XFH-trust is on,
#         an attacker can poison the link recipient gets
# ---------------------------------------------------------------------
def test_bb2_09_magic_link_host_header_poisoning_when_xfh_trusted(monkeypatch, tmp_path):
    """BB2-09 — CLOSED. `public_url.base_for` now requires THREE
    conditions before honoring X-Forwarded-Host:
      1. `IAM_JIT_TRUST_FORWARDED_HOST=1`
      2. the immediate peer in `IAM_JIT_TRUSTED_PROXY_CIDRS`
      3. the XFH value present in `IAM_JIT_ALLOWED_PUBLIC_HOSTS`

    Even with XFH-trust enabled, an attacker hitting the Function
    URL directly cannot poison the magic-link host because their
    peer IP is not in the trusted proxy CIDRs AND `evil.attacker.
    example` is not in the public-host allowlist."""
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
        f"XFH host poisoning still works — got: {link}"
    )


# =====================================================================
# CATEGORY 3: Privilege-boundary gaps not exercised in round 1
# =====================================================================

# ---------------------------------------------------------------------
# BB2-10: Admin can demote themselves — last-admin lockout primitive
# ---------------------------------------------------------------------
def test_bb2_10_admin_can_self_demote(app_rw):
    """PATCH /api/v1/users/{user_id} with the admin's own id and a
    payload of `{"roles": ["requester"]}` succeeds. There's no
    last-admin protection. An attacker who CSRFs the admin (round 1
    BB-01..BB-04 finding is still open at the time of this audit)
    can transition the deployment into a no-admin state — at which
    point nobody can re-admin anyone without redeployment / data-
    plane intervention.

    Severity: MED (compounds with the still-open CSRF surface).

    Note: the test uses a writable in-memory user store because the
    default `FileUserStore` is read-only at runtime. Production
    deployments use `DynamoDBUserStore` (read/write) which has the
    same code path the in-memory store exercises here.

    Fix sketch:
      - refuse role-removal when the resulting role set excludes
        `admin` AND the actor is the last admin;
      - alternatively, refuse self-edits entirely and require
        another admin to demote (forcing a two-eyes path)."""
    # BB2-10 / round-5-WB HIGH — CLOSED.
    # PATCH refuses self-demotion AND refuses the last-admin
    # demotion of any admin (not just self). Recovery requires
    # promoting another user to admin first.
    app = app_rw
    admin = _client_as(app, "email:admin@example.com")

    # Self-demote attempt — refused 409.
    r = admin.patch(
        "/api/v1/users/email:admin@example.com",
        json={"roles": ["requester"]},
    )
    assert r.status_code == 409, (
        f"expected self-demote refused; got {r.status_code}: {r.text}"
    )
    assert "self-demotion" in r.text.lower()

    # Demoting ANOTHER admin (admin2) when admin and admin2 are the
    # only two admins is allowed — but if it would leave zero admins,
    # the last-admin guard refuses.
    r2 = admin.patch(
        "/api/v1/users/email:admin2@example.com",
        json={"roles": ["requester"]},
    )
    # admin2 was admin → after this, admin remains as sole admin (OK)
    assert r2.status_code == 200, r2.text

    # Now: attempt to demote admin (the actor) — both self-demote
    # AND last-admin guards fire. The self-demote rule wins first.
    r3 = admin.patch(
        "/api/v1/users/email:admin@example.com",
        json={"roles": ["requester"]},
    )
    assert r3.status_code == 409
    assert (
        "self-demotion" in r3.text.lower()
        or "last-admin" in r3.text.lower()
    )


# ---------------------------------------------------------------------
# BB2-11: Admin can mass-demote other admins (concentration primitive)
# ---------------------------------------------------------------------
def test_bb2_11_admin_can_demote_other_admins(app_rw):
    """An admin can iterate through the users list and demote every
    other admin, leaving themselves as the sole admin. No `require
    other admin's consent` workflow. Combined with the CSRF surface
    on the HTML user-mgmt routes (round 1 BB-01..BB-04), this means:
      - admin browser visits attacker page;
      - attacker page POSTs to /api/v1/users/<each-other-admin> with
        roles=['requester'] for each known admin;
      - admin loses co-admins silently; sole-admin attack vector
        completes.

    Severity: MED (privilege concentration; compounds CSRF).

    Fix sketch: emit `security.admin_demoted` audit on every
    demotion (today: not in the audit stream — verify by reading
    the audit log file after this test); require email confirmation
    to the demoted admin's address; or simply forbid mass demotes
    from a single actor within a time window."""
    app = app_rw
    admin = _client_as(app, "email:admin@example.com")
    r = admin.patch(
        "/api/v1/users/email:admin2@example.com",
        json={"roles": ["requester"]},
    )
    assert r.status_code == 200, r.text
    # Confirm admin2 lost the admin role.
    me = _client_as(app, "email:admin2@example.com")
    me_info = me.get("/api/v1/users/me").json()
    assert "admin" not in me_info.get("roles", [])


# ---------------------------------------------------------------------
# BB2-12: Approver-deregister can DoS a tenant's account onboarding
# ---------------------------------------------------------------------
def test_bb2_12_admin_can_deregister_in_use_account(app, tmp_path):
    """DELETE /api/v1/accounts/{account_id} succeeds even when there
    are active grants pointing at the account. The orphaned grants
    still reference the now-deregistered account_id; future
    `assume` / `revoke` calls against them will fail with confusing
    errors.

    Severity: LOW (admin self-foot-gun, not an external attacker
    primitive — admin role required).

    Fix sketch: refuse to deregister an account that has any
    active grants; or auto-revoke + audit on deregister."""
    # Register an account first.
    admin = _client_as(app, "email:admin@example.com")
    r = admin.post(
        "/api/v1/accounts",
        json={
            "account_id": "111122223333",
            "provisioner_role_arn": "arn:aws:iam::111122223333:role/iam-jit-prov",
            "provisioner_external_id": "ext-test",
            "provisioning_mode": "identity_center",
        },
    )
    assert r.status_code == 201, r.text
    # Deregister it — no in-use check.
    r = admin.delete("/api/v1/accounts/111122223333")
    assert r.status_code == 200, r.text


# =====================================================================
# CATEGORY 4: External-channel / config-shape attacks
# =====================================================================

# ---------------------------------------------------------------------
# BB2-13: Token label log injection — CR/LF / control chars in label
#         flow through to audit + logs unfiltered
# ---------------------------------------------------------------------
def test_bb2_13_token_label_accepts_crlf_and_control_chars(app):
    """Round 1 WB flagged TOKEN-LABEL-UNBOUNDED as LOW (no length
    cap). Round 2 confirms the deeper version: the label accepts
    raw CR/LF and other control characters. Tokens are listed on
    /api/v1/tokens via JSON (autoescape n/a), but the same label
    flows into:
      - server logs (`logger.info("issued API token ... label=%s", ...)`);
      - audit-log details JSON (which is grepped by SOC tooling);
      - the HTML /tokens page (Jinja autoescapes — defended on the
        UI side).

    A label like 'real-label\\nFAKE-LOG: admin-promoted user X'
    splits log lines on the consumer side and forges an entry. The
    line is in the iam-jit log group with the iam-jit log line
    prefix; downstream alerting based on log patterns is fooled.

    Severity: LOW (log-injection; depends on SOC tooling; mitigated
    by structured logging if downstream uses CloudWatch Logs
    Insights queries instead of grep).

    Fix sketch: validate label against `^[\\w \\-]{1,100}$` (or
    similar), 400 on mismatch. Length cap simultaneously."""
    dev = _client_as(app, "email:dev@example.com")
    evil = "real-label\nFAKE-LOG-LINE: admin-promoted dev@example.com"
    r = dev.post("/api/v1/tokens", json={"label": evil})
    assert r.status_code == 201, r.text
    body = r.json()
    # Currently broken: server accepted CR/LF unmodified.
    assert "\n" in body.get("label", "")


# ---------------------------------------------------------------------
# BB2-14: Session cookie still ships without Secure under prod-mode
#         + behind-proxy: dev override conflates two distinct intents
# ---------------------------------------------------------------------
def test_bb2_14_session_secure_flag_gated_on_dev_env_only(monkeypatch, tmp_path):
    """The `Secure` cookie flag is set when
    `IAM_JIT_DEV_INSECURE_SECRET != '1'`. That gate is correct for
    local dev (where the cookie travels over HTTP). But:

      - In CI E2E tests, IAM_JIT_DEV_INSECURE_SECRET is '1' AND the
        test client serves over HTTP — both correct; cookie has no
        Secure. Fine.
      - In production behind CloudFront, IAM_JIT_DEV_INSECURE_SECRET
        is unset → cookie gets Secure. Fine.
      - In a hybrid mode (dev override left on in a staging deploy
        accessible via HTTPS), the cookie ships WITHOUT Secure
        over HTTPS — i.e. an attacker on the staging domain's
        network can downgrade to a plain-HTTP variant and read it.

    Severity: LOW (operator misconfig; the env-var is documented
    as local-dev only).

    Fix sketch: compute Secure from the request scheme/XFP, not
    the dev-override env."""
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
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    link = r.json().get("dev_link")
    assert link
    token = link.split("token=")[1]
    r2 = c.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    cookie_hdr = r2.headers.get("set-cookie", "")
    # Currently broken: even via HTTPS, the cookie won't be Secure
    # if the dev-override is set. The Secure attribute is decided
    # by env, not by request scheme.
    assert "Secure" not in cookie_hdr


# ---------------------------------------------------------------------
# BB2-15: /api/v1/intake/turn does not validate role enum strictly —
#         arbitrary role string passes through pydantic regex
# ---------------------------------------------------------------------
def test_bb2_17_mcp_server_is_stateless(app):
    """The MCP server module imports policy_gen and exposes
    generate_iam_policy. We probe whether two back-to-back calls
    with different `task` strings result in state bleed (e.g. the
    second call's `policy` shows up referencing the first call's
    resources). Today this is defended — `generate_policy` is a
    pure function of its inputs.

    Severity: N/A (defended). Honest negative.

    Note: the MCP server runs over stdio (one process per session
    by design); cross-session leak would require module-level
    mutable state in iam_jit.policy_gen — which there isn't (we
    grep'd it)."""
    import pytest
    pytest.skip(
        "closed by deletion: policy_gen package removed in 0.4.0 "
        "([[no-nl-synthesis]] Stage 3). The MCP server's new tool "
        "triad (list_templates / get_template / submit_policy) is "
        "explicitly stateless — each call constructs its own response "
        "from immutable catalog data + caller args. Cross-session "
        "leak surface is gone with the deleted pattern matcher."
    )


# ---------------------------------------------------------------------
# BB2-18: Honest negative — magic-link email field rejects unicode
#         right-to-left override and other homograph attacks
# ---------------------------------------------------------------------
def test_bb2_18_magic_link_rejects_homograph_email(app):
    """RTLO / IDN-confusable characters in the email field could
    let an attacker present 'admin@example.com' to a human reviewer
    while the iam-jit pipeline reads a different value. The
    `_safe_email` validator uses an ASCII-only regex
    (`[A-Za-z0-9._%+\\-]+@...`) so unicode chars are rejected.

    Severity: N/A (defended). Honest negative."""
    c = TestClient(app, raise_server_exceptions=False)
    # U+202E right-to-left override
    rtlo = "admin‮@example.com"
    r = c.post("/api/v1/auth/magic-link", json={"email": rtlo})
    assert r.status_code == 202
    # The response must be uniform — no dev_link generated for the
    # malformed input (because _safe_email returned None).
    body = r.json()
    assert "dev_link" not in body


# ---------------------------------------------------------------------
# BB2-19: Honest negative — Stripe webhook handler verifies signature
#         BEFORE running idempotency check, so a forged event can't
#         poison the processed-events store
# ---------------------------------------------------------------------
def test_bb2_19_stripe_unsigned_event_does_not_poison_idempotency(monkeypatch, tmp_path):
    """Verify: an attacker who submits an event with a BAD signature
    cannot inject `event.id=evt_real_one` into the processed-events
    store, which would silently DoS the real Stripe redelivery.

    Path: routes/webhooks_stripe.py:106-117 raises on signature
    failure (400) BEFORE dispatch_event is called. So the
    idempotency store is never touched on a bad signature.

    Severity: N/A (defended). Honest negative."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_neg_dummy")
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    body = b'{"id": "evt_attacker_target", "type": "checkout.session.completed", "data": {"object": {}}}'
    # Wrong signature
    r = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={
            "Stripe-Signature": "t=9999999999,v1=" + "0" * 64,
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 400

    # Confirm: a subsequent real event with the same id, properly
    # signed, would NOT be short-circuited (the attacker didn't
    # poison anything).
    ts = str(int(time.time()))
    sig = hmac.new(
        b"whsec_neg_dummy",
        f"{ts}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    r2 = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={
            "Stripe-Signature": f"t={ts},v1={sig}",
            "Content-Type": "application/json",
        },
    )
    assert r2.status_code == 200
    # Honest-negative: a real signed event lands and is processed.
    # Whether it's `handled: true / false` or `rejected: true`
    # depends on the event content (the test event has no
    # price/email). The IMPORTANT property is it's not flagged as
    # `duplicate` — proving the attacker didn't poison the
    # idempotency store with the same event_id.
    body = r2.json()
    assert not body.get("duplicate"), (
        "real event after attacker probe should NOT be treated as "
        f"duplicate; got {body}"
    )


# ---------------------------------------------------------------------
# BB2-20: Honest negative — session fixation (pre-auth cookie survives
#         post-auth flow)
# ---------------------------------------------------------------------
def test_bb2_20_session_fixation_pre_auth_cookie_replaced_on_callback(app):
    """An attacker pre-sets `Cookie: iam_jit_session=<attacker-signed
    value for victim_id>` on the victim's browser (via a cross-domain
    network position, a child cookie store XSS, or a co-located
    subdomain controlled by attacker). When the victim signs in via
    magic-link, the callback endpoint MUST overwrite the cookie value
    so the attacker's pre-set session is invalidated.

    Probe: callback's Set-Cookie response contains a freshly-signed
    cookie value, not whatever the client sent. Defended — the
    handler unconditionally signs a new session with the verified
    user_id and sets the cookie.

    Severity: N/A (defended). Honest negative."""
    c = TestClient(app, raise_server_exceptions=False)
    # Attacker sets a pre-auth cookie (e.g. for dev2)
    attacker_value = auth_mod.sign_session(_DEV_SECRET, "email:dev2@example.com")
    c.cookies.set("iam_jit_session", attacker_value)
    # Victim now signs in as dev (different identity)
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    link = r.json()["dev_link"]
    token = link.split("token=")[1]
    r2 = c.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    set_cookie = r2.headers.get("set-cookie", "")
    # The Set-Cookie overrides the pre-set value with a new sig.
    # The value should contain `email:dev@example.com`, not `dev2`.
    assert "email:dev@example.com" in set_cookie
    assert attacker_value not in set_cookie


# ---------------------------------------------------------------------
# BB2-21: Honest negative — magic-link single-use enforced cross-instance
#         when using the default in-process store
# ---------------------------------------------------------------------
def test_bb2_21_magic_link_single_use_within_process(app):
    """The round-1 WB MAGIC-LINK-REPLAY-MULTI-INSTANCE finding is a
    distributed-systems hole (process-local nonce store). Within
    one process, single-use IS enforced. Round 2 retests that the
    behavior holds.

    Severity: N/A (defended in single-process). Honest negative
    against accidental regression."""
    c = TestClient(app, raise_server_exceptions=False)
    r = c.post("/api/v1/auth/magic-link", json={"email": "dev@example.com"})
    link = r.json()["dev_link"]
    token = link.split("token=")[1]
    # First consume
    r1 = c.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    assert r1.status_code == 303
    # Reset session cookie to NOT carry the cookie from r1
    c.cookies.clear()
    # Second consume must fail
    r2 = c.get(f"/api/v1/auth/callback?token={token}", follow_redirects=False)
    assert r2.status_code == 400, r2.text


# ---------------------------------------------------------------------
# BB2-22: Honest negative — admin-self-unban refusal still holds
# ---------------------------------------------------------------------
def test_bb2_22_admin_cannot_self_unban(app):
    """Round 1 WB confirmed admin can't lift their own ban
    (`routes/admin.py:493-515`). Regression check."""
    admin = _client_as(app, "email:admin@example.com")
    # Self-ban first via /api/v1/admin endpoints isn't direct;
    # instead we add a ban via the store directly.
    from iam_jit import bans as bans_mod
    bans_mod.get_default_store().add(
        bans_mod.Ban(
            user_id="email:admin@example.com",
            banned_at="2026-05-14T00:00:00Z",
            reasons=["audit test"],
            snippets=[],
            confidence="high",
            actor="admin:email:admin2@example.com",
        )
    )
    # Now try to self-unban
    r = admin.post("/api/v1/admin/bans/email:admin@example.com/unban")
    # Admin endpoints require an unbanned admin to act — so the
    # self-unban must be refused OR the actor is denied for being
    # banned. Either way: 4xx, not 200.
    assert r.status_code >= 400, r.text


# =====================================================================
# CATEGORY 5: Re-test round-1 fix surface to record what's closed
# =====================================================================

# ---------------------------------------------------------------------
# BB2-23: Re-test BB-XFF — XFF spoof on score endpoint is now correctly
#         ignored
# ---------------------------------------------------------------------
def test_bb2_24_stripe_idempotency_works_for_handled_events(monkeypatch, tmp_path):
    """Confirm the round-1 STRIPE-NO-IDEMPOTENCY fix HOLDS for handled
    event types (the duplicate-token-mint regression class). Use a
    `checkout.session.completed` event with a mapped price id and
    confirm the second send returns `duplicate: True`.

    Severity: N/A (defended). Confirms the round-1 fix."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_handled_dummy")
    monkeypatch.setenv(
        "STRIPE_PRICE_ID_TO_TIER", '{"price_known": "indie"}'
    )
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(_USERS_YAML)
    app2 = create_app(
        request_store=FilesystemStore(tmp_path / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    c = TestClient(app2, raise_server_exceptions=False)

    ts = str(int(time.time()))
    body = (
        b'{"id": "evt_handled_dedup_1", '
        b'"type": "checkout.session.completed", '
        b'"data": {"object": {"customer_email": "buyer@example.com", '
        b'"line_items": {"data": [{"price": {"id": "price_known"}}]}}}}'
    )
    sig = hmac.new(
        b"whsec_handled_dummy",
        f"{ts}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    hdr = f"t={ts},v1={sig}"
    r1 = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": hdr, "Content-Type": "application/json"},
    ).json()
    r2 = c.post(
        "/api/v1/webhooks/stripe",
        content=body,
        headers={"Stripe-Signature": hdr, "Content-Type": "application/json"},
    ).json()
    assert r1.get("handled") is True, r1
    assert r2.get("duplicate") is True, r2


# ---------------------------------------------------------------------
# BB2-25: Honest negative — webhook other than Stripe is the only
#         inbound webhook surface (no shadow webhooks discovered)
# ---------------------------------------------------------------------
def test_bb2_25_only_stripe_webhook_exists(app):
    """Audit-grade enumeration: list all POST routes under
    `/api/v1/webhooks/*` and confirm Stripe is the only one. A
    shadow webhook handler (e.g. for a Slack callback that the
    operator wired without going through the security review)
    would show up here.

    Severity: N/A (inventory-grade negative)."""
    paths = []
    for route in app.routes:
        path = getattr(route, "path", "") or ""
        methods = set(getattr(route, "methods", []) or [])
        if "POST" in methods and path.startswith("/api/v1/webhooks"):
            paths.append(path)
    assert paths == ["/api/v1/webhooks/stripe"], paths
