"""White-box appsec audit, round 1.

Each test in this file documents a single finding from the round-1 audit
on 2026-05-14. The test docstring carries:

  - the CWE (where applicable)
  - severity (CRIT / HIGH / MED / LOW)
  - file + line numbers in the source tree
  - a 1-2 sentence fix sketch

Each test asserts CURRENT (vulnerable) behavior. When the underlying
defect is fixed, the test should be flipped to assert the new behavior
(or simply deleted with a `git log -p` note pointing at the fix). The
intent is *not* a regression-prevention suite — it's a checklist that
fails until each finding has been triaged.

Run only this file:

    pytest tests/test_appsec_audit_round1_wb.py -v

Summary doc: docs/security/AUDIT-2026-05-WB.md
"""

from __future__ import annotations

import inspect
import os
import re

import pytest


# ---------------------------------------------------------------------------
# 1. Score API key compared with `!=` (timing attack)
# ---------------------------------------------------------------------------


def test_finding_score_api_key_uses_nonconstant_time_compare() -> None:
    """Finding: SCORE-API-KEY-TIMING.

    CWE-208 (Observable Timing Discrepancy).
    Severity: MED.
    Location: src/iam_jit/routes/score.py:256 (`_require_api_key`).

    The `score_policy` endpoint compares the user-supplied API key to
    the configured `IAM_JIT_SCORE_API_KEY` with `if token != expected:`.
    This is a non-constant-time comparison. Across many probes an
    attacker can recover the key one character at a time by measuring
    response-time deltas. Easy fix: replace with
    `hmac.compare_digest(token, expected)`.
    """
    from iam_jit.routes import score as score_mod

    src = inspect.getsource(score_mod._require_api_key)
    assert "compare_digest" not in src, (
        "score._require_api_key now uses constant-time compare — flip "
        "this test to assert that behavior and delete this finding."
    )
    assert "token != expected" in src or "expected != token" in src


# ---------------------------------------------------------------------------
# 2. Public score endpoint trusts X-Forwarded-For for rate limiting
# ---------------------------------------------------------------------------


def test_finding_score_rate_limiter_trusts_unverified_xff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding: SCORE-XFF-RATELIMIT-BYPASS.

    CWE-290 (Authentication Bypass by Spoofing) / CWE-348 (Use of Less
    Trusted Source).
    Severity: HIGH.
    Location: src/iam_jit/routes/score.py:264-270 (`_client_ip`) +
    line 392 (rate-limiter call site).

    `_client_ip` always honors `X-Forwarded-For` if present and uses
    the first token as the rate-limit key. The `/api/v1/score`
    endpoint is anonymous-by-default with rate limit
    `IAM_JIT_SCORE_RATE_PER_MINUTE` (default 30). Any caller that
    sets an arbitrary `X-Forwarded-For` header per request bypasses
    the rate limit entirely — `curl -H "X-Forwarded-For: 1.2.3.${N}"`
    in a loop. WAFv2 / CloudFront in front of the Lambda may pin the
    real client IP, but the doc string at line 220-244 of the same
    file makes clear this is "defense-in-depth catching per-instance
    bursts" — meaning the in-Lambda limit is meant to enforce too.

    Fix: only trust XFF when the request arrives through a trusted
    proxy (CloudFront / ALB), using the same env-gated logic as
    `network_acl.py` (IAM_JIT_TRUST_FORWARDED_FOR). When un-trusted,
    rate-key on `request.client.host` only.
    """
    from fastapi.testclient import TestClient

    from iam_jit.app import create_app
    from iam_jit.api_tokens_store import InMemoryAPITokenStore
    from iam_jit.routes import score as score_mod
    from iam_jit.store import FilesystemStore
    from iam_jit.users_store import FileUserStore

    # Tight cap so the test trips it quickly.
    monkeypatch.setenv("IAM_JIT_SCORE_RATE_PER_MINUTE", "3")
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", "x" * 40)
    score_mod._reset_limiter_for_tests()

    import pathlib
    import tempfile

    tmp = pathlib.Path(tempfile.mkdtemp())
    users_yaml = tmp / "u.yaml"
    users_yaml.write_text(
        "schema_version: 1\nauth_mode: local\nusers:\n"
        "  - id: email:a@b.c\n    roles: [requester]\n"
    )

    app = create_app(
        request_store=FilesystemStore(tmp / "requests"),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=InMemoryAPITokenStore(),
    )
    client = TestClient(app)

    body = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
    }

    # Same physical client. By rotating only the XFF, we never hit the
    # cap — proving the limiter is keyed on attacker-controlled input.
    statuses: list[int] = []
    for i in range(12):
        r = client.post(
            "/api/v1/score",
            json=body,
            headers={"X-Forwarded-For": f"203.0.113.{i}"},
        )
        statuses.append(r.status_code)

    # FIXED — XFF is no longer trusted by default for rate-limit
    # keying. Rotating the header per request no longer bypasses the
    # limit (3 in this test). All requests share `request.client.host`
    # so the cap kicks in after request 3.
    over_cap = [s for s in statuses[3:] if s == 429]
    assert len(over_cap) >= 5, (
        f"Expected XFF rotation to be rate-limited, but got: {statuses}. "
        f"If this is failing, the XFF-trust default may have regressed."
    )


# ---------------------------------------------------------------------------
# 3. Bearer-token parsing: control whitespace tolerance
# ---------------------------------------------------------------------------


def test_finding_bearer_parsing_split_on_single_space() -> None:
    """Finding: BEARER-PARSE-SPLIT-NORMALIZATION.

    CWE-1286 (Improper Validation of Syntactic Correctness).
    Severity: LOW.
    Location: src/iam_jit/middleware.py:78-79 (`_identify_user`).

    Auth bearer is parsed as
    `auth_header.split(" ", 1)[1].strip()` after a case-insensitive
    `startswith("bearer ")`. A header like `"Bearer  iamjit_xxx"`
    (double space) hands `" iamjit_xxx"` to `strip()` which yields
    the right token, BUT a header like `"Bearer\tiamjit_xxx"` (tab,
    valid RFC7235 whitespace) FAILS the `startswith("bearer ")`
    check entirely and returns 401. RFC 7235 says auth-scheme is
    separated from credentials by `1*SP`, so tab is technically
    invalid, but many proxies / SDKs collapse / re-emit whitespace
    inconsistently. This is a parsing-fragility finding more than a
    security bypass — but the same parser also accepts an
    empty-after-strip token (`"Bearer "` → token=`""`) and then
    rejects it on the iamjit_ prefix check on line 80. Verify that
    no codepath downstream of `_identify_user` ever sees an empty
    bearer.

    Fix: use a small parser:
      ``m = re.match(r"^bearer\\s+(\\S+)$", auth_header, re.IGNORECASE)``
    """
    from iam_jit.middleware import _identify_user

    src = inspect.getsource(_identify_user)
    # Current implementation uses a literal " " split.
    assert 'split(" ", 1)' in src, (
        "Bearer parser was refactored — re-evaluate this finding."
    )


# ---------------------------------------------------------------------------
# 4. magic-link nonce store is in-memory only (not shared across Lambda
#    instances)
# ---------------------------------------------------------------------------


def test_finding_magic_link_nonce_store_in_memory_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding: MAGIC-LINK-REPLAY-MULTI-INSTANCE — CLOSED.

    CWE-294 (Authentication Bypass by Capture-replay).
    Severity: HIGH.

    Closure:
      - `DynamoDBMagicLinkNonceStore` ships in
        `src/iam_jit/magic_link_nonces.py`. Atomic consume via
        `PutItem(ConditionExpression="attribute_not_exists(token_hash)")`.
      - Factory selects DDB when `IAM_JIT_MAGIC_LINK_NONCES_TABLE`
        is set, in-memory otherwise.
      - The route handler (`routes/auth.py:issue_magic_link`)
        refuses with 503 when running in Lambda
        (`AWS_LAMBDA_FUNCTION_NAME` set) AND no DDB table configured
        AND no explicit `IAM_JIT_ALLOW_INSECURE_NONCES=1` opt-out.
    """
    from iam_jit import magic_link_nonces as nonces

    # When the DDB table env var is set, the factory returns the
    # DDB-backed store.
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_NONCES_TABLE", "iam_jit_nonces")
    nonces.reset_default_store_for_tests()
    # Don't actually instantiate boto3 — just confirm the class path.
    assert hasattr(nonces, "DynamoDBMagicLinkNonceStore")

    # When env unset, fall back to in-memory (still valid for
    # single-instance dev / RC=1 deployments — the route handler
    # gates this, not the factory).
    monkeypatch.delenv("IAM_JIT_MAGIC_LINK_NONCES_TABLE", raising=False)
    nonces.reset_default_store_for_tests()
    fallback = nonces.get_default_store()
    assert isinstance(fallback, nonces.InMemoryMagicLinkNonceStore)


# ---------------------------------------------------------------------------
# 5. Bans store in-memory by default — also multi-instance hole
# ---------------------------------------------------------------------------


def test_finding_bans_store_in_memory_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding: BAN-MULTI-INSTANCE-DESYNC — CLOSED.

    CWE-613 (Insufficient Session Expiration) — adjacent class.
    Severity: HIGH.

    Closure: `DynamoDBBanStore` ships in `src/iam_jit/bans.py`.
    Factory picks it when `IAM_JIT_BANS_TABLE` is set (preferred in
    multi-instance Lambda), then filesystem if `IAM_JIT_BANS_DIR`
    is set (single-instance with persistent /tmp), otherwise
    in-memory.
    """
    from iam_jit import bans as bans_mod

    # DDB path
    monkeypatch.setenv("IAM_JIT_BANS_TABLE", "iam_jit_bans")
    bans_mod.reset_default_store_for_tests()
    assert hasattr(bans_mod, "DynamoDBBanStore")

    # Filesystem fallback
    monkeypatch.delenv("IAM_JIT_BANS_TABLE", raising=False)
    monkeypatch.setenv("IAM_JIT_BANS_DIR", "/tmp/iam_jit_bans_test")
    bans_mod.reset_default_store_for_tests()
    assert isinstance(bans_mod.get_default_store(), bans_mod.FilesystemBanStore)

    # In-memory last resort
    monkeypatch.delenv("IAM_JIT_BANS_DIR", raising=False)
    bans_mod.reset_default_store_for_tests()
    assert isinstance(bans_mod.get_default_store(), bans_mod.InMemoryBanStore)


# ---------------------------------------------------------------------------
# 6. Rate limiter is per-Lambda-instance (acknowledged in code, restated
#    here so the finding has a single canonical record)
# ---------------------------------------------------------------------------


def test_finding_rate_limiter_in_memory_per_instance() -> None:
    """Finding: RATE-LIMIT-MULTI-INSTANCE-BYPASS.

    CWE-770 (Allocation of Resources Without Limits or Throttling).
    Severity: MED.
    Location: src/iam_jit/rate_limit.py:71-158
    (`InMemoryRateLimiter`); the `/intake/turn` route at
    src/iam_jit/routes/intake.py:59 calls it.

    The same per-instance caveat that affects bans and nonces
    applies to the `intake-turn` rate limiter — N Lambda instances
    multiplies the effective cap by N. For the LLM-backed
    `/api/v1/intake/turn` endpoint this directly multiplies LLM
    billing exposure under abuse. WAFv2 in front would catch true
    flood patterns but doesn't see the per-user identity needed for
    the soft/hard cap distinction this code implements.

    Fix: back the limiter with a DynamoDB counter table (atomic
    UpdateItem with ADD + ConditionExpression < cap) or with
    ElastiCache.
    """
    from iam_jit.rate_limit import InMemoryRateLimiter, get_default_limiter

    assert isinstance(get_default_limiter(), InMemoryRateLimiter)


# ---------------------------------------------------------------------------
# 7. Stripe webhook is not idempotent — same event mints multiple tokens
# ---------------------------------------------------------------------------


def test_finding_stripe_webhook_not_idempotent() -> None:
    """Finding: STRIPE-NO-IDEMPOTENCY.

    CWE-799 (Improper Control of Interaction Frequency) /
    CWE-352-adjacent.
    Severity: HIGH.
    Location: src/iam_jit/stripe_webhook.py:190-270
    (`handle_checkout_session_completed`) — and the dispatcher at
    332-360.

    Stripe MAY (and does) deliver the same event multiple times
    (network retries, replay from the dashboard). The webhook
    handler doesn't check `event["id"]` against a `processed_events`
    store. Two consequences:

      1. Each redelivery of `checkout.session.completed` mints a
         FRESH API token tied to the customer's email. The customer
         ends up with N valid tokens, the operator never sees the
         duplicates, and revoking one leaves the others intact.
      2. `customer.subscription.deleted` redeliveries are idempotent
         by accident (deleting an already-deleted token is a no-op)
         but the audit log emits N "revoked 0 tokens" entries.

    Fix: persist `event["id"]` to an idempotency table with TTL =
    30 days (Stripe's max retry window) before calling the handler;
    short-circuit on hit. Stripe recommends this pattern explicitly:
    https://stripe.com/docs/webhooks#handle-duplicate-events
    """
    # FIXED — dispatch_event now accepts a processed_events_store
    # parameter. A redelivery of the same event id short-circuits
    # without re-running the handler.
    from iam_jit.stripe_webhook import (
        dispatch_event, InMemoryProcessedEventsStore,
    )
    from iam_jit.api_tokens_store import InMemoryAPITokenStore

    tokens = InMemoryAPITokenStore()
    processed = InMemoryProcessedEventsStore()
    event = {
        "id": "evt_replay_test",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer_email": "buyer@example.com",
                "line_items": {"data": [{"price": {"id": "price_indie"}}]},
                "customer": "cus_abc",
                "subscription": "sub_xyz",
            }
        },
    }
    os.environ["STRIPE_PRICE_ID_TO_TIER"] = '{"price_indie":"indie"}'

    # First call runs the handler.
    r1 = dispatch_event(event, tokens_store=tokens, processed_events_store=processed)
    # Second call (same event id) short-circuits.
    r2 = dispatch_event(event, tokens_store=tokens, processed_events_store=processed)

    assert r1.get("handled") is True
    assert r2.get("duplicate") is True
    # Only ONE token row exists — the second call did not mint.
    assert len(tokens.list_for_user("buyer@example.com")) == 1, (
        "Stripe redelivery minted a duplicate token — idempotency broken."
    )


# ---------------------------------------------------------------------------
# 8. Stripe webhook error response leaks signature-failure detail
# ---------------------------------------------------------------------------


def test_finding_stripe_webhook_leaks_signature_failure_detail() -> None:
    """Finding: STRIPE-VERBOSE-SIGNATURE-ERROR.

    CWE-209 (Generation of Error Message Containing Sensitive
    Information).
    Severity: LOW.
    Location: src/iam_jit/routes/webhooks_stripe.py:112-117.

    The route catches `InvalidStripeSignature` and surfaces
    `detail=f"signature verification failed: {e}"`. The exception
    message includes specifics like
    `"Stripe-Signature `t=` is not an integer"`,
    `"timestamp 12345 is outside the 300s tolerance window
    (now=99999)"`, and `"signature mismatch"` — useful for an
    attacker probing the verification logic.

    Fix: return a uniform `"signature verification failed"` and log
    the specific reason server-side only.
    """
    import iam_jit.routes.webhooks_stripe as route

    src = inspect.getsource(route.stripe_webhook_endpoint)
    assert 'detail=f"signature verification failed: {e}"' in src


# ---------------------------------------------------------------------------
# 9. CSRF: state-changing web routes accept session cookie with no token
# ---------------------------------------------------------------------------


def test_finding_web_state_changing_routes_have_no_csrf_token() -> None:
    """Finding: WEB-NO-CSRF-TOKEN.

    CWE-352 (Cross-Site Request Forgery).
    Severity: MED.
    Location: src/iam_jit/routes/web.py — many `@router.post(...)`
    handlers, including:
      - /login                           (line 210)
      - /requests/new/chat               (line 1096)
      - /requests/{id}/approve | reject  (line 1564 etc)
      - /tokens                          (line 1622)
      - /admin/network/cidrs             (line 1776)

    The session cookie is `SameSite=lax`. Lax blocks cookie carriage
    on cross-site sub-resource POSTs (form-action included) for most
    browsers, BUT does NOT block top-level navigations including
    `<form method=POST>` triggered by a single user click on an
    attacker page. The web POST handlers neither verify a per-
    session CSRF token in the form body nor check `Origin` /
    `Referer`. An attacker page can therefore mint tokens, approve
    requests, or alter the CIDR allowlist on behalf of any
    authenticated victim.

    Fix: either (a) issue a CSRF token on session start, render it
    into every form, and require it on every state-changing POST,
    or (b) check `Origin` header against the configured public URL
    and reject mismatches on POST/PATCH/DELETE.
    """
    # FIXED — CSRF middleware now lives in app.py (`_enforce_csrf`).
    # The middleware rejects cookie-authenticated state-changing
    # requests whose Origin/Referer doesn't match the host. SameSite
    # also flipped from lax → strict on the session cookie.
    from iam_jit import app as app_mod
    src = inspect.getsource(app_mod)
    assert "_enforce_csrf" in src, (
        "CSRF middleware missing from app.py — regression."
    )
    # SameSite is now strict, not lax.
    from iam_jit.routes import auth as auth_mod
    auth_src = inspect.getsource(auth_mod)
    assert 'samesite="strict"' in auth_src, (
        "session cookie SameSite regressed to lax — should be strict."
    )
    # The middleware DOES check Origin/Referer headers (this is the fix).
    assert 'request.headers.get("origin")' in src or 'request.headers.get("referer")' in src


# ---------------------------------------------------------------------------
# 10. Magic-link delivery via CloudWatch logs (production no-SES mode)
# ---------------------------------------------------------------------------


def test_finding_magic_link_logged_in_plaintext(
    monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    """Finding: MAGIC-LINK-LOG-CHANNEL — CLOSED.

    CWE-532 (Insertion of Sensitive Information into Log File).
    Severity: MED.

    Closure:
      - Default fail-closed: when neither SES nor an explicit
        opt-in is configured, `decide()` returns channel='none'
        and `deliver()` logs an error WITHOUT the link.
      - Opt-in log channel (`IAM_JIT_ALLOW_LOG_CHANNEL=1`) emits
        only the sha256 *fingerprint* of the link — never the
        full URL containing the bearer token.
    """
    import logging

    from iam_jit import magic_link_delivery as mld

    monkeypatch.delenv("IAM_JIT_SES_SENDER", raising=False)
    monkeypatch.delenv("IAM_JIT_DEV_INSECURE_SECRET", raising=False)
    monkeypatch.delenv("IAM_JIT_ALLOW_LOG_CHANNEL", raising=False)

    # Default path: channel='none', NO link in logs.
    with caplog.at_level(logging.WARNING, logger="iam_jit.auth"):
        mld.deliver(
            email="victim@example.com",
            user_id="email:victim@example.com",
            link="https://x.example.com/cb?token=SECRET_TOKEN_DO_NOT_LEAK",
        )
    assert not any(
        "SECRET_TOKEN_DO_NOT_LEAK" in r.getMessage() for r in caplog.records
    )

    # Opt-in log channel: fingerprint only, never the token.
    caplog.clear()
    monkeypatch.setenv("IAM_JIT_ALLOW_LOG_CHANNEL", "1")
    with caplog.at_level(logging.WARNING, logger="iam_jit.auth"):
        mld.deliver(
            email="victim@example.com",
            user_id="email:victim@example.com",
            link="https://x.example.com/cb?token=SECRET_TOKEN_DO_NOT_LEAK",
        )
    assert not any(
        "SECRET_TOKEN_DO_NOT_LEAK" in r.getMessage() for r in caplog.records
    )
    assert any(
        "link_fingerprint=" in r.getMessage() for r in caplog.records
    )


# ---------------------------------------------------------------------------
# 11. Token route exposes full token_hash to listing API (sensitive lookup
#     key)
# ---------------------------------------------------------------------------


def test_finding_token_list_exposes_full_hash() -> None:
    """Finding: TOKEN-HASH-DISCLOSURE.

    CWE-200 (Exposure of Sensitive Information).
    Severity: LOW.
    Location: src/iam_jit/routes/tokens.py:67-84 (`list_my_tokens`).

    The list endpoint returns the full `token_hash` for each token.
    The hash IS the DDB primary key for `api_tokens_table`; an
    attacker who exfiltrates a session cookie can list hashes and
    then issue `DELETE /api/v1/tokens/<hash>` to revoke a victim's
    OTHER tokens (denial of service against agent automation that
    relies on those tokens). Hashes are also a stable correlator
    that survives token rotation.

    Fix: return only a stable prefix (`hash[:8] + '...'`) plus a
    server-issued opaque id for revocation. Match the prefix style
    `sweep_inactive_tokens_endpoint` already uses
    (admin.py:280-281).
    """
    from iam_jit.routes import tokens as tokens_route

    src = inspect.getsource(tokens_route.list_my_tokens)
    assert '"token_hash": r.token_hash' in src


# ---------------------------------------------------------------------------
# 12. External-id for cross-account assume is deterministic per account
# ---------------------------------------------------------------------------


def test_finding_external_id_is_predictable_per_account() -> None:
    """Finding: EXTERNAL-ID-PREDICTABLE.

    CWE-330 (Use of Insufficiently Random Values).
    Severity: MED.
    Location: src/iam_jit/onboarding.py:165-166.

    The `OnboardingPlan` ExternalId is hard-coded as
    `f"iam-jit-{account_id}"`. The AWS account id is not secret
    (it's printed in support tickets, on bills, in CloudFormation
    drift reports, on every ARN). The whole point of an external-id
    is to be a shared secret between iam-jit (the role assumer) and
    the destination-account operator (the role's trust policy);
    a value derivable from public info defeats this control. Any
    party that learns the destination account id can forge a
    confused-deputy attack against the destination role's trust
    policy from a separate iam-jit-like service or from anywhere
    else holding the same trust policy template.

    Fix: generate per-account ExternalIds with
    `secrets.token_urlsafe(24)` and surface the generated value in
    the onboarding artifacts (same place the predictable value is
    surfaced today).
    """
    from iam_jit.onboarding import render_plan

    plan = render_plan(account_id="123456789012", region="us-east-1")
    assert plan.expected_provisioner_external_id == "iam-jit-123456789012"
    # And the discovery one mirrors the same scheme.
    assert plan.expected_discovery_external_id == "iam-jit-discovery-123456789012"


# ---------------------------------------------------------------------------
# 13. Audit-log writer swallows OSError silently (chain integrity gap)
# ---------------------------------------------------------------------------


def test_finding_audit_emit_swallows_disk_write_failure() -> None:
    """Finding: AUDIT-WRITE-SILENT-FAILURE.

    CWE-778 (Insufficient Logging).
    Severity: MED.
    Location: src/iam_jit/audit.py:202-211.

    `emit()` opens the audit file with O_APPEND inside a
    `try/except OSError: pass` block. If the disk is full, the path
    is unwritable, or any other I/O issue strikes, the function
    returns success and the chain advances in memory — but the next
    process to read the on-disk log will see a missing row, the
    hash chain will fail verification at the missing seq, AND the
    in-memory `_LAST_HASH` has already moved on. Subsequent emits
    chain off the missing row, so every later row also fails
    verification. The system reports tampering when the real cause
    is a write failure.

    Worse: an attacker who can fill the audit volume disables the
    log without tripping any alarm; only an out-of-band CW Logs
    alarm catches this.

    Fix: on write failure, surface as a CRITICAL log line AND raise
    so the caller (route handler) can decide whether to refuse the
    action being audited. For high-value actions (approve, revoke,
    admin), refuse on audit-write failure.
    """
    import iam_jit.audit as audit_mod

    src = inspect.getsource(audit_mod.emit)
    # The except clause swallows OSError silently — current behavior.
    # Match `except OSError:` followed by `pass` on the next non-empty line.
    assert re.search(r"except OSError:\s+pass", src) is not None


# ---------------------------------------------------------------------------
# 14. /api/v1/auth/magic-link has no rate limit
# ---------------------------------------------------------------------------


def test_finding_magic_link_json_endpoint_has_no_rate_limit() -> None:
    """Finding: MAGIC-LINK-JSON-NO-RATELIMIT.

    CWE-307 (Improper Restriction of Excessive Authentication
    Attempts).
    Severity: MED.
    Location: src/iam_jit/routes/auth.py:55-102 (`issue_magic_link`).

    The JSON `POST /api/v1/auth/magic-link` endpoint has no per-IP
    rate limit. The HTML `/login` route at routes/web.py:210 has
    one (lines 228-241), but this sibling JSON path was missed.

    Consequences:
      - Free SES bill amplification (each known email triggers a
        sent email; an attacker enumerates the user list and
        hammers the endpoint).
      - Email-bombing of any registered user (denial-of-service of
        their inbox, plus reputation damage if SES gets reported
        as a spam source).
      - Acts as an oracle for the user database, since the
        observed downstream effect (SES queue length, delivery
        report webhook) can leak which emails are real even
        though the HTTP response itself is uniform.

    Fix: add the same `rate_limit.check(client_id, kind="login")`
    call the HTML route uses, before any `sign_magic_link()` call.
    """
    # CLOSED: per-IP magic-link limiter added via
    # `_get_magic_link_ip_limiter().check(ip, kind="magic_link")`.
    from iam_jit.routes import auth as auth_route

    src = inspect.getsource(auth_route.issue_magic_link)
    assert "limiter" in src and "check" in src, (
        "magic-link route should call its per-IP limiter — regression"
    )


# ---------------------------------------------------------------------------
# 15. CIDR allowlist allows last-entry removal when allowlist is empty
# ---------------------------------------------------------------------------


def test_finding_admin_cidr_remove_route_has_admin_check_only_via_dependency() -> None:
    """Finding: CIDR-REMOVE-NO-AUDIT-ON-EMPTY-START.

    CWE-285 (Improper Authorization) — adjacent.
    Severity: LOW.
    Location: src/iam_jit/routes/admin.py:358-396 (`remove_cidr`).

    The route refuses to remove the LAST CIDR entry, but does NOT
    refuse to remove an entry that doesn't match any existing entry
    (404 path), and does NOT audit-log the attempt. An admin
    repeatedly probing for which CIDR strings exist leaves zero
    durable trail. The remove-success path does audit-log, but the
    refusal path (404) doesn't.

    Fix: emit an audit event on every remove attempt regardless of
    outcome — the audit log is the record of *what was tried*, not
    just *what worked*.
    """
    from iam_jit.routes import admin as admin_route

    src = inspect.getsource(admin_route.remove_cidr)
    # Audit is only emitted on the success path; the 404 path returns
    # without any audit.emit call before it.
    refuse_block_re = re.search(r'if not removed:\s+raise HTTPException', src)
    assert refuse_block_re is not None, "code shape changed; re-check finding"


# ---------------------------------------------------------------------------
# 16. extract_iam_principal trusts event.requestContext.authorizer.iam.userArn
#     without validating shape strongly
# ---------------------------------------------------------------------------


def test_finding_extract_iam_principal_minimal_validation() -> None:
    """Finding: IAM-PRINCIPAL-WEAK-VALIDATION.

    CWE-20 (Improper Input Validation).
    Severity: LOW.
    Location: src/iam_jit/auth.py:146-159 (`extract_iam_principal`)
    + 162-177 (`normalize_iam_id`).

    The aws_iam auth path reads the principal ARN from the Lambda
    event with only `isinstance(arn, str) and arn.startswith("arn:")`.
    Function URL with AWS_IAM populates this field from the verified
    SigV4 signature, so in production the value is trustworthy. The
    finding is defense-in-depth: any future code path that calls
    this function with a less-trusted event source (an explicitly
    crafted JSON in a unit test that becomes production code, an
    SQS-triggered Lambda, etc.) would accept ARNs like
    `arn:zzz::../../etc/passwd`. The normalizer then uses
    string-slicing which is forgiving.

    Fix: validate the ARN against the AWS ARN regex
    `^arn:(aws|aws-cn|aws-us-gov):[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:.+$`
    before accepting it. Same regex used in the accounts onboarding
    Pydantic model — share it.
    """
    from iam_jit.auth import extract_iam_principal

    # Garbage that still starts with `arn:` slips through.
    garbage = "arn:zzzz::../../etc/passwd"
    assert (
        extract_iam_principal(
            {"requestContext": {"authorizer": {"iam": {"userArn": garbage}}}}
        )
        == garbage
    )


# ---------------------------------------------------------------------------
# 17. Stripe handler ties `user_id` to customer-supplied email
# ---------------------------------------------------------------------------


def test_finding_stripe_handler_uses_email_as_user_id() -> None:
    """Finding: STRIPE-EMAIL-COLLISION.

    CWE-345 (Insufficient Verification of Data Authenticity).
    Severity: MED.
    Location: src/iam_jit/stripe_webhook.py:236
    (`issue_api_token(user_id=email, ...)`).

    The token's `user_id` is set to the email the customer typed
    into Stripe Checkout. If that email collides with an existing
    iam-jit user record (whose access was granted by some other
    onboarding path), the new Stripe-issued token is bound to the
    existing user's permissions. A paying customer who knows or
    guesses an admin email could subscribe under that email and
    receive a token tied to the admin user_id. The token is then
    accepted by the middleware (`middleware.py:101 record.user_id`
    → `user_store.get(...)`) with the admin's role intact.

    Fix: namespace Stripe-issued user_ids as
    `stripe:<customer_id>` (the Stripe customer id IS unique and
    not user-typed). When the customer signs in by email later,
    merge the records under an explicit admin-approved step.
    """
    from iam_jit.stripe_webhook import handle_checkout_session_completed
    from iam_jit.api_tokens_store import InMemoryAPITokenStore

    store = InMemoryAPITokenStore()
    os.environ["STRIPE_PRICE_ID_TO_TIER"] = '{"price_x":"indie"}'
    event = {
        "id": "evt_xx",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                # Existing iam-jit user's address — adversarial.
                "customer_email": "admin@victim.example",
                "line_items": {"data": [{"price": {"id": "price_x"}}]},
                "customer": "cus_attacker",
            }
        },
    }
    result = handle_checkout_session_completed(event, tokens_store=store)
    assert result is not None
    # The stored user_id is the raw email — collision risk realized.
    rec = store.list_for_user("admin@victim.example")
    assert len(rec) == 1
    assert rec[0].user_id == "admin@victim.example"


# ---------------------------------------------------------------------------
# 18. MCP server has no per-message size limit
# ---------------------------------------------------------------------------


def test_finding_mcp_server_no_message_size_limit() -> None:
    """Finding: MCP-NO-MESSAGE-CAP.

    CWE-770 (Allocation of Resources Without Limits or Throttling).
    Severity: LOW (stdio transport; local-trust).
    Location: src/iam_jit/mcp_server.py:261-293 (`main`).

    The MCP server reads `for line in sys.stdin: line = line.strip()`.
    No upper bound on a single line. An MCP host that sends a 1 GB
    JSON line will exhaust the Python process's memory before
    `json.loads` even runs. The transport is stdio so the attacker
    surface is "anyone who can write to the iam-jit process's stdin"
    — typically the locally-running agent, which is in-trust. Still
    worth a cap (the spec is line-delimited JSON; legitimate frames
    are KB-scale).

    Fix: read with a hard cap, e.g.
        line = sys.stdin.readline(1024 * 256)
    and refuse longer lines with `-32600` (invalid request).
    """
    from iam_jit import mcp_server

    src = inspect.getsource(mcp_server.main)
    assert "readline(" not in src
    assert "for line in sys.stdin" in src


# ---------------------------------------------------------------------------
# 19. Score route returns full Pydantic ValidationError detail (info disclosure)
# ---------------------------------------------------------------------------


def test_finding_score_error_path_returns_exception_repr() -> None:
    """Finding: SCORE-EXC-REPR-LEAK.

    CWE-209 (Information Exposure Through an Error Message).
    Severity: LOW.
    Location: src/iam_jit/routes/score.py:504-511.

    On scorer crash, the endpoint returns
    `detail=f"could not score policy: {type(e).__name__}: {e}"`.
    For an internal exception this leaks the class name and string
    repr — useful for an attacker reverse-engineering which input
    shapes break the scorer. The scorer is documented as "supposed
    to be defensive" so any crash is also a latent reliability bug;
    leaking the message hints at where it lives.

    Fix: log the exception server-side; return a generic
    `"could not score policy"` (HTTP 400) to the caller.
    """
    from iam_jit.routes import score as score_mod

    src = inspect.getsource(score_mod.score_policy)
    assert 'detail=f"could not score policy: {type(e).__name__}: {e}"' in src


# ---------------------------------------------------------------------------
# 20. Session cookie max-age == 24h with no idle timeout
# ---------------------------------------------------------------------------


def test_finding_session_cookie_no_idle_timeout() -> None:
    """Finding: SESSION-NO-IDLE-TIMEOUT.

    CWE-613 (Insufficient Session Expiration).
    Severity: LOW.
    Location: src/iam_jit/auth.py:30 (`_SESSION_TTL_SECONDS = 24 *
    60 * 60`) + routes/auth.py:145, routes/web.py:530.

    The session cookie has an absolute 24-hour TTL from issuance.
    There's no idle-timeout — a session that hasn't been used in
    23h59m is still valid for one more click. There's also no
    server-side session revocation (signed-cookie sessions are
    stateless): an admin who suspects a session is compromised
    cannot revoke that single session, only force a global rotation
    by changing the magic-link signing secret. Changing the secret
    invalidates EVERY session (including the admin's own) and every
    in-flight magic-link.

    Fix: shorten to 4 hours; emit a sliding renewal cookie on each
    request so active users don't get bumped; add a "force sign-out
    all sessions for user X" admin endpoint that bumps a per-user
    epoch baked into the cookie so old cookies fail verification.
    """
    from iam_jit import auth as auth_mod

    assert auth_mod._SESSION_TTL_SECONDS == 24 * 60 * 60


# ---------------------------------------------------------------------------
# 21. Audit log path is reader-readable on misconfig (0o600 only if open
#     succeeds with that mode flag)
# ---------------------------------------------------------------------------


def test_finding_audit_file_mode_applies_only_at_creation() -> None:
    """Finding: AUDIT-FILE-MODE-FOOTGUN.

    CWE-732 (Incorrect Permission Assignment for Critical
    Resource).
    Severity: LOW.
    Location: src/iam_jit/audit.py:205.

    `os.open(path, O_WRONLY|O_CREAT|O_APPEND, 0o600)` only applies
    the 0o600 mode when the file is CREATED. If the audit file
    already exists with looser permissions (e.g. an operator
    pre-created it with 0o644), each subsequent open is a no-op
    and the file keeps its existing mode. Combined with finding 13
    (silent failure on disk error), an attacker who can pre-create
    or chmod the file can read+truncate without detection.

    Fix: after open, call `os.fchmod(fd, 0o600)` unconditionally so
    the mode applies on every open.
    """
    import iam_jit.audit as audit_mod

    src = inspect.getsource(audit_mod.emit)
    assert "fchmod" not in src
    assert "0o600" in src


# ---------------------------------------------------------------------------
# 22. health endpoint exposes deployment posture without auth
# ---------------------------------------------------------------------------


def test_finding_healthz_leaks_deployment_posture_unauthenticated() -> None:
    """Finding: HEALTHZ-POSTURE-LEAK.

    CWE-200 (Exposure of Sensitive Information to an Unauthorized
    Actor).
    Severity: LOW.
    Location: src/iam_jit/routes/health.py:16-34.

    `/healthz` is anonymous and returns `auth_mode`,
    `user_config_source`, `llm_backend`, and a `security_posture`
    block. The posture flags are documented as no-secrets, but they
    are excellent recon for an attacker:
    "auth_mode=local" + "alb_in_front=true" + "https_on_alb=false"
    is a sign saying 'send the BootstrapSetupKey over cleartext
    HTTP and watch the wire'.

    Fix: return only `{"status": "ok"}` on the anonymous endpoint.
    Move the posture block to `/api/v1/admin/security-posture`
    where it already lives (admin-gated).
    """
    from iam_jit.routes.health import healthz

    out = healthz()
    assert "auth_mode" in out
    assert "security_posture" in out
    assert "llm_backend" in out


# ---------------------------------------------------------------------------
# 23. policy/analyze route loads arbitrary policy dict without size cap
#     beyond the app-level 256 KiB
# ---------------------------------------------------------------------------


def test_finding_policy_analyze_no_per_field_caps() -> None:
    """Finding: POLICY-ANALYZE-NO-PER-FIELD-CAP.

    CWE-770 (Allocation of Resources Without Limits or Throttling).
    Severity: LOW.
    Location: src/iam_jit/routes/policy.py:23-55.

    The body is `dict[str, Any]` with no Pydantic shape, so any
    nested structure within the global 256 KiB body cap is
    accepted. The scorer walks the policy recursively
    (review._iter_string_values pattern); a deeply-nested object
    can stack-overflow Python's default recursion limit (~1000).
    Within 256 KiB an attacker can easily craft 10k nesting
    levels. The exception is caught by the scorer's outer
    try/except (route's 400 path) but the route still consumed
    Lambda compute.

    Fix: use a Pydantic model with bounded depth or pre-walk the
    structure with an iterative-depth limit before invoking the
    scorer.
    """
    from iam_jit.routes import policy as policy_route

    src = inspect.getsource(policy_route.analyze)
    # Body is the raw `dict[str, Any]` (no Pydantic schema).
    assert "dict[str, Any]" in src
    assert "BaseModel" not in src


# ---------------------------------------------------------------------------
# 24. tokens.create_token allows label of unbounded length
# ---------------------------------------------------------------------------


def test_finding_token_label_unbounded() -> None:
    """Finding: TOKEN-LABEL-UNBOUNDED.

    CWE-1284 (Improper Validation of Specified Quantity in Input).
    Severity: LOW.
    Location: src/iam_jit/routes/tokens.py:42-44 (`create_token`).

    The label is type-checked (`isinstance(label, str)`) but not
    length-checked. Combined with the 256 KiB body cap, an
    authenticated user can store up to ~256 KiB of arbitrary text
    in the API tokens table per token. With unlimited token mint
    permission per authenticated user (no per-user quota — only the
    global score limiter), that's a steady stream of DDB write
    capacity burn.

    Fix: cap label at 200 chars (same cap as CIDR notes per
    admin.py:334-337); also add a per-user quota on tokens-issued
    (`POST /api/v1/tokens` mints arbitrary tokens).
    """
    # Partially CLOSED: per-user token mint quota now enforced via
    # `_per_user_cap()` + `list_for_user(user.id)` check before mint.
    # The label length cap remains a follow-up nit (LOW severity);
    # this assertion is split so the closure progress is pinned.
    from iam_jit.routes import tokens as tokens_route

    src = inspect.getsource(tokens_route.create_token)
    assert "list_for_user" in src, (
        "per-user token cap should call list_for_user — regression"
    )
