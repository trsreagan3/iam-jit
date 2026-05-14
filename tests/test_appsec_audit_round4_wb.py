"""White-box appsec audit, round 4.

Round 4 of the white-box review on 2026-05-14, scoped to:

  1. **Re-audit of round-3 closures** — verify each closure actually
     closes the named bug AND does not introduce a structurally-adjacent
     new one. Focus on: did the fix propagate to every sibling call site,
     or only to the single named site?

  2. **New surfaces introduced by the round-3 closures** — the
     `session_revocation` module, the `trusted_proxy` module, the per-
     user-mint `defaultdict[Lock]`, the chunked-encoding refusal, and
     the new env vars: `IAM_JIT_SESSION_REVOCATION_TABLE`,
     `IAM_JIT_SESSION_REVOCATION_FAIL_OPEN`,
     `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA`,
     `IAM_JIT_PROCESSED_EVENTS_TABLE` (the wire-up).

  3. **Cross-cutting fix-fan-out** — every "extract to a shared helper"
     fix from round 3 needs the LAST call site verified.

Test conventions follow rounds 1, 2, 3: each test asserts CURRENT
(vulnerable) behavior. When a fix lands, flip the assertion or delete
the test as part of the fix PR.

Severity rubric (matches rounds 1, 2, 3):
  - CRIT — unauthenticated full account/data takeover at internet scale
  - HIGH — auth bypass / privilege escalation / unbounded resource burn
  - MED  — exploitable defense-in-depth gap; documented bypass with
           realistic prerequisites
  - LOW  — footgun / inconsistency / signal-loss-only

NEW-CODE markers (`# NEW-CODE`) flag findings on code introduced or
substantially rewritten in round 3.

Run only this file:

    pytest tests/test_appsec_audit_round4_wb.py -v

Summary doc: docs/security/AUDIT-2026-05-WB-ROUND4.md
"""

from __future__ import annotations

import inspect
import os
import threading
import time

import pytest


# ---------------------------------------------------------------------------
# 1. (HIGH) IAM_JIT_PROCESSED_EVENTS_TABLE is silently ignored. The
#    DDB-backed ProcessedEventsStore was never shipped; multi-instance
#    Stripe idempotency is NOT enforced even when the operator configures
#    the env var per the docs.
# ---------------------------------------------------------------------------


def test_finding_stripe_ddb_processed_events_unwired() -> None:
    """Finding: STRIPE-DDB-PROCESSED-EVENTS-UNWIRED.

    CWE-799 / CWE-1325 (incomplete fix).
    Severity: HIGH (multi-instance Lambda duplicate-mints under retry).
    Location: src/iam_jit/app.py:129-155 (`_build_processed_events_store_from_env`).

    The round-1 closure for STRIPE-NO-IDEMPOTENCY introduced a
    `ProcessedEventsStore` protocol and an in-memory implementation.
    The protocol's `release()` method was added in round 3 to close
    `STRIPE-CLAIM-BEFORE-PROCESS`. Both closures assume the deployed
    store is durable across Lambda instances.

    But: `_build_processed_events_store_from_env` returns the in-
    memory store regardless of whether `IAM_JIT_PROCESSED_EVENTS_TABLE`
    is set. The env var is only logged as a warning. Operators who
    follow the deploy docs ("set this table for prod") get exactly
    the same behavior as not setting it — and have no way to fix it
    via configuration.

    Realistic scenario: production Lambda with default unreserved
    concurrency. Stripe retries land on different instances; each
    instance has an empty `_seen` dict; each retry mints a fresh
    token. The customer ends up with N tokens for one paid
    subscription. The round-1 finding is still open in multi-
    instance posture.

    Fix sketch: ship a `DynamoDBProcessedEventsStore` (PutItem with
    `ConditionExpression="attribute_not_exists(event_id)"`; DeleteItem
    for release; TTL on a 30-day window). Until then, REFUSE startup
    when `AWS_LAMBDA_FUNCTION_NAME` is set AND
    `IAM_JIT_PROCESSED_EVENTS_TABLE` is unset AND reserved-concurrency
    is not 1 — same defensive shape used for
    `IAM_JIT_MAGIC_LINK_NONCES_TABLE`.
    """
    # CLOSED: `DynamoDBProcessedEventsStore` ships in
    # `stripe_webhook.py`; `_build_processed_events_store_from_env`
    # now instantiates it when `IAM_JIT_PROCESSED_EVENTS_TABLE` is
    # set. SAM template provisions `ProcessedEventsTable` with TTL
    # on `expires_at` and wires the env var in.
    from iam_jit import app as app_mod
    from iam_jit.stripe_webhook import (
        DynamoDBProcessedEventsStore,
        InMemoryProcessedEventsStore,
    )

    saved_table = os.environ.get("IAM_JIT_PROCESSED_EVENTS_TABLE")
    saved_region = os.environ.get("AWS_DEFAULT_REGION")
    try:
        os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
        os.environ["IAM_JIT_PROCESSED_EVENTS_TABLE"] = (
            "iam-jit-stripe-processed-events-prod"
        )
        store = app_mod._build_processed_events_store_from_env()
        assert isinstance(store, DynamoDBProcessedEventsStore), (
            f"expected DynamoDBProcessedEventsStore when env var set; "
            f"got {type(store).__name__}. Multi-instance Stripe "
            f"webhooks would duplicate-mint."
        )

        # Fallback: unset env var → in-memory (correct default for
        # single-instance / local dev).
        os.environ.pop("IAM_JIT_PROCESSED_EVENTS_TABLE", None)
        fallback = app_mod._build_processed_events_store_from_env()
        assert isinstance(fallback, InMemoryProcessedEventsStore)
    finally:
        if saved_table is None:
            os.environ.pop("IAM_JIT_PROCESSED_EVENTS_TABLE", None)
        else:
            os.environ["IAM_JIT_PROCESSED_EVENTS_TABLE"] = saved_table
        if saved_region is None:
            os.environ.pop("AWS_DEFAULT_REGION", None)
        else:
            os.environ["AWS_DEFAULT_REGION"] = saved_region


# ---------------------------------------------------------------------------
# 2. (HIGH) IAM_JIT_SESSION_REVOCATION_FAIL_OPEN=1 silently disables
#    server-side session revocation — same shape as the round-3
#    BANS-DDB-FAIL-OPEN-VIA-ENV finding, but the loud-bypass treatment
#    that closure mandated did NOT land on this sibling env var.
# ---------------------------------------------------------------------------


def test_finding_session_revocation_fail_open_silent_bypass() -> None:
    """Finding: SESSION-REVOCATION-FAIL-OPEN-SILENT-BYPASS.  # NEW-CODE

    CWE-732 / CWE-755.
    Severity: HIGH (the headline round-3 closure can be silently
    turned off).
    Location: src/iam_jit/middleware.py:159-181.

    Round 3 added the env var `IAM_JIT_SESSION_REVOCATION_FAIL_OPEN`
    as the operator escape hatch when the new server-side revocation
    store has an outage. The escape hatch is correct in principle.
    The bug is that — unlike its sibling `IAM_JIT_BANS_FAIL_OPEN`
    which the same round explicitly hardened with a `.critical()`
    log on every bypass invocation (`middleware.py:236-241`,
    "ALARM ON THIS LOG.") — this new env var was added WITHOUT the
    matching loud-bypass treatment.

    The round-3 BANS-DDB-FAIL-OPEN-VIA-ENV writeup wrote, verbatim:
    "this preserves the operator escape hatch but kills the
    silent-bypass shape". The lesson did not propagate to the
    sibling env var added in the same round.

    Realistic mis-set: SRE chases a 503 spike alarm during a DDB
    throttle, sets the flag, brings the service back up, forgets to
    clear it. Logged-out and admin-revoked sessions silently remain
    valid until the cookie's natural 24h TTL.

    Fix sketch: copy the exact CRITICAL-log pattern from the bans
    fail-open path. Also: emit an `audit.emit` event with kind
    `security.session_revocation_disabled` so the audit log retains
    a durable record.
    """
    # CLOSED: session-revocation fail-open path now emits a
    # CRITICAL log line on every bypass invocation, matching the
    # round-3 IAM_JIT_BANS_FAIL_OPEN treatment.
    from iam_jit import middleware

    src = inspect.getsource(middleware._identify_user)
    assert "IAM_JIT_SESSION_REVOCATION_FAIL_OPEN" in src

    marker = "session-revocation check failed"
    assert marker in src
    start = src.index(marker)
    block = src[start:start + 1200]
    assert ".critical(" in block, (
        "Expected .critical(...) on the session-revocation fail-open "
        "branch (round-4 closure). Got block: " + block[:300]
    )
    assert "ALARM ON THIS LOG" in block


# ---------------------------------------------------------------------------
# 3. (MED) routes/web._login_client_id still inlines IAM_JIT_TRUSTED_PROXY_CIDRS
#    parsing instead of delegating to the trusted_proxy SoT — last call
#    site missed by the round-3 TRUSTED-PROXY-CIDRS-PARSER-DISCREPANCY closure.
# ---------------------------------------------------------------------------


def test_finding_web_login_client_ip_inline_cidr_parser() -> None:
    """Finding: WEB-LOGIN-CLIENT-IP-INLINE-CIDR-PARSER.

    CWE-710 / CWE-1389-adjacent (parser drift across siblings).
    Severity: MED.
    Location: src/iam_jit/routes/web.py:198-259 (`_login_client_id`).

    Round 3 extracted `iam_jit.trusted_proxy` as the single source
    of truth for `IAM_JIT_TRUSTED_PROXY_CIDRS` parsing + matching.
    Four call sites migrated: `routes/score.py:_client_ip`,
    `network_acl._read_source_ip`,
    `public_url._peer_in_trusted_proxy_cidrs`, and
    `routes/auth._magic_link_client_ip`.

    `routes/web._login_client_id` was missed. It still inlines its
    own parser:

        for tok in trusted_cidrs_raw.replace(",", " ").split():
            ...

    Bug-for-bug differences from `trusted_proxy`:
      - No IPv4-mapped IPv6 normalization on the peer address.
        `trusted_proxy.peer_in_trusted_cidrs` normalizes
        `::ffff:10.0.0.5` → `10.0.0.5` before the CIDR check; this
        inline version does NOT. An operator with a dual-stack
        Lambda Function URL whose peer arrives as `::ffff:<cf-pop-v4>`
        gets the same broken posture round-3
        XFF-IPV4-MAPPED-IPV6 supposedly closed at every other site.
      - Even if the parser logic happens to match today, the
        round-3 closure's stated goal was "single source of truth".
        Drift here means future helper fixes (e.g., adding cycle-
        proof XFF chains) won't propagate.

    Impact: a CloudFront → ALB → Lambda stack with an IPv4-mapped
    IPv6 peer has the /login rate-limiter keyed on `peer.host`
    (== ALB's IPv4-mapped IPv6 string) — one user's burst denies
    sign-in for every other user routed through the same ALB.

    Fix sketch: replace the 60-line body with the same two-line
    `trusted_proxy.real_client_from_xff` call that
    `_magic_link_client_ip` uses.
    """
    from iam_jit.routes import web as web_mod

    src = inspect.getsource(web_mod._login_client_id)
    # The inline parser + matcher is still present.
    assert "ip_network" in src
    assert "ip_address" in src
    # And the helper that should be used is NOT.
    assert "trusted_proxy" not in src, (
        "_login_client_id now calls into iam_jit.trusted_proxy — the "
        "fix has shipped. Flip this test."
    )
    # Specifically: no IPv4-mapped normalization (the round-3 fix
    # that DID land at every other site that uses trusted_proxy).
    assert "ipv4_mapped" not in src, (
        "_login_client_id now normalizes IPv4-mapped IPv6 inline — "
        "the drift is partly closed. Verify and flip this test."
    )


# ---------------------------------------------------------------------------
# 4. (MED) magic_callback's bootstrap-admin auto-seed parses XFF inline
#    with the leftmost-token shape — same as round-2 SCORE-XFF-LEFTMOST-TRUSTED.
# ---------------------------------------------------------------------------


def test_finding_bootstrap_autoseed_xff_leftmost() -> None:
    """Finding: BOOTSTRAP-AUTOSEED-XFF-LEFTMOST.

    CWE-348 (Use of Less Trusted Source).
    Severity: MED — unauthenticated XFF spoof poisons the runtime
    CIDR allowlist on bootstrap-admin first sign-in.
    Location: src/iam_jit/routes/web.py:578-594 (`magic_callback`).

    The round-3 WEB-MAGIC-CALLBACK-BROKEN-AUTO-SEED closure added
    `request: Request` to the signature and re-enabled the auto-
    seed branch. But the IMPLEMENTATION inside the branch still
    parses XFF inline with all the failure modes that round 2
    closed everywhere else:

        xff = request.headers.get("x-forwarded-for") or ""
        client_host = request.client.host if request.client else None
        source_ip = None
        if (
            os.environ.get("IAM_JIT_TRUST_FORWARDED_FOR", "1").lower()
            in {"1", "true", "yes"}
        ) and xff:
            source_ip = xff.split(",")[0].strip()  # LEFTMOST

    Three failures stacked:
      1. Default `IAM_JIT_TRUST_FORWARDED_FOR=1` here — opposite of
         network_acl's "0" default. An operator who deliberately
         set it to 0 for network_acl is overridden.
      2. `split(",")[0].strip()` — leftmost. Round-2 SCORE-XFF-
         LEFTMOST-TRUSTED closed this everywhere else.
      3. No trusted-proxy peer gate — any XFF is trusted regardless
         of who the peer is.

    Attacker hits /auth/magic-callback?token=<attacker-token>
    (or wins a race against the legitimate bootstrap admin) with
    `X-Forwarded-For: <attacker-CIDR>, real-cf-pop` and pins the
    runtime allowlist to their IP. After this, the bootstrap
    admin's /admin/network UI shows the attacker's IP as the
    "captured IP" — and the operator trusts the docstring.

    Fix sketch: replace the inline XFF parse with
    `trusted_proxy.real_client_from_xff(client_host, xff)` and gate
    on `IAM_JIT_TRUSTED_PROXY_CIDRS` being configured (delete the
    `IAM_JIT_TRUST_FORWARDED_FOR` env-only path).
    """
    from iam_jit.routes import web as web_mod

    src = inspect.getsource(web_mod.magic_callback)
    # Confirm magic_callback has the auto-seed branch (round-3
    # WEB-MAGIC-CALLBACK-BROKEN-AUTO-SEED closure required
    # `request: Request` to land first).
    assert "auto_seed_for_bootstrap" in src
    # The leftmost-XFF pattern is still here.
    assert 'split(",")[0]' in src or '.split(",")[0]' in src
    # And the helper is NOT used.
    auto_seed_block_start = src.index("Pull the caller's IP")
    auto_seed_block = src[auto_seed_block_start:auto_seed_block_start + 1500]
    assert "trusted_proxy" not in auto_seed_block, (
        "Bootstrap auto-seed now uses trusted_proxy — flip this test."
    )
    # Default is `IAM_JIT_TRUST_FORWARDED_FOR=1` HERE (opposite of
    # network_acl.py's "0" default).
    assert 'IAM_JIT_TRUST_FORWARDED_FOR", "1"' in auto_seed_block


# ---------------------------------------------------------------------------
# 5. (MED) DEV-INSECURE-SECRET Lambda gate landed only on the delivery
#    leg; CSRF and Secure-cookie legs remain untouched.
# ---------------------------------------------------------------------------


def test_finding_dev_insecure_lambda_gate_csrf_and_cookie_legs_open() -> None:
    """Finding: DEV-INSECURE-LAMBDA-GATE-CSRF-AND-COOKIE-LEGS-OPEN.

    CWE-1188 / CWE-732.
    Severity: MED — prod-with-dev-flag misconfig disables CSRF and
    drops `Secure` from session cookies independently of SES.
    Location: src/iam_jit/app.py:236, src/iam_jit/routes/auth.py:252,
    src/iam_jit/routes/web.py:611.

    Round 3 introduced `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA` as
    the explicit opt-in for dev-insecure-in-prod. The closure
    landed on the DELIVERY leg of the round-3
    DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN finding only.

    The other two legs identified by that round-3 finding are
    untouched:
      - CSRF middleware: `app.py:236` — `if os.environ.get(
        "IAM_JIT_DEV_INSECURE_SECRET") == "1": return await call_next(request)`.
        No Lambda check; bypasses CSRF entirely.
      - Session cookie `Secure`: `auth.py:252` and `web.py:611` —
        `secure=os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") != "1"`.
        No Lambda check; cookie issued without `Secure`.

    A prod deploy that inherits the dev flag from `.env.example` (or
    a CI smoke-test env-var bleed) ships with CSRF off and non-
    Secure cookies. The delivery-leg closure now LOUDLY refuses to
    issue the magic link in-response, so the operator notices — but
    once they un-inherit the flag specifically for delivery (e.g.,
    by setting an SES sender), they may not realize the OTHER two
    legs were still silently active before they fixed the flag.

    Fix sketch: extract a helper `_dev_insecure_active()` that
    consults BOTH `IAM_JIT_DEV_INSECURE_SECRET` and the Lambda
    gate, and call it from all four sites. Better: refuse module
    import when the flag and `AWS_LAMBDA_FUNCTION_NAME` are both
    set without the explicit Lambda-allow flag.
    """
    from iam_jit import app as app_mod
    from iam_jit.routes import auth as auth_route, web as web_mod

    app_src = inspect.getsource(app_mod.create_app)
    auth_src = inspect.getsource(auth_route)
    web_src = inspect.getsource(web_mod)

    # CSRF leg: dev-flag check exists; no AWS_LAMBDA_FUNCTION_NAME
    # gate adjacent to it.
    csrf_start = app_src.index("_enforce_csrf")
    csrf_end = app_src.index("_enforce_max_body_size")
    csrf_block = app_src[csrf_start:csrf_end]
    assert 'IAM_JIT_DEV_INSECURE_SECRET") == "1"' in csrf_block
    assert "AWS_LAMBDA_FUNCTION_NAME" not in csrf_block
    assert "IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA" not in csrf_block, (
        "CSRF middleware now consults the Lambda allow flag — flip "
        "this test."
    )

    # Cookie-secure legs (both /api/v1/auth/callback and /auth/magic-callback).
    for label, src_text in (("auth", auth_src), ("web", web_src)):
        assert (
            'secure=os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") != "1"'
            in src_text
        ), f"{label}: cookie-set call no longer keys on the dev flag — flip this test."
        # Find the cookie-set call and confirm no allow-in-Lambda
        # check is adjacent.
        idx = src_text.index('secure=os.environ.get("IAM_JIT_DEV_INSECURE_SECRET")')
        nearby = src_text[max(0, idx - 200):idx + 200]
        assert "IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA" not in nearby, (
            f"{label}: cookie-set call now consults the Lambda allow "
            "flag — flip this test."
        )


# ---------------------------------------------------------------------------
# 6. (MED) Session revocation keys on the cookie VALUE, not the user.
#    Logout in Browser A doesn't revoke Browser B's session — the
#    user-expected "logout = logout everywhere" semantic is broken.
# ---------------------------------------------------------------------------


def test_finding_session_revocation_is_per_cookie_value_not_per_user() -> None:
    """Finding: SESSION-REVOCATION-IS-PER-COOKIE-VALUE-NOT-PER-USER.  # NEW-CODE

    CWE-613 (Insufficient Session Expiration).
    Severity: MED — a stolen-but-undisclosed cookie outlives the
    user's logout click.
    Location: src/iam_jit/session_revocation.py:36-69 +
    src/iam_jit/middleware.py:148-158.

    `_cookie_hash` keys on `sha256(cookie_value)`. Each magic-link
    sign-in mints a fresh signed cookie (TimestampSigner includes
    the issue-time stamp). A user signed in on two devices has
    two distinct cookie values. Logout from one device only
    revokes one cookie. The other device's session remains valid
    until the 24h natural TTL.

    Realistic shape: user suspects laptop compromise, signs out
    from their phone. The phone's session is revoked; the
    laptop's is NOT — the attacker who already exfiltrated the
    laptop cookie keeps their access for the rest of the 24h
    window.

    Fix sketch: add a per-user revocation marker
    (`revoke-after-this-timestamp` keyed on user_id). Check the
    cookie's issued-at timestamp against the user's marker on
    every auth check.
    """
    from iam_jit import session_revocation as sr
    from iam_jit.auth import sign_session

    # Two sign() calls for the same user produce DIFFERENT cookie
    # values (they include the TimestampSigner's t= field).
    secret = "test-secret-do-not-use-in-prod"
    cookie_a = sign_session(secret, "email:alice@example.com")
    # Sleep > 1s to make sure the timestamps differ at second
    # granularity.
    time.sleep(1.1)
    cookie_b = sign_session(secret, "email:alice@example.com")
    assert cookie_a != cookie_b, (
        "TimestampSigner produced identical signed values within "
        "1s; this test's premise is broken."
    )

    sr.reset_default_store_for_tests()
    store = sr.get_default_store()
    store.revoke(cookie_a, ttl_seconds=24 * 60 * 60)

    # Cookie A is revoked.
    assert store.is_revoked(cookie_a) is True
    # Cookie B (same user, different sign() output) is NOT — the
    # revocation primitive is per-value, not per-user.
    assert store.is_revoked(cookie_b) is False, (
        "store.is_revoked is now per-user — the fix has shipped. "
        "Flip this test."
    )


# ---------------------------------------------------------------------------
# 7. (MED) bans.is_banned() raises on corrupt file (round-3 closure);
#    the /api/v1/auth/magic-link call site has no try/except, so a
#    corrupt ban file gives a 500 while every other email gets a
#    uniform 202. Registration / ban-status oracle for the affected
#    user.
# ---------------------------------------------------------------------------


def test_finding_bans_is_banned_raises_at_magic_link_issuance_leaks_registration() -> None:
    """Finding: BANS-IS-BANNED-RAISES-AT-MAGIC-LINK-ISSUANCE-LEAKS-REGISTRATION.

    CWE-203 (Observable Discrepancy).
    Severity: MED — a corrupt ban file (or any other bans-store
    failure for a specific user) yields a non-uniform response,
    distinguishing the user from the population.
    Location: src/iam_jit/routes/auth.py:192.

    Round-3 BAN-STORE-CORRUPT-FILE-UNBAN changed
    `FilesystemBanStore.get` (and therefore `is_banned`) to raise
    on `JSONDecodeError` rather than silently return None. The
    middleware's call site (`current_user` at `middleware.py:217-250`)
    has a try/except + fail-closed 503 to handle that. The magic-
    link issuance call site at `routes/auth.py:192` does NOT:

        if bans_mod.get_default_store().is_banned(user_id):
            return {"status": "if the email is registered, ..."}

    A raised exception propagates → bare 500 from FastAPI's default
    handler. Every other email returns 202 (uniform). The
    differentiable response IS the registration / ban-status
    oracle.

    Fix sketch: wrap in try/except matching the middleware pattern
    — log + return the uniform 202 on store failure, OR raise a
    deliberate 503 (which leaks "some backend trouble" but is
    uniform across all bans-store failures, not just the
    corrupt-file shape).
    """
    from iam_jit.routes import auth as auth_route

    src = inspect.getsource(auth_route.issue_magic_link)
    # The is_banned call is present.
    assert "is_banned(user_id)" in src
    # Identify the line and the lines that surround it. There is no
    # try/except wrapping JUST the is_banned call.
    idx = src.index("is_banned(user_id)")
    nearby = src[max(0, idx - 200):idx + 100]
    # The middleware wraps its is_banned in try/except. This route
    # does NOT.
    assert "try:" not in nearby or "except Exception" not in nearby, (
        "issue_magic_link now wraps is_banned in try/except — fix "
        "shipped; flip this test."
    )


# ---------------------------------------------------------------------------
# 8. (MED) _PER_USER_MINT_LOCKS uses defaultdict(threading.Lock).
#    defaultdict.__missing__ is multi-step in pure Python; two
#    cold-path threads can each construct a fresh Lock and one is
#    orphaned. Also: no eviction → per-user-id memory growth.
# ---------------------------------------------------------------------------


def test_finding_per_user_mint_locks_defaultdict_race_and_leak() -> None:
    """Finding: PER-USER-MINT-LOCKS-DEFAULTDICT-RACE-AND-LEAK.  # NEW-CODE

    CWE-367 / CWE-401.
    Severity: MED — re-introduces the round-3 TOCTOU on the cold
    path; unbounded memory growth.
    Location: src/iam_jit/routes/tokens.py:36, 77-96.

    Two issues:

      1. **defaultdict race**: `defaultdict.__missing__` runs
         `default_factory()` then `__setitem__` — multiple
         bytecodes. Two threads concurrently accessing
         `_PER_USER_MINT_LOCKS[same_user_id]` when the key is
         absent can EACH construct a NEW Lock and return their
         own. The loser's Lock is then orphaned; the dict has the
         winner's Lock. Two threads in different `with`-blocks =
         no mutual exclusion = the round-3 TOCTOU closure is
         re-introduced on the cold path.

      2. **Memory leak**: the dict has no eviction. After serving
         N distinct user_ids, the Lambda instance retains N Lock
         objects forever.

    Fix sketch:

        _LOCKS_GUARD = threading.Lock()
        _PER_USER_MINT_LOCKS: dict[str, threading.Lock] = {}

        def _get_user_lock(user_id: str) -> threading.Lock:
            with _LOCKS_GUARD:
                lock = _PER_USER_MINT_LOCKS.get(user_id)
                if lock is None:
                    lock = threading.Lock()
                    _PER_USER_MINT_LOCKS[user_id] = lock
                return lock
    """
    # CLOSED: the registry now uses `dict.setdefault` (atomic
    # under the CPython GIL) to ensure two racers receive the
    # SAME Lock object on first-create. No more defaultdict
    # double-construction.
    from iam_jit.routes import tokens as tokens_route

    src = inspect.getsource(tokens_route)
    assert "defaultdict(threading.Lock)" not in src
    assert ".setdefault(" in src

    # Behavioral check: two concurrent callers asking for the lock
    # for the SAME user_id receive identical Lock objects.
    user = "race@example.com"
    locks_seen: list = []

    def grab() -> None:
        locks_seen.append(tokens_route._per_user_lock(user))

    threads = [threading.Thread(target=grab) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len({id(L) for L in locks_seen}) == 1, (
        "expected all 8 racers to share the same Lock object; got "
        f"{len({id(L) for L in locks_seen})} distinct locks"
    )

    # Memory-growth note: the registry has no eviction so a Lambda
    # instance retains one Lock per distinct user_id ever seen.
    # Bounded by realistic per-instance user counts (Lambda
    # instances live minutes-hours and cap at concurrent user
    # diversity). Out-of-scope for launch; revisit if instance
    # lifetimes start exceeding hours.
    before = len(tokens_route._PER_USER_MINT_LOCKS_REGISTRY)
    for i in range(50):
        _ = tokens_route._per_user_lock(f"email:leak-test-{i}@example.com")
    after = len(tokens_route._PER_USER_MINT_LOCKS_REGISTRY)
    assert after - before >= 50


# ---------------------------------------------------------------------------
# 9. (LOW) trusted_proxy.real_client_from_xff returns the candidate as
#    a raw string (e.g. "::ffff:10.0.0.5") — downstream network_acl
#    then fails the cross-family membership check and rejects the
#    legitimate IPv4-mapped client.
# ---------------------------------------------------------------------------


def test_finding_network_acl_ipv4_mapped_ipv6_source_ip_allowlist() -> None:
    """Finding: NETWORK-ACL-IPV4-MAPPED-IPV6-SOURCE-IP-ALLOWLIST.

    CWE-754 (Improper Check for Unusual or Exceptional Conditions).
    Severity: LOW — fail-closed (legitimate client locked out),
    not a bypass.
    Location: src/iam_jit/trusted_proxy.py:113-137,
    src/iam_jit/network_acl.py:180-200.

    The round-3 XFF-IPV4-MAPPED-IPV6 closure normalized the
    *peer* IP before the trusted-proxy CIDR check. It did NOT
    normalize the *returned candidate* — `real_client_from_xff`
    returns `candidate` (the original string token) on success.

    Downstream, `network_acl.evaluate` does
    `ipaddress.ip_address(source_ip)` and the cross-family skip
    at line 189-192 means an IPv4 allowlist won't match a
    client whose XFF arrived as `::ffff:10.0.0.5`. Result:
    legitimate IPv4 client locked out.

    Fix sketch: in `real_client_from_xff`, return the normalized
    address form: after the `cand_addr.ipv4_mapped` reassignment,
    return `str(cand_addr)` rather than the original `candidate`.
    """
    from iam_jit import trusted_proxy

    # The candidate-return shape is here.
    src = inspect.getsource(trusted_proxy.real_client_from_xff)
    assert "return candidate" in src

    # Functional: an IPv4-mapped IPv6 candidate is returned
    # un-normalized.
    nets = trusted_proxy.parse_trusted_cidrs("10.0.0.0/8")
    # Peer is a trusted proxy (10.0.0.0/8 includes it after
    # normalization); XFF claims the real client is the IPv4-mapped
    # form of an external address.
    result = trusted_proxy.real_client_from_xff(
        "10.0.0.5",  # trusted peer
        "::ffff:8.8.8.8",  # external client in IPv4-mapped form
        nets,
    )
    # Today: returns the raw "::ffff:8.8.8.8" string. After the
    # fix: would return "8.8.8.8".
    assert result == "::ffff:8.8.8.8", (
        "Helper now normalizes the returned candidate — flip this "
        "test."
    )


# ---------------------------------------------------------------------------
# 10. (LOW) STRIPE release-on-exception lets a partially-failed
#     handler (durable write succeeded, then raised) mint a second
#     token on retry.
# ---------------------------------------------------------------------------


def test_finding_stripe_release_race_double_mint_on_partial_failure() -> None:
    """Finding: STRIPE-RELEASE-RACE-DOUBLE-MINT-ON-PARTIAL-FAILURE.  # NEW-CODE

    CWE-755 (Improper Handling of Exceptional Conditions).
    Severity: LOW — produces extra (not missing) tokens; bounded
    by per-user cap.
    Location: src/iam_jit/stripe_webhook.py:480-497.

    Round-3 STRIPE-CLAIM-BEFORE-PROCESS closure releases the claim
    on ANY handler exception. If `tokens_store.put(record)` committed
    BEFORE the exception escaped (DDB write went through; the
    boto3 return path raised, or a subsequent line raised), the
    release lets Stripe's retry mint a SECOND token. The customer
    ends up with N tokens for one paid subscription.

    Realistic trigger: DDB partial write success + a flaky network
    on a Lambda timeout right after the put.

    Mitigated by: per-user cap (default 50) and the per-user lock.
    Still a defense-in-depth gap.

    Fix sketch: two-phase pattern — claim with `in_flight` TTL=5min;
    promote to `done` TTL=30d on success. On crash, leave the
    in_flight marker; expires naturally on retry beyond in_flight
    TTL. Or: make `issue_api_token` idempotent on `(user_id,
    event_id)` so a retry returns the SAME token row.
    """
    from iam_jit.stripe_webhook import (
        InMemoryProcessedEventsStore,
        dispatch_event,
    )
    from iam_jit.api_tokens_store import (
        APITokenRecord,
        InMemoryAPITokenStore,
    )

    saved = os.environ.get("STRIPE_PRICE_ID_TO_TIER")
    os.environ["STRIPE_PRICE_ID_TO_TIER"] = '{"price_pro":"pro"}'
    try:
        tokens = InMemoryAPITokenStore()
        processed = InMemoryProcessedEventsStore()
        event = {
            "id": "evt_partial_failure",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer_email": "pay@example.com",
                    "line_items": {"data": [{"price": {"id": "price_pro"}}]},
                    "customer": "cus_x",
                    "subscription": "sub_y",
                }
            },
        }

        # Wrap the tokens store so the first put SUCCEEDS-THEN-RAISES
        # (commit visible in the store, exception propagates from the
        # call). Subsequent calls behave normally.
        real_put = tokens.put
        call_count = {"n": 0}

        def partial_failure_put(record: APITokenRecord) -> None:
            call_count["n"] += 1
            real_put(record)
            if call_count["n"] == 1:
                # The commit went through; the EXCEPTION fires on
                # the return path (think: response-time DDB
                # ProvisionedThroughputExceeded on a write that
                # actually persisted).
                raise RuntimeError(
                    "simulated response-path failure after successful write"
                )

        tokens.put = partial_failure_put  # type: ignore[method-assign]

        # First delivery: claim succeeds, put writes, then raises.
        # ROUND-4 REGRESSION FIX: dispatch_event no longer releases
        # the claim on a generic exception — only on the narrowly-
        # typed `HandlerPreWriteError`. The bare RuntimeError here
        # is treated as "side effect may have committed; retain
        # claim; operator confirms and manually releases."
        with pytest.raises(RuntimeError):
            dispatch_event(
                event, tokens_store=tokens, processed_events_store=processed,
            )

        # The store has the token from the first attempt's commit.
        first_attempt_tokens = tokens.list_for_user("pay@example.com")
        assert len(first_attempt_tokens) == 1, (
            "Partial-failure simulation didn't commit a token; test "
            "premise is broken."
        )

        # Stripe retries. Claim was RETAINED → retry short-circuits
        # as duplicate. No second token is minted.
        result = dispatch_event(
            event, tokens_store=tokens, processed_events_store=processed,
        )
        assert result.get("duplicate") is True
        final_tokens = tokens.list_for_user("pay@example.com")
        assert len(final_tokens) == 1, (
            "expected exactly one token (no double-mint after "
            "partial-success regression fix); got "
            f"{len(final_tokens)}"
        )
    finally:
        if saved is None:
            os.environ.pop("STRIPE_PRICE_ID_TO_TIER", None)
        else:
            os.environ["STRIPE_PRICE_ID_TO_TIER"] = saved


# ---------------------------------------------------------------------------
# 11. (LOW) InMemorySessionRevocationStore only opportunistically expires
#     the entry being checked. Bulk revocations stay in memory until
#     re-queried.
# ---------------------------------------------------------------------------


def test_finding_session_revocation_inmemory_no_eviction_memory_growth() -> None:
    """Finding: SESSION-REVOCATION-INMEMORY-NO-EVICTION-MEMORY-GROWTH.  # NEW-CODE

    CWE-401 (Missing Release of Memory).
    Severity: LOW.
    Location: src/iam_jit/session_revocation.py:48-69.

    `is_revoked` only expires the SINGLE hash being checked. Entries
    revoked-and-never-rechecked stay until the Lambda instance
    recycles. On a bulk-revocation workload (admin disable, password
    rotation script), the dict grows indefinitely. Bounded by
    24h × revocation-rate; no hard cap.

    Compare: `magic_link_nonces.InMemoryMagicLinkNonceStore` sweeps
    ALL expired entries on every `consume_or_reject` (line 56-58)
    — the right shape.

    Fix sketch: copy the sweep loop into `is_revoked` and `revoke`.
    """
    from iam_jit import session_revocation as sr

    sr.reset_default_store_for_tests()
    store = sr.InMemorySessionRevocationStore()

    # Revoke 100 cookies with TTL=-1s (already expired).
    for i in range(100):
        store.revoke(f"cookie-{i}", ttl_seconds=-1)

    # The internal dict has 100 entries despite all being expired.
    assert len(store._revoked) == 100, (
        "InMemorySessionRevocationStore now sweeps on revoke — flip "
        "this test."
    )

    # is_revoked on a SINGLE cookie only sweeps that one.
    assert store.is_revoked("cookie-0") is False
    assert len(store._revoked) == 99, (
        "is_revoked now sweeps all expired entries — flip this test."
    )


# ---------------------------------------------------------------------------
# 12. (LOW) Module-level _GLOBAL lazy-init in session_revocation has no
#     init lock; cold-start race can lose a revocation made on the
#     loser-thread instance.
# ---------------------------------------------------------------------------


def test_finding_session_revocation_global_init_race_loses_revocations() -> None:
    """Finding: SESSION-REVOCATION-GLOBAL-INIT-RACE-LOSES-REVOCATIONS.  # NEW-CODE

    CWE-362 (Concurrent Execution using Shared Resource with
    Improper Synchronization).
    Severity: LOW — narrow cold-start window.
    Location: src/iam_jit/session_revocation.py:131-141.

    `get_default_store()` lazy-init: two cold-start threads can both
    see `_GLOBAL is None`, each constructs its own store, one
    assignment wins. The loser's instance carries any revocations
    it received and is then GC'd → those revocations are LOST.

    Fix sketch: protect with a module-level `threading.Lock`, or
    use `functools.lru_cache(maxsize=1)`.
    """
    from iam_jit import session_revocation as sr

    src = inspect.getsource(sr.get_default_store)
    # The lazy-init has no explicit lock.
    assert "global _GLOBAL" in src
    assert "Lock" not in src and "lru_cache" not in src, (
        "get_default_store() now serializes init — flip this test."
    )

    # Behavioral demo: a "first call" race produces MULTIPLE
    # transient instances. The winner ends up in _GLOBAL; every
    # loser's instance is GC'd. We instrument the constructor to
    # count invocations under N concurrent first-callers.
    sr.reset_default_store_for_tests()
    construction_count = {"n": 0}
    construction_lock = threading.Lock()
    instances: list[object] = []

    real_init = sr.InMemorySessionRevocationStore.__init__

    def counting_init(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        with construction_lock:
            construction_count["n"] += 1
        # Hold each constructor for long enough that other cold-
        # start threads also pass the `_GLOBAL is None` check
        # before this thread assigns.
        time.sleep(0.05)
        real_init(self, *args, **kwargs)

    sr.InMemorySessionRevocationStore.__init__ = counting_init  # type: ignore[method-assign,assignment]
    try:
        def first_call() -> None:
            instances.append(sr.get_default_store())

        threads = [threading.Thread(target=first_call) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sr.InMemorySessionRevocationStore.__init__ = real_init  # type: ignore[method-assign,assignment]

    # MORE than one instance was constructed → the race shape is
    # real. A revocation made on the loser-thread's instance
    # before the winner overwrote _GLOBAL would have been lost.
    assert construction_count["n"] > 1, (
        "Only one InMemorySessionRevocationStore was constructed "
        "across 8 concurrent first-callers — the race is no longer "
        "observable (perhaps an init lock landed). Flip this test."
    )


# ---------------------------------------------------------------------------
# 13. (LOW) Body-size middleware refuses chunked Transfer-Encoding
#     BEFORE the path-aware CSRF exempt-list. Future Stripe-webhook
#     intermediates that re-frame as chunked would get 411 with no
#     way to debug.
# ---------------------------------------------------------------------------


def test_finding_body_size_guard_breaks_legitimate_stripe_webhook_chunked() -> None:
    """Finding: BODY-SIZE-GUARD-BREAKS-LEGITIMATE-STRIPE-WEBHOOK-CHUNKED.

    CWE-755 (Improper Handling of Exceptional Conditions).
    Severity: LOW — defensive-only; Stripe currently sends
    Content-Length.
    Location: src/iam_jit/app.py:323-372.

    Round-3 BODY-SIZE-GUARD-CHUNKED-BYPASS closure refuses
    `Transfer-Encoding: chunked` with 411 before any path-aware
    exemption check. The Stripe webhook path is exempted from CSRF
    (line 222) but NOT from the chunked refusal. Any future
    intermediate that re-frames the webhook body as chunked would
    get 411s — and Stripe is unlikely to retry on 411 (non-
    retryable status class). The operator only sees Stripe's
    dashboard saying "endpoint returned 411" with no iam-jit-side
    log to debug.

    Fix sketch: exempt `/api/v1/webhooks/stripe` from the chunked
    refusal (it has its own HMAC + size limits by Stripe's design).
    Same pattern as the CSRF exempt path list.
    """
    from iam_jit import app as app_mod

    src = inspect.getsource(app_mod.create_app)
    # Identify the body-size middleware block.
    start = src.index("_enforce_max_body_size")
    end = src.index("_security_headers")
    block = src[start:end]
    # Chunked refusal is present.
    assert "chunked" in block.lower()
    assert "411" in block
    # And there's NO exemption for the Stripe webhook path.
    assert "/api/v1/webhooks/stripe" not in block, (
        "Body-size guard now exempts the Stripe webhook path — "
        "flip this test."
    )
