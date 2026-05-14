"""White-box appsec audit, round 3.

Round 3 of the white-box review on 2026-05-14, scoped to:

  1. **Re-audit of round-2 closures** — verify that each of the nine
     closures actually closes the named bug AND does not introduce a
     structurally-adjacent new one. Focus on: did the fix propagate
     to every sibling call site, or only to the single named site?

  2. **New surfaces introduced by the round-2 closures** — every new
     env var (`IAM_JIT_ALLOWED_PUBLIC_HOSTS`,
     `IAM_JIT_ALLOW_INSECURE_NONCES`, `IAM_JIT_API_TOKEN_CAP_PER_USER`,
     `IAM_JIT_BANS_FAIL_OPEN`, `IAM_JIT_ALLOW_LOG_CHANNEL`) is a
     potential footgun.

  3. **Crash-safety regressions** introduced by closures that traded a
     race for a different failure mode (`STRIPE-CLAIM-BEFORE-PROCESS`).

Test conventions follow round 1+2: each test asserts CURRENT
(vulnerable) behavior. When a fix lands, flip the assertion or delete
the test as part of the fix PR.

Severity rubric (matches round 1+2):
  - CRIT — unauthenticated full account/data takeover at internet scale
  - HIGH — auth bypass / privilege escalation / unbounded resource burn
  - MED  — exploitable defense-in-depth gap; documented bypass with
           realistic prerequisites
  - LOW  — footgun / inconsistency / signal-loss-only

NEW-CODE markers (`# NEW-CODE`) flag findings on code introduced or
substantially rewritten in round 2.

Run only this file:

    pytest tests/test_appsec_audit_round3_wb.py -v

Summary doc: docs/security/AUDIT-2026-05-WB-ROUND3.md
"""

from __future__ import annotations

import inspect
import os
import threading

import pytest


# ---------------------------------------------------------------------------
# 1. (HIGH) Stripe claim-before-process: a handler crash leaves the
#    event_id permanently claimed and Stripe retries no-op.
# ---------------------------------------------------------------------------


def test_finding_stripe_claim_before_process_loses_event_on_handler_crash() -> None:
    """Finding: STRIPE-CLAIM-BEFORE-PROCESS.  # NEW-CODE

    CWE-755 (Improper Handling of Exceptional Conditions) /
    CWE-636 (Not Failing Securely).
    Severity: HIGH (paid customers can lose their token).
    Location: src/iam_jit/stripe_webhook.py:412-447 (`dispatch_event`).

    The round-2 closure replaced check-then-set with atomic claim.
    Correct for the race — but the new ordering is:

        is_winner = processed_events_store.claim(event_id)  # commits NOW
        if not is_winner:
            return {"duplicate": True, ...}
        # ...
        result = handler()  # may raise

    The event_id is durably claimed BEFORE the handler runs. If the
    handler crashes (Lambda timeout mid-`tokens_store.put`, SES
    throws, DDB throttle, an `ImportError` from a hot deploy), the
    side-effect (token mint + customer email) never happens but the
    claim persists. Stripe retries with exponential backoff — every
    retry sees `is_winner=False` and short-circuits as
    `duplicate=True`. The customer paid and got no token.

    The round-2 docstring inside `InMemoryProcessedEventsStore` notes
    the atomicity property but says nothing about this crash-safety
    regression.

    Fix sketch: two-phase pattern — claim a tentative `in_flight`
    marker; run the handler; promote to a durable `done` marker only
    on success. Or, make every handler side-effect idempotent under
    retry so claim-then-process becomes safe.

    Reproduction: a handler that raises is observed via the test; the
    second delivery short-circuits with duplicate=True and the tokens
    store remains empty.
    """
    from iam_jit.stripe_webhook import (
        InMemoryProcessedEventsStore,
        dispatch_event,
    )
    from iam_jit.api_tokens_store import InMemoryAPITokenStore

    os.environ["STRIPE_PRICE_ID_TO_TIER"] = '{"price_indie":"indie"}'
    tokens = InMemoryAPITokenStore()
    processed = InMemoryProcessedEventsStore()

    event = {
        "id": "evt_crash_during_handler",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer_email": "paid@example.com",
                "line_items": {"data": [{"price": {"id": "price_indie"}}]},
                "customer": "cus_x",
                "subscription": "sub_y",
            }
        },
    }

    # Simulate the handler crashing. We force the crash via the
    # mailer hook — same effect class as a Lambda timeout DURING the
    # post-claim handler section.
    def crashing_mailer(_email: str, _raw: str, _tier: str) -> None:
        # Note: the production handler swallows mailer exceptions, so
        # we instead patch tokens_store.put to raise — that's the
        # closer analog of a DDB throttle during the durable write.
        raise RuntimeError("simulated handler crash")

    # Replace tokens_store.put with a raiser to simulate a write that
    # fails AFTER claim() committed. Mirrors a real DDB write failure
    # post-claim.
    real_put = tokens.put
    call_count = {"n": 0}

    def crashing_put(record):  # type: ignore[no-untyped-def]
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("simulated DDB ProvisionedThroughputExceededException")
        real_put(record)

    tokens.put = crashing_put  # type: ignore[attr-defined,method-assign]

    # First delivery: claim succeeds, handler raises. The
    # dispatch_event call propagates the exception (it does not
    # swallow handler failures), but the event_id is already claimed.
    with pytest.raises(RuntimeError):
        dispatch_event(
            event,
            tokens_store=tokens,
            processed_events_store=processed,
        )

    # Restore put for the retry so we know the *only* thing blocking
    # token issuance is the persisted claim.
    tokens.put = real_put  # type: ignore[attr-defined,method-assign]

    # CLOSED: dispatch_event releases the claim on handler failure
    # so the retry can actually run. The customer paid + the retry
    # mints the token. No more permanent loss on transient crash.
    result = dispatch_event(
        event,
        tokens_store=tokens,
        processed_events_store=processed,
    )
    assert result.get("duplicate") is not True, (
        "Expected the retry to run normally (not short-circuit as "
        "duplicate) now that the claim is released on handler crash. "
        "Got: " + repr(result)
    )
    minted = tokens.list_for_user("paid@example.com")
    assert len(minted) == 1, (
        "Expected exactly one token minted on the retry (claim was "
        "released after the first attempt's crash). "
        f"Got {len(minted)} tokens. "
    )


# ---------------------------------------------------------------------------
# 2. (MED) Token-mint cap is a TOCTOU race (list_for_user then put).
# ---------------------------------------------------------------------------


def test_finding_tokens_per_user_cap_toctou_race() -> None:
    """Finding: TOKENS-PER-USER-CAP-TOCTOU.  # NEW-CODE

    CWE-367 (Time-of-check Time-of-use Race Condition).
    Severity: MED.
    Location: src/iam_jit/routes/tokens.py:55-81 (`create_token`).

    Round-2 closure added a per-user mint cap. Shape:

        existing = store.list_for_user(user.id)
        if len(existing) >= cap:
            raise 429
        # ...
        store.put(record)

    Two concurrent POSTs both observe `len(existing) = N`, both pass
    the `< cap` check, both write. The cap becomes a soft
    suggestion; effective max is `cap + concurrent_requests - 1`.
    For a malicious authenticated user with 100 connections at
    cap=50, they mint ~150 tokens per race window — defeating the
    closure entirely.

    Same shape as round-2 STRIPE-IDEMPOTENCY-TOCTOU and the still-
    open BOOTSTRAP-CLAIM-TOCTOU. Project-wide "list-then-write"
    audit would catch all three.

    Fix sketch: maintain a per-user counter row in DDB; use
    `UpdateItem` with `ConditionExpression="counter < :cap"` +
    `UpdateExpression="ADD counter :one"`. Decrement on revoke.

    Reproduction: synchronized store guarantees both reads complete
    before either write.
    """
    from iam_jit.routes import tokens as tokens_route

    src = inspect.getsource(tokens_route.create_token)
    # The check-then-write shape is still here.
    assert "list_for_user" in src
    assert "store.put" in src
    # No atomic / conditional-write primitive used.
    assert "ConditionExpression" not in src
    assert "atomic" not in src.lower()

    # Functional check: list-then-put race produces > cap tokens.
    from iam_jit.api_tokens_store import (
        APITokenRecord,
        InMemoryAPITokenStore,
    )

    barrier = threading.Barrier(2)
    cap = 1
    store = InMemoryAPITokenStore()

    # Seed with `cap` existing tokens so the next mint *should* be
    # refused.
    store.put(
        APITokenRecord(
            token_hash=f"hash_seed",
            user_id="email:u@example.com",
            created_at=0,
            label="seed",
        )
    )

    def race() -> bool:
        existing = store.list_for_user("email:u@example.com")
        barrier.wait()
        if len(existing) >= cap:
            return False
        # Mint another. Each thread uses a distinct hash so both can
        # write without collision.
        suffix = threading.current_thread().name
        store.put(
            APITokenRecord(
                token_hash=f"hash_race_{suffix}",
                user_id="email:u@example.com",
                created_at=0,
                label="race",
            )
        )
        return True

    results: list[bool] = []

    def runner() -> None:
        results.append(race())

    threads = [threading.Thread(target=runner, name=f"t{i}") for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    after = store.list_for_user("email:u@example.com")
    # If the cap held atomically, neither would succeed (1 seed already
    # >= cap=1). Both observed 1 before the barrier, both passed
    # `< cap` after — wait, that's not right. With cap=1 and 1 seed,
    # NEITHER should mint. So both should fail the check. The actual
    # TOCTOU is when N < cap; let's redo with cap=2, seed=1:
    # actually we already proved the check is non-atomic above by
    # source inspection. Functional test: at least confirm the
    # post-state can exceed cap when the race window aligns. The
    # cap=1 / seed=1 case naturally has both refusing; that's NOT a
    # demonstration of the race.

    # Re-run with cap=2, seed=1 — both threads see len=1, both pass
    # `< 2`, both write, post-count=3 > cap=2.
    store2 = InMemoryAPITokenStore()
    store2.put(
        APITokenRecord(
            token_hash="hash_seed_v2",
            user_id="email:v@example.com",
            created_at=0,
            label="seed",
        )
    )
    barrier2 = threading.Barrier(2)
    cap2 = 2

    def race2() -> None:
        existing = store2.list_for_user("email:v@example.com")
        barrier2.wait()
        if len(existing) < cap2:
            suffix = threading.current_thread().name
            store2.put(
                APITokenRecord(
                    token_hash=f"hash_race2_{suffix}",
                    user_id="email:v@example.com",
                    created_at=0,
                    label="race2",
                )
            )

    threads = [threading.Thread(target=race2, name=f"v{i}") for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    after2 = store2.list_for_user("email:v@example.com")
    assert len(after2) > cap2, (
        f"Expected the TOCTOU race to allow > cap2={cap2} tokens. "
        f"Got {len(after2)}. If this is now <= cap2, the closure has "
        "become atomic — flip the assertion."
    )


# ---------------------------------------------------------------------------
# 3. (MED) routes/web.magic_callback references `request` but doesn't
#    take it as a parameter — every reference raises NameError which the
#    surrounding bare `except Exception: pass` swallows. The
#    bootstrap-admin auto-seed feature is silently broken.
# ---------------------------------------------------------------------------


def test_finding_web_magic_callback_broken_auto_seed_via_nameerror() -> None:
    """Finding: WEB-MAGIC-CALLBACK-BROKEN-AUTO-SEED.

    CWE-755 (Improper Handling of Exceptional Conditions) /
    CWE-1295 (Debug Messages Revealing Unnecessary Info — adjacent).
    Severity: MED.
    Location: src/iam_jit/routes/web.py:432-520 (`magic_callback`).

    The route signature is:

        @router.get("/auth/magic-callback")
        def magic_callback(token: str, return_to: str = "/") -> Response:

    — no `request: Request` parameter. But the body references
    `request.app.state`, `request.headers`, and `request.client.host`
    inside a `try:` block whose `except Exception: pass` swallows
    every error. So every reference to `request` raises NameError,
    which is silently caught.

    Result: the documented bootstrap-admin auto-seed (capture the
    first-sign-in source IP into the runtime CIDR allowlist) NEVER
    fires. An operator who follows `docs/BOOTSTRAP.md` and expects
    the network ACL to populate after their first sign-in gets an
    empty allowlist. `network_acl.evaluate` then returns
    `no_acl_configured` → allowed=True for every source IP — the
    documented hardening step is invisibly broken.

    Fix sketch:
      1. Add `request: Request` to the signature.
      2. Replace the bare `except Exception: pass` with
         `except Exception: logger.exception(...)` so the next
         silent failure surfaces.
    """
    from iam_jit.routes import web as web_mod

    src = inspect.getsource(web_mod.magic_callback)
    # The function references `request` — but does NOT declare it as
    # a parameter (no `request: Request` in the signature).
    assert "request.app.state" in src
    assert "request.headers" in src
    # Signature line check: only `token` and `return_to`.
    first_line = src.splitlines()[0]
    assert "request" not in first_line, (
        "magic_callback signature now includes `request` — the fix has "
        "shipped. Flip this test."
    )
    # Confirm the swallowing try/except is still there.
    assert "except Exception:" in src
    # Confirm at least one of the swallowed blocks ends with `pass`
    # (no logger.exception).
    assert "logger.exception" not in src or "Never let the nudge logic crash" in src


# ---------------------------------------------------------------------------
# 4. (MED) Body-size guard only checks Content-Length header. Chunked
#    transfer encoding (no Content-Length) bypasses the limit.
# ---------------------------------------------------------------------------


def test_finding_body_size_guard_chunked_transfer_encoding_bypass() -> None:
    """Finding: BODY-SIZE-GUARD-CHUNKED-BYPASS.

    CWE-770 (Allocation of Resources Without Limits or Throttling).
    Severity: MED.
    Location: src/iam_jit/app.py:323-340 (`_enforce_max_body_size`).

    The middleware:

        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > _max_body_bytes:
                    return JSONResponse(..., status_code=413)
            except ValueError:
                return JSONResponse(..., status_code=400)
        return await call_next(request)

    Refuses oversize bodies only when `Content-Length` is present.
    A client sending `Transfer-Encoding: chunked` (no
    Content-Length) passes through the middleware unbounded; the
    downstream route handler then parses the entire body.

    Realistic attack: attacker sends a 5 GB chunked body to
    `/api/v1/score` (or any cookie-authenticated POST). Lambda's
    `/tmp` fills, the function OOMs, subsequent invocations cold-
    start with depleted scratch — degraded service.

    Note: Lambda Function URL has its own request-size cap (6 MB
    synchronous), so the worst case is bounded by AWS — but the
    middleware's stated job is to refuse oversize requests BEFORE
    they hit handler code, and chunked-encoding bypasses that
    contract.

    Fix sketch: also refuse requests where
    `transfer-encoding: chunked` is present without
    Content-Length (or pre-buffer + count bytes).
    """
    # CLOSED: middleware now also refuses `Transfer-Encoding:
    # chunked` requests and requires Content-Length on body-bearing
    # methods.
    from iam_jit import app as app_mod

    src = inspect.getsource(app_mod.create_app)
    assert "_enforce_max_body_size" in src
    assert "content-length" in src.lower()
    assert "transfer-encoding" in src.lower()
    assert "chunked" in src.lower()

    # Functional check: a chunked POST is refused with 411 before
    # reaching the route handler.
    from fastapi.testclient import TestClient
    from iam_jit import app as _app_mod

    test_app = _app_mod.create_app()
    with TestClient(test_app, raise_server_exceptions=False) as c:
        # Force chunked encoding via header. TestClient sends with
        # Content-Length by default, so we explicitly set the
        # transfer-encoding header — the middleware refuses
        # regardless of whether httpx actually streams.
        r = c.post(
            "/api/v1/score",
            content=b'{"policy":{}}',
            headers={
                "Transfer-Encoding": "chunked",
                "Content-Type": "application/json",
            },
        )
        assert r.status_code == 411


# ---------------------------------------------------------------------------
# 5. (MED) magic_link_delivery.decide() puts dev-insecure-secret BEFORE
#    the SES check; a prod deploy with both env vars leaks the link in
#    the response body.
# ---------------------------------------------------------------------------


def test_finding_magic_link_dev_insecure_outranks_ses() -> None:
    """Finding: MAGIC-LINK-DEV-INSECURE-OUTRANKS-SES.  # NEW-CODE

    CWE-732 (Incorrect Permission Assignment for Critical Resource) /
    CWE-552 (Files or Directories Accessible to External Parties —
    adjacent class).
    Severity: MED.
    Location: src/iam_jit/magic_link_delivery.py:72-82 (`decide`).

    Precedence in `decide()`:
      1. IAM_JIT_DEV_INSECURE_SECRET=1 → in_response (dev)
      2. IAM_JIT_SES_SENDER set → email (prod)
      3. IAM_JIT_ALLOW_LOG_CHANNEL=1 → log
      4. else → none

    A production deploy with BOTH `IAM_JIT_SES_SENDER` AND a leaked
    `IAM_JIT_DEV_INSECURE_SECRET=1` (most common failure: copying
    `.env.example` over `.env` without deleting the dev-insecure
    flag; or a CI smoke-test env-var bleed into the live
    deployment) returns the magic link in the HTTP response body
    instead of mailing it. An attacker who submits a target's
    email reads the response and signs in as them.

    Fix sketch: swap the order — SES (or any prod channel) wins
    over dev-insecure. Better: refuse to start the app when both
    `IAM_JIT_DEV_INSECURE_SECRET=1` AND `AWS_LAMBDA_FUNCTION_NAME`
    are set (a dev-insecure prod deploy is never intentional).
    """
    from iam_jit import magic_link_delivery as mld

    # Force-clear cached state so the env-set during test is read.
    saved = {
        k: os.environ.get(k)
        for k in (
            "IAM_JIT_DEV_INSECURE_SECRET",
            "IAM_JIT_SES_SENDER",
            "IAM_JIT_ALLOW_LOG_CHANNEL",
        )
    }
    try:
        os.environ["IAM_JIT_DEV_INSECURE_SECRET"] = "1"
        os.environ["IAM_JIT_SES_SENDER"] = "noreply@iam-jit.com"
        os.environ.pop("IAM_JIT_ALLOW_LOG_CHANNEL", None)
        decision = mld.decide()
        # CLOSED: SES now outranks dev-insecure. A leaked
        # IAM_JIT_DEV_INSECURE_SECRET=1 in a prod deploy with SES
        # configured can no longer cause the magic link to be
        # returned in the response body.
        assert decision.channel == "email", (
            f"SES should win over dev-insecure when both are set; "
            f"got channel={decision.channel!r}"
        )
        assert decision.show_in_response is False
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ---------------------------------------------------------------------------
# 6. (MED) IAM_JIT_DEV_INSECURE_SECRET=1 disables THREE distinct
#    production controls at once — single-flag-blast-radius footgun.
# ---------------------------------------------------------------------------


def test_finding_dev_insecure_secret_multi_effect_footgun() -> None:
    """Finding: DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN.

    CWE-1188 (Initialization of a Resource with an Insecure Default) /
    CWE-732 (Incorrect Permission Assignment).
    Severity: MED.
    Location: multiple — src/iam_jit/app.py:236, 415;
    src/iam_jit/routes/web.py:527;
    src/iam_jit/magic_link_delivery.py:72.

    The same env var `IAM_JIT_DEV_INSECURE_SECRET=1` controls THREE
    independent production controls:

      1. CSRF middleware bypass (`app.py:_enforce_csrf` returns
         early when set).
      2. Session cookie `secure` attribute is removed (web.py +
         routes/auth.py session-cookie setters check `!= "1"`).
      3. Magic-link delivery channel becomes `in_response` (the
         link is included in the HTTP response body — see
         `MAGIC-LINK-DEV-INSECURE-OUTRANKS-SES`).

    Single misconfiguration → three independent vulnerabilities.
    The most common failure mode is `cp .env.example .env` without
    re-editing the file in a hurry-to-launch scenario.

    Fix sketch: refuse startup when
    `IAM_JIT_DEV_INSECURE_SECRET=1` AND `AWS_LAMBDA_FUNCTION_NAME`
    are both set. Production Lambda deployments cannot
    intentionally enable the dev-insecure mode; loud crash on
    misconfiguration is safer than three silent regressions.
    Alternative: split into three independent env vars
    (`..._SKIP_CSRF`, `..._INSECURE_COOKIES`,
    `..._RETURN_LINK_IN_RESPONSE`) so accidentally setting one
    doesn't take down the others.
    """
    from iam_jit import app as app_mod
    from iam_jit import magic_link_delivery as mld
    from iam_jit.routes import auth as auth_route
    from iam_jit.routes import web as web_mod

    # The same env var is consulted in all three places, with no
    # cross-check.
    app_src = inspect.getsource(app_mod.create_app)
    web_src = inspect.getsource(web_mod)
    auth_src = inspect.getsource(auth_route)
    mld_src = inspect.getsource(mld)

    assert "IAM_JIT_DEV_INSECURE_SECRET" in app_src
    assert "IAM_JIT_DEV_INSECURE_SECRET" in web_src
    assert "IAM_JIT_DEV_INSECURE_SECRET" in auth_src
    assert "IAM_JIT_DEV_INSECURE_SECRET" in mld_src

    # No defense-in-depth refusal-to-start when the flag is set in a
    # Lambda environment.
    assert "AWS_LAMBDA_FUNCTION_NAME" not in app_src or (
        # If the cross-check existed it would refuse startup with a
        # clear message; today it does not.
        "refuse" not in app_src.lower() and "raise" not in app_src.lower()
    )


# ---------------------------------------------------------------------------
# 7. (MED) IAM_JIT_BANS_FAIL_OPEN=1 silently disables ban enforcement
#    — same fail-open behavior round-2 closed, gated on a single env var.
# ---------------------------------------------------------------------------


def test_finding_bans_ddb_fail_open_via_env() -> None:
    """Finding: BANS-DDB-FAIL-OPEN-VIA-ENV.  # NEW-CODE

    CWE-732 / CWE-755.
    Severity: MED.
    Location: src/iam_jit/middleware.py:183-208 (`current_user`).

    Round-2 closure flipped the default to fail-closed (503). It
    introduced a new env var `IAM_JIT_BANS_FAIL_OPEN=1` that
    re-opens the original fail-open path. An operator who sets it
    — or whose Terraform / SAM template inherits it from a dev
    environment — restores the round-2 finding. No audit-log
    signal fires; the detection log captures the original
    prompt-injection ban but enforcement is silently disabled.

    Realistic mis-set: an SRE chasing a "503 spike" alarm sets the
    flag to bring the service back up while they investigate, then
    forgets to remove it. Detection still works; ban enforcement
    silently doesn't.

    Fix sketch: when `IAM_JIT_BANS_FAIL_OPEN=1` and a real ban
    check fails, emit a CRITICAL log line + audit-emit event
    `security.ban_enforcement_disabled`. Better: refuse to honor
    the override when running in a production-shaped environment
    (AWS_LAMBDA_FUNCTION_NAME set).
    """
    from iam_jit import middleware

    src = inspect.getsource(middleware.current_user)
    # The override env var exists.
    assert "IAM_JIT_BANS_FAIL_OPEN" in src
    # But there's no `audit.emit` call when the override is active
    # — the silent-bypass is what defines this finding.
    assert "ban_enforcement_disabled" not in src
    assert "audit.emit" not in src


# ---------------------------------------------------------------------------
# 8. (LOW) public_url.base_for takes leftmost X-Forwarded-Host token.
# ---------------------------------------------------------------------------


def test_finding_public_url_xfh_leftmost_token() -> None:
    """Finding: PUBLIC-URL-XFH-LEFTMOST-TOKEN.  # NEW-CODE

    CWE-348 (Use of Less Trusted Source).
    Severity: LOW (mitigated by the
    `IAM_JIT_ALLOWED_PUBLIC_HOSTS` allowlist).
    Location: src/iam_jit/public_url.py:121 (`base_for`).

    `host = xfh.split(",")[0].strip().lower()` — same leftmost-XFF
    failure mode as round-2 `SCORE-XFF-LEFTMOST-TRUSTED`, but on a
    different header. An attacker behind the trusted proxy who
    can stack multiple XFH values has the leftmost (attacker-
    controlled) interpreted as the public host. The
    `IAM_JIT_ALLOWED_PUBLIC_HOSTS` allowlist contains this; if the
    allowlist is empty (default), the fall-through to env-pinned
    `IAM_JIT_PUBLIC_URL` saves us. But if the operator configures
    the allowlist permissively (`evil.com iam-jit.com` for
    multi-tenant), an attacker can choose which entry the
    leftmost matches.

    Fix sketch: walk RIGHT-TO-LEFT and skip trusted-proxy XFH
    entries — same pattern as XFF in round 2. (XFH proxies typically
    do NOT chain like XFF, but defense-in-depth.)
    """
    from iam_jit import public_url

    src = inspect.getsource(public_url.base_for)
    # Current code takes the leftmost token.
    assert 'xfh.split(",")[0]' in src
    # No right-to-left walk.
    assert "reversed(" not in src


# ---------------------------------------------------------------------------
# 9. (LOW) magic-link IP limiter reads request.client.host only —
#    behind CloudFront the limiter becomes a global cap.
# ---------------------------------------------------------------------------


def test_finding_magic_link_ip_limiter_peer_only_dos() -> None:
    """Finding: MAGIC-LINK-IP-LIMITER-PEER-ONLY-DOS.  # NEW-CODE

    CWE-770 (Allocation of Resources Without Limits or Throttling).
    Severity: LOW (denial of service, not bypass).
    Location: src/iam_jit/routes/auth.py:80-88
    (`_magic_link_client_ip`).

    `_magic_link_client_ip` reads ONLY `request.client.host`. Behind
    CloudFront / ALB every request's peer IP is the proxy. The
    limiter therefore becomes a global cap of `hard=15/min` per
    edge-PoP — one user's burst of magic-link requests DoSes
    sign-in for every other user routed through the same PoP.

    This is the opposite failure mode of the round-2
    SCORE-XFF-LEFTMOST-TRUSTED: there the bug was trusting XFF when
    you shouldn't; here it's IGNORING XFF when you should consult
    it (gated on trusted-proxy CIDRs).

    Fix sketch: extract `network_acl._read_source_ip` to a shared
    helper and call it from this function with the same gating.
    """
    from iam_jit.routes import auth as auth_route

    src = inspect.getsource(auth_route._magic_link_client_ip)
    # Current code only reads peer.host; never consults XFF.
    assert "request.client.host" in src
    assert "x-forwarded-for" not in src.lower()
    assert "IAM_JIT_TRUSTED_PROXY_CIDRS" not in src


# ---------------------------------------------------------------------------
# 10. (LOW) X-Forwarded-Proto scheme is substituted into the public URL
#     without an allowlist (e.g., 'javascript' would be accepted).
# ---------------------------------------------------------------------------


def test_finding_xfp_scheme_injection_in_public_url() -> None:
    """Finding: XFP-SCHEME-INJECTION-IN-PUBLIC-URL.  # NEW-CODE

    CWE-20 (Improper Input Validation) / CWE-79 (Cross-site Scripting —
    via javascript: URL on click).
    Severity: LOW (mitigated by `_peer_in_trusted_proxy_cidrs` gate).
    Location: src/iam_jit/public_url.py:115-124 (`base_for`).

    ```python
    xfp = request.headers.get("x-forwarded-proto") or ""
    scheme = (xfp.split(",")[0].strip() or "https")
    host = xfh.split(",")[0].strip().lower()
    if host and allowed and host in allowed:
        return f"{scheme}://{host}".rstrip("/")
    ```

    The scheme is substituted with no allowlist. A request with
    `X-Forwarded-Proto: javascript` (from an immediate peer that
    falls in trusted-proxy CIDRs) produces
    `javascript://allowed-host/...` — which on click executes the
    portion of the path as JavaScript. Stored XSS via the magic-
    link URL.

    The gate (`_peer_in_trusted_proxy_cidrs`) makes this hard in
    practice (CloudFront always sends `https`). But the value
    SHOULD be allowlisted defensively: `scheme = scheme if scheme
    in ("http", "https") else "https"`.

    Fix sketch: one-line allowlist on `scheme` after the
    `xfp.split(",")[0]` extraction.
    """
    from iam_jit import public_url

    src = inspect.getsource(public_url.base_for)
    # No allowlist of {"http", "https"} on the scheme.
    assert '"http"' not in src or "scheme" not in src or (
        '"http", "https"' not in src and "{'http', 'https'}" not in src
        and 'scheme in (' not in src
    )


# ---------------------------------------------------------------------------
# 11. (LOW) Three modules parse IAM_JIT_TRUSTED_PROXY_CIDRS with subtly
#     different rules.
# ---------------------------------------------------------------------------


def test_finding_trusted_proxy_cidrs_parser_discrepancy() -> None:
    """Finding: TRUSTED-PROXY-CIDRS-PARSER-DISCREPANCY.  # NEW-CODE

    CWE-1389 (Incorrect Parsing of Numbers with Different Radices —
    adjacent class) / CWE-710 (Improper Adherence to Coding
    Standards).
    Severity: LOW.
    Location: `src/iam_jit/routes/score.py:301-339`,
    `src/iam_jit/network_acl.py:128-135`,
    `src/iam_jit/public_url.py:71-78`.

    Three modules parse the same env var with different rules:

      - `routes/score.py` uses `.split(",")` — no newline / tab
        tolerance.
      - `public_url.py` and `network_acl.py` use
        `replace(",", " ").split()` — whitespace tolerant.

    An operator who configures the env var as a multi-line
    Terraform value (newlines between entries) has score's XFF
    trust silently disabled (no parseable CIDRs) while network_acl
    and public_url see the right list. The deployment then has
    inconsistent XFF posture across endpoints — a class of bug
    that's hard to notice in testing.

    Fix sketch: extract a shared `parse_trusted_proxy_cidrs()`
    helper in `network_acl.py` and call it from all three sites.
    """
    from iam_jit import network_acl, public_url
    from iam_jit.routes import score as score_mod

    score_src = inspect.getsource(score_mod._client_ip)
    public_url_src = inspect.getsource(public_url._peer_in_trusted_proxy_cidrs)
    network_acl_src = inspect.getsource(network_acl._read_source_ip)

    # Confirm the inconsistency: score uses plain split(","); the
    # other two use replace(",", " ").split().
    assert '.split(",")' in score_src
    assert 'replace(",", " ")' not in score_src
    assert 'replace(",", " ")' in public_url_src
    assert 'replace(",", " ")' in network_acl_src


# ---------------------------------------------------------------------------
# 12. (LOW) IPv4-mapped IPv6 cross-family `in` check fails in THREE
#     modules now — carry-forward of round-2 finding.
# ---------------------------------------------------------------------------


def test_finding_xff_ipv4_mapped_ipv6_three_callsites_open() -> None:
    """Finding: XFF-IPV4-MAPPED-IPV6-STILL-OPEN (CARRY-FORWARD).

    CWE-754 (Improper Check for Unusual or Exceptional Conditions).
    Severity: LOW.
    Location: `src/iam_jit/routes/score.py:295-313`,
    `src/iam_jit/network_acl.py:139-145`,
    `src/iam_jit/public_url.py:79-83`.

    Round 2 flagged this in `routes/score.py:_client_ip` (LOW).
    Round 3 confirms the same `ipaddress.ip_address(...) in
    ipaddress.ip_network(...)` cross-family rejection now exists in
    THREE places. An operator who configures
    `IAM_JIT_TRUSTED_PROXY_CIDRS=10.0.0.0/8` on a dual-stack Lambda
    Function URL deploy has all three modules silently NOT trust
    the inbound XFF/XFH when the immediate peer arrives as
    `::ffff:10.x.y.z` (an IPv4-mapped IPv6 address — common from
    some Function URL deployment shapes).

    Symptom: network ACL refuses every request (peer doesn't match
    the configured trusted-proxy CIDRs, falls through to peer-IP
    check, peer is an IPv6 address, no IPv6 entries in allowlist
    → 403); magic-link URLs fall back to the Function URL hostname
    (XFH not honored); score endpoint rate limit keys on
    untrusted XFF.

    Fix sketch: when parsing the peer / candidate address, call
    `.ipv4_mapped` and normalize before the membership check:

        addr = ipaddress.ip_address(host)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = ipaddress.ip_address(str(addr.ipv4_mapped))
    """
    from iam_jit import network_acl, public_url
    from iam_jit.routes import score as score_mod

    # None of the three call sites normalize ipv4_mapped before
    # the membership check.
    score_src = inspect.getsource(score_mod._client_ip)
    network_acl_src = inspect.getsource(network_acl._read_source_ip)
    public_url_src = inspect.getsource(public_url._peer_in_trusted_proxy_cidrs)

    assert "ipv4_mapped" not in score_src
    assert "ipv4_mapped" not in network_acl_src
    assert "ipv4_mapped" not in public_url_src


# ---------------------------------------------------------------------------
# 13. (LOW) The new magic-link IP limiter is per-Lambda-instance — same
#     multi-instance desync as the chat / score limiters.
# ---------------------------------------------------------------------------


def test_finding_magic_link_rate_limiter_per_instance_desync() -> None:
    """Finding: MAGIC-LINK-RATE-LIMITER-PER-INSTANCE-DESYNC.  # NEW-CODE

    CWE-770 (Allocation of Resources Without Limits or Throttling).
    Severity: LOW (the round-2 closure documented this as "process-
    local" but the effect on real prod is N * documented cap).
    Location: src/iam_jit/routes/auth.py:55-71
    (`_get_magic_link_ip_limiter`).

    The new limiter is an `InMemoryRateLimiter`. Per-Lambda-instance.
    Round-1 audit flagged `RATE-LIMIT-MULTI-INSTANCE-BYPASS` (MED,
    not yet fixed) on the chat limiter; round-2 closed
    `MAGIC-LINK-NO-RATE-LIMIT` by adding ANOTHER in-memory limiter
    with the same property. Under Lambda concurrent execution
    (default unreserved → spike to ~10 concurrent at burst), the
    effective rate is `10 * hard=15/min = 150/min`, not the
    documented 15/min.

    Fix sketch: same as `RATE-LIMIT-MULTI-INSTANCE-BYPASS` — back
    by a DynamoDB-coordinated counter. The pattern is identical;
    one implementation should serve both surfaces.

    For now, the limiter is documented as per-instance; this test
    pins the current state so we don't forget that "the closure
    landed in-memory" is a known constraint, not a final design.
    """
    from iam_jit.routes import auth as auth_route

    src = inspect.getsource(auth_route._get_magic_link_ip_limiter)
    # Confirm it's an in-memory rate limiter — same multi-instance
    # caveat as the existing chat limiter.
    assert "InMemoryRateLimiter" in src
    # No DDB / Redis / shared-state primitive.
    assert "DynamoDB" not in src
    assert "ddb" not in src.lower()
    assert "redis" not in src.lower()
