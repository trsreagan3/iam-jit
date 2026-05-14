"""White-box appsec audit, round 5.

Round 5 of the white-box review on 2026-05-14, scoped to:

  1. **Re-audit of round-4 closures** — verify each closure actually
     closes the named bug AND propagates to every sibling site.
     Round-4 focus areas: `is_dev_insecure_active()` extraction +
     four-site fan-out, `DynamoDBProcessedEventsStore` shipping,
     `IAM_JIT_SESSION_REVOCATION_FAIL_OPEN` CRITICAL-log treatment,
     `_PER_USER_MINT_LOCKS_REGISTRY` race fix via `dict.setdefault`,
     `HandlerPreWriteError` narrow-typed claim-release.

  2. **New surfaces introduced by the round-4 env vars** —
     `IAM_JIT_PROCESSED_EVENTS_TABLE`,
     `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA`.

  3. **Cross-cutting fix-fan-out** — `is_dev_insecure_active()` was
     supposed to be the SoT for the dev flag. Did it really land on
     EVERY site that consults `IAM_JIT_DEV_INSECURE_SECRET`, or only
     the four named ones (CSRF, two cookie-Secure, delivery)?

  4. **New classes not yet probed across 4 rounds** — admin
     endpoints (CIDR mgmt + user mgmt) for role-self-demotion
     (BB2-10 was MED in round 2, marked OPEN in round 3, not touched
     in round 4); wildcard-CIDR admission; mass-assignment in user
     PATCH; header injection (clean); pickle/serialization (clean);
     SSRF (clean — MCP path inert at the moment).

Test conventions follow rounds 1-4: each test asserts CURRENT
(vulnerable) behavior. When a fix lands, flip the assertion or
delete the test as part of the fix PR.

Severity rubric (matches rounds 1-4):
  - CRIT — unauthenticated full account/data takeover at internet scale
  - HIGH — auth bypass / privilege escalation / unbounded resource burn
  - MED  — exploitable defense-in-depth gap; documented bypass with
           realistic prerequisites
  - LOW  — footgun / inconsistency / signal-loss-only

ROUND4-REGRESSION markers flag findings where a round-4 closure
introduced or carried over the vulnerable shape.

Run only this file:

    pytest tests/test_appsec_audit_round5_wb.py -v

Summary doc: docs/security/AUDIT-2026-05-WB-ROUND5.md
"""

from __future__ import annotations

import inspect
import os

import pytest


# ---------------------------------------------------------------------------
# 1. (CRIT) `middleware._get_secret()` bypasses `is_dev_insecure_active()`.
#    In Lambda with `IAM_JIT_DEV_INSECURE_SECRET=1` and
#    `IAM_JIT_MAGIC_LINK_SECRET` unset, the function returns a
#    hard-coded, publicly-known secret that signs every magic-link
#    token and session cookie. Full account takeover.
# ---------------------------------------------------------------------------


def test_finding_middleware_get_secret_bypasses_lambda_dev_gate() -> None:
    """Finding: MIDDLEWARE-GET-SECRET-BYPASSES-LAMBDA-DEV-GATE.  # ROUND4-REGRESSION

    CWE-798 / CWE-321 / CWE-1188.
    Severity: CRIT — public-internet attacker forges magic-link
    tokens for any email, signs session cookies as any user;
    full account takeover with zero other prerequisites.
    Location: src/iam_jit/middleware.py:59-70.

    The round-4 closure for DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN
    extracted `auth.is_dev_insecure_active()` as the SoT for the
    dev flag. It correctly threaded the helper through CSRF, the
    two cookie-Secure sites, and the magic-link delivery channel.

    It did NOT thread the helper through `middleware._get_secret`.
    That function — called from ~thirteen sites that sign/verify
    every magic-link token and session cookie — still inlines:

        if os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") == "1":
            return "dev-only-insecure-secret-do-not-use-in-prod"

    In Lambda with the dev flag set and `IAM_JIT_MAGIC_LINK_SECRET`
    unset (the .env.example bleed scenario round 4 explicitly
    modeled), the function returns the hard-coded, publicly-known
    literal. That value is checked into the repo at line 65,
    GitHub-indexed, present in every fork.

    Attack: with the public secret, an attacker uses itsdangerous'
    `TimestampSigner` to mint a magic-link token for any email
    (e.g., `email:admin@<target>`), GETs
    `/auth/magic-callback?token=<forged>`, the verify succeeds,
    the session cookie is set as that user, full admin access if
    the email matches a configured admin (or a bootstrap-seeded
    user).

    Fix sketch: route _get_secret through is_dev_insecure_active(),
    or — better — refuse module import in Lambda when
    `IAM_JIT_MAGIC_LINK_SECRET` is unset regardless of the dev flag.
    """
    # CLOSED: _get_secret now delegates to is_dev_insecure_active(),
    # AND the dev fallback is a per-process random secret (not a
    # checked-in literal). The CRIT shape — repo-committed signing
    # key + Lambda gate bypassed for the crypto leg — is closed.
    from iam_jit import middleware
    from iam_jit.auth import is_dev_insecure_active

    src = inspect.getsource(middleware._get_secret)
    assert "is_dev_insecure_active" in src, (
        "_get_secret should delegate to is_dev_insecure_active()"
    )
    # No more hard-coded repo-committed dev secret.
    assert "dev-only-insecure-secret-do-not-use-in-prod" not in src

    saved_secret = os.environ.get("IAM_JIT_MAGIC_LINK_SECRET")
    saved_dev = os.environ.get("IAM_JIT_DEV_INSECURE_SECRET")
    saved_lambda = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    saved_allow = os.environ.get("IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA")
    try:
        os.environ.pop("IAM_JIT_MAGIC_LINK_SECRET", None)
        os.environ["IAM_JIT_DEV_INSECURE_SECRET"] = "1"
        os.environ["AWS_LAMBDA_FUNCTION_NAME"] = "iam-jit-prod"
        # Lambda-allow is NOT set: dev-insecure should be REFUSED
        # in Lambda by default. _get_secret() should now raise the
        # same 500 it raises for unconfigured prod, not return the
        # repo-committed literal.
        os.environ.pop("IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA", None)
        # Reset the cached ephemeral dev secret so this test sees
        # the fresh decision.
        middleware._reset_ephemeral_dev_secret_for_tests()
        assert is_dev_insecure_active() is False
        import pytest
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            middleware._get_secret()
        assert exc_info.value.status_code == 500

        # With explicit opt-in: returns a per-process random secret
        # (NOT the old literal). Verify it's not the public literal
        # and is high-entropy.
        os.environ["IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA"] = "1"
        middleware._reset_ephemeral_dev_secret_for_tests()
        secret = middleware._get_secret()
        assert secret != "dev-only-insecure-secret-do-not-use-in-prod"
        assert len(secret) >= 32  # token_hex(32) yields 64 hex chars
    finally:
        if saved_secret is None:
            os.environ.pop("IAM_JIT_MAGIC_LINK_SECRET", None)
        else:
            os.environ["IAM_JIT_MAGIC_LINK_SECRET"] = saved_secret
        if saved_dev is None:
            os.environ.pop("IAM_JIT_DEV_INSECURE_SECRET", None)
        else:
            os.environ["IAM_JIT_DEV_INSECURE_SECRET"] = saved_dev
        if saved_lambda is None:
            os.environ.pop("AWS_LAMBDA_FUNCTION_NAME", None)
        else:
            os.environ["AWS_LAMBDA_FUNCTION_NAME"] = saved_lambda
        if saved_allow is None:
            os.environ.pop("IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA", None)
        else:
            os.environ["IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA"] = saved_allow


# ---------------------------------------------------------------------------
# 2. (HIGH) BB2-10 admin can self-demote — never fixed across rounds
#    2/3/4. Single mistake (or CSRF click) transitions deployment to
#    a no-admin state requiring DDB-level recovery.
# ---------------------------------------------------------------------------


def test_finding_admin_self_demote_last_admin_lockout() -> None:
    """Finding: ADMIN-SELF-DEMOTE-LAST-ADMIN-LOCKOUT.  # BB2-10-RE-RAISED

    CWE-269 / CWE-840.
    Severity: HIGH — single CSRF-able action transitions deployment
    to a no-admin state requiring DDB-level recovery.
    Location: src/iam_jit/routes/users.py:132-159.

    BB2-10 was flagged MED in round 2, marked "OPEN (out of scope
    for round 3)" in round-3 BB, never touched in round 4. Launch
    is days away.

    The PATCH /api/v1/users/{user_id} route accepts a `roles` field
    that can drop the actor's `admin` role with NO last-admin
    protection, NO audit emission, and NO two-eyes step. The
    sibling routes (`unban`, `revoke-tokens`) refuse self-action
    with a "second pair of eyes" message — that pattern was NEVER
    extended to user PATCH.

    Realistic shape: an admin clicks a confused-UI button, or a
    CSRF page lands on a logged-in admin browser, and the
    deployment loses its only admin. Recovery requires either a
    `IAM_JIT_ADMIN_BOOTSTRAP_EMAIL` redeploy (and the bootstrap
    user already exists, so the redeploy is a no-op) OR a manual
    DDB edit.

    Fix sketch:
      - in update_user, refuse the PATCH when the resulting role
        set would leave fewer than 1 admin in the enabled-user list
      - emit `security.user_role_changed` on every PATCH that
        mutates roles, with before/after and actor
      - bonus: refuse self-edit of own roles regardless of count
        (forces a two-eyes path; matches unban / revoke-tokens)
    """
    # CLOSED: update_user now refuses both self-demotion and the
    # last-admin demotion. Recovery requires promoting another
    # user to admin first.
    from iam_jit.routes import users as users_route

    src = inspect.getsource(users_route.update_user)
    assert "last-admin" in src.lower() or "remaining_admins" in src, (
        "update_user should refuse last-admin demotion"
    )
    assert "self-demotion" in src.lower(), (
        "update_user should refuse self-demotion explicitly"
    )


# ---------------------------------------------------------------------------
# 3. (HIGH) `HandlerPreWriteError` is dead code — no handler raises it,
#    so the round-4 "release only on narrow-typed exception" closure
#    means ANY handler error leaves the claim INTACT permanently.
#    Customer pays Stripe, never gets a token, Stripe retries see
#    "duplicate", no recovery.
# ---------------------------------------------------------------------------


def test_finding_handler_pre_write_error_dead_code() -> None:
    """Finding: HANDLER-PRE-WRITE-ERROR-DEAD-CODE-LOCKS-OUT-PAID-CUSTOMER.
    # ROUND4-REGRESSION

    CWE-755 / CWE-754.
    Severity: HIGH — paid customer is silently locked out of the
    product on any handler failure path.
    Location: src/iam_jit/stripe_webhook.py:202-282 (handler),
    :561-592 (dispatch).

    Round 4 added `HandlerPreWriteError` and changed dispatch to
    release the claim ONLY on that narrowly-typed exception. The
    intent — conservative, "better lose a retry than double-mint" —
    is correct.

    The bug: **no handler ever raises HandlerPreWriteError.**
    `handle_checkout_session_completed` returns None for soft
    failures (no email, no mapped tier), raises bare exceptions for
    hard failures (DDB throttle, encoding bug). ALL of these land
    in the catch-all `except Exception:` branch which does NOT
    release. The claim is durable in DDB. Stripe retries see
    "duplicate". The customer paid; they never get a token; the
    operator has no signal (just a buried .exception() log line).

    Fix sketch:
      - in handle_checkout_session_completed, replace the pre-write
        `return None` shapes with `raise HandlerPreWriteError(...)`
        for missing email, unmapped price, etc.
      - add POST /api/v1/admin/stripe/release-claim/{event_id} as
        the explicit operator-tool to release a stuck claim with
        an audit-trail reason.
    """
    from iam_jit import stripe_webhook

    # Verify the mechanism exists.
    assert hasattr(stripe_webhook, "HandlerPreWriteError")

    # Walk the module source for any `raise HandlerPreWriteError`
    # — there should be none today. A `raise` in the body (not in a
    # comment) is detected as a leading-whitespace `raise` token.
    module_src = inspect.getsource(stripe_webhook)
    raise_lines = [
        ln for ln in module_src.splitlines()
        if "raise HandlerPreWriteError" in ln
        and not ln.lstrip().startswith("#")
    ]
    assert len(raise_lines) == 0, (
        f"HandlerPreWriteError now has {len(raise_lines)} raise "
        "site(s) — the round-5 HIGH closure is in progress; "
        "flip this test."
    )

    # Cross-check the specific places we'd expect raises if the fix
    # landed: the no-email and no-tier soft-fail returns in
    # handle_checkout_session_completed.
    handler_src = inspect.getsource(stripe_webhook.handle_checkout_session_completed)
    assert 'return None' in handler_src or 'return\n' in handler_src
    # And there's no exception-bridging guard around tokens_store.put.
    assert "tokens_store.put(record)" in handler_src
    # The put call is NOT wrapped in try/except.
    put_idx = handler_src.index("tokens_store.put(record)")
    nearby = handler_src[max(0, put_idx - 200):put_idx + 100]
    assert "try:" not in nearby or "except" not in nearby, (
        "tokens_store.put is now wrapped — partial closure; review."
    )


# ---------------------------------------------------------------------------
# 4. (MED) `_enforce_auth_cache_control` only covers /api/v1/* and
#    /admin/*. Auth'd HTML web routes that render per-user PII
#    (/queue, /all, /tokens, /requests/{id}, /accounts,
#    /auth/magic-callback) are uncovered.
# ---------------------------------------------------------------------------


def test_finding_web_auth_cache_control_middleware_skips_pii_web_routes() -> None:
    """Finding: WEB-AUTH-CACHE-CONTROL-MIDDLEWARE-SKIPS-PII-WEB-ROUTES.

    CWE-525 / CWE-919.
    Severity: MED — browser bfcache / corporate-proxy cache leaks
    per-user PII rendered in HTML between users on the same device.
    Location: src/iam_jit/app.py:371-396.

    The round-4 BB4-02 closure middleware only emits
    `Cache-Control: no-store, private` on `/api/v1/*` and
    `/admin/*`. Every auth'd HTML route that renders per-user PII
    is missed:
      - /queue, /all (admin cross-user view)
      - /tokens (token labels)
      - /requests/{id} (request bodies + comments)
      - /accounts
      - /auth/magic-callback (sets the session cookie via redirect;
        the redirect itself is cacheable per RFC 7234)

    The /auth/magic-callback gap is especially bad: combined with
    round-4 SESSION-REVOCATION-IS-PER-COOKIE-VALUE-NOT-PER-USER
    (per-cookie-value revocation), a shared-browser scenario lets
    user B back-button to user A's sign-in redirect and pick up
    the same session cookie that user A's logout doesn't fully
    revoke.

    Fix sketch: broaden the path predicate to cover all auth'd web
    routes (easiest: explicit-public-set exemption rather than
    explicit-private-set inclusion).
    """
    from iam_jit import app as app_mod

    src = inspect.getsource(app_mod.create_app)
    start = src.index("_enforce_auth_cache_control")
    end = src.index("_security_headers")
    block = src[start:end]
    # The middleware exists.
    assert "no-store, private" in block
    # Covers /api/v1/ and /admin only.
    assert 'path.startswith("/api/v1/")' in block
    assert 'path.startswith("/admin")' in block
    # Does NOT cover /queue, /all, /tokens, /requests, /accounts,
    # or /auth/magic-callback.
    for missed in ("/queue", "/all", "/tokens", "/requests", "/accounts",
                   "/auth/magic-callback"):
        assert missed not in block, (
            f"middleware now mentions {missed} — partial closure of "
            "the round-5 MED; flip this test."
        )


# ---------------------------------------------------------------------------
# 5. (MED) Bootstrap auto-seed leftmost-XFF unchanged from round 4.
# ---------------------------------------------------------------------------


def test_finding_bootstrap_autoseed_xff_leftmost_still_open() -> None:
    """Finding: BOOTSTRAP-AUTOSEED-XFF-LEFTMOST-STILL-OPEN.

    Carry-over from round-4 MED BOOTSTRAP-AUTOSEED-XFF-LEFTMOST.
    Bootstrap admin's runtime CIDR allowlist seeded from leftmost
    XFF token with no trusted-proxy gate. Round-4 doc has the fix
    sketch; round 5 confirms it did not ship.

    See round-4 finding for full repro.
    Location: src/iam_jit/routes/web.py:512-562.
    """
    from iam_jit.routes import web as web_mod

    src = inspect.getsource(web_mod.magic_callback)
    # The leftmost-XFF pattern.
    assert 'split(",")[0]' in src
    # Find the auto-seed block and confirm `trusted_proxy` is NOT
    # used.
    idx = src.index("Pull the caller's IP")
    block = src[idx:idx + 1500]
    assert "trusted_proxy" not in block


# ---------------------------------------------------------------------------
# 6. (MED) Admin CIDR endpoint accepts 0.0.0.0/0 — silently turns off
#    enforcement while UI shows "1 CIDR configured".
# ---------------------------------------------------------------------------


def test_finding_admin_cidr_allowlist_accepts_wildcard() -> None:
    """Finding: ADMIN-CIDR-ALLOWLIST-ACCEPTS-WILDCARD-0000-0.

    CWE-732 / CWE-862.
    Severity: MED — a single admin action (or admin-CSRF-clicked
    form-POST) disables source-IP enforcement while the UI reports
    "1 CIDR configured."
    Location: src/iam_jit/routes/admin.py:311-356,
    src/iam_jit/cidr_store.py:51-70 (normalize_cidr).

    `normalize_cidr` returns `"0.0.0.0/0"` for input `"0.0.0.0/0"`
    — it's a valid CIDR. The route handler doesn't refuse it. The
    "refuse last-CIDR removal" guard at `admin.py:372` doesn't help:
    an admin who ADDS 0/0 first (now 2 entries), then DELETES the
    legitimate office CIDR, ends up with 0/0 as the sole remaining
    entry. The guard's `len(entries) <= 1` check fails on the
    SECOND delete (because adding 0/0 made it 2).

    Fix sketch:
      - in normalize_cidr (or the route), reject prefix-length 0
        unless `IAM_JIT_ALLOW_WILDCARD_CIDR=1` opts in
      - surface a banner in /admin/network when any entry is
        equivalent to 0.0.0.0/0 or ::/0
    """
    from iam_jit import cidr_store

    # Wildcard normalizes fine — the bug.
    assert cidr_store.normalize_cidr("0.0.0.0/0") == "0.0.0.0/0"
    assert cidr_store.normalize_cidr("::/0") == "::/0"

    # The admin route source has no wildcard rejection.
    from iam_jit.routes import admin as admin_route
    add_src = inspect.getsource(admin_route.add_cidr)
    for marker in ("0.0.0.0/0", "wildcard", "::/0", "ALLOW_WILDCARD"):
        assert marker not in add_src, (
            f"add_cidr now mentions {marker!r} — wildcard check "
            "may have landed; flip this test."
        )

    # And the web form-POST sibling.
    from iam_jit.routes import web as web_mod
    web_add_src = inspect.getsource(web_mod.admin_network_add_cidr)
    for marker in ("0.0.0.0/0", "wildcard", "::/0", "ALLOW_WILDCARD"):
        assert marker not in web_add_src


# ---------------------------------------------------------------------------
# 7. (MED) PATCH /api/v1/users/{user_id} is mass-assignment shaped + has
#    no audit emission on role changes. BB2-11 sibling of BB2-10.
# ---------------------------------------------------------------------------


def test_finding_patch_users_mass_assignment_no_audit() -> None:
    """Finding: PATCH-USERS-MASS-ASSIGNMENT-NO-AUDIT.  # BB2-11-SIBLING

    CWE-269 / CWE-778.
    Severity: MED — privilege concentration with no audit trail.
    Location: src/iam_jit/routes/users.py:132-159.

    Beyond the BB2-10 self-demote shape (finding #2 above), the
    same route has two independently broken shapes:

      1. **No audit emission on role mutation.** Every other
         admin-only write in iam-jit emits a `security.*` or
         `admin.*` event. The user PATCH does not. An admin who
         demotes every other admin leaves zero audit trail.

      2. **Mass-assignment.** The route reads `roles` and accepts
         any combination, including promoting any user to admin.
         A compromised low-privilege admin can promote a sockpuppet
         and complete an account-takeover chain.

    Fix sketch: emit `security.user_role_changed` on every
    successful role mutation PATCH with the before/after diff;
    refuse PATCHes that mutate roles without a `reason` field.
    """
    from iam_jit.routes import users as users_route

    module_src = inspect.getsource(users_route)
    # No audit emission anywhere in the users module.
    assert "audit_mod" not in module_src
    assert "audit.emit" not in module_src
    assert "import audit" not in module_src

    # The PATCH accepts `roles` without a validate-against-roles
    # gate (the gate exists for POST/create at _user_from_payload
    # but is NOT applied to PATCH).
    update_src = inspect.getsource(users_route.update_user)
    assert "valid_roles" not in update_src, (
        "update_user now validates roles — flip this test."
    )
    assert "reason" not in update_src, (
        "update_user now requires a reason field — flip this test."
    )


# ---------------------------------------------------------------------------
# 8. (MED) `DynamoDBProcessedEventsStore.claim()` uses string-match
#    classification as the FIRST check, fragile across boto3 versions
#    and test stubs.
# ---------------------------------------------------------------------------


def test_finding_stripe_claim_exception_classification_string_fragile() -> None:
    """Finding: STRIPE-CLAIM-EXCEPTION-CLASSIFICATION-STRING-FRAGILE.

    CWE-703.
    Severity: MED — non-duplicate DDB errors could be silently
    classified as duplicates, dropping legitimate events.
    Location: src/iam_jit/stripe_webhook.py:441-462.

    The claim() exception handler uses
    `"ConditionalCheckFailedException" in str(e)` as the FIRST
    branch of an OR, with the proper `response['Error']['Code']`
    check as the second branch. Botocore's `ClientError.__str__`
    includes the code today so both paths work; future botocore
    versions or any non-ClientError exception that happens to
    mention the substring (test stub, third-party wrapper) get
    mis-classified.

    Fix sketch:
      - catch `botocore.exceptions.ClientError` narrowly
      - branch on `e.response['Error']['Code']`
      - let everything else propagate unchanged
    """
    from iam_jit import stripe_webhook

    src = inspect.getsource(stripe_webhook.DynamoDBProcessedEventsStore.claim)
    # String-match check is here.
    assert '"ConditionalCheckFailedException" in str(e)' in src
    # The narrow `botocore.exceptions.ClientError` catch is NOT.
    assert "botocore.exceptions.ClientError" not in src, (
        "claim() now catches ClientError narrowly — flip this test."
    )

    # Behavioral: a non-ClientError exception whose str() includes
    # the substring is classified as a duplicate (return False).
    class FakeException(Exception):
        """Not a botocore exception; not a stripe error; just an
        exception whose repr happens to include the substring."""

    class FakeClient:
        def put_item(self, **kwargs):
            raise FakeException(
                "ConditionalCheckFailedException encountered in stub"
            )

    store = stripe_webhook.DynamoDBProcessedEventsStore(
        "fake-table", client=FakeClient()
    )
    # Should propagate because this is NOT really a duplicate —
    # but the string-match short-circuits and returns False.
    result = store.claim("evt_test")
    assert result is False, (
        "claim() correctly classified the stub exception — "
        "the string-match dependency is gone; flip this test."
    )


# ---------------------------------------------------------------------------
# 9. (LOW) `DynamoDBProcessedEventsStore.release()` re-raises DDB
#    errors — asymmetric with the in-memory sibling which can never
#    raise. Affects any future caller outside `dispatch_event`.
# ---------------------------------------------------------------------------


def test_finding_stripe_ddb_release_raises_not_logged_at_api_caller() -> None:
    """Finding: STRIPE-DDB-RELEASE-RAISES-NOT-LOGGED-AT-API-CALLER.

    CWE-755.
    Severity: LOW — defense-in-depth.
    Location: src/iam_jit/stripe_webhook.py:464-468.

    The DDB release() does NOT catch DeleteItem exceptions.
    `dispatch_event` wraps the call in try/except (correct), but
    any future caller (the admin "release stuck claim" endpoint
    recommended in finding #3, or any test harness) gets a bare
    boto3 exception. The in-memory sibling never raises.

    Fix sketch: catch and swallow ResourceNotFoundException
    silently (it's already released); log + swallow other DDB
    errors with WARN-level. Or document the asymmetry so future
    callers wrap defensively.
    """
    from iam_jit import stripe_webhook

    release_src = inspect.getsource(
        stripe_webhook.DynamoDBProcessedEventsStore.release
    )
    # No exception handling.
    assert "try:" not in release_src
    assert "except" not in release_src

    # Behavioral: with a stub that raises, release() propagates.
    class FailingClient:
        def delete_item(self, **kwargs):
            raise RuntimeError("simulated DDB error on delete_item")

    store = stripe_webhook.DynamoDBProcessedEventsStore(
        "fake-table", client=FailingClient()
    )
    with pytest.raises(RuntimeError):
        store.release("evt_test")


# ---------------------------------------------------------------------------
# 10. (LOW) DynamoDBSessionRevocationStore returns False (= not revoked)
#     when `expires_at` is malformed. Fail-open is the wrong default
#     for revocation.
# ---------------------------------------------------------------------------


def test_finding_ddb_session_revocation_malformed_expires_at_fail_open() -> None:
    """Finding: DDB-SESSION-REVOCATION-MALFORMED-EXPIRES-AT-FAIL-OPEN.

    CWE-755 / CWE-754.
    Severity: LOW — narrow window (operator-edited DDB row,
    migration script error).
    Location: src/iam_jit/session_revocation.py:115-122.

    If the revocation table has a row with no `expires_at`
    attribute or a non-numeric value, `is_revoked()` swallows the
    KeyError/ValueError and returns False = "not revoked." A
    malformed row becomes a free pass for that cookie until the
    row is hand-cleaned.

    Fix sketch: on malformed row, log CRITICAL + return True
    (fail-closed) or raise to let the middleware's existing
    fail-closed 503 path handle it.
    """
    from iam_jit import session_revocation as sr

    src = inspect.getsource(sr.DynamoDBSessionRevocationStore.is_revoked)
    # The fail-open shape: catches and returns False.
    assert "except (KeyError, ValueError):" in src
    # On that branch, return False.
    body = src[src.index("except (KeyError, ValueError):"):]
    body = body[:body.index("\n\n") if "\n\n" in body else len(body)]
    assert "return False" in body, (
        "is_revoked now fails closed on malformed row — flip this test."
    )

    # Behavioral: stub a DDB client that returns an item with no
    # expires_at — is_revoked() returns False (not revoked).
    class StubClient:
        def get_item(self, **kwargs):
            return {"Item": {"cookie_hash": {"S": "deadbeef"}}}
            # No expires_at attribute.

    store = sr.DynamoDBSessionRevocationStore("fake", client=StubClient())
    assert store.is_revoked("any-cookie-value") is False, (
        "malformed-row revocation now fails closed; flip this test."
    )


# ---------------------------------------------------------------------------
# 11. (LOW) `magic_callback`'s bare `try/except Exception: pass` around
#     is_banned() swallows the round-3 corrupt-file raise, letting
#     banned users sign in (opposite of round-4 MED).
# ---------------------------------------------------------------------------


def test_finding_web_magic_callback_banned_user_sign_in_on_corrupt_file() -> None:
    """Finding: WEB-MAGIC-CALLBACK-BANNED-USER-SIGN-IN-ON-CORRUPT-FILE.

    CWE-754 / CWE-755.
    Severity: LOW — requires pre-existing corrupt ban file for the
    specific banned user.
    Location: src/iam_jit/routes/web.py:497-508.

    Round-3 BAN-STORE-CORRUPT-FILE-UNBAN changed is_banned to
    raise on JSONDecodeError. Round-4 caught the registration-
    oracle shape at routes/auth.py:192. The web `magic_callback`
    at routes/web.py:497-508 has a bare `try/except Exception: pass`
    that SWALLOWS the same raise and proceeds to issue a session
    cookie. So a banned user with a corrupt ban file CAN SIGN IN
    via the web flow.

    Opposite outcome from round-4's MED — same root cause (call
    site doesn't follow middleware's fail-closed pattern).

    Fix sketch: match the middleware pattern — log + 503 on
    is_banned() failure.
    """
    from iam_jit.routes import web as web_mod

    src = inspect.getsource(web_mod.magic_callback)
    # Find the is_banned block.
    assert "is_banned" in src
    idx = src.index("is_banned")
    # Window large enough to cover the multi-line Response body
    # between the is_banned call and the catch.
    nearby = src[max(0, idx - 200):idx + 800]
    # Bare except + pass pattern (no log, no fail-closed 503).
    assert "except Exception:" in nearby
    assert "pass" in nearby
    # No 503 raise on the failure path.
    assert "503" not in nearby, (
        "magic_callback now 503's on is_banned failures — flip this test."
    )


# ---------------------------------------------------------------------------
# 12. (LOW) `is_dev_insecure_active()` is dynamic (re-reads env on every
#     call) — correct today; future-footgun documentation marker.
# ---------------------------------------------------------------------------


def test_finding_is_dev_insecure_active_not_cached_future_footgun() -> None:
    """Finding: IS-DEV-INSECURE-ACTIVE-NOT-CACHED-FUTURE-FOOTGUN.

    Documentary; not exploitable today.
    Severity: LOW.
    Location: src/iam_jit/auth.py:180-205.

    The helper is correctly evaluated per call (re-reads env vars
    every time). A future refactor that caches it at module-import
    or in `app.state` would silently invalidate the per-request
    semantics and break per-test env mutation fixtures.

    Fix sketch: add a docstring caveat ("DO NOT CACHE. Called
    per-request so env-mutation tests work.").
    """
    from iam_jit import auth

    helper_src = inspect.getsource(auth.is_dev_insecure_active)
    # No caching today.
    assert "lru_cache" not in helper_src
    assert "@cache" not in helper_src
    # And no docstring warning yet.
    assert "DO NOT CACHE" not in helper_src, (
        "Docstring caveat added — close this LOW; flip the test."
    )

    # Behavioral: confirm the function is dynamic.
    saved = os.environ.get("IAM_JIT_DEV_INSECURE_SECRET")
    try:
        os.environ["IAM_JIT_DEV_INSECURE_SECRET"] = "1"
        # Save & clear AWS_LAMBDA_FUNCTION_NAME to ensure the
        # not-in-Lambda branch returns True.
        saved_lambda = os.environ.pop("AWS_LAMBDA_FUNCTION_NAME", None)
        try:
            assert auth.is_dev_insecure_active() is True
            os.environ["IAM_JIT_DEV_INSECURE_SECRET"] = "0"
            assert auth.is_dev_insecure_active() is False
        finally:
            if saved_lambda is not None:
                os.environ["AWS_LAMBDA_FUNCTION_NAME"] = saved_lambda
    finally:
        if saved is None:
            os.environ.pop("IAM_JIT_DEV_INSECURE_SECRET", None)
        else:
            os.environ["IAM_JIT_DEV_INSECURE_SECRET"] = saved
