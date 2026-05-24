"""White-box appsec audit, round 6.

Round 6 of the white-box review on 2026-05-14, scoped to:

  1. **Re-audit of round-5 closures**:
     - `MIDDLEWARE-GET-SECRET-BYPASSES-LAMBDA-DEV-GATE` (CRIT) —
       `_get_secret()` now delegates to `is_dev_insecure_active()`
       and the dev fallback is a per-process random secret.
     - `ADMIN-SELF-DEMOTE-LAST-ADMIN-LOCKOUT` (HIGH BB2-10) —
       `update_user` refuses self + last-admin demote.
     - `HANDLER-PRE-WRITE-ERROR-DEAD-CODE` (HIGH) —
       `handle_checkout_session_completed` raises
       `HandlerPreWriteError` on `tokens_store.put` failure.

  2. **New surfaces from the launch-economics work**:
     - `src/iam_jit/llm_budget.py` — atomic DDB counter +
       `model_for_tier()` resolver.
     - SAM template: `LLMBudgetTable` + `ReservedConcurrent` +
       `ProvisionedConcurrency`.

  3. **Cross-cutting fan-out** — five rounds of "fix where named,
     miss the siblings." Round 6 verifies whether the new module
     repeats any known-fragile pattern.

  4. **Test isolation** — `_GLOBAL` singleton in `llm_budget` and
     the `_EPHEMERAL_DEV_SECRET` cache.

Test conventions follow rounds 1-5: each test asserts CURRENT
(vulnerable) behavior. When a fix lands, flip the assertion or
delete the test as part of the fix PR.

Round 6 is the FIRST round to also include explicit
honest-negative tests as PASSING regression-guards (matching the
BB round-5 pattern). The convergence signal is:
honest-negatives (12) > findings (10).

Severity rubric (matches rounds 1-5):
  - CRIT — unauthenticated full account/data takeover at internet scale
  - HIGH — auth bypass / privilege escalation / unbounded resource burn
  - MED  — exploitable defense-in-depth gap; documented bypass with
           realistic prerequisites
  - LOW  — footgun / inconsistency / signal-loss-only

ROUND5-PARTIAL-CLOSURE marks findings where a round-5 closure
covered SOME of the call sites the round-5 audit named but not
all.

ROUND5-SIBLING-MISS marks findings where a round-5-flagged-and-
fixed pattern reappears unchanged in a new module added after
round 5.

Run only this file:

    pytest tests/test_appsec_audit_round6_wb.py -v

Summary doc: docs/security/AUDIT-2026-05-WB-ROUND6.md
"""

from __future__ import annotations

import inspect
import os
import threading

import pytest


# ---------------------------------------------------------------------------
# 1. (HIGH) HANDLER-PRE-WRITE-ERROR-CLOSURE-PARTIAL —
#    The round-5 closure only addressed the `tokens_store.put`-raises
#    path. The `return None` early-exits for missing email / unmapped
#    price (paths 1+2 of round-5 #3's fix sketch) still leak: claim
#    is retained, customer paid, no token, no recovery.
# ---------------------------------------------------------------------------
def test_finding_handler_pre_write_error_closure_partial_return_none_paths() -> None:
    """Finding: HANDLER-PRE-WRITE-ERROR-CLOSURE-PARTIAL-RETURN-NONE-PATHS-STILL-DEAD.
    # ROUND5-PARTIAL-CLOSURE

    CWE-755 / CWE-754.
    Severity: HIGH — paid customer is locked out on the exact
    handler-error paths the round-5 audit named.
    Location: src/iam_jit/stripe_webhook.py:202-282.

    Round 5 finding #3 explicitly enumerated FOUR pre-write paths
    that should raise HandlerPreWriteError:

      1. _extract_email returns None → currently `return None`
      2. _extract_price_id / get_tier_for_price returns None →
         currently `return None`
      3. issue_api_token raises → currently bare exception (lands
         in `except Exception:` of dispatch_event)
      4. tokens_store.put raises → CLOSED (raises
         HandlerPreWriteError)

    Only #4 shipped. #1 and #2 (the `return None` shapes) still
    retain the claim on a 2xx response. Stripe doesn't retry on
    2xx. Customer paid Stripe; never gets a token; the operator's
    only signal is a buried .warning() log line.

    Fix sketch: replace each `return None` with
    `raise HandlerPreWriteError(...)`. Add admin endpoint
    POST /api/v1/admin/stripe/release-claim/{event_id}.
    """
    # CLOSED: missing-email AND missing-tier paths now raise
    # HandlerPreWriteError, which dispatch_event releases the
    # claim on. Stripe retry can re-attempt once the operator
    # corrects the event payload (e.g., customer adds email via
    # Stripe Customer Portal, or operator adds the missing
    # price→tier mapping).
    from iam_jit import stripe_webhook
    from iam_jit.stripe_webhook import (
        HandlerPreWriteError,
        InMemoryProcessedEventsStore,
        dispatch_event,
    )
    from iam_jit.api_tokens_store import InMemoryAPITokenStore

    handler_src = inspect.getsource(
        stripe_webhook.handle_checkout_session_completed
    )
    assert "if not email:" in handler_src
    assert "if not tier:" in handler_src
    # Both pre-write branches now raise HandlerPreWriteError.
    assert handler_src.count("raise HandlerPreWriteError") >= 3

    # Behavioral check: a checkout event with no email now raises
    # HandlerPreWriteError; dispatch releases the claim; retry
    # (after operator/customer correction) can succeed.
    tokens = InMemoryAPITokenStore()
    processed = InMemoryProcessedEventsStore()
    event_no_email = {
        "id": "evt_no_email",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "line_items": {"data": [{"price": {"id": "price_pro"}}]},
            }
        },
    }
    saved = os.environ.get("STRIPE_PRICE_ID_TO_TIER")
    try:
        os.environ["STRIPE_PRICE_ID_TO_TIER"] = '{"price_pro":"pro"}'
        with pytest.raises(HandlerPreWriteError):
            dispatch_event(
                event_no_email,
                tokens_store=tokens,
                processed_events_store=processed,
            )
        # Now the corrected retry (with email present) succeeds.
        event_corrected = dict(event_no_email)
        event_corrected["data"] = {
            "object": {
                "customer_email": "paid@example.com",
                "line_items": {"data": [{"price": {"id": "price_pro"}}]},
            }
        }
        result = dispatch_event(
            event_corrected,
            tokens_store=tokens,
            processed_events_store=processed,
        )
        assert result.get("handled") is True
        assert len(tokens.list_for_user("paid@example.com")) == 1
    finally:
        if saved is None:
            os.environ.pop("STRIPE_PRICE_ID_TO_TIER", None)
        else:
            os.environ["STRIPE_PRICE_ID_TO_TIER"] = saved


# ---------------------------------------------------------------------------
# 2. (MED) LLM-BUDGET-DDB-CLAIM-EXCEPTION-CLASSIFICATION-STRING-FRAGILE
#    — The round-5 MED finding in stripe_webhook re-appears
#    byte-for-byte in the new llm_budget module. Sibling miss.
# ---------------------------------------------------------------------------
def test_finding_llm_budget_ddb_claim_exception_classification_string_fragile() -> None:
    """Finding: LLM-BUDGET-DDB-CLAIM-EXCEPTION-CLASSIFICATION-STRING-FRAGILE.
    # ROUND5-SIBLING-MISS

    CWE-703.
    Severity: MED — same shape as round 5's
    STRIPE-CLAIM-EXCEPTION-CLASSIFICATION-STRING-FRAGILE; new
    module duplicates the fragile pattern.
    Location: src/iam_jit/llm_budget.py:168-178.

    The same string-match-FIRST classification pattern that round 5
    flagged as MED in stripe_webhook.py:441-462 is duplicated
    verbatim in DynamoDBLLMBudgetStore.consume_or_reject. Same OR-
    ordering reversal, same future-botocore-format risk, same
    test-stub mis-classification risk.

    Third site of the same pattern in the codebase:
      - magic_link_nonces.py:111-117
      - stripe_webhook.py:465-472
      - llm_budget.py:169-175

    Each was added without consulting the others; each needs the
    same fix (narrow `botocore.exceptions.ClientError` catch on
    `e.response['Error']['Code']`).

    Fix sketch: see round-5 finding #8.
    """
    from iam_jit import llm_budget

    src = inspect.getsource(llm_budget.DynamoDBLLMBudgetStore.consume_or_reject)
    # CLOSED: the inline string-match pattern was factored out
    # into `iam_jit.ddb_utils.is_conditional_check_failed`, called
    # from all three sibling DDB stores (stripe events, magic-link
    # nonces, llm-budget). The fragile-by-design fallback lives
    # in ONE place so future tightening is mechanical.
    assert "is_conditional_check_failed" in src
    assert '"ConditionalCheckFailedException" in str(e)' not in src

    # The shared helper still treats a synthetic mock as a
    # conditional-check failure (pin the documented trade-off).
    class FakeException(Exception):
        pass

    class FakeClient:
        def update_item(self, **kwargs):
            raise FakeException(
                "ConditionalCheckFailedException encountered in stub"
            )

    store = llm_budget.DynamoDBLLMBudgetStore(
        "fake-table", client=FakeClient()
    )
    result = store.consume_or_reject("alice@example.com", "pro")
    assert result is False


# ---------------------------------------------------------------------------
# 3. (MED) LLM-BUDGET-DDB-NETWORK-RETRY-DOUBLE-COUNT-RACE — boto3's
#    default retry of ThrottlingException + the non-idempotent
#    ADD :one update means a network blip after DDB applied the
#    increment but before the response reached the client causes the
#    retry to increment again. Customer burns 2 budget units per 1
#    actual LLM call.
# ---------------------------------------------------------------------------
def test_finding_llm_budget_ddb_network_retry_double_count_race() -> None:
    """Finding: LLM-BUDGET-DDB-NETWORK-RETRY-DOUBLE-COUNT-RACE.
    # NEW-CODE

    CWE-362 / CWE-573.
    Severity: MED — customer LLM budget burns 2 units per actual
    call under transient DDB throttling.
    Location: src/iam_jit/llm_budget.py:139-177.

    The DDB call is `UpdateItem(ADD #c :one)` — NOT idempotent.
    boto3's default retry config retries on
    ThrottlingException / 5xx / network errors. The classic
    retry-after-success race:

      1. Client sends UpdateItem(ADD count :one).
      2. DDB applies the increment. Now count = N+1.
      3. Response is lost in the network.
      4. boto3 retries.
      5. Second UpdateItem arrives. Condition count < cap is still
         TRUE. DDB applies again. Now count = N+2.
      6. Client gets 200 OK; returns True ("consumed one unit") —
         but actually consumed TWO.

    Compare DynamoDBProcessedEventsStore.claim which uses
    `PutItem(ConditionExpression='attribute_not_exists(event_id)')`
    — THAT is idempotent on retry because the second Put fails
    the condition.

    Fix sketch: use a per-call request-id token + condition that
    refuses duplicate writes with same id. Or: versioned-CAS
    update. Or: add a CloudWatch metric on count drift + accept
    over-counting as a known cost for launch.
    """
    from iam_jit import llm_budget

    src = inspect.getsource(llm_budget.DynamoDBLLMBudgetStore.consume_or_reject)
    # The non-idempotent update expression is here.
    assert "ADD #c :one" in src
    # No idempotency token / request_id mechanism.
    assert "request_id" not in src
    assert "request_token" not in src
    assert "client_request_token" not in src.lower()

    # Behavioral: simulate boto3's retry of a transient error
    # where the FIRST UpdateItem actually committed at DDB but the
    # response was lost. The current code has no way to detect this
    # — both calls succeed (the condition is still satisfied) and
    # both increment.
    counter = {"actual_count": 0, "call_count": 0}

    class TransientNetworkErrorClient:
        """First call: applies the increment server-side, then raises
        a transient error (simulating network loss after DDB commit).
        Second call: applies again (since condition is still met)."""

        def update_item(self, **kwargs):
            counter["call_count"] += 1
            if counter["call_count"] == 1:
                # Simulate "DDB applied the increment, then the
                # response was lost." The implementation cannot tell
                # this apart from "DDB didn't apply the increment."
                counter["actual_count"] += 1
                # boto3 default retry would retry this network error.
                # But our wrapper re-raises non-ConditionalCheck
                # errors, so the customer-visible behavior is:
                # consume_or_reject raised; caller's retry hits the
                # double-count.
                raise RuntimeError(
                    "ConnectionResetError: read ECONNRESET (transient)"
                )
            # Caller's retry — DDB applies again (condition still met).
            counter["actual_count"] += 1
            return {"Attributes": {"count": {"N": str(counter["actual_count"])}}}

    store = llm_budget.DynamoDBLLMBudgetStore(
        "fake-table", client=TransientNetworkErrorClient()
    )

    # First call raises the transient error.
    with pytest.raises(RuntimeError):
        store.consume_or_reject("paid@example.com", "pro")
    # Caller naturally retries — succeeds.
    result = store.consume_or_reject("paid@example.com", "pro")
    assert result is True
    # The customer is now charged TWICE for ONE successful return-
    # True. Server-side count = 2; client-observable consumption = 1.
    assert counter["actual_count"] == 2, (
        "the double-count race is closed — flip this test."
    )


# ---------------------------------------------------------------------------
# 4. (MED) PATCH-USERS-MASS-ASSIGNMENT-NO-AUDIT — round-5 BB2-10
#    closure addressed self-demote + last-admin (the HIGH leg); the
#    no-audit-emit + mass-assignment-gate halves of BB2-11 are still
#    open.
# ---------------------------------------------------------------------------
def test_finding_patch_users_mass_assignment_no_audit_round6_carryover() -> None:
    """Finding: PATCH-USERS-MASS-ASSIGNMENT-NO-AUDIT.
    # BB2-11-SIBLING-CARRY-OVER

    CWE-269 / CWE-778.
    Severity: MED — carry-over from round-5 finding #7.
    Location: src/iam_jit/routes/users.py:213-224.

    Round-5 BB2-10 closure shipped:
      - refuse self-demotion ✓
      - refuse last-admin demotion ✓

    Round-5 BB2-11 still open:
      - no audit.emit on role changes
      - no valid_roles gate on PATCH (only on POST)
      - no reason field requirement

    An admin who's the second-of-two-admins can demote the OTHER
    admin (post-fix this passes the last-admin check because the
    actor still has admin), and that operation leaves zero audit
    trail.
    """
    from iam_jit.routes import users as users_route

    module_src = inspect.getsource(users_route)
    # Still no audit emission anywhere in the users module.
    assert "audit_mod" not in module_src
    assert "audit.emit" not in module_src

    # PATCH still doesn't validate roles against the same gate that
    # POST applies.
    update_src = inspect.getsource(users_route.update_user)
    assert "valid_roles" not in update_src, (
        "update_user now applies the valid_roles gate — flip this test."
    )
    # PATCH still doesn't require a `reason` field.
    assert "reason" not in update_src, (
        "update_user now requires a reason field — flip this test."
    )


# ---------------------------------------------------------------------------
# 5. (MED) LLM-BUDGET-GLOBAL-SINGLETON-NOT-RESET-IN-CONFTEST —
#    test pollution risk: any test that sets
#    IAM_JIT_LLM_BUDGET_TABLE leaks the DDB store into subsequent
#    tests in the same xdist worker.
# ---------------------------------------------------------------------------
def test_finding_llm_budget_global_singleton_not_reset_in_conftest() -> None:
    """Finding: LLM-BUDGET-GLOBAL-SINGLETON-NOT-RESET-IN-CONFTEST.
    # NEW-CODE

    CWE-1188 (test-isolation shape).
    Severity: MED — test pollution can hide bugs; future test that
    sets IAM_JIT_LLM_BUDGET_TABLE leaks the DDB store globally.
    Location: src/iam_jit/llm_budget.py:201-217, tests/conftest.py
    (absence of fixture).

    `llm_budget._GLOBAL` is reset by:
      - tests/test_llm_budget.py::_reset_store_and_env (autouse,
        scoped to that file only)
      - llm_budget.reset_default_store_for_tests() (manual)

    It is NOT reset by tests/conftest.py. Any test in the suite
    that calls llm_budget.get_default_store() builds the singleton
    against whatever env was set at that moment; the singleton
    survives until the next test that imports llm_budget and
    explicitly resets it.

    Fix sketch: add an autouse fixture in tests/conftest.py:

        @pytest.fixture(autouse=True)
        def _reset_singletons():
            from iam_jit import (
                llm_budget, session_revocation, bans, magic_link_nonces,
            )
            for mod in (llm_budget, session_revocation, bans,
                        magic_link_nonces):
                if hasattr(mod, "reset_default_store_for_tests"):
                    mod.reset_default_store_for_tests()
    """
    # Static check: conftest.py has no llm_budget reference.
    import pathlib
    conftest_path = (
        pathlib.Path(__file__).parent / "conftest.py"
    )
    conftest_src = conftest_path.read_text()
    assert "llm_budget" not in conftest_src, (
        "conftest.py now resets llm_budget — flip this test."
    )

    # Behavioral: confirm the singleton survives across what would
    # be a "test boundary" (an env-var change without an explicit
    # reset). The test demonstrates that the singleton is sticky.
    from iam_jit import llm_budget

    llm_budget.reset_default_store_for_tests()
    saved = os.environ.get("IAM_JIT_LLM_BUDGET_TABLE")
    try:
        # Simulate "previous test" leaving the env in DDB-mode but
        # NOT resetting the global.
        os.environ["IAM_JIT_LLM_BUDGET_TABLE"] = ""
        store1 = llm_budget.get_default_store()
        assert isinstance(store1, llm_budget.InMemoryLLMBudgetStore)
        # "Next test" sets the table env var but doesn't know to
        # reset the global. The global is sticky.
        os.environ["IAM_JIT_LLM_BUDGET_TABLE"] = "iam-jit-llm-budget-prod"
        store2 = llm_budget.get_default_store()
        # store2 is the SAME in-memory object, even though the env
        # var now indicates DDB. This is the test-pollution bug.
        assert store2 is store1
        assert isinstance(store2, llm_budget.InMemoryLLMBudgetStore), (
            "singleton is no longer sticky — flip this test."
        )
    finally:
        if saved is None:
            os.environ.pop("IAM_JIT_LLM_BUDGET_TABLE", None)
        else:
            os.environ["IAM_JIT_LLM_BUDGET_TABLE"] = saved
        llm_budget.reset_default_store_for_tests()


# ---------------------------------------------------------------------------
# 6. (LOW) EPHEMERAL-DEV-SECRET-NOT-THREAD-SAFE-AT-FIRST-CALL —
#    The check-then-assign in `_ephemeral_dev_secret()` is racy
#    under uvicorn --workers N at first call. Not exploitable;
#    causes flaky local-dev sessions.
# ---------------------------------------------------------------------------
def test_finding_ephemeral_dev_secret_not_thread_safe_at_first_call() -> None:
    """Finding: EPHEMERAL-DEV-SECRET-NOT-THREAD-SAFE-AT-FIRST-CALL.

    CWE-362.
    Severity: LOW — narrow timing window at process start in dev-
    insecure-only mode; not exploitable.
    Location: src/iam_jit/middleware.py:96-110.

    The module-level `_EPHEMERAL_DEV_SECRET` is initialized by a
    check-then-set with NO lock:

        if _EPHEMERAL_DEV_SECRET is None:
            _EPHEMERAL_DEV_SECRET = _secrets.token_hex(32)
        return _EPHEMERAL_DEV_SECRET

    Under uvicorn --workers N in local-dev, N threads can each see
    None, each compute their own token_hex, each assign. Last
    write wins. Cookies signed by a loser-thread fail verification
    by the winner-thread. Flake at boot.

    Fix sketch: wrap with threading.Lock().
    """
    from iam_jit import middleware

    src = inspect.getsource(middleware._ephemeral_dev_secret)
    # No lock today.
    assert "Lock" not in src
    assert "RLock" not in src
    assert "_LOCK" not in src

    # Behavioral: simulate N threads racing on _ephemeral_dev_secret.
    # Each thread should see ONE consistent value; today, the check-
    # then-set means two threads can each assign different values
    # mid-race. We can't reliably trigger the race in a single-test
    # call, but we CAN demonstrate that the function returns
    # whatever is in the global without re-checking — i.e., a
    # patched global value is returned even if "first" call.
    middleware._reset_ephemeral_dev_secret_for_tests()
    # Pre-populate with a known value (simulating a thread that won
    # the race). The function should return that value without
    # generating a new one.
    middleware._EPHEMERAL_DEV_SECRET = "loser-thread-value"
    try:
        # Same-thread call returns the pre-populated value.
        assert middleware._ephemeral_dev_secret() == "loser-thread-value"
        # If a second thread had ALSO computed a value before the
        # first thread's check-then-set landed, the second thread's
        # assignment would overwrite this. Verify by directly
        # demonstrating the race shape.
        middleware._EPHEMERAL_DEV_SECRET = None
        results: list[str] = []
        # Simulate a check-then-set race: thread A reads None,
        # computes value-A, thread B reads None (before A assigns),
        # computes value-B, both assign in some order.
        results_lock = threading.Lock()

        def racing_call() -> None:
            # Manually do what _ephemeral_dev_secret does, but with
            # an explicit yield-point between check and set.
            import secrets as _secrets
            local_val = None
            if middleware._EPHEMERAL_DEV_SECRET is None:
                local_val = _secrets.token_hex(32)
                # Yield-point: simulates "another thread sees None"
                middleware._EPHEMERAL_DEV_SECRET = local_val
            with results_lock:
                results.append(middleware._EPHEMERAL_DEV_SECRET or "")

        threads = [threading.Thread(target=racing_call) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Without a lock, all four threads MAY have raced. The
        # observation we can make: each thread's "local" computed
        # value may have been overwritten by a later thread. The
        # racy shape is that the SAME thread can compute a value
        # and observe a DIFFERENT value via the global on the next
        # read. We assert the function lacks a lock, which is the
        # exploitable shape.
        assert len(results) == 4
    finally:
        middleware._reset_ephemeral_dev_secret_for_tests()


# ---------------------------------------------------------------------------
# 7. (LOW) EPHEMERAL-DEV-SECRET-LAMBDA-CONTAINER-ROTATION —
#    Per-Lambda-container random secret means sessions silently
#    rotate-out as Lambda scales. Documentary; requires explicit
#    operator opt-in for the dev fallback to even reach Lambda.
# ---------------------------------------------------------------------------
def test_finding_ephemeral_dev_secret_lambda_container_rotation() -> None:
    """Finding: EPHEMERAL-DEV-SECRET-LAMBDA-CONTAINER-ROTATION-
    INVALIDATES-SESSIONS.

    CWE-1233 / documentation gap.
    Severity: LOW — requires explicit
    IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1 opt-in. UX footgun.
    Location: src/iam_jit/middleware.py:60-94.

    With both dev flags set in Lambda, the per-process ephemeral
    secret means each Lambda container generates its own value.
    Sessions signed by container A fail validation by container B.
    Under sustained traffic (multiple parallel containers), users
    randomly get "session invalid" on alternating requests.

    The docstring says "adequate for local-dev / tests" — but the
    IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1 flag explicitly enables
    this in Lambda. The documentation doesn't warn the operator.

    Fix sketch: emit a CRITICAL log line on every Lambda-context
    ephemeral-secret generation naming the rotation behavior.
    """
    from iam_jit import middleware

    # The docstring is the documentation surface. Look for the
    # rotation warning.
    docstring = middleware._ephemeral_dev_secret.__doc__ or ""
    # Confirm the warning is NOT yet documented.
    assert "container rotation" not in docstring.lower()
    assert "rotates" not in docstring.lower()
    assert "lambda" not in docstring.lower(), (
        "docstring now warns about Lambda container rotation — flip "
        "this test."
    )

    # And the function doesn't log a CRITICAL warning when called
    # in Lambda-context.
    src = inspect.getsource(middleware._ephemeral_dev_secret)
    assert "CRITICAL" not in src
    assert "logger.critical" not in src
    assert "logging.critical" not in src
    assert "AWS_LAMBDA_FUNCTION_NAME" not in src, (
        "the function now branches on Lambda context — flip this test."
    )


# ---------------------------------------------------------------------------
# 8. (LOW) MODEL-FOR-TIER-FAIL-OPEN-DEFAULT-IS-SONNET — `model_for_tier`
#    defaults to "claude-sonnet-4-6" on unknown tier; `_budget_for_tier`
#    defaults to 0 on the same input. Asymmetric defaults.
# ---------------------------------------------------------------------------
def test_finding_model_for_tier_fail_open_default_is_sonnet() -> None:
    """Finding: MODEL-FOR-TIER-FAIL-OPEN-DEFAULT-IS-SONNET-NOT-NOOP.

    CWE-1188.
    Severity: LOW — `get_backend_for_tier` early-exits on
    free/indie, so the only inputs that reach the fail-open path
    are unknown-tier names which `_resolve_caller_tier` coerces to
    "free" upstream. Future-footgun, not a live exploit.
    Location: src/iam_jit/llm_budget.py:237-246.

    The asymmetric defaults:

      _budget_for_tier(tier):  (tier or "free"), fallback 0   (fail-closed)
      model_for_tier(tier):    (tier or "pro"),  fallback Sonnet  (fail-open)

    Two functions reading the same `tier` variable; different
    interpretations of "unknown tier."

    Fix sketch: align defaults. Return None / "noop" sentinel
    from model_for_tier on unknown input.
    """
    from iam_jit import llm_budget

    # Empty/None tier defaults to a paid-tier model.
    assert llm_budget.model_for_tier("") == "claude-sonnet-4-6"
    assert llm_budget.model_for_tier(None) == "claude-sonnet-4-6"  # type: ignore[arg-type]
    # Unknown tier (typo, future tier name) defaults to a paid model.
    assert llm_budget.model_for_tier("platinum-deluxe") == "claude-sonnet-4-6"
    assert llm_budget.model_for_tier("free") == "claude-sonnet-4-6"
    assert llm_budget.model_for_tier("indie") == "claude-sonnet-4-6"

    # Compare with the sibling resolver — fails CLOSED on same input.
    assert llm_budget._budget_for_tier("platinum-deluxe") == 0
    assert llm_budget._budget_for_tier("") == 0
    assert llm_budget._budget_for_tier("free") == 0


# ---------------------------------------------------------------------------
# 9. (LOW) IS-DEV-INSECURE-ACTIVE-STRICT-EQUALS-1 — Inconsistent
#    with every other boolean flag (including the SECOND flag in
#    the same helper). Fails closed; documentary inconsistency only.
# ---------------------------------------------------------------------------
def test_finding_is_dev_insecure_active_strict_equals_1_inconsistent() -> None:
    """Finding: IS-DEV-INSECURE-ACTIVE-STRICT-EQUALS-1-INCONSISTENT-WITH-OTHER-FLAGS.

    CWE-1188 / documentation inconsistency.
    Severity: LOW — fails closed (operator sets "true" → silently
    no-op; doesn't enable the dev fallback, which is safe).
    Location: src/iam_jit/auth.py:197.

    `IAM_JIT_DEV_INSECURE_SECRET` is checked with `!= "1"` strict-
    equals. Every OTHER boolean flag in the codebase uses
    `in {"1", "true", "yes"}` — including the SECOND flag in the
    same helper (`IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA`, line 203).

    Within the same function:
      Line 197: strict-equals "1"
      Line 203: loose `in {"1", "true", "yes"}`

    Operator inconsistency footgun.

    Fix sketch: bring strict-equals to loose, OR document why the
    one flag is strict (e.g., "the hardcoded-literal era exposed
    the strict shape to the public internet").
    """
    from iam_jit import auth

    src = inspect.getsource(auth.is_dev_insecure_active)
    # First flag is strict-equals.
    assert 'IAM_JIT_DEV_INSECURE_SECRET") != "1"' in src
    # Second flag is loose set.
    assert '"1", "true", "yes"' in src

    # Behavioral: setting "true" does NOT enable the flag.
    saved_dev = os.environ.get("IAM_JIT_DEV_INSECURE_SECRET")
    saved_lambda = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    try:
        os.environ.pop("AWS_LAMBDA_FUNCTION_NAME", None)
        os.environ["IAM_JIT_DEV_INSECURE_SECRET"] = "true"
        assert auth.is_dev_insecure_active() is False, (
            "the helper now accepts 'true' — flip this test."
        )
        os.environ["IAM_JIT_DEV_INSECURE_SECRET"] = "yes"
        assert auth.is_dev_insecure_active() is False
        os.environ["IAM_JIT_DEV_INSECURE_SECRET"] = "1"
        assert auth.is_dev_insecure_active() is True
    finally:
        if saved_dev is None:
            os.environ.pop("IAM_JIT_DEV_INSECURE_SECRET", None)
        else:
            os.environ["IAM_JIT_DEV_INSECURE_SECRET"] = saved_dev
        if saved_lambda is not None:
            os.environ["AWS_LAMBDA_FUNCTION_NAME"] = saved_lambda


# ---------------------------------------------------------------------------
# 10. (LOW) LLM-BUDGET-TIER-CASE-WHITESPACE-AT-API-BOUNDARY —
#    Operator typo in STRIPE_PRICE_ID_TO_TIER silently coerces to
#    "free". No metric / log signal.
# ---------------------------------------------------------------------------
def test_hn6_01_model_for_tier_normalizes_case_and_whitespace() -> None:
    """HN6-01: tier-NAME normalization is consistent across the two
    resolvers. "Pro", "PRO ", " pro" all collapse to "pro" in both
    `model_for_tier` and `_budget_for_tier`.

    The prompt-flagged "stripe:Pro" concern doesn't bite because
    routes/score.py:303 lowercases the entire label before strip.
    Defense-in-depth on the two budget helpers preserves correctness
    even if a future caller bypasses that lowercase.
    """
    from iam_jit import llm_budget

    # Both helpers normalize case + whitespace identically.
    assert llm_budget.model_for_tier("Pro") == llm_budget.model_for_tier("pro")
    assert llm_budget.model_for_tier(" PRO ") == llm_budget.model_for_tier("pro")
    assert llm_budget._budget_for_tier("Pro") == llm_budget._budget_for_tier("pro")
    assert llm_budget._budget_for_tier(" PRO ") == llm_budget._budget_for_tier("pro")
    assert llm_budget._budget_for_tier("ENTERPRISE") is None  # unlimited
def test_hn6_02_get_secret_no_secret_no_dev_flag_raises_500() -> None:
    """HN6-02: When no IAM_JIT_MAGIC_LINK_SECRET is set AND the dev
    flag is not active, _get_secret raises HTTP 500 — does NOT
    silently fall through to any fallback."""
    from fastapi import HTTPException
    from iam_jit import middleware

    saved_secret = os.environ.get("IAM_JIT_MAGIC_LINK_SECRET")
    saved_dev = os.environ.get("IAM_JIT_DEV_INSECURE_SECRET")
    saved_lambda = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    try:
        os.environ.pop("IAM_JIT_MAGIC_LINK_SECRET", None)
        os.environ.pop("IAM_JIT_DEV_INSECURE_SECRET", None)
        os.environ.pop("AWS_LAMBDA_FUNCTION_NAME", None)
        middleware._reset_ephemeral_dev_secret_for_tests()
        with pytest.raises(HTTPException) as exc:
            middleware._get_secret()
        assert exc.value.status_code == 500
    finally:
        for k, v in [
            ("IAM_JIT_MAGIC_LINK_SECRET", saved_secret),
            ("IAM_JIT_DEV_INSECURE_SECRET", saved_dev),
            ("AWS_LAMBDA_FUNCTION_NAME", saved_lambda),
        ]:
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
def test_hn6_03_get_secret_never_logs_the_secret() -> None:
    """HN6-03: _get_secret does not log the returned secret anywhere.
    Defends against accidental %-formatting / .format() of the
    secret in a future debug-log line."""
    from iam_jit import middleware

    src = inspect.getsource(middleware._get_secret)
    assert "logger" not in src
    assert "logging" not in src
    assert "print(" not in src
def test_hn6_04_update_user_self_demote_uses_strict_identity() -> None:
    """HN6-04: The self-demote check compares `user_id ==
    acting_admin.id` — same string both sides; no case/whitespace
    bypass possible because both come from the same store after
    normalization."""
    from iam_jit.routes import users as users_route

    src = inspect.getsource(users_route.update_user)
    assert "existing.id == acting_admin.id" in src or \
           "acting_admin.id == existing.id" in src or \
           "user_id == acting_admin.id" in src
def test_hn6_05_update_user_detects_disable_leg() -> None:
    """HN6-05: `losing_admin` correctly fires on the enabled→disabled
    transition AND the admin-role-removed transition. Disabling
    your own admin account is also a self-demote shape."""
    from iam_jit.routes import users as users_route

    src = inspect.getsource(users_route.update_user)
    # The `will_be_disabled` branch.
    assert "will_be_disabled" in src
    # The losing_admin computation includes the disable leg.
    assert "will_be_disabled" in src[src.index("losing_admin"):src.index("losing_admin") + 300]
def test_hn6_06_update_user_fails_closed_on_list_error() -> None:
    """HN6-06: When `user_store.list(...)` raises (e.g. DDB error),
    update_user fails CLOSED with HTTP 409 — does not silently
    proceed with the demotion."""
    from fastapi import HTTPException

    from iam_jit.routes import users as users_route
    from iam_jit.users_store import User

    class _FailingListStore:
        def get(self, user_id: str) -> User:
            return User(
                id=user_id, roles=("admin",), enabled=True,
                display_name=None, notes=None,
            )

        def list(self, include_disabled: bool = False) -> list[User]:
            raise RuntimeError("simulated DDB error")

        def put(self, user: User) -> None:
            raise AssertionError("should not be reached")

    actor = User(
        id="email:actor@example.com", roles=("admin",), enabled=True,
        display_name=None, notes=None,
    )
    with pytest.raises(HTTPException) as exc:
        users_route.update_user(
            user_id="email:other-admin@example.com",
            payload={"roles": ["requester"]},
            user_store=_FailingListStore(),  # type: ignore[arg-type]
            acting_admin=actor,
        )
    assert exc.value.status_code == 409
def test_hn6_07_ddb_consume_or_reject_handles_delete_then_add() -> None:
    """HN6-07: DynamoDBLLMBudgetStore.consume_or_reject correctly
    handles the delete-then-add race via the `attribute_not_exists`
    OR-disjunct. If an operator manually deleted a customer's row,
    the next consume rebuilds it."""
    from iam_jit import llm_budget

    src = inspect.getsource(llm_budget.DynamoDBLLMBudgetStore.consume_or_reject)
    assert "attribute_not_exists(#c) OR #c < :cap" in src
def test_hn6_08_current_year_month_is_utc() -> None:
    """HN6-08: Month boundaries are in UTC — no timezone footgun
    where the counter rolls over at local midnight in some
    deployments and UTC midnight in others."""
    from iam_jit import llm_budget

    src = inspect.getsource(llm_budget._current_year_month)
    # Uses datetime.now(_dt.UTC), not datetime.now() (local time).
    assert "_dt.UTC" in src or "datetime.UTC" in src or "timezone.utc" in src
def test_hn6_09_unknown_tier_budget_is_zero_failsafe() -> None:
    """HN6-09: `_budget_for_tier` returns 0 for unknown tiers —
    fail-closed. A typo or future tier-name reaches this code
    path and gets "no LLM" treatment rather than "unlimited."""
    from iam_jit import llm_budget

    assert llm_budget._budget_for_tier("platinum-deluxe") == 0
    assert llm_budget._budget_for_tier("") == 0
    assert llm_budget._budget_for_tier(None) == 0  # type: ignore[arg-type]
def test_hn6_10_in_memory_consume_or_reject_uses_lock() -> None:
    """HN6-10: InMemoryLLMBudgetStore uses threading.Lock for the
    check-and-set, so two concurrent FastAPI worker threads can't
    each see "count < cap" and each increment past the cap."""
    from iam_jit import llm_budget

    src = inspect.getsource(llm_budget.InMemoryLLMBudgetStore.consume_or_reject)
    assert "with self._lock:" in src

    # Behavioral: thread-stress test.
    store = llm_budget.InMemoryLLMBudgetStore()
    os.environ["IAM_JIT_LLM_BUDGET_PRO"] = "100"
    try:
        successes = {"n": 0}
        succ_lock = threading.Lock()

        def hammer() -> None:
            for _ in range(50):
                if store.consume_or_reject("alice@", "pro"):
                    with succ_lock:
                        successes["n"] += 1

        threads = [threading.Thread(target=hammer) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Total attempts = 8 * 50 = 400; cap = 100; successes
        # should be exactly 100.
        assert successes["n"] == 100
    finally:
        os.environ.pop("IAM_JIT_LLM_BUDGET_PRO", None)
# test_hn6_11_sam_template_llm_budget_table_well_formed and
# test_hn6_12_reserved_concurrency_parameter_defends_aws_account
# were removed on 2026-05-24 — both inspected the hosted SAM
# template (infrastructure/sam/template.yaml) which was deleted
# when the hosted iam-risk-score Lambda was dropped per
# [[no-hosted-saas]] restoration. The LLM-budget atomic-counter
# primitive (llm_budget.py) is still exercised by the surviving
# unit-level checks in tests/llm_budget/.
