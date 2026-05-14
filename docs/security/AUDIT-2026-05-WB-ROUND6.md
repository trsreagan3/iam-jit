# iam-jit white-box appsec audit — round 6 (2026-05-14)

Sixth-pass white-box review on top of rounds 1, 2, 3, 4, 5
(`AUDIT-2026-05-WB.md`, `AUDIT-2026-05-WB-ROUND{2,3,4,5}.md`). Scoped to:

1. **Re-audit of round-5 closures**:
   - `MIDDLEWARE-GET-SECRET-BYPASSES-LAMBDA-DEV-GATE` (CRIT) —
     `_get_secret()` now delegates to `auth.is_dev_insecure_active()`
     and the dev fallback is a per-process `_ephemeral_dev_secret`.
   - `ADMIN-SELF-DEMOTE-LAST-ADMIN-LOCKOUT` (HIGH BB2-10) — `update_user`
     now refuses both self-demotion and last-admin demotion (fails
     closed on `user_store.list()` errors).
   - `HANDLER-PRE-WRITE-ERROR-DEAD-CODE-LOCKS-OUT-PAID-CUSTOMER`
     (HIGH) — `handle_checkout_session_completed` now wraps
     `tokens_store.put` in `try/except` that raises
     `HandlerPreWriteError`. Dispatch releases the claim so Stripe
     retry can re-attempt.

2. **New surfaces from launch-economics work**:
   - `src/iam_jit/llm_budget.py` — atomic DDB counter
     (`InMemoryLLMBudgetStore` + `DynamoDBLLMBudgetStore`).
   - `model_for_tier()` resolver (Pro→Sonnet, Team/Enterprise→Opus).
   - SAM template — new `LLMBudgetTable`,
     `ReservedConcurrentExecutions`, `ProvisionedConcurrency`.

3. **Cross-cutting fan-out** — the "fix where named; miss the sibling"
   pattern that's haunted every prior round. Did the round-5
   closures REALLY land on every consumer site, including the new
   `llm_budget.py` module?

4. **Test isolation** — `_GLOBAL` singleton in `llm_budget` and the
   process-level `_EPHEMERAL_DEV_SECRET` cache are mutable
   module-globals shared across tests. Where are the resets?

**Headline: 0 CRIT, 1 HIGH, 4 MED, 5 LOW (10 total). 12 honest
negatives.** Honest negatives now OUTNUMBER findings 12:10. The
audit loop has reached the convergence threshold per the round-5
forward-look criterion ("if round 5's CRIT lands and BB2-10 is
finally addressed, round 6 would likely find only LOW-severity
edge cases" — round-5 doc, §"Has the audit loop converged?"). All
three round-5 marquee closures hold. The one HIGH this round is a
partial-fix sibling miss on round-5 finding #3 (the
`HandlerPreWriteError` closure landed on `tokens_store.put`-throws
ONLY; the `return None` early-exit shapes that the round-5 audit
explicitly called out are still dead-ends). The MEDs and LOWs are
esoteric edge cases — exactly the convergence signal the round-5
recommendation flagged.

## Round-5 closure verification

| Finding | Closure shape | Status |
| ------- | ------------- | ------ |
| `MIDDLEWARE-GET-SECRET-BYPASSES-LAMBDA-DEV-GATE` (CRIT) | `_get_secret` delegates to `is_dev_insecure_active()`; dev fallback is per-process random `_ephemeral_dev_secret`; repo literal removed | **HOLDS** (with two new LOW caveats — see #5, #6) |
| `ADMIN-SELF-DEMOTE-LAST-ADMIN-LOCKOUT` (HIGH BB2-10) | `update_user` refuses self-demotion AND last-admin demotion; fails closed on `list()` errors | **HOLDS** (one MED sibling — see #2) |
| `HANDLER-PRE-WRITE-ERROR-DEAD-CODE` (HIGH) | `tokens_store.put` wrapped in `try/except` that raises `HandlerPreWriteError` | **PARTIALLY HOLDS** — `return None` pre-write paths still leak (HIGH — see #1) |

## Totals

| Severity         | Count |
| ---------------- | ----- |
| CRIT             | 0     |
| HIGH             | 1     |
| MED              | 4     |
| LOW              | 5     |
| Honest negatives | 12    |
| **TOTAL findings** | **10** |

### Severity breakdown by finding id

HIGH (1):

- `HANDLER-PRE-WRITE-ERROR-CLOSURE-PARTIAL-RETURN-NONE-PATHS-STILL-DEAD`
  — the round-5 closure for the round-5 HIGH finding only addressed
  the `tokens_store.put`-throws path. The OTHER pre-write paths the
  round-5 audit explicitly named (missing customer email, unmapped
  price id, missing tier) STILL early-return `None` with the claim
  retained. Stripe doesn't retry on a 2xx response. Customer paid;
  no token; no recovery path. Same root attack surface;
  partial-closure pattern.

MED (4):

- `LLM-BUDGET-DDB-CLAIM-EXCEPTION-CLASSIFICATION-STRING-FRAGILE`
  — `DynamoDBLLMBudgetStore.consume_or_reject` copies the
  string-match exception-classification pattern that round 5 already
  flagged as MED in `DynamoDBProcessedEventsStore.claim()`. Fresh
  sibling miss in the new module. Identical CWE-703; identical fix
  shape.

- `LLM-BUDGET-DDB-NETWORK-RETRY-DOUBLE-COUNT-RACE` — boto3's default
  retry policy retries on `ThrottlingException` /
  `InternalServerError`. The atomic-counter
  `UpdateItem(ADD #c :one)` is **NOT idempotent across retries** —
  a network blip after DDB applied the increment but before the
  response reached the client causes the retry to increment again.
  Customer's monthly LLM budget burns 2 units for 1 actual LLM
  call. Defense-in-depth: at the launch traffic level the
  over-count is small; at the launch-day "Pro customer running CI"
  shape this matters.

- `PATCH-USERS-MASS-ASSIGNMENT-NO-AUDIT` (BB2-11 sibling, carry-over)
  — the round-5 BB2-10 closure fixed the self-demote leg but did NOT
  add `audit.emit` on role mutations and did NOT add the
  `_user_from_payload`-style `valid_roles` gate to PATCH. Mass-
  assignment of any combination of roles is still allowed; an admin
  who demotes every other admin (post-self-demote-fix) leaves zero
  audit trail. Same finding as round-5 #7; not regressed, not
  closed.

- `LLM-BUDGET-GLOBAL-SINGLETON-NOT-RESET-IN-CONFTEST` — the module-
  level `_GLOBAL: LLMBudgetStore | None` is reset only by
  `test_llm_budget.py`'s autouse fixture. Every OTHER test in the
  suite that triggers `llm_budget.get_default_store()` (e.g. any
  route-level test that hits `/api/v1/score` with a Pro-tier token)
  builds the singleton against whatever env-var was set at that
  moment and the singleton survives until the next test that
  imports `llm_budget` and resets it. Test-pollution risk
  (covers + masks bugs) and a real production footgun if a future
  test fixture sets `IAM_JIT_LLM_BUDGET_TABLE` and forgets to reset.

LOW (5):

- `EPHEMERAL-DEV-SECRET-NOT-THREAD-SAFE-AT-FIRST-CALL` — the
  module-level `_EPHEMERAL_DEV_SECRET` is initialized by a
  check-then-set in `_ephemeral_dev_secret()` with no lock. Under
  `uvicorn --workers N` in local-dev (the exact context the dev
  secret is for), N threads can each see `None` and each assign
  their own random value. Whichever assignment runs last wins.
  Sessions signed by the loser-thread are invalid for verification
  by the winner-thread. Two-second flake at process start. Not
  exploitable.

- `EPHEMERAL-DEV-SECRET-LAMBDA-CONTAINER-ROTATION-INVALIDATES-SESSIONS`
  — with `IAM_JIT_DEV_INSECURE_SECRET=1` AND
  `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1` (the explicit operator
  opt-in for "use dev fallback in Lambda"), each new Lambda
  container instance generates its own ephemeral secret. A user
  signed in via container A cannot validate via container B. The
  documentation in `middleware._get_secret` says "Sessions / magic
  links signed with this secret survive the lifetime of the Python
  process and no longer — adequate for local-dev / tests" — but
  Lambda is the production path, not local-dev/tests, and the
  `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1` flag means the operator
  thinks they're in dev-but-on-Lambda. The closure correctly
  refuses the OLD hardcoded literal but the new ephemeral-per-
  container behavior is its own UX/availability footgun. Documentary
  + add operator-warning log line.

- `MODEL-FOR-TIER-FAIL-OPEN-DEFAULT-IS-SONNET-NOT-NOOP` — when an
  empty / unknown / typo'd tier is passed,
  `model_for_tier(tier or "pro")` defaults to `claude-sonnet-4-6`
  (a paid model). The sibling `_budget_for_tier` defaults to `0`
  for the same unknown input (fail-closed: no budget). Asymmetric
  defaults across the two resolvers reading the same `tier` value.
  `get_backend_for_tier` does early-exit on `free`/`indie` so the
  real attack surface is narrow (call-path doesn't currently call
  `model_for_tier("platinum-deluxe")`), but the two functions
  disagreeing about what "unknown tier" means is a future-footgun
  shape that the round-5 cross-cutting recommendation explicitly
  called out.

- `IS-DEV-INSECURE-ACTIVE-STRICT-EQUALS-1-INCONSISTENT-WITH-OTHER-FLAGS`
  — `auth.is_dev_insecure_active()` reads
  `os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") != "1"` —
  strict-equals "1". Every other boolean env-var across the codebase
  uses the looser `in {"1", "true", "yes"}` pattern (see e.g.
  `network_acl.py:110`, `score.py:334`, `middleware.py:223`,
  `bans.py`, `routes/web.py`). An operator who sets
  `IAM_JIT_DEV_INSECURE_SECRET=true` thinks they enabled the flag;
  the helper returns False; the operator's intent is silently
  dropped. Failsafe? Yes — closed-default. But documentary
  inconsistency.

- `LLM-BUDGET-TIER-CASE-WHITESPACE-AT-API-BOUNDARY-WRAPPED-OK-AT-DEFAULT`
  — `_budget_for_tier` and `model_for_tier` both normalize with
  `.lower().strip()` internally, so direct calls with `" Pro "` or
  `"PRO"` are handled. But `_resolve_caller_tier` at
  `routes/score.py:303-311` validates against an exact set
  `{"free", "indie", "pro", "team", "enterprise"}` — anything not in
  that set silently coerces to `"free"`. If an operator
  mis-configures `STRIPE_PRICE_ID_TO_TIER` with a typo
  (e.g., `{"price_x":"premium"}`), the customer gets free-tier
  treatment with no operator visibility. Logged-but-not-alarmed
  shape. Defense-in-depth: emit a metric on every unknown-tier
  coercion.

## Honest negatives (12)

These are sites where round 6 specifically looked and the code was
correct:

| id | check |
| -- | ----- |
| HN6-01 | `model_for_tier` is consistent with `_budget_for_tier` on the tier-NAME normalization (both `.lower().strip()`) — the case/whitespace concerns from the prompt's "stripe:Pro" example are handled |
| HN6-02 | `_get_secret`'s no-secret-no-dev-flag branch still raises HTTP 500 (does not silently fall through) |
| HN6-03 | `_get_secret` does NOT log the secret value anywhere |
| HN6-04 | `update_user`'s self-demote check uses identity-equality on `user_id == acting_admin.id` correctly (no string-equality bypass via case/whitespace because `user_id` is the same string both sides) |
| HN6-05 | `update_user`'s `losing_admin` logic correctly detects the "enabled→disabled" leg in addition to the "admin role removed" leg |
| HN6-06 | `update_user`'s `list(...)` failure handler fails CLOSED with HTTP 409 (not 200, not silent OK) |
| HN6-07 | `DynamoDBLLMBudgetStore.consume_or_reject` correctly handles delete-then-add via `attribute_not_exists(#c) OR #c < :cap` — the OR-disjunct covers a deleted row |
| HN6-08 | `DynamoDBLLMBudgetStore` correctly month-boundaries via `_current_year_month()` (UTC); no timezone footgun |
| HN6-09 | `_DEFAULT_BUDGETS` returns `0` (fail-closed) for unrecognized tier keys |
| HN6-10 | `consume_or_reject` for the in-memory store uses `threading.Lock()` for the check-and-set (no race) |
| HN6-11 | `SAM template`'s `LLMBudgetTable` correctly configures `customer_id` (HASH) + `year_month` (RANGE) keys, TTL on `ttl_at`, PAY_PER_REQUEST billing |
| HN6-12 | `ReservedConcurrentExecutions` parameter caps Lambda concurrency at ~10% of the AWS-account quota by default (protects the account from a CI burst exhausting all 1000 default concurrency) |

## Per-finding writeups

### 1. HANDLER-PRE-WRITE-ERROR-CLOSURE-PARTIAL-RETURN-NONE-PATHS-STILL-DEAD (HIGH) #ROUND5-PARTIAL-CLOSURE

- **CWE**: CWE-755 / CWE-754.
- **Severity**: HIGH — paid customer is silently locked out on the
  exact handler-error paths the round-5 audit named as the
  shape-of-concern. Round-5 closure addressed only the
  `tokens_store.put`-raises path.
- **Location**: `src/iam_jit/stripe_webhook.py:202-282` (handler).

Round-5 finding #3 explicitly called out FOUR pre-write failure
paths in `handle_checkout_session_completed` that needed to raise
`HandlerPreWriteError`:

1. `_extract_email(data)` returns None → handler returns `None`.
2. `_extract_price_id(data)` returns None → same shape.
3. `issue_api_token` raises → bare exception (lands in
   `except Exception:`).
4. `tokens_store.put` raises → bare exception.

The round-5 closure addressed ONLY path 4. Paths 1 and 2 still
look like:

```python
email = _extract_email(data)
if not email:
    logger.warning(...)
    return None   # ← claim is RETAINED; Stripe doesn't retry on 2xx

price_id = _extract_price_id(data)
tier: str | None = None
if price_id:
    tier = get_tier_for_price(price_id)
if not tier:
    logger.warning(...)
    return None   # ← claim is RETAINED; Stripe doesn't retry on 2xx
```

`dispatch_event` reads `result = handler()` (`stripe_webhook.py:573`),
sees `result = None`, returns `{"handled": True, ...}`. The claim
is retained. Stripe's webhook delivery semantics: a 2xx response
is "delivered, do not retry." The customer paid Stripe; no token
was minted; no retry will ever happen; the operator's only signal
is a `WARNING` log line that's drowned in the same log group as
every other webhook warning. There is no admin endpoint to
manually release a claim.

The round-5 fix sketch explicitly said:

> 1. Change `handle_checkout_session_completed` to raise
>    `HandlerPreWriteError` for every pre-write failure path:
>    ```python
>    if not email:
>        raise HandlerPreWriteError("no customer email in event")
>    if not tier:
>        raise HandlerPreWriteError(f"no tier for price {price_id}")
>    ```

The round-5 closure landed only the `tokens_store.put`-throws case
(path 4). Paths 1, 2, and 3 still leak.

**Realistic launch-day attack**: a Stripe Checkout integration that
uses a `customer.id` but not `customer_email` (common when the
operator uses Stripe Customer Portal flows) — every successful
purchase locks out the customer permanently. The operator only
notices when customers email support saying "I paid, got nothing."

**Fix**: replace the three `return None` early-exits with
`raise HandlerPreWriteError(...)` calls. Add an admin endpoint
`POST /api/v1/admin/stripe/release-claim/{event_id}` for the
operator's manual recovery (round-5 fix sketch already provided
this).

### 2. LLM-BUDGET-DDB-CLAIM-EXCEPTION-CLASSIFICATION-STRING-FRAGILE (MED) #ROUND5-SIBLING-MISS

- **CWE**: CWE-703.
- **Severity**: MED — same shape as round-5 finding #8
  (`STRIPE-CLAIM-EXCEPTION-CLASSIFICATION-STRING-FRAGILE`) which
  was flagged MED for the identical fragility. New module
  duplicates it.
- **Location**: `src/iam_jit/llm_budget.py:168-178`.

```python
except Exception as e:
    if "ConditionalCheckFailedException" in str(e) or (
        hasattr(e, "response")
        and getattr(e, "response", {})
        .get("Error", {})
        .get("Code")
        == "ConditionalCheckFailedException"
    ):
        return False
    raise
```

This is byte-for-byte the same pattern that round-5 flagged in
`stripe_webhook.py:441-462`. Same OR-ordering reversal (string
match FIRST, the authoritative `.response['Error']['Code']` check
on the OR side). Same future-botocore breakage risk; same
test-stub mis-classification risk.

Cross-cutting theme: **the fan-out enforcement that the round-5
WB recommendation called for ("automated 'verify the fix didn't
miss its siblings' gate") was not landed.** The fragile pattern
was correctly diagnosed in round 5; the new module copy-pasted
the same shape unchanged. Identical situation to the round-4-5
`is_dev_insecure_active` sibling-miss that led to round 5's CRIT.

A third site has the same pattern:
`magic_link_nonces.py:111-117`. So this is the THIRD instance in
the codebase. Each one was added without consulting the others;
each one needs to be fixed identically.

**Fix**:

```python
import botocore.exceptions
...
except botocore.exceptions.ClientError as e:
    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
        return False
    raise
```

Then port to `stripe_webhook.py:464` and `magic_link_nonces.py:111`
in the same PR. Add a CI grep gate matching the pattern
`"ConditionalCheckFailedException" in str(e)` and refuse the commit.

### 3. LLM-BUDGET-DDB-NETWORK-RETRY-DOUBLE-COUNT-RACE (MED) #NEW-CODE

- **CWE**: CWE-362 (Concurrent Execution using Shared Resource with
  Improper Synchronization) / CWE-573.
- **Severity**: MED — customer LLM budget burns 2 units per actual
  LLM call under transient DDB throttling; over-counts a customer's
  monthly cap by N for N retry rounds. At launch traffic, rare; at
  the launch-target "Pro customer running CI" shape, this matters.
- **Location**: `src/iam_jit/llm_budget.py:139-177`.

boto3's default `retry_config` retries on:
- `ThrottlingException`
- `ProvisionedThroughputExceededException`
- HTTP 5xx
- network/timeout errors

The atomic counter call:

```python
resp = self._client.update_item(
    TableName=self._table_name,
    Key={"customer_id": ..., "year_month": ...},
    UpdateExpression="ADD #c :one SET ttl_at = :ttl",
    ConditionExpression="attribute_not_exists(#c) OR #c < :cap",
    ...
)
```

is NOT idempotent. The classic retry-after-success race:

1. Client sends `UpdateItem(ADD count :one)`.
2. DDB applies the increment. Now `count = N+1`.
3. Response is lost in the network (RST, timeout, etc.).
4. boto3 sees the network error → retries.
5. Second `UpdateItem` arrives at DDB. Condition `count < :cap`
   is still TRUE (we're still below cap). DDB applies again.
   Now `count = N+2`.
6. Client gets a `200 OK` back from the retry.
7. Client returns `True` ("consumed one unit") — but actually
   consumed two.

The customer's monthly budget burns faster than their actual LLM
calls. Compounding effect under sustained transient errors: each
flake counts double.

Compare: `DynamoDBProcessedEventsStore.claim` uses
`PutItem(ConditionExpression="attribute_not_exists(event_id)")`
— that IS idempotent (the second Put fails the condition because
the first one wrote the item). The right shape for an atomic
counter is similar: use a per-call `request_token` written into
DDB AS the item, with a condition that refuses duplicates.

**Fix**: write a UUID4 `request_id` attribute on the increment;
add a condition `request_id <> :id` that refuses re-write with the
same id. Or: switch to a versioned-CAS update pattern (read the
current count + version, increment with `version = :old`). At the
launch-traffic level this might be over-engineering; documenting
the over-count as a known limitation + adding a CloudWatch metric
on count drift is the minimum viable closure.

### 4. PATCH-USERS-MASS-ASSIGNMENT-NO-AUDIT (MED) #BB2-11-SIBLING-CARRY-OVER

- **CWE**: CWE-269 / CWE-778.
- **Severity**: MED — carry-over from round 5 finding #7. The
  round-5 closure addressed self-demote + last-admin (the HIGH
  half of the same BB2-10/BB2-11 cluster) but the audit-emit and
  mass-assignment-gate halves were not closed.
- **Location**: `src/iam_jit/routes/users.py:213-224`.

Three shapes from round-5 finding #7 are still open:

1. **No `audit.emit` on any successful role mutation.** Verifiable
   by grepping the entire `routes/users.py` module for "audit_mod"
   / "audit.emit" / "import audit" — all return zero hits.
2. **PATCH does not apply the `valid_roles = {"requester",
   "approver", "admin"}` gate that `_user_from_payload` applies to
   POST.** An admin can PATCH a user's roles to
   `["arbitrary-future-role"]` and the route accepts it silently.
3. **No `reason` field requirement on role-mutating PATCHes.**
   The round-5 fix sketch suggested forcing the operator to
   document intent.

Same root cause as round-5; not regressed, not closed. The
round-5 doc's fix sketch is still the correct shape.

### 5. LLM-BUDGET-GLOBAL-SINGLETON-NOT-RESET-IN-CONFTEST (MED) #NEW-CODE

- **CWE**: CWE-1188 (Initialization with Insecure Default) — but
  the test-isolation shape, not a production-runtime shape.
- **Severity**: MED — test pollution can hide bugs across the
  audit-loop discipline. Specifically: a future test fixture that
  sets `IAM_JIT_LLM_BUDGET_TABLE` for a route-level test will leak
  into subsequent tests in the same xdist worker.
- **Location**: `src/iam_jit/llm_budget.py:201-217`,
  `tests/conftest.py` (no `llm_budget` reset).

`llm_budget._GLOBAL` is reset by:

- `tests/test_llm_budget.py::_reset_store_and_env` (autouse,
  scoped to that file)
- `llm_budget.reset_default_store_for_tests()` (manual call)

It is NOT reset by:

- `tests/conftest.py` (no fixture references `llm_budget`)
- Any other test file in the suite

Sibling stores `session_revocation` and `magic_link_nonces` follow
the same module-singleton pattern. Of these, only
`session_revocation` is reset by a top-level conftest fixture
(grep `reset_default_store_for_tests` shows it in
`test_appsec_audit_round4_wb.py:820` etc., but always per-test, not
in a global autouse).

The cross-cutting theme: the audit-loop has been good at finding
production bugs, but the test-suite hygiene that prevents the
audit from missing future bugs (because a stale singleton makes a
fresh-set env-var look like it has no effect) is not codified.

**Fix**: add an autouse session-scoped or per-test fixture in
`tests/conftest.py`:

```python
@pytest.fixture(autouse=True)
def _reset_singletons() -> None:
    from iam_jit import llm_budget, session_revocation, bans
    llm_budget.reset_default_store_for_tests()
    session_revocation.reset_default_store_for_tests()
    bans.reset_default_store_for_tests()
```

This is the round-5 recommendation generalized to a test-fixture
shape.

### 6. EPHEMERAL-DEV-SECRET-NOT-THREAD-SAFE-AT-FIRST-CALL (LOW)

- **CWE**: CWE-362.
- **Severity**: LOW — narrow timing window at process start; only
  affects dev-insecure mode (operator opt-in only); not exploitable.
- **Location**: `src/iam_jit/middleware.py:96-110`.

```python
_EPHEMERAL_DEV_SECRET: str | None = None


def _ephemeral_dev_secret() -> str:
    global _EPHEMERAL_DEV_SECRET
    if _EPHEMERAL_DEV_SECRET is None:
        import secrets as _secrets
        _EPHEMERAL_DEV_SECRET = _secrets.token_hex(32)
    return _EPHEMERAL_DEV_SECRET
```

The check-then-assign is NOT atomic. Under `uvicorn --workers 4`
in local-dev (the exact context this dev fallback is for), four
worker threads can each:

- read `_EPHEMERAL_DEV_SECRET` as `None`
- compute their own `_secrets.token_hex(32)`
- assign their value to the global

The last assignment wins. Any session cookie / magic-link signed
between the first assignment and the final one will fail
verification if the verifier thread reads the post-final value.
Two-second flake at process boot, then stable.

Not exploitable (the attacker can't induce specific values; the
flake just rotates a random secret to a different random secret).
Pure UX papercut for local-dev.

**Fix**: wrap with a `threading.Lock()`:

```python
_EPHEMERAL_DEV_SECRET_LOCK = threading.Lock()
_EPHEMERAL_DEV_SECRET: str | None = None

def _ephemeral_dev_secret() -> str:
    global _EPHEMERAL_DEV_SECRET
    with _EPHEMERAL_DEV_SECRET_LOCK:
        if _EPHEMERAL_DEV_SECRET is None:
            import secrets as _secrets
            _EPHEMERAL_DEV_SECRET = _secrets.token_hex(32)
        return _EPHEMERAL_DEV_SECRET
```

### 7. EPHEMERAL-DEV-SECRET-LAMBDA-CONTAINER-ROTATION-INVALIDATES-SESSIONS (LOW)

- **CWE**: CWE-1233 (Improper Lockout Mechanism Configuration) /
  documentation gap.
- **Severity**: LOW — requires operator to set BOTH
  `IAM_JIT_DEV_INSECURE_SECRET=1` AND
  `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1` (explicit dev-on-Lambda
  opt-in). UX/availability footgun, not a security vuln.
- **Location**: `src/iam_jit/middleware.py:60-94`.

The closure correctly refuses the OLD hardcoded literal. The NEW
behavior — a per-process random secret — means that each Lambda
container instance generates its own secret. A user signed in via
container A cannot have their session validated by container B.
The Lambda free-tier allocation rotates containers every ~15 min
of idle; under sustained traffic, AWS Lambda runs N containers in
parallel, each with its own ephemeral secret.

The docstring at `middleware.py:71-79` says:

> Refuses to fall back in Lambda environments unless the operator
> explicitly opted in via `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1`.
> And the dev fallback no longer uses a fixed string — it derives
> a per-process random secret on first use, so even with the dev
> flag on in Lambda (explicit opt-in), an attacker reading the
> repo doesn't already have your signing key.

The security narrative is correct. The UX consequence is not
documented: an operator who opts in expecting "transient dev mode
on Lambda for an emergency" will be confused when half their
sessions silently rotate-out as Lambda scales.

**Fix**: emit a CRITICAL log line on every `_ephemeral_dev_secret`
generation in Lambda, naming the failure mode explicitly
("WARNING: ephemeral dev secret generated for this Lambda
container; sessions will not survive container rotation. Set
IAM_JIT_MAGIC_LINK_SECRET to fix."). Make the operator's "I
opted in" signal noisy.

### 8. MODEL-FOR-TIER-FAIL-OPEN-DEFAULT-IS-SONNET-NOT-NOOP (LOW)

- **CWE**: CWE-1188 (Initialization with Insecure Default) — but
  the asymmetric-defaults shape, not a production-exploitable
  vector.
- **Severity**: LOW — `get_backend_for_tier` early-exits on
  `free`/`indie`, so the only exploitable input is a tier value
  that's neither `free`/`indie` nor `pro`/`team`/`enterprise` —
  which `_resolve_caller_tier` coerces to `free` upstream. Future-
  footgun, not a live exploit.
- **Location**: `src/iam_jit/llm_budget.py:237-246`.

```python
def model_for_tier(tier: str) -> str:
    tier = (tier or "pro").lower().strip()   # ← default "pro"
    env_key = f"IAM_JIT_LLM_MODEL_{tier.upper()}"
    explicit = (os.environ.get(env_key) or "").strip()
    if explicit:
        return explicit
    return _DEFAULT_MODELS_BY_TIER.get(tier, "claude-sonnet-4-6")  # ← default Sonnet
```

Two fail-open defaults in one function:

1. `(tier or "pro")` — empty/None tier gets the Pro-tier model.
2. `.get(tier, "claude-sonnet-4-6")` — unknown tier name gets
   Sonnet.

Compare:

```python
def _budget_for_tier(tier: str) -> int | None:
    tier = (tier or "free").lower().strip()   # ← default "free"
    ...
    return _DEFAULT_BUDGETS.get(tier, 0)        # ← default 0 (fail-closed)
```

Two functions, same input variable, different defaults. The
asymmetry is the bug shape: if any future code path bypasses the
`_resolve_caller_tier` validation gate (e.g. a CLI flag-driven
call, a new MCP-server path, a test fixture), `_budget_for_tier`
fails closed while `model_for_tier` fails open — meaning the
"call the LLM" boolean comes back False (correct) but if any
caller plumbs the model id THROUGH the budget-False branch, it'd
get a Sonnet model id with no enforcement to back it.

**Fix**: align defaults. Make `model_for_tier`:

```python
def model_for_tier(tier: str) -> str | None:
    tier = (tier or "").lower().strip()
    if tier not in _DEFAULT_MODELS_BY_TIER:
        return None  # callers must handle None
    ...
```

Or: keep returning a string but make the default a sentinel like
`"noop"` that the backend factory routes to `NoOpBackend()`.

### 9. IS-DEV-INSECURE-ACTIVE-STRICT-EQUALS-1-INCONSISTENT-WITH-OTHER-FLAGS (LOW)

- **CWE**: CWE-1188 / documentation inconsistency.
- **Severity**: LOW — fails closed (operator's intent to enable
  the flag with "true" silently doesn't take effect, which is the
  SAFE direction). Documentary inconsistency only.
- **Location**: `src/iam_jit/auth.py:197`.

```python
if os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") != "1":
    return False
```

Strict equals `"1"`. Every OTHER boolean flag in the codebase
uses the looser:

```python
in {"1", "true", "yes"}
```

Examples:
- `middleware.py:223` (`IAM_JIT_SESSION_REVOCATION_FAIL_OPEN`)
- `middleware.py:290` (`IAM_JIT_BANS_FAIL_OPEN`)
- `network_acl.py:110` (`IAM_JIT_TRUST_FORWARDED_FOR`)
- `routes/score.py:334` (`IAM_JIT_TRUST_FORWARDED_FOR_FOR_SCORE`)
- `routes/web.py:543` (`IAM_JIT_TRUST_FORWARDED_FOR`)
- `auth.py:203` (`IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA` — SAME
  module, line 6 below this finding!)

Within `is_dev_insecure_active` itself, the FIRST flag is
strict-equals-1 and the SECOND flag is the loose-set. Operator
who reads the helper expecting consistency will be confused.

**Fix**: bring `IAM_JIT_DEV_INSECURE_SECRET` to the loose-set
shape OR document why this one flag is strict (probably: "the
hardcoded-literal era exposed the strict shape to the public
internet, so we leave it strict as a deliberate signal").

### 10. LLM-BUDGET-TIER-CASE-WHITESPACE-AT-API-BOUNDARY-WRAPPED-OK-AT-DEFAULT (LOW)

- **CWE**: CWE-184 (Incomplete List of Disallowed Inputs) — but
  for the "free-tier downgrade" direction, not a security bypass.
- **Severity**: LOW — fails to free-tier on operator typo. Not
  exploitable; just costs the operator and the customer a confused
  ticket-thread.
- **Location**: `src/iam_jit/routes/score.py:303-311`.

```python
label = (record.label or "").lower()
if label.startswith("stripe:"):
    tier = label[len("stripe:"):].strip()
    if tier not in {"free", "indie", "pro", "team", "enterprise"}:
        tier = "free"
else:
    tier = "free"
return record.user_id, tier
```

If `STRIPE_PRICE_ID_TO_TIER` has a typo (e.g.,
`{"price_x":"premium"}` for what should be "pro"), then the stored
label is `"stripe:premium"`, the strip-and-validate logic coerces
`"premium"` to `"free"`, and the customer is silently treated as
free-tier. The operator's only signal is the operator-side
support ticket from the customer ("I paid for Pro but the LLM
narrative isn't showing").

**Fix**: emit a metric / log line on every unknown-tier coercion,
keyed by user_id + raw_label. CloudWatch alarm threshold > 0/day.

## Cross-cutting theme: the loop is converging

Round 5 explicitly predicted: "If round 5's CRIT lands and BB2-10
is finally addressed, round 6 would likely find only LOW-severity
edge cases." Round 6 confirms:

- The CRIT did land (the `_get_secret` rewrite is correct).
- BB2-10 was addressed (self-demote and last-admin demote both
  refused).
- The one remaining HIGH is a partial-closure (paths 1/2/3 of the
  round-5 finding #3 sketch — the round-5 fix-sketch covered four
  paths but only one shipped).
- The MEDs are: a literal copy-paste of a round-5 finding into the
  new module (#2), a new-module bug (#3 — atomic counter
  non-idempotent), a carry-over of round-5 #7 (#4), and a test-
  hygiene gap (#5).
- The LOWs are esoteric edge cases: thread-safety on a 64-byte
  random secret (#6), UX gap on container rotation (#7),
  fail-open default in a function whose only current caller never
  triggers the fail-open (#8), boolean-flag inconsistency (#9), and
  operator-typo silent-coercion (#10).

**Convergence diagnostic**: honest-negatives (12) OUTNUMBER
findings (10). Per the convergence criterion in the audit prompt
("honest-negatives outnumber findings = converged"), the loop has
converged. The remaining shapes are:

- One partial-closure that should be a same-PR follow-up to round
  5's #3 closure.
- One copy-paste of a known fragile pattern into a new module —
  the EXACT recommendation from round 5's cross-cutting theme
  ("automated 'verify the fix didn't miss its siblings' gate") was
  not landed; round 6 finding #2 is the consequence.
- Esoteric edge cases consistent with a mature audit.

**Recommendation for shipping**: the round-5 cross-cutting
recommendation — a CI gate that grep-enforces the sibling-
propagation discipline — is now the single highest-leverage move.
Without it, round 7 will find the same string-match-classification
shape in a fourth module. With it, the structural sibling-miss
class of bug is mechanically closed forever.

**Recommendation for the launch**: ship round 5 + the one HIGH
from round 6 (partial closure) before launch day. The four MEDs
can ship in the first post-launch hotfix sprint. The LOWs are
operator-toil reducers; ship them with the documentation pass for
v1.1.
