# iam-jit white-box appsec audit — round 5 (2026-05-14)

Fifth-pass white-box review on top of rounds 1, 2, 3, and 4
(`AUDIT-2026-05-WB.md`, `AUDIT-2026-05-WB-ROUND{2,3,4}.md`). Scoped to:

1. **Re-audit of round-4 closures** — `STRIPE-DDB-PROCESSED-EVENTS-UNWIRED`
   (DDB-backed `ProcessedEventsStore` shipped),
   `SESSION-REVOCATION-FAIL-OPEN-SILENT-BYPASS` (CRITICAL log line
   landed), `WEB-LOGIN-CLIENT-IP-INLINE-CIDR-PARSER` (5/5 XFF call
   sites unified on `trusted_proxy`), `DEV-INSECURE-LAMBDA-GATE-…`
   (`is_dev_insecure_active()` helper, 4 call sites delegated),
   `PER-USER-MINT-LOCKS-DEFAULTDICT-RACE-AND-LEAK` (`dict.setdefault`
   replaced `defaultdict`), `STRIPE-RELEASE-RACE-DOUBLE-MINT-…`
   (`HandlerPreWriteError` introduced; release on narrowly-typed
   exception only).
2. **New surfaces introduced by the round-4 env vars** —
   `IAM_JIT_PROCESSED_EVENTS_TABLE` (now wired),
   `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA` (Lambda-gate opt-in).
3. **Cross-cutting fix-fan-out** — every round-4 helper-extraction
   verified at every consumer. Specifically `is_dev_insecure_active()`
   — did the closure REALLY land on every site that consults the
   dev flag, or only the four named ones?
4. **New classes** — admin endpoints (CIDR mgmt + user mgmt) for
   IDOR, mass-assignment, role-self-demotion (BB2-10 still OPEN per
   round-3 status). Header injection, pickle/SSRF/file-traversal — all
   probed and clean.

**Headline: 1 CRIT, 2 HIGH, 5 MED, 4 LOW (12 total).** All
findings assert behavior at HEAD (commit `cb6a1d8`). The working
tree at audit time has uncommitted edits to `middleware.py` that
appear to be an in-flight closure of the CRIT finding (#1); the
audit test pins the HEAD-vulnerable shape regardless, so the test
will correctly fail once the in-flight fix lands — that's the
test-flip signal per round-1..4 conventions. Note this for the PR
reviewer.

The CRIT is
**the round-4 closure for the dev-insecure flag MISSED `_get_secret()`
in middleware.py:59**: with `IAM_JIT_DEV_INSECURE_SECRET=1` set in
Lambda but `IAM_JIT_MAGIC_LINK_SECRET` unset (the .env.example bleed
scenario the round-4 audit explicitly modeled), the code falls back
to a hard-coded, **publicly visible** dev secret —
`"dev-only-insecure-secret-do-not-use-in-prod"` (`middleware.py:65`).
This secret is checked into the repo, GitHub-indexed, and is the
single piece of bytes that signs every magic-link token and session
cookie. An attacker with that secret can forge a magic-link for any
email, sign a session cookie as any user, mint API tokens — full
account takeover with no other prerequisites. The round-4
`is_dev_insecure_active()` helper landed on CSRF, cookie-Secure, and
magic-link DELIVERY — but the actual cryptographic-secret leg was
overlooked. This is exactly the "fix where named, miss the siblings"
pattern that's haunted every prior round.

The two HIGHs are:

- **`BB2-10` admin role-self-demotion** — flagged MED in round 2,
  marked "OPEN (out of scope for round 3)" in round-3 BB, never
  addressed in round 4 even though the launch is days away. The
  `PATCH /api/v1/users/{user_id}` route accepts `roles=["requester"]`
  for the actor's OWN id with no last-admin protection, no audit
  emission, no two-eyes step. A single CSRF click (or just an
  admin's lapse) can transition the deployment to a no-admin state
  that requires data-plane intervention to recover.
- **`HANDLER-PRE-WRITE-ERROR-DEAD-CODE-LOCKS-OUT-PAID-CUSTOMER`** —
  the round-4 `HandlerPreWriteError` mechanism was added BUT no
  handler ever actually raises it. Today, ANY exception inside
  `handle_checkout_session_completed` (including pre-write failures
  like a bad price-id, missing email, or a DDB throttle on the
  initial `_extract_email` path) lands in the `except Exception:`
  branch which DOES NOT release. The customer who paid Stripe is
  now locked out: claim is durable in DDB, retries see "duplicate",
  no token is ever minted. The audit doc says "operator manually
  releases" — but there's no admin endpoint to release a claim,
  and the operator has no signal that they need to (logs are
  `.exception()` mixed in with normal errors).

The MEDs cluster around the same recurring patterns:

- **Bootstrap auto-seed leftmost-XFF still open** — round-4 MED
  `BOOTSTRAP-AUTOSEED-XFF-LEFTMOST` carried forward unchanged.
- **Auth-PII Cache-Control middleware skips web routes** — the new
  `_enforce_auth_cache_control` only covers `/api/v1/*` and
  `/admin/*`, missing every auth'd HTML route that renders
  per-user PII (`/queue`, `/all`, `/tokens`, `/requests/{id}`,
  `/accounts`, even `/auth/magic-callback` which sets the session
  cookie).
- **`POST /api/v1/admin/network/cidrs` accepts `0.0.0.0/0`** — no
  wildcard CIDR rejection on either the API or the form-POST sibling.
  The "refuse last-CIDR removal" guard doesn't help: an admin who
  ADDS `0.0.0.0/0` first, then DELETES the legitimate CIDR, ends up
  with `0/0` as the only entry — equivalent to no enforcement.
- **`PATCH /api/v1/users/{user_id}` mass-assignment + no audit
  emission** — the BB2-11 sibling of BB2-10. Same root cause; same
  fix shape (audit emission on every role change + last-admin
  guard).
- **`DynamoDBProcessedEventsStore.claim()` exception classification
  is string-match fragile** — uses `"ConditionalCheckFailedException"
  in str(e)` as the FIRST check, only falls back to the proper
  `response['Error']['Code']` check on the OR side. For botocore's
  real `ClientError` both paths work; for any wrapper / stub /
  alternative SDK version, the string match could mis-classify a
  non-DDB error as a duplicate-claim, silently dropping events.

LOWs are now esoteric:

- **`DynamoDBProcessedEventsStore.release()` re-raises DDB errors**
  back to `dispatch_event` — the existing `try/except` in the
  PreWrite-error branch swallows it (correct), but no
  defense-in-depth path covers the case where `release()` is
  called from external test code or a future code path.
- **`DynamoDBSessionRevocationStore` lacks an `expires_at`
  check at the membership step** — if DDB returns a stale item
  whose TTL has lapsed but DDB hasn't reaped, the check still
  works (line 120-121), but the `int()` conversion can raise on
  malformed data; the bare `except (KeyError, ValueError): return
  False` is fail-OPEN for revocation.
- **`bans.is_banned` raise behavior at `magic_callback`** — round 4
  flagged the same shape at `routes/auth.py:192`. The web
  `magic_callback` at `routes/web.py:498` has a bare `try/except
  Exception: pass`, which **swallows** the corrupt-file raise and
  proceeds to issue the session cookie. So a banned user with a
  corrupt ban file can SIGN IN. This is the opposite shape from
  round 4's MED (registration oracle); same root cause (call site
  doesn't follow middleware's fail-closed pattern).
- **`is_dev_insecure_active()` is dynamic but `app.py` imports
  `is_dev_insecure_active` once at request time inside the middleware
  closure** — fine in practice, but if a future refactor caches it
  module-globally (e.g. as a `IS_DEV_INSECURE = is_dev_insecure_active()`
  constant), the test fixtures that mutate env vars per-test would
  silently miss the change. Documentary, not exploitable.

## Totals

| Severity  | Count  |
| --------- | ------ |
| CRIT      | 1      |
| HIGH      | 2      |
| MED       | 5      |
| LOW       | 4      |
| **TOTAL** | **12** |

### Severity breakdown by finding id

CRIT (1):

- `MIDDLEWARE-GET-SECRET-BYPASSES-LAMBDA-DEV-GATE` — the round-4
  closure for `DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN` extracted
  `auth.is_dev_insecure_active()` and routed CSRF, cookie-Secure, and
  magic-link delivery through it. The **fourth leg — the actual
  cryptographic secret fallback in `middleware._get_secret()` at
  line 59-70 — was missed.** With `IAM_JIT_DEV_INSECURE_SECRET=1`
  in Lambda and `IAM_JIT_MAGIC_LINK_SECRET` unset, the function
  returns the hard-coded literal
  `"dev-only-insecure-secret-do-not-use-in-prod"`. That secret signs
  every magic-link token (`auth_mod.sign_magic_link(_get_secret(),
  user_id)`, `routes/auth.py:202`, `routes/web.py:307`) and every
  session cookie (`auth_mod.sign_session(_get_secret(), user_id)`,
  `routes/auth.py:245`, `routes/web.py:449`, `web.py:510`). The
  secret is checked into the repo and GitHub-indexed. An attacker
  with public-internet knowledge can forge a magic link for
  `email:admin@<target-domain>`, redeem it, and complete a full
  account takeover. Location: `src/iam_jit/middleware.py:59-70`.

HIGH (2):

- `ADMIN-SELF-DEMOTE-LAST-ADMIN-LOCKOUT` (BB2-10 re-raised) — the
  `PATCH /api/v1/users/{user_id}` route (`routes/users.py:132-159`)
  accepts a `roles` field that can drop the actor's `admin` role
  with no protection. There is no last-admin check, no audit
  emission, no two-eyes step. Flagged MED in round-2; "OPEN, out of
  scope for round 3" in round-3 BB; not touched in round 4. Launch
  is days away. Compounds with the still-broken CSRF surface on
  HTML form-post routes — a single CSRF click can transition the
  deployment to a no-admin state. Recovery requires data-plane
  intervention (manual DDB edit or `IAM_JIT_ADMIN_BOOTSTRAP_EMAIL`
  redeploy). Location: `src/iam_jit/routes/users.py:132-159`.

- `HANDLER-PRE-WRITE-ERROR-DEAD-CODE-LOCKS-OUT-PAID-CUSTOMER` —
  round-4 `STRIPE-RELEASE-RACE-DOUBLE-MINT-ON-PARTIAL-FAILURE`
  closure introduced `HandlerPreWriteError` and changed
  `dispatch_event` to release the claim ONLY on that narrowly-typed
  exception. The intent was conservative: better lose a retry than
  double-mint. The bug is that **no handler ever raises
  `HandlerPreWriteError`** — `handle_checkout_session_completed`
  raises bare exceptions for missing email, unmapped price id, DDB
  throttle on the initial extract, mailer init failure, etc. ALL of
  these now leave the claim INTACT permanently. Stripe retries see
  "duplicate", no token is minted, the paid customer is silently
  locked out. There's no admin endpoint to manually release a claim,
  and the operator's only signal is a mixed-severity `.exception()`
  log line. Location: `src/iam_jit/stripe_webhook.py:202-282,
  561-592`.

MED (5):

- `WEB-AUTH-CACHE-CONTROL-MIDDLEWARE-SKIPS-PII-WEB-ROUTES` — the
  round-4 `_enforce_auth_cache_control` middleware only sets
  `Cache-Control: no-store, private` on `/api/v1/*` and `/admin/*`.
  It misses every auth'd HTML route that renders per-user PII:
  `/queue`, `/all` (cross-user!), `/tokens` (token labels +
  metadata), `/requests/{id}`, `/accounts`, and critically
  `/auth/magic-callback` (sets the session cookie via redirect — a
  shared-browser scenario can cache the redirect response). A
  corporate-proxy / browser-bfcache leak between users on the same
  device remains for these routes. Location:
  `src/iam_jit/app.py:371-396`.

- `BOOTSTRAP-AUTOSEED-XFF-LEFTMOST-STILL-OPEN` — carried over from
  round-4 MED `BOOTSTRAP-AUTOSEED-XFF-LEFTMOST` unchanged. Bootstrap
  admin's runtime CIDR allowlist seeded from leftmost XFF token
  with no trusted-proxy gate; round-4 doc had the fix sketch but
  no closure shipped. Location: `src/iam_jit/routes/web.py:512-562`.

- `ADMIN-CIDR-ALLOWLIST-ACCEPTS-WILDCARD-0000-0` — the API and
  form-POST routes for adding CIDRs (`/api/v1/admin/network/cidrs`,
  `/admin/network/cidrs`) accept ANY valid CIDR, including
  `0.0.0.0/0` and `::/0`. Combined with the "refuse last-CIDR
  removal" check (which only inspects the CIDR being deleted, not
  the surviving entries), an admin who ADDS `0/0` then DELETES the
  legitimate office CIDR ends up with `0/0` as the only entry —
  enforcement effectively off, but the UI shows "1 CIDR
  configured" (looks healthy). No "you're about to make this
  internet-open" warning. Location:
  `src/iam_jit/routes/admin.py:311-356`,
  `src/iam_jit/routes/web.py:1833-1874`.

- `PATCH-USERS-MASS-ASSIGNMENT-NO-AUDIT` (BB2-11 sibling) — the
  same `PATCH /api/v1/users/{user_id}` route that allows
  self-demote (BB2-10) also allows an admin to demote every OTHER
  admin in a tight loop. No rate limit, no audit-emit on role
  change, no email-to-demoted-admin. Allows privilege concentration
  (sole-admin attack) and silent demotion of the original team
  bench. Location: `src/iam_jit/routes/users.py:132-159`.

- `STRIPE-CLAIM-EXCEPTION-CLASSIFICATION-STRING-FRAGILE` —
  `DynamoDBProcessedEventsStore.claim()` (`stripe_webhook.py:441-462`)
  classifies "this was a duplicate" via
  `"ConditionalCheckFailedException" in str(e)` FIRST, with the
  proper `response['Error']['Code']` check as the OR branch. For
  botocore's `ClientError`, both work; for any custom-wrapped
  exception (e.g. an inner exception whose `__str__` doesn't include
  the code string, but whose `response.Error.Code` does), the first
  branch fails and falls into the second. For an unrelated exception
  whose string HAPPENS to contain the substring (e.g. a `RuntimeError`
  message mentioning the code by accident, or a test stub), the
  first branch returns False = treat as duplicate, and the event is
  silently dropped. Defense-in-depth shape; not currently
  exploitable. Location: `src/iam_jit/stripe_webhook.py:441-462`.

LOW (4):

- `STRIPE-DDB-RELEASE-RAISES-NOT-LOGGED-AT-API-CALLER` —
  `DynamoDBProcessedEventsStore.release()` does NOT catch exceptions
  from `DeleteItem`. In `dispatch_event`'s
  `except HandlerPreWriteError:` branch this is wrapped in try/except
  (correct). But any other caller (test code, future admin endpoint
  to release a stuck claim) gets a bare boto3 exception. The
  in-memory sibling does `pop(event_id, None)` — never raises.
  Asymmetric error contract. Location:
  `src/iam_jit/stripe_webhook.py:464-468`.

- `DDB-SESSION-REVOCATION-MALFORMED-EXPIRES-AT-FAIL-OPEN` —
  `DynamoDBSessionRevocationStore.is_revoked` catches
  `KeyError | ValueError` from `int(item["expires_at"]["N"])` and
  returns False (= not revoked). If a malicious or malformed write
  ever lands in the table (operator running a manual DDB edit, a
  test fixture leaking through, a migration script with the wrong
  attribute type), the entry effectively becomes a free pass —
  unrevocable for the cookie until manual DDB cleanup. Fail-open is
  the wrong default for revocation. Location:
  `src/iam_jit/session_revocation.py:115-122`.

- `WEB-MAGIC-CALLBACK-BANNED-USER-SIGN-IN-ON-CORRUPT-FILE` — round
  4's `BANS-IS-BANNED-RAISES-AT-MAGIC-LINK-ISSUANCE-…` flagged the
  registration-oracle shape at `routes/auth.py:192`. The
  `magic_callback` at `routes/web.py:497-508` has a bare
  `try/except Exception: pass` around `is_banned`, which **swallows**
  the corrupt-file raise and proceeds to issue a session cookie.
  Same root cause (call site doesn't match middleware's
  fail-closed pattern); opposite outcome — a banned user with a
  corrupt ban file can SIGN IN. Narrow exploit window; LOW only
  because it requires a pre-existing corrupt file. Location:
  `src/iam_jit/routes/web.py:497-508`.

- `IS-DEV-INSECURE-ACTIVE-NOT-CACHED-FUTURE-FOOTGUN` — the helper
  is correctly re-evaluated per call, but every consumer reads it
  inside the request path (no startup-time cache). A future
  refactor that caches it at module-import or in `app.state` would
  silently invalidate the four current call sites — test fixtures
  that mutate env per-test would miss the cached value. Documentary
  caveat only. Location: `src/iam_jit/auth.py:180-205`.

## Per-finding writeups

### 1. MIDDLEWARE-GET-SECRET-BYPASSES-LAMBDA-DEV-GATE (CRIT) #ROUND4-REGRESSION

- **CWE**: CWE-798 (Use of Hard-coded Credentials) /
  CWE-1188 (Initialization with Insecure Default) / CWE-321 (Use
  of Hard-coded Cryptographic Key).
- **Severity**: CRIT — public-internet attacker forges magic-link
  tokens for any email, signs session cookies as any user, completes
  full account takeover.
- **Location**: `src/iam_jit/middleware.py:59-70`.

```python
def _get_secret() -> str:
    secret = os.environ.get("IAM_JIT_MAGIC_LINK_SECRET")
    if not secret:
        # Allow local-dev fallback ONLY if the dev override flag is set;
        # production must always have the real secret configured.
        if os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") == "1":
            return "dev-only-insecure-secret-do-not-use-in-prod"
        raise HTTPException(...)
    return secret
```

The round-4 closure for `DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN`
extracted `auth.is_dev_insecure_active()` as the single source of
truth for the dev flag. It correctly threaded that helper through:

- `app.py:230-233` (CSRF middleware bypass)
- `routes/auth.py:252` (`secure=` on the session cookie)
- `routes/web.py:455, 569` (the two web cookie-set sites)
- `magic_link_delivery.py:82-87` (delivery channel)

**It did NOT thread the helper through `middleware._get_secret`.**
That function is consulted by:

- `middleware.py:142` (session-cookie verify on every authenticated
  request)
- `routes/auth.py:202` (sign the magic-link token)
- `routes/auth.py:225` (verify the magic-link token at callback)
- `routes/auth.py:245` (sign the new session cookie after callback)
- `routes/web.py:103` (verify session cookie in web flow)
- `routes/web.py:307` (sign magic-link via the web /login form)
- `routes/web.py:449` (sign cookie after web sign-in)
- `routes/web.py:477` (verify magic-link at the web /auth/magic-callback)
- `routes/web.py:510` (sign cookie at magic-callback)
- `routes/web.py:1253, 1267, 1300` (sign/verify intake state)

All thirteen call sites are signing or verifying with whichever
secret `_get_secret()` returns. In a deployment where
`IAM_JIT_DEV_INSECURE_SECRET=1` is set (the .env.example bleed
scenario the round-4 audit explicitly modeled — `.env.example` ships
with this set; an operator who copies it to `.env` and forgets gets
it in prod) AND `IAM_JIT_MAGIC_LINK_SECRET` is unset (no value
configured), the returned secret is the literal
`"dev-only-insecure-secret-do-not-use-in-prod"`. That value is
present in the repo at `middleware.py:65`, on GitHub, in every
downstream fork, in every dependency-mirror cache.

**Attack chain:**

1. Attacker GETs the deployment URL (any Lambda Function URL or
   CloudFront distribution serving iam-jit).
2. `iam-jit` security-posture page (`/healthz`) returns an issue
   `magic_link_secret_unset` — public info confirms the
   posture (`security_posture.py:150-165`).
3. Attacker constructs a magic-link token via stdlib:
   ```python
   from itsdangerous import URLSafeTimedSerializer
   s = URLSafeTimedSerializer("dev-only-insecure-secret-do-not-use-in-prod", salt="iam-jit-magic-link")
   tok = s.dumps("email:admin@<target-domain>")
   ```
4. Attacker visits `<deployment>/auth/magic-callback?token=<tok>`.
5. `verify_magic_link` succeeds; `consume_or_reject` records the
   token (one-shot is OK for an attacker — they only need one
   shot). Session cookie is set as `email:admin@<target-domain>`.
6. If that email matches a configured admin (or matches the
   `IAM_JIT_ADMIN_BOOTSTRAP_EMAIL`, or matches any seeded user with
   admin role), the attacker now has admin browser access.
7. Even if no admin email is known, the attacker forges a
   `email:any-existing-user@<target>` from the user store
   (enumerable via `/api/v1/auth/magic-link` 202-uniform response
   doesn't leak but a stuffing attack via the admin
   `GET /api/v1/users` endpoint after step 6 trivially completes).

The Lambda gate that round-4 added to the four other legs of the
dev flag (`IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1` opt-in)
**explicitly does NOT cover this leg.** A prod operator who
intentionally set `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1` (the
round-4 round-trip flag) for some other reason would get the same
hardcoded-secret behavior.

**Trigger conditions (BOTH required):**

- `IAM_JIT_DEV_INSECURE_SECRET=1` is set in the Lambda env.
- `IAM_JIT_MAGIC_LINK_SECRET` is unset / empty.

The first condition is the same .env.example-bleed shape the round-4
audit explicitly modeled. The second is the documented "you need to
set this for prod" — but it's documented in a different env-var
group (the deploy guide), and the `security_posture` warning on
`/healthz` only surfaces it as an informational issue, NOT a
deploy-blocker.

**Fix sketch:**

```python
def _get_secret() -> str:
    secret = os.environ.get("IAM_JIT_MAGIC_LINK_SECRET")
    if secret:
        return secret
    # Dev fallback — only when dev mode is active per the SoT helper.
    # In Lambda, this requires both IAM_JIT_DEV_INSECURE_SECRET=1
    # AND IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1.
    from .auth import is_dev_insecure_active
    if is_dev_insecure_active():
        return "dev-only-insecure-secret-do-not-use-in-prod"
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="IAM_JIT_MAGIC_LINK_SECRET is not configured",
    )
```

Better: **refuse module import** when `AWS_LAMBDA_FUNCTION_NAME` is
set and `IAM_JIT_MAGIC_LINK_SECRET` is unset, regardless of
`IAM_JIT_DEV_INSECURE_SECRET`. A signed-secret fallback to a
public-domain literal has no defensible production use case.

### 2. ADMIN-SELF-DEMOTE-LAST-ADMIN-LOCKOUT (HIGH) #BB2-10-RE-RAISED

- **CWE**: CWE-269 (Improper Privilege Management) /
  CWE-840 (Business Logic Errors).
- **Severity**: HIGH — single CSRF-able action transitions the
  deployment to a no-admin state requiring data-plane recovery.
- **Location**: `src/iam_jit/routes/users.py:132-159`.

The `PATCH /api/v1/users/{user_id}` route accepts a `roles` field
that can drop the actor's `admin` role with NO last-admin
protection, NO audit emission, and NO two-eyes step.

```python
@router.patch("/{user_id}")
def update_user(...)
    ...
    roles = payload.get("roles")
    ...
    updated = User(
        id=existing.id,
        roles=tuple(roles) if roles is not None else existing.roles,
        ...
    )
    try:
        user_store.put(updated)
    except StoreReadOnly as e:
        raise HTTPException(status_code=409, detail=str(e))
    return _serialize(updated)
```

Round-2 BB2-10 flagged this MED, round-3 BB marked it "OPEN, out of
scope", round 4 didn't touch it. Launch is days away. The
`/api/v1/admin/bans/{user_id}/unban` endpoint refuses self-unban
("you cannot unban yourself; another admin must lift this ban") —
that's the right shape, but it's not applied here.

**Realistic attack:** an admin browser visits an attacker-controlled
page. Since the CSRF middleware exempts `Bearer` auth and the
admin's auth is cookie-based, the page form-POSTs to
`/api/v1/users/email:admin@<target>` with
`{"roles": ["requester"]}`. The CSRF Origin/Referer check at
`app.py:255-300` SHOULD catch this (attacker page Origin != target
host) — BUT the round-1 BB findings on CSRF were on HTML form-POST
routes, not the JSON API. The Origin check is enforced for the JSON
API in round 1 closure. So the JSON-API attack requires a CORS
bypass (none today).

A direct shape that's not CSRF-dependent: an admin SIMPLY
PATCHes their own user from a legitimate admin console session by
mistake, or follows confusing UI prompts. Recovery requires:

- `IAM_JIT_ADMIN_BOOTSTRAP_EMAIL` is set AND the bootstrap user
  doesn't already exist (it usually does after first sign-in —
  the bootstrap is single-shot). In practice, the recovery path
  is "redeploy with the bootstrap env-var set, manually delete
  the bootstrap user record from DynamoDB."
- Or: manual DDB edit on the iam-jit-users table to restore the
  admin role.

Both options are launch-day-painful and require root AWS access.
There is no in-product recovery primitive.

**Fix sketch:** in `update_user`, refuse the PATCH if:

```python
if user_id == actor.id and "admin" in existing.roles and "admin" not in (roles or existing.roles):
    raise HTTPException(403, "another admin must demote you")
admin_count = sum(1 for u in user_store.list() if u.is_admin and u.enabled)
if admin_count == 1 and "admin" not in (roles or existing.roles) and existing.is_admin:
    raise HTTPException(409, "cannot demote the last remaining admin")
```

Plus emit `security.role_changed` on every successful PATCH with the
before/after roles diff and actor id — closes BB2-11 simultaneously.

### 3. HANDLER-PRE-WRITE-ERROR-DEAD-CODE-LOCKS-OUT-PAID-CUSTOMER (HIGH) #ROUND4-REGRESSION

- **CWE**: CWE-755 (Improper Handling of Exceptional Conditions)
  / CWE-754 (Improper Check for Unusual or Exceptional Conditions).
- **Severity**: HIGH — a customer who paid Stripe is silently
  locked out of the product because the round-4 idempotency closure
  refuses to release a claim on any non-`HandlerPreWriteError`
  failure, and no handler ever raises that class.
- **Location**: `src/iam_jit/stripe_webhook.py:561-592` (dispatch),
  `src/iam_jit/stripe_webhook.py:202-282` (handler).

The round-4 closure introduced `HandlerPreWriteError`:

```python
class HandlerPreWriteError(Exception):
    """Raised by a handler BEFORE it commits any durable side
    effect ... `dispatch_event` catches this specific class and
    releases the claim so a retry can re-run the handler.

    Any OTHER exception bubbles up with the claim INTACT — Stripe
    retries will short-circuit as duplicate. Operator must verify
    no side effect committed and release the claim manually if a
    retry is desired."""
```

And the dispatch logic:

```python
try:
    result = handler()
except HandlerPreWriteError:
    if processed_events_store is not None and event_id:
        try:
            processed_events_store.release(event_id)
            ...
        except Exception:
            ...
    raise
except Exception:
    # Do NOT release — the side effect may have committed.
    logger.exception(...)
    raise
```

The conservative intent is correct: better lose a retry than
double-mint. The bug: **`handle_checkout_session_completed` never
raises `HandlerPreWriteError`** for any pre-write failure. It
raises bare exceptions, returns None for soft-failures, and
relies on the caller's catch-all. Examples of pre-write failures
that today land in `except Exception:` and lock out the customer:

1. `_extract_email(data)` returns None → handler returns `None`,
   no token minted, no claim release. The customer paid, gets no
   token, Stripe retries, retry sees duplicate, no recovery.
   (`stripe_webhook.py:228-234`)
2. `_extract_price_id(data)` returns None → same shape.
   (`stripe_webhook.py:236-246`)
3. `issue_api_token(user_id=email, ...)` raises (e.g., the
   `secrets.token_urlsafe` failed, or the email contains a null
   byte that breaks the HMAC) → bare exception. Pre-write
   (handler hasn't called `tokens_store.put` yet). But it lands in
   `except Exception:`. (`stripe_webhook.py:248`)
4. `tokens_store.put(record)` raises BEFORE the DDB write
   committed (e.g., `ValidationException` because the record
   shape changed) → bare exception. Definitely pre-write. Lands
   in `except Exception:`. (`stripe_webhook.py:255`)

For cases 1 and 2 (the `return None` shape), the handler just
returns and `dispatch_event` sees `result = None`, returns
`{"handled": True, ...}` — the claim is RETAINED but no error
visibility. Stripe DOESN'T retry on 2xx; the customer is silently
charged-no-product.

For cases 3 and 4, the handler raises, hits `except Exception:`,
claim retained, customer is silently charged-no-product on retry
(retries see duplicate).

**There is no admin endpoint to release a claim.** The operator's
only signal is a `.exception()` log line buried in the same log
group as every other error.

**Fix sketch:**

1. Change `handle_checkout_session_completed` to raise
   `HandlerPreWriteError` for every pre-write failure path:
   ```python
   if not email:
       raise HandlerPreWriteError("no customer email in event")
   if not tier:
       raise HandlerPreWriteError(f"no tier for price {price_id}")
   ```
2. Wrap the write in a try/except:
   ```python
   try:
       tokens_store.put(record)
   except Exception as e:
       # If put committed before raising, we don't know. But the
       # idempotency claim is durable; better to surface the error
       # loudly than to silently retain the claim.
       raise  # falls through to except Exception in dispatch
   ```
3. Add `POST /api/v1/admin/stripe/release-claim/{event_id}` as an
   explicit operator-tool: paste the event_id from CloudWatch, the
   endpoint calls `processed_events_store.release(event_id)`, the
   audit log records the actor and reason.

### 4. WEB-AUTH-CACHE-CONTROL-MIDDLEWARE-SKIPS-PII-WEB-ROUTES (MED)

- **CWE**: CWE-525 (Use of Web Browser Cache Containing Sensitive
  Information) / CWE-919.
- **Severity**: MED — per-user PII leaks through browser bfcache /
  corporate-proxy cache between users on the same device, despite
  the headline round-4 closure.
- **Location**: `src/iam_jit/app.py:371-396`.

The round-4 closure for `BB4-02` adds
`Cache-Control: no-store, private` only when:

```python
if path.startswith("/api/v1/") or path.startswith("/admin"):
    response.headers["Cache-Control"] = "no-store, private"
```

Missing categories (all auth'd, all render per-user PII in HTML):

- `/queue` — lists requests with owner identities
  (`routes/web.py:640`)
- `/all` — admin view of ALL users' requests
  (`routes/web.py:666`)
- `/tokens` — token labels + metadata + raw-token-on-creation
  (`routes/web.py:1661, 1679`)
- `/requests/{id}` — request body + comments + history
  (`routes/web.py:1537`)
- `/accounts` — account list + alias mapping
  (`routes/web.py:2007`)
- `/auth/magic-callback` — sets the session cookie via redirect;
  the redirect response itself can be cached. `Set-Cookie` headers
  on a 303 redirect ARE cacheable per RFC 7234 unless explicitly
  no-stored. (`routes/web.py:472`)

Of these, `/auth/magic-callback` is the worst — a shared-browser
"sign in" pattern (kiosk, family device) lets user B's browser
back-button into user A's just-completed sign-in redirect, picking
up the session cookie. Pulls together with the round-4
SESSION-REVOCATION-IS-PER-COOKIE-VALUE-NOT-PER-USER MED
(per-cookie-value revocation means user A's logout doesn't revoke
the cookie user B now has).

**Fix sketch:** broaden the path predicate to cover all auth'd web
routes. Easiest: just exclude the explicit public set
(`/`, `/login`, `/static`, `/healthz`, `/docs`, etc.) and apply
the header to everything else. Or: tag auth'd routes with a
sentinel and check `request.state` after the route runs.

### 5. BOOTSTRAP-AUTOSEED-XFF-LEFTMOST-STILL-OPEN (MED)

- **CWE**: CWE-348 (Use of Less Trusted Source).
- **Severity**: MED — unchanged from round 4 MED of the same name.
- **Location**: `src/iam_jit/routes/web.py:512-562`.

Round 4 explicitly identified the leftmost-XFF shape in
`magic_callback`'s bootstrap-admin auto-seed and provided a clear
fix sketch (delegate to `trusted_proxy.real_client_from_xff`).
Round 5 confirms the fix did not ship. The pinned round-4 test
(`test_finding_bootstrap_autoseed_xff_leftmost`) still asserts the
vulnerable shape (`assert 'split(",")[0]' in src`). Verified by
reading `web.py:539-552`:

```python
xff = request.headers.get("x-forwarded-for") or ""
client_host = request.client.host if request.client else None
source_ip = None
if (
    os.environ.get("IAM_JIT_TRUST_FORWARDED_FOR", "1").lower()
    in {"1", "true", "yes"}
) and xff:
    source_ip = xff.split(",")[0].strip()
```

The fix is the same as round 4's writeup.

### 6. ADMIN-CIDR-ALLOWLIST-ACCEPTS-WILDCARD-0000-0 (MED)

- **CWE**: CWE-732 (Incorrect Permission Assignment for Critical
  Resource) / CWE-862 (Missing Authorization at Configuration
  Boundary).
- **Severity**: MED — a single admin action (or admin-CSRF-clicked
  form-POST) silently disables source-IP enforcement while the UI
  reports "1 CIDR configured" (looks healthy).
- **Location**: `src/iam_jit/routes/admin.py:311-356`,
  `src/iam_jit/routes/web.py:1833-1874`.

Both the JSON API endpoint and the form-POST handler accept any
valid CIDR. `normalize_cidr` returns `"0.0.0.0/0"` for the input
`"0.0.0.0/0"` (or `"::/0"` for IPv6) — passes the
"not None" check, passes the note length check, gets persisted.

The "refuse last-CIDR removal" guard at `admin.py:372` (and
sibling `web.py:1890`):

```python
if len(entries) <= 1 and any(e.cidr == norm for e in entries):
    raise HTTPException(...)
```

is correctly written to refuse deletion of the only-remaining CIDR,
BUT does NOT inspect what that CIDR is. An admin who:

1. POSTs `{"cidr": "0.0.0.0/0", "note": "temp"}` — entries: 2.
2. DELETEs the legitimate office CIDR — guard says "fine, 2 > 1".
3. Now `0.0.0.0/0` is the sole remaining entry. Future deletes
   refuse.

The deployment is now wide-open to the internet, and the UI shows
"1 CIDR configured" — looks healthy.

**Fix sketch:** in `normalize_cidr` (or in the route handler),
reject CIDRs with prefix length 0 unless the operator sets an
explicit env-var override (`IAM_JIT_ALLOW_WILDCARD_CIDR=1`).
Surface a banner in the `/admin/network` UI when the runtime
allowlist effectively covers the internet
(`any(e.cidr in {"0.0.0.0/0", "::/0"} for e in entries)`).

### 7. PATCH-USERS-MASS-ASSIGNMENT-NO-AUDIT (MED) #BB2-11-SIBLING

- **CWE**: CWE-269 (Improper Privilege Management) /
  CWE-778 (Insufficient Logging).
- **Severity**: MED — privilege concentration with no audit trail.
- **Location**: `src/iam_jit/routes/users.py:132-159`.

Same root cause as finding #2. Even setting aside the
last-admin lockout, the PATCH route has TWO independently broken
shapes:

1. **No `audit.emit` on role changes.** Every other admin-only
   write in iam-jit (CIDR add/remove, force-delete-role, unban,
   revoke-tokens, dismiss-warning, log-retention update, settings
   PATCH) emits a `security.*` or `admin.*` audit event. The user
   PATCH does not. After an admin demotes every other admin, the
   audit log has zero record of the operation.
2. **Mass-assignment shape.** The route reads `roles` and accepts
   any valid combination, including upgrading any user to admin.
   The valid-roles check in `_user_from_payload` doesn't apply to
   PATCH (only to POST/create). A compromised low-privilege admin
   account can promote a sockpuppet to admin and then demote
   itself.

**Fix sketch:** emit `audit.emit(actor=actor.id, kind="security.user_role_changed",
summary=..., details={"user_id": user_id, "before": list(existing.roles),
"after": list(updated.roles)})` on every successful role mutation
PATCH. Refuse the PATCH if the `roles` payload is delivered without
a `reason` field (forcing the operator to document why).

### 8. STRIPE-CLAIM-EXCEPTION-CLASSIFICATION-STRING-FRAGILE (MED)

- **CWE**: CWE-703 (Improper Check or Handling of Exceptional
  Conditions).
- **Severity**: MED — could silently classify non-duplicate DDB
  errors as duplicates, dropping legitimate events.
- **Location**: `src/iam_jit/stripe_webhook.py:441-462`.

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

The OR ordering is exact-backwards for correctness. The
authoritative source is `e.response['Error']['Code']` (botocore's
contract); `str(e)` is a human-readable rendering that includes
the code, but it's not the contract. Future botocore versions that
change the `__str__` format (e.g., to localize, or to drop
verbose exception class names) break this check silently. Also: a
non-botocore exception that happens to mention
"ConditionalCheckFailedException" in its message string
(test stub, third-party wrapper) gets mis-classified.

The right shape:

```python
import botocore.exceptions
except botocore.exceptions.ClientError as e:
    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
        return False
    raise
```

Catches narrowly, doesn't depend on string formatting, and lets
non-ClientError exceptions (network errors, sentinels) propagate
unchanged.

### 9. STRIPE-DDB-RELEASE-RAISES-NOT-LOGGED-AT-API-CALLER (LOW)

- **CWE**: CWE-755.
- **Severity**: LOW — defense-in-depth.
- **Location**: `src/iam_jit/stripe_webhook.py:464-468`.

`DynamoDBProcessedEventsStore.release` calls `delete_item` and lets
exceptions propagate. The in-memory sibling uses
`self._seen.pop(event_id, None)` — never raises. Asymmetric error
contracts between the two implementations of the same protocol.

`dispatch_event` wraps the call in try/except (correct), so the
production path is fine today. The concern is for any future
caller (the admin "release stuck claim" endpoint recommended in
finding #3) — that caller will get a bare boto3 exception.

**Fix sketch:** wrap the DDB call in `try/except` and log; OR
match the in-memory contract by catching `delete_item`'s
`ResourceNotFoundException` and returning silently for "already
released."

### 10. DDB-SESSION-REVOCATION-MALFORMED-EXPIRES-AT-FAIL-OPEN (LOW)

- **CWE**: CWE-755 / CWE-754.
- **Severity**: LOW — narrow window (operator manual DDB edit /
  migration script error).
- **Location**: `src/iam_jit/session_revocation.py:115-122`.

```python
try:
    expires_at = int(item["expires_at"]["N"])
except (KeyError, ValueError):
    return False
```

A revocation row whose `expires_at` attribute is missing or
non-numeric is treated as "not revoked." For a deliberate
revocation table this should never happen — DDB schema is fixed.
But for a deployment that just-migrated, was edited manually, or
ran a backfill script with the wrong attribute name, the row
becomes a free pass.

**Fix sketch:** on malformed row, log CRITICAL and either return
True (fail-closed) or raise so the upstream `_identify_user`
fail-closed path catches it.

### 11. WEB-MAGIC-CALLBACK-BANNED-USER-SIGN-IN-ON-CORRUPT-FILE (LOW)

- **CWE**: CWE-754 / CWE-755.
- **Severity**: LOW — opposite shape of round-4
  `BANS-IS-BANNED-RAISES-AT-MAGIC-LINK-ISSUANCE-LEAKS-REGISTRATION`;
  requires pre-existing corrupt ban file for the specific user.
- **Location**: `src/iam_jit/routes/web.py:497-508`.

```python
try:
    if bans_mod.get_default_store().is_banned(user_id):
        return Response(status_code=403, ...)
except Exception:
    pass

cookie_value = auth_mod.sign_session(_get_secret(), user_id)
```

The bare `except Exception: pass` swallows the corrupt-file raise
that the round-3 `BAN-STORE-CORRUPT-FILE-UNBAN` closure introduced.
Banned user signs in. Opposite outcome from round-4's middleware
shape (which fails CLOSED with 503).

**Fix sketch:** match the middleware pattern — log + 503 on
`is_banned` failure; mirror the round-3 fail-closed default.

### 12. IS-DEV-INSECURE-ACTIVE-NOT-CACHED-FUTURE-FOOTGUN (LOW)

- **CWE**: documentary.
- **Severity**: LOW — not exploitable today.
- **Location**: `src/iam_jit/auth.py:180-205`.

`is_dev_insecure_active()` is correctly re-evaluated on every
call. A future refactor that caches it at module-import or in
`app.state` would silently invalidate the per-request semantics
and break tests that mutate env vars per-test.

**Fix sketch:** add a docstring caveat: "DO NOT CACHE. Called
per-request so env-mutation tests work."

## Cross-cutting theme

**"Fix where named; miss the structurally-identical sibling."**
This is now the fifth round in a row where the same shape dominates:

- Round 4: `is_dev_insecure_active` landed at four of the FIVE
  consumer sites; the fifth (`_get_secret`) was the one that
  matters most cryptographically. **CRIT finding this round.**
- Round 4: `_enforce_auth_cache_control` landed at `/api/v1/*` and
  `/admin/*`; the auth'd web HTML routes that render PII (`/queue`,
  `/all`, `/tokens`, `/requests/{id}`, `/accounts`,
  `/auth/magic-callback`) were missed.
- Round 4: `IAM_JIT_BANS_FAIL_OPEN` "CRITICAL log" pattern was
  ported to `IAM_JIT_SESSION_REVOCATION_FAIL_OPEN` (round-4 HIGH).
  Round 5 confirms that fix is solid. **One pattern that DID
  propagate.**
- Round 4: `HandlerPreWriteError` was added to `dispatch_event` but
  no handler raises it. **HIGH finding this round.**

**Recommendation for round 6 (if there is one):** an automated
"verify the fix didn't miss its siblings" gate. Concrete shape:
when a fix lands for a class of finding (e.g., "use the SoT helper
X"), the PR must include a `grep` audit that proves no remaining
inline shape exists. Example for the dev-insecure flag:

```bash
# CI gate: every reference to IAM_JIT_DEV_INSECURE_SECRET goes
# through is_dev_insecure_active(), except in the helper itself
# and in the docs/templates.
git grep -n "IAM_JIT_DEV_INSECURE_SECRET" -- src/ \
    | grep -v 'is_dev_insecure_active' \
    | grep -v 'auth.py' \
    | grep -v 'security_posture.py' \
    | grep -v 'templates/' && exit 1 || exit 0
```

Same shape for `xff.split(",")[0]`, `defaultdict(threading.Lock)`,
`IAM_JIT_TRUSTED_PROXY_CIDRS` inline parsing, `_GLOBAL is None`
without a lock, and bare `is_banned()` calls.

This isn't security tooling per se; it's enforcement that the
"fan-out to all sites" discipline becomes mechanical. Five rounds
of "we caught one more site" suggests this is the right tool to
build before round 6.

**Has the audit loop converged?**

Round 5 found one CRIT and two HIGHs. The CRIT is a clean
round-4-closure regression (missed sibling — exactly the pattern
the audits keep finding). The two HIGHs are: BB2-10 (never
fixed across rounds 2-4; not a regression, just untouched), and a
new-shape regression from round 4 (the dead-code `HandlerPreWriteError`
mechanism that silently locks out paid customers).

If round 5's CRIT lands and BB2-10 is finally addressed, round 6
would likely find only LOW-severity edge cases (the audit is
converging on the same dozen-or-so shapes; novelty per round is
declining). The cross-cutting recommendation above — automated
fan-out enforcement — is the single biggest lever to flip the
convergence trajectory.
