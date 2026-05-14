# iam-jit white-box appsec audit — round 3 (2026-05-14)

Third-pass white-box review on top of rounds 1 and 2
(`AUDIT-2026-05-WB.md`, `AUDIT-2026-05-WB-ROUND2.md`). Two
objectives:

1. **Re-audit the round-2 closures**: `STRIPE-IDEMPOTENCY-TOCTOU`,
   `SCORE-XFF-LEFTMOST-TRUSTED`, `NETWORK-ACL-XFF-DEFAULT-TRUSTED`,
   `MAGIC-LINK-XFH-POISONING`, `MAGIC-LINK-LOG-CHANNEL`,
   `TOKENS-NO-PER-USER-MINT-QUOTA`, `MAGIC-LINK-NO-RATE-LIMIT`,
   `MAGIC-LINK-REPLAY-MULTI-INSTANCE`, `BAN-MULTI-INSTANCE-DESYNC`.
2. **New surfaces introduced by those closures** — every new env
   var is a footgun ladder; every new "atomic" primitive is a
   correctness claim to verify; every fix targeted at one route
   needs sibling routes audited too.

**Headline number: 1 HIGH, 6 MED, 6 LOW (13 total).** The single
HIGH is a crash-safety regression introduced by the round-2 Stripe
idempotency fix — the new "claim then process" ordering swapped a
race condition for a crash-recovery hole. The MEDs cluster around
two themes: TOCTOU patterns that the round-2 fixes copied without
realising, and new env-var footguns where a single misconfig
unlocks multiple defenses.

Note on what we DIDN'T find: two findings drafted during the
review (`LOGIN-WEB-XFF-LEFTMOST-RATE-LIMIT-BYPASS` and
`LOGIN-WEB-MAGIC-LINK-NO-MULTI-INSTANCE-GUARD`) turned out to be
already-closed in `routes/web.py:_login_client_id` and
`routes/web.py:login_submit`. Both fixes mirror the round-2
closures across the HTML form path; well done. Round 3 confirms
fix-fan-out on those two sites and finds the remaining HIGH/MED
elsewhere.

Each finding has a corresponding pytest case in
`tests/test_appsec_audit_round3_wb.py`. Tests assert *current*
(vulnerable) behavior; when a fix lands, the test fails — flip the
assertion (or delete the test) as part of the fix PR.

## Totals

| Severity | Count |
| -------- | ----- |
| CRIT     | 0     |
| HIGH     | 1     |
| MED      | 6     |
| LOW      | 6     |
| **TOTAL**| **13**|

### Severity breakdown by finding id

HIGH (1):

- `STRIPE-CLAIM-BEFORE-PROCESS` — `dispatch_event` calls
  `processed_events_store.claim(event_id)` BEFORE running the
  handler. If the handler crashes (Lambda timeout / OOM / SES
  failure / DDB tokens-store outage), the event_id is permanently
  claimed and Stripe's retries see "duplicate" and short-circuit —
  the customer paid but never gets their token. Location:
  `src/iam_jit/stripe_webhook.py:412-447`.

MED (6):

- `TOKENS-PER-USER-CAP-TOCTOU` — `routes/tokens.create_token` reads
  `list_for_user(user.id)`, checks `< cap`, then calls `store.put`.
  Two concurrent POSTs both see N items and both write — the cap
  becomes a soft suggestion. Same shape as round-2 STRIPE
  has_processed → mark_processed (`routes/tokens.py:55-81`).

- `WEB-MAGIC-CALLBACK-BROKEN-AUTO-SEED` — `magic_callback` references
  `request` (not in its signature) inside a `try:` block that
  swallows `NameError`. The bootstrap-admin auto-seed of the CIDR
  allowlist therefore **never fires**. Operator who relied on
  documented "auto-seed on first sign-in" gets a CIDR allowlist
  that stays empty (treats every IP as allowed when ACL is empty,
  per `network_acl.evaluate`'s `no_acl_configured` branch). The
  documented hardening step is silently broken
  (`src/iam_jit/routes/web.py:432-520`).

- `BODY-SIZE-GUARD-CHUNKED-BYPASS` — `_enforce_max_body_size`
  middleware only refuses requests with `Content-Length >
  IAM_JIT_MAX_BODY_BYTES`. Requests with `Transfer-Encoding:
  chunked` (no Content-Length) pass through unbounded; route
  handlers then parse the full body
  (`src/iam_jit/app.py:323-340`).

- `MAGIC-LINK-DEV-INSECURE-OUTRANKS-SES` — `magic_link_delivery.decide`
  precedence puts `IAM_JIT_DEV_INSECURE_SECRET=1` BEFORE the SES
  check. A production deployment with both `IAM_JIT_SES_SENDER`
  AND a leaked / accidentally-copied `IAM_JIT_DEV_INSECURE_SECRET=1`
  (from a developer's local `.env` template) returns the magic
  link in the HTTP response body instead of mailing it — the
  attacker who submits a target's email reads the response and
  signs in as them (`src/iam_jit/magic_link_delivery.py:72-82`).

- `DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN` —
  `IAM_JIT_DEV_INSECURE_SECRET=1` is a single flag that disables
  THREE distinct production controls: (1) CSRF Origin/Referer
  check, (2) `Secure` cookie attribute on the session cookie,
  (3) magic-link delivery channel safety (see above). A
  misconfigured launch where this leaks into prod (most common
  failure mode: copying `.env.example` over `.env` without
  re-editing) opens three independent attack vectors with one
  env var. There is no defense-in-depth check that this flag is
  consistent with the rest of the deploy posture. Locations:
  `src/iam_jit/app.py:236, 415`,
  `src/iam_jit/routes/web.py:527`,
  `src/iam_jit/magic_link_delivery.py:72`.

- `BANS-DDB-FAIL-OPEN-VIA-ENV` — round-2 closure for
  `BAN-CHECK-FAIL-OPEN` correctly flipped the default to fail
  closed (503). BUT introduced a new env var
  `IAM_JIT_BANS_FAIL_OPEN=1` that re-opens the original fail-open
  path. An operator who sets it (or whose deploy template inherits
  it from a dev environment) re-introduces the round-2 finding
  without any audit-log signal — the BB-style detection log fires
  but enforcement is silently disabled. No alarm
  (`src/iam_jit/middleware.py:183-208`).

LOW (6):

- `PUBLIC-URL-XFH-LEFTMOST-TOKEN` — `public_url.base_for` takes the
  leftmost X-Forwarded-Host token (`xfh.split(",")[0].strip()`).
  Same leftmost-XFF-token failure mode as round-2 SCORE-XFF-
  LEFTMOST-TRUSTED, but on a different header. Lower severity
  because the value is then checked against the
  `IAM_JIT_ALLOWED_PUBLIC_HOSTS` allowlist — but an operator who
  configures the allowlist permissively gets attacker-controlled
  hostname embedded in their magic-link URLs
  (`src/iam_jit/public_url.py:121`).

- `MAGIC-LINK-IP-LIMITER-PEER-ONLY-DOS` — `_magic_link_client_ip`
  in `routes/auth.py` reads ONLY `request.client.host` and ignores
  XFF entirely. Behind CloudFront/ALB every request's peer IP is
  the proxy. The limiter becomes a global cap of 15/min/edge-IP
  — one user's traffic spike DoSes magic-link sign-in for every
  other user routed through the same CloudFront PoP
  (`src/iam_jit/routes/auth.py:80-88`).

- `XFP-SCHEME-INJECTION-IN-PUBLIC-URL` — `public_url.base_for`
  reads `X-Forwarded-Proto` and substitutes it directly into the
  resolved base URL with no allowlist. A malicious value (e.g.,
  `javascript`) becomes `javascript://allowed-host/...` which is
  a valid JavaScript-URL on click. Mitigated by the
  `_peer_in_trusted_proxy_cidrs` gate, but defense-in-depth: the
  scheme should be allowlisted to `{"http", "https"}`
  (`src/iam_jit/public_url.py:115-124`).

- `TRUSTED-PROXY-CIDRS-PARSER-DISCREPANCY` — three modules parse
  `IAM_JIT_TRUSTED_PROXY_CIDRS` independently with subtly
  different rules: `routes/score.py` uses `.split(",")` (no
  newline tolerance); `public_url.py` and `network_acl.py` use
  `replace(",", " ").split()` (whitespace-tolerant). An operator
  who writes the env var with newlines (e.g., a multi-line
  Terraform value) has score's XFF trust silently
  disabled while network_acl + public_url see the right list
  (`src/iam_jit/routes/score.py:301-339`,
  `src/iam_jit/network_acl.py:128-135`,
  `src/iam_jit/public_url.py:71-78`).

- `XFF-IPV4-MAPPED-IPV6-STILL-OPEN` (CARRY-FORWARD) — round-2
  finding `SCORE-XFF-IPV4MAPPED-IPV6` was LOW and not yet fixed.
  Round-3 confirms the same cross-family `in` check now lives in
  THREE places (`routes/score.py`, `network_acl.py`,
  `public_url.py`) — fix all three together
  (`src/iam_jit/routes/score.py:295-313`,
  `src/iam_jit/network_acl.py:139-145`,
  `src/iam_jit/public_url.py:79-83`).

- `MAGIC-LINK-RATE-LIMITER-PER-INSTANCE-DESYNC` — the new
  `_get_magic_link_ip_limiter` is an `InMemoryRateLimiter`,
  per-Lambda-instance. The closure documented soft=5, hard=15
  per minute, but the effective production rate is
  `instances * 15 / minute`. Stripe webhooks already burned us
  on multi-instance with `STRIPE-IDEMPOTENCY-TOCTOU`; same
  pattern here — closure assumes single instance, prod runs N
  (`src/iam_jit/routes/auth.py:55-71`).

## Top 5 findings

### 1. STRIPE-CLAIM-BEFORE-PROCESS (HIGH)

`src/iam_jit/stripe_webhook.py:412-447`

The round-2 closure pattern is "claim then process" — claim is
atomic, so the race is gone. But it traded one bug for another:

```python
# stripe_webhook.py:412-445
if processed_events_store is not None and event_id:
    is_winner = processed_events_store.claim(event_id)  # commits NOW
    if not is_winner:
        return {"duplicate": True, ...}
# ...
result = handler()  # may raise
```

The event_id is committed BEFORE the handler runs. If the handler
crashes (Lambda timeout mid-write to the tokens table; SES throws;
DDB throttle; an `ImportError` from a hot-reload), the event_id
is permanently locked but the side-effect (token issuance +
email) never happened.

Stripe retries the webhook with exponential backoff. Every retry
sees `is_winner=False` → short-circuits with `duplicate=True`.
The customer paid for a subscription and got no token.

The fix is to either:
- (a) Use "process then claim, with a separate `in_flight` marker"
  pattern (claim a tentative lock, process, then promote to a
  durable claim only on success), OR
- (b) Claim-then-process where every handler side-effect is
  idempotent on retry (DDB conditional writes that no-op on
  re-attempt). The current `tokens_store.put` is unconditional and
  uses the token hash as the key; redelivery would mint a NEW token
  hash. So (b) needs work too.

Round-2 audit's closure note specifically flagged this as
"in-memory implementation uses dict.setdefault" but didn't
acknowledge that the claim-then-process semantics create a new
class of failure mode. **The race condition was closed; the
crash-safety property was lost.**

Reproduction is a 2-thread/2-step test: claim succeeds, handler
raises, retry observes `duplicate=True` and the tokens store
stays empty.

### 2. TOKENS-PER-USER-CAP-TOCTOU (MED)

`src/iam_jit/routes/tokens.py:55-81`

```python
existing = store.list_for_user(user.id)
if len(existing) >= cap:
    raise 429
# … construct token …
store.put(record)
```

Standard TOCTOU. Two concurrent POSTs both see `len(existing)=N`
and both write — the cap becomes `cap + concurrent_request_count - 1`.
For the default cap=50 and an attacker holding 100 concurrent
connections, they mint ~150 tokens.

This is the same shape as the closed `STRIPE-IDEMPOTENCY-TOCTOU`
and the still-open `BOOTSTRAP-CLAIM-TOCTOU`. The pattern is
endemic; a project-wide audit for "list-then-write" pairs would
catch all three at once.

Fix sketch: maintain a per-user counter row in DDB; use
`UpdateItem` with `ConditionExpression="counter < :cap"` +
`UpdateExpression="ADD counter :one"`. Decrement on revoke.

### 3. WEB-MAGIC-CALLBACK-BROKEN-AUTO-SEED (MED)

`src/iam_jit/routes/web.py:432-520`

```python
@router.get("/auth/magic-callback")
def magic_callback(token: str, return_to: str = "/") -> Response:
    # … no `request` in signature …
    try:
        # … 80 lines that reference `request.app.state`,
        #     `request.headers`, `request.client.host` …
    except Exception:
        # Never let the nudge logic crash the sign-in path.
        pass
```

Every reference to `request` raises `NameError` (the route handler
doesn't declare `request: Request` as a FastAPI dependency). The
`NameError` is caught by the bare `except Exception:` and
swallowed. The bootstrap-admin auto-seed of the CIDR allowlist
(documented as the recommended first-sign-in flow) silently never
fires.

This is a launch-day pain point: the documented hardening step
for a new deployment is to sign in once and have your IP captured
into the allowlist. It just doesn't work. Operators who don't
notice run with an empty allowlist → `network_acl.evaluate`'s
`no_acl_configured` branch returns `allowed=True` for every IP →
the deployment is effectively unprotected at the network layer.

Fix: add `request: Request` to the `magic_callback` signature and
the auto-seed code path becomes reachable. Plus replace the bare
`except Exception: pass` with `except Exception: logger.exception(...)`
so the next silent failure gets surfaced.

### 4. DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN (MED)

The same env var `IAM_JIT_DEV_INSECURE_SECRET=1` controls THREE
independent production controls:

  1. CSRF middleware bypass (`app.py:236`).
  2. Session cookie `secure` attribute removed
     (`app.py:415`, `routes/web.py:527`, `routes/auth.py:235`).
  3. Magic-link delivery channel becomes `in_response` — the link
     comes back in the HTTP response body
     (`magic_link_delivery.py:72`). See
     MAGIC-LINK-DEV-INSECURE-OUTRANKS-SES.

A single misconfiguration → three independent vulnerabilities.
Most common failure: `cp .env.example .env` in a launch hurry
and forgetting to flip the flag back off.

Fix sketch: refuse startup when `IAM_JIT_DEV_INSECURE_SECRET=1`
AND `AWS_LAMBDA_FUNCTION_NAME` are both set. Loud crash on
misconfiguration is safer than three silent regressions.
Alternative: split into three independent env vars so
accidentally setting one doesn't take down the others.

### 5. BODY-SIZE-GUARD-CHUNKED-BYPASS (MED)

`src/iam_jit/app.py:323-340`

```python
cl = request.headers.get("content-length")
if cl is not None:
    if int(cl) > _max_body_bytes:
        return 413
# else: pass through unbounded
```

Refuses oversize bodies only when `Content-Length` is present.
A client sending `Transfer-Encoding: chunked` (no
Content-Length) passes through the middleware unbounded; the
downstream route handler then parses the entire body.

Realistic attack: attacker sends a multi-MB chunked body to a
cookie-authenticated POST. Lambda Function URL caps at 6 MB
synchronous (so the worst case is bounded by AWS), but the
middleware's stated job is to refuse oversize requests BEFORE
they hit handler code — and chunked-encoding bypasses the
contract.

Fix sketch: also refuse requests where
`transfer-encoding: chunked` is present without Content-Length
(or pre-buffer + count bytes).

## Re-audit of round-2 closures

| Closure | Status | Notes |
| --- | --- | --- |
| `STRIPE-IDEMPOTENCY-TOCTOU` | **CLOSED on race; introduces `STRIPE-CLAIM-BEFORE-PROCESS` (HIGH)** | Atomic claim works. Crash between claim and handler success → permanent lock with no retry recovery. |
| `SCORE-XFF-LEFTMOST-TRUSTED` | **CLOSED in score.py AND propagated to routes/web._login_client_id** | Right-to-left walk + trusted-proxy CIDR gate in both call sites. Good fix fan-out. |
| `NETWORK-ACL-XFF-DEFAULT-TRUSTED` | **CLOSED** | Default-off + peer-in-trusted-CIDR gate is correct. Inconsistent parser of `IAM_JIT_TRUSTED_PROXY_CIDRS` across the three modules (LOW). |
| `MAGIC-LINK-XFH-POISONING` | **CLOSED with leftmost-token LOW left open** | `IAM_JIT_ALLOWED_PUBLIC_HOSTS` allowlist + peer-in-trusted-CIDR gate works. Leftmost-token parsing of XFH itself remains (LOW). XFP scheme is not allowlisted (LOW). |
| `MAGIC-LINK-LOG-CHANNEL` | **CLOSED with footgun** | Fingerprint-only log line is correct. `IAM_JIT_DEV_INSECURE_SECRET=1` outranks SES in the decide() precedence — if the flag leaks into prod, prod returns the magic link in the HTTP response body (MED, `MAGIC-LINK-DEV-INSECURE-OUTRANKS-SES`). |
| `TOKENS-NO-PER-USER-MINT-QUOTA` | **CLOSED on quota; introduces `TOKENS-PER-USER-CAP-TOCTOU` (MED)** | List-then-write is TOCTOU. Race lets concurrent POSTs exceed the cap by `n-1` per race window. |
| `MAGIC-LINK-NO-RATE-LIMIT` | **CLOSED with per-instance desync (LOW) and peer-only-DOS (LOW)** | Sliding-window limiter is correct. (1) Per-instance so prod cap is `instances*15/min`. (2) Reads peer.host only; behind CloudFront the limiter becomes a global cap of 15/min/CloudFront-edge — one user DoSes everyone routed through the same PoP. |
| `MAGIC-LINK-REPLAY-MULTI-INSTANCE` | **CLOSED on JSON API AND mirrored to HTML form** | Both `routes/auth.issue_magic_link` and `routes/web.login_submit` carry the `_in_lambda + IAM_JIT_MAGIC_LINK_NONCES_TABLE` guard. Good fix fan-out. |
| `BAN-MULTI-INSTANCE-DESYNC` | **CLOSED** | `DynamoDBBanStore` is correct and integrates with the middleware fail-closed path. |
| `BAN-CHECK-FAIL-OPEN` | **CLOSED with env-var footgun (MED, `BANS-DDB-FAIL-OPEN-VIA-ENV`)** | Default flipped to fail-closed (503). New env var `IAM_JIT_BANS_FAIL_OPEN=1` re-opens the original behavior — no operator alarm when set. |
| `BAN-STORE-CORRUPT-FILE-UNBAN` | **CLOSED** | `JSONDecodeError` now raises; corrupted file fails CLOSED via the middleware 503 path. |
| `BOOTSTRAP-CLAIM-TOCTOU` | **STILL OPEN** | Round-2 finding remains; `user_store.put` is unconditional. |

The good news: round-2 fix authors propagated the
SCORE-XFF-LEFTMOST and MAGIC-LINK-REPLAY-MULTI-INSTANCE fixes
across sibling call sites (web's `_login_client_id` and
`login_submit`). The bad news: every fix that landed a NEW
env-var control surface created at least one new footgun
(`IAM_JIT_BANS_FAIL_OPEN`, `IAM_JIT_DEV_INSECURE_SECRET`
side-effects, `IAM_JIT_ALLOW_INSECURE_NONCES`).

## Honest negatives — checked and adequately defended

- **CSRF middleware shape** — origin/referer check is correct;
  bearer/SigV4 exempt; safe methods exempt; webhook path exempt.
  Host-header trust is OK (an external attacker cannot route a
  forged Host to the Lambda).

- **DDB conditional-claim implementation** — the magic-link nonces
  store uses `attribute_not_exists(token_hash)` correctly. The
  exception detection by string-match on
  `"ConditionalCheckFailedException"` is brittle but functional.

- **CSRF cookie scope on session** — `samesite="strict"` is set on
  both `/setup`-success and `/auth/magic-callback`-success cookies.
  `httponly=True`. `secure` is gated on
  `IAM_JIT_DEV_INSECURE_SECRET != 1`.

- **Magic-link nonce store DDB shape** — atomic claim via
  PutItem + ConditionExpression is correct. TTL via
  `expires_at` attribute is correct.

- **Stripe-webhook signature verification** — `hmac.compare_digest`
  + 5-minute tolerance; unchanged since round 1.

- **`_safe_return_to` allowlist** — explicit path-prefix allowlist
  defeats `//evil.com` open-redirect via `return_to`. Confirmed
  unchanged.

- **Stripe `event_id` claim atomicity (race property only)** —
  `dict.setdefault` with per-call sentinel is atomic under the
  CPython GIL. DDB implementation note in the docstring is correct.
  The class of bug *added* is crash-safety, not race.

- **Body size guard (Content-Length path)** — the middleware
  correctly refuses bodies that declare oversize via
  Content-Length. (The chunked-encoding bypass is a separate
  finding above.)

- **routes/web._login_client_id and routes/web.login_submit
  multi-instance guard** — round-2 closures DID propagate to the
  HTML form path. Both checks present and correct.

## Methodology

Files re-read in round 3 (delta-focused on round-2-fix sites +
the new env vars):

- `src/iam_jit/stripe_webhook.py` — re-checked the new
  `claim()`-protocol shape; spotted the claim-before-process
  crash-safety regression.
- `src/iam_jit/routes/score.py` — confirmed the right-to-left
  walk is correct.
- `src/iam_jit/network_acl.py` — confirmed default-off behavior
  + per-family CIDR check.
- `src/iam_jit/public_url.py` — found the leftmost-XFH-token
  issue, the XFP scheme-injection footgun, and the inconsistent
  CIDR parser.
- `src/iam_jit/magic_link_delivery.py` — found the
  `IAM_JIT_DEV_INSECURE_SECRET=1`-outranks-SES precedence bug.
- `src/iam_jit/routes/auth.py` — confirmed the multi-instance
  nonce guard works on the JSON API.
- `src/iam_jit/routes/web.py` — verified the matching guards in
  `_login_client_id` and `login_submit`; found the broken
  bootstrap auto-seed (NameError swallowed by bare except in
  `magic_callback`).
- `src/iam_jit/routes/tokens.py` — found the list-then-put
  TOCTOU on the per-user cap.
- `src/iam_jit/middleware.py` — found the `IAM_JIT_BANS_FAIL_OPEN`
  env-var footgun.
- `src/iam_jit/magic_link_nonces.py` — confirmed DDB store
  shape; no new findings.
- `src/iam_jit/bans.py` — confirmed corrupt-file closure and
  DDB store; no new findings.
- `src/iam_jit/app.py` — found the chunked-encoding body-size
  bypass.

Tools: `grep`, direct file read, `pytest tests/test_appsec_audit_round3_wb.py`
to confirm each new finding's test reproduces vulnerable
behavior. All 13 tests pass against the current code (each test
asserts CURRENT vulnerable behavior — they're expected to fail
once a fix lands).

## Next-action ordering for the fixer

Highest leverage first:

1. **STRIPE-CLAIM-BEFORE-PROCESS** (HIGH) — design pass on the
   claim+process ordering. Either two-phase (in-flight marker +
   durable claim on success) or per-side-effect idempotency. Both
   are non-trivial; pick before launch so this isn't a hotfix on
   day 1 of paid traffic.

2. **WEB-MAGIC-CALLBACK-BROKEN-AUTO-SEED** (MED) — one-line fix
   (`def magic_callback(token: str, return_to: str = "/", request: Request = ...)`)
   plus removing the bare-except so the next silent failure
   surfaces.

3. **TOKENS-PER-USER-CAP-TOCTOU** (MED) — conditional-counter row
   in DDB; small diff once the pattern from STRIPE is mirrored.

4. **DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN** (MED) — refuse to
   start the app with `IAM_JIT_DEV_INSECURE_SECRET=1` AND
   `IAM_JIT_SES_SENDER` AND `AWS_LAMBDA_FUNCTION_NAME` (i.e., the
   shape of a prod deploy). Loud crash on misconfiguration is
   safer than three independent silent regressions.

5. **BANS-DDB-FAIL-OPEN-VIA-ENV** (MED) — when the override is
   active and a real ban check fails, emit an `audit.emit` event
   `security.ban_enforcement_disabled` so the SIEM can spot the
   misconfiguration.

6. **BODY-SIZE-GUARD-CHUNKED-BYPASS** (MED) — add a
   `transfer-encoding: chunked` rejection alongside the existing
   `content-length` check.

## Cross-cutting theme across rounds 1-3

The recurring pattern across all three rounds is the same:
**round-N's fixes ship as correct local diffs, but each one
either (a) trades one bug class for an adjacent one, or (b) opens
a new env-var control surface that doubles as a footgun.**

- Round 1 added the score-endpoint XFF gate (round-2 found it
  trusted the leftmost token).
- Round 2 fixed STRIPE has-then-mark (round-3 found the
  claim-then-process crash hole).
- Round 2 fixed BAN-CHECK-FAIL-OPEN (round-3 found the new
  IAM_JIT_BANS_FAIL_OPEN env-var that re-opens it).
- Round 2 added the per-user token cap (round-3 found it's
  TOCTOU).

The good news: round-2 fix authors DID propagate the
SCORE-XFF-LEFTMOST and MAGIC-LINK-REPLAY-MULTI-INSTANCE fixes
across all sibling call sites in `routes/web.py`. That discipline
should be the project default for every future fix PR — a
checklist item "did this fix propagate to every structurally
identical site?" prevents the round-2-style HIGH-regressions
from happening at all.
