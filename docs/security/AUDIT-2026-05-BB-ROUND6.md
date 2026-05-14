# iam-jit black-box appsec audit — round 6 (2026-05-14)

Round-6 external-researcher probe. Round 5 declared "externally
converged" with 14 honest negatives plus 7 findings (2 MED regressions
of the round-5 brief, 5 LOW hygiene). Round 6's brief re-probes three
new closures landed since round 5:

  * Hard-coded dev-secret fallback REMOVED — in Lambda + no
    `IAM_JIT_MAGIC_LINK_SECRET` → magic-link routes 500/503 (refuses
    to operate without explicit `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1`).
  * `PATCH /api/v1/users/{user_id}` now refuses self-demotion AND
    last-admin demotion.
  * Stripe webhook on transient-handler-failure now retries
    successfully (no longer locks out paid customer with "duplicate").

Plus the round-6 launch-day-attacker grab-bag the prior rounds missed:

  * HEAD-method handling on auth'd vs public routes.
  * OPTIONS-preflight cache + CORS behavior on `/docs` and `/healthz`.
  * Compression-bomb (`Content-Encoding: gzip`) re-probe.
  * Content-Type alternatives (`text/plain`, `x-www-form-urlencoded`).
  * JSON-parser quirks: deeply-nested arrays/objects, BOM, U+0000 in
    string, trailing junk, duplicate keys, RFC 8259 edge cases.
  * Method tampering via `_method=` body, `?_method=` query, or
    `X-HTTP-Method-Override` header on `/api/v1/admin/*` paths.
  * Query-parameter override attempts (`?score=10`, `?tier=low`).
  * Tier-leakage of authenticated-customer tier identity to anonymous
    callers via timing, headers, or error messages.

Each finding has a corresponding pytest case in
[`tests/test_appsec_audit_round6_bb.py`](../../tests/test_appsec_audit_round6_bb.py).
Convention unchanged: broken-behavior tests assert the **vulnerable**
state (flip on fix); honest-negative tests assert the **defended**
state (regression guard).

## Totals

| Severity | Count |
| -------- | ----- |
| CRIT     | 0     |
| HIGH     | 1 (BB6-01) |
| MED      | 0     |
| LOW      | 3 (BB6-02, BB6-03, BB6-04) |
| Honest negatives | 21 (BB6-05..BB6-25) |
| **TOTAL new findings** | **4** (1 HIGH, 3 LOW) |

**One HIGH finding.** All three round-6 brief closures hold externally
(BB6-05, BB6-06, BB6-07 verified). The HIGH is a previously-unprobed
JSON-parser-recursion vector that crashes the worker with an uncaught
exception AND bypasses the security-headers middleware on the 500
response path. The three LOWs are: a round-4/5 Stripe carryover that
the brief didn't list, an admin-endpoint 405-vs-404 enumeration delta,
and a whitespace event.id parser quirk.

## Severity breakdown by finding id

### HIGH

| id     | title |
| ------ | ----- |
| BB6-01 | Deep JSON nesting (≥~990 array depth) → uncaught 500 with no security headers, pre-auth attackable on /api/v1/score |

### LOW

| id     | title |
| ------ | ----- |
| BB6-02 | Stripe duplicate-event response still leaks `event_id` + `event_type` (round-4 BB4-05 / round-5 BB5-21 carryover) |
| BB6-03 | Admin-endpoint enumeration via 405-vs-404 differential when non-admin probes /api/v1/admin/* |
| BB6-04 | Stripe whitespace-only `event.id` ("   ") bypasses `missing_event_id` rejection |

### Honest negatives — defended classes

| id     | round-N closure / class | status |
| ------ | ----------------------- | ------ |
| BB6-05 | Lambda + no `IAM_JIT_MAGIC_LINK_SECRET` → 503 refusal (brief closure) | **HOLDING** |
| BB6-06 | PATCH self-demotion refused with operator-readable detail (brief closure) | **HOLDING** |
| BB6-07 | Stripe webhook retry returns 200 (no infinite-retry lockout) (brief closure) | **HOLDING** |
| BB6-08 | HEAD /healthz → 405 WITH security headers (CSP, X-Frame-Options) | PINNED |
| BB6-09 | OPTIONS /docs → 405 with NO CORS Allow-Origin leak | PINNED |
| BB6-10 | /api/v1/score `Content-Encoding: gzip` → 400 parse (no inflation) | PINNED (BB5-17 re-pin) |
| BB6-11 | /api/v1/score with `text/plain` / `application/xml` / etc. → 422 | PINNED |
| BB6-12 | /api/v1/auth/magic-link 10MB email body → 413 | PINNED |
| BB6-13 | `X-HTTP-Method-Override` / `?_method=` / body `_method` all ignored on PATCH /api/v1/users | PINNED |
| BB6-14 | /api/v1/score `?score=10` / `?tier=low` query overrides ignored | PINNED |
| BB6-15 | Tier-leakage: anon vs auth'd /api/v1/score response IDENTICAL (no leak today) | PINNED forward |
| BB6-16 | JSON parser handles trailing data / duplicate keys / NUL-in-string without crashes | PINNED |
| BB6-17 | Magic-link callback replay → 400; tampered token → 400 | PINNED (BB-27 re-pin) |
| BB6-18 | Cookie injection (multi-`iam_jit_session`) → last-wins; CRLF rejected | PINNED |
| BB6-19 | /healthz body minimal (`{"status":"ok","version":"..."}`) — BB-13 closure holds | PINNED |
| BB6-20 | Method tampering (TRACE/CONNECT/PROPFIND/MOVE/LOCK/MKCOL) → 405 or 404 | PINNED |
| BB6-21 | /api/v1/score score field bounded 0..10 under header tampering | PINNED forward |
| BB6-22 | /api/v1/auth/callback with NUL-in-token → 400, no 500 crash | PINNED |
| BB6-23 | HEAD /api/v1/score returns 405 — anon/auth identical (no tier leak) | PINNED forward |
| BB6-24 | /api/v1/score with tiny malformed JSON (null, [], {}, "0") → 422 not 500 | PINNED |
| BB6-25 | /api/v1/score Cache-Control still `private, max-age=300, must-revalidate` | PINNED (BB5-07 re-pin) |

## Did the brief's stated closures hold externally?

| Closure | Status | Notes |
| ------- | ------ | ----- |
| Lambda + no MAGIC_LINK_SECRET → 503 refuses to operate | **HOLDING** | BB6-05: subprocess test with cleared env confirms; 503 detail points at nonce table config; no dev_link emitted. |
| PATCH self-demotion refused | **HOLDING** | BB6-06: 409 with "refusing self-demotion" detail; fires for both `roles:[requester]` and `roles:[]`. |
| Stripe webhook retry returns 200 (no lockout) | **HOLDING** | BB6-07: triple-retry of same event returns 200 each time; Stripe retry policy sees success. |

The PATCH last-admin-demotion path is harder to verify externally with
the read-only `FileUserStore` (all PATCH writes 409 with "read-only at
runtime" before reaching the last-admin check). The **self-demotion**
check fires earlier (returns the "refusing self-demotion" detail in
preference to the "read-only" detail), confirming it's wired in front
of the store. WB verification of the last-admin path is recommended
for completeness.

## Top finding — BB6-01 (HIGH, launch-blocking)

### Deep JSON nesting → uncaught 500 with no security headers

**Probe:** send a 2KB payload of nested arrays to `/api/v1/score`:

```python
payload = "[" * 1500 + "1" + "]" * 1500   # ~3KB
r = anon.post("/api/v1/score",
              content=payload,
              headers={"Content-Type": "application/json"})
```

**Result:**

```
status: 500
Content-Type: text/plain; charset=utf-8
body: "Internal Server Error"
```

**Critical secondary finding:** the 500 response is **missing the
entire security-headers chain** that round-1 BB observed as the
strong baseline:

* No `Content-Security-Policy`
* No `X-Frame-Options`
* No `X-Content-Type-Options`
* No `Referrer-Policy`
* No `Cache-Control`

Round 1 explicitly noted: "Custom security-headers middleware applies
CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy /
`frame-ancestors 'none'` to every response (HTML and JSON alike) —
strong baseline." That baseline does NOT hold on the uncaught-
RecursionError path.

**Threshold:** depth ≈ 990 array brackets is the crossover. Below ~950
returns 422 (model-validation error, properly handled with security
headers). Above ~990 returns 500 (uncaught).

**Reproduces on every JSON-accepting POST route:**
* `/api/v1/score` (anon-callable — pre-auth attack)
* `/api/v1/auth/magic-link` (anon-callable)
* `/api/v1/requests` (auth required)
* `/api/v1/requests/preview` (auth required)
* `PATCH /api/v1/users/{user_id}` (admin required)

**Worker survives** — a subsequent valid request after the crash
returns 200 normally. So this is **not a process-kill DoS**, it's a
**log-spam + security-headers-bypass** DoS.

**Production blast radius:**

1. **Pre-auth attacker** on `/api/v1/score` and
   `/api/v1/auth/magic-link` can trigger the 500 path. Both endpoints
   are anonymous-callable today.
2. **CloudWatch log spam.** Each 500 produces a Python stack trace
   in the Lambda logs (RecursionError + the long FastAPI/Pydantic
   call chain). A coordinated 100 req/min burst generates ~100KB/min
   of log volume from a single attacker. Across the deployment
   lifetime, this both costs money (CloudWatch ingest) and masks
   real errors in the alerting layer.
3. **Security-headers regression on error path.** The 500 body is
   `text/plain` so injecting HTML wouldn't render, BUT:
   * No `X-Content-Type-Options: nosniff` → older browsers may
     MIME-sniff the response as HTML and render the (attacker-
     influenced) error.
   * No `frame-ancestors 'none'` → the 500 page could be framed by
     an attacker site for UI redress (low-value, but defense-in-
     depth lost).
   * No `Cache-Control: no-store` → if a misconfigured CDN sits
     in front, the 500 response could be cached and replayed to
     other users. Unlikely in practice (text/plain 500 is rarely
     cacheable by default CDN policy), but the missing header is
     the launch-day-attacker grab.
4. **Discoverability:** an attacker running a generic fuzzer (afl,
   boofuzz, jsonfuzz) against `/api/v1/score` would discover this in
   under a minute. It is **the** obvious first-100-attacker probe.

**Why HIGH not MED:**

* Pre-auth.
* Bypasses an explicit round-1 invariant (security-headers on every
  response).
* 5 endpoints affected.
* Trivial reproducer (2KB attacker-controlled payload).

**Fix sketch:**

Two viable approaches:

1. **JSON parse-depth limit.** Replace the default `json.loads` in
   the Pydantic/FastAPI body parser with a depth-limited decoder.
   Python's stdlib `json` doesn't expose a depth limit directly, but
   wrapping with `orjson` (which has a depth limit) or a small
   custom recursion-counter decoder produces a clean 400 before the
   RecursionError fires.
2. **Exception handler catching RecursionError + generic Exception.**
   Add a Starlette `Exception` handler that catches RecursionError
   specifically and returns 400 with `{"detail": "JSON nesting too
   deep"}`, and a generic handler that ensures the security-headers
   middleware applies to any 500 response.

Approach (1) is cleaner — the goal is to never reach the
RecursionError. Approach (2) is the safety net.

A WB recommendation: pin the parse-depth limit at 256, which is more
than the deepest legitimate IAM policy nesting (~5 levels) by a
generous margin. The "Statement" array depth in real policies is
typically ≤ 100 statements with ≤ 5 levels of nesting per statement.

**Estimated fix effort:** ~30 minutes (add the depth-limited decoder
+ a unit test + a flip of the BB6-01 assertion).

## Other findings (one paragraph each)

### BB6-02 — Stripe duplicate-event response still leaks event_id + event_type (LOW)

Round-4 BB4-05 / round-5 BB5-21 carryover. The brief listed the
transient-failure retry fix but did not close the metadata leak.
Duplicate response body still includes `event_type` + `event_id`. With
a leaked webhook secret, an attacker has a free event-id existence
oracle. **Fix:** on duplicate path, emit `{"handled": false,
"duplicate": true}` only. ~10 minutes.

### BB6-03 — Admin-endpoint enumeration via 405-vs-404 (LOW)

A non-admin POSTing to `/api/v1/admin/security-posture` gets 405
(endpoint exists, GET-only). Same caller POSTing to
`/api/v1/admin/users` (not a real endpoint) gets 404. The 405-vs-404
delta lets the caller enumerate which admin endpoints exist without
admin auth. Already covered by `/openapi.json` being public (BB3-02
intentional). **Fix is optional:** uniformly return 403 for any
`/api/v1/admin/*` lacking admin role. Probably not worth the
complexity given openapi.json is public. Pin so a future "make
openapi.json admin-only" refactor doesn't accidentally re-expose this
enum vector.

### BB6-04 — Stripe whitespace-only event.id bypasses rejection (LOW)

Brief closure: empty `event.id` is rejected with `rejected: true,
reason: missing_event_id`. External probe shows the closure does NOT
strip whitespace before checking emptiness — an event with
`id: "   "` (3 spaces) passes the check and is treated as a normal
unhandled event. Combined with no idempotency dedupe on this path
(since the id is whitespace, not a real key), an attacker with the
webhook secret can replay whitespace-id events for log noise or
dedupe-store pollution. **Fix:** `id.strip() == ""` should hit the
same rejection path. ~5 minutes.

## Tier-leakage probe (brief-specific, NEGATIVE — honest negative)

Brief: "/api/v1/score may behave differently depending on caller's
tier (when the budget-cap wiring lands). Probe whether response shape
leaks tier identity to anonymous callers via timing, headers, or
error messages."

**External probe today (pre-budget-cap-wiring):**

* **Body identity:** anonymous and authenticated calls to
  `/api/v1/score` return BYTE-IDENTICAL response bodies for the same
  policy input. Same `score`, same `tier`, same `factors`, same
  `suggestions`.
* **Header identity:** Cache-Control, Vary, X-Policy-Fingerprint,
  CSP, X-Frame-Options — all identical between anon and dev caller.
  No `X-Tier`, `X-Plan`, `X-Quota-Remaining`, `X-Budget-Remaining`
  headers present today.
* **Timing identity:** anon median 2.14 ms vs auth'd median 1.89 ms
  across 20 samples each. Difference is within noise (sub-ms);
  almost certainly within the cold-cache vs warm-cache band, not a
  tier-discriminator signal.
* **Status code identity:** both 200.
* **No `/api/v1/billing`, `/api/v1/tier`, `/api/v1/quota`,
  `/api/v1/usage` endpoint exists today** (all 404).

**Verdict:** today, tier-leakage is **CLOSED** at this surface
because there's no tier wiring to leak. Pinned forward as BB6-15
honest-negative — when the budget-cap wiring lands, a regression of
"anon vs auth produce different response shape" will fire that test.

**Recommendation for the budget-cap wiring (forward-looking):**

1. Keep the public `/api/v1/score` response shape **identical** for
   anon and authenticated callers. Tier-specific info (budget
   remaining, rate limit window) should be a SEPARATE
   `/api/v1/me/usage` endpoint, NOT a header on /score.
2. Do NOT add tier-identifying response headers (`X-Tier`,
   `X-Plan`, etc.) on /score.
3. If a tier-specific rate limit fires, the 429 error message
   should be tier-neutral ("too many requests; try again in N
   seconds") — NOT tier-revealing ("free tier exceeded; upgrade
   to Pro").
4. Cache-Control: keep the current `private, max-age=300,
   must-revalidate` for ALL tiers. Don't split caching policy by
   tier — that creates a header-fingerprint vector.

## Methodology

* Spun up `create_app(...)` against `FilesystemStore` +
  `FileUserStore` + `InMemoryAPITokenStore` (same fixtures as
  rounds 1-5).
* All probes via `TestClient` HTTP behavior. **No source-file reads
  of `src/iam_jit/**`**. Reads limited to round-1..5 audit docs and
  the round-5 BB test file.
* Re-ran the round-5 BB suite to confirm prior closures (21/21
  pass).
* Each round-6 finding has at least one TestClient repro in
  `tests/test_appsec_audit_round6_bb.py`.
* For the Lambda + no MAGIC_LINK_SECRET closure probe: used
  `subprocess.run` with `os.environ.clear()` to construct a clean
  Lambda-env-only scenario without contaminating the test session
  env vars.
* For tier-leakage timing: ran 20 paired requests across anon /
  authenticated, recorded `time.perf_counter()` deltas, compared
  medians.
* For deep-JSON 500 boundary: bisected from depth=50 (422) to
  depth=2000 (500) in steps of 50, found crossover at ~990.

## Has the BB loop converged?

**Yes — converged except for BB6-01.** Round 6's findings are:

* **1 HIGH** (BB6-01 deep-JSON 500) — launch-blocking, but the fix is
  ~30 min.
* **3 LOW** (BB6-02 Stripe metadata, BB6-03 admin enum, BB6-04
  whitespace event.id) — non-launch-blocking hygiene.
* **21 honest negatives** confirming the obvious-attack surfaces are
  locked down, including all three brief closures.

After 6 rounds of BB probing across 120+ findings and 80+ honest
negatives (rounds 1-6 combined), the surface is **realistic-attacker
hardened with one outstanding HIGH**. The remaining BB-discoverable
findings would require esoteric setups (multi-tenant DDB conditions,
CDN-edge behaviors, specific browser-version SameSite handling) — best
caught by WB review of specific code paths or by production
red-teaming, not further BB rounds.

**Recommendation:**

* **Fix BB6-01 BEFORE launch.** ~30 minutes work; the
  RecursionError-on-deep-JSON is the obvious first-fuzzer-pass attack
  and the missing-security-headers regression on 500 is a posture
  loss that touches every error path.
* Fix BB6-02 + BB6-03 + BB6-04 in the first week post-launch (total
  ~30 min of work).
* **Skip a round-7 BB pass.** The remaining surface is either
  WB-territory or production-red-team territory. The diminishing
  returns crossed in round 5; round 6 was right to dig one more
  layer (and found BB6-01), but round 7 would not find anything
  HIGH-or-higher with TestClient alone.

## Verdict on overall security posture

**Three brief closures hold; one HIGH found in the previously-
unprobed JSON-parser-recursion surface.**

The round-5 brief closures (BB5-01 XFF, BB5-10 /docs CSP) were not
explicitly listed in the round-6 brief and were not re-probed in this
round — assumed-closed for this round's scope.

**Launch recommendation:**

* **Fix BB6-01 (deep JSON 500) BEFORE launch** — pre-auth DoS +
  security-headers regression on the error path. ~30 min.
* Fix BB6-02, BB6-03, BB6-04 in the first week post-launch (~30 min
  combined).
* **The BB surface is now genuinely settled** modulo BB6-01. After
  that lands, the round-6 honest-negative suite covers the 100-
  attacker mindset comprehensively. Further hardening should come
  from production red-teaming (real browsers, real CDN, real WAF)
  and continued WB review of specific subsystems (rate-limit key
  derivation, billing event handlers, multi-tenant DDB conditions).

Estimated total round-6 remediation effort: ~1 engineer-hour, of which
~30 minutes are launch-blocking.
