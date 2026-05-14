# iam-jit black-box appsec audit — round 3 (2026-05-14)

Round-3 external-researcher probe — the launch-day perspective. Rounds 1 and 2 closed (or pinned) the CSRF, magic-link-log, XFF-trust, and Stripe-idempotency clusters. The first 100 attackers hitting the public URL on launch day are looking for: free recon, unauthenticated cost-amplification, broken auth invariants ("logout that doesn't logout"), and check-then-act races on the now-atomic webhook claim. This round looks specifically at: surfaces re-exposed by the round-1/2 fixes, surfaces no prior round actually probed in depth, and the public-recon channel (`/healthz`, `/openapi.json`, `/docs`).

Each finding has a corresponding pytest case in [`tests/test_appsec_audit_round3_bb.py`](../../tests/test_appsec_audit_round3_bb.py). Convention is unchanged from rounds 1 and 2: broken-behavior tests assert the *vulnerable* state (flip the assertion when fixing); honest-negative tests assert the *defended* state (protect against regression).

## Totals

| Severity | Count |
| -------- | ----- |
| CRIT     | 0     |
| HIGH     | 2 (BB3-01, BB3-02) |
| MED      | 4 (BB3-03, BB3-04, BB3-05, BB3-06) |
| LOW      | 4 (BB3-07, BB3-08, BB3-09, BB3-10) |
| Honest negatives | 5 (BB3-11..BB3-15) |
| Round-1/2 re-tests | 3 (BB3-16, BB3-17, BB3-18) |
| **TOTAL new findings** | **10** |

No criticals. The HIGH cluster is two launch-blocking gaps: (a) `/api/v1/auth/logout` doesn't actually invalidate the cookie server-side — a stolen cookie remains valid for its full 24h TTL after the user clicks "Sign out"; (b) `/openapi.json` 500s on every request due to a pydantic forward-ref bug, which both breaks public API consumers and is a noisy recon signal that "something is off" with this deployment. The MEDs cluster around launch-day recon (`/healthz` still leaks the full security_posture; Stripe webhook signature error echoes server timestamp; Stripe idempotency skipped when `event.id` is missing/empty) and a still-open round-1 CSRF on HTML token-mint.

## Severity breakdown by finding id

### HIGH

| id | title |
| -- | ----- |
| BB3-01 | `POST /api/v1/auth/logout` is client-side only — old cookie remains valid |
| BB3-02 | `GET /openapi.json` returns 500 (pydantic ForwardRef Response unresolved) |

### MED

| id | title |
| -- | ----- |
| BB3-03 | `/healthz` still leaks full `security_posture` (BB-13 regression class — re-confirmed) |
| BB3-04 | Stripe webhook signature-error response echoes server-side `now=<epoch>` |
| BB3-05 | Stripe webhook with empty/missing `event.id` is replayable indefinitely |
| BB3-06 | HTML `POST /tokens` still mints token on cookie-only request (BB-02 re-confirmed open) |

### LOW

| id | title |
| -- | ----- |
| BB3-07 | `GET /docs` (Swagger UI) renders against a broken `/openapi.json` |
| BB3-08 | Score endpoint rate-limit keys on peer IP only — co-tenant DoS via shared NAT |
| BB3-09 | `/api/v1/requests/preview` reflects raw user input in JSON error body |
| BB3-10 | Stripe webhook detail messages contain payload-shape information |

### Honest negatives (defended classes)

| id | class |
| -- | ----- |
| BB3-11 | Stripe webhook atomic-claim holds under concurrent replay (BB2-04 retest) |
| BB3-12 | Magic-link per-IP rate limiter survives rotating XFF spoof (XFF default-off) |
| BB3-13 | Cookie tampering still rejected with `SameSite=strict` upgrade observed |
| BB3-14 | `POST /requests/new/chat` (HTML) refuses cookie-only cross-origin POST |
| BB3-15 | Session cookie is `SameSite=Strict` on auth callback (round-1 BB-01 chain partially closed) |

### Round-1/2 retests (closures confirmed externally)

| id | round-1/2 finding | status |
| -- | ----------------- | ------ |
| BB3-16 | BB-12 magic-link log channel — fingerprint-only emit | HOLDING |
| BB3-17 | BB2-04 Stripe atomic claim under concurrent redelivery | HOLDING |
| BB3-18 | BB2-09 magic-link XFH host-header poisoning | HOLDING |

## Top 3 launch-critical findings

### 1. BB3-01 — `POST /api/v1/auth/logout` is client-side-only (HIGH)

When a user signs out (via either `POST /api/v1/auth/logout` or `GET /logout`), the server returns `Set-Cookie: iam_jit_session=""; Max-Age=0`. That clears the cookie in the browser the user clicked from — but the cookie VALUE is still a valid signed-timed token. An attacker who exfiltrated the cookie value before the user clicked "Sign out" (via XSS-on-co-located-subdomain, packet sniff on a downgraded request, shared device, ALB access log, browser extension) can keep using the cookie for the full TTL (`Max-Age=86400` = 24h).

Reproducer (TestClient): sign a cookie, hit `/api/v1/users/me` → 200, POST `/api/v1/auth/logout` → 200, instantiate a fresh TestClient, set the same cookie value, hit `/api/v1/users/me` → still 200. Documented in `test_bb3_01_logout_does_not_invalidate_cookie_server_side`.

**Why HIGH at launch:** "Sign out" is the user-visible recovery for "I lost my laptop / my cookie leaked / I'm leaving a shared device." Today the only true revocation is waiting 24h for the cookie to time-expire. This is the kind of finding a competent external researcher files within the first hour and headlines on Twitter.

**Fix sketch:** server-side session blacklist. On logout, store `(cookie_signature, expires_at)` in a small DDB table with TTL. The auth middleware checks the blacklist (single GetItem per request) before honoring a cookie. Alternative: tie the cookie value to a per-user epoch counter; logout bumps the counter; cookies with an older counter are rejected. Either fix collapses logout-to-true-revocation.

### 2. BB3-02 — `/openapi.json` 500s (HIGH, availability/recon)

`GET /openapi.json` returns 500 on every request. The traceback (when `raise_server_exceptions=True`) shows pydantic raising `PydanticUserError: TypeAdapter[Annotated[ForwardRef('Response'), ...]] is not fully defined`. Something added a `Response` annotation that pydantic can't resolve at schema-build time.

**Why HIGH at launch:** 
1. *Functional outage*: API consumers (the MCP server, the CI/CD GitHub Action, third-party SDK generators) cannot fetch the schema. `GET /docs` returns HTML but the embedded Swagger UI fetches `/openapi.json` client-side → users see a broken Swagger page with `Failed to load API definition`.
2. *Recon signal*: an attacker hitting `/openapi.json` and seeing 500 immediately knows the deployment has unhandled exceptions on a critical public route. They probe harder.
3. *Trust*: launch-day customers running `curl /openapi.json | grep` to learn the API will hit 500 and bounce.

**Fix sketch:** find the route or pydantic model declaring `Response` (likely a Union/discriminated type) without an explicit `model_rebuild()` call. Either rebuild explicitly at app startup, or annotate with the resolved `starlette.responses.Response` type.

### 3. BB3-05 — Stripe webhook with empty/missing `event.id` replayable indefinitely (MED, billing-integrity)

The round-2 fix landed `processed_events_store.claim(event_id)` as the gatekeeper. Probe shows that when the event body has `"id": ""` (empty string) OR omits the `id` field entirely, the webhook returns 200 every time with no `duplicate=True` marker — i.e. the claim either short-circuits or claims the empty string once and the second call would dedupe, but in practice all three calls return non-duplicate.

Reproducer: send a signed `{"type": "customer.created", "data": {"object": {}}}` payload (no `id`) three times → all three return `{"handled": False, "event_type": "customer.created"}` with no `duplicate` flag.

**Impact today is small** because no handler currently runs for malformed events (`handled: False`). But:
1. Future handlers will trigger N times when Stripe sends N retries.
2. An attacker who forges a payload with empty `id` and a valid signature (which Stripe will *never* generate for real, but an operator's leaked webhook secret means signature is no longer the gate) can pump the audit log / billing-event-log endlessly.

**Fix sketch:** reject events with `event_id in (None, "")` BEFORE the handler dispatch — 400 with a clear message. Stripe always populates `event.id` (it's a required field in their schema) so rejecting empties is correct.

## Other findings (one-paragraph each)

### BB3-03 — `/healthz` still leaks full security_posture (MED)

Round 1 filed BB-13 LOW asking for `/healthz` to shrink to `{"status":"ok"}`. Round 3 retest: the endpoint returns a JSON blob with `status`, `version`, `auth_mode`, `user_config_source`, `llm_backend`, AND the full `security_posture` object including the `issues` array with `detail` and `fix` strings. A launch-day attacker hits `/healthz` first and learns:
- the auth mode (`local`),
- whether SES is configured (`ses_configured: false`),
- whether ALB is in front (`alb_in_front: false`),
- whether HTTPS is set up (`alb_has_https_cert: false`),
- the literal text of the `no_ses` issue including the fix recommendation,
- the magic-link delivery channel (`in_response`).

Same severity as round 1 (LOW for recon-only), but bumped to MED here because the `issues[].detail` field includes operational hints like "the link appears in any browser that observes the response, including via shoulder-surfing or browser history." That tells the attacker exactly which attack to run. **Fix sketch:** keep `/healthz` as `{"status":"ok"}`; serve the posture at the admin-gated `/api/v1/admin/security-posture` (which already exists).

### BB3-04 — Stripe error response echoes server `now=<epoch>` (MED, info leak + clock skew gadget)

When the Stripe signature verification fails due to timestamp outside the 300s window, the 400 response body includes:
```
"signature verification failed: Stripe-Signature timestamp 1810283285 is outside the 300s tolerance window (now=1778747285)"
```
The `now=1778747285` is the server's wall-clock epoch. An attacker pings the webhook with a deliberately-bad signature and gets a free clock-sync gadget — useful for synchronizing replay attacks against time-windowed tokens (e.g. coordinating a magic-link replay across regions / instances if the WB-MAGIC-LINK-REPLAY-MULTI-INSTANCE finding is still open). **Fix sketch:** error message can stay informative for legit operators (Stripe-side debugging) but should NOT reveal the server's now. Reduce to `{"detail": "signature verification failed"}` and log the diagnostics server-side.

### BB3-06 — HTML `POST /tokens` still mints on cookie-only POST (MED, round-1 BB-02 retest)

The round-1 BB-02 finding (HTML token-mint accepts cookie-only POST → CSRF token-mint primitive) is still open. Probe confirms: `dev.post("/tokens", data={"label":"csrf-mint"}, headers={"Referer":"https://evil.example.com/"})` returns 200 and the token count goes 0 → 1. The session cookie's `SameSite=Strict` (BB3-15 closure) mostly mitigates this for top-level cross-origin form posts in modern browsers — but the JSON `POST /api/v1/tokens` accepts the SAME cookie-only request, and `SameSite=Strict` is bypassed by any flow where the attacker can get the victim to navigate top-level to iam-jit and then trigger a same-site JS (e.g. an open-redirect chain). Pin as MED to track the still-open intent.

### BB3-07 — `/docs` Swagger UI renders against broken `/openapi.json` (LOW, UX/trust)

Pair finding to BB3-02. `GET /docs` returns the Swagger HTML 200, but the embedded swagger-ui.js fetches `/openapi.json` client-side and gets 500. Launch-day API consumers see "Failed to load API definition" in red on the docs page. Not a security issue per se, but it's the *first* impression a customer running `curl URL/docs` makes — and they file a bug report or move on.

### BB3-08 — Score endpoint rate-limit keys on peer IP — co-tenant DoS via shared NAT (LOW)

`POST /api/v1/score` rate limiter throttles by peer IP. Two authenticated users behind the same corporate NAT / consumer ISP CGNAT share the bucket. A noisy neighbor (or an attacker who knows the target's NAT egress IP) can pin the bucket at 429 for everyone behind that IP. Probe: dev user bursts 100 score calls (70 × 429, 30 × 200), then a separate admin via Bearer token from the same client also gets 429 — they share the bucket. **Fix sketch:** authenticated requests should rate-limit by `(user_id, IP)` tuple; unauthenticated requests stay IP-only. Add a per-user soft cap (e.g. 60 score/min/user) on top of the per-IP cap.

### BB3-09 — `/api/v1/requests/preview` reflects raw user input in JSON error body (LOW)

Sending `{"spec":{"description":"<script>alert(1)</script>"}}` to `/api/v1/requests/preview` returns a 200 with `schema_errors[].text` containing `"{'description': '<script>alert(1)</script>'} is not valid under any of the given schemas"`. Content-Type is `application/json` so the XSS doesn't fire in browsers — but a debug console / a markdown-rendering log viewer / a webhook-relay-to-Slack downstream would render it. Low priority; standard "don't echo user input in error messages" hygiene. **Fix sketch:** sanitize / truncate user-provided fields in schema-error rendering. Or just emit `"schema_errors": ["field 'description' is invalid"]` without the value.

### BB3-10 — Stripe webhook detail messages contain payload-shape info (LOW)

When sending a syntactically-valid-but-semantically-empty Stripe webhook, the response includes the `event_type` that was sent, even when the signature was forged from a known secret. E.g. `{"handled": false, "event_type": "evil.type.no.id"}` confirms to an attacker that they can name any `event_type` they want and the server records it. Useful for finding which event types ARE handled (the attacker probes systematically and learns from `handled: True/False`). Already implicitly known via Stripe docs, so the leak is small — but combined with BB3-05 (no event_id required) it gives an attacker a free "event type enumeration" oracle. **Fix sketch:** drop the `event_type` field from the response body for non-handled events.

## Honest negatives — defended classes re-confirmed

### BB3-11 — Stripe atomic claim under concurrent replay holds

Probe runs 5 concurrent threads racing the same signed event under a barrier. Exactly 1 returns `{handled: False}` first-time; the other 4 return `{handled: False, duplicate: True, event_id: "..."}`. The round-2 BB2-04 atomic-claim fix is robust under contention.

### BB3-12 — Magic-link IP-limiter immune to XFF spoofing

With XFF trust default-off (round-2 BB2-02 closure), a TestClient burst with rotating `X-Forwarded-For: 1.2.3.{i}` headers still gets 429 after the soft cap. The limiter correctly keys on the peer (`testclient` / `127.0.0.1`), not the spoofed XFF.

### BB3-13 — Session cookie is `SameSite=Strict` on auth callback

Round-1 BB-01..BB-04 noted `SameSite=Lax` allowed CSRF via form submission. Probe confirms the cookie now ships as `SameSite=strict` on the auth-callback path. The HTML form CSRF surface still exists (BB3-06) but the `Strict` upgrade meaningfully shrinks the attack window for top-level cross-origin form posts in modern browsers.

### BB3-14 — `POST /requests/new/chat` refuses cookie-only POST

A round-3 anti-regression check: the HTML `/requests/new/chat` endpoint refuses cookie-only POST with 403 (CSRF token / origin check is enforced). This is the round-1 BB-01 fix landed on this specific HTML route.

### BB3-15 — Tampered cookie still rejected (round-1 BB-22 retest)

Tampered cookie value (last 2 chars flipped) → 401 across all probed endpoints. Wrong-secret-signed cookie → 401. Unsigned plaintext `email:admin@example.com` → 401. itsdangerous URLSafeTimedSerializer signature verification holds.

## Methodology

- Spun up `create_app(...)` against `FilesystemStore` + `FileUserStore` + `InMemoryAPITokenStore` (same fixtures as round 1 + 2).
- All probes through `TestClient` HTTP behavior. No source-file reads of `src/iam_jit/**`; reads limited to round-1/2 audit docs, round-1/2 BB test files, and `docs/` user-facing docs.
- Re-ran the round-1 + round-2 BB suites to capture the current pinned state of every prior finding. The round-2 closure list (XFF gates, atomic claim, host-header gate, log-channel fingerprint) all verified externally.
- Each round-3 finding has at least one TestClient repro in `tests/test_appsec_audit_round3_bb.py`.

## Did the round-1 + round-2 fixes hold externally?

| Finding | Status | Notes |
| ------- | ------ | ----- |
| BB-12 / BB2-08 magic-link log channel | **HOLDING** | Default fail-closed; `IAM_JIT_ALLOW_LOG_CHANNEL=1` emits `link_fingerprint=<hex>` only, never the URL. |
| BB-13 `/healthz` posture leak | **NOT HOLDING** | Still emits the full security_posture object. Re-filed as BB3-03. |
| BB-09 magic-link rate limit | **HOLDING** | Soft cap returns 429 after configured limit; XFF spoof does not bypass. |
| BB2-02 network-acl XFF trust default-off | **HOLDING** | Empty `IAM_JIT_TRUSTED_PROXY_CIDRS` correctly causes ACL to fall back to peer IP. |
| BB2-04 Stripe atomic claim | **HOLDING** | 5-thread concurrent replay correctly returns 4 duplicates. |
| BB2-05 token-mint per-user cap | **HOLDING** | Default cap is 50; configurable; 51st mint returns 429. |
| BB2-09 XFH host-header poisoning | **HOLDING** | Magic-link does not honor `X-Forwarded-Host` unless 3-of-3 (env + CIDR + allowlist) conditions met. |
| BB2-10 admin self-demote / last-admin lockout | **OPEN (round-2 status was MED, not fixed)** | Not re-probed this round; out of scope for round 3 (focus is on external/launch-day primitives, not admin-vs-admin invariants). |
| BB-01 HTML approve CSRF | **OPEN** | Still vulnerable. SameSite=Strict mitigates partially. Out of scope for round 3 retest beyond confirming class is alive. |
| BB-02 HTML token-mint CSRF | **OPEN** | Re-filed as BB3-06. |

## New surprises this round

1. **`SameSite=Strict` upgrade on session cookies** — round 1 noted `SameSite=Lax`. The auth-callback now sets `Strict`. Good move; not announced in either prior audit doc, so a fix author re-reading those docs might re-introduce `Lax` thinking the cookie was always that way. The closure tests in `test_appsec_audit_round3_bb.py::test_bb3_15_session_cookie_samesite_strict` pin the new behavior so a regression here will fail.
2. **`POST /api/v1/auth/logout` exists** — round 1 only probed `GET /logout`. Round 3 probed `POST /api/v1/auth/logout` and found the SAME server-side-non-invalidation bug. Both routes need the fix.
3. **`/openapi.json` is broken** — not flagged in any prior round because rounds 1/2 didn't `GET /openapi.json` directly. It's the kind of bug that an external researcher running `curl URL/openapi.json` notices in their first 30 seconds. Launch-blocker.

## Verdict on overall security posture

**Solid, with two launch-day cleanup items.** The core multi-tenant + auth-signature + webhook-idempotency invariants hold. The round-2 fixes (XFF gates, atomic claim, host-header gate, log-channel fingerprint) all confirmed externally. The HIGH findings this round are operational/availability (BB3-02 openapi-500) and a missed primitive (BB3-01 logout-not-revocation). Both are mechanical fixes (~1 engineer-day combined). The MED findings are launch-day recon hardening: trim `/healthz`, redact Stripe error verbosity, validate Stripe `event.id` is non-empty. The `/tokens` HTML CSRF (BB3-06 / round-1 BB-02 retest) is the lone "still open" round-1 issue that compounds with everything else in the HTML-form surface — recommend bundling its fix with the CSRF token middleware that the round-1 audit doc already prescribed.

Estimated remediation effort:
- BB3-01 logout-blacklist: ~3-4 hours (DDB table + middleware check).
- BB3-02 openapi-500: ~1-2 hours (find the unresolved ForwardRef, add `model_rebuild()`).
- BB3-03 healthz trim: ~30 minutes (remove fields from the response model).
- BB3-04 stripe-error verbosity: ~15 minutes.
- BB3-05 stripe-event-id validation: ~30 minutes.
- BB3-06 HTML token-mint CSRF: bundled with the round-1 CSRF fix (estimated separately in BB-01..BB-04).

Total ~1 engineer-day of remediation for the round-3 backlog. No findings warrant blocking launch beyond BB3-01 (logout-revocation) and BB3-02 (openapi-500), which between them are half a day.
