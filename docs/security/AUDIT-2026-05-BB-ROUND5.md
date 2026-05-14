# iam-jit black-box appsec audit — round 5 (2026-05-14)

Round-5 external-researcher probe. Round 4 closed three MEDs (score
Cache-Control over-aggressive, auth'd PII no Cache-Control, /docs CSP
vs CDN block — note: BB4-03 still open per round-5 finding below).
Round 5's brief: re-probe each round-4 closure stated in the brief,
look for regressions, and cover probe categories not yet audited
(HEAD/OPTIONS, path traversal, request smuggling, compression bombs,
long path / oversize header / null-byte handling).

Each finding has a corresponding pytest case in [`tests/test_appsec_audit_round5_bb.py`](../../tests/test_appsec_audit_round5_bb.py). Convention unchanged: broken-behavior tests assert the **vulnerable** state (flip on fix); honest-negative tests assert the **defended** state (regression guard).

## Totals

| Severity | Count |
| -------- | ----- |
| CRIT     | 0     |
| HIGH     | 0     |
| MED      | 2 (BB5-01, BB5-10) |
| LOW      | 5 (BB5-02..BB5-05, BB5-21) |
| Honest negatives | 14 (BB5-06..BB5-09, BB5-11..BB5-20) |
| **TOTAL new findings** | **7** (1 regression of brief, 1 contradiction of brief, 5 new minor) |

**Two findings contradict the brief's stated closures**:

* **BB5-01 (MED, regression)** — the brief states "Magic-link IP limiter buckets on the real-client IP (via XFF + trusted-proxy gate) not just peer.host." External probe shows distinct XFF values from the same TestClient peer all share one bucket. Even with `IAM_JIT_TRUST_FORWARDED_FOR=1` and a wide-open trusted-proxy CIDR (`0.0.0.0/0`) set BEFORE app creation, phase-A 5 requests under XFF=A burn the soft cap, and phase-B 5 requests under XFF=B from the same peer all 429. The limiter still keys on peer.host. **Production blast radius behind ALB: 5/min magic-link issuance shared across the entire user population**, because every legit request has the same ALB internal peer IP.

* **BB5-10 (MED, contradicts brief)** — the brief states "/docs Swagger UI renders." External probe shows /docs returns 200 HTML referencing `cdn.jsdelivr.net/npm/swagger-ui-dist@5/...` while the CSP header is still `script-src 'self'` (no CDN allowance). Visually the page is broken in any modern browser. **BB4-03 is NOT closed** despite the brief implying it is.

Everything else the brief described as closed is verified holding: score Cache-Control tightened (private/300/must-revalidate), auth'd PII Cache-Control (no-store/private), logout revocation on both POST and GET routes, Stripe sig failure uniform, Stripe rejected/unhandled body shape, Lambda+no-DDB → 503, DEV_INSECURE_SECRET refused in Lambda.

## Severity breakdown by finding id

### MED

| id | title |
| -- | ----- |
| BB5-01 | Magic-link IP limiter does NOT bucket on XFF — buckets on peer.host (regression of brief's closure; behind ALB: 5/min total across all users) |
| BB5-10 | /docs Swagger UI still CSP-blocked from loading CDN scripts (brief said this was closed; BB4-03 is still open) |

### LOW

| id | title |
| -- | ----- |
| BB5-02 | HEAD on auth'd /api/v1/* routes returns 405 + Cache-Control header WITHOUT auth (Allow header confirms supported method — recon-assist, but openapi.json is public so minor) |
| BB5-03 | /api/v1/auth/logout accepts cross-origin POST without Origin/Referer check — CSRF-logout possible if SameSite not enforced by browser |
| BB5-04 | /api/v1/score `Vary: Authorization` doesn't include `Cookie` — multi-user-shared-browser cache collision (narrow) |
| BB5-05 | /api/v1/* 404 responses ship `Cache-Control: no-store, private`; non-/api/v1 404s don't — prefix-fingerprint via response header |
| BB5-21 | Stripe duplicate-event response still leaks `event_type` + `event_id` (round-4 BB4-05 not yet closed; re-pinned) |

### Honest negatives — defended classes (closure re-pins)

| id | round-N closure / class | status |
| -- | ----------------------- | ------ |
| BB5-06 | HEAD /openapi.json + /docs return 200 (intentionally-public docs surface) | PINNED |
| BB5-07 | score Cache-Control tightened to `private, max-age=300, must-revalidate` (brief closure) | HOLDING |
| BB5-08 | All auth'd /api/v1/* endpoints emit `Cache-Control: no-store, private`; exemptions correct | HOLDING |
| BB5-09 | Logout revocation closure on both POST /api/v1/auth/logout AND GET /logout | HOLDING |
| BB5-11 | Magic-link in Lambda + no DDB → 503 (BB4-19 closure) | HOLDING |
| BB5-12 | IAM_JIT_DEV_INSECURE_SECRET=1 refused in Lambda (no dev_link short-circuit) | HOLDING |
| BB5-13 | Stripe webhook closures: empty event.id rejected, unhandled → {handled:false}, sig failure uniform | HOLDING |
| BB5-14 | OPTIONS preflight — no ACAO leak across third-party origins | HOLDING |
| BB5-15 | /static/ path-traversal — 404 across 10 standard payload variants | DEFENDED |
| BB5-16 | TE+CL smuggling combo refused 411; whitespace-prefixed TE also refused | DEFENDED |
| BB5-17 | Compression bomb (200MB→200KB gzip with Content-Encoding header) — 400 at JSON parse, no inflation | DEFENDED |
| BB5-18 | Long path / 100KB header / 2000 headers / 8KB cookie — handled without crash or 500 | DEFENDED |
| BB5-19 | NUL byte in URL path — 404, never reaches a file-handling code path | DEFENDED |
| BB5-20 | Method tampering (TRACE/CONNECT/PUT/PATCH/PROPFIND) — never 200, always 405/404 | DEFENDED |

## Top 3 launch-critical findings

### 1. BB5-01 — Magic-link IP limiter doesn't bucket on XFF (MED, regression)

**Brief claim:** "Magic-link IP limiter buckets on the real-client IP (via XFF + trusted-proxy gate) not just peer.host."

**External probe:** with `IAM_JIT_TRUST_FORWARDED_FOR=1` and `IAM_JIT_TRUSTED_PROXY_CIDRS=0.0.0.0/0` set BEFORE `create_app` is called:

```
Phase A: 5 requests with X-Forwarded-For: 203.0.113.1
         → 5x 202 (under the soft cap for that XFF)
Phase B: 5 requests with X-Forwarded-For: 203.0.113.99
         → 5x 429 (sharing phase A's bucket)
```

If the limiter bucketed on XFF, phase B would have its own fresh 5/min budget. The fact that phase B 429s with no shared XFF confirms the bucket key is peer.host.

**Production blast radius:** behind an ALB / API Gateway / CloudFront, every legit request to iam-jit comes from the upstream proxy's internal IP. If the limiter buckets on peer.host:

* The 5/min soft cap and 15/min hard cap are **shared across the entire user base**.
* On launch day, 5 magic-link requests per minute is the entire global limit.
* An attacker forging XFF doesn't bypass the limit either, but a legitimate signup spike will trip the limit and lock out new users globally.

**Reproducer:**

```python
monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "0.0.0.0/0")
# build app
c = TestClient(app)

# 5 reqs with XFF=A
for _ in range(5):
    c.post("/api/v1/auth/magic-link",
           json={"email":"dev@example.com"},
           headers={"X-Forwarded-For": "203.0.113.1"})  # all 202

# 5 reqs with XFF=B from same peer
for _ in range(5):
    r = c.post("/api/v1/auth/magic-link",
               json={"email":"dev@example.com"},
               headers={"X-Forwarded-For": "203.0.113.99"})
    assert r.status_code == 429  # currently regressed
```

**Fix sketch:** in the rate-limit key derivation for `/api/v1/auth/magic-link`, when `IAM_JIT_TRUST_FORWARDED_FOR=1` AND peer.host falls inside `IAM_JIT_TRUSTED_PROXY_CIDRS`, derive the bucket key from the leftmost (or rightmost-trusted) hop of XFF. Fall back to peer.host only when the trusted-proxy gate rejects the XFF source. The same logic is presumably already implemented for audit-log IP fields elsewhere in the codebase — share it.

### 2. BB5-10 — /docs Swagger UI still CSP-blocked from CDN (MED, brief contradiction)

**Brief claim:** "/openapi.json returns 200 with full schema; /docs Swagger UI renders."

**External probe:**

* `/openapi.json` — 200, openapi 3.1.0, full schema with 60+ paths. ✓
* `/docs` — 200, HTML body references `cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js`.
* Response CSP header on /docs is `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; ...` — the CDN is NOT whitelisted.

In a modern browser, the CDN script is blocked by CSP and the Swagger UI page renders blank. Same launch-day "broken docs" first-impression as BB3-07 and BB4-03. The /openapi.json closure landed but the /docs UI closure did NOT (despite the brief implying it).

**Why MED, not LOW:** launch-day API consumer first-impression is the docs page. A blank-rendering docs page reads as "broken product, abandon." This is a discoverable trust gap.

**Fix sketch (same as round 4):** either (a) self-host swagger-ui-dist behind `/static/swagger/` and configure FastAPI's `swagger_js_url` + `swagger_css_url` to point at the local path, or (b) per-route CSP override that adds `https://cdn.jsdelivr.net` to script-src / style-src on the /docs + /redoc paths only.

### 3. BB5-03 — /api/v1/auth/logout accepts cross-origin POST (LOW, but launch-day-class)

`POST /api/v1/auth/logout` with `Origin: https://evil.example.com` and `Referer: https://evil.example.com/exploit` returns 200 and revokes the cookie. No Origin / Referer / CSRF-token check at the app layer.

**Why launch-class despite LOW:** the impact (force-logout of a user) is annoyance-class, not account-takeover-class — but at scale, a coordinated CSRF-logout campaign targeting authenticated users via an attacker page is a denial-of-use vector. Defense-in-depth at the app layer would catch the case where a browser respects SameSite less strictly than expected (older browsers, Safari ITP edge cases).

**The current defense:** the auth-callback Set-Cookie is `SameSite=Strict` (BB3-15 closure). Modern browsers refuse to send Strict cookies on cross-origin POSTs initiated from an attacker page. So in practice the cookie isn't sent, and the cross-origin logout fails at the cookie level — not at the app level.

**Why pin anyway:** a future refactor that loosens the auth-callback cookie to `SameSite=Lax` (which is technically necessary if iam-jit ever wants to support top-level navigation flows) re-opens the CSRF-logout vector. An Origin/Referer allowlist at the route layer would catch the regression.

**Fix sketch:** add an Origin-allowlist check to the `/api/v1/auth/logout` route. For deployments behind a known origin, reject POSTs whose Origin doesn't match. For the Bearer-token logout case (programmatic), the Bearer header itself is the auth.

## Other findings (one-paragraph each)

### BB5-02 — HEAD on auth'd routes leaks Cache-Control + Allow without auth (LOW)

`HEAD /api/v1/users/me` (no auth) returns 405 with `Allow: GET`, `Cache-Control: no-store, private`, and the full security-headers chain (CSP, X-Frame-Options, etc). The 405 + Allow combination confirms the route exists and which method it supports — an unauth attacker can enumerate every `/api/v1/*` endpoint's method set this way. Recon-assist value is small because `/openapi.json` is intentionally public (BB3-02 closure); the same enumeration is available there. **Severity: LOW** — informational. Fix is optional; pin so a future refactor that makes openapi.json admin-only doesn't accidentally re-expose this enumeration vector.

### BB5-04 — Score endpoint Vary missing Cookie (LOW)

`POST /api/v1/score` returns `Cache-Control: private, max-age=300, must-revalidate` (BB4-01 closure) with `Vary: Authorization`. The `Vary` header does NOT include `Cookie`. For cookie-auth users sharing a browser profile (kiosk, public terminal, multi-user account-switching), the same cache entry could be served across different cookie values. Body has no PII (it's a pure function of the policy), so the practical leak is "did this fingerprint get scored on this browser recently" — minor. **Fix:** change `Vary: Authorization` to `Vary: Authorization, Cookie` so cookie-auth users are properly cache-keyed.

### BB5-05 — /api/v1/* 404s emit no-store; non-api/v1 404s don't (LOW)

`GET /api/v1/nonexistent` returns 404 with `Cache-Control: no-store, private`. `GET /foo/bar` returns 404 with no Cache-Control. The difference lets a fuzzer distinguish `/api/v1/*` from other prefixes via response header alone, without consulting `/openapi.json`. Very minor — `/openapi.json` is the actual recon surface, this just saves the attacker a 62KB schema download. **Fix:** strip Cache-Control from 404 responses across the board (uniform), OR keep current behavior as "all auth'd-prefix responses no-store, regardless of status." Pinning the current behavior.

### BB5-21 — Stripe duplicate-event response still leaks event metadata (LOW, round-4 carryover)

BB4-05 found that duplicate Stripe events echo `event_type` + `event_id` in the response body. The round-5 brief listed Stripe closures (rejected, unhandled, sig-failure) but did NOT mention BB4-05 — re-probe confirms BB4-05 is still open. Body is `{"handled": false, "event_type": "...", "duplicate": true, "event_id": "..."}`. With webhook-secret leak, an attacker has a free event-id existence oracle. **Severity: LOW** (depends on webhook-secret leak). **Fix:** on duplicate path, emit `{"handled": false}` only (or `{"handled": false, "duplicate": true}` if a confirmation field is needed for operators).

## Honest negatives — defended classes

These tests pin the *defended* state so a future regression in the closure layer fails loudly.

### BB5-06 — HEAD on /openapi.json + /docs returns 200 (PINNED)

Both endpoints are intentionally public per BB3-02 closure. HEAD returns 200 with Content-Length (62KB schema; ~1KB /docs HTML). Pinned so a future refactor that makes openapi.json admin-only catches this leak.

### BB5-07 — Score Cache-Control tightened (HOLDING)

`POST /api/v1/score` ships `Cache-Control: private, max-age=300, must-revalidate`. The previous `public, max-age=3600, s-maxage=86400` is gone. CDN/proxy can no longer stale-serve scores past a 5-minute window. The adversarial-loop process moat is preserved.

### BB5-08 — All auth'd /api/v1/* endpoints emit no-store, private (HOLDING)

Verified across `/api/v1/users/me`, `/api/v1/tokens`, `/api/v1/requests/preview`, `/api/v1/users` (admin), `/api/v1/reports/grants` (admin). Exemptions correctly applied: `/api/v1/score` has its own private/300/must-revalidate; `/healthz`, `/docs`, `/openapi.json`, `/static/*` have no Cache-Control. No accidental over-correction.

### BB5-09 — Logout revocation HOLDS on both POST and GET routes

Saved-elsewhere copy of the cookie returns 401 after either `POST /api/v1/auth/logout` or `GET /logout`. Round-3 BB3-01 closure plus round-4 BB4-10 re-pin both verified.

### BB5-11 — Magic-link Lambda+no-DDB → 503 (HOLDING)

With `AWS_LAMBDA_FUNCTION_NAME` set and no DDB nonce table configured, `POST /api/v1/auth/magic-link` returns 503 with operator-guidance detail pointing at `IAM_JIT_MAGIC_LINK_NONCES_TABLE` / `IAM_JIT_ALLOW_INSECURE_NONCES` / `IAM_JIT_DEV_INSECURE_SECRET`. Multi-instance replay is closed.

### BB5-12 — DEV_INSECURE_SECRET refused in Lambda (HOLDING)

With `IAM_JIT_DEV_INSECURE_SECRET=1` and Lambda env detected and `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA` unset, magic-link does NOT short-circuit to a dev_link delivery. The route falls through to standard config (503 for missing nonce config). The dev short-circuit is closed in Lambda environments.

### BB5-13 — Stripe webhook closures HOLD

Empty event.id → `rejected: true`. Unhandled type → `{"handled": false}` only. Sig failure (garbage, missing, expired-timestamp) → uniform `{"detail": "signature verification failed"}`, no clock leak. BB3-04 + BB3-05 + BB3-10 closures all hold.

### BB5-14 — OPTIONS no ACAO leak (HOLDING)

`OPTIONS` preflight against `/api/v1/score`, `/users/me`, `/tokens`, `/auth/magic-link` from origins `https://evil.example.com`, `null`, `http://localhost:3000`, `https://iam-risk-score.com` all return 405 with no `Access-Control-Allow-Origin` and no `Access-Control-Allow-Credentials` headers. CORS middleware absent. Pinning protects against a "we want a browser SDK" refactor that adds reflective CORS (one of the top-3 ways to leak Bearer-token data cross-origin).

### BB5-15 — /static/ path traversal DEFENDED

Ten standard payload variants (`../`, URL-encoded `..%2F`, double-encoded `..%252F`, mixed-encoding, backslash, NUL byte, `.git/config`, `...//`) all 404. FastAPI's `StaticFiles` normalizes and rejects. No content leak from `/etc/passwd`, `[boot loader]`, `windows registry` strings.

### BB5-16 — TE+CL smuggling combo refused (HOLDING)

`Transfer-Encoding: chunked` + `Content-Length` together → 411. Whitespace-prefixed `Transfer-Encoding: chunked` (` chunked`) also → 411. The body-size middleware (BB4-16 closure) catches both the standard and the Cloudflare-research bypass variant.

### BB5-17 — Compression bomb DEFENDED

200MB of zeros compressed to 200KB with `Content-Encoding: gzip` header sent against `/api/v1/score` returns 400 at JSON parse. The server does NOT auto-decompress request bodies based on `Content-Encoding` (starlette/FastAPI behavior). Bomb does not inflate to 200MB of RAM. Note: a production deployment behind an ALB or CloudFront might decompress at the edge — but that hits the body-size limit before the app sees it.

### BB5-18 — Long path / oversize headers handled (DEFENDED)

8KB path → 404. 100KB single header → 200 on `/healthz`. 2000 small headers → 200. 8KB cookie → 200. No 500, no crash, no DoS. Upstream proxies (ALB caps headers at 32KB total; API GW at 10KB) will cap before this hits the app — at the app layer there's no app-level cap, which is fine.

### BB5-19 — NUL byte in URL path DEFENDED

`GET /healthz%00.json` and `GET /static/foo%00.jpg` both return 404. The percent-encoded NUL is treated as part of the path literal that doesn't match any route. No NUL byte reaches a file-handling code path.

### BB5-20 — Method tampering handled (DEFENDED)

`TRACE`, `CONNECT`, `PROPFIND`, `PUT`, `DELETE`, `PATCH` on routes that don't support them all return 405 or 404 — never 200. TRACE specifically (which has historic XST implications) is blocked. No method-tunneling vector.

## Methodology

* Spun up `create_app(...)` against `FilesystemStore` + `FileUserStore` + `InMemoryAPITokenStore` (same fixtures as rounds 1-4).
* All probes through `TestClient` HTTP behavior. **No source-file reads of `src/iam_jit/**`**. Reads limited to round-1/2/3/4 audit docs and round-4 BB test file.
* Re-ran the round-4 BB suite to confirm prior closures (23/23 pass).
* Each round-5 finding has at least one TestClient repro in `tests/test_appsec_audit_round5_bb.py`.
* For the XFF bucketing probe (BB5-01): set `IAM_JIT_TRUST_FORWARDED_FOR=1` and `IAM_JIT_TRUSTED_PROXY_CIDRS=0.0.0.0/0` BEFORE `create_app` is called; ran phase-A 5 reqs under one XFF, phase-B 5 reqs under different XFF, observed phase-B all-429.
* For the /docs CSP probe (BB5-10): parsed `<script src="...">` tags from /docs HTML, cross-checked against the CSP `script-src` directive.

## Did the brief's stated closures hold externally?

| Closure | Status | Notes |
| ------- | ------ | ----- |
| /api/v1/score Cache-Control → private/300/must-revalidate | **HOLDING** | Verified verbatim. |
| Auth'd /api/v1/* → no-store, private | **HOLDING** | Verified across 5 auth'd endpoints; exemptions correct for /score, /healthz, /docs, /openapi.json, /static. |
| Logout (POST + GET) → revoke session cookie hash | **HOLDING** | Both routes; saved-elsewhere 401s. |
| /openapi.json returns 200 with schema | **HOLDING** | Verified. |
| /docs Swagger UI renders | **NOT HOLDING** | CSP still blocks the CDN — BB4-03 still open (BB5-10). |
| Magic-link in Lambda + no DDB → 503 | **HOLDING** | Detail message correct. |
| Stripe empty event.id → rejected=True | **HOLDING** | (Body still leaks event_type — BB4-04 not yet fixed but not in brief.) |
| Stripe unhandled → {handled: false} | **HOLDING** | Exact body, no echo. |
| Stripe sig failure → uniform | **HOLDING** | Across 6 sig-error flavors. |
| Magic-link IP limiter buckets on XFF + trusted-proxy gate | **NOT HOLDING** | Regression — limiter still keys on peer.host (BB5-01). |
| DEV_INSECURE_SECRET refused in Lambda | **HOLDING** | No dev_link short-circuit; falls through to 503. |

## New surprises this round

1. **XFF bucketing is the most consequential miss.** The brief listed it as closed; external probe shows it isn't. Behind ALB this is a launch-day denial-of-service-on-self vector: 5/min global magic-link issuance, not 5/min per user. Production users will trip the limit on launch-day signup spikes.

2. **The /docs CSP block is still there.** Round-4 BB4-03 flagged it; the brief implies it's fixed; it isn't. The fix is well-understood (self-host swagger-ui-dist OR per-route CSP override) but landing the closure correctly should test for "the /docs page actually renders in a real browser" rather than "/openapi.json returns 200."

3. **Cross-origin /api/v1/auth/logout works** (no Origin/Referer check at app layer). The defense relies entirely on the SameSite=Strict cookie attribute being honored. Defense-in-depth at the app layer is cheap and would catch a future cookie-SameSite refactor.

4. **The "first-100-attacker" grab-bag is mostly defended.** Path traversal, smuggling, compression bombs, long paths, NUL bytes, method tampering, OPTIONS preflight — all handled correctly. This is the round where the obvious-attack surfaces have all been pinned. The remaining surface is either esoteric (require source-code reading, multi-step setup, or specific tenant configurations) or already filed (BB5-01, BB5-10).

## Has the BB loop converged?

**Yes — converged externally.** Round 5's findings are all either:

* **Regressions of stated closures** (BB5-01 XFF, BB5-10 /docs CSP) — these contradict the brief and need to be fixed.
* **LOW-severity hygiene** (BB5-02 HEAD recon-assist, BB5-04 Vary missing Cookie, BB5-05 prefix-fingerprint, BB5-03 logout CSRF, BB5-21 Stripe dup-leak carryover) — none would block launch.
* **Honest negatives** (14 of 21 tests) confirming the obvious-attack surface is locked down.

After 5 rounds of BB probing across 100+ findings (rounds 1-5 combined) the surface is **realistic-attacker hardened**. The remaining BB-discoverable findings would require esoteric setups (multi-tenant cookie collisions under specific browser conditions, CDN-edge behaviors that TestClient can't simulate, log-injection downstream of accepted UTF-8 inputs). These are best caught by WB review of specific code paths, not further BB rounds.

**Recommendation for further audit cycles:**

* **One more WB pass** focused on (a) the rate-limit key derivation logic in `routes/auth.py` (confirm BB5-01 root cause), (b) the FastAPI `swagger_ui_html` / `swagger_js_url` configuration (BB5-10 fix path), and (c) the CSP middleware to confirm per-route overrides are plumbed.
* **Skip a round-6 BB pass.** The 100-attacker mindset findings are all in; further BB probing will produce diminishing returns.
* **Add a smoke test:** a Playwright/Selenium check that `/docs` actually renders Swagger UI in a real browser (not just 200 on the HTML). This would have caught BB5-10 / BB4-03 / BB3-07 at CI time.

## Verdict on overall security posture

**The round-4 launch-day cluster is closed.** All round-3 closures hold, the round-4 score Cache-Control and PII Cache-Control closures hold, logout revocation works across both routes, openapi.json works, Stripe webhook is correct on sig-failure / unhandled-type / missing-event-id.

The round-5 backlog is **two MEDs that contradict the brief** (XFF bucketing regression, /docs CSP not actually fixed) plus five LOWs (mostly informational). The XFF regression is the only one with production-blast-radius implications and should be fixed before launch — the others can batch in the first week post-launch.

**Launch recommendation:**

* **Fix BB5-01 (XFF bucketing) BEFORE launch** — the production behavior of "5/min magic-link issuance globally behind ALB" is genuinely launch-blocking.
* **Fix BB5-10 (/docs CSP) BEFORE launch** — first-impression UX gap, easy fix.
* Schedule BB5-02..BB5-05 + BB5-21 in the first week post-launch.

Estimated remediation effort:
* BB5-01 XFF bucketing: ~30 min (share existing real-IP derivation logic with the rate-limiter).
* BB5-10 /docs CSP: ~1 hr (self-host swagger-ui-dist OR per-route CSP override).
* BB5-02..BB5-05: ~30 min combined.
* BB5-21 Stripe duplicate response: ~10 min.

Total ~2.5 engineer-hours of remediation for the round-5 backlog. Two of those hours are launch-blocking.
