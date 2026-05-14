# iam-jit black-box appsec audit — round 4 (2026-05-14)

Round-4 external-researcher probe. Round 3 filed the launch-day cluster: logout-not-revocation (BB3-01), openapi-500 (BB3-02), healthz-leaks-posture (BB3-03), stripe-clock-leak (BB3-04), stripe-empty-event-id-replay (BB3-05), and stripe-event-type-echo (BB3-10). Round 4's brief: re-probe each of those closures externally, and look for the *next* attacker surface — the things exposed by the fixes themselves, the classes no prior round audited (Cache-Control on auth'd endpoints, CORS misconfig, webhook-secret leak via error path, revocation-list timing oracle, TOCTOU race between logout and the next request), and the first-100-attacker fuzzing grab-bag (empty bodies, oversize headers, malformed Content-Length, Transfer-Encoding, duplicate headers).

Each finding has a corresponding pytest case in [`tests/test_appsec_audit_round4_bb.py`](../../tests/test_appsec_audit_round4_bb.py). Convention is unchanged from rounds 1, 2, and 3: broken-behavior tests assert the **vulnerable** state (flip the assertion when fixing); honest-negative tests assert the **defended** state (protect against regression).

## Totals

| Severity | Count |
| -------- | ----- |
| CRIT     | 0     |
| HIGH     | 0     |
| MED      | 3 (BB4-01, BB4-02, BB4-03) |
| LOW      | 6 (BB4-04..BB4-09) |
| Honest negatives | 14 (BB4-10..BB4-23) |
| **TOTAL new findings** | **9** |

No criticals, no HIGHs. The round-3 launch-critical cluster (BB3-01 logout, BB3-02 openapi-500) is fully closed externally. The MEDs this round are all "the fix exposed a new surface": (a) `/api/v1/score` now serves a `Cache-Control: public, max-age=3600, s-maxage=86400` response so CDNs cache score outputs for 24h (BB4-01), (b) auth'd PII endpoints (`/api/v1/users/me`, `/api/v1/tokens`) ship with **no** `Cache-Control` header so browser/proxy heuristic caching can stale-serve user state (BB4-02), and (c) the openapi-500 closure fixed the schema route, but `/docs` and `/redoc` still reference CDN scripts that CSP `script-src 'self'` blocks — so docs render visibly broken in a modern browser (BB4-03).

LOW cluster: minor Stripe response-shape oracles (BB4-04, BB4-05), `POST /api/v1/auth/logout` always-200 (BB4-06), missing HSTS header at the app layer (BB4-07), Set-Cookie SameSite inconsistency between auth-callback (Strict) and logout (Lax) (BB4-08), null-byte acceptance in `description` (BB4-09).

The **good news** at the closure layer: every round-3 closure verified holding externally, the revocation-list lookup is NOT timing-attackable (revoked vs non-revoked cookie request times are statistically indistinguishable across 200 trials), the body-size middleware correctly 411s chunked TE without blocking any legitimate POST, and the TOCTOU race between concurrent requests and a logout resolves correctly (all post-logout requests see the post-revocation state).

## Severity breakdown by finding id

### MED

| id | title |
| -- | ----- |
| BB4-01 | `POST /api/v1/score` serves `Cache-Control: public, s-maxage=86400` — CDN caches scoring output for 24h |
| BB4-02 | Auth'd PII endpoints (`/api/v1/users/me`, `/api/v1/tokens`) ship with **no** `Cache-Control` header |
| BB4-03 | `/docs` and `/redoc` load CDN scripts that the app's CSP `script-src 'self'` blocks |

### LOW

| id | title |
| -- | ----- |
| BB4-04 | Stripe rejected response leaks `event_type` + `reason: missing_event_id` instead of `{rejected: true}` |
| BB4-05 | Stripe duplicate-event response echoes `event_type` + `event_id` — event-id confirmation oracle |
| BB4-06 | `POST /api/v1/auth/logout` 200s with no/garbage/forged cookie — endpoint always issues Set-Cookie+200 |
| BB4-07 | No `Strict-Transport-Security` header on any response (relies entirely on ALB) |
| BB4-08 | Logout's `Set-Cookie` is `SameSite=Lax`; auth-callback issues `SameSite=Strict` — inconsistency |
| BB4-09 | `\x00` (NUL) bytes accepted in `description` field on `/api/v1/score` |

### Honest negatives — defended classes (closure re-pins)

| id | round-3 closure / class | status |
| -- | ----------------------- | ------ |
| BB4-10 | BB3-01 — `POST /api/v1/auth/logout` + `GET /logout` revoke server-side | HOLDING |
| BB4-11 | BB3-02 — `/openapi.json` returns 200 with real schema | HOLDING |
| BB4-12 | BB3-03 — `/healthz` is `{"status":"ok","version":"..."}` only | HOLDING |
| BB4-13 | BB3-04 — Stripe sig-error body is generic, no clock leak | HOLDING |
| BB4-14 | BB3-05 — Stripe empty/missing `event.id` → `rejected=true` | HOLDING |
| BB4-15 | BB3-10 — Stripe unhandled `event_type` → `{"handled": false}` only | HOLDING |
| BB4-16 | Body-size middleware — chunked TE → 411 | HOLDING |
| BB4-17 | Token-mint cap — 51st mint → 429 | HOLDING |
| BB4-18 | Magic-link per-IP rate limit — 5/min soft, 15/min hard | HOLDING |
| BB4-19 | Magic-link in Lambda without DDB nonce table → 503 | HOLDING |
| BB4-20 | Revocation-list lookup is NOT timing-attackable (revoked vs non-revoked statistically indistinguishable across 200 trials) | DEFENDED |
| BB4-21 | TOCTOU race between concurrent `/users/me` and `/auth/logout` resolves correctly | DEFENDED |
| BB4-22 | CORS — no preflight ACAO for third-party origins (CORS middleware absent) | DEFENDED |
| BB4-23 | Sibling-cookie semantics — logout revokes only the specific cookie value sent (per-cookie revocation, NOT per-user epoch) | PINNED |

## Top 3 launch-critical findings

### 1. BB4-01 — `/api/v1/score` `Cache-Control: public, s-maxage=86400` (MED)

`POST /api/v1/score` ships with:

```
Cache-Control: public, max-age=3600, s-maxage=86400
Vary: Authorization
X-Policy-Fingerprint: sha256:...
```

The intent is clear: scoring is a pure function of the policy, so it's cacheable. The `X-Policy-Fingerprint` header is the policy-content hash, and `Vary: Authorization` prevents Bearer-keyed cross-tenant cache hits. The body itself is identical across users for the same policy input (confirmed by probe: dev and admin sending the same policy produce byte-identical bodies).

**Why MED at launch:**

1. **POST responses are not cached by default by most CDNs**, but Cloudflare's "Cache Everything" page rule, Fastly with explicit POST caching, and corporate forward proxies that honor `Cache-Control: public` explicitly *do* cache POST responses. The directive is a request to cache, and a fraction of intermediaries will honor it.
2. **Browser cache will honor the directive** for the cookie-auth case (no `Authorization` header → all browser-auth'd users share the cache entry). The body has no PII, so this isn't a cross-tenant data leak — but it is a **scoring-integrity staleness issue**: when iam-jit ships a scoring-rule update (e.g. closes an adversarial-loop finding), users continue to see the old score for up to 24h.
3. **The adversarial-loop process moat depends on rule freshness** — a scoring rule that lands at 9am UTC should be live for everyone by 9am UTC, not "everyone whose CDN cache expired."
4. **`s-maxage=86400` is the killer.** That's 24 hours of CDN cache freshness. A more conservative `private, max-age=300, must-revalidate` retains the no-PII property but bounds staleness at 5 minutes.

**Reproducer (TestClient):**

```python
r = dev.post("/api/v1/score", json={...})
assert r.headers["cache-control"] == "public, max-age=3600, s-maxage=86400"
```

**Fix sketch:** drop `s-maxage`, drop `public`, keep `private, max-age=300, must-revalidate`. Or move to an ETag-only model (`ETag: <X-Policy-Fingerprint>`, `Cache-Control: no-cache`, conditional GETs return 304). The latter is the right shape because it preserves the cacheability while letting iam-jit invalidate by bumping a rule-engine version that becomes part of the fingerprint.

### 2. BB4-02 — Auth'd PII endpoints have no `Cache-Control` (MED)

`GET /api/v1/users/me` and `GET /api/v1/tokens` return user PII (email-based user_id, role list, token labels, token IDs, creation timestamps) with **no `Cache-Control` header at all**.

```
GET /api/v1/users/me -> 200, headers do not include cache-control
GET /api/v1/tokens   -> 200, headers do not include cache-control
```

The HTTP spec treats the absence of `Cache-Control` as "use heuristic freshness," which for responses without `Last-Modified` is typically 0-10% of (now - Date) but implementation-dependent. **In practice:** browser bfcache and back-button restore can show stale user state after logout; corporate proxies that aggressively cache GET responses may serve one user's `/api/v1/users/me` body to a colleague-on-same-NAT making the same request.

**Why MED:**
- Pin a launch-day defense rather than discover an "$X corp leaked my session info between employees via their corporate proxy" issue post-launch.
- Single-line fix.

**Reproducer:**

```python
r = dev.get("/api/v1/users/me")
assert "cache-control" not in {k.lower() for k in r.headers}
```

**Fix sketch:** Add a small middleware (or per-route response_class) that emits `Cache-Control: no-store, private` on every authenticated response. Whitelist `/api/v1/score` (per BB4-01 fix). Static assets (`/static/*`) get `public, max-age=...` separately.

### 3. BB4-03 — `/docs` and `/redoc` blocked by app's own CSP (MED, UX regression)

The BB3-02 closure fixed the openapi-500 issue and `/openapi.json` now returns a valid schema. But `/docs` (Swagger UI) and `/redoc` HTML pages reference CDN-hosted JS:

```html
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script src="https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js"></script>
```

The app's CSP header is:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; ...
```

Modern browsers reject `cdn.jsdelivr.net` scripts because they're not in `script-src`. Net result: `GET /docs` returns 200 with HTML, but the page renders blank or with a CSP error in the console.

This was previously observed as BB3-07 with the assumption that the root cause was the openapi-500. Round 4 confirms the openapi route works, so this is the new failure mode (CSP CDN block).

**Why MED:**
- Same launch-day trust hit as BB3-07 — first impression for API consumers is broken docs.
- Two fix paths, both ~30min: (a) self-host the swagger UI bundle (add `swagger-ui-dist` to a `/static` path and override FastAPI's default CDN URL); (b) extend CSP with `script-src 'self' https://cdn.jsdelivr.net` for the `/docs` route only.

**Reproducer:**

```python
r = c.get("/docs")
assert "cdn.jsdelivr.net" in r.text
csp = r.headers["content-security-policy"]
assert "cdn.jsdelivr.net" not in csp  # CDN is blocked
```

**Fix sketch:** self-host swagger-ui-dist behind `/static/swagger/` and configure FastAPI's `swagger_ui_oauth2_redirect_url` and `swagger_js_url` to point at the local path. Same for redoc.

## Other findings (one-paragraph each)

### BB4-04 — Stripe rejected response shape (LOW)

Brief said missing/empty `event.id` should be `{"rejected": true}` 200 response. Actual response is `{"handled": false, "event_type": "customer.created", "rejected": true, "reason": "missing_event_id"}`. The `event_type` echo confirms to the attacker that their forged event was parsed (and reveals the canonicalization: an empty-string type becomes `event_type: "unknown"`). The `reason` field is a stable string keyed to the rejection class, which gives an attacker an enumeration vector for "what malformations does this endpoint reject vs accept?" Minor — only matters if the attacker has the webhook secret. **Fix:** drop `event_type` and `reason` from the rejected response; keep them in server logs.

### BB4-05 — Stripe duplicate-event response leaks event metadata (LOW)

When the SAME event_id is sent twice (idempotency-store hit on the 2nd), the response is `{"handled": false, "event_type": "<type>", "duplicate": true, "event_id": "<id>"}`. An attacker with the webhook secret can probe arbitrary event_ids; the response distinguishes "never seen" (`{"handled": false}`) from "already processed" (`{"handled": false, "duplicate": true, "event_id": "..."}`). This is a free **event-id existence oracle**. Combined with the rejected-shape leak in BB4-04, an attacker can map out the Stripe event-processing state machine. **Fix:** on the duplicate path, emit `{"handled": false}` only. The duplicate detection lives in server logs.

### BB4-06 — `POST /api/v1/auth/logout` 200s on any input (LOW)

The endpoint returns 200 `{"status": "logged out"}` and `Set-Cookie: iam_jit_session=""; Max-Age=0` regardless of whether the caller sent (a) no cookie, (b) a malformed cookie, (c) a wrong-secret-signed cookie, or (d) a valid revoked cookie. Uniformity is **good** (no oracle that distinguishes "this cookie was valid before logout" from "this cookie was never valid"). But the always-200 behavior also confirms to a recon scanner that the route exists and is processing requests — even without auth. **Fix sketch:** the trade-off here is real (oracle vs free-acknowledgement). Keep current behavior; this finding is informational/pin.

### BB4-07 — No HSTS header on any response (LOW)

No `Strict-Transport-Security` header on `/healthz`, `/`, `/api/v1/users/me`, `/api/v1/score`. The deployment relies on ALB to inject HSTS at the edge. If the app is fronted by anything other than the production ALB (a dev deployment, a local tunnel, a misconfigured staging environment, a sidecar in a docker-compose), there is no HSTS — and a network attacker can MitM downgrade the first request. **Fix:** add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` to the security-headers middleware. Defense-in-depth so the app stays secure even when the ALB isn't.

### BB4-08 — Set-Cookie SameSite inconsistency (LOW)

Auth-callback issues `iam_jit_session=<value>; SameSite=Strict`. Logout issues `iam_jit_session=""; SameSite=Lax`. The logout cookie value is empty (it's the deletion cookie), so the SameSite mode is functionally irrelevant — but the inconsistency is the kind of thing a careful auditor flags as "the author wasn't paying attention" and that often signals deeper inconsistencies elsewhere. **Fix:** issue the logout cookie with the same SameSite mode as the auth-callback cookie (`Strict`). One-line change.

### BB4-09 — NUL bytes accepted in `description` on `/api/v1/score` (LOW)

`description: "foo\x00bar"` is accepted and scored normally (status 200). Most downstream sinks (CloudWatch, Slack, Datadog) handle NULs fine, but some (notably PostgreSQL `text` columns) reject NUL bytes with a hard error — and any markdown-renderer that interprets NUL as a terminator could truncate displays. Defense-in-depth. **Fix:** add NUL-byte rejection to the description Pydantic validator (`min_length`/`max_length` already enforced; add `pattern=` or a custom validator).

## Honest negatives — defended classes (closure re-pins)

These tests pin the *defended* state so a future regression in the closure layer fails loudly.

### BB4-10 — Logout closure HOLDS

`POST /api/v1/auth/logout` and `GET /logout` both write to a server-side revocation table. A saved-elsewhere copy of the cookie returns 401 on `/api/v1/users/me` after the logout. The closure works on both routes and for both cookie sources (dev session, real magic-link callback).

### BB4-11 — `/openapi.json` 200 closure HOLDS

`/openapi.json` returns a 62KB schema with 53 paths including the core `/api/v1/score`, `/api/v1/auth/*`, `/api/v1/requests/*` surface. Schema version is openapi 3.1.0.

### BB4-12 — `/healthz` minimal closure HOLDS

`GET /healthz` returns `{"status": "ok", "version": "0.0.1"}` exactly. No `auth_mode`, no `security_posture`, no `llm_backend`, no `ses_configured`. Response is 33 bytes.

### BB4-13 — Stripe sig-error closure HOLDS

Every flavor of sig-error (wrong timestamp, wrong signature, missing header, garbage header, empty body) returns 400 with body `{"detail": "signature verification failed"}` — exactly. No clock leak, no detail variance.

### BB4-14 — Stripe missing/empty event.id closure HOLDS

Both `body without "id" field` and `body with "id": ""` are rejected with `rejected: true`. Three consecutive replays all reject (no idempotency bypass). (Note: response body is more verbose than the brief asked — BB4-04 — but the closure for the *replay-protection* invariant holds.)

### BB4-15 — Unhandled event_type closure HOLDS

For genuinely unhandled types (`my.totally.fake.type`, `not.handled`, `another.unknown`, `customer.created`), the response is exactly `{"handled": false}` with no type echo. (The duplicate path is a separate leak — BB4-05.)

### BB4-16 — Chunked TE → 411 closure HOLDS

`POST /api/v1/auth/magic-link` and `POST /api/v1/score` with `Transfer-Encoding: chunked` both return 411 with `{"detail": "chunked Transfer-Encoding is not supported; send a Content-Length-bounded request body."}`. Critically, **this does NOT block legitimate POSTs**: same endpoint without the TE header completes normally (verified). The middleware is correctly fail-closed on the unsupported encoding without affecting valid request paths.

### BB4-17 — Token-mint cap HOLDS

Default cap is 50 tokens per user. 51st mint returns 429. Probe: 55 mint attempts → Counter({201: 50, 429: 5}). Cap is enforced.

### BB4-18 — Magic-link per-IP rate limit HOLDS

Soft cap 5 / minute, hard cap 15 / minute (defaults). 25-burst from same peer → Counter({429: 20, 202: 5}). Limits are configurable via env vars.

### BB4-19 — Magic-link Lambda + no DDB → 503 HOLDS

With `AWS_LAMBDA_FUNCTION_NAME` set (Lambda heuristic), `IAM_JIT_DEV_INSECURE_SECRET` unset, and no `IAM_JIT_MAGIC_LINK_NONCES_TABLE`, the route returns 503 with a clear message pointing the operator at the three valid configurations (DDB table, single-instance opt-in, dev mode). Multi-instance replay is closed.

### BB4-20 — Revocation lookup NOT timing-attackable

200-sample timing of `GET /api/v1/users/me` with revoked vs non-revoked cookies shows medians of 1466us vs 1621us — within the natural per-request noise (stdev 84us-2487us). No reliable timing oracle.

### BB4-21 — TOCTOU race between concurrent requests and logout

10 concurrent `GET /api/v1/users/me` racing 1 `POST /api/v1/auth/logout` under a barrier: all 10 `/users/me` results consistently see the post-revocation state (401) once the logout is in flight. No "I sneaked in a request before the revocation landed" gap.

### BB4-22 — No CORS preflight ACAO leak

`OPTIONS /api/v1/score` and `OPTIONS /api/v1/users/me` with Origins `https://evil.example.com`, `https://iam-risk-score.com`, `null`, `http://localhost:3000` all return 405 with no `Access-Control-Allow-Origin` header. CORS middleware is absent. **Pin this**: the desire for a browser-based JS SDK from a third-party origin would tempt adding CORS — adding it wrong (`*` or reflection) is one of the top-3 ways to leak Bearer-token data cross-origin. The current locked-down state is correct.

### BB4-23 — Sibling-cookie semantics (per-cookie revocation, NOT per-user epoch)

If the user has two valid cookies (e.g. signed-in on two devices, both cookie values distinct due to per-request signing nonce), logout of cookie A does not invalidate cookie B. This is "log out this device only" semantics and is correct for the documented threat model. Pin to make sure a future refactor that switches to a per-user-epoch model is a conscious decision, not an accident.

## Methodology

- Spun up `create_app(...)` against `FilesystemStore` + `FileUserStore` + `InMemoryAPITokenStore` (same fixtures as rounds 1-3).
- All probes through `TestClient` HTTP behavior. **No source-file reads of `src/iam_jit/**`**. Reads limited to round-1/2/3 audit docs, round-1/2/3 BB test files, and `pyproject.toml`.
- Re-ran the round-3 BB suite to confirm every prior closure (18/18 pass).
- Each round-4 finding has at least one TestClient repro in `tests/test_appsec_audit_round4_bb.py`.
- For timing probes (BB4-20), 200-sample runs with a 20-sample warmup; medians compared.
- For TOCTOU probes (BB4-21), `threading.Barrier(11)` synchronizes 10 reader threads + 1 logout thread.

## Did the round-3 fixes hold externally?

| Finding | Status | Notes |
| ------- | ------ | ----- |
| BB3-01 logout server-side revocation | **HOLDING** | Both POST `/api/v1/auth/logout` and GET `/logout` revoke the cookie hash; saved-elsewhere copy returns 401 within milliseconds. |
| BB3-02 `/openapi.json` 200 | **HOLDING** | 200, openapi 3.1.0, 53 paths. |
| BB3-03 `/healthz` minimal | **HOLDING** | `{"status":"ok","version":"..."}` only. |
| BB3-04 Stripe error generic | **HOLDING** | Every flavor of sig-error → `{"detail":"signature verification failed"}` exactly. |
| BB3-05 Stripe empty event.id | **HOLDING** | `rejected: true` on missing and empty cases; replayable behavior closed. (Response body more verbose than ideal — see BB4-04.) |
| BB3-10 Stripe unhandled type echo | **HOLDING** for plain unhandled types | Echo eliminated on `{"handled": false}` path. (Duplicate path still echoes — see BB4-05.) |

## New surprises this round

1. **Cache-Control on `/api/v1/score` is a real, intentional design choice with a security-relevant blast radius.** The `X-Policy-Fingerprint` header makes it clear the engineer was thinking "scoring is pure, let's let CDNs cache it." That's almost-right — but `public, s-maxage=86400` is too aggressive for a scoring service whose rule set evolves (the adversarial-loop process literally requires rule updates to propagate). The right shape is ETag-only or `private, max-age=300`.

2. **The revocation-list lookup is fast enough to be invisible to timing.** This is good news: the round-3 BB3-01 fix landed without introducing a timing oracle (revoked vs non-revoked is statistically indistinguishable across 200 trials). The implementation is performant enough that a remote attacker can't differentiate.

3. **`/docs` is still broken**, just for a different reason than BB3-07 thought. BB3-07 hypothesized openapi-500 was the cause. The openapi closure is solid — and yet `/docs` is still visually broken because of CSP-vs-CDN script-src. This is the cluster of "we fixed X, now Y breaks." A future fix author should treat `/docs` rendering correctly as the actual test, not "openapi.json returns 200."

4. **No HSTS at the app layer.** Easy to miss because ALB injects it at the edge in production. The right defense-in-depth is to add it at the app layer too — covers dev deployments, sidecars, and the case where someone proxies through a not-ALB-with-HSTS path.

## Verdict on overall security posture

**The round-3 launch-day cluster is closed.** All six round-3 closures verified externally. The HIGH and MED clusters that round-3 filed are gone — the cookie-revocation primitive works, the openapi route returns valid schema, healthz is minimal, Stripe error bodies don't leak the clock, and Stripe missing-event-id is rejected.

The round-4 backlog is **all MED/LOW caching and headers hygiene** — no broken auth, no broken multi-tenant, no broken webhook idempotency. The three MEDs (BB4-01 score caching, BB4-02 PII caching, BB4-03 docs CSP) are each ~30min-1hr to fix; the LOWs are ~5-15 min each. Estimated total remediation: ~half an engineer-day for the round-4 backlog.

**Launch recommendation:** ship. Schedule the three MED-tier fixes within the first week post-launch; the LOWs can batch with the next round of hardening. None of the round-4 findings warrant blocking launch.

Estimated remediation effort:
- BB4-01 score Cache-Control: ~30 min (drop `s-maxage`/`public`, or move to ETag-only).
- BB4-02 PII Cache-Control: ~30 min (security-headers middleware addition).
- BB4-03 docs CSP: ~1 hour (self-host swagger-ui-dist or extend CSP per-route).
- BB4-04..BB4-09: ~30 min combined.

Total ~3 engineer-hours of remediation for the round-4 backlog.
