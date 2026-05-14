# iam-jit black-box appsec audit — round 1 (2026-05-14)

External-researcher style audit performed without reading any
application source. The tester ran the FastAPI app via TestClient,
authenticated as the supplied test personas (dev, dev2, approver,
admin), and probed HTTP behavior only — the same surface an external
attacker with a leaked URL + a test account would see.

Scope: the SaaS plumbing around the IAM scoring engine — magic-link
auth, API-token issuance/use, session cookies, HTML web routes, MCP
JSON-RPC server, Stripe webhook, admin endpoints, multi-tenant
isolation. The scoring engine itself (`/api/v1/score`, policy
generation, calibration corpus) is **out of scope** — it has been
adversarially red-teamed separately.

Each finding has a corresponding pytest case in
[`tests/test_appsec_audit_round1_bb.py`](../../tests/test_appsec_audit_round1_bb.py)
that documents and asserts the current behavior. Following the
white-box audit convention, broken-behavior tests assert the
*vulnerable* state — when a fix lands, the test fails and signals the
need to flip the assertion (or delete the test) as part of the fix PR.
Honest-negative tests assert the *defended* state and protect against
regression.

## Totals

| Severity | Count |
| -------- | ----- |
| CRIT     | 0     |
| HIGH     | 3     |
| MED      | 6     |
| LOW      | 7     |
| Honest negatives | 14 |
| **TOTAL findings**| **16**|

No critical (pre-auth RCE / cross-tenant data leak / credential theft)
findings. The application's core authentication and multi-tenant
isolation are sound. Issues cluster in:

1. **CSRF on the HTML routes** (the JSON-API routes are mostly accessed
   via Bearer tokens which are not CSRF-able, but the cookie-auth HTML
   form handlers approve / cancel / mint-token / revoke-token with no
   anti-CSRF token).
2. **Operational hardening around magic-link delivery** (the token URL
   ships in logs when SES is not configured).
3. **Defense-in-depth on rate limiting** (magic-link and
   request-creation endpoints unthrottled).
4. **Webhook idempotency** (Stripe replay not deduped by event.id).

## Severity breakdown by finding id

### HIGH

| id     | title |
| ------ | ----- |
| BB-01  | CSRF: HTML approve accepts cookie-only POST |
| BB-02  | CSRF: HTML token-mint accepts cookie-only POST |
| BB-12  | Magic-link token URL emitted to logger when SES unset |

### MED

| id     | title |
| ------ | ----- |
| BB-03  | CSRF: HTML cancel accepts cookie-only POST |
| BB-04  | CSRF: HTML token-revoke accepts cookie-only POST |
| BB-06  | `/api/v1/requests/{id}/assume` is a state-mutating GET |
| BB-07  | Session cookie missing `Secure` attribute |
| BB-09  | No rate limit on `/api/v1/auth/magic-link` |
| BB-10  | No rate limit on `POST /api/v1/requests` |
| BB-11  | Stripe webhook lacks event.id idempotency dedupe |

### LOW

| id     | title |
| ------ | ----- |
| BB-05  | `GET /logout` is state-changing (CSRF-able via SameSite=Lax) |
| BB-08  | Session cookie embeds user_id in plaintext |
| BB-13  | `/healthz` leaks security-posture object to unauth callers |
| BB-14  | Verbose JSON-schema errors aid recon |
| BB-15  | `Authorization` header case-insensitive (RFC-compliant but log-redaction risk) |
| BB-16  | Magic-link URL embeds requester email in plaintext |
| BB-18  | `POST /accounts/register` accepts unauthenticated input |

### Honest negatives (defended classes)

| id     | class |
| ------ | ----- |
| BB-17  | Open-redirect via magic-link `?next=` — ignored, hard-coded `/` |
| BB-19  | User enumeration via magic-link response — uniform 202 |
| BB-20  | XSS in request description / requester.name — Jinja autoescape |
| BB-21  | XSS in comment — Jinja autoescape |
| BB-22  | Session cookie tampering / wrong-secret forgery — itsdangerous rejects |
| BB-23  | Cross-tenant IDOR on `/api/v1/requests/{id}/*` — 403 across all verbs |
| BB-24  | Dev bearer token reaching admin endpoints — 403 across all admin paths |
| BB-25  | Stripe signature verification (missing/malformed/old) — rejected 400 |
| BB-26  | Score endpoint rate limiting — 429 after ~30 req/min |
| BB-27  | Magic-link single-use — second callback returns 400 |
| BB-28  | MCP JSON-RPC bogus methods — returns -32601 error cleanly |
| BB-29  | Comment author forgery via client-supplied `author` — ignored |
| BB-30  | Static file path traversal — StaticFiles 404 |
| (n/a)  | CSP / X-Frame-Options / Referrer-Policy headers — present on all responses |

## Top 5 findings

### 1. BB-01 / BB-02 / BB-03 / BB-04 — CSRF on every HTML form route (HIGH)

The HTML web routes (`POST /requests/{id}/approve`, `/cancel`,
`/comments`, `POST /tokens`, `POST /tokens/{hash}/revoke`) accept
cookie-only requests with no CSRF token, no Origin/Referer
validation, no `X-Requested-With` requirement. Combined with the
session cookie's `SameSite=Lax` attribute (which still allows
form-submission CSRF), an attacker site can silently:

- approve a victim approver's pending request (granting AWS IAM access
  to a third party);
- mint an API token in the victim's account (persistent backdoor — the
  raw token returns in the response, harder to exfil but combinable
  with timing/XSS);
- cancel or revoke the victim's resources.

The `/api/v1/*` JSON routes are not affected if accessed via Bearer
token — but they ALSO accept cookie auth, and a cookie-only POST with
`Content-Type: application/json` triggers a CORS preflight (mitigated
by browser). The HTML routes use form-encoded bodies, which require
NO preflight — full CSRF surface.

**Fix**: emit a per-session CSRF token (Starlette session middleware
or a custom signed-double-submit cookie), inject into every form, and
verify on POST. Alternative: hard-flip session cookie to
`SameSite=Strict`. The former is the safer, conventional fix.

### 2. BB-12 — Magic-link token URL emitted to logger when SES unset (HIGH, operational)

When `IAM_JIT_SES_SENDER` is unset, the `magic_link_delivery.py`
fallback logs `MAGIC_LINK channel=log user_id=email:<addr>
url=<full-callback-url>` at WARNING level. The URL contains the signed
magic-link token, which is a bearer-equivalent: anyone with read
access to CloudWatch (or whatever log sink Lambda ships to) can mint
sessions for any user who has signed in recently.

The behavior is acknowledged in `/healthz security_posture` as a
known issue (`severity: info, id: no_ses`). This is an "accepted
risk" by design — but as a behavioral finding it deserves an explicit
boot-time gate so a production deployment can't accidentally ship in
this mode.

**Fix**: refuse to start if `delivery_channel == "log"` AND
`IAM_JIT_AUTH_MODE != local`. Or accept the risk and require
`IAM_JIT_ALLOW_LOG_DELIVERY=1` as an explicit override.

### 3. BB-09 / BB-10 — Missing rate limits on magic-link & request-creation (MED)

The `POST /api/v1/score` endpoint correctly throttles (~30 req/min →
429), but the equivalent expensive endpoints `POST
/api/v1/auth/magic-link` and `POST /api/v1/requests` are unthrottled
and accept 150+ requests in a tight loop. Attackers can:

- email-bomb a known user (and burn the SES quota — billing-exfil);
- create thousands of role-requests to flood approvers and exhaust
  filesystem/DynamoDB storage.

The `rate_limit.py` module is already present — just bind its limiters
to these endpoints.

### 4. BB-11 — Stripe webhook lacks event.id idempotency dedupe (MED)

The Stripe webhook signature verification is correct (signed, time-
windowed, malformed-rejected — confirmed in BB-25), but two POSTs of
the *same* signed body succeed with identical 200 responses. Stripe
explicitly delivers webhooks at-least-once and documents that
receivers MUST dedupe by `event.id`
(https://stripe.com/docs/webhooks#handle-duplicate-events).

Today the production handlers return `handled: false` for unknown
event types, so impact is minimal. But as billing event-handlers
land (the project roadmap is on a launch path), every
"subscription.created", "invoice.paid", "customer.updated" handler
will be silently double-applied. This is a billing-integrity bug
waiting to fire on the first networking blip between Stripe and the
endpoint.

**Fix**: persist seen `event.id` (DynamoDB conditional-put with 7-day
TTL — Stripe doesn't retry beyond that). Reject duplicates with
200 + `{"handled": "duplicate"}` so Stripe stops retrying.

### 5. BB-13 — `/healthz` leaks security-posture object to unauth callers (LOW, recon-grade)

`GET /healthz` is intentionally public (load-balancer health check)
but returns a fully-detailed security-posture object including:
whether an ALB is in front, whether HTTPS cert configured, whether
network ACL is active, whether SES is configured, the LLM backend
identity, the auth mode, the user-config source, and a free-form
issues array with `detail` and `fix` strings. An attacker probing the
deployment learns: "this deployment has no ALB, no HTTPS, magic-links
delivered via CloudWatch logs — go after the log sink." That's not a
CVE but it's a free recon win.

**Fix**: shrink `/healthz` to `{"status": "ok"}` (HTTP 200 is the
health signal). Keep the posture object at the existing admin-gated
`/api/v1/admin/security-posture`.

## Methodology notes

- **Probe technique**: spawned the FastAPI app via `create_app()` with
  in-memory stores, drove with `TestClient`. No source files of
  `src/iam_jit/**` were opened during probing. Test-fixture personas
  were authenticated by signing session cookies with the magic-link
  secret (i.e. simulating the post-callback state) — this is exactly
  what a real session looks like after `/api/v1/auth/callback`.
- **Surface coverage**: enumerated all routes via
  `app.routes` introspection (purely observable from the OpenAPI doc
  in real deployment), then targeted each route with one or more
  attack classes from the OWASP Top 10. Approximately 100+ HTTP
  probes were executed across the surface.
- **Defenders observed at the perimeter**:
  - Custom security-headers middleware applies CSP / X-Frame-Options /
    X-Content-Type-Options / Referrer-Policy / `frame-ancestors 'none'`
    to every response (HTML and JSON alike) — strong baseline.
  - The body-size middleware returns 413 on >5 MB POSTs.
  - The `score` endpoint has a dedicated per-IP rate limiter.
  - The signed-cookie session is single-key, time-windowed via
    `itsdangerous.URLSafeTimedSerializer` — tampering rejected.
  - Magic-link nonces are stored and single-use.
- **Surfaces NOT probed in depth** (call out for round 2):
  - The MCP server's full tool-execution flow (only initialize, list,
    bogus-method paths exercised); a deep probe of `generate_iam_policy`
    with prompt-injection in `task` description deserves its own round
    (and the project has a `test_prompt_injection*.py` series that
    suggests this is being handled, but black-box of the JSON-RPC path
    specifically wasn't exhaustive).
  - The Lambda-deployed `lambda_handler.py` path — TestClient drives
    `create_app()` directly; the Lambda-vs-direct flow may diverge in
    e.g. header parsing.
  - The DynamoDB-backed code paths (the audit tests run with the
    in-memory `FileUserStore` + `FilesystemStore`; the DynamoDB
    variants have separate test coverage in `test_request_store_dynamodb.py`
    et al. but the black-box probe was filesystem-only).
  - SigV4 auth (the project hints at an admin SigV4 path; not
    enumerated in `app.routes`, possibly enabled via env var).

## Verdict on overall security posture

**Solid for a v0.x SaaS, with a clearly identifiable hardening
backlog.**

The high-value invariants — authentication signature verification,
tenant isolation on the IAM-grant API, admin RBAC, webhook signature
verification, output encoding — all hold under probe. The
white-box audit (`AUDIT-2026-05-WB.md`) found 0 CRIT findings; this
black-box audit confirms the same from the outside.

The CSRF findings are the most actionable: they are easy to exploit
end-to-end (the only requirement is the victim's browser visiting an
attacker page while logged into iam-jit), the impact is
high (silent approval of role grants is a "convince a user to click
a link and they granted AWS access" attack), and the fix is
mechanical (anti-CSRF token).

Beyond CSRF, the remaining work is hardening: rate-limit parity with
the score endpoint, log-channel gating, webhook idempotency, and
trimming `/healthz`. None of these are gating for the founder's launch,
but BB-01..BB-04 (CSRF) should be patched before any external-customer
rollout that has an active approver/admin browser session in the wild.
