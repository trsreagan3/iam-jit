# iam-jit white-box appsec audit — round 1 (2026-05-14)

White-box review of the iam-jit SaaS application as of commit on disk
2026-05-14. Scope: application security only (the IAM scoring engine
has been adversarially tested separately and is out of scope here).

Each finding has a corresponding pytest case in
`tests/test_appsec_audit_round1_wb.py`. The test asserts the *current*
(vulnerable) behavior; when a fix lands, the test fails — that's the
signal to flip the assertion (or delete the test) as part of the fix
PR.

## Totals

| Severity | Count |
| -------- | ----- |
| CRIT     | 0     |
| HIGH     | 4     |
| MED      | 9     |
| LOW      | 11    |
| **TOTAL**| **24**|

No critical (pre-auth RCE / cross-tenant data leak / credential theft)
findings. The application's auth-and-authorization spine is sound;
issues cluster in (a) operational hardening around magic-link delivery
and audit-log durability, (b) multi-instance correctness for in-memory
stores that the comments already flag as 'swap for Redis later', and
(c) defense-in-depth around the public scoring endpoint.

### Severity breakdown by finding id

HIGH (4):

- `SCORE-XFF-RATELIMIT-BYPASS` — anonymous score endpoint trusts
  client-supplied `X-Forwarded-For` for rate-limit keying
  (`src/iam_jit/routes/score.py:264`).
- `MAGIC-LINK-REPLAY-MULTI-INSTANCE` — magic-link single-use
  enforcement is process-local; replay-window of 15min across N
  Lambda instances (`src/iam_jit/magic_link_nonces.py:44`).
- `BAN-MULTI-INSTANCE-DESYNC` — same per-instance hole, applied to the
  user-ban store that the prompt-injection control depends on
  (`src/iam_jit/bans.py:218`).
- `STRIPE-NO-IDEMPOTENCY` — `checkout.session.completed` redeliveries
  mint duplicate API tokens; no `event["id"]` dedupe table
  (`src/iam_jit/stripe_webhook.py:190`).

MED (9):

- `SCORE-API-KEY-TIMING` — `!=` instead of `hmac.compare_digest`
  (`src/iam_jit/routes/score.py:256`).
- `STRIPE-EMAIL-COLLISION` — customer-supplied email used as `user_id`
  on token issue, can collide with admin user records
  (`src/iam_jit/stripe_webhook.py:236`).
- `MAGIC-LINK-LOG-CHANNEL` — full magic-link URL logged when SES isn't
  configured (`src/iam_jit/magic_link_delivery.py:113`).
- `EXTERNAL-ID-PREDICTABLE` — cross-account ExternalId is
  `iam-jit-<account_id>` (`src/iam_jit/onboarding.py:165`).
- `AUDIT-WRITE-SILENT-FAILURE` — disk-write OSError is swallowed; chain
  head advances anyway (`src/iam_jit/audit.py:202`).
- `RATE-LIMIT-MULTI-INSTANCE-BYPASS` — intake-turn limiter is
  per-instance (`src/iam_jit/rate_limit.py:71`).
- `MAGIC-LINK-JSON-NO-RATELIMIT` — `POST /api/v1/auth/magic-link` has
  no per-IP limit (HTML sibling does)
  (`src/iam_jit/routes/auth.py:55`).
- `WEB-NO-CSRF-TOKEN` — SameSite=lax is the only CSRF defense; no
  token, no Origin/Referer check (`src/iam_jit/routes/web.py`, many
  handlers).
- `STRIPE-VERBOSE-SIGNATURE-ERROR` — exception detail flows to the
  caller via HTTP 400 (`src/iam_jit/routes/webhooks_stripe.py:114`).

LOW (11):

- `BEARER-PARSE-SPLIT-NORMALIZATION` (`middleware.py:78`)
- `TOKEN-HASH-DISCLOSURE` (`routes/tokens.py:67`)
- `CIDR-REMOVE-NO-AUDIT-ON-EMPTY-START` (`routes/admin.py:358`)
- `IAM-PRINCIPAL-WEAK-VALIDATION` (`auth.py:146`)
- `MCP-NO-MESSAGE-CAP` (`mcp_server.py:269`)
- `SCORE-EXC-REPR-LEAK` (`routes/score.py:504`)
- `SESSION-NO-IDLE-TIMEOUT` (`auth.py:30`)
- `AUDIT-FILE-MODE-FOOTGUN` (`audit.py:205`)
- `HEALTHZ-POSTURE-LEAK` (`routes/health.py:16`)
- `POLICY-ANALYZE-NO-PER-FIELD-CAP` (`routes/policy.py:23`)
- `TOKEN-LABEL-UNBOUNDED` (`routes/tokens.py:42`)

## Top 5 findings

### 1. SCORE-XFF-RATELIMIT-BYPASS (HIGH)

`src/iam_jit/routes/score.py:264-270` — `_client_ip()` returns the
first comma-separated token of `X-Forwarded-For` whenever the header
is present, with no check on whether the request came through a
trusted proxy. The `/api/v1/score` endpoint is the launch feature and
is anonymous-by-default; its 30-req/min limiter
(`_limiter.check(ip)` at line 392) is keyed off this value. An
attacker varying the header per-request bypasses the limiter
entirely. The path comment at line 158-169 makes clear the in-Lambda
limiter is the second-of-two enforcement layers — the first being
WAFv2 — which means the in-Lambda layer is meant to be a real
backstop, not a stub. Fix is to gate XFF trust on
`IAM_JIT_TRUST_FORWARDED_FOR=1` the way `network_acl.py` already
does, and to require a configured trusted-proxy CIDR set before
honoring the header.

### 2. STRIPE-NO-IDEMPOTENCY (HIGH)

`src/iam_jit/stripe_webhook.py:332-360` (`dispatch_event`) calls
`handle_checkout_session_completed` (line 190-270) without checking
whether `event["id"]` has been processed before. Stripe's documented
delivery model includes retries on any non-2xx response, dashboard-
initiated replays, and at-least-once delivery semantics under network
faults. Each redelivery passes signature verification cleanly (the
signed payload is byte-identical), and the handler runs end-to-end:
new `issue_api_token`, new DDB row, new email to the customer. The
customer ends up with N valid tokens for one paid subscription; the
operator only sees one in the dashboard unless they go grep DDB. The
test `test_finding_stripe_webhook_not_idempotent` reproduces it with
two identical events and confirms both rows land in the store. Fix
is the Stripe-recommended `processed_events` table with a TTL and a
short-circuit at the top of `dispatch_event`.

### 3. MAGIC-LINK-REPLAY-MULTI-INSTANCE (HIGH)

`src/iam_jit/magic_link_nonces.py:44-67` — single-use enforcement
lives in a process-local dict. Lambda runs N concurrent execution
contexts; nonces consumed on context A don't exist on context B for
the entire 15-minute signed-token TTL. Combined with
`MAGIC-LINK-LOG-CHANNEL` (the link is logged in production-no-SES
mode), an attacker with CloudWatch read access can clone an
authenticated session by hitting the callback through any other
warm Lambda instance. The on-call mitigation is a deploy with SES
configured, but the architectural fix is a DynamoDB-backed nonce
store using
`PutItem(ConditionExpression="attribute_not_exists(token_hash)")`
as the atomic consume.

### 4. WEB-NO-CSRF-TOKEN (MED)

The Jinja-rendered web routes in `src/iam_jit/routes/web.py` use the
same signed session cookie as the JSON API but accept form POSTs
with no CSRF token and no Origin/Referer check (a grep for
`csrf` across the module returns nothing). SameSite=lax (set at
`routes/auth.py:144` and `routes/web.py:528`) blocks most
cross-site sub-resource requests but does NOT block top-level
form-action POSTs triggered by a single user click on an attacker
page. State-changing handlers reached this way include
`POST /tokens` (mints API tokens),
`POST /requests/{id}/approve` (auto-grants IAM access from the
attacker's payload), and `POST /admin/network/cidrs` (alters the
allowlist that gates the entire system). Minimum-viable fix is an
Origin-header check; the proper fix is a per-session CSRF token
rendered into every form.

### 5. AUDIT-WRITE-SILENT-FAILURE (MED)

`src/iam_jit/audit.py:202-211` wraps the on-disk append in a bare
`except OSError: pass`. The chain head (`_LAST_HASH`, `_NEXT_SEQ`)
has already advanced in-memory by the time the disk write is
attempted (line 195-196), so a write failure produces a missing row
that breaks the chain for *every* subsequent emit. The next reader
running `audit.verify_chain` will see the gap and report tampering,
even though the cause was a transient I/O failure or — worse — an
attacker filling the audit volume to disable the log without
tripping any alarm. The audit log is the durable record we point
compliance auditors at; it needs to be the loudest failure mode in
the system, not the quietest. The chain-integrity work elsewhere in
this module (checkpoint anchors, refingerprint detection) is excellent
and would matter much more if write-failure surfaced.

## Methodology

Files reviewed (read end-to-end, not just grepped):

- `src/iam_jit/middleware.py` — auth-dependency injection
- `src/iam_jit/auth.py` — session signing, magic-link signing, token
  issuance
- `src/iam_jit/magic_link_nonces.py` — single-use enforcement
- `src/iam_jit/magic_link_delivery.py` — SES / log / in-response
  channels
- `src/iam_jit/api_tokens_store.py` — token storage
- `src/iam_jit/stripe_webhook.py` — Stripe signature verification +
  event handlers
- `src/iam_jit/routes/webhooks_stripe.py` — HTTP wrapper
- `src/iam_jit/audit.py` — hash-chained audit log
- `src/iam_jit/bans.py` — auto-ban store for prompt-injection control
- `src/iam_jit/rate_limit.py` — per-user sliding-window limiter
- `src/iam_jit/users_store.py` — user record store (file + DDB)
- `src/iam_jit/store.py` — request store (FS + S3 + DDB)
- `src/iam_jit/bootstrap_claim.py` — first-admin claim flow
- `src/iam_jit/security_posture.py` — public posture summary
- `src/iam_jit/onboarding.py` — destination-account artifact rendering
- `src/iam_jit/mcp_server.py` — MCP stdio JSON-RPC server
- `src/iam_jit/app.py` — FastAPI factory + global middleware
- `src/iam_jit/routes/score.py` — public scoring endpoint
- `src/iam_jit/routes/auth.py` — JSON magic-link endpoint
- `src/iam_jit/routes/tokens.py` — per-user API token CRUD
- `src/iam_jit/routes/users.py` — admin user mgmt
- `src/iam_jit/routes/requests.py` — request lifecycle
- `src/iam_jit/routes/admin.py` — admin ops
- `src/iam_jit/routes/blacklist.py` — admin blacklist mgmt
- `src/iam_jit/routes/intake.py` — conversational intake
- `src/iam_jit/routes/policy.py` — policy analysis
- `src/iam_jit/routes/reports.py` — admin reports
- `src/iam_jit/routes/accounts.py` — destination-account registry
- `src/iam_jit/routes/web.py` — HTML routes (partial — handler names +
  CSRF surface)
- `src/iam_jit/routes/webhooks_stripe.py` — Stripe receiver
- `src/iam_jit/routes/health.py` — anonymous health endpoint
- `infrastructure/sam/template.yaml` — IAM, permissions, log retention
  (partial)
- `pyproject.toml` — dependency manifest

Tools: `grep`, `find`, direct read in IDE-equivalent; `pytest` to
sanity-check that each finding's test reproduces the asserted current
behavior on the current source tree.

Out of scope (by request): the IAM risk-scoring engine — already
adversarially tested in a separate workstream. Findings here do not
duplicate that work.

## Honest negatives (vulnerability classes the app correctly defends)

The following were checked and found to be defended adequately; tests
are NOT written for these (no work-to-do signal).

- **SQL injection** — no SQL anywhere. DynamoDB queries pass values
  through parameterized `ExpressionAttributeValues`. See
  `api_tokens_store.py:124-128`, `users_store.py:266-269`,
  `store.py:312-321`.

- **Pickle / arbitrary-class deserialization** — no `pickle`,
  `yaml.unsafe_load`, or `eval` callsites. Every YAML load uses
  `YAML(typ="safe")` (see `users_store.py:29`, `accounts_store.py:32`,
  `memory.py:52`, `routes/web.py:1376`). The single `typ="rt"` usage
  in `schema.py:11` reads a static schema file shipped with the
  package — caller-controlled input never reaches it.

- **Pydantic field-smuggling via `extra=allow`** — `grep -rn
  'extra = .allow' src/iam_jit/` returns no results. Every
  user-input-facing Pydantic model implicitly forbids extras
  (Pydantic v2 default).

- **Path traversal in request id → filesystem** — `store.py:35-43`
  applies a strict allowlist regex (`^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$`)
  on every store operation, with the `_load_or_404` route helper at
  `routes/requests.py:606-616` converting `ValueError` to a clean
  404 (no validator-regex leak).

- **Server-side request forgery** — no `httpx.get(<user-input>)` /
  `requests.get(<user-input>)` callsites on user input. The only
  outbound HTTP is to configured Anthropic / Bedrock endpoints in
  `llm.py`, which read from env, not request bodies.

- **HTML XSS via `|safe` filter** — `grep -rn '|safe\|markupsafe\|
  Markup' src/iam_jit/templates/` returns nothing; all template
  output is HTML-escaped by Jinja2's default autoescape (set
  implicitly by `Jinja2Templates`).

- **HTTPOnly + Secure + SameSite session cookie** — set explicitly at
  `routes/auth.py:138-146` and `routes/web.py:523-530`. Secure flag
  is gated on `IAM_JIT_DEV_INSECURE_SECRET != "1"`, which is the
  documented dev override.

- **Constant-time compare on bootstrap-setup-key** —
  `bootstrap_claim.py:113-115` uses `hmac.compare_digest`. (The
  parallel finding `SCORE-API-KEY-TIMING` is about a DIFFERENT
  comparison: the score-endpoint API key.)

- **Stripe signature verification** — `verify_stripe_signature` at
  `stripe_webhook.py:72-136` is implemented to the documented Stripe
  pattern: rejects missing `t=`, rejects out-of-tolerance timestamps
  (default 300s), uses `hmac.compare_digest` for the signature
  comparison.

- **Audit-log chain integrity (forward & backward)** — `audit.py:88-98`
  and `audit.py:231-295` implement prev_hash linking, seq monotonicity,
  and external-checkpoint anchoring. Re-hash on read catches in-place
  edits, reorderings, and deletions. (The separate finding here is
  about *write-failure handling*, not the chain math.)

- **Lambda IAM role least-privilege** —
  `infrastructure/sam/template.yaml:976-1098` scopes S3 to
  `StateBucket` only, DDB to the specific tables and indices, SES to
  `ses:FromAddress == SesSenderAddress`, sts:AssumeRole to the
  enumerated `ProvisionerRoleArns` and `DiscoveryRoleArns`, and the
  self-log-retention policy has an explicit `Deny` on any
  `logs:Delete*` action against any log group plus an `Allow` on
  PutRetentionPolicy scoped to the iam-jit log group only.

- **DynamoDB queries are per-record, not per-tenant** — but the
  `User`/`request_id` partition keys ARE the natural tenancy scope
  (one-deployment-per-tenant is the documented topology), so per-user
  isolation collapses to per-record isolation, which the store and
  authorization layers DO enforce via owner-check + `lifecycle.can_view`
  (`lifecycle.py:459-464`).

- **Email header injection in `/login`** — the
  `_normalize_login_email` function at `routes/web.py:170-198` refuses
  CR / LF / NUL and obviously-malformed input; the JSON-API sibling
  `_safe_email` (`routes/auth.py:36-50`) does the same.

- **Body-size DoS** — global middleware at `app.py:183-199` caps
  `Content-Length` at 256 KiB (configurable via
  `IAM_JIT_MAX_BODY_BYTES`), returning 413 before the route handler
  runs.

- **Security headers** — `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Content-Security-Policy`, and
  `Strict-Transport-Security` are emitted by global middleware
  (`app.py:220-244`). HSTS is correctly gated on
  `request.url.scheme == 'https'` so dev HTTP isn't poisoned.

- **Request-id forgery** — `routes/requests.py:51-52` server-generates
  every request id and explicitly refuses any client-supplied
  `metadata.id`. The schema enforces the same regex at validation
  time (`store.py:35`).

- **Authorization on the user-mgmt CRUD** — every write endpoint on
  `routes/users.py:118-172` and `routes/accounts.py:117-216` uses the
  `require_admin` dependency.

- **Self-unban refusal** — `routes/admin.py:493-515` explicitly
  refuses an admin's attempt to lift their own ban, forcing a
  second-pair-of-eyes path.
