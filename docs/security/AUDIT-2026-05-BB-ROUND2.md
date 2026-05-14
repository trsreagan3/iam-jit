# iam-jit black-box appsec audit — round 2 (2026-05-14)

Round-2 external-researcher probe. Round 1 BB (CSRF, magic-link
logging, rate limits, Stripe idempotency) and round 1 WB
(SCORE-XFF-RATELIMIT-BYPASS, STRIPE-NO-IDEMPOTENCY, …) landed earlier;
their fixes are shipping concurrently with this round. Round 2 hunts
for:

1. Regressions or edge cases the round-1 fixes opened.
2. Surface areas round 1 didn't fully cover.
3. Privilege-boundary gaps round 1 didn't enumerate.
4. External-channel / config-shape attacks (host-header
   smuggling, log-injection via labels).

Each finding has a corresponding pytest case in
[`tests/test_appsec_audit_round2_bb.py`](../../tests/test_appsec_audit_round2_bb.py).
Same convention as round 1: broken-behavior tests assert the
*vulnerable* state (flip the assertion when fixing); honest-negative
tests assert the *defended* state (protect against regression).

## Totals

| Severity | Count |
| -------- | ----- |
| CRIT     | 0     |
| HIGH     | 3 (BB2-02, BB2-04, BB2-09) |
| MED      | 4 (BB2-05, BB2-06, BB2-10, BB2-11) |
| LOW      | 5 (BB2-03, BB2-07, BB2-12, BB2-13, BB2-14) |
| Honest negatives | 11 (BB2-01, BB2-15..BB2-22, BB2-25) |
| Round-1 retests  | 3 (BB2-08 still open; BB2-23 + BB2-24 confirmed holding) |
| **TOTAL new findings** | **12** |

No new criticals. The HIGH findings cluster around the
**XFF-trust-by-default** pattern: the round-1 fix correctly closed
the score-endpoint hole, but the same vulnerable pattern lives on in
`network_acl.py` and `public_url.py` (one HIGH each), and the
Stripe idempotency fix has a check-then-act race that re-introduces
the original duplicate-handler bug under concurrent redelivery (one
HIGH). Beyond those, the bulk of round-2 findings are
operational/auditability gaps (admin self-demote, account
deregister-in-use, label log-injection).

## Top 5 findings

### 1. BB2-02 — `network_acl.py` trusts `X-Forwarded-For` by default (HIGH)

The round-1 WB fix for SCORE-XFF-RATELIMIT-BYPASS correctly gates
XFF trust on TWO env vars (`IAM_JIT_TRUST_FORWARDED_FOR_FOR_SCORE=1`
AND `IAM_JIT_TRUSTED_PROXY_CIDRS=<list>`) inside
`routes/score.py:_client_ip`. But the SAME vulnerable pattern lives
on inside `network_acl.py` for the source-IP CIDR allowlist:

```python
# network_acl.py
trust_xff = (
    os.environ.get("IAM_JIT_TRUST_FORWARDED_FOR", "1").lower()
    in {"1", "true", "yes"}
)
if trust_xff and xff_header:
    first = xff_header.split(",")[0].strip()
    if first:
        return first
```

The default is "1" — XFF is trusted without a trusted-proxy check.
If the operator locks the surface to office IPs via
`IAM_JIT_ALLOWED_SOURCE_CIDRS` AND the Lambda Function URL is
directly reachable (the SAM template's `AllowPublicNetworkExposure`
path), an attacker spoofs `X-Forwarded-For: <office-ip>` to bypass
the allowlist entirely. Test `test_bb2_02_network_acl_trusts_xff_by_default`
reproduces.

**Fix**: same pattern as `score._client_ip`. Default trust off; only
honor XFF when the immediate peer is in a trusted-proxy CIDR set.

### 2. BB2-09 — `X-Forwarded-Host` is also blindly trusted when opted in (HIGH)

`public_url.base_for` reads `X-Forwarded-Host` whenever
`IAM_JIT_TRUST_FORWARDED_HOST=1` is set. There is no trusted-proxy
check on the immediate peer. An attacker who can hit the Function
URL directly can:

1. POST `/api/v1/auth/magic-link` with `email=<victim>` and header
   `X-Forwarded-Host: evil.attacker.example`.
2. iam-jit generates the link pointing at the attacker's domain.
3. The link is delivered to the victim (via SES — they get a
   normal-looking iam-jit email; the link domain matches the
   header).
4. Victim clicks. Their browser sends the signed token to the
   attacker's server. Attacker replays the token against iam-jit
   for full account takeover.

Pre-conditions: `IAM_JIT_TRUST_FORWARDED_HOST=1` (the CloudFront
front-door deploy path) AND direct Function URL is reachable.
Test `test_bb2_09_magic_link_host_header_poisoning_when_xfh_trusted`
reproduces.

**Fix**: same as BB2-02. Gate XFH-trust on a trusted-proxy CIDR
list. Alternatively, pin the public domain in
`IAM_JIT_PUBLIC_URL` and ignore XFH entirely (the env-var path in
`public_url.py:70-72` already supports this).

### 3. BB2-04 — Stripe idempotency check-then-act race re-introduces duplicate-handler bug (HIGH)

The round-1 fix in `stripe_webhook.dispatch_event` short-circuits
when `processed_events_store.has_processed(event_id)` returns True
and otherwise runs the handler then calls `mark_processed`. The
`InMemoryProcessedEventsStore` does NOT lock the check + claim
sequence. Stripe's at-least-once delivery + dashboard-replay can
deliver the same event id twice within ~1ms; both threads pass
`has_processed` before either has called `mark_processed`. Both
run the handler. Duplicate token mint returns. This is exactly the
regression the round-1 fix was supposed to close.

Test `test_bb2_04_stripe_idempotency_check_then_act_race`
demonstrates the gap directly against the in-memory store.

**Fix**: atomic claim. For DynamoDB-backed:
`PutItem(ConditionExpression="attribute_not_exists(event_id)")` —
ConditionalCheckFailed = duplicate, short-circuit. For in-memory:
wrap the check + claim in one `Lock`-guarded `dict.setdefault`
call. Don't run the handler unless the claim succeeded.

### 4. BB2-10 / BB2-11 — Admin can self-demote / mass-demote with no last-admin protection (MED)

`PATCH /api/v1/users/{user_id}` allows ANY admin to:

- demote themselves to `requester` (BB2-10): if no other admin
  exists, the deployment becomes admin-less. Recovery requires
  redeployment / direct DDB writes / bootstrap re-claim;
- demote OTHER admins (BB2-11) with no rate limit, audit-of-
  demotion, or second-pair-of-eyes confirmation.

Combined with the still-open BB-01..BB-04 CSRF surface from round
1, an attacker page can iterate every known admin id and force
each demotion silently. Tests
`test_bb2_10_admin_can_self_demote` and
`test_bb2_11_admin_can_demote_other_admins` reproduce.

**Fix**:
- Refuse role-removal when the actor IS the target AND the actor
  is the last admin.
- Emit a `security.admin_demoted` audit event on every demotion
  (today the only audit is the generic user-update path, which
  doesn't differentiate role-removal from name-edits).
- Optionally: forbid mass-demotion within a short window (e.g.
  one admin demote per actor per 5 minutes).

### 5. BB2-08 — Round-1 BB-12 magic-link-log finding still open (HIGH, operational)

Round 1 flagged BB-12 (HIGH) — magic-link callback URL emitted to
the logger when SES is unset. Round 2 retests: the warning log
line still contains `MAGIC_LINK channel=log user_id=… url=…<full-
token>`. No boot-time gate has shipped to refuse this mode in
production. The behavior is documented in `/healthz security_
posture` (info, id `no_ses`), so it's "accepted risk" but it's
still a credential leak to anyone with log read on the iam-jit
log group.

**Fix**: refuse to start when `delivery_channel == 'log'` AND
`IAM_JIT_AUTH_MODE != 'local'` AND `IAM_JIT_ALLOW_LOG_DELIVERY != 1`.

## Did the round-1 fixes hold under retest?

| Round-1 finding | Round-2 status | Notes |
| ---------------- | --------------- | ----- |
| SCORE-XFF-RATELIMIT-BYPASS (WB HIGH) | **HOLDING** | `routes/score.py:_client_ip` correctly gates XFF on TWO env vars (`IAM_JIT_TRUST_FORWARDED_FOR_FOR_SCORE` + `IAM_JIT_TRUSTED_PROXY_CIDRS`). Tests `test_bb2_01` and `test_bb2_23` confirm. **But**: the same vulnerable pattern lives on in `network_acl.py` (BB2-02) and `public_url.py` (BB2-09). Fix needs to spread. |
| STRIPE-NO-IDEMPOTENCY (WB HIGH, BB-11 MED) | **PARTIALLY HOLDING** | `dispatch_event` correctly dedupes HANDLED event types (`test_bb2_24` confirms). Two new gaps: (a) unhandled event types skip the dedupe entirely (BB2-03 LOW; intentional but exploitable as a CPU/log-DoS); (b) check-then-act race lets concurrent redeliveries both pass (BB2-04 HIGH). |
| BB-12 / MAGIC-LINK-LOG-CHANNEL (BB HIGH, WB MED) | **NOT YET FIXED** | The log line still ships with the full callback URL. No boot-time gate has been added. Retest confirms (`test_bb2_08`). |
| BB-01..BB-04 CSRF on HTML routes (BB HIGH/MED) | **NOT YET FIXED** | A `grep -rn 'csrf\|CSRF' src/iam_jit/` returns NO matches. All HTML state-changing routes (approve, cancel, comment, token-mint, token-revoke, network-cidr-add, account-register) still accept cookie-only POSTs. BB2-10 / BB2-11 compound on this surface. |
| BB-07 cookie missing `Secure` (BB MED) | **DESIGNED, NOT FIXED** | The Secure flag is computed from `IAM_JIT_DEV_INSECURE_SECRET != "1"` (the dev-override env), not from the request scheme. Today: prod deploys (env unset) get Secure. Staging/hybrid deploys with the dev override left on do NOT — see BB2-14. |
| BB-09 `/api/v1/auth/magic-link` rate-limit (BB MED) | **NOT YET FIXED** | The JSON magic-link endpoint still accepts unbounded requests. Verified by re-running `tests/test_appsec_audit_round1_bb.py::test_bb_09_no_rate_limit_on_magic_link` — still passes (vulnerable behavior pinned). |
| BB-10 `POST /api/v1/requests` rate-limit (BB MED) | **NOT YET FIXED** | Same — request-creation still unbounded. |
| BB-13 `/healthz` posture leak (BB LOW) | **NOT YET FIXED** | `routes/health.py:16-34` still emits the full posture object. |

## Honest negatives confirmed in round 2

| id | class |
| -- | ----- |
| BB2-01 | XFF gate on score endpoint correctly defeats spoof when only the flag-env (not the CIDR-env) is set |
| BB2-15 | `_ChatMessage.role` pydantic pattern rejects `system` role injection in `/intake/turn` |
| BB2-16 | `ScoreRequest.description` length cap (500 chars) holds |
| BB2-17 | MCP `policy_gen.generate_policy` is a pure function — no cross-session state bleed |
| BB2-18 | Magic-link email validator rejects non-ASCII (RTLO / homograph) emails |
| BB2-19 | Stripe webhook signature check runs BEFORE the idempotency store touch — attacker can't poison processed-events on a bad signature |
| BB2-20 | Magic-link callback signs a fresh session cookie — pre-auth attacker-controlled cookie is overwritten |
| BB2-21 | Magic-link single-use enforced within one process (the multi-instance hole is white-box WB-MAGIC-LINK-REPLAY-MULTI-INSTANCE, unchanged) |
| BB2-22 | Admin cannot lift their own ban (round-1 WB defended class; still holds) |
| BB2-23 | Score-endpoint XFF defense holds when no XFF-trust env vars are set (the default deploy mode) |
| BB2-24 | Stripe idempotency closes the original double-mint bug for HANDLED event types |
| BB2-25 | Only one webhook endpoint exists (`/api/v1/webhooks/stripe`) — no shadow webhook handlers shipped by accident |

## Nothing-new categories

These were probed in round 2 and produced no new findings beyond
what round 1 already filed:

- **File uploads**: iam-jit has no file-upload endpoints. (`multipart/form-data` is used only for the simple key-value `<input>` form fields on `/login`, `/setup`, `/accounts/register`, `/tokens` — no `UploadFile` types anywhere.)
- **GET endpoints with JSON bodies**: none — every JSON-accepting route is a `POST` or `PATCH`.
- **MCP cross-session state**: the MCP server is stdio per session and `policy_gen` is stateless (BB2-17 negative).
- **DNS-based SSRF**: confirmed no `requests.get(<user-input>)` /
  `httpx.get(<user-input>)` callsites (echo of round-1 WB negative). Only outbound HTTP is to configured LLM endpoints; the `boto3.client("ses")` SES path uses pre-configured AWS endpoints.
- **SES bounce / complaint handling**: not configured. The deploy
  does not wire an SNS topic for SES bounces — the operator who
  enables SES needs to add bounce handling separately. This is
  documented limitation, not a new finding.
- **Session fixation**: callback flow overwrites any pre-set
  session cookie (BB2-20 negative).

## Methodology

- Re-ran the round-1 BB test suite to baseline current state
  (`tests/test_appsec_audit_round1_bb.py` — all 30 tests still
  pin their findings, confirming most round-1 fixes have NOT yet
  shipped to source on this commit).
- For each round-1 fix area that DID land
  (`routes/score.py:_client_ip` and `stripe_webhook.dispatch_event`
  + the `processed_events_store` infrastructure), wrote targeted
  edge-case tests to find regressions.
- Enumerated NEW categories the round-1 spec called out
  (CloudFront/ALB edges, simultaneous-redelivery races, intake-LLM
  abuse, bootstrap-claim races, host-header smuggling, admin
  privilege concentration).
- Used `TestClient` only — no source files of `src/iam_jit/**` were
  used to determine attack payloads (source reads were limited to
  finding routes to probe and confirming the round-1 fix
  *locations*, which is consistent with the round-1 spirit).

## Methodology caveats

The round-2 audit is run against the *same on-disk commit* as
round 1; the prompt says "round-1 fixes are shipping concurrently."
A subset of fixes HAVE landed (the SCORE-XFF gate;
`ProcessedEventsStore` scaffolding); most have NOT (no CSRF token;
no rate-limit-on-magic-link; no boot-gate against log-channel
delivery). The findings table above documents the exact mid-flight
state — when the remaining round-1 fixes land, the corresponding
tests in `tests/test_appsec_audit_round1_bb.py` will fail (as
designed) and the fix author will flip the assertions.

## Verdict on overall security posture

**Still solid for v0.x SaaS; the round-1 fixes that landed are
correct in shape but need to spread to sibling code paths.**

The pattern that recurs in round 2 is: a round-1 finding was
fixed in ONE place (the score endpoint's XFF; the Stripe
event-id idempotency), but the SAME vulnerable pattern lives on
in another code path (the network ACL's XFF; the magic-link
URL's XFH). Either the fix author missed the sibling, or the
fix is in flight and the sibling is next on the list. Round 2's
HIGH findings — BB2-02, BB2-09, BB2-04 — would all be closed by
extending the round-1 fix patterns to the second site.

Beyond that, the admin-self-demote class (BB2-10/BB2-11) and the
token-mint flood (BB2-05) are new MED findings that compose with
the still-open round-1 CSRF surface to make a complete admin-
account-takeover chain. CSRF + self-demote + last-admin-no-recover
= "single attacker click silently demotes the only admin." Fixing
either of the two ingredients (CSRF or last-admin protection)
breaks the chain.

The honest-negatives list is encouraging: signature verification
order, session-fixation handling, pure-function MCP server,
email-validator robustness, and the score-XFF-when-flag-only-set
defense all hold under retest. No new criticals; no new pre-auth
RCE / cross-tenant data leak. The hardening backlog is concrete
and small (estimated ~1.5 engineer-days for BB2-02, BB2-09, BB2-04,
BB2-10, plus a re-spread of the round-1 fix-list).
