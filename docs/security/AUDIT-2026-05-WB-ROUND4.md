# iam-jit white-box appsec audit — round 4 (2026-05-14)

Fourth-pass white-box review on top of rounds 1, 2 and 3 (`AUDIT-2026-05-WB.md`,
`AUDIT-2026-05-WB-ROUND2.md`, `AUDIT-2026-05-WB-ROUND3.md`). Scoped to:

1. **Re-audit of round-3 closures** — `STRIPE-CLAIM-BEFORE-PROCESS`,
   `BB3-01` (logout server-side revocation), `BANS-DDB-FAIL-OPEN-VIA-ENV`,
   `BAN-STORE-CORRUPT-FILE-UNBAN`, `WEB-MAGIC-CALLBACK-BROKEN-AUTO-SEED`,
   `TOKENS-PER-USER-CAP-TOCTOU`, `BODY-SIZE-GUARD-CHUNKED-BYPASS`,
   `MAGIC-LINK-DEV-INSECURE-OUTRANKS-SES`,
   `DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN` (delivery leg only),
   `MAGIC-LINK-IP-LIMITER-PEER-ONLY-DOS`,
   `PUBLIC-URL-XFH-LEFTMOST-TOKEN`, `XFP-SCHEME-INJECTION-IN-PUBLIC-URL`,
   `TRUSTED-PROXY-CIDRS-PARSER-DISCREPANCY`, `XFF-IPV4-MAPPED-IPV6`.
2. **New surfaces introduced by the round-3 closures** — `session_revocation`
   module, `trusted_proxy` module, the per-user-mint `defaultdict[Lock]`,
   the chunked-encoding refusal, the `IAM_JIT_SESSION_REVOCATION_*`
   /`IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA` env vars.
3. **Cross-cutting fix-fan-out** — did the trusted_proxy SoT replace
   every inline parser? Did the dev-insecure Lambda gate land on all
   three legs (delivery, CSRF, Secure-cookie) or just one?

**Headline: 0 CRIT, 2 HIGH, 6 MED, 5 LOW (13 total).** The two HIGHs
are both regressions in round-3 closures: a STRIPE idempotency
"closure" that the operator can't actually enable on multi-instance
Lambda (the documented DDB-backed store isn't wired — env var is
silently ignored with a warning log), and a session-revocation fail-
open env var that, unlike its sibling `IAM_JIT_BANS_FAIL_OPEN`, was
added WITHOUT the "loud CRITICAL bypass log" treatment the round-3
audit explicitly mandated for that class.

The MEDs cluster around two themes:

- **Round-3 "fix the shape" closure didn't propagate to every sibling
  call site.** `_login_client_id` in `routes/web.py` still inlines its
  own CIDR parser instead of delegating to `trusted_proxy`. The
  bootstrap-admin auto-seed in `magic_callback` parses XFF inline with
  the LEFTMOST-TRUSTED shape that round-2 SCORE-XFF-LEFTMOST-TRUSTED
  closed everywhere else. Same shape: an attacker who controls XFF
  poisons the source-IP allowlist on first sign-in.

- **`IAM_JIT_DEV_INSECURE_SECRET=1` is still a 3-effect flag in prod.**
  The round-3 closure plugged ONLY the delivery leg (refuses to issue
  in-response link in Lambda unless `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1`).
  The CSRF-bypass leg (`app.py:236`) and the `Secure` cookie-flag-removed
  leg (`auth.py:252`, `web.py:611`) have NO such gate. A prod deploy
  that inherits the dev flag from `.env.example` ships with CSRF
  disabled and non-Secure cookies — independent of whether SES is
  configured.

Each finding has a corresponding pytest case in
`tests/test_appsec_audit_round4_wb.py`. Tests assert *current*
(vulnerable) behavior; when a fix lands, flip the assertion (or delete
the test) as part of the fix PR.

## Totals

| Severity  | Count  |
| --------- | ------ |
| CRIT      | 0      |
| HIGH      | 2      |
| MED       | 6      |
| LOW       | 5      |
| **TOTAL** | **13** |

### Severity breakdown by finding id

HIGH (2):

- `STRIPE-DDB-PROCESSED-EVENTS-UNWIRED` — `_build_processed_events_store_from_env`
  silently falls back to the in-memory store **even when**
  `IAM_JIT_PROCESSED_EVENTS_TABLE` is set. Multi-instance Lambdas
  remain non-idempotent for Stripe events. The round-3
  `STRIPE-CLAIM-BEFORE-PROCESS` closure is correct in-shape but only
  protects single-instance deployments; operators following the docs
  ("set the table for prod") will not actually get multi-instance
  idempotency. Location: `src/iam_jit/app.py:129-155`.

- `SESSION-REVOCATION-FAIL-OPEN-SILENT-BYPASS` — `IAM_JIT_SESSION_REVOCATION_FAIL_OPEN=1`
  silently disables the new server-side revocation check on DDB
  outage (or any exception from `is_revoked`). Unlike its sibling
  `IAM_JIT_BANS_FAIL_OPEN`, which round-3 explicitly hardened with a
  `.critical()` log on every bypass invocation
  (`middleware.py:236-241`, "ALARM ON THIS LOG"), this newer env was
  added WITHOUT the same loud-bypass treatment. An operator who
  flips it during a 503 incident leaves logged-out / revoked cookies
  fully valid until natural TTL, with no SIEM signal. Location:
  `src/iam_jit/middleware.py:159-181`.

MED (6):

- `WEB-LOGIN-CLIENT-IP-INLINE-CIDR-PARSER` — `_login_client_id`
  parses `IAM_JIT_TRUSTED_PROXY_CIDRS` and matches CIDRs inline
  instead of delegating to `iam_jit.trusted_proxy`. The exact
  shape round-3 `TRUSTED-PROXY-CIDRS-PARSER-DISCREPANCY` closed
  across `score.py`, `network_acl.py`, `public_url.py`, and the
  magic-link IP limiter. Location:
  `src/iam_jit/routes/web.py:198-259`.

- `BOOTSTRAP-AUTOSEED-XFF-LEFTMOST` — `magic_callback`'s bootstrap-
  admin auto-seed path takes `xff.split(",")[0].strip()` to seed
  the runtime CIDR allowlist with the caller's "real" IP. Same
  leftmost-XFF failure mode as round-2
  `SCORE-XFF-LEFTMOST-TRUSTED`. An attacker who racially-orders the
  first sign-in (e.g., compromises the bootstrap-admin's email
  inbox in a fresh deploy window) can submit `X-Forwarded-For:
  <attacker-CIDR>, real-cf-pop, fastly-pop` and pin the allowlist
  to the attacker's IP. Default is `IAM_JIT_TRUST_FORWARDED_FOR=1`
  (note: opposite of `network_acl.py`'s `"0"` default). Location:
  `src/iam_jit/routes/web.py:578-594`.

- `DEV-INSECURE-LAMBDA-GATE-CSRF-AND-COOKIE-LEGS-OPEN` —
  the round-3 `DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN` closure
  plugged ONE of the three legs (delivery). The CSRF bypass at
  `app.py:236` and the `Secure` cookie-flag removal at `auth.py:252`
  and `web.py:611` have NO `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA`
  / Lambda-presence gate. A prod deployment that inherits the
  dev flag — common when `.env.example` is copied as a starter,
  or when CI smoke-test env-vars bleed into the prod stage —
  ships with CSRF Origin/Referer checks disabled AND non-Secure
  cookies. Locations: `src/iam_jit/app.py:236`,
  `src/iam_jit/routes/auth.py:252`, `src/iam_jit/routes/web.py:611`.

- `SESSION-REVOCATION-IS-PER-COOKIE-VALUE-NOT-PER-USER` — server-
  side revocation hashes the COOKIE VALUE (`sha256(cookie)`), not
  `user_id`. A user who signed in from two browsers has TWO
  distinct signed-cookie values (different `t=` timestamps). Logout
  from Browser A only revokes A's cookie; Browser B's session
  remains valid until TTL. There is no "revoke all my sessions"
  primitive. An attacker who exfiltrated a stale-but-unexpired
  cookie from a separate device retains the session even after the
  user clicks logout. The fix sketch: also key revocations on
  `sha256(user_id)` and check both. Location:
  `src/iam_jit/session_revocation.py:36-69` +
  `src/iam_jit/middleware.py:148-158`.

- `BANS-IS-BANNED-RAISES-AT-MAGIC-LINK-ISSUANCE-LEAKS-REGISTRATION` —
  after the round-3 `BAN-STORE-CORRUPT-FILE-UNBAN` closure,
  `FilesystemBanStore.get` re-raises on a corrupt JSON file. The
  call site at `routes/auth.py:192` invokes
  `bans_mod.get_default_store().is_banned(user_id)` with no
  try/except — a corrupt ban file for a banned user produces a
  bare 500, while every other email returns the uniform 202
  ("if the email is registered, a link has been sent"). An
  attacker who corrupts (or witnesses corruption of) one specific
  ban file gains a registration / ban-status oracle for that user
  id. Location: `src/iam_jit/routes/auth.py:192`.

- `PER-USER-MINT-LOCKS-DEFAULTDICT-RACE-AND-LEAK` —
  `_PER_USER_MINT_LOCKS: dict[str, threading.Lock] = defaultdict(threading.Lock)`
  in `routes/tokens.py:36`. `defaultdict.__missing__` is two
  separate bytecodes — invoke factory, install value — so two
  simultaneous requests for the SAME user_id whose lock doesn't
  yet exist can each construct a different Lock instance and the
  one installed last wins; the loser thread holds an orphaned
  lock. Result: the TOCTOU race that round-3 `TOKENS-PER-USER-CAP-TOCTOU`
  attempted to close is re-introduced on the cold path (first
  mint per Lambda instance per user_id). The dict also has no
  eviction — an attacker who can mint-and-revoke or just iterate
  random `user.id` values can grow this dict without bound
  (memory DoS — minor in practice because `user.id` is bounded by
  the user store, but the unbounded-growth shape is wrong).
  Location: `src/iam_jit/routes/tokens.py:36, 77-96`.

LOW (5):

- `NETWORK-ACL-IPV4-MAPPED-IPV6-SOURCE-IP-ALLOWLIST` —
  `trusted_proxy.real_client_from_xff` returns the XFF candidate
  string verbatim (no IPv4-mapped normalization). `network_acl.evaluate`
  then `ipaddress.ip_address(source_ip)` keeps it as IPv6, and
  the cross-family `if isinstance(...) != isinstance(...)` skip at
  line 189-192 means a CIDR like `10.0.0.0/8` does NOT match a
  client whose XFF arrived as `::ffff:10.0.0.5`. Fails CLOSED
  (legitimate IPv4-mapped client locked out) so this is LOW. The
  round-3 `XFF-IPV4-MAPPED-IPV6` closure normalized the *peer*
  IP before the trusted-proxy CIDR check, but did NOT normalize
  the *returned candidate* before the source-IP allowlist check.
  Location: `src/iam_jit/trusted_proxy.py:113-137`,
  `src/iam_jit/network_acl.py:180-200`.

- `STRIPE-RELEASE-RACE-DOUBLE-MINT-ON-PARTIAL-FAILURE` —
  `dispatch_event` releases the claim on ANY handler exception. If
  `tokens_store.put(record)` succeeded BUT raised after the write
  (e.g., DDB throttle on the return path, or any subsequent line
  in the handler raises after the durable write committed), the
  release lets Stripe's retry mint a SECOND token. The customer
  ends up with N tokens for one paid subscription. Practical
  trigger: DDB partial write success + a flaky network on a
  Lambda timeout. Mitigated by: the per-user cap (max 50) and the
  per-user lock. Still a defense-in-depth gap. Location:
  `src/iam_jit/stripe_webhook.py:480-497`.

- `SESSION-REVOCATION-INMEMORY-NO-EVICTION-MEMORY-GROWTH` —
  `InMemorySessionRevocationStore.is_revoked` only opportunistically
  expires the SINGLE entry being checked (line 67); entries for
  hashes never re-checked stay forever. The store grows unbounded
  on a high-revocation workload (admin bulk-disable, password-
  rotation script). Bounded by the 24h cookie TTL × revocation
  rate; not exploitable as an attack but a slow memory leak. The
  DDB version uses TTL attribute — correct. Location:
  `src/iam_jit/session_revocation.py:48-69`.

- `SESSION-REVOCATION-GLOBAL-INIT-RACE-LOSES-REVOCATIONS` —
  `get_default_store()` lazy-init: two cold-start threads can both
  evaluate `_GLOBAL is None` as True, each constructs its own
  `InMemorySessionRevocationStore` instance, the second assignment
  wins. Any revocation made on the loser's transient instance is
  lost when the instance is GC'd. Tiny window (single cold-start
  per Lambda); won't matter in practice but is a real fail-open
  shape. Same shape applies to every `_GLOBAL`-pattern singleton
  in the codebase. Fix sketch: add a module-level
  `threading.Lock`. Location:
  `src/iam_jit/session_revocation.py:131-141`.

- `BODY-SIZE-GUARD-BREAKS-LEGITIMATE-STRIPE-WEBHOOK-CHUNKED` —
  the round-3 `BODY-SIZE-GUARD-CHUNKED-BYPASS` closure now refuses
  `Transfer-Encoding: chunked` with 411 BEFORE the CSRF exempt-
  path check has a chance to see `/api/v1/webhooks/stripe`. The
  body-size middleware runs at app.py:323 ahead of any path-aware
  exemption. While Stripe currently sends with Content-Length, any
  intermediate proxy that re-frames as chunked would have webhooks
  rejected — at which point the operator only sees 411s in Stripe's
  dashboard with no clue why. Defensive fix: exempt the Stripe
  webhook path from the chunked refusal (it has its own HMAC).
  Location: `src/iam_jit/app.py:323-372`.

## Per-finding writeups

### 1. STRIPE-DDB-PROCESSED-EVENTS-UNWIRED (HIGH)

- **CWE**: CWE-1325 (Improperly Controlled Sequential Memory Allocation) / CWE-799 (Improper Control of Interaction Frequency).
- **Severity**: HIGH — paid customers get multiple tokens on multi-instance Stripe webhook retries.
- **Location**: `src/iam_jit/app.py:129-155` (`_build_processed_events_store_from_env`).

```python
table = os.environ.get("IAM_JIT_PROCESSED_EVENTS_TABLE")
if not table:
    return InMemoryProcessedEventsStore()
# DynamoDB-backed implementation isn't shipped yet; in-memory
# works for single-instance Lambda. ...
_logging.getLogger(__name__).warning(...)
return InMemoryProcessedEventsStore()
```

The round-3 `STRIPE-CLAIM-BEFORE-PROCESS` closure assumes a durable
processed-events store. But the production wire-up at `app.py:129`
returns `InMemoryProcessedEventsStore` **regardless of whether
`IAM_JIT_PROCESSED_EVENTS_TABLE` is set** — only a warning is
logged. Multi-instance Lambdas (default for unreserved concurrency)
each have their own in-memory `_seen` dict. A Stripe retry that
lands on a different instance sees an empty dict, claims and re-
processes, mints a second token. The round-1 `STRIPE-NO-IDEMPOTENCY`
finding is therefore only partially closed: in single-instance
posture it's fixed; in multi-instance posture it's still open and
the operator has no way to fix it via configuration.

**Fix sketch**: ship the `DynamoDBProcessedEventsStore` (PutItem
with `ConditionExpression="attribute_not_exists(event_id)"`,
DeleteItem for release, TTL on a 30-day window) and have
`_build_processed_events_store_from_env` instantiate it when the
env var is set. Until then, REFUSE to start when
`AWS_LAMBDA_FUNCTION_NAME` is set AND
`IAM_JIT_PROCESSED_EVENTS_TABLE` is unset AND reserved-concurrency
isn't 1 — same defensive shape used for
`IAM_JIT_MAGIC_LINK_NONCES_TABLE`.

### 2. SESSION-REVOCATION-FAIL-OPEN-SILENT-BYPASS (HIGH)  # NEW-CODE

- **CWE**: CWE-732 (Incorrect Permission Assignment for Critical Resource) / CWE-755 (Improper Handling of Exceptional Conditions).
- **Severity**: HIGH — the headline closure (logout actually invalidates the cookie) can be silently turned off.
- **Location**: `src/iam_jit/middleware.py:159-181`.

```python
    except Exception:
        # Fail closed on revocation-store outage (same posture as
        # the BAN-CHECK-FAIL-OPEN closure). Override with
        # IAM_JIT_SESSION_REVOCATION_FAIL_OPEN=1 if availability
        # outranks revocation enforcement for the deployment.
        ...
        _logging.getLogger("iam_jit.session_revocation").exception(...)
        if (
            _os.environ.get("IAM_JIT_SESSION_REVOCATION_FAIL_OPEN") or ""
        ).lower() not in {"1", "true", "yes"}:
            raise HTTPException(status_code=503, ...)
    # FALLS THROUGH silently when FAIL_OPEN=1
```

The bans equivalent at `middleware.py:236-241` emits a `.critical()`
log line on every bypass invocation:

```python
logging.getLogger("iam_jit.bans").critical(
    "BANS_FAIL_OPEN bypass invoked for user_id=%s — store "
    "error, but enforcement was skipped because "
    "IAM_JIT_BANS_FAIL_OPEN=1 is set. ALARM ON THIS LOG.",
    user.id,
)
```

The round-3 `BANS-DDB-FAIL-OPEN-VIA-ENV` finding wrote, verbatim:
"this preserves the operator escape hatch but kills the silent-
bypass shape". The `SESSION_REVOCATION_FAIL_OPEN` env var was added
in the same round but did NOT inherit the loud-bypass treatment.

**Realistic mis-set**: an SRE chasing a "503 spike" alarm during a
DDB throttle event sets the flag to bring sign-ins back up while
they investigate, then forgets to clear it. Logged-out sessions
(and admin-revoked sessions, after the next round of features
land) silently remain valid until the cookie's natural 24h TTL.

**Fix sketch**: copy the exact CRITICAL-log pattern from the bans
fail-open path. Also: emit an `audit.emit` event with kind
`security.session_revocation_disabled` so the audit log retains a
durable record.

### 3. WEB-LOGIN-CLIENT-IP-INLINE-CIDR-PARSER (MED)

- **CWE**: CWE-710 (Improper Adherence to Coding Standards) / CWE-1389-adjacent.
- **Severity**: MED — drift between this parser and `trusted_proxy.parse_trusted_cidrs` produces inconsistent rate-limit keying.
- **Location**: `src/iam_jit/routes/web.py:198-259` (`_login_client_id`).

The round-3 `TRUSTED-PROXY-CIDRS-PARSER-DISCREPANCY` closure
extracted a single source-of-truth into `iam_jit.trusted_proxy` and
migrated `routes/score.py:_client_ip`, `network_acl._read_source_ip`,
`public_url._peer_in_trusted_proxy_cidrs`, and
`routes/auth._magic_link_client_ip` onto it.

`routes/web._login_client_id` was missed. It still inlines all four
behaviors:

```python
trusted_cidrs_raw = (os.environ.get("IAM_JIT_TRUSTED_PROXY_CIDRS") or "").strip()
...
for tok in trusted_cidrs_raw.replace(",", " ").split():  # no \n tolerance
    ...
peer_trusted = (
    peer_addr is not None
    and any(... peer_addr in n ...)
)  # no IPv4-mapped IPv6 normalization
if peer_trusted:
    xff = request.headers.get("x-forwarded-for") or ""
    if xff:
        tokens = [t.strip() for t in xff.split(",") if t.strip()]
        for candidate in reversed(tokens):
            ...
```

Bug-for-bug differences from `trusted_proxy`:

- No `.replace("\n", " ")` — a multi-line env var (Terraform
  heredoc) silently makes this parser see one entry per line as
  garbage. Score / network_acl / public_url / web's magic-link
  limiter all parse this correctly via the shared helper; the
  login form does not.
- No IPv4-mapped IPv6 normalization on `peer_addr` (same shape as
  the round-3 `XFF-IPV4-MAPPED-IPV6` closure that was supposed to
  land in EVERY trusted-proxy call site).

**Impact**: an operator with a CloudFront → ALB → Lambda stack and
a multi-line `IAM_JIT_TRUSTED_PROXY_CIDRS` value gets per-IP rate
limiting on `/login` keyed on `peer.host` (== ALB IP) → one user
exhausts the limit for everyone routed through the same ALB.

**Fix sketch**: delete the entire body of `_login_client_id` and
replace with the same two-line `trusted_proxy.real_client_from_xff`
call used by `_magic_link_client_ip`.

### 4. BOOTSTRAP-AUTOSEED-XFF-LEFTMOST (MED)

- **CWE**: CWE-348 (Use of Less Trusted Source).
- **Severity**: MED — bootstrap admin's runtime CIDR allowlist can be poisoned by an unauthenticated XFF spoof on first sign-in.
- **Location**: `src/iam_jit/routes/web.py:578-594` (`magic_callback`).

```python
xff = request.headers.get("x-forwarded-for") or ""
client_host = request.client.host if request.client else None
source_ip = None
if (
    os.environ.get("IAM_JIT_TRUST_FORWARDED_FOR", "1").lower()
    in {"1", "true", "yes"}
) and xff:
    source_ip = xff.split(",")[0].strip()
if not source_ip:
    source_ip = client_host
if source_ip:
    _cidr_store.auto_seed_for_bootstrap(
        source_ip=source_ip, user_id=user_id
    )
```

Three failures stacked:

1. **Default-on trust**: `IAM_JIT_TRUST_FORWARDED_FOR` defaults to
   `"1"` here (compare: `network_acl._read_source_ip` defaults to
   `"0"`). An operator who deliberately set it to `0` for
   `network_acl` is OVERRIDDEN here.
2. **Leftmost token**: `xff.split(",")[0].strip()` — exactly the
   shape round-2 closed everywhere else. An attacker who can hit
   `/auth/magic-callback?token=<their-own-token>` with
   `X-Forwarded-For: 198.51.100.0/24, real-cloudfront-pop`
   makes `auto_seed_for_bootstrap` insert `198.51.100.0/24` (or
   the singleton IP) into the runtime allowlist.
3. **No trusted-proxy gating**: there's no `peer_in_trusted_cidrs`
   gate — the XFF is trusted regardless of who the peer is.

**Trigger condition** (narrow but realistic): bootstrap admin
clicks their first magic-link inside a window where the attacker
can race the click. Real-world shape: attacker sees the deploy
URL go live (CF distribution or just `*.lambda-url.us-east-1.on.aws`
DNS probing), spams `/auth/magic-callback?token=...` with
attacker-IPs in XFF. The bootstrap admin (who hasn't claimed yet)
clicks their own legitimate link; AT THIS MOMENT auto-seed fires.
If the attacker has a parallel valid-token request in flight, the
race is theirs. Even simpler: attacker compromises the bootstrap
admin's email inbox briefly, clicks the link from a curl with the
attacker's XFF, gets the runtime allowlist seeded with their CIDR.
After this, the admin's `/admin/network` page shows the attacker's
IP as allowed — and the admin probably trusts the docstring that
says "we captured YOUR IP on first sign-in".

**Fix sketch**: replace the inline XFF parse with
`trusted_proxy.real_client_from_xff(client_host, xff)` and require
`IAM_JIT_TRUSTED_PROXY_CIDRS` to be configured before honoring XFF
at all (i.e., delete the `IAM_JIT_TRUST_FORWARDED_FOR` env-only
path).

### 5. DEV-INSECURE-LAMBDA-GATE-CSRF-AND-COOKIE-LEGS-OPEN (MED)

- **CWE**: CWE-1188 (Initialization with Insecure Default) / CWE-732.
- **Severity**: MED — a prod-with-dev-flag misconfig disables CSRF AND drops `Secure` from session cookies.
- **Location**: `src/iam_jit/app.py:236`, `src/iam_jit/routes/auth.py:252`, `src/iam_jit/routes/web.py:611`.

The round-3 `MAGIC-LINK-DEV-INSECURE-OUTRANKS-SES` closure plus the
delivery-leg fix (`magic_link_delivery.decide` now refuses
in_response in Lambda unless `IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA=1`)
addressed ONE of the three legs the round-3 audit identified for
`DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN`:

1. ✅ Delivery: refuses in_response in Lambda without the new gate.
2. ❌ CSRF bypass (`app.py:236`): `if os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") == "1": return await call_next(request)`. No Lambda check. A prod deploy with the flag set bypasses CSRF entirely.
3. ❌ `Secure` cookie attribute (`auth.py:252`, `web.py:611`): `secure=os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") != "1"`. No Lambda check. Session cookies issued without `Secure` over HTTPS still work, but they'll also be sent over any accidental plain-HTTP path (e.g., a misconfigured CloudFront origin).

The most realistic failure mode (per the round-3 writeup): an
operator copies `.env.example` to `.env`, forgets to delete the
dev flag, deploys to Lambda. The delivery leg is now refused at
runtime (loud); the CSRF and Secure-cookie legs are SILENTLY
disabled (quiet). The asymmetry is the bug: the closure should
have gated all three legs uniformly.

**Fix sketch**: extract a helper:

```python
def _dev_insecure_active() -> bool:
    if os.environ.get("IAM_JIT_DEV_INSECURE_SECRET") != "1":
        return False
    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return os.environ.get("IAM_JIT_ALLOW_DEV_INSECURE_IN_LAMBDA", "").lower() in {"1", "true", "yes"}
    return True
```

and call it from all four sites (delivery, CSRF, two cookie
setters). Even better: refuse module-import when
`IAM_JIT_DEV_INSECURE_SECRET=1` and `AWS_LAMBDA_FUNCTION_NAME` are
both set and the new allow flag is not — loud crash beats three
silent regressions.

### 6. SESSION-REVOCATION-IS-PER-COOKIE-VALUE-NOT-PER-USER (MED)  # NEW-CODE

- **CWE**: CWE-613 (Insufficient Session Expiration).
- **Severity**: MED — user expects "log me out" to invalidate every device; gets only the current device.
- **Location**: `src/iam_jit/session_revocation.py:36-69` + `src/iam_jit/middleware.py:148-158`.

```python
def _cookie_hash(cookie_value: str) -> str:
    return hashlib.sha256(cookie_value.encode("utf-8")).hexdigest()
```

Every magic-link sign-in mints a fresh signed cookie (the
TimestampSigner output includes the issue-time stamp). Two
browsers → two distinct cookie values → two distinct revocation-
list keys. Logout in Browser A only revokes Browser A's value.

**Trigger**: user signs in on laptop and on phone. Suspects their
laptop has been compromised, clicks "logout" from the phone.
Phone's session is revoked. Laptop session remains valid until
24h TTL — the attacker who exfiltrated the laptop's cookie keeps
working.

**Fix sketch**: store revocations keyed on
`sha256(verify_session(secret, cookie).user_id)` (or a versioned
"revoke-after-this-timestamp" per-user marker). On every auth
check, verify the cookie's issued-at against the user's revoke-
after marker — same shape Auth0 / Cognito / WorkOS use.
Alternative shorter-term fix: add an admin endpoint
`/api/v1/auth/logout-everywhere` that bulk-revokes per-user, and
document that the current `/logout` is per-device.

### 7. BANS-IS-BANNED-RAISES-AT-MAGIC-LINK-ISSUANCE-LEAKS-REGISTRATION (MED)

- **CWE**: CWE-203 (Observable Discrepancy).
- **Severity**: MED — a known-banned user's email address can be distinguished from an unknown email via 500 vs 202.
- **Location**: `src/iam_jit/routes/auth.py:192`.

```python
user_id = f"email:{email}"
# Refuse banned users at the link-issuance step too.
if bans_mod.get_default_store().is_banned(user_id):
    return {"status": "if the email is registered, a link has been sent"}
```

The round-3 `BAN-STORE-CORRUPT-FILE-UNBAN` closure changed
`FilesystemBanStore.get` to RAISE on `JSONDecodeError` instead of
silently un-banning. `is_banned` calls `get`. The call site here
has no try/except — a corrupt ban file for a specific user
produces a 500 response while every other email returns the
uniform 202.

**Trigger**: attacker who can read DDB / S3 / disk briefly (or any
other route that touches the same store and corrupts a known
user's row — e.g., a partial write) can probe `/api/v1/auth/magic-link`
with candidate emails and identify which one corresponds to the
corrupted row. The corruption oracle is narrow; the broader shape
is that the call site doesn't follow the same fail-closed-503
pattern the middleware uses (`middleware.py:217-250`) when ban-
store calls fail.

**Fix sketch**: wrap `is_banned` in try/except matching the
middleware pattern — log + return the uniform 202 on store
failure, OR explicitly 503 (which leaks "we have some kind of
backend trouble for this id" but at least is uniform across all
ban-store failure modes, not just corrupt-file).

### 8. PER-USER-MINT-LOCKS-DEFAULTDICT-RACE-AND-LEAK (MED)  # NEW-CODE

- **CWE**: CWE-367 (Time-of-check Time-of-use Race Condition) / CWE-401 (Missing Release of Memory after Effective Lifetime).
- **Severity**: MED — TOCTOU race that round-3 `TOKENS-PER-USER-CAP-TOCTOU` "closed" is re-introduced on the cold path; per-user-id memory growth.
- **Location**: `src/iam_jit/routes/tokens.py:36, 77-96`.

```python
_PER_USER_MINT_LOCKS: dict[str, threading.Lock] = defaultdict(threading.Lock)
...
with _PER_USER_MINT_LOCKS[user.id]:
    existing = store.list_for_user(user.id)
    if len(existing) >= cap:
        raise HTTPException(...)
    issued = issue_api_token(user.id, label=label)
    store.put(record)
```

**defaultdict race**: `defaultdict.__getitem__` for a missing key
is roughly:

```python
def __missing__(self, key):
    self[key] = value = self.default_factory()
    return value
```

This is multiple bytecodes. Two threads concurrently hitting
`_PER_USER_MINT_LOCKS["alice@example.com"]` when the key is absent
can both run `default_factory()` (create a NEW `threading.Lock`),
both `__setitem__` the dict (the second write wins), and each
thread receives the lock from its OWN `__missing__` call (because
`__missing__` returns the value it just `self[key] =`'d to). The
loser thread holds a Lock that's no longer in the dict; the winner
thread holds the Lock that's IN the dict. Both then proceed inside
their respective `with` blocks → no mutual exclusion → the TOCTOU
race re-emerges for the first concurrent mint pair per user_id
per Lambda instance.

(CPython detail: in some implementations a single dict-lookup-or-
insert is atomic via the GIL; `defaultdict.__getitem__` is NOT
documented to be atomic. Even if today's CPython happens to make
it atomic via the C implementation, relying on it without a
docstring claim is fragile.)

**Memory leak**: the dict has no eviction. After the Lambda
instance has served N distinct user_ids, it holds N Lock objects
forever. Bounded by the user store's max size; not exploitable as
DoS but still a real growth shape.

**Fix sketch**: wrap factory access in a module-level lock:

```python
_LOCKS_GUARD = threading.Lock()
_PER_USER_MINT_LOCKS: dict[str, threading.Lock] = {}

def _get_user_lock(user_id: str) -> threading.Lock:
    with _LOCKS_GUARD:
        lock = _PER_USER_MINT_LOCKS.get(user_id)
        if lock is None:
            lock = threading.Lock()
            _PER_USER_MINT_LOCKS[user_id] = lock
        return lock
```

Better long-term: replace with a DDB atomic-counter row per user
so the cap holds across Lambda instances. The per-user lock pattern
is fundamentally single-instance.

### 9. NETWORK-ACL-IPV4-MAPPED-IPV6-SOURCE-IP-ALLOWLIST (LOW)

- **CWE**: CWE-754 (Improper Check for Unusual or Exceptional Conditions).
- **Severity**: LOW — fail-closed (legitimate user locked out), not a bypass.
- **Location**: `src/iam_jit/trusted_proxy.py:113-137`, `src/iam_jit/network_acl.py:180-200`.

`real_client_from_xff` returns the XFF token verbatim:

```python
for candidate in reversed(tokens):
    try:
        cand_addr = ipaddress.ip_address(candidate)
    except ValueError:
        return peer_host
    # IPv4-mapped normalization for membership tests.
    if (
        isinstance(cand_addr, ipaddress.IPv6Address)
        and cand_addr.ipv4_mapped
    ):
        cand_addr = cand_addr.ipv4_mapped
    for n in nets:
        ...
        if cand_addr in n:
            break
    else:
        return candidate  # <-- the ORIGINAL string, not the normalized address
```

The normalization happens for the trusted-proxy CIDR membership
check but the return value is the raw XFF token. Downstream,
`network_acl.evaluate`:

```python
addr = ipaddress.ip_address(source_ip)
...
for net in networks:
    if isinstance(addr, ipaddress.IPv4Address) != isinstance(
        net.network_address, ipaddress.IPv4Address
    ):
        continue
    if addr in net:
        return CIDRDecision(allowed=True, ...)
```

If `source_ip == "::ffff:192.0.2.5"`, `addr` is an `IPv6Address`,
no IPv4 net matches, fall through to "ip_not_in_allowlist" → 403.
The legitimate IPv4 client gets locked out of a deployment whose
allowlist is `10.0.0.0/8`-shaped.

**Fix sketch**: in `real_client_from_xff`, when returning a
candidate, return the normalized form: `return str(cand_addr)`
(after the ipv4_mapped normalization). Or, normalize at every
downstream consumer.

### 10. STRIPE-RELEASE-RACE-DOUBLE-MINT-ON-PARTIAL-FAILURE (LOW)

- **CWE**: CWE-755 (Improper Handling of Exceptional Conditions).
- **Severity**: LOW — produces extra (not missing) tokens; bounded by per-user cap.
- **Location**: `src/iam_jit/stripe_webhook.py:480-497`.

The round-3 `STRIPE-CLAIM-BEFORE-PROCESS` closure releases the
claim on ANY handler exception. The handler's durable step
(`tokens_store.put(record)`) might have actually committed BEFORE
the exception escaped — DDB writes can succeed but raise on the
return path (network blip, Lambda timeout right after write).

Sequence:

1. `claim(event_id)` → True.
2. `tokens_store.put(record)` → succeeds in DDB.
3. Lambda timeout or network exception en route back from boto3.
4. `dispatch_event`'s `except Exception:` → `release(event_id)`.
5. Stripe retries. New invocation → `claim(event_id)` → True
   (the previous claim was released).
6. `tokens_store.put(record)` → succeeds again (different
   `token_hash` because `issue_api_token` generates fresh
   randomness).
7. Customer now has TWO tokens for one paid subscription.

Mitigations in place: per-user cap (default 50) limits the blast
radius; the dispatch_event response is logged. But the
release-on-any-exception heuristic IS the bug; the original
round-3 motivation ("permanent lockout on transient failure") is
fixed at the cost of "occasional double-mint on transient
failure".

**Fix sketch**: two-phase pattern. Claim with an `in_flight`
marker (TTL=5min). On success, promote to `done` marker
(TTL=30d). On crash, leave the `in_flight` marker — it expires
naturally on retry beyond the in_flight TTL. Or: make
`issue_api_token` idempotent on `(user_id, event_id)` so a retry
returns the SAME token row.

### 11. SESSION-REVOCATION-INMEMORY-NO-EVICTION-MEMORY-GROWTH (LOW)  # NEW-CODE

- **CWE**: CWE-401 (Missing Release of Memory after Effective Lifetime).
- **Severity**: LOW.
- **Location**: `src/iam_jit/session_revocation.py:59-69`.

```python
def is_revoked(self, cookie_value: str) -> bool:
    h = _cookie_hash(cookie_value)
    now = time.time()
    with self._lock:
        expires_at = self._revoked.get(h)
        if expires_at is None:
            return False
        if expires_at <= now:
            self._revoked.pop(h, None)
            return False
        return True
```

Only the single entry being checked is expired. Entries that were
revoked but never re-queried stay in `self._revoked` until the
Lambda instance recycles. On a bulk-revocation workload (admin
disables N users, or a credential-rotation script invalidates N
sessions) the dict accumulates indefinitely. Bounded by 24h × N,
but no upper cap. The `magic_link_nonces.InMemoryMagicLinkNonceStore`
does the right thing — sweeps ALL expired entries on every
`consume_or_reject` (line 56-58). The session revocation store
should mirror that.

**Fix sketch**: sweep all expired entries on every `revoke()` and
`is_revoked()` call (the cost is one O(N) pass per request; at
iam-jit's scale that's free).

### 12. SESSION-REVOCATION-GLOBAL-INIT-RACE-LOSES-REVOCATIONS (LOW)  # NEW-CODE

- **CWE**: CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization).
- **Severity**: LOW — narrow window (cold start), losing revocations only.
- **Location**: `src/iam_jit/session_revocation.py:131-141`.

```python
_GLOBAL: SessionRevocationStore | None = None

def get_default_store() -> SessionRevocationStore:
    global _GLOBAL
    if _GLOBAL is None:
        table = (os.environ.get("IAM_JIT_SESSION_REVOCATION_TABLE") or "").strip()
        if table:
            _GLOBAL = DynamoDBSessionRevocationStore(table)
        else:
            _GLOBAL = InMemorySessionRevocationStore()
    return _GLOBAL
```

Two threads concurrent during cold start can both observe
`_GLOBAL is None`. Each constructs an instance. One assignment
wins; the loser's instance is GC'd. If the LOSER thread completed
a `revoke()` call before being torn down, that revocation is
lost. The DDB variant is unaffected (no in-process state). The
in-memory variant has a narrow but real fail-open shape.

Same shape applies to most `_GLOBAL`-pattern singletons in the
codebase (`bans._GLOBAL`, `magic_link_nonces._GLOBAL`,
`intake_drafts._GLOBAL`, etc.). The pattern is wrong project-wide
but the only one that produces an auth-bypass shape is this one.

**Fix sketch**: protect the lazy-init with a module-level
`threading.Lock` or use `functools.lru_cache(maxsize=1)`.

### 13. BODY-SIZE-GUARD-BREAKS-LEGITIMATE-STRIPE-WEBHOOK-CHUNKED (LOW)

- **CWE**: CWE-755 (Improper Handling of Exceptional Conditions).
- **Severity**: LOW — defensive-only; Stripe currently sends Content-Length.
- **Location**: `src/iam_jit/app.py:323-372`.

The round-3 `BODY-SIZE-GUARD-CHUNKED-BYPASS` closure refuses
`Transfer-Encoding: chunked` with HTTP 411 in the middleware
before any path-aware exemption check. The Stripe webhook path
(`/api/v1/webhooks/stripe`) IS exempted from CSRF (line 222) but
NOT from the chunked refusal. Today this doesn't matter (Stripe
sends with Content-Length). But: any future intermediate (a
proxy, an SQS-to-Lambda adapter, a Stripe replay tool that
re-frames the body) that ships chunked would have webhooks return
411 — the operator only sees Stripe's dashboard saying "endpoint
returned 411", with no log line on iam-jit's side explaining why.

Note: Stripe's own retry behavior on 411 is unclear from the
docs — likely a non-retryable status. So the second-order effect
is that legit webhook events from a slightly-misconfigured
intermediate are DROPPED, not retried.

**Fix sketch**: exempt `/api/v1/webhooks/stripe` from the chunked
refusal (it has its own HMAC + size limits via Stripe's design).
Same pattern as the CSRF exempt path list at `app.py:221`.

## Cross-cutting theme

**"Fix lands at the named site; sibling sites and downstream
consumers get missed."** This theme dominated rounds 2 and 3 and
continues into round 4:

- The trusted-proxy SoT was the round-3 fix for this exact pattern.
  Round 4 finds the LAST call site missed (`_login_client_id`) and
  one downstream consumer where the normalization stops short
  (`real_client_from_xff` returns un-normalized string).
- The `IAM_JIT_DEV_INSECURE_SECRET` Lambda-gate fix landed on the
  delivery leg only; CSRF and Secure-cookie legs were noted in
  round 3 and explicitly NOT addressed.
- The `IAM_JIT_BANS_FAIL_OPEN` "loud bypass" pattern is the right
  shape; the sibling `IAM_JIT_SESSION_REVOCATION_FAIL_OPEN`
  introduced in the same round did NOT inherit it.
- The `STRIPE-NO-IDEMPOTENCY` closure depends on a DDB store that
  was never shipped; the env var is silently ignored.

For round 5, recommended sweeping action: an automated lint that
fails CI on any of `os.environ.get("IAM_JIT_TRUSTED_PROXY_CIDRS")`,
`xff.split(",")[0]`, `IAM_JIT_DEV_INSECURE_SECRET` lookup that
doesn't go through a single helper, `defaultdict(threading.Lock)`,
or `if _GLOBAL is None:` outside of a `with _LOCK:` block. These are
the round-2/3/4 recurring shapes.
