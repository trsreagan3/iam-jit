# iam-jit white-box appsec audit — round 2 (2026-05-14)

Second-pass white-box review on top of round 1
(`AUDIT-2026-05-WB.md`). Two objectives:

1. Re-audit the four round-1 HIGH fixes that shipped concurrently
   (`SCORE-XFF-RATELIMIT-BYPASS` landed in commit 788fb8c; the other
   three HIGHs are in progress).
2. Categories round 1 deferred — concurrency / TOCTOU, fail-open
   defenses, policy-gen / MCP server input handling, audit-callsite
   exception swallowing.

Each finding has a corresponding pytest case in
`tests/test_appsec_audit_round2_wb.py`. Tests assert *current*
(vulnerable) behavior; when a fix lands the test fails — flip the
assertion (or delete the test) as part of the fix PR.

## Totals

| Severity | Count |
| -------- | ----- |
| CRIT     | 0     |
| HIGH     | 2     |
| MED      | 4     |
| LOW      | 10    |
| **TOTAL**| **16**|

No critical findings. The two HIGHs are both *adjacent to round-1
fixes* — the fix surfaces are correct in shape but each has a
narrow correctness gap that re-opens the original threat.

### Severity breakdown by finding id

HIGH (2):

- `STRIPE-IDEMPOTENCY-TOCTOU` — `has_processed` then
  `mark_processed` is a TOCTOU race. Two concurrent Stripe
  redeliveries of the same event can both pass the dedupe check
  before either marks-processed. Reproduces the original
  `STRIPE-NO-IDEMPOTENCY` failure mode under concurrent delivery.
  Location: `src/iam_jit/stripe_webhook.py:392-403, 423-428`.

- `SCORE-XFF-LEFTMOST-TRUSTED` — the new `_client_ip` correctly
  gates XFF trust on a configured proxy CIDR list, but THEN
  returns `xff.split(",")[0].strip()` — the LEFTMOST entry.
  Standard XFF semantics: proxies APPEND the real client to the
  right; leftmost is whatever the attacker sent in their request.
  An attacker varying the leftmost XFF value defeats per-IP rate
  limit again, AND can burn legitimate IPs' rate-limit quotas
  under their key. Location:
  `src/iam_jit/routes/score.py:308-311`.

MED (4):

- `BOOTSTRAP-CLAIM-TOCTOU` — `_has_been_claimed` check + unconditional
  `user_store.put` is non-atomic; concurrent /setup POSTs can both
  succeed (`bootstrap_claim.py:139-149`,
  `users_store.py:277`).

- `BAN-CHECK-FAIL-OPEN` — middleware `current_user` wraps
  `is_banned()` in `try / except Exception: log+continue`.
  Documented design choice; we disagree — ban enforcement is a
  security control and should fail closed (503) on store error
  (`middleware.py:181-188`).

- `BAN-STORE-CORRUPT-FILE-UNBAN` — `FilesystemBanStore.get` treats
  `JSONDecodeError` as "not banned". A partial write or attacker
  with write access to the bans state dir silently unbans a user
  (`bans.py:117-120`).

- `TOKENS-NO-PER-USER-MINT-QUOTA` — `POST /api/v1/tokens` has no
  per-user cap, no rate limit. Authenticated users can burn DDB
  write capacity unboundedly. Pairs with round-1
  `TOKEN-LABEL-UNBOUNDED` for max amplification
  (`routes/tokens.py:35-63`).

LOW (10):

- `SCORE-XFF-IPV4MAPPED-IPV6` — IPv4-mapped IPv6 peer
  (`::ffff:10.x.y.z`) never matches an IPv4 trusted-proxy CIDR
  due to cross-family `in` semantics
  (`routes/score.py:295-313`).
- `SCORE-XFF-CIDR-PARSE-PERMISSIVE` — malformed entry in
  `IAM_JIT_TRUSTED_PROXY_CIDRS` silently `continue`'d; no
  log line, no startup validation (`routes/score.py:301-313`).
- `SCORE-API-KEY-NO-ROTATION` — single static key; rotation
  requires a redeploy that immediately breaks every caller
  (`routes/score.py:239-261`).
- `MCP-TASK-DESCRIPTION-UNBOUNDED` — `task` field on the MCP
  `tools/call` has no length cap (`mcp_server.py:157-200`,
  `policy_gen/result.py:101`).
- `MCP-INTERNAL-ERROR-LEAK` — `f"internal error: {e}"` returned
  to MCP caller on any handler exception (`mcp_server.py:288-289`).
- `MCP-ARN-SEGMENT-INJECTION` — caller-supplied `account_id`,
  `region`, `partition` interpolated into ARNs without validation
  (`policy_gen/resources.py:170-273`).
- `POLICY-GEN-NO-INJECTION-SCAN` — `task_description` and
  `refinement.rationale` not scanned by `prompt_injection.detect`
  (`policy_gen/generate.py`, `mcp_server.py`).
- `TOKEN-REVOKE-EXISTENCE-ORACLE` — distinct 200 vs 403
  for not-found vs not-yours hash; 2^256 makes it unexploitable
  but the failure-mode shape is wrong
  (`routes/tokens.py:87-102`).
- `AUDIT-EMIT-CALLSITES-SWALLOW` — 9+ `except Exception: pass`
  blocks around `audit.emit` in `routes/admin.py` alone; extends
  round-1 `AUDIT-WRITE-SILENT-FAILURE` to the route layer
  (`routes/admin.py` 203, 269, 353, 394, 482, 537, 662, 819, 861).
- `WEB-NO-CSRF-TOKEN` (CARRY-FORWARD) — round 1 finding restated
  to confirm the fix has NOT shipped (`routes/web.py`).

## Top 5 findings

### 1. STRIPE-IDEMPOTENCY-TOCTOU (HIGH)

`src/iam_jit/stripe_webhook.py:392-403, 423-428`

The round-1 fix added `processed_events_store.has_processed()` as
a short-circuit and `mark_processed()` AFTER the handler runs.
Two threads can both pass the check before either marks. The
`InMemoryProcessedEventsStore` is a plain dict with no internal
lock; the `Protocol` does not require atomicity from implementers.
The documented DynamoDB implementation has the same
get-then-conditional-write shape unless the implementer specifically
uses `PutItem(ConditionExpression="attribute_not_exists(...)")` —
not mentioned in the docstring.

Under realistic Stripe redelivery (network glitch causing a retry
~30s after the original) the original was already in-flight; the
retry sees `has_processed=False` simultaneously. Result: the
exact dual-token mint the fix was meant to prevent.

Test `test_finding_stripe_idempotency_toctou_under_concurrency`
reproduces this with two threads. Result: 2 tokens for one
subscription.

Fix sketch: rename the Protocol method to
`claim(event_id) -> bool` and require it to be atomic. In-memory
implementation uses a `Lock` around `setdefault`; DDB uses
`PutItem(ConditionExpression="attribute_not_exists(event_id)")`
and catches `ConditionalCheckFailedException` as "already claimed".

### 2. SCORE-XFF-LEFTMOST-TRUSTED (HIGH)

`src/iam_jit/routes/score.py:308-311`

```python
xff = request.headers.get("x-forwarded-for")
if xff:
    return xff.split(",")[0].strip()
```

The XFF spec: each hop APPENDS its client IP to the right end of
the header. So in `X-Forwarded-For: A, B, C`, A is the original
client. BUT — A is also whatever value the attacker chose to send
in THEIR initial XFF header. The proxies then append B, C to the
right. The LEFTMOST value (A) is therefore attacker-supplied even
when every proxy in the chain is trusted.

Attacker exploits this two ways:

1. Vary the leftmost XFF per request to defeat the per-IP rate
   limiter (the original `SCORE-XFF-RATELIMIT-BYPASS` exploit, NOT
   closed by the round-1 fix).
2. Send `X-Forwarded-For: <victim-ip>` to burn the victim's
   legitimate rate-limit quota — a denial-of-service against a
   chosen victim IP.

Fix sketch: walk the XFF list RIGHT-TO-LEFT, skipping any IP that
falls in `IAM_JIT_TRUSTED_PROXY_CIDRS`. The first non-trusted IP
from the right is the real client. This is the documented pattern
in AWS WAF's `forwarded_ip_config`, Django's
`SECURE_PROXY_SSL_HEADER` doc, and RFC 7239.

### 3. BOOTSTRAP-CLAIM-TOCTOU (MED)

`src/iam_jit/bootstrap_claim.py:139-149`

```python
if _has_been_claimed(user):
    return ClaimDecision(success=False, ..., reason="already_claimed")
# … construct marker …
user_store.put(updated)
```

Standard TOCTOU. Two concurrent /setup POSTs (operator's accidental
double-submit; or attacker racing a deployer's submission with the
known secret) both pass the check then both write. The DDB-backed
store's `put_item` has no `ConditionExpression`, so both writes
land — both threads return `success=True` and both get a valid
bootstrap-admin session cookie.

Test reproduces deterministically with a synchronized in-memory
store.

Fix sketch: write the claim marker conditionally —
`put_item(... ConditionExpression="attribute_not_exists(notes) OR NOT contains(notes, :marker)")`,
or move the marker into a separate sentinel record claimed via
`PutItem(ConditionExpression="attribute_not_exists(setup_claim)")`.

### 4. BAN-CHECK-FAIL-OPEN (MED)

`src/iam_jit/middleware.py:181-188`

```python
except HTTPException:
    raise
except Exception:
    # Fail-open if the bans store itself is broken — better to
    # keep serving legitimate users than to lock the system.
    logging.getLogger("iam_jit.bans").exception("ban check in middleware failed")
return user
```

The comment makes it clear this is a documented design decision.
We disagree. Ban enforcement IS the prompt-injection control's
enforcement leg — detection still fires, but the gate is silently
open during any store-internal error (DDB throttling, a corrupt
filesystem entry, a transient S3 5xx, an `ImportError` from a
refactor). The audit log already captured the original prompt-
injection event; the ban store's job is to deny subsequent
requests, and it abdicates silently here.

Fix sketch: treat `is_banned` exceptions as "ban status unknown"
and return 503 (transient). 503 surfaces in operator alarms; the
current behavior is invisible.

### 5. BAN-STORE-CORRUPT-FILE-UNBAN (MED)

`src/iam_jit/bans.py:117-120`

```python
try:
    data = json.loads(self._path_for(user_id).read_text())
except (FileNotFoundError, json.JSONDecodeError):
    return None
```

`FilesystemBanStore.get` treats a corrupted ban file as "not
banned". `is_banned` is `get() is not None`. So any partial write
(crash during `write_text`), filesystem corruption, or attacker
write to the bans dir produces a silent unban. The audit-log
record of the ORIGINAL ban remains intact — only enforcement is
disabled.

Fix sketch: on `JSONDecodeError`, raise (or treat as banned + emit
a CRITICAL log line). Fails closed, surfaces the operator's
broken state immediately, and treats the audit log as
authoritative.

## Re-audit of round 1 fixes

| Fix | Status | Notes |
| --- | --- | --- |
| `SCORE-XFF-RATELIMIT-BYPASS` | **REGRESSION** | The env-var gate is correct; the leftmost-XFF parse re-introduces the original bypass when XFF trust IS enabled. See `SCORE-XFF-LEFTMOST-TRUSTED` (HIGH). The IPv4-mapped IPv6 footgun (`SCORE-XFF-IPV4MAPPED-IPV6`, LOW) and silent malformed-CIDR skip (`SCORE-XFF-CIDR-PARSE-PERMISSIVE`, LOW) are correctness gaps in the same fix. |
| `STRIPE-NO-IDEMPOTENCY` | **HOLDS UNDER SERIAL DELIVERY; RACE UNDER CONCURRENT REDELIVERY** | Two-step `has_processed` → `mark_processed` is TOCTOU. Test reproduces dual-mint with 2 threads. See `STRIPE-IDEMPOTENCY-TOCTOU` (HIGH). |
| `MAGIC-LINK-REPLAY-MULTI-INSTANCE` | **NOT YET FIXED** | `magic_link_nonces.py` default store is still `InMemoryMagicLinkNonceStore`. Round-1 test still passes (asserts vulnerable state). |
| `BAN-MULTI-INSTANCE-DESYNC` | **NOT YET FIXED** | `bans.py:get_default_store` still defaults to in-memory. Round-1 test still passes. Plus this round: `BAN-CHECK-FAIL-OPEN` (MED) on the middleware code path and `BAN-STORE-CORRUPT-FILE-UNBAN` (MED) on the filesystem store. |
| `SCORE-API-KEY-TIMING` (MED) | **NOT YET FIXED** | Still `if token != expected:`. |
| `MAGIC-LINK-LOG-CHANNEL` (MED) | **NOT YET FIXED** | `magic_link_delivery.py:113-117` still logs full link. |
| `STRIPE-EMAIL-COLLISION` (MED) | **NOT YET FIXED** | `stripe_webhook.py:236` still uses customer-supplied email as `user_id`. |
| `EXTERNAL-ID-PREDICTABLE` (MED) | **NOT YET FIXED** | `onboarding.py:165-166` still `f"iam-jit-{account_id}"`. |
| `AUDIT-WRITE-SILENT-FAILURE` (MED) | **NOT YET FIXED** | `audit.py:202-211` still bare `except OSError: pass`. Plus this round: `AUDIT-EMIT-CALLSITES-SWALLOW` (LOW) on the 9+ route-handler call sites that swallow `audit.emit` failures. |
| `RATE-LIMIT-MULTI-INSTANCE-BYPASS` (MED) | **NOT YET FIXED** | `rate_limit.py:71` still in-memory. |
| `MAGIC-LINK-JSON-NO-RATELIMIT` (MED) | **NOT YET FIXED** | `routes/auth.py:55-102` still has no rate limit. |
| `WEB-NO-CSRF-TOKEN` (MED) | **NOT YET FIXED** | `routes/web.py` still has no token, no Origin / Referer check. Round-2 carry-forward test confirms. |
| `STRIPE-VERBOSE-SIGNATURE-ERROR` (MED) | **NOT YET FIXED** | `routes/webhooks_stripe.py:112-117` still `detail=f"signature verification failed: {e}"`. |

The only round-1 fix that shipped (`SCORE-XFF-RATELIMIT-BYPASS`)
regressed in a different way; the four HIGH fixes documented as
in-progress haven't landed yet on disk.

## Honest negatives — checked and adequately defended

These were probed in round 2 and the app's existing defense is
correct. No work-to-do signal.

- **JSON deserialization gadget surface** — `grep -rn "object_hook"
  src/iam_jit/` returns no hits; `json.loads` is called with no
  `object_hook` parameter anywhere. No risk of class-loading
  during `loads` (which is the standard Python-side equivalent of
  pickle's deserialize-arbitrary-class problem).

- **`subprocess` / `os.system` / `shell=True`** — no callsites
  anywhere in `src/iam_jit/` (only a comment reference in
  `assume.py`). No shell-injection surface.

- **Hardcoded credentials** — `grep -rn 'password\s*=\s*"\|secret\s*=\s*"\|api_key\s*=\s*"\|access_key\s*=\s*"' src/iam_jit/`
  returns nothing. Every credential-shaped value reads from env
  or a config store.

- **`random.*` for cryptographic material** — `grep -rn "random\."
  src/iam_jit/` returns nothing. All entropy comes from
  `secrets.token_urlsafe` / `secrets.token_*`.

- **`yaml.load` (unsafe)** — every YAML loader in the codebase
  uses `YAML(typ="safe")`. The single `typ="rt"` instance in
  `schema.py` reads a static package-shipped schema file (no
  user input). Confirmed unchanged from round 1.

- **HMAC comparison consistency** — `hmac.compare_digest` is used
  for the Stripe webhook signature (`stripe_webhook.py:130`) and
  the bootstrap setup key (`bootstrap_claim.py:113-115`). The
  one remaining `!=` compare on the score API key is round-1
  finding `SCORE-API-KEY-TIMING` (MED, not yet fixed).

- **Test coverage of unauth attempts (401) on protected routes**
  — every route in `routes/{requests,tokens,policy,intake,admin,
  users,blacklist,accounts,reports}.py` declares a
  `Depends(current_user | require_admin | require_approver |
  require_requester)` parameter; FastAPI dependency injection
  forces 401 / 403 before the body runs. The auth path was
  exhaustively reviewed in round 1 and no new bypass surfaced.

- **DynamoDB query parameterization** — confirmed in round 1, no
  changes since (no new query sites).

- **Path traversal via request id → filesystem** — confirmed in
  round 1, no changes since.

- **MCP server uses safe JSON-RPC parsing** — `json.loads(line)`
  with no `object_hook`; safe. Per-line cap missing (round-1
  finding `MCP-NO-MESSAGE-CAP`, LOW); per-field cap on `task`
  also missing (round-2 finding `MCP-TASK-DESCRIPTION-UNBOUNDED`,
  LOW).

- **Score endpoint blacklist evasion oracle** —
  `routes/score.py:486-525` correctly returns generic 400 to
  anonymous callers, specific 400 to authenticated callers.
  Anonymous bisection-of-the-blacklist is defeated.

- **Bootstrap setup key compared constant-time** — confirmed in
  round 1; the bootstrap claim TOCTOU (round 2) is a separate
  concurrency issue, not a comparison weakness.

## Methodology

Files re-read in round 2 (delta-focused on round-1-fix sites + the
deferred categories):

- `src/iam_jit/routes/score.py` — the new `_client_ip` (full read,
  XFF parsing focus)
- `src/iam_jit/stripe_webhook.py` — the new `ProcessedEventsStore`
  protocol + `dispatch_event` claim path
- `src/iam_jit/bootstrap_claim.py` — race scrutiny on the
  check-then-write claim flow
- `src/iam_jit/middleware.py` — current_user ban-check fail-open
- `src/iam_jit/bans.py` — corrupt-file handling on the filesystem
  store
- `src/iam_jit/magic_link_nonces.py` — round-1 fix not yet
  shipped; no new analysis
- `src/iam_jit/mcp_server.py` — JSON-RPC + exception leak
- `src/iam_jit/policy_gen/*.py` — entire new feature (added in
  last 14 days per round-2 scope)
- `src/iam_jit/routes/tokens.py` — per-user quota gap +
  revoke-existence oracle
- `src/iam_jit/routes/admin.py` — count `except Exception: pass`
  blocks around audit emits

Tools: `grep`, direct file read, `pytest` to confirm each new
finding's test reproduces vulnerable behavior.

Out of scope: the IAM risk-scoring engine (covered by the
adversarial-loop workstream that converged at round 10).

## Next-action ordering for the fixer

Highest leverage first:

1. **STRIPE-IDEMPOTENCY-TOCTOU** — same fix as
   `MAGIC-LINK-REPLAY-MULTI-INSTANCE` (DDB
   ConditionExpression-based atomic claim). Both fixes need the
   same DDB table pattern; ship them together.
2. **SCORE-XFF-LEFTMOST-TRUSTED** — five-line change in
   `_client_ip` to walk the XFF list right-to-left. Plus a
   warning log on malformed CIDRs and an IPv4-mapped IPv6
   normalization step (covers `SCORE-XFF-CIDR-PARSE-PERMISSIVE`
   and `SCORE-XFF-IPV4MAPPED-IPV6` in the same diff).
3. **BOOTSTRAP-CLAIM-TOCTOU** — small additional change to the
   DDB user store: add a `put_if_not_claimed` method that uses
   `ConditionExpression`. Then `evaluate_and_claim` calls that
   instead of plain `put`.
4. **BAN-CHECK-FAIL-OPEN** — flip the `except Exception:` arm
   to return 503. One-line change in `middleware.py`.
5. **BAN-STORE-CORRUPT-FILE-UNBAN** — flip the `except` arm in
   `bans.py:117-120` to raise (or to return a sentinel "ban
   status unknown" that callers handle the same as #4).

The two HIGHs are the cycle's headline; the MEDs are
straightforward follow-up.
