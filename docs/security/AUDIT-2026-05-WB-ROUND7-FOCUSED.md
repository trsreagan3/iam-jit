# iam-jit white-box appsec audit — round 7 (focused re-run, 2026-05-15)

Round-7 focused re-run after the previous round-7 attempt timed out
before reaching the most important new code. Scope is the four
modules added since round 6:

- `src/iam_jit/bridge_role.py`  (HIGHEST PRIORITY — mutates trust
  policies of EXISTING roles)
- `src/iam_jit/scoring_feedback.py` + `src/iam_jit/routes/feedback.py`
- `src/iam_jit/llm_budget.py`
- `src/iam_jit/ddb_utils.py` (sibling-miss verification)

Findings keyed `WB7F-NN`.

**Headline: 2 CRIT, 2 HIGH, 3 MED, 1 LOW (8 total).** All findings
are in `bridge_role.py` or its caller-contract; every one of them
fires the *first* time a real production caller invokes the module.
Tests pass because they use `iam_client_factory` which short-circuits
the broken code paths.

---

## Findings

### WB7F-01 — `_iam_client_for_role` references non-existent `account.external_id` (CRIT)

**File:** `src/iam_jit/bridge_role.py:170`

`_iam_client_for_role` calls
`sts_client.assume_role(..., ExternalId=account.external_id)`. The
`Account` dataclass in `accounts_store.py:40-41` has NO field named
`external_id` — the field is `provisioner_external_id` (and there's
also `discovery_external_id`). `provision.py:279,668` correctly
uses `account.provisioner_external_id`.

**Attack scenario:** None — this is a sibling-miss. But it means
the FIRST production call to `add_trust_for_grant` /
`remove_trust_for_grant` raises `AttributeError: 'Account' object
has no attribute 'external_id'`. Because that exception escapes the
explicit `TrustUpdateFailed` wrapper (it fires BEFORE the
update-policy call), the caller (sweep, route handler) sees a raw
500. Worse: in the `remove_trust_for_grant` path, an in-progress
sweep that fails here will keep stale Allow Statements on the trust
policy past expiry — the role keeps trusting the principal until a
subsequent successful sweep.

**Repro hint:** unit test `add_trust_for_grant` with
`iam_client_factory=None` and a mocked `sts_client` + a registered
account; observe `AttributeError`.

**Fix:** s/`account.external_id`/`account.provisioner_external_id`/.
This is the round-6 sibling-miss anti-pattern: `provision.py` was
written correctly; `bridge_role.py` was the new sibling that
copy-pasted incorrectly.

---

### WB7F-02 — `_read_trust_policy` mangles single-Statement trust policies (CRIT)

**File:** `src/iam_jit/bridge_role.py:218`

```
statements = list(policy.get("Statement") or [])
```

AWS IAM trust policies legally have `Statement` as EITHER a single
object OR an array. Single-object form is common — every "Allow
service.amazonaws.com to assume this role" template you find in AWS
docs is single-object. When `Statement` is a single dict
`{"Sid":"X","Effect":"Allow",...}`, `list(<dict>)` returns a list of
its KEYS — `["Sid","Effect","Principal","Action"]` — not the dict
itself wrapped in a list.

**Attack scenario / consequence:**

1. Customer has a HoopBridgeRole with single-statement trust:
   `{"Statement": {"Sid":"InitialBootstrap","Effect":"Allow",
   "Principal":{"AWS":"arn:aws:iam::ACCT:role/HoopBootstrap"},
   "Action":"sts:AssumeRole"}}`.
2. iam-jit calls `add_trust_for_grant`.
3. `statements` becomes `["Sid","Effect","Principal","Action"]`.
4. The filter-by-Sid loop runs `s.get("Sid")` on STRINGS — strings
   don't have `.get`, so it raises `AttributeError` AND/OR returns
   garbage.
5. If by some path it doesn't crash, the new policy written back is
   `{"Statement": ["Sid","Effect","Principal","Action",
   {our new statement}]}` — invalid policy, AWS rejects, role is
   left in unknown state mid-write. If validation is lax, the
   ORIGINAL trust grant is destroyed, locking the customer's
   bootstrap principal out.

**Repro hint:**

```python
client = _FakeIAMClient(initial_trust={
    "Version": "2012-10-17",
    "Statement": {  # single-object form
        "Sid": "Boot",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
        "Action": "sts:AssumeRole",
    },
})
bridge_role.add_trust_for_grant(_ROLE_ARN, _PRINCIPAL,
    int(time.time())+3600, "G-x",
    iam_client_factory=_factory_for(client))
```

**Fix:**

```python
raw = policy.get("Statement")
if raw is None:
    statements = []
elif isinstance(raw, dict):
    statements = [raw]
else:
    statements = list(raw)
```

Apply the same coercion in `remove_trust_for_grant:265`.

---

### WB7F-03 — `add_trust_for_grant` accepts attacker-controlled `principal_arn` with no validation (HIGH)

**File:** `src/iam_jit/bridge_role.py:197-239`

The function signature accepts `principal_arn: str` and embeds it
verbatim as `Principal: {"AWS": principal_arn}`. There is NO
validation that the value is a well-formed ARN, that the partition
matches the role, that the account is allow-listed, or that it
isn't `"*"` / `"arn:aws:iam::*:root"` / a wildcard form.

**Attack scenario:**

1. The bridge-role flow is documented as the integration path for
   Hoop / StrongDM / Teleport / "custom scripts" (`bridge_role.py`
   docstring lines 4-8).
2. A custom script bug, an admin UI form, or an MCP tool that
   forwards a user-supplied "who should this grant cover" string
   directly to `add_trust_for_grant` lets the caller install
   `Principal: {"AWS": "*"}` — a wildcard trust that allows ANY AWS
   account to assume the role, gated only by the DateLessThan
   condition.
3. The iam-jit deterministic safety floor is BYPASSED entirely
   because `add_trust_for_grant` doesn't go through `review` /
   `analyze_policy`. The whole point of iam-jit is the floor; the
   bridge-role path side-steps it.
4. There is also no allow-list of acceptable principal-shapes.
   `Principal: {"Federated": "saml-provider/anything"}` /
   `{"Service": "lambda.amazonaws.com"}` would be rejected by AWS
   (we hardcode the `"AWS"` key) — but `{"AWS": "*"}` and
   `{"AWS": "arn:aws:iam::999999999999:root"}` are accepted.

**Note on combined bugs:** combined with WB7F-02, an attacker who
can influence `principal_arn` can take a single-statement legit
trust policy, crash the read-modify-write, and either (a) lock out
the legit principal or (b) write `Principal: {"AWS": "*"}`
depending on how the policy survives the mangling.

**Repro hint:** call
`add_trust_for_grant(role_arn, "*", expires_at, "G-x")` against a
fake client; inspect `client.trust["Statement"]` for the wildcard.

**Fix:** validate `principal_arn` shape (regex
`^arn:aws[a-z\-]*:iam::\d{12}:(root|user/.+|role/.+)$` at minimum),
reject `"*"` and ARN forms with wildcards in the account or
resource segments, and document a caller-side allow-list contract.
Either the route layer or `add_trust_for_grant` itself MUST refuse
unsafe principal forms; today neither does.

---

### WB7F-04 — `wait_for_trust_propagation` confirms iam-jit's OWN access, not the granted principal's (HIGH)

**File:** `src/iam_jit/bridge_role.py:294-366`

The propagation wait calls `sts.assume_role(RoleArn=role_arn, ...)`
from the iam-jit Lambda's own credentials and declares "trust
propagated" on success (line 350-354). The function signature
accepts `principal_arn` and uses it only for logging (line 352, 360,
361). The actual STS call has no relationship to the principal that
was just granted.

**Attack scenario / failure mode:**

1. iam-jit Lambda's role is in the role's trust policy permanently
   (it must be, to test). So `wait_for_trust_propagation` succeeds
   on the very first attempt every time, regardless of whether
   `add_trust_for_grant` actually wrote the requested principal.
2. The "trust propagated" success is therefore a fail-open lie.
   If the trust write was silently corrupted (see WB7F-02), or the
   principal_arn was malformed and AWS quietly accepted it
   (e.g. typo in the account number), the engineer's first session
   STILL fails with AccessDenied — exactly the symptom this
   function was added to prevent.
3. A `PropagationTimeout` would fire only if iam-jit Lambda itself
   loses its ability to assume the bridge role — which means the
   trust write *destroyed* the Lambda's own access. The function
   detects the wrong failure mode.

**Repro hint:** unit test where the IAM stub records the policy
write but the policy doesn't actually contain `principal_arn`, and
the STS factory returns success. Function returns "propagated"
falsely.

**Fix:** the test caller must impersonate `principal_arn` (e.g.
chain-assume from a test role the customer registers; OR drop the
function and rely on a documented post-grant retry contract on the
caller side). The current implementation gives false confidence and
should be deleted if the impersonation path can't be implemented.

---

### WB7F-05 — `_parse_role_arn` mishandles role paths (MED)

**File:** `src/iam_jit/bridge_role.py:121-131`

For an ARN with a path like
`arn:aws:iam::111122223333:role/team/eng/HoopBridgeRole`,
`role_name = parts[5][len("role/"):]` becomes
`"team/eng/HoopBridgeRole"`. AWS IAM API methods like
`get_role(RoleName=...)` and `update_assume_role_policy(RoleName=...)`
require the **bare RoleName** (`HoopBridgeRole`), not the
path-prefixed name. The IAM call will fail.

Customers commonly use IAM paths to organize roles by team /
environment. The current code can't manage their bridge roles.

**Attack scenario:** none — this is a reliability bug, but it means
the `TrustUpdateFailed` exception propagates from a customer's first
real attempt, leaving the trust policy in an unknown state if the
read had succeeded but the write fails partway through retry logic
(none exists).

**Fix:** `role_name = parts[5].split("/")[-1]` and document that
the path is preserved by AWS automatically. Add a passing test for
path-prefixed ARNs.

---

### WB7F-06 — Trust-policy read-modify-write has no optimistic-concurrency guard (MED)

**File:** `src/iam_jit/bridge_role.py:217-226` and 263-283

`_read_trust_policy` then `_write_trust_policy` is a classic
read-modify-write race. AWS IAM's `update_assume_role_policy` does
NOT support a conditional `If-Match` / etag. Two concurrent
`add_trust_for_grant` calls (or `add` racing with `remove`) on the
same role will silently lose one of them — the later writer
overwrites the earlier writer's Statement set.

**Concrete scenario:**

1. Sweep timer fires `remove_trust_for_grant("G-old")` — reads
   policy with G-old + G-new1.
2. Concurrently, route handler fires `add_trust_for_grant("G-new2")` —
   reads policy with G-old + G-new1.
3. Sweep writes back: G-new1 only.
4. Route writes back: G-old + G-new1 + G-new2.

G-old is back. The sweep "succeeded" but the principal it removed
is still trusted.

**Fix options:** (a) serialize bridge-role writes per role_arn via a
DDB lock with TTL; (b) call `get_role` again after write and verify
post-state matches expected; (c) document concurrent-writer
limitation and gate via the existing `intake_drafts` lock.

---

### WB7F-07 — Feedback route uses raw `request.client.host` while score route has defended XFF resolver (MED)

**File:** `src/iam_jit/routes/feedback.py:97-101`

`_submitter_ip` reads `request.client.host` directly with no
XFF-trust-policy. The score route went through extensive hardening
(`_client_ip` at `routes/score.py:325-357` honoring
`IAM_JIT_TRUST_FORWARDED_FOR_FOR_SCORE` + trusted-proxy CIDRs)
explicitly to address SCORE-XFF-RATELIMIT-BYPASS (round 1 WB).

The feedback route is the **same shape**: per-IP rate-limited
endpoint accepting public POSTs. Behind ALB / CloudFront, every
anonymous submission shares one IP (the proxy's) — the 3/day cap
becomes a deployment-wide 3/day cap (fail-closed but DoSes itself).
Behind Lambda Function URL with no proxy, fine — but the
deployment topology isn't enforced anywhere, and the trusted-XFF
plumbing already exists.

This is the round-6 sibling-miss anti-pattern: the fix landed on
score.py but not on feedback.py. Note: failing closed (over-counting
shared IPs) is safer than failing open (forgeable XFF). But a
single anon attacker behind a residential CGNAT can DoS legitimate
neighbor submissions, AND in deployments where XFF *is* trusted
the shared `_submitter_ip` makes the per-IP limit forgeable — the
resolution is opposite directions in the two failure modes, so the
operator MUST get to choose. Today they can't.

**Fix:** call `_client_ip` from `routes/score.py` (extract to a
shared module first; mark with a comment that it must stay in lockstep
with score.py). Add an `IAM_JIT_TRUST_FORWARDED_FOR_FOR_FEEDBACK`
env knob mirroring the score one.

---

### WB7F-08 — `is_conditional_check_failed` substring fallback can match wrapper-embedded text (LOW)

**File:** `src/iam_jit/ddb_utils.py:29`

```python
return "ConditionalCheckFailedException" in str(exc)
```

Substring-match on `str(exc)`. This is the *only* fallback when the
boto3 `response["Error"]["Code"]` shape isn't present. Risk: a
wrapper exception that includes a CCFE in its `__cause__` chain or
a logging-context message can render as `str(exc)` containing the
literal phrase even when the *current* operation didn't fail
conditionally. With Python 3.11+ exception groups and
`add_note()`, an exception's `str()` can grow to include arbitrary
text including a previous ConditionalCheckFailedException string
captured in a retry log.

**Attack scenario:** none directly attacker-reachable. But this is
the kind of ambiguity that, combined with a future refactor to wrap
exceptions, will let `consume_or_reject` return `False` (budget
exceeded) when in reality the call succeeded — the customer is
billed for an LLM call that didn't happen, OR a customer with
budget remaining is denied LLM. Reverse direction is also possible.

**Fix:** narrow the fallback further — only check
`type(exc).__name__ == "ConditionalCheckFailedException"`, which
catches synthetic mocks (the documented use case) without
substring-matching wrapper messages. Drop the `in str(exc)` form.

Sibling-miss verification: the helper IS called from all 3 sites
(`stripe_webhook.py:480`, `magic_link_nonces.py:110`,
`llm_budget.py:169`) — no remaining inline patterns. Closure
itself is complete.

---

## What I checked and didn't find

- **Rate-limit bypass via header forgery in feedback.py**: aside
  from WB7F-07, the per-user counter keys on the *resolved*
  `record.user_id` from the token store, not on a header, so a
  forged header can't bypass the authed cap. The token-resolution
  path is the same code as score.py.
- **PATCH allowing non-admin self-service**: `mark_feedback_reviewed`
  is gated by `Depends(require_admin)` — fail-closed.
- **Admin GET leaking other-customer feedback**: yes, by design — the
  admin is the iam-jit operator, not a per-customer admin. Tests
  pin this. If iam-jit ever becomes multi-tenant in the same
  deployment, this needs revisiting; for the launch shape (one
  deployment per customer + iam-jit's own SaaS deployment) it's OK.
- **LLM budget tier-spoofing**: tier comes from the API token's
  `label` (Stripe-issued), not from a request body / header.
  Attacker would need to forge a Stripe webhook to set label —
  out of scope for this module, covered by stripe_webhook hardening
  in prior rounds.
- **LLM budget month-rollover race**: `_current_year_month()` is
  called inside `consume_or_reject` once per call; the DDB key
  changes at month boundary atomically. No race.
- **LLM budget env injection from request**: `IAM_JIT_LLM_BUDGET_*`
  is read from `os.environ` only; no code path writes to environ
  from request data.
- **DDB conditional helper substring shape**: addressed above
  (WB7F-08 LOW); mainline path uses the structured
  `response["Error"]["Code"]` check, fallback is only the
  string-match.
- **Feedback admin endpoints' lack of CSRF**: token-bearer model,
  not cookie-session, so standard CSRF doesn't apply.

---

## Severity counts

| Severity | Count |
|----------|-------|
| CRIT     | 2     |
| HIGH     | 2     |
| MED      | 3     |
| LOW      | 1     |
| **Total**| **8** |

All 4 CRIT/HIGH findings are in `bridge_role.py`. The module is not
yet called from any production code path (`grep` in `src/` returns
zero callers), so these are **pre-launch** bugs — fix before the
first production caller is wired up. Tests pass because the
`iam_client_factory` test seam short-circuits the `external_id`
attribute access (WB7F-01) and the test fixtures all use the
array-form `Statement` shape (WB7F-02).
