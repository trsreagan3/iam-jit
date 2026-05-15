# WB Audit Round 10 — Delta since Round 9 (safety-mode + doctor + WB9 closures)

Scope: code in the round-10 changelist only. Specifically:

- `src/iam_jit/safety_mode.py` (new)
- `src/iam_jit/auto_approve.py` (new `effective_threshold`)
- `src/iam_jit/routes/requests.py` (wiring)
- `src/iam_jit/accounts_store.py` (`safety_mode_override`, `llm_policy*`)
- `src/iam_jit/cli.py` (doctor subcommands)
- `src/iam_jit/routes/oidc.py` + `src/iam_jit/oidc.py` (WB9 closures)
- `src/iam_jit/slack_bot.py` (WB8-02/03/04 closures)
- `src/iam_jit/routes/score.py` (per-account LLM wiring)

Findings keyed `WB10-NN`.

---

## WB10-01 — CRIT — DynamoDBAccountStore silently drops `safety_mode_override` and `llm_policy*`

**Location**: `accounts_store.py` `DynamoDBAccountStore._to_item` (lines 309–332) and `_from_item` (lines 334–349).

The `Account` dataclass now carries three new fields: `llm_policy`, `llm_policy_reason`, `safety_mode_override`. The `FileAccountStore` round-trip (`_account_from_dict`/`_account_to_dict`, lines 108–156) is correct. The DynamoDB round-trip is NOT — neither `_to_item` nor `_from_item` reads/writes any of these three fields.

Impact on a production deployment (DynamoDB-backed is the only documented production shape per `accounts_store.py` docstring):
1. Admin sets `safety_mode_override="strict"` on the prod account → write returns success, value silently discarded. Account is read back in `read_write_swap` mode. Auto-approve threshold for reads is 9 (default mode) instead of the intended 5. **Strict mode is unenforceable on DynamoDB deployments.**
2. Admin sets `llm_policy="deterministic_only"` on a PII-bearing account → ignored. LLM is consulted on every grant. Compliance violation for customers who used this gate to keep policy text out of Bedrock/Anthropic.

There is no other write path; `accounts_store.put()` is the only sink. There is no migration shim for old items lacking the fields (the `_from_item` `.get()` calls would still return None even if `_to_item` wrote them, because `_to_item` never sets them).

This isn't an exploitability finding from an external attacker, but from the iam-jit threat model — admin assumes their tightening took effect when it didn't — it's CRIT. Memo `[[safety-mode-two-modes]]` explicitly designs around the deployment-default-`read_write_swap` / opt-up-`strict` model; that model is silently broken on the production backend.

**Fix**: serialize/deserialize the three fields in `_to_item`/`_from_item` mirroring the File store.

---

## WB10-02 — HIGH — `effective_threshold` bypasses the `max_auto_approve_risk_below` floor

**Location**: `auto_approve.py` lines 124–128; `safety_mode.py` `_THRESHOLDS_BY_MODE`; `routes/requests.py` lines 312–328 (preview) and 502–526 (submit).

`Floors.max_auto_approve_risk_below` (default 5) is the platform-team-owned ceiling per the [[settings-vs-floors]] model. It is enforced only at settings PATCH time via `validate_against_floors` — not at decision time.

Round 10 routes the safety-mode-derived `effective_threshold` directly into `auto_approve.evaluate` with no floor check. For the deployment-default mode (`read_write_swap`) with `access_type=read-only`, that threshold is hardcoded to **9** in `safety_mode._THRESHOLDS_BY_MODE`. The platform team's `max_auto_approve_risk_below=5` SCP-equivalent is silently overridden.

Concrete exploitation path:
1. User submits a request with `access_type: "read-only"` and a policy containing a mislabeled-write action against a non-blocklisted service, e.g. `dynamodb:DeleteTable`.
2. `review.py` lines 2233–2240 score the mislabel at **8**.
3. `iam`/`sts`/`kms` etc. are floored on the service blocklist, but `dynamodb`, `s3`, `lambda`, `ec2`, `rds`, `dms`, `eks`, `glue`, `ssm`, `ec2:Terminate*`, `s3:DeleteBucket`, etc. are NOT in the default `required_service_blocklist`.
4. Score 8 < threshold 9 → auto-approved by `system:auto-approver`.

The user did not have to be malicious — they could have an agent that defaults `access_type` to `"read-only"` while writing a write policy. Either way the floor is bypassed.

**Fix options**: (a) cap `effective_threshold` by `floors.max_auto_approve_risk_below` in the route before passing in; or (b) in `auto_approve.evaluate`, apply `threshold = min(threshold, floors.max_auto_approve_risk_below)`. Option (b) is the safer single-point-of-truth fix.

---

## WB10-03 — HIGH — heterogeneous-account requests evaluate safety mode against `accounts[0]` only

**Location**: `routes/requests.py` lines 309–317 (preview) and 506–515 (submit).

`_first_account = _accounts[0].get("account_id") if _accounts and isinstance(_accounts[0], dict) else None`. The resolved safety mode is then used for the WHOLE request, including grants targeting the OTHER accounts in `accounts[]`.

Exploit: a user files a single request whose `accounts` list is `[{dev-account-no-override}, {prod-account-with-strict}]`. The resolver picks dev → `read_write_swap` (threshold 9). The grant on the prod account is auto-approved at the loose threshold despite the admin's per-account strict opt-in.

The same issue applies to `llm_account_policy.decide` in score.py only when `account_id` is supplied (single-account path there), so this is requests-route-specific.

**Fix**: resolve mode per account in the request; if ANY account in the request requires strict, use strict for the whole grant (worst-mode-wins). Or refuse multi-account requests crossing modes with a 409.

---

## WB10-04 — HIGH — Strict-mode `allow_action_wildcards` and `allow_admin_fallback` are advisory-only (unenforced)

**Location**: `safety_mode.py` lines 51–52, 79–80; full repo grep.

`SafetyModeThresholds.allow_action_wildcards` and `allow_admin_fallback` are exposed on the dataclass, set differently per mode, and never consulted anywhere in the codebase. Strict mode claims (per the module docstring) to forbid action wildcards in synthesized policies and forbid the admin-fallback escape hatch, but there is no enforcement site — `policy_gen/`, `narrow.py`, `provision.py`, `review.py`, `lifecycle.py` do not import `safety_mode`.

Customers who buy strict mode (Pro/Team's compliance angle) will get the tighter auto-approve thresholds and `extended_audit_retention=True` (also unused, see WB10-08), but get strict-mode promises in the docs that the implementation doesn't keep. This is a product-truth bug, not a remote exploit, but it directly contradicts the [[safety-mode-two-modes]] memo and a customer reading the strict-mode docs would assume an enforcement that isn't there.

**Fix**: either (a) wire `allow_action_wildcards=False` through `policy_gen` / score-route advice / submit-route refusal; (b) remove the unused flags from the dataclass until they're implemented; or (c) document that strict mode currently only differs in thresholds + retention until the wildcards/fallback gates ship.

---

## WB10-05 — MED — Audit details for auto-approve do not capture safety mode / effective threshold

**Location**: `routes/requests.py` lines 532–548; `auto_approve.AutoApproveDecision.details` (success path lines 211–215).

The audit `details` for `request.auto_approved` / `request.auto_approve_skipped` includes `score` + `threshold` but NOT the safety mode (`read_write_swap` vs `strict`) nor whether the threshold came from `settings.auto_approve_risk_below` vs the safety-mode resolver. Two grants on the same account scored 4 — one in read-only at read_write_swap (threshold 9) and one in read-write at strict (threshold 2) — would render identically in audit.

This breaks compliance review (auditor cannot prove "this grant was made under strict mode") and breaks the adversarial-loop feedback channel (calibration corpus loses the mode signal).

**Fix**: thread `effective_threshold`, `mode`, and `access_type` into the audit `details` on emit. The route already has these as locals.

---

## WB10-06 — MED — `WB9-01` (MFA cookie binding) closure protects a cookie that is never read

**Location**: `routes/oidc.py` lines 288–305; full-repo grep for `iam_jit_session_mfa` and `oidc-mfa` salt.

The MFA-presence cookie is now bound to `user.id` at write time (good defensive change). However, NO code reads the cookie anywhere — `middleware.py`, `auth.py`, `assume.py`, `provision.py`, the routes, the lifecycle module — none consume `iam_jit_session_mfa` or unsign the `oidc-mfa` salt. `aws:MultiFactorAuthPresent` Conditions are scored at policy-text level (`review.py`) but never injected into trust policies at provision time based on the cookie.

So the WB9-01 closure is correct, but the underlying feature is a no-op: MFA assertion from the IdP is captured, stored in a cookie, and discarded. A defended cookie binding around a cookie that authorizes nothing has no real impact.

Calling this MED rather than INFO because the MFA roadmap [[mfa-compliance-roadmap]] depends on a downstream consumer existing; future consumers must check the binding (compare `mfa:{session.user.id}` against the current session user.id at unsign time). If the consumer ships and merely calls `unsign()` without that comparison, the WB9-01 fix is undone.

**Fix**: (a) add a test that asserts the consumer (when written) compares the unsigned payload to the current session user.id; or (b) document the read-side contract inline in `routes/oidc.py` near the write so future authors can't miss it.

---

## WB10-07 — LOW — `_AMR_MFA_VALUES` is module-frozen with no env override despite docstring

`oidc.py` line 486 promises a future `IAM_JIT_OIDC_AMR_MFA_VALUES` override. None exists; the comment is aspirational. Not a security finding — flagging because the documented escape hatch for customers who want SMS counted as MFA doesn't exist and may surprise an operator who reads the comment.

---

## WB10-08 — LOW — `extended_audit_retention` flag is unused

Same shape as WB10-04 but for the audit-retention promise. Strict-mode customers expecting longer-tail audit retention by virtue of mode selection won't get it — retention is governed independently by `log_retention.py` / `audit.py` config.

---

## WB10-09 — INFO — `score.py` `llm_skip_detail` echoes admin-authored `llm_policy_reason` to the caller

The caller in this path is an authenticated paid-tier customer scoring policy against THEIR own account. Information disclosure to self is not a finding. Flagging only because a multi-tenant deployment (shared-IdP, multi-customer-on-same-API-token) would let one customer see another's admin notes via `llm_skip_detail`. iam-jit's per-customer-token model precludes this today; if multi-tenant Stripe linking ever conflates `customer_id`s the surface would matter.

---

## WB10-10 — INFO — `score.py` `account_id` enumeration via `llm_skip_reason` is gated to paid tier

`account_id` probing produces different `skip_reason` values for in-store vs not-in-store accounts, but only for paid tiers (`pro|team|enterprise`) that already know their own account IDs. Free tier returns `tier_does_not_use_llm` uniformly. No anonymous enumeration. No action.

---

## WB10-11 — INFO — `doctor slack` posts a message to the configured channel

By design. Stdout reveals workspace name + bot name + bot user_id from `auth.test`; no tokens. The command is CLI-only (not registered as a route in `routes/`). Anyone with shell access to the deployment host can already exfiltrate the bot token from env; the doctor command does not add surface. No action.

---

## WB10-12 — INFO — `_endpoints_cache` TTL refresh works on long-lived Lambdas

WB9-04 TTL is 3600s. Lambda concurrent instances expire well before that in normal traffic; provisioned-concurrency instances live indefinitely and the TTL correctly causes a re-discovery once per hour. Verified the comparison is `cached[0] > now` (greater-than, expires at `now + ttl` mark) — correct. No race within a Lambda instance (single-threaded). No action.

---

## Summary

- 1 CRIT (WB10-01): `safety_mode_override` + `llm_policy*` are silently dropped on the DynamoDB store — strict mode and the per-account LLM gate are unenforceable in production.
- 3 HIGH (WB10-02/03/04): floor bypass via `effective_threshold`; heterogeneous-account requests pick mode from `accounts[0]` only; strict-mode wildcards/admin-fallback flags are unenforced.
- 2 MED (WB10-05/06): audit doesn't capture mode/threshold; MFA cookie binding protects a cookie nothing reads.
- Remainder are LOW/INFO.

Priority recommendation: ship WB10-01 (one-line DDB fix) and WB10-02 (floor cap) before any customer relies on safety_mode for compliance positioning. WB10-03 + WB10-04 close behind. WB10-05 unlocks the calibration corpus + compliance story and is cheap.
