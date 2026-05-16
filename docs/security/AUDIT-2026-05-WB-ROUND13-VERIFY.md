# WB Audit Round 13 — verification of Round-12 fixes (commits `b0efd45` + `3838486`)

Scope: confirm the round-12 CRIT/HIGH/MED fixes actually close the findings they
claim, and probe for regressions / new issues introduced by the fixes.

Findings keyed `WB13-NN`. Each `verify` entry says **PASS** or **FAIL**, citing the
test/proof. New findings carry severity + recommended fix.

---

## Round-12 fix verification

### WB13-01 — WB12-01 (import path) — **PASS**

`from ..middleware import _get_secret as _auth_secret_getter` appears at
`src/iam_jit/routes/requests.py:485` (preview) and `:747` (submit). The import
still lives inside the `try/except` block (lazy), but `from iam_jit.middleware
import _get_secret` resolves at runtime (verified).
`tests/test_mfa_enforcement_e2e.py::test_high_risk_request_no_mfa_cookie_blocks_auto_approve`
exercises the full route end-to-end and PASSES (state stays `pending`,
auto_approve=False). The pre-fix dead code path is closed.

### WB13-02 — WB12-02 (owner field) — **PASS** with caveat

`self_approve_reductions.evaluate` now reads `(status.owner OR metadata.owner)`
at `src/iam_jit/self_approve_reductions.py:124-130`.
`tests/test_mfa_enforcement_e2e.py::test_admin_self_approve_in_solo_mode_with_fresh_mfa`
PASSES. Probed disagreement scenarios (status.owner=alice, metadata.owner=attacker,
authenticated user=attacker) — `status.owner` wins because it's evaluated FIRST in
the OR; the attacker scenario correctly returns `not_owner`. Caveat: see WB13-08.

### WB13-03 — WB12-03 (env-var clamp) — **PASS**

Probed `_high_risk_score_floor`: `999→10, 0→1, -5→1, abc→7, ""→7, 7→7, 1→1, 10→10`.
Probed `step_up_max_age_seconds`: `999999→86400, 0→30, -5→30, abc→300, 30→30,
29→30, 86400→86400, 86401→86400`. Both clamps work as documented.
**Test gap**: no unit test in `tests/test_mfa_gate.py` exercises the clamp
boundaries — `999/-5/86401/29` paths are untested. See WB13-09.

### WB13-04 — WB12-04 (`bool()` coercion) — **PASS**

Probed with `would_require_mfa` set to `1`, `'yes'`, `'True'`, `[1]` (and
`mfa_present=0/''/None/[]`); MFA gate fires correctly in all four cases. The
`bool()` coercion in `_apply_mfa_and_self_approve_enforcement:95-98` works.

### WB13-05 — WB12-05 (preview enforcement) — **PARTIAL PASS / functional gap**

`/preview` does call `_apply_mfa_and_self_approve_enforcement` at
`routes/requests.py:519-525`. Probed: high-risk policy + no MFA cookie →
`would_auto_approve=False`. But the response `auto_approve_decision.reason` is
`above_threshold`, **not** `mfa_required_for_high_risk`, because the score gate
denies first and the MFA branch never runs (see WB13-07). The dial flips
correctly, but the user cannot tell from the preview that fresh MFA would
unlock auto-approve. UX-trust angle of WB12-05 is only half-closed.

### WB13-06 — WB12-11 (response-body leak) — **PASS** with caveat

`auto_approve_decision.details` in the MFA-block path no longer includes
`original_reason`, `score`, `mfa_reason`, `mfa_age_seconds`, `policy_size_chars`,
or `threshold` (probed via direct helper call). `block_response.reason` is the
opaque `"fresh_mfa_required"` literal. **Caveat**: the score still leaks via
`response.review.risk_score` (the canonical UX field for the dial). The
WB12-11 fix only closed the leak inside `auto_approve_decision`. An attacker
probing the score oracle reads `response.review.risk_score` instead. Not a
regression — this field predates round 12 — but the WB12-11 mitigation is
narrower than the threat model implies.

### WB13-07 — WB12-08 (strict-mode allow-list) — **PASS**

Probed: self-approve override fires for `above_threshold` only; correctly does
NOT fire for `strict_mode_action_wildcard`, `strict_mode_admin_fallback`,
`service_blocked`, `over_quota`, `feature_disabled`. Mechanism is the
`reason == "above_threshold"` equality check at line 136. No regression test
pins this contract for the OTHER reasons; if a maintainer broadens the check
the strict-mode bypass re-opens silently.

---

## New findings introduced by / surfaced during round-12 fixes

### WB13-08 — **CRIT** — MFA gate is bypassed by self-approve when score gate already denied

Reproduced end-to-end (`/tmp/test_mfa_bypass3.py`):

- Settings: `auto_approve_risk_below=3`, `IAM_JIT_DEPLOYMENT_MODE=solo`,
  `IAM_JIT_MFA_STEP_UP_AT_SCORE=7`.
- Admin user, **no MFA cookie**, policy `ec2:RunInstances on *` → score 8.
- Score gate denies `above_threshold` (score 8 >= threshold 4).
- Helper enters `_apply_mfa_and_self_approve_enforcement`. The MFA branch (line
  101) requires `_auto_approve_currently AND _would_require_mfa AND not
  _mfa_present`. Because `auto_decision.auto_approve` is already `False` from
  the score gate, `_auto_approve_currently=False`, so the MFA branch is skipped.
- Self-approve branch (line 134) fires (admin + solo + owner), flips decision
  to `auto_approve=True, reason="self_approve_reduction"`.
- Request transitions `pending → provisioning → active` and the IAM role is
  provisioned, **with no fresh MFA**.

Final response: `{auto_approve: True, reason: 'self_approve_reduction',
details: {score: 8, original_reason: 'above_threshold', ...}}`, state=`active`.

Layer C of `[[mfa-compliance-strategy]]` is bypassed by the very admin
population it's designed to step-up. PCI 8.x / SOC 2 CC6.x rows in
`COMPLIANCE-MAPPING.md` are again "implemented but not enforced" — same shape
as WB12-01, different mechanism. Self-approve is supposed to skip APPROVAL,
not skip MFA freshness on high-risk grants.

**Fix**: evaluate the MFA gate independently of the score-gate verdict. Move
the MFA check to apply on EITHER the original auto-approve verdict OR the
self-approve override:

```python
# 1. Self-approve override fires first (no MFA assumption either way).
if (not _auto_approve_currently
    and getattr(auto_decision, "reason", "") == "above_threshold"
    and _self_approve_eligible):
    auto_decision = ... self_approve_reduction ...
    _auto_approve_currently = True

# 2. THEN MFA gate runs unconditionally on whatever decision we have.
if _auto_approve_currently and _would_require_mfa and not _mfa_present:
    return blocked, "system:auto-approver", block_response
```

Add an integration test mirroring the bypass repro above.

### WB13-09 — **MED** — `mfa_step_up_max_age_seconds` field is misnamed; it carries the score-floor (1-10), not seconds

`routes/requests.py:113`:

```python
"mfa_step_up_max_age_seconds": mfa_audit.get("mfa_step_up_floor"),
```

`mfa_step_up_floor` is the SCORE floor (e.g., `7` from `_high_risk_score_floor()`,
range 1-10). It is being assigned to a key named `_max_age_seconds`, which
clients will reasonably interpret as "MFA cookie max age in seconds". Effect:
the MFA-block response body tells API clients "your MFA must be fresher than 7
seconds" instead of the actual default 300 seconds. A client honoring the
field would force a re-login on every MFA-block — degraded UX + broken
documentation. Likely a copy/paste typo introduced in the WB12-11 fix.

**Fix**: either (a) rename the response field to `mfa_step_up_score_floor` (it
IS the score-floor that triggered the gate, which is informative) and ALSO
add a `mfa_step_up_max_age_seconds` field carrying the actual
`step_up_max_age_seconds()` value, or (b) just emit the actual seconds value.
Add a test that asserts `mfa_step_up_max_age_seconds >= 30` (i.e., a value
that could plausibly be seconds).

### WB13-10 — **MED** — Clamp boundaries (`999`, `0`, `-5`, `86401`, `29`) are not unit-tested

`tests/test_mfa_gate.py` covers the default (7) and one valid override (5),
plus the `not-an-int` fallback. None of the clamp boundaries are tested.
A future maintainer "simplifying" `_high_risk_score_floor()` could remove the
clamp without breaking any test.

**Fix**: add parametrize tests for the boundary values shown in WB13-03.

### WB13-11 — **LOW** — `metadata.owner` fallback is reachable from client input

The route does NOT strip `metadata.owner` from the client-supplied payload
(`routes/requests.py:636` does `dict(_metadata_raw)` which preserves any
caller-supplied keys; only `id`, `name`, `requester` are explicitly overwritten).
Today this is harmless because `lifecycle.init_status` always writes
`status.owner` (which the OR check evaluates first). But the WB12-02 fix
introduced a SECONDARY trust in `metadata.owner`. If any future code path
creates a request without calling `init_status` (e.g., a CLI import that
bypasses the route, a future `auto_grant.py` that writes directly to the
store), `metadata.owner` becomes the only owner field, and an attacker who
can inject into the JSON body can control it.

Today only `routes/requests.py:690` and `routes/web.py:1391, 1497` call
`init_status` in the request-creation path. Verified by grep — no other
code writes `status["owner"]` (apart from `store.py` which only READS).

**Fix**: explicitly drop `metadata.owner` from the client payload right after
the `metadata = dict(_metadata_raw)` line in submit_request, the same way
`status` is dropped. Defense-in-depth so a future ingestion path can't
silently re-introduce the WB12-02 attack class.

### WB13-12 — **LOW** — `# type: ignore[attr-defined]` comment lingers on a now-correct import

Both `routes/requests.py:485` and `:747` still carry
`# type: ignore[attr-defined]` on the `from ..middleware import _get_secret`
import. With the import path corrected, the type-ignore is no longer needed
(`_get_secret` IS defined in `middleware.py` — verified by reading line 59 of
that file). The lingering comment hides any FUTURE attribute-error regression
from mypy. The round-12 commit message acknowledged this and said it would
remove the comment but did not.

**Fix**: drop the `# type: ignore[attr-defined]` from both lines.

### WB13-13 — **INFO** — No regression test pins the strict-mode reason allow-list

WB12-08 closure relies on the `reason == "above_threshold"` equality check.
A future maintainer "improving" this to `reason in {"above_threshold",
"strict_mode_action_wildcard"}` would silently re-open the strict-mode
bypass. The audit memo said add tests for `strict_mode_*`, `service_blocked`,
`over_quota`, `feature_disabled`, `floor_clamped`, `no_policy` → `decision is
original`. Probed manually (PASS for `strict_mode_action_wildcard`,
`strict_mode_admin_fallback`, `service_blocked`, `over_quota`,
`feature_disabled`); no unit test pins it.

**Fix**: parametrize `test_self_approve_does_not_override_*` over the full
non-overridable reason set.

---

## Headline summary

Round-12's claimed fixes mostly hold. **WB12-01, WB12-02, WB12-03, WB12-04,
WB12-08, WB12-11 all PASS** under direct probe. WB12-05 (preview enforcement)
is wired but the user-visible reason on a high-risk-no-MFA preview is
`above_threshold` rather than `mfa_required_for_high_risk` — the dial flips
correctly but the diagnostic text doesn't tell the user "fresh MFA would
unlock this," which was a stated goal.

**One new CRIT (WB13-08)**: the MFA freshness gate is bypassable when the
score gate already denied + admin is self-approve eligible. Reproduced
end-to-end: a high-risk policy (`ec2:RunInstances on *`, score 8) submitted
by an admin in solo mode with no MFA cookie transitions all the way to
`active` (provisioned IAM role). The MFA branch only fires when
`auto_decision.auto_approve` was originally `True`; when score-gate denies
first, MFA never gets a chance. Fix: run self-approve FIRST, then run MFA
unconditionally on the final auto-approve decision.

Two MEDs: WB13-09 (response field `mfa_step_up_max_age_seconds` carries the
score-floor 1-10 instead of the cookie age in seconds — likely a copy/paste
bug), and WB13-10 (env-var clamp boundaries are untested, regression risk).

Two LOWs (WB13-11 metadata.owner client-controllable but harmless today;
WB13-12 lingering `type: ignore`) plus one INFO (WB13-13 regression-test
gap on strict-mode allow-list).

Recommended ship order:

1. **WB13-08 CRIT first** — reorder helper so MFA runs after self-approve;
   add the bypass repro as a test case.
2. WB13-09 — fix the misnamed response field.
3. WB13-10 + WB13-13 — backfill the regression tests for clamp + strict-mode
   allow-list.
4. WB13-05 polish — wire `mfa_required_for_high_risk` into the preview
   reason text so the dial diagnostic explains "MFA needed."
5. WB13-11 + WB13-12 — defense-in-depth + cleanup.

Until WB13-08 is closed, `[[mfa-compliance-strategy]]` Layer C should
again be marked "implemented but bypassable for self-approve-eligible
admins; see AUDIT-2026-05-WB-ROUND13" in `COMPLIANCE-MAPPING.md` so PCI
auditors get the right answer.
