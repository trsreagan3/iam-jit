# Round 21 audit — Guided reduction OSS scaffolding (#156)

Commit under review: `8b30d6d` (`feat(guided-reduction): OSS checklist + apply tools for agentless UI users (#156)`).

Scope: `src/iam_jit/guided_reduction.py` (211 LOC) + `src/iam_jit/mcp_server.py` (+109 LOC: 2 tools + dispatch wiring) + `tests/test_guided_reduction.py` (248 LOC, 20 tests). Read-only audit. Per [[audit-cadence-discipline]].

Regression: **1997 passed, 29 skipped, 14 deselected** (88s, excluding `tests/e2e/*` which needs `playwright`, and `tests/test_calibration_corpus.py` which has 96 pre-existing failures unrelated to #156 — verified by re-running against `HEAD~1` and getting the same 96 failures). Matches the audit-prompt baseline exactly.

## Headline

8 findings: **0 CRIT, 1 HIGH, 3 MED, 4 LOW.**

The user's biggest worry was right: **`deny-secrets`'s description and implementation disagree**, and so does `deny-s3-writes` (which is a complete no-op). Both are the same shape as the WB19-MED-01 silent-fail-open pattern, in a new module. `deny-iam-admin`'s "stops principal-pivot" claim is partially overstated (the specific create-role-then-assume path is blocked, but other lateral-movement vectors — `s3:PutBucketPolicy`, `kms:CreateGrant`, assuming pre-existing roles that trust this principal — are not). The MCP wiring, input validation, aggregation logic, and dispatch flow are clean; the test suite verifies mechanics but never verifies the description claims that the implementation must back, which is itself a test-coverage gap. The forward-compat "unknown IDs silently ignored" property holds for unknown IDs, but does NOT hold for unknown reduction axes — silently dropping a future axis is a Round-22+ trap.

The HIGH (`deny-s3-writes` is a labeled no-op that lies in `selected_item_ids`) is the single most important fix before this lands in any UI.

## Closure status

| Finding | Status |
|---|---|
| HIGH-21-01 `deny-s3-writes` produces zero policy changes; `reduction_values=()` is empty; the item silently does nothing while `selected_item_ids` reports it as applied — the audit chain lies | OPEN |
| MED-21-01 `deny-secrets` description claims "Secrets Manager + SSM Parameter Store + KMS Decrypt"; implementation only denies `secretsmanager:*`. SSM SecureString parameter values and KMS `Decrypt` are NOT blocked. Same shape as WB19-MED-01 | OPEN |
| MED-21-02 `deny-iam-admin` "principal-pivot escape" claim is partially correct (blocks `iam:CreateRole`/`PutRolePolicy`/`PassRole`) but does NOT block lateral moves via `s3:PutBucketPolicy`, `kms:CreateGrant`, `lambda:AddPermission`, or `sts:AssumeRole` into pre-existing roles that already trust this principal. Description overpromises | OPEN |
| MED-21-03 Test suite verifies mechanics (statement count, action presence) but NEVER verifies the description claims of any checklist item — the same gap that let WB19-MED-01 slip through. No test asserts that `deny-secrets` denies `ssm:*` or `kms:Decrypt`, and no test asserts that `deny-s3-writes` actually blocks any S3 write | OPEN |
| LOW-21-01 `apply_selections` silently drops items whose `reduction_axis` is anything other than `"deny_services"`. The dataclass docstring lists `"deny_specific_services"` as a valid axis; if a future OSS item or Enterprise-plugin item uses a non-deny_services axis, it will silently no-op | OPEN |
| LOW-21-02 `apply_selections` reports unknown IDs in `selected_item_ids` as filtered out, but does NOT distinguish "selected and applied" from "selected and known but produced no effect" (e.g. `deny-s3-writes`). Audit chain conflates the two | OPEN |
| LOW-21-03 `apply_selections(policy=None, ...)` crashes with `AttributeError` deep inside `reductions.deny_services` instead of returning a structured error. MCP wrapper validates; direct callers (Enterprise plugin) get an opaque crash | OPEN |
| LOW-21-04 `_apply_reduction_checklist_for_mcp` validates `selected_item_ids` is a list but does NOT validate items inside are strings. Caller can send `[1, 2, 3]`; downstream filtering silently drops them. Aligns with `_reduce_policy_for_mcp` validator depth, but worth tightening | OPEN |

## CRIT findings

None.

## HIGH findings

### HIGH-21-01 — `deny-s3-writes` is a labeled no-op; the audit chain reports it as applied

- File: `src/iam_jit/guided_reduction.py:119-129`
- Issue: the checklist item declares:
  ```python
  ReductionChecklistItem(
      id="deny-s3-writes",
      label="I don't need to WRITE to S3",
      description=(
          "Block s3:Put*, s3:Delete*, s3:CreateBucket*. Keeps read "
          "access; blocks all modifications. Useful for read-only "
          "investigation grants."
      ),
      reduction_axis="deny_services",
      reduction_values=(),  # placeholder — s3 write blocking is handled differently
  ),
  ```
  The `reduction_values=()` is empty. `apply_selections` aggregates `deny_services_acc.extend(item.reduction_values)` for each selected item with `reduction_axis == "deny_services"`. For `deny-s3-writes`, the extension contributes zero strings. The aggregated `deny_services_unique` is unchanged; `apply_reductions` is called with the same list it would have been called with had `deny-s3-writes` not been selected.

  Repro (verified):
  ```
  apply_selections(admin_policy, selected_item_ids=["deny-s3-writes"])
  → policy: unchanged (just the original Allow * on *)
  → summary: "no reductions applied"
  → recipe: []
  → selected_item_ids: ["deny-s3-writes"]   ← LIES
  ```
  The UI user ticks "I don't need to WRITE to S3", the audit log records "selected: deny-s3-writes", the scorer evaluates the unchanged Allow `*` on `*`, the policy STILL grants `s3:PutObject` / `s3:DeleteObject` / `s3:CreateBucket` / etc., the grant runs, the agent deletes a production bucket, the incident review sees `selected_item_ids: ["deny-s3-writes"]` in the audit chain.

  This is the WB19-MED-01 shape exactly — a sentinel field set with the user's intent to PROTECT against something the system does not actually protect against. In the WB19 case the silent gap was bucket-vs-object ARN type mismatch; here it's a structural empty-tuple placeholder. The author left a comment ("placeholder — s3 write blocking is handled differently") signaling this is unfinished, but shipped it anyway with default-checked=false (so not pre-checked) — which means many UI users will see this item, opt in to it expecting protection, and get none.

- Three possible fixes (in order of correctness):
  1. **Best**: implement an action-glob reduction axis (e.g., `deny_action_patterns: ("s3:Put*", "s3:Delete*", "s3:CreateBucket*")`) and route it through a new `reductions.deny_action_patterns(...)` function. The reduction recipe entry should record the patterns. This is the "right" fix and matches the description.
  2. **Acceptable as v1**: remove the item from `DEFAULT_CHECKLIST` until the action-glob axis ships. Better to omit a feature than to ship one that lies.
  3. **Worst-but-still-better-than-status-quo**: keep the item but also have `apply_selections` drop known-no-op items from `selected_item_ids` so the audit chain does not lie. This is honest but still hides the feature gap from the UI user.

- Why HIGH not CRIT: there is no path-to-exploit difference compared to "user didn't select anything." The risk is that the audit chain becomes unreliable AND the user has a false sense of security. HIGH because both the broken behavior and the misleading audit-record are exposed simultaneously and the UI marketing of this feature (per the commit message: "agentless UI users can pick what they DON'T need from the checklist") makes it the kind of thing they'll rely on.

## MED findings

### MED-21-01 — `deny-secrets` denies only `secretsmanager:*`; description claims SSM + KMS Decrypt too

- File: `src/iam_jit/guided_reduction.py:69-80`
- Issue: the checklist item:
  ```python
  ReductionChecklistItem(
      id="deny-secrets",
      label="I don't need to READ secrets",
      description=(
          "Block reading from Secrets Manager + SSM Parameter Store "
          "(SecureString) + KMS Decrypt. Almost every admin task can "
          "be done without touching secret VALUES."
      ),
      reduction_axis="deny_services",
      reduction_values=("secretsmanager",),  # ssm + kms decrypt are pattern-specific
      default_checked=True,
  ),
  ```
  An admin who reads "I don't need to READ secrets" reasonably believes that ticking the box (it is pre-checked) blocks the three named services. The implementation produces:
  ```
  Deny secretsmanager:* on *
  ```
  This means:
  - ✓ `secretsmanager:GetSecretValue` blocked.
  - ✗ `ssm:GetParameter`, `ssm:GetParameters`, `ssm:GetParametersByPath`, `ssm:GetParameterHistory` — NOT blocked. SSM SecureString parameters are a common substitute for Secrets Manager; reading them returns the decrypted value (the AWS console even routes you to use SSM SecureString instead of Secrets Manager for cost reasons). An admin who believes they've blocked "Secrets Manager + SSM Parameter Store" can still read every SecureString param.
  - ✗ `kms:Decrypt` — NOT blocked. The principal can decrypt arbitrary KMS-encrypted blobs (S3 SSE-KMS objects, RDS snapshots, secrets stored in dynamodb / s3 / files) using `kms:Decrypt` directly.

- Comparison with the sibling baseline policy already shipped (`AdminLikeWithSensitiveExclusions.DenySecretData`, `src/iam_jit/aws_managed_catalog.py:464-479`):
  ```python
  "Action": [
      "secretsmanager:GetSecretValue",
      "secretsmanager:BatchGetSecretValue",
      "ssm:GetParameter*",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:ReEncrypt*",
  ],
  ```
  The baseline policy `AdminLikeWithSensitiveExclusions` — which this checklist item's description explicitly mirrors ("matches AdminLikeWithSensitiveExclusions deny categories" per commit message) — gets all three categories right. The checklist item is the LESS-strict shadow of the baseline, with the same label.

- The author's inline comment `# ssm + kms decrypt are pattern-specific` confirms this is a known gap, not an oversight. The "pattern-specific" routing is the missing action-glob axis (same gap as HIGH-21-01) — `ssm:GetParameter*` is an action wildcard, not a service prefix; `kms:Decrypt` is a single action. The current `deny_services` axis only emits `service:*`, so it cannot express either.

- Fix options:
  1. **Best**: add the action-glob reduction axis (per HIGH-21-01 fix #1) and use `deny_action_patterns=("secretsmanager:Get*", "secretsmanager:BatchGet*", "ssm:GetParameter*", "kms:Decrypt", "kms:GenerateDataKey", "kms:ReEncrypt*")` to match the AdminLikeWithSensitiveExclusions baseline exactly.
  2. **Acceptable**: narrow the description to what's actually delivered. New label: "I don't need Secrets Manager"; new description: "Block secretsmanager:*. Does NOT block SSM SecureString reads or KMS Decrypt — for those, pair with the AdminLikeWithSensitiveExclusions baseline or wait for action-glob support."
  3. **Worst**: leave it; document the gap separately. Risks the same trust loss as HIGH-21-01.

- Severity: MED not HIGH because at least one of the three claims (secretsmanager) is delivered, and `default_checked=True` makes the user MORE likely to have it selected (so non-zero net protection). HIGH if you weight the user's false sense of security higher than partial protection.

### MED-21-02 — `deny-iam-admin`'s "stops principal-pivot escape" claim is overstated

- File: `src/iam_jit/guided_reduction.py:81-92`
- Issue: the description:
  > "Block iam:* operations. Stops the principal-pivot escape (create new role + assume it). Pair with this for hardest containment of an admin-class grant."

  The specific named path — "create new role + assume it" — IS blocked: `iam:CreateRole` is denied; the principal cannot create a new role. `iam:PassRole` is also denied, so the principal cannot attach existing roles to compute (Lambda/EC2). Both correct.

  Not blocked (lateral / pivot vectors NOT covered by `iam:*`):
  - `sts:AssumeRole` into any **pre-existing** role that already trusts this principal (or trusts `*` with weak conditions). The Allow `*` still grants `sts:AssumeRole`. If the account has any admin-shaped role with a trust policy that names this principal — common in multi-account setups — the principal escapes through it.
  - `s3:PutBucketPolicy` — rewrite trust on a bucket the principal owns to allow another principal to read/write. The Allow `*` includes `s3:*`; `iam:*` deny does not touch `s3`. Standard cross-account data-exfil pivot.
  - `kms:CreateGrant` — issue a grant to another principal letting them use a KMS key. Not iam-namespace.
  - `lambda:AddPermission` — grant invoke rights to a function (or other AWS account) without touching the principal's IAM identity. Then the new caller can run code with the function's execution role. Classic Lambda confused-deputy.
  - `events:PutTargets` / `scheduler:CreateSchedule` — schedule code that runs as a service role, with the principal as creator.
  - `cloudformation:CreateStack` with a stack that creates roles. `cloudformation:CreateStack` itself doesn't need `iam:*` if `iam:PassRole` to CFN is also denied, but custom resources / nested stacks invoke Lambdas that have their own execution roles.

  None of these are NEW vulnerabilities; they are the documented "any Allow * + Deny iam:* policy still has lateral movement" property of IAM. WB19-LOW-05 caught the same shape in `AdminLikeWithSensitiveExclusions` and that entry's summary now explicitly notes "this policy DOES NOT block IAM principal-pivot. For full containment, pair with a Permissions Boundary." (`src/iam_jit/aws_managed_catalog.py:455` area.)

  The checklist item makes the opposite claim — that ticking it gives "hardest containment" — which contradicts the very baseline it claims to mirror.

- Fix: rewrite the description to be honest about scope. Suggested:
  ```
  description=(
      "Block iam:* operations. Blocks the iam:CreateRole + "
      "iam:PassRole pivot. Does NOT block sts:AssumeRole into "
      "pre-existing roles, s3:PutBucketPolicy, kms:CreateGrant, "
      "or lambda:AddPermission — for full lateral-movement "
      "containment, also use a Permissions Boundary."
  ),
  ```

- Severity: MED not LOW because the description's prescriptive claim ("hardest containment") will lead users to skip pairing with a Permissions Boundary, leaving real lateral-movement paths open. Same trust-gap shape as HIGH-21-01 / MED-21-01, smaller blast radius.

### MED-21-03 — Test suite verifies mechanics, not description claims; same gap that let WB19-MED-01 ship

- File: `tests/test_guided_reduction.py`
- Issue: the 20 tests cover:
  - checklist size (8-12)
  - ID uniqueness
  - serialization round-trip
  - pre-checked-by-default presence of `deny-secrets` + `deny-iam-admin`
  - empty selection → no-op
  - single item → one Deny statement
  - multi-item aggregation → one combined Deny
  - unknown ID silently dropped
  - account narrowing composition
  - region narrowing composition
  - non-list defensiveness
  - MCP get + apply round-trip
  - MCP input validation (3 tests)
  - full dispatch round-trip (3 tests)

  None of them verify the **description-to-implementation mapping**:
  - No test asserts that selecting `deny-secrets` produces a policy that actually blocks `ssm:GetParameter` or `kms:Decrypt`.
  - No test asserts that selecting `deny-s3-writes` produces a policy that actually blocks `s3:PutObject`.
  - No test asserts that selecting `deny-iam-admin` produces a policy that blocks `iam:CreateRole`.

  Each of the checklist items has a `label` and `description` with concrete promises ("block reading from Secrets Manager + SSM Parameter Store + KMS Decrypt"; "block s3:Put*, s3:Delete*, s3:CreateBucket*"). A trust-gap test would parameterize over `DEFAULT_CHECKLIST` and assert that for each item, the resulting policy's Deny statement actually denies a sample action from the item's claimed coverage.

  This is the same test-coverage gap pattern that let WB19-MED-01 (s3:ListBucket falls through Deny) ship — the WB19 sentinel test asserted the four substring patterns were present in the Resource list but did NOT check resource-type / action compatibility.

- Fix: add a parameterized test that, for each `DEFAULT_CHECKLIST` item, applies it to an Allow-* policy and asserts the resulting Deny actually denies a representative action from the item's description. Items that cannot be verified (because they're broken — HIGH-21-01, MED-21-01) will fail the test, surfacing the trust gap before merge.

- Severity: MED — it's a process gap that gates whether HIGH-21-01 / MED-21-01 / MED-21-02 get caught at PR time vs in audit. Worth treating as a separate finding because the fix is in the test file, not the implementation.

## LOW findings

### LOW-21-01 — `apply_selections` silently drops items with non-`deny_services` reduction axis

- File: `src/iam_jit/guided_reduction.py:184-189`
- Issue: the aggregation loop only consults items where `item.reduction_axis == "deny_services"`:
  ```python
  for item_id in selected_set:
      item = by_id.get(item_id)
      if item is None:
          continue
      if item.reduction_axis == "deny_services":
          deny_services_acc.extend(item.reduction_values)
  ```
  The `ReductionChecklistItem.reduction_axis` docstring (line 44) declares `"deny_services" | "deny_specific_services" | etc.` as valid values. If a future OSS item or Enterprise-plugin item adds a row with axis `"deny_specific_services"` (or anything else), `apply_selections` will silently no-op for that item — same shape as HIGH-21-01 (selected_item_ids reports it as applied; policy is unchanged).

  The forward-compat docstring on `apply_selections` claims "Unknown item IDs are silently ignored" — but this property is described for IDs, not axes. Unknown axes are not unknown items; they're known items with axes the executor doesn't understand. The current code treats them identically to unknowns, which conflicts with the "known + handled" intent of having an `id` on the item.

- Fix: when an item is known but its axis is not handled, either (a) raise (loud failure), (b) record it in a `dropped_axes` field in the return value so the caller / audit chain sees what was ignored. Option (b) preserves forward-compat while making the gap auditable.

### LOW-21-02 — `selected_item_ids` conflates "selected and applied" with "selected, known, but no-op"

- File: `src/iam_jit/guided_reduction.py:202-204`
- Issue: the function returns
  ```python
  out["selected_item_ids"] = sorted(selected_set & set(by_id.keys()))
  ```
  This is the intersection of "what the user picked" and "what we know about." It is NOT "what we applied." Direct consequence of HIGH-21-01: `selected_item_ids=["deny-s3-writes"]` is reported even though the policy is unchanged. Also the consequence of LOW-21-01: a known item with an unknown axis would be in this set.

- Fix: split into two fields — `selected_item_ids_known` (current behavior, for audit-of-intent) and `applied_item_ids` (only items whose reduction actually produced a recipe entry, for audit-of-effect). Without the split the audit chain cannot distinguish "user opted in but feature broken" from "user opted in and got protection."

### LOW-21-03 — `apply_selections(policy=None, ...)` crashes inside `reductions.deny_services`

- File: `src/iam_jit/guided_reduction.py:162-205`
- Issue: no `isinstance(policy, dict)` validation. With `policy=None`:
  ```
  AttributeError: 'NoneType' object has no attribute 'setdefault'
  ```
  (raised from `reductions.deny_services` `stmts = new_policy.setdefault(...)`).

  The MCP wrapper `_apply_reduction_checklist_for_mcp` validates `isinstance(policy, dict)` before calling `apply_selections`, so this is unreachable through the MCP tool. But the Enterprise-plugin reuse pattern (the whole reason this is OSS scaffolding) means the function will be called directly from non-MCP code. A crash instead of a structured error makes the failure mode less debuggable.

- Fix: add the same `isinstance(policy, dict)` guard at the top of `apply_selections`; return `{"policy": None, "recipe": [], "error": "policy must be a JSON object"}` to mirror the MCP wrapper's contract.

### LOW-21-04 — `_apply_reduction_checklist_for_mcp` validates the list shape but not item types

- File: `src/iam_jit/mcp_server.py:849-879`
- Issue:
  ```python
  if not isinstance(selected, list):
      return {"error": "selected_item_ids must be a list of strings", ...}
  ```
  rejects `selected_item_ids: "string"` but accepts `selected_item_ids: [1, 2, 3]` or `selected_item_ids: [{"x": 1}]`. Inside `apply_selections`, the comprehension `{str(i) for i in selected_item_ids if isinstance(i, str)}` silently drops non-strings. The caller gets `selected_item_ids: []` back with no error, even though they passed three "items."

  The same pattern exists in `_reduce_policy_for_mcp` (line 896-903) for `deny_services` etc., so the new code matches existing depth — but tightening would surface malformed-payload bugs faster.

- Fix: after the `isinstance(selected, list)` check, also check `all(isinstance(i, str) for i in selected)` and return an error if not.

## Forward-compat & AWS-IAM-semantics specifically asked about

**Q: "If Enterprise adds `deny-eventbridge`, does the OSS code break?"**

No. The OSS `apply_selections` does `by_id = {item.id: item for item in DEFAULT_CHECKLIST}` — the Enterprise plugin's extra IDs are not in `by_id`, so they hit the `item is None` branch and are silently dropped. The OSS does not import or know about the Enterprise plugin's checklist; the Enterprise plugin would supply both its own item definitions AND its own apply logic (or extend the OSS `DEFAULT_CHECKLIST` directly via composition / its own iteration). Forward-compat claim holds **for unknown IDs**.

It does NOT hold for **unknown axes** (LOW-21-01): if the Enterprise plugin adds an OSS-known ID with a non-`deny_services` axis, OSS code silently drops the axis. This is unlikely in practice (IDs are namespaced; Enterprise wouldn't reuse OSS IDs) but the dataclass docstring explicitly lists `"deny_specific_services"` as a valid axis, hinting at future evolution.

**Q: "Even with `iam:*` denied, can `sts:AssumeRole` bypass?"**

Yes, for pre-existing roles. The Allow `*` still grants `sts:AssumeRole`. The check at request time is whether the TARGET role's trust policy permits this principal. If any role in the account already trusts this principal (or trusts `*` with weak conditions), `sts:AssumeRole` into it succeeds. `iam:*` deny only prevents the principal from CREATING/MUTATING IAM resources; it does not prevent the principal from EXERCISING permissions that other resources have granted to it. See MED-21-02.

**Q: "Does `deny-secrets`'s implementation actually block what the description claims?"**

No. See MED-21-01. The description names three categories (Secrets Manager + SSM Parameter Store + KMS Decrypt); the implementation only blocks the first.

## Aggregation correctness — verified

The aggregation logic in `apply_selections` is correct given the inputs:
- Multi-item selection with the `deny_services` axis aggregates into ONE Deny statement (verified: `["deny-rds", "deny-dynamodb", "deny-cloudformation"]` produces one Deny with `["cloudformation:*", "dynamodb:*", "rds:*"]` — deterministic via `sorted(set(...))`).
- Dedup works: selecting two items that both contribute the same service prefix produces one entry in the Deny (verified by inspection — `sorted(set(deny_services_acc))`).
- Account / region narrowing composes correctly: verified end-to-end via `test_apply_selections_with_account_narrowing`.
- Empty selection + no narrowing returns `recipe=[]` and `summary="no reductions applied"` (verified).
- Unknown IDs do not crash (verified).
- Non-list `selected_item_ids` treated as `[]` (verified).
- Sid hashing in `deny_services` prevents Sid collision when multiple `apply_selections` calls stack — verified by reading `reductions.py:124-126` (sha256 hash of sorted service set).

## MCP dispatch wiring — verified

- `get_reduction_checklist` and `apply_reduction_checklist` are surfaced in `tools/list` (test: `test_two_new_tools_in_tools_list`).
- Both dispatch to the correct handler (tests: `test_dispatch_get_reduction_checklist`, `test_dispatch_apply_reduction_checklist`).
- Response shape matches MCP convention (content[] + structuredContent) via `_handle_request` at `src/iam_jit/mcp_server.py:1180-1190`.
- Input validation matches the WB14-MED depth used by `_reduce_policy_for_mcp` (one-level type check, no item-type validation — see LOW-21-04).
- `get_reduction_checklist` accepts no required args; schema `properties: {}` correct.

## Summary

**0 CRIT, 1 HIGH, 3 MED, 4 LOW.** The OSS scaffolding ships clean plumbing (dispatch, aggregation, validation) but two checklist items have description-vs-implementation gaps that lie in the audit chain (`deny-s3-writes`: total no-op; `deny-secrets`: 1-of-3 promised categories). A third (`deny-iam-admin`) overstates its containment claim. The test suite enforces mechanics but no test asserts that any checklist item's description matches its behavior — the same gap that let WB19-MED-01 ship.

Recommended pre-launch sequence:
1. **HIGH-21-01**: either ship the action-glob reduction axis (best) or remove `deny-s3-writes` from `DEFAULT_CHECKLIST` (acceptable).
2. **MED-21-01**: ship the action-glob axis (best, ties to fix #1) or narrow the `deny-secrets` description to "Secrets Manager only" (acceptable).
3. **MED-21-02**: rewrite `deny-iam-admin` description to match reality (lateral-movement vectors NOT blocked).
4. **MED-21-03**: add the parameterized description-claim test; it should fail on HIGH-21-01 / MED-21-01 / MED-21-02 today, then pass once they're fixed.
5. **LOW-21-01..04**: clean up at convenience; none block launch.

---

## WB21 closures (2026-05-16)

All 8 findings addressed in one commit. Pre-launch trust gap closed.

### Updated closure table

| Finding | Status | How closed |
|---|---|---|
| HIGH-21-01 `deny-s3-writes` no-op | **CLOSED** | Added `deny_actions` reduction axis in `reductions.py`. `deny-s3-writes` now declares `reduction_axis="deny_actions"` with `("s3:Put*", "s3:Delete*", "s3:Create*", "s3:Restore*", "s3:Replicate*")`. Item now produces a real Deny statement that blocks the writes its label promises while keeping reads — verified by the new `CHECKLIST_BLOCK_CLAIMS` parameterized test in `test_guided_reduction.py`. |
| MED-21-01 `deny-secrets` partial | **CLOSED** | Same `deny_actions` axis. `deny-secrets` now denies `("secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue", "ssm:GetParameter*")` — mirrors `AdminLikeWithSensitiveExclusions.DenySecretData`. Description updated to explicitly call out that `kms:Decrypt` is NOT blocked (too broad — would break every KMS-encrypted blob in S3/RDS/EBS) and direct users to a dedicated policy for that. Parameterized test asserts both directions. |
| MED-21-02 `deny-iam-admin` overclaim | **CLOSED** | Description rewritten to honestly say "closes the CreateRole + PutRolePolicy + AssumeRole principal-pivot path" and explicitly call out the four vectors it does NOT block (`sts:AssumeRole` into pre-existing trusts, `kms:CreateGrant`, `s3:PutBucketPolicy`, `lambda:AddPermission`) plus the Permissions Boundary as the harder-containment recommendation. Aligned with WB19-LOW-05's parent-baseline guidance. |
| MED-21-03 description-vs-implementation test gap | **CLOSED** | Added `CHECKLIST_BLOCK_CLAIMS` table + `test_each_checklist_item_description_matches_implementation` parameterized over `DEFAULT_CHECKLIST`. For every item, the test asserts (a) actions the description promises to BLOCK are denied in the output policy and (b) actions the description promises NOT to block are NOT denied. Adding any new checklist item without claims-table coverage fails the test, enforcing the discipline going forward. |
| LOW-21-01 unknown reduction axes silently dropped | **CLOSED** | `apply_selections` now skips items with unknown axes but still reports them in `selected_item_ids`. Combined with LOW-21-02 closure (`applied_item_ids`), unknown-axis items are visibly "selected but not applied" in the audit chain. Documented in the `apply_selections` docstring. |
| LOW-21-02 selected vs applied conflated | **CLOSED** | Added `applied_item_ids` to the `apply_selections` return shape. `selected_item_ids` = user picked AND we recognize; `applied_item_ids` = subset whose axis actually fired a recipe entry. MCP `apply_reduction_checklist` description updated. New test `test_applied_item_ids_distinguishes_selected_from_fired` covers it. |
| LOW-21-03 `apply_selections(None)` AttributeError | **CLOSED** | Added defensive `isinstance(policy, dict)` guard at the top of `apply_selections`. Returns the same structured `{policy: None, recipe: [], error: "policy must be a dict", ...}` shape that the MCP wrapper produces. New test `test_apply_selections_handles_none_policy` covers it. |
| LOW-21-04 MCP per-element type validation | **DEFERRED** | Matches `_reduce_policy_for_mcp`'s existing depth (one-level list-or-not check); tightening it here without tightening the sibling validator would be inconsistent. Filed as a future cleanup that should touch BOTH wrappers together. Downstream filtering already drops non-string items safely, so risk is presentation-only. |

### Verification

- `tests/test_guided_reduction.py`: 19 → 26 tests (+7); all pass.
- `tests/test_reductions.py`: 30 → 40 tests (+10 covering `deny_actions`); all pass.
- Broader suite: **2021 passed**, 29 skipped, 14 deselected (was 1997 before WB21 closures; +24 net tests).
- Pre-existing 96 `tests/test_calibration_corpus.py` failures unchanged (not caused by WB21 work).

### What the WB21 fix DID NOT do

- Did not add a `narrow_resources` axis (still deferred per `reductions.py` docstring).
- Did not split LOW-21-04 into both wrappers; flagged for a paired-touch follow-up.
- Did not introduce a new `kms:Decrypt` deny item (intentional — too broad; user can compose via `reduce_policy` directly with `deny_actions=["kms:Decrypt"]`).

### Why this matters

The WB19→WB20→WB21 pattern keeps repeating: a feature ships with unit tests that verify mechanics, an audit catches descriptions that lie, fixes go in, the trust-gap test pattern travels forward. After this round, the `CHECKLIST_BLOCK_CLAIMS` test enforces the rule mechanically — any future checklist addition without claims coverage will fail. The audit chain now distinguishes "selected" from "actually changed the policy," which closes the dishonest-audit-chain category at the data-model level.

Per [[audit-cadence-discipline]]: 1 HIGH + 3 MED + 4 LOW in code that had 19 passing unit tests. Worth it.
