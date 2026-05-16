# Round 20 audit — reduction primitives + reduce_policy MCP tool (#155)

## Closure status (2026-05-16, post-audit fix pass)

| Finding | Status |
|---|---|
| CRIT-20-01 (aws:RequestedAccount is not a real AWS key — silent fail-closed) | ✅ FIXED — changed to `aws:ResourceAccount` (the real AWS global key for "narrow to account hosting the resource"). reductions.py docstring updated to explain the three real options (ResourceAccount / PrincipalAccount / SourceAccount). MCP tool description updated. Existing test renamed `test_narrow_to_accounts_uses_real_aws_condition_key` with explicit anti-regression assertion. |
| MED-20-01 (malformed Condition silent skip + dishonest recipe) | ✅ FIXED — `_add_condition_to_allow_statements` now tracks `statements_modified`; returns recipe entry as None when zero Allow statements were actually modified. 2 new tests cover malformed-condition skip + multi-statement-mixed cases. |
| MED-20-02 (StringLike conflict on same key creates unsatisfiable AND) | ✅ FIXED — new `_other_operators_reference_key()` helper checks if any operator other than StringEquals already references the target key; if so, skip the statement (don't create the dead AND). 1 new test asserts the skip behavior + None recipe. |
| LOW-20-LOW1 (deny_services accepts service prefixes with `:`) | ✅ FIXED — validation rejects tokens containing `:` (would produce malformed `rds:*:*`), `*`, or whitespace inside. 1 new test. |
| LOW-20-LOW2 (Sid `ReductionDenyServices` hardcoded — duplicate Sid risk) | ✅ FIXED — Sid is now `ReductionDenyServices{sha256(sorted(services))[:8]}` — deterministic but unique per service set. Same set produces same Sid (idempotent); different sets produce different Sids (no PUT-IAM-policy collision). 2 new tests. |
| LOW-20-LOW3 (region values not lowercased) | ✅ FIXED — `narrow_to_regions` lowercases input. 1 new test. |
| LOW-20-LOW4 (Effect exact-match only) | ✅ FIXED — Effect comparison is case-insensitive per AWS spec (`Allow` / `allow` / `ALLOW` all equivalent). 1 new test. |

Post-closure test count: **30 reduction tests pass** (was 21; +9 closure tests). Broader suite: **1977 passed**.

Commit under review: `303281e` (`feat(reductions): deterministic policy reduction primitives + reduce_policy MCP tool (#155)`).

Scope:
- `src/iam_jit/reductions.py` (256 LOC) — pure functions `deny_services`, `narrow_to_accounts`, `narrow_to_regions`, plus the `apply_reductions` composer and the `ReductionEntry` / `ReductionResult` dataclasses.
- `src/iam_jit/mcp_server.py` — `reduce_policy` tool added to the `TOOLS` registry (lines 338-398), dispatched at line 1066-1067, handler `_reduce_policy_for_mcp` at lines 776-806.
- `tests/test_reductions.py` (284 LOC, 21 tests) — pure-function tests + 4 MCP-wiring tests.

Audit focused on:
1. AWS-IAM-semantics correctness of each reduction axis (does the produced policy actually do at AWS evaluation time what the docstring + recipe claim?).
2. Input validation on the MCP entry point.
3. Mutation safety on every axis (not just `deny_services`).
4. Edge cases — no Statement key, single-dict Statement form, malformed Condition, 12-digit-with-leading-zero account IDs, region case, empty policy.
5. Composition order (apply_reductions: does the appended Deny inappropriately receive account/region narrowing?).
6. Recipe accuracy (do empty inputs correctly produce no recipe entry; do non-empty inputs always produce one?).
7. Regression check on the broader suite.

Read-only audit. No code changes proposed; this report enumerates findings + suggested remediations.

## Headline

**7 findings: 1 CRIT, 0 HIGH, 2 MED, 4 LOW.**

The CRIT is a wrong-condition-key bug in `narrow_to_accounts`: the function emits a `StringEquals` condition on `aws:RequestedAccount`, which is **not a real AWS global condition key**. The genuine keys are `aws:ResourceAccount` (account of the resource being accessed), `aws:PrincipalAccount` (account of the caller), and `aws:SourceAccount` (cross-service call source). AWS IAM evaluates unknown condition keys as "value not in request context → StringEquals false" — so every Allow narrowed by this function fails the condition on every real request, meaning the Allow grants NOTHING at AWS evaluation time. This is fail-CLOSED (the policy grants less than the user thinks, not more), so it is not a privilege-escalation hole — but it makes `narrow_to_accounts` non-functional and breaks the [[scorer-is-ground-truth]] audit-chain promise that "the recipe describes what the policy does at AWS evaluation."

Cross-checks that confirm the diagnosis:
- The project's own calibration corpus (`tests/calibration_corpus/`) contains zero uses of `aws:RequestedAccount`; AWS-managed policies use `aws:ResourceAccount` and `aws:PrincipalAccount`.
- The project's own scorer (`src/iam_jit/review.py:1733, 2889`) enumerates account-narrowing keys as `principalaccount`, `principalarn`, `principalorgid`, `sourceaccount`, `sourcearn` — `requestedaccount` is not in the list, meaning the scorer itself would not credit this condition as risk-reducing (consistent with it being a non-key).
- The MCP tool's `inputSchema.properties.narrow_to_accounts.description` (`src/iam_jit/mcp_server.py:379-382`) also names `aws:RequestedAccount`, so an LLM agent reading the tool schema will propagate the wrong key into its own reasoning ("the docs told me aws:RequestedAccount is the right key").

`aws:RequestedRegion` (used by `narrow_to_regions`), by contrast, IS a real AWS global condition key — verified by direct usage in AWS-managed policies in the calibration corpus (`AWSForWordPressPluginPolicy.yaml`, `AWSTransformSecretsManagerConnectorPolicy.yaml`, several ROSA policies) and by the project's research-pattern `research-11-14-requestedregion-stringequals-wildcard.yaml`. So the region axis is functionally correct (modulo the documented global-services caveat).

The 2 MEDs are silent fail-opens at the recipe-honesty layer:
- **MED-20-01** — when an Allow statement has a malformed `Condition` (e.g. `Condition: "broken-string"`), the narrowing helpers silently skip it but the recipe still records the axis as applied. The audit-chain artifact ("scoped to account X") becomes a lie about what the produced policy will do.
- **MED-20-02** — `narrow_to_regions` on a baseline that already uses a different condition operator on the same key (e.g. `StringLike: aws:RequestedRegion: us-east-*`) merges the new `StringEquals` operator into the same Condition block. AWS AND's multiple operators in one Condition, so the resulting Allow requires BOTH the StringLike match AND the StringEquals match — typically unsatisfiable. The Allow becomes dead. This is plausible because the calibration corpus contains AWS-managed policies using exactly this `StringLike: aws:RequestedRegion` shape.

The 4 LOWs are robustness / hygiene gaps that don't break security but should be tightened: service prefixes containing `:` produce malformed AWS Actions (`rds:*` → `rds:*:*`), Sid collisions if `deny_services` is called twice or if the baseline already uses the Sid `ReductionDenyServices`, region casing not normalized (StringEquals is case-sensitive, so `us-EAST-1` silently nullifies vs real region `us-east-1`), and Effect comparison is exact-`Allow`-only (lowercase `allow` silently skipped while recipe entry still recorded).

Regression: **1968 passed, 29 skipped, 14 deselected** in 88.9s — matches the audit-prompt expectation exactly. No regressions.

Mutation safety: verified across `deny_services`, `narrow_to_accounts`, `narrow_to_regions`, and the 3-axis `apply_reductions` composition. All four paths leave the input policy structurally and value-equal-to-deepcopy. The `copy.deepcopy(policy)` at each function's entry is doing the work; the test suite's `test_deny_services_does_not_mutate_input` is the canary, and the other axes inherit the same `copy.deepcopy(policy)` pattern.

Composition order: verified that the appended Deny in `apply_reductions` does NOT inappropriately receive account/region narrowing (`_add_condition_to_allow_statements` correctly gates on `Effect == "Allow"`, line 193). So the order deny → narrow_accounts → narrow_regions produces the intuitive result: the Allow is narrowed to acct+region; the Deny applies globally. Correct.

Empty-input recipe: verified — `apply_reductions(p)` with no arguments returns `recipe=()` and `policy == p` (test `test_apply_reductions_no_op_returns_empty_recipe`). Each individual function with `[]` returns `None` for the entry (tests `test_*_empty_no_op`). Correct.

Input validation on MCP tool: `_reduce_policy_for_mcp` correctly rejects non-dict `policy` and non-list axis filters with structured error responses (lines 783-798). N/A on numeric-arg bool-rejection because the tool has no numeric args.

## Closure status

| Finding | Status |
|---|---|
| CRIT-20-01 `narrow_to_accounts` uses non-existent AWS condition key `aws:RequestedAccount`; should be `aws:ResourceAccount` (or `aws:PrincipalAccount`) — narrowed Allows fail-CLOSED at AWS evaluation; recipe + summary lie about scoping | OPEN |
| MED-20-01 Malformed `Condition` (non-dict) on an Allow causes narrowing helpers to silently skip the statement; recipe still records axis as applied | OPEN |
| MED-20-02 `narrow_to_regions` on a baseline that already uses `StringLike: aws:RequestedRegion` merges into same Condition block; AWS AND's operators → unsatisfiable → Allow becomes dead | OPEN |
| LOW-20-01 `deny_services` accepts service prefixes containing `:` (e.g. `rds:*`), producing malformed AWS Actions (`rds:*:*`); no character-class validation on input | OPEN |
| LOW-20-02 `deny_services` always appends Sid `ReductionDenyServices` without uniquifying — second call (or baseline collision) produces duplicate-Sid policy, rejected by AWS at PUT time | OPEN |
| LOW-20-03 Region values not normalized (case + whitespace); `us-EAST-1` is kept as-is, AWS StringEquals is case-sensitive → silently nullifies. Validator only checks non-empty string | OPEN |
| LOW-20-04 Effect comparison is exact-`"Allow"` only; statements with `"allow"` or `" Allow"` are silently skipped in narrowing while the recipe entry is still recorded | OPEN |

## CRIT findings

### CRIT-20-01 — `narrow_to_accounts` emits `StringEquals` on `aws:RequestedAccount`, which is not a real AWS IAM global condition key

- File: `src/iam_jit/reductions.py:133` (and `mcp_server.py:379-382` for the user-facing schema description)
- Code:
  ```python
  return _add_condition_to_allow_statements(
      policy,
      condition_key="aws:RequestedAccount",
      condition_values=valid,
      recipe_axis="narrow_to_accounts",
  )
  ```
- Issue: `aws:RequestedAccount` is not in the [AWS IAM Global Condition Keys reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html). The documented account-related global keys are:

  | Key | Meaning |
  |---|---|
  | `aws:ResourceAccount` | The AWS account ID of the resource being accessed. Most common "scope this Allow to a specific account's resources" key. |
  | `aws:PrincipalAccount` | The AWS account ID the calling principal belongs to. Used for cross-account "scope to MY account's principals" patterns. |
  | `aws:SourceAccount` | The AWS account ID of the resource making a cross-service call (e.g. S3 → Lambda). Specific to confused-deputy mitigation. |

  `aws:RequestedAccount` does not appear in this list, in AWS's actions-resources-condition-keys-by-service tables, in the project's calibration corpus (`grep -rn aws:RequestedAccount tests/calibration_corpus/` returns zero hits), or in the project's own scorer's enumeration of known account-narrowing keys (`src/iam_jit/review.py:1733, 2889` lists `principalaccount`, `sourceaccount`, `principalorgid`, `sourcearn` — no `requestedaccount`).

- AWS evaluation behavior for unknown condition keys (per [AWS docs: IfExists condition operator](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_IfExists)):
  > If a key isn't present in the request context, the values do not match.

  For `StringEquals` without `IfExists`, "values do not match" → condition evaluates `false` → if the condition is in an Allow statement, the Allow does not fire.

- Effect at AWS evaluation time:
  - User authors a baseline (broad `Allow * on *`).
  - User calls `reduce_policy(policy=baseline, narrow_to_accounts=["111111111111"])`.
  - Returned policy: `{"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"StringEquals": {"aws:RequestedAccount": ["111111111111"]}}}`.
  - Returned recipe: `[{"axis": "narrow_to_accounts", "values": ["111111111111"]}]`.
  - Returned summary: `"scoped to account(s) 111111111111"`.
  - User scores the policy → scorer doesn't credit unknown keys → score stays at 10 (no surprise from the score itself).
  - User submits the policy, admin approves based on the recipe ("scoped to one account, looks fine"), grant is issued.
  - At AWS evaluation time: the condition's key `aws:RequestedAccount` is not present in the request context (AWS doesn't populate keys it doesn't know about) → `StringEquals` returns false → Allow doesn't fire → **the principal can do nothing through this statement**.

- Direction of fail: **fail-CLOSED**. The principal gets less access than the user thinks (none, instead of "everything within account 111"). This is the safe direction in terms of immediate blast radius, BUT:

  1. **The recipe + summary lie** about what the policy does. The audit-chain artifact says "scoped to account 111" but the AWS-evaluated policy grants nothing. This breaks the load-bearing [[scorer-is-ground-truth]] promise that the recipe describes ground-truth IAM behavior.
  2. **Customer-facing breakage**: the user submits a grant, admin approves it, principal tries to do real work, AWS denies every operation. Customer support burden + trust erosion + "iam-jit is broken" narrative.
  3. **Adjacent silent-fail-open risk** when this primitive is composed: if a future workflow ever uses `narrow_to_accounts` to "scope down" a broader pre-narrowed policy (e.g. `Allow ec2:*` + `Allow s3:*` separately, then narrow ALL to account X), the user assumes the resulting policy is "ec2 + s3 in account X only" — in reality it's "nothing." If a downstream consumer then BACKS OFF the narrowing on the assumption that account scoping was effective, the resulting policy could be broader than the user understood. Speculative but worth noting.

- Repro:
  ```python
  from iam_jit.reductions import narrow_to_accounts
  import json
  p = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
  result, entry = narrow_to_accounts(p, ["111111111111"])
  print(json.dumps(result, indent=2))
  # Condition uses aws:RequestedAccount — not a real key.
  # AWS will evaluate this as: StringEquals on key not in request context → false → Allow does nothing.
  ```

- Recommended fix: change `condition_key="aws:RequestedAccount"` to `condition_key="aws:ResourceAccount"` in `src/iam_jit/reductions.py:133`. ALSO:
  - Update the docstring on `narrow_to_accounts` (lines 118-125) to reference `aws:ResourceAccount` and clarify the semantics ("scopes Allow to operations targeting resources owned by these accounts").
  - Update the MCP tool description in `mcp_server.py:379-382` to reference `aws:ResourceAccount`.
  - Update the test `test_narrow_to_accounts_adds_condition_to_allow` (line 97) to assert the corrected key.
  - Consider whether the intent is actually `aws:PrincipalAccount` (scope based on caller's account, not resource owner's account). For the agent-driven reduction loop, `aws:ResourceAccount` is almost certainly what users want ("only let this grant touch resources in account X"), but documentation should be explicit because the two keys differ when cross-account access is involved.
  - Add a calibration-corpus entry exercising the reduction with the corrected key, so future regressions are caught.
  - Bonus hardening: validate the chosen `condition_key` against a known-keys allow-list in `_add_condition_to_allow_statements`; an unknown key should raise rather than silently producing a non-functional policy.

- Severity: **CRIT** because (a) the primary feature (account narrowing) does not work at AWS evaluation time, (b) the recipe + summary actively misrepresent what was applied (the [[scorer-is-ground-truth]] / [[creates-never-mutates]] invariant family includes "the audit chain truthfully describes the policy"), (c) the fix is mechanical (one-line code change + docs + test), (d) the bug would be caught immediately by any end-to-end test against real AWS but the existing test suite is structural-only (asserts the condition key string is what the code emits, not that AWS recognizes it).

## HIGH findings

None.

## MED findings

### MED-20-01 — Malformed `Condition` (non-dict) on an Allow statement causes silent skip; recipe still records axis as applied

- File: `src/iam_jit/reductions.py:196-198`
- Code:
  ```python
  cond = s.setdefault("Condition", {})
  if not isinstance(cond, dict):
      # Existing condition is malformed; skip rather than corrupt
      continue
  ```
- Issue: the comment correctly identifies the safety motivation (don't corrupt a malformed Condition), but the surrounding logic still produces a `ReductionEntry` for the axis even though the narrowing was NOT actually applied to that Allow. The function returns a single recipe entry per axis, NOT per statement, so the result reports "narrowed to X" while one or more Allow statements remain unscoped.

- Repro:
  ```python
  from iam_jit.reductions import apply_reductions
  p = {
    "Version": "2012-10-17",
    "Statement": [
      {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},                            # well-formed
      {"Effect": "Allow", "Action": "ec2:*", "Resource": "*", "Condition": "GARBAGE"},   # malformed
    ]
  }
  r = apply_reductions(p, narrow_to_accounts_list=["111111111111"])
  # Result: s3 statement narrowed; ec2 statement passes through with the broken Condition still attached.
  # Recipe says: [{"axis": "narrow_to_accounts", "values": ["111111111111"]}]
  # Summary says: "scoped to account(s) 111111111111"
  # Reality: ec2:* is not scoped at all.
  ```

- Why this matters: the recipe is the audit-chain artifact admins read when approving a grant. If it asserts "scoped to account 111" but the produced policy contains an unscoped Allow, the admin's approval is based on false ground. Defense-in-depth: the scorer would still flag the broad `ec2:*` if the request asked for narrower scope, but the scorer doesn't know "the user intended to narrow this" — only the recipe does. The recipe lying weakens the human-review layer.

- Likelihood: LOW. The most common path is `policy = get_template(baseline)` → reduce. Catalog baselines have well-formed Conditions. Malformed Conditions enter the path if (a) the agent constructs a custom baseline, (b) a user-saved template was hand-edited badly, (c) an LLM hallucinated a policy with `Condition: "..."` as a string. The agent-driven loop ([[agent-driven-reduction-loop]]) is exactly the workflow where (c) can happen.

- Recommended fix (one of):
  - **(a)** Track per-statement application and only record the recipe entry if at least one statement was successfully narrowed; OR record the recipe entry but include a `statements_skipped` count/list when any were skipped, so the admin sees "narrowed to account 111 (1 of 2 Allow statements; 1 skipped due to malformed Condition)."
  - **(b)** Raise an error when a malformed Condition is encountered, forcing the caller to clean up the input policy before reducing. This matches the [[creates-never-mutates]] discipline — iam-jit should refuse to silently work around customer-provided malformed data.
  - **(c)** Add a structural-validation pass at the top of `_add_condition_to_allow_statements` that returns an error result if any Allow statement has a non-dict Condition.

- Severity: MED — recipe-honesty bug rather than a security-grant bug. Composes badly with the agent-driven reduction loop where LLMs can produce malformed Conditions.

### MED-20-02 — `narrow_to_regions` on a baseline that already uses `StringLike: aws:RequestedRegion` produces an unsatisfiable AND; Allow becomes dead

- File: `src/iam_jit/reductions.py:174-215`
- Issue: `_add_condition_to_allow_statements` always writes the new narrowing into `Condition.StringEquals`. If the existing Condition already constrains the same key with a different operator (e.g. `StringLike: aws:RequestedRegion: "us-east-*"`), the produced Condition contains BOTH operators on the same key:
  ```json
  "Condition": {
      "StringLike": {"aws:RequestedRegion": "us-east-*"},
      "StringEquals": {"aws:RequestedRegion": ["us-west-2"]}
  }
  ```
  Per AWS IAM evaluation, multiple operators in the same Condition block are AND'd. So the Allow now requires the region to match `us-east-*` AND equal `us-west-2` — never satisfiable → Allow is dead → policy grants nothing through that statement.

- Plausibility (this is not theoretical):
  - `tests/calibration_corpus/research_patterns/research-11-14-requestedregion-stringequals-wildcard.yaml` exists and describes `StringEquals: aws:RequestedRegion: "us-east-*"` and StringLike variants in the wild.
  - `tests/calibration_corpus/aws_managed/ROSAImageRegistryOperatorPolicy.yaml` uses `${aws:RequestedRegion}` in Resource ARNs — adjacent pattern.
  - `tests/calibration_corpus/aws_managed/AWSForWordPressPluginPolicy.yaml:39` uses `aws:RequestedRegion: us-east-1`.

  If an agent picks any of these as a baseline and then calls `narrow_to_regions` to "scope down," the result is a dead policy.

- Repro:
  ```python
  from iam_jit.reductions import narrow_to_regions
  p = {
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow", "Action": "*", "Resource": "*",
      "Condition": {"StringLike": {"aws:RequestedRegion": "us-east-*"}}
    }]
  }
  result, _ = narrow_to_regions(p, ["us-west-2"])
  # result has both StringLike and StringEquals — unsatisfiable AND.
  ```

- Recommended fix (one of):
  - **(a)** Detect existing operators on the same key and merge intent rather than appending: if `StringLike: aws:RequestedRegion: "us-east-*"` is present, compute the intersection (in this case: regions matching `us-east-*` that ARE in the StringEquals list) and write only that. Complex — requires region-glob expansion.
  - **(b)** Detect existing operators on the same key and REPLACE rather than append: drop `StringLike: aws:RequestedRegion: ...` when adding `StringEquals: aws:RequestedRegion: [...]`. Surfaces in the recipe entry as a note (e.g. `"replaced StringLike with StringEquals on aws:RequestedRegion"`). Aligns with "reductions are transparent" but the replacement is a semantic change the admin should see.
  - **(c)** Refuse to narrow when the same key is already constrained by a different operator; return a recipe with no entry and an explanatory note, leaving the caller to either accept the existing narrowing or use a different baseline. Most conservative.
  - **(d)** Document the limitation explicitly in the docstring + tool description ("narrow_to_regions does not handle baselines that already constrain aws:RequestedRegion with a different operator; use a different baseline").
  - Also covers an analogous concern for `narrow_to_accounts` if the corrected key (`aws:ResourceAccount` per CRIT-20-01) is already constrained by a different operator in the baseline.

- Severity: MED — produces a non-functional grant (same end-state as CRIT-20-01 but rarer trigger), and the recipe + summary continue to claim the narrowing was applied. Frequency depends on how often baselines pre-narrow regions; AWS-managed catalog has multiple such policies, so it's not negligible.

## LOW findings

### LOW-20-01 — `deny_services` accepts service prefixes containing `:`; produces malformed AWS Actions

- File: `src/iam_jit/reductions.py:91, 103`
- Validation at line 91:
  ```python
  valid = [s.strip() for s in services if isinstance(s, str) and s.strip()]
  ```
  Then at line 103:
  ```python
  "Action": [f"{s}:*" for s in valid],
  ```
- Issue: a service prefix like `"rds:*"` or `"ec2:Describe*"` passes the validation (it's a non-empty string after strip), then gets the `:*` suffix appended → produces `"rds:*:*"` or `"ec2:Describe*:*"`. These are malformed AWS Action strings (extra `:` segment); AWS rejects at PUT time.
- Whether this is caught depends on whether the iam-jit submit/grant pipeline validates Actions before sending to AWS. If yes, the user gets a structured error. If no, AWS rejects the AssumeRole / PutPolicy call with a generic error.
- Recommended fix: validate service prefix is `^[a-z][a-z0-9-]*$` (or similar — match the AWS service namespace shape). Reject anything containing `:`, `*`, whitespace, or uppercase.
- Severity: LOW — caller error rather than silent fail-open; produces a loud failure (AWS rejection) downstream, not a silent compromise.

### LOW-20-02 — `deny_services` always appends Sid `ReductionDenyServices`; second call (or baseline pre-existing Sid) produces duplicate-Sid policy

- File: `src/iam_jit/reductions.py:100-101`
- Code:
  ```python
  deny_stmt = {
      "Sid": "ReductionDenyServices",
      ...
  }
  ```
- Issue: AWS requires Sids to be unique within a policy. Two paths reproduce the duplicate:
  1. `deny_services(deny_services(p, ['rds'])[0], ['ec2'])` — two sequential calls produce two `ReductionDenyServices` Sids.
  2. A baseline that happens to already use this Sid (unlikely but unguarded).
- AWS rejects at PUT time.
- Likelihood (1) is low because `apply_reductions` calls `deny_services` once, but the primitive is callable directly per the public API (it's exported from `reductions`).
- Recommended fix: when appending the Deny, check existing Sids and either uniquify (`ReductionDenyServices`, `ReductionDenyServices_2`, …) or merge into the existing Sid'd statement if one is present. Alternatively, omit the Sid entirely (Sid is optional in AWS) — but Sids aid recipe readability when the same policy is later inspected.
- Severity: LOW — produces a loud AWS rejection, not silent breakage.

### LOW-20-03 — Region values not normalized; AWS StringEquals is case-sensitive, so `us-EAST-1` silently nullifies vs real region `us-east-1`

- File: `src/iam_jit/reductions.py:158`
- Validation:
  ```python
  valid = [r.strip() for r in regions if isinstance(r, str) and r.strip()]
  ```
- Issue: only checks "non-empty string after strip." A typo like `us-EAST-1`, `US-east-1`, or `us-east1` passes validation. AWS populates `aws:RequestedRegion` with the canonical lowercase region code; `StringEquals` is case-sensitive; so the produced condition never matches → Allow dead in the same way as CRIT-20-01 (but caller error rather than design bug).
- Recommended fix: normalize to lowercase + validate against the project's existing `_VALID_AWS_REGIONS` set (already maintained in `src/iam_jit/review.py:1191-1195`). Reject unknown regions, lowercase the rest.
- Severity: LOW — caller-error class; consistent with the broader pattern of doing strict input validation elsewhere in the codebase (the scorer already enforces the valid-regions set for ARN parsing).

### LOW-20-04 — Effect comparison is exact-`"Allow"`; statements with `"allow"` or `" Allow"` silently skipped while recipe entry still recorded

- File: `src/iam_jit/reductions.py:193`
- Code:
  ```python
  if s.get("Effect") != "Allow":
      continue
  ```
- Issue: a statement with `Effect: "allow"` (lowercase, rejected by AWS at PUT time but possible in malformed input) or with surrounding whitespace (`" Allow"`) is silently skipped from narrowing, and — same shape as MED-20-01 — the recipe entry is still recorded.
- Defending the current behavior: AWS rejects malformed Effect at PUT time, so a downstream submit would loud-fail. So this is more a recipe-honesty issue than a security one. The exact-`"Allow"` match is correct strictness; the problem is the recipe entry shouldn't claim narrowing happened if no statements were modified.
- Recommended fix: same fix family as MED-20-01 — track per-statement application and either record nothing in the recipe (no Allows touched) or include a `skipped` count so the admin sees the truth.
- Severity: LOW — bounded by AWS PUT-time rejection of the upstream malformation.

## Test-integrity notes

The 21 new tests in `tests/test_reductions.py` probe what they claim, with the following gaps:

- `test_deny_services_appends_deny_statement` (line 39) — checks Effect=Deny, Action format, and Recipe entry. Solid. Does NOT validate the Sid value or that `Resource: "*"` is correct (cosmetic; could be tightened).
- `test_deny_services_empty_list_no_op` (line 52) — solid.
- `test_deny_services_ignores_non_string_items` (line 59) — exercises type-filtering. Solid.
- `test_deny_services_handles_single_dict_statement_form` (line 66) — exercises the single-dict normalization. Solid.
- `test_deny_services_does_not_mutate_input` (line 79) — solid. Does NOT cover the deeper case of a single-dict-form Statement (whose mutation would be a different code path).
- `test_narrow_to_accounts_adds_condition_to_allow` (line 94) — asserts the produced Condition uses the key `aws:RequestedAccount`. **Encodes CRIT-20-01 as the expected behavior.** The test passes because it checks "code emits the key we wrote in the code," not "AWS would honor the key." This is exactly the test-pattern gap that [[audit-cadence-discipline]] is designed to catch: structural tests that confirm a string is present without validating it has the correct AWS-IAM-semantics.
- `test_narrow_to_accounts_rejects_non_12_digit` (line 101) — solid.
- `test_narrow_to_accounts_does_not_touch_deny_statements` (line 109) — solid; confirms `Effect == "Allow"` gating.
- `test_narrow_to_accounts_merges_with_existing_condition_values` (line 126) — tests merging within the same `StringEquals` operator. Does NOT test the cross-operator MED-20-02 case (existing `StringLike` on the same key).
- `test_narrow_to_accounts_empty_no_op` (line 145) — solid.
- `test_narrow_to_regions_*` (lines 156-179) — analogous to the accounts tests; same coverage profile. Does NOT cover MED-20-02.
- `test_apply_reductions_all_three_axes` (line 187) — exercises the 3-axis composition end to end. Confirms order. Solid.
- `test_apply_reductions_no_op_returns_empty_recipe` (line 210) — solid.
- `test_apply_reductions_summary_describes_what_was_reduced` (line 216) — solid.
- MCP-wiring tests (lines 233-284) — `_reduce_policy_for_mcp` round-trip, non-dict-policy rejection, non-list-filter rejection, `_handle_request` dispatch, `tools/list` discovery. Solid coverage of the MCP boundary.

Recommended test additions to close the gaps:
1. `test_narrow_to_accounts_uses_documented_aws_global_condition_key` — assert the condition key matches one of the documented AWS global keys (`aws:ResourceAccount`, `aws:PrincipalAccount`, `aws:SourceAccount`). This would have caught CRIT-20-01.
2. `test_narrow_to_*_recipe_truthful_when_no_statements_touched` — pass a policy with only malformed-Condition Allows, assert recipe entry is `None` (or includes a skipped-count). Would catch MED-20-01.
3. `test_narrow_to_regions_with_existing_stringlike_operator` — pass a policy with `StringLike: aws:RequestedRegion: "us-east-*"`, narrow to `us-west-2`, assert the resulting policy is either correctly merged or explicitly errored. Would catch MED-20-02.

## Regression check

`pytest tests/ -q --ignore=tests/e2e --ignore=tests/test_calibration_corpus.py` → **1968 passed, 29 skipped, 14 deselected** in 88.91s. Matches the audit-prompt's expectation exactly. No regressions.

## Summary

The reduction primitives are clean structurally: pure functions, deepcopy at every entry, no mutation, deterministic composition order, well-formed MCP boundary, and 21 tests that exercise the structural shape thoroughly. **The CRIT — `aws:RequestedAccount` is not a real AWS condition key — is mechanical to fix (one-character change-of-string) but is a load-bearing bug**: the primary feature does not work at AWS evaluation time, and the recipe + summary actively lie about what was applied. This is exactly the bug shape [[audit-cadence-discipline]] targets — the unit tests pass because they assert structural identity ("code emits the string we wrote"), not AWS-IAM-semantic correctness ("AWS will honor this key"). Recommend fixing CRIT-20-01 before the `reduce_policy` MCP tool is presented to agents, since the schema description (`mcp_server.py:379-382`) names the same wrong key and will propagate the error into LLM reasoning.

The two MEDs (malformed-Condition silent skip + cross-operator unsatisfiable AND) are recipe-honesty bugs that compose particularly badly with the agent-driven reduction loop where LLM-produced baselines may exercise the edge cases. Fix priority is post-CRIT.

The four LOWs are robustness gaps (service-prefix character-class validation, Sid uniquification, region case normalization, recipe-honesty on skipped Allows) that don't block launch but should be batched into the next reductions iteration.

Per [[audit-cadence-discipline]] the "structural tests that don't validate semantics" pattern keeps surfacing — round 19 had the same shape (`test_admin_like_baseline_denies_sensitive_s3_patterns` checked the patterns were in the resource list without validating action-resource compatibility, missing MED-19-01). The class of test bug worth a discipline note: **string-presence tests on AWS-IAM-semantic identifiers (condition keys, action names, resource-type ARNs) must always be paired with a "does AWS interpret this the same way" check** — either an allow-list of known-valid identifiers, a calibration-corpus entry that exercises the produced policy end-to-end, or an explicit "AWS doc reference" comment naming the source of truth.
