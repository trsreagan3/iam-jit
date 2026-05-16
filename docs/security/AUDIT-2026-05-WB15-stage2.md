# Round 15 audit — Stage 2 of NL deprecation

Commit under review: `c2cb142` (`deprecate(stage 2): delete fuzzy match_baseline + baseline-fallback`).

Scope: `src/iam_jit/aws_managed_catalog.py` (-104 LOC), `src/iam_jit/mcp_server.py` (-42 LOC), `tests/test_aws_managed_catalog.py` (rewritten), `tests/test_mcp_score_policy.py` (sentinels), `tests/test_mcp_template_tools.py` (deletion). Net -242 LOC. Black-box probes against `python -m iam_jit.mcp_server` over stdio. White-box review of imports + caller graph + flow integrity.

## Headline

2 findings: 0 CRIT, 0 HIGH, 0 MED, 2 LOW. Clean deletion — no dangling callers, no broken imports, no behavior regressions. Both LOWs are documentation/dead-data hygiene gaps inherited from the deletion; neither affects runtime or security. Stage 2 lands as planned.

## Closure status (2026-05-16, post-audit fix pass)

| Finding | Status |
|---|---|
| LOW-15-01 (stale module docstring) | ✅ FIXED — docstring rewritten to describe browse API + reference [[no-nl-synthesis]] Stage 2 |
| LOW-15-02 (use_case_tags dead data) | ✅ FIXED — wired into `list_entries(tag=...)` filter; surfaced in summary dict; MCP tool schema updated; 4 new tests |

Test count after closures: **91 passing** (was 87; +4 tag-filter tests). All clean.

All Stage-1 carry-forward items addressed:

| Stage-1 carry-forward | Status |
|---|---|
| Deprecation block on (now sole) generate path | ✅ Present on both success-return and empty-task error-return |
| Update `test_generate_iam_policy_baseline_fallback_also_has_deprecation` | ✅ Deleted with NOTE explaining why |
| INFO-14-09 (garbage-policy scoring) if shape validation touched | ⏸ Not touched in Stage 2 — defer |
| `_generate_for_mcp` callers in cli.py/app.py if removed in Stage 3 | ⏸ Not removed in Stage 2 — defer |

Test count after Stage 2: **87 passing** (MCP+catalog focused). Broader suite: **2130 passing**, 26 deselected (`tests/e2e` + `tests/test_calibration_corpus.py`), unchanged from Stage 1. No new test failures introduced.

## CRIT findings

None.

## HIGH findings

None.

## MED findings

None.

## LOW / INFO findings

### LOW-15-01 Stale module docstring in aws_managed_catalog.py still describes the deleted fuzzy-match contract
- File: `src/iam_jit/aws_managed_catalog.py:9-33`
- Issue: The module docstring opens with "This module is the registry + the fuzzy-match function" and then specifies the return shape of the deleted `best_baseline` (lines 22-33):
  ```
  When the catalog match succeeds, the recommender returns:
      {
          "policy": {...},
          "provenance": {
              "baseline": "AmazonS3ReadOnlyAccess",
              ...
              "match_confidence": "high" | "medium" | "low",
              "matched_tags": [...],
          },
      }
  ```
  None of that exists anymore. The module is now "registry + browse API" (`list_entries` / `get_entry`); the `provenance` / `match_confidence` / `matched_tags` shape is gone with `best_baseline`.
- Impact: Documentation rot only. A future contributor reading the module-level docstring would chase a contract that no caller actually expects. The `ManagedPolicyEntry` field-level comment on line 54 also calls `use_case_tags` "kebab-case keywords for fuzzy match" — same issue, fuzzy match was deleted.
- Fix: Rewrite the module docstring to describe the surviving surface: catalog of `ManagedPolicyEntry` rows + `list_entries(...)` / `get_entry(name)` browse API per `[[no-nl-synthesis]]`. Update the line-54 comment to "kebab-case keywords for the future `query=` filter / per-tag indexing" or just "human-readable use-case tags".

### LOW-15-02 `use_case_tags` field is now dead data with no production consumer
- File: `src/iam_jit/aws_managed_catalog.py:54` (declaration), populated on all 11 entries (lines 74, 106, 137, 160, 185, 220, 285, 319, 356, 389, 421)
- Issue: The only consumer of `use_case_tags` was `_score_match()` (deleted line 444-462 in the diff). After Stage 2, no production code reads the field. The hygiene test `assert entry.use_case_tags` (tests/test_aws_managed_catalog.py:42) still defends its existence, so deletion would cascade into test failures, but the field itself is unused at runtime.
- Verified by grep:
  ```
  $ grep -rn "use_case_tags" src/ tests/
  src/iam_jit/aws_managed_catalog.py:54        use_case_tags: tuple[str, ...]
  src/iam_jit/aws_managed_catalog.py:74,106,137,160,185,220,285,319,356,389,421  (data)
  tests/test_aws_managed_catalog.py:42         assert entry.use_case_tags, "at least one use-case tag required"
  tests/test_aws_managed_catalog.py:181        use_case_tags=("x",), ...  (test fixture)
  ```
  No `entry.use_case_tags` access outside data declarations and test assertions.
- Impact: Memory + maintenance footprint only. The field carries ~5-15 strings per entry × 11 entries that no code reads. No security or correctness risk. Could become useful again if a future `list_entries(tag=...)` filter is added — the data is harmless to keep. Worth deciding explicitly rather than letting it drift.
- Fix: Two options. (a) Wire `use_case_tags` into `list_entries`'s `query=` filter (or add a `tag=` filter) so the data has a live consumer — supports the Stage-3 agent-driven catalog browsing in `docs/AGENTS.md`. (b) Delete the field + its 11 populations + the hygiene assertion if the team commits to "browse by name/service only." Either is fine; the in-between status (data carried, no consumer) is the worst of both. Recommend (a) — adding a `tag=` filter to `list_entries` is ~10 LOC and gives the field a reason to exist.

## What's solid (positive findings)

1. **Caller graph is clean.** `grep -rn "match_baseline\|best_baseline\|confidence_label\|_tokenize\|_score_match\|_WORD_SPLIT_RE"` across `src/` + `tests/` returns ZERO production or test references to the deleted symbols. Only hits are:
   - `tests/test_aws_managed_catalog.py:4-5` — docstring documenting *why* the file was rewritten (historical).
   - `tests/test_routes_score.py:261` — substring false-positive on `test_score_matches_calibration_corpus` (different function entirely).
   - `docs/calibration/feature-reality-check.md` + `docs/calibration/100-prompt-sufficiency-loop.md` + `docs/security/AUDIT-2026-05-WB14-stage1.md` — historical analysis docs that recommended the deletion. All are correctly framed past-tense / "to be deleted."
2. **Imports are clean.** `aws_managed_catalog.py` now imports only `dataclasses` + `typing.Any` from `__future__ import annotations`. The `re` import that backed `_WORD_SPLIT_RE` is gone (confirmed via `head` of file). No unused imports.
3. **`mcp_server.py` imports `aws_managed_catalog` correctly.** Only two import sites: `from .aws_managed_catalog import list_entries` (line 475, inside `_list_templates_for_mcp`) and `from .aws_managed_catalog import get_entry` (line 502, inside `_get_template_for_mcp`). Both are local imports of surviving functions. No stale `best_baseline` import remains.
4. **`_generate_for_mcp` flow integrity verified.**
   - Empty-task error path: returns `{deprecation, error, policy: None}` — `deprecation` present (LOW-14-07 closure preserved). Test `test_generate_iam_policy_empty_task_error_also_has_deprecation` exercises this.
   - Success path (synthesis returns policy): returns `{deprecation, policy, matched_patterns, ...}` — `deprecation` present. Test `test_generate_iam_policy_emits_deprecation_block` exercises this.
   - Success path with empty synthesis (the prompts that used to trigger fallback): returns `{deprecation, policy: None, matched_patterns: [], ...}` — no crash, no `baseline_provenance`, no `aws-managed:` pattern. Verified via end-to-end stdio probe + the two new sentinel tests.
   - No `raise` paths introduced. `generate_policy(req)` failure modes are unchanged (Stage 2 didn't touch the synthesis core).
5. **Sentinel tests probe what they claim.**
   - `test_generate_no_longer_baseline_falls_back_when_synthesis_empty` asserts no `matched_patterns` entry starts with `aws-managed:`. If the fallback were re-introduced, the only way to emit this prefix is via the deleted `best_baseline` provenance shape — the assertion would catch a regression. Also asserts `deprecation` block is still present (covers the carry-forward concern).
   - `test_generate_does_not_introduce_baseline_provenance_field` iterates THREE distinct vague tasks (data lake / SOC2 audit / incident-admin) — covers the three baseline-fallback scenarios from the deleted tests. Asserts `baseline_provenance` key is absent from each result. The key was only ever set by the deleted block, so the test is the precise inverse of the removed behavior. Both tests pass for the right reason.
6. **Catalog data integrity verified.**
   - `_CATALOG` parses cleanly (probed via `for entry in _CATALOG: ...` — no `ValueError`).
   - All 11 entries enumerated: `ReadOnlyAccess`, `SecurityAudit`, `AmazonS3ReadOnlyAccess`, `CloudWatchReadOnlyAccess`, `AmazonRDSReadOnlyAccess`, `ExploreReadOnlyWithSensitiveExclusions`, `DatabaseAdministrator`, `DataScientist`, `NetworkAdministrator`, `PowerUserAccess`, `AdministratorAccess`.
   - `ExploreReadOnlyWithSensitiveExclusions` (lines 208-271) retains all three statements: `ReadEverything` (Allow), `ExcludeSensitiveReads` (Deny secretsmanager:GetSecretValue + ssm:GetParameter[s|sByPath] + kms:Decrypt + kms:GenerateDataKey + kms:ReEncryptFrom + kms:ReEncryptTo), `ExcludeSensitiveBucketReads` (Deny s3:GetObject + s3:ListBucket on `*-secrets|*-sensitive|*-pii|*-customer-data` plus `/*` suffixes). Launch-critical baseline intact.
7. **Browse API behavior unchanged from Stage 1.** `list_entries` filters (`access_type`, `service`, `source`, `query`) and `get_entry(name)` exact-match are byte-identical to Stage 1 — Stage 2 only deleted code below the browse section. All 87 MCP+catalog tests pass, including the new browse-API tests in `tests/test_aws_managed_catalog.py`.
8. **MCP dispatch surface unchanged.** Black-box stdio probe of `python -m iam_jit.mcp_server`:
   - `tools/list` returns all 5: `['generate_iam_policy', 'score_iam_policy', 'list_templates', 'get_template', 'submit_policy']`.
   - `tools/call generate_iam_policy` with vague gibberish prompt returns `{policy: null, matched_patterns: [], deprecation: {...}, baseline_provenance: <absent>}` — no exception, no crash, server stays alive.
   - `_DEPRECATION_BLOCK` content unchanged: `removed_in: "0.4.0"`, `replacement_tools: [list_templates, get_template, score_iam_policy, submit_policy]`, `agent_guidance` pointing at `docs/AGENTS.md`.
9. **No collateral damage to adjacent modules.** Surveyed `src/iam_jit/routes/`, `src/iam_jit/cli.py`, `src/iam_jit/suggest.py`, `src/iam_jit/narrow.py`, `src/iam_jit/policy_gen/` — none import from `aws_managed_catalog` and none reference baseline_provenance / match_baseline / best_baseline. The two-import-site claim (`mcp_server.py` only) holds.
10. **Test deletions accurately reflect deleted code.**
    - `tests/test_aws_managed_catalog.py`: 8 fuzzy-match tests deleted (data-lake → DataScientist, audit → SecurityAudit, DBA, NetworkAdmin, CloudWatch, admin-mode gating, no-match-empty, confidence_label sanity). Replaced with browse-API tests + catalog hygiene + Explore Deny sentinel. Net direction is correct: tests for deleted code are gone, tests for surviving code remain or are added.
    - `tests/test_mcp_score_policy.py`: 4 baseline-fallback test cases (`test_generate_falls_back_to_baseline_for_vague_intent`, `test_generate_baseline_includes_refinement_guidance`, `test_generate_does_not_fallback_when_synthesis_succeeds`, `test_generate_baseline_handles_admin_intent`) replaced with the 2 sentinels described above.
    - `tests/test_mcp_template_tools.py`: `test_generate_iam_policy_baseline_fallback_also_has_deprecation` deleted (its premise was the fallback exists). Replaced with a NOTE comment that explicitly explains the deletion lineage.
11. **Regression net intact for surviving surface.** All 87 MCP+catalog tests pass. Broader suite: 2130 pass, same as Stage 1 (the 26 deselected = 96 pre-existing calibration-corpus failures + tests/e2e per [[audit-cadence-discipline]] baseline). No new test failures introduced by Stage 2.

## Tests passed (regression check)

- `tests/test_mcp_template_tools.py` ……… all pass (including the post-Stage-1 audit-finding tests for MED-14-01/02/03/04)
- `tests/test_mcp_server.py` …………………… all pass (existing MCP server tests)
- `tests/test_mcp_score_policy.py` ………… all pass (Stage-2 sentinels included)
- `tests/test_mcp_read_only_default.py` …… all pass
- `tests/test_aws_managed_catalog.py` ……… all pass (rewritten for browse-API + catalog hygiene)

Combined: **87 passed in 0.22s** (matches commit message claim).

Full repo suite (excluding `tests/e2e` and `tests/test_calibration_corpus.py`): **2130 passed, 26 deselected, 2 warnings in 92.45s**. Same warning set as Stage 1 (HS256 short-key + Starlette per-request cookies deprecation). Zero new failures.

## Stage-3 carry-forward checklist

When the legacy `generate_iam_policy` tool itself is removed in Stage 3 (per the `removed_in: "0.4.0"` deprecation tombstone):

- [ ] Audit any callers of `_generate_for_mcp` (the audit didn't survey app.py / cli.py here because nothing in Stage 2 changed its signature — but Stage 3 removes the call entirely).
- [ ] Remove the `generate_iam_policy` entry from `TOOLS` (line ~74) and the dispatch `if tool_name == "generate_iam_policy"` branch (line ~760).
- [ ] Delete `_DEPRECATION_BLOCK` if no other tool uses it.
- [ ] Decide LOW-15-01 (rewrite catalog module docstring) and LOW-15-02 (`use_case_tags` consumer or removal) — both are best resolved before Stage 3 ships so the catalog module's documented contract matches its actual surface at launch.
- [ ] Confirm `_generate_for_mcp` removal doesn't strand `generate_policy` / `GenerationRequest` / `Refinement` / `BIAS_ALLOW` / `BIAS_DENY` / `GenerationContext` imports in `mcp_server.py` — if Stage 3 removes the last caller, those imports become unused.

When the catalog grows past the pre-launch ~11 entries:

- [ ] Revisit the 50-entry truncation cap in `list_entries` (Stage-1 audit positive-finding #9) — may need pagination.
- [ ] Decide whether `use_case_tags` becomes the basis of a `tag=` filter (LOW-15-02 option (a)).
