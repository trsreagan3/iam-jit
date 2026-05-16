# Round 16 audit — Stage 3 of NL deprecation

Commit under review: `df54352` (`deprecate(stage 3): delete policy_gen + agent-grant; tombstone generate_iam_policy`).

Scope: deletion of `src/iam_jit/policy_gen/` (20 files, ~2163 LOC), deletion of `tests/test_policy_gen/` (6 files + ADVERSARIAL-FINDINGS.md, ~1439 LOC), deletion of `agent-grant` CLI block (~186 LOC) replaced with a tombstone command, replacement of `_generate_for_mcp` with a tombstone in `src/iam_jit/mcp_server.py`, and SERVER_VERSION bump 0.3.0 → 0.4.0. Net -3951 LOC across 35 files. Black-box probes against `python -m iam_jit.mcp_server` over stdio. White-box review of imports + caller graph + tombstone integrity + test-deletion accuracy.

## Headline

4 findings: 0 CRIT, 0 HIGH, 0 MED, 4 LOW. Clean deletion at the code level — no dangling callers, no broken imports, no behavior regressions, no test regressions. All four LOWs are documentation/cleanup hygiene gaps inherited from a deletion of this scale; none affect runtime, security, or scoring correctness. Stage 3 lands as planned. The big-deletion failure mode (dangling references) didn't materialize: only the orphan-`__pycache__`-as-namespace-package gotcha (LOW-16-04) is even arguable as "dangling," and it's inert.

## Closure status (2026-05-16, post-audit fix pass)

| Finding | Status |
|---|---|
| LOW-16-01 (mcp_server module docstring stale) | ✅ FIXED — rewritten to describe the four live MCP tools + tombstone; references [[no-nl-synthesis]] decision + docs/AGENTS.md |
| LOW-16-02 (cli mcp-server command docstring stale) | ✅ FIXED — rewritten to enumerate the four tools + the tombstone; explains the agent-author / iam-jit-gates architecture |
| LOW-16-03 (tombstone inputSchema property descriptions undermine REMOVED signal) | ✅ FIXED — schema reduced to `{"type": "object"}`; per-property descriptions deleted; tool remains discoverable but signals tombstone status consistently |
| LOW-16-04 (orphan `__pycache__/` directories) | ✅ FIXED — working-tree cleanup; verified directories absent |

All 90 MCP+catalog tests still pass after the closure pass.

## CRIT findings

None.

## HIGH findings

None.

## MED findings

None.

## LOW / INFO findings

### LOW-16-01 Stale module docstring in `mcp_server.py` describes the deleted synthesis contract
- File: `src/iam_jit/mcp_server.py:1-46`
- Issue: The module docstring opens with "MCP (Model Context Protocol) server exposing iam-jit policy generation" and then specifies the deleted architecture diagram:
  ```
  Lets any MCP-aware agent ... natively request scoped AWS IAM policies for
  specific tasks. The agent describes what it needs to do; the server returns
  a generated policy + risk score; the agent ... decides whether to attach the
  policy to a JIT-issued STS credential.

  Architecture:
    agent → MCP request: { task, context, bias }
          ↓
    this server: validates input, calls generate_policy(), runs the
                 output through the deterministic scorer
          ↓
    agent ← MCP response: { policy, risk_score, refinement_hints }
  ```
  None of this is true post-Stage-3: there is no `generate_policy()` to call (the package is gone); the server does not "return a generated policy"; the `{ policy, risk_score, refinement_hints }` shape is a tombstone-only response. The "tiny ... one tool, no prompts, no resources" implementation note (line 26) is also wrong — there are five tools.
- Impact: Documentation rot only. Same shape as LOW-15-01 (stale `aws_managed_catalog` module docstring) — a future contributor reading the module docstring would chase a contract that no code expects. Higher visibility than LOW-15-01 because this is the primary integration surface for MCP-aware agents.
- Fix: Rewrite the module docstring to describe the four-tool surface (`list_templates` / `get_template` / `score_iam_policy` / `submit_policy`) + the tombstoned `generate_iam_policy`, per `docs/AGENTS.md`. Architecture diagram should show "agent picks baseline → narrows with codebase context → re-scores → submits". Reference `[[no-nl-synthesis]]` Stage 3 + the 1.8% joint-sufficiency measurement.

### LOW-16-02 `mcp-server` CLI subcommand docstring still advertises the deleted `generate_iam_policy` tool
- File: `src/iam_jit/cli.py:667-689` (`mcp_server_cmd`)
- Issue: The `iam-jit mcp-server --help` output ends with:
  ```
  The agent then has access to the `generate_iam_policy` tool, which
  returns a scoped IAM policy + risk score + refinement hints for
  any task description it submits.
  ```
  Calling `generate_iam_policy` post-Stage-3 returns a tombstone, not "a scoped IAM policy + risk score + refinement hints". This is what an operator first sees when configuring iam-jit in Claude Desktop / Code — and it directly mis-sells the surface.
- Impact: Documentation rot only. A new operator who runs `iam-jit mcp-server --help` to verify the MCP integration before adding it to their Claude config gets the deleted contract verbatim. The tool description in `tools/list` IS correct ("REMOVED in iam-jit 0.4.0 (tombstone)..."), so as soon as the agent fetches it the error is corrected — but the CLI help advertises the wrong story.
- Fix: Rewrite the docstring to describe the four-tool surface, mirroring the `mcp_server.py` module docstring fix from LOW-16-01. Keep the Claude Desktop config snippet — that part is correct.

### LOW-16-03 Tombstone tool schema retains misleading parameter descriptions (back-compat trade-off)
- File: `src/iam_jit/mcp_server.py:83-162` (`TOOLS[0].inputSchema`)
- Issue: Per Q7 in the audit request, the schema was deliberately kept for cached-client back-compat. The tool **description** at line 67-82 cleanly announces "REMOVED in iam-jit 0.4.0 (tombstone)." But the per-property descriptions below it still describe live behavior the tombstone does not provide:
  - `task` description: "Plain-English description of the task. Be specific about resources..." — but `task` is fully ignored by `_generate_for_mcp`.
  - `access_type` description: "REQUIRED behavioral default: 'read-only'. Only set to 'read-write' when..." — `access_type` is ignored.
  - `bias` description: "'allow' (default) includes more actions; 'deny' includes only explicit ones." — bias is ignored; no actions are produced regardless.
  - `exclude_actions` / `include_actions` / `rationale` similarly. All five label themselves as "Refinement: ..." actions on a result that no longer exists.

  A well-behaved MCP client reads the `inputSchema` *before* invoking the tool (to validate / surface a UI). The tool description prepares the agent for "REMOVED" but the parameter descriptions create the impression "...but the parameters still do their advertised thing." An agent that sets `rationale="<important compliance reason>"` will discover at call-time that the value was dropped into a void — including any audit-log expectation the agent had based on the description's "Surfaces in audit logs for compliance review" claim.
- Impact: Documentation honesty — agents and operators are mis-led by per-property descriptions that no longer hold. The tombstone payload is fully covered by the top-level description; the per-property text is now strictly misleading. No security impact (no input is honored anyway), but the deprecation signal is weaker than the tool description implies.
- Fix: Two options, both acceptable.
  - (a) **Strip the schema** to `{type: "object", properties: {}, description: "All parameters ignored — see tool description."}`. Clean break. Cached clients pass schema validation against the old shape but their call is ignored anyway; new clients see the honest schema. ~5 LOC.
  - (b) **Prefix every property description** with `"(IGNORED in tombstone) "`. Preserves the original cached-shape signal AND tells the agent every property is dead. ~10 LOC.
  The stated intent ("agents with cached schemas don't get a shape-changed surprise") is fine, but the per-property strings undermine that intent. Recommend (b) — keeps the back-compat property *names* / *types* but honestly labels their dead-ness.

### LOW-16-04 Orphan `src/iam_jit/policy_gen/__pycache__/` directories cause `import iam_jit.policy_gen` to succeed silently as a namespace package
- File: `src/iam_jit/policy_gen/__pycache__/`, `src/iam_jit/policy_gen/patterns/__pycache__/` (working-tree-only; not in git)
- Issue: `git rm -r src/iam_jit/policy_gen/` removed the .py files but the `__pycache__/` byte-cache directories survived locally. Python 3's namespace-package resolution (PEP 420) sees the bare directories and treats `iam_jit.policy_gen` as a valid namespace package — so `import iam_jit.policy_gen` succeeds, returning an empty module with `__file__ = None`.
- Repro:
  ```py
  $ .venv/bin/python -c "import iam_jit.policy_gen as p; print(p, p.__file__)"
  <module 'iam_jit.policy_gen' (namespace) from
   ['/Users/reagan/repos/iam-roles/src/iam_jit/policy_gen']>
  None
  ```
- Behavior of stale `.pyc` files:
  ```py
  from iam_jit.policy_gen import generate_policy  # → ImportError ✓
  from iam_jit.policy_gen import generate         # → ImportError ✓ (no .py shadow loads stale .pyc)
  from iam_jit.policy_gen.patterns import s3      # → ImportError ✓
  ```
  Python's loader does **not** fall back to orphan `.pyc` files when no `.py` exists — those bytecode files are functionally inert. So no deleted symbol is accidentally importable. The only artifact is that the bare `import iam_jit.policy_gen` line resolves successfully (empty module).
- Impact: Cleanliness only. Could mask a contributor bug if someone later writes `import iam_jit.policy_gen` and expects an ImportError as the signal "this package was deleted." Not exploitable; no symbols accessible. The .pyc files themselves are dead bytecode that the loader won't use.
- Fix: Add `find . -name __pycache__ -type d -exec rm -rf {} +` to the repo's `make clean` / contribute setup (or just delete them manually as a follow-up to commit `df54352`). Optionally add `**/__pycache__/` to a Stage-3 cleanup script or to the `pyproject.toml` `[tool.setuptools.exclude-package-data]` — though this is a working-tree-only issue (the .pyc files aren't in git, confirmed via `git status` clean). Consider adding `src/iam_jit/policy_gen/` to `.gitignore` defensively in case anything re-creates it.

## What's solid (positive findings)

1. **Caller graph is clean.** `grep -rn "policy_gen|generate_policy|GenerationRequest|GenerationContext|GenerationResult|^Refinement\b|BIAS_ALLOW|BIAS_DENY" src/ --include="*.py"` returns only:
   - The two `agent-grant` tombstone lines in `src/iam_jit/cli.py:321-322,333` (the deprecated command itself).
   - One historical comment in `src/iam_jit/mcp_server.py:12` (stale docstring — LOW-16-01).
   - Line 55 (annotation noting Stage 3 deletion).
   - Lines 142, 150 (the `Refinement: ...` description strings in the tombstoned tool schema — LOW-16-03).
   - Line 662 (the tombstone docstring referencing "the entire policy_gen package").
   No live production reference to any deleted symbol. The `grep` against deleted package imports (`from .policy_gen`, `from iam_jit.policy_gen`, etc.) returns empty.

2. **CLI tombstone works.** Verified end-to-end:
   ```
   $ python -m iam_jit.cli agent-grant
   iam-jit agent-grant has been removed in 0.4.0.
   Use the MCP tools (list_templates / get_template / score_iam_policy / submit_policy) instead. See docs/AGENTS.md.
   exit: 2
   ```
   And `agent-grant --help` cleanly renders the click help with the docstring (the "REMOVED in iam-jit 0.4.0 — see docs/AGENTS.md" message + `[[no-nl-synthesis]]` Stage 3 attribution + the 1.8% sufficiency reference).

3. **MCP server tombstone works end-to-end.** Stdio probe against `python -m iam_jit.mcp_server`:
   - `initialize` → `serverInfo.version == "0.4.0"` ✓
   - `tools/list` → 5 tools: `[generate_iam_policy, score_iam_policy, list_templates, get_template, submit_policy]` ✓; `generate_iam_policy.description` starts with `"REMOVED in iam-jit 0.4.0 (tombstone)."` and points at all four replacement tools.
   - `tools/call generate_iam_policy {task: "anything"}` → `{policy: null, deprecation: {removed_in: "0.4.0", replacement_tools: [...]}, error: "...0.4.0...", matched_patterns: [], confidence: null, scored_risk: null, refinement_hints: [], reasons: []}` ✓.
   - `tools/call generate_iam_policy {}` (no args) → identical tombstone response, no crash ✓.
   - Sanity check: `list_templates`, `get_template`, `score_iam_policy`, `submit_policy` all still dispatch correctly through the same `_handle_request` → return their expected payloads (12-entry catalog list, S3RO policy fetch, scored payload, would_submit envelope).

4. **Tombstone is hermetic — no input crashes, no leaks, fast.** Black-box stress with 10 adversarial input shapes (empty, oversize task, wrong types, path-traversal `partition`, env-var-named `rationale`, etc.) — none crash; every response has `policy=None`, the `error` mentions 0.4.0, no echo of any input value, no env-var leak (sentinel-value probe verified). Timing: 0.38 µs per call (10k iterations / 3.8 ms) — well under the ~1ms claim from Q8.

5. **Import hygiene is clean.** `src/iam_jit/mcp_server.py` now imports only `json` + `sys` + `typing.Any` at top. The only `policy_gen`-touching `from .policy_gen import ...` block at the old top of the file is gone (replaced by nothing). The deferred imports inside MCP handlers (`from .review import analyze_policy`, `from .aws_managed_catalog import list_entries`, `from .aws_managed_catalog import get_entry`, `import httpx`) are all live and intentional. `src/iam_jit/cli.py` has no remaining `from .policy_gen` or `from iam_jit.policy_gen` references.

6. **Test integrity preserved.** `tests/test_policy_gen/` is fully removed (no orphan files, no `__init__.py` left). `grep -rn "from .*test_policy_gen\|import test_policy_gen" tests/` is empty — no other test file references the deleted directory. The 6 deleted test files map cleanly to the 20 deleted source files (no dangling test-of-deleted-test).

7. **All 4 audit-finding tests skip cleanly with the correct closure-by-deletion message.** Ran `pytest -v` on the four specific tests:
   - `tests/test_appsec_audit_round2_wb.py::test_finding_mcp_generate_no_task_description_cap` → SKIPPED ✓
   - `tests/test_appsec_audit_round2_wb.py::test_finding_mcp_arn_segments_unvalidated` → SKIPPED ✓
   - `tests/test_appsec_audit_round2_wb.py::test_finding_policy_gen_no_prompt_injection_scan` → SKIPPED ✓
   - `tests/test_appsec_audit_round2_bb.py::test_bb2_17_mcp_server_is_stateless` → SKIPPED ✓
   All four skip-reason strings start with `"closed by deletion: policy_gen package removed in 0.4.0 ([[no-nl-synthesis]] Stage 3)..."` and clearly explain why the finding is closed (deletion, not fix). Each skip is the only line after the docstring — no dangling `assert ... not in pol1` style leftovers were found (Q6 audit specifically requested this check).

8. **Tombstone schema preservation IS intentional and consistent with the back-compat story.** Q7 audit: the `inputSchema` for `generate_iam_policy` retains all 9 properties (`task`, `access_type`, `account_id`, `region`, `partition`, `resources`, `bias`, `exclude_actions`, `include_actions`, `rationale`) so MCP hosts that cached the 0.3.0 schema don't see a "shape changed" surprise. The tool **description** is the authoritative deprecation signal ("REMOVED in iam-jit 0.4.0 (tombstone)..."). The handler ignores all inputs and returns the tombstone uniformly. This matches the stated intent — but see LOW-16-03 for the property-description honesty gap.

9. **Targeted MCP+catalog suite: 90 passing.** `pytest tests/test_mcp_*.py tests/test_aws_managed_catalog.py` → `90 passed in 0.19s`. Matches the commit-message claim exactly. Breakdown:
   - `test_mcp_read_only_default.py`: 6 (rewritten for `submit_policy` access_type convention)
   - `test_mcp_score_policy.py`: 11 (Stage-2 sentinels + scoring tests)
   - `test_mcp_server.py`: 9 (including the renamed `test_tools_call_generate_iam_policy_returns_tombstone` + `test_refinement_args_ignored_by_tombstone`)
   - `test_mcp_template_tools.py`: 46 (triad coverage + 2 tombstone tests + audit-finding tests for MED-14-01..03)
   - `test_aws_managed_catalog.py`: 18 (browse API + tag filter from Stage-2 closures)

10. **Broader suite: 2026 passing + 4 skipped + 26 deselected.** `pytest --ignore=tests/e2e --ignore=tests/test_calibration_corpus.py` → `2026 passed, 4 skipped, 26 deselected, 2 warnings in 91.85s`. Matches the commit-message claim exactly. Net delta from Stage 2 (2130 → 2026, -104) tracks the deleted-test count (the `test_policy_gen` package + the deleted baseline-fallback fixtures). The 4 skipped = the four closure-by-deletion audit-finding tests (per check #6 above). No new failures introduced.

11. **Tombstone test pair in `test_mcp_template_tools.py` accurately reflects the new contract.**
    - `test_generate_iam_policy_is_tombstone_returns_null_policy` (line 360): asserts `deprecation.deprecated is True`, `removed_in == "0.4.0"`, `list_templates` + `submit_policy` in `replacement_tools`, `policy is None`, `matched_patterns == []`, `error` present, `"0.4.0"` in error.
    - `test_generate_iam_policy_tombstone_response_is_consistent` (line 388): asserts the same shape across 4 input variants (`{}`, `{"task": ""}`, `{"task": "valid task"}`, `{"foo": "bar"}`). Covers Q3 + Q8 directly.
    Both pass under the implementation and would fail if a future regression brought back any synthesis path.

12. **Stage-2 sentinel tests still hold under Stage 3.** `test_generate_no_longer_baseline_falls_back_when_synthesis_empty` and `test_generate_does_not_introduce_baseline_provenance_field` (`tests/test_mcp_score_policy.py:178-208`) still pass — the tombstone produces no `matched_patterns` and no `baseline_provenance`. The Stage-2 invariants survive the Stage-3 deletion trivially (tombstone is a stricter regime). Sentinels become weaker post-Stage-3 (the tombstone can't possibly fire the old paths) but remain valid regression guards if the tombstone were ever re-replaced with a real implementation that re-introduced fallback shapes.

13. **`_DEPRECATION_BLOCK` correctly retained as tombstone payload.** Stage-2 carry-forward checklist item #3 asked "Delete _DEPRECATION_BLOCK if no other tool uses it." Post-Stage-3, the tombstone IS the only consumer (`mcp_server.py:669`) — but it's load-bearing for the tombstone's response shape. Correct call to keep it.

14. **No collateral damage to adjacent modules.** Surveyed `src/iam_jit/routes/`, `src/iam_jit/cli.py` (apart from the tombstone), `src/iam_jit/suggest.py`, `src/iam_jit/narrow.py`, `src/iam_jit/review.py`, `src/iam_jit/aws_managed_catalog.py` — none import from the deleted `policy_gen` package and none reference the deleted symbols. The two-import-site claim from WB15 (`aws_managed_catalog` only imported by `mcp_server.py`) still holds.

15. **Test deletions accurately reflect deleted code.** Verified each renamed / deleted test corresponds to a deleted-code path:
    - `test_mcp_server.py::test_tools_call_generate_iam_policy_round_trips` → renamed to `test_tools_call_generate_iam_policy_returns_tombstone` — semantics flip (now asserts `policy is None` + `deprecation` present).
    - `test_mcp_server.py::test_refinement_args_round_trip_correctly` → renamed to `test_refinement_args_ignored_by_tombstone` — semantics flip (now asserts the args don't influence the tombstone output).
    - `test_mcp_template_tools.py::test_generate_iam_policy_emits_deprecation_block` → renamed to `test_generate_iam_policy_is_tombstone_returns_null_policy` — semantics tightened (now asserts `policy is None`, not just "deprecation block present").
    - `test_mcp_template_tools.py::test_generate_iam_policy_empty_task_error_also_has_deprecation` → renamed to `test_generate_iam_policy_tombstone_response_is_consistent` — semantics generalized to "all input shapes produce the same tombstone."
    - `test_mcp_read_only_default.py` → rewritten end-to-end to test `submit_policy` (the surviving convention site) instead of the tombstoned `generate_iam_policy`.

16. **MCP dispatch surface unchanged.** All 5 tools dispatch correctly: `generate_iam_policy` → tombstone; `score_iam_policy` → scorer; `list_templates` → catalog (12 entries); `get_template` → policy fetch; `submit_policy` → would-submit envelope (no env vars set in probe). Unknown tool → `-32601` error. Unknown method → `-32601` error. Notifications → `None`. Whole flow exercised end-to-end via stdio probes.

## Pre-existing artifacts (NOT findings)

- **`tests/test_appsec_audit_round2_bb.py::test_bb2_20`, `test_bb2_21` fail under `pytest tests/test_appsec_audit_round2_bb.py`** (full-file run) because of a magic-link `dev_link` JSON key absent on second invocation. Verified against the Stage-2 baseline `e48be63` — the same two tests fail in the same way pre-Stage-3. Both PASS in the full broader-suite run (test-ordering effect from a process-global magic-link single-use store) and PASS in isolation. Pre-existing; orthogonal to Stage 3. Documented here so future audits don't re-attribute to deletion.

## Tests passed (regression check)

- Targeted MCP+catalog suite (`tests/test_mcp_*.py tests/test_aws_managed_catalog.py`): **90 passed in 0.19s** (matches commit-message claim).
- Broader suite (`pytest --ignore=tests/e2e --ignore=tests/test_calibration_corpus.py`): **2026 passed, 4 skipped, 26 deselected, 2 warnings in 91.85s** (matches commit-message claim).
- Same warning set as Stage 1/2 (HS256 short-key + Starlette per-request cookies deprecation). Zero new failures.

## Stage-3-close carry-forward checklist

These are the four LOWs above plus housekeeping items that should land before iam-jit 0.4.0 ships externally.

- [ ] **LOW-16-01**: Rewrite `mcp_server.py` module docstring to describe the four-tool surface + tombstoned `generate_iam_policy`. Reference `[[no-nl-synthesis]]` Stage 3 + the 1.8% sufficiency measurement. (~30 LOC docstring rewrite.)
- [ ] **LOW-16-02**: Rewrite `cli.py::mcp_server_cmd` docstring (the `iam-jit mcp-server --help` output) to drop the `generate_iam_policy` advertisement and describe the four-tool surface. (~10 LOC.)
- [ ] **LOW-16-03**: Decide schema-honesty fix for the tombstoned tool's per-property descriptions. Recommend prefixing each with `"(IGNORED in tombstone) "` (option b in the finding) — preserves cached-shape back-compat while honestly labeling dead inputs. (~10 LOC string edits.)
- [ ] **LOW-16-04**: Delete the orphan `src/iam_jit/policy_gen/__pycache__/` directories from the working copy (working-tree only; not in git). Consider adding `src/iam_jit/policy_gen/` to `.gitignore` defensively in case anything re-creates the path. (~1 minute.)

## Audit-completeness note (per [[audit-cadence-discipline]])

Stage 3 was the biggest deletion in the deprecation (-3951 LOC, 35 files). The audit specifically looked for the big-deletion failure mode — dangling references — across:
1. Production source (`src/iam_jit/`) → zero live references to deleted symbols.
2. Test source (`tests/`) → only docstrings, comments, and intentional skip messages reference deleted code.
3. MCP wire surface (initialize / tools/list / tools/call) → all five tools dispatch correctly; tombstone is hermetic.
4. CLI surface (`agent-grant`, `mcp-server`) → tombstone exits non-zero; surviving subcommands intact.
5. Python import surface → all `from .policy_gen` imports gone; only the namespace-package gotcha (LOW-16-04) remains, and it's inert.
6. Stale-bytecode loadability → confirmed `.pyc` orphans do NOT load (namespace-package resolution preempts them).
7. Test count delta → matches deleted-test count exactly (-104 from broader suite); 4 closure-by-deletion skips accounted for.
8. Tombstone behavior → static return, ~0.38µs/call, no input crashes, no echo of inputs in error string, no env-var leakage.

The four findings above are all post-deletion cleanup; none are deletion-induced functional bugs. Big-deletion audit pattern continues paying for itself per `[[audit-cadence-discipline]]`.
