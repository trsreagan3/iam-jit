# Round 18 audit — preset library pre-launch slice

Commit under review: `b2e748b` (`feat(preset library): personal-tier templates + similarity matcher (#150)`).

Scope: pre-launch slice of [[evolving-preset-library]] — the personal-tier templates. Adds `src/iam_jit/user_templates_store.py` (293 LOC: `UserTemplate` dataclass, `UserTemplateStore` Protocol, `InMemoryUserTemplateStore`, `compute_shape_hash`, `action_overlap_similarity`, `find_similar`, `find_by_shape_hash`, module-level singleton + reset helper), three new MCP tools in `src/iam_jit/mcp_server.py` (`save_template`, `list_my_templates`, `find_similar_templates`) with `_handle_request` dispatch wiring, and `tests/test_user_templates.py` (408 LOC, 32 tests). Net +933 LOC across 3 files. White-box review of the per-user isolation invariant, input validation, shape-hash determinism, and `action_overlap_similarity` edge cases. Black-box probes via direct dispatch + `tools/list` + the structured-content path on `_handle_request`.

## Headline

8 findings: **0 CRIT, 1 HIGH, 2 MED, 5 LOW/INFO.** Per-user isolation **holds at every MCP entry point shipped in this slice** — the bob-can't-see-alice probe passes via dispatch, `list_for_user`, `get_by_name`, and `find_similar`. The single HIGH is the latent footgun the audit prompt explicitly flagged for verification: `UserTemplateStore.get(template_id)` returns any user's template by id regardless of requester, with no `user_id` argument in the signature. No current MCP tool calls it (verified — only `store.put()` and `store.list_for_user()` are wired in), so the bug is **not exploitable today**, but the very next post-launch tool (`get_my_template(template_id)` / `delete_template(template_id)` / org-tier promote) that calls `store.get(id)` will cross-user-leak by default. Calling this HIGH-18-01 not CRIT solely because there is no live exploit path in this commit — but it WILL become CRIT the moment a caller is added without the cross-cutting `assert returned.user_id == requesting_user_id` guard.

The two MEDs are: (a) MED-18-02 — `action_overlap_similarity` silently returns 0 for the AWS-permitted single-dict `Statement` form, while `compute_shape_hash` correctly normalizes it; semantically-identical policies (one saved as `{"Statement": {...}}`, one queried as `{"Statement": [{...}]}`) fail to surface as matches in `find_similar_templates`; and (b) MED-18-03 — `save_template`'s and `list_my_templates`'s tool descriptions advertise `list_templates(source='personal-recurring') + get_template` as the read path for personal templates, but neither tool actually serves personal-tier templates — `get_template` is AWS-managed-catalog-only and returns `{"error":"template not found"}`, and `list_templates(source='personal-recurring')` returns `{"templates":[],"total":0}`. There is no MCP tool to retrieve a personal template's policy body — agents that follow the documented contract get nothing back.

Input validation matches the WB14-MED-14-* pattern exactly (bool-not-int order-of-check, `isinstance(str)` guards, `isinstance(dict)` guards, structured `{"error": ..., "<result_key>": <empty>}` returns). Found no validation regressions vs the rigor of `submit_policy` / `list_templates`.

Regression suite is **green at the commit-message-claimed numbers: 1929 passed, 29 skipped, 14 deselected** (was 1897 + 29 + 14 before #150; +32 new tests, math checks). The 32 new tests in `tests/test_user_templates.py` all pass; the 122-test focused MCP+catalog+user-template suite passes.

This is the first audit-round in the WB14-onward sequence where **#1 audit-prompt suspicion turned out to be a real (latent) bug**, vindicating [[audit-cadence-discipline]] once again. The HIGH does NOT block launch by itself (no live path), but it MUST be closed before the next MCP tool that touches `store.get(id)` ships — that work is task #151+ of the preset-library expansion.

## Closure status

| Finding | Status |
|---|---|
| HIGH-18-01 `UserTemplateStore.get(template_id)` has no user_id arg → latent cross-user-leak for any future caller | ⏳ OPEN |
| MED-18-02 `action_overlap_similarity` silently returns 0 for single-dict `Statement` form (asymmetric with `compute_shape_hash`) | ⏳ OPEN |
| MED-18-03 `save_template` + `list_my_templates` tool descriptions point at `list_templates(source='personal-recurring') + get_template` — neither tool surfaces personal-tier templates | ⏳ OPEN |
| LOW-18-04 In-memory store keeps caller's `policy` dict by reference (no defensive copy) — caller mutation after save silently mutates the saved template | ⏳ OPEN |
| LOW-18-05 No quotas — per-user template count + per-template policy size + name + description all unbounded | ⏳ OPEN |
| LOW-18-06 `_current_user_id` accepts whitespace-only `IAM_JIT_USER_ID`; falls back to `USER` then `"local"` without `.strip()` | ⏳ OPEN |
| LOW-18-07 `find_by_shape_hash` shipped but no MCP tool exposes it — dead code | ⏳ OPEN |
| INFO-18-08 `IAM_JIT_USER_ID` is undocumented outside the source; per-user isolation invariant depends on a setup convention nothing enforces | ⏳ OPEN |

## CRIT findings

None.

## HIGH findings

### HIGH-18-01 — `UserTemplateStore.get(template_id)` returns any user's template regardless of who's asking; latent cross-user-leak for any future caller

- File: `src/iam_jit/user_templates_store.py:65` (Protocol declaration), `:203-206` (InMemory impl)
- Issue: The `UserTemplateStore` Protocol's `get(template_id)` method takes ONLY a `template_id`, with no `user_id` argument. `InMemoryUserTemplateStore.get` returns any matching item from `self._items` regardless of the requesting user. Sibling methods are correctly scoped — `get_by_name(user_id, name)`, `list_for_user(user_id)`, the helper `find_similar(store, user_id, ...)` — but `get(template_id)` is the lone outlier. The audit prompt called this out for verification under "CHECK: get(template_id) returns any user's template — does the MCP handler validate that the requesting user owns it? Or is this a cross-user leak?"
- Repro (white-box, confirmed):
  ```python
  from iam_jit.user_templates_store import InMemoryUserTemplateStore, UserTemplate
  s = InMemoryUserTemplateStore()
  s.put(UserTemplate(template_id='tmpl_alice', user_id='alice', name='secret',
                     policy={'Version':'2012-10-17',
                             'Statement':[{'Effect':'Allow','Action':'s3:*','Resource':'*'}]},
                     created_at=0))
  # Any caller can fetch alice's template by id, including full policy body:
  out = s.get('tmpl_alice')
  # → UserTemplate(user_id='alice', name='secret', policy={'Statement':[{'Action':'s3:*'...}]}, ...)
  ```
- Why this is HIGH not CRIT:
  - **No current MCP tool calls `store.get(id)`** — verified by grep across `src/`: the only `store.` method calls in `mcp_server.py` are `store.put()` (line 598) and `store.list_for_user()` (line 615). `find_similar()` internally calls `list_for_user(user_id)`, which IS correctly scoped. So today, an MCP-attached agent CANNOT exercise the bug via any shipped surface.
  - However, the bug is the EXACT shape future tools will trip over. The slice's own commit message lists post-launch follow-ups including "Org-tier templates (admin-promote UI)" and "Stale-template detection" — both fundamentally need to fetch a single template by id, and the obvious implementation is `store.get(id)`. The signature itself invites the bug; a `get_my_template` MCP tool added next sprint would, written with no special care, look like:
    ```python
    def _get_my_template_for_mcp(args):
        t = get_default_store().get(args["template_id"])
        return {"template_id": t.template_id, "name": t.name, "policy": t.policy, ...}
    ```
    and would cross-user-leak with no warning.
  - The MCP tool `find_similar_templates` returns `template_id` as part of every match (mcp_server.py:657). Once an agent has a `template_id`, the natural next step is to fetch its body — there is no current tool for that, but the very fact that the matcher hands out ids invites the future request.
- Impact: Latent, not live. If exploited by a future caller, the impact would be CRIT: cross-user disclosure of saved policy bodies (which can themselves contain sensitive identifiers like specific resource ARNs, account ids in conditions, or PII in `source_description`).
- Fix (in severity order, recommend (a) or (b) before any new tool ships):
  - **(a) [recommended]** Add `user_id` as a required argument to `UserTemplateStore.get` and `InMemoryUserTemplateStore.get`; raise `UserTemplateNotFound` if `item.user_id != user_id`. Same signature as `get_by_name`. ~5 LOC. Forces every future caller to thread the user id. Update the Protocol declaration so static type-checkers also flag the gap.
  - **(b)** Rename the current method to `get_unsafe` / `_get_raw` (visibly NOT-user-scoped) and add a new `get(user_id, template_id)` as the public form. Mechanical refactor; same end state.
  - **(c)** Add a `get_for_user(user_id, template_id)` companion method and leave `get` as-is but flag with a `# WARNING: not user-scoped` comment + a TODO to make it private. Weakest fix — the footgun remains.
- Pin the fix with a test: `tests/test_user_templates.py` should add a `test_store_get_requires_user_id_and_rejects_cross_user` test that asserts `store.get('alice-tid', user_id='bob')` raises `UserTemplateNotFound`. This pins the contract for all future implementations of the Protocol (post-launch DDB / SQLite stores).

## MED findings

### MED-18-02 — `action_overlap_similarity` silently returns 0 for single-dict `Statement` form; asymmetric with `compute_shape_hash`

- File: `src/iam_jit/user_templates_store.py:159-174` (`_extract_actions`)
- Issue: AWS IAM accepts BOTH `{"Statement": {...one stmt...}}` (single dict) AND `{"Statement": [{...}]}` (list) — they're semantically identical. `_canonicalize_shape` (lines 101-106) correctly normalizes the single-dict form into a list before processing:
  ```python
  stmts = policy.get("Statement") or []
  if isinstance(stmts, dict):
      stmts = [stmts]
  ```
  But `_extract_actions` (used by `action_overlap_similarity`) does NOT have the same normalization (line 164):
  ```python
  for s in policy.get("Statement") or []:
      if not isinstance(s, dict):
          continue
      ...
  ```
  When `Statement` is a single dict, `for s in <dict>` iterates over its KEYS (strings like `"Effect"`, `"Action"`, `"Resource"`), the `isinstance(s, dict)` guard correctly filters them out, and `_extract_actions` returns the empty set. No crash — but silently-wrong behavior.
- Repro:
  ```python
  from iam_jit.user_templates_store import compute_shape_hash, action_overlap_similarity
  p_dict = {'Version':'2012-10-17',
            'Statement':{'Effect':'Allow','Action':'s3:GetObject','Resource':'*'}}
  p_list = {'Version':'2012-10-17',
            'Statement':[{'Effect':'Allow','Action':'s3:GetObject','Resource':'*'}]}
  compute_shape_hash(p_dict) == compute_shape_hash(p_list)       # → True (correct)
  action_overlap_similarity(p_dict, p_list)                       # → 0.0 (WRONG: should be 1.0)
  ```
  Via the MCP tools:
  ```python
  _save_template_for_mcp({'name': 'single', 'policy': p_dict})   # saves OK
  _find_similar_templates_for_mcp({'policy': p_list, 'min_similarity': 0.0})
  # → matches contains the template with similarity=0.0 (returned only because threshold is 0;
  #   at default min_similarity=0.3 the match would be filtered out entirely)
  ```
- Why this is MED not LOW:
  - This is exactly the "I saved a template last week; now I'm authoring an equivalent policy and find_similar can't see it" failure mode. The feature exists to surface those matches. When agents produce policies, they tend to use the list form (it's what list_templates returns); when humans hand-write policies in the AWS console or older IaC, they often use the single-dict form. Cross-form silent miss-rate undermines the value prop.
  - The asymmetry with `compute_shape_hash` is the smoking gun — someone obviously knew about the single-dict form (the canon normalizer handles it) but didn't carry the normalization into the action extractor. This is an oversight, not a design choice.
- Impact: silent under-recall in `find_similar_templates`. Templates saved in single-dict form never surface as matches for list-form queries (and vice-versa). The user just sees "no matches" and re-authors a template they already have — the very anti-pattern the library exists to prevent. Compounds over time as the library grows mixed-form.
- Fix: ~3 LOC at the top of `_extract_actions`:
  ```python
  stmts = policy.get("Statement") or []
  if isinstance(stmts, dict):
      stmts = [stmts]
  for s in stmts:
      ...
  ```
  Add tests `test_extract_actions_single_dict_statement` + `test_action_overlap_similarity_dict_vs_list_form_match` to pin the fix.

### MED-18-03 — `save_template` + `list_my_templates` tool descriptions advertise `list_templates(source='personal-recurring') + get_template` as the read path for personal templates; neither tool surfaces them

- File: `src/iam_jit/mcp_server.py:250` (save_template description), `:297` (list_my_templates description)
- Issue: The two new tool descriptions point agents at MCP tools that don't actually serve personal-tier templates:
  - `save_template` description: "save it so next time the same access is needed you can `list_templates(source='personal-recurring') + get_template` instead of re-authoring."
  - `list_my_templates` description: "Returns metadata only (no policy bodies — use `get_template` for the full shape)."

  But:
  - `list_templates(source='personal-recurring')` returns `{"templates": [], "total": 0, "truncated": False}` (verified — the catalog source flag for personal-recurring is a planned-not-shipped value; the catalog branch silently empties).
  - `get_template(name='my-personal')` returns `{"error": "template not found: my-personal", "policy": None}` — `_get_template_for_mcp` only consults `aws_managed_catalog`, not the user template store.

  There is **no MCP tool to retrieve a personal template's policy body**. The matcher (`find_similar_templates`) returns `template_id` + `name` + `similarity` but NOT the policy itself; the lister (`list_my_templates`) returns metadata only; and the (incorrectly-advertised) `get_template` doesn't know about personal templates.
- Repro: see audit-run probe — `get_template my-personal` → `{"error": "template not found"}`, `list_templates source=personal-recurring` → `{"templates":[]}`.
- Why this is MED not LOW:
  - The agent contract is broken by misdirection, not silence. An agent that reads the docstring and follows the documented path gets nothing back and has to guess. The MCP `description` field IS the contract for tool selection — Claude / Cursor / Devin agents pick tools based on description match.
  - Cross-product with HIGH-18-01: even if an agent figured out it needs to fetch by id directly, no shipped tool does that (which is the only reason HIGH-18-01 hasn't bitten us yet). So the personal-tier library is currently *write-only with metadata-list* — the most useful operation (read body of saved template) is unreachable through MCP.
- Impact: documented agent workflow ("save once, reuse later") is broken end-to-end. The user CAN save and list, but they can't actually retrieve the policy body the next time, which means they have to either remember the policy themselves or re-author it — defeating the feature's purpose.
- Fix (depends on intended product shape):
  - **(a) [recommended]** Add a `get_my_template(name)` MCP tool that returns the full policy body — pair the fix with HIGH-18-01 (use `store.get_by_name(user_id, name)` which is already user-scoped). Update both descriptions to reference `get_my_template` instead of `get_template`. ~50 LOC + 2 tests.
  - **(b)** Extend `_get_template_for_mcp` to consult the user-template store first, then fall through to the catalog. Riskier — mixes two namespaces (catalog template names vs user template names) and creates a back-door for HIGH-18-01 (catalog template names are global, user templates are per-user). Not recommended.
  - **(c)** Extend `list_my_templates` to optionally include policy bodies (e.g. `include_bodies: bool`). Functional but conflates list + fetch; loses cacheability.
  - For ALL three: also fix `list_templates`'s `source='personal-recurring'` branch — either route it to the user template store (making it the read path) or remove the published-schema value to stop advertising a dead source.

## LOW / INFO findings

### LOW-18-04 — In-memory store keeps caller's `policy` dict by reference; caller mutation after save silently mutates the saved template

- File: `src/iam_jit/mcp_server.py:587-596` (UserTemplate construction), `src/iam_jit/user_templates_store.py:189-201` (`InMemoryUserTemplateStore.put`)
- Issue: The `UserTemplate` dataclass is declared `frozen=True` (line 31), which gives a false sense of immutability — `frozen` blocks reassignment of fields but does not deep-copy field VALUES. The `policy: dict[str, Any]` field is a mutable container held by reference. `_save_template_for_mcp` passes `policy=policy` directly from `args.get("policy")` (line 591), and `store.put` stores the dataclass without deep-copying.
- Repro:
  ```python
  p = {'Version':'2012-10-17',
       'Statement':[{'Effect':'Allow','Action':'s3:GetObject','Resource':'*'}]}
  _save_template_for_mcp({'name': 'mytmpl', 'policy': p})
  p['Statement'][0]['Action'] = 's3:DeleteBucket'   # caller mutates
  get_default_store().list_for_user('alice')[0].policy
  # → {'Statement': [{'Action': 's3:DeleteBucket'...}]}  (mutation leaked into store)
  ```
- Why LOW:
  - In MCP-stdio mode (the only deployment shape pre-launch), `args` is freshly parsed from JSON on every request, so there's no live caller holding a reference to mutate.
  - In tests + any future in-process integration (FastAPI route wrapper, agent-grant-style internal call), the mutation IS reachable.
  - `find_similar` also returns the same template object, not a copy — same mutation risk on the read side.
- Impact: silent mutation bug in any future in-process caller path. Compounds with HIGH-18-01 in that BOTH sides of the policy-body lifecycle (read + write) currently lack defensive copies.
- Fix: deep-copy on `put` (and ideally on read, though one side is enough to break the reference chain). `import copy; record = dataclasses.replace(record, policy=copy.deepcopy(record.policy))` at the top of `InMemoryUserTemplateStore.put`. ~2 LOC. Add a `test_store_isolates_caller_mutation_after_save` test.

### LOW-18-05 — No quotas: per-user template count, per-template policy size, name length, description length all unbounded

- File: `src/iam_jit/mcp_server.py:_save_template_for_mcp` (no size checks)
- Issue: There is no upper bound on:
  - Number of templates per user (probed: 2000 templates saved for 'alice' in <1s; lives in process memory)
  - Policy body size (probed: 10000-action policy saved without complaint)
  - Template name length (probed: 100000-char name saved; would explode any UI listing)
  - Description length (no cap)
  - Control / non-printable characters in description (probed: `\x00` accepted)
- Why LOW for pre-launch:
  - InMemory store is bounded by laptop RAM (~10000s of templates is fine; storage cost is the policy dict + overhead, ~1-2KB each).
  - No multi-tenant adversary path — single-user-per-process MCP stdio means the user is exhausting their own RAM.
  - Self-host SQLite (post-launch) IS bounded by disk + sqlite row-size limits, but at that point the same blast-radius logic applies.
- Impact: localized DoS surface only; no security implication. Note for post-launch DDB store where DDB item-size limit (400KB) IS load-bearing and ought to be enforced before the put.
- Fix: defer for pre-launch; add when SQLite/DDB ships. When added: per-user max ~1000 templates (configurable env), per-template policy JSON ≤ ~64KB, name ≤ 100 chars, description ≤ 1000 chars, strip control chars from description. ~20 LOC + 4 tests.

### LOW-18-06 — `_current_user_id` accepts whitespace-only `IAM_JIT_USER_ID`; no `.strip()` applied

- File: `src/iam_jit/mcp_server.py:543-557`
- Issue:
  ```python
  return (
      os.environ.get("IAM_JIT_USER_ID")
      or os.environ.get("USER")
      or "local"
  )
  ```
  `"   "` (whitespace-only) is truthy in Python, so it bypasses the `or` fallback chain and becomes the user_id. Repro:
  ```python
  os.environ['IAM_JIT_USER_ID'] = '   '
  _current_user_id()  # → '   '
  ```
  Two users with `"   "` and `" "` would see DIFFERENT libraries (different namespace strings). Two users who both forgot to set `IAM_JIT_USER_ID` would share the `USER` namespace (or `"local"`) — meaning one human-user could leak templates to another local-account-user on the same host.
- Why LOW:
  - In MCP-stdio mode the env is operator-controlled; the operator is responsible for setting it consistently.
  - No security boundary today — local mode is "trust the binary + trust the env" by design (per [[local-only-safety-mode]]).
- Impact: cosmetic UX confusion only. Worth fixing as `(os.environ.get("IAM_JIT_USER_ID") or "").strip() or (os.environ.get("USER") or "").strip() or "local"` to make the fallback chain robust. ~3 LOC.
- Fix: also wire the doc note in LOW-18-08.

### LOW-18-07 — `find_by_shape_hash` shipped but no MCP tool exposes it; dead code

- File: `src/iam_jit/user_templates_store.py:285-293`
- Issue: `find_by_shape_hash(store, user_id, policy)` is implemented + correctly user-scoped (no HIGH-18-01 footgun) + iterates `list_for_user`. Zero callers anywhere in `src/` or `tests/`. The matching exact-shape MCP tool (`find_exact_match`? `is_already_saved`?) is not in this slice.
- Why LOW:
  - Not a bug; it's intentional preparation for a tool that's "save-if-not-already-saved" or "detect-duplicate-before-save". Per the commit message, that workflow is post-launch ("Auto-suggest 'save as recurring template after N reuses'" — needs reuse tracking from `submit_policy`).
  - Worth flagging in this audit only so the next slice doesn't forget it exists.
- Impact: ~10 LOC of unreferenced code; no runtime impact.
- Fix: either ship the calling MCP tool in the next preset-library slice or add a `# UNUSED: exposed via TODO MCP tool in #151` comment. Or delete and re-add when needed (YAGNI). No urgency.

### INFO-18-08 — `IAM_JIT_USER_ID` is undocumented outside the source

- File: only reference is `src/iam_jit/mcp_server.py:554`
- Issue: The per-user-isolation invariant (the load-bearing security property of the personal library) depends entirely on each MCP-stdio process having `IAM_JIT_USER_ID` set to a unique-per-user value. There is no doc page that mentions this requirement. The fallback to `USER` then `"local"` means an operator that doesn't know about the env var gets shared-namespace behavior with no warning — and on a multi-user laptop (rare but exists), this could cross-leak.
- Why INFO:
  - Pre-launch local-only-mode design assumes single-user-per-laptop ([[local-only-safety-mode]]).
  - The current MCP host model (Claude Code / Cursor) runs per-user processes, so in practice this is fine.
- Fix: add to `docs/AGENTS.md` (or wherever the MCP-stdio config is documented) a one-paragraph note: "If you run iam-jit MCP server in a shared / multi-user environment, set `IAM_JIT_USER_ID` per process so the personal template library is isolated correctly. The default fallback uses `USER`, which works for single-user laptops." 1 paragraph + 1 link.

## What's solid (positive findings)

1. **Per-user isolation holds at every shipped MCP entry point.** The cross-user dispatch probe (`IAM_JIT_USER_ID=alice` save → `IAM_JIT_USER_ID=bob` list / find_similar) returns empty / no-match. The store's `list_for_user`, `get_by_name`, and `find_similar` are all correctly scoped. Only `get(template_id)` is the latent outlier (HIGH-18-01).

2. **Input validation matches WB14-MED-14-* pattern exactly.** Verified probes:
   - `save_template`: `name` rejected for non-str / empty / whitespace / None ✓; `policy` rejected for non-dict / list / None ✓; `description` rejected for non-str ✓; `source_grant_id` rejected for non-str ✓; name auto-`.strip()` applied before save ✓; dup detection works after strip ✓.
   - `find_similar_templates`: `top_k` rejected for `True` / `False` / `0` / `-1` / `"5"` / `5.0` / `5.5` / `999` ✓ (bool-not-int checked first, exactly per LOW-14-08 pattern); `min_similarity` rejected for `True` / `False` / `2.0` / `-0.1` / `1.1` ✓; boundary `0.0` and `1.0` accepted ✓.
   - All error returns have the `{"error": "...", "<result_key>": <empty>}` structured shape — no string-only errors that an agent has to regex-parse.

3. **Shape-hash determinism holds across all probed inputs.** Same actions different order → same hash ✓. Statement order in 2-statement policy → invariant ✓. Same actions different Resource → different hash ✓ (resources ARE in the canon, as docstring claims). Wildcards `s3:*` vs `s3:Get*` correctly distinct ✓. `Statement` single-dict vs list → same hash ✓. Empty / missing `Statement` / empty policy → all same hash ✓ (expected — all "empty" policies legitimately collapse to one shape).

4. **`action_overlap_similarity` edge cases (other than MED-18-02):**
   - Identical actions → 1.0 ✓
   - Disjoint actions → 0.0 ✓
   - Partial overlap → exact Jaccard fraction ✓
   - Deny statements correctly ignored ✓ (only Allow actions count)
   - Single-string `Action` value handled correctly ✓
   - Empty action list → 0.0 vs non-empty ✓
   - Both empty → 1.0 ✓ (sentinel-correct)
   - `None` policy → 0.0 vs policy ✓ (no crash)
   - Both `None` → 1.0 ✓ (sentinel-correct, matches empty-both behavior)
   - **Failing case (MED-18-02):** single-dict `Statement` form silently returns 0 actions.

5. **find_similar performance is fine for personal-tier:** 1000 templates × 1 query → 0.84ms. O(N) over `list_for_user` results, well within human-interactive budget for N up to ~10K. The audit-prompt's "fine for personal-tier (typical N < 100); note for post-launch when org-tier ships and N could be 1000s" reads correct — even at N=1000 it's sub-ms.

6. **Tool discovery is correct:**
   - `tools/list` returns 8 tools total (5 pre-existing + 3 new). All three new tools present with correct names + descriptions + inputSchema ✓.
   - `save_template`: required `["name", "policy"]`; properties `["name", "policy", "description", "source_grant_id"]` ✓.
   - `list_my_templates`: required `[]`; properties `[]` ✓.
   - `find_similar_templates`: required `["policy"]`; properties `["policy", "top_k", "min_similarity"]` ✓.
   - Schema declares `top_k: integer default 5` and `min_similarity: number default 0.3` ✓ (matches the validator).
   - Important caveat: the descriptions for `save_template` and `list_my_templates` point at the wrong follow-up tools (MED-18-03), but the SHAPES of the schemas are correct.

7. **End-to-end dispatch via `tools/call` works:**
   - `save_template` → `result.structuredContent.template_id` starts with `tmpl_` ✓
   - `list_my_templates` → `result.structuredContent.total >= 1` ✓
   - `find_similar_templates` → `result.structuredContent.total >= 1` with `similarity == 1.0` for identical policy ✓
   - Both `content[0].text` (JSON string) AND `structuredContent` (dict) are populated in the response ✓.

8. **No regression in broader suite:** 1929 passed + 29 skipped + 14 deselected = exactly +32 net new passes vs WB17's 1897 + 29 + 14, matching commit-message claim. The 32 new tests in `tests/test_user_templates.py` all pass.

9. **122 focused MCP+catalog+user-template tests pass** (`pytest tests/test_mcp_*.py tests/test_aws_managed_catalog.py tests/test_user_templates.py`) — exactly matches the commit-message "122 MCP+catalog+user-template tests pass total."

10. **Module-level singleton + `reset_default_store_for_tests()` pattern matches the precedent of other singleton stores** (`bans.get_default_store()`, `cidr_store.get_default_store()`, `settings_store.get_default_store()`, etc.). Test fixture (`tests/test_user_templates.py:33-38`) is correctly `autouse=True` and resets both pre and post yield. No fixture-leak risk.

11. **Per-user name uniqueness correctly enforced ONLY within a user namespace.** Verified: `alice` can save `'read-prod'` and `bob` can also save `'read-prod'` with no collision (each gets its own `template_id`). Same-user duplicate (even after `.strip()`) is rejected with `UserTemplateNameTaken`. Sweet spot.

12. **`reset_default_store_for_tests()` is correctly module-singleton-aware** — sets `_default_store = None`, next call to `get_default_store()` constructs a fresh instance. Verified via test-isolation behavior.

13. **`MCP_PROTOCOL_VERSION` + `SERVER_VERSION` unchanged from WB17** — this slice was a feature add, not a protocol bump. Correct decision; the new tools are discoverable via `tools/list` regardless of cached protocol version.

14. **`UserTemplate` is `frozen=True`** — gives surface immutability (caller can't reassign `record.user_id = 'attacker'`). The `policy` field is mutable-by-reference (LOW-18-04), but the `user_id` / `template_id` / `name` / `created_at` fields are field-frozen, so they can't be tampered with post-construction.

15. **No `dangerous_*` / `eval` / `exec` / pickled-state / yaml.load / SQL-injection-shaped surfaces** in the new code. The only persistence is the in-memory dict; no parser is invoked beyond `json.dumps` for the canonical hash; no subprocess; no file I/O.

## Tests passed (regression check)

- Broader suite (`pytest tests/ -q --ignore=tests/e2e --ignore=tests/test_calibration_corpus.py`): **1929 passed, 29 skipped, 14 deselected, 2 warnings in 89.94s** — matches commit-message-implied count exactly (+32 vs WB17's 1897).
- Focused MCP+catalog+user-template suite (`pytest tests/test_mcp_*.py tests/test_aws_managed_catalog.py tests/test_user_templates.py`): **122 passed in 0.26s** — matches commit-message claim exactly.
- `tests/test_user_templates.py` standalone: **32 passed in 0.03s**.

The 29 skipped + 14 deselected counts are unchanged from WB17 (Stage 4 deprecation closure markers + the long-standing pre-existing deselect set). No skip/deselect drift.

Same warning set as WB17 (HS256 short-key in `tests/test_oidc.py` + Starlette per-request cookies deprecation in `test_routes_oidc.py`). Pre-existing; not made worse by #150.

## Audit-completeness note (per [[audit-cadence-discipline]])

Round 18 audit checked:

1. **Per-user isolation via every public surface** — `store.get(id)` is the latent footgun (HIGH-18-01); `list_for_user` / `get_by_name` / `find_similar` are all correctly scoped ✓; MCP dispatch enforces it via `_current_user_id` ✓.
2. **Input validation rigor matches WB14-MED-14-* pattern** — verified `bool-not-int` order-of-check, `isinstance(dict)` guards, `isinstance(str)` guards, structured error returns ✓.
3. **Shape-hash determinism** — same-actions-different-order, same-actions-different-resource, statement-reorder, empty / missing Statement, wildcard distinction — all probed ✓.
4. **`action_overlap_similarity` edge cases** — identical / disjoint / partial / deny-ignored / single-string action / empty action / both-empty / None policies — all probed; one bug found (MED-18-02).
5. **find_similar performance** — N=1000 in <1ms ✓; comfortable margin for personal-tier and well beyond.
6. **Tool discovery** — all 3 new tools in `tools/list` with correct descriptions + schemas (caveat: docs point at wrong follow-up tools — MED-18-03).
7. **End-to-end dispatch** — `tools/call` for all 3 new tools returns correctly-shaped `result.structuredContent` ✓.
8. **Cross-user leak via dispatch** — `IAM_JIT_USER_ID=alice` save → `IAM_JIT_USER_ID=bob` list / find_similar → empty ✓.
9. **bool/int validation** — `top_k=True` / `False`, `min_similarity=True` / `False` all rejected with structured errors ✓.
10. **Mutation / aliasing** — caller-side `policy` dict mutation after save leaks into stored template (LOW-18-04); flagged for in-process callers.
11. **Quota / size** — no caps; flagged LOW for pre-launch InMemory, MUST-fix when SQLite / DDB ships (LOW-18-05).
12. **`_current_user_id` fallback chain** — whitespace-only IAM_JIT_USER_ID bypasses fallback (LOW-18-06); `IAM_JIT_USER_ID` undocumented (INFO-18-08).
13. **Dead-code inventory** — `find_by_shape_hash` shipped without caller (LOW-18-07).
14. **Test-isolation fixture** — `_reset_store` autouse correctly resets before and after each test ✓.

The discipline from rounds 10 / 12 / 13 / 14 / 15 / 16 / 17 continues to pay for itself: the audit-prompt's #1 suspicion (HIGH-18-01) was real, the unit-test suite missed it (32 tests passed but none probed cross-user `store.get(id)` leakage because no caller exercises that surface), and three additional findings (MED-18-02, MED-18-03, LOW-18-04) emerged from the cross-cutting probes that the test suite doesn't have a regression-net for.

A clean audit was the expected outcome — but the audit prompt explicitly asked to verify the per-user isolation concern, and that verification surfaced a real latent bug. Per the audit-cadence rubric ("3 CRITs caught across rounds 10/12/13 in code that passed unit + integration tests"), HIGH-18-01 is the round-18 entry in that pattern — found by white-box review, not by the test suite.

## Carry-forward checklist

In severity order. Items 1-3 must close before any post-launch preset-library slice that touches the read path.

- [ ] **HIGH-18-01**: add `user_id` argument to `UserTemplateStore.get` and `InMemoryUserTemplateStore.get`; raise `UserTemplateNotFound` if the requesting user doesn't own the template. Update Protocol declaration. Add pinned test asserting cross-user `get('alice-tid', user_id='bob')` raises. (~10 LOC + 1 test.)
- [ ] **MED-18-02**: add 3-line `isinstance(stmts, dict)` normalization to `_extract_actions` to mirror `_canonicalize_shape`. Add 2 tests: extract-actions-from-single-dict-statement + similarity-dict-vs-list-form-matches. (~5 LOC + 2 tests.)
- [ ] **MED-18-03**: add `get_my_template(name)` MCP tool that uses `store.get_by_name(user_id, name)` (already user-scoped — also dodges HIGH-18-01); update `save_template` + `list_my_templates` descriptions to reference the new tool; either remove `personal-recurring` from `list_templates`'s `source` enum OR route it to the user store. Pair with HIGH-18-01 fix for symmetry. (~60 LOC + 4 tests.)
- [ ] **LOW-18-04**: `copy.deepcopy(record.policy)` at the top of `InMemoryUserTemplateStore.put`; pin with test_store_isolates_caller_mutation_after_save. (~3 LOC + 1 test.)
- [ ] **LOW-18-06**: tighten `_current_user_id` fallback chain with `.strip()` on each candidate. (~3 LOC.)
- [ ] **INFO-18-08**: 1-paragraph doc in `docs/AGENTS.md` (or equivalent) noting `IAM_JIT_USER_ID` requirement for multi-user MCP-stdio deployments.

Defer to post-launch (when SQLite / DDB ships):

- [ ] **LOW-18-05**: per-user template-count quota + per-template policy-body size cap + name/description length caps. Configurable env vars. (~20 LOC + 4 tests.)
- [ ] **LOW-18-07**: decide whether `find_by_shape_hash` ships its companion MCP tool or gets deleted (YAGNI).

Net pre-launch fix budget for round-18 closure: ~80 LOC + 8 tests across 2 small commits.
