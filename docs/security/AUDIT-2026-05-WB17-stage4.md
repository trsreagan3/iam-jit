# Round 17 audit — Stage 4 of NL deprecation

Commit under review: `767b66b` (`deprecate(stage 4): delete suggest/narrow/intake + web NL routes`).

Scope: final-stage deletion of `src/iam_jit/suggest.py` (98 LOC), `narrow.py` (269 LOC), `intake.py` (535 LOC), `intake_drafts.py` (331 LOC), `routes/intake.py` (148 LOC), the chat / generate / chat-stream web routes from `routes/web.py` (~435 LOC), the `iam-jit suggest` + `refine` CLI subcommands (~75 LOC), templates `new_chat.html` + `new_describe.html`, 7 test files, and surgical skip-wraps to ~24 tests in 10 other test files. Net -5159 LOC across 36 files. Black-box probes against the FastAPI app via `starlette.testclient.TestClient` + direct CLI invocations. White-box review of imports, caller graph, web-router surface, and template / API-hint contract surfaces.

## Headline

7 findings: **2 CRIT, 1 HIGH, 0 MED, 4 LOW.** The big-deletion failure mode the audit was looking for (dangling callers + broken routes) *did* materialize, in three places that share a root cause: when the routes were removed, the **callers downstream of the routes** weren't audited. The `iam-jit remote chat` CLI subcommand POSTs to the deleted `/api/v1/intake/turn`; the `/requests/new` HTML chooser still 303s to deleted `/requests/new/chat`; and the `new_request.html` chooser template still links to deleted `/requests/new/generate`. Two of these are CRIT because they break primary user-facing surfaces (the AI-mode-default web flow, and a shipped CLI feature) with a 404 at first click; the third is HIGH because it's an agent-contract-stable JSON response (`/api/v1/users/me::agent_hints.submit_request_conversational`) that mis-directs every authenticated agent caller. The 4 LOWs are orphan helper code that should be swept in a follow-up.

This is a substantial set of findings for what was supposed to be the "last" deprecation stage, and they were all surfaced inside the read-only black-box pass — the test suite at HEAD does not exercise any of them (the `cli_remote` module has zero tests, and the `/me` agent-hints test asserts on the string contents of the broken hint rather than that the hint's path resolves).

The unit + integration test suite remains green at the commit-message-claimed numbers (**1897 passed, 29 skipped, 14 deselected**), and the suite of 90 MCP+catalog tests also passes (**90 passed**). All sampled skip-wrapped tests are accurately wrapped — i.e. each genuinely probed deleted code and would now fail meaningfully if un-skipped. The Stage 3 `agent-grant` tombstone still works (exits 2 with the deprecation message).

Stage 4 should not be declared "complete / NL deprecation done" until at minimum CRIT-17-01 + CRIT-17-02 + HIGH-17-03 are closed.

## Closure status

| Finding | Status |
|---|---|
| CRIT-17-01 `iam-jit remote chat` + `submit-from-chat` POST to deleted `/api/v1/intake/turn` | ⏳ OPEN |
| CRIT-17-02 `/requests/new` chooser 303s to deleted `/requests/new/chat` when AI enabled | ⏳ OPEN |
| HIGH-17-03 `GET /api/v1/users/me::agent_hints.submit_request_conversational.path` points to deleted `/api/v1/intake/turn` | ⏳ OPEN |
| LOW-17-04 `new_request.html` chooser card links to deleted `/requests/new/generate` | ⏳ OPEN |
| LOW-17-05 `tokens.html` page advertises `POST /api/v1/intake/turn` to authenticated callers | ⏳ OPEN |
| LOW-17-06 Orphan helpers in `routes/web.py` + `auth.py` (intake-state signers, `_enforce_rate_limit`, `_CHAT_PARSE_ERRORS_BEFORE_FALLBACK`, `augment_for_debug`) | ⏳ OPEN |
| LOW-17-07 `_safe_return_to` allowlist + test still includes `/requests/new/chat` | ⏳ OPEN |

## CRIT findings

### CRIT-17-01 — `iam-jit remote chat` and `iam-jit remote submit-from-chat` POST to deleted route → unconditional 404 against every Stage-4 server

- File: `src/iam_jit/cli_remote.py:140` (`chat`), `:236, :243` (`submit-from-chat`)
- CLI: `iam-jit remote chat <msg>`, `iam-jit remote submit-from-chat --conversation <path>`
- Issue: Stage 4 deleted `/api/v1/intake/turn` (the `intake_router` registration in `app.py` is gone and the file `routes/intake.py` is deleted). But `src/iam_jit/cli_remote.py` still has two live, click-registered CLI subcommands whose only network call is:
  ```python
  resp = c.post("/api/v1/intake/turn", json={"conversation": convo})
  ```
  These commands are registered via `cli.py:250` (`from .cli_remote import remote as _remote_group; main.add_command(_remote_group)`). They appear in `iam-jit remote --help`:
  ```
  Commands:
    ...
    chat              Send one user turn to the LLM intake; print the...
    submit-from-chat  Submit a request using the prefill the LLM produced.
    ...
  ```
- Repro (TestClient stand-in for any real deployment):
  ```
  POST /api/v1/intake/turn → 404 {"detail":"Not Found"}
  ```
  Verified via `from iam_jit.app import create_app; from starlette.testclient import TestClient; ...` — the route is genuinely gone.
- Why this is CRIT not HIGH:
  1. `iam-jit remote chat` is the **headline `remote` subcommand** — its docstring is the first thing operators read when integrating an iam-jit deployment from CI / agents (the module docstring at `cli_remote.py:1-22` literally opens with "chat through an intake to draft a policy"). It's not a hidden command; it ships as a live CLI surface.
  2. `submit-from-chat` is a documented downstream of `chat` (its `--help` says "Run `remote chat` until the response shows `complete: true`" — also broken).
  3. There are **zero tests** for `cli_remote` anywhere under `tests/` (verified: `grep -rln cli_remote tests/` returns empty). The bug therefore can NOT be caught by the existing suite no matter how green it is. Every CI green light on this commit is silent about this surface.
  4. The failure mode is not a graceful tombstone (`agent-grant` Stage-3-style exit-2 with a deprecation message) — it's a network 404 wrapped in `_bail(resp)` which raises a `ClickException`. Users get "HTTP 404 Not Found" with no hint that the feature was deprecated.
- Impact: Any user of `iam-jit remote chat` or `iam-jit remote submit-from-chat` against a 0.4.0+ server gets an opaque 404. CI pipelines using these subcommands break silently on the upgrade. The "agent-via-remote" usage pattern documented in the cli_remote module docstring is broken.
- Fix (parallels Stage-3 tombstone):
  - Option A (recommended): replace the two commands with tombstones modeled on `cli.py::agent_grant` — print a yellow deprecation message to stderr, exit 2, and tell the user to use `iam-jit remote submit` directly (which still works) plus the MCP `submit_policy` tool for the conversational draft path. Update the module docstring to drop the "chat through an intake" bullet.
  - Option B: just delete the two commands outright (since this is a 0.4.0 major-style breaking change and click's "No such command" error IS a clean signal).
  - Either way: add at least one black-box test to `tests/` that imports `iam_jit.cli` and runs `iam-jit remote --help` (via click's CliRunner) to assert the subcommand list — that would have caught this CRIT and pins the surface going forward.

### CRIT-17-02 — `/requests/new` chooser redirects to deleted `/requests/new/chat` when AI is enabled → primary web flow 404s for AI-enabled deployments

- File: `src/iam_jit/routes/web.py:696-706` (`new_chooser`)
- Issue: The chooser handler still has:
  ```python
  if review.is_review_enabled():
      return RedirectResponse(url="/requests/new/chat", status_code=303)
  return _render(request, "new_request.html", active="new", user=user)
  ```
  but `/requests/new/chat` was removed in this commit. `is_review_enabled()` returns `True` whenever a non-NoOp LLM backend is configured (`review.py:35-47`) — i.e., for every Pro / Team / Enterprise tier deployment (the default production posture). Anonymous users hitting `/requests/new` get 303 → `/login` first (correct), but **authenticated** users get 303 → `/requests/new/chat` → 404.
- Repro (verified empirically):
  ```python
  # with review.is_review_enabled monkey-patched to True
  GET /requests/new          → 303  location=/requests/new/chat
  GET /requests/new/chat     → 404
  ```
- Why this is CRIT:
  1. AI-mode is the documented primary deployment posture in the LLM-tier pricing model. Stating "AI mode" as the case where this breaks IS stating "the case the customer paid for."
  2. The "+ New request" link is the dominant call-to-action on the web home page — it's the route a new requester would land on within seconds of first logging in.
  3. The test suite does not cover this path: `tests/test_web_routes.py::test_new_chooser_renders_for_authenticated` only exercises the non-AI branch (the default test fixture has no LLM backend wired), so it never exercises the redirect-to-/chat path. Every grep for `/requests/new/chat` in tests/ hits only deletion-closure skips and the `_safe_return_to` allowlist assertion (LOW-17-07).
- Impact: Authenticated users on AI-enabled deployments cannot create a new request via the web UI's standard entry point. The chooser dead-redirects on first click. They CAN reach `/requests/new/paste` directly (URL-bar typed or bookmarked), so the underlying functionality isn't gone — but the discoverable web flow is broken.
- Fix: edit the conditional. Recommendations in order:
  - **(a) [recommended]** Drop the conditional entirely; always render the chooser. The chooser already displays an `{% if ai_enabled %}` branch in `new_request.html` that distinguishes AI-on vs AI-off paste; let the user decide. Net change: `return _render(request, "new_request.html", active="new", user=user)` always.
  - **(b)** Keep the conditional but redirect to `/requests/new/paste` (the current working surface) when AI is enabled.
  - Either fix needs LOW-17-04 closed at the same time (the chooser template's `/requests/new/generate` link must be repointed to `/requests/new/paste`).

## HIGH findings

### HIGH-17-03 — `GET /api/v1/users/me::agent_hints.submit_request_conversational.path` points to deleted `/api/v1/intake/turn` → every authenticated agent caller gets a misleading bootstrap contract

- File: `src/iam_jit/routes/users.py:70-83`
- Issue: The `/api/v1/users/me` response includes a `agent_hints` block that is explicitly documented as the **stable agent-bootstrap contract** (line 30-31: `"The hints are stable contract — agents may rely on them to bootstrap without reading the README."`). One of the hints is:
  ```json
  "submit_request_conversational": {
    "method": "POST",
    "path": "/api/v1/intake/turn",
    "body": {"conversation": [{"role": "user", "content": "<your request in plain English>"}]},
    "notes": "Stateless turn-by-turn intake. Each call returns {ask, fields, complete, draft_policy, prefill}. When complete=true, hand 'prefill' to /api/v1/requests."
  }
  ```
  The path is dead. Any agent that reads this hint and POSTs accordingly gets a 404.
- Test coverage actively pins the wrong behavior: `tests/test_routes_users.py:30` asserts:
  ```python
  assert hints["submit_request_conversational"]["path"] == "/api/v1/intake/turn"
  ```
  The test passes because it only checks the *string contents* of the contract, not that the contract *works*. This is a textbook example of "a test that holds a broken contract in place."
- Why this is HIGH not CRIT:
  - The other agent_hints (`mint_token`, `submit_request_structured` → `/api/v1/requests`, `list_my_requests`, `assume_instructions`) are still correct, so a well-behaved agent that prefers the structured submit path (`submit_request_structured`) is unaffected.
  - The cost-of-getting-it-wrong is one 404 per agent on first conversational attempt, recoverable by falling back to the structured path. Not silent corruption.
- Impact: Any agent that introspects `/me` and uses the conversational hint hits 404. Any 3rd-party tooling that wrote integrations against this hint's documented stability is now broken.
- Fix: remove the `submit_request_conversational` block from `agent_hints` entirely (the deletion-not-replacement pattern, consistent with Stage 4's "delete the synthesis surface" intent). Update `tests/test_routes_users.py::test_me_returns_agent_hints_for_token_minting` to assert the block is **absent**. Optionally add an `agents_md` field pointing at `docs/AGENTS.md` so agents that need MCP-style guidance know where to read.

## MED findings

None.

## LOW / INFO findings

### LOW-17-04 — `new_request.html` chooser card links to deleted `/requests/new/generate`

- File: `src/iam_jit/templates/new_request.html:9`
- Issue: The "Generate a new role" card in the chooser template has `<a class="card pickable" href="/requests/new/generate">`. The route was deleted in Stage 4. In **NoAI mode** (the only mode that actually *renders* this template — see CRIT-17-02), the card is visibly disabled with the "unavailable" badge, but the surrounding `<a>` is still clickable, and `href` still points at the dead route.
- Repro:
  ```
  GET /requests/new                              → 200 (renders chooser)
  GET /requests/new/generate (from clicking card) → 404
  ```
- Impact: A user on a NoAI deployment can still click the "unavailable" card and land on a 404 instead of a graceful "this mode is disabled" page. Low because (a) NoAI mode is uncommon, (b) the card is visually marked unavailable, but (c) the link should not be clickable at all.
- Fix: Either drop the `href` attribute when `not ai_enabled`, or repoint it to `/requests/new/paste` (with the AI-on body re-worded to "Generate locally with a code-aware agent, then paste here" — which actually matches the post-Stage-4 architecture described in the existing disclaimer at lines 35-43 of the same file).

### LOW-17-05 — `tokens.html` page advertises `POST /api/v1/intake/turn` to authenticated callers

- File: `src/iam_jit/templates/tokens.html:55`
- Issue: The tokens page (rendered at `GET /tokens` for any authenticated user) contains:
  ```html
  <p>The simplest path: <code>POST /api/v1/intake/turn</code> drives the conversational flow; <code>POST /api/v1/requests</code> takes a structured policy directly. Both accept the same bearer token.</p>
  ```
  This is user-visible documentation that points at the deleted endpoint. Same shape as HIGH-17-03 but in HTML rather than JSON.
- Impact: A developer who reads the tokens page and follows the "simplest path" guidance lands on a 404. Low because anyone who reads to the next clause finds the working `POST /api/v1/requests` recommendation.
- Fix: rewrite the paragraph to drop the `/api/v1/intake/turn` claim; recommend `POST /api/v1/requests` as the only path. Could also link `docs/AGENTS.md` for the MCP-style flow.

### LOW-17-06 — Orphan helpers left behind by route deletions

Stage 4 deleted the *callers* but left several *callees* dangling. None affect runtime (they're never called); all are dead code that should be swept in a follow-up commit.

Specific orphans confirmed via grep across `src/` and `tests/`:

| Symbol | File | Reason orphan |
|---|---|---|
| `_sign_intake_state` | `routes/web.py:887` | Only called by `_sign_intake_conversation` (also orphan) |
| `_sign_intake_conversation` | `routes/web.py:899` | No callers — deleted chat routes were the only consumer |
| `_load_intake_state` | `routes/web.py:904` | No callers |
| `_load_intake_conversation` | `routes/web.py:939` | No callers |
| `_enforce_rate_limit` | `routes/web.py:739` | No callers — chat/intake routes were the only consumers; `_check_banned` + `_enforce_no_injection` remain live for `paste_submit` + `post_comment_form` |
| `_CHAT_PARSE_ERRORS_BEFORE_FALLBACK = 2` | `routes/web.py:709` | No callers |
| `auth.sign_intake_state` | `auth.py:71` | Only called by orphan `_sign_intake_state` |
| `auth.verify_intake_state` | `auth.py:82` | Only called by orphan `_load_intake_state` / `_load_intake_conversation` |
| `debug_bundles.augment_for_debug` | `debug_bundles.py:579` | No callers in `src/` — only `tests/test_debug_bundles.py` exercises it. The function was wired into the now-deleted `intake.take_turn`. The `debug_bundles.BUNDLES` dict IS still used (by `_managed_policy_refs_for_request` in `web.py:1075`), so the module itself stays. |
| `debug_bundles.py` module docstring | `debug_bundles.py:14` | References "applied as a code-level augmentation in `intake.take_turn`" — `intake` module deleted |

The audit prompt #9 specifically noted "if Stage 4 left them for safety, not necessarily a finding" — agreed in principle, but the orphan-helper *chain* extends past `routes/web.py` into `auth.py` and `debug_bundles.py`, which makes the cleanup follow-up larger than the prompt anticipated. Worth a single follow-up commit (`chore(stage 4 cleanup): remove orphan intake helpers + dead augment_for_debug`).

- Impact: None at runtime. Code-hygiene only. Risk is that a future contributor finds `_load_intake_state` and assumes it's wired up to *something*, then adds a caller that re-introduces the conversational pattern — undoing Stage 4 silently.
- Fix: a single follow-up commit deletes the dead helpers in `routes/web.py` (lines 709 + 739-760 + 887-962) + the corresponding `auth.sign_intake_state` / `verify_intake_state` (lines 71-88 of `auth.py`) + `debug_bundles.augment_for_debug` and its tests (`tests/test_debug_bundles.py`) + the stale docstring line in `debug_bundles.py:14`. Net delete ~150-200 LOC.

### LOW-17-07 — `_safe_return_to` allowlist still includes `/requests/new/chat`; pinned by a security-hardening test

- File: `src/iam_jit/routes/web.py:122` (`_SAFE_RETURN_TO`); `tests/test_security_hardening.py:132` (`test_return_to_known_path_is_preserved`)
- Issue: The allowlist of `?return_to=...` values that survive the magic-link callback includes `/requests/new/chat`. The path is deleted. A user who clicked a stale link / bookmark / email that embedded `?return_to=/requests/new/chat` and goes through the magic-link login flow lands on a 404 after auth. The hardening test pins the broken behavior with:
  ```python
  assert _safe_return_to("/requests/new/chat") == "/requests/new/chat"
  assert _safe_return_to("/requests/new/chat?resume=drft-abc") == "/requests/new/chat?resume=drft-abc"
  ```
- Impact: UX only — no security implication (the allowlist's *job* is preventing redirect to off-origin hosts, and that job is intact). User lands on 404 after login on a stale link.
- Fix: drop `/requests/new/chat` from `_SAFE_RETURN_TO`; update `test_return_to_known_path_is_preserved` to assert `_safe_return_to("/requests/new/chat") == "/"` (or `"/requests/new/paste"` if we want to be friendly to stale links). 2 LOC each.

## Pre-existing artifacts (NOT findings)

- **`tests/test_appsec_audit_round2_bb.py::test_bb2_20_session_fixation_pre_auth_cookie_replaced_on_callback`, `test_bb2_21_magic_link_single_use_within_process` still fail under `pytest tests/test_appsec_audit_round2_bb.py`** (full-file run) because of a magic-link `dev_link` JSON key absent on the second invocation. Same behavior + same line numbers as WB16 noted. Verified PASS in isolation:
  ```
  pytest tests/test_appsec_audit_round2_bb.py::test_bb2_20_session_fixation_pre_auth_cookie_replaced_on_callback \
         tests/test_appsec_audit_round2_bb.py::test_bb2_21_magic_link_single_use_within_process
  → 2 passed in 0.55s
  ```
  Verified FAIL under full-file run (same as WB16):
  ```
  pytest tests/test_appsec_audit_round2_bb.py
  → 2 failed, 20 passed, 3 skipped in 1.99s
  ```
  Both PASS under the broader-suite run (test-ordering effect from a process-global magic-link single-use store, per WB16 note). Pre-existing; not made worse by Stage 4. Documented again here so future audits don't re-attribute.

- **`tests/test_post_routes_fuzz.py:37` still lists `/api/v1/intake/turn`** in the `_JSON_POST_ROUTES` allowlist. Stage 4 left it. The test still passes because the route 404s on every payload (404 satisfies the `< 500` invariant the fuzz suite asserts). Cosmetic; not a finding. Suggest removing it in the same follow-up commit as LOW-17-06.

- **`docs/security-notes.md:39` and `:396` still reference `/api/v1/intake/turn` and `/requests/new/chat`** respectively. Out-of-scope for this audit (the audit prompt covers production code + the test surface, not the docs/ tree), but worth a sweep in the same Stage-4 follow-up commit.

## Tests passed (regression check)

- Broader suite (`pytest tests/ -q --ignore=tests/e2e --ignore=tests/test_calibration_corpus.py`): **1897 passed, 29 skipped, 14 deselected, 2 warnings in 90.52s** — matches the commit-message claim exactly.
- Targeted MCP+catalog suite (`pytest tests/test_mcp_*.py tests/test_aws_managed_catalog.py`): **90 passed in 0.21s** — matches WB16.
- `test_routes_users.py`: 8 passed (incl. the test that PINS the broken `submit_request_conversational` hint — HIGH-17-03).
- `test_routes_policy.py`: 3 passed + 2 skipped (the back-compat-empty-narrowing-questions case passes; the two skipped tests are the closure-by-deletion Stage 4 skips and read correctly).

Test counts match the commit message exactly. The 29 skips are the closure-by-deletion entries Stage 4 added (24 newly-added; 5 from Stage 1-3 still in place). Same warning set as Stage 3 (HS256 short-key + Starlette per-request cookies deprecation).

## What's solid (positive findings)

1. **No production `from .suggest` / `from .narrow` / `from .intake` / `from .intake_drafts` / `from .routes.intake` imports anywhere in `src/`.** Grep returns empty:
   ```
   grep -rn "from .suggest\|from .narrow\|from .intake\|from .intake_drafts\|from \.routes\.intake" src/
   → (empty)
   grep -rn "from iam_jit.suggest\|from iam_jit.narrow\|from iam_jit.intake\|..." src/ tests/
   → (empty)
   ```
   The deleted modules are not referenced as Python imports anywhere — the breaks are all in URL strings and HTML / JSON contract text.

2. **No production `suggest_policy` / `detect_broadness` / `apply_constraints` / `take_turn` / `TurnRequest` / `TurnResponse` / `intake_router` / `_CHAT_OPENING_GREETING` symbol references in `src/`.** Only the comment in `app.py:34` ("NOTE: intake_router deleted in Stage 4 of [[no-nl-synthesis]]") and `routes/policy.py:18` + `routes/requests.py:718` ("narrow module deleted...") which are intentional Stage-4 deletion markers.

3. **CLI surface is clean for the targeted deletions:**
   ```
   $ iam-jit suggest --help → "No such command 'suggest'." exit:2 ✓
   $ iam-jit refine --help  → "No such command 'refine'."  exit:2 ✓
   $ iam-jit --help         → no `suggest` or `refine` in command list ✓
   ```
   But `iam-jit remote chat` + `iam-jit remote submit-from-chat` ARE still present and broken — see CRIT-17-01.

4. **App loads cleanly:** `from iam_jit.app import create_app; create_app()` succeeds; 108 routes registered; `TestClient(app)` spins up; `app.routes` enumerates without raising. No deferred-import surprises.

5. **All targeted deleted routes return 404:**
   ```
   GET  /requests/new/chat         → 404 ✓
   POST /requests/new/chat         → 404 ✓
   GET  /requests/new/chat/stream  → 404 ✓
   GET  /requests/new/generate     → 404 ✓
   POST /requests/new/generate     → 404 ✓
   POST /api/v1/intake/turn        → 404 ✓
   ```
   Anonymous `GET /requests/new` correctly 303s to `/login`. Authenticated rendering of `/requests/new` works in NoAI mode (chooser HTML); 303s to dead `/requests/new/chat` in AI mode (CRIT-17-02).

6. **`POST /api/v1/policy/analyze` back-compat preserved:** the route still accepts a `{policy}` body and returns `{review, narrowing_questions: [], ai_enabled}`. `narrowing_questions` is permanently `[]` post-Stage-4, exactly as documented in `routes/policy.py:18-22`. Verified via `tests/test_routes_policy.py::test_analyze_clean_policy_no_narrowing` (PASS) — the IDE-plugin back-compat contract is held.

7. **Templates are removed and not referenced elsewhere:**
   ```
   ls src/iam_jit/templates/ → no new_chat.html, no new_describe.html ✓
   grep -rn "new_chat\|new_describe" src/iam_jit/templates/ → (empty) ✓
   grep -rn "new_chat\|new_describe" src/ → (empty) ✓
   ```
   No Jinja `{% include "new_chat.html" %}` survives anywhere.

8. **Stage-3 tombstone still works (audit prompt #8):**
   ```
   $ iam-jit agent-grant
   → iam-jit agent-grant has been removed in 0.4.0.
     Use the MCP tools (list_templates / get_template / score_iam_policy /
     submit_policy) instead. See docs/AGENTS.md.
   exit:2 ✓
   ```
   No regression to the Stage-3 tombstone behavior.

9. **Skip-wrap accuracy: 10 sampled tests all genuinely probe deleted code.** Verified via `git show 767b66b~1:tests/...` of the pre-skip bodies for:
   - `test_routes_bans.py::test_chat_post_high_signal_injection_bans_user` (line 61 skip) — POSTed to `/requests/new/chat`. Would fail meaningfully (404). ✓
   - `test_routes_bans.py::test_chat_stream_injection_bans_and_returns_403` (line 71 skip) — POSTed to `/requests/new/chat/stream`. Would fail (404). ✓
   - `test_routes_bans.py::test_chat_post_medium_signal_refused_but_no_ban` (line 66 skip) — same shape. ✓
   - `test_routes_bans.py::test_admin_user_is_not_banned_for_injection` (line 76 skip) — POSTed to `/requests/new/chat`. ✓
   - `test_rate_limit.py::test_chat_post_429_after_soft_cap` (line 128 skip) — POSTed to `/requests/new/chat` + monkey-patched `intake.take_turn`. Both surfaces gone. ✓
   - `test_rate_limit.py::test_chat_post_hard_cap_bans_user` (line 133 skip) — same. ✓
   - `test_appsec_audit_round2_bb.py::test_bb2_06_intake_turn_large_message_no_per_field_cap` (line 418 skip) — explicitly POSTed to `/api/v1/intake/turn`. ✓
   - `test_appsec_audit_round3_bb.py::test_bb3_14_requests_new_chat_refuses_cross_origin_post` (line 759 skip) — POSTed to `/requests/new/chat`. ✓
   - `test_security_hardening.py::test_chat_login_redirect_uses_safe_return_to` (line 171 skip) — GET on `/requests/new/chat?resume=...`. Would now return 404 not 303. ✓
   - `test_web_routes.py::test_new_describe_redirects_when_no_ai` (line 144 skip) — GET on `/requests/new/generate`. Would now return 404. ✓

   100% of the sampled skips are accurate. The closure-by-deletion message is consistent (`closed by deletion: ... removed in 0.4.0 ([[no-nl-synthesis]] Stage 4)`).

10. **Test count delta is internally consistent:** Stage 3 baseline was 2026 passed + 4 skipped. Stage 4 broader suite is 1897 passed + 29 skipped. Delta: -129 passes + 25 newly-skipped. The 129 missing passes split as: ~22 from deleted whole test files (`test_intake.py` + `test_intake_drafts.py` + `test_intake_llm.py` + `test_narrow.py` + `test_routes_chat.py` + `test_routes_chat_resume.py` + `test_prompt_edge_cases.py`) minus the 25 skip-wraps that still register but skip = matches commit-message claim cleanly.

11. **MCP server unchanged + still healthy:** the same 90 MCP+catalog tests from Stage 3 still pass. `mcp_server.py` imports nothing from `intake` / `narrow` / `suggest` / `intake_drafts`. The Stage-3 tombstone for `generate_iam_policy` is intact.

## Audit-completeness note (per [[audit-cadence-discipline]])

Stage 4 audit checked:

1. **Production source caller graph** — found CRIT-17-01 (`cli_remote.py`) + finding-driven scrutiny of `routes/web.py`, `routes/users.py`, `auth.py`, `debug_bundles.py`. The deleted-module *imports* are gone everywhere; the deleted-route *URL strings* are scattered across CLI / web / API surfaces (CRIT-17-01, CRIT-17-02, HIGH-17-03, LOW-17-04, LOW-17-05, LOW-17-07).
2. **Deleted-route HTTP probes** — all 6 targeted URLs return 404 ✓.
3. **CLI surface** — `suggest` + `refine` gone ✓; `remote chat` + `remote submit-from-chat` still present and broken (CRIT-17-01).
4. **API back-compat** — `/api/v1/policy/analyze` still returns the documented `{review, narrowing_questions: [], ai_enabled}` shape ✓.
5. **Templates** — both deleted; no `{% include %}` rot ✓; chooser template still links to one deleted URL (LOW-17-04).
6. **Skip-wrap accuracy** — 10/10 sampled tests are genuine closure-by-deletion ✓.
7. **Orphan helper inventory** — 10 orphans across 3 files identified (LOW-17-06).
8. **Stage-3 tombstone non-regression** — `agent-grant` still exits 2 with deprecation message ✓.
9. **Pre-existing flake** — `test_bb2_20` / `bb2_21` still flake exactly as in WB16; not made worse ✓.
10. **`/me` agent-hint contract** — found the most-load-bearing dangling-string (HIGH-17-03) + the test that pins it (`test_routes_users.py:30`).
11. **`_safe_return_to` allowlist** — found the dead `/requests/new/chat` entry + the test that pins it (LOW-17-07).
12. **Docs sweep (best-effort)** — flagged `tokens.html` (LOW-17-05) + noted `docs/security-notes.md` references (pre-existing not-a-finding).

The big-deletion audit pattern continues paying for itself per `[[audit-cadence-discipline]]`. Stage 4 specifically vindicated the round-1-of-WB14's-discipline of probing *callers downstream of the deletion*, not just the deletion itself — the unit test suite is fully green and would never have caught any of the three primary findings.

## Stage-4-close carry-forward checklist

In severity order. Items 1-3 must close before declaring Stage 4 done.

- [ ] **CRIT-17-01**: tombstone or delete `iam-jit remote chat` + `iam-jit remote submit-from-chat`; update `cli_remote.py` module docstring; add a smoke test asserting `iam-jit remote --help` does NOT list `chat` / `submit-from-chat`. (~30 LOC + 1 test.)
- [ ] **CRIT-17-02**: edit `routes/web.py::new_chooser` to drop the `is_review_enabled()` → `/requests/new/chat` redirect; render the chooser always (or redirect to `/requests/new/paste`). Add a TestClient test for both AI-on and AI-off paths. (~5 LOC + 2 tests.)
- [ ] **HIGH-17-03**: remove `submit_request_conversational` block from `routes/users.py::me`'s `agent_hints`; update `tests/test_routes_users.py::test_me_returns_agent_hints_for_token_minting` to assert the key is **absent**. Consider adding an `agents_md_url` field instead. (~15 LOC + 1 test edit.)
- [ ] **LOW-17-04**: update `templates/new_request.html` — repoint the "Generate a new role" card's `href` to `/requests/new/paste` (with the body re-worded to describe the locally-generate-then-paste workflow that matches the existing disclaimer text), or drop the `<a>` wrapper entirely when `not ai_enabled`. (~10 LOC HTML.)
- [ ] **LOW-17-05**: edit `templates/tokens.html:55` to drop the `POST /api/v1/intake/turn` advertisement; recommend `POST /api/v1/requests` + link `docs/AGENTS.md`. (~3 LOC HTML.)
- [ ] **LOW-17-06**: single follow-up commit removing orphan helpers across `routes/web.py` + `auth.py` + `debug_bundles.augment_for_debug` + `tests/test_debug_bundles.py` + the stale `debug_bundles.py:14` docstring line. (~150-200 LOC delete.) Also: remove `/api/v1/intake/turn` from `tests/test_post_routes_fuzz.py:_JSON_POST_ROUTES`.
- [ ] **LOW-17-07**: drop `/requests/new/chat` from `_SAFE_RETURN_TO`; update `tests/test_security_hardening.py::test_return_to_known_path_is_preserved` accordingly. (~3 LOC + 1 test edit.)

Optional sweep (not strictly required for Stage-4 closure but completes the deprecation story):

- [ ] Update `docs/security-notes.md` lines 39 + 396 to drop the chat/intake references.
- [ ] Add a CHANGELOG entry for the 0.4.0 deletion (covering Stages 3 + 4 together; per `[[update-release-strategy]]`'s "scorer-version-independent semver from 1.0.0" memo this maps to the next breaking-pre-1.0 bump).
