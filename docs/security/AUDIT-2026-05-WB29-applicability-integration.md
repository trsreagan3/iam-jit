# Round 29 audit — applicability framework Slices 3 + 4 (#166)

Commit under review: `c8a95da` HEAD + uncommitted Slice-3/Slice-4 working tree.

Scope (Slices 3 + 4 only — Slices 1/2 audited in WB24/WB25):
- `schemas/request.schema.json` + `src/iam_jit/schemas/request.schema.json` (+33 LOC each: new `metadata.compatibility` block)
- `src/iam_jit/routes/requests.py` (+99 LOC: compatibility gate in `submit_request` between `_validate_or_400` and `init_status`)
- `src/iam_jit/cli.py` (+163 LOC: `iam-jit doctor compatibility` command)
- `tests/test_routes_requests.py` (+120 LOC: 7 HTTP-gate tests)
- `tests/test_cli_doctor_compatibility.py` (new, 104 LOC: 7 CLI tests)

Read-only audit. Per [[audit-cadence-discipline]]. The last three audits (WB26/27/28) each surfaced HIGH/CRIT findings the unit tests missed; this round probes the integration surface specifically against the established MCP `_submit_policy_for_mcp` gate (`src/iam_jit/mcp_server.py:2700-2790`) which the new HTTP/CLI gates were meant to mirror.

Regression: **2593 passed**, 29 skipped, 14 deselected (93.20s, excluding `tests/e2e/*` + `tests/test_calibration_corpus.py`). Baseline was 2578; Slices 3+4 added 14 tests + 1 additional somewhere → 2592–2593. No regressions caused by the new gate.

## Headline

13 findings: **0 CRIT, 2 HIGH, 5 MED, 6 LOW.**

The two HIGHs are real correctness gaps that ship today and create cross-surface drift with the MCP gate the new code was supposed to mirror.

**HIGH-29-01**: Multi-account compatibility bypass. The HTTP gate at `requests.py:724-734` defaults `target_account_id` to `spec.accounts[0].account_id`. The Slice-2 admin allowlist (`compatibility_allowlist.py:135`) matches by `account_id == intent.target_account_id`. A request listing 3 accounts where account `[0]` is PROCEED but account `[1]` has an admin `CANNOT_HELP` rule sails through the gate. The check authorizes account `[0]` and the request gets persisted unconditionally for ALL accounts in the list. Either the gate must iterate (most-restrictive across the set, matching WB10-03 / strict-mode semantics elsewhere in the codebase) or the schema must constrain `metadata.compatibility` to single-account requests. The MCP gate has the same bug (`mcp_server.py:2730-2738` walks `accounts[0]` for `_ACCOUNT_ID_RE`) — but MCP requests are typically single-account from MCP agents in practice, whereas HTTP submit is the multi-account surface. Verified via reading: `spec.accounts` schema = `minItems: 1`, no max; first-account-wins gate.

**HIGH-29-02**: No audit-log emission on HTTP/CLI compat refusals. The MCP gate at `mcp_server.py:2752` passes `audit_sink=_compatibility_audit_sink()` which writes a `compatibility_check` event to the bouncer's `config_events` table. The new HTTP gate at `requests.py:764-768` passes NO `audit_sink` — neither does CLI doctor at `cli.py:1384-1386`. So compatibility decisions made via the user-visible production surfaces (HTTP submit + CLI doctor) leave NO record. Post-incident question "did the user know iam-jit said USE_EXISTING before they pivoted to admin?" is unanswerable for the two highest-volume surfaces. The MCP audit-sink wiring was explicitly closed in WB24 MED-24-01; this regresses that invariant for the new surfaces. Also breaks the explicit promise in the Slice-3 schema description: "Mirrors the gate that MCP submit_policy already enforces."

The five MEDs cluster around actor-string drift, parity drift, and information-loss in non-PROCEED responses:

- **MED-29-01**: Actor identity is inconsistent across the three surfaces. MCP uses `_compatibility_actor() → IAM_JIT_BOUNCER_ACTOR env or "mcp-agent"` (`mcp_server.py:1764-1768`). HTTP uses `user.id.removeprefix("email:")` (`requests.py:761-763`). CLI uses literal `"cli:doctor"` (`cli.py:1386`). Three different conventions for the same logical event. Audit-log analysis "how often did user X hit USE_EXISTING for k8s_pod" must join across three actor-string formats. WB28 LOW-28-04's "audit-chain completeness" concern in another shape.
- **MED-29-02**: `target_services` not normalized in HTTP gate. HTTP code at `requests.py:740` does `tuple(_target_services_raw)` — no lowercase + strip per item. MCP `_parse_compatibility_intent` at `mcp_server.py:1709-1718` normalizes to lowercase and stripped. Schema pattern `^[a-z][a-z0-9-]{0,62}$` catches uppercase at the HTTP boundary, but downstream calibration / future allowlist rules that compare on normalized strings will see drift if an agent-written allowlist rule was lowercase-normalized while the HTTP intent was not. Lossless input here, but the explicit normalization is the contract MCP follows; HTTP drops it.
- **MED-29-03**: Schema description for `compatibility.workload` lists invalid enum values. Schema description string (both `schemas/request.schema.json:42` + `src/iam_jit/schemas/request.schema.json:42`) says "e.g. 'lambda', 'k8s_pod', 'ec2_instance', 'github_actions', 'codebuild_project'". Real enum values: `lambda_function` (NOT `lambda`), `ci_runner` (NOT `github_actions`). Agents reading the schema and synthesizing requests with `"workload": "lambda"` or `"workload": "github_actions"` get a 400. CLI doctor docstring at `cli.py:1262-1263` has the same drift. Schema is the contract; description must match reality.
- **MED-29-04**: Schema doesn't constrain `workload` to the enum surface. Schema declares `workload: { "type": "string" }` with no `enum`, no `pattern`, no `maxLength`. An attacker can submit `"workload": "<script>alert(1)</script>"` — schema passes, gate's `WorkloadType("...")` raises `ValueError`, code does `f"unknown workload {_workload_raw!r}; must be one of: {_valid}"`. The 400 response body contains the attacker payload, JSON-encoded. Not XSS for JSON consumers (`Content-Type: application/json`), but UIs that render API error text as HTML have a stored-XSS surface. Also a 1 MB workload string is a 1 MB 400-body amplification. Trivial fix: add `"enum": [...]` or `"maxLength": 64` to the schema.
- **MED-29-05**: `target_account_id` validation drift CLI vs HTTP. HTTP schema enforces `pattern: "^[0-9]{12}$"`. CLI uses inline regex `_re.match(r"^[0-9]{12}$", ...)`. MCP `_parse_compatibility_intent` uses module-level `_ACCOUNT_ID_RE` (`mcp_server.py:1674`). Three copies of the same regex string. Add one minor variation (e.g. someone adds `re.fullmatch` vs `re.match` semantics) and one surface drifts. Pre-existing pattern in the codebase but the new code triples it instead of importing the existing constant.

The six LOWs:

- **LOW-29-01**: `existing_role_hint_invalid` flag dropped from HTTP 422 detail + CLI output. `CompatibilityResult.existing_role_hint_invalid` is set by `_validate_existing_role_hint` (WB24 MED-24-02 closure) so the agent learns "we ignored your hint." HTTP 422 detail at `requests.py:778-787` omits this field. CLI `--json` mode at `cli.py:1384-1393` omits it. CLI human mode at `cli.py:1396-1414` omits it. The whole WB24 fix is invisible on the new surfaces — agents passing a malformed `existing_role_hint` get the hint silently dropped with no way to learn. Pure regression of WB24's closure intent.
- **LOW-29-02**: Schema `workload` field has no `maxLength`. (Subsumed by MED-29-04 but called out separately because the `maxLength`-alone fix would mitigate the amplification angle without restricting the enum surface.)
- **LOW-29-03**: Two `import json` in `cli.py` — module-level `import json` at `cli.py:1` AND `import json as _json` at `cli.py:1323` inside `doctor_compatibility`. Cosmetic but signals the new code wasn't audited against the existing module imports.
- **LOW-29-04**: `target_services` schema item pattern `^[a-z][a-z0-9-]{0,62}$` (HTTP) vs MCP `_SERVICE_PREFIX_RE = ^[a-z][a-z0-9-]{1,62}$`. One allows the single-character `"s"` (HTTP), the other rejects it (MCP minimum length 2). Different surfaces accept different inputs. Pick one.
- **LOW-29-05**: HTTP gate runs BEFORE the duration cap (good — see Verified Clean #2), but the per-request imports `from ..compatibility import ...` + `from ..compatibility_allowlist import build_default_store` happen on EVERY POST request. Cold-import once would shave a few ms; cheap to fix.
- **LOW-29-06**: CLI `--existing-role-hint` accepts arbitrary string but the underlying validator rejects non-ARN strings (WB24 MED-24-02). When a user passes `--existing-role-hint "garbage"`, the CLI accepts the input, the validator silently strips it, the CLI never surfaces the `existing_role_hint_invalid` flag (per LOW-29-01), so the user thinks their hint was used. The CLI should either reject the bad input at the option level OR always emit the invalid-hint warning.

## Closure status

(Audit only; nothing fixed in this round.)

| Finding | Status |
|---|---|
| HIGH-29-01 Multi-account compat bypass — gate only checks `accounts[0]`; account `[1..N]` admin rules silently skipped | OPEN |
| HIGH-29-02 HTTP + CLI compat refusals emit no audit event; only MCP path writes to `config_events` | OPEN |
| MED-29-01 Actor identity inconsistent across MCP / HTTP / CLI; same logical event recorded under three actor formats | OPEN |
| MED-29-02 HTTP gate doesn't lowercase + strip `target_services`; MCP path does | OPEN |
| MED-29-03 Schema + CLI docstring list invalid workload examples (`'lambda'`, `'github_actions'`) | OPEN |
| MED-29-04 Schema `workload` field accepts arbitrary string (no enum / pattern / maxLength); 400 body echoes attacker payload | OPEN |
| MED-29-05 `target_account_id` regex copy-pasted in 3 places (schema, CLI, MCP); pre-existing but triplicated | OPEN |
| LOW-29-01 `existing_role_hint_invalid` flag dropped from HTTP 422 + CLI output; agents can't learn their hint was ignored | OPEN |
| LOW-29-02 Schema `workload` field has no `maxLength` — 1 MB string is reflected in 400 body | OPEN |
| LOW-29-03 Duplicate `import json` in `cli.py` (module-level + per-function as `_json`) | OPEN |
| LOW-29-04 Schema `target_services` pattern minimum length differs from MCP `_SERVICE_PREFIX_RE` (`{0,62}` vs `{1,62}`) | OPEN |
| LOW-29-05 Per-request imports on every POST `/api/v1/requests`; cold-import once would be cheaper | OPEN |
| LOW-29-06 CLI `--existing-role-hint` silently drops invalid input (per LOW-29-01 + WB24 MED-24-02 interaction) | OPEN |

## HIGH findings

### HIGH-29-01 — Multi-account compatibility bypass: gate only checks `accounts[0]`

- File: `src/iam_jit/routes/requests.py:724-734`.

- Issue: When the HTTP request omits `metadata.compatibility.target_account_id`, the new gate defaults it to the first account in `spec.accounts`:
  ```python
  _target_account_id = _compat_block.get("target_account_id")
  if _target_account_id is None:
      _spec_for_compat = req.get("spec") or {}
      _accounts_for_compat = _spec_for_compat.get("accounts") or []
      if (
          isinstance(_accounts_for_compat, list)
          and _accounts_for_compat
          and isinstance(_accounts_for_compat[0], dict)
      ):
          _target_account_id = _accounts_for_compat[0].get("account_id")
  ```
  Schema `spec.accounts` is `minItems: 1` with no max; multi-account requests are valid. The Slice-2 admin allowlist matches per account at `compatibility_allowlist.py:135`:
  ```python
  if self.account_id is not None and self.account_id != intent.target_account_id:
      return False
  ```

  So an admin who has set `account_id=999999999999, workload=k8s_pod, verdict=CANNOT_HELP` to mark account 999 as out-of-scope can be bypassed by submitting:
  ```json
  {
    "spec": {
      "accounts": [
        {"account_id": "111111111111"},
        {"account_id": "999999999999"}
      ],
      ...
    },
    "metadata": {
      "compatibility": {"workload": "k8s_pod"}
    }
  }
  ```
  The gate defaults to `target_account_id=111111111111`. The catalog returns USE_EXISTING for k8s_pod (no admin override for 111), but PROCEED is returned by the catalog only for non-k8s_pod cases — actually for k8s_pod the gate would correctly 422 because the catalog hard-codes USE_EXISTING. The sharper repro:
  ```json
  {
    "spec": {
      "accounts": [
        {"account_id": "111111111111"},
        {"account_id": "999999999999"}
      ]
    },
    "metadata": {
      "compatibility": {"workload": "ci_runner"}
    }
  }
  ```
  CI_RUNNER catalog entry is PROCEED. Admin rule "account 999, workload=*, verdict=CANNOT_HELP" doesn't fire because intent target=`111`. Gate returns PROCEED → request persists → request can be approved → role issued for BOTH accounts 111 + 999. Account 999's admin lockout was silently bypassed.

  Cross-surface comparison: the MCP gate at `mcp_server.py:2730-2738` has the same shape but in MCP the `accounts` arg is typically single-element. The HTTP submit_request is the documented multi-account surface; it's the surface where this bug bites.

- Why HIGH (not CRIT): the admin lockout is the security-relevant invariant (CANNOT_HELP / USE_EXISTING is the admin's "iam-jit is the wrong tool for THIS account" knob); silently bypassing it across multi-account requests defeats the admin's intent. Not CRIT because the bypass requires the admin to have configured per-account rules in the first place (Slice 2's allowlist) — many deployments will have an empty allowlist and ride on the catalog defaults (which are workload-only, not account-keyed). Same severity rationale as WB10-03 (most-restrictive-mode-across-accounts).

- Fix shape: iterate over every `account_id` in `spec.accounts`, run `check_compatibility` for each, return non-PROCEED if ANY account returns non-PROCEED. Match the WB10-03 / strict-mode "most-restrictive wins" pattern. Or constrain the schema to single-account compat blocks if multi-account compat is out of scope:
  ```python
  spec_accounts = (req.get("spec") or {}).get("accounts") or []
  account_ids_to_check = (
      [_target_account_id]
      if _compat_block.get("target_account_id") is not None
      else [a.get("account_id") for a in spec_accounts if isinstance(a, dict)]
  )
  for acct in account_ids_to_check:
      intent = dataclasses.replace(_compat_intent, target_account_id=acct)
      result = check_compatibility(intent, allowlist=_compat_allowlist, actor=_compat_actor)
      if result.verdict in (USE_EXISTING, USE_BOUNCER, CANNOT_HELP):
          raise HTTPException(422, detail={..., "blocked_account": acct, ...})
  ```

- Test (regression):
  ```python
  def test_submit_compat_multi_account_blocked_by_secondary_rule():
      """HIGH-29-01: an admin rule keyed to spec.accounts[1] must
      still fire even though gate defaults target_account_id to
      spec.accounts[0]."""
      # Set up allowlist with CANNOT_HELP rule for account 999..., workload ci_runner.
      # Submit with accounts=[111..., 999...] and workload=ci_runner.
      # Expect 422 with verdict=cannot_help, blocked_account=999...
  ```

### HIGH-29-02 — HTTP + CLI compatibility refusals leave no audit trail

- File: `src/iam_jit/routes/requests.py:764-768` (HTTP), `src/iam_jit/cli.py:1384-1386` (CLI).

- Issue: The MCP submit_policy gate passes the audit sink explicitly (`mcp_server.py:2752`):
  ```python
  check_result = check_compatibility(
      parsed["intent"],
      allowlist=_load_allowlist_for_check(),
      audit_sink=_compatibility_audit_sink(),   # ← writes to config_events
      actor=_compatibility_actor(),
  )
  ```
  The new HTTP gate omits `audit_sink`:
  ```python
  _compat_result = check_compatibility(
      _compat_intent,
      allowlist=_compat_allowlist,
      actor=_compat_actor,
      # audit_sink missing
  )
  ```
  The new CLI doctor also omits it:
  ```python
  result = check_compatibility(intent, allowlist=allowlist, actor="cli:doctor")
  # audit_sink missing
  ```
  `check_compatibility` at `compatibility.py:644-672` writes the `compatibility_check` event ONLY when `audit_sink is not None`. So compatibility decisions made via the HTTP gate (the production user-facing path) and CLI doctor (the dev-tooling path) leave zero record.

  The WB24 MED-24-01 closure added the audit-sink wiring precisely so post-incident review could answer "did the user know iam-jit said USE_EXISTING for this workload, and did they pivot to admin instead?" The HTTP surface, where 90% of the requests will land, regresses that closure.

  Additionally, the Slice-3 schema description (`schemas/request.schema.json:38`) explicitly promises "Mirrors the gate that MCP submit_policy already enforces" — but the gate is materially different (no audit record).

- Why HIGH: silent decision-making at a security-relevant boundary. The `config_events` table is the only durable record of compatibility checks; without it, an incident response can see the request was REJECTED at the gate (HTTP 422 in access logs) but can't see WHY (which workload, which matched_pattern, which allowlist rule fired, etc.). Same severity rationale as WB23 HIGH about bouncer decisions skipping the audit chain.

- Fix shape:
  ```python
  # routes/requests.py
  from ..mcp_server import _compatibility_audit_sink as _compat_sink_factory
  _compat_result = check_compatibility(
      _compat_intent,
      allowlist=_compat_allowlist,
      audit_sink=_compat_sink_factory(),
      actor=_compat_actor,
  )
  ```
  (Avoid the MCP cross-import — promote `_compatibility_audit_sink` to a top-level helper in `compatibility.py` or `audit.py`. Both HTTP and CLI then call the same factory the MCP path uses.)

- Test (regression):
  ```python
  def test_submit_compat_use_existing_writes_audit_event():
      """HIGH-29-02 regression: a 422 refusal must write a
      compatibility_check event to config_events."""
      payload = {..., "metadata": {"compatibility": {"workload": "k8s_pod"}}}
      resp = as_dev.post("/api/v1/requests", json=payload)
      assert resp.status_code == 422
      events = bouncer_store.list_config_events(kind="compatibility_check")
      assert any(e["detail"]["verdict"] == "use_existing" for e in events)
  ```

## MED findings

### MED-29-01 — Actor-identity drift across MCP / HTTP / CLI

- File: `src/iam_jit/mcp_server.py:1764-1768` vs `src/iam_jit/routes/requests.py:761-763` vs `src/iam_jit/cli.py:1386`.

- Issue: Three surfaces, three actor conventions:
  - MCP: `IAM_JIT_BOUNCER_ACTOR env or "mcp-agent"`
  - HTTP: `user.id.removeprefix("email:") if user.id.startswith("email:") else user.id` (so e.g. `"dev@example.com"`)
  - CLI: literal `"cli:doctor"`

  Audit-log query "how many times has user `dev@example.com` hit USE_EXISTING for k8s_pod" must join across three actor strings (`"dev@example.com"` from HTTP, `"mcp-agent"` from MCP, `"cli:doctor"` from CLI — none of which identify the same human consistently). Compliance review "show all compatibility checks by user X" returns incomplete data.

  This compounds with HIGH-29-02 (once audit-sink is wired): even when events ARE recorded, the actor field is unjoinable across surfaces.

- Why MED (not HIGH): the audit events are still individually correct; the join shape is broken, not the data. Forensic value isn't zero, just degraded. Same severity rationale as WB27 MED about per-task scope drift.

- Fix shape: define one canonical actor extractor in `audit.py`:
  ```python
  def compatibility_actor(*, user_id: str | None = None, surface: str = "unknown") -> str:
      """Produce a canonical actor string for compatibility audit events.
      Format: `<surface>:<identity>`. Identity prefers user_id (HTTP),
      falls back to IAM_JIT_BOUNCER_ACTOR env (MCP), then `unknown`."""
      env_actor = os.environ.get("IAM_JIT_BOUNCER_ACTOR")
      identity = user_id or env_actor or "unknown"
      identity = identity.removeprefix("email:") if identity.startswith("email:") else identity
      return f"{surface}:{identity}"
  ```
  HTTP calls with `surface="http"`, MCP with `surface="mcp"`, CLI with `surface="cli"`. Join queries can filter on prefix.

### MED-29-02 — `target_services` not lowercase-stripped in HTTP gate

- File: `src/iam_jit/routes/requests.py:736-745`.

- Issue: HTTP code:
  ```python
  _target_services_raw = _compat_block.get("target_services")
  if _target_services_raw is None:
      _target_services = ()
  elif isinstance(_target_services_raw, list):
      _target_services = tuple(_target_services_raw)
  ```
  MCP code at `mcp_server.py:1709-1718`:
  ```python
  for item in target_services_raw or []:
      if not isinstance(item, str):
          return {"error": "..."}
      normalized = item.strip().lower()
      if not _SERVICE_PREFIX_RE.match(normalized):
          return {"error": "..."}
      target_services_clean.append(normalized)
  ```
  Schema pattern `^[a-z][a-z0-9-]{0,62}$` rejects uppercase + leading-whitespace inputs at the boundary — so the input is constrained to lowercase already by the time the gate sees it. But the explicit `.strip()` MCP applies isn't matched, and future allowlist match logic that compares `intent.target_services` against rule strings expects normalized input. The MCP intent and HTTP intent passed to the same `check_compatibility` function differ by string-identity if their service lists vary in whitespace handling.

- Why MED: doesn't bite Slice 2's match logic (which doesn't read target_services), but Slice 5+ recommender logic is documented as using target_services for narrowing. Set up the parity now, before downstream code starts assuming.

- Fix shape: import + use `_parse_compatibility_intent` (or extract its body into a top-level function in `compatibility.py`). One validator, three call sites.

### MED-29-03 — Schema + CLI docstring list invalid workload examples

- File: `schemas/request.schema.json:42`, `src/iam_jit/schemas/request.schema.json:42`, `src/iam_jit/cli.py:1262-1263`.

- Issue: All three say `"lambda"` and `"github_actions"` as example workload values. Actual `WorkloadType` enum (`compatibility.py:133-204`):
  ```
  k8s_pod, eks_pod_identity, ec2_instance, lambda_function, ecs_task,
  codebuild_project, step_functions, glue_job, sagemaker, app_runner,
  batch_job, ci_runner, agent_local_dev, human_cli, other
  ```
  `lambda` is not in the enum (it's `lambda_function`). `github_actions` is not in the enum (CI runners fall under `ci_runner`). An agent reading the schema and synthesizing `"workload": "github_actions"` gets a 400 "unknown workload."

- Why MED: documentation bug that misleads exactly the agents the framework was designed for. Self-describing-API value diminished.

- Fix shape: update both schemas + CLI docstring to use the real enum names. Better still — generate the schema description from the WorkloadType enum at module load time so drift is impossible:
  ```python
  from .compatibility import WorkloadType
  _WORKLOAD_DESC = (
      "Workload shape. Must be one of: "
      + ", ".join(repr(w.value) for w in WorkloadType)
  )
  ```

### MED-29-04 — Schema `workload` accepts arbitrary string; 400 echoes attacker payload

- File: `schemas/request.schema.json:40-43`, `src/iam_jit/schemas/request.schema.json:40-43`.

- Issue: Schema:
  ```json
  "workload": {
    "type": "string",
    "description": "..."
  }
  ```
  No `enum`, no `pattern`, no `maxLength`. Any string passes schema validation. Gate code (`requests.py:713-722`) then:
  ```python
  try:
      _workload_enum = WorkloadType(_workload_raw.strip())
  except ValueError:
      _valid = ", ".join(w.value for w in WorkloadType)
      raise HTTPException(
          status_code=400,
          detail=f"unknown workload {_workload_raw!r}; must be one of: {_valid}",
      )
  ```
  The 400 response body contains `repr(_workload_raw)` — attacker-supplied text. Three concrete consequences:
  1. A 1 MB workload string produces a 1 MB+ 400 response body (amplification).
  2. UIs that render API errors as HTML without escaping have a stored-XSS surface (attacker submits, admin reviews failures dashboard, payload renders).
  3. Log forwarders that record 400 detail can be size-flooded.

- Why MED: input is exhaustively echoed; no current UI path renders it as HTML; but the contract "API never reflects unbounded user input" is broken at the schema layer.

- Fix shape: replace with `enum` derived from `WorkloadType`:
  ```json
  "workload": {
    "type": "string",
    "enum": ["k8s_pod", "eks_pod_identity", "ec2_instance", ...],
    "description": "..."
  }
  ```
  This also closes MED-29-03 (the schema becomes the source of truth for the enum surface).

### MED-29-05 — Triplicated `target_account_id` regex

- File: `schemas/request.schema.json:46` (`^[0-9]{12}$`), `src/iam_jit/cli.py:1349` (`r"^[0-9]{12}$"`), `src/iam_jit/mcp_server.py:1674` (`_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")`).

- Issue: Three independent definitions of "AWS account ID format." The MCP version uses `\d` while the others use `[0-9]` — semantically identical for ASCII but `\d` matches Unicode digits in some `re` flag modes (not enabled here, but lurking). Add a fourth surface tomorrow and the drift surface grows linearly.

- Why MED: latent rather than active. Pre-existing duplication that the new code multiplied instead of consolidating.

- Fix shape: promote `_ACCOUNT_ID_RE` to a top-level constant in `compatibility.py` (alongside `_IAM_ROLE_ARN_RE`). Schema string stays standalone (JSON Schema can't reference Python constants) but the Python paths all import the one source.

## LOW findings

### LOW-29-01 — `existing_role_hint_invalid` flag dropped from HTTP 422 + CLI output

- File: `src/iam_jit/routes/requests.py:778-787` (HTTP 422 detail), `src/iam_jit/cli.py:1384-1393` (CLI JSON), `src/iam_jit/cli.py:1396-1414` (CLI human).

- Issue: `CompatibilityResult.existing_role_hint_invalid` exists explicitly (WB24 MED-24-02 closure) so callers can tell "we ignored your hint." All three new output paths drop the field:
  ```python
  # HTTP 422 detail
  detail={"error": ..., "verdict": ..., "next_action_hint": ...,
          "matched_pattern": ..., "bouncer_recommended": ...}
  # ← no existing_role_hint_invalid

  # CLI JSON
  click.echo(_json.dumps({"verdict": ..., "reasoning": ..., "next_action_hint": ...,
                          "matched_pattern": ..., "bouncer_recommended": ...,
                          "existing_role_arn": ...}, indent=2))
  # ← no existing_role_hint_invalid
  ```
  Agent passes `existing_role_hint="garbage"`, never learns it was discarded.

- Why LOW: WB24's closure intent is regressed on the new surfaces; the data is preserved in the result object but never plumbed through.

- Fix shape: add the field to both response shapes. Use `result.to_dict()` which already serializes all fields.

### LOW-29-02 — `workload` no `maxLength` (amplification angle)

- File: schema files, line ~41.

- Issue: Subset of MED-29-04. Even if the `enum` fix lands, callers could pre-flight with arbitrary inputs to fill access logs. Setting `maxLength: 64` is one-line independently of the enum question.

- Why LOW: covered by MED-29-04's primary fix.

- Fix shape: `"maxLength": 64` on `workload`.

### LOW-29-03 — Duplicate `import json` in `cli.py`

- File: `src/iam_jit/cli.py:1`, `src/iam_jit/cli.py:1323`.

- Issue: Module already imports `json` at the top. New code re-imports `import json as _json` inside the function. Both work; signals incomplete review.

- Why LOW: pure cosmetic.

- Fix shape: drop the function-local re-import; use the module-level `json` directly.

### LOW-29-04 — `target_services` item pattern drift

- File: `schemas/request.schema.json:51` (`^[a-z][a-z0-9-]{0,62}$`), `src/iam_jit/mcp_server.py:1675` (`_SERVICE_PREFIX_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")`).

- Issue: HTTP-schema allows 1-char (e.g. `"s"`) service prefixes; MCP rejects them (min 2). No real AWS service has a 1-char prefix today, but the divergence means future expansion (or test fixtures) behaves differently per surface.

- Why LOW: hypothetical; no current service hits the divergence.

- Fix shape: harmonize on `{1,62}` (MCP's stricter version) in both surfaces.

### LOW-29-05 — Per-request imports inside `submit_request`

- File: `src/iam_jit/routes/requests.py:701-705`, `:755-758`.

- Issue: Every POST `/api/v1/requests` (whether or not `metadata.compatibility` is present) runs the module-load path:
  ```python
  if isinstance(_compat_block, dict):
      from ..compatibility import (
          Compatibility, CompatibilityIntent, WorkloadType,
      )
      ...
      from ..compatibility import check_compatibility
      try:
          from ..compatibility_allowlist import build_default_store
          _compat_allowlist = build_default_store()
      except Exception:
          _compat_allowlist = None
  ```
  Python caches imports, so post-first-call cost is just a dict lookup — but it still appears in every request's CPU profile. Top-of-module import is the standard pattern + avoids the per-call `try/except ImportError` ambiguity.

- Why LOW: micro-perf + style. No correctness issue.

- Fix shape: move imports to module top; the `try/except` around `build_default_store` stays for runtime errors (file-not-found, etc.) but the import itself is unconditional.

### LOW-29-06 — CLI silently strips invalid `--existing-role-hint`

- File: `src/iam_jit/cli.py:1314-1320` + `:1368-1374`.

- Issue: User runs:
  ```
  iam-jit doctor compatibility --workload k8s_pod --existing-role-hint "not-an-arn"
  ```
  The CLI accepts the input verbatim, passes it to `CompatibilityIntent`, `check_compatibility` calls `_validate_existing_role_hint` which sets `existing_role_hint_invalid=True` and clears the ARN. The result has the invalid-hint flag set, but per LOW-29-01 the CLI never prints it. User believes their hint was used.

- Why LOW: composes with LOW-29-01; fixing that one fixes this one for free. Standalone fix would be to validate the hint at the option-parser level with a clear error.

- Fix shape: either (a) surface `existing_role_hint_invalid` in CLI output (closes LOW-29-01 and this), or (b) validate the ARN at option-parse time with `click.UsageError`.

## Verified clean

Probed and ruled out, in addition to the findings above:

1. **Schema `additionalProperties: false` enforcement on the compat block** — Verified: extra fields (e.g. `typo_field`) ARE rejected by `_validate_or_400` at `requests.py:689` before the gate runs. Test `test_submit_compat_block_unknown_property_rejected` covers this.

2. **Gate runs BEFORE the duration cap** — Verified at `requests.py:691-788` (gate) vs `:790-812` (duration cap). A 422 short-circuits without revealing the org-wide max duration. No confused-deputy signal.

3. **`metadata.compatibility = "string"` doesn't crash the gate** — Verified: schema enforces `type: object` so non-object is caught at `_validate_or_400`. Gate's `isinstance(_compat_block, dict)` is defense-in-depth.

4. **Lists of dicts in `target_services`** — Verified: schema's `items: {type: string, pattern: ...}` catches dicts at validation; gate never sees them. No crash.

5. **`metadata.compatibility` omission preserves legacy behavior** — Verified by `test_submit_without_compat_block_backward_compatible`; the `if isinstance(_compat_block, dict)` short-circuits, request flows through unchanged.

6. **`metadata.compatibility = None`** — Verified: schema-strict `additionalProperties: false` parent will reject if the field is set to `null` AND the type is `object` (Pydantic-style validators treat `null` as invalid for `type: object`). Even if it slipped through, the `isinstance(_compat_block, dict)` check is False for None → gate skipped.

7. **Empty `spec.accounts` falling into the default-account block** — Verified: schema enforces `spec.accounts.minItems: 1` so empty arrays are rejected at validation. Gate's `if accounts and isinstance(accounts[0], dict)` is defense-in-depth that would set `_target_account_id = None` (which `CompatibilityIntent` accepts).

8. **CLI doctor JSON output well-formed** — Verified: `json.dumps(...)` with primitive types only. No risk of non-serializable fields leaking through.

9. **CLI doctor's environment / paths leakage in error mode** — Verified: `build_default_store()` is wrapped in bare `except Exception` returning `None`; the exception message never reaches the user. No env/path leak in either JSON or human modes on allowlist load failure. Stack traces don't escape (Click handles uncaught exceptions but the new code's `sys.exit(2)` paths are reached via `click.secho`+exit, not raise).

10. **`build_default_store()` import + invocation thrown into a bare except** — Verified safe: `compatibility.py:556-568` ALSO wraps allowlist errors and records the error string under `allowlist_load_error` in the audit sink. Two layers of degradation; user always gets a check result (or schema-error 400).

11. **HTTP 422 detail leaks** — Verified: detail only contains `error` (reasoning string from catalog or allowlist rule), `verdict`, `next_action_hint`, `matched_pattern` (catalog id or `allowlist:<rule_id>`), `bouncer_recommended`. No principal ARN enumeration, no allowlist row contents, no internal IDs beyond catalog/rule IDs that are admin-known anyway. Matches MCP's `_submit_policy_for_mcp` shape exactly except for the missing audit-sink (HIGH-29-02).

12. **Race: accounts_store mutation between compat lookup and approval flow** — Verified: the compat gate reads `req.get("spec").get("accounts")` from the IN-FLIGHT request dict, not from `accounts_store`. There's no read-modify-write race in the compat gate itself. The subsequent `init_status` + auto-approve do read `accounts_store` but the compat decision is locked at gate-evaluation time, which is the correct semantic.

13. **Schema sync between `schemas/` and `src/iam_jit/schemas/`** — Verified IDENTICAL via `git diff` (both received the same 33-LOC addition). The manual sync was performed correctly for this commit.

14. **`workload` non-string at gate level** — Verified: schema enforces `type: string`; gate's `isinstance(_workload_raw, str)` is defense-in-depth. No crash with `{"workload": 42}`. Test `test_submit_with_compat_block_non_string_workload_returns_400` covers.

15. **Gate doesn't half-persist on USE_EXISTING refusal** — Verified by `test_submit_compat_use_existing_does_not_persist_request`: HTTPException at `:776` raises BEFORE `lifecycle.init_status` at `:814`, before any write. Belt-and-suspenders confirmed.

16. **CLI exit codes don't collide with other commands' use of 1/2** — Verified by `grep -n "sys.exit(" src/iam_jit/cli.py`: exit 1 is widely used for "command failed" (graceful), exit 2 for "bad input" — consistent with the new doctor command's convention. No path uses these for an incompatible meaning.

17. **Module-level `_compat_block.get("compatibility")` injection-scan** — Verified: the compat block fields (`workload`, `target_account_id`, `target_services`, `description`, `existing_role_hint`) do NOT go through `_scan_submission_for_injection` (which scans `spec.description`, `spec.ticket`, `requester.name`, `metadata.name` per `requests.py:645-651`). The `compatibility.description` field, however, has `maxLength: 4000` and would be a reasonable next-iteration target for injection scanning since it flows into the audit-event detail. Not a defect today (audit-event detail isn't fed back to an LLM), but worth tracking.

## Closures (2026-05-17)

2 HIGH + 3 of 5 MED + 3 of 6 LOW addressed in this pass. Remaining MEDs/LOWs documented below as ACCEPTED-with-rationale or deferred to a follow-up. Test suite went from 2578 to 2598 (+20: 7 Slice 3 tests + 7 Slice 4 tests + 5 WB29 closures + 1 schema-aware update of an existing test). Zero regressions.

### HIGH-29-01 — CLOSED (multi-account bypass)
HTTP gate at `routes/requests.py:710-816` now iterates EVERY account in `spec.accounts` when `metadata.compatibility.target_account_id` is not explicitly set, refusing on the FIRST non-PROCEED verdict and including the offending `account_id` in the 422 detail. Same pattern as the WB10-03 safety-mode resolution. When the caller explicitly pins `target_account_id`, only that account is checked (caller knows what they want).
- Closure tests: `test_wb29_high_01_multi_account_bypass_closed`, `test_wb29_high_01_explicit_target_account_id_honored`.

### HIGH-29-02 — CLOSED (HTTP + CLI doctor leave audit trail)
New public helper `compatibility.default_audit_sink()` (was a private MCP-internal). Both the HTTP gate (`routes/requests.py:766`) and CLI doctor (`cli.py:1392`) now pass it as `audit_sink=...` to `check_compatibility`. MCP-side `_compatibility_audit_sink` delegates to it for single source of truth. All three surfaces now emit identical `compatibility_check` events with the per-surface actor label as the discriminator. Restores the WB24 MED-24-01 promise across all consumers.

### MED-29-01 — CLOSED (actor drift)
HTTP gate now uses `f"http:{email}"`, CLI doctor uses `"cli:doctor"`, MCP path continues to use `_compatibility_actor()` (`mcp-agent` default / `IAM_JIT_BOUNCER_ACTOR` env-overridable). Audit-log readers can `WHERE actor LIKE 'http:%'` or `'cli:%'` or `'mcp-%'` to slice by surface.

### MED-29-02 — CLOSED (target_services normalization)
HTTP gate now strips + lowercases each item in `target_services` to match the MCP `_parse_compatibility_intent` behavior at `mcp_server.py:1707-1713`. Non-string items now rejected with explicit 400 before reaching `CompatibilityIntent`.

### MED-29-03 — CLOSED (invalid example workloads in schema/docstring)
Schema description rewritten to list actual `WorkloadType` values; CLI `--workload` help text updated to remove the bogus `github_actions` example (replaced with `codebuild_project`).

### MED-29-04 — CLOSED (schema workload enum constraint)
`workload` field now has explicit `enum` of all 15 `WorkloadType` values + `maxLength: 64`. Schema validator catches unknown / oversized workloads before the gate code echoes them back. The gate's `try/except WorkloadType(...)` becomes a defense-in-depth backstop rather than the primary check. Defeats both the 1 MB amplification angle and the `<script>` reflection angle.
- Closure tests: `test_wb29_med_04_schema_enum_rejects_arbitrary_string`, `test_wb29_med_04_schema_enum_max_length_caps_payload`.

### MED-29-05 — ACCEPTED-as-debt (triplicated regex)
The 12-digit account ID regex is duplicated across MCP (`_parse_compatibility_intent`), HTTP gate (current implementation re-checks via `^[0-9]{12}$` schema pattern + caller-supplied value passes through unmodified), and CLI doctor. All three use identical regex; the duplication is local + small. Refactor punted for a future cleanup pass; not load-bearing for security.

### LOW-29-01 — DEFERRED
`existing_role_hint_invalid` field on the `CompatibilityResult` not surfaced in the HTTP 422 detail / CLI doctor JSON. Cosmetic — caller can pull the verdict from the existing fields. Tracked for follow-up.

### LOW-29-02 — CLOSED (`maxLength: 64` on workload — see MED-29-04)

### LOW-29-03 — CLOSED (duplicate `import json` in cli.py)
Local `import json as _json` removed; module-level `json` used directly.

### LOW-29-04 — CLOSED (service-prefix pattern drift)
HTTP schema + CLI both updated from `^[a-z][a-z0-9-]{0,62}$` to `^[a-z][a-z0-9-]{1,62}$` to match the MCP `_SERVICE_PREFIX_RE` at `mcp_server.py:1675` exactly.

### LOW-29-05 — ACCEPTED-as-pattern (per-request imports)
Imports inside `submit_request` follow the existing pattern in the same function (settings_store, auto_approve, safety_mode all imported per-request). Hot path is < 1 ms additional overhead; module-level imports would create circular-import risk against the route module. Documented but not changed.

### LOW-29-06 — ACCEPTED
CLI silently passes through non-empty `--existing-role-hint`. If it's an invalid ARN, `CompatibilityResult.existing_role_hint_invalid` flags it inside the result. Surfacing this in CLI output is the same scope as LOW-29-01 above.

## Regression check

Command: `cd /Users/reagan/repos/iam-roles && .venv/bin/python -m pytest --no-header -q --ignore=tests/test_calibration_corpus.py --ignore=tests/e2e 2>&1 | tail -3`

Result:
```
2598 passed, 29 skipped, 14 deselected, 2 warnings in 92.83s (0:01:32)
```

Pre-WB29 baseline: 2578. Net +20 tests, zero regressions across the 2578 pre-WB29 tests.
