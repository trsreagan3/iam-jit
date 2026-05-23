# Custom harness — ambient iam-jit setup

Any MCP-capable agent can use the same flow as Claude Code / Cursor /
Codex / Devin. This page covers the agent-side contract.

## First-run wallpaper

Your iam-jit bouncer audits your harness's tool calls silently. When
it catches something worth your attention you'll see a one-line
"Your bouncer caught X" notification + a structured 403 the agent
can act on. The framing is "caught + here's how to allow if safe"
not "ERROR". See [claude-code.md](claude-code.md#first-run-wallpaper--what-to-expect)
for the cross-surface table.

## The contract

1. Operator writes a declaration in `.iam-jit.yaml` at repo root, OR
   a fenced YAML codeblock tagged `iam-jit-config` in any of:
   `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules.md`,
   `.devin/config.yaml`.

2. The agent has the `iam-jit` MCP server wired in (`iam-jit
   mcp-server` over stdio).

3. On session start (or whenever the agent re-evaluates context), the
   agent calls:

   ```json
   {
     "name": "iam_jit_setup_from_config",
     "arguments": {}
   }
   ```

   With no arguments the tool auto-discovers the declaration in the
   process cwd.

4. The tool returns a structured result containing:
   - `bouncers_started`: which bouncers came up
   - `bouncers_already_running`: which were already up (no-op)
   - `bouncers_skipped`: which were skipped + why
   - `env_vars_to_set`: env vars the agent should propagate to
     subprocesses
   - `posture_after`: full posture snapshot
   - `warnings`: anything the operator should know
   - `audit_event_ids`: emitted audit events

5. The agent propagates `env_vars_to_set` to its subprocess `env`
   when invoking tools (`aws ...`, `kubectl ...`, `psql ...`,
   `curl ...`).

## Honest behavior the agent should know

* **`iam_jit_setup_from_config` is idempotent.** Calling it twice in a
  row is safe — the second call sees the bouncers running + reports
  `bouncers_already_running` rather than restarting.

* **`when_X_present` heuristics are transparent.** The result includes
  a `resolved_conditionals` block showing what each `when_X_present`
  evaluated to + why. If the agent wants to verify, call with
  `dry_run: true` and re-read the resolved values without taking
  action.

* **The tool will NEVER overwrite an operator's config.** If a bouncer
  is already running with a different mode/profile/port than the
  declaration asked for, the tool emits a warning and leaves it alone.
  The agent should surface the warning to the operator (don't
  silently move on).

* **Phase A is setup-only.** Declarations with `improve.enabled: true`
  parse fine but the improve block is a no-op (with a warning) until
  Phase B (#401) ships `iam_jit_improve_profile`.

## Suggested system-prompt fragment

```
On session start, call `iam_jit_setup_from_config` with no arguments.
If the result has `warnings`, surface each warning to the user before
proceeding. Use `env_vars_to_set` for any subprocess invocations
(AWS, K8s, DB, HTTP). After setup, you can call `iam_jit_posture`
to verify the bouncer surface at any point.
```

## Related MCP tools the agent should know

* `iam_jit_posture` — read the current bouncer / role posture.
* `bouncer_posture` — read just ibounce's posture (single-bouncer
  view).
* `bounce_denies_recent` — query recent denies across all bouncers.
* `bounce_profile_allow` — propose adding an allow rule when
  something legit got blocked (agent-self-grant safety rail applies:
  the request is QUEUED for operator approval unless the bouncer was
  started with `--allow-agent-self-grant`).
* `bounce_extract_permissions_from_audit` — Phase E #419: extract a
  structured permission set from a bouncer audit window. The first
  primitive in the bouncer→agent→iam-jit synthesis loop. See
  [bouncer-to-role-pattern.md](bouncer-to-role-pattern.md).
* `iam_jit_resource_map` — Phase E #420: apply a declared
  resource-mapping (staging→prod, etc.) to the extracted permission
  set. Pure declarative substitution.
* `iam_jit_request_role_from_synthesis` — Phase E #421: synthesis-
  aware role-request seam. REQUIRES an evidence block per
  [[ibounce-honest-positioning]]; routes through the same scorer +
  auto-approve gate as every other iam-jit request.
* `bounce_query_audit_long_range` — Phase G #436: year+ window
  audit query for ONE bouncer with deployment-target scope
  filtering. Surfaces a `cold_tier_warning` flag when the window
  crosses ~90 days. See
  [bouncer-history-to-config-pattern.md](bouncer-history-to-config-pattern.md).
* `bounce_deployment_targets_for_filter` — Phase G #437: look up
  the operator-declared deployment-target taxonomy. Returns the
  classifier dict ready to pass as `scope_filter` to
  `bounce_query_audit_long_range` (or `--scope-filter` to
  `iam-jit audit query`).

## Bouncer activity → iam-jit role: the canonical pattern

See [bouncer-to-role-pattern.md](bouncer-to-role-pattern.md) for the
end-to-end agent conversation that composes the three Phase E
primitives. The pattern is harness-agnostic — any MCP-capable agent
can drive it.

## Long-range bouncer history → bouncer config: the canonical pattern

See [bouncer-history-to-config-pattern.md](bouncer-history-to-config-pattern.md)
for the Phase G three-canonical-ask recipe (positive / scope-
isolated / negative). iam-jit provides the LOGS + the TAXONOMY +
the recipe; the AGENT does the synthesis (no synthesize-config CLI
inside iam-jit per [[bouncer-informs-agent-informs-iam-jit]]).

## See also

* The JSON Schema: `schemas/iam-jit-config.schema.json` — drives
  validation; suitable for editor autocomplete.
* `docs/HARNESS-RECIPES/README.md` for the cross-harness overview.
