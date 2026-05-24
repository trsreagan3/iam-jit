# L5 recipe — profile lifecycle

**Recipe-primary scenario.** The agent's LLM reasoning is the actual
work here: generating a profile from audit events is the load-bearing
"agent-mediated LLM work" path of `[[bouncer-zero-llm-when-agent-in-loop]]`.
The deterministic harness covers state-shape verification only.

## Pre-conditions

* Mode A container OR Mode B host with isolated state.
* L1 + L2 PASS.
* LocalStack reachable if exercising ibounce variant.
* `fixtures/workflows/L5-debug-lambda.md` + `L5-terraform-plan.md`
  templates loaded.

## Steps for the operator's agent

### Phase 1 — Discovery accumulation

1. Confirm bouncer in discovery mode (`iam_jit_posture` →
   `mode: discovery`).
2. Drive synthetic activity:
   * gbounce: 10 HTTPS requests across `fixtures/workflows/L5-*.md`
     URL lists.
   * ibounce: 10 AWS API calls (`s3:ListBuckets`, `ec2:Describe*`,
     `iam:GetRole`) against LocalStack.
3. Call `bounce_query_audit_long_range` with window covering the
   activity. Confirm 10 events.

### Phase 2 — Profile generation (LLM reasoning)

4. Call `bounce_profile_generate_from_audit` with the audit window.
5. Inspect the returned YAML.
6. **Agent reasoning**: confirm the profile covers the activity
   WITHOUT being overly permissive. The agent decides whether
   broader patterns (e.g. `s3:Get*` instead of enumerated
   `s3:GetBucketVersioning`) are appropriate. Note the rationale in
   the JSONL `agent_reasoning` field.

### Phase 3 — Install + mode switch

7. Call `bounce_profile_save` with the generated YAML.
8. Confirm hot-reload via `iam_jit_posture` — new profile is active.
9. Switch mode to `enforce` (via MCP or CLI).
10. Issue a request OUTSIDE the generated profile (e.g.,
    `kms:Decrypt`). Confirm DENIED via the synchronous response +
    via `bounce_query_audit_long_range`.

### Phase 4 — Improve suggestions

11. Call `iam_jit_improve_profile` with the post-deny audit window.
12. Inspect suggested additions.
13. **Agent reasoning**: judge whether the suggestions are
    legitimate-task additions or whether they are noise from a
    truly-bad request. The agent records the judgment.

### Phase 5 — Rollback

14. Snapshot the pre-modification profile from disk.
15. Add suggested rules; confirm enforce now allows previously-
    denied traffic.
16. Revert profile from snapshot; confirm hot-reload + previous
    deny re-fires.

### Phase 6 — Cleanup

17. Reset bouncer to discovery mode.
18. Append result JSONL via the harness with `agent_used` set.

## MCP tools

| Tool | Phase |
|---|---|
| `iam_jit_posture` | Pre/post mode confirmation |
| `bounce_query_audit_long_range` | Phase 1 + Phase 3 + Phase 4 |
| `bounce_profile_generate_from_audit` | Phase 2 (LLM reasoning) |
| `bounce_profile_save` | Phase 3 (install) |
| `iam_jit_improve_profile` | Phase 4 (LLM reasoning) |

Per `[[bouncer-zero-llm-when-agent-in-loop]]`: the operator's agent
LLM does all reasoning. iam-jit returns deterministic data + accepts
deterministic actions. ZERO bouncer-side LLM credits consumed.
