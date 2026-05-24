# L4 recipe — update FAILURE recovery

Harness-primary. Agent reasoning helps on the "operator-visible error
actionable" assertion, which is partly a judgment call.

## Steps for the operator's agent

1. Run harness for Variant A, B, C sequentially (each emits its own
   JSONL line).
2. For each FAIL: read the stderr captured in the evidence block;
   judge whether the operator could ACT on the message:
   * Says WHAT failed?
   * Says WHY (root cause)?
   * Says WHAT TO DO (recovery hint)?
   This rubric matches MRR-2 error-path actionability.
3. If any variant produces a non-actionable error, file MED issue
   against MRR-2 (cryptic error catalogue).
4. If any variant fails to rollback (bouncers down post-failure):
   CRIT — surface to operator immediately; the canary contract is
   broken.

## MCP tools

| Tool | Purpose |
|---|---|
| `iam_jit_canary_status` | Confirm bouncers still alive after failure |
| `bounce_query_audit_long_range` | Confirm audit DB intact |
| `iam_jit_canary_report` | Confirm `issues.jsonl` carries the CRIT |

Agent LLM reasoning is appropriate here for the actionability
judgment (matches MRR-2 rubric). All other assertions are
deterministic.
