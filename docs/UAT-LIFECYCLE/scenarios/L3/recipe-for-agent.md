# L3 recipe — update mechanism end-to-end

Harness-primary; agent reasoning helps interpret the audit-chain
continuity output but isn't required for the binary verdict.

## Steps for the operator's agent

1. Confirm Mode A (Docker) is available — abort with SKIP otherwise.
2. Run `deterministic-harness.sh` with `${PRE_SHA}` + `${POST_SHA}`
   args. Harness handles container spin-up + update cycle.
3. If `status: PASS`: agent may optionally call
   `bounce_query_audit_long_range` to spot-check the audit events
   span the restart boundary cleanly.
4. If `status: FAIL`: surface the evidence block; specifically flag
   whether the failure was in dry-run, real-update, version-check, or
   audit-chain.
5. Agent decides severity:
   * Version-check mismatch → CRIT (release shipped wrong version).
   * Audit chain break → CRIT (forensic data integrity).
   * Profile not loaded post-update → HIGH (data preservation gap).
   * `update_success` line missing → MED (logging gap, not user-visible).

## MCP tools

| Tool | Purpose |
|---|---|
| `iam_jit_canary_update` | Trigger update (if exposed; otherwise CLI) |
| `iam_jit_canary_status` | Pre-state + post-state snapshot |
| `bounce_query_audit_long_range` | Verify chain continuity |
| `iam_jit_posture` | Confirm bouncers up post-update |

The agent does NOT need an LLM to drive L3; the harness is
self-sufficient. Agent participation is for severity classification
on failure.
