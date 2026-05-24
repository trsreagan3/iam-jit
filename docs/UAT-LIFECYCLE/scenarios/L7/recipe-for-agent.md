# L7 recipe — crash recovery

Harness-primary. Agent reasoning helps on the "is this gap honestly
logged" judgment (which is partly a documentation contract check).

## Steps for the operator's agent

1. Run `deterministic-harness.sh`.
2. If PASS: log run.
3. If FAIL on `audit_chain_continuous: false`: check whether the
   gap is explicitly logged via `bounce_query_audit_long_range` —
   per the spec contract, an explicit `process_killed` event with
   the missing-sequence range is acceptable. If the gap is silent,
   it's CRIT (forensic integrity broken).

## MCP tools

| Tool | Purpose |
|---|---|
| `bounce_query_audit_long_range` | Verify chain continuity + gap logging |
| `iam_jit_posture` | Confirm bouncer alive post-restart |

No LLM reasoning required.
