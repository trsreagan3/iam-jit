# L12 recipe — cross-bouncer update consistency

Harness-primary.

## Steps for the operator's agent

1. Run `deterministic-harness.sh`.
2. If FAIL on atomic-rollback: CRIT — half-state is the operationally
   worst outcome.
3. If FAIL on cross-bouncer query post: HIGH — wire-divergence
   regression.

## MCP tools

| Tool | Purpose |
|---|---|
| `iam_jit_canary_update` | Trigger update |
| `iam_jit_posture` | Both-bouncer health post-update |
| `bounce_query_audit_long_range` | Cross-bouncer correlation |

No LLM reasoning required.
