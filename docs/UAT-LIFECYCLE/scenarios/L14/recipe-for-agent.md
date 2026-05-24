# L14 recipe — AWS credential rotation

Harness-primary. Agent reasoning helps interpret false-positive
denies (might be legitimately denied for other reasons + masked as
rotation-boundary failure).

## Steps for the operator's agent

1. Run `deterministic-harness.sh`.
2. If any `invalid_token_errors` > 0: CRIT — production-breaking
   for any short-lived-cred workflow.
3. If `false_positive_denies_at_rotation` > 0: agent investigates
   each denied event; classifies as legitimate-deny vs rotation-
   artifact.

## MCP tools

| Tool | Purpose |
|---|---|
| `bounce_query_audit_long_range` | Pull rotation-window events for classification |

Agent LLM reasoning appropriate for false-positive vs legitimate-
deny classification.
