# L8 recipe — disk pressure circuit breaker

Harness-primary. Agent reasoning helps interpret whether the
operator-visible signal is actionable per MRR-2 rubric.

## Steps for the operator's agent

1. Run `deterministic-harness.sh` for both variants.
2. If PASS: check log message wording — does it tell the operator
   what to DO (free disk space; rotate audit logs early; etc.)?
3. If FAIL: surface immediately — this is the #1 production-risk
   path for any audit-logging system.

## MCP tools

| Tool | Purpose |
|---|---|
| `bounce_query_audit_long_range` | Confirm bouncer still queryable in pass-through |
| `iam_jit_posture` | Confirm bouncer alive |

Agent LLM reasoning appropriate for actionability rubric.
