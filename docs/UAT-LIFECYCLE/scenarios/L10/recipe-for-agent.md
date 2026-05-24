# L10 recipe — multi-machine config portability

Harness-primary. Agent reasoning helps assess the YAML semantic-diff
question (sort order differences may be acceptable).

## Steps for the operator's agent

1. Run `deterministic-harness.sh`.
2. If the diff fails byte-identity but agent decides it's
   semantic-identity (e.g. reordered list), reclassify as PASS
   with a note in the evidence block (`yaml_byte_diff_but_semantic_match: true`).
3. If schema_version_check is missing: HIGH — this is the wire
   divergence already on record.

## MCP tools

| Tool | Purpose |
|---|---|
| `iam_jit_posture` | Cross-machine smoke verification |
| `bounce_query_audit_long_range` | Verify smoke audit events on Machine B |

Agent LLM reasoning appropriate for semantic-vs-byte diff judgment.
