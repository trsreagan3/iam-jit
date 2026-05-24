# L9 recipe — audit log rotation lifecycle

Harness-primary. Agent reasoning helps interpret retention policy
edge cases.

## Steps for the operator's agent

1. Run `deterministic-harness.sh` (handles the seed + rotate +
   verify cycle).
2. If PASS: log.
3. If FAIL on chain-verify: CRIT — forensic integrity broken.
4. If FAIL on purge-tombstone-present: HIGH — compliance audit
   trail incomplete; operator should know what was purged + when.

## MCP tools

| Tool | Purpose |
|---|---|
| `bounce_query_audit_long_range` | Multi-tier query verification |

No LLM reasoning required for the binary verdict.
