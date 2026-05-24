# L15 recipe — dynamic-deny lifecycle

Harness-primary. Agent reasoning helps for the cross-protocol
fan-out variant (target shape parsing).

## Steps for the operator's agent

1. Run `deterministic-harness.sh` for both variants.
2. If FAIL on cross-protocol fan-out: HIGH — marketing claim
   "denies a target everywhere it can possibly be reached" is
   broken.
3. If FAIL on `revoke` (rule still in YAML): CRIT — this is the
   exact #463 shape that `docs/CONTRIBUTING.md` was written to
   prevent regressing.

## MCP tools

| Tool | Purpose |
|---|---|
| `bounce_deny_add` | (if exposed via MCP) |
| `bounce_deny_revoke` | (if exposed via MCP) |
| `bounce_query_audit_long_range` | Confirm denies fired post-add + ceased post-revoke |

Agent LLM reasoning appropriate for designing cross-protocol fan-out
targets (which ARN shapes should reach which bouncers).
