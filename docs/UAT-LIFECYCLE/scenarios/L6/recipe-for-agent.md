# L6 recipe — threat-feed lifecycle

Harness-primary. Agent participation valuable for the tamper test —
the operator's agent can construct adversarial payloads to test
edge cases beyond the canned tamper variant.

## Steps for the operator's agent

1. Run `deterministic-harness.sh` (covers pin/list/dry-run/apply/
   revoke/tamper).
2. If PASS: optionally run extended tamper variants — wrong signing
   key, expired payload, mismatched publisher ID. Append additional
   JSONL lines with `evidence.variant: "tamper-wrong-key"` etc.
3. If FAIL on the apply step: this is the highest-severity threat-
   feed bug. Per CONTRIBUTING.md the #463 shape is exactly this
   scenario; surface immediately.

## MCP tools

| Tool | Purpose |
|---|---|
| `iam_jit_updates_list` | Confirm pending feed visible |
| `iam_jit_updates_apply` | Trigger apply (if exposed via MCP) |
| `iam_jit_updates_revoke` | Trigger revoke |
| `bounce_query_audit_long_range` | Confirm rule-effective + post-revoke audit events |

Agent LLM reasoning is appropriate for adversarial tamper variant
design.
