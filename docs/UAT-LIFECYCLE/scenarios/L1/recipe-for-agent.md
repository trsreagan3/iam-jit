# L1 recipe — fresh install on clean system

This is a **harness-primary** scenario; the deterministic harness
(`deterministic-harness.sh`) covers all pass-criteria. The recipe is
brief: an agent runs the harness, interprets the JSONL, and files a
regression if anything failed.

## Steps for the operator's agent

1. Verify pre-state: there is NO `~/.iam-jit/` directory in the
   target environment (container or Mode B root).
2. Run:
   ```bash
   bash docs/UAT-LIFECYCLE/scenarios/L1/deterministic-harness.sh
   ```
3. Tail the last line of `~/.iam-jit/uat-lifecycle/results.jsonl`.
4. If `status: PASS`, append a one-line note to
   `~/.iam-jit/canary/notes.md` (only on the operator's REAL canary,
   not the in-scenario one) saying "L1 PASS at <ts>".
5. If `status: FAIL` or `ERROR`: do NOT auto-retry. Surface the
   evidence block to the operator + propose filing a regression
   per `README.md` § "How to file a regression".

## MCP tools the agent may use

| Tool | Why |
|---|---|
| `bounce_query_audit_long_range` | Confirm zero audit events created during install (audit DB shouldn't even exist yet). |
| `iam_jit_posture` | Confirm posture reports `mode: neither` on the clean system. |

No LLM reasoning is required for L1; this is a pure deterministic
check.
