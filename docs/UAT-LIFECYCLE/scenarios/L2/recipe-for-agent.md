# L2 recipe — bootstrap declaration → discovery-mode bring-up

Harness-primary scenario; agent can drive it via MCP for the
verify-setup half.

## Steps for the operator's agent

1. Copy `fixtures/canary-yaml/L2-minimal.iam-jit.yaml` into the
   scenario state dir at `${IAM_JIT_HOME}/canary/.iam-jit.yaml`.
2. Call MCP tool `iam_jit_canary_verify_setup` (or run
   `iam-jit canary verify-setup` directly).
3. Inspect the response: PIDs for ibounce + gbounce, port bindings,
   discovery-mode confirmation.
4. Call `iam_jit_posture` MCP tool — assert both bouncers report
   `mode: discovery`.
5. Issue a pass-through test request through gbounce; confirm via
   `bounce_query_audit_long_range` the request was logged but NOT
   denied.
6. Emit JSONL via the harness.

## MCP tools

| Tool | Purpose |
|---|---|
| `iam_jit_canary_verify_setup` | Confirms bouncers up + discovery mode |
| `iam_jit_posture` | Cross-bouncer mode confirmation |
| `bounce_query_audit_long_range` | Verify the pass-through request landed in audit, was not denied |

No LLM reasoning required.
