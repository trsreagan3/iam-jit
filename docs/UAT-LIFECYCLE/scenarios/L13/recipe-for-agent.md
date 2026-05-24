# L13 recipe — LLM credential rotation (standalone)

**Recipe-primary scenario** because the rotation decisions involve
operator judgment: which provider's rotation pattern is being
modeled (Anthropic / OpenAI / Bedrock / Ollama no-key), how
graceful is "graceful" for this provider, etc.

## Steps for the operator's agent

1. Start mock LLM server (`fixtures/mock-llm/L13-mock-llm-server.py`).
2. Configure bouncer with `--enable-side-llm --llm-backend mock
   --llm-api-key-path ${KEY_PATH}` pointing at the mock.
3. Drive an initial request that triggers a side-LLM call; verify
   200.
4. **Rotation step (agent picks pattern)**:
   * Pattern A: file-based key — write new key to ${KEY_PATH};
     send SIGHUP; assert reload.
   * Pattern B: CLI reload — `iam-jit creds reload`.
   * Pattern C: env-var swap (bouncer reads on each call) — `kill
     -HUP` then update env.
   Agent picks the pattern that matches the operator's intended
   prod rotation cycle + records the choice in evidence.
5. During the rotation window, drive 10 requests/sec; assert ALL
   succeed.
6. Post-rotation: drive 5 requests; confirm new key used (mock
   server logs old-key requests stopped).
7. Emit JSONL via harness.

## MCP tools

| Tool | Purpose |
|---|---|
| `iam_jit_posture` | Confirm bouncer alive throughout |
| `bounce_query_audit_long_range` | Confirm no auth-failure events emitted during rotation |

Agent LLM reasoning appropriate for choosing rotation pattern +
judging whether mid-rotation latency is acceptable.
