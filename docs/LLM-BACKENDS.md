# LLM backends

**Local-dev (agent-in-loop) needs ZERO LLM credentials on the
iam-jit / bouncer side.** Per `[[bouncer-zero-llm-when-agent-in-loop]]`
(2026-05-23): when an agent (Claude Code / Cursor / Codex / Devin /
any MCP client) is in the loop, all intelligent work (deny classify,
profile improvement, NL synthesis, audit-NL, scoring narrative) runs
as MCP tools the agent calls with the agent's OWN credentials. iam-jit
+ bouncers stay deterministic + audit + MCP-server.

**Backend selection (below) is for the standalone / CI / cron mode
only** — explicitly opt in with `--enable-bouncer-side-llm
--llm-backend <name>`. iam-jit's optional LLM commentary adds an
LLM-generated narrative and 1-3 reduction suggestions on top of the
deterministic score. The deterministic score itself NEVER changes —
per [scorer-is-ground-truth](../README.md). The LLM is bounded to
commentary only.

When standalone-mode LLM IS desired, the LLM call is **pluggable**:
pick any of four backends based on your existing vendor relationships,
latency budget, and cost target. None is "the default" —
`IAM_JIT_LLM_BACKEND` selects per deployment; per-account
`llm_preferred_backend` can override per AWS account.

| Backend     | Best for                                       | Latency  | Cost (rough) | Setup                    |
|-------------|-----------------------------------------------|----------|--------------|--------------------------|
| `bedrock`   | AWS-native shops with Bedrock model-access    | 1-3s     | $0.003 in / $0.015 out per 1k tok | AWS approval gate (30-60 day lead time, see [aws-account-verification]) |
| `anthropic` | Shops with an Anthropic console org           | 1-3s     | $0.003 in / $0.015 out per 1k tok | `ANTHROPIC_API_KEY`      |
| `openai`    | Shops with an OpenAI org (or OpenRouter/Azure)| 1-3s     | $0.00015 in / $0.0006 out per 1k tok (gpt-4o-mini) | `OPENAI_API_KEY` (+ optional `OPENAI_BASE_URL`) |
| `ollama`    | Self-host on the iam-jit box; zero phone-home | 2-30s    | $0           | run `ollama` locally     |

Cost numbers are order-of-magnitude estimates surfaced by
`backend.estimate_cost_per_1k()`. Your actual bill depends on your
provider contract.

## Selection precedence

1. Per-account `llm_preferred_backend` (account record field; route
   high-stakes accounts to a specific provider).
2. `IAM_JIT_LLM_BACKEND` env var (deployment default).
3. Legacy `IAM_JIT_LLM` env var (pre-v1.0 contract; still honored).
4. Autoselect: `anthropic` → `openai` → `bedrock` → `ollama` (first
   one whose creds are available wins).

Autoselect deprioritizes Bedrock because the model-access approval
gate has a variable AWS-side lead time. Shops with both an Anthropic
key AND Bedrock enabled get the hosted API by default; explicit env
flips that.

## Per-backend setup

### `bedrock`

```bash
pip install iam-jit[bedrock]      # boto3 is base; this is a no-op extra
export IAM_JIT_LLM_BACKEND=bedrock
export IAM_JIT_BEDROCK_MODEL=anthropic.claude-sonnet-4-6-v1:0
export AWS_REGION=us-east-1
```

Bedrock model-access must be requested + approved in the AWS console
ONCE per account. Plan for 30-60 days lead time on first request.
While you wait, run `anthropic` or `openai` so the Pro feature is
live for customers.

### `anthropic`

```bash
pip install iam-jit[anthropic]
export IAM_JIT_LLM_BACKEND=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
# Optional — defaults to claude-sonnet-4-6
export IAM_JIT_LLM_MODEL=claude-opus-4-7
```

### `openai`

```bash
pip install iam-jit[openai]
export IAM_JIT_LLM_BACKEND=openai
export OPENAI_API_KEY=sk-...
# Optional — for OpenRouter / Azure OpenAI / proxied keys
export OPENAI_BASE_URL=https://your-gateway/v1
# Optional — defaults to gpt-4o-mini
export IAM_JIT_LLM_MODEL=gpt-4o
```

The OpenAI backend uses Chat Completions with
`response_format=json_object` (so the model is guaranteed to emit
parseable JSON). If your provider doesn't support that, set
`IAM_JIT_LLM_BACKEND=anthropic` instead.

### `ollama`

```bash
pip install iam-jit[ollama]   # httpx is base; this is a no-op extra
# In another shell:
ollama serve
ollama pull llama3.2:3b
# Then:
export IAM_JIT_LLM_BACKEND=ollama
export OLLAMA_HOST=http://localhost:11434
export IAM_JIT_LLM_MODEL=llama3.2:3b
```

Per [self-host-zero-billing-dependency], Ollama keeps the whole
scoring loop inside your network — no per-token cost, no provider
relationship.

## Per-account override

For Enterprise customers using the `accounts` registry, each account
record can declare a preferred backend:

```yaml
accounts:
  - account_id: "111111111111"
    alias: prod-payments
    llm_policy: use_llm
    llm_preferred_backend: anthropic   # high-stakes → hosted API
  - account_id: "222222222222"
    alias: dev-sandbox
    llm_policy: use_llm
    llm_preferred_backend: ollama      # dev → local model
  - account_id: "333333333333"
    alias: secrets-vault
    llm_policy: deterministic_only     # never call LLM for this one
```

If the preferred backend has no creds in the running deployment, the
registry falls back to the deployment default rather than failing the
score call (defense-in-depth: never crash a score because of a typo).

## Install everything

For local dev or test rigs that want every backend importable:

```bash
pip install iam-jit[all-llm-backends]
```

This pulls `anthropic` + `openai` SDKs. `boto3` (bedrock) and `httpx`
(ollama) are already base deps.

## Programmatic use

```python
from iam_jit.llm import (
    ScoreContext,
    default_score_backend,
    score_policy,
)

ctx = ScoreContext(
    request_shape={"spec": {"description": "read app logs"}},
    deterministic_score=7,
    deterministic_factors=("wildcard-resource",),
    description="read app logs",
)

# Use whatever the deployment selected:
response = score_policy(my_policy, ctx)

# Or pin a backend for this call:
response = score_policy(my_policy, ctx, preferred_backend="openai")

print(response.narrative)        # 1-3 sentence summary
print(response.suggestions)      # tuple of <=3 reduction sentences
print(response.backend_name)     # which provider answered
print(response.risk_signal)      # advisory 1-10; never overrides deterministic
```

## Selection log

The registry emits an info-level log line every time it picks a
backend so operators can debug "why did my score route to X today":

```
INFO iam_jit.llm.registry: llm.backend.select source=preferred name=openai
INFO iam_jit.llm.registry: llm.backend.select source=env name=anthropic
INFO iam_jit.llm.registry: llm.backend.select source=autoselect name=bedrock
INFO iam_jit.llm.registry: llm.backend.select no backend available; deterministic-only
```

[aws-account-verification]: ./DEPLOYMENT.md#bedrock-only-model-access-prerequisite
[scorer-is-ground-truth]: ../README.md#scoring-philosophy
[self-host-zero-billing-dependency]: ./DEPLOYMENT.md#self-hosted-zero-billing-dependency
