# Testing

The project ships three testing tiers. The default is fast and self-contained — no Docker, no AWS, no API keys. The opt-in tiers verify the cloud-agnostic abstractions hold up against real (containerized) services.

The principle: **a contributor should be able to run the entire test suite without an AWS account.** If a test can only pass against real AWS, that's a bug — it means we accidentally hardcoded an AWS-specific URL, region, or behavior.

## Tier 1 — Unit (default)

```
.venv/bin/pytest
```

- All boundaries mocked: AWS via [moto], HTTP via [respx], boto3 via the same.
- No network, no Docker, no API keys.
- ~25 seconds for the whole suite.
- Runs on every commit and in CI.

The `[-m "not integration and not e2e"]` filter is the project default in `pyproject.toml`, so plain `pytest` only runs Tier 1.

### CloudFormation template linting

Tier 1 includes `tests/test_cfn_lint.py` which shells out to
[`cfn-lint`](https://github.com/aws-cloudformation/cfn-lint) against
both deploy templates (`infrastructure/sam/template.yaml` and
`infrastructure/cloudformation/destination-account-roles.yaml`).
Catches CFN-specific issues — wrong property types, missing required
fields, intrinsic-function misuse — that the YAML-only structural
tests in `test_cloudformation_templates.py` can't see. No AWS account
needed. If `cfn-lint` isn't installed, these two tests skip cleanly.

To run just the CFN tests:

```
.venv/bin/pytest tests/test_cfn_lint.py tests/test_cloudformation_templates.py
```

To run cfn-lint by hand against a template you're editing:

```
.venv/bin/cfn-lint infrastructure/sam/template.yaml
```

If a lint rule needs to be suppressed across the whole project,
add it to a `.cfnlintrc` at the repo root rather than editing the
test (so the suppression has a visible-in-PR home).

## Tier 2 — Integration (opt-in)

```
scripts/test-local.sh up           # one-time per session: bring up containers
scripts/pull-test-models.sh        # one-time per docker volume: pull the tiny test model
scripts/test-local.sh integration  # run integration tests (or: pytest -m integration)
```

- LocalStack (community edition, free) emulates IAM, STS, EventBridge, S3, Lambda.
- Ollama runs in a container with `smollm2:135m` (~270 MB) — used **only to verify the HTTP contract**, not the model's quality.
- Tests skip gracefully if the containers aren't running. Never hard-fail.
- ~30 seconds–2 minutes once images are cached.

What Tier 2 proves:
- The IAM provisioning code path Phase 2 will ship works against any S3-compatible / IAM-compatible endpoint, not just AWS.
- The `OllamaBackend`'s HTTP request shape matches what Ollama actually expects.
- We aren't accidentally depending on AWS-only behavior (e.g., service-specific quirks not in LocalStack's emulator).

## Tier 2.5 — LLM behavioral tests (opt-in, three sub-modes)

```
# Replay (deterministic, no LLM needed) — recommended for CI:
IAM_JIT_LLM_REPLAY=1 .venv/bin/pytest -m integration tests/test_intake_llm.py

# Live (calls real LLM, slow but exercises actual behavior):
.venv/bin/pytest -m integration tests/test_intake_llm.py

# Re-record after a prompt change:
IAM_JIT_LLM_RECORD=1 .venv/bin/pytest -m integration tests/test_intake_llm.py
```

These verify that the conversational intake — the user-visible "What can
I help you access?" surface — actually behaves the way the system prompt
claims:

- Empty `Statement: []` is never the final answer
- The model doesn't paraphrase user-typed proper nouns (company names, env aliases)
- It doesn't hallucinate unrelated services
- It honors explicit read-only / read-write requests
- It addresses the user's clarifying questions instead of pivoting

**Three modes selected by env var:**

- **Replay** (`IAM_JIT_LLM_REPLAY=1`): plays back recorded LLM responses
  from `tests/cassettes/intake_llm/<test>.jsonl`. Deterministic, no
  network, no API keys. Fails loudly if a cassette is missing — that's
  the signal to re-record. **This is the CI mode.**
- **Live** (no env vars): calls the real LLM each time. Used during
  local prompt iteration. Skips gracefully if no LLM is reachable.
- **Record** (`IAM_JIT_LLM_RECORD=1`): calls the real LLM, captures every
  response into the cassette. Run once after intentionally changing the
  prompt; commit the updated cassettes alongside the prompt change.

**Recording model.** The shipped cassettes were recorded against
`qwen2.5:14b` running on native Ollama (Apple Silicon, Metal). On a
direct comparison against `llama3.1:8b`:

| Model | Scenarios completed | Total turns | Wall time |
|---|---|---|---|
| llama3.1:8b | 1/5 | 12 | 220s |
| **qwen2.5:14b** | **5/5** | **6** | **320s** |

llama3.1:8b struggles with the multi-rule prompt + org-context
grounding — it asks too many follow-ups and can't reliably follow the
"don't paraphrase proper nouns" rule. qwen2.5:14b handles the prompt
cleanly. If you self-host, use qwen2.5:14b. If you use Bedrock, Sonnet
or Haiku both handle the prompt without issue.

Re-record cassettes by setting `IAM_JIT_LLM_MODEL=qwen2.5:14b` and
running `IAM_JIT_LLM_RECORD=1 pytest -m integration tests/test_intake_llm.py`.

The recording layer is `RecordingBackend` in `iam_jit/llm.py`. It keys
each cassette entry by `sha256(system_prompt + json(messages))`, so any
prompt change immediately misses every existing entry — making prompt
drift visible at PR-review time.

Cassettes are committed to git so the CI run is fully self-contained.
Treat them like fixtures: they're checked into the repo, they belong to
the prompt that produced them, and they should be re-recorded any time
the prompt changes.

## Tier 3 — End-to-end (opt-in, Phase 2+)

```
scripts/test-local.sh e2e
```

- Brings up LocalStack + Ollama, runs the full Lambda code path via `sam local invoke` against LocalStack endpoints.
- Submits a fake role request, watches it move through approval → provisioning → expiry, asserts state at each step.
- Lands in **Phase 2**, when `provision.py` and the SAM template exist. The directory layout is in place; tests are stubbed.
- ~5–10 minutes when fully built out.

## Stack management

```
scripts/test-local.sh up            # bring up the docker test stack
scripts/test-local.sh down          # tear down (also removes named volumes)
scripts/test-local.sh logs          # tail logs from both containers
scripts/test-local.sh shell-ls      # bash into LocalStack container
scripts/test-local.sh shell-ollama  # bash into Ollama container
```

The compose file is `docker-compose.test.yml`. Models persist in the named volume `iam-jit-ollama-models` across `up` / `down` cycles, but `down -v` (which the script uses) wipes the volume. Re-pull with `scripts/pull-test-models.sh` afterward.

A separate `docker-compose.dev.yml` is reserved for Phase 1b — it adds the iam-jit FastAPI app to the same stack so you can click around the UI fully locally, no AWS required.

## Adding tests

| What you're testing | Where it goes | Marker |
|---|---|---|
| Pure logic (schema validation, policy generation, LLM response parsing) | `tests/` | none |
| `boto3` interactions you can mock with moto | `tests/` | none |
| HTTP interactions you can mock with respx | `tests/` | none |
| Real AWS-shaped behavior that needs an emulator (cross-region wiring, IAM-eventual-consistency, etc.) | `tests/integration/` | `@pytest.mark.integration` |
| The full request → approve → provision → expire loop | `tests/e2e/` | `@pytest.mark.e2e` |

If you're tempted to write a test that requires a real AWS account, stop and reach for moto or LocalStack first. That constraint is doing useful work — it forces clean abstractions.

## Why no real AWS in tests

For the same reason no real Anthropic/Bedrock API calls are made in tests:

- **Cost.** Tests should be free to run, including in CI.
- **Reliability.** External service flakiness should not fail your build.
- **Adopters.** A new contributor shouldn't need an AWS account to make a PR.
- **Agnosticism.** Forcing tests to work against a generic AWS-compatible endpoint surfaces hardcoded assumptions about AWS-specific behavior. That's the same property that makes the system itself easier to fork, self-host, and modify.

[moto]: https://github.com/getmoto/moto
[respx]: https://github.com/lundberg/respx
