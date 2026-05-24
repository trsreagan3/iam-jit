# L13 — LLM credential rotation (standalone mode)

## What this tests

An operator running iam-jit / bouncer in standalone mode
(`--enable-side-llm`) rotates the LLM API key → bouncer handles
gracefully → no failure of in-flight requests.

## Why this matters

Per `[[bouncer-zero-llm-when-agent-in-loop]]`: the default local-dev
mode requires ZERO LLM credentials. BUT standalone mode (CI/CD, cron,
no-agent-in-loop) needs them and the operator will rotate the key on
the normal credential-rotation cycle. The rotation must not knock
the bouncer offline.

## Pass criteria

1. Bring up bouncer with `--enable-side-llm --llm-backend
   <test-backend>` pointed at a mock LLM endpoint that accepts a
   bearer token.
2. Drive a request that triggers a side-LLM call (e.g., deny
   classifier on a borderline event). Confirm 200.
3. Rotate the API key:
   * Write the new key to `${IAM_JIT_LLM_API_KEY_PATH}`.
   * Trigger reload: SIGHUP OR `iam-jit creds reload` (whichever
     the bouncer supports).
4. Assert mid-rotation behaviour:
   * In-flight requests at rotation moment complete successfully
     (with EITHER old or new key, but not failed).
   * No new requests fail during the swap window.
5. Drive a new request post-rotation; confirm 200 with the new key.
6. Verify old key is no longer used (mock endpoint logs old key
   was retired at swap timestamp).

## Fail criteria

* In-flight request dropped during rotation.
* New requests fail post-rotation with auth error.
* Bouncer requires restart to pick up new key (no graceful
  reload — this would make the standalone-mode promise weak).

## Prerequisites

* L2 PASS.
* Mock LLM endpoint fixture
  (`fixtures/mock-llm/L13-mock-llm-server.py`).
* `--enable-side-llm` mode opted in.

## Supported isolation modes

* Mode A or Mode B.

## Expected duration

~5-8 minutes.

## Evidence block schema

```json
{
  "side_llm_enabled": true,
  "initial_request_succeeded": true,
  "key_rotation_method": "sighup|cli_reload",
  "in_flight_completed": true,
  "post_rotation_request_succeeded": true,
  "old_key_retired_observable": true,
  "restart_required": false
}
```
