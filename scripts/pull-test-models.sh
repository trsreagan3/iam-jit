#!/usr/bin/env bash
# scripts/pull-test-models.sh — pull the tiny model used by integration tests.
#
# Defaults to smollm2:135m (~270 MB Q4). Override with IAM_JIT_TEST_OLLAMA_MODEL.
# Models persist in the named volume `iam-jit-ollama-models`, so this is a
# one-time cost per docker-compose lifetime.

set -euo pipefail

model="${IAM_JIT_TEST_OLLAMA_MODEL:-smollm2:135m}"
container="${IAM_JIT_OLLAMA_CONTAINER:-iam-jit-ollama}"

if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
  echo "Ollama container '${container}' is not running." >&2
  echo "Bring it up first: scripts/test-local.sh up" >&2
  exit 1
fi

echo "Pulling ${model} into ${container} ..."
docker exec "$container" ollama pull "$model"
docker exec "$container" ollama list
