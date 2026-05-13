#!/usr/bin/env bash
# scripts/test-local.sh — orchestrate the three testing tiers.
#
# Usage:
#   scripts/test-local.sh              # run unit tests (Tier 1, no docker)
#   scripts/test-local.sh unit         # same as above
#   scripts/test-local.sh up           # bring up the docker test stack
#   scripts/test-local.sh integration  # bring up the stack + run integration
#   scripts/test-local.sh e2e          # bring up the stack + run e2e
#   scripts/test-local.sh down         # tear down the stack
#   scripts/test-local.sh logs         # tail container logs
#   scripts/test-local.sh shell-ls     # exec into LocalStack
#   scripts/test-local.sh shell-ollama # exec into Ollama

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

compose_file="docker-compose.test.yml"
venv_pytest="$repo_root/.venv/bin/pytest"

if [[ ! -x "$venv_pytest" ]]; then
  echo "venv not found at $venv_pytest" >&2
  echo "Run: python3 -m venv .venv && .venv/bin/pip install -e .[dev]" >&2
  exit 1
fi

up() {
  docker compose -f "$compose_file" up -d
  echo
  echo "Waiting for LocalStack to become healthy..."
  for _ in {1..40}; do
    if curl -sf http://localhost:4566/_localstack/health >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  echo "Stack is up."
  echo "  LocalStack: http://localhost:4566"
  echo "  Ollama:     http://localhost:11434"
  echo
  echo "First run? Pull the test model into Ollama:"
  echo "  scripts/pull-test-models.sh"
}

down() {
  docker compose -f "$compose_file" down -v
}

case "${1:-unit}" in
  unit)
    "$venv_pytest" -q
    ;;
  up)
    up
    ;;
  integration)
    up
    "$venv_pytest" -q -m integration
    ;;
  e2e)
    up
    "$venv_pytest" -q -m e2e
    ;;
  down)
    down
    ;;
  logs)
    docker compose -f "$compose_file" logs -f
    ;;
  shell-ls)
    docker exec -it iam-jit-localstack bash
    ;;
  shell-ollama)
    docker exec -it iam-jit-ollama bash
    ;;
  *)
    echo "Unknown command: $1" >&2
    echo "Try: unit | up | integration | e2e | down | logs | shell-ls | shell-ollama" >&2
    exit 2
    ;;
esac
