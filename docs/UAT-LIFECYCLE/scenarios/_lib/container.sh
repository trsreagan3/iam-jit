#!/usr/bin/env bash
# Shared container helpers for UAT-LIFECYCLE scenarios.
#
# Per HARNESS-SPEC.md Mode A — ubuntu:22.04 base, source mounted RO,
# port range 17400-17499, /root/.iam-jit state root.

set -euo pipefail

# Resolve operator's source checkouts; honor cli_canary.py override pattern.
# _lib is at iam-roles/docs/UAT-LIFECYCLE/scenarios/_lib — repo root is 4 levels up.
: "${IAM_JIT_CANARY_IAM_ROLES_REPO:=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)}"
: "${IAM_JIT_CANARY_GBOUNCE_REPO:=$(cd "${IAM_JIT_CANARY_IAM_ROLES_REPO}/../gbounce" 2>/dev/null && pwd || echo "")}"

UAT_IMAGE="${UAT_IMAGE:-ubuntu:22.04}"
GO_VERSION="${GO_VERSION:-1.26.3}"
GO_ARCH_LINUX="$(uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')"

container_spawn() {
  local scenario_id="$1"
  local name="iam-jit-uat-${scenario_id}-$$"
  docker run --rm -d \
    --name "${name}" \
    -v "${IAM_JIT_CANARY_IAM_ROLES_REPO}":/src/iam-roles:ro \
    -v "${IAM_JIT_CANARY_GBOUNCE_REPO}":/src/gbounce:ro \
    -e IAM_JIT_UAT_SCENARIO="${scenario_id}" \
    -e IAM_JIT_CANARY_IAM_ROLES_REPO=/work/iam-roles \
    -e IAM_JIT_CANARY_GBOUNCE_REPO=/work/gbounce \
    -e DEBIAN_FRONTEND=noninteractive \
    -p 17400-17499:17400-17499 \
    "${UAT_IMAGE}" \
    sleep 3600 >/dev/null
  echo "${name}"
}

container_rm() {
  local name="$1"
  docker rm -f "${name}" >/dev/null 2>&1 || true
}

container_exec() {
  local name="$1"; shift
  docker exec "${name}" bash -c "$*"
}

container_install_toolchain() {
  local name="$1"
  container_exec "${name}" "apt-get update -qq && apt-get install -y -qq python3 python3-pip python3-venv git curl ca-certificates sqlite3 iproute2 >/dev/null" 2>&1
  container_exec "${name}" "curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH_LINUX}.tar.gz -o /tmp/go.tgz && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz && ln -sf /usr/local/go/bin/go /usr/local/bin/go && ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt" 2>&1
  # Copy source to /work (writable).
  container_exec "${name}" "mkdir -p /work && cp -a /src/iam-roles /work/iam-roles && cp -a /src/gbounce /work/gbounce" 2>&1
}

container_install_iam_jit() {
  local name="$1"
  container_exec "${name}" "cd /work/iam-roles && pip3 install -e . --quiet 2>&1 | tail -20"
}

container_install_gbounce() {
  local name="$1"
  container_exec "${name}" "cd /work/gbounce && export PATH=/usr/local/go/bin:/root/go/bin:\$PATH && go install ./cmd/gbounce 2>&1 | tail -20"
}
