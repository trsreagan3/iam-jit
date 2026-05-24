#!/usr/bin/env bash
# L2 — bootstrap declaration → discovery-mode bring-up.
#
# Mode A (Docker) — reuses L1's install path inside a fresh container,
# places the L2 fixture YAML, manually starts ibounce + gbounce on
# the declared ports, writes a status.json, then runs
# `iam-jit canary verify-setup`.
#
# Notes:
#   * The canary's "deploy" surface (scripts/deploy-canary.sh) is
#     referenced in docs but is NOT present in the repo (see L2
#     finding). This harness emulates the deploy artifact by
#     starting bouncers + writing status.json by hand.
set -euo pipefail

SCENARIO_ID="L2"
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_EPOCH="$(date +%s)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${HOME}/.iam-jit/uat-lifecycle/${SCENARIO_ID}"
RESULTS_FILE="${RESULTS_DIR}/results.jsonl"
mkdir -p "${RESULTS_DIR}"

CONTAINER_NAME=""

cleanup() {
  if [[ -n "${CONTAINER_NAME}" ]]; then
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

emit_result() {
  local status="$1" evidence="$2" reason="${3:-null}"
  local end_epoch duration_sec line os_lower
  end_epoch="$(date +%s)"
  duration_sec=$((end_epoch - START_EPOCH))
  os_lower="$(uname -s | tr '[:upper:]' '[:lower:]')"
  line=$(printf '{"ts":"%s","scenario_id":"%s","status":"%s","evidence":%s,"env":{"os":"%s","container":"ubuntu:22.04","iam_jit_version":%s,"iam_jit_sha":%s,"gbounce_sha":%s,"docker_version":%s},"agent_used":null,"reason":%s,"duration_sec":%d}\n' \
    "${START_TS}" "${SCENARIO_ID}" "${status}" "${evidence}" "${os_lower}" \
    "${IAM_JIT_VERSION_J:-null}" "${IAM_JIT_SHA_J:-null}" "${GBOUNCE_SHA_J:-null}" "${DOCKER_VERSION_J:-null}" \
    "${reason}" "${duration_sec}")
  printf '%s' "${line}" >> "${RESULTS_FILE}"
  echo "${line}"
}

if ! command -v docker >/dev/null 2>&1; then
  emit_result "SKIP" '{"reason":"docker not on PATH"}' '"L2 requires Docker (Mode A)"'
  exit 0
fi

# shellcheck source=../_lib/container.sh
source "${SCRIPT_DIR}/../_lib/container.sh"

DOCKER_VERSION_J="\"$(docker --version | awk '{print $3}' | tr -d ',')\""
IAM_JIT_SHA="$(cd "${IAM_JIT_CANARY_IAM_ROLES_REPO}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
GBOUNCE_SHA="$(cd "${IAM_JIT_CANARY_GBOUNCE_REPO}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
IAM_JIT_SHA_J="\"${IAM_JIT_SHA}\""
GBOUNCE_SHA_J="\"${GBOUNCE_SHA}\""

# Phase 1: spawn + install (depends on L1 path).
CONTAINER_NAME="$(container_spawn "${SCENARIO_ID}")"
container_install_toolchain "${CONTAINER_NAME}" >/dev/null
container_install_iam_jit "${CONTAINER_NAME}" >/dev/null 2>&1 || true
container_install_gbounce "${CONTAINER_NAME}" >/dev/null 2>&1 || true

# Phase 2: place fixture YAML at /root/.iam-jit/canary/.iam-jit.yaml
container_exec "${CONTAINER_NAME}" "mkdir -p /root/.iam-jit/canary"
docker cp "${SCRIPT_DIR}/../../fixtures/canary-yaml/L2-minimal.iam-jit.yaml" \
  "${CONTAINER_NAME}:/root/.iam-jit/canary/.iam-jit.yaml" >/dev/null

# Phase 3: start ibounce + gbounce in discovery mode on declared ports.
# ibounce lands on /usr/local/bin (Python entry-point); gbounce lands
# in /root/go/bin (Go install default — NOT on default PATH; use full path).
container_exec "${CONTAINER_NAME}" "nohup ibounce run --port 17401 >/tmp/ibounce.log 2>&1 < /dev/null &" >/dev/null 2>&1 || true
container_exec "${CONTAINER_NAME}" "nohup /root/go/bin/gbounce --port 17402 --mgmt-port 17412 --allow-connect >/tmp/gbounce.log 2>&1 < /dev/null &" >/dev/null 2>&1 || true
sleep 4
IBOUNCE_PID="$(container_exec "${CONTAINER_NAME}" "pgrep -f 'ibounce.*17401' | head -1" | tail -1 | tr -d '\r\n ')"
GBOUNCE_PID="$(container_exec "${CONTAINER_NAME}" "pgrep -f 'gbounce.*17402' | head -1" | tail -1 | tr -d '\r\n ')"

# (Bouncer bind already waited above with sleep 4.)

# Phase 4: write status.json so verify-setup sees the bouncers.
status_json=$(cat <<JSON
{
  "bouncers": {"ibounce": "discovery", "gbounce": "discovery"},
  "canary_day": 0,
  "commits": {"iam-roles": "${IAM_JIT_SHA}", "gbounce": "${GBOUNCE_SHA}"},
  "daemon_args": {"ibounce": [], "gbounce": ["--allow-connect"]},
  "denies_24h": 0,
  "improvement_cycles": 0,
  "intervention_count_24h": 0,
  "last_corrective_action": null,
  "last_issue_ts": null,
  "llm_mode": "agent-delegated",
  "open_issues_count": 0,
  "pids": {"ibounce": ${IBOUNCE_PID:-0}, "gbounce": ${GBOUNCE_PID:-0}},
  "ports": {"ibounce": 17401, "gbounce": 17402, "gbounce_mgmt": 17412},
  "started_at": "${START_TS}",
  "upstreams": {"ibounce": "real-aws (per-request routing)", "gbounce": "general HTTPS forward proxy"}
}
JSON
)
echo "${status_json}" | docker exec -i "${CONTAINER_NAME}" tee /root/.iam-jit/canary/status.json >/dev/null

# Phase 5: run verify-setup; capture stdout + exit code.
VERIFY_OUT="$(container_exec "${CONTAINER_NAME}" "iam-jit canary verify-setup --json 2>&1" || true)"
VERIFY_EXIT="$(container_exec "${CONTAINER_NAME}" "iam-jit canary verify-setup --json >/dev/null 2>&1; echo \$?" | tail -1 | tr -d '\r\n ')"

# Phase 6: observable-state assertions.
IBOUNCE_ALIVE="$(container_exec "${CONTAINER_NAME}" "kill -0 ${IBOUNCE_PID:-0} 2>/dev/null && echo yes || echo no" | tail -1 | tr -d '\r\n ')"
GBOUNCE_ALIVE="$(container_exec "${CONTAINER_NAME}" "kill -0 ${GBOUNCE_PID:-0} 2>/dev/null && echo yes || echo no" | tail -1 | tr -d '\r\n ')"
IBOUNCE_PORT_BOUND="$(container_exec "${CONTAINER_NAME}" "ss -ltn 2>/dev/null | grep -q ':17401' && echo yes || echo no" | tail -1 | tr -d '\r\n ')"
GBOUNCE_PORT_BOUND="$(container_exec "${CONTAINER_NAME}" "ss -ltn 2>/dev/null | grep -q ':17402' && echo yes || echo no" | tail -1 | tr -d '\r\n ')"
AUDIT_DB_EXISTS="$(container_exec "${CONTAINER_NAME}" "test -f /root/.iam-jit/audit.db && echo yes || echo no" | tail -1 | tr -d '\r\n ')"
AUDIT_DB_WRITABLE="$(container_exec "${CONTAINER_NAME}" "test -w /root/.iam-jit/audit.db 2>/dev/null && echo yes || echo no" | tail -1 | tr -d '\r\n ')"

# Phase 7: pass-through smoke — curl through gbounce should not deny.
PASS_THROUGH_EXIT="$(container_exec "${CONTAINER_NAME}" "curl -sS -x http://127.0.0.1:17402 -m 8 --connect-timeout 5 https://example.com/ -o /dev/null -w '%{http_code}' 2>&1 || echo curl_err" | tail -1 | tr -d '\r\n ')"

# Determine pass/fail.
status="PASS"
reasons=()
[[ "${VERIFY_EXIT}" != "0" ]] && { status="FAIL"; reasons+=("verify_exit=${VERIFY_EXIT}"); }
[[ "${IBOUNCE_ALIVE}" != "yes" ]] && { status="FAIL"; reasons+=("ibounce_dead"); }
[[ "${GBOUNCE_ALIVE}" != "yes" ]] && { status="FAIL"; reasons+=("gbounce_dead"); }
[[ "${IBOUNCE_PORT_BOUND}" != "yes" ]] && { status="FAIL"; reasons+=("ibounce_port_unbound"); }
[[ "${GBOUNCE_PORT_BOUND}" != "yes" ]] && { status="FAIL"; reasons+=("gbounce_port_unbound"); }

reason_j="null"
if [[ ${#reasons[@]} -gt 0 ]]; then
  reason_j="\"$(printf '%s;' "${reasons[@]}" | sed 's/;$//')\""
fi

iam_jit_ver="$(container_exec "${CONTAINER_NAME}" "iam-jit --version 2>&1" | tail -1 | tr -d '\r\n ')"
IAM_JIT_VERSION_J="\"${iam_jit_ver}\""

evidence=$(cat <<EOF
{"verify_setup_exit_code":${VERIFY_EXIT:-99},"ibounce_pid":${IBOUNCE_PID:-0},"gbounce_pid":${GBOUNCE_PID:-0},"ibounce_alive":"${IBOUNCE_ALIVE}","gbounce_alive":"${GBOUNCE_ALIVE}","ibounce_port_bound":"${IBOUNCE_PORT_BOUND}","gbounce_port_bound":"${GBOUNCE_PORT_BOUND}","audit_db_exists":"${AUDIT_DB_EXISTS}","audit_db_writable":"${AUDIT_DB_WRITABLE}","pass_through_http_code":"${PASS_THROUGH_EXIT}"}
EOF
)
evidence="$(echo "${evidence}" | tr -d '\n')"

emit_result "${status}" "${evidence}" "${reason_j}"
[[ "${status}" == "PASS" ]] && exit 0 || exit 1
