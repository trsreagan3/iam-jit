#!/usr/bin/env bash
# L1 — fresh install on clean system.
#
# Mode A (Docker) implementation. Mounts iam-roles + gbounce checkouts
# read-only into a fresh ubuntu:22.04, installs toolchain, runs pip +
# go install, then verifies observable state per spec.md.
set -euo pipefail

SCENARIO_ID="L1"
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
  emit_result "SKIP" '{"reason":"docker not on PATH"}' '"L1 requires Docker (Mode A)"'
  exit 0
fi

# shellcheck source=../_lib/container.sh
source "${SCRIPT_DIR}/../_lib/container.sh"

DOCKER_VERSION_J="\"$(docker --version | awk '{print $3}' | tr -d ',')\""

CONTAINER_NAME="$(container_spawn "${SCENARIO_ID}")"
container_install_toolchain "${CONTAINER_NAME}" >/dev/null

# Capture pip + go install exit codes (single invocation each).
# Pipe + $? = tail's exit, not pip's. Use set -o pipefail + capture
# directly to a tempfile so EXIT line reflects pip's real exit code.
PIP_OUT="$(container_exec "${CONTAINER_NAME}" "set -o pipefail; cd /work/iam-roles && pip3 install -e . 2>&1 | tail -10; echo EXIT=\${PIPESTATUS[0]}" 2>&1)"
PIP_EXIT="$(echo "${PIP_OUT}" | grep -oE 'EXIT=[0-9]+' | tail -1 | cut -d= -f2)"

GO_OUT="$(container_exec "${CONTAINER_NAME}" "set -o pipefail; cd /work/gbounce && export PATH=/usr/local/go/bin:/root/go/bin:\$PATH && go install ./cmd/gbounce 2>&1 | tail -10; echo EXIT=\${PIPESTATUS[0]}" 2>&1)"
GO_EXIT="$(echo "${GO_OUT}" | grep -oE 'EXIT=[0-9]+' | tail -1 | cut -d= -f2)"

# Detect whether gbounce landed on the default PATH (a `go install`
# drops binaries into $GOPATH/bin which defaults to ~/go/bin, NOT on
# the default ubuntu PATH). This is an L1 finding worth recording: the
# operator must add ~/go/bin to PATH (standard Go ergonomics) for the
# install to be reachable. We probe via full path for the rest of the
# assertions; the missing-PATH state is captured in evidence.
GBOUNCE_ON_DEFAULT_PATH="$(container_exec "${CONTAINER_NAME}" "command -v gbounce >/dev/null 2>&1 && echo yes || echo no" | tail -1 | tr -d '\r\n ')"
GBOUNCE_BIN_EXISTS="$(container_exec "${CONTAINER_NAME}" "test -x /root/go/bin/gbounce && echo yes || echo no" | tail -1 | tr -d '\r\n ')"

# Check ~/.iam-jit/ NOT yet created (lazy).
HOME_EXISTS_PRE="$(container_exec "${CONTAINER_NAME}" "test -d /root/.iam-jit && echo yes || echo no" | tail -1 | tr -d '\r\n ')"

# --version (read-only, must not create state).
IAM_JIT_VER="$(container_exec "${CONTAINER_NAME}" "iam-jit --version 2>&1 | head -3" | tail -1 | tr -d '\r\n')"
GBOUNCE_VER="$(container_exec "${CONTAINER_NAME}" "/root/go/bin/gbounce --version 2>&1 | head -3" | tail -1 | tr -d '\r\n')"

HOME_EXISTS_POST_VERSION="$(container_exec "${CONTAINER_NAME}" "test -d /root/.iam-jit && echo yes || echo no" | tail -1 | tr -d '\r\n ')"

# Snapshot processes.
PS_BEFORE="$(container_exec "${CONTAINER_NAME}" "ps -e -o pid,comm --no-headers | wc -l" | tail -1 | tr -d '\r\n ')"

# Run posture (state-writing/state-aware).
POSTURE_OUT="$(container_exec "${CONTAINER_NAME}" "iam-jit posture --json 2>&1 | tail -30" 2>&1 || true)"
POSTURE_EXIT_RAW="$(container_exec "${CONTAINER_NAME}" "iam-jit posture --json >/dev/null 2>&1; echo \$?" | tail -1 | tr -d '\r\n ')"
POSTURE_EXIT="${POSTURE_EXIT_RAW:-99}"
POSTURE_MODE="$(container_exec "${CONTAINER_NAME}" "iam-jit posture --json 2>/dev/null | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get(\"overall_mode\", d.get(\"mode\", \"unknown\")))
except Exception as e:
    print(\"unknown\")' 2>/dev/null || echo unknown" | tail -1 | tr -d '\r\n ')"

HOME_EXISTS_POST_POSTURE="$(container_exec "${CONTAINER_NAME}" "test -d /root/.iam-jit && echo yes || echo no" | tail -1 | tr -d '\r\n ')"
PS_AFTER="$(container_exec "${CONTAINER_NAME}" "ps -e -o pid,comm --no-headers | wc -l" | tail -1 | tr -d '\r\n ')"
NEW_PROCS="$(container_exec "${CONTAINER_NAME}" "ps -e -o pid,comm --no-headers | grep -vE 'sleep|ps|bash|sh|docker-init|tini|init$' | awk '{print \$2}' | sort -u | tr '\n' ',' | sed 's/,\$//'" | tail -1 | tr -d '\r\n')"

IAM_JIT_SHA="$(cd "${IAM_JIT_CANARY_IAM_ROLES_REPO}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
GBOUNCE_SHA="$(cd "${IAM_JIT_CANARY_GBOUNCE_REPO}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
IAM_JIT_VERSION_J="\"${IAM_JIT_VER}\""
IAM_JIT_SHA_J="\"${IAM_JIT_SHA}\""
GBOUNCE_SHA_J="\"${GBOUNCE_SHA}\""

# Determine PASS/FAIL.
status="PASS"
reasons=()
[[ "${PIP_EXIT:-99}" != "0" ]] && { status="FAIL"; reasons+=("pip_exit=${PIP_EXIT:-99}"); }
[[ "${GO_EXIT:-99}" != "0" ]] && { status="FAIL"; reasons+=("go_exit=${GO_EXIT:-99}"); }
[[ -z "${IAM_JIT_VER}" || "${IAM_JIT_VER}" == *"Traceback"* ]] && { status="FAIL"; reasons+=("iam_jit_version_bad"); }
[[ -z "${GBOUNCE_VER}" || "${GBOUNCE_VER}" == *"unknown"* ]] && { status="FAIL"; reasons+=("gbounce_version_bad:${GBOUNCE_VER}"); }
[[ "${HOME_EXISTS_PRE}" != "no" ]] && { status="FAIL"; reasons+=("home_existed_pre_install"); }
[[ "${HOME_EXISTS_POST_VERSION}" != "no" ]] && { status="FAIL"; reasons+=("home_created_eagerly_by_version"); }
[[ "${POSTURE_EXIT}" != "0" ]] && { status="FAIL"; reasons+=("posture_exit=${POSTURE_EXIT}"); }

reason_j="null"
if [[ ${#reasons[@]} -gt 0 ]]; then
  reason_j="\"$(printf '%s;' "${reasons[@]}" | sed 's/;$//')\""
fi

iam_jit_ver_esc="$(echo "${IAM_JIT_VER}" | sed 's/\\/\\\\/g; s/"/\\"/g')"
gbounce_ver_esc="$(echo "${GBOUNCE_VER}" | sed 's/\\/\\\\/g; s/"/\\"/g')"

evidence=$(cat <<EOF
{"pip_install_exit_code":${PIP_EXIT:-99},"go_install_exit_code":${GO_EXIT:-99},"iam_jit_version":"${iam_jit_ver_esc}","gbounce_version":"${gbounce_ver_esc}","gbounce_on_default_path":"${GBOUNCE_ON_DEFAULT_PATH}","gbounce_binary_at_gopath":"${GBOUNCE_BIN_EXISTS}","iam_jit_home_existed_pre_install":"${HOME_EXISTS_PRE}","iam_jit_home_created_after_version_cmd":"${HOME_EXISTS_POST_VERSION}","iam_jit_home_created_after_posture_cmd":"${HOME_EXISTS_POST_POSTURE}","posture_exit_code":${POSTURE_EXIT},"posture_reported_mode":"${POSTURE_MODE}","ps_count_before":${PS_BEFORE:-0},"ps_count_after":${PS_AFTER:-0},"background_processes_added":"${NEW_PROCS}"}
EOF
)
evidence="$(echo "${evidence}" | tr -d '\n')"

emit_result "${status}" "${evidence}" "${reason_j}"
[[ "${status}" == "PASS" ]] && exit 0 || exit 1
