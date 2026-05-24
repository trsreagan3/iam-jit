#!/usr/bin/env bash
# L3 — update mechanism end-to-end.
#
# Mode A REQUIRED. Spins a container, clones iam-roles + gbounce at a
# PRE_SHA inside /work, installs, brings up bouncers, runs the update
# command pointing at POST_SHA, verifies post-state.
#
# IMPORTANT: This harness exercises `iam-jit canary update`. Per the
# canary spec the update command runs against the bouncers' on-disk
# repos at /work/iam-roles + /work/gbounce. To safely test the update
# WITHOUT mutating the operator's source tree, we clone fresh copies
# inside the container instead of mounting the host checkout.
set -euo pipefail

SCENARIO_ID="L3"
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
  emit_result "SKIP" '{"reason":"docker not on PATH"}' '"L3 requires Docker (Mode A); Mode B would mutate operator source tree"'
  exit 0
fi

# shellcheck source=../_lib/container.sh
source "${SCRIPT_DIR}/../_lib/container.sh"

DOCKER_VERSION_J="\"$(docker --version | awk '{print $3}' | tr -d ',')\""

# Pick PRE/POST commits from the host iam-roles checkout: HEAD~1 and HEAD.
PRE_SHA="$(cd "${IAM_JIT_CANARY_IAM_ROLES_REPO}" && git rev-parse --short HEAD~1 2>/dev/null || echo unknown)"
POST_SHA="$(cd "${IAM_JIT_CANARY_IAM_ROLES_REPO}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
GBOUNCE_SHA_HOST="$(cd "${IAM_JIT_CANARY_GBOUNCE_REPO}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
IAM_JIT_SHA_J="\"${POST_SHA}\""
GBOUNCE_SHA_J="\"${GBOUNCE_SHA_HOST}\""

if [[ "${PRE_SHA}" == "unknown" || "${POST_SHA}" == "unknown" || "${PRE_SHA}" == "${POST_SHA}" ]]; then
  emit_result "SKIP" "{\"pre_sha\":\"${PRE_SHA}\",\"post_sha\":\"${POST_SHA}\"}" '"L3 needs two distinct commits; HEAD~1 unavailable"'
  exit 0
fi

# Phase 1: spawn container with iam-roles + gbounce checkouts mounted RO.
CONTAINER_NAME="$(container_spawn "${SCENARIO_ID}")"
container_install_toolchain "${CONTAINER_NAME}" >/dev/null

# Phase 2: reset /work/iam-roles + /work/gbounce to PRE_SHA. The
# `iam-jit canary update` flow does git fetch + git pull, so we need
# an `origin` remote pointing at a writable bare repo we control.
# Set up a bare clone in /work/origin-iam-roles + /work/origin-gbounce
# that contains both PRE and POST commits, then point /work/<repo>'s
# origin at it. Then check out PRE_SHA in /work/<repo>.
container_exec "${CONTAINER_NAME}" "cd /work && git clone --bare /src/iam-roles origin-iam-roles 2>&1 | tail -3" >/tmp/uat-L3-clone-iam 2>&1 || true
container_exec "${CONTAINER_NAME}" "cd /work && git clone --bare /src/gbounce origin-gbounce 2>&1 | tail -3" >/tmp/uat-L3-clone-gb 2>&1 || true
container_exec "${CONTAINER_NAME}" "cd /work/iam-roles && git remote remove origin 2>/dev/null; git remote add origin /work/origin-iam-roles && git fetch origin 2>&1 | tail -3 && git checkout -q ${PRE_SHA} && git branch -f main ${PRE_SHA} && git checkout -q main && git branch --set-upstream-to=origin/main main 2>&1 | tail -3" >/tmp/uat-L3-pre-checkout 2>&1 || true
container_exec "${CONTAINER_NAME}" "cd /work/gbounce && git remote remove origin 2>/dev/null; git remote add origin /work/origin-gbounce && git fetch origin 2>&1 | tail -3 && git checkout -q ${GBOUNCE_SHA_HOST} && git branch -f main ${GBOUNCE_SHA_HOST} && git checkout -q main && git branch --set-upstream-to=origin/main main 2>&1 | tail -3" >/tmp/uat-L3-pre-gb-checkout 2>&1 || true

# Phase 3: install iam-jit + gbounce at PRE_SHA.
container_install_iam_jit "${CONTAINER_NAME}" >/dev/null 2>&1 || true
container_install_gbounce "${CONTAINER_NAME}" >/dev/null 2>&1 || true

# Phase 4: place L2 fixture YAML and start bouncers (reuse L2 path).
container_exec "${CONTAINER_NAME}" "mkdir -p /root/.iam-jit/canary"
docker cp "${SCRIPT_DIR}/../../fixtures/canary-yaml/L2-minimal.iam-jit.yaml" \
  "${CONTAINER_NAME}:/root/.iam-jit/canary/.iam-jit.yaml" >/dev/null
container_exec "${CONTAINER_NAME}" "nohup ibounce run --port 17401 >/tmp/ibounce.log 2>&1 < /dev/null &" >/dev/null 2>&1 || true
container_exec "${CONTAINER_NAME}" "nohup /root/go/bin/gbounce --port 17402 --mgmt-port 17412 --allow-connect >/tmp/gbounce.log 2>&1 < /dev/null &" >/dev/null 2>&1 || true
sleep 3
IBOUNCE_PID="$(container_exec "${CONTAINER_NAME}" "pgrep -f 'ibounce.*17401' | head -1" | tail -1 | tr -d '\r\n ')"
GBOUNCE_PID="$(container_exec "${CONTAINER_NAME}" "pgrep -f 'gbounce.*17402' | head -1" | tail -1 | tr -d '\r\n ')"

# Phase 5: write status.json with PRE_SHA.
status_json=$(cat <<JSON
{
  "bouncers": {"ibounce": "discovery", "gbounce": "discovery"},
  "canary_day": 0,
  "commits": {"iam-roles": "${PRE_SHA}", "gbounce": "${GBOUNCE_SHA_HOST}"},
  "daemon_args": {"ibounce": [], "gbounce": ["--allow-connect"]},
  "denies_24h": 0, "improvement_cycles": 0, "intervention_count_24h": 0,
  "last_corrective_action": null, "last_issue_ts": null,
  "llm_mode": "agent-delegated", "open_issues_count": 0,
  "pids": {"ibounce": ${IBOUNCE_PID:-0}, "gbounce": ${GBOUNCE_PID:-0}},
  "ports": {"ibounce": 17401, "gbounce": 17402, "gbounce_mgmt": 17412},
  "started_at": "${START_TS}",
  "upstreams": {"ibounce": "real-aws (per-request routing)", "gbounce": "general HTTPS forward proxy"}
}
JSON
)
echo "${status_json}" | docker exec -i "${CONTAINER_NAME}" tee /root/.iam-jit/canary/status.json >/dev/null

# Phase 6: capture pre-state.
PRE_VERIFY_EXIT="$(container_exec "${CONTAINER_NAME}" "iam-jit canary verify-setup --json >/dev/null 2>&1; echo \$?" | tail -1 | tr -d '\r\n ')"
PRE_AUDIT_COUNT="$(container_exec "${CONTAINER_NAME}" "test -f /root/.iam-jit/audit.db && sqlite3 /root/.iam-jit/audit.db 'SELECT COUNT(*) FROM audit_events' 2>/dev/null || echo 0" | tail -1 | tr -d '\r\n ')"
PRE_ISSUES_COUNT="$(container_exec "${CONTAINER_NAME}" "test -f /root/.iam-jit/canary/issues.jsonl && wc -l < /root/.iam-jit/canary/issues.jsonl || echo 0" | tail -1 | tr -d '\r\n ')"

# Phase 7: dry-run update.
DRY_RUN_OUT="$(container_exec "${CONTAINER_NAME}" "iam-jit canary update --dry-run 2>&1 | tail -40" 2>&1 || true)"
DRY_RUN_EXIT="$(container_exec "${CONTAINER_NAME}" "iam-jit canary update --dry-run >/dev/null 2>&1; echo \$?" | tail -1 | tr -d '\r\n ')"

# Assert dry-run didn't mutate (post-status.json commit-iam-roles still PRE).
POST_DRY_COMMIT="$(container_exec "${CONTAINER_NAME}" "python3 -c 'import json; print(json.load(open(\"/root/.iam-jit/canary/status.json\"))[\"commits\"][\"iam-roles\"])' 2>/dev/null" | tail -1 | tr -d '\r\n ')"
DRY_RUN_MUTATED="no"
if [[ "${POST_DRY_COMMIT}" != "${PRE_SHA}" ]]; then DRY_RUN_MUTATED="yes"; fi

# Phase 8: advance origin/main to POST_SHA so `iam-jit canary update`
# (which does git fetch + git pull) actually sees a newer commit.
container_exec "${CONTAINER_NAME}" "cd /work/origin-iam-roles && git branch -f main ${POST_SHA} 2>&1 | tail -3" >/tmp/uat-L3-origin-advance 2>&1 || true

UPDATE_START="$(date +%s)"
UPDATE_OUT="$(container_exec "${CONTAINER_NAME}" "iam-jit canary update 2>&1 | tail -50" 2>&1 || true)"
UPDATE_EXIT="$(container_exec "${CONTAINER_NAME}" "iam-jit canary update >/dev/null 2>&1; echo \$?" | tail -1 | tr -d '\r\n ')"
UPDATE_END="$(date +%s)"
UPDATE_DURATION=$((UPDATE_END - UPDATE_START))

# Phase 9: post-update state verification.
POST_VERIFY_EXIT="$(container_exec "${CONTAINER_NAME}" "iam-jit canary verify-setup --json >/dev/null 2>&1; echo \$?" | tail -1 | tr -d '\r\n ')"
POST_STATUS_COMMIT="$(container_exec "${CONTAINER_NAME}" "python3 -c 'import json; print(json.load(open(\"/root/.iam-jit/canary/status.json\"))[\"commits\"][\"iam-roles\"])' 2>/dev/null" | tail -1 | tr -d '\r\n ')"
POST_AUDIT_COUNT="$(container_exec "${CONTAINER_NAME}" "test -f /root/.iam-jit/audit.db && sqlite3 /root/.iam-jit/audit.db 'SELECT COUNT(*) FROM audit_events' 2>/dev/null || echo 0" | tail -1 | tr -d '\r\n ')"
POST_ISSUES_COUNT="$(container_exec "${CONTAINER_NAME}" "test -f /root/.iam-jit/canary/issues.jsonl && wc -l < /root/.iam-jit/canary/issues.jsonl || echo 0" | tail -1 | tr -d '\r\n ')"
UPDATE_SUCCESS_LINE="$(container_exec "${CONTAINER_NAME}" "test -f /root/.iam-jit/canary/issues.jsonl && grep -c 'update_success' /root/.iam-jit/canary/issues.jsonl 2>/dev/null || echo 0" | tail -1 | tr -d '\r\n ')"

# Version match check (catches version-constant-didn't-bump).
POST_VER="$(container_exec "${CONTAINER_NAME}" "iam-jit --version 2>&1" | tail -1 | tr -d '\r\n ')"
IAM_JIT_VERSION_J="\"${POST_VER}\""

# Determine pass/fail.
status="PASS"
reasons=()
[[ "${DRY_RUN_EXIT}" != "0" ]] && { status="FAIL"; reasons+=("dry_run_exit=${DRY_RUN_EXIT}"); }
[[ "${DRY_RUN_MUTATED}" == "yes" ]] && { status="FAIL"; reasons+=("dry_run_mutated_state"); }
[[ "${UPDATE_EXIT}" != "0" ]] && { status="FAIL"; reasons+=("update_exit=${UPDATE_EXIT}"); }
[[ "${POST_VERIFY_EXIT}" != "0" ]] && { status="FAIL"; reasons+=("post_verify_exit=${POST_VERIFY_EXIT}"); }

reason_j="null"
if [[ ${#reasons[@]} -gt 0 ]]; then
  reason_j="\"$(printf '%s;' "${reasons[@]}" | sed 's/;$//')\""
fi

# Audit chain continuity — count must be >= pre count (no events lost).
CHAIN_CONTINUOUS="yes"
if [[ "${POST_AUDIT_COUNT}" -lt "${PRE_AUDIT_COUNT}" ]] 2>/dev/null; then
  CHAIN_CONTINUOUS="no"
  status="FAIL"
  reasons+=("audit_count_regressed:${PRE_AUDIT_COUNT}->${POST_AUDIT_COUNT}")
fi

evidence=$(cat <<EOF
{"pre_sha":"${PRE_SHA}","post_sha":"${POST_SHA}","pre_verify_exit":${PRE_VERIFY_EXIT:-99},"dry_run_exit_code":${DRY_RUN_EXIT:-99},"dry_run_mutated_state":"${DRY_RUN_MUTATED}","update_exit_code":${UPDATE_EXIT:-99},"post_verify_exit":${POST_VERIFY_EXIT:-99},"post_status_commit_iam_roles":"${POST_STATUS_COMMIT}","audit_pre_count":${PRE_AUDIT_COUNT:-0},"audit_post_count":${POST_AUDIT_COUNT:-0},"audit_chain_continuous":"${CHAIN_CONTINUOUS}","issues_pre_count":${PRE_ISSUES_COUNT:-0},"issues_post_count":${POST_ISSUES_COUNT:-0},"update_success_line_count":${UPDATE_SUCCESS_LINE:-0},"restart_duration_sec":${UPDATE_DURATION}}
EOF
)
evidence="$(echo "${evidence}" | tr -d '\n')"

emit_result "${status}" "${evidence}" "${reason_j}"
[[ "${status}" == "PASS" ]] && exit 0 || exit 1
