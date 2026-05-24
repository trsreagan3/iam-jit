#!/usr/bin/env bash
# L2 — bootstrap declaration → discovery-mode bring-up.
# Stage A skeleton; Stage B implements the assertions.
set -euo pipefail

SCENARIO_ID="L2"
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_EPOCH="$(date +%s)"
RESULTS_DIR="${HOME}/.iam-jit/uat-lifecycle"
RESULTS_FILE="${RESULTS_DIR}/results.jsonl"
mkdir -p "${RESULTS_DIR}"

emit_result() {
  local status="$1" evidence="$2" reason="${3:-null}"
  local end_epoch duration_sec line
  end_epoch="$(date +%s)"
  duration_sec=$((end_epoch - START_EPOCH))
  line=$(printf '{"ts":"%s","scenario_id":"%s","status":"%s","evidence":%s,"env":{"os":"%s","container":null,"iam_jit_version":null,"iam_jit_sha":null},"agent_used":null,"reason":%s,"duration_sec":%d}\n' \
    "${START_TS}" "${SCENARIO_ID}" "${status}" "${evidence}" "$(uname -s | tr '[:upper:]' '[:lower:]')" "${reason}" "${duration_sec}")
  printf '%s' "${line}" >> "${RESULTS_FILE}"
  echo "${line}"
}

# STAGE-B implementation order:
#   1. Spin Mode A container OR set up Mode B IAM_JIT_HOME.
#   2. Copy fixtures/canary-yaml/L2-minimal.iam-jit.yaml into place.
#   3. Run `iam-jit canary verify-setup`; capture stdout + exit.
#   4. Parse PIDs; assert both bouncers alive + ports bound.
#   5. Call `iam-jit posture --json`; assert mode=discovery for both.
#   6. Stat the audit DB; assert exists + writable.
#   7. Issue a pass-through request; assert NOT denied.
#   8. emit_result with evidence per spec.md.

emit_result "SKIP" '{"stage":"A","depends_on":"L1"}' '"Stage A skeleton — Stage B implements assertions"'
exit 0
