#!/usr/bin/env bash
# L15 — dynamic-deny lifecycle.
# Stage A skeleton.
set -euo pipefail

SCENARIO_ID="L15"
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
#   Variant A: deny add → assert YAML + hot-reload + bouncer denies
#              matching traffic → revoke → assert YAML lacks rule +
#              traffic allowed again.
#   Variant B: stop gbounce; deny add → CLI still exit 0; restart
#              gbounce → assert rule picked up.

emit_result "SKIP" '{"stage":"A","depends_on":"L2","variants":["A","B"]}' '"Stage A skeleton — Stage B implements both variants"'
exit 0
