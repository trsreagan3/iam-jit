#!/usr/bin/env bash
# L7 — crash recovery.
# Stage A skeleton; Stage B implements SIGKILL + restart + chain check.
set -euo pipefail

SCENARIO_ID="L7"
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
#   1. Bring up bouncer in scenario state dir.
#   2. Drive 10 baseline requests; capture audit tail seq via
#      bounce_query_audit_long_range.
#   3. Start traffic-generator subshell (1 req/sec for 30s).
#   4. mid-traffic: kill -9 ${BOUNCER_PID}; wait 5s.
#   5. Restart bouncer; poll /healthz until 200 (timeout 30s).
#   6. Re-query audit; assert SQLite opens cleanly + chain continuous
#      OR gap explicitly logged.
#   7. Check no other process bound the port during the kill window
#      (orphan-bind detection).
#   8. emit_result with evidence.

emit_result "SKIP" '{"stage":"A","depends_on":"L2"}' '"Stage A skeleton — Stage B implements SIGKILL + restart"'
exit 0
