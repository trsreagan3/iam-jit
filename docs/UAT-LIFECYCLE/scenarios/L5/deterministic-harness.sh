#!/usr/bin/env bash
# L5 — profile lifecycle.
# Recipe-primary scenario; this harness covers state-shape verification
# only. The actual LLM-reasoning steps are in recipe-for-agent.md.
set -euo pipefail

SCENARIO_ID="L5"
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
#   Phase 1: drive synthetic activity from fixtures/workflows/L5-*.md;
#            assert audit event count.
#   Phase 3-state: assert profile file landed on disk with non-zero
#                  rules count (#326/#448 shape check).
#   Phase 3-state: assert OCSF audit event for the out-of-profile deny.
#   Phase 5-state: assert post-rollback profile bytes match pre-snapshot.
#   The Phase 2 + Phase 4 LLM-reasoning happens in recipe; harness only
#   verifies the deterministic side effects.

emit_result "SKIP" '{"stage":"A","depends_on":"L1,L2","primary":"recipe","harness_role":"state-shape only"}' '"Stage A skeleton — Stage B implements state-shape assertions; recipe is primary"'
exit 0
