#!/usr/bin/env bash
# L11 — clean uninstall.
# Stage A skeleton. Stage B implements once `iam-jit uninstall` ships
# (see spec.md "Stage A gap" section).
set -euo pipefail

SCENARIO_ID="L11"
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

# Pre-check: does `iam-jit uninstall` exist?
if ! command -v iam-jit >/dev/null 2>&1; then
  emit_result "SKIP" '{"stage":"A","gap":"iam-jit not installed"}' '"iam-jit not on PATH; cannot test uninstall"'
  exit 0
fi

if ! iam-jit --help 2>&1 | grep -q "uninstall"; then
  emit_result "SKIP" '{"stage":"A","gap":"uninstall command not shipped"}' '"iam-jit uninstall not in --help; MRR-4 dependency"'
  exit 0
fi

# STAGE-B implementation order (once uninstall ships):
#   1. Populate state via L1+L2 equivalent setup.
#   2. Run `iam-jit uninstall --yes`; capture exit.
#   3. pgrep for ibounce/gbounce processes; assert empty.
#   4. Stat ~/.iam-jit/, launchd plists, binaries; assert removed.
#   5. Re-install (pip install -e . + go install ./cmd/...); assert
#      iam-jit posture works on a clean re-installed system.

emit_result "SKIP" '{"stage":"A","depends_on":"L1,L2","gap":"awaiting Stage B implementation"}' '"Stage A skeleton — Stage B implements once uninstall command shipped"'
exit 0
