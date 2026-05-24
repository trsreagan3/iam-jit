#!/usr/bin/env bash
# L1 — fresh install on clean system.
#
# Stage A: SKELETON harness. Stage B will fill in container spin-up
# + actual assertion logic. The shape + JSONL contract are fixed;
# Stage B implements the bodies marked `# STAGE-B:`.
#
# Per docs/UAT-LIFECYCLE/HARNESS-SPEC.md the harness MUST:
#   - emit exactly one JSONL line on every exit path
#   - sanitize operator-identifying data before writing
#   - verify observable state, not just exit codes
#   - support both Mode A (Docker) + Mode B (ephemeral dir)
set -euo pipefail

SCENARIO_ID="L1"
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_EPOCH="$(date +%s)"
RESULTS_DIR="${HOME}/.iam-jit/uat-lifecycle"
RESULTS_FILE="${RESULTS_DIR}/results.jsonl"
mkdir -p "${RESULTS_DIR}"

emit_result() {
  # $1=status, $2=evidence-json, $3=reason-or-null
  local status="$1" evidence="$2" reason="${3:-null}"
  local end_epoch duration_sec line
  end_epoch="$(date +%s)"
  duration_sec=$((end_epoch - START_EPOCH))
  # STAGE-B: pipe through _lib/sanitize.sh once it lands.
  line=$(printf '{"ts":"%s","scenario_id":"%s","status":"%s","evidence":%s,"env":{"os":"%s","container":null,"iam_jit_version":null,"iam_jit_sha":null},"agent_used":null,"reason":%s,"duration_sec":%d}\n' \
    "${START_TS}" "${SCENARIO_ID}" "${status}" "${evidence}" "$(uname -s | tr '[:upper:]' '[:lower:]')" "${reason}" "${duration_sec}")
  printf '%s' "${line}" >> "${RESULTS_FILE}"
  echo "${line}"
}

# Mode detection.
if command -v docker >/dev/null 2>&1; then
  MODE="A"
else
  MODE="B"
fi

# STAGE-B implementation order:
#   1. (Mode A) docker run a fresh ubuntu:22.04 container with /src
#      mounted; run the install commands inside it. (Mode B) export
#      IAM_JIT_HOME to an ephemeral dir; run on host.
#   2. Capture: pip exit code, go exit code, iam-jit --version,
#      gbounce --version.
#   3. Observable-state checks:
#        - test ! -d "${IAM_JIT_HOME}" BEFORE state-writing commands
#        - test -d "${IAM_JIT_HOME}" AFTER `iam-jit posture` (state-writing)
#        - posture output reports `mode: neither`
#        - no background process started (compare `ps` before/after)
#   4. Build the evidence JSON per scenarios/L1/spec.md.
#   5. emit_result PASS|FAIL with the evidence block.
#   6. Tear down the container (`docker rm -f`) or the ephemeral dir.

emit_result "SKIP" '{"stage":"A","note":"harness scaffold landed; Stage B fills implementation"}' '"Stage A skeleton — Stage B implements assertions"'
exit 0
