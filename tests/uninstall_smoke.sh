#!/usr/bin/env bash
# tests/uninstall_smoke.sh — MRR-4 clean-uninstall smoke test.
#
# Runs the documented uninstall sequence from docs/MRR-4-UNINSTALL.md
# inside a clean Linux container, verifies each step works, and reports
# PASS / PARTIAL / FAIL with evidence.
#
# Per the MRR-4 plan: if uninstall doesn't actually work cleanly, this
# is a CRIT finding to be filed honestly per [[ibounce-honest-positioning]].
#
# Usage:
#   bash tests/uninstall_smoke.sh                  # run via docker (default)
#
# Exit codes:
#   0 = PASS (all uninstall steps verified clean)
#   1 = PARTIAL (some leftover state; not catastrophic)
#   2 = FAIL (uninstall fundamentally broken)
#   3 = test infrastructure error (docker unavailable etc.)

set -u  # NOT set -e — we want to capture partial failures honestly

IAM_ROLES_REPO="${IAM_ROLES_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
IMAGE="${IAM_JIT_UNINSTALL_IMAGE:-python:3.12-slim-bookworm}"
SMOKE_LOG="${SMOKE_LOG:-/tmp/iam-jit-uninstall-smoke.log}"

log() { echo "[smoke] $*" | tee -a "$SMOKE_LOG"; }

: > "$SMOKE_LOG"
log "=== MRR-4 uninstall smoke test ==="
log "image: $IMAGE"
log "repo: $IAM_ROLES_REPO"
log ""

if ! command -v docker >/dev/null 2>&1; then
  log "docker not available; cannot run smoke"
  exit 3
fi

# ---------------------------------------------------------------------------
# The entire smoke sequence runs in ONE container so env state (venv on PATH,
# installed packages, /tmp/iam-roles working copy) persists across phases.
# Each phase logs its own PASS / FAIL markers; outer script greps the log.
# ---------------------------------------------------------------------------
smoke_script='
set -u
echo "[in-container] python: $(python3 --version)"
echo "[in-container] uname: $(uname -a)"

# ===========================================================================
# Phase 1 — INSTALL (we need a real install to uninstall meaningfully)
# ===========================================================================
echo ""
echo "=== PHASE 1: INSTALL ==="

apt-get update -qq >/dev/null 2>&1 || { echo "PHASE1-FAIL: apt-get update"; exit 2; }
apt-get install -y -qq --no-install-recommends git curl sqlite3 ca-certificates procps lsof >/dev/null 2>&1 || { echo "PHASE1-FAIL: apt-get install"; exit 2; }

cp -r /src /tmp/iam-roles
cd /tmp/iam-roles

mkdir -p "$HOME/.iam-jit"
python3 -m venv "$HOME/.iam-jit/venv"
# shellcheck disable=SC1091
. "$HOME/.iam-jit/venv/bin/activate"
pip install --quiet --upgrade pip wheel 2>&1 | tail -3
pip install --quiet -e . 2>&1 | tail -10

if ! command -v iam-jit >/dev/null; then
  echo "PHASE1-FAIL: iam-jit not in PATH after pip install"
  exit 2
fi
if ! command -v ibounce >/dev/null; then
  echo "PHASE1-FAIL: ibounce not in PATH after pip install"
  exit 2
fi

iam-jit --version 2>&1 | head -3 || true
ibounce --version 2>&1 | head -3 || true

# Create representative state files (mimic post-deploy state).
mkdir -p "$HOME/.iam-jit/canary" "$HOME/.iam-jit/bouncer"
echo "{\"pids\":{\"ibounce\":99999}}" > "$HOME/.iam-jit/canary/status.json"
touch "$HOME/.iam-jit/bouncer/state.db"
touch "$HOME/.iam-jit/audit.jsonl"
touch "$HOME/.iam-jit/anomaly-baseline.db"

# Simulate Go binaries for the uninstall step to exercise.
mkdir -p "$HOME/go/bin"
for bin in gbounce kbounce kbouncer dbounce; do
  echo "#!/bin/sh" > "$HOME/go/bin/$bin"
  chmod +x "$HOME/go/bin/$bin"
done

echo "PHASE1-OK"
echo "  venv-size: $(du -sh $HOME/.iam-jit/venv | cut -f1)"

# ===========================================================================
# Phase 2 — UNINSTALL (documented sequence from docs/MRR-4-UNINSTALL.md)
# ===========================================================================
echo ""
echo "=== PHASE 2: UNINSTALL ==="

PHASE2_PARTIAL=0
PHASE2_FAIL=0

# Step 1: SIGTERM any running bouncer processes.
echo "[step 1] SIGTERM bouncers"
for proc in ibounce gbounce kbounce dbounce iam-jit; do
  pkill -TERM -f "$proc run" 2>/dev/null || true
done
sleep 1
echo "  step 1 OK"

# Step 2: pip uninstall iam-jit (env is still activated from phase 1).
echo "[step 2] pip uninstall iam-jit"
pip uninstall -y iam-jit 2>&1 | tail -5
echo "  step 2 OK"

# Step 3: verify console scripts gone (still inside activated venv).
echo "[step 3] verify console scripts gone"
SCRIPTS_REMAINING=""
for script in iam-jit ibounce iam-risk-score iam-jit-bouncer iam-jit-feed-publish; do
  if [ -e "$HOME/.iam-jit/venv/bin/$script" ]; then
    SCRIPTS_REMAINING="$SCRIPTS_REMAINING $script"
  fi
done
if [ -n "$SCRIPTS_REMAINING" ]; then
  echo "  PARTIAL: console scripts remain in venv:$SCRIPTS_REMAINING"
  PHASE2_PARTIAL=$((PHASE2_PARTIAL+1))
else
  echo "  console scripts removed from venv OK"
fi

# Step 4: clean Go binaries.
echo "[step 4] clean Go binaries"
GO_REMOVED=""
for bin in gbounce kbounce kbouncer dbounce; do
  if [ -e "$HOME/go/bin/$bin" ]; then
    rm -f "$HOME/go/bin/$bin" && GO_REMOVED="$GO_REMOVED $bin"
  fi
done
echo "  removed:$GO_REMOVED"

# Step 5: verify no orphan bouncer processes.
# Match the process EXECUTABLE name (not full cmdline) to avoid matching
# the smoke-script bash itself which contains the literal "ibounce run" string.
echo "[step 5] verify no orphan bouncer processes"
ORPHANS=""
for proc in ibounce gbounce kbounce dbounce; do
  # pgrep -x matches process basename; ignore self bash PID.
  for pid in $(pgrep -x "$proc" 2>/dev/null || true); do
    ORPHANS="$ORPHANS $proc(pid=$pid)"
  done
done
if [ -n "$ORPHANS" ]; then
  echo "  FAIL: orphan processes:$ORPHANS"
  PHASE2_FAIL=$((PHASE2_FAIL+1))
else
  echo "  no orphan processes OK"
fi

# Step 6: verify bouncer ports are free.
echo "[step 6] verify bouncer ports free"
PORT_OCCUPANTS=""
for port in 7401 7402 7412 8767; do
  if lsof -nP -iTCP:$port -sTCP:LISTEN 2>/dev/null | grep -q LISTEN; then
    PORT_OCCUPANTS="$PORT_OCCUPANTS $port"
  fi
done
if [ -n "$PORT_OCCUPANTS" ]; then
  echo "  FAIL: ports in use:$PORT_OCCUPANTS"
  PHASE2_FAIL=$((PHASE2_FAIL+1))
else
  echo "  ports 7401/7402/7412/8767 free OK"
fi

# Step 7: remove venv.
echo "[step 7] remove venv (~/.iam-jit/venv)"
deactivate 2>/dev/null || true
rm -rf "$HOME/.iam-jit/venv"
if [ -d "$HOME/.iam-jit/venv" ]; then
  echo "  FAIL: venv still present"
  PHASE2_FAIL=$((PHASE2_FAIL+1))
else
  echo "  venv removed OK"
fi

# Step 8: report on data-bearing files (operator-confirmation required to delete).
echo "[step 8] report on data-bearing files"
DATA_FILES=""
for f in "$HOME/.iam-jit/audit.jsonl" "$HOME/.iam-jit/anomaly-baseline.db" "$HOME/.iam-jit/bouncer/state.db"; do
  if [ -e "$f" ]; then
    DATA_FILES="$DATA_FILES $f"
  fi
done
if [ -n "$DATA_FILES" ]; then
  echo "  data-bearing files PRESENT (operator decision):$DATA_FILES"
  echo "  per MRR-4-UNINSTALL.md: operator MUST explicitly delete these"
else
  echo "  no data-bearing files left"
fi

# Step 9: purge mode (full wipe — explicit operator choice).
echo "[step 9] purge mode: removing all ~/.iam-jit/"
rm -rf "$HOME/.iam-jit"
if [ -d "$HOME/.iam-jit" ]; then
  echo "  FAIL: ~/.iam-jit still present after purge"
  PHASE2_FAIL=$((PHASE2_FAIL+1))
else
  echo "  ~/.iam-jit removed OK"
fi

# Step 10: re-install verification on the cleaned system.
echo "[step 10] re-install verification"
cd /tmp/iam-roles
mkdir -p "$HOME/.iam-jit"
python3 -m venv "$HOME/.iam-jit/venv"
# shellcheck disable=SC1091
. "$HOME/.iam-jit/venv/bin/activate"
pip install --quiet -e . 2>&1 | tail -3
if ! command -v iam-jit >/dev/null; then
  echo "  FAIL: iam-jit not in PATH after re-install"
  PHASE2_FAIL=$((PHASE2_FAIL+1))
else
  iam-jit --version 2>&1 | head -1
  echo "  re-install OK"
fi

# Phase 2 summary.
echo ""
if [ $PHASE2_FAIL -gt 0 ]; then
  echo "PHASE2-FAIL ($PHASE2_FAIL fail / $PHASE2_PARTIAL partial)"
  exit 2
elif [ $PHASE2_PARTIAL -gt 0 ]; then
  echo "PHASE2-PARTIAL ($PHASE2_PARTIAL partial)"
  exit 1
else
  echo "PHASE2-OK"
  exit 0
fi
'

docker run --rm \
  -v "$IAM_ROLES_REPO":/src:ro \
  "$IMAGE" \
  bash -c "$smoke_script" >>"$SMOKE_LOG" 2>&1

container_rc=$?
# Also surface key lines to stdout for the operator.
grep -E "^\[in-container\]|^=== PHASE|^\[step|^  (PASS|FAIL|PARTIAL|OK|no orphan|ports |venv |~/\.iam-jit|console scripts|removed|re-install|data-bearing)|^PHASE[12]-(OK|FAIL|PARTIAL)" "$SMOKE_LOG" || true

# ---------------------------------------------------------------------------
# Outer summary
# ---------------------------------------------------------------------------
log ""
log "=== MRR-4 uninstall smoke test summary ==="

PASS_CT=$(grep -c "PHASE1-OK\|PHASE2-OK" "$SMOKE_LOG" 2>/dev/null || echo 0)
FAIL_CT=$(grep -c "PHASE1-FAIL\|PHASE2-FAIL" "$SMOKE_LOG" 2>/dev/null || echo 0)
PARTIAL_CT=$(grep -c "PHASE2-PARTIAL" "$SMOKE_LOG" 2>/dev/null || echo 0)

log "PASS marks:    $PASS_CT"
log "PARTIAL marks: $PARTIAL_CT"
log "FAIL marks:    $FAIL_CT"
log "container exit: $container_rc"
log "log: $SMOKE_LOG"
log ""

if [ "$container_rc" -eq 0 ]; then
  log "RESULT: PASS — uninstall path verified clean in $IMAGE"
  exit 0
elif [ "$container_rc" -eq 1 ]; then
  log "RESULT: PARTIAL — uninstall mostly works; gaps documented in log"
  exit 1
else
  log "RESULT: FAIL — uninstall path has CRIT-level breakage; see log"
  exit 2
fi
