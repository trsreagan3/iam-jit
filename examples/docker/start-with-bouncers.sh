#!/bin/sh
# start-with-bouncers.sh — Pattern A entrypoint wrapper.
#
# Starts ibounce in the background, runs iam-jit init (non-interactive if no
# TTY), then execs the user's command. Stops ibounce on exit.
#
# Usage in Dockerfile:
#   ENTRYPOINT ["/usr/local/bin/start-with-bouncers"]
#   CMD ["bash"]
#
# Usage at runtime:
#   docker run my-claude-with-bouncers claude "Write a hello-world Lambda"
#   docker run my-claude-with-bouncers python3 my_agent.py

set -e

log() { printf '[iam-jit] %s\n' "$*" ; }

DATA_DIR="${IAM_JIT_DATA_DIR:-/var/lib/iam-jit}"
HARNESS="${IAM_JIT_HARNESS:-claude-code}"

# ---------------------------------------------------------------------------
# 1. Non-interactive init (only when config doesn't exist)
# ---------------------------------------------------------------------------
if [ ! -f "${DATA_DIR}/iam-jit.yaml" ]; then
    log "Running iam-jit init --non-interactive --harness=${HARNESS}..."
    iam-jit init --non-interactive --harness="${HARNESS}" 2>&1 \
        || log "init returned non-zero; continuing anyway."
fi

# ---------------------------------------------------------------------------
# 2. Start ibounce in background
# ---------------------------------------------------------------------------
log "Starting ibounce on 127.0.0.1:8767..."
ibounce run --mode cooperative &
IBOUNCE_PID=$!

# Wait for ibounce to bind.
_tries=0
while [ $_tries -lt 15 ]; do
    if curl -sf http://127.0.0.1:8767/healthz >/dev/null 2>&1; then
        log "ibounce ready (decisions_count=$(curl -s http://127.0.0.1:8767/healthz | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("decisions_count",0))' 2>/dev/null || echo '?'))."
        break
    fi
    _tries=$((_tries + 1))
    sleep 1
done
if [ $_tries -ge 15 ]; then
    log "WARNING: ibounce did not respond in 15s. AWS calls may not be gated."
fi

# ---------------------------------------------------------------------------
# 3. Signal forwarding + exec user command
# ---------------------------------------------------------------------------
_shutdown() {
    log "Stopping ibounce..."
    kill "$IBOUNCE_PID" 2>/dev/null || true
    wait "$IBOUNCE_PID" 2>/dev/null || true
}
trap _shutdown INT TERM EXIT

log "Handing off to: $*"
exec "$@"
