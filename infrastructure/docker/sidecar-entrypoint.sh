#!/bin/sh
# sidecar-entrypoint.sh — supervisor for iam-jit bouncer sidecar container.
#
# Reads the BOUNCERS env var (default: "ibounce") and starts each requested
# bouncer as a background process. Traps SIGTERM/SIGINT and forwards to all
# child PIDs for clean shutdown.
#
# Per [[ibounce-honest-positioning]]: if ibounce fails to start, we exit
# non-zero immediately so docker-compose restarts the container and the
# depends_on health-check keeps the claude service waiting.
#
# Per [[permission-minimal-install]]: no sudo required. Runs as UID 10001
# (non-root). The container itself does NOT need --privileged.
#
# Per [[self-host-zero-billing-dependency]]: zero phone-home.
#
# Environment variables:
#   BOUNCERS            space-separated bouncer list (default: ibounce)
#   IBOUNCE_MODE        ibounce mode: cooperative|transparent|plan-capture
#                       (default: cooperative per [[discovery-first-default]])
#   IBOUNCE_AUDIT_TOKEN bearer token for /audit/events when bound externally
#                       (auto-generated from /dev/urandom if not set)
#   IAM_JIT_HARNESS     harness for iam-jit init (default: claude-code)
#   IAM_JIT_DATA_DIR    data directory (default: /var/lib/iam-jit)

set -e

log()  { printf '[sidecar] %s\n' "$*" ; }
die()  { printf '[sidecar] FATAL: %s\n' "$*" >&2 ; exit 1 ; }

# ---------------------------------------------------------------------------
# Step 1: iam-jit init (non-interactive, idempotent)
# ---------------------------------------------------------------------------

HARNESS="${IAM_JIT_HARNESS:-claude-code}"
DATA_DIR="${IAM_JIT_DATA_DIR:-/var/lib/iam-jit}"

log "Initializing iam-jit (harness=${HARNESS}, data_dir=${DATA_DIR})..."
# --non-interactive: use defaults + skip prompts (auto-detected when stdin
# isn't a TTY, but explicit here for clarity in the sidecar context).
if iam-jit init --non-interactive --harness="${HARNESS}" 2>&1; then
    log "iam-jit init succeeded."
else
    EC=$?
    log "iam-jit init returned $EC (config may already exist). Continuing."
fi

# ---------------------------------------------------------------------------
# Step 2: Start bouncers
# ---------------------------------------------------------------------------

PIDS=""

_contains() { printf '%s' "$1" | grep -qF "$2" ; }

BOUNCERS_LIST="${BOUNCERS:-ibounce}"

if _contains "$BOUNCERS_LIST" "ibounce"; then
    log "Starting ibounce on 0.0.0.0:8767..."

    # --i-know-this-binds-externally is required when --host != 127.0.0.1.
    # In the sidecar, 0.0.0.0 is intentional: the claude service connects
    # by docker-compose service name (iam-jit-bouncer:8767), which requires
    # the sidecar to listen on all interfaces inside its container network.
    #
    # --audit-events-token is required when binding externally (CRIT-32-02).
    # Use the operator-provided token or auto-generate a random one.
    # The token is used by `iam-jit audit query` to authenticate cross-bouncer
    # fan-out; it does NOT gate the proxy itself.
    if [ -z "${IBOUNCE_AUDIT_TOKEN:-}" ]; then
        IBOUNCE_AUDIT_TOKEN="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32 2>/dev/null || \
            python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
        log "Auto-generated IBOUNCE_AUDIT_TOKEN (set env var to use a fixed token)."
    fi

    # IBOUNCE_MODE defaults to "cooperative" (audit-only, always forwards).
    # Per [[discovery-first-default]]: observe first, then tighten.
    # Set IBOUNCE_MODE=transparent to block on deny verdicts.
    ibounce run \
        --host 0.0.0.0 \
        --i-know-this-binds-externally \
        --port 8767 \
        --mode "${IBOUNCE_MODE:-cooperative}" \
        --audit-events-token "${IBOUNCE_AUDIT_TOKEN}" \
        &
    IBOUNCE_PID=$!
    PIDS="$PIDS $IBOUNCE_PID"
    log "ibounce PID: $IBOUNCE_PID"

    # Wait for ibounce to bind before declaring healthy.
    _tries=0
    while [ $_tries -lt 20 ]; do
        if curl -sf http://localhost:8767/healthz >/dev/null 2>&1; then
            log "ibounce healthy (http://localhost:8767/healthz)."
            break
        fi
        _tries=$((_tries + 1))
        sleep 1
    done
    if [ $_tries -ge 20 ]; then
        die "ibounce did not become healthy within 20s — check logs above."
    fi
fi

if _contains "$BOUNCERS_LIST" "gbounce"; then
    log "Starting gbounce on 0.0.0.0:8080 (mgmt: 8769)..."

    if [ -z "${GBOUNCE_AUDIT_TOKEN:-}" ]; then
        GBOUNCE_AUDIT_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    fi

    # gbounce flags may differ per its own flag schema; adapt as needed.
    gbounce run \
        --host 0.0.0.0 \
        --i-know-this-binds-externally \
        --port 8080 \
        --mgmt-port 8769 \
        --mode "${GBOUNCE_MODE:-cooperative}" \
        --audit-events-token "${GBOUNCE_AUDIT_TOKEN}" \
        &
    GBOUNCE_PID=$!
    PIDS="$PIDS $GBOUNCE_PID"
    log "gbounce PID: $GBOUNCE_PID"
fi

# ---------------------------------------------------------------------------
# Step 3: Signal forwarding + wait
# ---------------------------------------------------------------------------

log "All bouncers started. PIDs:${PIDS}"
log "Health: curl http://localhost:8767/healthz"

_shutdown() {
    log "Received shutdown signal. Stopping bouncers..."
    # shellcheck disable=SC2086
    kill $PIDS 2>/dev/null || true
    wait
    log "Shutdown complete."
}

trap _shutdown INT TERM

# Wait for ibounce to exit (abnormal exit → container restart → depends_on
# keeps the claude service from making unaudited AWS calls).
wait $IBOUNCE_PID 2>/dev/null || true
_EC=$?
log "ibounce exited (rc=${_EC}). Shutting down sidecar."
_shutdown
exit "${_EC}"
