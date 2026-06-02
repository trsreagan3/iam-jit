#!/usr/bin/env sh
# install.sh — iam-jit + Bounce-suite bootstrap installer
#
# Usage (pipe-to-sh, no sudo required at runtime):
#   curl -fsSL https://raw.githubusercontent.com/trsreagan3/iam-jit/main/install.sh | sh
#
# Or with options:
#   curl -fsSL ... | IAM_JIT_BOUNCERS=ibounce,gbounce sh
#   curl -fsSL ... | IAM_JIT_SKIP_GO=1 sh          # skip Go bouncers
#   curl -fsSL ... | IAM_JIT_SKIP_INIT=1 sh         # skip iam-jit init
#
# Per [[permission-minimal-install]]: no sudo required.
#   - Inside containers (root at build time): pip install uses system Python.
#   - On developer laptops (non-root): uses --user install + ~/.local/bin.
# Per [[ibounce-honest-positioning]]: no silent degradation.
# Per [[self-host-zero-billing-dependency]]: zero phone-home at runtime.
#
# Supported environments:
#   - Debian/Ubuntu (apt; python:3.x-slim, ubuntu:*, debian:*)
#   - Fedora/RHEL/Rocky/Alma (dnf/yum)
#   - Alpine (apk; alpine:*)
#   - macOS (Homebrew Python via pipx, or system Python)
#   - Any distro with Python 3.10+ already present
#
# Environment overrides:
#   IAM_JIT_REPO        GitHub repo slug (default: trsreagan3/iam-jit)
#   IAM_JIT_REF         git ref to install (default: main)
#   IAM_JIT_BOUNCERS    comma-separated bouncers to install
#                       (default: ibounce; options: ibounce,kbounce,dbounce,gbounce)
#   IAM_JIT_SKIP_GO     set to 1 to skip Go bouncer installation
#   IAM_JIT_SKIP_INIT   set to 1 to skip iam-jit init
#   IAM_JIT_HARNESS     harness for non-interactive init (default: claude-code)
#   IAM_JIT_DATA_DIR    override data dir (default: ~/.iam-jit or /var/lib/iam-jit)

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

IAM_JIT_REPO="${IAM_JIT_REPO:-trsreagan3/iam-jit}"
IAM_JIT_REF="${IAM_JIT_REF:-main}"
IAM_JIT_BOUNCERS="${IAM_JIT_BOUNCERS:-ibounce}"
IAM_JIT_SKIP_GO="${IAM_JIT_SKIP_GO:-0}"
IAM_JIT_SKIP_INIT="${IAM_JIT_SKIP_INIT:-0}"
IAM_JIT_HARNESS="${IAM_JIT_HARNESS:-claude-code}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '[iam-jit install] %s\n' "$*" ; }
warn() { printf '[iam-jit install] WARN: %s\n' "$*" >&2 ; }
die()  { printf '[iam-jit install] ERROR: %s\n' "$*" >&2 ; exit 1 ; }

running_as_root() { [ "$(id -u)" -eq 0 ] ; }

# Detect whether we're inside a container (any OCI/Docker env).
in_container() {
    # /proc/1/cgroup contains "docker" or "kubepods" when inside a container.
    # /.dockerenv is written by Docker.
    [ -f /.dockerenv ] \
    || grep -qE "(docker|kubepods|lxc)" /proc/1/cgroup 2>/dev/null \
    || [ "${container:-}" = "docker" ]
}

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        printf '%s' "${ID:-unknown}"
    elif [ "$(uname -s)" = "Darwin" ]; then
        printf 'macos'
    else
        printf 'unknown'
    fi
}

OS_ID="$(detect_os)"

# ---------------------------------------------------------------------------
# Python detection + install
# ---------------------------------------------------------------------------

find_python() {
    for candidate in python3 python python3.12 python3.11 python3.10; do
        if command -v "$candidate" >/dev/null 2>&1; then
            ver="$("$candidate" -c 'import sys; print(sys.version_info[:2])' 2>/dev/null || true)"
            # Require >= (3, 10)
            if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
                printf '%s' "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

ensure_python() {
    if find_python >/dev/null 2>&1; then
        PYTHON="$(find_python)"
        log "Using Python: $PYTHON ($($PYTHON --version 2>&1))"
        return 0
    fi

    log "Python 3.10+ not found — installing via package manager..."
    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop)
            apt-get update -qq
            apt-get install -y --no-install-recommends python3 python3-pip python3-venv curl ca-certificates
            ;;
        fedora|rhel|rocky|alma|centos)
            dnf install -y python3 python3-pip curl ca-certificates 2>/dev/null \
            || yum install -y python3 python3-pip curl ca-certificates
            ;;
        alpine)
            apk add --no-cache python3 py3-pip curl ca-certificates
            ;;
        *)
            die "Cannot auto-install Python on OS '$OS_ID'. Install Python 3.10+ manually and re-run."
            ;;
    esac

    PYTHON="$(find_python)" || die "Python install succeeded but binary not found in PATH."
    log "Installed Python: $PYTHON ($($PYTHON --version 2>&1))"
}

# ---------------------------------------------------------------------------
# pip install strategy — handle PEP 668 + container vs laptop differences
# ---------------------------------------------------------------------------

pip_install() {
    # $1 = package spec (e.g. "git+https://...")
    spec="$1"

    # Inside containers running as root: --break-system-packages is safe.
    # On laptops (non-root): use --user.
    # We also try pipx on macOS Homebrew systems where pip is blocked.

    if running_as_root || in_container; then
        # Root / container: system-wide install is fine.
        # Use --break-system-packages only when the flag is supported (pip >= 23).
        if $PYTHON -m pip install --quiet "$spec" 2>&1 | grep -q "externally-managed"; then
            log "Detected PEP 668 managed environment; using --break-system-packages"
            $PYTHON -m pip install --quiet --break-system-packages "$spec"
        else
            $PYTHON -m pip install --quiet "$spec" || \
            $PYTHON -m pip install --quiet --break-system-packages "$spec"
        fi
    else
        # Non-root: --user first, fall back to pipx on macOS.
        if $PYTHON -m pip install --quiet --user "$spec" 2>&1 | grep -q "externally-managed"; then
            log "Detected PEP 668 + non-root; falling back to pipx"
            if ! command -v pipx >/dev/null 2>&1; then
                $PYTHON -m pip install --quiet --user pipx \
                || brew install pipx 2>/dev/null \
                || die "Cannot install pipx. Install pipx manually: https://pypa.github.io/pipx/"
                # Ensure pipx is on PATH
                export PATH="$HOME/.local/bin:$PATH"
            fi
            pipx install "$(printf '%s' "$spec" | sed 's|git+||')" --force
            return
        fi
        # Ensure ~/.local/bin is on PATH for subsequent commands
        export PATH="$HOME/.local/bin:$PATH"
    fi
}

# ---------------------------------------------------------------------------
# Step 1: Ensure Python
# ---------------------------------------------------------------------------

log "Step 1/4: Checking Python installation..."
ensure_python

# ---------------------------------------------------------------------------
# Step 2: Install iam-jit (includes ibounce as a console-script entry-point)
# ---------------------------------------------------------------------------

log "Step 2/4: Installing iam-jit (+ ibounce) from github.com/${IAM_JIT_REPO}..."

IAM_JIT_PKG="git+https://github.com/${IAM_JIT_REPO}.git@${IAM_JIT_REF}"
pip_install "$IAM_JIT_PKG"

# Verify iam-jit + ibounce are callable
for bin in iam-jit ibounce; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        # Might be in ~/.local/bin after --user install
        export PATH="$HOME/.local/bin:$PATH"
        if ! command -v "$bin" >/dev/null 2>&1; then
            # Try $PYTHON -m iam_jit style as last resort
            warn "$bin not found in PATH after install. Add ~/.local/bin to PATH."
        fi
    fi
done

log "iam-jit: $(iam-jit --version 2>&1 || echo '(version unknown)')"
log "ibounce: $(ibounce --version 2>&1 || echo '(version unknown)')"

# ---------------------------------------------------------------------------
# Step 3: Install Go bouncers (kbounce / dbounce / gbounce) — optional
# ---------------------------------------------------------------------------

_contains() { printf '%s' "$1" | grep -qF "$2" ; }

should_install_go_bouncers() {
    [ "$IAM_JIT_SKIP_GO" = "0" ] \
    && { _contains "$IAM_JIT_BOUNCERS" "kbounce" \
      || _contains "$IAM_JIT_BOUNCERS" "dbounce" \
      || _contains "$IAM_JIT_BOUNCERS" "gbounce" ; }
}

install_go_binary() {
    # $1 = module path e.g. github.com/trsreagan3/kbouncer/cmd/kbounce@latest
    go install "$1"
}

if should_install_go_bouncers; then
    log "Step 3/4: Installing Go bouncers..."

    # Ensure Go is available
    if ! command -v go >/dev/null 2>&1; then
        log "Go not found — installing..."
        case "$OS_ID" in
            ubuntu|debian|linuxmint|pop)
                # Install from golang.org tarball so we get a recent version
                _goarch="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
                _gotar="go1.22.4.linux-${_goarch}.tar.gz"
                curl -fsSL "https://dl.google.com/go/${_gotar}" -o "/tmp/${_gotar}"
                tar -C /usr/local -xzf "/tmp/${_gotar}"
                rm "/tmp/${_gotar}"
                export PATH="/usr/local/go/bin:$PATH"
                ;;
            alpine)
                apk add --no-cache go
                ;;
            fedora|rhel|rocky|alma|centos)
                dnf install -y golang 2>/dev/null || yum install -y golang
                ;;
            *)
                warn "Cannot auto-install Go on '$OS_ID'. Skipping Go bouncers."
                IAM_JIT_SKIP_GO=1
                ;;
        esac
    fi

    if [ "$IAM_JIT_SKIP_GO" = "0" ] && command -v go >/dev/null 2>&1; then
        export GOPATH="${GOPATH:-$HOME/go}"
        export PATH="$GOPATH/bin:$PATH"
        log "Go: $(go version)"

        _contains "$IAM_JIT_BOUNCERS" "kbounce" && {
            log "  installing kbounce..."
            install_go_binary "github.com/trsreagan3/kbouncer/cmd/kbounce@latest"
            log "  kbounce: $(kbounce --version 2>&1 || echo '(version unknown)')"
        }

        _contains "$IAM_JIT_BOUNCERS" "dbounce" && {
            log "  installing dbounce..."
            install_go_binary "github.com/trsreagan3/dbounce/cmd/dbounce@latest"
            log "  dbounce: $(dbounce --version 2>&1 || echo '(version unknown)')"
        }

        _contains "$IAM_JIT_BOUNCERS" "gbounce" && {
            log "  installing gbounce..."
            install_go_binary "github.com/trsreagan3/gbounce/cmd/gbounce@latest"
            log "  gbounce: $(gbounce --version 2>&1 || echo '(version unknown)')"
        }
    fi
else
    log "Step 3/4: Skipping Go bouncers (IAM_JIT_BOUNCERS=${IAM_JIT_BOUNCERS})."
fi

# ---------------------------------------------------------------------------
# Step 4: Non-interactive init (skip in TTY mode — let operator run manually)
# ---------------------------------------------------------------------------

if [ "$IAM_JIT_SKIP_INIT" = "1" ]; then
    log "Step 4/4: Skipping init (IAM_JIT_SKIP_INIT=1)."
elif [ -t 0 ]; then
    # stdin is a TTY — operator can run `iam-jit init` interactively
    log "Step 4/4: Skipping auto-init (interactive TTY detected)."
    log "  Run 'iam-jit init' to complete setup."
else
    # Non-TTY (pipe-to-sh, Dockerfile RUN, CI) — non-interactive init.
    log "Step 4/4: Running iam-jit init --non-interactive --harness=${IAM_JIT_HARNESS}..."
    iam-jit init --non-interactive --harness="${IAM_JIT_HARNESS}" || \
        warn "iam-jit init returned non-zero. Run 'iam-jit init' manually to complete setup."
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

log "Install complete."
log ""
log "Next steps:"
log "  1. Run 'ibounce init && ibounce run' to start the AWS gate."
log "  2. Set AWS_ENDPOINT_URL=http://127.0.0.1:8767 in your agent env."
log "  3. Check 'iam-jit posture' to verify your setup."
log ""
log "Docs: https://github.com/${IAM_JIT_REPO}/blob/main/docs/DOCKER-CLAUDE-INTEGRATION.md"
