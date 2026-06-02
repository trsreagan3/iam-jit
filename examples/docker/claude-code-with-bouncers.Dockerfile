# claude-code-with-bouncers.Dockerfile — Pattern A: In-container install
#
# PURPOSE: shows how an operator with an EXISTING Claude-in-Docker setup
# can extend their image to include iam-jit bouncers in ONE RUN block.
#
# The resulting image has:
#   - Everything from the base Claude image (or python:3.12-slim analog)
#   - iam-jit + ibounce installed and ready to run
#   - AWS calls automatically routed through ibounce when
#     AWS_ENDPOINT_URL=http://127.0.0.1:8767 is set in the container
#
# Per [[permission-minimal-install]]: no sudo required at runtime. Build
# stages run as root (container build-time norm); runtime drops to UID 1000
# via USER directive.
#
# USAGE:
#   # Build
#   docker build -f examples/docker/claude-code-with-bouncers.Dockerfile \
#                -t my-claude-with-bouncers:latest .
#
#   # Run interactively (ibounce starts, then claude is available)
#   docker run --rm -it \
#     -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION \
#     -v "$(pwd)/audit-logs:/var/lib/iam-jit" \
#     my-claude-with-bouncers:latest
#
#   # Run a single command (non-interactive, CI-safe)
#   docker run --rm \
#     -e AWS_ACCESS_KEY_ID=fake -e AWS_SECRET_ACCESS_KEY=fake \
#     -e AWS_DEFAULT_REGION=us-east-1 \
#     my-claude-with-bouncers:latest \
#     python3 -c "import boto3; print(boto3.client('sts').get_caller_identity())"
#
# NOTE: anthropics/claude-code:latest is a private/restricted image.
# This file uses python:3.12-slim-bookworm as a drop-in stand-in that
# demonstrates the exact RUN block an operator would add to their own
# Claude-based image. The bouncers work identically regardless of the
# base image, as long as Python 3.10+ is present.
#
# If you have access to anthropics/claude-code:latest, replace the FROM
# line with: FROM anthropics/claude-code:latest

# ---- Change this to your actual Claude image ----
ARG BASE_IMAGE=python:3.12-slim-bookworm
FROM ${BASE_IMAGE}

# Build args — pin repo/ref in CI for reproducible builds.
ARG IAM_JIT_REPO=trsreagan3/iam-jit
ARG IAM_JIT_REF=main
ARG BOUNCERS=ibounce

# ---------------------------------------------------------------------------
# Install iam-jit + bouncers (the block operators copy into their Dockerfile)
# ---------------------------------------------------------------------------
# This is the canonical "add bouncers to my Claude image" block.
# It is intentionally a SINGLE RUN layer to minimize image size.

RUN set -e \
 # Ensure git + curl + ca-certificates are present (most Claude base images
 # already have these; harmless if present).
 && apt-get update -qq \
 && apt-get install -y --no-install-recommends \
        git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 \
 # Install iam-jit (includes ibounce as a console-script entry-point).
 # --break-system-packages is safe inside container build stages (root context).
 && pip install --quiet --break-system-packages \
        "git+https://github.com/${IAM_JIT_REPO}.git@${IAM_JIT_REF}" \
 \
 # Verify both binaries are callable at build time (catches arch/ABI issues).
 && iam-jit --version \
 && ibounce --version \
 \
 # Create writable data dir for audit logs + config.
 && mkdir -p /var/lib/iam-jit/ibounce \
 && chmod 777 /var/lib/iam-jit

# ---------------------------------------------------------------------------
# Runtime environment
# ---------------------------------------------------------------------------

# Route AWS SDK calls through ibounce when it's running.
# Operators can override this by passing -e AWS_ENDPOINT_URL=... at runtime.
ENV AWS_ENDPOINT_URL=http://127.0.0.1:8767 \
    IAM_JIT_DATA_DIR=/var/lib/iam-jit \
    IBOUNCE_DATA_DIR=/var/lib/iam-jit/ibounce

# Persistent audit log volume.
VOLUME ["/var/lib/iam-jit"]

# Advisory: ibounce proxy port
EXPOSE 8767

# Healthcheck: verify ibounce is running (if started) or iam-jit is installed.
# In Pattern A the operator starts ibounce separately; this checks iam-jit.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD iam-jit --version || exit 1

# ---------------------------------------------------------------------------
# Example: default entrypoint starts ibounce then opens a shell
# ---------------------------------------------------------------------------
# In production, operators typically override ENTRYPOINT/CMD with their
# actual agent command. This shell wrapper demonstrates how to start
# ibounce before the main process.

COPY examples/docker/start-with-bouncers.sh /usr/local/bin/start-with-bouncers
RUN chmod +x /usr/local/bin/start-with-bouncers
# Also copy the sidecar entrypoint for reference / reuse.
COPY infrastructure/docker/sidecar-entrypoint.sh /usr/local/bin/sidecar-entrypoint
RUN chmod +x /usr/local/bin/sidecar-entrypoint

ENTRYPOINT ["/usr/local/bin/start-with-bouncers"]
CMD ["bash"]
