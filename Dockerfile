# syntax=docker/dockerfile:1.7
#
# ibounce — AWS IAM safety proxy (multi-stage build).
#
# Per [[ibounce-honest-positioning]] + [[self-host-zero-billing-dependency]]:
# this image is a packaging convenience, NOT a different product. It bundles
# exactly the same `ibounce` binary you get from `pip install iam-jit`,
# with the same zero-telemetry / no-phone-home posture and the same
# opt-in version-check (`ibounce version-check`).
#
# - Stage 1 (builder): builds wheels for iam-jit + all runtime deps into
#   /wheels using `pip wheel`. Keeps the runtime layer free of build
#   toolchain residue.
# - Stage 2 (runtime): copies the wheels in, `pip install --no-index
#   --find-links` against them, then removes the wheel directory so the
#   final image only carries installed packages. Runs as the unprivileged
#   `ibounce` user.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# No apt build-deps needed: every runtime dependency that ships a C
# extension (cryptography, pydantic-core, aiohttp, etc.) publishes
# prebuilt manylinux wheels on PyPI for both linux/amd64 and
# linux/arm64. Skipping apt keeps the builder layer small and avoids
# a slow/flaky upstream apt mirror in CI. If a future dep requires
# a source build, add the apt step back behind a `--mount=type=cache`.

WORKDIR /src

# Copy only what's needed to build the wheel. Avoids busting the layer
# cache when unrelated files (docs, tests, recordings, .git) change.
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --upgrade pip wheel build \
 && python -m pip wheel --wheel-dir /wheels .

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/ibounce

# Create the unprivileged runtime user. UID/GID 10001 is well outside the
# usual host-user range to avoid colliding with bind-mounted host files.
RUN groupadd --system --gid 10001 ibounce \
 && useradd  --system --uid 10001 --gid ibounce \
              --home-dir /home/ibounce --create-home \
              --shell /usr/sbin/nologin ibounce

# Install from the pre-built wheels. `--no-index --find-links` enforces
# that we only install what builder produced — no implicit PyPI fetch
# at install time. After install we strip __pycache__ + bundled test
# directories from site-packages; those are dead weight inside a
# runtime image.
#
# Note: the COPY layer adds ~36 MB of wheels to the on-disk image
# size because deleted files persist in lower layers. Acceptable for
# this image — the runtime footprint of the installed packages is
# what matters for cold-start + memory. A future tightening could
# use a BuildKit `--mount=type=bind,from=builder,source=/wheels`
# pattern to avoid materializing the wheels into a layer at all.
COPY --from=builder /wheels /tmp/wheels
RUN python -m pip install --no-index --find-links /tmp/wheels iam-jit \
 && rm -rf /tmp/wheels /root/.cache \
 && find /usr/local/lib/python3.12/site-packages \
        \( -type d -a \( -name '__pycache__' -o -name 'tests' -o -name 'test' \) \) \
        -prune -exec rm -rf '{}' +

USER ibounce
WORKDIR /home/ibounce

# 8767 = `ibounce run` default loopback port. Exposing the port is
# advisory only — the binary still binds 127.0.0.1 inside the container
# unless invoked with --host 0.0.0.0 --i-know-this-binds-externally.
# Operators who want to reach the proxy from the host should publish
# the port AND pass those flags explicitly (see docs/DEPLOYMENT.md).
EXPOSE 8767

# Healthcheck mirrors what an operator would type to confirm the binary
# is callable; doesn't hit any network endpoint (preserves no-phone-home).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ibounce --version || exit 1

LABEL org.opencontainers.image.source="https://github.com/trsreagan3/iam-jit" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="ibounce" \
      org.opencontainers.image.description="AWS IAM safety proxy for AI agents and dev workflows"

ENTRYPOINT ["ibounce"]
CMD ["--help"]
