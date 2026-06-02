# Claude-in-Docker Integration Guide

Operator guide for adding iam-jit + ibounce to a Docker-based Claude Code
(or any AI-agent) setup.  Covers both deployment patterns, env-var passthrough,
audit-log volume mounts, and the tradeoff between patterns.

---

## Why this guide exists

The canonical Claude Code install is a desktop app.  Increasingly teams run
Claude inside Docker for:

- **Hermetic CI/CD** — reproducible agent environment, no host-side tool drift.
- **Multi-agent orchestration** — N claude containers, each scoped to a task.
- **Security isolation** — the agent process is sandboxed in a container; its
  AWS calls are the only network surface that needs gating.

When Claude runs in Docker, the standard ibounce install (`ibounce init &&
ibounce run`) still works — you just have to deliver those binaries into the
right place.  This guide shows the two standard ways.

> **Private image note:** `anthropics/claude-code:latest` is a private/restricted
> image. Both patterns below use `python:3.12-slim-bookworm` as a public stand-in
> that demonstrates the exact RUN block or compose snippet an operator would add
> to their Claude-based image. Swap `FROM python:3.12-slim-bookworm` with
> `FROM anthropics/claude-code:latest` (or your org's Claude runner image).

---

## Two patterns

| | **Pattern A — in-container** | **Pattern B — sidecar** |
|---|---|---|
| Bouncer lives | Inside the Claude container | In a separate sidecar container |
| Claude image changes needed | Yes — one `RUN` block + `COPY` | None — use your image as-is |
| Routing | `AWS_ENDPOINT_URL=http://127.0.0.1:8767` | `AWS_ENDPOINT_URL=http://iam-jit-bouncer:8767` |
| Audit logs | Volume-mounted from the Claude container | Volume-mounted from the sidecar |
| Best for | Single container, simple setup, CI jobs | Multi-container stacks, unmodified Claude images |
| Sidecar restart | N/A | `depends_on: condition: service_healthy` |

### When to use Pattern A

- You control the Dockerfile and adding one `RUN` layer is acceptable.
- Your setup is a single Claude container (no compose stack).
- CI ephemeral containers: you want everything in one image, no compose.

### When to use Pattern B

- You pull `anthropics/claude-code:latest` directly (can't modify it).
- Your stack already has multiple services; adding a sidecar is natural.
- You want to update ibounce without rebuilding the Claude image.

---

## Pattern A — in-container install

**Reference Dockerfile:** `examples/docker/claude-code-with-bouncers.Dockerfile`

### What the RUN block does

```dockerfile
FROM python:3.12-slim-bookworm     # replace with your Claude image

RUN set -e \
 && apt-get update -qq \
 && apt-get install -y --no-install-recommends \
        git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 \
 # Install iam-jit (includes ibounce as a console-script entry-point).
 && pip install --quiet --break-system-packages \
        "git+https://github.com/trsreagan3/iam-jit.git@main" \
 \
 # Verify both binaries are callable at build time.
 && iam-jit --version \
 && ibounce --version \
 \
 # Create writable data dir for audit logs + config.
 && mkdir -p /var/lib/iam-jit/ibounce \
 && chmod 777 /var/lib/iam-jit

ENV AWS_ENDPOINT_URL=http://127.0.0.1:8767 \
    IAM_JIT_DATA_DIR=/var/lib/iam-jit \
    IBOUNCE_DATA_DIR=/var/lib/iam-jit/ibounce

VOLUME ["/var/lib/iam-jit"]

ENTRYPOINT ["/usr/local/bin/start-with-bouncers"]
CMD ["bash"]
```

The `start-with-bouncers` entrypoint (`infrastructure/docker/start-with-bouncers.sh`):

1. Runs `iam-jit init --non-interactive` on first boot.
2. Starts `ibounce run --mode cooperative` in the background.
3. Waits for `/healthz` to respond.
4. Execs the operator's command (e.g., `bash`, `claude "..."`, `python3 agent.py`).

### Build + run

```bash
# Build
docker build \
  -f examples/docker/claude-code-with-bouncers.Dockerfile \
  -t my-claude-with-bouncers:latest \
  .

# Interactive shell (ibounce starts, then bash)
docker run --rm -it \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION \
  -v "$(pwd)/audit-logs:/var/lib/iam-jit" \
  my-claude-with-bouncers:latest

# Run a single agent command (CI-safe)
docker run --rm \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION=us-east-1 \
  -v "$(pwd)/audit-logs:/var/lib/iam-jit" \
  my-claude-with-bouncers:latest \
  python3 -c "import boto3; print(boto3.client('sts').get_caller_identity())"
```

### Env-var passthrough

Pass AWS credentials and any other secrets as `-e` flags or via a `.env` file:

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION \
  -e ANTHROPIC_API_KEY \
  -v "$(pwd)/audit-logs:/var/lib/iam-jit" \
  my-claude-with-bouncers:latest \
  claude "List the S3 buckets in us-east-1"
```

`AWS_ENDPOINT_URL` is already baked into the image (`http://127.0.0.1:8767`);
do not override it unless you are deliberately bypassing ibounce.

### Audit-log volume mount

All ibounce decisions are written to `/var/lib/iam-jit/ibounce/` inside the
container.  Bind-mount this directory to the host to persist logs across
container restarts:

```bash
docker run --rm \
  -v /var/log/iam-jit-claude:/var/lib/iam-jit \
  my-claude-with-bouncers:latest
```

Logs survive `docker stop` + `docker rm` and can be queried with
`iam-jit audit query` on the host.

---

## Pattern B — sidecar deployment

**Reference compose file:** `examples/docker/docker-compose.claude-sidecar.yml`

**Reference sidecar image:** `infrastructure/docker/Dockerfile.sidecar`

### Compose snippet

```yaml
services:

  iam-jit-bouncer:
    build:
      context: .   # repo root
      dockerfile: infrastructure/docker/Dockerfile.sidecar
    environment:
      BOUNCERS: ibounce
      IBOUNCE_MODE: cooperative      # cooperative (audit-only) or transparent (enforce)
    volumes:
      - ./audit-logs:/var/lib/iam-jit
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8767/healthz"]
      interval: 15s
      timeout: 5s
      start_period: 20s
    restart: unless-stopped
    ports:
      - "8767:8767"                  # expose for `iam-jit audit query` on host

  claude:
    image: python:3.12-slim-bookworm   # replace with your Claude image
    environment:
      AWS_ENDPOINT_URL: http://iam-jit-bouncer:8767
      AWS_ACCESS_KEY_ID: "${AWS_ACCESS_KEY_ID:-}"
      AWS_SECRET_ACCESS_KEY: "${AWS_SECRET_ACCESS_KEY:-}"
      AWS_DEFAULT_REGION: "${AWS_DEFAULT_REGION:-us-east-1}"
      ANTHROPIC_API_KEY: "${ANTHROPIC_API_KEY:-}"
    depends_on:
      iam-jit-bouncer:
        condition: service_healthy
```

`depends_on: condition: service_healthy` ensures the claude container does
NOT start until ibounce is ready to gate its AWS calls.  If the sidecar
crashes, docker-compose restarts it automatically (`restart: unless-stopped`).

### Start the stack

```bash
# Build + start (first run or after Dockerfile changes)
docker-compose -f examples/docker/docker-compose.claude-sidecar.yml up --build -d

# Check sidecar health
curl http://localhost:8767/healthz | python3 -m json.tool

# Stream audit log
docker-compose -f examples/docker/docker-compose.claude-sidecar.yml \
  exec iam-jit-bouncer cat /var/lib/iam-jit/ibounce/audit.jsonl

# Stop + remove
docker-compose -f examples/docker/docker-compose.claude-sidecar.yml down
```

### Env-var passthrough

Export credentials before running `docker-compose up`; the compose file
interpolates them automatically:

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
export ANTHROPIC_API_KEY=...

docker-compose -f examples/docker/docker-compose.claude-sidecar.yml up -d
```

Or put them in a `.env` file in the same directory as the compose file:

```dotenv
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
ANTHROPIC_API_KEY=sk-ant-...
```

### Audit-log volume mount

The sidecar bind-mounts `/var/lib/iam-jit` to `./audit-logs/` relative to
the compose file.  Change this to any absolute path for production deployments:

```yaml
volumes:
  - /var/log/iam-jit-claude:/var/lib/iam-jit
```

---

## Bouncer mode selection

Both patterns support two operational modes (set via `IBOUNCE_MODE` env var):

| Mode | Behaviour | When to use |
|---|---|---|
| `cooperative` (default) | Audit-only — every AWS call is logged, none are blocked. | Start here: observe what the agent does before adding rules. |
| `transparent` | Enforcement — deny rules block calls; matched requests return 403. | After you have reviewed the cooperative-mode logs and authored rules. |

Per [`docs/DEPLOYMENT-PRESETS.md`](DEPLOYMENT-PRESETS.md) the `security-observe`
preset (`ibounce run --preset security-observe`) is a quick way to start in
transparent mode with sensible default alert rules.

---

## Published sidecar image

A pre-built sidecar image is published to GitHub Container Registry on every
tagged release:

```bash
docker pull ghcr.io/trsreagan3/iam-jit-sidecar:latest
```

Pin to a specific version for reproducible deployments:

```bash
docker pull ghcr.io/trsreagan3/iam-jit-sidecar:1.0.0
```

See `.github/workflows/publish-sidecar-image.yml` for the publish pipeline.

---

## Checking audit output

After any AWS calls from the Claude container, query the bouncer:

```bash
# Pattern A — from the host (if port is exposed)
curl http://localhost:8767/healthz | python3 -c "
import sys, json; d=json.load(sys.stdin)
print('decisions_count:', d['decisions_count'])
print('mode:', d['mode'])
"

# Pattern B — from inside the sidecar container
docker exec <sidecar-container-name> \
  curl -s http://127.0.0.1:8767/healthz

# Stream audit events via CLI (both patterns)
iam-jit audit query --url http://localhost:8767
```

---

## See also

- [`examples/docker/claude-code-with-bouncers.Dockerfile`](../examples/docker/claude-code-with-bouncers.Dockerfile) — Pattern A reference Dockerfile
- [`examples/docker/docker-compose.claude-sidecar.yml`](../examples/docker/docker-compose.claude-sidecar.yml) — Pattern B reference compose
- [`infrastructure/docker/Dockerfile.sidecar`](../infrastructure/docker/Dockerfile.sidecar) — sidecar image
- [`infrastructure/docker/sidecar-entrypoint.sh`](../infrastructure/docker/sidecar-entrypoint.sh) — sidecar supervisor
- [`infrastructure/docker/start-with-bouncers.sh`](../infrastructure/docker/start-with-bouncers.sh) — Pattern A entrypoint
- [`tests/integration/test_claude_in_docker_e2e.py`](../tests/integration/test_claude_in_docker_e2e.py) — E2E verification
- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — full deployment guide
- [`docs/SECURITY-POSTURE.md`](SECURITY-POSTURE.md) — trust model
