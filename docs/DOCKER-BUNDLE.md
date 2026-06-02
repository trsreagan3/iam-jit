# iam-jit unified Docker bundle

The `ghcr.io/trsreagan3/iam-jit` image ships **all five** iam-jit
suite components in a single container:

| Binary | What it is |
|---|---|
| `iam-jit` (entrypoint) | IAM JIT credential issuer — the primary CLI |
| `ibounce` | AWS API-call gating proxy |
| `kbounce` | Kubernetes API-call gating proxy |
| `dbounce` | SQL database gating proxy |
| `gbounce` | Generic HTTP/HTTPS forward proxy |

Per `[[automatic-bootstrap-must-just-work-everywhere]]`: this image is the
canonical "just works" packaging for CI/CD pipelines, cloud runners, and any
environment where running `pip install` + 3× `go install` during bootstrap
is not acceptable.

Per `[[self-host-zero-billing-dependency]]`: zero phone-home at runtime. No
license call-back, no usage telemetry, no error reporting.

---

## Image tags

| Tag | When pushed |
|---|---|
| `ghcr.io/trsreagan3/iam-jit:latest` | On every `v*` tag push |
| `ghcr.io/trsreagan3/iam-jit:1.0.0` | Exact version tag |
| `ghcr.io/trsreagan3/iam-jit:1.0` | Major.minor alias |
| `ghcr.io/trsreagan3/iam-jit:1` | Major alias |
| `ghcr.io/trsreagan3/iam-jit:main` | On push to main (dev builds) |
| `ghcr.io/trsreagan3/iam-jit:sha-<short>` | Every build, pinnable |

Multi-arch: `linux/amd64` and `linux/arm64`.

---

## Quick start

### One-off non-interactive init (CI / agent bootstrap)

```bash
docker run --rm \
  -v ~/.iam-jit:/var/lib/iam-jit \
  -e IAM_JIT_DATA_DIR=/var/lib/iam-jit \
  ghcr.io/trsreagan3/iam-jit:latest \
  init --no-prompt --harness=claude-code
```

This writes `~/.iam-jit/iam-jit.yaml` (bind-mounted from the host).
The command is idempotent with `--overwrite`; without it, init refuses
to clobber an existing config (per `[[creates-never-mutates]]`).

### Check installed versions

```bash
# All five binaries in one container:
docker run --rm ghcr.io/trsreagan3/iam-jit:latest --version
docker run --rm --entrypoint ibounce  ghcr.io/trsreagan3/iam-jit:latest --version
docker run --rm --entrypoint kbounce  ghcr.io/trsreagan3/iam-jit:latest --version
docker run --rm --entrypoint dbounce  ghcr.io/trsreagan3/iam-jit:latest --version
docker run --rm --entrypoint gbounce  ghcr.io/trsreagan3/iam-jit:latest --version
```

### Run iam-jit serve --local (dev / canary)

```bash
docker run --rm \
  -p 8000:8000 \
  -v ~/.iam-jit:/var/lib/iam-jit \
  -e IAM_JIT_DATA_DIR=/var/lib/iam-jit \
  -e AWS_DEFAULT_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
  ghcr.io/trsreagan3/iam-jit:latest \
  serve --local
```

### Run ibounce proxy

```bash
docker run --rm \
  -p 8767:8767 \
  -v ~/.iam-jit:/var/lib/iam-jit \
  -e IAM_JIT_DATA_DIR=/var/lib/iam-jit \
  --entrypoint ibounce \
  ghcr.io/trsreagan3/iam-jit:latest \
  run --host 0.0.0.0 --i-know-this-binds-externally
```

**Note:** ibounce binds loopback (`127.0.0.1`) by default. To reach it
from outside the container you must pass `--host 0.0.0.0` and the
acknowledgement flag shown above.

---

## docker-compose.yml examples

### CI pipeline — init + score

```yaml
# docker-compose.ci.yml
# Runs iam-jit init in non-interactive mode, then exits.
# Mount your policy files and score them in a one-shot run.

version: "3.9"

services:
  iam-jit-init:
    image: ghcr.io/trsreagan3/iam-jit:latest
    command: ["init", "--no-prompt", "--harness=none"]
    environment:
      IAM_JIT_DATA_DIR: /var/lib/iam-jit
      AWS_DEFAULT_REGION: ${AWS_DEFAULT_REGION:-us-east-1}
      AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:-}
      AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:-}
    volumes:
      - iam-jit-data:/var/lib/iam-jit

  iam-risk-score:
    image: ghcr.io/trsreagan3/iam-jit:latest
    entrypoint: iam-risk-score
    command: ["--help"]
    depends_on:
      iam-jit-init:
        condition: service_completed_successfully
    volumes:
      - ./policies:/policies:ro
      - iam-jit-data:/var/lib/iam-jit

volumes:
  iam-jit-data:
```

### Development stack — ibounce + iam-jit serve

```yaml
# docker-compose.dev-bundle.yml
# Full local dev stack: ibounce proxy + iam-jit API.

version: "3.9"

services:
  ibounce:
    image: ghcr.io/trsreagan3/iam-jit:latest
    entrypoint: ibounce
    command:
      - run
      - --host
      - "0.0.0.0"
      - --i-know-this-binds-externally
    ports:
      - "8767:8767"
    environment:
      IBOUNCE_DATA_DIR: /var/lib/iam-jit/ibounce
      IAM_JIT_DATA_DIR: /var/lib/iam-jit
    volumes:
      - iam-jit-data:/var/lib/iam-jit
    healthcheck:
      test: ["CMD-SHELL", "ibounce status || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 5
      start_period: 5s

  iam-jit:
    image: ghcr.io/trsreagan3/iam-jit:latest
    command:
      - serve
      - --local
    ports:
      - "8000:8000"
    environment:
      IAM_JIT_DATA_DIR: /var/lib/iam-jit
      AWS_DEFAULT_REGION: ${AWS_DEFAULT_REGION:-us-east-1}
      AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:-}
      AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:-}
      AWS_SESSION_TOKEN: ${AWS_SESSION_TOKEN:-}
    volumes:
      - iam-jit-data:/var/lib/iam-jit
    depends_on:
      ibounce:
        condition: service_healthy

volumes:
  iam-jit-data:
```

---

## Environment variable passthrough

| Variable | Purpose | Default inside container |
|---|---|---|
| `IAM_JIT_DATA_DIR` | Root data directory | `/var/lib/iam-jit` |
| `IBOUNCE_DATA_DIR` | ibounce state directory | `/var/lib/iam-jit/ibounce` |
| `KBOUNCE_DATA_DIR` | kbounce state directory | `/var/lib/iam-jit/kbounce` |
| `DBOUNCE_DATA_DIR` | dbounce state directory | `/var/lib/iam-jit/dbounce` |
| `GBOUNCE_DATA_DIR` | gbounce state directory | `/var/lib/iam-jit/gbounce` |
| `AWS_DEFAULT_REGION` | AWS region for boto3 | (unset — inherit from env) |
| `AWS_ACCESS_KEY_ID` | AWS access key | (unset — inherit from env) |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | (unset — inherit from env) |
| `AWS_SESSION_TOKEN` | AWS session token | (unset — inherit from env) |
| `AWS_ENDPOINT_URL` | Override AWS endpoint (ibounce proxy) | (unset) |
| `IAM_JIT_LLM` | LLM backend (`ollama` / `bedrock` / `openai`) | (unset) |
| `IAM_JIT_LLM_MODEL` | LLM model name | (unset) |
| `IAM_JIT_FEEDBACK_ENABLED` | Opt-in feedback pipeline (default OFF) | `false` |

All `AWS_*` variables should be passed with `-e VAR` (no value) so the
host value is forwarded without embedding credentials in the compose file.

---

## Security posture

- **Runtime user**: UID 1000 (`iamjit`). The container never runs as root
  at runtime (build-time root is used only to install packages).
- **Read-only filesystem**: Only `/var/lib/iam-jit` needs to be writable.
  All other paths can be mounted read-only (`--read-only` with
  `--tmpfs /tmp`).
- **No phone-home**: Zero telemetry, no license call-back, no
  version-check unless the operator runs `iam-jit doctor --check-update`
  explicitly.
- **No held credentials**: ibounce forwards SigV4-signed requests verbatim.
  The container never stores AWS credentials on disk.

---

## Building locally

The Dockerfile bundles three Go repos as build contexts alongside the
iam-roles Python source. Clone all four repos as siblings, then build:

```bash
# Assumes iam-roles, kbouncer, dbounce, gbounce are siblings.
docker build \
  -f iam-roles/infrastructure/docker/Dockerfile.iam-jit-bundle \
  --build-context kbouncer=kbouncer \
  --build-context gbounce=gbounce \
  --build-context dbounce=dbounce \
  --build-arg VERSION=1.0.0 \
  -t iam-jit-bundle:local \
  iam-roles
```

Multi-arch (requires QEMU):

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f iam-roles/infrastructure/docker/Dockerfile.iam-jit-bundle \
  --build-context kbouncer=kbouncer \
  --build-context gbounce=gbounce \
  --build-context dbounce=dbounce \
  --build-arg VERSION=1.0.0 \
  -t ghcr.io/trsreagan3/iam-jit:1.0.0 \
  --push \
  iam-roles
```

---

## Running smoke tests against the local build

```bash
# 1. Build the local image (see above).
# 2. Run integration smoke tests:
IAM_JIT_BUNDLE_IMAGE=iam-jit-bundle:local \
  pytest -m integration tests/integration/test_docker_bundle_smoke.py -v

# 3. With live ibounce (decisions_count test):
#    Start ibounce on :8767 first, then:
IAM_JIT_BUNDLE_IMAGE=iam-jit-bundle:local \
  pytest -m integration tests/integration/test_docker_bundle_smoke.py -v
```

---

## Related docs

- [DEPLOYMENT.md](DEPLOYMENT.md) — self-host deploy guide
- [IBOUNCE.md](IBOUNCE.md) — ibounce operator guide
- [GETTING-STARTED.md](GETTING-STARTED.md) — first-run walkthrough
- [SECURITY-POSTURE.md](SECURITY-POSTURE.md) — security questionnaire reference
