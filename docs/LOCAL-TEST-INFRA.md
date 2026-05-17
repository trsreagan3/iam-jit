# Local test infrastructure

How to run iam-jit, kbouncer, and dbounce integration tests against
real service containers on your laptop — no cloud account required.

## Why this exists

For most of the launch path, "blocked on the AWS account verification"
was a legitimate excuse for deferring features that needed real STS,
real CloudTrail, real Lambda, etc.

That excuse pattern eats too much velocity. This page documents the
local equivalents that close it: LocalStack for AWS APIs, Keycloak for
OIDC, kind for K8s apiservers, Postgres + MySQL containers for the
dbounce wire-protocol tier. None of these are perfect substitutes for
the real cloud — but they cover the bulk of API-shape testing without
the account-verification round-trip.

Per the `local-test-infra-unblocks-aws-wait` design call: AWS-account-
blocked is no longer a valid deferral reason for items that have a
working local equivalent. If your feature CAN be tested against
LocalStack / Keycloak / kind / Postgres-in-Docker, it MUST be.

## What's covered locally vs what still needs real AWS

| Surface                                      | Local? | Why / why not                                                                    |
| -------------------------------------------- | ------ | -------------------------------------------------------------------------------- |
| IAM CreateRole, PutRolePolicy, DeleteRole    | yes    | LocalStack community edition supports the full IAM surface iam-jit uses          |
| STS GetCallerIdentity, AssumeRole (same acct)| yes    | LocalStack STS works for single-account cases                                    |
| S3 GetObject, PutObject, ListBucket          | yes    | LocalStack S3 is the most-mature service                                         |
| Lambda invoke / deploy (SAM)                 | yes    | LocalStack Lambda + the SAM CLI talk to each other                               |
| OIDC discovery + JWKS                        | yes    | Keycloak 25 is a standards-compliant OIDC provider                               |
| K8s apiserver round-trip (kbouncer proxy)    | yes    | kind brings up a real apiserver in seconds                                       |
| Postgres + MySQL wire protocols (dbounce)    | yes    | Real engines in Docker; same protocol bytes as a hosted instance                 |
| **Real STS cross-account trust**             | NO     | LocalStack runs one "account"; cross-account `sts:AssumeRole` semantics are mocked, not enforced |
| **Real CloudTrail event latency**            | NO     | LocalStack emits CloudTrail events synchronously; production has 5-15min lag the Live-Action-Tail UX must handle |
| **Real IAM permissions-boundary enforcement**| NO     | LocalStack's IAM accepts boundary attachments but doesn't enforce them at evaluation time |
| **Real CloudFormation StackSets timing**     | NO     | CFN StackSets has multi-account orchestration timing that LocalStack does not model |
| **Real Bedrock / Anthropic model API**       | NO     | The LLM path is exercised against Ollama locally; real Bedrock invocations need the account |

The five rows marked **NO** are the items that genuinely require the
real AWS account verification to come through. Everything else has a
local equivalent below.

## iam-jit (`iam-roles` repo)

LocalStack (AWS APIs) + Keycloak (OIDC IdP) + Ollama (local LLM).

```bash
# One-shot — brings services up, runs integration suite, tears down.
make test-integration

# Or run the pieces yourself:
docker compose -f docker-compose.test.yml up -d
pytest tests/integration -v
docker compose -f docker-compose.test.yml down

# Clean tear-down (removes volumes too):
make test-integration-clean
```

Env-var conventions (auto-set by `make test-integration`):

- `LOCALSTACK_ENDPOINT` — default `http://127.0.0.1:4566`
- `IAM_JIT_KEYCLOAK_URL` — default `http://127.0.0.1:8088`
- `OLLAMA_HOST` — default `http://127.0.0.1:11434`

Each integration test SKIPS CLEANLY (not fails) when its target
service isn't reachable, so `pytest tests/integration -v` is always
safe to run.

## kbouncer (`kbouncer` repo)

kind cluster (real kube-apiserver in a Docker container).

```bash
# Full run — creates kind cluster, runs build-tagged integration suite,
# deletes cluster. Idempotent + safe to interrupt.
make test-integration

# Iteration loop — leaves the cluster running between invocations
# (much faster: ~5s vs ~20s):
make test-integration-keep
# ...iterate...
make test-integration-clean   # when done

# The build-tagged suite is safe to run without kind installed:
go test -tags=integration -timeout 5m ./...
# (skips when KBOUNCE_TEST_KUBECONFIG isn't set)
```

Env-var convention (auto-set by `make test-integration`):

- `KBOUNCE_TEST_KUBECONFIG` — path to a kubeconfig pointing at any
  reachable apiserver. The Makefile writes the kind kubeconfig to
  `./.kind-kubeconfig` (gitignored).

## dbounce (`dbounce` repo)

Postgres + MySQL engines in Docker.

```bash
# Full stack at once (Postgres + MySQL together):
docker compose -f compose.test.yaml up -d
make test-integration
docker compose -f compose.test.yaml down

# Or single engines (faster iteration loop):
make pg-up                     # Postgres 16 on :5432
make test-integration          # runs build-tagged suite against PG
make pg-down

make mysql-up                  # MySQL 8.4 on :3306
make test-integration          # build-tagged suite also picks up MySQL
make mysql-down

# Clean everything:
make test-integration-clean
```

Env-var conventions (printed by `make pg-up` / `make mysql-up`):

- `DBOUNCE_INTEGRATION_PG_URL`
- `DBOUNCE_INTEGRATION_MYSQL_URL`

The build-tagged suite is safe to run with no engines up — each test
skips when its target engine isn't reachable.

## Required tools

| Tool       | Required for         | Install                                            |
| ---------- | -------------------- | -------------------------------------------------- |
| Docker     | all three repos      | https://docs.docker.com/get-docker/ (or Colima on macOS) |
| docker compose | iam-jit, dbounce | bundled with modern Docker Desktop                 |
| kind       | kbouncer only        | https://kind.sigs.k8s.io                           |
| Go 1.26+   | kbouncer, dbounce    | https://go.dev/dl/                                 |
| Python 3.12+ + venv | iam-jit     | https://www.python.org/downloads/                  |

On macOS specifically, `colima start` is the standard alternative to
Docker Desktop. If you use Colima, point `DOCKER_HOST` at the Colima
socket before running `make test-integration` — see the `colima +
DOCKER_HOST` note in the project memory if you hit
`Cannot connect to the Docker daemon`.

## CI integration

CI integration (GitHub Actions service-containers + a job per
integration suite) is **post-launch** — service-container YAML is
easy to get wrong, and the integration suite already runs locally
on every developer's laptop before they push. We will wire it into
GHA after v1.0 ships, at which point the labels-or-nightly schedule
documented in `[[local-test-infra-spec]]` becomes the design.

Until then: run the integration suites locally before merging anything
that touches the IAM / OIDC / proxy / wire-protocol code paths.
