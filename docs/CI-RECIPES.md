# CI Recipes — iam-jit bouncer protection for CI/CD pipelines

This document is the operator guide for running iam-jit + ibounce in
CI/CD pipelines across multiple CI systems. Each recipe installs iam-jit,
starts ibounce as a local AWS API proxy, and asserts that real traffic was
audited (per `[[uat-tests-setup-end-to-end]]`).

> **GitHub Actions users:** see [`docs/GITHUB-ACTION-RECIPE.md`](GITHUB-ACTION-RECIPE.md)
> and [`examples/github-actions/use-iam-jit-action.yml`](../examples/github-actions/use-iam-jit-action.yml)
> for the first-class Action (`trsreagan3/iam-jit-action@v1`). The recipes
> below are for the four other major CI systems.

---

## Honesty bar

Per `[[vendor-integration-claim-qualifier]]`:

> Every recipe below is **"written + manually walked through; NOT tenant-validated"**
> — the YAML/pipeline shape matches each CI system's documented syntax but
> has not been exercised against a live CI tenant.
>
> This is honest positioning. Each system is marked **docs✅ / live⚠️**.
>
> When a live-tenant run is completed by an operator, update the relevant
> section to **live✅** with the date, runner image, and test result.

---

## Quick-reference: CI system matrix

| CI System | File | Status | OIDC support | Artifact upload | Decisions assertion |
|---|---|---|---|---|---|
| **GitHub Actions** | `examples/github-actions/use-iam-jit-action.yml` | docs✅ live✅ | `id-token: write` + aws-actions | `upload-artifact@v4` | `steps.iam-jit.outputs.decisions-count-baseline` |
| **GitLab CI** | `examples/ci/gitlab-ci.yml` | docs✅ live⚠️ | `id_tokens:` + Web Identity | `artifacts: paths:` | `IBOUNCE_BASELINE` from `build.env` |
| **CircleCI** | `examples/ci/circleci-config.yml` | docs✅ live⚠️ | `CIRCLE_OIDC_TOKEN` | `store_artifacts` | `IBOUNCE_BASELINE` from `$BASH_ENV` |
| **Jenkins** | `examples/ci/Jenkinsfile` | docs✅ live⚠️ | `withCredentials` + STS | `archiveArtifacts` | `ibounce-baseline.txt` + sourced env |
| **Buildkite** | `examples/ci/buildkite-pipeline.yml` | docs✅ live⚠️ | `buildkite-agent oidc` + STS | `artifact_paths:` | inline `BASELINE` variable |

---

## Why add ibounce to CI?

AI agents running in CI pipelines typically operate under a broad IAM role
scoped to the pipeline's AWS account. Without interception, every `aws` CLI
or boto3 call the agent makes is unaudited — you have no log of what the
agent did, and no gate to stop it from doing something destructive.

ibounce installs as a **loopback HTTP proxy** on port 8767. Setting
`AWS_ENDPOINT_URL=http://127.0.0.1:8767` causes every AWS SDK and CLI call
to route through ibounce, where it is:

1. **Logged** — recorded as a JSONL entry in the audit log
2. **Scored** — compared against the active profile's allow/deny rules
3. **Gated** (cooperative or strict mode) or **observed** (discovery mode)

No code change is required in the agent. The proxy is transparent.

---

## Enforcement modes

All recipes accept a `mode` variable that controls enforcement:

| Mode | ibounce behaviour | Recommended use |
|---|---|---|
| `discovery` | Observe + log only; **zero denies** | Start here for 1-2 sprints |
| `cooperative` | Deny with rationale; agent may retry with narrower scope | After `discovery` is stable |
| `strict` | Maximalist deny; no retry loop | Production or regulated environments |

Default is `discovery`. Change the mode variable in your pipeline — no
code change in the agent.

---

## Common install sequence (all CI systems)

Every recipe follows the same 8-step pattern:

```
1. Install Python 3.12+
2. Install Go 1.22+
3. pip install iam-jit  (PyPI, fallback to GitHub source)
4. Verify ibounce is on PATH  (ships with iam-jit pip package)
5. iam-jit init --non-interactive --harness=none ...
6. ibounce run --port 8767 --mode <mode> --audit-log-path <path> &
7. Wait for ibounce /healthz  (fail loud if timeout)
8. Export AWS_ENDPOINT_URL=http://127.0.0.1:8767
```

Then your agent step runs, followed by:

```
9.  Assert decisions_count ticked  (fail if delta == 0)
10. Archive audit log
```

---

## GitLab CI

**File:** [`examples/ci/gitlab-ci.yml`](../examples/ci/gitlab-ci.yml)
**Status:** docs✅ live⚠️ — compatible per GitLab CI documented YAML shape

### Quick install

Copy `examples/ci/gitlab-ci.yml` into your `.gitlab-ci.yml` or include
the `agent-run` job definition.

### OIDC (GitLab 15.7+)

GitLab generates per-job OIDC tokens via `id_tokens:`. Use
`CI_JOB_JWT_V2` (legacy, pre-15.7) or the newer `id_tokens:` block:

```yaml
# .gitlab-ci.yml
agent-run:
  id_tokens:
    AWS_OIDC_TOKEN:
      aud: sts.amazonaws.com
  script:
    - |
      aws sts assume-role-with-web-identity \
        --role-arn "${AWS_ROLE_ARN}" \
        --role-session-name "gitlab-ci-${CI_JOB_ID}" \
        --web-identity-token "${AWS_OIDC_TOKEN}" \
        --duration-seconds 3600 \
        > /tmp/aws-creds.json
      export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId /tmp/aws-creds.json)
      export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretAccessKey /tmp/aws-creds.json)
      export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken /tmp/aws-creds.json)
```

Set `AWS_ROLE_ARN` as a CI/CD variable in your GitLab project settings.

### Decisions assertion

The recipe sources `build.env` to pick up `IBOUNCE_BASELINE` and
`AWS_ENDPOINT_URL` from the ibounce start step, then asserts:

```bash
AFTER=$(curl -sf "http://127.0.0.1:${IBOUNCE_PORT}/healthz" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('decisions_count',0))")
DELTA=$((AFTER - IBOUNCE_BASELINE))
[ "${DELTA}" -gt 0 ] || { echo "ERROR: no traffic routed through ibounce"; exit 1; }
```

### Artifact upload

```yaml
artifacts:
  name: "iam-jit-audit-${CI_JOB_ID}"
  when: always
  expire_in: 14 days
  paths:
    - "${IAM_JIT_AUDIT_LOG}"
    - /tmp/ibounce.log
```

---

## CircleCI

**File:** [`examples/ci/circleci-config.yml`](../examples/ci/circleci-config.yml)
**Status:** docs✅ live⚠️ — compatible per CircleCI 2.1 documented config shape

### Quick install

Copy `examples/ci/circleci-config.yml` to `.circleci/config.yml` in your
repo. The file is self-contained with reusable `commands:` that can be
embedded in any existing job.

### OIDC (CircleCI Cloud + self-hosted 3.x)

CircleCI generates OIDC tokens available as `$CIRCLE_OIDC_TOKEN` (built-in
env var, no extra configuration). Exchange for AWS credentials:

```yaml
- run:
    name: Configure AWS (OIDC)
    command: |
      aws sts assume-role-with-web-identity \
        --role-arn "${AWS_ROLE_ARN}" \
        --role-session-name "circleci-${CIRCLE_BUILD_NUM}" \
        --web-identity-token "${CIRCLE_OIDC_TOKEN}" \
        --duration-seconds 3600 \
        > /tmp/aws-creds.json
      {
        echo "export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId /tmp/aws-creds.json)"
        echo "export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretAccessKey /tmp/aws-creds.json)"
        echo "export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken /tmp/aws-creds.json)"
      } >> "$BASH_ENV"
```

Set `AWS_ROLE_ARN` in a CircleCI context (Organization Settings →
Contexts) and reference it in the workflow:

```yaml
workflows:
  agent-ci:
    jobs:
      - agent-run:
          context:
            - aws-oidc-context
```

### Decisions assertion

The `start-ibounce` command appends `IBOUNCE_BASELINE` to `$BASH_ENV`.
CircleCI sources `$BASH_ENV` before each `run:` step, so the assertion
command picks it up automatically:

```yaml
- assert-decisions-ticked:
    port: << pipeline.parameters.ibounce-port >>
```

### Artifact upload

```yaml
- store_artifacts:
    path: /tmp/iam-jit-audit.jsonl
    destination: iam-jit/audit-log.jsonl
```

---

## Jenkins

**File:** [`examples/ci/Jenkinsfile`](../examples/ci/Jenkinsfile)
**Status:** docs✅ live⚠️ — compatible per Jenkins Declarative Pipeline documented syntax (Jenkins 2.387+)

### Quick install

Create a Jenkins Pipeline job pointing at your repo, with
"Pipeline script from SCM" and `Jenkinsfile` as the path. No plugin
is required beyond the standard pipeline suite.

### OIDC via `withCredentials`

Jenkins does not natively generate OIDC tokens, but the
`aws-credentials` plugin (≥ 1.71) adds a `withAWS` step that handles
Web Identity exchange. Two options are documented inline in the
Jenkinsfile:

**Option A — `withAWS` (preferred):**
```groovy
withAWS(role: env.AWS_ROLE_ARN, region: 'us-east-1') {
    sh 'aws sts get-caller-identity'
}
```

**Option B — `withCredentials` + manual STS exchange:**
```groovy
withCredentials([
    string(credentialsId: 'aws-role-arn', variable: 'AWS_ROLE_ARN'),
    string(credentialsId: 'aws-oidc-token', variable: 'OIDC_TOKEN')
]) {
    sh '''
        aws sts assume-role-with-web-identity \
            --role-arn "${AWS_ROLE_ARN}" \
            --role-session-name "jenkins-${BUILD_NUMBER}" \
            --web-identity-token "${OIDC_TOKEN}" \
            --duration-seconds 3600 \
            > /tmp/aws-creds.json
        # export from /tmp/aws-creds.json ...
    '''
}
```

Store credentials in Jenkins Credentials Manager (Manage Jenkins →
Credentials), never in the Jenkinsfile.

### Decisions assertion

ibounce's baseline is written to `ibounce-baseline.txt` and env vars
are sourced from `ibounce-env.sh` between stages. The assertion stage:

```groovy
stage('Assert ibounce audited traffic') {
    steps {
        sh '''
            source "${WORKSPACE}/ibounce-env.sh"
            AFTER=$(curl -sf "http://127.0.0.1:${IBOUNCE_PORT}/healthz" \
                | python3 -c "import sys,json; print(json.load(sys.stdin).get('decisions_count',0))")
            DELTA=$((AFTER - IBOUNCE_BASELINE))
            [ "${DELTA}" -gt 0 ] || { echo "ERROR: no traffic audited"; exit 1; }
        '''
    }
}
```

### Artifact archive + cleanup

```groovy
post {
    always {
        archiveArtifacts(artifacts: 'iam-jit-audit.jsonl,ibounce.log', allowEmptyArchive: true)
    }
    cleanup {
        sh 'kill $(cat "${WORKSPACE}/ibounce.pid") 2>/dev/null || true'
    }
}
```

The `cleanup` block kills ibounce so the agent process does not linger
between builds. Jenkins agents run multiple builds sequentially on the
same workspace, so cleanup is important.

---

## Buildkite

**File:** [`examples/ci/buildkite-pipeline.yml`](../examples/ci/buildkite-pipeline.yml)
**Status:** docs✅ live⚠️ — compatible per Buildkite documented pipeline.yml shape (Agent 3+)

### Quick install

Upload `buildkite-pipeline.yml` as your pipeline's YAML definition
(Pipeline Settings → Steps → Upload pipeline from YAML). Or paste
individual steps into the pipeline steps UI.

### OIDC via `buildkite-agent oidc` (Agent 3.71+)

```bash
OIDC_TOKEN=$(buildkite-agent oidc request-token --audience sts.amazonaws.com)
CREDS=$(aws sts assume-role-with-web-identity \
  --role-arn "${AWS_ROLE_ARN}" \
  --role-session-name "buildkite-${BUILDKITE_BUILD_NUMBER}" \
  --web-identity-token "${OIDC_TOKEN}" \
  --duration-seconds 3600)
export AWS_ACCESS_KEY_ID=$(echo "${CREDS}" | jq -r .Credentials.AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo "${CREDS}" | jq -r .Credentials.SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo "${CREDS}" | jq -r .Credentials.SessionToken)
```

Set `AWS_ROLE_ARN` as a Buildkite pipeline environment variable
(Pipeline Settings → Environment).

### Decisions assertion

The agent-run step is a **single inline script** (not separate `commands:` list
items) so that ibounce's background process persists across sub-commands.
The baseline is captured after ibounce starts and the assertion runs in the
same shell:

```bash
BASELINE=$(curl -sf "http://127.0.0.1:${IBOUNCE_PORT}/healthz" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('decisions_count',0))")
# ... run agent ...
AFTER=$(curl -sf "http://127.0.0.1:${IBOUNCE_PORT}/healthz" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('decisions_count',0))")
DELTA=$((AFTER - BASELINE))
[ "${DELTA}" -gt 0 ] || { echo "ERROR: no traffic audited"; exit 1; }
```

### Artifact upload

```yaml
artifact_paths:
  - "iam-jit-audit.jsonl"
  - "ibounce.log"
```

Buildkite automatically uploads these to its artifact store at the end of
each step. Access them from the Build UI under "Artifacts".

---

## Recommended CI matrix

For shops choosing a CI system for new projects with AI agent workloads:

| Priority | CI system | Reason |
|---|---|---|
| 1 | **GitHub Actions** | First-class Action (`trsreagan3/iam-jit-action@v1`); easiest install; OIDC built-in |
| 2 | **GitLab CI** | Strong EU/gov market; native OIDC; SARIF/security-dashboard integration |
| 3 | **CircleCI** | Startup + cloud-native shops; clean orb model; `$BASH_ENV` makes env propagation reliable |
| 4 | **Jenkins** | Largest enterprise installed base; most config overhead but well-documented |
| 5 | **Buildkite** | Small absolute volume but exceptional logo density (Airbnb, Shopify, Slack) |

---

## Troubleshooting (all CI systems)

### `decisions_count` did not tick

The most common cause is `AWS_ENDPOINT_URL` not being inherited by the
agent step.

- **GitLab CI:** Use `build.env` artifacts or `source build.env` at the
  top of each script that needs the variable.
- **CircleCI:** `$BASH_ENV` is sourced automatically before each `run:`.
  Confirm the `start-ibounce` command wrote to `$BASH_ENV`.
- **Jenkins:** `source "${WORKSPACE}/ibounce-env.sh"` at the top of each
  `sh` block that needs the variable.
- **Buildkite:** Use a single-script step so the background ibounce process
  and the agent share the same shell environment.

### ibounce did not respond within 15s

- Check the ibounce log: `ibounce.log` in the workspace or temp dir.
- Port 8767 may be in use. Set `IBOUNCE_PORT` to an available port.
- On constrained runners (< 1 CPU), increase the wait loop timeout from
  15s to 30s.

### pip install failed

- Confirm Python 3.12+ is available: `python3 --version`.
- If PyPI is blocked by your network policy, use the GitHub source fallback
  (already in every recipe) or pre-build a Docker image with iam-jit baked in.

### go install failed for a Go bouncer

- Confirm Go 1.22+ is available: `go version`.
- Only ibounce is required for AWS auditing. Go bouncers (kbouncer,
  dbounce, gbounce) are optional. The recipes emit a warning and continue
  if a Go bouncer fails to install.

---

## Related docs

- [`docs/GITHUB-ACTION-RECIPE.md`](GITHUB-ACTION-RECIPE.md) — GitHub Actions first-class recipe
- [`docs/IBOUNCE.md`](IBOUNCE.md) — ibounce full configuration reference
- [`docs/BOOTSTRAP.md`](BOOTSTRAP.md) — local setup (macOS / Linux / Docker)
- [`docs/LOCAL-TEST-INFRA.md`](LOCAL-TEST-INFRA.md) — LocalStack + compose for local CI parity
- [`docs/SECURITY-POSTURE.md`](SECURITY-POSTURE.md) — security posture reference
- [`examples/ci/gitlab-ci.yml`](../examples/ci/gitlab-ci.yml) — GitLab CI reference pipeline
- [`examples/ci/circleci-config.yml`](../examples/ci/circleci-config.yml) — CircleCI reference config
- [`examples/ci/Jenkinsfile`](../examples/ci/Jenkinsfile) — Jenkins Declarative Pipeline
- [`examples/ci/buildkite-pipeline.yml`](../examples/ci/buildkite-pipeline.yml) — Buildkite reference pipeline
