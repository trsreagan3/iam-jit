# GitHub Actions Recipe — iam-jit bouncer protection for CI agents

This document describes how to add iam-jit + Bounce-suite bouncer protection
to any GitHub Actions CI pipeline that runs an AI agent (Claude Code, Codex,
a custom boto3-based agent, etc.).

## Why add bouncer protection to CI?

Agents running in CI pipelines often have broad IAM permissions scoped to the
runner's assumed role. Without interception, every `aws` CLI call or boto3
call the agent makes is unaudited — you get no log of what the agent did,
and no gate to stop it from doing something destructive.

The `iam-jit-action` installs **ibounce** as a local AWS API proxy on the
runner. By setting `AWS_ENDPOINT_URL` to the ibounce address, every AWS call
the agent makes is:

1. **Logged** — recorded in a JSONL audit log
2. **Scored** — compared against the active profile's allow/deny rules
3. **Gated** (cooperative / strict mode) or **observed** (discovery mode)

## Quick install

```yaml
- name: Install iam-jit + wire bouncer
  id: iam-jit
  uses: trsreagan3/iam-jit-action@v1
  with:
    bouncers: 'ibounce'
    mode: 'discovery'
    harness: 'none'
```

That is the entire install step. See
[`examples/github-actions/use-iam-jit-action.yml`](../examples/github-actions/use-iam-jit-action.yml)
for the full reference workflow.

## Inputs reference

| Input | Default | Description |
|---|---|---|
| `version` | `latest` | iam-jit pip version |
| `bouncers` | `ibounce,kbouncer,dbounce,gbounce` | Which bouncers to start |
| `harness` | `claude-code` | Agent harness for MCP wiring |
| `mode` | `cooperative` | Enforcement mode |
| `audit-log-path` | `$RUNNER_TEMP/iam-jit-audit.jsonl` | Audit output path |

## Outputs reference

| Output | Description |
|---|---|
| `bouncer-port` | ibounce port (default 8767) |
| `audit-log-path` | JSONL audit log path |
| `decisions-count-baseline` | `decisions_count` at bouncer start |

## Env vars exported by the action

| Variable | Purpose |
|---|---|
| `AWS_ENDPOINT_URL` | Routes AWS SDK/CLI through ibounce |
| `HTTPS_PROXY` | Routes HTTPS through gbounce (when enabled) |
| `IAM_JIT_AUDIT_LOG` | Path to audit JSONL |
| `IBOUNCE_PORT` | ibounce management port |

## Progressive enforcement

Start with `discovery` mode and tighten over time:

```
discovery → cooperative → strict
```

- **discovery**: zero denies, full audit trail. Use for first 1-2 sprints.
- **cooperative**: denies with rationale. Agent may retry with narrower scope.
- **strict**: maximalist deny. Use for prod accounts or regulated environments.

Change `mode:` in the action input — no code change in the agent.

## Asserting protection (per [[uat-tests-setup-end-to-end]])

CI pipelines MUST assert the outcome (decisions_count ticked), not just that
install succeeded. This step should follow every agent run step:

```yaml
- name: Assert ibounce audited real traffic
  run: |
    port="${{ steps.iam-jit.outputs.bouncer-port }}"
    baseline="${{ steps.iam-jit.outputs.decisions-count-baseline }}"
    after=$(curl -sf "http://127.0.0.1:${port}/healthz" \
      | python3 -c "import sys,json; print(json.load(sys.stdin).get('decisions_count',0))")
    delta=$((after - baseline))
    echo "decisions_count Δ=$delta"
    [ "$delta" -gt 0 ] || { echo "::error::No traffic routed through ibounce"; exit 1; }
```

If this assertion fails:
1. Check that `AWS_ENDPOINT_URL` was set before the agent step.
2. Check that the agent's boto3/aws CLI inherited the environment.
3. Check the ibounce log: `cat $RUNNER_TEMP/ibounce.log`.

## Uploading the audit log

```yaml
- name: Upload audit log
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: iam-jit-audit-log
    path: ${{ steps.iam-jit.outputs.audit-log-path }}
    retention-days: 30
```

## Bouncer selection guide

| Bouncer | Use when |
|---|---|
| `ibounce` | Agent makes AWS SDK / CLI calls (always include this) |
| `kbouncer` | Agent makes Kubernetes API calls |
| `dbounce` | Agent makes SQL calls via a proxied DB connection |
| `gbounce` | Agent makes arbitrary HTTPS calls you want to audit |

For a pure AWS agent: `bouncers: 'ibounce'`.

## OIDC + ibounce

ibounce is transparent to OIDC credential refresh. Configure AWS credentials
normally with `aws-actions/configure-aws-credentials`, then set
`AWS_ENDPOINT_URL` to ibounce. Credential refresh requests to
`sts.amazonaws.com` are proxied through ibounce and logged like any other call.

```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/ci-read-only
    aws-region: us-east-1

- uses: trsreagan3/iam-jit-action@v1
  with:
    bouncers: 'ibounce'
    mode: 'cooperative'
    harness: 'none'

# AWS_ENDPOINT_URL is now set; all subsequent aws calls go through ibounce.
```

## Runner compatibility

| Runner | Status |
|---|---|
| `ubuntu-latest` / `ubuntu-22.04` | Supported |
| `macos-latest` | Supported |
| `windows-latest` | v1.1 (shell script dependency) |
| Self-hosted Linux | Supported (Python + Go must be on PATH) |

## Troubleshooting

**ibounce did not respond within 15s**
- Check `$RUNNER_TEMP/ibounce.log` for startup errors.
- Port 8767 may be taken: check `ss -ltnp | grep 8767` (Linux) or `lsof -i:8767` (macOS).

**decisions_count did not tick**
- `AWS_ENDPOINT_URL` was probably not inherited by the agent step. Ensure it
  runs in the same job after the `iam-jit` step, or explicitly pass the env var:
  ```yaml
  env:
    AWS_ENDPOINT_URL: http://127.0.0.1:8767
  ```

**go install failed for a Go bouncer**
- The action emits a `::warning::` and continues. Only ibounce is required.
- Confirm Go 1.22+ is available: `go version`.

## Related docs

- [`docs/IBOUNCE.md`](IBOUNCE.md) — ibounce full configuration reference
- [`docs/BOOTSTRAP.md`](BOOTSTRAP.md) — local setup (macOS / Linux / Docker)
- [`docs/LOCAL-TEST-INFRA.md`](LOCAL-TEST-INFRA.md) — LocalStack + compose for local CI parity
- [`examples/github-actions/use-iam-jit-action.yml`](../examples/github-actions/use-iam-jit-action.yml) — reference workflow
