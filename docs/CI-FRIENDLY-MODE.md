# CI-friendly `iam-jit init`

> **Per `[[automatic-bootstrap-must-just-work-everywhere]]`**: `iam-jit init`
> must work in CI/CD pipelines with no TTY, no human interaction, and no
> dependency on parsed text output.

## New flags (added in #744)

| Flag | Env-var alternative | Effect |
|------|--------------------|----|
| `--quiet` | `IAM_JIT_INIT_QUIET=1` | Suppresses human-facing stdout banners on success. Structured JSON errors still go to stderr on failure. |
| `--format json` | `IAM_JIT_INIT_FORMAT=json` | Writes the init result summary to stdout as machine-parsable JSON. |

These flags compose freely with existing flags:

```bash
iam-jit init \
  --non-interactive \
  --quiet \
  --format json \
  --harness none \
  --skip-mcp-install \
  --no-doctor-check \
  --data-dir /var/lib/iam-jit
```

## JSON output schema (`--format json`)

On success, a single JSON line is written to stdout:

```json
{
  "status": "ok",
  "version": "1.0.0",
  "harness": "claude-code",
  "bouncers_started": ["ibounce", "gbounce"],
  "config_path": "/home/runner/.iam-jit/iam-jit.yaml",
  "env_vars_set": {
    "AWS_ENDPOINT_URL": "http://localhost:8767"
  },
  "warnings": [],
  "errors": []
}
```

On failure (any exit code > 0), a JSON envelope is written to **stderr**:

```json
{
  "status": "error",
  "error_code": "INIT_CONFIG_CONFLICT",
  "message": "refusing to overwrite existing /home/runner/.iam-jit/iam-jit.yaml …",
  "config_path": "/home/runner/.iam-jit/iam-jit.yaml"
}
```

`error_code` is stable. `message` is human-readable and may change between
releases. CI scripts MUST NOT parse `message`.

## Exit-code reference

See [CI-INIT-EXIT-CODES.md](CI-INIT-EXIT-CODES.md) for the full table.

Quick reference:

| Code | Meaning |
|------|---------|
| 0 | success |
| 2 | invalid args |
| 10 | config conflict — use `--overwrite` |
| 11 | bouncer start failed |
| 12 | harness write failed |
| 13 | network / install failure |

## GitHub Actions recipe

```yaml
- name: Bootstrap iam-jit
  run: |
    iam-jit init \
      --non-interactive \
      --quiet \
      --format json \
      --harness none \
      --skip-mcp-install \
      --no-doctor-check \
      --data-dir "$HOME/.iam-jit" \
      > init-result.json
  env:
    IAM_JIT_DATA_DIR: ${{ runner.temp }}/iam-jit

- name: Parse init result
  run: |
    CONFIG=$(jq -r '.config_path' init-result.json)
    echo "Config written to: $CONFIG"
    jq '.warnings[]' init-result.json || true
```

## GitLab CI recipe

```yaml
bootstrap-iam-jit:
  script:
    - |
      iam-jit init \
        --non-interactive \
        --quiet \
        --format json \
        --harness none \
        --skip-mcp-install \
        --no-doctor-check \
        --data-dir "$CI_PROJECT_DIR/.iam-jit" \
        2>init-errors.json || {
          echo "init failed (exit $?):"
          cat init-errors.json
          exit 1
        }
  artifacts:
    when: on_failure
    paths:
      - init-errors.json
```

## CircleCI recipe

```yaml
steps:
  - run:
      name: Bootstrap iam-jit
      command: |
        iam-jit init \
          --non-interactive \
          --quiet \
          --format json \
          --harness none \
          --skip-mcp-install \
          --no-doctor-check 2>init-errors.json
        EXIT=$?
        if [ $EXIT -ne 0 ]; then
          echo "iam-jit init failed (exit $EXIT):"
          cat init-errors.json
          exit $EXIT
        fi
```

## Shell one-liner (environment variable form)

```bash
IAM_JIT_INIT_QUIET=1 \
IAM_JIT_INIT_FORMAT=json \
iam-jit init --non-interactive --harness none --skip-mcp-install --no-doctor-check
```

## Combining with `--managed` (corp deployment)

```bash
iam-jit init \
  --managed \
  --org-policy https://internal.example.com/iam-jit/policy.yaml \
  --org-public-key /etc/iam-jit/org.pub \
  --quiet \
  --format json \
  --no-doctor-check
```

On `ManagedPolicyError` (SSRF gate / bad signature / network failure),
exit code is 13 and stderr carries:

```json
{
  "status": "error",
  "error_code": "INIT_MANAGED_FETCH_FAILED",
  "message": "org-policy URL network error: …"
}
```

## Per `[[ibounce-honest-positioning]]`: quiet ≠ silent failure

`--quiet` suppresses **success banners** only.  Errors are **always**
written to stderr as structured JSON regardless of `--quiet`.  A CI job
that captures stderr will always see machine-readable failure detail.

---

*Related: [CI-INIT-EXIT-CODES.md](CI-INIT-EXIT-CODES.md) — exit-code contract table.*
