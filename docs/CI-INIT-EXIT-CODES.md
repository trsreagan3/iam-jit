# `iam-jit init` exit-code contract

> **Source of truth** — CI parsers MUST switch on these codes, not on
> stderr text. Text output is human-readable and subject to change.

| Code | Constant | Meaning | Operator action |
|------|----------|---------|-----------------|
| 0 | `EXIT_OK` | Success — config written (or dry-run previewed). | None. |
| 2 | `EXIT_INVALID_ARGS` | Invalid flag or argument (Click convention). | Fix the flag. `iam-jit init --help` for usage. |
| 10 | `EXIT_CONFLICT` | Existing `iam-jit.yaml` found; refused to clobber per `[[creates-never-mutates]]`. | Re-run with `--overwrite` to replace, or move the existing file aside. |
| 11 | `EXIT_BOUNCER_FAIL` | A bouncer process could not be started (reserved; surfaced by autopilot start path). | Check bouncer binary on `PATH`; run `iam-jit doctor install-check`. |
| 12 | `EXIT_HARNESS_FAIL` | Harness config write failed (e.g. could not write `settings.json`). | Check file permissions on the harness config path. |
| 13 | `EXIT_NETWORK_FAIL` | Network or install failure — managed-mode HTTPS fetch failed, SSRF gate rejected the URL, or signature verification failed. | Check connectivity; verify `--org-policy` URL is HTTPS + publicly reachable. |

## Structured stderr on failure

All failures in `--quiet` mode (and `--format json` mode) emit a
machine-parsable JSON envelope to **stderr**:

```json
{
  "status": "error",
  "error_code": "INIT_CONFIG_CONFLICT",
  "message": "refusing to overwrite existing /home/runner/.iam-jit/iam-jit.yaml …",
  "config_path": "/home/runner/.iam-jit/iam-jit.yaml"
}
```

`error_code` values are stable across releases and can be used in CI
`switch` logic.  The `message` field is human-readable and MAY change.

## CI script skeleton

```bash
#!/usr/bin/env bash
set -euo pipefail

iam-jit init \
  --non-interactive \
  --quiet \
  --format json \
  --harness none \
  --skip-mcp-install \
  --no-doctor-check \
  --data-dir /var/lib/iam-jit \
  2>init-errors.json
EXIT=$?

case $EXIT in
  0)  echo "init OK" ;;
  2)  echo "bad flags — check your CI config"; cat init-errors.json; exit 1 ;;
  10) echo "config exists — re-run with --overwrite to replace"; exit 1 ;;
  13) echo "network failure — check --org-policy URL"; cat init-errors.json; exit 1 ;;
  *)  echo "unexpected exit $EXIT"; cat init-errors.json; exit 1 ;;
esac
```

## Python constants

```python
from iam_jit.cli_init import (
    EXIT_OK,           # 0
    EXIT_INVALID_ARGS, # 2
    EXIT_CONFLICT,     # 10
    EXIT_BOUNCER_FAIL, # 11
    EXIT_HARNESS_FAIL, # 12
    EXIT_NETWORK_FAIL, # 13
)
```

These constants are exported from `iam_jit.cli_init.__all__` and are
stable across minor releases.

---

*Related: [CI-FRIENDLY-MODE.md](CI-FRIENDLY-MODE.md) — full CI usage guide.*
