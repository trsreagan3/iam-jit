# CLI reference

## Install

```bash
pip install iam-risk-score
```

Two binaries are installed: `iam-risk-score` (the scoring CLI) and
`iam-jit` (full provisioner — separate command, not covered here).

## Synopsis

```
iam-risk-score [OPTIONS] POLICY_FILE
```

`POLICY_FILE` is a path to an AWS IAM policy JSON file. Use `-` for
stdin:

```bash
cat policy.json | iam-risk-score -
```

The CLI is **offline-only** — runs the deterministic scorer locally
without any network call. The previously-documented `--api-url` /
`--api-key` remote mode was dropped on 2026-05-24 when the hosted
`api.iam-risk-score.com` Lambda was removed (see `[[no-hosted-saas]]`).
The `--offline` flag is silently accepted as a back-compat no-op
until v1.1 so existing CI scripts keep working.

## Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--access-type` | choice | `read-only` | `read-only` or `read-write`. Affects scoring. |
| `--duration-hours N` | int | 1 | Hypothetical grant duration. Longer = higher score for medium-risk policies. |
| `--description "..."` | string | — | One-line context for the score (informational; the offline CLI does not emit an LLM narrative). |
| `--threshold N` | int | 5 | Score >= threshold → FAIL exit code |
| `--format` | choice | `human` | `human`, `json`, `github`, or `sarif` |
| `--version` | flag | — | Print version + exit |
| `--help` | flag | — | Print this help |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Pass — score < threshold |
| 1 | Fail — score >= threshold |
| 2 | Bad input (malformed JSON, unreadable file, etc.) |
| 3 | Internal scoring error |

## Output formats

### `--format human` (default)

Colorized terminal output, designed for interactive use:

```
IAM Policy Risk Score

  Score:     7/10 (high)
  Threshold: 5 (FAIL)
  Analyzer:  deterministic

Risk factors:
  - Destructive action `s3:DeleteBucket` on Resource: `*`
    (blast radius = every resource in this account)

Suggestions to reduce risk:
  - Scope `s3:DeleteBucket` to specific resource ARNs
```

### `--format json`

Programmatic consumption. Same shape as the API response:

```json
{
  "score": 7,
  "tier": "high",
  "would_auto_approve_at_threshold_5": false,
  "factors": ["..."],
  "suggestions": ["..."],
  "llm_narrative": null,
  "analyzer": "deterministic",
  "policy_fingerprint": "sha256:..."
}
```

### `--format github`

GitHub Actions workflow commands — sets outputs + emits annotations:

```
::set-output name=score::7
::set-output name=tier::high
::set-output name=would_auto_approve::false
::set-output name=policy_fingerprint::sha256:abc
::error title=IAM Policy Risk::Score 7/10 (high) — above threshold 5
```

Use with the GitHub Action wrapper for tighter integration —
see [GitHub Action docs](github-action.md).

## Examples

### Pre-commit hook

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit
for policy in $(git diff --cached --name-only --diff-filter=ACM | grep -E '/iam-.*\.json$'); do
    iam-risk-score --threshold 5 "$policy" || {
        echo "❌ $policy exceeds risk threshold; refusing commit"
        exit 1
    }
done
```

### CI gate

```bash
iam-risk-score --threshold 5 --format github iam/*.json
```

### Cache scoring results across CI runs

```bash
FP=$(iam-risk-score --format json policy.json | jq -r .policy_fingerprint)
if cache-has "$FP"; then
    echo "Skipping (cached): $FP"
else
    iam-risk-score policy.json
    cache-store "$FP"
fi
```

### SARIF output for GitHub Code Scanning

```bash
iam-risk-score --format sarif policy.json > findings.sarif
# Then in your workflow:
#   - uses: github/codeql-action/upload-sarif@v3
#     with: { sarif_file: findings.sarif }
```

Findings show up inline on the PR + on the Security tab.
