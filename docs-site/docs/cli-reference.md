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
cat policy.json | iam-risk-score --offline -
```

## Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--offline` | flag | (mode required) | Run the deterministic scorer locally. No network call. |
| `--api-url URL` | string | — | Hit a hosted iam-risk-score API. Pass `https://api.iam-risk-score.com` for the public service. |
| `--api-key KEY` | string | — | Bearer token. Authenticated callers bypass the rate limit. |
| `--access-type` | choice | `read-only` | `read-only` or `read-write`. Affects scoring. |
| `--duration-hours N` | int | 1 | Hypothetical grant duration. Longer = higher score for medium-risk policies. |
| `--description "..."` | string | — | One-line context for the LLM narrative (paid tier only). |
| `--threshold N` | int | 5 | Score >= threshold → FAIL exit code |
| `--format` | choice | `human` | `human`, `json`, or `github` |
| `--version` | flag | — | Print version + exit |
| `--help` | flag | — | Print this help |

One of `--offline` or `--api-url` is required.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Pass — score < threshold |
| 1 | Fail — score >= threshold |
| 2 | Bad input (malformed JSON, unreadable file, etc.) |
| 3 | API error (network failure, 5xx response, etc.) |

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
    iam-risk-score --offline --threshold 5 "$policy" || {
        echo "❌ $policy exceeds risk threshold; refusing commit"
        exit 1
    }
done
```

### CI gate

```bash
iam-risk-score --offline --threshold 5 --format github iam/*.json
```

### Cache scoring results across CI runs

```bash
FP=$(iam-risk-score --offline --format json policy.json | jq -r .policy_fingerprint)
if cache-has "$FP"; then
    echo "Skipping (cached): $FP"
else
    iam-risk-score --offline policy.json
    cache-store "$FP"
fi
```

### Hosted API mode

```bash
# Free tier — no key
iam-risk-score --api-url https://api.iam-risk-score.com policy.json

# Paid tier — set IAM_RISK_SCORE_API_KEY env var
export IAM_RISK_SCORE_API_KEY=iamjit_...
iam-risk-score --api-url https://api.iam-risk-score.com policy.json
```
