# iam-risk-score GitHub Action

Score AWS IAM policies on every PR. Block merges to main when a
policy exceeds your risk threshold; require an extra reviewer for
medium-risk changes; auto-merge low-risk reads.

## Quick start

```yaml
# .github/workflows/iam-risk-review.yml
name: IAM Policy Risk Review
on:
  pull_request:
    paths:
      - 'terraform/**/iam*.tf'
      - 'cdk/**/policies/*.json'
      - 'infrastructure/iam/*.json'

jobs:
  risk-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: trsreagan3/iam-risk-score-action@v1
        with:
          policy-file: 'infrastructure/iam/*.json'
          threshold: 5
          comment-on-pr: true
```

## Inputs

| Name | Description | Default |
|---|---|---|
| `policy-file` | Path or glob to policy JSON | (required) |
| `threshold` | Pass/fail score boundary | `5` |
| `api-url` | Scoring API URL; omit for offline mode | `''` (offline) |
| `api-key` | API key for hosted service | `''` |
| `access-type` | `read-only` or `read-write` | `read-write` |
| `duration-hours` | Hypothetical grant duration | `1` |
| `comment-on-pr` | Post score as PR comment | `false` |

## Outputs

| Name | Description |
|---|---|
| `score` | Worst score across policy files (1-10) |
| `tier` | `low` \| `medium` \| `high` |
| `would_auto_approve` | `'true'` if below threshold |
| `policy_fingerprint` | sha256 of policy (use for CI caching) |

## Common workflows

### Required-reviewers based on score

```yaml
- uses: trsreagan3/iam-risk-score-action@v1
  id: score
  with:
    policy-file: 'iam/*.json'

- name: Require security review for high-risk
  if: steps.score.outputs.tier == 'high'
  uses: actions/github-script@v7
  with:
    script: |
      await github.rest.pulls.requestReviewers({
        ...context.repo,
        pull_number: context.issue.number,
        team_reviewers: ['security-team'],
      });
```

### Block merge on high risk

```yaml
- uses: trsreagan3/iam-risk-score-action@v1
  with:
    policy-file: 'iam/*.json'
    threshold: 7  # only block on high
```

The action exits non-zero when score >= threshold, which fails
the workflow → branch protection rule "requires this check to
pass" → merge button greys out.

### Auto-approve trivial changes

```yaml
- uses: trsreagan3/iam-risk-score-action@v1
  id: score
  with:
    policy-file: 'iam/*.json'
    threshold: 3

- name: Auto-approve if low risk
  if: steps.score.outputs.would_auto_approve == 'true'
  uses: hmarr/auto-approve-action@v4
```

## Offline vs hosted mode

**Offline (default):** runs the deterministic scorer locally.
Fast, no network call, no API key. The LLM narrative is
unavailable (the deterministic score is the same).

**Hosted (set `api-url`):** calls the iam-risk-score SaaS. Adds
the LLM narrative and contributes to cross-org calibration data.
Free tier: 100 PR scans/month. Paid tiers for higher usage.

## What the scoring model considers

- Service sensitivity (iam, kms, secretsmanager, etc.)
- Action breadth (specific action vs `s3:*` vs `*`)
- Resource scope (specific ARN vs wildcard)
- Destructive verbs (Delete, Destroy, Terminate, etc.)
- access_type mismatch (read-only marked but mutates state)
- iam:PassRole privilege escalation patterns
- Admin-curated context (your org's sensitive services)
- Grant duration amplification

Full calibration: see [docs/USE-CASES.md](https://github.com/trsreagan3/iam-jit/blob/main/docs/USE-CASES.md).

## Self-hosting

For air-gapped environments, the offline mode runs entirely on
the runner — no external API calls. The action installs the
`iam-risk-score` Python package which contains the same
deterministic scorer the SaaS uses.
