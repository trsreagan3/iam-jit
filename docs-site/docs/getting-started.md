# Getting started

Three integration paths. Pick the one that matches your use case.

## :material-console: CLI (offline, free, no signup)

```bash
pip install iam-risk-score
echo '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:DeleteBucket"],"Resource":["*"]}]}' > policy.json
iam-risk-score --offline --access-type read-write policy.json
```

Output:

```
IAM Policy Risk Score

  Score:     7/10 (high)
  Threshold: 5 (FAIL)
  Analyzer:  deterministic

Risk factors:
  - Destructive action `s3:DeleteBucket` on Resource: `*`
    (blast radius = every resource in this account)
  - Resource: `*` for s3 (broad cross-resource read/access)

Suggestions to reduce risk:
  - Scope `s3:DeleteBucket` to specific resource ARNs
```

Exit code 1 (above threshold) — usable in CI pipelines as a gate.

## :material-language-python: Python library

```python
from iam_jit import review

policy = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::my-bucket/file"]},
    ],
}
request_shape = {"spec": {"access_type": "read-only", "duration": {"duration_hours": 1}, "resource_constraints": []}}

analysis = review.analyze_policy(policy, request_shape)
print(analysis.risk_score)        # 1
print(analysis.risk_factors)      # ()
```

Same deterministic engine as the CLI. See the
[library reference](api-reference.md) for the full surface.

> **No hosted API.** The previously-documented `api.iam-risk-score.com`
> endpoint was dropped on 2026-05-24 to restore `[[no-hosted-saas]]`
> to 100%. The scorer is the moat; the offline CLI + library are
> the supported access surface.

## :material-github: GitHub Action

`.github/workflows/iam-review.yml`:

```yaml
name: IAM Policy Risk Review
on:
  pull_request:
    paths: ['terraform/**/iam*.tf', 'infrastructure/iam/*.json']

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

The action exits non-zero when the score exceeds the threshold,
failing the check — wire into branch protection as a required
status to block merges of high-risk IAM PRs.

## Common workflows

### Block merge on high risk

```yaml
- uses: trsreagan3/iam-risk-score-action@v1
  with:
    policy-file: 'iam/*.json'
    threshold: 7  # only block on tier "high"
```

### Auto-approve low-risk PRs

```yaml
- uses: trsreagan3/iam-risk-score-action@v1
  id: score
- name: Auto-approve trivial reads
  if: steps.score.outputs.would_auto_approve == 'true'
  uses: hmarr/auto-approve-action@v4
```

### Required-reviewers based on risk tier

```yaml
- uses: trsreagan3/iam-risk-score-action@v1
  id: score
- name: Request security review for high-risk
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

## Score interpretation

| Range | Tier | Typical patterns | Auto-approve? |
|---|---|---|---|
| 1–3 | low | Narrow ARN, read-only, single resource | Yes |
| 4–5 | medium | Some wildcard, write actions, sensitive service | Borderline |
| 6–10 | high | Resource: *, destructive verbs, IAM mutations | No — human review |

The default auto-approve threshold is 5. Score >= 5 means
"don't auto-approve."

## What's next

- [API reference](api-reference.md) — full request/response schema
- [CLI reference](cli-reference.md) — every flag + exit code
- [GitHub Action](github-action.md) — all inputs/outputs
- [Calibration model](calibration.md) — how scoring is calibrated
