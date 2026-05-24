# Library reference

The `iam-jit` Python package exposes the deterministic scorer as a
library. The previously-documented hosted HTTP API
(`api.iam-risk-score.com`) was dropped on 2026-05-24 — see
`[[no-hosted-saas]]`. The library is now the supported programmatic
entry point.

## `review.analyze_policy(...)`

Score an AWS IAM policy. Stateless, idempotent, deterministic.

```python
from iam_jit import review

policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::my-bucket/file"],
        }
    ],
}

request_shape = {
    "spec": {
        "access_type": "read-only",       # or "read-write"
        "duration": {"duration_hours": 1},
        "resource_constraints": [],
    }
}

analysis = review.analyze_policy(policy, request_shape)
print(analysis.risk_score)        # int 1-10
print(analysis.risk_factors)      # list[str]
print(analysis.suggestions)       # list[str]
print(analysis.analyzer)          # "deterministic"
print(analysis.llm_narrative)     # str | None (only set when an LLM backend is configured)
```

### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `policy` | `dict` | yes | AWS IAM policy document |
| `request_shape` | `dict` | yes | Wrapper carrying `spec.access_type`, `spec.duration.duration_hours`, and `spec.resource_constraints`. See `tests/conftest_routes.py::request_payload` for a minimal example. |
| `extra_sensitive_services` | `tuple[str, ...]` | no | Extend the scorer's sensitive-service set (e.g. `("dynamodb", "kms")`) |
| `extra_high_impact_actions` | `tuple[str, ...]` | no | Extend the scorer's high-impact action set |

### Returns

A `PolicyAnalysis` dataclass with the following attributes:

| Attribute | Type | Description |
|---|---|---|
| `risk_score` | `int` | 1-10 risk score. Same input -> same value, every time. |
| `risk_factors` | `tuple[str, ...]` | Human-readable rule-fire descriptions |
| `suggestions` | `tuple[str, ...]` | Actionable risk-reduction recommendations |
| `analyzer` | `str` | `"deterministic"` (or `"deterministic+<llm-backend>"` when an LLM is configured) |
| `llm_narrative` | `str \| None` | Plain-English narrative when an LLM backend is configured; `None` otherwise |

### Tier mapping

| Score | Tier |
|---|---|
| 1-3 | `low` |
| 4-5 | `medium` |
| 6-10 | `high` |

The 5-point threshold is iam-jit's default auto-approve cutoff. The
mapping is exposed structurally by `review` consumers; downstream
tooling should not hard-code the boundaries (the calibration corpus
may shift them in future scorer versions).

## CLI wrapper — `iam-risk-score`

For shell + CI use, the same engine is wrapped in the
`iam-risk-score` console script. See [CLI reference](cli-reference.md)
for the full flag matrix.

```bash
$ iam-risk-score path/to/policy.json
$ iam-risk-score path/to/policy.json --format sarif > findings.sarif
$ iam-risk-score path/to/policy.json --format github
$ iam-risk-score path/to/policy.json --format json | jq '.score'
```

## Determinism + safety contract

The deterministic scorer is the moat. Same input -> same numeric
score, every time, on every machine. The optional LLM contributes
narrative + suggestions only; it cannot change the numeric score.

This is a safety contract: a compromised or hallucinating LLM
cannot lower the score to sneak a policy under an auto-approve
threshold. The score is computed by `_deterministic()` BEFORE any
LLM is consulted, and the LLM's output is constrained to narrative
+ suggestions only.

Regression-tested by:

- 1,489 AWS-managed-policy snapshots — every published AWS-managed
  policy must score within ±1 of its target band.
- 203 / 217 documented attack patterns from the open security
  literature (Bishop Fox / Rhino / HackingTheCloud / MITRE) —
  pinned by score.

See `docs/CONVERGENCE-REPORT-2026-05.md` and
`docs/ADVERSARIAL-LOOP-PROCESS.md` for the calibration methodology.

## Idempotency + caching

Identical policies (by canonical JSON) produce identical results.
The CLI emits a `policy_fingerprint` (`sha256:...` of the canonical
JSON) in `--format json` and `--format sarif` output. Use it to
dedupe expensive scoring calls in your CI / agent runtime:

```python
import hashlib, json

fingerprint = "sha256:" + hashlib.sha256(
    json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
if fingerprint in cache:
    return cache[fingerprint]
analysis = review.analyze_policy(policy, request_shape)
cache[fingerprint] = analysis
```
