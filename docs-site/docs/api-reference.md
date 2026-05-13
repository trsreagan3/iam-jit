# API reference

## `POST /api/v1/score`

Score an AWS IAM policy. Stateless, idempotent, JSON in / JSON out.

**Base URL**: `https://api.iam-risk-score.com`

### Request

```http
POST /api/v1/score HTTP/1.1
Host: api.iam-risk-score.com
Content-Type: application/json
Authorization: Bearer <api-key>   # optional for free tier

{
  "policy": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": ["arn:aws:s3:::my-bucket/file"]
      }
    ]
  },
  "access_type": "read-only",
  "duration_hours": 1,
  "description": "Read app config from S3"
}
```

### Request fields

| Field | Type | Required | Description |
|---|---|---|---|
| `policy` | object | yes | AWS IAM policy document |
| `access_type` | string | no (default `read-only`) | `read-only` or `read-write` |
| `duration_hours` | int | no (default 1) | Hypothetical grant duration, 1–8760 |
| `description` | string | no | Optional one-line context for the LLM narrative; max 500 chars |
| `additional_sensitive_services` | string[] | no | Admin context — extend scorer's sensitive-service set |
| `additional_high_impact_actions` | string[] | no | Admin context — extend scorer's high-impact action set |

### Response

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600, s-maxage=86400
Vary: Authorization
X-Policy-Fingerprint: sha256:abc...

{
  "score": 1,
  "tier": "low",
  "would_auto_approve_at_threshold_5": true,
  "factors": ["All statements are scoped or limited; no broad patterns"],
  "suggestions": [],
  "llm_narrative": null,
  "analyzer": "deterministic",
  "policy_fingerprint": "sha256:abc...",
  "api_version": "v1"
}
```

### Response fields

| Field | Type | Description |
|---|---|---|
| `score` | int (1–10) | Risk score. Same input → same value every time. |
| `tier` | string | `low` (1–3), `medium` (4–5), or `high` (6–10) |
| `would_auto_approve_at_threshold_5` | bool | Convenience: `score < 5` |
| `factors` | string[] | Human-readable rule-fire descriptions |
| `suggestions` | string[] | Actionable risk-reduction recommendations |
| `llm_narrative` | string\|null | Paid-tier LLM-generated explanation; null on free tier |
| `analyzer` | string | `deterministic` or `deterministic+<llm-backend>` |
| `policy_fingerprint` | string | sha256 of the canonical policy JSON, prefixed `sha256:` |
| `api_version` | string | API version that produced this response (`v1`) |

### Response headers

| Header | Value | Purpose |
|---|---|---|
| `Cache-Control` | `public, max-age=3600, s-maxage=86400` | Score is deterministic; safe to cache by content-hash |
| `Vary` | `Authorization` | Don't share paid-tier responses with anonymous cache entries |
| `X-Policy-Fingerprint` | `sha256:...` | Same as response body field; usable as cache key by CDNs |

## Status codes

| Code | Meaning | When |
|---|---|---|
| 200 | OK | Successful scoring |
| 400 | Bad Request | Malformed policy, invalid access_type, prompt-injection detected |
| 401 | Unauthorized | API key required (paid tier) and missing/invalid |
| 429 | Too Many Requests | Free-tier rate limit (30 req/min/IP); paid keys bypass |
| 503 | Service Unavailable | Self-hosted deploy not configured (rare) |

## Rate limits

| Tier | Limit | Where enforced |
|---|---|---|
| Free (anonymous) | 30 req/min/IP | In-Lambda (process-local) + CloudFront WAFv2 rate-based rule (edge) |
| Paid (authenticated) | Per-tier (5K, 50K, 500K, unlimited per month) | Quota tracking |

429 responses include a `Retry-After` header indicating the seconds
to wait before retrying.

## Security defenses on the endpoint

- **Prompt-injection scanner** walks every string in the policy and
  description; detection returns 400 with a generic detail (no
  field-name leak to abusers) + audit-log entry server-side.
- **Body size limit** of 256 KiB (configurable). 413 on larger.
- **Rate limit** documented above.
- **Edge protection** (CloudFront + WAFv2 rate rule, optional via
  `EnableEdgeProtection=true` on self-hosted deploys).

The deterministic safety contract: even a fully-compromised LLM
cannot lower the numeric score. The score is computed by
`_deterministic()` before any LLM is consulted, and the LLM's
output is constrained to narrative + suggestions only.

## Idempotency

Identical policies (by canonical JSON) produce identical responses
and identical `policy_fingerprint` values. Use the fingerprint to
dedupe expensive scoring calls in your CI:

```python
fingerprint = sha256(canonical_policy_json).hexdigest()
if fingerprint in cache:
    return cache[fingerprint]
# else hit the API
```

CloudFront in front of the hosted API does this automatically
when `EnableEdgeProtection=true`.
