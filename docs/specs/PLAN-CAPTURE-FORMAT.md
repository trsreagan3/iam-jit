# Plan-capture file format (v1alpha1)

*Spec for the JSONL capture file format. The **reader**
(`iam_jit.plan_capture`) ships in v1.0 and consumes hand-authored
or externally-produced captures. The **producer** (an HTTP/SDK
proxy that records `terraform plan` / `cdk synth` calls
automatically) is planned for v1.1 — see [docs/ROADMAP-V1.1.md].*

The file is **line-delimited JSON**. One captured AWS API call per
line. Comment / blank lines are not permitted. Files may be gzipped
(suffix `.jsonl.gz`); readers MUST handle both.

## Shape of one line

```json
{
  "schema": "iam-jit.dev/plan-capture/v1alpha1",
  "ts": "2026-05-16T14:22:01.503Z",
  "service": "s3",
  "action": "ListBuckets",
  "region": "us-east-1",
  "account_id": "123456789012",
  "principal_arn": "arn:aws:iam::123456789012:role/terraform-runner",
  "request": {
    "Bucket": "logs-archive-2023"
  },
  "response_status": 200,
  "response_summary": {
    "count": 14
  },
  "iam_jit": {
    "iam_action": "s3:ListBuckets",
    "iam_resource": "*",
    "access_type": "read-only"
  }
}
```

### Field reference

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema` | string | yes | Constant `iam-jit.dev/plan-capture/v1alpha1` |
| `ts` | RFC 3339 string | yes | When the call was made |
| `service` | string | yes | AWS service name, lowercase (e.g. `s3`, `ec2`) |
| `action` | string | yes | API operation, PascalCase (e.g. `ListBuckets`) |
| `region` | string | yes | AWS region or `"global"` |
| `account_id` | string | no | 12-digit account ID if known |
| `principal_arn` | string | no | The caller's identity |
| `request` | object | no | Captured request params (PII / secrets MUST be scrubbed) |
| `response_status` | integer | no | HTTP status |
| `response_summary` | object | no | Summarized response (not the full body) |
| `iam_jit.iam_action` | string | yes | The IAM action the call requires (e.g. `s3:ListBuckets`) |
| `iam_jit.iam_resource` | string \| array | yes | ARN(s) the call touches; `*` if not scopable |
| `iam_jit.access_type` | string | yes | `read-only` / `read-write` / `admin` |

## Why the `iam_jit` block

A capture file is mostly raw AWS API observations. The `iam_jit`
sub-object is the iam-jit-specific projection: what permissions
this call needs and at what scope. Splitting this out:

- lets non-iam-jit consumers (Datadog, Wiz) read the raw call
  data without parsing iam-jit's vocabulary
- lets iam-jit consumers skip the AWS-API-to-IAM-action mapping
  (which is a non-trivial table)
- lets us version the projection independently of the raw shape

## Privacy / safety constraints

The format is designed to be **safe to share** — captured plan
files frequently move between dev laptops and CI artifacts to
get a `terraform apply` audited. Producers MUST:

- Scrub `request.SecretString`, `request.Password`, `request.UserData`
  to `"<redacted>"`.
- Truncate any field longer than 4096 chars with a `...` suffix.
- Never include the raw response body for `secretsmanager:*`,
  `kms:Decrypt`, `ssm:GetParameter (SecureString)`.

Readers MAY warn (but not fail) if these fields are present.

## Producing a capture file

**v1.0 (shipping):**

1. **Hand-authored capture** — conforming JSONL is accepted by
   the reader. Used today for recommender unit tests and any
   pipeline that emits capture files via its own tooling.

**v1.1 (planned, see [docs/ROADMAP-V1.1.md]):**

2. **`iam-jit plan-capture` HTTP proxy** (`#132` / `#119`)
   — local SigV4-speaking endpoint;
   set `AWS_ENDPOINT_URL=http://127.0.0.1:8767` and run
   `terraform plan` / `cdk synth` / `cfn-lint`. **Not yet implemented.**
3. **`iam-jit plan-capture from-boto3`** — wraps a boto3
   `Session` with an event-handler that records all calls.
   Useful for Python-only workflows (Pulumi-Python, CDK-Python).
   **Not yet implemented.**

## Consuming a capture file

```python
from iam_jit.plan_capture import read_capture

for call in read_capture("plan.jsonl"):
    print(call.iam_action, call.iam_resource)
```

The iam-jit recommender consumes captures via:

```bash
$ iam-jit synth-policy-from-capture plan.jsonl --threshold 5
```

…and emits a synthesized IAM policy + a risk score against
the canonical scorer. The agent / operator sees the same
narrow grant shape they'd get from any other iam-jit request,
but pre-derived from observed AWS calls instead of natural
language.

## Versioning

The schema string is `iam-jit.dev/plan-capture/v<version>`.
Major-version bumps are NOT backwards compatible. Readers MUST
check the version string and refuse files they don't understand
(don't silently mis-parse).

v1alpha1 is the launch shape; v1 will follow after the first
two production captures.
