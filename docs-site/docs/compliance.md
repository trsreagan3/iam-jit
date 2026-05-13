# Compliance

## Data handling

- **What we receive**: the IAM policy JSON you submit + the optional
  `description` field. Both are processed in memory and discarded
  after the response is built.
- **What we store**: nothing about the policy content. Audit logs
  record only the `policy_fingerprint` (sha256 of canonical JSON),
  not the policy itself.
- **What we share**: nothing. The scoring API doesn't send your
  policy to any third party.
- **Where it's processed**: us-east-1 by default. Self-hosted
  deploys are in your account, your region — fully under your
  control.

## Credential safety

- The API never receives your AWS credentials. It scores the
  POLICY JSON ONLY.
- API keys for paid tiers are stored as sha256 hashes — the raw
  bearer token exists only briefly during issuance + delivery
  via SES.
- API keys are scoped to per-IAM-Identity-Center-user-equivalent;
  Stripe subscription cancellation auto-revokes keys via the
  webhook.

## SOC 2

**Status**: SOC 2 Type 1 in progress (target: Q3 2026).

The Enterprise tier ($2K+/mo) includes:

- Audit-trail evidence export (log retention, IAM principal mapping,
  access-grant lineage)
- DPA / BAA on request
- Dedicated security review on integration

## GDPR / privacy

The service doesn't intentionally process personal data. Policy
descriptions are free-text and could contain PII if you write it
there — we recommend not. Audit logs record only the `policy_
fingerprint` + source IP + timestamp, no policy content.

For self-hosted deploys, you control the data lifecycle entirely.

## Regression-tested calibration

Every commit runs 2,691 unit tests in CI, including:

- 1,489 AWS managed policy snapshots (pinned with ±1 tolerance —
  any rule change that significantly shifts AWS-blessed verdicts
  fails CI)
- 83 adversarial attack patterns (your "did we forget the obvious
  attack vector" regression)
- 10 real-world custom policies
- Calibration loop measuring agreement against an Opus-4.7-as-judge
  evaluation — currently 100% within ±1

This isn't a feature — it's the receipts. Any score the API gives
you today is the same score it gave yesterday and will give
tomorrow.

## Self-hosting compliance benefits

If you have SOC 2 / PCI / HIPAA / FedRAMP requirements, self-hosted
is the simpler path. The SAM template configures:

- 545-day CloudWatch log retention by default (above PCI DSS 1-year
  minimum; SOC 2 / ISO 27001 typically expect 1+ year)
- A `MinLogRetentionDays` floor that prevents admins shortening
  retention to hide evidence
- IAM Deny statements protecting the audit log group from
  destruction even by privileged callers
- Tamper-evident logging on every admin action

For the full hardening checklist, see [production hardening](production-hardening.md)
and the [security notes](https://github.com/trsreagan3/iam-jit/blob/main/docs/security-notes.md)
in the source repo.
