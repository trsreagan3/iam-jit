# Security SLA

iam-jit's security-patch SLA. Communicated explicitly so
procurement + compliance reviewers can map iam-jit to their
internal vendor-risk policies.

## Patch SLA table

| Severity | Disclosure → patch shipped | Customer notified → upgrade mandatory |
|---|---|---|
| CRITICAL | 7 days | 14 days |
| HIGH | 30 days | 60 days |
| MEDIUM | 90 days | 180 days |
| LOW | Next scheduled minor release | Next scheduled minor release |

### What each severity means

- **CRITICAL**: remotely exploitable; bypasses authentication or
  authorization; allows arbitrary AWS credential issuance; data
  exfiltration from iam-jit's audit log or session store.
- **HIGH**: bypasses a security control under specific
  conditions; privilege escalation within iam-jit; significant
  information disclosure (e.g., credentials in logs).
- **MEDIUM**: defense-in-depth weakness; partial control bypass;
  weakens an iam-jit security property without directly
  exploitable impact.
- **LOW**: hardening opportunity; doesn't change the threat
  model materially; usually code-quality or minor-error-path
  improvement.

## Process for CRITICAL / HIGH

1. **Triage** — privately, by iam-jit maintainers. Confirm
   severity + reproduction.
2. **Develop fix** — in a private fork. Test against the full
   regression corpus.
3. **Coordinate disclosure** with the reporter. Default window:
   14 days for CRIT, 30 for HIGH. Earlier if mutually agreed.
4. **Publish patch** — tagged GitHub release with a brief
   "what's fixed" summary. Detailed advisory follows on
   disclosure day.
5. **GitHub Security Advisory** published on disclosure day.
6. **Email list notification** to customers subscribed to
   `releases@iam-jit.dev`.
7. **In-product notification** for deployments running
   version-check.

## For self-host customers

- We notify customers via the registered email + GitHub
  Security Advisory on disclosure day.
- Customer responsibility: deploy the patched version within
  the "upgrade mandatory" window per the table above.
- For CRITICAL: we recommend deploying within hours of patch
  release. The 14-day window is a maximum, not a target.

## For hosted SaaS customers (Indie / Pro / Team)

- We auto-apply patches on disclosure day. No customer action
  required.
- Status page updates: `status.iam-jit.dev` (when launched).
- Customer can opt to delay the patch by ≤24 hours via the
  admin UI if they have a deploy freeze.

## For dedicated managed customers (when offered)

- We coordinate patch deployment with each customer's change
  window.
- Default: deployed within the SLA, in a pre-agreed maintenance
  window.

## Coordinated disclosure

For CRIT and HIGH issues:

- Embargo period from initial private report → disclosure day
- Customer notified ~24-48 hours BEFORE disclosure so they can
  patch ahead of the public announcement
- Reporter credited (with permission) in the disclosure

## Audit cadence (preventative)

iam-jit follows the [[adversarial-loop-process]]:

- Black-box + white-box audit rounds spawned after each major
  feature lands (e.g., Slack bot → round 8, OIDC → round 9)
- Pinned regression tests added for every closed finding (at
  `tests/test_appsec_audit_round*_*.py`)
- Independent reviewers welcome; report via the [security
  policy](../SECURITY.md)

## Compliance framework mappings

This SLA satisfies:

- **PCI DSS 6.3** (security update procedures)
- **SOC 2 CC4** (monitoring activities) + CC7 (system
  operations)
- **HIPAA §164.308(a)(5)(ii)(B)** (protection from malicious
  software)
- **ISO 27001 A.12.6.1** (technical vulnerability management)
- **NIST 800-53 SI-2** (flaw remediation)

See [docs/compliance/COMPLIANCE-MAPPING.md](compliance/COMPLIANCE-MAPPING.md)
(when published) for control-by-control mapping.

## Out-of-scope SLAs

We do NOT commit to:

- Patch SLAs for upstream dependencies — they have their own
  vulnerability-management processes (boto3, FastAPI, PyJWT,
  etc.). We track CVEs in our dependencies and update on a
  best-effort basis; specifically, we monitor `cryptography`,
  `PyJWT`, `requests`/`httpx`, `boto3`, `fastapi`, `pydantic`,
  `python-multipart`, and `itsdangerous`.
- Patches for issues in customer-controlled deployments that
  we cannot reproduce with the published artifacts (e.g.,
  customer-side custom forks).

## Contact

Vulnerability reports: **security@iam-jit.dev** (see
[SECURITY.md](../SECURITY.md)).
