# Security Policy

iam-jit / iam-risk-score handles AWS IAM credential issuance + risk
scoring. Security is the product.

## Reporting a vulnerability

**Email: security@iam-jit.dev** (PGP key fingerprint below).

Please **do not** open public GitHub issues for security
vulnerabilities. We respond to all reports within 48 hours
(usually faster).

### What to include

- A description of the vulnerability + how to reproduce
- Affected version(s) — software, scorer, or both
- Your assessment of impact (CRIT / HIGH / MED / LOW)
- Whether you've discussed the issue with anyone else

### What you can expect from us

| Severity | Initial response | Patch shipped within | Disclosure |
|---|---|---|---|
| CRITICAL | 24 hours | 7 days | 14 days from initial report |
| HIGH | 48 hours | 30 days | 60 days |
| MEDIUM | 1 week | 90 days | 180 days |
| LOW | 2 weeks | Next minor release | Public from disclosure |

Full SLA details in [docs/SECURITY-SLA.md](docs/SECURITY-SLA.md).

### Coordinated disclosure

For CRIT and HIGH issues, we follow coordinated disclosure:

1. You report privately to security@iam-jit.dev
2. We acknowledge within the SLA + begin work on a fix
3. We coordinate a disclosure date (~14 days for CRIT, ~30 for HIGH)
4. Patch ships + GitHub Security Advisory published
5. Public disclosure with credit to the reporter (if desired)

### Recognition

Researchers who report vulnerabilities responsibly are credited
in:

- The GitHub Security Advisory for the issue
- Release notes for the patch version
- A `docs/security/HALL-OF-FAME.md` page (with permission)

We don't currently run a paid bug bounty program but plan to
launch one once the product is more mature. Pre-bounty: a
genuine "thank you" + public recognition + occasional swag.

## Scope

In scope:

- The `iam-jit` Python package + its deployed Lambda surface
- The `iam-risk-score` CLI + hosted API
- The MCP server
- The GitHub Action
- All published deployment artifacts (SAM templates, Docker
  images when shipped, PyPI package)
- The web UI

Out of scope:

- Bugs in dependencies that don't affect iam-jit's security
  posture (report to upstream)
- Issues in customer-side deployments that we can't reproduce
  with the published artifacts
- Theoretical attacks without a concrete exploitation path

## What "security" means here

iam-jit's threat model:

| Attacker | What they can do | What iam-jit prevents |
|---|---|---|
| Compromised iam-jit Lambda (self-host) | Issue credentials within their AWS account | Bounded by what the Lambda's role can do; audit logs to detect; `creates-never-mutates` invariant means it can't elevate existing roles. There is no multi-tenant hosted SaaS tier, so cross-tenant blast radius does not exist by design. |
| Compromised customer API token | Submit grant requests; receive credentials within token's scope | Token-bound rate limits + admin revocation + per-token IP allowlist (optional) |
| Compromised customer AWS principal | Whatever the principal can already do | Out of scope — iam-jit doesn't add powers, just narrows the use of existing ones |
| Compromised approver Slack account | Approve requests on Slack | Signed-request authentication + workspace pin + channel pin + iam-jit-side role check (approver flag on iam-jit User) |
| Stolen iam-jit-issued STS credentials | Use them within their narrow scope until TTL expiry | Region-scope + account-scope + 1h TTL + egregious-action floor |
| Malicious / prompt-injected agent | Request bad grants; iam-jit gates by score | Scoring engine + auto-approve threshold + approval routing + audit + `creates-never-mutates` |

We are NOT trying to defend against:

- An attacker who has FULL admin AWS credentials of the customer
- Compromise of the IdP (Google Workspace / Okta) — those breaches
  are catastrophic regardless of iam-jit
- AWS itself being compromised
- Bugs in PyJWT / FastAPI / boto3 that we can't reproduce or fix

## Audit history

iam-jit follows the [[adversarial-loop-process]] — multiple
rounds of black-box + white-box audits with pinned regression
tests. Audit history:

| Round | Focus | Findings | Status |
|---|---|---|---|
| 1-6 | Foundational app-security | All closed | Pinned tests at `tests/test_appsec_audit_round*_*.py` |
| 7 | `bridge_role.py` + new code | 2 CRIT + 2 HIGH + 2 MED | All closed (mostly via deletion of `bridge_role.py`) |
| 8 | Slack approval bot | 1 HIGH + 3 MED + 2 LOW + 1 INFO | HIGH + 3 MED closed |
| 9 | OIDC SSO multi-provider | 1 HIGH + 2 MED + 3 LOW + 2 INFO | HIGH + 2 MED + 3 LOW closed |

Full audit docs: `docs/security/AUDIT-2026-05-WB-ROUND*.md`.

## Sensitive-information policy

When reporting a vulnerability, **do not** include:

- Real customer AWS account IDs (use `123456789012`)
- Real API tokens, secrets, or session cookies
- PII / PHI of any kind
- Credentials of any kind

We will redact anything you send anyway, but don't make it
necessary.

## PGP key

```
[PGP fingerprint TBD — will publish at security@iam-jit.dev
before v1.0 launch]
```

If you require encrypted communication and the key isn't yet
published, request it at security@iam-jit.dev.

---

Last updated: 2026-05-15
