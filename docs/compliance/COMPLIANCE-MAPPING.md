# Compliance Mapping

How iam-jit's design satisfies specific control requirements
under PCI DSS, SOC 2, HIPAA, and ISO 27001.

> **Important caveat:** iam-jit (the company) does NOT hold any
> third-party compliance certifications at v1.0. This document
> maps iam-jit's TECHNICAL controls to framework requirements,
> not certifications. Customers using iam-jit retain
> responsibility for their own compliance posture; their
> auditors review iam-jit's implementation as part of the
> overall environment review. Self-host deployments fold
> iam-jit into the customer's compliance scope (their certs
> cover the deployment).

## Audience

This document is intended for:

- Customer security teams evaluating iam-jit
- External compliance auditors (PCI QSA, SOC 2 auditors, etc.)
- iam-jit's eventual SOC 2 Type II preparation

Cross-references to memos prefixed `[[...]]` are internal
design rationale, not customer-facing documentation.

## PCI DSS v4.0

### §8.4 — Multi-Factor Authentication

iam-jit's 3-layer MFA model satisfies §8.4 requirements:

| Requirement | iam-jit implementation |
|---|---|
| §8.4.1 — MFA for all non-console admin access to CDE | Layer A: OIDC SSO with IdP-enforced MFA. Layer B: `aws:MultiFactorAuthPresent` Condition propagation. (Layer B requires the `create-not-assume` deployment pattern; until that ships, MFA assertion is captured in iam-jit's audit log per §10 — the chain "human authorizer MFA + system execution" satisfies the requirement per the standard's intent.) |
| §8.4.2 — MFA for all remote access into CDE | Same as 8.4.1. Remote access via iam-jit-issued credentials inherits the human authorizer's MFA assertion. |
| §8.4.3 — MFA required for personnel with administrative access | Approver users + admin users in iam-jit are gated through the OIDC SSO flow; MFA is enforced at the IdP. |

### §8.6 — System and Application Account Use

The emerging-consensus framing for AI agents under §8.6:

| Requirement | iam-jit implementation |
|---|---|
| §8.6.1 — Interactive use of system accounts prevented unless necessary | AI agents are SYSTEM accounts (per definition). Their use IS interactive (acting on behalf of humans). iam-jit handles this by recording the HUMAN AUTHORIZER for every agent action. Audit chain: "agent X acted under admin Y's authorization; admin Y completed MFA at HH:MM." This makes the human, not the agent, the responsible party — satisfying the spirit of §8.6 + §8.4. |
| §8.6.2 — Hard-coded credentials prohibited | iam-jit issues short-lived (1h default) STS credentials per task. No standing keys. |
| §8.6.3 — Interactive use logged | Every grant + every assume-role is logged via iam-jit's audit module + AWS CloudTrail. |

### §10 — Audit Logs

| Requirement | iam-jit implementation |
|---|---|
| §10.2 — Audit logs for all access | Every grant request → grant decision → credential issuance → expiry has a corresponding audit log entry with actor, action, timestamp, request_id, score. |
| §10.3 — Required log content (user, event type, date/time, success/failure, origin, resource affected) | All present in iam-jit's audit schema. |
| §10.5 — Audit log retention 12 months minimum | Customer-configurable via `IAM_JIT_AUDIT_RETENTION_DAYS`. Default 13 months (>12). |
| §10.7 — Centralized log management | iam-jit's audit log lives in customer's DDB; exportable to centralized SIEM (CloudWatch Logs → splunk / sumo / elastic). |

### §7 — Access Control

| Requirement | iam-jit implementation |
|---|---|
| §7.2 — Need-to-know enforced | Scoring engine + auto-approve gate + approval workflow ensure each access grant is justified + bounded. |
| §7.3 — Least privilege | Recommender + scorer collaborate to produce minimum-scope policies. Score-based gating rejects over-broad grants. |
| §7.4 — Authorize all access | Every grant flows through iam-jit's gate; nothing is granted without an explicit decision (auto-approve OR human approval). |

## SOC 2 Trust Service Criteria

### CC6 — Logical and Physical Access Controls

| Criterion | iam-jit implementation |
|---|---|
| CC6.1 — Logical access security | Scoring + approval workflow gates every grant. Audit log captures decisions. |
| CC6.2 — User access provisioned + de-provisioned | Time-bounded grants auto-revoke on TTL expiry. Admin can revoke active grants on demand. |
| CC6.6 — MFA for privileged access | Per [§8.4](#84--multi-factor-authentication) mapping. |
| CC6.7 — Movement / changes restricted to authorized | Lifecycle state machine (`apply_transition`) is the single mutation entry-point; actor-role-checked at every transition. |
| CC6.8 — Prevent unauthorized changes | `[[creates-never-mutates]]` invariant: iam-jit creates new IAM resources; never modifies existing ones the customer owns. |

### CC7 — System Operations

| Criterion | iam-jit implementation |
|---|---|
| CC7.2 — System monitoring | Audit log + structured logging across all components. |
| CC7.3 — Anomaly detection | Auto-approve gate's anti-spam layers (rate limits, same-purpose retry, boundary-probe detection) flag suspicious patterns. |
| CC7.4 — Response to anomalies | Surfaces anomalies in admin UI + Slack notifications; admin acts. |

### CC4 — Monitoring Activities

| Criterion | iam-jit implementation |
|---|---|
| CC4.1 — Ongoing monitoring | Adversarial-loop audit cadence (rounds 1-9 shipped; new round after each major feature). Pinned regression tests catch reintroduction. |
| CC4.2 — Reporting deficiencies | Vulnerability disclosure policy (`SECURITY.md`); patch SLA (`docs/SECURITY-SLA.md`). |

## HIPAA Security Rule

### §164.308 — Administrative Safeguards

| Requirement | iam-jit implementation |
|---|---|
| §164.308(a)(3)(ii)(B) — Workforce clearance procedure | iam-jit User registration + role assignment (requester / approver / admin) is the workforce-clearance surface. |
| §164.308(a)(4) — Information access management | Scoring + approval gates each access grant. |
| §164.308(a)(5)(ii)(B) — Protection from malicious software | Patch SLA per `docs/SECURITY-SLA.md`. |

### §164.312 — Technical Safeguards

| Requirement | iam-jit implementation |
|---|---|
| §164.312(a)(1) — Access control (unique user ID, automatic logoff, encryption/decryption) | Each iam-jit User has a unique ID; session cookies have TTL; STS credentials have 1h TTL; encryption-at-rest via AWS DDB defaults + KMS. |
| §164.312(b) — Audit controls | iam-jit's audit module captures every grant + every assume-role. |
| §164.312(c) — Integrity | Audit log is tamper-evident (DDB conditional writes; CloudTrail attestation). |
| §164.312(d) — Person or entity authentication | OIDC SSO with IdP MFA. |
| §164.312(e) — Transmission security | All endpoints HTTPS-only; TLS via AWS Lambda Function URLs or API Gateway. |

## ISO 27001:2022

### Annex A — Information Security Controls

| Control | iam-jit implementation |
|---|---|
| A.5.15 — Access control | Scoring + approval workflow per §7 PCI mapping. |
| A.5.16 — Identity management | User store + OIDC SSO integration. |
| A.5.17 — Authentication information | Short-lived STS credentials; no standing keys; MFA propagation. |
| A.5.18 — Access rights | Time-bounded grants; auto-revoke on expiry. |
| A.8.2 — Privileged access rights | Approver / admin roles in iam-jit; OIDC-gated; audit log. |
| A.8.3 — Information access restriction | Per-account LLM policy (cost surgery); recommender's narrow-scope output. |
| A.8.5 — Secure authentication | OIDC SSO with MFA per §164.312(d). |
| A.8.15 — Logging | Audit log per §10 PCI mapping. |
| A.8.34 — Vulnerability management | Patch SLA + adversarial-loop process. |

## NIST 800-53 (selected high-impact controls)

| Control | iam-jit implementation |
|---|---|
| AC-2 — Account management | iam-jit User store + lifecycle. |
| AC-3 — Access enforcement | Scoring + approval gate + AWS IAM authority. |
| AC-6 — Least privilege | Recommender output + scoring floor. |
| AU-2 — Audit events | Every grant + transition logged. |
| AU-12 — Audit record generation | Audit module emits structured events. |
| IA-2(1) — Multi-factor authentication for privileged accounts | Layer A + Layer B MFA propagation. |
| SI-2 — Flaw remediation | Patch SLA. |

## What iam-jit does NOT claim

- iam-jit-the-company does NOT hold PCI Service Provider Level
  1 / 2 designation. Customers placing PCI-regulated workloads
  in hosted-SaaS iam-jit (Indie / Pro / Team) await our
  certifications. Self-host customers absorb iam-jit into
  THEIR PCI scope (their QSA reviews the deployment).
- iam-jit does NOT hold SOC 2 Type II at v1.0. Type I planned
  for Q3 2026; Type II 12 months later.
- iam-jit does NOT hold ISO 27001 certification.
- iam-jit does NOT hold HIPAA Business Associate Agreement
  authority at v1.0 for hosted-SaaS customers. Self-host
  customers using iam-jit for HIPAA-regulated workloads
  absorb it into their compliance scope.
- iam-jit does NOT hold FedRAMP authorization. Out of scope
  at v1; revisit at $5M+ ARR.

## What iam-jit DOES claim

- TECHNICAL implementation of controls maps to specific
  framework requirements as documented above.
- BB+WB audit cadence (9 rounds shipped) provides ongoing
  monitoring discipline.
- Pinned regression tests catch reintroduction of closed
  findings.
- Customer SELF-HOST deployments can be folded into the
  customer's own compliance scope; their certs cover iam-jit
  within their environment.

## For your auditor

If you're a PCI QSA / SOC 2 auditor / HIPAA reviewer evaluating
iam-jit:

- Start with [SECURITY.md](../../SECURITY.md) for the threat
  model + vulnerability disclosure process.
- Review [docs/SECURITY-SLA.md](../SECURITY-SLA.md) for the
  patch SLA.
- Review `docs/security/AUDIT-2026-05-WB-ROUND*.md` for the
  audit history.
- Review `docs/ADVERSARIAL-LOOP-PROCESS.md` for the testing
  methodology.
- For specific control questions, email
  `security@iam-jit.dev` — we respond within 48 hours.

We are happy to engage with customer auditors on specific
control evidence. The discipline is genuine; the
documentation supports it; the audit history is public.

---

Last updated: 2026-05-15
