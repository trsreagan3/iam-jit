# Hoop + iam-jit: scoped just-in-time IAM credentials for Hoop sessions

**Status:** integration design + demo runbook (V0, docs-only — no
Hoop plugin work required).

**Audience:** engineering teams already running [Hoop](https://hoop.dev)
who want their AWS-side credentials to be just-in-time, scoped,
and audited per session — rather than long-lived IAM access keys
or always-on cross-account assume-roles.

This document covers:
1. Why Hoop + iam-jit are complementary (not competitive)
2. The integration architecture (no code changes to Hoop)
3. Step-by-step setup
4. The end-user (engineer) experience
5. The audit trail
6. Open questions for a deeper V1 plugin

---

## 1. Why both, not either

Hoop and iam-jit live at different layers of the same defense-
in-depth stack:

| Layer | Hoop | iam-jit |
|---|---|---|
| Architecture | L7 PROXY in the data path | IAM POLICY ISSUER, not in path |
| What it does | Intercepts queries, masks PII, blocks destructive SQL, records sessions | Issues short-lived scoped IAM credentials |
| Where it sits | Between user / agent and the resource (DB / K8s / SSH) | At the AWS auth boundary |

A realistic engineer flow looks like:

```
   Engineer
       │
       │  1. asks for DB access via Hoop
       ▼
     Hoop ─── 2. needs an AWS role to assume into target account
       │
       │  3. iam-jit scores the implied IAM grant
       ▼
   iam-jit ── 4. score ≤ threshold → auto-approves
       │       score > threshold → routes to admin
       │
       │  5. iam-jit updates the trust policy of HoopBridgeRole
       │     to allow the engineer's user-id for the next 1h
       ▼
     Hoop ─── 6. sts:AssumeRole HoopBridgeRole → temporary creds
       │
       │  7. opens DB session with those creds
       ▼
   Engineer
```

Hoop owns: session recording, PII masking, destructive-SQL
blocking, the engineer's UX.

iam-jit owns: scoring the grant, gating the approval, time-
bounding the credentials, capturing the *why* of each access.

Neither product needs the other to function. Together, the
customer gets a single defense-in-depth story they can put on
a SOC 2 report: every engineer's database access is (a)
auto-expiring, (b) scoped to the just-in-time role iam-jit
issued, (c) PII-masked at the wire, (d) recorded by Hoop, (e)
explained by the engineer's stated reason. Five layers; one
path.

---

## 2. The integration architecture (V0: docs-only)

The cleanest V0 doesn't require any Hoop plugin work. It uses
Hoop's existing cross-account `sts:AssumeRole` flow + iam-jit's
existing trust-policy-management capability.

**The single shared resource:** an IAM role in the target AWS
account, conventionally named `HoopBridgeRole`. Hoop assumes
this role to open connections. iam-jit manages the role's
**trust policy** dynamically.

### What's static (deploy-time, configured once)

`HoopBridgeRole`'s **inline policy** lists the AWS actions Hoop's
session-runtime needs (e.g., `rds:DescribeDBInstances`,
`rds-data:ExecuteStatement`, `secretsmanager:GetSecretValue` for
the relevant secrets, etc.). This is whatever the existing Hoop
deployment already grants for cross-account access — copy from
[Hoop's AWS-integration doc](https://hoop.dev/docs/integrations/aws).

### What's dynamic (per-engineer, per-session)

`HoopBridgeRole`'s **trust policy** is iam-jit-managed. By
default it trusts NO ONE. When an engineer requests access via
iam-jit (or implicitly via Hoop calling iam-jit's API), iam-jit
adds the engineer's IAM principal (or the Hoop gateway's
principal + an `sts:ExternalId` matching the iam-jit grant ID)
to the trust policy for the duration of the grant. When the
grant expires (auto-sweep), iam-jit removes the trust.

**Net effect:** Hoop's `sts:AssumeRole` only succeeds while
iam-jit has an active grant for that engineer. No standing
trust. No "we forgot to revoke."

### Variant: iam-jit issues STS creds directly to the Hoop agent

A second V0 shape skips trust-policy management and instead
has iam-jit issue STS credentials directly, then the Hoop agent
process sets them as env vars (`AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) for the lifetime
of one connection. This requires per-session restart of the
Hoop agent OR Hoop's `AWS_SESSION_TOKEN_JSON` flag (the
environment variable Hoop already supports for EC2 metadata
mocking, which can also serve as a session-credential source).

For V0 we recommend the trust-policy approach because it
requires no agent restart and uses Hoop's existing assume-role
code path unchanged.

---

## 3. Setup (45 minutes, copy-paste runbook)

Prerequisites:
- Existing Hoop deployment (gateway + at least one agent)
- iam-jit deployed (see iam-jit's [DEPLOYMENT.md](../DEPLOYMENT.md))
- Both have IAM principals in the target AWS account

### Step 1 — Create the bridge role

In the target AWS account:

```bash
# Create the role with a deny-all trust policy as the starting
# point. iam-jit will manage the trust policy from here on.
aws iam create-role \
  --role-name HoopBridgeRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach the inline policy describing what Hoop sessions need
# to do. Adjust to your deployment's actual scope.
aws iam put-role-policy \
  --role-name HoopBridgeRole \
  --policy-name HoopSessionPermissions \
  --policy-document file://hoop-session-permissions.json
```

Where `hoop-session-permissions.json` is the policy your Hoop
deployment uses today (RDS data API + secrets-manager for the
relevant secrets, typically).

### Step 2 — Register the role with iam-jit

```bash
iam-jit accounts add \
  --account-id 111122223333 \
  --provisioner-role HoopBridgeRole \
  --notes "Hoop session bridge — trust managed by iam-jit"
```

This tells iam-jit it's allowed to mutate the trust policy on
`HoopBridgeRole`.

### Step 3 — Define a Hoop role template

In iam-jit's admin UI (or via env), define a role-template that
matches what Hoop sessions need:

```yaml
# hoop-session.template.yaml
template_id: hoop-db-session
display_name: "Hoop database session"
description: |
  Just-in-time access to the Hoop bridge role for the
  duration of one database session. Default: 1 hour.
default_duration_hours: 1
target_role_arn: arn:aws:iam::111122223333:role/HoopBridgeRole
trust_principal_strategy: caller_iam_principal
```

When an engineer requests this template, iam-jit adds them to
the trust policy of `HoopBridgeRole` for `default_duration_hours`.

### Step 4 — Configure Hoop to assume the bridge role

In Hoop's connection config (cross-account section per the
[AWS-integration docs](https://hoop.dev/docs/integrations/aws)):

```bash
INTEGRATION_AWS_INSTANCE_ROLE_ALLOW=true
# Hoop's gateway / agent runs with its OWN IAM principal.
# It assumes HoopBridgeRole when opening sessions.
HOOP_TARGET_ACCOUNT_ROLE=arn:aws:iam::111122223333:role/HoopBridgeRole
```

(Adjust env-var names to match the Hoop version you're running
— consult Hoop's setup docs.)

### Step 5 — End-user flow

Engineer Alice wants to run a query against the prod analytics
DB via Hoop:

```bash
# Alice asks iam-jit for a session-bridge grant
iam-jit request \
  --template hoop-db-session \
  --duration 1h \
  --reason "investigating customer 1234's signup-flow events"

# Output:
# ✓ Score: 4/10 (medium) — auto-approved (your team threshold: 5)
# ✓ Trust policy on HoopBridgeRole updated; expires 2026-05-15T16:00Z
# ✓ Use Hoop normally — your session will work for the next 1h.

# Alice opens her usual Hoop session
hoop connect prod-analytics-db
# (Hoop assumes HoopBridgeRole, succeeds because Alice is in
# the trust policy. Session opens.)

# 1 hour later, iam-jit's sweep removes Alice from the trust
# policy. Subsequent `hoop connect` attempts fail at the
# assume-role step with AccessDenied. Alice requests a fresh
# grant if she needs more time.
```

If the request scores above the team's threshold (e.g., a
production database with destructive permissions), iam-jit
routes to admin review and Alice waits for approval — same flow
as any other iam-jit grant.

---

## 4. Audit story (the joint pitch)

For each Hoop session, both products contribute distinct audit
rows that compose into a single compliance narrative:

```
2026-05-15T15:01:23Z  iam-jit grant:   alice@ requested hoop-db-session
                                        score=4/10, auto-approved,
                                        reason="investigating customer 1234"
2026-05-15T15:01:24Z  iam-jit trust:   HoopBridgeRole trust policy
                                        updated to add alice@ for 1h
2026-05-15T15:02:11Z  Hoop session:    alice@ opened prod-analytics-db
                                        (sts:AssumeRole HoopBridgeRole succeeded)
2026-05-15T15:02:14Z  Hoop session:    SELECT * FROM events WHERE
                                        customer_id = 1234 LIMIT 50
                                        (PII masked: email, phone)
2026-05-15T16:01:24Z  iam-jit sweep:   HoopBridgeRole trust policy
                                        revoked alice@ (grant expired)
```

One CSV export from each product → joint compliance narrative.
Auditor can answer: *who accessed what data, when, why, with
what scope, and how long?* — in five rows.

---

## 5. Why we are NOT proposing a Hoop plugin

A natural reflex when integrating two products is to write a
plugin in one for the other. We're explicitly NOT proposing
that here, because:

1. **The trust-policy approach above already works** with no
   Hoop code changes. Adoption friction = zero. A Hoop user
   who reads this doc can have it running in 45 minutes
   against their existing deployment.

2. **A plugin couples release cycles.** A "Hoop iam-jit
   credential-source plugin" means every iam-jit version
   change triggers a Hoop-side validation; every Hoop release
   risks breaking the plugin. The pure-API integration has
   no shared release surface.

3. **Pure-API integration is more honest about responsibility
   boundaries.** Hoop's job: open the session, mask the data,
   record the audit. iam-jit's job: issue the credentials,
   score the request, gate the approval. Both products do
   what they do best, with AWS IAM as the well-defined
   contract surface between them.

4. **It's the same shape any other JIT-credential tool would
   use.** SSM Session Manager, Teleport, custom scripts —
   they all benefit from the same trust-policy pattern. Not
   plugin-specific.

If Hoop later wants a first-class "iam-jit-aware connection
type" in their UI for marketing differentiation, that's
worth a conversation. For shipping a working integration today,
the API path is enough.

## 6. Known sharp edges (real, but small)

- **Trust-policy updates are eventually consistent.** When iam-jit
  adds the engineer to the trust, `sts:AssumeRole` may take
  1-15 seconds to honor it. The first session attempt right
  after grant issuance can transient-fail. Mitigation: iam-jit
  waits for a successful test-`sts:AssumeRole` before declaring
  the grant active (1-2 second wait). This is iam-jit's
  responsibility, not Hoop's.

- **Audit correlation requires both logs.** Today, joining "this
  iam-jit grant" to "this specific Hoop session" requires
  matching timestamps + engineer-id across two systems. Acceptable
  for V0; if customers ask for tighter correlation, iam-jit
  can expose a webhook that Hoop's session-start hook posts
  to. No Hoop code change required — they already support
  webhooks per their docs.

---

## Quick FAQ

**Does iam-jit replace Hoop's session controls?**
No. Hoop's PII masking, session recording, destructive-SQL
blocking are all unique to Hoop and remain. iam-jit is the
AWS-credential layer ONLY.

**Does Hoop replace iam-jit's grant flow?**
No. iam-jit's risk scoring, threshold-based admin routing, and
audit trail are separate from Hoop's controls. iam-jit is the
just-in-time IAM layer.

**Can I use this with non-Hoop database access too?**
Yes. iam-jit's bridge-role pattern works for any tool that
needs short-lived AWS credentials. Hoop is the example because
it's a common deployment shape; the same pattern serves SSM
session manager, Teleport, custom scripts, etc.

**What if Hoop and iam-jit disagree about whether to allow a
session?**
The engineer needs BOTH approvals: iam-jit must have an active
grant (else `sts:AssumeRole` fails), AND Hoop must allow the
connection (else the session never opens). Either layer can
veto. Defense in depth.

---

## Related

- [iam-jit DEPLOYMENT.md](../DEPLOYMENT.md) — set up iam-jit
  itself
- [Hoop AWS integration docs](https://hoop.dev/docs/integrations/aws)
  — Hoop's cross-account assume-role setup
- iam-jit's [agent-access use case](../USE-CASES.md#agent-access)
  — same architecture applied to AI-agent credentials
