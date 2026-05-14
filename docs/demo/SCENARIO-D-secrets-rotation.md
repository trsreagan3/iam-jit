# Scenario D — "5 minutes to rotate a secret"

**Length:** ~90 seconds
**Hook:** the textbook just-in-time access use case
**Audience:** SREs / DevOps / compliance buyers (PCI, SOC 2)

The product point: standing access to secrets is the audit
nightmare, not the rotation itself. iam-jit makes the 5-minute
just-in-time access pattern routine — and the audit log captures
every who/what/when/why automatically.

---

## Scene 1 — The problem with standing access (15s)

**Voiceover:**
> "Your SREs need to rotate production secrets. The on-call
> dev needs to update one database password right now. There
> are exactly two options today, and both are bad."

**Screen:** split panel.

**Left side — "Option A: standing access" (in red):**

```
Role: ops-team-prod
Policy: secretsmanager:* on *

  - 47 developers have this role
  - It's been "temporary" for 2 years
  - Audit finding: SOC 2 CC6.6, PCI DSS 8.6.1
```

**Right side — "Option B: file-a-ticket" (in yellow):**

```
Slack: "@admins can someone grant me secretsmanager
        access for 5 min to rotate prod/db/password?"

  - Admin is in a meeting
  - 47 min wait
  - Two pages while waiting
```

**On-screen text overlay:**
> Standing access fails the audit. Tickets fail the SLA.

---

## Scene 2 — The iam-jit just-in-time grant (30s)

**Voiceover:**
> "iam-jit makes the 5-minute grant routine. One specific
> secret. One specific dev. One specific reason. Five minutes
> later it's gone."

**Screen:** dev's terminal.

**Commands to run on camera:**

```bash
iam-jit request \
  --action secretsmanager:UpdateSecret \
  --action secretsmanager:GetSecretValue \
  --resource arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db/password-A1b2C3 \
  --duration 5m \
  --reason "rotating db password per quarterly schedule (PROD-ROT-2026Q2-031)"
```

**Expected output:**

```
✓ Request submitted
  Score: 5/10 (medium) — at admin-review threshold
  Why: secretsmanager:PutSecretValue is a high-impact mutation
  Resource: one named secret (prod/db/password-A1b2C3)
  Duration: 5 minutes
  Reason: rotating db password per quarterly schedule (PROD-ROT-2026Q2-031)

Routed to: admin@example.com (the team enables transparent-approve
for `secrets-rotation` template; this request didn't use the
template, so admin review applies).
```

**Voiceover continues:**
> "Score 5 — borderline. The admin gets a clean request: one
> secret, five minutes, with a runbook ticket number in the
> reason. Approve takes seven seconds."

**Screen:** cut to admin's review.

**UI panel spec:**

```
┌─────────────────────────────────────────────────────────────┐
│  iam-jit · Secret rotation request                          │
├─────────────────────────────────────────────────────────────┤
│  Requester:    sre-mike@example.com                         │
│  Score:        5/10 (medium)                                │
│                                                             │
│  What:         secretsmanager:GetSecretValue,               │
│                secretsmanager:UpdateSecret                  │
│  On:           prod/db/password-A1b2C3 (one named secret)   │
│  Duration:     5 min                                        │
│  Reason:       rotating db password per quarterly schedule  │
│                (PROD-ROT-2026Q2-031)                        │
│                                                             │
│  Audit context:                                             │
│    Runbook PROD-ROT-2026Q2-031 — valid                      │
│    sre-mike has rotated 14 secrets this quarter             │
│    No prior denials this quarter                            │
│                                                             │
│  [ Approve (5 min) ]  [ Approve longer ]  [ Refuse ]        │
└─────────────────────────────────────────────────────────────┘
```

**Voiceover continues:**
> "Click. Mike's terminal pops a notification. He runs the
> rotation. Five minutes later the grant auto-expires."

---

## Scene 3 — The audit story (25s)

**Voiceover:**
> "Every rotation is now a discrete grant in the audit log.
> Compliance review goes from 'show me who has Secrets
> Manager access' — a never-ending list — to 'show me every
> secret-access event last quarter, with reason, duration,
> approver.' One query. One CSV. Auditor moves on."

**Screen:** mock audit-log query result.

```
$ iam-jit audit query --action 'secretsmanager:*' --since 2026-Q1

DATE        USER       SECRET                    ACTION         DURATION  REASON                              APPROVER
2026-04-15  sre-mike   prod/db/password          UpdateSecret   5m        PROD-ROT-2026Q2-014                 admin
2026-04-22  sre-mike   prod/api/stripe-key       UpdateSecret   5m        PROD-ROT-2026Q2-021                 admin
2026-04-29  sre-alice  prod/db/password          UpdateSecret   5m        PROD-ROT-2026Q2-031                 admin
2026-05-06  sre-mike   prod/services/jwt-sign    UpdateSecret   5m        PROD-ROT-2026Q2-038                 admin

4 rotations, 4 grants, total 20 minutes of elevated access.
```

**On-screen text overlay:**
> Audit: 4 grants, 20 minutes total.
> Standing-access alternative: 47 people × 90 days = ~6 person-years
> of elevated access for the same work.

---

## Scene 4 — The wrap (10s)

**Voiceover:**
> "Standing access is the actual risk. Just-in-time isn't a
> compliance theater — it's a smaller blast radius, measured
> in minutes, with every action attributable. iam-jit makes
> that the default."

**End card:**
> iam-jit · the blast radius your auditor wants you to have
> 5-minute grants. Full audit trail. SOC 2, PCI, NIST out
> of the box.

---

## Compliance footnotes (use as on-screen-text overlays where they fit)

- **PCI DSS 4.0 §8.6.1** — application/system passwords must
  be changed periodically with documented procedures
- **SOC 2 CC6.6** — logical access controls restrict
  administrative access to authorized personnel
- **NIST 800-53 SC-28** — protection of information at rest
  (includes secrets); just-in-time access supports the
  least-privilege principle in AC-6

## Recording checklist

- [ ] Verify the score locally first:
      `iam-risk-score --offline examples/demo/06-secrets-rotation.json --access-type read-write --duration-hours 1`
      should print `5/10 (medium)`. If your scorer version
      produces a different number, re-run the scene voiceover
      to match.
- [ ] The audit-log query at the end can be a real `aws
      cloudtrail lookup-events` call OR a mock — both work, the
      point is the SHAPE of the result.
- [ ] Keep the standing-access panel SHORT. Don't dwell on
      "Option A is bad." The point is the contrast.
