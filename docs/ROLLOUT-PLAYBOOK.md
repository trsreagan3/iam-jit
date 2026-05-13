# Rollout playbook — going from deployed to trusted

iam-jit makes security-critical decisions. Customers don't (and
shouldn't) turn on auto-approve in production on day one. This
playbook describes the staged rollout from "deployed but
observed" to "fully auto-approving" in 8-12 weeks, with explicit
gates between stages.

The playbook covers two deployment shapes:

  - **Full iam-jit SaaS** (auto-approve + provision) — for
    customers using iam-jit as their JIT IAM provider.
  - **Scoring API only** (POST /api/v1/score + GitHub Action) —
    for customers integrating iam-jit's risk evaluation into
    their existing provisioning system.

Both shapes follow the same trust-building arc; the playbook
gates work for both.

## Stage 0 — Internal proof of value (1-2 weeks, your time)

Before any customer-facing deployment, run iam-jit against your
own org's historical IAM changes. Take 30-50 IAM policies your
team has shipped in the last 6 months, run them through
`iam-risk-score --offline`, and check: does the scorer's verdict
match the team's intuition?

**Gate to advance:** ≥85% of historical examples score in the
range you'd have placed them. Disagreements documented (either
fix the scorer or accept the calibration).

**Output:** a one-page "this is what iam-jit would say about
your policies" report. Use it as the design-partner pitch.

## Stage 1 — Shadow mode at a design partner (4-6 weeks)

Customer deploys iam-jit with `IAM_JIT_SHADOW_MODE=1`. Their
existing IAM-grant approval workflow continues unchanged. iam-jit
observes every request that flows through their system AND records
what it WOULD have done in the audit trail.

For the **scoring API only** path: customer wires the GitHub
Action into their CI but sets the action to "comment only, do
not block":

```yaml
- uses: iam-jit/iam-risk-score-action@v1
  with:
    policy-file: 'iam/*.json'
    threshold: 11  # impossible to exceed — comments only, never fails
    comment-on-pr: true
```

**What customer does during this stage:**

  - Watches the scorer's verdicts in their normal PR review
  - Flags any "the scorer was wrong about this one" cases via a
    weekly review meeting
  - Tracks: how often did the scorer agree with the human?

**Gate to advance to Stage 2:**

  - ≥4 weeks of shadow observation completed
  - ≥80% scorer-vs-human agreement rate
  - Zero "scorer said safe, human knew was dangerous" cases
  - At least 50 real decisions observed (statistical floor)
  - Customer is comfortable enough to enable enforcement

If any of these fail: extend shadow period, tune calibration via
`additional_sensitive_services` / `additional_high_impact_actions`,
re-evaluate. Don't push past this gate to hit a deadline.

## Stage 2 — Auto-approve at threshold=2 (1-2 weeks)

The scorer fires `auto_approve` only on score=1 examples. Score
1 = single read action on a single resource ARN, read-only,
trivial duration. Maybe 5-10% of requests qualify. Most still
route to humans.

**Settings:**

```bash
curl -X PATCH .../api/v1/admin/auto-approve/settings \
  -d '{"auto_approve_risk_below": 2}'
```

Or for the scoring-API-only path:

```yaml
- uses: iam-jit/iam-risk-score-action@v1
  with:
    policy-file: 'iam/*.json'
    threshold: 2  # only score-1 passes
```

**Gate to advance:** ≥1 week of auto-approved grants with zero
revoked-early events AND zero "I wish that hadn't been auto-
approved" admin complaints.

## Stage 3 — Threshold=3 (2 weeks)

Score 1-2 auto-approve. ~20-30% of typical traffic qualifies.
Still dev/staging accounts only (use the
`never_auto_approve_accounts` floor for prod IDs).

**Gate to advance:** ≥2 weeks, zero incidents traced to an
auto-approved grant, ≥95% admin satisfaction with auto-approve
verdicts in this band.

## Stage 4 — Threshold=4 (2 weeks)

Score 1-3 auto-approve. Boundary cases included (cross-resource
reads, single-secret reads). Customer should run the calibration
report weekly during this period:

```bash
curl .../api/v1/admin/calibration?since_days=14
```

Look at `scorer_overshoot_count` — auto-approves the human would
have rejected. If non-zero, investigate before advancing.

**Gate to advance:** ≥2 weeks, overshoot rate <5%, no rejected
auto-approves traced to scorer error.

## Stage 5 — Threshold=5 (default), open to staging accounts (2-4 weeks)

The recommended steady state for non-prod. Score ≤4 auto-approves.
~50-70% of typical traffic qualifies.

The `never_auto_approve_services` floor still blocks IAM, KMS,
secrets, etc. The `never_auto_approve_accounts` floor still blocks
prod IDs.

**Gate to advance to Stage 6:** 4 consecutive weeks at this
threshold with zero scorer-attributed incidents AND ≥90% calibration
agreement.

## Stage 6 — Production accounts (gradual, 4+ weeks)

Remove a single prod account from `never_auto_approve_accounts`.
Watch for 2 weeks. If clean, remove another. Continue until prod
is open OR you decide some accounts will always require human
approval (typical: PCI, payment-system accounts stay locked).

**This stage is reversible.** If anything looks off, add the
account back to `never_auto_approve_accounts`. The floor structure
means platform-team-owned configuration drives this — no admin
can fast-track prod opening.

## Stage 7 — Steady state (forever)

Weekly calibration review (30 min):

  - `GET /api/v1/admin/calibration?since_days=7`
  - Look at overshoot + early-revoke rows
  - Promote real disagreements to the calibration corpus
  - Tune `additional_sensitive_services` if a service appears
    repeatedly in disagreements

Quarterly:

  - Run `scripts/generate-adversarial-policies.py` with a larger
    batch (50-100 examples)
  - Promote real findings to `tests/calibration_corpus/`
  - Major calibration release

## When to PAUSE the rollout (one signal triggers a freeze)

- An auto-approved grant is named in a security incident
- The overshoot rate spikes above 10% week-over-week
- A new service category appears in traffic that the scorer
  hasn't been calibrated for
- Customer leadership asks for a freeze

In all cases: roll back to the previous stage's threshold. Run a
post-incident review. Document the pattern as a calibration test.
Don't advance again until evidence is rebuilt.

## Customer success milestones (use these in QBRs)

| Milestone | Evidence | Typical timeline |
|---|---|---|
| Deployed | Stack live, healthz returns 200 | Day 1 |
| Shadow-mode active | Audit log shows shadow events | Week 1 |
| First gate passed | ≥80% agreement, ≥50 decisions | Week 4 |
| First production auto-approve | Score=1 request auto-approved successfully | Week 6 |
| Threshold=5 reached | Default steady state for non-prod | Week 10 |
| Prod account opened | First prod auto-approve | Week 14+ |
| Steady state | 4 consecutive weeks at threshold without incident | Week 18+ |

## How this maps to the calibration data flywheel

Each stage feeds the flywheel:

  - **Shadow mode** produces the largest, cleanest calibration
    data — every request labeled by both scorer AND human, no
    enforcement bias.
  - **Bounded auto-approve** stages reveal real-world traffic
    patterns the scorer hadn't seen.
  - **Adversarial generation** (Stage 7 weekly ritual) covers
    the long tail.

Six months of shadow + bounded rollout = ~5000-50000 labeled
decisions. That's what makes the scorer measurably better than
human review for the routine cases (see
`docs/EVOLVING-THE-SCORER.md`).

## What this looks like for the scoring-API-only customer

The same arc, with the actions translated:

| Stage | Scoring-API behavior |
|---|---|
| 0 | Customer runs CLI against their historical policies |
| 1 | GitHub Action installed, `threshold: 11` (comment only) |
| 2 | `threshold: 2` — high-risk PRs require security review |
| 3 | `threshold: 3` |
| 4 | `threshold: 4` |
| 5 | `threshold: 5` — default steady state |
| 6 | Same threshold, expanded scope (more repos / orgs) |
| 7 | Weekly review of action-blocked PRs, calibration tuning |

No "production accounts" stage for the scoring-API path because
the action doesn't grant access — it just gates merges.

## Selling this playbook

The playbook is a sales asset. Hand it to a prospect during
discovery. The structured 6-week-to-trust ramp is exactly what
security teams need to hear. Without it, every conversation starts
at "how do we know we can trust this?" With it, the answer is
"here's the staged plan; we'll be in shadow mode for a month
before anything is enforced."

This is the single most important non-product asset for closing
enterprise deals.
