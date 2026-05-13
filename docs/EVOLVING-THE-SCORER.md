# Evolving the scorer past human-review parity

> **Thesis:** the iam-jit risk scorer starts out as a fast,
> deterministic baseline that approximates what a careful human
> reviewer would say. Over time — through deliberate tuning against
> real decisions and real outcomes — the scorer should become
> **more reliable than human reviewers** for the routine 80% of
> requests, freeing humans for the genuinely novel cases.

This isn't AI hype. It's a structural advantage:

  - Scorers don't get fatigued at request 200 of the day.
  - Scorers apply the same rules to the same shapes every time;
    humans drift toward whatever rule of thumb they used last week.
  - Scorers can encode the full accumulated history of "what
    decisions later turned out to be wrong"; humans only remember
    the incidents they were personally on call for.
  - Scorers can flag patterns across requests (this user keeps
    requesting `s3:*`; this service is being requested 10× more
    than last quarter) that no individual human reviewer sees.

The scorer doesn't get there for free. It gets there because the
deployment **records every decision, surfaces every disagreement,
and feeds that data back into the calibration**. That data flywheel
is the scaffolding this doc covers.

## What "better than human reviewers" looks like

Three concrete measures iam-jit can drive on:

1. **Faster decision latency** for the routine cases. Already true:
   auto-approve fires in milliseconds vs a human's
   minutes-to-hours. The win here is unblocking the requester, not
   beating the human on quality.

2. **Higher precision on the rejection side.** When a human rejects
   a request, they sometimes do so out of caution or unfamiliarity
   with the service rather than because the request is actually
   risky. A well-calibrated scorer rejects only when there's a
   specific reason (matched blocklist, high-impact action, broad
   scope) it can name in the audit log — no "felt off."

3. **Lower miss rate on actual incidents.** This is the real prize.
   If 6 months of audit data shows a category of grant correlated
   with security incidents (e.g., `sts:AssumeRole` grants on prod
   accounts later revoked early), the scorer can bake that
   correlation in as a higher score for that shape, BEFORE the next
   incident.

The first measure is operational; the second and third are quality.
The data flywheel makes both possible.

## The data flywheel

Every decision iam-jit makes is a labeled example:

```
   Submit
   ┌───────────────────────────┐
   │ policy + context          │  ← features
   └────────┬──────────────────┘
            ▼
   ┌───────────────────────────┐
   │ deterministic score = 4   │  ← scorer's predicted verdict
   └────────┬──────────────────┘
            ▼
   ┌───────────────────────────┐  ← human's actual verdict
   │ Approved by alice@…       │     (THE LABEL)
   └────────┬──────────────────┘
            ▼
   ┌───────────────────────────┐
   │ active for 47 min, then   │  ← OUTCOME signal
   │ revoked by bob@… for      │     (the ultimate label)
   │ "ended up not needing it" │
   └───────────────────────────┘
```

Each grant generates three signals:

  - **Scorer's verdict** — what the deterministic scorer said.
  - **Human's verdict** — what the human approver/rejecter chose.
  - **Outcome** — did the grant get used? Was it revoked early? Was
    it cited in an incident later?

The disagreements between the scorer and humans, weighted by
outcomes, ARE the calibration signal. A request the scorer scored
3 (auto-approve eligible) that a human rejected and that a later
incident validated → the scorer was wrong; add the matching pattern
to `additional_high_impact_actions`. A request the scorer scored 7
(human review) that a human approved 50 times in a row without
incident → the scorer is too cautious; relax the scoring for that
service-action combo, OR add a `auto_approve_if` toggle.

## Scaffolding shipped today

The pieces that are already in place to make this work:

| Scaffolding | What it captures | Where |
|---|---|---|
| Score on every request | The scorer's predicted verdict | `status.review.risk_score`, persisted with the request |
| Risk factors that drove the score | Which specific rules fired | `status.review.risk_factors` |
| Auto-approve decision audit event | When the scorer fired auto-approve, with full details | audit event `request.auto_approved` |
| Auto-approve skipped audit event | When the scorer COULD have auto-approved but didn't | audit event `request.auto_approve_skipped` |
| Human approve/reject in history | The human's verdict, with reason | `status.history[].action` |
| Settings fingerprints | Which admin context was active at scoring time | `status.review.context_fingerprints` |
| Calibration endpoint | `GET /api/v1/admin/calibration` — disagreement stats | `src/iam_jit/calibration.py` + admin route |

The fingerprint capture is critical: it means six months from now,
when an admin looks at a disputed past decision, they can answer
"the scorer was running with THIS version of
`additional_sensitive_services` when it scored this request." No
mystery drift.

## Calibration loop — how to run it

Monthly (or after any major scoring tuning):

1. **Pull the calibration report:**
   ```bash
   curl <iam-jit>/api/v1/admin/calibration?since=30d
   ```
   The response shows:
     - Total decisions in the window
     - How many auto-approved vs human-reviewed
     - For human-reviewed: how many approved vs rejected, broken
       down by what the scorer's verdict would have been
     - Disagreement rates: % of human-reviewed where the scorer
       would have auto-approved (false negative on the human side),
       and % of auto-approved where the human-side outcome was
       early-revoke or never-used (potential false positive on the
       scorer side)

2. **Investigate the disagreements.** Each row of the disagreement
   table is a candidate for re-calibration:
     - Scorer said auto-approve, human rejected → either tighten
       the scorer (add to `additional_high_impact_actions` or raise
       a sensitive-service score weight) or accept that the human
       was being overly cautious and document the rationale.
     - Scorer said review, human auto-approved every time → too
       cautious; consider an `auto_approve_if` toggle for the
       matching shape, or lower the deterministic weight for the
       triggering rule.

3. **Update settings**:
   - Runtime knobs that don't change the scorer's CODE go through
     PATCH `/api/v1/admin/auto-approve/settings` (see
     `docs/TUNING-RISK.md`).
   - Scorer code changes (new rules, new factor weights) go through
     `src/iam_jit/review.py` with a calibration-test commit in
     `tests/test_review_calibration.py` showing the before/after
     score on representative payloads.

4. **Re-run the report after a calibration cycle** to confirm the
   disagreement rate moved the way you intended.

## Outcomes — closing the loop

The strongest training signal is **post-grant outcomes**:

  - **Early revoke**: a grant revoked well before its expiry
    suggests it shouldn't have been auto-approved.
  - **Never used**: a grant that was never assumed (no STS
    AssumeRole CloudTrail event) suggests the requester
    over-asked.
  - **Cited in an incident**: a grant that shows up in a
    post-incident review is the strongest "scorer should have
    flagged this" signal.

Today the **early-revoke** signal is captured automatically (every
revoke event records the revocation timestamp). The
**never-used** signal requires CloudTrail integration (on the
roadmap). The **incident-cited** signal requires manual tagging by
the security team during an incident review.

Run the outcome correlator periodically (manually for now;
scheduled-task on the roadmap):

```bash
curl <iam-jit>/api/v1/admin/calibration?include_outcomes=true&since=90d
```

The endpoint correlates the scorer's verdict, the human's verdict,
and the observed outcome — producing rows like:

```
score=3 | human=approved | revoked_after=4m | usage=0     ← over-asked, scorer agreed
score=3 | human=approved | revoked_after=58m | usage=12   ← appropriate
score=7 | human=approved | revoked_after=2m | usage=0     ← human disagreed with scorer, retrospectively over-cautious
score=7 | human=rejected                                  ← human agreed with scorer
```

Every row of "human disagreed AND outcome supports the human" is a
calibration target.

## What an outperforming scorer looks like (qualitative bar)

When the scorer is genuinely beating humans on the median case,
you'll see:

  - **Approver-team time spent on review drops** without
    auto-approve threshold being relaxed. The same threshold
    correctly classifies more requests because the score
    distribution has improved.
  - **Approvers re-read the scorer's risk_factors before deciding,
    and find themselves agreeing more often than disagreeing.** The
    scorer's listed factors become the conversation starter, not
    something the approver has to re-derive from scratch.
  - **New approvers onboard faster.** The scorer's narrative
    becomes the training data for what to look for. A junior
    approver who sees "risk_factors: ['Resource: * for s3', ...]"
    learns the patterns the scorer encodes — including patterns the
    senior approvers couldn't have articulated explicitly.
  - **Calibration reports stabilize.** Month-over-month
    disagreement rates trend down, not up. Spikes in disagreement
    correlate with NEW service usage patterns (the org started
    using Bedrock; nobody had calibrated the scorer for it yet) —
    not with random drift.

## What the scorer can't do

To avoid hype: there are things the scorer will NEVER beat humans
at, no matter how much data accumulates:

  - **Novel attack shapes.** A targeted social-engineering attack
    crafted to look like a routine request will pass the scorer.
    Humans pattern-match on context (this request came in at 2 AM
    from someone who never works that late) that the scorer can't
    see.
  - **Accountability.** Even if the scorer makes the better
    decision, a human-in-the-loop is required for genuinely
    privileged grants (prod, IAM, KMS) because someone has to be
    answerable. Threshold + service blocklist enforce this even
    when the scorer agrees.
  - **One-off business context.** "This week we're migrating; treat
    every prod request as more permissive" is a human override the
    scorer should not learn.

The scorer's role is to handle the 80% confidently so humans can
focus on the 20% where their judgment is irreplaceable. Not 100%.

## Roadmap

Listed in `docs/ROADMAP.md` § "Scorer evolution path":

  - **Phase 1 (today):** calibration endpoint + audit-event capture
    of disagreements + manual outcome review.
  - **Phase 2:** automatic outcome correlation (early-revoke +
    never-used signals from CloudTrail) feeding a periodic report.
  - **Phase 3:** suggested-tuning generator — the report doesn't
    just show disagreements, it suggests specific
    `additional_sensitive_services` / `additional_high_impact_actions`
    additions and shows what the disagreement rate would have been
    with those changes applied historically.
  - **Phase 4:** ML residual model that learns the patterns NOT
    captured by the deterministic rules. Always shadow-scored,
    never blocking, with explicit admin review before promotion.

Each phase preserves the safety invariants:

  - The deterministic baseline always runs. Any learned model is
    additive (can raise score, not lower it).
  - The floor parameters (`MaxAutoApproveRiskBelow`,
    `RequiredServiceBlocklist`, etc.) constrain every layer.
  - The audit chain always records WHICH scorer/version made the
    call — model upgrades don't erase history.

Better than human reviewers, with the safety net of human reviewers
when it matters. That's the destination.
