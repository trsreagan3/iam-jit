# Hoop partnership: outreach + internal-pilot plan

Companion to `HOOP-IAMJIT.md`. The integration spec is the
artifact; this is the plan for getting it adopted.

Two parallel tracks:

1. **Internal pilot at $YOUR_COMPANY** — your team already runs
   Hoop, so you can be the first joint deployment. Lowest-risk,
   fastest validation, most useful artifact (a real customer
   reference that isn't iam-jit's founder talking).

2. **Hoop relationship-build** — partnership outreach to Hoop's
   founder + DevRel. Goal: Hoop adds iam-jit to their docs as a
   recommended credential source.

Internal pilot earns the right to do the Hoop outreach with a
real customer story.

---

## Track 1 — Internal pilot ($YOUR_COMPANY)

You're already a Hoop customer. Your team already has the AWS
account, the IAM roles, the engineers using Hoop daily.
Deploying iam-jit alongside is the cheapest possible
demonstration that the integration spec works.

### Phase 1 — Shadow mode (week 1)

Goal: prove the integration works end-to-end against ONE Hoop
connection without disrupting any production access.

Steps:

1. **Deploy iam-jit to your AWS account** in a sub-account or
   dev account. Use the SAM template + the
   `IAM_JIT_DEV_INSECURE_SECRET` posture for the trial — full
   prod-readiness is week 3, not week 1.

2. **Pick one low-stakes Hoop connection** as the pilot target.
   Ideal: a staging database, or a dev-environment Lambda
   you're comfortable having a "permissions hiccup" on if
   something goes sideways.

3. **Create the bridge role** per `HOOP-IAMJIT.md` step 1, but
   with a deny-trust default policy. Don't wire it into Hoop
   yet — iam-jit just manages the role.

4. **Have one engineer (probably you) request a grant** via
   iam-jit's web UI. Confirm:
   - The grant is issued (visible in iam-jit's UI)
   - The trust policy on the bridge role is updated (check via
     `aws iam get-role`)
   - After the grant expires, the trust policy reverts (check
     via the same call after the grant TTL)

   This validates iam-jit's piece WITHOUT touching Hoop.

### Phase 2 — One-engineer cutover (week 2)

Goal: one engineer's Hoop connections route through the
iam-jit-managed bridge role for one week. Daily standups
include "did the new flow break anything?"

Steps:

1. **Update the pilot Hoop connection** to assume
   `HoopBridgeRole` instead of whatever role it currently
   uses. (Keep the OLD config commented out so rollback is
   one-line.)

2. **Configure the pilot engineer's iam-jit user** with a
   `hoop-db-session` role-template grant.

3. **Daily check-ins** (5 min):
   - Did sessions open without delay?
   - Did the trust-policy eventual-consistency window cause
     any AccessDenied surprises?
   - Did the audit log produce the joint narrative the
     integration doc promises?

4. **At end of week 2**, decide: roll out to the team OR roll
   back to standing-creds.

### Phase 3 — Team rollout (weeks 3-4)

Goal: every Hoop user on your team uses iam-jit-issued
credentials for production access. Standing IAM keys retired.

Steps:

1. **Migrate each Hoop connection** that touches AWS to the
   bridge-role pattern. Stagger by environment: dev first,
   staging second, prod third.

2. **Document the engineer-facing flow** in your team wiki.
   Include the "score crossed threshold → admin review" path
   so people know what to expect.

3. **Designate one admin-on-call** per week to handle iam-jit
   review queues. Probably a 5-15 minute commitment per day
   for the first month while the team learns what scopes to
   request.

4. **Capture metrics:**
   - Average grant approval time (auto-approved vs. admin-
     reviewed)
   - Number of grants per engineer per week
   - Score distribution (mostly low? mostly admin-reviewed?
     This tells you whether the threshold is correctly set)
   - Any session blocked because the iam-jit grant expired
     mid-session (rough edge to fix in V1)

### Phase 4 — Reference customer (week 5+)

Goal: turn the internal pilot into a public reference.

Deliverables:
- **Internal write-up** for your team: how the migration went,
  what to do differently next time. Useful artifact even if
  external-facing version doesn't ship.

- **Public case study** (optional, with company approval):
  "How we replaced standing IAM keys for Hoop sessions with
  iam-jit at $YOUR_COMPANY." Length: ~600-800 words. Becomes
  the first iam-jit customer story; doubles as the proof Hoop
  wants before recommending iam-jit.

- **Metrics summary** for the Hoop outreach pitch: "$YOUR_COMPANY
  retired N standing IAM keys, reduced average permission
  duration from infinity to 1 hour, captured M grants in the
  audit log over 4 weeks. Zero production incidents."

---

## Track 2 — Hoop outreach

Goal: Hoop adds iam-jit to their AWS-integration docs as a
recommended credential source. Stretch: a co-marketing blog
post about the joint pattern.

### Why Hoop should care (the pitch)

1. **Their customers are already asking the question.** Anyone
   running Hoop in production cares about reducing standing IAM
   credentials — that's literally why they bought Hoop. iam-jit
   is the missing piece on the AWS-credential layer.

2. **Zero engineering cost to recommend us.** The integration
   is API-only. Hoop adds a docs page; iam-jit adds the
   reciprocal docs page. No shared release surface. No support
   burden on Hoop's eng team.

3. **The joint narrative makes Hoop look more sophisticated.**
   "Hoop + iam-jit = standing-credentials-free AWS access" is
   a stronger compliance pitch than Hoop's current "you still
   manage the IAM credentials yourself, but Hoop sees them in
   transit" story.

4. **A YC-network introduction.** Both companies are early. Both
   are in the "make production safer" lane. Both founders care
   about the same buyer. Cooperation is more valuable than
   competition for either.

### Who to reach

Primary: **Andrios Robert** (founder, Hoop.dev). LinkedIn or X.
Secondary: whoever runs Hoop's DevRel / docs.

### Outreach sequence

**Week 0 (now): the cold DM.**

```
Hi Andrios — I'm [name] from iam-jit.

We're an AWS-IAM just-in-time credential issuer (per-action
scoring, time-bound STS, audit log). Different layer from Hoop
but shaped to slot in below it cleanly.

I wrote up an integration spec for using iam-jit as the
AWS-credential source for Hoop sessions — works against your
current product, no plugin work required:

  [link to HOOP-IAMJIT.md]

We're already piloting this internally at [my employer], who's
a Hoop customer. Happy to share results once we've got two
weeks of real data.

The ask: would you be open to a 20-min call to see if it makes
sense to mention iam-jit in your AWS-integration docs as a
recommended credential pattern? Mutual distribution; zero
support burden on your side.

Either way thanks for building Hoop — the data-masking story
is the right one.

[name]
```

**Week 2 (post-internal-Phase-2): the metrics follow-up.**

If Andrios responded: schedule the call, bring the integration
spec + the internal pilot's two-week report.

If silent: send a one-liner with the metrics from the internal
pilot ("we've been running this at [company] for 2 weeks, here's
what we found — would love your reaction").

**Week 5 (post-internal-Phase-4): the case-study close.**

If the internal pilot publishes a case study: send the case
study link to Andrios with one line — "real customer running
both, here's the result, want to amplify?" Hard to ignore at
this point.

### What to ask for, in order

1. **Lowest ask:** Hoop's docs add a section like "Use with
   external just-in-time credential issuers (e.g., iam-jit)"
   under their AWS-integration page. Costs Hoop nothing.

2. **Medium ask:** A joint blog post on either Hoop's or
   iam-jit's blog about the integration. ~400 words, 2 hours
   of time on either side. Cross-link in both companies'
   marketing.

3. **Higher ask:** A Hoop sales/DevRel mention of iam-jit when
   prospects ask "how do you handle the AWS credentials we
   give you?" — natural sales objection-handling, costs Hoop
   nothing, value compounds.

4. **Highest ask:** A reciprocal "iam-jit recommends Hoop for
   session controls" placement in iam-jit's docs (we offer
   this from day 1; not contingent on Hoop reciprocating).

### What to NOT ask for

- Don't pitch acquisition. Don't even hint. They just raised
  seed; the ask is wrong-shape and would tank the partnership
  conversation.
- Don't pitch a Hoop plugin. We agreed: API-only is the right
  integration shape. A plugin ask sounds like "we want you to
  build for us."
- Don't ask for an exclusivity arrangement. Hoop is going to
  get pitched by 5 other JIT-credential startups in the next
  year. Position iam-jit as "the obvious one to start with,"
  not "the only one."

---

## What "success" looks like at each timepoint

**End of week 1:** internal pilot Phase 1 done. Trust-policy
flow validated. Cold DM sent to Andrios.

**End of week 2:** one engineer using iam-jit + Hoop daily.
Pilot data exists.

**End of week 4:** team-wide rollout. Standing IAM keys retired
for Hoop access. Internal write-up shared with $YOUR_COMPANY's
security team. If Andrios engaged: first call done.

**End of week 8:** public case study published OR an explicit
"not yet, here's why" decision from $YOUR_COMPANY. Either way,
iam-jit has a real production-deployment data point.

**End of week 12:** Hoop's docs mention iam-jit OR an explicit
"not interested" from Hoop. Pivot the recommendation play to
StrongDM / Teleport / another peer if Hoop says no.

---

## Risk register (honest)

- **$YOUR_COMPANY says no to the pilot.** Backup: deploy the
  pilot in a personal AWS sandbox account, simulate the Hoop
  flow against a test database. Lower-fidelity but still
  validates the integration end-to-end.

- **Hoop's eventual-consistency window bites real engineers.**
  Mitigation: the post-grant `sts:AssumeRole` test-call from
  iam-jit (V0 sharp-edge fix) should land before Phase 2.

- **Andrios doesn't respond.** Most likely outcome of any cold
  DM. Backup: use the integration spec as a standalone
  marketing asset (blog post on iam-jit's site about "the
  Hoop pattern"). Hoop sees it indirectly via SEO; their
  customers ask them about it; conversation comes to us.

- **Hoop says "we'll build this ourselves."** The risk is real.
  Mitigation: ship before they have time to. Internal pilot
  data + a public reference customer = faster than they can
  build, especially since they just raised seed and are
  growth-focused not product-expansion-focused.
