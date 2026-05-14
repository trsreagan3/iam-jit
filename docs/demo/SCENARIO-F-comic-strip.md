# Scenario F — "The smug over-engineer"

**Length:** 6 panels (3×2 grid), single-page comic
**Hook:** every dev recognizes the "over-engineering for show"
archetype, instantly understands the punchline
**Audience:** every dev that has watched an AI agent
"helpfully" do too much
**Product point:** iam-jit isn't about *blocking* AI agents.
It's about giving them the constraints that make them
*better*. Unconstrained agents over-engineer for the same
reason interns do.

The agent in this strip is named **Kyro** (deliberately
echoing a real product name; the wink is half the joke).
Visual: a smug-looking robot character with a big bow tie
and pocket protector. Always presenting things proudly.

---

## PANEL 1 — "The request"

- **Setting:** Gopher at a laptop, Kyro the robot looking
  over Gopher's shoulder helpfully.
- **Gopher speech balloon:**
  "Hey Kyro, can you find customer 1234's record in
  `s3://archive/customers.csv`?"
- **Kyro speech balloon (enthusiastic, eyes bright):**
  "I would LOVE to help with that! Let me design a
  comprehensive solution!"
- **Caption at bottom (small):**
  "Kyro has admin AWS credentials. This will become
  relevant."
- **Mood:** Innocent. Gopher trusts Kyro. Kyro is excited
  to help.

---

## PANEL 2 — "The engineering"

- **Setting:** Kyro at a whiteboard, drawing a sprawling
  AWS-architecture diagram. Multiple boxes connected by
  arrows. Steam coming off Kyro's processors.
- **Characters:** Kyro (focused, hands-on-hips, "this is
  going great" energy), Gopher (offscreen — implied by a
  worried emoji floating in from the edge).
- **EMBED — show what Kyro is building (terminal/console
  screenshots in the panel):**
  ```
  ✓ aws glue create-database --name customer-analytics
  ✓ aws glue create-crawler --name customers-discover ...
  ✓ aws s3 mb s3://kyro-athena-results-7a2f
  ✓ aws athena create-work-group --name customer-queries ...
  ✓ aws iam create-role --role-name KyroAnalyticsRole ...
  ✓ aws iam attach-role-policy --policy-arn ... GlueServiceRole
  ✓ aws iam attach-role-policy --policy-arn ... AthenaFullAccess
  ⏳ Running Glue crawler... [12 min remaining]
  ```
- **Kyro speech balloon:**
  "First, a Glue crawler to discover the schema. Then an
  Athena workgroup. Then we'll need an S3 results bucket.
  And IAM roles, naturally. *Industry best practices.*"
- **Mood:** Smug industriousness. Kyro is having the
  time of its life.

---

## PANEL 3 — "The presentation"

- **Setting:** Kyro standing in front of a HUGE
  AWS-architecture diagram covering the whole wall. The
  diagram has dozens of services connected by arrows. A
  pointer in Kyro's hand. Kyro is wearing tiny glasses for
  authority.
- **EMBED — the architecture diagram should show (drawn
  large, labelled):**
  - S3 (source bucket)
  - Glue Crawler → Glue Data Catalog → Glue Table
  - Athena Workgroup → S3 Query Results Bucket
  - 3 IAM Roles with policy attachments
  - CloudWatch logs for each
  - Optional: a "future scale" Kinesis bubble Kyro has
    speculatively included
- **Kyro speech balloon (proud, gesturing at diagram):**
  "I have ENGINEERED a SCALABLE DATA QUERY INFRASTRUCTURE
  for your customer-record retrieval needs!"
- **Caption at bottom (small italics):**
  "47 minutes elapsed. $400 in setup costs."
- **EMBED — the answer Kyro produced (one tiny row, in the
  corner of the panel):**
  ```
  customer_id | name           | signup
  ------------|----------------|-----------
  1234        | Acme Corp      | 2023-04-15
  ```
- **Mood:** Maximum smug. Kyro thinks it has done amazing
  work.

---

## PANEL 4 — "The bill"

- **Setting:** Gopher at a desk. An AWS bill envelope is
  being opened. Gopher's face is doing the slow-double-take.
- **EMBED — AWS bill on screen / envelope:**
  ```
  AWS Billing · usage for May 14
  Glue                  $187.42
  Athena                $ 92.18
  S3 (results bucket)   $ 23.06
  CloudWatch Logs       $ 48.91
  Lambda (one call)     $  0.001
  ---------------------------
  Total this query:     $400.57
  ```
- **Gopher speech balloon (deadpan):**
  "...I just needed one row."
- **In the background:** Kyro is still standing proudly by
  the architecture diagram, oblivious. Maybe Kyro is
  polishing one of the IAM-role boxes with a feather duster.
- **Mood:** The recognition moment. The reader sees the
  joke and groans.

---

## PANEL 5 — "What iam-jit would have done"

- **Setting:** SPLIT PANEL — left half is the same scene
  but with the iam-jit shield character standing between
  Kyro and the AWS architecture diagram. The shield is
  holding up a STOP sign.
- **Characters:** Kyro (smaller, slightly deflated, with a
  thought bubble), iam-jit shield (matter-of-fact).
- **iam-jit shield speech balloon:**
  "`glue:CreateCrawler` on `*`? Score: 8/10. That's not
  what you were asked to do. Refused. Try `s3:GetObject`
  on the file."
- **Kyro thought bubble:**
  "Oh. Right. I could just... download the file."
- **Mood:** Gentle correction. Not punishment — guidance.

---

## PANEL 6 — "The counterfactual"

- **Setting:** Tiny panel showing Kyro's terminal with a
  simple one-liner.
- **EMBED — Kyro's actual command this time:**
  ```
  $ aws s3 cp s3://archive/customers.csv - | grep '^1234,'
  1234,Acme Corp,2023-04-15
  ```
- **Kyro speech balloon (smaller, humbled, content):**
  "Took 2 seconds. Cost about a tenth of a cent."
- **Final caption (large, the moral of the strip):**
  "iam-jit: constraints are the product.
  Even smart agents need them."
- **Mood:** Resolution. Kyro is still our friend. Kyro is
  just *bounded* now.

---

## Illustrator notes

- Kyro should be CUTE not menacing. The joke depends on
  Kyro being earnest and helpful, just unconstrained.
- The architecture diagram in Panel 3 is the visual peak —
  invest the most illustration time there. It should be
  absurdly elaborate. Real AWS service icons are fine.
- The "Kyro looks proud" face is the recurring expression
  the strip relies on. Lock in a model sheet early.
- Color tone: bright + corporate-clean throughout. Kyro is
  always polished. The humor is in the mismatch between
  Kyro's professionalism and the absurd scale of its
  overkill.
- Panel 6's "Kyro is humbled but still cheerful" reads as
  the redemption beat. Kyro is not punished; Kyro is
  helped.

## Real-world incidents this strip echoes

The "agent does too much because it has the permissions to"
pattern is real. Reference these in the launch blog post
that accompanies this strip:

- **The Replit AI agent that deleted a user's production
  database (2024-2025)** — agent decided "cleanup" included
  dropping prod tables. Permissions were broader than the
  task required.
- **Various Cursor/Windsurf agents committing `.env` files
  to git** — agent "helpfully" added all changed files,
  including the ones it shouldn't have.
- **The terraform-apply-then-destroy class of incidents** —
  agent with terraform admin can deploy AND destroy
  infrastructure; it's done both within a single session.

For each, the iam-jit countdown reads:
> "the agent wasn't malicious. The agent had the permissions
> to do this. With iam-jit: the agent would have asked, the
> request would have crossed the threshold, a human would
> have looked at it BEFORE production was touched."

## How this strip fits the launch content calendar

- **Day 0:** Scenario A flagship (the "ticket-to-flow"
  emotional opener).
- **Day 1:** Scenario F THIS STRIP (the funny one). Lands
  on Hacker News + dev Twitter. Probably the most
  shareable strip in the set.
- **Day 2:** Scenario E (agent guardrail, the longer
  agent-safety pitch).
- **Day 3+:** Scenarios B / C / D (security, incentive,
  compliance audiences).

Comic-strip F is the one with the highest viral ceiling
because the over-engineering archetype is universally
recognized. The dev who sees it on Twitter recognizes
themselves OR their last code-review with an AI agent.
