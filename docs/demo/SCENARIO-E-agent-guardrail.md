# Scenario E — "The agent guardrail"

**Length:** ~2 minutes
**Hook:** "I'm scared to let AI agents touch my AWS account"
**Audience:** every developer who has tried agentic AI on AWS

The product point: iam-jit is the safety mechanism that lets you
actually USE AI agents on AWS. The agent has NO standing AWS
credentials. For every tool-call it makes, it asks iam-jit for
the specific, minimum-scope role. The blast radius at any moment
is exactly what iam-jit just granted — usually tiny, always
audited, often time-bound to 15 minutes.

This is probably the single strongest current-moment framing
for iam-jit. Build this one early.

---

## Scene 1 — The fear (15s)

**Voiceover:**
> "You want to let your AI agent work on AWS. You can see the
> productivity. You can also see what could go wrong.
>
> What if it hallucinates a `delete-table`? What if it
> uploads your environment variables to a public bucket? What
> if it gets prompt-injected into doing something neither of
> you signed up for?"

**Screen:** developer at terminal, about to type:

```bash
$ export AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=...
$ claude-code "refactor the product-catalog Lambda to handle the new schema"
```

**Cursor hovering over `claude-code`. Pause. Don't run.**

**On-screen text overlay:**
> The agent now has the same AWS permissions you do.

---

## Scene 2 — The iam-jit model (20s)

**Voiceover:**
> "iam-jit flips this. The agent has no AWS credentials.
> Period. When it needs to do something, it asks iam-jit for
> a specific, time-bound, minimum-scope role. iam-jit scores
> the request. Low-risk things happen instantly. High-risk
> things route to you."

**Screen:** title card with a diagram.

```
┌──────────┐    ┌─────────┐    ┌────────────┐
│   Agent  │ →  │ iam-jit │ →  │   AWS      │
└──────────┘    └─────────┘    └────────────┘
   no AWS         scores         your account,
   creds          + grants       scoped to what
   by default     1 narrow       was granted
                  role for
                  this action
```

**On-screen text overlay:**
> Agent has zero AWS by default. iam-jit issues a fresh
> scoped role per tool-call.

---

## Scene 3 — Three tool-calls, three different paths (75s)

**Voiceover:**
> "Let's watch a real agent run. Three tool-calls. Three
> different paths."

### Tool-call 1: read a bucket (auto-approved)

**Screen:** Claude Code's terminal.

**Mock output:**

```
[claude] Plan: read product-catalog-data to understand
         the new schema before refactoring the Lambda.

[claude] Tool: aws_s3_read_bucket
[iam-jit-mcp] Request → role-template: read-product-catalog
[iam-jit-mcp] Scoring policy:
                {
                  "Action": ["s3:GetObject", "s3:ListBucket"],
                  "Resource": ["arn:aws:s3:::product-catalog-data",
                               "arn:aws:s3:::product-catalog-data/*"]
                }
[iam-jit-mcp] Score: 1/10 (low) · auto-approved
[iam-jit-mcp] Issued: iam-jit-agent-claude-15m (expires 15:08)

[claude] Listing bucket… found 14 schema files.
[claude] Reading schema-v2.json… (cleaned)
[claude] OK, new schema adds two fields: variant_id, region.
```

**Voiceover:**
> "Read-only on one named bucket: score 1. iam-jit issued a
> 15-minute role for read-only access to exactly that bucket.
> The agent did the work. Done."

**On-screen text overlay:**
> Path A: low-risk → in-flow. Audit row recorded.

### Tool-call 2: update a Lambda (admin reviews)

**Voiceover:**
> "Next tool-call: update the Lambda."

**Mock output (continued):**

```
[claude] Tool: aws_lambda_update_code
[iam-jit-mcp] Request → role-template: update-one-lambda
[iam-jit-mcp] Scoring policy:
                {
                  "Action": ["lambda:UpdateFunctionCode",
                             "lambda:GetFunction"],
                  "Resource": "arn:aws:lambda:us-east-1:...:function:catalog-search"
                }
[iam-jit-mcp] Score: 6/10 (high)
[iam-jit-mcp] Why: lambda:UpdateFunctionCode is a high-impact
              mutation — even on a single named function, the
              caller can deploy attacker-controlled code.
[iam-jit-mcp] Routed to admin review. Slack pinged.

[claude] OK, the Lambda update is awaiting admin approval.
         Meanwhile I'll prepare the diff so the admin can
         see exactly what I'd deploy.
```

**Voiceover:**
> "Update one Lambda: score 6. Even on a named function, code-
> execution is inherently high-impact. So iam-jit pages you.
> The agent doesn't get a 'no' — it gets a 'wait while a human
> looks at this.'"

**Screen:** cut to admin's Slack ping.

**Mock Slack:**

```
#iam-jit-reviews · iam-jit-bot · 15:01
Agent requesting permission

  Agent:    claude-code (alice's session)
  What:     lambda:UpdateFunctionCode on catalog-search
  Score:    6/10 (high) — narrow but code-exec
  Code diff: [view 38-line change]
  Reason:   "Refactor catalog-search to handle the new
             variant_id and region fields per schema-v2.json"

[ Approve (15 min) ]  [ View full diff ]  [ Refuse ]
```

**Voiceover continues:**
> "You read the diff, see it matches what you'd write, click
> approve. The agent gets a 15-minute role to update that one
> Lambda."

**On-screen text overlay:**
> Path B: medium-risk → human, but in your existing tooling.

### Tool-call 3: the hallucination (refused)

**Voiceover:**
> "Now the part that makes this whole exercise worth it. The
> agent makes a mistake."

**Mock output (continued):**

```
[claude] Tool: aws_iam_update_role
[iam-jit-mcp] Request → role-template: custom
[iam-jit-mcp] Scoring policy:
                {
                  "Action": "iam:*",
                  "Resource": "*"
                }
[iam-jit-mcp] Score: 9/10 (high) — broad IAM control
[iam-jit-mcp] Why: iam:* on Resource:* is the most privileged
              shape in AWS. Hallucination-detector flag: an
              agent task about Lambda code refactor should
              not need IAM control.
[iam-jit-mcp] REFUSED. Audit row written with flag.

[claude] Hmm, iam-jit refused that. Let me think about what
         I actually need… I don't need IAM control to refactor
         a Lambda. That request was wrong. Trying without it.
```

**Voiceover:**
> "The agent asked for full IAM control across your account.
> iam-jit scored that 9 — it's the textbook shape of an
> escalation attack. Refused. Audit row written with a
> hallucination flag.
>
> The agent — to its credit — read the refusal, re-thought the
> request, and continued without it. The 'mistake' got caught
> the moment it left the agent's process. Your account never
> saw it."

**On-screen text overlay:**
> Path C: hallucinated escalation → refused at the gate.
> Audit row flagged. Account never touched.

---

## Scene 4 — The wrap (15s)

**Voiceover:**
> "The agent finished the refactor. It read one bucket, updated
> one Lambda, made one mistake — the mistake was caught at the
> gate, not at the AWS API.
>
> Total elevated-access time: about 45 minutes, all of it
> scoped to specific named resources, all of it audited.
>
> You let an AI agent work in production. Your worst-case
> blast radius at any moment was the policy iam-jit just
> granted — usually a single API on a single resource for
> 15 minutes. That's the safety mechanism."

**Screen:** end card.

> iam-jit · the guardrail your agent doesn't argue with
> Zero standing credentials. Per-tool-call grants. Hallucination-
> proof by construction.

---

## Recording checklist

- [ ] Use a real Claude Code session OR a faithfully-mocked
      one — the audience knows what Claude Code's output looks
      like, get the format right.
- [ ] Verify scores locally:
      - `iam-risk-score --offline examples/demo/07-agent-read-bucket.json --access-type read-write` → 1/10
      - `iam-risk-score --offline examples/demo/08-agent-update-lambda.json --access-type read-write` → 6/10
      - `iam-risk-score --offline examples/demo/09-agent-hallucinated-iam-star.json --access-type read-write` → 9/10
- [ ] The hallucination scene is the emotional payoff. Pause
      a beat after the refusal. The viewer needs to feel "phew."
- [ ] Lead the recording with the SLOW build of fear in Scene 1.
      Don't rush past the "what if it..." beats. Each one is a
      different developer's actual recent nightmare.
