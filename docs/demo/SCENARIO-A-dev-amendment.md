# Scenario A — "From file-a-ticket to flow"

**Length:** ~3-4 minutes (flagship demo)
**Arc:** old workflow → "what if?" → augmented mode → transparent mode → still safe
**Audience hook:** every developer recognizes the old workflow's pain

The product point: iam-jit doesn't force a workflow change. It
augments the ticket-based flow you already have (faster, richer
context, instant scoring), and OPTIONALLY makes low-risk requests
transparent through the AI-native path. You pick the mode per
team or per request.

---

## Scene 1 — The old workflow (40s)

**Voiceover:**
> "Here's how access requests work today. You're a developer.
> Your script fails because it can't read a bucket."

**Screen:** terminal.

**Commands to run on camera:**

```bash
aws s3 cp s3://iam-jit-demo-staging/data.csv ./
```

**Expected output:**

```
An error occurred (AccessDenied) when calling the GetObject operation:
User: arn:aws:iam::111122223333:user/alice is not authorized to perform:
s3:GetObject on resource: "arn:aws:s3:::iam-jit-demo-staging/data.csv"
```

**Voiceover continues:**
> "So you do the dance. Open Slack. Find the right admin. Fill
> out the request. Wait."

**Screen:** cut to Slack (mock).

**Mock Slack message (alice typing in `#access-requests`):**

```
alice  ·  2:13 PM
@admins — can someone grant me read access to the staging
data bucket? I'm working on the sync job that pulls
analytics. Need a few hours. Thanks!
```

**Show the wait — fade through:**

- 2:13 PM — request posted
- 2:47 PM — alice context-switches to a different ticket
- 3:31 PM — admin sees the message, asks "what bucket exactly?"
- 4:12 PM — back-and-forth, admin grants permanent read access
            (because nobody wants to redo this dance)
- 4:14 PM — alice finally gets back to the original task

**On-screen text overlay:**
> 2 hours from blocked → unblocked.
> Permanent grant because the loop hurts more than the risk.

---

## Scene 2 — "What if?" (15s)

**Voiceover (slower, more measured):**
> "What if the request could happen *in* the work, instead of
> next to it? What if the admin got every piece of context they
> needed in the message itself — so there's no back-and-forth?
> And what if the requests that are obviously safe didn't need
> to bother a human at all?"

**Screen:** fade to iam-jit title card.

**On-screen text:**
> iam-jit
> Two modes, your call.

---

## Scene 3 — Augmented mode: same workflow, better (50s)

**Voiceover:**
> "First mode: augmented. The flow you already have, just with
> better tools. Same admins, same approvals, same audit trail.
> The difference is what the admin sees."

**Screen:** alice's terminal again. Different command this time.

**Commands to run on camera:**

```bash
iam-jit request \
  --role-template read-staging-bucket \
  --duration 4h \
  --reason "sync job analytics pull — bucket iam-jit-demo-staging only"
```

**Expected output (the augmented-mode response — sent to admin):**

```
✓ Request submitted to admin@example.com
  Score: 3/10 (low) — would auto-approve at threshold ≥ 5
  Reason: sync job analytics pull — bucket iam-jit-demo-staging only
  Duration: 4h
  Awaiting admin review (your team has auto-approve disabled)
```

**Voiceover continues:**
> "iam-jit scored it instantly: low risk. The admin gets a
> message with that score, the reason, and the exact policy.
> No 'what bucket exactly?' back-and-forth."

**Screen:** cut to admin's Slack (mock).

**Mock Slack message:**

```
#iam-jit-reviews · iam-jit-bot · 2:14 PM
Request from alice@example.com — Score 3/10 (low) 🟢

What:    Read iam-jit-demo-staging for 4h
Reason:  sync job analytics pull — bucket iam-jit-demo-staging only
Scope:   s3:GetObject, s3:ListBucket on one bucket
Why low: All statements scoped, no broad patterns

CloudTrail context (last 24h):
  alice@ has touched this bucket 14× in the past week (normal)
  alice@ has not requested broader scope in 90d

[ Approve as-requested ]  [ Approve with edits ]  [ Refuse ]
```

**Voiceover continues:**
> "The admin reads the whole request in one glance, clicks
> approve. Twenty seconds, not two hours. Same human approval —
> just instrumented better."

**Click Approve. Show the confirmation toast back to alice.**

**On-screen text overlay:**
> Augmented mode: human approval, instrumented.
> 20 sec instead of 2 hours.

---

## Scene 4 — Transparent mode: low-risk just works (40s)

**Voiceover:**
> "Second mode: transparent. For your low-risk requests — and
> the scorer tells you which those are — iam-jit can just grant
> them. The audit trail still records every detail. The admin
> just doesn't have to look at every one."

**Screen:** alice's terminal. This time, the request comes from
her AI agent (Claude Code) using the MCP integration.

**Commands to run on camera (showing the agent's view):**

```bash
# alice is now using Claude Code; the agent autonomously
# requests via MCP when it hits AccessDenied
claude-code "investigate the data.csv format in staging"
```

**Show Claude Code's terminal output (mock):**

```
[claude] Reading data.csv from iam-jit-demo-staging…
[claude] AccessDenied. Requesting role via iam-jit MCP server.
[iam-jit-mcp] request → role-template: read-staging-bucket
[iam-jit-mcp] ✓ Scored: 3/10 (low) · transparent-approve threshold 5
[iam-jit-mcp] ✓ Grant issued: iam-jit-alice-1715706000 (expires in 1h)
[claude] download: s3://iam-jit-demo-staging/data.csv to ./
[claude] data.csv has 4 columns: event_id, user_id, ts, payload_json
[claude] Looks like the sync job needs event_id as the primary key.
```

**Voiceover continues:**
> "The agent never paused. Alice never paused. The grant still
> shows up in the admin dashboard — fully audited — but nobody
> had to be paged. The reviewer's time is freed up for the
> requests that actually matter."

**Screen:** cut to admin dashboard (mock).

**Admin dashboard panel:**

```
Recent activity (transparent-approved):
  2:14 PM  alice@  read-staging-bucket  3/10  expires 6:14 PM
  2:09 PM  bob@    deploy-staging       4/10  expires 2:14 PM
  1:55 PM  ci/cd   lambda-update        6/10  ⚠ admin-approved template
```

**On-screen text overlay:**
> Transparent mode: audit trail full, queue empty.

---

## Scene 5 — The high-risk amendment still gets a human (45s)

**Voiceover:**
> "Transparent doesn't mean unsupervised. Some requests still
> matter enough that a human has to see them. iam-jit knows
> which ones."

**Screen:** alice's terminal, working with the data.

**Commands to run on camera:**

```bash
# alice's agent needs to write the cleaned data back to a
# different bucket — prod-snapshots
claude-code "copy the cleaned parquet into prod-snapshots"
```

**Claude Code output (mock):**

```
[claude] AccessDenied on s3:PutObject for iam-jit-demo-prod-snapshots
[claude] Asking iam-jit MCP to amend the current grant…
[iam-jit-mcp] amend → add s3:PutObject, s3:DeleteObject on prod-snapshots/*
[iam-jit-mcp] Re-scoring FULL effective policy (amendment + original):
[iam-jit-mcp] ⚠ Score: 8/10 (high) — above threshold 5
[iam-jit-mcp] Routed to admin review. Slack pinged.
[iam-jit-mcp] Awaiting decision; existing grant still active.
[claude] OK, waiting on admin review for the prod-snapshots write.
[claude] Meanwhile: I can still read staging. Continuing analysis.
```

**Voiceover continues:**
> "iam-jit re-scored the *full* effective policy after the
> amendment. The combined grant is now 8 out of 10. That
> crosses the auto-approve line — even in transparent mode —
> and routes to a human. The original low-risk grant keeps
> working; only the amendment is blocked."

**Screen:** cut to the admin's iam-jit review UI.

**UI panel spec:**

```
┌─────────────────────────────────────────────────────────────┐
│  iam-jit · Amendment awaiting review (HIGH-RISK delta)      │
├─────────────────────────────────────────────────────────────┤
│  Original grant:  alice@ · read-staging-bucket · 3/10 ✓     │
│  Amendment delta: + prod-snapshots write/delete             │
│  New full score:  8/10  ████████░░  (was 3/10)              │
│                                                             │
│  Why the score went up:                                     │
│    ⚠ Destructive action s3:DeleteObject on prod resource    │
│    ⚠ State-changing s3:PutObject on prod resource           │
│                                                             │
│  Agent's reason:                                            │
│    "Need to copy cleaned parquet from staging analysis      │
│     into prod-snapshots for sync team"                      │
│                                                             │
│  CloudTrail context (last 24h):                             │
│    alice@ has touched prod-snapshots: 0 times               │
│    alice@ has touched staging:        14 times              │
│                                                             │
│  [ Approve as-requested ]  [ Edit scope ]  [ Refuse ]       │
└─────────────────────────────────────────────────────────────┘
```

**Voiceover continues:**
> "The admin reads the diff, the score change, the reason. It
> makes sense — the sync job needs to land somewhere. Approve.
> Alice's agent picks back up where it left off."

---

## Scene 6 — The wrap (20s)

**Voiceover:**
> "You don't have to throw out your access-request workflow to
> use iam-jit. Run it in augmented mode — same humans, faster
> loop. Run it in transparent mode for low-risk patterns and
> let humans focus on the requests that actually need them.
> Run both, with different thresholds per team.
>
> The product meets you where you are."

**Screen:** three-column summary.

| Mode | Who approves | What changes |
| --- | --- | --- |
| Old workflow | Human, every time | Manual context-gathering, 2h round trips |
| **Augmented** | Human, every time | Richer context, score, instant routing — 20 sec |
| **Transparent** | Human only for high-risk | Low-risk grants happen in-flow — 3 sec |

**End card:**
> iam-jit · score, route, audit.
> The risk gate that fits your existing workflow.

---

## Recording checklist

- [ ] Three "windows" minimum: alice's terminal, alice's Slack,
      admin's Slack/dashboard. Color-code so viewers track who's
      who.
- [ ] Use real terminal output for the commands that hit the CLI;
      mock the Slack messages with a tool like Mockuups Studio.
- [ ] Verify scores locally before recording:
      - `iam-risk-score --offline examples/demo/01-initial-grant.json --access-type read-write` → 3/10
      - `iam-risk-score --offline examples/demo/02-amendment-with-prod-write.json --access-type read-write` → 8/10
- [ ] If iam-jit is deployed locally, the admin UI screenshots
      can be real (record from `uvicorn iam_jit.app:create_app --factory`).
      Otherwise use the mock spec above.
- [ ] The "old workflow" Slack scene takes the longest to mock
      well — invest there. It's the contrast that sells the rest.
