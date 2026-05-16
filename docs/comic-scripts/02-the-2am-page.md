# 02 — The 2am page

**Length:** 5 panels.
**Hook:** "On-call at 2am. You need prod read access for 15 minutes.
The approval chain takes 45."
**Use:** "Who actually needs this" post for the developer audience.
Lands the "iam-jit makes me sleep better" angle.

---

## Panel 1

**VISUAL:** A bedroom at 2am. Reagan is in bed, phone vibrating
violently on the nightstand. PagerDuty notification visible on the
screen: "PROD ALERT — checkout-svc 500s rising". Cat on the bed
looking unimpressed.

**DIALOGUE:**
- Phone: 🚨 **BZZZZ BZZZZ** 🚨

**CAPTION:** *2:07 AM. The pager wins again.*

---

## Panel 2

**VISUAL:** Reagan at desk in pajamas, terminal open, blearily
typing. A Slack channel sidebar shows "#incident-response" with a
red dot. He's drafting a request to read prod CloudWatch logs and
the prod DDB table.

**DIALOGUE:**
- Reagan (mumbling): "Need to see what the checkout service is
  actually doing in prod..."
- Reagan: "...and our prod-access flow has me on the night
  approval list, which is staffed by..."
- Reagan: *checks rotation* "...someone in Tokyo. Who is asleep."

**CAPTION:** *The approval flow that protects prod also blocks the
person fixing prod.*

---

## Panel 3

**VISUAL:** Split panel. LEFT: Reagan staring at "Pending approval"
status, the customer-impact chart climbing in the background. RIGHT:
A small superimposed clock counting up — 14 min, 31 min, 42 min, 47
min.

**DIALOGUE:**
- Reagan: "We are losing customers WHILE the system that's supposed
  to protect customers..."
- Slack notification appears: "Tanaka-san approved your request. Sorry,
  was asleep."

**CAPTION:** *Reagan now has the read access. The customers do not
have the company.*

---

## Panel 4

**VISUAL:** Same desk, but the next on-call rotation a week later.
Reagan is using iam-jit via Claude. Claude is asking for
`cloudwatch:GetMetricStatistics + logs:FilterLogEvents` on the
checkout service, score 2/10. iam-jit shield is auto-approving with
a green checkmark.

**DIALOGUE:**
- Claude: "checkout-svc 500s — pulling logs + metrics..."
- iam-jit: "Read-only, score 2/10, audited as req-9b2. Granted
  15min."
- Reagan: "Wait, I didn't... approve anything? Did anyone approve?"
- iam-jit: "Self-approval — you have admin authority. Audit
  records that you authorized it via the on-call session."

**CAPTION:** *iam-jit recognizes "you're already an admin asking
for a narrower thing." Reductions skip approval, not audit.*

---

## Panel 5

**VISUAL:** Reagan back in bed. Cat is now between Reagan and the
phone. Phone shows the same 2am pager, but the next message is
already "RESOLVED — root-caused to checkout-svc retry storm."

**DIALOGUE:**
- Reagan: "...okay, I can actually sleep this time."
- Cat (thought bubble): *finally*

**CAPTION:** *The on-call rotation didn't change. The friction did.*

**FOOTER (small text):** `iam-jit init-solo` →
`https://iam-jit.com/recipes/admin-safety`

---

## Distribution notes

- Lead-out CTA panel can be cropped off for the social cut; the
  story works as a 4-panel without it.
- Reagan's pajamas are intentional — readers should feel the
  "this is me" moment in panel 1.
- Panel 4's "wait, I didn't approve anything?" is the educational
  moment for the `[[self-approve-reductions]]` feature; don't lose it.
