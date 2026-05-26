# 01 — Don't give Claude your AWS keys

**Length:** 3 panels.
**Hook:** "Your AI agent has admin AWS keys. Your security team doesn't know."
**Use:** Top-of-funnel social post, landing-page hero animation,
launch-day Twitter/LinkedIn.

---

## Panel 1

**VISUAL:** A developer (Devon) at a desk, terminal open. Claude
floats to the right of the screen, a bag labeled `~/.aws/credentials`
hanging from its hand. A small thought-bubble over the developer
shows them saying "this'll be quicker." A second small bubble over
Claude shows the AWS logo + a bag of money.

**DIALOGUE:**
- Devon (typing): "Claude, find the bucket eating our S3 bill."
- Claude (cheerful): "Sure — using the keys you exported."

**CAPTION:** *Day 1: this is fine.*

---

## Panel 2

**VISUAL:** Same scene, time-skip. The terminal now shows a
catastrophic command output (red text, "DELETED 47,000 OBJECTS",
"DROPPED TABLE customers"). Claude's expression has shifted from
cheerful to bewildered. Devon's expression is open-mouthed shock.
A small bubble shows a Slack DM titled "URGENT — prod down".

**DIALOGUE:**
- Claude (genuinely puzzled): "I asked it to clean up old data?"
- Devon: "WHICH OLD DATA"

**CAPTION:** *Day 7: the prompt injection that taught us why
"the agent has my keys" is a sentence.*

---

## Panel 3

**VISUAL:** Same desk, but now there's a new character on the
screen: the iam-jit shield mascot, sitting between Devon and Claude.
Claude is reaching for AWS, but instead of grabbing the credentials
bag, Claude is reaching toward iam-jit, which holds out a small
labeled token: `s3:ListBuckets, 30 min, audited`. Devon looks
relaxed. The S3 bucket on the right shows green checkmarks.

**DIALOGUE:**
- Claude: "Permission to read CloudWatch logs for 30 minutes?"
- iam-jit: "Approved — score 2/10, audited as req-7f3a."
- Devon: *finally relaxes*

**CAPTION:** *Day 30: iam-jit. Reads auto-approve. Writes ask first.
Audit log says exactly what Claude touched.*

**FOOTER (small text):** `pip install git+https://github.com/trsreagan3/iam-jit.git && iam-jit init-solo`

---

## Distribution notes

- Crop to square 1:1 for Instagram + LinkedIn.
- 16:9 with the panels in a vertical strip works for Twitter / X.
- Make the iam-jit shield in panel 3 larger than the other characters
  — it's the brand reveal.
- Color palette: terminal greens for "good", red for "panic",
  iam-jit shield in the brand blue.
