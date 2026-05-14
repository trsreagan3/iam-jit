# Scenario A — comic-strip brief

**Same story as `SCENARIO-A-dev-amendment.md`, formatted for an
illustrator.** Each panel below is a self-contained artist
brief: setting, characters, speech/caption, mood cue. Hand this
file to a freelance illustrator — they should be able to
produce all 8 panels from these briefs alone.

**Format:** 8 landscape panels, intended for a 2-column × 4-row
grid (web-friendly + Twitter-card-shareable).

**Cast:**
- **Gopher** = Go gopher (Renee French), our developer character
- **Tux** = Linux penguin, our admin character
- **Robot** = generic friendly robot icon, our AI agent character
  (appears in later panels)
- **iam-jit shield** = small recurring badge with a friendly face,
  the product's visual presence. Color: matches landing-page
  brand (green pill for "low score", red pill for "high score").

---

## PANEL 1 — "AccessDenied"

- **Setting:** Gopher's home workspace. Desk, laptop, plant.
  Time-of-day: afternoon (warm lighting).
- **Characters:** Gopher, looking surprised.
- **On-screen text (laptop):** A terminal showing
  `AccessDenied: User alice is not authorized to perform: s3:GetObject`
- **Gopher speech balloon:** "Wait, I just need to read one
  file..."
- **Mood:** Frustrated but neutral. The "everyone has had this
  Tuesday" face.

---

## PANEL 2 — "The old workflow"

- **Setting:** Split panel — Gopher's screen on the left,
  Tux's monitor on the right (different rooms, connected by a
  Slack window stretched across both).
- **Characters:** Gopher (typing), Tux (sleeping at desk, "ZZZ"
  bubble over head; it's late in Tux's timezone).
- **On-screen Slack message (from Gopher):** "@admins — can
  someone grant me read access to the staging data bucket?"
- **Caption strip at bottom:** "2:13 PM"
- **Mood:** Subdued. Gopher looks tired of this dance. Tux is
  literally asleep.

---

## PANEL 3 — "Two hours later"

- **Setting:** Same as panel 2 but the clock now says 4:14 PM.
  Gopher's plant is slightly wilted (visual time-passing gag).
- **Characters:** Gopher (slumped over keyboard), Tux (just
  waking up, coffee in hand).
- **Tux speech balloon (Slack):** "Wait, which bucket exactly?
  Is this for the sync job?"
- **Gopher speech balloon (small, defeated):** "...yes"
- **Mood:** Resignation. The classic "we have to redo this
  every Tuesday" energy.

---

## PANEL 4 — "What if?"

- **Setting:** Full-bleed panel. White background. Just the
  iam-jit shield logo, slightly larger than usual, floating
  in the center.
- **Characters:** None (the shield is the subject).
- **Caption / large text:**
  "What if the request happened *in* the work — and the obvious
  ones didn't bother a human at all?"
- **Small caption at bottom:** "iam-jit"
- **Mood:** Pause. Beat. This panel is the pivot of the strip.

---

## PANEL 5 — "Augmented mode"

- **Setting:** Gopher's workspace again, but the plant is
  perked back up (visual cue: this is the alternate timeline).
  iam-jit shield is now sitting on Gopher's desk.
- **Characters:** Gopher (typing happily), iam-jit shield
  (smiling).
- **On-screen text (laptop):**
  ```
  $ iam-jit request --role read-staging --duration 4h
  ✓ Score: 3/10 (low) · routed to admin
  ```
- **iam-jit shield speech balloon (small, friendly):**
  "Score 3 — I scored it for you. Tux is getting a clean
  request now."
- **Mood:** Cheerful. The shield is a helpful little buddy.

---

## PANEL 6 — "Tux gets a request worth approving"

- **Setting:** Tux's workspace. Slack open. The message is
  clearly different from panel 2's vague request.
- **Characters:** Tux (alert, coffee in hand, smiling).
- **Slack message panel content (visible in the comic):**
  ```
  iam-jit-bot · Request from alice
  Score: 3/10 (low) 🟢
  Read: staging bucket, 4h
  Reason: sync job analytics pull
  [ Approve ]  [ Edit ]  [ Refuse ]
  ```
- **Tux speech balloon:** "Oh, that's straightforward. Approve."
  (Tux's hand on a comically large APPROVE button.)
- **Caption at bottom:** "20 seconds, not 2 hours."
- **Mood:** Smooth. The admin is doing the work they should be
  doing, but quickly.

---

## PANEL 7 — "Transparent mode (for the obvious ones)"

- **Setting:** Same as panel 5 but with a small robot icon
  also on Gopher's desk. The robot is helping with work.
- **Characters:** Gopher (working on something else), Robot
  (its arm reaching toward a small screen labeled "request"),
  iam-jit shield (giving the robot a thumbs up).
- **Robot's speech balloon (small):** "I need to read the
  schema..."
- **iam-jit shield speech balloon:** "Score 1. Approved.
  15-minute grant. Off you go."
- **Caption at bottom (small):**
  "For routine low-risk requests, no human in the loop."
- **Mood:** Quiet hum of productivity. Nobody is paged. The
  agent is working but bounded.

---

## PANEL 8 — "The amendment still routes to Tux"

- **Setting:** Two-panel split — Gopher's workspace on the
  left, Tux's workspace on the right.
- **Characters:** Robot (asking for more), iam-jit shield
  (holding up a STOP sign), Tux (back at desk, attentive).
- **Robot's speech balloon (small):**
  "Now I need to write to prod-snapshots..."
- **iam-jit shield speech balloon:**
  "Score jumped to 8/10. That one needs a human. Tux —"
- **Tux's speech balloon (right side):**
  "I see it. The score, the diff, the reason. One look. Approve
  or refuse."
- **Caption at bottom (FINAL):**
  "iam-jit: humans for the requests that matter. In-flow for
  everything else."
- **Mood:** Tidy resolution. The system did the right thing.
  Tux is empowered, not flooded.

---

## Illustrator notes

- Keep speech balloons SHORT (max ~12 words). Panels rely on
  visual storytelling first; text is captions, not dialogue.
- Color tone:
  - Panels 1-3 (old workflow): muted, slightly desaturated.
  - Panel 4 (pivot): clean, hopeful, mostly white.
  - Panels 5-8 (new world): brighter, warmer, more saturated.
- The iam-jit shield should be the same character in every
  panel — keep proportions and expression library consistent
  across the strip. (It's our recurring mascot; viewers will
  see it again across the other strips.)
- The "score" pill (red/amber/green) is a recurring UI element.
  Show it as a chip badge floating near whatever it's scoring.

## Where this strip lands

- Landing page hero (above the fold, in place of the
  current marketing copy)
- Top of the launch blog post
- Twitter/X launch thread, image-1
- LinkedIn announcement, image-1
- README hero image

One strip, five touchpoints. That's the leverage.

## After this lands well

Convert scenarios B (compromised CI), C (incentive loop),
D (5-min secret), and E (agent guardrail) into the same
panel-by-panel brief format. Same cast, same shield-mascot
visual style, different stories. The four-or-five-strip set
is the launch-week content calendar.
