# Comic-strip scripts

Per `[[comic-strip-demo-format]]` memo: comic strips are the PRIMARY
demo content for iam-jit (not videos). Easier to produce, more
shareable, work without sound, embed cleanly in social posts.

This directory holds the SCRIPTS — text-only descriptions of panels
+ characters + dialogue. The actual artwork is produced separately
(per the moodboard PDF in `docs/moodboard/`).

## Cast

- **Claude** — purple Anthropic logo character. Eager, helpful,
  unaware of consequences.
- **Devon** — the developer protagonist character (avatar pending).
- **Tux** — Linux penguin, when the scene is on a server / shell.
- **Gopher** — Go gopher, when the scene involves backend infra
  (terraform, k8s, AWS SDK).
- **Helmsman** — Kubernetes helmsman, for k8s scenes.
- **iam-jit** — the security-shield mascot (a friendly armored
  shield with eyes, not menacing).

## Format

Each script is a markdown file with:
- **Title** — short, memorable, sharable.
- **Length** — number of panels (3, 5, 9 typical).
- **Hook** — one-sentence pitch that fits in a tweet.
- **Panels** — numbered, each with VISUAL + DIALOGUE + CAPTION.

## Existing scripts

- `01-dont-give-claude-your-keys.md` — the 3-panel flagship.
- `02-the-2am-page.md` — 5-panel on-call story.
- `03-the-prompt-injection.md` — 5-panel attack scenario.
- `04-the-friday-deploy.md` — 9-panel cautionary tale.

## Don't

- Don't draw real-world incidents in a way that names companies or
  identifies specific incidents — keep them composite. The
  `docs/INCIDENTS-IAMJIT-WOULD-HAVE-PREVENTED.md` doc has source
  material; the comics are inspired-by, not documenting.
- Don't make Claude look stupid. The hook is "agents are powerful
  AND fallible" — not "AI is dumb."
- Don't lead with "we BLOCK" — per `[[safety-mode-lean-permissive]]`,
  block-happy framing is a turnoff. Lead with audit + scope.
