# I adversarially tested my IAM risk scorer for 10 rounds — here's what convergence actually looks like

*Draft — May 2026. Target: HN front page, Twitter/X, /r/aws, security mailing lists. Cut hard before publishing.*

---

I built a deterministic AWS IAM policy risk scorer. The kind of thing that takes a JSON IAM policy and tells you "this is a 7 out of 10, here's why, don't auto-approve." Open source under Apache 2.0, free up to 100 requests/month at the hosted API, paid tiers add an LLM-generated narrative on top.

The interesting part isn't that I built a scorer. The interesting part is what happened when I stopped trusting myself and ran an adversarial loop against my own engine for 10 rounds.

## The setup

Two roles, run in parallel each round:

- **Black-box agent**: no source access. Hits the scoring engine like an external attacker would — submits weird-looking policies, watches what scores come back, learns the engine's blind spots from behavior alone.
- **White-box agent**: full source-code access. Reads the rules. Finds predicates that fire too narrowly, normalization edges, action-set omissions the black-box agent couldn't deduce from behavior.

Each round, both agents wrote YAML test fixtures asserting "this policy should score at least N." If the engine scored lower, that fixture became a regression-protected red test. Round ends; I close the gaps in the rules; commit; spawn the next round.

I let this run for 10 rounds plus one big "enumerate every documented attack pattern" pass against the open IAM security literature (197 patterns from Bishop Fox, Rhino Security Labs, HackingTheCloud, PMapper, MITRE ATT&CK cloud matrix, real-world incidents like Capital One and SCARLETEEL).

## What convergence looks like

The naive metric is "raw finding count drops over rounds." That's not what happened. Findings per round stayed in the 20-40 range from round 6 through round 9. Looking at just that number, you'd conclude the loop isn't converging.

The actual convergence signal is `max_gap` — the biggest single bypass the agent could find in one round. Trend:

```
Round  6 WB: max_gap = 1    (calibration only)
Round  7 WB: max_gap = 4
Round  8 WB: max_gap = 4
Round  9 BB: max_gap = 3
Round  9 WB: max_gap = 3
Round 10 BB: max_gap = 1    ← converged
Round 10 WB: max_gap = 0    ← converged
```

Two consecutive rounds at max_gap ≤ 1. That's the documented stopping criterion. The "raw count" never went to zero — it stayed at ~10-15 because each round drew from the documented-pattern library, and each find spawned a fix that pinned that pattern shut. The pattern surface is finite; we just had to walk through it.

## The bypasses that surprised me

I'd built the scorer assuming the obvious cases: `Action: "*"`, `Resource: "*"`, `Effect: "Allow"`, all the catastrophic action names. The adversarial rounds found classes I hadn't thought of:

### Statement-as-dict (round 5)

AWS IAM grammar officially supports two forms:

```json
"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]   // list
"Statement":  {"Effect": "Allow", "Action": "*", "Resource": "*"}    // single dict
```

My code only handled the list form. Single-dict form returned "no statements" and scored 1 — a complete admin bypass.

Worse: 16 AWS-published managed policies use the single-dict form. They'd all been scoring 1 in my corpus until the agent found it.

### Cyrillic `Effect: "Аllow"` (round 7)

`Effect: "Аllow"` (first character is Cyrillic А, U+0410, not Latin A) parsed-string-compared to `"Allow"` returns False. Statement is silently skipped. Combined with a real Allow statement elsewhere, the entire admin grant slips through scoring 1 while the malformed Cyrillic statement covers the smuggling.

NFKC normalization doesn't merge Cyrillic and Latin (different script blocks). I had to build a per-character homoglyph map.

### Conditions that look like scoping but aren't (rounds 6-9)

This category was the biggest blind spot. Eleven distinct patterns where a `Condition` block visually narrows the grant but actually imposes no constraint:

- `StringLike: { aws:PrincipalOrgID: "o-*" }` — `o-*` matches every AWS organization, not a specific one
- `Null: { aws:MultiFactorAuthAge: "true" }` — means "MFA must be ABSENT," inverted from typical intent
- `IpAddress: { aws:SourceIp: "10.0.0.0/8" }` — `aws:SourceIp` reflects the request's PUBLIC IP, so private CIDRs literally never match
- `DateGreaterThan: { aws:CurrentTime: "2020-01-01" }` — always-true past date
- `Bool: { aws:SecureTransport: "false" }` — only HTTP (cleartext) requests pass
- `StringNotEquals: { aws:PrincipalAccount: "111111111111" }` — every account EXCEPT this one (scope-OUT)

Every one of these had been flagged at some point by Bishop Fox or Rhino but nobody had built a scorer that detected the whole class. I now have eleven Condition vacuity rules.

### Cross-account direction (rounds 7-8)

When a trust policy or resource policy has `Principal.AWS = "arn:aws:iam::999999999999:root"`, that's a literal cross-account grant. The Resource looks narrow (one role, one bucket), the Principal looks narrow (one specific account), so a naive scorer flags nothing.

But the *direction* — Principal account ≠ Resource account — is the grant's whole point. I added a detector that compares the two account-id segments. Sibling detector for the `Condition.StringEquals: { aws:PrincipalAccount: "<other-account>" }` pattern where the cross-account intent is hidden in the Condition value.

### URL-encoded and HTML-entity colons (rounds 9-10)

`iam%3APassRole` (URL-encoded `:`) and `iam&#58;PassRole` (HTML-entity `:`) bypass service-prefix lookups because the action string no longer contains a real colon, so it can't be split into service+name. AWS rejects these at evaluation time, but the scorer's job is to flag risk *before* AWS sees the policy — otherwise a downstream tool that auto-corrects the encoding could ship a policy that scored 1 in review.

## The methodology in one paragraph

For every adversarial finding, ask three questions: is this a single bypass, a pattern class, or an entire missing feature? Single bypasses fix at the YAML level. Pattern classes fix at the rule level. Missing features (`Principal` field was never read for the first 5 rounds; `Condition` field for the first 6) fix at the architectural level. The third class is the one that's slowest to spot and most expensive to leave open — those are the bypasses that scale.

## What this means in practice

The scorer's deterministic floor is now load-bearing. When the engine returns score 9, it's seeing what an attacker would see. When it returns score 1, it's because every known bypass class has been considered and the policy genuinely is what it looks like.

The marketable number isn't "9 out of 10 policies score correctly" — that's a noisy summary that overweights edge cases. The real number is:

> **1,489 / 1,489 publicly-published AWS-managed policies score within their expected ±1 band against an independent Opus-4.7 judge.**

That's every IAM policy AWS itself publishes. Either the engine matches a third-party LLM oracle on the entire population, or it doesn't. It does.

## What this doesn't mean

Convergence is not proof of a perfect scorer. It's proof that the *known* attack pattern surface — 197 documented patterns from the open security literature, plus 10 rounds of adversarial probing — is now closed.

An attacker who publishes a genuinely novel attack pattern WILL bypass the scorer on first try. The defense is "fast follow on every new published attack," not "guaranteed catch-all." The discipline is the product, not the rules.

Three signals that should trigger a fresh round:

1. AWS launches new services (re:Invent, mid-year). I update the research compendium and re-enumerate.
2. New attack research published by Bishop Fox / Rhino / Wiz / HackingTheCloud. Same.
3. A customer reports a real-world bypass. Reproduce, fix at source, credit the reporter, ship.

That's monthly maintenance, not constant emergency response.

## The open question

I think the real moat here is the *process* being public, not the rules. Anyone can fork the corpus. Nobody can fork ten rounds of commit history that show me getting incrementally less wrong. The convergence trend is itself the trust artifact.

Code, corpus, rounds: github.com/trsreagan3/iam-jit.

If you're running an IAM scorer in production and haven't subjected it to this kind of discipline, I'd suggest one of two things: run a comparable loop yourself, or use this one. The deterministic floor is open source; the hosted API tier is what I sell. The methodology is documented in `docs/ADVERSARIAL-LOOP-PROCESS.md` and you can run the corpus locally with `make convergence`.

---

*Reagan Schiller, May 2026*

*Drafting notes: cut the methodology paragraph if HN length is an issue. The "surprising bypasses" section is the part that gets people to the bottom. The "what this doesn't mean" caveat is what wins trust with security skeptics — leave it in.*
