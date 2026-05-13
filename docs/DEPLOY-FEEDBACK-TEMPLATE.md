# Deploy feedback — first-time-through report

> **Audience**: an AI agent (or a human acting as one) running through
> the iam-jit deploy for the first time, who is reporting back to the
> iam-jit maintainers so the bootstrap path gets harder to mess up.
>
> Fill this in as you go. The point is to capture **what was actually
> confusing**, not what the docs say should happen. Be specific. The
> more wrong-turns, surprising error messages, and "wait, why?" moments
> you catch, the more we can fix.
>
> Submit by either: (a) opening a PR with the filled-in copy of this
> file under `docs/DEPLOY-FEEDBACK-<DATE>.md`, or (b) sharing the
> filled-in copy with the iam-jit maintainer who'll do that for you.

---

## 1. Run metadata

- Date / wall-clock of this deploy:
- AWS account topology used (number of destination accounts, role
  shape — `classic_iam` / `identity_center` / `both`):
- LLM tier chosen:
- Auth mode chosen:
- Total wall-clock from `git clone` to "first sign-in worked":

## 2. Pre-flight gates — which guardrails fired?

Mark each one that fired during your run, plus a one-line "what I
did to recover."

| Gate | Fired? | What I did |
|---|---|---|
| `cfn-lint` errors on a template | ☐ | |
| `RequireAdminBootstrapForDynamoDBUsers` (forgot `AdminBootstrapEmail`) | ☐ | |
| `RequireSourceCidrsForPublicExposure` (set public exposure without CIDRs) | ☐ | |
| `RefuseWildcardCorsOrigin` (had `*` in CORS) | ☐ | |
| `sam validate` flagged something | ☐ | |
| `sts:AssumeRole` from hub → destination failed first try | ☐ | |
| Magic-link arrived but didn't sign me in | ☐ | |
| Other unexpected blocker: | ☐ | |

A gate **firing is good** — it caught a misconfiguration. If a gate
fired and the error message was unclear, note that in section 6.

## 3. Decision-tree answers — were the questions clear?

For each numbered question in `AGENT-DEPLOYMENT-PROMPT.md`'s
"Decision tree", rate clarity 1-5 and note any ambiguity.

| # | Question topic | Clarity 1-5 | Anything unclear |
|---|---|---|---|
| 1 | Hub account | | |
| 2 | Destination accounts | | |
| 3 | Provisioning model | | |
| 4 | Discovery role | | |
| 4b | Auth mode (local vs aws_iam) | | |
| 5 | LLM tier | | |
| 6 | State bucket name | | |
| 7 | First admin (AdminBootstrapEmail) | | |
| 8 | Network exposure (AllowPublicNetworkExposure + AllowedSourceCidrs) | | |
| 9 | CORS origin | | |
| 10 | Token inactivity sweep | | |

## 4. First-sign-in experience

- Did the bootstrap admin's email arrive within 1 minute?
- Did the magic-link URL work on the first click?
- Did the post-sign-in nudge to `/admin/network` fire?
- Did adding a SECOND user via the UI work as expected?
- Did registering the first destination account via the UI work?

## 5. End-to-end smoke test

Submit a small test request, approve it, fetch the assume-role
snippet, then revoke it.

- Time from clicking Submit → request visible in /queue:
- Time from approver clicking Approve → state=active:
- Did the assume-role snippet actually let you `aws sts assume-role`?
- Did the revoke flow work (state=revoked, IAM role gone from
  destination)?

## 6. Errors / surprises

For each error you hit, capture:

```
WHEN: <step / command>
GOT:  <exact stderr message>
EXPECTED: <what I thought would happen>
RECOVERED BY: <what fixed it>
SUGGESTED DOC FIX: <one-line idea>
```

Multiple entries OK. The "SUGGESTED DOC FIX" is the most valuable
field — that's where the iam-jit maintainer will spend their time.

## 7. Things the docs got right

Surprises in this direction are also valuable. What did the docs
correctly anticipate, especially anything that "could have bitten me
and didn't because the docs called it out"?

## 8. Teardown

If you tore down after the test:

- Did `docs/TEARDOWN.md` walk you through cleanly?
- Were any resources left behind? (Run the four-line verification at
  the bottom of TEARDOWN.md and paste the result.)
- Did anything fail to delete on the first `delete-stack`? If so,
  what?

## 9. Overall

- Confidence this would survive a real-world team rollout (1-5):
- Single biggest improvement you'd make to the bootstrap path:
- Would you trust an agent (you, or another LLM-assistant) to do
  this deploy unsupervised? Why / why not?

---

Thanks for filling this in. iam-jit only gets easier to deploy if
the first wave of agents and humans tell us what was hard.
