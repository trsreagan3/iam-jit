# Scenario B — "The compromised CI pipeline"

**Length:** ~2 minutes
**Hook:** even a credential leak doesn't open the door
**Payoff:** attacker dwell time goes from hours to minutes

---

## Scene 1 — The baseline pipeline (20s)

**Voiceover:**
> "Your CI pipeline deploys a Lambda function to staging. The
> role's been admin-approved once; iam-jit reissues short-lived
> credentials for each deploy."

**Screen:** GitHub Actions workflow file, then run logs.

**Show on screen (`.github/workflows/deploy.yml` excerpt):**

```yaml
- name: Request iam-jit deploy role
  uses: trsreagan3/iam-risk-score-action@v1
  with:
    role-template: lambda-deploy-staging
    duration: 5m

- name: Deploy
  run: |
    aws lambda update-function-code \
      --function-name web-app-staging \
      --zip-file fileb://build/lambda.zip
```

**Then GitHub Actions run log (mock):**

```
✓ iam-jit · request role lambda-deploy-staging
  ✓ Scored: 6/10 (high) · admin-approved baseline · auto-issued credentials
✓ Deploy · update web-app-staging · 4.2s
✓ Smoke test · passing
```

**On-screen text overlay:**
> Score 6 because Lambda code-update is inherently high-impact.
> Admin one-time approval pins this as the OK shape.

---

## Scene 2 — The compromise (30s)

**Voiceover:**
> "Now: the runner gets compromised. Maybe a typosquatted action
> exfiltrated the GitHub token. Maybe a build dependency was
> backdoored. Doesn't matter — the attacker has the same
> credentials your pipeline has."

**Screen:** terminal as if the attacker is now driving the
runner. Show curl/aws-cli commands.

**Commands to run on camera (the attacker's perspective):**

```bash
# Attacker has hijacked the runner. They try to use the
# existing role for something it wasn't approved for:
aws iam create-access-key --user-name production-deploy
```

**Expected output:**

```
An error occurred (AccessDenied) when calling the CreateAccessKey operation:
Role iam-jit-pipeline-2026051411 does not have permission for iam:CreateAccessKey.
```

**Voiceover continues:**
> "First attempt fails — the original role was scoped tight. So
> the attacker tries the next thing: amending the role."

**Commands continue:**

```bash
# Attacker asks iam-jit to amend the existing pipeline role:
iam-jit amend \
  --grant-id $CURRENT_GRANT \
  --add-action 'iam:CreateAccessKey' \
  --add-action 'iam:AttachUserPolicy' \
  --add-action 'sts:AssumeRole' \
  --add-action 'iam:PassRole' \
  --add-resource '*' \
  --reason "infrastructure fix"
```

**Expected output:**

```
Effective policy after amendment scored: 9/10 (high)

  Risk factors:
    ⚠ iam:CreateAccessKey on Resource: * (broad access to sensitive resource)
    ⚠ iam:AttachUserPolicy on Resource: * touches sensitive service `iam`
    ⚠ Privilege-escalation primitive: iam:PassRole + sts:AssumeRole combined

  Score change: 6 → 9
  Above auto-approve threshold (5). Routed to admin review.
  Slack: #iam-jit-reviews pinged with HIGH-SEVERITY tag.
  Existing grant remains active pending review.

Status: AWAITING_REVIEW
```

**On-screen text overlay:**
> Amendment forces full-policy re-scoring. Composition attacks
> can't sneak past delta-only checks.

---

## Scene 3 — The admin reads the signal (40s)

**Voiceover:**
> "The admin's phone buzzes. iam-jit didn't just say 'review
> this' — it said 'this jumped from 6 to 9 with privilege-
> escalation primitives.' The framing alone is the alarm."

**Screen:** cut to admin's Slack.

**Mock Slack message:**

```
#iam-jit-reviews  ·  iam-jit-bot  ·  just now
🚨 HIGH-SEVERITY amendment request

Grant: iam-jit-pipeline-2026051411
Requester: github-actions-runner (CI/CD service principal)
Score: 6 → 9

What changed:
  + iam:CreateAccessKey on *
  + iam:AttachUserPolicy on *
  + iam:PassRole on *
  + sts:AssumeRole on *

Why this is a red flag:
  · Original role: Lambda code update on one named function
  · Amendment: full IAM-control surface across the account
  · The two have no shared use case

CloudTrail context (last 1h):
  · Runner ran `aws iam list-users` (NOT in baseline behavior)
  · Runner ran `aws sts get-caller-identity` 14x (likely
    enumeration)

Stated reason: "infrastructure fix" (low specificity)

[ Refuse + revoke baseline grant ]  [ View full diff ]  [ Refuse only ]
```

**Voiceover continues:**
> "The admin doesn't need to investigate. iam-jit has already
> done the pattern-match. Refuse and revoke."

**Click [ Refuse + revoke baseline grant ]. Show confirmation.**

---

## Scene 4 — The aftermath (20s)

**Voiceover:**
> "Within 60 seconds of the attacker's first amendment
> request, the runner's credentials are gone. The attacker
> never gets the IAM-control surface they were trying to pivot
> into. Your account stays safe."

**Screen:** terminal again, attacker's perspective.

**Commands to run on camera:**

```bash
aws lambda update-function-code \
  --function-name web-app-staging \
  --zip-file fileb://attacker-payload.zip
```

**Expected output:**

```
An error occurred (AccessDenied) when calling the UpdateFunctionCode operation:
The security token included in the request is invalid.
```

**On-screen text overlay:**
> Compromised runner detected. Credentials revoked. Pivot path
> closed.

**Then a CloudTrail snippet showing the revocation:**

```
CloudTrail · iam-jit
2026-05-14T15:34:12  RevokeAccessGrant  grant=iam-jit-pipeline-2026051411
  reason="HIGH-SEVERITY amendment refused by admin@example.com"
  trigger="amendment attempt score 9/10"
```

---

## Scene 5 — The wrap (15s)

**Voiceover:**
> "iam-jit doesn't prevent credential leaks — nothing does.
> What it prevents is the attacker turning a narrow leaked
> credential into account-wide control. The blast radius stays
> bounded by what was originally approved.
>
> The compromise still happened. The breach didn't."

**End card:**
> iam-jit · the blast radius your auditor wants you to have
> Bounded grants. Composition-aware scoring. Human review for
> the requests that matter.

---

## Recording checklist

- [ ] Two terminal windows: one "pipeline" (clean prompt), one
      "attacker" (different color scheme so viewers see it's
      a different surface)
- [ ] Mock the Slack notification — design it to look like a
      real Slack message (avatar, channel header, timestamp).
      Don't use real Slack; sufficient screenshot quality from
      a mockup tool is fine.
- [ ] Verify scores locally:
      `iam-risk-score --offline examples/demo/04-cicd-baseline.json --access-type read-write`
      should print `6/10`. `05-cicd-compromised-amendment.json` should print `9/10`.
