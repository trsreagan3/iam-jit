# Landing page copy — iam-risk-score

Draft copy for the public landing site at iam-risk-score.com. Designed
to load fast and convert technical decision-makers (eng leaders,
DevSecOps, AI platform teams).

---

## Hero section

### Headline (one of)

  - "Score AWS IAM policies before you grant access"
  - "The risk evaluator for AI agents requesting AWS access"
  - "JIT IAM with a brain"

Pick one based on A/B test or vibes. The middle one converts best
for AI-team buyers; the first one converts best for DevSecOps.

### Subheadline

> A deterministic-plus-LLM scoring engine that grades any IAM
> policy 1-10 in under 100ms. Drop into your CI pipeline, your
> agent runtime, or your existing JIT IAM tool. Free for the
> first 100 requests/month.

### Above-the-fold CTAs

  - **Primary:** "Try it now" → links to the live API playground
  - **Secondary:** "Install the CLI" → `pip install iam-risk-score`

### Above-the-fold code sample (the one thing visitors actually read)

```bash
$ iam-risk-score --offline my-policy.json

IAM Policy Risk Score

  Score:     7/10 (high)
  Threshold: 5 (FAIL)
  Analyzer:  deterministic

Risk factors:
  - Destructive action `s3:DeleteObject` on Resource: `*`
    (blast radius = every resource in this account)
  - Resource: `*` for s3 (broad cross-resource read/access)

Suggestions to reduce risk:
  - Scope `s3:DeleteObject` to specific resource ARNs
  - Consider adding `resource_constraints` for s3
```

---

## "How it works" section (three boxes)

**Box 1: Submit**

> Send any IAM policy via API, CLI, or GitHub Action. No SDK
> required — it's just JSON over HTTPS.

```bash
curl -X POST https://api.iam-risk-score.com/api/v1/score \
  -H "Content-Type: application/json" \
  -d '{"policy": {"Version": "2012-10-17", "Statement": [...]}}'
```

**Box 2: Score**

> A deterministic scorer applies 30+ calibrated risk rules.
> An optional LLM (Claude Opus or your own Bedrock/Ollama)
> generates a plain-English narrative for the human reviewer.

```json
{
  "score": 7,
  "tier": "high",
  "factors": ["Destructive action on wildcard", "..."],
  "suggestions": ["Scope to specific ARNs", "..."],
  "llm_narrative": "This policy gives the requester the ability to delete..."
}
```

**Box 3: Act**

> Auto-approve low-risk grants, route medium-risk to peer review,
> block destructive policies before they merge. Same score, three
> integration shapes — your existing tools decide what to do.

---

## "Why iam-risk-score is different" section

Compare table:

| | iam-risk-score | tfsec / Checkov | ConductorOne / Britive |
|---|---|---|---|
| Pass/fail rule check | ✅ | ✅ | ✅ |
| Numeric risk score (1-10) | ✅ | ❌ | partial |
| LLM-narrative explanation | ✅ | ❌ | ❌ |
| Calibrated for AI agents | ✅ | ❌ | ❌ |
| Customizable per-org context | ✅ | partial | partial |
| Free tier | ✅ | ✅ | ❌ |
| Self-hostable | ✅ | ✅ | ❌ |

---

## "Built for AI agents" section

A panel specifically targeting the AI-agent buyer.

### Heading: "Your agents need access. We need it to be safe."

> Every Claude / Cursor / coding-agent integration eventually
> asks for production access. The question is: how do you tell
> a safe request ("I need to read one S3 object") from a
> dangerous one ("Grant me iam:* to debug")?
>
> iam-risk-score answers in under 100ms. The deterministic
> scorer is designed to evaluate LLM-generated policies — it
> catches the patterns rule-based scanners miss (destructive
> verbs on wildcard, deceptive read-only labeling, chained
> privilege escalation).

Sample integration:

```python
# In your agent runtime
import iam_risk_score

verdict = iam_risk_score.score(
    policy=agent_proposed_policy,
    access_type="read-only",
)

if verdict.score < 4:
    # Auto-grant via your provisioning system
    grant_role(policy=agent_proposed_policy)
elif verdict.score < 7:
    # Surface to user for one-click approval
    ask_user(policy, verdict.factors, verdict.suggestions)
else:
    # Refuse — share the LLM narrative so the agent learns
    refuse(verdict.llm_narrative)
```

---

## "Built for CI/CD" section

A panel targeting the DevSecOps buyer.

### Heading: "Block destructive IAM PRs before they merge."

> Drop the GitHub Action into any repo with IAM IaC. It scores
> every policy change on every PR, sets required reviewers
> based on risk, and posts a structured comment.

```yaml
# .github/workflows/iam-review.yml
- uses: trsreagan3/iam-risk-score-action@v1
  with:
    policy-file: 'terraform/**/iam-*.tf'
    threshold: 5
    comment-on-pr: true
```

Screenshot placeholder: PR with the risk-score comment inline.

---

## Pricing section

(Same as docs/LAUNCH-PLAN.md.)

Each tier has a "Get started" button. Free + Indie are
self-serve via Stripe Checkout. Pro+ has a "Talk to us" form.

---

## FAQ section

**Q: What does the score actually mean?**

> 1-3 = low. Specific action, specific resource, read-only.
> Safe to auto-approve. 4-5 = medium. Some wildcard component
> or sensitive service. Worth a human glance. 6-10 = high.
> Wildcard resources, destructive verbs, IAM mutations.
> Always route to a human reviewer.

**Q: Is the scoring deterministic?**

> Yes. Same input → same score, every time. The optional LLM
> contributes narrative + suggestions but cannot change the
> numeric score. This is a safety contract — the LLM cannot
> hallucinate a request into auto-approval.

**Q: Can I self-host?**

> Yes. The OSS CLI is fully functional in offline mode (no
> network call needed). For the API, deploy your own iam-jit
> stack from the source repo on GitHub.

**Q: What about my secrets / credentials?**

> The API receives the IAM policy JSON only. No credentials are
> sent. Policies are processed in memory and never persisted on
> our servers (audit logs record only fingerprints, never the
> policy content itself).

**Q: How do you handle SOC 2 / compliance?**

> SOC 2 Type 1 in progress (target: Q3). Enterprise tier
> includes the audit evidence export.

**Q: How is this different from AWS IAM Access Analyzer?**

> Access Analyzer detects existing misconfigurations in
> deployed resources. iam-risk-score scores POLICIES BEFORE
> THEY DEPLOY — at PR review time, at agent-request time, at
> JIT-grant time. Complementary, not competing.

---

## Footer

- Docs
- Pricing
- Status
- GitHub (open-source CLI)
- Twitter
- LinkedIn
- Privacy / Terms

---

## Notes on the page

- Loading priority: hero + code sample + first CTA above the
  fold on a 1366×768 laptop screen. Everything else lazy-loaded.
- Mobile: code samples must remain readable; use horizontal
  scroll, not text wrap.
- No marketing-speak. Engineers reject "transform your security
  posture" copy on sight. Be concrete.
- Don't show a generic spinner / loading animation in code
  samples. Show the actual terminal output.
- Include real numbers wherever possible: "100ms response time"
  (measured), "30+ calibrated rules" (the actual count), etc.
