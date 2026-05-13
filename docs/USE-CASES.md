# What iam-jit is for

The most common time-bound-IAM tools target the "human asks for prod
access, human approves" workflow. iam-jit handles that, but the
sharper-edge use case it's built for is different:

**An agent (or a human) needs ONE PIECE of production information,
RIGHT NOW, and the alternative is either (a) waiting for someone with
standing access to do it for them, or (b) granting standing access
they'll keep forever.**

Examples from real workflows:

  - "What's the public IP of `api-prod-1` so I can update a CDN
    origin?" — needs `ec2:DescribeInstances` on one ARN for 1 hour.
  - "Which target group is registered behind the staging ALB?" —
    needs `elasticloadbalancing:DescribeTargetGroups` on one
    LoadBalancer ARN for 30 minutes.
  - "Read `config/feature-flags.json` from the prod config bucket
    to debug a flag." — needs `s3:GetObject` on one key prefix for
    1 hour.
  - "Look up the current DNS A record for `mailgun.example.com` so
    I know what to point a CNAME at." — needs `route53:GetHostedZone`
    + `ListResourceRecordSets` on one zone for 5 minutes.

Each of these requests is small in blast radius, time-bound,
auditable, and revocable. The traditional alternatives — "I'll
Slack you the answer", or "I'll grant you read access for the
quarter" — are worse in both directions: slower than auto-approval
when the request is benign, and broader than necessary when it
isn't.

## The intended workflow

```
Agent (or human)
    │
    │  "I need to know X. Here's the minimal policy that gets me X."
    ▼
iam-jit submission
    │
    │  Deterministic risk score (1-10) + LLM narrative (optional)
    ▼
Auto-approve gate
    ├── Score ≤ threshold AND environment policy allows
    │      → instant grant → caller assumes the role and continues
    │
    └── Otherwise
           → request queues for human review (Slack/email/UI)
           → approver clicks approve → caller assumes
```

The latency asymmetry is the design lever: narrow well-scoped
requests get answered in seconds; broad requests get answered when
a human looks at the queue. Agents (and the people prompting them)
learn that "smaller request = faster grant" without iam-jit ever
having to refuse.

## Auto-approve calibration — concrete examples

The risk model is the policy. Pinning a few representative
examples gives operators a calibration target to aim at when
choosing their `IAM_JIT_AUTO_APPROVE_RISK_BELOW` threshold (see
`ROADMAP.md` § "Auto-approve-under-risk-threshold setting").

| Request | Auto-approve? | Why |
|---|---|---|
| `ec2:DescribeInstances` on one instance ARN in staging, 1h | ✅ | Single read, no mutation, single resource |
| `ec2:DescribeInstances` on `*` in staging, 1h | ❌ | Wildcard resource — broader than necessary |
| `elbv2:DescribeTargetGroups` on one TG ARN in staging or prod, 30min | ✅ | Single read, single resource, short window |
| `s3:GetObject` on one prefix in *staging*, 1h | ✅ | Single read, narrow scope, low-criticality env |
| `s3:GetObject` on one prefix in *prod* config bucket, 1h | ⚠️ borderline | Same shape as above, but prod data — needs human-or-policy override |
| `s3:GetObject` on `arn:aws:s3:::prod-*/*`, 1h | ❌ | Cross-bucket wildcard in prod — broad blast |
| `route53:ChangeResourceRecordSets` (any env) | ❌ | Mutation of DNS — never auto-approve |
| `iam:CreateRole` / `iam:PassRole` (any env) | ❌ | IAM mutation is a privilege-escalation path |
| `secretsmanager:GetSecretValue` on one secret ARN, 15min | ⚠️ | Even single-secret access is sensitive — typically a human gate |
| `kms:Decrypt` on one key ARN, 15min | ⚠️ | Same — depends on the key's role |

The deterministic scorer (`src/iam_jit/review.py`) implements the
"single read with constraints" → low-score path today (verified by
`test_specific_resource_read_scores_low`). The "prod environment as
a risk amplifier" axis is roadmap (`ROADMAP.md` § "Environment-
aware risk dimension"). Until it ships, operators are expected to
EITHER:

  - Keep the auto-approve threshold low enough that prod reads
    drop into human review by default, OR
  - Use the admin context input (also roadmap) to express
    "auto-approve in dev, never auto-approve in prod regardless of
    score" as a deployment-level rule.

## Where this fits in the market

There are several paid IAM-access tools in the human-approval
space (Common Fate, ConductorOne, Sym, Opal, Indent.io, Teleport).
The wedge for iam-jit is **agent-driven access**: built for the
case where an LLM agent is submitting requests, the deterministic
risk score is the policy, and the auto-approve threshold is the
performance lever. The OSS posture + self-hosted-in-your-account
deployment shape also appeals to teams that won't put a vendor in
their IAM path.

## Anti-patterns this tool is NOT for

  - **Standing production access.** iam-jit grants are time-bound
    by construction. If a team needs permanent read on a bucket,
    grant them permanent read — don't add iam-jit as a
    re-requesting interceptor.
  - **Break-glass admin access.** Critical-incident wide-scope
    grants should flow through a separate process iam-jit
    doesn't model: shorter approval path, broader scope, harder
    audit. iam-jit is for narrow, frequent, agent-driven requests.
  - **Replacement for IAM Identity Center.** iam-jit grants
    short-lived per-request roles; Identity Center grants
    longer-lived role-mappings to users. Both can coexist.
