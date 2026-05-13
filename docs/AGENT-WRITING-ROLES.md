# Writing low-risk role requests

This doc is for agents (and humans) submitting iam-jit requests.
The latency asymmetry between auto-approve and human review is the
design lever — narrow well-scoped requests get answered in seconds;
broad requests wait. Read this once; the patterns it teaches make
every future submission faster.

## The 30-second mental model

iam-jit scores every policy on a 1-10 scale:

  - **1-3 (low)**: typically auto-approves
  - **4-6 (medium)**: usually human review
  - **7-10 (high)**: always human review

The exact threshold is set per-deployment by an admin. Use
`POST /api/v1/requests/preview` to see the current score + the
threshold + the auto-approval verdict for your request, BEFORE you
submit. Iterate until you're under.

## What raises the score

In rough order from worst to mildest:

  1. **`Action: "*"`** (full admin) — score 10, no exception
  2. **`iam:PassRole` on `Resource: "*"`** — privilege escalation, score 9
  3. **Wildcard within a sensitive service**, e.g. `iam:*`,
     `kms:*`, `secretsmanager:*` — score 8-9
  4. **High-impact mutation actions** (DNS, SG ingress, IAM
     policy attach, S3 bucket policy, Lambda code update, etc.)
     — score floors at 5 even on a single resource
  5. **Service wildcard outside sensitive set** (e.g. `s3:*`) on
     specific resource — score 7
  6. **Read-only marked but write actions in policy** — score 8
     (the request is lying about its scope)
  7. **`Resource: "*"`** with non-trivial actions — score 4-6
     depending on services
  8. **Long durations on a non-trivial score** (e.g. score 4
     for 60 days) — `+1` to `+2` adjustment

## What keeps the score low

The opposite of the list above:

  - **Specific resource ARNs.** `arn:aws:s3:::config-bucket/key`
    instead of `arn:aws:s3:::config-bucket/*` or
    `arn:aws:s3:::*`.
  - **Specific actions.** `s3:GetObject` instead of `s3:*`.
  - **Read-only access_type** when you only need to read. The
    scorer treats this as a positive signal AND flags any
    mutation actions inside.
  - **Short durations.** 1 hour is the default; longer durations
    raise medium-risk scores higher.
  - **One service per statement.** Mixing `s3:*` and `ec2:*` in
    one statement looks like enumeration.
  - **`resource_constraints` block** in the request spec —
    explicitly tells the analyzer "yes, this is narrow."

## Canonical low-risk patterns (auto-approves at threshold 4+)

### Pattern 1: Look up one piece of info

```json
{
  "spec": {
    "access_type": "read-only",
    "description": "look up the public IP of api-prod-1 for CDN config",
    "duration": {"duration_hours": 1},
    "accounts": [{"account_id": "111111111111", "regions": ["us-east-1"]}],
    "policy": {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": ["ec2:DescribeInstances"],
        "Resource": "arn:aws:ec2:us-east-1:111111111111:instance/i-0abcdef1234567890"
      }]
    }
  }
}
```

Why low: read-only + single action + single resource ARN + 1h.

### Pattern 2: Read one config file from S3

```json
{
  "spec": {
    "access_type": "read-only",
    "duration": {"duration_hours": 1},
    "policy": {
      "Statement": [{
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": "arn:aws:s3:::team-config/feature-flags.json"
      }]
    }
  }
}
```

Why low: one read, one specific S3 key, no list.

### Pattern 3: Inspect one target group

```json
{
  "spec": {
    "access_type": "read-only",
    "duration": {"duration_hours": 1},
    "policy": {
      "Statement": [{
        "Effect": "Allow",
        "Action": ["elasticloadbalancing:DescribeTargetGroups"],
        "Resource": "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/api-prod-tg/abc123"
      }]
    }
  }
}
```

## Anti-patterns to avoid

### ❌ Service wildcard

```json
{"Action": "s3:*", "Resource": "arn:aws:s3:::config/*"}
```

Even on a specific bucket, `s3:*` includes `DeleteBucket`,
`PutBucketPolicy`, etc. Score: 7+. Replace with the specific
actions you need (`s3:GetObject`, `s3:ListBucket`).

### ❌ Resource wildcard

```json
{"Action": "s3:GetObject", "Resource": "*"}
```

Reads ANY object in ANY bucket. Score: 4-6. Even if you don't
know which bucket yet, scope to a prefix:
`arn:aws:s3:::*/config.json` is narrower than `*`.

### ❌ Read-only mismatch

```json
{
  "spec": {
    "access_type": "read-only",
    "policy": {
      "Statement": [{"Action": "s3:DeleteObject", ...}]
    }
  }
}
```

The request claims read-only but the action mutates state. Score:
8. Either flip access_type to `read-write` (and accept the higher
score), or remove the mutation action.

### ❌ Long duration for routine work

```json
{
  "spec": {"duration": {"duration_hours": 720}}
}
```

30 days is overkill for "look up an IP." 1 hour is the standard.
Use 24h if you genuinely need the session to outlast a normal
context. Beyond that, ask if a permanent role would be more
honest (and submit a separate, longer-term governance request).

## The iteration loop

```
1. Write a candidate policy.
2. POST /api/v1/requests/preview
3. Read the response:
     - review.risk_score        → your current score
     - auto_approve_threshold   → the bar you need to be UNDER
     - would_auto_approve       → true means you're done
     - review.suggestions       → concrete tightenings
     - advice                   → what to change next
4. Apply one of the suggestions. Re-preview.
5. Repeat until would_auto_approve = true. Then submit.
```

Preview calls are rate-limited per user (default 60/min) to
prevent runaway loops; iterate thoughtfully, not in a tight loop.

## What blocks auto-approve even at a low score

Even if your score is below the threshold, the request can still
be routed to human review by:

  - **Service blocklist.** Admin-configured. By default: `iam`,
    `organizations`, `sts`, `kms`, `secretsmanager`. Any action
    touching these → human review regardless of score.
  - **Account blocklist.** Admin-configured. Often: production
    account IDs.
  - **Per-user quota.** Default 5 auto-approves per hour per
    user. The (N+1)th request from the same user inside the
    window forces human review. This is the
    composability-attack defense: a stream of low-risk requests
    that combine to do damage gets caught.
  - **Max duration.** Admin-configured org-wide cap (e.g., "no
    role lasts longer than 60 days"). Submission with
    duration > cap is REJECTED with HTTP 400.

The preview endpoint surfaces ALL of these — its `advice` field
tells you exactly which gate would fire.

## Cheat sheet: what to put in description

The `spec.description` is what a human approver reads when your
request hits review. Make it count:

  - **What you're trying to accomplish** (in human terms — not
    "I need s3:GetObject", but "looking up the feature-flag config
    to debug an outage")
  - **Why you need access yourself** (not "the user asked me to"
    if a less-privileged path exists)
  - **What you'll do with the info** ("paste it into a Slack
    thread", "feed it into the next prompt", "store it in
    memory for the rest of this task")

A good description is the single biggest factor in how quickly a
human approves. If the score is borderline, a clear description
often tips it.

## Quick-reference table

| You want… | Best policy |
|---|---|
| one EC2 instance's IP / SG / state | `ec2:DescribeInstances` on the specific ARN |
| one S3 file's contents | `s3:GetObject` on the specific key |
| list of files in one bucket | `s3:ListBucket` on the specific bucket ARN |
| one secret's value | `secretsmanager:GetSecretValue` on the specific ARN — but this is service-blocked by default, expect human review |
| one DNS zone's records | `route53:ListResourceRecordSets` on the specific zone ARN |
| modify one DNS record | `route53:ChangeResourceRecordSets` — always human review (HIGH_IMPACT_MUTATION) |
| call one Lambda function | `lambda:InvokeFunction` on the specific function ARN |
| run one Athena query | `athena:StartQueryExecution` is flagged as a "deceptive write" — gets medium risk; consider whether you really need it vs read-only S3 access to the result |

## See also

  - `docs/USE-CASES.md` — the "one piece of prod info" framing +
    auto-approve calibration table
  - `docs/security-notes.md` — threat model, including what
    attacks the deterministic scorer is meant to defend against
  - `docs/ROADMAP.md` — coming features: LLM-driven natural-
    language → policy intake, environment-aware risk dimension,
    pattern-similarity gate
