# Roadmap

Tracks features that are sketched but not in the shipped surface. Each
entry has a one-liner motivation so the priority isn't lost.

## v2 — pending

### Continuous role auto-discovery + risk-threshold alerts (self-hosted)

Targets the self-hosted deployment. iam-jit continuously enumerates
IAM roles across connected AWS accounts, scores each one with the
deterministic scorer (+ agent-delegated LLM per
`[[bouncer-zero-llm-when-agent-in-loop]]` when an agent is in the
loop), and emits a notification when a role's score crosses a
user-configured "high risk" threshold.

- **Discovery triggers**: CloudTrail event subscription on
  `CreateRole`, `PutRolePolicy`, `AttachRolePolicy`, `PutUserPolicy`,
  `AttachUserPolicy`, plus a scheduled full-account sweep as a
  backstop (CloudTrail can miss / lag rare event types).
- **Scoring**: same engine as the request-time gate. Effective-policy
  composition (inline + attached + boundary) is re-evaluated end to
  end — the amendment-workflow rule applies: never score deltas, only
  the full effective policy.
- **Threshold config**: per-environment + per-role-prefix, with a
  per-deployment default. Day-1 defaults must NOT be noisy or the
  feature gets muted and adoption dies (same lesson as Snyk's first
  noisy-by-default era).
- **Notification channels**: webhook first (cheapest, most flexible),
  then Slack and email, then PagerDuty / generic SIEM forwarders.
- **Trend history**: score history per role-arn surfaced as a chart
  in the UI. This is the artifact auditors find comfortable — the
  same trust-building shape as the scoring-bands page.
- **Positioning**: turns iam-jit from a request-time gate into a
  continuous posture monitor. Mirrors the Snyk/Semgrep "scan
  everything, alert on regressions" playbook that produced their
  "we run X in CI" market position.
- **Threat-model note**: discovery runs read-only IAM APIs; iam-jit
  never auto-revokes. The notification is the action; humans decide.
  A future enhancement could offer one-click "open a remediation
  ticket" via the same webhook channel, but the destructive step
  stays out of scope.

### EKS / Kubernetes cluster access

Granting time-bound access to a Kubernetes cluster, not just to AWS
IAM. This is meaningfully different from the v1 surface because:

- The grant target is a **Kubernetes RBAC binding**, not an IAM role.
  The IAM role still gates *who can talk to the cluster's API server*
  (via `aws eks get-token` and the cluster's `aws-auth` config), but
  the in-cluster permissions are a separate dimension — namespace,
  verb, resource (pods, deployments, secrets, …).
- iam-jit needs to **provision both halves**: (a) the IAM role that
  authenticates against the EKS control plane and (b) the
  ClusterRoleBinding or RoleBinding that grants the actual k8s
  permissions. The two get torn down together at expiry.
- The destination ProvisionerRole's policy gains `eks:DescribeCluster`
  + an in-cluster service-account whose RBAC permissions are scoped
  to creating/deleting **only** `iam-jit-*`-prefixed RoleBindings in
  pre-approved namespaces.
- For clusters using `aws-auth` configmap (EKS classic), iam-jit
  edits the configmap. For clusters using the newer EKS Access
  Entries API (2024+), it uses `eks:CreateAccessEntry`. The
  destination CFN exposes both shapes; iam-jit picks whichever the
  target cluster is configured for.
- Request UI surfaces: namespace selector + verb-set selector +
  optional resource pin (e.g., "logs on pods in `payments-staging`
  for 4 hours, no `exec`").
- Audit + revocation: same model as IAM grants — the binding gets a
  `managed-by=iam-jit` label, an `expires-at` annotation, and the
  scheduled sweep deletes both halves.
- Threat-model note: a Kubernetes binding doesn't have AWS's
  `DateLessThan` IAM condition equivalent, so the time-bound is
  enforced by the sweep deleting the binding — **not** by k8s
  refusing the action after expiry. Sweep latency = effective
  blast-radius extension. Document this.

Suggested early scope: read-only `get`/`list`/`watch` on a single
namespace, no `exec` / `port-forward` / `proxy`. That's 80% of
real-world "give me k8s access" asks and matches the read-only-
first default already in v1.

### Auto-approve-under-risk-threshold setting

A single deployment-level knob: "auto-approve any request whose
risk score is ≤ N." Simpler / faster ship than the full Evaluator
(below) — same end-user outcome for the cheapest case ("this
read-only s3 GET for 4 hours scored a 2, just let it through")
without needing the policy-as-code surface.

Sketch:

- New env var / SAM parameter `IAM_JIT_AUTO_APPROVE_RISK_BELOW`,
  default unset (= manual approval required). Set to e.g. `3` to
  auto-approve everything ≤ 3.
- Optional companion: `IAM_JIT_AUTO_APPROVE_REQUIRES` allowlist of
  states the request must additionally satisfy: `read-only`,
  `duration ≤ 24h`, `account in allowlist`, etc. Without the
  allowlist a low score alone wins; with it, all conditions must
  hold.
- Submission path: after `_build_review_block` computes the score,
  if the setting is set and the score qualifies, the route
  transitions `pending → approved → provisioning` in one shot using
  a `system:auto-approver` actor in the audit chain. The history
  event makes the auto-approval explicit and queryable.
- Audit + UI: requests auto-approved this way carry a
  `status.review.auto_approved: true` flag and a
  `status.review.auto_approved_reason: "score=2, policy auto-approve-below-3"`.
  Dashboard renders these with a distinct badge so a reviewer can
  spot them in retrospect.
- Safety hatches:
  - Self-submission still flows through approval — auto-approver
    never bypasses the "approvers can't approve their own request"
    rule (this rule will be lifted for auto-approval since there's
    no human-approver self-trust issue, but admins can still flip
    `IAM_JIT_AUTO_APPROVE_SELF=false` if they want a four-eyes
    invariant).
  - High-confidence prompt-injection bans still block the route
    BEFORE the score is even computed.
  - A "panic switch" admin endpoint `/api/v1/admin/auto-approve/disable`
    flips the in-memory flag to off without redeploying, for fast
    incident response.

This is essentially the "minimum-viable Evaluator" — same effect, no
policy-as-code engine to maintain. Most deployments would never need
more than this.

**Required guards that ship with auto-approve** (composability
attack — see `docs/security-notes.md` § E3):

  - **Per-user auto-approve quota** — sliding-window cap (default
    5 auto-approves per hour per user). Exceeding the cap forces
    human review on subsequent requests regardless of score.
    Reuses `iam_jit/rate_limit.py` with a new `kind="auto-approve"`.
  - **Pattern-similarity gate** — two consecutive low-risk
    requests from the same user with near-identical policy shapes
    (same service+access-level+duration, varying resource ARN) →
    route to human review. Catches enumeration chains.
  - **Aggregate scope budget** — track cumulative resource scope
    of the user's not-yet-expired auto-approvals. Union beyond
    threshold → force human review.
  - **Cool-down on sensitive services** — once any
    `secretsmanager:`, `kms:`, `iam:` request has been auto-
    approved in the last hour, subsequent requests in the same
    service-family bypass auto-approve.

Tests REQUIRED before auto-approve can be enabled in production:

  - A sequence of N+1 auto-approve-eligible requests from one
    user must see the (N+1)th routed to human review even though
    it scores low (the per-user quota guard).
  - Two near-identical-shape requests within 60 seconds must
    force the second to human review (the similarity gate).
  - A request that would push the user's aggregate scope past
    the budget must route to human review.

### Environment-aware risk dimension

The deterministic scorer in `src/iam_jit/review.py` is policy-only:
two requests with identical policies score identically whether the
target is a dev sandbox or a production-critical account. The
operator's mental model says they should differ — reading a single
config file from `prod-config` is meaningfully riskier than the
same read against `dev-scratch`.

Add an `environment` axis to each registered destination account:

  - SAM parameter: `AccountEnvironments` — JSON mapping like
    `{"518710148615": "dev", "750487550314": "prod"}`. Or
    per-account via the existing `accounts` admin API: each
    registration carries `environment: "dev" | "staging" | "prod"`.
  - Risk amplifier in `_deterministic`: read-only on dev → no
    change; same shape on prod → +1 to +2 score depending on
    sensitivity of the read.
  - Make the amplifier configurable so each org can express its
    own dev-vs-prod policy.

Companion roadmap entry: **admin-configurable risk-context input**
(below).

### Admin-configurable risk context

A deployment-level rule set the admin can set without redeploying:

  - "Auto-approve all requests against accounts tagged
    `environment=dev`."
  - "Never auto-approve in `environment=prod` regardless of score."
  - "Auto-approve `service in {ec2, elbv2}` reads in any env, score ≤ 4."
  - "Never auto-approve `service in {iam, secretsmanager, kms,
    organizations}` regardless of env or score."

Stored in a small `risk_context` DynamoDB table (admin-editable
via UI + API). Evaluated at submission time alongside the
deterministic score. Combines with the auto-approve threshold:
a request that scores below threshold AND passes the context
rules auto-approves; either failing → human review.

The use-cases doc (`docs/USE-CASES.md`) has the calibration table
operators should aim at. The risk-context rule set is how they
*encode* their aim without touching code.

**Design intent — least-privilege incentive for agents.** The
auto-approve feature is not just a convenience knob; it's the
primary tool for shifting agent behavior toward least-privilege
requests. The dynamic to engineer:

  - Agents that request narrow, well-scoped permissions
    (`s3:GetObject` on one bucket prefix for 1 hour) score low and
    sail through to auto-approval. The agent gets unblocked in
    seconds.
  - Agents that request wide permissions (`s3:*` on `*` for 24h)
    score high and stop at human approval. The agent waits.

That latency asymmetry — instant vs minutes-to-hours — is what
makes the right behavior cheaper to do. Agents (and the humans
prompting them) learn that "smaller request = faster grant"
without iam-jit ever having to refuse. The system shapes the
behavior by making the desirable path the path of least resistance.

Implementation implications:

  - The risk scoring model is the policy. It's worth investing in
    making the scoring legible to agents: when an agent's request
    gets scored 4 (over the auto-approve threshold), the response
    body should explain WHY — which action was the high-impact one,
    which scope was too broad, what a lower-score version of the
    same request looks like. The agent can then re-submit narrower.
  - The auto-approve threshold itself should be operator-visible
    so agents (with read access to settings) can fetch it and aim
    just under. That's not a leak — knowing the score that earns
    auto-approval doesn't tell an attacker anything they couldn't
    learn by submitting requests and observing the verdict.
  - The audit chain MUST capture "this request was auto-approved
    because score=2 < threshold=3" so a periodic human review can
    catch threshold drift (someone bumped the threshold to 5 and
    now risky stuff is sailing through) before it becomes an
    incident.

### Resource-ARN blocklist (auto-reject)

A separate, narrower control than `never_auto_approve_services`:
admin-curated list of **specific ARNs** that no request may target.
A submission whose `policy.Statement[].Resource` matches any
blocklisted ARN is **automatically rejected at evaluation time** —
not routed to a human, not auto-approved, refused outright with a
clear reason.

Use cases:

  - **Production database / secret ARNs.** Even a "read-only"
    request for `secretsmanager:GetSecretValue` against the prod
    creds secret is a no-go; the blocklist refuses it without an
    approver ever seeing it.
  - **Break-glass roles.** Specific IAM role ARNs (the
    "incident-response-root" role) that iam-jit must never
    sub-issue access to.
  - **Compliance-tagged resources.** PII data buckets, audit log
    buckets, CDE-tagged DynamoDB tables.
  - **Other iam-jit infrastructure.** iam-jit's own DDB tables,
    state bucket, and IAM roles should be in every deployment's
    default blocklist — auto-refusing any request for access to
    iam-jit's own substrate prevents privilege escalation.

Surface:

  - SAM param `RequiredArnBlocklist` (CommaDelimitedList): floor.
    Every entry MUST be in runtime `never_target_arns`; admins
    can ADD, never remove these floor entries.
  - Settings field `never_target_arns: list[str]` (runtime PATCH
    via `/api/v1/admin/auto-approve/settings`).
  - Matching: exact-string OR ARN-prefix-glob (`arn:aws:s3:::prod-*`).
    Matching is conservative — wildcards in the requested policy
    match the wildcards in the blocklist via set-intersection so
    requests like `Resource: "*"` always match (covers everything).
  - Auto-reject lands the request in a NEW state `rejected_by_policy`
    (distinct from human `rejected` — the latter has a human
    approver as actor; the former is system-driven). The audit
    log captures the matched ARN(s) for the reviewer to see WHY.
  - Submit response surfaces the matched ARNs + the policy
    document line that requested them, so the requester can fix
    the policy and re-submit.

Threat-model fit:

  - Closes a gap in the current model: today an admin who lowers
    the threshold or empties `never_auto_approve_services` can
    auto-approve broad-access requests. Resource-ARN blocklist
    operates AT the deterministic-evaluator step (before
    threshold compare) and AT the deploy-time floor — neither
    the in-system admin nor the auto-approver bypasses it.
  - Complements (not replaces) the existing controls:
    `never_auto_approve_services` blocks at the service level;
    this blocks at the specific-resource level. Both can be
    floored at deploy time.

Implementation notes:

  - The matching logic belongs in `auto_approve.evaluate()`
    (alongside the existing service/account blocklist checks).
  - The `_deterministic` scorer in `review.py` should ALSO
    surface a high score (>=8) for any request that names a
    blocklisted ARN, so the `/preview` endpoint can warn an
    iterating user before they submit.
  - Tests must cover: exact match, prefix wildcard, request
    wildcard intersection, multi-ARN policy where only one ARN
    is blocked, floor-vs-runtime semantics.

### Four-eyes admin changes

Today an iam-jit admin can create another admin / approver and use
that puppet user to approve their own requests, bypassing the
"approvers can't approve their own requests" rule. The audit log
records the sequence, but nothing prevents it. See
`docs/security-notes.md` § E2 for the attack walk-through.

Fixes, in increasing strictness:

  1. **Audit alerts on suspicious sequences.** Scheduled job
     scans the audit log for `user-create within 5min of
     magic-link-issued within 1h of approve(by=that-user)` and
     posts to the on-call channel. Buys time for human review
     to catch the puppet before grant completes.

  2. **Approver cooldown.** A new approver's first N approvals
     require co-sign by a pre-existing approver. The puppet
     can't immediately grant anything; the audit alert in (1)
     has time to fire.

  3. **Two-stage admin role grants.** `POST /api/v1/users` and
     `PATCH /api/v1/users/{id}` that grant `admin` or `approver`
     create a `pending_grant` record. The role isn't effective
     until a *second* admin confirms via
     `POST /api/v1/admin/pending-grants/{id}/confirm`. Bootstrap
     edge case: the very first admin (seeded by
     `AdminBootstrapEmail`) is exempt because there's no other
     admin to confirm.

  4. **Email-domain pinning.** SAM parameter
     `AllowedUserEmailDomains` listing the domains user records
     can have. Refuses any `POST /api/v1/users` with email
     outside the list. Closes the path where an admin uses
     `puppet@disposable.com` to receive the magic-link.

(1) is cheap and ships standalone; (2) and (3) compose; (4) is a
separate dimension. Recommended ship order: (1) → (3) → (4) →
deprecate (2) once (3) is universally adopted.

### Role inspection + low-friction revision

The realistic developer flow is: request a role → discover halfway
through a task that the permissions don't actually match the work →
need to revise. The first role generated will frequently be wrong;
this can't turn into dozens of back-and-forth iterations or developers
will route around the system.

Two missing pieces:

  1. **Role JSON viewer.** A developer should be able to open any of
     their own requests (pending, approved, active, expired) and see
     the canonical request YAML AND the rendered IAM policy. Today
     they can see a summary; they can't easily inspect the policy
     document that's actually being attached / will be attached.
     Surface it as both a UI tab on the request detail page and a
     `GET /api/v1/requests/{id}/policy` JSON endpoint.

  2. **In-place revision flow.** Instead of "cancel and re-submit",
     allow a developer to clone a request into a *draft revision*
     pre-filled from the original. They edit the policy / services /
     description, submit, and the approver sees a diff against the
     prior version with the original linked. Approving the revision
     either (a) re-provisions the same role with the new policy
     attached, or (b) provisions a fresh role and revokes the old one
     — pick the simpler option per provisioning mode.

     Hard requirements:
       - Revisions inherit the original's risk score baseline; if the
         new policy expands scope, the diff is flagged as
         "expanded-scope" and demands a full re-review.
       - A revision that *narrows* scope (drops actions, tightens
         resources) can be auto-approved if the original was already
         approved + the auto-approve threshold (above) is in scope.
       - Revisions are capped at N iterations per request (config,
         default 3) so a single ambiguous request doesn't generate
         an unbounded chain. Beyond the cap, the developer files a
         new request.

This pair (view + revise) collapses the "wrong policy → cancel →
re-explain → re-submit → re-approve" loop into "view → edit → diff →
approve". For approvers it surfaces *why* the policy changed instead
of leaving them to guess from a fresh summary.

### Evaluator service

(Already documented in `EVALUATOR.md`.) Automated approver for
routine low-risk grants — policy-as-code that decides yes/no based on
risk score + service allowlist + duration + account, with humans
still in the loop for anything ambiguous. The auto-approve-threshold
setting above is a strict subset of this; the Evaluator is the
generalization (multi-condition rules, deny-list, time-of-day
windows, per-team policies).

### Scorer evolution path — past human-review parity

Full thesis in `docs/EVOLVING-THE-SCORER.md`. The aim: over time,
the deterministic scorer (plus eventual learned residual) becomes
**more reliable than human reviewers** on the routine 80% of IAM
requests, freeing humans for the genuinely novel 20%.

Phased plan, each phase preserves the safety invariants (floors,
deterministic baseline, audit trail):

**Phase 1 — calibration scaffolding (shipped today)**
  - Score recorded on every request (`status.review.risk_score`).
  - Audit events `request.auto_approved` /
    `request.auto_approve_skipped` capture scorer verdicts with
    full detail.
  - `GET /api/v1/admin/calibration` returns scorer-vs-human
    disagreement statistics + early-revoke outcome signals.
  - Settings fingerprint (`context_fingerprints`) on every score
    so historic decisions are reproducible.

**Phase 2 — outcome correlation**
  - Wire CloudTrail to detect "grant never assumed" (no
    `AssumeRole` event in the grant's lifetime). Add the signal to
    the calibration report.
  - Schedule a weekly digest email to admins summarizing
    disagreement deltas and flagged decisions.
  - Manual-tagging UI for "this grant was cited in incident X" so
    the strongest outcome signal can be captured.

**Phase 3 — suggested-tuning generator**
  - The calibration report doesn't just describe the
    disagreement — it suggests specific
    `additional_sensitive_services` / `additional_high_impact_actions`
    additions and shows the historical decision deltas if those
    changes had been applied.
  - "Try this calibration" mode: apply the suggested change to a
    shadow scorer that runs in parallel, compare outcomes before
    promoting the change to the live scorer.

**Phase 4 — learned residual model**
  - A small ML model trained on (features → outcome) pairs that
    learns the patterns NOT captured by deterministic rules.
  - Always shadow-scored against the deterministic baseline.
  - Can ONLY raise the score, never lower it (preserves the
    deterministic floor).
  - Promoted to influence the decision only after explicit admin
    review of N weeks of shadow-scoring data with documented
    rationale (audit-logged).
  - Model artifact + training data fingerprint captured with
    every decision, so audit traceability survives model swaps.

**Phase 5 — pattern detector across requests**
  - Cross-request analysis: this user has requested 12 different
    s3 reads in the last week, each individually low-risk. The
    aggregate is a different shape.
  - Org-level anomaly flags: this service is being requested 10x
    more than last quarter, attention warranted.
  - These flags raise the score on the NEXT matching request
    rather than retroactively changing past decisions.

Safety invariants the path MUST preserve across every phase:

  - The deterministic baseline always runs and can never be
    short-circuited by a learned model — the floor is the same
    rules-driven score iam-jit ships with on day one.
  - Floors (`MaxAutoApproveRiskBelow`, `RequiredServiceBlocklist`,
    `RequiredAccountBlocklist`) constrain every scorer layer.
  - Every decision records WHICH version of the scorer made it,
    so model upgrades don't erase historical traceability.
  - Humans-in-the-loop for genuinely privileged grants (IAM, KMS,
    organizations, anything matching the resource-ARN blocklist)
    regardless of what the scorer says.

The destination: scorer handles routine cases as well as or
better than humans; humans focus on cases where the scorer flags
uncertainty or where structural rules require human judgment.
Better than human reviewers, with the safety net of human
reviewers when it matters.

## Validated as of v1 ship

Everything in the F1–F35 implementation log. See `docs/security-notes.md`
for the threat-model coverage and `tests/` for the pinned behavior.

## Known caveats — not regressions, just things we did NOT build

- **No native source-IP restriction on Function URLs.** AWS doesn't
  support `aws:SourceIp` on Lambda Function URLs. iam-jit's CIDR
  allowlist is application-layer (`IAM_JIT_ALLOWED_SOURCE_CIDRS`).
  For deeper network isolation, deploy CloudFront + WAF in front and
  rely on the Lambda's XFF parsing.
- **No SCIM / IdP-pushed user provisioning.** Users get added either
  through the bootstrap admin or via `/api/v1/users`. An IdP integration
  (Okta SCIM, etc.) is a reasonable v2 add but isn't in scope today.
- **No automatic rollback on partial provisioning.** If `create_role`
  succeeds but `put_role_policy` fails, the bare role stays in AWS
  with the iam-jit tags. The rediscovery sweep + force-delete
  endpoint cleans this up; we don't auto-rollback because typical
  failures are transient and operator visibility is more valuable
  than a hidden retry.
- **DynamoDB tables are deleted on stack delete.** The audit log is
  the source of truth for compliance retention — copy it to a
  long-term bucket before tear-down. `docs/TEARDOWN.md` covers this.
