# iam-jit security notes

This is the running threat model + a record of what's been hardened.
Read alongside `infrastructure/sam/template.yaml` (deploy-time
guardrails) and `src/iam_jit/prompt_injection.py` (runtime detection).

## Threat model

iam-jit's job is to provision time-bound IAM roles in cross-account
AWS environments. The blast radius of a compromise is "an attacker
gets the IAM permissions a successful submission could be approved
for." That makes the human-approver step the *primary* defense and
everything else defense-in-depth.

### Trust boundaries

- **End user** (requester) → **iam-jit hub Lambda**: end users can
  only submit requests. Their submissions are reviewed by an approver
  before any AWS API call is made on their behalf.
- **iam-jit hub Lambda** → **destination account ProvisionerRole**:
  cross-account assume with ExternalId. The destination account's
  ProvisionerRole policy is the second-line scope limit (path prefix
  `/iam-jit/`, name pattern `iam-jit-grant-*`).
- **Destination account IAM admin** → **iam-jit hub**: NOT a trust
  boundary. An admin in a destination account can already do anything
  iam-jit can do; spoofing iam-jit-tagged roles in their own account
  buys them nothing.

## Attack vectors considered + status

### A. Prompt injection (direct)

Attack: user types text designed to coerce the LLM into emitting
permissive policies, fake tool calls, or self-approving JSON.

Defenses:
- Regex-based detection in `prompt_injection.py` (high + medium
  signals). High → 403 + immediate ban; medium → 400 refuse, no ban.
- Detection runs on every chat POST + `/api/v1/intake/turn`.
- LLM output NEVER provisions directly — every policy is rendered
  back to a human approver who must explicitly approve.
- Approvers cannot self-approve their own requests.

### B. Prompt injection (indirect via stored fields)

Attack: user plants malicious text in `description`, `ticket`,
`requester.name`, or `metadata.name`, knowing those fields flow into
the review block, the approved-request memory store, or the agent's
serialized response.

Defenses:
- Submission-time scan of all four free-form fields (see
  `routes/requests.py:_scan_submission_for_injection`).
- Same ban/reject contract as direct injection.

Open: org-context.yaml is admin-uploaded — an admin can poison the
LLM's grounding. This is documented as in-trust-boundary; admins are
trusted not to attack themselves.

### C. Provisioning bypass

Attack: user submits a request, gets it approved, then edits the
spec mid-flight (TOCTOU) to swap in a different policy after approval
but before provisioning.

Defenses:
- Edits are only allowed in `pending` and `needs_changes` states.
  After approve transitions state to `provisioning`, edits are
  refused.
- Approve handler immediately calls `provision()` synchronously —
  there's no window between transition and AWS API call for an
  outside actor to interpose.

### D. Role-deletion abuse

Attack: someone tricks iam-jit into deleting roles it didn't create
(e.g. a sensitive service role in the destination account).

Defenses:
- `validate_role_for_cleanup` requires BOTH the iam-jit-grant name
  pattern AND the `managed-by=iam-jit` tag.
- IAM path prefix `/iam-jit/` further scopes IAM:DeleteRole at the
  destination ProvisionerRole's policy layer.
- A privileged actor in the destination account *could* fabricate a
  role that satisfies both checks. That's documented as
  in-trust-boundary; iam-jit's safety gate prevents accidents, not a
  privileged adversary.

### E. Admin-role abuse

Attack: a banned admin's session is used to inject; the system
refuses to ban them (correctly), but they could continue.

Defenses:
- Self-unban is refused — even with admin privileges, an admin
  cannot lift their own ban; another admin must do it. This forces
  second-pair-of-eyes on reinstatement.
- Force-cancel is the only state-machine action admins can take from
  any non-terminal state, and it lands the request in `cancelled`,
  which is fully audited.

### E2. Admin self-escalation via puppet approver

Attack: an admin creates a new user, grants them the `approver` role
(or `admin`), signs in as that user via magic-link, then has the
puppet user approve the admin's own access request. The
"approvers cannot approve their own requests" rule in
`lifecycle.py:_check_authorized` checks `actor.id == owner.id`, which
this attack satisfies — the puppet is a distinct user.

Specifically achievable today:
- Step 1: admin posts `POST /api/v1/users {"id": "email:puppet@admin-controlled.com", "roles": ["approver"]}`
- Step 2: admin signs in as the puppet via `/login` → magic-link
  delivered to email. If the admin can read mail at
  `puppet@admin-controlled.com` (any domain — there's no email-domain
  pinning), they obtain the puppet's session.
- Step 3: admin submits a request; puppet approves it. Audit trail
  shows requester=admin, approver=puppet — both legitimate users,
  the self-approve rule is satisfied at the technical level.

Defenses TODAY (deterrent, not prevention):
- Both events emit audit-log entries. The sequence
  `users.create(puppet) → auth.magic_link.issued(puppet) →
  requests.approve(by=puppet, request_owner=admin)` is highly
  unusual and pattern-detectable in retrospect.
- The bootstrap-admin email is fixed at deploy via the NoEcho
  `AdminBootstrapEmail` parameter. A new admin can be added but
  the first one's identity is anchored to the CFN deploy event.
- `is_owner` checks `request.metadata.owner_id` — there's no way
  to forge the owner because the route stamps it from the
  authenticated session, not the request body.

Defenses MISSING (roadmap):
- Four-eyes admin changes. `POST /api/v1/users` and
  `PATCH /api/v1/users/{id}` that grant `admin` or `approver` role
  should require a *second* admin to confirm before the role is
  effective. Stored as a two-stage `pending_grant` → `active`
  transition with both admin user_ids audited.
- Email-domain pinning. SAM param `AllowedUserEmailDomains` —
  list of domains user records can have. Refuses any
  `POST /api/v1/users` with an email outside the list. Closes the
  "admin uses `puppet@admin-controlled-throwaway-domain.com`" path.
- Audit alerts. A scheduled job that scans the audit log for
  sequences matching `user-create within 5min of magic-link-issued
  for that user within 1h of approve(by=that-user)` and emits an
  alert (Slack, email, on-call).
- Approver-cooldown. A new approver's first N approvals require
  co-sign from a pre-existing approver. Buys time for the audit
  alert to fire before the puppet can grant anything.

This attack vector is the primary reason iam-jit is intended to be
**provisioned by an infrastructure / platform team but operated by
an IT or security team** — separation of who deploys the system
from who administers it inside the system limits which one party
can mount this attack alone. Document this division of
responsibility in your runbook.

### E3. Composability — chained low-risk requests

Attack: an agent (or human) submits a series of individually low-
risk grants, each cleanly auto-approved at the configured risk
threshold, that COMBINE to do something high-risk.

Examples:

  - **Exfiltration by enumeration.** Agent gets per-file `s3:GetObject`
    grants on `arn:aws:s3:::vault/key-1.json`, `key-2.json`,
    `key-3.json` … each scored low (single-resource read). Over
    N requests the agent has effectively pulled the whole bucket.

  - **Reconnaissance**. `ec2:DescribeInstances` on i-A, then on
    i-B, then on i-C, etc. — each a tiny read, collectively a
    network map.

  - **IAM enumeration**. `iam:GetRolePolicy` on role-1, then
    role-2, etc. — each ostensibly fine, together a full IAM
    map (privilege-escalation reconnaissance).

  - **Multi-secret read**. `secretsmanager:GetSecretValue` on
    secret-A, secret-B, secret-C — if the risk model treats each
    single-secret read as borderline-low, the chain reads all
    secrets.

The deterministic scorer evaluates requests in isolation. It has
no concept of "this user just made 4 similar requests in the
last 10 minutes." Without auto-approve enabled today, every
request hits human review — composability is bounded by approver
attention. The moment auto-approve ships, this becomes a real
attack vector.

Defenses TODAY (none — auto-approve isn't shipped):
- Every request requires human approval; an alert reviewer can
  notice a pattern across requests and refuse.
- Audit log captures every grant; a periodic review can detect
  exfiltration in retrospect.

Defenses MISSING (roadmap — must ship with auto-approve):

  1. **Per-user auto-approve quota.** Cap auto-approvals per
     user per sliding window (e.g., 5 in 1h). Exceeded → force
     human review on subsequent requests regardless of score.
     Cheap to implement using the existing `rate_limit` module.

  2. **Pattern-similarity gate.** Two consecutive requests where
     the policy shapes are near-identical (same service, same
     access level, same duration, different resource ARNs) →
     force human review. Catches enumeration-style chains.

  3. **Aggregate-scope budget.** Track cumulative scope of the
     user's auto-approved-and-not-yet-expired grants. If the
     union grows beyond a threshold, force human review.
     Higher-order than per-request scoring; harder to game.

  4. **Cool-down on sensitive services.** Once a user has had
     one auto-approval involving e.g. `secretsmanager:` in the
     last hour, subsequent `secretsmanager:` requests bypass
     auto-approve. Service-scoped variant of (1).

Tests must verify (1) before auto-approve ships: a sequence of
N+1 auto-approve-eligible requests from one user must see the
(N+1)th routed to human review even though it scores low. See
`docs/ROADMAP.md § Auto-approve-under-risk-threshold setting`
for the planned guard set.

### E4. Attacks introduced by auto-approve + preview + settings

The auto-approve feature set adds three new surfaces. Each was
audited for novel attack vectors:

**E4a. /preview DoS.**

Attack: a malicious user (or buggy script) hammers `/api/v1/requests/preview`
in a tight loop. The endpoint runs the deterministic scorer (cheap),
optionally an LLM narrative (expensive, when wired up), and reads
the settings store. Tight-loop usage could:
  - Exhaust Lambda concurrency for legitimate callers
  - Run up the LLM bill (anthropic / bedrock) post-roadmap
  - Push DDB read units (settings store + cidr store) past a
    burst

Defense: per-user rate limit on `/preview` with `kind="preview"`,
using the existing rate_limit module. The (N+1)th call in the
window returns HTTP 429 with `Retry-After`. Defaults to the same
SOFT_CAP as chat. Tunable via `IAM_JIT_CHAT_RATE_SOFT_CAP` (sharing
the env var is intentional — preview is a chat-like interactive
flow).

Tested by: `tests/test_request_preview.py` exercises the endpoint
across multiple calls; the rate limit itself is verified by the
shared rate_limit tests.

**E4b. Settings tampering.**

Attack: an admin (or a session-stealer who acquired admin
privileges) loosens the auto-approve settings to e.g. threshold=10
+ empty service blocklist + max_quota=999, then submits a series
of broad requests that all auto-approve.

Defenses:
  - Setting updates are admin-only (`require_admin` dep).
  - Every settings change emits an audit event with the actor's
    user_id, the previous settings, and the new settings (diff).
    A periodic review can detect "threshold quietly raised from
    3 to 10" before damage propagates.
  - The `IAM_JIT_AUTO_APPROVE_FORCE_OFF=1` env-var panic switch
    bypasses the settings store entirely. Operators with shell
    access (the platform team that deployed iam-jit, NOT the
    in-system admin) can flip this without touching iam-jit's
    state, providing a hard cutoff that no in-system actor can
    undo.
  - The puppet-admin escalation path (§E2) still applies —
    settings tampering by a puppet admin is no easier than
    puppet-driven approval was before settings existed.

**E4c. max_role_duration bypass.**

Attack: a request crafts a `spec.duration` block that the schema
validator accepts but the duration-cap check misses (e.g.,
fractional hours, scientific notation, embedded units).

Defense: the cap check explicitly handles `int | float` and the
schema's `duration.duration_hours` field is typed `number`. The
check is `req_duration > max_duration` — straightforward numeric
comparison. The reverse-engineered request-validator (`schema.py`)
rejects non-numeric strings before the cap check runs.

Tested by: `tests/test_request_preview.py::test_max_role_duration_caps_submissions`.

**E4d. Preview-to-submit divergence.**

Attack: the preview endpoint reports `would_auto_approve=True`,
the user submits, the submit endpoint scores DIFFERENTLY and the
request routes to human review (or worse, scores LOWER and bypasses
a check the preview applied).

Defense: both endpoints call the same `review.analyze_policy` and
`auto_approve.evaluate` functions, with identical inputs derived
from the same payload-stamping logic. The preview uses an
*independent* InMemoryRateLimiter to simulate quota without
mutating real state, but every other input is shared. A divergence
test is on the roadmap (compare preview vs submit verdict for the
same payload).

**E4e. Quota laundering via /preview.**

Attack: a user hits the per-user quota cap. They want one more
auto-approval. They submit via /preview, see `over_quota` in the
response... and what they want is for /preview to NOT count
against the real quota (so they can keep iterating). The current
implementation INTENTIONALLY uses a separate simulation limiter
in /preview — preview calls don't burn the real quota. Is this a
laundering risk?

Analysis: NO. The simulation limiter in /preview only affects the
preview's verdict; the real quota only counts SUBMITTED requests
that auto-approved. A user can preview infinitely but only
auto-approve N times per hour. This matches the design intent:
"iterating is free; submitting consumes quota."

The risk would be: a user batches up N+1 candidates via /preview,
sees they all qualify, then submits them all at once. Only N
auto-approve; the (N+1)th hits the real quota. Still bounded.
Verified by `test_preview_does_not_advance_quota`.

**E4f. Threshold gaming by score-manipulation.**

Attack: a user crafts policies whose deterministic score reliably
lands just below the threshold (e.g. score=2 when threshold=3).
They iterate via /preview until they find one that auto-approves,
then submit that variant — even though their original intent was
broader.

This is by design: it's what the latency-asymmetry incentive is
SUPPOSED to do — push agents toward narrower requests. The
"attack" is the engineering of low-score policies, and the
mitigation is the calibration of the scorer + the threshold the
admin sets.

Where this becomes a real attack: the composability case (§E3) —
N narrow requests that combine to broad access. The per-user
quota guard is the defense; alarms on suspicious patterns are
roadmap.

### F. Open redirect on `return_to`

Attack: attacker crafts a magic-link with `return_to=https://evil.com`
to phish credentials post-login.

Defenses:
- `_safe_return_to` in `routes/web.py` allows only paths in a
  fixed allowlist of iam-jit surfaces. Anything else (schemes,
  protocol-relative URLs, javascript:) maps to `/`.
- Validation runs at both the chat-redirect-to-login step AND at the
  magic-callback step.

### G. Public deploy footgun

Attack: deployer accidentally creates a Function URL with `local`
auth and no network restriction → anyone on the internet can POST to
the magic-link endpoint and probe email addresses.

Defenses:
- SAM `Parameters` add `AllowPublicNetworkExposure` (default `false`)
  + `CorsAllowedOrigins` (no wildcard allowed).
- CFN `Rules` block deploys where opt-in is true but CORS is wildcard
  or empty.
- Template Description carries the warning explicitly.
- Recommended posture: `AuthMode=aws_iam` so AWS validates SigV4 at
  the Function URL layer.

### H. Audit-log tampering

Attack: an attacker with write access to the audit-log file or DDB
table edits, deletes, or reorders entries to cover their tracks.

Defenses (F9 work):
- Hash chain across events with monotonic seq numbers.
- External checkpoint anchors detect truncation.
- `verify_chain` returns `(ok, first_bad, reason)` so detection is
  precise.

### I. Token / credential leakage

Attack: API token reused after the user's role was downgraded.

Defenses:
- Tokens are user-scoped. The user record's roles are checked at
  middleware time on every authenticated request, not stored in the
  token. Downgrading a user's role takes effect on the next request.

### J. Resource exhaustion / cost DoS

Attack: a logged-in user spams the chat endpoint to burn LLM cost.

Status: NOT YET ADDRESSED in code. Mitigations to add later:
- Per-user token-bucket rate limit on `/requests/new/chat`.
- Per-user throttle on `/login` (SES bill protection).

### K. CSRF on web POST endpoints

Status: PARTIAL.
- Session cookie is `SameSite=lax`, which mitigates classic
  cross-site form POST attacks.
- iam-jit-served pages are same-origin only; no third-party iframe.
- Explicit CSRF tokens NOT YET implemented.

### E5. Evidence destruction — admin shortens audit window

A malicious or compromised iam-jit admin grants themselves
elevated access (or approves a peer's), uses it for damage, then
shortens CloudWatch Logs retention so the evidence ages out
before discovery. Mirror-image attack: stack-delete the iam-jit
deployment so the audit data goes with it.

Status: MITIGATED.

  - **Retention floor.** `MinLogRetentionDays` SAM parameter
    (default 545 days = ~1.5 years) sets a hard floor that the
    runtime API refuses to go below. Shortening below the floor
    requires a redeploy with platform-team PR review, not a
    runtime API call.
  - **Audit emission on every retention change.** PATCH
    `/api/v1/admin/log-retention` emits an
    `admin.log_retention_updated` event with actor + previous +
    new values BEFORE applying the change to CloudWatch. Even if
    the change reduces what's preserved, the change-event itself
    survives in the audit stream.
  - **Scoped IAM permission + explicit Deny.** The Lambda's
    `logs:PutRetentionPolicy` grant is scoped to its OWN log
    group ARN. The policy ALSO carries explicit Deny statements
    against (a) all `logs:Delete*` actions on `*` (the policy
    grants no Allow for these, but the Deny defends against
    future template edits accidentally widening the grant), and
    (b) `logs:PutRetentionPolicy` via `NotResource` on any log
    group OTHER than iam-jit's. Explicit Deny overrides any
    Allow, so a compromised admin can never shorten retention on
    foreign log groups via this endpoint.
  - **Handler-side log-group validation.**
    `log_retention.set_retention()` refuses to call CloudWatch
    if the supplied `log_group_name` doesn't match the floor's
    configured name. Belt-and-suspenders on top of the IAM
    boundary. Tested at `tests/test_log_retention.py`.
  - **Data stores survive stack-delete.** DynamoDB tables and the
    S3 state bucket carry `DeletionPolicy: Retain`. Running
    `cloudformation delete-stack` removes the compute layer
    (Lambda, ALB, IAM role) but does NOT delete the audit data.
    The retained-on-delete posture means even the "burn it all
    down" version of the attack leaves the evidence intact.
  - **Recommended floor for regulated environments:** raise
    `MinLogRetentionDays` to 731 (~2y) for SOC 2 / ISO 27001,
    or 1827 (~5y) for financial-services worst case.

Residual risk: a deployer with root CFN access can lower the
floor by redeploying. That's gated by your PR review process and
is the intended boundary — the FLOOR is meant to constrain
in-system admins, not the platform team that owns deploys.

## Operational invariants the template can't enforce

These are invariants the deployer must hold separately:

- A real `MagicLinkSecret` (generated from `openssl rand -hex 32`).
  The template makes this a NoEcho parameter but doesn't reject empty
  values.
- DynamoDB point-in-time recovery on `RequestsTable`, `UsersTable`,
  and `ApiTokensTable` for production.
- VPN / IAP / WAF in front of the Function URL when AuthMode=local.
- Periodic review of `/api/v1/admin/bans` for false positives.
- Periodic review of `/api/v1/admin/rediscover` to catch orphan or
  stale roles before they age into noise.

## Reporting a vulnerability

Open a GitHub issue with the `security` label, OR email the address
in the README. Do not include exploitation details in the public
issue; the maintainers will set up a private channel for the writeup.
