# Evaluator — automated approvals for low-risk requests

> **Status:** design only. Not yet implemented. Planned for after the
> core lifecycle (Phase 2 provisioning + Phase 3 expiry) lands.

## Why

iam-jit is agent-first. The first wave of usage will be *humans approving
agent-submitted requests*: the agent gathers context locally, drafts the
policy, submits, a human glances at the risk review and clicks approve.

That's a step forward, but the human-in-the-loop is still the
bottleneck. Many of the requests that come through this system are
genuinely routine: read-only access to a known bucket in a known
account, for an hour, by a service that requests this exact shape
several times a day. Forcing a human to manually re-approve the same
shape repeatedly trains them to click without reading — the worst
possible outcome.

The **Evaluator** is a separate, opt-in service that closes that loop
for the routine cases while still escalating anything ambiguous or
risky. It is a *gate*, not a *bypass*: every Evaluator decision is
recorded in the same hash-chained audit log as a human decision, every
Evaluator-approved grant carries the same time-bounded expiry, every
admin retains the ability to revoke at any time. The Evaluator does not
make iam-jit *less* safe — it removes friction from the cases where
human review was already approving 100% of the time anyway, freeing the
human to spend attention on the cases that actually need it.

## Design constraints

1. **Off by default.** The Evaluator is a separately deployed component.
   Greenfield iam-jit installations have human-only approval; turning on
   the Evaluator is a deliberate admin action.

2. **Separate process, separate trust boundary.** The Evaluator does not
   share a Lambda, a database, or an IAM role with the user-facing API.
   It calls iam-jit's normal `POST /api/v1/requests/{id}/approve` as an
   API consumer, using its own bearer token. iam-jit treats it as just
   another approver — the bearer token's user record has the `approver`
   role and a special `is_machine: true` flag for audit clarity.

3. **Belt and suspenders.** Even when the Evaluator says "approve":
   - The IAM time-condition self-expiry on the provisioned role still
     fires regardless of whether the cleanup Lambda runs.
   - The Evaluator's confidence threshold has a *deny floor*: below
     that floor it must escalate to human review, never approve.
   - An admin can configure a *maximum auto-approved duration* (e.g.
     8h), beyond which everything escalates regardless of the Evaluator's
     decision.
   - An admin can configure a *maximum auto-approved risk score* (e.g.
     4), above which everything escalates.

4. **Human override is unconditional.** Any auto-approval can be
   force-cancelled by an admin in the UI. Auto-approved active grants
   show a distinct visual treatment so admins can spot-check what the
   Evaluator has been doing.

5. **Auditable.** Every Evaluator decision emits an audit event with:
   - which rule(s) fired
   - the LLM response if one was used (full text, including reasoning)
   - the confidence score
   - the request's risk score and risk factors at decision time
   - the context fingerprints in effect at the time of decision

6. **Reversible.** The Evaluator is stateless. Disabling it stops new
   auto-approvals immediately; previously auto-approved grants continue
   their normal expiry timeline.

## Architecture

```
                           ┌────────────────────────────┐
   request submitted       │  iam-jit (existing)         │
   ──────────────────────► │  POST /api/v1/requests      │
                           │  state=pending              │
                           └───────────────┬─────────────┘
                                           │ webhook OR poll
                                           ▼
                           ┌────────────────────────────┐
                           │  Evaluator                  │
                           │  - rule engine (deterministic)│
                           │  - LLM scorer (optional)    │
                           │  - confidence aggregator    │
                           └───────────────┬─────────────┘
                                           │ approve / reject / pass
                                           ▼
                           ┌────────────────────────────┐
                           │  iam-jit                    │
                           │  POST /requests/{id}/approve│
                           │  state=provisioning         │
                           └────────────────────────────┘
```

The Evaluator is triggered one of two ways. The deployment picks one;
both are equivalent semantically.

- **Webhook mode**: iam-jit emits a `request.submitted` webhook
  (configured via `IAM_JIT_WEBHOOK_URL`). The Evaluator's HTTP endpoint
  receives the request payload and replies async by calling the
  appropriate `/approve` / `/reject` / `/request-changes` endpoint.

- **Poll mode**: the Evaluator runs as a scheduled Lambda or cron job
  that calls `GET /api/v1/requests?state=pending` every N seconds and
  decides on anything new.

## Decision pipeline

A request enters the Evaluator and flows through three stages, each of
which can short-circuit the rest:

### Stage 1 — Hard rules

A YAML config file (mounted at deploy time, identical structure to
`org-context.yaml`, hash-chained into the audit log) declares the rules.
Hard rules are deterministic and never use the LLM. Examples:

```yaml
hard_rules:
  - name: deny-iam-and-org-services
    if: "any service in policy is in [iam, organizations, sts, sso, kms]"
    action: escalate     # always go to human review
    reason: "privileged service — human review required"

  - name: deny-write-on-prod
    if: "access_type == 'read-write' AND target_account in [prod_accounts]"
    action: escalate
    reason: "write on prod requires human approval"

  - name: auto-approve-readonly-known-account-short-duration
    if: >
      access_type == 'read-only' AND
      duration_hours <= 8 AND
      target_account in [known_accounts] AND
      risk_score <= 4
    action: approve
    reason: "matches routine read-only pattern"
```

If a hard rule fires with `action: escalate`, the Evaluator hands off to
the human queue and stops. If a hard rule fires with `action: approve`,
the Evaluator skips the LLM stage and approves with `confidence: 1.0`.

### Stage 2 — LLM evaluator (optional)

If no hard rule matches, and the deployment has the LLM evaluator
enabled, the request is sent to the same LLM backend the rest of
iam-jit uses, with a *separate* system prompt scoped to evaluation:

```
You are evaluating an AWS IAM access request for automated approval.
You may APPROVE, REJECT, or PASS (request human review).

You will be given:
  - the description and submitted policy
  - the deterministic risk score and risk factors
  - this organization's standing context (account purposes, etc.)

You must NOT approve if any of the following are true (regardless of
context). PASS for human review instead:
  - the policy grants any IAM, organizations, sts, sso, or kms action
  - the duration exceeds {max_auto_approved_duration} hours
  - the risk score is greater than {max_auto_approved_risk}
  - the policy uses '*' as Resource on a service that supports ARNs
  - the description is empty, gibberish, or inconsistent with the policy

Respond as strict JSON: {decision, confidence, reason, redactions}.
```

The Evaluator parses the JSON response. Below the configured confidence
threshold (default 0.85), the decision is downgraded to PASS regardless
of what the LLM said.

### Stage 3 — Aggregation + execution

The Evaluator computes a final decision:

- Any `escalate` from Stage 1 → human queue
- `approve` from Stage 1 → call `POST /approve`
- LLM `approve` with `confidence >= threshold` → call `POST /approve`
- LLM `reject` → call `POST /reject` with the LLM's reason
- Anything else → leave it pending for human review

It then emits an audit event:

```json
{
  "kind": "evaluator.decided",
  "actor": "evaluator:default",
  "summary": "approved by hard rule auto-approve-readonly-known-account-short-duration",
  "details": {
    "request_id": "rq-abc123",
    "decision": "approve",
    "stage": "hard_rules",
    "rule_name": "auto-approve-readonly-known-account-short-duration",
    "confidence": 1.0,
    "risk_score": 3,
    "context_fingerprints": {...}
  }
}
```

## What it does NOT do

- **It does not provision.** The Evaluator only approves/rejects. The
  existing iam-jit Lambda still owns provisioning into the destination
  account.
- **It does not replace the human queue.** Anything below threshold,
  anything in services not on the allow-list, anything beyond the
  configured time/risk caps — all still go to humans.
- **It does not learn online.** The Evaluator is stateless and uses
  static configuration plus the LLM's per-request reasoning. Online
  learning is explicitly out of scope: it would create a feedback loop
  where past approvals teach the system to keep approving.
- **It does not bypass the audit chain.** Every decision is recorded in
  the same tamper-evident log as a human decision.

## Configuration sketch

```yaml
# evaluator.yaml — mounted at /etc/iam-jit/evaluator.yaml
enabled: true
mode: poll               # or "webhook"
poll_interval_seconds: 30

# Hard caps — these override anything the LLM says.
max_auto_approved_risk: 4
max_auto_approved_duration_hours: 8
auto_approval_confidence_threshold: 0.85

# Allow-list of accounts whose routine read-only requests can auto-approve.
# Other accounts always go to human review (until added here).
allow_listed_accounts:
  - account_id: "060392206767"
    purpose: "staging dev"
  - account_id: "534625442569"
    purpose: "shared infra/ECR"

# Service allow-list. Anything not here always escalates.
allow_listed_services:
  - s3
  - logs
  - cloudwatch
  - dynamodb
  - kinesis

hard_rules: [...]        # see above
```

## Open questions

These are explicitly *deferred* until after the core lifecycle ships:

- **Per-team evaluators.** Should the Evaluator have a notion of
  "approvers for team X"? Today iam-jit has a single approver pool.
  Solving this likely means generalizing the `users.yaml` schema to
  include team membership, then teaching the Evaluator (and the human
  queue) to route by team. Not blocking for v1 of the Evaluator.
- **Self-improving rules.** Could the system suggest new hard rules
  based on patterns in the human approval log ("you've approved this
  exact shape 47 times, want to auto-approve it going forward?")? Yes,
  probably; designing it well is non-trivial. v1 of the Evaluator ships
  with manual rule authoring only.
- **Multi-Evaluator.** Could a deployment run two Evaluators (e.g. one
  per business unit)? Architecturally trivial — they're just API
  consumers — but operationally messy without team-aware routing.
  Deferred.
- **GCP/Azure.** Out of scope for the Evaluator as a feature; it's an
  orthogonal concern that lives at the iam-jit core layer.

## Implementation milestones

1. Webhook emitter in iam-jit core (Phase 2.5): `IAM_JIT_WEBHOOK_URL`
   env var; signed POST on every state transition. Useful even without
   an Evaluator (Slack notifications, etc.).
2. Evaluator skeleton (`evaluator/` directory, separate package):
   stateless Lambda, takes a request payload + decision config, emits
   an iam-jit API call. No LLM in the first cut — hard rules only.
3. LLM-based scorer (Stage 2): parameterized via the existing
   `IAM_JIT_LLM` backend choice. Reuses the LLM context fingerprints so
   tampering with the evaluator prompt is visible.
4. Admin UI surfacing: a "evaluator decisions" filter on the activity
   report; a distinct visual treatment for auto-approved active grants;
   the existing health banner picks up "evaluator unreachable" as a
   degradation signal.
5. Per-deployment guardrail config in `evaluator.yaml`, hash-chained
   into the audit log just like `org-context.yaml`.
