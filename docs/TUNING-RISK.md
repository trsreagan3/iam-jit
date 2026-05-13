# Tuning the risk evaluation

iam-jit ships with a deterministic risk scorer calibrated for the
median AWS environment. Your environment is unlikely to be the
median. This doc covers how to tune the scorer for your org —
which knobs exist, how to choose between commit-time and runtime
tuning, and the safety guardrails that prevent foot-guns.

## Two-axis model

There are TWO independent axes of tuning, with different
ownership and different blast radii:

```
              Platform team owns         In-system admin owns
              (commit + redeploy)        (UI / API at runtime)
              ────────────────────       ──────────────────────
  Behavior   • Built-in scorer code      • Threshold (within floor)
             • SAM-param floors          • Quota (within floor)
             • SAM-param defaults        • Account blocklist (must
                                            include floor entries)
                                          • Service blocklist (must
                                            include floor entries)
                                          • Toggles (enable/disable
                                            pre-defined rules)
                                          • Additional sensitive
                                            services / high-impact
                                            actions (admin context)
                                          • Max role duration

  Blast      • Affects every deploy      • Affects every request
   radius      from this template          submitted to THIS deploy

  Persists   • Across deploys           • Until next admin change
                                          (DDB-backed, survives
                                          Lambda cold-starts)

  Authorized • PR review + deploy        • iam-jit admin user
   by          permission                  via UI / API
```

The principle: **runtime can tighten, never loosen below the
deploy-time floor.** Same model as AWS SCPs.

## When to commit (vs UI-edit)

**Commit (PR + redeploy) when:**
- Adding a brand-new scoring rule (e.g., "treat any action ending
  in `:Set*` as high-impact"). That's a code change.
- Changing the floor (e.g., raising `MaxAutoApproveRiskBelow` from
  3 to 5 because your org wants more permissive defaults). PR
  review + deploy is the right gate for changes that affect
  every future runtime decision.
- Setting up the initial context for a new deployment
  (`AutoApproveTogglesJson`, the floor values, etc.).

**UI / admin API when:**
- Reacting to an incident ("disable auto-approve right now").
- Adding an org-specific service to the sensitive set
  ("athena should be sensitive for us").
- Adding a one-off prod account to the blocklist after a new
  account onboards.
- Enabling/disabling a pre-defined toggle ("turn on read-only
  auto-approve in staging for the maintenance window").
- Adjusting the threshold up or down within the floor for
  steady-state operations.

A useful rule of thumb: **if the change should be reverted at the
end of an incident, do it in the UI. If the change should
persist forever, commit it.** UI changes are visible in the audit
log but they're easy to forget about — commits get reviewed.

## The six runtime knobs

Each is editable via PATCH `/api/v1/admin/auto-approve/settings`
or via the corresponding UI section (UI is on the roadmap as of
this writing; the API works today).

### 1. `auto_approve_risk_below`

Integer 1-10 (or null to disable). Requests scoring STRICTLY less
than this auto-approve. `null` = auto-approve is off entirely.

Floor: `MaxAutoApproveRiskBelow` SAM param (default 5). PATCH
with a value above this is refused with HTTP 400.

```bash
# Set auto-approve to fire on scores 1, 2, 3:
curl -X PATCH .../api/v1/admin/auto-approve/settings \
  -d '{"auto_approve_risk_below": 4}'
```

### 2. `auto_approve_quota_per_hour`

Sliding-window cap on auto-approves per user. Composability
attack defense (chained low-risk requests).

Floor: `MaxAutoApproveQuotaPerHour` SAM param (default 10).

### 3. `never_auto_approve_services`

List of service prefixes (e.g., `["iam", "kms"]`) that NEVER
auto-approve regardless of score.

Floor: `RequiredServiceBlocklist` SAM param (default
`iam,organizations,sts,kms,secretsmanager`). Admins can ADD
services, can NEVER remove these built-ins.

### 4. `never_auto_approve_accounts`

List of account IDs that never auto-approve. Typical use: prod
account IDs.

Floor: `RequiredAccountBlocklist` SAM param (default empty).
Set this at deploy for any deployment that manages prod access.

### 5. `additional_sensitive_services`

ADMIN-CURATED EXTENSION of the built-in sensitive-services set
(`iam`, `organizations`, `sts`, `kms`, `secretsmanager`). The
scorer treats any service listed here like a built-in sensitive
service: wildcards score higher, `Resource: "*"` triggers a
warning, etc.

Use this when your org has services that are sensitive in YOUR
context but not in the median. Examples:

  - Analytics-heavy org: add `athena`, `redshift-data`
  - Database-heavy org: add `rds-data`
  - ML platform: add `bedrock`, `sagemaker`

```bash
curl -X PATCH .../api/v1/admin/auto-approve/settings \
  -d '{"additional_sensitive_services": ["athena", "redshift-data"]}'
```

### 6. `additional_high_impact_actions`

Specific actions (`service:Action`) that floor at score 5 even
with a specific resource ARN. Use for actions where a single
narrowly-scoped change can affect production.

```bash
curl -X PATCH .../api/v1/admin/auto-approve/settings \
  -d '{"additional_high_impact_actions": ["dynamodb:UpdateItem", "kinesis:PutRecords"]}'
```

## Log retention (compliance / audit)

CloudWatch Logs retention for the iam-jit Lambda is a tunable
control with the same commit-vs-runtime split as the auto-approve
knobs, but its purpose is **anti-tampering** rather than
permissiveness.

  - **Default 545 days (~1.5 years)** — exceeds PCI DSS (1 year),
    matches SOC 2 / ISO 27001 norms.
  - **SAM param `LogRetentionDays`** sets the actual CloudWatch
    retention at deploy. Default 545. Adjust upward (731, 1827)
    for stricter regulatory regimes.
  - **SAM param `MinLogRetentionDays`** sets the FLOOR. Default
    545. Admins can extend retention beyond the floor at runtime
    but cannot shorten below it.
  - **Runtime API** `GET/PATCH /api/v1/admin/log-retention`
    surfaces the current retention + the floor. PATCH refuses any
    `retention_days` below the floor with HTTP 400.

```bash
# Read current retention + floor
curl .../api/v1/admin/log-retention

# Extend retention to 2 years (still within compliance, just longer
# audit window):
curl -X PATCH .../api/v1/admin/log-retention \
  -d '{"retention_days": 731}'
```

Why a floor: a compromised or malicious admin could otherwise
shorten retention to bury audit trails AFTER doing the damage.
The floor makes this a deploy-time / PR-reviewed decision, not a
runtime one. See `security-notes.md` § E5 for the threat model.

**Persistence stores have a parallel control:** the DynamoDB
tables and S3 state bucket use CloudFormation `DeletionPolicy:
Retain`, so a `cloudformation delete-stack` does NOT delete the
audit data. The retained-on-delete posture and the CloudWatch
retention floor together cover both directions of the
evidence-destruction attack.

## Pre-defined toggles

For complex tuning patterns ("approve all read-only in staging",
"do not auto-approve anything in production"), the platform team
defines toggles at deploy via the `AutoApproveTogglesJson` SAM
parameter, and admins flip them on/off at runtime via the UI/API.

A toggle has:
  - `id`, `name`, `description` (human readable)
  - `condition` (typed match: account_id, access_type, service)
  - `action` (`force_review_if` or `auto_approve_if`)
  - `enabled` (admin-flippable boolean)

Example toggle set:

```json
[
  {
    "id": "no_prod_auto",
    "name": "No auto-approve in production",
    "description": "All prod-account requests go to human review.",
    "enabled": true,
    "condition": {"account_id": "<prod-account-id>"},
    "action": "force_review_if"
  },
  {
    "id": "approve_dev",
    "name": "Auto-approve all in development",
    "description": "Dev sandbox — score-gate bypassed.",
    "enabled": false,
    "condition": {"account_id": "<dev-account-id>"},
    "action": "auto_approve_if"
  },
  {
    "id": "readonly_staging",
    "name": "Auto-approve read-only in staging",
    "description": "Read-only requests against staging skip score gate.",
    "enabled": true,
    "condition": {"account_id": "<staging-account-id>", "access_type": "read-only"},
    "action": "auto_approve_if"
  }
]
```

Admins enable/disable via:

```bash
curl -X PATCH .../api/v1/admin/auto-approve/settings \
  -d '{"preset_toggles": [<full toggle list with `enabled` flipped>]}'
```

(A dedicated `POST /toggles/<id>/enable` endpoint is on the
roadmap to make the UI cleaner.)

**Force-review wins:** if a request matches BOTH a
`force_review_if` AND an `auto_approve_if` toggle, the force-
review wins. Conservative deny-side bias.

**Floors still apply to toggles:** even an enabled
`auto_approve_if` toggle is rejected if the request targets an
account in `never_auto_approve_accounts` (which includes
deploy-time floor entries). The toggle can't override the floor.

## The complete tuning workflow

```
1. Read docs/USE-CASES.md and docs/AGENT-WRITING-ROLES.md to
   understand the baseline calibration.

2. Run a sample of representative requests through /preview to
   see how the baseline scores them. Identify which ones don't
   score the way YOUR org wants them to.

3. For each miscalibration:
     (a) If it's an org-specific service that should be sensitive:
         add to `additional_sensitive_services`.
     (b) If it's a specific action that's high-impact for you:
         add to `additional_high_impact_actions`.
     (c) If it's a structural pattern ("read-only in dev should
         auto-approve"): define a toggle in
         `AutoApproveTogglesJson` and deploy.
     (d) If the baseline scoring of a built-in needs to change:
         that's a code PR to `src/iam_jit/review.py`. Includes
         a test update in `tests/test_review_calibration.py`.

4. After every tuning change: re-run the /preview sample. Check
   that the score moved the way you intended. NO unexpected
   side effects on other requests.

5. Audit log captures every settings change with the admin's
   user_id + diff. Review periodically for drift ("threshold
   quietly raised from 3 to 5").
```

## What the admin CANNOT do (safety invariants)

  - Lower the threshold below the floor: `MaxAutoApproveRiskBelow`
    SAM param is a hard ceiling.
  - Remove a service from the required blocklist: the
    `RequiredServiceBlocklist` SAM param entries are floors.
  - Remove an account from the required blocklist: the
    `RequiredAccountBlocklist` SAM param entries are floors.
  - Disable the per-user quota: `auto_approve_quota_per_hour` has
    a deploy-time max via `MaxAutoApproveQuotaPerHour`.
  - Lower built-in sensitive services / high-impact actions: the
    admin context can only EXPAND, never SHRINK these sets.
  - Bypass the audit log: every settings change emits a
    `admin.auto_approve_settings_updated` event with actor + diff.
  - Shorten log retention below the floor: `MinLogRetentionDays`
    SAM param is a hard ceiling on log-retention shortening.
  - Delete audit data via stack-delete: DDB tables + S3 state
    bucket carry `DeletionPolicy: Retain`, so `cloudformation
    delete-stack` leaves the audit records intact.

The combination of these invariants is the deploy-time floor that
keeps the in-system admin's power bounded.

## Common tuning recipes

### "Auto-approve only the safest reads"

```json
{
  "auto_approve_risk_below": 3,
  "never_auto_approve_services": ["iam", "kms", "secretsmanager", "organizations", "sts", "ssm"],
  "additional_sensitive_services": ["secretsmanager", "kms"],
  "auto_approve_quota_per_hour": 5
}
```

### "Liberal in dev, strict elsewhere"

Combination of a toggle for dev + tight settings overall:

```json
{
  "auto_approve_risk_below": 3,
  "never_auto_approve_accounts": ["<prod>", "<prod-cde>"],
  "preset_toggles": [
    {
      "id": "approve_dev",
      "enabled": true,
      "condition": {"account_id": "<dev-account>"},
      "action": "auto_approve_if"
    }
  ]
}
```

### "Incident mode — disable auto-approve fully"

```bash
curl -X POST .../api/v1/admin/auto-approve/disable
```

OR set the env var `IAM_JIT_AUTO_APPROVE_FORCE_OFF=1` on the
Lambda (faster than waiting for the settings-store TTL to expire;
survives admin actions until the env is changed).

## Auditing tuning changes

Every settings change emits:

```
event: admin.auto_approve_settings_updated
actor: email:admin@your-corp.com
at: 2026-05-11T15:30:00Z
details:
  previous:
    auto_approve_risk_below: 3
    never_auto_approve_services: [iam, kms]
  updated:
    auto_approve_risk_below: 5
    never_auto_approve_services: [iam, kms, athena]
```

Audit events stream to the iam-jit log group in CloudWatch (see
`security-notes.md` § E5 — protected by the
`MinLogRetentionDays` floor). To review settings-change events,
query CloudWatch directly:

```bash
aws logs filter-log-events \
  --log-group-name /aws/lambda/iam-jit \
  --filter-pattern '"admin.auto_approve_settings_updated"' \
  --start-time $(date -u -v-7d +%s)000 \
  --profile <your-profile>
```

A read-only HTTP endpoint for audit events is on the roadmap
(`GET /api/v1/admin/audit`). Until then, CloudWatch is the
canonical query surface. Audit-log review is part of the standard
operational rhythm for high-trust deployments.
