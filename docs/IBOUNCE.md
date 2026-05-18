# ibounce

> **Renamed in v1.0 (2026-05-17).** What used to be `iam-jit-bouncer`
> is now `ibounce` — the canonical name across the Bounce family
> (ibounce + kbounce + future). The `iam-jit-bouncer` console
> script keeps working in v1.0 (prints a deprecation warning + forwards
> to the same entrypoint); it's removed in v1.1. See [docs/UPGRADING.md](UPGRADING.md)
> for the migration note.

Local proxy that gates every AWS API call against rules. Defense-in-depth
over IAM role scoping — when the boundary the JIT role draws is correct
but the call TARGET was wrong (prompt injection, agent misstep, typo on
a destructive call), ibounce catches it.

## What ships in v1.0

The bouncer is feature-complete for v1.0. The HTTP proxy that
originally was Stage 2 work landed in pre-launch and is the
default enforcement surface today. Below is the full v1.0 shape.

### CLI + audit foundation

- **Rule management** (`ibounce rules add|list|remove`)
- **Per-task scopes** (`ibounce tasks start|active|end|review`)
  for declaring narrow allow/deny rules for one specific job
- **Dry-run decision evaluator** (`ibounce decide`)
- **Audit chain** (`ibounce logs tail` + per-task review +
  per-pause review) — SQLite-backed local-only
- **Admin-action OCSF events** (#278) — every config change
  (`profile install`, profile hot-swap, `rules add/remove`,
  `pause start/stop`, `presets apply`, `tasks end`) emits a distinct
  OCSF v1.1.0 class 6003 event with `unmapped.iam_jit.event_type ==
  "ADMIN_ACTION"` so security teams can answer "who changed what,
  when" from the audit-export stream. Same wire shape as kbounce +
  dbounce. See [QUERYING-AUDIT-LOGS.md](QUERYING-AUDIT-LOGS.md#admin-actions-who-changed-what-when).
- **Compatibility allowlist** (`iam-jit allowlist`) for per-account /
  per-workload overrides

### HTTP proxy (`ibounce run`)

Localhost-only aiohttp server that intercepts AWS SDK traffic via
`AWS_ENDPOINT_URL=http://127.0.0.1:8767`. SigV4-preserving — the
proxy never re-signs, never holds credentials, never phones home.

Two modes (user picks, configurable per-deployment):
- **COOPERATIVE** (default): every call is parsed + logged but
  forwarded regardless of verdict (advisory)
- **TRANSPARENT**: DENY verdicts return 403 to the SDK client
  (enforcing); ALLOW verdicts forward unchanged

`/healthz` liveness endpoint returns status + mode + active profile +
decisions count + active pause window if any. Bypasses audit log.

### Environment profiles

Named, switchable rule layers that act as a HARD FLOOR above task
scopes + global rules. Default-shipped: **`full-user`** (passthrough,
default-active) and **`safe-default`** (AWS readonly admin baseline
minus sensitive reads — see "What safe-default does + does not cover"
below). Activate with `--profile NAME` on `ibounce run` OR
`export IAM_JIT_BOUNCER_PROFILE=safe-default` in your shell rc.
Profile precedence (cross-product, both ibounce + kbounce): explicit
`--profile` flag → `IAM_JIT_BOUNCER_PROFILE` / `KBOUNCER_PROFILE`
env var → built-in `full-user` default. When `ibounce run` is invoked
without `--profile`, it prints a one-line banner pointing operators
at `--profile safe-default` as the recommended state-preservation
opt-in.

Other community profiles (`dev-only`, `staging-work`,
`incident-response`) ship as YAML files under
`tools/community-profiles/` (future home:
`trsreagan3/bounce-profiles`); install with
`ibounce profile install --from URL`.

Profile fields: `deny_keywords` (with word_boundary matching +
per-profile exceptions list), `keyword_targets`, `only_account_ids`,
`deny_verbs`, `allow_rules` (profile-scoped ALLOW rules that merge
into the rule engine when this profile is active), `allow_baseline`
(named structural allow-set — `aws_managed_readonly_access` resolves
via `policy_sentry` to AWS's Read+List action classifications),
`deny_actions` (exact-match `service:Action` strings denied even if
they're in the baseline — the "subtract" half of readonly-admin-minus),
`deny_actions_with_condition` (resource-pattern + tag-based subtract
list), `source` (org URL when installed via `profile install --from
URL`; read-only at the CLI surface when non-local).

### Profile distribution (`profile install --from URL`)

HTTPS-only fetch of org-curated profile bundles. The
[enterprise-profile-distribution](../README.md#enterprise-profile-distribution)
shape: IT teams publish a curated profiles.yaml; engineers run
`ibounce profile install --from <URL>` on day 1; installed
profiles record their fetch URL in the `source` field, making them
READ-ONLY at the CLI surface (engineers cannot edit org guardrails
to bypass them).

Security:
- HTTPS-only (refuses `http://`)
- Optional `--sha256 <hex>` pin for integrity (IT should ship the
  hash in onboarding docs)
- `source` field forced to the fetch URL even if payload tries to
  spoof `source: local`
- All-or-nothing install: validates every profile in the bundle
  BEFORE writing any

### Recommender + `--save-as-profile`

(`ibounce recommend [--save-as-profile [NAME]]`) — synthesizes
a draft ruleset from observed decisions; with `--save-as-profile`
the recommendations are written as that profile's `allow_rules` so
future `--profile NAME` activates them. Merges on re-run (deduped
on pattern+arn+region).

**Profile naming.** The `NAME` argument is optional (#226). When
omitted on an interactive terminal, you're prompted with a
suggested default (e.g. `auto-2026-05-17-s3-ec2-readonly`). In
non-interactive contexts (CI, MCP-tool calls, scripts), the
suggested name is used automatically + printed to stderr.
Format: `auto-{YYYY-MM-DD}-{top-1-2-services}-{shape}` where
`shape` is `readonly` if every recommendation is a Read action,
else `session`. Collisions are avoided via a `-2`/`-3` suffix.
Per-profile `source` field stays `local` — auto-named profiles
are normal local profiles (editable, deletable). Org-distributed
profiles (installed via `profile install --from URL`) never get
auto-named — their names come from the bundle.

The same auto-naming applies to `ibounce prompts answer ID --kind
profile --target` — `--target` alone (no NAME) auto-generates from
the prompt's service+action as
`auto-{YYYY-MM-DD}-prompt-{ID}-{service}-{action}`.

### Timed pause (`bouncer pause --for 30m`)

Operator-controlled escape hatch. Demotes TRANSPARENT to
COOPERATIVE for a window; auto-reverts at expiry; every decision
inside the window is audit-linked to the pause id. Subcommands:
`start --for DURATION [--reason]`, `stop`, `status`, `history`.
Capped at 24h (longer is an "I don't want the proxy" signal, not
a pause — stop the daemon instead). Pauses surface on `/healthz`
so monitors can flag overnight-left-open windows.

### Async deny prompts (`bouncer prompts`)

When the proxy is run with `--prompt-on-deny`, every transparent-
mode DENY also enqueues a `pending_prompts` row. Operator sees the
queue with `bouncer prompts list`, inspects with `prompts show ID`,
and answers with `prompts answer ID --kind always|profile|ignore`:
- `always` → adds a global ALLOW rule for the exact
  service:action[+arn]
- `profile --target NAME` → appends a `ProfileAllowRule` to the
  named local profile (refuses if profile is org-distributed)
- `ignore` → marks answered, no rule change

v1.0 is ASYNC — agent gets denied immediately; answer takes effect
on the next call of the same shape. SYNC mode (proxy briefly waits
for an answer) is post-launch v1.1.

### MCP server tools

Full agent-discoverable API for everything above; see
[docs/AGENTS.md](AGENTS.md) for the canonical agent flow. Agents
that call `iam_jit_scope_self_for_task` before touching AWS get
scoped credentials + an audit log. Agents that bypass the MCP
composer go through the HTTP proxy instead.

### Security-team observation preset (`--preset security-observe`)

A single-flag shortcut for the canonical "security-team gathering
data" deployment shape. Designed for the starting position the
security team takes BEFORE deciding which agent calls to gate (per
`docs/SECURITY-TEAM-AUDIT-EXPORT.md` + `[[bouncer-mode-selection-
for-agents]]`).

```
ibounce run --preset security-observe
```

is equivalent to the explicit flag bundle:

```
ibounce run \
  --mode transparent \
  --default-policy allow \
  --audit-log-path ~/.iam-jit/audit/ibounce.jsonl \
  --alert-rules defaults \
  --heartbeat-interval 30
```

What each setting buys you:

| Setting | Why |
|---|---|
| `--mode transparent` | Observe + audit; do not enforce rules the team has not yet authored. |
| `--default-policy allow` | Transparent observation; do not surprise the operator with denies. |
| `--audit-log-path <default>` | Per-product JSONL stream the security team can ship to a SIEM. |
| `--alert-rules defaults` | Surfaces the six built-in deterministic alerts (admin_fallback_burst, pause_long, non_org_profile_install, unusual_high_risk_action, heartbeat_gap, audit_export_degraded) on top of the audit stream. |
| `--heartbeat-interval 30` | Liveness signal so the SIEM detects when the proxy is killed/silenced. |

**Override semantics** (per `[[cross-product-agent-parity]]`):

- **HARD overrides** (preset value cannot be overridden — passing a
  different value errors with "drop the preset OR drop the explicit
  flag"):
  - `--mode` (the entire point of `security-observe` is transparent)
- **SOFT overrides** (operator's value wins; preset value is the
  default-only):
  - `--audit-log-path` (operators have different SIEM destinations)
  - `--alert-rules` (operators may layer a custom YAML over the
    built-in defaults)
  - `--heartbeat-interval` (tune to your SIEM's absence-window)
  - `--default-policy` (a security team that wants default-deny
    from day 1 overrides this)

**What the preset does NOT set** (operator wires explicitly):

- `--audit-webhook-url` + `--audit-webhook-token` (different SIEM
  endpoint per deployment; set via flag, env var
  `IAM_JIT_BOUNCER_AUDIT_WEBHOOK_TOKEN`, or `ibounce config import`)

**Startup banner** announces the preset + every derived setting so
the operator sees exactly what changed:

```
ibounce proxy starting on http://127.0.0.1:8767 (mode=transparent, default-policy=allow, profile=full-user)
deployment preset: security-observe
  --mode = 'transparent' (from preset; hard)
  --audit-log-path = '/Users/<you>/.iam-jit/audit/ibounce.jsonl' (from preset; soft)
  --alert-rules-path = '' (from preset; soft)
  --heartbeat-interval-seconds = 30 (from preset; soft)
  --default-policy = 'allow' (from preset; soft)
```

See `docs/DEPLOYMENT-PRESETS.md` for the preset framework + the
roadmap (`dev-loop`, `production-strict`, `compliance-audit`).

## What's coming in v1.1

- **Synchronous deny prompts** — proxy briefly waits for an
  operator answer before returning; for now, async prompts cover
  the "I want to know what my agent hit" use case
- **HTTPS/MITM TLS handling** for proxied AWS endpoints behind a
  TLS-required proxy chain
- **Plan-capture proxy** for IaC (terraform / pulumi) workflows

## Enterprise add-ons (post-v1.1)

Multi-machine fleet rules, web UI, anomaly detection, live action
tail with CloudTrail.

## Why a local proxy

Two distinct reasons; both load-bearing.

### Reason 1 — Defense-in-depth over IAM-scoped roles

IAM is coarse. A role granted `s3:GetObject` on bucket `my-data` can
call `GetObject` on every key in `my-data` for the role's session
lifetime — even if the prompt-injected agent meant to read one
specific file and instead loops over the entire bucket.

The bouncer adds an in-process question: **is THIS specific call
allowed right now?** It runs on your laptop, against your local AWS
creds, with no iam-jit-the-company involvement.

Per creates-never-mutates: the bouncer never modifies IAM. It
inspects + forwards + denies — that's the entire surface.

### Reason 2 — Gating when you can't (or shouldn't) touch IAM rapidly

Even if your company gives you full IAM authority, IAM has structural
limits the bouncer doesn't. And many developers don't have full IAM
authority at all.

- **Rapid iteration.** Bouncer rule changes take effect on the next
  request — local file edit + reload, no API call. IAM has propagation
  delays (seconds to minutes for some changes; longer for policy
  attachments + STS session refreshes) and rate limits if you iterate
  fast. When you're narrowing scope as you discover a new dangerous
  call, the bouncer keeps up; IAM doesn't.
- **You don't need IAM-write permission.** Many companies have SecOps
  own IAM and won't grant `iam:CreateRole` / `iam:PutRolePolicy` to
  individual engineers, or only via tickets that take days. The
  bouncer runs entirely on YOUR laptop using your existing
  credentials; it adds gating without needing any new IAM authority.
  You can be productive with ibounce even when your company
  doesn't let you touch IAM.
- **Local context in rules.** Bouncer rules can reference your
  codebase context (`deny anything in the prod-* cluster`, `allow
  only the staging account`) without coordinating with a central IAM
  policy. Per-task scopes (`bouncer tasks start ...`) are declared in
  seconds, used for one job, then ended.
- **Easy to disable when something breaks.** Need to unblock yourself
  fast at 2 AM? `ibounce tasks end <id>` or stop the proxy.
  No central ticket, no SecOps escalation. The bouncer is yours to
  flip on and off.

This makes the bouncer the natural fit for developers at companies
with locked-down IAM, contractors operating under read-only-by-
default credentials, anyone doing rapid iteration where IAM
propagation would slow them down, and anyone who wants a kill-switch
they personally control.

The two reasons compose: when you have IAM authority, run both
layers (narrow the role AND gate calls against task scope). When you
don't, the bouncer is what you have — and it's often enough on its
own.

## Architecture

```
boto3 / aws-cli / agent
        |
        v                       (AWS_ENDPOINT_URL=http://127.0.0.1:8767)
http://127.0.0.1:8767  <-- ibounce (Stage 2 HTTP proxy)
        |                            |
        |                            +--> rule matcher (Stage 1, this slice)
        |                            +--> SQLite audit log (Stage 1, this slice)
        v
   real AWS endpoint
   (SigV4 signature still valid — bouncer doesn't re-sign)
```

The SigV4 signature is the load-bearing piece: the bouncer never
re-signs requests. AWS still authenticates against the customer's
own creds at the other end. The bouncer is purely a denial layer
that lives between the SDK and the network.

## Modes

| Mode | Behavior | When to use |
|---|---|---|
| `learn` | Records every call. Always allows. | Default on first install. Run normally for a few days; then review captured calls and convert to rules. |
| `enforce` | Applies rules. Unmatched calls → `default_policy` (allow/deny). | Production mode after you've built your ruleset. |
| `prompt` | Applies rules. Unmatched → interactive prompt. | High-touch developer mode for handling one-off calls without writing rules upfront. (Prompt UX in Stage 2.) |

Per safety-mode-lean-permissive: `learn` is intentionally the
default. Block-happy tools get uninstalled. The bouncer's first
action on a fresh install should never be "interrupt your workflow."

## Rule shape

A rule is a `(pattern, effect, scope)` triple:

- **pattern**: `service:action_glob` — e.g. `s3:GetObject`, `s3:Put*`, `iam:Delete*`
- **effect**: `allow` or `deny`
- **arn_scope** (optional): ARN-glob — e.g. `arn:aws:s3:::my-bucket/*`
- **region_scope** (optional): region-glob — e.g. `us-east-1`, `us-*`
- **note** (optional): human label for why this rule exists

### Evaluation order

Within a ruleset:

1. **Any matching DENY rule** wins (explicit deny beats allow — mirrors AWS IAM and the iam-jit blacklist module).
2. **Else, first matching ALLOW rule** wins.
3. **Else, no match** — caller (decision module) falls back to mode default.

When an environment profile is active, profile checks fire BEFORE
the ruleset (see "Environment profiles" below). A profile DENY is
a hard floor and cannot be overridden by an ALLOW rule or a task
scope.

## Environment profiles

An **environment profile** is a named, switchable layer of
hard-floor rules that activate at proxy start time. Profiles
exist so a developer with broad IAM credentials can confidently
work on staging while the proxy blocks anything that looks like
production — no IAM change required, no SecOps ticket, just
`--profile staging-work`.

A profile can:

- Block ARNs / resource names containing specific keywords
  (`prod`, `production`, `live`, `customer-data`, etc.)
- Lock the proxy to one or more AWS account IDs
- Block whole verb classes (`*:Delete*`, `*:Put*`, etc.)
- Carry per-profile exceptions for known false-positive names
  (e.g. `eng-productivity-tooling`)

**Composition with other rules:** profile checks run BEFORE the
rule engine and BEFORE the active task scope. A profile DENY
short-circuits with `decision_source: profile` in the audit log,
so post-hoc review can distinguish profile-fired denies from
task-fired or global-fired denies. A permissive ALLOW rule
cannot override a profile deny — that's the load-bearing
property SecOps needs to approve installs in locked-down envs.

### Built-in profiles (v1.0)

| Profile | What it blocks |
|---|---|
| `full-user` (default-active) | Nothing — pure rule-engine behavior (the passthrough) |
| `safe-default` | AWS readonly admin baseline minus sensitive reads. See "What safe-default covers + does not cover" below. |

The default-active profile is `full-user` — calls forwarded as-is +
audit-logged. Operators opt into the state-preservation safety floor
by running `ibounce run --profile safe-default` OR
`export IAM_JIT_BOUNCER_PROFILE=safe-default` in their shell rc.

#### What `safe-default` covers + does NOT cover

`safe-default` is a state-preservation profile, NOT a confidentiality
boundary. The shape:

- **BASELINE**: allow everything `policy_sentry` classifies as Read or
  List access level. This matches the AWS managed `ReadOnlyAccess`
  policy by construction and automatically inherits new-service
  coverage as `policy_sentry` updates. The Opus AWS-side audit
  (2026-05-17) found that the previous enumerated-deny-verb model
  missed CRIT primitives — `sts:AssumeRole`, `lambda:InvokeFunction`,
  `ssm:SendCommand`, `iam:PassRole`, `iam:Attach*Policy`,
  `ec2:Authorize*`, `cloudformation:ExecuteChangeSet`,
  `route53:ChangeResourceRecordSets`, `kms:ScheduleKeyDeletion`, and
  many more — because their names don't start with
  `Delete`/`Put`/`Update`/`Create`/`Terminate`/`Stop`/`Reboot`. Under
  the new baseline model, those actions are denied by construction
  because they're classified as Write or Permissions-management
  (NOT in the Read+List set).
- **SUBTRACT**: a small list of sensitive Read actions —
  `kms:Decrypt`, `secretsmanager:GetSecretValue`, `ssm:GetParameter*`
  (may return `SecureString`), `ec2:GetPasswordData`,
  `ec2:GetConsoleScreenshot`, `cognito-idp:AdminGetUser`/
  `AdminListGroupsForUser` — plus resource-pattern conditional denies
  (e.g. `dynamodb:Scan` against `secrets-*` tables).

**WHAT IT COVERS:** state-changing AWS operations (writes, privilege
grants, credential minting, code execution, exfiltration verbs) +
the curated sensitive-Read subtract list.

**WHAT IT DOES NOT COVER:** this is NOT a confidentiality boundary.
The baseline allows reads of S3 objects, RDS data, CloudWatch logs,
IAM user metadata, etc. Pair with:
- S3 bucket policies / KMS grants for data confidentiality
- AWS-side IAM Condition keys for tag-based denial (the ibounce
  `tag/<key>` condition in `deny_actions_with_condition` is
  best-effort because the proxy boundary does not always surface
  resource tags)
- Resource-pattern denies in your own profiles for project-specific
  carve-outs (e.g. `arn:aws:s3:::company-private-*`)

### Backward-compat aliases (deprecated)

The pre-reshape names `none` (was the passthrough), `prod-readonly`
(was the v1.0-alpha write-block), and `readonly` (was the
v1.0-alpha-2 post-47b616a rename of `prod-readonly`) keep working in
v1.0 — `none` resolves to `full-user`; `prod-readonly` + `readonly`
both resolve to the new `safe-default` profile. Each emits a one-line
stderr deprecation banner on use. All three aliases are removed in
v1.1.

### Community profiles

The opinionated profiles that used to ship as built-ins (`dev-only`,
`staging-work`, `incident-response`) now live in
`tools/community-profiles/` (future home: the standalone
`trsreagan3/bounce-profiles` cross-product bundle). Install one
with:

```bash
ibounce profile install --from https://example.com/path/to/staging-work.yaml
```

Write the built-in `full-user` + `safe-default` defaults to disk with
`ibounce profile install-defaults`. The file lives at
`~/.iam-jit/bouncer/profiles.yaml` and can be edited freely — add
your own profiles, override the defaults, or extend the
`exceptions` list when a legitimate ARN trips the keyword check.

### Activating a profile

Three ways, in priority order:

1. **CLI flag** (wins): `ibounce run --profile safe-default`
2. **Env var**: `IAM_JIT_BOUNCER_PROFILE=safe-default ibounce run` (the
   env-var name stays `IAM_JIT_BOUNCER_PROFILE` in v1.0 — no
   `IBOUNCE_PROFILE` alias is added; env-var alignment with the
   `ibounce` CLI name happens in v1.1 alongside removal of the
   deprecation shim). The same name is also recognized cross-product
   by kbounce as `KBOUNCER_PROFILE`.
3. **Default**: `full-user` profile (passthrough) — existing rule
   behavior unchanged. `ibounce run` without `--profile` prints a
   banner pointing the operator at `--profile safe-default` as the
   recommended state-preservation opt-in.

A typo in `--profile` (unknown name) is a hard error — the proxy
refuses to start. Silent fallback to `full-user` would disable a
guardrail you thought you'd enabled.

### Profile YAML shape

```yaml
profiles:
  staging-work:
    description: "Working on staging; block anything that looks like prod"
    deny_keywords: ["prod", "production", "live", "customer-data", "uat"]
    keyword_targets: ["arn", "resource_name"]
    keyword_match: "word_boundary"     # vs "substring"
    only_account_ids: ["111122223333"]
    exceptions:
      - "eng-productivity-tooling"     # known false-positive
  safe-default:
    description: "AWS readonly admin baseline minus sensitive reads"
    allow_baseline: "aws_managed_readonly_access"  # policy_sentry Read+List
    deny_actions:
      - kms:Decrypt
      - secretsmanager:GetSecretValue
      - ssm:GetParameter
    deny_actions_with_condition:
      - action: s3:GetObject
        condition: { tag/sensitive: "true" }
      - action: dynamodb:Scan
        condition: { resource_pattern: "arn:aws:dynamodb:*:*:table/secrets-*" }
```

`word_boundary` (the default) matches a keyword only at a
separator edge: `prod-bucket` matches, `productivity` does not.
This drastically reduces false positives. `substring` mode
matches anywhere and is stricter — use when you want zero
chance of a `prod-*` resource slipping through.

### Honest limitations

- **Bypass-able by renaming.** An attacker who creates
  `myapp-customer-stuff-2026` instead of `prod-customer-stuff-2026`
  evades the keyword filter. Profiles are defense-in-depth, not
  the primary security boundary. The `only_account_ids` lock is
  the structured boundary; keywords are the human-friendly 80%
  layer on top.
- **No agent-controlled switching.** Agents can READ which
  profile is active via MCP (`bouncer_active_profile`) but
  cannot change it. Profile switching is a human/admin action.
- **Profiles do not replace per-task scopes.** A profile sets
  the OUTER envelope; the task scope can narrow further within it.

Service prefix comparison is case-insensitive on the request side
(AWS canonical prefixes are lowercase like `s3`, `ec2`, `iam`).
Action and ARN globs are case-sensitive (AWS action names are
PascalCase and must match exactly).

## CLI usage

### Initialize

```bash
ibounce init
# bouncer initialized at: ~/.iam-jit/bouncer/state.db
# current rules: 0
# current decisions: 0
```

### Manage rules

```bash
# Allow S3 GetObject on a specific bucket
ibounce rules add 's3:Get*' \
    --arn 'arn:aws:s3:::my-data/*' \
    --region us-east-1 \
    --note 'dev read access'

# Deny all IAM writes (admin guardrail)
ibounce rules add 'iam:Delete*' --effect deny
ibounce rules add 'iam:Put*'    --effect deny
ibounce rules add 'iam:Create*' --effect deny

# List
ibounce rules list
#    1  allow  s3:Get*  [arn=arn:aws:s3:::my-data/*, region=us-east-1]  # dev read access
#    2   deny  iam:Delete*
#    3   deny  iam:Put*
#    4   deny  iam:Create*

# Remove by id
ibounce rules remove 2
```

### Dry-run decisions

Before flipping to `enforce`, sanity-check what your rules would do:

```bash
ibounce decide --service s3 --action GetObject \
    --arn arn:aws:s3:::my-data/file.txt --region us-east-1
# decision: allow
# reason:   explicit-allow rule
# rule:     allow s3:Get*

ibounce decide --service iam --action DeleteRole
# decision: deny
# reason:   explicit-deny rule
# rule:     deny iam:Delete*

ibounce decide --service ec2 --action DescribeInstances
# decision: deny
# reason:   enforce-mode unmatched (default-deny)
```

### Inspect raw HTTP requests

Useful for debugging the request parser:

```bash
ibounce inspect \
    --method GET \
    --host s3.amazonaws.com \
    --path /my-bucket/file.txt \
    --header 'Authorization: AWS4-HMAC-SHA256 Credential=KEY/20260517/us-east-1/s3/aws4_request, ...'
# {
#   "service": "s3",
#   "action": "GetObject",
#   "region": "us-east-1",
#   "resource_hint": "arn:aws:s3:::my-bucket/file.txt",
#   ...
# }
```

### Audit log

```bash
ibounce logs tail
ibounce logs tail --decision deny --limit 20
ibounce logs tail --json
```

### Pause (timed escape hatch)

```bash
ibounce pause start --for 30m --reason "incident response"
ibounce pause status
ibounce pause stop                 # end early
ibounce pause history --limit 20
```

During a pause, TRANSPARENT mode is demoted to COOPERATIVE — the
proxy still parses every call + logs the verdict, but DENY no
longer 403s the client. Auto-reverts at the duration's expiry.
Every decision inside the window carries `pause_id` in the audit
log so `logs tail --pause-id N` (post-launch) can replay exactly
what happened during the window. Caps at 24h.

### Prompts (async deny notifications)

When running the proxy with `--prompt-on-deny`, transparent-mode
DENYs are also enqueued for later operator review:

```bash
ibounce run --mode transparent --default-policy deny \
    --prompt-on-deny
```

In another terminal:

```bash
ibounce prompts list                       # pending
ibounce prompts show 7
ibounce prompts answer 7 --kind always     # add global ALLOW
ibounce prompts answer 7 --kind profile \
    --target dev-session                            # add to a profile
ibounce prompts answer 7 --kind ignore     # mark answered
```

The agent has already been denied by the time the prompt appears;
the answer's rule takes effect on the NEXT call of the same shape.
The synchronous flow (proxy briefly waits for an operator answer
before returning) ships in v1.1.

## Storage

SQLite at `~/.iam-jit/bouncer/state.db` (override with
`IAM_JIT_BOUNCER_DB`). Directory created with mode `0o700` per
no-hosted-saas + local-only-safety-mode precedent.

Schema versioned via `schema_version` table; additive migrations
only (no Alembic, no ORM). Current schema: `rules` + `decisions`.

## Config export / import

`ibounce config export | import` round-trips the operator's full
config surface as a single redacted JSON file so you can back up
before a risky change, migrate a hand-tuned config across machines, or
feed a diff into change-management review without scraping `state.db`
by hand.

```
ibounce config export --out PATH [--redact-secrets] [--include-audit] [--include-prompts]
ibounce config import --in PATH [--merge | --replace] [--dry-run]
```

### What ships in the bundle

`schemas/ibounce-config.schema.json` is the authoritative shape. Top-
level fields:

- `schema_version` (string; currently `"1.0"`) + `product` (always
  `"ibounce"`) — load-bearing for cross-product reject (a kbounce
  bundle bounces with `value 'kbounce' not in enum ['ibounce']`).
- `ibounce_version`, `exported_at` (RFC3339 UTC), `source_hostname_hash`
  (sha256[:12] of the source hostname — stable but non-revealing).
- `profiles`: every profile in `profiles.yaml` + the active selection.
- `rules`: every row in the rules table (pattern + effect + scope +
  origin + expires_at).
- `tasks`: active + recent task scopes — INFORMATIONAL only; tasks are
  NEVER replayed on import (time-bounded; replay would be a no-op).
- `presets`: applied-preset history from `config_events`.
- `audit_webhook`: JSONL log path + env-key presence + redacted
  webhook URL/token.
- `alert_rules`: pointer + inlined YAML content when
  `--alert-rules PATH` was set.
- `mcp_install_history`: which MCP host config files contain an
  `ibounce` server entry.
- `license`: `license_id` + `expires_at`; the signed payload is NEVER
  carried (separate bytes belong in the SQLite-backup channel #279).

The export file lives at the operator-chosen `--out` path; mode `0600`,
atomic write (temp file + rename) so an interrupted run never leaves a
half-written file.

### Redaction defaults

Redaction is ON by default and ibounce **refuses** the
`--no-redact-secrets` opt-out — backups with live tokens belong in the
SQLite-backup channel (#279), not in a human-reviewable JSON file
checkable into a config repo.

Masked fields:

- Audit-webhook URL + token + Splunk-HEC / Datadog / Sentinel
  per-preset secrets → `"***"` with a hint string.
  Preset support per [[audit-webhook-presets]] — see
  [WEBHOOK-PRESETS.md](WEBHOOK-PRESETS.md) for the full per-vendor
  wire shape + token-acquisition steps + the cross-product
  `audit-webhook presets list` CLI surface.
- Token-shaped fields anywhere in the bundle (HEC token, API key,
  integration key, license content/PEM/private key) → `"***"`.
- Env-var **values** → not projected; the env-var **keys** are
  recorded so a reviewer sees which channels the source host had
  configured.
- License content → masked, but `license_id` + `expires_at` are
  retained so the importer knows whether the destination needs its
  own license install.

### Cross-product semantics

Each Bounce product (`ibounce`, `kbounce`, `dbounce`) ships the same
bundle skeleton under its own `product` magic. Imports across the
suite are refused: each product owns its own rule + profile semantics,
and a kbounce profile YAML wouldn't pass ibounce's `_profile_from_dict`
validator anyway.

The error message matches the sibling products exactly so a customer
authoring one generic backup workflow sees uniform output:

```
value 'kbounce' not in enum ['ibounce']; this bundle was produced by
a different product (kbounce / dbounce / unknown). Imports across the
Bounce suite are not allowed: each product owns its own rule + profile
semantics.
```

### Import modes

- `--merge` (default; safer) — union by stable key (profile.name,
  rule fingerprint = effect+pattern+arn_scope+region_scope). On
  collision: keep the EXISTING value + log a collision note.
- `--replace` — clear the importing categories first, then load the
  bundle wholesale. Existing rules are `remove_rule`'d so the audit
  trail in `config_events` preserves what was wiped.
- `--dry-run` — print what would happen (counts per section + the
  collision list) and exit without mutating. Still emits a
  `config.import` admin-action OCSF row with `result=noop` so SIEM
  dashboards see the planning activity.

The default (no flag) is `--merge`.

### Refuse-if-running

`config import` probes `127.0.0.1:8767` (the default `ibounce run`
loopback port; override via `IBOUNCE_PROBE_PORT`). If the probe
succeeds, import refuses with:

```
ERROR: ibounce appears to be running (loopback probe on
127.0.0.1:8767 succeeded). Stop ibounce first — importing while the
proxy holds an open SQLite connection would race on the rules / tasks
tables.
```

Importing while the live proxy holds an open SQLite connection would
race on the rules / tasks tables; the refuse-first posture is cheaper
than recovering a half-imported config.

### Admin-action audit emission

Every export AND every import enqueues exactly one ADMIN_ACTION OCSF
row (`kind = config.export` / `config.import`) via the queue stub
wired in #278. The serve process's drainer picks it up + emits through
the configured audit channels — so a security team watching the
audit-export stream sees the lifecycle event for every backup /
restore action, including `--dry-run` plans.

### Sample export

```bash
$ ibounce config export --out /tmp/ibounce-backup.json
exported /tmp/ibounce-backup.json
  profiles: 2, rules: 12, tasks: 1, presets: 1
  webhook tokens + license content are redacted by default.
```

Sample (redacted) export file:

```json
{
  "schema_version": "1.0",
  "product": "ibounce",
  "ibounce_version": "1.0.0",
  "exported_at": "2026-05-18T10:14:22Z",
  "source_hostname_hash": "9c8b7a6d5e4f",
  "profiles": {"active": "full-user", "items": [...]},
  "rules": [
    {"id": 1, "pattern": "s3:GetObject", "effect": "allow",
     "arn_scope": "arn:aws:s3:::demo-bucket/*", "origin": "user"},
    {"id": 2, "pattern": "iam:DeleteRole", "effect": "deny"}
  ],
  "tasks": [...],
  "presets": [{"preset_name": "admin-minus-sensitive", "rules_added": 12, ...}],
  "audit_webhook": {
    "log_path": "/var/log/ibounce/audit.jsonl",
    "webhook_url": "***",
    "webhook_token": "***",
    "redaction_hint": "redacted by default; live values stay on the source host",
    "env_keys_present": ["IAM_JIT_BOUNCER_AUDIT_WEBHOOK_TOKEN", "..."]
  },
  "alert_rules": {"path": "/etc/ibounce/alerts.yaml", "content": {...}},
  "mcp_install_history": [{"client": "claude-code", "path": "~/.claude.json"}],
  "license": {"license_id": "lic_abc123", "expires_at": "2027-05-17T00:00:00Z", "content": null}
}
```

### Sample import session

```bash
# Stop the live proxy first.
$ pkill ibounce

# Preview what would land.
$ ibounce config import --in /tmp/ibounce-backup.json --dry-run
import mode: dry-run
  profiles: added=2 collided=0 replaced=0
  rules: added=12 collided=0 replaced=0
  tasks: 1 carried (informational; tasks are NOT replayed)
  presets: 1 preset-apply events carried (informational; rules already landed in store)

# Looks right — apply it.
$ ibounce config import --in /tmp/ibounce-backup.json --merge
import mode: merge
  profiles: added=2 collided=0 replaced=0
  rules: added=12 collided=0 replaced=0
```

### Relation to #279 SQLite backup

`config export` is the human-reviewable, redacted, check-into-config-
repo channel. Sibling slice **#279 SQLite backup** is the
trusted-channel, byte-for-byte backup (preserves audit trail, decision
log, live tokens, license payload). The two are complementary:

- Reach for `config export` when you want a diff-able artefact, when
  you're migrating between machines, or when the bundle goes through a
  security-review pipeline.
- Reach for the #279 SQLite backup when you need byte-identical
  restore of the operational state (including audit history + live
  tokens) and the backup target is itself trusted.

### Cross-links

- Sibling Go implementation in **kbounce**: commit `6e5a678`
  (`internal/cli/config.go` + `schemas/kbounce-config.schema.json`).
- Sibling Go implementation in **dbounce**: commit `9608b14`
  (`internal/cli/config.go` + `schemas/dbounce-config.schema.json`).

Per [[cross-product-agent-parity]] the wire shape + CLI flags + admin-
action kinds match across the three products so one cross-product SIEM
correlation rule on `action="config.import"` catches the lifecycle
event regardless of which Bounce fired it.

## What's deferred to Stage 2

- HTTP proxy server itself (uvicorn-based)
- AWS_ENDPOINT_URL injection helper / shell snippet generator
- Interactive PROMPT-mode UX
- Service-specific request parsers for less-common shapes (multipart
  S3, DynamoDB Streams, EC2 raw query, etc.)
- "Convert learn-captured calls → rules" workflow

## What's deferred to Enterprise

- Multi-machine fleet rules (centrally distributed)
- Web UI for rule management
- Anomaly detection (call pattern outliers, off-hours flags)
- Multi-account aggregation

## Use case: fixed-role workloads (k8s, EC2, ECS, etc.)

The bouncer is the canonical gating answer for workloads where
iam-jit-the-issuer can't help because the role is baked into the
workload at creation time (k8s IRSA, EC2 instance profile, ECS Task
Role, Batch job role, etc.). The pattern:

1. Agent calls `check_iam_jit_compatibility(workload="k8s_pod", ...)`.
2. Gets back `verdict="use_existing"` + `bouncer_recommended=true`.
3. The workload's pre-existing role (the IRSA role, the instance
   profile, etc.) is used for AWS calls — iam-jit doesn't issue
   anything.
4. The bouncer runs alongside the workload as the local gate.

Deployment shapes per environment (Stage 2 documents will go deeper):

- **K8s pods** — bouncer as a sidecar container; the application
  container sets `AWS_ENDPOINT_URL=http://127.0.0.1:8767`.
- **EC2 instances** — bouncer as a systemd unit on the instance;
  set `AWS_ENDPOINT_URL` in the application's environment.
- **ECS tasks / Fargate** — bouncer as a sidecar container in the
  task definition; same env-var pattern.
- **Lambda** — bouncer can't run inside the Lambda runtime; the
  compatibility checker returns `bouncer_recommended=false` for
  Lambda specifically. Use a Lambda execution-role-scoping flow at
  deploy time instead of runtime gating.

In all cases, the bouncer's audit log (`ibounce logs tail`)
shows every gated AWS call regardless of how the workload obtained
its creds. The audit chain promise holds whether the role was
issued by iam-jit or assigned by the platform.

## Task scope — agent-declared narrowing

Per proxy-smart-defaults-and-task-scope: an agent doing a
discrete task can declare a TASK SCOPE that narrows bouncer
behavior for the task's duration. Canonical example:

```
agent: "I'm upgrading the staging EKS cluster control plane
to 1.30 for the next 60 minutes."
```

```python
bouncer_start_task(
    description="upgrade EKS staging cluster control plane to 1.30",
    allow_rules=[
        {"pattern": "eks:*",
         "arn_scope": "arn:aws:eks:us-east-1:111111111111:cluster/staging"},
        {"pattern": "ec2:Describe*", "region_scope": "us-east-1"},
        {"pattern": "iam:GetRole"},
        {"pattern": "iam:PassRole",
         "arn_scope": "arn:aws:iam::111111111111:role/eks-*"},
    ],
    deny_rules=[
        # Nothing in the prod account, even though global rules would allow:
        {"pattern": "*", "arn_scope": "arn:aws:*:*:222222222222:*"},
    ],
    duration_minutes=60,
)
# → returns task_id; bouncer enforces for 60 min or until bouncer_end_task
```

### Composition with global rules

| Layer | When it applies | Wins over |
|---|---|---|
| Task explicit deny | Active task; matches request | Everything (incl. learn mode) |
| Global explicit deny | Always | Task allow, default policy |
| Task allow | Active task; matches request | Default deny (within task) |
| Global allow | Always | Default policy when no task allow matched |
| Default policy | No rule matched, no task active | — |

Plain English: an agent's task-deny is the strongest layer (the
"no prod" must hold even during learn mode). A global-deny baseline
still wins over a task-allow (admin's `iam:Delete*` deny isn't lifted
by an agent saying "for this task, allow iam:*"). And calls the
task didn't declare that GLOBAL rules already allow (`sts:GetCaller
Identity`, etc.) keep working — task scope NARROWS but doesn't
require declaring every infrastructure call.

### Lifecycle

- **Start** — `bouncer_start_task` MCP tool OR `ibounce
  tasks start` CLI.
- **Active** — every decision during the task references its
  `task_id` in the decision audit log.
- **End** — `bouncer_end_task` MCP tool OR `ibounce tasks
  end <task_id>` OR auto-expiry on the wall-clock duration.
- **Inspect** — `ibounce tasks active` shows the current
  task; `tasks list` shows historical tasks; `tasks show <id>`
  shows full details.

**Concurrent tasks (Slice C):** multiple agent sessions can each
have their own active task scope by declaring a distinct `owner`
identifier at start. Within a single owner, the single-active
invariant still holds (same owner can't start a second concurrent
task). Tasks without an explicit owner share the "default-owner
slot" — useful for the single-laptop case where only one agent is
running at a time.

**Post-task review:** `ibounce tasks review <id>` (or
`bouncer_task_review` MCP tool) returns an aggregated summary of
the task — total decisions, allow/deny breakdown, list of denied
calls. Useful to see whether the scope was right-sized (lots of
denies = too narrow; broad allows but no use = too broad). Owner-
match is enforced via MCP: agents can only review their own tasks.

### Auto-expiry

Tasks auto-expire on the wall-clock duration so a forgotten
`end_task` call doesn't leave the scope active indefinitely. The
expiry transition is audit-logged via `config_events`
(`kind=task_ended, end_reason=timeout`).

### What task scope catches

The staging-EKS-upgrade canonical case: a prompt injection mid-task
that tells the agent to "also delete the prod cluster while you're
at it" hits the explicit task-deny on `arn:aws:*:*:222222222222:*`
and gets blocked. The audit log shows the attempted out-of-scope
call alongside the task that was active. Without task scope, the
global rules might have allowed the prod call (especially in
admin-minus-sensitive's permissive baseline).

## Observation-based recommender (Slice D)

Per bouncer-learn-then-recommend + apply-little-snitch-principles:
the bouncer can synthesize a draft ruleset from observed traffic in
LEARN mode. Closes the loop from "learn-first lean-permissive
default" to "switch to ENFORCE with a real ruleset" without
hand-authoring rules from thousands of audit-log lines.

### Workflow

> **The "Day 0-7: run normally" step requires the Stage 2 HTTP
> proxy [v1.1: HTTP proxy] to capture traffic transparently.** In
> v1.0, decisions only land in the audit log when (a) an agent calls
> the MCP tools (see [docs/AGENTS.md](AGENTS.md)) or (b) the admin
> runs `ibounce decide ... --record` for each call. Once
> Stage 2 ships, this workflow becomes the canonical Day-0/Day-7
> path; for now the recommender works on any audit-log entries that
> exist, but seeding them requires one of those two paths.

```bash
# Day 0: install + smart default (admin-minus-sensitive)
ibounce init

# Day 0-7 [v1.1: HTTP proxy]: run normally; the bouncer records
# everything in LEARN mode. (In v1.0, see callout above for how to
# seed the audit log via MCP or decide --record.)

# Day 7: ask for a recommendation
ibounce recommend --since 2026-05-10T00:00:00Z

# observation window: 2026-05-10T00:00:00Z -> 2026-05-17T15:14:22Z
# 847 total calls (allow=847 deny=0 prompt=0)
# 6 distinct services, 23 distinct actions
#
# ## Recommended rules (12):
#   ALLOW s3:GetObject [arn=arn:aws:s3:::reports-*]
#     support: 643 calls (75.9% of window)
#     arn:    8 of 10 observed ARNs (80%) share the prefix 'arn:aws:s3:::reports-'
#     region: 643 of 643 calls in us-east-1 (100%)
#     note:   Read object data from an S3 bucket.
#             Fetching files for analysis, download, or display.
#   ...
#
# Apply as-is? Cherry-pick? Modify? (--apply to bulk-add)
```

### Research Assistant pattern

Per apply-little-snitch-principles: every recommended rule
carries:

- **support** — how many observed calls matched (sort by impact)
- **ARN-pattern rationale** — e.g. "92% hit `arn:aws:s3:::reports-*`"
- **region rationale** — e.g. "all calls in us-east-1"
- **research note** — curated "what does this action do + when is it
  typical" for ~30 common AWS actions (s3:GetObject, sts:AssumeRole,
  iam:PassRole, etc.). The agent / admin doesn't have to look up
  every action to review a recommendation.

### Synthesis algorithm

Deterministic, no LLM (scorer-is-ground-truth):

1. Group decisions by `(service, action)`.
2. Skip groups below `--min-support` (default 3) — sparse traffic
   will default-deny in enforce mode; agent can add explicit rules
   if needed.
3. For each remaining group: detect ARN-prefix pattern (full LCP
   preferred; fall back to majority-cluster); detect dominant
   region (≥90% in one region).
4. Recommend an ALLOW rule with the discovered scopes.
5. Attach the research note if the action is in the curated catalog.

### Apply

Review-first by default. `ibounce recommend --apply` (or
MCP `bouncer_apply_recommendation`) bulk-adds the recommendations
as new rules in one batch + writes a `recommendation_applied`
config event to the audit chain so post-hoc review can spot
which batch each rule came from.

### MCP tools

- `bouncer_recommend_rules` — synthesize + return draft
- `bouncer_apply_recommendation` — apply a subset (agent reviews,
  cherry-picks, modifies, applies)

## Agent-friendly, not bypassable

Per agent-friendly-not-bypassable: the bouncer is configurable
by agents AND impossible to silently bypass. Both directions are
load-bearing.

**Agent-friendly (Lens A):** every CLI command has an MCP equivalent
so agents can read posture, propose changes, and verify outcomes
without shelling out:

| CLI | MCP tool |
|---|---|
| `ibounce rules list` | `bouncer_list_rules` |
| `ibounce rules add ...` | `bouncer_add_rule` |
| `ibounce rules remove ...` | `bouncer_remove_rule` |
| `ibounce decide ...` | `bouncer_decide` |
| `ibounce presets list` | `bouncer_list_presets` |
| `ibounce presets show ...` | `bouncer_show_preset` |
| `ibounce presets apply ...` | `bouncer_apply_preset` |
| `ibounce events tail` | `bouncer_tail_events` |
| `ibounce logs tail` | `bouncer_tail_decisions` |
| `ibounce tasks start ...` | `bouncer_start_task` |
| `ibounce tasks active` | `bouncer_active_task` |
| `ibounce tasks end ...` | `bouncer_end_task` |
| `ibounce tasks review ...` | `bouncer_task_review` |
| `ibounce effective-scope` | `bouncer_effective_scope` |
| `ibounce recommend ...` | `bouncer_recommend_rules` + `bouncer_apply_recommendation` |
| (composer — no CLI equivalent) | `iam_jit_scope_self_for_task` |

The `iam_jit_scope_self_for_task` composer (Slice E) is the
canonical agent-side entry point: one MCP call atomically declares
a bouncer task scope, requests a JIT role with the same narrowing,
and returns scoped STS credentials + the task_id. Most agents
should call this BEFORE touching AWS rather than threading
`bouncer_start_task` + `submit_policy` by hand. See
[docs/AGENTS.md](AGENTS.md) for the full agent flow.

Curated presets (`bouncer_list_presets`) give agents vetted starting
points instead of authoring rules from scratch:

- `readonly` — broad Get*/List*/Describe* allow + deny on secret reads
- `admin-minus-sensitive` — allow * except IAM admin, secrets, billing, audit-infra destruction
- `prod-deny-destructive` — deny `*:Delete*` / `*:Terminate*` + KMS deletion / RDS / EKS / etc.
- `deny-iam-admin` — block all IAM modification + STS escalation paths

`bouncer_decide` returns a `how_to_allow` hint when a call is denied
without a matching rule, so the agent can propose the right config
change in its next turn — no vague "denied" responses with no path
forward.

**Uncircumventable (Lens B):** every config change writes to a
config-event audit log (`bouncer_tail_events` / `ibounce events
tail`). The audit chain captures:

| Event kind | What's recorded |
|---|---|
| `rule_added` | actor + rule pattern + scope + note |
| `rule_removed` | actor + FULL prior rule content (post-hoc forensics) |
| `mode_changed` | actor + old mode + new mode + reason |
| `preset_applied` | actor + preset name + rule count |

There is intentionally NO MCP tool or CLI flag that:
- Disables the bouncer
- Skips audit logging
- Removes events from the audit log
- Switches modes without recording the switch

LEARN mode is permissive — it never DENIES — but it still RECORDS
every call to the decision audit log. The cost of bypass must
always exceed the cost of compliance.
