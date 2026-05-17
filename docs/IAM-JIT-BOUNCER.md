# iam-jit-bouncer

Local proxy that gates every AWS API call against rules. Defense-in-depth
over IAM role scoping — when the boundary the JIT role draws is correct
but the call TARGET was wrong (prompt injection, agent misstep, typo on
a destructive call), the bouncer catches it.

Per [[iam-jit-bouncer]]: doesn't exist productized elsewhere. Per
[[four-products-one-brand]]: separate product, separate binary
(`iam-jit-bouncer`).

## Status

**Stage 1 (this release):** Foundation — data model, rule matcher,
decision logic, SQLite store, request parser, CLI for rule + log
management + dry-run decisions.

**Stage 2 (next release):** HTTP proxy server (the actual runtime
that intercepts `AWS_ENDPOINT_URL`-redirected calls), interactive
PROMPT-mode UX.

**Stage 3 (Enterprise):** Multi-machine fleet rules, web UI,
anomaly detection.

## Why a local proxy

IAM is coarse. A role granted `s3:GetObject` on bucket `my-data` can
call `GetObject` on every key in `my-data` for the role's session
lifetime — even if the prompt-injected agent meant to read one
specific file and instead loops over the entire bucket.

The bouncer adds an in-process question: **is THIS specific call
allowed right now?** It runs on your laptop, against your local AWS
creds, with no iam-jit-the-company involvement.

Per [[creates-never-mutates]]: the bouncer never modifies IAM. It
inspects + forwards + denies — that's the entire surface.

## Architecture

```
boto3 / aws-cli / agent
        |
        v                       (AWS_ENDPOINT_URL=http://127.0.0.1:8767)
http://127.0.0.1:8767  <-- iam-jit-bouncer (Stage 2 HTTP proxy)
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

Per [[safety-mode-lean-permissive]]: `learn` is intentionally the
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

Service prefix comparison is case-insensitive on the request side
(AWS canonical prefixes are lowercase like `s3`, `ec2`, `iam`).
Action and ARN globs are case-sensitive (AWS action names are
PascalCase and must match exactly).

## CLI usage

### Initialize

```bash
iam-jit-bouncer init
# bouncer initialized at: ~/.iam-jit/bouncer/state.db
# current rules: 0
# current decisions: 0
```

### Manage rules

```bash
# Allow S3 GetObject on a specific bucket
iam-jit-bouncer rules add 's3:Get*' \
    --arn 'arn:aws:s3:::my-data/*' \
    --region us-east-1 \
    --note 'dev read access'

# Deny all IAM writes (admin guardrail)
iam-jit-bouncer rules add 'iam:Delete*' --effect deny
iam-jit-bouncer rules add 'iam:Put*'    --effect deny
iam-jit-bouncer rules add 'iam:Create*' --effect deny

# List
iam-jit-bouncer rules list
#    1  allow  s3:Get*  [arn=arn:aws:s3:::my-data/*, region=us-east-1]  # dev read access
#    2   deny  iam:Delete*
#    3   deny  iam:Put*
#    4   deny  iam:Create*

# Remove by id
iam-jit-bouncer rules remove 2
```

### Dry-run decisions

Before flipping to `enforce`, sanity-check what your rules would do:

```bash
iam-jit-bouncer decide --service s3 --action GetObject \
    --arn arn:aws:s3:::my-data/file.txt --region us-east-1
# decision: allow
# reason:   explicit-allow rule
# rule:     allow s3:Get*

iam-jit-bouncer decide --service iam --action DeleteRole
# decision: deny
# reason:   explicit-deny rule
# rule:     deny iam:Delete*

iam-jit-bouncer decide --service ec2 --action DescribeInstances
# decision: deny
# reason:   enforce-mode unmatched (default-deny)
```

### Inspect raw HTTP requests

Useful for debugging the request parser:

```bash
iam-jit-bouncer inspect \
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
iam-jit-bouncer logs tail
iam-jit-bouncer logs tail --decision deny --limit 20
iam-jit-bouncer logs tail --json
```

## Storage

SQLite at `~/.iam-jit/bouncer/state.db` (override with
`IAM_JIT_BOUNCER_DB`). Directory created with mode `0o700` per
[[no-hosted-saas]] + [[local-only-safety-mode]] precedent.

Schema versioned via `schema_version` table; additive migrations
only (no Alembic, no ORM). Current schema: `rules` + `decisions`.

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

In all cases, the bouncer's audit log (`iam-jit-bouncer logs tail`)
shows every gated AWS call regardless of how the workload obtained
its creds. The audit chain promise holds whether the role was
issued by iam-jit or assigned by the platform.

## Task scope — agent-declared narrowing

Per [[proxy-smart-defaults-and-task-scope]]: an agent doing a
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

- **Start** — `bouncer_start_task` MCP tool OR `iam-jit-bouncer
  tasks start` CLI.
- **Active** — every decision during the task references its
  `task_id` in the decision audit log.
- **End** — `bouncer_end_task` MCP tool OR `iam-jit-bouncer tasks
  end <task_id>` OR auto-expiry on the wall-clock duration.
- **Inspect** — `iam-jit-bouncer tasks active` shows the current
  task; `tasks list` shows historical tasks; `tasks show <id>`
  shows full details.

Only ONE task active at a time in Slice B. Slice C may add per-PID
concurrent tasks.

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

## Agent-friendly, not bypassable

Per [[agent-friendly-not-bypassable]]: the bouncer is configurable
by agents AND impossible to silently bypass. Both directions are
load-bearing.

**Agent-friendly (Lens A):** every CLI command has an MCP equivalent
so agents can read posture, propose changes, and verify outcomes
without shelling out:

| CLI | MCP tool |
|---|---|
| `iam-jit-bouncer rules list` | `bouncer_list_rules` |
| `iam-jit-bouncer rules add ...` | `bouncer_add_rule` |
| `iam-jit-bouncer rules remove ...` | `bouncer_remove_rule` |
| `iam-jit-bouncer decide ...` | `bouncer_decide` |
| `iam-jit-bouncer presets list` | `bouncer_list_presets` |
| `iam-jit-bouncer presets show ...` | `bouncer_show_preset` |
| `iam-jit-bouncer presets apply ...` | `bouncer_apply_preset` |
| `iam-jit-bouncer events tail` | `bouncer_tail_events` |
| `iam-jit-bouncer logs tail` | `bouncer_tail_decisions` |

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
config-event audit log (`bouncer_tail_events` / `iam-jit-bouncer events
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
