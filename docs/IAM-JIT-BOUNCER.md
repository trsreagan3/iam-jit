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
