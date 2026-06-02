# `iam-jit agent-diff` — operator guide

**What it does:** compares two agent sessions captured in the
cross-bouncer audit log and surfaces a structured diff —
permission delta, decision-pattern delta, behavioral fingerprint
delta, risk delta, and a narrowed IAM policy ready for operator
review.

**Why you want this:** when two agents (Claude vs Codex vs Devin vs
in-house) have both performed the same task in your environment,
this command answers "which one should I write the production role
for" with evidence the operator can re-verify.

> Marketing angle: "Agent A did the job in 7 permissions. Agent B took
> 47. Use A's role."

Read-only — never mutates any audit data, never creates roles. The
narrowed policy is operator input for `iam-jit request` or the
synthesis MCP tool; those flows run their own scorer pass.

See `docs/AGENT-DIFF-DESIGN.md` for the data-model spec.

## Prerequisites

* At least one bouncer (ibounce / kbounce / dbounce / gbounce) running
  with its management endpoint reachable on localhost (default ports
  per `[[cross-product-agent-parity]]`).
* Each session you want to diff must have at least one OCSF event
  carrying `unmapped.iam_jit.agent.session_id` (the bouncers populate
  this automatically when the agent passes the session header).

## CLI

```
iam-jit agent-diff <session_a> <session_b> \
  [--bouncer ibounce,kbounce,dbounce,gbounce] \
  [--since 1h] [--until ISO8601] \
  [--scope permissions|decisions|behavioral|risk|all] \
  [--format json|table|markdown] \
  [--narrow union|intersection|left|right] \
  [--limit 1000] \
  [--audit-events-token TOKEN] \
  [--output PATH]
```

Defaults:

| Flag       | Default                              |
| ---------- | ------------------------------------ |
| `--bouncer`| probe all four default bouncers      |
| `--since`  | `1h`                                 |
| `--scope`  | `all`                                |
| `--format` | `table` on a TTY, `json` otherwise   |
| `--narrow` | `intersection`                       |
| `--limit`  | `1000` per bouncer per session       |

Exit codes:

* `0` — diff produced (including when the deltas / narrowing are
  honestly empty).
* `2` — invalid input.
* `3` — every bouncer was unreachable for both sessions.

## Worked examples

### 1. Pick the tighter agent for the production role

You ran the same nightly-reports job through two agents in staging.
Now you need a tight IAM policy.

```bash
iam-jit agent-diff sess_claude_2026_06_02 sess_codex_2026_06_02 \
  --since 24h --format markdown --output ./diff.md
```

`diff.md` shows behavioral fingerprint + decisions + the narrowed
policy. Use the intersection policy (default) as the start point for
the production role.

### 2. Just the permissions delta, piped into `jq`

```bash
iam-jit agent-diff sess_a sess_b \
  --scope permissions --format json \
  | jq '.permission_delta'
```

### 3. Diff against a single bouncer + narrow strategy = left

> "Use session A's surface verbatim. I just want to confirm B didn't
> need anything A missed."

```bash
iam-jit agent-diff sess_a sess_b \
  --bouncer ibounce \
  --narrow left
```

If `permission_delta.only_in_b` is non-empty, session B touched
something session A didn't — review before locking the role to A.

### 4. Audit window that covers a multi-day soak test

```bash
iam-jit agent-diff sess_long_a sess_long_b \
  --since 2026-05-25T00:00:00Z \
  --until 2026-05-28T00:00:00Z \
  --limit 5000
```

## Sample output

### `table` (default on TTY)

```
agent-diff: sess_claude_a vs sess_codex_b

Behavioral fingerprint
  metric                      A      B              Δ
  total_calls                 7     47        +40 (B)
  distinct_actions            4     12         +8 (B)
  distinct_principals         1      1              0
  distinct_resources          3     19        +16 (B)
  distinct_hosts              0      1         +1 (B)

Decisions
  allow_count: A=7 B=41 Δ=+34 (B)
  deny_count:  A=0 B=6 Δ=+6 (B)
  deny reasons only B: org_policy:no-prod, region:eu-west-1

Risk
  max_anomaly_score: A=0.21 B=0.83 Δ=+0.62 (B)
  anomalous events:  A=0 B=3 Δ=+3 (B)

Permissions
  only in A (0): (none)
  only in B (4): s3:ListBucket, s3:GetBucketAcl, iam:ListRoles, ec2:DescribeRegions
  intersection (4): s3:GetObject, s3:PutObject, dynamodb:GetItem, dynamodb:Query

Narrowing (intersection) — 4 actions
```

### `markdown` (paste into a PR or incident doc)

The markdown form embeds the real IAM JSON policy inside a fenced
`json` block, ready to be copied into a role document.

```markdown
## Narrowed policy (intersection, 4 actions)

```json
{
  "Statement": [
    {"Action": ["dynamodb:GetItem"], "Effect": "Allow", "Resource": [...]},
    ...
  ],
  "Version": "2012-10-17"
}
```
```

## Narrowing strategies — when to use which

| Strategy        | When to pick it                                              |
| --------------- | ------------------------------------------------------------ |
| `intersection`  | DEFAULT. Both sessions agreed they needed these actions; tightest defensible policy. |
| `union`         | When you want the production role to admit either agent's behaviour (e.g. you'll run both in prod). |
| `left`          | When you've already decided session A is canonical + you just want B's surface as a cross-check. |
| `right`         | Mirror of `left`.                                            |

When the intersection is empty (sessions touched disjoint actions),
the output's `narrowing.cannot_narrow_reason` says so honestly. Per
`[[ibounce-honest-positioning]]` the policy is never invented to
look non-empty.

## Honesty bar — what the tool DOES NOT do

* Does NOT score sessions. Risk delta reads pre-computed anomaly
  scores off events (Phase H, #469). When no scores are present, the
  output's `risk_delta.reason` says
  `anomaly_scoring_unavailable_for_protocol`.
* Does NOT recommend an agent. Per `[[no-nl-synthesis]]` no natural-
  language verdict. The operator reads the structured diff + decides.
* Does NOT issue roles. The narrowed policy is operator input for the
  next step (e.g. `iam_jit_request_role_from_synthesis`).
* Does NOT modify any audit data. Read-only per
  `[[creates-never-mutates]]`.

## MCP tool

The same backend is reachable from any MCP client as
`iam_jit_agent_diff(session_a, session_b, ...)`:

```jsonc
{
  "name": "iam_jit_agent_diff",
  "arguments": {
    "session_a": "sess_claude_2026_06_02",
    "session_b": "sess_codex_2026_06_02",
    "bouncer": "ibounce",
    "since": "24h",
    "scope": "all",
    "narrow": "intersection"
  }
}
```

Per `[[cross-product-agent-parity]]` the MCP tool returns the same
top-level keys as the CLI's `--format json` output, plus a
`status: "ok"` / `status: "error"` envelope.

## Composing with the rest of iam-jit

```
                ┌──────────────────────────────────┐
                │ iam-jit audit query --extract-permissions │
                │ → permission set per session     │
                └──────────────────────────────────┘
                              │
                              ▼
            ┌───────────────────────────────────────┐
            │ iam-jit agent-diff session_a session_b│
            │ → narrowed policy + structured diff   │
            └───────────────────────────────────────┘
                              │
                              ▼
            ┌───────────────────────────────────────┐
            │ iam_jit_request_role_from_synthesis   │
            │ → scored, optionally auto-approved    │
            └───────────────────────────────────────┘
                              │
                              ▼
                         short-lived
                       STS credentials
```

Each step is independently runnable; `agent-diff` is the new middle
seam that makes "pick the tighter session" structured.
