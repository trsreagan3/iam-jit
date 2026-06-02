# `iam-jit agent-diff` — differential audit design

**Status:** SHIPPED v1 — task #722 / BUILD-1.
**Surface:** new `iam-jit agent-diff <session_a> <session_b>` CLI +
`iam_jit_agent_diff` MCP tool.
**Module:** `src/iam_jit/agent_diff/`.

## What problem this solves

Operators running multiple AI agents in parallel (Claude vs Codex vs
Devin vs in-house) have no structured way to answer:

> "Agent A did the job in 7 permissions, Agent B took 47. Which one
> should I write the production role for?"

Apono / Pipelock / NanoClaw all do per-session analysis. None publish
session-to-session diff. Per the competitive-firewall landscape PDF,
this is iam-jit's **highest single differentiation**.

This surface pairs with role-effectiveness grading (#393) — the
operator picks the agent whose audit-derived role is tightest, and
the diff structures the evidence.

Per [[recommender-context-boundary]] the diff consumes ONLY AWS state
+ audit events. No codebase context, no LLM, no inference.

Per [[ibounce-honest-positioning]] empty deltas surface as empty
arrays + honest messages, not fabricated insights.

Per [[scorer-is-ground-truth]] when risk-delta uses the #469 anomaly
scorer, the scorer is consumed as-is — never tuned to make the diff
look better.

## Diff data model

The output of `iam-jit agent-diff` is an `AgentDiff` document with
four orthogonal sub-deltas + a narrowing block:

```
AgentDiff
├── sessions
│   ├── a: {session_id, events_analyzed, bouncers_observed, time_window}
│   └── b: {session_id, events_analyzed, bouncers_observed, time_window}
├── permission_delta            # what each session touched that the other didn't
│   ├── only_in_a: [{action, resources, count}]
│   ├── only_in_b: [{action, resources, count}]
│   └── intersection: [{action, resources_a, resources_b, count_a, count_b}]
├── decision_delta              # allow/deny rates + reasons
│   ├── a: {allow_count, deny_count, distinct_deny_reasons:[str]}
│   ├── b: {allow_count, deny_count, distinct_deny_reasons:[str]}
│   └── delta: {allow_count_delta, deny_count_delta, deny_reasons_only_in_a, deny_reasons_only_in_b}
├── behavioral_delta            # countable stream metrics
│   ├── a: {total_calls, distinct_actions, distinct_principals, distinct_resources, distinct_hosts}
│   ├── b: {total_calls, ...}
│   └── delta: {calls_delta, distinct_actions_delta, ...}
├── risk_delta                  # #469 anomaly-score delta (or null + reason)
│   ├── a: {max_anomaly_score, anomalous_event_count} | null
│   ├── b: {max_anomaly_score, anomalous_event_count} | null
│   └── delta: {max_score_delta, anomalous_count_delta} | null
└── narrowing                   # operator-ready IAM policy + reason
    ├── strategy: "intersection" | "union" | "left" | "right"
    ├── policy: {Version, Statement: [...]}                 # real IAM JSON
    ├── action_count: int
    ├── cannot_narrow_reason: str | null                    # honest empty-result handler
    └── notes: [str]
```

## Algorithms

### Permission delta

1. Group session A's events by `api.operation` → set `A` of actions.
2. Same for B → set `B`.
3. `only_in_a = A - B`, `only_in_b = B - A`, `intersection = A ∩ B`.
4. For intersection actions, surface per-side resources + counts so
   "both did `s3:PutObject` but A scoped to `/reports/*` and B
   wildcarded" is visible.

### Decision delta

1. Bucket per-session events by `unmapped.iam_jit.verdict` —
   `allow` / `deny`.
2. Collect distinct deny reasons from `unmapped.iam_jit.deny_reason`
   (already populated by every bouncer per
   [[cross-product-agent-parity]]).
3. Deltas are the per-bucket count differences + symmetric difference
   on the reason set.

### Behavioral delta

Pure countable metrics off the event stream:

| Metric              | Source                                     |
| ------------------- | ------------------------------------------ |
| `total_calls`       | `len(events)`                              |
| `distinct_actions`  | `len({api.operation})`                     |
| `distinct_principals` | `len({actor.user.uid})`                  |
| `distinct_resources` | `len({resources[*].uid \| resources[*].name})` |
| `distinct_hosts`    | `len({dst_endpoint.hostname})`             |

NEVER invent metrics. NEVER infer "efficiency" or "intent" — those are
operator-side judgements. We just count what the bouncer recorded.

### Risk delta

Reuses #469 `anomaly_detection.score_anomaly` for each event in each
session, picks the max score + counts anomalous events.

When the bouncer's protocol has no anomaly-scoring baseline wired
(e.g. dbounce + gbounce in their first cut), surface
`risk_delta: null` with `reason: "anomaly_scoring_unavailable_for_protocol"`.

### Narrowing

Four strategies. All produce a real `Version: 2012-10-17` IAM policy
document (or empty + honest reason).

| Strategy        | Output                                                  |
| --------------- | ------------------------------------------------------- |
| `intersection`  | actions touched by BOTH sessions; resources = union of (resources_a ∩ resources_b) per action |
| `union`         | every action from either session; resources = union     |
| `left`          | only A's actions + resources                            |
| `right`         | only B's actions + resources                            |

When the resulting policy would be empty (e.g. intersection on
disjoint sessions), the output sets:

```
narrowing.policy = {"Version": "2012-10-17", "Statement": []}
narrowing.cannot_narrow_reason = "no overlapping actions between sessions"
```

The agent / operator never gets a wishful sketch. They get a real
empty policy + an honest `cannot_narrow_reason`.

## Example diff (markdown table form)

```
$ iam-jit agent-diff sess_claude_a sess_codex_b --format markdown

# Agent Diff: sess_claude_a vs sess_codex_b

| Metric             | A    | B    | Δ        |
| ------------------ | ---- | ---- | -------- |
| total_calls        | 7    | 47   | +40 (B)  |
| distinct_actions   | 4    | 12   | +8 (B)   |
| distinct_resources | 3    | 19   | +16 (B)  |
| allow_count        | 7    | 41   | +34 (B)  |
| deny_count         | 0    | 6    | +6 (B)   |
| max_anomaly_score  | 0.21 | 0.83 | +0.62 (B)|

## Permission delta

Only in A: (none)
Only in B: s3:ListBucket, s3:GetBucketAcl, iam:ListRoles, ec2:DescribeRegions
Intersection: s3:GetObject, s3:PutObject, dynamodb:GetItem, dynamodb:Query

## Narrowed policy (intersection strategy)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": ["arn:aws:dynamodb:us-east-1:111:table/reports"]},
    {"Effect": "Allow", "Action": ["dynamodb:Query"],   "Resource": ["arn:aws:dynamodb:us-east-1:111:table/reports"]},
    {"Effect": "Allow", "Action": ["s3:GetObject"],     "Resource": ["arn:aws:s3:::reports/*"]},
    {"Effect": "Allow", "Action": ["s3:PutObject"],     "Resource": ["arn:aws:s3:::reports/*"]}
  ]
}
```

→ Recommendation: A's role covers the job. B added 40 extra calls + 6
denials + a 0.62-point anomaly jump for no additional capability.
Write A's policy.
```

## CLI surface

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
* `--bouncer` = all four (fan out, merge)
* `--since` = `1h`
* `--scope` = `all`
* `--format` = `table` for TTY, `json` for non-TTY
* `--narrow` = `intersection`
* `--limit` = `1000` per bouncer per session

Exit codes:
* `0` — diff produced (even if narrowing is empty + honest)
* `2` — invalid input (bad session id, bad `--since`, etc.)
* `3` — every bouncer unreachable (no events on either side)

## MCP surface

```
iam_jit_agent_diff(
  session_a: str,
  session_b: str,
  bouncer: str = "ibounce",
  since: str = "1h",
  until: str | None = None,
  scope: str = "all",
  narrow: str = "intersection",
  limit: int = 1000,
  audit_events_token: str | None = None,
) -> AgentDiff dict
```

Single-bouncer default mirrors `bounce_extract_permissions_from_audit`;
the agent that wants cross-bouncer correlation calls
`iam-jit audit query` first.

## Test coverage

Per [[uat-tests-setup-end-to-end]] +
[[tests-and-independent-uat-required]], the integration tests live in
`tests/integration/test_agent_diff_e2e.py` and cover:

1. **Identical sessions** — empty diff, narrowing.policy non-empty,
   intersection == union.
2. **Disjoint sessions** — only_in_a + only_in_b populated;
   intersection empty; narrowing.policy empty +
   `cannot_narrow_reason` set.
3. **Resource-scope difference** — both sessions touch
   `s3:PutObject` but A uses `arn:aws:s3:::reports/*` while B uses
   `arn:aws:s3:::*`. Intersection narrowing keeps A's tighter resource.
4. **Risk delta meaningful** — A's events score baseline-normal;
   B's events trigger an anomaly bump. `risk_delta.delta.max_score_delta`
   surfaces the gap.

Unit tests (`tests/agent_diff/`) cover the core lib's pure
functions: `compute_permission_delta`, `compute_decision_delta`,
`compute_behavioral_delta`, `build_narrowing_policy`.

## What this surface DOES NOT do

* Does NOT score sessions. Risk delta uses the #469 scorer as-is; no
  new heuristics.
* Does NOT recommend an agent. The operator reads the diff + decides.
  Per [[no-nl-synthesis]] we never produce a natural-language verdict.
* Does NOT issue roles. The narrowed policy is operator-input for
  `iam-jit request` / `iam_jit_request_role_from_synthesis` — those
  flows still run their own scorer pass.
* Does NOT modify any audit data. Read-only per
  [[creates-never-mutates]].
