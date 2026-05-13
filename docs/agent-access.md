# Agent access: scoped IAM roles from task descriptions

The `iam-jit agent-grant` command turns a plain-English task description
into a minimum-scope IAM policy, scored by the same deterministic engine
that powers the rest of iam-jit. Built for the case where a developer
or AI agent needs *temporary, bounded* AWS access for a specific task —
without handing over a long-lived admin credential.

## Why this exists

If you're using Claude Code, Cursor, Devin, Aider, or a custom agent
loop with AWS, you've hit this problem: the agent needs AWS access to
do anything useful, but giving it your full credentials means a single
prompt-injection or model misunderstanding can drop a production
table. The alternatives — manually-crafted scoped IAM roles, permanent
IAM users tied to the agent, or no AWS access at all — are either too
much friction or too dangerous.

`iam-jit agent-grant` makes "right-sized IAM role per task" a one-line
command. The deterministic scorer validates every generated policy so
the agent can't ask for admin and get it.

## How it works

```
task description ─▶ heuristic pattern library ─▶ candidate policy
                                                       │
                       resource extraction ────────────┤
                       (explicit ARNs + names)
                                                       │
                       bias (allow / deny) ────────────┤
                                                       ▼
                                              deterministic scorer
                                                       │
                                                       ▼
                                         scored policy + refinement hints
```

1. **Pattern library**: ~30 patterns for common AWS task verbs (S3
   read/write, Lambda invoke/deploy, DynamoDB query, CloudWatch logs,
   SSM, Secrets, KMS, SQS/SNS, ECS, RDS, STS). Each pattern declares
   the action set it grants, with both an `allow` (broader) and
   `deny` (narrower) subset.

2. **Resource extraction**: regex-based extraction of explicit ARNs
   AND named resources ("the prod-orders DynamoDB table", "function
   deploy-api"). Falls back to `*` wildcards when no resource info
   is in the description.

3. **Bias**: `--bias allow` (default) includes more actions when the
   intent is ambiguous; `--bias deny` includes only the explicit
   subset. Use `allow` for developer/agent workflows where the
   scorer's safety floor protects you. Use `deny` for strict-
   compliance environments and fully-automated agent loops where
   over-grant is more costly than re-asking the user for detail.

4. **Scorer validation**: every generated policy runs through
   `analyze_policy()` before return. The risk score is included in
   the response so the caller can decide whether to auto-approve.

## CLI usage

### Basic — read an S3 bucket

```sh
$ iam-jit agent-grant -t "read S3 logs from the prod-logs bucket" \
                      --account 123456789012 --region us-east-1
Matched patterns: s3-read, cloudwatch-logs-read
Confidence: 2/10 (1=high, 10=low)
Risk score: 3/10

Policy:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket", ...],
      "Resource": "arn:aws:s3:::prod-logs"
    },
    {
      "Effect": "Allow",
      "Action": ["logs:GetLogEvents", ...],
      "Resource": "arn:aws:logs:*:*:log-group:*"
    }
  ]
}
```

Note that "logs" triggered both the S3 pattern *and* the CloudWatch
Logs pattern. The generator includes both, surfaces a refinement
hint, and the scorer scores 3 (logs is broad but reads-only).

### Deploy a Lambda (high-risk by design)

```sh
$ iam-jit agent-grant -t "deploy lambda function api-handler with role app-runtime-role" \
                      --account 123456789012 --region us-east-1
Matched patterns: lambda-deploy
Confidence: 3/10
Risk score: 9/10                          ◀── inherently high; PassRole + code-exec
```

`iam:PassRole` + `lambda:UpdateFunctionCode` is a code-execution
composition that scores 9 even on narrow resource ARNs (this is the
scorer's catastrophic-floor rule — a misconfigured role passed to a
Lambda can compromise the account). The generator correctly produces
a narrow policy; the score reflects the inherent risk of the
operation; a human reviewer makes the final call.

### Iterating with refinement

After reviewing the first result, refine without retyping the task:

```sh
$ iam-jit agent-grant -t "deploy lambda" \
                      --exclude-action iam:PassRole \
                      --rationale "code-only deploy; role isn't changing"
```

This removes `iam:PassRole` from the generated policy. The scorer
re-validates the result. The rationale appears in the audit log so
reviewers later understand why the refinement was made.

To add an action that the pattern missed:

```sh
$ iam-jit agent-grant -t "read S3 logs" \
                      --include-action s3:GetBucketTagging \
                      --rationale "need bucket tags for incident triage"
```

### Output formats for agents

```sh
# Full JSON for programmatic consumption (MCP servers, agent loops)
$ iam-jit agent-grant -t "..." --format json

# Just the IAM policy for piping
$ iam-jit agent-grant -t "..." --format policy | \
    aws iam create-policy --policy-name agent-temp --policy-document file:///dev/stdin
```

## Bias semantics

| Setting | Use case | What it does |
|---------|----------|--------------|
| `--bias allow` (default) | Developer or assisted-agent workflows | Includes every action the matched patterns allow. The scorer catches over-broad output. Best UX. |
| `--bias deny` | Strict compliance, fully-autonomous agents | Includes only the `deny_actions` subset each pattern declares. Some patterns contribute nothing in deny mode (you'll have to be more explicit in the description). |

**Recommendation:** start with `allow`. If a generated policy scores
higher than you want, refine with `--exclude-action` instead of
flipping to `deny`. The bias toggle is for *consistent organizational
policy* across many requests, not for tuning individual outputs.

## The safety contract

The generator can propose any policy; the scorer is what decides
whether the policy is safe to auto-approve. Specifically:

- The generator NEVER skips the scorer. Every result has a
  `scored_risk` and a list of `risk_factors` from `analyze_policy()`.
- The scorer's safety floor is unchanged — same rules that protect
  hand-written policies protect generated ones.
- An LLM mistake (in future LLM-backed generation) cannot bypass the
  scorer. The scorer doesn't trust the generator; it re-analyzes
  the output from scratch.
- Refinement edits (`--exclude-action`, `--include-action`) also
  run through the scorer. A refinement that adds catastrophic
  actions will produce a high-scored output, NOT a silently-approved
  one.

## What's NOT generated

The generator deliberately refuses to include certain actions even
when the task description seems to ask for them:

- IAM mutation actions (`iam:AttachRolePolicy`, `iam:CreateRole`,
  `iam:PutRolePolicy`, etc.) — these are catastrophic-tier and
  should never be generated from a casual task description.
- `iam:PassRole` is only included as part of patterns that
  genuinely need it (Lambda deploy, ECS deploy), and is always
  emitted as a separate statement with an IAM role ARN as Resource
  — never paired with a service ARN.
- Bedrock model invoke without a specific model ARN, organization
  management, account closure — all out-of-scope for heuristic
  generation.

If you need these, hand-author the policy and submit it via the
normal `iam-jit init` flow with full human review.

## Adding new patterns

Patterns live in `src/iam_jit/policy_gen/patterns/<service>.py`.
Each pattern is a `Pattern` dataclass with phrases, allow/deny
actions, and resource templates. Add a new entry to the relevant
service file (or create a new file and register it in
`patterns/__init__.py`).

The regression suite in `tests/test_policy_gen/test_corpus.py` pins
the input → output mapping for representative descriptions. Add a
case there when you add a new pattern.

## Architectural notes

- **Heuristic-first, no ML.** The current generator does NOT use an
  LLM. Every output is a deterministic function of the input. This
  makes the generator suitable for the Free tier — no per-call cost,
  no LLM hosting, no prompt injection in the description.
- **LLM-backed generation is planned for Pro tier.** When a
  description doesn't match any heuristic pattern, the Free tier
  returns "unmatched" and suggests rephrasing; Pro tier (future)
  will fall through to an LLM that produces a candidate policy,
  which is then re-validated by the same deterministic scorer.
- **The scorer is the moat.** Every generated policy gets scored
  before return. The deterministic-scoring discipline (97+ adversarial-
  round closures, 1,800+ corpus test cases) protects the generator
  exactly as much as it protects hand-written policies.

## Roadmap

- MCP (Model Context Protocol) server wrapper so Claude Code, Cursor,
  and other agents natively request scoped credentials.
- Direct AWS STS integration: after the policy is approved, the CLI
  can return `aws sts assume-role` credentials ready to export.
- More patterns (request via PR or open an issue).
- LLM-backed generation (Pro tier) for free-form task descriptions
  that don't match any heuristic pattern.
