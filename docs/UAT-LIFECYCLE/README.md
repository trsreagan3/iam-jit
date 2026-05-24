# UAT Lifecycle Framework

> **Stage A artifact — framework + scenario specs + harness + fixtures.**
> Stage B (separate agents) actually runs the scenarios.

Per founder direction 2026-05-24 and `[[mrr-flight-readiness-program]]` MRR-3:
build a series of UAT agents that test the **lifecycle** of iam-jit
(updating, removing, restarting, profile generation, threat-feed cycle,
crash recovery, etc.) — not just per-feature behaviour.

The role-effectiveness corpus
(`tests/dogfood/role-effectiveness-grades*.md`,
`[[role-effectiveness-corpus]]`) measures whether a profile MEANINGFULLY
constrains misuse. **This corpus measures whether the system survives the
operational lifecycle** — updating cleanly, recovering from crashes,
purging stale data, rotating credentials, etc. Together they form the
two halves of MRR-3 acceptance.

## What lifecycle UAT means

Synthetic feature UAT verifies a feature works once it is installed.
Lifecycle UAT verifies the **operational paths around** the feature:

* installing on a clean system without leftover state
* updating between two real commits without losing state
* recovering from a SIGKILL mid-traffic
* purging old audit log entries without breaking the chain
* uninstalling cleanly with no orphaned processes or files
* rotating credentials without dropping in-flight requests

These are the bugs the project's own dogfood cycle has caught most often
(seven of the seven `docs/CONTRIBUTING.md` reference bugs were
state-verification gaps in lifecycle paths, not in feature logic). They
also map directly to MRR-3 acceptance: "synthetic fixtures generate
realistic-shaped data without needing 14d real activity."

## Architecture — operator-portable, BYO-agent, BYO-LLM

Per `[[bouncer-zero-llm-when-agent-in-loop]]`: the framework is
re-runnable by **any operator with their own LLM** — Claude Max,
ChatGPT Plus, Cursor Pro, Codex, or any client that speaks MCP. iam-jit
provides:

1. **Scenario specs** (`scenarios/L{N}/spec.md`) — what the test verifies,
   pass/fail criteria, prerequisites, expected duration.
2. **MCP-driven recipes** (`scenarios/L{N}/recipe-for-agent.md`) — the
   structured walkthrough for the operator's agent. The operator's
   agent does the LLM reasoning; iam-jit's MCP tools provide the data
   + accept the actions.
3. **Deterministic harness** (`scenarios/L{N}/deterministic-harness.sh`
   or `.py`) — the state-shape verification that doesn't need agent
   reasoning. Runs in a Docker container or ephemeral test directory;
   produces a JSONL result line; exits 0 on PASS / non-zero on FAIL.

For scenarios that NEED agent reasoning (L5 profile generation; L13
credential-rotation reasoning), the recipe is primary + the harness
covers only the state-shape assertions. For scenarios that don't
(L1 install, L7 crash recovery, L8 disk pressure, L11 uninstall), the
harness is primary + the recipe is brief.

## How to run a single scenario in your own environment

Pre-flight:

```bash
# 1. Pick a scenario.
ls docs/UAT-LIFECYCLE/scenarios/

# 2. Read the spec to know what it tests + what it needs.
cat docs/UAT-LIFECYCLE/scenarios/L1/spec.md

# 3. If you have an MCP-speaking agent (Claude Code, Cursor, etc.):
#    point it at recipe-for-agent.md and let it drive.
#    Otherwise run the deterministic harness directly.
```

Recipe-driven (BYO agent):

```bash
# Your agent reads:
docs/UAT-LIFECYCLE/scenarios/L1/recipe-for-agent.md

# Your agent calls the MCP tools listed in the recipe + writes
# the result line to:
~/.iam-jit/uat-lifecycle/results.jsonl
```

Harness-driven (no agent needed):

```bash
bash docs/UAT-LIFECYCLE/scenarios/L1/deterministic-harness.sh
# Exit 0 = PASS; non-zero = FAIL.
# Result line appended to ~/.iam-jit/uat-lifecycle/results.jsonl.
```

## How to run the whole suite

```bash
# Sequential (safest; ~45-90 min total depending on scenarios).
for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  bash docs/UAT-LIFECYCLE/scenarios/L${n}/deterministic-harness.sh \
    || echo "L${n} FAILED — see ~/.iam-jit/uat-lifecycle/results.jsonl"
done

# Aggregate.
python docs/UAT-LIFECYCLE/aggregate.py \
  --results ~/.iam-jit/uat-lifecycle/results.jsonl \
  --out-md ~/.iam-jit/uat-lifecycle/summary.md \
  --out-jsonl ~/.iam-jit/uat-lifecycle/summary.jsonl
```

Parallel runs are supported only for scenarios that do NOT touch shared
state (see `HARNESS-SPEC.md` for the isolation contract). The current
default is sequential to keep the operator's mental model simple.

## How to interpret results

Each scenario emits one JSONL line per run with this shape:

```json
{
  "ts": "2026-05-24T10:15:33Z",
  "scenario_id": "L3",
  "status": "PASS",
  "evidence": {
    "pre_commit_sha": "abc123",
    "post_commit_sha": "def456",
    "audit_chain_continuous": true,
    "bouncer_version_check_match": true,
    "restart_duration_sec": 12.4
  },
  "env": {
    "os": "darwin",
    "container": "ubuntu:22.04",
    "iam_jit_version": "0.x.y",
    "iam_jit_sha": "f30001b"
  },
  "agent_used": "claude-code-with-max"
}
```

Statuses:

| Status | Meaning | Operator action |
|---|---|---|
| `PASS` | All assertions held; observable state matched the claim. | Log it; move on. |
| `FAIL` | At least one assertion did not hold; the failure is a real bug. | File a regression with the JSONL evidence line. |
| `SKIP` | Scenario could not run (Docker unavailable / LocalStack missing). | Note the gap; rerun when prerequisites are met. |
| `ERROR` | Harness itself crashed before producing a verdict. | Fix the harness; not a product bug. |

## How to file a regression when a scenario fails

1. Grab the failing JSONL line from `~/.iam-jit/uat-lifecycle/results.jsonl`.
2. Open a new issue in the iam-roles tracker titled
   `UAT-LIFECYCLE L{N} regression: <one-line summary>`.
3. Paste the JSONL line in the body + the relevant scenario spec
   section.
4. Apply severity per `[[mrr-flight-readiness-program]]` acceptance:
   * CRIT if it blocks a clean redeploy (L3 / L4 / L7 / L11).
   * HIGH if it degrades the operator experience after deploy
     (L5 / L8 / L9 / L13 / L14).
   * MED otherwise.
5. Per `[[push-policy-public-repo]]`: scrub any operator-identifying
   data from the evidence block before attaching.

## Recommended cadence

| When | Run what |
|---|---|
| Before every `iam-jit canary update` | L3 dry-run + L4 dry-run (cheap; ~5 min). |
| Weekly on the canary | Full L1-L15 suite (~60-90 min). |
| Before a public release / tag | Full suite + manual sign-off per MRR-8. |
| After any change to `cli_canary.py`, `cli_updates.py`, `bouncer_cli.py`, or the bouncer state schema | Re-run L3 + L4 + L7 + L9 + L12 at minimum. |

This cadence composes with `[[canary-redeploys-on-every-update]]`: every
merge to main triggers a canary redeploy AND a lifecycle UAT sweep, so
the update path is exercised constantly.

## Composes with

* `[[mrr-flight-readiness-program]]` — this is MRR-3's framework half.
* `[[bouncer-zero-llm-when-agent-in-loop]]` — operator's LLM, operator's
  agent; iam-jit provides MCP + specs.
* `[[canary-redeploys-on-every-update]]` — lifecycle UAT runs alongside
  the canary redeploy as the recurring quality gate.
* `[[role-effectiveness-corpus]]` — companion corpus on
  semantic-effectiveness; this one is the lifecycle complement.
* `docs/CONTRIBUTING.md` — state-verification convention; every harness
  assertion follows the "claim AND observable state" pattern.
* `[[ibounce-honest-positioning]]` — a PASS is honest only when the
  state-shape assertion fired; a SKIP that the operator forgets is a
  silent regression.
* `[[independence-as-security-property]]` — the framework runs entirely
  in operator-owned environments; no phone-home; results stay local.

## Out of scope (Stage A)

* Running the scenarios — that is Stage B, by separate agents.
* Adding scenarios for non-lifecycle concerns (those go to the
  role-effectiveness corpus or the closing-audit cluster).
* Wiring the framework into CI — manual operator-run for now; CI
  promotion happens after Stage B validates the harness shape.
