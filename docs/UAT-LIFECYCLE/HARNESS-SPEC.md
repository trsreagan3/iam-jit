# UAT Lifecycle Harness — Technical Spec

> The contract between the scenario specs and the operator's runner.
> If you're writing a new scenario, this is the contract you implement.
> If you're running scenarios, this is what you can rely on.

## Design principles

1. **Operator-portable.** No assumption that the operator is on macOS,
   has a specific GitHub identity, has Docker, or has Anthropic API
   credentials. Per `[[bouncer-zero-llm-when-agent-in-loop]]` the
   operator's agent handles all LLM reasoning.
2. **Isolated.** Lifecycle scenarios MUST NOT touch the operator's
   live canary state (`~/.iam-jit/canary/`) or any daily-use
   directories. Each scenario gets its own root.
3. **State-verifying.** Per `docs/CONTRIBUTING.md` every harness
   assertion checks BOTH the reported status AND the observable
   state change. A green status without state evidence is rejected
   as `ERROR` not `PASS`.
4. **Honest.** Per `[[ibounce-honest-positioning]]` if a scenario
   cannot validate something, the harness emits `SKIP` with a
   `reason` field. It MUST NOT emit `PASS` for the un-validated
   path.
5. **No phone-home.** Per `[[independence-as-security-property]]`
   results stay on the operator's machine; the harness never POSTs
   to any iam-jit-the-company endpoint.

## Isolation model

The harness supports two isolation modes. Scenarios declare which
modes they support in their `spec.md` `Prerequisites` block.

### Mode A — Docker container (preferred)

Verified Linux-smoke compatible per #485 + commit `5a5665f`
(`fix(canary): Linux-portability — drop lsof dependency in
_restart_bouncers`). Each scenario spawns a fresh container with:

* base image: `ubuntu:22.04` (matches the #485 smoke baseline)
* mounted source: the operator's iam-roles checkout (read-only) as
  `/src/iam-roles`; same for the operator's gbounce checkout when
  the scenario touches gbounce. The harness resolves checkout
  paths via the same `IAM_JIT_CANARY_*_REPO` env-var override
  pattern `src/iam_jit/cli_canary.py` uses, so no operator paths
  are hardcoded in this spec.
* working dir inside container: `/work` (isolated tmpfs)
* iam-jit state dir inside container: `/root/.iam-jit/`
  (completely separate from the host operator's `~/.iam-jit/`)
* network: bridge with host port range `17400-17499` (deliberately
  distinct from the live canary's `7400-7499` per the safety
  constraint)

Container lifecycle:

```bash
# IAM_JIT_CANARY_IAM_ROLES_REPO + IAM_JIT_CANARY_GBOUNCE_REPO point
# at the operator's local checkouts; defaults match the sibling-
# checkout layout cli_canary.py uses.
docker run --rm -d \
  --name iam-jit-uat-${scenario_id}-$$ \
  -v "${IAM_JIT_CANARY_IAM_ROLES_REPO}":/src/iam-roles:ro \
  -v "${IAM_JIT_CANARY_GBOUNCE_REPO}":/src/gbounce:ro \
  -e IAM_JIT_UAT_SCENARIO=${scenario_id} \
  -e IAM_JIT_CANARY_IAM_ROLES_REPO=/work/iam-roles \
  -e IAM_JIT_CANARY_GBOUNCE_REPO=/work/gbounce \
  -p 17400-17499:17400-17499 \
  ubuntu:22.04 \
  sleep 3600
```

The harness ALWAYS `docker rm -f` on exit (success OR failure) so
nothing leaks. The `--rm -d` pair guarantees cleanup even if the
operator SIGINTs the runner.

### Mode B — ephemeral test directory (fallback when Docker unavailable)

When `docker` is not on PATH, the harness falls back to running on
the host with an isolated state root:

* state root: `~/.iam-jit/uat-lifecycle/{scenario-id}/`
* explicit env vars: `IAM_JIT_HOME=~/.iam-jit/uat-lifecycle/{scenario-id}`
  + `IAM_JIT_AUDIT_DB=$IAM_JIT_HOME/audit.db` + per-bouncer-equivalents
* port range: `17400-17499` (still distinct from canary; collisions
  with the live canary's `7400-7499` are impossible by construction)
* on failure the scenario directory is preserved for forensics; on
  success it is `rm -rf`ed unless `IAM_JIT_UAT_KEEP=1`

Mode B is REQUIRED for L11 (clean uninstall) so the harness can
verify "nothing left on disk" — a containerized uninstall is not
informative for a host-level cleanup claim. Mode B is ACCEPTABLE
fallback for everything else.

### Mode selection

Each scenario's `spec.md` lists supported modes. The harness picks:

1. Mode A if `docker` is on PATH AND the scenario supports it.
2. Mode B if Mode A is unavailable AND the scenario supports B.
3. `SKIP` with `reason: "docker required for L{N}; not available"`
   if neither mode is supported.

## State directory layout

Inside the scenario's state root (`/root/.iam-jit/` in Mode A;
`~/.iam-jit/uat-lifecycle/{scenario-id}/` in Mode B):

```
.iam-jit/
├── audit.db                    # SQLite audit DB
├── dynamic-denies.yaml         # cross-product deny rules
├── profiles/                   # installed profiles
├── threat-feed-state/          # threat-feed ledger
├── canary/                     # canary-emulated state (separate
│                               #   from live canary by construction —
│                               #   this is INSIDE the UAT root)
│   ├── issues.jsonl
│   ├── notes.md
│   ├── status.json
│   └── .iam-jit.yaml
└── uat-meta/                   # harness internals
    ├── pre-snapshot.tar.gz     # pre-action state snapshot
    └── post-snapshot.tar.gz    # post-action state snapshot
```

The operator's live canary at `~/.iam-jit/canary/` is **never**
read or written by the harness. The UAT root is always
distinguishable by the `uat-meta/` subdirectory.

## Result JSONL shape

One line per scenario run, appended to
`~/.iam-jit/uat-lifecycle/results.jsonl`. Schema:

```json
{
  "ts": "ISO8601 UTC",
  "scenario_id": "L1..L15",
  "status": "PASS|FAIL|SKIP|ERROR",
  "evidence": {
    "...": "scenario-specific; documented in each scenario's spec.md"
  },
  "env": {
    "os": "darwin|linux",
    "kernel": "string",
    "container": "ubuntu:22.04|null",
    "iam_jit_version": "string",
    "iam_jit_sha": "string",
    "gbounce_sha": "string|null",
    "docker_version": "string|null"
  },
  "agent_used": "string|null",
  "reason": "string|null",
  "duration_sec": "number"
}
```

Field rules:

* `status` is required; one of the four enum values.
* `evidence` is required for `PASS` and `FAIL`; MUST contain at
  least one OBSERVABLE-STATE field (per the convention) — not just
  a status string echo.
* `reason` is required for `SKIP` and `ERROR`; explains why no
  verdict could be reached.
* `agent_used` is `null` for pure-harness runs and a free-form
  string identifying the agent + LLM for recipe-driven runs
  (e.g. `"claude-code+max"`, `"cursor+gpt4o"`).
* Per `[[push-policy-public-repo]]` sanitize any evidence values
  that contain operator-identifying paths before committing
  results to a public tracker.

## Shared utilities

Helpers live under `docs/UAT-LIFECYCLE/fixtures/` and
`docs/UAT-LIFECYCLE/scenarios/_lib/` (created lazily as scenarios
need them). The Stage A framework lays down the contract; Stage B
agents may add helpers as they implement scenarios.

| Helper | Purpose | Where |
|---|---|---|
| `_lib/container.sh` | spin up/tear down the Docker container | scenarios reference it |
| `_lib/state.sh` | snapshot + diff the state dir | called before+after actions |
| `_lib/result.sh` | emit the JSONL line | called on every exit path |
| `_lib/wait_for_healthz.sh` | poll a bouncer's healthz endpoint | reused across L3/L7/L12 |
| `fixtures/audit-events/` | synthetic audit-event generators | input for L5/L9 |
| `fixtures/mock-creds/` | `AKIATEST...` mock AWS creds | input for L1/L13/L14 |
| `fixtures/threat-feed/` | signed test threat-feed payloads + public test key | input for L6 |
| `fixtures/workflows/` | realistic NL workflow templates | input for L5 |
| `fixtures/state-snapshots/` | pre-state snapshots for L7/L9 | restored at scenario start |

## Sanitization contract

Per `[[push-policy-public-repo]]` the harness must NEVER write any
of the following to a result that could be shared:

* operator's real `/Users/...` paths (rewrite to `/HOME/`)
* operator's git identity (rewrite to `<operator>`)
* operator's AWS account IDs, role ARNs, region names from real
  AWS calls (no real AWS calls are made; if any appear they are a
  bug — emit ERROR)
* operator's IP address or hostname
* any string matching the operator's configured marker list
  (real-name, employer-name, OS-username — see `OPERATOR_MARKERS`
  env var in `_lib/sanitize.sh`)

The sanitizer is implemented in `_lib/sanitize.sh` and is called
by every `_lib/result.sh` invocation. Sanitization failures are
themselves results — emit `ERROR` rather than write tainted
output.

## Aggregation

`aggregate.py` reads `~/.iam-jit/uat-lifecycle/results.jsonl` and
produces two outputs:

* `~/.iam-jit/uat-lifecycle/summary.md` — operator-readable matrix
  (scenarios on rows, recent runs on columns; PASS/FAIL/SKIP cells
  with timestamps + brief evidence).
* `~/.iam-jit/uat-lifecycle/summary.jsonl` — agent-readable shape;
  one line per scenario with the most recent run + a count of each
  status over the last 30 days. Next-session agents can ingest
  this for context.

The aggregator NEVER modifies `results.jsonl` itself — append-only
discipline matches the canary issues log.

## Adding a new scenario (Stage B+ guidance)

1. Pick the next free `L{N}` id.
2. `mkdir -p docs/UAT-LIFECYCLE/scenarios/L${N}` with three files:
   `spec.md`, `recipe-for-agent.md`, `deterministic-harness.sh`
   (or `.py`).
3. Spec must enumerate: what it tests, pass/fail criteria,
   prerequisites, supported isolation modes, expected duration,
   evidence-block schema.
4. Recipe must be MCP-callable: the operator's agent should be
   able to follow it with only `mcp_server.py`'s tool list +
   `docs/MCP-RECIPES.md`.
5. Harness must conform to the JSONL shape + the sanitization
   contract + the state-verification convention.
6. Add a row to the matrix in `aggregate.py`'s scenario list.

## Composes with

* `[[bouncer-zero-llm-when-agent-in-loop]]` — the recipe half;
  harness is the LLM-free deterministic floor.
* `docs/CONTRIBUTING.md` — state-verification convention; this
  spec extends it from unit tests to lifecycle scenarios.
* `[[push-policy-public-repo]]` — sanitization contract.
* `[[independence-as-security-property]]` — local-only result
  storage; no phone-home.
* `[[canary-redeploys-on-every-update]]` — operational layer
  this harness exercises.
