# Using long-range bouncer history to synthesise bouncer configs

Phase G of [[bouncer-informs-agent-informs-iam-jit]] (tasks
#436 + #437 + #438). This recipe shows how an agent turns a year+
window of bouncer audit history into a per-deployment-target
bouncer config — the "browse my last 2 years of kbouncer logs and
put together a prod K8s config" workflow.

**Key architectural property**: iam-jit provides the LOGS + the
DEPLOYMENT-TARGET TAXONOMY + the recipe. The AGENT (Claude / Cursor
/ Codex / Devin / etc.) does the actual SYNTHESIS — it reads the
historical events with its full context (operator intent,
codebase, CLAUDE.md, organisational conventions) and emits the
right bouncer config. iam-jit deliberately does not generate
configs from history; the agent does.

Per [[recommender-context-boundary]] iam-jit consumes context from
exactly two channels (AWS state + customer-supplied) — historical
audit IS the customer-supplied channel here, but the synthesis
judgment lives in the agent.

The pattern is harness-agnostic. The per-harness pages
([claude-code.md](claude-code.md), [cursor.md](cursor.md),
[codex.md](codex.md), [devin.md](devin.md),
[custom-harness.md](custom-harness.md)) reference this page for the
canonical conversation.

## The three primitives Phase G adds

| Tool | What it does | Where the synthesis lives |
|---|---|---|
| `iam-jit audit query --since 2y --extract-permissions --scope-filter` (#436) | Long-time-range bouncer-event query (year+ windows), with deployment-target scope filtering. Streams to a file for memory-bounded read of 100K+ events. Emits cold-tier warning when the window crosses ~90 days. | iam-jit only retrieves + filters. |
| `iam-jit deployment-targets {list,show}` (#437) | Look up the operator-declared deployment-target taxonomy (`prod-k8s` / `staging-k8s` / `prod-aws` / etc.). The `show NAME --classifier-only` form returns the exact dict shape `--scope-filter` accepts. | iam-jit only looks up. |
| `bounce_query_audit_long_range` + `bounce_deployment_targets_for_filter` (MCP siblings) | Same surface for agents. | Agent decides what to do with the returned events. |

There is intentionally **no** `iam-jit synthesize-config` CLI / MCP
tool. Synthesis is the agent's job; iam-jit's role is the data + the
taxonomy.

## Declare your deployment-targets first

Operator authors the taxonomy in `.iam-jit.yaml`:

```yaml
iam-jit:
  enabled: true
  deployment_targets:
    prod-k8s:
      bouncer: kbouncer
      description: production K8s clusters in 3 regions
      classifier:
        clusters: ["prod-east", "prod-west", "prod-eu"]
        accounts: ["999988887777"]
        namespaces: ["api-*", "payments-*", "data-*"]
    staging-k8s:
      bouncer: kbouncer
      classifier:
        clusters: ["staging-*"]
        accounts: ["111122223333"]
    prod-aws:
      bouncer: ibounce
      classifier:
        accounts: ["999988887777"]
        regions: ["us-east-1", "us-west-2"]
    prod-gbounce-targets:
      bouncer: gbounce
      classifier:
        hosts: ["*.prod.example.com", "api.production.io"]
```

The classifier dimensions intersect (AND across dimensions; OR
across globs within a dimension). Per
[[multi-account-region-cluster-use-case]] the dimensions cover the
full multi-account + multi-region + multi-cluster + multi-database
+ multi-host shape primary-persona buyers operate against.

## The three canonical asks

All three execute via the SAME agent-driven flow. Only the agent's
synthesis-side decision changes (positive allow-list vs scope-
isolated allow-list with negative denies vs pure negative deny-
list).

### Ask 1 — Positive synthesis from production history

> Operator: *"Browse my last 2 years of kbouncer logs and put
> together a kbouncer config for prod K8s."*

```text
Agent steps:
1. Look up prod-k8s deployment-target:
     iam-jit deployment-targets show prod-k8s \
         --classifier-only > /tmp/prod-classifier.json
   (or MCP: bounce_deployment_targets_for_filter(name="prod-k8s"))

2. Query 2 years of kbouncer audit, scoped + extracted:
     iam-jit audit query \
         --since 2y \
         --bouncer kbounce \
         --scope-filter "$(cat /tmp/prod-classifier.json)" \
         --extract-permissions \
         --output /tmp/prod-permissions.json
   (or MCP: bounce_query_audit_long_range(
       bouncer="kbouncer", since="2y",
       scope_filter={"clusters":["prod-*"], "accounts":["999..."]}
     ))

3. Optionally apply resource-map for staging→prod-style scope
   translation (Phase E #420 — only when the synthesis source +
   target environments differ).

4. Synthesise the kbouncer profile YAML using LLM context (the
   operator intent + the historical events + the
   organisation conventions in CLAUDE.md). Emit an allow-list
   that covers every action+resource pair observed in the
   prod-k8s scope.

5. Install via:
     kbounce profile install /tmp/prod-kbouncer-profile.yaml
   OR submit through iam_jit_request_role_from_synthesis
   (Phase E #421) with the evidence block:
     evidence: {
       bouncer_audit_window: {
         from: "<2y ago ISO>",
         to:   "<now ISO>",
         bouncer: "kbouncer"
       },
       codebase_references: ["CLAUDE.md", ".iam-jit.yaml"],
       operator_intent:
         "Synthesise prod K8s kbouncer config from 2yr history"
     }
```

The agent emits a positive allow-list. iam-jit's role is the data
+ the safety floor (the standard scorer still gates the request
when submitted through the role-request seam).

### Ask 2 — Scope-isolated synthesis (positive + implicit-negative)

> Operator: *"Browse my last year of bouncer logs and put together
> a kbouncer config to work on staging without touching anything in
> prod."*

```text
Agent steps:
1. Look up BOTH deployment-targets:
     bounce_deployment_targets_for_filter()  # full list
   (or two `deployment-targets show ... --classifier-only` calls)

2. Query the year of kbouncer audit with the staging scope filter:
     iam-jit audit query --since 1y --bouncer kbounce \
         --scope-filter '{"clusters":["staging-*"]}' \
         --extract-permissions --json \
         --output /tmp/staging-permissions.json

3. Synthesise the kbouncer profile YAML with TWO sections:
     allow_rules:
       # synthesised from the staging-scoped permission set
       - ...
     deny_rules:
       # DEFENSIVE BELT — the agent emits these from the
       # prod classifier so a staging profile NEVER touches prod
       # by accident, even if the agent's allow-list is too wide
       - { cluster: "prod-*" }
       - { account: "999988887777" }

   The agent decides the defensive shape from its full context;
   iam-jit just hands back the data + the classifier shapes.

4. Install + use on the staging workstation.
```

Per [[discovery-first-default]] the staging profile is the
guardrail; explicit prod denies are the belt.

### Ask 3 — Negative synthesis (block-what-was-done-elsewhere)

> Operator: *"Make a gbounce config that blocks the production URLs
> and APIs when I am working on staging or dev."*

```text
Agent steps:
1. Look up the production gbounce deployment-target:
     bounce_deployment_targets_for_filter(name="prod-gbounce-targets")

2. Query gbounce audit for events MATCHING the prod scope:
     iam-jit audit query --since 1y --bouncer gbounce \
         --scope-filter '{"hosts":["*.prod.example.com",
                                   "api.production.io"]}' \
         --extract-permissions \
         --output /tmp/prod-hosts-observed.json

3. Synthesise a gbounce config that:
     deny_hosts:    [observed prod hostnames]
     deny_rules:    [observed prod URL + method patterns]

   The agent has full context to convert the OBSERVED prod hosts
   into a deny-list for the staging-mode gbounce profile.

4. Install on the operator's staging machine. When the operator
   runs in staging mode, the bouncer blocks accidental requests
   to the historically-observed prod hosts.
```

Same primitives. Different synthesis decision. The agent picks the
mode based on operator intent; iam-jit's surface is mode-agnostic.

## Safety properties

* iam-jit-the-tool never auto-installs a long-range synthesised
  config. The agent emits; the operator (or the agent, under the
  operator's `posture: ambient` declaration) reviews + installs.
  This is by design — distinct from short-window
  `improve_profile` which is allowed to auto-install above
  threshold.
* Cold-tier queries surface an operator-visible warning
  (`--cold-tier-warn-days`, default 90). Long-range queries can be
  slow + costly; the operator sees that upfront.
* Per [[ibounce-honest-positioning]] the evidence chain is
  auditable: the operator can later inspect WHY a synthesised
  config carries the actions it carries — the bouncer's audit
  window + the deployment-target classifier + the operator-stated
  intent all live in the request's `evidence` block (when
  submitted through the Phase E role-request seam).
* Per [[scorer-is-ground-truth]] the synthesised config still goes
  through the standard scorer when submitted. The scorer isn't
  watered down because the request came from a long-range
  synthesis vs a hand-authored YAML.
* Per [[creates-never-mutates]] any role iam-jit creates is a new
  short-lived role; no existing customer IAM resource is mutated.

## What this pattern does NOT do

* Does not generate the bouncer config inside iam-jit. The agent
  has the full context (operator intent + codebase + CLAUDE.md +
  organisational conventions) and is the right layer to synthesise.
* Does not auto-install long-range-synthesised configs.
* Does not infer deployment-target boundaries from event content.
  The operator authors the taxonomy in `.iam-jit.yaml`; iam-jit
  looks up.
* Does not query cold-tier storage without an operator-visible
  warning.

## Smoke test

```bash
# 1. Declare your taxonomy.
cat > .iam-jit.yaml <<'YAML'
iam-jit:
  enabled: true
  deployment_targets:
    prod-k8s:
      bouncer: kbouncer
      classifier:
        clusters: ["prod-east"]
        accounts: ["999988887777"]
YAML

# 2. Verify the taxonomy is readable.
iam-jit deployment-targets list

# 3. Pull the classifier for use as scope-filter.
iam-jit deployment-targets show prod-k8s --classifier-only \
    > /tmp/scope.json

# 4. Run a long-range query scoped by the classifier.
#    (Bouncer must be running OR the call surfaces a per-bouncer note.)
iam-jit audit query \
    --bouncer kbounce \
    --since 2y \
    --scope-filter "$(cat /tmp/scope.json)" \
    --extract-permissions \
    --output /tmp/prod-perms.json

# 5. Stream raw events to file (verifies the streaming write path).
iam-jit audit query \
    --bouncer kbounce \
    --since 2y \
    --scope-filter "$(cat /tmp/scope.json)" \
    --output /tmp/raw-events.ndjson
wc -l /tmp/raw-events.ndjson

# 6. Hand /tmp/prod-perms.json to your agent and ask:
#    "Synthesise a kbouncer profile YAML from this permission set,
#     scoped to prod-k8s. Install via `kbounce profile install`."
#
#    The agent does the synthesis. iam-jit's job is done.
```

## References

* [[bouncer-informs-agent-informs-iam-jit]] — Phase E pattern
  extended from IAM-role-synthesis to bouncer-config-synthesis.
* [[historical-synthesis-phase-g]] — the re-scoped Phase G memo
  that motivates this recipe (the synthesise-config CLI was
  rejected; this recipe is the replacement).
* [[recommender-context-boundary]] — iam-jit consumes exactly two
  context channels; the agent's synthesised config is the
  customer-supplied channel.
* [[multi-account-region-cluster-use-case]] — the founder + primary-
  persona use case that motivates the deployment-target taxonomy.
* [[creates-never-mutates]] — iam-jit creates new short-lived
  roles; never modifies existing IAM resources.
* [[scorer-is-ground-truth]] — synthesised requests still go through
  the standard scorer when submitted.
* [[discovery-first-default]] — the safe default is observation;
  deny is opt-in.
* Phase E recipe: [bouncer-to-role-pattern.md](bouncer-to-role-pattern.md)
  — the per-session role-synthesis pattern this Phase G recipe
  extends to year+ windows.
