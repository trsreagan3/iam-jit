# Using bouncer activity to provision roles — the canonical pattern

Phase E of [[bouncer-informs-agent-informs-iam-jit]] (tasks #419–#422).
This recipe shows how an agent turns bouncer observation into an
iam-jit role request — the "I just did staging through the bouncer;
generate the equivalent role for prod" workflow.

The pattern is harness-agnostic. The per-harness pages
([claude-code.md](claude-code.md), [cursor.md](cursor.md),
[codex.md](codex.md), [devin.md](devin.md),
[custom-harness.md](custom-harness.md)) reference this page for the
canonical conversation.

## The three primitives

| MCP tool | What it does | Who has the context |
|---|---|---|
| `bounce_extract_permissions_from_audit` | Reads a window of bouncer audit events; returns `[{action, resources, count}]` + `observed_scope`. | iam-jit reads the bouncer's audit-export channel. No inference about intent. |
| `iam_jit_resource_map` | Applies a NAMED mapping (e.g. `staging_to_prod`) declared by the operator in `.iam-jit.yaml`. Pure substitution. | iam-jit applies operator-declared substitution; agent picks the mapping name based on operator intent. |
| `iam_jit_request_role_from_synthesis` | Validates a REQUIRED evidence block, scores the synthesised policy, routes through auto-approve / pending. | Agent assembles inputs + supplies evidence chain; iam-jit applies safety floors. |

Per [[recommender-context-boundary]] iam-jit deliberately does NOT
read source code, infer environment names, or guess what an operator
meant. The agent (Claude / Cursor / Codex / Devin / etc.) has full
local context (bouncer logs + codebase + intent + CLAUDE.md) — it
synthesises; iam-jit provisions.

## The canonical conversation

```
Operator:  I just did staging deployment work through the bouncer.
           Generate the equivalent role for prod.

Agent:     [calls bounce_extract_permissions_from_audit(bouncer="ibounce",
                                                       since="1h")]

           Found 47 events in the last hour. Extracted permissions:
           - s3:GetObject  on staging-deploy-* (12 events)
           - lambda:UpdateFunctionCode on staging-lambda-* (8 events)
           - iam:UpdateAssumeRolePolicy on lambda-staging-* (3 events)
           - cloudwatch:PutMetricAlarm on staging-* (5 events)
           - sns:Publish on staging-deploy-notifications (3 events)
           ... (16 more actions)

           [reads CLAUDE.md, finds:
              resource_mappings:
                staging_to_prod:
                  account_id: { "111122223333": "999988887777" }
                  region: { "us-east-1": "us-west-2" }
                  name_patterns:
                    - { match: "staging-*", replace: "prod-*" }
           ]

           [calls iam_jit_resource_map(permissions=<above>,
                                       using="staging_to_prod")]

           Translated:
           - s3:GetObject  on prod-deploy-* (12)
           - lambda:UpdateFunctionCode on prod-lambda-* (8)
           ... (account 111122223333 → 999988887777, region us-east-1 → us-west-2)

           [calls iam_jit_request_role_from_synthesis(
              permissions=<translated>,
              observed_scope={"account_ids":["999988887777"],
                              "regions":["us-west-2"]},
              justification="Replicate staging deployment in prod per
                             operator request 2026-05-23 14:02",
              evidence={
                "bouncer_audit_window": {
                  "from": "2026-05-23T13:00:00Z",
                  "to": "2026-05-23T14:00:00Z",
                  "bouncer": "ibounce"
                },
                "codebase_references": [
                  "CLAUDE.md",
                  "terraform/prod/main.tf"
                ],
                "operator_intent": "Replicate staging deployment in prod"
              },
              requested_duration="PT3H",
              resource_mapping_applied="staging_to_prod",
           )]

           iam-jit response:
           - request_id: rfs_01HQ8...
           - status: pending_operator_approval
             (score 6/10; threshold 4/10 — admin-adjacent due to
              iam:UpdateAssumeRolePolicy)
           - audit_event_id: evt_rfs_4f8a...
           - Run `iam-jit pending review rfs_01HQ8...` to approve

           Want me to walk through the synthesis before you approve?
```

## The REQUIRED evidence block

Per [[ibounce-honest-positioning]] `iam_jit_request_role_from_synthesis`
REJECTS any request without a complete `evidence` block:

```json
{
  "bouncer_audit_window": {
    "from": "<ISO 8601>",
    "to":   "<ISO 8601>",
    "bouncer": "<ibounce | kbounce | dbounce | gbounce>"
  },
  "codebase_references": [
    "<path 1>",
    "<path 2>"
  ],
  "operator_intent": "<the operator's own words>"
}
```

If ANY of these fields is missing or empty, the request returns
`status: "rejected"` with `rejection_code: "missing_evidence_field"`
(or `missing_evidence_block` / `invalid_audit_window` / etc.). An
audit row is STILL emitted — the auditor reading "why did this
synth request fail at 14:02" should always find the rejection
explained, not a silent gap.

**Why this discipline:** without the evidence chain, a synthesised
role request is indistinguishable from a hand-authored one in the
audit log. With it, the operator can later inspect WHY this role was
issued and trace it back to a specific bouncer window + a specific
operator-stated intent.

## Safety properties

* The synthesised request goes through the SAME scorer + auto-approve
  gate every other iam-jit request does. Per [[scorer-is-ground-truth]]
  the scorer doesn't get watered down because the request came from a
  bouncer-audit synthesis instead of a hand-authored YAML.
* High-scope requests auto-route to `pending_operator_approval` —
  iam:* actions, admin-adjacent action sets, broad `Resource: "*"`
  patterns all push the score above the auto-approve threshold.
* Per [[creates-never-mutates]] any STS credentials returned belong
  to a NEW short-lived role iam-jit just created. No existing
  customer IAM resource is modified.
* The audit row captures the FULL evidence chain (bouncer window +
  codebase references + operator intent + the synthesised
  permissions + the resource-mapping name if used). One row per
  attempt — rejections too.

## When to use each primitive directly

* **Just want to see what the bouncer observed?** Use `iam-jit audit
  query --since 1h --bouncer ibounce` (returns raw OCSF events).
* **Want the aggregated permission set without a role request?** Add
  `--extract-permissions` to the same query, OR call
  `bounce_extract_permissions_from_audit` from MCP.
* **Want to translate scope without requesting a role?** Use
  `iam-jit resource-map --from-permissions perms.json --using
  staging_to_prod` (CLI) or `iam_jit_resource_map` (MCP).
* **Want the full bouncer→agent→iam-jit loop?** Compose all three as
  shown in the canonical conversation above.

## What this pattern does NOT do

* Does not auto-generate role requests from bouncer audit without an
  agent in the loop. The bouncer audit is EVIDENCE; the synthesis is
  JUDGMENT; judgment lives in the agent.
* Does not infer "staging" or "prod" from resource names at the
  iam-jit layer. The operator declares the mapping; the agent picks
  it by name; iam-jit substitutes.
* Does not skip the safety floor. Synthesised requests still get
  scored + still route to pending above threshold.
* Does not require operator approval for the synthesis ITSELF — the
  operator can opt-in to view the synthesised request before it's
  submitted (see the "Want me to walk through" prompt in the
  canonical conversation), but the agent can also submit directly
  when intent is unambiguous.

## Smoke test

Once you have a bouncer running + an `.iam-jit.yaml` with a
`resource_mappings` block:

```bash
# Generate some bouncer traffic (drive a few AWS calls via the
# bouncer's loopback endpoint).

# Extract the permission set.
iam-jit audit query --since 5m --bouncer ibounce \
    --extract-permissions \
    > /tmp/staging_perms.json

# Translate to prod scope.
iam-jit resource-map \
    --from-permissions /tmp/staging_perms.json \
    --using staging_to_prod \
    > /tmp/prod_perms.json

# At this point an MCP-capable agent calls
# iam_jit_request_role_from_synthesis with the contents of
# /tmp/prod_perms.json + a justification + an evidence block.
```

The flow is the same across all four supported harnesses. See the
per-harness pages for the harness-specific MCP wiring.

## References

* [[bouncer-informs-agent-informs-iam-jit]] — the founder direction
  that motivates Phase E.
* [[ibounce-honest-positioning]] — why the evidence block is required.
* [[scorer-is-ground-truth]] — why iam-jit doesn't second-guess the
  agent's contextual synthesis at the scorer layer.
* [[recommender-context-boundary]] — the two-channel rule for iam-jit
  context consumption. The agent's synthesised request IS the
  customer-prompt channel; the bouncer-observation feeds the agent,
  not iam-jit directly.
* [[creates-never-mutates]] — credentials returned belong to a NEW
  short-lived role; nothing in the customer's existing IAM is mutated.
