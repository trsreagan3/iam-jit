# Dynamic Deny Rules (#324) — Design

> **Status:** SHIPPED (all 6 slices, 2026-05-22) — #324a (ibounce),
> #324b (kbouncer), #324c (dbounce), #324d (gbounce), #324e (unified
> `iam-jit deny` CLI + MCP fan-out), and #324f (recommender
> Deny-injection + role-effectiveness re-grade) are LIVE. The CLI +
> MCP tools call through to the live YAML store + per-bouncer reload
> endpoints; the iam-jit recommender consults the same YAML at
> role-issuance time and embeds an explicit `Deny` statement per
> active rule into every newly-issued role's inline policy. This
> document is the canonical contract those implementations converge
> against — DO NOT diverge from the wire shapes below without
> updating this doc first.

## TL;DR

Dynamic deny rules let an operator (or an agent on the operator's behalf
via MCP) install a short-lived deny across the whole Bounce suite in
ONE command:

```
$ iam-jit deny add --target 'arn:aws:s3:::prod-*' --reason 'incident #4711 contains prod' --duration 3h
```

That target gets routed to every applicable bouncer (ibounce here),
written to `~/.iam-jit/dynamic-denies.yaml`, hot-reloaded by the
running proxy, AND fed to the iam-jit recommender so any role issued
during the deny window embeds the same constraint as an explicit
`Deny` statement. Defense-in-depth: bouncer denies at request time
+ role denies at credential-evaluation time.

## Why this exists

Post-`[[discovery-first-default]]` (§A21, 2026-05-22) the four bouncers
default to discovery-mode pass-through. Static `safe-default` profiles
graded out at **23.1%** role-effectiveness against the launch corpus
because they could not carve by bucket / table / secret / namespace
name. gbounce alone graded at **66.7%** — the variable was that
gbounce's `deny_hosts` were OPERATOR-SET OPT-IN denies authored at the
moment of need, not blanket safe-defaults. Dynamic deny rules generalise
that gbounce ergonomic across the suite:

1. **Conversational ergonomics.** "Claude, make sure this doesn't
   touch prod for 3h." → MCP call → admin-action OCSF event →
   bouncer + recommender pick up the deny atomically.
2. **Defense-in-depth.** Bouncer + role both carry the constraint.
   If one path is bypassed (agent skips ibounce; agent uses a
   role minted before the deny), the other still holds.
3. **Audit-first.** Every add / remove / expiry is an admin-action
   OCSF event — same shape as profile install / preset apply, so the
   SIEM filter `unmapped.iam_jit.admin_action.kind:"dynamic_deny.*"`
   answers "what denies were live on date X?".
4. **Cross-product fan-out.** ONE pattern (`arn:aws:s3:::prod-*`,
   `payments-db-prod.us-east-1.rds.amazonaws.com`, `kube-system`,
   `api.openai.com`) lands on the right bouncer(s) without the
   operator picking which proxy to call.

## What ships in #324

| Slice  | Scope                                                                                  | Status           |
|--------|----------------------------------------------------------------------------------------|------------------|
| #324a  | **ibounce** — ARN-target matcher + YAML watcher + decision-pipeline wiring + OCSF      | shipped          |
| #324b  | **kbouncer** — namespace/cluster matcher + YAML watcher + parity with #324a            | shipped          |
| #324c  | **dbounce** — hostname / RDS endpoint matcher + YAML watcher                           | shipped          |
| #324d  | **gbounce** — URL/hostname glob matcher (reuses #314 `deny_hosts` shape) + YAML watcher| shipped          |
| #324e  | **iam-jit** — unified CLI + MCP fan-out + cross-bouncer e2e                            | shipped          |
| #324f  | **iam-jit recommender** — `Deny`-injection at role-issuance + role-effectiveness re-grade | shipped       |

The unified CLI shipped with #324e replaces the skeleton — `iam-jit
deny add | list | remove | show` now:

- Reads + atomically rewrites `~/.iam-jit/dynamic-denies.yaml`
  (write-temp + rename + 0600).
- Resolves each target pattern via
  [`src/iam_jit/dynamic_denies/resolver.py`](../src/iam_jit/dynamic_denies/resolver.py)
  (shipped with #324e) and routes the rule to the right bouncer(s).
- POSTs each affected bouncer's `/admin/dynamic-denies/reload`
  endpoint so the rule is enforced immediately.
- Surfaces unreachable bouncers honestly (warning + retry hint) but
  exits 0 — the YAML file IS the source of truth per
  `[[ibounce-honest-positioning]]`.

The MCP tool surface ships alongside in the same slice: `bounce_deny_add`,
`bounce_deny_list`, `bounce_deny_remove` (see the MCP section below).

## CLI surface

> **NOTE — code path.** The skeleton lives at
> `src/iam_jit/cli_deny.py` (the existing repo convention is flat
> `cli_*.py` modules registered onto the top-level click group — see
> `cli_audit_query.py`, `cli_session_replay.py`, `cli_remote.py`). The
> original spec called for `src/iam_jit/cli/deny.py`; the rename
> avoids a module-vs-package collision with the existing
> `src/iam_jit/cli.py`.

### `iam-jit deny add`

```
iam-jit deny add \
    --target PATTERN [--target PATTERN ...]  \
    --reason 'short string surfaced in 403 + audit' \
    --duration 30m|3h|7d|permanent \
    [--applies-to-recommender / --no-applies-to-recommender]  \
    [--bouncer ibounce|kbounce|dbounce|gbounce  ...]  \
    [--json]
```

Adds ONE deny rule with one-or-more targets. The target resolver
classifies each pattern by shape (see below) and writes the
destination(s) into the rule's `applied_to`. `--bouncer` overrides
the resolver for ambiguous cases; the resolver refuses to write a
rule it can't classify.

**Sample output (success):**

```text
✓ added dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C
  targets:     arn:aws:s3:::prod-*
  applied_to:  ibounce
  reason:      incident #4711 contains prod
  duration:    3h
  expires_at:  2026-05-22T19:13:48Z
  written to:  ~/.iam-jit/dynamic-denies.yaml
  recommender: enabled — JIT roles issued in this window embed an
               explicit Deny matching the targets.
```

**Sample output (`--json`):**

```json
{
  "id": "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C",
  "targets": ["arn:aws:s3:::prod-*"],
  "applied_to": ["ibounce"],
  "expires_at": "2026-05-22T19:13:48Z",
  "applies_to_recommender": true
}
```

### `iam-jit deny list`

```
iam-jit deny list [--bouncer NAME ...] [--include-expired] [--json]
```

Tabular listing by default (id / targets / applied_to / expires_in
/ reason). `--json` returns the full rule objects per the schema.

### `iam-jit deny remove`

```
iam-jit deny remove ID [ID ...] [--reason 'audit-trail metadata'] [--json]
```

Removes by id. Removal is an admin-action audit event regardless of
whether the rule was expiring on its own. `--reason` is optional but
strongly recommended for org-distributed rule overrides.

### `iam-jit deny show`

```
iam-jit deny show ID [--json]
```

Detailed view of one rule including provenance (`source`,
`org_distributed_url`) + the full audit trail for that rule (add
event, any modification events, scheduled-expiry event).

## MCP tool surface

Three tools, one per write path + one read path. The MCP server
(per `src/iam_jit/mcp_server.py`) gains:

### `bounce_deny_add`

```json
{
  "name": "bounce_deny_add",
  "description": "Install a deny rule across the Bounce suite. Resolves target patterns to the right bouncer(s). Surfaces in 403 deny_reason + admin-action OCSF audit.",
  "inputSchema": {
    "type": "object",
    "required": ["targets", "reason", "duration"],
    "properties": {
      "targets":  {"type": "array", "items": {"type": "string"}, "minItems": 1},
      "reason":   {"type": "string", "minLength": 1},
      "duration": {"type": "string", "description": "Go duration (e.g. 30m, 3h, 7d) or 'permanent'."},
      "applies_to_recommender": {"type": "boolean", "default": true},
      "bouncer_override": {
        "type": "array",
        "items": {"type": "string", "enum": ["ibounce", "kbounce", "dbounce", "gbounce"]}
      }
    }
  }
}
```

### `bounce_deny_list`

Returns the active rules per the schema.

### `bounce_deny_remove`

```json
{
  "name": "bounce_deny_remove",
  "inputSchema": {
    "type": "object",
    "required": ["id"],
    "properties": {
      "id":     {"type": "string"},
      "reason": {"type": "string"}
    }
  }
}
```

## Conversational examples

**Example 1 — fast deny mid-incident.**

```
operator: Claude, make sure nothing touches prod buckets for the next 3 hours.
agent:    Tool: bounce_deny_add(
            targets=["arn:aws:s3:::prod-*"],
            reason="operator: lockout while we triage incident #4711",
            duration="3h"
          )
agent:    Added dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C. The ibounce proxy is
          now denying any S3 call against arn:aws:s3:::prod-* until
          2026-05-22T19:13:48Z. The iam-jit recommender will embed
          this as an explicit Deny statement in any role it issues
          during the window.
```

OCSF admin-action event emitted:

```json
{
  "class_uid": 6003,
  "activity_id": 1,
  "status": "Success",
  "unmapped": {
    "iam_jit": {
      "event_type": "ADMIN_ACTION",
      "admin_action": {
        "kind": "dynamic_deny.added",
        "source": "mcp",
        "actor": "operator@org.com",
        "target": {"kind": "dynamic_deny_rule", "id": "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"},
        "details": {
          "targets": ["arn:aws:s3:::prod-*"],
          "applied_to": ["ibounce"],
          "duration": "3h",
          "expires_at": "2026-05-22T19:13:48Z",
          "applies_to_recommender": true
        }
      }
    }
  }
}
```

**Example 2 — agent requesting a self-applied deny.**

```
agent:    I'm about to run an ad-hoc Postgres migration on the
          staging cluster. I want to make sure I can't accidentally
          touch payments-db-prod while I'm doing it.
agent:    Tool: bounce_deny_add(
            targets=["payments-db-prod.us-east-1.rds.amazonaws.com"],
            reason="agent self-applied lockout during staging migration",
            duration="45m"
          )
agent:    Added dd_01HZ8WPRBZ6CG. dbounce will now refuse connections
          to payments-db-prod for the next 45 minutes; gbounce will
          also block CONNECT to that hostname.
```

**Example 3 — explicit removal post-incident.**

```
operator: Claude, the incident is resolved. Lift the prod-bucket lockout.
agent:    Tool: bounce_deny_list()  → [dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C, ...]
agent:    Tool: bounce_deny_remove(id="dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C",
            reason="incident #4711 resolved")
agent:    Removed. Bouncers reverted to pre-deny behavior; the next
          role issued by iam-jit will no longer carry the embedded
          Deny.
```

## Cross-protocol target resolver

The resolver in `iam-jit deny add` (#324e) classifies each target
pattern by shape and writes the destination(s) into the rule's
`applied_to`. Heuristics, evaluated top-to-bottom:

| Pattern shape                                                                                  | Routes to            | Notes                                                                                            |
|------------------------------------------------------------------------------------------------|----------------------|--------------------------------------------------------------------------------------------------|
| `arn:aws:*:*:*:*` (optionally with `*` wildcards on the resource segment)                      | ibounce              | Canonical AWS-call gate. ARN parser per `botocore.utils.ArnParser`; wildcards on resource only. |
| `*.amazonaws.com`, `*.rds.amazonaws.com`, `<host>.<region>.rds.amazonaws.com`                  | dbounce + gbounce    | RDS endpoints land on BOTH (dbounce for the SQL session; gbounce for CONNECT during clients).   |
| `*.<custom-domain>.com` / IP literal / CIDR                                                    | gbounce              | Generic egress block — reuses the gbounce `deny_hosts` glob from #314.                          |
| Kubernetes namespace name (matches `^[a-z0-9-]+$`, no dots) OR `cluster:<name>`                | kbounce              | Heuristic: hostname-shaped strings without dots OR explicit `cluster:` / `namespace:` prefix.   |
| `secret:<arn or name>` (ARN OR plain Secrets Manager name)                                     | ibounce              | Convenience shortcut for the common "lock out a specific secret" pattern.                       |
| `https://<host>/...`, `http://<host>/...`                                                      | gbounce              | URL form — exact path/glob matched per gbounce's URL-matcher.                                   |
| Bare hostname (`api.openai.com`, `metadata.google.internal`)                                   | gbounce              | Defaults to gbounce since arbitrary hostnames imply HTTP egress.                                |
| **ambiguous: no shape matches**                                                                 | (rejected)           | Add-time error: `cannot classify target '<pattern>'; pass --bouncer NAME to override`.          |
| **ambiguous: multiple shapes match**                                                            | union, with warning  | Resolver emits the union into `applied_to` + writes a stderr warning naming each match.         |

Operators with non-default routing override with explicit `--bouncer NAME`
(repeatable). Per `[[cross-product-agent-parity]]` the same resolver
ships in the MCP tool path so an agent gets identical routing as a
typed CLI invocation.

## Persistence schema

The file lives at `~/.iam-jit/dynamic-denies.yaml`. Exact shape is
specified by [`schemas/dynamic-denies-v1.json`](schemas/dynamic-denies-v1.json);
the field names + types here MUST match it byte-for-byte.

```yaml
schema_version: "1.0"
product: iam-jit-dynamic-denies
exported_at: "2026-05-22T16:13:48Z"
source_hostname_hash: "ab12cd34ef56"
denies:
  - id: dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C
    targets:
      - "arn:aws:s3:::prod-*"
    reason: "operator: lockout while we triage incident #4711"
    duration: "3h"
    added_by: "operator@org.com"
    added_at: "2026-05-22T16:13:48Z"
    expires_at: "2026-05-22T19:13:48Z"
    applied_to:
      - ibounce
    applies_to_recommender: true
    source: "mcp"
```

**File-on-disk requirements:**

- **Path:** `~/.iam-jit/dynamic-denies.yaml`. Override via
  `IAM_JIT_DYNAMIC_DENIES_PATH` (matches the pattern of
  `IAM_JIT_BOUNCER_*` env vars elsewhere).
- **Permissions:** 0600 (read/write owner only). The writer enforces
  this on every write; the reader refuses to load a file with looser
  perms + emits a `dynamic_deny.file_perms_loose` admin-action event.
- **Format:** YAML 1.2, round-trippable (preserves operator comments).
  Library choice: `ruamel.yaml` (already a dependency).
- **Watcher:** every running bouncer subscribes to
  fsevents (macOS) / inotify (Linux) for the file. Hot reload is
  atomic: parse-into-memory THEN swap; never mutate the live decision
  store partway through a parse.

## Defense-in-depth model

Dynamic deny rules apply at TWO points:

1. **Request time, in the bouncer.** The proxy (ibounce / kbounce /
   dbounce / gbounce) consults its in-memory dynamic-deny set on every
   request. A match returns the appropriate per-protocol deny payload
   (`403` with `deny_reason: "dynamic-deny: <id> — <reason>"` for
   ibounce/gbounce; SQL session refused with the same string for
   dbounce; admission webhook rejection for kbounce) AND emits an
   OCSF audit event with `unmapped.iam_jit.deny_reason` naming the
   rule id.

2. **Role-issuance time, in the iam-jit recommender (#324f SHIPPED).**
   When `src/iam_jit/provision.py` assembles the inline policy for a
   newly-issued role, it calls
   `src/iam_jit/dynamic_denies/recommender.py::build_deny_statements`
   on the active rule set + appends one `Deny` statement per
   eligible rule (`applied_to` contains `ibounce` AND
   `applies_to_recommender` is true AND `expires_at` is in the future
   AND at least one ARN-shaped target). Each statement carries
   `Sid: "dynamicdeny<id>"` (IAM Sid grammar strips the underscore
   from `dd_<ULID>`) + `Effect: Deny` + `Action: "*"` + `Resource:
   <rule.targets>` so the operator reading the role policy can
   trace exactly which deny rule contributed. The recommender
   re-runs this evaluation any time it issues a new role; existing
   roles minted before a deny lands keep the bouncer-only enforcement
   path until they expire at their TTL.

   The embedded rule ids surface as `embedded_dynamic_denies` on
   `ProvisioningResult` + on the request's `status.provisioned`
   block, AND as
   `unmapped.iam_jit.ext.embedded_dynamic_denies[]` +
   `unmapped.iam_jit.ext.embedded_dynamic_denies_count` on the
   per-issuance `request.provisioned_with_dynamic_denies` audit
   event. SIEM query:
   `kind:"request.provisioned_with_dynamic_denies"` answers "which
   role issuances embedded a dynamic-deny over the last N days?".

   The recommender Deny-injection is gated by the
   `IAM_JIT_DYNAMIC_DENIES_RECOMMENDER` env var (default enabled);
   operators who want bouncer-only enforcement can set it to `0` /
   `false` / `no` / `off`.

Why both? Because the bouncer path is bypassable (agent calls AWS
directly, skipping the proxy); the role path is bypassable (agent
uses a role minted before the deny landed). Together they raise the
bypass bar materially. Per `[[creates-never-mutates]]` neither path
modifies existing principals — we add Deny to NEWLY-issued roles only.

## Admin-action OCSF events

Three event shapes, all conforming to
`schemas/admin-action-event.schema.json`:

### `dynamic_deny.added`

```json
{
  "unmapped": {
    "iam_jit": {
      "event_type": "ADMIN_ACTION",
      "admin_action": {
        "kind": "dynamic_deny.added",
        "source": "cli|mcp|api",
        "actor": "<operator>",
        "target": {"kind": "dynamic_deny_rule", "id": "dd_..."},
        "details": {
          "targets": ["..."],
          "applied_to": ["ibounce", ...],
          "reason": "...",
          "duration": "3h",
          "expires_at": "...",
          "applies_to_recommender": true
        }
      }
    }
  }
}
```

### `dynamic_deny.removed`

Emitted by both manual removal and the cleanup of an org-distributed
rule that was withdrawn upstream.

```json
{
  "kind": "dynamic_deny.removed",
  "target": {"kind": "dynamic_deny_rule", "id": "dd_..."},
  "details": {
    "removed_by_reason": "<--reason flag value, or 'org-distributed-withdraw'>",
    "rule_age_seconds": 4271
  }
}
```

### `dynamic_deny.expired`

Emitted by the bouncer (NOT the CLI) when `expires_at` elapses + the
watcher removes the rule. Distinguished from `removed` because the
operator did NOT take action — useful for "did we leave a deny on
too long?" retros.

```json
{
  "kind": "dynamic_deny.expired",
  "target": {"kind": "dynamic_deny_rule", "id": "dd_..."},
  "details": {
    "added_at": "...",
    "expires_at": "...",
    "match_count_during_lifetime": 17
  }
}
```

(`match_count_during_lifetime` is computed by each bouncer's local
counter; cross-bouncer aggregation is a follow-up.)

## Conflict resolution

Deny rules + the existing allow surfaces interact via three rules,
applied in this order:

1. **Deny always wins over allow.** A `dynamic-deny` match on a
   request short-circuits the decision pipeline before the profile's
   allow rules / passthrough mode get a vote. Same precedence as
   `safe-default`'s sensitive-read denies.

2. **Org-distributed denies cannot be loosened by personal denies.**
   When a rule with `source: "org-distributed"` is present, a
   personal `iam-jit deny remove` of that id is refused with a
   structured error pointing at `org_distributed_url`. The org-
   distributed channel is the only way to lift an org-distributed
   deny. (Future enhancement: `--break-glass` flag that removes the
   rule + emits an extra-loud admin-action event with
   `severity=critical` + signs the action with a hardware-backed
   key; not in #324 scope.)

3. **Explicit Deny statements (recommender-injected) beat implicit
   allows.** This is just IAM semantics — but is named here because
   it's the reason the role-injection half of the defense-in-depth
   model works without any new evaluator code.

## Honest caveats

- **Deny rules are operator-set; the bouncer does NOT propose
  rules.** The recommender proposes ROLE shapes; deny rules are
  authored by the operator (typed or conversationally via MCP). A
  future iteration could surface "you might want to deny X" based on
  the discovery-mode call graph, but that is explicitly out of #324
  scope per `[[scorer-is-ground-truth]]` (we don't ship recommender
  features without their own calibration corpus).

- **Per-host TLS pinning is NOT re-handled.** If a target hostname
  is reached via a non-Bounce client that pins its own CA (e.g. an
  EKS kubelet talking to the control plane), the dynamic-deny on the
  hostname applies only to traffic the relevant bouncer proxies. The
  TLS-pinned bypass is documented in `KNOWN-CAVEATS.md §B14`; dynamic
  denies do not change that boundary.

- **Bouncer restart behavior.** On startup each bouncer parses
  `~/.iam-jit/dynamic-denies.yaml` BEFORE accepting any traffic. A
  corrupted file (YAML parse error) is logged as a
  `dynamic_deny.file_corrupt` admin-action event AND the bouncer
  falls back to "no dynamic denies active". Per
  `[[ibounce-honest-positioning]]`: we surface this in `/healthz`
  output as `dynamic_denies_status: "corrupt"` so the operator
  sees it on the next liveness probe. We do NOT refuse to start
  the bouncer — the alternative is "your bouncer is dead because
  one rule had a typo", which fails worse than "your bouncer is
  up but with no dynamic denies".

- **What happens to roles already minted.** Per
  `[[creates-never-mutates]]` we do NOT modify existing roles. A
  role minted before a deny lands keeps the bouncer-only
  enforcement path; once it expires (TTL), the next role issued
  carries the Deny statement.

- **Clock skew.** `expires_at` is computed at WRITE time on the
  authoring host. Bouncers running on different hosts evaluate
  expiry against their own wall clock. Per
  `[[creates-never-mutates]]`: we accept up to ±30s drift; rules
  expire ≤30s before/after on remote hosts. For tighter expiry
  semantics use a shorter `duration` than your skew tolerance
  budget.

- **Not a hosted SaaS.** Per `[[no-hosted-saas]]` there is no
  multi-tenant central deny store; org-distributed denies are
  installed from operator-controlled HTTPS URLs (same shape as
  org-distributed profiles per `[[enterprise-profile-distribution]]`).

- **`secret:NAME` shorthand target does NOT embed into iam-jit roles.**
  This shorthand is recognized by the loader + the bouncer-side
  matcher but is NOT embedded into the iam-jit-issued IAM role's
  policy. The recommender Deny-injection (#324f) requires
  ARN-shaped targets (`arn:aws:*`) to embed; `secret:NAME` rules
  fire at the bouncer layer only. For defense-in-depth (bouncer +
  role both denying), use the explicit ARN form
  (`arn:aws:secretsmanager:*:*:secret:NAME-*`).

## References

- Schema: [`schemas/dynamic-denies-v1.json`](schemas/dynamic-denies-v1.json)
- Cross-product schema index: [`../schemas/INDEX.md`](../schemas/INDEX.md)
- Pivot context: [`KNOWN-CAVEATS.md §A21 — discovery-mode default`](KNOWN-CAVEATS.md#a21)
- Admin-action event base: [`../schemas/admin-action-event.schema.json`](../schemas/admin-action-event.schema.json)
- Per-product audit log surfacing: [`QUERYING-AUDIT-LOGS.md`](QUERYING-AUDIT-LOGS.md)
- Follow-on tracking items: see [`tasks/324-dynamic-deny-rules.md`](tasks/324-dynamic-deny-rules.md) for the six implementation slices (`#324a` ibounce core · `#324b` kbouncer core · `#324c` dbounce core · `#324d` gbounce core · `#324e` unified CLI + MCP + fan-out · `#324f` recommender `Deny`-injection + role-effectiveness re-grade).
