# #324 — Dynamic deny rules: sub-task tracking

> **Status:** ALL 6 SLICES SHIPPED (2026-05-22). #324a (ibounce),
> #324b (kbouncer), #324c (dbounce), #324d (gbounce), #324e (unified
> `iam-jit deny` CLI + MCP fan-out + cross-product e2e), AND #324f
> (recommender `Deny`-injection + role-effectiveness re-grade) are
> LIVE. The defense-in-depth model is end-to-end functional: an
> operator's `iam-jit deny add ...` writes the YAML + fans out to
> bouncer reloads (request-time enforcement) AND the next role
> iam-jit issues embeds the same constraint as an explicit `Deny`
> statement (role-evaluation-time enforcement). The canonical
> design + wire shapes live in
> [`../DYNAMIC-DENY-RULES.md`](../DYNAMIC-DENY-RULES.md); the on-disk
> YAML schema in
> [`../schemas/dynamic-denies-v1.json`](../schemas/dynamic-denies-v1.json).
> Every sub-task below MUST converge against those two artifacts; if a
> sub-task needs to diverge, update the design doc FIRST + reference
> the change here.

Per `[[deliberate-feature-completion]]`: this slice is COMPLETE
(design + skeleton + tracking). The six follow-on slices each ship
as their own slice; they do NOT block each other strictly — #324a
ships first because it has the largest existing surface (ibounce
decision pipeline) + sets the reference shape for the YAML watcher,
but #324b-d can ship in parallel.

---

## #324a — ibounce dynamic-deny core

**Scope:** Bring dynamic-deny enforcement to ibounce (the iam-roles
Python repo).

**Surface:**

- New module `src/iam_jit/dynamic_denies/store.py` — load + watch +
  query the `~/.iam-jit/dynamic-denies.yaml` file. Validate against
  `docs/schemas/dynamic-denies-v1.json`. fsevents/inotify watcher
  via `watchdog` (already a transitive dep).
- New module `src/iam_jit/dynamic_denies/matcher.py` — ARN target
  matcher (per the design doc's resolver table). Wildcard semantics
  match the existing `bouncer/rules.py` ARN matching to keep one
  evaluation grammar across the codebase.
- Wire into `src/iam_jit/bouncer/decisions.py` — dynamic-deny match
  short-circuits the decision pipeline BEFORE profile + task evaluation
  (per the design doc's `Conflict resolution` rule 1).
- Emit `dynamic_deny.added` / `removed` / `expired` admin-action
  OCSF events via `src/iam_jit/bouncer/audit_export/admin_action.py`.
- `/healthz` surfaces `dynamic_denies_count` + `dynamic_denies_status`
  (matches the gbounce `deny_hosts_count` shape from #314).

**Tests:**

- `tests/bouncer/test_dynamic_denies_store.py` — load + watch +
  schema-validate.
- `tests/bouncer/test_dynamic_denies_decision.py` — decision-
  pipeline short-circuit + 403 deny_reason content.
- `tests/bouncer/test_dynamic_denies_audit.py` — OCSF event shape.

**Out of scope:** the unified CLI (#324e), MCP fan-out (#324e),
recommender embedding (#324f). #324a's enforcement runs against a
manually-written YAML file.

**Tracking refs in code:** every new module + test file carries a
`# #324a` comment in the header so a `grep -rn '#324a'` enumerates
the touch set.

---

## #324b — kbouncer dynamic-deny core

**Repo:** `kbouncer` (separate Go repo per `[[kbouncer-separate-repo]]`).

**Scope:** parity with #324a on the k8s admission-webhook path.

**Surface:**

- Same YAML schema + watcher (Go: `fsnotify`).
- Namespace + cluster matcher per the design doc's resolver row.
- Decision-pipeline short-circuit in the admission webhook.
- Admin-action OCSF events (kbouncer already has this surface from
  the §A16 audit-export work — extend the `kind` enum to cover
  `dynamic_deny.*`).
- `/healthz` parity (`dynamic_denies_count`).

**Tests:** Go test files mirror the Python set above.

**Out of scope:** unified CLI / MCP / recommender.

---

## #324c — dbounce dynamic-deny core

**Repo:** `dbounce` (separate Go repo).

**Scope:** parity with #324a/b on the SQL-proxy path.

**Surface:**

- Same YAML schema + watcher.
- Hostname + RDS-endpoint matcher per the design doc's resolver
  row (`<host>.<region>.rds.amazonaws.com` pattern).
- SQL-session refusal carries the same `deny_reason: dynamic-deny: <id>`
  shape (mirrors the §A6 DCL deny shape).
- Admin-action OCSF events.
- `/healthz` parity.

**Out of scope:** unified CLI / MCP / recommender.

---

## #324d — gbounce dynamic-deny core

**Repo:** `gbounce` (separate Go repo).

**Scope:** parity with #324a-c on the HTTP-egress proxy path. The
shape here is the SIMPLEST of the four because gbounce already has
the `deny_hosts` infrastructure from #314; dynamic-deny is an
additional source of glob entries layered on top.

**Surface:**

- Same YAML schema + watcher.
- URL/hostname glob matcher REUSES the existing `deny_hosts`
  matcher in `internal/proxy/deny_hosts.go`. The dynamic-deny entries
  are merged with the operator's static `--deny-host` list at
  watcher-reload time; the merge is order-preserving + duplicates
  prefer the dynamic entry (so an `expires_at` from the dynamic side
  wins over an indefinite static entry of the same glob).
- Admin-action OCSF events.
- `/healthz` already surfaces `deny_hosts_count`; add
  `dynamic_denies_count` as a separate counter.

**Out of scope:** unified CLI / MCP / recommender.

---

## #324e — iam-jit unified CLI + MCP + cross-bouncer fan-out — SHIPPED

**Repo:** `iam-roles` (this repo).

**Scope:** REPLACED the skeleton at `src/iam_jit/cli_deny.py`. This
is the headline slice — what an operator actually USES day-to-day.

**What landed:**

- `src/iam_jit/cli_deny.py` — real impl. Same flag shape as the
  skeleton; the four subcommands now read + write the YAML + fan out
  reloads.
- `src/iam_jit/dynamic_denies/resolver.py` — cross-protocol target
  resolver (ARN -> ibounce, namespace:/cluster: -> kbouncer, rds:/
  hostname-DB-shape -> dbounce+gbounce, URL/hostname -> gbounce).
- `src/iam_jit/dynamic_denies/store.py` — atomic 0600 writer +
  ULID generator + duration parser.
- `src/iam_jit/dynamic_denies/fanout.py` — POST each affected
  bouncer's `/admin/dynamic-denies/reload`; honest unreachable
  surface (warn + retry hint, exit 0 — YAML is source of truth per
  `[[ibounce-honest-positioning]]`).
- `src/iam_jit/dynamic_denies/operations.py` — shared add/list/
  remove/show backend for both CLI + MCP per
  `[[cross-product-agent-parity]]`.
- `src/iam_jit/mcp_server.py` — `bounce_deny_add` /
  `bounce_deny_list` / `bounce_deny_remove` MCP tools wired to the
  same operations backend.
- `tests/cli/test_deny_real.py` — 40 real-impl tests covering
  resolver matrix + CLI happy + JSON + fan-out + remove +
  unreachable-bouncer paths + MCP shape.
- `tests/integration/dynamic_deny_cross_product_test.py` — 10
  end-to-end scenarios (the 9 from the brief + an
  unreachable-bouncer path); uses 4 in-process HTTP fakes per the
  bouncer mgmt-port reload contract.
- `tests/cli/test_deny_skeleton.py` — preserved + skip-marked per
  `[[creates-never-mutates]]` so the skeleton -> real-impl
  transition stays visible in history.

**Acceptance (met):** the four skeleton subcommands swapped to real
impl with ZERO surface change (same flag names, same JSON shape,
the only exit-code change is intentional: success is now 0
(formerly 2), and operator-fixable errors are 1). Every cross-
product scenario in the brief passes.

---

## #324f — iam-jit recommender Deny-injection + role-effectiveness re-grade — SHIPPED

**Repo:** `iam-roles` (this repo).

**Scope:** Defense-in-depth half of the model. Embed dynamic-deny
rules as explicit `Deny` statements in any role iam-jit issues
during a rule's lifetime.

**What landed (2026-05-22):**

- `src/iam_jit/dynamic_denies/recommender.py` — pure functions
  `build_deny_statements()`, `embedded_rule_ids()`, and
  `inject_into_policy()` that consume a :class:`RuleSet` + produce
  the policy Statement dicts to append. Eligibility filter: rule's
  `applied_to` must contain `ibounce` AND
  `applies_to_recommender` must be true AND `expires_at` (if set)
  must be in the future AND at least one target must be an
  ARN-shaped string. Each statement carries
  `Sid: "dynamicdeny<id>"` (IAM Sid grammar strips the underscore
  from `dd_<ULID>`) so an operator reading the role policy traces
  exactly which deny rule contributed.
- `src/iam_jit/provision.py` — wires the recommender into BOTH the
  preview path + the real `provision()` path via a new helper
  `_build_issued_policy()` that runs after the existing
  `_augment_policy_with_time_condition()` augmentation. The two
  passes compose: every Statement (Allow + recommender-injected
  Deny) carries the DateLessThan time-condition. Env-var gate
  `IAM_JIT_DYNAMIC_DENIES_RECOMMENDER` (default enabled) for
  operators who want bouncer-only enforcement.
- `ProvisioningResult.embedded_dynamic_denies: list[str]` — list
  of rule ids the recommender embedded. Surfaces in the request's
  `status.provisioned` block (per `schemas/request.schema.json`
  additive optional field) so the UI / `iam-jit show` reads it
  without re-parsing the IAM inline policy JSON.
- `request.provisioned_with_dynamic_denies` audit event — emitted
  on every issuance that embedded at least one rule, carrying
  `details.unmapped.iam_jit.ext.embedded_dynamic_denies[]` +
  `details.unmapped.iam_jit.ext.embedded_dynamic_denies_count` so
  a SIEM filter on the `kind` answers "which issuances embedded
  dynamic denies?".
- `tests/recommender/test_dynamic_deny_injection.py` — 14 tests
  covering: ARN-rule embed, non-ibounce skip, expired skip,
  multi-rule embed, no-YAML baseline, audit-event shape,
  hot-reload (re-read every issuance), disabled-flag short-circuit,
  + pure-function unit tests for the recommender module
  (recommender-opt-out, non-mutation, secret-shorthand filter,
  GovCloud + China partitions, Sid IAM legality, YAML round-trip).
- `tests/dogfood/role-effectiveness-grades-post-pivot.md` — new
  "After #324f recommender Deny-injection + dynamic-denies"
  section with the re-graded corpus + new hit-rate metric.

**Acceptance (met):** the corpus re-grade lands the new hit-rate
under the post-#324f narrowed bucket; per
`[[scorer-is-ground-truth]]` the result is reported honestly with
known limits documented (D1 dbounce statement-level deny is v1.1
candidate per `KNOWN-CAVEATS.md §B`).

**Out of scope:** UI surfacing of the embedded Deny in the role-
policy review screen (separate v1.1 polish task); statement-level
dynamic-denies for dbounce (v1.1 candidate per `KNOWN-CAVEATS.md`);
retroactive Deny embedding for already-issued roles (per
`[[creates-never-mutates]]` they expire at their TTL).

---

## Cross-slice notes

- **Schema-version bump rule.** Any of these slices that needs to
  add a new required field bumps `schema_version` from `"1.0"` to
  `"1.1"` in `docs/schemas/dynamic-denies-v1.json` + adds a
  migration path for existing v1.0 files (the next-released bouncer
  parses both versions; the writer always emits the newer version).
  Additive optional fields do NOT bump the version per the
  cross-product convention in `schemas/INDEX.md`.

- **Wire contract guard.** A cross-product test in #324e validates
  the same YAML against the schema-served-from-each-bouncer's
  `GET /schemas/dynamic-denies` endpoint (added in #324a-d as part
  of the per-product schema-endpoint surface).

- **No partial-impl claims.** Per `[[ibounce-honest-positioning]]`
  + `[[v1-scope-bar]]`: until #324e lands, the `iam-jit deny`
  surface remains the SKELETON. The per-bouncer enforcement
  (#324a-d) is wired against a manually-written YAML during their
  development; we do NOT advertise dynamic-denies as "shipped" until
  the operator-facing CLI is real.
