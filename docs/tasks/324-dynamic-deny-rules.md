# #324 — Dynamic deny rules: sub-task tracking

> **Status:** DESIGN shipped (this commit) — six implementation slices
> open. The canonical design + wire shapes live in
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

## #324e — iam-jit unified CLI + MCP + cross-bouncer fan-out

**Repo:** `iam-roles` (this repo).

**Scope:** REPLACES the skeleton at `src/iam_jit/cli_deny.py`. This
is the headline slice — what an operator actually USES day-to-day.

**Surface:**

- Replace each `_emit_not_implemented` body with the real impl per
  the design doc's CLI surface section.
- Cross-protocol target resolver in
  `src/iam_jit/dynamic_denies/resolver.py` per the design doc's table.
- Atomic write of `~/.iam-jit/dynamic-denies.yaml` (write-temp +
  rename + 0600 perms) so the per-bouncer watchers always see a
  complete + valid file.
- MCP tools `bounce_deny_add` / `bounce_deny_list` /
  `bounce_deny_remove` in `src/iam_jit/mcp_server.py` per the
  design doc's MCP surface section.
- Cross-bouncer integration test:
  `tests/integration/test_dynamic_deny_cross_bouncer.py` — spin up
  ibounce + kbouncer-stub + dbounce-stub + gbounce-stub; add a deny;
  verify each bouncer's `/healthz` increments `dynamic_denies_count`;
  send a matching request to each; verify the 403; remove the deny;
  verify counters tick back down.

**Acceptance:** the four skeleton subcommands swap to real impl with
ZERO surface change (same flag names, same JSON shape, same exit
codes on success/error). The `test_deny_skeleton.py` tests in this
commit get REPLACED by the real impl tests; the skeleton tests
exist precisely to make the swap mechanical.

---

## #324f — iam-jit recommender Deny-injection + role-effectiveness re-grade

**Repo:** `iam-roles` (this repo).

**Scope:** Defense-in-depth half of the model. Embed dynamic-deny
rules as explicit `Deny` statements in any role iam-jit issues
during a rule's lifetime.

**Surface:**

- `src/iam_jit/bouncer/recommender.py` (or wherever the issued-role
  policy is assembled — confirm at slice start; per
  `[[creates-never-mutates]]` this is the role we CREATE, not the
  user's existing principal): consult
  `src/iam_jit/dynamic_denies/store.py` at issuance time, emit a
  `Deny` statement per rule whose `applied_to` includes `ibounce`
  AND `applies_to_recommender` is true. Each statement carries
  `Sid: "dynamic-deny-<id>"` so an operator reading the role policy
  can trace which deny rule contributed.
- Re-grade the role-effectiveness corpus
  (`tests/dogfood/role-effectiveness-grades.md` +
  `role-effectiveness-grades-post-pivot.md`) with the new
  enforcement path active. Per `[[role-effectiveness-grading]]`
  EVERY scenario gets a fresh Opus grade
  (MEANINGFUL/PARTIAL/THEATER/NEGATIVE-VALUE) so we know if
  dynamic denies materially move the hit-rate vs the
  post-pivot baseline (23.1% pre-dynamic-deny; target ≥50%).

**Acceptance:** role-effectiveness re-grade lands as
`tests/dogfood/role-effectiveness-grades-with-dynamic-denies.md`
preserving the historical comparison points. Update the
`[[role-effectiveness-corpus]]` memory.

**Out of scope:** UI surfacing of the embedded Deny in the role-
policy review screen (separate v1.1 polish task).

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
