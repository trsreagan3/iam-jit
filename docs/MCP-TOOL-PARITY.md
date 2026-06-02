# MCP tool parity across the Bounce suite

Verified state of the MCP tool surface exposed by each product, and
which tools are expected to have cross-product parity vs. which are
intentionally product-specific. This is the reference for the
install-consistency goal: an agent that learns one bouncer's surface
should be able to use the others by swapping only the tool prefix.

Verified: 2026-06-02 (ADOPT-9 #733 + ADOPT-12 #736).

- **ibounce / iam-jit** — `src/iam_jit/mcp_server.py` (70 tools; the
  superset, because iam-jit is the role-issuing core).
- **kbounce** — `kbouncer/internal/mcp/` (Go; K8s API gating).
- **dbounce** — `dbounce/internal/mcp/` (Go; SQL gating).
- **gbounce** — `gbounce/internal/mcp/` (Go; HTTP egress gating).

Authoritative live shape: `ibounce mcp list-tools`,
`kbounce mcp list-tools`, `dbounce mcp list-tools`,
`gbounce mcp list-tools`.

## Cross-product common surface (normalized verb → product prefix)

`Y` = present, `.` = absent. Verbs are shown without the per-product
prefix (`iam_jit_` / `bouncer_` / `bounce_` for ibounce; `kbounce_`,
`dbounce_`, `gbounce_` for the Go bouncers).

| verb | ib | kb | db | gb | notes |
|---|:--:|:--:|:--:|:--:|---|
| `active_mode` | Y | Y | Y | Y | full parity |
| `posture` | Y | Y | Y | Y | full parity |
| `denies_recent` | Y | Y | Y | Y | full parity |
| `profile_allow` | Y | Y | Y | Y | full parity (easy-allow round-trip) |
| `recommend_mode_for_task` | Y | Y | Y | Y | full parity (deterministic, no LLM) |
| `active_profile` | Y | Y | Y | . | gb is rule-list-only (no named profile) |
| `active_task` | Y | Y | Y | . | gb has no task-session model |
| `decide` | Y | Y | Y | . | dry-run a candidate request; gb uses deny-rule list |
| `add_rule` / `remove_rule` / `list_rules` | Y | Y | Y | . | gb uses `deny_add`/`deny_remove`/`dynamic_denies_list` |
| `deny_add` / `deny_remove` / `dynamic_denies_list` | Y | . | . | Y | gb's deny-rule verbs (egress-firewall shape) |
| `tail_decisions` | Y | Y | Y | . | gb exposes `denies_recent` instead of a decision tail |
| `pending_sync_prompts` / `prompts_bulk_pending` / `prompts_bulk_answer` | Y | Y | Y | . | sync-mode operator prompts; gb is async-deny only |
| `audit_export_status` | Y | Y | Y | . | gb has no export-status MCP verb yet |
| `recommend_rules` | Y | Y | . | . | rule synthesis from observed traffic |
| `scope_self_for_task` | Y | Y | . | . | declare a task; bouncer narrows |
| `task_review` | Y | Y | . | . | review a closed task's effective scope |
| `apply_preset` | Y | Y | . | . | curated rule packs |
| `end_task` | Y | Y | . | . | close a task session |
| `start_task` | Y | . | . | . | ibounce-only verb (kb uses scope_self) |
| `tail_events` | Y | . | . | . | ibounce raw event tail |

### Verdict on the common surface

The **agent-parity core** — `active_mode`, `posture`,
`denies_recent`, `profile_allow`, `recommend_mode_for_task` — is at
**full 4-way parity**. An agent that knows
`<prefix>_recommend_mode_for_task` on one bouncer uses it identically
on the others.

The gaps below the core are **intentional per-protocol differences**,
not inconsistencies a user would hit by accident:

- **gbounce** is an HTTP egress firewall: its model is a list of deny
  rules, not named profiles or task sessions. It correctly exposes
  `deny_add` / `deny_remove` / `dynamic_denies_list` instead of
  `add_rule` / `list_rules`, and has no `active_profile` /
  `active_task` / `decide` / `tail_decisions`. ibounce carries
  `deny_add`/`deny_remove`/`dynamic_denies_list` too (its bouncer
  surface spans all protocols), so the two egress-shaped surfaces
  match.
- **dbounce** lacks `recommend_rules`, `apply_preset`, `task_review`,
  `scope_self_for_task`. These are candidate Go-repo follow-ups
  (`dbounce` repo, not iam-jit) if SQL-side task scoping is wanted;
  they are **not** required for the self-service access-request flow
  (see below) and are reported as findings rather than fixed here per
  the read-only-on-Go-repos constraint.

## Self-service access-request seam (ADOPT-9 focus)

These tools are the access-request / role-issuance path. They live
**only** on ibounce/iam-jit by design — the Go bouncers gate their own
protocol but do **not** issue AWS IAM roles. The cross-product chain
is: a Go bouncer surfaces evidence (`<prefix>_tail_decisions` /
`<prefix>_denies_recent`), the agent reasons, and the agent calls the
ibounce tools below to provision the role
(`[[bouncer-informs-agent-informs-iam-jit]]`).

| Tool | Issue | Present | Documented |
|---|---|:--:|:--:|
| `iam_jit_setup_from_config` | #397 | Y | Y |
| `iam_jit_improve_profile` | #400 | Y | Y |
| `iam_jit_handle_deny` | #401 | Y | Y |
| `iam_jit_classify_deny` | #401 | Y | Y |
| `bounce_extract_permissions_from_audit` | #419 | Y | Y |
| `iam_jit_request_role_from_synthesis` | #421 | Y | Y |
| `iam_jit_resource_map` | #420 | Y | Y |
| `iam_jit_audit_search` | #444 | Y | **Y (added in this PR)** |
| `iam_jit_scope_self_for_task` | — | Y | Y |
| `iam_jit_posture` | #383 | Y | Y |

**ADOPT-9 verdict: PARITY-COMPLETE (one doc gap fixed).** Every
spec-named MCP tool (#397 / #400 / #401 / #419 / #421 / #438-synthesis
/ #444) is present, has a chainable structured return shape, and an
LLM-callable description. The single gap was that `iam_jit_audit_search`
(#444) — the discovery entry point — was missing from
`MCP-RECIPES.md`; this PR adds it. No tool needed to be created.

## Natural-language resource discovery (ADOPT-12 focus)

ADOPT-12 proposes extending NL discovery from audit-only to three new
CLI surfaces: `posture --ask`, `inventory --ask`, `deny --ask`.

**Verified state:**

- `iam_jit_audit_search` (#444) — the NL→structured audit search — is
  **real and tested**, not stubbed. The handler
  (`_iam_jit_audit_search_for_mcp` in `mcp_server.py`) reuses the full
  `cli_audit_query` fan-out machinery and is covered by
  `tests/test_mcp_audit_search_444.py` (10 tests, all passing).
- There is **no** `--ask` flag on `posture`, `deny`, or any other CLI
  command, and there is **no** `inventory` command at all.

**ADOPT-12 verdict: PARITY-COMPLETE as designed; the proposed `--ask`
flags are intentionally NOT built.** The product's deliberate
architecture (`[[bouncer-zero-llm-when-agent-in-loop]]`,
`[[no-nl-synthesis]]`) keeps the LLM on the *agent* side. The single
canonical NL surface is `iam_jit_audit_search`: the agent translates
free-text → structured args using the worked examples in the tool
description, and iam-jit answers with a deterministic, no-LLM fan-out.
A `posture --ask` / `deny --ask` / `inventory --ask` CLI flag would put
an LLM call inside the server, which the suite deliberately does not do.
An agent answers "what bouncers protect prod?" by reading
`iam_jit_posture`; "which denies mention SSN today?" by calling
`iam_jit_audit_search` (or `bounce_denies_recent`) and reasoning over
the structured result; "which MCP tools write?" by reading the tool
catalog. No new server-side surface is needed.

If a future decision reverses `[[no-nl-synthesis]]` for the CLI
specifically, ADOPT-12's `--ask` flags become the implementation; until
then they are correctly absent and this is documented honestly per
`[[ibounce-honest-positioning]]` rather than papered over.

## Findings for the Go repos (not fixed here — read-only constraint)

- **dbounce**: no `recommend_rules`, `apply_preset`, `task_review`,
  `scope_self_for_task` MCP verbs. Below the agent-parity core, so not
  blocking, but worth a `dbounce` repo task if SQL task-scoping is
  wanted for cross-product parity.
- These are reported as findings, not half-fixed, per the task's
  honesty constraint.

---

Last reviewed: 2026-06-02.
