# Round 27 audit — bouncer task scope Slice C (#168)

Commit under review: `86ddd56` (`feat(bouncer): #168 Slice C — per-owner concurrent tasks + per-task review`).

Scope (Slice C only — Slice A audited under #160, Slice B audited in WB26):
- `src/iam_jit/bouncer/tasks.py` (+20 LOC: `owner` field on `TaskScope` + validation in `build_task_scope`)
- `src/iam_jit/bouncer/store.py` (+203 LOC: v3 → v4 migration adding `owner` column; per-owner `add_task` / `get_active_task` / `list_tasks`; `task_review_summary`)
- `src/iam_jit/bouncer_cli.py` (+42 LOC: `--owner` on `tasks start`/`tasks active`; new `tasks review` subcommand)
- `src/iam_jit/mcp_server.py` (+95 LOC: `bouncer_task_review` tool + `owner` parameter on start/active MCP tools)
- `tests/bouncer/test_tasks.py` (+238 LOC, 17 new tests)

Read-only audit. Per [[audit-cadence-discipline]].

Regression: **2478 passed**, 29 skipped, 14 deselected (87.65s, excluding `tests/e2e/*` and `tests/test_calibration_corpus.py`). Matches the audit-prompt baseline (2478) exactly. No regressions caused by Slice C.

## Headline

13 findings: **0 CRIT, 2 HIGH, 5 MED, 6 LOW.**

The two HIGHs are real correctness/security gaps that ship today.

**HIGH-27-01**: the v4 migration's `CREATE INDEX idx_tasks_owner_status` is **never created on a fresh DB**. The migration ALTER + CREATE INDEX live inside the same `try / except sqlite3.OperationalError` block at `store.py:210-216`. On a brand-new DB, the inline `CREATE TABLE IF NOT EXISTS tasks (... owner TEXT)` at `:179-192` already creates the column, so the subsequent `ALTER TABLE tasks ADD COLUMN owner` raises `OperationalError: duplicate column name: owner` — and the exception handler silently swallows BOTH statements. Verified via repro:

```
indexes after fresh init: ['sqlite_autoindex_tasks_1', 'idx_tasks_status', 'idx_tasks_started_at']
indexes after v3->v4 migrate: [..., 'idx_tasks_owner_status']
```

A fresh install (the canonical case for Slice C — most users will create new DBs after this change) is MISSING the index that every per-owner lookup queries. `get_active_task(owner=?)` (called on every decision when an agent declares an owner), the atomic active-conflict check inside `add_task`, and `list_tasks(owner=?)` all hit `WHERE status='active' AND owner=?` or `(owner=? OR owner IS NULL)`. With no index, every lookup is a full table scan over `tasks`. Low impact today (most tables are tiny) but the WHOLE POINT of `idx_tasks_owner_status` is that it should ship; the migration silently fails to do its job on the most common path. Trivial fix: separate the two statements into two `try/except` blocks (or use `CREATE INDEX IF NOT EXISTS` outside any try/except — it's idempotent on its own).

**HIGH-27-02**: `bouncer_task_review` (and `bouncer_end_task`, by direct extension) has **no per-owner access check**. The Slice C narrative is "multiple agent sessions on the same machine can each have their own task scope" — but ANY caller that can reach the bouncer's MCP/CLI can review or end ANY task by passing its task_id, regardless of who owns it. Verified via repro:

```python
>>> a = _bouncer_start_task_for_mcp({'description':'agent A secret task',
...     'allow_rules':[{'pattern':'secretsmanager:*'}], 'owner':'agent-A'})
>>> # Agent B (no auth) reviews A's task:
>>> b_review = _bouncer_task_review_for_mcp({'task_id': a['task_id']})
>>> b_review['owner']
'agent-A'
>>> b_review['description']
'agent A secret task'

>>> # Agent B also ends A's task with no owner check:
>>> _bouncer_end_task_for_mcp({'task_id': a['task_id']})
{'task_id': '...', 'ended': True, 'audit_event_kind': 'task_ended'}
```

The review exposes the task's `allow_rules` + `deny_rules` (via `description` + decision history) and the full denied-calls list — useful for an attacker to discover what scopes other agents declared. The end-task variant is sharper: an attacker session can shut down a victim session's protective scope mid-task, dropping it back to global rules. Both vectors are "all-local agent sessions sharing the same bouncer DB" — exactly the Slice C multi-session premise.

Mitigating context: on a SINGLE-LAPTOP deployment (the canonical [[local-only-safety-mode]] use case) all "agents" are the same human's agents — no isolation concern. The risk lands when the Slice C "multiple agent sessions" promise lands in a context where those sessions are different trust principals (CI runner farms, shared dev VMs, partner-hosted Enterprise — see [[hosted-safety-mode]] for the kind of deployment where this becomes real). The CURRENT code's invariant is "owner is an organizational label, not an access control." That's defensible but the Slice C tool descriptions / docs imply isolation.

Fix shape: either (a) add an `owner` parameter to `bouncer_task_review` + `bouncer_end_task` and reject when supplied-owner doesn't match the task's stored owner; or (b) document explicitly that owner is "naming, not authorization." Today the code is in between.

The five MEDs cluster around schema migration safety, validator gaps, and audit-chain integrity:

- **MED-27-01**: `task_review_summary` has NO LIMIT on the decisions aggregation. Verified that 5,000-decision tasks return 5,000 entries in the response. For long-running tasks (24h-cap allows lots of decisions) this is a memory + serialization cost amplifier, especially over MCP/JSON where the entire payload must fit in memory + cross the JSON-RPC boundary. WB26's `list_decisions` is explicitly hard-capped at 10,000; `task_review_summary` should mirror that (cap + a `truncated: true` field).
- **MED-27-02**: `TaskScope.owner` accepts null bytes (`\x00`) and other non-printable characters within the 256-char limit. Confirmed: `build_task_scope(..., owner='alice\x00bob')` returns a scope with `owner='alice\x00bob'`. Same shape as the existing `started_by` validation (WB26 MED-26-03) which DID get a non-empty/length check but no charset check. The null byte breaks log parsing (most tools treat `\x00` as terminator), breaks downstream CSV / TSV export, and — for owners stored from an attacker's input — could exploit downstream display code. Same fix shape as the description validation pattern: regex `[\x00-\x1f\x7f]` reject.
- **MED-27-03**: `task_review_summary` reads decisions across ALL tasks with matching `task_id` — but task_id is a 12-char hex UUID prefix (`uuid.uuid4().hex[:12]`). Birthday-collision odds for 12 hex chars (48 bits) hit ~1% at ~2.3M tasks. Theoretical, but the column has a PRIMARY KEY constraint on `task_id` so a collision in `add_task` would raise `IntegrityError` before insert — defensive. However the decisions table's `task_id` column has NO foreign-key constraint, so a stale or hand-injected task_id in the decisions table could mismatch. Worth a sanity probe.
- **MED-27-04**: `bouncer_end_task` MCP tool is still missing the owner-isolation check (called out in HIGH-27-02 above as the security half). Even without the security framing, end-task is asymmetric vs start-task: start enforces per-owner uniqueness, end has no owner consideration at all. A future "auto-restart on end" workflow that uses the same owner finds itself confused if a different owner-session ended its task. Recommend (a) optional `owner` parameter on `bouncer_end_task` that, if supplied, must match the task's stored owner; otherwise reject — or (b) audit-log a `cross_owner_end` event when the actor's claimed owner doesn't match.
- **MED-27-05**: `test_mcp_three_task_tools_in_tools_list` (test name + body still hardcodes "three") tests inclusion not exact count. Slice C added a fourth task tool (`bouncer_task_review`) but no test verifies it's discoverable. A future regression that drops the new tool from `TOOLS` would pass this assertion. Same anti-pattern as WB25 LOW-25-01: an integration test that "asserts subset" instead of "asserts equal" doesn't catch removal regressions. Worth a `test_mcp_four_task_tools_in_tools_list` (or rename the existing test + add `bouncer_task_review`).

Six LOWs: doc drift (LOW-27-01); `--owner ''` accepted at CLI but useless (LOW-27-02); cross-owner review-not-isolated noted but Lens-A guidance missing (LOW-27-03); 11-column backwards-compat branch in `_row_to_task_scope` unreachable in practice (LOW-27-04); `tasks review` exit-code for empty-decision tasks not asserted by any test (LOW-27-05); the per-task-review reason strings include task_id redundantly (LOW-27-06).

## Closure status

| Finding | Status |
|---|---|
| HIGH-27-01 v4 migration's `CREATE INDEX idx_tasks_owner_status` silently skipped on fresh DBs because it shares a `try/except sqlite3.OperationalError` block with `ALTER TABLE` which raises on duplicate column | OPEN |
| HIGH-27-02 `bouncer_task_review` + `bouncer_end_task` have no per-owner access check; any caller can read/end any task by task_id; breaks Slice C multi-session isolation premise | OPEN |
| MED-27-01 `task_review_summary` reads ALL decisions for a task with no LIMIT; long-running tasks return unbounded payload over MCP | OPEN |
| MED-27-02 `TaskScope.owner` accepts null bytes + non-printable characters; breaks log parsing + CSV export downstream | OPEN |
| MED-27-03 task_id PK uniqueness is enforced at task insert but no FK on decisions.task_id; stale/injected IDs reach review aggregation untyped | OPEN |
| MED-27-04 `bouncer_end_task` has no owner parameter / isolation check (the security half of HIGH-27-02 plus asymmetric API surface) | OPEN |
| MED-27-05 `test_mcp_three_task_tools_in_tools_list` still asserts the three Slice B tools by inclusion; `bouncer_task_review` (Slice C's 4th) not asserted; subset-test pattern doesn't catch regressions | OPEN |
| LOW-27-01 `docs/IAM-JIT-BOUNCER.md:296` still says "Only ONE task active at a time in Slice B. Slice C may add per-PID concurrent tasks" — Slice C shipped per-OWNER concurrent tasks + review report unmentioned | OPEN |
| LOW-27-02 CLI `tasks active --owner ''` accepted; queries `WHERE owner=''`; always returns None; should reject at click layer for consistency with `build_task_scope`'s empty-owner rejection | OPEN |
| LOW-27-03 HIGH-27-02 + MED-27-04 cross-owner-data-leak is correct but Lens-A doesn't tell the agent "this task wasn't yours but you reviewed it anyway"; no warning emitted | OPEN |
| LOW-27-04 `_row_to_task_scope` 11-column backwards-compat branch is unreachable in practice — every SELECT in this commit explicitly selects 12 columns; the branch only fires for hand-crafted test fixtures | OPEN |
| LOW-27-05 `tasks review` on a task with zero decisions returns exit 0 + prints `decisions: 0 total` — defensible but no test asserts this exit code | OPEN |
| LOW-27-06 Per-task review reason strings include `task X active` redundantly (the operator is already looking at task X's review) | OPEN |

## HIGH findings

### HIGH-27-01 — v4 migration's `CREATE INDEX idx_tasks_owner_status` silently skipped on fresh DBs

- File: `src/iam_jit/bouncer/store.py:179-216`.

- Issue: the v4 migration block is:
  ```python
  # store.py:210-216
  try:
      self._conn.execute("ALTER TABLE tasks ADD COLUMN owner TEXT")
      self._conn.execute(
          "CREATE INDEX IF NOT EXISTS idx_tasks_owner_status ON tasks(owner, status)"
      )
  except sqlite3.OperationalError:
      pass
  ```

  But the `tasks` CREATE TABLE earlier (lines 179-192) is inline:
  ```sql
  CREATE TABLE IF NOT EXISTS tasks (
      ...
      end_reason TEXT,
      owner TEXT
  );
  ```

  On a FRESH DB, the inline CREATE TABLE provides the column directly. When the migration code then runs `ALTER TABLE tasks ADD COLUMN owner TEXT`, SQLite raises `OperationalError: duplicate column name: owner`. The `except` block at `:215-216` swallows the exception silently — AND swallows the next statement in the try block (the CREATE INDEX) because exception flow exits the try.

  Verified via repro:
  ```
  $ python -c "from iam_jit.bouncer.store import BouncerStore; \
      s = BouncerStore(); \
      cur = s._conn.execute(\"SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='tasks'\"); \
      print([r[0] for r in cur.fetchall()])"
  ['sqlite_autoindex_tasks_1', 'idx_tasks_status', 'idx_tasks_started_at']
  ```

  Compared to v3→v4 migration path (DB existed without the column):
  ```
  ['sqlite_autoindex_tasks_1', 'idx_tasks_status', 'idx_tasks_started_at', 'idx_tasks_owner_status']
  ```

  Fresh installs (the canonical case for Slice C — most users will pick up Slice C on a new DB) are missing the index that every per-owner lookup queries:
  - `get_active_task(owner=?)` at `store.py:697-708` (`WHERE status='active' AND owner=?`)
  - `add_task` atomic conflict check at `:618-622` (`WHERE status='active' AND (owner=? OR (owner IS NULL AND ? IS NULL))`)
  - `list_tasks(owner=?)` at `:741-771`

  With no `idx_tasks_owner_status`, each becomes a full table scan over `tasks`. Low immediate impact (most `tasks` tables are tiny — single-laptop user). But the WHOLE POINT of shipping the index is that it WORKS — the migration that should ship it silently doesn't, on the most common path.

- Why HIGH (not MED): structural-integrity break that ships silently. Same severity rationale as WB26 HIGH-26-01 (correctness-via-luck where the luck is "no one's exercised the failure path yet"). The performance impact today is small; the integrity claim "v4 migration installs the per-owner index" is FALSE for ~every install going forward. Same shape as the WB23 HIGH "DDL drift hidden by IF NOT EXISTS" pattern.

- Fix:
  ```python
  # store.py — split the two operations:
  try:
      self._conn.execute("ALTER TABLE tasks ADD COLUMN owner TEXT")
  except sqlite3.OperationalError:
      pass
  # CREATE INDEX IF NOT EXISTS is idempotent on its own; no need
  # for the try/except, and it MUST run even when ALTER raised.
  self._conn.execute(
      "CREATE INDEX IF NOT EXISTS idx_tasks_owner_status ON tasks(owner, status)"
  )
  ```

  Test:
  ```python
  def test_v4_migration_creates_owner_index_on_fresh_db(tmp_path):
      """Regression: HIGH-27-01 — `idx_tasks_owner_status` must exist
      after BouncerStore init, regardless of whether the DB was fresh
      or migrated from v3."""
      db = tmp_path / "fresh.db"
      store = BouncerStore(db_path=db)
      cur = store._conn.execute(
          "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='tasks'"
      )
      names = {r[0] for r in cur.fetchall()}
      assert "idx_tasks_owner_status" in names
  ```

  Also worth applying the "split statements with their own exception handlers" rule retroactively to v3's `ALTER TABLE decisions ADD COLUMN task_id` at `:201-204` — same shape: if v3 added an index alongside the column, the same drift would have hit. Today there's no v3 index alongside the task_id column, so no live bug, but the pattern is the same hazard.

### HIGH-27-02 — `bouncer_task_review` + `bouncer_end_task` have no per-owner access check

- Files:
  - `src/iam_jit/mcp_server.py:1947-1965` (`_bouncer_task_review_for_mcp` — only `task_id` parameter, no owner)
  - `src/iam_jit/mcp_server.py:1912-1933` (`_bouncer_end_task_for_mcp` — only `task_id`, no owner)
  - `src/iam_jit/bouncer/store.py:828-878` (`task_review_summary` — only `task_id`, no owner filter)
  - `src/iam_jit/bouncer/store.py:773-822` (`end_task` — only `task_id`, no owner filter)

- Issue: Slice C's MCP tool descriptions promise that "multiple agent sessions on the same machine can each have their own task scope" (`mcp_server.py:1058-1065`). The implication is per-owner isolation. But the **review** + **end** code paths only take `task_id` — they don't accept an `owner` parameter, and they don't filter the underlying SQL by owner. Any caller that can reach the bouncer's MCP/CLI surface can review/end ANY task by passing its task_id.

  Verified via repro:
  ```python
  >>> # Agent A starts a sensitive task with secretsmanager allow rules
  >>> a = _bouncer_start_task_for_mcp({
  ...     'description': 'agent A secret task',
  ...     'allow_rules': [{'pattern': 'secretsmanager:*'}],
  ...     'owner': 'agent-A',
  ... })
  >>> # Agent B can review A's task (no owner check on review):
  >>> b_review = _bouncer_task_review_for_mcp({'task_id': a['task_id']})
  >>> b_review['owner']
  'agent-A'
  >>> b_review['description']
  'agent A secret task'
  >>> # Even more impactful — B can END A's task:
  >>> _bouncer_end_task_for_mcp({'task_id': a['task_id']})
  {'task_id': '...', 'ended': True, 'audit_event_kind': 'task_ended'}
  ```

  Two attack shapes ship today:

  1. **Information disclosure**. Agent B enumerates task_ids (12-hex chars from `uuid.uuid4().hex[:12]` — guessable in a finite session set, plus task_ids leak via `list_tasks` which has no owner-filter-required behavior). For each, `bouncer_task_review` returns the task's `description` (free-form, may contain "PR-12345 staging upgrade"), `owner` (reveals which sessions exist), and the full denied-calls list (reveals what the OTHER agent attempted — useful for an attacker to map what the victim agent was authorized to do).

  2. **Cross-session denial-of-protection**. Agent B calls `bouncer_end_task(task_id=A's id)`. A's protective scope drops mid-task. A's next AWS call now falls back to global rules (which may be permissive per [[safety-mode-lean-permissive]] + [[admin-minus-sensitive-baseline]]). The audit chain records the `task_ended` event with B's actor (good for forensics), but the damage — protective scope removed without A's consent — has already happened.

  The Slice C commit message is explicit that the multi-session use case is "agent sessions" plural. Single-laptop solo founder: one human's agents, no isolation concern, current behavior is fine. CI runner farm OR partner-hosted Enterprise (per [[hosted-safety-mode]] roadmap) OR shared developer VM: different humans' agents, isolation MUST hold for "owner" to mean anything more than "label."

  Compare to Slice B's `bouncer_end_task` — same code, single-active design meant there was only one task to end, so no isolation question. Slice C added concurrent tasks but did NOT extend the access surface to match.

- Why HIGH (not CRIT): no AWS-side privilege escalation (the bouncer doesn't grant credentials; it's a gate). Severity is "Slice C's multi-session isolation premise is structurally violated." Single-laptop deployments are unaffected. The risk lands when Slice C is used in any multi-trust-principal context — and the commit narrative explicitly references that case.

- Fix options:

  1. **Add owner parameter to both tools + reject on mismatch**:
     ```python
     # mcp_server.py
     def _bouncer_task_review_for_mcp(args):
         task_id = args.get('task_id')
         owner = args.get('owner')  # NEW — optional but if supplied must match
         ...
         summary = store.task_review_summary(task_id.strip())
         if not summary:
             return {'error': ...}
         if owner is not None and summary.get('owner') != owner:
             return {'error': 'task does not belong to this owner'}
         return summary
     ```
     Same shape for `_bouncer_end_task_for_mcp`.

  2. **Store-layer owner check** (preferred, defense-in-depth):
     ```python
     # store.py
     def task_review_summary(self, task_id, *, owner=None):
         scope = self.get_task(task_id)
         if scope is None:
             return {}
         if owner is not None and scope.owner != owner:
             return {}  # treat as not-found rather than disclosing
         ...
     ```
     Same shape for `end_task`. Database layer enforces; wrapper layers pass through.

  3. **Document only**: state explicitly in the Slice C docs that "owner is an organizational label, NOT an access control boundary; any caller that can reach the bouncer MCP can review + end any task." Cheap but punts the Slice C multi-session promise.

  Recommend option 2. Treat the missing-or-wrong-owner case as "not found" so the surface doesn't reveal "this task exists but you can't access it" (vs "this task doesn't exist") — closes a side-channel.

  Test:
  ```python
  def test_review_does_not_leak_across_owners(store):
      """HIGH-27-02 regression: review with wrong owner returns
      empty, not the full task summary."""
      s = build_task_scope(description='secret', allow_rules=[{'pattern':'s3:*'}],
                           started_by='alice', owner='alice')
      store.add_task(s)
      # Wrong owner — should NOT leak description
      summary = store.task_review_summary(s.task_id, owner='bob')
      assert summary == {}

  def test_end_task_rejects_cross_owner(store):
      """HIGH-27-02 regression: end_task with wrong owner does
      nothing + returns False."""
      s = build_task_scope(description='x', allow_rules=[{'pattern':'eks:*'}],
                           started_by='alice', owner='alice')
      store.add_task(s)
      ended = store.end_task(s.task_id, actor='bob', owner='bob')
      assert not ended
      assert store.get_active_task(owner='alice') is not None
  ```

## MED findings

### MED-27-01 — `task_review_summary` has no LIMIT on decisions aggregation

- File: `src/iam_jit/bouncer/store.py:842-859`.

- Issue: `task_review_summary` reads every decision row matching `task_id`:
  ```python
  cur = self._conn.execute(
      "SELECT decision, service, action, arn, reason, at "
      "FROM decisions WHERE task_id = ? ORDER BY id",
      (task_id,),
  )
  rows = cur.fetchall()
  ...
  for r in rows:
      if r[0] == 'deny':
          denied.append({...})
  ```
  No LIMIT, no pagination, no truncation flag. A long-running task (24-hour cap allows tens of thousands of decisions for a chatty agent) returns the entire list verbatim. Verified via repro:
  ```
  decisions: 5000 denied: 5000
  ```
  Compare to `list_decisions` at `:534-574` which has an explicit `capped_limit = max(1, min(int(limit), 10_000))`. Same risk shape (unbounded payload over a JSON-RPC boundary) is hard-capped there but not here.

  Two failure modes:
  1. **MCP payload bloat**. `_bouncer_task_review_for_mcp` returns the summary dict verbatim to JSON-RPC. A 5,000-deny payload at ~200 bytes/entry = 1 MB JSON. Most JSON-RPC stacks handle this but some don't (Claude Code's MCP transport buffers; large payloads slow / fail).
  2. **CLI tail rendering**. `bouncer_cli.py:660-670` iterates `summary["denied_calls"]` and `click.echo`s each — for 5,000 entries this is 5,000 `click.echo` calls + 10,000 lines of stdout. Slow + impractical to read.

- Why MED (not LOW): real correctness gap relative to `list_decisions`'s explicit hard-cap. Single-line fix.

- Fix:
  ```python
  # store.py — mirror the list_decisions cap
  REVIEW_DECISION_CAP = 10_000
  cur = self._conn.execute(
      "SELECT decision, service, action, arn, reason, at "
      "FROM decisions WHERE task_id = ? ORDER BY id LIMIT ?",
      (task_id, REVIEW_DECISION_CAP + 1),
  )
  rows = cur.fetchall()
  truncated = len(rows) > REVIEW_DECISION_CAP
  rows = rows[:REVIEW_DECISION_CAP]
  ...
  return {
      ...
      'truncated': truncated,
      'decision_cap': REVIEW_DECISION_CAP,
  }
  ```

### MED-27-02 — `TaskScope.owner` accepts null bytes and non-printable characters

- File: `src/iam_jit/bouncer/tasks.py:196-203`.

- Issue: the owner validation at `tasks.py:196-203` checks non-empty + length cap but no charset check:
  ```python
  if owner is not None:
      if not isinstance(owner, str) or not owner.strip():
          raise TaskValidationError(...)
      if len(owner) > 256:
          raise TaskValidationError(...)
      cleaned_owner = owner.strip()
  ```
  Verified:
  ```python
  >>> s = build_task_scope(... owner='alice\x00bob')
  >>> s.owner
  'alice\x00bob'
  ```
  Effects:
  1. **Audit log corruption**. The `task_started` config_event row writes `started_by` (and indirectly via `actor`) into the audit log. A null byte in owner shows up in the log; most log readers truncate at `\x00`.
  2. **CSV/TSV export**. If owner is later exported (Enterprise tier's "live action tail" CSV export per [[live-action-tail-pro-tier]]), a null byte breaks the parser.
  3. **Downstream display**. CLI `tasks active --json` prints `"owner": "alice bob"` — JSON-correct but visually odd; if the operator pipes to `jq -r .owner` then to `mail`, the null byte propagates.

  Same shape as WB26 MED-26-03 which added validation for `started_by` non-empty + length cap, but left the charset open. Owner inherits the same gap.

- Why MED (not LOW): owner is a NEW field with no existing data; clean charset validation is easy to land now; later requires a backfill (drop or rename rows with bad owner values).

- Fix:
  ```python
  import re
  _OWNER_BAD_CHARS = re.compile(r'[\x00-\x1f\x7f]')
  
  if owner is not None:
      if not isinstance(owner, str) or not owner.strip():
          raise TaskValidationError(...)
      if len(owner) > 256:
          raise TaskValidationError(...)
      if _OWNER_BAD_CHARS.search(owner):
          raise TaskValidationError(
              "owner contains control characters (null bytes / control codes); "
              "use printable ASCII or UTF-8 letters/digits/punctuation"
          )
      cleaned_owner = owner.strip()
  ```
  Test:
  ```python
  @pytest.mark.parametrize("bad", ["alice\x00bob", "alice\x07bob", "alice\x7fbob"])
  def test_build_task_scope_rejects_control_chars_in_owner(bad):
      with pytest.raises(TaskValidationError, match="control characters"):
          build_task_scope(description='x', allow_rules=[{'pattern':'eks:*'}],
                           started_by='a', owner=bad)
  ```
  Worth applying the same regex to `started_by` (back-port for WB26 MED-26-03's closure).

### MED-27-03 — task_id collision risk at 12 hex chars; no FK on `decisions.task_id`

- Files:
  - `src/iam_jit/bouncer/tasks.py:206` (`task_id=task_id or uuid.uuid4().hex[:12]` — 48-bit hex)
  - `src/iam_jit/bouncer/store.py:179-192` (`task_id TEXT PRIMARY KEY`)
  - `src/iam_jit/bouncer/store.py:142-153` (decisions table — `task_id` column but NO foreign-key constraint)

- Issue: 12 hex chars = 48 bits. Birthday collision odds reach ~1% at ~2.3M tasks and ~50% at ~17M tasks. Realistic single-laptop deployment: never hits this. Realistic CI farm: could.

  Two scenarios:
  1. **Direct collision on `add_task`**: SQLite raises `IntegrityError` on PK constraint. Caller sees an unexpected exception (not `ActiveTaskExistsError`); MCP / CLI wrappers don't catch `IntegrityError`. Visible failure, not silent — fine.
  2. **Stale or hand-injected `task_id` in `decisions.task_id`**: there's no FK constraint, so a decisions row can claim `task_id='abc123'` for a task that doesn't exist (or was deleted). The `task_review_summary` first calls `get_task(task_id)` — if the task exists, it then aggregates decisions matching that task_id. If a stale orphan decision row exists matching a CURRENT live task_id (deleted task, recycled UUID — astronomically unlikely but technically possible), the review aggregates wrong data.

  Also: `record_decision` at `store.py:482-532` (WB26 MED-26-05 closure) re-checks task status at insert time and writes `task_id=NULL` if the task ended between fetch + record. Good — but only for the active-task-just-ended race; doesn't protect against a maliciously-fabricated task_id (e.g. via direct SQL).

- Why MED (not LOW): the audit-chain claim "task_review reflects decisions made during the task" is a load-bearing operator contract. Even a tiny risk of bad data showing up in a security review is worth a defensive measure.

- Fix options:
  1. **Bump the UUID prefix length** to 16 hex chars (64 bits — birthday collision at ~4B tasks). Trivial change; only the existing task_id length cap on display has to be adjusted (cosmetic).
  2. **Add a foreign key constraint** on `decisions.task_id` referencing `tasks.task_id`. SQLite supports this but `PRAGMA foreign_keys=OFF` is set at `store.py:118` — flipping it on may regress existing tests. Worth investigating.
  3. **Defensive query**: in `task_review_summary`, instead of `WHERE task_id = ?`, use a JOIN with `tasks` to ensure the task exists:
     ```sql
     SELECT d.decision, d.service, d.action, d.arn, d.reason, d.at
     FROM decisions d
     INNER JOIN tasks t ON d.task_id = t.task_id
     WHERE d.task_id = ? ORDER BY d.id
     ```
     Cheap; ensures only decisions that match a real task are aggregated.

  Recommend option 3 — cheapest path; defense in depth.

### MED-27-04 — `bouncer_end_task` has no owner parameter / isolation check

- File: `src/iam_jit/mcp_server.py:1912-1933`, `src/iam_jit/bouncer/store.py:773-788`.

- Issue: this is the API-asymmetry half of HIGH-27-02. `bouncer_start_task` takes an `owner` parameter (Slice C); `bouncer_active_task` takes an `owner` parameter (Slice C); but `bouncer_end_task` only takes `task_id`. The store's `end_task` only takes `task_id`.

  Effects:
  1. **Asymmetric API**: agents are encouraged to declare owner on start + active; but end-task ignores owner. A confused agent might assume passing `owner` would enforce isolation; passing `owner=X` for `bouncer_end_task` is silently ignored (extra-kwargs JSON-RPC tolerated).
  2. **Future workflow bugs**: a "auto-restart on end" workflow that uses the same owner finds itself confused if a different owner-session ended its task — the audit chain shows the end event but the workflow has no way to detect "this end wasn't from my owner."

  Confirmed by reading the MCP wrapper:
  ```python
  def _bouncer_end_task_for_mcp(args):
      task_id = args.get('task_id')
      if not isinstance(task_id, str) or not task_id.strip():
          return {'error': 'task_id is required and must be a non-empty string'}
      # NO owner check here
      ...
      ended = store.end_task(task_id, actor=_bouncer_actor(), end_reason=...)
  ```

- Why MED (not HIGH): the security framing of this finding (HIGH-27-02) carries the bigger weight; this MED captures the API-asymmetry / forward-compat concern.

- Fix: add optional `owner` parameter to `_bouncer_end_task_for_mcp` + `store.end_task`. If supplied, must match the task's stored owner; otherwise reject. Same pattern as HIGH-27-02's fix option 2.

### MED-27-05 — `test_mcp_three_task_tools_in_tools_list` is a subset assertion, not exact count

- File: `tests/bouncer/test_tasks.py:1021-1030`.

- Issue: the test asserts three Slice B tools are IN the tool list:
  ```python
  def test_mcp_three_task_tools_in_tools_list():
      ...
      names = {t['name'] for t in resp['result']['tools']}
      assert 'bouncer_start_task' in names
      assert 'bouncer_end_task' in names
      assert 'bouncer_active_task' in names
  ```
  Slice C added a 4th tool (`bouncer_task_review`) — no test verifies it's in the list. The existing test still passes (subset assertion); a regression that drops `bouncer_task_review` from `TOOLS` would NOT be caught.

  Same anti-pattern as WB25 LOW-25-01's drift surface: subset assertions don't catch removal regressions. The test name "three task tools" is also now stale — there are four.

- Why MED (not LOW): coverage gap with named regression risk (Slice D / future feature could drop `bouncer_task_review` and only the integration test would catch it — but the existing assertion doesn't).

- Fix: rename to `test_mcp_four_task_tools_in_tools_list` + assert exact-set OR maintain a `TASK_TOOL_NAMES` constant in the test module that the test asserts equality on. Pattern:
  ```python
  TASK_TOOL_NAMES = {'bouncer_start_task', 'bouncer_end_task',
                     'bouncer_active_task', 'bouncer_task_review'}
  
  def test_mcp_task_tools_in_tools_list():
      ...
      names = {t['name'] for t in resp['result']['tools']}
      assert TASK_TOOL_NAMES <= names  # subset
      # Also assert no UNKNOWN task tools snuck in (forward-compat)
      bouncer_task_names = {n for n in names
                            if n.startswith('bouncer_') and 'task' in n}
      assert bouncer_task_names == TASK_TOOL_NAMES
  ```

## LOW findings

### LOW-27-01 — Doc drift: `docs/IAM-JIT-BOUNCER.md` still says "ONE task active at a time in Slice B"

- File: `docs/IAM-JIT-BOUNCER.md:296-297`.

- Issue: the Task scope section says:
  > Only ONE task active at a time in Slice B. Slice C may add per-PID concurrent tasks.

  Slice C shipped:
  1. Per-OWNER (not per-PID) concurrent tasks.
  2. A `tasks review` report (CLI + MCP) — not mentioned in the doc.

  Operator reading the doc has incorrect information: thinks single-active is still the rule.

- Why LOW: documentation, not code; doesn't affect behavior. But the [[deliberate-feature-completion]] memo says a feature is "done" only when both halves of its loop work end-to-end — and docs are one half.

- Fix: update the doc to reflect per-owner concurrent tasks + add a "Review" subsection covering `tasks review` + `bouncer_task_review`. Roughly 30 lines added.

### LOW-27-02 — CLI `tasks active --owner ''` accepted but useless

- File: `src/iam_jit/bouncer_cli.py:585-595`.

- Issue: the CLI `tasks active` and `tasks start` `--owner` options use `default=None`. Passing `--owner ''` (empty string) from the shell is accepted at the click layer; `get_active_task(owner='')` queries `WHERE owner = ''` which never matches (no row has empty-string owner because `build_task_scope` rejects). Returns `None`. Confirmed:
  ```
  $ ... tasks active --owner '' ...
  No active task.
  ```

  Confusing because:
  1. `build_task_scope` REJECTS empty-string owner with `TaskValidationError`.
  2. CLI `tasks start --owner ''` would similarly reject in `build_task_scope`.
  3. But `tasks active --owner ''` silently returns None without explaining "empty-string owner is not a valid owner; use --owner with a name OR omit the flag."

- Why LOW: user gets the right answer (no active task); just an unclear surface.

- Fix: explicit check at the click layer:
  ```python
  if owner is not None and not owner.strip():
      click.echo("--owner cannot be empty; omit the flag for the default-owner slot", err=True)
      sys.exit(2)
  ```
  Same for `tasks start --owner`.

### LOW-27-03 — HIGH-27-02 cross-owner review reveals data; no Lens-A signal to the reviewer

- File: `src/iam_jit/bouncer/store.py:828-878`, `src/iam_jit/mcp_server.py:1947-1965`.

- Issue: until HIGH-27-02 is fixed, reviewing a cross-owner task succeeds silently. There's no Lens-A signal (`reviewing a task NOT owned by you`) to the agent. Per [[agent-friendly-not-bypassable]] Lens A, the agent should know when something unusual happened.

- Why LOW: only matters if HIGH-27-02 is fixed via documentation rather than enforcement. If the fix is enforcement, this LOW disappears.

- Fix: when the access check passes but the reviewer-owner != task-owner (e.g. admin reviewing a user task), include a `reviewer_owner` + `task_owner` distinction in the response. Today the response only includes `owner` (the task's owner); no record of who asked.

### LOW-27-04 — `_row_to_task_scope` 11-column backwards-compat branch is unreachable in practice

- File: `src/iam_jit/bouncer/store.py:889-913`.

- Issue: the `_row_to_task_scope` helper has two branches:
  ```python
  if len(row) == 12:
      (task_id, ..., owner) = row
  else:
      (task_id, ...) = row  # 11 elements
      owner = None
  ```
  Every SELECT in `store.py` post-Slice-C explicitly selects 12 columns (verified via grep). The 11-column branch fires only for hand-constructed test fixtures or a hypothetical "stale cursor from before migration" scenario — which doesn't exist (the migration runs in `__init__`).

  Not dead code per se (defensive), but the rationale isn't documented and the test surface that would exercise it is missing.

- Why LOW: defensive but uncovered. Lens-B "every code path is reachable from a test" suggests either remove (with comment) or add a test exercising the backwards-compat path.

- Fix: add a docstring explaining the rationale ("for tests that hand-construct rows; production migrations always make rows 12-column"). Or remove the branch and depend on tests using the canonical `build_task_scope` path.

### LOW-27-05 — `tasks review` on zero-decision task: exit 0 + visual confusion

- File: `src/iam_jit/bouncer_cli.py:640-668`.

- Issue: `tasks review <id>` for a task with no recorded decisions prints:
  ```
  task:        abc123
  description: x
  status:      active
  owner:       None
  window:      2026-05-17T00:00:00Z -> 2026-05-17T00:30:00Z
  decisions:   0 total (allow=0 deny=0 prompt=0)
  ```
  Exit code 0. No `denied calls (0):` section because the loop is gated by `if summary["denied_calls"]:`. This is correct behavior (zero decisions ≠ unknown task), but no test asserts the exit code or the rendering. A future change that makes this exit non-zero would slip silently.

- Why LOW: defensible behavior; no test coverage gap.

- Fix: add a test:
  ```python
  def test_cli_tasks_review_zero_decisions_exits_zero(cli_db):
      runner = CliRunner()
      runner.invoke(main, ['tasks', 'start', '--description', 'x',
                            '--allow', 'eks:*', '--db', cli_db])
      list_out = runner.invoke(main, ['tasks', 'list', '--json', '--db', cli_db])
      task_id = json.loads(list_out.output)[0]['task_id']
      result = runner.invoke(main, ['tasks', 'review', task_id, '--db', cli_db])
      assert result.exit_code == 0
      assert 'decisions:   0 total' in result.output
      assert 'denied calls' not in result.output
  ```

### LOW-27-06 — Per-task review reason strings include `task X active` redundantly

- File: `src/iam_jit/bouncer/decisions.py:251-263` (reason format), `src/iam_jit/bouncer/store.py:828-878` (review aggregation).

- Issue: when a task is active and a call is denied as "out-of-task-scope," the `reason` string is:
  ```
  "out-of-task-scope (task abc123 active; unmatched by task allow rules)"
  ```
  When an operator runs `tasks review abc123`, the per-denied-call output includes this reason verbatim for every entry:
  ```
  denied calls (4):
    2026-05-17T00:01:23Z  s3:DeleteObject
        -- out-of-task-scope (task abc123 active; unmatched by task allow rules)
    2026-05-17T00:01:24Z  iam:DeleteRole
        -- out-of-task-scope (task abc123 active; unmatched by task allow rules)
    ...
  ```
  The `(task abc123 active)` is redundant — the operator is REVIEWING task abc123; every denied call in this report happened during it. Verbose noise reduces signal.

- Why LOW: cosmetic; doesn't affect correctness.

- Fix options:
  1. **Reason string redesign**: shorten the standard reason to just `"out-of-task-scope (unmatched by task allow rules)"` since the task_id is on the row anyway via the FK to decisions.task_id; reviewer can cross-reference.
  2. **Strip in review rendering**: the CLI / MCP review path strips known noise from reasons before rendering — fragile.
  3. **Leave as-is**: the redundancy is harmless when reading INDIVIDUAL decisions; only redundant in the per-task review context. Document that this is intentional.

  Recommend option 1; the task_id is on the row, the reason doesn't need to re-state it.

## Verified clean

The following were probed per the audit prompt and found no issues:

- **Per-owner uniqueness atomicity (HIGH-26-02 regression check)** — verified the new SQL `WHERE status='active' AND (owner = ? OR (owner IS NULL AND ? IS NULL))` correctly handles NULL via the second branch (`owner IS NULL AND ? IS NULL` evaluates to true when both are NULL). The SQL runs inside `with self._lock` at `store.py:611-628`, matching WB26 HIGH-26-02's atomicity claim. Verified by 20-thread race repro: exactly 1 success + 19 `ActiveTaskExistsError`, no errors, for both the named-owner and default-owner (NULL) cases.
- **Default-owner semantics** — `add_task` with no owner inserts NULL owner; `get_active_task()` with no owner queries `WHERE owner IS NULL`; they correctly find each other. Verified via `test_slice_c_default_owner_isolated_from_named_owners` plus direct repro.
- **Default-owner isolated from named-owners** — a default-owner task (NULL) does NOT match `get_active_task(owner='agent-A')` because the SQL is `WHERE owner = 'agent-A'` (NULL = 'agent-A' is never true). Verified via repro.
- **TaskScope.owner field forward-compat** — direct grep for `TaskScope(` reveals only two construction sites: `tasks.py:205` (canonical `build_task_scope`) and `store.py:934` (`_row_to_task_scope`). Both updated correctly to include `owner`. No other callers bypass `build_task_scope`.
- **Schema migration safety (v3 → v4 on existing DB)** — verified via repro: a v3 DB without owner column correctly migrates: ALTER TABLE adds the column (NULL for existing rows), CREATE INDEX runs successfully, owner column appears in the table_info output. The HIGH-27-01 issue is ONLY for fresh DBs.
- **Backward compat (old code, new DB)** — if pre-Slice-C code's `_row_to_task_scope` SELECT had 11 columns, the new code's 12-column schema doesn't affect it (the old SELECT's column list is explicit). New code's add_task INSERT specifies all 12 columns including owner. No write-time incompat.
- **`is_expired` correctness** — unchanged from Slice B; still returns False for non-active status, parses ISO-Z correctly, works on the new TaskScope dataclass with `owner` field.
- **CLI `tasks list --owner` filter** — verified the SQL builder at `store.py:741-771` correctly appends `owner = ?` to the WHERE clause when owner is supplied. Empty result for unknown owner. Confirmed via `test_slice_c_list_tasks_filter_by_owner`.
- **CLI `tasks active --owner` with shell-special chars** — verified spaces, semicolons, and shell metacharacters in owner pass through verbatim via Click + DB binding; no SQL injection risk (parameterized binding). Confirmed via direct CliRunner repro.
- **MCP `bouncer_task_review` returns error (not crash) on bad input** — `task_id=''`, `task_id=None` (missing), `task_id='   '`, `task_id=123` (wrong type), `task_id='nonexistent'` all return structured `{'error': ...}` payloads. No exception escapes the wrapper.
- **MCP `bouncer_task_review` on completed task** — verified via direct repro: a task that was started, recorded decisions, then ended via `end_task` still returns a valid review summary with `status='completed'` and all decision counts intact.
- **Total MCP bouncer tools** — 13 (including the 4 task tools: `bouncer_start_task`, `bouncer_end_task`, `bouncer_active_task`, `bouncer_task_review`). All wired in `_handle_request` dispatcher at `mcp_server.py:2540-2546`.
- **`tasks review` CLI exit code on unknown task_id** — exits 1 (mirrors `tasks show`). Verified via `test_cli_tasks_review_unknown`.
- **TaskScope.owner length cap boundary** — exactly 256 chars accepted; 257 rejected with `TaskValidationError("owner max length is 256 chars")`. Verified.
- **`task_review_summary` empty for unknown task** — returns `{}` (not error); MCP wrapper converts to `{'error': ...}`; CLI exits 1. Lens A: agent gets a clear "no such task" signal.
- **`first_decision_at` / `last_decision_at` ordering** — verified ordering is by `id` (monotonic AUTOINCREMENT) not `at` string; two decisions in the same SQLite-second correctly preserve insertion order via id. Test `test_slice_c_review_aggregates_decisions` exercises 4 decisions; the implementation correctly threads the order.
- **MCP tool description accuracy** — the `bouncer_task_review` description at `mcp_server.py:960-970` accurately describes the response shape. The `bouncer_active_task` description at `mcp_server.py:1098-1110` correctly notes the optional `owner` parameter.
- **Slice B → Slice C migration safety for tasks** — existing Slice B tasks (no owner column) get NULL owner via ALTER TABLE default. Slice B's single-active invariant maps cleanly to per-owner with NULL = "default owner."

## Regression check

Command run: `cd /Users/reagan/repos/iam-roles && .venv/bin/python -m pytest --no-header -q --ignore=tests/test_calibration_corpus.py --ignore=tests/e2e 2>&1 | tail -5`

Result:
```
2478 passed, 29 skipped, 14 deselected, 2 warnings in 87.65s (0:01:27)
```

Matches the audit-prompt baseline (2478) exactly. All 17 new Slice-C tests pass. No regressions in any of the 2461 pre-Slice-C tests.

## Summary

**0 CRIT, 2 HIGH, 5 MED, 6 LOW.** Slice C extends Slice B's single-active-task model with per-owner concurrent tasks + per-task review. The data layer is clean (per-owner atomicity verified under 20-thread race; NULL handling correct; backwards-compat row decode safe). The bug concentration is in: (a) the migration block sharing a try/except for ALTER + INDEX, silently dropping the index on fresh DBs; (b) missing owner-based access control on review + end MCP/CLI surfaces; (c) test coverage drift (the subset-assertion test pattern that doesn't catch removal regressions).

The two HIGHs are the most impactful:

- **HIGH-27-01** (v4 migration's `CREATE INDEX idx_tasks_owner_status` silently skipped on fresh DBs at `store.py:210-216`): the index that every per-owner lookup depends on never gets created on fresh installs because it shares a try/except with `ALTER TABLE ADD COLUMN` which raises duplicate-column-error. Fix: split the two statements into separate try/except blocks (the `CREATE INDEX IF NOT EXISTS` is idempotent on its own and doesn't need a guard). 10-min fix + regression test.

- **HIGH-27-02** (`bouncer_task_review` + `bouncer_end_task` have no per-owner access check at `mcp_server.py:1947-1965` + `1912-1933`): any caller that can reach the bouncer MCP can review or end any task by passing its task_id. The Slice C multi-session isolation premise is structurally violated. Single-laptop deployments unaffected; CI runner / shared-VM / partner-hosted Enterprise contexts vulnerable. Fix: add optional `owner` parameter to both tools + reject when supplied-owner doesn't match the task's stored owner. ~30 min fix + tests.

The 5 MEDs cluster around three themes:

Schema / persistence integrity:
- **MED-27-01** (`task_review_summary` no LIMIT — unbounded payload over MCP).
- **MED-27-03** (12-hex-char task_id collision potential; no FK on `decisions.task_id`).

Validator gaps:
- **MED-27-02** (`TaskScope.owner` accepts null bytes + control chars — breaks audit log + CSV export downstream).
- **MED-27-04** (`bouncer_end_task` API asymmetry vs start/active — accepts no owner param).

Test coverage drift:
- **MED-27-05** (`test_mcp_three_task_tools_in_tools_list` is subset assertion; doesn't catch removal regressions; name + body stale for Slice C's 4-tool surface).

The 6 LOWs are: doc drift (LOW-27-01); empty-string CLI owner accepted (LOW-27-02); cross-owner review-without-Lens-A-signal (LOW-27-03); 11-column backwards-compat branch unreachable (LOW-27-04); zero-decision review exit code untested (LOW-27-05); redundant `task X active` in review reason strings (LOW-27-06).

Recommended closure-commit fix sequence:

1. **HIGH-27-01**: split the ALTER + CREATE INDEX into separate try/except blocks; add `test_v4_migration_creates_owner_index_on_fresh_db` to lock the invariant. ~10 min.
2. **HIGH-27-02 + MED-27-04**: add optional `owner` parameter to `task_review_summary`, `end_task` (store) + their MCP wrappers (`_bouncer_task_review_for_mcp`, `_bouncer_end_task_for_mcp`); when supplied, reject on mismatch (return `{}` for review, `False` for end_task; map to structured errors at MCP layer). Add regression tests for cross-owner access denial. ~30 min including tests.
3. **MED-27-01**: hard-cap `task_review_summary` decisions to 10,000 + add `truncated: true` flag; mirror `list_decisions` cap. ~15 min.
4. **MED-27-02**: charset validation on `TaskScope.owner` (reject `\x00-\x1f\x7f`); backport to `started_by` (WB26 MED-26-03's closure). ~10 min.
5. **MED-27-05**: rename `test_mcp_three_task_tools_in_tools_list` + add exact-set assertion for the bouncer_*task* tool surface. ~5 min.
6. **MED-27-03**: extend the review SQL to JOIN with tasks (defense-in-depth against stale/injected decisions.task_id). ~10 min.
7. **LOW-27-01**: update `docs/IAM-JIT-BOUNCER.md` — replace the "Slice B single active / Slice C per-PID" line with the actual per-owner shipped reality + add a Review section. ~15 min.
8. **LOW-27-02**: explicit empty-string `--owner ''` rejection at CLI layer (consistent with build_task_scope). ~5 min.
9. **LOW-27-04**: add docstring rationale to `_row_to_task_scope` 11-column branch OR remove + add test for the 12-column-only path. ~5 min.
10. **LOW-27-05**: add `test_cli_tasks_review_zero_decisions_exits_zero`. ~5 min.
11. **LOW-27-06**: shorten the `out-of-task-scope` reason to drop redundant `task X active` when the task_id is already on the decision row. ~5 min.

After fixes ship, re-run audit (Round 28) — recommended scope: re-probe HIGH-27-01 (fresh DB index creation) + HIGH-27-02 (cross-owner access denial under MCP).

The Slice C data layer is solid (per-owner atomicity is the load-bearing claim and it holds under threaded race for both named + default owners). The 13 findings concentrate at the migration-block layer (one try/except wrapping two statements), at the access-surface (review + end forgot to gain the same owner parameter that start + active got), and at the test-coverage drift surface (subset assertions, untested exit codes, stale test names). Same lesson WB23-WB26 keep teaching: foundation is reliably solid; cross-layer wiring is where invariants drift. Slice C compounds Slice B's single-active invariant with multi-owner isolation; the invariant generalization landed cleanly at the data layer but didn't propagate to every access path.

Audit ROI continues: 2 HIGHs (one of which is a migration-failure that the test suite by design doesn't exercise — tests use existing-DB fixtures that hit the v3→v4 path; one of which is a multi-session security gap the Slice C narrative implies isolation for), 5 MEDs catching unbounded-payload + validator-drift continuations. Per [[audit-cadence-discipline]] the BB+WB pattern continues to surface the cross-layer integration bugs the within-feature test suite doesn't catch.
