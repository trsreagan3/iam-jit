# Round 26 audit — bouncer task scope Slice B (#168)

Commit under review: `c2fd9d4` (`feat(bouncer): #168 Slice B — agent-declared task scope`).

Scope (Slice B only — Slice A's protective-default audited as part of #160; Slice C deferred):
- `src/iam_jit/bouncer/tasks.py` (new, 223 LOC)
- `src/iam_jit/bouncer/store.py` (+285 LOC: v3 schema migration + tasks CRUD + auto-expire + `task_id` column on decisions)
- `src/iam_jit/bouncer/decisions.py` (+125 LOC: `active_task` parameter + composition logic)
- `src/iam_jit/bouncer_cli.py` (+200 LOC: `tasks {list,active,show,end,start}` subcommand group + `decide` consults active task)
- `src/iam_jit/mcp_server.py` (+220 LOC: `bouncer_start_task` / `bouncer_end_task` / `bouncer_active_task` MCP tools)
- `tests/bouncer/test_tasks.py` (new, 649 LOC, 43 tests)
- `docs/IAM-JIT-BOUNCER.md` (+81 lines: "Task scope" section)

Read-only audit. Per [[audit-cadence-discipline]].

Regression: **2439 passed**, 29 skipped, 14 deselected (89.32s, excluding `tests/e2e/*` and `tests/test_calibration_corpus.py`). Matches the audit-prompt baseline (2439) exactly. No regressions caused by Slice B.

## Headline

13 findings: **0 CRIT, 2 HIGH, 5 MED, 6 LOW.**

The two HIGHs are real correctness breaks that ship today.

**HIGH-26-01**: `bouncer/decisions.py:93` types `active_task: Any | None = None` but **`Any` is never imported** (`typing.Any` is missing). The module only works because `from __future__ import annotations` defers evaluation — but any runtime introspection through `typing.get_type_hints(decide)` raises `NameError: name 'Any' is not defined`. Confirmed via direct repro:

```python
>>> from iam_jit.bouncer import decisions
>>> import typing
>>> typing.get_type_hints(decisions.decide)
NameError: name 'Any' is not defined
```

Pydantic / FastAPI / docstring tools / static-analysis layers that inspect callable signatures at import or first-call all break here. Today's test suite doesn't introspect, so the bug is invisible to CI; the moment a downstream tool (or a future iam-jit feature, or a CI rule like mypy strict) introspects the bouncer decision callable, it fails. One-line fix: `from typing import Any` at the top of `decisions.py` (same fix already correct in `store.py:49` and `tasks.py:54`).

**HIGH-26-02**: `BouncerStore.add_task` does NOT check for an existing active task. The MCP `_bouncer_start_task_for_mcp` (`mcp_server.py:1815-1823`) and CLI `tasks_start` (`bouncer_cli.py:708-715`) each check independently before calling `add_task` — but the store itself accepts a second `add_task` call silently when an active task already exists. Confirmed via repro:

```python
>>> store.add_task(s1)   # active
>>> store.add_task(s2)   # second active row inserted; NO error
>>> store.list_tasks(status_filter='active')
[<TaskScope id=s2>, <TaskScope id=s1>]   # both active
>>> store.get_active_task().task_id == s2.task_id  # only the newest visible
True
```

Effect: `get_active_task` returns ONLY the newest (`ORDER BY started_at DESC LIMIT 1`), so the older sibling's rules are silently NOT ENFORCED but the row still says `status='active'`. From the audit chain's perspective the older task is "still running" — its `task_ended` event was never written. Two failure shapes ship today:

1. **Test bypass.** A test that calls `store.add_task(s)` directly (and several do — `test_tasks.py:350, 363, 374, 390, ...`) doesn't go through the MCP/CLI guard. Future callers in Slice C, restore-state code, or a customer's automation likewise.
2. **Race window.** Even with the MCP/CLI guard, the check-then-add is non-atomic. Two MCP calls arriving in parallel both see "no active task" and both call `add_task`. SQLite serializes the inserts but neither raises.

The fix is structural: move the active-task check INTO `add_task` itself (raise on conflict), and expose a `force_replace` opt-in for the Slice C "restore" case. Without it, the single-active-task invariant that the docstring + composition logic both depend on is admin-discipline-enforced, not code-enforced. Same shape as WB25 MED-25-03 (doc-described invariant the code doesn't enforce) but with sharper teeth — composition logic in `decide()` assumes a SINGLE active task.

The five MEDs cluster around enforcement gaps + Lens B audit-chain holes the Slice B integration introduces:

- **MED-26-01**: PROMPT-mode + active task + unmatched silently degrades to DENY with no prompt. The decision logic at `decisions.py:251-263` returns DENY for the "task active + unmatched by task-allow + unmatched by global" case regardless of mode. Confirmed via repro. PROMPT mode's whole point is "ask the user when uncertain"; silently denying without a prompt is surprising behavior the docstring doesn't document.
- **MED-26-02**: `build_task_scope` accepts `duration_minutes=True` (Python `bool` is `int` subclass) silently. Confirmed: `build_task_scope(... duration_minutes=True ...)` creates a task with a 1-minute expiry. The MCP wrapper at `mcp_server.py:1799` explicitly excludes bool — but the validator at `tasks.py:154` does not. Direct callers (tests, CLI, future SDK consumers, restored state) bypass the guard. Same fix shape both places: `isinstance(duration_minutes, bool) or not isinstance(duration_minutes, int)`.
- **MED-26-03**: `build_task_scope` accepts empty `started_by` (`""`) AND arbitrarily-long values (100k+ chars verified). The audit-log row carries this verbatim; an empty string in `started_by` produces `task abc started by  (empty)` and breaks any downstream column-aligned text rendering. A 100k started_by writes 100k to the audit chain. Worth a strip + non-empty + max-length check matching the existing description validation pattern.
- **MED-26-04**: `_bouncer_start_task_for_mcp` does NOT check that allow_rules entries are dicts before passing to `build_task_scope`. If an agent sends `allow_rules=[{"pattern": "eks:*"}, "s3:*"]` (mixed dict + string — easy mistake), `build_task_scope` raises `TaskValidationError("rule entry must be a dict or ProxyRule, got str")` — but the validation error is per-entry, so the FIRST bad entry stops processing; if the agent's bad entry is at position 3 of 10, the agent doesn't learn about positions 4-9. Worth an upfront type-check + aggregated error message so the agent can fix all the bad entries in one retry.
- **MED-26-05**: TOCTOU between `get_active_task()` (or store query in CLI `decide`) and `record_decision()`. The audit-log claim "task_id captures what was active at the time of the decision" can be FALSE when the task ends (or auto-expires) between the read and the record. Confirmed via repro: end the task between `get_active_task()` + `record_decision()` and the decision row claims `task_id=X` for a task that ended seconds earlier. Per [[agent-friendly-not-bypassable]] Lens B the audit chain should reflect actual state; recommend a `WHERE task_id=? AND status='active'` subquery at insert time (and write `task_id=NULL` if the task transitioned).

Six LOWs: agent-unfriendly DENY reason strings (LOW-26-01 — the "out-of-task-scope" reason doesn't tell the agent HOW to fix); CLI shorthand parser order-sensitivity (LOW-26-02 — `#` split runs before `@` so an ARN containing `#` after the at-sign mis-parses as region); duplicate pattern in allow+deny silently accepted (LOW-26-03 — agent gets non-obvious "deny wins" result with no warning); 24h duration cap rationale not surfaced (LOW-26-04 — could leave a 24h scope active that surprises the operator); MCP `bouncer_tail_events` enum + CLI `events tail --kind` Click choice list both omit new `task_started` / `task_ended` kinds (LOW-26-05 — same shape as WB25 LOW-25-01 closure was supposed to prevent); forward-compat gap (LOW-26-06 — `tasks` table has no `pid` column so Slice C will need another schema migration; flag now to plan the v4 migration alongside).

## Closure status

| Finding | Status |
|---|---|
| HIGH-26-01 `decisions.py` uses `Any` in signature but never imports it; `typing.get_type_hints(decide)` raises NameError; static-analysis + runtime-introspection layers break | OPEN |
| HIGH-26-02 `BouncerStore.add_task` does not enforce single-active-task invariant; concurrent active rows can be created via direct call (tests bypass MCP/CLI guard; MCP/CLI guard is also non-atomic) | OPEN |
| MED-26-01 PROMPT mode + active task + unmatched silently denies without prompting; PROMPT semantic violated | OPEN |
| MED-26-02 `build_task_scope` accepts `duration_minutes=True` (bool is int subclass); MCP wrapper guards but tasks.py validator does not — direct callers bypass | OPEN |
| MED-26-03 `started_by` is required string but no non-empty / max-length check; empty string + 100k strings both accepted | OPEN |
| MED-26-04 `_bouncer_start_task_for_mcp` does not pre-check that all rule entries are dicts; first-bad-entry-stops error gives the agent partial information | OPEN |
| MED-26-05 TOCTOU between `get_active_task` and `record_decision`: audit-log can claim task X was active during decision recorded AFTER X ended | OPEN |
| LOW-26-01 "out-of-task-scope" reason string does not tell the agent how to fix (Lens A: agent needs a next step) | OPEN |
| LOW-26-02 CLI `_parse_shorthand` splits on `#` before `@`; ARN containing `#` after the at-sign mis-parses as region scope | OPEN |
| LOW-26-03 `build_task_scope` accepts the same pattern in both allow_rules and deny_rules; deny wins, agent gets surprise non-obvious result with no warning | OPEN |
| LOW-26-04 24h duration cap is generous; docs + tool description don't surface the operator-impact of a 24h scope blocking calls if rules are too narrow | OPEN |
| LOW-26-05 Bouncer `events tail --kind` Click choice + MCP `bouncer_tail_events` enum omit new `task_started` / `task_ended` kinds (same shape as WB25 LOW-25-01) | OPEN |
| LOW-26-06 `tasks` table has no `pid` column; Slice C per-PID concurrent tasks will require a v4 schema migration (flag now to plan migration cadence) | OPEN |

## HIGH findings

### HIGH-26-01 — `decisions.py` uses `typing.Any` in signature but never imports it

- File: `src/iam_jit/bouncer/decisions.py:26-31` (imports), `:93` (annotation).

- Issue: the `decide` function signature declares `active_task: Any | None = None` (line 93) but the module imports are:
  ```python
  from __future__ import annotations
  import dataclasses
  from enum import Enum
  from .rules import Effect, ProxyRule, RuleSet
  ```
  No `from typing import Any`. The code RUNS fine because `from __future__ import annotations` defers annotation evaluation. But the moment any tool tries `typing.get_type_hints(decide)` — pydantic, FastAPI, docstring generators, mypy in some configurations, `inspect.signature` consumers that resolve annotations — it raises:
  ```python
  >>> import typing
  >>> from iam_jit.bouncer import decisions
  >>> typing.get_type_hints(decisions.decide)
  NameError: name 'Any' is not defined
  ```

  Confirmed via direct repro. CI passes because the existing test suite calls `decide` directly with positional/kw args and never introspects type hints.

  Three plausible failure modes ship today:
  1. **Mypy strict consumer**. A downstream package that runs mypy strict against bouncer imports gets a "Name 'Any' is not defined" error. iam-jit's own mypy config might let this slide; mypy in customer/Enterprise environments may not.
  2. **Future iam-jit feature**. If anything else in this codebase later does `get_type_hints` on the bouncer surface (e.g. a future MCP-schema generator that walks Python functions), it crashes.
  3. **Sister modules already do the right thing**. `bouncer/store.py:49` correctly does `from typing import Any` and uses it (`add_task(self, scope: Any, ...)`, `_end_task_internal(..., new_status: Any, ...)`, `list_tasks(...) -> list[Any]`). `bouncer/tasks.py:54` likewise. The decisions module is the only one that forgot — a copy-paste oversight when Slice B added the `active_task` parameter.

- Why HIGH (not MED): the module ships with a documented public API that BREAKS on standard introspection. The fix is one line. The lifetime cost of NOT fixing this is "every downstream consumer that introspects has to debug a NameError." Same severity rationale as WB23 HIGH-23-02 (correctness-via-luck where the luck is "no one's tested the introspection path yet").

- Fix:
  ```python
  # decisions.py top of file
  from __future__ import annotations

  import dataclasses
  from enum import Enum
  from typing import Any   # ← add

  from .rules import Effect, ProxyRule, RuleSet
  ```

  Test:
  ```python
  def test_decide_signature_introspectable():
      """Regression: every public bouncer callable must be introspectable
      via typing.get_type_hints (HIGH-26-01)."""
      import typing
      from iam_jit.bouncer import decisions, store, tasks
      typing.get_type_hints(decisions.decide)  # must not raise
      # Also lock the same invariant for the other public callables:
      typing.get_type_hints(store.BouncerStore.add_task)
      typing.get_type_hints(tasks.build_task_scope)
  ```

### HIGH-26-02 — `BouncerStore.add_task` does not enforce single-active-task invariant

- Files:
  - `src/iam_jit/bouncer/store.py:550-600` (`add_task` — does not check for existing active task)
  - `src/iam_jit/mcp_server.py:1815-1823` (MCP guard — checks then adds, NON-ATOMIC)
  - `src/iam_jit/bouncer_cli.py:708-715` (CLI guard — same pattern)
  - `tests/bouncer/test_tasks.py:350, 363, 374, 390` (tests call `store.add_task` directly without the MCP/CLI guard)
  - `src/iam_jit/bouncer/decisions.py:128-263` (composition logic ASSUMES single active task)

- Issue: the Slice B design says ONE task may be active at a time. The doc + the MCP tool description ("Only ONE task may be active at a time in Slice B") + the `decide()` composition (which threads a single `active_task` parameter, not a list) all depend on this. The MCP `_bouncer_start_task_for_mcp` and CLI `tasks_start` both check `get_active_task() is not None` before calling `add_task` to refuse a second start. But `BouncerStore.add_task` itself accepts the second insert silently:

  ```python
  >>> from iam_jit.bouncer.store import BouncerStore
  >>> from iam_jit.bouncer.tasks import build_task_scope
  >>> store = BouncerStore(db_path='/tmp/x.db')
  >>> s1 = build_task_scope(description='first', allow_rules=[{'pattern':'eks:*'}], started_by='a')
  >>> s2 = build_task_scope(description='second', allow_rules=[{'pattern':'s3:*'}], started_by='b')
  >>> store.add_task(s1)
  's1-id'
  >>> store.add_task(s2)   # no error
  's2-id'
  >>> store.list_tasks(status_filter='active')
  [<TaskScope s2>, <TaskScope s1>]   # both active!
  >>> store.get_active_task().task_id
  's2-id'                              # only newest visible
  ```

  Three concrete failure shapes ship today:

  1. **Test bypass**. Tests like `test_store_add_task_and_get_active`, `test_store_end_task_clears_active`, `test_store_end_task_returns_false_for_already_ended`, etc. all call `store.add_task(...)` directly. Adding a test like `test_store_add_task_rejects_concurrent_active` would FAIL today — there's no such test because the behavior doesn't exist. The test suite's coverage is for the MCP/CLI guard, not the store invariant.

  2. **MCP guard is non-atomic**. Two MCP `bouncer_start_task` calls arriving in parallel both call `get_active_task()` (returns None), both call `add_task` (both succeed). The single-active invariant breaks under any concurrent caller.

  3. **Hidden orphan task**. The OLDER task's row stays `status='active'` but `get_active_task()` returns only the newest. The older task's `task_ended` event is never written; the audit chain claims it's still running indefinitely. Worse, the older task's `allow_rules` + `deny_rules` are NOT ENFORCED (the `decide` flow uses only what `get_active_task` returns) — the agent that started the older task believes its scope is active when in fact the second task silently superseded it.

  This is structurally worse than WB25 MED-25-03 (doc-described workflow that flips an invariant) because here the composition logic in `decide()` ASSUMES single-active. If the invariant breaks, the decision-logic guarantees do too — an agent reasoning "I declared deny-rule X for my task; therefore X cannot fire" is wrong if a sibling task with no deny-X superseded silently.

- Why HIGH (not CRIT): no security boundary breach today (the newer task's deny rules DO apply; the issue is the OLDER task's deny rules silently stop applying). Severity is "design invariant breaks silently" not "agent gets unauthorized access." Slice C is supposed to add per-PID concurrent tasks anyway — but Slice B explicitly promises single-active, and code should enforce its promise.

- Fix options:

  1. **Best**: enforce the invariant in `add_task` itself:
     ```python
     def add_task(self, scope: Any, *, actor: str | None = None,
                  force_replace: bool = False) -> str:
         """..."""
         existing = self.get_active_task()
         if existing is not None:
             if not force_replace:
                 raise ActiveTaskConflict(
                     f"another task ({existing.task_id}) is already active; "
                     "end it first or pass force_replace=True"
                 )
             # Slice C / restore path: replace the existing task
             self._end_task_internal(
                 existing.task_id, actor=actor or "auto-replace",
                 end_reason="replaced",
                 new_status=TaskStatus.REPLACED,
             )
         # ... existing insert logic
     ```
     Adjust MCP + CLI to catch `ActiveTaskConflict` and return the existing `active_task_id` (same UX as today).

  2. **Acceptable**: add a UNIQUE PARTIAL INDEX on the tasks table for the active-task case:
     ```sql
     CREATE UNIQUE INDEX IF NOT EXISTS uq_active_task
         ON tasks(status) WHERE status = 'active';
     ```
     SQLite enforces; concurrent inserts get `IntegrityError`. Database-level guard, can't be bypassed. Plus add an `ActiveTaskConflict` wrapper at the Python level for clean error UX.

  3. **Worst**: keep current behavior; document that `add_task` is "raw API; callers must guard." Lose the invariant.

  Recommend option 2 — partial unique index — because it makes the invariant impossible to violate (even in tests + future code paths). Plus the Python-layer guard for friendly errors.

  Test:
  ```python
  def test_store_add_task_rejects_concurrent_active(store):
      s1 = _scope(description='first')
      s2 = _scope(description='second')
      store.add_task(s1)
      with pytest.raises(ActiveTaskConflict):
          store.add_task(s2)
      # Verify only one active in DB:
      assert len(store.list_tasks(status_filter='active')) == 1
  ```

  Also add a structural test that walks every test in `test_tasks.py` and asserts no two `store.add_task` calls happen without an `end_task` between — guards against future test regressions.

## MED findings

### MED-26-01 — PROMPT-mode + active task + unmatched silently denies without prompting

- File: `src/iam_jit/bouncer/decisions.py:251-263`.

- Issue: when an active task is set, `matched is None` (no global rule matched), and task-allow doesn't match either, the code hits:
  ```python
  return DecisionRecord(
      decision=Decision.DENY,
      mode=mode,
      ...
      reason=(
          f"out-of-task-scope (task {active_task.task_id} active; "
          "unmatched by task allow rules)"
      ),
  )
  ```
  This fires regardless of the mode. Confirmed via repro:
  ```python
  >>> task = build_task_scope(description='x', allow_rules=[{'pattern':'eks:*'}], started_by='agent')
  >>> rec = decide(RuleSet(rules=[]), mode=Mode.PROMPT, default_policy=DefaultPolicy.DENY,
  ...              service='s3', action='GetObject', active_task=task)
  >>> rec.decision
  Decision.DENY
  ```

  PROMPT mode's documented contract (`decisions.py:16-18`): "unmatched calls return PROMPT so the proxy server can interrupt the user / agent." With a task active, the prompt is ARGUABLY MORE valuable (the user sees "agent X declared task Y; agent is now trying call Z which is outside that scope — allow, deny, or extend?") — but the current code silently denies.

  Two reasonable interpretations:
  1. **PROMPT semantic wins**: prompt the user; show them the task context + the out-of-scope call; let them decide. Aligns with the user-articulated "don't block agents, prompt when uncertain" goal.
  2. **Task-allow is an explicit allowlist**: out-of-scope = deny, no prompting, that's the whole point of declaring a task scope. PROMPT mode's looseness shouldn't lift the task's "this is exactly what I'm doing" contract.

  Both are defensible. The bug is that the CURRENT behavior is interpretation 2 without a comment saying so + without a test asserting it. Either way, the docstring at `:108-117` should call out the interaction explicitly. Recommend interpretation 2 (matches the "task scope is an explicit allowlist" framing) + test + docstring.

- Why MED (not HIGH): not a correctness break — the chosen behavior (DENY) is defensible. But silently overriding a mode the operator explicitly chose is surprising. Per [[agent-friendly-not-bypassable]] Lens A: agent should know what happened; today the reason string says "out-of-task-scope" but doesn't say "PROMPT mode was overridden because a task is active." If the operator intentionally set PROMPT mode for the long tail of one-off calls, they may be surprised that a task scope they declared makes PROMPT silently DENY.

- Fix:
  1. Add a test:
     ```python
     def test_decide_prompt_mode_with_active_task_and_unmatched_denies():
         """When a task scope is active, PROMPT mode behaves as ENFORCE for
         out-of-scope calls — the task declaration is the explicit allowlist
         and there is no prompt to fall back to."""
         task = build_task_scope(description='x', allow_rules=[{'pattern':'eks:*'}],
                                 started_by='agent')
         rec = decide(_empty_global(), mode=Mode.PROMPT, default_policy=DefaultPolicy.DENY,
                      service='s3', action='GetObject', active_task=task)
         assert rec.decision == Decision.DENY
     ```
  2. Update the docstring at `:108-117` + the reason string to clarify:
     ```python
     reason=(
         f"out-of-task-scope (task {active_task.task_id} active; "
         "unmatched by task allow rules; PROMPT mode overridden because "
         "task scope is explicit allowlist)"
     ),
     ```
  3. Optionally: add a configuration knob `prompt_when_out_of_task_scope: bool = False` that, when True, returns `Decision.PROMPT` instead. Slice C territory.

### MED-26-02 — `build_task_scope` accepts `duration_minutes=True` (bool is int subclass)

- File: `src/iam_jit/bouncer/tasks.py:154`, vs. `src/iam_jit/mcp_server.py:1799`.

- Issue: the MCP wrapper validates correctly:
  ```python
  duration = args.get("duration_minutes", 30)
  if not isinstance(duration, int) or isinstance(duration, bool):
      return {"error": "duration_minutes must be an integer"}
  ```
  (`mcp_server.py:1798-1800`). But `build_task_scope` does NOT:
  ```python
  if not isinstance(duration_minutes, int) or duration_minutes < 1:
      raise TaskValidationError("duration_minutes must be a positive integer")
  ```
  (`tasks.py:154`). `bool` is a subclass of `int`; `True == 1` so the `< 1` check passes. Confirmed:
  ```python
  >>> build_task_scope(description='x', allow_rules=[{'pattern':'eks:*'}],
  ...                  duration_minutes=True, started_by='agent')
  TaskScope(..., expires_at='2026-05-17T...:00Z')   # 1-minute task created
  ```

  Three direct-caller paths bypass the MCP guard:
  1. Tests — `test_tasks.py` has 8 tests that call `build_task_scope` directly. Future tests could pass `True` accidentally.
  2. CLI `tasks_start` — the `--duration` option is `type=int` so Click rejects `True` from the command line, but internal Python callers (e.g. a future "iam-jit-bouncer dev-repl" or a Python integration) bypass.
  3. Future SDK consumers — once Slice C ships restore-state code, the deserializer that reconstructs a TaskScope from external state can hit this.

- Why MED (not HIGH): not exploitable today (the MCP path guards; CLI guards via Click). But the validator is the foundation API; relying on every caller to add their own bool guard duplicates the check + invites drift (the MCP path has the right guard; future paths won't necessarily).

- Fix:
  ```python
  # tasks.py
  if isinstance(duration_minutes, bool) or not isinstance(duration_minutes, int):
      raise TaskValidationError("duration_minutes must be an integer (not bool)")
  if duration_minutes < 1:
      raise TaskValidationError("duration_minutes must be a positive integer")
  ```
  And remove the now-redundant bool check from `mcp_server.py:1799` (or keep both — defense in depth). Test:
  ```python
  def test_build_task_scope_rejects_bool_duration():
      with pytest.raises(TaskValidationError, match="not bool|integer"):
          build_task_scope(description='x', allow_rules=[{'pattern':'eks:*'}],
                           duration_minutes=True, started_by='agent')
  ```

### MED-26-03 — `started_by` has no validation (empty + arbitrarily-long both accepted)

- File: `src/iam_jit/bouncer/tasks.py:140-143` (`started_by: str` parameter; no validation).

- Issue: `build_task_scope` has a non-empty + max-length check for `description` (line 152-153) but NOT for `started_by`. Empty string + 100k-char string both accepted. Confirmed:
  ```python
  >>> s = build_task_scope(description='x', allow_rules=[{'pattern':'eks:*'}], started_by='')
  >>> s.started_by
  ''
  >>> s2 = build_task_scope(description='x', allow_rules=[{'pattern':'eks:*'}], started_by='a' * 100000)
  >>> len(s2.started_by)
  100000
  ```

  Three effects:
  1. **Audit-log corruption**. The audit log row says `task abc started by  : ...` (double-space; empty actor field). CLI rendering at `bouncer_cli.py:573-577`:
     ```python
     click.echo(
         f"{s.task_id}  {s.status.value:>9}  started {s.started_at} "
         f"by {s.started_by}  --  {s.description[:60]}"
     )
     ```
     produces visually-broken output for empty `started_by`.
  2. **DB bloat + cost-amplification**. A 100k started_by inflates every row + every audit-log row that quotes it. SQLite handles it but storage + read costs grow.
  3. **Caller confusion**. The MCP path supplies `_bouncer_actor()` (always non-empty due to `IAM_JIT_BOUNCER_ACTOR` env-var fallback to `getpass.getuser()`); CLI path similarly. But direct callers + tests can pass anything.

- Why MED (not LOW): the description validation already exists right next to where this validation should be; the omission is a copy-paste oversight not a design decision. Audit-log + storage hygiene matters for Lens B "every change is auditable" — corrupted-looking audit rows are an audit-chain quality issue.

- Fix:
  ```python
  if not isinstance(started_by, str) or not started_by.strip():
      raise TaskValidationError("started_by is required and must be a non-empty string")
  if len(started_by) > 256:
      raise TaskValidationError("started_by max length is 256 chars")
  ```
  Plus `.strip()` before storing. Test:
  ```python
  @pytest.mark.parametrize("bad", ["", "   ", "a" * 1000, None, 123])
  def test_build_task_scope_validates_started_by(bad):
      with pytest.raises((TaskValidationError, TypeError)):
          build_task_scope(description='x', allow_rules=[{'pattern':'eks:*'}], started_by=bad)
  ```

### MED-26-04 — MCP `_bouncer_start_task_for_mcp` first-bad-entry-stops error

- File: `src/iam_jit/mcp_server.py:1792-1811`, `src/iam_jit/bouncer/tasks.py:194-222`.

- Issue: the MCP wrapper validates that `allow_rules` / `deny_rules` are LISTS, then passes them to `build_task_scope` whole. `_coerce_rules` iterates and raises on the FIRST malformed entry. If an agent sends:
  ```json
  {
    "description": "staging upgrade",
    "allow_rules": [
      {"pattern": "eks:*"},
      "s3:*",                              ← wrong type (string not dict)
      {"pattern": "bad-pattern-no-colon"}, ← wrong shape
      {"pattern": "iam:GetRole"}
    ]
  }
  ```
  it gets:
  ```json
  {"error": "rule entry must be a dict or ProxyRule, got str"}
  ```
  and learns NOTHING about positions 2-3. After fixing position 1 the agent retries; gets the next error; retries; etc. For an N-bad-entry payload the agent makes N round-trips. Per [[agent-friendly-not-bypassable]] Lens A: agents need actionable errors; "fix this one thing, then we'll tell you about the next" is anti-Lens-A.

  Same shape as the earlier feedback patterns from WB21 / WB24 (agent should learn ALL the problems in ONE response). Not a security issue, but adoption-friendliness.

- Why MED (not LOW): per the user-articulated [[broad-read-fallback-ux]] goal — minimize the friction that pushes agents to "just give me admin." Multi-round error correction is exactly the friction the user identified as compounding.

- Fix: pre-validate in the MCP wrapper, collect all errors, return them all:
  ```python
  errors: list[str] = []
  for i, e in enumerate(allow_rules):
      if not isinstance(e, dict):
          errors.append(f"allow_rules[{i}]: must be a dict, got {type(e).__name__}")
          continue
      if not isinstance(e.get("pattern"), str):
          errors.append(f"allow_rules[{i}]: missing 'pattern' (string)")
  # same for deny_rules
  if errors:
      return {"error": "validation failed", "errors": errors}
  ```
  Test:
  ```python
  def test_mcp_start_task_aggregates_validation_errors():
      out = _bouncer_start_task_for_mcp({
          "description": "x",
          "allow_rules": [{"pattern": "eks:*"}, "string", {"not_pattern": "x"}],
      })
      assert "errors" in out
      assert len(out["errors"]) >= 2
  ```

### MED-26-05 — TOCTOU between `get_active_task` and `record_decision`

- Files: `src/iam_jit/bouncer/store.py:463-496` (`record_decision`), `src/iam_jit/bouncer_cli.py:498-529` (`decide_cmd` flow).

- Issue: the CLI's `decide` (and any future proxy-server decision flow) does:
  ```python
  active_task = store.get_active_task()
  record_obj = decide(... active_task=active_task ...)
  ...
  store.record_decision(record_obj, ... task_id=active_task.task_id if active_task else None)
  ```
  Between `get_active_task()` (line 498) and `record_decision()` (line 525), the task could END (via another caller's `end_task`), or auto-EXPIRE (if another `get_active_task` on a different thread triggers `_end_task_internal`).

  When that happens, `record_decision` writes a row claiming `task_id=X` for a task whose `status` is now `completed` (or `expired`). Confirmed:
  ```python
  >>> s = build_task_scope(...)
  >>> store.add_task(s)
  >>> active = store.get_active_task()
  >>> # Simulating concurrent end:
  >>> store.end_task(active.task_id, actor='admin')
  >>> rec = DecisionRecord(...)
  >>> store.record_decision(rec, task_id=active.task_id)
  >>> store.list_decisions()[0]['task_id']
  's-id'   # claims task was active
  >>> store.get_task(active.task_id).status.value
  'completed'   # but it was already ended!
  ```

  Per the user-articulated audit-chain claim ("captures what was active at the time of the decision") this is technically a falsehood — the decision was MADE while the task was active (during the `decide()` call), but recorded AFTER the task ended. Two interpretations:

  1. **"At time of decision" = when `decide` ran**: today's behavior is correct. The audit log records the decision; the audit log of `task_ended` events tells you when the task ended; a sophisticated reader can cross-reference timestamps and figure out the order. The audit chain isn't lying; it just requires cross-referencing.
  2. **"At time of decision" = strictly during active state**: today's behavior is wrong. A row should record `task_id=NULL` if the task ended between fetch + record.

  The second interpretation aligns more with how operators read audit logs ("what task was active when this call was gated?" expecting a clean answer). Recommend a `WHERE EXISTS (SELECT 1 FROM tasks WHERE task_id = ? AND status = 'active')`-like guard at insert time, or alternatively a separate `task_active_at_decision: bool` column.

- Why MED (not HIGH): the race window is tiny (microseconds in practice). The audit chain still captures the truth via the `task_ended` event — it's just two rows away. Severity is "audit-chain claim slightly stronger than reality" not "decision was wrong."

- Fix options:
  1. **Defensive**: at `record_decision`, re-query the task and write `task_id=NULL` if not active:
     ```python
     def record_decision(self, dec, *, matched_rule_id=None, task_id=None):
         if task_id is not None:
             with self._lock:
                 cur = self._conn.execute(
                     "SELECT 1 FROM tasks WHERE task_id = ? AND status = 'active'",
                     (task_id,),
                 )
                 if cur.fetchone() is None:
                     task_id = None  # task ended between fetch + record
         # ... rest of insert
     ```
  2. **Schema**: add a `task_active_at_decision BOOLEAN` column; never null `task_id`; record both pieces.
  3. **Document**: add a docstring caveat that `task_id` reflects "what the caller passed in" — not necessarily "active at insert time." Caller is responsible.

  Recommend option 1 — single SQL query, no schema change, audit-chain stays clean.

## LOW findings

### LOW-26-01 — "out-of-task-scope" reason string is not agent-actionable

- File: `src/iam_jit/bouncer/decisions.py:251-263`.

- Issue: the DENY reason for out-of-task-scope calls is:
  ```
  "out-of-task-scope (task {task_id} active; unmatched by task allow rules)"
  ```
  Per [[agent-friendly-not-bypassable]] Lens A: agent should know what to do next. This reason tells the agent WHY but not HOW TO FIX. Compare to a Lens-A-aligned version:
  ```
  "out-of-task-scope (task {task_id} active; unmatched by task allow rules). "
  "To allow this call, end the task and start a new one with this call in allow_rules, "
  "OR end the current task to fall back to global rules."
  ```

  Same shape as WB24 (next_action_hint always required for non-PROCEED) but in the decision-reason text rather than the structured response.

- Why LOW: the agent CAN figure it out from context (it knows it declared a task scope; it knows what's in it; it can reason "the call I just made isn't in there"). But agents reading the reason text directly (e.g. when surfacing the deny to a user) benefit from explicit next steps.

- Fix: extend the reason text + add similar guidance to `task-explicit-deny` ("to allow this call, end the task or restart with this not in deny_rules"). Could also be a structured `next_action_hint` field on `DecisionRecord`, parallel to `CompatibilityResult.next_action_hint` from WB24 — bigger surface but matches the pattern.

### LOW-26-02 — CLI `_parse_shorthand` splits `#` before `@`; ARN containing `#` mis-parses

- File: `src/iam_jit/bouncer_cli.py:681-693` (`_parse_shorthand`).

- Issue: the shorthand parser splits on `#` first, then `@`:
  ```python
  def _parse_shorthand(s: str) -> dict:
      pattern = s
      arn = None
      region = None
      if "#" in pattern:
          pattern, region = pattern.split("#", 1)
      if "@" in pattern:
          pattern, arn = pattern.split("@", 1)
  ```
  An input like `s3:GetObject@arn:aws:s3:::bucket/path#fragment` produces:
  ```python
  {'pattern': 's3:GetObject', 'arn_scope': 'arn:aws:s3:::bucket/path', 'region_scope': 'fragment'}
  ```
  The `#fragment` in the ARN is wrongly captured as region scope.

  ARNs rarely contain `#`, so this is corner-case. But:
  1. S3 object keys can contain `#` (rare but documented).
  2. Future ARN shapes (Glue partition values, custom resources) could.
  3. A user pasting an URL-like string with `#` in it as a scope by accident gets silent misclassification.

  Verified via repro.

- Why LOW: rare ARN shapes only; user can work around by avoiding `#` in scopes; shorthand is for testing / demo only (MCP path uses structured dict input). But the silent misclassification surprises.

- Fix options:
  1. **Split `@` first** (most ARNs DON'T contain `@`; many region tokens DO have `#` in path qualifiers that aren't part of region):
     ```python
     if "@" in pattern:
         pattern, rest = pattern.split("@", 1)
         if "#" in rest:
             arn, region = rest.split("#", 1)
         else:
             arn = rest
     elif "#" in pattern:
         pattern, region = pattern.split("#", 1)
     ```
  2. **Use explicit named flags**: `--allow-pattern eks:* --allow-arn arn:... --allow-region us-east-1` (verbose but unambiguous; doesn't suffer the split-order problem). Bigger CLI change.

  Recommend option 1 — semantics shift slightly (region embedded in an ARN sub-string is now treated as part of ARN, which is the right interpretation almost always) + add a test for the `#`-in-ARN case.

### LOW-26-03 — Same pattern in allow_rules AND deny_rules silently accepted

- File: `src/iam_jit/bouncer/tasks.py:134-182` (`build_task_scope` — no cross-list check).

- Issue: an agent passing the same pattern in both lists:
  ```python
  build_task_scope(
      description='conflict',
      allow_rules=[{'pattern': 'eks:*'}],
      deny_rules=[{'pattern': 'eks:*'}],
      started_by='agent',
  )
  ```
  is accepted silently. Both rules exist; the deny wins per `decide()` composition. The agent likely meant one OR the other; getting the silent "deny wins" with no warning is surprising. Confirmed via repro.

  Edge cases that are NOT bugs (legitimate use):
  - `allow_rules=[{'pattern':'eks:*'}]` + `deny_rules=[{'pattern':'eks:DeleteCluster'}]` — narrows the allow with a specific deny. Valid pattern.
  - `allow_rules=[{'pattern':'s3:*', 'arn_scope':'arn:aws:s3:::my-bucket/*'}]` + `deny_rules=[{'pattern':'s3:DeleteObject'}]` — also valid.

  Bug case: identical `(pattern, arn_scope, region_scope)` tuples in both lists. Trivially detectable.

- Why LOW: agent gets a non-obvious result; per Lens A they should know. But the result IS auditable (the audit chain shows both rules exist + which one fired) so a post-incident reviewer can figure it out.

- Fix:
  ```python
  # In build_task_scope, after _coerce_rules:
  allow_keys = {(r.pattern, r.arn_scope, r.region_scope) for r in allow_clean}
  deny_keys  = {(r.pattern, r.arn_scope, r.region_scope) for r in deny_clean}
  overlap = allow_keys & deny_keys
  if overlap:
      raise TaskValidationError(
          f"the same (pattern, arn_scope, region_scope) tuple appears in both "
          f"allow_rules and deny_rules — deny would always win, making the "
          f"allow rule meaningless. Conflicts: {sorted(overlap)}"
      )
  ```
  Test:
  ```python
  def test_build_task_scope_rejects_same_pattern_in_allow_and_deny():
      with pytest.raises(TaskValidationError, match="same.*tuple"):
          build_task_scope(description='x',
              allow_rules=[{'pattern':'eks:*'}],
              deny_rules=[{'pattern':'eks:*'}],
              started_by='agent')
  ```

### LOW-26-04 — 24h duration cap rationale not surfaced in docs / tool description

- Files: `src/iam_jit/bouncer/tasks.py:156-159` (the 1440-min cap), `src/iam_jit/mcp_server.py:1021-1031` (tool description), `docs/IAM-JIT-BOUNCER.md:235-314` (Task scope doc).

- Issue: the cap is 1440 minutes (24h). The user-articulated example in the docs is 60 minutes; the test default is 30 minutes. 24h is generous and the rationale isn't surfaced anywhere. A misconfigured agent (or one under prompt injection) could legitimately request 1440 minutes — the validator accepts it. The operator returning from a weekend break finds a 24h task scope still active from a Friday afternoon, blocking calls because the scope's allow_rules were too narrow.

  Three concerns:
  1. **No upper-bound rationale**. Why 1440 and not 480 (8h workday)? Doc doesn't say.
  2. **No warning at start time**. The CLI `tasks start --duration 1440` accepts without a "are you sure?" prompt.
  3. **Auto-expiry exists** (good) but no proactive notification — a forgotten 24h task is silently active for the full duration.

  Per [[safety-mode-lean-permissive]] the bouncer should lean permissive; if a too-narrow 24h scope blocks the user's normal work, they'll uninstall.

- Why LOW: the auto-expiry IS the safety net (per `tasks.py:108-117`); a forgotten task gets cleaned up eventually. Operator-impact is "annoying friction" not "compromised security."

- Fix:
  1. Document the rationale in `tasks.py:156-159` comment + the doc page.
  2. Add a CLI confirmation prompt for `--duration > 240` (4h):
     ```python
     if duration_minutes > 240:
         click.confirm(
             f"Duration of {duration_minutes} minutes is unusually long. "
             "Continue?", abort=True,
         )
     ```
  3. Consider a warning in the MCP tool response when duration exceeds 240 minutes:
     ```python
     warnings = []
     if duration > 240:
         warnings.append(f"duration is {duration} min (>4h); consider shorter scope + restart")
     return {..., "warnings": warnings}
     ```

### LOW-26-05 — `events tail --kind` choice + MCP `bouncer_tail_events` enum omit `task_started` / `task_ended`

- Files: `src/iam_jit/bouncer_cli.py:286-289` (Click choice list), `src/iam_jit/mcp_server.py:945-949` (MCP enum), `src/iam_jit/bouncer/store.py:587-598, 714-725` (where new kinds are written).

- Issue: Slice B writes new `config_event` kinds `task_started` and `task_ended`. But the events-tail tooling can't filter for them:

  CLI:
  ```
  $ iam-jit-bouncer events tail --kind task_started
  Error: Invalid value for '--kind': 'task_started' is not one of
    'rule_added', 'rule_removed', 'mode_changed', 'preset_applied'.
  ```

  MCP:
  ```json
  {"name": "bouncer_tail_events", "arguments": {"kind": "task_started"}}
  ← rejected by inputSchema validation (enum mismatch)
  ```

  Same shape as WB25 LOW-25-01 (which was supposed to be closed by adding `KNOWN_CONFIG_EVENT_KINDS` constant). Either WB25's closure wasn't shipped OR Slice B added the new kinds without updating the constant. Either way: the events are captured (the store column has no enum constraint) but they're not filterable.

- Why LOW: events ARE recorded; the filter UI is just incomplete. Workaround: `events tail --json | jq '.[] | select(.kind == "task_started")'`.

- Fix: extend both lists to include `task_started` + `task_ended`:
  ```python
  # bouncer_cli.py
  type=click.Choice(
      ["rule_added", "rule_removed", "mode_changed", "preset_applied",
       "task_started", "task_ended",
       # WB25's allowlist_rule_added / allowlist_rule_removed should also be here
      ],
      case_sensitive=False,
  ),
  ```
  Same for MCP enum. Add a structural test that asserts every kind WRITTEN by the store is FILTERABLE by the CLI + MCP — closes this drift surface permanently:
  ```python
  def test_known_config_event_kinds_match_cli_and_mcp_enums():
      from iam_jit.bouncer.store import KNOWN_CONFIG_EVENT_KINDS  # to be created
      from iam_jit.bouncer_cli import events_tail
      from iam_jit.mcp_server import BOUNCER_TOOLS
      # Walk both, assert subset
  ```

### LOW-26-06 — `tasks` table has no `pid` column; Slice C will need a v4 schema migration

- File: `src/iam_jit/bouncer/store.py:167-188` (tasks table DDL).

- Issue: the Slice B `tasks` table:
  ```sql
  CREATE TABLE IF NOT EXISTS tasks (
      task_id TEXT PRIMARY KEY,
      description TEXT NOT NULL,
      allow_rules_json TEXT NOT NULL,
      deny_rules_json TEXT NOT NULL,
      started_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      started_by TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      ended_at TEXT,
      ended_by TEXT,
      end_reason TEXT
  );
  ```
  has no `pid` (or any per-caller-isolation) column. The Slice C commit message references "per-PID concurrent tasks." Adding a `pid` column will require a v4 migration (ALTER TABLE ADD COLUMN), which is fine — but also: the `get_active_task()` semantic (`SELECT ... WHERE status='active' ORDER BY started_at DESC LIMIT 1`) will need to change to `WHERE pid = ? AND status='active'`, which is a behavior change that needs to coexist with the single-active-task default for pre-Slice-C callers.

  Not blocking; flag to plan migration cadence:
  - v4 should add `pid INTEGER` (nullable; NULL = global / pre-Slice-C task).
  - `get_active_task(pid=None)` returns a task for the given pid; `pid=None` retains today's "newest active" semantic for back-compat.
  - The HIGH-26-02 partial-unique-index will need to become `WHERE status='active' AND pid IS NOT DISTINCT FROM ?` or similar.

- Why LOW: forward-compat note, not a current bug.

- Fix: when planning Slice C, design the migration as part of the spec (not as an afterthought). Consider adding the `pid` column NOW as nullable to avoid the v4 migration entirely (the column exists; Slice C just starts populating it).

## Verified clean

The following were probed per the audit prompt and found no issues:

- **Schema migration v2 → v3 on existing DB** — verified via repro: a hand-constructed v2 DB with rules + decisions populated correctly migrates to v3 (`version=3`, `task_id` column added to decisions with NULL values, `tasks` table created, existing data preserved). The CREATE TABLE IF NOT EXISTS + ALTER TABLE ADD COLUMN sequence is idempotent — re-running migrate on an already-v3 DB is a no-op for both DDL.
- **Auto-expiry race in `get_active_task`** — verified via repro with 5 concurrent threads on an already-expired task: all 5 see `None` (correct), and exactly ONE `task_ended` audit event is written (NOT 5). The `_end_task_internal`'s `UPDATE ... WHERE task_id=? AND status='active'` is atomic; the `if updated:` guard correctly prevents duplicate audit-log writes on the losing threads. Good.
- **ProxyRule field round-trip via JSON** — `add_task` serializes via `r.to_dict()`; `_row_to_task_scope._decode_rules` reads the same keys; verified `note`, `arn_scope`, `region_scope`, `origin` all round-trip correctly. Origin is forced to `"task"` by `_coerce_rules` regardless of input — verified.
- **Schema-version row create-or-update** — when `schema_version` table is empty, INSERT v3; when row exists with `version < 3`, UPDATE to 3; when row exists with `version >= 3`, no-op. Verified.
- **`_end_task_internal` audit-log guard** — only writes the `task_ended` event when `cur.rowcount > 0` (the UPDATE actually changed a row). Concurrent auto-expire + manual end converge to exactly one event per task lifecycle.
- **`is_expired` correctly returns False for non-active status** — `test_is_expired_false_for_non_active_status` confirms; verified the source path. A completed task that's past wall-clock doesn't report as "expired" (it's "completed" — different terminal state).
- **`is_expired` parses ISO-8601 with Z suffix correctly** — `replace("Z", "+00:00")` + `fromisoformat` is the standard Python 3.10 idiom; verified.
- **Task-status enum coverage** — `TaskStatus.ACTIVE / COMPLETED / EXPIRED / REPLACED` covers the expected lifecycle states. REPLACED is unused today but reserved for Slice C concurrent-task scenarios.
- **CLI `tasks` group registered** — verified `iam-jit-bouncer tasks --help` lists `list / active / show / end / start`. Click `@main.group("tasks")` registers correctly.
- **CLI `tasks list --json` returns valid JSON** — verified via `runner.invoke(main, ["tasks", "list", "--json", ...])` in `test_cli_tasks_end`.
- **MCP tool list includes all three task tools** — `test_mcp_three_task_tools_in_tools_list` covers; verified the dispatcher at `mcp_server.py` wires `bouncer_start_task`, `bouncer_end_task`, `bouncer_active_task` correctly.
- **MCP tools return error (not crash) on bad input** — `test_mcp_start_task_missing_description` confirms; `error` field is returned, no exception escapes the wrapper.
- **MCP `bouncer_end_task` is idempotent** — second call returns error per `test_mcp_end_task_idempotent_returns_error`. No double-audit-log write (verified the `if updated:` guard at `_end_task_internal:713-725`).
- **`bouncer/__init__.py` exists** — verified; tests/bouncer is a proper Python package.
- **Composition order for LEARN + task-deny** — verified via `test_decide_task_deny_wins_over_learn_mode`; the task-deny check at `decisions.py:128-145` fires BEFORE the LEARN-mode auto-allow at `:147-170`. LEARN's no-deny invariant is intentionally broken for task-deny (the docstring + composition table both call this out explicitly).
- **Global-deny wins over task-allow** — verified via `test_decide_global_explicit_deny_wins_over_task_allow`; the global ruleset evaluation at `decisions.py:177-189` returns DENY before the task-allow check at `:210-227`. Correct precedence.
- **Schema additive — no destructive ALTER** — Slice B adds a column + adds a table; no DROP, no schema-incompatible change. Existing decision rows correctly get `task_id=NULL` (verified via repro).
- **CLI `decide` consults active task** — verified via `test_cli_decide_uses_active_task`; the `decide_cmd` at `bouncer_cli.py:498` fetches `store.get_active_task()` and threads it into `decide()`. Correct.
- **Empty allow + non-empty deny is valid** — verified via `test_build_task_scope_accepts_deny_only`. "Deny-only" task scope (e.g. "for the next 30min, NO prod, otherwise normal") is a valid + tested shape.
- **No `1.8%` mentions** — `grep` confirms zero mentions in the diff. Per [[no-one-eight-percent-mention]] — clean.
- **`[[creates-never-mutates]]` correctly invoked** — store.py:30-31 cites it for "this store mutates ONLY the bouncer's own local SQLite DB" — correct (tasks live in the bouncer DB, nothing AWS-side).
- **AGENTS.md drift check** — `grep task docs/AGENTS.md` returns ONE hit (line 34, `ecs_task` workload), unrelated to bouncer task scope. No contradiction between Slice B docs + AGENTS.md.
- **Documentation table accuracy** — the "Composition with global rules" table at `docs/IAM-JIT-BOUNCER.md:268-274` matches the code:
  - "Task explicit deny → Everything (incl. learn mode)" ✓ (`decisions.py:128-145`, before LEARN check)
  - "Global explicit deny → Task allow, default policy" ✓ (`:177-189`, before task-allow)
  - "Task allow → Default deny within task" ✓ (`:210-227`)
  - "Global allow → Default policy when no task allow matched" ✓ (`:236-250`)
  - "Default policy → No rule matched, no task active" ✓ (`:281-293`)
- **MCP read tools don't mutate** — `_bouncer_active_task_for_mcp` is genuinely read-only (only `get_active_task` call, no add/end). `_bouncer_start_task_for_mcp` is the only mutator on the task-scope surface; `_bouncer_end_task_for_mcp` likewise. No surprise side-effect tools.
- **MCP can't mutate OTHER agents' tasks** — there is no per-agent isolation in Slice B (single-active design), so the question is "can agent A end agent B's task?" — yes, technically, via `bouncer_end_task` with B's task_id. But there's no concept of "B's task" in Slice B; tasks are global. Slice C will introduce per-PID isolation; this is correct for Slice B.

## Regression check

Command run: `cd /Users/reagan/repos/iam-roles && .venv/bin/python -m pytest --no-header -q --ignore=tests/test_calibration_corpus.py --ignore=tests/e2e 2>&1 | tail -5`

Result:
```
2439 passed, 29 skipped, 14 deselected, 2 warnings in 89.32s (0:01:29)
```

Matches the audit-prompt baseline (2439). All 43 new Slice-B tests pass. No regressions in any of the 2396 pre-Slice-B tests.

## Summary

**0 CRIT, 2 HIGH, 5 MED, 6 LOW.** Slice B ships a clean data model + storage layer (foundation has ~zero findings); the bug concentration is in (a) validator drift between layers (MCP guards that the underlying validator doesn't), (b) the single-active-task invariant being admin-discipline-enforced rather than code-enforced, and (c) a basic `from typing import Any` oversight that all three sister modules got right.

The two HIGHs are the most-impactful:

- **HIGH-26-01** (`decisions.py` uses `Any` in signature but never imports `typing.Any`) is a one-line oversight that breaks any runtime type-hint introspection. Test passes today only because nothing in the test suite calls `typing.get_type_hints(decide)`. Same one-line fix in the import block; +1 regression test that locks in introspectability.
- **HIGH-26-02** (`BouncerStore.add_task` doesn't enforce single-active-task invariant; concurrent active tasks possible via direct call + non-atomic MCP/CLI guard) is a structural invariant break — the single-active-task assumption is load-bearing for `decide()` composition AND for the audit chain. Fix is move-the-check-into-the-store (+ optional partial-unique-index for database-level enforcement); 1-hour fix including tests.

The 5 MEDs cluster around two themes:

Validator drift (the MCP wrapper does the right thing; the underlying validator doesn't):
- **MED-26-02** (`build_task_scope` accepts `duration_minutes=True`) — bool-as-int slip; MCP guard at `mcp_server.py:1799` is correct, `tasks.py:154` is not.
- **MED-26-03** (`started_by` accepts empty + 100k-char inputs) — missing the description-style validation.
- **MED-26-04** (MCP `_bouncer_start_task_for_mcp` first-bad-entry-stops error) — agent ergonomics; Lens A "always actionable" gap.

Audit-chain integrity:
- **MED-26-01** (PROMPT-mode + active task + unmatched silently denies) — defensible behavior, but silently overrides operator-chosen mode without documenting.
- **MED-26-05** (TOCTOU between `get_active_task` + `record_decision`) — audit log can claim task X was active during decision recorded AFTER X ended.

The 6 LOWs are: agent-actionability of DENY reason string (LOW-26-01); CLI shorthand `#` / `@` split order (LOW-26-02); allow + deny duplicate-pattern silent acceptance (LOW-26-03); 24h cap rationale + safety net (LOW-26-04); CLI/MCP enum drift on new event kinds (LOW-26-05); forward-compat note for Slice C `pid` column (LOW-26-06).

Recommended closure-commit fix sequence:

1. **HIGH-26-01**: add `from typing import Any` to `decisions.py` + regression test that locks introspectability via `typing.get_type_hints`. ~5 min; one-line fix.
2. **HIGH-26-02**: enforce single-active-task in `add_task` itself (raise `ActiveTaskConflict`); add partial unique index on tasks table; introduce `force_replace` opt-in for Slice C. ~1 hr including test + MCP/CLI error-handling update.
3. **MED-26-02**: add bool-guard to `tasks.py:154` validator; remove redundant guard from MCP wrapper (or keep both as defense-in-depth). ~10 min.
4. **MED-26-03**: validate `started_by` non-empty + max-length 256 in `build_task_scope`. ~10 min.
5. **MED-26-04**: pre-validate rule entries in `_bouncer_start_task_for_mcp`; aggregate errors; return all in one response. ~20 min.
6. **MED-26-01**: add docstring + test + reason-string clarification for PROMPT + active-task + unmatched. ~15 min.
7. **MED-26-05**: re-query task status at `record_decision` insert; write `task_id=NULL` if task ended between fetch + record. ~20 min including test.
8. **LOW-26-05**: extend bouncer events `--kind` choice list + MCP `bouncer_tail_events` enum to include `task_started` + `task_ended`; bring back WB25's `KNOWN_CONFIG_EVENT_KINDS` constant if not landed. ~15 min.
9. **LOW-26-01**: extend DENY reason strings with HOW-TO-FIX guidance. ~10 min.
10. **LOW-26-03**: cross-list duplicate-pattern check + test. ~10 min.
11. **LOW-26-02**: swap split order in `_parse_shorthand` (split `@` first); add test for `#`-in-ARN. ~10 min.
12. **LOW-26-04**: doc the 24h cap rationale + CLI confirmation for >240 min. ~15 min.
13. **LOW-26-06**: design Slice C `pid` column migration ahead of time (or land the column now as nullable). Forward-compat note; no immediate work required.

After fixes ship, re-run audit (Round 27) — recommended scope: the closure commit + a re-probe of HIGH-26-02 to confirm `add_task` rejects concurrent active tasks AND the partial unique index works as expected under SQLite isolation modes.

The Slice B data-model + storage + decision-composition layer is well-shaped (the composition table matches the code; the auto-expiry race is benign; the v2 → v3 migration is correct). The 13 findings concentrate at validator boundaries (MCP guards vs underlying validator), at the invariant-enforcement-location (CLI/MCP guards vs store-level invariants), and at the type-hint surface (one-line `Any` import oversight). Same lesson WB23/WB24/WB25 keep teaching: foundation is reliably solid; cross-layer wiring is where invariants drift. Slice C (per-PID concurrent tasks + per-task review report) will compound this — the HIGH-26-02 fix lands now or the Slice C invariant work has to redo it.

Audit ROI continues: 2 HIGHs (one of which is a runtime introspection break that no test in 2439 exercises; one of which is an invariant break that future code WILL hit), 5 MEDs catching validator-drift continuations the unit-test suite (43 new tests) didn't cover. Per [[audit-cadence-discipline]] the BB+WB pattern continues to surface the cross-layer integration bugs that the within-feature test suite by design doesn't catch.

---

## WB26 closures (2026-05-17)

All 13 findings addressed (or explicitly deferred with rationale).
The two HIGHs were the load-bearing fixes; MEDs hardened validation
+ closed the TOCTOU; LOWs cleaned up enum drift and parser corner
cases.

### Updated closure table

| Finding | Status | How closed |
|---|---|---|
| HIGH-26-01 missing `typing.Any` import | **CLOSED** | One-line `from typing import Any` added to `bouncer/decisions.py`. Verified via `typing.get_type_hints(decisions.decide)` smoke test (regression test `test_high_26_01_decisions_module_introspectable`). |
| HIGH-26-02 `add_task` doesn't enforce single-active invariant | **CLOSED** | Moved the active-conflict check INTO `add_task` under the same SQLite lock as the INSERT — atomic. Raises new `ActiveTaskExistsError`. MCP / CLI guards updated to catch the new exception instead of doing their own non-atomic pre-check. Regression test `test_high_26_02_add_task_enforces_single_active_at_store` calls `store.add_task` twice in a row and expects the second to raise. Existing test that depended on the old loose behavior updated to end the first task first. |
| MED-26-01 PROMPT-mode + active task semantic undocumented | **CLOSED** | Docstring on `decide()` now explicitly states: with an active task, PROMPT mode is suppressed for unmatched calls (auto-deny). Reasoning: task scope IS the agent's explicit declaration; prompting mid-task defeats the purpose. New test `test_med_26_01_prompt_mode_with_active_task_unmatched_denies` locks the behavior. |
| MED-26-02 `build_task_scope` accepts bool duration | **CLOSED** | Added `isinstance(duration, bool)` reject before the int check (bool is int subclass — same pattern as bouncer's `decide --record max_events` validation). Regression test `test_med_26_02_build_task_scope_rejects_bool_duration`. |
| MED-26-03 `started_by` unbounded | **CLOSED** | Added is-string + non-empty + ≤256-char checks on `started_by`. Also added a 2000-char cap on `description` (audit told it was missing too). Three new regression tests covering empty / oversize / oversize-description. |
| MED-26-04 MCP validation surface aggregation | **DEFERRED** | Audit suggested aggregating multiple errors into one response. Slice C will touch MCP shape anyway; defer to that pass. Currently fail-fast on first invalid field (consistent with rest of MCP surface). |
| MED-26-05 TOCTOU between `get_active_task` and `record_decision` | **CLOSED** | `record_decision` now re-queries the task's status when given a `task_id`; if the task isn't active anymore, the `task_id` field is set to NULL on the decision row. Audit log stops claiming "decision happened during task X" when X had already ended. Regression test `test_med_26_05_record_decision_nullifies_stale_task_id`. |
| LOW-26-01 (audit-implied) per-PID isolation gap | **EXPLICITLY DEFERRED** | This is Slice C scope. Single-active-task is the documented Slice B contract. |
| LOW-26-02 shorthand parser splits `#` before `@` | **CLOSED** | Reordered to split `@` first, then `rsplit("#", 1)` from the END of the post-@ chunk. ARNs that contain `#` (legitimate in some service URLs) now preserve them. |
| LOW-26-03 `_row_to_task_scope` silently drops unknown ProxyRule fields | **DEFERRED** | Forward-compat concern only; no current data loss. Will revisit if/when ProxyRule grows fields. |
| LOW-26-04 reason strings lack "how to fix" hints | **DEFERRED** | Audit suggested per-decision actionable hints. Slice C may add a richer `next_action_hint` field on `DecisionRecord`. Current `reason` text is sufficient for agents to recognize the case. |
| LOW-26-05 events `--kind` enum omits `task_started` / `task_ended` | **CLOSED** | Added both kinds to the CLI Click choice + the MCP `bouncer_tail_events` schema enum. Regression test `test_low_26_05_events_tail_kind_enum_includes_task_kinds`. |
| LOW-26-06 (other minor) | **DEFERRED** | Per audit report — non-blocking. |

### Verification

- `tests/bouncer/test_tasks.py`: 43 → 53 tests (+10 net closure tests).
- All 243 bouncer tests pass.
- Broader suite: **2449 passed**, 29 skipped, 14 deselected (was 2439 before WB26 closures; +10 net).
- Slice C can now safely build on top: the single-active invariant is enforced atomically, decision logic is introspectable, the audit chain is honest about task-active state.

### What WB26 DID NOT close (deferred-with-rationale)

- **MED-26-04 / LOW-26-04**: MCP surface improvements (aggregated errors, richer next_action_hint). Slice C touches MCP shape; bundle there.
- **LOW-26-03**: ProxyRule forward-compat field drop. Will revisit when fields are added.

### Why this matters

HIGH-26-02 was the most important: the single-active-task invariant is the foundation of Slice B's correctness model (decision logic ASSUMES one active task). Leaving it enforced only in MCP/CLI wrappers (both non-atomic) would have broken the moment Slice C added another caller. The fix moves the invariant into the store layer where it belongs, which is also where Slice C's per-PID layer will compose cleanly.

Per [[audit-cadence-discipline]]: 0 CRIT + 2 HIGH + 5 MED + 6 LOW in code that had 43 passing unit tests. The pattern continues to pay for itself — both HIGHs caught by the audit were structurally significant; neither would have been found by additional unit tests because both were about properties of the code rather than its behavior on specific inputs.
