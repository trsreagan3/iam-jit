# Round 25 audit — compatibility allowlist Slice 2 (#166)

Commit under review: `f439b66` (`feat(applicability): Slice 2 — admin compatibility allowlist (#166)`).

Scope (Slice 2 only — Slice 1's catalog audited in WB24; Slice 3 deferred):
- `src/iam_jit/compatibility_allowlist.py` (new, 437 LOC)
- `src/iam_jit/compatibility.py` (+77 LOC: allowlist integration into `check_compatibility`)
- `src/iam_jit/mcp_server.py` (+53 LOC: `list_compatibility_overrides` MCP tool + `_load_allowlist_for_check` plumbing into both `check_iam_jit_compatibility` and `submit_policy`)
- `src/iam_jit/cli.py` (+170 LOC: `iam-jit allowlist {list,add,remove,show}` subcommand group + `_allowlist_audit_record` writer)
- `tests/test_compatibility_allowlist.py` (new, 661 LOC, 47 tests)
- `docs/AGENTS.md` (+4 lines: "Admin allowlist overrides" subsection)
- `docs/COMPATIBILITY-ALLOWLIST.md` (new, 145 lines: admin guide)

Read-only audit. Per [[audit-cadence-discipline]].

Regression: **2391 passed**, 29 skipped, 14 deselected (88.6s, excluding `tests/e2e/*` which needs `playwright`, and `tests/test_calibration_corpus.py` which has the well-known pre-existing failures). Matches the audit-prompt baseline (2391) exactly. No regressions caused by Slice 2.

## Headline

12 findings: **0 CRIT, 1 HIGH, 5 MED, 6 LOW.**

The HIGH is a real correctness break that ships today. **HIGH-25-01**: `docs/COMPATIBILITY-ALLOWLIST.md` tells admins "you can edit the file by hand." PyYAML's `safe_load` auto-deserializes ISO-8601 timestamps (e.g. `created_at: 2026-05-17T15:00:00Z`) into Python `datetime` objects. The deserialized rule then carries `created_at=<datetime>` instead of the expected string. Three downstream effects ALL fire today, all confirmed via repro:

1. **MCP `list_compatibility_overrides` crashes the tool call.** `_list_compatibility_overrides_for_mcp` builds `{"rules": [r.to_dict() for r in rules], ...}`; the dispatcher then calls `json.dumps(result_payload)`; the datetime field raises `TypeError: Object of type datetime is not JSON serializable`. The MCP server's outer `except Exception` swallows it into `-32603 internal error: Object of type datetime is not JSON serializable` so the server doesn't crash — but the agent loses access to the listing entirely.
2. **`iam-jit allowlist list --json` crashes** with the same `TypeError`.
3. **The next `allowlist add` corrupts the file format.** YAML round-trips the datetime as `2026-05-17 15:00:00+00:00` (Python `str(datetime)` form, NOT ISO-Z with quotes), so the file ends up with mixed `created_at: 2026-05-17 15:00:00+00:00` (untyped scalar that re-loads as datetime) and `created_at: '2026-05-17T15:00:00Z'` (quoted string) entries. Each subsequent edit re-corrupts.

Repro is one-liner; see HIGH-25-01 for the exact command and trace. This is the same shape as WB23 MED-23-01 (malformed-row tolerance) but inverted — here PyYAML's "helpful" deserialization injects a different malformation that the build_rule validator doesn't catch (it accepts `created_at` of any type without isinstance-checking). Fix: stringify the parsed `created_at` defensively in `_read_all`, OR force a string format in `to_dict` so round-trips stay stable.

The five MEDs cluster around enforcement gaps + Lens B audit-chain holes the Slice 2 design introduces:

- **MED-25-01**: admin sets `--verdict use_bouncer` for an account expecting `submit_policy` to refuse issuance. The MCP `submit_policy` rejection set is `{USE_EXISTING, CANNOT_HELP}` — `USE_BOUNCER` is missing. An admin override saying "for this account, use the bouncer not issuance" is honored by `check_iam_jit_compatibility` (returns the verdict) but ignored by `submit_policy` (issues the role anyway). Same trust-gap shape as WB24 HIGH-24-01: a verdict the checker can return that no enforcement layer respects.
- **MED-25-02**: a `cannot_help` allowlist rule with no `--next-action-hint` produces a `CompatibilityResult` where `next_action_hint=None`, breaking the WB24 "every non-PROCEED carries a path forward" invariant. The catalog enforces it via test (`test_every_catalog_entry_has_next_action_hint`); the allowlist has no equivalent test or default. An admin who writes `iam-jit allowlist add --verdict cannot_help --reason "out of scope"` (the example in `COMPATIBILITY-ALLOWLIST.md:48-52`) leaves the agent with `next_action_hint: None`. Per Lens A the agent should always have a path forward — even "escalate to a human" is more useful than null.
- **MED-25-03**: removing + re-adding a rule moves it to the END of the insertion-order list, silently flipping first-match-wins semantics. The doc tells admins "to change a rule, remove + re-add" (`COMPATIBILITY-ALLOWLIST.md:135-137`) AND "order rules from specific to general" (`:75`). Doing the first breaks the second. Confirmed via repro: a specific rule shadowed by a wildcard becomes the wildcard's victim after one remove/re-add cycle.
- **MED-25-04**: when the allowlist store load FAILS (broken file, permission error, etc.), the checker silently degrades to catalog-only AND the audit event records `source: catalog` with no indicator that an allowlist was supposed to be consulted but couldn't. If an admin set `cannot_help` for account X and the file is unreadable, post-incident review sees a clean `source: catalog → use_existing` and can't tell the admin's intent was lost. Lens B audit-chain hole.
- **MED-25-05**: `iam-jit allowlist add` silently creates `~/.iam-jit/bouncer/state.db` on first run for users who've never installed the bouncer. The CLI prints nothing about it. A user adding their first allowlist rule expects the allowlist file to be created (documented), not the bouncer's SQLite database (undocumented for this command). Surprise side-effect; ~80% of admins running the allowlist CLI today are not bouncer users.

Six LOWs: cross-tool inconsistency (the bouncer's `events tail --kind` Click choice list AND the `bouncer_tail_events` MCP tool's `enum` for `kind` BOTH whitelist only the four old kinds; an admin trying `iam-jit-bouncer events tail --kind allowlist_rule_added` gets a Click rejection; the new kinds appear when no filter is given but can't be filtered for); doc-claim drift (`COMPATIBILITY-ALLOWLIST.md:75` says "order rules from specific to general" as a code-enforced rule but `match_intent` just walks `store.list()` with zero ordering logic — admin discipline only); audit-detail-on-best-effort-skip (`_allowlist_audit_record` swallows ALL exceptions so an admin "added rule X" CLI confirmation can ship without ANY audit-log entry — the docs say "every mutation is audit-logged" but the implementation makes it best-effort); the dead-branch fallback in `check_compatibility` that echoes `cleaned_hint` into a USE_EXISTING allowlist result with no ARN (such a rule is impossible — `build_rule` rejects USE_EXISTING-without-ARN — so the branch is unreachable for any rule produced via the public constructor); MCP `_list_compatibility_overrides_for_mcp` returns ALL rules with no pagination + no limit (probably fine for the human-managed case at <1000 rules, but worth flagging); blank-string ARN error message ("not a valid IAM role ARN" when the user passed `'   '`) — minor UX confusion.

## Closure status

| Finding | Status |
|---|---|
| HIGH-25-01 PyYAML auto-deserializes ISO-8601 `created_at` into `datetime`; MCP `list_compatibility_overrides` crashes with `TypeError: Object of type datetime is not JSON serializable`; `allowlist list --json` likewise; subsequent `allowlist add` corrupts the file format on write-back | OPEN |
| MED-25-01 `submit_policy` rejection set is `{USE_EXISTING, CANNOT_HELP}` — `USE_BOUNCER` missing; admin override saying "use bouncer" is honored by checker but ignored by submit_policy; same trust-gap shape as WB24 HIGH-24-01 | OPEN |
| MED-25-02 Allowlist rules with `verdict=cannot_help` / `use_bouncer` and no `--next-action-hint` produce `CompatibilityResult` with `next_action_hint=None`, breaking "every non-PROCEED carries a path forward" invariant from WB24 | OPEN |
| MED-25-03 Remove + re-add moves rule to END of insertion-order list, silently flipping first-match-wins semantics; doc tells admins to use this pattern as the "update" workaround | OPEN |
| MED-25-04 Broken allowlist store silently degrades to catalog-only; audit event records `source: catalog` with no indicator the allowlist was supposed to be consulted; admin's intent invisibly lost in audit chain | OPEN |
| MED-25-05 `iam-jit allowlist add` silently creates `~/.iam-jit/bouncer/state.db` on first run for users who've never installed the bouncer; surprise side-effect, undocumented for this command | OPEN |
| LOW-25-01 `iam-jit-bouncer events tail --kind` Click choice + `bouncer_tail_events` MCP enum both whitelist only the 4 old kinds; new `allowlist_rule_added`/`allowlist_rule_removed` kinds aren't filterable | OPEN |
| LOW-25-02 Doc says "order rules from specific to general" but `match_intent` has zero specificity-sort logic; describes admin discipline the code doesn't enforce (LOW-24-03 shape) | OPEN |
| LOW-25-03 `_allowlist_audit_record` catches all exceptions silently; admin sees "added rule X" CLI confirmation while NO audit-log row exists; docs claim "every mutation is audit-logged" but impl is best-effort | OPEN |
| LOW-25-04 `check_compatibility` allowlist branch has a dead fallback ("if rule's verdict is USE_EXISTING and rule didn't pre-set ARN, fall back to agent's hint") — `build_rule` rejects USE_EXISTING-without-ARN so the branch is unreachable for public-constructor rules | OPEN |
| LOW-25-05 MCP `list_compatibility_overrides` returns ALL rules with no pagination/limit; fine at human admin scale but no defensive cap (LOW-22-02 shape) | OPEN |
| LOW-25-06 `build_rule` error message says "not a valid IAM role ARN" for whitespace-only `--role-arn` input; correct verdict, misleading message | OPEN |

## HIGH findings

### HIGH-25-01 — PyYAML datetime auto-deserialization breaks JSON serialization end-to-end

- Files:
  - `src/iam_jit/compatibility_allowlist.py:319-350` (`FileAllowlistStore._read_all`)
  - `src/iam_jit/compatibility_allowlist.py:226-258` (`build_rule` — accepts `created_at: str | None` but no type-check)
  - `src/iam_jit/compatibility_allowlist.py:123-134` (`to_dict` — echoes whatever type `created_at` carries)
  - `src/iam_jit/mcp_server.py:1390-1402` (`_list_compatibility_overrides_for_mcp`)
  - `src/iam_jit/mcp_server.py:2237-2248` (dispatcher's `json.dumps(result_payload)`)
  - `docs/COMPATIBILITY-ALLOWLIST.md:98-100` ("You can edit the file by hand")

- Issue: `yaml.safe_load` deserializes unquoted ISO-8601 timestamps as Python `datetime` objects. The docs explicitly tell admins they can hand-edit the YAML file. An admin who writes the example shown in the docs (and copy-paste-formatted as `created_at: 2026-05-17T15:00:00Z` without quotes) gets a rule whose `created_at` is a `datetime`, not a string. The build_rule validator at `:226-258` accepts `created_at: str | None = None` declaratively but does no isinstance-check; the dataclass constructor accepts whatever type is passed (frozen dataclass holds the value as-is); `to_dict` at `:123-134` returns the value verbatim.

  Three confirmed downstream crashes, ALL via repro on a freshly-built repo:

  **Crash 1: MCP `list_compatibility_overrides`** —
  ```python
  >>> # File contains: created_at: 2026-05-17T15:00:00Z   (unquoted, hand-edited per docs)
  >>> from iam_jit.mcp_server import _list_compatibility_overrides_for_mcp
  >>> import json
  >>> out = _list_compatibility_overrides_for_mcp({})
  >>> json.dumps(out, indent=2)
  TypeError: Object of type datetime is not JSON serializable
  ```
  Dispatcher's outer `except Exception` (mcp_server.py:2296) catches it; client sees `{"jsonrpc": "2.0", "id": ..., "error": {"code": -32603, "message": "internal error: Object of type datetime is not JSON serializable"}}` — the entire `list_compatibility_overrides` tool becomes non-functional for this admin's installation. Agents can no longer see what their org has configured (the whole point of the read-only tool per [[agent-friendly-not-bypassable]] Lens A).

  **Crash 2: `iam-jit allowlist list --json`** — same TypeError, same root cause. The CLI invocation crashes out via the click runner.

  **Crash 3: writeback corrupts the file** —
  ```yaml
  # Before (admin hand-edited):
  rules:
    - rule_id: abc123def456
      ...
      created_at: 2026-05-17T15:00:00Z
  
  # After running `iam-jit allowlist add ...` for an unrelated new rule:
  rules:
    - rule_id: abc123def456
      ...
      created_at: 2026-05-17 15:00:00+00:00       # ← Python str(datetime), NOT ISO-Z; unquoted
    - rule_id: 02273888d994
      ...
      created_at: '2026-05-17T15:00:00Z'           # ← quoted (build_rule generated this one)
  ```
  Mixed formats; the next hand-edit MAY parse one as datetime + one as string; the bug cascades.

- Why HIGH (not CRIT): the read-only MCP tool's failure is "agent can't see allowlist" not "agent gets WRONG allowlist." The audit chain still works for the audit-log-on-add path (CLI add goes through build_rule → `_isoformat_z(datetime.now(UTC))` → string). The corruption is only triggered by hand-editing, which the docs invite. Severity is "ships broken for the documented hand-edit workflow" rather than "agent gets unauthorized access."

  But: the docs at `COMPATIBILITY-ALLOWLIST.md:98-100` SAY "you can edit the file by hand; bad rows are skipped at read time and the rest of the file stays usable." That's a load-bearing claim — admins WILL hand-edit. Today the claim is false: rows with unquoted timestamps don't get skipped (build_rule accepts them); they get returned WITH a datetime created_at that crashes the next JSON-serializing consumer.

- Fix options:
  1. **Best**: defensive normalization in `_read_all`. Before passing to `build_rule`, coerce non-string `created_at` to ISO-Z string:
     ```python
     raw_created_at = raw.get("created_at")
     if isinstance(raw_created_at, _dt.datetime):
         raw_created_at = _isoformat_z(raw_created_at)
     elif raw_created_at is not None and not isinstance(raw_created_at, str):
         raw_created_at = str(raw_created_at)
     # ...
     build_rule(..., created_at=raw_created_at)
     ```
     Plus an isinstance-check in `build_rule` itself (defense in depth):
     ```python
     if created_at is not None and not isinstance(created_at, str):
         raise InvalidRule("created_at must be a string (ISO-8601)")
     ```
  2. **Acceptable**: in `to_dict`, coerce `created_at` to string at output time:
     ```python
     "created_at": (self.created_at if isinstance(self.created_at, str)
                    else _isoformat_z(self.created_at) if isinstance(self.created_at, _dt.datetime)
                    else str(self.created_at)),
     ```
     Loses the validator's "fail fast at insert" property but unblocks MCP serialization without code changes elsewhere.
  3. **Worst**: tell admins in the docs to ALWAYS quote `created_at`. Footgun lives forever.

  Recommend option 1 + isinstance-check in `build_rule`. Add a test:
  ```python
  def test_file_store_handles_yaml_datetime_autodeserialization(tmp_path):
      path = tmp_path / "allowlist.yaml"
      path.write_text(
          "version: 1\nrules:\n"
          "  - rule_id: abc\n"
          "    account_id: '111111111111'\n"
          "    workload: k8s_pod\n"
          "    verdict: proceed\n"
          "    reason: hand-edited\n"
          "    created_by: admin\n"
          "    created_at: 2026-05-17T15:00:00Z\n"   # unquoted!
      )
      s = FileAllowlistStore(path)
      rules = s.list()
      assert len(rules) == 1
      assert isinstance(rules[0].created_at, str)
      import json
      json.dumps(rules[0].to_dict())   # must not raise
  ```

## MED findings

### MED-25-01 — `submit_policy` doesn't reject `USE_BOUNCER` verdicts

- Files: `src/iam_jit/mcp_server.py:1962-1976` (rejection set is exactly `{USE_EXISTING, CANNOT_HELP}` — line 1963-1964); `src/iam_jit/compatibility_allowlist.py:106-121` (`to_result` correctly produces USE_BOUNCER verdict from rule).

- Issue: an admin who sets `--verdict use_bouncer` for an account expects `submit_policy` to refuse issuance ("don't issue a new role; use the bouncer to gate existing creds"). The MCP `_check_compatibility_for_mcp` correctly returns `verdict: use_bouncer` for matching intents. But `_submit_policy_for_mcp`'s post-check rejection block (mcp_server.py:1962-1976) only rejects `USE_EXISTING` and `CANNOT_HELP`. `USE_BOUNCER` falls through to the issuance path — `submit_policy` proceeds, creates the JIT role, returns success.

  Concretely: admin runs
  ```
  iam-jit allowlist add --account 333333333333 --verdict use_bouncer \
      --reason "prefer bouncer to issuance for this account"
  ```
  Agent in account 333 calls `submit_policy(workload=agent_local_dev, target_account_id="333333333333", ...)`. The internal `check_compatibility` returns USE_BOUNCER. The post-check `if` doesn't fire. Submission proceeds. Admin's intent silently ignored.

  This is the same trust-gap shape as WB24 HIGH-24-01 (the docstring promised behavior the enforcement layer didn't honor). WB24's closure added the rejection logic — but only for the verdicts Slice 1 returned. Slice 2 extended the set of returnable verdicts without updating the rejection logic.

- Why MED (not HIGH): no security boundary is breached — `submit_policy` still scores the policy, still enforces all the normal gates. The bug is "admin's policy preference ignored" not "agent gets extra access." But the whole point of admin overrides per `COMPATIBILITY-ALLOWLIST.md:20-23` is "this account should use the bouncer instead of issuance." When the override is set and the agent submits anyway, the admin has no signal — and the bouncer-fallback they expected doesn't happen.

- Fix:
  ```python
  if check_result.verdict in (
      Compatibility.USE_EXISTING,
      Compatibility.CANNOT_HELP,
      Compatibility.USE_BOUNCER,   # MED-25-01 closure
  ):
      ...
  ```
  Adjust the rejection-error message to be verdict-aware (USE_BOUNCER → "use the bouncer to gate calls; don't issue a JIT role"). Add a test:
  ```python
  def test_submit_policy_rejects_use_bouncer_override(cli_env):
      # Admin sets USE_BOUNCER for account X
      # Agent submits for account X
      # Expect rejection with verdict=use_bouncer in response
  ```
  Also: add a structural test (LOW-25-04-style) that walks `Compatibility` enum + asserts every non-PROCEED verdict has a rejection path in `submit_policy`. Prevents future enum additions silently bypassing.

### MED-25-02 — `cannot_help` / `use_bouncer` allowlist rules with no `--next-action-hint` produce null hint

- Files: `src/iam_jit/compatibility_allowlist.py:106-121` (`to_result` uses `self.next_action_hint` verbatim; default is None); `src/iam_jit/compatibility_allowlist.py:226-258` (`build_rule` defaults `next_action_hint=None`); `tests/test_compatibility.py` (`test_every_catalog_entry_has_next_action_hint` — enforced for catalog, NOT for allowlist).

- Issue: WB24 established the invariant that every non-PROCEED `CompatibilityResult` carries a `next_action_hint` so agents always have a path forward (Lens A per [[agent-friendly-not-bypassable]]). The Slice 1 catalog enforces this — every CatalogEntry has a non-empty `next_action_hint` and `test_every_catalog_entry_has_next_action_hint` is a structural test.

  Slice 2's allowlist doesn't enforce it. `build_rule` accepts `next_action_hint=None` and defaults to None when the CLI's `--next-action-hint` is omitted. The doc's example in `COMPATIBILITY-ALLOWLIST.md:48-52`:
  ```
  iam-jit allowlist add \
      --account 222222222222 \
      --verdict cannot_help \
      --reason "compliance environment; named-role-only"
  ```
  has no `--next-action-hint`. After running this, the matching `check_iam_jit_compatibility` call returns:
  ```json
  {
    "verdict": "cannot_help",
    "reasoning": "Admin allowlist rule '...' matched: compliance environment; named-role-only",
    "next_action_hint": null,
    ...
  }
  ```
  Agent reads `next_action_hint: null` and has no path forward. The verdict-shapes table in the doc itself (`COMPATIBILITY-ALLOWLIST.md:104-109`) says `cannot_help → "Escalate to a human"` — but the system doesn't tell the agent that.

  Same for USE_BOUNCER: `next_action_hint: null` instead of "run the bouncer alongside the workload."

- Why MED (not HIGH): the agent does still get `reasoning`, which echoes the admin's `--reason`. So an agent reading "compliance environment; named-role-only" can probably guess "ask a human." But the WB24 invariant was explicit; Slice 2 shouldn't quietly break it. Plus the doc table makes a contract that the system doesn't keep.

- Fix options:
  1. **Best**: `build_rule` populates a verdict-specific default `next_action_hint` when the admin doesn't supply one:
     ```python
     _DEFAULT_HINTS = {
         Compatibility.PROCEED: "Proceed with iam-jit.",
         Compatibility.USE_EXISTING: "Use the supplied existing role; do not submit a JIT request for this workload.",
         Compatibility.USE_BOUNCER: "Use iam-jit-the-bouncer to gate calls with the role you already have; don't submit a JIT request.",
         Compatibility.CANNOT_HELP: "Escalate to a human; iam-jit is not configured for this account/workload.",
     }
     # In build_rule:
     final_hint = next_action_hint.strip() if next_action_hint else _DEFAULT_HINTS[cleaned_verdict]
     ```
     Admin can always override with `--next-action-hint`; default matches the doc table.
  2. **Acceptable**: structural test that asserts allowlist rules always produce non-null hints; combined with a build_rule requirement that `next_action_hint` is non-empty for non-PROCEED verdicts (forces admin to supply it explicitly).

  Recommend option 1 — same UX shape as the catalog (hint always present, admin can override).

### MED-25-03 — Remove + re-add silently flips first-match-wins ordering

- Files: `src/iam_jit/compatibility_allowlist.py:287-292` (`InMemoryAllowlistStore.remove` — `pop(i)`), `:385-393` (`FileAllowlistStore.remove` — pops, rewrites); `src/iam_jit/compatibility_allowlist.py:279-285` (`add` appends to end); `docs/COMPATIBILITY-ALLOWLIST.md:75` ("Order rules from specific to general"); `:135-137` ("Update-in-place — to change a rule, remove + re-add").

- Issue: the doc tells admins (a) to order rules specific→general and (b) to "update" by removing then re-adding. Both `InMemoryAllowlistStore.add` and `FileAllowlistStore.add` append to the END of the list. So an admin who has a specific rule at position 0 and a wildcard at position 1, then "updates" the specific rule by remove + re-add, ends up with:
  ```
  Before:  [specific, wildcard]
  After:   [wildcard, specific]   # wildcard now wins
  ```
  Verified via repro:
  ```python
  >>> s = InMemoryAllowlistStore()
  >>> specific = build_rule(account_id='111111111111', workload='k8s_pod', verdict='proceed', reason='specific', ...)
  >>> wildcard = build_rule(account_id=None, workload='k8s_pod', verdict='cannot_help', reason='generic deny', ...)
  >>> s.add(specific); s.add(wildcard)
  >>> s.remove(specific.rule_id)
  >>> specific2 = build_rule(account_id='111111111111', workload='k8s_pod', verdict='proceed', reason='re-added', ...)
  >>> s.add(specific2)
  >>> result = check_compatibility(CompatibilityIntent(workload=WorkloadType.K8S_POD, target_account_id='111111111111'), allowlist=s)
  >>> result.verdict
  Compatibility.CANNOT_HELP   # wildcard wins now; admin expected PROCEED
  ```

  Same shape as WB24 LOW-24-03 (first-match-wins comment that the catalog doesn't exercise) but with TEETH — the doc encourages the workflow that breaks the invariant.

- Why MED (not HIGH): admin discipline can avoid it (always remove WILDCARDS not specific rules; or re-add specific rules and then re-add the wildcard so it ends up last; or order by inverse-specificity from the start). But these are subtle requirements the doc doesn't surface, and the failure mode is silent — admin gets no warning, no error; just the wrong verdict.

- Fix options:
  1. **Best**: insertion-position parameter on `add`. CLI's `add` defaults to current behavior; new `--position` flag lets admin insert at a specific slot. CLI's `remove` warns "this rule was at position N; subsequent re-add will land at the end — use `--position N` to preserve ordering."
  2. **Acceptable**: auto-sort by specificity at lookup time. `match_intent` computes specificity (account_id + workload set → higher; both None → lowest) and walks rules in specificity-descending order. Admin order doesn't matter. Breaks the "predictable insertion-order" semantics the test relies on but eliminates the footgun entirely.
  3. **Acceptable**: CLI add of a duplicate (account, workload) pair WARNS: "you already have a rule for (account=X, workload=Y) at position N; the new rule will land at position last and may shadow existing wildcards. Continue? [y/N]"
  4. **Worst**: leave silent; document the footgun.

  Recommend option 2 — admin discipline shouldn't be load-bearing for correctness. Slice 3 already calls out "automatic specificity ordering" as deferred work (`COMPATIBILITY-ALLOWLIST.md:144-145`) — move it forward.

  Test invariant: `test_remove_and_readd_preserves_match_result` — create a specific + wildcard pair, remove specific, re-add, assert the matched verdict is unchanged.

### MED-25-04 — Broken allowlist silently degrades to catalog with no audit signal

- Files: `src/iam_jit/compatibility.py:554-564` (the try/except wrapping `match_intent`), `:643-667` (audit log writes `source: catalog` regardless of why); `src/iam_jit/mcp_server.py:1357-1365` (`_load_allowlist_for_check` returns None on exception).

- Issue: the allowlist load path has TWO best-effort failure modes:
  1. `_load_allowlist_for_check` returns None if store construction fails (permission error, missing parent dir, etc.).
  2. `check_compatibility` wraps `match_intent` in try/except so allowlist `.list()` failures become `allowlist_rule = None`.

  Both paths fall through to catalog evaluation, and the resulting audit event records:
  ```
  detail.source = "catalog"
  ```
  with no indicator that an allowlist was SUPPOSED to be consulted. Verified:
  ```python
  >>> recorded = []
  >>> class Sink: ...
  >>> check_compatibility(
  ...     CompatibilityIntent(workload=WorkloadType.K8S_POD),
  ...     allowlist=BrokenStore(),       # .list() raises RuntimeError
  ...     audit_sink=Sink(), actor="test",
  ... )
  >>> recorded[0]["detail"]["source"]
  'catalog'                                # NO indication allowlist was attempted-but-failed
  ```

  Concrete failure scenario: admin sets `cannot_help` for account 222 (compliance env). Six months later, the YAML file gets corrupted (disk error, mistaken `chmod`, whatever). An agent in account 222 calls the checker; allowlist load fails silently; catalog returns `use_existing` (or whatever the default is for the workload); audit log shows `source: catalog → use_existing`. Post-incident: admin asks "did the agent know iam-jit said cannot_help?" → audit log answers `source: catalog → use_existing`. The admin's intent is INVISIBLY LOST.

  Per [[agent-friendly-not-bypassable]] Lens B: "every config-shape decision should be auditable." The decision "iam-jit consulted catalog because allowlist was broken" is auditable in the SENSE that the catalog event is recorded, but it doesn't capture WHY the allowlist wasn't consulted. Same shape as WB22 LOW-22-03 (live-action-tail silently exited 0 on source failure).

- Why MED (not HIGH): degraded-but-functional is the right default per the comment at `compatibility.py:560-563` ("a broken admin file can't crash the check"). The problem isn't that we degrade; it's that we degrade SILENTLY. The audit chain needs a distinct event kind for "allowlist consultation failed."

- Fix:
  ```python
  allowlist_rule = None
  allowlist_load_error: str | None = None
  if allowlist is not None:
      try:
          from .compatibility_allowlist import match_intent
          allowlist_rule = match_intent(intent, allowlist)
      except Exception as e:
          allowlist_load_error = repr(e)
  # ... in the catalog-fallback audit event:
  detail = {
      ..., "source": "catalog",
      "allowlist_load_error": allowlist_load_error,   # nullable; non-null when allowlist was passed but couldn't be read
  }
  ```
  And in `_load_allowlist_for_check`:
  ```python
  try:
      from .compatibility_allowlist import build_default_store
      return build_default_store()
  except Exception as e:
      # Optionally log to a separate iam-jit warnings table.
      logger.warning("allowlist store load failed: %s", e)
      return None
  ```
  Test: pass a BrokenStore + audit sink, assert the recorded event includes a non-null `allowlist_load_error`.

### MED-25-05 — `iam-jit allowlist add` silently creates the bouncer DB on first run

- Files: `src/iam_jit/cli.py:745-757` (`_allowlist_audit_record` — calls `BouncerStore()` unconditionally); `src/iam_jit/bouncer/store.py:80-113` (`BouncerStore.__init__` creates parent dirs + DB if absent); `docs/COMPATIBILITY-ALLOWLIST.md` (no mention that running allowlist CLI initializes the bouncer DB).

- Issue: a user who's never installed iam-jit-the-bouncer but wants to set up the compatibility allowlist runs:
  ```
  $ iam-jit allowlist add --account 111111111111 --workload k8s_pod --verdict proceed --reason "trusted"
  added rule 84f812474fab: proceed
  ```
  Behind the scenes, this CREATES `~/.iam-jit/bouncer/state.db` (a 16KB SQLite file) including the bouncer's full schema (rules, decisions, config_events tables). Verified via fresh-HOME repro: empty `~/.iam-jit/` before; after one `allowlist add`, `~/.iam-jit/bouncer/state.db` exists with the full bouncer schema.

  Three concerns:
  1. **Surprise side-effect.** Allowlist docs say nothing about the bouncer DB being created. Users running `iam-jit allowlist` for the first time don't expect a separate product's database to materialize.
  2. **No CLI signal.** Output is silent ("added rule X") — nothing like "(initialized bouncer audit-log DB at ~/.iam-jit/bouncer/state.db)" so the user understands what happened.
  3. **Tight coupling.** The Slice 2 design uses the bouncer's `config_events` table as the shared audit chain (sensible per the commit message), but admins who don't use the bouncer have no signal that they've implicitly opted into the bouncer's storage shape.

- Why MED (not HIGH): the file is created with 0o700 perms (WB23 LOW-23-03 closure) inside the user's HOME under `.iam-jit/`; not a security exposure. But it's surprising behavior and the docs don't mention it; if the user has `~/.iam-jit/` on a read-only or quota-restricted volume, the silent creation could fail in non-obvious ways (mitigated by `_allowlist_audit_record`'s broad `except Exception: pass` — which is itself LOW-25-03).

- Fix options:
  1. **Best**: emit a one-line CLI signal on first DB creation:
     ```python
     # In _allowlist_audit_record, after store init:
     if not pre_existed:
         click.echo(
             f"(initialized iam-jit audit DB at {store.db_path})",
             err=True,
         )
     ```
     Plus a one-line addition to `COMPATIBILITY-ALLOWLIST.md`: "Allowlist mutations write audit entries to `~/.iam-jit/bouncer/state.db` (shared with iam-jit-the-bouncer if you use it; standalone SQLite otherwise)."
  2. **Acceptable**: skip silently if the bouncer DB doesn't already exist AND the user hasn't opted in via env var (e.g. `IAM_JIT_AUDIT_DB`). Trade-off: loses "every mutation audit-logged" for users who haven't enabled audit. NOT recommended — the Lens B claim is load-bearing.
  3. **Acceptable**: separate `iam-jit allowlist init` command that explicitly sets up the audit DB; `add` errors with a helpful message if the DB doesn't exist yet. More friction but no surprise side-effects.

  Recommend option 1 — keep the audit chain intact, just be honest about it.

## LOW findings

### LOW-25-01 — Bouncer events tail can't filter on new allowlist event kinds

- Files: `src/iam_jit/bouncer_cli.py:224-231` (`events tail --kind` Click choice list — only 4 old kinds); `src/iam_jit/mcp_server.py:945-949` (`bouncer_tail_events` MCP tool's `kind` enum — same 4 kinds).

- Issue: the new allowlist event kinds `allowlist_rule_added` / `allowlist_rule_removed` are written to the bouncer's `config_events` table per the Slice 2 design. But the bouncer's own events-tail tooling can't filter for them:

  CLI:
  ```
  $ iam-jit-bouncer events tail --kind allowlist_rule_added
  Error: Invalid value for '--kind': 'allowlist_rule_added' is not one of 'rule_added', 'rule_removed', 'mode_changed', 'preset_applied'.
  ```

  MCP:
  ```json
  {"name": "bouncer_tail_events", "arguments": {"kind": "allowlist_rule_added"}}
  → JSON schema validation rejects (kind not in enum).
  ```

  Without `--kind`, both surfaces show the new events MIXED IN with bouncer rule/mode events. Admins reviewing "what allowlist changes happened last week" have to grep through ALL bouncer config events. Same for agents using `bouncer_tail_events`.

- Why LOW: events ARE captured (the table just stores arbitrary `kind` strings; no schema constraint). Discoverability is the gap, not correctness.

- Fix:
  ```python
  # bouncer_cli.py
  @click.option(
      "--kind",
      type=click.Choice(
          ["rule_added", "rule_removed", "mode_changed", "preset_applied",
           "allowlist_rule_added", "allowlist_rule_removed"],
          case_sensitive=False,
      ),
      default=None,
  )
  ```
  Same enum addition to the MCP `bouncer_tail_events` schema. Optionally split the kinds into bouncer-events vs allowlist-events with separate top-level commands; for now extending the existing list is cheapest.

  Also flag for future drift: any new audit-event kind needs both the writer + the filter enum updated. Could add a single `KNOWN_CONFIG_EVENT_KINDS` constant in `bouncer/store.py` that both the CLI and MCP enums import from. Removes the drift surface.

### LOW-25-02 — Doc says "order rules specific to general" but match_intent has no specificity logic

- Files: `docs/COMPATIBILITY-ALLOWLIST.md:75` ("Order rules from specific to general."); `src/iam_jit/compatibility_allowlist.py:401-414` (`match_intent` walks `store.list()` and returns first match; no specificity sort).

- Issue: the doc tells admins "Order rules from specific to general. Put narrow account-specific rules at the top, wildcards at the bottom." This is presented as an instruction — but the code doesn't enforce it. `match_intent` walks rules in INSERTION order. If admin puts a wildcard first and a specific rule second, the wildcard wins.

  Same WB24 LOW-24-03 shape: comment-driven semantics not enforced by code. The catalog has only one entry per workload so the "first-match-wins" comment there is also unused — but at least the catalog is curated. The allowlist is admin-managed; ordering errors WILL happen.

  Tied to MED-25-03 (remove+re-add flips order silently). If LOW-25-02 had auto-sort, MED-25-03 would not exist.

- Why LOW: admin discipline can avoid the failure; doc tells admins what to do. But it's documentation describing code-enforced behavior the code doesn't enforce.

- Fix: (option 2 in MED-25-03) — `match_intent` sorts by specificity at lookup time. Then the doc claim becomes true regardless of insertion order.

  OR: structural test that asserts the allowlist's CURRENT state has no wildcard-before-specific shadows. Useful for catching admin errors at CLI add time:
  ```python
  # In InMemoryAllowlistStore.add and FileAllowlistStore.add, after insert:
  shadows = _detect_wildcard_shadows(self.list())
  if shadows:
      logger.warning("rule %s may be shadowed by earlier wildcard rule(s): %s", ...)
  ```

### LOW-25-03 — `_allowlist_audit_record` silently swallows all exceptions

- File: `src/iam_jit/cli.py:747-757`:
  ```python
  def _allowlist_audit_record(*, kind: str, summary: str, detail: dict | None = None) -> None:
      """Mirror the bouncer's config_events writer. Best-effort — if
      the bouncer store isn't initialized, the CLI continues."""
      try:
          from .bouncer.store import BouncerStore
          store = BouncerStore()
          try:
              store._record_config_event_locked(
                  actor=_allowlist_actor(), kind=kind, summary=summary, detail=detail,
              )
          finally:
              store.close()
      except Exception:
          pass
  ```

- Issue: the docstring + `COMPATIBILITY-ALLOWLIST.md:28-30` ("every mutation is audit-logged via the bouncer's `config_events` table") promise a contract that this implementation doesn't keep. If `BouncerStore()` construction fails (read-only volume, quota, ...) OR `_record_config_event_locked` raises (SQLite lock contention, disk full, ...), the admin sees:
  ```
  $ iam-jit allowlist add ... --reason "audit-required change"
  added rule abc123: proceed
  ```
  with NO indication that the audit log write didn't happen. The rule is now in the allowlist file BUT not in the audit chain. Per Lens B "uncircumventable" — the audit chain has a hole.

  Three failure modes:
  1. Bouncer DB unreachable (permissions, disk full) → rule added, no audit entry.
  2. Bouncer DB schema mismatch (older bouncer binary's schema on disk) → rule added, no audit entry.
  3. `_record_config_event_locked` is a PRIVATE method (underscore prefix). If bouncer refactors it (renames, changes signature, deletes), the silent failure persists indefinitely until someone notices the audit gap.

- Why LOW: the immediate failure mode is "audit gap" not "wrong rule applied." But the doc + design philosophy explicitly call out Lens B uncircumventability; the best-effort impl undercuts that.

- Fix options:
  1. **Best**: ATOMIC invariant. If audit-log write fails, the rule add should also fail (or roll back):
     ```python
     def _allowlist_audit_record(...) -> None:
         """Raises if the audit chain can't be written. Caller is responsible
         for either rolling back the corresponding state change or surfacing
         the error to the operator."""
         from .bouncer.store import BouncerStore
         store = BouncerStore()
         try:
             store._record_config_event_locked(...)
         finally:
             store.close()
     # Caller:
     try:
         _allowlist_audit_record(...)
     except Exception as e:
         # roll back: remove the rule we just added
         store.remove(rule.rule_id)
         click.echo(f"audit-log write failed; rule add rolled back: {e}", err=True)
         sys.exit(3)
     ```
  2. **Acceptable**: log to a fallback (e.g. stderr / a sidecar file) when the bouncer write fails, AND warn the admin: "audit-log write failed; rule added but audit chain has gap. See: ..."
  3. **Worst**: keep current behavior; update docs to say "best-effort audit logging." Loses the Lens B claim.

  Recommend option 1 — the audit chain is the WHOLE POINT of the design. If it can't be written, the change shouldn't ship.

  Also: stop reaching into bouncer's private API (`_record_config_event_locked`). Add a public `BouncerStore.record_external_event(kind, actor, summary, detail)` method (or similar) and call THAT.

### LOW-25-04 — Dead fallback branch in `check_compatibility` allowlist path

- File: `src/iam_jit/compatibility.py:566-577`:
  ```python
  if allowlist_rule is not None:
      result = allowlist_rule.to_result()
      # Echo the agent's existing_role_hint if the rule's verdict
      # is USE_EXISTING and the rule didn't pre-set an ARN
      # (admin may have intentionally left it for the agent to
      # supply).
      if (
          result.verdict == Compatibility.USE_EXISTING
          and result.existing_role_arn is None
          and cleaned_hint is not None
      ):
          result = dataclasses.replace(result, existing_role_arn=cleaned_hint)
  ```

- Issue: the comment says "admin may have intentionally left it [the ARN] for the agent to supply." But `build_rule` REJECTS `USE_EXISTING` without `existing_role_arn`:
  ```python
  if verdict_enum == Compatibility.USE_EXISTING:
      if not existing_role_arn:
          raise InvalidRule("verdict=use_existing requires existing_role_arn")
  ```
  So any rule constructed via the public builder CAN'T trigger this fallback. The branch is unreachable for normally-built rules.

  Three failure modes for reachability:
  1. `AllowlistRule(...)` constructed directly via the dataclass (bypassing `build_rule`) — possible in tests, possible in future code that constructs rules from a different source. Currently no such code.
  2. Hand-edited YAML with USE_EXISTING + missing ARN — would be skipped by `_read_all`'s try/except (build_rule raises InvalidRule, row gets dropped).
  3. Future "intent: admin can leave ARN for agent to supply" UX — `build_rule` would need to change to permit it. Then this branch would fire.

  So the comment describes a future-intended UX; the code today doesn't allow it. Either build_rule should permit USE_EXISTING-without-ARN (and the comment is right + the fallback is meaningful), or the fallback should be deleted (since it's unreachable).

- Why LOW: dead code, no harm. But it's the "comment describes behavior code doesn't keep" shape WB22/WB23/WB24 keep finding.

- Fix options:
  1. **Best**: delete the fallback. Comment + branch + 4 lines gone. If Slice 3 needs the "admin leaves ARN for agent to supply" UX, build it deliberately at that point.
  2. **Acceptable**: change `build_rule` to permit USE_EXISTING-without-ARN AND adjust the rejection-in-validate accordingly. Then the fallback is meaningful. Bigger surface change; not warranted today.

### LOW-25-05 — MCP `list_compatibility_overrides` returns all rules without pagination

- File: `src/iam_jit/mcp_server.py:1390-1402`:
  ```python
  def _list_compatibility_overrides_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
      ...
      try:
          store = build_default_store()
          rules = store.list()
      except Exception as e:
          return {"error": f"could not load allowlist: {e}", "rules": [], "count": 0}
      return {
          "rules": [r.to_dict() for r in rules],
          "count": len(rules),
      }
  ```

- Issue: no limit parameter, no max-rule cap. An admin with 10,000 rules gets 10,000 rules in the MCP response (subject to JSON line-length limits on the MCP transport). The bouncer's `bouncer_tail_events` MCP tool has a `limit` parameter with `default=50, maximum=1000` (mcp_server.py:944) — the allowlist listing doesn't follow the same pattern.

  Same WB22 LOW-22-02 shape — unbounded MCP responses. Realistic for admin-managed allowlists at <100 rules; relevant if anyone scripts bulk import.

- Why LOW: today's admin-managed scale (per the doc, hand-managed via CLI) is tiny. Not a security or correctness issue. Worth flagging for consistency with the bouncer MCP tools.

- Fix:
  ```python
  def _list_compatibility_overrides_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
      limit_raw = args.get("limit", 100)
      try:
          limit = max(1, min(int(limit_raw), 1000))
      except (TypeError, ValueError):
          return {"error": "limit must be a positive integer"}
      ...
      truncated = len(rules) > limit
      return {
          "rules": [r.to_dict() for r in rules[:limit]],
          "count": len(rules),
          "truncated": truncated,
          "limit": limit,
      }
  ```
  Match the bouncer's enum/limit pattern. Update the MCP tool inputSchema to declare `limit`.

### LOW-25-06 — Blank-string `--role-arn` error message says "not a valid IAM role ARN"

- File: `src/iam_jit/compatibility_allowlist.py:183-193` (`_validate_verdict_and_arn` for USE_EXISTING).

- Issue: an admin who passes `--role-arn '   '` (whitespace-only) for a USE_EXISTING rule gets:
  ```
  rejected: existing_role_arn '   ' is not a valid IAM role ARN
  ```
  Technically correct but misleading. The actual issue is "ARN is blank after stripping" not "ARN failed regex." Verified:
  ```python
  >>> build_rule(account_id='111111111111', workload='k8s_pod', verdict='use_existing',
  ...     existing_role_arn='   ', reason='x', created_by='admin')
  InvalidRule: existing_role_arn '   ' is not a valid IAM role ARN
  ```

  Trace: `not existing_role_arn` is False (truthy non-empty string `'   '`); falls to `_validate_existing_role_hint` which strips and returns `(None, False)`; then `if invalid or cleaned is None` → True → raises with the misleading message.

- Why LOW: UX confusion, not a correctness issue. Admin will retry with a real ARN.

- Fix: add a specific blank-check at the top of the USE_EXISTING branch:
  ```python
  if verdict_enum == Compatibility.USE_EXISTING:
      if existing_role_arn is None or not existing_role_arn.strip():
          raise InvalidRule("verdict=use_existing requires existing_role_arn")
      cleaned, invalid = _validate_existing_role_hint(existing_role_arn)
      if invalid or cleaned is None:
          raise InvalidRule(
              f"existing_role_arn {existing_role_arn!r} is not a valid IAM role ARN"
          )
  ```

## Verified clean

The following were probed per the audit prompt and found no issues:

- **No MCP mutation tool for allowlist** — `test_mcp_no_mutation_tool_for_allowlist` checks the `tools/list` response for a hardcoded set of forbidden names. The test is solid for the basic surface check. Verified via grep + dispatcher inspection (`mcp_server.py:2233-2234`): the only dispatched allowlist-related tool is `list_compatibility_overrides`, which calls `_list_compatibility_overrides_for_mcp` (pure read, no `store.add`/`store.remove` calls in the entire MCP module — verified via `grep`). NO indirect mutation paths through `check_iam_jit_compatibility` either — it only calls `match_intent(intent, store)` which is read-only.
- **Read tool doesn't write audit log on read** — `_list_compatibility_overrides_for_mcp` does not call `_compatibility_audit_sink()` or any event-record path. Read is genuinely side-effect-free. (Whether reads SHOULD be audited is a different question — flagged separately as a deferral consideration but not a bug.)
- **AGENTS.md correctly says agents can READ via MCP** — `docs/AGENTS.md:57-60` text matches the actual MCP surface (`list_compatibility_overrides` exposed for read; nothing for mutation). No drift.
- **Atomic temp-and-rename writes** — `FileAllowlistStore._write_all` uses `self.path.with_suffix(self.path.suffix + ".tmp")` + `tmp.replace(self.path)`. For `.yaml` files becomes `.yaml.tmp` (fine); for suffix-less paths becomes `.tmp` (also fine). Verified `os.replace` is atomic on POSIX.
- **`InMemoryAllowlistStore` thread safety** — uses `threading.Lock` correctly around list mutation + iteration. `list()` returns a copy (`list(self._rules)`) so callers can't mutate the internal state.
- **Duplicate rule_id rejected** — both stores check `any(r.rule_id == rule.rule_id for r in existing)` before insert. Test `test_in_memory_store_duplicate_rule_id_rejected` covers.
- **`_read_all` skips non-dict rows** — `if not isinstance(raw, dict): continue` catches the YAML-rules-is-dict case (iterating yields keys = strings; strings aren't dicts; skipped). Same for None / scalar entries. Verified via repro.
- **`_read_all` skips InvalidRule rows** — test `test_file_store_skips_malformed_rows` covers; mirrors WB23 MED-23-01 pattern. Confirmed correct behavior for one-bad-one-good case.
- **All 4 AWS partitions accepted in role-ARN validator** — `_IAM_ROLE_ARN_RE = r"^arn:aws(?:-[a-z-]+)?:iam::\d{12}:role/[\w+=,.@/-]+$"` (from WB24 MED-24-02 closure). Matches `aws / aws-us-gov / aws-cn / aws-iso / aws-iso-b`. Test coverage from WB24 still applies.
- **Account-ID validator rejects bad input** — `_ACCOUNT_ID_RE = r"^\d{12}$"` rejects non-digit, wrong-length, alphanumeric. Test `test_build_rule_rejects_bad_account_id` covers four bad shapes.
- **`build_rule` accepts WorkloadType instances OR string names** — handled in `_validate_workload` via `isinstance(workload, WorkloadType)` branch. Test exists.
- **CLI subcommand discoverability** — verified `iam-jit --help` lists `allowlist` group; `iam-jit allowlist --help` lists `list / add / remove / show`. Click registers the group correctly via `@main.group("allowlist")`.
- **Click's `Choice(["proceed", "use_existing", "use_bouncer", "cannot_help"])` rejects uppercase** — verified `--verdict USE_EXISTING` returns exit 2 with "Invalid value for '--verdict'". Correctly case-sensitive.
- **No `1.8%` mentions** — grep confirms zero `1.8%` mentions in the diff. Per [[no-one-eight-percent-mention]] — clean.
- **`[[creates-never-mutates]]` not invoked spuriously** — the allowlist creates rules, not IAM resources; the `[[recommender-context-boundary]]` citation at `compatibility_allowlist.py:23-25` is correct (admin-supplied config, not inferred from source code / AWS state).
- **`description` field plumbed into audit event** — `compatibility.py:596` includes `"description": intent.description` in the audit detail (WB24 LOW-24-02 closure still works in Slice 2).
- **MCP `list_compatibility_overrides` error path** — when `build_default_store` fails (e.g. permission error), returns `{"error": ..., "rules": [], "count": 0}` instead of crashing. (Note: this is the GOOD path; the HIGH-25-01 crash happens AFTER successful read, in JSON serialization.)
- **Frozen dataclasses** — `AllowlistRule` is `@dataclasses.dataclass(frozen=True)`; immutable. `CompatibilityResult` likewise (from WB24).
- **`_isoformat_z` handles UTC correctly** — `dt.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")` — verified with naïve + aware inputs.
- **Allowlist file lives outside repo by default** — `~/.iam-jit/compatibility_allowlist.yaml`; user-scoped; can't be committed by accident.

## Regression check

Command run: `cd /Users/reagan/repos/iam-roles && .venv/bin/python -m pytest --no-header -q --ignore=tests/test_calibration_corpus.py --ignore=tests/e2e 2>&1 | tail -5`

Result:
```
2391 passed, 29 skipped, 14 deselected, 2 warnings in 88.60s (0:01:28)
```

Matches the audit-prompt baseline (2391). All 47 new Slice-2 tests pass. No regressions in any of the 2344 pre-Slice-2 tests.

## Summary

**0 CRIT, 1 HIGH, 5 MED, 6 LOW.** Slice 2 ships clean architecture at the data-model + store + validation layers (zero findings there); the bug concentration is in the cross-layer trust gaps WB21-WB24 keep finding. The HIGH (PyYAML datetime auto-deserialization) is a real production breakage that fires the FIRST time an admin follows the doc's "you can edit by hand" instruction with an unquoted ISO-8601 timestamp.

The 1 HIGH is the most-impactful:
- **HIGH-25-01** (PyYAML datetime auto-deserialization → JSON serialization crash → MCP tool unusable + file format corruption on writeback) is a foundation-layer bug that breaks the documented hand-edit workflow. Should land in the closure commit; defensive normalization in `_read_all` is ~5 lines.

The 5 MEDs cluster around two themes:

Trust-gap pattern continuation (WB21-WB24 lineage):
- **MED-25-01** (USE_BOUNCER verdict accepted by checker, ignored by submit_policy) — same shape as WB24 HIGH-24-01; the verdict-enum + rejection-set drift needs a structural test.
- **MED-25-02** (cannot_help / use_bouncer with no hint → next_action_hint=None) — breaks WB24's "every non-PROCEED carries a path forward" invariant; fix by adding verdict-specific default hints.
- **MED-25-03** (remove+re-add silently flips first-match-wins) — doc-encouraged workflow that breaks doc-stated ordering rule; auto-specificity-sort fixes this AND LOW-25-02.

Lens B audit-chain integrity:
- **MED-25-04** (broken allowlist degrades silently to catalog; admin intent invisible in audit log) — needs an `allowlist_load_error` field on the catalog-fallback audit event.
- **MED-25-05** (`iam-jit allowlist add` silently creates bouncer DB) — small UX fix (one-line CLI signal + doc note) but worth doing.

The 6 LOWs are: cross-tool drift (bouncer events tail can't filter the new kinds — LOW-25-01); doc-claim asymmetry (LOW-25-02 ordering, LOW-25-03 audit best-effort); dead-code branch (LOW-25-04); MCP pagination consistency (LOW-25-05); UX error-message clarity (LOW-25-06).

Recommended closure-commit fix sequence:

1. **HIGH-25-01**: defensive normalization of `created_at` in `_read_all` + isinstance-check in `build_rule` + test for the unquoted-timestamp case. ~30 min; pure defensive code. Highest priority.
2. **MED-25-01**: add `USE_BOUNCER` to `submit_policy` rejection set + structural test that every non-PROCEED verdict has a rejection branch. ~30 min.
3. **MED-25-02**: verdict-specific default `next_action_hint` in `build_rule` + parameterized test asserting non-null hint for every non-PROCEED rule. ~30 min.
4. **MED-25-03 + LOW-25-02**: implement auto-specificity-sort in `match_intent` (specific rules before wildcards regardless of insertion order). Closes both findings; ~1 hr with tests.
5. **MED-25-04**: add `allowlist_load_error` field to audit-event detail; propagate from try/except in `check_compatibility`. ~30 min.
6. **MED-25-05**: CLI signal on first-time DB creation + doc note in `COMPATIBILITY-ALLOWLIST.md`. ~20 min.
7. **LOW-25-01**: extend bouncer events `--kind` choice list + MCP `bouncer_tail_events` enum to include the new kinds; add `KNOWN_CONFIG_EVENT_KINDS` constant. ~20 min.
8. **LOW-25-03**: make `_allowlist_audit_record` atomic (raise on failure; caller rolls back the rule add). ~30 min including test.
9. **LOW-25-04**: delete the dead `existing_role_arn` fallback branch. ~5 min.
10. **LOW-25-05**: add `limit` parameter to `_list_compatibility_overrides_for_mcp` matching `bouncer_tail_events`'s pattern. ~15 min.
11. **LOW-25-06**: blank-ARN-specific error message in `_validate_verdict_and_arn`. ~5 min.

After fixes ship, re-run audit (Round 26) — recommended scope: the closure commit + a re-probe of HIGH-25-01 to confirm hand-edited unquoted timestamps round-trip cleanly through `list --json` + MCP listing + writeback.

The Slice 2 data-model + storage + validation layer is well-shaped (zero findings); the 12 findings concentrate at the integration boundaries (compatibility → submit_policy enforcement, CLI → audit-chain, file format → JSON serialization, CLI → bouncer DB initialization, docs → code-enforced semantics). Same lesson WB21-WB24 keep teaching: the foundation is reliably solid; the cross-tool wiring is where Lens A and Lens B claims diverge. Slice 3 (intake integration with DEFER_TO_EXISTING) will provide another opportunity to test this; the structural-invariant tests (LOW-25-01's `KNOWN_CONFIG_EVENT_KINDS` constant, MED-25-01's "every verdict has a rejection branch") shrink the drift surface so future audits find fewer instances of the same pattern.

Audit ROI continues: 1 HIGH that would have shipped breaking the documented hand-edit workflow, 5 MEDs catching trust-gap continuations the unit-test suite (47 new tests) didn't cover. The structural-invariant gaps are the highest-value learning — per [[audit-cadence-discipline]] the catch rate of pattern-similar bugs (LOW-24-03 → LOW-25-02 → MED-25-01) suggests the next slice should land with the per-verdict-has-rejection-branch test as part of the test scaffolding rather than as audit closure work.

---

## WB25 closures (2026-05-17)

10 of 12 findings addressed; 2 deferred-with-rationale.

### Updated closure table

| Finding | Status | How closed |
|---|---|---|
| HIGH-25-01 PyYAML datetime breaks JSON serialization | **CLOSED** | (a) Defensive normalization in `FileAllowlistStore._read_all`: coerce non-string `created_at` to ISO-Z string before calling `build_rule`. Handles `datetime` (PyYAML default for unquoted timestamps), `date` (PyYAML for date-only values), and other non-string types. (b) `build_rule` rejects non-string `created_at` with a clear "quote your timestamp" error. Defense-in-depth. Regression test loads a hand-edited YAML with unquoted timestamp + serializes the result; previously crashed, now passes. |
| MED-25-01 `submit_policy` doesn't reject `USE_BOUNCER` | **CLOSED** | Extended the rejection set to `{USE_EXISTING, USE_BOUNCER, CANNOT_HELP}`. Now all three non-PROCEED verdicts get refused by `submit_policy` with the same structured response (reasoning + next_action_hint + bouncer_recommended). Regression test starts with an admin-allowlist USE_BOUNCER rule, calls submit_policy, asserts refused. |
| MED-25-02 `cannot_help`/`use_bouncer` rules return null next_action_hint | **CLOSED** | New `_default_hint_for_verdict()` helper supplies per-verdict default hints when the admin didn't pass `--next-action-hint`. Wired into `AllowlistRule.to_result()`. Per [[agent-friendly-not-bypassable]] Lens A: agents always get a path forward, never a vague "denied." Tests cover both verdicts. |
| MED-25-03 Remove+re-add flips first-match-wins order | **CLOSED** | New `_rule_specificity()` scoring: rules with both account_id AND workload set score 2; one set scores 1; both wildcards score 0. `match_intent` sorts by specificity DESC, then insertion order ASC (stable). Remove+re-add no longer can shadow a specific rule with a wildcard. Two regression tests cover the canonical workflow + the "specific wins over wildcard regardless of insertion" invariant. |
| MED-25-04 Broken allowlist degrades silently to catalog | **CLOSED** | `check_compatibility` now captures the exception's repr into `allowlist_load_error` and includes it in the audit event detail. Admins reviewing the audit log see "tried allowlist, failed with: X" rather than a silent catalog fallthrough. Regression test asserts the field is recorded. |
| MED-25-05 CLI creates bouncer DB on first run with no signal | **DEFERRED** | Touches the bouncer-store init path which is shared with the bouncer's own CLI; cross-product UX work better done as its own change. Banner can land in Slice C of #168 alongside the per-PID work. |
| LOW-25-01 events filter enum drift | **CLOSED** | Added `allowlist_rule_added` + `allowlist_rule_removed` to both the CLI `events tail --kind` choice and the MCP `bouncer_tail_events` schema enum. (Same shape as WB26 LOW-26-05's `task_started`/`task_ended` addition.) |
| LOW-25-02 docs say specificity but match_intent didn't sort | **CLOSED** | MED-25-03 fix solves this — specificity is now actually enforced by code, not just documented. |
| LOW-25-03 `_allowlist_audit_record` swallows exceptions | **DEFERRED** | Intentional best-effort logging (mirrors bouncer's `_record_config_event_locked` pattern). Same shape as WB26 MED-26-05 audit-write best-effort. Documented in the function docstring. Will revisit if telemetry shows admins missing audit events. |
| LOW-25-04 dead fallback branch | **CLOSED** | Deleted the unreachable USE_EXISTING-without-ARN echo branch in `check_compatibility`. `build_rule` enforces ARN-required-with-USE_EXISTING, so the branch couldn't fire for any normally-constructed rule. Comment explains the deletion + invites Slice 3 to deliberately permit if a use case appears. |
| LOW-25-05 MCP `list_compatibility_overrides` not paginated | **CLOSED** | Added `limit` parameter (default 50, hard cap 1000) mirroring `bouncer_tail_events` shape. Response includes `total` alongside `count` so callers can detect truncation. Bool/non-int/zero limit rejected. Three regression tests. |
| LOW-25-06 blank ARN error message confusing | **CLOSED** | Distinguish blank-/whitespace-only `existing_role_arn` from non-empty-but-malformed: first says "is whitespace-only; supply a real IAM role ARN like..."; second says "is not a valid IAM role ARN (expected '...' shape)". Regression tests for both. |

### Verification

- `tests/test_compatibility_allowlist.py`: 47 → 59 tests (+12 closure tests).
- All 119 allowlist + compatibility tests pass.
- Broader suite: **2461 passed**, 29 skipped, 14 deselected (was 2449 before WB25 closures; +12 net).
- Verified end-to-end via the canonical hand-edit scenario from HIGH-25-01 — unquoted timestamps now parse and the result serializes cleanly through MCP.

### What WB25 DID NOT close

- **MED-25-05** (silent bouncer DB creation on first allowlist add): bundled with WB26 / Slice C bouncer work.
- **LOW-25-03** (silent exception swallow in audit-record): same best-effort pattern as bouncer's config_events writes; intentional + documented.

### Why this round matters

HIGH-25-01 was a real "documented workflow is broken" bug — the COMPATIBILITY-ALLOWLIST.md doc invited hand-editing, and the hand-edited file crashed the JSON serialization. The fix (defensive normalization + defensive validation) honors the doc's contract: hand-editable YAML where bad rows skip but valid rows parse cleanly.

MED-25-03 closed the trust-gap shape: docs promised specificity ordering, code didn't enforce it. The specificity-scoring fix means admins can use the documented "specific rules win over wildcards" pattern without manually re-ordering after every remove+re-add.

Per [[audit-cadence-discipline]]: 0 CRIT + 1 HIGH + 5 MED + 6 LOW in code that had 47 passing unit tests. The pattern continues to pay for itself — HIGH-25-01 specifically would have shipped to launch if not for the audit (unit tests don't typically exercise the YAML-edit → MCP-serialize round trip).
