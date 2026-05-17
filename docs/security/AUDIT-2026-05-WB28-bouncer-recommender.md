# Round 28 audit — bouncer recommender Slice D (#173)

Commit under review: `b51e008` (`feat(bouncer): #173 Slice D — observation-based rule recommender`).

Scope (Slice D only — Slices A/B/C audited in WB23/WB26/WB27):
- `src/iam_jit/bouncer/recommender.py` (new ~478 LOC: `KNOWN_ACTIONS`, `RuleRecommendation`, `_longest_common_prefix`, `_detect_arn_prefix`, `_detect_region_pattern`, `synthesize_rules`, `summarize_window`, `research_note`)
- `src/iam_jit/bouncer_cli.py` (+117 LOC: `recommend` command + `_apply_recommendations_via_cli` helper)
- `src/iam_jit/mcp_server.py` (+183 LOC: `bouncer_recommend_rules` + `bouncer_apply_recommendation` MCP tools + dispatch)
- `tests/bouncer/test_recommender.py` (new ~497 LOC, 40 tests)
- `docs/IAM-JIT-BOUNCER.md` (+76 LOC: Observation-based recommender section)

Read-only audit. Per [[audit-cadence-discipline]].

Regression: **2526 passed**, 29 skipped, 14 deselected (90.36s, excluding `tests/e2e/*` and `tests/test_calibration_corpus.py`). Matches the commit's stated baseline (2526) exactly. No regressions caused by Slice D.

## Headline

15 findings: **1 CRIT, 2 HIGH, 6 MED, 6 LOW.**

The CRIT is a recommender-semantics inversion. The two HIGHs are real correctness/integrity gaps that ship today.

**CRIT-28-01**: `synthesize_rules` does NOT filter decisions by `decision` field. **Denied** and **prompted** calls are aggregated alongside **allowed** ones into a single ALLOW-rule recommendation. The agent runs in LEARN mode, attempts `iam:CreateRole` 3 times, the bouncer correctly denies (or prompts and the human rejects); the next `recommend --apply` proposes "ALLOW iam:CreateRole" because the 3 denied attempts cleared `--min-support`. Apply that recommendation and the rule the human's brain previously rejected is now ALLOW-listed in the persisted ruleset. Inverts the security premise of the entire recommend-then-enforce loop. Verified via direct repro:

```
3 DENIED iam:CreateRole calls  →  recommended:  ALLOW iam:CreateRole (support=3)
2 ALLOW + 3 DENY mixed S3 reads  →  recommended:  ALLOW s3:GetObject [arn=arn:aws:s3:::*]  (covering both prefixes)
```

The second repro is sharper: 2 allowed reads of `arn:aws:s3:::data/x` plus 3 denied reads of `arn:aws:s3:::secrets/y` produce a single ALLOW rule whose `arn:aws:s3:::*` glob covers BOTH prefixes — the previously-denied secrets bucket becomes ALLOWED via the synthesized rule. The recommender is effectively answering "what did the agent TRY to do" rather than "what was correctly allowed and worth promoting to a rule."

**HIGH-28-01**: `_detect_arn_prefix`'s anchor-back-to-delimiter step over-trims when the LCP ends mid-segment. Concrete repro: ARNs `arn:aws:s3:::reports-2026-q1/a`, `…q2/b`, `…q3/c` share LCP `arn:aws:s3:::reports-2026-q`. The anchor loop finds the last `/` at position before `reports-2026-q`, backs up to `arn:aws:s3:::`, and emits a `arn:aws:s3:::*` rule — proposing ALL of S3 even though the observed traffic only touched `reports-2026-*`. The intended conservatism (don't propose a fake bucket name like `reports-2026-q`) lands as catastrophic over-broadening (propose all S3). The fix should anchor to the last `/` OR `:` _within_ the bucket-name segment when the bucket name has no `/`, or fall back to the dash/digit boundary (`reports-2026-` is the right answer).

**HIGH-28-02**: MCP `bouncer_apply_recommendation` accepts arbitrary types for `arn_scope`, `region_scope`, and `note` pass-through fields. An agent that submits `{"pattern": "s3:GetObject", "arn_scope": {"nested": "object"}}` crashes the handler with `sqlite3.ProgrammingError: Error binding parameter 3: type 'dict' is not supported` — the exception escapes the wrapper (no `except sqlite3.ProgrammingError` block). Same crash for `note` (dict / list) and `region_scope` (dict). The `inputSchema` declares them as `"type": "string"` but the handler doesn't enforce; numerics get silently accepted (`arn_scope=12345` succeeds with an `arn_scope` of int(12345) stored in the rule, breaking later `_aws_glob_match`). Either explicit isinstance() validation or a single try/except around add_rule.

The six MEDs cluster around recommender-correctness contracts, MCP/CLI parity, and audit-chain completeness:

- **MED-28-01**: ARN/region scope inferred from a tiny non-None subset, then APPLIED to the whole support group. With 10 calls and 2 having ARN data (the other 8 had `arn=None`), the recommender writes a rule scoped to that 2-ARN prefix. In ENFORCE mode, the 8 None-ARN calls then FAIL to match the rule (per `rule_matches`: "Rule scopes by ARN but request has no resolvable ARN — be conservative: don't match"). The rule the recommender just shipped silently breaks 80% of the historical traffic it was meant to authorize.
- **MED-28-02**: `_apply_recommendations_via_cli` and `_bouncer_apply_recommendation_for_mcp` do NOT dedupe against existing rules. Calling `recommend --apply` twice produces two identical rule rows. First-match-wins evaluation means correctness isn't broken, but `list_rules` accumulates duplicates over time. Verified via direct repro: 2 rules, both `s3:GetObject allow origin=recommendation`.
- **MED-28-03**: The `recommendation_applied` audit-chain event records `{"count": N}` only — not which specific rule IDs were added in the batch. Post-incident review can't reconstruct "what rules did recommendation batch on date X produce" without correlating `rule_added` events by timestamp + actor. Slice D's docs explicitly promise the batch event "shows the batch shape" but the shape is just an integer.
- **MED-28-04**: CLI `recommend` accepts `--limit 0`, `--limit -5`, `--min-support 0` without rejection. Returns "no recommendations" silently. MCP enforces `min_support >= 1` and `limit >= 1` correctly; CLI surface is asymmetric. Same anti-pattern as WB27 LOW-27-02 (CLI `--owner ''` silently accepted).
- **MED-28-05**: Recommender ingests decisions made under per-task scopes (those with `task_id != NULL`). 3 one-off task-scoped allowed calls now generate a permanent ALLOW rule. The recommender has no signal of "this was one-off." Should filter `WHERE task_id IS NULL` to consider only general-population traffic, or carry the task_id forward so the agent can decide.
- **MED-28-06**: CLI `--apply` is a one-shot single Click boolean — no preview-then-confirm, no `--dry-run` opposite. The agent / admin running `recommend --apply` adds rules in bulk with no chance to skim. The default is review (good) but the flag is "all-or-nothing"; the MCP variant exposes per-rule cherry-pick but the CLI doesn't.

The six LOWs are: misleading ARN/region rationale string ("2 of 2 ARNs" hides "8 of 10 calls had no ARN") (LOW-28-01); KNOWN_ACTIONS severity markers inconsistent across catalog entries (DESTRUCTIVE / SENSITIVE / WRITE / EXPENSIVE / HIGH RISK as prose) (LOW-28-02); `summarize_window`'s `total_calls` may exceed `allow + deny + prompt` for missing/unknown decision values (LOW-28-03); time-window filter is naive lexicographic string comparison — silently mishandles mixed-timezone input (LOW-28-04); KNOWN_ACTIONS catalog has stale-text risk (curated prose, AWS service behavior evolves) (LOW-28-05); `_apply_recommendations_via_cli` calls private `store._record_config_event_locked` (consistent-with-WB23-precedent but still API debt) (LOW-28-06).

## Closure status

| Finding | Status |
|---|---|
| CRIT-28-01 `synthesize_rules` includes deny + prompt decisions in ALLOW-rule recommendations; denied traffic becomes proposed allow rule | OPEN |
| HIGH-28-01 `_detect_arn_prefix` anchor over-trims mid-segment LCPs; proposes `arn:aws:s3:::*` for `reports-2026-q[1-3]` ARNs | OPEN |
| HIGH-28-02 MCP `bouncer_apply_recommendation` crashes (uncaught `sqlite3.ProgrammingError`) on dict/list `arn_scope`/`region_scope`/`note`; silently accepts numeric values | OPEN |
| MED-28-01 ARN/region scope inferred from subset of records-with-data, applied to whole support group; rule blocks majority of historical calls in ENFORCE mode | OPEN |
| MED-28-02 CLI + MCP apply paths do not dedupe against existing rules; repeat apply produces duplicate rows | OPEN |
| MED-28-03 `recommendation_applied` event detail is `{count: N}` only; doesn't record which rule IDs were applied | OPEN |
| MED-28-04 CLI accepts `--limit 0/-N` and `--min-support 0` without validation; MCP correctly rejects same | OPEN |
| MED-28-05 Recommender includes task-scoped decisions; one-off task traffic becomes permanent rule recommendation | OPEN |
| MED-28-06 CLI `--apply` is bulk-only; no `--dry-run` opposite or per-rule confirmation; MCP exposes per-rule cherry-pick but CLI doesn't | OPEN |
| LOW-28-01 ARN/region rationale strings count only non-None records (`2 of 2 observed ARNs`); user reading sees support_count=10 and infers consistency | OPEN |
| LOW-28-02 KNOWN_ACTIONS severity markers (DESTRUCTIVE / SENSITIVE / WRITE / EXPENSIVE / HIGH RISK) inconsistent across catalog; embedded in prose; should be a structured field | OPEN |
| LOW-28-03 `summarize_window`'s `total_calls` may exceed `allow + deny + prompt` for missing/unknown `decision` field values | OPEN |
| LOW-28-04 `--since`/`--until` filter is naive lexicographic string comparison; silently mishandles mixed-timezone input (+00:00 vs Z) | OPEN |
| LOW-28-05 KNOWN_ACTIONS catalog risks staleness over time; curated prose has no provenance/last-reviewed-at field; AWS service behavior evolves | OPEN |
| LOW-28-06 `_apply_recommendations_via_cli` calls private `store._record_config_event_locked`; consistent with WB23 precedent but still API debt | OPEN |

## CRIT findings

### CRIT-28-01 — `synthesize_rules` does not filter by decision; denied/prompted calls become ALLOW recommendations

- File: `src/iam_jit/bouncer/recommender.py:391-444`.

- Issue: `synthesize_rules` groups decisions by `(service, action)` and produces ALLOW rule recommendations based on `support_count = len(group_decisions)`. The grouping code at `:395-401`:
  ```python
  for d in decisions:
      service = d.get("service")
      action = d.get("action")
      if not service or not action:
          continue
      groups[(service.lower(), action)].append(d)
  ```
  Never reads `d.get("decision")`. So a denied call counts the same as an allowed one. The rule construction at `:423-431`:
  ```python
  rule = ProxyRule(
      pattern=pattern,
      effect=Effect.ALLOW,
      arn_scope=arn_scope,
      region_scope=region_scope,
      note=f"recommended from {support} observed calls",
      origin="recommendation",
  )
  ```
  Always emits `Effect.ALLOW`. So 3 denied attempts at `iam:CreateRole` produce: "ALLOW iam:CreateRole, support: 3 calls."

  Verified via direct repro:
  ```python
  >>> # 3 denied iam:CreateRole calls
  >>> recs = synthesize_rules([
  ...     {'service': 'iam', 'action': 'CreateRole', 'decision': 'deny', ...}
  ... ] * 3, min_support=3)
  >>> recs[0].proposed_rule.effect, recs[0].proposed_rule.pattern, recs[0].support_count
  (Effect.ALLOW, 'iam:CreateRole', 3)
  ```

  And the mixed-decision variant (sharper because the ARN broadening compounds):
  ```python
  >>> # 2 allowed s3 reads of data/* + 3 denied reads of secrets/*
  >>> recs = synthesize_rules([
  ...     {'service':'s3','action':'GetObject','arn':'arn:aws:s3:::data/x','decision':'allow', ...},
  ...     {'service':'s3','action':'GetObject','arn':'arn:aws:s3:::data/y','decision':'allow', ...},
  ...     {'service':'s3','action':'GetObject','arn':'arn:aws:s3:::secrets/a','decision':'deny', ...},
  ...     {'service':'s3','action':'GetObject','arn':'arn:aws:s3:::secrets/b','decision':'deny', ...},
  ...     {'service':'s3','action':'GetObject','arn':'arn:aws:s3:::secrets/c','decision':'deny', ...},
  ... ], min_support=3)
  >>> recs[0].proposed_rule.pattern, recs[0].proposed_rule.arn_scope
  ('s3:GetObject', 'arn:aws:s3:::*')
  ```
  The 3 previously-denied `secrets/*` reads are now covered by the recommended `s3:GetObject [arn:aws:s3:::*]` rule. Apply it and the agent's next read of `arn:aws:s3:::secrets/credentials.txt` is ALLOWED in ENFORCE mode.

  Conceptually: the recommend-then-enforce loop's whole premise is "observe the agent's traffic, codify what's actually safe as rules, then switch to ENFORCE." The bouncer's deny decisions IS the explicit signal of "this traffic should NOT be ALLOW-listed." The recommender ignores that signal.

  The prompt-decision case is similar but less sharp: a prompt that the human REJECTED is recorded as `decision='prompt'` (not separately as deny). So you can't tell from the audit log whether a prompt was answered yes or no without looking at downstream decisions. Either way, treating prompts as "this is allowed traffic" is wrong; the prompt's existence means the bouncer wasn't sure.

  Per [[scorer-is-ground-truth]] + [[safety-mode-lean-permissive]]: the recommender is a tool to convert observed-safe traffic into rules. It must not convert observed-blocked traffic into permission to bypass the block.

- Why CRIT (not HIGH): inverts the security premise of the entire recommend-then-enforce workflow. A user who ran the recommender after a few days of agent activity could ship a ruleset that explicitly ALLOWS the operations the bouncer was correctly blocking. Lens-A signal to the user: zero (the proposed rule is listed identically to legitimately-observed-allowed rules, with no annotation that 100% of the support was deny). Same severity rationale as WB22 CRIT-22-01 (a feature that ships the OPPOSITE of its stated invariant).

  Mitigating context: the recommendation is review-first by default (`--apply` is opt-in), so a careful operator reading every recommendation could spot "wait, this is iam:CreateRole, should I ALLOW that?" — but the curated `research_note` for `iam:CreateRole` says "HIGH RISK — principal-pivot vector. Should be denied in most workflows" which DOES warn. Discoverability mitigates SOME risk; the structural shape is still wrong.

- Fix shape:
  ```python
  # recommender.py — filter at the grouping layer
  for d in decisions:
      service = d.get("service")
      action = d.get("action")
      decision = d.get("decision")
      if not service or not action:
          continue
      if decision != "allow":  # NEW — only learn from observed-safe traffic
          continue
      groups[(service.lower(), action)].append(d)
  ```
  Plus a summary field on the recommendation indicating how many calls in the window were _excluded_ as deny/prompt, so the agent reviewing knows the recommender is being conservative.

  Test:
  ```python
  def test_synthesize_excludes_deny_decisions():
      """CRIT-28-01 regression: denied calls must not become ALLOW recommendations."""
      decisions = [_decision(service='iam', action='CreateRole', decision='deny') for _ in range(5)]
      recs = synthesize_rules(decisions, min_support=3)
      assert recs == [], f"deny-only group produced rule: {recs}"

  def test_synthesize_mixed_only_counts_allows():
      decisions = (
          [_decision(arn='arn:aws:s3:::ok/x', decision='allow') for _ in range(3)]
          + [_decision(arn='arn:aws:s3:::secrets/y', decision='deny') for _ in range(5)]
      )
      recs = synthesize_rules(decisions, min_support=3)
      # support should be only the 3 allowed; arn_scope should reflect ONLY the allowed path
      assert recs[0].support_count == 3
      assert 'secrets' not in (recs[0].proposed_rule.arn_scope or '')
  ```

## HIGH findings

### HIGH-28-01 — `_detect_arn_prefix` anchor over-trims mid-segment LCPs

- File: `src/iam_jit/bouncer/recommender.py:294-310`.

- Issue: When the longest-common-prefix ends mid-segment (e.g. inside a bucket name with no further delimiter), the anchor loop at `:301-307` backs up to the previous delimiter:
  ```python
  prefix = full_lcp
  # Anchor on a sensible boundary
  for delim in ["/", ":"]:
      if delim in prefix:
          idx = prefix.rfind(delim)
          if idx > len("arn:aws:") - 1:
              prefix = prefix[: idx + 1]
              break
  ```

  The intent is sound: "don't propose a half-bucket-name like `reports-2026-q*`." But the implementation collapses to the FIRST delimiter found in `["/", ":"]` order. When the LCP is `arn:aws:s3:::reports-2026-q`, there's no `/` in it (bucket-name segment has no path separator), so the loop falls to `:`. The last `:` is at position 13 (in `arn:aws:s3::`), and the anchor backs up to `arn:aws:s3:::` — the service-root prefix. The resulting glob is `arn:aws:s3:::*` — every S3 bucket in the account.

  Verified via direct repro:
  ```python
  >>> arns = ['arn:aws:s3:::reports-2026-q1/a',
  ...         'arn:aws:s3:::reports-2026-q2/b',
  ...         'arn:aws:s3:::reports-2026-q3/c']
  >>> _detect_arn_prefix(arns)
  ('arn:aws:s3:::*', '3 of 3 observed ARNs share the prefix \'arn:aws:s3:::\' (100%)')
  ```

  The recommender goes from "I observed traffic to 3 buckets all starting with `reports-2026-q`" → "I propose a rule allowing ALL S3 buckets." Massive over-broadening.

  The shape that DOES work — when the LCP ends at a `/`:
  ```python
  >>> arns = ['arn:aws:s3:::reports-2026/q1/summary.csv',
  ...         'arn:aws:s3:::reports-2026/q2/summary.csv', ...]
  # LCP = 'arn:aws:s3:::reports-2026/q...' — has `/` after bucket name → anchors correctly
  ('arn:aws:s3:::reports-2026/*', ...)
  ```

  So if the observed traffic happens to use path-separator boundaries, the algorithm works; if it doesn't, the algorithm fails catastrophically.

- Why HIGH (not CRIT): not a security inversion (the rule still says ALLOW for what was originally ALLOW). But the rule's _scope_ is wildly broader than the observed traffic justifies. An admin reviewing the recommendation sees `arn:aws:s3:::*` and might apply it not realizing it's actually `reports-2026-q1/2/3` traffic. In ENFORCE mode, ALL S3 buckets become accessible — including `arn:aws:s3:::secrets-bucket/credentials.txt`. The `_detect_arn_prefix` rationale string ("100% of ARNs share the prefix `arn:aws:s3:::`") makes the over-broadening visible IF the admin reads it carefully.

- Fix shape:
  ```python
  # recommender.py — also anchor to the last `-` or `_` within the
  # bucket-name segment when no `/` is present. Or: stop trimming when
  # the LCP is already past `arn:aws:service:::` (already at a usable
  # boundary) and only anchor BACK to `/` if doing so doesn't fall
  # below the resource-name start.
  prefix = full_lcp
  resource_start = prefix.find(":::")  # for s3-shape ARNs
  if resource_start < 0:
      resource_start = prefix.rfind(":")  # generic fallback
  if resource_start >= 0:
      resource_start += len(":::") if "s3:::" in prefix else 1
  # Anchor only DOWN to resource_start; never below
  for delim in ["/", "-", "_", ":"]:
      if delim in prefix[resource_start:]:
          idx = prefix.rfind(delim)
          if idx > resource_start:
              prefix = prefix[: idx + 1]
              break
  ```
  Or simpler: emit the full LCP as-is when it's already past the service-root, even if it ends mid-segment — the resulting glob `arn:aws:s3:::reports-2026-q*` is conservative-broad (matches `reports-2026-q*` not just `reports-2026-q1/2/3`) but still narrower than `arn:aws:s3:::*`. The user can tighten in review.

  Test:
  ```python
  def test_detect_arn_prefix_does_not_over_trim_mid_segment():
      """HIGH-28-01 regression: LCP ending mid-segment must not anchor
      back to the service root."""
      arns = [
          'arn:aws:s3:::reports-2026-q1/a',
          'arn:aws:s3:::reports-2026-q2/b',
          'arn:aws:s3:::reports-2026-q3/c',
      ]
      glob, _ = _detect_arn_prefix(arns)
      assert glob != 'arn:aws:s3:::*', f"over-broadened: {glob}"
      assert 'reports-2026' in (glob or ''), f"lost bucket-name discrimination: {glob}"
  ```

### HIGH-28-02 — MCP `bouncer_apply_recommendation` crashes on non-string `arn_scope`/`region_scope`/`note`; silently accepts numeric

- File: `src/iam_jit/mcp_server.py:2102-2160` (`_bouncer_apply_recommendation_for_mcp`).

- Issue: The handler validates `pattern` (isinstance str + non-empty) and `effect` (∈ {allow, deny}). But `arn_scope`, `region_scope`, and `note` are passed through to `ProxyRule(...)` without type checking:
  ```python
  rule = ProxyRule(
      pattern=pattern,
      effect=Effect(effect_str),
      arn_scope=entry.get("arn_scope"),
      region_scope=entry.get("region_scope"),
      note=entry.get("note") or "applied from bouncer recommendation",
      origin="recommendation",
  )
  ```
  `ProxyRule` is a `@dataclass(frozen=True)` — no validators. `store.add_rule` then calls SQLite with these values as bind params; SQLite only accepts str/int/float/bytes/None.

  Verified via direct repro:
  ```python
  >>> _bouncer_apply_recommendation_for_mcp({
  ...     'rules': [{'pattern': 's3:GetObject', 'arn_scope': {'nested': 'object'}}]
  ... })
  sqlite3.ProgrammingError: Error binding parameter 3: type 'dict' is not supported
  ```
  Same crash for `note` (dict / list) and `region_scope` (dict). The exception is uncaught — the MCP wrapper's try/except (`except InvalidRuleError as e:`) doesn't catch `ProgrammingError`. The wrapper crashes mid-batch; rules added before the bad entry are committed (no transaction wraps the loop); the `recommendation_applied` audit event is NEVER written (the `_record_config_event_locked` call comes AFTER the loop).

  Numeric values are silently accepted:
  ```python
  >>> _bouncer_apply_recommendation_for_mcp({
  ...     'rules': [{'pattern': 's3:GetObject', 'arn_scope': 12345}]
  ... })
  {'applied': 1, 'rejected': [], 'audit_event_kind': 'recommendation_applied'}
  ```
  But the stored rule has `arn_scope=12345`. Later `rule_matches` calls `_aws_glob_match(arn, '12345')` which compiles `\A12345\Z` regex — never matches a real ARN. The rule silently never fires.

  The MCP `inputSchema` declares all three as `"type": "string"` but the handler doesn't enforce. JSON-RPC implementations don't validate against `inputSchema` (Anthropic's MCP transport in particular does not). Schema documents intent; the handler is the actual gate.

- Why HIGH (not CRIT): no security boundary crossed (the crash terminates the request before any wrong data lands at the AWS layer). But the partial-batch-then-crash shape means: (a) rules added before the bad entry are committed without the batch-level audit event; (b) the agent retrying with the bad entry removed re-adds the first N rules — duplicates per MED-28-02. The numeric-silent-accept shape ships a never-matching rule that looks valid in `list_rules`. Same shape as WB25 HIGH-25-01 (handler that trusts MCP schema for validation).

- Fix shape:
  ```python
  # mcp_server.py
  for entry in rules_arg:
      if not isinstance(entry, dict):
          rejected.append({"entry": entry, "error": "not a dict"}); continue
      pattern = entry.get("pattern")
      if not isinstance(pattern, str) or not pattern.strip():
          rejected.append({"entry": entry, "error": "pattern required"}); continue
      effect_str = entry.get("effect", "allow")
      if effect_str not in ("allow", "deny"):
          rejected.append({"entry": entry, "error": "effect must be allow|deny"}); continue
      # NEW: enforce string-or-None for the pass-through fields
      bad_type = None
      for field in ("arn_scope", "region_scope", "note"):
          val = entry.get(field)
          if val is not None and not isinstance(val, str):
              bad_type = f"{field} must be string or null"
              break
      if bad_type:
          rejected.append({"entry": entry, "error": bad_type}); continue
      # ... build ProxyRule + add_rule
  ```
  Plus an outer try/except around `store.add_rule` catching `sqlite3.ProgrammingError` defensively (so a future field that bypasses validation doesn't crash the batch).

  Test:
  ```python
  @pytest.mark.parametrize("field", ["arn_scope", "region_scope", "note"])
  @pytest.mark.parametrize("bad_value", [{"nested": "dict"}, ["list"], 12345, True])
  def test_mcp_apply_rejects_non_string_passthrough(field, bad_value):
      """HIGH-28-02 regression: arn_scope/region_scope/note must be string or null."""
      out = _bouncer_apply_recommendation_for_mcp({
          "rules": [{"pattern": "s3:GetObject", field: bad_value}],
      })
      assert out["applied"] == 0
      assert len(out["rejected"]) == 1
      assert field in out["rejected"][0]["error"]
  ```

## MED findings

### MED-28-01 — ARN/region scope inferred from subset; rule blocks majority of historical traffic

- File: `src/iam_jit/bouncer/recommender.py:413-431`.

- Issue: `synthesize_rules` calls `_detect_arn_prefix(arns)` where `arns = [d.get("arn") for d in group_decisions]`. `_detect_arn_prefix` filters out `None` values (`real_arns = [a for a in arns if a]`) and only returns a prefix if `len(real_arns) >= 2`. So if 10 calls had `arn=None` and 2 had ARNs, the function returns a prefix based on those 2 — and the rule construction at `:424-431` uses that prefix unconditionally.

  Verified via direct repro:
  ```python
  >>> # 8 calls with arn=None + 2 calls with arn=arn:aws:s3:::secret-bucket/*
  >>> recs = synthesize_rules(decisions, min_support=3)
  >>> recs[0].support_count
  10
  >>> recs[0].proposed_rule.arn_scope
  'arn:aws:s3:::secret-bucket/*'
  >>> recs[0].arn_pattern_rationale
  "2 of 2 observed ARNs share the prefix 'arn:aws:s3:::secret-bucket/' (100%)"
  ```

  Per `rule_matches` at `bouncer/rules.py:163-170`:
  ```python
  if rule.arn_scope and rule.arn_scope != "*":
      if arn is None:
          # Rule scopes by ARN but request has no resolvable ARN —
          # be conservative: don't match.
          return False
  ```
  So in ENFORCE mode, the 8 None-ARN calls that previously matched (no scope) now DON'T match the new scoped rule, fall through to default-deny, and get blocked. The rule the user just shipped to "codify observed safe traffic" silently breaks 80% of the historical traffic it was meant to authorize.

  Same shape applies to region: 8 region=None + 2 region=us-east-1 → rule scoped to `us-east-1` → 8 None-region calls fail.

- Why MED (not HIGH): not a silent privilege escalation (the failure is denial, not over-broadening); the user notices when agent calls start failing in ENFORCE. But it's an availability bug that frustrates the recommend-then-enforce flow exactly when the user is trying to commit to ENFORCE — bad UX timing.

- Fix shape: require `non_none_count >= ARN_INFER_MIN_FRACTION * support_count` (e.g. 0.5) before applying any ARN scope. If too few records have ARN data, ship the rule scope-less and surface a rationale "8 of 10 calls had no resolvable ARN; not narrowing by ARN scope." Same fraction-of-support gate for region.

### MED-28-02 — CLI + MCP apply paths do not dedupe against existing rules

- Files:
  - `src/iam_jit/bouncer_cli.py:878-899` (`_apply_recommendations_via_cli`)
  - `src/iam_jit/mcp_server.py:2120-2160` (`_bouncer_apply_recommendation_for_mcp`)

- Issue: Both apply paths iterate recommendations and call `store.add_rule(r.proposed_rule, ...)` unconditionally. `add_rule` doesn't check for existing rows with the same `(pattern, effect, arn_scope, region_scope)`. So running `recommend --apply` twice — or running it after manually adding the same rule — produces duplicate rows.

  Verified via direct repro:
  ```python
  >>> _bouncer_apply_recommendation_for_mcp({'rules': [{'pattern': 's3:GetObject'}]})
  {'applied': 1, ...}
  >>> _bouncer_apply_recommendation_for_mcp({'rules': [{'pattern': 's3:GetObject'}]})  # same input
  {'applied': 1, ...}
  >>> store.list_rules()
  [(1, ProxyRule(pattern='s3:GetObject', ..., origin='recommendation')),
   (2, ProxyRule(pattern='s3:GetObject', ..., origin='recommendation'))]
  ```
  Two identical rows. `RuleSet.evaluate` is first-match-wins, so correctness isn't broken — both will match — but `list_rules` accumulates noise + the audit log gets two `rule_added` events for what semantically is the same rule.

  Concrete scenario: user runs LEARN for a week, applies recommendation. Two weeks later they run LEARN for another week and apply the new recommendation. Most traffic was the same; most recommendations are duplicates of existing rules. After 6 months of weekly applies, `list_rules` is 80% duplicate noise.

- Why MED (not LOW): the long-term rule-list growth is real; users will see this within weeks. Cheap fix.

- Fix shape:
  ```python
  # store.py
  def rule_exists(self, rule: ProxyRule) -> bool:
      """True iff an identical (pattern, effect, arn_scope, region_scope) row already exists."""
      with self._lock:
          cur = self._conn.execute(
              "SELECT 1 FROM rules WHERE pattern=? AND effect=? AND "
              "(arn_scope IS ? OR arn_scope = ?) AND (region_scope IS ? OR region_scope = ?)",
              (rule.pattern, rule.effect.value,
               rule.arn_scope, rule.arn_scope,
               rule.region_scope, rule.region_scope),
          )
          return cur.fetchone() is not None
  ```
  Then in both apply paths, skip with a rejected-as-duplicate annotation:
  ```python
  if store.rule_exists(rule):
      rejected.append({"entry": entry, "error": "rule already exists"})
      continue
  ```

### MED-28-03 — `recommendation_applied` event detail records only `{count: N}`

- Files:
  - `src/iam_jit/bouncer_cli.py:893-898`
  - `src/iam_jit/mcp_server.py:2147-2153`

- Issue: Both apply paths write a config event after the batch:
  ```python
  store._record_config_event_locked(
      actor=actor,
      kind="recommendation_applied",
      summary=f"applied {added} recommended rule(s)",
      detail={"count": added},
  )
  ```
  The `detail` is `{count: N}`. The CLI variant doesn't even record `rejected_count` (MCP does). Neither records which rule IDs were added in the batch — just an integer.

  Post-incident review can't answer "what specific rules did the recommendation batch on 2026-05-17 add?" The reviewer would have to:
  1. Find the `recommendation_applied` event timestamp.
  2. Find all `rule_added` events from the same actor within a few seconds.
  3. Hope no manually-added rules interleaved.

  Slice D's docs (`docs/IAM-JIT-BOUNCER.md:386-389`) explicitly say: "writes a `recommendation_applied` config event to the audit chain so post-hoc review can spot which batch each rule came from." That promise is half-met: the event exists, but the linkage between batch and rule IDs is lost.

- Why MED (not LOW): named promise in docs that isn't kept. Same shape as WB22 MED-22-04 (audit event captures shape but not specifics).

- Fix shape:
  ```python
  # Both paths — collect rule_ids as add_rule returns them
  added_rule_ids = []
  for r in recs:
      try:
          rid = store.add_rule(r.proposed_rule, actor=actor)
          added_rule_ids.append(rid)
      except InvalidRuleError as e:
          ...
  store._record_config_event_locked(
      ...,
      detail={
          "count": len(added_rule_ids),
          "rule_ids": added_rule_ids,
          "rejected_count": len(rejected),
          "rejected": rejected,  # optional — verbose but useful
      },
  )
  ```

### MED-28-04 — CLI accepts `--limit 0/-N` and `--min-support 0` without validation

- File: `src/iam_jit/bouncer_cli.py:786-803`.

- Issue: The CLI declares `--limit` and `--min-support` as `type=int` but no `minimum`. `--limit 0`, `--limit -5`, `--min-support 0` are accepted at the click layer, propagated to `list_decisions(limit=0)` which clamps to 1, and `synthesize_rules(min_support=0)` which never skips anything (every group with ≥1 decision passes the gate).

  Verified via direct repro:
  ```
  $ iam-jit-bouncer recommend --limit 0
  # 0 total calls (allow=0 deny=0 prompt=0)
  (no recommendations — ...)
  $ iam-jit-bouncer recommend --min-support 0
  # 0 total calls ...
  ```
  No error. `min_support=0` is semantically different — it would generate rules from ANY observed call, including singletons (every one-off call becomes a permanent rule). Currently masked because the test DBs are empty; in a populated DB the recommender would produce thousands of recommendations.

  MCP enforces both correctly:
  ```python
  >>> _bouncer_recommend_rules_for_mcp({'min_support': 0})
  {'error': 'min_support must be a positive integer'}
  >>> _bouncer_recommend_rules_for_mcp({'limit': 0})
  {'error': 'limit must be a positive integer'}
  ```
  CLI surface is asymmetric. Same anti-pattern as WB27 LOW-27-02 (CLI `--owner ''` silently accepted).

- Why MED (not LOW): CLI/MCP parity gap. The CLI is the canonical local-only-safety-mode interface; bad input slipping through silently breaks expectations.

- Fix shape:
  ```python
  # bouncer_cli.py
  @click.option("--min-support", type=click.IntRange(min=1), default=3, show_default=True, ...)
  @click.option("--limit", type=click.IntRange(min=1, max=10000), default=10000, ...)
  ```

### MED-28-05 — Recommender ingests task-scoped decisions; one-off task traffic becomes permanent rule

- File: `src/iam_jit/bouncer/recommender.py:391-444`.

- Issue: `synthesize_rules` ingests every decision in the input list — including those made under a per-task scope (`decision["task_id"] != None`). Per WB27, task scopes are explicitly "one-off declared sessions" with a 24-hour cap; the rules an agent declared for a single CI run are NOT meant to become persistent global rules.

  Verified via direct repro:
  ```python
  >>> # 3 task-scoped allowed calls — all under task_id='one-off-task-abc'
  >>> decisions = [{'service': 's3', 'action': 'GetObject', 'task_id': 'one-off-task-abc', 'decision': 'allow', ...}] * 3
  >>> recs = synthesize_rules(decisions, min_support=3)
  >>> recs[0].proposed_rule.pattern, recs[0].support_count
  ('s3:GetObject', 3)  # → permanent ALLOW rule recommendation
  ```

  The Slice C task-scope feature exists BECAUSE certain traffic shouldn't become permanent (e.g. an admin doing a one-off bucket migration declares a task with `allow_rules=['s3:*']`, runs the migration, ends the task). The recommender then proposes to make `s3:*` a permanent rule. The Slice C invariant is undone.

- Why MED (not HIGH): not a security inversion per se, but the recommender's input set should respect the Slice C "this is one-off" signal. The two slices were authored independently; the recommender wasn't updated to know about task scopes.

- Fix shape: filter task-scoped decisions out by default; expose `--include-task-scoped` flag for the rare case where the user wants both. Or carry `task_id` forward into the recommendation as a signal "this was task-scoped traffic; verify before applying."
  ```python
  for d in decisions:
      ...
      if d.get("task_id"):  # NEW — skip task-scoped one-off traffic
          continue
      groups[(service.lower(), action)].append(d)
  ```

### MED-28-06 — CLI `--apply` is bulk-only; no `--dry-run` opposite or per-rule confirmation

- File: `src/iam_jit/bouncer_cli.py:790-833`.

- Issue: The CLI `recommend` defaults to review (good), and `--apply` adds ALL recommendations as new rules in one shot. There's no per-rule confirmation, no `--dry-run` flag to show what `--apply` would do without doing it, no `--accept-only-known-actions` subset flag.

  Per [[agent-friendly-not-bypassable]] Lens A: agents review + decide. The MCP variant exposes this correctly (`bouncer_apply_recommendation` takes a `rules` array — the agent cherry-picks). The CLI is bulk-only.

  Concrete scenario: admin runs `recommend` and sees 12 recommendations. 10 look fine. 2 are over-broad. The admin wants to apply the 10 and skip the 2. The CLI doesn't support this — they'd have to either (a) `--apply` all and then `rules remove` the 2, or (b) skip `--apply` and add the 10 manually via `rules add`.

- Why MED (not LOW): UX friction at the exact moment the user is committing to ENFORCE — high-stakes timing.

- Fix shape: add `--dry-run` flag (default) vs `--apply` (one shot, bulk) vs `--interactive` (per-rule yes/no prompt). Or simpler: accept `--apply-only PATTERN[,PATTERN,...]` flag that filters which recommendations to apply.

## LOW findings

### LOW-28-01 — ARN/region rationale strings count only non-None records; misleading vs support_count

- File: `src/iam_jit/bouncer/recommender.py:307-310, 336-340, 356-359`.

- Issue: The rationale text reports counts in non-None-record terms ("2 of 2 observed ARNs"), but the support_count is the full group size ("support: 10 calls"). Reader cross-referencing the two thinks "100% of the 10 supported the pattern" when actually only 2 of 10 had observable ARN data.

  Example output:
  ```
  ALLOW s3:GetObject [arn=arn:aws:s3:::secret-bucket/*]
    support: 10 calls (12.5% of window)
    arn:    2 of 2 observed ARNs share the prefix 'arn:aws:s3:::secret-bucket/' (100%)
  ```
  The "2 of 2" hides that 8 of the 10 calls had `arn=None`.

- Why LOW: cosmetic; doesn't break correctness on its own (the MED-28-01 issue is the real bug). But it amplifies MED-28-01 by making the misleading scoping look correct.

- Fix shape: change rationale to `"2 of 10 calls had observable ARN data; of those, 100% share prefix X"`.

### LOW-28-02 — KNOWN_ACTIONS severity markers inconsistent across catalog entries

- File: `src/iam_jit/bouncer/recommender.py:43-212`.

- Issue: 11 of 30 entries embed severity hints in the `typical_use` prose using inconsistent terms:
  - `DESTRUCTIVE` (5×): s3:DeleteObject, ec2:TerminateInstances, iam:DeleteRole, eks:UpdateClusterVersion, rds:DeleteDBInstance, cloudformation:DeleteStack
  - `WRITE` (2×): s3:PutObject, dynamodb:PutItem
  - `SENSITIVE` (1×): secretsmanager:GetSecretValue
  - `EXPENSIVE` (1×): ec2:RunInstances
  - `HIGH RISK` (1×): iam:CreateRole

  Others mention severity in prose without a marker (e.g. `lambda:InvokeFunction`: "broad scope is privilege escalation" — no marker).

  This format prevents structured handling — e.g. UI can't render DESTRUCTIVE actions in red, can't filter "only show high-risk recommendations," can't program-driven sort. The marker should be a separate field (`severity: "destructive" | "write" | "sensitive" | "expensive" | "high_risk" | None`).

- Why LOW: works for human-only review; structural debt for any agent-side or UI consumer.

- Fix shape: add a `severity` field to each entry:
  ```python
  "s3:DeleteObject": {
      "summary": "Delete an object from an S3 bucket.",
      "typical_use": "Cleanup workflows; narrow to specific prefix; avoid wildcard ARN scope.",
      "severity": "destructive",  # NEW
  },
  ```
  Plus a test asserting every entry with destructive-class actions has the severity field set. Plus update the recommendation `to_dict` to surface severity alongside the research note.

### LOW-28-03 — `summarize_window` `total_calls` may exceed `allow + deny + prompt`

- File: `src/iam_jit/bouncer/recommender.py:469-478`.

- Issue: `summarize_window` reports:
  ```python
  return {
      "total_calls": len(decisions),
      ...
      "allow_count": sum(1 for d in decisions if d.get("decision") == "allow"),
      "deny_count": sum(1 for d in decisions if d.get("decision") == "deny"),
      "prompt_count": sum(1 for d in decisions if d.get("decision") == "prompt"),
      ...
  }
  ```
  `total_calls` counts every decision; `allow_count` / `deny_count` / `prompt_count` count only recognized values. So `total ≠ allow + deny + prompt` if any decision has a missing or unrecognized `decision` field. Verified:
  ```
  total=3, allow=1, deny=0, prompt=0  (one decision had no 'decision' key)
  ```

- Why LOW: defensive against bad rows; users will see a mismatch and assume "must be a bug" (it kind of is).

- Fix shape: add `other_count = total - allow - deny - prompt`; show it in the summary when non-zero so the user understands the discrepancy.

### LOW-28-04 — `--since`/`--until` filter is naive lexicographic string compare

- File: `src/iam_jit/bouncer_cli.py:824-828`, `src/iam_jit/mcp_server.py:2095-2099`.

- Issue: Both paths filter via:
  ```python
  decisions = [
      d for d in all_decisions
      if (since is None or (d.get("at") and d["at"] >= since))
      and (until is None or (d.get("at") and d["at"] <= until))
  ]
  ```
  Lexicographic string compare. Works for canonical Z-suffix ISO-8601 (which is what `_isoformat_z` produces). Silently mishandles mixed-timezone input:
  ```
  '2026-05-17T15:00:00+00:00' < '2026-05-17T15:00:00Z'  → True (because '+' = 0x2B < 'Z' = 0x5A)
  '2026-05-17T15:00:00+00:00' == '2026-05-17T15:00:00Z' → False
  ```
  An admin passing `--since 2026-05-17T15:00:00+00:00` (semantically same time as `Z`) gets DIFFERENT results than passing `Z`. The decisions table is all-Z, so the `+00:00` input matches MORE decisions than expected (because all Z-suffix decisions come after `+00:00` lexicographically).

- Why LOW: only bites users who pass non-canonical input. Most users will paste a copy of a `window_start` value from the summary, which is canonical Z.

- Fix shape: parse both sides as `datetime.fromisoformat`, normalize to UTC, compare as datetime objects. Or reject non-Z input at the CLI/MCP layer with a clear message.

### LOW-28-05 — KNOWN_ACTIONS catalog risks staleness

- File: `src/iam_jit/bouncer/recommender.py:43-212`.

- Issue: 30 hand-curated entries. AWS service behavior evolves (new use cases for `s3:PutObject`, new sensitivity considerations for `kms:Decrypt`). No provenance / last-reviewed-at field on entries; no test that asserts the prose still matches AWS docs. The risk: 12 months from now, an entry's `typical_use` text gives outdated advice; agents reading the recommendation make a stale decision.

- Why LOW: forward-looking maintenance debt; no immediate bug.

- Fix shape: add `last_reviewed: "2026-05"` field to every entry. Quarterly hygiene pass to bump dates + re-check prose against AWS docs. Or: switch to a generation-time fetch from AWS service-authorization reference (post-launch; not Slice D scope).

### LOW-28-06 — `_apply_recommendations_via_cli` calls private `store._record_config_event_locked`

- File: `src/iam_jit/bouncer_cli.py:893-898`.

- Issue: The CLI helper calls `store._record_config_event_locked(...)` directly — a method with an underscore prefix indicating "internal use." Same precedent established in WB23 for the allowlist CLI (which also needed to write arbitrary-kind config events without a public method existing). Consistent with prior decisions but still API debt.

- Why LOW: works correctly today; precedent is documented.

- Fix shape: lift `_record_config_event_locked` to a public `record_config_event(...)` method with explicit "this is for batch-event recording from CLI/MCP wrappers" docstring. Or accept the private-method-from-wrapper pattern as Slice D's normal shape and document the precedent in CONTRIBUTING.md.

## Verified clean

The following were probed per the audit prompt and found no issues:

- **`_longest_common_prefix` with duplicates** — `_longest_common_prefix(['abc'] * 5) == 'abc'` (string equality means the inner `while not s.startswith(prefix)` never iterates). No set-semantics issue; duplicate ARNs converge to the dup's full string as LCP, which the anchor then trims correctly. Verified.
- **`_detect_arn_prefix` with single ARN** — returns `(None, None)` per the `len(real_arns) < 2` guard. Verified.
- **`_detect_arn_prefix` with all-None ARNs** — returns `(None, None)` (filter at `:281` produces empty list; guard triggers). Verified.
- **`_detect_arn_prefix` cluster fallback when partition+service is uniform but resource differs widely** — clusters by `arn:partition:service:` prefix; if all ARNs are s3 with diverse resources, all land in one cluster; majority gate (`len(best_group) >= threshold`) requires `n * min_coverage` (default 0.8); if 100% are in the cluster, gate passes. Then `cluster_lcp >= len("arn:aws:s3:::")` check. The s3-without-region ARN format has 5 colons; the cluster key is `arn:aws:s3` (3 fields, 2 colons). IAM ARNs (no region) cluster identically. Worked as expected on direct repro.
- **`_detect_arn_prefix` with malformed ARN (fewer than 3 colons)** — `_service_prefix` returns the whole string; cluster gets one entry; below threshold; falls through to `(None, None)`. No crash. Verified.
- **`synthesize_rules` with empty decisions** — returns `[]`. Verified by `test_synthesize_empty_returns_empty`.
- **`synthesize_rules` with all-below-min-support groups** — returns `[]`. Verified by `test_synthesize_skips_low_support_groups`.
- **`synthesize_rules` ignores decisions with empty service/action** — verified by `test_synthesize_ignores_decisions_missing_service_or_action`.
- **`summarize_window` with all-None `at` values** — returns `window_start=None, window_end=None` via `default=None` on min/max. Verified.
- **`research_note` for unknown action** — returns `None`. Verified by `test_research_note_unknown_action_returns_none`.
- **MCP `bouncer_recommend_rules` empty DB** — returns `count=0, summary.total_calls=0`. Verified by `test_mcp_recommend_rules_empty`.
- **MCP `bouncer_recommend_rules` input validation** — `min_support=0/True/"many"` correctly rejected. Verified by `test_mcp_recommend_rules_min_support_validation`.
- **MCP `bouncer_apply_recommendation` empty rules array** — returns `{"error": "rules is required and must be a non-empty list"}`. Verified by `test_mcp_apply_recommendation_empty_rules`.
- **MCP `bouncer_apply_recommendation` partial failure** — valid rules apply, invalid ones land in `rejected[]`. Verified by `test_mcp_apply_recommendation_partial_failure`.
- **MCP both tools discoverable via `tools/list`** — verified by `test_mcp_both_tools_in_tools_list` (subset assertion; would still benefit from exact-set per WB27 MED-27-05).
- **Both tools dispatched via `_handle_request`** — verified at `mcp_server.py:2772-2776`.
- **Decision case-sensitivity** — `service.lower()` correctly unifies `S3` vs `s3` in grouping; action is case-sensitive (matches AWS docs). Verified by direct repro.
- **CLI `recommend` exit code on empty DB** — exits 0, prints "no recommendations". Verified by `test_cli_recommend_empty_db`.
- **CLI `--json` output is valid JSON** — `json.loads(result.output)` succeeds. Verified by `test_cli_recommend_json_output`.
- **CLI `--apply` writes the rule + audit event** — verified by `test_cli_recommend_apply_adds_rules` + audit-event inspection.
- **`RuleRecommendation.to_dict` round-trip** — verified by `test_recommendation_to_dict_round_trip`.
- **KNOWN_ACTIONS catalog completeness** — verified by `test_known_actions_covers_critical_set` (must include s3 read/write/delete, sts:Assume, iam:Create/Delete/Pass, secretsmanager:Get, kms:Decrypt, dynamodb:Get).
- **Total bouncer MCP tools** — 15 (was 13 in WB27; +2 from Slice D: `bouncer_recommend_rules`, `bouncer_apply_recommendation`). All dispatch correctly.
- **No regression in pre-Slice-D tests** — 2526 pass, +40 from Slice D.

## Regression check

Command run: `cd /Users/reagan/repos/iam-roles && .venv/bin/python -m pytest --no-header -q --ignore=tests/test_calibration_corpus.py --ignore=tests/e2e 2>&1 | tail -5`

Result:
```
2526 passed, 29 skipped, 14 deselected, 2 warnings in 90.36s (0:01:30)
```

Matches the commit's stated baseline (2526) exactly. All 40 new Slice-D tests pass. No regressions in any of the 2486 pre-Slice-D tests.

## Summary

**1 CRIT, 2 HIGH, 6 MED, 6 LOW.** Slice D adds an observation-based rule recommender that synthesizes a draft ruleset from observed LEARN-mode decisions. The data-shape APIs (synthesize_rules, summarize_window, research_note, KNOWN_ACTIONS catalog) work as designed; LCP detection works for the happy path. The bug concentration is in: (a) recommender semantics (the CRIT — denied decisions become ALLOW recommendations); (b) pattern detection algorithms (HIGH-28-01 over-broadens mid-segment LCPs; MED-28-01 over-narrows from sparse ARN/region data); (c) MCP input validation (HIGH-28-02 — dict/list pass-through crashes the handler); (d) CLI/MCP parity drift (MED-28-04 — CLI accepts invalid limits MCP rejects; MED-28-06 — CLI lacks per-rule cherry-pick).

The most impactful are:

- **CRIT-28-01** (`synthesize_rules` doesn't filter by decision at `recommender.py:395-401`): denied calls become ALLOW recommendations. 3 denied `iam:CreateRole` attempts → "ALLOW iam:CreateRole" recommendation. 2 allowed + 3 denied mixed S3 reads → single ALLOW rule covering both prefixes, ALLOWing the previously-denied paths. Inverts the recommend-then-enforce security premise. Fix: filter `if d.get("decision") != "allow": continue` at the grouping step. 5-min fix + regression tests.

- **HIGH-28-01** (`_detect_arn_prefix` anchor over-trims at `recommender.py:301-307`): when the LCP ends mid-segment (e.g. inside a bucket name with no further `/`), the anchor loop backs up to the service root, proposing `arn:aws:s3:::*` (all S3) for ARNs that actually share `reports-2026-q*`. Massive over-broadening hidden behind a "100% of ARNs share this prefix" rationale string. Fix: anchor to last `/`-or-`-`-or-`_` within the resource segment; never below the resource-name start. 15-min fix + regression test.

- **HIGH-28-02** (`bouncer_apply_recommendation` crashes on non-string `arn_scope`/`region_scope`/`note` at `mcp_server.py:2102-2160`): `{"arn_scope": {"nested": "object"}}` raises uncaught `sqlite3.ProgrammingError`; `{"arn_scope": 12345}` silently stored as int(12345), creating a never-matching rule. Crash terminates the batch mid-loop; rules before the bad entry are committed but the batch audit event never fires. Fix: explicit isinstance() validation for all three pass-through fields. 15-min fix + parametrized test.

The 6 MEDs cluster around three themes:

Recommender correctness:
- **MED-28-01** (ARN/region scope inferred from subset of records-with-data; rule then blocks majority in ENFORCE).
- **MED-28-02** (apply paths don't dedupe; long-term rule list accumulates duplicates).
- **MED-28-05** (task-scoped decisions ingested; one-off task traffic becomes permanent rule).

Audit-chain completeness:
- **MED-28-03** (`recommendation_applied` event records `{count: N}` only; can't reconstruct which rules came from which batch).

CLI/MCP parity:
- **MED-28-04** (CLI accepts `--limit 0/-N` and `--min-support 0`; MCP rejects same).
- **MED-28-06** (CLI `--apply` is bulk-only; MCP exposes per-rule cherry-pick; CLI doesn't).

The 6 LOWs are: misleading rationale strings (LOW-28-01); catalog severity-marker inconsistency (LOW-28-02); summary-counter total-vs-breakdown discrepancy (LOW-28-03); naive lexicographic time-window compare (LOW-28-04); KNOWN_ACTIONS staleness risk (LOW-28-05); private-method call from CLI helper (LOW-28-06).

Recommended closure-commit fix sequence:

1. **CRIT-28-01**: filter `synthesize_rules` to only ingest `decision == "allow"`; add `excluded_count` to `summarize_window`; regression test for deny-only + mixed groups. ~15 min.
2. **HIGH-28-01**: fix `_detect_arn_prefix` anchor to respect resource-segment start; add `reports-2026-q[1-3]` regression test. ~20 min.
3. **HIGH-28-02**: add isinstance() validation for `arn_scope`/`region_scope`/`note` in `_bouncer_apply_recommendation_for_mcp`; parametrize test across all three fields and four bad-type values. ~15 min.
4. **MED-28-01**: require fraction-of-support gate before applying ARN/region scope (e.g. `non_none_count >= 0.5 * support_count`). ~15 min.
5. **MED-28-05**: filter task-scoped decisions out of the recommender input by default. ~10 min.
6. **MED-28-02**: add `store.rule_exists(rule)` helper; both apply paths skip duplicates with `{error: "rule already exists"}`. ~15 min.
7. **MED-28-03**: collect rule_ids during the apply loop; include in `recommendation_applied` event detail. ~10 min.
8. **MED-28-04**: switch CLI `--limit` and `--min-support` to `click.IntRange(min=1, max=...)`. ~5 min.
9. **MED-28-06**: add CLI `--apply-only PATTERN[,PATTERN,...]` or `--dry-run` opposite. ~15 min.
10. **LOW-28-01**: rewrite ARN/region rationale text to surface non-None-vs-total counts ("2 of 10 calls had observable ARN data; of those, 100% share prefix X"). ~5 min.
11. **LOW-28-02**: add `severity` structured field to KNOWN_ACTIONS entries; surface in `to_dict`. ~20 min.
12. **LOW-28-03**: add `other_count` to `summarize_window` output. ~5 min.
13. **LOW-28-04**: parse `--since`/`--until` as datetimes; normalize to UTC for compare. ~10 min.
14. **LOW-28-05**: add `last_reviewed` field to KNOWN_ACTIONS entries (set all to "2026-05" now). ~10 min.
15. **LOW-28-06**: promote `_record_config_event_locked` to a public `record_config_event` method OR document the precedent in CONTRIBUTING.md. ~5 min.

After fixes ship, re-run audit (Round 29) — recommended scope: re-probe CRIT-28-01 (allow-only filter) + HIGH-28-01 (ARN anchor) + HIGH-28-02 (non-string field rejection) under real LEARN-mode traffic shapes.

The Slice D synthesis layer has solid bones — grouping, prefix detection, region detection, research-note attachment all compose cleanly. The 15 findings concentrate at: the omission of the `decision` field as a filter (the CRIT — a semantic, not algorithmic, gap); the anchor-trimming heuristic that's too aggressive when traffic doesn't conveniently end at `/`; and the MCP input validator that trusts schema instead of enforcing at runtime. Same lesson WB23-WB27 keep teaching: foundation algorithms tend to be correct; the bugs cluster at the integration boundaries (validator gaps, semantic field omissions, CLI/MCP parity drift, audit-chain shape contracts).

Audit ROI continues: 1 CRIT (the recommender's whole purpose was structurally inverted in a way that all 40 unit tests miss because none seed deny decisions and check the recommendation's effect field), 2 HIGHs (algorithm over-broadening + validator-bypass crash), 6 MEDs catching parity drift + audit-chain promise gaps. Per [[audit-cadence-discipline]] the BB+WB pattern continues to surface the cross-layer integration bugs the within-feature test suite doesn't catch. The CRIT in particular is the kind of finding that justifies the audit cadence — it ships in code with passing unit tests and a passing integration test, because no test imagined "what if the recommender's input contains denied decisions."
