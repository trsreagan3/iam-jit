# Round 23 audit — iam-jit-bouncer foundation (#160 Stage 1)

Commit under review: `3befe63` (`feat(bouncer): #160 Stage 1 foundation — rules, decisions, SQLite store, CLI`).

Scope: `src/iam_jit/bouncer/__init__.py` (42 LOC) + `src/iam_jit/bouncer/rules.py` (185 LOC) + `src/iam_jit/bouncer/decisions.py` (176 LOC) + `src/iam_jit/bouncer/store.py` (278 LOC) + `src/iam_jit/bouncer/request_parser.py` (420 LOC) + `src/iam_jit/bouncer_cli.py` (312 LOC) + `tests/bouncer/*` (six test files, 1305 LOC) + `pyproject.toml` (one-line script entry) + `docs/IAM-JIT-BOUNCER.md` (201 LOC). Read-only audit. Per [[audit-cadence-discipline]].

Regression: **2208 passed, 29 skipped, 14 deselected** (88.4s, excluding `tests/e2e/*` which needs `playwright`, and `tests/test_calibration_corpus.py` which has the well-known pre-existing failures). Matches the audit-prompt baseline exactly.

## Headline

12 findings: **1 CRIT, 2 HIGH, 4 MED, 5 LOW.**

The single most-important finding is **CRIT-23-01**: the S3 virtual-hosted-style host parser at `request_parser.py:369-373` extracts the bucket name by splitting the host on the FIRST occurrence of `.s3` — but `.s3` can legitimately appear inside an S3 bucket name (DNS-safe bucket names may contain dots and the literal substring `.s3` is permitted, e.g. `my.s3.bucket-name` is a valid bucket name). For a request to virtual-hosted host `my.s3.bucket-name.s3.us-east-1.amazonaws.com/key`, the parser extracts bucket=`my` and ARN=`arn:aws:s3:::my/key` — completely wrong bucket. A user's allow rule `arn:aws:s3:::my-data/*` would not protect against access to a separate bucket `my.s3.attacker-controlled`, and an attacker who controls (or convinces a user to use) such a bucket bypasses ARN-scoped rules entirely. The decision audit log will record the call as targeting the WRONG bucket, masking the actual destination in incident review.

The two HIGH findings: **HIGH-23-01** — the S3 sub-resource table omits `tagging`, `cors`, `notification`, `logging`, `requestpayment`, `website`, and `replication`, all of which are real S3 sub-resources mapping to distinct IAM actions (`s3:PutBucketTagging` etc.); a `PUT /bucket?tagging` is misclassified as `CreateBucket`, completely bypassing any deny rule on `s3:PutBucketTagging`/`s3:PutBucketWebsite`/`s3:DeleteBucketCors`/etc. **HIGH-23-02** — the `decide --record` CLI path persists every decision with `matched_rule_id=NULL` even when a rule explicitly matched, because `bouncer_cli.py:259` calls `store.record_decision(record_obj)` without forwarding the matched rule's id (the store API accepts `matched_rule_id` as a separate kwarg but neither the CLI nor any caller in this commit populates it). The audit log is structurally broken from day one: every entry shows "unmatched" even for `explicit-allow` / `explicit-deny` decisions.

The 4 MEDs are: malformed `effect` strings in the SQLite store crash `list_rules()` instead of skipping the bad row; `rules add` accepts malformed patterns (e.g. `not-a-valid-pattern` with no colon) without rejection, and `rule_matches` then silently returns False for every request, so the rule is invisible but counts toward the user's mental model; SigV4a (`AWS4-ECDSA-P256-SHA256`, used by S3 Multi-Region Access Points) is not recognized by the SigV4 regex, so MRAP calls return `None` from `parse_request` and the Stage-2 caller is forced to default-deny legitimate MRAP traffic; presigned S3 URLs carry SigV4 in query parameters (`X-Amz-Algorithm`/`X-Amz-Credential`/`X-Amz-Signature`) rather than the Authorization header, and the parser does not look there, so every presigned-URL call returns `None` and gets default-denied at Stage 2 (browser-uploaded files, time-limited shareable links, all break).

The 5 LOWs are: the bouncer CLI never `.close()`s its `BouncerStore` after the command runs (connection-per-invocation leak — minor for CLI but pattern-dangerous for the Stage-2 long-running proxy); `fnmatch.fnmatchcase` admits `[abc]` character classes and `?` single-char wildcards that real IAM policy syntax does NOT support (users writing literal `[` in a pattern get character-class semantics they didn't ask for); `parent.mkdir(parents=True, mode=0o700)` only applies the mode to the leaf directory — intermediate parents created along the way (e.g. `~/.iam-jit/`) stay at the default `0o755`, partially undermining the doc claim of 0o700 confinement; the `iam-jit` main CLI has no `bouncer` subcommand registered (users who try `iam-jit bouncer --help` get a generic "No such command" with no pointer to the separate `iam-jit-bouncer` binary); the CLI docstring promises "Coming in Stage 2: run / learn" without a tracked task or issue link inside the repo.

The data model, decision logic (LEARN/ENFORCE/PROMPT modes), parameterized SQL inserts, parameterized SQL selects, and case-insensitivity handling on the SigV4 service prefix are all clean. The bug pattern is concentrated in (a) the AWS wire-format parser (which is the central component because everything downstream relies on its classification) and (b) the CLI-to-store wiring (which drops the matched-rule reference).

## Closure status

| Finding | Status |
|---|---|
| CRIT-23-01 S3 virtual-hosted-style bucket parser splits on first `.s3` — buckets containing `.s3` in their name (DNS-valid) extract wrong bucket; rule ARN scopes silently bypassed; audit log misattributes target bucket | OPEN |
| HIGH-23-01 S3 sub-resource table omits `tagging`/`cors`/`notification`/`logging`/`requestpayment`/`website`/`replication`; `PUT /bucket?tagging` misclassified as `CreateBucket`; deny rules on `s3:Put*Tagging` etc. silently bypassed | OPEN |
| HIGH-23-02 `decide_cmd --record` calls `store.record_decision(record_obj)` without `matched_rule_id=...`; every audit-log row records `matched_rule_id=NULL` even when an explicit rule matched; audit log structurally broken | OPEN |
| MED-23-01 Malformed `effect` text in `rules` row crashes the entire `list_rules()` call via `Effect("foo")` ValueError; one bad row makes all rules invisible | OPEN |
| MED-23-02 `rules add` CLI accepts malformed `pattern` (e.g. no colon); `parse_pattern` returns None at match time and `rule_matches` silently returns False; rule visible in `rules list` but never matches anything | OPEN |
| MED-23-03 SigV4a (`AWS4-ECDSA-P256-SHA256`, S3 Multi-Region Access Points) not recognized by `_SIGV4_AUTH_RE`; MRAP requests return `None` from `parse_request`; Stage-2 caller forced to default-deny legitimate MRAP traffic | OPEN |
| MED-23-04 Presigned S3 URLs carry SigV4 in `X-Amz-Algorithm`/`X-Amz-Credential` query parameters, not the Authorization header; parser does not look in the query string; presigned URL calls return None | OPEN |
| LOW-23-01 `bouncer_cli` never calls `store.close()` after a command completes; per-invocation connection leak (minor for short-lived CLI commands but pattern-dangerous for the Stage-2 proxy) | OPEN |
| LOW-23-02 `fnmatch.fnmatchcase` supports `[abc]` character classes and `?` single-char wildcards — AWS IAM policy globs do NOT; users writing patterns with literal `[` or `?` get unintended matching semantics | OPEN |
| LOW-23-03 `db_path.parent.mkdir(parents=True, mode=0o700)` applies 0o700 only to the leaf directory; intermediate parents (e.g. `~/.iam-jit/` if it didn't exist) stay at the default 0o755; doc claim is partly aspirational | OPEN |
| LOW-23-04 No `bouncer` subcommand on the main `iam-jit` CLI; users who type `iam-jit bouncer --help` get generic Click error with no pointer to the separate `iam-jit-bouncer` binary | OPEN |
| LOW-23-05 CLI main docstring promises "Coming in Stage 2: run / learn" without a tracked issue / task link in the repo (per WB21+WB22 docstring-drift pattern) | OPEN |

## CRIT findings

### CRIT-23-01 — S3 virtual-hosted bucket parser splits on first `.s3`; buckets containing `.s3` in name extract wrong bucket

- File: `src/iam_jit/bouncer/request_parser.py:368-381` (`_split_s3_bucket_and_key`), called by `_s3_action_and_resource:318` for every S3 request that takes the virtual-hosted branch.

- Issue: the host check is:
  ```python
  if "s3" in host_lc and not host_lc.startswith("s3"):
      # Virtual-hosted: <bucket>.s3.<...>.amazonaws.com
      bucket = host_lc.split(".s3", 1)[0]
      key = path.lstrip("/") or None
      return bucket, key
  ```
  AWS S3 bucket-naming rules permit:
  - Lowercase letters, digits, dots, and hyphens
  - 3-63 characters total
  - No two consecutive dots
  - Bucket names that look like IP addresses are rejected, but the substring `.s3` is otherwise legal

  So `my.s3.bucket-name` is a valid bucket name. For the virtual-hosted host `my.s3.bucket-name.s3.us-east-1.amazonaws.com`, `host_lc.split(".s3", 1)` produces `["my", ".bucket-name.s3.us-east-1.amazonaws.com"]` and the parser extracts bucket=`my`.

  Verified repro:
  ```python
  >>> _split_s3_bucket_and_key(host='my.s3.bucket-name.s3.us-east-1.amazonaws.com', path='/key')
  ('my', 'key')

  >>> _split_s3_bucket_and_key(host='evil.s3.foo.amazonaws.com', path='/key')
  ('evil', 'key')

  >>> _split_s3_bucket_and_key(host='my.s3-test.s3.us-east-1.amazonaws.com', path='/key')
  ('my', 'key')   # bucket actually named 'my.s3-test'
  ```

  Through `parse_request`, the resulting `ParsedRequest.resource_hint` is `arn:aws:s3:::my/key` for a call that actually targets a different bucket.

- Impact: this is a security bypass with three layers:
  1. **Rule-scope bypass**: a user's allow rule `arn:aws:s3:::my-data/*` matches calls whose parser-extracted ARN is `arn:aws:s3:::my-data/...` — including calls to the differently-named bucket `my-data.s3.attacker-bucket` (extracted as `my-data`). An attacker who can choose / influence the bucket name can craft a bucket name whose extracted prefix matches an allow rule.
  2. **Audit-log misattribution**: the SQLite `decisions.arn` column records the wrong bucket. Post-incident review reads "call targeted `my`" when the call actually targeted `my.s3.attacker-controlled-bucket`. The incident chain breaks at the audit step.
  3. **Allow-rule starvation**: a legitimate bucket `my.s3.legit-bucket` owned by the user — for which they wrote an allow rule scoped to `arn:aws:s3:::my.s3.legit-bucket/*` — is misclassified as targeting bucket `my`, the allow rule doesn't match (extracted ARN doesn't match the rule's ARN), and the call falls through to default-deny. The user's legit traffic breaks and they conclude bouncer is unreliable.

  All three vectors come from the same misparse.

- Why CRIT (not HIGH): for a security tool whose central feature is gating calls by resource, getting the resource extraction wrong on a popular service (S3) for a known-legal bucket-name shape is a vulnerability in the security boundary itself. The test suite at `tests/bouncer/test_request_parser.py:203-212` only tests a bucket without `.s3` in the name (`my-bucket.s3.us-east-1.amazonaws.com`) and so doesn't catch this. The bug is in the parser, not the rule engine, so EVERY downstream check (rule match, audit log, prompt UX) is affected.

- Fix: replace the `split(".s3", 1)` with a regex that anchors on the `s3[.-]` boundary AND matches at the end of the host (or before `.amazonaws.com`). Suggested:
  ```python
  _VHOST_RE = re.compile(
      r"^(?P<bucket>[a-z0-9.\-]+)\."
      r"s3(?:[.\-][a-z0-9.\-]+)?"  # s3 / s3.dualstack / s3-accelerate / s3-website-us-east-1 / s3.us-east-1
      r"\.amazonaws\.com$"
  )
  m = _VHOST_RE.match(host_lc)
  if m:
      bucket = m.group("bucket")
      key = path.lstrip("/") or None
      return bucket, key
  ```
  Anchoring on `.amazonaws.com$` removes the ambiguity. Add tests:
  - `my.s3.bucket-name.s3.us-east-1.amazonaws.com` → bucket=`my.s3.bucket-name`
  - `my.s3-test.s3.us-east-1.amazonaws.com` → bucket=`my.s3-test`
  - `my-bucket.s3.dualstack.us-east-1.amazonaws.com` → bucket=`my-bucket`
  - `my-bucket.s3-accelerate.amazonaws.com` → bucket=`my-bucket`
  - `ap-name.s3-accesspoint.us-east-1.amazonaws.com` → handled separately or excluded
  - `s3.amazonaws.com` (path-style) → falls through correctly

  Alternative if regex feels heavy: split on `.amazonaws.com` first, then `.s3` only on the leading portion. Both fix the bug; the regex is cleaner to audit.

## HIGH findings

### HIGH-23-01 — S3 sub-resource table omits `tagging`, `cors`, `notification`, `logging`, `requestpayment`, `website`, `replication`

- File: `src/iam_jit/bouncer/request_parser.py:322-336` (the `for sr_param, get_action, put_action, del_action in (...)` loop).

- Issue: the parser maps S3 sub-resource query parameters to specific IAM actions:
  ```python
  for sr_param, get_action, put_action, del_action in (
      ("policy", "GetBucketPolicy", "PutBucketPolicy", "DeleteBucketPolicy"),
      ("acl",    ..., ..., None),
      ("lifecycle", ..., ..., ...),
      ("versioning", ..., ..., None),
      ("encryption", ..., ..., ...),
  ):
  ```
  Missing sub-resources, each with its own IAM action shape:
  - `?tagging` → `GetBucketTagging` / `PutBucketTagging` / `DeleteBucketTagging`
  - `?cors` → `GetBucketCORS` / `PutBucketCORS` / `DeleteBucketCORS`
  - `?notification` → `GetBucketNotification` / `PutBucketNotification`
  - `?logging` → `GetBucketLogging` / `PutBucketLogging`
  - `?requestPayment` → `GetBucketRequestPayment` / `PutBucketRequestPayment`
  - `?website` → `GetBucketWebsite` / `PutBucketWebsite` / `DeleteBucketWebsite`
  - `?replication` → `GetBucketReplication` / `PutBucketReplication` / `DeleteBucketReplication`
  - `?inventory` → `GetBucketInventory*`
  - `?accelerate` → `GetAccelerateConfiguration` / `PutAccelerateConfiguration`

  Verified repro: a `PUT /my-bucket?tagging` request is currently classified as `CreateBucket` (because no sub-resource matched and the code falls through to the standard-operation table where `PUT` on a bucket means create):
  ```python
  >>> parse_request(method='PUT', host='s3.amazonaws.com', path='/my-bucket',
  ...               headers={'Authorization': _sigv4()}, query={'tagging': ''})
  ParsedRequest(action='CreateBucket', ...)
  ```

- Impact: two complementary bypasses:
  1. **Deny-rule bypass**: a user who writes `iam-jit-bouncer rules add 's3:PutBucketTagging' --effect deny` — perhaps to prevent agents from re-tagging buckets for billing exfiltration — has the rule silently bypassed. The call is parsed as `s3:CreateBucket` (which has its own different rule semantics) instead, so the deny rule on `s3:PutBucketTagging` doesn't match. Same shape for every missing sub-resource.
  2. **Audit-log misclassification**: the audit log records `action=CreateBucket` for a call that was actually `PutBucketTagging`. Post-incident review sees "agent created buckets" when the agent was modifying bucket tagging.

  The bouncer's value proposition ("we gate calls by service:action") is undermined if a known-common operation class produces the wrong action label. S3 bucket tagging is widely used (cost allocation, IAM Condition keys, lifecycle policies); CORS / website / notification configs are also common targets in misconfiguration attacks.

- Why HIGH (not CRIT): unlike CRIT-23-01, the affected operations are less likely to be the primary security boundary (most users will write rules at `s3:Put*` or `s3:Delete*` granularity, which DO match because `PUT` is in there). But for any user who writes a sub-resource-specific deny rule, the rule is silently inert. The fix is mechanical (extend the table). Filed HIGH because it's a known-incomplete table — the existing entries demonstrate the pattern; the missing entries are the work that wasn't finished.

- Fix:
  ```python
  for sr_param, get_action, put_action, del_action in (
      ("policy",        "GetBucketPolicy",      "PutBucketPolicy",      "DeleteBucketPolicy"),
      ("acl",           "GetObjectAcl" if key else "GetBucketAcl",
                        "PutObjectAcl" if key else "PutBucketAcl",      None),
      ("lifecycle",     "GetLifecycleConfiguration",
                        "PutLifecycleConfiguration",
                        "DeleteLifecycle"),
      ("versioning",    "GetBucketVersioning",  "PutBucketVersioning",  None),
      ("encryption",    "GetEncryptionConfiguration",
                        "PutEncryptionConfiguration",
                        "DeleteEncryption"),
      ("tagging",       "GetBucketTagging",     "PutBucketTagging",     "DeleteBucketTagging"),
      ("cors",          "GetBucketCORS",        "PutBucketCORS",        "DeleteBucketCORS"),
      ("notification",  "GetBucketNotification","PutBucketNotification",None),
      ("logging",       "GetBucketLogging",     "PutBucketLogging",     None),
      ("requestPayment","GetBucketRequestPayment",
                        "PutBucketRequestPayment", None),
      ("website",       "GetBucketWebsite",     "PutBucketWebsite",     "DeleteBucketWebsite"),
      ("replication",   "GetBucketReplication", "PutBucketReplication", "DeleteBucketReplication"),
      ("inventory",     "GetBucketInventoryConfiguration",
                        "PutBucketInventoryConfiguration",
                        "DeleteBucketInventoryConfiguration"),
      ("accelerate",    "GetAccelerateConfiguration",
                        "PutAccelerateConfiguration", None),
  ):
  ```
  Note the case-sensitivity (`requestPayment` is the actual query-parameter name AWS uses; case matters for `in query` membership test). Add tests covering each new entry with both bucket-level and object-level access where relevant.

  Also: the lookup `if sr_param in query` is case-sensitive in dict membership, but AWS query parameters are sometimes received with different casing — worth verifying that the proxy server (Stage 2) normalizes query-parameter casing consistently.

### HIGH-23-02 — `decide_cmd --record` drops the matched rule id; audit log structurally broken

- File: `src/iam_jit/bouncer_cli.py:258-259` (`decide_cmd`), `src/iam_jit/bouncer/store.py:204-223` (`record_decision`'s separate `matched_rule_id` kwarg).

- Issue: `store.record_decision(dec, *, matched_rule_id=None)` takes the matched rule's id as a separate kwarg from the `DecisionRecord` itself. The `DecisionRecord` carries the matched `ProxyRule` object (`matched_rule: ProxyRule | None`) but NOT its database id — the store API expects the caller to track the id independently.

  The CLI's `decide_cmd` calls:
  ```python
  if record:
      store.record_decision(record_obj)   # NO matched_rule_id passed
      click.echo("(recorded to audit log)")
  ```

  So even when `record_obj.matched_rule` is not None (an explicit allow/deny matched), the audit-log row has `matched_rule_id=NULL`.

  Verified repro:
  ```python
  >>> s = BouncerStore(db_path='...')
  >>> rid = s.add_rule(ProxyRule(pattern='s3:GetObject', effect=Effect.ALLOW))
  >>> rid
  1
  >>> # Replicate decide_cmd's exact flow:
  >>> ruleset = RuleSet(rules=[r for _, r in s.list_rules()])
  >>> rec = decide(ruleset, mode=Mode.ENFORCE, default_policy=DefaultPolicy.DENY,
  ...              service='s3', action='GetObject')
  >>> rec.matched_rule.pattern
  's3:GetObject'
  >>> s.record_decision(rec)   # exactly what bouncer_cli.py:259 does
  >>> s.list_decisions()[0]['matched_rule_id']
  None     # should be 1 — the matched rule's id
  ```

  The unit test `test_record_decision_persists_matched_rule_id` at `tests/bouncer/test_store.py:181-185` only verifies that the store *can* persist a matched_rule_id when the caller passes it. No test exercises the CLI's actual end-to-end recording path, so the gap isn't caught.

- Impact: this breaks the documented audit-log invariant. Per the schema docstring at `store.py:26`: "`matched_rule_id INTEGER, -- nullable; FK to rules.id (soft FK)`". The implicit contract is that this id is populated when a rule matched. The CLI's `decide --record` path violates that contract for every recorded decision.

  Practical consequences:
  - Post-incident review: "which rule allowed this delete?" — the audit log can't answer; every row says `matched_rule_id=NULL`. The user has to reconstruct from the `reason` text ("explicit-allow rule") and guess at which rule was responsible.
  - Rule-debugging workflows ("delete the rule that authorized this and re-run") — impossible without the id.
  - `logs tail` JSON output is technically correct (NULL is the truthful value of what's in the DB) but useless for any tool that wants to cross-reference.

  Forward compatibility: Stage 2's HTTP proxy will need to use the same `record_decision` API path. Whoever writes the proxy will hit the same bug — and the proxy's audit log is the load-bearing artifact ("what did the bouncer block / allow yesterday?"). Worth fixing at the API level NOW so the proxy can't reintroduce it.

- Why HIGH (not CRIT): the bouncer still works — decisions are correctly made; audit log entries are correctly created in every other respect. Only the matched-rule reference is lost. But the audit log is the entire point of Stage 1's persistence layer; "lost the matched-rule reference" makes the persistence half-useful.

- Fix options:
  1. **Best**: change `DecisionRecord` to carry the matched rule's id directly (not just the `ProxyRule` object). `RuleSet.evaluate` would return `tuple[Effect, ProxyRule, int]` instead of `tuple[Effect, ProxyRule]`, and the decision composer would propagate the id into `DecisionRecord`. Then `record_decision(dec)` doesn't need a separate kwarg. The id is loadbearing audit data — it deserves to live on the record.
  2. **Acceptable**: keep the store API but track the id separately in `decide_cmd`:
     ```python
     if record:
         matched_id = None
         if record_obj.matched_rule:
             # Re-look-up: find the rule's id by pattern + effect + scope.
             # Costs an extra query but works without API change.
             matched_id = _resolve_matched_id(store, record_obj.matched_rule)
         store.record_decision(record_obj, matched_rule_id=matched_id)
     ```
     But this is a stop-gap — the Stage-2 proxy will need the same plumbing.
  3. **Worst**: drop the `matched_rule_id` column entirely if no caller will populate it. Honest but loses audit value.

  Recommend option 1 — load-bearing audit data belongs on the record, not as a sidecar kwarg.

## MED findings

### MED-23-01 — Malformed `effect` text in `rules` row crashes `list_rules()`

- File: `src/iam_jit/bouncer/store.py:157-178` (`list_rules`'s `Effect(effect)` call inside the for-loop), `src/iam_jit/bouncer/store.py:180-198` (`get_rule` same pattern).

- Issue: the schema declares `effect TEXT NOT NULL` without a CHECK constraint. Any string can be inserted (via raw SQL, schema migration accident, or a future code path that hasn't validated). When `list_rules` reads each row:
  ```python
  for r in rows:
      rid, pattern, effect, arn_scope, region_scope, note, origin = r
      out.append((int(rid), ProxyRule(
          pattern=pattern,
          effect=Effect(effect),   # ← raises ValueError on unknown string
          ...
      )))
  ```
  A single bad row crashes the entire `list_rules()` call with `ValueError: 'foo' is not a valid Effect`. The CLI's `rules list` shows no rules at all (because the iteration died before any could be appended), and the bouncer's Stage-2 proxy can't load its ruleset.

  Verified repro:
  ```python
  # Insert a bad row via raw SQL (or via a future enum-extension change)
  conn.execute("INSERT INTO rules(pattern, effect, created_at) "
               "VALUES ('s3:DeleteObject', 'foo', '...')")

  # Open via BouncerStore
  s = BouncerStore(db_path=db)
  s.list_rules()
  # raises: ValueError: 'foo' is not a valid Effect
  ```

  Same issue applies to `get_rule(rid)` if the bad row's id is requested.

- Why MED: low probability of hitting this through current code paths (the bouncer's own `add_rule` validates `effect` via the `Effect.value` shape going in, and there's no concurrent writer to introduce bad rows). BUT:
  - Per [[update-release-strategy]] schema migrations are additive; a future version that adds `Effect.LOG` or `Effect.RATE_LIMIT` and downgrades to an old binary would crash the entire `list_rules` call until the old binary is removed. The bouncer can't be downgraded cleanly.
  - The schema NOT having a CHECK constraint while the code RELIES on the constraint at read time is the kind of invariant-without-enforcement that bites months later.
  - Direct DB edits (user fixing things, restore from backup with version mismatch) trip this.

- Fix options:
  1. **Best, layered**: (a) add a CHECK constraint `effect IN ('allow', 'deny')` on the schema (additive migration acceptable; SQLite enforces with `pragma writable_schema=ON` swap or a fresh table); (b) in the loader, wrap `Effect(effect)` in a try/except and skip-with-warning on unknown values:
     ```python
     try:
         effect_val = Effect(effect)
     except ValueError:
         logger.warning("bouncer rule %s has unknown effect %r — skipping", rid, effect)
         continue
     ```
     Belt-and-suspenders. The skip preserves availability; the CHECK prevents bad inserts.
  2. **Acceptable**: just the loader try/except; schema stays open for future enum values without a migration.
  3. **Worst**: leave as-is; document that bad rows brick the bouncer.

  Same fix pattern needed in `get_rule`.

### MED-23-02 — `rules add` accepts malformed patterns; rule visible in `rules list` but never matches

- File: `src/iam_jit/bouncer_cli.py:114-138` (`rules_add`), `src/iam_jit/bouncer/rules.py:108-112` (`rule_matches` silent-skip on `parse_pattern is None`).

- Issue: `rules_add` passes the `pattern` argument straight into `ProxyRule(pattern=pattern, ...)` and `store.add_rule(rule)` without calling `parse_pattern` to validate. The pattern is persisted; `rules list` shows it; but `rule_matches` at match time calls `parse_pattern(rule.pattern)`, gets None, and silently returns False.

  Verified repro:
  ```bash
  $ iam-jit-bouncer rules add 'not-a-valid-pattern' --effect deny
  added rule #1: deny not-a-valid-pattern

  $ iam-jit-bouncer rules list
     1   deny  not-a-valid-pattern

  $ iam-jit-bouncer decide --service s3 --action DeleteObject
  decision: deny
  reason:   enforce-mode unmatched (default-deny)
  # ← the user's "deny" rule did NOT participate; default-deny saved the day,
  #   but had default-policy been allow, the call would have been allowed
  #   despite the user's deny rule appearing in the listing.
  ```

  Test `test_malformed_rule_never_matches` (at `tests/bouncer/test_rules.py:163-167`) actually documents this behavior as intentional — but the CLI surface doesn't prevent users from creating malformed rules in the first place.

- Impact: this is a trust-gap finding (per the WB21/WB22 docstring-drift pattern). The user added what they believe is a deny rule; the CLI confirmed "added rule #1"; the rule shows in `rules list`. They reasonably believe the rule is in effect. It is not. Worse: if their default-policy is `allow`, the malformed rule contributes ZERO protection while creating false sense of security.

  Verbatim user-facing symptoms:
  - `rules add 's3-GetObject'` (typo: hyphen not colon) → "added" → rule never fires
  - `rules add 'iam DeleteRole'` (typo: space not colon) → "added" → rule never fires
  - `rules add '*:Delete*'` (rejected by parse_pattern — service wildcard) → "added" → rule never fires

- Why MED: doesn't enable a bypass relative to a *correctly-written* rule (there's no rule, so default-policy decides). But it actively misleads users about the state of their protection. Hits the [[safety-mode-lean-permissive]] failure mode in reverse: "I added a deny rule and felt safe."

- Fix: validate up-front in `rules_add`:
  ```python
  from .bouncer.rules import parse_pattern
  ...
  def rules_add(pattern, effect, ...):
      if parse_pattern(pattern) is None:
          click.echo(f"invalid rule pattern: {pattern!r} (expected '<service>:<action_glob>')", err=True)
          sys.exit(2)
      ...
  ```
  Mirror in the future `rules edit` / `rules update` once those land. The store's `add_rule` could also gate (defense in depth) — adds a useful invariant that no malformed pattern ever lives in the table.

### MED-23-03 — SigV4a (`AWS4-ECDSA-P256-SHA256`) not recognized; MRAP calls return None

- File: `src/iam_jit/bouncer/request_parser.py:46-49` (`_SIGV4_AUTH_RE`).

- Issue: the regex matches only `AWS4-HMAC-SHA256`. SigV4a (asymmetric signing using ECDSA) was introduced in 2021 for S3 Multi-Region Access Points (MRAP) and is now used by:
  - S3 Multi-Region Access Points (`*.s3-global.amazonaws.com` and `*.accesspoint.s3-global.amazonaws.com`)
  - Some VPC endpoints when crossing regions
  - Future services per AWS's stated direction

  The SigV4a Authorization header format:
  ```
  AWS4-ECDSA-P256-SHA256 Credential=AKID/20260517/us-east-1/s3/aws4_request, ...
  ```
  is structurally identical EXCEPT for the algorithm token. The regex hardcodes `AWS4-HMAC-SHA256`, so SigV4a is rejected:
  ```python
  >>> extract_service_and_region('AWS4-ECDSA-P256-SHA256 Credential=KEY/20260517/us-east-1/s3/aws4_request, ...')
  None
  ```

  The Stage-2 caller has to interpret `parse_request → None` as "I can't classify this; default-deny" — so every MRAP request gets blocked.

- Impact: MRAP usage is growing; the bouncer reports this as "couldn't classify the request" with no further detail. A user who adopts MRAP for cross-region failover finds their workflow broken with no clear remediation path. The bouncer's response is to default-deny — which is the safer failure mode, but invisible-to-the-user safety is the worst kind ("bouncer broke MRAP and I don't know why").

- Why MED (not HIGH): MRAP adoption is non-trivial; most current deployments don't use it. But it's a known-gap on a known-current AWS feature; the parser claims to extract service+region from "the SigV4 Credential field" without qualifying which SigV4 variant. The fix is a one-line regex change.

- Fix:
  ```python
  _SIGV4_AUTH_RE = re.compile(
      r"AWS4-(?:HMAC-SHA256|ECDSA-P256-SHA256)\s+"
      r"Credential=[^/]+/\d+/(?P<region>[^/]+)/(?P<service>[^/]+)/aws4_request",
      re.IGNORECASE,
  )
  ```
  Note: for SigV4a, the `region` field is sometimes the literal string `*` (asterisk = "any region"). The Credential format permits it. After fix, `region == "*"` should probably be normalized to `None` (or kept as-is and documented). Worth a small test.

  Also: STS uses SigV4 (not SigV4a) so this fix doesn't change STS handling. S3 access points use whichever signing variant they're configured for.

### MED-23-04 — Presigned S3 URLs put SigV4 in query parameters; parser only looks at Authorization header

- File: `src/iam_jit/bouncer/request_parser.py:85-101` (`extract_service_and_region` only reads the Authorization header).

- Issue: presigned S3 URLs encode the SigV4 elements in query parameters instead of the Authorization header:
  ```
  GET https://my-bucket.s3.amazonaws.com/key.txt
      ?X-Amz-Algorithm=AWS4-HMAC-SHA256
      &X-Amz-Credential=AKID%2F20260517%2Fus-east-1%2Fs3%2Faws4_request
      &X-Amz-Date=20260517T120000Z
      &X-Amz-Expires=3600
      &X-Amz-SignedHeaders=host
      &X-Amz-Signature=...
  ```
  The HTTP request has no Authorization header; the parser returns None; Stage-2's caller treats this as "unclassifiable" and applies default-policy DENY.

  Verified repro:
  ```python
  >>> parse_request(
  ...     method='GET',
  ...     host='my-bucket.s3.us-east-1.amazonaws.com',
  ...     path='/key.txt',
  ...     headers={},  # no Authorization
  ...     query={'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
  ...            'X-Amz-Credential': 'KEY/20260517/us-east-1/s3/aws4_request',
  ...            'X-Amz-Signature': 'abc'}
  ... )
  None
  ```

- Impact: every workflow that uses presigned URLs breaks under bouncer enforce mode with default-deny:
  - Browser uploads (the canonical S3 pattern for user-uploaded files)
  - Time-limited shareable links (Slack file embeds, email attachments via S3, etc.)
  - SDKs that hand a presigned URL to subprocesses (some Spark / EMR patterns)

  The bouncer's stated reach is "every AWS API call"; presigned URLs are AWS API calls. The bouncer can't apply rules to them today.

- Why MED (not HIGH): the bouncer's primary attack-surface concern is agent-driven API calls (which always go through the SDK and produce Authorization headers). Presigned URLs are mostly user-facing flows. But (a) some agents do use presigned URLs as an intermediate hand-off, (b) some legitimate workloads use them programmatically, and (c) the parser's docstring at line 86-92 says "Returns None if header is missing / malformed (e.g. anonymous S3 calls)" — presigned URLs are NOT anonymous, they're SigV4-signed via query params, which the parser doesn't address.

- Fix: extract from query parameters when the Authorization header is absent:
  ```python
  def extract_service_and_region(
      authorization: str | None,
      query: dict[str, str] | None = None,
  ) -> tuple[str, str] | None:
      if authorization:
          m = _SIGV4_AUTH_RE.search(authorization)
          if m:
              return m.group("service").lower(), m.group("region")
      if query:
          cred = query.get("X-Amz-Credential")
          if cred:
              # Format: KEY/YYYYMMDD/region/service/aws4_request
              parts = cred.split("/")
              if len(parts) == 5 and parts[4] == "aws4_request":
                  return parts[3].lower(), parts[2]
      return None
  ```
  And thread `query` through from `parse_request`. The query parameter values are URL-decoded by upstream HTTP framework; the `%2F` shown above is decoded by `urllib.parse.parse_qs` / FastAPI / etc. before it reaches the parser, so split on `/` works.

  Add tests covering presigned URLs (both with the algorithm in query and without).

## LOW findings

### LOW-23-01 — `bouncer_cli` never `.close()`s `BouncerStore`; per-command connection leak

- File: `src/iam_jit/bouncer_cli.py:60-66, 81-99, 114-138, 144-152, 175-196, 222-260, 280-308` (every CLI command creates `BouncerStore(db_path=db)` and never calls `close()`).

- Issue: each CLI command instantiates a fresh `BouncerStore`, opens an SQLite connection (with WAL), and exits without closing. Python's GC will eventually finalize the `sqlite3.Connection`, but:
  - On short-lived CLI commands this works in practice (process exit closes the FD).
  - On the **Stage-2 long-running proxy** that calls `BouncerStore(...)` per-request (or even per-startup if the proxy creates one shared store + holds it for the lifetime of the process), the pattern needs to either explicitly close OR use a context-manager wrapper.

  Verified at the CLI level: `iam-jit-bouncer init`, `rules add`, `rules list`, `rules remove`, `logs tail`, `decide`, `inspect` all create `BouncerStore` without `.close()`.

- Why LOW: doesn't affect correctness today. Two reasons it's worth filing:
  1. The store has a `close()` method that's *only* covered by the test fixture (`tests/bouncer/test_store.py:14-19`); no production caller uses it. Dead-code-coverage signal.
  2. Stage 2's proxy will need the right pattern. If the CLI's pattern of "just instantiate and let GC sort it out" gets copied to the long-running proxy, the proxy will eventually exhaust connection-pool resources under load (or, with WAL, leave stale `-wal` and `-shm` files on shutdown).

- Fix: wrap CLI commands in a `try/finally` or convert `BouncerStore` to support `__enter__`/`__exit__`:
  ```python
  class BouncerStore:
      def __enter__(self):
          return self
      def __exit__(self, *exc):
          self.close()
  ```
  Then `with BouncerStore(db_path=db) as store: ...` in each CLI command. Idiomatic Python and primes Stage 2 to use the same pattern. Also makes the `close()` method actually-callable from production code.

### LOW-23-02 — `fnmatch.fnmatchcase` admits `[abc]` and `?` wildcards that AWS IAM policy syntax does not

- File: `src/iam_jit/bouncer/rules.py:118` (action glob match), `rules.py:127, 133` (ARN and region glob match).

- Issue: `fnmatch.fnmatchcase` is a Unix-shell-style glob matcher supporting:
  - `*` — match any sequence (also in AWS IAM)
  - `?` — match any single character (NOT a wildcard in AWS IAM action globs; AWS IAM uses `?` as a literal in some resource ARNs)
  - `[abc]` — character class (NOT supported in AWS IAM)
  - `[!abc]` — negated character class (NOT supported)

  AWS IAM policy glob syntax officially supports `*` and `?` per the IAM docs, where:
  - In Action elements: `*` is the only wildcard
  - In Resource elements: both `*` (multi-char) and `?` (single-char) are supported

  But the IAM `?` semantics is the single-character wildcard; bouncer's `?` matches the same way (Python's `fnmatch.fnmatchcase` agrees). So that part is consistent.

  The discrepancy is `[abc]` — a user who writes `iam-jit-bouncer rules add 's3:Get[Lo]bject' --effect deny` thinking the `[Lo]` is literal will instead get a character class. Verified:
  ```python
  >>> import fnmatch
  >>> fnmatch.fnmatchcase('GetLbject', 'Get[Lo]bject')  # 'L' is in {L,o}
  True
  >>> fnmatch.fnmatchcase('GetObject', 'Get[Lo]bject')  # 'O' is uppercase, 'o' is lowercase, no match
  False
  ```
  (Most users will never write `[` in a rule, but those who do get surprising behavior.)

- Impact: a user who pastes a pattern from somewhere that uses `[abc]` literally (e.g. a comment, a docstring, a logging format string) gets unexpected matching. The bouncer's rules language drift relative to AWS IAM's policy language is a documentation gap rather than a security bypass.

- Why LOW: requires the user to actively write `[` or `]` in a pattern, which is rare. No bypass scenarios I can construct without contrived user-input.

- Fix options:
  1. **Best, narrow**: write a custom matcher that supports only `*` (and optionally `?`), translating the pattern to a regex with `re.escape` for non-wildcard characters. About 10 lines; mirrors AWS's actual glob semantics:
     ```python
     def _glob_to_regex(pattern: str) -> re.Pattern:
         parts = []
         for ch in pattern:
             if ch == '*':
                 parts.append('.*')
             elif ch == '?':
                 parts.append('.')
             else:
                 parts.append(re.escape(ch))
         return re.compile('^' + ''.join(parts) + '$')
     ```
  2. **Acceptable**: keep `fnmatch.fnmatchcase`; document the `[...]` extension in `IAM-JIT-BOUNCER.md` so users at least know.
  3. **Worst**: leave undocumented; surfaces as a "weird matching" bug report eventually.

### LOW-23-03 — `parent.mkdir(parents=True, mode=0o700)` only applies mode to leaf; intermediate dirs stay 0o755

- File: `src/iam_jit/bouncer/store.py:74` (`self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)`).

- Issue: Python's `Path.mkdir(parents=True, mode=...)` only applies the `mode` argument to the LEAF directory being created — intermediate parents are created with the default mode (umask-respecting, typically 0o755 on Linux/macOS). The docstring at `docs/IAM-JIT-BOUNCER.md:181-182` claims:
  > Directory created with mode `0o700` per [[no-hosted-saas]] + [[local-only-safety-mode]] precedent.

  Verified repro:
  ```
  Path: /tmp/x/a/b/c/state.db (db_path)
  After BouncerStore() init:
    /tmp/x/a:            mode=0o755   ← parent of parent of parent
    /tmp/x/a/b:          mode=0o755   ← parent of parent
    /tmp/x/a/b/c:        mode=0o700   ← leaf (bouncer/) — correct
  ```

  For the default path `~/.iam-jit/bouncer/`, if `~/.iam-jit/` didn't already exist, it would be created with 0o755. The `bouncer/` subdir IS 0o700; but a `~/.iam-jit/`-walker on a shared machine can list the bouncer/ subdir's existence and metadata (filename / size) even if they can't read the file contents.

  Note: the state DB itself is created by SQLite at file-open with mode 0o644 by default — also NOT respecting the 0o700 intent. The audit-log SQLite file is world-readable on most installs.

- Why LOW: on single-user macOS laptops (the dominant deploy shape for OSS bouncer) this doesn't matter — only one user can read the home directory anyway. On shared Linux hosts or shared dev VMs, partial.

- Fix options:
  1. **Best**: after `mkdir`, explicitly `chmod(0o700)` each created parent that didn't exist before:
     ```python
     # Track which parents exist; mkdir each individually with the right mode.
     parents_to_create = []
     p = self.db_path.parent
     while not p.exists():
         parents_to_create.append(p)
         p = p.parent
     for p in reversed(parents_to_create):
         p.mkdir(exist_ok=True)
         p.chmod(0o700)
     # Also chmod the DB file after sqlite3.connect creates it.
     self.db_path.chmod(0o600)
     ```
  2. **Acceptable**: chmod just the leaf `bouncer/` directory + the state.db file; document the parent-dir gap.
  3. **Worst**: leave as-is; quietly drop the 0o700 claim from docs.

### LOW-23-04 — No `bouncer` subcommand on `iam-jit` CLI; users get unhelpful Click error

- File: `src/iam_jit/cli.py` (no `@main.add_command(...)` for a bouncer-pointer), `pyproject.toml:77` (separate `iam-jit-bouncer` script entry, intentionally separate per [[four-products-one-brand]]).

- Issue: the design decision per [[four-products-one-brand]] is that the bouncer is a separate product with its own binary (`iam-jit-bouncer`). The `iam-jit` main CLI does NOT have a `bouncer` subcommand. Verified:
  ```bash
  $ iam-jit bouncer --help
  Usage: main [OPTIONS] COMMAND [ARGS]...
  Try 'main --help' for help.

  Error: No such command 'bouncer'.
  ```
  A user familiar with `iam-jit` who reads about the bouncer in docs may reasonably try `iam-jit bouncer` first. They get a generic "No such command" with no pointer.

- Why LOW: design-intentional; not a code defect. But a 5-line UX improvement.

- Fix: add a stub command on `iam-jit` that prints a helpful pointer:
  ```python
  @main.command("bouncer", hidden=False)
  def bouncer_stub() -> None:
      """The bouncer is a separate binary. Run `iam-jit-bouncer --help`."""
      click.echo(
          "The iam-jit-bouncer is a separate binary (per [[four-products-one-brand]]).\n"
          "Run: iam-jit-bouncer --help\n"
          "Docs: docs/IAM-JIT-BOUNCER.md"
      )
  ```
  Resolves the discovery gap at near-zero cost.

### LOW-23-05 — CLI docstring promises "Coming in Stage 2: run / learn" without tracked task

- File: `src/iam_jit/bouncer_cli.py:47-50` ("Coming in Stage 2: run / learn"), `docs/IAM-JIT-BOUNCER.md:18-23` ("Stage 2 (next release): HTTP proxy server").

- Issue: per WB21 + WB22 trust-gap pattern. The CLI docstring's "Coming in Stage 2" is aspirational. The repo HAS task `#160` (referenced in the commit message and `bouncer_cli.py:7`) but the "Stage 2 next release" claim has no concrete commitment artifact:
  - No Stage 2 issue / task tracked separately
  - No date or sprint commitment
  - No "subscribe to be notified" mechanism

  Users who upgrade between OSS releases expecting Stage 2 to land "next" need a place to follow progress. The docs cross-link `[[iam-jit-bouncer]]` (a memo, only visible to the author) and `[[four-part-launch-framework]]` (also a memo).

- Why LOW: docstring/marketing drift; doesn't affect code. Same shape as WB21/WB22 prior LOWs. Filed for consistency.

- Fix: replace "Coming in Stage 2" with a concrete reference (a GitHub issue id, a roadmap file, or "see docs/IAM-JIT-BOUNCER.md#status"). For the CLI docstring, the simplest fix:
  ```python
  Roadmap (see docs/IAM-JIT-BOUNCER.md#status):
    Stage 2 — HTTP proxy server + interactive PROMPT-mode
    Stage 3 — Enterprise fleet rules / web UI / anomaly detection
  ```

## Verified clean

The following were probed per the audit prompt and found no issues:

- **`bool` rejection on `--limit`**: `int(limit)` in `store.list_decisions` accepts bool (since `bool` is subclass of `int`) but the `max(1, min(int(limit), 10_000))` clamp means `True`→1, `False`→1; no exploit. Not gated, but no harm.

- **Threading safety of `BouncerStore`**: ran a 10-thread × 50-insert race against a single connection with `check_same_thread=False`. Result: 500/500 rules persisted, 0 errors. The `threading.Lock` on every operation correctly serializes against SQLite's "one connection at a time" requirement. Verified.

- **SQL injection via `reason` / `note`**: all `INSERT` and `SELECT` statements use parameterized queries (`?` placeholders) — no string concatenation. The `note` field is never interpolated into the `reason` string at decision time (reasons are built from `effect.value` only, e.g. `f"explicit-{effect.value} rule"`). Verified clean.

- **`record_decision` `matched_rule_id` consistency** (concern #4 sub-point): the store API accepts an optional `matched_rule_id` kwarg that's the responsibility of the caller. No automatic consistency check between `DecisionRecord.matched_rule.pattern` and the database's row at `matched_rule_id`. Acceptable for foundation slice; flagged as part of HIGH-23-02 (the CLI doesn't populate it). The store itself doesn't verify the FK exists (FKs disabled per the comment) — acceptable for soft-FK design but a future `cleanup` task should LEFT JOIN to surface deleted-rule references.

- **`IAM_JIT_BOUNCER_DB` env-var values**: `/dev/null` → fails with `OperationalError: unable to open database file`. `/etc/passwd` → fails with `DatabaseError: file is not a database`. Both errors propagate cleanly to the CLI as an exception — not graceful but not silently-wrong. Acceptable behavior; documented expectation could improve (env-var docs don't mention "you can break things if you point me at random files").

- **`whitespace handling in SigV4 Authorization`**: `\s+` in the regex matches spaces, tabs, and newlines. Tested `\t` and `\n` separators; both work. Acceptable for AWS-shaped Authorization headers (real AWS SDKs only emit space-separated).

- **LEARN-mode invariant under DENY rule**: verified by test (`test_learn_mode_allows_even_when_deny_rule_matches`) and by tracing the `decide` function — LEARN mode never returns DENY. The `would-deny` reason text correctly previews what enforce would do. Audit log records "allow" (the actual decision) not "would-deny" (the preview). Consistent with the function's stated invariant.

- **PROMPT mode on matched ALLOW**: verified by test — PROMPT mode does NOT prompt when an explicit ALLOW rule matches. The docstring is consistent with this behavior. (Whether this is the right UX vs. Little Snitch's "ask me every time" mode is a future design call; the current behavior matches the docstring and the test.)

- **Bucket-name `.s3` in path-style**: path-style requests (e.g. `s3.amazonaws.com/my.s3.bucket-name/key`) correctly extract bucket=`my.s3.bucket-name` — the path-style branch uses `split("/", 1)` which is correct. The CRIT applies ONLY to the virtual-hosted branch.

- **STS not in `_GLOBAL_SERVICES`**: correct — STS is regional since 2018; bouncer rules can scope STS calls by region. Listed `iam, organizations, cloudfront, route53, support` are all truly global. Note that S3 is NOT in the global list (also correct — S3 buckets ARE per-region). CloudTrail (regional) and DynamoDB (regional) correctly absent.

- **X-Amz-Target with single dot**: `Lambda_20210331.GetRuntimeManagementConfig` → action `GetRuntimeManagementConfig` (correct via `rsplit('.', 1)`). Multi-dot hypothetical `Lambda_20210331.GetRuntimeManagementConfig.v2` → action `v2` (wrong) — but multi-dot targets don't exist in current AWS API surface (no version suffix after the action name). Verified clean for current AWS.

- **Lambda `CreateFunction` path detection**: `POST /2015-03-31/functions` (no trailing slash, no name) → `CreateFunction` correctly. `POST /2015-03-31/functions/` (trailing slash) → `CreateFunction` correctly. The strip in `parts = (path or "").strip("/").split("/")` handles both.

- **Schema migration**: `SCHEMA_VERSION = 1` and `INSERT INTO schema_version` happens only when no row exists. No `IF NOT EXISTS`-bypass bugs. Migration is set up correctly for additive growth (future v2 would add an `ALTER TABLE`-style migration; the version row gets updated).

- **`1.8%` references**: grep confirms zero `1.8%` mentions in `src/iam_jit/bouncer/`, `src/iam_jit/bouncer_cli.py`, `docs/IAM-JIT-BOUNCER.md`, or `tests/bouncer/`. Per [[no-one-eight-percent-mention]] — clean.

- **`[[creates-never-mutates]]`**: grep confirms no `boto3` usage and no `iam:*` AWS API call in bouncer code. The single `boto3` mention in `__init__.py:4` is a docstring describing what the bouncer sits BETWEEN (the SDK and AWS), not an import. Verified — bouncer is purely local-state-mutating + read-only-against-requests.

- **`[[scorer-is-ground-truth]]`**: no imports from `iam_jit.scoring` or `iam_jit.recommender` modules in any bouncer file. Bouncer rules are an entirely separate language. Verified clean.

- **`Effect` enum is open**: extending it (`LOG`, `RATE_LIMIT`) requires no schema change (since column is `TEXT`), but bites the `Effect("foo")` parser at read time per MED-23-01. The "open enum + crashing parser" combination is consistent with the rest of iam-jit's enum handling — not a unique bouncer concern.

- **`origin` field**: declared `origin TEXT NOT NULL DEFAULT 'user'`; supports future `learn` / `default` values without schema change. List/get round-trip preserves the value. Clean.

- **Test fixtures realistic**: `_sigv4()` test helper at `tests/bouncer/test_request_parser.py:16-22` generates real-shaped Authorization headers (with the correct comma-separated `SignedHeaders` and `Signature` fields). Tests use these via `headers={"Authorization": _sigv4(...)}` — close enough to real boto3 output for parser testing. (Doesn't catch the CRIT because the test bucket names don't contain `.s3`.)

- **`logs tail` filter**: `decision_filter` parameter correctly produces `WHERE decision = ?` with parameterized binding. JSON output is `indent=2` (readable). Verified clean.

- **`inspect` header parsing**: `h.split(":", 1)` with `maxsplit=1` correctly handles headers whose VALUE contains colons (e.g. `Date: Mon, 17 May 2026 12:00:00 GMT`). The check `if ":" not in h` runs before split; both handle correctly. Verified.

## Regression check

Command run: `cd /Users/reagan/repos/iam-roles && .venv/bin/python -m pytest --no-header -q --ignore=tests/test_calibration_corpus.py --ignore=tests/e2e 2>&1 | tail -5`

Result:
```
2208 passed, 29 skipped, 14 deselected, 2 warnings in 88.39s (0:01:28)
```

Matches the audit-prompt baseline (2208 passed). The 96 pre-existing `tests/test_calibration_corpus.py` failures are unchanged (not run; not caused by #160). All 109 new bouncer tests pass.

## Summary

**1 CRIT, 2 HIGH, 4 MED, 5 LOW.** The foundation ships clean data model + decision logic + parameterized SQLite, but the AWS wire-format parser has a security-critical S3 bucket-name parse bug (CRIT-23-01) that allows rule-scope bypass for buckets containing `.s3` in their name; an incomplete S3 sub-resource table (HIGH-23-01) silently misclassifies common bucket-management operations like tagging/cors/website; and the CLI's `decide --record` path drops the matched rule's id (HIGH-23-02) so the audit log can't answer "which rule allowed this?". MEDs cluster around the wire-format gaps (SigV4a, presigned URLs) and surface-area discipline (malformed rule acceptance, malformed effect crash). LOWs are connection-leak pattern (gets worse in Stage 2), wildcard-syntax drift from AWS IAM, partial 0o700 enforcement, missing `iam-jit bouncer` pointer subcommand, and docstring-drift on Stage-2 promises.

Recommended pre-Stage-2 fix sequence:

1. **CRIT-23-01**: replace `host_lc.split(".s3", 1)[0]` with a `.amazonaws.com`-anchored regex; add tests for buckets named `my.s3.bucket-name` / `my.s3-test` / dual-stack / accelerate / access-point hosts.
2. **HIGH-23-01**: extend the S3 sub-resource table with `tagging`, `cors`, `notification`, `logging`, `requestPayment`, `website`, `replication`, `inventory`, `accelerate` (verify exact case of each query-parameter name against AWS docs); add a parameterized test that walks all entries.
3. **HIGH-23-02**: change `DecisionRecord` to carry the matched rule's id (or thread the id through `RuleSet.evaluate` and the `decide` composer); update `decide_cmd --record` accordingly; add a test that records a decision via the CLI flow and asserts `matched_rule_id` is the correct rule's row id.
4. **MED-23-01**: add a SQLite CHECK constraint on `rules.effect` AND a try/except in the loader for forward-compat with new Effect values.
5. **MED-23-02**: validate `pattern` in `rules add` up-front (call `parse_pattern`); reject with exit 2 on None. Also gate at `store.add_rule`.
6. **MED-23-03**: extend `_SIGV4_AUTH_RE` to accept `AWS4-ECDSA-P256-SHA256`; add a test fixture and a region=`*` normalization.
7. **MED-23-04**: extend `extract_service_and_region` to look in `X-Amz-Credential` query parameter when Authorization header is absent.
8. **LOW-23-01**: add `__enter__`/`__exit__` to `BouncerStore` and use `with BouncerStore(db_path=db) as store:` in every CLI command — primes the pattern Stage-2 proxy will follow.
9. **LOW-23-02**: replace `fnmatch.fnmatchcase` with a small custom glob-to-regex helper that supports only `*` and `?`; OR document the `[abc]` extension explicitly in IAM-JIT-BOUNCER.md.
10. **LOW-23-03**: chmod each created parent + the SQLite db file to 0o700/0o600; OR drop the "0o700" claim from the docs.
11. **LOW-23-04**: add `iam-jit bouncer` stub command that points at the `iam-jit-bouncer` binary.
12. **LOW-23-05**: replace "Coming in Stage 2" with a concrete tracked-issue link (or remove the claim).

After fixes ship, re-run audit (Round 24) — recommended scope: the Stage-2 HTTP proxy server when it lands, plus a re-probe of CRIT-23-01 and HIGH-23-01 against a moto-based S3-bucket-list-with-`.s3`-in-name fixture to confirm the parser-level fix holds end-to-end.

The bouncer's foundation is well-shaped at the data-model / decision-logic layer — those layers had zero findings. The bug pattern is concentrated in (a) the AWS wire-format parser (the highest-leverage component because every downstream decision depends on its classification) and (b) the CLI-to-store wiring (which doesn't pass through the matched-rule id). Both are mechanical fixes; neither requires re-architecture. The CRIT is the only finding that could enable a security bypass under realistic usage.

---

## WB23 closures (2026-05-17)

All 12 findings addressed in one commit per user direction (combined
audit closure + [[agent-friendly-not-bypassable]] layer so both get
verified together).

### Updated closure table

| Finding | Status | How closed |
|---|---|---|
| CRIT-23-01 S3 vhost bucket parser | **CLOSED** | Rewrote `_S3_VHOST_SUFFIX_RE` to require the prefix segment be exactly `s3` or `s3-<x>` and use a negative lookahead `(?!s3(?:\.|-|$))` in the middle quantifier so another `.s3.` segment can't be absorbed. Now `my.s3.bucket-name.s3.<region>.amazonaws.com` extracts bucket=`my.s3.bucket-name` correctly. Added 6 regression tests covering bucket-name-with-dots3 + the attacker-controlled-pseudo-bucket scenario + dualstack/accelerate/FIPS endpoints. |
| HIGH-23-01 S3 sub-resource table | **CLOSED** | Expanded from 5 to 18 sub-resources covering tagging/cors/notification/logging/requestPayment/website/replication/inventory/accelerate/publicAccessBlock/ownershipControls/object-lock/intelligent-tiering. Both object-level and bucket-level variants where applicable. Case-insensitive query-key lookup (AWS accepts `?Tagging` and `?tagging`). 11 parameterized regression tests verify each sub-resource resolves to its specific IAM action. |
| HIGH-23-02 CLI decide drops matched_rule_id | **CLOSED** | CLI `decide` now matches the parsed `record_obj.matched_rule` against the id-tagged ruleset and forwards the id to `record_decision(record_obj, matched_rule_id=...)`. Regression test asserts the persisted row has the rule id, not NULL. |
| MED-23-01 malformed effect crashes list_rules | **CLOSED** | `list_rules` wraps `Effect(effect)` in try/except; bad rows are logged and skipped instead of crashing the entire listing. Other rules remain usable. Regression test inserts a corrupt row directly via sqlite3 and confirms list_rules returns the valid rows. |
| MED-23-02 malformed pattern silently no-ops | **CLOSED** | `add_rule` validates pattern via `parse_pattern` before insert; raises `InvalidRuleError` on malformed. CLI `rules add` catches + exits with stderr message. Tests at both store and CLI layer. |
| MED-23-03 SigV4a not recognized | **CLOSED** | `_SIGV4_AUTH_RE` extended to accept both `AWS4-HMAC-SHA256` and `AWS4-ECDSA-P256-SHA256`. Regression test confirms MRAP credential headers parse. |
| MED-23-04 presigned URL signature in query | **CLOSED** | `extract_service_and_region` accepts an optional `query` kwarg and falls back to `X-Amz-Algorithm` + `X-Amz-Credential` query params when no Auth header is present. `parse_request` forwards query through. Regression tests for happy path + truly-anonymous (which still returns None — Stage 2 caller must default-deny). |
| LOW-23-01 CLI never closes store | **CLOSED** | Added `_opened_store` context manager; every CLI handler uses it via `with`. Eliminates per-invocation connection leak (important for the Stage-2 long-running proxy). |
| LOW-23-02 fnmatch supports `[abc]` classes | **CLOSED** | Replaced `fnmatch.fnmatchcase` with a custom `_aws_glob_match` that only honors `*` and `?` (AWS IAM policy spec). Literal `[` and `]` chars are escaped through `re.escape`. Tests verify `[Aa]` matches only the literal string, not character-class semantics. |
| LOW-23-03 mkdir mode applies only to leaf | **CLOSED** | `BouncerStore.__init__` walks the dir chain from the leaf upward and chmods each segment we created to 0o700, stopping at HOME. Best-effort (won't crash on filesystems that ignore POSIX modes). |
| LOW-23-04 `iam-jit bouncer` no pointer | **CLOSED** | Added an `@main.command("bouncer")` stub on the main iam-jit CLI that echoes "iam-jit-bouncer is shipped as a separate binary; run: iam-jit-bouncer ..." to stderr and exits 2. Per [[four-products-one-brand]] the bouncer keeps its own binary; this is just a discovery aid. |
| LOW-23-05 Stage 2 promise without task | **CLOSED** | Stage 2 explicitly documented in the audit doc + `docs/IAM-JIT-BOUNCER.md` agent-friendly section; tracked via task #160 (still in_progress) until proxy server lands. |

### What additionally shipped (Lens A + Lens B agent-friendly layer)

Beyond closing the 12 audit findings, this commit adds the
[[agent-friendly-not-bypassable]] layer per user direction
2026-05-17:

**Lens A (agent-friendly):**
- **9 new MCP tools** (`bouncer_list_rules`, `bouncer_add_rule`,
  `bouncer_remove_rule`, `bouncer_decide`, `bouncer_list_presets`,
  `bouncer_show_preset`, `bouncer_apply_preset`,
  `bouncer_tail_events`, `bouncer_tail_decisions`). Every CLI
  command has an MCP mirror. Agents configure without shelling out.
- **4 curated preset baselines** in `bouncer/presets.py`:
  `readonly` / `admin-minus-sensitive` / `prod-deny-destructive` /
  `deny-iam-admin`. Agents start from a vetted preset and narrow,
  instead of authoring from scratch.
- **Self-describing denials**: `bouncer_decide` adds a
  `how_to_allow` field to denied responses with the exact MCP call
  the agent should make to fix it.
- **CLI subcommands**: `init --preset`, `presets list|show|apply`,
  `events tail` (with `--kind` filter).
- **`*:Action` and bare `*` pattern support**: cross-service deny
  patterns (`*:Delete*`, `*:Terminate*`) now valid, enabling the
  `prod-deny-destructive` preset shape.

**Lens B (uncircumventable):**
- **New `config_events` SQLite table** (schema v2; additive
  migration). Every config mutation writes here.
- **`record_mode_change` / `record_preset_applied` / wired-in
  `add_rule` / wired-in `remove_rule`**: all mutations write
  config events.
- **`remove_rule` captures FULL prior content** in the event detail
  so an agent can't rules-add-then-remove to cover its tracks —
  the audit chain still shows what existed.
- **`_current_actor()` helper**: reads `IAM_JIT_BOUNCER_ACTOR` env
  if set (lets agents identify themselves), else OS username. No
  way to write an event without an actor.
- **Audit-chain invariant test**: `test_lens_b_no_silent_bypass_mcp_tool`
  fails if anyone adds a `bouncer_disable` / `bouncer_skip` /
  `bouncer_clear_audit` tool. CI-enforced.

### Verification

- `tests/bouncer/*` grew from 109 → 185 tests (+76). All pass.
- Broader suite: **2284 passed**, 29 skipped, 14 deselected (was 2208
  before WB23 + agent-friendly changes; +76 net tests).
- `iam-jit-bouncer init --preset readonly --db /tmp/x.db` smoke-test
  applied 23 rules and wrote a `preset_applied` event.
- `iam-jit bouncer` (the pointer) exits 2 with the redirect message
  to stderr.

### What WB23 DID NOT do (deferred-with-rationale)

- **No moto-based integration test** for the boto3 paths. The
  hand-rolled fixtures now mirror real AWS shapes correctly; moto
  closure deferred to Round 24+ when Stage 2 ships the HTTP proxy
  server.
- **No `mode set` CLI command yet** — the helper `record_mode_change`
  exists in the store but Stage 1 doesn't surface a CLI for it
  because there's no actual proxy enforcing mode yet. Wires in
  Stage 2.
- **Per-account / per-session source registry** as a `ContextVar`
  remains deferred (mirrors WB22 MED-22-01 deferral pattern).

### Why this round matters

WB23 found a CRIT that would have been a real security bypass under
realistic usage (attacker-controlled bucket names extracting wrong
ARNs). It also forced the conversation that produced the
[[agent-friendly-not-bypassable]] memory — the central UX framing
that shapes every iam-jit feature going forward. The combined
closure commit demonstrates the principle in code: every CLI knob
has an MCP equivalent, every config change writes to an audit
chain, every denial includes a path to compliance. The pattern
generalizes beyond the bouncer.

Per [[audit-cadence-discipline]]: 1 CRIT + 2 HIGH + 4 MED + 5 LOW
caught in code that had 109 passing unit tests. The audit ROI keeps
compounding; the test gap that let the CRIT through (test fixture
encoding the same assumption as the bug) was itself closed by the
realistic-fixture rewrite.
