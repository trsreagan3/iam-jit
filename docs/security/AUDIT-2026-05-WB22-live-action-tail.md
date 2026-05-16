# Round 22 audit — Live action tail OSS scaffolding (#157)

Commit under review: `89b6435` (`feat(live-action-tail): OSS scaffolding for grant session CloudTrail tail (#157)`).

Scope: `src/iam_jit/live_action_tail.py` (334 LOC) + `src/iam_jit/live_action_tail_cloudtrail.py` (238 LOC) + `src/iam_jit/mcp_server.py` (+172 LOC: `tail_grant` tool + `_tail_grant_for_mcp` + dispatch + docstring) + `src/iam_jit/cli.py` (+138 LOC: `tail` subcommand + `mcp-server` docstring update) + `tests/test_live_action_tail.py` (324 LOC) + `tests/test_live_action_tail_cloudtrail.py` (328 LOC) + `tests/test_live_action_tail_mcp.py` (232 LOC). Read-only audit. Per [[audit-cadence-discipline]].

Regression: **2086 passed, 29 skipped, 14 deselected** (88s, excluding `tests/e2e/*` which needs `playwright`, and `tests/test_calibration_corpus.py` which has the well-known pre-existing failures). Matches the audit-prompt baseline exactly.

## Headline

9 findings: **1 CRIT, 1 HIGH, 3 MED, 4 LOW.**

The single most-important finding is **CRIT-22-01**: the `CloudTrailLookupSource` filters CloudTrail by `LookupAttributes: [{AttributeKey: "Username", AttributeValue: "iam-jit-provision-{request_id}"}]`. This is the session name iam-jit uses when IT assumes the customer's **provisioner role** to CREATE the JIT role — it is NOT the session name the end-user (or the agent) uses when THEY assume the issued JIT role. iam-jit does not constrain the end-user's `RoleSessionName` (no `sts:RoleSessionName` Condition on the trust policy, no `sts:SourceIdentity` requirement). The end-user picks an arbitrary session name when they call `STS:AssumeRole`. As a result, the `Username` filter matches a tiny window of iam-jit's own provisioning activity (the `iam:CreateRole` / `iam:PutRolePolicy` calls iam-jit made during role creation, made as `iam-jit-provision-{request_id}`) — and matches ZERO of the end-user's downstream API calls under the JIT role.

The feature's headline promise — "what is alice's agent doing right now with the grant I approved 10 min ago?" — cannot work with this implementation. Every CloudTrail tail returns either empty or only iam-jit's own provisioning footprint. The InMemory test source masks this because the test fixture's `session_name` is set to `"iam-jit-provision-grant-1"` — i.e. the test agrees with the bug.

The HIGH (audit log doesn't record that an admin tailed a grant) is the next-most-important fix; without it, the `tail_grant` action becomes the only admin-on-grant action with no audit trail, breaking the broader iam-jit audit-chain invariant. The four MEDs are: (1) `set_default_source` is a process-wide global with no thread/tenant isolation; (2) the `CloudTrailLookupSource` describe() claim "lag~15min, retention=90d" only matches if a multi-region trail is configured — in default single-region installs this can be much shorter retention; (3) error surface honesty — `[]` is indistinguishable from CloudTrail error; (4) the test suite never asserts that `Username=<session_name>` is the correct CloudTrail filter for the end-user's calls (the CRIT). LOWs are pagination spin under empty-events + NextToken, hard-cap interaction subtleties, missing per-element type validation, and DynamoDBStore.get not regex-validating grant_id.

The MCP / CLI plumbing, dispatch wiring, input validation, parsing helpers, and formatting are clean. The bug is structural, in the AWS-IAM semantic mapping — exactly the category the audit prompt called out as the most-impactful place to probe.

## Closure status

| Finding | Status |
|---|---|
| CRIT-22-01 `CloudTrailLookupSource.fetch_events` filters by `Username=iam-jit-provision-{request_id}` — this is iam-jit's provisioner session, NOT the end-user's session under the issued JIT role; tail returns ~zero real events for the feature's intended use case | OPEN |
| HIGH-22-01 `tail_grant` (MCP + CLI) does NOT append to `status.history` or any audit log; an admin can read a grant's session activity without leaving an audit trail; violates the broader iam-jit "every admin-action-on-grant is logged" invariant | OPEN |
| MED-22-01 `_active_source` is a process-wide module global; in any multi-threaded process (FastAPI, MCP server, test parallelism) one thread's `set_default_source` clobbers all other threads; verified by repro | OPEN |
| MED-22-02 `CloudTrailLookupSource.describe()` claims `retention=90d`; this is only true when a CloudTrail Event history is enabled (the default per-region) — in installs that use only a custom trail to S3, `LookupEvents` retention may differ. Claim is partly install-dependent | OPEN |
| MED-22-03 `CloudTrailLookupSource.fetch_events` silently swallows `Exception` (client init AND lookup_events) and returns `[]`; caller cannot distinguish "no activity" from "AccessDenied / rate-limit / network error". CLI's `# (no events — ...)` message implies the former; same MCP response shape for both | OPEN |
| LOW-22-01 Pagination loop with HARD_MAX_EVENTS=1000 + empty `Events` + non-empty `NextToken` issues up to 20 API calls per `fetch_events` (verified). At 2 TPS rate limit, this can monopolize CloudTrail quota for a region for ~10s on a misbehaving session window | OPEN |
| LOW-22-02 `_tail_grant_for_mcp` validates that `selected_item_ids`-shaped fields are strings, but does NOT regex-validate `grant_id` against the store's `^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$` pattern before calling `store.get`; for `FilesystemStore` / `S3Store` this is caught one layer down (their `_path` / `_key` validates), but `DynamoDBStore.get` does NOT validate — verified | OPEN |
| LOW-22-03 `tail_cmd` CLI exits 0 with "no events" message on the success-empty AND on every error path that `CloudTrailLookupSource` swallows to `[]` (AccessDenied, rate-limit, etc.); the CLI can't differentiate, so monitors / wrapper scripts see "success" on real failures | OPEN |
| LOW-22-04 No test asserts that the CloudTrail `Username` LookupAttribute is the correct filter for the end-user's session under the issued JIT role; the existing assertion (`Username=iam-jit-provision-req-1`) verifies internal consistency but encodes the CRIT-22-01 bug; same shape as the WB21-MED-03 test-coverage gap | OPEN |

## CRIT findings

### CRIT-22-01 — `CloudTrailLookupSource` filters by iam-jit's provisioner session, not the end-user's session

- File: `src/iam_jit/live_action_tail_cloudtrail.py:113-114` (filter), `src/iam_jit/live_action_tail.py:277-285` (TailQuery construction), `src/iam_jit/provision.py:463,559,669` (provisioner session_name origin), `src/iam_jit/provision.py:214-235` (trust policy lacks `sts:RoleSessionName` Condition)

- Issue: the CloudTrail filter strategy:
  ```python
  params: dict[str, Any] = {
      "LookupAttributes": [
          {"AttributeKey": "Username", "AttributeValue": query.session_name}
      ],
      ...
  }
  ```
  `query.session_name` comes from `status.provisioned.session_name`, which `mark_provisioned` populates from `ProvisioningResult.session_name`, which `provision.py` populates from:
  ```python
  session_name = f"iam-jit-provision-{request_id}"[:64]  # provision.py:463, 559
  ```
  This `session_name` is the `RoleSessionName` iam-jit uses when IT calls `sts:AssumeRole` into the **customer's provisioner role** to perform `iam:CreateRole` + `iam:PutRolePolicy` + `iam:TagRole` (the steps that CREATE the JIT role).

  This `session_name` is NOT the `RoleSessionName` the end-user (or their agent) uses when they call `sts:AssumeRole` to enter the **issued JIT role**. iam-jit does not constrain the end-user's session name:
  - The trust policy at `provision.py:214-235` Allows `sts:AssumeRole` from `assumer_arn` with only a `DateLessThan` time condition — there is NO `sts:RoleSessionName` String/Regex Condition that would force the end-user to use a specific session name.
  - There is no `sts:SourceIdentity` Condition either.
  - The role is created with `MaxSessionDuration` but the end-user passes whatever `RoleSessionName` they like (typically their IAM identity name, e.g. `alice@example.com` or `cli-session-2026-05-17`).

  CloudTrail's `Username` LookupAttribute for an `AssumedRole` userIdentity = the `RoleSessionName` from the AssumeRole call. So:
  - `Username=iam-jit-provision-{request_id}` matches CloudTrail events where the assumed-role session WAS `iam-jit-provision-{request_id}` — i.e. events made by **iam-jit itself** during the few seconds of role creation. (e.g. the `iam:CreateRole` call iam-jit emitted as it assumed the provisioner role.)
  - `Username=iam-jit-provision-{request_id}` does NOT match CloudTrail events made by the end-user under the issued JIT role, because the end-user's session has a different name.

- Verified by reading code, NOT by running against real CloudTrail. The hand-rolled test fixture at `tests/test_live_action_tail_mcp.py:55` sets `session_name: "iam-jit-provision-grant-1"` — i.e. the test agrees with the implementation. The InMemory source matches events whose `session_name` equals the query's `session_name`; both are the iam-jit-provisioner value, so the test "passes" while encoding the bug.

- Impact: the feature's stated use case ("what is alice's agent doing right now with the grant I approved 10 min ago?") cannot work. An admin who tails a grant will see either (a) empty results, or (b) a small handful of iam-jit's own `iam:CreateRole` / `iam:TagRole` / `sts:AssumeRole` (into provisioner) calls — none of which are the end-user's actual API activity. The CLI and MCP descriptions promise the end-user's activity. Headline trust-gap.

- Why CRIT not HIGH: the feature does not work at all for its stated purpose. Unlike WB21-HIGH-01 (where the checklist item produced a no-op policy but the rest of the system still worked correctly), this CRIT means the entire `tail_grant` MCP tool + `iam-jit tail` CLI return effectively nothing for any real grant. It's a complete-feature-doesn't-work scenario, not a partial one.

- Three fix paths:
  1. **Best**: change the filter to look up by the actual end-user session. Two ways:
     - **(a)** Filter by `LookupAttributes: [{AttributeKey: "ResourceName", AttributeValue: "<issued-role-name>"}]` — this finds CloudTrail events where the issued JIT role itself is the user identity (i.e. all `AssumedRole` events under the role, regardless of the session name the end-user chose). This is the correct shape for "show me everything the issued role did." Role-name is in `status.provisioned.role_name`; `TailQuery.role_name` already carries it.
     - **(b)** Filter by `LookupAttributes: [{AttributeKey: "AccessKeyId", AttributeValue: "<sts-temp-key-id>"}]` — surgical to one session, but requires capturing the AccessKeyId from the user's AssumeRole call back into iam-jit's grant record. Not viable without a return-trip from the user; (a) is the practical fix.
  2. **Acceptable as v1**: keep the current filter for "what iam-jit did during provisioning" and ADD a second `LookupAttributes` call (or a follow-up query) on `ResourceName=<issued-role-name>` for "what the end-user did under the role." Merge and de-dupe. Slightly more complex but covers both use cases.
  3. **Worst-but-honest**: until fixed, rewrite all descriptions (MCP tool, CLI help, docs/LIVE-ACTION-TAIL.md, `CloudTrailLookupSource.describe()`) to say "shows iam-jit's provisioning footprint, NOT the end-user's API activity. Use CloudTrail Lake / Athena directly for end-user activity until iam-jit ships the role-based filter." This is misery-honest and would tank the feature, but matches what the code does.

  Recommend fix path 1(a) before anything else lands on top of this scaffolding.

## HIGH findings

### HIGH-22-01 — `tail_grant` does not append to the grant's audit history

- File: `src/iam_jit/mcp_server.py:912-1018` (`_tail_grant_for_mcp`), `src/iam_jit/cli.py:635-712` (`tail_cmd`), `src/iam_jit/lifecycle.py` (the audit-history pattern used by every other admin action)

- Issue: every other admin action on an iam-jit grant — approve, reject, cancel, revoke, provision, mark-provisioning-failed, mark-revoked — appends a structured event to `request["status"]["history"]` via `_commit` / `_commit_system`. This is the iam-jit audit chain: "every change to a grant has a who+when+why entry in its history list."

  The `tail_grant` tool READS a grant's session activity but writes NOTHING. An admin can pull up the CloudTrail tail for any grant via MCP or CLI and leave no record that they did. Per the broader audit-chain invariant (used by `routes/reports.py`'s `audit_log_report`), this is the first admin-on-grant action that escapes the chain.

- Why HIGH: in incident review or compliance audit ("who accessed what session data when?"), the tail-tool reads are invisible. For tiered compliance frameworks (SOC 2 CC6.x audit-log requirements; PCI 10.x), this is a defensible gap to close before launch. The compromise scenario: an admin tails a grant where the agent did something sensitive, learns information, takes a follow-up action; the audit chain shows only the follow-up action, not the look-up that motivated it.

- Why not CRIT: the tail tool itself does not MUTATE anything (per [[creates-never-mutates]] the tool is read-only), so this is a observability/compliance gap, not a security breach. The grant's actual provisioned state is unchanged.

- Fix: append a structured event to `status.history` on each tail call. Suggested shape:
  ```python
  {
      "kind": "tail_read",
      "at": _now(),
      "actor": <caller identity from MCP/CLI context>,
      "tool": "tail_grant",
      "since": query.since,
      "until": query.until,
      "event_count": len(events),
      "source": source.describe(),
  }
  ```
  Lifecycle helper would be `lifecycle.record_tail_read(request, actor, query, source, event_count)` to match the existing pattern. This requires a `put` back to the store after the read, which adds a round-trip — acceptable for an admin-facing tool that's not in a hot loop.

  Alternative: write to a separate audit-log sink (e.g. CloudTrail's own data events on the request store, or an iam-jit-audit DynamoDB table) instead of mutating the request record. Either works; the constraint is "tail reads are visible after the fact."

- Edge: the current MCP/CLI flow has no clear "actor" identity to attribute the read to. MCP is stdio (single-user-per-process), CLI is invoking-user. The actor field would need to be plumbed from caller context (env var / stdin metadata / OIDC session if a future hosted variant). For OSS launch, "actor=local" is acceptable as a starting point; the audit entry's value is the existence of the record, not the identity precision.

## MED findings

### MED-22-01 — `_active_source` is a process-wide module global with no per-thread / per-tenant scoping

- File: `src/iam_jit/live_action_tail.py:314-334`

- Issue: the source registry uses a module-level `_active_source` variable, mutated by `set_default_source` and read by `get_default_source`. Verified repro (in main response): two threads racing `set_default_source` end up both reading whichever source was set last.

  Per [[no-hosted-saas]] iam-jit does not run multi-tenant SaaS, so the per-tenant scoping risk is low at launch. But:
  - The FastAPI request handler in `app.py` serves requests on multiple worker threads (uvicorn workers + asyncio loop). If two requests in parallel each set a source (e.g. one Pro-tier customer's bootstrap sets `CloudTrailLookupSource(region=us-east-1)` and another's bootstrap sets `region=eu-west-1`), they race.
  - The MCP server runs as a single stdio process — no per-thread risk there.
  - Test parallelism (`pytest -n auto`) would have isolation issues if any other test file uses the source registry without the `_reset_source_after_test` autouse fixture.

  The current OSS pattern (set source once at bootstrap; never mutate) avoids the race in practice. But the pattern is fragile — adding any "switch source per request" feature later (e.g. per-account `live_action_tail_policy` analogous to [[per-account-llm-policy]]) would surface the race immediately.

- Why MED: not exploitable today (single-tenant deploy, set-once-at-startup pattern), but the dataclass docstring and the public API suggest a more dynamic usage model than the implementation safely supports. Whoever writes the per-account source-override feature will hit this.

- Fix options:
  1. **Best**: scope the source via a context (ContextVar, request-scoped dependency injection) instead of a module global. Forces callers to pass context through, which is the correct shape for multi-account.
  2. **Acceptable**: lock the registry — make it set-once (raise on `set_default_source` if already set, unless explicitly cleared with a sentinel). Catches the dangerous case while preserving the simple API.
  3. **Worst**: leave as-is, document the "set once at bootstrap; never mutate at request time" constraint loudly in the docstring + LIVE-ACTION-TAIL.md.

### MED-22-02 — `CloudTrailLookupSource.describe()` "retention=90d" is install-dependent

- File: `src/iam_jit/live_action_tail_cloudtrail.py:80-84`

- Issue: the source's `describe()` returns:
  ```
  cloudtrail:LookupEvents (region=us-east-1, lag~15min, retention=90d)
  ```
  The `retention=90d` claim is the AWS CloudTrail **Event history** retention, which is the per-region 90-day history maintained by CloudTrail automatically (separate from a CloudTrail "trail"). That IS the data `LookupEvents` returns — `LookupEvents` queries Event history specifically. So the claim is technically correct for the API being called.

  BUT: many compliance-driven installs disable or reduce Event history (rare — it's free and on by default) OR rely on a long-retention trail to S3 + CloudTrail Lake / Athena for the actual queryable record. In such installs, `LookupEvents` works but only returns the standard 90 days regardless. The describe()'s "retention=90d" claim is correct for `LookupEvents` but doesn't reflect what the customer's organization actually retains.

  The bigger issue: customers tail this expecting "everything from the grant window" — and grants are typically <24h, so 90d retention is fine. But the customer's compliance team may believe the iam-jit tail is reading their forensic-trail data (it isn't — only Event history). Setting the wrong expectation.

  The docs/LIVE-ACTION-TAIL.md "Known caveats" section at line 124 does explain "`LookupEvents` only sees the last 90 days. Older events require CloudTrail Lake or a configured trail querying S3." So the docstring is consistent. The describe() string is just terse and could mislead.

- Why MED not LOW: this is a customer-facing string returned in every MCP response (`out["source"]`) and printed on every CLI run. It will be in screenshots and ticket replies. The same wording will be quoted back at iam-jit in compliance review.

- Fix: tighten the describe() string. Suggested:
  ```python
  return (
      f"cloudtrail:LookupEvents Event-history (region={self._default_region}, "
      f"lag up to ~15min, Event-history window 90d — for older events use "
      f"CloudTrail Lake / Athena against your trail's S3 destination)"
  )
  ```
  Longer but specific. Or shorter: `cloudtrail:LookupEvents Event-history (region={self._default_region})` and let the docs carry the lag/retention detail.

### MED-22-03 — `fetch_events` returns `[]` indistinguishably for "no activity" vs error

- File: `src/iam_jit/live_action_tail_cloudtrail.py:102-110, 131-140`

- Issue: two catch-all `except Exception` blocks:
  ```python
  try:
      client = self._client(region)
  except Exception as e:
      logger.warning("cloudtrail client init failed: %s", e)
      return []
  ...
  try:
      resp = client.lookup_events(**params)
  except Exception as e:
      logger.warning(...)
      break
  ```
  Both swallow the exception and produce `[]`. The caller (`_tail_grant_for_mcp`, `tail_cmd`) sees an empty list and prints `# (no events — check that the source is configured and that the session window contains activity)`. There is no signal that an error occurred — only a log line that admins won't see unless they're tailing iam-jit's logs concurrently.

  Common failure modes that get silenced:
  - boto3 import error / missing credentials → empty + log
  - `AccessDeniedException` on `cloudtrail:LookupEvents` → empty + log
  - `ThrottlingException` (CloudTrail's 2 TPS limit) → empty + log
  - Network error / region typo → empty + log
  - boto3 lazy-import `ImportError` (per the audit prompt's concern #8) → empty + log

  The user sees `# events: 0` followed by a "no events" hint. Their natural inference is "the agent did nothing in that window" — wrong. The correct inference would be "the source errored; check logs."

- Why MED: documented failure-mode-hiding is a known design choice for the OSS layer (the comment at line 105-108 says "fail soft: surface as an empty result + a logged warning so callers can show the user a 'couldn't reach CloudTrail' banner without crashing"). But the callers (MCP + CLI) do NOT show that banner — they treat empty as success. The contract is asymmetric: source admits "I might have erred"; callers don't propagate.

- Fix: return a structured "result" from `fetch_events` instead of a bare `list`:
  ```python
  @dataclass(frozen=True)
  class TailResult:
      events: list[LiveActionEvent]
      ok: bool
      error: str | None
  ```
  Then `_tail_grant_for_mcp` and `tail_cmd` can surface `result.error` separately from `result.events`. Exit code 3 on the CLI for "source errored"; structured `"warning"` field in MCP response.

  Alternative: keep the list return but ALSO pass through a `source_status` field (or set it on the source instance and `describe()` it). Less invasive but more state-y.

## LOW findings

### LOW-22-01 — Pagination spin with HARD_MAX_EVENTS + empty pages + NextToken

- File: `src/iam_jit/live_action_tail_cloudtrail.py:123-151`

- Issue: `max_pages = max(1, (max_events + 49) // 50)`. For `max_events=1000` (the hard cap), `max_pages=20`. If CloudTrail returns pages where `Events` is empty but `NextToken` is non-empty (legal per the API — happens under eventual consistency or when the underlying lookup matches nothing), the loop iterates 20 times before exiting.

  Repro (verified in main response): 20 API calls per `fetch_events` for `max_events=1000` with an always-empty-with-token client. At the documented 2 TPS rate limit, 20 calls = ~10 seconds of CloudTrail quota consumed for a single tail request. Multiplied by per-grant tail traffic, can hit the rate limit.

  Pagination correctness: for `max_events ≤ 50`, max_pages=1 → 1 API call max. For `max_events=51..100`, max_pages=2. For 999..1000, max_pages=20. Math is correct; the loop bound is honored.

- Why LOW: not a correctness bug; the loop terminates. Cost/quota concern only. Hard cap on max_pages already exists.

- Fix: add an early-exit when `Events` is empty for two consecutive pages, OR when a page returns empty and `NextToken` matches the previous token (signals "nothing new will come of this"). Lazy fix: lower `max_pages` to e.g. `min(20, (max_events + 49) // 50)` — already at 20 for the worst case, so this is a no-op.

  Better: track total empty-page count and bail after N=3 consecutive empties.

### LOW-22-02 — `_tail_grant_for_mcp` does not regex-validate `grant_id` before passing to `store.get`

- File: `src/iam_jit/mcp_server.py:925-930, 965-973`, `src/iam_jit/store.py:38-44`, `src/iam_jit/store.py:316-321` (`DynamoDBStore.get` no validation)

- Issue: `_tail_grant_for_mcp` validates `grant_id` is a non-empty string, then strips it and passes to `store.get(grant_id.strip())`. The store-layer regex `^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$` is enforced by:
  - `FilesystemStore.get` → calls `self._path(request_id)` → calls `_validate_request_id` ✓
  - `S3Store.get` → calls `self._key(request_id)` → calls `_validate_request_id` ✓
  - `DynamoDBStore.get` → calls `self.table.get_item(Key={"request_id": request_id})` → does NOT validate ✗

  Verified repro: `DynamoDBStore.get("../../../etc/passwd")` passes the literal string to DynamoDB. (Practically low-risk: DynamoDB doesn't filesystem-traverse, and the returned `NotFoundError` is raised with the literal string back to the caller.) But the docstring at `store.py:30-33` says "Enforced at every store operation — a bug elsewhere that lets a non-conformant id through ... doesn't reach the filesystem / S3 key." DynamoDB silently violates that invariant.

- Why LOW: not exploitable through the new code (the filesystem/S3 stores validate; DynamoDB has its own injection-resistant key encoding). But the new code surfaces the inconsistency — every other store-using callsite in iam-jit makes the same assumption.

- Fix: add `_validate_request_id(request_id)` at the top of `DynamoDBStore.get` (and `delete`, `exists` — for consistency). One-line fix at the store layer; pre-existing to #157 but worth filing.

  Alternative: validate at the `_tail_grant_for_mcp` layer (and `tail_cmd`) by importing the store's regex. Belt-and-suspenders — slightly defensive but couples the MCP layer to the store's regex implementation.

### LOW-22-03 — CLI exits 0 on "no events" regardless of whether the source errored

- File: `src/iam_jit/cli.py:704-709`

- Issue: `tail_cmd`'s success-path:
  ```python
  events = source.fetch_events(query)
  click.echo(...)
  if not events:
      click.echo("# (no events — check that the source is configured ...)")
      return  # exits 0
  ```
  Whether `events` is empty because the session window genuinely had no activity, OR because `CloudTrailLookupSource` caught an `AccessDeniedException` and returned `[]`, OR because boto3 isn't installed, the CLI prints the same message and exits 0.

  Wrapper scripts and `iam-jit tail ... | grep FAIL` pipes will see "all good" on real errors. Same shape as MED-22-03 from the caller's side.

- Why LOW: depends on the fix for MED-22-03 (the source needs to expose error state for the CLI to act on it). Filed separately so it isn't lost.

- Fix: once MED-22-03 produces a structured result, exit 3 (or similar non-2 non-success) for "source errored." Differentiates from exit 2 (validation / setup error) and exit 0 (real "no activity").

### LOW-22-04 — No test asserts that `Username=<session_name>` is the correct CloudTrail attribute

- File: `tests/test_live_action_tail_cloudtrail.py:175-191`

- Issue: the existing test asserts:
  ```python
  assert call["LookupAttributes"] == [
      {"AttributeKey": "Username", "AttributeValue": "iam-jit-provision-req-1"}
  ]
  ```
  This verifies the implementation passes the value it computed — internal consistency. It does NOT verify that `Username` is the correct AttributeKey for finding the end-user's CloudTrail events under the issued JIT role. The test passes today because both the code and the test agree on the wrong value (the iam-jit-provisioner session name).

  Same shape as WB21-MED-03 ("test suite verifies mechanics, not description claims"). The test mechanically asserts what the code does; what the code does is wrong (CRIT-22-01); the test cannot catch the bug.

- Why LOW (not MED like WB21-MED-03): the test-coverage gap here is downstream of CRIT-22-01 — fixing the CRIT will require updating this test, at which point the right assertion is "encoded automatically." Filed separately so it isn't forgotten.

- Fix: parameterize a test over `(query.session_name, query.role_name) → expected LookupAttributes` that encodes the corrected filter. The test should fail today (forcing the CRIT fix) and pass once the fix lands.

  Even better: a contract test that documents which CloudTrail LookupAttribute matches which userIdentity field, so future audits can verify by name rather than by encoded string.

## Verified clean

The following were probed per the audit prompt and found no issues:

- **Boto3 lazy-import** (concern #8): `live_action_tail_cloudtrail.py` imports boto3 inside `_session()`. Verified: a user with iam-jit installed without boto3 gets an `ImportError` at first `fetch_events` call, caught by the outer `except Exception` and surfaced as `logger.warning("cloudtrail client init failed: ...")` + empty list. No import-time crash. (Interacts with MED-22-03 for surface honesty.)

- **Timezone correctness** (concern #9): `_parse_iso8601` returns tz-aware datetime. Verified boto3 accepts tz-aware datetimes for CloudTrail's `StartTime` / `EndTime` parameters (botocore serializer handles both naive-UTC and tz-aware via `.isoformat()`).

- **Resource list extraction** (concern #10): `_parse_cloudtrail_event` reads top-level `Resources`, defaulting to `[]` when absent. `format_event_summary` handles empty resources cleanly (no resource section in output). Verified.

- **Pagination math** (concern #11): worked example `max_events ∈ {1, 50, 51, 100, 999, 1000}` → `max_pages ∈ {1, 1, 2, 2, 20, 20}`. Math correct. `[:max_events]` final slice always truncates to the exact requested cap. No off-by-one.

- **Hard cap correctness** (concern #5): `_tail_grant_for_mcp` caps at `min(max_events, 1000)`. `CloudTrailLookupSource.fetch_events` caps at `min(query.max_events, HARD_MAX_EVENTS=1000)`. Both code paths enforce. Pagination loop exits when `len(collected) >= max_events`. Verified.

- **Input validation depth** (concern #6 partial): grant_id type check + non-empty check happen in `_tail_grant_for_mcp` before `store.get`. For FilesystemStore + S3Store, the store-layer regex validates. For DynamoDB, see LOW-22-02. Side fields (`since`, `until`, `aws_region`) all type-checked. `bool` correctly rejected for `max_events` (because `bool` is subclass of `int`).

- **bool-vs-int rejection** (subtle Python gotcha): `_tail_grant_for_mcp` has `if not isinstance(max_events, int) or isinstance(max_events, bool)` — correctly rejects `True` / `False` as `max_events`. Test coverage at `tests/test_live_action_tail_mcp.py:124-127` confirms.

- **NullLiveActionTailSource.describe()** (concern #1 subset): claim "no live-action source configured" is honest; the source returns `[]` and the describe() string explicitly tells the user how to wire a real source. Test coverage at `tests/test_live_action_tail.py:84-85`.

- **`mcp_server_cmd` docstring update** (concern #15): verified the 1.8% reference IS removed from the `mcp-server` CLI docstring (the diff at lines 154 of the cli.py diff confirms). `docs/LIVE-ACTION-TAIL.md` is also clean of 1.8% — verified. (Two OTHER 1.8% references in `src/iam_jit/cli.py` at lines 82 and 259 are PRE-EXISTING and not in the #157 diff — separate cleanup item; out of audit scope but worth flagging for a follow-up commit that scrubs them per [[no-one-eight-percent-mention]].)

- **`extract_tail_inputs_from_grant`** (concern #1 subset, partial): does populate `since` from `tags.provisioned-at` OR history fallback. Does populate `until` from `expires_at`. Returns None when required fields are missing. Handles non-dict input. Test coverage adequate (`tests/test_live_action_tail.py:258-298`). The CLI's `--since` / `--until` defaults to the grant's provisioned-at / expires_at — verified.

- **MCP dispatch wiring**: `tail_grant` is in `TOOLS` (test: `test_tail_grant_appears_in_tools_list`), dispatched in `_handle_request` (test: `test_dispatch_tail_grant`), response shape uses `structuredContent` correctly per MCP convention.

- **Cross-grant authorization** (concern #3): MCP server has NO authz layer (verified — no `authorize`, `require_admin`, `check_caller` calls in `mcp_server.py`). Per MCP design, the stdio server is single-user-per-process; the host (Claude Desktop, Cursor) restricts access. So "user passes arbitrary grant_id to read someone else's tail" is structurally prevented by the deployment model, not by code. Worth documenting in `LIVE-ACTION-TAIL.md` as a "if you expose iam-jit MCP server via remote transport, add a proxy auth layer" caveat. NOT a code finding; design-by-deployment.

- **`InMemoryLiveActionTailSource` session-name matching**: events with `session_name=None` are treated as match-any (`test_in_memory_source_session_none_matches_any`). Convenient for test instrumentation, but the predicate-OR semantics could surprise; documented in the docstring at line 169-173. Acceptable.

- **`format_event_summary` malformed time**: gracefully falls back to literal or `??:??:??Z`. Test coverage at line 205-208. No crash.

## Forward-compat & AWS-IAM-semantics specifically asked about

**Q: "Is `Username` the right CloudTrail LookupAttribute for assumed-role session names?"**

YES — `Username` for an `AssumedRole` userIdentity in CloudTrail Event history is exactly the `RoleSessionName` from the AssumeRole call. The bug is NOT the AttributeKey; the bug is that iam-jit's `query.session_name` is the wrong session_name (it's the iam-jit-provisioner session, not the end-user's session). See CRIT-22-01.

If the goal had been "find all events made by the JIT role regardless of who assumed it with what session name," the right attribute is `ResourceName=<role-name>` (or `ResourceType=AWS::IAM::Role` + `ResourceName=<role-name>`). See CRIT-22-01 fix path 1(a).

**Q: "Does `userIdentity.sessionContext.sessionIssuer.userName` parsing match the actual CloudTrail event shape?"**

YES, for `AssumedRole` userIdentity entries. AWS CloudTrail's userIdentity element for an assumed-role action carries `sessionContext.sessionIssuer.userName` = the role's name (NOT the session name). So the field iam-jit extracts as `session_name` in `_parse_cloudtrail_event` is actually the **role name**, not the session name. The field name `session_name` on `LiveActionEvent` is misleading — but the value is what would correctly filter "events under role X" semantically. The mismatch is in the naming; the extraction itself works.

This compounds with CRIT-22-01: the InMemory source filter (`e.session_name == query.session_name`) is checking that the parsed `sessionIssuer.userName` (the ROLE name, e.g. `iam-jit-grant-1`) equals the query's `session_name` (the iam-jit-provisioner SESSION name, e.g. `iam-jit-provision-grant-1`). They will NEVER match in real CloudTrail data, regardless of how the LookupAttributes filter is configured.

In the test fixture both happen to be set to `iam-jit-provision-grant-1` (lines 51-55 of `test_live_action_tail_mcp.py`) because the test was written without consulting the real CloudTrail event shape. Fix CRIT-22-01 by realigning both the LookupAttributes call AND the InMemory filter to the correct concept (role-name vs session-name; pick one and use consistently).

**Q: "Could a user pass an arbitrary grant_id and get events for someone else's grant?"**

In OSS MCP-over-stdio mode, NO — the MCP server has one user-process, no authz layer needed. Same answer for `iam-jit tail` CLI (it runs as the calling shell user).

In a hypothetical hosted variant (which iam-jit does not ship per [[no-hosted-saas]]), YES — there is no per-grant authz check in `_tail_grant_for_mcp`. Anyone with MCP access could fetch any grant's session activity. This is structurally prevented by the deployment model (one-process-per-user for MCP; one-shell-session-per-user for CLI). Worth documenting as a "if you build a remote MCP variant, add authz" caveat. Not a code finding under current deployment shape.

**Q: "Does `set_default_source` survive multi-process / multi-tenant deployment?"**

NO — see MED-22-01. Module-global, no per-thread or per-tenant scoping. For OSS launch this is fine (set-once-at-startup pattern). For any future per-account or per-tenant override, it needs a context-variable rework.

## Regression check

Command run: `cd /Users/reagan/repos/iam-roles && .venv/bin/python -m pytest --no-header -q --ignore=tests/test_calibration_corpus.py --ignore=tests/e2e 2>&1 | tail -5`

Result:
```
2086 passed, 29 skipped, 14 deselected, 2 warnings in 88.01s (0:01:28)
```

Matches the audit-prompt baseline. The 96 pre-existing `tests/test_calibration_corpus.py` failures are unchanged (not run; not caused by #157). All new tests in #157 pass.

## Summary

**1 CRIT, 1 HIGH, 3 MED, 4 LOW.** The OSS scaffolding ships well-shaped plumbing — abstractions, validation, dispatch, formatting, parsing — but the central CloudTrail filter strategy is built on a session-name misidentification (CRIT-22-01) that makes the feature return effectively zero real events for its stated use case. The supporting test suite encodes the bug rather than catching it. The HIGH (no audit log of admin reads on grants) breaks the iam-jit audit-chain invariant; the MEDs flag a global-state concurrency risk, an over-specific describe() claim, and an error-surface asymmetry that turns silent failures into "no activity" reports.

Recommended pre-launch fix sequence:
1. **CRIT-22-01**: change `LookupAttributes` to `[{AttributeKey: "ResourceName", AttributeValue: query.role_name}]`. Update the `InMemoryLiveActionTailSource` filter to match on role-name instead of session-name. Rename `LiveActionEvent.session_name` to `role_name` (or add both fields). Update `_parse_cloudtrail_event` to capture both `sessionContext.sessionIssuer.userName` (role name) AND the actual session name from `sessionContext.attributes.creationDate`-adjacent fields if needed. Add a test that asserts the filter targets the issued role, not the provisioner session.
2. **HIGH-22-01**: add `lifecycle.record_tail_read(request, actor, query, source, event_count)` helper and wire it into both `_tail_grant_for_mcp` and `tail_cmd`. Add a `status.history` entry per tail call. Test it appears in `audit_log_report` output.
3. **MED-22-03 + LOW-22-03**: change `fetch_events` to return a `TailResult` with `events + ok + error`. Surface `error` in MCP response and use non-zero exit in CLI on source error. (Pairs with LOW-22-04: once errors are surfaced, the parameterized contract test becomes easier to write.)
4. **MED-22-01**: convert `_active_source` to a `ContextVar` OR enforce set-once semantics. Document the rationale in docstring.
5. **MED-22-02**: tighten `CloudTrailLookupSource.describe()` to say "Event-history" and clarify the 90d window comes from Event history, not the customer's trail retention.
6. **LOW-22-01**: add empty-page early-exit (bail after 3 consecutive empty `Events` pages).
7. **LOW-22-02**: add `_validate_request_id` to `DynamoDBStore.get` / `delete` / `exists` (pre-existing gap; fix here while in the neighborhood).
8. **LOW-22-04**: rewrites itself naturally as part of CRIT-22-01 fix.

After fixes ship, re-run audit (Round 23) to confirm CRIT-22-01 is genuinely closed by testing against a real CloudTrail event or a moto-based fixture that mirrors the real `Username` semantics — the current hand-rolled fixtures lie about the AWS contract and would happily greenlight a different incorrect implementation.
