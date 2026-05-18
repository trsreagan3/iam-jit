# Changelog

All notable changes to iam-jit follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adhere to semantic versioning per [docs/UPGRADING.md](docs/UPGRADING.md).

Calibration corpus + scorer rules ship pinned to the wheel
version in v1.0. A future release may split scorer version
from software version (see `docs/ROADMAP-V1.1.md`); changes to
the scorer corpus today are noted as `### Scorer` blocks
within the same release.

## Unreleased — Bounce-suite rename (2026-05-17)

### Added

- **`iam-jit audit query` cross-bouncer CLI** (#271) — single
  command that queries the `/audit/events` HTTP endpoint on every
  reachable Bounce-suite bouncer in parallel and merges results
  into one OCSF-compliant stream. Defaults probe ibounce (8767) +
  kbounce (8766) + dbounce (8768) + gbounce (8769); unreachable
  bouncers skip with a stderr note. Four output formats: `jsonl`
  (default; merged + sorted NDJSON), `ocsf-bundle` (single OCSF
  v1.1.0 class 2004 Detection Finding wrapping all events from all
  bouncers — cross-product correlation in one SIEM-ingestible
  artifact), `csv` (tabular with the per-bouncer column), `summary`
  (per-bouncer + total counts). Filters forwarded server-side per
  [[cross-product-agent-parity]]. Bearer-token auth supported via
  `--audit-events-token` for externally-bound bouncers.
  ThreadPoolExecutor fan-out so one slow bouncer doesn't pin the
  query. New module `iam_jit/cli_audit_query.py`; new doc
  `docs/IAM-JIT-AUDIT-QUERY.md`. Pairs with the per-product HTTP
  endpoint (ibounce serves it on port 8767 alongside `/healthz`).
- **ibounce HTTP `GET /audit/events` endpoint** (#271 A) — headless
  sibling of `ibounce audit tail --filter ... --export jsonl`.
  Same filter language, same supported field catalog, same OCSF
  v1.1.0 wire shape. Query parameters: `since` / `until` (ISO
  8601), `filter` (repeatable; `field=value` / `field~regex` /
  `field>=N` / `field<=N`), `limit` (default 100, max 1000),
  `format` (`jsonl` default | `ocsf-bundle`). Loopback bind needs
  no auth; external bind requires `--audit-events-token TOKEN`
  (refuses to start in external-bind mode without it). New module
  `iam_jit/bouncer/audit_export/events_endpoint.py`. Powers the
  cross-bouncer query CLI above.
- **`ibounce investigate` subcommand** (#273) — one-shot helper
  that lands a Claude-ready evidence pack on disk. Composes the
  existing `audit tail --export ocsf-bundle` (#268) and
  `diagnostics bundle` (#277) into a single command: writes
  `ibounce-investigation.ndjson` (OCSF Detection Finding wrapping
  filtered events) and `ibounce-investigation-context.zip`
  (redacted diagnostics bundle with `--no-audit`) into `--out-dir`,
  then prints a "now what" block with three starter prompts.
  Flags: `--out-dir`, `--time-range` (e.g. `24h`/`7d`/`4w`),
  `--filter` (forwarded to the audit-tail filter grammar),
  `--print-prompts` (lists the 10 starter prompts without writing
  files). Cross-product alignment per [[cross-product-agent-
  parity]] — `kbounce` / `dbounce` / `gbounce` ship the same
  subcommand shape. Per [[self-host-zero-billing-dependency]] the
  command never calls Anthropic; the operator opens THEIR Claude
  session and drops both files in. Per [[creates-never-mutates]]
  it's strictly read-only.
- **`docs/INVESTIGATE-WITH-CLAUDE.md`** — workflow walkthrough,
  the 10 starter prompts, privacy story, and cross-product
  parity notes. Cross-linked from `DIAGNOSTICS.md` +
  `QUERYING-AUDIT-LOGS.md`.

### Docs

- `docs/LOCAL-TEST-INFRA.md` now documents the AWS-SDK
  HTTPS-default-with-HTTP-endpoint quirk that bites first-time
  LocalStack users (boto3 ignores the scheme on `AWS_ENDPOINT_URL`
  for some code paths and tries HTTPS regardless, producing
  `SSL: WRONG_VERSION_NUMBER`). Documented the three workarounds
  (`AWS_ENDPOINT_URL_<SERVICE>`, `AWS_USE_SSL=0`, CLI
  `--no-verify-ssl`).

### Changed (canonical names; deprecation aliases ship in v1.0)

- **`iam-jit-bouncer` → `ibounce`** — canonical CLI name for the
  AWS-API gating proxy. Console-script `iam-jit-bouncer` keeps
  working (prints a one-line stderr deprecation warning + forwards
  to the same Click app); removed in v1.1. Wheel name unchanged
  (`iam-jit` still ships both the scorer and `ibounce`).
- **MCP tools: `bouncer_*` → `ibounce_*`** — every `bouncer_*` tool
  gets an `ibounce_*` alias in v1.0. Both dispatch to the same
  handler. The legacy `bouncer_*` descriptions carry a
  `(DEPRECATED — use ibounce_* in v1.1)` prefix on every
  `tools/list` response. Removed in v1.1.
- **Built-in profiles reduced to two** — `full-user` (passthrough,
  default-active) + `readonly` (cross-product write/destructive-verb
  block). Replaces the pre-rename `none` + `prod-readonly` names.
  Old names still resolve in v1.0 + emit a one-line stderr
  deprecation banner; removed in v1.1.
- **`ibounce run` banner** — when invoked without `--profile`, the
  proxy now prints a one-line banner pointing the operator at
  `--profile readonly` OR `export IAM_JIT_BOUNCER_PROFILE=readonly`
  in their shell rc as the recommended write-block opt-in. Per
  `feedback_bounce_default_profile_pattern`.

### Moved

- **Opinionated profiles moved out of built-ins** — `dev-only`,
  `staging-work`, and `incident-response` profiles relocate from
  `src/iam_jit/bouncer/profiles.py:DEFAULT_PROFILES` to standalone
  YAML files under `tools/community-profiles/`. Future home:
  `trsreagan3/bounce-profiles` (the cross-product community-profile
  bundle). Install via `ibounce profile install --from URL` once
  hosted.
- **Doc file renames (`git mv` preserves history)**
  `docs/IAM-JIT-BOUNCER.md` → `docs/IBOUNCE.md`;
  `docs/launch-posts/DONT-GIVE-CLAUDE-YOUR-AWS-KEYS.md` →
  `docs/launch-posts/DONT-GIVE-CLAUDE-FULL-ADMIN.md`.

### Unchanged (v1.0 backward-compat surface)

- `IAM_JIT_BOUNCER_*` env vars stay as the canonical names (no
  `IBOUNCE_*` aliases — env-var alignment ships in v1.1 with the
  rest of the deprecation removal).
- HTTP response headers `x-iam-jit-bouncer-*` keep their old prefix
  for v1.0 (agents + tooling that grep on them keep working);
  renamed in v1.1.
- Wire-protocol observability (audit-log row shape, SQLite schema,
  `/healthz` JSON shape) unchanged.

### Quality (audit-cadence)

Per `feedback_audit_cadence_discipline`, a brief BB+WB self-check
for the rename change-set:

- **Does the deprecation shim actually run the new code path?** Yes
  — `main_deprecated_alias()` in `src/iam_jit/bouncer_cli.py`
  prints to stderr then calls the canonical `main()` Click app
  with `sys.argv` intact. The `iam-jit-bouncer` console-script
  binding in `pyproject.toml` points at the wrapper; both
  entrypoints exercise the same Click groups and subcommands.
- **Does any test assume the old name in a way that hides a
  regression?** Tests updated to the new `full-user` / `readonly` /
  `ibounce_*` names; backward-compat aliases get explicit pinned
  tests (`test_resolve_active_profile_legacy_none_alias_still_works`,
  `test_resolve_active_profile_legacy_prod_readonly_alias_still_works`,
  `test_tools_list_exposes_ibounce_aliases_for_every_bouncer_tool`,
  `test_bouncer_tool_descriptions_carry_deprecation_note`,
  `test_ibounce_alias_dispatches_to_same_handler`,
  `test_legacy_prod_readonly_alias_points_at_readonly`) so a
  regression breaks loudly.
- **Does the alias mechanism mask a permission elevation bug?** No
  — every MCP `ibounce_*` call normalizes to its `bouncer_*` lookup
  string at the dispatch boundary (one transform, no per-tool
  branching), so the alias cannot accept arguments the canonical
  name wouldn't accept. The profile-name aliases resolve to the
  same `Profile` object instance (`profiles["none"] is
  profiles["full-user"]`); there is no parallel resolution path
  where an alias could pick up different rules. Pre-existing bug
  in `bouncer_cli.py` — `os` not imported at module level despite
  `os.environ` use in `profile_list_cmd` — fixed in passing
  (caught by smoke-running `ibounce profile list` to verify the
  rename touched paths still execute).

## Unreleased (2026-05-15)

### Added — multi-feature push

- **Multi-provider OIDC SSO** (`src/iam_jit/oidc.py` +
  `src/iam_jit/routes/oidc.py`) — generic OIDC client with
  Google Workspace + Okta provider configs; generic provider
  for Azure AD / Auth0 / others. Full authorization-code flow,
  JWKS-cached signature verification, mandatory claim checks
  (iss, aud, exp, iat, nonce), provider-specific gates (Google
  `hd`, Okta `groups`), AMR-based MFA detection per RFC 8176.
  54 OIDC tests; round-9 BB+WB audit shipped + closures
  landed.
- **Per-account LLM policy** (`src/iam_jit/llm_account_policy.py`)
  — per-`Account` `llm_policy` field (use_llm /
  deterministic_only / unset) gates LLM-backend selection
  BEFORE the per-customer monthly budget cap. Decision flow:
  account policy → deployment default → budget cap. Surfaced
  in score response as `llm_used` + `llm_skip_reason` +
  `llm_skip_detail`. 12 unit + 7 route tests.
- **Slack approval bot** (`src/iam_jit/slack_bot.py` +
  `src/iam_jit/routes/slack.py`) — interactive approve / reject
  / request-changes flow with signed-request authentication
  (HMAC + 300s replay window), Block Kit rendering, modal-based
  context capture. Approver resolution by explicit
  `slack_user_id` mapping OR Slack `users.info` → email →
  iam-jit User. Workspace + channel pinning. App manifest +
  setup runbook. 105 Slack-surface tests.
- **Read-only-default for agent-safety mode** — MCP server's
  `generate_iam_policy` tool description instructs Claude to
  default to `access_type: "read-only"`. The behavioral contract
  for the agent-safety adoption channel. 7 pinned tests.
- **Safety-mode two-mode resolver** (`src/iam_jit/safety_mode.py`)
  — `read_write_swap` (default, lean-permissive) vs `strict`
  (compliance-strict) modes. Per-deployment / per-account /
  per-session override resolution. 14 tests.

### Security

- **Round-7 audit closures** (`docs/security/AUDIT-2026-05-WB-ROUND7-FOCUSED.md`):
  Deleted `bridge_role.py` (made 6 of 8 findings moot — the
  module violated [[creates-never-mutates]]; pattern superseded
  by Secrets Manager rotation recipe). WB7F-07 MED + WB7F-08
  LOW closed via shared `trusted_proxy.client_ip` + anchored
  `is_conditional_check_failed` substring match.
- **Round-8 Slack-bot audit closures**
  (`docs/security/AUDIT-2026-05-WB-ROUND8-SLACK-BOT.md`):
  WB8-01 HIGH (Block Kit / mrkdwn injection via
  `spec.description` + `risk_factors` — closed via
  `_escape_mrkdwn` helper applied to requester-influenced
  fields). WB8-02 MED (ambiguous `slack_user_id` mapping —
  closed via multi-match raise). WB8-03 MED (workspace pin
  via `IAM_JIT_SLACK_TEAM_ID`). WB8-04 MED (channel pin via
  approval channel ID).
- **Round-9 OIDC audit closures**
  (`docs/security/AUDIT-2026-05-WB-ROUND9-OIDC.md`):
  WB9-01 HIGH (MFA cookie now bound to `user.id`). WB9-02
  MED (token-exchange error no longer leaks access_token to
  logs). WB9-04 MED (endpoints cache has 1hr TTL). WB9-05
  LOW (iss-missing → clean error). WB9-06 LOW (AMR set
  tightened per RFC 8176 + NIST 800-63B). WB9-07 LOW
  (`_cookie_secure` delegates to canonical helper).

### Documentation

- **README rewrite** (499 → 234 lines): three-mode framing
  leading with "Don't give Claude your AWS keys." Removed
  terraform references (we use SAM); removed outdated
  "upsell SaaS" framing.
- **`docs/recipes/AGENT-IAMJIT-HOOP-EXAMPLES.md`** — six
  agent + iam-jit + Hoop scenarios using Secrets Manager
  rotation pattern.
- **`docs/recipes/SLACK-APP-SETUP.md`** — operator runbook
  for the Slack approval bot.
- **`docs/recipes/GOOGLE-OIDC-SSO.md`** — multi-provider OIDC
  setup with Google + Okta sections.
- **`docs/RECOMMENDER-API-SPEC.md`** — recommender intent +
  needs_context flow spec.
- **DEPLOYMENT.md** Step 5.5 (self-host Bedrock billing) +
  Step 5.6 (pilot deployment profile with cost-capped
  Enterprise tier).

## Unreleased (pre-launch — 2026-05-14)

### Added

- **SARIF 2.1.0 output mode** in the score CLI (`iam-risk-score
  ... --format sarif`). High-leverage CI integration substrate
  — one output mode, broad reach (GitHub Code Scanning, GitLab
  Code Quality, generic security-CI consumers). [Commit
  2966adf]
- **GitHub Action `preset:` input** with `strict | standard |
  permissive` shorthand bundling threshold + access-type.
  Explicit `threshold:` / `access-type:` inputs still override.
  Mirrors the Snyk / Semgrep "three-tier preset" pattern.
- **GitHub Action `sarif-output:` input** writes a combined
  SARIF 2.1.0 report at the given path for `actions/upload-
  sarif@v3` integration.
- **`session_revocation` module** (`src/iam_jit/session_
  revocation.py`) — Protocol + InMemory + DynamoDB
  implementations. Wired into the middleware on every
  authenticated request. SAM template provisions the table
  with TTL on `expires_at`.
- **`trusted_proxy` module** (`src/iam_jit/trusted_proxy.py`)
  — single source of truth for `IAM_JIT_TRUSTED_PROXY_CIDRS`
  parsing across score, network_acl, public_url, and the
  magic-link route's IP limiter. Normalizes IPv4-mapped IPv6.
- **`DynamoDBMagicLinkNonceStore`** for multi-instance magic-
  link replay protection. SAM table with TTL on `expires_at`.
- **`DynamoDBBanStore`** for multi-instance ban enforcement.
- **`LAUNCH-DAY-RUNBOOK.md`** — first-72h operational triage
  (dashboards, down-site decision tree, attack-decision tree,
  bug-bounty intake protocol).

### Closed (security)

10 HIGH findings, 12 MED findings, 8 LOW findings closed across
3 adversarial-audit rounds (BB+WB each). Highlights:

- **Round 1 HIGH** — STRIPE-NO-IDEMPOTENCY, SCORE-XFF-
  RATELIMIT-BYPASS, WEB-NO-CSRF-TOKEN.
- **Round 2 HIGH** — STRIPE-IDEMPOTENCY-TOCTOU (atomic
  claim()), SCORE-XFF-LEFTMOST-TRUSTED (right-to-left walk),
  NETWORK-ACL-XFF-DEFAULT-TRUSTED (default-off), MAGIC-LINK-
  XFH-POISONING (peer + allowlist gates), MAGIC-LINK-LOG-
  CHANNEL (fingerprint-only opt-in), MAGIC-LINK-REPLAY-MULTI-
  INSTANCE + BAN-MULTI-INSTANCE-DESYNC (DDB-backed stores).
- **Round 3 HIGH** — STRIPE-CLAIM-BEFORE-PROCESS (release on
  handler crash), BB3-01 logout-doesn't-revoke (session-
  revocation list), BB3-02 /openapi.json 500 (Response
  ForwardRef fix).
- **Round 3 MED** — WEB-MAGIC-CALLBACK-BROKEN-AUTO-SEED (now
  takes Request param), TOKENS-PER-USER-CAP-TOCTOU (per-user
  Lock), BODY-SIZE-GUARD-CHUNKED-BYPASS (411 on chunked + no-
  Content-Length), MAGIC-LINK-DEV-INSECURE-OUTRANKS-SES (SES
  wins), DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN (refused in
  Lambda without explicit opt-in), BAN-CHECK-FAIL-OPEN (503
  default), BAN-STORE-CORRUPT-FILE-UNBAN (raise not silent
  un-ban).
- **Round 3 LOW** — BB-13 / BB3-03 /healthz posture leak,
  PUBLIC-URL-XFH-LEFTMOST, XFP-SCHEME-INJECTION, MAGIC-LINK-
  IP-LIMITER-PEER-ONLY-DOS, TRUSTED-PROXY-CIDRS-PARSER-
  DISCREPANCY, XFF-IPV4-MAPPED-IPV6, BB3-04 stripe-verbose
  error, BB3-05 empty event_id bypass, BB3-10 event_type
  echo.

Full audit docs in `docs/security/AUDIT-2026-05-*.md`.

### Documentation

- **`docs/PRODUCTION-READINESS.md`** updated with new env vars
  (`IAM_JIT_TRUSTED_PROXY_CIDRS`, `IAM_JIT_ALLOWED_PUBLIC_
  HOSTS`, `IAM_JIT_SES_SENDER` / `IAM_JIT_ALLOW_LOG_CHANNEL`,
  `IAM_JIT_MAGIC_LINK_NONCES_TABLE`, `IAM_JIT_BANS_TABLE`,
  `IAM_JIT_SESSION_REVOCATION_TABLE`,
  `IAM_JIT_ALLOW_INSECURE_NONCES`).
- **`docs/ROADMAP.md`** added "continuous role auto-discovery
  + risk-threshold alerts" as a self-hosted v2 feature.
- **`docs/ADVERSARIAL-LOOP-PROCESS.md`** captures the
  cross-cutting lesson from rounds 1-3: "fix where named,
  miss the siblings." Now part of the closure methodology.

### Quality

- **1,369 tests pass** (16 ignored by tag — e2e Playwright +
  calibration-corpus residuals from the scorer adversarial
  loop). Round-1, -2, -3 audit-pinned tests on the entire BB
  + WB surface.
- **`pip-audit`** clean on locked deps.
- **Dist builds cleanly** and passes `twine check`.
