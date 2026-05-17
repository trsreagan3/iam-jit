# Changelog

All notable changes to iam-jit follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adhere to semantic versioning per [docs/UPGRADING.md](docs/UPGRADING.md).

Calibration corpus + scorer rules ship pinned to the wheel
version in v1.0. A future release may split scorer version
from software version (see `docs/ROADMAP-V1.1.md`); changes to
the scorer corpus today are noted as `### Scorer` blocks
within the same release.

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
