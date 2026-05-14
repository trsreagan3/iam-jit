# Changelog

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
