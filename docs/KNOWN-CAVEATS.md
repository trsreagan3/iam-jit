# Known caveats + bugs (cross-product)

**Read this BEFORE you install** — knowing the boundaries up-front saves hours of debugging.

This doc is **strictly split into two sections**:

- **§A — LAUNCH-BLOCKING BUGS** — issues that must be FIXED before v1.0. Severity CRITICAL or HIGH. Each has a fix-tracker task. The product does NOT launch until every entry in §A is FIXED.
- **§B — DOCUMENTED LIMITS** — design choices + gaps. NOT launch-blocking. Documented for transparency.

If a user hits something not in either section → it's a documentation gap. File an issue.

Last updated 2026-05-22.

---

# §A — LAUNCH-BLOCKING BUGS (must fix before v1.0)

Tracking: every BUG entry has a task number (e.g., #299). v1.0 release gate: every entry below shows `STATUS: FIXED`.

## A1. iam-jit: solo-mode self-approval deadlock — `STATUS: FIXED` ✓
- **Severity:** CRITICAL
- **Was:** solo founder on laptop submits a request → goes to `human-review-required` → four-eyes check refuses approver==owner → deadlock.
- **Fix:** iam-roles `5237ad4` — expanded eligible reasons in `_apply_mfa_and_self_approve_enforcement` to include `feature_disabled` (solo-mode default).
- **Task:** #297 — completed 2026-05-22.

## A2. dbounce: SCRAM-SHA-256 handshake hangs — `STATUS: FIXED` ✓
- **Severity:** CRITICAL
- **Was:** Modern PG 14+ defaults to SCRAM. Connecting any psql/libpq client through dbounce hung forever during initial auth — the proxy forwarded SCRAM bytes upstream but the AuthenticationOk / ParameterStatus / BackendKeyData / ReadyForQuery responses never propagated back to the client.
- **Root cause:** `pumpAuthPhase` in `internal/proxy/forward.go` treated every `AuthenticationRequest` sub-code other than 0 (Ok) as "client-response required" and blocked on a client read. SCRAM walks `R/10` (SASL) → `R/11` (SASLContinue) → `R/12` (SASLFinal) → `R/0` (Ok); sub-code 12 is server-only with no client response. The proxy deadlocked on the spurious client read.
- **Fix:** dbounce — introduced `authRequestExpectsClientResponse(uint32) bool` enumerating which PG protocol auth sub-codes trigger a client follow-up. Sub-codes 0, 2, 6, 12 (and any unknown code) fall through to the next upstream read instead of blocking on the client. Wire-protocol pass-through invariants preserved (no SCRAM bytes inspected/named). Regression coverage: `TestForward_SCRAMSHA256HandshakeCompletes` + `TestAuthRequestExpectsClientResponse` (unit) + `TestIntegration_SCRAMAuthThroughProxy` (build tag `integration`). End-to-end: psycopg2 through dbounce against PG 16 with `scram-sha-256` now succeeds in ~95ms.
- **Task:** #299 — completed 2026-05-22.

## A3. ibounce: hardcoded HTTPS upstream scheme — `STATUS: FIXED` ✓
- **Severity:** CRITICAL
- **Was:** ibounce `proxy.py` hard-coded `https://` for the outbound forward + always forwarded to the inbound SigV4-signed Host header. Pointing it at a plain-HTTP upstream (LocalStack at `http://127.0.0.1:4566`) failed entirely — UAT 2026-05-22 had to bypass ibounce for all writes (Variants A + C).
- **Root cause:** `ProxyConfig.forward_scheme` had a `"https"` default but no CLI surface to override it; the forward target was always `host_header` (the inbound SigV4-signed Host), which for a `boto3 + AWS_ENDPOINT_URL=http://127.0.0.1:8770` flow is the proxy's OWN port — loops without an explicit upstream override.
- **Fix:** added `ibounce run --upstream URL` flag. New `parse_upstream_url(url)` helper extracts scheme + `host:port`; validates scheme ∈ {http, https} (rejects `ftp://`, `file://`, schemeless URLs with a clear error); threads `forward_scheme` + new `forward_host_override` field through `ProxyConfig` into the two `_forward_to_aws` call sites. CRIT-32-01 outbound-host allowlist still gates the override target (loopback / `.amazonaws.com` / operator EXTRA_HOSTS). Regression coverage: `tests/bouncer/test_proxy_upstream_scheme.py` (14 tests: unit parser + CLI-startup-rejection + end-to-end against a mock-LocalStack aiohttp app proving the override target receives the call). End-to-end verified against LocalStack 3.8: `list_buckets / create_bucket / put_object / get_object` all 200 through `ibounce --upstream http://127.0.0.1:4566 --mode transparent` with audit log showing `allow` verdicts.
- **Task:** #300 — completed 2026-05-22.

## A4. kbounce: kubectl OpenAPI discovery classified as "unclassifiable" — `STATUS: FIXED 2026-05-22`
- **Severity:** CRITICAL
- **Symptom:** Every kubectl invocation fails. First call kubectl makes is `GET /openapi/v3/<group>` → kbounce parser → unclassifiable → safe-default denies.
- **Fix shipped (kbouncer #301):** parser-side recognition of apiserver meta/discovery URL shapes (`/openapi/v2`, `/openapi/v3[/...]`, `/api`, `/apis`, `/api/{version}`, `/apis/{group}[/{version}]`, `/version`, `/healthz[/...]`, `/readyz[/...]`, `/livez[/...]`, `/metrics`) as `IsMetaRead=true`, `verb=get`, `resource=meta:<kind>`. The proxy short-circuits them to `VerdictAllow` with `decision_source=meta-discovery`. Writes on the same prefixes stay unclassifiable (apiserver 405s them; per `[[creates-never-mutates]]` we refuse to widen). New regression tests in `internal/parser/parser_test.go` (`TestParse_MetaDiscoveryPaths`, `TestParse_ResourceTailNotMistakenForMeta`) + `internal/proxy/proxy_test.go` (`TestEvaluateRequest_MetaDiscoveryAllowedUnderSafeDefault`, `TestEvaluateRequest_MetaDiscoveryWritesStillDenied`, `TestEvaluateRequest_RealResourceCallStillFlowsThroughProfile`). End-to-end verified with kbounce against the dogfood kind cluster — all 12 canonical meta paths returned `verdict=allow source=meta-discovery`. Ships in kbouncer v1.0.
- **Task:** #301 — completed 2026-05-22. See kbouncer CHANGELOG "Unreleased / #301" for the full design rationale.

## A5. dbounce: GRANT / REVOKE / DCL classified as `unknown` → default-allow — `STATUS: QUEUED`
- **Severity:** HIGH
- **Symptom:** `GRANT ALL PRIVILEGES ... TO PUBLIC` allowed by safe-default profile. dbounce parser doesn't classify DCL.
- **Workaround until fix:** add explicit `deny grants_to_public: true` rule in custom profile.
- **Task:** #302 — queued, not yet started.

## A6. gbounce: unreachable-host CONNECTs not logged — `STATUS: QUEUED`
- **Severity:** HIGH
- **Symptom:** SSRF probes against private IPs (e.g., `169.254.169.254`) are INVISIBLE. gbounce only audits successful CONNECTs.
- **Workaround until fix:** monitor stdout log for connection errors.
- **Task:** #303 — queued.

## A7. gbounce: non-CONNECT requests rejected with no audit — `STATUS: QUEUED`
- **Severity:** HIGH
- **Symptom:** Plain HTTP requests get 421 "only CONNECT accepted" → silently dropped, no audit event. IMDS attacks (plain HTTP) invisible.
- **Workaround until fix:** none — gbounce is HTTPS-CONNECT-only in v1.0.
- **Task:** #305 — needs creation (added below).

## A10. Local audit-log retention is not robust — `STATUS: QUEUED`
- **Severity:** HIGH (would surprise operators after 30-60 days of use)
- **Symptom:** JSONL audit files grow forever; SQLite audit DB grows forever. No automatic rotation, compression, retention enforcement, or disk-space monitoring. After weeks of use, operators discover their disk filling silently.
- **Why this matters:** Per `[[self-host-zero-billing-dependency]]` everything is local. The audit log IS the compliance value — if it silently corrupts or fills disk + drops events, the compliance claim fails.
- **What "robust" needs:**
  1. Automatic JSONL rotation (size + age thresholds, gzip on rotate)
  2. SQLite audit DB partitioning OR archive-rotate-replace
  3. `/healthz` reports degraded when disk usage > configurable threshold (default 85%)
  4. Admin-action audit event on rotation + write-failure + retention-purge
  5. `*bounce logs {tail|purge|archive|verify}` subcommand surface
  6. Crash recovery: detect partial-write JSONL tail on next startup; truncate cleanly
  7. `*bounce doctor logs` checks integrity + freshness + retention
  8. `docs/LOG-RETENTION.md` with defaults + admin-override
- **Workaround until fix:** operator-side cron + manual `*bounce diagnostics bundle` (#277)
- **Task:** #311.

## A8. kbouncer + dbouncer: stale `bin/` binaries in repos — `STATUS: FIXED (2026-05-22)`
- **Severity:** HIGH
- **Symptom (historical):** README led with `go build ./cmd/<binary>` followed by `./<binary> run`, encouraging a workflow where someone could commit a pre-built binary that lags source by days. Users picking up the repo and running the stale `./bin/<binary>` silently missed recent features (UI, audit endpoints, agent identity, etc.).
- **Fix:** Both repos canonicalize `go install` as THE install path. The README "Install" section now leads with `go install github.com/trsreagan3/<repo>/cmd/<binary>@latest`, which builds fresh from source every time — no stale binary surface possible. Local-dev iteration uses `make build` (writes to gitignored `./bin/`) or `make install` (writes to `$GOPATH/bin`). `bin/` was already gitignored in both repos; this slice locks in the documentation + Makefile shape to keep it that way.
- **Verification:** `go install github.com/trsreagan3/kbouncer/cmd/kbounce@latest` and `go install github.com/trsreagan3/dbounce/cmd/dbounce@latest` both succeed against the public module proxy (gbounce-routed run on 2026-05-22 — kbounce v0.0.0-20260522064802-131bcaca7334, dbounce v0.0.0-20260522064202-a7a8a2d49a4d).
- **Tasks closed:** #306 + #307. ibounce (Python; iam-roles repo) ships via `pip install`; gbounce ships via the same `go install` shape as kbounce/dbounce and is unaffected by this caveat.

---

# §B — DOCUMENTED LIMITS (NOT launch-blocking)

These are intentional limits OR roadmap-tracked gaps. Documented so users + agents aren't surprised. The product LAUNCHES with these in place; they're listed so adoption decisions are informed.

## B1. ibounce: SigV4-only request classification (DESIGN)
**Symptom:** Plain GET requests to ibounce return 403 "no SigV4 header."  
**Why:** ibounce gates AWS SDK calls. AWS SDKs always sign SigV4. A bare GET isn't an AWS call.  
**Browsers**: ibounce uses `Accept` header — `text/html` gets the UI, JSON gets the proxy path.

## B2. ibounce: AWS-only scope (DESIGN)
ibounce gates AWS calls only. K8s → kbounce. DB → dbounce. HTTP → gbounce.

## B3. ibounce: safe-default = `readonly-admin-minus` (DESIGN)
First-time profile is "reads allowed except sensitive prefixes; writes prompt." Use `--profile strict-admin` for stricter.

## B4. ibounce: safe-default catches are VERB-level, not CONTENT-aware (DESIGN — v1.1 enhancement)
**Symptom:** Scoped `iam:CreateRole` and wildcard `iam:*` both denied by same rule. Catches of legit + malicious writes look identical.  
**For content-aware decisions:** add iam-jit to the path (Variants C). iam-jit provides scope-aware risk scoring; ibounce provides the atomic gate.  
**v1.1 plan:** ibounce calls into iam-jit's scorer for content-aware decisions.

## B5. kbounce: doesn't see container-internal calls (DESIGN)
kbounce sits between kubectl/client-go and the kube-apiserver. Pod-to-pod service-mesh traffic doesn't go through that path. Per `[[no-k8s-proxy-for-iam-jit]]`.

## B6. dbounce: per-statement gating, not per-result (DESIGN)
A SELECT returning 1M rows is one DECISION event, not 1M.

## B7. dbounce: literal-redaction is heuristic (DESIGN — partial)
String literals in `WHERE` get redacted; numeric literals do NOT (per `[[dbounce-sql-redaction-gaps]]`). If you store PII as numeric columns, use `--redact-numerics` (post-v1.0 flag).

## B8. gbounce: `--allow-connect` only sees host:port (DESIGN)
HTTPS through gbounce shows `CONNECT host:443`. Not request URL/body. Per `[[ibounce-honest-positioning]]` — no MITM = more privacy + deployability.  
**URL-level visibility:** use `--upstream` rewrite mode (HTTP only) OR enable MITM in v1.1.

## B9. gbounce: G-Slice 1 = discovery only (GAP — v1.1)
gbounce observes + logs but doesn't BLOCK. Profile-mode gating + auto-recommender are G-Slice 2-3, post-launch.

## B10. iam-jit: AWS-only scope (DESIGN)
iam-jit is the AWS IAM risk scorer. K8s/DB/HTTP unaffected.

## B11. iam-jit: deterministic floor never lowered by LLM (DESIGN)
LLM-Pro overrides go UP, never DOWN. Per `[[scorer-is-ground-truth]]`.

## B12. iam-jit: IAM score-9 collision (CALIBRATION — MEDIUM, not launch-blocking)
Scoped `iam:CreateRole` and wildcard `iam:*` both score 9. Distinguishable via `factors` list but not numeric score.  
**Severity:** MED — affects within-band-9 resolution; threshold-based auto-approval still works correctly.  
**Plan:** v1.0.x calibration sweep.

## B13. Cross-product: 1-3 concurrent terminals in v1.0 (GAP — v1.1 raises to 20)
**Why:** active-mcp-session.json is single-entry; profile + pause state are global. 10+ concurrent terminals produce session-attribution issues.  
**v1.1 plan:** task #296 multi-session SQLite refactor → 20-terminal target.

## B14. Cross-product: defense-in-depth ≠ unified product (DESIGN per `[[four-products-one-brand]]`)
~10% of decisions show TRUE multi-layer composition per UAT. The marketing claim is "complementary products under one brand," NOT "single integrated suite." This is the honest framing per `[[ibounce-honest-positioning]]`.

## B15. Cross-product: no unified deny-prompt UI in v1.0 (GAP — v1.1)
Each bouncer prompts independently. v1.1 brings unified prompt-inbox UI.

---

# Discoverability surfaces

The §A + §B content here is **surfaced** at:

1. **README "Known Limitations" section** per product — top 3 entries + link here
2. **CLI startup banner** — when a bouncer detects a triggering config, prints the relevant §A entry
3. **`*bounce doctor`** — runs known-issue checks + prints applicable §A entries
4. **`*bounce diagnostics bundle`** — includes a snapshot of this doc
5. **Error messages** — when a §A bug triggers, error message links to the relevant entry
6. **MCP tool descriptions** — agents see relevant §B entries embedded

Surfacing is tracked under task #304.

---

# Launch gate

v1.0 ships when:
- Every §A entry shows `STATUS: FIXED`
- §B is reviewed + signed off as accepted limits / honest gaps
- Discoverability surfaces (#304) are live

If a critical bug is discovered after this doc is locked: it's added to §A with `STATUS: NEW` and the launch is rebooked.

# Issue reporting

- iam-jit: https://github.com/trsreagan3/iam-jit/issues
- kbouncer: https://github.com/trsreagan3/kbouncer/issues
- dbounce: https://github.com/trsreagan3/dbounce/issues
- gbounce: https://github.com/trsreagan3/gbounce/issues

A caveat you discover + we miss documenting = a documentation gap we both want closed.
