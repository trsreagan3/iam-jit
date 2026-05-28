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

## A5. dbounce: GRANT / REVOKE / DCL classified as `unknown` → default-allow — `STATUS: FIXED 2026-05-22`
- **Severity:** HIGH
- **Symptom:** `GRANT ALL PRIVILEGES ... TO PUBLIC` allowed by safe-default profile. dbounce parser didn't classify DCL.
- **Fix shipped (dbounce #302, commit `d0dccff`):** parser now dispatches on `pg_query.Node_GrantStmt` / `Node_GrantRoleStmt` / `Node_AlterDefaultPrivilegesStmt` and surfaces three new statement types (`StmtGrant` / `StmtRevoke` / `StmtAlterPrivileges`) + two new predicates (`IsDCL` + `DCLTargetsPublic`). The walker sets `DCLTargetsPublic=true` when any grantee resolves to PG's `PUBLIC` pseudo-role; REVOKE direction never sets the predicate (revoking FROM PUBLIC is cleanup). A new `Profile.DenyDCLTargetsPublic` field fires at Order 2.5 in the composition (after deny_keywords / deny_actions, BEFORE allow_baseline) so a permissive sql_read_only baseline can't let a PUBLIC-targeting grant through. The `safe-default` profile in `internal/profile/defaults.yaml` now ships with `deny_dcl_targets_public: true` on by default. Regression coverage: `TestParse_GrantAllPrivilegesToPublic`, `TestParse_GrantSelectOnTableToSpecificUser`, `TestParse_GrantCaseInsensitivePublic`, `TestParse_RevokeFromPublic`, `TestParse_RevokeFromSpecificUser`, `TestParse_AlterDefaultPrivilegesGrantToPublic`, `TestParse_AlterDefaultPrivilegesGrantToSpecificUser`, `TestParse_GrantRoleToUser`, `TestParse_GrantMultipleGranteesIncludesPublic`, `TestEvaluate_SafeDefault_DeniesGrantAllToPublic`, `TestEvaluate_SafeDefault_DeniesAlterDefaultPrivilegesGrantToPublic`, `TestEvaluate_SafeDefault_AllowsGrantToSpecificUser`, `TestEvaluate_SafeDefault_AllowsRevokeFromPublic`, `TestEvaluate_DCLFloor_NotConsultedWhenDisabled`, `TestEvaluate_DCLFloor_FiresBeforeAllowBaseline`. End-to-end verified with psycopg2 against the dogfood Postgres (4 task-spec scenarios + baseline SELECT all returned expected verdicts). See dbounce CHANGELOG "Unreleased / #302" for the full design rationale.
- **Task:** #302 — completed 2026-05-22.

## A6. gbounce: unreachable-host CONNECTs not logged — `STATUS: FIXED`
- **Severity:** HIGH
- **Symptom:** SSRF probes against private IPs (e.g., `169.254.169.254`) are INVISIBLE. gbounce only audits successful CONNECTs.
- **Workaround until fix:** monitor stdout log for connection errors.
- **Task:** #303 — fixed 2026-05-22. Failed CONNECT attempts now emit OCSF events with `activity_id=6 (Connect)`, `status_id=2 (Failure)`, `verdict=ALLOW`, `unmapped.iam_jit.ext.connect_refused=true` + `connect_error=<dial-err>`. Same `host:port` extraction as successful-CONNECT happy path, so SIEM pivot on `dst_endpoint.hostname` correlates failures with successes. Regression test: `TestProxy_UnreachableHostCONNECTLogged` + `TestProxy_DNSFailureCONNECTLogged` in `internal/proxy/proxy_test.go`.

## A7. gbounce: non-CONNECT requests rejected with no audit — `STATUS: FIXED`
- **Severity:** HIGH
- **Symptom:** Plain HTTP requests get 421 "only CONNECT accepted" → silently dropped, no audit event. IMDS attacks (plain HTTP) invisible.
- **Workaround until fix:** none — gbounce is HTTPS-CONNECT-only in v1.0.
- **Task:** #305 — fixed 2026-05-22. Rejected non-CONNECT requests now emit OCSF events with `activity_id` derived from method, `status_id=4 (Denied)`, `verdict=DENY`, `unmapped.iam_jit.ext.deny_reason="non-CONNECT method on CONNECT-only listener"`. Method + host + path captured pre-TLS so IMDS probes (`GET http://169.254.169.254/latest/meta-data/...`) land in the audit row with their target host + path visible. Regression test: `TestProxy_NonCONNECTRequestLogged` in `internal/proxy/proxy_test.go`.

## A9. gbounce: audit events lack `unmapped.iam_jit.agent.{name,session_id}` — `STATUS: FIXED 2026-05-22`
- **Severity:** HIGH (last §A launch-blocker for cross-bouncer parity)
- **Symptom:** gbounce audit events showed `something connected to api.github.com` but not `Claude Code session X did it.` ibounce + kbounce + dbounce all stamp the agent under `unmapped.iam_jit.agent`; gbounce was the lone outlier so `iam-jit audit query --filter unmapped.iam_jit.agent.session_id=X` returned an empty stream from gbounce while the other three bouncers returned the matching events.
- **Why this matters:** cross-bouncer correlation per `[[agent-identity-in-audit]]` (#266) collapses without this — an investigation that pivots on session id misses every HTTP call the agent made.
- **Workaround until fix:** none — gbounce stashed the agent id under `unmapped.iam_jit.ext.agent_session_id` (flat), so the recorder routed events into the right per-session NDJSON file, but the canonical `unmapped.iam_jit.agent.session_id` filter never matched.
- **Task:** #308 — fixed 2026-05-22. gbounce's OCSF event builder (`internal/audit/event.go`) now always populates `unmapped.iam_jit.agent` with `{name, session_id, detected_from}`. Headers `X-Agent-Session-Id` + `X-Agent-Name` are extracted from inbound requests + validated (alphanumeric + `_`/`-`/`.`; max 64-128 chars); invalid headers are dropped (audited as anonymous) + counted under `/healthz.total_agent_headers_rejected`. The SQLite store gains `agent_name` + `agent_session_id` columns (schema v2) so the HTTP `/audit/events` endpoint + `gbounce audit tail` CLI surface the same agent block as the JSONL hot path. Regression tests: `TestProxy_AgentHeadersThreadedIntoOCSF` + `TestProxy_NoAgentHeadersGracefulFallback` + `TestProxy_InvalidAgentHeaders_Rejected` in `internal/proxy/proxy_test.go`; `TestFromRequest_AgentBlockAlwaysPopulated` + `TestIsValidAgentName` in `internal/audit/event_test.go`. Header convention documented at [AGENT-ATTRIBUTION.md](AGENT-ATTRIBUTION.md). MCP install commands (`ibounce mcp install-*` + `kbounce mcp install-*`) inject the env-var hints that wire the headers automatically for Claude Code / Cursor / Codex.

## A10. Local audit-log retention is not robust — `STATUS: FIXED 2026-05-22`
- **Severity:** HIGH (would surprise operators after 30-60 days of use)
- **Symptom (pre-fix):** JSONL audit files grew forever; SQLite audit DB grew forever. No automatic rotation, compression, retention enforcement, or disk-space monitoring. After weeks of use, operators discovered their disk filling silently.
- **Why this matters:** Per `[[self-host-zero-billing-dependency]]` everything is local. The audit log IS the compliance value — if it silently corrupts or fills disk + drops events, the compliance claim fails.
- **Fix:** ships [docs/LOG-RETENTION.md](LOG-RETENTION.md) + cross-product rotation across ibounce / kbounce / dbounce / gbounce:
  1. Automatic JSONL rotation (size 100 MB OR age 7 d, gzip on rotate → `audit-{YYYY-MM-DD-HHMMSS}.jsonl.gz`)
  2. SQLite audit DB daily archive-rotate-replace (`audit-{YYYY-MM-DD}.db.gz`) + 30-day retention
  3. `/healthz` `audit_log.status` reports `degraded` at >85 % disk, `critical` at >95 %; optional `--stop-on-disk-critical`
  4. Admin-action audit events: `audit.log.rotated`, `audit.log.rotation_failed`, `audit.log.recovered_partial`, `audit.log.purged`, `audit.log.archived`
  5. `*bounce logs {tail|purge|archive|verify}` subcommand surface — same flag names across products
  6. Crash recovery: `RecoverPartialTail` on startup truncates a partial trailing JSONL line; emits `audit.log.recovered_partial`
  7. `*bounce doctor logs` integrity + freshness + retention + disk checks; exits non-zero on any failure
  8. Cross-product runbook at [docs/LOG-RETENTION.md](LOG-RETENTION.md)
- **Known gap:** gbounce LogWriter-level rotation wiring is deferred — a parallel agent's work on `gbounce/internal/audit/log.go` reverted the integration as this slice landed. The rotation primitives + CLI + `doctor logs` surface all ship on gbounce; the writer-level guard ports cleanly from the dbounce reference once the parallel work settles (see the LOG-RETENTION.md "Cross-product parity matrix").
- **Task:** #311 — completed 2026-05-22.

## A14. No production log-storage runbook — `STATUS: FIXED 2026-05-22`
- **Severity:** HIGH (operators picking up the suite couldn't tell where their audit events should land in production without reading three different doc pages — webhook presets, Security Lake adapter, alert-routes — and synthesising a decision tree themselves)
- **Symptom:** A new operator deploying ibounce + kbounce + dbounce + gbounce together would hit the `--audit-log-path` flag in each bouncer's README, see scattered references to "webhook preset" + "Security Lake adapter" + "alert routes" in separate docs, and have no single "where do my logs go" decision tree by deployment context. Result: either everything stays JSONL (loses SIEM correlation) or the operator builds a one-off pipeline per product (loses cross-product parity).
- **Fix:** ships [docs/PRODUCTION-LOG-STORAGE.md](PRODUCTION-LOG-STORAGE.md) — operator decision tree organised by deployment context (single-host dev, multi-host on-prem, AWS-heavy, AWS+S3, GCP, Azure, CI/CD ephemeral, Enterprise fan-out), full per-context setup snippets, sample Lambda receiver for "dump to S3", honest gaps section (no GCS / Azure-Blob / Kafka / syslog / Elasticsearch / ClickHouse native sinks — operator chains a thin shim or Vector / Fluent Bit / Cribl per `[[self-host-zero-billing-dependency]]`), per-product flag-parity matrix, three-layer validation guide (bouncer-side `audit tail`, `/healthz.audit_export` block, SIEM-side SPL / KQL / SQL queries). Linked from the main README "Documentation" section + each bouncer README. Doc framed per `[[security-team-positioning-safety-not-surveillance]]` (safety + investigation, not surveillance) and `[[don't-tailor-to-lighthouse]]` (no customer-specific recommendation).
- **Task:** #316 — completed 2026-05-22.

## A16. Cross-bouncer X-Agent-Session-Id header parity — `STATUS: FIXED 2026-05-22`
- **Severity:** HIGH (broke the headline cross-bouncer correlation claim — now closed)
- **Surfaced by:** #312 NanoClaw integration test 2026-05-22 — all 3 paths pass functionally, but only gbounce read `X-Agent-Session-Id` on inbound. ibounce / kbounce / dbounce emitted `session_id=null` even when the header was present.
- **Effect (historical):** `iam-jit audit query --filter agent.session_id=X` returned gbounce events only. Investigations across AWS + K8s + SQL missed correlation. `docs/INTEGRATION-OPENCLAW-NANOCLAW.md` + `[[audit-layer-complement-to-agent-harnesses]]` positioning both promised this worked; before #318 it didn't.
- **What shipped (3 parallel slices, all mirror #308's gbounce buildAgentBlock pattern):**
  - **ibounce**: `src/iam_jit/bouncer/audit_export/agent_context.py` now exposes `extract_agent_headers()` + `is_valid_agent_name()` + `is_valid_agent_session_id()` + `total_agent_headers_rejected()`. `resolve_agent_block()` accepts `header_agent_name` + `header_agent_session_id` kwargs at HIGHEST precedence (above MCP / User-Agent / process tree). `audit_event_from_decision()` threads the same kwargs through to the OCSF event. `proxy.py:evaluate_request` extracts the headers once + threads them through all 3 audit-event call sites. Invalid headers are dropped (audited as anonymous) + counted under `audit_export.total_agent_headers_rejected` on `/healthz`. `detected_from` is `"http_header"` when both headers parse cleanly, `"http_header_name_only"` when only the name validates, and falls through to the existing detection chain otherwise.
  - **kbounce**: `internal/proxy/proxy.go:resolveAgentInfo` reads the canonical `X-Agent-Name` + `X-Agent-Session-Id` headers at HIGHEST precedence (before the existing `X-Kbouncer-Session-Id` MCP registry lookup + the User-Agent fingerprint fallback). `internal/audit/agent_context.go` gains `IsValidAgentName()` mirroring gbounce's regex; existing `IsValidSessionID()` is reused. Rejection counter `totalAgentHeadersRejected` lives on the proxy `Server` struct + surfaces via `/healthz.total_agent_headers_rejected`.
  - **dbounce**: `internal/audit/agent_context.go:ParsePGStartupAppName` now recognises the canonical `iam-jit-agent:NAME:SESSIONID` shape in `application_name` (in addition to the existing direct app-name → agent-name table). `internal/proxy/proxy.go:registerPGAgentFromBody` validates the parsed pieces via the shared regex + bumps a per-Server rejection counter for malformed values. SQL connections set `application_name=iam-jit-agent:claude-code:01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef` to thread session id through PG wire (documented in `docs/AGENT-ATTRIBUTION.md` §SQL).
- **Cross-product test:** `tests/integration/cross_bouncer_session_id_parity_test.py` (iam-roles) starts all four bouncers on free ports, fires one request through each with the same `X-Agent-Session-Id`, then runs `iam-jit audit query --filter agent.session_id=<UUID>` + asserts 4 events (one per bouncer) come back.
- **Regression tests:**
  - ibounce: `tests/bouncer/test_agent_headers_318.py` — happy path + no-headers fallback + invalid-name rejection + name-only partial detection + validator parity with gbounce regex.
  - kbouncer: `internal/proxy/agent_headers_318_test.go` — same canonical names: `TestAgentHeaders_HappyPath` + `TestAgentHeaders_NoHeaders_FallbackToUserAgent` + `TestAgentHeaders_InvalidName_Rejected` + `TestAgentHeaders_NameOnly_PartialDetection`.
  - dbounce: `internal/proxy/agent_headers_318_test.go` — `TestApplicationName_AgentParsing_HappyPath` + `TestApplicationName_NoAgentTag_FallbackToUA` + the canonical 4 above.
- **Docs:** `docs/AGENT-ATTRIBUTION.md` extended with the dbounce `application_name` convention. `docs/INTEGRATION-OPENCLAW-NANOCLAW.md` §B16 entry removed (no longer a v1.1 gap).
- **Task:** #318 — completed 2026-05-22. Depends on #308 (gbounce reference implementation).

## A19. Silent profile-upgrade-blindness across the Bounce suite — `STATUS: FIXED 2026-05-22`
- **Severity:** HIGH (silent safety-claim degradation on older installs; D3 dbounce launch-blocker)
- **Surfaced by:** role-effectiveness eval 2026-05-22 — the D3 dbounce scenario found that an operator who installed dbounce pre-#302 was silently running WITHOUT the `deny_dcl_targets_public` floor. dbounce's `~/.dbounce/profiles.yaml` is intentionally never overwritten (operator may have customized) — but that means new safety floors added to embedded `defaults.yaml` AFTER an operator's file was written go unnoticed. Cross-product pattern likely; kbouncer + ibounce share the same "never-overwrite-once-exists" rule.
- **Symptom (historical):**
  - dbounce — `GRANT ALL PRIVILEGES ON DATABASE x TO PUBLIC` BLOCKED with a fresh profile (post-#302); ALLOWED with a profile dated before #302 because `deny_dcl_targets_public` was missing. Operator had no breadcrumb telling them their profile was behind.
  - kbouncer + ibounce — same architectural pattern. Operators who installed before later-shipped safety floors silently run without them.
- **Fix (#321, cross-product surgical):**
  - **All 4 bouncers — `*bounce profile doctor` subcommand:** diff-checks the operator's installed profile YAML against the embedded shipped defaults and reports missing fields. Does NOT auto-overwrite. Per [[creates-never-mutates]]: additive merge via opt-in `--apply` only; backup written before write; operator-customized field VALUES never touched.
  - **Per-product field categories:** bounded enum (`safety-floor` / `detection` / `audit` / `convenience`). Startup-banner warning fires ONLY for `safety-floor` misses (the kind that silently make the safety claim false); convenience misses surface only on explicit `profile doctor` invocation.
  - **`--apply` flag:** additively merges missing default fields; backs up the prior file to `<profiles.yaml>.bak-YYYYMMDD-HHMMSS` BEFORE write. Operator-customized field values never overwritten (the merge skips any field already present in the raw YAML map).
  - **`--acknowledge` flag:** writes a per-operator `.profiles-acknowledged-version` stamp; future `*bounce run` startup banners skip the §A19 warning until a new shipped-defaults version bumps the stamp.
  - **`--check` + `--json` flags:** silent + machine-readable shapes for CI / install scripts.
  - **Startup banner on `*bounce run`:** one-line caveat ("caveat: your safe-default profile is missing fields shipped in this version — run `*bounce profile doctor` for details (KNOWN-CAVEATS §A19)") emitted to stderr when a safety-floor field is missing AND no `.profiles-acknowledged-version` matches the current shipped-defaults version. Per [[security-team-positioning-safety-not-surveillance]]: framed as "your profile is behind" — NOT "you are non-compliant."
  - **gbounce special case:** v1.0 has no shipped-default profiles.yaml (rules are explicit-file via `--profile-rules-file`). The `gbounce profile doctor` surface ships for cross-product CLI parity per [[cross-product-agent-parity]]; it reports "current" + a Notes line explaining the architectural difference. G-Slice 2 will populate the catalog when gbounce gains a YAML profiles surface.
- **Engineering scope:** ~2-3 days cross-product (closed in 1 working session 2026-05-22).
- **Task:** #321.
- **Verification:** new launch-gate integration test `tests/integration/profile_upgrade_doctor_test.py` boots each of the 4 bouncer binaries, seeds a pre-#302-shape profile (sans the safety-floor field), asserts `profile doctor` exits 2 with the missing field surfaced under `safety-floor` category, asserts `--apply` merges the field + writes a timestamped backup, asserts re-running doctor reports current. Per-product regression: `TestDoctor_*` in `dbounce/internal/profile/doctor_test.go` + `kbouncer/internal/profile/doctor_test.go` + `gbounce/internal/profile/doctor_test.go`; `test_doctor_*` in `iam-roles/tests/bouncer/test_profile_doctor_321.py`. Each per-product suite carries the same 7 (Go: 7; Python: 7; gbounce v1.0: 5) tests covering fresh / missing-safety-floor / missing-convenience / apply-additive / apply-backs-up / acknowledge-silences / catalog-covers-embedded-defaults. The D3 role-effectiveness scenario now grades MEANINGFUL not PARTIAL after `--apply` (verified manually in the dogfood loop).
- **Docs:** `docs/PROFILE-UPGRADE.md` (NEW) carries the operator-facing runbook. README "First-60-seconds" section across all 4 repos mentions `profile doctor` as a one-time-after-upgrade step.

## A20. UAT R3 CRIT regressions — ibounce ProxyConfig missing rotation fields + gbounce `/audit/events` strips agent block — `STATUS: FIXED 2026-05-22`
- **Severity:** CRIT × 2 (both launch-blockers — one crashes proxy startup; the other silently breaks cross-product audit-query attribution)
- **Surfaced by:** UAT round 3 (`tests/dogfood/findings-2026-05-22-round-3.md`) — perpetual UAT agent on the `9a8606c` HEAD found that the two CLI surfaces shipped in earlier rounds had drifted out of sync with the dataclasses + projection functions they fed.
- **Symptom (historical):**
  - **R3-01 (ibounce)** — `src/iam_jit/bouncer_cli.py` accepted `--audit-log-max-size-mb` + `--audit-log-max-age-days` + `--audit-db-retention-days` options + threaded them as kwargs into `ProxyConfig(...)`, but `src/iam_jit/bouncer/proxy.py`'s `ProxyConfig` dataclass didn't declare the fields. Every `ibounce run` invocation that passed any of the three flags crashed immediately with `TypeError: ProxyConfig.__init__() got an unexpected keyword argument 'audit_log_max_size_mb'`. The flags were advertised in `--help` + `docs/LOG-RETENTION.md`; both said "works"; neither did. Pure CLI parity / declaration gap from the §A10 rotation work.
  - **R3-02 (gbounce)** — `store.DecisionRow` carried `AgentSessionID` + `AgentName` columns (per the #318 / #320 schema migration; persisted on `RecordDecision`; selected by `RecentDecisions`) — but `internal/proxy/audit_events.go:rowsToAuditEvents` constructed `audit.RequestInput` WITHOUT copying the two fields. Result: GET `/audit/events` returned `{"agent":{"name":"anonymous","detected_from":"unknown"}}` for EVERY event, even when the JSONL log + the in-memory exporter had the correct agent block. Cross-product `iam-jit audit query --filter agent.session_id=<id>` against gbounce returned zero matches. The CLI mirror `internal/cli/cli.go:rowsToEvents` had the same bug, breaking `gbounce audit tail --export jsonl` symmetrically.
- **Fix (cross-product surgical):**
  - **R3-01 (ibounce, `iam-roles`)** — `ProxyConfig` gains three `int | None = None` fields (`audit_log_max_size_mb` / `audit_log_max_age_days` / `audit_db_retention_days`); `None` means "use the shipped default" (the rotation module's `DEFAULT_MAX_SIZE_MB` / `DEFAULT_MAX_AGE_DAYS` / `DEFAULT_DB_RETENTION_DAYS` = 100 MB / 7 days / 30 days), an explicit `0` means "operator disabled the trigger" (per the Go bouncer convention documented in `[[cross-product-agent-parity]]`). `serve()` now threads `audit_log_max_size_mb` + `audit_log_max_age_days` into `AuditLogWriter(max_size_mb=..., max_age_days=...)` at startup; the startup log line surfaces all three effective values so the operator can confirm the rotation policy from logs alone. New regression test `tests/bouncer/test_ibounce_run_smoke.py` (7 cases) covers: dataclass accepts each field; `None` default semantics; `0` round-trip; click callback signature declares the params; full end-to-end `CliRunner.invoke(main, ["run", "--audit-log-max-size-mb", ...])` no longer surfaces `TypeError`; AuditLogWriter receives the threaded values; proxy.py source mentions both rotation kwargs at the writer init site (defensive against a refactor that adds the fields but forgets to wire them).
  - **R3-02 (gbounce, `gbounce`)** — `rowsToAuditEvents` (proxy package) + `rowsToEvents` (cli package) both copy `r.AgentSessionID` + `r.AgentName` into the `audit.RequestInput`. Per `[[cross-product-agent-parity]]`: matches the recipe dbounce + kbouncer already use. `audit.FromRequest` (`event.go:419-458`) validates via `IsValidSessionID` + `IsValidAgentName` + builds the OCSF `unmapped.iam_jit.agent` block — populated when either field is present (with `detected_from="http_header"`), the `{name:"anonymous", detected_from:"unknown"}` fallback otherwise. New regression test `TestRowsToAuditEvents_ThreadsAgentFieldsR302` + `TestRowsToAuditEvents_AnonymousWhenNoAgentR302` + `TestAuditEvents_HTTPSurfaceShowsAgentR302` in `internal/proxy/audit_events_test.go` covers the unit-level threading + the HTTP-wire-shape end-to-end.
- **Engineering scope:** ~1 working session 2026-05-22 (both regressions surgical; full cross-product verification ran).
- **Verification:** R3-01 — `ibounce run --port 19090 --audit-log-max-size-mb 50 --audit-log-max-age-days 14 --audit-db-retention-days 60` no longer surfaces `TypeError`; the values land on the `ProxyConfig` passed to `serve`. R3-02 — boot `gbounce run --upstream https://httpbin.org`; send `curl -H "X-Agent-Name: claude-code" -H "X-Agent-Session-Id: 01HXYZ..." http://127.0.0.1:<port>/get`; GET `/audit/events` returns `"agent":{"name":"claude-code","session_id":"01HXYZ...","detected_from":"http_header"}` (was `"name":"anonymous","detected_from":"unknown"` pre-fix).
- **Docs:** ibounce CHANGELOG (`iam-roles/CHANGELOG.md`) + gbounce CHANGELOG (`gbounce/CHANGELOG.md`) get §A20 entries.

## A21. Default-mode flip to DISCOVERY across the Bounce suite (BREAKING) — `STATUS: FIXED 2026-05-22`
- **Severity:** HIGH (breaking default change that materially shifts the v1.0 launch shape)
- **Surfaced by:** role-effectiveness eval `tests/dogfood/role-effectiveness-grades.md` 2026-05-22 — hit-rate landed at **23.1%** vs the 50% launch bar. Failure concentrated in NEGATIVE-VALUE (safe-default over-blocked legit ops — K1/K3/D2) + THEATER (static profiles couldn't carve by bucket/table/secret name — I1/I4/K2/D1). gbounce alone hit 66.7% because its primitives (deny_hosts + MITM URL+method) are operator-set OPT-IN denies, not blanket safe-defaults.
- **Decision:** per [[discovery-first-default]] (2026-05-22 founder direction) all 4 bouncers default to **discovery-mode pass-through** (the gbounce model). Existing strict profiles (readonly-admin-minus on ibounce; verb-deny safe-default on kbouncer; sql_read_only on dbounce) become NAMED OPT-IN PROFILES, NOT the default. Value reframes from "we block bad things" → "we observe + audit + issue scoped TTL roles" + dynamic deny ergonomics from `[[dynamic-deny-rules]]`.
- **What ships (BREAKING for operators upgrading from pre-pivot v1.0):**
  - **ibounce** — `ProxyConfig.default_mode` property surfaces `"discovery"` (active when `active_profile` is `None`/`full-user`/`none`) vs `"profile"` (active when operator explicitly picked a named profile). Banner copy refreshed: `default_mode=discovery|profile` is included in the headline + the "no profile selected" block names this discovery mode explicitly. `--profile safe-default` remains first-class opt-in.
  - **kbouncer** — banner copy refreshed; `full-user` (passthrough) is already the default; "default mode: discovery" framing surfaces on the passthrough path. `--profile safe-default` remains first-class opt-in. K8s API pass-through preserved.
  - **dbounce** — banner copy refreshed; `full-user` (passthrough) is already the default. **DCL safety floor JUDGMENT CALL:** `deny_dcl_targets_public` stays TIED to the `safe-default` profile (operator must opt into safe-default to get the floor). Rationale: a DCL floor that fires without an active profile would surprise operators in discovery mode who explicitly chose audit-only; the floor remains documented in §A5 + §B7 and lives on the safe-default profile. Operators who want the DCL floor without other safe-default writes-blocking pin `--profile safe-default` (the floor + writes block ship together by design).
  - **gbounce** — already discovery-default; CHANGELOG note documenting parity with the pivot.
- **Discovery-mode behavior contract (cross-product):**
  - Every request returns the upstream's actual response (pass-through; bouncer doesn't deny).
  - Every request generates an OCSF v1.1.0 audit event with the full agent block (per #318/#320).
  - Plan-capture (#132) records the permission shape regardless of profile.
  - Recommender (#173) sees the full call graph for eventual scoped-role issuance.
  - Operator value: full audit visibility + plan-capture for scoped role issuance (defense via role, not via bouncer) + foundation for opt-in dynamic denies (#324) + symmetric agent attribution across all 4 bouncers.
- **Migration path:** operators on pre-pivot v1.0 builds where any bouncer auto-applied a safe-default profile (silently or otherwise) must pin `--profile safe-default` to keep pre-pivot behavior. See `docs/PROFILE-UPGRADE.md` for the cross-product upgrade path.
- **SUPERSEDED reference:** `[[safe-default-is-readonly-admin-minus]]` documents the v1.0-alpha *shape* of the safe-default profile; the *default* is no longer to apply it. The memo content remains accurate for operators who explicitly opt in via `--profile safe-default`.
- **Re-grade:** `tests/dogfood/role-effectiveness-grades-post-pivot.md` (NEW) holds the updated grades. The pre-pivot file (`role-effectiveness-grades.md`) is preserved verbatim for historical comparison.
- **Engineering scope:** ~1 working session 2026-05-22 (surgical; mostly banner copy + one new `default_mode` property on the ibounce ProxyConfig dataclass).
- **Docs:** ibounce + kbouncer + dbounce CHANGELOGs each get a `### Changed` entry with the BREAKING-CHANGE marker; gbounce CHANGELOG gets a note. README first-60-seconds sections reflect the discovery default on each product.

## A22. Cross-product: 20-terminal concurrency support on one machine — `STATUS: FIXED 2026-05-22`
- **Severity:** HIGH (launch-blocker — independent reviewer hard-question #4 + §B13 ceiling of 1-3 concurrent terminals was below par for any team larger than a solo founder)
- **Surfaced by:** founder direction 2026-05-22 + reviewer hard-question #4 — §B13 of this doc documented "1-3 concurrent terminals in v1.0; 10+ produces session-attribution issues." Target: lift to 20+ on a single machine (8-engineer team with multiple terminals each).
- **Architectural reminder:** one bouncer instance per operator (e.g., `ibounce run --port 8767`); multiple terminals point `AWS_ENDPOINT_URL=http://127.0.0.1:8767` and SHARE the proxy. So this is NOT multi-instance scaling — it is ONE bouncer instance serving N concurrent agent sessions, each tagged with its own `X-Agent-Session-Id`.
- **Diagnosis (20-writer SQLite microbench at 600 calls per writer = 12,000 attempts):**
  - **ibounce (Python):** already passing — 12,000/12,000 committed, 0 errors, p99 ≈ 10ms (single `threading.Lock` + WAL + autocommit). HTTP-level load test (20 sessions × 10 RPS × 60s = 12,000 reqs through the actual aiohttp proxy) confirms 0 errors, p99 = 36ms, 20/20 distinct session-id attribution intact.
  - **kbouncer (Go):** **CRITICAL** — 209/12,000 committed; **11,791 audit-write errors** (`SQLITE_BUSY`). Cause: `sql.DB` pool with `MaxOpenConns=4` + SQLite default rollback-journal mode + no `busy_timeout` PRAGMA. Two pool goroutines could simultaneously `BEGIN IMMEDIATE` on different connections; the second got immediate `SQLITE_BUSY`.
  - **gbounce (Go):** **CRITICAL** — 196/12,000 committed; **11,804 audit-write errors** (`SQLITE_BUSY`). Same root cause as kbouncer (no PRAGMAs at all).
  - **dbounce (Go):** 12,000/12,000 committed, 0 errors (busy_timeout=5000 absorbed contention) but p99 = 86ms and **max latency = 1.4 seconds** because all writers serialized at the file-level write lock in rollback-journal mode.
- **Fix (one-line DSN change per Go bouncer; ibounce unchanged):**
  - **kbouncer:** `internal/store/store.go` `Open()` switches from bare `sql.Open("sqlite", path)` to a DSN with `journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL`, `foreign_keys=1`. Applied via DSN so EVERY pool connection inherits the PRAGMAs (per-connection bind, not session-set).
  - **gbounce:** identical fix — same DSN PRAGMA triple. gbounce had ZERO PRAGMAs before this change.
  - **dbounce:** ADD `journal_mode=WAL` to the existing PRAGMA triple. Crucially, dbounce's LOW-D8-12 audit closure intentionally pinned `synchronous=FULL` for durability; we PRESERVE that — under WAL, `synchronous=FULL` still fsyncs the WAL on every commit (audit-row durability matches pre-#296), the only difference is parallel writers no longer serialize at the journal header.
- **Verification (after-fix re-run of the same 20-writer 600-calls-each probe):**
  - **kbouncer:** 12,000/12,000 committed, 0 errors, p99 = 10.04ms, max = 104ms. Throughput jumped from ~700 rps to 10,293 rps.
  - **gbounce:** 12,000/12,000 committed, 0 errors, p99 = 8.18ms, max = 130ms. Throughput 14,000 rps.
  - **dbounce:** 12,000/12,000 committed, 0 errors, p99 dropped from 86ms → 11.77ms; max-latency dropped from 1,435ms → 132ms (~10x improvement).
  - **ibounce:** end-to-end HTTP load test at 50 sessions × 10 RPS × 60s = 30,000 client requests: 0 errors, p99 = 85.5ms, 50/50 distinct session-id attribution intact, 30,000 audit-export events emitted (zero dropped).
  - **30-writer stretch test** holds across all four bouncers — kbouncer p99 = 12.4ms, gbounce p99 = 9.75ms, dbounce p99 = 16.5ms, ibounce p99 = 41.4ms with 30/30 distinct session attribution.
- **Verified ceiling:** **30 concurrent terminals at p99 < 50ms per bouncer with 0 errors + 100% session-attribution accuracy** (one bouncer at a time; not all four under simultaneous load). Pass criteria for the 20-terminal target was 0 errors / p99 < 200ms / 0 dropped audit rows / 100% session-id correlation — all four bouncers exceed it.
- **Out of scope (DOCUMENTED, deferred):**
  - Multi-process bouncer instances (none of the four ship in a multi-process shape; the WAL config DOES safely support it if a future Enterprise daemon goes there).
  - Running all 4 bouncers under simultaneous 20-session load (separate concern — that's a 4-product resource-explosion test, not §A22's scope).
  - Latency under a sustained 100-RPS-per-session firehose (the 10-RPS-per-session × 20-sessions = 200 RPS / proxy was the §A22 spec; 100 RPS × 20 = 2,000 RPS / proxy is out of scope and would benefit from the audit-write-batching follow-up).
- **Engineering scope:** ~1 working session 2026-05-22 (diagnosis-heavy + one DSN line per Go bouncer + load-probe regression tests committed under the `loadtest` build tag).
- **Docs:** §B13 below struck-through + replaced with the measured ceiling. Per-bouncer CHANGELOG entries note the PRAGMA tuning + verified concurrency posture.

## A18. `/audit/events` wire-shape parity gap — `STATUS: FIXED 2026-05-22`
- **Severity:** CRIT (cross-bouncer audit-query claim was wire-protocol false)
- **Surfaced by:** UAT round 2 — perpetual UAT agent verified the "cross-bouncer audit query via `agent.session_id`" claim shipped in §A16 against the HTTP `/audit/events` endpoint that powers `iam-jit audit query`. JSONL was correct; the HTTP wire shape that SOC analysts actually consume returned ZERO dbounce events + mis-labelled `detected_from` on kbouncer.
- **Symptom (historical):**
  - dbounce — `decisionRowsToAuditEvents` routed through `FromDecisionRow` with an empty `Agent`, so every `/audit/events` row emitted `"agent": {}` regardless of what the in-memory exporter pipeline knew. Cross-bouncer query by `agent.session_id` returned zero dbounce hits.
  - kbouncer — `agentInfoFromDecisionRow` heuristically guessed `detected_from=mcp_clientinfo` whenever an `agent_session_id` was persisted, mis-labelling http_header-detected requests as MCP-detected. SIEM filters that distinguish "agent declared via HTTP header" from "agent declared via MCP handshake" silently lied.
  - Cross-product — when agent header validation failed, only the `/healthz` counter `total_agent_headers_rejected` bumped + a truncated-stderr line surfaced. The audit event itself silently fell through to `name=anonymous` with no breadcrumb naming WHICH header failed or WHY.
  - iam-jit CLI — the spec-example copy-pasted shape `--filter agent.session_id=X` returned HTTP 400 from every per-bouncer parser (only the canonical `unmapped.iam_jit.agent.session_id=X` long form was accepted).
- **Fix (#320, 4-slice surgical):**
  - **Slice 1 — dbounce:** v7 schema bump adds `decisions.agent_name TEXT`, `decisions.agent_session_id TEXT`, `decisions.detected_from TEXT NOT NULL DEFAULT 'unknown'` via idempotent `ALTER TABLE` migration. Proxy hot-path looks up the agent registry on every decision + persists the fingerprint alongside the row; `/audit/events` projection threads the persisted agent into `audit.FromDecisionRowWithAgent`. Pre-#320 rows surface NULL → the projection drops the agent block (historical event shape preserved per `[[creates-never-mutates]]`).
  - **Slice 2 — kbouncer:** v9 schema bump adds `decisions.detected_from TEXT NOT NULL DEFAULT 'unknown'` (the v8 #289 columns landed without it). Replaces the read-time `agentInfoFromDecisionRow` heuristic with a stored-column read. Both proxy-package + cli-package siblings updated.
  - **Slice 3 — all 4 bouncers:** structured `agent_header_rejection` breadcrumb lands at `unmapped.iam_jit.ext.agent_header_rejection` whenever an inbound X-Agent-* header (or dbounce `application_name` tag) fails validation. Each entry records `field` + bounded enum `reason` (`invalid_name_charset` / `invalid_name_length` / `invalid_session_id_format` / `invalid_session_id_length` / dbounce-only `application_name_unparseable`) + `value_redacted_length`. Raw header value is NEVER included — only its length, for safe forensics. The pre-existing §A17 string `agent_rejected_reason` stays alongside for backward compat (additive per `[[creates-never-mutates]]`).
  - **Slice 4 — iam-jit CLI:** short-form filter aliases (`agent.session_id=X` / `agent.name=X` / `agent.detected_from=X`) expand to their canonical `unmapped.iam_jit.agent.*` paths CLIENT-SIDE before forwarding so each bouncer's filter parser still sees the canonical long form. CLI help + docs updated.
- **Engineering scope:** ~2-3 days cross-product (closed in 1 working session 2026-05-22).
- **Task:** #320.
- **Verification:** new launch-gate integration test `tests/integration/audit_events_wire_parity_test.py` brings up all four bouncers, fires one request per bouncer with a shared session id, hits each `/audit/events` endpoint + asserts the agent block lands with the correct `detected_from` per transport, AND runs `iam-jit audit query --filter agent.session_id=X` (short form) + asserts 4 events back. Per-product regression tests (`TestAuditEvents_320_*` in dbounce + kbouncer + gbounce; `test_320_*` in ibounce + iam-jit) cover the slice contracts. Existing #318 + #319 + #289 regression tests still pass.

## A15. Cloud-neutral object-storage NDJSON sink (S3-compatible) — `STATUS: FIXED 2026-05-22`
- **Severity:** HIGH (per founder direction 2026-05-22: bouncers other than ibounce are cloud-neutral; AWS-only Security Lake adapter alone isn't enough)
- **Why pre-launch:** operators need their SIEM/security-tool to collect bouncer logs from a bucket. Pre-#317: HTTPS webhook (synchronous push) + Security Lake (AWS-only parquet). Operators on GCS / Azure / MinIO / R2 / B2 had no pull-based collection path.
- **What shipped (#317, 2026-05-22):**
  - New exporter on every Bounce product: `--audit-object-storage-endpoint URL --audit-object-storage-bucket NAME --audit-object-storage-prefix PREFIX --audit-object-storage-region REGION --audit-object-storage-credentials-file PATH --audit-object-storage-rotation-minutes N --audit-object-storage-max-size-mb N --audit-object-storage-instance-id ID`
  - Per [[cross-product-agent-parity]]: identical flag shape on ibounce + kbounce + dbounce + gbounce.
  - Uses S3-compatible API via boto3 (ibounce, Python) + aws-sdk-go-v2 (kbouncer + dbounce + gbounce, Go); works with AWS S3 (native), GCS (S3 interop / HMAC keys), Azure Blob (S3-compat layer), MinIO, Cloudflare R2, Backblaze B2, DigitalOcean Spaces.
  - Authentication: standard AWS-style env vars (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN) OR explicit `--audit-object-storage-credentials-file` (YAML or INI; file overrides env vars when both are present).
  - Output format: NDJSON (one OCSF event per line, gzip-compressed); files rotated every `--audit-object-storage-rotation-minutes` (default 5) OR `--audit-object-storage-max-size-mb` (default 16), whichever fires first.
  - Path convention: `{prefix}/year=YYYY/month=MM/day=DD/hour=HH/{product}-{instance_id}-{timestamp}.jsonl.gz` — Hive-style partitioning. Athena / BigQuery / Spark / Trino auto-discover partitions from this layout.
  - SIEM-pull-friendly: collectors do `LIST + GET` against the prefix; new files land at predictable cadence.
  - Works ALONGSIDE existing webhook / Security Lake adapters per [[creates-never-mutates]] — additive composition; the operator can run multiple sinks simultaneously.
  - Per [[self-host-zero-billing-dependency]]: operator owns the bucket; iam-jit-the-company never receives the data.
  - Refuse-to-start posture: `Start()` issues HeadBucket on each writer so credential / endpoint / bucket-name misconfigurations surface immediately, not at first flush.
  - On shutdown: pending NDJSON buffer finalized synchronously (matches the Security Lake adapter's flush-on-stop posture) so a clean restart doesn't drop in-memory rows.
- **What does NOT ship in v1.0** (deferred to v1.1 per [[don't-tailor-to-lighthouse]]):
  - Native GCS auth (Workload Identity / Service Account)
  - Native Azure Blob auth (Managed Identity)
  - Reason: S3-compatible covers ~95% of "drop logs in a bucket" via interop; native auth is friction-reducer for v1.1
- **Verification:**
  - **ibounce:** `tests/bouncer/test_audit_export_object_storage.py` — 27 tests cover defaults, credentials resolution (env + YAML + INI), partition path format, construction refusal, write/flush happy path, status surface, size-cap synchronous flush, drop-on-buffer-full, write-before-start no-op, stop-flushes-pending, put_object failure -> writes_ok=false, and the rotation timer triggering a background flush.
  - **kbouncer:** `internal/audit/object_storage_test.go` — same 19 test surface (Go).
  - **dbounce:** `internal/audit/object_storage_test.go` — same 19 test surface (Go).
  - **gbounce:** `internal/audit/object_storage_test.go` — same 19 test surface (Go).
- **Task:** #317 — completed 2026-05-22.

## A17. UAT findings cluster — cross-product CLI parity + doc-truth-up gaps — `STATUS: FIXED 2026-05-22`
- **Severity:** CRIT + HIGH (per `[[uat-findings-2026-05-22]]`; 1 CRIT + 5 HIGH launch-blockers)
- **Surfaced by:** dogfood UAT loop 2026-05-22 — perpetual UAT agent exercised the 6 recent slices as a brand-new operator. The cross-product slices (#311 retention, #304 caveats, #316 runbook) shipped on ibounce + gbounce but didn't carry kbounce + dbounce CLI wiring despite specs saying "cross-product parity." The Go impl shipped in shared library code; CLI subcommand registration on each bouncer was a separate step that got missed.
- **Findings (closed in #319, 2026-05-22):**
  - **F-316-1 CRIT — FIXED** — PRODUCTION-LOG-STORAGE.md §2.7 rewritten to use the actual graceful-shutdown path (SIGTERM → audit-channel teardown drains in-flight sends + flushes queues before close). No `audit-export flush --wait DUR` subcommand ships; the bouncer's existing signal handler IS the drain (Python: aiohttp `runner.cleanup()` → audit-channel `.stop()` chain; Go: cobra `signal.NotifyContext` → `s.Shutdown(ctx)` → audit-channel close). Belt-and-braces: §2.7 also recommends setting `--audit-log-path` alongside the webhook so a webhook outage during shutdown still leaves a local file for post-job upload.
  - **F-311-3 HIGH — already FIXED** — verified 2026-05-22 that `kbounce logs {archive,purge,verify}` + `dbounce logs {archive,purge,verify}` + `kbounce doctor {caveats,logs}` + `dbounce doctor {caveats,logs}` all ship + work via `/tmp/kbounce --help` + `/tmp/dbounce --help`. The findings doc was stale.
  - **F-311-4 HIGH — FIXED** — added `--audit-log-max-size-mb` + `--audit-log-max-age-days` + `--audit-db-retention-days` flags + matching env-var overrides (`<PRODUCT>_AUDIT_LOG_MAX_SIZE_MB`, etc.) to all four `*bounce run` surfaces. ibounce wires the size + age values into the live `AuditLogWriter`; kbounce + dbounce wire both into the live `audit.LogWriter`; gbounce accepts the flags + surfaces resolved values but the writer-level rotation hook is deferred (per the LOG-RETENTION.md parity-matrix gbounce row — concurrent-agent work on `internal/audit/log.go`). DB-retention is consumed by the on-demand `*bounce logs purge` path across all four products.
  - **F-304-1 HIGH — already FIXED** — see F-311-3 verification.
  - **F-304-2 HIGH — FIXED** — `dbounce run` now calls `caveats.BannerLines(caveats.Trigger{...})` after the preset banner + before the `signal.NotifyContext` install, on stderr, gated by `--quiet-banner`. kbounce already had the equivalent (verified). ibounce + gbounce unchanged.
  - **F-316-2 HIGH — FIXED** — PRODUCTION-LOG-STORAGE.md TL;DR table swapped the gbounce GCP row to ibounce + added explicit "(gbounce v1.0: use JSONL + Fluent Bit / Vector — see §3 gap)" annotation. The per-product parity matrix at the bottom of the doc + the cross-product line in §2.7 already correctly scoped webhook to G-Slice 6.
- **Medium follow-ups — FIXED:**
  - F-311-1 — `gbounce logs archive` now errors loudly when the directory contains zero audit-shaped files (filename-prefix `audit*` + suffix `.jsonl{,.gz}`/`.db{,.gz}` filter) so the operator sees the empty-tar case immediately instead of silently producing a 50-byte gzip trailer.
  - F-311-2 — `gbounce logs verify` now flips `OK=false` + returns a non-zero exit when `files_checked == 0`, with a clear stderr message naming the dir + the three likely root causes (writer never started / wrong dir / `--audit-log` pointed at a sibling path). JSON output also reflects the corrected `ok=false`.
  - F-304-3 — `gbounce doctor --help` Long help now lists both `caveats` AND `logs` subcommands + the `RunE` error message points at both.
  - F-308-1 — invalid `X-Agent-Name` / `X-Agent-Session-Id` headers now land in the audit event at `unmapped.iam_jit.ext.agent_rejected_reason` as bounded enum strings (`session_id:invalid_charset_or_length`, `agent_name:invalid_charset_or_length`, semicolon-joined when both fail). Raw header values are NEVER included (the truncated stderr line emitted by `logAgentHeaderRejected` remains the only place the raw value surfaces, with control-char filtering).
- **Engineering scope:** ~3-5 days cross-product (closed in 1 working session 2026-05-22).
- **Task:** #319.
- **Verification:** dogfood UAT loop re-run against each repo confirms the original CRIT + 5 HIGH gaps no longer reproduce; med follow-ups verified via path-targeted manual smoke + the existing regression-test suite continues to pass.
- **Severity:** HIGH (pre-launch feature gap; operators needed to block specific domains without MITM)
- **Symptom (historical):** gbounce could audit-log every CONNECT, but couldn't REFUSE one based on destination host. Operators who wanted "block this agent from calling api.openai.com" had no way to do it.
- **Fix (#314, gbounce commit `39afcf1`):**
  - `--deny-host <entry>` CLI flag (repeatable; union with `--deny-hosts-file`).
  - `--deny-hosts-file PATH` flag accepting newline-delimited entries OR the YAML-list shape the future profile-mode YAML will use (`deny_hosts:` key + `- entry` lines + inline `deny_hosts: [a, b]`). Forward-compatible with G-Slice 2 profile YAML.
  - Wildcard semantics: `*.example.com` matches `api.example.com`, `foo.bar.example.com`, AND bare `example.com` (operator-friendly; documented in `internal/proxy/deny_hosts.go` header).
  - Parse-time rejections (clear errors that name the offending entry):
    - Bare `*` rejected (use `--default-policy deny` instead — queued for G-Slice 2).
    - Multi-level wildcards (`*.foo.*.bar.com`, `foo.*`, `*.*`) rejected.
    - Entries with embedded scheme / path / port / whitespace rejected.
  - On CONNECT match: gbounce returns 403 to the client + emits OCSF event with `verdict=DENY`, `status_id=4 (Denied)`, `activity_id=6 (Connect)`, `ext.deny_reason="matched deny_hosts: <rule>"` naming the operator-written rule. Upstream TCP connection NEVER opened.
  - Order of evaluation: deny WINS over any future allow_hosts list (safer-by-default per `[[safety-mode-lean-permissive]]`).
  - `/healthz` surfaces `deny_hosts_count` + `total_deny_host_matches` for liveness-probe visibility.
- **Verification:** 11 regression tests in `gbounce/internal/proxy/deny_hosts_test.go` cover exact match, wildcard subdomain, wildcard-matches-bare-domain, wildcard-does-NOT-match-unrelated, not-in-list-allows, bare-`*`-rejected-at-parse, multi-level-wildcard-rejected-at-parse, audit-event-shape (verdict + status_id + deny_reason + dst_endpoint + activity_id=Connect), deny-wins-over-allow, CLI+profile merge, and the /healthz counter surface. E2E sanity-run on a free port (8081 + mgmt 8770) with `--deny-host '*.openai.com' --deny-host 169.254.169.254`: `curl -x http://127.0.0.1:8081 https://api.openai.com/v1/models` → 403; `curl -x http://127.0.0.1:8081 https://openai.com/` → 403 (wildcard bare-domain); `curl -x http://127.0.0.1:8081 https://169.254.169.254/...` → 403; allowed hosts flow through. Audit log carries the documented OCSF deny shape.
- **Task:** #314.

## A13. gbounce: MITM mode v1.0 BETA (default-off, PII/PCI leak risk) — `STATUS: FIXED 2026-05-22`
- **Severity:** HIGH (pre-launch feature; ships v1.0 but flagged BETA + default-off because terminated TLS exposes bodies to every persistence sink — `[[mitm-beta-pii-pci-concern]]`)
- **Why pre-launch:** founder direction 2026-05-22 — security teams in early sales conversations ask "can you see inside TLS?" Without MITM at all, the answer "no, by design" kills some deals. BETA pre-launch flips the answer to "yes, opt-in; here are the constraints."
- **Why BETA (not GA) in v1.0:** when MITM terminates TLS, request/response bodies flow plaintext through gbounce. Every persistence sink then receives those bodies unless redacted:
  - Local JSONL audit log (`--audit-log-path`)
  - SQLite audit DB (`*bounce audit query`)
  - HTTPS webhook sinks (#257 — Splunk / Datadog / Sentinel)
  - AWS Security Lake parquet (#258)
  - S3-compat NDJSON sink (#317, queued)
  - Diagnostics bundle (`*bounce diagnostics`)

  Default-on redaction strips CREDENTIAL-shaped fields (Authorization, Cookie, x-api-key, *_token, *_secret, password, api_key). It does NOT strip PII (emails, SSNs, addresses) or PCI (PAN, CVV, expiry) or PHI (patient name + DOB) — those need operator-configured redaction policy. For HIPAA / PCI-DSS / GDPR workloads, operators MUST configure their own redaction before enabling MITM, or stay on default CONNECT mode (never sees bodies).
- **What ships v1.0 BETA:**
  - `gbounce ca install` / `gbounce ca uninstall` / `gbounce ca info` — CA cert lifecycle, ~/.iam-jit/gbounce/ca/
  - `gbounce run --mode mitm` — opt-in flag; refuses to start if CA isn't installed
  - Per-host cert generation (signed by our CA) with brief LRU cache
  - Default-on credential redaction (Authorization / Cookie / x-api-key / *_token / *_secret / JSON fields)
  - `--audit-log-include-bodies` flag OFF by default; loud warning if enabled
  - BETA stderr banner at MITM startup: "BETA: bodies may contain PII/PCI; default redaction strips credentials only — configure your own pattern for PII/PCI workloads"
  - Per-runtime warning in `gbounce ca install` output: "Beta. If you handle PHI / PCI / PII, configure operator-side redaction before enabling MITM"
  - Audit event extensions: URL path + method + response status visible (none of these are PII per se)
  - Profile rules extended: match on method + path + query_param.NAME
  - docs/MITM-MODE.md leads with BETA + PII/PCI warning in §1
- **v1.1 GA criterion (NOT pre-launch):** pluggable PII/PCI redaction policy (regex packs for PAN/CVV/SSN/email/etc., structured field detectors, operator-configurable on-detection-action). Until that ships, MITM stays BETA.
- **Honest framing:** cert-pinning SDKs (most modern AWS SDKs, banking SDKs, some mobile SDKs) WILL break under MITM; documented explicitly.
- **Engineering scope:** ~7-10 days (CA lifecycle + per-host cert gen + TLS interception + redaction + audit + tests + docs + BETA wiring).
- **Fix shipped (gbounce #315, 2026-05-22):** opt-in `--mode mitm` ships v1.0 default-off. New `gbounce ca {install,uninstall,info,rotate}` subcommand surface generates a local ECDSA P-256 CA at `~/.iam-jit/gbounce/ca/` (10-year lifetime; common name `iam-jit gbounce local CA` — no operator-identifying info). The install command prints platform-specific OS trust-store install commands (macOS `security`, Debian/Ubuntu `update-ca-certificates`, RHEL/Fedora `update-ca-trust`, Firefox manual). MITM-mode CONNECT hijacks the client, terminates TLS with a per-host minted cert (LRU cache size 1024), and re-encrypts to the real upstream. Audit log carries `unmapped.iam_jit.ext.{url_path, url_query, request_method, request_body_redacted, response_status}`; cert-pinning failures land under `mitm_upstream_handshake_failed` + `mitm_upstream_handshake_error`. Body redaction DEFAULT-ON: credential-shape headers (Authorization, Cookie, x-api-key, x-anthropic-api-key, x-openai-api-key, x-aws-access-key-id, x-vercel-protection-bypass, x-github-token, x-auth-token, x-access-token, ...) + JSON body fields (`*_token`, `*_secret`, `*_key`, `password`, `api_key`, `client_secret`, `refresh_token`, ...) replaced with `***REDACTED-CREDENTIAL***`. Profile-rule shape supports `host` (exact + leading wildcard) + `method` (string or list) + `path` (exact / prefix / RE2 regex) + `query_params` (per-name value match); rules with MITM-only predicates skip in CONNECT mode so the existing discovery shape is unchanged. Private-key permissions enforced (0o600; refuses to start with group/world-readable). CA expiry check at startup. /healthz exposes `mitm_enabled`, `mitm_rules_count`, `mitm_audit_include_bodies`, `total_mitm_denies`, `total_mitm_upstream_handshake_failures`. 28-test regression suite covers CA lifecycle (generate / overwrite refusal / key-perm rejection / info / uninstall idempotency / missing-file helpful-error), per-host cert generation (LRU hit-rate + host normalization + chain-verify), redaction (Authorization header / vendor API keys / JSON `api_key` fields / nested-object walk / non-JSON unchanged / query-param scrub), profile rules (path / method / host wildcard / query-param / prefix / regex / multi-level-wildcard reject / `RequiresMITM()` semantics + CONNECT-mode skip), and proxy end-to-end (refuses start without CA / audit-event ext-key population / cert-pinning graceful 502 / profile DENY enforcement / latency soft cap). Canonical docs: gbounce/docs/MITM-MODE.md.
- **Task:** #315. Composes with `[[mitm-beta-pii-pci-concern]]`, `[[ibounce-honest-positioning]]`.

## A8. kbouncer + dbouncer: stale `bin/` binaries in repos — `STATUS: FIXED (2026-05-22)`
- **Severity:** HIGH
- **Symptom (historical):** README led with `go build ./cmd/<binary>` followed by `./<binary> run`, encouraging a workflow where someone could commit a pre-built binary that lags source by days. Users picking up the repo and running the stale `./bin/<binary>` silently missed recent features (UI, audit endpoints, agent identity, etc.).
- **Fix:** Both repos canonicalize `go install` as THE install path. The README "Install" section now leads with `go install github.com/trsreagan3/<repo>/cmd/<binary>@latest`, which builds fresh from source every time — no stale binary surface possible. Local-dev iteration uses `make build` (writes to gitignored `./bin/`) or `make install` (writes to `$GOPATH/bin`). `bin/` was already gitignored in both repos; this slice locks in the documentation + Makefile shape to keep it that way.
- **Verification:** `go install github.com/trsreagan3/kbouncer/cmd/kbounce@latest` and `go install github.com/trsreagan3/dbounce/cmd/dbounce@latest` both succeed against the public module proxy (gbounce-routed run on 2026-05-22 — kbounce v0.0.0-20260522064802-131bcaca7334, dbounce v0.0.0-20260522064202-a7a8a2d49a4d).
- **Tasks closed:** #306 + #307. ibounce (Python; iam-roles repo) ships via `pip install`; gbounce ships via the same `go install` shape as kbounce/dbounce and is unaffected by this caveat.

---

## A24. Pre-launch claims-vs-functionality audit fix sweep — `STATUS: FIXED 2026-05-23`
- **Severity:** HIGH (cluster of doc overclaims + 1 load-bearing test gap surfaced by the 2026-05-23 claims-vs-functionality audit; left unfixed, every claim about iam-jit's discovery-default + recommender + org-distribution would have shipped with a documented gap between docs and shipped surface)
- **Symptom (historical):** 2026-05-23 audit found:
  1. **H1 — Org-distribution doc overclaim:** `docs/ORG-PROFILE-DISTRIBUTION.md` + README L436/L489 documented `bounce init --org-url ...` + `bounce profile sync` + ETag-based sync as shipped CLI surface. Code only ships `ibounce profile install --from URL --sha256 <hex>` (one-shot, per-profile, no bundle index, no ETag sync). Engineers following the docs would hit "command not found".
  2. **H2 — `RECOMMENDER-API-SPEC.md` overclaim:** the spec doc had a one-line "Status: design draft" note at the top that was easy to miss; README's MCP-tools list (§Status) enumerated `reduce_policy` / `get_reduction_checklist` / `apply_reduction_checklist` alongside actually-shipped tools with no marker.
  3. **M1 — `secret:NAME` shorthand non-embedding:** `docs/DYNAMIC-DENY-RULES.md` "Honest caveats" section didn't disclose that `secret:NAME` shorthand fires at the bouncer layer only and is NOT embedded into iam-jit-issued role Deny statements (recommender Deny-injection per #324f requires ARN-shaped targets). Operators wanting defense-in-depth at both layers needed to know to use `arn:aws:secretsmanager:*:*:secret:NAME-*`.
  4. **M3 — gbounce LogWriter rotation gap:** README L395 said audit-log rotation "ships on kbounce / dbounce / gbounce" with no qualifier; in reality gbounce ships the rotation primitives + CLI surface but the WRITER-side rotation hook is pending (deferred to v1.1 per §A10).
  5. **Test gap — `ProxyConfig.default_mode` property had no unit coverage:** the property is the discovery-vs-profile mode selector that the 38.5% / 69.2% / 84.6% role-effectiveness hit-rate numbers measure against. A silent regression flipping the truth table would invalidate the published claims.
- **Fix (#343):**
  1. Added a prominent v1.0-vs-v1.1 status note at the top of `docs/ORG-PROFILE-DISTRIBUTION.md`; reshaped §3 (Distribution mechanics), §4 (Engineer onboarding), §6 (Update flow), §7 (CI/CD), §8 (Audit chain) so the shipped `ibounce profile install --from URL --sha256 <hex>` flow is the PRIMARY path and the v1.1 `bounce init --org-url` + `bounce profile sync` surface is clearly marked PLANNED. README L436 + L489 rewritten to cite the actually-shipped CLI command.
  2. Strengthened the status banner at the top of `docs/RECOMMENDER-API-SPEC.md` so it's impossible to miss it's a design draft, with pointers to the actually-shipped code paths (`src/iam_jit/bouncer/recommender.py` per #173, `src/iam_jit/dynamic_denies/recommender.py` per #324f). README MCP-tools list footnotes `reduce_policy` / `get_reduction_checklist` / `apply_reduction_checklist` as design-draft.
  3. Added a new bullet to `docs/DYNAMIC-DENY-RULES.md` "Honest caveats" disclosing the `secret:NAME` shorthand non-embedding behavior + the explicit-ARN workaround.
  4. README L395 audit-log paragraph now notes gbounce LogWriter-level rotation is deferred to v1.1 per §A10.
  5. Added `tests/bouncer/test_default_mode.py` (15 tests) covering the discovery-vs-profile truth table: `None` / `""` / `"full-user"` / `"none"` → "discovery"; any other profile name → "profile". Parametrize-driven row for table-locked coverage.
- **Verification:** 15/15 tests in `tests/bouncer/test_default_mode.py` pass; doc audits confirm no remaining unflagged `bounce init --org-url` / `bounce profile sync` references in either ORG-PROFILE-DISTRIBUTION.md or README; RECOMMENDER-API-SPEC.md status banner is now unmissable.
- **Tasks closed:** #343

---

## A23. Missing / unattributed LICENSE + NOTICE files across the suite — `STATUS: FIXED 2026-05-23`
- **Severity:** HIGH (blocks Anthropic Cyber Verification Program application #338; renders "open source" competitive claim technically false per Berne Convention — code without LICENSE = all-rights-reserved by default)
- **Symptom (historical):** License verification on 2026-05-23 found:
  - **kbouncer** — NO `LICENSE` file at all
  - **iam-roles + gbounce + dbounce** — `LICENSE` files were canonical Apache-2.0 text BUT the boilerplate copyright line was unfilled (`Copyright [yyyy] [name of copyright owner]`) or wrong (`Copyright 2026 dbounce contributors` in dbounce)
  - **All 4 repos** — NO `NOTICE` file
  - **iam-roles + gbounce READMEs** — `## License` section was a one-liner (`Apache-2.0.` / `Apache 2.0. See [LICENSE](LICENSE).`) without copyright attribution
  - **kbouncer + dbounce READMEs** — NO `## License` section at all
  - `pyproject.toml` declared `license = { text = "Apache-2.0" }` but didn't ship `LICENSE` or `NOTICE` in the wheel
- **Fix (#342):** Apache-2.0 with `trsreagan3` as the copyright holder across the full suite. Per repo:
  - `LICENSE` — canonical Apache-2.0 text verbatim, copyright line `Copyright 2026 trsreagan3` (created in kbouncer; copyright line corrected in iam-roles + gbounce + dbounce)
  - `NOTICE` — minimal attribution with per-product name (iam-jit (Python) / gbounce / kbouncer / dbounce)
  - README `## License` section — populated / added with `Apache-2.0 — see [LICENSE](./LICENSE). Copyright 2026 trsreagan3.`
  - `pyproject.toml` (iam-roles only) — added `[tool.setuptools].license-files = ["LICENSE", "NOTICE"]` so the wheel ships both files; kept the existing `license = { text = "Apache-2.0" }` form to avoid bumping `setuptools>=68` to `>=77.0.3` just for PEP 639
- **Deferred:** Per-source-file `SPDX-License-Identifier: Apache-2.0` headers (good hygiene but high churn; v1.1 candidate per `[[deliberate-feature-completion]]`)
- **Verification:** All 4 repos now satisfy `ls LICENSE NOTICE` + `grep "^## License" README.md` + `grep "Copyright 2026 trsreagan3" LICENSE`
- **Tasks closed:** #342

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
HTTPS through gbounce shows `CONNECT host:443` in the default discovery mode. Not request URL/body. Per `[[ibounce-honest-positioning]]` — no MITM = more privacy + deployability.
**URL-level visibility:** use `--upstream` rewrite mode (HTTP only) OR opt INTO MITM mode (#315 / §A13 — `gbounce ca install` + `gbounce run --mode mitm`). MITM IS available v1.0 default-off. Cert-pinning SDKs WILL break under MITM; flip those back to discovery mode per the honest trade-off. Full reference: gbounce/docs/MITM-MODE.md.

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

## B13. Cross-product: concurrent-terminal ceiling — `RESOLVED 2026-05-22` (was: 1-3 concurrent terminals in v1.0)
~~**Why:** active-mcp-session.json is single-entry; profile + pause state are global. 10+ concurrent terminals produce session-attribution issues.~~
~~**v1.1 plan:** task #296 multi-session SQLite refactor → 20-terminal target.~~

**Updated 2026-05-22 per §A22:** the original 1-3 ceiling was a CONSERVATIVE PLACEHOLDER, not a measured limit. Task #296 ran the 20-session × 10-RPS × 60s load probe against each bouncer and confirmed:
- **ibounce:** verified ceiling **50 concurrent terminals** (p99 = 85.5ms, 0 errors, 50/50 session attribution at 30,000 reqs in 60s).
- **kbouncer / gbounce / dbounce:** verified ceiling **30 concurrent terminals** at the SQLite store layer (p99 < 50ms, 0 errors, all session-ids correlate). HTTP-level ceiling depends on the wire-protocol parser hot-path (not re-measured in §A22 scope) — but the audit-write bottleneck that capped this at 5 writers pre-fix is fully closed.

The pre-#296 ceiling was driven by `SQLITE_BUSY` errors at ~5 concurrent writers in the Go bouncers (kbouncer + gbounce lost ~98% of audit rows; dbounce queued but with 1.4s tail latency). Root cause was missing `journal_mode=WAL` + `busy_timeout` PRAGMAs; fix is one DSN line per bouncer. ibounce was never in this state (its Python `threading.Lock` + WAL pair held throughout).

**Session-attribution** is via `X-Agent-Session-Id` (per `[[cross-product-agent-parity]]` / #316 / #318). Profile + pause state remain process-global; that's INTENTIONAL — they're operator-controlled deny floors, not per-session knobs. Concurrent terminals share the same profile/pause posture by design.

## B14. Cross-product: defense-in-depth ≠ unified product (DESIGN per `[[four-products-one-brand]]`)
~10% of decisions show TRUE multi-layer composition per UAT. The marketing claim is "complementary products under one brand," NOT "single integrated suite." This is the honest framing per `[[ibounce-honest-positioning]]`.

## B15. Cross-product: no unified deny-prompt UI in v1.0 (GAP — v1.1)
Each bouncer prompts independently. v1.1 brings unified prompt-inbox UI.

## B16. Cross-product: only gbounce reads `X-Agent-Session-Id` header in v1.0 (GAP — v1.1)
Tested 2026-05-22 against the simulation harness at `tests/integration/nanoclaw_paths/`. gbounce reads `X-Agent-Session-Id` + `X-Agent-Name` headers and populates `unmapped.iam_jit.agent.session_id` on every event (#308). ibounce / kbounce / dbounce do NOT read the header today — they derive `agent.name` from `User-Agent` (or process-tree for ibounce) and leave `agent.session_id` null. Effect: cross-bouncer correlation by `agent.session_id` works for HTTPS-via-gbounce traffic only; AWS / K8s / SQL traffic isn't yet correlatable on session_id. Workaround until v1.1: filter by `agent.name` + time window across products. The kbouncer / dbounce schemas already have the column (#289 / #266 plumbing); the missing piece is reading the header on inbound. Fix is the same shape across all three: mirror gbounce's `buildAgentBlock` from `internal/audit/event.go`. Per `[[don't-tailor-to-lighthouse]]`: the generic-header surface is already documented; closing this is product polish, not lighthouse-bespoke work.

## B17. LLM-generated profiles: non-deterministic output (DESIGN per `[[ibounce-honest-positioning]]`)
**Task #326** ships `iam-jit profile generate-from-audit` + `iam-jit profile generate`. Two design caveats baked into the output:

1. **Non-determinism.** Two runs of the same input on the same LLM may produce slightly different YAML (different patterns, different reasons strings). This is INTENTIONAL — the operator-review step is the determinism gate, not the synthesis step. We do NOT cassette / pin LLM responses across runs because that would conflict with the operator-configurable `--preferred-backend`.
2. **Wildcard inference is best-effort.** When the LLM emits a broad glob (`*-staging-*`, `arn:aws:s3:::*-prod-*`) the generator auto-adds it to `flagged_for_review` regardless of whether the LLM flagged it. The operator must confirm broad patterns explicitly before installing.
3. **Deterministic fallback is event-literal.** If the LLM is unavailable / returns junk, the fallback emits an exact-match allow for every observed resource (no wildcards inferred) — better to be too narrow than silently too broad. The `flagged_for_review` block carries the "LLM unavailable" note.

Workaround: operators who want determinism set `--preferred-backend ollama` (locally-hosted) + pin the model via `IAM_JIT_LLM_MODEL`. Hosted-API runs (Anthropic / Bedrock / OpenAI) are inherently sampling-non-deterministic; review the bundle before installing. See [docs/PROFILE-GENERATION.md](PROFILE-GENERATION.md) for the full guide.

## B18. dbounce: dynamic-deny gates connections, not statements (DESIGN — v1.1 candidate)

**Task #324f** (recommender Deny-injection from dynamic-deny rules) ships across the suite — except dbounce's dynamic-deny matcher operates at the CONNECTION level, not the per-statement level. An operator can `iam-jit deny add --target payments-db-prod.us-east-1.rds.amazonaws.com --duration 3h` to refuse connections to that DB host, but cannot author a dynamic-deny rule that says "deny SELECT against this column" or "deny INSERT into this table" — there is no statement-shaped pattern in the cross-product YAML schema (per `docs/schemas/dynamic-denies-v1.json`).

**Practical impact on the role-effectiveness corpus.** Scenarios D1 (`SELECT * FROM credit_cards` from a shared connection) and D4 (`COPY (SELECT * FROM credit_cards) TO STDOUT` from a shared connection) remain THEATER / PARTIAL respectively under the post-#324f dynamic-denies bucket. To close these scenarios today, operators use the **#326 audit-pinned profile flow** instead — narrowing the allowlist by table rather than the denylist by statement-shape. Under the #326 path D1 and D4 both grade MEANINGFUL (see `tests/dogfood/role-effectiveness-grades-post-pivot.md`).

**v1.1 candidate.** Statement-level dynamic-denies on dbounce would require:

1. A new pattern shape in `docs/schemas/dynamic-denies-v1.json` (`statement:table.column` or `statement:verb:table` — schema_version 1.0 → 1.1 bump per the cross-product schema-bump convention).
2. The dynamic-deny matcher composing with dbounce's existing AST-walk classifier (rather than running parallel-and-conflict).
3. A new MCP tool argument letting agents author per-statement denies without learning the SQL parser.

Tracked under the v1.1 roadmap, NOT a launch blocker. Logged per `[[ibounce-honest-positioning]]` so an operator evaluating dynamic-denies for dbounce knows the boundary up-front.

## B19. ibounce: `iam-jit attach` writes a port-pinned endpoint_url (#698 LOW-1)

**Symptom:** Operator runs `iam-jit attach --endpoint http://127.0.0.1:7401`
which writes `endpoint_url = http://127.0.0.1:7401` into the AWS config
profile. Operator later restarts ibounce on a DIFFERENT port (e.g. `--port 7402`
because 7401 was in use). Boto3 still hits the OLD port → connection-refused
or the call goes to nothing → silent agent-flow failure.

**Why:** `attach` writes the endpoint pinned to the port the operator passed.
There is no "detect ibounce port on the fly" path; aws-config is static.

**Fix when this bites you:**
```bash
iam-jit detach                          # removes the endpoint_url line
iam-jit attach --endpoint http://127.0.0.1:<new-port>
```

Always pair an ibounce port change with a detach/re-attach. The two CLIs
ship in the same release exactly because they're meant to be used together.

Tracked v1.1+ candidates:
- `iam-jit attach --auto-detect` — find ibounce by pid file, follow port changes.
- `ibounce serve --pidfile <path>` + `iam-jit attach --follow-pidfile` — let
  attach re-read the port from the pidfile on each AWS SDK invocation.

Neither is launch-blocking; the pair is one shell command away today.

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
