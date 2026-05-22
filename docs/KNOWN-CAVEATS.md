# Known caveats + limitations (cross-product)

**Read this BEFORE you install** — knowing the boundaries up-front saves hours of "why isn't this working?" debugging. Every claim in the README has a footnote in here.

This doc is mirrored across all 5 product repos (iam-jit, ibounce, kbounce, dbounce, gbounce) — same content, same path. Last updated 2026-05-22 after UAT findings.

## Categorization

Each caveat is one of:
- **BUG** — will be fixed; track via the linked task. Workaround documented until fix lands.
- **DESIGN** — intentional limit per architectural choice (e.g., `[[ibounce-honest-positioning]]`); not going away.
- **GAP** — known incomplete; on the roadmap; documented version expectations.

---

## ibounce (AWS IAM gating proxy)

### BUG: hardcoded HTTPS upstream scheme (UAT 2026-05-22)
**Symptom:** Pointing ibounce at a plain-HTTP upstream (e.g., LocalStack at `http://127.0.0.1:4566`) fails with connection errors. The proxy code internally uses `https://` regardless of the upstream URL scheme.

**Severity:** CRITICAL — blocks local development, blocks LocalStack-based testing.

**Workaround:** point at an HTTPS upstream OR patch `src/iam_jit/bouncer/proxy.py` to honor the scheme of `--upstream`.

**Fix tracking:** queued — see task list. Target v1.0.1.

### DESIGN: SigV4-only request classification
**Symptom:** Plain GET requests to ibounce return `403 "unclassifiable request — no SigV4 auth header"`.

**Why:** ibounce gates AWS SDK calls. AWS SDKs always sign requests with SigV4. A bare GET isn't an AWS SDK call.

**For browsers viewing the UI:** ibounce uses the `Accept` header to discriminate. Browsers (sending `Accept: text/html`) get the live audit UI. SDKs (sending JSON Accept) hit the proxy path.

### DESIGN: ibounce gates AWS calls only
**Symptom:** Your kubectl / psql / curl calls work normally — ibounce doesn't see them.

**Why:** ibounce is the AWS-specific bouncer. K8s → kbounce. DB → dbounce. HTTP → gbounce.

### GAP: ibounce safe-default = `readonly-admin-minus`
**Behavior:** First-time-run profile is "all reads allowed except sensitive-data reads; all writes prompt." This is intentionally permissive on reads + strict on writes per `[[safe-default-is-readonly-admin-minus]]`.

**If you want stricter (block all reads from sensitive prefixes):** use `--profile strict-admin` instead.

### GAP: ibounce safe-default catches are VERB-level, not CONTENT-aware (UAT 2026-05-22)
**Symptom:** The "catches" of hostile attempts (e.g., `iam:CreateRole` with wildcard policy) come from the same uniform "writes denied unless allowlisted" rule that also denies legitimate writes (PutPublicAccessBlock, PutBucketVersioning, CreateLogGroup, NetworkPolicy create, etc.). The denies are CORRECT outcomes but cosmetic — the bouncer can't tell a scoped `iam:CreateRole` from an `iam:*` wildcard one.

**Why this matters:** without sync-deny-prompt enabled, every legitimate write is a hard fail with no escape valve. With sync-deny-prompt enabled, you'll prompt-storm on legitimate work.

**For meaningful content-aware risk decisions:** add iam-jit to the path (Variant C — `iam-jit + ibounce`). iam-jit's policy-content risk scoring gives the scope-aware decision; ibounce gives the atomic gate. Per `[[four-products-one-brand]]`: they're complementary, not redundant.

**Fix tracking:** queued. The right architectural answer is "ibounce calls into iam-jit's scorer for content-aware decisions" — design slice for v1.1.

---

## kbounce (Kubernetes API gating proxy)

### BUG: kubectl OpenAPI discovery classified as "unclassifiable" (UAT 2026-05-22)
**Symptom:** Every `kubectl` invocation fails. The first thing kubectl does is hit `/openapi/v3/<group>` for API discovery. kbounce's parser treats these as unclassifiable URL shapes → applies default-deny under safe-default profile.

**Severity:** CRITICAL — makes the product unusable with kubectl on safe-default.

**Workaround:** use `--profile full-user` until fix lands, OR explicitly allowlist `/openapi/v3/*` paths in your custom profile.

**Fix tracking:** queued. Target v1.0.1. The fix is parser-side: classify `GET /openapi/*` as `verb=read, resource=meta:openapi-schema` and let safe-default ALLOW it.

### BUG: stale binary in repo (UAT 2026-05-22)
**Symptom:** Features documented in CHANGELOG might be missing from your binary if you cloned the repo + ran the pre-built bin/kbounce instead of `go build`.

**Severity:** HIGH — affects everyone who picks up the repo + uses the pre-built binary.

**Workaround:** always run `go build -o bin/kbounce ./cmd/kbounce` before first use, OR run `go install github.com/trsreagan3/kbouncer/cmd/kbounce@latest`.

**Fix tracking:** queued — the bin/ checked-in binary will be removed from the repo; only `go install` will be supported. Target v1.0.

### DESIGN: kbounce doesn't see container-internal calls
**Symptom:** Calls made INSIDE a pod (e.g., container-to-container service-mesh traffic) don't appear in kbounce.

**Why:** kbounce sits between `kubectl` (or `client-go`) and the kube-apiserver. Pod-to-pod traffic doesn't go through that path. Per `[[no-k8s-proxy-for-iam-jit]]`.

---

## dbounce (SQL gating proxy)

### BUG: SCRAM-SHA-256 handshake hangs (UAT 2026-05-22)
**Symptom:** Connecting any modern Postgres client (psql 14+, libpq 14+, etc.) through dbounce hangs forever during initial auth. dbounce forwards the SCRAM bytes upstream but the auth-OK / ReadyForQuery responses don't propagate back to the client.

**Severity:** CRITICAL — modern PG 14+ defaults to SCRAM-SHA-256. This breaks every default Postgres install.

**Workaround:** edit upstream Postgres `pg_hba.conf` to use `trust` or `md5` auth for the IP range dbounce connects from. Restart Postgres. Then dbounce works.

**Fix tracking:** queued — dbounce's upstream forwarder needs to handle SCRAM message framing. Target v1.0.1.

### BUG: GRANT / REVOKE / other DCL classified as "unknown" → default-allow (UAT 2026-05-22)
**Symptom:** `GRANT ALL PRIVILEGES ... TO PUBLIC` is allowed by safe-default profile even though it's clearly dangerous. dbounce's parser doesn't classify DCL operations.

**Severity:** HIGH — a hostile attack (H3 in the UAT) succeeded against dbounce safe-default because of this.

**Workaround:** in your dbounce profile, explicitly add `deny grants_to_public: true` rule (custom rule today; will be built-in after fix).

**Fix tracking:** queued. Target v1.0.1.

### BUG: stale binary in repo (UAT 2026-05-22)
Same as kbounce — always rebuild via `go build` or `go install`.

### DESIGN: dbounce gates per-statement, not per-result
**Symptom:** A SELECT that returns 1M rows is one DECISION event, not 1M.

**Why:** Per-result gating would be insanely expensive + provide no value. The risk decision is on the QUERY, not the data.

### DESIGN: literal-redaction is heuristic
**Symptom:** Some literals in WHERE clauses get redacted in audit logs (replaced with `?`); others don't. Specifically: numeric literals are NEVER redacted (per `[[dbounce-sql-redaction-gaps]]` memo).

**Why:** Identifying which numbers are PII (credit card numbers, SSNs) vs which are configuration (port numbers, retention days) requires schema knowledge dbounce doesn't have.

**If you store PII as numeric columns:** use `--redact-numerics` (post-v1.0 flag).

---

## gbounce (generic HTTP/HTTPS forward proxy)

### DESIGN: `--allow-connect` only sees host:port, NOT request URL/body
**Symptom:** HTTPS calls through gbounce show `CONNECT api.example.com:443` in the audit log. Not `GET /v1/users/123`. Not the request body. Not the response.

**Why:** gbounce in CONNECT mode tunnels TLS. It can't read encrypted bytes. This is intentional per `[[ibounce-honest-positioning]]` — no MITM means more privacy + more deployability.

**If you need URL-level visibility:** use `--upstream` rewrite mode (HTTP only) OR enable MITM mode in v1.1 (planned).

### BUG: unreachable-host CONNECTs not logged (UAT 2026-05-22)
**Symptom:** If gbounce can't reach the upstream (host doesn't exist, network blocked), no audit event is logged. SSRF probes against private IPs (e.g., `169.254.169.254`) are invisible.

**Severity:** HIGH — defeats one of the canonical attack-detection use cases.

**Workaround:** until fix lands, monitor gbounce's stdout log file (set `--log-path`) for connection errors.

**Fix tracking:** queued. Target v1.0.1.

### BUG: non-CONNECT requests rejected without audit logging (UAT 2026-05-22)
**Symptom:** Plain HTTP forward requests (NOT CONNECT) hit gbounce → returns 421 "only CONNECT accepted" → no audit event logged. Affects every protocol that's HTTP-but-not-HTTPS routed through gbounce.

**Severity:** HIGH — contradicts the "discovery-only" + "complete visibility" claims simultaneously. IMDS attacks (HTTP, not HTTPS) become invisible.

**Workaround:** until fix lands, document that gbounce v1.0 is HTTPS-CONNECT-only; use a separate HTTP proxy for plain-HTTP visibility.

**Fix tracking:** queued — gbounce should support `--upstream` rewrite mode (HTTP) per its existing flag, AND audit-log rejections rather than silently dropping them. Target v1.0.1.

### GAP: G-Slice 1 = discovery mode only
**Behavior:** gbounce currently OBSERVES + LOGS, but doesn't BLOCK. Profile-mode gating + auto-recommender are G-Slice 2-3, post-launch.

**If you need active blocking on HTTPS today:** use ibounce (AWS-specific blocking) + your firewall.

---

## iam-jit (AWS IAM risk scorer + JIT grant issuer)

### BUG: solo mode self-approval deadlock (UAT 2026-05-22 — in-flight fix #297)
**Symptom:** Run iam-jit locally on your laptop. Submit a request. It goes to `human-review-required`. You ARE the only human. Four-eyes check refuses `approver==owner`. Deadlock.

**Severity:** **CRITICAL — first experience every solo security engineer hits.**

**Workaround:** set `IAM_JIT_AUTO_APPROVE_REDUCTIONS=true` in env (post-fix).

**Fix tracking:** in flight as task #297 (will land in next 24h).

### CALIBRATION: score-9 collision on IAM operations (UAT 2026-05-22)
**Symptom:** A scoped `iam:CreateRole` for a narrow scoped policy scores 9. A wildcard `iam:* on *` also scores 9. Numerically identical despite very different risk.

**Why:** the IAM-category scoring rule fires at risk-9 anytime broad IAM verbs are present, without distinguishing scope-narrow from scope-wide policies.

**Severity:** MEDIUM — affects threshold-based auto-approval routing. The score-bands per `docs/SCORING-BANDS.md` still apply correctly; this is about WITHIN the band-9 zone there's lost resolution.

**Fix tracking:** queued for calibration sweep. The `factors` list distinguishes them; the numeric score doesn't.

### DESIGN: iam-jit is AWS-only
**Symptom:** iam-jit doesn't gate K8s, DB, or HTTP operations. You can do whatever on those protocols.

**Why:** iam-jit is the AWS IAM risk scorer + JIT grant issuer. The Bounce suite handles the other protocols.

### DESIGN: deterministic scorer is the ground truth
**Symptom:** Even when iam-jit Pro tier overrides the deterministic score (UP) with LLM analysis, the deterministic FLOOR is never lowered.

**Why:** Per `[[scorer-is-ground-truth]]`. The safety contract is the floor.

---

## Cross-product

### GAP: 1-3 concurrent terminals supported in v1.0 (per UAT findings + the active-mcp-session.json race)
**Symptom:** Running 10+ Claude Code terminals through one shared bouncer instance produces unpredictable session-attribution and prompt-routing.

**Severity:** HIGH at scale; not relevant for solo use.

**Fix tracking:** v1.0 ships with 1-3 terminal support. v1.1 raises the bar to 20 terminals (task #296). 100+ deferred to v1.2.

### GAP: defense-in-depth (iam-jit + bouncers) ≠ unified product (UAT 2026-05-22)
**Behavior:** When you run iam-jit + bouncers together, you get more catches than either alone, but only ~10% of decisions show TRUE multi-layer composition. Most catches come from just one layer.

**Implication:** the marketing claim should be "complementary products under one brand" (per `[[four-products-one-brand]]`), NOT "single integrated suite."

### GAP: no unified deny-prompt UI
**Behavior:** Each bouncer surfaces its own deny-prompts independently. When 4 bouncers all prompt simultaneously, the operator sees 4 separate prompt streams.

**Fix tracking:** v1.1 — unified prompt-inbox UI (per `[[per-org-notification-routing]]` shape).

---

## How these caveats are surfaced (discoverability layers)

This document is the canonical reference. Caveats are ALSO surfaced at:

1. **README "Known Limitations" section** — top 3 caveats per product, with link to this doc
2. **CLI startup banner** — when a bouncer detects a known-caveat-triggering config, prints a warning
3. **`*bounce doctor` command** — runs known-issue checks + prints any that apply
4. **`*bounce diagnostics bundle`** — includes a snapshot of this doc + your version's specific caveats
5. **Error messages** — when a known caveat triggers, error message links to the relevant section here
6. **MCP tool descriptions** — agents see "this tool has known limitation X" embedded in tool descriptions

If you hit something that ISN'T in this doc, please file an issue at:
- iam-jit: https://github.com/trsreagan3/iam-jit/issues
- kbouncer: https://github.com/trsreagan3/kbouncer/issues
- dbounce: https://github.com/trsreagan3/dbounce/issues
- gbounce: https://github.com/trsreagan3/gbounce/issues

A caveat you discover + we miss documenting = a documentation gap. Both you and we want this list comprehensive.
