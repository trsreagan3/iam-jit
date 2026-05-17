# Feature reality-check (2026-05-16)

This is a measurement pass after the natural-language policy synthesis
feature was found to score 1.8% on its joint-sufficiency metric. The
question: which other features ship code but don't actually deliver
their claimed value end-to-end?

Method per feature: read implementation, find tests, classify test
flavor (unit / TestClient-integration / real-external-system), check
docs for evidence of manual validation, look at git history.

## Executive summary

16 features investigated.

- ✅ DELIVERS: 4 (self-approve reductions, MFA Phase 1 propagation,
  iam-jit init-solo, local-only mode)
- ⚠️ PARTIAL: 8 (Slack bot, OIDC SSO, device flow, AWS-managed
  baseline matching, scoring feedback, GitHub Action presets, SARIF,
  MFA Phase 3 nudge)
- ❌ DOESN'T DELIVER: 2 (Plan-capture proxy, OAuth proxy for
  mid-session MFA)
- 🤷 UNVALIDATABLE-FROM-CODE: 2 (landing page liveness, pluggable
  LLM beyond shipped backends)

**Headline concerns for the founder:**

1. **Three "MFA / SSO / Slack" surfaces have never run against a real
   external system.** They're stub-tested only. The Slack `doctor`
   command and OIDC `doctor` command exist as manual-validation
   crutches but there's no record of either having been run against
   a real workspace / IdP. Pilots will be the first contact with the
   real systems. Plan a half-day buffer for each.

2. **Plan-capture is reader-only.** The module's own docstring says
   "Producers will land later (see task #118)." There is no proxy
   that intercepts `terraform plan` / CDK / AWS SDK calls today.
   The schema is durable and tests are clean, but nothing PRODUCES
   captures. If any external doc or pitch implies "we intercept
   your IaC" — that's a gap.

3. **The natural-language baseline fallback (the thing the
   1.8%-sufficiency loop blamed) is wired in the MCP path and
   currently lives behind two functions (`match_baseline` /
   `best_baseline`) you are about to delete per task #149.** The
   browse/catalog half is fine. The fuzzy-match half is the
   1.8%-causing piece. Confirm the deletion plan covers BOTH call
   sites (`mcp_server.py:341-342`).

## Slack approval bot — ⚠️ PARTIAL

**Claim (per task #93/#97/#98 + memory):** "post grant requests,
support approve/deny, MFA step-up nudge" against a real Slack
workspace.

**Evidence:**
- Implementation is 900 LOC at `src/iam_jit/slack_bot.py` — signature
  verification, Block Kit rendering, `chat.postMessage`, `chat.update`,
  workspace + channel pin defenses (WB8-03, WB8-04), mrkdwn injection
  escape (WB8-01), MFA step-up nudge DM.
- Three test files: `tests/test_slack_bot.py` (42 unit tests),
  `tests/test_routes_slack.py` (15 FastAPI route tests using
  TestClient), `tests/test_slack_mock.py` (11 tests against
  in-process `MockSlackServer`).
- `iam-jit doctor slack` exists at `src/iam_jit/cli.py:871` and runs
  `auth.test`, `chat.postMessage`, scope probes against a real
  workspace.
- Runbook at `docs/recipes/SLACK-APP-SETUP.md` (199 lines) — has
  step-by-step instructions including "smoke test by submitting a
  real request as described in Step 6."

**Gap:** Every automated test exercises `slack_bot.py` against a
mock (in-process FastAPI `MockSlackServer` OR injected stub
`SlackHTTPClient`). The unit-test header in `test_slack_bot.py` line
20 explicitly says "These are unit tests with no live Slack call."
No artifact in `docs/` (runbook, audit log, post-mortem) records a
single `doctor slack` run against a real workspace. The mock is good
— Slack's API contract is well-documented and stable — but you
won't discover scope-mismatch / mrkdwn-rendering / OAuth-permission
quirks until you point at a real workspace.

**Recommendation:** Before the first pilot, install the app in
iam-jit's own workspace, run `iam-jit doctor slack`, fire one
real `post_approval_message` + one click, then one real
`post_mfa_step_up_nudge`. Reserve half a day. Add a section to the
audit log noting "validated against real workspace
<workspace_name>, <date>" so it's grep-able later.

## OIDC SSO Google + Okta — ⚠️ PARTIAL

**Claim (task #94):** "users authenticate via Google or Okta SSO."

**Evidence:**
- 884 LOC at `src/iam_jit/oidc.py` — full authz-code flow, JWKS
  cache w/ rotation, ID-token validation (sig, iss, aud, exp, nonce,
  email_verified, Google `hd`, Okta groups, amr).
- 630-LOC test file at `tests/test_oidc.py` — explicitly notes "NO
  live network calls. All tests use stub HTTP clients +
  locally-generated keys via cryptography library."
- 163-LOC integration test at `tests/test_routes_oidc.py` uses a
  `stub_discovery` fixture that fakes Google + Okta discovery
  endpoints. Real Google JWKS / token endpoint never touched.
- `iam-jit doctor oidc` exists at `cli.py:1064` and does reach
  real discovery + JWKS endpoints if env vars are configured.

**Gap:** Same shape as Slack — the protocol is correctly
implemented per RFC vectors; the integration tests use
TestClient + stubbed discovery; nothing in the repo shows a real
Google or Okta sign-in has ever completed end-to-end. Most likely
points of failure on first real attempt: redirect-URI exact-match
mismatches, Google `hd` enforcement against personal accounts,
Okta non-standard discovery paths (the dataclass has a
`discovery_url` override for exactly this — but it's never been
exercised against a real Okta tenant).

**Recommendation:** Before any pilot that uses SSO, register a
test Google OAuth client, set the env vars, run
`iam-jit doctor oidc`, then complete one full sign-in. ~30 min.

## MFA Phase 2 — Device Authorization Grant (RFC 8628) — ⚠️ PARTIAL

**Claim (task #142):** "agents auth via device code flow against
Google/Okta."

**Evidence:**
- Implementation at `oidc.py:447-552` (`start_device_flow`,
  `poll_device_flow`) — protocol-compliant per RFC 8628.
- 211-LOC test file `tests/test_oidc_device_flow.py` uses a
  `_StubClient` that programs canned responses. The header
  explicitly notes "These tests stub the HTTPClient so we exercise
  the protocol shape without depending on real Google/Okta
  credentials."

**Gap:** Has never been pointed at a real
`device_authorization_endpoint`. Google publishes one
(`https://oauth2.googleapis.com/device/code`); Okta's varies by
tenant. The code reads `endpoints.device_authorization_endpoint`
from `discover()` — if a provider doesn't publish it, `ConfigError`
fires. Untested edge: what if a provider publishes it but doesn't
honor the `client_secret` field in the poll body? (Google does, but
the RFC says public clients shouldn't send one.) Untested edge:
human-readable user-code rendering (`ABCD-EFGH`) in actual agent
output.

**Recommendation:** Before claiming "agents can auth via device
flow" in any pilot or launch post, run one end-to-end real flow.
Budget 30 min. Same story as Slack + OIDC: the unit tests are
clean, but they only prove the protocol *shape* is right.

## MFA Phase 3 — OAuth proxy for step-up re-auth — ❌ DOESN'T DELIVER (as claimed)

**Claim (task #143):** "agents prompt user for fresh MFA
mid-session."

**Evidence:**
- What's BUILT: `post_mfa_step_up_nudge` at
  `slack_bot.py:676-778`. Sends the human a Slack DM with a
  one-click "Re-authenticate" link to `/api/v1/auth/oidc/login`.
  The HUMAN re-auths via OIDC; the agent then resubmits.
- The implementation docstring is honest: "Trade-off vs full OAuth
  proxy: this version requires the human to actively
  re-authenticate. The fully-proxied alternative (#143 follow-up)
  would let iam-jit-hosted handle the dance directly."
- No code anywhere implements an OAuth proxy that programmatically
  prompts a user for fresh MFA mid-session.

**Gap:** This isn't a "tests aren't real" gap; it's a "feature
isn't built" gap. The shipped piece is a NUDGE (Slack DM) that
requires manual human re-auth via the existing browser OIDC flow.
The fully-proxied piece — where iam-jit-hosted brokers a fresh MFA
challenge directly to the user out-of-band — does not exist.

**Recommendation:** Re-label this in any external doc as "MFA
step-up nudge" not "OAuth proxy for mid-session MFA re-auth."
Update task #143 to reflect that the nudge variant shipped and the
proxy variant is a follow-up. If marketing copy claims the proxy
behavior, fix it.

## Plan-capture proxy for IaC — ❌ DOESN'T DELIVER

**Claim (task #118):** "intercepts terraform/cdk SDK calls,
captures planned operations."

**Evidence:**
- `src/iam_jit/plan_capture.py` is **277 LOC of READER code only**.
  The module's own docstring on line 5: "Producers will land later
  (see task #118); the reader is the durable contract iam-jit uses
  to consume captures regardless of who produced them."
- No directory matching `proxy*`, `intercept*`, or `capture*` in
  `src/`. The only `.py` files matching `*capture*` are
  `src/iam_jit/plan_capture.py` and `tests/test_plan_capture.py`.
- The reader is well-tested (parse_line, gzip handling, size caps
  per WB11-10) and is downstream consumer-ready.

**Gap:** The CONSUMER half is ready. The PRODUCER half — the actual
proxy / shim / wrapper that records terraform/CDK/boto3 calls into
the JSONL format — does not exist in this repository. Anyone who
sees task #118 listed as "done" and reads it as "plan capture
ships" will be surprised when they go to use it.

**Recommendation:** Re-scope #118 to "plan-capture FORMAT + reader
shipped; producers are post-launch." Don't pitch plan-capture as a
working feature in launch comms. If/when you build a producer, the
schema is already pinned (`iam-jit.dev/plan-capture/v1alpha1`).

## AWS-managed baseline matching — ⚠️ PARTIAL (acknowledged)

**Claim (task #147):** "match requests to closest AWS-managed
policy as starting point."

**Evidence:**
- 536-LOC catalog at `src/iam_jit/aws_managed_catalog.py`. The
  CATALOG (browse, entries, schemas) is solid — 237-LOC of unit
  tests in `tests/test_aws_managed_catalog.py` covers it.
- The MATCH functions (`match_baseline:472`, `best_baseline:514`)
  use a token-based fuzzy match.
- This match function is the **direct cause** of the 1.8% joint
  rate per `docs/calibration/100-prompt-sufficiency-loop.md`: 28
  of 111 prompts get no policy because the fuzzy match doesn't
  fire on common synonyms ("inherited account", "lay of the
  land", "walk me through").
- Currently called from `mcp_server.py:341-342`.

**Gap:** Already known. Memo says this is about to be deleted per
task #149.

**Recommendation:** When you delete `match_baseline` /
`best_baseline`, update both call sites in `mcp_server.py` and
the doc that claims #147 shipped. The catalog itself (browse-only)
remains a useful piece — keep it.

## Scoring feedback channel — ⚠️ PARTIAL

**Claim (task #81 + memory):** "users flag bad scores, feeds
calibration corpus."

**Evidence:**
- 295-LOC store at `src/iam_jit/scoring_feedback.py` with rate
  limiting (authed 10/day, anon 3/day, deployment 100/hour).
- Routes wired at `src/iam_jit/routes/feedback.py`: POST
  `/api/v1/feedback/scoring`, GET admin list, PATCH admin mark
  reviewed.
- 200-LOC test file with 10 tests, including TestClient-based
  rate-limiting and admin-flow tests.
- The docstring promises: "Admin marks 'valid + add to corpus' →
  exports a YAML fixture under `tests/calibration_corpus/community/`."
- **There is no `tests/calibration_corpus/community/` directory.**
  The promised export path is unimplemented.
- Storage backend: `InMemoryFeedbackStore` only — no
  DynamoDB / persistent variant. On a Lambda restart in hosted
  mode, **all queued feedback is lost.**

**Gap:** Submission + admin-review endpoints work in tests, but the
critical loop-closer (export to YAML fixture + corpus reload) is
not built, and the storage is non-persistent. Without persistence,
a hosted deployment cannot actually retain feedback between cold
starts. Without the export-to-corpus path, there is no path from
"customer flagged a score" to "calibration corpus contains the
example."

**Recommendation:** Either (a) finish the loop — add a DDB store
and an "export to YAML" admin action — or (b) descope the feature
in launch comms to "we capture feedback in-memory; the
calibration-corpus integration is post-launch." Don't claim
end-to-end "feedback → corpus → calibration" until both halves
exist.

## Self-approve reductions — ✅ DELIVERS

**Claim (task #107):** "admins/solo-devs auto-approve their OWN
narrower grants."

**Evidence:**
- 177-LOC clean module at `src/iam_jit/self_approve_reductions.py`.
- Wired into the lifecycle from three call sites in
  `routes/requests.py` (lines 128, 529, 788).
- WB12-02 closure (owner field mismatch) and WB13-08 closure
  (ordering + MFA gate bypass) are visibly addressed in the code
  (the `owner` resolution at line 126 explicitly checks BOTH
  `status.owner` AND `metadata.owner` with the closure
  documented).
- Three test files exercise the path:
  `tests/test_self_approve_reductions.py` (helper unit tests),
  `tests/test_mfa_self_approve_enforcement.py`, and
  `tests/test_mfa_enforcement_e2e.py` (the latter goes through
  the real submit_request → mfa_gate → self_approve flow via
  TestClient — see WB12-14 closure note at line 5).
- `local_server.py:17` shows "self_approve_reductions=true by
  default" wired in local solo mode.

**Gap:** None at the code/test level. The audit-level CRITs caught
in rounds 12 and 13 are visibly closed and the e2e test file
exists specifically to prevent regression of the same shape.

**Recommendation:** Ship it.

## GitHub Action presets — ⚠️ PARTIAL

**Claim (task #75):** "strict/standard/permissive preset that
customers drop into .github/workflows."

**Evidence:**
- `github-action/action.yml` has the `preset:` input with three
  documented values, default `standard`.
- `github-action/README.md` documents usage.
- Action is implemented as a composite action.
- `docs/launch-posts/GITHUB-ACTION-MARKETPLACE-CHECKLIST.md` exists
  but is a CHECKLIST — items like "Submit for Marketplace review at
  github.com/marketplace/new" are unchecked.
- `docs/LAUNCH-READINESS-2026-05-16.md` line 137-140: "GitHub Action
  marketplace submission — Option B (separate repo) recommended …
  submission needs your one-time click."

**Gap:** The action exists, the presets exist, the README exists.
The action has NOT been submitted to the Marketplace, has not been
installed in any external repo, and there's no evidence it has run
in a real PR. Used by anyone? Unknown — no telemetry, no record.

**Recommendation:** Submit to Marketplace (one click per the
checklist), install in this repo's own `.github/workflows/` as a
self-test, and only then claim "GitHub Action shipped."

## SARIF output — ⚠️ PARTIAL

**Claim (task #76):** "scorer emits SARIF for GitHub code scanning UI."

**Evidence:**
- Implementation in `src/iam_jit/cli_score.py` (`_format_sarif`).
- Tests in `tests/test_cli_score_sarif.py` (4 tests) — assert
  top-level shape: `version=="2.1.0"`, `$schema.startswith("https://")`,
  `runs` array structure, severity levels mapped from score tiers.
- NO test validates against the actual OASIS SARIF 2.1.0 JSON
  schema (no `jsonschema` library import in the test file). The
  tests check that fields the code writes are present, not that
  every required SARIF field is present and well-formed per the
  spec.

**Gap:** "Valid-looking JSON" ≠ "renders correctly in GitHub Code
Scanning UI." The SARIF spec is large; field shape errors that
pass the in-repo tests can still cause GitHub to refuse the upload
or render incorrectly (e.g., missing `tool.driver.rules[]`,
malformed `physicalLocation`). The CHANGELOG claim is "High-leverage
CI integration substrate." The only way to validate that claim is to
upload one SARIF artifact through `actions/upload-sarif@v3` and
view the result.

**Recommendation:** Wire the GitHub Action into this repo's own
`.github/workflows/`, set `sarif-output: iam.sarif`, add a
`actions/upload-sarif@v3` step, push a PR with a deliberately bad
IAM policy, confirm the result renders in the GitHub Code Scanning
tab. ~1 hour. Until that's done, downgrade the public claim to
"emits SARIF 2.1.0 (shape-validated; render-in-GitHub validation
pending)."

## iam-jit init-solo — ✅ DELIVERS

**Claim (task #108):** "one command bootstraps a working local
install."

**Evidence:**
- `iam-jit init-solo` registered at `cli.py:564`.
- Reuses `local_server._seed_local_user`,
  `_seed_local_accounts`, `_ensure_local_cli_token`,
  `_set_local_env_defaults` — all unit tested in
  `test_local_server.py` (16 tests covering directory creation,
  YAML preservation, file permissions, idempotency, STS fallback,
  CLI token rotation behavior).
- Dedicated `tests/test_cli_init_solo.py` (4 tests via
  `CliRunner`) verifies: data dir + users.yaml + accounts.yaml +
  cli-token are produced; MCP snippets are printed; idempotent;
  `--print-mcp-config` skips bootstrap correctly.
- WB11-12 closure (`_safe_identity_token`) hardens the user-input
  path against YAML injection from `$USER`.
- WB11-04 closure: bearer token is NOT echoed to stdout, only
  referenced by file path.

**Gap:** The tests exercise the file creation, idempotency, and
output. The actual "produces a working system" claim — i.e. "and
then `iam-jit serve --local` starts and Claude Code connects
through MCP" — is covered by separate tests (see below). No
documented manual-run record, but the assertions are tight enough
that a regression would be caught.

**Recommendation:** Ship it.

## Local-only mode (iam-jit serve --local) — ✅ DELIVERS

**Claim (task #117):** "runs entirely on dev laptop, no SaaS dep,
MCP exposed on localhost."

**Evidence:**
- `src/iam_jit/local_server.py` (468 LOC) implements the full
  local-mode startup: seeded data dir, in-memory stores, uvicorn
  serve on `127.0.0.1:8765`.
- The actual server start path at line 466-467 uses
  `uvicorn.run(app, ...)` with the real FastAPI `app` from
  `create_app()` — so the request-handling stack is identical to
  hosted mode.
- 497-LOC test file `test_local_server.py` covers the seed path,
  permissions (0600 on token file), idempotency, AWS-STS-failure
  fallback.
- `test_users_agent_path.py`, `test_mcp_server.py`,
  `test_mcp_read_only_default.py` exercise the MCP endpoints that
  are exposed in local mode.
- `docs/UX-FEEDBACK-LOCAL-MODE-2026-05-16-DEEP.md` and
  `docs/UX-FEEDBACK-LOCAL-MODE-2026-05-16.md` exist — evidence
  of actual hands-on UX runs.

**Gap:** The detailed UX-feedback docs are the closest thing to
external manual validation — they discuss real first-run
observations, not theoretical concerns.

**Recommendation:** Ship it. The UX-feedback docs suggest this is
the most-validated feature in the launch set.

## "Don't give Claude your AWS keys" landing page — 🤷 UNVALIDATABLE-FROM-CODE

**Claim (task #109 + memory):** landing page shipped.

**Evidence:**
- Source at `landing-site/src/pages/iam-jit.astro` (305+ LOC, full
  Astro page with H1 "Don't give Claude your AWS keys.").
- Built output exists at `landing-site/dist/iam-jit/index.html`.
- `LAUNCH-READINESS-2026-05-16.md:149` declares "iam-jit.com
  landing page ✅ shipped."

**Gap:** The page builds. Whether it's actually deployed at
`iam-jit.com` and renders for outside visitors requires an HTTP
fetch I shouldn't make from this audit (and the memory note
indicates iam-jit.com vs iam-risk-score.com is the
two-product-split design that may or may not be live).

**Recommendation:** Verify `curl -I https://iam-jit.com/` returns
200 and the content matches `landing-site/dist/iam-jit/index.html`.
1 minute.

## Pluggable LLM backend — 🤷 UNVALIDATABLE-FROM-CODE / honest

**Claim (memory):** NOT BUILT — defer until 3+ enterprise asks.

**Evidence:**
- `src/iam_jit/llm.py` line 1 docstring: "Pluggable LLM backends for
  the suggest pipeline." The framework EXISTS: `LLMBackend` Protocol
  + `NoOpBackend`, `OllamaBackend`, `AnthropicBackend`,
  `BedrockBackend` (also `RecordingBackend` for test cassettes).
- These four are the same backends the per-account-LLM-policy memo
  expects. No OpenAI / Cohere / vLLM / Groq / generic-HTTP-provider
  backends.
- Docs do not claim broader "bring-your-own-LLM" support.
  `DEPLOYMENT.md` and `AGENT-DEPLOYMENT-PROMPT.md` enumerate exactly
  these four options.

**Gap:** None visible. The memory's "defer until 3+ enterprise
asks" is consistent with what's shipped + documented. The
framework architecture would make adding a 5th backend a small
change, but no false claim is being made.

**Recommendation:** No action. Just confirm no external pitch
claims more than ollama/anthropic/bedrock/none.

## MFA propagation through bearer tokens (Phase 1) — ✅ DELIVERS

**Claim (task #141):** "tokens carry MFA-at-issuance, enforcement
gate checks it."

**Evidence:**
- `api_tokens_store.py:34` stores `mfa_at_issuance: int | None`
  on the API token record; lines 110-124 round-trip it via
  DynamoDB.
- `routes/tokens.py:106-123` sets it at issuance time from the
  caller's session MFA cookie.
- `mfa_gate.py:194-220` checks
  `api_token_record.mfa_at_issuance` against the freshness window
  before allowing high-risk grants.
- `tests/test_mfa_enforcement_e2e.py` (227 LOC, 5 tests) goes
  through the FULL submit_request route via FastAPI TestClient
  with minted MFA cookies. WB12-14 closure explicitly created this
  file because helper-only tests didn't catch WB12-01 + WB12-02.
- WB13-08 closure also visible: self-approve no longer bypasses
  the MFA gate.

**Gap:** None at the code/test level. The repeated audit-round
cleanup (round 12 + round 13 both found regressions of the same
shape) shows the test discipline is working — each CRIT had a
proper e2e regression test added after closure.

**Recommendation:** Ship it.

## OAuth proxy for mid-session MFA re-auth (#143 follow-up) — ❌ DOESN'T DELIVER

Same finding as Section "MFA Phase 3" above — the OAuth proxy
piece is documented as a "(#143 follow-up)" in the code, and no
OAuth-proxy implementation exists. What ships is the Slack DM nudge.

**Recommendation:** Same as above — don't claim the proxy variant
exists.

## Cross-cutting findings

- **The "doctor" command pattern is the right escape valve for
  un-real-system-tested features.** `iam-jit doctor slack` and
  `iam-jit doctor oidc` exist precisely so the founder can run
  one command and learn whether the real external system agrees
  with the unit-test stubs. The pattern should extend: add
  `iam-jit doctor device-flow` and `iam-jit doctor mfa-nudge` for
  the next pilot.

- **There is a recurring pattern of "Producer ships, Reader
  doesn't" or vice versa.** plan_capture has a reader without a
  producer. scoring_feedback has a submission endpoint without a
  corpus-export consumer. AWS-managed catalog has browse without
  reliable match. In each case the half that ships does so as a
  clean, well-tested module — but the loop-closer is missing.
  Before launch, audit the "loop" claim of every feature and
  confirm both halves exist.

- **Audit-discipline (BB + WB rounds) is paying off.** Self-approve
  reductions, MFA Phase 1, and the e2e MFA enforcement tests all
  came out of round 12 + round 13 audit CRIT closures. The bugs
  in those features were caught by audits AFTER they passed unit
  tests. Continue this pattern. The 1.8% sufficiency finding —
  which was a calibration-loop finding, not an audit finding — is
  the same shape: "the test suite said it works; running it for
  real said otherwise." Pre-launch, queue an integration-pass
  round that points each external-system feature at a real
  external system before pilot kickoff.

- **Code lines do not match value lines.** 900 LOC of Slack bot,
  884 LOC of OIDC, 277 LOC of plan_capture all "ship" — but the
  delivered value per claim is uneven. For launch comms, sort
  features by validation flavor (real-system-tested >
  TestClient-integration-tested > unit-only > shape-only) and
  pitch only the top tier as "shipped."
