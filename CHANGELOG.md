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

- **random-policy fuzz methodology** (founder direction
  2026-05-22, `scripts/random_policy_fuzz.py` +
  `scripts/random_policy_fuzz_oracle_prompt.md` +
  `scripts/random_policy_fuzz_compare.py` +
  `docs/RANDOM-FUZZ-METHODOLOGY-2026-05-22.md`) — generator
  samples 2-5 AWS-managed policies uniformly at random (50%
  pairs / 30% triples / 15% quads / 5% pentuples), concatenates
  their `Statement` blocks (with statement-level dedupe), and
  scores each composite LOCALLY via `iam_jit.review.analyze_policy`
  — no LLM calls in any iam-jit script. Initial 100-composite
  batch at `seed=42` lands in
  `tests/calibration_corpus/random_composites/` and is content-
  hashed for cross-run dedupe. The oracle phase (Opus judgment)
  is a separate manual step using the documented prompt; the
  comparison script classifies each composite per the rubric
  (CALIBRATED / DRIFT / UNDER_FLAG / OVER_FLAG / LIKELY_BUG) +
  emits `docs/RANDOM-FUZZ-RESULTS-{date}.md`. Per
  `[[scorer-is-ground-truth]]` the scorer is NOT auto-tuned to
  match Opus; promotion of LIKELY_BUG cases to
  `bug_regressions/` is a deliberate manual step. Calibration
  loader (`tests/test_calibration_corpus.py`) explicitly skips
  the `random_composites/` subdir because composites carry a
  `scores`-style schema (not the `expected`-assertion schema).
  Regression coverage in
  `tests/scripts/test_random_policy_fuzz.py` (3 tests:
  determinism + content-hash dedupe + det_score populated on
  every composite).

### Fixed

- **ibounce hardcoded HTTPS upstream scheme** (UAT 2026-05-22
  Variant A + C, KNOWN-CAVEATS A3, task #300,
  `src/iam_jit/bouncer/proxy.py` + `src/iam_jit/bouncer_cli.py`) —
  the bouncer always forwarded over HTTPS to the inbound SigV4-
  signed Host header, so pointing it at LocalStack
  (`http://127.0.0.1:4566`) failed and UAT had to bypass ibounce
  for every write. CRITICAL launch-blocker. Adds `ibounce run
  --upstream URL` flag with new `parse_upstream_url(url)` helper
  that extracts scheme + host:port + validates scheme ∈ {http,
  https} (rejects `ftp://`, `file://`, schemeless URLs at startup
  with a clear error). New `ProxyConfig.forward_host_override`
  field threads the parsed host through both `_forward_to_aws`
  call sites; existing CRIT-32-01 outbound-host allowlist still
  gates the override target. Default behaviour unchanged when
  `--upstream` is unset (forward to signed Host over HTTPS — the
  real-AWS shape). Regression coverage in
  `tests/bouncer/test_proxy_upstream_scheme.py` (14 tests: parser
  unit + CLI-startup-rejection + end-to-end mock-LocalStack +
  no-override regression-guard). End-to-end verified against
  LocalStack 3.8 on 2026-05-22:
  `list_buckets / create_bucket / put_object / get_object` all
  200 through `ibounce --upstream http://127.0.0.1:4566 --mode
  transparent`, audit log shows `allow` verdicts on each call.

- **Solo-mode self-approve deadlock** (Variant B UAT finding #2,
  `src/iam_jit/routes/requests.py`) — `IAM_JIT_DEPLOYMENT_MODE=solo`
  enabled the self-approve-reductions gate but the auto-approve
  override in `_apply_mfa_and_self_approve_enforcement` only fired
  on `auto_decision.reason == "above_threshold"`. Solo deployments
  default to `auto_approve_risk_below=None` so the route returned
  `feature_disabled` instead — the override never had a chance and
  the admin's own reduction landed in `pending`, where the
  four-eyes check in `lifecycle.py` refused approver==owner. Net
  effect: every solo founder ran into a deadlock on their first
  request. Fix extends override-eligible reasons to include
  `feature_disabled`. Strict-mode, toggle, blocklist, and quota
  denials remain non-overrideable (platform floors). Per the
  [[self-approve-reductions]] memo the skip is APPROVAL, not
  AUDIT — the `request.auto_approved` audit event still emits
  with actor `self_approve_reduction:<user.id>`, and the
  `original_reason` field on the override now carries through the
  pre-override reason (`feature_disabled` or `above_threshold`)
  for the audit trail. Adds 4 route-level regression tests in
  `tests/test_routes_requests.py` and 4 helper-level tests in
  `tests/test_mfa_self_approve_enforcement.py` covering the
  override-eligible vs floor-protected reasons.

### Docs

- **LLM-backend reframe in `docs/DEPLOYMENT.md`** — Step 5 now
  presents the four supported LLM backends (Bedrock / Anthropic
  API / OpenAI API / Ollama) as equal first-class choices with a
  per-backend cost-per-1k-scores table, instead of recommending
  Bedrock as the default. Notes that Bedrock requires a one-time
  per-account model-access approval (with variable lead time) and
  that the other three backends have no AWS-side approval gate.
  Bedrock-specific sections (AWS Budget alarm, model-access
  prerequisite, pilot parameter set) now carry "Bedrock-only"
  banners pointing operators at the equivalent path for the other
  backends. Companion polish in `docs/ENTERPRISE-SELF-BOOTSTRAP.md`
  to add OpenAI to the LLM-backend list. No code changes.

### Added

- **Pluggable LLM-backend abstraction** (`src/iam_jit/llm/`) — the
  Pro-tier LLM call is now a 4-way choice (Bedrock / Anthropic API /
  OpenAI API / Ollama) selected by `IAM_JIT_LLM_BACKEND` env or
  per-account `llm_preferred_backend`. Backs the doc claims that
  shipped in `d31d8e4`. Old single-file `src/iam_jit/llm.py` is now
  a package; every back-compat import path (`NoOpBackend`,
  `OllamaBackend`, `AnthropicBackend`, `BedrockBackend`,
  `RecordingBackend`, `CassetteMiss`, `wrap_with_cassette`, `_parse`,
  `_cassette_key`, `get_backend`, `get_backend_for_tier`,
  `LLMBackend`, `SYSTEM_PROMPT`) is preserved verbatim. New public
  surface: `score_policy()`, `default_score_backend()`,
  `get_score_backend()`, `available_backends()`, `ScoreContext`,
  `ScoreResponse`. Per-account `LLMDecision` now carries
  `preferred_backend` so the score route can route prod accounts to
  a specific provider. `pyproject.toml` adds per-backend extras
  (`[bedrock]`, `[anthropic]`, `[openai]`, `[ollama]`,
  `[all-llm-backends]`); the legacy `[llm]` extra keeps mapping to
  Anthropic for back-compat. New ops doc at `docs/LLM-BACKENDS.md`.
  Closes the doc/code gap from `d31d8e4` (Bedrock 30-60 day approval
  lead time, see `[aws-account-verification]`).

- **AWS-usage builder cron** (`scripts/aws_usage_builder.py`) — tiny
  operator-side daily job that warms an AWS account with three cheap
  no-op calls per day (`s3:PutObject` of a 1-byte file,
  `cloudwatch:PutMetricData` against namespace `iam-jit/usage-builder`,
  and `ec2:DescribeRegions`) to build usage + billing history per
  Amazon's 2026-05-19 Bedrock denial-email guidance ("Continue to
  actively use other AWS services on your account to build Usage and
  billing history"). Refuses to run without `IAM_JIT_USAGE_BUCKET` or
  configured credentials; partial failures don't abort the run; exits
  non-zero only when ALL three calls fail (cron-friendly). Logs to
  `~/.iam-jit/aws-usage-builder.log`. Cost: well under $1/month at
  one tick per day. Per `[[creates-never-mutates]]` read-only on the
  operator's machine outside the log file + the 1-byte S3 object. Per
  `[[self-host-zero-billing-dependency]]` talks only to the operator's
  own AWS account; no phone-home. Crontab template
  (`scripts/aws_usage_builder.crontab.example`) + setup README
  (`scripts/README.md`) included. 6 moto-mocked tests in
  `tests/scripts/test_aws_usage_builder.py`.

- **Per-org notification routing engine** (#280; ENTERPRISE tier) — new
  `--alert-routes ROUTES.yaml` flag on `ibounce run` activates the
  multi-destination routing engine. Each event is matched against the
  YAML's `routes:` list (per-route `match` block with `equals` /
  `gte` / `lte` / `gt` / `lt` / `in` / `match` (regex) / `glob`
  operators; AND-within / OR-across); matching routes dispatch the
  event to their declared `destinations:` (`webhook` per #257 preset,
  `pagerduty` via the Events API v2, `slack` via incoming-webhook).
  `on_match: stop` (default) short-circuits subsequent routes;
  `on_match: continue` enables fan-out (e.g. "all-events archive"
  alongside team-scoped routes). Secrets live in env vars via
  `${ENV_VAR}` interpolation; literal tokens in the YAML are refused
  at parse time. Startup banner reports each resolved secret as
  `ENV_NAME (first-8-char-prefix***)`; tokens NEVER appear in logs,
  status surfaces, or routing-error messages. New `ibounce config
  preview-routes --routes ROUTES.yaml --event sample.json` subcommand
  dry-runs a sample event against the file and prints matched routes
  + masked destinations without sending any HTTP. When `--alert-routes`
  is set, the legacy `--audit-webhook-url` flag is ignored (with a
  warning at parse time + at startup); the JSONL log + Security Lake
  adapters stay independent. Enterprise-tier feature; license gate
  fires at CLI parse AND serve() start (defense in depth). Per
  `[[creates-never-mutates]]` the engine never mutates the event it
  routes. Per `[[no-hosted-saas]]` + `[[self-host-zero-billing-
  dependency]]` every destination is operator-configured (no phone-
  home). Documented in `docs/PER-ORG-NOTIFICATION-ROUTING.md`.
- **AWS Security Lake audit-export adapter** (#258) — new
  `--security-lake-bucket BUCKET --security-lake-region REGION
  [--security-lake-role-arn ARN] [--security-lake-rotation-seconds N]`
  flags on `ibounce run` write OCSF v1.1.0 class 6003 events as
  parquet files into a Security-Lake-compatible S3 bucket layout
  (`region=<r>/eventday=<YYYYMMDD>/eventhour=<HH>/api_activity-
  <unix-ms>.parquet`). Per-class in-memory batching with rotation on
  the configured interval (default 300s) OR a 10 MiB size cap,
  whichever fires first; `stop()` flushes pending batches
  synchronously. Credentials via STS AssumeRole when
  `--security-lake-role-arn` is set, otherwise the default boto3
  credential chain; refuses to start with a clear error if no
  credentials are reachable. New `pip install iam-jit[security-lake]`
  extra brings pyarrow in only when needed. Per
  `[[cross-product-agent-parity]]` kbouncer + dbounce ship the
  matching adapter (Go) with byte-identical column set + partition
  layout. Per `[[no-hosted-saas]]` + `[[self-host-zero-billing-
  dependency]]` the bucket lives in the operator's AWS account; no
  iam-jit-the-company traffic. Per `[[creates-never-mutates]]` every
  S3 operation is `PutObject` only. Documented in
  `docs/SECURITY-LAKE-INTEGRATION.md`.
- **Per-session recording + cross-product replay CLI** (#285) — new
  `--record-sessions-dir PATH` flag on `ibounce run` tees every
  audit event into a per-session NDJSON file at
  `{dir}/{agent.session_id}.ndjson`. Each file carries a `_meta`
  header (recording_schema_version, session_id, agent_name,
  bouncer_product, recording_started_at) followed by one OCSF event
  per line; `.partial` suffix while in-flight, atomically renamed on
  clean shutdown or heartbeat-timeout finalisation. File mode 0o600.
  New `ibounce session` subcommand group (`list / show / export /
  purge`) inspects recordings; new cross-product `iam-jit session
  replay <FILE>` CLI walks any product's recording with optional
  `--realtime` timing preservation, `--filter EXPR` (same grammar
  as #268), `--max-events N`, and `--what-if-profile NAME` that
  re-evaluates each event against an alternate profile and reports
  the diff. Documented in `docs/SESSION-REPLAY.md`. Per
  `[[cross-product-agent-parity]]` kbouncer / dbounce / gbounce
  ship the matching recorder + subcommands with the same on-disk
  shape. Per `[[creates-never-mutates]]` the recorder is additive
  (tees existing events); per `[[self-host-zero-billing-dependency]]`
  entirely local filesystem.
- **`ibounce run --preset security-observe`** (#254) — single-flag
  shortcut for the canonical security-team observation deployment
  shape. Equivalent to `--mode transparent --default-policy allow
  --audit-log-path ~/.iam-jit/audit/ibounce.jsonl --alert-rules
  defaults --heartbeat-interval 30`. Designed for the
  "gather data first; author profile second" starting position per
  `[[bouncer-mode-selection-for-agents]]` + the cross-product
  `docs/SECURITY-TEAM-AUDIT-EXPORT.md` memo. HARD override on
  `--mode` (the entire point of the preset is transparent);
  passing `--preset security-observe --mode cooperative` errors
  fast with a clear "drop the preset OR drop the explicit flag"
  message. SOFT overrides on the audit-log-path / alert-rules /
  heartbeat-interval / default-policy (operators have different
  SIEM destinations + tunings). Startup banner names the preset +
  every derived setting (with hard/soft annotation). Same preset
  name + same override semantics ships across `kbounce` /
  `dbounce` / `gbounce` per `[[cross-product-agent-parity]]`.
  Framework docs at `docs/DEPLOYMENT-PRESETS.md`; the post-v1.0
  roadmap (`dev-loop`, `production-strict`, `compliance-audit`)
  is documented but explicitly NOT shipped in this slice per
  `[[deliberate-feature-completion]]`.
- **Cross-product JSON Schema registry** (#276) — published JSON
  Schemas for the four cross-product audit / artifact wire shapes
  every Bounce product emits identically: OCSF v1.1.0 class 6003
  audit event (`schemas/ocsf-iam-jit-audit-event.schema.json`),
  admin-action event (`schemas/admin-action-event.schema.json`),
  diagnostics bundle manifest (`schemas/diagnostics-manifest.schema.json`),
  backup metadata table (`schemas/backup-metadata.schema.json`).
  Each schema validates against a representative sample in
  `schemas/testdata/` (CI guard); a triage tool consuming a bundle
  from any Bounce product can validate identically. New cross-product
  schema index at `schemas/INDEX.md` lists every per-product config
  schema + the cross-product common subset (`schema_version` +
  `product` + `exported_at` + `source_hostname_hash`). Per
  `[[cross-product-agent-parity]]`.
- **`GET /schemas/config` HTTP endpoint** (#276) — ibounce's mgmt
  port serves the embedded `ibounce-config.schema.json` byte-for-byte
  at `Content-Type: application/schema+json`. An agent that wants to
  validate a proposed `ibounce config import` payload against the
  LIVE bouncer's accepted shape fetches this rather than relying on
  a stale GitHub URL. Read-only; no auth (matches `/healthz`). Per
  `[[cross-product-agent-parity]]`: kbounce + dbounce + gbounce ship
  the same endpoint shape with their own product schema.
- **`ibounce audit-webhook presets list`** (#259) — operator-facing
  CLI subcommand that prints the four webhook preset shapes the
  binary speaks (`generic`, `datadog`, `splunk-hec`, `sentinel`) +
  each preset's required + optional flags + auth header + body
  shape. `--json` flag emits the structured descriptor list for
  agent consumption. Mirrors the new `list_audit_webhook_presets`
  MCP tool. Per `[[audit-webhook-presets]]` + `[[cross-product-agent-parity]]`.
- **`list_audit_webhook_presets` MCP tool** (#259) — agent-facing
  surface that returns the same descriptor list `ibounce audit-webhook
  presets list --json` emits. Read-only; safe for agents to poll;
  identical JSON shape across `ibounce` / `kbounce` / `dbounce` so
  cross-product orchestration code can call the matching tool on each
  bouncer and collate the results uniformly.
- **`docs/WEBHOOK-PRESETS.md`** (#259) — cross-product reference for
  the webhook preset framework: what each preset shape is, when to
  use which, per-vendor token-acquisition steps (Splunk HEC token,
  Datadog API key, Sentinel shared key), per-preset wire shape
  (header set + body shape + HMAC signing for Sentinel), cross-links
  to the #283 marketplace assets (Splunk app + Datadog content pack).
  Sentinel grep test in `tests/test_webhook_presets_doc.py` keeps the
  doc in sync with the preset registry.
- **`iam-jit audit stream` cross-bouncer live TUI** (#272) — k9s-
  style terminal UI that subscribes to every reachable Bounce-suite
  bouncer's `/audit/events` endpoint and renders one merged, sorted,
  colourised table that updates live. Title-bar carries total + per-
  bouncer counts (with `(skip)` next to unreachable bouncers, matching
  `iam-jit audit query`). Keyboard shortcuts: `/` filter (forwarded
  server-side), `p` pause/resume, `t` toggle per-bouncer column,
  `c` clear, `q` quit. Row colours follow SIEM convention (red=deny,
  green=allow, blue=admin, grey=heartbeat). Built on `rich.live`
  rather than `textual` so iam-roles takes no new direct dependency
  (rich ships transitively via click). Per `[[creates-never-mutates]]`
  the TUI is read-only — no keystroke mutates bouncer state. New
  module `iam_jit/cli_audit_stream.py`; new doc
  `docs/AUDIT-STREAM-TUI.md`.
- **ibounce live web UI at `GET /`** (#272 A) — minimal vanilla-JS
  page on ibounce's mgmt port (8767) alongside `/healthz` and
  `/audit/events`. Single self-contained HTML+CSS+JS file (no build
  step, no CDN, no Google Fonts, no analytics), under 500 lines.
  Long-polls `/audit/events?since=<cursor>` every two seconds and
  renders a colour-coded table with top-bar event counters, filter
  input (same syntax as `/audit/events?filter=`), pause + clear
  controls, mobile-responsive layout. Same auth model as the
  endpoint: loopback no auth; external bind takes the bearer token
  through the URL `#token=...` fragment so the HTML body never
  embeds the secret. Per `[[creates-never-mutates]]` the UI is
  read-only; strict CSP headers; cross-product-identical HTML
  shape with kbounce / dbounce / gbounce. New module
  `iam_jit/bouncer/audit_export/events_ui.py`; new doc section in
  `docs/QUERYING-AUDIT-LOGS.md`.
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

### Fixed

- **#272 regression — audit-stream UI shadowed root-path AWS
  operations on the proxy port.** The `GET /` route registered for the
  live audit UI was unconditionally matching every request to `/`,
  which silently swallowed S3 ListBuckets (the most common root-path
  AWS API call) plus unclassifiable proxy traffic and presigned-URL
  redirects. The UI now defers to the proxy handler whenever the
  request does not advertise `Accept: text/html`, so browser visits
  still land on the UI while SDK + curl + agent traffic flows through
  the normal verdict path. Resolves 5 pre-existing test failures
  surfaced across multiple ship-reports
  (`test_proxy_plan_capture.py::test_plan_capture_never_forwards_to_backend`
  + four `test_proxy_slice2.py` cases). Files touched:
  `src/iam_jit/bouncer/audit_export/events_ui.py`,
  `src/iam_jit/bouncer/proxy.py`.
- **`test_parse_duration_rejects_garbage` stale expectation** — the
  test predated #285's addition of the `d` (days) suffix for
  session-recording retention; it asserted `30d` should raise
  `BadParameter`. Updated to assert the suffix set the parser
  actually accepts today (`s/m/h/d`) and switched the
  unsupported-suffix probe to `30y`. Files touched:
  `tests/bouncer/test_pause_for.py`.

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
