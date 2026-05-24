# MRR-1 — Use-case audit (2026-05-24)

Phase 1 of the Mission Readiness Review (`[[mrr-flight-readiness-program]]`)
before the founder's work-machine deploy. Audited starting against
`iam-roles` HEAD `5a5665f`; the concurrent iam-risk-score hosted-cleanup
agent `a0bb55f208c227466` landed as `f30001b` mid-audit (drops hosted
Lambda + REST scoring endpoint; restores `[[no-hosted-saas]]`). Audit
findings below were verified against both states; UC-2 (Pro-tier LLM-
augmented scoring) wording reflects the post-cleanup local-only scoring
shape.

Method per `[[ibounce-honest-positioning]]`: be honest, not generous.
"Individually works" is not "shipped." Composition gaps are surfaced even
when the underlying pieces have unit-test coverage. Per
`[[calibration-quality-bar]]` features whose value depends on judgment
quality (improve_profile, deny_classifier, profile_generator) must have
their own calibration corpus or the marketing claim is unsupported.

## 1. Executive summary

Audited 41 use cases. The deterministic-floor architecture is in
strong shape: 2,367-yaml calibration corpus on the scorer, 8,000+
unit tests, multiple integration tests against LocalStack + the cross-
bouncer wire. The COMPOSITION + MEASUREMENT story is much weaker
than the per-feature story, which is the exact pattern the founder
flagged.

| Severity | Count | Headline |
|---|---|---|
| **CRIT (blocks-deploy)** | **5** | (1) audit→profile-→install-→iterate never E2E-tested; (2) iam_jit_setup_from_config never E2E-tested via real MCP agent; (3) dbounce H3 (GRANT ALL bypass) known and unfixed; (4) iam_jit_request_role_from_synthesis composition only mock-tested (#475/476/477 same shape); (5) `iam-jit init` interview NOT SHIPPED (#489) yet referenced in MRR-6 plan |
| **HIGH (blocks-promote)** | **12** | improve_profile/deny_classifier/profile_generator have NO independent measurement corpus; cross-bouncer fan-out (dynamic deny) test mocks the wire; multi-account+multi-region scope filtering not E2E'd; threat-feed publisher trust chain not exercised against real malicious feed; Pro-tier LLM-augmented scoring has no calibration; anomaly detection (Phase H) ibounce-only, no cross-product UAT; pause/bulk-prompt + session recording have unit-only coverage; org-managed --managed mode pending (#490); diagnostics bundle never tested with a real failure |
| **MED (defer-to-post-deploy)** | **18** | helm-charts install untested locally; air-gapped path documented but not smoke-verified post-launch; gbounce MITM mode is BETA per [[mitm-beta-pii-pci-concern]] — known caveat; live_action_tail rarely exercised; Pro-tier UI guided reduction (PARTIAL); enterprise self-bootstrap (rarely run); etc. |
| **DEPLOY-READY** | **6** | Discovery-mode observation; profile install YAML; audit chain retention (Phase F); `iam-jit posture` (with caveats); `iam-jit audit query`; iam-risk-score scorer + free-tier CLI |

### Top 5 most-blocking gaps

1. **Use case 17 — "audit → agent generates profile → install → enforce → iterate" composition has NEVER been exercised end-to-end.** The pieces exist (`bounce_profile_generate_from_audit` #326, `bounce profile install`, audit-tail). The integration test mocks the bouncer HTTP layer and only verifies the bundle is well-formed. No test runs the WHOLE loop against actual bouncer binaries observing actual traffic. Dogfood variant-A documented "every legitimate write was denied — uninstall on day 1 territory" — that IS the symptom of this composition gap.
2. **Use case 20 — `iam_jit_setup_from_config` never E2E-tested via real MCP agent.** `tests/ambient_config/test_mcp_tool.py` exists but stubs the MCP transport. The "one declaration → bouncers install + start + configure" promise is the load-bearing pitch of `[[ambient-autonomous-protection]]`. If the agent's MCP call fails partway through install, the operator's state is unknown — and there's no documented rollback (MRR-4 territory).
3. **Use case 3 — synthesis flow `iam_jit_request_role_from_synthesis` (#421) has ONLY mock-tested composition.** `tests/request_from_synthesis/test_request_from_synthesis.py` is 886 LOC of unit tests. Bugs #475 / #476 / #477 (catalogued in `docs/CONTRIBUTING.md`) are the EXACT shape — `status:auto_approved` with `credentials: null`, `audit_event_ids` returned but events were write-only — that the state-verification convention was created to prevent. No automated test runs the synthesis flow → real role-creation → real STS:AssumeRole → real audit-event readback.
4. **Use case 34 — dbounce H3 (`GRANT ALL PRIVILEGES ON DATABASE postgres TO PUBLIC` classified as `operation: UNKNOWN`, allowed through default-policy=allow).** Documented in `docs/dogfood/role-effectiveness-grades-FINAL-2026-05-23.md` + `dbounce-sql-redaction-gaps`. The scenario spec named this as the expected catch and it was MISSED in 2 of 3 variants. dbounce ships v1.0 with a KNOWN classifier gap on `GrantStmt`. If founder's work AWS account hosts ANY RDS Postgres, this is a deploy-blocker.
5. **Use case 30 — `iam-jit init` interview NOT SHIPPED (#489).** The MRR-6 operator runbook + the bootstrap UX in `iam-jit-overview` both reference `iam-jit init` as the onboarding entry point. Today operators must `iam-jit init-solo` (different shape) + hand-author `.iam-jit.yaml` + run `iam-jit doctor apply-config`. The composed-experience the docs sell does not exist as a single command. Founder will hit this on day 1.

### Recommended MRR-2..7 sequencing (post-MRR-1)

* **MRR-2 (error-path audit)** first — the cryptic-error symptom is the same root cause as the composition gaps (state-claimed-without-verification). Run MRR-2 on the 5 CRIT surfaces first; the patterns will inform MRR-3 fixtures.
* **MRR-3 (UAT framework)** in parallel with MRR-4 — UAT scenarios for the 5 CRIT use cases double as MRR-4 abort/rollback fixtures.
* **MRR-5 + MRR-6** can run in parallel after MRR-2; MRR-6 explicitly needs MRR-2 + MRR-4 outputs.
* **MRR-7** is the bar for the 5 CRITs to be reviewed by an agent that did NOT implement the fixes.
* **MRR-8** is founder signoff per the original plan.

If any of the 5 CRITs prove harder to fix than estimated, the right move is to NARROW the deploy scope (e.g. dbounce off until H3 fixed; setup-from-config gated behind operator approval) NOT to ship under-tested.

## 2. Per-category audit

### Category A — iam-jit role-issuance (7 use cases)

#### UC-1 Agent submits role request → score → create → assume (`[[create-not-assume-pattern]]`)

* **Pieces**: `mcp_server.py:submit_policy` (line 573), `review.analyze_policy()` (4233 LOC), `provision.py` (1083 LOC), `assume.py`, `auto_approve.py` (364 LOC).
* **Tests**: ✅ unit (`test_review.py`, `test_auto_approve.py`, `test_provision.py`); ✅ state-verification (`test_e2e_lifecycle.py`, `test_provision_lifecycle_full.py`); ✅ integration with LocalStack (`tests/integration/test_localstack_iam.py`); ✅ calibration corpus (2,367 yamls).
* **Composition status**: **VERIFIED-E2E**. The lifecycle tests submit → score → auto-approve → provision against LocalStack IAM → assume → expire. Dual-persona E2E test exists. `tests/e2e/test_dual_persona_flow.py` drives via Playwright.
* **Measurement**: ✅ 2,367-yaml corpus + 1,489/1,489 AWS-managed + 217 attack patterns.
* **Severity**: DEPLOY-READY.

#### UC-2 Pro-tier LLM-augmented scoring (agent-mediated)

* **Pieces**: `review.py:_narrate_with_llm` + `_suggest_with_llm` (commentary AROUND the scorer); `bounce_profile_generate` MCP tool surface (agent does LLM with own LLM).
* **Tests**: ✅ unit (`test_llm_backend.py`, `test_account_policy_preferred_backend.py`); ✅ integration with Ollama (`tests/integration/test_ollama_contract.py`, `test_review_with_llm.py`).
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. The LLM-narration path is exercised in tests; the AGENT-MEDIATED path (per `[[bouncer-zero-llm-when-agent-in-loop]]`) has no integration test that simulates "agent calls MCP, agent decides on augmented evidence, agent calls back with create_role."
* **Measurement**: ❌ **MISSING** — no calibration corpus measures whether the LLM-augmented score is more / less / equally accurate than deterministic alone. Per `[[calibration-quality-bar]]` this is HIGH.
* **Severity**: HIGH. Pro-tier marketing claim "LLM judgment improves scoring" is unsupported by measurement.

#### UC-3 Synthesis flow: bouncer audit → role via `iam_jit_request_role_from_synthesis` (#421)

* **Pieces**: `request_from_synthesis.py` + Phase E modules (`audit_extract/`, `resource_map/`).
* **Tests**: ✅ unit (886 LOC `test_request_from_synthesis.py`); ✅ harness recipe test (`test_harness_recipes_phase_e.py` 80 LOC).
* **Composition**: **COMPOSITION-NEVER-TESTED**. Bugs #475/476/477 were the exact shape — status claimed without state. The convention now exists but no E2E test runs the full audit→synthesis→role-creation→STS-assume→audit-readback loop.
* **Measurement**: ❌ no measure of "did the synthesised permission set narrow vs admin baseline" — this is the entire value claim.
* **Severity**: **CRIT** (#3 in top blockers).

#### UC-4 Self-approve reductions (#297)

* **Pieces**: `self_approve_reductions.py` (177 LOC).
* **Tests**: ✅ `test_self_approve_reductions.py`, `test_mfa_self_approve_enforcement.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. The reduction-path is unit-tested + the MFA gate is enforced. But the dogfood variants documented "Self-approve blocked" — implying the FLOW (operator runs in safety mode, attempts reduction, gets denied for non-obvious reason) isn't smoke-tested with the canonical workflow recipe.
* **Severity**: HIGH. The error message in the variant-C UAT was "Self-approve blocked" with no actionable next-step.

#### UC-5 Auto-approve below threshold / human review above

* **Pieces**: `auto_approve.py` (364 LOC); approval routes; Slack notification.
* **Tests**: ✅ `test_auto_approve.py`, `test_auto_approve_safety_mode.py`, route tests.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. Auto-approve path is well-tested. Human-review queue → Slack approve-click → STS-credential-back is route-tested with TestClient + mock Slack; per `docs/calibration/feature-reality-check.md` this has NEVER been validated against a real Slack workspace.
* **Severity**: HIGH if founder's work-machine deploy will exercise Slack approval; MED if local-only approval-UI is the only path.

#### UC-6 Multi-account/region/cluster role scoping (`[[multi-account-region-cluster-use-case]]`)

* **Pieces**: `deployment_targets/` (3 modules + tests); `cli_deployment_targets.py`; `bounce_deployment_targets_for_filter` MCP tool.
* **Tests**: ✅ `tests/deployment_targets/test_cli.py`, `test_mcp.py`, `test_registry.py`.
* **Composition**: **COMPOSITION-NEVER-TESTED**. Multi-account scope filtering is unit-tested at the registry layer; no test runs "agent observes traffic in prod-east + prod-west + prod-eu → synthesises filter → requests role scoped to that intersection." The founder's own use case spans multi-account+region+cluster (per the memory).
* **Severity**: HIGH. Founder uses this shape; missing E2E means he is the first to exercise it.

#### UC-7 Enterprise bootstrap proposer (`enterprise/proposal.py`)

* **Pieces**: `enterprise/proposal.py`, `enterprise/cli.py`, `enterprise/discovery.py`.
* **Tests**: ✅ unit-tested.
* **Composition**: **NOT-SHIPPED for v1.0 deploy scope** — Enterprise tier per `[[enterprise-self-host-only]]` is rarely-run + post-launch.
* **Severity**: MED. Defer.

### Category B — Bouncer cross-product (10 use cases)

#### UC-8 Discovery mode observation (`[[discovery-first-default]]`)

* **Pieces**: All 4 bouncers default to discovery; `bouncer/proxy.py` pass-through + audit.
* **Tests**: ✅ `tests/bouncer/test_default_mode.py`, `test_ibounce_run_smoke.py`, audit-export tests (20+ files).
* **Composition**: **VERIFIED-E2E**. Dogfood variant-A ran discovery → observed → audit log written. Canary is live.
* **Severity**: DEPLOY-READY.

#### UC-9 Profile install YAML

* **Pieces**: `bouncer/profiles.py`, `bouncer/profile_doctor.py`, `bouncer/config_io.py`; cross-product `bounce profile install`.
* **Tests**: ✅ `test_profile_install.py`, `test_profile_install_ssrf.py`, `test_profile_doctor_321.py`, `test_profiles_slice7.py`, `tests/integration/profile_upgrade_doctor_test.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. SSRF + #326 generator→parser convergence are tested. Cross-bouncer install (4 bouncers, one bundle) is integration-tested with mocked HTTP.
* **Severity**: MED — known regression shape (#326 = generator emit / parser couldn't consume) is now state-verified; risk is medium not high.

#### UC-10 Profile-allow flow (#345 + cross-product #386/#387/#388)

* **Pieces**: `profile_allow/` (3 modules: denies, fanout, operations).
* **Tests**: ✅ `tests/cli/test_profile_allow.py`, `tests/bouncer/test_profile_allow_rules.py`.
* **Composition**: **COMPOSITION-NEVER-TESTED**. Cross-bouncer fan-out (one allow → applied to ibounce + kbouncer + dbounce + gbounce) is referenced in the docs but the test only mocks the per-bouncer HTTP layer.
* **Severity**: HIGH.

#### UC-11 Dynamic-deny rules + cross-protocol fan-out (#324)

* **Pieces**: `dynamic_denies/`; `recommender/`.
* **Tests**: ✅ `tests/integration/dynamic_deny_cross_product_test.py` (509 LOC).
* **Composition**: **VERIFIED-INTEGRATION** (with mocked transport). Real cross-bouncer-process fan-out is not run.
* **Severity**: HIGH. The fan-out is documented as a v1.0 differentiator; not exercising it against real bouncer processes is the calibration-drift shape.

#### UC-12 Threat-feed subscription + Ed25519 verify (#407)

* **Pieces**: `threat_feed/` (8 modules: fetcher / signing / applier / publisher / subscription / models / cli_publisher / __init__).
* **Tests**: ✅ 8 test files including `test_smoke.py`, `test_signing.py`, `test_publisher.py`, `test_autopilot_integration.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. Tests use file:// + test-controlled keys. No test exercises "publisher signs → operator subscribes → applier fetches → trust chain verified → rule actually denies." Trust-chain validation is unit-tested but no test verifies a maliciously-modified feed gets rejected.
* **Severity**: HIGH. Per `[[signed-audit-receipts-v11]]` the Ed25519 chain is THE security claim; needs a hostile-feed test.

#### UC-13 Anomaly detection (Phase H — ibounce only)

* **Pieces**: `anomaly_detection/` (6 modules); `mitre_atlas.py` mapping.
* **Tests**: ✅ `tests/anomaly_detection/test_*.py` (4 files); `tests/bouncer/test_proxy_anomaly_wiring.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. The 14-day baseline + z-score logic is unit-tested. No test runs "agent operates for 14 days, baseline matures, novel action triggers alert, operator sees it" — implausible to run in CI but should have a fixture-driven simulation.
* **Severity**: MED for v1.0 (opt-in feature, ibounce-only; kbouncer/dbounce/gbounce Phase-H parity defers to v1.0+1 #508).

#### UC-14 Audit chain + retention tiering (Phase F)

* **Pieces**: `bouncer/audit_export/` (20+ files); `log_retention.py`; `bouncer/audit_export/disk_pressure.py`.
* **Tests**: ✅ 23 test files; `test_disk_pressure_circuit_breaker.py`; `test_audit_export_chain.py`; cross-bouncer wire-parity (`tests/integration/audit_events_wire_parity_test.py`).
* **Composition**: **VERIFIED-INTEGRATION**. Disk-pressure circuit breaker tested; chain integrity tested; OCSF mapping tested. Vendor-shape verification tested (Datadog/Splunk/Sentinel/Security Lake — per `[[vendor-integration-claim-qualifier]]` wire-shape only, NOT live-tenant tested).
* **Severity**: DEPLOY-READY (with the vendor-integration caveat marketing-side).

#### UC-15 Pause + bulk-prompt-answer (#201, #253)

* **Pieces**: `bouncer/proxy.py:pause`, `mcp_server.py:bouncer_prompts_bulk_answer`.
* **Tests**: ✅ `test_pause_for.py`, `test_bulk_prompt_ux.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. No test runs "operator pauses bouncer → 5 prompts queue → agent calls bulk_answer → all answered atomically → bouncer resumes."
* **Severity**: HIGH if the founder will use bulk-answer flow; MED otherwise.

#### UC-16 Session recording + playback (#285)

* **Pieces**: `bouncer/store.py`; `cli_session_replay.py`; `live_action_tail.py`.
* **Tests**: ✅ `test_session_recorder.py`, `test_cli_session_replay.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**.
* **Severity**: MED.

#### UC-17 Audit → agent generates profile → install → enforce → iterate

* **Pieces**: `bounce_profile_generate_from_audit` MCP tool; `iam-jit profile generate-from-audit` CLI; `bounce profile install`; cross-product audit query.
* **Tests**: ✅ `tests/integration/profile_generate_cli_integration_test.py` (422 LOC — but MOCKS the bouncer HTTP layer); `tests/llm/test_profile_generator_from_audit.py`.
* **Composition**: **COMPOSITION-NEVER-TESTED**. NO test runs the WHOLE loop against actual bouncer binaries: bouncer A observes traffic → agent calls generate-from-audit → bouncer B has the profile installed → bouncer B's enforcement matches what bouncer A observed.
* **Severity**: **CRIT** (#1 in top blockers). This is the canonical "killer UX" in `docs/PROFILE-GENERATION.md`; if the composition fails on first dogfood, founder will hit it on day 1. Dogfood variant-A "every legitimate write denied" IS this composition gap.

### Category C — Agent-mediated zero-LLM flows (5 use cases)

Per `[[bouncer-zero-llm-when-agent-in-loop]]` + the LLM-call-site-audit (#509) refactor — these are the agent-delegate paths.

#### UC-18 `iam_jit_classify_deny` (agent classifies on bouncer's behalf)

* **Pieces**: `mcp_server.py:iam_jit_classify_deny` (line 2359); `deny_classifier/classifier.py` (561 LOC); `structured_deny/response.py` (956 LOC).
* **Tests**: ✅ `tests/deny_classifier/test_classifier.py`; `tests/structured_deny/test_response.py`; `tests/bouncer/test_proxy_deny_path_agent_delegated.py` (497 LOC); `tests/bouncer/test_proxy_structured_deny_wire.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. Agent-delegate REFACTOR (Phase 2 of #509) is in flight (`aef074b08183d0f53` per the LLM audit memo). The synchronous LLM call has been replaced with structured deny event + MCP tool; but no test exercises "real agent calls MCP, classifies, calls back."
* **Measurement**: ⚠️ `src/iam_jit/deny_classifier/calibration/corpus.json` exists but has only ~3 example legit cases visible. Needs expansion before deploy if marketing claim is "classifier improves over time."
* **Severity**: HIGH (calibration gap) + MED (refactor in flight; verify completion before deploy).

#### UC-19 `iam_jit_improve_profile` (agent suggests improvements)

* **Pieces**: `mcp_server.py:iam_jit_improve_profile` (line 2225); `improve/pipeline.py` (1099 LOC); `cli_improve.py`.
* **Tests**: ✅ `tests/improve/test_pipeline.py`, `test_improve_pipeline_side_llm_gate.py`.
* **Composition**: **COMPOSITION-NEVER-TESTED**. No test exercises "agent calls improve_profile, gets rule suggestions, calls bounce_deny_add or bounce_profile_save to apply, then verifies bouncer's behavior changed." Bug #448 (status=auto_installed with zero rules persisted) is this exact shape.
* **Measurement**: ❌ **MISSING** — no corpus measures suggestion quality. Per `[[calibration-quality-bar]]` HIGH.
* **Severity**: HIGH (cross-cutting per Section 7 #1).

#### UC-20 `iam_jit_setup_from_config` (agent installs per declaration)

* **Pieces**: `mcp_server.py:iam_jit_setup_from_config` (line 2141); `ambient_config/setup.py` (984 LOC); `cli_apply_config.py`.
* **Tests**: ✅ `tests/ambient_config/test_*.py` (6 files: cli, loader, mcp_tool, schema, setup, uat_phase_a_fixes).
* **Composition**: **COMPOSITION-NEVER-TESTED** end-to-end against real MCP agent. The MCP-tool test stubs the transport; install paths are unit-tested per bouncer.
* **Severity**: **CRIT** (#2 in top blockers). This is the load-bearing pitch of ambient-autonomous-protection.

#### UC-21 `iam_jit_handle_deny` (agent next-action)

* **Pieces**: `mcp_server.py:iam_jit_handle_deny` (line 2307).
* **Tests**: ✅ unit (in `test_mcp_tools.py` or harness-recipe tests).
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**.
* **Severity**: MED.

#### UC-22 NL → profile YAML (`bounce_profile_generate`, agent-side)

* **Pieces**: `mcp_server.py:bounce_profile_generate` (line 1864); `llm/profile_generator.py` (1732 LOC); `cli_profile_generate.py`.
* **Tests**: ✅ `tests/llm/test_profile_generator_from_context.py`, `test_profile_generator_side_llm_gate.py`, `test_profile_save_and_install.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**.
* **Measurement**: ❌ **MISSING** per the same `[[calibration-quality-bar]]` rule that flagged #149 (the 1.8% NL-policy synthesis number). Profile-generation quality has the same shape — needs corpus before marketing the feature.
* **Severity**: HIGH (calibration gap).

### Category D — Cross-bouncer composition (3 use cases)

#### UC-23 Cross-bouncer audit query (`iam-jit audit tail` / `iam-jit audit query`)

* **Pieces**: `cli_audit_query.py`; `cli_audit_stream.py`; cross-bouncer wire-parity tests.
* **Tests**: ✅ `test_cli_audit_query.py`, `test_cli_audit_stream.py`, `test_cli_audit_query_long_range.py`; `tests/integration/audit_events_wire_parity_test.py`, `cross_bouncer_session_id_parity_test.py`.
* **Composition**: **VERIFIED-INTEGRATION**.
* **Severity**: DEPLOY-READY.

#### UC-24 Unified `iam-jit posture`

* **Pieces**: `posture/` (6 modules); `cli_posture.py`; `iam_jit_posture` MCP tool (line 2106) + per-bouncer aliases.
* **Tests**: ✅ `tests/test_posture.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. No cross-product orchestration test (all 4 bouncers reachable → unified report has correct fields per bouncer); the 4-mode matrix in `docs/POSTURE.md` is documented but not exhaustively tested.
* **Severity**: MED. This IS the founder's "am I protected?" surface — should at minimum smoke-test the 4-mode matrix as a fixture.

#### UC-25 Cross-bouncer fan-out for dynamic-deny

Same as UC-11. HIGH.

### Category E — Operator workflows (10 use cases)

#### UC-26 Fresh install → observe → use (canary live)

* **Pieces**: `cli_canary.py`; `scripts/deploy-canary.sh`.
* **Tests**: ✅ `test_cli_canary.py`, `test_cli_canary_watch.py`, `test_cli_canary_daemon_args.py`.
* **Composition**: **VERIFIED-E2E** on author's macOS; **VERIFIED-INDIVIDUAL-ONLY** on Linux. `LINUX-SUPPORT-AUDIT-2026-05-24.md` exists (Phase 1 findings); the `lsof` fix in HEAD is the most recent Linux fix.
* **Severity**: DEPLOY-READY for macOS; MED for Linux (the founder's work-machine OS should be verified).

#### UC-27 Investigate a deny (query audit + ask agent)

* **Pieces**: `bouncer/investigate.py`; `bouncer/decisions.py`; `iam_jit_handle_deny` MCP tool.
* **Tests**: ✅ `test_investigate.py`, `test_decisions.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**.
* **Severity**: MED.

#### UC-28 Switch posture: discovery → enforce → ambient

* **Pieces**: `bouncer_cli.py`; `cli_posture.py`; ambient_config setup.
* **Tests**: ✅ per-mode tests exist.
* **Composition**: **COMPOSITION-NEVER-TESTED**. No test runs the migration: "operator in discovery → captures audit → generates profile → switches to enforce → no false-positives → switches to ambient."
* **Severity**: HIGH. The "posture upgrade path" is the recommended journey in `docs/HARNESS-RECIPES/`.

#### UC-29 Apply org-managed config (#490 pending)

* **Pieces**: `ambient_config/`; `cli_apply_config.py` (--managed flag).
* **Status**: **NOT SHIPPED** per the matrix (Phase I, #490 pending).
* **Severity**: HIGH if founder's work account expects managed-by-org; otherwise MED.

#### UC-30 Bootstrap interview (`iam-jit init` — #489 pending)

* **Status**: **NOT SHIPPED**. Today: `iam-jit init-solo` exists (different shape per `[[init-solo-different-shape]]` understanding).
* **Severity**: **CRIT** (#5 in top blockers). MRR-6 operator runbook references this as canonical day-1 flow.

#### UC-31 Export config + import on another machine (#275)

* **Pieces**: `bouncer_cli.py:config export/import` (lines 6863+); cross-product Tier-1.
* **Tests**: ✅ `test_config_io.py`; `tests/integration/cross_bouncer_session_id_parity_test.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. Export shape consistency (`[[config-export-wire-divergence]]` finding — int vs string schema_version) needs reconciliation per the memory.
* **Severity**: MED (known reconciliation queued).

#### UC-32 Diagnostics bundle (#277)

* **Pieces**: `bouncer_cli.py:diagnostics bundle`; `bouncer/diagnostics.py`; `debug_bundles.py`.
* **Tests**: ✅ `test_diagnostics.py`, `test_debug_bundles.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. No test exercises "real failure occurs, bundle captured, support-engineer-grade ZIP exists." Need fixture that artificially fails + asserts the bundle has the right shape.
* **Severity**: HIGH if founder needs to file an issue; the bundle must be self-sufficient.

#### UC-33 Multi-cluster K8s (kbouncer)

* **Pieces**: kbouncer (separate Go repo at `/Users/reagan/repos/kbouncer/`).
* **Tests**: ✅ Go test suite per kbouncer repo. From iam-roles vantage: integration via cross-product audit-tail.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. No multi-cluster fixture test.
* **Severity**: MED.

#### UC-34 SQL gating per database (dbounce)

* **Pieces**: dbounce (separate Go repo).
* **Tests**: ✅ Go test suite.
* **Known issue**: **H3 — `GRANT ALL PRIVILEGES ON DATABASE x TO PUBLIC` classified `operation: UNKNOWN`, allowed through default-policy=allow** (per `tests/dogfood/role-effectiveness-grades-FINAL-2026-05-23.md` + `[[dbounce-sql-redaction-gaps]]`).
* **Severity**: **CRIT** (#4 in top blockers) IF founder's work account has RDS Postgres and dbounce is active. Otherwise HIGH.

#### UC-35 HTTP gating per upstream (gbounce)

* **Pieces**: gbounce (separate Go repo); MITM mode shipped BETA.
* **Tests**: ✅ 28-test MITM regression suite per `docs/KNOWN-CAVEATS.md`.
* **Known issue**: PII/PCI redaction is credential-only per `[[mitm-beta-pii-pci-concern]]` — operators with PHI/PCI workloads must configure own redaction.
* **Severity**: MED (BETA + documented caveat).

### Category F — Deployment scenarios (6 use cases)

#### UC-36 Local-dev solo macOS

DEPLOY-READY (canary live).

#### UC-37 Work-machine deploy on work company AWS account

* **Status**: This IS the MRR target. Higher blast radius vs personal dev.
* **Severity**: Implicit in every CRIT above.

#### UC-38 CI/CD standalone with `--enable-side-llm`

* **Pieces**: `autopilot/daemon.py` `--enable-side-llm` flag (B1 of LLM audit); GH Action at `/Users/reagan/repos/iam-risk-score-action/`.
* **Tests**: ✅ `tests/autopilot/test_daemon_side_llm_flag.py`; `test_improve_pipeline_side_llm_gate.py`.
* **Composition**: **VERIFIED-INDIVIDUAL-ONLY**. No CI-shaped test (GH Actions workflow + bouncer + side-LLM).
* **Severity**: MED for v1.0 deploy (CI/CD is a separate audience; founder's work-machine is local-dev shape).

#### UC-39 Docker container Linux

* **Pieces**: `Dockerfile` + `docker-compose.dev.yml`.
* **Tests**: Smoke verified per HEAD commit message `5a5665f fix(canary): Linux-portability — drop lsof dependency in _restart_bouncers`.
* **Severity**: DEPLOY-READY for container-only; MED for "Linux + canary" combination per LINUX-SUPPORT-AUDIT-2026-05-24.

#### UC-40 Helm K8s install

* **Pieces**: `/Users/reagan/repos/helm-charts/`.
* **Status**: Helm chart published but not exercised in CI on a real kind/k3s cluster.
* **Severity**: MED (not founder's deploy target).

#### UC-41 Air-gapped (no LLM, no threat-feed remote)

* **Pieces**: Multiple paths — `IAM_JIT_NO_VERSION_CHECK`, threat-feed `file://` support, `--enable-side-llm` opt-in.
* **Tests**: ✅ unit-tested per feature.
* **Composition**: **COMPOSITION-NEVER-TESTED**. No fixture runs the full air-gap path (zero outbound network).
* **Severity**: MED.

## 3. Composition gaps table

| UC | Surface | Why it's a composition gap | Severity |
|---|---|---|---|
| 3 | synthesis flow | Real bouncer → MCP → role-create → STS-assume → audit-readback never run end-to-end | CRIT |
| 17 | audit→profile→install→iterate | Whole loop with real bouncer binaries never run | CRIT |
| 20 | iam_jit_setup_from_config | Real MCP agent → install + start + configure never run | CRIT |
| 6 | multi-account/region/cluster scope | Filter-and-narrow never run against multi-AWS-account fixture | HIGH |
| 10 | profile-allow fan-out | Cross-product fan-out only mocked | HIGH |
| 11 | dynamic-deny cross-protocol | Cross-bouncer fan-out only mocked | HIGH |
| 12 | threat-feed | Hostile-feed test missing | HIGH |
| 15 | pause + bulk-answer | Full pause-queue-bulkanswer-resume never run | HIGH |
| 19 | iam_jit_improve_profile | Suggestion → apply → behavior-change loop missing | HIGH |
| 28 | discovery → enforce → ambient migration | Posture-upgrade journey not E2E | HIGH |
| 32 | diagnostics bundle | Real-failure → bundle-capture never simulated | HIGH |
| 13 | anomaly detection | 14-day baseline simulation missing | MED |
| 16 | session recording + playback | No "record real session → replay correctly" | MED |
| 24 | unified posture | 4-mode matrix not exhaustively tested | MED |
| 41 | air-gapped | Zero-egress fixture missing | MED |

## 4. Measurement gaps table

Per `[[calibration-quality-bar]]` — features whose value depends on judgment quality.

| UC | Feature | Calibration status | Severity |
|---|---|---|---|
| 2 | Pro-tier LLM-augmented scoring | ❌ no corpus measures LLM-vs-deterministic accuracy | HIGH |
| 18 | iam_jit_classify_deny | ⚠️ ~3-example corpus visible at `src/iam_jit/deny_classifier/calibration/corpus.json` | HIGH |
| 19 | iam_jit_improve_profile | ❌ no corpus measures suggestion quality | HIGH |
| 22 | bounce_profile_generate (NL) | ❌ no corpus — same shape as #149 (1.8% sufficiency) | HIGH |
| 17 | audit→profile generator | ❌ no corpus measures "did the generated profile narrow correctly" | HIGH |
| 13 | anomaly detection | ❌ no corpus measures z-score precision/recall | MED (advisory only) |
| 1 | deterministic scorer | ✅ 2,367 yamls + 1,489 AWS-managed + 217 attack patterns | DEPLOY-READY |

**Cross-cutting**: every Pro-tier LLM-augmented surface (UC-2, 18, 19, 22) ships marketing claims about quality but ships ZERO independent measurement. Per `[[calibration-quality-bar]]` this is the same shape that caught the 1.8% sufficiency feature.

## 5. Error-handling spot-flags (MRR-2 input)

Noted during the audit; flagged for the MRR-2 error-path review:

* **Variant-A UAT**: "Self-approve blocked" with no actionable next-step — error message lacks "why" + "what-to-do" per CONTRIBUTING.md rubric.
* **`request_from_synthesis.py:_max_lookback_days`**: bad env var FALLS BACK + logs warning. Good — but warning is `_logger.warning` which the operator likely never sees (silent-degradation #5 in LLM-call-site audit).
* **dbounce H3**: `GRANT ALL TO PUBLIC` returns SUCCESS with no log entry indicating "we couldn't classify this — defaulting to allow." Operator has no way to know the classifier missed.
* **gbounce H4 (IMDS SSRF)**: blocked WITHOUT audit. Per variant-A: "DOUBLE-MISS: blocks + doesn't log."
* **`iam-jit logs ship-to`**: per `[[ambient-value-prop-and-friction-framing]]` the surface IS value-framed ("Detected X — here's how"); good baseline pattern.
* **Profile install SSRF protection**: structured error per `test_profile_install_ssrf.py`; verify message is agent-actionable.
* **`bounce profile install` overwrite refusal** (per `[[creates-never-mutates]]`): error must tell operator "this file exists; use --overwrite or pick a new name" — verify in MRR-2.

## 6. Recommended MRR sequence

| Phase | Pre-deploy gate? | Why |
|---|---|---|
| **MRR-2** (error-path audit) | Yes — start immediately | The 5 CRITs share a root cause: state-claimed-without-verification. MRR-2 closes the operator-side of that. |
| **MRR-3** (UAT framework) | Yes — start in parallel | E2E UAT for the 5 CRITs IS the composition-gap close. Re-use as MRR-7 fixtures. |
| **MRR-4** (abort + rollback) | Yes | `iam_jit_setup_from_config` partial-install rollback is the load-bearing case here. |
| **MRR-5** (in-flight monitoring) | Yes | Disk-pressure circuit breaker tested; bouncer-hang + chain-break monitoring needs runbook. |
| **MRR-6** (operator runbook) | **Yes BUT blocked on #489 `iam-jit init`** | Cannot write a runbook that references a command that doesn't exist. Either ship #489 first or de-scope MRR-6 to "init-solo + manual YAML." |
| **MRR-7** (independent review) | Yes | Same agent doing MRR-1 should NOT do MRR-7 per `[[tests-and-independent-uat-required]]`. |
| **MRR-8** (founder signoff) | Yes | Quality gate not calendar gate. |

**Post-deploy / promotion-only**: helm K8s install validation; air-gapped fixture; Pro-tier UI guided reduction; enterprise self-bootstrap; deny_classifier corpus expansion; improve_profile suggestion-quality corpus.

## 7. Cross-cutting findings

1. **Every LLM-augmented surface lacks its own calibration corpus.** UC-2, 17, 18, 19, 22 all ship judgment-quality claims with no measurement. Per `[[calibration-quality-bar]]` this is the single largest cross-cutting gap. Build ONE corpus framework (per `[[role-effectiveness-corpus]]` shape, MEANINGFUL / PARTIAL / THEATER / NEGATIVE-VALUE grades) and run all four surfaces against it. MRR-3 should produce this as a primary deliverable.
2. **"Reported status without observable state" is the recurring bug shape.** CONTRIBUTING.md catalogued 7 such bugs (#326, #448, #462, #463, #475, #476, #477). The state-verification convention now exists but post-convention NEW SURFACES (UC-17, UC-20, UC-19) lack the same E2E discipline applied. MRR-2 should add state-verification assertions to the 5 CRIT surfaces.
3. **Cross-bouncer composition is consistently mocked.** UC-10, 11, 17, 23, 24, 28 all have "integration" tests that mock the per-bouncer HTTP transport. Real four-process fan-out has never been exercised in CI. Recommend a `tests/integration_live_bouncers/` tier that spawns real bouncer binaries (the dogfood orchestration scaffold at `/Users/reagan/repos/dogfood/` is the closest existing artifact — adopt its pattern into the iam-roles CI matrix).
4. **dbounce's H3 + gbounce's H4 represent the worst-of-both: known-bypass + missing-audit.** Per `[[ibounce-honest-positioning]]` the FRAMING ("dev loop, not security boundary") covers the dbounce-bypass risk for development workloads — but on a WORK AWS account these are dependably-exploitable holes. Either fix or document loudly that "if you have RDS Postgres / IMDS-reachable subnets, do not enable dbounce/gbounce on prod data plane yet."
5. **The "ambient-autonomous-protection" pitch is load-bearing AND structurally untested.** UC-20 `iam_jit_setup_from_config` is the single command that closes the loop from `docs/HARNESS-RECIPES/`. Today it works in unit tests; nobody has run the actual MCP-agent install flow against the actual bouncers. The pitch is the v1.0 differentiator (per `[[ambient-autonomous-protection]]` LAUNCH-BLOCKER promotion); the verification is missing.
6. **MRR-6 is blocked on a CRIT (#489).** Operator-runbook prose cannot reference `iam-jit init` until the command exists. Sequence accordingly: either land #489 OR rewrite MRR-6 around `init-solo + manual YAML + iam-jit doctor apply-config`.
7. **`a0bb55f208c227466` (iam-risk-score hosted cleanup) landed mid-audit as `f30001b` "chore: drop hosted iam-risk-score Lambda + REST endpoint (restores [[no-hosted-saas]])"**. Deleted: `infrastructure/sam/template.yaml`, `src/iam_jit/lambda_handler.py`, `src/iam_jit/routes/score.py`, hosted-scoring tests. UC-2 + UC-38 audit findings above reflect the POST-cleanup local-only scoring shape. The C1 Bucket entry in `[[llm-call-site-audit-2026-05-23]]` ("POST /api/v1/score HOSTED scoring API — tier-gated; out of local-dev scope") is now moot because the route no longer exists; no Bucket-C path requires deploy-blocker re-audit.

---

End of MRR-1.
