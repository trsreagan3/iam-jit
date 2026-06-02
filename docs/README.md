# docs/ — index + reading order

This directory has ~100 markdown files. Most are reference material;
some are dated artifacts (audits, launch checkpoints, sweeps). Read
this index first so you know which file answers your question.

If you're new, start with the repo-root [`README.md`](../README.md)
for the product overview + [`FEATURES.md`](FEATURES.md) for the full
catalog. Once you've decided which product to deploy, the per-role
sections below tell you which docs to read next.

---

## Start here

| Doc | What it answers |
|---|---|
| [`../README.md`](../README.md) | What iam-jit is + which of the four products fits you |
| [`FEATURES.md`](FEATURES.md) | Full feature catalog (extracted from the old long-form README) |
| [`GETTING-STARTED.md`](GETTING-STARTED.md) | Self-host MVP deploy — git clone to working endpoint in ~5 minutes |
| [`SECURITY-POSTURE.md`](SECURITY-POSTURE.md) | Trust model, threat model, what iam-jit will + won't protect against |
| [`KNOWN-CAVEATS.md`](KNOWN-CAVEATS.md) | Authoritative limitation list (read before install) |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Testing standards (state-verification convention) + `assert` discipline |

---

## For operators

You're deploying or running iam-jit + bouncers in your environment.

### Install + deploy

| Doc | Covers |
|---|---|
| [`GETTING-STARTED.md`](GETTING-STARTED.md) | Self-host MVP deploy walkthrough (~5 min) |
| [`DEPLOYMENT.md`](DEPLOYMENT.md) | Full production deploy: hardening tiers, cost levers |
| [`DEPLOYMENT-PRESETS.md`](DEPLOYMENT-PRESETS.md) | Pre-baked CFN parameter bundles per deployment shape |
| [`BOOTSTRAP.md`](BOOTSTRAP.md) | First-admin claim flow + bootstrap secrets |
| [`REDEPLOY.md`](REDEPLOY.md) | Stack-update workflow |
| [`UPGRADING.md`](UPGRADING.md) | v0.x → v1.0 migration + deprecation timelines |
| [`TEARDOWN.md`](TEARDOWN.md) | Clean uninstall of a deployed stack |
| [`HTTPS-SETUP.md`](HTTPS-SETUP.md) | TLS termination + cert wiring |
| [`ENTERPRISE-SELF-BOOTSTRAP.md`](ENTERPRISE-SELF-BOOTSTRAP.md) | Enterprise self-host bootstrap pathway |
| [`MARKETPLACE-PUBLISHING.md`](MARKETPLACE-PUBLISHING.md) | Publishing your fork to internal marketplaces |
| [`PUBLISHING.md`](PUBLISHING.md) | Public release flow for forks |

### Day-to-day operation

| Doc | Covers |
|---|---|
| [`POSTURE.md`](POSTURE.md) | `iam-jit posture` CLI — which mode is running where |
| [`DIAGNOSTICS.md`](DIAGNOSTICS.md) | `iam-jit doctor` flows + interpretation |
| [`IBOUNCE.md`](IBOUNCE.md) | ibounce CLI reference + per-task scopes + audit chain |
| [`WIRING-AN-AGENT.md`](WIRING-AN-AGENT.md) | Wire any agent through any bouncer — per-protocol table + canonical port table |
| [`DYNAMIC-DENY-RULES.md`](DYNAMIC-DENY-RULES.md) | Cross-product `iam-jit deny add` fan-out |
| [`PROFILE-GENERATION.md`](PROFILE-GENERATION.md) | Generate bounce profiles from observed audit events |
| [`PROFILE-UPGRADE.md`](PROFILE-UPGRADE.md) | `ibounce profile doctor` post-upgrade flow |
| [`ORG-PROFILE-DISTRIBUTION.md`](ORG-PROFILE-DISTRIBUTION.md) | Distribute safety profiles across your fleet |
| [`PER-ORG-NOTIFICATION-ROUTING.md`](PER-ORG-NOTIFICATION-ROUTING.md) | Slack channel + webhook routing per org |
| [`LOG-RETENTION.md`](LOG-RETENTION.md) | Audit log rotation + retention runbook |
| [`PRODUCTION-LOG-STORAGE.md`](PRODUCTION-LOG-STORAGE.md) | Decision tree: where audit logs go per deployment context |
| [`QUERYING-AUDIT-LOGS.md`](QUERYING-AUDIT-LOGS.md) | `iam-jit audit query` filters + cross-bouncer correlation |
| [`IAM-JIT-AUDIT-QUERY.md`](IAM-JIT-AUDIT-QUERY.md) | Audit query reference |
| [`SESSION-REPLAY.md`](SESSION-REPLAY.md) | Replay a JIT session from audit events |
| [`LIVE-ACTION-TAIL.md`](LIVE-ACTION-TAIL.md) | Real-time per-grant CloudTrail tail |
| [`AUDIT-STREAM-TUI.md`](AUDIT-STREAM-TUI.md) | Terminal UI for live audit stream |
| [`ANOMALY-DETECTION.md`](ANOMALY-DETECTION.md) | Z-score baseline + MITRE ATLAS classifier |
| [`BACKUP-RESTORE.md`](BACKUP-RESTORE.md) | DynamoDB + state backup runbook |
| [`MITM-MODE.md`](MITM-MODE.md) | HTTPS/MITM proxy mode (BETA) |
| [`SECURITY-LAKE-INTEGRATION.md`](SECURITY-LAKE-INTEGRATION.md) | AWS Security Lake export |
| [`WEBHOOK-PRESETS.md`](WEBHOOK-PRESETS.md) | Pre-baked webhook payload shapes (Datadog / Splunk / Sentinel) |
| [`INTEGRATION-OPENCLAW-NANOCLAW.md`](INTEGRATION-OPENCLAW-NANOCLAW.md) | Composition with NanoClaw / OpenClaw harnesses |
| [`HARDENING-AGAINST-PROMPT-INJECTION.md`](HARDENING-AGAINST-PROMPT-INJECTION.md) | Prompt-injection resistance posture |
| [`COMPATIBILITY-ALLOWLIST.md`](COMPATIBILITY-ALLOWLIST.md) | Which MCP clients are verified |
| [`PERMISSIONS-MODEL.md`](PERMISSIONS-MODEL.md) | Role / requester / approver / admin model |

### Runbooks

| Doc | Covers |
|---|---|
| [`MRR-4-ROLLBACK-RUNBOOK.md`](MRR-4-ROLLBACK-RUNBOOK.md) | Rollback after a bad deploy |
| [`MRR-4-HALT-CONDITIONS.md`](MRR-4-HALT-CONDITIONS.md) | When to stop a rollout |
| [`MRR-4-UNINSTALL.md`](MRR-4-UNINSTALL.md) | Full multi-product uninstall |
| [`MRR-5-MONITORING-RUNBOOK.md`](MRR-5-MONITORING-RUNBOOK.md) | Alert wiring + escalation paths |
| [`LAUNCH-DAY-RUNBOOK.md`](LAUNCH-DAY-RUNBOOK.md) | Launch-day operator checklist |
| [`ROLLOUT-PLAYBOOK.md`](ROLLOUT-PLAYBOOK.md) | Phased fleet rollout |
| [`DEPLOY-FEEDBACK-TEMPLATE.md`](DEPLOY-FEEDBACK-TEMPLATE.md) | Template for capturing post-deploy feedback |
| [`PRODUCTION-READINESS.md`](PRODUCTION-READINESS.md) | Pre-flight checklist before public traffic |

---

## For developers

You're building on top of iam-jit, integrating it into an agent, or
contributing to the core repo.

### Architecture + design

| Doc | Covers |
|---|---|
| [`AGENTS.md`](AGENTS.md) | The agent-driven reduction-loop pattern |
| [`AGENT-ATTRIBUTION.md`](AGENT-ATTRIBUTION.md) | How agent identity flows through audit |
| [`AGENT-WRITING-ROLES.md`](AGENT-WRITING-ROLES.md) | When agents author roles vs. when iam-jit does |
| [`AGENT-DEPLOYMENT-PROMPT.md`](AGENT-DEPLOYMENT-PROMPT.md) | Agent-side system-prompt patterns |
| [`agent-access.md`](agent-access.md) | Agent access patterns reference |
| [`EVALUATOR.md`](EVALUATOR.md) | Auto-approve evaluator design |
| [`EVOLVING-THE-SCORER.md`](EVOLVING-THE-SCORER.md) | Calibration discipline for scorer changes |
| [`RECOMMENDER-API-SPEC.md`](RECOMMENDER-API-SPEC.md) | Recommender API contract (design draft, not v1.0) |
| [`PROFILE-GENERATION-DESIGN.md`](PROFILE-GENERATION-DESIGN.md) | Design notes for profile generation |
| [`ADVERSARIAL-LOOP-PROCESS.md`](ADVERSARIAL-LOOP-PROCESS.md) | How the scorer is adversarially calibrated |
| [`INFRASTRUCTURE-MIGRATION-PLAN.md`](INFRASTRUCTURE-MIGRATION-PLAN.md) | Infra migration design |

### Build + test

| Doc | Covers |
|---|---|
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Testing standards + state-verification convention |
| [`TESTING.md`](TESTING.md) | Test tiers, markers, LocalStack, LLM cassettes |
| [`LOCAL-TEST-INFRA.md`](LOCAL-TEST-INFRA.md) | Per-repo compose.test.yaml + Makefile patterns |
| [`BEDROCK-TEST-PLAN.md`](BEDROCK-TEST-PLAN.md) | Bedrock LLM test plan |
| [`LLM-BACKENDS.md`](LLM-BACKENDS.md) | LLM backend selection (Bedrock / Anthropic / OpenAI / Ollama / none) |
| [`FORKING.md`](FORKING.md) | Forking the repo for an internal build |
| [`MCP-RECIPES.md`](MCP-RECIPES.md) | MCP client recipes |
| [`recipes/`](recipes/) | Per-pattern integration recipes |
| [`HARNESS-RECIPES/`](HARNESS-RECIPES/) | Per-harness recipes (Claude Code / Cursor / Codex / Devin) |
| [`examples/`](examples/) | Working examples (incl. starter profiles) |
| [`schemas/`](schemas/) | JSON schemas |
| [`specs/`](specs/) | Design specs |
| [`tasks/`](tasks/) | Per-task design notes |
| [`UAT-LIFECYCLE/`](UAT-LIFECYCLE/) | UAT process docs |

### Reference

| Doc | Covers |
|---|---|
| [`scoring-bands.md`](scoring-bands.md) | 1–10 scoring band reference |
| [`TUNING-RISK.md`](TUNING-RISK.md) | Tuning the deterministic risk model |
| [`USE-CASES.md`](USE-CASES.md) | Use-case catalog |
| [`INCIDENTS-IAMJIT-WOULD-HAVE-PREVENTED.md`](INCIDENTS-IAMJIT-WOULD-HAVE-PREVENTED.md) | Real-world AI-agent incidents iam-jit prevents |
| [`INVESTIGATE-WITH-CLAUDE.md`](INVESTIGATE-WITH-CLAUDE.md) | Agent-led investigation patterns |
| [`ROADMAP.md`](ROADMAP.md) | Roadmap |
| [`ROADMAP-V1.1.md`](ROADMAP-V1.1.md) | Post-launch scope (currently empty per v1-scope-bar) |
| [`compliance/`](compliance/) | Compliance framework mappings (SOC 2, PCI, HIPAA) |
| [`calibration/`](calibration/) | Calibration corpus + methodology |
| [`research/`](research/) | Research notes |
| [`ci-integrations-research.md`](ci-integrations-research.md) | CI integration research |
| [`LANDING-PAGE-COPY.md`](LANDING-PAGE-COPY.md) | Landing page copy |
| [`launch-posts/`](launch-posts/) | Launch post drafts |
| [`posts/`](posts/) | Blog post drafts |
| [`comic-scripts/`](comic-scripts/) | Comic-strip demo scripts |
| [`demo/`](demo/) | Demo assets |

---

## For reviewers

You're auditing the codebase (security review, due diligence, calibration check).

| Doc | Covers |
|---|---|
| [`SECURITY-POSTURE.md`](SECURITY-POSTURE.md) | The single source of truth for trust + threat model |
| [`SECURITY-SLA.md`](SECURITY-SLA.md) | Vulnerability response SLA |
| [`security-notes.md`](security-notes.md) | Loose-leaf security notes |
| [`security/`](security/) | **The BB+WB audit history.** Start with the latest round; older rounds are historical. |
| [`CONVERGENCE-REPORT-2026-05.md`](CONVERGENCE-REPORT-2026-05.md) | Calibration corpus + methodology (1489/1489 AWS-managed pass rate) |
| [`calibration/feature-reality-check.md`](calibration/feature-reality-check.md) | Feature-by-feature "claim vs. delivery" audit |
| [`calibration/100-prompt-sufficiency-loop.md`](calibration/100-prompt-sufficiency-loop.md) | The calibration measurement that drove the NL-synthesis removal |
| [`compliance/`](compliance/) | SOC 2 / PCI / HIPAA framework mappings |
| [`RANDOM-FUZZ-METHODOLOGY-2026-05-22.md`](RANDOM-FUZZ-METHODOLOGY-2026-05-22.md) | Fuzz methodology + corpus generation |

**How to read the security/ tree.** Each `AUDIT-2026-05-*` file is a
self-contained round. They are cumulative, not iterative — the latest
WB round is the most authoritative current view; the earlier rounds
are kept for traceability of historical findings. New reviewers should
read the latest WB round first, then dip into earlier rounds only when
investigating a specific historical finding referenced from
[`KNOWN-CAVEATS.md`](KNOWN-CAVEATS.md).

---

## Archive — dated artifacts

These files are historical checkpoints. They are NOT the current state
of the project; they are kept for traceability. If you're trying to
understand "what's true today," do NOT start here.

### Calibration / sweep / smoke

- [`CALIBRATION-SWEEP-2026-05-19.md`](CALIBRATION-SWEEP-2026-05-19.md)
- [`CONVERGENCE-REPORT-2026-05.md`](CONVERGENCE-REPORT-2026-05.md) — current calibration reference (kept above too)
- [`SMOKE-TEST-RESULTS-2026-05-19.md`](SMOKE-TEST-RESULTS-2026-05-19.md)
- [`LINUX-SUPPORT-AUDIT-2026-05-24.md`](LINUX-SUPPORT-AUDIT-2026-05-24.md)
- [`COMPETITIVE-PI-ANOMALY-2026-05-24.md`](COMPETITIVE-PI-ANOMALY-2026-05-24.md)

### Use-case + error-path audits (MRR series)

- [`MRR-1-USE-CASE-AUDIT-2026-05-24.md`](MRR-1-USE-CASE-AUDIT-2026-05-24.md)
- [`MRR-2-ERROR-PATH-AUDIT-2026-05-24.md`](MRR-2-ERROR-PATH-AUDIT-2026-05-24.md)
- (MRR-4-*, MRR-5-* runbooks stay above under operator runbooks — they are live, not archive.)

### Launch readiness checkpoints

- [`LAUNCH-PLAN.md`](LAUNCH-PLAN.md) — current live plan
- [`LAUNCH-READINESS-2026-05-16.md`](LAUNCH-READINESS-2026-05-16.md) — historical checkpoint
- [`LAUNCH-READINESS-2026-05-17.md`](LAUNCH-READINESS-2026-05-17.md) — historical checkpoint

### UX feedback snapshots

- [`UX-FEEDBACK-LOCAL-MODE-2026-05-16.md`](UX-FEEDBACK-LOCAL-MODE-2026-05-16.md)
- [`UX-FEEDBACK-LOCAL-MODE-2026-05-16-DEEP.md`](UX-FEEDBACK-LOCAL-MODE-2026-05-16-DEEP.md)

### Adversarial-loop history

- `security/AUDIT-2026-05-*` (19+ rounds) — the BB+WB sequence. See "For reviewers" above for how to read.

Files in this archive section are intentionally NOT moved into a
subdir, because several are cross-referenced by `KNOWN-CAVEATS.md`
+ launch posts + commit messages. Moving them would break those
references. Treat the dated suffix as the archive marker.
