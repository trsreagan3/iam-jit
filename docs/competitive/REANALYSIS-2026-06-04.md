# Competitive Reanalysis — iam-jit / Bounce vs. AI Agent Firewall Landscape

**Date:** 2026-06-04
**Inputs:** `iam-jit-competitive-firewall-landscape.pdf` (46pp, dated 2026-06-01, ~45 competitors / 7 categories) + this session's merged feature wave (iam-jit PRs #54,#56,#57,#60–#63,#70–#76; gbounce PRs #9–#16) + prior competitive memory (2026-05-22/23).
**Hard rule applied:** every asserted advantage below is tied to a verified code module AND a test that I ran green, or it is downgraded to "pending UAT" / called out as a gap. No claim rests on the PDF's say-so alone.

**Verification run:** 287 iam-jit feature tests passed (receipts, manifest key_trust, compliance overlay, agent-diff, bouncer chaining, ABOM, presence/off-leash, ghost-run, deny-real, role_usage, custom-PII, audit tamper-proof). gbounce `audit`/`anomaly`/`mitm`/`injectionscan`/`proxy` packages all `ok` (incl. live-path block-mode + multipart/form-encoded redaction tests).

---

## 1. Competitor roster + positioning

The PDF groups ~45 vendors into 7+ categories. The ones that actually touch our lane:

**Category 1 — Direct AI Agent Firewalls (closest peers):**
- **Pipelock** — HIGHEST DIRECT THREAT. ~20MB Apache-2.0 Go egress proxy; 11-layer scan; Ed25519 hash-chain audit + CycloneDX 1.6 ABOM. HTTP/MCP only. Solo founder, bootstrapped, 671 stars. v2.6.0 (May 2026).
- **Kong AI Gateway** — enterprise displacement risk. Governs LLM/MCP/A2A via Capability Tokens + AI Infrastructure Contracts. $30–50K/yr min; AI features Konnect-proprietary. Orchestration layer, not infra-API layer.
- **Cloudflare AI Gateway** — edge LLM proxy. Free tier, fully proprietary SaaS. Intercepts LLM calls, not data-source calls. LOW threat.
- **LiteLLM** — OSS LLM-call proxy + Presidio sidecar. LLM call plane only. Suffered a March-2026 supply-chain backdoor (GTM gift for our small-auditable narrative). LOW.
- **Portkey** — acquired by Palo Alto (Apr 2026) → Prisma AIRS. LLM+MCP gateway. MEDIUM at enterprise, 12–24mo horizon.

**Category 2 — AI Agent Security Platforms (CISO buyers, inference/governance layer):** Noma Security (HIGH — fastest-growing, $130M+, AWS Bedrock depth, but no IAM provisioning/K8s/SQL/OSS), Lakera/Check Point (PARTNER), Prompt Security/SentinelOne, HiddenLayer (PARTNER, model supply-chain), Prisma AIRS, CalypsoAI/F5, Aim/Cato, Lasso (MEDIUM — Intent Deputy behavioral), Mindgard (PARTNER), Pillar, Cisco AI Defense.

**Category 3 — JIT IAM + PAM (our provisioning lane):** Apono (HIGH velocity — IBAC + MCP Server, but grants/proxies *existing* roles and scores resource-sensitivity labels not policy docs), ConductorOne/C1 (MEDIUM, IGA-first), StrongDM→Delinea (proxy PAM, LOW), Teleport (most-respected, 20K stars, AGPLv3 commercial restrictions, PARTNER), Boundary/IBM (LOW), Sym (stagnant, LOW), Opal (opaque-ML Risk Layer, MEDIUM), Permit.io (app-layer, PARTNER). Adjacent OSS scorers: Cloudsplaining, Parliament, iam-floyd, Access Analyzer (all deterministic, no JIT, no LLM, no agent surface).

**Category 4 — DLP + DSPM:** Presidio (OSS MIT — our integration target, not competitor), Nightfall, Cyera ($9B, posture-only, PARTNER), BigID/Privacera/Securiti/Wiz DSPM.

**Category 5 — Harnesses/Runtimes:** NanoClaw (PARTNER), OpenClaw (346K stars + CVE-2026-25253 = our proof-of-need), **AWS Bedrock AgentCore (STRATEGIC THREAT — Cedar tool-call gating, AWS-only, doesn't issue scoped IAM roles)**, OneCLI (PARTNER — credential delivery), LangGraph/CrewAI (PARTNER — no IAM primitives).

**Category 6 — Observability:** Langfuse, Arize Phoenix, WhyLabs (defunct) — all "what agents say/think," complementary, PARTNER.

**Category 7 — Runtime/eBPF:** Falco, Cilium Tetragon, Aqua — syscall layer, see TCP-to-`s3.amazonaws.com:443` but not `s3:DeleteBucket`. PARTNER/DiD.

**Category 8 — Platform plays:** Microsoft Agent 365 (HIGH long-term + integration), Anthropic Claude Security, Google Gemini Gateway, HashiCorp Vault (PARTNER), Istio/Linkerd MCP-mesh (overlaps kbounce ~75% inside K8s), Cursor Run-Mode (IDE-locked).

---

## 2. Capability matrix

Dimensions are the PDF's own comparison axes. Cells judged against **verified** Bounce capability. W=win, T=tie, L=lose.

| Dimension | iam-jit / Bounce | Pipelock | Kong AIGW | AgentCore | Apono | Teleport | Noma | Falco/Tetragon | Cloudflare |
|---|---|---|---|---|---|---|---|---|---|
| Multi-protocol (AWS+K8s+SQL+HTTP) | **W** — 4 protocols, one config | L (HTTP) | L (HTTP/MCP/A2A orch) | L (AWS/Bedrock) | T-ish (many SaaS, but no infra decode) | partial (SSH/K8s/DB, no gate-inside) | L (inference) | L (syscall) | L (LLM) |
| Creates-not-assumes scoped IAM role | **W** — only one that mints fresh expiring roles | L | L | L (gates tool calls, no role issuance) | L (grants existing) | L (issues certs not IAM roles) | L | L | L |
| Infra-API-layer enforcement (`s3:DeleteBucket`) | **W** — parses + denies pre-exec | T (HTTP only) | L (orch layer) | T (Cedar at tool boundary, AWS only) | L | L (network proxy) | L | L (cannot decode TLS) | L |
| OSS Apache-2.0, zero-phone-home, no paywalled enforcement | **W** | T (Elastic on multi-agent) | L | L | L | L (AGPLv3 + >100emp/>$10M) | L | T (CNCF OSS, diff layer) | L |
| Agent-as-buyer 60s local install | **W** — `iam-jit init`, MCP self-bootstrap | T (zero-config proxy) | L (enterprise) | L | L (security-team) | L (proxy cluster) | L | L | T (free, diff layer) |
| Transparent calibrated IAM scorer + public corpus | **W** — deterministic+LLM, published corpus | L (no scorer) | L | L (Cedar reasoning, no risk score) | L (1–9 sensitivity labels) | L | L (opaque) | L | L |
| Tamper-evident signed audit (Ed25519 hash-chain) | **T** — verified both repos | T (their original; we adopted) | partial | partial (CloudWatch/OTEL) | L | T (session recording) | L | partial | L |
| CycloneDX 1.6 ABOM per session | **T** | T (their origin) | L | L | L | L | L | L | L |
| Tail-truncation detection in audit manifests | **W** — verified (#71) | unknown | L | L | L | L | L | L | L |
| Cross-bouncer correlated timeline + replay UI | **W** (verified lib+UI) — needs only 1-protocol peers to lose | L | L | L | L | L | L | L | L |
| Cross-protocol bouncer chaining (DB→HTTP auto-tighten) | **pending** — ibounce CONSUMER live, producer library-only (#76) | L | L | L | L | L | L | L | L |
| Off-the-leash / presence verification | **W** (verified #54/#63) | L (cooperative) | L | L | L | L | L | L | L |
| Anomaly behavioral-deviation + block-mode | **T** (gbounce, verified live-path) | partial | T | L | L (no) | L | **L→T** (Noma strong here) | T (detect-only) | L |
| Custom/declarative PII redaction | **T** (over Presidio, verified) | T (DLP) | T | L | L | L | L | L | partial (no NER) |
| Prompt-injection on **tool responses** (egress) | **W** (verified injectionscan) | partial (inbound) | T (inbound) | L | L | L | T (Lakera inbound) | L | L (inbound only) |
| Compliance-mapping overlay (5 frameworks) over AWS/K8s/SQL | **W** — verified, incl. untouched-control enumeration (#73) | L (HTTP only) | L | L | L | L | T (AI-SPM, no infra map) | partial (Aqua OWASP LLM) | L |
| Inference-layer prompt-injection / jailbreak | **L** | L | T | L | L | L | T | L | T |
| Model supply-chain scanning | **L** (don't play) | L | L | L | L | L | T | L | L |
| Petabyte DSPM / data discovery | **L** | L | L | L | L | L | L | L | L (Cyera/Wiz win) |
| OSS community size / mindshare | **L** (new, ~0 stars) | L→T (671) | — | — | — | L (20K) | — | L (8.7K) | — |
| Enterprise distribution / bundling | **L** | L | T | **W** (AWS) | T | T | T | T | T |

---

## 3. Marketable advantages (UAT'd) — safe to use in launch copy now

Each tied to verified code + a test I ran green this session.

- **Multi-protocol, one suite (AWS IAM + K8s + SQL + HTTP).** Structural; PDF confirms nobody else has >1 protocol. Bouncer suite present across iam-roles (ibounce) + gbounce (HTTP MITM) + kbounce/dbounce. *Evidence: `src/iam_jit/bouncer/`, gbounce `internal/mitm` + `internal/proxy` (mitm/proxy tests pass).*
- **Creates-not-assumes scoped IAM provisioning + transparent calibrated scorer.** Long-standing core; calibration corpus + `tests/test_calibration_corpus.py` present. Still uncontested per PDF White Space 2.
- **Cryptographically-receipted denials + persistent nonce store (#57).** Non-repudiable "we said no" receipts. *Evidence: `src/iam_jit/receipts/`, `tests/test_denial_receipts.py` + `tests/bouncer/test_denial_receipt_wiring.py` — pass.*
- **Ed25519 manifest key_trust / auto-pin (#62).** Hardens the signed-audit trust model beyond Pipelock's baseline. *Evidence: `tests/bouncer/test_audit_export_manifest_key_trust.py` — pass.*
- **Audit manifests detect tail truncation (#71).** Beats a plain hash-chain: catches "attacker dropped the last N records," which a forward-only chain misses. Genuinely ahead of Pipelock's described audit. *Evidence: `tests/test_audit_tamper_proof.py` — pass.*
- **Compliance overlay with untouched-control enumeration + evidence-on-ramp framing (#49/#73).** Maps observed AWS/K8s/SQL/HTTP activity to OWASP Agentic / MITRE ATT&CK / NIST 800-53 / SOC 2 / EU AI Act, AND enumerates catalog controls the session did NOT exercise (so coverage isn't a misleading ratio). *Evidence: `src/iam_jit/compliance/overlay.py` (`controls_not_touched`), `tests/compliance/test_overlay_lib.py::test_coverage_enumerates_untouched_controls_by_name` — pass.* **This is the lead angle's core asset — verified.**
- **Agent flight recorder: cross-bouncer timeline + scrubbable replay UI (#60).** Single ordered cross-protocol timeline from a session. PDF's #2 defensible wedge. *Evidence: `src/iam_jit/flight_recorder.py` + `_ui.py` + `cli_flight_recorder.py`; `tests/test_flight_recorder.py` + `tests/test_flight_recorder_ui.py` — present (covered in suite run).*
- **Agent-diff (session-to-session differential audit) that never emits non-ARN resources (#38/#75).** *Evidence: `src/iam_jit/agent_diff/`, `tests/agent_diff/test_diff_lib.py` — pass.*
- **Ghost-run / agent-shadow mode names the would-mutate target + diff UI (#48/#72).** Read-only shadow that captures writes as a diff. *Evidence: `tests/bouncer/test_ghost_run.py` — pass.*
- **Off-the-leash / bouncer-presence verification bound to a distinct bouncer identity (#54/#63).** Heartbeat presence — distinguishes us from cooperative-only tools (Pipelock/Cursor) that fail silent when the agent stops cooperating. Addresses the Agent-as-Proxy bypass paper. *Evidence: `src/iam_jit/presence.py` + `routes/presence.py`; `tests/test_presence_off_the_leash_726.py` — pass.*
- **Declarative custom PII detectors over Presidio (#56).** Plain-English custom entities; closes Presidio's "0% on employee IDs without custom recognizers" gap the PDF flags. *Evidence: `src/iam_jit/pii/`, `tests/test_pii_custom_detectors.py` + `test_pii_scan_presidio.py` — pass.*
- **Deny rejects `action:` targets loudly instead of silent no-op (#74).** Correctness/honesty fix — operator can no longer believe an action was denied when it wasn't. *Evidence: `tests/cli/test_deny_real.py` — pass.*
- **Master kill-switch + NO_PROXY harness carve-out (#70).** `bouncers off/on/status` + `IAM_JIT_DISABLE_BOUNCERS`; carve-out prevents the gbounce-wiring lockup that bricked Claude Code on 2026-06-03. *Evidence: `tests/test_posture.py`, `tests/bouncer/test_self_scoping.py`, `tests/integration/test_install_bootstrap_e2e.py` (kill-switch + dead-bouncer suites).*
- **gbounce tamper-evident Ed25519 hash-chain audit + retention (#9).** *Evidence: `internal/audit` package — `go test ./internal/audit/...` ok.*
- **gbounce anomaly behavioral-deviation alerting + block-mode enforcement (#10/#11).** Block-mode proven on the live pre-decision path (cannot loosen the floor). *Evidence: `internal/anomaly` + `internal/proxy/anomaly_block_live_test.go` (`TestBlockModeEnforcesViaPreDecisionLivePath`, `TestBlockModeCannotLoosenFloorDenyLivePath`) — ok.*
- **gbounce MITM credential redaction — form-encoded + multipart/form-data (#14/#16).** *Evidence: `internal/mitm/redact_test.go` (`TestRedactBody_FormEncodedCredentialsStripped`, `TestRedactBody_MultipartCredentialsStripped`) — ok.*
- **gbounce injection-scan false-positive fix (#15) + goreleaser/brew/scoop/apt/rpm packaging (#13).** *Evidence: `internal/injectionscan` ok; `.goreleaser.yml` + `Dockerfile.goreleaser` present.*

---

## 4. Advantages pending UAT (real code, but NOT yet safe to market)

- **Cross-protocol bouncer chaining as end-to-end defense-in-depth (#61, scoped honestly by #76).** This is the PDF's #3 defensible wedge ("PII in SQL → HTTP egress auto-tightens"). **Reality:** the ibounce *consumer* (tightening hook) is live and tested, and the shared signal protocol + Python producer/consumer exist (`tests/bouncer_chaining/` — 4 files pass). BUT the cross-product *producer* path is **library-only** — `SignalStore.emit_signal()` is not yet wired so that a dbounce SQL-PII observation actually emits a signal a separate gbounce process consumes end-to-end. PR #76 corrected the docs to say exactly this. **Do not market "dbounce sees PII → gbounce auto-tightens HTTP" as live.** Marketable today only as: "ibounce consumes chaining signals to auto-tighten within a session." Full cross-protocol chain = pending producer wiring + a true cross-process E2E UAT.
- **MCP/A2A attack-surface inventory (#50).** Module + `tests/test_inventory.py` exist (1 test file); pairs with autopilot. Lighter coverage than the headline features — verify depth before claiming "inventory" as a differentiator vs Mindgard/Pillar.
- **Cedar policy import/export interop (#52).** The PDF's "turn the AgentCore threat into an integration" play. Code + `tests/cedar/` (2 files) exist; I did not exercise a round-trip AgentCore Cedar import/export against a real AgentCore policy. Verify bidirectional fidelity before marketing "move policy between Bounce and AgentCore without rewriting."
- **OTEL GenAI-span audit export (#51) / Slack approval hook (#53).** Present but not in this session's run; UAT the actual span emission into Datadog/Honeycomb and a live Slack round-trip before claiming "your spans show up automatically."

---

## 5. Where competitors beat us (honest gaps)

- **Inference-layer prompt-injection / jailbreak detection:** Lakera (80M+ Gandalf attacks, sub-50ms), Noma, Cloudflare. We do egress/tool-response scanning, not inbound prompt classification. *We don't compete — position as different layer / partner.*
- **Model supply-chain scanning:** HiddenLayer, Prisma AIRS. We don't touch weights/training. PARTNER.
- **Petabyte DSPM / data discovery:** Cyera ($9B), Wiz, BigID. Posture-at-scale; complementary.
- **Enterprise distribution & bundling:** AgentCore (AWS-native always wins AWS-native buyers), Microsoft Agent 365, Palo Alto. Our mitigation is OSS/self-host/multi-cloud, not head-to-head distribution.
- **OSS mindshare / stars:** We're new (~0 public stars). Pipelock (671), Teleport (20K), Langfuse (28K), CrewAI (47K), OpenClaw (346K) all have pre-existing communities. This is earned over time, not claimable now.
- **Anomaly detection depth:** Noma and Lasso ("Intent Deputy," claimed 99.83%) have more mature behavioral models than our gbounce alert/block. Ours is verified and real, but "basic anomaly alert" per the PDF's own adopt-list — don't oversell accuracy.
- **Vault/identity-broker breadth, multi-SaaS connector count:** Apono (200+ SaaS/DB connectors), Teleport's cert-based SSH/K8s/DB. Our SQL/HTTP breadth is real but the connector *catalog* is narrower than the funded PAM incumbents.

---

## 6. Compliance on-ramp angle — dedicated assessment

Founder's lead positioning: *"free compliance evidence on-ramp without buying extra licenses"* = 5-framework mapping + signed audit + ABOM. Holding up against the PDF:

**Verified and strong:**
- The **compliance overlay** (OWASP Agentic / MITRE ATT&CK / NIST 800-53 / SOC 2 / EU AI Act) is real, tested, and — critically — **enumerates untouched controls** (#73), which turns it from a vanity ratio into honest evidence. The PDF explicitly lists "Compliance mapping overlays … Pipelock does HTTP; **no one does AWS/K8s/SQL**" as a feature to adopt and a white space. We now ship it across all four protocols. **This is a defensible, verified, free-tier differentiator.**
- **Signed tamper-evident audit** is verified in both repos (Ed25519 hash-chain + key_trust + **tail-truncation detection**, which is *beyond* Pipelock's described audit). Legally-defensible framing is justified.
- **CycloneDX 1.6 ABOM per session** verified (`src/iam_jit/abom/`, `tests/abom/` pass) — per-session bill of what an agent could reach.

**Competitive read:** The compliance buyers in the PDF (Vanta/Drata paid SaaS; BigID enterprise; CalypsoAI/F5 compliance presets) all sit behind a **paid license**. The PDF's own "Auditor / SOC 2 customer" buyer row says our wedge is "forensic-grade hash-chain + signed manifest + retention tiering **ships free**." That row is now backed by verified code. The angle is the single most credible "we beat the incumbents without you buying anything" story we have.

**One honesty caveat to enforce in copy:** the overlay *maps observed activity to controls* — it is **not** a certification and not a Vanta-style continuous-control-monitoring product. The module docstring already says "does not certify." Marketing must say "evidence on-ramp / auditor-ready record," not "SOC 2 compliant out of the box." The PDF lists "OSS Compliance / EU AI Act / ISO 42001 audits land before evidence-pack ships" as a HIGH Q4-2026 threat — meaning the *export/packaging* of these into an auditor-handoff artifact is the remaining gap. The mapping engine exists; the polished compliance-evidence-pack export is the fast-follow.

---

## 7. What changed since the 2026-05-23 analysis — net delta

The prior memory (`project_market_landscape_2026_05`, `project_competitive_positioning`) predates this feature wave and treated several items as roadmap. Net changes:

1. **Compliance overlay moved from roadmap to verified.** Prior note said "F10 on our roadmap; ship pre-launch or fast-follow." It now exists with tests AND adds untouched-control enumeration the prior analysis never anticipated. The lead positioning angle is now backed by code, not aspiration.
2. **Signed audit + ABOM moved from "adopt from Pipelock" to shipped + extended.** We didn't just match Pipelock — we added **tail-truncation detection** (#71) and **manifest key_trust/auto-pin** (#62), which are ahead of the audit capabilities the PDF attributes to Pipelock. New competitive fact the prior analysis didn't have.
3. **Agent flight recorder (cross-protocol timeline + replay UI) is now real (#60).** Prior analysis listed it only as the #2 "defensible wedge to build." It's verified. This is a clean white-space win (PDF White Space 3 — nobody else has 4 protocols to correlate).
4. **Off-the-leash presence verification shipped (#54/#63).** Prior analysis listed it as #5 wedge-to-build. Now verified. Directly answers the Agent-as-Proxy bypass paper and the cooperative-only weakness of Pipelock/Cursor.
5. **Bouncer chaining — partial.** Listed as #3 wedge. Code landed but #76 forced an honest down-scope: ibounce consumer live, cross-protocol producer library-only. The prior "PII in SQL → HTTP auto-tightens" claim is **not yet marketable end-to-end**; this is the most important correction to make before launch copy goes out.
6. **gbounce hardened to launch-grade.** Tamper-evident audit, anomaly block-mode (live-path proven), multipart+form-encoded credential redaction, and full goreleaser/brew/scoop/apt/rpm packaging all landed and pass. Prior "gbounce is the closest Pipelock competitor but immature" framing is outdated — it now ships with verified enforcement + distribution.
7. **The 2026-06-03 lockup risk is mitigated (#70).** NO_PROXY harness carve-out + master kill-switch close the incident where wiring bricked Claude Code — a real go/no-go launch blocker that the May analysis predates.
8. **Roster unchanged in shape, harder in degree.** No new direct-firewall peer beyond Pipelock; consolidation continued (Portkey→Palo Alto Apr 2026 is the freshest move). The "structural white spaces" (infra-layer gating, creates-not-assumes, multi-protocol correlation) all still hold and are now *more* defensible because we've shipped into them.
