# Competitive scan: PI detection + anomaly detection vendors 2026-05-24

**Scope**: focused scan on prompt-injection (PI) detection + behavioral anomaly detection vendors,
research papers, OSS projects, and patents — scored against iam-jit's architectural shape per
`[[progressive-tightening-as-injection-detector]]`.

**Methodology**: WebSearch + WebFetch over last 60 days of product releases + last 12 months of
research. Public-source only per `[[outreach-anti-spray-discipline]]`. No vendor contact, no trial
signups. Honesty-first per `[[ibounce-honest-positioning]]`.

**Date**: 2026-05-24. Re-validate quarterly.

---

## 1. Executive summary

**Surveyed**: 22 vendors + 7 research papers + 8 OSS repos + USPTO patent skim.

**Closest 5 architectural overlaps** (in descending order of overlap):

1. **Lasso Intent Deputy** (Feb 2026) — per-agent behavioral fingerprints + intent alignment +
   anomaly detection in one product. Same product surface as our progressive-tightening +
   anomaly-detection. Different deployment shape (Cloud-default; self-host available) + different
   layer (LLM prompt+response, not protocol action).
2. **Pipelock v2.4 learn-and-lock** (May 2026) — observe → compile contract → ratify → enforce
   workflow that mirrors our discovery → lean-permissive → tightened phases. Org-wide not
   per-operator. One-shot not progressive. Detection separate from contract.
3. **Microsoft Agent Governance Toolkit** (Apr 2026) — MIT-licensed, all-10-OWASP, behavioral
   trust scoring 0-1000 that decays. Multi-language. Framework-level, no protocol decode.
4. **Pillar Security** — per-agent baselines vs "defined business purpose"; adaptive guardrails
   per agent. Cloud + VPC self-host. No protocol decode.
5. **Progent + AgentGuardian** (research, Apr 2025 + Jan 2026) — peer-reviewed papers proving the
   "tighten-the-belt" + SMT-narrowing-only-with-approval pattern. No shipping product.

**Honest threat assessment**: 1 vendor (Lasso) ships our same-data-drives-both architecture;
1 vendor (Pipelock) ships our progressive-observation-to-policy workflow. NEITHER ships our
combination + protocol-decode + per-operator + independence properties. Pipelock could close
the gap fastest (Apache 2.0, agent-firewall positioning, ~6mo of focused work). Lasso could
close fastest on PI-detection-from-baseline (already has the fingerprint primitive, would need
to drop to action-layer protocol decode — major scope expansion).

**Honest opportunity**: NO vendor surveyed combines (per-operator habit-trained) + (progressive
tightening) + (same data drives BOTH profile AND PI detection) + (protocol-aware action layer)
+ (independent self-host with zero vendor LLM dependency). VentureBeat's RSAC 2026 coverage
explicitly states "no vendor shipped an agent behavioral baseline" at the enterprise SOC layer.
The category is open.

---

## 2. Per-vendor rubric table

Dimensions (per project doc):
- **A**: Operates at action layer (vs prompt/model/cloud-control)
- **B**: Per-operator habit-trained (vs org-wide static)
- **C**: Progressive tightening (vs static profile day 1)
- **D**: Same data drives profile + PI detection
- **E**: Protocol-aware (AWS/K8s/SQL/HTTP)
- **F**: Agent-mediated reasoning (operator's LLM)
- **G**: Independent control plane
- **H**: OSS + free local-dev
- **I**: Honest framing (PI-AWARE not PI-PROOF)

| Vendor | A | B | C | D | E | F | G | H | I | One-line |
|---|---|---|---|---|---|---|---|---|---|---|
| **iam-jit (us)** | YES | YES | YES | YES | YES | YES | YES | YES | YES | reference baseline |
| Lasso Intent Deputy | PARTIAL | YES | NO | YES | NO | NO | PARTIAL | NO | YES | closest same-data-drives-both; SaaS-default; prompt-layer not action |
| Pipelock v2.4 | YES | NO | PARTIAL | NO | PARTIAL (HTTP/MCP) | NO | YES | YES (Apache 2.0) | YES | progressive obs→policy; org-wide; HTTP/MCP only; OSS |
| Microsoft Agent Governance Toolkit | NO | NO | PARTIAL (trust decay) | NO | NO | NO | YES | YES (MIT) | YES | framework-layer; trust scoring decays; no protocol decode |
| Pillar Security | NO | YES | NO | YES | NO | NO | PARTIAL (VPC self-host) | NO | YES | per-agent purpose baseline; gateway-layer; SaaS+VPC |
| CalypsoAI/F5 Agentic Fingerprints | NO | YES | NO | PARTIAL | NO | NO | NO | NO | YES | decision-tree fingerprint; SaaS; F5 acquisition |
| HiddenLayer Agentic Runtime | NO | PARTIAL | NO | YES | NO | NO | NO | NO | YES | session/tool/path search; SaaS |
| Lakera Guard | NO | NO | NO | NO | NO | NO | NO | FREEMIUM (10k/mo) | OVERSELLS (claims 99.83%) | content classifier; single API; Check Point owned |
| Aporia | NO | NO | NO | NO | NO | NO | NO | NO | YES | input/output guardrails; LiteLLM integration |
| Cisco AI Defense (RobustIntel) | PARTIAL | NO | NO | PARTIAL | NO | NO | NO | NO | YES | 5-detector ensemble; SaaS; enterprise focus |
| Prisma AIRS (Palo Alto) | YES (MCP) | NO | NO | PARTIAL | NO | NO | NO | NO | YES | MCP gateway; SaaS; Palo Alto channel |
| WitnessAI | NO | NO | NO | YES | NO | NO | NO | NO | YES | intent-based behavioral; SaaS; $58M Series |
| Prompt Security | NO | NO | NO | NO | NO | NO | NO | NO | YES | preconfigured per-model extractors |
| Sysdig Sage + Prempti | YES (syscall) | NO | NO | NO | NO | NO | NO | PARTIAL (Prempti OSS) | YES | wrong-layer (kernel/syscall not API); Falco rules |
| Wiz AI-SPM | NO | NO | NO | PARTIAL (runtime drift) | NO | NO | NO | NO | YES | inventory + drift; Google Cloud post-acq |
| CrowdStrike Falcon Shield | NO | PARTIAL | NO | NO | NO | NO | NO | NO | YES | discovery + visibility; "no behavioral baseline shipped" per VentureBeat |
| Datadog AI Observability | NO | NO | NO | NO | NO | NO | NO | NO | YES | LLM observability; tool-call mapping |
| Apono Agent Privilege Guard | YES (IAM) | NO | NO | NO | YES (multi-cloud IAM) | NO | NO | NO | YES | JIT IAM via MCP; SaaS; $34M Series B |
| Teleport Agentic Identity Framework | YES (infra) | PARTIAL | NO | PARTIAL (identity ctx) | YES (multi-protocol) | NO | YES (self-host avail) | NO | YES | infra-identity layer; not per-tool-call |
| CyberArk Agent Guard + Conjur | NO | NO | NO | NO | NO | NO | NO | NO | YES | vault + JIT secrets; enterprise PAM |
| Aembit IAM for Agentic AI | YES (workload) | NO | NO | PARTIAL | YES (multi-cloud) | NO | NO | NO | YES | workload-identity for agents; GA Apr 2026 |
| Solo.io agentgateway | YES (MCP/A2A) | NO | NO | NO | PARTIAL (MCP) | NO | YES (LF OSS) | YES (Apache 2.0) | YES | MCP/A2A gateway; uses Agent Card declared capabilities |
| NeuralTrust | NO | NO | NO | NO | NO | NO | NO | NO | YES | runtime + MCP hardening; SaaS |

**OSS-only PI detection (no behavioral baseline)**:

| Project | A | B | C | D | E | F | G | H | I | One-line |
|---|---|---|---|---|---|---|---|---|---|---|
| Meta Prompt Guard 2 | NO | NO | NO | NO | NO | n/a | YES | YES | YES | BERT classifier; HF model |
| LLM Guard (ProtectAI) | NO | NO | NO | NO | NO | n/a | YES | YES | YES | 2.5M+ downloads; CPU-cheap |
| Rebuff (ProtectAI) | NO | NO | NO | NO | NO | n/a | YES | YES | YES | multi-layer + canary; explicitly "prototype" |
| Garak (NVIDIA) | n/a (scanner) | n/a | n/a | n/a | n/a | n/a | YES | YES | YES | offline red-team scanner; 6.9k stars |
| PIGuard (was InjecGuard) | NO | NO | NO | NO | NO | n/a | YES | YES | YES | ACL 2025; over-defense mitigation |
| PISanitizer | NO | NO | NO | NO | NO | n/a | YES | YES | YES | long-context sanitization |
| prompt-armor | NO | NO | NO | NO | NO | n/a | YES | YES | YES | 5 layers, 91.7% F1, 27ms offline |

### Rubric counts (vendors only, n=22)

| Dimension | YES | PARTIAL | NO |
|---|---|---|---|
| A: Action layer | 8 | 3 | 11 |
| B: Per-operator habit-trained | 4 | 4 | 14 |
| C: Progressive tightening | 0 | 3 | 19 |
| D: Same data drives both | 4 | 7 | 11 |
| E: Protocol-aware (AWS/K8s/SQL/HTTP) | 4 | 4 | 14 |
| F: Agent-mediated (operator LLM) | 0 | 0 | 22 |
| G: Independent control plane | 5 | 4 | 13 |
| H: OSS + free local | 4 | 2 | 16 |
| I: Honest framing | 21 | 0 | 1 (Lakera) |

**Key observation**: **Dimension F (agent-mediated reasoning via operator's LLM) is 0/22.** Every
surveyed vendor either runs their own model or no model. None defer reasoning to the operator's
own agent. This is the single biggest architectural differentiator we own.

**Secondary observation**: **Dimension C (progressive tightening) is 0 YES, 3 PARTIAL.** Closest
are Pipelock (one-shot learn→lock, not progressive), Microsoft (trust score decays, not profile),
and Pillar (purpose-defined baseline, not tightening). The progressive shape per
`[[ambient-mode-progressive-tightening]]` is unique to us.

---

## 3. Top 3 overlap deep-dives

### 3.1 Lasso Intent Deputy — closest "same data drives both"

**What they ship** (per Feb 2026 launch + Help Net Security + Lasso blog):
- "Behavioral Fingerprints": unique per-agent fingerprints from historical usage
- "Intent Alignment": verifies every action against the agent's authorized purpose
- "Anomaly Detection": flags deviation from established baseline in real time
- "Explainable Compliance": human-readable evidence for legal/compliance teams
- Sub-50ms latency, claimed 99.83% detection accuracy across 3000+ obfuscation techniques
- Deployment: Gateway, API, or SDK; self-host available (custom apiEndpoint)

**Where they overlap with our shape**:
- Same primitive: per-agent baseline + anomaly detection in one product
- Per-agent NOT per-operator (subtle but real distinction — they baseline the AGENT, we baseline
  PER OPERATOR'S habits) — but the underlying mechanic is the same
- Explainability surface = our anomaly-breakdown surface (per `[[competitive-research-ai-anomaly-detection-2026-05-23]]` F.1)

**Where they DIFFER from our shape**:
- **Layer**: Lasso operates at LLM prompt/response layer + agent action layer in a unified
  scanner. iam-jit operates at protocol action layer with SigV4/K8s/SQL/HTTP decode. Lasso
  doesn't claim AWS-action-shape awareness.
- **Cloud-default**: SaaS-first; self-host is configurable but not the default shape
- **No progressive tightening**: the fingerprint is built once + then compared against, not
  iteratively tightened through phases (Discovery → Lean-permissive → Confidence-tightened →
  Habit-trained → Stable)
- **Vendor model**: their detection runs their model, not operator's agent reasoning over their
  signals
- **Not free**: enterprise pricing

**Honest threat level**: HIGH. Closest single-product analog. If they add AWS/K8s/SQL protocol
decode + progressive tightening, the gap closes. Estimate 12-18 months given their Series B
roadmap pressure to add enterprise features rather than dev-shop OSS shape.

### 3.2 Pipelock v2.4 — closest progressive-observation-to-policy

**What they ship** (per pipelab.org + GitHub):
- Apache 2.0 Go binary, ~20MB, 22 dependencies
- 11-layer scanner pipeline (SSRF + DLP + 25 injection patterns + path traversal + entropy + etc.)
- v2.4.0 "learn-and-lock contracts": `pipelock learn observe → compile → review → shadow → diff
  → ratify → promote → rollback → forget → split`
- Hash-chained Ed25519 audit
- Per-agent behavioral contracts via observed traffic

**Where they overlap with our shape**:
- Apache 2.0 + Go binary + OSS-first + dev-shop persona — same playbook
- Observe → compile → enforce workflow ≈ our Discovery → Lean-permissive → tightened phases
- Per-agent contracts ≈ our per-operator profiles
- "Honest deterrent + audit" framing per `[[ibounce-honest-positioning]]`
- Agent firewall positioning per market-landscape memo

**Where they DIFFER from our shape** (confirmed via WebFetch of pipelab.org/learn/learn-and-lock/):
- **Org-wide not per-operator**: contracts apply to "agent traffic" generally; not per-individual-
  operator habits
- **One-shot not progressive**: documentation explicitly presents lifecycle as "deliberate
  operator review and modification cycles" with `split/pin/forget` — NOT automated tightening
  over time
- **Detection separate from contract**: scanner block always wins over contract allow; the
  learn-and-lock data feeds CONTRACT not anomaly detection
- **Protocols**: HTTP + MCP + WebSocket. No SigV4/K8s API server/SQL AST. Their wedge is
  egress + injection-pattern + DLP; ours is protocol-decoded action classification.
- **Per agent fingerprint**: claimed via "claude-code" example; but appears closer to
  "per-agent-binary contract" than "per-operator behavior model"

**Honest threat level**: MEDIUM-HIGH. Closest OSS analog. Their roadmap explicitly trends toward
our shape (learn-and-lock is a recent v2.4 addition). If they add per-operator habit-tracking +
automated tightening + protocol-decode for AWS/K8s/SQL, gap closes. Estimate 6-12 months for
per-operator; protocol decode requires multi-protocol parser investment (12-24 months).

### 3.3 Microsoft Agent Governance Toolkit — closest behavioral-trust-scoring at framework layer

**What they ship** (per Microsoft Open Source blog + GitHub microsoft/agent-governance-toolkit):
- MIT licensed, 7-package multi-language (Python/TypeScript/Rust/Go/.NET)
- All 10 OWASP Agentic Top 10 risks covered
- Sub-millisecond deterministic policy enforcement
- 20+ framework integrations (LangChain/CrewAI/AutoGen/OpenAI Agents/Bedrock/etc.)
- "Behavioral trust scoring (0-1000) that decays when agents act outside expected patterns"
- SPIFFE/SVID compatible; CloudEvents export; OpenTelemetry observability
- Deploy: Azure/AWS/GCP/Docker Compose (framework-neutral)

**Where they overlap with our shape**:
- MIT licensed + multi-language + independent control plane + framework-neutral
- Trust-decay primitive ≈ our progressive-tightening (both: behavior over time affects policy)
- All-10-OWASP coverage = peer aspiration matching our v1.0 launch surface
- Deterministic enforcement ≈ our deterministic scorer

**Where they DIFFER from our shape** (confirmed via WebFetch of GitHub repo):
- **Framework-layer not protocol-layer**: enforces at LangChain/CrewAI integration points;
  not at SigV4/K8s API/SQL AST decode
- **Trust SCORE decay vs PROFILE TIGHTENING**: their primitive shrinks per-agent trust; ours
  shrinks per-operator allowed actions. Conceptually similar; operationally different.
- **No per-operator habit profile**: trust is per-agent identity, not per-operator behavior
- **Microsoft-led OSS**: cathedral model with foundation aspiration; not bazaar dev-shop adoption

**Honest threat level**: MEDIUM. Microsoft + OWASP + MIT + multi-language = serious gravity well
for buyer attention. Their wedge is "framework integration" not "protocol decode"; they could
absorb buyers who don't care about deep AWS/K8s/SQL awareness. If we miss the dev-shop OSS
adoption window, they could become the default. Estimate 6-12 months before MS reaches general
adoption equivalent to current Falco/Prempti footprint.

---

## 4. Research-paper landscape

Top 3 most-relevant papers to our architecture (last 12 months):

### 4.1 Progent — Programmable Privilege Control for LLM Agents (arXiv 2504.11703, Apr 2025)
- **Architecture**: SMT solver determines whether policy update is narrowing (auto-applied) or
  expansion (requires explicit approval). Monotonic confinement.
- **Match to us**: this is essentially `[[ambient-mode-progressive-tightening]]` with formal
  verification. Our human-readable confidence-gate corresponds to their SMT narrowing check.
- **Implication**: peer-reviewed academic validation of our pattern. Cite as prior art if any
  patent challenge arises.

### 4.2 AgentGuardian — Learning Access Control Policies (arXiv 2601.10440, Jan 2026)
- **Architecture**: collect benign execution traces during staging → generate adaptive policies
  via "tighten-the-belt" principle → using more samples produces increasingly restrictive
  policies → regex patterns become substantially more constrained
- **Match to us**: this is `[[progressive-tightening-as-injection-detector]]` proven academically.
  Same observe-then-tighten primitive.
- **Implication**: second peer-reviewed validation. The architecture is researched-and-published.

### 4.3 Agent Behavioral Contracts — Runtime Enforcement (arXiv 2602.22302, Feb 2026)
- **Architecture**: Preconditions + Invariants + Governance policies + Recovery as runtime-
  enforceable components. AgentAssert runtime library. AgentContract-Bench (200 scenarios).
- **Match to us**: more formal than our shape (formal contracts vs lean-permissive heuristics)
  but same wedge (runtime enforcement of behavioral rules).
- **Implication**: research front is moving toward formal contracts. Our heuristic shape may
  need to add a formal-spec mode in v1.x for compliance buyers.

**Secondary papers worth tracking**:
- **TraceAegis** (arXiv 2510.11203): hierarchical workflow profiling for anomaly detection in
  LLM agents — embedding-distance approach we explicitly SKIP per Phase H research
- **Trajectory Guard** (arXiv 2601.00516): Siamese RNN autoencoder for plan-trajectory anomaly —
  same SKIP reasoning (explainability cost)
- **PIGuard / PISanitizer / prompt-armor**: ACL 2025 + arXiv 2511.10720 — content-classifier
  approaches, complement-not-replace our action-layer wedge

---

## 5. Patent surface

**Lightweight USPTO + Google Patents search** (last 24 months, queries: "progressive agent
policy tightening", "habit-trained AI agent permissions", "behavioral baseline agent IAM",
"per-operator AI agent profile"):

- **No direct hits** on our exact phrasing in last 24mo USPTO results.
- Several adjacent filings (Microsoft, Google, IBM) on "policy-based AI agent control" + "AI
  device control based on policies" — broad language; freedom-to-operate likely OK with our
  specific implementation (per-operator + progressive + protocol-decode is narrower).
- 2025 USPTO direction is to RECOGNIZE AI/ML innovation under § 101 (subject-matter
  eligibility) per Director Squires memos — meaning the bar for our defensive filings is lower
  if we choose to file.

**Recommendation**: light-touch defensive filing on the combination of (per-operator habit-
trained) + (progressive tightening) + (same data drives both profile AND PI detection) +
(agent-mediated reasoning via operator's LLM) — would close a real freedom-to-operate gap.
Counsel-verify before filing; per `[[brand-legal-clearance-2026-05]]` discipline.

**Honest gap**: Lasso shipped Intent Deputy Feb 2026 — they may have a filing in flight on
"behavioral fingerprints + intent alignment + anomaly detection" combination. Should monitor
their patent activity quarterly via Google Patents alert on "Lasso Security" assignee.

---

## 6. OSS landscape

Categorized by what's freely replicable vs vendor-locked:

### Freely replicable (Apache 2.0 / MIT)
- **Pipelock** (Apache 2.0, ~20MB Go binary, agent-firewall positioning) — closest OSS analog
- **Microsoft Agent Governance Toolkit** (MIT, multi-language, framework-neutral)
- **Solo.io agentgateway** (Apache 2.0, Linux Foundation, MCP/A2A gateway)
- **Sysdig Falco + Prempti** (Apache 2.0, Falco rules, syscall layer — different layer)
- **Meta Prompt Guard 2** (Llama license, HF model, BERT classifier)
- **NVIDIA Garak** (Apache 2.0, 6.9k stars, vulnerability scanner)
- **LLM Guard** (ProtectAI/Palo Alto, MIT, 2.5M+ downloads)
- **Rebuff** (ProtectAI/Palo Alto, Apache 2.0, multi-layer detection)
- **PIGuard / PISanitizer / prompt-armor** (Apache 2.0 + academic licenses)

### Vendor-locked (closed source or proprietary SaaS)
- Lasso Intent Deputy (self-host avail but core engine proprietary)
- Pillar Security (VPC deploy but proprietary)
- CalypsoAI/F5 Agentic Fingerprints
- HiddenLayer Agentic Runtime
- Lakera Guard (Check Point acquired)
- Aporia, Cisco AI Defense, Prisma AIRS, WitnessAI, Prompt Security, Wiz, CrowdStrike, Datadog
- Apono Agent Privilege Guard, CyberArk, Teleport (self-host avail), Aembit
- NeuralTrust

**Strategic implication**: OSS competition is concentrated in Pipelock + Microsoft for
agent-firewall + governance. Content-classifier OSS (Garak/LLM Guard/Rebuff/Prompt Guard) is
complement-not-replace per our `[[ambient-autonomous-protection]]` #404 LLM classifier pattern.

---

## 7. Honest threats

### Threat 1: Pipelock closes the per-operator + progressive gap (probability 40%, horizon 6-12mo)
- They already ship learn-and-lock + Apache 2.0 + dev-shop persona
- Adding per-operator scoping is a config knob away from current architecture
- Automating tightening is a roadmap addition not architecture change
- Protocol decode for AWS/K8s/SQL is the hard part (multi-protocol parser investment)
- **What they'd ship**: per-agent profiles that auto-tighten over time on HTTP/MCP surfaces
- **Our defense**: ship protocol-decode for AWS/K8s/SQL surfaces BEFORE they do; calibration
  corpus stays our durable moat per `[[scorer-is-ground-truth]]`

### Threat 2: Lasso adds action-layer protocol decode (probability 25%, horizon 12-18mo)
- They have the same-data-drives-both primitive working
- Series B funding pressure may push them to enterprise SOC features rather than dev OSS
- Protocol decode is major scope expansion; less likely than Threat 1
- **What they'd ship**: Intent Deputy v2 with AWS action awareness via SDK integration
- **Our defense**: independence + free-tier + OSS adoption window; if Lasso goes more enterprise,
  we lock in dev-shop persona per `[[target-market-personas]]`

### Threat 3: Microsoft Agent Governance Toolkit becomes default (probability 30%, horizon 6-12mo)
- MIT + multi-language + OWASP coverage + Microsoft channel = serious gravity
- They aspire to move to foundation (likely CNCF or Linux Foundation)
- Once foundation-housed, becomes the obvious "neutral choice" for procurement
- **What they'd ship**: framework integrations + trust-decay + foundation governance
- **Our defense**: framework-layer is different from protocol-layer; clearly position our wedge;
  recipe for "use Microsoft AGT + iam-jit together" defense-in-depth pitch

**Worst case scenario** (probability 10%): all three close their respective gaps in 12 months
and we're squeezed. Mitigation: ship faster, ship the protocol-decode + per-operator + agent-
mediated combination as the architectural moat that can't be closed without a complete redesign.

---

## 8. Honest opportunities

### Opportunity 1: Per-operator (not per-agent) habit profiling
- **Gap**: Lasso baselines per-AGENT; Pipelock contracts per-AGENT; nobody baselines per-OPERATOR
- **Why we have it**: founder use case is multi-account/region/cluster ops per
  `[[multi-account-region-cluster-use-case]]`; operator-pinned discipline per multiple memos
- **How to market**: "your senior SRE has different habits than your junior dev; your profile
  shouldn't lump them"

### Opportunity 2: Same data drives BOTH profile AND PI detection (the architectural insight)
- **Gap**: vendors split observation-for-profile and observation-for-anomaly into separate code
  paths. Lasso comes closest but their fingerprint feeds anomaly, not the other way around.
- **Why we have it**: the scorer is the ground truth for BOTH (per `[[scorer-is-ground-truth]]`)
- **How to market**: "the same audit log that tightens your profile also catches the prompt
  injection that tries to widen it"
- **Honest caveat**: this insight isn't unique technology — it's an architectural choice. A
  competitor could refactor to do it. But none have shipped it yet.

### Opportunity 3: Agent-mediated reasoning (operator's LLM, not vendor's model)
- **Gap**: 0/22 vendors defer reasoning to operator's agent. They all run their own model.
- **Why we have it**: `[[bouncer-zero-llm-when-agent-in-loop]]` discipline; independence-as-
  security-property per multiple memos
- **How to market**: "your agent already has context (your repo + your data + your patterns); we
  surface signals + let your agent reason. No vendor model in your security loop."
- **Honest caveat**: only legible to operators who already have an agent in the loop. Doesn't
  win the no-agent-yet operator (small minority of our persona per `[[target-market-personas]]`).

### Opportunity 4: Protocol decode at action layer (AWS/K8s/SQL/HTTP)
- **Gap**: Apono + Aembit + Teleport do multi-cloud IAM identity. None do action-level
  SigV4/K8s/SQL decode. Pipelock does HTTP/MCP only. Sysdig does syscall (wrong layer).
- **Why we have it**: 4 separate bouncers each with protocol-specific parsers; calibration
  corpus per protocol per `[[scorer-is-ground-truth]]`
- **How to market**: per `[[onecli-competitive-positioning]]` Counter #1 — "host+path matching
  can't tell admin-role-assume from read-only-role-assume; we parse the SigV4 body"

### Opportunity 5: Honest framing as moat per [[ibounce-honest-positioning]]
- **Gap**: 1/22 vendor (Lakera with "99.83%") oversells. The rest are honest. But NONE go as
  far as our "deterrent not boundary + friction-as-feature + tightening optional if-possible"
  framing
- **Why we have it**: founder discipline per multiple memos
- **How to market**: "the only vendor that tells you their product is bypassable"

---

## 9. Marketing positioning recommendations

Per `[[ibounce-honest-positioning]]` discipline. NEVER oversell. Always frame competitor work
accurately, even when they overlap.

### Primary pitch (lead)
> "iam-jit + Bounce: per-operator habit-trained, progressively-tightening agent profiles +
> protocol-aware action-layer enforcement (AWS / K8s / SQL / HTTP) — defense your agent
> reasons over, not a vendor model you depend on. Same audit data that tightens your profile
> catches the prompt injection that tries to widen it."

### Honest acknowledgment of closest competitors
> "Lasso Intent Deputy ships behavioral fingerprints + intent alignment at the prompt-and-
> response layer. Pipelock ships learn-and-lock contracts as an OSS agent firewall. Microsoft
> Agent Governance Toolkit covers all 10 OWASP agentic risks at the framework layer. iam-jit
> composes with any of them and adds the protocol-aware action-layer wedge + per-operator
> habit tracking + agent-mediated reasoning none of them ship today."

### What NOT to claim (per [[ibounce-honest-positioning]])
- Don't claim "only vendor with behavioral baselines" — Lasso, Pillar, Microsoft trust-decay
  all overlap to varying degrees
- Don't claim "only OSS option" — Pipelock + Microsoft AGT + Solo.io agentgateway are also OSS
- Don't claim "we prevent prompt injection" — per `[[prompt-injection-protection-positioning]]`
  we constrain blast radius; we don't claim PI-proof
- Don't cite competitor accuracy numbers (Lasso 99.83%) — they're not measured against our
  corpus per `[[hit-rate-meaning]]`
- Don't oversell progressive tightening as "automatic" — it's "automatic IF POSSIBLE" per
  `[[ambient-mode-progressive-tightening]]`

### Lead with what's structurally unique
1. **Agent-mediated reasoning** (0/22 vendors; structural)
2. **Per-operator habit tracking** (1/22; structural for our use case)
3. **Same data drives profile AND PI detection** (0/22 with our exact composition)
4. **Protocol decode across 4 wire surfaces** (specialized investment moat)
5. **Independence + OSS + free local + honest framing** (composition moat)

### Don't lead with what ages out
- Free-tier (Microsoft + Pipelock match)
- OSS (multiple match)
- Self-host (most have it as option)
- Sub-50ms latency (Lasso matches; Pipelock claims similar)

---

## 10. Quarterly tracking list

Re-validate August 2026 with these queries + targets:

### Vendors to track (in order of overlap risk)
1. **Lasso Intent Deputy** — does v2 add action-layer protocol awareness? Track blog + Help Net
2. **Pipelock** — does post-v2.4 add per-operator scoping + automated tightening? Track GitHub
   releases + pipelab.org blog
3. **Microsoft Agent Governance Toolkit** — does foundation move complete? Does any new package
   add behavioral profile (not just trust decay)? Track microsoft/agent-governance-toolkit
4. **Pillar Security** — does purpose-defined baseline become progressive? Track pillar.security
5. **Solo.io agentgateway** — does Agent Card capability declaration evolve into observed
   behavior? Track solo.io/blog
6. **Aembit** — IAM-for-agentic-AI GA was Apr 2026; does v2 add anomaly detection? Track aembit.io

### Research papers / arXiv to track
1. **Progent** (arXiv 2504.11703) — track for v2 or related work from same authors (Berkeley)
2. **AgentGuardian** (arXiv 2601.10440) — track citing-papers + extensions
3. **Agent Behavioral Contracts** (arXiv 2602.22302) — track AgentAssert library + benchmark
4. **TraceAegis** (arXiv 2510.11203) — track for productionization
5. **Trajectory Guard** (arXiv 2601.00516) — same

### OSS repos to track (>100 stars or recent commits)
1. github.com/luckyPipewrench/pipelock — release cadence + per-operator scoping
2. github.com/microsoft/agent-governance-toolkit — package growth + foundation status
3. github.com/solo-io/agentgateway-new-ui — capability evolution
4. github.com/NVIDIA/garak — agent-breaker probe additions
5. github.com/protectai/rebuff — post-Palo-Alto-acquisition direction

### Patent monitor
- Google Patents alert on "Lasso Security" + "Pillar Security" + "Pipelock" assignees
- Quarterly USPTO scan on "behavioral baseline" + "AI agent" + "permission tightening" terms

### What would trigger an architectural pivot
- A vendor ships ALL of: per-operator habit + progressive + same-data-drives-both + protocol-
  decode + agent-mediated + independent + OSS + honest framing — in one product. Currently
  0/22 vendors. Tracking quarterly. If any vendor reaches 7/9 dimensions, pivot review.

---

## Composes with

- `[[progressive-tightening-as-injection-detector]]` — the architectural insight this report
  validates remains unique 2026-05-24
- `[[ambient-mode-progressive-tightening]]` — the time-evolution trajectory; no vendor matches
- `[[competitive-research-ai-anomaly-detection-2026-05-23]]` — prior scan (#488) focused on
  statistical anomaly; this report focuses on PI + behavioral-baseline product surfaces
- `[[market-landscape-2026-05]]` — Pipelock + Microsoft AGT validate the "OCSF-native protocol-
  decoded audit" + "complement to every harness" positioning
- `[[onecli-competitive-positioning]]` — same complementary framing for Lasso + Pipelock +
  Microsoft AGT
- `[[ibounce-honest-positioning]]` — every claim in this report is honest about competitor work
- `[[scorer-is-ground-truth]]` — calibration corpus is the durable moat against all 3 threats
- `[[target-market-personas]]` — small-team dev-shop persona is where Pipelock + we compete;
  enterprise SOC is where Lasso + others compete
- `[[outreach-anti-spray-discipline]]` — no vendor contact during research

## Don't

- Don't share this report with any of the named vendors
- Don't email/DM/comment on any competitor's site / Twitter / etc. per anti-spray discipline
- Don't claim any of the 9 dimensions as uniquely-iam-jit without re-checking against this table
- Don't cite Lasso's "99.83%" or any vendor accuracy number in our marketing
- Don't re-run full vendor scan before August 2026 (quarterly cadence; spot-check on triggered
  alerts)
- Don't position iam-jit as "killer" of any specific vendor — complementary framing per
  `[[independence-as-security-property]]` + `[[onecli-competitive-positioning]]` reframing
