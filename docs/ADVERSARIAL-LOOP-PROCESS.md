# The adversarial-loop process — how we keep the scorer accurate

This is the standing playbook for keeping the deterministic scorer
calibrated as AWS evolves. It's both a "how the scoring got this
good" archaeology and a "how to do it again next quarter" runbook.

The process is the product moat. If you stop running it, the scorer
gets stale; competitors who run it will overtake you. If you keep
running it, the public corpus + visible discipline + calibration
agreement number remain defensible against any new entrant (even
AWS).

## The big picture

```
                ┌────────────────────────────┐
                │  IAM-BYPASS-RESEARCH.md    │  ← living attack pattern library
                │  (197+ documented patterns) │     (grows when AWS ships, when
                └──────────┬─────────────────┘       researchers publish, when
                           │                          incidents are disclosed)
                           ↓
              ┌────────────┴─────────────┐
              │                          │
              ↓                          ↓
   ┌──────────────────┐          ┌──────────────────┐
   │ Corpus           │          │ Adversarial      │
   │ enumeration agent│          │ agents (BB + WB) │
   │ — one YAML per   │          │ — find net-new   │
   │ documented       │          │ patterns the     │
   │ pattern          │          │ research doc     │
   │                  │          │ doesn't cover    │
   └──────┬───────────┘          └────────┬─────────┘
          │                               │
          ↓                               ↓
   tests/calibration_corpus/research_patterns/
   tests/calibration_corpus/agent_discovered/
                       │
                       ↓
              ┌────────────────┐
              │ Scorer runs    │
              │ every YAML;    │
              │ gap report     │
              └────────┬───────┘
                       │
                       ↓
              ┌────────────────┐
              │ Close gaps in  │
              │ batches; commit│
              │ + push         │
              └────────┬───────┘
                       │
                       ↓
              ┌────────────────┐
              │ Round-stats    │
              │ shows trend    │
              └────────────────┘
```

Three roles to run in parallel:

1. **Research-corpus enumerator** (heavy, one-shot per quarter). Reads
   `IAM-BYPASS-RESEARCH.md`. Writes one YAML per documented pattern
   into `tests/calibration_corpus/research_patterns/`. Run when:
   - The research doc gains 20+ new patterns (AWS service launches,
     security disclosures).
   - You suspect calibration drift but haven't run a recent pass.
   - Before any public claim about coverage percentage.

2. **Black-box adversarial agent** (running weekly during active
   maintenance, monthly in steady state). NO source access. Probes the
   API behaviorally — tries weird policies, observes scores. Best for
   finding patterns the research doc doesn't yet document.

3. **White-box adversarial agent** (same cadence). Source access.
   Reads the scoring rules. Finds source-code-level gaps: predicates
   that fire too narrowly, normalization edges, missing action-set
   entries the BB agent can't deduce from behavior alone.

## The cadence

| Trigger | Action |
|---|---|
| AWS adds 5+ new services (re:Invent, mid-year launches) | Update IAM-BYPASS-RESEARCH.md → run enumerator → close findings |
| Security firm publishes new attack research (Bishop Fox, Rhino, Wiz, etc.) | Add patterns to IAM-BYPASS-RESEARCH.md → run enumerator |
| Major IAM incident disclosed (Capital One-tier) | Add to §5 (real incidents) → run enumerator |
| Monthly steady-state | Spawn 1 BB + 1 WB round; close findings |
| Customer reports a real-world bypass | Encode their policy as a YAML; close at source |
| Quarterly | Full pass — enumerator + BB + WB; publish convergence report |

## How to spawn a round (the actual commands)

### Black-box

Use the Agent tool with this prompt template:

```
You are an adversarial security researcher attacking the iam-risk-score
deterministic policy scorer. Round N — BLACK-BOX (no source access).

REPO: <repo>/

PRIOR-ART CONTEXT: [paste current closure state, mention recent
closures so the agent doesn't rediscover them]

YOUR JOB: Find patterns the scorer underrates. Categories to probe:
[list specific surface areas — newer services, novel compositions,
condition operators not yet covered, etc.]

OUTPUT: YAMLs to `tests/calibration_corpus/agent_discovered/`
numbered agent-NNN+ (use the next free 100-block).
Each YAML cites the research-doc pattern OR the source if it's novel.

When done, append to FINDINGS.txt: "## Round N — Black-box".

Budget: 45 min tool use.
```

### White-box

Same prompt structure but with:
- "WHITE-BOX (full source code access)"
- Require reading `src/iam_jit/review.py`
- Require reading the FINDINGS.txt history
- Each YAML cites the source-code rule it exploits + proposed fix sketch

## Closure methodology

After agents land:

1. **Get the failure surface:**
   ```sh
   cd ~/repos/iam-roles
   .venv/bin/python -m pytest tests/test_calibration_corpus.py --tb=no -q | grep FAILED
   ```

2. **Triage by gap severity:**
   ```sh
   .venv/bin/python scripts/round-stats.py
   ```
   - `max_gap = 0`: round is fully closed, no action.
   - `max_gap ≤ 2`: calibration drift, defer unless trend.
   - `max_gap ≥ 3`: architectural finding, fix at source.
   - `gap = ∞` (CRASH): drop everything, fix immediately.

3. **Batch fixes by attack class.** Don't fix one YAML at a time —
   group findings into:
   - Architectural (new helper function or rule)
   - Action-set additions (one or many actions added to existing set)
   - Service-alias additions
   - Calibration nudges (only when several findings agree on direction)

4. **Commit per batch.** One commit message per attack class. The
   commit log becomes the audit trail of the discipline.

5. **Regenerate AWS-managed corpus when action sets change:**
   ```sh
   .venv/bin/python scripts/fetch-aws-managed-policies.py --no-fetch
   ```
   This updates expected-score bands on AWS-managed policies whose
   risk profile shifted due to new action-set membership.

6. **Push every batch.** Visibility of the discipline matters as
   much as the discipline itself.

## Lesson from rounds 1-3 (May 2026 application-security cycle)

Three rounds of BB+WB on the SaaS plumbing (not the scorer)
converged on one recurring theme:

> **"Fix where named. Miss the siblings."**

The auditor surfaces a finding tied to a specific
`file:line`. Closures that only patch that location keep working
copies of the same bug at sibling call sites. Examples from the
cycle:

- Round 1 closed XFF-leftmost in `routes/score._client_ip`. Round
  3 found the exact same bug in `routes/web._login_client_id` —
  unrelated route, identical shape.
- Round 2 closed Stripe `has_processed`/`mark_processed` TOCTOU
  with atomic `claim()`. Round 3 found the new claim-then-process
  ordering let a handler crash permanently strand the customer's
  event_id.
- Round 1 closed CSRF on web HTML routes via Origin/Referer
  middleware. Round 3 found cookie-only token-mint (POST /tokens)
  still accepted cross-origin Origin/Referer because the route
  bypasses the CSRF middleware path.

**Implications for new closures:**

1. **When you close a finding, grep for the failure shape.** Not
   the exact code — the shape. Pattern: "anywhere we read XFF →
   does it gate on trusted-proxy CIDRs?" "Anywhere we mint tokens
   → does it check the cap?" "Anywhere we set a session cookie
   → is SameSite=Strict?"

2. **Prefer one shared helper to N inlined copies.** The
   `iam_jit.trusted_proxy` module exists because rounds 1+2
   produced four slightly-different XFF parsers, one of which
   silently failed on multi-line env vars. The shared helper +
   single test suite makes "fix once, fix everywhere" mechanical.

3. **The audit doc IS load-bearing.** The auditor agent's job is
   to find shape-classes. Each round's finding list is the
   canonical inventory of which-shape-bug-where. Treat it as a
   regression-prevention surface, not a one-off list.

## The convergence criterion

The loop has converged for a round when:
- `max_gap ≤ 2` across both BB and WB halves.
- The round's findings (if any) are esoteric edge cases (specific
  AWS service we forgot to support, weird Unicode normalization
  edge) rather than common attack vectors.

Once two consecutive rounds hit this signal, the loop is in
maintenance mode — run monthly, expect zero-or-tiny new findings.

The convergence criterion is NOT "raw count drops." Each new round
finds new things if AWS keeps adding services. Track `max_gap` as
the convergence indicator, not finding count.

## What to do when AWS announces new services (re:Invent, mid-year)

1. **Read the launch announcements.** Pay attention to:
   - New IAM action names (look for new service prefixes)
   - New resource types
   - New condition keys
   - Trust-policy implications (Service principals)
2. **Update `IAM-BYPASS-RESEARCH.md` §9** with the new surface.
   Each new service gets a sub-entry with: actions added, attack
   primitive (privesc / exfil / persistence / RCE), severity.
3. **Run the enumerator** to write fixtures for the new patterns.
4. **Close the architectural gaps** — usually action-set additions
   to one of the 5 sets.
5. **Update `_SERVICE_ALIASES`** if the new service has multiple
   IAM prefixes (Bedrock split into bedrock / bedrock-runtime /
   bedrock-agent etc.).

## When a customer reports a real bypass

This is the highest-priority signal. Process:
1. **Reproduce.** Encode their reported policy as a YAML in
   `tests/calibration_corpus/customer_reports/` (create the dir if
   missing). Don't put it in `agent_discovered/` — provenance matters
   for the public corpus.
2. **Confirm it bypasses.** Run through `analyze_policy()`. If the
   reported bypass doesn't repro, work with the customer to find the
   exact case.
3. **Categorize.** Architectural (new rule needed) vs Action-set
   omission (action missing from set) vs Calibration (we knew but
   under-scored).
4. **Fix at source.** Same batch-commit-push process.
5. **Notify the reporter.** Send them the commit URL. This is
   community-building — security reporters who feel heard come back
   with more findings.
6. **Public credit.** If they consent, add their name to a
   `SECURITY-HALL-OF-FAME.md`. Free marketing for them, free trust
   for us.

## The "we shipped real safety" claim

The marketable artifact is the **calibration-confidence number**:

> Our deterministic scorer matches Opus-4.7 within ±1 risk score on
> 1,500+ AWS-managed policies and 217 documented attack patterns.
> [Number]% closure rate across 9+ rounds of adversarial testing.
> Public corpus, public methodology, public commit history.

Update this number after every quarterly pass. Publish it in:
- README header
- the landing site (`landing-site/`) — the v1.0 marketing surface;
  hosted `docs.iam-risk-score.com` was dropped per [[no-hosted-saas]]
  (2026-05-24)
- Blog post per quarter ("Quarterly calibration report")
- Sales materials

This number is what no competitor can match without running the same
discipline — and most competitors structurally can't (closed-source
or unwilling to expose their methodology).

## When to retire patterns

Some patterns become obsolete (deprecated AWS services, fixed
upstream AWS-side, etc.). Don't delete them — the regression-
protection value is high. Add a comment explaining the obsolescence
and keep the test pinned.

## Related processes

- **Policy-generation adversarial loop** — same methodology but
  applied to the generator (does `iam-jit agent-grant` produce the
  right policy for a task description?). See `tests/test_policy_gen/
  ADVERSARIAL-FINDINGS.md` for current state.
- **AWS-managed-corpus regression** — every action-set change must
  regenerate `tests/calibration_corpus/aws_managed/` bands. The
  `fetch-aws-managed-policies.py --no-fetch` script handles this.

## Single most important rule

**Never lower the deterministic floor in response to a finding.** The
scorer's job is to over-flag. If a finding says "you scored too high,"
that's not a bug — that's the floor doing its job. The auto-approval
threshold is the customer-side knob; the floor is the safety contract.

Bumping the floor up = improvement. Lowering it = silent regression
that won't show up until a real attack succeeds.

---

Last updated 2026-05-13. Maintained as part of the scoring-engine
discipline. Edits welcome via PR.
