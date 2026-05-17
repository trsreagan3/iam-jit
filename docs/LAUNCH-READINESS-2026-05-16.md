# iam-jit launch readiness snapshot (2026-05-16)

*Concrete, mode-by-mode status. Read this before pilot kickoff.*

The goal of this doc is to be honest about what works, what's
half-done, and what's deferred. Per the calibration discipline
memo: shipping with known gaps clearly named is better than
shipping with hidden gaps.

## Test posture (objective)

- **2017 / 2017** passing tests outside the calibration corpus
- **89 / ~2200** calibration corpus failures — pre-existing
  scorer drift, characterized in
  `docs/security/CALIBRATION-INVESTIGATION-2026-05-16.md`,
  not regressions from this session
- 0 failures in routes_requests, routes_accounts, routes_admin,
  local_server, mfa_gate, self_approve_reductions, plan_capture,
  slack_mock, OIDC, Slack bot, auto_approve_safety_mode
- Test isolation: global env-snapshot fixture (#137 closed)

## Security posture (audit cadence)

| Round | Date | Findings | Status |
|---|---|---|---|
| Round 1-7 | (prior sessions) | mixed | all closed |
| Round 8 (Slack bot) | 2026-05 | 3 HIGH, 2 MED | closed |
| Round 9 (OIDC) | 2026-05 | 1 HIGH, 2 MED, 3 LOW | closed |
| Round 10 (safety mode) | 2026-05-15 | 1 CRIT, 3 HIGH, 1 MED | closed |
| Round 11 (session delta) | 2026-05-15 | 4 HIGH, 4 MED, 4 LOW, 4 INFO | HIGH+MED closed; INFO docs only |
| Round 12 (MFA enforcement) | 2026-05-16 | 2 CRIT, 3 HIGH, 4 MED | CRIT+HIGH+MED closed; INFO open |
| Round 13 (verify round-12) | 2026-05-16 | 1 CRIT, 2 MED, 3 LOW + verify-passes | CRIT + MEDs closed |

**The audit pattern works.** Every round has caught real
shipping bugs in code that looked done at the time. Round-12
caught 2 CRITs in MFA enforcement that would have shipped to
the pilot as "compliance-grade MFA" while actually being
bypassed. Round-13 then verified those fixes — and caught a
THIRD CRIT (self-approve flipping past the MFA gate). The
discipline of always-audit-after-fix is now memo'd as
`[[audit-cadence-discipline]]`.

## Mode-by-mode readiness

### Local mode (`iam-jit serve --local`) — READY for solo-dev pilot

**Pitched as:** "Don't give Claude your AWS keys."
**Trust model:** trust the binary on your laptop (same as
aws-cli, kubectl, gh).

- ✅ One-command setup: `pip install iam-jit && iam-jit init-solo`
- ✅ Wheel builds clean (TestPyPI dry-run #68); schemas + templates
  ship correctly post-install
- ✅ Admin bearer token minted to `~/.iam-jit/cli-token` (mode 0o600,
  atomic via O_NOFOLLOW)
- ✅ `iam-jit serve --local` refuses non-localhost binds (WB11-08)
- ✅ Canonical demo flow works end-to-end (UX agent confirmed in
  two rounds — round 1 found user_store bug, round 2 found
  validation-ordering bug, both fixed)
- ✅ MCP server stdio wiring documented
- ✅ Safety mode read_write_swap default + strict opt-in
- ✅ Read-only-default for agent grants (#110)
- ⚠️ Calibration drift: ~4% of corpus examples under-score.
  Investigation report identifies four clusters of fixable
  patterns (degenerate Conditions, wildcard edge cases, STS
  chains, missing service surfaces). Not blocking but visible
  if anyone runs the corpus tests.

**Verdict:** Ship-ready for individual devs.

### Hosted mode (Indie / Pro / Team SaaS) — READY for closed pilot

**Pitched as:** "iam-jit runs the control plane; you apply a
90-second CFN that gives iam-jit a trust role."

- ✅ FastAPI app with full route surface (requests, accounts,
  users, tokens, blacklist, score, feedback, admin, web)
- ✅ DDB-backed stores (with the WB10-01 fix: now round-trips
  safety_mode_override + llm_policy fields)
- ✅ Multi-provider OIDC SSO (Google + Okta + generic)
- ✅ Slack approval bot + signature verification + workspace pinning
- ✅ Per-customer LLM budget cap; per-account LLM policy
- ✅ Strict mode actually enforces its docstring (action wildcards,
  NotAction, admin fallback, floor-clamping)
- ✅ MFA freshness gate ENFORCED for high-risk grants (round-12
  CRITs closed)
- ✅ Self-approve reductions ENFORCED for admin solo-mode
- ✅ Audit chain records safety_mode, mode_source, MFA state,
  self-approve eligibility, floor — compliance-evidence-grade
- ⚠️ MFA enforcement is PHASE 1 (auto-approve gate only).
  Phase 2 (human-approver MFA) + Phase 3 (grant-issuance MFA)
  are deferred — would require auth-flow rework.
- ⚠️ Hosted CFN onboarding deck (#115/#116) not built yet.
  Customers can self-deploy with manual role setup until then.

**Verdict:** Ship-ready for a closed pilot. Multi-customer
SaaS launch waits on CFN onboarding ergonomics.

### Self-host mode (Enterprise) — READY pending pilot signal

**Pitched as:** "Deploy iam-jit into your own AWS account via SAM.
No phone-home; bills route directly to your account."

- ✅ SAM template + deployment guide
- ✅ All hosted features apply
- ✅ Bedrock + Anthropic + AWS billing all stay in customer
  account (per `[[self-host-zero-billing-dependency]]`)
- ✅ Compliance mapping doc (PCI / SOC 2 / HIPAA)
- ⚠️ Enterprise tier signoff process not formalized (annual
  license + support contract template not drafted)
- ⚠️ `iam-jit configures itself` feature (#102) deferred
  post-pilot — agents-via-Opus configuration discovery

**Verdict:** Technical surface ready; commercial paperwork is
the remaining gap.

## Pre-launch deferred items (NOT blocking pilot)

- #100 Calibration corpus expansion — adds new shapes; not
  needed for pilot
- #101 EKS pattern in policy_gen — DEFERRED per user direction
- #102 iam-jit configures itself — DEFERRED post-pilot
- #104 EKS template-role recipe — DEFERRED
- #105 broad_with_denylist intent — DEFERRED
- #106 Terraform-state recipe — DEFERRED
- #119 Full enforcement-proxy mode — POST-LAUNCH
- #132 Plan-mode capture HTTP producer — DEFERRED until pilot
  signal (#118 format + reader shipped; producer waits)

## External blockers

- **#64 Route 53 / iam-risk-score.com** — blocked on AWS
  account verification (not iam-jit's fault; one open support
  ticket per `[[aws-account-verification-gate]]`)
- **TestPyPI upload** — token not provided; dry-run validated
  the artifacts (#68)
- **GitHub Action marketplace submission** — Option B (separate
  repo) recommended in `docs/launch-posts/GITHUB-ACTION-
  MARKETPLACE-CHECKLIST.md`; submission needs your one-time
  click

## Pre-launch marketing (PAUSED per user direction)

Per "make sure all technical work is ready/tested/complete
thoroughly before we start the marketing stuff":

- #83 Comic strips (scripts 01 + 02 drafted; remaining 02
  + final art pending)
- iam-jit.com landing page ✅ shipped
- "Don't give Claude your AWS keys" launch post ✅ drafted

## Recommended ship order

1. **TODAY**: review the round-12 + round-13 audit reports;
   confirm CRIT/HIGH closures are acceptable
2. **+1 day**: TestPyPI upload (needs token) + verify install
   end-to-end one more time
3. **+2 days**: submit GitHub Action to marketplace (Option B
   in the checklist)
4. **+2-3 days**: first-pilot kickoff using local mode + canonical
   recipe (`docs/recipes/IAM-JIT-FOR-ADMIN-SAFETY.md`)
5. **+1 week**: real PyPI release (after pilot installs cleanly)
6. **+1-2 weeks**: comic strips + launch posts + ProductHunt /
   HackerNews announcement
7. **+2-4 weeks**: post-pilot retro → calibration corpus fixes
   (#99/#100) + Phase 2 MFA + hosted CFN onboarding

## Snapshot summary

- Tests green outside the documented calibration drift
- All audit CRITs + HIGHs closed through round 12
- Local mode pilot-ready
- Hosted mode pilot-ready for one customer; multi-tenant launch
  needs CFN ergonomics
- Marketing on hold pending pilot signal

**You can ship the first pilot in local mode right now.**
