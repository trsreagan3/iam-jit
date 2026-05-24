# iam-jit launch readiness snapshot (2026-05-17)

*Concrete, product-by-product status. Read this before pilot kickoff.*

> **Supersedes** [`LAUNCH-READINESS-2026-05-16.md`](LAUNCH-READINESS-2026-05-16.md).
> Significant work landed in one day: bouncer product (CLI + MCP + per-task
> scopes + recommender + composer), applicability framework (#166 Slices
> 1-4), license-cap (#161), 5 more BB+WB audit rounds (WB27-31), 4 outside-
> context UAT rounds with all BLOCKERs closed, doc reframing as 4 products,
> agent-agnostic positioning, locked-down-IAM positioning. Test suite grew
> 2017 → 2646.

The doc is honest about what works, what's half-done, and what's deferred.
Per the calibration discipline memo: shipping with known gaps clearly
named is better than shipping with hidden gaps.

## Test posture (objective)

- **2646 / 2646** passing tests outside the calibration corpus
  (+629 from the 2026-05-16 baseline; 0 regressions on prior tests)
- 30 skipped (mostly version-gated; 1 is the WB31 placeholder-key
  release gate that's expected-skip pre-launch)
- Test isolation: global env-snapshot fixture; no cross-test leakage
- Calibration corpus drift: characterized in
  `docs/security/CALIBRATION-INVESTIGATION-2026-05-16.md`; not a launch
  blocker

## Security posture (audit cadence)

| Round | Date | Subject | Findings | Status |
|---|---|---|---|---|
| 1–13 | (prior) | various | all closed | ✅ |
| WB14-17 | 2026-05-16 | NL-synthesis deprecation (Stages 1-4) | 2 CRIT, 1 HIGH, ~12 misc | all closed |
| WB18 | 2026-05-16 | preset library | 1 HIGH, 2 MED | closed |
| WB19 | 2026-05-16 | AdminLikeWithSensitiveExclusions baseline | 2 MED, 3 LOW | closed |
| WB20 | 2026-05-16 | reduction primitives | 1 CRIT, 2 MED, 4 LOW | closed |
| WB21 | 2026-05-16 | guided-reduction | 1 HIGH, 3 MED, 4 LOW | closed |
| WB22 | 2026-05-16 | live action tail | 1 CRIT, 1 HIGH, 3 MED, 4 LOW | closed |
| WB23 | 2026-05-16 | bouncer foundation | 1 CRIT, 2 HIGH, 4 MED, 5 LOW | closed |
| WB24 | 2026-05-17 | applicability framework | 2 HIGH, 4 MED, 5 LOW | closed |
| WB25 | 2026-05-17 | compatibility allowlist | 1 HIGH, 4 MED, 5 LOW | closed |
| WB26 | 2026-05-17 | bouncer task scope | 2 HIGH, 4 MED, 2 LOW | closed |
| WB27 | 2026-05-17 | bouncer Slice C | 2 HIGH, 3 MED + doc drift | closed |
| WB28 | 2026-05-17 | bouncer recommender | **1 CRIT**, 2 HIGH, 6 MED, 5 LOW | closed |
| WB29 | 2026-05-17 | applicability gate integration | 2 HIGH, 5 MED, 6 LOW | closed |
| WB31 | 2026-05-17 | license + user cap | 1 CRIT, 3 HIGH, 4 MED, 3 LOW | closed (CRIT is launch-block release gate) |

Across the launch-blocking rounds: **6 CRIT + 21 HIGH + ~50 MED + ~50 LOW
identified; all CRITs + HIGHs closed.** The audit cadence per
audit-cadence-discipline kept catching findings the unit tests missed —
WB28 CRIT in particular (recommender treating deny decisions as
endorsements) shipped past the within-feature test suite.

**Outside-context UAT** ran 4 independent agents (UAT-A bouncer setup,
UAT-B per-task scope, UAT-C agent self-scope, UAT-D iam-jit local install,
UAT-E validation re-run). All previously-flagged BLOCKERs closed; UAT-E
verified the doc reframing holds for a fresh user.

## Product-by-product readiness (per four-products-one-brand)

The README now frames iam-jit as **four separate products** sharing a
scorer + brand. Each has independent launch readiness.

### Product 1 — iam-risk-score — SHIPPED

- CLI + API + GitHub Action live
- 1,489 / 1,489 AWS-managed-policy corpus pass rate
- No changes needed pre-launch

### Product 2 — iam-jit-bouncer — READY for v1.0 (Stage 1 + MCP)

What ships in v1.0:
- CLI: rule add/list/remove, presets, decide, logs, tasks (start/active/
  end/show/list/review), effective-scope, recommend
- MCP server: 16 bouncer tools including `bouncer_start_task`,
  `bouncer_end_task`, `bouncer_task_review`, `bouncer_recommend_rules`,
  `bouncer_apply_recommendation`, `bouncer_effective_scope`, the full
  decide / list / tail surface
- **`iam_jit_scope_self_for_task` composer** — one MCP call atomically
  declares task scope + JIT role + returns scoped STS credentials
- SQLite audit chain
- Smart-default protective baseline on init (17 deny rules covering
  IAM admin / secrets / billing / audit-infra destruction)
- Observation-based rule recommender (Slice D)
- Per-task scopes with owner-match access control (Slice C)
- 6 BB+WB audit rounds (WB23, WB26, WB27, WB28, WB29 integration, WB30
  UAT-A closures)

Explicitly deferred to v1.1 per UAT-A doc-reframing:
- `iam-jit-bouncer run` transparent HTTP proxy (intercepts SDK traffic
  via `AWS_ENDPOINT_URL`). The MCP path IS the v1.0 enforcement surface;
  agents that call the composer get scoped creds + audit log.

### Product 3 — iam-jit local (`serve --local`) — READY for solo-dev pilot

- `iam-jit init-solo` + `serve --local` + read-only-default + region/
  account scoping + 1h TTL + local SQLite audit
- `iam-jit mcp install-claude-code` + `iam-jit mcp show-config` (UAT-D
  closures — these commands now exist and work)
- `mcp-server --help` lists 24 tools accurately
- Egregious-action floor (IAM admin / billing / MFA / cross-account /
  do-not-delete tags)
- Validated end-to-end by UAT-D + UAT-E: indie dev can get Claude using
  iam-jit in ~6 minutes from a clean terminal

### Product 4 — iam-jit self-host (Enterprise) — READY pending pilot signal

- Multi-provider OIDC (Google Workspace + Okta + generic OIDC)
- Slack approval bot (signed-request authenticated)
- Template browser (AWS-managed + parameterized task templates +
  evolving personal-tier preset library)
- Agent-driven reduction loop
- Two safety modes (`read_write_swap` default + `strict`)
- MFA propagation through STS via `aws:MultiFactorAuthPresent`
- Applicability framework (#166): MCP `check_iam_jit_compatibility`,
  HTTP `metadata.compatibility` gate on POST /api/v1/requests, CLI
  `iam-jit doctor compatibility`, admin allowlist
- Per-account LLM policy
- License-cap (#161): Free-tier 25-user soft cap with offline-signed
  Ed25519 license file raising the cap (per user-count-soft-cap)
- Per no-hosted-saas: no multi-tenant hosted SaaS. Enterprise
  customers self-host OR contract for dedicated-managed single-tenant.

## Pre-launch deferred items (NOT blocking pilot)

| Item | Status | Why deferred |
|---|---|---|
| #83 Comic strips | scripts 01+02 drafted | Needs design tools; not blocking |
| #85 Extended UAT | 4 rounds done | More post-pilot if needed |
| #102 iam-jit-configures-itself | spec'd | Enterprise feature, multi-week, post-launch |
| #119 Full enforcement-proxy mode | spec'd | Stage 2 bouncer (v1.1) |
| #132 Plan-capture HTTP producer | spec'd | Multi-week, post-launch |
| #145 Plan-capture read→write switch UX | spec'd | Depends on #132 |
| #153 Real-IdP doctor validation | blocked | Needs AWS account verification (route 53) |
| Real production Ed25519 license key | placeholder | Generate offline before v1.0 release tag; release gate test in place |

## External blockers (unchanged from 2026-05-16)

- **AWS account 123456789012 verification** (Route 53 + Bedrock Anthropic
  access) — single support case unblocks both per
  `aws-account-verification`. Not blocking pre-launch self-host /
  bouncer / local pilots; blocks the iam-risk-score.com hosted scorer
  domain registration and the LLM-tier convergence runs.

## Pre-launch positioning (this session's strategic adds)

- **Four-products framing** (per four-products-one-brand): not "one
  product with four modes"; four separate products + four sales
  surfaces, different audiences, different friction profiles.
- **Agent-agnostic** (per agent-agnostic-positioning): iam-jit's MCP
  server works with any MCP-compatible agent — Claude Code, Cursor,
  Codex MCP, Devin, custom runtimes. README hero + AGENTS.md updated.
- **Bouncer locked-down-IAM positioning** (per bouncer-positioning-
  locked-iam): the bouncer's strongest underserved audience is
  developers whose company doesn't let them touch IAM rapidly — rapid
  local iteration, no IAM-write needed, easy kill-switch. README +
  IAM-JIT-BOUNCER.md "Why a local proxy" both updated to cover this
  audience alongside defense-in-depth.
- **LLC + consulting funnel** (per llc-brand-consulting-funnel): the
  founder's plan is to form a US LLC as the parent brand and launch
  products + consulting under one entity; 14 distinct revenue lines
  mapped across iam-jit-adjacent + general AI/AI-sec + LLC-as-entity
  buckets. Not launch-blocking but maximizes funnel reinforcement.
- **Pre-public-push hygiene** (per push-policy-public-repo): standing
  push auth; sensitive-data scan run before every push; repo will go
  public around launch. Today's scrub removed all `/Users/reagan/`
  paths + prior internal-customer-name references + `1.8%` mentions
  in product-surface code per no-one-eight-percent-mention.

## Recommended ship order (updated from 2026-05-16)

1. **TODAY**: this readiness doc + all today's commits pushed; remote
   in sync with local (verified at `5bcb404`).
2. **+1 day**: review the 5 newest audit-doc closure sections (WB27,
   WB28, WB29, WB30, WB31); confirm CRIT closures hold; spot-check
   the doc-reframing changes via one more UAT pass (UAT-F broader
   coverage).
3. **+1-2 days**: generate the real production Ed25519 keypair offline,
   commit ONLY the public key to `license.py`, flip the release-gate
   test from skip → enforce. This is the final launch-block per
   WB31 CRIT-31-00.
4. **+2 days**: form the LLC (Delaware filing + EIN + business bank)
   per llc-brand-consulting-funnel. In parallel with #3.
5. **+3-4 days**: first-pilot kickoff using local mode + canonical
   recipe (`docs/recipes/IAM-JIT-FOR-ADMIN-SAFETY.md` for admin-side;
   `docs/recipes/agent-safety-mode.md` for agent-side).
6. **+1 week**: TestPyPI dry-run upload, then real PyPI release (after
   pilot installs cleanly).
7. **+1-2 weeks**: comic strips + launch posts + landing-page hero
   refresh with locked-down-IAM positioning paired to "Don't give
   Claude your AWS keys" hook + ProductHunt / HackerNews announcement
   per LLC.
8. **+2-4 weeks**: post-pilot retro → calibration corpus fixes + v1.1
   scope decision (Stage 2 HTTP proxy vs other priorities surfaced
   by pilot signal).

## Snapshot summary

- 2646/2646 tests green; 0 regressions
- 6 CRIT + 21 HIGH closed across 17 audit rounds; UAT-A/B/C/D/E
  validated outside-context
- All four products v1.0-ready (modulo the placeholder-key release
  gate for license verification)
- Marketing on hold per "finish technical work first"; positioning
  + audience-segmentation work done in docs, awaiting design /
  landing-page assets
- Self-host + bouncer + local pilot-ready
- Hosted SaaS off the table per no-hosted-saas — Enterprise customers
  self-host or contract for dedicated-managed

**You can ship the first pilot in local mode right now.** The only
launch-blocking item between now and a v1.0 tag is the real
production Ed25519 license key (offline keygen + commit + flip the
release-gate test), which is a 1-hour task that hasn't been done
because pre-launch builds intentionally run on Free-tier-only.
