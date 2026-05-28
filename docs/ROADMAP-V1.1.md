# iam-jit v1.1 Roadmap

*Last updated 2026-05-17.*

## Deferred to v1.1 (each with a "why deferral is legitimate")

Three items are explicitly deferred from v1.0 to v1.1:

### 1. Synchronous deny-prompts (ibounce; was `iam-jit-bouncer`)

**What:** Today's `--prompt-on-deny` is async — agent gets denied
immediately; operator answers later via `bouncer prompts answer`
and the rule takes effect on the next call of the same shape.
v1.1 makes the proxy briefly poll `pending_prompts.status` so the
agent's CURRENT call can be allowed once the operator answers.

**Why deferred:** Sync requires real concurrency design (lock
contention with audit writes, pause-state polling, timeout
policy, operator-side IPC for near-real-time prompt delivery)
that needs a WB-audit pass before shipping a credential-handling
proxy with new blocking behavior. v1.0 ships the data-model + UI
that v1.1 will reuse — shipping async first is the safer
delivery sequence, not a scope cut.

### 2. HTTPS/MITM TLS handling on the proxy listener (ibounce)

**What:** The proxy listens on plain HTTP for v1.0; kubectl /
SDK clients can speak to it via `HTTPS_PROXY=http://127.0.0.1:PORT`
or `--insecure-skip-tls-verify`. v1.1 adds a real TLS listener +
MITM cert (operator-trusted local CA) so clients can speak HTTPS
to the proxy without skipping verification.

**Why deferred:** AWS-account-blocked at the time of v1.0 cut
(no real AWS endpoint to validate against without the verification
gate per `project_aws_account_verification`). Documenting +
shipping the workaround (`HTTPS_PROXY` env var) for v1.0; full
TLS listener lands when the account gate clears.

### 3. Plan-capture proxy for IaC workflows

**What:** A separate proxy mode that consumes `terraform plan`
output, scores the planned IAM changes, and writes them to the
audit log with the same shape as live request scoring. Lets the
JIT/scoring story extend to GitOps-style IaC pipelines.

**Why deferred:** Requires the same HTTPS/MITM layer as #2 to be
useful in practice (terraform `--proxy` doesn't ship with TLS-
skip-verify the way kubectl does). Scheduling-bound to #2.

### 4. TOTP CLI MFA path for solo deployment mode (#695)

**What:** Today `iam-jit serve --local` (solo deployment mode) has
no fresh-MFA fulfillment path — no OIDC/IdP loop AND no TOTP CLI
for the operator to satisfy `mfa_required_for_high_risk`. The v1.0
dogfood (#695) found the documented "self-approve up to 7" Pro-tier
flow silently caps at ~5 because every self-approve at 7+ fails
the MFA gate the operator can't satisfy. v1.0 ships a permissive
workaround: solo-mode default floor rises from 7 to 9 (env override
still wins). v1.1 adds a real TOTP CLI path so solo operators can
satisfy the gate at score 7-8 deliberately + keep the floor at 7.

**Shape:**
  - `iam-jit mfa enroll`: generate a TOTP secret + QR code, store it
    under `~/.iam-jit/mfa.totp` (Ed25519-signed, chmod 600).
  - `iam-jit mfa challenge <code>`: mint a fresh MFA cookie
    equivalent (signed timestamp) when the 6-digit TOTP code
    verifies. Cookie binds to the operator's user-id.
  - `iam-jit mfa step-up <code>`: auto-prompted by submit when a
    high-risk grant is in flight; same as challenge with a hint
    in the submit response.
  - Solo-mode default floor returns to 7 once TOTP ships.

**Why deferred:** TOTP enrollment + challenge UX is its own product
slice (storage, secret-rotation, lost-device recovery, backup codes).
The v1.0 permissive floor closes the dogfood gap without
compromising security — solo mode never had a fresh-MFA path to
begin with, so the gate at 9 is honest about what it can actually
enforce. Per [[safety-mode-lean-permissive]]: a gate that can never
satisfy itself just gets uninstalled.

## Bar for legitimate deferral

The earlier draft of this doc deferred ~5 features ("plan-capture
HTTP producer", "MFA full OAuth proxy", "scoring-feedback
persistence + export", "agent-delegated LLM scoring", "preset
library org-curated distribution") based on multi-week build
estimates and speculative demand. That deferral criterion was too
loose:

- **Bar for legitimate deferral:** the feature has been tried,
  measured, and proven to not deliver value (e.g., natural-language
  policy synthesis was measured + removed when it didn't deliver — see
  [docs/calibration/100-prompt-sufficiency-loop.md] and
  `docs/calibration/feature-reality-check.md`).
- **NOT valid deferral reasons:** multi-week build, complex admin
  UX, speculative demand, blocked on AWS account verification.
  Those are scheduling problems; they extend the launch timeline
  but don't move features off the launch list.

The only feature legitimately removed from launch scope is the
**deterministic natural-language policy generator** — measured,
failed, dropped. See `src/iam_jit/aws_managed_catalog.py`
deletion path in task #149.

## What this implies for v1.0 scope

Everything else in the open task queue is in-scope for v1.0:

- #132 Plan-capture HTTP producer (the proxy that auto-captures
  `terraform plan` / `cdk synth` / boto3 calls)
- MFA full OAuth proxy (was "Phase 3 follow-up")
- Scoring-feedback persistence (DDB-backed store) + corpus
  export pipeline (`iam-jit feedback export`)
- #115 + #116 CloudFormation onboarding (create-not-assume pattern)
- #119 Full enforcement-proxy mode
- #102 iam-jit-configures-itself
- #104 EKS template-role recipe
- #145 Plan-capture proxy read→write switch UX
- #149 NL deprecation
- #150 Preset library (full scope: personal + org-curated tiers,
  stale detection, versioning)
- #154 AdminLikeWithSensitiveExclusions baseline
- #155 Reduction UX on templates

Per [[deliberate-feature-completion]], the queue is worked
sequentially — one feature fully closed (code + tests + audit +
e2e validation + docs + marketing) before the next starts. Per
[[v1-scope-bar]], the queue doesn't get truncated to fit a
timeline; it gets worked through.

## What to put here

When a feature is genuinely *tried, measured, and found not to
deliver*, add it here with:

- One sentence: what was tried
- One paragraph: what measurement showed
- A link to the calibration / audit doc that recorded the
  decision
- (Optional) what could revive the work later — what would
  need to change for the attempt to make sense again

Anything else stays in v1.0.
