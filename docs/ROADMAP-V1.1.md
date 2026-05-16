# iam-jit v1.1 Roadmap

*Last updated 2026-05-16.*

This document captures work intentionally **deferred from v1.0** so launch comms stay aligned with what ships. Each entry: what v1.0 ships, what v1.1 adds, why deferral is honest, and acceptance criteria.

---

## 1. Plan-capture HTTP producer (proxy)

**v1.0 ships:** The plan-capture **reader** (`iam_jit.plan_capture`). Consumes JSONL capture files conforming to the v1alpha1 spec (`docs/specs/PLAN-CAPTURE-FORMAT.md`). `iam-jit synth-policy-from-capture <file>` emits a synthesized policy + risk score. Accepts hand-authored or externally-produced captures.

**v1.0 does NOT ship:** The producer. There is no proxy that intercepts `terraform plan` / `cdk synth` / `cfn-lint` calls automatically. The spec describes the producer as future work.

**v1.1 acceptance criteria:**
- `iam-jit plan-capture serve` runs a local SigV4-speaking HTTP endpoint on a configurable port.
- `AWS_ENDPOINT_URL=http://127.0.0.1:<port>` makes `terraform plan` / `cdk synth` / boto3 emit calls through it.
- Each call is recorded to a configurable JSONL file conforming to the v1alpha1 spec.
- Privacy / safety constraints from the spec (scrub `request.SecretString`, etc.) enforced at producer-write time.
- Tested against a real `terraform plan` of a non-trivial module (e.g., AWS provider sample) — capture file consumes cleanly with the v1.0 reader.

**Why deferred:** The producer is a multi-week build (SigV4 termination, request shape parsing for every AWS service, scrubbing safety, integration tests against real terraform). Shipping the reader first means external pipelines + hand-authored test fixtures can use the capture format today; the proxy is additive when it lands.

**Tracking:** task #132 + #119.

---

## 2. MFA step-up: full OAuth proxy

**v1.0 ships:** `post_mfa_step_up_nudge()` — when the MFA gate blocks a request (e.g., elevated grant requires fresh MFA), iam-jit sends a Slack DM to the user prompting them to re-authenticate manually against their IdP. The user re-auths, iam-jit accepts a new bearer token, the gate clears. Human-in-the-loop.

**v1.0 does NOT ship:** A full OAuth proxy where iam-jit-hosted handles the re-auth dance directly (mid-session token refresh without prompting the user). The task #143 title said "OAuth proxy" — that label was aspirational; what shipped is the nudge variant.

**v1.1 acceptance criteria:**
- iam-jit-hosted brokers a fresh `acr=urn:mace:incommon:iap:bronze` or equivalent step-up auth against the IdP without bouncing the user through manual UI.
- Works with Google Workspace + Okta (the two IdPs OIDC SSO targets).
- Step-up duration ≤ 10 seconds in the happy path.
- CloudTrail / audit log records the step-up as a distinct event (different from initial auth).
- Existing nudge path still available as a fallback / for IdPs that don't support programmatic step-up.

**Why deferred:** Building this correctly requires real-world IdP testing (Google + Okta) which is blocked on AWS account verification (per [[aws-account-verification]] memo) anyway. The nudge variant covers the same compliance surface area for v1.0 (PCI §8.6 step-up MFA is satisfied by either path) — the proxy variant is a UX improvement.

**Tracking:** task #143 (rename pending) + new ticket TBD.

---

## 3. Scoring-feedback persistence + corpus export

**v1.0 ships:** Submit endpoint (`POST /api/v1/feedback/score`), admin-review UI, per-user + global rate limits. Users can flag low-confidence scores; admins can review the queue.

**v1.0 does NOT ship:** Persistent storage in hosted mode (only `InMemoryFeedbackStore` exists — Lambda restart loses all collected feedback). The promised export path to `tests/calibration_corpus/community/` is unimplemented — the directory doesn't exist.

**v1.1 acceptance criteria:**
- DynamoDB-backed `FeedbackStore` for hosted mode; SQLite-backed for self-host. Survives restart.
- `iam-jit feedback export` command writes accepted feedback entries to a directory matching the calibration-corpus YAML format.
- Acceptance pipeline: admin reviews flagged feedback → marks `accept-as-corpus-entry` → entry exported to community corpus → next calibration run picks it up.
- Privacy: customer policies in feedback are scrubbed of account IDs / ARNs / customer-identifying names before corpus export (manual review gate, not automatic).
- The full "user flags bad score → ends up in the calibration corpus" loop tested end-to-end with at least one round-trip.

**Why deferred:** The submission infrastructure was the substantive build; the persistence + export pieces are straightforward but require careful privacy review before flagged customer policies enter a public corpus. Better to ship the submission UI and iterate on the export pipeline than to ship the loop half-broken.

**Tracking:** task #81 (rename pending) + new tickets TBD.

---

## 4. (Possible) LLM-narrowed policy generation as Pro+ tier

**v1.0 ships:** Three honest paths to a policy — browse the AWS-managed catalog, submit raw JSON, or have an IDE agent draft it with codebase context. iam-jit scores and gates, but does **not** synthesize policies from natural-language prompts. See [[no-nl-synthesis]] for the decision and [[evolving-preset-library]] for the longer-term shape.

**v1.0 does NOT ship:** An iam-jit-hosted LLM tier that takes natural-language requests and produces narrowed policies for users without an IDE agent. Per [[agent-context-primacy]] the user's local agent is usually a better author than a server-side LLM (because the agent has codebase context iam-jit doesn't); a hosted LLM tier is a convenience for agentless users, not a strategic pillar.

**v1.1 acceptance criteria (if pursued):**
- Pro tier subscription includes `iam-jit generate-llm <prompt>` that calls Bedrock (or customer-supplied Anthropic key) and produces a narrowed policy.
- The LLM output goes through the SAME scorer as every other policy. The LLM does not influence the scorer.
- Per-customer budget cap (existing, task #82) applies.
- Calibration loop measures joint sufficiency rate — must beat the deterministic 1.8% baseline by ≥10x before declaring shipped.

**Why deferred:** Open question whether the agentless-user segment is large enough to justify the build. Most early adopters will have Claude Code / Cursor / similar. Better to launch + observe demand than to build speculatively.

**Tracking:** No ticket yet; revisit post-launch if customer asks justify it.

---

## 5. Evolving preset library — org tier + later steps

**v1.0 ships (pre-launch slice of [[evolving-preset-library]]):** `save_as_template` on approved grants (per-user); similarity matcher for "did you mean..." on new requests; auto-suggest "save as recurring template?" after N reuses.

**v1.0 does NOT ship:** Admin-curated org-tier templates; stale-template detection; versioning + lineage tracking.

**v1.1 acceptance criteria:**
- Admin can promote a personal-tier template to org-tier (org tier visible to all users in the customer org).
- Per-customer storage only; no cross-customer learning (composes with [[recommender-context-boundary]]).
- Stale-template detection: ARNs that no longer resolve get flagged; admin chooses to update or retire the template.
- Template versioning: each save creates a new version; diff against last-approved version is visible at request time.

**Why deferred:** Personal-tier captures most of the value in the per-user-flow; org-tier requires admin UX which is more complex. Ship personal-tier first, learn from usage, build admin-tier on signal.

**Tracking:** task #150 (pre-launch slice scoped to personal-tier).

---

## Cross-cutting principle

Every entry in this doc is a "feature with a missing half" that was shipped in v1.0. The pattern caught us in the 1.8% calibration finding (NL synthesis: scorer worked but generator didn't). Per [[audit-cadence-discipline]], v1.1 explicitly closes the loops rather than leaving them half-built.

**Loop-closure invariant:** before v1.1 wraps, every entry in this doc must either ship with both halves (producer + consumer, store + export, etc.) or be retired from the codebase entirely.
