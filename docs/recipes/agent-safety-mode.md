# Agent safety mode — the read-only-default contract

Recipe: when an AI agent (Claude Code, Cursor, Devin, etc.) is
about to operate against AWS through iam-jit, the safety-mode UX
defaults to **read-only**. Write operations require an explicit,
audited elevation step. This is the load-bearing contract behind
the "don't give Claude your AWS keys" pitch and the canonical
shape of [agent self-scoping via iam-jit](../AGENTS.md).

## The contract in one sentence

> **Claude can READ; WRITES require your OK.** Every JIT role
> iam-jit issues to an agent ships read-only unless the request
> explicitly opts into writes AND a human approves (or a self-
> approve gate fires for owner-narrowing reductions).

## Why this default exists

Per [[read-only-default]]: ~80% of agent operations are reads
(`Get*`, `List*`, `Describe*`, `Head*`) with near-zero blast
radius. The remaining ~20% — writes, deletes, role mutations,
infrastructure provisioning — carry essentially all the risk. A
sensible default that flips the friction onto WRITES (not reads)
makes safety-mode usable on the daily agent path without making
the agent feel handcuffed.

The default is also a **trust signal** to your security team:
when you onboard iam-jit, your agent's default posture is "looks,
doesn't touch." Auditors can see the read-only split in the audit
log without parsing every grant.

## How it composes

1. Agent calls `iam_jit_scope_self_for_task(...)` (MCP composer,
   see [docs/AGENTS.md](../AGENTS.md) §"Self-scoping flow").
2. iam-jit checks compatibility (#166 framework), declares a
   bouncer task scope, and requests a JIT role.
3. **Default access_type is `read-only`** in the policy generator;
   the role's policy ships with `Action: [Get*, List*, Describe*,
   Head*]` against the scoped ARN set.
4. The agent operates normally — reads succeed, writes are denied
   at the IAM layer with a clear "this role is read-only" error.
5. When the agent needs writes, it submits a SEPARATE grant
   request with `access_type: read-write` + `description:` of why.
   That request goes through the standard approval flow (auto-
   approve if it's low-risk, human review if not).
6. The audit log shows two distinct grants: the read-only baseline
   + the explicit write grant. Auditors get a clean trail.

## Safety modes that affect this

Two safety modes control how strict the gate is (see
[[safety-mode-two-modes]] memory + `docs/recipes/IAM-JIT-FOR-ADMIN-
SAFETY.md`):

- **`read_write_swap`** (default): lean-permissive. Reads ship
  immediately; writes require a separate grant. Admin-fallback
  scopes (region/account narrowing) always allowed.
- **`strict`**: maximalist. Narrow ARNs only, per-operation
  prompts for writes, no admin-fallback escape hatches.

Configure per-deployment via `IAM_JIT_SAFETY_MODE` env var or
per-account in the accounts store.

## What "uncircumventable" means here (and what it doesn't)

The read-only default is enforced at the IAM-policy layer (the
issued role itself has no write actions in its policy document).
This means writes are denied by AWS — there's nothing iam-jit-the-
bouncer needs to do; the AWS API itself rejects the call.

What read-only does NOT defend against in v1.0:
- An agent that already had write credentials BEFORE calling iam-
  jit. The composer issues a NEW scoped principal; it doesn't
  revoke existing access. The agent has to actually use the iam-
  jit-issued role for the read-only default to bind.
- An agent that explicitly requests `read-write` from the start
  and the request auto-approves. Auto-approve thresholds + risk
  scoring catch the dangerous ones; lower-risk write grants get
  through without human review by design.

The v1.1 HTTP proxy (`iam-jit-bouncer run`, see
[docs/IAM-JIT-BOUNCER.md](../IAM-JIT-BOUNCER.md) §"Stage 2") closes
the first gap by intercepting the agent's pre-existing credentials
at the network layer.

## CLI / MCP surface

Read-only default behavior is automatic — no flag to set. To
explicitly request writes from an agent:

```python
# MCP path (agent calling submit_policy directly)
submit_policy(
    workload="agent_local_dev",
    description="Upload report to s3://reports/q1/ for analyst review",
    access_type="read-write",   # <-- explicit opt-in
    policy={...},               # narrow to specific resource
)
```

```bash
# Human-driven CLI path (review a write request before submission)
iam-jit review \
    --description "Upload q1 report to S3" \
    --access-type read-write \
    --policy /tmp/draft-policy.json
```

When the read-only default fires and a write is needed, the agent
should:
1. Pause and tell the user "I need write access to X for Y."
2. Submit the separate write grant.
3. Wait for approval (or auto-approve if the gate passes).
4. Proceed with the write.

## Related

- [[read-only-default]] — the founding decision memo
- [[agent-safety-adoption-play]] — bottoms-up adoption channel
- [[safety-mode-two-modes]] — strict vs lean-permissive modes
- [docs/AGENTS.md](../AGENTS.md) — full agent self-scope flow
- [docs/recipes/IAM-JIT-FOR-ADMIN-SAFETY.md](IAM-JIT-FOR-ADMIN-SAFETY.md) —
  admin-side safety-mode recipe
- [docs/IAM-JIT-BOUNCER.md](../IAM-JIT-BOUNCER.md) — the local
  AWS-call gating proxy (defense-in-depth)
