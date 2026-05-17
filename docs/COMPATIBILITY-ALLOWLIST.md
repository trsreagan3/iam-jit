# Compatibility allowlist (admin guide)

Per-account / per-workload overrides for `check_iam_jit_compatibility`.
Ship admin-supplied rules that change what verdict iam-jit returns
for specific environments — useful when your org has policies the
curated catalog doesn't know about.

## When to add an override

The curated catalog (per `docs/AGENTS.md`) covers generic AWS shapes:
k8s IRSA, EC2 instance profile, Lambda execution role, etc. Add an
allowlist override when:

- **Specific account requires a specific role** — "all k8s pods in
  account `111111111111` use the shared ML role, not whatever IRSA
  binding the pod spec has." Verdict: `use_existing` + role ARN.
- **Account is out-of-scope for iam-jit** — "account `222222222222`
  is a regulated environment; no iam-jit. Escalate to the security
  team." Verdict: `cannot_help`.
- **Prefer bouncer over issuance** — "in account `333333333333`,
  don't issue new roles even if the workload would normally allow
  it; use the bouncer to gate whatever creds the agent has."
  Verdict: `use_bouncer`.
- **Override the catalog default** — "k8s pods are normally
  `use_existing`, but in this specific cluster we have a JIT-issuer
  pattern that does work." Verdict: `proceed`.

Per [[agent-friendly-not-bypassable]] Lens B: **every mutation is
audit-logged** via the bouncer's `config_events` table. Agents see
allowlist rules via the `list_compatibility_overrides` MCP tool but
cannot mutate them (only admins, via this CLI).

## CLI

```bash
# List current rules
iam-jit allowlist list
iam-jit allowlist list --json

# Add a rule (k8s pods in account 111... always use the shared role)
iam-jit allowlist add \
    --account 111111111111 \
    --workload k8s_pod \
    --verdict use_existing \
    --role-arn arn:aws:iam::111111111111:role/shared-ml \
    --reason "shared ML cluster has fixed role"

# Mark an account as out-of-scope
iam-jit allowlist add \
    --account 222222222222 \
    --verdict cannot_help \
    --reason "compliance environment; named-role-only"

# Show one rule in detail
iam-jit allowlist show RULE_ID

# Remove a rule (the deletion is audit-logged with prior content)
iam-jit allowlist remove RULE_ID
```

## Matching semantics

Rules are evaluated in **insertion order, first-match-wins**:

1. iam-jit calls the checker with an intent (workload + optional
   target account + optional services).
2. Walks the allowlist top-to-bottom.
3. First rule whose `account_id` and `workload` match wins. A rule
   with `account_id=None` matches any account; same for `workload`.
4. If no rule matches, fall through to the curated catalog
   (`docs/AGENTS.md`).
5. If the catalog doesn't have an entry either, default to `proceed`
   with a "fall back to bouncer if it fails" hint.

**Order rules from specific to general.** Put narrow account-specific
rules at the top, wildcards at the bottom. (Yes, this is hand-managed
in Slice 2; Slice 3 may add automatic specificity ordering.)

## Storage

`~/.iam-jit/compatibility_allowlist.yaml` by default. Override with
`IAM_JIT_ALLOWLIST_PATH`. Format:

```yaml
version: 1
rules:
  - rule_id: abc123def456
    account_id: '111111111111'
    workload: k8s_pod
    verdict: use_existing
    existing_role_arn: arn:aws:iam::111111111111:role/shared-ml
    reason: shared ML cluster has fixed role
    next_action_hint: null
    created_at: '2026-05-17T15:00:00Z'
    created_by: admin@example.com
```

You can edit the file by hand; bad rows are skipped at read time and
the rest of the file stays usable. Adding via CLI is recommended —
it validates everything up-front + writes the audit-log entry.

## Verdict shapes

| Verdict | When iam-jit returns it | What the agent should do |
|---|---|---|
| `proceed` | iam-jit-the-issuer can mint a JIT role for this case. | Continue the normal flow (`submit_policy`). |
| `use_existing` | A specific pre-existing role should be used. The `existing_role_arn` field carries it. | Use the supplied role; do NOT call `submit_policy` with this workload. |
| `use_bouncer` | iam-jit-the-issuer isn't the right tool, but iam-jit-the-bouncer can gate the calls. | Run the bouncer alongside the workload; use whatever creds it has. |
| `cannot_help` | Neither iam-jit product applies. | Escalate to a human. |

## Validation

The CLI rejects:

- `account_id` that isn't exactly 12 digits (use `None` / omit for "any account")
- `verdict=use_existing` without `--role-arn`
- `--role-arn` with a verdict that isn't `use_existing` (would be confusing)
- `existing_role_arn` that isn't a valid IAM role ARN (all 4 AWS partitions accepted)
- Unknown workload values
- Empty `--reason`

## Composition with the catalog

Allowlist consulted FIRST; catalog SECOND. If an allowlist rule
matches, the catalog is skipped. The audit-log event records
`source: "allowlist"` vs `source: "catalog"` so post-incident review
can tell which source produced any given verdict.

If an allowlist rule has a malformed entry that throws at runtime,
the checker falls back to catalog-only behavior — the allowlist
never crashes the check.

## What's NOT in Slice 2

- **Update-in-place** — to change a rule, remove + re-add. (Each
  mutation is captured separately in the audit chain.)
- **Bulk import** — one rule per CLI invocation. Bulk import comes
  in Slice 3 if customers ask.
- **DynamoDB backend** — Slice 2 ships filesystem only. DynamoDB
  for production deployments lands in Slice 3 if needed.
- **DEFER_TO_EXISTING outcome in submit_policy** — Slice 3 wires the
  allowlist into the broader request-intake flow so submit_policy
  returns an assume snippet for the deferred role.
- **Automatic specificity ordering** — admin orders rules by hand
  for now. Slice 3 may add automatic specific-before-general ordering.
