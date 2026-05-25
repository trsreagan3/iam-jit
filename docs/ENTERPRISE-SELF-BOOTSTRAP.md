# Self-host bootstrap (`iam-jit enterprise bootstrap`)

> **Status**: ships in v1.0 (free + open source).
> **Tracking issue**: #102.
> **SUPERSEDED 2026-05-23**: per `project_oss_only_launch_decision.md`,
> v1.0 ships fully free + open source. References below to "Enterprise
> tier" / "license file" / "tier gating" are HISTORICAL DESIGN CONTEXT
> only — the bootstrap command runs without any license at v1.0. The
> license-validation code stays in the repo for future paid-tier
> introduction (no earlier than 12-18mo post-launch) but does NOT
> enforce at v1.0. The `enterprise` subcommand name is retained for
> backward-compat; self-host bootstrap is the v1.0-accurate framing.

`iam-jit enterprise bootstrap` lets a customer's IAM admin point
iam-jit at a fresh AWS environment and have iam-jit propose its
own initial configuration. The admin reviews the YAML proposal
and accepts (or edits, or rejects). On accept, the proposal is
written to `~/.iam-jit/config.yaml` and a tamper-evident audit
row is appended to `~/.iam-jit/bootstrap-audit.jsonl`.

## When to use this

You just installed iam-jit on a self-host machine and want a sane
starting `config.yaml` without hand-authoring it from the schema
documentation. Bootstrap is run **once per environment** at install
time; you re-run it only when the AWS landscape changes
significantly (new prod accounts come online, new clusters, etc.).

For per-grant operations (issuing roles, scoring policies),
bootstrap is not involved — use the regular `iam-jit` CLI,
MCP tools, or HTTP API.

## How the three phases work

### Phase 1 — Discovery (deterministic, no LLM)

Read-only enumeration of AWS state using the operator's current
admin session. Calls:

| Service        | API                                | Purpose                                      |
| -------------- | ---------------------------------- | -------------------------------------------- |
| STS            | `GetCallerIdentity`                | Resolve caller account + ARN (gate)          |
| Organizations  | `ListAccounts`, `ListTagsForResource` | Enumerate sibling accounts + their tags |
| IAM            | `ListRoles`                        | Filter for OIDC-anchored roles               |
| Bedrock        | `ListFoundationModels` (Anthropic) | Probe Bedrock LLM availability per region (skipped if you've already chosen Anthropic / OpenAI / Ollama as your backend) |
| EKS            | `ListClusters`, `DescribeCluster`  | Cluster ARN inventory                        |
| ECS            | `ListClusters`                     | Cluster ARN inventory                        |

The output is a structured `DiscoveredEnv` object. If any service
fails (e.g. SCP denies `organizations:ListAccounts`), the failure
is captured on `DiscoveredEnv.errors` rather than crashing — the
operator sees a complete-but-partial picture and decides whether
to proceed.

**Out of scope in v1.0** (surfaced in `DiscoveredEnv.deferred_services`):
KMS keys, Secrets Manager secrets, RDS / DynamoDB / S3 inventories,
Identity Center permission sets. Each of these has either
high-cardinality / sensitive-name concerns or is already covered
by a separate iam-jit onboarding flow. They're candidates for a
v1.1 "deeper scan" follow-up.

### Phase 2 — Proposal (LLM-augmented, customer's tier)

Feeds the discovery summary + your free-text `--prompt` to the
customer's own LLM backend (Bedrock / Anthropic API / OpenAI API /
Ollama per the customer's `IAM_JIT_LLM` configuration). The model
returns a proposed configuration with these top-level keys:

| Key                                       | Purpose                                                                        |
| ----------------------------------------- | ------------------------------------------------------------------------------ |
| `org_context_name`                        | Display name for the organization                                              |
| `account_llm_policies`                    | Per-account `use_llm` / `deterministic_only` choice + the rationale            |
| `recommended_cluster_arns`                | EKS/ECS clusters to register as workload anchors                               |
| `recommended_profiles`                    | Built-in profiles to enable (dev-only / staging-work / prod-readonly / incident-response) |
| `recommended_bouncer_mode_per_account`    | Per-account bouncer mode (`strict` / `read_write_swap`)                        |
| `notes`                                   | Free-text rationale; flags discovery gaps                                      |

The parser is strict-with-soft-clamps: unknown extras are
tolerated but mark the result as `parser_strict_match=False` so
the audit row records that the LLM drifted from spec. Invalid
account IDs, cluster ARNs outside discovery, profiles outside
the allowlist, and bogus `llm_policy` values are silently
dropped — the LLM cannot inject configuration for resources the
operator's session can't see.

If the LLM is unavailable or returns garbage, Phase 2 falls back
to a deterministic config (all accounts → `deterministic_only`,
all discovered clusters included, `dev-only` + `prod-readonly`
profiles). The operator still gets to review.

**Prompt template is the API surface.** Tests pin invariants of
`SYSTEM_PROMPT` (required JSON keys, vocab, length) so any
intentional change requires updating the snapshot test.

### Phase 3 — Review (operator decision)

Prints the proposed YAML and a unified diff against the current
config, then prompts `y/n/edit`:

- **y / yes** — write the YAML to `--config-path` (default
  `~/.iam-jit/config.yaml`); append accept-audit row.
- **n / no** — write nothing; append reject-audit row.
- **edit / e** — open `$EDITOR` on the proposal YAML; re-parse
  on close; re-prompt with the edited proposal. Malformed YAML
  is discarded with a warning, and the original proposal is
  restored.

`--yes` skips the prompt (auto-accept) for CI/agent flows. Use
sparingly; the review step is the safety net.

## Trust model

| Concern                            | How bootstrap handles it                                                                                       |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| AWS credentials                    | Read from the operator's current shell (boto3 default chain). Never leave the machine.                          |
| LLM traffic                        | Routed through the customer's own Bedrock / Anthropic / OpenAI / Ollama backend. Never touches iam-jit-the-company. |
| Source code                        | **Never read.** Per `[[recommender-context-boundary]]`, iam-jit consumes exactly two context channels — AWS state + operator config/prompt. |
| Existing IAM resources             | **Never mutated.** Per `[[creates-never-mutates]]`, bootstrap only CREATES the iam-jit config file + audit row. |
| Network egress to iam-jit-the-company | None. No phone home, no license callback, no telemetry. Per `[[self-host-zero-billing-dependency]]`.           |
| Source/binary trust                | Bypass-honest. Anyone with the source can patch out the tier gate; the contract is the legal artifact.          |

## Licensing (v1.0: not enforced)

Per `project_oss_only_launch_decision.md`, v1.0 ships fully free +
open source. Bootstrap runs without any license file. The license-
validation code stays in the repo (see `docs/PERMISSIONS-MODEL.md`)
but does NOT enforce at v1.0; the upgrade-path messaging is reserved
for a future paid-tier introduction (no earlier than 12-18mo
post-launch). Self-host stays the only deployment shape per
`[[no-hosted-saas]]`.

## Reference

```text
iam-jit enterprise bootstrap [OPTIONS]

  --prompt TEXT         Free-text context about the org
  --region TEXT         AWS region to probe (default: session region)
  --config-path PATH    Output config file (default: ~/.iam-jit/config.yaml)
  --audit-path PATH     Append-only audit log (default: ~/.iam-jit/bootstrap-audit.jsonl)
  --yes                 Skip interactive review (auto-accept)
  --dry-run             Run discovery + proposal; write nothing
```

Environment variables consulted:

- `IAM_JIT_LICENSE_FILE` — path to the license JSON
- `IAM_JIT_CONFIG_FILE` — default output config path
- `IAM_JIT_BOOTSTRAP_AUDIT_FILE` — default audit log path
- `IAM_JIT_BOOTSTRAP_ACTOR` — overrides the actor name in the audit row
- `IAM_JIT_LLM` / `IAM_JIT_BEDROCK_MODEL` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `OLLAMA_HOST` — LLM backend selection (same precedence as the rest of iam-jit, see `src/iam_jit/llm.py`)
- `EDITOR` — used when the operator picks `edit` at the review prompt

## Composition with other features

Bootstrap is the configuration on-ramp for several other
Enterprise features:

- **Per-account LLM policy** (`[[per-account-llm-policy]]`) —
  the proposal sets `llm_policy` per account based on tags +
  naming heuristics; this drives whether the (paid) LLM scorer
  runs for grants touching each account.
- **K8s bouncer integration** — proposed cluster ARNs are the
  starting set for `kbounce` admission-webhook anchors.
- **Agents-default-to-iam-jit** (`[[agents-default-to-iam-jit]]`) —
  bootstrap is the natural place for an admin's IDE agent to
  drive the discovery + review loop end-to-end; the proposal's
  strict JSON shape makes the loop programmatic.
- **Live action tail** (`[[live-action-tail-pro-tier]]`) — the
  proposed cluster ARNs + account list become the audit-source
  scope for CloudTrail streaming.

## Related design notes

- `[[iam-jit-configures-itself]]` — the originating memo
- `[[agent-context-primacy]]` — why agents do the discovery
- `[[recommender-context-boundary]]` — the two-channel rule
- `[[enterprise-self-host-only]]` — tier model
- `[[don't-tailor-to-lighthouse]]` — why the prompt doesn't make any one customer's config "look pretty"
