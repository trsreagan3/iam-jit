"""Enterprise self-bootstrapping (#102 — iam-jit-configures-itself).

3-phase loop that lets the customer's IAM admin point iam-jit at a fresh
AWS environment and have iam-jit propose its own initial config:

  1. Discovery — read-only enumeration of AWS state via the customer's
     admin session (accounts, IAM roles, Bedrock model availability,
     EKS + ECS clusters). Deterministic; no LLM. Output: DiscoveredEnv.
  2. Proposal — feeds DiscoveredEnv + the operator's free-text prompt
     to the customer's own LLM tier (Bedrock / Anthropic key / Ollama)
     per the Enterprise license. Output: ProposedConfig.
  3. Review — prints YAML diff against current config and asks
     y/n/edit; on accept, writes the new config + audit row.

Trust + context invariants (the load-bearing ones):

  - Customer-granted AWS state + customer config/prompt are the ONLY
    two context channels iam-jit ever consumes (per
    [[recommender-context-boundary]]). Bootstrap does NOT read source
    code, does NOT crawl out-of-band, does NOT phone home.
  - iam-jit-the-company never sees the customer's AWS credentials or
    the LLM call (per [[self-host-zero-billing-dependency]] +
    [[enterprise-self-host-only]]).
  - The proposal CREATES new config files; it never mutates existing
    IAM in the customer's account (per [[creates-never-mutates]]).
  - Enterprise-tier gated; on Free/Pro/Team the CLI errors with the
    upgrade path (per [[enterprise-self-host-only]]).
"""

from __future__ import annotations

from .discovery import (
    AccountSummary,
    BedrockAvailability,
    ClusterSummary,
    DiscoveredEnv,
    DiscoveryError,
    RoleSummary,
    discover,
)
from .proposal import (
    AccountLLMPolicyChoice,
    ProposedConfig,
    build_proposal_prompt,
    parse_llm_proposal,
    propose,
)
from .review import (
    ReviewDecision,
    apply_proposal,
    diff_against_current,
    review_loop,
)

__all__ = [
    "AccountLLMPolicyChoice",
    "AccountSummary",
    "BedrockAvailability",
    "ClusterSummary",
    "DiscoveredEnv",
    "DiscoveryError",
    "ProposedConfig",
    "ReviewDecision",
    "RoleSummary",
    "apply_proposal",
    "build_proposal_prompt",
    "diff_against_current",
    "discover",
    "parse_llm_proposal",
    "propose",
    "review_loop",
]
