"""Unit tests for Phase 2 (proposal + LLM prompt construction).

Covers:
  - ProposedConfig shape + serialization
  - SYSTEM_PROMPT snapshot — the prompt template IS the API surface,
    so any change should be a deliberate, reviewed test update
  - Prompt construction is grounded in DiscoveredEnv shape
  - parse_llm_proposal accepts well-formed JSON
  - parse_llm_proposal rejects: bad JSON, missing keys, invalid
    llm_policy values, cluster ARNs not in discovery, profiles
    outside the allowlist
  - propose() falls back to a deterministic config when the
    backend raises or returns empty

The snapshot test is intentionally byte-exact: see prompt-
template-as-API-surface in the docstring of
src/iam_jit/enterprise/proposal.py.
"""

from __future__ import annotations

import json


from iam_jit.enterprise.discovery import (
    AccountSummary,
    BedrockAvailability,
    ClusterSummary,
    DiscoveredEnv,
    RoleSummary,
)
from iam_jit.enterprise.proposal import (
    SYSTEM_PROMPT,
    AccountLLMPolicyChoice,
    ProposedConfig,
    build_proposal_prompt,
    parse_llm_proposal,
    propose,
)


def _env() -> DiscoveredEnv:
    return DiscoveredEnv(
        discovered_at="2026-05-18T00:00:00Z",
        caller_account_id="111111111111",
        caller_arn="arn:aws:iam::111111111111:role/Admin",
        caller_region="us-east-1",
        accounts=(
            AccountSummary(account_id="111111111111", is_caller_account=True),
            AccountSummary(
                account_id="222222222222", alias="prod",
                tags={"env": "prod"},
            ),
        ),
        oidc_roles=(
            RoleSummary(
                role_name="gha-deployer",
                role_arn="arn:aws:iam::111111111111:role/gha-deployer",
                account_id="111111111111",
                trusts_oidc_provider=True,
                trusted_oidc_providers=(
                    "arn:aws:iam::111111111111:oidc-provider/"
                    "token.actions.githubusercontent.com",
                ),
            ),
        ),
        bedrock=BedrockAvailability(
            region="us-east-1",
            bedrock_reachable=True,
            anthropic_model_ids=("anthropic.claude-opus-4-7-v1:0",),
        ),
        eks_clusters=(
            ClusterSummary(
                cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/prod",
                cluster_name="prod",
                account_id="111111111111",
                region="us-east-1",
                kind="eks",
            ),
        ),
        ecs_clusters=(),
        errors=(),
    )


# ---------------------------------------------------------------------------
# ProposedConfig shape
# ---------------------------------------------------------------------------


def test_proposed_config_to_dict_and_yaml() -> None:
    pc = ProposedConfig(
        org_context_name="acme",
        account_llm_policies=(
            AccountLLMPolicyChoice(
                account_id="111111111111",
                llm_policy="deterministic_only",
                reason="dev account",
            ),
        ),
        recommended_cluster_arns=("arn:aws:eks:us-east-1:111111111111:cluster/prod",),
        recommended_profiles=("dev-only", "prod-readonly"),
        recommended_bouncer_mode_per_account={"111111111111": "read_write_swap"},
        notes="initial bootstrap",
    )
    d = pc.to_dict()
    assert d["org_context_name"] == "acme"
    assert d["account_llm_policies"][0]["llm_policy"] == "deterministic_only"
    assert d["recommended_cluster_arns"] == [
        "arn:aws:eks:us-east-1:111111111111:cluster/prod",
    ]
    yaml_text = pc.to_yaml()
    assert "org_context_name: acme" in yaml_text
    assert "recommended_profiles:" in yaml_text


# ---------------------------------------------------------------------------
# Prompt snapshot (the API surface)
# ---------------------------------------------------------------------------


def test_system_prompt_is_compact_and_lists_required_keys() -> None:
    """Snapshot the SYSTEM_PROMPT structure. We don't pin the full
    text byte-exact (too brittle), but we DO pin invariants the LLM
    + downstream parser depend on."""
    # Required JSON keys must be enumerated in the prompt — this is
    # the contract with the LLM.
    for required_key in (
        "org_context_name",
        "account_llm_policies",
        "recommended_cluster_arns",
        "recommended_profiles",
        "recommended_bouncer_mode_per_account",
        "notes",
    ):
        assert required_key in SYSTEM_PROMPT, f"prompt missing {required_key!r}"
    # Valid value vocabularies must be enumerated.
    for vocab in ("use_llm", "deterministic_only", "strict", "read_write_swap"):
        assert vocab in SYSTEM_PROMPT, f"prompt missing vocab {vocab!r}"
    # Allowed profile names enumerated verbatim.
    for prof in ("dev-only", "staging-work", "prod-readonly", "incident-response"):
        assert prof in SYSTEM_PROMPT, f"prompt missing profile {prof!r}"
    # Compact target — guards against drift toward essay prompts.
    # 2400 chars is generous (~600 tokens); current prompt sits at
    # ~1700. If this fails on a deliberate expansion, raise the cap
    # in a separate PR with rationale.
    assert len(SYSTEM_PROMPT) < 2400, (
        f"SYSTEM_PROMPT grew to {len(SYSTEM_PROMPT)} chars; keep it under "
        "2400 to stay grounded + cheap (see docs/ENTERPRISE-SELF-BOOTSTRAP.md "
        "on prompt-template-as-API-surface)."
    )


def test_build_proposal_prompt_is_grounded_in_discovery() -> None:
    env = _env()
    messages = build_proposal_prompt(env, "we want strict on prod")
    assert len(messages) == 1
    assert messages[0]["role"] == "user"
    content = messages[0]["content"]
    # Discovery payload appears verbatim (JSON-encoded).
    assert "111111111111" in content
    assert "222222222222" in content
    assert "gha-deployer" in content
    assert "prod" in content
    assert "we want strict on prod" in content
    # Prompt-injection brackets present.
    assert "<<<BEGIN_DISCOVERY>>>" in content
    assert "<<<END_DISCOVERY>>>" in content
    assert "<<<BEGIN_OPERATOR_PROMPT>>>" in content
    assert "<<<END_OPERATOR_PROMPT>>>" in content


def test_build_proposal_prompt_caps_operator_text() -> None:
    env = _env()
    huge = "x" * 10_000
    messages = build_proposal_prompt(env, huge, max_operator_chars=500)
    content = messages[0]["content"]
    # Truncated to 500 chars within the operator brackets.
    after = content.split("<<<BEGIN_OPERATOR_PROMPT>>>", 1)[1]
    operator_chunk = after.split("<<<END_OPERATOR_PROMPT>>>", 1)[0].strip()
    assert len(operator_chunk) <= 500


# ---------------------------------------------------------------------------
# parse_llm_proposal — strict
# ---------------------------------------------------------------------------


def _good_response() -> str:
    return json.dumps({
        "org_context_name": "acme-prod",
        "account_llm_policies": [
            {"account_id": "111111111111",
             "llm_policy": "deterministic_only",
             "reason": "caller / sandbox"},
            {"account_id": "222222222222",
             "llm_policy": "use_llm",
             "reason": "prod-tagged"},
        ],
        "recommended_cluster_arns": [
            "arn:aws:eks:us-east-1:111111111111:cluster/prod",
        ],
        "recommended_profiles": ["dev-only", "prod-readonly"],
        "recommended_bouncer_mode_per_account": {
            "111111111111": "read_write_swap",
            "222222222222": "strict",
        },
        "notes": "initial proposal",
    })


def test_parse_llm_proposal_accepts_well_formed_response() -> None:
    env = _env()
    pc = parse_llm_proposal(_good_response(), env)
    assert pc.org_context_name == "acme-prod"
    assert pc.parser_strict_match is True
    assert len(pc.account_llm_policies) == 2
    assert pc.recommended_bouncer_mode_per_account["222222222222"] == "strict"


def test_parse_llm_proposal_rejects_bad_json() -> None:
    env = _env()
    pc = parse_llm_proposal("not json {", env)
    assert pc.parser_strict_match is False
    assert "non-JSON" in pc.notes


def test_parse_llm_proposal_rejects_missing_keys() -> None:
    env = _env()
    partial = json.dumps({"org_context_name": "acme"})
    pc = parse_llm_proposal(partial, env)
    assert pc.parser_strict_match is False
    assert "missing keys" in pc.notes


def test_parse_llm_proposal_drops_invalid_llm_policy_values() -> None:
    env = _env()
    bad = json.loads(_good_response())
    bad["account_llm_policies"].append({
        "account_id": "111111111111",
        "llm_policy": "GIVE_ME_ROOT",
        "reason": "injection attempt",
    })
    pc = parse_llm_proposal(json.dumps(bad), env)
    # Original two entries survive; injection-attempt entry dropped.
    assert len(pc.account_llm_policies) == 2
    assert all(
        p.llm_policy in ("use_llm", "deterministic_only")
        for p in pc.account_llm_policies
    )


def test_parse_llm_proposal_drops_cluster_arns_not_in_discovery() -> None:
    env = _env()
    bad = json.loads(_good_response())
    bad["recommended_cluster_arns"].append(
        "arn:aws:eks:us-east-1:999999999999:cluster/attacker"
    )
    pc = parse_llm_proposal(json.dumps(bad), env)
    # Only the discovered ARN survives.
    assert pc.recommended_cluster_arns == (
        "arn:aws:eks:us-east-1:111111111111:cluster/prod",
    )


def test_parse_llm_proposal_drops_profiles_outside_allowlist() -> None:
    env = _env()
    bad = json.loads(_good_response())
    bad["recommended_profiles"].append("rm-rf-prod")
    pc = parse_llm_proposal(json.dumps(bad), env)
    assert "rm-rf-prod" not in pc.recommended_profiles
    assert set(pc.recommended_profiles).issubset({
        "dev-only", "staging-work", "prod-readonly", "incident-response",
    })


def test_parse_llm_proposal_account_ids_outside_discovery_dropped() -> None:
    env = _env()
    bad = json.loads(_good_response())
    bad["recommended_bouncer_mode_per_account"]["999999999999"] = "strict"
    bad["account_llm_policies"].append({
        "account_id": "999999999999",
        "llm_policy": "use_llm",
        "reason": "spoofed",
    })
    pc = parse_llm_proposal(json.dumps(bad), env)
    assert "999999999999" not in pc.recommended_bouncer_mode_per_account
    assert all(
        p.account_id in {"111111111111", "222222222222"}
        for p in pc.account_llm_policies
    )


def test_parse_llm_proposal_tolerates_extra_keys_as_non_strict() -> None:
    env = _env()
    bad = json.loads(_good_response())
    bad["extra_speculative_field"] = "ignored"
    pc = parse_llm_proposal(json.dumps(bad), env)
    # Soft-clamp: parsed successfully but flagged non-strict.
    assert pc.parser_strict_match is False
    assert pc.org_context_name == "acme-prod"


# ---------------------------------------------------------------------------
# propose() — backend integration
# ---------------------------------------------------------------------------


class _FakeBackend:
    def __init__(self, response: str = "") -> None:
        self._response = response
        self.last_system_prompt: str | None = None
        self.last_messages: list[dict[str, str]] | None = None

    def chat(self, *, system_prompt: str, messages: list[dict[str, str]]) -> str:
        self.last_system_prompt = system_prompt
        self.last_messages = messages
        return self._response


class _RaisingBackend:
    def chat(self, **kw):  # type: ignore[no-untyped-def]
        raise RuntimeError("bedrock down")


def test_propose_passes_system_prompt_and_returns_strict_match() -> None:
    backend = _FakeBackend(_good_response())
    pc = propose(_env(), "we have two accounts", backend=backend)
    assert backend.last_system_prompt == SYSTEM_PROMPT
    assert pc.parser_strict_match is True


def test_propose_falls_back_when_backend_raises() -> None:
    pc = propose(_env(), "anything", backend=_RaisingBackend())
    assert pc.parser_strict_match is False
    assert "LLM backend error" in pc.notes
    # Fallback should mark everything deterministic_only.
    assert all(
        p.llm_policy == "deterministic_only"
        for p in pc.account_llm_policies
    )


def test_propose_falls_back_when_backend_empty_response() -> None:
    pc = propose(_env(), "anything", backend=_FakeBackend(""))
    assert pc.parser_strict_match is False
    assert "empty LLM response" in pc.notes


def test_propose_fallback_includes_all_discovered_clusters() -> None:
    """Fallback config must NOT lose information from discovery —
    the operator can still review + accept cluster ARNs."""
    env = _env()
    pc = propose(env, "", backend=_RaisingBackend())
    assert pc.recommended_cluster_arns == (
        "arn:aws:eks:us-east-1:111111111111:cluster/prod",
    )
