"""§A93 / #509 Phase 3 — opt-in gate tests for
:func:`iam_jit.enterprise.proposal.propose` (A4 site).

The enterprise bootstrap proposer takes a DiscoveredEnv + operator
prompt and asks the customer's LLM tier to propose an initial
``.iam-jit.yaml``. Per [[bouncer-zero-llm-when-agent-in-loop]] the
default (local-dev / agent-in-loop) is to SKIP the bouncer-side LLM
call and return a deterministic fallback. The agent drives the
LLM-augmented proposal via MCP using ITS OWN LLM when desired.

Caller-supplied ``backend`` (explicit code paths, tests, the
autopilot ``--enable-side-llm`` flow) is HONORED — the gate only
applies to the auto-resolved default backend resolution path.

State-verification convention per ``docs/CONTRIBUTING.md`` — every
assertion is on OBSERVABLE state: mock chat() call count, skip
counter snapshot, ProposedConfig fields.
"""

from __future__ import annotations


import pytest

from iam_jit.enterprise.discovery import (
    AccountSummary,
    BedrockAvailability,
    ClusterSummary,
    DiscoveredEnv,
)
from iam_jit.enterprise.proposal import propose
from iam_jit.llm import (
    REASON_NO_LLM_BACKEND,
    REASON_NO_SIDE_LLM_ENABLED,
    reset_skip_counter,
    skip_counter_snapshot,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_counter() -> None:
    reset_skip_counter()
    yield
    reset_skip_counter()


@pytest.fixture(autouse=True)
def _no_llm_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip every LLM-related env var so the default path reflects
    no creds + no opt-in."""
    for var in (
        "IAM_JIT_LLM",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "IAM_JIT_BEDROCK_MODEL",
        "OLLAMA_HOST",
        "IAM_JIT_ENABLE_SIDE_LLM",
    ):
        monkeypatch.delenv(var, raising=False)


def _env() -> DiscoveredEnv:
    return DiscoveredEnv(
        discovered_at="2026-05-23T00:00:00Z",
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
        oidc_roles=(),
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


class _RecordingBackend:
    """Test-only backend that records every chat() invocation."""

    name = "recording"

    def __init__(self, reply: str = "") -> None:
        self._reply = reply
        self.chat_calls: list[dict] = []

    def chat(self, *, system_prompt, messages):
        self.chat_calls.append({
            "system_prompt": system_prompt,
            "messages": messages,
        })
        return self._reply


# ---------------------------------------------------------------------------
# Default OFF — local-dev / agent-in-loop mode
# ---------------------------------------------------------------------------


def test_propose_default_off_skips_llm_and_returns_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No opt-in + no caller-supplied backend: propose() returns the
    deterministic fallback WITHOUT touching the LLM. Even if an
    Anthropic key happens to be in the env (sibling tools), it's
    NOT used."""
    # Simulate a sibling tool having set an API key — the gate should
    # still skip because no opt-in.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-used")
    # Patch get_backend_for_tier to a recorder so we can assert chat
    # was never called even though the resolution happened.
    recorder = _RecordingBackend(reply="should-not-be-seen")

    def _fake_get_backend_for_tier(_tier):
        return recorder

    # Inject the recorder through the lazy import path inside propose().
    import iam_jit.llm as llm_mod
    monkeypatch.setattr(
        llm_mod, "get_backend_for_tier", _fake_get_backend_for_tier
    )
    pc = propose(_env(), "we have two accounts")

    # Observable 1: chat() was never called.
    assert recorder.chat_calls == [], (
        "backend.chat() must not be called in local-dev default mode; "
        f"got {len(recorder.chat_calls)} calls"
    )

    # Observable 2: skip counter fired with REASON_NO_SIDE_LLM_ENABLED.
    snap = skip_counter_snapshot()
    assert snap["counts"].get("enterprise.proposal", 0) == 1
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) == 1

    # Observable 3: the returned ProposedConfig is the deterministic
    # fallback (per-account llm_policy = deterministic_only).
    assert pc.parser_strict_match is False
    assert "side-LLM not enabled" in pc.notes
    assert all(
        p.llm_policy == "deterministic_only"
        for p in pc.account_llm_policies
    )


def test_propose_default_returns_complete_response_structure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default-off result still matches the documented ProposedConfig
    shape — no contract regressions."""
    import iam_jit.llm as llm_mod
    monkeypatch.setattr(
        llm_mod, "get_backend_for_tier",
        lambda _t: _RecordingBackend(reply=""),
    )
    pc = propose(_env(), "anything")
    # Fields populated per the dataclass contract.
    assert isinstance(pc.org_context_name, str) and pc.org_context_name
    assert isinstance(pc.account_llm_policies, tuple)
    assert isinstance(pc.recommended_cluster_arns, tuple)
    assert isinstance(pc.recommended_bouncer_mode_per_account, dict)
    assert isinstance(pc.notes, str)


# ---------------------------------------------------------------------------
# Caller-supplied backend — gate is bypassed (explicit opt-in)
# ---------------------------------------------------------------------------


def test_propose_caller_supplied_backend_bypasses_gate() -> None:
    """When caller passes ``backend=...`` explicitly (tests / the
    autopilot --enable-side-llm flow), the gate is bypassed because
    the caller already opted in by injecting a backend object."""
    recorder = _RecordingBackend(reply="")
    pc = propose(_env(), "anything", backend=recorder)
    # Observable: chat() WAS called (caller's backend honored).
    assert len(recorder.chat_calls) == 1
    # No NO_SIDE_LLM_ENABLED skip (caller explicitly opted in).
    snap = skip_counter_snapshot()
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) == 0
    # Empty reply → existing fallback path engages.
    assert "empty LLM response" in pc.notes


# ---------------------------------------------------------------------------
# Opt-in via env var — chat fires through auto-resolved backend
# ---------------------------------------------------------------------------


def test_propose_opt_in_via_env_var_invokes_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``IAM_JIT_ENABLE_SIDE_LLM=1`` + auto-resolved backend: chat()
    runs through the resolved backend."""
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
    recorder = _RecordingBackend(reply="")
    import iam_jit.llm as llm_mod
    monkeypatch.setattr(
        llm_mod, "get_backend_for_tier", lambda _t: recorder
    )
    propose(_env(), "we have two accounts")
    # Observable: chat() WAS called (opt-in honored).
    assert len(recorder.chat_calls) == 1
    snap = skip_counter_snapshot()
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) == 0


def test_propose_opt_in_truthy_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All canonical truthy values enable the opt-in."""
    import iam_jit.llm as llm_mod
    for truthy in ("1", "true", "TRUE", "yes", "Yes", "on"):
        reset_skip_counter()
        monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", truthy)
        recorder = _RecordingBackend(reply="")
        monkeypatch.setattr(
            llm_mod, "get_backend_for_tier", lambda _t, r=recorder: r
        )
        propose(_env(), "x")
        assert len(recorder.chat_calls) == 1, (
            f"chat() must fire for truthy={truthy!r}"
        )


def test_propose_opt_in_falsy_values_still_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Falsy / weird values do NOT enable the gate."""
    import iam_jit.llm as llm_mod
    for falsy in ("", "0", "false", "no", "off", "maybe", "  "):
        reset_skip_counter()
        monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", falsy)
        recorder = _RecordingBackend(reply="")
        monkeypatch.setattr(
            llm_mod, "get_backend_for_tier", lambda _t, r=recorder: r
        )
        propose(_env(), "x")
        assert recorder.chat_calls == [], (
            f"chat() must NOT fire for falsy={falsy!r}"
        )


# ---------------------------------------------------------------------------
# Opt-in WITHOUT working creds — distinct misconfig skip fires
# ---------------------------------------------------------------------------


def test_propose_opt_in_without_creds_surfaces_misconfig(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opt-in IS set but auto-resolved backend is NoOp (creds missing):
    REASON_NO_LLM_BACKEND fires (NOT NO_SIDE_LLM_ENABLED — operator
    opted in; the misconfig is the missing creds)."""
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")

    class _NoOpShaped:
        name = "noop"

        def chat(self, **_kw):
            return ""

    import iam_jit.llm as llm_mod
    monkeypatch.setattr(
        llm_mod, "get_backend_for_tier", lambda _t: _NoOpShaped()
    )
    propose(_env(), "anything")
    snap = skip_counter_snapshot()
    assert snap["by_reason"].get(REASON_NO_LLM_BACKEND, 0) >= 1
    assert snap["by_reason"].get(REASON_NO_SIDE_LLM_ENABLED, 0) == 0


# ---------------------------------------------------------------------------
# Cross-cutting — counter parity with /healthz + posture
# ---------------------------------------------------------------------------


def test_propose_counter_visible_via_top_level_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """report_skip surface used by /healthz + iam-jit posture reflects
    proposal gate fires."""
    import iam_jit.llm as llm_mod
    monkeypatch.setattr(
        llm_mod, "get_backend_for_tier",
        lambda _t: _RecordingBackend(reply=""),
    )
    propose(_env(), "one")
    propose(_env(), "two")
    snap = skip_counter_snapshot()
    assert snap["counts"]["enterprise.proposal"] == 2
    assert snap["total"] == 2
