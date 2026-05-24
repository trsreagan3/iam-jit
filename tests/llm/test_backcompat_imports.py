"""Back-compat import-surface tests.

The pluggable-backend slice converted `iam_jit/llm.py` to a package.
Every symbol that was importable from the old module MUST stay
importable from `iam_jit.llm`. This test pins the surface so a future
refactor catches a removal immediately.
"""

from __future__ import annotations


def test_back_compat_imports() -> None:
    from iam_jit.llm import (  # noqa: F401
        SYSTEM_PROMPT,
        AnthropicBackend,
        BedrockBackend,
        CassetteMiss,
        LLMBackend,
        NoOpBackend,
        OllamaBackend,
        RecordingBackend,
        _cassette_key,
        _parse,
        get_backend,
        get_backend_for_tier,
        wrap_with_cassette,
    )

    assert SYSTEM_PROMPT  # truthy
    assert NoOpBackend().refine(
        description="x", initial_services=["s3"], initial_actions=["read"]
    ) == (["s3"], ["read"])
    assert isinstance(get_backend(), NoOpBackend)


def test_new_pluggable_imports() -> None:
    from iam_jit.llm import (  # noqa: F401
        ScoreContext,
        ScoreResponse,
        available_backends,
        default_score_backend,
        get_score_backend,
        score_policy,
    )

    assert set(available_backends()) == {"bedrock", "anthropic", "openai", "ollama"}


def test_consumers_still_import_via_old_path() -> None:
    """Spot-check the actual modules that historically imported from
    `iam_jit.llm` — exercises real consumer-import sites end-to-end."""
    # review.py uses NoOpBackend + get_backend (gated)
    from iam_jit import review

    assert hasattr(review, "analyze_policy")
    # (routes/score.py consumer-import check dropped 2026-05-24 —
    # the hosted scoring API was removed per [[no-hosted-saas]].)
