"""#326 — golden tests for NL-context profile generation."""

from __future__ import annotations

import json

import pytest

from iam_jit.llm import profile_generator as pg


class _StubBackend:
    name = "stub"

    def __init__(self, reply: str) -> None:
        self._reply = reply

    def chat(self, *, system_prompt: str, messages: list[dict[str, str]]) -> str:
        return self._reply


@pytest.fixture
def patch_backend(monkeypatch: pytest.MonkeyPatch):
    """Patch `_resolve_backend` to return a stub backend.

    Also enables the §A93 / #509 Phase 3 opt-in
    (``IAM_JIT_ENABLE_SIDE_LLM=1``) — these tests explicitly want to
    exercise the LLM-path behavior, so they signal opt-in matching the
    new local-dev / agent-in-loop default."""
    def _make(reply: str, name: str = "stub"):
        def _resolve(preferred: str | None):
            return _StubBackend(reply), name
        monkeypatch.setattr(pg, "_resolve_backend", _resolve)
        monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
    return _make


def test_context_strict_parse_happy_path(patch_backend):
    reply = json.dumps({
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [],
                "denies": [
                    {
                        "target": "arn:aws:iam::*:role/break-glass-*",
                        "actions": ["sts:AssumeRole"],
                        "reason": "break-glass requires human approval",
                    },
                ],
                "flagged_for_review": [],
                "skipped": [],
            },
            {
                "bouncer": "dbounce",
                "allows": [],
                "denies": [
                    {
                        "sql_patterns": ["GRANT * TO PUBLIC"],
                        "reason": "silent privilege escalation",
                    },
                ],
                "flagged_for_review": [],
                "skipped": [],
            },
        ],
        "explanation": (
            "Generated starting-point denies for a mid-size SaaS. "
            "Operator should add prod-account-id isolation."
        ),
    })
    patch_backend(reply, name="anthropic")

    result = pg.generate_from_context(
        context="Mid-size SaaS, prod/staging split, 5 engineers, no PCI",
        start_from=["example-org-base"],
        profile_name="mid-saas-base",
    )

    assert result.parser_strict_match is True
    assert result.backend_name == "anthropic"
    bouncers = {p.bouncer for p in result.bundle}
    assert "ibounce" in bouncers
    assert "dbounce" in bouncers

    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    assert "llm-generated-from-context" in ibounce.profile_yaml
    assert "STARTING POINT" in ibounce.profile_yaml
    # Context hash provenance.
    assert any(
        f.startswith("context_sha256_prefix:") for f in ibounce.flagged_for_review
    )


def test_context_deterministic_fallback_includes_full_safety_floor(
    patch_backend,
):
    """No LLM available -> deterministic fallback emits the safety
    floor across all four bouncers."""
    patch_backend("", name="stub")
    result = pg.generate_from_context(
        context="Anything",
        profile_name="floor-test",
    )
    bouncers = {p.bouncer for p in result.bundle}
    assert bouncers == {"ibounce", "kbounce", "dbounce", "gbounce"}
    # Each bouncer's safety floor was emitted.
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    assert "iam:CreateAccessKey" in ibounce.profile_yaml
    kbounce = next(p for p in result.bundle if p.bouncer == "kbounce")
    assert "clusterrolebindings" in kbounce.profile_yaml
    dbounce = next(p for p in result.bundle if p.bouncer == "dbounce")
    assert "GRANT" in dbounce.profile_yaml
    gbounce = next(p for p in result.bundle if p.bouncer == "gbounce")
    assert "169.254.169.254" in gbounce.profile_yaml


def test_context_yaml_is_valid(patch_backend):
    import yaml
    patch_backend("", name="stub")
    result = pg.generate_from_context(
        context="Test",
        profile_name="yaml-test",
    )
    for p in result.bundle:
        parsed = yaml.safe_load(p.profile_yaml)
        assert parsed["schema_version"] == 1
        assert parsed["bouncer"] == p.bouncer
        assert parsed["provenance"]["source"] == "llm-generated-from-context"
    idx = yaml.safe_load(result.index_yaml)
    assert idx["schema_version"] == 1


def test_context_no_compliance_claims(patch_backend):
    """Per [[ibounce-honest-positioning]] the generator must never
    emit profile YAML claiming compliance even if the LLM does."""
    # We can only enforce this on output; the prompt instructs the
    # LLM not to. Confirm the deterministic fallback (no LLM) NEVER
    # has compliance language.
    patch_backend("", name="stub")
    result = pg.generate_from_context(
        context="HIPAA-regulated healthcare org",
        profile_name="no-claims",
    )
    for p in result.bundle:
        body = p.profile_yaml.lower()
        # No compliance-certification claims.
        assert "hipaa-compliant" not in body
        assert "pci-compliant" not in body
        assert "soc2-compliant" not in body
        assert "soc 2 compliant" not in body
