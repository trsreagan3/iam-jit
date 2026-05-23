"""#422 / §A61 — tests for the Phase E bouncer-to-role-pattern recipe.

Per [[cross-product-agent-parity]] every per-harness page references
the Phase E pattern so an operator reading any one harness recipe
discovers the bouncer→agent→iam-jit synthesis loop.
"""

from __future__ import annotations

import pathlib

_HARNESS_DIR = pathlib.Path(__file__).resolve().parents[1] / "docs" / "HARNESS-RECIPES"
_PATTERN_FILE = _HARNESS_DIR / "bouncer-to-role-pattern.md"


def test_bouncer_to_role_recipe_exists() -> None:
    assert _PATTERN_FILE.is_file(), (
        f"Phase E #422 recipe missing: {_PATTERN_FILE}"
    )


def test_bouncer_to_role_recipe_documents_evidence_block_requirement() -> None:
    """The recipe MUST surface the REQUIRED evidence-block discipline
    per [[ibounce-honest-positioning]] — otherwise agents reading the
    recipe wouldn't know to supply the audit chain."""
    text = _PATTERN_FILE.read_text()
    # Discipline is clearly named.
    assert "REQUIRED evidence block" in text or "REQUIRED" in text and "evidence" in text
    # All three required fields are mentioned explicitly.
    assert "bouncer_audit_window" in text
    assert "codebase_references" in text
    assert "operator_intent" in text
    # The discipline mentions REJECTED as the consequence of missing
    # evidence (so agents understand it's not a soft suggestion).
    assert "REJECT" in text or "rejected" in text
    # The pattern shows all three Phase E primitives composed.
    assert "bounce_extract_permissions_from_audit" in text
    assert "iam_jit_resource_map" in text
    assert "iam_jit_request_role_from_synthesis" in text


def test_per_harness_recipes_reference_bouncer_to_role_pattern() -> None:
    """Each per-harness page links to the Phase E recipe."""
    per_harness = [
        "claude-code.md",
        "cursor.md",
        "codex.md",
        "devin.md",
        "custom-harness.md",
    ]
    missing: list[str] = []
    for name in per_harness:
        text = (_HARNESS_DIR / name).read_text()
        if "bouncer-to-role-pattern.md" not in text:
            missing.append(name)
    assert not missing, (
        f"Phase E recipe must be referenced from every per-harness "
        f"page (cross-product-agent-parity); missing: {missing}"
    )


def test_readme_lists_phase_e_companion_tools() -> None:
    """The HARNESS-RECIPES/README.md companion-tools table mentions the
    three Phase E primitives so a reader discovers them from the index."""
    text = (_HARNESS_DIR / "README.md").read_text()
    assert "bounce_extract_permissions_from_audit" in text
    assert "iam_jit_resource_map" in text
    assert "iam_jit_request_role_from_synthesis" in text


def test_recipe_shows_safety_properties() -> None:
    """The recipe explains the safety properties so an operator
    isn't surprised by pending routing on high-scope requests."""
    text = _PATTERN_FILE.read_text()
    # Mentions the scoring + pending routing.
    assert "scorer" in text.lower()
    assert "pending" in text.lower()
    # Mentions [[creates-never-mutates]] — credentials belong to a NEW
    # role, never modifying existing IAM.
    assert "creates-never-mutates" in text or "NEW" in text
