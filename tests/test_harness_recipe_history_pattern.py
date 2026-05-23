"""#438 / §A72 — doc-truth tests for the Phase G history-to-config
recipe.

iam-jit ships a "recipe" not a CLI for historical synthesis (per
[[historical-synthesis-phase-g]] re-scoped 2026-05-23). The recipe
doc is the load-bearing artifact: agents read it to know HOW to
turn long-range bouncer history into a per-target bouncer config.

These tests pin the recipe's properties so an accidental edit
(removing the architectural separation, dropping a canonical ask,
etc.) is caught at CI time rather than slipping through to a
launch-blocker UAT.
"""

from __future__ import annotations

import pathlib

RECIPE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "docs"
    / "HARNESS-RECIPES"
    / "bouncer-history-to-config-pattern.md"
)


def test_recipe_doc_exists_and_documents_canonical_3_asks():
    """The recipe doc must enumerate the three canonical asks
    (positive / scope-isolated / negative) — these are the asks the
    Phase G memo names verbatim from founder direction
    2026-05-23."""
    assert RECIPE.is_file(), f"recipe missing: {RECIPE}"
    text = RECIPE.read_text()
    # Three canonical asks named in the Phase G memo.
    assert "Positive synthesis" in text, text
    assert "Scope-isolated synthesis" in text, text
    assert "Negative synthesis" in text, text
    # All three operator-quote shapes are quoted somewhere in the
    # doc so a copy-paste hunt finds them. Operator quotes wrap
    # across multiple lines — we look for the load-bearing phrases.
    assert "Browse my last 2 years" in text
    assert "without touching" in text and "prod" in text
    assert "blocks the production URLs" in text


def test_recipe_doc_references_phase_e_421_evidence_block():
    """The recipe MUST reference the Phase E #421 evidence-block
    seam so agents synthesising configs from long-range history
    know they can submit through the same role-request seam they
    use for short-window synthesis."""
    text = RECIPE.read_text()
    assert "iam_jit_request_role_from_synthesis" in text
    # Evidence-block shape is documented (so the agent doesn't
    # have to re-derive it).
    assert "evidence" in text.lower()
    assert "bouncer_audit_window" in text
    assert "codebase_references" in text
    assert "operator_intent" in text


def test_recipe_doc_explains_agent_does_synthesis_not_iam_jit():
    """The architectural-separation invariant (iam-jit provides
    logs + taxonomy; agent does synthesis) MUST be obvious from
    the recipe. Operators reading the recipe should understand
    WHY there's no `iam-jit synthesize-config` CLI to invoke."""
    text = RECIPE.read_text()
    # The separation is stated in plain language.
    assert "agent" in text.lower()
    assert "synthesis" in text.lower() or "synthesise" in text.lower()
    # The taxonomy primitive (Phase G #437) appears so the agent
    # knows where the scope-filter comes from.
    assert "deployment_targets" in text or "deployment-targets" in text
    # The long-range query primitive (Phase G #436) appears.
    assert "--since 2y" in text or "bounce_query_audit_long_range" in text
    # The Phase E + bouncer-informs-agent memo is cited.
    assert "bouncer-informs-agent-informs-iam-jit" in text


def test_recipe_doc_referenced_from_per_harness_pages():
    """Every per-harness page MUST link to the new Phase G recipe so
    an agent landing on (say) claude-code.md finds the long-range
    flow without hunting through the docs tree."""
    recipes_dir = RECIPE.parent
    for harness in (
        "claude-code.md", "cursor.md", "codex.md",
        "devin.md", "custom-harness.md",
    ):
        page = recipes_dir / harness
        assert page.is_file(), page
        body = page.read_text()
        assert "bouncer-history-to-config-pattern" in body, (
            f"{harness}: missing link to Phase G history-to-config "
            "recipe"
        )
