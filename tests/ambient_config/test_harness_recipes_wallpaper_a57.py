"""#413 / §A57 — per-harness recipe pages MUST include first-run
wallpaper messaging per [[ambient-value-prop-and-friction-framing]].

Each per-harness recipe needs a short "what to expect day-to-day"
blurb that:
  * Leads with caught-framing ("Your bouncer caught X"), NOT "ERROR".
  * Sets the friction expectation honestly (the bouncer is silent
    most of the time; you'll only see prompts when something catches
    its attention).
"""

from __future__ import annotations

import pathlib

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_RECIPES_DIR = _REPO_ROOT / "docs" / "HARNESS-RECIPES"


def _read(name: str) -> str:
    return (_RECIPES_DIR / name).read_text(encoding="utf-8")


def test_per_harness_recipe_includes_first_run_wallpaper_readme() -> None:
    """The recipes README MUST include the day-to-day wallpaper
    messaging so an operator opening the recipes folder for the first
    time sees the expectation set."""
    txt = _read("README.md")
    lowered = txt.lower()
    # Lead the wallpaper section with caught-framing.
    assert "what to expect" in lowered
    assert "bouncer audits everything" in lowered
    assert "your bouncer caught" in lowered
    # Categorization framing surfaced.
    assert "likely-adversarial" in lowered
    assert "likely-legit" in lowered


@pytest.mark.parametrize(
    "filename",
    [
        "claude-code.md",
        "cursor.md",
        "codex.md",
        "devin.md",
        "custom-harness.md",
    ],
)
def test_per_harness_recipe_includes_first_run_wallpaper(filename: str) -> None:
    """Each per-harness page MUST carry a "First-run wallpaper" section
    that leads with caught-framing per [[ambient-value-prop-and-friction-framing]]."""
    txt = _read(filename)
    lowered = txt.lower()
    assert "first-run wallpaper" in lowered, (
        f"{filename}: missing 'First-run wallpaper' section"
    )
    assert "your bouncer" in lowered, (
        f"{filename}: missing 'Your bouncer' caught-framing"
    )
    # The framing canonical — "caught + here's how to allow" not "ERROR".
    # We don't forbid the word "ERROR" globally (HTTP status code etc),
    # but the wallpaper section itself MUST NOT lead with it.
    # Find the wallpaper section + assert no "ERROR:" / "DENIED" /
    # "BLOCKED" appears before the next heading.
    section_start = lowered.index("first-run wallpaper")
    # Heuristic: capture next 800 chars (the wallpaper section is
    # short — explicitly per the brief).
    section = lowered[section_start : section_start + 1500]
    for forbidden in ("error:", "denied", "blocked"):
        assert forbidden not in section, (
            f"{filename}: forbidden lead text {forbidden!r} in wallpaper section"
        )
