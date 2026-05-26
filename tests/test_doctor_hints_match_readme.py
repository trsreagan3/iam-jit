"""CI lint: doctor Section 1 Go-bouncer hint strings must equal README commands.

This is the structural guard that would have caught the three hint-drift bugs
this week (#548 PEP 660, #649 PEP 668 macOS, #653 gbouncer/kbouncer wrong
module paths).

The approach:
  1. Parse README.md for every ``go install github.com/trsreagan3/<pkg>``
     line in the "Go bouncers" section.
  2. Load the canonical install commands from ``_GO_BOUNCER_BINARIES`` in
     ``cli_doctor_install_check.py``.
  3. Assert the doctor tuple's module path exactly matches the README line.

Per [[deliberate-feature-completion]] scope is limited to Section 1 Go-bouncer
hints only. Per [[ibounce-honest-positioning]] every hint must be paste-ready
and actually work.
"""

from __future__ import annotations

import pathlib
import re


_REPO_ROOT = pathlib.Path(__file__).parent.parent
_README = _REPO_ROOT / "README.md"

# Pattern: bare "go install github.com/..." on its own line (code-block content).
_GO_INSTALL_RE = re.compile(
    r"^\s*go install (github\.com/trsreagan3/\S+)\s*$",
    re.MULTILINE,
)


def _readme_go_install_commands() -> set[str]:
    """Extract every ``go install github.com/trsreagan3/...`` module path
    from README.md. Returns full module paths (the part after 'go install ').

    Only captures lines inside code blocks (backtick-fenced) in the README
    Go-bouncers section so stray mentions in prose don't pollute the corpus.
    """
    text = _README.read_text(encoding="utf-8")

    # Extract code-block contents only (triple-backtick fences).
    code_blocks = re.findall(r"```[a-z]*\n(.*?)```", text, re.DOTALL)
    combined = "\n".join(code_blocks)

    return {m.group(1) for m in _GO_INSTALL_RE.finditer(combined)}


def _doctor_go_install_commands() -> dict[str, str]:
    """Return {binary_name: module_path} from ``_GO_BOUNCER_BINARIES`` in
    ``cli_doctor_install_check.py``.

    Imports the real module so any future refactor that moves the constant is
    caught immediately (ImportError) rather than silently passing.
    """
    from iam_jit.cli_doctor_install_check import _GO_BOUNCER_BINARIES  # type: ignore[attr-defined]

    return {name: module_path for name, module_path in _GO_BOUNCER_BINARIES}


def test_go_bouncer_binaries_constant_has_three_entries() -> None:
    """Sanity: the constant covers all three Go bouncers."""
    doctor_cmds = _doctor_go_install_commands()
    assert set(doctor_cmds.keys()) == {"kbounce", "dbounce", "gbounce"}, (
        f"Expected exactly kbounce/dbounce/gbounce in _GO_BOUNCER_BINARIES; "
        f"got: {set(doctor_cmds.keys())}"
    )


def test_readme_has_go_install_commands_for_all_three_bouncers() -> None:
    """README.md must document all three canonical install commands.

    If this test fails, a Go bouncer is missing from the README Go-bouncers
    section — add it there, not by weakening this test.
    """
    readme_cmds = _readme_go_install_commands()
    expected_suffixes = [
        "kbouncer/cmd/kbounce@latest",
        "dbounce/cmd/dbounce@latest",
        "gbounce/cmd/gbounce@latest",
    ]
    for suffix in expected_suffixes:
        matching = [c for c in readme_cmds if c.endswith(suffix)]
        assert matching, (
            f"README.md missing 'go install github.com/trsreagan3/{suffix}' "
            f"in a code block. Add it to the 'Go bouncers' section.\n"
            f"Found README go-install commands: {sorted(readme_cmds)}"
        )


def test_doctor_hint_matches_readme_for_each_bouncer() -> None:
    """Core drift guard: for every binary in _GO_BOUNCER_BINARIES, the
    module path must appear verbatim in README.md's code blocks.

    This is the test that would have caught all three hint-drift bugs.
    If this fails, either:
      (a) The doctor was updated without updating README — fix README, or
      (b) README was updated without updating the doctor — fix the doctor.
    """
    readme_cmds = _readme_go_install_commands()
    doctor_cmds = _doctor_go_install_commands()

    mismatches: list[str] = []
    for binary_name, module_path in sorted(doctor_cmds.items()):
        full_cmd = f"go install {module_path}"
        # The module_path from the doctor should appear in the README commands.
        if module_path not in readme_cmds:
            mismatches.append(
                f"  {binary_name}: doctor has '{module_path}' but README "
                f"code blocks have: {sorted(readme_cmds)}"
            )

    assert not mismatches, (
        "Doctor hint strings diverge from README install commands — "
        "update ONE source (prefer README as the operator-facing truth) "
        "then update the doctor constant to match:\n"
        + "\n".join(mismatches)
    )


def test_doctor_go_module_paths_have_cmd_subpackage() -> None:
    """Structural: every Go module path must follow the <repo>/cmd/<binary>@tag
    pattern. Catches the original bug (bare repo@latest missing /cmd/<binary>)
    and future regressions like pointing at wrong subpackage.
    """
    doctor_cmds = _doctor_go_install_commands()
    bad: list[str] = []
    for binary_name, module_path in sorted(doctor_cmds.items()):
        # Must match: github.com/trsreagan3/<repo>/cmd/<binary>@<tag>
        pattern = re.compile(
            rf"^github\.com/trsreagan3/[^/]+/cmd/{re.escape(binary_name)}@\S+$"
        )
        if not pattern.match(module_path):
            bad.append(
                f"  {binary_name}: '{module_path}' does not match "
                f"'github.com/trsreagan3/<repo>/cmd/{binary_name}@<tag>'"
            )

    assert not bad, (
        "One or more Go bouncer module paths are missing the /cmd/<binary> "
        "subpackage — `go install` on a bare repo path installs nothing "
        "unless there's a main package at the root:\n"
        + "\n".join(bad)
    )


def test_doctor_go_module_paths_end_with_at_latest() -> None:
    """Doctor hint tags must be @latest (not @main or a pinned SHA).

    Operators paste these hints to install; @latest is the stable user-
    facing tag. @main is dev-only (may break). Pinned SHAs go stale.
    Tests that exercise @main live in smoke-test docs, not doctor hints.
    """
    doctor_cmds = _doctor_go_install_commands()
    bad: list[str] = []
    for binary_name, module_path in sorted(doctor_cmds.items()):
        if not module_path.endswith("@latest"):
            bad.append(f"  {binary_name}: '{module_path}' — must end with @latest")

    assert not bad, (
        "Doctor Go-bouncer hint strings must use @latest, not @main or "
        "pinned SHAs:\n" + "\n".join(bad)
    )
