"""State-verification tests for #626 Phase 4 — init-command collision
cleanup.

Pre-fix: cli.py:18 defined an OLD `def init` (a thin scaffolder that
took --description / --account / --write and emitted role-request YAML)
AND cli.py:1922 registered the NEW #489 interactive bootstrap as
`init` via `register_init_command(main)`. Click's add_command
semantics meant the NEW one won, but the dead OLD definition lived
on as confusing reader-trap code.

The #626 audit 2026-05-26 confirmed the runtime collision was benign
(``main.commands["init"].callback.__module__ == "iam_jit.cli_init"``)
but the dead-code path was a hazard. Phase 4 deletes the OLD shape
+ adds this regression test pinning the NEW shape.

Tests:
  1. `iam-jit init --help` shows the interactive-bootstrap docstring
     ("Bootstrap iam-jit on a fresh machine via guided interview.").
  2. `iam-jit init --help` does NOT show the OLD scaffolder's flags
     (--description, --account, --duration-hours, --write).
  3. The Click command callback's module is `iam_jit.cli_init` (the
     NEW shape), not `iam_jit.cli` (the OLD shape).
"""

from __future__ import annotations

from click.testing import CliRunner

from iam_jit.cli import main


def test_init_help_shows_interactive_bootstrap_docstring() -> None:
    """The canonical NEW #489 docstring is the operator-facing signal
    that the OLD shape is gone."""
    result = CliRunner().invoke(
        main, ["init", "--help"], catch_exceptions=False,
    )
    assert result.exit_code == 0
    # NEW docstring tokens (from cli_init.py:941).
    assert "Bootstrap iam-jit on a fresh machine via guided interview" in (
        result.output
    )
    # NEW flags present.
    assert "--non-interactive" in result.output
    assert "--shape" in result.output
    assert "--bouncers" in result.output
    assert "--harness" in result.output


def test_init_help_does_not_show_old_scaffolder_flags() -> None:
    """If any OLD scaffolder flag appears, Click is somehow showing
    the dead shape OR the old definition came back."""
    result = CliRunner().invoke(
        main, ["init", "--help"], catch_exceptions=False,
    )
    assert result.exit_code == 0
    # OLD shape's required flags must NOT appear.
    assert "--description" not in result.output, (
        "OLD `iam-jit init --description ...` shape resurrected; "
        "Phase 4 of #626 was undone."
    )
    assert "Plain-English task description" not in result.output
    # The OLD --account multiple-flag had specific help text.
    assert "Target account ID" not in result.output


def test_init_callback_lives_in_cli_init_module() -> None:
    """Pin the registration so a future refactor that re-orders
    add_command calls can't silently restore the OLD shape."""
    cmd = main.commands.get("init")
    assert cmd is not None
    assert cmd.callback is not None
    assert cmd.callback.__module__ == "iam_jit.cli_init", (
        f"`iam-jit init` callback now lives in "
        f"{cmd.callback.__module__!r}; expected 'iam_jit.cli_init' "
        "(the #489 interactive bootstrap). If this assertion fires, "
        "Phase 4 of #626 has regressed."
    )
