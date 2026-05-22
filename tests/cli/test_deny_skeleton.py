"""#324 — `iam-jit deny` skeleton tests.

Verifies the SKELETON contract per the design doc:

  * Every subcommand (`add`, `list`, `remove`, `show`) exits 2.
  * Every subcommand emits a structured "not implemented yet"
    payload that names: the subcommand, the design-doc path, the
    schema path, the slice that will replace it, AND the tracking
    refs (#324a-f).
  * `--json` toggles the payload to machine-parseable JSON on
    stderr.
  * The deny group is mounted on the top-level `iam-jit` CLI so
    `iam-jit deny --help` surfaces the planned shape.

Per ``[[ibounce-honest-positioning]]``: the skeleton is supposed to
fail honestly. These tests pin the failure SHAPE so a future
implementation slice (#324e) can replace the bodies without
disturbing the contract.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from iam_jit.cli import main
from iam_jit.cli_deny import (
    DESIGN_DOC_PATH,
    DESIGN_DOC_URL,
    REPLACEMENT_SLICE,
    SCHEMA_PATH,
    TRACKING_REFS,
)


# --------------------------------------------------------------------
# Mount + --help discovery
# --------------------------------------------------------------------

def test_deny_group_mounted_on_main_cli() -> None:
    """`iam-jit deny --help` must surface the planned shape today."""
    runner = CliRunner()
    result = runner.invoke(main, ["deny", "--help"])
    assert result.exit_code == 0, result.output
    # All four subcommands appear under the help banner.
    for sub in ("add", "list", "remove", "show"):
        assert sub in result.output, (
            f"`iam-jit deny --help` must list `{sub}` subcommand; "
            f"got:\n{result.output}"
        )
    # The group docstring names the design-doc reference.
    assert "DYNAMIC-DENY-RULES.md" in result.output or "DESIGN" in result.output


def test_deny_subcommands_each_have_help() -> None:
    runner = CliRunner()
    for sub in ("add", "list", "remove", "show"):
        result = runner.invoke(main, ["deny", sub, "--help"])
        assert result.exit_code == 0, (
            f"`iam-jit deny {sub} --help` failed: {result.output}"
        )
        # Every subcommand's help mentions it's DESIGN-stage.
        assert "DESIGN" in result.output, (
            f"`iam-jit deny {sub} --help` must mark itself DESIGN; "
            f"got:\n{result.output}"
        )


# --------------------------------------------------------------------
# Exit code + stderr shape (human mode)
# --------------------------------------------------------------------

@pytest.mark.parametrize(
    "argv",
    [
        ["deny", "add", "--target", "arn:aws:s3:::prod-*",
         "--reason", "test", "--duration", "1h"],
        ["deny", "list"],
        ["deny", "remove", "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"],
        ["deny", "show", "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"],
    ],
)
def test_each_subcommand_exits_two(argv: list[str]) -> None:
    """Skeleton contract: every command exits 2."""
    runner = CliRunner()
    result = runner.invoke(main, argv)
    assert result.exit_code == 2, (
        f"argv={argv} expected exit 2, got {result.exit_code}\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )


@pytest.mark.parametrize(
    "subcommand,argv",
    [
        ("add",    ["deny", "add", "--target", "arn:aws:s3:::prod-*",
                    "--reason", "test", "--duration", "1h"]),
        ("list",   ["deny", "list"]),
        ("remove", ["deny", "remove", "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"]),
        ("show",   ["deny", "show", "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"]),
    ],
)
def test_human_payload_names_the_contract(subcommand: str, argv: list[str]) -> None:
    """Human stderr names the design doc, schema, and replacement slice."""
    runner = CliRunner()
    result = runner.invoke(main, argv)
    assert result.exit_code == 2
    stderr = result.stderr
    # The subcommand name appears in the banner.
    assert subcommand in stderr
    # The design-doc reference + URL + schema are named verbatim.
    assert DESIGN_DOC_PATH in stderr
    assert DESIGN_DOC_URL in stderr
    assert SCHEMA_PATH in stderr
    # The slice that will replace this subcommand is named.
    expected_slice = REPLACEMENT_SLICE[subcommand]
    assert expected_slice in stderr
    # All six tracking refs are listed.
    for ref in TRACKING_REFS:
        assert ref in stderr, (
            f"stderr for `iam-jit deny {subcommand}` should list tracking "
            f"ref {ref}; got:\n{stderr}"
        )


# --------------------------------------------------------------------
# JSON mode shape
# --------------------------------------------------------------------

@pytest.mark.parametrize(
    "subcommand,argv",
    [
        ("add",    ["deny", "add", "--target", "arn:aws:s3:::prod-*",
                    "--reason", "test", "--duration", "1h", "--json"]),
        ("list",   ["deny", "list", "--json"]),
        ("remove", ["deny", "remove", "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C", "--json"]),
        ("show",   ["deny", "show", "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C", "--json"]),
    ],
)
def test_json_payload_shape(subcommand: str, argv: list[str]) -> None:
    """JSON mode emits a stable, machine-parseable shape per the design doc."""
    runner = CliRunner()
    result = runner.invoke(main, argv)
    assert result.exit_code == 2

    # JSON goes on stderr.
    payload = json.loads(result.stderr)

    # The documented stable keys are present.
    assert payload["status"] == "not_implemented_yet"
    assert payload["subcommand"] == f"iam-jit deny {subcommand}"
    assert payload["design_doc"] == DESIGN_DOC_PATH
    assert payload["design_doc_url"] == DESIGN_DOC_URL
    assert payload["schema"] == SCHEMA_PATH
    assert payload["replaced_by"] == REPLACEMENT_SLICE[subcommand]

    # Every documented tracking ref is present.
    assert set(payload["tracking"].keys()) == set(TRACKING_REFS.keys())
    for ref, summary in TRACKING_REFS.items():
        assert payload["tracking"][ref] == summary

    # The skeleton ECHOES received args back (debugging aid for agents
    # who hit a not-implemented + want to see what their call looked like).
    assert "received_args" in payload


# --------------------------------------------------------------------
# Tracking refs sanity
# --------------------------------------------------------------------

def test_tracking_refs_cover_all_six_subtasks() -> None:
    """All six #324a-f subtasks must be tracked + every subcommand must
    point at one of them as its replacement."""
    expected = {"#324a", "#324b", "#324c", "#324d", "#324e", "#324f"}
    assert set(TRACKING_REFS.keys()) == expected
    # Every subcommand's replacement slice exists in the tracking dict.
    for sub, slice_ref in REPLACEMENT_SLICE.items():
        assert slice_ref in TRACKING_REFS, (
            f"subcommand `{sub}` claims replacement by `{slice_ref}` but "
            f"that slice is not in TRACKING_REFS"
        )
