# ADOPT-5 / #719 — `iam-jit cedar {export,import}` CLI surface.
"""``iam-jit cedar export --policy FILE [--format cedar|json]`` and
``iam-jit cedar import --in FILE [--format json|cedar]``.

Move a policy between iam-jit / Bounce and a Cedar-based system (AWS
Bedrock AgentCore, AWS Verified Permissions) WITHOUT rewriting it by
hand.

* ``export`` : AWS IAM policy JSON  ->  Cedar policy text.
* ``import`` : Cedar policy text    ->  best-effort AWS IAM policy JSON.

POSITIONING (per [[cedar-positioning]]): iam-jit is NOT Cedar and does
NOT compete with Cedar. This is a portability / interop convenience, not
a claim that iam-jit "is" or "uses" Cedar.

HONESTY (per [[ibounce-honest-positioning]]): IAM and Cedar are not 1:1.
Untranslatable constructs (NotAction/NotResource/NotPrincipal, embedded
wildcards, exotic condition operators) produce a VISIBLE marker in the
output AND a structured translation note — never a silently-wrong
policy. When any construct is untranslatable, the command exits non-zero
unless ``--allow-lossy`` is passed, so a lossy translation can't slip
into a pipeline unnoticed.

NOTE: lossy Cedar output containing inline ``// UNTRANSLATABLE`` markers
is INTENTIONALLY not loadable by a real Cedar parser (the ``//`` comment
swallows the trailing comma) — this forces a human to review and edit
the marked spot before the policy can be used. This is by design.

Read-only: translation only. Never touches AWS.

Exit codes:
  0 — translated with no lossy/untranslatable constructs
  1 — translated but lossy/untranslatable (unless --allow-lossy)
  2 — malformed input / parse error
"""

from __future__ import annotations

import json
import sys

import click

from .cedar import TranslationError, cedar_to_iam, iam_to_cedar


def _read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as e:
        raise TranslationError(f"could not read {path}: {e}") from e


def _emit_notes(result) -> None:
    """Print translation notes to stderr (never stdout — stdout stays
    clean for the translated policy so it can be piped)."""
    if not result.notes:
        return
    click.echo("translation notes:", err=True)
    for n in result.notes:
        marker = {
            "untranslatable": "UNTRANSLATABLE",
            "lossy": "LOSSY",
            "info": "info",
        }.get(n.severity, n.severity)
        locpart = f" [{n.location}]" if n.location else ""
        click.echo(f"  - {marker} {n.construct}{locpart}: {n.message}", err=True)


@click.group("cedar")
def cedar_group() -> None:
    """Translate policies between AWS IAM and Cedar (interop / portability).

    iam-jit is NOT Cedar and does not compete with it (Cedar is
    application-level authz; iam-jit is AWS IAM credential issuance).
    These commands are a portability convenience so a policy authored in
    one system can be carried to the other. Translation is HONEST: where
    IAM and Cedar are not 1:1, the output carries a visible marker and
    the command flags the result as lossy. Read-only — never touches AWS.
    """


@cedar_group.command("export")
@click.option(
    "--policy",
    "policy_path",
    required=True,
    help="Path to the AWS IAM policy JSON file (use '-' for stdin).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["cedar", "json"], case_sensitive=False),
    default="cedar",
    show_default=True,
    help="Output format. `cedar` = Cedar policy text (default); `json` = "
    "a structured result with the Cedar text + translation notes.",
)
@click.option(
    "--allow-lossy",
    is_flag=True,
    default=False,
    help="Exit 0 even when some constructs were untranslatable / lossy. "
    "Default: exit 1 so a lossy translation can't slip into CI unnoticed. "
    "Note: lossy Cedar output with inline // UNTRANSLATABLE markers is "
    "intentionally non-loadable until a human edits the marked spot.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write to PATH instead of stdout (notes still go to stderr).",
)
def cedar_export(
    policy_path: str, fmt: str, allow_lossy: bool, output: str | None
) -> None:
    """Translate an AWS IAM policy file to Cedar policy text.

    \b
    Examples:
      iam-jit cedar export --policy role.json
      iam-jit cedar export --policy role.json --format json
      cat role.json | iam-jit cedar export --policy - -o role.cedar
    """
    fmt = fmt.lower()
    try:
        text = _read_text(policy_path)
        policy = json.loads(text)
        result = iam_to_cedar(policy)
    except json.JSONDecodeError as e:
        click.echo(f"ERROR: {policy_path} is not valid JSON: {e}", err=True)
        sys.exit(2)
    except TranslationError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)

    if fmt == "json":
        rendered = json.dumps(result.as_dict(), indent=2) + "\n"
    else:
        rendered = result.output
        _emit_notes(result)

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        click.echo(f"Cedar policy written to {output}", err=True)
    else:
        click.echo(rendered, nl=False)

    if result.is_lossy and not allow_lossy:
        click.echo(
            "ERROR: translation was LOSSY (untranslatable / approximated "
            "constructs above). Review the markers; re-run with "
            "--allow-lossy to accept.",
            err=True,
        )
        sys.exit(1)


@cedar_group.command("import")
@click.option(
    "--in",
    "cedar_path",
    required=True,
    help="Path to the Cedar policy text file (use '-' for stdin).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "cedar"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Output format. `json` = the AWS IAM policy document (default); "
    "`cedar` here means a structured result (IAM policy + notes).",
)
@click.option(
    "--allow-lossy",
    is_flag=True,
    default=False,
    help="Exit 0 even when some constructs were untranslatable / lossy. "
    "Default: exit 1 so a lossy translation can't slip into CI unnoticed. "
    "Note: lossy Cedar output with inline // UNTRANSLATABLE markers is "
    "intentionally non-loadable until a human edits the marked spot.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write to PATH instead of stdout (notes still go to stderr).",
)
def cedar_import(
    cedar_path: str, fmt: str, allow_lossy: bool, output: str | None
) -> None:
    """Translate a Cedar policy file to a best-effort AWS IAM policy.

    Best-effort: inverts the faithful subset. Cedar constructs with no
    IAM equivalent (entity-attribute refs, `is` type tests, set/`like`
    operators, `unless`) are flagged as notes; the affected scope is left
    conservative rather than silently approximated.

    \b
    Examples:
      iam-jit cedar import --in policy.cedar
      iam-jit cedar import --in policy.cedar -o role.json
      iam-jit cedar import --in - < policy.cedar
    """
    fmt = fmt.lower()
    try:
        text = _read_text(cedar_path)
        result = cedar_to_iam(text)
    except TranslationError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)

    if fmt == "cedar":
        rendered = json.dumps(result.as_dict(), indent=2) + "\n"
    else:
        rendered = result.output + "\n"
        _emit_notes(result)

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        click.echo(f"IAM policy written to {output}", err=True)
    else:
        click.echo(rendered, nl=False)

    if result.is_lossy and not allow_lossy:
        click.echo(
            "ERROR: translation was LOSSY (untranslatable / approximated "
            "constructs above). Review the markers; re-run with "
            "--allow-lossy to accept.",
            err=True,
        )
        sys.exit(1)


def register_cedar_group(parent_group: click.Group) -> None:
    """Wire ``iam-jit cedar {export,import}`` onto the top-level CLI group.

    Mirrors the import-time registration discipline used by
    ``cli_compliance_map`` / ``cli_agent_diff`` (register at the bottom
    of :mod:`iam_jit.cli`).
    """
    parent_group.add_command(cedar_group)
