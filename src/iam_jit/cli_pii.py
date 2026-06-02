# ADOPT-7 / #721 — `iam-jit pii {scan,validate}` CLI surface.
"""``iam-jit pii scan --config FILE [--text STR | --file PATH]`` and
``iam-jit pii validate --config FILE``.

Define custom PII detectors DECLARATIVELY (entity name + regex/deny-list
+ context words + score) in a YAML/JSON config; scan text or a file for
matches; redact them. The config compiles directly into Presidio
``PatternRecognizer`` / deny-list recognizers — there is NO server-side
LLM or NL parsing (per [[no-nl-synthesis]] +
[[bouncer-zero-llm-when-agent-in-loop]]).

OPTIONAL DEPENDENCY: presidio-analyzer is an extra
(``pip install 'iam-jit[pii]'``). When absent, `pii scan` is a clean
no-op with a clear message + exit 3 — never a crash. `pii validate`
works WITHOUT presidio (pure config parsing) so an operator can author +
check a config before installing the extra.

HONESTY (per [[ibounce-honest-positioning]]): regex/keyword detection
has false positives + negatives. The caveat is printed on every scan.

Exit codes:
  0 — ran cleanly (matches may or may not have been found)
  2 — bad config / bad input / bad flags
  3 — presidio-analyzer not installed (scan only)
"""

from __future__ import annotations

import json
import sys

import click


@click.group("pii")
def pii_group() -> None:
    """Custom PII detectors — define org-specific PII entities
    declaratively and scan/redact text for them.

    iam-jit's bouncer already redacts credential-shaped + basic-PII
    patterns. `pii` lets you ADD org-specific entities (employee badge
    IDs, internal project codenames, customer-account formats) without
    writing Python — just a small YAML/JSON config that compiles into
    Presidio recognizers.

    \b
    Requires the optional extra:
        pip install 'iam-jit[pii]'

    Config shape (YAML):

    \b
        schema_version: 1
        entities:
          - name: EMP_BADGE
            description: "employee badge ID"
            patterns: ["EMP-\\d{5}"]
            context: [badge, employee]
            score: 0.8
          - name: PROJECT_CODE
            deny_list: ["Project Bluefin", "Codename Redshift"]

    NO server-side LLM: every field maps 1:1 onto a Presidio recognizer.
    """


def _read_input(text: str | None, file: str | None) -> str:
    if text is not None and file is not None:
        raise click.UsageError("pass only one of --text / --file")
    if text is not None:
        return text
    if file is not None:
        if file == "-":
            return sys.stdin.read()
        try:
            with open(file, encoding="utf-8") as fh:
                return fh.read()
        except OSError as e:
            raise click.ClickException(f"could not read --file {file}: {e}")
    # Nothing supplied: read stdin (lets `... | iam-jit pii scan -c cfg`).
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise click.UsageError("supply --text, --file, or pipe text on stdin")


@pii_group.command("scan")
@click.option(
    "--config", "-c", "config_path", required=True,
    type=click.Path(dir_okay=False),
    help="Custom-entities config (YAML/JSON).",
)
@click.option("--text", "-t", default=None, help="Text to scan.")
@click.option(
    "--file", "-f", "file_path", default=None,
    help="File to scan ('-' for stdin). Mutually exclusive with --text.",
)
@click.option(
    "--threshold", type=float, default=0.0, show_default=True,
    help="Minimum confidence (0.0–1.0) a match needs to be reported/redacted.",
)
@click.option(
    "--json", "as_json", is_flag=True, default=False,
    help="Emit a JSON result (matches + redacted text + caveat).",
)
@click.option(
    "--show-redacted/--no-show-redacted", default=True, show_default=True,
    help="Print the redacted text (default). --no-show-redacted prints only "
         "the match summary (use when the body is large).",
)
def pii_scan(
    config_path: str,
    text: str | None,
    file_path: str | None,
    threshold: float,
    as_json: bool,
    show_redacted: bool,
) -> None:
    """Scan text/file for operator-defined custom PII entities + redact.

    \b
        iam-jit pii scan -c detectors.yaml --text "badge EMP-12345"
        cat body.json | iam-jit pii scan -c detectors.yaml --json
    """
    from .pii import (
        HONESTY_CAVEAT,
        PiiConfigError,
        PresidioUnavailableError,
        load_config,
        presidio_available,
    )
    from .pii.recognizers import _PIP_HINT, scan_text

    # Optional-dep guard BEFORE touching input, so the operator gets the
    # friendly hint immediately. Clean no-op, exit 3 — never a traceback.
    if not presidio_available():
        click.secho(
            "custom PII detection is unavailable: presidio-analyzer is not "
            f"installed.\nInstall the optional extra:  {_PIP_HINT}",
            fg="yellow", err=True,
        )
        sys.exit(3)

    if not (0.0 <= threshold <= 1.0):
        raise click.UsageError("--threshold must be between 0.0 and 1.0")

    try:
        config = load_config(config_path)
    except PiiConfigError as e:
        click.secho(f"config error: {e}", fg="red", err=True)
        sys.exit(2)

    body = _read_input(text, file_path)

    try:
        result = scan_text(body, config, threshold=threshold)
    except PresidioUnavailableError as e:  # belt-and-suspenders
        click.secho(str(e), fg="yellow", err=True)
        sys.exit(3)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return

    if result.matches:
        click.echo(f"Found {len(result.matches)} match(es):")
        for m in result.matches:
            click.echo(
                f"  {m.entity:<20} score={m.score:.2f}  "
                f"[{m.start}:{m.end}]  {m.text!r}"
            )
    else:
        click.echo("No custom PII detected.")

    if show_redacted:
        click.echo("")
        click.echo("Redacted:")
        click.echo(result.redacted)

    # Honesty caveat on every scan — to stderr so --show-redacted output
    # stays pipe-clean on stdout.
    click.echo("", err=True)
    click.secho(f"note: {HONESTY_CAVEAT}", fg="yellow", err=True)


@pii_group.command("validate")
@click.option(
    "--config", "-c", "config_path", required=True,
    type=click.Path(dir_okay=False),
    help="Custom-entities config (YAML/JSON) to validate.",
)
@click.option(
    "--json", "as_json", is_flag=True, default=False,
    help="Emit the parsed entity summary as JSON.",
)
def pii_validate(config_path: str, as_json: bool) -> None:
    """Validate a custom-entities config WITHOUT running a scan.

    Pure config parsing — does NOT require presidio-analyzer, so you can
    author + check a config before installing the optional extra. Exits
    non-zero on any validation error.
    """
    from .pii import PiiConfigError, load_config

    try:
        config = load_config(config_path)
    except PiiConfigError as e:
        click.secho(f"INVALID: {e}", fg="red", err=True)
        sys.exit(2)

    if as_json:
        click.echo(json.dumps(
            {
                "schema_version": config.schema_version,
                "entities": [
                    {
                        "name": e.name,
                        "description": e.description,
                        "patterns": list(e.patterns),
                        "deny_list_count": len(e.deny_list),
                        "context": list(e.context),
                        "score": e.score,
                    }
                    for e in config.entities
                ],
            },
            indent=2,
        ))
        return

    click.secho(
        f"OK: {len(config.entities)} entit"
        f"{'y' if len(config.entities) == 1 else 'ies'} "
        f"(schema_version {config.schema_version})",
        fg="green",
    )
    for e in config.entities:
        bits = []
        if e.patterns:
            bits.append(f"{len(e.patterns)} pattern(s)")
        if e.deny_list:
            bits.append(f"{len(e.deny_list)} deny-list term(s)")
        if e.context:
            bits.append(f"context={list(e.context)}")
        desc = f" — {e.description}" if e.description else ""
        click.echo(f"  {e.name} (score {e.score}): {', '.join(bits)}{desc}")


def register_pii_group(parent_group: click.Group) -> None:
    """Wire ``iam-jit pii {scan,validate}`` onto the top-level CLI group.

    Mirrors the import-time registration discipline used by
    ``cli_cedar`` / ``cli_compliance_map`` (register at the bottom of
    :mod:`iam_jit.cli`).
    """
    parent_group.add_command(pii_group)
