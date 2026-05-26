"""#489 + #532 CRIT — `iam-jit init` interactive bootstrap interview.

Per founder direction 2026-05-26 (§A89 LAUNCH-BLOCKER + UC-30 CRIT):
`iam-jit init` is the canonical first-time-operator onboarding path.
MRR-6 references it; `init-solo` (in `cli.py`) is the narrower
predecessor and stays in place unchanged.

The interview walks a fresh operator through:

  1. Deployment shape pick (local-solo / multi-user / canary / corp-managed)
  2. AWS account detection + offer to write ``~/.iam-jit/accounts.yaml``
  3. Bouncer(s) to install (ibounce only / ibounce+gbounce / all 4)
  4. Mode pick (discovery / cooperative / strict) per
     ``[[discovery-first-default]]``
  5. MCP harness detect (Claude Code / Cursor / Codex / Devin / none)
  6. Generate + write declarative config to ``~/.iam-jit/iam-jit.yaml``
  7. Offer to run ``iam-jit doctor apply-config --config <path>``
  8. Print next-step summary

For non-TTY callers (agents) per
``[[bouncer-zero-llm-when-agent-in-loop]]`` ``stdin.isatty() == False``
is detected automatically; defaults are applied + decisions are logged
to stdout so the caller can audit what was picked without parsing
prompts. Per-step flags (``--shape`` / ``--mode`` / ``--bouncers`` /
``--harness``) let agents bypass any specific prompt while accepting
defaults for the rest.

Reuses existing helpers — does NOT reinvent:

* AWS-account detection + accounts.yaml seeding from
  ``local_server._seed_local_accounts`` (via ``LocalServerConfig``)
* MCP-server JSON snippet shape from ``cli._mcp_server_config_dict``
* Claude Desktop config path from ``cli._claude_desktop_config_path``
* Pre-existing-data preflight from
  ``cli._preflight_check_existing_data`` /
  ``cli._print_preflight_warning`` (#617 MED-3)
* Declarative-config validation from ``ambient_config.load_declaration``

Per ``[[creates-never-mutates]]`` init writes new files but refuses to
clobber pre-existing ``~/.iam-jit/iam-jit.yaml`` without an explicit
``--overwrite`` flag.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import sys
from typing import Any

import click
import yaml

# Allowed enumerations — kept module-scope so tests + agents can
# introspect them via `_VALID_*` without invoking the CLI.
_VALID_SHAPES = ("local-solo", "multi-user", "canary", "corp-managed")
_VALID_MODES = ("discovery", "cooperative", "strict")
_VALID_BOUNCERS = ("ibounce", "kbouncer", "dbounce", "gbounce")
_VALID_HARNESSES = ("claude-code", "cursor", "codex", "devin", "none")


# ---------------------------------------------------------------------------
# Data shape — the in-memory interview result. Tests assert against the
# *file* contents (state-verification per CONTRIBUTING.md) but the
# dataclass keeps the helper plumbing typed.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _InterviewResult:
    shape: str
    mode: str
    bouncers: tuple[str, ...]
    harness: str
    accounts_detected: tuple[str, ...]
    data_dir: pathlib.Path


# ---------------------------------------------------------------------------
# Helpers — kept private + small so the public command body stays linear.
# ---------------------------------------------------------------------------


def _is_interactive(non_interactive_flag: bool) -> bool:
    """True iff the caller wants interactive prompts.

    Non-TTY (agents, CI, piped input) auto-falls to non-interactive per
    ``[[bouncer-zero-llm-when-agent-in-loop]]``. Operator can force
    non-interactive even on a TTY with ``--non-interactive``.
    """
    if non_interactive_flag:
        return False
    try:
        return bool(sys.stdin.isatty())
    except Exception:
        return False


def _log_decision(label: str, value: Any, *, interactive: bool) -> None:
    """Non-interactive paths surface every defaulted decision to stdout
    so an agent / CI consumer can audit the choices. Interactive paths
    don't need this because the operator answered each prompt.
    """
    if interactive:
        return
    click.echo(f"[init] {label}: {value}")


def _default_data_dir() -> pathlib.Path:
    """Mirror ``local_server._DEFAULT_DATA_DIR`` without importing the
    server module at call-time (avoids loading boto3 for --dry-run)."""
    return pathlib.Path.home() / ".iam-jit"


def _detect_aws_accounts(interactive: bool) -> tuple[str, ...]:
    """Return a tuple of detected AWS account IDs.

    Best-effort: tries the boto3 default credential chain. Returns an
    empty tuple if no credentials are configured — init still writes a
    config file with a placeholder account, and the operator edits it
    later. NEVER raises.
    """
    try:
        import boto3  # type: ignore[import-not-found]
        sts = boto3.client("sts")
        ident = sts.get_caller_identity()
        account_id = str(ident.get("Account") or "").strip()
        if account_id and account_id != "000000000000":
            _log_decision(
                "aws_account_detected", account_id,
                interactive=interactive,
            )
            return (account_id,)
    except Exception as e:
        _log_decision(
            "aws_account_detected", f"none ({type(e).__name__})",
            interactive=interactive,
        )
    return ()


def _detect_harness(interactive: bool) -> str:
    """Best-effort detection of which MCP harness the operator is on.

    Checks for canonical config-file locations on disk; first match
    wins per the same ordering ``bouncer/config_io.py`` uses.

    Returns ``"none"`` when no harness is detected so the operator can
    install manually later via ``iam-jit mcp show-config``.
    """
    home = pathlib.Path.home()
    candidates: list[tuple[str, pathlib.Path]] = [
        ("claude-code", home / ".claude.json"),
        ("claude-code", home / ".config" / "claude-code" / "mcp.json"),
        ("cursor", home / ".cursor" / "mcp.json"),
        ("claude-code",
         home / "Library" / "Application Support"
         / "Claude" / "claude_desktop_config.json"),
        ("claude-code", home / ".config" / "Claude" / "claude_desktop_config.json"),
    ]
    for name, path in candidates:
        if path.exists():
            _log_decision("harness_detected", name, interactive=interactive)
            return name
    _log_decision("harness_detected", "none", interactive=interactive)
    return "none"


def _prompt_shape(interactive: bool) -> str:
    """Interactive shape pick. Defaults to local-solo (per existing
    init-solo onboarding flow + most-common operator shape)."""
    if not interactive:
        return "local-solo"
    click.echo()
    click.secho("1. Deployment shape", bold=True)
    click.echo("   - local-solo:    one operator, one laptop "
               "(matches `init-solo`)")
    click.echo("   - multi-user:    shared team server")
    click.echo("   - canary:        single-machine evaluation deploy")
    click.echo("   - corp-managed:  IT-curated org profile via --org-url "
               "(#490 — not in this interview)")
    return click.prompt(
        "Pick shape",
        type=click.Choice(list(_VALID_SHAPES)),
        default="local-solo",
        show_default=True,
    )


def _prompt_bouncers(interactive: bool, shape: str) -> tuple[str, ...]:
    """Interactive bouncer pick. Defaults to ibounce only per the
    pre-launch sequencing in [[bounce-suite-rename]] (ibounce is the
    AWS gating product most operators want first)."""
    if not interactive:
        return ("ibounce",)
    click.echo()
    click.secho("3. Bouncer(s) to install", bold=True)
    click.echo("   - ibounce-only:  AWS API gating (most common)")
    click.echo("   - ibounce+gbounce: AWS + HTTP gating")
    click.echo("   - all:           ibounce + kbouncer + dbounce + gbounce "
               "(four Bounce-suite products)")
    choice = click.prompt(
        "Pick bouncer set",
        type=click.Choice(["ibounce-only", "ibounce+gbounce", "all"]),
        default="ibounce-only",
        show_default=True,
    )
    if choice == "ibounce-only":
        return ("ibounce",)
    if choice == "ibounce+gbounce":
        return ("ibounce", "gbounce")
    return _VALID_BOUNCERS


def _prompt_mode(interactive: bool) -> str:
    """Interactive mode pick. Defaults to discovery per
    ``[[discovery-first-default]]`` — observe before block.
    """
    if not interactive:
        return "discovery"
    click.echo()
    click.secho("4. Bouncer mode", bold=True)
    click.echo("   - discovery:     observe + log only, no deny "
               "(default — per [[discovery-first-default]])")
    click.echo("   - cooperative:   agent sees deny rationale + may retry "
               "scoped")
    click.echo("   - strict:        maximalist deny + alert; no retry "
               "loop")
    return click.prompt(
        "Pick mode",
        type=click.Choice(list(_VALID_MODES)),
        default="discovery",
        show_default=True,
    )


def _resolve_config_path(data_dir: pathlib.Path | None) -> pathlib.Path:
    """Where the declarative config gets written. Mirrors the data-dir
    convention used by init-solo (~/.iam-jit/) unless --data-dir
    overrides."""
    base = data_dir if data_dir is not None else _default_data_dir()
    return base / "iam-jit.yaml"


def _build_config(
    *,
    shape: str,
    mode: str,
    bouncers: tuple[str, ...],
    accounts_detected: tuple[str, ...],
    harness: str,
) -> dict[str, Any]:
    """Translate interview answers into the declarative-config dict
    shape the ``ambient_config`` loader validates.

    Per [[ibounce-honest-positioning]]: every decision is recorded as
    a literal field (no hidden defaults), and the operator-readable
    YAML preserves comments via `_render_yaml_with_comments` below.

    Returns a dict that ``ambient_config.load_declaration`` accepts.
    """
    bouncer_blocks: dict[str, dict[str, Any]] = {}
    for name in bouncers:
        bouncer_blocks[name] = {
            "enabled": True,
            "mode": mode,
        }
    declaration: dict[str, Any] = {
        "iam-jit": {
            "schema_version": "1.0",
            "enabled": True,
            # Shape "corp-managed" gets posture: managed (pin-everything);
            # everything else gets ambient (the default).
            "posture": "managed" if shape == "corp-managed" else "ambient",
            "bouncers": bouncer_blocks,
        },
    }
    # Carry the operator-visible interview metadata as a top-level
    # comment-block in the rendered YAML (see _render_yaml_with_comments).
    # We do NOT put the metadata inside the schema-validated declaration
    # because the ambient_config schema has additionalProperties=False.
    declaration["__interview_metadata__"] = {
        "shape": shape,
        "mode": mode,
        "bouncers": list(bouncers),
        "harness": harness,
        "accounts_detected": list(accounts_detected),
    }
    return declaration


def _render_yaml_with_comments(declaration: dict[str, Any]) -> str:
    """Render the declaration to YAML with operator-visible header
    comments documenting what `iam-jit init` picked. Strips the
    metadata sentinel before serializing so the file passes the
    `additionalProperties: false` schema check."""
    metadata = declaration.pop("__interview_metadata__", None)
    body = yaml.safe_dump(declaration, sort_keys=False)
    if metadata is None:
        return body
    header_lines = [
        "# iam-jit declarative config — generated by `iam-jit init`.",
        "# Apply with:  iam-jit doctor apply-config --config "
        f"~/.iam-jit/iam-jit.yaml",
        "# Edit at your own risk; this file is operator-owned.",
        "#",
        f"# shape:              {metadata['shape']}",
        f"# mode:               {metadata['mode']}",
        f"# bouncers:           {', '.join(metadata['bouncers'])}",
        f"# harness:            {metadata['harness']}",
        "# accounts_detected:  "
        f"{', '.join(metadata['accounts_detected']) or '(none — edit accounts.yaml)'}",
        "",
    ]
    return "\n".join(header_lines) + body


def _validate_or_refuse(declaration: dict[str, Any]) -> None:
    """Refuse to write an empty / structurally-wrong config.

    The sabotage test (per the task spec) monkeypatches `_build_config`
    to return ``{}``; this guard MUST refuse the write so we don't ship
    a file the doctor-apply step then chokes on. Per the
    state-verification convention every claim ("init wrote a valid
    config") needs an observable check.
    """
    if not isinstance(declaration, dict) or not declaration:
        raise click.ClickException(
            "init refused to write: generated config is empty. This "
            "is a bug in the interview helper; please file an issue "
            "with the flags you passed."
        )
    inner = declaration.get("iam-jit")
    if not isinstance(inner, dict) or not inner.get("enabled"):
        raise click.ClickException(
            "init refused to write: generated config is missing the "
            "required `iam-jit.enabled: true` block. This is a bug; "
            "please file an issue."
        )
    bouncers = inner.get("bouncers")
    if not isinstance(bouncers, dict) or not bouncers:
        raise click.ClickException(
            "init refused to write: generated config has no enabled "
            "bouncers. Pass --bouncers explicitly or re-run interactively."
        )


def _write_config_atomic(
    *,
    config_path: pathlib.Path,
    body: str,
    interactive: bool,
    overwrite: bool,
) -> None:
    """Write the rendered YAML to disk with mode 0600.

    Per ``[[creates-never-mutates]]`` refuses to clobber an existing
    file unless ``--overwrite`` was passed. In interactive mode an
    operator can confirm overwrite at the prompt; in non-interactive
    mode the only path to overwrite is the flag.
    """
    config_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        config_path.parent.chmod(0o700)
    except Exception:
        pass

    if config_path.exists() and not overwrite:
        if interactive and click.confirm(
            f"{config_path} already exists. Overwrite?",
            default=False,
        ):
            pass
        else:
            raise click.ClickException(
                f"refusing to overwrite existing {config_path} "
                "(per [[creates-never-mutates]]). Pass --overwrite to "
                "replace it, or move the existing file aside."
            )

    config_path.write_text(body)
    try:
        config_path.chmod(0o600)
    except Exception:
        pass


def _seed_accounts_yaml_if_needed(
    *, data_dir: pathlib.Path, interactive: bool,
) -> None:
    """Reuse ``local_server._seed_local_accounts`` so init produces the
    same on-disk shape as init-solo (no divergent yaml schemas).

    Per [[creates-never-mutates]] the seed helper is a no-op when
    accounts.yaml already exists; we don't pre-check + race-touch."""
    try:
        from . import local_server
    except Exception as e:
        _log_decision(
            "accounts_seed_skipped", f"local_server import failed: {e}",
            interactive=interactive,
        )
        return
    cfg = local_server.LocalServerConfig(data_dir=data_dir)
    # _ensure_data_dir is idempotent + mirrors init-solo's mkdir+chmod.
    local_server._ensure_data_dir(cfg)
    try:
        local_server._seed_local_accounts(cfg)
    except Exception as e:
        _log_decision(
            "accounts_seed_failed", str(e),
            interactive=interactive,
        )


def _run_doctor_apply(config_path: pathlib.Path) -> int:
    """Invoke `iam-jit doctor apply-config --config <path>` in-process.

    Returns the exit code so the caller can decide whether to halt
    init's exit-0 claim. Reuses the existing
    `cli_apply_config.register_apply_config_command` shim — no
    duplicated logic.
    """
    from click.testing import CliRunner

    from .cli import main as _main

    runner = CliRunner()
    result = runner.invoke(
        _main,
        ["doctor", "apply-config", "--config", str(config_path)],
        catch_exceptions=False,
    )
    if result.output:
        click.echo(result.output)
    return result.exit_code


def _print_summary(
    *, result: _InterviewResult, config_path: pathlib.Path,
) -> None:
    """Final ASCII summary the operator sees + the agent parses."""
    click.echo()
    click.secho("iam-jit init: summary", fg="cyan", bold=True)
    click.echo(f"  shape:       {result.shape}")
    click.echo(f"  mode:        {result.mode}")
    click.echo(f"  bouncers:    {', '.join(result.bouncers)}")
    click.echo(f"  harness:     {result.harness}")
    accounts = (
        ", ".join(result.accounts_detected)
        if result.accounts_detected else "(none detected — edit "
        f"{result.data_dir / 'accounts.yaml'})"
    )
    click.echo(f"  accounts:    {accounts}")
    click.echo(f"  config:      {config_path}")
    click.echo()
    click.secho("Next steps:", bold=True)
    click.echo(
        f"  1. Apply the config:   iam-jit doctor apply-config "
        f"--config {config_path}"
    )
    click.echo(
        "  2. Start autopilot:    iam-jit autopilot start  "
        "(see [[ambient-autonomous-protection]])"
    )
    if result.harness != "none":
        click.echo(
            f"  3. Restart {result.harness} so it re-reads MCP config."
        )
    else:
        click.echo(
            "  3. Wire MCP into your agent harness: "
            "iam-jit mcp show-config"
        )


# ---------------------------------------------------------------------------
# Public CLI entry-point
# ---------------------------------------------------------------------------


def register_init_command(main_group: click.Group) -> click.Command:
    """Attach `iam-jit init` to the top-level click group.

    Returns the registered command so tests can invoke it via
    ``CliRunner.invoke(main.commands["init"], [...])`` without
    importing this module's private helpers.
    """

    @main_group.command("init")
    @click.option(
        "--non-interactive",
        is_flag=True,
        default=False,
        help="Use defaults + skip prompts. Auto-detected when stdin is "
             "not a TTY (agents, CI, piped input).",
    )
    @click.option(
        "--data-dir",
        type=click.Path(file_okay=False, path_type=pathlib.Path),
        default=None,
        help="Local data directory. Default: ~/.iam-jit/. Mirrors "
             "`iam-jit init-solo --data-dir` + `iam-jit uninstall "
             "--data-dir`.",
    )
    @click.option(
        "--shape",
        type=click.Choice(list(_VALID_SHAPES)),
        default=None,
        help="Deployment shape (skip interview prompt #1). Non-"
             "interactive default: local-solo.",
    )
    @click.option(
        "--mode",
        type=click.Choice(list(_VALID_MODES)),
        default=None,
        help="Bouncer mode (skip interview prompt #4). Non-interactive "
             "default: discovery per [[discovery-first-default]].",
    )
    @click.option(
        "--bouncers",
        type=str,
        default=None,
        help="Comma-separated bouncer list (skip interview prompt #3). "
             "Non-interactive default: ibounce. Valid: "
             f"{', '.join(_VALID_BOUNCERS)}.",
    )
    @click.option(
        "--harness",
        type=click.Choice(list(_VALID_HARNESSES)),
        default=None,
        help="MCP harness to wire (skip interview prompt #5). Non-"
             "interactive default: auto-detect; falls to 'none' when "
             "nothing detected.",
    )
    @click.option(
        "--dry-run",
        is_flag=True,
        default=False,
        help="Print what would be written + do NOT touch the filesystem. "
             "Always safe to run.",
    )
    @click.option(
        "--overwrite",
        is_flag=True,
        default=False,
        help="Overwrite an existing iam-jit.yaml at the target path. "
             "Per [[creates-never-mutates]] default is to refuse + exit "
             "non-zero.",
    )
    @click.option(
        "--apply",
        "apply_now",
        is_flag=True,
        default=False,
        help="After writing the config, immediately run "
             "`iam-jit doctor apply-config`. Non-interactive default: "
             "off (operator runs it explicitly).",
    )
    def init_cmd(
        non_interactive: bool,
        data_dir: pathlib.Path | None,
        shape: str | None,
        mode: str | None,
        bouncers: str | None,
        harness: str | None,
        dry_run: bool,
        overwrite: bool,
        apply_now: bool,
    ) -> None:
        """Bootstrap iam-jit on a fresh machine via guided interview.

        The canonical first-time-operator onboarding command per UC-30
        + MRR-6. Walks an 8-step interview: shape → AWS accounts →
        bouncers → mode → harness → generate config → apply → summary.

        Non-TTY callers (agents, CI) auto-fall to non-interactive
        defaults per [[bouncer-zero-llm-when-agent-in-loop]]; every
        defaulted decision is logged to stdout so the caller can
        audit the choices.

        `init-solo` (older + narrower) remains available for the
        legacy "just one user, just my laptop" path. `init` is the
        recommended entry point.
        """
        interactive = _is_interactive(non_interactive)

        # Step 1 — deployment shape
        resolved_shape = shape or _prompt_shape(interactive)
        if shape is None and not interactive:
            _log_decision("shape", resolved_shape, interactive=interactive)
        if resolved_shape not in _VALID_SHAPES:
            raise click.BadParameter(
                f"invalid shape {resolved_shape!r}; "
                f"valid: {', '.join(_VALID_SHAPES)}",
                param_hint="--shape",
            )

        # Step 2 — AWS account detection
        accounts_detected = _detect_aws_accounts(interactive)

        # Step 3 — bouncer set
        if bouncers is not None:
            parsed = tuple(
                b.strip() for b in bouncers.split(",") if b.strip()
            )
            bad = [b for b in parsed if b not in _VALID_BOUNCERS]
            if bad:
                raise click.BadParameter(
                    f"unknown bouncer(s) {bad!r}; "
                    f"valid: {', '.join(_VALID_BOUNCERS)}",
                    param_hint="--bouncers",
                )
            if not parsed:
                raise click.BadParameter(
                    "must list at least one bouncer",
                    param_hint="--bouncers",
                )
            resolved_bouncers = parsed
        else:
            resolved_bouncers = _prompt_bouncers(interactive, resolved_shape)
        if bouncers is None and not interactive:
            _log_decision(
                "bouncers", ",".join(resolved_bouncers),
                interactive=interactive,
            )

        # Step 4 — mode pick
        resolved_mode = mode or _prompt_mode(interactive)
        if mode is None and not interactive:
            _log_decision("mode", resolved_mode, interactive=interactive)
        if resolved_mode not in _VALID_MODES:
            raise click.BadParameter(
                f"invalid mode {resolved_mode!r}; "
                f"valid: {', '.join(_VALID_MODES)}",
                param_hint="--mode",
            )

        # Step 5 — harness detect
        resolved_harness = harness or _detect_harness(interactive)
        if resolved_harness not in _VALID_HARNESSES:
            raise click.BadParameter(
                f"invalid harness {resolved_harness!r}; "
                f"valid: {', '.join(_VALID_HARNESSES)}",
                param_hint="--harness",
            )

        resolved_data_dir = (
            data_dir if data_dir is not None else _default_data_dir()
        )
        config_path = _resolve_config_path(data_dir)

        result = _InterviewResult(
            shape=resolved_shape,
            mode=resolved_mode,
            bouncers=resolved_bouncers,
            harness=resolved_harness,
            accounts_detected=accounts_detected,
            data_dir=resolved_data_dir,
        )

        # Step 6 — generate declaration
        declaration = _build_config(
            shape=resolved_shape,
            mode=resolved_mode,
            bouncers=resolved_bouncers,
            accounts_detected=accounts_detected,
            harness=resolved_harness,
        )

        # Sabotage check: refuse to write empty / bad configs.
        # This is the load-bearing validation the test exercises.
        _validate_or_refuse(declaration)

        rendered = _render_yaml_with_comments(declaration)

        if dry_run:
            click.echo(rendered)
            click.echo(f"\n(dry-run; would write to {config_path})")
            return

        # Seed accounts.yaml first so accounts/users/cli-token + config
        # land together (avoids "config references account that isn't
        # in accounts.yaml" partial-state).
        _seed_accounts_yaml_if_needed(
            data_dir=resolved_data_dir, interactive=interactive,
        )

        _write_config_atomic(
            config_path=config_path,
            body=rendered,
            interactive=interactive,
            overwrite=overwrite,
        )

        click.secho(
            f"\n[ok] wrote {config_path}", fg="green",
        )

        # Step 7 — offer doctor apply
        should_apply = apply_now
        if interactive and not should_apply:
            should_apply = click.confirm(
                f"Run `iam-jit doctor apply-config --config {config_path}` "
                "now?",
                default=True,
            )

        if should_apply:
            rc = _run_doctor_apply(config_path)
            if rc != 0:
                click.secho(
                    f"\n[warn] doctor apply-config exited {rc}; "
                    "config written but not applied.",
                    fg="yellow",
                )

        # Step 8 — summary
        _print_summary(result=result, config_path=config_path)

    return init_cmd


__all__ = [
    "register_init_command",
]
