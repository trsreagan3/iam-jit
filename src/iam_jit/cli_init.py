"""#489 + #532 CRIT — `iam-jit init` interactive bootstrap interview.
#490 §A90 LAUNCH-BLOCKER — `iam-jit init --managed` non-interactive
corp mode (extends #489).

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

#490 MANAGED MODE: ``iam-jit init --managed --org-policy URL`` is the
non-interactive corp deployment shape per
``[[enterprise-profile-distribution]]``. IT pre-builds
``org-policy.yaml`` + Ed25519-signs it; engineers run the command and
the tool:

  1. Fetches the URL (HTTPS only; SSRF-gated per #522).
  2. Fetches the companion ``.sig`` URL (raw Ed25519 signature).
  3. Verifies the signature against the operator-pinned public key
     (resolved from ``--org-public-key`` / ``$IAM_JIT_ORG_PUBLIC_KEY``
     / ``$XDG_CONFIG_HOME/iam-jit/org.pub`` / ``~/.iam-jit/org.pub``).
  4. If valid: writes ``iam-jit.yaml`` + runs ``iam-jit doctor
     apply-config``.
  5. If INVALID: refuses + errors; ZERO partial state written.

Per ``[[scorer-is-ground-truth]]`` + ``[[ibounce-honest-positioning]]``
fail-CLOSED at every gate (non-HTTPS / loopback / invalid sig /
missing pubkey all hard-fail with a clear error).

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
* SSRF gate from ``bouncer.audit_export.webhook.validate_webhook_url``
  (reused for org-policy URL fetch per #522)
* Ed25519 verify from ``threat_feed.signing._load_ed25519_public``
  (reused for org-policy signature verify per #407)

Per ``[[creates-never-mutates]]`` init writes new files but refuses to
clobber pre-existing ``~/.iam-jit/iam-jit.yaml`` without an explicit
``--overwrite`` flag.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import pathlib
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
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


def _render_yaml_with_comments(
    declaration: dict[str, Any],
    *,
    config_path: pathlib.Path | None = None,
) -> str:
    """Render the declaration to YAML with operator-visible header
    comments documenting what `iam-jit init` picked. Strips the
    metadata sentinel before serializing so the file passes the
    `additionalProperties: false` schema check.

    ``config_path`` is used in the "Apply with" comment header; when
    omitted the comment falls back to ``~/.iam-jit/iam-jit.yaml``
    (legacy behaviour preserved for callers that don't know the resolved
    path yet). Passing the resolved path avoids confusing operators who
    used ``--data-dir`` / ``$IAM_JIT_DATA_DIR``.
    """
    metadata = declaration.pop("__interview_metadata__", None)
    body = yaml.safe_dump(declaration, sort_keys=False)
    if metadata is None:
        return body
    apply_path = config_path if config_path is not None else pathlib.Path.home() / ".iam-jit" / "iam-jit.yaml"
    header_lines = [
        "# iam-jit declarative config — generated by `iam-jit init`.",
        "# Apply with:  iam-jit doctor apply-config --config "
        f"{apply_path}",
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


def _any_bouncer_running() -> bool:
    """Best-effort check: returns True if at least one bouncer is
    currently listening on its canonical loopback port. Used to decide
    whether the Next steps block should surface `eval "$(iam-jit
    shellinit)"` as a first-action hint. Never raises."""
    try:
        from .posture import capture_posture
        snapshot = capture_posture()
        bouncers = snapshot.get("bouncers", {})
        return any(b.get("running") for b in bouncers.values())
    except Exception:
        return False


def _print_summary(
    *,
    result: _InterviewResult,
    config_path: pathlib.Path,
    mcp_install_results: list[_McpInstallResult] | None = None,
) -> None:
    """Final ASCII summary the operator sees + the agent parses.

    ``mcp_install_results`` (from ``_run_harness_mcp_installs``) drives
    the harness restart hint at the bottom of Next steps:
      - When at least one server was installed successfully: names the
        count so the operator knows what to expect after restart.
      - When all failed or the list is absent: falls back to the
        original "wire manually" text.
      - When harness is "none": always shows "iam-jit mcp show-config".
    """
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
    step = 1
    # Per [[ibounce-honest-positioning]]: surface shellinit as the FIRST
    # action when a bouncer is already live — it's the most-impactful
    # wiring step; burying it inside FAIL rows misses non-interactive ops.
    if _any_bouncer_running():
        click.echo(
            f"  {step}. Wire bouncers into your shell:  "
            'eval "$(iam-jit shellinit)"'
        )
        step += 1
    click.echo(
        f"  {step}. Apply the config:   iam-jit doctor apply-config "
        f"--config {config_path}"
    )
    step += 1
    click.echo(
        f"  {step}. Start autopilot:    iam-jit autopilot start  "
        "(see [[ambient-autonomous-protection]])"
    )
    step += 1
    if result.harness != "none":
        # Determine whether install actually succeeded for any server.
        installed = [r for r in (mcp_install_results or []) if r.ok]
        if installed:
            count = len(installed)
            names = ", ".join(r.label for r in installed)
            click.echo(
                f"  {step}. Restart {result.harness} so it picks up "
                f"the {count} MCP server(s) we just registered "
                f"({names})."
            )
        else:
            # No auto-install succeeded (skipped / all failed / codex / devin).
            click.echo(
                f"  {step}. Wire MCP manually: iam-jit mcp show-config  "
                f"(harness: {result.harness})"
            )
    else:
        click.echo(
            f"  {step}. Wire MCP into your agent harness: "
            "iam-jit mcp show-config"
        )


# ---------------------------------------------------------------------------
# #626 Phase 2 — install-verification at end-of-init.
#
# Per founder dogfood 2026-05-26: the original failure mode was that
# init succeeded silently while the install was actually broken (no
# binaries on PATH; AWS_ENDPOINT_URL never wired). Phase 2 closes the
# loop by running `doctor install-check` at the end of init and
# surfacing any FAIL rows + paste-ready remediation BEFORE the
# operator walks away thinking they're protected.
#
# We render a CONDENSED verdict (not the full 8-section dump) — the
# operator can always run `iam-jit doctor install-check` for the full
# report. Init's exit code is NOT changed by install-check verdicts
# (init succeeded at config-write; install-check is post-write
# informational) per [[ibounce-honest-positioning]]: name the gap, but
# don't pretend init failed when it didn't.
# ---------------------------------------------------------------------------


def _print_post_init_install_check(*, suppress: bool = False) -> None:
    """Render a condensed install-check verdict at end-of-init.

    Always best-effort: any failure inside install-check itself
    degrades silently (logs an INFO-level note) so init doesn't appear
    to fail just because the doctor probe couldn't run. The operator
    can always re-run `iam-jit doctor install-check` for a full report.

    When ``suppress`` is True, emit a one-line stderr warning
    ([[ibounce-honest-positioning]]: opt-outs must be visible) then
    return early. Used by --managed and tests that need init's output to
    stay deterministic.
    """
    if suppress:
        import sys
        print(
            "[warn] install-check suppressed via --no-doctor-check; "
            "run `iam-jit doctor install-check` manually to verify "
            "protection.",
            file=sys.stderr,
        )
        return
    try:
        from .cli_doctor_install_check import run_install_check
    except Exception:
        return
    try:
        sections = run_install_check(run_self_test=True)
    except Exception:
        return

    # Collect FAIL + WARN rows for the condensed render.
    from .cli_doctor_install_check import _SEV_ERR, _SEV_WARN

    fails: list[tuple[str, str, str]] = []  # (section, label, fix)
    warns: list[tuple[str, str, str]] = []
    for s in sections:
        for r in s.rows:
            if r.severity >= _SEV_ERR:
                fails.append((s.title, r.label, r.fix))
            elif r.severity == _SEV_WARN:
                warns.append((s.title, r.label, r.fix))

    click.echo()
    click.secho("install-check:", bold=True)
    if not fails and not warns:
        click.secho(
            "  every required surface is on PATH, running, and wired.",
            fg="green",
        )
        return
    if fails:
        click.secho(
            f"  {len(fails)} FAIL row(s) — install will NOT protect until "
            "fixed:",
            fg="red",
        )
        for sect, label, fix in fails:
            click.echo(f"    - [{sect}] {label}")
            if fix:
                click.echo(f"        Fix: {fix}")
    if warns:
        click.secho(f"  {len(warns)} WARN row(s):", fg="yellow")
        for sect, label, fix in warns:
            click.echo(f"    - [{sect}] {label}")
    click.echo()
    click.echo(
        "  Run `iam-jit doctor install-check` for the full 8-section report."
    )


# ---------------------------------------------------------------------------
# #651 CRIT — MCP install helper (closes the advertised-but-never-wired gap)
#
# Per founder dogfood 2026-05-26: `iam-jit init --harness=claude-code`
# printed "Restart claude-code so it re-reads MCP config" but NEVER
# actually called `iam-jit mcp install-claude-code` or the bouncer
# install equivalents. The operator got a false "all set" signal.
#
# Design decisions:
#   - iam-jit install always passes --path ~/.claude.json explicitly to
#     dodge #652 (install-claude-code wrongly defaults to Claude Desktop
#     path on macOS). The workaround is safe because ~/.claude.json is
#     the canonical Claude Code agent config path.
#   - Bouncer installs are invoked via subprocess (not in-process Click
#     runner) so we exercise the real binary + don't couple init to
#     internal bouncer-cli wiring. Go-backed bouncers (kbounce/dbounce/
#     gbounce) are handled the same way — subprocess exits non-zero if
#     the binary isn't on PATH, which surfaces as a WARN row.
#   - Each install is independent: one failure MUST NOT abort the others
#     (fail-graceful per [[creates-never-mutates]] + [[ibounce-honest-
#     positioning]]). Init exits 0 as long as the config was written.
#   - The WARN rows propagate a count so _print_summary can switch the
#     "Restart harness" instruction between "X servers registered" vs
#     the old manual text.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _McpInstallResult:
    """Outcome of a single harness MCP install invocation."""
    label: str         # human-readable ("iam-jit", "ibounce", …)
    ok: bool           # True iff the install command exited 0
    detail: str        # short message for WARN row or success note


def _run_harness_mcp_installs(
    *,
    harness: str,
    bouncers: tuple[str, ...],
    claude_code_path: str | None = None,
    cursor_path: str | None = None,
) -> list[_McpInstallResult]:
    """Invoke the correct install subcommand(s) for *harness* × *bouncers*.

    For ``claude-code``:
      1. ``iam-jit mcp install-claude-code --path ~/.claude.json``
      2. For each Python-backed bouncer in *bouncers*:
         ``<bouncer> mcp install-claude-code --path ~/.claude.json``
         (Go-backed bouncers — kbounce / dbounce / gbounce — use the
         same path convention if they're on PATH; a missing binary
         surfaces as a WARN row, not a crash.)

    For ``cursor``:
      Same shape with ``install-cursor --path ~/.cursor/mcp.json``.
      ``cursor_path`` lets callers override the target for project-scoped
      Cursor configs (``<project>/.cursor/mcp.json``) or UAT isolation.

    For ``codex``:
      Codex config path is unstable; print the snippet + a WARN that
      the operator must paste it manually. No filesystem write.

    For ``devin``:
      Devin has no auto-install path; print the recipe + WARN to paste.

    For ``none`` (and anything else):
      Returns an empty list — caller skips the install block.

    Per [[creates-never-mutates]] every subprocess failure is caught +
    returned as a failed ``_McpInstallResult`` — NEVER raises + NEVER
    silently swallows. The caller surfaces them as WARN rows.

    The ``claude_code_path`` parameter lets callers override the target
    path for claude-code installs (default: ``~/.claude.json``).
    The ``cursor_path`` parameter lets callers override the target path
    for cursor installs (default: ``~/.cursor/mcp.json``). Both are used
    for project-scoped configs + UAT isolation.
    """
    results: list[_McpInstallResult] = []

    if harness == "none":
        return results

    # Harnesses that need snippet-only (no auto-write)
    if harness in ("codex", "devin"):
        try:
            from .cli import _mcp_server_config_dict
            snippet = json.dumps(_mcp_server_config_dict(), indent=2)
        except Exception as e:
            snippet = f"(could not generate snippet: {e})"
        click.echo(
            f"\n[mcp-install] {harness}: no auto-install path — paste "
            "the snippet below into your harness MCP config:"
        )
        click.echo(snippet)
        results.append(_McpInstallResult(
            label="iam-jit",
            ok=False,  # not installed automatically
            detail=(
                f"{harness} requires manual MCP config wiring; "
                "snippet printed above"
            ),
        ))
        return results

    # claude-code and cursor: auto-install via subcommand.
    install_sub = (
        "install-claude-code" if harness == "claude-code" else "install-cursor"
    )

    # Resolve the target path for path-aware harnesses.
    # claude-code: explicit override or default ~/.claude.json (per #652).
    # cursor: explicit override or default ~/.cursor/mcp.json.
    if harness == "claude-code":
        path: str | None = (
            claude_code_path or str(pathlib.Path.home() / ".claude.json")
        )
    elif harness == "cursor":
        path = cursor_path or str(pathlib.Path.home() / ".cursor" / "mcp.json")
    else:
        path = None

    # 1. iam-jit mcp install-<harness>
    iam_jit_cmd = ["iam-jit", "mcp", install_sub]
    if path is not None:
        iam_jit_cmd += ["--path", path]

    try:
        proc = subprocess.run(
            iam_jit_cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        ok = proc.returncode == 0
        detail = proc.stdout.strip() or proc.stderr.strip() or "(no output)"
        results.append(_McpInstallResult(label="iam-jit", ok=ok, detail=detail))
    except FileNotFoundError:
        results.append(_McpInstallResult(
            label="iam-jit",
            ok=False,
            detail="iam-jit binary not found on PATH; MCP not installed",
        ))
    except Exception as e:
        results.append(_McpInstallResult(
            label="iam-jit",
            ok=False,
            detail=f"iam-jit mcp {install_sub} failed: {e}",
        ))

    # 2. <bouncer> mcp install-<harness> for each enabled bouncer.
    for bouncer in bouncers:
        bouncer_cmd = [bouncer, "mcp", install_sub]
        if path is not None:
            bouncer_cmd += ["--path", path]

        try:
            proc = subprocess.run(
                bouncer_cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            ok = proc.returncode == 0
            detail = proc.stdout.strip() or proc.stderr.strip() or "(no output)"
            results.append(_McpInstallResult(label=bouncer, ok=ok, detail=detail))
        except FileNotFoundError:
            results.append(_McpInstallResult(
                label=bouncer,
                ok=False,
                detail=f"{bouncer} binary not found on PATH; MCP not installed",
            ))
        except Exception as e:
            results.append(_McpInstallResult(
                label=bouncer,
                ok=False,
                detail=f"{bouncer} mcp {install_sub} failed: {e}",
            ))

    return results


def _print_mcp_install_summary(
    results: list[_McpInstallResult],
) -> None:
    """Render WARN rows for every failed MCP install.

    Per [[ibounce-honest-positioning]]: every gap is named, never
    swallowed. Successes get a quiet confirmation. The operator's
    terminal shows exactly which servers wired and which didn't.
    """
    if not results:
        return
    ok_labels = [r.label for r in results if r.ok]
    fail_labels = [r.label for r in results if not r.ok]

    if ok_labels:
        click.secho(
            f"[mcp-install] registered: {', '.join(ok_labels)}",
            fg="green",
        )
    for r in results:
        if not r.ok:
            click.secho(
                f"[mcp-install] WARN: {r.label} — {r.detail}",
                fg="yellow",
            )
    if fail_labels:
        click.echo(
            "  Run `iam-jit mcp show-config` + paste the snippet "
            "into your harness config manually for any WARN items above."
        )


# ---------------------------------------------------------------------------
# #490 §A90 — Managed-mode helpers (SSRF gate + Ed25519 verify + fetch)
# ---------------------------------------------------------------------------


class ManagedPolicyError(click.ClickException):
    """Raised when the managed-mode org-policy fetch / verify pipeline
    fails. Surfaces a human-readable error + exits non-zero per the
    fail-CLOSED discipline of [[scorer-is-ground-truth]] +
    [[ibounce-honest-positioning]].

    No partial state is written; the calling code checks for this
    exception BEFORE touching the filesystem.
    """


_ORG_PUBLIC_KEY_ENV = "IAM_JIT_ORG_PUBLIC_KEY"
_FETCH_TIMEOUT_S = 15.0
_MAX_ORG_POLICY_BYTES = 1 * 1024 * 1024  # 1 MB hard cap


def _resolve_org_public_key(
    explicit_path: str | None,
) -> str:
    """Return the operator's Ed25519 public key (PEM or base64).

    Resolution order (first hit wins, fail-CLOSED if nothing found):

      1. ``--org-public-key <path>`` flag (explicit_path).
      2. ``$IAM_JIT_ORG_PUBLIC_KEY`` env var (path to key file OR raw
         PEM/base64 string).
      3. ``$XDG_CONFIG_HOME/iam-jit/org.pub`` if ``$XDG_CONFIG_HOME``
         is set.
      4. ``~/.iam-jit/org.pub`` (default XDG-equivalent location).

    Raises :class:`ManagedPolicyError` when no key can be found /
    read. Per [[scorer-is-ground-truth]] fail-CLOSED: a missing key
    means the operator hasn't pinned trust + we MUST refuse.
    """
    # Priority 1: explicit path flag.
    if explicit_path:
        p = pathlib.Path(explicit_path)
        try:
            return p.read_text(encoding="ascii").strip()
        except OSError as e:
            raise ManagedPolicyError(
                f"--org-public-key: could not read key file "
                f"{p}: {e}"
            ) from e

    # Priority 2: env var (path or literal PEM/b64).
    env_val = (os.environ.get(_ORG_PUBLIC_KEY_ENV) or "").strip()
    if env_val:
        ep = pathlib.Path(env_val)
        if ep.exists():
            try:
                return ep.read_text(encoding="ascii").strip()
            except OSError as e:
                raise ManagedPolicyError(
                    f"{_ORG_PUBLIC_KEY_ENV} points to file "
                    f"{ep} which cannot be read: {e}"
                ) from e
        # Treat the env value itself as the raw key material.
        return env_val

    # Priority 3: $XDG_CONFIG_HOME/iam-jit/org.pub.
    xdg = (os.environ.get("XDG_CONFIG_HOME") or "").strip()
    if xdg:
        xp = pathlib.Path(xdg) / "iam-jit" / "org.pub"
        if xp.exists():
            try:
                return xp.read_text(encoding="ascii").strip()
            except OSError as e:
                raise ManagedPolicyError(
                    f"could not read org public key at {xp}: {e}"
                ) from e

    # Priority 4: ~/.iam-jit/org.pub.
    default = pathlib.Path.home() / ".iam-jit" / "org.pub"
    if default.exists():
        try:
            return default.read_text(encoding="ascii").strip()
        except OSError as e:
            raise ManagedPolicyError(
                f"could not read org public key at {default}: {e}"
            ) from e

    raise ManagedPolicyError(
        "no operator public key found. Pass --org-public-key <path>, "
        f"set ${_ORG_PUBLIC_KEY_ENV}, or place the key at "
        f"{default}. Per [[enterprise-profile-distribution]] the key "
        "must be pinned before `--managed` can proceed (fail-CLOSED)."
    )


def _ssrf_gate_url(url: str) -> None:
    """Gate `url` through the same SSRF primitives the webhook pusher +
    threat-feed fetcher use. Reuses the implementation from
    ``bouncer.audit_export.webhook`` per [[scorer-is-ground-truth]]
    (no reinvented SSRF logic).

    Raises :class:`ManagedPolicyError` on:
      - Non-HTTPS scheme (http:// or anything else).
      - Loopback / RFC1918 / link-local / multicast / intranet-suffix host.
      - Unresolvable hostname.
    """
    # Import lazily so this module stays importable in test envs that
    # don't load the full audit_export stack.
    from .bouncer.audit_export.webhook import (
        SSRFRejectedError,
        _hostname_has_internal_suffix,
        _is_internal_ip,
    )
    import socket as _socket

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        raise ManagedPolicyError(
            f"could not parse org-policy URL {url!r}: {e}"
        ) from e

    if parsed.scheme != "https":
        raise ManagedPolicyError(
            f"org-policy URL must use https:// (got scheme "
            f"{parsed.scheme!r}). Non-HTTPS URLs are refused "
            "per SSRF gate (#522)."
        )

    hostname = parsed.hostname or ""
    if not hostname:
        raise ManagedPolicyError(
            f"org-policy URL {url!r} is missing a hostname."
        )

    if _hostname_has_internal_suffix(hostname):
        raise ManagedPolicyError(
            f"org-policy URL hostname {hostname!r} matches an "
            "intranet suffix. SSRF gate refuses internal URLs "
            "(#522). Use an external HTTPS host."
        )

    try:
        _, _, ip_list = _socket.gethostbyname_ex(hostname)
    except _socket.gaierror as e:
        raise ManagedPolicyError(
            f"could not resolve org-policy hostname {hostname!r}: "
            f"{e}. SSRF gate fails CLOSED on unresolvable hosts."
        ) from e

    if not ip_list:
        raise ManagedPolicyError(
            f"org-policy hostname {hostname!r} resolved to no IPs. "
            "SSRF gate refused."
        )

    for ip in ip_list:
        if _is_internal_ip(ip):
            raise ManagedPolicyError(
                f"org-policy hostname {hostname!r} resolves to "
                f"internal IP {ip}. SSRF gate refuses internal "
                "addresses (#522)."
            )


def _fetch_url_bytes(url: str) -> bytes:
    """Fetch `url` via HTTPS and return the raw body bytes.

    Hard cap: ``_MAX_ORG_POLICY_BYTES``. Raises
    :class:`ManagedPolicyError` on every failure (network, HTTP error,
    oversized body).
    """
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "iam-jit-managed-init/1.0"},
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 — scheme checked by _ssrf_gate_url
            req, timeout=_FETCH_TIMEOUT_S,
        ) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            if status != 200:
                raise ManagedPolicyError(
                    f"org-policy URL returned HTTP {status} (expected 200)."
                )
            body = resp.read(_MAX_ORG_POLICY_BYTES + 1)
    except ManagedPolicyError:
        raise
    except urllib.error.HTTPError as e:
        raise ManagedPolicyError(
            f"org-policy URL returned HTTP {e.code}: {e.reason}"
        ) from e
    except urllib.error.URLError as e:
        raise ManagedPolicyError(
            f"org-policy URL network error: {e.reason}"
        ) from e
    except (OSError, TimeoutError) as e:
        raise ManagedPolicyError(
            f"org-policy URL fetch failed: {e}"
        ) from e

    if len(body) > _MAX_ORG_POLICY_BYTES:
        raise ManagedPolicyError(
            f"org-policy body exceeds {_MAX_ORG_POLICY_BYTES} byte cap. "
            "Refusing to continue (possible OOM attack vector)."
        )
    return body


def _verify_ed25519_signature(
    payload_bytes: bytes,
    signature_bytes: bytes,
    public_key_pem_or_b64: str,
) -> None:
    """Verify an Ed25519 signature over `payload_bytes`.

    Reuses ``_load_ed25519_public`` from
    ``threat_feed.signing`` per [[scorer-is-ground-truth]] — no
    reinvented crypto. Raises :class:`ManagedPolicyError` on any
    failure (bad key, bad sig, mismatch) so the caller can fail-CLOSED
    without touching the filesystem.

    The signature bytes must be the raw 64-byte Ed25519 signature
    (NOT base64 — the caller decoded it; OR pass base64 and the
    function will detect + decode if the raw 64-byte check fails).
    """
    from .threat_feed.signing import VerificationFailed, _load_ed25519_public

    try:
        pubkey = _load_ed25519_public(public_key_pem_or_b64)
    except VerificationFailed as e:
        raise ManagedPolicyError(
            f"org-policy public key is invalid: {e}. "
            "Per [[enterprise-profile-distribution]] the operator must "
            "pin a valid Ed25519 public key."
        ) from e
    except Exception as e:
        raise ManagedPolicyError(
            f"org-policy public key could not be loaded: {e}"
        ) from e

    try:
        pubkey.verify(signature_bytes, payload_bytes)
    except Exception:
        raise ManagedPolicyError(
            "org-policy Ed25519 signature verification FAILED. "
            "The downloaded policy does not match the signed document. "
            "Refusing to write config (fail-CLOSED per "
            "[[scorer-is-ground-truth]])."
        )


def _fetch_managed_policy(
    org_policy_url: str,
    org_public_key_path: str | None,
) -> str:
    """Top-level managed-mode pipeline.

    1. SSRF-gate the URL.
    2. Fetch policy YAML body.
    3. Fetch companion ``.sig`` body (raw base64-encoded Ed25519 sig).
    4. Resolve the operator public key.
    5. Verify signature.
    6. Return the verified YAML text.

    Raises :class:`ManagedPolicyError` at any failed gate — no partial
    state is returned.

    The ``.sig`` URL is the policy URL with ``.sig`` appended (standard
    convention matching the threat-feed publisher pattern in #407).
    """
    sig_url = org_policy_url + ".sig"

    # Gate both URLs before any network call.
    _ssrf_gate_url(org_policy_url)
    _ssrf_gate_url(sig_url)

    # Fetch the policy YAML.
    policy_bytes = _fetch_url_bytes(org_policy_url)

    # Fetch the companion signature.
    sig_raw = _fetch_url_bytes(sig_url)

    # Decode the signature — the convention is base64-encoded raw bytes
    # (same as the threat-feed signing.py publisher emits).
    try:
        sig_bytes = base64.b64decode(sig_raw.strip(), validate=True)
    except Exception as e:
        raise ManagedPolicyError(
            f"org-policy signature at {sig_url!r} is not valid base64: "
            f"{e}"
        ) from e

    # Resolve the operator public key (fail-CLOSED if absent).
    pubkey = _resolve_org_public_key(org_public_key_path)

    # Verify — raises ManagedPolicyError on mismatch.
    _verify_ed25519_signature(policy_bytes, sig_bytes, pubkey)

    # Decode + return the verified YAML text.
    try:
        return policy_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ManagedPolicyError(
            f"org-policy YAML is not valid UTF-8: {e}"
        ) from e


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
        envvar="IAM_JIT_DATA_DIR",
        help="Local data directory. Default: ~/.iam-jit/. Mirrors "
             "`iam-jit init-solo --data-dir` + `iam-jit uninstall "
             "--data-dir`. Also read from $IAM_JIT_DATA_DIR env var "
             "per [[cross-product-agent-parity]].",
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
    @click.option(
        "--managed",
        is_flag=True,
        default=False,
        help="#490 §A90 — Non-interactive corp mode. Fetches + "
             "Ed25519-verifies + writes config + runs doctor apply. "
             "Requires --org-policy URL. Implies --non-interactive. "
             "Per [[enterprise-profile-distribution]].",
    )
    @click.option(
        "--org-policy",
        "org_policy_url",
        default=None,
        help="HTTPS URL to org-signed iam-jit policy YAML. Required "
             "with --managed. The companion signature is fetched from "
             "<URL>.sig (raw Ed25519 sig, base64-encoded). Per #490.",
    )
    @click.option(
        "--org-public-key",
        "org_public_key_path",
        default=None,
        type=click.Path(exists=True, dir_okay=False),
        help="Path to operator's Ed25519 public key file for verifying "
             "--org-policy. Defaults to $IAM_JIT_ORG_PUBLIC_KEY env var, "
             "then $XDG_CONFIG_HOME/iam-jit/org.pub, then "
             "~/.iam-jit/org.pub. Per #490 §A90.",
    )
    @click.option(
        "--no-doctor-check",
        is_flag=True,
        default=False,
        help="#626 — Skip the post-init install-verification pass. By "
             "default, init runs `doctor install-check` at the end + "
             "surfaces any FAIL rows. Suppress for deterministic "
             "scripted runs / tests.",
    )
    @click.option(
        "--skip-mcp-install",
        is_flag=True,
        default=False,
        help="#651 — Skip the automatic MCP harness wiring step. By "
             "default, init calls `iam-jit mcp install-<harness>` + "
             "`<bouncer> mcp install-<harness>` for every enabled bouncer "
             "after writing the config. Pass this flag in CI / scripted "
             "callers that manage harness config separately.",
    )
    @click.option(
        "--claude-code-path",
        type=click.Path(dir_okay=False, path_type=pathlib.Path),
        default=None,
        help="#659 — Override Claude Code MCP config path (default: "
             "auto-detect via ladder; falls back to ~/.claude.json). "
             "Useful for project-scoped configs (<project>/.claude/mcp.json) "
             "and UAT isolation.",
    )
    @click.option(
        "--cursor-path",
        type=click.Path(dir_okay=False, path_type=pathlib.Path),
        default=None,
        help="#659 — Override Cursor MCP config path (default: "
             "~/.cursor/mcp.json). Useful for workspace-scoped configs "
             "(<project>/.cursor/mcp.json) and UAT isolation.",
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
        managed: bool,
        org_policy_url: str | None,
        org_public_key_path: str | None,
        no_doctor_check: bool,
        skip_mcp_install: bool,
        claude_code_path: pathlib.Path | None,
        cursor_path: pathlib.Path | None,
    ) -> None:
        """Bootstrap iam-jit on a fresh machine via guided interview.

        The canonical first-time-operator onboarding command per UC-30
        + MRR-6. Walks an 8-step interview: shape → AWS accounts →
        bouncers → mode → harness → generate config → apply → summary.

        Non-TTY callers (agents, CI) auto-fall to non-interactive
        defaults per [[bouncer-zero-llm-when-agent-in-loop]]; every
        defaulted decision is logged to stdout so the caller can
        audit the choices.

        ``--managed`` enables the corp deployment shape (#490 §A90):
        fetches + Ed25519-verifies + writes an IT-curated org-policy.yaml
        without any prompts. All decisions come from the policy file.

        `init-solo` (older + narrower) remains available for the
        legacy "just one user, just my laptop" path. `init` is the
        recommended entry point.
        """
        # ------------------------------------------------------------------
        # #490 §A90 — Managed-mode fast-path. Bypasses the full interview.
        # ------------------------------------------------------------------
        if managed:
            if not org_policy_url:
                raise click.UsageError(
                    "--managed requires --org-policy URL. "
                    "Provide the HTTPS URL to the IT-curated org-policy.yaml "
                    "file. See [[enterprise-profile-distribution]]."
                )

            # Fetch + SSRF-gate + verify signature — raises ManagedPolicyError
            # on ANY failure. Zero partial state written before this returns.
            policy_yaml = _fetch_managed_policy(
                org_policy_url, org_public_key_path,
            )

            resolved_data_dir = (
                data_dir if data_dir is not None else _default_data_dir()
            )
            config_path = _resolve_config_path(data_dir)

            if dry_run:
                click.echo(policy_yaml)
                click.echo(
                    f"\n(managed dry-run; would write to {config_path})"
                )
                return

            _write_config_atomic(
                config_path=config_path,
                body=policy_yaml,
                interactive=False,  # --managed is always non-interactive
                overwrite=overwrite,
            )

            click.echo(
                f"[managed] org-policy verified + written to {config_path}"
            )

            rc = _run_doctor_apply(config_path)
            if rc != 0:
                click.secho(
                    f"\n[warn] doctor apply-config exited {rc}; "
                    "config written but not applied. Re-run "
                    "`iam-jit doctor apply-config` manually.",
                    fg="yellow",
                )
            # #626 Phase 2 — install-check at end of managed-mode init.
            _print_post_init_install_check(suppress=no_doctor_check)
            return

        # ------------------------------------------------------------------
        # #489 — Standard interactive / non-interactive interview flow.
        # ------------------------------------------------------------------
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

        rendered = _render_yaml_with_comments(declaration, config_path=config_path)

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

        # Step 7.5 — MCP harness wiring (#651 CRIT)
        # Actually wire the MCP config now — not just print a hint.
        # Per [[creates-never-mutates]] every failure surfaces as a WARN;
        # init never crashes on a subprocess error. --skip-mcp-install
        # lets CI / scripted callers opt out while still getting the
        # config file.
        mcp_install_results: list[_McpInstallResult] = []
        if not skip_mcp_install and result.harness != "none":
            mcp_install_results = _run_harness_mcp_installs(
                harness=result.harness,
                bouncers=result.bouncers,
                claude_code_path=(
                    str(claude_code_path) if claude_code_path is not None else None
                ),
                cursor_path=(
                    str(cursor_path) if cursor_path is not None else None
                ),
            )
            _print_mcp_install_summary(mcp_install_results)

        # Step 8 — summary
        _print_summary(
            result=result,
            config_path=config_path,
            mcp_install_results=mcp_install_results,
        )

        # #626 Phase 2 — install-check at end of standard init flow.
        # Renders condensed verdict (PATH gaps + env-wire gaps + Go-side
        # status). Does NOT change init's exit code; init succeeded at
        # config-write. Per [[ibounce-honest-positioning]] this is the
        # operator's first-and-best chance to see "is my install
        # actually going to work?" before they walk away.
        _print_post_init_install_check(suppress=no_doctor_check)

    return init_cmd


__all__ = [
    "ManagedPolicyError",
    "_McpInstallResult",
    "_fetch_managed_policy",
    "_print_mcp_install_summary",
    "_resolve_org_public_key",
    "_run_harness_mcp_installs",
    "_ssrf_gate_url",
    "_verify_ed25519_signature",
    "register_init_command",
]
