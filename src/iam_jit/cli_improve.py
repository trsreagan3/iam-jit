"""#401 / §A47 — `iam-jit improve-profile` CLI shim.

Thin operator-side CLI over :func:`iam_jit.improve.improve_profile`.
Mirrors the `iam_jit_improve_profile` MCP tool per
[[cross-product-agent-parity]]; same backend, same defaults.

Usage:

  iam-jit improve-profile                          # dry-run default
  iam-jit improve-profile --apply                  # actually install
  iam-jit improve-profile --bouncer ibounce
  iam-jit improve-profile --cadence-window 1h
  iam-jit improve-profile --json
"""

from __future__ import annotations

import json as _json
import sys

import click

from .improve import ImproveProfileError, improve_profile


def register_improve_command(parent_group: click.Group) -> click.Command:
    """Attach `improve-profile` to the top-level iam-jit Click group."""

    @parent_group.command("improve-profile")
    @click.option(
        "--bouncer",
        type=click.Choice(["ibounce", "kbouncer", "dbounce", "gbounce"]),
        default="ibounce",
        show_default=True,
        help="Which bouncer's profile to improve.",
    )
    @click.option(
        "--cadence",
        type=click.Choice(["per_session", "daily", "weekly", "never"]),
        default="per_session",
        show_default=True,
        help="Cadence label; controls default audit window.",
    )
    @click.option(
        "--cadence-window",
        type=str,
        default=None,
        help="Explicit window override (e.g. `1h`, `24h`, `7d`).",
    )
    @click.option(
        "--threshold",
        type=float,
        default=0.30,
        show_default=True,
        help="Auto-install when change_size < threshold; queue for "
             "approval otherwise.",
    )
    @click.option(
        "--apply",
        "apply_changes",
        is_flag=True,
        default=False,
        help="Actually mutate the profile. Default DRY-RUN.",
    )
    @click.option(
        "--posture",
        type=click.Choice(["ambient", "managed"]),
        default="ambient",
        show_default=True,
        help="Declaration posture; managed REFUSES auto-improve.",
    )
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit JSON.",
    )
    def improve_cmd(
        bouncer: str,
        cadence: str,
        cadence_window: str | None,
        threshold: float,
        apply_changes: bool,
        posture: str,
        as_json: bool,
    ) -> None:
        """Run one improve-profile cycle for the named bouncer.

        Per [[creates-never-mutates]] this never overwrites manually-
        authored allow rules. Per [[ibounce-honest-positioning]]
        managed-posture invocations REFUSE explicitly.
        """
        try:
            result = improve_profile(
                bouncer=bouncer,
                cadence=cadence,
                cadence_window=cadence_window,
                threshold=threshold,
                apply=apply_changes,
                posture=posture,
                source="cli",
            )
        except ImproveProfileError as e:
            payload = {
                "status": "error",
                "code": e.code,
                "message": str(e),
                "details": e.details,
            }
            if as_json:
                click.echo(_json.dumps(payload, indent=2))
            else:
                click.secho(f"improve-profile: {e}", fg="red", err=True)
            sys.exit(2)
        if as_json:
            click.echo(_json.dumps(result.as_dict(), indent=2, default=str))
            return
        _render_human(result)

    return improve_cmd


def _render_human(result) -> None:
    color_by_status = {
        "auto_installed": "green",
        "partial_install": "yellow",  # MRR-2 F1: honest amber
        "no_install": "red",  # MRR-2 F1: honest red
        "pending_approval": "yellow",
        "no_change": "cyan",
        "dry_run": "cyan",
        "managed_posture_refused": "yellow",
        "error": "red",
    }
    color = color_by_status.get(result.status, "cyan")
    click.secho(
        f"improve-profile [{result.bouncer}]: {result.status}",
        fg=color,
        bold=True,
    )
    click.echo(f"  cadence_window:   {result.cadence_window}")
    click.echo(f"  posture:          {result.posture}")
    click.echo(f"  rules_added:      {result.rules_added}")
    click.echo(f"  rules_removed:    {result.rules_removed}")
    click.echo(f"  scope_changes:    {len(result.scope_changes)}")
    click.echo(f"  change_size:      {result.change_size:.3f}")
    click.echo(f"  requires_approval: {result.requires_approval}")
    if result.audit_event_ids:
        click.echo(f"  audit_event_ids:")
        for ev in result.audit_event_ids:
            click.echo(f"    - {ev}")
    if result.pending_entry_ids:
        click.echo(f"  pending_entry_ids:")
        for pid in result.pending_entry_ids:
            click.echo(f"    - {pid}")
    if result.scope_changes:
        click.echo(f"  scope details:")
        for s in result.scope_changes:
            click.echo(f"    - {s}")
    # MRR-2 F1: surface installed_rules / failed_rules / recommended_action
    # so the operator can see WHICH rules landed (and WHY others didn't)
    # without parsing the explanation paragraph.
    failed = getattr(result, "failed_rules", None) or []
    if failed:
        click.secho(f"  failed_rules:     {len(failed)}", fg="red")
        for f in failed:
            click.echo(
                f"    - {f.get('action')} @ {f.get('target') or '<no target>'}: "
                f"{f.get('error_code')} — {f.get('error_message')}"
            )
    installed = getattr(result, "installed_rules", None) or []
    if installed and result.status in {"partial_install", "auto_installed"}:
        click.echo(f"  installed_rules:  {len(installed)}")
    rec = getattr(result, "recommended_action", "") or ""
    if rec:
        click.echo()
        click.secho(f"  recommended: {rec}", fg=color)
    if result.explanation:
        click.echo()
        click.secho(result.explanation, fg=color)


__all__ = ["register_improve_command"]
