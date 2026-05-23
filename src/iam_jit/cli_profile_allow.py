"""#345 / §A25 — `iam-jit profile allow` + `iam-jit denies recent` CLI.

Symmetric flip of `iam-jit deny add` (#324e). Same flag shapes;
same JSON wire shape contract per
``[[cross-product-agent-parity]]``.

The `profile allow` command lives under the existing `iam-jit
profile` group (registered by :mod:`iam_jit.cli_profile_generate`).
The `denies recent` command lives under a NEW `iam-jit denies` group
(parallel to the existing `iam-jit deny` group — operators reach for
the plural "denies" when they want VISIBILITY into what was blocked;
they reach for the singular "deny" when they want to INSTALL a
new deny rule).
"""

from __future__ import annotations

import json
import sys
from typing import Any

import click


# ---------------------------------------------------------------------------
# Audit-event emission (shared with cli_deny.py)
# ---------------------------------------------------------------------------


def _emit_admin_action(
    *,
    kind: str,
    actor: str | None = None,
    target_id: str = "",
    extra: dict[str, Any] | None = None,
    source: str = "cli",
) -> None:
    """Best-effort admin-action OCSF emit. No-op outside the bouncer
    serve process (the CLI runs out-of-process)."""
    try:
        from .bouncer.audit_export.admin_action import emit_admin_action_direct
        from .bouncer.proxy import _emit_audit_event
    except Exception:
        return
    try:
        emit_admin_action_direct(
            _emit_audit_event,
            kind=kind,
            actor=actor,
            target_kind="profile_allow_rule",
            target_id=target_id,
            source=source,
            extra=extra or {},
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# `profile allow` command
# ---------------------------------------------------------------------------


_BOUNCER_URL_HELP = (
    "Override the mgmt URL for a specific bouncer. Format: `NAME=URL` "
    "(e.g. `ibounce=http://127.0.0.1:8767`). Repeatable."
)


def _parse_bouncer_url_overrides(
    raw: tuple[str, ...],
) -> tuple[dict[str, str], list[str]]:
    parsed: dict[str, str] = {}
    errors: list[str] = []
    for spec in raw:
        if "=" not in spec:
            errors.append(
                f"bouncer override {spec!r} must be `NAME=URL`"
            )
            continue
        name, _, url = spec.partition("=")
        name = name.strip()
        url = url.strip()
        if not name or not url:
            errors.append(
                f"bouncer override {spec!r} must be `NAME=URL`"
            )
            continue
        parsed[name] = url
    return parsed, errors


def _do_profile_allow(
    *,
    target: str,
    actions: tuple[str, ...],
    reason: str | None,
    duration: str | None,
    profile_name: str | None,
    bouncer_url_overrides: tuple[str, ...],
    profiles_path: str | None,
    as_json: bool,
    source: str = "cli",
    allow_agent_self_grant: bool | None = None,
) -> int:
    from .profile_allow.operations import (
        ProfileAllowError,
        add_profile_allow_rule,
    )

    url_overrides, override_errors = _parse_bouncer_url_overrides(
        bouncer_url_overrides,
    )
    if override_errors:
        for e in override_errors:
            click.echo(f"profile allow: {e}", err=True)
        return 2

    try:
        result = add_profile_allow_rule(
            target=target,
            action=list(actions),
            reason=reason or "",
            duration=duration,
            profile_name=profile_name,
            source=source,
            profiles_path=profiles_path,
            bouncer_url_overrides=url_overrides,
            allow_agent_self_grant=allow_agent_self_grant,
        )
    except ProfileAllowError as e:
        return _emit_profile_allow_error(e, as_json=as_json)
    except (ValueError, OSError) as e:
        return _emit_unknown_error(str(e), as_json=as_json)

    # Audit emit (best-effort).
    _emit_admin_action(
        kind="profile.allow.added"
        if result.status == "applied"
        else "profile.allow.requested_by_agent",
        actor=result.actor,
        target_id=f"{result.profile_name}:{','.join(result.actions)}",
        source=source,
        extra={
            "target": result.target,
            "actions": result.actions,
            "reason": result.reason,
            "duration": result.duration,
            "expires_at": result.expires_at,
            "status": result.status,
            "profile_name": result.profile_name,
        },
    )

    if as_json:
        click.echo(json.dumps(result.as_dict(), indent=2, default=str))
        return 0

    if result.status == "pending_approval":
        click.echo(
            f"PENDING APPROVAL: agent-issued profile allow queued for "
            f"operator confirmation."
        )
        entry = result.pending_entry or {}
        click.echo(f"  pending id:  {entry.get('id', '?')}")
        click.echo(f"  profile:     {result.profile_name}")
        click.echo(f"  target:      {result.target}")
        click.echo(f"  actions:     {', '.join(result.actions)}")
        click.echo(f"  reason:      {result.reason}")
        click.echo(f"  by:          {result.actor} (via {result.source})")
        click.echo(
            "  (re-run the bouncer with --allow-agent-self-grant OR "
            "IAM_JIT_BOUNCER_ALLOW_AGENT_SELF_GRANT=1 to auto-apply "
            "agent-issued allows in future)"
        )
        return 0

    click.echo(
        f"OK  added profile allow to {result.profile_name!r}"
    )
    click.echo(f"  target:        {result.target}")
    click.echo(f"  actions:       {', '.join(result.actions)}")
    click.echo(f"  reason:        {result.reason}")
    click.echo(
        f"  expires_at:    {result.expires_at if result.expires_at else '(permanent)'}"
    )
    click.echo(f"  rule_count:    {result.rule_count_after}")
    click.echo(f"  by:            {result.actor} (via {result.source})")
    click.echo(f"  profile_path:  {result.profile_path}")
    click.echo("")
    click.echo("  fanout:")
    if not result.fanout:
        click.echo("    (skipped)")
    else:
        for r in result.fanout:
            bouncer = r.get("bouncer", "?")
            url = r.get("url", "")
            if r.get("reloaded"):
                click.echo(f"    [OK]   {bouncer:<10} {url}")
            else:
                err = r.get("error") or "reload failed"
                code = r.get("status_code")
                code_str = f"HTTP {code}" if code else "unreachable"
                click.echo(f"    [WARN] {bouncer:<10} {url} {code_str}: {err}")
                click.echo(
                    "           (profile YAML is updated; bouncer "
                    "will pick it up on next reload)"
                )
    return 0


def _emit_profile_allow_error(err: Any, *, as_json: bool) -> int:
    payload = {
        "status": "error",
        "command": "iam-jit profile allow",
        "code": err.code,
        "message": str(err),
        "details": err.details,
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2), err=True)
    else:
        click.echo(f"profile allow: {err}", err=True)
        if err.details:
            for k, v in err.details.items():
                click.echo(f"  {k}: {v}", err=True)
    # Exit code 2 for user-fixable input errors (matches cli_deny).
    return 2 if err.code in {
        "missing_target",
        "missing_action",
        "missing_reason",
        "bad_action",
        "target_too_broad",
        "profile_not_found",
        "org_distributed",
    } else 1


def _emit_unknown_error(msg: str, *, as_json: bool) -> int:
    if as_json:
        click.echo(
            json.dumps({"status": "error", "code": "unknown", "message": msg}),
            err=True,
        )
    else:
        click.echo(f"profile allow: {msg}", err=True)
    return 1


def register_profile_allow_command(profile_group: click.Group) -> click.Command:
    """Mount the `allow` subcommand on an existing `iam-jit profile`
    group (the group is created by cli_profile_generate.register_profile_group)."""

    @profile_group.command("allow")
    @click.option(
        "--target",
        required=True,
        metavar="PATTERN",
        help="Resource target (ARN glob). Examples: "
             "'arn:aws:s3:::staging-cache-*', "
             "'arn:aws:dynamodb:*:*:table/cache-*'. `*` alone is refused.",
    )
    @click.option(
        "--action", "actions",
        multiple=True,
        required=True,
        metavar="SERVICE:ACTION",
        help="`service:Action` string (repeatable). Examples: "
             "'s3:GetObject', 'dynamodb:Query'.",
    )
    @click.option(
        "--reason",
        required=True,
        help="Free-text explanation; surfaces in the profile's note "
             "field + the admin-action OCSF audit event.",
    )
    @click.option(
        "--duration",
        default=None,
        help="Optional Go-style duration (`30m`, `3h`, `7d`) or "
             "`permanent` / unset for default (permanent). When set, "
             "the rule's note carries an `expires=<iso>` tag (advisory "
             "today; Phase 2 wires expiry-sweep into the profile "
             "watcher).",
    )
    @click.option(
        "--profile", "profile_name",
        default=None,
        help="Profile to extend. Defaults to the active profile "
             "(IAM_JIT_BOUNCER_PROFILE env or `full-user`).",
    )
    @click.option(
        "--bouncer-url", "bouncer_url_overrides",
        multiple=True,
        metavar="NAME=URL",
        help=_BOUNCER_URL_HELP,
    )
    @click.option(
        "--profiles-path",
        type=click.Path(dir_okay=False),
        default=None,
        help="Override the profiles.yaml path. Default: "
             "$IAM_JIT_BOUNCER_PROFILES_FILE or "
             "~/.iam-jit/bouncer/profiles.yaml.",
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured shape as JSON.",
    )
    def profile_allow_cmd(
        target: str,
        actions: tuple[str, ...],
        reason: str,
        duration: str | None,
        profile_name: str | None,
        bouncer_url_overrides: tuple[str, ...],
        profiles_path: str | None,
        as_json: bool,
    ) -> None:
        """Append an ALLOW rule to a profile + reload affected bouncers.

        Per [[creates-never-mutates]] the operation is ADDITIVE — the
        existing allow_rules / deny_actions are preserved, the new
        rule appends to the END of allow_rules with provenance in the
        `note` field.

        Per [[dynamic-deny-rules]] conflict resolution: a personal
        allow CANNOT loosen an org-distributed deny. The dynamic-deny
        watcher continues to short-circuit profile-level allows at
        request time.

        \b
        Examples:
          # Allow staging cache reads under the active profile
          iam-jit profile allow \\
            --target 'arn:aws:s3:::staging-cache-*' \\
            --action 's3:GetObject' \\
            --reason "agent needs staging cache access"

          # Allow time-bounded write access under a named profile
          iam-jit profile allow \\
            --target 'arn:aws:dynamodb:*:*:table/incident-*' \\
            --action 'dynamodb:PutItem' \\
            --action 'dynamodb:UpdateItem' \\
            --reason "incident #4711 triage" \\
            --duration 3h \\
            --profile incident-response
        """
        exit_code = _do_profile_allow(
            target=target,
            actions=actions,
            reason=reason,
            duration=duration,
            profile_name=profile_name,
            bouncer_url_overrides=bouncer_url_overrides,
            profiles_path=profiles_path,
            as_json=as_json,
        )
        sys.exit(exit_code)

    return profile_allow_cmd


# ---------------------------------------------------------------------------
# `denies recent` command
# ---------------------------------------------------------------------------


def _format_denies_table(rows: list, notes: list[str]) -> str:
    """Render denies rows as a compact table."""
    if not rows:
        return "no denies in the requested window\n"
    lines = [
        f"{len(rows)} deny row(s); newest first"
    ]
    if notes:
        for n in notes:
            lines.append(f"  (note) {n}")
    lines.append("")
    header = (
        f"  {'WHEN':<20} {'BOUNCER':<10} {'ACTION':<28} "
        f"{'RESOURCE':<40} {'SOURCE':<22}"
    )
    lines.append(header)
    lines.append(f"  {'-' * (len(header) - 2)}")
    for r in rows:
        when = r.when[:19] if r.when else "?"
        bouncer = (r.bouncer or "?")[:10]
        action = (r.action or "?")[:28]
        resource = (r.resource or "?")[:40]
        source = (r.deny_source or "?")[:22]
        lines.append(
            f"  {when:<20} {bouncer:<10} {action:<28} "
            f"{resource:<40} {source:<22}"
        )
        if r.deny_reason:
            lines.append(f"    reason: {r.deny_reason[:120]}")
        if r.agent_session_id:
            lines.append(f"    agent.session_id: {r.agent_session_id}")
        if r.suggested_allow_command:
            lines.append(f"    fix: {r.suggested_allow_command}")
    return "\n".join(lines) + "\n"


def _do_denies_recent(
    *,
    since: str,
    agent_session_id: str | None,
    limit: int,
    bouncer_names: tuple[str, ...],
    audit_events_token: str | None,
    as_json: bool,
    follow: bool,
) -> int:
    from .profile_allow.denies import fetch_recent_denies

    if follow:
        return _do_denies_follow(
            since=since,
            agent_session_id=agent_session_id,
            limit=limit,
            bouncer_names=bouncer_names,
            audit_events_token=audit_events_token,
        )

    try:
        rows, notes = fetch_recent_denies(
            since=since,
            agent_session_id=agent_session_id,
            limit=limit,
            bouncer_names=list(bouncer_names) if bouncer_names else None,
            audit_events_token=audit_events_token,
        )
    except Exception as e:
        click.echo(f"denies recent: {e}", err=True)
        return 1

    if as_json:
        payload = {
            "status": "ok",
            "since": since,
            "count": len(rows),
            "rows": [r.as_dict() for r in rows],
            "notes": notes,
        }
        click.echo(json.dumps(payload, indent=2, default=str))
        return 0
    click.echo(_format_denies_table(rows, notes))
    return 0


def _do_denies_follow(
    *,
    since: str,
    agent_session_id: str | None,
    limit: int,
    bouncer_names: tuple[str, ...],
    audit_events_token: str | None,
) -> int:
    """Tail-mode poller. Polls every 2 s; emits new denies as they
    appear; ignores rows already shown this run."""
    import time as _time

    from .profile_allow.denies import fetch_recent_denies

    seen: set[tuple[str, str, str]] = set()
    current_since = since
    click.echo(
        f"following denies (since={since!r}); Ctrl-C to stop"
    )
    try:
        while True:
            rows, notes = fetch_recent_denies(
                since=current_since,
                agent_session_id=agent_session_id,
                limit=limit,
                bouncer_names=list(bouncer_names) if bouncer_names else None,
                audit_events_token=audit_events_token,
            )
            for r in reversed(rows):  # oldest first in the follow stream
                key = (r.when, r.bouncer, r.action + ":" + r.resource)
                if key in seen:
                    continue
                seen.add(key)
                click.echo(
                    f"[{r.when}] {r.bouncer:<10} DENY {r.action} {r.resource}"
                    f"  source={r.deny_source}"
                )
                if r.deny_reason:
                    click.echo(f"    reason: {r.deny_reason[:160]}")
                if r.suggested_allow_command:
                    click.echo(f"    fix: {r.suggested_allow_command}")
            for n in notes:
                click.echo(f"  (note) {n}", err=True)
            # After the first poll narrow the window so subsequent
            # polls don't reach all the way back.
            current_since = "30s"
            _time.sleep(2.0)
    except KeyboardInterrupt:
        return 0


def register_denies_group(main_group: click.Group) -> click.Group:
    """Mount the top-level `denies` group on the iam-jit CLI."""

    @main_group.group("denies")
    def denies_group() -> None:
        """Deny visibility across the Bounce suite (#345 / §A25).

        Symmetric flip of `iam-jit deny` (which INSTALLS deny rules);
        `denies` SHOWS what got denied + suggests a `profile allow`
        path to unblock when safe.
        """

    @denies_group.command("recent")
    @click.option(
        "--since",
        default="5m",
        show_default=True,
        help="Window lookback: `5m` / `1h` / `2d` or an ISO 8601 "
             "lower bound.",
    )
    @click.option(
        "--agent-session", "agent_session_id",
        default=None,
        help="Filter to one agent session ID (the "
             "unmapped.iam_jit.agent.session_id field).",
    )
    @click.option(
        "--limit",
        type=int,
        default=50,
        show_default=True,
        help="Max rows to return.",
    )
    @click.option(
        "--bouncer", "bouncer_names",
        multiple=True,
        help="Restrict to specific bouncer(s) (e.g. `ibounce`). "
             "Default: every reachable bouncer.",
    )
    @click.option(
        "--audit-events-token",
        default=None,
        envvar="IAM_JIT_AUDIT_EVENTS_TOKEN",
        help="Bearer token for /audit/events. Read from "
             "IAM_JIT_AUDIT_EVENTS_TOKEN env when unset.",
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured shape as JSON.",
    )
    @click.option(
        "--follow",
        is_flag=True,
        default=False,
        help="Tail mode — poll every 2 s and emit new denies.",
    )
    def denies_recent_cmd(
        since: str,
        agent_session_id: str | None,
        limit: int,
        bouncer_names: tuple[str, ...],
        audit_events_token: str | None,
        as_json: bool,
        follow: bool,
    ) -> None:
        """Show recent DENY decisions + a suggested-fix `profile allow`
        command per row.

        Per [[ibounce-honest-positioning]] this is the OPERATOR
        feedback loop: "what did the bouncer block + how do I unblock
        if safe?" Symmetric flip of `iam-jit deny add` (which
        INSTALLS denies).

        \b
        Examples:
          iam-jit denies recent
          iam-jit denies recent --since 1h --agent-session abc123
          iam-jit denies recent --bouncer ibounce --json
          iam-jit denies recent --follow
        """
        exit_code = _do_denies_recent(
            since=since,
            agent_session_id=agent_session_id,
            limit=limit,
            bouncer_names=bouncer_names,
            audit_events_token=audit_events_token,
            as_json=as_json,
            follow=follow,
        )
        sys.exit(exit_code)

    return denies_group


__all__ = [
    "register_denies_group",
    "register_profile_allow_command",
]
