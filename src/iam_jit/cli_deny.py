"""#324e — `iam-jit deny` cross-product dynamic-deny CLI.

Replaces the design-stage skeleton (the ``_emit_not_implemented`` body
that pointed back at #324e). The CLI surface stays IDENTICAL to the
skeleton's `--help` shape per ``[[deliberate-feature-completion]]``;
what changed is that each subcommand now actually does work:

  * ``iam-jit deny add`` — resolve targets, write
    ``~/.iam-jit/dynamic-denies.yaml`` atomically (0600), POST each
    affected bouncer's ``/admin/dynamic-denies/reload`` endpoint.
  * ``iam-jit deny list`` — read the YAML, format as a table (or
    JSON), include expired entries on request.
  * ``iam-jit deny remove`` — drop one or more rules by id /
    regex / expiry; re-fan-out to every previously-affected bouncer.
  * ``iam-jit deny show`` — single-rule detail dump.

Per ``[[ibounce-honest-positioning]]``: bouncer reload failures are
SURFACED honestly (red line + status code + url) but do NOT abort
the CLI — the YAML file IS the source of truth, and the downed
bouncer's watcher picks the rule up on its next start. The CLI exits
0 on a successful write even when fan-out partially failed; the
operator sees the warning + can rerun once the bouncer is back.

Per ``[[security-team-positioning-safety-not-surveillance]]`` the
CLI frames its output as "safety rule installed" (neutral) rather
than violation-tracking language.

Per ``[[creates-never-mutates]]``: every write rebuilds the file
from the desired list — never mutates rules in place. The OLD
skeleton tests at ``tests/cli/test_deny_skeleton.py`` are skip-marked
(not deleted) so the migration is visible in history; the new
behaviour is covered by ``tests/cli/test_deny_real.py``.
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
from typing import Any

import click

from .dynamic_denies.fanout import (
    DEFAULT_BOUNCER_URLS,
    ReloadResult,
    parse_bouncer_override,
)
from .dynamic_denies.operations import (
    DenyOperationError,
    add_rule,
    list_rules,
    remove_rules,
    show_rule,
)
from .dynamic_denies.store import DynamicDenyWriteError


# ----------------------------------------------------------------------
# Backwards-compat constants (the skeleton test suite imports these;
# the new real-impl test suite does NOT, but we keep them exported so
# any external script that read them off cli_deny doesn't break).
# ----------------------------------------------------------------------

DESIGN_DOC_PATH = "docs/DYNAMIC-DENY-RULES.md"
"""Repo-relative path to the canonical design doc."""

DESIGN_DOC_URL = (
    "https://github.com/trsreagan3/iam-jit/blob/main/docs/DYNAMIC-DENY-RULES.md"
)
"""Web URL for the design doc."""

SCHEMA_PATH = "docs/schemas/dynamic-denies-v1.json"
"""Repo-relative path to the canonical JSON schema."""

TRACKING_REFS: dict[str, str] = {
    "#324a": "ibounce dynamic-deny core (ARN matcher + YAML watcher + decision pipeline + OCSF)",
    "#324b": "kbouncer dynamic-deny core (namespace/cluster matcher + YAML watcher)",
    "#324c": "dbounce dynamic-deny core (hostname/RDS pattern matcher + YAML watcher)",
    "#324d": "gbounce dynamic-deny core (URL/hostname glob matcher + YAML watcher)",
    "#324e": "iam-jit unified CLI + MCP + cross-bouncer fan-out (REPLACES this skeleton)",
    "#324f": "iam-jit recommender Deny-injection + role-effectiveness re-grade",
}

REPLACEMENT_SLICE: dict[str, str] = {
    "add":    "#324e",
    "list":   "#324e",
    "remove": "#324e",
    "show":   "#324e",
}


# ----------------------------------------------------------------------
# Audit-event emission helper. Best-effort; fail-soft per the design
# doc's audit-export contract.
# ----------------------------------------------------------------------


def _emit_admin_action(
    *,
    kind: str,
    actor: str | None = None,
    target_id: str = "",
    extra: dict[str, Any] | None = None,
    source: str = "cli",
) -> None:
    """Best-effort admin-action OCSF event emit.

    The CLI runs out-of-process from the bouncer; the audit row lands
    via the in-process emitter only when the CLI is invoked under an
    audit-export-configured environment (rare for the CLI path; the
    MCP path inside the serve process is the common case). Honest
    no-op when no emitter is registered.
    """
    try:
        from .bouncer.audit_export.admin_action import (
            emit_admin_action_direct,
        )
        from .bouncer.proxy import _emit_audit_event
    except Exception:
        return
    try:
        emit_admin_action_direct(
            _emit_audit_event,
            kind=kind,
            actor=actor,
            target_kind="dynamic_deny_rule",
            target_id=target_id,
            source=source,
            extra=extra or {},
        )
    except Exception:
        # The bouncer-side proxy._emit_audit_event is only wired
        # inside `iam-jit serve`. From the CLI process it's a no-op.
        pass


# ----------------------------------------------------------------------
# Helpers shared between subcommands
# ----------------------------------------------------------------------


def _format_relative(seconds: int | None) -> str:
    """Format an int seconds count as ``Nh M m`` for human display."""
    if seconds is None:
        return "—"
    if seconds < 0:
        return f"expired {abs(seconds)//60}m ago"
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h{minutes:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d{hours}h"


def _parse_bouncer_url_overrides(
    raw: tuple[str, ...],
) -> tuple[dict[str, str], list[str]]:
    """Parse the repeatable ``--bouncer NAME=URL`` flag.

    Returns ``(map, errors)``. Errors are surfaced to the operator
    via stderr before any other work.
    """
    parsed: dict[str, str] = {}
    errors: list[str] = []
    for spec in raw:
        try:
            name, url = parse_bouncer_override(spec)
        except ValueError as e:
            errors.append(str(e))
            continue
        parsed[name] = url
    return parsed, errors


def _format_fanout(results: list[dict[str, Any]]) -> list[str]:
    """Pretty-print fan-out outcomes for the human banner.

    Per #618: when a bouncer reports a ``source_path`` that diverges
    from the CLI's write path, emit a loud ``[FAIL] path mismatch``
    line in addition to the existing ``[OK] reloaded`` line. The OK
    line still appears because the reload itself succeeded — the bug
    is that the reload re-read a DIFFERENT file from the one the CLI
    wrote to, so the rule is not in effect at this bouncer.
    """
    lines: list[str] = []
    if not results:
        lines.append("  fanout:      (skipped)")
        return lines
    lines.append("  fanout:")
    for r in results:
        bouncer = r.get("bouncer", "?")
        url = r.get("url", "")
        if r.get("reloaded"):
            applied = r.get("rules_applied_to_self")
            total = r.get("rules_count")
            applied_str = (
                f"{applied} applied / {total} total"
                if applied is not None and total is not None
                else ""
            )
            lines.append(
                f"    [OK]  {bouncer:<8} {url}  {applied_str}".rstrip()
            )
            # #618 — path-divergence diagnostic. Even when reload
            # succeeded, the bouncer may be reading a different file
            # than the one we wrote to. Severity decides the prefix:
            #   hard -> [FAIL] (drives non-zero exit)
            #   soft -> [WARN] (older bouncer; can't verify; exit 0)
            severity = r.get("path_mismatch_severity")
            if r.get("path_mismatch"):
                bouncer_path = r.get("source_path") or "(unknown)"
                if severity == "hard":
                    lines.append(
                        f"    [FAIL] {bouncer:<8} path mismatch: "
                        f"bouncer reads {bouncer_path}"
                    )
                else:
                    lines.append(
                        f"    [WARN] {bouncer:<8} path unverified: "
                        f"bouncer reads {bouncer_path}"
                    )
                reason = r.get("path_mismatch_reason") or ""
                if reason:
                    lines.append(f"           {reason}")
        else:
            err = r.get("error") or "reload failed"
            status = r.get("status_code")
            status_str = f"HTTP {status}" if status else "unreachable"
            lines.append(
                f"    [WARN] {bouncer:<8} {url}  {status_str}: {err}"
            )
            lines.append(
                f"           (rule is in YAML; bouncer will pick up via watcher "
                f"OR retry: curl -XPOST {url})"
            )
    return lines


# ----------------------------------------------------------------------
# Add
# ----------------------------------------------------------------------


def _do_add(
    *,
    targets: tuple[str, ...],
    reason: str | None,
    duration: str | None,
    applies_to_recommender: bool,
    bouncer_overrides: tuple[str, ...],
    bouncer_url_overrides: tuple[str, ...],
    path: str | None,
    as_json: bool,
    source: str = "cli",
) -> int:
    """Execute `iam-jit deny add` + render output. Returns an exit code."""

    url_overrides, override_errors = _parse_bouncer_url_overrides(
        bouncer_url_overrides,
    )
    if override_errors:
        for e in override_errors:
            click.echo(f"deny add: {e}", err=True)
        return 2

    try:
        result = add_rule(
            targets=list(targets),
            reason=reason or "",
            duration=duration or "",
            applies_to_recommender=applies_to_recommender,
            bouncer_overrides=list(bouncer_overrides),
            bouncer_url_overrides=url_overrides,
            source=source,
            path=path,
        )
    except DenyOperationError as e:
        return _emit_operation_error(e, as_json=as_json, command="add")
    except DynamicDenyWriteError as e:
        return _emit_write_error(e, as_json=as_json, command="add")

    # Successful add → emit OCSF admin-action best-effort.
    rule = result["rule"]
    _emit_admin_action(
        kind="dynamic_deny.added",
        actor=rule.get("added_by"),
        target_id=rule["id"],
        source=source,
        extra={
            "targets": rule.get("targets"),
            "applied_to": rule.get("applied_to"),
            "reason": rule.get("reason"),
            "duration": rule.get("duration"),
            "expires_at": rule.get("expires_at"),
            "applies_to_recommender": rule.get("applies_to_recommender"),
        },
    )

    # #618 — HARD path-divergence is a non-zero-exit failure even
    # when the YAML write + reload both reported success individually.
    # The rule landed on disk + the bouncer cheerfully reloaded, but
    # the bouncer is reading a different file than the one we wrote
    # to, so the deny will not actually apply.
    #
    # SOFT divergence (bouncer didn't report source_path; older build
    # or test stub) is a WARN — preserves backward-compat with pre-
    # #618 bouncer builds + the dozens of existing CLI tests that
    # stub the fan-out.
    any_hard_path_mismatch = bool(result.get("any_hard_path_mismatch"))

    if as_json:
        click.echo(json.dumps(_add_json_shape(result), indent=2))
        return 2 if any_hard_path_mismatch else 0

    rule = result["rule"]
    click.echo(f"OK  added {rule['id']}")
    click.echo(f"  targets:     {', '.join(rule.get('targets') or [])}")
    click.echo(f"  applied_to:  {', '.join(rule.get('applied_to') or [])}")
    click.echo(f"  reason:      {rule.get('reason', '')}")
    click.echo(f"  duration:    {rule.get('duration', '')}")
    expires_at = rule.get("expires_at")
    click.echo(
        f"  expires_at:  {expires_at if expires_at else '(permanent)'}"
    )
    click.echo(f"  written to:  {result.get('written_to')}")
    if applies_to_recommender:
        click.echo(
            "  recommender: enabled - JIT roles issued in this window will "
            "embed an explicit Deny (#324f)."
        )
    else:
        click.echo("  recommender: disabled (bouncer-only enforcement)")
    click.echo("")
    click.echo("  routing:")
    for entry in result.get("per_target_rationale", []):
        applied = ", ".join(entry.get("applied_to") or []) or "(none)"
        click.echo(f"    {entry['target']:<40}  -> {applied}")
        click.echo(f"      {entry['rationale']}")
    click.echo("")
    for line in _format_fanout(result.get("fanout", [])):
        click.echo(line)
    # #618 — when any bouncer is reading a DIFFERENT file from the one
    # we wrote to (severity=hard), emit a loud trailing summary line
    # to stderr (in addition to the per-bouncer [FAIL] lines in the
    # fanout block) AND exit non-zero so wrappers can react. The text
    # shape mirrors the JSON shape's `any_hard_path_mismatch` field.
    if any_hard_path_mismatch:
        mismatched = [
            m for m in (result.get("path_mismatches") or [])
            if m.get("path_mismatch_severity") == "hard"
        ]
        names = [m.get("bouncer", "?") for m in mismatched]
        click.echo(
            f"ERROR  rule {rule['id']} did NOT apply at "
            f"{len(mismatched)} bouncer(s) reading a different file: "
            f"{', '.join(names)}. The rule IS in "
            f"{result.get('written_to')!r}; either point the bouncer(s) "
            f"at that file (restart with --dynamic-denies-path) or "
            f"re-run `iam-jit deny add --path <bouncer's path>`.",
            err=True,
        )
        return 2
    return 0


def _add_json_shape(result: dict[str, Any]) -> dict[str, Any]:
    """Stable JSON wire shape for `iam-jit deny add --json`. Mirrors
    the design doc's sample.

    Per #618: ``any_path_mismatch`` + ``path_mismatches`` surface the
    write/read path divergence that pre-#618 was silently dropped on
    the floor. Each entry in ``fanout`` also gets a ``source_path`` +
    ``path_mismatch`` + ``path_mismatch_reason`` field so JSON
    consumers can react per-bouncer.
    """
    rule = result["rule"]
    return {
        "id": rule["id"],
        "targets": rule.get("targets", []),
        "applied_to": rule.get("applied_to", []),
        "reason": rule.get("reason"),
        "duration": rule.get("duration"),
        "expires_at": rule.get("expires_at"),
        "applies_to_recommender": rule.get("applies_to_recommender"),
        "added_by": rule.get("added_by"),
        "added_at": rule.get("added_at"),
        "source": rule.get("source"),
        "routing_explanation": result.get("routing_explanation"),
        "per_target_rationale": result.get("per_target_rationale", []),
        "fanout": result.get("fanout", []),
        "written_to": result.get("written_to"),
        "any_path_mismatch": bool(result.get("any_path_mismatch")),
        "any_hard_path_mismatch": bool(
            result.get("any_hard_path_mismatch"),
        ),
        "path_mismatches": result.get("path_mismatches", []),
    }


# ----------------------------------------------------------------------
# List
# ----------------------------------------------------------------------


def _do_list(
    *,
    bouncer_filter: tuple[str, ...],
    include_expired: bool,
    path: str | None,
    as_json: bool,
) -> int:
    try:
        result = list_rules(
            path=path,
            include_expired=include_expired,
            bouncer_filter=list(bouncer_filter),
        )
    except DenyOperationError as e:
        return _emit_operation_error(e, as_json=as_json, command="list")
    except DynamicDenyWriteError as e:
        return _emit_write_error(e, as_json=as_json, command="list")

    if as_json:
        click.echo(json.dumps(result, indent=2, default=str))
        return 0

    rules = result.get("rules", [])
    if not rules:
        click.echo(
            f"no active dynamic deny rules (file: {result.get('path') or '(none)'})",
        )
        return 0
    click.echo(f"{len(rules)} dynamic deny rule(s) — {result.get('path')}")
    click.echo("")
    # Column widths chosen to fit a typical 120-col terminal.
    header = (
        f"  {'ID':<33} {'EXPIRES IN':<14} {'AGE':<10} "
        f"{'BOUNCERS':<28} {'TARGETS':<30}"
    )
    click.echo(header)
    click.echo(f"  {'-' * (len(header) - 2)}")
    for r in rules:
        rid = r.get("id", "?")
        expires_in = _format_relative(r.get("_expires_in_seconds"))
        age = _format_relative(r.get("_age_seconds"))
        applied = ",".join(r.get("applied_to") or [])
        targets = ",".join(r.get("targets") or [])
        if len(targets) > 30:
            targets = targets[:27] + "..."
        if r.get("_expired"):
            expires_in = "EXPIRED"
        click.echo(
            f"  {rid:<33} {expires_in:<14} {age:<10} "
            f"{applied:<28} {targets:<30}",
        )
        reason = r.get("reason") or ""
        if reason:
            click.echo(f"    reason: {reason}")
    return 0


# ----------------------------------------------------------------------
# Show
# ----------------------------------------------------------------------


def _do_show(
    *,
    rule_id: str | None,
    path: str | None,
    as_json: bool,
) -> int:
    if not rule_id:
        click.echo("deny show: ID is required", err=True)
        return 2
    try:
        result = show_rule(rule_id, path=path)
    except DenyOperationError as e:
        return _emit_operation_error(e, as_json=as_json, command="show")
    except DynamicDenyWriteError as e:
        return _emit_write_error(e, as_json=as_json, command="show")

    if as_json:
        click.echo(json.dumps(result, indent=2, default=str))
        return 0
    rule = result["rule"]
    click.echo(f"  id:                     {rule.get('id')}")
    click.echo(f"  targets:                {', '.join(rule.get('targets') or [])}")
    click.echo(f"  reason:                 {rule.get('reason')}")
    click.echo(f"  duration:               {rule.get('duration')}")
    click.echo(f"  added_by:               {rule.get('added_by')}")
    click.echo(f"  added_at:               {rule.get('added_at')}")
    click.echo(f"  expires_at:             {rule.get('expires_at') or '(permanent)'}")
    click.echo(
        f"  expires_in:             {_format_relative(result.get('expires_in_seconds'))}",
    )
    click.echo(f"  age:                    {_format_relative(result.get('age_seconds'))}")
    click.echo(f"  applied_to:             {', '.join(rule.get('applied_to') or [])}")
    click.echo(f"  applies_to_recommender: {rule.get('applies_to_recommender')}")
    click.echo(f"  source:                 {rule.get('source')}")
    if rule.get("org_distributed_url"):
        click.echo(f"  org_distributed_url:    {rule.get('org_distributed_url')}")
    return 0


# ----------------------------------------------------------------------
# Remove
# ----------------------------------------------------------------------


def _do_remove(
    *,
    ids: tuple[str, ...],
    reason: str | None,
    reason_match: str | None,
    drop_expired: bool,
    bouncer_url_overrides: tuple[str, ...],
    path: str | None,
    as_json: bool,
    source: str = "cli",
) -> int:
    url_overrides, override_errors = _parse_bouncer_url_overrides(
        bouncer_url_overrides,
    )
    if override_errors:
        for e in override_errors:
            click.echo(f"deny remove: {e}", err=True)
        return 2

    try:
        result = remove_rules(
            rule_ids=list(ids),
            path=path,
            reason_match=reason_match,
            drop_expired=drop_expired,
            actor_reason=reason,
            bouncer_url_overrides=url_overrides,
        )
    except DenyOperationError as e:
        return _emit_operation_error(e, as_json=as_json, command="remove")
    except DynamicDenyWriteError as e:
        return _emit_write_error(e, as_json=as_json, command="remove")

    # Best-effort admin-action emit for each removed rule.
    for rule in result.get("removed_rules", []):
        _emit_admin_action(
            kind="dynamic_deny.removed",
            actor=None,
            target_id=rule.get("id", ""),
            source=source,
            extra={
                "removed_by_reason": reason,
                "targets": rule.get("targets"),
                "applied_to": rule.get("applied_to"),
            },
        )

    # #618 — parity with deny add: HARD path divergence is a non-zero
    # exit even when the YAML write + reload reported success. The
    # remove landed on disk + the bouncer reloaded, but if the
    # bouncer is reading a different file then the rule the operator
    # just "removed" is still LIVE at the bouncer's matcher. SOFT
    # mismatch (no source_path reported) preserves exit 0.
    any_hard_path_mismatch = bool(result.get("any_hard_path_mismatch"))

    if as_json:
        click.echo(json.dumps(result, indent=2, default=str))
        # Non-empty `not_found` is a soft warning, not an exit-error.
        return 2 if any_hard_path_mismatch else 0

    removed = result.get("removed_count", 0)
    if removed == 0:
        if result.get("not_found"):
            click.echo(
                f"no rules removed; not_found: "
                f"{', '.join(result['not_found'])}",
                err=True,
            )
            return 1
        if result.get("refused_org_distributed"):
            click.echo(
                f"no rules removed; refused (org-distributed): "
                f"{', '.join(result['refused_org_distributed'])}",
                err=True,
            )
            return 1
        click.echo("no rules matched the selector(s)")
        return 0

    click.echo(f"OK  removed {removed} rule(s):")
    for rule in result.get("removed_rules", []):
        click.echo(f"    {rule.get('id')}  ({', '.join(rule.get('targets') or [])})")
    if result.get("not_found"):
        click.echo(
            f"  not found: {', '.join(result['not_found'])}",
            err=True,
        )
    if result.get("refused_org_distributed"):
        click.echo(
            f"  refused (org-distributed): "
            f"{', '.join(result['refused_org_distributed'])}",
            err=True,
        )
    click.echo("")
    for line in _format_fanout(result.get("fanout", [])):
        click.echo(line)
    # #618 — same loud trailing stderr line + non-zero exit as deny add.
    if any_hard_path_mismatch:
        mismatched = [
            m for m in (result.get("path_mismatches") or [])
            if m.get("path_mismatch_severity") == "hard"
        ]
        names = [m.get("bouncer", "?") for m in mismatched]
        click.echo(
            f"ERROR  removal did NOT apply at {len(mismatched)} "
            f"bouncer(s) reading a different file: "
            f"{', '.join(names)}. The remove DID land in "
            f"{result.get('written_to')!r}; either point the bouncer(s) "
            f"at that file (restart with --dynamic-denies-path) or "
            f"re-run `iam-jit deny remove --path <bouncer's path>`.",
            err=True,
        )
        return 2
    return 0


# ----------------------------------------------------------------------
# Error rendering
# ----------------------------------------------------------------------


def _emit_operation_error(
    err: DenyOperationError,
    *,
    as_json: bool,
    command: str,
) -> int:
    payload = {
        "status": "error",
        "command": f"iam-jit deny {command}",
        "code": err.code,
        "message": str(err),
        "details": err.details,
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2), err=True)
    else:
        click.echo(f"deny {command}: {err}", err=True)
        if err.details:
            for k, v in err.details.items():
                click.echo(f"  {k}: {v}", err=True)
    return 1


def _emit_write_error(
    err: DynamicDenyWriteError,
    *,
    as_json: bool,
    command: str,
) -> int:
    payload = {
        "status": "error",
        "command": f"iam-jit deny {command}",
        "code": f"write.{err.stage}",
        "message": str(err),
        "path": err.path,
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2), err=True)
    else:
        click.echo(f"deny {command}: write failed at stage `{err.stage}`: {err}", err=True)
        if err.path:
            click.echo(f"  path: {err.path}", err=True)
    return 1


# ----------------------------------------------------------------------
# Click group registration
# ----------------------------------------------------------------------


_PATH_HELP = (
    "Path to dynamic-denies.yaml. Default: $IAM_JIT_DYNAMIC_DENIES_PATH "
    "or ~/.iam-jit/dynamic-denies.yaml."
)

_BOUNCER_URL_HELP = (
    "Override the mgmt URL for a specific bouncer. Format: `NAME=URL` "
    "(e.g. `ibounce=http://127.0.0.1:8767`). Repeatable. Defaults: "
    "ibounce 8767, kbouncer 8766, dbounce 8768, gbounce 8769."
)


def register_deny_group(main_group: click.Group) -> click.Group:
    """Mount the `deny` subcommand group on the top-level `iam-jit` CLI.

    Replaces the #324 skeleton bodies with real implementation per
    #324e. The flag shape + JSON wire shape are STABLE per the design
    doc; future slices that change behavior update the design doc
    first.
    """

    @main_group.group("deny")
    def deny_group() -> None:
        """Dynamic deny rules across the Bounce suite (#324).

        Operator + agent surface for installing short-lived denies that
        fan out to every applicable Bounce product (ibounce / kbouncer /
        dbounce / gbounce). Defense-in-depth: bouncer request-time deny
        + (per #324f) embedded Deny in any role iam-jit issues during
        the deny window.

        \b
        See docs/DYNAMIC-DENY-RULES.md for the full design + on-disk YAML
        shape.
        """

    # -- add ------------------------------------------------------------

    @deny_group.command("add")
    @click.option(
        "--target", "targets",
        multiple=True,
        required=False,
        metavar="PATTERN",
        help="Target pattern (repeatable). Resolver classifies each by "
             "shape. Examples: 'arn:aws:s3:::prod-*' (ibounce), "
             "'rds:payments-db-prod' (dbounce+gbounce), 'namespace:prod' "
             "(kbouncer), 'api.openai.com' (gbounce).",
    )
    @click.option(
        "--reason",
        required=False,
        help="Short string surfaced in the bouncer's 403 deny_reason + "
             "the admin-action OCSF audit event.",
    )
    @click.option(
        "--duration",
        required=False,
        help="Go-style duration ('30m', '3h', '7d') or 'permanent'.",
    )
    @click.option(
        "--applies-to-recommender/--no-applies-to-recommender",
        "applies_to_recommender",
        default=True,
        help="When true (default; #324f): the iam-jit recommender embeds "
             "an explicit Deny matching the targets into any role it "
             "issues during the deny window.",
    )
    @click.option(
        "--bouncer", "bouncer_overrides",
        multiple=True,
        type=click.Choice(["ibounce", "kbouncer", "kbounce", "dbounce", "gbounce"]),
        help="Override the resolver — force this rule onto specific "
             "bouncer(s). Repeatable.",
    )
    @click.option(
        "--bouncer-url", "bouncer_url_overrides",
        multiple=True,
        metavar="NAME=URL",
        help=_BOUNCER_URL_HELP,
    )
    @click.option(
        "--path",
        type=click.Path(dir_okay=False),
        default=None,
        help=_PATH_HELP,
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured shape as JSON (stable shape per "
             "docs/DYNAMIC-DENY-RULES.md).",
    )
    def deny_add(
        targets: tuple[str, ...],
        reason: str | None,
        duration: str | None,
        applies_to_recommender: bool,
        bouncer_overrides: tuple[str, ...],
        bouncer_url_overrides: tuple[str, ...],
        path: str | None,
        as_json: bool,
    ) -> None:
        """Install a dynamic deny rule across the Bounce suite.

        Resolves each target pattern to the right bouncer(s), writes
        the rule to ~/.iam-jit/dynamic-denies.yaml (atomically, 0600),
        and POSTs each affected bouncer's
        /admin/dynamic-denies/reload endpoint.
        """
        exit_code = _do_add(
            targets=targets,
            reason=reason,
            duration=duration,
            applies_to_recommender=applies_to_recommender,
            bouncer_overrides=bouncer_overrides,
            bouncer_url_overrides=bouncer_url_overrides,
            path=path,
            as_json=as_json,
        )
        sys.exit(exit_code)

    # -- list -----------------------------------------------------------

    @deny_group.command("list")
    @click.option(
        "--bouncer", "bouncer_filter",
        multiple=True,
        type=click.Choice(["ibounce", "kbouncer", "kbounce", "dbounce", "gbounce"]),
        help="Filter to rules whose `applied_to` includes the named "
             "bouncer(s). Repeatable.",
    )
    @click.option(
        "--include-expired",
        is_flag=True,
        default=False,
        help="Include rules whose `expires_at` is in the past.",
    )
    @click.option(
        "--path",
        type=click.Path(dir_okay=False),
        default=None,
        help=_PATH_HELP,
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured shape as JSON.",
    )
    def deny_list(
        bouncer_filter: tuple[str, ...],
        include_expired: bool,
        path: str | None,
        as_json: bool,
    ) -> None:
        """List active dynamic deny rules."""
        exit_code = _do_list(
            bouncer_filter=bouncer_filter,
            include_expired=include_expired,
            path=path,
            as_json=as_json,
        )
        sys.exit(exit_code)

    # -- remove ---------------------------------------------------------

    @deny_group.command("remove")
    @click.argument("ids", nargs=-1)
    @click.option(
        "--reason",
        default=None,
        help="Optional audit-trail metadata; surfaces in the "
             "`dynamic_deny.removed` admin-action event.",
    )
    @click.option(
        "--reason-match",
        default=None,
        metavar="REGEX",
        help="Bulk-remove rules whose `reason` field matches REGEX.",
    )
    @click.option(
        "--expired",
        "drop_expired",
        is_flag=True,
        default=False,
        help="Drop every rule whose `expires_at` is in the past.",
    )
    @click.option(
        "--bouncer-url", "bouncer_url_overrides",
        multiple=True,
        metavar="NAME=URL",
        help=_BOUNCER_URL_HELP,
    )
    @click.option(
        "--path",
        type=click.Path(dir_okay=False),
        default=None,
        help=_PATH_HELP,
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit the structured shape as JSON.",
    )
    def deny_remove(
        ids: tuple[str, ...],
        reason: str | None,
        reason_match: str | None,
        drop_expired: bool,
        bouncer_url_overrides: tuple[str, ...],
        path: str | None,
        as_json: bool,
    ) -> None:
        """Remove one or more dynamic deny rules.

        Org-distributed rules cannot be loosened by a personal remove;
        the request is refused with a structured warning pointing at
        the rule's `org_distributed_url`.
        """
        exit_code = _do_remove(
            ids=ids,
            reason=reason,
            reason_match=reason_match,
            drop_expired=drop_expired,
            bouncer_url_overrides=bouncer_url_overrides,
            path=path,
            as_json=as_json,
        )
        sys.exit(exit_code)

    # -- show -----------------------------------------------------------

    @deny_group.command("show")
    @click.argument("id_", metavar="ID", required=False)
    @click.option(
        "--path",
        type=click.Path(dir_okay=False),
        default=None,
        help=_PATH_HELP,
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit the full rule object as JSON.",
    )
    def deny_show(
        id_: str | None,
        path: str | None,
        as_json: bool,
    ) -> None:
        """Show one dynamic deny rule including provenance."""
        exit_code = _do_show(
            rule_id=id_,
            path=path,
            as_json=as_json,
        )
        sys.exit(exit_code)

    return deny_group


__all__ = [
    "DESIGN_DOC_PATH",
    "DESIGN_DOC_URL",
    "REPLACEMENT_SLICE",
    "SCHEMA_PATH",
    "TRACKING_REFS",
    "register_deny_group",
]
