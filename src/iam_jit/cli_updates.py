"""#408 / §A52 — ``iam-jit updates`` CLI surface + MCP backends.

Operator surface for the threat-feed subscription mechanic. Mirrors the
cross-product agent parity shape ([[cross-product-agent-parity]]):

  CLI                          MCP tool
  ---                          --------
  iam-jit updates list         bounce_updates_recent
  iam-jit updates pin          bounce_updates_pin       (POST-LAUNCH; not
                                                         shipped here)
  iam-jit updates unpin        bounce_updates_unpin     (same)
  iam-jit updates dry-run      bounce_updates_dry_run
  iam-jit updates revoke       bounce_updates_revoke
  iam-jit updates last-fetch   bounce_update_status

Per [[ibounce-honest-positioning]] `last-fetch` surfaces BOTH the last
successful fetch AND the last attempt — so the operator sees stale
cache + recent failure simultaneously, never one without the other.

Per [[no-hosted-saas]] there is no centralized state — everything is
local: cache files + applied-ledger + the declarative config.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import sys
import typing

import click

from .threat_feed import (
    FeedFetchError,
    Subscription,
    SubscriptionConfigError,
    apply_feed_entries,
    fetch_feed,
    load_subscriptions_from_declaration,
)
from .threat_feed.applier import (
    load_ledger,
    peek_latest_application,
    record_revoked_in_ledger,
    resolve_ledger_path,
)
from .threat_feed.fetcher import (
    _meta_path as _fetch_meta_path,
    load_cached_feed,
    resolve_cache_dir,
)
from .threat_feed.models import Severity, severity_at_or_above, severity_from_str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_declaration_silently(
    config_path: pathlib.Path | None,
    cwd: pathlib.Path | None,
) -> tuple[dict[str, typing.Any] | None, str]:
    """Load the declarative config without raising. Returns
    ``(declaration | None, source_label)``."""
    try:
        from .ambient_config import load_declaration

        return load_declaration(config_path, cwd=cwd)
    except Exception as e:
        return None, f"(could not load declaration: {e})"


def _load_subscriptions(
    config_path: pathlib.Path | None = None,
    cwd: pathlib.Path | None = None,
) -> tuple[list[Subscription], dict[str, typing.Any], str]:
    """Load subscriptions for the current cwd. Returns
    ``(subscriptions, threat_feed_block, source_label)``."""
    declaration, source = _load_declaration_silently(config_path, cwd)
    try:
        subs, block = load_subscriptions_from_declaration(declaration or {})
    except SubscriptionConfigError as e:
        raise click.ClickException(f"threat_feed config error: {e}") from e
    return subs, block, source


def _format_compliance_tags(tags: typing.Sequence[str]) -> str:
    return ", ".join(tags) if tags else "(none)"


# ---------------------------------------------------------------------------
# `updates list`
# ---------------------------------------------------------------------------


def _filter_records(
    records: typing.Sequence[dict[str, typing.Any]],
    *,
    since: str = "",
    severity_min: Severity | None = None,
    feed_url: str = "",
    show_refused: bool = False,
) -> list[dict[str, typing.Any]]:
    import datetime as _dt
    import re

    out: list[dict[str, typing.Any]] = []
    since_dt: _dt.datetime | None = None
    if since.strip():
        # Reuse the existing short-form parser.
        m = re.match(r"^(\d+)([smhdw])$", since.strip())
        if m:
            n = int(m.group(1))
            unit = m.group(2)
            delta = {
                "s": _dt.timedelta(seconds=n),
                "m": _dt.timedelta(minutes=n),
                "h": _dt.timedelta(hours=n),
                "d": _dt.timedelta(days=n),
                "w": _dt.timedelta(weeks=n),
            }[unit]
            since_dt = _dt.datetime.now(_dt.timezone.utc) - delta
    for r in records:
        if not show_refused and r.get("status") in (
            "refused_verification", "revoked",
        ):
            continue
        if feed_url and (r.get("feed_url") or "") != feed_url:
            continue
        if severity_min:
            sev_raw = r.get("severity") or ""
            try:
                sev = severity_from_str(sev_raw)
            except ValueError:
                continue
            if not severity_at_or_above(sev, severity_min):
                continue
        if since_dt:
            applied_at = r.get("applied_at") or r.get("revoked_at") or ""
            try:
                tt = _dt.datetime.fromisoformat(
                    applied_at.replace("Z", "+00:00"),
                )
            except ValueError:
                continue
            if tt < since_dt:
                continue
        out.append(r)
    return out


def _do_list(
    *,
    since: str,
    severity: str,
    feed_url: str,
    show_refused: bool,
    as_json: bool,
) -> int:
    severity_min: Severity | None = None
    if severity.strip():
        try:
            severity_min = severity_from_str(severity)
        except ValueError as e:
            click.secho(f"updates list: {e}", fg="red", err=True)
            return 2
    records = load_ledger()
    filtered = _filter_records(
        records,
        since=since,
        severity_min=severity_min,
        feed_url=feed_url,
        show_refused=show_refused,
    )
    payload = {
        "schema_version": "1.0",
        "ledger_path": str(resolve_ledger_path()),
        "filters": {
            "since": since,
            "severity_min": severity_min.value if severity_min else None,
            "feed_url": feed_url,
            "show_refused": show_refused,
        },
        "count": len(filtered),
        "records": filtered,
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, default=str))
        return 0
    if not filtered:
        click.secho(
            f"(no threat-feed entries matching filters; "
            f"ledger: {resolve_ledger_path()})",
            fg="yellow",
        )
        return 0
    click.echo(f"{len(filtered)} threat-feed entries:")
    click.echo("")
    for r in filtered:
        click.echo(
            f"  {r.get('rule_id', '?'):<28}  "
            f"{r.get('severity', '?'):<8}  "
            f"{r.get('rule_kind', '?'):<28}  "
            f"{r.get('status', '?')}"
        )
        click.echo(f"      from: {r.get('feed_url', '?')}")
        if r.get("source_incident"):
            click.echo(f"      incident: {r['source_incident']}")
        if r.get("compliance_tags"):
            click.echo(
                f"      compliance: {_format_compliance_tags(r['compliance_tags'])}"
            )
        if r.get("applied_artifact_id"):
            click.echo(f"      artifact: {r['applied_artifact_id']}")
        if r.get("pending_entry_id"):
            click.echo(f"      pending: {r['pending_entry_id']}")
        if r.get("error"):
            click.secho(f"      ERROR: {r['error']}", fg="red")
        click.echo("")
    return 0


# ---------------------------------------------------------------------------
# `updates pin / unpin`
# ---------------------------------------------------------------------------


def _do_pin(
    feed_url: str,
    publisher_pubkey: str,
    *,
    severity_threshold: str,
    verification_mode: str,
    cosign_identity: str,
    cosign_issuer: str,
    nickname: str,
    as_json: bool,
) -> int:
    # We DO NOT mutate the operator's declarative config from the CLI —
    # per [[creates-never-mutates]] config mutation is operator-only.
    # `pin` instead emits the YAML snippet they should paste.
    snippet = {
        "iam-jit": {
            "threat_feed": {
                "enabled": True,
                "update_cadence": "daily",
                "feeds": [
                    {
                        "url": feed_url,
                        "publisher_pubkey": publisher_pubkey,
                        "verification_mode": verification_mode,
                        "severity_auto_apply_threshold": severity_threshold,
                        "nickname": nickname,
                    },
                ],
            },
        },
    }
    if verification_mode == "cosign-keyless":
        snippet["iam-jit"]["threat_feed"]["feeds"][0].update({
            "cosign_identity": cosign_identity,
            "cosign_issuer": cosign_issuer,
        })
    if as_json:
        click.echo(json.dumps(snippet, indent=2))
        return 0
    try:
        from ruamel.yaml import YAML
        from io import StringIO
        yaml = YAML(typ="safe")
        yaml.default_flow_style = False
        sio = StringIO()
        yaml.dump(snippet, sio)
        rendered = sio.getvalue()
    except Exception:
        rendered = json.dumps(snippet, indent=2)
    click.secho(
        "PASTE this into your .iam-jit.yaml (or CLAUDE.md / AGENTS.md / "
        ".cursorrules YAML codeblock) — per [[creates-never-mutates]] "
        "we don't mutate your config file directly:",
        fg="yellow",
    )
    click.echo("")
    click.echo(rendered)
    return 0


def _do_unpin(
    feed_url: str,
    *,
    as_json: bool,
) -> int:
    msg = (
        f"To unpin {feed_url!r}: remove its entry from your "
        f".iam-jit.yaml threat_feed.feeds list. Per "
        f"[[creates-never-mutates]] the CLI does not edit your config.\n"
        f"To purge the cache: rm -rf {resolve_cache_dir()}"
    )
    if as_json:
        click.echo(json.dumps({"feed_url": feed_url, "instructions": msg}, indent=2))
        return 0
    click.secho(msg, fg="yellow")
    return 0


# ---------------------------------------------------------------------------
# `updates dry-run`
# ---------------------------------------------------------------------------


def _do_dry_run(
    feed_url: str,
    *,
    config_path: pathlib.Path | None,
    cwd: pathlib.Path | None,
    as_json: bool,
) -> int:
    subs, _block, _src = _load_subscriptions(config_path, cwd)
    subscription = next((s for s in subs if s.url == feed_url), None)
    if subscription is None:
        click.secho(
            f"updates dry-run: feed {feed_url!r} not pinned in "
            f"declarative config; pin it first via `iam-jit updates pin`",
            fg="red",
            err=True,
        )
        return 2
    try:
        result = fetch_feed(feed_url)
    except FeedFetchError as e:
        click.secho(f"updates dry-run: fetch failed: {e}", fg="red", err=True)
        return 2
    if result.feed is None:
        click.secho(
            f"updates dry-run: feed unavailable: {result.error}",
            fg="red",
            err=True,
        )
        return 2
    outcomes = apply_feed_entries(
        result.feed,
        subscription,
        posture="ambient",
        dry_run=True,
    )
    payload = {
        "feed_url": feed_url,
        "feed_id": result.feed.feed_id,
        "publisher": result.feed.publisher,
        "manifest_sha256": result.feed.manifest_sha256,
        "entry_count": len(result.feed.entries),
        "outcomes": [o.as_dict() for o in outcomes],
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, default=str))
        return 0
    click.echo(
        f"DRY-RUN  {feed_url}  ({len(result.feed.entries)} entries; "
        f"publisher={result.feed.publisher})"
    )
    click.echo("")
    for o in outcomes:
        marker = "[OK]" if o.verified else "[REFUSED]"
        click.echo(
            f"  {marker} {o.rule_id:<28}  "
            f"{o.severity.value:<8}  "
            f"action={o.action}  "
            f"kind={o.rule_kind}"
        )
        click.echo(f"    target: {o.target}")
        click.echo(f"    explanation: {o.explanation}")
    return 0


# ---------------------------------------------------------------------------
# `updates revoke`
# ---------------------------------------------------------------------------


def _do_revoke(
    rule_id: str,
    *,
    as_json: bool,
) -> int:
    """Revoke a previously-applied threat-feed entry.

    Order-of-operations (per [[ibounce-honest-positioning]]):

      1. Peek the latest ledger application — exit 1 if absent.
      2. If the prior was an auto-apply of a ``dynamic_deny``, call
         ``remove_rules(rule_ids=[artifact_id])`` to actually delete
         the rule from ``dynamic-denies.yaml`` + fan out a reload.
      3. ONLY when step 2 succeeds (or was unnecessary) do we append a
         ``status="revoked"`` record to the ledger.

    The historical implementation appended the revoke FIRST + then tried
    the bouncer-side removal — meaning a bouncer failure left the ledger
    falsely advertising "revoked" while the YAML still contained the
    rule. That violated [[ibounce-honest-positioning]] (status reporting
    must match reality) + was the §A51b CRIT.
    """
    prior = peek_latest_application(rule_id)
    if prior is None:
        click.secho(
            f"updates revoke: rule_id {rule_id!r} not found in ledger",
            fg="yellow",
            err=True,
        )
        return 1
    artifact_id = prior.get("applied_artifact_id") or ""
    bouncer_remove_result: dict[str, typing.Any] = {}
    bouncer_error: str | None = None
    needs_bouncer_remove = bool(
        artifact_id and prior.get("action") in ("auto_apply", "auto_apply_notify")
    )
    if needs_bouncer_remove:
        try:
            from .dynamic_denies.operations import remove_rules

            removed = remove_rules(
                rule_ids=[artifact_id],
                skip_fanout=False,
            )
            bouncer_remove_result = {
                "removed_count": int(removed.get("removed_count") or 0),
                "removed_ids": list(removed.get("removed_ids") or []),
                "not_found": list(removed.get("not_found") or []),
                "fanout": list(removed.get("fanout") or []),
            }
        except Exception as e:
            bouncer_error = f"{type(e).__name__}: {e}"
            bouncer_remove_result = {"error": bouncer_error}

    if bouncer_error is not None:
        payload = {
            "rule_id": rule_id,
            "prior": prior,
            "bouncer_remove": bouncer_remove_result,
            "ledger_updated": False,
            "error": bouncer_error,
        }
        if as_json:
            click.echo(json.dumps(payload, indent=2, default=str))
        else:
            click.secho(
                f"FAIL  revoke aborted for {rule_id}: bouncer-side removal "
                f"failed ({bouncer_error})",
                fg="red",
                err=True,
            )
            click.secho(
                "  ledger unchanged — rule_id is still active. Inspect the "
                "bouncer + dynamic-denies.yaml + retry.",
                fg="red",
                err=True,
            )
        return 2

    # Bouncer-side removal succeeded (or wasn't needed). Now and only
    # now do we mark the ledger.
    record_revoked_in_ledger(rule_id, prior)

    # Per [[ibounce-honest-positioning]] surface fan-out reload failures
    # honestly. The dynamic-denies.yaml on THIS host was updated (so
    # ledger-revoked is truthful here), but a downstream bouncer that
    # holds a cached copy may still be enforcing the rule until its
    # next reload — surface that so the operator doesn't think the
    # revoke is globally effective when it isn't.
    fanout_failures = [
        f for f in bouncer_remove_result.get("fanout", [])
        if not f.get("reloaded", False)
    ] if needs_bouncer_remove else []

    payload = {
        "rule_id": rule_id,
        "prior": prior,
        "bouncer_remove": bouncer_remove_result,
        "ledger_updated": True,
        "fanout_failures": fanout_failures,
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, default=str))
        return 0
    click.secho(f"OK  revoked {rule_id}", fg="green")
    if artifact_id:
        click.echo(f"  prior artifact: {artifact_id}")
    if needs_bouncer_remove:
        removed_count = bouncer_remove_result.get("removed_count", 0)
        click.echo(
            f"  bouncer remove: {removed_count} rule(s) removed from "
            f"dynamic-denies.yaml"
        )
        if fanout_failures:
            click.secho(
                f"  fanout: {len(fanout_failures)} bouncer(s) did NOT reload — "
                f"they may still enforce this rule until their next reload",
                fg="yellow",
            )
            for f in fanout_failures:
                bouncer = f.get("bouncer") or "(unknown)"
                err = f.get("error") or "unknown error"
                click.secho(f"    - {bouncer}: {err}", fg="yellow")
    else:
        click.echo("  bouncer remove: (no dynamic-deny artifact to remove)")
    return 0


# ---------------------------------------------------------------------------
# `updates last-fetch`
# ---------------------------------------------------------------------------


def _do_last_fetch(
    *,
    config_path: pathlib.Path | None,
    cwd: pathlib.Path | None,
    as_json: bool,
) -> int:
    subs, _block, source = _load_subscriptions(config_path, cwd)
    rows: list[dict[str, typing.Any]] = []
    for s in subs:
        cached, meta = load_cached_feed(s.url)
        rows.append({
            "url": s.url,
            "label": s.label(),
            "enabled": s.enabled,
            "verification_mode": s.verification_mode,
            "severity_auto_apply_threshold": s.severity_auto_apply_threshold.value,
            "last_fetch_at": meta.get("last_fetch_at"),
            "last_fetch_status": meta.get("last_fetch_status"),
            "http_status": meta.get("http_status"),
            "manifest_sha256": meta.get("manifest_sha256"),
            "entry_count": meta.get("entry_count"),
            "cache_present": cached is not None,
        })
    payload = {
        "schema_version": "1.0",
        "declaration_source": source,
        "feeds": rows,
        "cache_dir": str(resolve_cache_dir()),
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, default=str))
        return 0
    if not rows:
        click.secho(
            "(no threat-feed subscriptions declared)",
            fg="yellow",
        )
        return 0
    click.echo(f"declaration_source: {source}")
    click.echo(f"cache_dir:          {resolve_cache_dir()}")
    click.echo("")
    for r in rows:
        click.echo(
            f"  {r['label']:<40}  "
            f"{'enabled' if r['enabled'] else 'paused':<8}  "
            f"last_fetch={r['last_fetch_at'] or '(never)'}  "
            f"status={r['last_fetch_status'] or '(unknown)'}  "
            f"entries={r['entry_count'] or '?'}"
        )
    return 0


# ---------------------------------------------------------------------------
# Click registration
# ---------------------------------------------------------------------------


def register_updates_command(parent_group: click.Group) -> click.Group:
    """Attach the ``updates`` subgroup to the iam-jit CLI."""

    @parent_group.group("updates")
    def updates() -> None:
        """Threat-feed subscription mechanic (#407-#411).

        Subscribe to operator-pinned threat feeds; CRITICAL+HIGH
        entries auto-apply, MEDIUM goes through pending-approval,
        LOW is informational. Per [[independence-as-security-property]]
        feeds are OPERATOR-pinned with Ed25519 (or cosign keyless)
        verification — no phone-home.
        """

    @updates.command("list")
    @click.option("--since", type=str, default="", help="Filter to entries applied/refused within window (e.g. 7d).")
    @click.option("--severity", type=str, default="", help="Filter to severity ≥ this (CRITICAL/HIGH/MEDIUM/LOW).")
    @click.option("--feed", "feed_url", type=str, default="", help="Filter to one feed URL.")
    @click.option("--show-refused", is_flag=True, default=False, help="Include refused (verification failure) + revoked entries.")
    @click.option("--json", "as_json", is_flag=True, default=False)
    def list_cmd(since, severity, feed_url, show_refused, as_json):
        """List entries from the applied-ledger."""
        sys.exit(_do_list(
            since=since,
            severity=severity,
            feed_url=feed_url,
            show_refused=show_refused,
            as_json=as_json,
        ))

    @updates.command("pin")
    @click.argument("feed_url", type=str)
    @click.argument("publisher_pubkey", type=str)
    @click.option("--severity-threshold", type=str, default="HIGH", help="Min severity for auto-apply (default HIGH).")
    @click.option("--verification-mode", type=click.Choice(["ed25519", "cosign-keyless"]), default="ed25519")
    @click.option("--cosign-identity", type=str, default="")
    @click.option("--cosign-issuer", type=str, default="")
    @click.option("--nickname", type=str, default="")
    @click.option("--json", "as_json", is_flag=True, default=False)
    def pin_cmd(feed_url, publisher_pubkey, severity_threshold, verification_mode, cosign_identity, cosign_issuer, nickname, as_json):
        """Emit YAML snippet to paste into .iam-jit.yaml."""
        sys.exit(_do_pin(
            feed_url,
            publisher_pubkey,
            severity_threshold=severity_threshold,
            verification_mode=verification_mode,
            cosign_identity=cosign_identity,
            cosign_issuer=cosign_issuer,
            nickname=nickname,
            as_json=as_json,
        ))

    @updates.command("unpin")
    @click.argument("feed_url", type=str)
    @click.option("--json", "as_json", is_flag=True, default=False)
    def unpin_cmd(feed_url, as_json):
        """Print instructions for removing a feed from your config."""
        sys.exit(_do_unpin(feed_url, as_json=as_json))

    @updates.command("dry-run")
    @click.argument("feed_url", type=str)
    @click.option(
        "--config",
        "config_path",
        type=click.Path(dir_okay=False, path_type=pathlib.Path),
        default=None,
    )
    @click.option(
        "--cwd",
        type=click.Path(file_okay=False, dir_okay=True, path_type=pathlib.Path),
        default=None,
    )
    @click.option("--json", "as_json", is_flag=True, default=False)
    def dry_run_cmd(feed_url, config_path, cwd, as_json):
        """Preview what a feed would apply WITHOUT mutating state."""
        sys.exit(_do_dry_run(
            feed_url,
            config_path=config_path,
            cwd=cwd,
            as_json=as_json,
        ))

    @updates.command("revoke")
    @click.argument("rule_id", type=str)
    @click.option("--json", "as_json", is_flag=True, default=False)
    def revoke_cmd(rule_id, as_json):
        """Revoke a previously-applied feed entry by rule_id."""
        sys.exit(_do_revoke(rule_id, as_json=as_json))

    @updates.command("last-fetch")
    @click.option(
        "--config",
        "config_path",
        type=click.Path(dir_okay=False, path_type=pathlib.Path),
        default=None,
    )
    @click.option(
        "--cwd",
        type=click.Path(file_okay=False, dir_okay=True, path_type=pathlib.Path),
        default=None,
    )
    @click.option("--json", "as_json", is_flag=True, default=False)
    def last_fetch_cmd(config_path, cwd, as_json):
        """Show per-feed last-fetch status."""
        sys.exit(_do_last_fetch(
            config_path=config_path,
            cwd=cwd,
            as_json=as_json,
        ))

    return updates


# ---------------------------------------------------------------------------
# MCP backends
# ---------------------------------------------------------------------------


def updates_recent_for_mcp(args: dict[str, typing.Any]) -> dict[str, typing.Any]:
    """MCP backend for ``bounce_updates_recent``."""
    since = str(args.get("since") or "")
    severity = str(args.get("severity") or "")
    feed_url = str(args.get("feed_url") or "")
    show_refused = bool(args.get("show_refused", False))
    severity_min: Severity | None = None
    if severity:
        try:
            severity_min = severity_from_str(severity)
        except ValueError as e:
            return {"status": "error", "code": "bad_severity", "message": str(e)}
    records = load_ledger()
    filtered = _filter_records(
        records,
        since=since,
        severity_min=severity_min,
        feed_url=feed_url,
        show_refused=show_refused,
    )
    return {
        "status": "ok",
        "schema_version": "1.0",
        "ledger_path": str(resolve_ledger_path()),
        "count": len(filtered),
        "records": filtered,
        "filters": {
            "since": since,
            "severity_min": severity_min.value if severity_min else None,
            "feed_url": feed_url,
            "show_refused": show_refused,
        },
    }


def update_status_for_mcp(args: dict[str, typing.Any]) -> dict[str, typing.Any]:
    """MCP backend for ``bounce_update_status`` (per-feed health)."""
    config_path_raw = args.get("config_path")
    config_path = pathlib.Path(config_path_raw) if config_path_raw else None
    cwd_raw = args.get("cwd")
    cwd = pathlib.Path(cwd_raw) if cwd_raw else None
    try:
        subs, _block, source = _load_subscriptions(config_path, cwd)
    except click.ClickException as e:
        return {"status": "error", "code": "config", "message": e.message}
    rows: list[dict[str, typing.Any]] = []
    for s in subs:
        cached, meta = load_cached_feed(s.url)
        rows.append({
            "url": s.url,
            "label": s.label(),
            "enabled": s.enabled,
            "verification_mode": s.verification_mode,
            "severity_auto_apply_threshold": s.severity_auto_apply_threshold.value,
            "last_fetch_at": meta.get("last_fetch_at"),
            "last_fetch_status": meta.get("last_fetch_status"),
            "http_status": meta.get("http_status"),
            "manifest_sha256": meta.get("manifest_sha256"),
            "entry_count": meta.get("entry_count"),
            "cache_present": cached is not None,
        })
    return {
        "status": "ok",
        "schema_version": "1.0",
        "declaration_source": source,
        "feeds": rows,
        "cache_dir": str(resolve_cache_dir()),
    }


__all__ = [
    "register_updates_command",
    "update_status_for_mcp",
    "updates_recent_for_mcp",
]
