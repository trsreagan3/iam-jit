"""Cross-product session-recording replay CLI — #285 part B.

Mounts under `iam-jit session replay <FILE>` (alongside the existing
`iam-jit audit query` / `iam-jit audit stream` subgroups). Reads a
session-recording NDJSON file produced by ANY of the four Bounce
products (ibounce / kbounce / dbounce / gbounce — same on-disk shape per
[[cross-product-agent-parity]]) and walks through the events one-by-one
with the bouncer's verdict + the operator's choice of timing mode.

Three modes
-----------

* Default: prints each event with a timing-delta from the previous one
  ("+1.243s") and a one-line summary. Best for a quick "what happened"
  scan or piping into a less.
* `--realtime`: sleeps between events to preserve the original timing.
  Useful for demos + auditor walkthroughs — the replay feels like
  watching the agent act in real time.
* `--what-if-profile NAME`: re-evaluates every event against the named
  profile (loaded from the local ibounce profile store) and reports
  every verdict difference. The killer use case for an auditor: "what
  WOULD have happened if the bouncer had been running profile X?".

Per [[creates-never-mutates]]: this CLI is read-only over the recording
file + the local profile store; it never forwards to AWS, never writes
the recording back, and never modifies any external state.

Per [[self-host-zero-billing-dependency]]: entirely local; no network.

What-if profile sourcing
-------------------------

The replay CLI is cross-product but the profile-evaluator lives inside
each product. For ibounce (Python) we import the profile loader
directly. For kbounce / dbounce / gbounce (Go) the evaluator isn't
callable from Python without a subprocess or RPC; that gap is
documented in `docs/SESSION-REPLAY.md` and shows a clear stderr message
when an operator points `--what-if-profile` at a non-ibounce recording.
The replay itself still works for every product's recordings; only the
what-if diff is product-scoped.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import time
from typing import Any

import click

from .bouncer.audit_export import read_session_file

# Tiny filter grammar — same shape used by #268 (audit-event filter).
# Supports `key=value`, `key!=value`, `key~/regex/` and `&&`/`||`. Kept
# minimal so the replay CLI stays useful without a parser dependency.
_FILTER_TOKEN_RE = re.compile(
    r"^(?P<key>[A-Za-z0-9_.]+)(?P<op>!=|=|~)(?P<val>.*)$"
)


def _walk_value(obj: Any, dotted_key: str) -> Any:
    """Walk a dotted path through a nested dict. Returns None on miss."""
    cur: Any = obj
    for part in dotted_key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _evaluate_filter(event: dict[str, Any], expr: str) -> bool:
    """Tiny filter evaluator. Conjunction-only (`&&`) for v1; an `||`
    case can be added when an operator surfaces a need."""
    parts = [p.strip() for p in expr.split("&&")]
    for part in parts:
        m = _FILTER_TOKEN_RE.match(part)
        if not m:
            raise click.ClickException(f"unparseable filter clause: {part!r}")
        key, op, val = m.group("key"), m.group("op"), m.group("val")
        actual = _walk_value(event, key)
        actual_s = "" if actual is None else str(actual)
        if op == "=":
            if actual_s != val:
                return False
        elif op == "!=":
            if actual_s == val:
                return False
        elif op == "~":
            try:
                if not re.search(val, actual_s):
                    return False
            except re.error as e:
                raise click.ClickException(
                    f"invalid regex in filter clause {part!r}: {e}"
                ) from e
        else:  # pragma: no cover — guarded by regex
            raise click.ClickException(f"unknown operator: {op!r}")
    return True


def _format_event_oneline(event: dict[str, Any], delta_s: float | None) -> str:
    """One-line summary of an event for the default-mode print."""
    op = (
        _walk_value(event, "api.operation")
        or event.get("activity_name")
        or "?"
    )
    svc = _walk_value(event, "api.service.name") or "?"
    verdict = _walk_value(event, "unmapped.iam_jit.verdict") or "-"
    profile = _walk_value(event, "unmapped.iam_jit.profile") or "-"
    delta = f"+{delta_s:.3f}s" if delta_s is not None else " 0.000s "
    return f"  [{delta:>9s}]  {svc}:{op:30s}  verdict={verdict:10s}  profile={profile}"


def _diff_oneline(
    event: dict[str, Any],
    recorded_verdict: str,
    new_verdict: str,
    reason: str,
) -> str:
    op = (
        _walk_value(event, "api.operation")
        or event.get("activity_name")
        or "?"
    )
    svc = _walk_value(event, "api.service.name") or "?"
    arrow = "->"
    return (
        f"  {svc}:{op:30s}  recorded={recorded_verdict:10s}  "
        f"{arrow} what-if={new_verdict:10s}  ({reason})"
    )


def _build_request_from_event(event: dict[str, Any]) -> dict[str, Any]:
    """Project an OCSF event back into the shape `decide()` expects.

    The bouncer's decide() takes a parsed request dict with keys
    `service`, `operation`, `region`, `account_id`, `account_alias`,
    `arn`, `principal`. We pull the same fields out of the OCSF event
    so the what-if path doesn't need the original request body.
    """
    service = _walk_value(event, "api.service.name") or ""
    operation = _walk_value(event, "api.operation") or ""
    resources = event.get("resources") or []
    arn = ""
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            arn = first.get("uid") or ""
    cloud = _walk_value(event, "cloud") or {}
    region = ""
    account_id = ""
    if isinstance(cloud, dict):
        region = cloud.get("region", "") or ""
        account_id = cloud.get("account_uid", "") or ""
    account_alias = (
        _walk_value(event, "unmapped.iam_jit.account_alias") or ""
    )
    principal = _walk_value(event, "actor.user.uid") or ""
    return {
        "service": str(service),
        "operation": str(operation),
        "region": str(region),
        "account_id": str(account_id),
        "account_alias": str(account_alias),
        "arn": str(arn),
        "principal": str(principal),
    }


def _what_if_evaluator(profile_name: str):
    """Resolve a callable `(event) -> (verdict_str, reason_str)` from
    the named ibounce profile.

    Returns the callable + a one-line description of the loaded profile.
    Raises click.ClickException if the profile can't be loaded.

    What-if uses ENFORCE mode (default-policy ALLOW) because that's the
    shape the proxy uses internally to compute every audited verdict —
    the COOPERATIVE/TRANSPARENT distinction is purely about whether the
    proxy 403s the request or forwards anyway (the verdict itself is
    computed the same way). For replay we want the verdict, not the
    forwarding posture.
    """
    from .bouncer.decisions import DefaultPolicy, Mode, decide
    from .bouncer.profiles import (
        evaluate_profile,
        load_profiles,
        resolve_active_profile,
    )
    from .bouncer.rules import Effect, ProxyRule, RuleSet

    try:
        profiles = load_profiles()
        profile = resolve_active_profile(
            cli_flag=profile_name, profiles=profiles,
        )
    except (ValueError, FileNotFoundError) as e:
        raise click.ClickException(
            f"failed to load what-if profile {profile_name!r}: {e}"
        ) from e

    # Compose the profile's allow_rules into a standalone ruleset so the
    # what-if path mirrors the proxy's composition. We deliberately do
    # NOT pull in the local SQLite-store global rules: what-if asks
    # "what would THIS profile do" — global rules vary per box and
    # would muddy the diff. An operator who wants global + profile
    # together can run the recording through their live proxy with
    # `--profile X` instead.
    composed_rules: list[ProxyRule] = []
    for par in profile.allow_rules:
        composed_rules.append(ProxyRule(
            pattern=par.pattern,
            effect=Effect.ALLOW,
            arn_scope=par.arn_scope,
            region_scope=par.region_scope,
            note=par.note or f"from profile {profile.name}",
            origin="profile",
        ))
    ruleset = RuleSet(rules=composed_rules)

    def evaluate(event: dict[str, Any]) -> tuple[str, str]:
        req = _build_request_from_event(event)
        # Profile-layer check first (mirrors evaluate_request).
        try:
            prof_verdict = evaluate_profile(
                profile,
                arn=req["arn"] or None,
                resource_name=req["arn"] or None,
                account_id=req["account_id"] or None,
                account_alias=req["account_alias"] or None,
                service=req["service"],
                action=req["operation"],
            )
        except Exception as e:  # noqa: BLE001
            return ("error", f"profile-eval raised: {e}")
        if prof_verdict.denied:
            return ("deny", prof_verdict.reason or "profile-fired deny")
        # Fall through to ruleset evaluation. Default-policy ALLOW so a
        # profile that doesn't enumerate is permissive by construction —
        # matches the safe-default vs full-user distinction.
        try:
            record = decide(
                ruleset,
                mode=Mode.ENFORCE,
                default_policy=DefaultPolicy.ALLOW,
                service=req["service"],
                action=req["operation"],
                arn=req["arn"] or None,
                region=req["region"] or None,
            )
        except Exception as e:  # noqa: BLE001
            return ("error", f"decide() raised: {e}")
        return (str(record.decision.value), str(record.reason or ""))

    return evaluate, profile.name


def register_session_replay_group(main_group: click.Group) -> click.Group:
    """Mount `iam-jit session replay <FILE>` on the top-level CLI.

    Returns the `session` group so callers can extend it later (a
    `bundle` subcommand for #273-style multi-session evidence packs is
    on the list for v1.1)."""

    @main_group.group("session")
    def session_group() -> None:
        """Replay session recordings produced by any Bounce product.

        Recordings are NDJSON files (one per agent session) written by
        the proxy when run with `--record-sessions-dir`. The same shape
        works across ibounce / kbounce / dbounce / gbounce per
        [[cross-product-agent-parity]]. Replay is the time-axis
        complement to `iam-jit audit query` (entity-axis) + #273
        `iam-jit investigate` (Claude analysis).
        """

    @session_group.command("replay")
    @click.argument("file_path", type=click.Path(dir_okay=False))
    @click.option(
        "--realtime",
        is_flag=True,
        default=False,
        help="Sleep between events to preserve original timing. Useful "
             "for demos + auditor walkthroughs.",
    )
    @click.option(
        "--what-if-profile",
        "what_if_profile",
        default=None,
        help="Re-evaluate each event against the named local profile + "
             "report verdict differences. Currently supported for "
             "ibounce recordings; kbounce / dbounce / gbounce surface "
             "a clear gap message (see docs/SESSION-REPLAY.md).",
    )
    @click.option(
        "--filter",
        "filter_expr",
        default=None,
        help="Conjunctive filter expression. Tokens: "
             "`key=value`, `key!=value`, `key~regex`; join with `&&`. "
             "Keys are dotted paths into the OCSF event (e.g. "
             "`api.service.name=s3 && unmapped.iam_jit.verdict=deny`).",
    )
    @click.option(
        "--max-events",
        "max_events",
        type=int,
        default=None,
        help="Cap the number of events processed.",
    )
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit one JSON object per event (overrides the default "
             "human format). Pipe-friendly.",
    )
    def replay_cmd(
        file_path: str,
        realtime: bool,
        what_if_profile: str | None,
        filter_expr: str | None,
        max_events: int | None,
        as_json: bool,
    ) -> None:
        """Replay one session recording with optional what-if re-evaluation."""
        path = pathlib.Path(file_path)
        try:
            meta, events = read_session_file(path)
        except FileNotFoundError as e:
            click.secho(str(e), fg="red", err=True)
            sys.exit(2)
        except ValueError as e:
            click.secho(str(e), fg="red", err=True)
            sys.exit(2)

        bouncer = meta.get("bouncer_product", "unknown")
        sid = meta.get("session_id", "unknown")
        agent = meta.get("agent_name", "unknown")
        started = meta.get("recording_started_at", "?")
        if not as_json:
            click.echo(
                f"replaying session {sid} (agent={agent}, "
                f"bouncer={bouncer}, started={started}, "
                f"events={len(events)})"
            )

        # Set up the what-if evaluator if requested. For non-ibounce
        # recordings we surface the gap on stderr + skip the what-if
        # path; the replay itself still works.
        what_if = None
        if what_if_profile is not None:
            if bouncer != "ibounce":
                click.secho(
                    f"--what-if-profile is only wired for ibounce "
                    f"recordings; this recording is from {bouncer!r}. "
                    f"Replay continues without re-evaluation. See "
                    f"docs/SESSION-REPLAY.md for the cross-product "
                    f"gap + plan.",
                    fg="yellow", err=True,
                )
            else:
                what_if, loaded_name = _what_if_evaluator(what_if_profile)
                click.echo(
                    f"what-if profile loaded: {loaded_name}",
                    err=True,
                )

        prev_ms: int | None = None
        diff_count = 0
        match_count = 0
        printed = 0
        diffs: list[tuple[dict[str, Any], str, str, str]] = []

        for i, ev in enumerate(events):
            if max_events is not None and printed >= max_events:
                break
            if filter_expr is not None and not _evaluate_filter(ev, filter_expr):
                continue
            ts_ms = ev.get("time")
            delta_s: float | None = None
            if isinstance(ts_ms, (int, float)) and isinstance(
                prev_ms, (int, float)
            ):
                delta_s = max(0.0, (ts_ms - prev_ms) / 1000.0)
            if realtime and delta_s is not None and delta_s > 0:
                # Cap sleeps so a forgotten weekend gap doesn't hang the
                # operator. 60s is enough for realistic agent-session
                # pauses; anything longer than that is almost certainly
                # a session boundary the operator wants to skip past.
                time.sleep(min(delta_s, 60.0))
            if as_json:
                row: dict[str, Any] = {
                    "index": i,
                    "delta_seconds": delta_s,
                    "event": ev,
                }
                if what_if is not None:
                    new_verdict, reason = what_if(ev)
                    recorded = (
                        _walk_value(ev, "unmapped.iam_jit.verdict") or ""
                    )
                    row["recorded_verdict"] = recorded
                    row["what_if_verdict"] = new_verdict
                    row["what_if_reason"] = reason
                    row["differs"] = (recorded != new_verdict)
                click.echo(json.dumps(row, ensure_ascii=False))
            else:
                click.echo(_format_event_oneline(ev, delta_s))
                if what_if is not None:
                    new_verdict, reason = what_if(ev)
                    recorded = (
                        _walk_value(ev, "unmapped.iam_jit.verdict") or ""
                    )
                    if recorded != new_verdict:
                        diffs.append((ev, recorded, new_verdict, reason))
                        diff_count += 1
                    else:
                        match_count += 1
            prev_ms = ts_ms if isinstance(ts_ms, (int, float)) else prev_ms
            printed += 1

        if not as_json:
            click.echo("")
            click.echo(f"replay complete: {printed} event(s) printed")
            if what_if is not None:
                click.echo(
                    f"what-if vs recorded: "
                    f"{match_count} matched, {diff_count} differed"
                )
                if diffs:
                    click.echo("differences:")
                    for ev, rec, new, reason in diffs:
                        click.echo(_diff_oneline(ev, rec, new, reason))

    return session_group


__all__ = ["register_session_replay_group"]
