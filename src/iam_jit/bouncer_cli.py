"""`ibounce` CLI — separate entry point for the bouncer
product. Per [[four-products-one-brand]] the bouncer is one of four
addressable products and gets its own binary; self-host admins who
want only the bouncer can install just the iam-jit package and use
this entry.

Foundation slice (#160 Stage 1): subcommands for rule management,
decision audit log inspection, and a `decide` dry-run for testing
what current rules would do for a given request. The actual HTTP
proxy server (`run`) lands in Stage 2.
"""

from __future__ import annotations

import contextlib
import json
import os
import pathlib
import sys
from typing import Any

import click

from .bouncer.decisions import (
    DefaultPolicy,
    Decision,
    Mode,
    decide,
)
from .bouncer.presets import PRESETS, get_preset, list_preset_names
from .bouncer.profile_naming import (
    AUTO_NAME_SENTINEL as _AUTO_NAME_SENTINEL,
    resolve_profile_name,
    suggest_profile_name_for_prompts_answer,
    suggest_profile_name_for_recommender,
)
from .bouncer.request_parser import parse_request
from .bouncer.rules import Effect, ProxyRule, RuleSet
from .bouncer.store import BouncerStore, InvalidRuleError, default_db_path
from .bouncer.tasks import TaskValidationError, build_task_scope


def _current_actor() -> str:
    """Best-effort actor identification for audit-log entries. Reads
    IAM_JIT_BOUNCER_ACTOR if set (lets agents identify themselves
    explicitly), else falls back to the OS username. Per
    [[agent-friendly-not-bypassable]] Lens B: there is NO way to
    write an audit-log row with no actor — even unidentified callers
    get tagged with their OS username."""
    import getpass
    import os

    explicit = os.environ.get("IAM_JIT_BOUNCER_ACTOR")
    if explicit:
        return explicit
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


@contextlib.contextmanager
def _opened_store(db_path: str | None):
    """WB23 LOW-23-01 closure: every CLI command opens via this
    context manager so the SQLite connection always gets closed.
    Eliminates the per-invocation leak that's harmless for CLI but
    pattern-dangerous for the Stage-2 long-running proxy."""
    store = BouncerStore(db_path=db_path)
    try:
        yield store
    finally:
        store.close()


def _enqueue_admin_action(
    store: BouncerStore,
    *,
    kind: str,
    target_kind: str = "",
    target_id: str = "",
    target_extra: dict[str, Any] | None = None,
    before: Any = None,
    after: Any = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """#278 — best-effort admin-action OCSF event enqueue from a CLI
    subcommand.

    Wires every CLI touchpoint that MUTATES ibounce's gating surface
    (rule add/remove, pause start/stop, preset apply, profile install,
    profile hot-swap, session kill) into the ADMIN_ACTION OCSF stream
    so a security team can answer "who changed what, when, why"
    directly from the audit-export channel.

    Best-effort posture per the existing PROFILE_INSTALL pattern in
    `profile install --from URL`: a queue-write failure surfaces on
    stderr but NEVER fails the user-facing op (the mutation has
    already landed; rolling back for an audit-row failure would
    itself be an unaudited mutation per [[creates-never-mutates]]).

    The serve process's pending_audit_events drainer picks the row up
    on the next 1s tick + materialises the OCSF event via
    `admin_action_event_from_payload`. CLI runs in a SEPARATE process
    from `ibounce run`, so the SQLite queue is the only emit path
    that crosses the process boundary.
    """
    try:
        from .bouncer.audit_export import enqueue_admin_action

        enqueue_admin_action(
            store,
            kind=kind,
            actor=_current_actor(),
            target_kind=target_kind,
            target_id=target_id,
            target_extra=target_extra,
            before=before,
            after=after,
            extra=extra,
        )
    except Exception as e:
        # Visible to the operator so a quiet emit failure surfaces
        # immediately, but not exit-1: the mutation IS done.
        click.echo(
            f"warning: admin-action audit-event enqueue failed "
            f"(the action itself succeeded): {e}",
            err=True,
        )


# ---------------------------------------------------------------------------
# #253 — pre-burst hint surface
#
# When ANY ibounce subcommand runs AND a burst-shaped condition exists
# in the operator's pending_prompts queue, print a single one-line
# stderr hint BEFORE the subcommand's output. Spec:
#
#   ℹ N pending prompts accumulated in the last Ts. Run
#     `ibounce prompts bulk-answer` to handle them all at once.
#
# Auto-suppression rules per the spec:
#   - Non-TTY (piped / CI / redirected stderr) — silent.
#   - Within the cool-down window of the LAST hint printed — silent
#     (so repeated CLI runs in a script don't spam the hint).
#   - When the operator is RUNNING the bulk-answer subcommand itself —
#     silent (would be redundant; the subcommand prints the same info).
#
# The burst threshold here mirrors burst.DEFAULT_BURST_THRESHOLD /
# DEFAULT_BURST_WINDOW_SECONDS so the CLI hint stays in lockstep with
# the proxy's BURST_DETECTED event semantics. We compute the window
# from pending_prompts.created_at, not the in-process detector
# (which lives in serve()'s process; the CLI is a separate process).
#
# Per [[security-team-positioning-safety-not-surveillance]] the hint
# string is neutral. No "violation" / "unauthorized" / "infraction".
# ---------------------------------------------------------------------------

_PRE_BURST_HINT_COOL_DOWN_SECONDS = 300
_PRE_BURST_HINT_STATE_FILE = ".pre_burst_hint_last"
# Subcommand names that should NOT print the hint (running them is
# itself the operator's response to the burst).
_HINT_SUPPRESS_COMMANDS = {"bulk-answer", "answer", "list", "show"}


def _maybe_print_pre_burst_hint(ctx: click.Context) -> None:
    """Inspect the operator's pending_prompts queue + print a one-line
    stderr hint when a burst-shaped condition is live.

    Fail-soft: any unexpected exception is swallowed (the hint is a
    convenience, NOT a correctness boundary; we never want a broken
    hint path to break the rest of the CLI).
    """
    import datetime as _dt
    import pathlib as _pl
    import sys as _sys
    import time as _time

    from .bouncer.burst import (
        DEFAULT_BURST_THRESHOLD,
        DEFAULT_BURST_WINDOW_SECONDS,
    )

    try:
        # Skip in non-TTY contexts.
        if not _sys.stderr.isatty():
            return
        # Skip if we're inside the prompts subgroup running a command
        # that already shows pending queue context.
        cmd_chain: list[str] = []
        cur: click.Context | None = ctx
        while cur is not None:
            if cur.info_name:
                cmd_chain.append(cur.info_name)
            cur = cur.parent
        if any(c in _HINT_SUPPRESS_COMMANDS for c in cmd_chain):
            return
        # Cool-down: read the timestamp file under the bouncer DB dir.
        # No DB lookup needed when within cool-down; cheap fast-path.
        from .bouncer.store import default_db_path
        state_dir = _pl.Path(default_db_path()).parent
        state_file = state_dir / _PRE_BURST_HINT_STATE_FILE
        try:
            last_at = float(state_file.read_text().strip())
        except Exception:
            last_at = 0.0
        now = _time.time()
        if now - last_at < _PRE_BURST_HINT_COOL_DOWN_SECONDS:
            return
        # Inspect pending_prompts. The window we check is the burst
        # detector's default window (60s); count rows whose created_at
        # falls inside it. This intentionally MIRRORS the in-process
        # detector's logic so CLI hint + proxy event agree.
        from .bouncer.store import BouncerStore
        store = BouncerStore()
        try:
            rows = store.list_pending_prompts(
                status="pending", kind="deny-prompt", limit=500,
            )
        finally:
            store.close()
        if not rows:
            return
        # rows are sorted newest-first; window-filter using created_at.
        cutoff_dt = _dt.datetime.now(_dt.UTC) - _dt.timedelta(
            seconds=DEFAULT_BURST_WINDOW_SECONDS,
        )
        cutoff_str = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        in_window = [r for r in rows if (r.get("created_at") or "") >= cutoff_str]
        if len(in_window) < DEFAULT_BURST_THRESHOLD:
            return
        # Compute oldest_seconds_ago for the hint string.
        oldest = in_window[-1].get("created_at") or ""
        try:
            oldest_dt = _dt.datetime.strptime(
                oldest, "%Y-%m-%dT%H:%M:%SZ",
            ).replace(tzinfo=_dt.UTC)
            oldest_ago = max(0, int((_dt.datetime.now(_dt.UTC) - oldest_dt).total_seconds()))
        except Exception:
            oldest_ago = DEFAULT_BURST_WINDOW_SECONDS
        # Print + record the cool-down timestamp.
        click.secho(
            f"i {len(in_window)} pending prompts accumulated in the last "
            f"{oldest_ago}s. Run `ibounce prompts bulk-answer` to handle "
            f"them all at once.",
            err=True, fg="yellow",
        )
        try:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            state_file.write_text(str(now))
        except Exception:
            pass
    except Exception:
        # Fail-soft per the docstring contract.
        pass


@click.group()
@click.version_option()
@click.pass_context
def main(ctx: click.Context) -> None:
    """ibounce — local AWS-API call gating proxy.

    Defense-in-depth over IAM role scoping. Sits between local AWS
    SDK calls and AWS endpoints; gates each call against rules.
    Never modifies IAM (creates-never-mutates invariant). Runs
    entirely on your machine — no phone home, no SaaS dependency.

    Foundation commands (this slice):
      init           — initialize SQLite state at ~/.iam-jit/bouncer/
      rules          — manage rules (add, list, remove)
      logs           — inspect decision audit log
      decide         — dry-run: ask "what would the bouncer do for X?"
      version-check  — opt-in check for newer GitHub releases (not phone-home)

    Coming in Stage 2:
      run     — start the HTTP proxy server (point AWS_ENDPOINT_URL at it)
      learn   — start in passive recording mode (no blocking)
    """
    # #253 — pre-burst hint surface. Fires once per cool-down window;
    # auto-suppressed in non-TTY contexts + when running the prompts
    # subcommands that already surface pending-queue context.
    _maybe_print_pre_burst_hint(ctx)


# Per [[proxy-smart-defaults-and-task-scope]] Slice A: the protective
# default applied when `init` is run on an empty store without an
# explicit --preset. Chosen because it's the closest match to "works
# for most people" — denies the sensitive set (secrets, IAM admin,
# billing, audit-infra destruction) while allowing everything else,
# so day-one users get protection without breaking common workflows.
# Per [[safety-mode-lean-permissive]]: blocks are rare and surgical.
DEFAULT_PRESET_NAME = "admin-minus-sensitive"


@main.command("init")
@click.option(
    "--db",
    type=click.Path(dir_okay=False),
    default=None,
    help="SQLite DB path (default: ~/.iam-jit/bouncer/state.db)",
)
@click.option(
    "--preset",
    "preset_name",
    type=click.Choice(sorted(PRESETS.keys()), case_sensitive=False),
    default=None,
    help="Apply a specific curated baseline ruleset at init time.",
)
@click.option(
    "--no-default",
    is_flag=True,
    default=False,
    help=(
        "Skip the protective default. Use this if you want an empty "
        "ruleset (typically because you'll build rules manually or "
        "from learn-mode captures)."
    ),
)
def init_cmd(db: str | None, preset_name: str | None, no_default: bool) -> None:
    """Initialize the bouncer's local SQLite state.

    On a fresh install (empty rule store), ibounce applies a
    PROTECTIVE DEFAULT BASELINE (`admin-minus-sensitive`) so day-one
    users get protection against secret reads + IAM admin + billing +
    audit-infra destruction without any further config. Per
    [[proxy-smart-defaults-and-task-scope]]: the bouncer should be
    useful out of the box, not "wait for the user to curate rules."

    Opt out with `--no-default` (e.g. when you intend to build rules
    from learn-mode captures or apply a different preset). Pass
    `--preset NAME` to use a specific named baseline instead.

    Re-running `init` on a store that ALREADY has rules is a no-op
    for the default (your existing rules are preserved); `--preset
    NAME` still appends.
    """
    with _opened_store(db) as store:
        click.echo(f"bouncer initialized at: {store.db_path}")
        actor = _current_actor()
        existing_rule_count = len(store.list_rules())

        if preset_name:
            # Explicit preset — apply regardless of existing rules.
            preset = get_preset(preset_name)
            assert preset is not None
            _apply_preset_to_store(store, preset, actor)
            click.echo(f"applied preset '{preset.name}': {len(preset.rules)} rules added")
        elif no_default:
            click.echo("(skipped protective default per --no-default)")
        elif existing_rule_count > 0:
            click.echo(
                f"(store already has {existing_rule_count} rules; "
                "skipping protective default. Pass --preset NAME to "
                "append a specific baseline.)"
            )
        else:
            # Fresh install — apply the protective default. This is
            # the [[proxy-smart-defaults-and-task-scope]] change.
            preset = get_preset(DEFAULT_PRESET_NAME)
            assert preset is not None
            _apply_preset_to_store(store, preset, actor)
            click.echo(
                f"applied protective default '{preset.name}': "
                f"{len(preset.rules)} rules. Deny on secrets/IAM-admin/"
                "billing/audit-infra; allow everything else. Run "
                "`ibounce rules list` to inspect; "
                "`ibounce init --no-default` to skip."
            )

        click.echo(f"current rules: {len(store.list_rules())}")
        click.echo(f"current decisions: {store.count_decisions()}")


def _apply_preset_to_store(store: BouncerStore, preset, actor: str) -> int:
    """Apply a preset's rules to the store + record the audit event.
    Returns the count of rules actually added."""
    added = 0
    for rule in preset.rules:
        try:
            store.add_rule(rule, actor=actor)
            added += 1
        except InvalidRuleError as e:
            click.echo(f"warning: preset rule rejected: {e}", err=True)
    store.record_preset_applied(
        preset_name=preset.name, rules_added=added, actor=actor
    )
    return added


# ---------------------------------------------------------------------------
# presets
# ---------------------------------------------------------------------------


@main.group("presets")
def presets_group() -> None:
    """Curated rule baselines for common use cases."""


@presets_group.command("list")
@click.option("--json", "as_json", is_flag=True, default=False)
def presets_list(as_json: bool) -> None:
    """List available preset baselines."""
    items = [PRESETS[name] for name in list_preset_names()]
    if as_json:
        click.echo(json.dumps([p.to_dict() for p in items], indent=2))
        return
    for p in items:
        click.echo(f"{p.name}  ({len(p.rules)} rules)")
        click.echo(f"  {p.description}")
        click.echo()


@presets_group.command("show")
@click.argument("preset_name")
@click.option("--json", "as_json", is_flag=True, default=False)
def presets_show(preset_name: str, as_json: bool) -> None:
    """Show the rules a preset would add (without applying)."""
    p = get_preset(preset_name)
    if p is None:
        click.echo(f"no preset named {preset_name!r}; try `presets list`", err=True)
        sys.exit(2)
    if as_json:
        click.echo(json.dumps(p.to_dict(), indent=2))
        return
    click.echo(f"preset: {p.name}")
    click.echo(f"  {p.description}")
    click.echo()
    for r in p.rules:
        scope_bits = []
        if r.arn_scope:
            scope_bits.append(f"arn={r.arn_scope}")
        if r.region_scope:
            scope_bits.append(f"region={r.region_scope}")
        scope = f" [{', '.join(scope_bits)}]" if scope_bits else ""
        note = f"  # {r.note}" if r.note else ""
        click.echo(f"  {r.effect.value:>5}  {r.pattern}{scope}{note}")


@presets_group.command("apply")
@click.argument("preset_name", type=click.Choice(sorted(PRESETS.keys()), case_sensitive=False))
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def presets_apply(preset_name: str, db: str | None) -> None:
    """Add all rules from a preset to the current ruleset.

    Existing rules are preserved (preset rules are appended).
    The application itself is audit-logged via config_events.
    """
    preset = get_preset(preset_name)
    assert preset is not None
    actor = _current_actor()
    added = 0
    with _opened_store(db) as store:
        for rule in preset.rules:
            try:
                store.add_rule(rule, actor=actor)
                added += 1
            except InvalidRuleError as e:
                click.echo(f"warning: preset rule rejected: {e}", err=True)
        store.record_preset_applied(
            preset_name=preset.name, rules_added=added, actor=actor
        )
        # #278 — admin-action OCSF emit. After-state captures the
        # added-rule count so a SIEM dashboard can correlate "preset
        # X applied + N rules added" against the per-rule.add stream.
        _enqueue_admin_action(
            store,
            kind="preset.apply",
            target_kind="preset",
            target_id=preset.name,
            target_extra={
                "rules_added": added,
                "rules_offered": len(preset.rules),
            },
            after={
                "preset_name": preset.name,
                "rules_added": added,
            },
        )
    click.echo(f"applied preset '{preset.name}': {added} rules added")


# ---------------------------------------------------------------------------
# events — config-change audit log (Lens B)
# ---------------------------------------------------------------------------


@main.group("events")
def events_group() -> None:
    """Inspect config-change events (rule add/remove, mode changes,
    preset applications). Separate from `logs` (which shows
    decisions); together they form the full audit chain so post-
    incident review can answer 'what was the bouncer's config at
    time T, and what calls did it gate.'"""


@events_group.command("tail")
@click.option("--limit", type=int, default=50, show_default=True)
@click.option(
    "--kind",
    type=click.Choice(
        # WB26 LOW-26-05 closure: include task lifecycle kinds.
        # WB25 LOW-25-01 closure: include allowlist lifecycle kinds.
        ["rule_added", "rule_removed", "mode_changed", "preset_applied",
         "task_started", "task_ended",
         "allowlist_rule_added", "allowlist_rule_removed"],
        case_sensitive=False,
    ),
    default=None,
)
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.option("--json", "as_json", is_flag=True, default=False)
def events_tail(limit: int, kind: str | None, db: str | None, as_json: bool) -> None:
    """Show recent config-change events, newest first."""
    with _opened_store(db) as store:
        out = store.list_config_events(limit=limit, kind_filter=kind)
    if as_json:
        click.echo(json.dumps(out, indent=2))
        return
    if not out:
        click.echo("(no config events logged)")
        return
    for row in out:
        click.echo(f"{row['at']}  {row['actor']:>20}  {row['kind']:>16}  {row['summary']}")


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------


@main.group("rules")
def rules_group() -> None:
    """Manage bouncer rules (allow / deny + ARN + region scoping)."""


@rules_group.command("list")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.option("--json", "as_json", is_flag=True, default=False, help="JSON output")
def rules_list(db: str | None, as_json: bool) -> None:
    """List all rules in evaluation order."""
    with _opened_store(db) as store:
        rules = store.list_rules()
    if as_json:
        click.echo(json.dumps([{"id": rid, **r.to_dict()} for rid, r in rules], indent=2))
        return
    if not rules:
        click.echo("(no rules configured)")
        return
    for rid, r in rules:
        scope_bits = []
        if r.arn_scope:
            scope_bits.append(f"arn={r.arn_scope}")
        if r.region_scope:
            scope_bits.append(f"region={r.region_scope}")
        scope = f" [{', '.join(scope_bits)}]" if scope_bits else ""
        note = f"  # {r.note}" if r.note else ""
        click.echo(f"{rid:>4}  {r.effect.value:>5}  {r.pattern}{scope}{note}")


@rules_group.command("add")
@click.argument("pattern")
@click.option(
    "--effect",
    type=click.Choice(["allow", "deny"], case_sensitive=False),
    default="allow",
    help="Decision effect (default: allow).",
)
@click.option("--arn", "arn_scope", default=None, help="Optional ARN-glob scope.")
@click.option("--region", "region_scope", default=None, help="Optional region-glob scope.")
@click.option("--note", default=None, help="Human note (why this rule exists).")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def rules_add(
    pattern: str,
    effect: str,
    arn_scope: str | None,
    region_scope: str | None,
    note: str | None,
    db: str | None,
) -> None:
    """Add a new rule. Example:

    \b
        ibounce rules add 's3:Get*' --arn 'arn:aws:s3:::my-bucket/*'
        ibounce rules add 'iam:Delete*' --effect deny
    """
    rule = ProxyRule(
        pattern=pattern,
        effect=Effect(effect.lower()),
        arn_scope=arn_scope,
        region_scope=region_scope,
        note=note,
        origin="user",
    )
    with _opened_store(db) as store:
        try:
            rid = store.add_rule(rule, actor=_current_actor())
        except InvalidRuleError as e:
            # WB23 MED-23-02 closure: surface validation errors at CLI
            # time rather than letting a never-matches rule enter the DB.
            click.echo(f"rejected: {e}", err=True)
            sys.exit(2)
        # #278 — admin-action OCSF emit. After-state is the rule shape
        # (no full ruleset snapshot — large + adds nothing the SIEM
        # can't reconstruct from the rule.add stream itself).
        _enqueue_admin_action(
            store,
            kind="rule.add",
            target_kind="rule",
            target_id=f"#{rid}",
            target_extra={
                "pattern": rule.pattern,
                "effect": rule.effect.value,
                "arn_scope": rule.arn_scope or "",
                "region_scope": rule.region_scope or "",
            },
            after={
                "id": rid,
                "pattern": rule.pattern,
                "effect": rule.effect.value,
                "arn_scope": rule.arn_scope,
                "region_scope": rule.region_scope,
                "note": rule.note,
            },
        )
    click.echo(f"added rule #{rid}: {rule.effect.value} {rule.pattern}")


@rules_group.command("remove")
@click.argument("rule_id", type=int)
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def rules_remove(rule_id: int, db: str | None) -> None:
    """Remove a rule by id. The deletion is itself audit-logged so
    post-incident review can answer 'what rule existed at time T'
    (per [[agent-friendly-not-bypassable]] Lens B)."""
    with _opened_store(db) as store:
        # Capture before-state by id-tagged list so the admin-action
        # event records WHAT was removed (pattern + effect + scopes),
        # not just the id. Fail-soft: missing pre-snapshot still
        # emits the event with a None before-hash.
        before_rule: dict[str, Any] | None = None
        try:
            for rid, r in store.list_rules():
                if rid == rule_id:
                    before_rule = {
                        "id": rid,
                        "pattern": r.pattern,
                        "effect": r.effect.value,
                        "arn_scope": r.arn_scope,
                        "region_scope": r.region_scope,
                        "note": r.note,
                    }
                    break
        except Exception:
            before_rule = None
        removed = store.remove_rule(rule_id, actor=_current_actor())
        if removed:
            _enqueue_admin_action(
                store,
                kind="rule.remove",
                target_kind="rule",
                target_id=f"#{rule_id}",
                target_extra={
                    "pattern": (before_rule or {}).get("pattern", ""),
                    "effect": (before_rule or {}).get("effect", ""),
                },
                before=before_rule,
                after=None,
            )
    if removed:
        click.echo(f"removed rule #{rule_id}")
    else:
        click.echo(f"no rule with id #{rule_id}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------


@main.group("logs")
def logs_group() -> None:
    """Inspect the bouncer's decision audit log."""


@logs_group.command("tail")
@click.option("--limit", type=int, default=50, show_default=True)
@click.option(
    "--decision",
    type=click.Choice(["allow", "deny", "prompt"], case_sensitive=False),
    default=None,
    help="Filter to one decision class.",
)
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.option("--json", "as_json", is_flag=True, default=False)
def logs_tail(limit: int, decision: str | None, db: str | None, as_json: bool) -> None:
    """Show recent decisions, newest first."""
    decision_filter = Decision(decision.lower()) if decision else None
    with _opened_store(db) as store:
        out = store.list_decisions(limit=limit, decision_filter=decision_filter)
    if as_json:
        click.echo(json.dumps(out, indent=2))
        return
    if not out:
        click.echo("(no decisions logged yet)")
        return
    for row in out:
        scope_bits = []
        if row["arn"]:
            scope_bits.append(row["arn"])
        if row["region"]:
            scope_bits.append(f"({row['region']})")
        scope = " ".join(scope_bits)
        click.echo(
            f"{row['at']}  {row['decision']:>6}  "
            f"{row['service']}:{row['action']}  {scope}  -- {row['reason']}"
        )


# ---------------------------------------------------------------------------
# logs purge / archive / verify — #311 / §A10 retention surface
# ---------------------------------------------------------------------------


def _resolve_log_dir(audit_log: str | None) -> pathlib.Path:
    """Resolve the log directory for `logs {purge,archive,verify}`.

    Mirrors the `ibounce run --audit-log-path` resolution: the
    CLI flag wins; otherwise we fall back to the default
    `~/.iam-jit/audit/audit.jsonl` location. The returned path is
    the DIRECTORY containing the active log + rotated archives.
    """
    from .bouncer.audit_export.tail import default_audit_log_path

    if audit_log:
        return pathlib.Path(audit_log).expanduser().parent
    return default_audit_log_path().parent


def _parse_duration(s: str) -> int:
    """Parse a human duration ('7d', '24h', '30m') to seconds.

    Mirrors the cross-product flag style used by `kbounce logs
    purge --older-than`. Plain integers are treated as days for
    operator convenience (the most common audit-retention unit).
    """
    s = s.strip().lower()
    if s.endswith("d"):
        return int(s[:-1]) * 86400
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("s"):
        return int(s[:-1])
    # Bare integer == days.
    return int(s) * 86400


@logs_group.command("purge")
@click.option(
    "--audit-log",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to the active audit.jsonl (rotated archives live next to it).",
)
@click.option(
    "--older-than",
    type=str,
    required=True,
    help="Duration threshold (7d, 24h, 30m). Bare integer = days.",
)
@click.option(
    "--yes",
    is_flag=True,
    default=False,
    help="Skip the confirmation prompt (required for non-interactive use).",
)
def logs_purge(audit_log: str | None, older_than: str, yes: bool) -> None:
    """Delete rotated audit archives older than DURATION.

    Touches only rotated `audit-*.jsonl.gz` / `audit-*.db.gz`
    archives — the active `audit.jsonl` + `audit.db` are never
    removed (per [[creates-never-mutates]]: only an explicit
    `logs purge` invocation reaps audit data, and it can't touch
    the live file).
    """
    import time as _time

    from .bouncer.audit_export import rotation_purge_older_than

    log_dir = _resolve_log_dir(audit_log)
    seconds = _parse_duration(older_than)
    if not log_dir.is_dir():
        click.echo(f"(no audit dir at {log_dir})", err=True)
        sys.exit(1)
    if not yes:
        click.echo(
            f"About to purge rotated archives older than {older_than} in {log_dir}.",
            err=True,
        )
        click.echo("Pass --yes to confirm.", err=True)
        sys.exit(2)
    # `rotation_purge_older_than` takes days; we convert via the
    # ratio so the operator's `--older-than 12h` is honoured. Per-
    # type cutoffs both use the same threshold here (the cross-
    # product runbook spells this out).
    days_eq = max(1, seconds // 86400) if seconds >= 86400 else 0
    removed = rotation_purge_older_than(
        log_dir,
        jsonl_max_age_days=days_eq,
        db_max_age_days=days_eq,
        now=_time.time(),
    )
    if not removed:
        click.echo("(no archives matched)")
        return
    for p in removed:
        click.echo(str(p))
    click.echo(f"-- removed {len(removed)} file(s)", err=True)


@logs_group.command("archive")
@click.option(
    "--audit-log",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to the active audit.jsonl (rotated archives live next to it).",
)
@click.option(
    "--out",
    type=click.Path(dir_okay=False, writable=True),
    required=True,
    help="Destination tar.gz path.",
)
@click.option(
    "--exclude-active",
    is_flag=True,
    default=False,
    help="Skip the live audit.jsonl/audit.db (avoid an inconsistent tail).",
)
def logs_archive(audit_log: str | None, out: str, exclude_active: bool) -> None:
    """Bundle all audit files into a tar.gz at OUT."""
    from .bouncer.audit_export import archive_logs

    log_dir = _resolve_log_dir(audit_log)
    if not log_dir.is_dir():
        click.echo(f"(no audit dir at {log_dir})", err=True)
        sys.exit(1)
    archive = archive_logs(log_dir, out, include_active=not exclude_active)
    click.echo(str(archive))


@logs_group.command("verify")
@click.option(
    "--audit-log",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to the active audit.jsonl (rotated archives live next to it).",
)
@click.option("--json", "as_json", is_flag=True, default=False)
def logs_verify(audit_log: str | None, as_json: bool) -> None:
    """Per-file integrity check — gzip decompresses + JSONL parses."""
    from .bouncer.audit_export import verify_integrity

    log_dir = _resolve_log_dir(audit_log)
    res = verify_integrity(log_dir)
    if as_json:
        click.echo(json.dumps(res.to_dict(), indent=2))
    else:
        click.echo(f"checked {res.files_checked} file(s) in {log_dir}")
        if res.ok:
            click.echo("OK")
        else:
            click.echo("FAILURES:")
            for path, reason in res.failures:
                click.echo(f"  {path}: {reason}")
    if not res.ok:
        sys.exit(1)


# ---------------------------------------------------------------------------
# doctor — #311 / §A10 health-check subcommand group
# ---------------------------------------------------------------------------


@main.group("doctor")
def doctor_group() -> None:
    """Health-check subcommands; exit non-zero on any failure."""


@doctor_group.command("logs")
@click.option(
    "--audit-log",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to the active audit.jsonl (rotated archives live next to it).",
)
@click.option(
    "--max-age-days",
    type=int,
    default=7,
    show_default=True,
    help="Freshness threshold; the most recent rotated archive must be newer.",
)
@click.option(
    "--warn-pct",
    type=int,
    default=85,
    show_default=True,
)
@click.option(
    "--crit-pct",
    type=int,
    default=95,
    show_default=True,
)
@click.option("--json", "as_json", is_flag=True, default=False)
def doctor_logs(
    audit_log: str | None,
    max_age_days: int,
    warn_pct: int,
    crit_pct: int,
    as_json: bool,
) -> None:
    """Run integrity + freshness + retention + disk checks.

    Exits 0 when every check is green, 1 when any fails. The output
    shape (sectioned by check) matches the cross-product `doctor
    logs` surface so an operator one runbook covers all four
    products.
    """
    import time as _time

    from .bouncer.audit_export import disk_status, verify_integrity

    log_dir = _resolve_log_dir(audit_log)
    report: dict[str, Any] = {"log_dir": str(log_dir), "checks": {}}
    overall_ok = True

    # Integrity check
    if log_dir.is_dir():
        integ = verify_integrity(log_dir)
        report["checks"]["integrity"] = integ.to_dict()
        if not integ.ok:
            overall_ok = False
    else:
        report["checks"]["integrity"] = {
            "ok": False,
            "reason": f"audit dir {log_dir} does not exist",
        }
        overall_ok = False

    # Freshness check — most recent rotated archive newer than threshold
    if log_dir.is_dir():
        archives = sorted(
            (p for p in log_dir.iterdir()
             if p.name.startswith("audit-") and p.name.endswith(".jsonl.gz")),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if archives:
            age_days = (_time.time() - archives[0].stat().st_mtime) / 86400
            fresh_ok = age_days <= max_age_days
            report["checks"]["freshness"] = {
                "ok": fresh_ok,
                "most_recent": str(archives[0]),
                "age_days": round(age_days, 2),
                "threshold_days": max_age_days,
            }
            if not fresh_ok:
                overall_ok = False
        else:
            # No rotated archives yet — only a concern if the
            # active file itself is older than the threshold.
            active = log_dir / "audit.jsonl"
            if active.exists():
                age_days = (_time.time() - active.stat().st_mtime) / 86400
                report["checks"]["freshness"] = {
                    "ok": True,
                    "most_recent": str(active),
                    "age_days": round(age_days, 2),
                    "threshold_days": max_age_days,
                    "note": "no rotated archives yet (active file present)",
                }
            else:
                report["checks"]["freshness"] = {
                    "ok": False,
                    "reason": "no audit files present",
                }
                overall_ok = False

    # Disk check
    disk = disk_status(log_dir, warn_pct=warn_pct, crit_pct=crit_pct)
    report["checks"]["disk"] = disk.to_dict()
    if disk.status == "critical":
        overall_ok = False

    report["ok"] = overall_ok

    if as_json:
        click.echo(json.dumps(report, indent=2))
    else:
        click.echo(f"doctor logs — {log_dir}")
        click.echo("=" * 40)
        for name, payload in report["checks"].items():
            status = "OK" if payload.get("ok", True) else "FAIL"
            if name == "disk":
                status = payload.get("status", "?").upper()
            click.echo(f"  [{status:>8}] {name}: {json.dumps(payload)}")
        click.echo("=" * 40)
        click.echo("OVERALL: " + ("OK" if overall_ok else "FAIL"))
    if not overall_ok:
        sys.exit(1)


@doctor_group.command("caveats")
def doctor_caveats() -> None:
    """Print KNOWN-CAVEATS §B entries that apply to ibounce.

    Per #304 — caveats must be easily discoverable. Sibling Bounce
    products ship the same ``*bounce doctor caveats`` shape per
    [[cross-product-agent-parity]]. Full canonical doc:
    https://github.com/trsreagan3/iam-jit/blob/main/docs/KNOWN-CAVEATS.md

    Per [[creates-never-mutates]]: read-only.
    """
    from .bouncer import caveats as _caveats

    click.echo("ibounce: KNOWN-CAVEATS §B entries that apply to this product")
    click.echo(f"Full canonical doc: {_caveats.CANONICAL_DOC_URL}")
    click.echo()
    for entry in _caveats.doctor_entries():
        click.echo(f"§{entry.id}")
        click.echo(f"  {entry.doctor_blurb}")
        click.echo(f"  link: {entry.url}")
        click.echo()


# ---------------------------------------------------------------------------
# decide (dry-run)
# ---------------------------------------------------------------------------


@main.command("decide")
@click.option("--service", required=True)
@click.option("--action", required=True)
@click.option("--arn", default=None)
@click.option("--region", default=None)
@click.option(
    "--mode",
    type=click.Choice(["learn", "enforce", "prompt"], case_sensitive=False),
    default="enforce",
)
@click.option(
    "--default-policy",
    type=click.Choice(["allow", "deny"], case_sensitive=False),
    default="deny",
    help="What ENFORCE does when no rule matches (default: deny).",
)
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.option("--record/--no-record", default=None,
              help="Persist decision to audit log. Default: True when a "
                   "task is active (so `tasks review` has data); False "
                   "otherwise. Override either way with the flag.")
def decide_cmd(
    service: str,
    action: str,
    arn: str | None,
    region: str | None,
    mode: str,
    default_policy: str,
    db: str | None,
    record: bool | None,
) -> None:
    """Dry-run: ask the bouncer what it WOULD do for a hypothetical
    request, without forwarding it to AWS. Useful for sanity-checking
    rules before flipping to enforce mode.

    \b
        ibounce decide --service s3 --action GetObject \\
            --arn arn:aws:s3:::my-bucket/file.txt --region us-east-1
    """
    with _opened_store(db) as store:
        # WB23 HIGH-23-02 closure: build an id-tagged ruleset so we know
        # which row matched, then pass that id through to record_decision
        # below. Without this, the audit log records every entry with
        # matched_rule_id=NULL even when an explicit rule matched.
        id_tagged = store.list_rules()
        ruleset = RuleSet(rules=[r for _, r in id_tagged])
        # Slice B: pick up the currently-active task scope (if any)
        # so decide() applies task allow/deny rules.
        active_task = store.get_active_task()
        record_obj = decide(
            ruleset,
            mode=Mode(mode.lower()),
            default_policy=DefaultPolicy(default_policy.lower()),
            service=service,
            action=action,
            arn=arn,
            region=region,
            active_task=active_task,
        )
        matched_rule_id: int | None = None
        if record_obj.matched_rule is not None:
            for rid, r in id_tagged:
                if r == record_obj.matched_rule:
                    matched_rule_id = rid
                    break
        click.echo(f"decision: {record_obj.decision.value}")
        click.echo(f"reason:   {record_obj.reason}")
        if record_obj.matched_rule:
            click.echo(
                f"rule:     #{matched_rule_id} {record_obj.matched_rule.effect.value} "
                f"{record_obj.matched_rule.pattern}"
            )
        if active_task is not None:
            click.echo(f"active task: {active_task.task_id} ({active_task.description[:60]})")
        # WB30 UAT-A H1 + UAT-B B1: when a task is active, default
        # --record to True so `tasks review` actually shows the
        # decisions made under that scope. Outside an active task,
        # keep the conservative no-record default for true dry-runs.
        # Caller can still flip either way explicitly with the flag.
        if record is None:
            effective_record = active_task is not None
        else:
            effective_record = record
        if effective_record:
            store.record_decision(
                record_obj,
                matched_rule_id=matched_rule_id,
                task_id=active_task.task_id if active_task is not None else None,
            )
            click.echo("(recorded to audit log)")
        elif active_task is None:
            click.echo(
                "(not recorded — pass --record to seed the audit log, "
                "or start a task with `ibounce tasks start` to "
                "auto-record decisions while it's active)"
            )


# ---------------------------------------------------------------------------
# tasks — agent-declared task scope (Slice B of #168)
# ---------------------------------------------------------------------------


@main.group("tasks")
def tasks_group() -> None:
    """Inspect / manage agent-declared task scopes.

    Tasks are typically STARTED by agents via the
    `bouncer_start_task` MCP tool. Use this CLI group to LIST
    historical + active tasks, SHOW the rule details of one task,
    or END the active task manually.

    A task narrows the bouncer's behavior for its duration. The
    agent declares allow
    rules (what the task needs) + deny rules (what the task must
    not touch, e.g. prod). Global rules still apply on top — task
    deny + global deny both block; global ALLOW that wasn't
    declared in task allow still goes through (so infrastructure
    calls keep working).
    """


@tasks_group.command("list")
@click.option("--status", default=None,
              type=click.Choice(["active", "completed", "expired", "replaced"]))
@click.option("--limit", type=int, default=50, show_default=True)
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.option("--json", "as_json", is_flag=True, default=False)
def tasks_list(status: str | None, limit: int, db: str | None, as_json: bool) -> None:
    """List task scopes, newest first."""
    with _opened_store(db) as store:
        scopes = store.list_tasks(limit=limit, status_filter=status)
    if as_json:
        click.echo(json.dumps([s.to_dict() for s in scopes], indent=2))
        return
    if not scopes:
        click.echo("(no tasks)")
        return
    for s in scopes:
        click.echo(
            f"{s.task_id}  {s.status.value:>9}  started {s.started_at} "
            f"by {s.started_by}  --  {s.description[:60]}"
        )


@tasks_group.command("active")
@click.option("--owner", default=None,
              help="Owner filter (Slice C); omit for default-owner slot.")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.option("--json", "as_json", is_flag=True, default=False)
def tasks_active(owner: str | None, db: str | None, as_json: bool) -> None:
    """Show the currently-active task (if any). Reports None if
    no task is active OR the active task has timed out."""
    with _opened_store(db) as store:
        active = store.get_active_task(owner=owner)
    if active is None:
        if as_json:
            click.echo(json.dumps({"active": None}))
        else:
            click.echo("(no active task)")
        return
    if as_json:
        click.echo(json.dumps(active.to_dict(), indent=2))
        return
    # WB30 UAT-B M1 closure: surface a relative expiry countdown so
    # the user sees "expires in 17m" not just an ISO timestamp.
    import datetime as _dt
    expires_in_str = ""
    try:
        exp_dt = _dt.datetime.fromisoformat(active.expires_at.replace("Z", "+00:00"))
        now = _dt.datetime.now(_dt.UTC)
        delta = exp_dt - now
        secs = int(delta.total_seconds())
        if secs <= 0:
            expires_in_str = "  (EXPIRED)"
        else:
            hours, rem = divmod(secs, 3600)
            mins = rem // 60
            if hours:
                expires_in_str = f"  (in {hours}h {mins}m)"
            else:
                expires_in_str = f"  (in {mins}m {secs % 60}s)"
            if secs < 600:
                expires_in_str += "  ⚠ EXPIRING SOON"
    except (ValueError, AttributeError):
        pass
    click.echo(f"task_id:      {active.task_id}")
    click.echo(f"description:  {active.description}")
    click.echo(f"started_at:   {active.started_at}")
    click.echo(f"expires_at:   {active.expires_at}{expires_in_str}")
    click.echo(f"started_by:   {active.started_by}")
    click.echo(f"allow rules:  {len(active.allow_rules)}")
    for r in active.allow_rules:
        scope = ""
        if r.arn_scope:
            scope += f" arn={r.arn_scope}"
        if r.region_scope:
            scope += f" region={r.region_scope}"
        click.echo(f"  + {r.pattern}{scope}")
    click.echo(f"deny rules:   {len(active.deny_rules)}")
    for r in active.deny_rules:
        scope = ""
        if r.arn_scope:
            scope += f" arn={r.arn_scope}"
        if r.region_scope:
            scope += f" region={r.region_scope}"
        click.echo(f"  - {r.pattern}{scope}")


def _resolve_task_selector(store, selector: str) -> str | None:
    """WB30 UAT-B H1 closure: accept exact id, id-prefix, OR
    description-prefix when the user references a task on
    end/show/review.

    Matching order (most-specific wins):
    1. Exact task_id match.
    2. Unique task_id prefix match (≥4 chars).
    3. Unique description-prefix match (≥4 chars, case-insensitive).

    Returns the resolved task_id, or None if no unique match exists.
    Ambiguous matches return None too (caller surfaces a helpful
    "did you mean..." message).
    """
    if not selector or len(selector.strip()) < 1:
        return None
    sel = selector.strip()

    exact = store.get_task(sel)
    if exact is not None:
        return sel

    candidates = []
    try:
        all_tasks = store.list_tasks(limit=500)
    except Exception:
        return None
    sel_lower = sel.lower()
    for t in all_tasks:
        if len(sel) >= 4 and t.task_id.startswith(sel):
            candidates.append(("id", t.task_id, t.description))
            continue
        desc = (t.description or "").lower()
        if len(sel) >= 4 and desc.startswith(sel_lower):
            candidates.append(("desc", t.task_id, t.description))
    if len(candidates) == 1:
        return candidates[0][1]
    return None


def _resolve_or_die(store, selector: str) -> str:
    """As _resolve_task_selector, but click-exit on miss/ambiguity
    with a helpful diagnostic message."""
    resolved = _resolve_task_selector(store, selector)
    if resolved is not None:
        return resolved
    try:
        all_tasks = store.list_tasks(limit=500)
    except Exception:
        click.echo(f"no task matching {selector!r}", err=True)
        sys.exit(1)
    matches = [
        t for t in all_tasks
        if t.task_id.startswith(selector)
        or (t.description or "").lower().startswith(selector.lower())
    ]
    if len(matches) > 1:
        click.echo(
            f"selector {selector!r} matches {len(matches)} tasks; "
            "be more specific:", err=True,
        )
        for t in matches[:10]:
            click.echo(f"  {t.task_id[:12]}  {t.description[:60]}", err=True)
    else:
        click.echo(f"no task matching {selector!r}", err=True)
    sys.exit(1)


@tasks_group.command("show")
@click.argument("selector")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def tasks_show(selector: str, db: str | None) -> None:
    """Show full details for one task scope.

    SELECTOR can be the exact task_id, a unique 4+ char id-prefix,
    or a unique 4+ char description-prefix.
    """
    with _opened_store(db) as store:
        task_id = _resolve_or_die(store, selector)
        scope = store.get_task(task_id)
    if scope is None:
        click.echo(f"no task with id {task_id!r}", err=True)
        sys.exit(1)
    click.echo(json.dumps(scope.to_dict(), indent=2))


@tasks_group.command("review")
@click.argument("selector")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.option("--json", "as_json", is_flag=True, default=False)
def tasks_review(selector: str, db: str | None, as_json: bool) -> None:
    """Post-task review summary: total decisions, allow/deny
    breakdown, list of denied calls. Admins use this to see whether
    the scope was right-sized.

    SELECTOR can be the exact task_id, a unique 4+ char id-prefix,
    or a unique 4+ char description-prefix.
    """
    with _opened_store(db) as store:
        task_id = _resolve_or_die(store, selector)
        summary = store.task_review_summary(task_id)
    if not summary:
        click.echo(f"no task with id {task_id!r}", err=True)
        sys.exit(1)
    if as_json:
        click.echo(json.dumps(summary, indent=2))
        return
    click.echo(f"task:        {summary['task_id']}")
    click.echo(f"description: {summary['description']}")
    click.echo(f"status:      {summary['status']}")
    click.echo(f"owner:       {summary['owner']}")
    click.echo(f"window:      {summary['started_at']} -> {summary['ended_at'] or summary['expires_at']}")
    click.echo(f"decisions:   {summary['decision_count']} total "
               f"(allow={summary['allow_count']} deny={summary['deny_count']} prompt={summary['prompt_count']})")
    if summary["denied_calls"]:
        click.echo(f"denied calls ({len(summary['denied_calls'])}):")
        for d in summary["denied_calls"]:
            arn_bit = f" {d['arn']}" if d["arn"] else ""
            click.echo(f"  {d['at']}  {d['service']}:{d['action']}{arn_bit}")
            click.echo(f"      -- {d['reason']}")


@tasks_group.command("end")
@click.argument("selector")
@click.option("--reason", default="manually ended",
              help="End reason recorded in audit log.")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def tasks_end(selector: str, reason: str, db: str | None) -> None:
    """End the named task.

    SELECTOR can be the exact task_id, a unique 4+ char id-prefix,
    or a unique 4+ char description-prefix. The audit event is
    written via config_events (kind=task_ended).
    """
    with _opened_store(db) as store:
        task_id = _resolve_or_die(store, selector)
        ok = store.end_task(task_id, actor=_current_actor(), end_reason=reason)
        if ok:
            # #278 — admin-action OCSF emit. Ending a task ends its
            # scoped allow/deny rules (a session-kill in the sense
            # that the agent's elevated scope evaporates), so this
            # is the security-relevant config-change row for "who
            # closed the session."
            _enqueue_admin_action(
                store,
                kind="session.kill",
                target_kind="task",
                target_id=task_id,
                target_extra={"end_reason": reason or ""},
                before={"task_id": task_id, "status": "active"},
                after={"task_id": task_id, "status": "ended"},
            )
    if not ok:
        click.echo(
            f"no active task with id {task_id!r} "
            "(already ended, or task doesn't exist)",
            err=True,
        )
        sys.exit(1)
    click.echo(f"ended task {task_id}")


@tasks_group.command("start")
@click.option("--description", required=True,
              help="Human-readable task description (recorded in audit log).")
@click.option("--allow", "allow_rules_raw", multiple=True,
              help="Allow-rule in 'pattern[@arn][#region]' form. Repeatable.")
@click.option("--deny", "deny_rules_raw", multiple=True,
              help="Deny-rule in 'pattern[@arn][#region]' form. Repeatable.")
@click.option("--duration", "duration_minutes", type=int, default=30,
              show_default=True, help="Task duration in minutes (1..1440).")
@click.option("--owner", default=None,
              help="Slice C: owner identifier for per-owner concurrent tasks.")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def tasks_start(
    description: str,
    allow_rules_raw: tuple[str, ...],
    deny_rules_raw: tuple[str, ...],
    duration_minutes: int,
    owner: str | None,
    db: str | None,
) -> None:
    """Manually start a task scope (typically done via MCP from an
    agent; CLI form is for testing + demo).

    Rule shorthand: `pattern@arn_scope#region_scope` — both scopes
    optional. Examples:

    \b
        --allow 'eks:*@arn:aws:eks:us-east-1:111:cluster/staging'
        --allow 'ec2:Describe*#us-east-1'
        --deny  '*@arn:aws:*::222:*'
    """
    def _parse_shorthand(s: str) -> dict:
        # WB26 LOW-26-02 closure: split on `@` BEFORE `#`. ARN values
        # can legitimately contain `#` (e.g. anchors in URLs encoded
        # into a resource identifier); splitting region-first would
        # truncate the ARN. Pattern + region delimiter `#` only
        # applies AFTER the ARN segment is extracted.
        pattern = s
        arn = None
        region = None
        if "@" in pattern:
            pattern, after_at = pattern.split("@", 1)
            # The ARN may itself contain `#`? Only canonical AWS ARNs
            # don't, but defensive: split region off the END of the
            # post-@ chunk using rsplit so a `#` inside the ARN body
            # is preserved.
            if "#" in after_at:
                arn, region = after_at.rsplit("#", 1)
            else:
                arn = after_at
        elif "#" in pattern:
            pattern, region = pattern.split("#", 1)
        return {
            "pattern": pattern.strip(),
            "arn_scope": arn.strip() if arn else None,
            "region_scope": region.strip() if region else None,
        }

    try:
        scope = build_task_scope(
            description=description,
            allow_rules=[_parse_shorthand(s) for s in allow_rules_raw],
            deny_rules=[_parse_shorthand(s) for s in deny_rules_raw],
            duration_minutes=duration_minutes,
            started_by=_current_actor(),
            owner=owner,
        )
    except TaskValidationError as e:
        click.echo(f"rejected: {e}", err=True)
        sys.exit(2)

    from .bouncer.store import ActiveTaskExistsError

    with _opened_store(db) as store:
        try:
            store.add_task(scope, actor=_current_actor())
        except ActiveTaskExistsError as e:
            # WB26 HIGH-26-02 closure: the store enforces; CLI just
            # surfaces the message + a remediation hint.
            click.echo(
                f"{e}\nrun `ibounce tasks active` to see the "
                "current task; `ibounce tasks end <id>` to end it.",
                err=True,
            )
            sys.exit(2)
    click.echo(f"started task {scope.task_id} (expires {scope.expires_at})")


# ---------------------------------------------------------------------------
# inspect — parse a raw HTTP request and show what the bouncer would
# classify it as. Useful for debugging the request parser.
# ---------------------------------------------------------------------------


@main.command("effective-scope")
@click.option("--owner", default=None,
              help="Owner identifier (Slice C); omit for default-owner slot.")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.option("--json", "as_json", is_flag=True, default=False)
def effective_scope_cmd(owner: str | None, db: str | None, as_json: bool) -> None:
    """Show what's gating the caller RIGHT NOW.

    Returns the composed snapshot of active task (if any) + global
    rule count. After a task ends, has_active_task becomes False —
    the proxy has returned to its baseline setting.
    """
    from .bouncer.self_scoping import get_effective_scope

    # The CLI passes db via an env override since get_effective_scope
    # uses BouncerStore() with default-path lookup. We don't have a
    # plumbed-in store for self_scoping; use env.
    import os
    if db:
        os.environ["IAM_JIT_BOUNCER_DB"] = db
    scope = get_effective_scope(owner=owner)
    if as_json:
        click.echo(json.dumps(scope.to_dict(), indent=2))
        return
    if not scope.has_active_task:
        click.echo("(no active task — at baseline)")
        click.echo(f"global rules: {scope.global_rule_count}")
        return
    click.echo(f"active task:       {scope.active_task_id}")
    click.echo(f"  description:    {scope.active_task_description}")
    click.echo(f"  expires:        {scope.active_task_expires_at}")
    click.echo(f"  owner:          {scope.active_task_owner or '(default)'}")
    click.echo(f"  allow rules:    {scope.active_task_allow_rule_count}")
    click.echo(f"  deny rules:     {scope.active_task_deny_rule_count}")
    click.echo(f"global rules:    {scope.global_rule_count}")


@main.command("recommend")
@click.option("--since", default=None,
              help="ISO-8601 lower bound (e.g. 2026-05-10T00:00:00Z). "
                   "Omit to read the full audit log.")
@click.option("--until", default=None,
              help="ISO-8601 upper bound. Omit for 'until now'.")
@click.option("--min-support", type=click.IntRange(min=1), default=3, show_default=True,
              help="Skip groups with fewer than N observed calls (must be >= 1).")
@click.option("--limit", type=click.IntRange(min=1, max=10000), default=10000,
              show_default=True,
              help="Max number of decisions to read (1 to 10000).")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.option("--apply", "apply_now", is_flag=True, default=False,
              help="Apply recommendations as new rules. Skip for review-only.")
@click.option("--apply-only", "apply_only", default=None,
              help="With --apply, only apply recommendations whose "
                   "pattern is in this comma-separated list. "
                   "Example: --apply-only s3:GetObject,s3:ListBucket")
@click.option("--include-task-scoped", is_flag=True, default=False,
              help="By default, task-scoped (Slice C one-off session) "
                   "decisions are excluded. Pass this to include them.")
@click.option("--save-as-profile", "save_as_profile", default=None,
              is_flag=False, flag_value=_AUTO_NAME_SENTINEL,
              metavar="[NAME]",
              help="Persist the recommendations as a NEW profile in "
                   "~/.iam-jit/bouncer/profiles.yaml. NAME is optional "
                   "(#226 profile-auto-naming): pass `--save-as-profile` "
                   "alone for a context-suggested name (TTY: prompts; "
                   "non-TTY: auto-generates as "
                   "`auto-YYYY-MM-DD-{services}-{shape}` + prints to stderr). "
                   "Pass `--save-as-profile NAME` for an explicit name. "
                   "Refuses to overwrite an existing profile sourced from "
                   "an org URL; collision-avoids local names via -2/-3 "
                   "suffix.")
@click.option("--profile-description", default=None,
              help="With --save-as-profile, the description string written "
                   "into the new profile. Falls back to a generated summary.")
def recommend_cmd(
    since: str | None,
    until: str | None,
    min_support: int,
    limit: int,
    db: str | None,
    as_json: bool,
    apply_now: bool,
    apply_only: str | None,
    include_task_scoped: bool,
    save_as_profile: str | None,
    profile_description: str | None,
) -> None:
    """Synthesize a draft ruleset from observed traffic in a window.

    Groups observed decisions by service:action, detects ARN/region
    patterns, recommends ALLOW rules with the discovered scope, and
    attaches a curated 'what does this action do' note for common
    actions.

    Review-first by default. Pass --apply to add recommendations as
    new rules. Combine with --apply-only to cherry-pick which
    patterns to apply.
    """
    from .bouncer.recommender import (
        filter_decisions_by_window,
        summarize_window,
        synthesize_rules,
    )

    with _opened_store(db) as store:
        all_decisions = store.list_decisions(limit=limit)
    # WB28 LOW-28-04 closure: semantic datetime comparison instead of
    # lexicographic string compare (handles mixed-tz input).
    decisions = filter_decisions_by_window(
        all_decisions, since=since, until=until
    )

    summary = summarize_window(decisions)
    recs = synthesize_rules(
        decisions,
        min_support=min_support,
        include_task_scoped=include_task_scoped,
    )

    # WB28 MED-28-06 closure: cherry-pick which patterns to apply.
    apply_patterns: set[str] | None = None
    if apply_only:
        apply_patterns = {p.strip() for p in apply_only.split(",") if p.strip()}
        if not apply_patterns:
            click.echo("--apply-only: no patterns parsed; aborting.", err=True)
            raise SystemExit(2)

    if as_json:
        click.echo(json.dumps({
            "summary": summary,
            "recommendations": [r.to_dict() for r in recs],
        }, indent=2))
        if apply_now and recs:
            _apply_recommendations_via_cli(db, recs, apply_patterns)
        return

    click.echo(f"# observation window: {summary['window_start']} -> {summary['window_end']}")
    click.echo(f"# {summary['total_calls']} total calls "
               f"(allow={summary['allow_count']} deny={summary['deny_count']} prompt={summary['prompt_count']})")
    click.echo(f"# {summary['distinct_services']} distinct services, "
               f"{summary['distinct_actions']} distinct actions")
    click.echo()
    if not recs:
        click.echo("(no recommendations — either no observed calls or all groups below "
                   f"the --min-support threshold of {min_support})")
        return
    click.echo(f"## Recommended rules ({len(recs)}):")
    for r in recs:
        scope_bits = []
        if r.proposed_rule.arn_scope:
            scope_bits.append(f"arn={r.proposed_rule.arn_scope}")
        if r.proposed_rule.region_scope:
            scope_bits.append(f"region={r.proposed_rule.region_scope}")
        scope = f" [{', '.join(scope_bits)}]" if scope_bits else ""
        click.echo(f"  ALLOW {r.proposed_rule.pattern}{scope}")
        click.echo(f"    support: {r.support_count} calls "
                   f"({round(r.hit_rate * 100, 1)}% of window)")
        if r.arn_pattern_rationale:
            click.echo(f"    arn:    {r.arn_pattern_rationale}")
        if r.region_pattern_rationale:
            click.echo(f"    region: {r.region_pattern_rationale}")
        if r.research_note:
            click.echo(f"    note:   {r.research_note['summary']}")
            click.echo(f"            {r.research_note['typical_use']}")
        click.echo()

    if apply_now:
        _apply_recommendations_via_cli(db, recs, apply_patterns)

    if save_as_profile is not None:
        # #226 profile-auto-naming: resolve the actual name from the
        # CLI value via the shared resolver. `_AUTO_NAME_SENTINEL`
        # (set by Click when the user passed `--save-as-profile` with
        # NO value) triggers suggest+TTY-prompt-or-auto-gen; any other
        # value is treated as an explicit name (still collision-avoided).
        from .bouncer.profiles import load_profiles
        suggested = suggest_profile_name_for_recommender(recs, summary)
        try:
            existing = load_profiles()
        except Exception:
            existing = {}
        resolved_name = resolve_profile_name(
            save_as_profile, suggested, taken=existing.keys(),
        )
        _save_recommendations_as_profile(
            recs, resolved_name,
            description=profile_description,
            apply_patterns=apply_patterns,
        )


def _save_recommendations_as_profile(
    recs: list,
    profile_name: str,
    *,
    description: str | None = None,
    apply_patterns: set[str] | None = None,
) -> None:
    """Persist synthesized recommendations as a NEW profile's allow_rules.
    The profile lives in ~/.iam-jit/bouncer/profiles.yaml under the
    given name; future `ibounce run --profile NAME` invocations
    will load those rules.

    Respects the org-distributed read-only invariant: profiles with
    source != "local" cannot be overwritten."""
    from .bouncer.profiles import (
        Profile,
        ProfileAllowRule,
        load_profiles,
        upsert_profile,
    )

    # Filter to apply_patterns when set (cherry-pick mirrors --apply-only)
    chosen = [
        r for r in recs
        if apply_patterns is None or r.proposed_rule.pattern in apply_patterns
    ]
    if not chosen:
        click.echo("--save-as-profile: no recommendations matched filters; "
                   "nothing written.", err=True)
        raise SystemExit(2)

    # If a local profile of the same name exists, MERGE allow_rules
    # rather than overwrite (otherwise --save-as-profile becomes a
    # foot-gun that loses prior saves).
    existing_rules: list[ProfileAllowRule] = []
    existing_description = ""
    try:
        existing_profiles = load_profiles()
        if profile_name in existing_profiles:
            prior = existing_profiles[profile_name]
            if prior.source != "local":
                click.echo(
                    f"profile {profile_name!r} is sourced from "
                    f"{prior.source!r} and is read-only. Pick a "
                    f"different name.",
                    err=True,
                )
                raise SystemExit(2)
            existing_rules = list(prior.allow_rules)
            existing_description = prior.description
    except ValueError:
        # Malformed profiles.yaml — let upsert_profile re-raise.
        pass

    seen_patterns = {
        (r.pattern, r.arn_scope, r.region_scope) for r in existing_rules
    }
    added: list[ProfileAllowRule] = []
    for r in chosen:
        pr = r.proposed_rule
        key = (pr.pattern, pr.arn_scope, pr.region_scope)
        if key in seen_patterns:
            continue
        added.append(ProfileAllowRule(
            pattern=pr.pattern,
            arn_scope=pr.arn_scope,
            region_scope=pr.region_scope,
            note=pr.note or f"recommended from session at {_now_iso_no_micros()}",
        ))

    if not added:
        click.echo(
            f"profile {profile_name!r}: all {len(chosen)} recommendations "
            f"already present; nothing to add."
        )
        return

    merged = Profile(
        name=profile_name,
        description=description or existing_description or (
            f"Recommendations captured from session — "
            f"{len(existing_rules) + len(added)} allow rules."
        ),
        allow_rules=tuple(existing_rules + added),
        source="local",
    )
    path = upsert_profile(merged)
    click.echo(
        f"wrote {len(added)} new rule(s) to profile {profile_name!r} "
        f"(total: {len(merged.allow_rules)}) at {path}"
    )
    click.echo(
        f"activate with: ibounce run --profile {profile_name}"
    )


def _now_iso_no_micros() -> str:
    """Wall-clock ISO timestamp without microseconds. Used in
    profile-rule notes so the audit trail says when each rule was
    captured without micro-noise."""
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _apply_recommendations_via_cli(
    db_path: str | None,
    recs: list,
    apply_patterns: set[str] | None = None,
) -> None:
    """Apply recommendations as rules in a single audit-logged batch.

    WB28 MED-28-02 closure: skip duplicates against existing rules
    so re-running `recommend --apply` doesn't accumulate identical
    rows.
    WB28 MED-28-03 closure: record the rule_ids in the
    `recommendation_applied` event detail so post-hoc review can
    correlate the batch with its rows without timestamp guessing.
    WB28 MED-28-06 closure: respect `apply_patterns` cherry-pick.
    """
    from .bouncer.store import InvalidRuleError

    with _opened_store(db_path) as store:
        actor = _current_actor()
        added_rule_ids: list[int] = []
        rejected: list[dict[str, Any]] = []
        for r in recs:
            pat = r.proposed_rule.pattern
            if apply_patterns is not None and pat not in apply_patterns:
                continue
            if store.rule_exists(r.proposed_rule):
                rejected.append({"pattern": pat, "error": "rule already exists"})
                click.echo(f"skipped (duplicate): {pat}")
                continue
            try:
                rid = store.add_rule(r.proposed_rule, actor=actor)
                added_rule_ids.append(rid)
            except InvalidRuleError as e:
                rejected.append({"pattern": pat, "error": str(e)})
                click.echo(f"warning: rejected recommended rule {pat}: {e}",
                           err=True)
        # Log a top-level "recommendations applied" event so the
        # audit chain shows the batch shape.
        store._record_config_event_locked(
            actor=actor,
            kind="recommendation_applied",
            summary=f"applied {len(added_rule_ids)} recommended rule(s)",
            detail={
                "count": len(added_rule_ids),
                "rule_ids": added_rule_ids,
                "rejected_count": len(rejected),
                "rejected": rejected,
            },
        )
    click.echo(f"applied {len(added_rule_ids)} recommended rules.")


@main.command("inspect")
@click.option("--method", required=True, help="HTTP method (GET / POST / ...)")
@click.option("--host", required=True, help="HTTP Host header value")
@click.option("--path", default="/", help="HTTP path (default: /)")
@click.option(
    "--header",
    "headers",
    multiple=True,
    help="HTTP header in 'Name: value' form; repeatable.",
)
@click.option("--body", default=None, help="Request body (raw string).")
def inspect_cmd(
    method: str,
    host: str,
    path: str,
    headers: tuple[str, ...],
    body: str | None,
) -> None:
    """Parse a raw AWS API HTTP request and show how the bouncer
    classifies it (service / action / region / resource hint).
    Doesn't gate or forward — pure diagnostic."""
    header_dict: dict[str, str] = {}
    for h in headers:
        if ":" not in h:
            click.echo(f"bad header (missing ':'): {h}", err=True)
            sys.exit(2)
        name, val = h.split(":", 1)
        header_dict[name.strip()] = val.strip()

    parsed = parse_request(
        method=method,
        host=host,
        path=path,
        headers=header_dict,
        body=body,
    )
    if parsed is None:
        click.echo("could not classify request (no SigV4 Authorization header)", err=True)
        sys.exit(2)
    click.echo(json.dumps(parsed.to_dict(), indent=2))


@main.group("profile")
def profile_group() -> None:
    """Manage environment profiles (Slice 7).

    Profiles are named, switchable rule layers that add environment-
    aware keyword denies on top of per-task scopes + global rules.
    Profile denies are a HARD FLOOR — they fire even if a task scope
    or global rule would have allowed the call.
    """


@profile_group.command("list")
def profile_list_cmd() -> None:
    """List available profiles + show which would be active."""
    from .bouncer.profiles import (
        ACTIVE_PROFILE_ENV, load_profiles, resolve_profiles_path,
    )
    profiles = load_profiles()
    env_active = os.environ.get(ACTIVE_PROFILE_ENV) or "(none set)"
    click.echo(f"profiles file: {resolve_profiles_path()}")
    click.echo(f"{ACTIVE_PROFILE_ENV}: {env_active}")
    click.echo()
    click.echo(f"{'name':<22} {'kw':>3} {'verbs':>5} {'accts':>5}  description")
    click.echo("-" * 78)
    for name in sorted(profiles.keys()):
        p = profiles[name]
        click.echo(
            f"{name:<22} {len(p.deny_keywords):>3} "
            f"{len(p.deny_verbs):>5} {len(p.only_account_ids):>5}  "
            f"{p.description}"
        )


@profile_group.command("install-defaults")
def profile_install_defaults_cmd() -> None:
    """Write the default profiles.yaml to disk (no-op if it exists)."""
    from .bouncer.profiles import resolve_profiles_path, write_default_profiles
    target = resolve_profiles_path()
    if target.exists():
        click.echo(f"profiles file already exists at {target} (no change)")
        return
    written = write_default_profiles()
    click.secho(f"wrote default profiles to {written}", fg="green")


@profile_group.command("show")
@click.argument("name")
def profile_show_cmd(name: str) -> None:
    """Show details for one profile."""
    import dataclasses as _dc
    from .bouncer.profiles import load_profiles
    profiles = load_profiles()
    if name not in profiles:
        click.secho(
            f"profile {name!r} not found. Available: {sorted(profiles.keys())}",
            fg="red", err=True,
        )
        sys.exit(1)
    click.echo(json.dumps(_dc.asdict(profiles[name]), indent=2, default=str))


@profile_group.command("install")
@click.option(
    "--from", "from_url", required=True, metavar="URL",
    help="HTTPS URL of a profiles.yaml fragment (or single-profile YAML). "
         "Used by enterprises to distribute curated profiles: IT publishes "
         "`https://internal.acme.com/iam-jit-profiles/staging.yaml` + each "
         "engineer runs `ibounce profile install --from <URL>`. "
         "Refuses http:// — distribution over plaintext could be MITM'd to "
         "substitute a permissive profile.",
)
@click.option(
    "--sha256", "expected_sha256", default=None, metavar="HEX",
    help="Optional SHA-256 of the fetched bytes. If provided, install "
         "fails when the actual hash differs — protects against a "
         "compromised distribution server swapping the file under you. "
         "IT teams should pin this in their onboarding docs.",
)
@click.option(
    "--force", is_flag=True, default=False,
    help="Overwrite if a profile of the same name already exists "
         "(including one from a prior install). WITHOUT --force, "
         "install refuses to overwrite to prevent accidentally "
         "downgrading an existing profile.",
)
@click.option(
    "--timeout", type=int, default=10, show_default=True,
    help="HTTPS fetch timeout in seconds.",
)
def profile_install_cmd(
    from_url: str,
    expected_sha256: str | None,
    force: bool,
    timeout: int,
) -> None:
    """Fetch + install one or more profiles from a URL.

    Composes with [[enterprise-profile-distribution]]: IT teams ship
    curated profile sets, engineers `install --from <URL>` on day 1.
    The `source` field on installed profiles is set to the fetch URL,
    making them READ-ONLY at this CLI surface (engineers cannot edit
    org profiles to bypass guardrails).
    """
    import hashlib
    import urllib.error
    import urllib.request

    from .bouncer.profiles import (
        Profile,
        load_profiles,
        resolve_profiles_path,
        upsert_profile,
        _profile_from_dict,
    )

    if not from_url.lower().startswith("https://"):
        click.secho(
            f"refusing to fetch from {from_url!r}: only https:// URLs "
            f"are allowed (MITM-substitutable plaintext is an attack "
            f"vector against IT-distributed profiles).",
            fg="red", err=True,
        )
        sys.exit(2)

    click.echo(f"fetching {from_url} ...")
    try:
        with urllib.request.urlopen(from_url, timeout=timeout) as resp:
            payload = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        click.secho(f"fetch failed: {e}", fg="red", err=True)
        sys.exit(1)

    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if expected_sha256:
        expected_norm = expected_sha256.lower().replace(":", "")
        if actual_sha256 != expected_norm:
            click.secho(
                f"sha256 mismatch:\n  expected: {expected_norm}\n"
                f"  actual:   {actual_sha256}\nrefusing to install.",
                fg="red", err=True,
            )
            sys.exit(2)
        click.echo(f"sha256 verified: {actual_sha256}")
    else:
        click.echo(f"sha256 (no pin given): {actual_sha256}")

    import yaml as _yaml
    try:
        data = _yaml.safe_load(payload.decode("utf-8"))
    except (UnicodeDecodeError, _yaml.YAMLError) as e:
        click.secho(f"payload is not valid YAML: {e}", fg="red", err=True)
        sys.exit(1)
    if not isinstance(data, dict):
        click.secho("payload must be a YAML object", fg="red", err=True)
        sys.exit(1)

    profiles_obj = data.get("profiles")
    if not isinstance(profiles_obj, dict) or not profiles_obj:
        click.secho(
            "payload must contain a non-empty `profiles` object",
            fg="red", err=True,
        )
        sys.exit(1)

    # Validate every profile BEFORE writing anything (no partial installs)
    parsed: list[Profile] = []
    for name, body in profiles_obj.items():
        if not isinstance(body, dict):
            click.secho(
                f"profile {name!r} must be a dict",
                fg="red", err=True,
            )
            sys.exit(1)
        # Force the source field to the fetch URL — engineers cannot
        # spoof a local source by including `source: local` in the
        # payload.
        body_with_source = {**body, "source": from_url}
        try:
            parsed.append(_profile_from_dict(name, body_with_source))
        except ValueError as e:
            click.secho(
                f"profile {name!r} failed validation: {e}",
                fg="red", err=True,
            )
            sys.exit(1)

    # Conflict check against existing profiles
    existing = load_profiles()
    conflicts: list[tuple[str, str]] = []
    for p in parsed:
        if p.name in existing:
            prior_src = existing[p.name].source
            conflicts.append((p.name, prior_src))
    if conflicts and not force:
        click.secho(
            "the following profiles already exist; pass --force to "
            "overwrite:",
            fg="yellow", err=True,
        )
        for name, prior_src in conflicts:
            click.echo(f"  {name}  (current source: {prior_src})", err=True)
        sys.exit(2)

    # Write each profile. upsert_profile enforces the read-only invariant
    # for non-local prior sources; --force bypasses CONFLICT but not the
    # read-only check. (We choose to allow re-install from a DIFFERENT
    # org URL — IT teams legitimately re-host. The shape they can't
    # do is `force`-installing OVER an org profile from a LOCAL one,
    # which upsert_profile catches.)
    written: list[str] = []
    for p in parsed:
        # When --force, we need to bypass upsert_profile's read-only
        # check for prior org profiles. The cleanest way: write
        # directly via a re-implementation here that knows we're
        # installing from a URL.
        _install_one_profile(p, from_url)
        written.append(p.name)

    # #270 Slice 2 — enqueue one PROFILE_INSTALL synthetic per
    # installed profile so the `ibounce serve` process's drainer
    # picks them up + the non_org_profile_install alert rule sees
    # them. Best-effort: a store error here does NOT fail the
    # install (the profile is already on disk; the audit event is
    # a visibility-channel feature, per [[audit-export-failure-
    # visibility]]). Cross-process pattern from dbounce 24eca0c.
    try:
        from .bouncer.audit_export.alerts import EVENT_TYPE_PROFILE_INSTALL
        installer = _current_actor()
        with _opened_store(None) as audit_store:
            for name in written:
                audit_store.enqueue_pending_audit_event(
                    event_type=EVENT_TYPE_PROFILE_INSTALL,
                    payload_json=json.dumps({
                        "profile_name": name,
                        "source_url": from_url,
                        "installed_by": installer,
                        "sha256": actual_sha256,
                    }),
                )
                # #278 — additionally enqueue an ADMIN_ACTION row so a
                # SIEM dashboard keyed on the cross-product
                # `event_type == "ADMIN_ACTION"` filter catches profile
                # installs alongside rule edits / pauses / preset
                # applies. The dedicated PROFILE_INSTALL synthetic
                # stays for the non_org_profile_install alert rule
                # (which keys on its richer payload).
                _enqueue_admin_action(
                    audit_store,
                    kind="profile.install",
                    target_kind="profile",
                    target_id=name,
                    target_extra={
                        "source_url": from_url,
                        "sha256": actual_sha256,
                    },
                    after={
                        "profile_name": name,
                        "source_url": from_url,
                        "sha256": actual_sha256,
                    },
                )
    except Exception as e:
        # Visible to the operator so a quiet drain failure surfaces
        # immediately, but not exit-1: the install IS done.
        click.secho(
            f"warning: audit-event enqueue failed (the install itself "
            f"succeeded): {e}",
            fg="yellow", err=True,
        )

    target = resolve_profiles_path()
    click.secho(
        f"installed {len(written)} profile(s) into {target}:",
        fg="green",
    )
    for name in written:
        click.echo(f"  {name}")
    click.echo()
    click.echo("Activate one with:")
    click.echo(f"  ibounce run --profile {written[0]}")
    click.echo("These profiles are READ-ONLY (sourced from URL); "
               "edit the upstream YAML + re-install to update.")


def _install_one_profile(profile: "Profile", source_url: str) -> None:
    """Write an installed profile to profiles.yaml, bypassing the
    upsert_profile read-only check (we know the source is org-curated
    and the user passed --force or there was no conflict). The source
    field is always set to the fetch URL — engineers cannot spoof
    'local' source via payload."""
    import yaml as _yaml

    from .bouncer.profiles import (
        Profile,
        profile_to_yaml_dict,
        resolve_profiles_path,
    )
    resolved = resolve_profiles_path()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    if resolved.exists():
        try:
            existing = _yaml.safe_load(resolved.read_text()) or {}
        except _yaml.YAMLError as e:
            raise ValueError(
                f"profiles file at {resolved} is not valid YAML: {e}"
            ) from e
        if not isinstance(existing, dict):
            existing = {}
        profiles_obj = existing.get("profiles")
        if not isinstance(profiles_obj, dict):
            profiles_obj = {}
            existing["profiles"] = profiles_obj
    else:
        existing = {"profiles": {}}
        profiles_obj = existing["profiles"]

    # Force source to URL regardless of what the upstream YAML says
    p = Profile(
        name=profile.name,
        description=profile.description,
        deny_keywords=profile.deny_keywords,
        keyword_targets=profile.keyword_targets,
        keyword_match=profile.keyword_match,
        only_account_ids=profile.only_account_ids,
        deny_verbs=profile.deny_verbs,
        exceptions=profile.exceptions,
        allow_rules=profile.allow_rules,
        source=source_url,
    )
    profiles_obj[p.name] = profile_to_yaml_dict(p)
    resolved.write_text(_yaml.safe_dump(existing, sort_keys=False))


@profile_group.command("doctor")
@click.option(
    "--profiles-path", default=None,
    help="Path to profiles.yaml (default: ~/.iam-jit/bouncer/profiles.yaml). "
         "Honors IAM_JIT_BOUNCER_PROFILES_FILE env var if unset.",
)
@click.option(
    "--apply", "apply_changes", is_flag=True, default=False,
    help="Additively merge missing default fields into profiles.yaml + "
         "back up prior file. Per [[creates-never-mutates]]: only ADDS "
         "absent fields; never overwrites operator-customized values.",
)
@click.option(
    "--acknowledge", is_flag=True, default=False,
    help="Record the current shipped-defaults version as acknowledged. "
         "Future `ibounce run` startup banners skip the §A19 warning "
         "until a new version bumps the stamp.",
)
@click.option(
    "--diff", "show_diff", is_flag=True, default=False,
    help="Print the YAML fragment that --apply would add.",
)
@click.option(
    "--check", "check_only", is_flag=True, default=False,
    help="Silent mode: exit 0 if profile is current, exit 2 if gaps found. "
         "For scripted use (CI / install hooks).",
)
@click.option(
    "--json", "json_out", is_flag=True, default=False,
    help="Emit machine-readable JSON. Exit 2 if gaps found.",
)
def profile_doctor_cmd(
    profiles_path: str | None,
    apply_changes: bool,
    acknowledge: bool,
    show_diff: bool,
    check_only: bool,
    json_out: bool,
) -> None:
    """Diff installed profile against shipped defaults + report missing fields.

    Compares ~/.iam-jit/bouncer/profiles.yaml against the shipped defaults
    and reports any fields the operator's local file is missing.
    ibounce NEVER auto-overwrites profiles.yaml — operator edits survive
    upgrades — but that means a new safety floor (e.g. an additional
    deny_actions entry, or allow_baseline gating) added to embedded
    defaults AFTER your file was written goes unnoticed.

      ibounce profile doctor              # report missing fields (no write)
      ibounce profile doctor --apply      # additively merge + back up prior file
      ibounce profile doctor --acknowledge # silence the warning for this version
      ibounce profile doctor --diff       # show the YAML delta --apply would write
      ibounce profile doctor --check      # silent; exit 2 if gaps found (CI-friendly)

    Per [[creates-never-mutates]]: --apply is ADDITIVE only.

    Per [[security-team-positioning-safety-not-surveillance]]: framed
    as "your profile is behind" not "you are non-compliant."

    Per task #321 / KNOWN-CAVEATS §A19.
    """
    from .bouncer import profile_doctor as _doctor

    if apply_changes and acknowledge:
        click.secho(
            "--apply and --acknowledge are mutually exclusive",
            fg="red", err=True,
        )
        sys.exit(2)

    if apply_changes:
        try:
            result = _doctor.apply(profiles_path)
        except FileNotFoundError as e:
            click.secho(str(e), fg="red", err=True)
            click.echo(
                "Run `ibounce profile install-defaults` first to materialize "
                "the embedded defaults on disk.",
                err=True,
            )
            sys.exit(1)
        if not result.applied_fields:
            click.echo(
                f"ibounce: profile doctor — nothing to apply; installed "
                f"profile matches shipped defaults "
                f"(version {_doctor.SHIPPED_DEFAULTS_VERSION})."
            )
            return
        click.echo(
            f"ibounce: profile doctor --apply — added "
            f"{len(result.applied_fields)} field(s); backup at "
            f"{result.backup_path}"
        )
        for g in result.applied_fields:
            click.echo(
                f"  + {g.profile_name}.{g.field} = {g.default_value!r}   "
                f"[{g.category.value}] {g.added_in}"
            )
        return

    if acknowledge:
        path = _doctor.acknowledge(profiles_path)
        click.echo(
            f"ibounce: profile doctor --acknowledge — recorded "
            f"{_doctor.SHIPPED_DEFAULTS_VERSION} at {path}"
        )
        click.echo(
            "future `ibounce run` startup banners will skip the §A19 "
            "warning until a new shipped-defaults version bumps the stamp."
        )
        return

    report = _doctor.check(profiles_path)
    if check_only:
        if report.missing_fields:
            sys.exit(2)
        return
    if json_out:
        click.echo(_doctor.report_to_json_str(report))
        if report.missing_fields:
            sys.exit(2)
        return
    click.echo(_doctor.format_report(report), nl=False)
    if show_diff and report.missing_fields:
        click.echo("--- YAML that --apply would add ---")
        for g in report.missing_fields:
            click.echo(f"profiles.{g.profile_name}.{g.field}: {g.default_value!r}")
    if report.missing_fields:
        sys.exit(2)


@main.group("prompts")
def prompts_group() -> None:
    """View + answer DENY notifications the proxy queued.

    When the proxy runs with `--prompt-on-deny`, every transparent-
    mode DENY also writes a row here so the operator can later
    answer (always-allow / add-to-profile / ignore). The agent has
    already been denied by the time the prompt appears — answers
    take effect on the NEXT call of the same shape.

    v1.0 (now): async queue. v1.1 will add a synchronous prompt
    where the proxy briefly waits for an answer before returning.
    """


@prompts_group.command("list")
@click.option("--status", default="pending", show_default=True,
              type=click.Choice(["pending", "answered", "ignored"]))
@click.option("--limit", type=int, default=20, show_default=True)
@click.option("--kind", default=None,
              type=click.Choice(["deny-prompt", "plan-write"], case_sensitive=False),
              help="#145 prompt-kind filter: omit to see BOTH kinds "
                   "(deny-prompts from --prompt-on-deny + plan-write "
                   "prompts from --mode plan-capture's read->write "
                   "switch); pass to filter to one. Kind is shown in "
                   "the rendered table either way.")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def prompts_list_cmd(
    status: str, limit: int, kind: str | None, db: str | None,
) -> None:
    """Show prompts in the queue.

    #145: the queue now contains TWO kinds of prompt:
      - `deny-prompt` — transparent-mode DENY surfaced via
        `--prompt-on-deny` (#5); answer with --kind always/profile/ignore
      - `plan-write` — first write in a plan-capture session under
        --write-switch-notify=manual (#145); answer with
        `--kind plan-write --decision approve|reject`

    The kind is rendered per row + can be filtered via `--kind`.
    """
    with _opened_store(db) as store:
        rows = store.list_pending_prompts(
            status=status, limit=limit, kind=kind,
        )
    if not rows:
        scope = f"{kind} " if kind else ""
        click.echo(f"(no {status} {scope}prompts)")
        return
    click.echo(f"{'id':>5}  {'kind':<12}  {'at':<20}  {'service':<10}  action")
    click.echo("-" * 90)
    for r in rows:
        click.echo(
            f"{r['id']:>5}  {r.get('kind') or 'deny-prompt':<12}  "
            f"{r['created_at']:<20}  "
            f"{r['service']:<10}  {r['action']}"
        )
        if r.get("session_id"):
            click.echo(f"        session: {r['session_id']}")
        if r["arn"]:
            click.echo(f"        arn: {r['arn']}")
        click.echo(f"        reason: {r['deny_reason']}")


@prompts_group.command("show")
@click.argument("prompt_id", type=int)
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def prompts_show_cmd(prompt_id: int, db: str | None) -> None:
    """Show one prompt with full detail."""
    with _opened_store(db) as store:
        row = store.get_pending_prompt(prompt_id)
    if row is None:
        click.secho(f"prompt #{prompt_id} not found", fg="red", err=True)
        sys.exit(1)
    click.echo(json.dumps(row, indent=2))


@prompts_group.command("answer")
@click.argument("prompt_id", type=int)
@click.option("--kind", required=True,
              type=click.Choice(["always", "profile", "ignore", "plan-write"]),
              help="always = add a global ALLOW rule for the exact "
                   "service:action[+arn] of this prompt. profile = "
                   "append an allow_rule to --target NAME (must be "
                   "a local profile, not org-distributed). ignore = "
                   "mark answered without side effect. plan-write "
                   "(#145) = approve/reject the first-write-in-session "
                   "transition for a plan-capture session; use with "
                   "--decision approve|reject.")
@click.option("--target", default=None,
              is_flag=False, flag_value=_AUTO_NAME_SENTINEL,
              metavar="[NAME]",
              help="With --kind profile: the profile name to append to. "
                   "NAME is optional (#226 profile-auto-naming): pass "
                   "`--target` alone to auto-name from the prompt's "
                   "service+action (TTY: prompts; non-TTY: auto-generates "
                   "as `auto-YYYY-MM-DD-prompt-{ID}-{service}-{action}` + "
                   "prints to stderr). If the chosen name doesn't yet "
                   "exist, the profile is created (as a local profile) "
                   "before the allow_rule is appended.")
@click.option("--decision",
              type=click.Choice(["approve", "reject"], case_sensitive=False),
              default=None,
              help="#145 — required for --kind plan-write. approve = "
                   "transition session to writes_approved (subsequent "
                   "writes still get success synthetic). reject = "
                   "transition to writes_rejected (subsequent writes "
                   "get PlanCaptureWritesRejected synthetic error).")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def prompts_answer_cmd(
    prompt_id: int, kind: str, target: str | None,
    decision: str | None, db: str | None,
) -> None:
    """Answer a pending prompt + apply the side-effect."""
    from .bouncer.profiles import (
        Profile,
        ProfileAllowRule,
        load_profiles,
        upsert_profile,
    )
    actor = _current_actor()
    # #145 — plan-write answer path. Handled BEFORE the deny-prompt
    # branches because the side effect (session phase transition) is
    # completely different and the schema we read off the prompt row
    # is different (session_id vs arn-scope). Validation:
    #   --decision is required
    #   --target / --kind=always|profile|ignore are NOT valid here
    if kind == "plan-write":
        if not decision:
            click.secho(
                "--kind plan-write requires --decision approve|reject",
                fg="red", err=True,
            )
            sys.exit(2)
        if target is not None:
            click.secho(
                "--target is not valid with --kind plan-write "
                "(plan-write prompts are session-scoped, not "
                "profile-scoped).",
                fg="red", err=True,
            )
            sys.exit(2)
        with _opened_store(db) as store:
            prompt = store.get_pending_prompt(prompt_id)
            if prompt is None:
                click.secho(
                    f"prompt #{prompt_id} not found", fg="red", err=True,
                )
                sys.exit(1)
            if prompt.get("kind") != "plan-write":
                click.secho(
                    f"prompt #{prompt_id} is kind={prompt.get('kind')!r}, "
                    f"not 'plan-write'. Use the appropriate --kind for "
                    f"deny-prompts (always/profile/ignore).",
                    fg="red", err=True,
                )
                sys.exit(2)
            if prompt["status"] != "pending":
                click.secho(
                    f"prompt #{prompt_id} already {prompt['status']!r}; "
                    f"nothing to do",
                    fg="yellow",
                )
                return
            answered = store.answer_plan_write_prompt(
                prompt_id, decision=decision.lower(), answered_by=actor,
            )
            if answered is None:
                click.secho(
                    f"prompt #{prompt_id}: answer not recorded (race?)",
                    fg="yellow",
                )
                return
            target_phase = (
                "writes_approved" if decision.lower() == "approve"
                else "writes_rejected"
            )
            store.transition_plan_session_phase(
                answered["session_id"],
                new_phase=target_phase,
                decision=decision.lower(),
                decided_by=actor,
            )
        click.secho(
            f"plan-write prompt #{prompt_id} answered: {decision.lower()} "
            f"(session {answered['session_id']} -> {target_phase})",
            fg="green",
        )
        return

    # #226 profile-auto-naming: `target` is now optional for --kind
    # profile. If the operator passed neither `--target` nor
    # `--target NAME`, that's still an error (need to opt in to the
    # auto-name path explicitly, otherwise a typo'd command would
    # silently create a brand-new profile). If `--target` was passed
    # alone, Click set target = _AUTO_NAME_SENTINEL and we'll resolve
    # the name once we have the prompt context below.
    if kind == "profile" and target is None:
        click.secho(
            "--kind profile requires --target [NAME] (use --target alone "
            "for an auto-generated name).",
            fg="red", err=True,
        )
        sys.exit(2)
    # Guard against --decision passed without --kind plan-write
    if decision is not None:
        click.secho(
            "--decision is only valid with --kind plan-write",
            fg="red", err=True,
        )
        sys.exit(2)

    with _opened_store(db) as store:
        prompt = store.get_pending_prompt(prompt_id)
        if prompt is None:
            click.secho(f"prompt #{prompt_id} not found", fg="red", err=True)
            sys.exit(1)
        # #145 — refuse to apply a deny-prompt answer-kind to a
        # plan-write prompt id. Without this, an operator with a
        # typo'd --kind would silently mark the plan-write row as
        # answered with the wrong semantics + the session phase
        # wouldn't transition.
        if prompt.get("kind") == "plan-write":
            click.secho(
                f"prompt #{prompt_id} is a plan-write prompt; use "
                f"`--kind plan-write --decision approve|reject` "
                f"instead of --kind {kind!r}.",
                fg="red", err=True,
            )
            sys.exit(2)
        if prompt["status"] != "pending":
            click.secho(
                f"prompt #{prompt_id} already {prompt['status']!r}; nothing to do",
                fg="yellow",
            )
            return

        # Apply side effect FIRST. If the mutation fails (e.g. profile
        # is org-distributed and read-only), abort BEFORE marking the
        # prompt answered. Otherwise we'd lose the prompt + not have
        # applied the answer.
        if kind == "always":
            # HIGH-33-03 closure: refuse `always` when the prompt's
            # resolved arn is null. Otherwise the answer adds a
            # global ALLOW with arn_scope=None (matches ANY arn for
            # that action — broader than the operator likely
            # intends). Force the operator to either:
            #   (a) use --kind profile --target NAME (scoped to
            #       a specific profile), OR
            #   (b) edit the rules manually with a deliberate
            #       arn_scope.
            if not prompt.get("arn"):
                click.secho(
                    f"prompt #{prompt_id}: 'always' answer refused "
                    f"because the prompt has no ARN scope. A global "
                    f"ALLOW with arn_scope=None would match ANY "
                    f"{prompt['service']}:{prompt['action']} request, "
                    f"which is rarely the intent. Use --kind profile "
                    f"--target NAME for a scoped allow, OR add a rule "
                    f"manually with `ibounce rules add "
                    f"--pattern {prompt['service']}:{prompt['action']} "
                    f"--arn-scope <ARN>`. HIGH-33-03 closure.",
                    fg="red", err=True,
                )
                sys.exit(2)
            from .bouncer.rules import Effect, ProxyRule
            store.add_rule(
                ProxyRule(
                    pattern=f"{prompt['service']}:{prompt['action']}",
                    effect=Effect.ALLOW,
                    arn_scope=prompt["arn"],
                    region_scope=None,
                    note=f"answered prompt #{prompt_id} (always)",
                    origin="prompt",
                ),
                actor=actor,
            )
        elif kind == "profile":
            profs = load_profiles()
            # #226 profile-auto-naming: resolve `target` against the
            # prompt's context. If `target == _AUTO_NAME_SENTINEL` the
            # user passed `--target` with no value → suggest from the
            # prompt + TTY-or-auto. Explicit names still get
            # collision-avoided so a typo'd duplicate doesn't clobber.
            suggested = suggest_profile_name_for_prompts_answer(prompt)
            target = resolve_profile_name(
                target, suggested, taken=profs.keys(),
            )
            # If the chosen name doesn't exist, this answer CREATES a
            # new local profile (the auto-name path expects this; even
            # the explicit-name path may land here when the operator
            # typed a fresh name they intend as a new profile).
            if target not in profs:
                prof = Profile(name=target, description=(
                    f"created by `ibounce prompts answer #{prompt_id}` "
                    f"(#226 profile-auto-naming)"
                ))
            else:
                prof = profs[target]
                if prof.source != "local":
                    click.secho(
                        f"profile {target!r} is sourced from {prof.source!r} "
                        f"and is read-only", fg="red", err=True,
                    )
                    sys.exit(2)
            new_rule = ProfileAllowRule(
                pattern=f"{prompt['service']}:{prompt['action']}",
                arn_scope=prompt["arn"],
                note=f"answered prompt #{prompt_id}",
            )
            upsert_profile(Profile(
                name=prof.name,
                description=prof.description,
                deny_keywords=prof.deny_keywords,
                keyword_targets=prof.keyword_targets,
                keyword_match=prof.keyword_match,
                only_account_ids=prof.only_account_ids,
                deny_verbs=prof.deny_verbs,
                exceptions=prof.exceptions,
                allow_rules=prof.allow_rules + (new_rule,),
                source="local",
            ))
        # kind=ignore: no side effect

        # Record the answer
        ok = store.answer_pending_prompt(
            prompt_id, answer_kind=kind, answer_target=target,
            answered_by=actor,
        )
    if not ok:
        click.secho(
            f"prompt #{prompt_id}: answer not recorded (race?)",
            fg="yellow",
        )
        return

    # #203 — if this was a SYNC deny-prompt (the row carries a
    # sync_wait_id), wake the registered asyncio.Event so the
    # blocked proxy coroutine can return its decision. The wake
    # mapping: kind=always|profile -> 'allow' (forward to upstream),
    # kind=ignore -> 'deny' (return the original 403/error).
    #
    # In the typical single-process deployment (CLI + serve in the
    # same Python process), wake succeeds + the agent unblocks
    # synchronously. In a split-process deployment (CLI run from a
    # different shell than the serve daemon — common for the
    # bouncer), the registry lives in the serve process; this CLI
    # call's wake returns False + the proxy times out on its own
    # per --sync-prompt-timeout / --sync-prompt-default. The DB
    # row IS marked answered either way, so a future audit query
    # captures the operator's intent.
    sync_wait_id = prompt.get("sync_wait_id")
    if sync_wait_id:
        from .bouncer.proxy import wake_sync_pending_prompt
        sync_decision = "allow" if kind in ("always", "profile") else "deny"
        try:
            woken = wake_sync_pending_prompt(
                sync_wait_id,
                decision=sync_decision,
                answered_by=actor,
                answer_kind=kind,
            )
        except Exception as e:
            woken = False
            click.secho(
                f"sync-wake failed: {e} (proxy will timeout per its "
                f"--sync-prompt-default).",
                fg="yellow", err=True,
            )
        if not woken:
            click.echo(
                "  (no waiting proxy coroutine for this prompt — either "
                "the proxy is in a different process, or it already "
                "timed out. The answer is still recorded in the audit "
                "log.)",
                err=True,
            )

    summary = {
        "always": f"added global ALLOW rule for "
                  f"{prompt['service']}:{prompt['action']}",
        "profile": f"appended allow_rule to profile {target!r}",
        "ignore": "marked answered (no rule change)",
    }[kind]
    click.secho(f"prompt #{prompt_id} answered: {summary}", fg="green")


# ---------------------------------------------------------------------------
# #253 — `ibounce prompts bulk-answer` — burst-of-denies UX.
#
# When a wall of DENYs piles up, forcing the operator to answer each
# prompt individually is the fastest path to "uninstall the bouncer."
# Per [[safety-mode-lean-permissive]]: block-happy = uninstalled.
# This subcommand offers the 5-option interactive flow per
# [[bulk-prompt-answer-ux]]:
#   1. Switch profile (lists available)
#   2. Allow ALL (and similar) for THIS SESSION
#   3. Allow ALL for next 3 HOURS
#   4. Allow ALL for next 10 MINUTES
#   5. Leave pending (no-op)
#
# Options 2/3/4 create TIME-BOUNDED ALLOW rules (expires_at column,
# swept by the proxy's 30s background task) and mark all currently-
# pending deny-prompts as answered with kind='bulk-allow-time-bounded'.
# Option 1 hot-swaps the active profile + marks pending as answered
# with kind='profile-switch'. Option 5 is a true no-op (but still
# resets the burst detector so the operator isn't re-prompted).
#
# Per [[creates-never-mutates]]: nothing AWS-side is touched. The
# time-bounded rules expire from the active RuleSet but are PRESERVED
# in the DB so the audit chain shows what was active when.
# Per [[scorer-is-ground-truth]]: decision is deterministic; no LLM.
# Per [[security-team-positioning-safety-not-surveillance]]: every
# user-facing string is neutral.
# ---------------------------------------------------------------------------


# Time-bound mapping in SECONDS. "session" is treated as a 60-minute
# inactivity window per the issue body — long enough that a typical
# agent task doesn't get re-prompted mid-run, short enough that an
# unattended terminal doesn't keep the bypass open indefinitely. The
# "until proxy restart" half of session semantics is automatic: rules
# live in SQLite + sweep on expires_at, so a restart preserves any
# unexpired rules but the burst detector starts fresh.
_BULK_ANSWER_DURATIONS_SECONDS: dict[str, int] = {
    "session": 60 * 60,  # 60 minutes inactivity / until restart
    "3h": 3 * 60 * 60,
    "10min": 10 * 60,
}

_BULK_ANSWER_OPTION_LABELS: dict[str, str] = {
    "session": "this session (60 min inactivity / until restart)",
    "3h": "the next 3 hours",
    "10min": "the next 10 minutes",
}


def _summarize_pending_for_bulk(
    rows: list[dict[str, Any]],
) -> list[tuple[str, str, str | None]]:
    """De-duplicate pending deny-prompts down to the (service, action,
    arn) tuples we'll create ALLOW rules for. Returns the de-duped
    list in stable order so the rendered preview matches the rules
    actually applied.

    Per the issue body: bulk-allow creates rules covering "the union
    of (service, action, optional resource glob) from pending
    prompts." We take the prompt's ARN as the resource glob (NOT
    fuzzy-matched into a wildcard — operators who want a wildcard
    should answer individually with --kind always).
    """
    seen: set[tuple[str, str, str | None]] = set()
    out: list[tuple[str, str, str | None]] = []
    for r in rows:
        key = (
            str(r.get("service") or ""),
            str(r.get("action") or ""),
            r.get("arn"),
        )
        if not key[0] or not key[1]:
            # Skip unclassifiable rows — they can't be turned into a
            # rule pattern. The operator can answer those individually.
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _expires_at_iso(*, seconds_from_now: int) -> str:
    """Wall-clock UTC expiry as the canonical ISO-8601 Z string the
    store uses. Centralised so the CLI + the MCP tool produce
    identical timestamps (test parity).
    """
    import datetime as _dt
    now = _dt.datetime.now(_dt.UTC)
    return (now + _dt.timedelta(seconds=int(seconds_from_now))).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _apply_bulk_time_bounded(
    *,
    store: BouncerStore,
    pending_rows: list[dict[str, Any]],
    duration_key: str,
    actor: str,
) -> tuple[int, int, str]:
    """Create one ALLOW rule per unique (service, action, arn) from
    `pending_rows`, time-bounded per `duration_key`. Mark every row
    in `pending_rows` as answered with kind='bulk-allow-time-bounded'.

    Returns (rules_added, prompts_answered, expires_at).

    Pure function — no I/O beyond the supplied store. Called by both
    the CLI subcommand AND the MCP tool so the behavior stays
    identical across surfaces.
    """
    if duration_key not in _BULK_ANSWER_DURATIONS_SECONDS:
        raise ValueError(
            f"unknown bulk-answer duration {duration_key!r}; expected "
            f"one of: {list(_BULK_ANSWER_DURATIONS_SECONDS)}"
        )
    expires_at = _expires_at_iso(
        seconds_from_now=_BULK_ANSWER_DURATIONS_SECONDS[duration_key],
    )
    triples = _summarize_pending_for_bulk(pending_rows)
    rules_added = 0
    for service, action, arn in triples:
        rule = ProxyRule(
            pattern=f"{service}:{action}",
            effect=Effect.ALLOW,
            arn_scope=arn,
            region_scope=None,
            note=(
                f"bulk-allow time-bounded ({duration_key}); created by "
                f"`ibounce prompts bulk-answer` for burst of denies"
            ),
            origin="bulk-allow-time-bounded",
            expires_at=expires_at,
        )
        # Skip duplicates (an operator running bulk-answer twice in a
        # row shouldn't accumulate two of the same rule).
        if not store.rule_exists(rule):
            store.add_rule(rule, actor=actor)
            rules_added += 1
    # Mark every pending row answered. We use the existing answer
    # API with answer_kind='ignore' (the storage layer's enum
    # accepts only always|profile|ignore) + record the bulk context
    # in answer_target so the audit chain captures which bulk event
    # answered which row. The DB-level kind='deny-prompt' stays
    # accurate; the bulk-allow rule + the config_event row are the
    # canonical "this was a bulk-answer" trail.
    prompts_answered = 0
    for r in pending_rows:
        if r.get("status") != "pending":
            continue
        ok = store.answer_pending_prompt(
            int(r["id"]),
            answer_kind="ignore",
            answer_target=(
                f"bulk-allow-time-bounded:{duration_key}:expires_at={expires_at}"
            ),
            answered_by=actor,
        )
        if ok:
            prompts_answered += 1
    return rules_added, prompts_answered, expires_at


def _apply_bulk_profile_switch(
    *,
    store: BouncerStore,
    pending_rows: list[dict[str, Any]],
    profile_name: str,
    actor: str,
) -> tuple[Any, int]:
    """Hot-swap the active profile to `profile_name` + mark every
    currently-pending deny-prompt as answered with kind='profile-
    switch'. Returns (profile_obj, prompts_answered).

    Raises ValueError if `profile_name` doesn't exist.

    Pure function aside from the in-process profile-override singleton
    + the store writes. Called by both the CLI subcommand AND the MCP
    tool so behavior stays identical.
    """
    from .bouncer.profiles import load_profiles
    from .bouncer.proxy import set_session_profile_override

    profiles_map = load_profiles()
    if profile_name not in profiles_map:
        raise ValueError(
            f"profile {profile_name!r} not found; available: "
            f"{sorted(profiles_map.keys())}"
        )
    profile_obj = profiles_map[profile_name]
    # Install the in-process override so the very next decision uses
    # the new profile. The CLI + MCP run in the SAME process as serve()
    # for the local-only deployment shape; cross-process flip is out
    # of scope for v1.0.
    set_session_profile_override(profile_obj)
    # #278 — admin-action OCSF emit. Hot-swaps are security-relevant
    # because they change the active guardrail for every subsequent
    # request without touching the on-disk profiles. The audit event
    # records BOTH the new profile name AND the actor so a security
    # team can answer "who switched us off the staging profile."
    _enqueue_admin_action(
        store,
        kind="profile.swap",
        target_kind="profile",
        target_id=profile_name,
        target_extra={
            "pending_prompts_at_swap": len(pending_rows),
        },
        after={"profile_name": profile_name},
    )
    prompts_answered = 0
    for r in pending_rows:
        if r.get("status") != "pending":
            continue
        ok = store.answer_pending_prompt(
            int(r["id"]),
            answer_kind="ignore",
            answer_target=f"profile-switch:{profile_name}",
            answered_by=actor,
        )
        if ok:
            prompts_answered += 1
    return profile_obj, prompts_answered


@prompts_group.command("bulk-answer")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.option(
    "--non-interactive", is_flag=True, default=False,
    help="Refuse to run when stdin/stdout is not a TTY. Defaults off; "
         "the subcommand auto-detects TTY at runtime + errors if "
         "neither --decision nor --profile is supplied non-interactively.",
)
@click.option(
    "--decision",
    type=click.Choice(
        ["profile", "session", "3h", "10min", "none"], case_sensitive=False,
    ),
    default=None,
    help="Skip the interactive prompt + apply this decision directly. "
         "`profile` requires --profile NAME. `session`/`3h`/`10min` "
         "create a time-bounded ALLOW rule covering the pending prompts. "
         "`none` is a no-op (resets the burst detector + exits).",
)
@click.option(
    "--profile", "profile_name", default=None,
    help="With --decision profile: the profile name to switch to. "
         "Ignored otherwise.",
)
def prompts_bulk_answer_cmd(
    db: str | None,
    non_interactive: bool,
    decision: str | None,
    profile_name: str | None,
) -> None:
    """Handle a burst of pending DENY prompts with ONE choice.

    \b
    Per [[bulk-prompt-answer-ux]] the 5 options are:
      1. Switch profile to one with broader scope
      2. Allow ALL (and similar) for THIS SESSION (60 min inactivity)
      3. Allow ALL for the next 3 HOURS
      4. Allow ALL for the next 10 MINUTES
      5. Leave pending; answer individually

    Options 2-4 create TIME-BOUNDED ALLOW rules (expires_at column;
    swept on a 30s tick). Per [[creates-never-mutates]] expired rules
    are PRESERVED in the DB for audit, just removed from the active
    RuleSet.

    Per [[security-team-positioning-safety-not-surveillance]] all
    strings are neutral. The burst is framed as "your task probably
    needs a broader scope," NOT "policy violations detected."

    TTY only by default; --non-interactive errors out unless --decision
    is supplied.
    """
    from .bouncer.burst import active_burst_detector
    from .bouncer.profiles import load_profiles

    actor = _current_actor()
    is_tty = sys.stdin.isatty() and sys.stdout.isatty()

    with _opened_store(db) as store:
        pending = store.list_pending_prompts(
            status="pending", kind="deny-prompt", limit=500,
        )
        if not pending:
            click.echo("(no pending deny-prompts to bulk-answer)")
            # Still reset the burst detector — operator looked at the
            # queue, that's their acknowledgement.
            d = active_burst_detector()
            if d is not None:
                d.reset()
            return

        # Render the burst header — neutral language per
        # [[security-team-positioning-safety-not-surveillance]].
        detector = active_burst_detector()
        hint = detector.pending_hint() if detector is not None else None
        if hint is not None:
            click.echo(
                f"{len(pending)} pending prompts accumulated in the last "
                f"{hint['oldest_pending_seconds_ago']}s. "
                f"Your task probably needs a broader scope.",
                err=True,
            )
        else:
            click.echo(
                f"{len(pending)} pending prompts accumulated. Your "
                f"task probably needs a broader scope.",
                err=True,
            )

        # Branch: explicit --decision skips the prompt entirely
        if decision is not None:
            choice_key = decision.lower()
        else:
            if non_interactive or not is_tty:
                click.secho(
                    "prompts bulk-answer: TTY required (and "
                    "--non-interactive was passed OR no terminal "
                    "attached). Re-run interactively, or pass "
                    "--decision {profile|session|3h|10min|none} "
                    "(with --profile NAME for profile).",
                    fg="red", err=True,
                )
                sys.exit(2)
            # Interactive 5-option prompt.
            profiles_map = load_profiles()
            available_profiles = sorted(profiles_map.keys())
            click.echo("")
            click.echo("How would you like to handle them?")
            click.echo("")
            click.echo("  1. Switch profile to one with broader scope")
            if available_profiles:
                click.echo(
                    f"     (available: {', '.join(available_profiles[:6])}"
                    + (", ..." if len(available_profiles) > 6 else "")
                    + ")",
                )
            click.echo(
                "  2. Allow ALL of these (and similar) for this session"
            )
            click.echo("  3. Allow ALL for the next 3 hours")
            click.echo("  4. Allow ALL for the next 10 minutes")
            click.echo(
                "  5. Leave pending; I'll answer individually"
            )
            click.echo("")
            sel = click.prompt(
                "  ? [1-5]", type=click.IntRange(1, 5), default=5,
            )
            choice_map = {
                1: "profile", 2: "session", 3: "3h", 4: "10min", 5: "none",
            }
            choice_key = choice_map[int(sel)]

        # Dispatch
        if choice_key == "none":
            click.echo(
                "  no change. Burst detector reset; answer individually "
                "via `ibounce prompts answer` to clear the queue.",
            )
            if detector is not None:
                detector.reset()
            return

        if choice_key == "profile":
            if not profile_name and is_tty and decision is None:
                profiles_map = load_profiles()
                available = sorted(profiles_map.keys())
                if not available:
                    click.secho(
                        "no profiles available; install one with "
                        "`ibounce profile install` first.",
                        fg="red", err=True,
                    )
                    sys.exit(2)
                click.echo("  available profiles:")
                for i, name in enumerate(available, start=1):
                    click.echo(f"    {i}. {name}")
                profile_idx = click.prompt(
                    "  pick profile [1-{}]".format(len(available)),
                    type=click.IntRange(1, len(available)),
                    default=1,
                )
                profile_name = available[int(profile_idx) - 1]
            if not profile_name:
                click.secho(
                    "--decision profile requires --profile NAME "
                    "(non-interactive).", fg="red", err=True,
                )
                sys.exit(2)
            try:
                profile_obj, answered = _apply_bulk_profile_switch(
                    store=store,
                    pending_rows=pending,
                    profile_name=profile_name,
                    actor=actor,
                )
            except ValueError as e:
                click.secho(str(e), fg="red", err=True)
                sys.exit(2)
            if detector is not None:
                detector.reset()
            click.secho(
                f"switched active profile to {profile_obj.name!r}; "
                f"answered {answered} pending prompt(s) "
                f"(kind=profile-switch).",
                fg="green",
            )
            return

        # Time-bounded bulk allow (session / 3h / 10min)
        rules_added, answered, expires_at = _apply_bulk_time_bounded(
            store=store,
            pending_rows=pending,
            duration_key=choice_key,
            actor=actor,
        )
        if detector is not None:
            detector.reset()
        label = _BULK_ANSWER_OPTION_LABELS[choice_key]
        click.secho(
            f"allowed {rules_added} (service, action) shape(s) for {label}; "
            f"answered {answered} pending prompt(s). "
            f"Rules expire at {expires_at} and are preserved in the DB "
            f"for audit per creates-never-mutates.",
            fg="green",
        )


@main.group("pause")
def pause_group() -> None:
    """Timed escape hatch — temporarily demote the proxy to advisory
    (cooperative) mode for a window. The proxy keeps observing +
    logging every call (the decisions audit row links to the pause
    id so reviewers can ask "what happened inside that window?"),
    but DENY verdicts no longer return 403 to the client. Auto-
    reverts at expiry; resume early with `pause stop`.

    Use this when you NEED to do something the rules don't permit
    and editing rules would take longer than the work. Per the
    safety-mode-lean-permissive memo: this is the friendlier
    middle ground between "Ctrl-C the proxy" and "redo my rules."
    """


@pause_group.command("start")
@click.option("--for", "duration", required=True, metavar="DURATION",
              help="How long to pause. Format: '30m' / '2h' / '90s'. "
                   "Max 24h (longer windows are an 'I don't want the "
                   "proxy' signal — just stop the daemon instead).")
@click.option("--reason", default="",
              help="One-line reason recorded in the pause audit row + "
                   "shown on /healthz. e.g. 'incident response' / "
                   "'one-off bucket cleanup' / 'cluster migration'.")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def pause_start_cmd(duration: str, reason: str, db: str | None) -> None:
    """Open a new pause window."""
    seconds = _parse_duration(duration)
    actor = _current_actor()
    with _opened_store(db) as store:
        try:
            pid = store.start_pause(
                duration_seconds=seconds, reason=reason, started_by=actor,
            )
        except ValueError as e:
            click.secho(f"pause refused: {e}", fg="red", err=True)
            sys.exit(2)
        active = store.get_active_pause()
        # #278 — admin-action OCSF emit. The reason field is included
        # under target_extra because a security team that sees
        # "pause.start fired with reason=incident-response" can decide
        # whether to dig in vs. ignore.
        _enqueue_admin_action(
            store,
            kind="pause.start",
            target_kind="pause_window",
            target_id=f"#{pid}",
            target_extra={
                "duration_seconds": seconds,
                "reason": reason or "",
            },
            after={
                "pause_id": pid,
                "duration_seconds": seconds,
                "reason": reason,
                "started_by": actor,
            },
        )
    assert active is not None
    click.secho(
        f"pause #{pid} active — proxy is COOPERATIVE for the next "
        f"{duration} (ends at {active['ends_at']}).",
        fg="yellow",
    )
    click.echo("Every call during this window is still recorded in the "
               "decisions audit log with pause_id linkage.")
    click.echo("Run `ibounce pause stop` to end early.")


@pause_group.command("stop")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def pause_stop_cmd(db: str | None) -> None:
    """End the currently-active pause (if any)."""
    actor = _current_actor()
    with _opened_store(db) as store:
        pid = store.end_pause(ended_by=actor)
        if pid is not None:
            # #278 — admin-action OCSF emit. Distinct from the
            # existing PAUSE_END synthetic (which drives the pause_long
            # alert): this one is the "who closed the pause window"
            # config-change row.
            _enqueue_admin_action(
                store,
                kind="pause.stop",
                target_kind="pause_window",
                target_id=f"#{pid}",
                target_extra={"ended_by": actor},
                before={"pause_id": pid},
                after=None,
            )
    if pid is None:
        click.echo("no pause is currently active.")
        return
    click.secho(f"pause #{pid} ended early.", fg="green")


@pause_group.command("status")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def pause_status_cmd(db: str | None) -> None:
    """Show the current pause window, if any."""
    with _opened_store(db) as store:
        active = store.get_active_pause()
    if active is None:
        click.echo("no pause active. Proxy enforces per configured mode.")
        return
    click.secho(
        f"pause #{active['id']} ACTIVE "
        f"(started {active['started_at']}, ends {active['ends_at']}, "
        f"by {active['started_by']})",
        fg="yellow",
    )
    if active["reason"]:
        click.echo(f"  reason: {active['reason']}")


@pause_group.command("history")
@click.option("--limit", type=int, default=20, show_default=True)
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def pause_history_cmd(limit: int, db: str | None) -> None:
    """Show recent pause windows for audit review."""
    with _opened_store(db) as store:
        rows = store.list_recent_pauses(limit=limit)
    if not rows:
        click.echo("(no pauses recorded)")
        return
    for r in rows:
        end_kind = r["end_kind"] or "(still active)"
        ended = r["ended_at_actual"] or "(open)"
        click.echo(
            f"#{r['id']}  started={r['started_at']}  "
            f"ends_at={r['ends_at']}  actual_end={ended}  "
            f"kind={end_kind}  by={r['started_by']}"
        )
        if r["reason"]:
            click.echo(f"   reason: {r['reason']}")


def _parse_duration(raw: str) -> int:
    """Parse '30m' / '2h' / '90s' / '30d' into seconds.

    Picks suffix-based parsing rather than something like ISO 8601
    durations because operators tend to type `30m`, not `PT30M`. The
    `d` suffix is here because #285 session-recording retention runs in
    days, not hours; we expose it here so every duration-taking surface
    shares the same parser."""
    if not raw:
        raise click.BadParameter("duration is required")
    s = raw.strip().lower()
    suffix_map = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if s[-1] not in suffix_map:
        raise click.BadParameter(
            f"duration {raw!r}: must end in s/m/h/d (e.g. 30m, 2h, 90s, 7d)"
        )
    try:
        n = int(s[:-1])
    except ValueError as e:
        raise click.BadParameter(
            f"duration {raw!r}: prefix must be an integer count"
        ) from e
    if n <= 0:
        raise click.BadParameter(f"duration {raw!r}: must be > 0")
    return n * suffix_map[s[-1]]


@main.command("run")
@click.option(
    "--port", type=int, default=8767, show_default=True,
    help="TCP port to listen on (loopback only).",
)
@click.option(
    "--host", default="127.0.0.1", show_default=True,
    help="Interface to bind. Defaults to 127.0.0.1 (loopback). "
         "Binding to anything else exposes a credential-handling "
         "surface to the network — refused unless you also pass "
         "--i-know-this-binds-externally. CRIT-32-02 closure.",
)
@click.option(
    "--i-know-this-binds-externally", "force_external_bind", is_flag=True,
    default=False,
    help="Required acknowledgement when --host is anything other than "
         "127.0.0.1 / ::1 / localhost. Binding the bouncer externally "
         "exposes a credential-handling surface; combined with the "
         "exfil-vector this would be unrecoverable. Don't pass this "
         "flag unless you have read the SECURITY.md threat model + "
         "have a specific reason (e.g. dedicated test VM with no "
         "real credentials).",
)
@click.option(
    "--upstream",
    "upstream_url",
    default=None,
    help="#300 — point ibounce at a non-AWS upstream (LocalStack, "
         "moto, custom mock-AWS). Format: 'http://HOST:PORT' or "
         "'https://HOST:PORT'. The scheme of this URL drives outbound "
         "TLS choice (http vs https); the host:port becomes the "
         "forward target instead of the inbound SigV4-signed Host "
         "header. Example: --upstream http://127.0.0.1:4566 (LocalStack "
         "default). Schemeless URLs + non-http(s) schemes (ftp://, "
         "file://) are rejected at startup. Leave unset to forward to "
         "real AWS (the SigV4-signed Host header, https).",
)
@click.option(
    "--prompt-on-deny", is_flag=True, default=False,
    help="Enqueue every transparent-mode DENY in the pending-prompts "
         "queue so the operator can later answer via `bouncer prompts "
         "answer ID --kind always|profile|ignore`. Async — agent gets "
         "denied immediately, answer takes effect on the NEXT call. "
         "Mutually exclusive with --sync-prompt-on-deny.",
)
@click.option(
    "--sync-prompt-on-deny", "sync_prompt_on_deny",
    is_flag=True, default=False,
    help="#203 v1.1 — synchronous deny-prompt UX. Like "
         "--prompt-on-deny, except the proxy BLOCKS the request for "
         "up to --sync-prompt-timeout seconds awaiting the operator's "
         "answer. Answer kind=always|profile → request is forwarded "
         "to upstream + upstream's actual response is returned. "
         "Answer kind=ignore (deny) OR timeout → original 403/error "
         "is returned. Only fires in --mode transparent + no active "
         "pause. Mutually exclusive with --prompt-on-deny.",
)
@click.option(
    "--sync-prompt-timeout", "sync_prompt_timeout",
    type=click.IntRange(5, 300), default=30, show_default=True,
    help="#203 — seconds the proxy will block on a sync deny-prompt "
         "before applying --sync-prompt-default. Range 5..300. Only "
         "meaningful with --sync-prompt-on-deny.",
)
@click.option(
    "--sync-prompt-default", "sync_prompt_default",
    type=click.Choice(["allow", "deny"], case_sensitive=False),
    default="deny", show_default=True,
    help="#203 — decision applied when --sync-prompt-timeout fires "
         "without an operator answer. `deny` matches the fail-closed "
         "default; `allow` is fail-open for operators who'd rather "
         "let the call through than block agent progress when they "
         "step away from the terminal.",
)
@click.option(
    "--mode",
    type=click.Choice(
        ["cooperative", "transparent", "plan-capture"], case_sensitive=False,
    ),
    default="cooperative",
    show_default=True,
    help="cooperative: every call is parsed + verdict logged but "
         "always forwarded (advisory). transparent: DENY verdicts "
         "return 403 to the SDK client (enforcement). plan-capture "
         "(#132): every call is parsed + audited + returned with a "
         "synthetic SDK-shaped success — NEVER forwarded to AWS, "
         "so the operator gets a recorded call graph the agent "
         "intended to make ('terraform plan' for any AWS-touching "
         "agent task). Pick cooperative for solo-dev iteration "
         "speed; transparent for locked-down environments; "
         "plan-capture to preview an agent flow before any state "
         "change. Switch later by restarting with the other flag.",
)
@click.option(
    "--plan-session-id",
    "plan_session_id",
    default=None,
    help="Plan-capture session id to APPEND calls to. Only meaningful "
         "with --mode plan-capture. Omit to mint a fresh "
         "`plan-YYYYMMDDTHHMMSSZ-...` id at startup (the recommended "
         "default — every serve() invocation gets its own session).",
)
@click.option(
    "--write-switch-notify",
    "write_switch_notify",
    type=click.Choice(["manual", "auto-approve", "reject"], case_sensitive=False),
    default="manual",
    show_default=True,
    help="#145 read->write switch UX (plan-capture mode only). "
         "Configures what happens on the FIRST write call in the "
         "session: manual enqueues a plan-write prompt for the "
         "operator (answer via `ibounce prompts answer ID "
         "--kind plan-write --decision approve|reject`; write still "
         "gets synthetic success either way); auto-approve flips "
         "the session to writes_approved silently; reject flips to "
         "writes_rejected so subsequent writes get a typed "
         "PlanCaptureWritesRejected synthetic error. Per "
         "[[ibounce-honest-positioning]] this is a deterrent UX "
         "helper; plan-capture's actual safety property "
         "(never-forward) is identical across the three settings.",
)
@click.option(
    "--default-policy",
    type=click.Choice(["allow", "deny"], case_sensitive=False),
    default="deny",
    show_default=True,
    help="What happens in TRANSPARENT mode when no rule matches.",
)
@click.option(
    "--profile",
    "profile_name",
    default=None,
    help="Active environment profile name (per Slice 7). Falls back to "
         "IAM_JIT_BOUNCER_PROFILE env var, then 'none'. Profile denies "
         "are a hard floor and CANNOT be overridden by task scopes or "
         "global rules. Example: --profile staging-work blocks any "
         "resource whose ARN matches 'prod' / 'uat' / 'production' "
         "keywords even with admin credentials. Run `ibounce "
         "profile list` to see available profiles.",
)
@click.option(
    "--account-id",
    "account_id_flag",
    default=None,
    help="Override the account-id surfaced to profile rules. Useful "
         "when the proxy can't infer the account from the request.",
)
@click.option(
    "--account-alias",
    "account_alias_flag",
    default=None,
    help="Override the account-alias surfaced to profile rules. "
         "Keyword targets that include 'account_alias' match this.",
)
@click.option(
    "--audit-log-path",
    "audit_log_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="#252 Slice 1 (FREE tier) — JSONL audit log destination. One "
         "JSON object per line; append-only (no rotation built-in — "
         "point logrotate / Fluent Bit / Vector at the file). Every "
         "proxy decision is mirrored here in addition to the existing "
         "SQLite audit log. Unset = no JSONL export.",
)
@click.option(
    "--audit-log-fsync",
    "audit_log_fsync",
    is_flag=True, default=False,
    help="#252 — fsync the JSONL log after every write. Off by default "
         "for throughput (events sit in the page cache + survive a "
         "process crash but NOT a kernel/host crash). On for compliance-"
         "grade durability where every event must hit disk before the "
         "next decision is recorded. Trade-off: ~10x slower per write "
         "on rotational media; ~2x on consumer SSD.",
)
@click.option(
    "--audit-log-max-size-mb",
    "audit_log_max_size_mb",
    type=click.IntRange(0, 100_000),
    default=None,
    envvar="IBOUNCE_AUDIT_LOG_MAX_SIZE_MB",
    help="#311 / §A10 — rotate the JSONL audit log when it exceeds N MB. "
         "0 disables size-triggered rotation. Default 100 (matches the "
         "cross-product LOG-RETENTION.md spec). Rotated files are gzip'd "
         "into the same dir with a timestamp suffix and remain until an "
         "explicit `ibounce logs purge` reaps them (per [[creates-never-"
         "mutates]] the active log is never destroyed by automatic paths). "
         "Honors $IBOUNCE_AUDIT_LOG_MAX_SIZE_MB for non-flag overrides.",
)
@click.option(
    "--audit-log-max-age-days",
    "audit_log_max_age_days",
    type=click.IntRange(0, 36_500),
    default=None,
    envvar="IBOUNCE_AUDIT_LOG_MAX_AGE_DAYS",
    help="#311 / §A10 — rotate the JSONL audit log when its mtime is "
         "older than N days. 0 disables age-triggered rotation. Default 7 "
         "(matches the cross-product LOG-RETENTION.md spec). Pairs with "
         "--audit-log-max-size-mb; whichever trigger fires first wins. "
         "Honors $IBOUNCE_AUDIT_LOG_MAX_AGE_DAYS for non-flag overrides.",
)
@click.option(
    "--audit-db-retention-days",
    "audit_db_retention_days",
    type=click.IntRange(0, 36_500),
    default=None,
    envvar="IBOUNCE_AUDIT_DB_RETENTION_DAYS",
    help="#311 / §A10 — purge rotated SQLite audit DB archives older "
         "than N days. 0 disables DB retention. Default 30 (matches the "
         "cross-product LOG-RETENTION.md spec). Active `audit.db` is "
         "NEVER deleted by this path; only rotated `audit-*.db.gz` "
         "archives are eligible. Honors $IBOUNCE_AUDIT_DB_RETENTION_DAYS "
         "for non-flag overrides.",
)
@click.option(
    "--record-sessions-dir",
    "record_sessions_dir",
    type=click.Path(file_okay=False),
    default=None,
    help="#285 — per-session NDJSON recording directory. When set, "
         "every audit event is also written to "
         "`{dir}/{agent.session_id}.ndjson` (one file per agent "
         "session). Replayable via `iam-jit session replay <FILE>`. "
         "File mode 0o600. Default off; the recorder captures agent "
         "identity + operation details so it ships opt-in.",
)
@click.option(
    "--audit-webhook-url",
    "audit_webhook_url",
    default=None,
    help="#252 Slice 1 (ENTERPRISE tier — license-gated) — HTTPS URL of "
         "your audit collector. Every proxy decision is POSTed as NDJSON "
         "(matches the JSONL log channel). Bounded queue (1000); "
         "exponential-backoff retry (1s -> 32s, max 5 attempts); "
         "drop + AUDIT_DROPPED synthetic event on overflow. Per "
         "[[no-hosted-saas]] iam-jit-the-company NEVER receives this "
         "traffic; the customer's URL only. Requires --audit-webhook-token.",
)
@click.option(
    "--audit-webhook-token",
    "audit_webhook_token",
    default=None,
    help="#252 — Bearer token sent as 'Authorization: Bearer <token>'. "
         "NEVER logged. Masked as '***' in /healthz, startup banner, and "
         "error messages. Set via env var (IAM_JIT_BOUNCER_AUDIT_WEBHOOK_"
         "TOKEN) or a shell-escaped flag value; avoid putting the literal "
         "in shell history.",
)
@click.option(
    "--audit-webhook-batch-size",
    "audit_webhook_batch_size",
    type=click.IntRange(1, 1000), default=1, show_default=True,
    help="#252 — events per HTTP POST. Default 1 sends every decision "
         "individually (lowest latency, highest request rate). Raise for "
         "high-throughput orgs that prefer fewer, larger requests against "
         "the collector.",
)
@click.option(
    "--allow-internal-webhook",
    "audit_webhook_allow_internal",
    is_flag=True, default=False,
    help="#252 — opt-out of the SSRF gate that refuses webhook URLs "
         "resolving to RFC1918 / loopback / .internal / .local hosts. "
         "Required when shipping to an intranet collector on a trusted "
         "network segment. The token is still sent — make sure the "
         "segment is trusted.",
)
@click.option(
    "--audit-webhook-preset",
    "audit_webhook_preset",
    type=click.Choice(
        ["generic", "datadog", "splunk-hec", "sentinel"],
        case_sensitive=False,
    ),
    default="generic", show_default=True,
    help="#257 — webhook body/headers shape. `generic` (default) is "
         "byte-identical to the pre-#257 wire format (Bearer + NDJSON). "
         "`datadog` uses DD-API-KEY + Datadog-overlay fields (service, "
         "ddsource, ddtags, status, message). `splunk-hec` uses "
         "`Authorization: Splunk <token>` + event-wrapped NDJSON. "
         "`sentinel` uses HMAC-SHA256 SharedKey auth for Microsoft "
         "Sentinel / Log Analytics Workspace ingest. Operator picks "
         "explicitly — no autodetection from URL (per "
         "[[audit-webhook-presets]]: silent miswires cause incidents).",
)
@click.option(
    "--audit-webhook-tags",
    "audit_webhook_tags",
    default="", show_default=False,
    help="#257 — extra tags appended to Datadog `ddtags` "
         "(format: `key:value,key:value`). The default tags "
         "`product:iam-jit,bouncer:ibounce` are always sent. Ignored "
         "by `generic` / `splunk-hec` / `sentinel` presets.",
)
@click.option(
    "--audit-webhook-sentinel-table",
    "audit_webhook_sentinel_table",
    default="IamJitBouncer", show_default=True,
    help="#257 — name of the Microsoft Sentinel Log Analytics custom "
         "table that the events land in. Sent as the `Log-Type` "
         "header on the Sentinel ingest request. Ignored by other "
         "presets.",
)
@click.option(
    "--security-lake-bucket",
    "security_lake_bucket",
    default=None,
    help="#258 — name of the operator-owned S3 bucket that AWS "
         "Security Lake auto-ingests from. When set, every OCSF event "
         "is also written as a parquet file at "
         "`s3://<bucket>/region=<r>/eventday=<YYYYMMDD>/eventhour=<HH>/"
         "api_activity-<unix-ms>.parquet`. Per [[no-hosted-saas]] the "
         "bucket lives in the operator's AWS account; iam-jit-the-"
         "company never receives the data. Requires "
         "--security-lake-region; honours --security-lake-role-arn if "
         "set otherwise uses the default AWS credential chain.",
)
@click.option(
    "--security-lake-region",
    "security_lake_region",
    default=None,
    help="#258 — AWS region the Security Lake bucket lives in. Required "
         "when --security-lake-bucket is set. Becomes the `region=<r>` "
         "partition key on every parquet file.",
)
@click.option(
    "--security-lake-role-arn",
    "security_lake_role_arn",
    default=None,
    help="#258 — optional IAM role to assume for Security Lake writes "
         "(STS AssumeRole). When unset the default boto3 credential "
         "chain is used (env / shared-config / instance role). "
         "Recommended for cross-account Security Lake deployments where "
         "the bucket lives in a dedicated security account.",
)
@click.option(
    "--security-lake-rotation-seconds",
    "security_lake_rotation_seconds",
    type=click.IntRange(1, 3600), default=300, show_default=True,
    help="#258 — how often the in-memory parquet batch flushes to S3. "
         "Default 300 (5 minutes) matches the Security Lake custom-"
         "source ingest cadence. Lower values mean smaller files + "
         "faster Security Lake visibility; higher values mean fewer / "
         "larger files (better Athena scan efficiency). A 10 MiB size "
         "cap also forces a flush, whichever fires first.",
)
# #317 — cloud-neutral S3-compatible NDJSON object-storage sink.
# All fields OFF by default. Per [[self-host-zero-billing-dependency]]
# the bucket is operator-owned; iam-jit-the-company never receives
# the data. Per [[don't-tailor-to-lighthouse]]: generic S3-compat;
# works with AWS S3, GCS interop, Azure Blob S3-compat layer, MinIO,
# R2, B2, DigitalOcean Spaces, etc.
@click.option(
    "--audit-object-storage-endpoint",
    "audit_object_storage_endpoint",
    default=None,
    help="#317 — S3 API endpoint URL. Required when "
         "--audit-object-storage-bucket is set. Examples: "
         "https://s3.us-east-1.amazonaws.com (AWS S3); "
         "https://<accountid>.r2.cloudflarestorage.com (Cloudflare R2); "
         "https://minio.internal:9000 (MinIO); "
         "https://storage.googleapis.com (GCS interop with HMAC keys); "
         "https://s3.us-west-002.backblazeb2.com (Backblaze B2); "
         "https://nyc3.digitaloceanspaces.com (DigitalOcean Spaces).",
)
@click.option(
    "--audit-object-storage-bucket",
    "audit_object_storage_bucket",
    default=None,
    help="#317 — name of the operator-owned bucket the writer appends "
         "NDJSON files into. Operator creates the bucket; ibounce "
         "NEVER creates buckets. When set, every OCSF event is also "
         "written as a gzip-compressed NDJSON line into "
         "`{prefix}/year=YYYY/month=MM/day=DD/hour=HH/"
         "ibounce-{instance_id}-{timestamp}.jsonl.gz`. Hive-style "
         "partitioning lets Athena / BigQuery / Spark / Trino query "
         "the bucket directly; collectors do LIST + GET against the "
         "prefix at predictable cadence.",
)
@click.option(
    "--audit-object-storage-prefix",
    "audit_object_storage_prefix",
    default="", show_default=True,
    help="#317 — key prefix inside the bucket (e.g. "
         "`bounce-audit/prod`). Empty = bucket root. Hive partition "
         "directories are appended under the prefix.",
)
@click.option(
    "--audit-object-storage-region",
    "audit_object_storage_region",
    default="us-east-1", show_default=True,
    help="#317 — region for the SigV4 signature. AWS S3: real region "
         "(`us-east-1`, `eu-west-1`, ...). Cloudflare R2: `auto`. "
         "MinIO / vendor-specific: pick whatever the vendor docs say.",
)
@click.option(
    "--audit-object-storage-credentials-file",
    "audit_object_storage_credentials_file",
    type=click.Path(dir_okay=False),
    default=None,
    help="#317 — optional explicit credentials file (overrides env "
         "vars). YAML or INI shape with keys `access_key_id`, "
         "`secret_access_key`, optional `session_token`. When absent, "
         "reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / "
         "AWS_SESSION_TOKEN env vars.",
)
@click.option(
    "--audit-object-storage-rotation-minutes",
    "audit_object_storage_rotation_minutes",
    type=click.IntRange(1, 1440), default=5, show_default=True,
    help="#317 — rotate the active NDJSON file when N minutes elapse "
         "OR --audit-object-storage-max-size-mb fires, whichever "
         "first. Lower values mean smaller files + faster collector "
         "visibility; higher values mean fewer / larger files (better "
         "scan efficiency for Athena / BigQuery).",
)
@click.option(
    "--audit-object-storage-max-size-mb",
    "audit_object_storage_max_size_mb",
    type=click.IntRange(1, 1024), default=16, show_default=True,
    help="#317 — rotate the active NDJSON file when its in-memory "
         "size estimate crosses N megabytes. Default 16. Works "
         "together with --audit-object-storage-rotation-minutes; "
         "whichever cap fires first triggers a flush.",
)
@click.option(
    "--audit-object-storage-instance-id",
    "audit_object_storage_instance_id",
    default=None,
    help="#317 — override the auto-generated instance identifier "
         "(hostname-pid) used in the object key. Useful for "
         "operators with ephemeral hostnames (containers / k8s "
         "pods) who want the path stable across restarts.",
)
@click.option(
    "--alert-rules",
    "alert_rules_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="#262 Slice 2 (ENTERPRISE tier — license-gated) — YAML file "
         "configuring the suspicious-activity alert engine. Ships 5 "
         "built-in deterministic rules (admin_fallback_burst, "
         "pause_long, non_org_profile_install, "
         "unusual_high_risk_action, heartbeat_gap) over the existing "
         "audit-export transport (JSONL + webhook). Pass the literal "
         "string 'defaults' (or an empty path string) to enable all "
         "five built-ins with sensible thresholds. Per "
         "[[security-team-positioning-safety-not-surveillance]] alerts "
         "use NEUTRAL language; never frames a match as a violation.",
)
@click.option(
    "--alert-routes",
    "alert_routes_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="#280 (ENTERPRISE tier — license-gated) — YAML file describing "
         "per-org notification routing. When set, the multi-destination "
         "routing engine activates: each event is matched against the "
         "configured routes' match blocks + dispatched to the route's "
         "destinations (webhook / pagerduty / slack). When unset, the "
         "existing single-webhook --audit-webhook-url path stays exactly "
         "as today (zero regression). Secrets must use ${ENV_VAR} "
         "interpolation; literal tokens in the YAML are refused. Use "
         "`ibounce config preview-routes` to dry-run a sample event "
         "against the file before deploying. Setting BOTH --alert-routes "
         "and --audit-webhook-url ignores the latter (with a warning).",
)
@click.option(
    "--heartbeat-interval",
    "heartbeat_interval_seconds",
    type=click.IntRange(0, 3600), default=0, show_default=True,
    help="#264 — emit an OCSF activity_id=99 'heartbeat' event every "
         "N seconds through the audit-export channels (JSONL + "
         "webhook). 0 = OFF (default; zero phone-home preserved). "
         "Recommended 30 for Enterprise deployments. Per "
         "[[prompt-injection-disable-bouncer-threat]]: a prompt-"
         "injected agent can `pkill ibounce` to disable the proxy; "
         "heartbeats make that DETECTABLE downstream (a SIEM watching "
         "the audit stream sees the silence). Heartbeats themselves "
         "ship on every tier; the heartbeat_gap rule that fires on "
         "missed beats rides the Enterprise-gated alert engine.",
)
@click.option(
    "--alert-heartbeat-missing-count",
    "alert_heartbeat_missing_count",
    type=click.IntRange(1, 100), default=2, show_default=True,
    help="#264 — heartbeat_gap rule threshold. Fire after this many "
         "consecutive missed heartbeats (where 'missed' = elapsed "
         "time since last heartbeat > interval * count). Default 2 "
         "catches one missed beat + the detection scan that follows. "
         "Raise for noisy networks where the occasional missed beat "
         "is normal. Only meaningful when --heartbeat-interval > 0; "
         "/healthz uses the same threshold to flip to 503.",
)
@click.option(
    "--burst-threshold",
    "burst_threshold",
    type=click.IntRange(1, 1000), default=5, show_default=True,
    help="#253 — pending-prompt count over --burst-window that fires "
         "BURST_DETECTED + the pre-burst hint. Default 5 catches the "
         "block-happy failure mode early per [[safety-mode-lean-"
         "permissive]]. Raise for environments where occasional "
         "flurries are expected.",
)
@click.option(
    "--burst-window",
    "burst_window_seconds",
    type=click.IntRange(1, 3600), default=60, show_default=True,
    help="#253 — sliding window (in seconds) the burst detector "
         "counts over. Default 60s covers the typical SDK retry-loop "
         "(3-5 retries ~ 30-60s). Range 1..3600.",
)
@click.option(
    "--bulk-answer-mcp-token",
    "bulk_answer_mcp_token",
    default=None,
    help="#253 — operator-set token that ENABLES the "
         "`bouncer_prompts_bulk_answer` MCP tool. DEFAULT DISABLED: "
         "without this flag, every MCP bulk-answer call returns an "
         "error explaining how to enable. When set, the agent must "
         "echo the exact token on every call. Constant-time compare. "
         "Per [[bulk-prompt-answer-ux]]'s 'Don't' list: prevents an "
         "adversarial agent from bulk-allowing itself out of every "
         "pending prompt. Share the token out-of-band with your agent "
         "(paste into prompt window manually); do NOT put it in env "
         "vars an agent can read.",
)
@click.option(
    "--audit-events-token",
    "audit_events_token",
    default=None,
    help="#271 — bearer token required for GET /audit/events when the "
         "proxy is bound externally. Empty + loopback bind (the "
         "default) = no auth required (the loopback bind is the trust "
         "anchor). Empty + external bind = ibounce refuses to start. "
         "When set, callers must send `Authorization: Bearer <token>`. "
         "Powers the cross-bouncer `iam-jit audit query` CLI that fans "
         "queries across every reachable bouncer in parallel.",
)
@click.option(
    "--preset",
    "deployment_preset",
    type=click.Choice(["security-observe"], case_sensitive=False),
    default=None,
    help="#254 — single-flag shortcut for a common deployment shape. "
         "security-observe = transparent mode + JSONL audit + alert rules "
         "(defaults) + 30s heartbeat. Designed for the security-team "
         "'gather data first; author profile second' starting shape per "
         "[[bouncer-mode-selection-for-agents]]. Some preset values are "
         "HARD (e.g. --mode for security-observe — the entire point of "
         "the preset is transparent); passing them with a different value "
         "is an error. Others are SOFT (e.g. --audit-log-path); the "
         "operator's value wins. Startup banner shows which settings are "
         "derived from the preset.",
)
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.pass_context
def run_cmd(
    ctx: click.Context,
    port: int, host: str, force_external_bind: bool,
    upstream_url: str | None,
    prompt_on_deny: bool,
    sync_prompt_on_deny: bool,
    sync_prompt_timeout: int,
    sync_prompt_default: str,
    mode: str, plan_session_id: str | None,
    write_switch_notify: str,
    default_policy: str,
    profile_name: str | None,
    account_id_flag: str | None,
    account_alias_flag: str | None,
    audit_log_path: str | None,
    audit_log_fsync: bool,
    audit_log_max_size_mb: int | None,
    audit_log_max_age_days: int | None,
    audit_db_retention_days: int | None,
    record_sessions_dir: str | None,
    audit_webhook_url: str | None,
    audit_webhook_token: str | None,
    audit_webhook_batch_size: int,
    audit_webhook_allow_internal: bool,
    audit_webhook_preset: str,
    audit_webhook_tags: str,
    audit_webhook_sentinel_table: str,
    security_lake_bucket: str | None,
    security_lake_region: str | None,
    security_lake_role_arn: str | None,
    security_lake_rotation_seconds: int,
    audit_object_storage_endpoint: str | None,
    audit_object_storage_bucket: str | None,
    audit_object_storage_prefix: str,
    audit_object_storage_region: str,
    audit_object_storage_credentials_file: str | None,
    audit_object_storage_rotation_minutes: int,
    audit_object_storage_max_size_mb: int,
    audit_object_storage_instance_id: str | None,
    alert_rules_path: str | None,
    alert_routes_path: str | None,
    heartbeat_interval_seconds: int,
    alert_heartbeat_missing_count: int,
    burst_threshold: int,
    burst_window_seconds: int,
    bulk_answer_mcp_token: str | None,
    audit_events_token: str | None,
    deployment_preset: str | None,
    db: str | None,
) -> None:
    """Start the HTTP proxy server.

    Slice 1 ships the foundation: parsing + verdicts + audit log.
    Slice 2 will add request forwarding to AWS. Until Slice 2,
    the proxy is useful as an OBSERVABILITY tool — point an SDK
    client at it (`AWS_ENDPOINT_URL=http://127.0.0.1:8767`) and
    see a parsed log of every call your client would make, with
    the bouncer's verdict for each.

    Examples:

      ibounce run                          # cooperative on :8767
      ibounce run --mode transparent       # enforcement
      ibounce run --port 9876              # custom port
    """
    import asyncio as _asyncio

    from .bouncer.decisions import DefaultPolicy
    from .bouncer.deployment_presets import (
        PresetOverrideError, apply_preset, format_banner, get_preset,
    )
    from .bouncer.profiles import load_profiles, resolve_active_profile
    from .bouncer.proxy import ProxyConfig, ProxyMode, serve

    # #254 — deployment preset resolution. Runs FIRST so the downstream
    # validation gates see the preset-resolved values, not the raw
    # operator input. HARD-override conflicts (e.g. --preset security-
    # observe --mode cooperative) fail-fast here with a clear "drop one
    # OR the other" message. SOFT overrides flow through: the operator's
    # value wins. The preset's BANNER lines are stashed for later
    # printing so they appear after the standard "starting on
    # http://..." line.
    preset_banner_lines: list[str] = []
    if deployment_preset:
        _preset = get_preset(deployment_preset.lower(), product="ibounce")
        if _preset is None:
            click.secho(
                f"unknown --preset {deployment_preset!r}; "
                f"available: security-observe",
                fg="red", err=True,
            )
            sys.exit(2)
        # Detect which flags the operator explicitly supplied (vs left
        # at default). Click 8+ exposes parameter sources; sources of
        # COMMANDLINE / ENVIRONMENT / PROMPT all mean "operator-
        # supplied" — only DEFAULT / DEFAULT_MAP mean "left at default".
        from click.core import ParameterSource as _PSource
        _operator_supplied: dict[str, object] = {}
        _current_values = {
            "mode": mode,
            "default_policy": default_policy,
            "audit_log_path": audit_log_path,
            "alert_rules_path": alert_rules_path,
            "heartbeat_interval_seconds": heartbeat_interval_seconds,
        }
        for _k in _current_values:
            _src = ctx.get_parameter_source(_k)
            if _src not in (None, _PSource.DEFAULT, _PSource.DEFAULT_MAP):
                _operator_supplied[_k] = _current_values[_k]
        try:
            resolved, derived, skipped = apply_preset(
                preset=_preset,
                operator_supplied=_operator_supplied,
                flag_defaults=_current_values,
            )
        except PresetOverrideError as _e:
            click.secho(str(_e), fg="red", err=True)
            sys.exit(2)
        # Rebind the locals that downstream code reads.
        mode = resolved["mode"]
        default_policy = resolved["default_policy"]
        audit_log_path = resolved["audit_log_path"]
        alert_rules_path = resolved["alert_rules_path"]
        heartbeat_interval_seconds = resolved["heartbeat_interval_seconds"]
        # Make sure the preset's default audit-log directory exists
        # before the audit-export wiring tries to open() the file —
        # avoids a confusing 'No such file or directory' on first run.
        if audit_log_path:
            try:
                os.makedirs(os.path.dirname(audit_log_path), exist_ok=True)
            except OSError:
                # Non-fatal: if the dir is unwritable the JSONL writer
                # surfaces the error with its own context. We just
                # didn't pre-create it.
                pass
        preset_banner_lines = format_banner(
            _preset, derived_keys=derived, skipped_keys=skipped,
        )

    # #300 — parse the operator's --upstream URL up-front so a bad
    # value (schemeless, ftp://, etc.) fails fast with a clear
    # message BEFORE we touch the DB, validate licenses, or start
    # serve(). The parser validates scheme ∈ {http, https} + host
    # non-empty.
    from .bouncer.proxy import UpstreamUrlError, parse_upstream_url
    forward_scheme_resolved = "https"
    forward_host_override_resolved: str | None = None
    if upstream_url:
        try:
            forward_scheme_resolved, forward_host_override_resolved = (
                parse_upstream_url(upstream_url)
            )
        except UpstreamUrlError as _e:
            click.secho(f"--upstream error: {_e}", fg="red", err=True)
            sys.exit(2)

    # CRIT-32-02 closure: refuse externally-bindable hosts unless the
    # operator explicitly acknowledged. The proxy holds AWS SigV4
    # signatures + receives unauthenticated client connections; an
    # externally-bound instance is reachable by anyone on the network
    # who can then drive the proxy to forward signed requests.
    _LOOPBACK_HOSTS = {
        "127.0.0.1", "::1", "localhost", "ip6-localhost", "ip6-loopback",
    }
    if host not in _LOOPBACK_HOSTS and not force_external_bind:
        click.secho(
            f"refusing to bind to {host!r}: this exposes the bouncer's "
            f"credential-handling surface to the network.\n\n"
            f"If you genuinely need to bind externally (test VM with no "
            f"real credentials, network-segmented dev box), re-run with "
            f"--i-know-this-binds-externally AND read docs/SECURITY.md "
            f"first. CRIT-32-02 closure.",
            fg="red", err=True,
        )
        sys.exit(2)
    # #271 — GET /audit/events lives on the same port; an external
    # bind without a bearer token would expose recent audit events
    # (operation/account/region) without auth. Refuse to start in
    # that shape so the operator picks the explicit token shape.
    if host not in _LOOPBACK_HOSTS and not audit_events_token:
        click.secho(
            f"refusing to bind to {host!r}: --audit-events-token TOKEN is "
            f"required when --host is non-loopback (GET /audit/events "
            f"would otherwise be exposed without auth).",
            fg="red", err=True,
        )
        sys.exit(2)

    # #252 Slice 1 — env-var fallback for the webhook token so the
    # secret never has to appear on the command line / in shell
    # history. Operators almost always set this via env in real
    # deployments; the flag exists for tests + one-off scripts.
    if not audit_webhook_token:
        audit_webhook_token = os.environ.get(
            "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_TOKEN", "",
        ) or None

    # #252 — bail early on contradictory webhook flags. URL without
    # token (or vice versa) is almost certainly a misconfiguration.
    if bool(audit_webhook_url) != bool(audit_webhook_token):
        click.secho(
            "--audit-webhook-url and --audit-webhook-token must be set "
            "together (or both unset). Token can also come from "
            "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_TOKEN env var.",
            fg="red", err=True,
        )
        sys.exit(2)

    # #258 — Security Lake parse-time validation. Bucket without region
    # is a misconfiguration; fail-fast so the operator fixes it once
    # rather than seeing a credential probe failure deep in startup.
    if security_lake_bucket and not security_lake_region:
        click.secho(
            "--security-lake-bucket requires --security-lake-region "
            "(the region becomes the `region=<r>` partition key on every "
            "parquet file Security Lake ingests).",
            fg="red", err=True,
        )
        sys.exit(2)
    if security_lake_region and not security_lake_bucket:
        click.secho(
            "--security-lake-region requires --security-lake-bucket "
            "(passing region without a target bucket has no effect).",
            fg="red", err=True,
        )
        sys.exit(2)

    # #317 — object-storage parse-time validation. Bucket without
    # endpoint (or vice versa) is a misconfiguration; fail-fast so the
    # operator fixes it once rather than seeing a bucket probe failure
    # deep in startup.
    if audit_object_storage_bucket and not audit_object_storage_endpoint:
        click.secho(
            "--audit-object-storage-bucket requires "
            "--audit-object-storage-endpoint (the S3 API endpoint URL "
            "for the operator's cloud provider — examples: "
            "https://s3.us-east-1.amazonaws.com for AWS S3; "
            "https://<accountid>.r2.cloudflarestorage.com for "
            "Cloudflare R2; https://storage.googleapis.com for GCS "
            "interop).",
            fg="red", err=True,
        )
        sys.exit(2)
    if audit_object_storage_endpoint and not audit_object_storage_bucket:
        click.secho(
            "--audit-object-storage-endpoint requires "
            "--audit-object-storage-bucket (passing an endpoint "
            "without a target bucket has no effect).",
            fg="red", err=True,
        )
        sys.exit(2)

    # #252 — license + SSRF gates fire HERE (at CLI parse), not in
    # serve(), so the operator sees the error immediately rather than
    # finding it deep in startup logs. Both gates re-validate at
    # serve() time too (defense in depth + handles deployments where
    # the license file was added between parse and start).
    if audit_webhook_url:
        from .bouncer.audit_export.webhook import (
            SSRFRejectedError, WebhookLicenseError,
            gate_webhook_license, validate_webhook_url,
        )
        try:
            gate_webhook_license(None)
        except WebhookLicenseError as e:
            click.secho(f"audit webhook refused: {e}", fg="red", err=True)
            sys.exit(2)
        try:
            validate_webhook_url(
                audit_webhook_url,
                allow_internal=audit_webhook_allow_internal,
            )
        except SSRFRejectedError as e:
            click.secho(f"audit webhook refused: {e}", fg="red", err=True)
            sys.exit(2)

    # #262 Slice 2 — alert-rules license gate fires at CLI parse so
    # the operator sees "Enterprise required" immediately, not deep
    # in startup. serve() gates again (defense in depth, same
    # posture as the webhook gate above).
    if alert_rules_path is not None:
        from .bouncer.audit_export.alerts import (
            AlertsLicenseError, gate_alerts_license,
        )
        try:
            gate_alerts_license(None)
        except AlertsLicenseError as e:
            click.secho(
                f"audit-export alerts refused: {e}", fg="red", err=True,
            )
            sys.exit(2)
        # Normalize the magic "defaults" / "" / "<path>" surface so
        # ProxyConfig sees one of two shapes: None (no engine) or
        # str (engine; "" = built-in defaults, "<path>" = load YAML).
        if alert_rules_path.lower() == "defaults":
            alert_rules_path = ""

    # #280 — per-org notification routing. License gate + YAML load
    # both fire at CLI parse so the operator sees structure / secret
    # errors immediately. serve() re-validates the license (defense in
    # depth) and re-loads the YAML (handles rotated env-var secrets).
    if alert_routes_path is not None:
        from .bouncer.audit_export.routes import (
            RoutesConfigError, RoutesLicenseError,
            gate_routes_license, load_routes_config,
        )
        try:
            gate_routes_license(None)
        except RoutesLicenseError as e:
            click.secho(
                f"--alert-routes refused: {e}", fg="red", err=True,
            )
            sys.exit(2)
        try:
            # Validate eagerly so a bad YAML / unresolved ${ENV} surfaces
            # at parse time. serve() reloads to pick up rotated values.
            load_routes_config(alert_routes_path, product="ibounce")
        except RoutesConfigError as e:
            click.secho(
                f"--alert-routes config error: {e}", fg="red", err=True,
            )
            sys.exit(2)
        # Backward-compat warning when both single-webhook + multi-route
        # are set (per the memo: routes engine wins; single-webhook is
        # ignored).
        if audit_webhook_url:
            click.secho(
                "--alert-routes is set; --audit-webhook-url will be "
                "ignored (the multi-destination routing engine handles "
                "all dispatch when --alert-routes is configured).",
                fg="yellow", err=True,
            )

    # #203 — refuse the mutually-exclusive flag combo at parse time.
    # Both flags both try to surface DENYs to the operator, but they
    # have opposite blocking semantics: async returns 403 immediately,
    # sync blocks. Setting both at once is almost certainly a typo +
    # would produce confusing behavior (the proxy would block AND
    # enqueue an async row that the operator might answer separately).
    if prompt_on_deny and sync_prompt_on_deny:
        click.secho(
            "--prompt-on-deny and --sync-prompt-on-deny are mutually "
            "exclusive — pick one:\n"
            "  --prompt-on-deny       (async; agent gets 403 immediately, "
            "operator answers later; #5)\n"
            "  --sync-prompt-on-deny  (sync;  agent blocks until operator "
            "answers or timeout fires; #203)",
            fg="red", err=True,
        )
        sys.exit(2)

    # Resolve the active profile NOW (CLI flag → env var → 'full-user').
    # If the user passed --profile NAME and NAME doesn't exist,
    # resolve_active_profile raises with the available-names list —
    # better than silently falling back to 'full-user' (which would
    # disable the safety the user thought they enabled). Deprecated
    # aliases ('none', 'prod-readonly') still resolve in v1.0 + emit
    # a deprecation banner from resolve_active_profile itself.
    try:
        profiles_map = load_profiles()
        active_profile = resolve_active_profile(
            cli_flag=profile_name, profiles=profiles_map,
        )
    except ValueError as e:
        click.secho(f"profile error: {e}", fg="red", err=True)
        sys.exit(2)

    config = ProxyConfig(
        host=host,
        port=port,
        mode=ProxyMode(mode.lower()),
        default_policy=DefaultPolicy(default_policy.lower()),
        forward_scheme=forward_scheme_resolved,
        forward_host_override=forward_host_override_resolved,
        active_profile=active_profile,
        account_id=account_id_flag,
        account_alias=account_alias_flag,
        prompt_on_deny=prompt_on_deny,
        sync_prompt_on_deny=sync_prompt_on_deny,
        sync_prompt_timeout_seconds=sync_prompt_timeout,
        sync_prompt_default_decision=sync_prompt_default.lower(),
        plan_session_id=plan_session_id,
        plan_write_switch_notify=write_switch_notify.lower(),
        audit_log_path=audit_log_path,
        audit_log_fsync=audit_log_fsync,
        audit_log_max_size_mb=audit_log_max_size_mb,
        audit_log_max_age_days=audit_log_max_age_days,
        audit_db_retention_days=audit_db_retention_days,
        record_sessions_dir=record_sessions_dir,
        audit_webhook_url=audit_webhook_url,
        audit_webhook_token=audit_webhook_token,
        audit_webhook_batch_size=audit_webhook_batch_size,
        audit_webhook_allow_internal=audit_webhook_allow_internal,
        audit_webhook_preset=audit_webhook_preset.lower(),
        audit_webhook_tags=audit_webhook_tags,
        audit_webhook_sentinel_table=audit_webhook_sentinel_table,
        security_lake_bucket=security_lake_bucket,
        security_lake_region=security_lake_region,
        security_lake_role_arn=security_lake_role_arn,
        security_lake_rotation_seconds=security_lake_rotation_seconds,
        audit_object_storage_endpoint=audit_object_storage_endpoint,
        audit_object_storage_bucket=audit_object_storage_bucket,
        audit_object_storage_prefix=audit_object_storage_prefix,
        audit_object_storage_region=audit_object_storage_region,
        audit_object_storage_credentials_file=audit_object_storage_credentials_file,
        audit_object_storage_rotation_minutes=audit_object_storage_rotation_minutes,
        audit_object_storage_max_size_mb=audit_object_storage_max_size_mb,
        audit_object_storage_instance_id=audit_object_storage_instance_id,
        alert_rules_path=alert_rules_path,
        alert_routes_path=alert_routes_path,
        heartbeat_interval_seconds=heartbeat_interval_seconds,
        alert_heartbeat_missing_count=alert_heartbeat_missing_count,
        burst_threshold=burst_threshold,
        burst_window_seconds=burst_window_seconds,
        bulk_answer_mcp_token=bulk_answer_mcp_token,
        audit_events_token=audit_events_token,
    )

    # #132 plan-capture: surface the session id (operator-supplied or
    # the auto-minted one) up-front so the operator can find the
    # transcript later via `ibounce plan show <id>`. The serve()
    # entry installs the in-process slot; we resolve the actual id
    # AFTER serve() starts so the echoed value matches what gets
    # persisted.
    if ProxyMode(mode.lower()) == ProxyMode.PLAN_CAPTURE:
        from .bouncer import plan_capture as _plan_capture_pkg
        if plan_session_id:
            _plan_capture_pkg.set_session_id(plan_session_id)
            resolved_pid = plan_session_id
        else:
            resolved_pid = _plan_capture_pkg.new_session_id()
        click.echo(
            f"plan-capture session: {resolved_pid}  "
            f"(view: ibounce plan show {resolved_pid})",
            err=True,
        )
        # #145 — surface the write-switch UX up-front so the operator
        # knows what will happen on the agent's first write call.
        click.echo(
            f"  write-switch-notify={write_switch_notify.lower()}  "
            f"(first write transitions phase: read_only -> "
            + {
                "manual": "write_pending + prompt; answer via "
                          "`ibounce prompts answer ID --kind plan-write "
                          "--decision approve|reject`",
                "auto-approve": "writes_approved silently (no prompt)",
                "reject": "writes_rejected; subsequent writes get a "
                          "PlanCaptureWritesRejected synthetic error",
            }[write_switch_notify.lower()]
            + ")",
            err=True,
        )

    # Did the operator opt into a profile, or did we land on the
    # passthrough default? When the latter, surface the
    # write-block-opt-in instructions banner per
    # `feedback_bounce_default_profile_pattern`.
    operator_picked_profile = bool(
        profile_name or os.environ.get("IAM_JIT_BOUNCER_PROFILE")
    )
    passthrough_default = (
        not operator_picked_profile and active_profile.name == "full-user"
    )

    with _opened_store(db) as store:
        click.echo(
            f"ibounce proxy starting on http://{host}:{port} "
            f"(mode={mode}, default-policy={default_policy}, "
            f"profile={active_profile.name})",
            err=True,
        )
        # #300 — surface --upstream resolution in the startup banner so
        # the operator sees the override before any traffic lands. Quiet
        # when --upstream is unset (default real-AWS / signed-Host
        # behaviour); only mentioned on opt-in.
        if upstream_url:
            click.echo(
                f"  upstream override: {forward_scheme_resolved}://"
                f"{forward_host_override_resolved} "
                f"(forwarding bypasses inbound Host header; CRIT-32-01 "
                f"allowlist still applies)",
                err=True,
            )
        # #254 — preset-derivation banner sits RIGHT AFTER the address
        # line so the operator immediately sees which settings came
        # from the preset (vs. their own flags / env). Same format
        # across all four Bounce products per [[cross-product-agent-
        # parity]].
        for _line in preset_banner_lines:
            click.echo(_line, err=True)
        if active_profile.name not in ("full-user", "none"):
            click.echo(
                f"  profile: {active_profile.description}",
                err=True,
            )
        if passthrough_default:
            # Per safe_default_is_readonly_admin_minus (2026-05-17):
            # the banner explains BOTH what safe-default blocks AND
            # what it does not block, so an operator who skims past
            # the recommendation doesn't get a confidentiality
            # surprise in incident response. Mirrors the README +
            # docs/IBOUNCE.md callout.
            click.echo(
                "  No profile selected. Calls forwarded as-is + audit-logged.",
                err=True,
            )
            click.echo(
                "  For state-preservation safety, run with --profile safe-default.",
                err=True,
            )
            click.echo(
                "    blocks state-changing AWS operations (writes, privilege "
                "grants, exfil)",
                err=True,
            )
            click.echo(
                "    does NOT prevent reads of sensitive data (use S3 bucket "
                "policies +",
                err=True,
            )
            click.echo(
                "      KMS grants for confidentiality)",
                err=True,
            )
        # #252 — surface audit-export channels in the startup banner
        # so the operator immediately sees that decisions are being
        # mirrored. The webhook token is MASKED as '***' (per
        # [[security-team-audit-export]]: the token NEVER appears in
        # banner / /healthz / log / errors).
        if audit_log_path:
            click.echo(
                f"audit-export JSONL log: {audit_log_path}"
                + (" (fsync=on)" if audit_log_fsync else ""),
                err=True,
            )
        # #285 — surface session-recorder state in the startup banner.
        # Default OFF; only mention when opted in (matches the webhook +
        # heartbeat banner posture).
        if record_sessions_dir:
            click.echo(
                f"session recorder: {record_sessions_dir} "
                f"(one .ndjson per agent session; replay via "
                f"`iam-jit session replay`)",
                err=True,
            )
        if audit_webhook_url:
            from .bouncer.audit_export.webhook import mask_url_userinfo
            preset_extra = ""
            if audit_webhook_preset == "datadog" and audit_webhook_tags:
                preset_extra = f", tags={audit_webhook_tags}"
            elif audit_webhook_preset == "sentinel":
                preset_extra = f", table={audit_webhook_sentinel_table}"
            click.echo(
                f"audit-export HTTPS webhook: "
                f"{mask_url_userinfo(audit_webhook_url)} "
                f"(preset={audit_webhook_preset}, token=***, "
                f"batch={audit_webhook_batch_size}"
                + preset_extra
                + (", allow-internal=on" if audit_webhook_allow_internal else "")
                + ")",
                err=True,
            )
        if security_lake_bucket:
            # #258 — Security Lake banner. AWS account + caller arn
            # come from sts:GetCallerIdentity at writer.start(); the
            # serve() startup logs them again so the operator sees
            # which identity wrote to S3 (matches the "log AWS account
            # + role at startup banner" requirement).
            click.echo(
                f"audit-export Security Lake: s3://{security_lake_bucket}/ "
                f"(region={security_lake_region}, "
                f"role={security_lake_role_arn or '(default-chain)'}, "
                f"rotation={security_lake_rotation_seconds}s)",
                err=True,
            )
        if audit_object_storage_bucket:
            # #317 — object-storage banner. Cloud-neutral S3-compatible
            # NDJSON sink. Per [[self-host-zero-billing-dependency]]
            # the destination is operator-owned; iam-jit-the-company
            # never receives the data.
            click.echo(
                f"audit-export object-storage: "
                f"s3://{audit_object_storage_bucket}/"
                f"{audit_object_storage_prefix} "
                f"(endpoint={audit_object_storage_endpoint}, "
                f"region={audit_object_storage_region}, "
                f"rotation={audit_object_storage_rotation_minutes}m, "
                f"max-size={audit_object_storage_max_size_mb}MB)",
                err=True,
            )
        # #264 — surface heartbeat state in startup banner. Default is
        # OFF (zero phone-home preserved per
        # [[security-team-positioning-safety-not-surveillance]]); only
        # mention it when the operator opted in so the banner stays
        # quiet by default.
        if heartbeat_interval_seconds > 0:
            click.echo(
                f"audit-export heartbeat: every "
                f"{heartbeat_interval_seconds}s "
                f"(gap-threshold={alert_heartbeat_missing_count} "
                f"consecutive misses)",
                err=True,
            )
        click.echo(
            f"Point your SDK: export AWS_ENDPOINT_URL=http://{host}:{port}",
            err=True,
        )
        # #304 — known-caveats banner. Emits one line per triggered
        # §B entry. §B1 (SigV4-only) is structural — every ibounce
        # instance has this shape, so it always fires. §B3
        # (safe-default = readonly-admin-minus) fires only when the
        # active profile is safe-default. Per the founder direction
        # "the signal should be useful, not noise" — we don't surface
        # every §B entry here; `iam-jit doctor caveats` is the full
        # list.
        from .bouncer import caveats as _caveats
        _trigger = _caveats.Trigger(
            always_sigv4_only=True,
            safe_default_profile=active_profile.name == "safe-default",
        )
        for _line in _caveats.banner_lines(_trigger):
            click.echo(_line, err=True)
        # §A19 profile-upgrade-blindness banner (#321). Only fires
        # when the operator's installed profile is missing a safety-
        # floor field AND they haven't acknowledged the current
        # shipped-defaults version. Convenience / detection / audit
        # misses don't trigger the startup line — operators see those
        # on explicit `ibounce profile doctor`.
        from .bouncer import profile_doctor as _profile_doctor
        _doctor_line = _profile_doctor.startup_banner_line(product="ibounce")
        if _doctor_line:
            click.echo(_doctor_line, err=True)
        click.echo("Ctrl+C to stop.", err=True)
        try:
            _asyncio.run(serve(config, store=store))
        except KeyboardInterrupt:
            click.echo("\nibounce proxy stopped.", err=True)


# ---------------------------------------------------------------------------
# `ibounce plan ...` — review + export plan-capture session transcripts
# (#132). Sessions are populated by `ibounce serve --mode plan-capture`.
# Read-only surface; nothing here forwards anything to AWS or mutates
# the customer's IAM (per [[creates-never-mutates]]).
# ---------------------------------------------------------------------------


@main.group("plan")
def plan_group() -> None:
    """Inspect + export plan-capture session transcripts.

    Plan-capture is the 4th proxy mode (alongside cooperative /
    transparent / off). Start it via:

        ibounce serve --mode plan-capture

    Every intercepted SDK call is parsed + audited + returned
    with a synthetic SDK-shaped success — nothing forwards to AWS.
    The transcript that records "what the agent intended to do"
    is what these subcommands let you inspect.

    Subcommands:
      list    — list recent plan sessions (newest first)
      show    — show the full call graph for one session
      export  — export one session as JSON for downstream tooling
    """


@plan_group.command("list")
@click.option("--limit", type=int, default=20, show_default=True,
              help="Maximum number of sessions to return.")
@click.option("--db", type=click.Path(dir_okay=False), default=None,
              help="SQLite DB path (default: ~/.iam-jit/bouncer/state.db)")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Emit JSON instead of the human table.")
def plan_list_cmd(limit: int, db: str | None, as_json: bool) -> None:
    """List recent plan-capture sessions with per-session roll-ups."""
    with _opened_store(db) as store:
        rows = store.list_plan_sessions(limit=limit)
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo(
            "no plan-capture sessions recorded yet. "
            "Start one: ibounce serve --mode plan-capture",
            err=True,
        )
        return
    for r in rows:
        click.echo(
            f"{r['session_id']}  "
            f"started={r['started_at']}  by={r['started_by']}  "
            f"calls={r['call_count']}  "
            f"(allow={r['allow_count']} "
            f"deny={r['deny_count']} "
            f"unsupported={r['unsupported_count']})"
        )
        if r["note"]:
            click.echo(f"   note: {r['note']}")


@plan_group.command("show")
@click.argument("session_id")
@click.option("--db", type=click.Path(dir_okay=False), default=None,
              help="SQLite DB path (default: ~/.iam-jit/bouncer/state.db)")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Emit JSON instead of the human table.")
def plan_show_cmd(session_id: str, db: str | None, as_json: bool) -> None:
    """Show the full call graph for one plan-capture session."""
    with _opened_store(db) as store:
        session = store.get_plan_session(session_id)
        if session is None:
            click.secho(
                f"no plan-capture session with id {session_id!r}. "
                f"Run `ibounce plan list` to see available ids.",
                fg="red", err=True,
            )
            sys.exit(2)
        calls = store.list_plan_calls(session_id)
    if as_json:
        click.echo(json.dumps(
            {"session": session, "calls": calls}, indent=2,
        ))
        return
    click.echo(
        f"session: {session['session_id']}"
    )
    click.echo(
        f"  started: {session['started_at']}  by={session['started_by']}"
    )
    click.echo(
        f"  calls={session['call_count']}  "
        f"allow={session['allow_count']} "
        f"deny={session['deny_count']} "
        f"unsupported={session['unsupported_count']}"
    )
    # #145 — phase + write-switch state. Always shown (even for sessions
    # that never crossed read->write) so a quick glance at `plan show`
    # tells the operator exactly which side of the switch this session
    # ended on + which UX it was configured for.
    click.echo(
        f"  phase={session.get('phase', 'read_only')}  "
        f"write-switch-notify={session.get('write_switch_notify', 'manual')}  "
        f"reads={session.get('read_count', 0)} "
        f"writes={session.get('write_count', 0)}"
    )
    if session.get("first_write_at"):
        click.echo(
            f"  first-write-at: {session['first_write_at']}"
        )
    if session.get("write_decision"):
        click.echo(
            f"  write-decision: {session['write_decision']} "
            f"by={session.get('write_decision_by') or 'unknown'} "
            f"at={session.get('write_decision_at') or ''}"
        )
    if session["note"]:
        click.echo(f"  note: {session['note']}")
    if not calls:
        click.echo("  (no calls recorded)")
        return
    click.echo("calls:")
    for c in calls:
        flag = " " if c["supported"] else "!"
        click.echo(
            f"  {flag} #{c['id']}  {c['at']}  "
            f"{c['method']:6s} {c['service']}:{c['action']}  "
            f"verdict={c['verdict']}"
        )


@plan_group.command("export")
@click.argument("session_id")
@click.option("--output", "output_path", type=click.Path(dir_okay=False),
              default=None,
              help="Output file path (defaults to stdout).")
@click.option("--db", type=click.Path(dir_okay=False), default=None,
              help="SQLite DB path (default: ~/.iam-jit/bouncer/state.db)")
def plan_export_cmd(
    session_id: str, output_path: str | None, db: str | None,
) -> None:
    """Export one plan-capture session as JSON for downstream tooling.

    The output shape is `{"session": {...}, "calls": [{...}, ...]}`
    — the same shape `plan show --json` emits. Stable enough that
    downstream consumers (custom dashboards, audit-log ingest)
    can rely on the field names.
    """
    with _opened_store(db) as store:
        session = store.get_plan_session(session_id)
        if session is None:
            click.secho(
                f"no plan-capture session with id {session_id!r}",
                fg="red", err=True,
            )
            sys.exit(2)
        calls = store.list_plan_calls(session_id)
    payload = {"session": session, "calls": calls}
    blob = json.dumps(payload, indent=2)
    if output_path:
        # Plain write; no atomic-replace dance here (consumers point
        # at the file POST-write, not concurrently). Matches the
        # `tasks review --json > file` pattern elsewhere in the CLI.
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(blob)
        click.echo(f"wrote {output_path}", err=True)
    else:
        click.echo(blob)


# ---------------------------------------------------------------------------
# `ibounce mcp ...` — wire the iam-jit/ibounce MCP server into agent runtimes.
#
# Task #228 closure (launch-readiness Stage 5 agent-integration unlock).
# One command from a fresh install to a wired agent for the three most
# common MCP clients (Claude Code, Cursor, Codex). Mirrors the prior art
# `iam-jit mcp ...` group in src/iam_jit/cli.py (same JSON shape, same
# atomic-write semantics) plus per-client config-path detection.
#
# Cross-product parity: `kbounce mcp install-*` (sibling Go binary) ships
# the same subcommand surface + flags. Path detection differs by client;
# JSON shape is identical except for the server entry's `command`/`args`.
# See feedback_cross_product_agent_parity.
#
# Atomic-write invariant: each install-* command writes to a tempfile in
# the target's parent dir, then `os.replace`s it onto the target. The
# replace is atomic on POSIX + Windows; the partial-write window never
# leaves a half-merged config visible to the agent. No `sudo` required —
# every default path is user-owned ($HOME/...).
# ---------------------------------------------------------------------------


@main.group("mcp")
def mcp_group() -> None:
    """Wire ibounce's MCP server into an agent runtime.

    The bouncer's MCP tools (ibounce_list_rules, ibounce_start_task,
    ibounce_decide, ...) ship inside the iam-jit MCP server. Any
    MCP-compatible agent (Claude Code, Cursor, Codex MCP, Devin, custom)
    can call them once the server entry is registered in the agent's
    MCP config.

    Subcommands:
      serve                — run the MCP server on stdio (called by agents)
      show-config          — print the JSON snippet for any MCP client
      install-claude-code  — write the snippet into Claude Code's config
      install-cursor       — write the snippet into Cursor's config
      install-codex        — print the snippet + the manual-install location
      list-tools           — list every MCP tool ibounce exposes
    """


@mcp_group.command("serve")
def mcp_serve_cmd() -> None:
    """Run the ibounce MCP server on stdio.

    Thin wrapper around the iam-jit MCP server (which already exposes
    every ibounce_* tool — same binary, both brands). Speaks the open
    Model Context Protocol over stdin/stdout (line-delimited JSON-RPC).

    Typically NOT invoked by hand — the agent's MCP host launches this
    process per the config snippet emitted by `ibounce mcp show-config`.

    Equivalent to `iam-jit mcp-server`; both call the same module
    entrypoint.
    """
    from .mcp_server import main as mcp_main

    sys.exit(mcp_main())


def _ibounce_mcp_config_dict(*, agent_name_default: str = "claude-code") -> dict[str, Any]:
    """Canonical MCP config snippet for ibounce. Centralized so
    show-config + every install-* command emit IDENTICAL JSON.

    Per #308 + ``[[agent-identity-in-audit]]`` (#266) the snippet
    surfaces the ``X-Agent-Name`` + ``X-Agent-Session-Id`` header
    convention through env vars the agent's HTTP client reads.
    Defaults to ``claude-code``; ``install-cursor`` + ``install-codex``
    pass their own agent name so the canned config matches the agent
    that's about to consume it. The session id is deliberately left
    EMPTY in the static snippet — the agent runtime mints a fresh
    UUID v7 on each connection (see ``docs/AGENT-ATTRIBUTION.md``)
    and the env var serves as the carry-channel into the agent's HTTP
    headers. ibounce itself never reads these env vars — they're a
    hint to the AGENT runtime, not a configuration ibounce consumes.
    """
    return {
        "mcpServers": {
            "ibounce": {
                "command": "ibounce",
                "args": ["mcp", "serve"],
                "env": {
                    # #308 — header-injection hints. The agent's MCP
                    # host inherits these into the child process; the
                    # agent's HTTP client stamps them as
                    # X-Agent-Name + X-Agent-Session-Id on every
                    # outbound call back through the Bouncers'
                    # HTTP-shaped surfaces (gbounce; ibounce's
                    # AWS-API proxy mode). See
                    # docs/AGENT-ATTRIBUTION.md for the per-runtime
                    # patterns + the validation rules.
                    "IBOUNCE_AGENT_NAME": agent_name_default,
                    "IBOUNCE_AGENT_SESSION_ID": "",
                },
            },
        },
    }


def _atomic_write_json(target: "os.PathLike[str] | str", data: dict[str, Any]) -> None:
    """Atomic JSON write: write to a tempfile in the target's parent
    dir, fsync, then os.replace onto the target. POSIX + Windows both
    treat the rename as atomic, so an interrupted run never leaves a
    half-merged config visible to the agent's MCP host."""
    import pathlib as _pathlib
    import tempfile as _tempfile

    target_path = _pathlib.Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = _tempfile.mkstemp(
        prefix=target_path.name + ".",
        suffix=".tmp",
        dir=str(target_path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, indent=2) + "\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                # fsync isn't supported on all filesystems (e.g. some
                # tmpfs / NFS variants). The atomic rename is still
                # guaranteed by POSIX; we don't fail the install for a
                # missing fsync.
                pass
        os.replace(tmp_name, target_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _merge_ibounce_entry(
    target: "os.PathLike[str] | str",
    *,
    force: bool,
    agent_name_default: str = "claude-code",
) -> tuple[bool, str | None]:
    """Read the existing JSON config (if any), preserve all other keys
    + other `mcpServers` entries, and add/update the `ibounce` entry.
    Returns (overwriting, error_message). On error, the target file is
    left untouched.

    ``agent_name_default`` (#308) feeds the ``IBOUNCE_AGENT_NAME`` env
    var on the generated entry so the agent runtime stamps the right
    ``X-Agent-Name`` header on outbound HTTP traffic. Defaults to
    ``claude-code``; ``install-cursor`` + ``install-codex`` pass
    ``cursor`` + ``openai-codex`` respectively.
    """
    import pathlib as _pathlib

    target_path = _pathlib.Path(target)
    existing: dict[str, Any] = {}
    if target_path.exists():
        try:
            existing = json.loads(target_path.read_text())
        except json.JSONDecodeError as e:
            return False, (
                f"existing config at {target_path} is not valid JSON ({e}); "
                "refusing to overwrite. Pass --path to a clean location "
                "or run `ibounce mcp show-config` and merge by hand."
            )
        if not isinstance(existing, dict):
            return False, (
                f"existing config at {target_path} is not a JSON object; "
                "refusing to overwrite. Pass --path to a clean location "
                "or run `ibounce mcp show-config` and merge by hand."
            )

    mcp_servers = existing.setdefault("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        return False, (
            f"existing config at {target_path} has a non-object "
            "`mcpServers` value; refusing to overwrite. Pass --path to "
            "a clean location or run `ibounce mcp show-config` and "
            "merge by hand."
        )

    overwriting = "ibounce" in mcp_servers
    if overwriting and not force:
        # Confirm interactively. In non-tty contexts Click's confirm
        # returns False unless --force is set; we treat that as decline.
        if not click.confirm(
            f"`ibounce` MCP entry already exists at {target_path}. Overwrite?",
            default=False,
        ):
            return False, "declined overwrite (pass --force to skip this prompt)"

    snippet = _ibounce_mcp_config_dict(agent_name_default=agent_name_default)
    mcp_servers["ibounce"] = snippet["mcpServers"]["ibounce"]

    try:
        _atomic_write_json(target_path, existing)
    except OSError as e:
        return False, f"failed to write {target_path}: {e}"
    return overwriting, None


@mcp_group.command("show-config")
@click.option(
    "--shape",
    type=click.Choice(["json", "yaml"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Output format. JSON is the standard MCP config shape; YAML "
         "is offered for operators whose agent config is YAML-native.",
)
def mcp_show_config_cmd(shape: str) -> None:
    """Print the MCP server config snippet to stdout.

    Vendor-neutral — paste into any MCP-compatible client. For the
    three most-common clients there's a one-command installer that
    does the merge + write for you:

      ibounce mcp install-claude-code
      ibounce mcp install-cursor
      ibounce mcp install-codex

    For custom MCP clients, copy the snippet printed above into your
    client's MCP config (location is client-specific).
    """
    cfg = _ibounce_mcp_config_dict()
    if shape.lower() == "yaml":
        try:
            from ruamel.yaml import YAML
            from io import StringIO

            yaml = YAML(typ="safe")
            yaml.default_flow_style = False
            buf = StringIO()
            yaml.dump(cfg, buf)
            click.echo(buf.getvalue().rstrip("\n"))
        except Exception as e:  # pragma: no cover — ruamel.yaml is a hard dep
            click.secho(
                f"failed to emit YAML ({e}); falling back to JSON",
                fg="yellow", err=True,
            )
            click.echo(json.dumps(cfg, indent=2))
    else:
        click.echo(json.dumps(cfg, indent=2))

    click.echo("")
    click.echo("Wire it up:")
    click.echo("  - Claude Code:  ibounce mcp install-claude-code")
    click.echo("  - Cursor:       ibounce mcp install-cursor")
    click.echo("  - Codex MCP:    ibounce mcp install-codex")
    click.echo(
        "  - Other clients: copy the snippet above into your MCP "
        "config (location is client-specific)."
    )
    # #308 — point operators at the agent-attribution doc so they
    # understand the IBOUNCE_AGENT_NAME + IBOUNCE_AGENT_SESSION_ID
    # env vars in the snippet + the corresponding X-Agent-* header
    # convention.
    click.echo("")
    click.echo(
        "Agent attribution: the IBOUNCE_AGENT_NAME + "
        "IBOUNCE_AGENT_SESSION_ID env vars wire the agent's "
        "X-Agent-Name + X-Agent-Session-Id HTTP headers. See "
        "docs/AGENT-ATTRIBUTION.md for the per-runtime patterns "
        "(Claude Code / Cursor / Codex / Devin / OpenClaw / custom)."
    )


def _candidate_claude_code_paths() -> list["os.PathLike[str]"]:
    """Default Claude Code / Claude Desktop MCP config locations, in
    detection priority order. We prefer the Claude Code CLI path
    (`~/.claude.json`) over Claude Desktop because the target audience
    here is CLI-first developers; Desktop paths fall through for users
    on the Anthropic Desktop app."""
    import pathlib as _pathlib
    import platform as _platform

    home = _pathlib.Path.home()
    sysname = _platform.system()
    candidates: list[os.PathLike[str]] = [
        # Claude Code CLI (cross-platform — preferred for our audience)
        home / ".claude.json",
        home / ".config" / "claude-code" / "mcp.json",
    ]
    if sysname == "Darwin":
        candidates.append(
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )
    elif sysname == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(
                _pathlib.Path(appdata) / "Claude" / "claude_desktop_config.json"
            )
        candidates.append(
            home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
        )
    else:
        candidates.append(
            home / ".config" / "Claude" / "claude_desktop_config.json"
        )
    return candidates


def _pick_existing_or_default(candidates: list["os.PathLike[str]"]) -> "os.PathLike[str]":
    """Return the first candidate path that already exists; fall back
    to the first candidate (which the install command will create)."""
    import pathlib as _pathlib

    for c in candidates:
        if _pathlib.Path(c).exists():
            return c
    return candidates[0]


@mcp_group.command("install-claude-code")
@click.option(
    "--path",
    "explicit_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Override the auto-detected Claude Code MCP config path. "
         "Default detection order: ~/.claude.json, "
         "~/.config/claude-code/mcp.json, then the Claude Desktop path "
         "for the host OS.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite an existing `ibounce` entry without prompting.",
)
def mcp_install_claude_code_cmd(explicit_path: str | None, force: bool) -> None:
    """Wire ibounce into Claude Code (or Claude Desktop) MCP config.

    Detects the platform-appropriate config path, preserves every
    other server entry + top-level key, and adds (or replaces) the
    `ibounce` MCP server entry. Atomic write — interrupting the
    command never leaves a half-merged config behind.

    After install, restart Claude Code; then run `/mcp` in Claude
    Code to see the ibounce tools listed.
    """
    if explicit_path:
        target = explicit_path
    else:
        target = _pick_existing_or_default(_candidate_claude_code_paths())

    click.echo(f"target: {target}")
    overwriting, err = _merge_ibounce_entry(target, force=force)
    if err is not None:
        click.secho(f"ERROR: {err}", fg="red", err=True)
        sys.exit(1)

    verb = "updated existing" if overwriting else "added"
    click.secho(f"OK: {verb} `ibounce` MCP entry at {target}", fg="green")
    click.echo(
        "Verify: restart Claude Code; then run `/mcp` to confirm the "
        "ibounce server is listed + tools are discoverable. The agent "
        "config invokes: `ibounce mcp serve`."
    )


def _candidate_cursor_paths() -> list["os.PathLike[str]"]:
    """Default Cursor MCP config locations, in detection priority.
    Cursor's documented user-level path is ~/.cursor/mcp.json; the
    workspace-level .cursor/mcp.json is also supported but requires
    --path to opt in (we don't guess the workspace root)."""
    import pathlib as _pathlib

    home = _pathlib.Path.home()
    return [home / ".cursor" / "mcp.json"]


@mcp_group.command("install-cursor")
@click.option(
    "--path",
    "explicit_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Override the auto-detected Cursor MCP config path. "
         "Default: ~/.cursor/mcp.json. For workspace-level "
         "(<project>/.cursor/mcp.json), pass --path explicitly.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite an existing `ibounce` entry without prompting.",
)
def mcp_install_cursor_cmd(explicit_path: str | None, force: bool) -> None:
    """Wire ibounce into Cursor's MCP config.

    Default path: ~/.cursor/mcp.json (user-level). For workspace
    scope, pass --path <project>/.cursor/mcp.json. Atomic write +
    other servers preserved.

    After install, restart Cursor; then check the MCP tab in Cursor
    settings to confirm the ibounce server is listed.
    """
    if explicit_path:
        target = explicit_path
    else:
        target = _pick_existing_or_default(_candidate_cursor_paths())

    click.echo(f"target: {target}")
    # #308 — Cursor's runtime stamps X-Agent-Name="cursor" via the
    # IBOUNCE_AGENT_NAME env var on the spawned MCP server process.
    overwriting, err = _merge_ibounce_entry(
        target, force=force, agent_name_default="cursor",
    )
    if err is not None:
        click.secho(f"ERROR: {err}", fg="red", err=True)
        sys.exit(1)

    verb = "updated existing" if overwriting else "added"
    click.secho(f"OK: {verb} `ibounce` MCP entry at {target}", fg="green")
    click.echo(
        "Verify: restart Cursor; then open Settings → MCP to confirm "
        "the ibounce server is listed. The agent config invokes: "
        "`ibounce mcp serve`."
    )


@mcp_group.command("install-codex")
@click.option(
    "--path",
    "explicit_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="If you know your Codex MCP config path, pass it here and "
         "ibounce will write the entry atomically (same merge + "
         "preserve-existing semantics as the other installers).",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite an existing `ibounce` entry without prompting "
         "(only meaningful with --path).",
)
def mcp_install_codex_cmd(explicit_path: str | None, force: bool) -> None:
    """Print the snippet + the manual-install location for Codex MCP.

    Codex MCP's config-file location has shifted across releases and
    isn't stable enough for ibounce to auto-detect without risk of
    clobbering an unrelated file. We print the JSON snippet + tell
    you exactly what to do.

    If you know your Codex MCP config path, pass `--path PATH` and
    ibounce will perform the atomic merge for you (same semantics as
    install-claude-code / install-cursor).
    """
    if explicit_path:
        click.echo(f"target: {explicit_path}")
        # #308 — Codex stamps X-Agent-Name="openai-codex".
        overwriting, err = _merge_ibounce_entry(
            explicit_path, force=force, agent_name_default="openai-codex",
        )
        if err is not None:
            click.secho(f"ERROR: {err}", fg="red", err=True)
            sys.exit(1)
        verb = "updated existing" if overwriting else "added"
        click.secho(
            f"OK: {verb} `ibounce` MCP entry at {explicit_path}",
            fg="green",
        )
        click.echo(
            "Verify: restart Codex; consult your Codex client docs "
            "for MCP-tool discovery."
        )
        return

    cfg = _ibounce_mcp_config_dict(agent_name_default="openai-codex")
    click.echo("Codex MCP config locations vary by release; ibounce does")
    click.echo("not auto-detect (refusing to risk clobbering an unrelated")
    click.echo("file). Paste the snippet below into your Codex MCP config:")
    click.echo("")
    click.echo(json.dumps(cfg, indent=2))
    click.echo("")
    click.echo(
        "If you know the exact path, re-run with `ibounce mcp "
        "install-codex --path PATH` and ibounce will perform the same "
        "atomic merge as install-claude-code / install-cursor."
    )


@mcp_group.command("list-tools")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Emit a JSON array instead of the two-column table.",
)
@click.option(
    "--prefix",
    type=str,
    default=None,
    help="Filter to tools whose name starts with PREFIX (e.g. "
         "`--prefix ibounce_` to show only the bouncer surface).",
)
def mcp_list_tools_cmd(as_json: bool, prefix: str | None) -> None:
    """List every MCP tool the ibounce MCP server exposes.

    Useful for operators auditing what an agent can do via ibounce
    BEFORE wiring the server into a client. Reads the live TOOLS
    list out of the MCP server module so this output never drifts
    from what the agent actually sees on `tools/list`.
    """
    from .mcp_server import TOOLS as _TOOLS

    items: list[dict[str, str]] = []
    for tool in _TOOLS:
        name = str(tool.get("name", "")).strip()
        if not name:
            continue
        if prefix and not name.startswith(prefix):
            continue
        # Take the first sentence of the description for the table view.
        desc_full = str(tool.get("description", "")).strip()
        first = desc_full.split(". ", 1)[0].rstrip(".")
        # Collapse internal whitespace so the table stays one-line per tool.
        first = " ".join(first.split())
        if len(first) > 100:
            first = first[:97] + "..."
        items.append({"name": name, "description": first})

    items.sort(key=lambda r: r["name"])

    if as_json:
        click.echo(json.dumps(items, indent=2))
        return

    if not items:
        click.echo("(no tools matched)")
        return

    name_w = max(len(it["name"]) for it in items)
    name_w = max(name_w, len("TOOL"))
    click.secho(f"{'TOOL'.ljust(name_w)}  DESCRIPTION", bold=True)
    click.echo(f"{'-' * name_w}  {'-' * 11}")
    for it in items:
        click.echo(f"{it['name'].ljust(name_w)}  {it['description']}")
    click.echo("")
    click.echo(f"{len(items)} tool(s).")


# ---------------------------------------------------------------------------
# version-check (#234 — opt-in, operator-initiated, NOT phone-home)
# ---------------------------------------------------------------------------
#
# Per [[update-release-strategy]] + [[self-host-zero-billing-dependency]]:
# iam-jit ships with ZERO automatic phone-home / telemetry. This subcommand
# is the explicit, operator-initiated exception: a one-shot GET to the
# public GitHub Releases endpoint, result printed locally, no data sent
# about the install. It NEVER runs as a side-effect of any other
# subcommand — only on explicit `ibounce version-check` invocation.
#
# Env-var opt-out (IBOUNCE_NO_VERSION_CHECK / IAM_JIT_NO_VERSION_CHECK)
# preserves the airgapped-deployment invariant: an operator can prove the
# command does not call out by setting the env var, which short-circuits
# before any urllib call.
#
# Cross-product parity ([[feedback_cross_product_agent_parity]]): the
# kbounce sibling will mirror this shape — same flags, same env vars,
# same cache layout — so the kbounce port is mechanical translation.
# ---------------------------------------------------------------------------

VERSION_CHECK_URL = (
    "https://api.github.com/repos/trsreagan3/iam-jit/releases/latest"
)
VERSION_CHECK_OPT_OUT_ENVS = (
    "IBOUNCE_NO_VERSION_CHECK",
    "IAM_JIT_NO_VERSION_CHECK",
)
VERSION_CHECK_CACHE_TTL_SECONDS = 3600  # 1 hour


def _version_check_cache_path() -> "os.PathLike[str]":
    """`~/.iam-jit/bouncer/version_check.json` unless an env override
    is set (kept distinct from the SQLite state path so airgapped users
    can wipe just this file)."""
    import pathlib as _pathlib

    override = os.environ.get("IBOUNCE_VERSION_CHECK_CACHE")
    if override:
        return _pathlib.Path(override)
    return _pathlib.Path.home() / ".iam-jit" / "bouncer" / "version_check.json"


def _sanitize_for_print(s: str, *, max_len: int = 200) -> str:
    """BB+WB audit (c): a malicious GitHub Releases response could put
    control chars, ANSI escapes, or very long strings in `tag_name` or
    `html_url`. We're echoing these to a terminal, so strip control
    chars + cap length BEFORE handing to click.echo. Defensive even
    though GitHub validates tag names — we don't trust the network."""
    if not isinstance(s, str):
        s = str(s)
    # Drop ASCII control chars (incl. ESC for ANSI sequences) + DEL,
    # keep printable ASCII + common Unicode.
    cleaned = "".join(
        ch for ch in s if (ord(ch) >= 0x20 and ord(ch) != 0x7F) or ch in ("\t",)
    )
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


def _parse_semver_tag(tag: str) -> tuple[int, int, int] | None:
    """Parse a `vX.Y.Z` or `X.Y.Z` tag into a comparable tuple.
    Returns None if the tag isn't a clean three-segment semver — in
    which case the caller falls back to a string-equality check
    (conservative: a non-semver tag means we just compare literally,
    we never claim "newer available" without confidence)."""
    raw = tag.strip()
    if raw.startswith("v") or raw.startswith("V"):
        raw = raw[1:]
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


def _read_version_check_cache(cache_path: "os.PathLike[str]") -> dict[str, Any] | None:
    """Return cached payload if present + still within TTL, else None.
    A corrupt cache file is treated as a miss (not an error) — same
    fail-soft policy as the network branch."""
    import datetime as _dt
    import pathlib as _pathlib

    p = _pathlib.Path(cache_path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    checked_at_raw = data.get("checked_at")
    if not isinstance(checked_at_raw, str):
        return None
    try:
        checked_at = _dt.datetime.fromisoformat(checked_at_raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    age = (_dt.datetime.now(_dt.UTC) - checked_at).total_seconds()
    if age < 0 or age > VERSION_CHECK_CACHE_TTL_SECONDS:
        return None
    return {
        "latest": data.get("latest"),
        "url": data.get("url"),
        "checked_at": checked_at,
        "age_seconds": int(age),
    }


def _write_version_check_cache(
    cache_path: "os.PathLike[str]",
    *,
    latest: str,
    url: str,
) -> None:
    """Persist the latest result with 0o600 perms (matches the other
    bouncer state files; the file contains nothing sensitive but the
    convention catches future leaks if we ever add fields)."""
    import datetime as _dt
    import pathlib as _pathlib

    p = _pathlib.Path(cache_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "checked_at": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "latest": latest,
        "url": url,
    }
    # Atomic write so a Ctrl-C mid-write never leaves a corrupt cache.
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        # Best-effort: some filesystems (e.g. tmpfs/NFS) ignore chmod.
        pass
    os.replace(tmp, p)


def _format_age(seconds: int) -> str:
    """Human-readable age suffix for cache hits."""
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    return f"{seconds // 3600}h ago"


@main.group("audit")
def audit_group() -> None:
    """#268 — local-operator audit UX (read-only over the JSONL log).

    Sibling subcommand-set to `audit-export` (which checks the export
    channel's health). `audit` is the read surface: tail the JSONL
    log, filter to one agent / severity / operation, summarise it,
    or export the filtered view for incident review.

    Per [[cross-product-agent-parity]] the flag shape + supported
    field set match the kbounce + dbounce equivalents; muscle memory
    transfers across the Bounce suite. Per [[self-host-zero-billing-
    dependency]] no network calls; everything runs on the local file.
    Per [[creates-never-mutates]] read-only — the command never
    edits or rotates the log.
    """


@audit_group.command("tail")
@click.option(
    "--path",
    "audit_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to the JSONL audit log to read. Defaults to "
         "$IAM_JIT_BOUNCER_AUDIT_LOG or ~/.iam-jit/audit.jsonl. The "
         "path must match the `ibounce run --audit-log-path` value "
         "used when the bouncer was started; the read side has no "
         "way to discover the writer's path otherwise.",
)
@click.option(
    "--follow", "-f",
    "follow",
    is_flag=True,
    default=False,
    help="Live-tail the log: poll every 500ms, print new rows as they "
         "arrive. Exit cleanly on SIGINT (Ctrl-C). Equivalent to "
         "`tail -F` over a JSONL file with OCSF parsing applied.",
)
@click.option(
    "--filter", "filter_exprs",
    multiple=True,
    metavar="EXPR",
    help="Filter expressions, repeatable; AND-combined. Forms: "
         "`field=value` (string equality), `field~regex` "
         "(re.search), `field>=N` / `field<=N` (numeric). Fields "
         "use OCSF dotted paths: e.g. `severity_id`, "
         "`actor.user.name`, `api.operation`, "
         "`unmapped.iam_jit.agent.name`, "
         "`unmapped.iam_jit.event_type`. Shortcut: `event_type` "
         "alone resolves to `unmapped.iam_jit.event_type` (with "
         "`DECISION` as the implicit value for plain decisions).",
)
@click.option(
    "--summary",
    is_flag=True,
    default=False,
    help="Emit a count-summary table instead of individual rows. "
         "Default groupings: event_type, severity_id, "
         "actor.user.name, api.operation. Combine with --filter to "
         "summarise a subset.",
)
@click.option(
    "--export",
    "export_format",
    type=click.Choice(["jsonl", "csv", "ocsf-bundle"], case_sensitive=False),
    default=None,
    help="Export the current view (after --filter) to a file. `jsonl` "
         "= one OCSF event per line; `csv` = tabular (see "
         "--csv-columns); `ocsf-bundle` = single OCSF v1.1.0 class "
         "2004 Detection Finding wrapping the events for SIEM batch "
         "import. Requires --out.",
)
@click.option(
    "--out",
    "out_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Destination path for --export. Parent directories are "
         "created on demand.",
)
@click.option(
    "--csv-columns",
    "csv_columns_raw",
    default=None,
    help="Override the CSV default column set. Comma-separated dotted "
         "paths, e.g. `time,actor.user.name,api.operation`. The "
         "default set omits PII-shaped fields (email, phone, "
         "credentials); opt in explicitly by naming them here.",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Read at most LIMIT events (newest filtered set). Default: "
         "no limit (entire file). Ignored with --follow.",
)
def audit_tail_cmd(
    audit_path: str | None,
    follow: bool,
    filter_exprs: tuple[str, ...],
    summary: bool,
    export_format: str | None,
    out_path: str | None,
    csv_columns_raw: str | None,
    limit: int | None,
) -> None:
    """Tail / filter / summarise / export the audit JSONL log.

    \b
    Examples:
      # All events, newest 200 first
      ibounce audit tail --limit 200

      # Live-tail new events from claude-code, severity >= 3
      ibounce audit tail --follow \\
          --filter unmapped.iam_jit.agent.name=claude-code \\
          --filter severity_id>=3

      # Per-event-type / severity / actor / operation breakdown
      ibounce audit tail --summary

      # Export filtered view for incident review
      ibounce audit tail \\
          --filter unmapped.iam_jit.agent.session_id=01968d6a-... \\
          --export ocsf-bundle --out /tmp/finding.json
    """
    from .bouncer.audit_export.tail import (
        FilterParseError,
        build_ocsf_bundle,
        default_audit_log_path,
        export_csv,
        export_jsonl,
        export_ocsf_bundle,
        follow_audit_file,
        iter_audit_file,
        parse_filter_expr,
        render_event_row,
        render_summary,
        resolve_csv_columns,
        summarize_events,
    )

    # --follow and --summary are conceptually opposed (one streams
    # row by row; the other aggregates a closed set). Surface the
    # clash early with an actionable message rather than silently
    # picking one — per the spec's clash test.
    if follow and summary:
        click.secho(
            "ERROR: --follow streams individual events; --summary "
            "aggregates a closed set. Pick one.",
            fg="red", err=True,
        )
        sys.exit(2)
    if export_format and not out_path:
        click.secho(
            "ERROR: --export requires --out PATH.",
            fg="red", err=True,
        )
        sys.exit(2)
    if out_path and not export_format:
        click.secho(
            "ERROR: --out requires --export FORMAT.",
            fg="red", err=True,
        )
        sys.exit(2)

    # Parse filters first so a bad expression fails before we touch
    # the disk. The error message names the offending expression.
    parsed_filters = []
    for raw in filter_exprs:
        try:
            parsed_filters.append(parse_filter_expr(raw))
        except FilterParseError as e:
            click.secho(f"ERROR: {e}", fg="red", err=True)
            sys.exit(2)

    path = pathlib.Path(audit_path) if audit_path else default_audit_log_path()

    # --follow path: stream + filter live; exit on SIGINT. Cannot be
    # combined with --export (the export needs a closed input set;
    # the spec's --filter+--export composition test exercises the
    # non-follow path).
    if follow:
        import signal

        stop_flag = {"stop": False}

        def _handler(signum, frame):  # noqa: ARG001
            stop_flag["stop"] = True

        prev_int = signal.signal(signal.SIGINT, _handler)
        try:
            try:
                for event in follow_audit_file(
                    path, stop_flag=stop_flag,
                ):
                    if parsed_filters and not all(
                        f.matches(event) for f in parsed_filters
                    ):
                        continue
                    click.echo(render_event_row(event))
            except KeyboardInterrupt:
                # Defensive: the signal handler should have flipped
                # stop_flag and the generator returned, but cover the
                # case where the OS delivers the interrupt at an
                # unfortunate moment.
                pass
        finally:
            signal.signal(signal.SIGINT, prev_int)
        return

    # Non-follow path: read whole file, filter, optionally limit.
    def _read_events():
        for ev in iter_audit_file(path):
            if parsed_filters and not all(
                f.matches(ev) for f in parsed_filters
            ):
                continue
            yield ev

    events: list[dict[str, Any]] = list(_read_events())
    if limit is not None and limit >= 0:
        # Newest-first: keep the tail end of the list since the JSONL
        # writer appends, so the file is oldest-first on disk. The
        # final printed order is still oldest-first within the slice
        # (matches `tail -n N` semantics).
        events = events[-limit:]

    if export_format:
        out_pth = pathlib.Path(out_path)  # type: ignore[arg-type]
        fmt = export_format.lower()
        if fmt == "jsonl":
            n = export_jsonl(events, out_pth)
            click.echo(f"wrote {n} event(s) as JSONL to {out_pth}")
        elif fmt == "csv":
            cols_explicit = None
            if csv_columns_raw:
                cols_explicit = [c.strip() for c in csv_columns_raw.split(",")]
            cols, warnings = resolve_csv_columns(cols_explicit)
            if warnings:
                # Surface PII opt-in to stderr — the operator chose
                # to include the column, so we don't refuse; we just
                # make the choice visible in the run log.
                click.secho(
                    "note: --csv-columns includes PII-shaped field(s): "
                    + ", ".join(warnings)
                    + " — these are not in the default column set.",
                    fg="yellow", err=True,
                )
            n = export_csv(events, out_pth, columns=cols)
            click.echo(f"wrote {n} event(s) as CSV to {out_pth}")
        elif fmt == "ocsf-bundle":
            n = export_ocsf_bundle(events, out_pth)
            click.echo(
                f"wrote OCSF Detection Finding bundling {n} event(s) "
                f"to {out_pth}"
            )
        # `build_ocsf_bundle` is referenced via export_ocsf_bundle; the
        # import above keeps it available for direct callers.
        _ = build_ocsf_bundle  # silence "imported but unused" linters
        return

    if summary:
        out_struct = summarize_events(events)
        click.echo(render_summary(out_struct))
        return

    if not events:
        click.echo("(no events in audit log)")
        return
    for ev in events:
        click.echo(render_event_row(ev))


@main.group("audit-export")
def audit_export_group() -> None:
    """#267 — operator commands for the audit-export channel.

    Wraps the same /healthz audit_export block external monitoring
    polls — the CLI is the human-friendly view for "did the
    visibility channel break overnight?" The subcommands hit a
    running bouncer over HTTP so the values reflect the live process
    state (not a stale config dump).

    Per [[audit-export-failure-visibility]]: keep the channel
    OBSERVABLE — every degraded condition should be ONE command
    away from the operator, not buried in a SIEM dashboard the
    on-call engineer doesn't have access to.
    """


def _audit_export_default_url() -> str:
    """Default `ibounce run` healthz URL — loopback + the port the
    `run` subcommand listens on. Operators override with --url for
    non-default deployments."""
    return "http://127.0.0.1:8767/healthz"


def _format_seconds_ago(seconds: int | None) -> str:
    """Human-readable 'how long ago' for the CLI table. None means
    'never happened yet' (e.g. webhook configured but no send attempt
    has fired yet)."""
    if seconds is None:
        return "never"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    return f"{seconds // 3600}h ago"


def _print_audit_export_health_table(section: dict) -> None:
    """Pretty-print the /healthz audit_export section as a two-column
    table. Format spec'd in the [[audit-export-failure-visibility]]
    memo. Token + URL userinfo are NEVER printed in the raw — we
    surface what /healthz emits (already masked by the pusher's
    status()).
    """
    rows: list[tuple[str, str]] = []
    rows.append(("Log channel configured", str(section.get("configured", False))))
    rows.append(("Log writes OK", str(section.get("log_writes_ok", True))))
    rows.append(("Log path", str(section.get("log_path") or "—")))
    log_err = section.get("log_last_error")
    rows.append(("Log last error", str(log_err) if log_err else "—"))
    rows.append((
        "Webhook configured",
        str(section.get("webhook_configured", False)),
    ))
    rows.append((
        "Webhook URL (masked)",
        str(section.get("webhook_url_masked") or "—"),
    ))
    rows.append((
        "Webhook last success",
        _format_seconds_ago(section.get("webhook_last_success_seconds_ago")),
    ))
    rows.append((
        "Webhook last attempt",
        _format_seconds_ago(section.get("webhook_last_attempt_seconds_ago")),
    ))
    code = section.get("webhook_last_status_code")
    rows.append((
        "Webhook last status code",
        str(code) if code is not None else "—",
    ))
    rows.append((
        "Webhook consecutive failures",
        str(section.get("webhook_consecutive_failures", 0)),
    ))
    wh_err = section.get("webhook_last_error")
    rows.append(("Webhook last error", str(wh_err) if wh_err else "—"))
    rows.append((
        "Dropped events (since start)",
        str(section.get("dropped_count_since_start", 0)),
    ))
    rows.append((
        "Queue depth / capacity",
        f"{section.get('queue_depth', 0)} / {section.get('queue_capacity', 0)}",
    ))
    rows.append(("Degraded", str(section.get("degraded", False))))
    reasons = section.get("degraded_reasons") or []
    if reasons:
        rows.append(("Degraded reasons", "; ".join(reasons)))
    # Compute column widths; cap value width so a long URL doesn't
    # break the table.
    label_w = max(len(r[0]) for r in rows)
    for label, value in rows:
        # Don't truncate — the operator wants to see the full reason
        # string when something is broken.
        click.echo(f"  {label:<{label_w}}  {value}")


@audit_export_group.command("health")
@click.option(
    "--url",
    default=None,
    help="HTTP /healthz URL of the running ibounce proxy. Defaults to "
         "http://127.0.0.1:8767/healthz (the loopback port `ibounce "
         "run` binds by default).",
)
@click.option(
    "--timeout",
    type=float,
    default=5.0,
    show_default=True,
    help="HTTP timeout in seconds for the /healthz GET.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Emit the raw audit_export block as JSON instead of a "
         "pretty-printed table. Useful in scripts / monitoring "
         "wrappers; the exit code still reflects the degraded "
         "verdict.",
)
def audit_export_health_cmd(
    url: str | None, timeout: float, as_json: bool,
) -> None:
    """#267 — explicit health check of the audit-export channel.

    Hits the running ibounce proxy's /healthz endpoint, extracts the
    audit_export block, prints it as a table (or JSON), and exits
    non-zero when the channel is degraded so monitoring scripts can
    chain on the exit code.

    Exit codes:
      0 — channel healthy (or not configured, which means nothing
          can fail)
      2 — channel degraded (one of: log_writes_ok=false, webhook
          consecutive_failures > 3, webhook silent > 5min)
      3 — could not reach /healthz (proxy not running, wrong URL,
          network error) — operator should investigate as a separate
          failure mode from a degraded channel

    Re-uses the same logic as /healthz on purpose: the CLI + the
    probe report identical values. No divergence between "what the
    monitor sees" and "what the operator sees."
    """
    import urllib.error
    import urllib.request

    target = url or _audit_export_default_url()
    req = urllib.request.Request(
        target,
        headers={"Accept": "application/json"},
    )
    body: dict | None = None
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
        body = json.loads(raw)
    except urllib.error.HTTPError as e:
        # /healthz flips to 503 when degraded; the body is still a
        # valid JSON document we want to surface. Other 4xx/5xx
        # codes are unexpected here but we still try to parse the
        # body before giving up.
        try:
            raw = e.read()
            body = json.loads(raw)
        except Exception:
            click.secho(
                f"audit-export health: /healthz at {target} returned "
                f"HTTP {e.code} with unparseable body: {e}",
                fg="red", err=True,
            )
            sys.exit(3)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
        click.secho(
            f"audit-export health: could not reach {target}: {e}",
            fg="red", err=True,
        )
        click.echo(
            "  is the bouncer running? "
            "start it with `ibounce run` (or pass --url for a "
            "non-default deployment).",
            err=True,
        )
        sys.exit(3)
    assert body is not None
    section = body.get("audit_export")
    if not isinstance(section, dict):
        click.secho(
            f"audit-export health: /healthz at {target} returned no "
            f"audit_export block. Is this an older bouncer build "
            f"(pre-#267)?",
            fg="red", err=True,
        )
        sys.exit(3)
    if as_json:
        click.echo(json.dumps(section, indent=2, default=str))
    else:
        click.echo("audit-export channel health:")
        _print_audit_export_health_table(section)
    if bool(section.get("degraded", False)):
        # Non-zero exit so monitoring wrappers can chain on $?.
        sys.exit(2)


@main.command("version-check")
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress the up-to-date message; only print when a newer "
         "release is available OR a network error occurred.",
)
@click.option(
    "--timeout",
    type=float,
    default=5.0,
    show_default=True,
    help="HTTP timeout in seconds for the GitHub Releases GET.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Bypass the 1-hour cache + force a fresh GitHub Releases GET. "
         "Result is still written to the cache for the next call.",
)
def version_check_cmd(quiet: bool, timeout: float, no_cache: bool) -> None:
    """Check whether a newer ibounce release is published on GitHub.

    Opt-in, operator-initiated — NOT phone-home. Sends one anonymous
    HTTPS GET to the public GitHub Releases endpoint
    (api.github.com/repos/trsreagan3/iam-jit/releases/latest). No data
    about your install is transmitted; the response is parsed +
    printed locally. Result is cached for 1 hour at
    `~/.iam-jit/bouncer/version_check.json` so repeated calls don't
    hammer GitHub.

    Honors IBOUNCE_NO_VERSION_CHECK=1 (and the IAM_JIT_NO_VERSION_CHECK
    alias) for airgapped deployments — when either is set, the command
    refuses to call out + prints a one-line acknowledgement. This
    subcommand NEVER runs as a side-effect of any other ibounce
    subcommand; it only fires on explicit `ibounce version-check`.

    Exits 0 in every case (informational; a stale install or transient
    network error should not fail the shell).
    """
    import urllib.error
    import urllib.request

    from . import __version__ as local_version

    # Env-var opt-out: short-circuit BEFORE any urllib import-level
    # side effects matter; per the [[self-host-zero-billing-dependency]]
    # invariant, an operator who sets this MUST be able to prove no
    # outbound call happens.
    for env_name in VERSION_CHECK_OPT_OUT_ENVS:
        if os.environ.get(env_name):
            click.echo(f"version-check disabled by {env_name}")
            return

    cache_path = _version_check_cache_path()

    # Cache read path — only if --no-cache wasn't passed.
    if not no_cache:
        cached = _read_version_check_cache(cache_path)
        if cached is not None and cached.get("latest"):
            latest_tag = _sanitize_for_print(str(cached["latest"]))
            url = _sanitize_for_print(str(cached.get("url") or ""), max_len=300)
            age_suffix = f" (cached, checked {_format_age(int(cached['age_seconds']))})"
            _print_version_comparison(
                local_version=local_version,
                latest_tag=latest_tag,
                url=url,
                quiet=quiet,
                suffix=age_suffix,
            )
            return

    # Network path.
    req = urllib.request.Request(
        VERSION_CHECK_URL,
        headers={
            "User-Agent": f"ibounce-version-check/{local_version}",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
        data = json.loads(body)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
        # Network / parsing failure: print a soft error, exit 0.
        msg = _sanitize_for_print(str(e), max_len=120)
        click.echo(
            f"ibounce {local_version} — unable to reach GitHub Releases "
            f"(network error: {msg}). This is a soft check; not a phone-home."
        )
        return

    if not isinstance(data, dict):
        click.echo(
            f"ibounce {local_version} — unable to reach GitHub Releases "
            "(network error: unexpected response shape). This is a soft "
            "check; not a phone-home."
        )
        return

    latest_tag_raw = data.get("tag_name") or ""
    url_raw = data.get("html_url") or ""
    latest_tag = _sanitize_for_print(str(latest_tag_raw))
    url = _sanitize_for_print(str(url_raw), max_len=300)

    if not latest_tag:
        click.echo(
            f"ibounce {local_version} — unable to reach GitHub Releases "
            "(network error: response missing tag_name). This is a soft "
            "check; not a phone-home."
        )
        return

    # Persist to cache regardless of comparison outcome (the call
    # succeeded — the result is the result).
    try:
        _write_version_check_cache(cache_path, latest=latest_tag, url=url)
    except OSError:
        # Cache write failure is non-fatal; the comparison still works.
        pass

    _print_version_comparison(
        local_version=local_version,
        latest_tag=latest_tag,
        url=url,
        quiet=quiet,
        suffix="",
    )


def _print_version_comparison(
    *,
    local_version: str,
    latest_tag: str,
    url: str,
    quiet: bool,
    suffix: str,
) -> None:
    """Shared comparison + print routine for both the network + cache
    paths. Keeps the up-to-date / newer / unknown branches in one place
    so the cache + network branches can never drift on output shape."""
    local_tuple = _parse_semver_tag(local_version)
    remote_tuple = _parse_semver_tag(latest_tag)

    if local_tuple is not None and remote_tuple is not None:
        if remote_tuple > local_tuple:
            url_part = f" Release notes: {url}" if url else ""
            click.echo(
                f"ibounce {local_version} — {latest_tag} available."
                f"{url_part}{suffix}"
            )
            return
        # equal OR local is newer (dev build): treat as up-to-date.
        if not quiet:
            click.echo(f"ibounce {local_version} — up to date.{suffix}")
        return

    # Fallback: literal string compare when either side isn't clean
    # semver. Conservative — we only claim "newer available" with
    # confidence; otherwise print the latest tag for the operator to
    # judge.
    if latest_tag.lstrip("vV") == local_version.lstrip("vV"):
        if not quiet:
            click.echo(f"ibounce {local_version} — up to date.{suffix}")
        return
    url_part = f" Release notes: {url}" if url else ""
    click.echo(
        f"ibounce {local_version} — latest published tag is {latest_tag}."
        f"{url_part}{suffix}"
    )


# ---------------------------------------------------------------------------
# config export / import (#275) — cross-product Tier-1 hygiene
#
# Per [[cross-product-agent-parity]] the CLI shape MUST match kbounce +
# dbounce verbatim:
#
#   ibounce config export --out PATH [--redact-secrets] [--include-audit] [--include-prompts]
#   ibounce config import --in PATH [--merge | --replace] [--dry-run]
#
# Both commands fan out to `bouncer.config_io`. Admin-action emission +
# the redaction defaults live there; this file holds only the Click
# wiring + the operator-facing print surface.
# ---------------------------------------------------------------------------


@main.group("config")
def config_group() -> None:
    """Backup, restore, and migrate the ibounce configuration surface.

    Round-trips profiles + rules + tasks + presets + audit-export
    pointers + alert-rules + MCP-install history + license-pointer to
    a single JSON file so an operator can back up before an upgrade,
    move a deployment, or feed a change-management diff.

    Tokens / URLs / env-var values / license content are MASKED in the
    export by default (per [[push-policy-public-repo]]); live secrets
    belong in #279 SQLite backup.
    """


@config_group.command("export")
@click.option(
    "--out", "out_path", type=click.Path(dir_okay=False), required=True,
    help="Destination JSON file. Created with mode 0600.",
)
@click.option(
    "--redact-secrets/--no-redact-secrets", default=True, show_default=True,
    help="Redact webhook tokens, license content, env-var values. "
         "Default on; ibounce REFUSES to disable it — backups with "
         "live tokens belong in the SQLite-backup channel (#279).",
)
@click.option(
    "--include-audit", is_flag=True, default=True, show_default=True,
    help="Include the audit-webhook channel pointer + alert-rules YAML. "
         "Default on; the contents are still redacted per --redact-secrets.",
)
@click.option(
    "--include-prompts", is_flag=True, default=False, show_default=True,
    help="Reserved for future use. v1.0 always excludes pending prompts "
         "from the bundle (they are transient queue state per the "
         "dbounce-9608b14 'what does NOT ship' list).",
)
@click.option(
    "--db", type=click.Path(dir_okay=False), default=None,
    help="Override the SQLite store path (default ~/.iam-jit/bouncer/state.db).",
)
@click.option(
    "--profiles", "profiles_path",
    type=click.Path(dir_okay=False), default=None,
    help="Override the profiles.yaml path (default "
         "~/.iam-jit/bouncer/profiles.yaml).",
)
@click.option(
    "--alert-rules", "alert_rules_path",
    type=click.Path(dir_okay=False), default=None,
    help="Path of the configured --alert-rules YAML to inline into "
         "the bundle. Empty / omitted = section emitted with null body.",
)
@click.option(
    "--active-profile", "active_profile", default=None,
    help="Record this profile name as the active selection. Defaults "
         "to $IAM_JIT_BOUNCER_PROFILE.",
)
def config_export_cmd(
    out_path: str,
    redact_secrets: bool,
    include_audit: bool,
    include_prompts: bool,
    db: str | None,
    profiles_path: str | None,
    alert_rules_path: str | None,
    active_profile: str | None,
) -> None:
    """Export ibounce configuration to a redacted JSON bundle.

    The bundle is portable across the Bounce suite — kbounce + dbounce
    ship the same skeleton with their own `product` field. The wire
    shape lets you author one cross-product backup workflow.
    """
    # The --redact-secrets / --no-redact-secrets flag is wired only so
    # operators discovering it via --help see WHY redaction is locked
    # on. Per the brief: "If the export needs to NOT be redacted (rare;
    # for trusted-channel backup): refuse — the only path is the
    # redacted file. Backups with live tokens belong in #279."
    if not redact_secrets:
        click.echo(
            "ERROR: ibounce config export does not support unredacted "
            "bundles. Live tokens belong in the SQLite-backup channel "
            "(#279). The redacted bundle is checkable into a config "
            "repo without further sanitisation.",
            err=True,
        )
        sys.exit(2)
    # --include-prompts is reserved; today's behavior is to ignore it.
    _ = include_prompts
    from .bouncer.config_io import (
        build_export,
        emit_export_admin_action,
        write_export,
    )

    bundle = build_export(
        db_path=db,
        profiles_path=profiles_path,
        alert_rules_path=alert_rules_path if include_audit else None,
        active_profile=active_profile,
    )
    if not include_audit:
        # Caller opted out of the audit-webhook + alert-rules sections.
        bundle["audit_webhook"] = {
            "log_path": "",
            "webhook_url": "***",
            "webhook_token": "***",
            "redaction_hint": "section omitted via --include-audit=false",
            "env_keys_present": [],
        }
        bundle["alert_rules"] = {"path": "", "content": None}
    target = write_export(bundle, out_path)
    with _opened_store(db) as store:
        emit_export_admin_action(
            store, out_path=target, actor=_current_actor(),
            extra={"profiles": len(bundle.get("profiles", {}).get("items") or []),
                   "rules": len(bundle.get("rules") or [])},
        )
    click.echo(f"exported {target}")
    click.echo(
        f"  profiles: {len(bundle.get('profiles', {}).get('items') or [])}, "
        f"rules: {len(bundle.get('rules') or [])}, "
        f"tasks: {len(bundle.get('tasks') or [])}, "
        f"presets: {len(bundle.get('presets') or [])}"
    )
    click.echo("  webhook tokens + license content are redacted by default.")


@config_group.command("preview-routes")
@click.option(
    "--routes", "routes_path",
    type=click.Path(dir_okay=False, exists=True), required=True,
    help="#280 — path to the --alert-routes YAML to evaluate.",
)
@click.option(
    "--event", "event_path",
    type=click.Path(dir_okay=False, exists=True), required=True,
    help="#280 — path to a JSON file containing one OCSF event "
         "(decision, anomaly, heartbeat, etc.) to evaluate against "
         "the routes.",
)
def config_preview_routes_cmd(routes_path: str, event_path: str) -> None:
    """Dry-run a sample event against an --alert-routes YAML file.

    Loads the routes config + evaluates a single OCSF event against
    every route, printing which routes matched + the masked
    destinations each match would have dispatched to. No HTTP traffic
    is sent. Per [[per-org-notification-routing]] this is mandatory
    pre-deploy validation — YAML routing is dense + error-prone.

    Example:

        $ export SOC_SPLUNK_HEC_TOKEN=abc12345secret
        $ ibounce config preview-routes \\
              --routes ~/.iam-jit/ibounce-routes.yaml \\
              --event sample-event.json

    The output never prints any secret value; tokens render as
    `eight-char-prefix***`.
    """
    import json as _json

    from .bouncer.audit_export import (
        RoutesConfigError,
        load_routes_config,
        select_routes,
    )

    try:
        cfg = load_routes_config(routes_path, product="ibounce")
    except RoutesConfigError as e:
        click.secho(f"routes config error: {e}", fg="red", err=True)
        sys.exit(2)
    try:
        with open(event_path, encoding="utf-8") as f:
            event = _json.load(f)
    except (OSError, _json.JSONDecodeError) as e:
        click.secho(
            f"could not read --event JSON file {event_path!r}: {e}",
            fg="red", err=True,
        )
        sys.exit(2)
    if not isinstance(event, dict):
        click.secho(
            f"--event file must contain a JSON object; got "
            f"{type(event).__name__}",
            fg="red", err=True,
        )
        sys.exit(2)

    click.echo(f"routes config: {routes_path}")
    click.echo(f"event: {event_path}")
    click.echo(f"total routes defined: {len(cfg.routes)}")
    secrets = cfg.secrets_used()
    if secrets:
        click.echo("secrets resolved (env-var name + masked prefix):")
        for env_name, masked in secrets:
            click.echo(f"  {env_name} ({masked})")
    hits = select_routes(event, cfg.routes)
    if not hits:
        click.echo("no routes matched this event.")
        return
    click.echo(f"matched {len(hits)} route(s):")
    for route in hits:
        click.echo(f"  - {route.name} (on_match={route.on_match})")
        for dest in route.destinations:
            masked = dest.masked()
            details = ", ".join(f"{k}={v}" for k, v in masked.items())
            click.echo(f"      destination: {details}")


@config_group.command("import")
@click.option(
    "--in", "in_path", type=click.Path(dir_okay=False), required=True,
    help="Source JSON bundle.",
)
@click.option(
    "--merge", "merge_flag", is_flag=True, default=False,
    help="Union with the existing config; collisions keep the existing "
         "value + emit a note. Default when neither flag is passed.",
)
@click.option(
    "--replace", "replace_flag", is_flag=True, default=False,
    help="Clear the importing categories first, then load the bundle "
         "wholesale. Removes existing rules + overwrites profiles.yaml.",
)
@click.option(
    "--dry-run", "dry_run", is_flag=True, default=False,
    help="Print what would change (counts per section + collision "
         "list) and exit without mutating. Still emits a config.import "
         "admin-action row with result=noop so SIEM dashboards see the "
         "planning activity.",
)
@click.option(
    "--db", type=click.Path(dir_okay=False), default=None,
    help="Override the SQLite store path (default ~/.iam-jit/bouncer/state.db).",
)
@click.option(
    "--profiles", "profiles_path",
    type=click.Path(dir_okay=False), default=None,
    help="Override the profiles.yaml path (default "
         "~/.iam-jit/bouncer/profiles.yaml).",
)
def config_import_cmd(
    in_path: str,
    merge_flag: bool,
    replace_flag: bool,
    dry_run: bool,
    db: str | None,
    profiles_path: str | None,
) -> None:
    """Import a previously-exported ibounce config bundle.

    Refuses cross-product imports (kbounce / dbounce bundles bounce
    with a "value X not in enum [ibounce]" error). Refuses unsupported
    schema_version with a "this binary supports versions X, Y, Z"
    message. Refuses if `ibounce run` is live on the loopback probe
    port — stop the proxy first.
    """
    if merge_flag and replace_flag:
        click.echo(
            "ERROR: --merge and --replace are mutually exclusive.",
            err=True,
        )
        sys.exit(2)
    if dry_run:
        mode = "dry-run"
    elif replace_flag:
        mode = "replace"
    else:
        mode = "merge"

    from .bouncer.config_io import (
        ConfigBundleError,
        apply_import,
        emit_import_admin_action,
        is_ibounce_running,
        load_bundle,
    )

    if not dry_run and is_ibounce_running():
        click.echo(
            "ERROR: ibounce appears to be running (loopback probe on "
            "127.0.0.1:8767 succeeded). Stop ibounce first — importing "
            "while the proxy holds an open SQLite connection would race "
            "on the rules / tasks tables. Re-run after `pkill ibounce` "
            "or set IBOUNCE_PROBE_PORT to the actual port if you "
            "moved off the default.",
            err=True,
        )
        sys.exit(2)

    try:
        bundle = load_bundle(in_path)
    except ConfigBundleError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)

    summary = apply_import(
        bundle,
        mode=mode,
        db_path=db,
        profiles_path=profiles_path,
        actor=_current_actor(),
    )
    with _opened_store(db) as store:
        emit_import_admin_action(
            store, in_path=in_path, summary=summary, actor=_current_actor(),
        )
    click.echo(f"import mode: {summary.mode}")
    click.echo(
        f"  profiles: added={summary.profiles_added} "
        f"collided={summary.profiles_collided} "
        f"replaced={summary.profiles_replaced}"
    )
    click.echo(
        f"  rules: added={summary.rules_added} "
        f"collided={summary.rules_collided} "
        f"replaced={summary.rules_replaced}"
    )
    if summary.tasks_carried:
        click.echo(
            f"  tasks: {summary.tasks_carried} carried (informational; "
            "tasks are NOT replayed)"
        )
    if summary.presets_carried:
        click.echo(
            f"  presets: {summary.presets_carried} preset-apply events "
            "carried (informational; rules already landed in store)"
        )
    if summary.collision_notes:
        click.echo("  notes:")
        for note in summary.collision_notes:
            click.echo(f"    - {note}")


# ---------------------------------------------------------------------------
# diagnostics bundle (#277) — cross-product Tier-1 support-package ZIP
#
# Per [[cross-product-agent-parity]] the CLI shape matches kbounce +
# dbounce verbatim:
#
#   ibounce diagnostics bundle [--out PATH] [--include-audit-tail N]
#                              [--no-audit] [--panic-log PATH]
#                              [--insecure-skip-verify]
#   ibounce diag bundle ...    (alias matching kbounce + dbounce)
#
# The bundle is the operator's to share with support OR a Claude
# agent. Strictly READ-ONLY per [[creates-never-mutates]]; only
# network call is a single LOCAL /healthz GET per
# [[self-host-zero-billing-dependency]].
# ---------------------------------------------------------------------------


def _add_diagnostics_subcommands(group: click.Group) -> None:
    """Attach the `bundle` subcommand under whichever parent group
    is passed. Shared between `ibounce diagnostics` + `ibounce diag`
    so the alias resolves to the same Click command object — no
    duplicate flag-definition site."""

    @group.command("bundle")
    @click.option(
        "--out", "out_path", type=click.Path(dir_okay=False), default=None,
        help="Output ZIP path. Default: "
             "./ibounce-diagnostics-{UTC-timestamp}.zip. Parent dirs are "
             "created on demand.",
    )
    @click.option(
        "--include-audit-tail", "include_audit_tail",
        type=int, default=200, show_default=True,
        help="Include the last N audit-log events (REDACTED — user "
             "identifiers stably hashed, URLs / tokens masked). "
             "Default 200.",
    )
    @click.option(
        "--no-audit", is_flag=True, default=False,
        help="Suppress the audit-tail section entirely. Use when the "
             "audit log itself is the surface you don't want to share "
             "(regulated environments where even hashed-id events "
             "are sensitive).",
    )
    @click.option(
        "--panic-log", "panic_log_path",
        type=click.Path(dir_okay=False), default=None,
        help="Path to a captured stderr / panic file to include "
             "(REDACTED via regex pass). Optional — bundle works "
             "without it.",
    )
    @click.option(
        "--insecure-skip-verify", "insecure_skip_verify",
        is_flag=True, default=False,
        help="Skip TLS verification on the /healthz GET. Useful for "
             "dev-cert deployments.",
    )
    @click.option(
        "--healthz-url", "healthz_url", default=None,
        help="URL of the running ibounce proxy's /healthz. Defaults "
             "to http://127.0.0.1:8767/healthz (the loopback port "
             "`ibounce run` binds by default). Bundle records "
             "'unreachable' + the error reason when the GET fails — "
             "the command does NOT abort.",
    )
    @click.option(
        "--audit-log", "audit_log_path",
        type=click.Path(dir_okay=False), default=None,
        help="Path to the JSONL audit log to tail. Defaults to "
             "$IAM_JIT_BOUNCER_AUDIT_LOG_PATH.",
    )
    @click.option(
        "--db", type=click.Path(dir_okay=False), default=None,
        help="Override the SQLite store path (default "
             "~/.iam-jit/bouncer/state.db).",
    )
    @click.option(
        "--profiles", "profiles_path",
        type=click.Path(dir_okay=False), default=None,
        help="Override the profiles.yaml path (default "
             "~/.iam-jit/bouncer/profiles.yaml).",
    )
    @click.option(
        "--alert-rules", "alert_rules_path",
        type=click.Path(dir_okay=False), default=None,
        help="Path of the configured --alert-rules YAML to inline "
             "into the config section. Empty = section emitted with "
             "null body.",
    )
    def diagnostics_bundle_cmd(
        out_path: str | None,
        include_audit_tail: int,
        no_audit: bool,
        panic_log_path: str | None,
        insecure_skip_verify: bool,
        healthz_url: str | None,
        audit_log_path: str | None,
        db: str | None,
        profiles_path: str | None,
        alert_rules_path: str | None,
    ) -> None:
        """Produce a redacted diagnostics ZIP for sharing with support.

        Contents: ibounce version, redacted config, active profile
        pointer + sha256, last N audit events (user identifiers
        hashed), local /healthz snapshot, OS / Python metadata,
        listener pointers, optional panic-log capture, and a sha256
        manifest. Every section is redacted on the way in — the
        resulting ZIP is safe to share with support or paste to a
        Claude agent.

        Per [[creates-never-mutates]]: read-only. Per
        [[self-host-zero-billing-dependency]]: no network calls
        except a local /healthz GET on the loopback port.
        """
        import pathlib as _pathlib

        from .bouncer.diagnostics import (
            DEFAULT_HEALTHZ_URL,
            BundleOptions,
            default_bundle_path,
            emit_diagnostics_bundle_admin_action,
            write_diagnostics_bundle,
        )

        if include_audit_tail < 0:
            click.echo(
                "ERROR: --include-audit-tail must be >= 0.", err=True,
            )
            sys.exit(2)

        resolved_out = (
            _pathlib.Path(out_path) if out_path else default_bundle_path()
        )

        opts = BundleOptions(
            out_path=resolved_out,
            include_audit_tail=include_audit_tail,
            no_audit=no_audit,
            db_path=db,
            profiles_path=profiles_path,
            alert_rules_path=alert_rules_path,
            audit_log_path=audit_log_path,
            healthz_url=healthz_url or DEFAULT_HEALTHZ_URL,
            insecure_skip_verify=insecure_skip_verify,
            panic_log_path=panic_log_path,
        )
        summary = write_diagnostics_bundle(opts)

        # Emit the admin-action OCSF row so a security team has a
        # witness for "who pulled diagnostics + when?" The store
        # write is best-effort — a queue failure never fails the
        # user-facing bundle (the file has already landed).
        with _opened_store(db) as store:
            emit_diagnostics_bundle_admin_action(
                store, summary=summary, no_audit=no_audit,
                actor=_current_actor(),
            )

        click.echo(f"wrote {summary.out_path}")
        click.echo(
            f"  files: {summary.file_count}  "
            f"bytes: {summary.total_bytes}  "
            f"audit lines: {summary.audit_lines}  "
            f"healthz ok: {summary.healthz_ok}"
        )
        click.echo(
            "  contents are redacted by default; safe to share with "
            "support or paste to a Claude agent for analysis."
        )


@main.group("diagnostics")
def diagnostics_group() -> None:
    """Produce a redacted ZIP bundle for sharing with support.

    Subcommands:

      bundle    Write a redacted diagnostics ZIP to disk.

    The bundle contains everything needed to debug an ibounce
    deployment WITHOUT containing secrets: ibounce version, a
    redacted config snapshot, a tail of the audit log with user
    identifiers hashed, the local /healthz snapshot, OS / env
    metadata (KEY names only), and a sha256 manifest of every file.

    Sibling agents in kbounce + dbounce ship the same subcommand
    shape + flag names per [[cross-product-agent-parity]]:
    `{product} diag bundle --out ./bundle.zip` works against any
    Bounce.
    """


_add_diagnostics_subcommands(diagnostics_group)


@main.group("diag")
def diag_group() -> None:
    """Alias for `ibounce diagnostics`. Subcommands match verbatim.

    Operators learn one mnemonic — `{product} diag bundle` — across
    kbounce + ibounce + dbounce.
    """


_add_diagnostics_subcommands(diag_group)


# ---------------------------------------------------------------------------
# investigate (#273) — one-shot "give me a Claude-ready evidence pack"
#
# Composes the existing #268 audit-tail OCSF export + #277 diagnostics
# bundle into a single subcommand. The operator drops both artifacts
# into THEIR Claude session (Claude Code / Cursor / desktop / console)
# and runs an investigative prompt. ibounce never calls Anthropic —
# per [[self-host-zero-billing-dependency]] this is a strictly LOCAL
# workflow; per [[creates-never-mutates]] it's read-only.
#
# Cross-product alignment per [[cross-product-agent-parity]]: the same
# subcommand name + flag shape lives in kbounce / dbounce / gbounce
# so an operator running multiple bouncers learns ONE muscle-memory
# pattern.
# ---------------------------------------------------------------------------


@main.command("investigate")
@click.option(
    "--out-dir", "out_dir",
    type=click.Path(file_okay=False, dir_okay=True),
    default=None,
    help="Directory to write the two artifact files into. Default: a "
         "per-invocation tmpdir at "
         "$TMPDIR/ibounce-investigate-{UTC-timestamp}. Created on "
         "demand; existing same-named files are overwritten so a "
         "follow-up run inside the same --out-dir refreshes the "
         "pack without leaving stale copies.",
)
@click.option(
    "--time-range", "time_range",
    default=None,
    metavar="EXPR",
    help="Filter the audit-tail evidence to events from the last "
         "<N>{h,d,w} (e.g. '24h', '7d', '4w'). Default: no time "
         "filter (all events in the log). Translates to "
         "`time>=<unix-ms>` against the OCSF wire shape.",
)
@click.option(
    "--filter", "filter_exprs",
    multiple=True,
    metavar="EXPR",
    help="Extra filter expression(s) forwarded to the audit-tail "
         "layer. Same grammar as `ibounce audit tail --filter`: "
         "field=value / field~regex / field>=N / field<=N. "
         "Repeatable; AND-combined.",
)
@click.option(
    "--print-prompts", "print_prompts",
    is_flag=True,
    default=False,
    help="Print the 10 starter investigative prompts as a "
         "paste-able block and exit WITHOUT writing artifact files. "
         "Useful for refreshing a runbook or scripting a "
         "non-interactive Claude pipeline.",
)
@click.option(
    "--audit-log", "audit_log_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to the JSONL audit log to read. Defaults to "
         "$IAM_JIT_BOUNCER_AUDIT_LOG or ~/.iam-jit/audit.jsonl. "
         "Must match the running `ibounce run --audit-log-path` "
         "value — the read side has no IPC to discover the writer's "
         "path otherwise.",
)
@click.option(
    "--db", type=click.Path(dir_okay=False), default=None,
    help="Override the SQLite store path consulted by the embedded "
         "diagnostics bundle (default ~/.iam-jit/bouncer/state.db).",
)
@click.option(
    "--profiles", "profiles_path",
    type=click.Path(dir_okay=False), default=None,
    help="Override the profiles.yaml path consulted by the embedded "
         "diagnostics bundle (default ~/.iam-jit/bouncer/profiles.yaml).",
)
@click.option(
    "--healthz-url", "healthz_url",
    default=None,
    help="URL of the running ibounce proxy's /healthz endpoint. "
         "Defaults to http://127.0.0.1:8767/healthz. The context "
         "bundle records 'unreachable' + the error reason if the "
         "GET fails; the command does NOT abort.",
)
def investigate_cmd(
    out_dir: str | None,
    time_range: str | None,
    filter_exprs: tuple[str, ...],
    print_prompts: bool,
    audit_log_path: str | None,
    db: str | None,
    profiles_path: str | None,
    healthz_url: str | None,
) -> None:
    """Land a Claude-ready evidence pack for local investigation.

    \b
    Two files are written into --out-dir:
      ibounce-investigation.ndjson           OCSF Detection Finding
                                              wrapping the filtered
                                              audit-tail events
      ibounce-investigation-context.zip      redacted diagnostics
                                              bundle (config /
                                              profile / healthz /
                                              system info)

    \b
    The subcommand does NOT call Claude. Open your local Claude
    client (Claude Code, Cursor's Claude integration, the desktop
    app — whichever you use), drop both files into the
    conversation, then ask an investigative question. See
    docs/INVESTIGATE-WITH-CLAUDE.md for the full workflow.

    \b
    Per [[self-host-zero-billing-dependency]] the subcommand never
    calls Anthropic — the only network call is a single LOCAL
    /healthz GET on loopback (same as `diagnostics bundle`).
    Per [[creates-never-mutates]] it is read-only against the store,
    the profiles file, and the audit log.

    \b
    Examples:
      # Default: write to a per-invocation tmpdir
      ibounce investigate

      # Last 24h into a stable directory
      ibounce investigate --time-range 24h --out-dir ./out

      # Filter to one agent's denies, last 7d
      ibounce investigate --time-range 7d \\
          --filter unmapped.iam_jit.agent.name=claude-code \\
          --filter unmapped.iam_jit.verdict=deny

      # Refresh the runbook's prompt list
      ibounce investigate --print-prompts
    """
    import pathlib as _pathlib

    from .bouncer.audit_export.tail import (
        FilterParseError,
        default_audit_log_path,
        parse_filter_expr,
    )
    from .bouncer.investigate import (
        TimeRangeParseError,
        default_out_dir,
        parse_time_range,
        prepare_investigation,
        render_now_what_block,
        render_print_prompts_block,
    )

    if print_prompts:
        click.echo(render_print_prompts_block())
        return

    # Validate filters + time-range up front so a typo fails before
    # we touch the disk — same UX pattern as `audit tail`.
    for raw in filter_exprs:
        try:
            parse_filter_expr(raw)
        except FilterParseError as e:
            click.secho(f"ERROR: {e}", fg="red", err=True)
            sys.exit(2)

    window = None
    if time_range:
        try:
            window = parse_time_range(time_range)
        except TimeRangeParseError as e:
            click.secho(f"ERROR: {e}", fg="red", err=True)
            sys.exit(2)

    resolved_audit = (
        _pathlib.Path(audit_log_path) if audit_log_path
        else default_audit_log_path()
    )
    resolved_out_dir = (
        _pathlib.Path(out_dir) if out_dir else default_out_dir()
    )

    artifacts = prepare_investigation(
        out_dir=resolved_out_dir,
        audit_path=resolved_audit,
        extra_filters=tuple(filter_exprs),
        window=window,
        db_path=db,
        profiles_path=profiles_path,
        healthz_url=healthz_url,
    )

    click.echo(render_now_what_block(artifacts))


# ---------------------------------------------------------------------------
# backup + restore (#279) — SQLite snapshot + DR restore
#
# Two top-level subcommands matching the kbounce + dbounce sibling
# CLI shape per [[cross-product-agent-parity]]:
#
#   ibounce backup --out PATH [--include-audit] [--include-prompts]
#   ibounce restore --in PATH [--force]
#
# Backup is online (`VACUUM INTO` — no shutdown needed). Restore is
# destructive: gated on schema_version match (HARD), ibounce_version
# match (soft; --force overrides with warning), destination-empty
# (unless --force), and a TCP probe of the loopback management port
# to refuse if `ibounce run` is alive. Both commands emit
# `backup.create` / `backup.restore` ADMIN_ACTION OCSF rows so a
# SIEM dashboard sees the snapshot + DR lifecycle.
# ---------------------------------------------------------------------------


@main.command("backup")
@click.option(
    "--out", "out_path", type=click.Path(dir_okay=False), default=None,
    help="Output file path. Default: "
         "./ibounce-backup-{UTC-timestamp}.db. Parent dirs are "
         "created on demand.",
)
@click.option(
    "--include-audit", "include_audit", is_flag=True, default=False,
    help="Include the decisions + config_events + pending_audit_events "
         "tables in the backup (default: excluded — bulky + often "
         "redundant after a rotation policy fires).",
)
@click.option(
    "--include-prompts", "include_prompts", is_flag=True, default=False,
    help="Include the pending_prompts table in the backup (default: "
         "excluded — prompts are runtime state bound to in-flight "
         "proxy waiters that won't survive a restore anyway).",
)
@click.option(
    "--db", type=click.Path(dir_okay=False), default=None,
    help="SQLite source DB path. Default: ~/.iam-jit/bouncer/state.db "
         "(or $IAM_JIT_BOUNCER_DB).",
)
def backup_cmd(
    out_path: str | None,
    include_audit: bool,
    include_prompts: bool,
    db: str | None,
) -> None:
    """Write an online SQLite backup of the ibounce state DB to a file.

    Uses SQLite's VACUUM INTO primitive: the source database is NOT
    locked, concurrent writers continue uninterrupted, and the
    destination is an atomic single-file snapshot.

    Default contents EXCLUDE the audit-firehose tables (decisions,
    config_events, pending_audit_events) and the runtime
    pending_prompts table — these are bulky / runtime-bound. Pass
    `--include-audit` or `--include-prompts` to opt in.

    The backup file embeds an ibounce_backup_metadata table carrying:
    ibounce_version, created_at (RFC3339 UTC), source_hostname_hash
    (sha256[:12] of the source host's hostname), schema_version,
    included_audit / included_prompts flags. `ibounce restore` reads
    this metadata to validate cross-version + cross-schema restores.

    Sibling commands `kbounce backup` (kbouncer) + `dbounce backup`
    (dbounce) ship the same CLI shape + metadata-table format per
    [[cross-product-agent-parity]] so one shared tooling layer can
    target every Bounce.

    Per [[creates-never-mutates]]: backup is READ-ONLY against the
    source database. Per [[self-host-zero-billing-dependency]]: no
    network calls.
    """
    import pathlib as _pathlib

    from .bouncer.backup import (
        BackupError,
        BackupOptions,
        default_backup_path,
        emit_backup_create_admin_action,
        write_backup,
    )

    resolved_out = (
        _pathlib.Path(out_path) if out_path else default_backup_path()
    )

    opts = BackupOptions(
        out_path=resolved_out,
        include_audit=include_audit,
        include_prompts=include_prompts,
        db_path=db,
    )
    try:
        result = write_backup(opts)
    except BackupError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)

    # Emit the admin-action OCSF row so a security team has a
    # witness for "who snapshotted state + when?" The store write
    # is best-effort — a queue failure never fails the user-facing
    # backup (the file has already landed).
    with _opened_store(db) as store:
        emit_backup_create_admin_action(
            store, result=result, actor=_current_actor(),
        )

    click.echo(
        f"wrote ibounce backup to {result.out_path} "
        f"({result.size_bytes} bytes, sha256={result.sha256})"
    )
    click.echo(
        f"  schema_version={result.schema_version}  "
        f"ibounce_version={result.ibounce_version}  "
        f"created_at={result.created_at}"
    )
    click.echo(
        f"  source_hostname_hash={result.source_hostname_hash}  "
        f"included_audit={result.included_audit}  "
        f"included_prompts={result.included_prompts}"
    )
    if result.row_counts:
        click.echo("  tables:")
        for name in sorted(result.row_counts):
            click.echo(f"    {name:32s} {result.row_counts[name]} rows")


@main.command("restore")
@click.option(
    "--in", "in_path", type=click.Path(dir_okay=False), required=True,
    help="Path to the ibounce backup file to restore. Required.",
)
@click.option(
    "--force", is_flag=True, default=False,
    help="Override the non-empty-destination refusal + the "
         "ibounce_version-mismatch warning. Does NOT override "
         "schema_version mismatch (cross-schema migration is the "
         "future `ibounce migrate` story).",
)
@click.option(
    "--db", type=click.Path(dir_okay=False), default=None,
    help="Destination SQLite DB path. Default: "
         "~/.iam-jit/bouncer/state.db (or $IAM_JIT_BOUNCER_DB).",
)
@click.option(
    "--probe-skip", "probe_skip", is_flag=True, default=False,
    help="Skip the running-process TCP probe. Use only when the "
         "probe port is held by an unrelated process and you've "
         "manually verified ibounce is down.",
)
@click.option(
    "--probe-port", "probe_port", type=int, default=None,
    help="Override the loopback management port the probe dials "
         "(default 8767 — matches `ibounce run`'s default port).",
)
def restore_cmd(
    in_path: str,
    force: bool,
    db: str | None,
    probe_skip: bool,
    probe_port: int | None,
) -> None:
    """Replace ibounce's state DB with the contents of a backup file.

    Validation gates (all checked BEFORE the destructive copy):

    \b
      1. Source file exists + opens as a SQLite DB.
      2. Source carries the ibounce_backup_metadata table.
      3. schema_version match (HARD; --force does NOT override).
      4. ibounce_version match (soft; --force overrides with warning).
      5. Destination database must be empty OR --force.
      6. ibounce must not be running (TCP probe of loopback port
         8767). Pass --probe-skip if the port is held by an
         unrelated process and you've manually verified ibounce
         is down.

    On success, prints the per-table row counts of the restored
    database + its sha256 fingerprint.

    Per [[creates-never-mutates]]: restore is the one CLI surface
    that DOES mutate an existing DB; the destructive verb is gated
    by the explicit subcommand name + the --force semantics + the
    running-process probe.

    Cross-product-aligned with kbounce + dbounce per
    [[cross-product-agent-parity]]: same flag names, same
    refuse-without-force semantics, same metadata-table shape.
    """
    import pathlib as _pathlib

    from .bouncer.backup import (
        BackupError,
        DEFAULT_PROBE_PORT,
        DEFAULT_PROBE_TIMEOUT_SECONDS,
        IbounceVersionMismatchError,
        RestoreOptions,
        emit_backup_restore_admin_action,
        restore_from,
    )

    opts = RestoreOptions(
        in_path=_pathlib.Path(in_path),
        dest_db_path=db,
        force=force,
        probe_port=probe_port if probe_port is not None else DEFAULT_PROBE_PORT,
        probe_skip=probe_skip,
        probe_timeout_seconds=DEFAULT_PROBE_TIMEOUT_SECONDS,
    )
    try:
        result = restore_from(opts)
    except IbounceVersionMismatchError as e:
        # Specific class so the operator sees the actionable
        # "pass --force" hint clearly. The exception message already
        # carries the hint; surface it on stderr with exit 1.
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)
    except BackupError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)

    if result.version_mismatch:
        # Soft-mismatch surfaced under --force. Honest WARNING shape
        # (no "violation" framing per security-team-positioning).
        click.echo(
            f"WARNING: ibounce_version mismatch — backup was created by "
            f"ibounce {result.backup_ibounce_version!r}, running binary "
            f"is the current build. Continuing under --force.",
            err=True,
        )

    # Emit admin-action OCSF row. If ibounce was down at restore
    # time (the spec REQUIRES it), the running process picks the row
    # up from the freshly-restored DB on next start.
    with _opened_store(db) as store:
        emit_backup_restore_admin_action(
            store,
            in_path=_pathlib.Path(in_path),
            result=result,
            force=force,
            probe_skip=probe_skip,
            actor=_current_actor(),
        )

    click.echo(f"restored ibounce state.db from {in_path}")
    click.echo(f"  destination: {result.dest_path}")
    click.echo(f"  sha256: {result.sha256}")
    if result.row_counts:
        click.echo("  row counts:")
        for name in sorted(result.row_counts):
            click.echo(f"    {name:32s} {result.row_counts[name]} rows")


# ---------------------------------------------------------------------------
# `ibounce session ...` — #285 session recording / playback.
# ---------------------------------------------------------------------------


def _default_sessions_dir() -> pathlib.Path:
    return pathlib.Path.home() / ".iam-jit" / "bouncer" / "sessions"


def _format_ts_ms(ms: int | None) -> str:
    if ms is None:
        return "-"
    import datetime as _dt

    try:
        return (
            _dt.datetime.fromtimestamp(ms / 1000, tz=_dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (OverflowError, OSError, ValueError):
        return "-"


@main.group("session")
def session_group() -> None:
    """Per-session recording + replay (#285).

    Sessions are recorded into NDJSON files (one per agent session) when
    the proxy runs with `--record-sessions-dir`. Files are portable +
    replayable via the cross-product `iam-jit session replay <FILE>`
    command.

    Per [[creates-never-mutates]]: recording is additive (it tees the
    existing event stream); these subcommands are read-only over the
    recording files.

    Per [[self-host-zero-billing-dependency]]: entirely local
    filesystem; no phone-home.

    File permissions on recording files are 0o600 (owner-read-only) —
    recordings contain agent identity + operation details.
    """


@session_group.command("list")
@click.option(
    "--dir", "dir_path",
    type=click.Path(file_okay=False), default=None,
    help="Recordings dir. Defaults to ~/.iam-jit/bouncer/sessions/.",
)
@click.option("--json", "as_json", is_flag=True, default=False)
def session_list_cmd(dir_path: str | None, as_json: bool) -> None:
    """List recorded sessions with event counts + timestamps."""
    from .bouncer.audit_export import list_sessions

    target = pathlib.Path(dir_path) if dir_path else _default_sessions_dir()
    rows = list_sessions(target)
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo(f"no recordings in {target}")
        return
    click.echo(
        f"{'SESSION_ID':40s} {'AGENT':14s} {'EVENTS':>7s} "
        f"{'START':22s} {'END':22s}"
    )
    for r in rows:
        sid = r["session_id"]
        if r.get("is_partial"):
            sid = sid + " (partial)"
        click.echo(
            f"{sid:40s} {r['agent_name']:14s} {r['event_count']:>7d} "
            f"{_format_ts_ms(r['start_ms']):22s} "
            f"{_format_ts_ms(r['end_ms']):22s}"
        )


@session_group.command("show")
@click.argument("session_id")
@click.option(
    "--dir", "dir_path",
    type=click.Path(file_okay=False), default=None,
)
@click.option("--json", "as_json", is_flag=True, default=False)
def session_show_cmd(
    session_id: str, dir_path: str | None, as_json: bool,
) -> None:
    """Print a summary + event-count-by-type for one recording."""
    from .bouncer.audit_export import (
        event_count_by_type,
        read_session,
    )

    target = pathlib.Path(dir_path) if dir_path else _default_sessions_dir()
    try:
        meta, events = read_session(target, session_id)
    except FileNotFoundError as e:
        click.secho(str(e), fg="red", err=True)
        sys.exit(2)
    except ValueError as e:
        click.secho(str(e), fg="red", err=True)
        sys.exit(2)
    counts = event_count_by_type(events)
    summary = {
        "session_id": meta.get("session_id", session_id),
        "agent_name": meta.get("agent_name"),
        "bouncer_product": meta.get("bouncer_product"),
        "recording_schema_version": meta.get("recording_schema_version"),
        "recording_started_at": meta.get("recording_started_at"),
        "event_count": len(events),
        "events_by_activity": counts,
    }
    if as_json:
        click.echo(json.dumps(summary, indent=2))
        return
    click.echo(f"session_id:        {summary['session_id']}")
    click.echo(f"agent_name:        {summary['agent_name']}")
    click.echo(f"bouncer_product:   {summary['bouncer_product']}")
    click.echo(f"started_at:        {summary['recording_started_at']}")
    click.echo(f"schema_version:    {summary['recording_schema_version']}")
    click.echo(f"event_count:       {summary['event_count']}")
    if counts:
        click.echo("events by activity:")
        for k in sorted(counts):
            click.echo(f"  {k:32s} {counts[k]}")


@session_group.command("export")
@click.argument("session_id")
@click.option(
    "--dir", "dir_path",
    type=click.Path(file_okay=False), default=None,
)
@click.option(
    "--out", "out_path",
    type=click.Path(dir_okay=False), required=True,
    help="Output file. The session is wrapped in an OCSF Detection "
         "Finding envelope (matches #273 investigate-with-claude "
         "evidence shape).",
)
def session_export_cmd(
    session_id: str, dir_path: str | None, out_path: str,
) -> None:
    """Export a session as an OCSF Detection Finding JSON document."""
    from .bouncer.audit_export import (
        detection_finding_from_session,
        read_session,
    )

    target = pathlib.Path(dir_path) if dir_path else _default_sessions_dir()
    try:
        meta, events = read_session(target, session_id)
    except FileNotFoundError as e:
        click.secho(str(e), fg="red", err=True)
        sys.exit(2)
    except ValueError as e:
        click.secho(str(e), fg="red", err=True)
        sys.exit(2)
    finding = detection_finding_from_session(meta, events)
    out = pathlib.Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(finding, indent=2))
    try:
        os.chmod(out, 0o600)
    except OSError:
        pass
    click.echo(f"exported session {session_id} -> {out}")


@session_group.command("purge")
@click.option(
    "--dir", "dir_path",
    type=click.Path(file_okay=False), default=None,
)
@click.option(
    "--older-than", "older_than", required=True,
    help="Age threshold (e.g. '30d', '7d', '12h').",
)
@click.option(
    "--dry-run", is_flag=True, default=False,
    help="List files that would be removed without deleting.",
)
def session_purge_cmd(
    dir_path: str | None, older_than: str, dry_run: bool,
) -> None:
    """Remove recordings older than a threshold."""
    from .bouncer.audit_export import list_sessions, purge_older_than

    seconds = _parse_duration(older_than)
    target = pathlib.Path(dir_path) if dir_path else _default_sessions_dir()
    if dry_run:
        import time as _t

        threshold = _t.time() - seconds
        rows = list_sessions(target)
        to_remove = []
        for r in rows:
            if r.get("is_partial"):
                continue
            try:
                mtime = pathlib.Path(r["path"]).stat().st_mtime
            except OSError:
                continue
            if mtime < threshold:
                to_remove.append(r["path"])
        if not to_remove:
            click.echo(f"no recordings older than {older_than} in {target}")
            return
        click.echo(
            f"would remove {len(to_remove)} recording(s) older than "
            f"{older_than}:"
        )
        for p in to_remove:
            click.echo(f"  {p}")
        return
    removed = purge_older_than(target, older_than_seconds=seconds)
    click.echo(f"removed {len(removed)} recording(s) from {target}")
    for p in removed:
        click.echo(f"  {p}")


def main_deprecated_alias() -> None:
    """Console-script entrypoint for the deprecated `iam-jit-bouncer`
    name. Prints a one-line stderr deprecation warning + forwards to
    the canonical `ibounce` Click app with sys.argv intact.

    Per the Bounce-suite rename plan (2026-05-17): `iam-jit-bouncer`
    keeps working for v1.0 + is removed in v1.1. We don't add an
    `IBOUNCE_*` env-var alias — `IAM_JIT_BOUNCER_*` env vars stay as
    the canonical names (per the rename memo's backward-compat
    section)."""
    print(
        "WARN: iam-jit-bouncer is the deprecated name; use 'ibounce'. "
        "Both work in v1.0; iam-jit-bouncer is removed in v1.1.",
        file=sys.stderr,
    )
    main()


@main.group("audit-webhook")
def audit_webhook_group() -> None:
    """#259 — operator commands for the audit-export webhook channel.

    Sibling to `audit-export`. Where `audit-export` is about live
    status (is the webhook healthy?), `audit-webhook` is about
    configuration discovery (what preset shapes does this binary
    speak? what flags does each one need?). Per
    [[audit-webhook-presets]] + [[cross-product-agent-parity]].
    """


@audit_webhook_group.group("presets")
def audit_webhook_presets_group() -> None:
    """Manage / introspect the available audit-webhook preset
    shapes. Currently ships `list` only — read-only enumeration of
    the per-vendor adapters the binary knows about."""


def audit_webhook_preset_descriptors() -> list[dict[str, object]]:
    """Single source of truth describing every preset the binary
    speaks. Consumed by `presets list` (operator-facing) AND the
    `list_audit_webhook_presets` MCP tool (agent-facing) so a human
    + an agent see byte-identical preset metadata.

    Per [[audit-webhook-presets]]: this descriptor is GENERIC — it
    documents the wire shape + required flags + which Bounce product
    the preset applies to. It does NOT carry vendor secrets, nor any
    LLM-evaluated text (per [[scorer-is-ground-truth]] + [[don't-
    tailor-to-lighthouse]]).
    """
    return [
        {
            "name": "generic",
            "description": (
                "Default. Bearer token in Authorization + JSON body. "
                "Byte-identical to the pre-#257 wire shape; existing "
                "webhook consumers + custom ingest scripts keep working "
                "without code changes."
            ),
            "auth_header": "Authorization: Bearer <token>",
            "body_shape": "NDJSON of OCSF v1.1.0 class 6003 events",
            "required_flags": [
                "--audit-webhook-url",
                "--audit-webhook-token",
            ],
            "optional_flags": [
                "--audit-webhook-batch-size",
            ],
        },
        {
            "name": "datadog",
            "description": (
                "Datadog Logs HTTP intake. OCSF event overlaid with "
                "DD-native fields (ddsource, service, ddtags, status, "
                "message); the OCSF payload remains queryable as "
                "nested fields. Vendor-reserved field collisions "
                "(status, host) preserve the OCSF original under "
                "ocsf.<name>."
            ),
            "auth_header": "DD-API-KEY: <api_key>",
            "body_shape": (
                "JSON array of OCSF events, each overlaid with "
                "Datadog-native overlay fields"
            ),
            "required_flags": [
                "--audit-webhook-url",
                "--audit-webhook-token",
            ],
            "optional_flags": [
                "--audit-webhook-tags",
            ],
        },
        {
            "name": "splunk-hec",
            "description": (
                "Splunk HTTP Event Collector. NDJSON body where each "
                "line wraps the OCSF event under HEC's `event` "
                "envelope; sourcetype + source + host + time are set "
                "from OCSF metadata."
            ),
            "auth_header": "Authorization: Splunk <hec_token>",
            "body_shape": (
                "NDJSON; each line is one HEC envelope wrapping one "
                "OCSF event"
            ),
            "required_flags": [
                "--audit-webhook-url",
                "--audit-webhook-token",
            ],
            "optional_flags": [],
        },
        {
            "name": "sentinel",
            "description": (
                "Microsoft Sentinel / Log Analytics Workspace via the "
                "Data Collector API. HMAC-SHA256-signed SharedKey auth "
                "computed over the canonical (method, content-length, "
                "content-type, x-ms-date, resource) string keyed by "
                "the base64-decoded workspace shared key. The token "
                "value MUST be the base64-encoded shared key."
            ),
            "auth_header": (
                "Authorization: SharedKey <workspace-id>:<HMAC-SHA256>"
            ),
            "body_shape": "JSON array of OCSF events",
            "required_flags": [
                "--audit-webhook-url",
                "--audit-webhook-token",
            ],
            "optional_flags": [
                "--audit-webhook-sentinel-table",
            ],
        },
    ]


@audit_webhook_presets_group.command("list")
@click.option(
    "--json", "as_json", is_flag=True, default=False,
    help="Emit the descriptor list as JSON (for agent consumption).",
)
def audit_webhook_presets_list_cmd(as_json: bool) -> None:
    """Print the available audit-webhook preset shapes + their config
    requirements.

    Cross-product parity per [[cross-product-agent-parity]]:
    `kbounce audit-webhook presets list` + `dbounce audit-webhook
    presets list` print the same JSON shape under --json. The
    human-readable table format may vary by terminal width.
    """
    descriptors = audit_webhook_preset_descriptors()
    if as_json:
        click.echo(json.dumps(descriptors, indent=2))
        return
    # Human-readable two-column-ish table. Keep it terminal-portable
    # (no fancy box-drawing) so an operator's SSH session reads cleanly.
    click.echo(
        f"{'NAME':<12}  {'REQUIRES':<58}  OPTIONAL",
    )
    for desc in descriptors:
        req = ", ".join(desc["required_flags"])
        opt = ", ".join(desc["optional_flags"]) or "(none)"
        click.echo(f"{desc['name']:<12}  {req:<58}  {opt}")
    click.echo()
    click.echo(
        "See docs/WEBHOOK-PRESETS.md for the full per-vendor wire "
        "shape + token-acquisition steps.",
    )


if __name__ == "__main__":
    main()
