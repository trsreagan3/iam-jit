"""`iam-jit-bouncer` CLI — separate entry point for the bouncer
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


@click.group()
@click.version_option()
def main() -> None:
    """iam-jit-bouncer — local AWS-API call gating proxy.

    Defense-in-depth over IAM role scoping. Sits between local AWS
    SDK calls and AWS endpoints; gates each call against rules.
    Never modifies IAM (creates-never-mutates invariant). Runs
    entirely on your machine — no phone home, no SaaS dependency.

    Foundation commands (this slice):
      init    — initialize SQLite state at ~/.iam-jit/bouncer/
      rules   — manage rules (add, list, remove)
      logs    — inspect decision audit log
      decide  — dry-run: ask "what would the bouncer do for X?"

    Coming in Stage 2:
      run     — start the HTTP proxy server (point AWS_ENDPOINT_URL at it)
      learn   — start in passive recording mode (no blocking)
    """


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

    On a fresh install (empty rule store), iam-jit-bouncer applies a
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
                "`iam-jit-bouncer rules list` to inspect; "
                "`iam-jit-bouncer init --no-default` to skip."
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
        iam-jit-bouncer rules add 's3:Get*' --arn 'arn:aws:s3:::my-bucket/*'
        iam-jit-bouncer rules add 'iam:Delete*' --effect deny
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
    click.echo(f"added rule #{rid}: {rule.effect.value} {rule.pattern}")


@rules_group.command("remove")
@click.argument("rule_id", type=int)
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def rules_remove(rule_id: int, db: str | None) -> None:
    """Remove a rule by id. The deletion is itself audit-logged so
    post-incident review can answer 'what rule existed at time T'
    (per [[agent-friendly-not-bypassable]] Lens B)."""
    with _opened_store(db) as store:
        removed = store.remove_rule(rule_id, actor=_current_actor())
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
        iam-jit-bouncer decide --service s3 --action GetObject \\
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
                "or start a task with `iam-jit-bouncer tasks start` to "
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
                f"{e}\nrun `iam-jit-bouncer tasks active` to see the "
                "current task; `iam-jit-bouncer tasks end <id>` to end it.",
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
              metavar="NAME",
              help="Persist the recommendations as a NEW profile named NAME "
                   "in ~/.iam-jit/bouncer/profiles.yaml. Profile holds the "
                   "synthesized rules as `allow_rules`, so `--profile NAME` "
                   "on future `run` invocations applies them. Refuses to "
                   "overwrite an existing profile sourced from an org URL.")
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

    if save_as_profile:
        _save_recommendations_as_profile(
            recs, save_as_profile,
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
    given name; future `iam-jit-bouncer run --profile NAME` invocations
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
        f"activate with: iam-jit-bouncer run --profile {profile_name}"
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
         "engineer runs `iam-jit-bouncer profile install --from <URL>`. "
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

    target = resolve_profiles_path()
    click.secho(
        f"installed {len(written)} profile(s) into {target}:",
        fg="green",
    )
    for name in written:
        click.echo(f"  {name}")
    click.echo()
    click.echo("Activate one with:")
    click.echo(f"  iam-jit-bouncer run --profile {written[0]}")
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
    assert active is not None
    click.secho(
        f"pause #{pid} active — proxy is COOPERATIVE for the next "
        f"{duration} (ends at {active['ends_at']}).",
        fg="yellow",
    )
    click.echo("Every call during this window is still recorded in the "
               "decisions audit log with pause_id linkage.")
    click.echo("Run `iam-jit-bouncer pause stop` to end early.")


@pause_group.command("stop")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def pause_stop_cmd(db: str | None) -> None:
    """End the currently-active pause (if any)."""
    actor = _current_actor()
    with _opened_store(db) as store:
        pid = store.end_pause(ended_by=actor)
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
    """Parse '30m' / '2h' / '90s' into seconds.

    Picks suffix-based parsing rather than something like ISO 8601
    durations because operators tend to type `30m`, not `PT30M`."""
    if not raw:
        raise click.BadParameter("duration is required")
    s = raw.strip().lower()
    suffix_map = {"s": 1, "m": 60, "h": 3600}
    if s[-1] not in suffix_map:
        raise click.BadParameter(
            f"duration {raw!r}: must end in s/m/h (e.g. 30m, 2h, 90s)"
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
         "surface to the network — local-only is the safe default.",
)
@click.option(
    "--mode",
    type=click.Choice(["cooperative", "transparent"], case_sensitive=False),
    default="cooperative",
    show_default=True,
    help="cooperative: every call is parsed + verdict logged but "
         "always forwarded (advisory). transparent: DENY verdicts "
         "return 403 to the SDK client (enforcement). Pick "
         "cooperative for solo-dev iteration speed; transparent "
         "for locked-down environments where any call must be "
         "gated. Switch later by restarting with the other flag.",
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
         "keywords even with admin credentials. Run `iam-jit-bouncer "
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
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def run_cmd(
    port: int, host: str, mode: str, default_policy: str,
    profile_name: str | None,
    account_id_flag: str | None,
    account_alias_flag: str | None,
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

      iam-jit-bouncer run                          # cooperative on :8767
      iam-jit-bouncer run --mode transparent       # enforcement
      iam-jit-bouncer run --port 9876              # custom port
    """
    import asyncio as _asyncio

    from .bouncer.decisions import DefaultPolicy
    from .bouncer.profiles import load_profiles, resolve_active_profile
    from .bouncer.proxy import ProxyConfig, ProxyMode, serve

    # Resolve the active profile NOW (CLI flag → env var → 'none').
    # If the user passed --profile NAME and NAME doesn't exist,
    # resolve_active_profile raises with the available-names list —
    # better than silently falling back to 'none' (which would
    # disable the safety the user thought they enabled).
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
        active_profile=active_profile,
        account_id=account_id_flag,
        account_alias=account_alias_flag,
    )

    with _opened_store(db) as store:
        click.echo(
            f"iam-jit-bouncer proxy starting on http://{host}:{port} "
            f"(mode={mode}, default-policy={default_policy}, "
            f"profile={active_profile.name})",
            err=True,
        )
        if active_profile.name != "none":
            click.echo(
                f"  profile: {active_profile.description}",
                err=True,
            )
        click.echo(
            f"Point your SDK: export AWS_ENDPOINT_URL=http://{host}:{port}",
            err=True,
        )
        click.echo("Ctrl+C to stop.", err=True)
        try:
            _asyncio.run(serve(config, store=store))
        except KeyboardInterrupt:
            click.echo("\nbouncer proxy stopped.", err=True)


if __name__ == "__main__":
    main()
