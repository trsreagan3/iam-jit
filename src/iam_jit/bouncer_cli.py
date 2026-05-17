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
    Per [[creates-never-mutates]] never modifies IAM. Per
    [[no-hosted-saas]] runs entirely on your machine.

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
@click.option("--record/--no-record", default=False, help="Persist decision to audit log.")
def decide_cmd(
    service: str,
    action: str,
    arn: str | None,
    region: str | None,
    mode: str,
    default_policy: str,
    db: str | None,
    record: bool,
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
        if record:
            store.record_decision(
                record_obj,
                matched_rule_id=matched_rule_id,
                task_id=active_task.task_id if active_task is not None else None,
            )
            click.echo("(recorded to audit log)")


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

    Per [[proxy-smart-defaults-and-task-scope]]: a task narrows the
    bouncer's behavior for its duration. The agent declares allow
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
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.option("--json", "as_json", is_flag=True, default=False)
def tasks_active(db: str | None, as_json: bool) -> None:
    """Show the currently-active task (if any). Reports None if
    no task is active OR the active task has timed out."""
    with _opened_store(db) as store:
        active = store.get_active_task()
    if active is None:
        if as_json:
            click.echo(json.dumps({"active": None}))
        else:
            click.echo("(no active task)")
        return
    if as_json:
        click.echo(json.dumps(active.to_dict(), indent=2))
        return
    click.echo(f"task_id:      {active.task_id}")
    click.echo(f"description:  {active.description}")
    click.echo(f"started_at:   {active.started_at}")
    click.echo(f"expires_at:   {active.expires_at}")
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


@tasks_group.command("show")
@click.argument("task_id")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def tasks_show(task_id: str, db: str | None) -> None:
    """Show full details for one task scope."""
    with _opened_store(db) as store:
        scope = store.get_task(task_id)
    if scope is None:
        click.echo(f"no task with id {task_id!r}", err=True)
        sys.exit(1)
    click.echo(json.dumps(scope.to_dict(), indent=2))


@tasks_group.command("end")
@click.argument("task_id")
@click.option("--reason", default="manually ended",
              help="End reason recorded in audit log.")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def tasks_end(task_id: str, reason: str, db: str | None) -> None:
    """End the named task. The deletion-style audit event is written
    via config_events (kind=task_ended)."""
    with _opened_store(db) as store:
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
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def tasks_start(
    description: str,
    allow_rules_raw: tuple[str, ...],
    deny_rules_raw: tuple[str, ...],
    duration_minutes: int,
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


if __name__ == "__main__":
    main()
