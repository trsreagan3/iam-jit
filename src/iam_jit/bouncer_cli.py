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

import json
import sys

import click

from .bouncer.decisions import (
    DefaultPolicy,
    Decision,
    Mode,
    decide,
)
from .bouncer.request_parser import parse_request
from .bouncer.rules import Effect, ProxyRule, RuleSet
from .bouncer.store import BouncerStore, default_db_path


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


@main.command("init")
@click.option(
    "--db",
    type=click.Path(dir_okay=False),
    default=None,
    help="SQLite DB path (default: ~/.iam-jit/bouncer/state.db)",
)
def init_cmd(db: str | None) -> None:
    """Initialize the bouncer's local SQLite state."""
    store = BouncerStore(db_path=db)
    click.echo(f"bouncer initialized at: {store.db_path}")
    click.echo(f"current rules: {len(store.list_rules())}")
    click.echo(f"current decisions: {store.count_decisions()}")


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
    store = BouncerStore(db_path=db)
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
    store = BouncerStore(db_path=db)
    rid = store.add_rule(rule)
    click.echo(f"added rule #{rid}: {rule.effect.value} {rule.pattern}")


@rules_group.command("remove")
@click.argument("rule_id", type=int)
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def rules_remove(rule_id: int, db: str | None) -> None:
    """Remove a rule by id."""
    store = BouncerStore(db_path=db)
    removed = store.remove_rule(rule_id)
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
    store = BouncerStore(db_path=db)
    decision_filter = Decision(decision.lower()) if decision else None
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
    store = BouncerStore(db_path=db)
    ruleset = RuleSet(rules=[r for _, r in store.list_rules()])
    record_obj = decide(
        ruleset,
        mode=Mode(mode.lower()),
        default_policy=DefaultPolicy(default_policy.lower()),
        service=service,
        action=action,
        arn=arn,
        region=region,
    )
    click.echo(f"decision: {record_obj.decision.value}")
    click.echo(f"reason:   {record_obj.reason}")
    if record_obj.matched_rule:
        click.echo(
            f"rule:     {record_obj.matched_rule.effect.value} "
            f"{record_obj.matched_rule.pattern}"
        )
    if record:
        store.record_decision(record_obj)
        click.echo("(recorded to audit log)")


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
