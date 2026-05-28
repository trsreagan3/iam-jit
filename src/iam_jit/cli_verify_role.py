"""`iam-jit verify-role <role-arn>` — verify what an IAM role can do
RIGHT NOW, with the TTL gate honored.

Closes the gap reported in dogfood finding #694: a plain
`aws iam simulate-principal-policy` against an iam-jit-issued role
returns `implicitDeny` for every action because the role's policy is
TTL-gated via a `aws:CurrentTime < <expiry>` condition. Without
injecting an `aws:CurrentTime` context entry the simulator can't
evaluate the condition and falls through to the implicit deny.

This CLI runs `iam:SimulatePrincipalPolicy` with the right context
entries automatically and either prints a per-action allow/deny
report (if the operator passed `--action`) or enumerates every
action from the role's attached + inline policies and reports each.

Per [[creates-never-mutates]]: this is a read-only diagnostic. It
calls SimulatePrincipalPolicy + GetRolePolicy + ListRolePolicies +
ListAttachedRolePolicies + GetPolicyVersion. No state mutated.
"""

from __future__ import annotations

import datetime as _dt
import json as _json
import sys
from typing import Any

import click


def _now_iso_utc() -> str:
    """Current UTC time as ISO 8601 with `Z` suffix — the canonical
    format AWS expects for `aws:CurrentTime` context entries in
    SimulatePrincipalPolicy."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_actions_from_policy_doc(policy_doc: dict[str, Any]) -> set[str]:
    """Return the set of action strings declared in a policy document's
    Allow statements. Wildcards (`s3:*`, `*`) are passed through verbatim
    — the simulator handles them. Deny statements are ignored because the
    caller is asking "what CAN this role do" not "what's blocked"."""
    out: set[str] = set()
    statements = policy_doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action") or stmt.get("NotAction") or []
        if isinstance(actions, str):
            actions = [actions]
        for a in actions:
            if isinstance(a, str) and a:
                out.add(a)
    return out


def _enumerate_role_actions(iam_client: Any, role_name: str) -> list[str]:
    """Collect every action declared in the role's inline + attached
    policies. Sorted for stable output."""
    actions: set[str] = set()

    # Inline policies
    inline_resp = iam_client.list_role_policies(RoleName=role_name)
    for pname in inline_resp.get("PolicyNames", []):
        pol = iam_client.get_role_policy(RoleName=role_name, PolicyName=pname)
        doc = pol.get("PolicyDocument") or {}
        if isinstance(doc, str):
            doc = _json.loads(doc)
        actions.update(_extract_actions_from_policy_doc(doc))

    # Attached managed policies
    attached_resp = iam_client.list_attached_role_policies(RoleName=role_name)
    for ap in attached_resp.get("AttachedPolicies", []):
        arn = ap.get("PolicyArn")
        if not arn:
            continue
        pol = iam_client.get_policy(PolicyArn=arn)
        version_id = pol.get("Policy", {}).get("DefaultVersionId")
        if not version_id:
            continue
        pver = iam_client.get_policy_version(
            PolicyArn=arn, VersionId=version_id,
        )
        doc = pver.get("PolicyVersion", {}).get("Document") or {}
        if isinstance(doc, str):
            doc = _json.loads(doc)
        actions.update(_extract_actions_from_policy_doc(doc))

    return sorted(actions)


def _role_name_from_arn(role_arn: str) -> str:
    """Extract the role name from a role ARN, accepting both
    `arn:aws:iam::<acct>:role/<name>` and
    `arn:aws:iam::<acct>:role/<path>/<name>` shapes. Raises
    `click.UsageError` on malformed input — the caller surfaces a
    human-friendly error before any AWS calls happen."""
    if not role_arn.startswith("arn:aws:iam::"):
        raise click.UsageError(
            f"role ARN must start with arn:aws:iam::, got {role_arn!r}"
        )
    if ":role/" not in role_arn:
        raise click.UsageError(
            f"role ARN must contain ':role/', got {role_arn!r}"
        )
    # role-path/name form: take everything after the last `/`.
    tail = role_arn.split(":role/", 1)[1]
    name = tail.split("/")[-1]
    if not name:
        raise click.UsageError(f"role ARN has empty role name: {role_arn!r}")
    return name


def verify_role_simulate(
    iam_client: Any,
    role_arn: str,
    actions: list[str],
    *,
    now_iso: str | None = None,
) -> list[dict[str, Any]]:
    """Run SimulatePrincipalPolicy for every requested action against
    the given role ARN with the TTL gate honored
    (aws:CurrentTime = now_iso, default = right-now UTC).

    Returns a list of `{"action": str, "decision": str, "matched_statements": [...]}`
    rows, one per action. `decision` is the raw AWS verdict
    ("allowed" | "explicitDeny" | "implicitDeny").
    """
    if not actions:
        return []
    now_iso = now_iso or _now_iso_utc()
    context_entries = [
        {
            "ContextKeyName": "aws:CurrentTime",
            "ContextKeyType": "string",
            "ContextKeyValues": [now_iso],
        }
    ]
    # AWS allows up to 100 actions per Simulate call; chunk defensively.
    out: list[dict[str, Any]] = []
    chunk = 50
    for i in range(0, len(actions), chunk):
        batch = actions[i : i + chunk]
        resp = iam_client.simulate_principal_policy(
            PolicySourceArn=role_arn,
            ActionNames=batch,
            ContextEntries=context_entries,
        )
        for row in resp.get("EvaluationResults", []):
            out.append({
                "action": row.get("EvalActionName"),
                "decision": row.get("EvalDecision"),
                "matched_statements": [
                    {
                        "policy_id": m.get("SourcePolicyId"),
                        "policy_type": m.get("SourcePolicyType"),
                    }
                    for m in row.get("MatchedStatements", []) or []
                ],
            })
    return out


def _format_row(row: dict[str, Any]) -> str:
    """Format a single verify-row for human display."""
    decision = row.get("decision", "?")
    marker = {
        "allowed": "ALLOW",
        "explicitDeny": "DENY (explicit)",
        "implicitDeny": "DENY (implicit)",
    }.get(decision, decision)
    return f"  [{marker:>16}] {row.get('action')}"


def register_verify_role_command(main_group: click.Group) -> None:
    """Wire `iam-jit verify-role` onto the main click group."""

    @main_group.command("verify-role")
    @click.argument("role_arn", type=str)
    @click.option(
        "--action", "actions", multiple=True,
        help=(
            "An IAM action to verify (e.g. s3:GetObject). May be given "
            "multiple times. If omitted, every action declared in the "
            "role's inline + attached policies is enumerated + verified."
        ),
    )
    @click.option(
        "--region", default=None,
        help=(
            "AWS region for the iam/sts clients. Defaults to the boto3 "
            "default chain (env, profile, IMDS)."
        ),
    )
    @click.option(
        "--profile", default=None,
        help="AWS named profile to use for the iam/sts clients.",
    )
    @click.option(
        "--now", "now_iso", default=None,
        help=(
            "Override the aws:CurrentTime context entry "
            "(ISO 8601, e.g. 2026-01-01T00:00:00Z). Default = right-now UTC."
        ),
    )
    @click.option(
        "--json", "as_json", is_flag=True, default=False,
        help="Emit the verdict list as JSON instead of a human table.",
    )
    def verify_role(
        role_arn: str,
        actions: tuple[str, ...],
        region: str | None,
        profile: str | None,
        now_iso: str | None,
        as_json: bool,
    ) -> None:
        """Verify what an iam-jit-issued IAM role can do RIGHT NOW.

        SimulatePrincipalPolicy returns implicitDeny for every action
        on an iam-jit role unless aws:CurrentTime is injected — the
        TTL gate (Condition: NumericLessThan aws:CurrentTime <expiry>)
        evaluates to false without it. This command injects the
        context entry automatically + (when no --action is given)
        enumerates every action declared in the role's policies so
        you don't have to type them.

        Per [[creates-never-mutates]]: read-only. Calls iam:Simulate*,
        iam:GetRolePolicy, iam:ListRolePolicies,
        iam:ListAttachedRolePolicies, iam:GetPolicy, iam:GetPolicyVersion.
        No state mutated.
        """
        import boto3  # local import so the CLI loads without boto3

        try:
            role_name = _role_name_from_arn(role_arn)
        except click.UsageError as e:
            click.secho(str(e), fg="red", err=True)
            sys.exit(2)

        session = boto3.Session(profile_name=profile, region_name=region)
        iam = session.client("iam")

        action_list = list(actions)
        if not action_list:
            try:
                action_list = _enumerate_role_actions(iam, role_name)
            except Exception as e:
                click.secho(
                    f"failed to enumerate actions for role {role_name}: {e}",
                    fg="red", err=True,
                )
                sys.exit(1)
            if not action_list:
                click.secho(
                    f"role {role_name} has no Allow actions in its inline or "
                    "attached policies — nothing to verify.",
                    fg="yellow", err=True,
                )
                sys.exit(0)

        try:
            rows = verify_role_simulate(
                iam, role_arn, action_list, now_iso=now_iso,
            )
        except Exception as e:
            click.secho(
                f"simulate_principal_policy failed: {e}",
                fg="red", err=True,
            )
            sys.exit(1)

        if as_json:
            click.echo(_json.dumps({
                "role_arn": role_arn,
                "now": now_iso or _now_iso_utc(),
                "results": rows,
            }, indent=2))
            return

        click.echo(f"Verify role: {role_arn}")
        click.echo(f"  aws:CurrentTime = {now_iso or _now_iso_utc()}")
        click.echo(f"  {len(rows)} action(s) verified")
        click.echo("")
        for row in rows:
            click.echo(_format_row(row))
        deny_count = sum(
            1 for r in rows if r.get("decision", "").endswith("Deny")
        )
        allow_count = sum(1 for r in rows if r.get("decision") == "allowed")
        click.echo("")
        click.echo(
            f"Summary: {allow_count} ALLOW, {deny_count} DENY "
            f"(out of {len(rows)})"
        )
