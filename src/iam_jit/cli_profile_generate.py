"""#326 — `iam-jit profile generate-from-audit` + sibling commands.

Mounted on the top-level `iam-jit` CLI per [[cross-product-agent-parity]]
so the same surface works for every Bounce-suite product (the CLI
reads audit events via the standard `iam-jit audit query` HTTP path
that every bouncer exposes; no per-bouncer code changes needed).

Per [[deliberate-feature-completion]] ships together with:
  - the MCP tool surface (mcp_server.py)
  - the LLM module (`iam_jit.llm.profile_generator`)
  - the operator doc (`docs/PROFILE-GENERATION.md`)
  - tests (`tests/llm/test_profile_generator_*.py`)
  - role-effectiveness re-grade append
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

import click

from .cli_audit_query import (
    DEFAULT_BOUNCERS,
    _expand_short_form_filters,
    _query_one_bouncer,
    _resolve_bouncer_set,
)
from .llm.profile_generator import (
    generate_from_audit,
    generate_from_context,
    now_iso,
    save_bundle,
)


def _gather_audit_events(
    *,
    bouncer_names: list[str] | None,
    since: str | None,
    until: str | None,
    filters: tuple[str, ...],
    limit: int,
    audit_events_token: str | None,
    timeout: float,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Fan out to each bouncer's /audit/events endpoint exactly like
    `iam-jit audit query` does. Returns (events, notes_for_stderr).

    Reuses the existing `_query_one_bouncer` helper rather than
    re-implementing the HTTP shape; per [[cross-product-agent-parity]]
    every bouncer ships the same endpoint."""
    notes: list[str] = []
    raw = tuple(bouncer_names) if bouncer_names else ()
    bouncers = _resolve_bouncer_set(raw if raw else None)
    expanded_filters = _expand_short_form_filters(filters)
    events: list[dict[str, Any]] = []
    for endpoint in bouncers:
        r = _query_one_bouncer(
            endpoint,
            since=since,
            until=until,
            filters=expanded_filters,
            limit=limit,
            bearer_token=audit_events_token,
            timeout=timeout,
        )
        if r.error:
            notes.append(f"{r.bouncer} skipped ({r.error})")
            continue
        events.extend(r.events)
    return events, notes


def register_profile_group(parent_group: click.Group) -> click.Group:
    """Register the `profile` subcommand group on the iam-jit CLI."""

    @parent_group.group("profile")
    def profile_group() -> None:
        """LLM-generated bounce profiles (#326).

        Two input paths to one operator-reviewable artifact:

        \b
          * generate-from-audit: synthesize a profile bundle from
            observed OCSF audit events across N bouncers (the
            headline post-[[discovery-first-default]] flow).
          * generate: synthesize a starting-point profile from a
            prose description of an org.
          * save: persist an already-generated bundle to disk; can
            also re-write to a fresh directory.

        Per [[ibounce-honest-positioning]] every generated profile
        is labeled "STARTING POINT" + carries provenance metadata.
        Per [[creates-never-mutates]] saves never overwrite.
        Per [[no-nl-synthesis]] this layer is DIFFERENT from
        IAM-policy synthesis (which remains forbidden) — bounce
        profiles are operator-reviewed config, not security
        boundary.
        """

    @profile_group.command("generate-from-audit")
    @click.option(
        "--agent-session", "agent_session",
        default=None,
        help="Filter to one agent session ID. Expands to "
             "`agent.session_id=X` filter against the audit query. "
             "Default: include all sessions in the time range.",
    )
    @click.option(
        "--time-range",
        default="1h",
        show_default=True,
        help="Operator-facing label for the audit window (e.g. `1h`, "
             "`6h`, `24h`). Used in the profile-header label AND, "
             "if --since/--until are not set, parsed into the "
             "lookback interval for the audit query.",
    )
    @click.option(
        "--since",
        default=None,
        help="ISO 8601 lower bound. Overrides the --time-range "
             "lookback derivation when set.",
    )
    @click.option(
        "--until",
        default=None,
        help="ISO 8601 upper bound. Default: now.",
    )
    @click.option(
        "--bouncer", "bouncers_raw",
        multiple=True,
        help="Restrict to specific bouncer(s). Default: every "
             "bouncer that returned events in the window. Same "
             "shape as `iam-jit audit query --bouncer`.",
    )
    @click.option(
        "--filter", "filter_exprs",
        multiple=True,
        metavar="EXPR",
        help="Additional filter (repeatable). Same syntax as "
             "`iam-jit audit query --filter`.",
    )
    @click.option(
        "--add-safety-denies/--no-add-safety-denies",
        default=True,
        show_default=True,
        help="Layer the universal safety floor (break-glass, IAM "
             "mutation, KMS deletion, audit-infra destruction, "
             "IMDS, GRANT TO PUBLIC) on top of the LLM's denies. "
             "Default ON per the post-pivot playbook.",
    )
    @click.option(
        "--name",
        default=None,
        help="Profile bundle name. Default: auto-generated as "
             "`audit-generated-<utc-iso-second>`. Per "
             "[[profile-auto-naming]] non-TTY runs auto-generate.",
    )
    @click.option(
        "--output", "output_dir",
        type=click.Path(file_okay=False, path_type=pathlib.Path),
        default=None,
        help="Directory to write the bundle to. Default: print the "
             "bundle as JSON to stdout (caller pipes / saves "
             "manually). When set, writes index.yaml + per-bouncer "
             "YAML files; refuses to overwrite existing files.",
    )
    @click.option(
        "--limit",
        type=int,
        default=500,
        show_default=True,
        help="Per-bouncer audit-event cap. Bumped above the audit-"
             "query default (100) because profile synthesis benefits "
             "from a wider sample.",
    )
    @click.option(
        "--audit-events-token",
        default=None,
        help="Bearer token for /audit/events; required when any "
             "bouncer is bound off-loopback.",
    )
    @click.option(
        "--timeout",
        type=float,
        default=10.0,
        show_default=True,
        help="Per-bouncer HTTP timeout (seconds).",
    )
    @click.option(
        "--preferred-backend",
        type=click.Choice(
            ["anthropic", "openai", "bedrock", "ollama"],
            case_sensitive=False,
        ),
        default=None,
        help="Override the LLM backend selection (default: env-based "
             "auto-select per [[pluggable-llm-backend-decision]]). "
             "Self-host operators usually leave this unset.",
    )
    @click.option(
        "--format", "fmt",
        type=click.Choice(["json", "yaml-bundle"], case_sensitive=False),
        default="json",
        show_default=True,
        help="`json` = full structured result with explanation, "
             "flagged_for_review, budget_spent_usd etc. "
             "`yaml-bundle` = concatenated YAML files separated by "
             "`---` markers (humans-only output; non-machine-"
             "parseable; use --output for files).",
    )
    def generate_from_audit_cmd(
        agent_session: str | None,
        time_range: str,
        since: str | None,
        until: str | None,
        bouncers_raw: tuple[str, ...],
        filter_exprs: tuple[str, ...],
        add_safety_denies: bool,
        name: str | None,
        output_dir: pathlib.Path | None,
        limit: int,
        audit_events_token: str | None,
        timeout: float,
        preferred_backend: str | None,
        fmt: str,
    ) -> None:
        """Synthesize a bounce-profile bundle from observed audit events.

        \b
        Examples:
          # Generate from the last hour across all reachable bouncers,
          # add the safety floor, name the bundle, write a bundle dir.
          iam-jit profile generate-from-audit \\
              --time-range 1h \\
              --add-safety-denies \\
              --name "incident-response-runbook" \\
              --output ./profiles/

          # Filter to one agent session.
          iam-jit profile generate-from-audit \\
              --agent-session 019687ef-... \\
              --time-range 6h \\
              --output ./session-profile/

          # Print structured JSON to stdout (for piping into another
          # tool or for `bounce profile save --as <name>` later).
          iam-jit profile generate-from-audit --time-range 30m
        """
        # Compose filters: --agent-session is sugar for
        # `agent.session_id=X` filter.
        all_filters: list[str] = list(filter_exprs)
        if agent_session:
            all_filters.append(f"agent.session_id={agent_session}")

        # Resolve since/until: if not provided + --time-range looks
        # like "1h" / "30m" / "24h", compute since=now-range.
        if since is None and time_range:
            since = _compute_since(time_range)

        # Resolve bouncer list (a list of names, not endpoints) for the
        # generator's `bouncers=` arg.
        bouncer_names: list[str] | None = None
        if bouncers_raw:
            names: list[str] = []
            for one in bouncers_raw:
                for part in one.split(","):
                    part = part.strip()
                    if not part:
                        continue
                    nm = part.split("=", 1)[0].strip()
                    if nm in DEFAULT_BOUNCERS:
                        names.append(nm)
            bouncer_names = names

        events, notes = _gather_audit_events(
            bouncer_names=list(bouncers_raw) if bouncers_raw else None,
            since=since,
            until=until,
            filters=tuple(all_filters),
            limit=limit,
            audit_events_token=audit_events_token,
            timeout=timeout,
        )
        for n in notes:
            click.echo(f"note: {n}", err=True)

        bundle_name = name or f"audit-generated-{now_iso()}"
        result = generate_from_audit(
            events=events,
            time_range=time_range,
            agent_session_id=agent_session,
            bouncers=bouncer_names,
            add_safety_denies=add_safety_denies,
            profile_name=bundle_name,
            preferred_backend=preferred_backend,
            audit_window_start=since,
            audit_window_end=until,
        )

        # Honest-positioning warning on stderr if any broad globs flagged.
        for p in result.bundle:
            for f in p.flagged_for_review:
                click.echo(
                    f"flag: {p.bouncer}: {f}",
                    err=True,
                )

        if output_dir is not None:
            try:
                manifest = save_bundle(result, output_dir)
            except FileExistsError as e:
                raise click.ClickException(str(e)) from e
            click.echo(json.dumps(manifest, indent=2))
            return

        if fmt == "yaml-bundle":
            click.echo("# index.yaml")
            click.echo(result.index_yaml)
            for p in result.bundle:
                click.echo(f"---\n# {p.bouncer}.yaml")
                click.echo(p.profile_yaml)
            return

        click.echo(json.dumps(result.to_dict(), indent=2))

    @profile_group.command("generate")
    @click.option(
        "--context", "context_text",
        required=True,
        help="Prose description of the organization (e.g. "
             "'Mid-size SaaS w/ prod/staging split, payment "
             "processor integration, 5-eng team using Claude').",
    )
    @click.option(
        "--start-from", "start_from",
        multiple=True,
        help="Names of example profiles to compose with (advisory). "
             "e.g. `--start-from example-org-base` to lean on the "
             "shipped starter.",
    )
    @click.option(
        "--name",
        default=None,
        help="Bundle name. Default: auto-generated.",
    )
    @click.option(
        "--output", "output_dir",
        type=click.Path(file_okay=False, path_type=pathlib.Path),
        default=None,
        help="Bundle output directory. None = JSON to stdout.",
    )
    @click.option(
        "--preferred-backend",
        type=click.Choice(
            ["anthropic", "openai", "bedrock", "ollama"],
            case_sensitive=False,
        ),
        default=None,
    )
    @click.option("--explain", is_flag=True, default=False,
                  help="Print the explanation prose first, then the bundle.")
    def generate_cmd(
        context_text: str,
        start_from: tuple[str, ...],
        name: str | None,
        output_dir: pathlib.Path | None,
        preferred_backend: str | None,
        explain: bool,
    ) -> None:
        """Synthesize a starting-point profile from prose context.

        Typical use: security team writes the org-base profile.
        """
        bundle_name = name or f"context-generated-{now_iso()}"
        result = generate_from_context(
            context=context_text,
            start_from=list(start_from),
            profile_name=bundle_name,
            preferred_backend=preferred_backend,
        )

        for p in result.bundle:
            for f in p.flagged_for_review:
                click.echo(f"flag: {p.bouncer}: {f}", err=True)

        if explain:
            click.echo(result.explanation)
            click.echo("---")

        if output_dir is not None:
            try:
                manifest = save_bundle(result, output_dir)
            except FileExistsError as e:
                raise click.ClickException(str(e)) from e
            click.echo(json.dumps(manifest, indent=2))
            return

        click.echo(json.dumps(result.to_dict(), indent=2))

    @profile_group.command("save")
    @click.option("--as", "save_as", required=True,
                  help="Bundle directory name to save to.")
    @click.argument(
        "yaml_path",
        type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
    )
    def save_cmd(save_as: str, yaml_path: pathlib.Path) -> None:
        """Save a pre-generated profile YAML under a named bundle dir.

        Wraps a single YAML into a one-file bundle for the engineer-
        side `bounce profile install --from <dir>` flow.
        """
        target = pathlib.Path(save_as)
        if target.exists() and any(target.iterdir()):
            raise click.ClickException(
                f"{target} already has content; per "
                f"[[creates-never-mutates]] pick a fresh dir."
            )
        target.mkdir(parents=True, exist_ok=True)
        body = yaml_path.read_text()
        dest = target / yaml_path.name
        dest.write_text(body)

        import hashlib as _hash
        sha = _hash.sha256(body.encode("utf-8")).hexdigest()
        click.echo(json.dumps({
            "saved_to": str(dest),
            "sha256": sha,
            "as": save_as,
        }, indent=2))

    return profile_group


def _compute_since(time_range: str) -> str | None:
    """Convert `1h`, `30m`, `24h`, `2d` to an ISO 8601 timestamp
    representing `now - range`. Returns None for unparseable input
    (caller's audit query will just default to "from beginning")."""
    import datetime as _dt
    s = (time_range or "").strip().lower()
    if not s:
        return None
    try:
        unit = s[-1]
        n = int(s[:-1])
    except (ValueError, IndexError):
        return None
    multipliers = {"m": 60, "h": 3600, "d": 86400}
    if unit not in multipliers:
        return None
    delta = n * multipliers[unit]
    when = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=delta)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Convenience: the MCP-server side reuses these helpers.
# ---------------------------------------------------------------------------


def generate_from_audit_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """MCP-side wrapper. Same arg shape as the CLI but accepts the
    audit events as an already-fetched list (so the MCP tool can
    accept events directly + cross-host bouncer probes aren't a
    requirement for the agent runtime).

    Phase 3 (docs/PROFILE-GENERATION-DESIGN.md §6 Phase 3): accepts
    ``lean_permissive`` (bool, default False) and ``friction_budget``
    (dict | None, default None). When ``lean_permissive=True`` the
    deterministic §2 heuristic drives the profile (no LLM call);
    default-off keeps existing MCP callers byte-identical.
    """
    time_range = args.get("time_range") or "1h"
    agent_session_id = args.get("agent_session_id")
    bouncers = args.get("bouncers") or None
    add_safety_denies = bool(args.get("add_safety_denies", True))
    name = args.get("name") or f"audit-generated-{now_iso()}"
    preferred_backend = args.get("preferred_backend")
    audit_window_start = args.get("audit_window_start")
    audit_window_end = args.get("audit_window_end")
    lean_permissive = bool(args.get("lean_permissive", False))
    friction_budget_raw = args.get("friction_budget")
    friction_budget = (
        friction_budget_raw
        if isinstance(friction_budget_raw, dict)
        else None
    )

    # Two ways the agent can supply events:
    #   1. `events`: pre-fetched OCSF events as a list
    #   2. `query_local_bouncers`: True -> the MCP server probes
    #      DEFAULT_BOUNCERS itself
    events: list[dict[str, Any]] = list(args.get("events") or [])
    if not events and args.get("query_local_bouncers"):
        since = args.get("since") or _compute_since(time_range)
        events, _notes = _gather_audit_events(
            bouncer_names=bouncers,
            since=since,
            until=args.get("until"),
            filters=tuple(args.get("filters") or []),
            limit=int(args.get("limit") or 500),
            audit_events_token=args.get("audit_events_token"),
            timeout=float(args.get("timeout") or 10.0),
        )

    result = generate_from_audit(
        events=events,
        time_range=time_range,
        agent_session_id=agent_session_id,
        bouncers=bouncers,
        add_safety_denies=add_safety_denies,
        profile_name=name,
        preferred_backend=preferred_backend,
        audit_window_start=audit_window_start,
        audit_window_end=audit_window_end,
        lean_permissive=lean_permissive,
        friction_budget=friction_budget,
    )
    return result.to_dict()


def generate_from_context_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """MCP-side wrapper for the NL-context flow."""
    context_text = args.get("context") or ""
    start_from = args.get("start_from") or []
    if isinstance(start_from, str):
        start_from = [start_from]
    name = args.get("name") or f"context-generated-{now_iso()}"
    preferred_backend = args.get("preferred_backend")
    result = generate_from_context(
        context=context_text,
        start_from=list(start_from),
        profile_name=name,
        preferred_backend=preferred_backend,
    )
    return result.to_dict()


def save_for_mcp(args: dict[str, Any]) -> dict[str, Any]:
    """MCP-side wrapper for save: accepts raw YAML content + a name
    and writes it under the operator's ~/.iam-jit/generated-profiles
    directory."""
    import hashlib as _hash
    import os as _os
    yaml_text = args.get("yaml")
    name = args.get("name")
    if not isinstance(yaml_text, str) or not yaml_text.strip():
        return {"error": "yaml argument is required + must be a non-empty string"}
    if not isinstance(name, str) or not name.strip():
        return {"error": "name argument is required + must be a non-empty string"}

    base = pathlib.Path(
        _os.environ.get("IAM_JIT_GENERATED_PROFILES_DIR") or
        (pathlib.Path.home() / ".iam-jit" / "generated-profiles"),
    )
    base.mkdir(parents=True, exist_ok=True)
    target_dir = base / name
    if target_dir.exists() and any(target_dir.iterdir()):
        return {
            "error": (
                f"{target_dir} already exists with content; per "
                f"[[creates-never-mutates]] pick a different name."
            ),
        }
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / "profile.yaml"
    path.write_text(yaml_text)
    sha = _hash.sha256(yaml_text.encode("utf-8")).hexdigest()
    return {"path": str(path), "sha256": sha, "name": name}
