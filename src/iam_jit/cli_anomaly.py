"""§A78 #470 + §A79 #471 — `iam-jit anomaly` CLI subcommand-group.

Phase H of the anomaly-detection cluster. The CLI surfaces:

  iam-jit anomaly status            # show installed config + baseline stats
  iam-jit anomaly check ACTION      # score a single (action, resource)
  iam-jit anomaly known-agents      # list agent identities tracked so far

Per ``[[scorer-is-ground-truth]]`` the CLI is honest: ``check`` is a
DRY-RUN scoring pass against the operator's local baseline; it never
mutates anything, never makes a network call.

Per ``[[ambient-value-prop-and-friction-framing]]`` the human output
leads with "your bouncer noticed something unusual" framing rather
than the harsh "VIOLATION" tone.
"""

from __future__ import annotations

import json
import os
import pathlib

import click

from .anomaly_detection import (
    AnomalyDetectionConfig,
    BaselineStore,
    SENSITIVITY_PRESETS,
    score_anomaly,
)


def _resolve_baseline_path(explicit: str | None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("IAM_JIT_ANOMALY_BASELINE_PATH")
    if env:
        return env
    return str(pathlib.Path.home() / ".iam-jit" / "anomaly-baseline.db")


def register_anomaly_group(main_group: click.Group) -> click.Group:
    """Attach ``anomaly`` to the iam-jit Click root."""

    @main_group.group("anomaly")
    def anomaly_group() -> None:
        """Inspect + dry-run the anomaly-detection baseline.

        Phase H (#468-#471). Per [[anomaly-detection-mode-phase-h]]
        the detector is opt-in (declared via
        `iam-jit.anomaly_detection` in the ambient config). This CLI
        surface is for operator inspection + dry-run scoring; the
        bouncer wires the detector into the request path when
        `enabled: true`.
        """

    @anomaly_group.command("status")
    @click.option(
        "--baseline-path", default=None,
        help="Path to the per-agent baseline DB. "
             "Default: $IAM_JIT_ANOMALY_BASELINE_PATH "
             "→ ~/.iam-jit/anomaly-baseline.db.",
    )
    @click.option(
        "--format", "fmt",
        type=click.Choice(["table", "json"]),
        default="table", show_default=True,
    )
    def status_cmd(baseline_path: str | None, fmt: str) -> None:
        """Show the installed baseline DB's status + recent agents."""
        path = _resolve_baseline_path(baseline_path)
        store = BaselineStore(path=path)
        try:
            store.start()
            stat = store.status()
            agents = store.known_agents()
        finally:
            store.stop()
        if fmt == "json":
            click.echo(json.dumps(
                {"baseline_status": stat, "known_agents": agents},
                indent=2,
            ))
            return
        click.echo(f"Baseline path: {stat['path']}")
        click.echo(f"  queue depth:        {stat['queue_depth']}")
        click.echo(f"  dropped:            {stat['dropped']}")
        click.echo(f"  write errors:       {stat['write_errors']}")
        click.echo(f"  window (seconds):   {stat['window_seconds']}")
        click.echo(f"  decay rate:         {stat['decay_rate']}")
        click.echo(
            f"  decay period (s):   {stat['decay_period_seconds']}",
        )
        click.echo(f"Tracked agents: {len(agents)}")
        for a in agents[:25]:
            click.echo(f"  - {a}")
        if len(agents) > 25:
            click.echo(f"  ... ({len(agents) - 25} more)")

    @anomaly_group.command("check")
    @click.argument("action")
    @click.option(
        "--agent-identity", default="anonymous",
        help="Agent identity whose baseline to score against.",
    )
    @click.option(
        "--resource", default="*",
        help="Resource ARN / target / SQL identifier. "
             "Canonicalised before lookup; never stored.",
    )
    @click.option(
        "--sensitivity",
        type=click.Choice(sorted(SENSITIVITY_PRESETS), case_sensitive=False),
        default="medium", show_default=True,
    )
    @click.option(
        "--min-actions", type=int, default=50, show_default=True,
        help="min_actions_for_baseline override.",
    )
    @click.option(
        "--cold-start-fallback/--no-cold-start-fallback",
        default=True, show_default=True,
        help="F.2 — fall back to the #404 deny-classifier when "
             "baseline is below the threshold.",
    )
    @click.option(
        "--baseline-path", default=None,
        help="Path to the per-agent baseline DB.",
    )
    @click.option(
        "--format", "fmt",
        type=click.Choice(["table", "json"]),
        default="table", show_default=True,
    )
    def check_cmd(
        action: str,
        agent_identity: str,
        resource: str,
        sensitivity: str,
        min_actions: int,
        cold_start_fallback: bool,
        baseline_path: str | None,
        fmt: str,
    ) -> None:
        """Dry-run score a single (action, resource) sample."""
        cfg = AnomalyDetectionConfig(
            enabled=True,
            mode="alert",
            sensitivity=sensitivity,
            min_actions_for_baseline=min_actions,
            cold_start_fallback=cold_start_fallback,
        )
        path = _resolve_baseline_path(baseline_path)
        store = BaselineStore(path=path)
        try:
            store.start()
            summary = store.summary_for(agent_identity, action, resource)
            result = score_anomaly(
                action=action,
                agent_identity=agent_identity,
                baseline_summary=summary,
                config=cfg,
                resource=resource,
            )
        finally:
            store.stop()
        if fmt == "json":
            click.echo(json.dumps(result.to_dict(), indent=2))
            return
        click.echo(
            f"Your bouncer scored: {action} (agent={agent_identity}, "
            f"resource={resource})",
        )
        click.echo(f"  verdict:                  {result.verdict}")
        click.echo(f"  anomaly_score:            {result.anomaly_score:.3f}")
        click.echo(
            f"  baseline_observations:    {result.baseline_observations}",
        )
        click.echo(
            f"  cold_start_fallback_used: "
            f"{result.cold_start_fallback_used}",
        )
        if result.threat_feed_severity:
            click.echo(
                f"  threat_feed_severity:    {result.threat_feed_severity}",
            )
        click.echo("  explanations:")
        for e in result.explanations:
            mark = "*" if e.contributing else " "
            click.echo(
                f"   {mark} {e.dimension}: mean={e.baseline_mean:.3f} "
                f"stddev={e.baseline_stddev:.3f} observed={e.observed:.3f} "
                f"sigma={e.sigma_distance:.2f}",
            )
        if result.mitre_atlas_techniques:
            click.echo("  MITRE techniques:")
            for t in result.mitre_atlas_techniques:
                click.echo(f"   - {t['id']} ({t['framework']}): {t['name']}")
        if result.note:
            click.echo(f"  note: {result.note}")

    @anomaly_group.command("known-agents")
    @click.option(
        "--baseline-path", default=None,
        help="Path to the per-agent baseline DB.",
    )
    def known_agents_cmd(baseline_path: str | None) -> None:
        """List agent identities tracked in the baseline."""
        path = _resolve_baseline_path(baseline_path)
        store = BaselineStore(path=path)
        try:
            store.start()
            agents = store.known_agents()
        finally:
            store.stop()
        for a in agents:
            click.echo(a)

    return anomaly_group


__all__ = ["register_anomaly_group"]
