"""#429 / §A68 — ``iam-jit logs`` CLI.

One subcommand today: ``iam-jit logs ship-to``. Two modes:

* ``--detect`` lists every destination the operator's environment
  signals support for, with the marker(s) that triggered detection
  + the bouncer flag recommendation to enable each.
* ``<destination>`` prints the bouncer flag recommendation for one
  destination so the operator can copy / paste into their bouncer
  launch.

Per ``[[creates-never-mutates]]`` the CLI NEVER rewrites
``.iam-jit.yaml`` or restarts the bouncer; every output is a snippet
the operator applies themselves. ``--detect`` requires zero
side-effects.

Per ``[[v1-scope-bar]]`` no new SIEM adapters — composes with #257
webhook presets + #258 Security Lake support + #317 S3 sink.

Per ``[[no-hosted-saas]]`` recommendations target operator-controlled
destinations only (their AWS / DD / Splunk / cluster). iam-jit-the-
company is never on the recipient list.

Per ``[[ambient-value-prop-and-friction-framing]]`` the CLI surfaces
the value framing ("Detected X — here's how to enable shipping"),
not deficit framing ("ERROR: no SIEM configured").
"""

from __future__ import annotations

import json as _json
import sys
from typing import Any

import click

from .log_shipping import (
    Destination,
    DetectedDestination,
    capture_env,
    detect_destinations,
    recommend_flags,
)


def _dest_choice_values() -> list[str]:
    return [d.value for d in Destination]


def register_logs_command(parent_group: click.Group) -> click.Group:
    """Attach ``logs`` to the top-level iam-jit Click group.

    Returns the logs subgroup so future Phase F+ subcommands (e.g.
    ``iam-jit logs verify``) can be hung off the same surface.
    """

    @parent_group.group("logs")
    def logs_group() -> None:
        """Log shipping detection + opt-in setup.

        \b
        Examples:
          iam-jit logs ship-to --detect           # list available destinations
          iam-jit logs ship-to datadog            # show flags for Datadog
          iam-jit logs ship-to --detect --json    # structured for agents

        Per `[[creates-never-mutates]]` every command prints flags /
        snippets you copy into your bouncer launch; no auto-apply, no
        bouncer restart.
        """

    @logs_group.command("ship-to")
    @click.argument(
        "destination",
        required=False,
        type=click.Choice(_dest_choice_values()),
    )
    @click.option(
        "--detect",
        "detect_mode",
        is_flag=True,
        default=False,
        help=(
            "List every destination the environment signals support for "
            "(AWS / Datadog / Splunk / K8s) plus the bouncer-launch "
            "flag recommendation for each."
        ),
    )
    @click.option(
        "--json",
        "as_json",
        is_flag=True,
        default=False,
        help="Emit structured JSON instead of human-readable text.",
    )
    def ship_to_cmd(
        destination: str | None,
        detect_mode: bool,
        as_json: bool,
    ) -> None:
        """Detect available SIEM destinations + print bouncer flags
        (NO auto-apply).

        \b
        --detect lists every destination your environment signals
        support for. Pass a destination name (no --detect) to print
        the bouncer-launch flag recommendation for that one
        destination.

        \b
        Detection markers:
          * AWS — ~/.aws/credentials, AWS_ACCESS_KEY_ID, AWS_PROFILE
          * Datadog — DD_API_KEY (or DATADOG_API_KEY)
          * Splunk — SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN
          * K8s — KUBERNETES_SERVICE_HOST or pod service-account token

        \b
        Composes with existing surfaces:
          * #257 webhook presets (generic / datadog / splunk-hec / sentinel)
          * #258 Security Lake S3 partitioning (via #317 S3 sink)
          * #317 cloud-neutral S3-compat NDJSON sink

        Exit codes:
          0 — at least one destination detected (or named one printed)
          1 — --detect mode + nothing detected (operator's env is bare)
          2 — invalid input (no destination + no --detect)
        """
        if not detect_mode and not destination:
            click.secho(
                "iam-jit logs ship-to: pass --detect OR a destination name "
                f"(one of: {', '.join(_dest_choice_values())})",
                fg="red",
                err=True,
            )
            sys.exit(2)

        env = capture_env()
        detected = detect_destinations(env)

        if destination:
            try:
                dest = Destination(destination)
            except ValueError:
                click.secho(
                    f"iam-jit logs ship-to: unknown destination {destination!r}",
                    fg="red",
                    err=True,
                )
                sys.exit(2)
            flags = recommend_flags(dest)
            if as_json:
                payload: dict[str, Any] = {
                    "status": "ok",
                    "destination": dest.value,
                    "flags": flags,
                    "detected": dest in {d.destination for d in detected},
                }
                click.echo(_json.dumps(payload, indent=2))
            else:
                _render_destination(dest, flags, detected)
            sys.exit(0)

        # --detect mode
        if as_json:
            click.echo(_json.dumps({
                "status": "ok" if detected else "no-destinations-detected",
                "destinations": [d.as_dict() for d in detected],
            }, indent=2))
        else:
            _render_detections(detected)

        sys.exit(0 if detected else 1)

    return logs_group


def _render_detections(detected: list[DetectedDestination]) -> None:
    """Pretty-print the --detect output.

    Per ``[[ambient-value-prop-and-friction-framing]]`` lead with the
    value (what we found) before the action items. Empty result is
    framed as "your environment is bare; here's the catalog" — not as
    an error.
    """
    if not detected:
        click.echo(
            "iam-jit logs ship-to: no destinations detected.\n\n"
            "Available destinations (configure the marker env vars / "
            "files then re-run --detect):\n"
            "  cloudwatch-logs / security-lake — set AWS_PROFILE or "
            "configure ~/.aws/credentials\n"
            "  datadog                          — set DD_API_KEY\n"
            "  splunk-hec                       — set SPLUNK_HEC_URL + "
            "SPLUNK_HEC_TOKEN\n"
            "  loki-elk                         — run inside a K8s pod\n"
        )
        return
    click.echo(f"iam-jit logs ship-to: detected {len(detected)} destination(s).\n")
    for d in detected:
        click.secho(f"  [{d.destination.value}]", fg="green", bold=True)
        click.echo(f"    via: {', '.join(d.markers)}")
        click.echo(f"    {d.summary}")
        click.echo(
            f"    enable: iam-jit logs ship-to {d.destination.value}",
        )
        click.echo("")


def _render_destination(
    dest: Destination,
    flags: list[str],
    detected: list[DetectedDestination],
) -> None:
    """Pretty-print the flag recommendation for one destination."""
    is_detected = dest in {d.destination for d in detected}
    if is_detected:
        click.secho(
            f"iam-jit logs ship-to: {dest.value} (DETECTED in your environment)",
            fg="green",
            bold=True,
        )
    else:
        click.secho(
            f"iam-jit logs ship-to: {dest.value} (not detected — flags "
            f"are still valid, you'll need to provide the env vars "
            f"or substitute the placeholders manually)",
            fg="yellow",
        )
    click.echo("")
    click.echo("Recommended bouncer-launch flags:")
    click.echo("")
    for flag in flags:
        click.echo(f"  {flag}")
    click.echo("")
    click.echo(
        "Append these to your bouncer launch (ibounce / kbounce / "
        "dbounce / gbounce). Per [[creates-never-mutates]] this CLI "
        "does NOT modify your bouncer config or restart anything — "
        "copy the flags + restart your bouncer when convenient.",
    )


__all__ = [
    "register_logs_command",
]
