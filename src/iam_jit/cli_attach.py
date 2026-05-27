"""``iam-jit attach`` / ``iam-jit detach`` — wire a running session's AWS
traffic through the ibounce bouncer in ONE universal, no-restart, no-sudo step.

This is the permission-minimal, harness-agnostic setup path
(see ``[[permission-minimal-install]]`` + ``[[no-sudo-userspace-install]]``).

Why a config-file write and not an env var? The AWS SDK/CLI reads
``endpoint_url`` from ``~/.aws/config`` **per invocation** — not from the
environment captured at process launch. So writing it makes an *already
running* agent's next ``aws``/boto3 call route through ibounce with:

  * **no restart** of the agent / shell / harness,
  * **no env var** (which a non-login ``bash -c`` tool wouldn't inherit anyway),
  * **no sudo / root**,
  * works for **any** harness or tool that uses the AWS SDK — Claude Code,
    Codex, Cursor, a plain shell, cron. Nothing Claude-specific.

``detach`` removes ONLY the lines iam-jit added (tagged with a sentinel),
never the operator's own config. A timestamped backup is written before any
modification per ``[[creates-never-mutates]]``.

gbounce / generic-HTTPS has no config-file equivalent (``HTTPS_PROXY`` is
env-only); that path needs the per-harness env wiring + restart-and-resume.
This command is AWS-only on purpose — it's the strong, universal path
(``[[aws-only-positioning]]``).
"""
from __future__ import annotations

import datetime as _dt
import os
import pathlib
from typing import Any

import click

# Sentinel comment so ``detach`` can find + remove ONLY the lines we added.
_SENTINEL = (
    "# iam-jit attach: route AWS through ibounce "
    "(remove with `iam-jit detach`)"
)
_DEFAULT_PORT = 8767
_DEFAULT_HOST = "127.0.0.1"


def _default_aws_config_path() -> pathlib.Path:
    """AWS CLI/SDK config-file precedence: ``$AWS_CONFIG_FILE`` then ``~/.aws/config``."""
    env = os.environ.get("AWS_CONFIG_FILE")
    if env:
        return pathlib.Path(env).expanduser()
    return pathlib.Path.home() / ".aws" / "config"


def _section_header(profile: str) -> str:
    """AWS config uses ``[default]`` for default, ``[profile NAME]`` for named."""
    return "[default]" if profile == "default" else f"[profile {profile}]"


def discover_ibounce_endpoint() -> str | None:
    """Return ``http://host:port`` for the running ibounce, or ``None``.

    Reuses the same ``posture.capture_posture()`` detection that ``shellinit``
    + ``iam-jit posture`` use — single source of truth for "is ibounce up,
    and on what port" (honors canary/non-default ports per #514).
    """
    try:
        from .posture import capture_posture

        snap = capture_posture()
        ib = (snap.get("bouncers") or {}).get("ibounce") or {}
        if ib.get("running"):
            port = ib.get("port", _DEFAULT_PORT)
            host = ib.get("host", _DEFAULT_HOST)
            return f"http://{host}:{port}"
    except Exception:
        # capture_posture is best-effort; attach can still proceed with the
        # default endpoint when explicitly forced (see --endpoint).
        return None
    return None


def _is_section_header(line: str) -> bool:
    s = line.strip()
    return s.startswith("[") and s.endswith("]")


def _endpoint_for(profile: str, lines: list[str]) -> str | None:
    """Return the existing ``endpoint_url`` value in *profile*, or ``None``.

    Walks the file line-by-line so we never reformat the operator's config.
    """
    header = _section_header(profile)
    in_section = False
    for line in lines:
        if _is_section_header(line):
            in_section = line.strip() == header
            continue
        if in_section:
            stripped = line.strip()
            if stripped.startswith("endpoint_url"):
                _, _, val = stripped.partition("=")
                return val.strip()
    return None


def _line_is_ours(line: str) -> bool:
    s = line.strip()
    return s == _SENTINEL or (
        s.startswith("endpoint_url") and "iam-jit" in line
    )


def attach_aws_config(
    *,
    config_path: pathlib.Path,
    profile: str,
    endpoint: str,
) -> dict[str, Any]:
    """Write ``endpoint_url = <endpoint>`` into *profile* of the aws config.

    Returns a structured result dict. Idempotent: re-attaching the same
    endpoint is a no-op. Refuses (no write) if the profile already has a
    DIFFERENT, operator-owned endpoint_url — surfaces it instead of
    clobbering, per ``[[creates-never-mutates]]``.
    """
    header = _section_header(profile)
    existing_lines: list[str] = []
    if config_path.exists():
        existing_lines = config_path.read_text().splitlines()

    current = _endpoint_for(profile, existing_lines)
    if current == endpoint:
        return {
            "status": "already_attached",
            "config_path": str(config_path),
            "profile": profile,
            "endpoint": endpoint,
            "restart_required": False,
        }
    if current is not None:
        # Only step on it if WE put it there (sentinel/tag). Otherwise refuse.
        ours = any(
            _line_is_ours(ln)
            for ln in existing_lines
        )
        if not ours:
            return {
                "status": "refused_existing_endpoint",
                "config_path": str(config_path),
                "profile": profile,
                "existing_endpoint": current,
                "reason": (
                    f"profile [{profile}] already has endpoint_url={current!r} "
                    f"that iam-jit did not set. Refusing to overwrite "
                    f"(per creates-never-mutates). Remove it yourself or use "
                    f"--profile to target a different profile."
                ),
                "restart_required": False,
            }

    # Backup before any mutation.
    backup_path: str | None = None
    if config_path.exists():
        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        bak = config_path.with_suffix(config_path.suffix + f".iam-jit-bak-{ts}")
        bak.write_text(config_path.read_text())
        backup_path = str(bak)

    # Build the new content: ensure the section exists, then place our
    # sentinel + endpoint_url line directly under the header. If an
    # iam-jit-owned endpoint_url is already present (different port), replace it.
    out: list[str] = []
    wrote = False
    section_seen = False
    skip_next_ours_endpoint = False

    for line in existing_lines:
        if skip_next_ours_endpoint and line.strip().startswith("endpoint_url"):
            skip_next_ours_endpoint = False
            continue  # drop the stale iam-jit endpoint_url; we re-add below
        if line.strip() == _SENTINEL:
            skip_next_ours_endpoint = True
            continue  # drop old sentinel; re-add fresh
        out.append(line)
        if _is_section_header(line) and line.strip() == header and not wrote:
            out.append(_SENTINEL)
            out.append(f"endpoint_url = {endpoint}")
            wrote = True
            section_seen = True

    if not section_seen:
        if out and out[-1].strip() != "":
            out.append("")
        out.append(header)
        out.append(_SENTINEL)
        out.append(f"endpoint_url = {endpoint}")
        wrote = True

    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = config_path.with_suffix(config_path.suffix + ".iam-jit-tmp")
    tmp.write_text("\n".join(out) + "\n")
    os.replace(tmp, config_path)

    return {
        "status": "attached",
        "config_path": str(config_path),
        "profile": profile,
        "endpoint": endpoint,
        "backup_path": backup_path,
        "restart_required": False,
    }


def detach_aws_config(
    *, config_path: pathlib.Path, profile: str | None = None
) -> dict[str, Any]:
    """Remove ONLY the iam-jit-added sentinel + endpoint_url lines.

    Leaves every other line of the operator's config untouched.
    """
    if not config_path.exists():
        return {
            "status": "nothing_to_detach",
            "config_path": str(config_path),
            "removed": 0,
        }
    lines = config_path.read_text().splitlines()
    out: list[str] = []
    removed = 0
    drop_next_endpoint = False
    for line in lines:
        if line.strip() == _SENTINEL:
            drop_next_endpoint = True
            removed += 1
            continue
        if drop_next_endpoint and line.strip().startswith("endpoint_url"):
            drop_next_endpoint = False
            removed += 1
            continue
        drop_next_endpoint = False
        out.append(line)

    if removed == 0:
        return {
            "status": "nothing_to_detach",
            "config_path": str(config_path),
            "removed": 0,
        }

    # Backup before mutation.
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = config_path.with_suffix(config_path.suffix + f".iam-jit-bak-{ts}")
    bak.write_text(config_path.read_text())

    tmp = config_path.with_suffix(config_path.suffix + ".iam-jit-tmp")
    tmp.write_text("\n".join(out) + "\n")
    os.replace(tmp, config_path)
    return {
        "status": "detached",
        "config_path": str(config_path),
        "removed": removed,
        "backup_path": str(bak),
    }


def register_attach_command(main_group: click.Group) -> None:
    """Register ``iam-jit attach`` + ``iam-jit detach`` on the main group."""

    @main_group.command("attach")
    @click.option(
        "--profile",
        default="default",
        show_default=True,
        help="AWS profile to wire (writes endpoint_url under [profile NAME]).",
    )
    @click.option(
        "--config-file",
        type=click.Path(dir_okay=False, path_type=pathlib.Path),
        default=None,
        help="Override the aws config path (default: $AWS_CONFIG_FILE or ~/.aws/config).",
    )
    @click.option(
        "--endpoint",
        default=None,
        help="ibounce endpoint URL. Default: auto-discover the running ibounce.",
    )
    def attach_cmd(
        profile: str, config_file: pathlib.Path | None, endpoint: str | None
    ) -> None:
        """Route this machine's AWS calls through the running ibounce — no restart.

        Writes endpoint_url into ~/.aws/config, which the AWS SDK/CLI reads on
        every call. An already-running agent's next aws/boto3 call is audited
        immediately. No env var, no sudo, harness-agnostic.
        """
        cfg = config_file or _default_aws_config_path()
        ep = endpoint or discover_ibounce_endpoint()
        if ep is None:
            raise click.ClickException(
                "no running ibounce detected (and no --endpoint given). "
                "Start it with `ibounce run`, then re-run `iam-jit attach`."
            )
        result = attach_aws_config(config_path=cfg, profile=profile, endpoint=ep)
        status = result["status"]
        if status == "refused_existing_endpoint":
            raise click.ClickException(result["reason"])
        if status == "already_attached":
            click.echo(
                f"already attached: [{profile}] endpoint_url = {ep} "
                f"({cfg}). AWS calls already route through ibounce."
            )
            return
        click.secho(
            f"attached: AWS profile [{profile}] now routes through ibounce "
            f"({ep}).",
            fg="green",
        )
        click.echo(f"  config: {cfg}")
        if result.get("backup_path"):
            click.echo(f"  backup: {result['backup_path']}")
        click.echo(
            "  No restart needed — your next `aws`/boto3 call is audited now."
        )
        click.echo("  Undo any time with: iam-jit detach")
        click.echo(
            "  Note: this is AWS-only. For generic HTTPS via gbounce, set "
            "HTTPS_PROXY (env-only; needs restart-and-resume)."
        )

    @main_group.command("detach")
    @click.option("--profile", default="default", show_default=True)
    @click.option(
        "--config-file",
        type=click.Path(dir_okay=False, path_type=pathlib.Path),
        default=None,
    )
    def detach_cmd(profile: str, config_file: pathlib.Path | None) -> None:
        """Remove the iam-jit endpoint wiring from ~/.aws/config (only our lines)."""
        cfg = config_file or _default_aws_config_path()
        result = detach_aws_config(config_path=cfg, profile=profile)
        if result["status"] == "nothing_to_detach":
            click.echo(f"nothing to detach in {cfg} (no iam-jit lines found).")
            return
        click.secho(
            f"detached: removed {result['removed']} iam-jit line(s) from {cfg}.",
            fg="green",
        )
        click.echo("  Your AWS calls no longer route through ibounce.")
