"""#626 Phase 3 — `iam-jit shellinit` shell-export emitter.

Operators are expected to wire env vars (AWS_ENDPOINT_URL, KUBECONFIG,
PG*, HTTP_PROXY) so AWS SDKs / kubectl / database drivers / outbound
HTTP traverses the bouncer. Pre-fix, this wiring was scattered across
docs + init prompts + `posture --check-direct` hints — operators had
to assemble it manually.

`iam-jit shellinit` reads the live bouncer state (via the same
`posture.capture_posture()` detection used by `iam-jit posture` + the
`iam_jit_posture` MCP tool) and emits a paste-ready shell-export
block:

  $ iam-jit shellinit
  # iam-jit shellinit — paste this OR eval "$(iam-jit shellinit)"
  # Detected running: ibounce(:8767)
  # Detected NOT running: kbounce / dbounce / gbounce
  export AWS_ENDPOINT_URL='http://127.0.0.1:8767'

Multi-shell support (`--shell bash|zsh|fish|powershell`) so a single
canonical install command works on any operator's shell.

Per [[creates-never-mutates]] this command NEVER writes to the
operator's shell rc files or modifies the environment of the calling
shell — it only emits text that the operator (or `eval`) consumes.

Per [[ibounce-honest-positioning]]:
  * If a bouncer is running but misconfigured (port mismatch), the
    block is COMMENTED-OUT with a misconfig note rather than emitted
    as a working export — `eval` won't silently brick the operator's
    env.
  * If no bouncers are running, output is comment-only — `eval`
    becomes a no-op, not an error.
"""

from __future__ import annotations

import os
import pathlib
from typing import Any

import click


# Shells whose syntax we know. Mapped to a (var-set, hint-prefix) tuple.
_SHELL_SYNTAX: dict[str, tuple[str, str]] = {
    "bash": ("export {name}='{value}'", "#"),
    "zsh":  ("export {name}='{value}'", "#"),
    "sh":   ("export {name}='{value}'", "#"),
    "fish": ("set -x {name} '{value}'", "#"),
    "powershell": ("$Env:{name} = '{value}'", "#"),
}


def _detect_shell_from_env() -> str:
    """Best-effort shell detection from $SHELL. Falls back to "bash"
    when the env var is empty / unfamiliar. Never raises."""
    shell_env = os.environ.get("SHELL", "").lower()
    if not shell_env:
        # On Windows / odd containers $SHELL may be empty.
        if os.name == "nt":
            return "powershell"
        return "bash"
    # $SHELL is a path like /bin/zsh — grab the basename.
    basename = pathlib.PurePosixPath(shell_env).name
    if basename in _SHELL_SYNTAX:
        return basename
    # Strip common version suffixes (e.g. "bash-5").
    head = basename.split("-", 1)[0]
    if head in _SHELL_SYNTAX:
        return head
    return "bash"


def _export_line(shell: str, name: str, value: str) -> str:
    """Format a single env-export line for the given shell."""
    tmpl, _ = _SHELL_SYNTAX[shell]
    return tmpl.format(name=name, value=value)


def _comment(shell: str, text: str) -> str:
    _, prefix = _SHELL_SYNTAX[shell]
    return f"{prefix} {text}"


def render_shellinit(
    snapshot: dict[str, Any], *, shell: str,
) -> str:
    """Render the shellinit text from a posture snapshot. Pure
    function; no IO. Per [[ibounce-honest-positioning]] this NEVER
    emits an export for a bouncer that's misconfigured — instead it
    comments the line with the misconfig note so `eval` is safe.
    """
    if shell not in _SHELL_SYNTAX:
        # Defensive: caller validated, but keep render_shellinit
        # callable from tests with arbitrary input.
        raise ValueError(f"unknown shell: {shell!r}")

    bouncers = snapshot.get("bouncers", {})

    running: list[str] = []
    stopped: list[str] = []
    for name in ("ibounce", "kbounce", "dbounce", "gbounce"):
        b = bouncers.get(name, {})
        if b.get("running"):
            running.append(f"{name}(:{b.get('port', '?')})")
        else:
            stopped.append(name)

    lines: list[str] = []
    lines.append(
        _comment(
            shell,
            f'iam-jit shellinit — paste this OR `eval "$(iam-jit shellinit)"`',
        ),
    )
    if running:
        lines.append(
            _comment(shell, f"Detected running: {', '.join(running)}"),
        )
    else:
        lines.append(_comment(shell, "Detected running: (none)"))
    if stopped:
        lines.append(
            _comment(
                shell,
                f"Detected NOT running: {', '.join(stopped)}",
            ),
        )

    # Per-bouncer export emission. Each bouncer has its own canonical
    # env-var name + port shape; see posture.bouncers for the source
    # of truth.
    ibounce = bouncers.get("ibounce", {})
    if ibounce.get("running"):
        port = ibounce.get("port", 8767)
        if ibounce.get("misconfig"):
            lines.append(
                _comment(
                    shell,
                    f"ibounce MISCONFIG: {ibounce['misconfig']} — "
                    f"skipping AWS_ENDPOINT_URL export",
                ),
            )
        else:
            lines.append(
                _export_line(
                    shell, "AWS_ENDPOINT_URL", f"http://127.0.0.1:{port}",
                ),
            )
    else:
        lines.append(
            _comment(shell, "(no AWS_ENDPOINT_URL export — ibounce not running)"),
        )

    kbounce = bouncers.get("kbounce", {})
    if kbounce.get("running") and not kbounce.get("misconfig"):
        # kbounce ships a generated kubeconfig the operator points at.
        # We surface the canonical hint; the actual file path is
        # determined by `kbounce kubeconfig` which lives in the Go
        # bouncer (not this repo). Render as comment so eval doesn't
        # break — operator must run `kbounce kubeconfig` to get path.
        lines.append(
            _comment(
                shell,
                "kbounce running: run `export KUBECONFIG=$(kbounce "
                "kubeconfig)` to wire kubectl through it",
            ),
        )
    else:
        lines.append(
            _comment(
                shell,
                "(no KUBECONFIG export — kbounce not running)",
            ),
        )

    dbounce = bouncers.get("dbounce", {})
    if dbounce.get("running") and not dbounce.get("misconfig"):
        wire_port = dbounce.get("wire_port") or 5433
        lines.append(_export_line(shell, "PGHOST", "127.0.0.1"))
        lines.append(_export_line(shell, "PGPORT", str(wire_port)))
    else:
        lines.append(
            _comment(shell, "(no PG* exports — dbounce not running)"),
        )

    gbounce = bouncers.get("gbounce", {})
    if gbounce.get("running") and not gbounce.get("misconfig"):
        wire_port = gbounce.get("wire_port") or 8080
        proxy_url = f"http://127.0.0.1:{wire_port}"
        lines.append(_export_line(shell, "HTTP_PROXY", proxy_url))
        lines.append(_export_line(shell, "HTTPS_PROXY", proxy_url))
    else:
        lines.append(
            _comment(shell, "(no HTTP_PROXY export — gbounce not running)"),
        )

    return "\n".join(lines) + "\n"


def register_shellinit_command(main_group: click.Group) -> click.Command:
    """Attach `shellinit` to the top-level iam-jit Click group.

    Returns the command so tests can invoke it via
    ``CliRunner.invoke(main.commands["shellinit"], [...])``.
    """

    @main_group.command("shellinit")
    @click.option(
        "--shell",
        "shell_name",
        type=click.Choice(sorted(_SHELL_SYNTAX.keys())),
        default=None,
        help="Shell syntax to emit. Default: auto-detected from $SHELL "
             "(falls back to 'bash' on unknown shells).",
    )
    def shellinit_cmd(shell_name: str | None) -> None:
        """Emit a paste-ready env-var block for the running bouncers.

        Reads the live bouncer state via the same detection used by
        `iam-jit posture` and emits ``export VAR=...`` lines for each
        bouncer that's running + correctly listening. Designed for
        ``eval "$(iam-jit shellinit)"``.

        Per [[creates-never-mutates]] this NEVER writes to the
        operator's shell rc files. Per [[ibounce-honest-positioning]]
        bouncers that are misconfigured are surfaced as comments — not
        emitted as broken exports.
        """
        shell = shell_name or _detect_shell_from_env()
        # Defensive: if env-detected shell is unfamiliar, fall back.
        if shell not in _SHELL_SYNTAX:
            shell = "bash"

        from .posture import capture_posture

        snapshot = capture_posture()
        click.echo(render_shellinit(snapshot, shell=shell), nl=False)

    return shellinit_cmd


__all__ = [
    "register_shellinit_command",
    "render_shellinit",
]
