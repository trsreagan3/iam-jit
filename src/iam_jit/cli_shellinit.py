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
import time
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


# Master kill-switch (prevention side). When this env var is truthy, the
# wiring layer emits NO live bouncer exports — `shellinit`, the settings.json
# env-block writer, and the MCP env all become inert. This is the "off the
# leash" lever: one var disables ALL bouncer interception for new sessions.
# (For an ALREADY-wired, already-running session use `iam-jit bouncers off`,
# which strips the baked env from settings.json — a static env var can't
# retroactively un-route a live process.)
IAM_JIT_DISABLE_BOUNCERS_ENV = "IAM_JIT_DISABLE_BOUNCERS"

_TRUTHY = {"1", "true", "yes", "on"}


def bouncers_disabled() -> bool:
    """True iff the master kill-switch env var is set to a truthy value."""
    import os as _os

    return _os.environ.get(IAM_JIT_DISABLE_BOUNCERS_ENV, "").strip().lower() in _TRUTHY


def _export_line(shell: str, name: str, value: str) -> str:
    """Format a single env-export line for the given shell."""
    tmpl, _ = _SHELL_SYNTAX[shell]
    return tmpl.format(name=name, value=value)


def _comment(shell: str, text: str) -> str:
    _, prefix = _SHELL_SYNTAX[shell]
    return f"{prefix} {text}"


def render_shellinit(
    snapshot: dict[str, Any],
    *,
    shell: str,
    all_missed: bool = False,
) -> str:
    """Render the shellinit text from a posture snapshot. Pure
    function; no IO. Per [[ibounce-honest-positioning]] this NEVER
    emits an export for a bouncer that's misconfigured — instead it
    comments the line with the misconfig note so `eval` is safe.

    ``all_missed`` should be True when every retry attempt in
    ``_capture_posture_with_retry`` found no running bouncer — triggers
    an additional hint comment pointing operators at the start-up-race
    window per [[ibounce-honest-positioning]].
    """
    if shell not in _SHELL_SYNTAX:
        # Defensive: caller validated, but keep render_shellinit
        # callable from tests with arbitrary input.
        raise ValueError(f"unknown shell: {shell!r}")

    if bouncers_disabled():
        # Master kill-switch set: emit an inert comment block so `eval` is a
        # no-op. Never emit a live export while interception is disabled.
        return (
            _comment(
                shell,
                f"iam-jit bouncers DISABLED ({IAM_JIT_DISABLE_BOUNCERS_ENV} is "
                "set) — no interception wired.",
            )
            + "\n"
            + _comment(
                shell,
                f"Unset {IAM_JIT_DISABLE_BOUNCERS_ENV} (and re-run) to re-enable.",
            )
            + "\n"
        )

    bouncers = snapshot.get("bouncers", {})

    running: list[str] = []
    stopped: list[str] = []
    for name in ("ibounce", "kbounce", "dbounce", "gbounce"):
        b = bouncers.get(name, {})
        if b.get("running"):
            running.append(f"{name}(:{b.get('port', '?')})")
        else:
            stopped.append(name)

    # Build a shell-appropriate eval hint for the header comment.
    # Fish uses `eval (iam-jit shellinit)` (no dollar-paren);
    # PowerShell uses `iam-jit shellinit | Invoke-Expression`;
    # bash / zsh / sh use `eval "$(iam-jit shellinit)"`.
    if shell == "fish":
        eval_hint = "eval (iam-jit shellinit)"
    elif shell == "powershell":
        eval_hint = "iam-jit shellinit | Invoke-Expression"
    else:
        eval_hint = 'eval "$(iam-jit shellinit)"'

    lines: list[str] = []
    lines.append(
        _comment(
            shell,
            f"iam-jit shellinit — paste this OR `{eval_hint}`",
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
    # Per [[ibounce-honest-positioning]]: when EVERY retry attempt
    # found no running bouncer, surface a hint about the start-up race
    # window so operators who run shellinit immediately after starting
    # a bouncer know what to do — without suppressing the "not running"
    # line that makes the comment-only output honest.
    # #658: list the ACTUAL missing bouncer names (not hard-coded "ibounce").
    # #657: track which bouncers are covered here so per-bouncer fallback
    #        can skip them and avoid duplicate noise.
    _header_race_hint_covered: set[str] = set()
    if all_missed and stopped:
        missing_names = " + ".join(stopped)
        lines.append(
            _comment(
                shell,
                f"If you JUST started {missing_names}, run shellinit again "
                "in a few seconds.",
            ),
        )
        _header_race_hint_covered = set(stopped)

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
    elif "ibounce" not in _header_race_hint_covered:
        # Only emit the per-bouncer fallback when the header race-hint
        # has NOT already covered ibounce (#657 dedupe).
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
        # Carve the harness's own control-plane (e.g. Claude Code -> Anthropic)
        # + loopback OUT of the proxy. Without this, routing the agent's whole
        # environment through gbounce also routes the harness's own LLM/API
        # traffic — so a gbounce outage bricks the agent itself, even after the
        # upstream API recovers (the export is static). See proxy_exclusions.
        from .proxy_exclusions import merge_no_proxy

        no_proxy = merge_no_proxy()
        lines.append(_comment(shell, "keep the harness's own API traffic direct (never via the bouncer):"))
        lines.append(_export_line(shell, "NO_PROXY", no_proxy))
        lines.append(_export_line(shell, "no_proxy", no_proxy))
    else:
        lines.append(
            _comment(shell, "(no HTTP_PROXY export — gbounce not running)"),
        )

    return "\n".join(lines) + "\n"


# Retry schedule (seconds between attempts).  Cumulative: 0 + 0.25 + 0.5 + 1.0 = 1.75 s max.
_RETRY_DELAYS: tuple[float, ...] = (0.25, 0.5, 1.0)


def _capture_posture_with_retry() -> tuple[dict[str, Any], bool]:
    """Run capture_posture() with exponential backoff.

    Retries up to len(_RETRY_DELAYS) more times after the initial
    attempt, sleeping _RETRY_DELAYS[i] between attempts.  Stops
    early as soon as at least one bouncer is detected running.

    Returns a 2-tuple:
      (snapshot, all_missed)

    ``all_missed`` is True when EVERY attempt returned no running
    bouncers — callers use this to decide whether to emit the
    start-up-race hint comment.
    """
    from .posture import capture_posture

    snapshot = capture_posture()
    bouncers = snapshot.get("bouncers", {})
    any_running = any(
        b.get("running") for b in bouncers.values() if isinstance(b, dict)
    )
    if any_running:
        return snapshot, False

    for delay in _RETRY_DELAYS:
        time.sleep(delay)
        snapshot = capture_posture()
        bouncers = snapshot.get("bouncers", {})
        any_running = any(
            b.get("running") for b in bouncers.values() if isinstance(b, dict)
        )
        if any_running:
            return snapshot, False

    # All attempts exhausted with no bouncer found.
    return snapshot, True


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

        snapshot, all_missed = _capture_posture_with_retry()
        click.echo(
            render_shellinit(snapshot, shell=shell, all_missed=all_missed),
            nl=False,
        )

    return shellinit_cmd


__all__ = [
    "register_shellinit_command",
    "render_shellinit",
]
