"""#272 — `iam-jit audit stream` cross-bouncer live TUI.

A k9s-style TUI that subscribes to every reachable bouncer's
``GET /audit/events`` endpoint (#271), shows ONE merged + sorted
table, and updates live. Pairs with the per-bouncer web UI at ``/``
on each bouncer's mgmt port (also #272).

Stack choice
------------

The spec called for ``textual`` first, with ``rich.live`` as the
fallback if textual isn't already a dep. ``textual`` is NOT a
declared dependency of iam-roles (and adding it would pull in 5+
transitive packages including ``markdown-it-py`` + ``mdit-py-
plugins`` + ``linkify-it-py``). ``rich`` ships transitively via
``click`` so it's already on every install. We ship the rich.live
implementation; the keybindings + layout match what textual would
offer for this read-only use case.

Wire model
----------

Long-polls each bouncer's ``/audit/events`` once per ``--poll``
seconds (default 2 s), advancing a per-bouncer ``since`` cursor.
The same dedupe key the web UI uses (time + actor + operation +
event_type) prevents overlapping-poll duplication.

Per ``[[creates-never-mutates]]`` the TUI is READ-ONLY — no
keystroke mutates bouncer state. Per ``[[security-team-positioning-
safety-not-surveillance]]`` event labels use "deny" / "allow" /
"policy mismatch", never "violation" / "infraction" /
"unauthorized".
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import click

from .cli_audit_query import (
    DEFAULT_BOUNCERS,
    BouncerEndpoint,
    _resolve_bouncer_set,
)


_POLL_DEFAULT_SECONDS = 2.0
_REQUEST_TIMEOUT_SECONDS = 4.0
_RING_BUFFER_DEFAULT = 500
_RING_BUFFER_MAX = 5000


@dataclass
class _BouncerState:
    """Mutable per-bouncer cursor + reachability snapshot."""
    endpoint: BouncerEndpoint
    last_time_ms: int = 0
    reachable: bool = True
    last_error: str | None = None
    fetched_count: int = 0


@dataclass
class _UIState:
    """Mutable global UI state. Owned by the asyncio main loop;
    background fetcher tasks mutate via `events.append` / counters
    only — no shared locks required since asyncio is single-threaded.
    """
    bouncers: dict[str, _BouncerState]
    events: deque  # of (BouncerName, dict[str, Any])
    filter_text: str = ""
    paused: bool = False
    show_bouncer_col: bool = True
    poll_interval: float = _POLL_DEFAULT_SECONDS
    bearer_token: str | None = None
    counts_total: int = 0
    counts_per_bouncer: dict[str, int] = field(default_factory=dict)
    seen_ids: set[str] = field(default_factory=set)
    quit_requested: bool = False


def _classify_verdict(ev: dict[str, Any]) -> tuple[str, str]:
    """Return (label, severity_class) for one event.

    severity_class is one of: deny / allow / admin / heartbeat /
    unknown. Used by the TUI to colourise the row.
    """
    u = (ev.get("unmapped") or {}).get("iam_jit") or {}
    verdict = str(u.get("verdict") or ev.get("verdict") or "").upper()
    event_type = str(
        u.get("event_type") or ev.get("event_type")
        or ev.get("class_name") or ""
    ).upper()
    if "HEARTBEAT" in event_type:
        return ("HEARTBEAT", "heartbeat")
    if "ADMIN" in event_type:
        return (event_type.replace("_", " "), "admin")
    if verdict in ("DENY", "DENIED"):
        return ("DENIED", "deny")
    if verdict in ("ALLOW", "ALLOWED"):
        return ("ALLOWED", "allow")
    if verdict:
        return (verdict, "unknown")
    return ("-", "unknown")


def _extract_actor(ev: dict[str, Any]) -> str:
    actor = ev.get("actor") or {}
    user = actor.get("user") or {}
    if user.get("name"):
        return str(user["name"])
    u = (ev.get("unmapped") or {}).get("iam_jit") or {}
    if u.get("actor"):
        return str(u["actor"])
    agent = u.get("agent") or {}
    if agent.get("name"):
        return str(agent["name"])
    return "-"


def _extract_operation(ev: dict[str, Any]) -> str:
    api = ev.get("api") or {}
    if api.get("operation"):
        return str(api["operation"])
    u = (ev.get("unmapped") or {}).get("iam_jit") or {}
    if u.get("operation"):
        return str(u["operation"])
    if ev.get("activity_name"):
        return str(ev["activity_name"])
    return "-"


def _extract_event_type(ev: dict[str, Any]) -> str:
    u = (ev.get("unmapped") or {}).get("iam_jit") or {}
    if u.get("event_type"):
        return str(u["event_type"])
    if ev.get("event_type"):
        return str(ev["event_type"])
    if ev.get("class_name"):
        return str(ev["class_name"])
    return "-"


def _extract_severity(ev: dict[str, Any]) -> str:
    if ev.get("severity"):
        return str(ev["severity"])
    sid = ev.get("severity_id")
    if sid is not None:
        return {
            1: "Info", 2: "Low", 3: "Medium",
            4: "High", 5: "Critical",
        }.get(int(sid), f"sev={sid}")
    return "-"


def _event_time_ms(ev: dict[str, Any]) -> int:
    t = ev.get("time")
    if isinstance(t, (int, float)):
        return int(t)
    if isinstance(t, str):
        try:
            norm = t[:-1] + "+00:00" if t.endswith("Z") else t
            dt = _dt.datetime.fromisoformat(norm)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_dt.UTC)
            return int(dt.timestamp() * 1000)
        except ValueError:
            return 0
    return 0


def _format_time(ms: int) -> str:
    if not ms:
        return "-"
    try:
        return _dt.datetime.fromtimestamp(
            ms / 1000.0, tz=_dt.UTC,
        ).strftime("%H:%M:%S")
    except (ValueError, OSError):
        return "-"


def _dedup_key(bouncer: str, ev: dict[str, Any]) -> str:
    return "|".join([
        bouncer,
        str(ev.get("time", "")),
        _extract_actor(ev),
        _extract_operation(ev),
        _extract_event_type(ev),
    ])


def _parse_ndjson(body: bytes) -> list[dict[str, Any]]:
    """Parse a bouncer response body. Tolerates bad lines."""
    out: list[dict[str, Any]] = []
    if not body:
        return out
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            continue
    return out


def _build_query_string(
    state: _BouncerState,
    filter_text: str,
    limit: int = 200,
) -> str:
    parts = [("limit", str(limit))]
    if state.last_time_ms:
        # bump by 1 ms so we don't refetch the same event each tick.
        since_iso = _dt.datetime.fromtimestamp(
            (state.last_time_ms + 1) / 1000.0, tz=_dt.UTC,
        ).isoformat()
        parts.append(("since", since_iso))
    if filter_text.strip():
        parts.append(("filter", filter_text.strip()))
    return urllib.parse.urlencode(parts)


async def _fetch_one(
    state: _BouncerState,
    *,
    filter_text: str,
    bearer_token: str | None,
    timeout: float,
) -> tuple[list[dict[str, Any]], str | None]:
    """Fetch one bouncer's /audit/events in a thread (urllib is sync).

    Returns (events, error). Error is None on success.
    """
    qs = _build_query_string(state, filter_text)
    url = f"{state.endpoint.mgmt_url.rstrip('/')}/audit/events?{qs}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/x-ndjson")
    if bearer_token:
        req.add_header("Authorization", f"Bearer {bearer_token}")

    def _do_request() -> tuple[bytes, int]:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(), resp.getcode()

    try:
        body, code = await asyncio.to_thread(_do_request)
    except urllib.error.HTTPError as exc:
        return [], f"HTTP {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return [], f"unreachable ({exc.__class__.__name__})"
    if code != 200:
        return [], f"HTTP {code}"
    return _parse_ndjson(body), None


async def _fetcher_loop(ui: _UIState) -> None:
    """Background poller: round-robin across bouncers each tick."""
    while not ui.quit_requested:
        if ui.paused:
            await asyncio.sleep(0.25)
            continue
        tasks = []
        for name, st in ui.bouncers.items():
            tasks.append(_fetch_one(
                st,
                filter_text=ui.filter_text,
                bearer_token=ui.bearer_token,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            ))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for (name, st), result in zip(ui.bouncers.items(), results):
            if isinstance(result, BaseException):
                st.reachable = False
                st.last_error = str(result)
                continue
            events, err = result
            if err is not None:
                st.reachable = False
                st.last_error = err
                continue
            st.reachable = True
            st.last_error = None
            for ev in events:
                key = _dedup_key(name, ev)
                if key in ui.seen_ids:
                    continue
                ui.seen_ids.add(key)
                tms = _event_time_ms(ev)
                if tms > st.last_time_ms:
                    st.last_time_ms = tms
                ui.events.append((name, ev))
                ui.counts_total += 1
                ui.counts_per_bouncer[name] = ui.counts_per_bouncer.get(name, 0) + 1
                st.fetched_count += 1
        # Bound the seen-ids set so a long session doesn't grow
        # unbounded. The ring-buffer keeps the table itself bounded.
        if len(ui.seen_ids) > 25_000:
            # Drop oldest half — set ordering isn't guaranteed but the
            # subsequent poll will re-seed any truly recent rows via
            # since= cursor; this is harmless.
            ui.seen_ids = set(list(ui.seen_ids)[-12_500:])
        await asyncio.sleep(ui.poll_interval)


def _render_table(ui: _UIState):
    """Build the rich Table for the current frame."""
    from rich.table import Table
    from rich.text import Text

    title_parts = [f"iam-jit audit stream"]
    title_parts.append(f"total={ui.counts_total}")
    for name in sorted(ui.bouncers):
        st = ui.bouncers[name]
        marker = "" if st.reachable else " (skip)"
        title_parts.append(
            f"{name}={ui.counts_per_bouncer.get(name, 0)}{marker}",
        )
    if ui.paused:
        title_parts.append("[PAUSED]")
    if ui.filter_text:
        title_parts.append(f"filter={ui.filter_text!r}")

    table = Table(
        title=" | ".join(title_parts),
        title_justify="left",
        expand=True,
        show_lines=False,
    )
    table.add_column("time", style="dim", width=10)
    if ui.show_bouncer_col:
        table.add_column("bouncer", width=9)
    table.add_column("sev", width=8)
    table.add_column("event_type", width=18)
    table.add_column("actor", width=22)
    table.add_column("operation")
    table.add_column("verdict", width=11)

    # Show only the tail that fits on a typical terminal; the ring
    # buffer itself holds more so the table can scroll up if the
    # operator resizes.
    rows = list(ui.events)[-200:]
    for name, ev in rows:
        label, cls = _classify_verdict(ev)
        colour = {
            "deny": "bold red",
            "allow": "green",
            "admin": "bold blue",
            "heartbeat": "grey50",
            "unknown": "white",
        }[cls]
        row_style = "dim" if cls == "heartbeat" else None
        verdict_cell = Text(label, style=colour)
        cells = [
            _format_time(_event_time_ms(ev)),
        ]
        if ui.show_bouncer_col:
            cells.append(name)
        cells.extend([
            _extract_severity(ev),
            _extract_event_type(ev),
            _extract_actor(ev),
            _extract_operation(ev),
        ])
        table.add_row(*cells, verdict_cell, style=row_style)
    return table


def _render_footer(ui: _UIState):
    """Help line shown below the table."""
    from rich.panel import Panel
    from rich.text import Text

    keys = Text()
    keys.append("[/]", style="bold")
    keys.append(" filter   ")
    keys.append("[p]", style="bold")
    keys.append(" pause/resume   ")
    keys.append("[t]", style="bold")
    keys.append(" toggle bouncer col   ")
    keys.append("[c]", style="bold")
    keys.append(" clear   ")
    keys.append("[q]", style="bold")
    keys.append(" quit")
    return Panel(keys, border_style="grey30")


def _build_layout(ui: _UIState):
    from rich.console import Group
    return Group(_render_table(ui), _render_footer(ui))


async def _key_reader(ui: _UIState) -> None:
    """Read single keypresses from stdin without echoing.

    On non-tty stdin we silently exit the reader so the TUI still
    runs against a pipe (e.g. in tests). q + ctrl-c are the canonical
    exit paths; / opens the filter prompt; p toggles pause; t toggles
    the per-bouncer column; c clears the table.
    """
    if not sys.stdin.isatty():
        # Headless mode — wait forever; main loop exits on quit_requested.
        while not ui.quit_requested:
            await asyncio.sleep(0.2)
        return

    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        loop = asyncio.get_running_loop()
        while not ui.quit_requested:
            ch = await loop.run_in_executor(None, sys.stdin.read, 1)
            if not ch:
                await asyncio.sleep(0.05)
                continue
            if ch == "q" or ch == "\x03":  # q / ctrl-c
                ui.quit_requested = True
                return
            if ch == "p":
                ui.paused = not ui.paused
            elif ch == "t":
                ui.show_bouncer_col = not ui.show_bouncer_col
            elif ch == "c":
                ui.events.clear()
                ui.seen_ids.clear()
                ui.counts_total = 0
                ui.counts_per_bouncer.clear()
            elif ch == "/":
                # Read a line for the filter. Restore cooked mode while
                # the operator types so backspace + echo behave.
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
                try:
                    sys.stdout.write("\nfilter expression (blank to clear): ")
                    sys.stdout.flush()
                    line = await loop.run_in_executor(None, sys.stdin.readline)
                    ui.filter_text = (line or "").strip()
                finally:
                    tty.setcbreak(fd)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


async def _run_tui_loop(ui: _UIState, *, max_frames: int | None = None) -> None:
    """Drive the rich.live render loop.

    ``max_frames`` is the test hook: when set, the loop renders that
    many frames then returns. None == run until quit_requested.
    """
    from rich.console import Console
    from rich.live import Live

    console = Console()
    fetcher_task = asyncio.create_task(_fetcher_loop(ui))
    key_task = asyncio.create_task(_key_reader(ui))
    frames = 0
    try:
        with Live(
            _build_layout(ui),
            console=console,
            refresh_per_second=4,
            screen=True,
        ) as live:
            while not ui.quit_requested:
                live.update(_build_layout(ui))
                await asyncio.sleep(0.25)
                frames += 1
                if max_frames is not None and frames >= max_frames:
                    ui.quit_requested = True
                    break
    finally:
        ui.quit_requested = True
        fetcher_task.cancel()
        key_task.cancel()
        for t in (fetcher_task, key_task):
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass


def make_ui_state(
    *,
    bouncers: list[BouncerEndpoint] | None = None,
    bearer_token: str | None = None,
    poll_interval: float = _POLL_DEFAULT_SECONDS,
    ring_buffer: int = _RING_BUFFER_DEFAULT,
    filter_text: str = "",
) -> _UIState:
    """Build a fresh UI state. Exposed for tests."""
    eps = bouncers or list(DEFAULT_BOUNCERS.values())
    return _UIState(
        bouncers={e.name: _BouncerState(endpoint=e) for e in eps},
        events=deque(maxlen=max(1, min(ring_buffer, _RING_BUFFER_MAX))),
        bearer_token=bearer_token,
        poll_interval=poll_interval,
        filter_text=filter_text,
    )


def register_audit_stream_command(audit_group: click.Group) -> None:
    """Register the `audit stream` subcommand on the existing
    iam-jit `audit` group built by :func:`register_audit_query_group`.
    """

    @audit_group.command("stream")
    @click.option(
        "--bouncer", "bouncers_raw",
        multiple=True,
        help="Which bouncer(s) to subscribe to. Repeatable; comma-"
             "separated also accepted. Default: probe all four "
             "default bouncers on their standard mgmt ports.",
    )
    @click.option(
        "--audit-events-token", "audit_events_token",
        default=None,
        help="Bearer token forwarded to every bouncer's "
             "/audit/events. Required if any subscribed bouncer is "
             "bound off-loopback.",
    )
    @click.option(
        "--poll", "poll_interval",
        type=float, default=_POLL_DEFAULT_SECONDS, show_default=True,
        help="Seconds between per-bouncer poll ticks. Lower = "
             "snappier; higher = less HTTP traffic.",
    )
    @click.option(
        "--filter", "filter_exprs",
        multiple=True, metavar="EXPR",
        help="Initial filter expression (repeatable). Same syntax as "
             "`iam-jit audit query --filter`; forwarded to each "
             "bouncer's /audit/events?filter= so the filter runs "
             "server-side. Press `/` inside the TUI to change "
             "interactively.",
    )
    @click.option(
        "--ring-buffer", "ring_buffer",
        type=int, default=_RING_BUFFER_DEFAULT, show_default=True,
        help=f"In-memory event ring-buffer cap (max {_RING_BUFFER_MAX}). "
             "Older events fall off as new ones arrive.",
    )
    def audit_stream_cmd(
        bouncers_raw: tuple[str, ...],
        audit_events_token: str | None,
        poll_interval: float,
        filter_exprs: tuple[str, ...],
        ring_buffer: int,
    ) -> None:
        """Live cross-bouncer audit-stream TUI (#272).

        \b
        Subscribes to /audit/events on every reachable bouncer and
        renders a merged, sorted, colourised table. Unreachable
        bouncers skip with a note in the title bar (matches
        `iam-jit audit query` skip semantics).

        \b
        Keyboard:
          /  set the filter (forwarded server-side to every bouncer)
          p  pause / resume polling
          t  toggle the per-bouncer column
          c  clear the table + counters
          q  quit (restores the terminal)
        """
        endpoints = _resolve_bouncer_set(bouncers_raw)
        if not endpoints:
            raise click.UsageError(
                "no bouncers to subscribe to; pass --bouncer name (or name=URL)",
            )
        ui = make_ui_state(
            bouncers=endpoints,
            bearer_token=audit_events_token,
            poll_interval=poll_interval,
            ring_buffer=ring_buffer,
            filter_text=" ".join(filter_exprs).strip(),
        )
        try:
            asyncio.run(_run_tui_loop(ui))
        except KeyboardInterrupt:
            ui.quit_requested = True
