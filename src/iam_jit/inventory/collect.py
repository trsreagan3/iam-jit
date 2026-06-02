# ADOPT-3 / #717 — top-level inventory assembly + table renderer.
"""Assemble the MCP/A2A attack-surface inventory + render it.

Three surfaces, each risk-tagged:

  1. ``mcp_servers`` — configured MCP servers + (where knowable) tools,
     from :mod:`iam_jit.inventory.mcp_config`.
  2. ``bouncers`` — the bouncers wired + their ports/endpoints, a
     risk-tagged projection of ``posture.detect_all_bouncers`` (REUSE,
     not reinvented).
  3. ``a2a_endpoints`` — A2A / agent endpoints discoverable from the
     environment (the bouncer mgmt/wire ports an agent or peer can be
     reached through, plus any explicit A2A endpoint env vars).

Each entry carries risk-relevant metadata: ``loopback_only`` (is the
reachable surface bound to 127.0.0.1) and ``authed`` (does it carry an
auth secret) — both reported as ``true`` / ``false`` / ``"unknown"``
honestly per [[ibounce-honest-positioning]].

The whole snapshot is run through ``posture.sanitize_posture`` before
return so no credential-shaped value escapes — belt-and-suspenders on
top of the field-level no-value-emit discipline in ``mcp_config``.
"""

from __future__ import annotations

import datetime as _dt
import os
from typing import Any

from ..posture.bouncers import detect_all_bouncers
from ..posture.sanitize import sanitize_posture
from .mcp_config import _url_host, discover_mcp_servers

INVENTORY_SCHEMA_VERSION = "1.0"

# Explicit A2A endpoint env vars an operator may set to point the agent
# at a peer-agent endpoint. We report the NAME + whether it's loopback;
# the value is a URL that may carry a secret (userinfo password or a
# ``?token=`` query param), so we surface ONLY scheme://host[:port] via
# ``_url_host`` (userinfo + query stripped) — never the raw value.
_A2A_ENDPOINT_ENV_VARS = (
    "IAM_JIT_A2A_ENDPOINT",
    "A2A_ENDPOINT",
    "AGENT_TO_AGENT_ENDPOINT",
)

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _host_is_loopback(host: str | None) -> bool | None:
    """Return True/False, or None when host is unknown."""
    if host is None:
        return None
    h = host.strip().lower()
    if not h:
        return None
    # Strip scheme + path if a full URL was passed.
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    if "@" in h:
        h = h.split("@", 1)[1]
    # Strip port.
    if h.startswith("["):
        h = h.split("]", 1)[0] + "]"
    else:
        h = h.split(":", 1)[0]
    return h in _LOOPBACK_HOSTS


def _bouncer_surface(bouncers: dict[str, Any]) -> list[dict[str, Any]]:
    """Risk-tagged projection of the posture bouncer block.

    For each bouncer we surface name / running / port(s) / endpoint /
    whether the operator env var is wired to it / misconfig — all of
    which posture already computed. We ADD the inventory-specific risk
    tags: ``loopback_only`` (bouncers bind loopback by design — True
    when running) and ``authed`` ("unknown" — the bouncer mgmt surface
    auth posture isn't introspectable from this process, reported
    honestly rather than assumed open).
    """
    out: list[dict[str, Any]] = []
    for name in ("ibounce", "kbounce", "dbounce", "gbounce"):
        b = bouncers.get(name)
        if not isinstance(b, dict):
            continue
        running = bool(b.get("running"))
        port = b.get("port")
        mgmt_port = b.get("mgmt_port")
        endpoints: list[str] = []
        if port is not None:
            endpoints.append(f"127.0.0.1:{port}")
        if mgmt_port is not None and mgmt_port != port:
            endpoints.append(f"127.0.0.1:{mgmt_port} (mgmt)")
        out.append(
            {
                "name": name,
                "wired": running or bool(b.get("env_var_pointing_here")),
                "running": running,
                "port": port,
                "mgmt_port": mgmt_port,
                "endpoints": endpoints,
                "env_var_pointing_here": b.get("env_var_pointing_here"),
                "misconfig": b.get("misconfig"),
                # Bouncers bind loopback by design; only meaningful when
                # we actually saw it listening.
                "loopback_only": True if running else "unknown",
                # The bouncer mgmt/wire surface auth posture is not
                # introspectable cross-process — honest "unknown".
                "authed": "unknown",
            }
        )
    return out


def _url_carries_auth(url: str) -> bool:
    """True if a URL carries an auth secret (userinfo creds or a
    ``?token=`` / ``?api_key=`` / ``?sig=`` query param).

    Mirrors ``mcp_config._server_authed``'s url inspection: only the
    PRESENCE of a secret is returned — the value is never read out."""
    after_scheme = url.split("://", 1)[1] if "://" in url else url
    authority = after_scheme.split("/", 1)[0]
    if "@" in authority:
        return True
    low = url.lower()
    return (
        "token=" in low
        or "api_key=" in low
        or "apikey=" in low
        or "sig=" in low
    )


def _a2a_endpoints(bouncers: dict[str, Any]) -> dict[str, Any]:
    """Enumerate A2A / agent-reachable endpoints.

    Two sources:
      * Explicit A2A endpoint env vars (operator-declared peer-agent
        endpoints) — reported by NAME + loopback flag.
      * The bouncer wire/mgmt ports: these ARE the endpoints through
        which the agent (sitting behind a bouncer) is reachable /
        reaches out. We surface them as agent-reachable surface so the
        operator sees the full "be-reached-through" picture.

    Per [[ibounce-honest-positioning]]: when no A2A env var is set and
    no bouncer is listening, the list is empty + a note explains that
    iam-jit cannot fabricate endpoints it can't observe.
    """
    endpoints: list[dict[str, Any]] = []
    notes: list[str] = []

    for env_name in _A2A_ENDPOINT_ENV_VARS:
        val = os.environ.get(env_name, "").strip()
        if not val:
            continue
        endpoints.append(
            {
                "kind": "a2a-env",
                "env_var": env_name,
                # NEVER the raw value: a URL may embed a userinfo
                # password or a ?token=/?api_key=/?sig= query secret.
                # Surface scheme://host[:port] only (userinfo + query
                # stripped by _url_host), mirroring the MCP-config path.
                "endpoint": _url_host(val),
                "loopback_only": _host_is_loopback(val),
                # We CAN tell whether the URL carried a secret (presence
                # only) — report it honestly instead of "unknown".
                "authed": _url_carries_auth(val),
            }
        )

    for name in ("ibounce", "kbounce", "dbounce", "gbounce"):
        b = bouncers.get(name)
        if not isinstance(b, dict) or not b.get("running"):
            continue
        port = b.get("port")
        if port is not None:
            endpoints.append(
                {
                    "kind": "bouncer-surface",
                    "bouncer": name,
                    "endpoint": f"127.0.0.1:{port}",
                    "loopback_only": True,
                    "authed": "unknown",
                }
            )

    if not endpoints:
        notes.append(
            "no A2A endpoint env var set + no bouncer listening; no "
            "agent-reachable endpoints discoverable from this process "
            "(not an error — nothing to report)"
        )

    return {"endpoints": endpoints, "notes": notes}


def _risk_summary(
    mcp: dict[str, Any],
    bouncer_surface: list[dict[str, Any]],
    a2a: dict[str, Any],
) -> dict[str, Any]:
    """Roll up countable, non-fabricated risk-relevant tallies.

    Every number here is a direct count off the enumerated surface —
    no inference, no scoring. Per [[scorer-is-ground-truth]] this is a
    descriptive inventory, not a risk score."""
    servers = mcp.get("servers", [])
    non_loopback_a2a = [
        e for e in a2a.get("endpoints", []) if e.get("loopback_only") is False
    ]
    return {
        "mcp_server_count": len(servers),
        "mcp_servers_authed": sum(1 for s in servers if s.get("authed")),
        "mcp_servers_unauthed": sum(
            1 for s in servers if s.get("authed") is False
        ),
        # Remote = any non-stdio transport: a static config may declare
        # the transport as "remote" OR a concrete wire ("sse" / "http" /
        # "streamable-http"). Anything carrying a remote_host is remote
        # regardless of how the transport string was spelled.
        "mcp_servers_remote": sum(
            1
            for s in servers
            if s.get("transport")
            in {"remote", "sse", "http", "streamable-http"}
            or s.get("remote_host")
        ),
        "bouncers_running": sum(
            1 for b in bouncer_surface if b.get("running")
        ),
        "bouncers_misconfigured": sum(
            1 for b in bouncer_surface if b.get("misconfig")
        ),
        "a2a_endpoint_count": len(a2a.get("endpoints", [])),
        "a2a_non_loopback_count": len(non_loopback_a2a),
    }


def capture_inventory(
    *,
    sanitize: bool = True,
    home: Any = None,
) -> dict[str, Any]:
    """Assemble the full MCP/A2A attack-surface inventory.

    Always safe to call (each sub-discovery is fail-soft + non-raising).
    When ``sanitize`` is True (default + recommended) the snapshot is
    run through the credential-scrubbing pass before returning so no
    token value escapes. ``home`` overrides the MCP-config search root
    (test isolation)."""
    bouncers = detect_all_bouncers()
    mcp = discover_mcp_servers(home=home)
    bouncer_surface = _bouncer_surface(bouncers)
    a2a = _a2a_endpoints(bouncers)
    snapshot: dict[str, Any] = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "captured_at": _dt.datetime.now(_dt.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "mcp_servers": mcp.get("servers", []),
        "mcp_configs_scanned": mcp.get("configs_scanned", []),
        "mcp_notes": mcp.get("notes", []),
        "bouncers": bouncer_surface,
        "a2a_endpoints": a2a.get("endpoints", []),
        "a2a_notes": a2a.get("notes", []),
        "risk_summary": _risk_summary(mcp, bouncer_surface, a2a),
    }
    if sanitize:
        snapshot = sanitize_posture(snapshot)
    return snapshot


# ---------------------------------------------------------------------------
# Human / table renderer
# ---------------------------------------------------------------------------


def _fmt_authed(val: Any) -> str:
    if val is True:
        return "authed"
    if val is False:
        return "no-auth"
    return "auth?"


def _fmt_loopback(val: Any) -> str:
    if val is True:
        return "loopback"
    if val is False:
        return "NON-LOOPBACK"
    return "scope?"


def render_inventory_table(snapshot: dict[str, Any]) -> str:
    """Render the inventory snapshot as a human-readable table-ish
    block. Stable section headers (tests pin them)."""
    lines: list[str] = []
    lines.append("== iam-jit inventory — MCP/A2A attack surface ==")
    lines.append(f"Captured: {snapshot.get('captured_at', '?')}")
    rs = snapshot.get("risk_summary", {})
    lines.append(
        "Summary: "
        f"{rs.get('mcp_server_count', 0)} MCP server(s) "
        f"({rs.get('mcp_servers_authed', 0)} authed, "
        f"{rs.get('mcp_servers_unauthed', 0)} no-auth, "
        f"{rs.get('mcp_servers_remote', 0)} remote); "
        f"{rs.get('bouncers_running', 0)} bouncer(s) running"
        + (
            f", {rs.get('bouncers_misconfigured', 0)} MISCONFIGURED"
            if rs.get("bouncers_misconfigured")
            else ""
        )
        + f"; {rs.get('a2a_endpoint_count', 0)} A2A endpoint(s)"
        + (
            f" ({rs.get('a2a_non_loopback_count', 0)} NON-LOOPBACK)"
            if rs.get("a2a_non_loopback_count")
            else ""
        )
    )

    lines.append("")
    lines.append("MCP servers:")
    servers = snapshot.get("mcp_servers", [])
    if not servers:
        lines.append("  (none configured / discoverable)")
    for s in servers:
        own = "  [iam-jit]" if s.get("iam_jit_owned") else ""
        lines.append(
            f"  {s.get('name')}  "
            f"[{s.get('transport', 'unknown')}]  "
            f"{_fmt_authed(s.get('authed'))}{own}"
        )
        tools = s.get("tools")
        if isinstance(tools, list):
            lines.append(
                f"    tools ({len(tools)}): {', '.join(tools[:8])}"
                + (" ..." if len(tools) > 8 else "")
            )
        else:
            lines.append(f"    tools: {tools}")
        if s.get("credential_fields"):
            lines.append(
                f"    auth fields: {', '.join(s['credential_fields'])} "
                "(values not shown)"
            )

    lines.append("")
    lines.append("Bouncers (wired surface):")
    bouncers = snapshot.get("bouncers", [])
    for b in bouncers:
        state = "RUNNING" if b.get("running") else "stopped"
        eps = ", ".join(b.get("endpoints", [])) or "(no endpoint)"
        lines.append(
            f"  {b.get('name')}: {state}  {eps}  "
            f"{_fmt_loopback(b.get('loopback_only'))}"
        )
        if b.get("env_var_pointing_here"):
            lines.append(f"    env: {b['env_var_pointing_here']}")
        if b.get("misconfig"):
            lines.append(f"    MISCONFIG: {b['misconfig']}")

    lines.append("")
    lines.append("A2A / agent-reachable endpoints:")
    a2a = snapshot.get("a2a_endpoints", [])
    if not a2a:
        lines.append("  (none discoverable)")
    for e in a2a:
        label = e.get("bouncer") or e.get("env_var") or e.get("kind", "?")
        lines.append(
            f"  {label}: {e.get('endpoint')}  "
            f"{_fmt_loopback(e.get('loopback_only'))}  "
            f"{_fmt_authed(e.get('authed'))}"
        )

    notes = list(snapshot.get("mcp_notes", [])) + list(
        snapshot.get("a2a_notes", [])
    )
    if notes:
        lines.append("")
        lines.append("Notes:")
        for n in notes:
            lines.append(f"  - {n}")

    return "\n".join(lines)


def inventory_for_mcp(args: dict | None = None) -> dict:  # noqa: SD-2 args reserved for MCP schema parity (mirrors posture_for_mcp); snapshot is captured fresh per call
    """MCP backend for the ``iam_jit_inventory`` tool. Returns the
    sanitized inventory snapshot. ``args`` is accepted for schema parity
    with other MCP handlers; the snapshot is captured FRESH on every
    call so agents that poll see live truth."""
    return capture_inventory(sanitize=True)


__all__ = [
    "INVENTORY_SCHEMA_VERSION",
    "capture_inventory",
    "render_inventory_table",
    "inventory_for_mcp",
]
