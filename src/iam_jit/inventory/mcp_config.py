# ADOPT-3 / #717 — MCP-config server/tool discovery.
"""Read configured MCP servers (and, where possible, their tools) from
the agent harness's on-disk config files.

Config-path ladder mirrors ``cli_init._detect_harness`` +
``cli_uninstall._check_mcp_entries`` so the inventory sees exactly the
same files the install/uninstall paths manage. Both the top-level
``mcpServers`` block and any per-project ``projects[*].mcpServers``
blocks are scanned (Claude Code stashes project-scoped servers under
``projects``).

Per [[ibounce-honest-positioning]]:
  * A static MCP config declares how to LAUNCH a server (command / args
    / env, or a url for SSE/HTTP servers) — it does NOT list the
    server's tools. So ``tools`` is reported as
    ``"unknown — not enumerable from static config"`` for every server
    EXCEPT iam-jit's own, whose tool names we read from the in-process
    ``mcp_server.TOOLS`` registry.
  * No token VALUE is ever surfaced: we report ``authed`` (does this
    server carry an auth secret in its ``env`` / ``headers`` / ``url``)
    as a bool, plus the NAMES of the credential-shaped fields, never
    their contents.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from ..posture.sanitize import is_credential_env_name

# iam-jit's own MCP server keys (mirrors cli_uninstall.MCP_SERVER_NAMES
# semantics — the names iam-jit + the Bounce suite register under).
_IAM_JIT_SERVER_NAMES = frozenset(
    {"iam-jit", "ibounce", "kbounce", "kbouncer", "dbounce", "gbounce"}
)

# Header tokens that look like an auth secret inside an SSE/HTTP server's
# `headers` map. Value is never emitted — only the presence.
_AUTH_HEADER_NAMES = frozenset(
    {"authorization", "x-api-key", "api-key", "proxy-authorization"}
)

_TOOLS_UNKNOWN = "unknown — not enumerable from static config"


def harness_config_candidates(
    home: pathlib.Path | None = None,
) -> list[tuple[str, pathlib.Path]]:
    """Return ``(harness_name, path)`` candidates in detection order.

    Mirrors the ladder in ``cli_init._detect_harness``. ``home``
    override exists for test isolation (point at a tmp_path).
    """
    h = home if home is not None else pathlib.Path.home()
    return [
        ("claude-code", h / ".claude.json"),
        ("claude-code", h / ".config" / "claude-code" / "mcp.json"),
        ("cursor", h / ".cursor" / "mcp.json"),
        (
            "claude-desktop",
            h
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json",
        ),
        (
            "claude-desktop",
            h / ".config" / "Claude" / "claude_desktop_config.json",
        ),
    ]


def _load_json(path: pathlib.Path) -> dict[str, Any] | None:
    """Best-effort JSON read. Returns None on missing / unreadable /
    non-object content. Never raises (parse failure is non-fatal per
    [[ibounce-honest-positioning]] — a malformed config is reported as
    a discovery NOTE upstream, not a crash)."""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None  # noqa: SD-4 fail-soft by contract; caller (discover_mcp_servers) treats None as "present-but-unreadable" + emits a discovery note — failure IS distinguished
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None  # noqa: SD-4 fail-soft by contract; None -> "not valid JSON" discovery note upstream, not silent
    if not isinstance(data, dict):
        return None
    return data


def _iam_jit_tool_names() -> list[str]:
    """Read iam-jit's own MCP tool names from the in-process registry.

    Best-effort: importing ``mcp_server`` is heavy-ish but safe (it
    only builds the static ``TOOLS`` list at import time). On any import
    failure we return ``[]`` and the caller falls back to the
    ``unknown`` marker — honest about the gap rather than fabricating.
    """
    try:
        from ..mcp_server import TOOLS
    except Exception:
        return []
    names: list[str] = []
    for t in TOOLS:
        if isinstance(t, dict):
            n = t.get("name")
            if isinstance(n, str) and n:
                names.append(n)
    return sorted(set(names))


def _server_authed(server: dict[str, Any]) -> tuple[bool, list[str]]:
    """Decide whether an MCP server entry carries an auth secret.

    Returns ``(authed, credential_field_names)``. We inspect — WITHOUT
    reading any value:
      * ``env``: any key whose NAME is credential-shaped
        (``*_TOKEN`` / ``*_KEY`` / ``*_SECRET`` / ...), via the same
        ``is_credential_env_name`` predicate the posture sanitizer uses.
      * ``headers`` (SSE/HTTP servers): an ``Authorization`` /
        ``X-Api-Key`` / ... header.
      * ``url``: userinfo credentials (``https://user:pass@host``) or a
        ``?token=`` / ``?api_key=`` query param.

    Only field NAMES are returned — never values. Per [[push-policy-
    public-repo]] + the #717 brief, token values must not leak.
    """
    cred_fields: list[str] = []

    env = server.get("env")
    if isinstance(env, dict):
        for k in env:
            if isinstance(k, str) and is_credential_env_name(k):
                cred_fields.append(f"env.{k}")

    headers = server.get("headers")
    if isinstance(headers, dict):
        for k in headers:
            if isinstance(k, str) and k.lower() in _AUTH_HEADER_NAMES:
                cred_fields.append(f"headers.{k}")

    url = server.get("url")
    if isinstance(url, str) and url:
        # userinfo credentials: scheme://user:pass@host
        after_scheme = url.split("://", 1)[1] if "://" in url else url
        authority = after_scheme.split("/", 1)[0]
        if "@" in authority:
            cred_fields.append("url.userinfo")
        low = url.lower()
        if "token=" in low or "api_key=" in low or "apikey=" in low:
            cred_fields.append("url.query_token")

    return (bool(cred_fields), sorted(set(cred_fields)))


def _transport_of(server: dict[str, Any]) -> str:
    """Classify the server's transport. ``stdio`` when it declares a
    launch ``command``; ``sse``/``http`` when it declares a ``url``;
    ``unknown`` otherwise (honest, not guessed)."""
    explicit = server.get("type")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().lower()
    if isinstance(server.get("url"), str) and server.get("url"):
        return "remote"
    if server.get("command"):
        return "stdio"
    return "unknown"


def _server_record(
    name: str,
    server: dict[str, Any],
    *,
    source: str,
    iam_jit_tools: list[str],
) -> dict[str, Any]:
    """Build one inventory record for a configured MCP server.

    Never emits a token value: ``command`` / ``args`` / ``url`` are
    structural launch metadata (paths, flags, hostnames) and are passed
    to the upstream sanitizer before emit; ``env`` VALUES are dropped
    entirely (only credential-field NAMES survive, via ``authed``).
    """
    if not isinstance(server, dict):
        server = {}
    transport = _transport_of(server)
    authed, cred_fields = _server_authed(server)
    is_own = name in _IAM_JIT_SERVER_NAMES

    # Tools: only knowable for iam-jit's own server (via the registry).
    if is_own and name in ("iam-jit",) and iam_jit_tools:
        tools: Any = iam_jit_tools
        tools_note = "from in-process iam-jit TOOLS registry"
    else:
        tools = _TOOLS_UNKNOWN
        tools_note = (
            "MCP configs declare a launch command, not a tool list; "
            "run the server + call tools/list to enumerate"
        )

    record: dict[str, Any] = {
        "name": name,
        "source": source,
        "transport": transport,
        # Structural launch metadata only (sanitized upstream). For a
        # remote server we surface the host (not the full URL with any
        # query token).
        "command": server.get("command") if server.get("command") else None,
        "remote_host": _url_host(server.get("url"))
        if isinstance(server.get("url"), str)
        else None,
        "iam_jit_owned": is_own,
        "authed": authed,
        "credential_fields": cred_fields,
        "tools": tools,
        "tools_note": tools_note,
    }
    return record


def _url_host(url: str | None) -> str | None:
    """Extract scheme://host[:port] from a URL, dropping userinfo +
    path + query (so no embedded token survives)."""
    if not url:
        return None
    if "://" in url:
        scheme, rest = url.split("://", 1)
    else:
        scheme, rest = "", url
    authority = rest.split("/", 1)[0]
    if "@" in authority:
        authority = authority.split("@", 1)[1]
    return f"{scheme}://{authority}" if scheme else authority


def discover_mcp_servers(
    home: pathlib.Path | None = None,
) -> dict[str, Any]:
    """Walk the config-path ladder + enumerate configured MCP servers.

    Returns::

        {
          "configs_scanned": [{"harness": str, "path": str,
                               "present": bool, "parse_ok": bool}, ...],
          "servers": [<server record>, ...],
          "notes": [str, ...],
        }

    Each scanned config is reported (present or not) so an operator can
    see WHERE we looked — honest about an empty result vs. an unreadable
    file. Servers are de-duplicated by ``(source-path, name)`` so a
    server appearing in both top-level + a project block is listed once
    per location.
    """
    iam_jit_tools = _iam_jit_tool_names()
    configs_scanned: list[dict[str, Any]] = []
    servers: list[dict[str, Any]] = []
    notes: list[str] = []

    seen_paths: set[str] = set()
    for harness, path in harness_config_candidates(home):
        path_str = str(path)
        if path_str in seen_paths:
            continue
        seen_paths.add(path_str)
        present = path.exists()
        entry: dict[str, Any] = {
            "harness": harness,
            "path": path_str,
            "present": present,
            "parse_ok": False,
        }
        if not present:
            configs_scanned.append(entry)
            continue
        data = _load_json(path)
        if data is None:
            entry["parse_ok"] = False
            notes.append(
                f"{path_str}: present but unreadable / not valid JSON object "
                "— skipped (no servers enumerated from it)"
            )
            configs_scanned.append(entry)
            continue
        entry["parse_ok"] = True
        configs_scanned.append(entry)

        # Top-level mcpServers.
        top = data.get("mcpServers")
        if isinstance(top, dict):
            for name, server in top.items():
                if not isinstance(name, str):
                    continue
                servers.append(
                    _server_record(
                        name,
                        server if isinstance(server, dict) else {},
                        source=f"{path_str}:mcpServers.{name}",
                        iam_jit_tools=iam_jit_tools,
                    )
                )

        # Per-project mcpServers (Claude Code project scope).
        projects = data.get("projects")
        if isinstance(projects, dict):
            for proj_key, proj_val in projects.items():
                if not isinstance(proj_val, dict):
                    continue
                proj_mcp = proj_val.get("mcpServers")
                if not isinstance(proj_mcp, dict):
                    continue
                for name, server in proj_mcp.items():
                    if not isinstance(name, str):
                        continue
                    servers.append(
                        _server_record(
                            name,
                            server if isinstance(server, dict) else {},
                            source=(
                                f"{path_str}:projects.{proj_key}"
                                f".mcpServers.{name}"
                            ),
                            iam_jit_tools=iam_jit_tools,
                        )
                    )

    if not servers and not any(c["present"] for c in configs_scanned):
        notes.append(
            "no MCP harness config found on the standard path ladder; "
            "either no harness is installed or it stores config "
            "elsewhere — nothing to enumerate (not an error)"
        )

    return {
        "configs_scanned": configs_scanned,
        "servers": servers,
        "notes": notes,
    }


__all__ = [
    "discover_mcp_servers",
    "harness_config_candidates",
]
