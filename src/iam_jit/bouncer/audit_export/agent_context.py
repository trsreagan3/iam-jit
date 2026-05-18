"""Agent identity + persistent session ID for audit-export (#266).

Per [[agent-identity-in-audit]] the gap closed here is "which agent
made this call months later." Today's audit row carries good USER
identity (operator email/principal) but no AGENT identity (was this
Claude Code, Cursor, Devin, a raw script?). This module fills that
gap with three best-effort detection paths, in priority order:

  1. MCP `clientInfo` — captured at `initialize` time. The MCP spec
     requires the client to send `{name, version}` in the initialize
     params; we bind that to the (single, per-process) stdio MCP
     session. Highest fidelity — the agent literally tells us who
     it is.
  2. User-Agent header — captured per-call by the HTTP proxy. We map
     known UA patterns to canonical agent names; unknown UAs are
     surfaced verbatim under `detected_from: "user_agent_raw"` so
     SIEM filters can still group on the raw string.
  3. Process-tree fallback — when the proxy gets an inbound from
     PID X (when the platform surfaces a remote PID — rare for TCP
     sockets), walk the parent chain and look at exe basenames.
     Heuristic; default Informational severity; NOT propagated to
     the webhook by default per [[security-team-positioning-safety-
     not-surveillance]].

Per [[scorer-is-ground-truth]] this is honest-effort detection: when
we don't know we mark `name="unknown"` + `detected_from="unknown"`
rather than guessing. Per [[ibounce-honest-positioning]] we never
claim 100% — non-MCP raw boto3 scripts with no User-Agent legitimately
land at `unknown`, and that's the correct answer.

Per [[deliberate-feature-completion]] the agent block lands under
`unmapped.iam_jit.agent` in the same OCSF event the existing
audit_event_from_decision builds; this module is the in-memory
context store + detection helpers that feed it.

Session ID lifecycle:
  - Minted at MCP `initialize` (UUID v7 if available, else UUID v4)
  - Bound to the MCP connection (one stdio process = one session)
  - Carried on every subsequent OCSF event from that agent until
    the MCP connection closes
  - On close: a `SESSION_ENDED` synthetic event fires + the session
    retires

Edge cases:
  - Non-MCP agent (raw boto3 from a cron job): no session_id; we
    return None and the OCSF event builder omits the agent block
    unless a User-Agent or process-tree hit gives us SOMETHING.
  - Multiple agents per machine: each MCP stdio invocation is its
    own process => its own MCP server module instance => its own
    session. The module-level store is naturally process-scoped.
  - Reconnect: each MCP `initialize` mints a fresh session_id by
    design (reconnect signals state-loss; correlating across
    reconnects would be misleading).
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# UUID v7 (fallback to UUID v4 on Python < 3.14)
# ---------------------------------------------------------------------------
#
# UUID v7 is time-ordered (millisecond Unix epoch in the leading
# 48 bits) + random in the trailing 80 bits. The time-ordering
# matters for SIEM queries that want to range-scan a single agent
# session's events; v4 forces a full-table sort. Python 3.14 added
# `uuid.uuid7()`; older versions fall back to `uuid.uuid4()` which
# is still cryptographically random (the order property is the
# only thing we lose).
#
# Per [[agent-identity-in-audit]] memo: session IDs must NOT be
# predictable (no counters) so a malicious agent can't forge
# "this came from session X". Both v7 + v4 carry enough random
# entropy to make forgery infeasible.


def _new_session_id() -> str:
    """Mint a fresh agent session ID. Prefer UUID v7, fall back to v4."""
    if hasattr(uuid, "uuid7"):
        return str(uuid.uuid7())
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# User-Agent -> canonical agent-name map
# ---------------------------------------------------------------------------
#
# Substring match (case-insensitive). Order matters when patterns
# overlap (claude-code first so a UA like "claude-code/1.2 (python-
# httpx)" doesn't get bucketed as `python-httpx`).
#
# This table is intentionally short. Per [[scorer-is-ground-truth]]
# we don't guess: unknown UAs are recorded verbatim under
# detected_from=user_agent_raw rather than mapped to a fake name.
# Per [[deliberate-feature-completion]] new entries land here when
# we've seen the UA in the wild AND verified it's the agent (not
# a coincidence on substring).

_USER_AGENT_MAP: tuple[tuple[str, str], ...] = (
    # AI agent IDE / agent tools — fingerprint substrings in order
    # of specificity. Each tuple: (substring_lower, canonical_name).
    ("claude-code", "claude-code"),
    ("claude code", "claude-code"),
    ("cursor", "cursor"),
    ("devin", "devin"),
    ("codex", "codex"),
    ("aider", "aider"),
    ("continue.dev", "continue"),
    ("windsurf", "windsurf"),
    # AWS-SDK UAs (so audit reviewers can at least tell "this was
    # boto3" vs "this was the JS SDK" vs an agent-shaped UA).
    ("boto3", "aws-sdk-python"),
    ("botocore", "aws-sdk-python"),
    ("aws-sdk-js", "aws-sdk-js"),
    ("aws-sdk-go", "aws-sdk-go"),
    ("aws-cli", "aws-cli"),
)


def _parse_version_from_ua(ua: str) -> str | None:
    """Best-effort version extraction. Looks for `<name>/<version>`
    or `<name> <version>` patterns. Returns None when nothing
    parseable. Per [[scorer-is-ground-truth]] we don't invent
    versions — if the UA doesn't carry one, `version` stays None.
    """
    if not ua:
        return None
    # Common: "claude-code/1.2.3 (...)". Take the first /vvv token.
    for sep in ("/", " "):
        for token in ua.split():
            if sep in token:
                _, _, tail = token.partition(sep)
                # Trim trailing punctuation / parens.
                tail = tail.strip().rstrip(",;()")
                if tail and tail[0].isdigit():
                    return tail
    return None


def detect_from_user_agent(ua: str | None) -> dict[str, Any] | None:
    """Map a User-Agent string to an agent dict.

    Returns:
      {"name": <canonical>, "version": <str or None>, "detected_from": "user_agent"}
        when the UA matches a known pattern
      {"name": "unknown", "version": None,
       "detected_from": "user_agent_raw", "raw_ua": <ua>}
        when the UA is present but unknown — the raw string is
        preserved so SIEM filters can still grep on it
      None when no UA was supplied
    """
    if not ua:
        return None
    ua_lower = ua.lower()
    for substring, name in _USER_AGENT_MAP:
        if substring in ua_lower:
            return {
                "name": name,
                "version": _parse_version_from_ua(ua),
                "detected_from": "user_agent",
            }
    # Unknown UA: preserve it raw. Truncate at 256 chars defensively
    # (some SDK UAs are pathological; 256 is enough for grep/filter).
    return {
        "name": "unknown",
        "version": None,
        "detected_from": "user_agent_raw",
        "raw_ua": ua[:256],
    }


# ---------------------------------------------------------------------------
# Process-tree fallback (best-effort, per-platform)
# ---------------------------------------------------------------------------
#
# This path is the weakest of the three. We only use it when the
# proxy KNOWS the inbound PID (rare — TCP sockets don't carry one
# unless we're on a Unix domain socket). Even when we have a PID,
# walking up the parent chain to a recognisable agent IDE is
# heuristic: an agent that exec()s a script that exec()s boto3 may
# not show "claude-code" anywhere in its ancestry.
#
# Per [[security-team-positioning-safety-not-surveillance]] the
# process-tree info is SENSITIVE (reveals the operator's tooling).
# Default OCSF severity stays Informational; the operator must opt
# in to propagate this fingerprint to the webhook (the JSONL log
# always carries it for local forensics).
#
# Per [[scorer-is-ground-truth]] we don't guess: if no ancestor
# matches a known agent, we return None and the caller falls back
# to "unknown".


# Same map of basename substrings -> canonical agent name. Kept
# separate from the UA map because process names + UA strings
# overlap inconsistently (e.g. `claude` the binary vs `claude-code/x`
# the UA).
_PROCESS_NAME_MAP: tuple[tuple[str, str], ...] = (
    ("claude-code", "claude-code"),
    ("claude", "claude-code"),
    ("cursor", "cursor"),
    ("devin", "devin"),
    ("codex", "codex"),
    ("aider", "aider"),
    ("continue", "continue"),
    ("windsurf", "windsurf"),
)


def _walk_parent_pids(pid: int, max_depth: int = 12) -> list[int]:
    """Return [pid, parent_pid, grandparent_pid, ...] up to max_depth.

    Best-effort; returns whatever we can resolve before hitting init
    (PID 1) or an error. Stops on duplicate PIDs (cycle guard, paranoid
    — shouldn't happen under a sane kernel but ps output has surprised
    us before)."""
    chain: list[int] = []
    current = pid
    seen: set[int] = set()
    for _ in range(max_depth):
        if current in seen or current <= 0:
            break
        seen.add(current)
        chain.append(current)
        parent = _ppid(current)
        if parent is None or parent == 0:
            break
        current = parent
    return chain


def _ppid(pid: int) -> int | None:
    """Return the parent PID for `pid` on Linux or macOS. None on error."""
    # Linux first — /proc is cheap + ps may not be installed in slim
    # containers.
    proc_status = f"/proc/{pid}/status"
    if os.path.exists(proc_status):
        try:
            with open(proc_status) as fh:
                for line in fh:
                    if line.startswith("PPid:"):
                        return int(line.split()[1])
        except (OSError, ValueError):
            return None
        return None
    # macOS / BSD — shell out to `ps`. We restrict the command and
    # arguments aggressively + use a 1s timeout so a stuck ps can't
    # block the audit-export hot path.
    try:
        out = subprocess.run(
            ["ps", "-o", "ppid=", "-p", str(int(pid))],
            capture_output=True, text=True, timeout=1.0, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    raw = out.stdout.strip()
    if not raw:
        return None
    try:
        return int(raw.split()[0])
    except (ValueError, IndexError):
        return None


def _exe_name(pid: int) -> str | None:
    """Return the basename of the exe behind `pid`, or None on error.

    Linux: /proc/<pid>/exe symlink.
    macOS: `ps -o comm= -p <pid>`.
    """
    proc_exe = f"/proc/{pid}/exe"
    if os.path.exists(proc_exe):
        try:
            return os.path.basename(os.readlink(proc_exe))
        except OSError:
            return None
    try:
        out = subprocess.run(
            ["ps", "-o", "comm=", "-p", str(int(pid))],
            capture_output=True, text=True, timeout=1.0, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    raw = out.stdout.strip()
    if not raw:
        return None
    return os.path.basename(raw.splitlines()[0])


def detect_from_process_tree(pid: int | None) -> dict[str, Any] | None:
    """Walk up from `pid` looking for a recognisable agent binary.

    Returns the agent dict on hit, None when no ancestor matches.
    `pid` of None / 0 short-circuits to None. Per [[security-team-
    positioning-safety-not-surveillance]] callers MAY choose not to
    propagate this fingerprint to the webhook — the dict carries
    a `process_tree_info` block the webhook side can strip.
    """
    if not pid or pid <= 0:
        return None
    chain = _walk_parent_pids(int(pid))
    if not chain:
        return None
    for ancestor_pid in chain:
        name = _exe_name(ancestor_pid)
        if not name:
            continue
        name_lower = name.lower()
        for substring, canonical in _PROCESS_NAME_MAP:
            if substring in name_lower:
                return {
                    "name": canonical,
                    "version": None,
                    "detected_from": "process_tree",
                    "process_tree_info": {
                        "matched_pid": ancestor_pid,
                        "matched_exe": name,
                    },
                }
    return None


# ---------------------------------------------------------------------------
# MCP-session context store
# ---------------------------------------------------------------------------
#
# A single per-process slot holding the currently-active MCP session.
# The MCP server module is loaded once per stdio invocation, so this
# slot's natural scope (the process) matches the MCP session's
# natural scope (one stdio connection per process). Thread-safe so
# tests can exercise concurrent reads, but the production path is
# single-threaded.


@dataclass(frozen=True)
class AgentSession:
    """A captured MCP `initialize` clientInfo + a minted session ID."""

    session_id: str
    name: str
    version: str | None
    detected_from: str  # always "mcp_clientinfo" for this dataclass


_LOCK = threading.Lock()
_ACTIVE: AgentSession | None = None


def begin_mcp_session(client_info: dict[str, Any] | None) -> AgentSession:
    """Mint a session and record the MCP client identity.

    Called from the MCP server's `initialize` handler. `client_info`
    is the params.clientInfo dict per the MCP spec; safe to pass
    None when the client didn't send one (older clients) — we'll
    record name="unknown" with detected_from="mcp_clientinfo" so the
    SIEM filter can still see "an MCP session existed here, we just
    don't know what client it was."

    Always replaces any prior active session. Reconnect / re-initialize
    is intentional new-session behaviour per the memo.
    """
    global _ACTIVE
    info = client_info or {}
    name = info.get("name") or "unknown"
    version = info.get("version")
    if version is not None and not isinstance(version, str):
        version = str(version)
    session = AgentSession(
        session_id=_new_session_id(),
        name=str(name),
        version=version,
        detected_from="mcp_clientinfo",
    )
    with _LOCK:
        _ACTIVE = session
    return session


def end_mcp_session() -> AgentSession | None:
    """Retire the active session; return the AgentSession that was
    active (so the caller can emit SESSION_ENDED). None if no session
    was active."""
    global _ACTIVE
    with _LOCK:
        prior = _ACTIVE
        _ACTIVE = None
    return prior


def active_agent_session() -> AgentSession | None:
    """Return the currently-bound MCP session, or None."""
    with _LOCK:
        return _ACTIVE


def reset_for_tests() -> None:
    """Drop the active session — test-only reset hook so tests don't
    leak state across each other."""
    global _ACTIVE
    with _LOCK:
        _ACTIVE = None


# ---------------------------------------------------------------------------
# Resolver — feed into the OCSF event builder
# ---------------------------------------------------------------------------


def resolve_agent_block(
    *,
    user_agent: str | None = None,
    peer_pid: int | None = None,
    include_process_tree: bool = True,
) -> dict[str, Any] | None:
    """Build the agent dict to land under `unmapped.iam_jit.agent`.

    Resolution order per [[agent-identity-in-audit]]:
      1. Active MCP session (mcp_clientinfo)
      2. User-Agent header (user_agent or user_agent_raw)
      3. Process-tree walk (process_tree) — only when
         include_process_tree is True; lets the webhook caller
         strip this branch per
         [[security-team-positioning-safety-not-surveillance]]

    Returns None when none of the three paths produced anything —
    the OCSF event builder omits the agent block in that case so a
    raw boto3 script with no MCP and no User-Agent doesn't fabricate
    fake identity.

    When MCP is the source, the session_id from that session lands
    on the dict. When User-Agent or process-tree wins, session_id
    is None — those calls have no persistent agent session.
    """
    # 1. MCP clientInfo — highest fidelity.
    mcp = active_agent_session()
    if mcp is not None:
        block: dict[str, Any] = {
            "name": mcp.name,
            "version": mcp.version,
            "session_id": mcp.session_id,
            "detected_from": "mcp_clientinfo",
        }
        # If we ALSO have a User-Agent that says something different,
        # surface that as a secondary tag — useful for catching the
        # MCP-session-spawns-subprocess case where the SDK call is
        # actually coming from somewhere else.
        ua = detect_from_user_agent(user_agent)
        if ua is not None and ua["name"] != mcp.name and ua["name"] != "unknown":
            block["user_agent_name"] = ua["name"]
        return block
    # 2. User-Agent — proxy-side primary path.
    ua_block = detect_from_user_agent(user_agent)
    if ua_block is not None:
        ua_block["session_id"] = None
        return ua_block
    # 3. Process-tree fallback (when enabled).
    if include_process_tree:
        pt_block = detect_from_process_tree(peer_pid)
        if pt_block is not None:
            pt_block["session_id"] = None
            return pt_block
    return None


# ---------------------------------------------------------------------------
# SESSION_ENDED synthetic event
# ---------------------------------------------------------------------------


def session_ended_event(session: AgentSession) -> dict[str, Any]:
    """OCSF-shaped synthetic event emitted when an MCP session retires.

    Sibling synthetic to `audit_dropped_event` — same class 6003
    shape so SIEMs that already filter on the OCSF schema pick it up
    without a separate ingestion path. Per [[security-team-
    positioning-safety-not-surveillance]] severity is Informational;
    a session ending is not a security event in itself, it's a
    bookend for forensic correlation.

    Per [[ocsf-audit-schema]] `unmapped.iam_jit.event_type =
    "SESSION_ENDED"` lets a single field test pick these out.
    """
    # Lazy import to avoid the import-cycle the event module already
    # documents (event.py imports from ...review lazily for the same
    # reason).
    from .event import (
        OCSF_SCHEMA_VERSION,
        _product_version,
        _now_unix_ms,
    )
    return {
        "metadata": {
            "version": OCSF_SCHEMA_VERSION,
            "product": {
                "name": "ibounce",
                "vendor_name": "iam-jit",
                "version": _product_version(),
            },
        },
        "time": _now_unix_ms(),
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "activity_id": 99,
        "activity_name": "session_ended",
        "type_uid": 600300 + 99,
        "type_name": "API Activity: Other",
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "status_detail": (
            f"MCP agent session {session.session_id} ended "
            f"(client={session.name} version={session.version or 'unknown'})"
        ),
        "actor": {"user": {"name": "", "uid": ""}},
        "api": {
            "operation": "session_ended",
            "service": {"name": "ibounce.audit_export"},
            "request": {"uid": session.session_id},
        },
        "resources": [],
        "src_endpoint": {},
        "dst_endpoint": {},
        "unmapped": {
            "iam_jit": {
                "event_type": "SESSION_ENDED",
                "agent": {
                    "name": session.name,
                    "version": session.version,
                    "session_id": session.session_id,
                    "detected_from": session.detected_from,
                },
                "ext": {},
            },
        },
    }


# Surface the platform once so test fixtures can branch on it
# without re-detecting per test (sys.platform is the source of truth
# anyway, but exposing here keeps imports tight in test code).
PLATFORM = sys.platform
