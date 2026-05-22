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

import json
import logging
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# #318 / §A16 — X-Agent-* header validators + rejection counter
# ---------------------------------------------------------------------------
#
# Bounce-suite-wide convention per [[cross-product-agent-parity]] +
# `docs/AGENT-ATTRIBUTION.md`:
#
#   X-Agent-Name        validation: [A-Za-z0-9._-]{1,64}
#   X-Agent-Session-Id  validation: [A-Za-z0-9_-]{1,128}
#
# Mirrors gbounce's `IsValidAgentName` / `IsValidSessionID` (Go regex)
# byte-for-byte so a SIEM query on `unmapped.iam_jit.agent.session_id=X`
# matches across all four products. An inbound header that fails
# validation is treated as ABSENT (the value is NEVER written into the
# audit event — shell-injection payloads can't pivot through the audit
# log) and the rejection is logged to stderr with a truncated raw value
# + the `total_agent_headers_rejected` counter is bumped so an operator
# debugging "why is my session id missing?" sees the rejection on
# /healthz. Per [[security-team-positioning-safety-not-surveillance]]:
# the rejection log + counter are SAFETY (operator visibility); the
# truncation + control-char stripping are privacy-shaped (a malicious
# header value can't reposition the operator's terminal cursor).

_AGENT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_AGENT_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def is_valid_agent_name(s: str | None) -> bool:
    """Return True iff `s` matches the canonical X-Agent-Name shape.

    Mirrors gbounce's `IsValidAgentName` Go regex so a SIEM filter on
    `unmapped.iam_jit.agent.name=X` is byte-for-byte consistent across
    the Bounce suite.
    """
    if not s:
        return False
    return bool(_AGENT_NAME_RE.match(s))


def is_valid_agent_session_id(s: str | None) -> bool:
    """Return True iff `s` matches the canonical X-Agent-Session-Id shape.

    Mirrors gbounce's `IsValidSessionID` Go regex; UUIDs (v4 + v7 + v6)
    all fit. Operators may use any UUID flavor — we don't enforce v7
    strictly because some agents still emit v4.
    """
    if not s:
        return False
    return bool(_AGENT_SESSION_ID_RE.match(s))


# Cross-process counter: bumped each time an inbound X-Agent-* header
# fails validation. Surfaced via /healthz so operators see agent-config
# drift (e.g. a misconfigured agent setting the header to a shell-
# injection payload) without grepping stderr. Atomic increment under the
# module lock since the proxy is async — only one event loop thread
# increments at a time in practice, but the lock guards against future
# multi-worker shapes.
_AGENT_HEADERS_REJECTED_COUNTER = 0
_AGENT_HEADERS_REJECTED_LOCK = threading.Lock()


def total_agent_headers_rejected() -> int:
    """Return the running total of invalid X-Agent-* headers rejected
    since process start. Read by the /healthz handler."""
    with _AGENT_HEADERS_REJECTED_LOCK:
        return _AGENT_HEADERS_REJECTED_COUNTER


def _log_agent_header_rejected(header_name: str, raw_value: str) -> None:
    """Emit one stderr line + bump the rejection counter. Bounded log
    shape: header name + truncated raw value (first 32 chars). Control
    characters are replaced with '?' so a malicious header value can't
    reposition the operator's terminal cursor. Mirror of gbounce's
    `logAgentHeaderRejected` Go function.
    """
    global _AGENT_HEADERS_REJECTED_COUNTER
    with _AGENT_HEADERS_REJECTED_LOCK:
        _AGENT_HEADERS_REJECTED_COUNTER += 1
    truncated = raw_value[:32]
    if len(raw_value) > 32:
        truncated = truncated + "..."
    clean_chars = []
    for ch in truncated:
        code = ord(ch)
        if 0x20 <= code <= 0x7E:
            clean_chars.append(ch)
        else:
            clean_chars.append("?")
    clean = "".join(clean_chars)
    print(
        f"ibounce: rejected invalid {header_name} header (value={clean!r}) — "
        f"request will be audited as anonymous",
        file=sys.stderr,
    )


def reset_agent_headers_rejected_for_tests() -> None:
    """Test-only reset for the rejection counter."""
    global _AGENT_HEADERS_REJECTED_COUNTER
    with _AGENT_HEADERS_REJECTED_LOCK:
        _AGENT_HEADERS_REJECTED_COUNTER = 0


def extract_agent_headers(
    headers: dict[str, str] | None,
) -> tuple[str | None, str | None]:
    """Return `(validated_name, validated_session_id)` from request
    headers. Performs case-insensitive lookup of `X-Agent-Name` +
    `X-Agent-Session-Id`, validates each, logs + counts rejections.
    Either or both may come back as None.

    Mirrors gbounce's pattern: an invalid header is treated as if the
    header were never sent (value is NEVER written into the audit
    event); a valid header passes through verbatim. Per
    [[creates-never-mutates]] this is additive — when neither header is
    present (or both are invalid) the caller's existing User-Agent /
    MCP / process-tree fallbacks fire unchanged.
    """
    validated_name, validated_session_id, _ = (
        extract_agent_headers_with_rejections(headers)
    )
    return validated_name, validated_session_id


# ---------------------------------------------------------------------------
# #320 / §A18 — structured agent-header rejection breadcrumb
# ---------------------------------------------------------------------------
#
# Cross-product invariant per [[cross-product-agent-parity]]: when an
# inbound X-Agent-* header fails validation, the audit event surfaces
# a structured breadcrumb at
# `unmapped.iam_jit.ext.agent_header_rejection` so a SOC analyst can
# tell which header failed + why + the rejected value's LENGTH (NEVER
# the value itself — that lives only in the truncated stderr line
# emitted above, with control-char filtering, so a malicious header
# value can't pollute the audit log). Same enum + field shape across
# ibounce / kbouncer / dbounce / gbounce.

# Bounded enum of rejection reasons. New reasons land here when the
# validation regex evolves.
AGENT_HEADER_REJECTION_INVALID_NAME_CHARSET = "invalid_name_charset"
AGENT_HEADER_REJECTION_INVALID_NAME_LENGTH = "invalid_name_length"
AGENT_HEADER_REJECTION_INVALID_SESSION_ID_FORMAT = "invalid_session_id_format"
AGENT_HEADER_REJECTION_INVALID_SESSION_ID_LENGTH = "invalid_session_id_length"
# Defined for cross-product enum parity; ibounce doesn't observe SQL
# `application_name` tags directly (that's dbounce's domain).
AGENT_HEADER_REJECTION_APPLICATION_NAME_UNPARSEABLE = "application_name_unparseable"

# Canonical field-name constants matching gbounce's
# `AgentNameField` / `AgentSessionIDField` Go constants byte-for-byte.
AGENT_NAME_FIELD = "X-Agent-Name"
AGENT_SESSION_ID_FIELD = "X-Agent-Session-Id"


def _classify_agent_name_rejection(raw: str) -> str:
    """Return the rejection reason for a raw X-Agent-Name value that
    already failed `is_valid_agent_name`. Splits charset vs length so
    SOC analysts can distinguish "agent SDK sending shell-injection-
    shaped payloads" from "agent picked an overly-verbose canonical
    name."
    """
    if len(raw) > 64:
        return AGENT_HEADER_REJECTION_INVALID_NAME_LENGTH
    return AGENT_HEADER_REJECTION_INVALID_NAME_CHARSET


def _classify_session_id_rejection(raw: str) -> str:
    """Return the rejection reason for a raw X-Agent-Session-Id value
    that already failed `is_valid_agent_session_id`."""
    if len(raw) > 128:
        return AGENT_HEADER_REJECTION_INVALID_SESSION_ID_LENGTH
    return AGENT_HEADER_REJECTION_INVALID_SESSION_ID_FORMAT


def build_agent_header_rejection_breadcrumb(
    field: str, reason: str, raw_value_length: int,
) -> dict[str, Any]:
    """Produce the per-rejection entry shape that lands at
    `unmapped.iam_jit.ext.agent_header_rejection`. NEVER include the
    raw value — only its length, for safe forensics per
    [[security-team-positioning-safety-not-surveillance]].
    """
    return {
        "field": field,
        "reason": reason,
        "value_redacted_length": raw_value_length,
    }


def extract_agent_headers_with_rejections(
    headers: dict[str, str] | None,
) -> tuple[str | None, str | None, list[dict[str, Any]]]:
    """Same as `extract_agent_headers` but also returns the list of
    structured rejection breadcrumbs (#320 / §A18). Empty list when
    every supplied header passed validation. Per
    [[cross-product-agent-parity]] the breadcrumb shape matches
    gbounce + kbouncer + dbounce byte-for-byte.
    """
    if not headers:
        return None, None, []
    raw_name = None
    raw_session_id = None
    for k, v in headers.items():
        if not isinstance(k, str):
            continue
        kl = k.lower()
        if kl == "x-agent-name" and raw_name is None:
            raw_name = v
        elif kl == "x-agent-session-id" and raw_session_id is None:
            raw_session_id = v
    validated_name = None
    validated_session_id = None
    rejections: list[dict[str, Any]] = []
    if raw_name:
        if is_valid_agent_name(raw_name):
            validated_name = raw_name
        else:
            _log_agent_header_rejected("X-Agent-Name", str(raw_name))
            rejections.append(build_agent_header_rejection_breadcrumb(
                AGENT_NAME_FIELD,
                _classify_agent_name_rejection(str(raw_name)),
                len(str(raw_name)),
            ))
    if raw_session_id:
        if is_valid_agent_session_id(raw_session_id):
            validated_session_id = raw_session_id
        else:
            _log_agent_header_rejected(
                "X-Agent-Session-Id", str(raw_session_id),
            )
            rejections.append(build_agent_header_rejection_breadcrumb(
                AGENT_SESSION_ID_FIELD,
                _classify_session_id_rejection(str(raw_session_id)),
                len(str(raw_session_id)),
            ))
    return validated_name, validated_session_id, rejections

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
    # #287 — persist to disk so the AWS-API proxy process (typically a
    # SEPARATE process) can pick up the same session_id + stamp it on
    # every decision's `unmapped.iam_jit.agent` block. Fail-soft inside
    # _persist_disk_session; never breaks the MCP handshake.
    _persist_disk_session(session)
    return session


def end_mcp_session() -> AgentSession | None:
    """Retire the active session; return the AgentSession that was
    active (so the caller can emit SESSION_ENDED). None if no session
    was active."""
    global _ACTIVE
    with _LOCK:
        prior = _ACTIVE
        _ACTIVE = None
    # Remove the cross-process state file too so the proxy stops
    # stamping this session_id on subsequent AWS-API calls. Stale-PID
    # cleanup in `_load_disk_session` is the fallback; this is the
    # happy-path cleanup.
    _clear_disk_session()
    return prior


def active_agent_session() -> AgentSession | None:
    """Return the currently-bound MCP session, or None."""
    with _LOCK:
        return _ACTIVE


def reset_for_tests() -> None:
    """Drop the active session — test-only reset hook so tests don't
    leak state across each other. Also removes any on-disk session file
    so a leaked file from a prior test doesn't bleed into the next."""
    global _ACTIVE
    with _LOCK:
        _ACTIVE = None
    _clear_disk_session()


# ---------------------------------------------------------------------------
# Cross-process MCP session pickup (#287 — AWS-API path)
# ---------------------------------------------------------------------------
#
# The MCP server and the AWS-API proxy commonly run in DIFFERENT processes
# (MCP is launched by the agent over stdio; the proxy is `ibounce serve`
# in a long-running terminal). The module-level `_ACTIVE` slot above is
# process-scoped — perfect for the MCP-internal path, useless for the
# proxy process which never calls `begin_mcp_session`.
#
# This block persists the active MCP session to a small on-disk file
# (atomic write) so the proxy process can pick the same session_id up
# and stamp it on every AWS-API decision's `unmapped.iam_jit.agent` block.
#
# Per [[scorer-is-ground-truth]] this is honest-effort: we record the
# writer's PID + skip the file when that PID is no longer alive (the
# MCP session ended ungracefully). Cross-machine deployments would
# need a different strategy; iam-jit's local-only deployment model
# (per [[local-only-safety-mode]]) means same-host always holds for
# the supported configurations.
#
# Per [[self-host-zero-billing-dependency]] this is purely local file IO
# — no phone-home, no shared service.


def _session_state_path() -> pathlib.Path:
    """Return the path to the cross-process MCP-session state file.

    Defaults to `~/.iam-jit/bouncer/active-mcp-session.json`; the
    `IAM_JIT_BOUNCER_AGENT_SESSION_FILE` env var overrides for tests +
    operators who keep state under a non-default home.
    """
    override = os.environ.get("IAM_JIT_BOUNCER_AGENT_SESSION_FILE")
    if override:
        return pathlib.Path(override)
    return (
        pathlib.Path.home() / ".iam-jit" / "bouncer" / "active-mcp-session.json"
    )


def _pid_is_alive(pid: int) -> bool:
    """True iff `pid` names a live process. Signal 0 is the kernel-
    cheap liveness probe (POSIX). Best-effort; on permission errors
    treat as alive (a sibling under a different uid can still be a
    real MCP process)."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _persist_disk_session(session: AgentSession) -> None:
    """Atomically write `session` to the on-disk state file. Fail-soft:
    a write failure NEVER breaks the MCP handshake; the AWS-API path
    just won't see the session until the next initialize."""
    path = _session_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "session_id": session.session_id,
            "name": session.name,
            "version": session.version,
            "detected_from": session.detected_from,
            "pid": os.getpid(),
        }
        # Atomic write via temp + rename so a concurrent reader never
        # sees a half-written JSON blob.
        fd, tmp_name = tempfile.mkstemp(
            prefix=".active-mcp-session.",
            suffix=".json",
            dir=str(path.parent),
        )
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(payload, fh)
            os.replace(tmp_name, str(path))
        except Exception:
            # Clean up the temp file on any error so we don't leak
            # `.active-mcp-session.*.json` debris in the state dir.
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
    except Exception as e:
        logger.debug(
            "agent_context: persist-disk-session failed (%s); "
            "AWS-API path will report session_id=None until next "
            "MCP initialize", e,
        )


def _clear_disk_session() -> None:
    """Remove the on-disk session file. Used by `end_mcp_session` +
    `reset_for_tests`. Fail-soft."""
    path = _session_state_path()
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.debug("agent_context: clear-disk-session failed: %s", e)


def _load_disk_session() -> AgentSession | None:
    """Read the on-disk session file. Returns None when:
      - file missing (no MCP session anywhere on this host)
      - file unreadable / malformed (fail-soft)
      - the writing PID is no longer alive (stale state — the MCP
        process exited without cleanup)
    """
    path = _session_state_path()
    try:
        with open(path) as fh:
            payload = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("agent_context: load-disk-session failed: %s", e)
        return None
    pid = payload.get("pid")
    if isinstance(pid, int) and not _pid_is_alive(pid):
        # Stale file — the MCP server crashed without calling
        # `end_mcp_session`. Don't stamp stale identity onto fresh
        # AWS-API decisions; clear + return None.
        _clear_disk_session()
        return None
    session_id = payload.get("session_id")
    name = payload.get("name")
    detected_from = payload.get("detected_from")
    if not session_id or not name or not detected_from:
        return None
    version = payload.get("version")
    if version is not None and not isinstance(version, str):
        version = str(version)
    return AgentSession(
        session_id=str(session_id),
        name=str(name),
        version=version,
        detected_from=str(detected_from),
    )


def active_or_disk_agent_session() -> AgentSession | None:
    """Resolve the active MCP session, preferring the in-process slot
    + falling back to the on-disk state file when no in-process session
    is bound (cross-process pickup for the AWS-API proxy path)."""
    in_proc = active_agent_session()
    if in_proc is not None:
        return in_proc
    return _load_disk_session()


# ---------------------------------------------------------------------------
# Resolver — feed into the OCSF event builder
# ---------------------------------------------------------------------------


def resolve_agent_block(
    *,
    user_agent: str | None = None,
    peer_pid: int | None = None,
    include_process_tree: bool = True,
    header_agent_name: str | None = None,
    header_agent_session_id: str | None = None,
) -> dict[str, Any] | None:
    """Build the agent dict to land under `unmapped.iam_jit.agent`.

    Resolution order per [[agent-identity-in-audit]] +
    [[cross-product-agent-parity]]:
      1. **HTTP headers** — `X-Agent-Name` + `X-Agent-Session-Id`
         (#318 / §A16). Highest precedence: when the agent explicitly
         declares itself via headers, that always wins over heuristic
         detection. Mirrors gbounce's `buildAgentBlock` pattern so
         cross-bouncer correlation by `agent.session_id` resolves
         across ibounce + kbounce + dbounce + gbounce. Caller must
         pre-validate the header values via
         `extract_agent_headers()` — this function trusts its inputs.
         Either-or-both headers populate the block; absence of
         either field falls back to the next detection source for
         the missing piece.
      2. Active MCP session (mcp_clientinfo)
      3. User-Agent header (user_agent or user_agent_raw)
      4. Process-tree walk (process_tree) — only when
         include_process_tree is True; lets the webhook caller
         strip this branch per
         [[security-team-positioning-safety-not-surveillance]]

    Returns None when none of the four paths produced anything —
    the OCSF event builder omits the agent block in that case so a
    raw boto3 script with no MCP and no User-Agent doesn't fabricate
    fake identity.

    When HTTP headers are the source, the `detected_from` field is:
      - `"http_header"` when BOTH name + session_id parsed cleanly
      - `"http_header_name_only"` when only name passed validation
        (session_id absent or invalid)
    Session-id-only (no name) does NOT short-circuit to header
    detection — without a name the row's investigation value is too
    thin to override richer downstream sources. The session_id still
    lands on whatever block the next source produces (preserving
    cross-bouncer correlation) and `detected_from` reflects that
    source.
    """
    # 1. HTTP headers — explicit declaration always wins. #318 / §A16.
    # Caller pre-validates via extract_agent_headers(); we just check
    # presence here.
    if header_agent_name:
        block: dict[str, Any] = {
            "name": header_agent_name,
            "version": None,
            "session_id": header_agent_session_id,
            "detected_from": (
                "http_header"
                if header_agent_session_id
                else "http_header_name_only"
            ),
        }
        return block
    # 2. MCP clientInfo — highest fidelity heuristic. Falls back to
    # the on-disk state file (#287) so the AWS-API proxy process picks
    # up the same session_id the in-process MCP server minted; without
    # this the AWS-API path always emitted `session_id=null` even
    # though an MCP session was live on the host.
    mcp = active_or_disk_agent_session()
    if mcp is not None:
        block_mcp: dict[str, Any] = {
            "name": mcp.name,
            "version": mcp.version,
            # Prefer the explicit X-Agent-Session-Id when an agent
            # supplied one — even though the name fell through to MCP,
            # the explicit session id still correlates across products.
            "session_id": header_agent_session_id or mcp.session_id,
            "detected_from": "mcp_clientinfo",
        }
        # If we ALSO have a User-Agent that says something different,
        # surface that as a secondary tag — useful for catching the
        # MCP-session-spawns-subprocess case where the SDK call is
        # actually coming from somewhere else.
        ua = detect_from_user_agent(user_agent)
        if ua is not None and ua["name"] != mcp.name and ua["name"] != "unknown":
            block_mcp["user_agent_name"] = ua["name"]
        return block_mcp
    # 3. User-Agent — proxy-side primary path.
    ua_block = detect_from_user_agent(user_agent)
    if ua_block is not None:
        # Explicit X-Agent-Session-Id (when present without a name)
        # overlays so cross-bouncer correlation works even when the
        # name fell through to UA detection.
        ua_block["session_id"] = header_agent_session_id
        return ua_block
    # 4. Process-tree fallback (when enabled).
    if include_process_tree:
        pt_block = detect_from_process_tree(peer_pid)
        if pt_block is not None:
            pt_block["session_id"] = header_agent_session_id
            return pt_block
    # Final fallback: when no detection source fired but the caller
    # supplied a session_id header, surface a minimal anonymous block
    # so the session_id still threads through for correlation. Without
    # this an agent that sent only X-Agent-Session-Id (no name, no UA,
    # no MCP, no PID) would land at None + the audit event would omit
    # the agent block entirely — losing the cross-bouncer pivot.
    if header_agent_session_id:
        return {
            "name": "anonymous",
            "version": None,
            "session_id": header_agent_session_id,
            "detected_from": "unknown",
        }
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
