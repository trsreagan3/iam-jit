"""Ghost-run (agent-shadow) session bookkeeping.

A "ghost run" (a.k.a. shadow run) groups the captured would-mutate
records for a single ``ibounce serve --mode ghost`` invocation, or
for an explicit ``--ghost-session-id`` flag.

Ghost mode is the safest possible dry-run of an agent against REAL
infrastructure: READ operations are forwarded to AWS normally so the
agent sees real state, but WRITE / mutating operations are NEVER
forwarded — they are captured as a structured "would-mutate" record
and the agent gets a synthesized non-error response so it keeps
going.

This module owns the in-process "which session is the proxy writing
into right now" slot. It deliberately mirrors
:mod:`iam_jit.bouncer.plan_capture.sessions` so operators carry one
mental model across both modes, but ghost sessions use a distinct
``shadow-`` id prefix so the two transcript namespaces never collide.

ID shape: ``shadow-YYYYMMDDTHHMMSSZ-<hex6>`` — sortable by prefix,
human-typeable (no UUIDs), unique-enough for the local-only
deployment shape per [[local-only-safety-mode]].

Per [[creates-never-mutates]]: a ghost session is bookkeeping. It
does NOT touch IAM, STS, or any AWS resource. The whole point of the
mode is that writes never reach AWS.
"""

from __future__ import annotations

import datetime as _dt
import secrets
import threading


_session_lock = threading.Lock()
_current_session_id: str | None = None

# Bound on operator-supplied ids so a misuse can't bloat record files
# or path components. Ids the library generates are ~30 chars.
_MAX_SESSION_ID_LEN = 120


def _make_session_id() -> str:
    """Build a fresh sortable-prefix ghost-run session id.

    Format: ``shadow-YYYYMMDDTHHMMSSZ-<hex6>``. The hex suffix is from
    ``secrets.token_hex`` so an operator who starts two shadow proxies
    in the same second gets distinct ids without coordination.
    """
    now = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"shadow-{now}-{secrets.token_hex(3)}"


def new_session_id() -> str:
    """Allocate + install a fresh session id as the current session.

    Called by ``ibounce serve --mode ghost`` at startup so every
    subsequent intercepted write records into the same logical
    transcript. Returns the new id so the CLI can echo it.
    """
    global _current_session_id
    sid = _make_session_id()
    with _session_lock:
        _current_session_id = sid
    return sid


def set_session_id(session_id: str | None) -> None:
    """Pin the current session to an operator-supplied id.

    Pass None to clear (mostly useful for tests). Used by
    ``ibounce serve --mode ghost --ghost-session-id ...`` to resume /
    append to a known transcript.
    """
    global _current_session_id
    if session_id is not None and not isinstance(session_id, str):
        raise TypeError(
            f"set_session_id: expected str | None, got "
            f"{type(session_id).__name__}"
        )
    if session_id is not None:
        session_id = session_id.strip()
        if not session_id:
            raise ValueError("set_session_id: session_id must be non-empty")
        if len(session_id) > _MAX_SESSION_ID_LEN:
            raise ValueError(
                f"set_session_id: session_id too long "
                f"({len(session_id)} chars; max {_MAX_SESSION_ID_LEN})"
            )
        if not _is_path_safe(session_id):
            # The session id becomes a directory name under
            # ~/.iam-jit/ghost-runs/. Reject path-traversal / separator
            # characters so a hostile id can't escape the runs dir.
            raise ValueError(
                "set_session_id: session_id may only contain "
                "[A-Za-z0-9._-] (it is used as a filesystem path)"
            )
    with _session_lock:
        _current_session_id = session_id


def current_session_id() -> str | None:
    """Return the session id the proxy is currently writing into, or
    None when ghost mode isn't running."""
    with _session_lock:
        return _current_session_id


def _is_path_safe(session_id: str) -> bool:
    """True iff ``session_id`` is safe to use as a single path
    component (no separators, no traversal, conservative charset)."""
    if session_id in (".", ".."):
        return False
    return all(c.isalnum() or c in "._-" for c in session_id)


def reset_session_for_tests() -> None:
    """Test helper: clear the in-process session slot."""
    global _current_session_id
    with _session_lock:
        _current_session_id = None
