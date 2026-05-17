"""Plan-capture session bookkeeping.

A "plan session" groups the synthetic-response call graph for a
single `ibounce serve --mode plan-capture` invocation (or for an
explicit `--plan-session-id` flag). Sessions live in-process AND
in the SQLite store; the in-process slot is the source of truth
for "what session is the proxy WRITING into right now" while the
store table is the durable source of truth for "what sessions
have ever existed."

ID shape: `plan-YYYYMMDDTHHMMSSZ-<6-char-suffix>` — sortable by
prefix, unique-enough for the local-only deployment shape. We
intentionally avoid UUID4 here so operators can read + type
session ids without copy-paste pain in the CLI.

Per [[local-only-safety-mode]] this all happens on the operator's
laptop — no central session registry, no cross-machine ids.

Per [[creates-never-mutates]]: sessions are bookkeeping rows in
ibounce's own SQLite. They do not touch IAM, STS, or any AWS
resource. The session ID is plumbing for the plan transcript,
nothing more.
"""

from __future__ import annotations

import datetime as _dt
import secrets
import threading


_session_lock = threading.Lock()
_current_session_id: str | None = None


def _make_session_id() -> str:
    """Build a fresh sortable-prefix session id.

    Format: `plan-YYYYMMDDTHHMMSSZ-<hex6>`. The hex suffix is from
    secrets.token_hex so an operator who starts two proxies in the
    same second (unlikely on a single laptop, but possible under
    test parallelism) gets distinct ids without coordination.
    """
    now = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"plan-{now}-{secrets.token_hex(3)}"


def new_session_id() -> str:
    """Allocate + install a fresh session id as the current session.

    Called by `ibounce serve --mode plan-capture` at startup so
    every subsequent intercepted call records into the same logical
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
    `ibounce serve --mode plan-capture --plan-session-id ...` to
    resume / append to a known transcript.
    """
    global _current_session_id
    if session_id is not None and not isinstance(session_id, str):
        raise TypeError(
            f"set_session_id: expected str | None, got {type(session_id).__name__}"
        )
    if session_id is not None:
        # Strip whitespace; reject empty strings since the CLI flag
        # would silently degrade to "no session" otherwise.
        session_id = session_id.strip()
        if not session_id:
            raise ValueError("set_session_id: session_id must be non-empty")
        if len(session_id) > 120:
            # Bound so a misuse can't bloat audit rows; ids the
            # library generates are ~30 chars.
            raise ValueError(
                f"set_session_id: session_id too long ({len(session_id)} chars; max 120)"
            )
    with _session_lock:
        _current_session_id = session_id


def current_session_id() -> str | None:
    """Return the session id the proxy is currently writing into,
    or None when plan-capture isn't running."""
    with _session_lock:
        return _current_session_id


def reset_session_for_tests() -> None:
    """Test helper: clear the in-process session slot. Not part of
    the public surface — tests import it directly via the
    `plan_capture` package."""
    global _current_session_id
    with _session_lock:
        _current_session_id = None
