"""Ghost-run (agent-shadow) mode for ibounce — #728.

A read-only agent-shadow mode where the bouncer runs an agent against
REAL infrastructure but with zero blast radius:

  * READ operations are forwarded to AWS normally (the agent sees real
    state), and
  * WRITE / mutating operations are NEVER forwarded — instead they are
    CAPTURED as a structured "would-mutate" diff record and the agent
    gets a synthesized non-error response so it keeps going.

The operator then reviews "here's everything the agent would have
changed" (``ibounce shadow diff SID``) without any real mutation having
occurred — the safest possible dry-run of an agent against production.

This package is intentionally self-contained (sessions + flat-file
store) so wiring it into the proxy is a minimal, low-conflict change.

Composes with [[read-only-default]], [[plan-capture]] (reuses
``iam_jit.bouncer.plan_capture.synthesize_response`` for the synthetic
responses + ``classify_action`` for read/write), [[read-to-write-switch-ux]],
and [[creates-never-mutates]]. Per [[ibounce-honest-positioning]] the
synthetic responses are clearly fabricated; per [[v1-scope-bar]] the
mode is default-OFF (opt-in via ``--mode ghost``).
"""

from __future__ import annotations

from .sessions import (
    current_session_id,
    new_session_id,
    reset_session_for_tests,
    set_session_id,
)
from .store import (
    SCHEMA_VERSION,
    GhostAction,
    GhostRunError,
    GhostRunStore,
    diff,
    list_sessions,
    read_actions,
    runs_root,
    session_dir,
)

__all__ = [
    "SCHEMA_VERSION",
    "GhostAction",
    "GhostRunError",
    "GhostRunStore",
    "current_session_id",
    "diff",
    "list_sessions",
    "new_session_id",
    "read_actions",
    "reset_session_for_tests",
    "runs_root",
    "session_dir",
    "set_session_id",
]
