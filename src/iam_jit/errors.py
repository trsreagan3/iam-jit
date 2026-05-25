"""MRR-2 R1 — shared operator-facing error helpers.

Closes the cross-cutting Pattern A from
``docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md``:

    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)   # or
        raise HTTPException(status_code=500, detail=f"... {e}")

The bare ``f"... {e}"`` shape (a) leaks raw Python exception text into
the operator-visible surface (info-disclosure for the work-AWS
deploy), (b) gives agents no ``code`` field to pattern-match on, and
(c) gives operators no ``recommended_action`` to recover.

The F1+F2+F3 pre-deploy CRITs (commit ``f00d845``) introduced the
structured-payload shape ad-hoc inside ``app.py`` + ``mcp_server.py``.
This module lifts that shape into one helper so every catch-all
operator surface emits the SAME envelope:

    {
        "error_id":     "err_<26-char-ULID>",   # operator/support handle
        "error_code":   "REVOKE_INTERNAL_ERROR", # agent pattern-match key
        "message":      "...",                   # short WHAT
        "recommended_action": "...",             # explicit WHAT-TO-DO
        # optional structured context (route_path, request_id, etc.)
        ...
    }

The inner exception text is NEVER returned — it is only logged
server-side, correlated by ``error_id``. Per
``[[ibounce-honest-positioning]]``: the helper is honest about what
the operator can do (the hint must reflect a real recovery path —
this module never invents aspirational hints).

Public surface:

  * :func:`new_error_id`     — generate a fresh ``err_<ULID>``.
  * :func:`make_error_payload` — build the structured dict.
  * :func:`log_and_make`     — convenience: log the inner exception
    server-side (correlated by ``error_id``) + return the payload.

This is INTENTIONALLY a leaf module — no FastAPI / aiohttp / click
imports — so it can be used from HTTP, MCP, CLI, autopilot, and
synthesis call-sites alike.
"""

from __future__ import annotations

import logging
from typing import Any

from .dynamic_denies.store import new_rule_id as _new_dd_id

__all__ = [
    "log_and_make",
    "make_error_payload",
    "new_error_id",
]


def new_error_id() -> str:
    """Generate a fresh ``err_<26-char-Crockford-base32>`` id.

    Mirrors the shape introduced by F2/F3 (commit ``f00d845``) so all
    structured-error envelopes use the same handle format — operators
    can grep server-side logs for ``err_*`` regardless of which
    surface raised.
    """
    return "err_" + _new_dd_id().removeprefix("dd_")


def make_error_payload(
    *,
    error_code: str,
    message: str,
    recommended_action: str,
    error_id: str | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical structured-error payload.

    Args:
      error_code: short SCREAMING_SNAKE_CASE token agents can
        pattern-match on (e.g. ``"REVOKE_INTERNAL_ERROR"``,
        ``"UPSTREAM_FORWARD_FAILED"``). Per
        ``[[ibounce-honest-positioning]]`` keep stable across
        releases; callers add/rename via a deprecation window.
      message: short operator-language WHAT-failed (do NOT include
        raw exception text — that goes only to the server log).
      recommended_action: explicit WHAT-TO-DO-NEXT. MUST reference a
        real recovery path (retry / contact support with ``error_id``
        / check IAM creds / etc.). No aspirational hints.
      error_id: pre-generated id (call :func:`new_error_id` if you
        need to log it before building the payload, e.g. so the log
        line carries the same id the response surfaces). Generated
        fresh when ``None``.
      context: optional structured fields appended to the envelope
        (``route_path``, ``request_id``, ``method``, etc.). Never
        contains credentials or PII per
        ``[[mitm-beta-pii-pci-concern]]``.

    Returns:
      The structured-error dict. Caller wraps it in the surface's
      envelope (``JSONResponse``, JSON-RPC ``error.data``, CLI JSON
      output, etc.).
    """
    eid = error_id or new_error_id()
    payload: dict[str, Any] = {
        "error_id": eid,
        "error_code": error_code,
        "message": message,
        "recommended_action": recommended_action,
    }
    if context:
        for k, v in context.items():
            # Don't let context shadow the canonical fields.
            if k in payload:
                continue
            payload[k] = v
    return payload


def log_and_make(
    *,
    logger: logging.Logger,
    error_code: str,
    message: str,
    recommended_action: str,
    log_message: str,
    context: dict[str, Any] | None = None,
    exc_info: bool = True,
) -> dict[str, Any]:
    """Convenience: generate ``error_id``, log the inner exception
    server-side with the same id, and return the structured payload.

    Call this from inside an ``except Exception:`` block. The ``exc_info``
    flag (default True) means the logger captures the full traceback
    via ``LogRecord.exc_info`` — operators can correlate ``error_id``
    in the response with the traceback in their log aggregator.
    """
    eid = new_error_id()
    logger.error(
        "%s (error_id=%s)",
        log_message,
        eid,
        exc_info=exc_info,
    )
    return make_error_payload(
        error_id=eid,
        error_code=error_code,
        message=message,
        recommended_action=recommended_action,
        context=context,
    )
