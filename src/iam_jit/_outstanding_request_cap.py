"""Per-user outstanding-request cap.

Per FOUNDER DIRECTION 2026-05-25: cap each user at N outstanding
requests to prevent rogue/buggy agent loops from filling the approver
queue / DDoS'ing the system. Without this, a buggy agent in a tight
loop submits a fresh request per iteration; the approver UI fills with
hundreds of pending entries; legitimate operators are buried.

Default cap = 20. Configurable via:

  1. Environment: ``IAM_JIT_MAX_OUTSTANDING_PER_USER``
  2. Per-user override in users.yaml: ``outstanding_request_cap: N``

Resolution order (most-specific wins): user-override > env-override >
default.

States counted as "outstanding":

  - ``pending``       (awaiting approval / system gate)
  - ``provisioning``  (being processed; #610 watchdog caps at 15min)

States NOT counted (terminal-or-not-consuming-approver-queue):

  - ``active``                — successfully provisioned, role exists
  - ``rejected``              — approver said no
  - ``cancelled``             — owner withdrew
  - ``expired``               — role TTL ran out
  - ``revoked``               — admin pulled credentials early
  - ``provisioning_failed``   — provisioning errored; not in the queue
  - ``needs_changes``         — bounced back to owner; not in approver queue

Per `[[cross-product-agent-parity]]`: this is a leaf module shared by
both POST paths (API `routes/requests.py` and web
`routes/web.py:new_paste_submit`). The same pattern as
`_auto_approve_helpers.py` (#601): underscore-prefixed leaf; both
callers depend on it; it depends on neither caller; cannot circular-
import.

Per `[[ibounce-honest-positioning]]`: when the cap fires, the
response carries cap + current count + recovery hint + the list of
outstanding requests. The agent / human sees exactly which requests
are blocking + how to unblock. No silent rejection.

Per `[[ambient-value-prop-and-friction-framing]]`: the cap-fire
emits an OCSF-shaped audit event (``request_cap_exceeded``) so the
operator-facing audit log surfaces "your iam-jit caught a runaway
agent" as a positive signal — not just a 429 error.

#613 HIGH.
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from . import lifecycle as _lifecycle

logger = logging.getLogger("iam_jit.outstanding_request_cap")

DEFAULT_CAP = 20

# Tuple in addition to docstring for runtime guard. Kept in alphabetical
# order so a future re-read can quickly verify nothing was silently added.
OUTSTANDING_STATES: frozenset[str] = frozenset({"pending", "provisioning"})

ENV_VAR_NAME = "IAM_JIT_MAX_OUTSTANDING_PER_USER"


class OutstandingRequestCapExceeded(Exception):
    """Raised by callers that prefer exception-flow to dict-return.

    Exposed for completeness; both shipped call sites use the
    ``check_outstanding_cap`` -> ``CapCheckResult`` return-value
    style instead so the response body can be built once at the
    route layer.
    """

    def __init__(
        self,
        user_id: str,
        outstanding_count: int,
        cap: int,
        current_outstanding: list[dict[str, Any]],
    ) -> None:
        self.user_id = user_id
        self.outstanding_count = outstanding_count
        self.cap = cap
        self.current_outstanding = current_outstanding
        super().__init__(
            f"user {user_id!r} has {outstanding_count} outstanding requests "
            f"(cap = {cap}); refusing new submission"
        )


@dataclass(frozen=True)
class CapCheckResult:
    """Outcome of a per-user outstanding-cap check.

    `would_exceed` is True when accepting one more request would push
    the user OVER the cap — i.e. count >= cap. (Cap = 20 means "20
    outstanding allowed; a 21st is refused".) Callers should reject
    the submission with HTTP 429 when this is True.
    """

    user_id: str
    outstanding_count: int
    cap: int
    cap_source: str  # "default" | "env_override" | "user_override"
    would_exceed: bool
    current_outstanding: list[dict[str, Any]] = field(default_factory=list)

    def to_response_body(self) -> dict[str, Any]:
        """Structured body for the 429 response.

        Per `[[ibounce-honest-positioning]]`: response names the cap,
        the current count, the user, the cap source, a recovery hint,
        and the list of blocking requests. Agent / human can act
        without needing to query a second endpoint.
        """
        return {
            "detail": "user has reached outstanding-request limit",
            "user_id": self.user_id,
            "outstanding_count": self.outstanding_count,
            "cap": self.cap,
            "cap_source": self.cap_source,
            "recovery_hint": (
                "Wait for some requests to complete or cancel existing "
                "requests at /. Admin can raise your cap via users.yaml "
                "(outstanding_request_cap: N) or set "
                f"{ENV_VAR_NAME} for the deployment."
            ),
            "current_outstanding": list(self.current_outstanding),
        }


def _resolve_cap(user: Any, env_value: str | None) -> tuple[int, str]:
    """Resolve the effective cap for a user.

    Precedence: user_override > env_override > default. Invalid values
    at either layer fall through to the next layer with a logged
    warning — per `[[ibounce-honest-positioning]]`, a typo in an env
    var should not silently disable the cap.
    """
    # Per-user override (users.yaml). Accept None / missing attribute.
    user_override = getattr(user, "outstanding_request_cap", None)
    if user_override is not None:
        try:
            parsed = int(user_override)
            if parsed >= 0:
                return parsed, "user_override"
            logger.warning(
                "user.outstanding_request_cap=%r is negative; falling "
                "back to env / default",
                user_override,
            )
        except (TypeError, ValueError):
            logger.warning(
                "user.outstanding_request_cap=%r is not an integer; "
                "falling back to env / default",
                user_override,
            )

    if env_value is not None and env_value.strip():
        try:
            parsed = int(env_value.strip())
            if parsed >= 0:
                return parsed, "env_override"
            logger.warning(
                "%s=%r is negative; falling back to default %d",
                ENV_VAR_NAME, env_value, DEFAULT_CAP,
            )
        except (TypeError, ValueError):
            logger.warning(
                "%s=%r is not an integer; falling back to default %d",
                ENV_VAR_NAME, env_value, DEFAULT_CAP,
            )

    return DEFAULT_CAP, "default"


def _age_seconds(req: dict[str, Any], now: _dt.datetime) -> float | None:
    """Best-effort age-of-request derivation in seconds.

    Used only for the diagnostic field in the 429 response — no
    behavior depends on it. Returns None when no parseable timestamp
    is available rather than guessing.
    """
    status = req.get("status") or {}
    submitted_at = status.get("submitted_at")
    if not isinstance(submitted_at, str) or not submitted_at:
        return None
    try:
        s = submitted_at[:-1] + "+00:00" if submitted_at.endswith("Z") else submitted_at
        parsed = _dt.datetime.fromisoformat(s)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.UTC)
        return (now - parsed).total_seconds()
    except (ValueError, TypeError):
        return None


def count_outstanding_for_user(
    user_id: str, store: Any, *, now: _dt.datetime | None = None,
) -> list[dict[str, Any]]:
    """Return the user's outstanding-request diagnostic list.

    Each entry: ``{request_id, state, age_seconds}``. `age_seconds`
    may be None for malformed records — those still count toward the
    cap; the field is just for the response body.

    Errors fetching individual records are logged + skipped (do not
    fail the count for one bad file). An error from `list_ids()`
    itself returns an empty list AND logs — this is the conservative
    fail-open behavior: a broken store should not lock all users out
    of submitting (the schema validator / store layer will surface
    the real outage elsewhere). The fail-open is deliberate; the cap
    is a DoS guard, not a security boundary.
    """
    if now is None:
        now = _dt.datetime.now(_dt.UTC)
    try:
        ids = list(store.list_ids())
    except Exception:
        logger.exception(
            "count_outstanding_for_user: store.list_ids() raised for "
            "user_id=%r; returning empty (fail-open, will not block "
            "submission). The store outage will surface in the "
            "subsequent store.put() call.",
            user_id,
        )
        return []
    outstanding: list[dict[str, Any]] = []
    for rid in ids:
        try:
            req = store.get(rid)
        except Exception:
            logger.exception(
                "count_outstanding_for_user: store.get(%r) raised; "
                "skipping this record from the cap count.",
                rid,
            )
            continue
        owner = _lifecycle.get_owner(req)
        if owner != user_id:
            continue
        state = _lifecycle.get_state(req)
        if state not in OUTSTANDING_STATES:
            continue
        outstanding.append(
            {
                "request_id": rid,
                "state": state,
                "age_seconds": _age_seconds(req, now),
            }
        )
    return outstanding


def _count_by_state(outstanding: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in outstanding:
        s = entry.get("state") or "unknown"
        counts[s] = counts.get(s, 0) + 1
    return counts


def check_outstanding_cap(
    user: Any,
    store: Any,
    *,
    env_value: str | None = None,
    audit_emit: Any | None = None,
    now: _dt.datetime | None = None,
) -> CapCheckResult:
    """Check whether the user is at-or-over their outstanding-request cap.

    Returns a `CapCheckResult` carrying the count, the resolved cap,
    the cap source, and a `would_exceed` boolean. Callers reject the
    submission (429 / form-error) when `would_exceed` is True.

    When the cap fires AND `audit_emit` is None (the default), this
    function emits via `iam_jit.audit.emit()` so the
    `request_cap_exceeded` event lands in the standard hash-chained
    audit log. Tests pass a stub `audit_emit` callable to capture
    the event without touching the global audit chain.

    Per `[[ibounce-honest-positioning]]`: an audit emit failure must
    NEVER fail the cap check / block the response. The whole
    submission must still receive the 429 it deserves; the audit
    failure is logged loudly so an operator notices the gap.

    `env_value` is the resolved value of `IAM_JIT_MAX_OUTSTANDING_PER_USER`
    (caller passes `os.environ.get(...)`; tests pass an explicit string
    to avoid polluting the real env). Passing None means "use the live
    process environment".
    """
    if env_value is None:
        env_value = os.environ.get(ENV_VAR_NAME)

    cap, cap_source = _resolve_cap(user, env_value)
    outstanding = count_outstanding_for_user(user.id, store, now=now)
    would_exceed = len(outstanding) >= cap

    result = CapCheckResult(
        user_id=user.id,
        outstanding_count=len(outstanding),
        cap=cap,
        cap_source=cap_source,
        would_exceed=would_exceed,
        current_outstanding=outstanding,
    )

    if would_exceed:
        details = {
            "user_id": user.id,
            "outstanding_count": len(outstanding),
            "cap": cap,
            "cap_source": cap_source,
            "outstanding_by_state": _count_by_state(outstanding),
            "outstanding_request_ids": [
                e.get("request_id") for e in outstanding
            ],
        }
        summary = (
            f"refused submission: user {user.id!r} at outstanding-cap "
            f"({len(outstanding)} >= {cap}, source={cap_source})"
        )
        if audit_emit is not None:
            try:
                audit_emit(
                    actor=user.id,
                    kind="request_cap_exceeded",
                    summary=summary,
                    details=details,
                )
            except Exception:
                logger.exception(
                    "check_outstanding_cap: provided audit_emit raised "
                    "for user_id=%r; the cap still fires (the 429 "
                    "will be returned). Operator should investigate "
                    "the audit sink.",
                    user.id,
                )
        else:
            try:
                from . import audit as _audit_mod
                _audit_mod.emit(
                    actor=user.id,
                    kind="request_cap_exceeded",
                    summary=summary,
                    details=details,
                )
            except Exception:
                logger.exception(
                    "check_outstanding_cap: audit.emit raised for "
                    "user_id=%r; the cap still fires (the 429 will "
                    "be returned). Operator should investigate the "
                    "audit log configuration.",
                    user.id,
                )

    return result
