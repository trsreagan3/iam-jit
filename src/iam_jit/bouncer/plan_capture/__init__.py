"""Plan-capture mode for ibounce — the 4th proxy mode (alongside
cooperative / transparent / off).

In plan-capture mode every inbound SDK call is:
  1. PARSED + AUDITED (same machinery the other modes use)
  2. RETURNED with a synthetic SDK-shaped success payload
  3. NEVER forwarded to AWS

The operator gets a recorded "call graph" of everything the agent
INTENDED to do — `terraform plan` for any AWS-touching agent task —
before any state change actually happens. Composes with
[[read-to-write-switch-ux]] (#145) for the agent-to-operator
transition prompt that lands as a separate slice.

Per [[ibounce-honest-positioning]]: plan-capture is a HELPFUL
OPERATOR PREVIEW (deterrent), NOT a security boundary. An
adversarial agent can detect plan-capture mode via response
shapes / latency profiles and behave differently. Operators
should treat the transcript the same way they'd treat a
`terraform plan` output: informative, not authoritative.

Per [[creates-never-mutates]]: plan-capture EXPLICITLY does not
mutate anything. Synthetic responses are FAKE responses, not
actual AWS calls.

Per [[scorer-is-ground-truth]]: deny verdicts that WOULD have
fired in transparent mode are still recorded as denies in the
plan transcript — the operator sees what the bouncer would have
blocked alongside what the agent would have done.

Public surface (consumed by proxy.py + bouncer_cli.py + mcp_server.py):

    from iam_jit.bouncer.plan_capture import (
        synthesize_response,
        PlanCaptureSynthetic,
        current_session_id,
        new_session_id,
        UNSUPPORTED_OP_SHAPE,
    )
"""

from __future__ import annotations

from .classifier import classify_action, is_read, is_write
from .sessions import (
    current_session_id,
    new_session_id,
    reset_session_for_tests,
    set_session_id,
)
from .synthetics import (
    PlanCaptureSynthetic,
    UNSUPPORTED_OP_SHAPE,
    SUPPORTED_OPERATIONS,
    WRITES_REJECTED_SHAPE,
    build_writes_rejected_response,
    is_supported,
    synthesize_response,
)

__all__ = [
    "PlanCaptureSynthetic",
    "SUPPORTED_OPERATIONS",
    "UNSUPPORTED_OP_SHAPE",
    "WRITES_REJECTED_SHAPE",
    "build_writes_rejected_response",
    "classify_action",
    "current_session_id",
    "is_read",
    "is_supported",
    "is_write",
    "new_session_id",
    "reset_session_for_tests",
    "set_session_id",
    "synthesize_response",
]
