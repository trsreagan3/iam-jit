# #419 / §A58 — `iam-jit audit query --extract-permissions` backend.
"""Backend for ``iam-jit audit query --extract-permissions`` CLI flag +
``bounce_extract_permissions_from_audit`` MCP tool.

Phase E of [[bouncer-informs-agent-informs-iam-jit]]. Bouncers observe
agent traffic and emit OCSF audit events; this module projects a
window of those events into a STRUCTURED PERMISSION SET ready for an
agent to feed to ``iam_jit_request_role_from_synthesis``.

The output shape is deliberately small + agent-shaped — not an OCSF
re-export. The agent already has the OCSF stream via
``iam-jit audit query``; this surface exists to skip the
event-by-event aggregation work and hand back the
``[{action, resources, count}, ...]`` shape directly.

Per [[recommender-context-boundary]] iam-jit consumes context from
exactly the two channels it always has (AWS state + customer prompt);
this module's input is the audit channel that the bouncer already
exports back to iam-jit's own CLI / MCP — no new context channel.

Per [[scorer-is-ground-truth]] this module does NOT score or
auto-generate any role requests; it returns the raw permission set the
agent later assembles into a request.
"""

from __future__ import annotations

from .extractor import (
    ExtractedPermissions,
    PermissionAggregate,
    extract_permissions_from_events,
    extract_permissions_via_fanout,
)

__all__ = [
    "ExtractedPermissions",
    "PermissionAggregate",
    "extract_permissions_from_events",
    "extract_permissions_via_fanout",
]
