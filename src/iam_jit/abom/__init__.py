# ADOPT-1 / #715 — CycloneDX 1.6 "Agent Bill of Materials" (ABOM).
"""Per-session Agent Bill of Materials.

An ABOM is a `CycloneDX 1.6 <https://cyclonedx.org/docs/1.6/json/>`_
JSON document that enumerates the *components* one agent session
touched — the IAM role(s) it assumed, the AWS services / resource
ARNs it called, the K8s namespaces it reached, the databases it
queried, the external HTTP endpoints it hit, and the MCP tools it
invoked. Compliance buyers want a single, standard-format artifact
that says "here is everything this agent did this session".

Plumbing reuse (NOT a reinvention)
-----------------------------------
The per-session events come from the SAME cross-bouncer fan-out the
agent-diff / role-usage features use:
:func:`iam_jit.agent_diff.fetch_session_events_via_fanout`, which
composes on :func:`iam_jit.cli_audit_query._query_one_bouncer`. This
module is a *pure* projection over the merged OCSF event list — it
performs no I/O of its own. The CLI (`iam-jit audit query --session
SID --format cyclonedx`) and the `iam_jit_audit_export_abom` MCP tool
both hand the already-fetched, already-merged event stream to
:func:`build_abom`.

Honesty (per [[ibounce-honest-positioning]])
--------------------------------------------
The ABOM reflects ONLY observed activity in the audit log. It is not
a proof of completeness. When the input is empty, when bouncers were
unreachable, or when the lookback window is short, that uncertainty
is surfaced explicitly in ``metadata.properties`` (the
``iam-jit:observed.*`` namespace) AND in a free-text
``metadata.properties[iam-jit:observed.disclaimer]`` line — never
hidden. A reader must be able to tell a *complete* picture from a
*partial* one.
"""

from __future__ import annotations

from .builder import (
    ABOM_PROPERTY_NS,
    CYCLONEDX_SPEC_VERSION,
    AbomResult,
    build_abom,
)

__all__ = [
    "ABOM_PROPERTY_NS",
    "CYCLONEDX_SPEC_VERSION",
    "AbomResult",
    "build_abom",
]
