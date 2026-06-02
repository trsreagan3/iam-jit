# ADOPT-2 / #716 — compliance mapping overlay.
"""Map iam-jit's observed bouncer/IAM decisions to compliance-framework
controls.

The differentiator vs HTTP-only competitors (Pipelock): iam-jit's
audit stream spans AWS IAM + Kubernetes + SQL + HTTP, so this overlay
answers "which OWASP-Agentic-Top-10 risks / MITRE ATT&CK techniques /
NIST 800-53 controls / SOC 2 criteria / EU AI Act articles does my
bouncer's activity touch?" across ALL four surfaces, not just HTTP.

Two products per session:

* an **overlay** — each decision event tagged with the
  ``compliance_tags`` it touches, and
* a **coverage report** — per-framework rollup of which controls the
  session exercised + an honest partial-coverage note.

Frameworks + cited versions: OWASP Agentic AI Top 10 (2026),
MITRE ATT&CK (Enterprise), NIST SP 800-53 Rev. 5, SOC 2 TSC
(2017 rev. 2022), EU AI Act (Regulation (EU) 2024/1689).

Plumbing reuse (NOT a reinvention): per-session events come from the
SAME cross-bouncer fan-out the agent-diff / role-usage / ABOM features
use (:func:`iam_jit.agent_diff.fetch_session_events_via_fanout`); the
mapping itself is a PURE projection over the merged OCSF stream.

Honesty per [[ibounce-honest-positioning]]: this is NOT a
certification; it maps observed activity to the controls it touches,
states per-framework coverage gaps explicitly, and flags
empty/partial sessions.

Public surface:

* :func:`build_overlay` — pure function; events in, overlay+report out.
* :func:`format_summary` — operator-readable rendering.
* :func:`tags_for_event` — single-event tag projection.
* :mod:`.mapping` — the curated control catalog + signal rules.

CLI: ``iam-jit compliance-map`` (see
:mod:`iam_jit.cli_compliance_map`); MCP tool:
``iam_jit_compliance_map`` (see :mod:`iam_jit.mcp_server`).
"""

from . import mapping
from .overlay import (
    ComplianceOverlay,
    ControlCoverage,
    FrameworkCoverage,
    TaggedEvent,
    build_overlay,
    format_summary,
    tags_for_event,
)

__all__ = [
    "ComplianceOverlay",
    "ControlCoverage",
    "FrameworkCoverage",
    "TaggedEvent",
    "build_overlay",
    "format_summary",
    "mapping",
    "tags_for_event",
]
