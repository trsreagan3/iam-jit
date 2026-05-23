"""#412 / §A56 — Weekly digest "your bouncer caught X" positive-signal counterweight.

Per ``[[ambient-value-prop-and-friction-framing]]`` this is the
positive-signal counterweight that prevents the "iam-jit is the thing
that occasionally blocks me" mental model. The digest leads with
caught-framing ("Your bouncer week in review") not deficit-framing
("BLOCKED: 3 requests").

Per ``[[creates-never-mutates]]`` the digest is READ-ONLY — never
modifies bouncer state, profiles, queues, or audit logs.

Per ``[[ibounce-honest-positioning]]`` denies tagged ``appears_adversarial``
are surfaced with classification + recommended action, NOT buried in
friendly framing.

Per ``[[cross-product-agent-parity]]`` the CLI surface
(``iam-jit digest``) and the MCP tool (``bounce_digest_recent``) share
the same backend (:func:`build_digest`) and the same JSON shape.

Data sources:

  * ``~/.iam-jit/autopilot.status.json`` (schema 1.1) for per-bouncer
    healthz.decisions_count + improve.last_results + denies_recent_count
  * :func:`iam_jit.profile_allow.denies.fetch_recent_denies` for the
    detailed classification breakdown
  * ``~/.iam-jit/bouncer/profile-allow-pending.jsonl`` for
    pending-approval count

The digest is LOCAL per ``[[no-hosted-saas]]`` — no central server
collects digest data.
"""

from .core import (
    DigestData,
    DigestError,
    build_digest,
    fetch_pending_approval_count,
    generate_recommendations,
    load_autopilot_status,
)
from .render import (
    render_html,
    render_json,
    render_markdown,
    render_terminal,
)

__all__ = [
    "DigestData",
    "DigestError",
    "build_digest",
    "fetch_pending_approval_count",
    "generate_recommendations",
    "load_autopilot_status",
    "render_html",
    "render_json",
    "render_markdown",
    "render_terminal",
]
