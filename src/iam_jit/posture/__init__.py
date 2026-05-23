"""#383 / §A42 — `iam-jit posture` cross-product introspection.

Built per the founder-direction memo
([[posture-check-feature]]): users + agents must be able to easily
answer "what mode am I in — iam-jit + scoped IAM role / bouncer
intercepting / both / neither?".

Surfaces (shipped in lockstep across the four bouncers per
[[cross-product-agent-parity]]):

* `iam-jit posture` — Click subcommand registered onto the top-level
  CLI; human + `--json` for agents.
* `iam_jit_posture` MCP tool — same schema as `--json` output.
* `bounce posture` per bouncer (ibounce / kbounce / dbounce / gbounce).
* `bounce_posture` MCP tool per bouncer.

The detection logic is HEURISTIC + HONEST per
[[ibounce-honest-positioning]]:

* If env var points at a loopback port but no bouncer is listening
  there: report ``"MISCONFIGURED — env points at down bouncer"``,
  NOT silently ``"intercepted"``.
* If a role's path / session marker doesn't match iam-jit's
  fingerprint: report ``"unknown"`` (uncertain) — never ``False``
  unless we have positive evidence the role was NOT iam-jit-issued.
* Discovery mode is reported as ``enforces_denials=False`` with a
  warning so agents don't assume bouncer = enforcement.

Sub-modules:
  * ``identity``    — local AWS identity heuristics (role ARN, source).
  * ``bouncers``    — bouncer process discovery + env-var wiring.
  * ``traffic``     — per-traffic-class roll-up of effective protection.
  * ``report``      — final structured posture dict + human renderer.
  * ``sanitize``    — credential-leak guard for the JSON output.
"""

from __future__ import annotations

from .report import (
    POSTURE_SCHEMA_VERSION,
    capture_posture,
    render_posture_human,
)

__all__ = [
    "POSTURE_SCHEMA_VERSION",
    "capture_posture",
    "render_posture_human",
]
