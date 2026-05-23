"""#402 / §A48 — Structured agent-facing deny response + ``iam_jit_handle_deny`` MCP.

When an agent's bouncer request is denied, the deny surfaces here are
framed as ``caught_by_bouncer`` per [[ambient-value-prop-and-friction-framing]]
(never "ERROR" / "BLOCKED" / "DENIED" lead text). The agent receives:

  * ``caught_by_bouncer``: which bouncer caught it (ibounce / kbouncer / ...).
  * ``deny_reason``: short operator-language reason ("profile_allow_rules",
    "dynamic_deny", "safe_default", etc).
  * ``deny_source``: classification (static_profile / dynamic_deny /
    safe_default / etc) from the existing #345 classifier.
  * ``is_likely_injection_classification``: ``appears_legitimate`` /
    ``ambiguous`` / ``appears_adversarial``. Today this is a structural
    heuristic ("ambiguous" placeholder) until #404 LLM classifier lands.
  * ``suggested_allow_command``: a one-line ``iam-jit profile allow ...``
    command an operator could paste to unblock a legit deny.
  * ``recommended_action``: one of ``easy-allow`` / ``halt+escalate`` /
    ``rephrase+retry``.
  * ``deny_event_id``: stable id the agent can pass to
    ``iam_jit_handle_deny`` for full context.

This module ships TWO surfaces:

  * :func:`build_structured_deny`  — pure function that takes a deny row
    (already a :class:`DenyRow` from :mod:`iam_jit.profile_allow.denies`,
    or a raw OCSF event) and returns the canonical structured-deny dict.
  * :func:`handle_deny_for_mcp`   — MCP backend for ``iam_jit_handle_deny``;
    fetches the deny event by id (from each bouncer's audit log) +
    returns the structured shape PLUS the recent audit-trail context
    the agent needs to decide.

Per [[creates-never-mutates]] this module is read-only — no profile
mutations, no fan-out. The deny PRESENTATION never escalates a
recommendation to an automated allow; ``recommended_action`` is advice
the agent surfaces to the operator (or quietly applies via
:func:`iam_jit.profile_allow.operations.add_profile_allow_rule` IF the
operator has opted in via ``IAM_JIT_BOUNCER_ALLOW_AGENT_SELF_GRANT``).
"""

from .response import (
    RECOMMENDED_ACTION_EASY_ALLOW,
    RECOMMENDED_ACTION_HALT_ESCALATE,
    RECOMMENDED_ACTION_REPHRASE_RETRY,
    StructuredDenyResponse,
    build_structured_deny,
    classify_injection_likelihood,
    derive_recommended_action,
    handle_deny_for_mcp,
)

__all__ = [
    "RECOMMENDED_ACTION_EASY_ALLOW",
    "RECOMMENDED_ACTION_HALT_ESCALATE",
    "RECOMMENDED_ACTION_REPHRASE_RETRY",
    "StructuredDenyResponse",
    "build_structured_deny",
    "classify_injection_likelihood",
    "derive_recommended_action",
    "handle_deny_for_mcp",
]
