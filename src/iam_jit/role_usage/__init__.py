# #727 / BUILD-6 — session-scoped role-usage analysis.
"""Used N of M permissions — here's the narrowed role.

The data-driven close of iam-jit's recommend → grant → observe loop.
After (or during) an agent session, compare the permissions the
JIT-issued role GRANTED against the permissions the agent ACTUALLY
USED (from the bouncer's own OCSF audit log), surface "used N of M",
and propose a narrowed policy containing only what was used.

Per the competitive firewall PDF (differentiation 5/5) this is a shape
nobody else ships: Apono publishes usage stats but doesn't propose a
tighter policy. iam-jit pairs the usage data with its existing
recommender + agent-diff to close the loop.

Read-only per [[creates-never-mutates]]: this RECOMMENDS a narrowed
role; it never mutates the issued role. The narrowed policy is a FLOOR
based on observed usage, honestly framed per
[[ibounce-honest-positioning]] — never a completeness guarantee.

Public surface:

* :func:`compute_role_usage` — pure function; takes the granted policy
  doc + the session's OCSF events and returns a :class:`RoleUsage`.
* :func:`extract_granted_globs` / :func:`expand_granted` — granted-set
  derivation (policy_sentry action expansion with honest glob-count
  fallback).
* :func:`extract_used` — used-set aggregation (reuses
  :mod:`iam_jit.agent_diff.diff`'s event-walking).
* :func:`build_narrowed_policy` — narrowed inline policy builder.

The CLI surface is ``iam-jit role-usage`` (see
:mod:`iam_jit.cli_role_usage`); the MCP tool is
``iam_jit_role_usage`` (see :mod:`iam_jit.mcp_server`).
"""

from .usage import (
    NarrowedPolicy,
    RoleUsage,
    UsedAction,
    build_narrowed_policy,
    compute_role_usage,
    expand_granted,
    extract_granted_globs,
    extract_used,
)

__all__ = [
    "NarrowedPolicy",
    "RoleUsage",
    "UsedAction",
    "build_narrowed_policy",
    "compute_role_usage",
    "expand_granted",
    "extract_granted_globs",
    "extract_used",
]
