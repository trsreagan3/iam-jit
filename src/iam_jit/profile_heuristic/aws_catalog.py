# Phase 3 prerequisite — real AWS IAM action catalog adapter.
"""Anchor pattern-generated action shapes to the real AWS IAM catalog.

Per UAT-A 2026-05-25 (#580 GAP-1) the verb-prefix sibling expander in
``ibounce_classes.sibling_action_prefixes`` was emitting patterns like
``s3:CheckObject*`` / ``s3:CountObject*`` / ``s3:HasObject*`` that do
NOT exist in AWS. Installed in a generated profile, those allows would
be silent no-ops in production — operator sees an allow rule that never
matches anything. That's the [[ibounce-honest-positioning]] failure
mode (silent allows = silent deny in practice).

This module adapts ``policy_sentry`` (already a hard dependency per
pyproject.toml) into a single boolean:

    ``is_real_aws_action("s3:GetObject*")  ->  True``
    ``is_real_aws_action("s3:CheckObject*") ->  False``

Pattern grammar:

* Glob via ``fnmatch`` (``*``, ``?``, character classes).
* ``service:VerbPattern`` shape required. Other shapes return False.
* Unknown service (not in catalog) returns False — caller decides
  whether to retain or drop.

Per [[scorer-is-ground-truth]] the real AWS catalog is the calibration
anchor; this module never widens its definition of "real" to make a
downstream feature look better. If policy_sentry's catalogue is stale
for a brand-new service, the fix is upgrading policy_sentry — not
relaxing the gate here.
"""

from __future__ import annotations

import fnmatch
import functools

from policy_sentry.querying.actions import get_actions_for_service


@functools.lru_cache(maxsize=None)
def _service_action_names(service: str) -> frozenset[str]:
    """Return the frozenset of bare action names for an AWS service.

    Cached per-service (``functools.lru_cache``) so the policy_sentry
    lookup runs at most once per service per process. Matches the
    caching pattern in :mod:`iam_jit.review` ``_service_action_levels``.

    Returns an empty frozenset for unknown services (so callers can
    treat "no actions" + "unknown service" uniformly).
    """
    if not service:
        return frozenset()
    try:
        full = get_actions_for_service(service) or []
    except Exception:
        # Defensive: policy_sentry can raise on truly malformed service
        # strings; surface as "no actions" rather than crashing the
        # sibling expander.
        return frozenset()
    names: set[str] = set()
    for entry in full:
        if ":" not in entry:
            continue
        _, name = entry.split(":", 1)
        if name:
            names.add(name)
    return frozenset(names)


def is_real_aws_action(action_pattern: str) -> bool:
    """Return True iff ``action_pattern`` matches at least one real action.

    ``action_pattern`` may be a literal (``s3:GetObject``) or a glob
    (``s3:Get*``, ``s3:GetObject*``, ``s3:?etObject``). Matching is done
    with ``fnmatch.fnmatchcase`` so case is preserved (AWS actions are
    TitleCase by convention; a lowercase pattern won't match a TitleCase
    action and vice versa).

    Returns False for:

    * Non-string input.
    * Missing colon (not AWS shape).
    * Empty service prefix or empty verb pattern.
    * Service unknown to policy_sentry (returns empty action set).
    * Glob with no real-action match in that service.

    The function is pure modulo the policy_sentry lookup (which is
    deterministic per the bundled catalogue).
    """
    if not isinstance(action_pattern, str):
        return False
    if ":" not in action_pattern:
        return False
    service, _, verb_pattern = action_pattern.partition(":")
    if not service or not verb_pattern:
        return False

    names = _service_action_names(service)
    if not names:
        return False
    # Fast path: literal action with no glob metacharacter.
    if not any(c in verb_pattern for c in "*?["):
        return verb_pattern in names
    return any(fnmatch.fnmatchcase(name, verb_pattern) for name in names)


__all__ = [
    "is_real_aws_action",
]
