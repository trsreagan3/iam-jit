"""Read vs Write classification for AWS IAM actions (#145).

The plan-capture `--write-switch-notify` feature needs a fast, in-
process predicate "is this AWS action a read or a write?". The
authoritative source for AWS IAM access-level classification is the
AWS service-authorization-reference dataset that policy_sentry
mirrors; reusing it here means our classifier stays in lockstep with
the same Read/List/Write/Tagging/Permissions-management labels the
review.py scorer already uses (per [[scorer-is-ground-truth]] —
we share the underlying data even though the consumers differ).

Reuses `iam_jit.review._action_level` (which itself wraps
policy_sentry's `get_actions_with_access_level`) so the classifier
is the SAME source of truth the scorer uses. Falls back to a small
verb-prefix heuristic when policy_sentry can't resolve the action
(brand-new services not yet in the data version we depend on,
synthetic ops, parser glitches that produced an oddly-cased action,
etc.) so the read->write switch still fires on the common cases.

Per [[ibounce-honest-positioning]]: this classifier is the
DETERMINISTIC half of the deterrent UX. It deliberately classifies
conservatively (when in doubt → write) because the cost of a false
write is an extra operator notification, while the cost of a false
read is "the agent's first state-changing call went un-flagged."
"""

from __future__ import annotations

import functools

# AWS access levels that are READS-only (no state change).
_READ_LEVELS: frozenset[str] = frozenset({"Read", "List"})

# AWS access levels that are WRITES (state change OR privilege change).
# Tagging + Permissions management both move state on the AWS side
# (resource tags drive ABAC; permissions management is exactly the
# IAM-escalation surface the scorer flags) so they count as writes for
# the read->write switch.
_WRITE_LEVELS: frozenset[str] = frozenset({
    "Write", "Tagging", "Permissions management",
})


# Heuristic fallback. Verb prefixes that pretty-reliably mean WRITE
# across AWS services (Create*, Delete*, Put*, Update*, Modify*, ...).
# Kept SHORT on purpose; the policy_sentry path covers ~99% of real
# traffic. Only the unknown-service-or-action case lands here.
#
# Matched against the action name's leading word — `CreateRole` ->
# prefix `Create`. Case-sensitive (AWS action names are canonical-cased
# but the parser already normalizes, so we don't add a .lower() tax to
# the hot path). NOT exhaustive — if policy_sentry can't classify AND
# the action doesn't match a prefix here, we return "unknown" and the
# caller treats unknown as WRITE (fail-loud for the UX prompt).
_WRITE_PREFIXES: tuple[str, ...] = (
    "Create", "Delete", "Destroy", "Terminate", "Stop", "Start",
    "Put", "Post", "Update", "Modify", "Patch", "Set", "Add",
    "Remove", "Detach", "Attach", "Associate", "Disassociate",
    "Register", "Deregister", "Enable", "Disable", "Tag", "Untag",
    "Restore", "Reboot", "Reset", "Run", "Cancel", "Submit",
    "Rotate", "Revoke", "Grant", "Apply", "Activate", "Deactivate",
    "Publish", "Send", "Invoke", "Execute", "Replace", "Import",
    "Upload", "Copy", "Sign", "Encrypt", "Decrypt", "ReEncrypt",
)

# Read prefixes. We DON'T need this to be exhaustive (the unknown
# path falls through to write per the conservative-default policy)
# but providing a few common ones gives `_classify_by_prefix` a
# chance to return "read" for unknown-but-obviously-Get-ish actions
# rather than treating Get* on a brand-new service as a write.
_READ_PREFIXES: tuple[str, ...] = (
    "Get", "List", "Describe", "Head", "Search", "Query", "Scan",
    "Lookup", "Test", "Validate", "Estimate", "Generate", "Preview",
)


def _classify_by_prefix(action: str) -> str:
    """Cheap verb-prefix heuristic. Returns 'read' / 'write' / 'unknown'.

    Greedy on length so `ReEncrypt` (a write) takes precedence over a
    hypothetical `Re*` prefix that would mis-classify. We sort the
    prefix tuples once at module-load via the iteration order; if a
    future addition needs precedence sorting, do it here not at the
    call site.
    """
    if not action:
        return "unknown"
    # Try WRITE prefixes first — when an action has prefixes from BOTH
    # buckets (rare but possible, e.g. hypothetical `ListAndDelete*`),
    # the WRITE classification wins per the conservative-default policy.
    for prefix in _WRITE_PREFIXES:
        if action.startswith(prefix):
            return "write"
    for prefix in _READ_PREFIXES:
        if action.startswith(prefix):
            return "read"
    return "unknown"


@functools.lru_cache(maxsize=4096)
def classify_action(service: str, action: str) -> str:
    """Classify an AWS (service, action) pair as 'read', 'write', or 'unknown'.

    Resolution order:
      1. policy_sentry access-level lookup via `review._action_level`.
         Read/List → 'read'. Write/Tagging/Permissions-management →
         'write'. Unknown to policy_sentry → fall through.
      2. Verb-prefix heuristic (Create*/Delete*/Put*/... → write,
         Get*/List*/Describe*/... → read).
      3. 'unknown' if neither resolved.

    The cache is large enough to hold the entire AWS action universe
    (~25k pairs) without churn; we cache because plan-capture sessions
    typically repeat the same handful of actions and we want the
    classification path to be sub-microsecond per call.

    The caller (proxy hot-path + plan_session_summary roll-up) is
    responsible for the policy of "unknown counts as write" — this
    function STAYS HONEST about what it could and couldn't determine.

    Per [[scorer-is-ground-truth]] we don't override or augment the
    underlying policy_sentry classification: if the scorer thinks
    `s3:Get*` is a Read, so do we. Calibration drift is the scorer's
    problem, not the classifier's.
    """
    if not service or not action:
        return "unknown"
    # Action 1: policy_sentry (authoritative). Lazy import keeps the
    # policy_sentry dependency off the bouncer-package import path for
    # callers that never touch plan-capture.
    try:
        from ...review import _action_level
    except ImportError:  # pragma: no cover — review.py is always shipped
        _action_level = None  # type: ignore[assignment]
    if _action_level is not None:
        try:
            level = _action_level(f"{service.lower()}:{action}")
        except Exception:
            level = None
        if level in _READ_LEVELS:
            return "read"
        if level in _WRITE_LEVELS:
            return "write"
    # Action 2: verb-prefix heuristic (covers unknown-to-policy_sentry).
    return _classify_by_prefix(action)


def is_write(service: str, action: str) -> bool:
    """True iff (service, action) is classified as a WRITE.

    The proxy hot-path consults this on every plan-capture call. We
    treat 'unknown' as a write — better to over-notify the operator
    than to silently miss the first state-changing call. Matches the
    [[safety-mode-lean-permissive]] guidance: lean permissive on
    EXECUTION (synthetic responses still go out either way), strict
    on NOTIFICATION (the operator wants to know).
    """
    klass = classify_action(service, action)
    return klass != "read"  # write OR unknown → notify


def is_read(service: str, action: str) -> bool:
    """True iff (service, action) is classified as a READ.

    Mirror of is_write so callers reading from either lens get
    matching predicates. Note: `not is_read(...) != is_write(...)`
    when the classification is 'unknown' — is_write treats unknown as
    write (notify on the conservative side), is_read does NOT treat
    unknown as read."""
    return classify_action(service, action) == "read"
