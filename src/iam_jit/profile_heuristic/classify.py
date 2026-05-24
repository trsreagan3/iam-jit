# Phase 1 — pure-function action classifier.
"""Lean-permissive action classifier.

Pure data-table lookup; no LLM, no I/O. The classifier is the
single source of truth that the deterministic Phase 3 fallback in
:mod:`iam_jit.llm.profile_generator` will consume to shape scope
per-class (read = broad, write/admin/destructive = tight).

Match order (per :mod:`.ibounce_classes` docstring):

1. KNOWN_ADVERSARIAL_PATTERNS exact match → ``ADMIN``
   (defense-in-depth: a destructive shape inside the adversarial
   catalogue is still classified ADMIN so the heuristic's "very tight +
   count >= 3 required" disposition fires, NOT the destructive "no
   widening even if observed 100×" disposition. The safety floor in
   §2.3 catches both shapes regardless.)
2. DESTRUCTIVE_PATTERNS prefix match → ``DESTRUCTIVE_DATA``
3. ADMIN_PATTERNS prefix match → ``ADMIN``
4. WRITE_DATA_PATTERNS prefix match → ``WRITE_DATA``
5. READ_PATTERNS prefix match → ``READ``
6. Default → ``UNKNOWN``
"""

from __future__ import annotations

from enum import Enum

from ..deny_classifier.prompts import KNOWN_ADVERSARIAL_PATTERNS
from . import dbounce_classes as _db
from . import gbounce_classes as _gb
from . import ibounce_classes as _ib
from . import kbouncer_classes as _kb


class ActionClass(Enum):
    """Blast-radius class for an observed action.

    Per `docs/PROFILE-GENERATION-DESIGN.md` §2.1 each class has a
    distinct disposition the Phase 3 generator will apply:

    * READ — allow broadly (service-level wildcard) when count >= 5
      AND 2+ resources observed.
    * WRITE_DATA — tight: exact action + exact resource ARN.
    * ADMIN — very tight: exact action + exact resource + count >= 3
      for auto-include; else ``flagged_for_review``.
    * DESTRUCTIVE_DATA — tight even if observed 100×; exact action +
      exact resource; no widening.
    * UNKNOWN — default-deny in Phase 3 lean-permissive mode (no
      speculative include).
    """

    READ = "read"
    WRITE_DATA = "write-data"
    ADMIN = "admin"
    DESTRUCTIVE_DATA = "destructive-data"
    UNKNOWN = "unknown"


# Bouncer name normalisation. Accept the long "kbouncer" name (Phase E
# preferred per [[bounce-suite-rename]]) and the short "kbounce" form;
# same for all four products.
_BOUNCER_ALIASES: dict[str, str] = {
    "ibounce": "ibounce",
    "ibouncer": "ibounce",
    "kbounce": "kbouncer",
    "kbouncer": "kbouncer",
    "dbounce": "dbounce",
    "dbouncer": "dbounce",
    "gbounce": "gbounce",
    "gbouncer": "gbounce",
}


# Pre-compute the KNOWN_ADVERSARIAL_PATTERNS index for O(1) exact match.
# Strip leading/trailing whitespace; case-sensitive (AWS action names
# are case-sensitive, SQL statements are normalised upper at call sites).
_KNOWN_ADVERSARIAL_INDEX: frozenset[str] = frozenset(
    p.strip() for p in KNOWN_ADVERSARIAL_PATTERNS
)


def _is_known_adversarial(bouncer: str, action: str, resource: str | None) -> bool:
    """Return True if ``action`` (or ``action`` + ``resource``) matches
    a KNOWN_ADVERSARIAL_PATTERNS entry.

    The catalogue mixes AWS action-only matches (``s3:DeleteBucket``)
    with K8s + SQL phrase-level matches (``kubectl delete namespace``,
    ``DROP TABLE``). For ibounce we exact-match the AWS action; for
    kbouncer + dbounce we substring-match against the catalogue
    (a K8s ``delete`` verb on a ``namespace`` resource matches the
    ``kubectl delete namespace`` catalogue entry).
    """
    if not action:
        return False
    a = action.strip()
    if a in _KNOWN_ADVERSARIAL_INDEX:
        return True
    if bouncer == "kbouncer":
        # Reconstruct a ``kubectl <verb> <resource>`` phrase and check
        # whether any catalogue entry is a substring of it.
        verb = a.split(":", 1)[-1].split()[0].lower() if a else ""
        res = (resource or "").lower()
        phrase = f"kubectl {verb} {res}".strip()
        for entry in _KNOWN_ADVERSARIAL_INDEX:
            if entry.lower().startswith("kubectl") and entry.lower() in phrase:
                return True
    if bouncer == "dbounce":
        # SQL statements: catalogue entries are phrases like
        # ``DROP TABLE`` or ``DELETE FROM users``. Match against the
        # uppercased statement form. Reuse strip_dialect_prefix so
        # ``psql:Drop Table`` normalises.
        stmt_type = _db.strip_dialect_prefix(a)
        # Also fold the resource into the search string so phrase
        # matches against e.g. ``DELETE FROM users`` work.
        composed = f"{stmt_type} {(resource or '').upper()}".strip()
        for entry in _KNOWN_ADVERSARIAL_INDEX:
            if entry.upper() in composed:
                return True
    return False


def _split_aws_action(action: str) -> tuple[str, str] | None:
    """Parse ``service:Action`` → ``(service, action)``. Returns None
    if the input isn't AWS-shape."""
    if ":" not in action:
        return None
    service, _, name = action.partition(":")
    if not service or not name:
        return None
    return service.lower(), name


def _matches_aws_table(
    service: str, name: str, table: tuple[tuple[str, str], ...],
) -> bool:
    for tbl_service, tbl_verb in table:
        if tbl_service != "*" and tbl_service != service:
            continue
        if name.startswith(tbl_verb):
            return True
    return False


def _classify_ibounce(action: str, resource: str | None) -> ActionClass:
    parsed = _split_aws_action(action)
    if parsed is None:
        return ActionClass.UNKNOWN
    service, name = parsed
    if _matches_aws_table(service, name, _ib.DESTRUCTIVE_PATTERNS):
        return ActionClass.DESTRUCTIVE_DATA
    if _matches_aws_table(service, name, _ib.ADMIN_PATTERNS):
        return ActionClass.ADMIN
    if _matches_aws_table(service, name, _ib.WRITE_DATA_PATTERNS):
        return ActionClass.WRITE_DATA
    if _matches_aws_table(service, name, _ib.READ_PATTERNS):
        return ActionClass.READ
    return ActionClass.UNKNOWN


def _classify_kbouncer(action: str, resource: str | None) -> ActionClass:
    if not action:
        return ActionClass.UNKNOWN
    # K8s verb is the bare ``action`` string (possibly with a
    # ``kbouncer:`` prefix); normalise.
    verb = action.split(":", 1)[-1].strip().lower()
    if not verb:
        return ActionClass.UNKNOWN
    res = (resource or "").lower()

    # 1. Delete + destructive resource hint → DESTRUCTIVE_DATA
    if verb in _kb.DELETE_VERBS:
        for hint in _kb.DESTRUCTIVE_RESOURCE_HINTS:
            if hint in res:
                return ActionClass.DESTRUCTIVE_DATA
        # Delete without a destructive-resource hint stays WRITE_DATA
        # rather than dropping to UNKNOWN — we know it mutates state.
        return ActionClass.WRITE_DATA

    # 2. Admin verbs or admin resource hints → ADMIN
    if verb in _kb.ADMIN_VERBS:
        return ActionClass.ADMIN
    for hint in _kb.ADMIN_RESOURCE_HINTS:
        if hint in res:
            # Read-shape on RBAC is still admin (RBAC discovery is
            # itself sensitive). Mutating shape definitely admin.
            return ActionClass.ADMIN

    # 3. Standard verb tables.
    if verb in _kb.WRITE_VERBS:
        return ActionClass.WRITE_DATA
    if verb in _kb.READ_VERBS:
        return ActionClass.READ
    return ActionClass.UNKNOWN


def _classify_dbounce(action: str, resource: str | None) -> ActionClass:
    if not action:
        return ActionClass.UNKNOWN
    stmt = _db.strip_dialect_prefix(action)
    if not stmt:
        return ActionClass.UNKNOWN
    if stmt in _db.DESTRUCTIVE_STATEMENTS:
        return ActionClass.DESTRUCTIVE_DATA
    if stmt in _db.ADMIN_STATEMENTS:
        return ActionClass.ADMIN
    if stmt in _db.WRITE_STATEMENTS:
        return ActionClass.WRITE_DATA
    if stmt in _db.READ_STATEMENTS:
        return ActionClass.READ
    return ActionClass.UNKNOWN


def _classify_gbounce(action: str, resource: str | None) -> ActionClass:
    if not action:
        return ActionClass.UNKNOWN
    method = _gb.normalize_method(action)
    if not method:
        return ActionClass.UNKNOWN
    res = (resource or "").lower()

    # 1. Admin resource hints force ADMIN regardless of method.
    for hint in _gb.ADMIN_RESOURCE_HINTS:
        if hint in res:
            return ActionClass.ADMIN

    if method in _gb.DESTRUCTIVE_METHODS:
        return ActionClass.DESTRUCTIVE_DATA
    if method in _gb.ADMIN_METHODS:
        return ActionClass.ADMIN
    if method in _gb.WRITE_METHODS:
        return ActionClass.WRITE_DATA
    if method in _gb.READ_METHODS:
        return ActionClass.READ
    return ActionClass.UNKNOWN


_PER_BOUNCER_CLASSIFIER = {
    "ibounce": _classify_ibounce,
    "kbouncer": _classify_kbouncer,
    "dbounce": _classify_dbounce,
    "gbounce": _classify_gbounce,
}


def classify_action(
    bouncer: str,
    action: str,
    resource: str | None = None,
) -> ActionClass:
    """Classify an action by its blast-radius class.

    Pure function — same inputs always produce the same output. No I/O,
    no LLM, no policy_sentry lookup.

    Args:
        bouncer: one of ``"ibounce"`` / ``"kbouncer"`` / ``"dbounce"`` /
            ``"gbounce"`` (short ``"kbounce"`` / ``"dbouncer"`` etc.
            aliases also accepted).
        action: bouncer-specific action string. ibounce =
            ``service:Action`` (e.g. ``s3:GetObject``); kbouncer =
            K8s verb (e.g. ``get`` / ``delete``); dbounce = SQL
            statement type (e.g. ``SELECT`` / ``psql:Delete``);
            gbounce = HTTP method (e.g. ``GET`` / ``http:POST``).
        resource: optional resource string. Used to escalate
            classifications (e.g. ``delete deployment`` →
            ``DESTRUCTIVE_DATA``; HTTP method to IMDS host → ``ADMIN``).

    Returns:
        :class:`ActionClass`. Empty or unmatched action → ``UNKNOWN``;
        no crash on malformed input.

    KNOWN_ADVERSARIAL_PATTERNS handling: a match in the catalogue
    forces ``ADMIN`` even when the prefix-table lookup would return
    DESTRUCTIVE_DATA (or anything else). Defense-in-depth per
    `docs/PROFILE-GENERATION-DESIGN.md` §2.3 — see also
    :mod:`iam_jit.deny_classifier.prompts` for the catalogue source
    of truth.
    """
    if not isinstance(bouncer, str) or not isinstance(action, str):
        return ActionClass.UNKNOWN
    normalised = _BOUNCER_ALIASES.get(bouncer.strip().lower())
    if normalised is None:
        return ActionClass.UNKNOWN

    # Defense-in-depth: KNOWN_ADVERSARIAL_PATTERNS short-circuits to
    # ADMIN. Per design §2.3 + §7 safeguard #2 — same predicate used
    # across all surfaces (`iam_jit_classify_deny`, future
    # `bounce_simulate_profile`, `bounce_grade_profile_for_workflow`).
    if _is_known_adversarial(normalised, action, resource):
        return ActionClass.ADMIN

    fn = _PER_BOUNCER_CLASSIFIER[normalised]
    return fn(action, resource)


__all__ = [
    "ActionClass",
    "classify_action",
]
