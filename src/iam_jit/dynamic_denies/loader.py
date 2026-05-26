# #324a — ibounce dynamic-deny YAML loader + schema validator.
"""Read + validate + filter ``~/.iam-jit/dynamic-denies.yaml``.

The file shape is specified by
``docs/schemas/dynamic-denies-v1.json``; this loader validates against
that schema (using ``jsonschema``, already a hard dep), filters the
``denies`` list to rules whose ``applied_to`` includes ``ibounce``, and
drops rules whose ``expires_at`` has already passed at load time.

Why a separate loader vs ``ibounce config import`` reuse? Three reasons:

  1. **Different wire shape.** The dynamic-deny file is operator-managed
     (hand-edited OR written by ``iam-jit deny add`` in #324e); the
     ibounce config-import path is full-export-import roundtrip with a
     completely different YAML root + multi-product semantics.
  2. **Schema-versioning isolation.** The dynamic-deny schema bumps on
     its own cadence (per the cross-product schema-index convention);
     bundling it into the ibounce config-import loader couples two
     unrelated bump streams.
  3. **Hot-reload safety.** The watcher (``watcher.py``) calls this
     loader on every fsevents notification; the import-path validator
     is slower + does more work + isn't safe to re-run mid-request.

Per ``[[ibounce-honest-positioning]]`` the failure semantics are
fail-CLOSED: a parse / schema / structural error returns a structured
:class:`DynamicDenyLoadError`; the watcher catches the error + RETAINS
the previous in-memory snapshot. We never silently drop rules.
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
import pathlib
import re
from typing import Any

from .types import Rule, RuleSet

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Path resolution + constants
# ---------------------------------------------------------------------------

DEFAULT_PATH_ENV = "IAM_JIT_DYNAMIC_DENIES_PATH"
"""Env-var override for the on-disk file path. Mirrors the
``IAM_JIT_BOUNCER_*`` convention from
``[[enterprise-profile-distribution]]`` so an operator who already
points their bouncer config at a non-default location can do the
same for dynamic denies."""

DEFAULT_REL_PATH = ".iam-jit/dynamic-denies.yaml"
"""Default relative path under the operator's home dir. ``~`` resolved
at lookup time via :py:func:`pathlib.Path.home()` so a multi-user
deployment doesn't inherit the build-time home."""

BOUNCER_NAME = "ibounce"
"""Value the loader matches in each rule's ``applied_to`` list. Pinned
here so a typo elsewhere in the package surfaces as a name-resolution
error rather than a silent miss."""

SCHEMA_VERSION = "1.0"
"""On-disk schema version this loader accepts. A future bump migrates
here per the cross-product index convention (string, not int)."""

PRODUCT_MAGIC = "iam-jit-dynamic-denies"
"""On-disk ``product`` discriminator. Matches
``docs/schemas/dynamic-denies-v1.json::product.const``."""

# Pattern for AWS ARN targets the loader keeps in the ibounce lane.
# Matches the three AWS partitions (commercial, China, GovCloud) since
# operators may legitimately route a deny against any of them.
_AWS_ARN_PARTITIONS = ("arn:aws:", "arn:aws-cn:", "arn:aws-us-gov:")

# Pattern for the ``secret:`` shorthand the design doc allows on the
# ibounce lane — convenience shortcut for "lock out a specific secret"
# that resolves to a Secrets Manager ARN at match time.
_SECRET_SHORTHAND_PREFIX = "secret:"

# Rule-id pattern (mirrors schema regex).
_RULE_ID_PATTERN = re.compile(r"^dd_[0-9A-HJKMNP-TV-Z]{26}$")

# Duration pattern (mirrors schema regex).
_DURATION_PATTERN = re.compile(r"^(permanent|[0-9]+(s|m|h|d|w))$")

# Set of bouncer names accepted in `applied_to`. The loader is
# permissive about WHICH bouncer the rule routes to (the file may
# legitimately carry kbouncer-only rules); it only filters DOWN to
# entries containing ``ibounce`` when building the snapshot. Per
# ``[[cross-product-agent-parity]]`` the canonical list is the
# Bounce-suite product names; ``kbouncer`` is a historical alias kept
# for cross-version-tolerance (matches gbounce/kbouncer loader behaviour).
_VALID_BOUNCER_NAMES: frozenset[str] = frozenset({
    "ibounce",
    "kbounce",
    "kbouncer",
    "dbounce",
    "gbounce",
})

# Provenance values accepted in each rule's ``source`` field.
# Exported as a module-level constant so tests can monkeypatch it for the
# sabotage check (per [[install-ux-gap-2026-05-26]] discipline) and so
# future provenance categories require a single-line addition here.
# #645 CRIT: "threat-feed" was missing — loader rejected rules written by
# the threat-feed applier, causing silent revert to last-good snapshot.
VALID_SOURCES: frozenset[str] = frozenset({
    "cli",
    "mcp",
    "org-distributed",
    "imported",
    "threat-feed",
})


def resolve_default_path() -> str:
    """Resolve the loader's default file path, honouring
    :data:`DEFAULT_PATH_ENV`.

    Returns an empty string when the home dir cannot be resolved (a
    container with no $HOME and no override env var). The caller
    surfaces the empty string in the startup banner + falls back to
    "no dynamic-denies file configured."
    """
    override = (os.environ.get(DEFAULT_PATH_ENV) or "").strip()
    if override:
        return override
    try:
        home = pathlib.Path.home()
    except (RuntimeError, KeyError):
        return ""
    if not str(home):
        return ""
    return str(home / DEFAULT_REL_PATH)


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------


class DynamicDenyLoadError(ValueError):
    """A parse / schema / structural error in the dynamic-deny YAML
    file. Carries a structured ``stage`` so the audit-event ``extra``
    block can surface where the failure happened (read / parse /
    schema / structure) without a free-text grep.
    """

    def __init__(
        self,
        message: str,
        *,
        stage: str,
        path: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.path = path
        self.__cause__ = cause


# ---------------------------------------------------------------------------
# Schema validator (JSON Schema Draft 2020-12)
# ---------------------------------------------------------------------------


def _schema_path() -> pathlib.Path:
    """Resolve the canonical schema file. Lives at
    ``docs/schemas/dynamic-denies-v1.json`` relative to the repo root;
    in installed wheels it lives under ``iam_jit/schemas/`` (the
    package-data shape used by the existing ibounce-config schema).
    Tries both locations so the loader works in source-tree pytest
    runs AND post-``pip install`` deployments.
    """
    here = pathlib.Path(__file__).resolve()
    # 1. Source-tree run: docs/schemas/dynamic-denies-v1.json
    src_tree = here.parents[3] / "docs" / "schemas" / "dynamic-denies-v1.json"
    if src_tree.exists():
        return src_tree
    # 2. Installed-package shape: iam_jit/schemas/dynamic-denies-v1.json
    installed = here.parents[1] / "schemas" / "dynamic-denies-v1.json"
    if installed.exists():
        return installed
    # 3. Embedded fallback — if neither file is present, the loader's
    #    structural validation (below) still catches every required
    #    field; the JSON-schema pass is defense-in-depth.
    return src_tree  # returns even when missing so the caller can stat


_cached_schema: dict[str, Any] | None = None


def _load_schema() -> dict[str, Any] | None:
    """Read + cache the JSON schema dict. Returns ``None`` when the
    schema file isn't reachable in this deployment — in which case the
    loader falls back to its hand-rolled structural validator
    (defense-in-depth: the structural validator covers every required
    field the schema declares).
    """
    global _cached_schema
    if _cached_schema is not None:
        return _cached_schema
    path = _schema_path()
    if not path.exists():
        logger.debug(
            "dynamic-denies schema not found at %s; falling back to "
            "structural validator only", path,
        )
        return None
    try:
        import json
        with path.open("r", encoding="utf-8") as fh:
            _cached_schema = json.load(fh)
        return _cached_schema
    except Exception as e:
        logger.warning(
            "dynamic-denies schema at %s failed to parse: %s "
            "(falling back to structural validator only)", path, e,
        )
        return None


def _validate_against_schema(data: Any, path: str) -> None:
    """Run the file through the JSON schema. Skips silently when the
    schema is unreachable (see ``_load_schema``); the structural
    validator below covers the same fields."""
    schema = _load_schema()
    if schema is None:
        return
    try:
        import jsonschema
    except ImportError:
        # jsonschema is a hard dep per pyproject.toml; this branch is
        # defensive (if someone strips deps for a slim container build
        # we still want the loader to function via the structural pass).
        logger.debug("jsonschema unavailable; falling back to structural validator")
        return
    try:
        validator_cls = getattr(
            jsonschema, "Draft202012Validator",
            jsonschema.Draft7Validator,
        )
        validator = validator_cls(schema)
        errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
        if errors:
            # Surface the first error verbatim — operators get one
            # actionable message (not a wall of every schema miss).
            first = errors[0]
            field_path = "/".join(str(p) for p in first.absolute_path) or "(root)"
            raise DynamicDenyLoadError(
                f"schema violation at {field_path}: {first.message}",
                stage="schema",
                path=path,
            )
    except DynamicDenyLoadError:
        raise
    except Exception as e:
        # A bad schema or jsonschema-internal error is not the
        # operator's problem; log + fall through to the structural
        # validator.
        logger.warning(
            "dynamic-denies schema validation failed internally: %s "
            "(falling back to structural validator)", e,
        )


# ---------------------------------------------------------------------------
# YAML parsing + filtering
# ---------------------------------------------------------------------------


def load_file(path: str | None) -> RuleSet:
    """Read, validate, filter, and return the active rule snapshot.

    Behaviour matrix:

    ============================  =========================================
    Input                          Output
    ============================  =========================================
    ``path is None`` or ``""``     :py:meth:`RuleSet.empty` (no file
                                   configured).
    File does not exist            :py:meth:`RuleSet.empty` (an operator
                                   without any installed dynamic denies
                                   still wants the proxy to start).
    Parse / schema / structural    Raises :class:`DynamicDenyLoadError`.
    error                          (Caller policy: fail-CLOSED, retain
                                   previous snapshot.)
    Valid file                     :class:`RuleSet` with ibounce-lane
                                   rules, expired entries dropped.
    ============================  =========================================
    """
    if not path:
        return RuleSet.empty()

    p = pathlib.Path(path)
    if not p.exists():
        # Honest "no file" shape — distinguished from a parse error so
        # the watcher emits the right ``ReloadReason`` and the banner
        # surfaces a clean "0 rules" without an alarm.
        return RuleSet.empty(source_path=str(p))

    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise DynamicDenyLoadError(
            f"failed to read {p}: {e}", stage="read", path=str(p), cause=e,
        ) from e

    # ruamel.yaml is the existing dep + round-trip-safe (preserves
    # comments) — important for the future writer (#324e) that wants to
    # append a rule without losing operator-written comments.
    try:
        from ruamel.yaml import YAML
        yaml_loader = YAML(typ="safe", pure=True)
        data = yaml_loader.load(raw)
    except Exception as e:
        raise DynamicDenyLoadError(
            f"YAML parse error in {p}: {e}", stage="parse",
            path=str(p), cause=e,
        ) from e

    if data is None:
        # An empty file -> empty rule set. Distinct from missing file
        # (above) — the operator may legitimately ``> dynamic-denies.yaml``
        # to clear all rules.
        return RuleSet.empty(source_path=str(p))
    if not isinstance(data, dict):
        raise DynamicDenyLoadError(
            f"{p}: top-level value must be an object, got {type(data).__name__}",
            stage="structure", path=str(p),
        )

    _validate_against_schema(data, str(p))
    _validate_structure(data, str(p))

    raw_denies = data.get("denies") or []
    if not isinstance(raw_denies, list):
        raise DynamicDenyLoadError(
            f"{p}: `denies` must be a list, got {type(raw_denies).__name__}",
            stage="structure", path=str(p),
        )

    now = _dt.datetime.now(_dt.timezone.utc)
    out: list[Rule] = []
    seen_ids: set[str] = set()
    for idx, raw_rule in enumerate(raw_denies):
        if not isinstance(raw_rule, dict):
            raise DynamicDenyLoadError(
                f"{p}: denies[{idx}] must be an object",
                stage="structure", path=str(p),
            )
        rule = _build_rule(raw_rule, idx=idx, path=str(p))
        if rule.id in seen_ids:
            raise DynamicDenyLoadError(
                f"{p}: denies[{idx}] duplicate rule id {rule.id!r}",
                stage="structure", path=str(p),
            )
        seen_ids.add(rule.id)
        if BOUNCER_NAME not in rule.applied_to:
            # Routes to another bouncer; not our lane. Skipped silently
            # — kbouncer/dbounce/gbounce loaders pick up their own.
            continue
        if rule.expires_at is not None and rule.expires_at < now:
            # Already expired at load time — drop so the matcher never
            # sees it. The expiry-event admin-action emit is the
            # watcher's job (#324a-future + #324e); the loader keeps
            # the read path pure.
            continue
        ibounce_rule = _filter_to_ibounce_targets(rule)
        if ibounce_rule is None:
            # Rule's `applied_to` claimed ibounce but none of its
            # targets parsed as an ARN/secret shorthand. Honest skip:
            # log a warning so a misrouted rule surfaces in the
            # operator's logs without crashing serve(). Mirrors the
            # design doc's "ambiguous: no shape matches" handling
            # (#324e rejects at WRITE time; the reader here is
            # defense-in-depth for hand-edited files).
            logger.warning(
                "dynamic-deny rule %s applied_to=ibounce but no ibounce-"
                "shaped targets — skipping. Hand-editing the YAML? "
                "ibounce targets must be AWS ARN globs or `secret:NAME` "
                "shortcuts.", rule.id,
            )
            continue
        out.append(ibounce_rule)

    return RuleSet(
        rules=tuple(out),
        source_path=str(p),
        loaded_at=now,
        total_rules_in_file=len(raw_denies),
    )


# ---------------------------------------------------------------------------
# Structural validator (defense-in-depth alongside the JSON schema pass)
# ---------------------------------------------------------------------------


def _validate_structure(data: dict[str, Any], path: str) -> None:
    """Hand-rolled validator for the fields the JSON schema declares
    `required`. Runs AFTER ``_validate_against_schema`` so a missing
    schema file still gets the same structural checks.

    Operator-friendly errors: each message names the offending field
    + value so the operator can fix without grepping the schema.
    """
    schema_version = data.get("schema_version")
    if not schema_version:
        raise DynamicDenyLoadError(
            f"{path}: missing required field `schema_version`",
            stage="structure", path=path,
        )
    if schema_version != SCHEMA_VERSION:
        raise DynamicDenyLoadError(
            f"{path}: unsupported schema_version {schema_version!r} "
            f"(this ibounce build accepts {SCHEMA_VERSION!r} only)",
            stage="structure", path=path,
        )
    product = data.get("product")
    if product is not None and product != PRODUCT_MAGIC:
        raise DynamicDenyLoadError(
            f"{path}: unexpected `product` value {product!r} "
            f"(this loader accepts {PRODUCT_MAGIC!r} only)",
            stage="structure", path=path,
        )
    if "denies" not in data:
        raise DynamicDenyLoadError(
            f"{path}: missing required field `denies`",
            stage="structure", path=path,
        )


def _build_rule(raw: dict[str, Any], *, idx: int, path: str) -> Rule:
    """Construct a :class:`Rule` from one ``denies[]`` entry. Performs
    field-level type / regex checks the schema declares ``required``
    and normalises optional fields to ``None``."""
    rid = str(raw.get("id") or "")
    if not _RULE_ID_PATTERN.match(rid):
        raise DynamicDenyLoadError(
            f"{path}: denies[{idx}] id {rid!r} does not match required "
            f"`dd_<ULID>` shape",
            stage="structure", path=path,
        )

    raw_targets = raw.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise DynamicDenyLoadError(
            f"{path}: denies[{idx}] ({rid}) `targets` must be a non-empty list",
            stage="structure", path=path,
        )
    targets: list[str] = []
    for j, t in enumerate(raw_targets):
        if not isinstance(t, str) or not t.strip():
            raise DynamicDenyLoadError(
                f"{path}: denies[{idx}] ({rid}) targets[{j}] must be a "
                f"non-empty string",
                stage="structure", path=path,
            )
        targets.append(t.strip())

    reason = str(raw.get("reason") or "")
    if not reason:
        raise DynamicDenyLoadError(
            f"{path}: denies[{idx}] ({rid}) `reason` is required + must "
            f"be non-empty",
            stage="structure", path=path,
        )

    duration = str(raw.get("duration") or "")
    if not _DURATION_PATTERN.match(duration):
        raise DynamicDenyLoadError(
            f"{path}: denies[{idx}] ({rid}) duration {duration!r} does not "
            f"match `permanent` or `N{{s|m|h|d|w}}`",
            stage="structure", path=path,
        )

    added_by = str(raw.get("added_by") or "")
    if not added_by:
        raise DynamicDenyLoadError(
            f"{path}: denies[{idx}] ({rid}) `added_by` is required",
            stage="structure", path=path,
        )

    added_at = _parse_iso8601(raw.get("added_at"))
    if added_at is None:
        raise DynamicDenyLoadError(
            f"{path}: denies[{idx}] ({rid}) `added_at` must be an "
            f"ISO 8601 / RFC 3339 timestamp",
            stage="structure", path=path,
        )

    # expires_at: None when duration=='permanent' OR when the writer
    # explicitly emitted `expires_at: null` (round-trip from the
    # writer). Otherwise must parse.
    raw_expires = raw.get("expires_at")
    if raw_expires is None or duration == "permanent":
        expires_at: _dt.datetime | None = None
    else:
        expires_at = _parse_iso8601(raw_expires)
        if expires_at is None:
            raise DynamicDenyLoadError(
                f"{path}: denies[{idx}] ({rid}) `expires_at` must be an "
                f"ISO 8601 timestamp or null",
                stage="structure", path=path,
            )

    raw_applied = raw.get("applied_to")
    if not isinstance(raw_applied, list) or not raw_applied:
        raise DynamicDenyLoadError(
            f"{path}: denies[{idx}] ({rid}) `applied_to` must be a "
            f"non-empty list",
            stage="structure", path=path,
        )
    applied_to: list[str] = []
    for j, b in enumerate(raw_applied):
        if not isinstance(b, str) or not b.strip():
            raise DynamicDenyLoadError(
                f"{path}: denies[{idx}] ({rid}) applied_to[{j}] must be a "
                f"non-empty string",
                stage="structure", path=path,
            )
        if b not in _VALID_BOUNCER_NAMES:
            raise DynamicDenyLoadError(
                f"{path}: denies[{idx}] ({rid}) applied_to[{j}] {b!r} is not "
                f"a recognised bouncer name (expected one of: "
                f"{sorted(_VALID_BOUNCER_NAMES)})",
                stage="structure", path=path,
            )
        applied_to.append(b)

    applies_to_recommender = bool(raw.get("applies_to_recommender", True))

    source = str(raw.get("source") or "cli")
    if source not in VALID_SOURCES:
        raise DynamicDenyLoadError(
            f"{path}: denies[{idx}] ({rid}) `source` {source!r} is not a "
            f"recognised provenance (expected one of: {'/'.join(sorted(VALID_SOURCES))})",
            stage="structure", path=path,
        )

    org_url = raw.get("org_distributed_url")
    org_url_str = str(org_url) if org_url else None

    return Rule(
        id=rid,
        targets=tuple(targets),
        reason=reason,
        duration=duration,
        added_by=added_by,
        added_at=added_at,
        expires_at=expires_at,
        applied_to=tuple(applied_to),
        applies_to_recommender=applies_to_recommender,
        source=source,
        org_distributed_url=org_url_str,
    )


def _parse_iso8601(value: Any) -> _dt.datetime | None:
    """Parse an ISO 8601 / RFC 3339 string into a UTC-aware
    :py:class:`datetime`. Accepts the ``Z`` suffix Python's stdlib
    ``fromisoformat`` rejects pre-3.11; returns ``None`` on failure so
    the caller can surface the error in context.
    """
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    # Python's fromisoformat is strict about `Z` pre-3.11; substitute
    # the canonical offset so we can rely on the stdlib path.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc)


def _filter_to_ibounce_targets(rule: Rule) -> Rule | None:
    """Return a copy of ``rule`` whose ``targets`` is filtered down to
    ibounce-shaped targets (AWS ARNs + the ``secret:NAME`` shorthand
    that the design doc routes to ibounce). Returns ``None`` if no
    targets survive — the loader skips such rules so the matcher only
    ever sees ARN-shaped patterns.

    This is a SECOND layer of filtering on top of ``applied_to`` —
    catches the case where #324e routed a rule to ibounce-and-gbounce
    (e.g. an RDS hostname that lands on both) but the ibounce-side
    only cares about the ARN-shaped targets within that rule.
    """
    keep: list[str] = []
    for t in rule.targets:
        if any(t.startswith(p) for p in _AWS_ARN_PARTITIONS):
            keep.append(t)
            continue
        if t.startswith(_SECRET_SHORTHAND_PREFIX):
            keep.append(t)
            continue
        # Not an ibounce-shaped target; drop silently.
        continue
    if not keep:
        return None
    if len(keep) == len(rule.targets):
        return rule
    return dataclasses_replace(rule, targets=tuple(keep))


def dataclasses_replace(rule: Rule, **changes: Any) -> Rule:
    """Wrapper around ``dataclasses.replace`` so callers don't need to
    import the stdlib module just to swap a tuple field."""
    import dataclasses
    return dataclasses.replace(rule, **changes)
