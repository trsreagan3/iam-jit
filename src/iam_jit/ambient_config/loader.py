"""Load + validate an iam-jit ambient declaration from various sources.

Supported sources:

* `dict` — already-parsed declaration (used by tests + by callers
  composing the declaration in memory).
* path to a standalone ``.iam-jit.yaml`` file.
* path to a context file (``CLAUDE.md``, ``AGENTS.md``, ``.cursorrules``,
  ``.devin/config.yaml``, etc.) that contains a YAML codeblock tagged
  ``iam-jit-config`` — we extract the codeblock, parse, and validate.
* auto-discovery — given a cwd, walk a fixed list of conventional file
  names + locations and return the first one that exists.

Per [[ibounce-honest-positioning]] every loader path is transparent
about WHERE the declaration came from — the returned tuple includes
the source path + the source kind so dry-run output can show the
operator "we read this from /repo/CLAUDE.md codeblock at line N".
"""

from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass
from typing import Any

import yaml

try:  # pragma: no cover — jsonschema is a base dep; guard anyway
    import jsonschema
    _HAS_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    jsonschema = None  # type: ignore[assignment]
    _HAS_JSONSCHEMA = False

from .schema import IAM_JIT_CONFIG_SCHEMA


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ConfigLoadError(ValueError):
    """Raised when a declaration cannot be loaded or fails validation.

    Carries a structured ``details`` dict so the MCP tool + CLI can
    re-emit it as JSON.
    """

    def __init__(
        self,
        message: str,
        *,
        source: str | None = None,
        code: str = "invalid_declaration",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.source = source
        self.code = code
        self.details = details or {}


# ---------------------------------------------------------------------------
# Source-discovery + extraction
# ---------------------------------------------------------------------------


# Canonical filenames an operator might write the declaration into.
# Ordered by precedence: standalone YAML wins over codeblocks in context
# files (operator intent is more explicit). Inside the context-file
# bucket, CLAUDE.md > AGENTS.md > .cursorrules > .devin/config.yaml.
# That ordering mirrors the per-harness recipes; agents reading this
# loader's output get the same precedence everywhere.
DEFAULT_FILENAMES_STANDALONE: tuple[str, ...] = (
    ".iam-jit.yaml",
    ".iam-jit.yml",
    "iam-jit.yaml",
    "iam-jit.yml",
)

DEFAULT_FILENAMES_CONTEXT: tuple[str, ...] = (
    "CLAUDE.md",
    "AGENTS.md",
    ".cursorrules",
    ".cursor/rules.md",
    ".devin/config.yaml",
    ".devin/config.yml",
)


# Codeblock tag we recognize inside context files. Operators wrap the
# declaration in a fenced YAML codeblock tagged ``iam-jit-config``:
#
#     ```iam-jit-config
#     iam-jit:
#       enabled: true
#       ...
#     ```
#
# We deliberately accept both the tag-only and the ``yaml iam-jit-config``
# form for editor-color-coding convenience.
_CODEBLOCK_RE = re.compile(
    r"```(?:yaml\s+)?iam-jit-config\s*\n(.*?)```",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class _DiscoveredSource:
    path: pathlib.Path
    kind: str  # "standalone" | "context"


def discover_declaration_source(
    cwd: pathlib.Path | str | None = None,
) -> _DiscoveredSource | None:
    """Find the first conventional source under ``cwd``.

    Walks ``DEFAULT_FILENAMES_STANDALONE`` first (standalone YAML wins),
    then ``DEFAULT_FILENAMES_CONTEXT`` (codeblock inside a context
    file). Returns None if nothing was found — callers decide whether
    that's an error.

    Per [[creates-never-mutates]] this never WRITES; it only reads.
    """
    root = pathlib.Path(cwd) if cwd else pathlib.Path.cwd()
    for name in DEFAULT_FILENAMES_STANDALONE:
        p = root / name
        if p.is_file():
            return _DiscoveredSource(path=p, kind="standalone")
    for name in DEFAULT_FILENAMES_CONTEXT:
        p = root / name
        if p.is_file():
            # Cheap pre-check: does the file contain a codeblock tag?
            # If not, skip — the operator put the file there for other
            # purposes and didn't declare iam-jit.
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            if _CODEBLOCK_RE.search(text):
                return _DiscoveredSource(path=p, kind="context")
    return None


def extract_from_context_file(text: str) -> str | None:
    """Pull the first ``iam-jit-config`` codeblock out of a context-file
    text. Returns the YAML body (str) or None if no codeblock matched.
    Multiple codeblocks: only the first is honored (operator intent =
    "this is THE declaration"; secondary blocks are informational
    documentation per the per-harness recipes).
    """
    m = _CODEBLOCK_RE.search(text)
    if not m:
        return None
    return m.group(1)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def load_declaration_from_string(
    yaml_text: str,
    *,
    source: str | None = None,
) -> dict[str, Any]:
    """Parse YAML text + validate against the schema. Returns the
    parsed + validated dict. Raises ConfigLoadError on YAML errors or
    schema-validation failures.
    """
    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise ConfigLoadError(
            f"failed to parse YAML: {e}",
            source=source,
            code="yaml_parse_error",
        ) from e
    if not isinstance(parsed, dict):
        raise ConfigLoadError(
            f"declaration must be a YAML mapping; got "
            f"{type(parsed).__name__}",
            source=source,
            code="not_a_mapping",
        )
    return validate_declaration(parsed, source=source)


def load_declaration_from_path(
    path: pathlib.Path | str,
) -> dict[str, Any]:
    """Read + parse + validate a declaration from a filesystem path.

    Auto-detects the source kind:
      * ``.yaml`` / ``.yml`` / ``.iam-jit.yaml`` — parse as standalone
      * anything else — try to extract an ``iam-jit-config`` codeblock
    """
    p = pathlib.Path(path)
    if not p.is_file():
        raise ConfigLoadError(
            f"declaration file not found: {p}",
            source=str(p),
            code="file_not_found",
        )
    try:
        text = p.read_text()
    except OSError as e:
        raise ConfigLoadError(
            f"cannot read {p}: {e}",
            source=str(p),
            code="read_error",
        ) from e

    suffix = p.suffix.lower()
    name = p.name.lower()
    is_standalone = (
        suffix in (".yaml", ".yml")
        or name in DEFAULT_FILENAMES_STANDALONE
    )

    if is_standalone:
        return load_declaration_from_string(text, source=str(p))

    # Context-file path: pull the codeblock.
    body = extract_from_context_file(text)
    if body is None:
        raise ConfigLoadError(
            f"no `iam-jit-config` codeblock found in {p}; expected a "
            f"fenced YAML block tagged ```iam-jit-config```.",
            source=str(p),
            code="no_codeblock",
        )
    return load_declaration_from_string(body, source=str(p))


def load_declaration(
    source: pathlib.Path | str | dict[str, Any],
    *,
    cwd: pathlib.Path | str | None = None,
) -> tuple[dict[str, Any], str]:
    """Polymorphic loader: takes a dict, a path, or None (auto-discover).

    Returns ``(declaration_dict, source_label)`` so dry-run output can
    cite the origin.
    """
    if isinstance(source, dict):
        return validate_declaration(source, source="<inline>"), "<inline>"
    if isinstance(source, (str, pathlib.Path)):
        # Treat strings that contain a newline as raw YAML text rather
        # than paths — convenient for tests + for MCP callers that
        # paste the declaration body directly.
        if isinstance(source, str) and "\n" in source:
            return (
                load_declaration_from_string(source, source="<inline-text>"),
                "<inline-text>",
            )
        path = pathlib.Path(source)
        return load_declaration_from_path(path), str(path)

    # Auto-discover under cwd.
    discovered = discover_declaration_source(cwd=cwd)
    if discovered is None:
        raise ConfigLoadError(
            "no iam-jit declaration found in cwd; expected "
            f"{', '.join(DEFAULT_FILENAMES_STANDALONE)} or a fenced "
            "`iam-jit-config` codeblock in "
            f"{', '.join(DEFAULT_FILENAMES_CONTEXT)}.",
            source=str(cwd) if cwd else None,
            code="no_declaration_found",
        )
    return load_declaration_from_path(discovered.path), str(discovered.path)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _check_common_key_mistakes(
    declaration: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return actionable error dicts for well-known operator mistakes
    BEFORE jsonschema runs.  These bypass the generic "Additional
    properties are not allowed" message with concrete, operator-language
    guidance per [[ibounce-honest-positioning]].

    Currently catches:
      * ``iam_jit`` (underscore) instead of ``iam-jit`` (hyphen)
      * top-level block present but ``enabled`` key missing
    """
    errors: list[dict[str, Any]] = []
    # Underscore vs hyphen in the top-level key.
    if "iam_jit" in declaration and "iam-jit" not in declaration:
        errors.append({
            "path": "/",
            "message": (
                "top-level key must be 'iam-jit' (hyphen), "
                "got 'iam_jit' (underscore). "
                "Rename the key: `iam-jit:` in your YAML."
            ),
            "schema_path": "properties/iam-jit",
        })
        return errors  # Nothing else is meaningful until the key is right.

    # Missing required `enabled` under `iam-jit`.
    iam_jit_block = declaration.get("iam-jit")
    if isinstance(iam_jit_block, dict) and "enabled" not in iam_jit_block:
        errors.append({
            "path": "iam-jit",
            "message": (
                "'iam-jit.enabled' is required but missing. "
                "Add `enabled: true` (or `enabled: false`) under the "
                "`iam-jit:` key."
            ),
            "schema_path": "properties/iam-jit/required",
        })
    return errors


def _enrich_schema_error(err: Any) -> str:
    """Return a more actionable message for common jsonschema errors.

    Falls back to ``err.message`` unchanged when no enrichment applies.
    Per [[ibounce-honest-positioning]]: never swap the message for
    something that omits the real problem — always include the original
    context.
    """
    msg = err.message
    # Intercept the generic "X was unexpected" additional-properties message
    # when the unexpected key is the underscore form.
    if "iam_jit" in msg and "not allowed" in msg.lower():
        return (
            "top-level key must be 'iam-jit' (hyphen), "
            "got 'iam_jit' (underscore). "
            "Rename the key: `iam-jit:` in your YAML. "
            f"(original: {msg})"
        )
    # "enabled" missing — surface the field path explicitly.
    if "'enabled' is a required property" in msg:
        path = "/".join(str(p) for p in err.absolute_path) or "iam-jit"
        return (
            f"'{path}.enabled' is required but missing. "
            "Add `enabled: true` (or `enabled: false`) to fix. "
            f"(original: {msg})"
        )
    return msg


def validate_declaration(
    declaration: dict[str, Any],
    *,
    source: str | None = None,
) -> dict[str, Any]:
    """Validate a parsed declaration against the embedded JSON Schema
    AND the cross-field rules that govern the ``posture`` distinction.

    Returns the declaration unchanged on success; raises
    ``ConfigLoadError`` with a structured ``details.errors`` list on
    failure. If jsonschema is somehow unavailable (it's a base dep,
    but...) returns the declaration unchanged.

    Cross-field rules (run AFTER JSON-Schema parse so the error
    messages use operator-language per [[ibounce-honest-positioning]]
    rather than ``oneOf failed at /...``):
      * `posture: managed` + `improve.enabled: true` → ERROR
        "managed posture forbids auto-improve; commit profile changes
        via PR"
      * `posture: managed` + bouncer with `profile: auto` (default or
        explicit) → ERROR "managed posture requires named + pinned
        profile; auto is for ambient only"
      * `posture: managed` + enabled bouncer missing `profile_source`
        → ERROR "managed posture requires profile_source for each
        enabled bouncer"
      * `posture: ambient` + `fail_on_deny: true` → WARNING returned
        in ``details.warnings`` (not an error; ambient still loads).
    """
    if not _HAS_JSONSCHEMA:
        # Defensive: jsonschema is a base dep but if it's missing
        # we still want the loader to be usable in tests / debugging.
        return declaration

    # ---- Common-mistake fast-path: surface actionable hints BEFORE the
    # generic jsonschema message so the operator sees a concrete fix, not
    # "Additional properties are not allowed".
    _early_errors: list[dict[str, Any]] = _check_common_key_mistakes(declaration)
    if _early_errors:
        raise ConfigLoadError(
            f"declaration has a configuration error: "
            f"{_early_errors[0]['message']}",
            source=source,
            code="schema_validation_error",
            details={"errors": _early_errors},
        )

    validator = jsonschema.Draft202012Validator(IAM_JIT_CONFIG_SCHEMA)
    errors = sorted(validator.iter_errors(declaration), key=lambda e: e.path)
    if errors:
        formatted = [
            {
                "path": "/".join(str(p) for p in err.absolute_path) or "/",
                "message": _enrich_schema_error(err),
                "schema_path": "/".join(str(p) for p in err.schema_path),
            }
            for err in errors
        ]
        raise ConfigLoadError(
            f"declaration failed schema validation: {len(errors)} error(s)",
            source=source,
            code="schema_validation_error",
            details={"errors": formatted},
        )

    # ---- Cross-field rules (posture-aware) ---------------------------
    cross_errors, cross_warnings = _check_cross_field_rules(declaration)
    if cross_errors:
        raise ConfigLoadError(
            f"declaration failed posture cross-field validation: "
            f"{len(cross_errors)} error(s)",
            source=source,
            code="posture_cross_field_error",
            details={
                "errors": cross_errors,
                "warnings": cross_warnings,
            },
        )
    # Warnings alone do not raise — they're surfaced via the loader's
    # caller (apply_declaration emits them; --inspect prints them).
    if cross_warnings:
        # Attach as a sentinel attribute so callers that want to see
        # the warning can read it. The declaration dict itself stays
        # untouched (no schema mutation).
        declaration.setdefault("__posture_warnings__", []).extend(
            cross_warnings
        )
    return declaration


def _check_cross_field_rules(
    declaration: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run the posture-aware cross-field checks.

    Returns ``(errors, warnings)`` where each error is a dict matching
    the JSON-Schema-error shape (so the CLI can print uniformly).
    """
    errors: list[dict[str, Any]] = []
    warnings: list[str] = []

    block = declaration.get("iam-jit") or {}
    if not isinstance(block, dict):
        return errors, warnings

    posture = (block.get("posture") or "ambient").strip().lower()
    bouncers = block.get("bouncers") or {}
    improve = block.get("improve") or {}
    fail_on_deny = bool(block.get("fail_on_deny", False))

    if posture == "managed":
        # Rule M1: managed forbids auto-improve.
        if improve.get("enabled") is True:
            errors.append({
                "path": "iam-jit/improve/enabled",
                "message": (
                    "managed posture forbids auto-improve; commit "
                    "profile changes via PR. Set `improve.enabled: "
                    "false` or change `posture: ambient` for local "
                    "dev."
                ),
                "schema_path": "cross_field/posture_managed_no_improve",
            })

        # Rule M2 + M3: each enabled bouncer must have a NAMED profile
        # (not `auto`) AND a `profile_source` pin.
        for name, bcfg in bouncers.items():
            if not isinstance(bcfg, dict):
                continue
            raw_enabled = bcfg.get("enabled")
            # In managed mode we treat any non-false `enabled` (true or
            # `when_X_present` heuristic) as "operator intends to run
            # this bouncer" → must be pinned. A conditional that
            # resolves false at runtime still must be pinned so the
            # declaration is self-contained.
            if raw_enabled is False:
                continue
            profile = (bcfg.get("profile") or "auto").strip()
            if profile == "auto":
                errors.append({
                    "path": f"iam-jit/bouncers/{name}/profile",
                    "message": (
                        "managed posture requires named + pinned "
                        f"profile for `{name}`; `auto` is for ambient "
                        "posture only. Specify `profile: <name>` "
                        "matching a profile in your profiles.yaml."
                    ),
                    "schema_path": (
                        "cross_field/posture_managed_no_auto_profile"
                    ),
                })
            if not bcfg.get("profile_source"):
                errors.append({
                    "path": f"iam-jit/bouncers/{name}/profile_source",
                    "message": (
                        "managed posture requires `profile_source` "
                        f"for each enabled bouncer; `{name}` is "
                        "enabled but no `profile_source` is set. "
                        "Pin to a committed file (e.g. "
                        "`./profiles/ci-staging.yaml`) or a signed "
                        "URL."
                    ),
                    "schema_path": (
                        "cross_field/"
                        "posture_managed_requires_profile_source"
                    ),
                })

    elif posture == "ambient":
        # Rule A1 (warning, not error): ambient + fail_on_deny is
        # unusual. Surface as a friendly suggestion.
        if fail_on_deny:
            warnings.append(
                "ambient posture typically tolerates blocks; you set "
                "`fail_on_deny: true` which will halt your dev loop on "
                "every deny. Consider `posture: managed` for CI/CD or "
                "leave `fail_on_deny: false` (the ambient default) for "
                "local dev."
            )

    return errors, warnings


__all__ = [
    "DEFAULT_FILENAMES_CONTEXT",
    "DEFAULT_FILENAMES_STANDALONE",
    "ConfigLoadError",
    "discover_declaration_source",
    "extract_from_context_file",
    "load_declaration",
    "load_declaration_from_path",
    "load_declaration_from_string",
    "validate_declaration",
]
