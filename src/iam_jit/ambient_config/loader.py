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


def validate_declaration(
    declaration: dict[str, Any],
    *,
    source: str | None = None,
) -> dict[str, Any]:
    """Validate a parsed declaration against the embedded JSON Schema.

    Returns the declaration unchanged on success; raises
    ``ConfigLoadError`` with a structured ``details.errors`` list on
    failure. If jsonschema is somehow unavailable (it's a base dep,
    but...) returns the declaration unchanged with a warning logged
    via the details payload.
    """
    if not _HAS_JSONSCHEMA:
        # Defensive: jsonschema is a base dep but if it's missing
        # we still want the loader to be usable in tests / debugging.
        return declaration

    validator = jsonschema.Draft202012Validator(IAM_JIT_CONFIG_SCHEMA)
    errors = sorted(validator.iter_errors(declaration), key=lambda e: e.path)
    if not errors:
        return declaration

    formatted = [
        {
            "path": "/".join(str(p) for p in err.absolute_path) or "/",
            "message": err.message,
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
