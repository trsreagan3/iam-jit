"""#397 / #398 / #400 — ambient autonomous protection: declarative config.

This package implements Phase A of the v1.1 ambient-autonomous-protection
feature cluster per [[ambient-autonomous-protection]]. Operators write ONE
declarative block (in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, or a
standalone `.iam-jit.yaml`); the agent reads it on session start and calls
`iam_jit_setup_from_config` to install + start + configure the bouncers
described in the declaration. After that, the operator never reconfigures.

Phase A ships in this package:

* `schema`  — embedded JSON Schema (mirror of schemas/iam-jit-config.schema.json
              for offline validation; the canonical copy is in schemas/).
* `loader`  — resolve a declaration from a dict, a path, or a context-file
              (CLAUDE.md / AGENTS.md / .cursorrules YAML codeblock tagged
              `iam-jit-config`). Validates against the embedded schema.
* `setup`   — `apply_declaration()` core: take a validated declaration +
              current posture, plan + (optionally) execute bouncer startup
              + env-var advisories + admin_action audit emit. The MCP tool
              `iam_jit_setup_from_config` and the CLI `iam-jit doctor
              apply-config` are both thin shims over this.

Phase B (#401-#404) is NOT shipped here. The schema accepts `improve.*`
fields for forward-compatibility; setup emits a warning when
`improve.enabled: true` until Phase B lands.
"""

from .loader import (
    ConfigLoadError,
    discover_declaration_source,
    extract_from_context_file,
    load_declaration,
    load_declaration_from_path,
    load_declaration_from_string,
    validate_declaration,
)
from .schema import IAM_JIT_CONFIG_SCHEMA, IAM_JIT_CONFIG_SCHEMA_VERSION
from .setup import SetupResult, apply_declaration, plan_declaration

__all__ = [
    "ConfigLoadError",
    "IAM_JIT_CONFIG_SCHEMA",
    "IAM_JIT_CONFIG_SCHEMA_VERSION",
    "SetupResult",
    "apply_declaration",
    "discover_declaration_source",
    "extract_from_context_file",
    "load_declaration",
    "load_declaration_from_path",
    "load_declaration_from_string",
    "plan_declaration",
    "validate_declaration",
]
