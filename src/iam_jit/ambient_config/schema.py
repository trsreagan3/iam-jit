"""Embedded JSON Schema for the iam-jit ambient declaration.

The canonical schema lives at ``schemas/iam-jit-config.schema.json``. We
embed a copy here so offline validation (in tests, in installed wheels
where ``schemas/`` is not on the import path, in the MCP server) does
not require a file-system lookup.

Both copies MUST be byte-identical except for whitespace + the embedded
``Mapping[str, Any]`` form. A test (`test_schema_embedded_matches_canonical`)
enforces that on every test run.
"""

from __future__ import annotations

import importlib.resources as _resources
import json
from typing import Any

IAM_JIT_CONFIG_SCHEMA_VERSION = "1.0"


def _read_canonical_schema() -> dict[str, Any]:
    """Read the canonical schema from disk.

    Tries the in-tree ``schemas/`` directory first (development), then
    falls back to ``importlib.resources`` once the wheel ships
    ``iam_jit/schemas/iam-jit-config.schema.json`` (see pyproject.toml
    package-data block). The fallback returns None if the resource
    isn't bundled; we then return the inline copy below.
    """
    import pathlib as _pl

    here = _pl.Path(__file__).resolve()
    # Walk up to find the repo root that contains `schemas/`. Caps at
    # 5 levels so we don't traverse the entire filesystem.
    for parent in [here.parent, *list(here.parents)[:5]]:
        candidate = parent / "schemas" / "iam-jit-config.schema.json"
        if candidate.is_file():
            try:
                return json.loads(candidate.read_text())
            except (OSError, json.JSONDecodeError):
                break

    # Wheel fallback: package-data copy under iam_jit/schemas/.
    try:
        text = (
            _resources.files("iam_jit.schemas")
            .joinpath("iam-jit-config.schema.json")
            .read_text()
        )
        return json.loads(text)
    except (FileNotFoundError, ModuleNotFoundError, AttributeError):
        pass

    # Last-ditch inline copy. Kept in sync with the canonical schema by
    # `test_schema_embedded_matches_canonical` (which loads the
    # canonical schema directly + compares).
    return _INLINE_SCHEMA


# Inline fallback so the package validates even if no schemas/ tree is
# present (e.g., when imported from a stripped-down distribution).
# MUST mirror schemas/iam-jit-config.schema.json. Tests enforce this.
_INLINE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://iam-jit.dev/schemas/iam-jit-config.v1.json",
    "title": "iam-jit ambient declarative config (v1.0)",
    "description": (
        "Operator-authored declaration consumed by "
        "`iam_jit_setup_from_config` (MCP) and `iam-jit doctor "
        "--apply-config` (CLI)."
    ),
    "type": "object",
    "additionalProperties": False,
    "required": ["iam-jit"],
    "properties": {
        "iam-jit": {
            "type": "object",
            "additionalProperties": False,
            "required": ["enabled"],
            "properties": {
                "schema_version": {"type": "string", "enum": ["1.0"]},
                "enabled": {"type": "boolean"},
                "posture": {
                    "type": "string",
                    "enum": ["ambient", "managed"],
                    "default": "ambient",
                },
                "bouncers": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "ibounce": {"$ref": "#/$defs/bouncer_block"},
                        "kbouncer": {"$ref": "#/$defs/bouncer_block"},
                        "dbounce": {"$ref": "#/$defs/bouncer_block"},
                        "gbounce": {"$ref": "#/$defs/bouncer_block"},
                    },
                },
                "improve": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "enabled": {"type": "boolean", "default": False},
                        "cadence": {
                            "type": "string",
                            "enum": [
                                "per_session",
                                "daily",
                                "weekly",
                                "never",
                            ],
                            "default": "per_session",
                        },
                        "auto_install_profiles": {
                            "type": "boolean",
                            "default": True,
                        },
                        "require_operator_approval_above_change_threshold": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "default": 0.30,
                        },
                    },
                },
                "notify_on_deny": {"type": "boolean", "default": True},
                "fail_on_deny": {"type": "boolean", "default": False},
                "require_signed_profiles": {
                    "type": "boolean",
                    "default": False,
                },
                "threat_feed": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "enabled": {"type": "boolean", "default": False},
                        "update_cadence": {
                            "type": "string",
                            "enum": [
                                "per_session",
                                "hourly",
                                "daily",
                                "weekly",
                                "on_demand",
                            ],
                            "default": "daily",
                        },
                        "feeds": {
                            "type": "array",
                            "items": {"$ref": "#/$defs/threat_feed_block"},
                        },
                    },
                },
                # #420 / §A59 — declarative resource mappings consumed by
                # `iam-jit resource-map` + `iam_jit_resource_map` MCP tool.
                # Phase E of [[bouncer-informs-agent-informs-iam-jit]]:
                # operator declares NAMED account/region/name substitution
                # rules; agent picks a name by intent ("staging→prod") and
                # iam-jit applies pure textual substitution. No inference
                # at iam-jit layer (per [[scorer-is-ground-truth]]).
                "resource_mappings": {
                    "type": "object",
                    "additionalProperties": {
                        "$ref": "#/$defs/resource_mapping_block",
                    },
                    "description": (
                        "Named mappings used by `iam-jit resource-map` + "
                        "`iam_jit_resource_map` (MCP) to translate a "
                        "permission set extracted from one environment "
                        "(e.g. staging) into the equivalent shape for "
                        "another environment (e.g. prod). The agent "
                        "picks the mapping name by operator intent."
                    ),
                },
            },
        }
    },
    "$defs": {
        "bouncer_block": {
            "type": "object",
            "additionalProperties": False,
            "required": ["enabled"],
            "properties": {
                "enabled": {
                    "oneOf": [
                        {"type": "boolean"},
                        {
                            "type": "string",
                            "enum": [
                                "when_kubeconfig_present",
                                "when_db_env_present",
                                "when_proxy_env_present",
                                "when_aws_env_present",
                            ],
                        },
                    ]
                },
                "mode": {
                    "type": "string",
                    "enum": ["discovery", "cooperative", "strict"],
                    "default": "discovery",
                },
                "profile": {
                    "type": "string",
                    "minLength": 1,
                    "default": "auto",
                },
                "port": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535,
                },
                "profile_source": {
                    "type": "string",
                    "minLength": 1,
                },
                "profile_sha256": {
                    "type": "string",
                    "pattern": "^[a-fA-F0-9]{64}$",
                },
                "extra_args": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
        },
        "threat_feed_block": {
            "type": "object",
            "additionalProperties": False,
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "minLength": 1},
                "publisher_pubkey": {"type": "string"},
                "verification_mode": {
                    "type": "string",
                    "enum": ["ed25519", "cosign-keyless"],
                    "default": "ed25519",
                },
                "severity_auto_apply_threshold": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "default": "HIGH",
                },
                "cosign_identity": {"type": "string"},
                "cosign_issuer": {"type": "string"},
                "enabled": {"type": "boolean", "default": True},
                "nickname": {"type": "string"},
            },
        },
        "resource_mapping_block": {
            "type": "object",
            "additionalProperties": False,
            "description": (
                "One named resource mapping. account_id + region are "
                "exact-match substitution maps. name_patterns are "
                "ordered glob-style rewrites applied to resource names "
                "(first match wins)."
            ),
            "properties": {
                "account_id": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "string",
                        "minLength": 1,
                    },
                },
                "region": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "string",
                        "minLength": 1,
                    },
                },
                "name_patterns": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["match", "replace"],
                        "properties": {
                            "match": {"type": "string", "minLength": 1},
                            "replace": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
}


IAM_JIT_CONFIG_SCHEMA: dict[str, Any] = _read_canonical_schema()


__all__ = [
    "IAM_JIT_CONFIG_SCHEMA",
    "IAM_JIT_CONFIG_SCHEMA_VERSION",
]
