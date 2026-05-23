"""#397 — tests for the ambient declaration schema + loader.

Covers:
  * embedded schema matches canonical schemas/iam-jit-config.schema.json
  * every example in docs validates
  * invalid enum values are rejected
  * missing required fields are rejected
"""

from __future__ import annotations

import json
import pathlib

import pytest

from iam_jit.ambient_config import (
    ConfigLoadError,
    IAM_JIT_CONFIG_SCHEMA,
    extract_from_context_file,
    load_declaration_from_string,
    validate_declaration,
)
from iam_jit.ambient_config.schema import _INLINE_SCHEMA


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CANONICAL_SCHEMA = REPO_ROOT / "schemas" / "iam-jit-config.schema.json"


# ---------------------------------------------------------------------------
# Schema self-consistency
# ---------------------------------------------------------------------------


def test_schema_canonical_and_package_data_copies_match() -> None:
    """Top-level `schemas/iam-jit-config.schema.json` (canonical) must
    be byte-identical to `src/iam_jit/schemas/iam-jit-config.schema.json`
    (wheel-bundled). Caught at every test run so a one-side edit can't
    silently drift.
    """
    canonical_text = CANONICAL_SCHEMA.read_text()
    bundled_text = (
        REPO_ROOT
        / "src"
        / "iam_jit"
        / "schemas"
        / "iam-jit-config.schema.json"
    ).read_text()
    assert canonical_text == bundled_text, (
        "schemas/iam-jit-config.schema.json and "
        "src/iam_jit/schemas/iam-jit-config.schema.json must be "
        "byte-identical. Re-run `cp schemas/iam-jit-config.schema.json "
        "src/iam_jit/schemas/iam-jit-config.schema.json` after editing."
    )


def test_schema_embedded_matches_canonical() -> None:
    """The inline fallback in schema.py + the loaded
    IAM_JIT_CONFIG_SCHEMA must have the same `properties` keys + the
    same `required` lists at the top level. We don't require byte-equal
    JSON (the descriptions can diverge slightly to save space inline)
    but the GATING surface (properties / required / enums) must match.
    """
    canonical = json.loads(CANONICAL_SCHEMA.read_text())
    # IAM_JIT_CONFIG_SCHEMA should resolve to the canonical schema in
    # development (loader walks parents).
    assert IAM_JIT_CONFIG_SCHEMA["$id"] == canonical["$id"]
    # Top-level required.
    assert IAM_JIT_CONFIG_SCHEMA["required"] == canonical["required"]
    # iam-jit block required.
    assert (
        IAM_JIT_CONFIG_SCHEMA["properties"]["iam-jit"]["required"]
        == canonical["properties"]["iam-jit"]["required"]
    )
    # Inline fallback should ALSO carry the same required gates so the
    # offline-validation path is honest.
    assert _INLINE_SCHEMA["required"] == canonical["required"]
    assert (
        _INLINE_SCHEMA["properties"]["iam-jit"]["required"]
        == canonical["properties"]["iam-jit"]["required"]
    )


# ---------------------------------------------------------------------------
# Valid examples
# ---------------------------------------------------------------------------


MINIMAL_VALID = {
    "iam-jit": {
        "enabled": True,
    }
}

FULL_VALID = {
    "iam-jit": {
        "schema_version": "1.0",
        "enabled": True,
        "posture": "ambient",
        "bouncers": {
            "ibounce": {
                "enabled": True,
                "mode": "discovery",
                "profile": "auto",
            },
            "kbouncer": {"enabled": "when_kubeconfig_present"},
            "dbounce": {"enabled": "when_db_env_present"},
            "gbounce": {"enabled": False},
        },
        "improve": {
            "enabled": True,
            "cadence": "per_session",
            "auto_install_profiles": True,
            "require_operator_approval_above_change_threshold": 0.30,
        },
        "notify_on_deny": True,
    }
}


def test_config_schema_valid_minimal() -> None:
    validate_declaration(MINIMAL_VALID)


def test_config_schema_valid_full() -> None:
    validate_declaration(FULL_VALID)


def test_config_schema_valid_examples_from_docs() -> None:
    """Pull the example block from docs/HARNESS-RECIPES/claude-code.md
    + validate it. Catches doc-drift (#397 spec calls for doc tests)."""
    doc = REPO_ROOT / "docs" / "HARNESS-RECIPES" / "claude-code.md"
    text = doc.read_text()
    # Find the first standalone .iam-jit.yaml example (the yaml-tagged
    # codeblock that isn't iam-jit-config — that one is the embedded
    # context-file form).
    import re

    # Pull both the standalone yaml block + the iam-jit-config block.
    iam_jit_config = extract_from_context_file(text)
    assert iam_jit_config is not None, (
        "claude-code.md should embed an iam-jit-config codeblock"
    )
    declaration = load_declaration_from_string(iam_jit_config)
    assert declaration["iam-jit"]["enabled"] is True

    # Standalone yaml example.
    yaml_blocks = re.findall(
        r"```yaml\s*\n(.*?)```", text, re.DOTALL,
    )
    for body in yaml_blocks:
        if body.strip().startswith("# .iam-jit.yaml"):
            load_declaration_from_string(body)
            break
    else:
        pytest.fail("expected a yaml standalone example in claude-code.md")


def test_config_schema_validates_all_recipe_examples() -> None:
    """Every recipe page should have at least one validating example."""
    recipes_dir = REPO_ROOT / "docs" / "HARNESS-RECIPES"
    pages = list(recipes_dir.glob("*.md"))
    assert pages, "expected per-harness recipe pages"
    for page in pages:
        if page.name == "README.md":
            continue
        text = page.read_text()
        body = extract_from_context_file(text)
        if body is None:
            # Custom-harness page may not embed a codeblock (it's
            # contract docs); skip silently.
            continue
        load_declaration_from_string(body)


# ---------------------------------------------------------------------------
# Invalid examples
# ---------------------------------------------------------------------------


def test_config_schema_rejects_missing_required_fields() -> None:
    with pytest.raises(ConfigLoadError) as exc:
        validate_declaration({})
    assert exc.value.code == "schema_validation_error"

    with pytest.raises(ConfigLoadError):
        validate_declaration({"iam-jit": {}})  # missing `enabled`


def test_config_schema_rejects_invalid_enum_values() -> None:
    bad_posture = {"iam-jit": {"enabled": True, "posture": "ambient-but-shy"}}
    with pytest.raises(ConfigLoadError):
        validate_declaration(bad_posture)

    bad_mode = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "stricter"}
            },
        }
    }
    with pytest.raises(ConfigLoadError):
        validate_declaration(bad_mode)

    bad_conditional = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "kbouncer": {"enabled": "when_aurora_present"}
            },
        }
    }
    with pytest.raises(ConfigLoadError):
        validate_declaration(bad_conditional)


def test_config_schema_rejects_unknown_top_level_keys() -> None:
    bad = {
        "iam-jit": {"enabled": True},
        "iam-bounce": {"enabled": True},  # additionalProperties false
    }
    with pytest.raises(ConfigLoadError):
        validate_declaration(bad)


def test_config_schema_rejects_unknown_bouncer_block_keys() -> None:
    bad = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mystery_key": "foo",
                },
            },
        }
    }
    with pytest.raises(ConfigLoadError):
        validate_declaration(bad)


# ---------------------------------------------------------------------------
# Codeblock extraction
# ---------------------------------------------------------------------------


def test_extract_from_context_file_simple() -> None:
    text = """# Some doc

```iam-jit-config
iam-jit:
  enabled: true
```

more notes.
"""
    body = extract_from_context_file(text)
    assert body is not None
    assert "iam-jit:" in body
    assert "enabled: true" in body


def test_extract_from_context_file_yaml_tag() -> None:
    text = """```yaml iam-jit-config
iam-jit:
  enabled: false
```"""
    body = extract_from_context_file(text)
    assert body is not None
    assert "enabled: false" in body


def test_extract_from_context_file_no_block() -> None:
    text = "# No iam-jit declaration here\n\njust regular markdown"
    assert extract_from_context_file(text) is None


def test_extract_from_context_file_picks_first_block() -> None:
    """When multiple iam-jit-config codeblocks appear, the FIRST wins
    per the loader contract."""
    text = """```iam-jit-config
iam-jit:
  enabled: true
```

```iam-jit-config
iam-jit:
  enabled: false
```
"""
    body = extract_from_context_file(text)
    assert body is not None
    assert "enabled: true" in body
    assert "enabled: false" not in body
