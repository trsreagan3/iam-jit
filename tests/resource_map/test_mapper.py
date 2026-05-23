"""#420 / §A59 — tests for resource_map.mapper.

Covers the declarative substitution rules consumed by `iam-jit
resource-map` + `iam_jit_resource_map` MCP tool.
"""

from __future__ import annotations

import pytest

from iam_jit.resource_map import (
    ResourceMapping,
    apply_resource_mapping,
    apply_resource_mapping_to_permissions,
    list_mappings_in_config,
    load_mapping_from_config,
    map_observed_scope,
)


def _staging_to_prod() -> ResourceMapping:
    return ResourceMapping.from_dict(
        "staging_to_prod",
        {
            "account_id": {"111122223333": "999988887777"},
            "region": {"us-east-1": "us-west-2"},
            "name_patterns": [
                {"match": "staging-*", "replace": "prod-*"},
                {"match": "*-dev", "replace": "*-prod"},
            ],
        },
    )


def test_resource_map_account_id_substitution() -> None:
    mapping = _staging_to_prod()
    arn = "arn:aws:s3:us-east-1:111122223333:bucket/key"
    out = apply_resource_mapping(arn, mapping)
    # account swapped + region swapped + name patterns don't apply to "bucket/key".
    assert "999988887777" in out
    assert "111122223333" not in out


def test_resource_map_region_substitution() -> None:
    mapping = _staging_to_prod()
    arn = "arn:aws:lambda:us-east-1:111122223333:function:staging-lambda-1"
    out = apply_resource_mapping(arn, mapping)
    assert "us-west-2" in out
    assert "us-east-1" not in out
    # Name pattern flipped staging- → prod-.
    assert "prod-lambda-1" in out


def test_resource_map_name_pattern_glob() -> None:
    mapping = _staging_to_prod()
    assert apply_resource_mapping("staging-cache-bucket", mapping) == "prod-cache-bucket"
    assert apply_resource_mapping("mysvc-dev", mapping) == "mysvc-prod"
    # Non-matching name should pass through unchanged.
    assert apply_resource_mapping("totally-unrelated", mapping) == "totally-unrelated"


def test_resource_map_name_pattern_first_match_wins() -> None:
    """Order in name_patterns controls precedence."""
    mapping = ResourceMapping.from_dict(
        "test",
        {
            "name_patterns": [
                {"match": "staging-*", "replace": "FIRST-*"},
                {"match": "staging-cache-*", "replace": "SECOND-*"},
            ],
        },
    )
    # The broader pattern is listed first; it wins.
    assert apply_resource_mapping("staging-cache-foo", mapping) == "FIRST-cache-foo"


def test_resource_map_preserves_observed_scope() -> None:
    mapping = _staging_to_prod()
    perms_doc = {
        "time_window": {"from": "X", "to": "Y"},
        "bouncer": "ibounce",
        "events_analyzed": 5,
        "permissions": [
            {
                "action": "s3:GetObject",
                "resources": [
                    "arn:aws:s3:us-east-1:111122223333:bucket/key",
                    "arn:aws:s3:::staging-cache-2026/k",
                ],
                "count": 3,
            },
            {
                "action": "lambda:UpdateFunctionCode",
                "resources": [
                    "arn:aws:lambda:us-east-1:111122223333:function:staging-foo",
                ],
                "count": 1,
            },
        ],
        "observed_scope": {
            "account_ids": ["111122223333"],
            "regions": ["us-east-1"],
        },
    }
    out = apply_resource_mapping_to_permissions(perms_doc, mapping)
    # observed_scope translated.
    assert out["observed_scope"]["account_ids"] == ["999988887777"]
    assert out["observed_scope"]["regions"] == ["us-west-2"]
    # Mapping name embedded in result.
    assert out["resource_mapping_applied"] == "staging_to_prod"
    # Permission actions unchanged; resources translated.
    actions = [p["action"] for p in out["permissions"]]
    assert "s3:GetObject" in actions
    assert "lambda:UpdateFunctionCode" in actions
    s3 = next(p for p in out["permissions"] if p["action"] == "s3:GetObject")
    # us-east-1 + 111122223333 replaced; staging- → prod- pattern hits second resource.
    assert any("999988887777" in r for r in s3["resources"])
    assert any("us-west-2" in r for r in s3["resources"])
    assert any("prod-cache-2026" in r for r in s3["resources"])
    # Time window + count preserved.
    assert out["time_window"] == perms_doc["time_window"]
    s3_count = next(p for p in out["permissions"] if p["action"] == "s3:GetObject")["count"]
    assert s3_count == 3


def test_resource_map_observed_scope_with_unknown_account_passes_through() -> None:
    mapping = _staging_to_prod()
    scope = {
        "account_ids": ["111122223333", "555555555555"],
        "regions": ["us-east-1", "eu-west-1"],
    }
    out = map_observed_scope(scope, mapping)
    # Mapped accounts substituted; unmapped pass through.
    assert "999988887777" in out["account_ids"]
    assert "555555555555" in out["account_ids"]
    # Regions same idea.
    assert "us-west-2" in out["regions"]
    assert "eu-west-1" in out["regions"]


def test_resource_map_pseudo_arn_falls_back_to_name_pattern() -> None:
    """Non-ARN strings (e.g. hostnames from dbouncer/gbouncer) are still
    name_patterns-substituted."""
    mapping = _staging_to_prod()
    assert apply_resource_mapping("staging-host.example.com", mapping) == (
        "prod-host.example.com"
    )


def test_resource_map_rejects_malformed_account_block() -> None:
    with pytest.raises(ValueError, match="account_id"):
        ResourceMapping.from_dict("bad", {"account_id": "not-a-map"})


def test_resource_map_rejects_malformed_name_patterns() -> None:
    with pytest.raises(ValueError, match="name_patterns"):
        ResourceMapping.from_dict("bad", {"name_patterns": "not-a-list"})


def test_resource_map_rejects_malformed_pattern_entry() -> None:
    with pytest.raises(ValueError, match="name_patterns"):
        ResourceMapping.from_dict(
            "bad",
            {"name_patterns": [{"match": 1, "replace": "x"}]},
        )


def test_schema_resource_mappings_block_valid() -> None:
    """The ambient_config schema accepts the resource_mappings block."""
    import jsonschema
    from iam_jit.ambient_config.schema import IAM_JIT_CONFIG_SCHEMA

    valid = {
        "iam-jit": {
            "enabled": True,
            "resource_mappings": {
                "staging_to_prod": {
                    "account_id": {"111122223333": "999988887777"},
                    "region": {"us-east-1": "us-west-2"},
                    "name_patterns": [
                        {"match": "staging-*", "replace": "prod-*"},
                    ],
                },
            },
        }
    }
    # Should not raise.
    jsonschema.Draft202012Validator(IAM_JIT_CONFIG_SCHEMA).validate(valid)

    # Invalid: name_patterns entries missing required keys.
    invalid = {
        "iam-jit": {
            "enabled": True,
            "resource_mappings": {
                "broken": {
                    "name_patterns": [{"match": "x"}],  # missing replace
                },
            },
        }
    }
    errors = list(
        jsonschema.Draft202012Validator(IAM_JIT_CONFIG_SCHEMA).iter_errors(invalid)
    )
    assert errors, "name_patterns entry missing `replace` must fail"


def test_schema_resource_mappings_rejects_unknown_fields() -> None:
    """additionalProperties: false on the mapping block."""
    import jsonschema
    from iam_jit.ambient_config.schema import IAM_JIT_CONFIG_SCHEMA

    invalid = {
        "iam-jit": {
            "enabled": True,
            "resource_mappings": {
                "bad": {
                    "account_id": {"a": "b"},
                    "totally_made_up_field": True,
                },
            },
        }
    }
    errors = list(
        jsonschema.Draft202012Validator(IAM_JIT_CONFIG_SCHEMA).iter_errors(invalid)
    )
    assert errors, "unknown field on the mapping block must fail"


def test_load_mapping_from_config_missing_raises_with_available() -> None:
    declaration = {
        "iam-jit": {
            "enabled": True,
            "resource_mappings": {"staging_to_prod": {"account_id": {"a": "b"}}},
        }
    }
    assert list_mappings_in_config(declaration) == ["staging_to_prod"]
    with pytest.raises(KeyError, match="missing_mapping"):
        load_mapping_from_config(declaration, "missing_mapping")


def test_mcp_tool_iam_jit_resource_map_returns_transformed(tmp_path) -> None:
    """The MCP wrapper loads the operator config + applies the mapping
    end-to-end."""
    from iam_jit.mcp_server import _iam_jit_resource_map_for_mcp

    config_path = tmp_path / ".iam-jit.yaml"
    config_path.write_text(
        """
iam-jit:
  enabled: true
  resource_mappings:
    staging_to_prod:
      account_id: { "111122223333": "999988887777" }
      region: { "us-east-1": "us-west-2" }
      name_patterns:
        - { match: "staging-*", replace: "prod-*" }
""".strip(),
    )
    perms_doc = {
        "time_window": {"from": "X", "to": "Y"},
        "bouncer": "ibounce",
        "events_analyzed": 1,
        "permissions": [
            {
                "action": "s3:GetObject",
                "resources": ["arn:aws:s3:us-east-1:111122223333:b/k"],
                "count": 1,
            },
        ],
        "observed_scope": {
            "account_ids": ["111122223333"],
            "regions": ["us-east-1"],
        },
    }
    result = _iam_jit_resource_map_for_mcp({
        "permissions": perms_doc,
        "using": "staging_to_prod",
        "config_path": str(config_path),
    })
    assert result["status"] == "ok"
    assert result["resource_mapping_applied"] == "staging_to_prod"
    assert result["observed_scope"]["account_ids"] == ["999988887777"]
    assert result["observed_scope"]["regions"] == ["us-west-2"]
    r = result["permissions"][0]["resources"][0]
    assert "999988887777" in r
    assert "us-west-2" in r


def test_mcp_tool_iam_jit_resource_map_missing_using() -> None:
    from iam_jit.mcp_server import _iam_jit_resource_map_for_mcp
    result = _iam_jit_resource_map_for_mcp({"permissions": {"permissions": []}})
    assert result["status"] == "error"
    assert result["code"] == "missing_using"


def test_mcp_tool_iam_jit_resource_map_missing_permissions() -> None:
    from iam_jit.mcp_server import _iam_jit_resource_map_for_mcp
    result = _iam_jit_resource_map_for_mcp({"using": "x"})
    assert result["status"] == "error"
    assert result["code"] == "invalid_permissions"
