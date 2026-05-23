"""#437 / §A71 — tests for the deployment_targets registry.

Pure look-up against an operator-declared `.iam-jit.yaml` block.
No I/O; the registry receives an already-parsed dict.
"""

from __future__ import annotations

import pytest

from iam_jit.deployment_targets import (
    DeploymentTarget,
    DeploymentTargetError,
    list_deployment_targets,
    load_deployment_target,
)


def _declaration(**targets):
    return {
        "iam-jit": {
            "enabled": True,
            "deployment_targets": targets,
        }
    }


def test_load_deployment_target_returns_dataclass() -> None:
    decl = _declaration(**{
        "prod-k8s": {
            "bouncer": "kbouncer",
            "classifier": {
                "clusters": ["prod-east", "prod-west"],
                "accounts": ["999988887777"],
            },
        },
    })
    target = load_deployment_target(decl, "prod-k8s")
    assert isinstance(target, DeploymentTarget)
    assert target.name == "prod-k8s"
    assert target.bouncer == "kbouncer"
    assert target.classifier["clusters"] == ["prod-east", "prod-west"]
    assert target.classifier["accounts"] == ["999988887777"]


def test_load_deployment_target_missing_raises_with_available() -> None:
    decl = _declaration(**{
        "staging-k8s": {
            "bouncer": "kbouncer",
            "classifier": {"clusters": ["staging-*"]},
        },
    })
    with pytest.raises(DeploymentTargetError) as exc_info:
        load_deployment_target(decl, "prod-k8s")
    # The available-list is part of the error message so the agent
    # can re-ask without a second tool call.
    assert "staging-k8s" in str(exc_info.value)
    assert exc_info.value.code == "deployment_target_not_found"


def test_load_deployment_target_no_block_raises() -> None:
    decl = {"iam-jit": {"enabled": True}}
    with pytest.raises(DeploymentTargetError) as exc_info:
        load_deployment_target(decl, "prod-k8s")
    assert exc_info.value.code == "no_deployment_targets"


def test_load_deployment_target_invalid_bouncer_raises() -> None:
    decl = _declaration(**{
        "weird": {"bouncer": "nbounce", "classifier": {}},
    })
    with pytest.raises(DeploymentTargetError) as exc_info:
        load_deployment_target(decl, "weird")
    assert exc_info.value.code == "invalid_deployment_target_bouncer"


def test_schema_deployment_targets_classifier_supports_clusters_accounts_regions_namespaces_hosts() -> None:
    """The classifier accepts every dimension the [[multi-account-
    region-cluster-use-case]] memo enumerates."""
    decl = _declaration(**{
        "everything": {
            "bouncer": "ibounce",
            "classifier": {
                "clusters": ["c-*"],
                "accounts": ["111"],
                "regions": ["us-east-1"],
                "namespaces": ["ns-*"],
                "hosts": ["*.example.com"],
                "databases": ["db-prod"],
            },
        },
    })
    target = load_deployment_target(decl, "everything")
    for dim in (
        "clusters", "accounts", "regions",
        "namespaces", "hosts", "databases",
    ):
        assert dim in target.classifier, dim


def test_list_deployment_targets_sorted_by_name() -> None:
    decl = _declaration(**{
        "prod-k8s": {"bouncer": "kbouncer", "classifier": {"clusters": ["prod-*"]}},
        "staging-k8s": {"bouncer": "kbouncer", "classifier": {"clusters": ["staging-*"]}},
        "dev-k8s": {"bouncer": "kbouncer", "classifier": {"clusters": ["dev-*"]}},
    })
    targets = list_deployment_targets(decl)
    names = [t.name for t in targets]
    assert names == ["dev-k8s", "prod-k8s", "staging-k8s"]


def test_list_deployment_targets_empty_returns_empty_list() -> None:
    decl = {"iam-jit": {"enabled": True}}
    assert list_deployment_targets(decl) == []


def test_schema_deployment_targets_block_valid() -> None:
    """An operator-authored deployment_targets block validates
    against the iam-jit ambient config JSON schema."""
    import jsonschema

    from iam_jit.ambient_config.schema import IAM_JIT_CONFIG_SCHEMA

    decl = _declaration(**{
        "prod-k8s": {
            "bouncer": "kbouncer",
            "description": "production K8s clusters in 3 regions",
            "classifier": {
                "clusters": ["prod-east", "prod-west", "prod-eu"],
                "accounts": ["999988887777"],
                "namespaces": ["api-*", "payments-*", "data-*"],
            },
        },
        "prod-aws": {
            "bouncer": "ibounce",
            "classifier": {
                "accounts": ["999988887777"],
                "regions": ["us-east-1", "us-west-2"],
            },
        },
    })
    # Will raise jsonschema.ValidationError on failure.
    jsonschema.Draft202012Validator(IAM_JIT_CONFIG_SCHEMA).validate(decl)


def test_as_dict_stable_shape_for_classifier_only_consumption() -> None:
    """The agent pipes `as_dict().classifier` into a scope-filter; the
    shape must be the same dict the audit-query CLI accepts."""
    decl = _declaration(**{
        "prod-k8s": {
            "bouncer": "kbouncer",
            "classifier": {
                "clusters": ["prod-east"],
                "accounts": ["999988887777"],
            },
        },
    })
    t = load_deployment_target(decl, "prod-k8s")
    d = t.as_dict()
    assert d["name"] == "prod-k8s"
    assert d["bouncer"] == "kbouncer"
    assert d["classifier"]["clusters"] == ["prod-east"]
    assert d["classifier"]["accounts"] == ["999988887777"]
