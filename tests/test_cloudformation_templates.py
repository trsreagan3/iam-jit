"""Structural tests for the destination-account CloudFormation template.

Pre-2026-05-24 this file also covered the hosted SAM template
(`infrastructure/sam/template.yaml`) — that template was deleted
when the hosted iam-risk-score Lambda was dropped per
[[no-hosted-saas]] restoration. The destination-account roles
template stays because operators still deploy it into their own
AWS accounts when running the self-host suite.

These tests do NOT call AWS. They parse the YAML with a custom loader
that ignores CFN intrinsic tags (`!Ref`, `!Sub`, `!Equals`, etc.) and
walk the resulting Python dict. For a deeper structural check the
operator can additionally run `cfn-lint` locally — these tests are
the always-on minimum.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
import yaml


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_DESTINATION_TEMPLATE = (
    _REPO_ROOT / "infrastructure" / "cloudformation"
    / "destination-account-roles.yaml"
)


def _load_cfn(path: pathlib.Path) -> dict[str, Any]:
    """Parse a CFN template YAML, ignoring intrinsic tags so the
    structural shape is inspectable as plain Python dicts."""
    class _CFNLoader(yaml.SafeLoader):
        pass

    def _ignore(loader: yaml.Loader, tag_suffix: str, node: Any) -> Any:
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        return None

    _CFNLoader.add_multi_constructor("!", _ignore)
    with path.open() as f:
        return yaml.load(f, Loader=_CFNLoader)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Destination-account template
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def destination_template() -> dict[str, Any]:
    return _load_cfn(_DESTINATION_TEMPLATE)


def test_destination_template_provisioner_role_exists(
    destination_template: dict[str, Any],
) -> None:
    res = destination_template["Resources"]
    assert "ProvisionerRole" in res
    assert res["ProvisionerRole"]["Type"] == "AWS::IAM::Role"


def test_destination_template_provisioner_external_id_required(
    destination_template: dict[str, Any],
) -> None:
    """Trust policy must require sts:ExternalId — defense against
    confused-deputy if the hub Lambda role is ever compromised."""
    role = destination_template["Resources"]["ProvisionerRole"]["Properties"]
    statements = role["AssumeRolePolicyDocument"]["Statement"]
    found = any(
        "sts:ExternalId" in (s.get("Condition") or {}).get("StringEquals", {})
        for s in statements
    )
    assert found, "ProvisionerRole trust policy is missing sts:ExternalId"


def test_destination_template_classic_iam_policy_is_path_scoped(
    destination_template: dict[str, Any],
) -> None:
    """iam:CreateRole / DeleteRole / etc. must be scoped to the
    `/iam-jit/*` path so the role can't touch unrelated IAM
    resources."""
    res = destination_template["Resources"]
    policy = res.get("ProvisionerClassicIAMPolicy") or {}
    statements = (
        policy.get("Properties", {})
        .get("PolicyDocument", {})
        .get("Statement", [])
    )
    iam_modify_actions = {
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:DeleteRole",
        "iam:DeleteRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListRoleTags",
        "iam:TagRole",
    }
    for stmt in statements:
        actions = stmt.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        # Only check statements that touch IAM mutation. The ReadIAMState
        # block uses Resource=* and that's intentional.
        if any(a in iam_modify_actions for a in actions) and stmt.get("Sid") != "ReadIAMState":
            resource = stmt.get("Resource")
            resource_str = resource if isinstance(resource, str) else str(resource)
            assert "/iam-jit/" in resource_str, (
                f"statement {stmt.get('Sid')} is not path-scoped to "
                f"/iam-jit/: resource={resource}"
            )


def test_destination_template_create_role_requires_managed_by_tag(
    destination_template: dict[str, Any],
) -> None:
    """At creation time, role must already carry managed-by=iam-jit."""
    res = destination_template["Resources"]
    statements = (
        res["ProvisionerClassicIAMPolicy"]["Properties"]
        ["PolicyDocument"]["Statement"]
    )
    create_stmt = next(
        s for s in statements if s.get("Sid") == "CreateOnlyTaggedRoles"
    )
    cond = create_stmt["Condition"]
    assert cond["StringEquals"]["aws:RequestTag/managed-by"] == "iam-jit"


def test_destination_template_modify_only_managed_by_tag(
    destination_template: dict[str, Any],
) -> None:
    """Modify operations require the role to already have the tag."""
    res = destination_template["Resources"]
    statements = (
        res["ProvisionerClassicIAMPolicy"]["Properties"]
        ["PolicyDocument"]["Statement"]
    )
    modify_stmt = next(
        s for s in statements if s.get("Sid") == "ModifyOnlyTaggedRoles"
    )
    cond = modify_stmt["Condition"]
    assert cond["StringEquals"]["aws:ResourceTag/managed-by"] == "iam-jit"


def test_destination_template_allowed_tag_keys_match_provision_module(
    destination_template: dict[str, Any],
) -> None:
    """The CFN ForAllValues:StringEquals on aws:TagKeys must include
    every key the provision module emits (otherwise create_role fails
    with `AccessDenied: tag key not allowed`)."""
    from iam_jit.provision import _build_tags

    expected_keys = set(
        _build_tags(
            request_id="rq-x",
            requester_email="dev@example.com",
            approver_id="email:approver@example.com",
            expires_at="2030-01-01T00:00:00Z",
            provisioned_at="2026-01-01T00:00:00Z",
            access_type="read-only",
        ).keys()
    )

    res = destination_template["Resources"]
    statements = (
        res["ProvisionerClassicIAMPolicy"]["Properties"]
        ["PolicyDocument"]["Statement"]
    )
    create_stmt = next(
        s for s in statements if s.get("Sid") == "CreateOnlyTaggedRoles"
    )
    cond = create_stmt["Condition"]
    allowed_keys = set(
        cond["ForAllValues:StringEquals"]["aws:TagKeys"]
    )

    missing = expected_keys - allowed_keys
    assert not missing, (
        f"provision._build_tags emits tag keys not allowed by the "
        f"destination ProvisionerRole policy: {sorted(missing)}. "
        f"Update the CFN template's ForAllValues list."
    )


def test_destination_template_outputs_provisioner_arn(
    destination_template: dict[str, Any],
) -> None:
    outs = destination_template["Outputs"]
    assert "ProvisionerRoleArn" in outs
    assert "ProvisionerExternalId" in outs


def test_destination_template_does_not_grant_iam_passrole(
    destination_template: dict[str, Any],
) -> None:
    """iam:PassRole would let the provisioner attach itself elsewhere
    — verify it's not anywhere in the policy."""
    import json as _json

    text = _json.dumps(destination_template["Resources"])
    assert "iam:PassRole" not in text, (
        "destination ProvisionerRole has iam:PassRole — that breaks the "
        "scoping invariant"
    )
