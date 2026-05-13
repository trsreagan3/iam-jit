"""Tests for new-account onboarding artifact rendering."""

from __future__ import annotations

import pytest

from iam_jit import onboarding


def test_renders_full_plan_with_defaults() -> None:
    plan = onboarding.render_plan(
        account_id="123456789012",
        hub_account_id="999988887777",
        region="us-east-1",
    )
    d = plan.to_dict()
    assert d["account_id"] == "123456789012"
    assert d["expected"]["provisioner_role_arn"] == (
        "arn:aws:iam::123456789012:role/iam-jit-provisioner"
    )
    assert d["expected"]["provisioner_external_id"] == "iam-jit-123456789012"
    assert d["expected"]["discovery_role_arn"] == (
        "arn:aws:iam::123456789012:role/iam-jit-discovery"
    )
    assert "AWSTemplateFormatVersion" in d["artifacts"]["cloudformation_template"]
    assert "aws cloudformation deploy" in d["artifacts"]["cli_commands"]
    assert "999988887777" in d["artifacts"]["cli_commands"]
    assert "terraform" in d["artifacts"]["terraform_module"].lower()


def test_omits_discovery_when_disabled() -> None:
    plan = onboarding.render_plan(
        account_id="123456789012",
        hub_account_id="999988887777",
        enable_discovery=False,
    )
    d = plan.to_dict()
    assert d["expected"]["discovery_role_arn"] is None
    assert d["expected"]["discovery_external_id"] is None
    assert "discovery_role_arn" not in d["after_deploy"]["register_payload"]


def test_does_not_assume_specific_credential_source() -> None:
    plan = onboarding.render_plan(
        account_id="123456789012",
        hub_account_id="999988887777",
    )
    cli = plan.cli_commands
    # The deploy commands themselves must not pin a specific auth method.
    # They are allowed to be MENTIONED as options in the prereq comments.
    deploy_lines = [
        line for line in cli.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    deploy_text = "\n".join(deploy_lines)
    assert "aws sso login" not in deploy_text
    assert "aws-vault" not in deploy_text
    # Prereq comment should hint at the requirement rather than picking a method.
    assert "credentials" in cli.lower()
    assert "named profile" in cli.lower() or "AWS_PROFILE" in cli


def test_register_curl_uses_configured_public_url() -> None:
    plan = onboarding.render_plan(
        account_id="123456789012",
        hub_account_id="999988887777",
        public_url="https://iam-jit.internal.example.com",
    )
    assert "https://iam-jit.internal.example.com/api/v1/accounts" in plan.register_curl
    assert "Bearer <your-iam-jit-admin-token>" in plan.register_curl


def test_rejects_bad_account_id() -> None:
    with pytest.raises(ValueError, match="12-digit"):
        onboarding.render_plan(account_id="123", hub_account_id="999988887777")


def test_rejects_unknown_provisioning_mode() -> None:
    with pytest.raises(ValueError, match="provisioning_mode"):
        onboarding.render_plan(
            account_id="123456789012",
            hub_account_id="999988887777",
            provisioning_mode="bogus",
        )


def test_identity_center_mode_includes_permission_sets() -> None:
    plan = onboarding.render_plan(
        account_id="123456789012",
        hub_account_id="999988887777",
        provisioning_mode="identity_center",
        allowed_permission_set_arns=[
            "arn:aws:sso:::permissionSet/ssoins-abc/ps-1",
            "arn:aws:sso:::permissionSet/ssoins-abc/ps-2",
        ],
    )
    assert "ssoins-abc/ps-1" in plan.cli_commands
    assert "ssoins-abc/ps-2" in plan.terraform_module
