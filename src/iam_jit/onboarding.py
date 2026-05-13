"""Account onboarding artifacts.

iam-jit cannot bootstrap itself into a new AWS account — that would
require pre-existing privileged access in that account, which is the
problem we're trying to avoid. Instead, this module produces the exact
artifacts a human (or an agent acting on a human's behalf) needs to
execute themselves:

  - the CloudFormation template, parameterized with the hub account ID
    and any naming overrides, ready to `aws cloudformation deploy`
  - the equivalent Terraform module skeleton, for shops that prefer it
  - the CLI commands to deploy, with the exact parameter values
  - the post-deploy registration call (POST /api/v1/accounts) with the
    role ARNs and ExternalIds that the deploy emits as outputs

The renderer takes nothing from AWS — it only reads the static template
file shipped with the repo and substitutes parameter values. Even if
iam-jit had no AWS credentials at all, this endpoint would still work.
"""

from __future__ import annotations

import os
import pathlib
import textwrap
from dataclasses import dataclass
from typing import Any

from . import _resources

_CFN_TEMPLATE_PATH = _resources.find(
    "infrastructure", "cloudformation", "destination-account-roles.yaml"
)


@dataclass(frozen=True)
class OnboardingPlan:
    account_id: str
    account_alias: str | None
    region: str
    hub_account_id: str
    hub_lambda_role_name: str
    provisioner_role_name: str
    discovery_role_name: str
    enable_discovery: bool
    provisioning_mode: str  # "classic_iam" | "identity_center" | "both"
    allowed_permission_set_arns: list[str]
    cfn_template: str
    cli_commands: str
    terraform_module: str
    expected_provisioner_role_arn: str
    expected_discovery_role_arn: str | None
    expected_provisioner_external_id: str
    expected_discovery_external_id: str | None
    register_payload: dict[str, Any]
    register_curl: str
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "account_alias": self.account_alias,
            "region": self.region,
            "hub_account_id": self.hub_account_id,
            "provisioning_mode": self.provisioning_mode,
            "enable_discovery": self.enable_discovery,
            "expected": {
                "provisioner_role_arn": self.expected_provisioner_role_arn,
                "discovery_role_arn": self.expected_discovery_role_arn,
                "provisioner_external_id": self.expected_provisioner_external_id,
                "discovery_external_id": self.expected_discovery_external_id,
            },
            "artifacts": {
                "cloudformation_template": self.cfn_template,
                "terraform_module": self.terraform_module,
                "cli_commands": self.cli_commands,
            },
            "after_deploy": {
                "register_payload": self.register_payload,
                "register_curl": self.register_curl,
            },
            "notes": self.notes,
        }


def _validate_account_id(account_id: str) -> None:
    if not (account_id.isdigit() and len(account_id) == 12):
        raise ValueError("account_id must be a 12-digit AWS account id")


def _read_cfn_template() -> str:
    return _CFN_TEMPLATE_PATH.read_text()


def render_plan(
    *,
    account_id: str,
    region: str = "us-east-1",
    account_alias: str | None = None,
    hub_account_id: str | None = None,
    hub_lambda_role_name: str = "iam-jit-lambda-execution",
    provisioner_role_name: str = "iam-jit-provisioner",
    discovery_role_name: str = "iam-jit-discovery",
    enable_discovery: bool = True,
    provisioning_mode: str = "classic_iam",
    allowed_permission_set_arns: list[str] | None = None,
    public_url: str | None = None,
) -> OnboardingPlan:
    """Build the full onboarding artifact set for a new destination account.

    `hub_account_id` and `public_url` default to the deployment-level env
    vars (`IAM_JIT_HUB_ACCOUNT_ID`, `IAM_JIT_PUBLIC_URL`) so a typical
    caller doesn't need to pass them. They can be overridden for tests or
    for cross-installation tooling.
    """
    _validate_account_id(account_id)
    if provisioning_mode not in {"classic_iam", "identity_center", "both"}:
        raise ValueError(f"unknown provisioning_mode: {provisioning_mode!r}")
    hub_account_id = hub_account_id or os.environ.get("IAM_JIT_HUB_ACCOUNT_ID") or ""
    if hub_account_id and not (hub_account_id.isdigit() and len(hub_account_id) == 12):
        raise ValueError("hub_account_id must be a 12-digit AWS account id")
    public_url = public_url or os.environ.get("IAM_JIT_PUBLIC_URL") or "https://iam-jit.example.com"
    permission_sets = allowed_permission_set_arns or [
        "arn:aws:sso:::permissionSet/CONFIGURE-WHEN-USING-IDENTITY-CENTER"
    ]

    cfn_template = _read_cfn_template()

    stack_name = f"iam-jit-roles-{account_alias or account_id}"
    enable_discovery_yn = "Yes" if enable_discovery else "No"
    perm_set_param = ",".join(permission_sets)

    cli_commands = _render_cli(
        stack_name=stack_name,
        account_id=account_id,
        region=region,
        hub_account_id=hub_account_id,
        hub_lambda_role_name=hub_lambda_role_name,
        provisioner_role_name=provisioner_role_name,
        discovery_role_name=discovery_role_name,
        enable_discovery=enable_discovery_yn,
        provisioning_mode=provisioning_mode,
        allowed_permission_set_arns=perm_set_param,
    )

    terraform_module = _render_terraform(
        account_id=account_id,
        hub_account_id=hub_account_id,
        hub_lambda_role_name=hub_lambda_role_name,
        provisioner_role_name=provisioner_role_name,
        discovery_role_name=discovery_role_name,
        enable_discovery=enable_discovery,
        provisioning_mode=provisioning_mode,
        permission_sets=permission_sets,
    )

    expected_provisioner_arn = (
        f"arn:aws:iam::{account_id}:role/{provisioner_role_name}"
    )
    expected_discovery_arn = (
        f"arn:aws:iam::{account_id}:role/{discovery_role_name}"
        if enable_discovery
        else None
    )
    expected_prov_eid = f"iam-jit-{account_id}"
    expected_disc_eid = f"iam-jit-discovery-{account_id}" if enable_discovery else None

    register_payload: dict[str, Any] = {
        "account_id": account_id,
        "alias": account_alias,
        "regions": [region],
        "provisioner_role_arn": expected_provisioner_arn,
        "provisioner_external_id": expected_prov_eid,
        "provisioning_mode": provisioning_mode,
    }
    if enable_discovery:
        register_payload["discovery_role_arn"] = expected_discovery_arn
        register_payload["discovery_external_id"] = expected_disc_eid

    register_curl = _render_register_curl(public_url, register_payload)

    notes = textwrap.dedent(
        f"""\
        - Run the CloudFormation deploy in the destination account ({account_id}),
          using a session that has CloudFormation + IAM CreateRole privileges in
          THAT account. iam-jit itself never holds those privileges.
        - The stack creates the trust policies that allow the iam-jit Lambda
          (running in account {hub_account_id or '<HUB_ACCOUNT_ID>'}) to assume
          ProvisionerRole — and only that — using ExternalId
          '{expected_prov_eid}'. ExternalId is enforced by the trust policy.
        - After the stack is CREATE_COMPLETE, hit the registration endpoint
          shown below (or use the MCP `register_account` tool) so iam-jit
          starts treating this account as a valid destination. The expected
          ARNs above match the stack outputs; verify them before registering.
        - To remove an account, delete the CloudFormation stack and call
          DELETE /api/v1/accounts/{account_id}.
        """
    )

    return OnboardingPlan(
        account_id=account_id,
        account_alias=account_alias,
        region=region,
        hub_account_id=hub_account_id,
        hub_lambda_role_name=hub_lambda_role_name,
        provisioner_role_name=provisioner_role_name,
        discovery_role_name=discovery_role_name,
        enable_discovery=enable_discovery,
        provisioning_mode=provisioning_mode,
        allowed_permission_set_arns=permission_sets,
        cfn_template=cfn_template,
        cli_commands=cli_commands,
        terraform_module=terraform_module,
        expected_provisioner_role_arn=expected_provisioner_arn,
        expected_discovery_role_arn=expected_discovery_arn,
        expected_provisioner_external_id=expected_prov_eid,
        expected_discovery_external_id=expected_disc_eid,
        register_payload=register_payload,
        register_curl=register_curl,
        notes=notes.strip(),
    )


def _render_cli(
    *,
    stack_name: str,
    account_id: str,
    region: str,
    hub_account_id: str,
    hub_lambda_role_name: str,
    provisioner_role_name: str,
    discovery_role_name: str,
    enable_discovery: str,
    provisioning_mode: str,
    allowed_permission_set_arns: str,
) -> str:
    hub_placeholder = hub_account_id or "<HUB_ACCOUNT_ID>"
    return textwrap.dedent(
        f"""\
        # PREREQ: have AWS credentials for the DESTINATION account ({account_id})
        # available to your shell. Source them however you normally do — static
        # keys via env vars, a named profile, SSO, OIDC, instance role,
        # container credentials, an assumed role, aws-vault, etc. The commands
        # below take no position on which; just make sure the calling identity
        # has CloudFormation + IAM CreateRole/PutRolePolicy in {account_id}.
        # iam-jit itself never holds credentials there.
        #
        # If you use named profiles, prefix each `aws` call with
        # `--profile <your-profile>` (or set AWS_PROFILE in your shell).

        # 1. Save the CloudFormation template (the API also returns it inline
        #    as `artifacts.cloudformation_template`):
        curl -fsS https://raw.githubusercontent.com/your-org/iam-jit/main/infrastructure/cloudformation/destination-account-roles.yaml \\
          -o /tmp/iam-jit-roles.yaml

        # 2. Deploy the stack into account {account_id}:
        aws cloudformation deploy \\
          --region {region} \\
          --stack-name {stack_name} \\
          --template-file /tmp/iam-jit-roles.yaml \\
          --capabilities CAPABILITY_NAMED_IAM \\
          --parameter-overrides \\
            HubAccountId={hub_placeholder} \\
            HubLambdaRoleName={hub_lambda_role_name} \\
            ProvisionerRoleName={provisioner_role_name} \\
            DiscoveryRoleName={discovery_role_name} \\
            EnableDiscovery={enable_discovery} \\
            ProvisioningMode={provisioning_mode} \\
            AllowedPermissionSetArns='{allowed_permission_set_arns}'

        # 3. Verify the outputs match the expected ARNs in this plan:
        aws cloudformation describe-stacks \\
          --region {region} \\
          --stack-name {stack_name} \\
          --query 'Stacks[0].Outputs'

        # 4. Register the account with iam-jit (see `after_deploy.register_curl`).
        """
    ).strip()


def _render_terraform(
    *,
    account_id: str,
    hub_account_id: str,
    hub_lambda_role_name: str,
    provisioner_role_name: str,
    discovery_role_name: str,
    enable_discovery: bool,
    provisioning_mode: str,
    permission_sets: list[str],
) -> str:
    """Skeleton Terraform that mirrors the CFN. Hand-rolled rather than
    auto-generated because Terraform users typically integrate this into a
    larger module — we ship the minimum that compiles."""
    hub_placeholder = hub_account_id or "<HUB_ACCOUNT_ID>"
    perm_sets_hcl = "[\n    " + ",\n    ".join(f'"{p}"' for p in permission_sets) + "\n  ]"
    discovery_block = ""
    if enable_discovery:
        discovery_block = textwrap.dedent(
            f"""\

            resource "aws_iam_role" "discovery" {{
              name               = "{discovery_role_name}"
              assume_role_policy = data.aws_iam_policy_document.discovery_trust.json
              tags = {{
                "managed-by" = "iam-jit"
                "purpose"    = "discovery"
              }}
            }}

            data "aws_iam_policy_document" "discovery_trust" {{
              statement {{
                actions = ["sts:AssumeRole"]
                principals {{
                  type        = "AWS"
                  identifiers = ["arn:aws:iam::{hub_placeholder}:role/{hub_lambda_role_name}"]
                }}
                condition {{
                  test     = "StringEquals"
                  variable = "sts:ExternalId"
                  values   = ["iam-jit-discovery-{account_id}"]
                }}
              }}
            }}

            resource "aws_iam_role_policy_attachment" "discovery_readonly" {{
              role       = aws_iam_role.discovery.name
              policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
            }}
            """
        )
    return textwrap.dedent(
        f"""\
        # iam-jit per-destination roles (Terraform port of the CFN template).
        # This is a starting point — adapt to your module conventions.
        # Apply in account {account_id}.

        terraform {{
          required_providers {{
            aws = {{ source = "hashicorp/aws", version = "~> 5.0" }}
          }}
        }}

        locals {{
          hub_account_id        = "{hub_placeholder}"
          hub_lambda_role_name  = "{hub_lambda_role_name}"
          provisioning_mode     = "{provisioning_mode}"
          allowed_permission_set_arns = {perm_sets_hcl}
        }}

        resource "aws_iam_role" "provisioner" {{
          name               = "{provisioner_role_name}"
          assume_role_policy = data.aws_iam_policy_document.provisioner_trust.json
          tags = {{
            "managed-by" = "iam-jit"
            "purpose"    = "provisioner"
          }}
        }}

        data "aws_iam_policy_document" "provisioner_trust" {{
          statement {{
            actions = ["sts:AssumeRole"]
            principals {{
              type        = "AWS"
              identifiers = ["arn:aws:iam::${{local.hub_account_id}}:role/${{local.hub_lambda_role_name}}"]
            }}
            condition {{
              test     = "StringEquals"
              variable = "sts:ExternalId"
              values   = ["iam-jit-{account_id}"]
            }}
          }}
        }}

        # NOTE: the inline policies (classic-iam-grants, identity-center-grants)
        # follow the exact statements in the CFN template under Resources.
        # Copy them into aws_iam_role_policy resources here, gated on
        # local.provisioning_mode. The CFN file is the canonical source.
        {discovery_block}
        """
    ).strip()


def _render_register_curl(public_url: str, payload: dict[str, Any]) -> str:
    import json as _json

    body = _json.dumps(payload, indent=2)
    return textwrap.dedent(
        f"""\
        curl -fsS -X POST '{public_url.rstrip("/")}/api/v1/accounts' \\
          -H 'Authorization: Bearer <your-iam-jit-admin-token>' \\
          -H 'Content-Type: application/json' \\
          -d '{body}'
        """
    ).strip()
