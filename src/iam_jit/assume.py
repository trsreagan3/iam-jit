"""Assume-role instruction rendering.

Two pieces are needed for a principal to successfully assume a role:

  1. The TARGET role's trust policy must allow that principal —
     handled by `provision.py` when it creates the role.
  2. The CALLING principal must itself have `sts:AssumeRole` permission
     on the target role's ARN. AWS evaluates both sides; missing either
     fails with `AccessDenied`.

Most teams set up (2) once via a permission set or attached policy and
forget about it. But for fresh principals (new IAM user, new CI runner
role, ad-hoc identities), the assumer-side policy is missing and the
JIT grant looks broken even though the role exists.

This module renders the assumer-side artifact too: the JSON policy
plus the appropriate CLI command for the assumer's identity type
(IAM user, IAM role, SSO/IdC). We do NOT auto-apply — cross-account
permissions + identity-type complexity make that a per-deploy
decision. The CLI command is copy-paste ready instead.

The principal that will assume the role can be inferred from the
requester's login (when iam-jit is using `aws_iam` auth, the SigV4 caller
is captured into `metadata.requester.principal_arn`). For local
magic-link auth, or whenever the requester wants to assume the role from
a *different* identity (CI runner role, a colleague's machine, etc.), the
submission can override it via `spec.assume_by.principal_arn`.

Resolution order, highest priority first:
  1. `spec.assume_by.principal_arn` (explicit override)
  2. `metadata.requester.principal_arn` (inferred from login)
  3. None — caller must prompt the user before rendering instructions
"""

from __future__ import annotations

import json
import re
import textwrap
from typing import Any
from urllib.parse import quote


_IAM_USER_ARN = re.compile(r"^arn:aws[a-z-]*:iam::([0-9]{12}):user/(.+)$")
_IAM_ROLE_ARN = re.compile(r"^arn:aws[a-z-]*:iam::([0-9]{12}):role/(.+)$")
_STS_ASSUMED_ROLE = re.compile(
    r"^arn:aws[a-z-]*:sts::([0-9]{12}):assumed-role/([^/]+)/(.+)$"
)
_SSO_ROLE = re.compile(
    r"^arn:aws[a-z-]*:iam::([0-9]{12}):role/aws-reserved/sso\.amazonaws\.com/.*?(AWSReservedSSO_[^/]+)$"
)


def render_assumer_grant(
    assumer_arn: str, target_role_arn: str
) -> dict[str, Any]:
    """Build the assumer-side artifact: the JSON policy that grants
    `sts:AssumeRole` on `target_role_arn`, plus the CLI command to
    attach it (when the assumer's identity type supports a direct
    attach), plus human-facing notes.

    Returns:
      {
        "policy_json": "{...}",          # ready to put into a file
        "cli_command": "aws iam put-user-policy ... | aws iam put-role-policy ... | None"
        "applies_to": "user" | "role" | "sso" | "assumed-role" | "unknown",
        "notes": "..."                   # human-readable explanation
      }
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAssumeIamJitGrant",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": target_role_arn,
            }
        ],
    }
    policy_json = json.dumps(policy, indent=2)

    user_match = _IAM_USER_ARN.match(assumer_arn)
    role_match = _IAM_ROLE_ARN.match(assumer_arn)
    sso_match = _SSO_ROLE.match(assumer_arn)
    assumed_match = _STS_ASSUMED_ROLE.match(assumer_arn)

    cli_command: str | None = None
    applies_to = "unknown"
    notes = ""

    flat_policy = json.dumps(policy, separators=(",", ":"))

    if sso_match:
        # SSO/Identity Center — the user can't directly attach; their
        # admin needs to update the permission set or its inline policy.
        applies_to = "sso"
        permset_name = sso_match.group(2).removeprefix("AWSReservedSSO_")
        # Strip any trailing _<random> suffix if present
        notes = (
            f"This is an AWS Identity Center (SSO) role: {assumer_arn}. "
            f"Direct iam:Put*Policy doesn't apply — your IAM/IdC admin "
            f"needs to add the policy below to the permission set "
            f"'{permset_name}' (Inline policy → Edit → paste). After saving, "
            "re-provision the SSO permission set in this account so the "
            "underlying IAM role picks up the inline policy."
        )
    elif user_match:
        applies_to = "user"
        user_name = user_match.group(2)
        cli_command = (
            f"aws iam put-user-policy "
            f"--user-name {user_name} "
            f"--policy-name iam-jit-assume-grant "
            f"--policy-document '{flat_policy}'"
        )
        notes = (
            f"Run this command with credentials for the assumer's account "
            f"({user_match.group(1)}) and `iam:PutUserPolicy` on user "
            f"'{user_name}'. Already-attached AssumeRole policies aren't "
            "overwritten — this adds an inline policy named "
            "'iam-jit-assume-grant'. Delete with "
            f"`aws iam delete-user-policy --user-name {user_name} "
            "--policy-name iam-jit-assume-grant` once the grant is no "
            "longer needed."
        )
    elif role_match:
        applies_to = "role"
        role_name = role_match.group(2)
        cli_command = (
            f"aws iam put-role-policy "
            f"--role-name {role_name} "
            f"--policy-name iam-jit-assume-grant "
            f"--policy-document '{flat_policy}'"
        )
        notes = (
            f"Run this command with credentials for the assumer's account "
            f"({role_match.group(1)}) and `iam:PutRolePolicy` on role "
            f"'{role_name}'. Cleanup with "
            f"`aws iam delete-role-policy --role-name {role_name} "
            "--policy-name iam-jit-assume-grant`."
        )
    elif assumed_match:
        # The assumer ARN looks like an STS session — the underlying
        # role is what needs the policy. Point the user at it.
        applies_to = "assumed-role"
        underlying_role = assumed_match.group(2)
        notes = (
            f"This is a session ARN. The underlying IAM role "
            f"'arn:aws:iam::{assumed_match.group(1)}:role/{underlying_role}' "
            "needs the AssumeRole policy attached. If it's an SSO role, "
            "update the permission set; otherwise:\n"
            f"  aws iam put-role-policy --role-name {underlying_role} "
            "--policy-name iam-jit-assume-grant "
            f"--policy-document '{flat_policy}'"
        )
        cli_command = (
            f"aws iam put-role-policy "
            f"--role-name {underlying_role} "
            f"--policy-name iam-jit-assume-grant "
            f"--policy-document '{flat_policy}'"
        )
    else:
        applies_to = "unknown"
        notes = (
            f"The assumer ARN {assumer_arn!r} is not a recognized IAM "
            "user/role shape. The JSON policy below grants the right to "
            "call sts:AssumeRole on the target role; attach it to the "
            "assumer through whatever mechanism your identity provider "
            "supports."
        )

    return {
        "policy_json": policy_json,
        "cli_command": cli_command,
        "applies_to": applies_to,
        "notes": notes,
    }


def resolve_assumer_principal(request: dict[str, Any]) -> str | None:
    """Return the ARN that will assume the provisioned role, or None."""
    spec = request.get("spec") or {}
    assume_by = spec.get("assume_by") or {}
    if assume_by.get("principal_arn"):
        return assume_by["principal_arn"]
    metadata = request.get("metadata") or {}
    requester = metadata.get("requester") or {}
    return requester.get("principal_arn") or None


def resolve_session_name(request: dict[str, Any]) -> str:
    spec = request.get("spec") or {}
    assume_by = spec.get("assume_by") or {}
    if assume_by.get("session_name"):
        return assume_by["session_name"]
    metadata = request.get("metadata") or {}
    rid = metadata.get("id") or "iam-jit-grant"
    return f"iam-jit-{rid}"[:64]


def render_instructions(
    request: dict[str, Any],
    *,
    role_arn: str,
    external_id: str | None = None,
    duration_seconds: int | None = None,
    region_hint: str | None = None,
) -> dict[str, Any]:
    """Build the assume_instructions block for `status.provisioned`.

    Caller passes the actually-provisioned `role_arn` (and `external_id`
    if the trust policy uses one). Everything else comes off the request.
    Returns a dict matching the schema's `assume_instructions` object plus
    a few sibling fields the caller may want to attach (`assumer_principal_arn`,
    `session_name`).
    """
    assumer = resolve_assumer_principal(request)
    session_name = resolve_session_name(request)

    cli_parts = [
        "aws sts assume-role",
        f"--role-arn {role_arn}",
        f"--role-session-name {session_name}",
    ]
    if external_id:
        cli_parts.append(f"--external-id {external_id}")
    if duration_seconds:
        cli_parts.append(f"--duration-seconds {duration_seconds}")
    cli_assume_role = " \\\n  ".join(cli_parts)

    profile_lines = [
        "# Optional ~/.aws/config snippet. Profile name is a suggestion —",
        "# rename freely. Pair this profile with whatever calling identity",
        "# you already use (static keys, SSO, OIDC, instance metadata,",
        "# container credentials, etc.) — see the AWS docs for sourcing",
        "# credentials in a named profile.",
        "[profile iam-jit-grant]",
        f"role_arn = {role_arn}",
        f"role_session_name = {session_name}",
    ]
    if external_id:
        profile_lines.append(f"external_id = {external_id}")
    if region_hint:
        profile_lines.append(f"region = {region_hint}")
    cli_profile_block = "\n".join(profile_lines)

    notes_parts: list[str] = []
    notes_parts.append(
        "Run the snippet from any environment that has AWS credentials for "
        "the assumer principal — local CLI, CI runner, EC2/ECS task, EKS "
        "pod, etc. iam-jit doesn't care which; the trust policy enforces "
        "the principal."
    )
    if assumer:
        notes_parts.append(
            f"Trust policy is locked to {assumer}. Calls from any other "
            "principal will be denied by STS regardless of permissions."
        )
    else:
        notes_parts.append(
            "No assumer principal was inferred from your iam-jit login and "
            "none was set on the request. Set spec.assume_by.principal_arn "
            "before approval, otherwise the trust policy can't be locked "
            "down to a specific identity."
        )
    notes_parts.append(
        "STS sessions default to 1h. For longer sessions, set a higher "
        "MaxSessionDuration on the role at provision time and pass "
        "--duration-seconds on the assume call."
    )
    if external_id:
        notes_parts.append(
            "ExternalId is required by the trust policy — include "
            "--external-id (CLI) or external_id= (config) on every call."
        )
    notes = " ".join(notes_parts)

    # ---- AI-tool-friendly usage hints ----
    # When agents (Claude Code, Cursor, custom internal tooling) consume
    # this block via the MCP `get_assume_instructions` tool, they need
    # concrete instructions for HOW to feed the assumed credentials into
    # subsequent AWS calls. The standard mechanisms across tools:
    agent_hints = textwrap.dedent(
        f"""\
        # For AI tools / agents using this role:
        #
        # Option A — environment variables (works in any subprocess, MCP servers,
        # and most AI tooling that shells out to `aws ...`):
        #
        #   eval "$(aws sts assume-role \\
        #     --role-arn {role_arn} \\
        #     --role-session-name {session_name}{' \\\n        --external-id ' + external_id if external_id else ''} \\
        #     --query 'Credentials' \\
        #     --output text \\
        #     | awk '{{print "export AWS_ACCESS_KEY_ID="$1"\\nexport AWS_SECRET_ACCESS_KEY="$3"\\nexport AWS_SESSION_TOKEN="$4}}')"
        #
        #   # Then any subsequent `aws ...`, boto3, MCP server, etc. picks them up.
        #
        # Option B — named profile (preferred when the agent supports AWS_PROFILE):
        #
        #   AWS_PROFILE=iam-jit-grant aws s3 ls
        #
        # Option C — credentials_process (for tools that respect ~/.aws/config):
        #   Add a credentials_process directive that runs the assume-role
        #   command and emits JSON in the format AWS expects. See AWS docs.
        #
        # All three work with: AWS CLI v2, boto3, AWS SDK for any language,
        # the AWS MCP server, Claude Code's bash tool, Cursor's terminal,
        # langchain's AWS tools, etc. The credentials are bog-standard
        # short-lived STS tokens; nothing about iam-jit is special.
        """
    ).strip()

    console_url: str | None = None
    if ":role/" in role_arn:
        try:
            account = role_arn.split(":")[4]
            role_name = role_arn.split(":role/", 1)[1]
            console_url = (
                "https://signin.aws.amazon.com/switchrole?"
                f"account={account}&roleName={quote(role_name)}&displayName={quote(session_name)}"
            )
        except (IndexError, ValueError):
            console_url = None

    # #696 defensive guard: force every multi-line scalar back to a
    # plain `str` so a future caller passing a ruamel CommentedScalar /
    # subclass through the renderer doesn't accidentally emit a
    # serializer-confused payload. `str(x)` on a `str` subclass is
    # idempotent + cheap. Plain-`str` values are guaranteed-correctly
    # escaped by every standard JSON encoder (stdlib json, orjson,
    # FastAPI's default).
    block: dict[str, Any] = {
        "cli_assume_role": str(cli_assume_role),
        "cli_profile_block": str(cli_profile_block),
        "agent_usage_hints": str(agent_hints),
        "notes": str(notes),
    }
    if console_url:
        block["console_url"] = console_url

    # Assumer-side grant: the policy + CLI the assumer's account admin
    # needs to attach so the principal can actually call sts:AssumeRole.
    # If we don't know the assumer ARN, we can still emit the policy with
    # a placeholder Resource — the admin substitutes the real role ARN.
    if assumer:
        block["assumer_grant"] = render_assumer_grant(assumer, role_arn)
    return {
        "assume_instructions": block,
        "assumer_principal_arn": assumer,
        "session_name": session_name,
    }
