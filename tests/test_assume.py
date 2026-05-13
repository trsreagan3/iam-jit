"""Tests for assume-role instruction rendering."""

from __future__ import annotations

import json

from iam_jit import assume


def _req(**spec_overrides) -> dict:
    spec = {
        "description": "test",
        "accounts": [{"account_id": "060392206767"}],
        "duration": {"duration_hours": 24},
        "policy": {"Version": "2012-10-17", "Statement": []},
    }
    spec.update(spec_overrides)
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": "req-abc",
            "requester": {
                "name": "Dev",
                "email": "dev@example.com",
                "principal_arn": "arn:aws:iam::060392206767:user/dev",
            },
        },
        "spec": spec,
    }


def test_resolves_from_login_principal_by_default() -> None:
    req = _req()
    assert assume.resolve_assumer_principal(req) == "arn:aws:iam::060392206767:user/dev"


def test_explicit_override_wins() -> None:
    req = _req(assume_by={"principal_arn": "arn:aws:iam::123456789012:role/ci"})
    assert assume.resolve_assumer_principal(req) == "arn:aws:iam::123456789012:role/ci"


def test_returns_none_when_no_principal() -> None:
    req = _req()
    req["metadata"]["requester"].pop("principal_arn")
    assert assume.resolve_assumer_principal(req) is None


def test_session_name_default_includes_request_id() -> None:
    req = _req()
    assert assume.resolve_session_name(req) == "iam-jit-req-abc"


def test_session_name_override() -> None:
    req = _req(assume_by={"session_name": "ci-job-42"})
    assert assume.resolve_session_name(req) == "ci-job-42"


def test_render_includes_role_arn_and_session_name() -> None:
    req = _req()
    out = assume.render_instructions(
        req,
        role_arn="arn:aws:iam::060392206767:role/iam-jit-grant-abc",
    )
    cli = out["assume_instructions"]["cli_assume_role"]
    assert "aws sts assume-role" in cli
    assert "arn:aws:iam::060392206767:role/iam-jit-grant-abc" in cli
    assert "iam-jit-req-abc" in cli
    assert out["assumer_principal_arn"] == "arn:aws:iam::060392206767:user/dev"


def test_render_includes_external_id_when_present() -> None:
    req = _req()
    out = assume.render_instructions(
        req,
        role_arn="arn:aws:iam::060392206767:role/iam-jit-grant-abc",
        external_id="iam-jit-eid-xyz",
    )
    cli = out["assume_instructions"]["cli_assume_role"]
    profile = out["assume_instructions"]["cli_profile_block"]
    assert "--external-id iam-jit-eid-xyz" in cli
    assert "external_id = iam-jit-eid-xyz" in profile


def test_render_omits_console_url_for_iam_user_arn() -> None:
    req = _req(assume_by={"principal_arn": "arn:aws:iam::123:user/x"})
    out = assume.render_instructions(
        req,
        role_arn="arn:aws:iam::060392206767:role/iam-jit-grant-abc",
    )
    assert out["assume_instructions"].get("console_url", "").startswith("https://signin.aws.amazon.com/switchrole")


def test_render_includes_assumer_grant_for_iam_user() -> None:
    """When the assumer is an IAM user, render put-user-policy CLI."""
    from iam_jit import assume

    req = _req(assume_by={"principal_arn": "arn:aws:iam::060392206767:user/dev"})
    out = assume.render_instructions(
        req, role_arn="arn:aws:iam::060392206767:role/iam-jit-grant-abc"
    )
    grant = out["assume_instructions"]["assumer_grant"]
    assert grant["applies_to"] == "user"
    assert grant["cli_command"]
    assert "put-user-policy" in grant["cli_command"]
    assert "--user-name dev" in grant["cli_command"]
    assert "iam-jit-assume-grant" in grant["cli_command"]
    # Policy JSON parses and grants AssumeRole on the new role.
    pol = json.loads(grant["policy_json"])
    assert pol["Statement"][0]["Action"] == "sts:AssumeRole"
    assert pol["Statement"][0]["Resource"] == "arn:aws:iam::060392206767:role/iam-jit-grant-abc"


def test_render_includes_assumer_grant_for_iam_role() -> None:
    """For an IAM role assumer (e.g. CI runner), render put-role-policy."""
    from iam_jit import assume

    req = _req(assume_by={"principal_arn": "arn:aws:iam::060392206767:role/ci-runner"})
    grant = assume.render_instructions(
        req, role_arn="arn:aws:iam::060392206767:role/iam-jit-grant-x"
    )["assume_instructions"]["assumer_grant"]
    assert grant["applies_to"] == "role"
    assert "put-role-policy" in grant["cli_command"]
    assert "--role-name ci-runner" in grant["cli_command"]


def test_render_includes_assumer_grant_for_sso_role() -> None:
    """SSO/Identity Center roles — no direct CLI; the admin updates the
    permission set. We surface clear instructions."""
    from iam_jit import assume

    sso_arn = (
        "arn:aws:iam::060392206767:role/aws-reserved/sso.amazonaws.com/"
        "AWSReservedSSO_DevOps_abc123def456"
    )
    req = _req(assume_by={"principal_arn": sso_arn})
    grant = assume.render_instructions(
        req, role_arn="arn:aws:iam::060392206767:role/iam-jit-grant-x"
    )["assume_instructions"]["assumer_grant"]
    assert grant["applies_to"] == "sso"
    assert grant["cli_command"] is None
    assert "permission set" in grant["notes"].lower()


def test_render_includes_assumer_grant_for_session_arn() -> None:
    """A session ARN gets resolved back to the underlying role for the CLI."""
    from iam_jit import assume

    session = "arn:aws:sts::060392206767:assumed-role/dev-role/session-name"
    req = _req(assume_by={"principal_arn": session})
    grant = assume.render_instructions(
        req, role_arn="arn:aws:iam::060392206767:role/iam-jit-grant-x"
    )["assume_instructions"]["assumer_grant"]
    assert grant["applies_to"] == "assumed-role"
    assert "dev-role" in (grant["cli_command"] or "")


def test_render_includes_assumer_grant_for_unknown_arn_shape() -> None:
    """Federated principals or unrecognized shapes still get the policy
    JSON; we just can't auto-build the CLI."""
    from iam_jit import assume

    req = _req(
        assume_by={"principal_arn": "arn:aws:something-weird:::federated/principal"}
    )
    grant = assume.render_instructions(
        req, role_arn="arn:aws:iam::060392206767:role/iam-jit-grant-x"
    )["assume_instructions"]["assumer_grant"]
    assert grant["applies_to"] == "unknown"
    assert grant["cli_command"] is None
    assert grant["policy_json"]  # JSON still rendered


def test_render_includes_agent_usage_hints() -> None:
    """The rendered block must include AI-tool hints (env vars,
    AWS_PROFILE, credentials_process) so an agent receiving this via
    MCP knows how to actually USE the role, not just print the snippet."""
    req = _req()
    out = assume.render_instructions(
        req,
        role_arn="arn:aws:iam::060392206767:role/iam-jit-grant-abc",
    )
    hints = out["assume_instructions"].get("agent_usage_hints", "")
    assert hints, "agent_usage_hints must be populated"
    assert "AWS_ACCESS_KEY_ID" in hints
    assert "AWS_SECRET_ACCESS_KEY" in hints
    assert "AWS_SESSION_TOKEN" in hints
    assert "AWS_PROFILE" in hints
    assert "credentials_process" in hints
    assert "boto3" in hints or "AWS SDK" in hints


def test_render_warns_when_no_assumer() -> None:
    req = _req()
    req["metadata"]["requester"].pop("principal_arn")
    out = assume.render_instructions(
        req,
        role_arn="arn:aws:iam::060392206767:role/iam-jit-grant-abc",
    )
    assert out["assumer_principal_arn"] is None
    assert "No assumer principal" in out["assume_instructions"]["notes"]
