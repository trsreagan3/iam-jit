"""Validate the AWS CLI replay strings emitted alongside provisioning.

Three layers of validation:
  1. **Shell-parseable**: each command must split cleanly via shlex
     (no unbalanced quotes, no broken escapes).
  2. **Structurally valid**: the create-role / put-role-policy CLI
     contracts (required flags present, JSON args parse, tag arg
     uses Key=...,Value=... shape).
  3. **Semantically valid**: every action prefix in the policy doc
     is a real AWS service prefix (matches a known service in
     debug_bundles or our action list); every Resource is a real ARN
     pattern; the policy round-trips through moto-IAM.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Iterator
from typing import Any

import pytest

from iam_jit import debug_bundles, provision
from iam_jit.accounts_store import Account, InMemoryAccountStore


@pytest.fixture
def moto_sts_iam(mock_aws_env: None) -> Iterator[Any]:
    from moto import mock_aws

    with mock_aws():
        import boto3

        sts = boto3.client("sts", region_name="us-east-1")

        def factory(creds: dict[str, str]) -> Any:
            return boto3.client("iam", region_name="us-east-1")

        yield sts, factory


@pytest.fixture
def store() -> InMemoryAccountStore:
    s = InMemoryAccountStore()
    s.put(
        Account(
            account_id="060392206767",
            provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
            provisioner_external_id="iam-jit-060392206767",
            provisioning_mode="classic_iam",
        )
    )
    return s


def _request(rid: str = "rq-cli", policy: dict | None = None) -> dict:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": rid,
            "requester": {
                "name": "Dev",
                "email": "dev@example.com",
                "principal_arn": "arn:aws:iam::060392206767:user/dev",
            },
        },
        "spec": {
            "description": "read s3 config files",
            "access_type": "read-only",
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 4},
            "policy": policy
            or {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
                    }
                ],
            },
            "provisioning": {"mode": "classic_iam"},
        },
    }


# ---- Layer 1: shell-parseable ----


def test_cli_replay_commands_parse_with_shlex(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request(),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    for cmd in result.aws_cli_replay:
        # If quoting is broken, shlex.split raises ValueError.
        parts = shlex.split(cmd)
        assert parts[0] == "aws"
        assert parts[1] == "iam"


def test_cli_replay_emits_create_role_and_put_role_policy(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-shape"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    verbs = [shlex.split(c)[2] for c in result.aws_cli_replay]
    assert verbs == ["create-role", "put-role-policy"]


# ---- Layer 2: structurally valid ----


def test_create_role_command_has_required_flags(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-flags"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    parts = shlex.split(result.aws_cli_replay[0])
    flags = _parse_flags(parts)
    assert "--role-name" in flags
    assert flags["--role-name"] == "iam-jit-grant-rq-flags"
    assert "--path" in flags and flags["--path"] == "/iam-jit/"
    assert "--assume-role-policy-document" in flags
    assert "--max-session-duration" in flags
    assert flags["--max-session-duration"] == "3600"
    assert "--description" in flags
    # --tags is variadic; check via the multi-value parser.
    tag_args = _parse_flags_multi(parts, "--tags")
    assert tag_args, "no --tags emitted"


def test_put_role_policy_command_has_required_flags(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-pp"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    parts = shlex.split(result.aws_cli_replay[1])
    flags = _parse_flags(parts)
    assert flags["--role-name"] == "iam-jit-grant-rq-pp"
    assert flags["--policy-name"] == "iam-jit-grant-rq-pp"
    assert "--policy-document" in flags


def test_create_role_assume_policy_is_valid_json(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-tjson"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    parts = shlex.split(result.aws_cli_replay[0])
    flags = _parse_flags(parts)
    trust = json.loads(flags["--assume-role-policy-document"])
    assert trust["Version"] == "2012-10-17"
    assert trust["Statement"][0]["Effect"] == "Allow"
    assert trust["Statement"][0]["Action"] == "sts:AssumeRole"
    # The trust policy should carry the time-condition (defense-in-depth).
    cond = trust["Statement"][0].get("Condition") or {}
    assert "DateLessThan" in cond


def test_put_role_policy_doc_is_valid_json(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-pjson"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    parts = shlex.split(result.aws_cli_replay[1])
    flags = _parse_flags(parts)
    pol = json.loads(flags["--policy-document"])
    assert pol["Version"] == "2012-10-17"
    assert isinstance(pol["Statement"], list)
    assert len(pol["Statement"]) >= 1
    for s in pol["Statement"]:
        assert s["Effect"] == "Allow"
        assert s["Action"]
        assert s.get("Resource") or s.get("NotResource")
        # Time-condition is enforced on every statement (defense-in-depth).
        assert "Condition" in s
        assert "DateLessThan" in s["Condition"]
        assert "aws:CurrentTime" in s["Condition"]["DateLessThan"]


def test_tags_argument_uses_key_value_shape(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-tags"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    parts = shlex.split(result.aws_cli_replay[0])
    flags = _parse_flags_multi(parts, "--tags")
    # AWS CLI tags use 'Key=foo,Value=bar' shape.
    assert all("Key=" in t and "Value=" in t for t in flags)
    assert any("Key=managed-by" in t for t in flags)
    assert any("Key=request-id" in t for t in flags)
    assert any("Key=expires-at" in t for t in flags)


# ---- Layer 3: semantically valid ----


def test_action_prefixes_match_known_aws_services(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    """Every action prefix in the rendered policy doc should be a real
    AWS service. We check against the curated list in debug_bundles
    plus a baseline set of common services not yet in the bundles."""
    KNOWN_BASELINE = {
        "logs",
        "cloudwatch",
        "xray",
        "sts",
        "iam",
        "events",
        "states",
        "ec2",
        "rds",
        "s3",
        "dynamodb",
        "lambda",
        "secretsmanager",
        "kms",
        "sns",
        "sqs",
        "route53",
        "elasticloadbalancing",
        "apigateway",
        "cloudfront",
        "eks",
        "ecs",
    }
    known = set(debug_bundles.BUNDLES.keys()) | KNOWN_BASELINE

    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-svc"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    parts = shlex.split(result.aws_cli_replay[1])
    flags = _parse_flags(parts)
    pol = json.loads(flags["--policy-document"])
    actions: list[str] = []
    for s in pol["Statement"]:
        a = s.get("Action") or []
        if isinstance(a, str):
            actions.append(a)
        elif isinstance(a, list):
            actions.extend(x for x in a if isinstance(x, str))
    for a in actions:
        prefix = a.split(":", 1)[0]
        assert prefix in known, f"unknown service prefix in action {a!r}"


def test_resource_arns_are_well_formed(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    sts, factory = moto_sts_iam
    result = provision.provision(
        _request("rq-arns"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )
    parts = shlex.split(result.aws_cli_replay[1])
    flags = _parse_flags(parts)
    pol = json.loads(flags["--policy-document"])
    for s in pol["Statement"]:
        r = s.get("Resource")
        if r is None:
            continue
        for arn in r if isinstance(r, list) else [r]:
            if arn == "*":
                continue
            # Real ARNs always start with 'arn:aws'. Wildcards are OK too.
            assert arn.startswith("arn:aws") or arn == "*", arn


def test_cli_replay_round_trips_through_moto_iam(
    moto_sts_iam, store: InMemoryAccountStore
) -> None:
    """Take the rendered CLI commands, extract their JSON args, and
    invoke moto's IAM client with the same kwargs. If the round-trip
    succeeds, the commands really are equivalent to what we executed
    via boto3 — anyone replaying them by hand would reproduce the
    same IAM state."""
    sts, factory = moto_sts_iam

    # First run real provision so the role exists; we'll just verify
    # the replay shape is replayable against a fresh client.
    result = provision.provision(
        _request("rq-rt"),
        accounts_store=store,
        sts_client=sts,
        iam_client_factory=factory,
    )

    # Tear down: delete the role moto-side, then replay from CLI strings.
    iam = factory({})
    # Policy name == role name in our convention. Re-derive from the
    # role rather than splitting strings.
    request_id = result.role_name.removeprefix("iam-jit-grant-")
    iam.delete_role_policy(
        RoleName=result.role_name, PolicyName=f"iam-jit-grant-{request_id}"
    )
    iam.delete_role(RoleName=result.role_name)

    # Replay create-role from the CLI string.
    create_parts = shlex.split(result.aws_cli_replay[0])
    f1 = _parse_flags(create_parts)
    iam.create_role(
        RoleName=f1["--role-name"],
        Path=f1["--path"],
        AssumeRolePolicyDocument=f1["--assume-role-policy-document"],
        Description=f1["--description"],
        MaxSessionDuration=int(f1["--max-session-duration"]),
        Tags=_parse_tags(_parse_flags_multi(create_parts, "--tags")),
    )

    # Replay put-role-policy.
    put_parts = shlex.split(result.aws_cli_replay[1])
    f2 = _parse_flags(put_parts)
    iam.put_role_policy(
        RoleName=f2["--role-name"],
        PolicyName=f2["--policy-name"],
        PolicyDocument=f2["--policy-document"],
    )

    # Verify the role exists with the expected shape.
    role = iam.get_role(RoleName=result.role_name)["Role"]
    assert role["Path"] == "/iam-jit/"
    assert role["MaxSessionDuration"] == 3600


# ---- helpers ----


def _parse_flags(parts: list[str]) -> dict[str, str]:
    """`['aws', 'iam', 'create-role', '--role-name', 'x', '--path', '/y/']` →
    {'--role-name': 'x', '--path': '/y/'}. Skips multi-value args."""
    out: dict[str, str] = {}
    i = 3
    while i < len(parts):
        if parts[i].startswith("--") and i + 1 < len(parts):
            # Detect multi-value (--tags Key=a,Value=b Key=c,Value=d ...) — skip
            # those for the simple-flag dict; use _parse_flags_multi instead.
            j = i + 1
            values: list[str] = []
            while j < len(parts) and not parts[j].startswith("--"):
                values.append(parts[j])
                j += 1
            if len(values) == 1:
                out[parts[i]] = values[0]
            i = j
        else:
            i += 1
    return out


def _parse_flags_multi(parts: list[str], flag: str) -> list[str]:
    """Return the variadic values for a specific flag (e.g. --tags)."""
    if flag not in parts:
        return []
    i = parts.index(flag) + 1
    out: list[str] = []
    while i < len(parts) and not parts[i].startswith("--"):
        out.append(parts[i])
        i += 1
    return out


def _parse_tags(tag_args: list[str]) -> list[dict[str, str]]:
    """`['Key=managed-by,Value=iam-jit', ...]` → list of {Key, Value} dicts."""
    out: list[dict[str, str]] = []
    for arg in tag_args:
        kv = dict(p.split("=", 1) for p in arg.split(","))
        out.append({"Key": kv["Key"], "Value": kv["Value"]})
    return out
