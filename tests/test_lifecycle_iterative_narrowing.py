"""End-to-end test of the iterative narrowing flow:

  1. user submits a request that's too broad ("read all RDS")
  2. approver request_changes with feedback to narrow to a specific instance
  3. user resubmits with a narrower scope (still wildcard but for one DB)
  4. approver request_changes again — still too broad
  5. user resubmits with a concrete db ARN
  6. approver approves → provisioning succeeds

This exercises the request_changes → edit → pending → approve cycle plus
multiple rejections, which is the realistic narrowing-by-review pattern.
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from iam_jit import auth as auth_mod
from iam_jit.accounts_store import Account, InMemoryAccountStore
from iam_jit.api_tokens_store import InMemoryAPITokenStore
from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore


_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:admin@example.com
    display_name: Admin
    roles: [admin]
  - id: email:approver@example.com
    display_name: Approver
    roles: [approver]
  - id: email:dev@example.com
    display_name: Dev
    roles: [requester]
"""

_DEV_SECRET = "test-secret-for-route-tests-aaaaaaaaa"


@pytest.fixture
def app(
    monkeypatch: pytest.MonkeyPatch, mock_aws_env: None, tmp_path: pathlib.Path
) -> Iterator[FastAPI]:
    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv("IAM_JIT_MAGIC_LINK_SECRET", _DEV_SECRET)

    from moto import mock_aws

    with mock_aws():
        users_yaml = tmp_path / "users.yaml"
        users_yaml.write_text(_USERS_YAML)
        accounts = InMemoryAccountStore()
        accounts.put(
            Account(
                account_id="060392206767",
                provisioner_role_arn="arn:aws:iam::060392206767:role/iam-jit-provisioner",
                provisioner_external_id="iam-jit-060392206767",
                provisioning_mode="classic_iam",
            )
        )
        yield create_app(
            request_store=FilesystemStore(tmp_path / "requests"),
            user_store=FileUserStore(str(users_yaml)),
            api_tokens_store=InMemoryAPITokenStore(),
            accounts_store=accounts,
        )


def _client(app: FastAPI, user_id: str | None = None) -> TestClient:
    c = TestClient(app)
    if user_id:
        c.cookies.set("iam_jit_session", auth_mod.sign_session(_DEV_SECRET, user_id))
    return c


def _rds_payload(resource: str | list[str]) -> dict:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "name": "RDS debug access",
            "requester": {
                "name": "Dev",
                "email": "dev@example.com",
                "principal_arn": "arn:aws:iam::060392206767:user/dev",
            },
        },
        "spec": {
            "description": "debug an RDS instance — slow query investigation",
            "access_type": "read-only",
            "task_intent": {"services": ["rds"], "actions": ["read", "list"]},
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 4},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "rds:DescribeDBInstances",
                            "rds:DescribeDBLogFiles",
                        ],
                        "Resource": resource,
                    }
                ],
            },
            "provisioning": {"mode": "classic_iam"},
        },
    }


def test_iterative_narrowing_two_rejections_then_approval(app: FastAPI) -> None:
    """Reviewer asks for narrowing twice before approving."""
    dev = _client(app, "email:dev@example.com")
    approver = _client(app, "email:approver@example.com")

    # 1. User submits with Resource='*' (every RDS instance — too broad).
    submission = dev.post("/api/v1/requests", json=_rds_payload("*")).json()
    rid = submission["request"]["metadata"]["id"]
    assert submission["request"]["status"]["state"] == "pending"

    # 2. Approver requests changes — too broad.
    r1 = approver.post(
        f"/api/v1/requests/{rid}/request-changes",
        json={
            "reason": "Too broad — Resource='*' grants access to every RDS database in the account.",
            "suggestions": [
                "Narrow to a single DB instance ARN",
                "e.g. arn:aws:rds:us-east-1:060392206767:db:<your-db-name>",
            ],
        },
    )
    assert r1.status_code == 200, r1.text
    assert r1.json()["request"]["status"]["state"] == "needs_changes"

    # 3. User edits — still too broad (wildcard within rds: prefix).
    edit1 = dev.patch(
        f"/api/v1/requests/{rid}",
        json={
            "spec": {
                "description": "debug an RDS instance — slow query investigation (narrowed)",
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "rds:DescribeDBInstances",
                                "rds:DescribeDBLogFiles",
                            ],
                            "Resource": "arn:aws:rds:*:060392206767:db:*",
                        }
                    ],
                },
            }
        },
    )
    if edit1.status_code == 404:
        edit1 = dev.patch(
            f"/api/v1/requests/{rid}",
            json={
                "spec": {
                    "description": "debug an RDS instance — slow query investigation (narrowed)",
                    "policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "rds:DescribeDBInstances",
                                    "rds:DescribeDBLogFiles",
                                ],
                                "Resource": "arn:aws:rds:*:060392206767:db:*",
                            }
                        ],
                    },
                }
            },
        )
    assert edit1.status_code == 200, edit1.text
    # State should be pending again after edit on needs_changes.
    state_after_edit1 = edit1.json()["request"]["status"]["state"]
    assert state_after_edit1 == "pending", state_after_edit1

    # 4. Approver still rejects — wildcard within db: is still too wide.
    r2 = approver.post(
        f"/api/v1/requests/{rid}/request-changes",
        json={
            "reason": "Still too broad — db:* matches every database. Pick one specific instance.",
        },
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["request"]["status"]["state"] == "needs_changes"

    # 5. User resubmits with concrete db ARN.
    edit2 = dev.patch(
        f"/api/v1/requests/{rid}",
        json={
            "spec": {
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "rds:DescribeDBInstances",
                                "rds:DescribeDBLogFiles",
                                "rds:DownloadDBLogFilePortion",
                            ],
                            "Resource": "arn:aws:rds:us-east-1:060392206767:db:payments-prod-1",
                        }
                    ],
                }
            }
        },
    )
    if edit2.status_code == 404:
        edit2 = dev.patch(
            f"/api/v1/requests/{rid}",
            json={
                "spec": {
                    "policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "rds:DescribeDBInstances",
                                    "rds:DescribeDBLogFiles",
                                    "rds:DownloadDBLogFilePortion",
                                ],
                                "Resource": "arn:aws:rds:us-east-1:060392206767:db:payments-prod-1",
                            }
                        ],
                    }
                }
            },
        )
    assert edit2.status_code == 200, edit2.text
    assert edit2.json()["request"]["status"]["state"] == "pending"

    # 6. Approver approves → provisioning runs against moto IAM.
    approve = approver.post(f"/api/v1/requests/{rid}/approve")
    assert approve.status_code == 200, approve.text
    final = approve.json()["request"]
    assert final["status"]["state"] == "active", final["status"]
    assert final["status"]["provisioned"]["role_arn"].endswith(f"/iam-jit-grant-{rid}")

    # History should record both rejections and the final approval.
    actions = [h["action"] for h in final["status"]["history"]]
    assert actions.count("request_changes") == 2
    assert actions.count("edit") == 2
    assert "approve" in actions


def test_iterative_narrowing_repeated_rejections_eventually_approved(
    app: FastAPI,
) -> None:
    """Three rejections, each with feedback, before the user lands on a
    scope the reviewer accepts."""
    dev = _client(app, "email:dev@example.com")
    approver = _client(app, "email:approver@example.com")

    # Submit broadly.
    rid = dev.post("/api/v1/requests", json=_rds_payload("*")).json()["request"]["metadata"]["id"]

    feedbacks = [
        "Resource='*' is too broad",
        "rds:* still too broad",
        "Pick one db instance",
    ]
    narrower_resources = [
        "arn:aws:rds:*:*:*",
        "arn:aws:rds:us-east-1:060392206767:db:*",
        "arn:aws:rds:us-east-1:060392206767:db:payments-1",
    ]
    for feedback, resource in zip(feedbacks, narrower_resources, strict=True):
        rc = approver.post(
            f"/api/v1/requests/{rid}/request-changes",
            json={"reason": feedback},
        )
        assert rc.status_code == 200, rc.text
        edit = dev.patch(
            f"/api/v1/requests/{rid}",
            json={
                "spec": {
                    "policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["rds:DescribeDBInstances"],
                                "Resource": resource,
                            }
                        ],
                    }
                }
            },
        )
        if edit.status_code == 404:
            edit = dev.patch(
                f"/api/v1/requests/{rid}",
                json={
                    "spec": {
                        "policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["rds:DescribeDBInstances"],
                                    "Resource": resource,
                                }
                            ],
                        }
                    }
                },
            )
        assert edit.status_code == 200, edit.text

    # Final approval should succeed.
    approve = approver.post(f"/api/v1/requests/{rid}/approve")
    assert approve.status_code == 200, approve.text
    body = approve.json()["request"]
    assert body["status"]["state"] == "active"

    # Three full rejection cycles in the history.
    actions = [h["action"] for h in body["status"]["history"]]
    assert actions.count("request_changes") == 3
    assert actions.count("edit") == 3
