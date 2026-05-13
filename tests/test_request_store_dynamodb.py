"""DynamoDBStore tests against moto."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from iam_jit.store import DynamoDBStore, NotFoundError


@pytest.fixture
def dynamodb_table(mock_aws_env: None) -> Iterator[Any]:
    """Provision a fresh DynamoDB table per test using moto."""
    from moto import mock_aws

    with mock_aws():
        import boto3

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="iam-jit-requests",
            KeySchema=[{"AttributeName": "request_id", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "request_id", "AttributeType": "S"}
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.Table("iam-jit-requests").wait_until_exists()
        yield ddb


def _request(rid: str = "rq-abc") -> dict:
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "id": rid,
            "requester": {"name": "Dev", "email": "dev@example.com"},
        },
        "spec": {
            "description": "read s3 config files",
            "access_type": "read-only",
            "accounts": [{"account_id": "060392206767"}],
            "duration": {"duration_hours": 24},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "arn:aws:s3:::ex",
                    }
                ],
            },
            "provisioning": {"mode": "identity_center"},
        },
        "status": {
            "state": "pending",
            "owner": "email:dev@example.com",
            "submitted_at": "2026-05-07T10:00:00Z",
        },
    }


def test_put_get_roundtrip(dynamodb_table: Any) -> None:
    store = DynamoDBStore("iam-jit-requests", dynamodb_resource=dynamodb_table)
    req = _request("rq-abc")
    store.put("rq-abc", req)
    fetched = store.get("rq-abc")
    assert fetched["metadata"]["id"] == "rq-abc"
    assert fetched["spec"]["description"] == "read s3 config files"
    assert fetched["status"]["state"] == "pending"


def test_get_missing_raises_notfound(dynamodb_table: Any) -> None:
    store = DynamoDBStore("iam-jit-requests", dynamodb_resource=dynamodb_table)
    with pytest.raises(NotFoundError):
        store.get("nope")


def test_exists(dynamodb_table: Any) -> None:
    store = DynamoDBStore("iam-jit-requests", dynamodb_resource=dynamodb_table)
    assert not store.exists("nope")
    store.put("rq", _request("rq"))
    assert store.exists("rq")


def test_list_ids(dynamodb_table: Any) -> None:
    store = DynamoDBStore("iam-jit-requests", dynamodb_resource=dynamodb_table)
    for rid in ("rq-c", "rq-a", "rq-b"):
        store.put(rid, _request(rid))
    assert store.list_ids() == ["rq-a", "rq-b", "rq-c"]


def test_delete(dynamodb_table: Any) -> None:
    store = DynamoDBStore("iam-jit-requests", dynamodb_resource=dynamodb_table)
    store.put("rq", _request("rq"))
    store.delete("rq")
    assert not store.exists("rq")
    with pytest.raises(NotFoundError):
        store.delete("rq")


def test_status_fields_projected_for_querying(dynamodb_table: Any) -> None:
    """state / owner_id / submitted_at are projected as top-level
    attributes so a future GSI can serve queue listing without
    deserializing the full payload."""
    store = DynamoDBStore("iam-jit-requests", dynamodb_resource=dynamodb_table)
    store.put("rq", _request("rq"))
    raw = dynamodb_table.Table("iam-jit-requests").get_item(Key={"request_id": "rq"})["Item"]
    assert raw["state"] == "pending"
    assert raw["owner_id"] == "email:dev@example.com"
    assert raw["submitted_at"] == "2026-05-07T10:00:00Z"
    assert "payload" in raw  # full JSON still stored


def test_invalid_request_rejected_before_put(dynamodb_table: Any) -> None:
    """Schema validation must run before any DynamoDB write. We strip
    `accounts` (which IS still required by the schema) — `description`
    is now optional for read-only requests so removing it wouldn't
    fail validation."""
    store = DynamoDBStore("iam-jit-requests", dynamodb_resource=dynamodb_table)
    bad = _request("rq")
    bad["spec"].pop("accounts")
    with pytest.raises(ValueError, match="Invalid request"):
        store.put("rq", bad)
    assert not store.exists("rq")


@pytest.fixture
def dynamodb_table_with_gsi(mock_aws_env: None) -> Iterator[Any]:
    """Table provisioned with the state-submitted_at-index GSI so
    query_by_state hits the index path rather than the scan fallback."""
    from moto import mock_aws

    with mock_aws():
        import boto3

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="iam-jit-requests",
            KeySchema=[{"AttributeName": "request_id", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "request_id", "AttributeType": "S"},
                {"AttributeName": "state", "AttributeType": "S"},
                {"AttributeName": "submitted_at", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "state-submitted_at-index",
                    "KeySchema": [
                        {"AttributeName": "state", "KeyType": "HASH"},
                        {"AttributeName": "submitted_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        )
        ddb.Table("iam-jit-requests").wait_until_exists()
        yield ddb


def test_query_by_state_returns_only_matching_state(
    dynamodb_table_with_gsi: Any,
) -> None:
    store = DynamoDBStore(
        "iam-jit-requests", dynamodb_resource=dynamodb_table_with_gsi
    )
    pending_ids = ["rq-p1", "rq-p2", "rq-p3"]
    approved_ids = ["rq-a1", "rq-a2"]
    for i, rid in enumerate(pending_ids):
        req = _request(rid)
        req["status"]["state"] = "pending"
        req["status"]["submitted_at"] = f"2026-05-07T10:0{i}:00Z"
        store.put(rid, req)
    for i, rid in enumerate(approved_ids):
        req = _request(rid)
        req["status"]["state"] = "approved"
        req["status"]["submitted_at"] = f"2026-05-07T10:0{i}:00Z"
        store.put(rid, req)

    pending = store.query_by_state("pending")
    assert {r["metadata"]["id"] for r in pending} == set(pending_ids)

    approved = store.query_by_state("approved")
    assert {r["metadata"]["id"] for r in approved} == set(approved_ids)


def test_query_by_state_orders_newest_first(
    dynamodb_table_with_gsi: Any,
) -> None:
    store = DynamoDBStore(
        "iam-jit-requests", dynamodb_resource=dynamodb_table_with_gsi
    )
    timestamps = [
        "2026-05-07T10:00:00Z",
        "2026-05-07T11:00:00Z",
        "2026-05-07T09:00:00Z",
    ]
    for i, ts in enumerate(timestamps):
        req = _request(f"rq-{i}")
        req["status"]["state"] = "pending"
        req["status"]["submitted_at"] = ts
        store.put(f"rq-{i}", req)

    pending = store.query_by_state("pending")
    submitted = [r["status"]["submitted_at"] for r in pending]
    assert submitted == sorted(submitted, reverse=True)


def test_query_by_state_respects_limit(dynamodb_table_with_gsi: Any) -> None:
    store = DynamoDBStore(
        "iam-jit-requests", dynamodb_resource=dynamodb_table_with_gsi
    )
    for i in range(5):
        req = _request(f"rq-{i}")
        req["status"]["state"] = "pending"
        req["status"]["submitted_at"] = f"2026-05-07T10:0{i}:00Z"
        store.put(f"rq-{i}", req)
    out = store.query_by_state("pending", limit=2)
    assert len(out) == 2


def test_query_by_state_falls_back_to_scan_without_gsi(
    dynamodb_table: Any,
) -> None:
    """The basic table fixture has no GSI; query_by_state must still
    return the right results via the scan fallback path."""
    store = DynamoDBStore("iam-jit-requests", dynamodb_resource=dynamodb_table)
    for i in range(3):
        req = _request(f"rq-{i}")
        req["status"]["state"] = "pending"
        req["status"]["submitted_at"] = f"2026-05-07T10:0{i}:00Z"
        store.put(f"rq-{i}", req)
    pending = store.query_by_state("pending")
    assert len(pending) == 3
    assert all(r["status"]["state"] == "pending" for r in pending)


def test_overwrite_replaces_payload(dynamodb_table: Any) -> None:
    store = DynamoDBStore("iam-jit-requests", dynamodb_resource=dynamodb_table)
    req = _request("rq")
    store.put("rq", req)
    req["spec"]["description"] = "updated description for service X"
    store.put("rq", req)
    assert store.get("rq")["spec"]["description"] == "updated description for service X"
