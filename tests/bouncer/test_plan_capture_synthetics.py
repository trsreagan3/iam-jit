"""Tests for the plan-capture synthetic-shape registry (#132).

Validates that each registered (service, action) returns a shape
the SDK / SDK-shaped-parser can consume, and that unregistered
operations return the unsupported-op error in a stable way.
"""

from __future__ import annotations

import json
import re

import pytest

from iam_jit.bouncer.plan_capture.synthetics import (
    PLAN_CAPTURE_ACCOUNT_ID,
    SUPPORTED_OPERATIONS,
    UNSUPPORTED_OP_SHAPE,
    is_supported,
    synthesize_response,
)


# ---------------------------------------------------------------------------
# Registry coverage
# ---------------------------------------------------------------------------


def test_registry_covers_minimum_viable_operations() -> None:
    """Per the #132 spec: minimum coverage = s3 ListBuckets / ListObjects /
    GetObject / PutObject; iam CreateRole / AttachRolePolicy / PassRole;
    sts AssumeRole; ec2 DescribeInstances / RunInstances / TerminateInstances;
    lambda Invoke / CreateFunction."""
    required = {
        ("s3", "ListBuckets"), ("s3", "ListObjects"), ("s3", "ListObjectsV2"),
        ("s3", "GetObject"), ("s3", "PutObject"),
        ("iam", "CreateRole"), ("iam", "AttachRolePolicy"), ("iam", "PassRole"),
        ("sts", "AssumeRole"),
        ("ec2", "DescribeInstances"), ("ec2", "RunInstances"),
        ("ec2", "TerminateInstances"),
        ("lambda", "Invoke"), ("lambda", "CreateFunction"),
    }
    covered = set(SUPPORTED_OPERATIONS)
    missing = required - covered
    assert not missing, f"#132 spec required ops not in registry: {missing}"


@pytest.mark.parametrize("service,action", SUPPORTED_OPERATIONS)
def test_each_registered_op_produces_well_formed_response(
    service: str, action: str,
) -> None:
    """For every registered op the response must:
       - have a status code in {200, 201, 204}
       - have a non-empty content-type header
       - have body bytes (possibly empty — HEAD/DELETE)
       - have a non-empty `would_have_returned` summary
    """
    synth = synthesize_response(
        service=service, action=action,
        host=f"{service}.us-east-1.amazonaws.com",
        path="/",
        body=b"",
        query={},
    )
    assert synth.status in (200, 201, 204)
    # content-type may be lowercased; check case-insensitively
    keys_lower = {k.lower() for k in synth.headers}
    assert "content-type" in keys_lower
    assert isinstance(synth.body, bytes)
    assert synth.would_have_returned, "would_have_returned must be non-empty"
    assert "kind" not in synth.would_have_returned or (
        synth.would_have_returned.get("kind") != UNSUPPORTED_OP_SHAPE
    )


def test_is_supported_true_for_registered_op() -> None:
    assert is_supported("s3", "ListBuckets") is True
    assert is_supported("S3", "ListBuckets") is True  # service is case-insensitive


def test_is_supported_false_for_unregistered_op() -> None:
    assert is_supported("s3", "AbortMultipartUpload") is False
    assert is_supported("dynamodb", "PutItem") is False


# ---------------------------------------------------------------------------
# Unsupported-op error shape
# ---------------------------------------------------------------------------


def test_unsupported_op_returns_clear_sdk_style_error() -> None:
    """Per the #132 spec: ops without a synthetic shape return a clear
    SDK-style error indicating 'switch modes if you need this'."""
    synth = synthesize_response(
        service="dynamodb", action="PutItem",
        host="dynamodb.us-east-1.amazonaws.com",
        path="/", body=b"", query={},
    )
    assert synth.status == 400
    payload = json.loads(synth.body)
    assert payload["__plan_capture"] is True
    assert payload["Error"]["Code"] == "PlanCaptureUnsupportedOperation"
    assert "switch to --mode" in payload["Error"]["Message"].lower()
    assert payload["Error"]["Service"] == "dynamodb"
    assert payload["Error"]["Action"] == "PutItem"
    assert synth.would_have_returned["kind"] == UNSUPPORTED_OP_SHAPE


def test_unsupported_response_carries_marker_header() -> None:
    """An operator using curl / mitmproxy must be able to tell the
    response came from plan-capture's unsupported branch."""
    synth = synthesize_response(
        service="rds", action="CreateDBInstance",
        host="rds.us-east-1.amazonaws.com",
        path="/", body=b"", query={},
    )
    assert synth.headers.get("x-iam-jit-bouncer-plan-capture-unsupported") == "true"


# ---------------------------------------------------------------------------
# #693 — XML-protocol services get XML <ErrorResponse> envelopes so
# boto3's response parser doesn't crash with ResponseParserError.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("service,action", [
    ("ec2", "AllocateAddress"),
    ("s3", "PutBucketTagging"),
    ("sqs", "CreateQueue"),
    ("sns", "Publish"),
    ("rds", "CreateDBInstance"),
    ("cloudformation", "CreateStack"),
    ("elasticache", "CreateCacheCluster"),
])
def test_unsupported_op_xml_envelope_for_xml_protocol_services(
    service: str, action: str,
) -> None:
    """XML-protocol services MUST get an XML <ErrorResponse> envelope —
    otherwise boto3's parser raises ResponseParserError mid-script. The
    body must include <Error><Code>PlanCaptureUnsupportedOperation</Code>
    so botocore surfaces a typed ClientError the agent can catch."""
    synth = synthesize_response(
        service=service, action=action,
        host=f"{service}.us-east-1.amazonaws.com",
        path="/", body=b"", query={},
    )
    assert synth.status == 400
    assert "xml" in synth.headers.get("content-type", "").lower()
    text = synth.body.decode("utf-8")
    assert text.startswith("<?xml")
    assert "<ErrorResponse" in text
    assert "<Code>PlanCaptureUnsupportedOperation</Code>" in text
    assert f"<RequestId>plan-capture-" in text
    # XML body MUST be JSON-rejected (proves XML, not accidental JSON).
    with pytest.raises(json.JSONDecodeError):
        json.loads(text)
    assert synth.would_have_returned["kind"] == UNSUPPORTED_OP_SHAPE


def test_unsupported_op_xml_body_parses_via_botocore() -> None:
    """End-to-end proof: feed the XML body through botocore's response
    parser the way a real SDK call does, and assert it surfaces a
    ClientError with the expected Code — never a ResponseParserError."""
    pytest.importorskip("botocore")
    from botocore.parsers import create_parser

    synth = synthesize_response(
        service="ec2", action="AllocateAddress",
        host="ec2.us-east-1.amazonaws.com",
        path="/", body=b"", query={},
    )
    parser = create_parser("ec2")
    parsed = parser.parse(
        {
            "status_code": synth.status,
            "headers": synth.headers,
            "body": synth.body,
            "context": {"operation_name": "AllocateAddress"},
        },
        None,
    )
    # botocore parses an error into {"Error": {...}, "ResponseMetadata": {...}}.
    assert "Error" in parsed
    assert parsed["Error"]["Code"] == "PlanCaptureUnsupportedOperation"


def test_unsupported_op_json_envelope_preserved_for_json_protocol() -> None:
    """JSON-protocol services (DynamoDB, Lambda, Bedrock, ...) must still
    get the original JSON envelope — the XML fix is XML-only."""
    synth = synthesize_response(
        service="dynamodb", action="PutItem",
        host="dynamodb.us-east-1.amazonaws.com",
        path="/", body=b"", query={},
    )
    assert "json" in synth.headers.get("content-type", "").lower()
    payload = json.loads(synth.body)
    assert payload["Error"]["Code"] == "PlanCaptureUnsupportedOperation"


def test_writes_rejected_xml_envelope_for_xml_protocol_services() -> None:
    """The writes-rejected synthetic must also emit XML for XML-protocol
    services — agents calling ec2:RunInstances in a rejected session
    should see a typed ClientError, not a parser crash."""
    from iam_jit.bouncer.plan_capture.synthetics import (
        build_writes_rejected_response,
    )
    synth = build_writes_rejected_response(service="ec2", action="RunInstances")
    assert synth.status == 400
    assert "xml" in synth.headers.get("content-type", "").lower()
    text = synth.body.decode("utf-8")
    assert "<Code>PlanCaptureWritesRejected</Code>" in text
    assert synth.headers.get("x-iam-jit-bouncer-plan-capture-writes-rejected") == "true"


# ---------------------------------------------------------------------------
# Per-service shape spot-checks
# ---------------------------------------------------------------------------


def test_s3_list_buckets_returns_empty_bucket_list_xml() -> None:
    """SDK consumers parse the XML; we need <ListAllMyBucketsResult>
    + <Buckets> for boto3 to surface a valid empty list."""
    synth = synthesize_response(
        service="s3", action="ListBuckets",
        host="s3.amazonaws.com", path="/", body=b"", query={},
    )
    text = synth.body.decode("utf-8")
    assert "<ListAllMyBucketsResult" in text
    assert "<Buckets>" in text
    assert "</ListAllMyBucketsResult>" in text


def test_iam_create_role_echoes_requested_role_name() -> None:
    """The synthetic ARN must include the role name the request asked
    for so a chained AttachRolePolicy / PassRole call (in the same
    agent flow) refers to a name the operator can recognize in the
    transcript."""
    body = b"Action=CreateRole&RoleName=my-test-role&Version=2010-05-08"
    synth = synthesize_response(
        service="iam", action="CreateRole",
        host="iam.amazonaws.com", path="/", body=body, query={},
    )
    text = synth.body.decode("utf-8")
    assert "<RoleName>my-test-role</RoleName>" in text
    expected_arn = f"arn:aws:iam::{PLAN_CAPTURE_ACCOUNT_ID}:role/my-test-role"
    assert expected_arn in text
    assert synth.would_have_returned["RoleName"] == "my-test-role"


def test_sts_assume_role_returns_obviously_synthetic_credentials() -> None:
    """An operator who accidentally pipes these creds anywhere should
    see they're fake at first glance — that's a feature, not a bug,
    per [[ibounce-honest-positioning]]."""
    synth = synthesize_response(
        service="sts", action="AssumeRole",
        host="sts.amazonaws.com", path="/", body=b"", query={},
    )
    text = synth.body.decode("utf-8")
    assert "ASIAPLANCAPTURE" in text
    assert "plan-capture-synthetic-not-a-real-secret" in text
    assert PLAN_CAPTURE_ACCOUNT_ID in text  # sentinel account


def test_ec2_run_instances_returns_a_synthetic_instance_id() -> None:
    """Agents that chain RunInstances -> DescribeInstances need an
    instance id back so the next call shape works."""
    synth = synthesize_response(
        service="ec2", action="RunInstances",
        host="ec2.us-east-1.amazonaws.com",
        path="/", body=b"Action=RunInstances", query={},
    )
    text = synth.body.decode("utf-8")
    m = re.search(r"<instanceId>(i-[0-9a-f]+)</instanceId>", text)
    assert m is not None
    assert m.group(1).startswith("i-")


def test_lambda_invoke_returns_empty_json_payload() -> None:
    """Lambda Invoke returns the function's response as the body
    (NOT wrapped). Empty JSON object is the least-disruptive
    synthetic that boto3 will surface as a `{}` payload."""
    synth = synthesize_response(
        service="lambda", action="Invoke",
        host="lambda.us-east-1.amazonaws.com",
        path="/2015-03-31/functions/foo/invocations",
        body=b'{"key":"v"}', query={},
    )
    assert synth.body == b"{}"
    assert synth.status == 200


def test_synthetic_request_id_uses_plan_capture_prefix() -> None:
    """The x-amz-request-id sentinel should let an operator grep
    `plan-capture` across any log to filter for synthetic calls."""
    synth = synthesize_response(
        service="s3", action="ListBuckets",
        host="s3.amazonaws.com", path="/", body=b"", query={},
    )
    rid = synth.headers.get("x-amz-request-id") or synth.headers.get("x-amzn-requestid")
    assert rid is not None
    assert rid.startswith("plan-capture")


# ---------------------------------------------------------------------------
# Determinism / no-network invariants
# ---------------------------------------------------------------------------


def test_synthesize_response_makes_no_network_calls(monkeypatch) -> None:
    """The synthetics module must NEVER reach AWS. Patch socket.connect
    to fail on any attempt + verify all registered ops still produce
    a response."""
    import socket

    def _explode(*a, **kw):
        raise AssertionError(
            "plan-capture synthesizer attempted a network call — "
            "violates [[creates-never-mutates]] + the no-forward invariant"
        )

    monkeypatch.setattr(socket.socket, "connect", _explode)
    for service, action in SUPPORTED_OPERATIONS:
        synth = synthesize_response(
            service=service, action=action,
            host=f"{service}.us-east-1.amazonaws.com",
            path="/", body=b"", query={},
        )
        assert synth is not None
