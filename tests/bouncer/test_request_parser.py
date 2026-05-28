"""Tests for the bouncer's wire-format AWS API request parser."""

from __future__ import annotations

import json

import pytest

from iam_jit.bouncer.request_parser import (
    ParsedRequest,
    extract_service_and_region,
    parse_request,
)


def _sigv4(service: str = "s3", region: str = "us-east-1") -> str:
    return (
        f"AWS4-HMAC-SHA256 "
        f"Credential=AKIAIOSFODNN7EXAMPLE/20260517/{region}/{service}/aws4_request, "
        f"SignedHeaders=host;x-amz-date, Signature=abc123"
    )


# ---------------------------------------------------------------------------
# extract_service_and_region
# ---------------------------------------------------------------------------


def test_extract_service_and_region_happy_path() -> None:
    assert extract_service_and_region(_sigv4("dynamodb", "us-west-2")) == ("dynamodb", "us-west-2")


def test_extract_service_lowercased() -> None:
    auth = _sigv4("S3", "us-east-1")
    s, r = extract_service_and_region(auth)
    assert s == "s3"


def test_extract_returns_none_for_missing_header() -> None:
    assert extract_service_and_region(None) is None
    assert extract_service_and_region("") is None


def test_extract_returns_none_for_non_sigv4_header() -> None:
    assert extract_service_and_region("Basic xyz") is None


def test_extract_returns_none_for_malformed_credential() -> None:
    assert extract_service_and_region("AWS4-HMAC-SHA256 Credential=garbage") is None


def test_extract_handles_extra_whitespace() -> None:
    auth = "AWS4-HMAC-SHA256   Credential=KEY/20260517/us-east-1/s3/aws4_request"
    assert extract_service_and_region(auth) == ("s3", "us-east-1")


# ---------------------------------------------------------------------------
# parse_request — top-level
# ---------------------------------------------------------------------------


def test_parse_request_returns_none_without_auth_header() -> None:
    out = parse_request(
        method="GET", host="s3.amazonaws.com", path="/bucket", headers={},
    )
    assert out is None


def test_parse_request_returns_parsed_with_sigv4() -> None:
    out = parse_request(
        method="GET",
        host="s3.amazonaws.com",
        path="/my-bucket",
        headers={"Authorization": _sigv4("s3", "us-east-1")},
    )
    assert out is not None
    assert out.service == "s3"
    assert out.region == "us-east-1"


def test_parse_request_global_service_strips_region() -> None:
    """IAM is global; SigV4 conventionally uses us-east-1 but we
    surface region=None so rules don't accidentally narrow."""
    out = parse_request(
        method="POST",
        host="iam.amazonaws.com",
        path="/",
        headers={"Authorization": _sigv4("iam", "us-east-1"), "Content-Type": "application/x-www-form-urlencoded"},
        body="Action=ListRoles&Version=2010-05-08",
    )
    assert out is not None
    assert out.service == "iam"
    assert out.region is None
    assert out.action == "ListRoles"


# ---------------------------------------------------------------------------
# X-Amz-Target (JSON-RPC) dispatch
# ---------------------------------------------------------------------------


def test_x_amz_target_extracts_action_from_dotted_form() -> None:
    out = parse_request(
        method="POST",
        host="dynamodb.us-east-1.amazonaws.com",
        path="/",
        headers={
            "Authorization": _sigv4("dynamodb", "us-east-1"),
            "X-Amz-Target": "DynamoDB_20120810.PutItem",
        },
        body=json.dumps({"TableName": "Users", "Item": {}}),
    )
    assert out is not None
    assert out.service == "dynamodb"
    assert out.action == "PutItem"
    assert out.resource_hint == "Users"


def test_x_amz_target_without_dot_uses_whole_value() -> None:
    out = parse_request(
        method="POST",
        host="dynamodb.us-east-1.amazonaws.com",
        path="/",
        headers={
            "Authorization": _sigv4("dynamodb", "us-east-1"),
            "X-Amz-Target": "WeirdSingleToken",
        },
    )
    assert out is not None
    assert out.action == "WeirdSingleToken"


# ---------------------------------------------------------------------------
# Action= form param (query-string services)
# ---------------------------------------------------------------------------


def test_action_form_param_from_body() -> None:
    out = parse_request(
        method="POST",
        host="iam.amazonaws.com",
        path="/",
        headers={"Authorization": _sigv4("iam", "us-east-1")},
        body="Action=GetRole&RoleName=admin-role&Version=2010-05-08",
    )
    assert out is not None
    assert out.action == "GetRole"
    assert out.resource_hint == "admin-role"


def test_action_form_param_from_query() -> None:
    out = parse_request(
        method="GET",
        host="ec2.us-east-1.amazonaws.com",
        path="/",
        headers={"Authorization": _sigv4("ec2", "us-east-1")},
        query={"Action": "DescribeInstances", "Version": "2016-11-15"},
    )
    assert out is not None
    assert out.action == "DescribeInstances"


# ---------------------------------------------------------------------------
# S3 dispatch
# ---------------------------------------------------------------------------


def test_s3_path_style_get_object() -> None:
    out = parse_request(
        method="GET",
        host="s3.amazonaws.com",
        path="/my-bucket/file.txt",
        headers={"Authorization": _sigv4("s3", "us-east-1")},
    )
    assert out is not None
    assert out.action == "GetObject"
    assert out.resource_hint == "arn:aws:s3:::my-bucket/file.txt"


def test_s3_path_style_list_bucket() -> None:
    out = parse_request(
        method="GET",
        host="s3.amazonaws.com",
        path="/my-bucket",
        headers={"Authorization": _sigv4("s3", "us-east-1")},
    )
    assert out is not None
    assert out.action == "ListBucket"
    assert out.resource_hint == "arn:aws:s3:::my-bucket"


def test_s3_put_object() -> None:
    out = parse_request(
        method="PUT",
        host="s3.amazonaws.com",
        path="/my-bucket/upload.zip",
        headers={"Authorization": _sigv4("s3", "us-east-1")},
    )
    assert out is not None
    assert out.action == "PutObject"


def test_s3_virtual_hosted_style() -> None:
    out = parse_request(
        method="GET",
        host="my-bucket.s3.us-east-1.amazonaws.com",
        path="/path/to/key.txt",
        headers={"Authorization": _sigv4("s3", "us-east-1")},
    )
    assert out is not None
    assert out.action == "GetObject"
    assert out.resource_hint == "arn:aws:s3:::my-bucket/path/to/key.txt"


def test_s3_delete_bucket() -> None:
    out = parse_request(
        method="DELETE",
        host="s3.amazonaws.com",
        path="/my-bucket",
        headers={"Authorization": _sigv4("s3", "us-east-1")},
    )
    assert out is not None
    assert out.action == "DeleteBucket"


def test_s3_create_bucket() -> None:
    out = parse_request(
        method="PUT",
        host="s3.amazonaws.com",
        path="/my-new-bucket",
        headers={"Authorization": _sigv4("s3", "us-east-1")},
    )
    assert out is not None
    assert out.action == "CreateBucket"


def test_s3_list_all_buckets() -> None:
    out = parse_request(
        method="GET",
        host="s3.amazonaws.com",
        path="/",
        headers={"Authorization": _sigv4("s3", "us-east-1")},
    )
    assert out is not None
    assert out.action == "ListAllMyBuckets"


def test_s3_bucket_policy_via_subresource() -> None:
    out = parse_request(
        method="PUT",
        host="s3.amazonaws.com",
        path="/my-bucket",
        headers={"Authorization": _sigv4("s3", "us-east-1")},
        query={"policy": ""},
    )
    assert out is not None
    assert out.action == "PutBucketPolicy"


def test_s3_object_acl_via_subresource() -> None:
    out = parse_request(
        method="GET",
        host="s3.amazonaws.com",
        path="/my-bucket/key",
        headers={"Authorization": _sigv4("s3", "us-east-1")},
        query={"acl": ""},
    )
    assert out is not None
    assert out.action == "GetObjectAcl"


# ---------------------------------------------------------------------------
# Lambda dispatch
# ---------------------------------------------------------------------------


def test_lambda_invoke_function() -> None:
    out = parse_request(
        method="POST",
        host="lambda.us-east-1.amazonaws.com",
        path="/2015-03-31/functions/my-func/invocations",
        headers={"Authorization": _sigv4("lambda", "us-east-1")},
    )
    assert out is not None
    assert out.action == "InvokeFunction"
    assert out.resource_hint == "my-func"


def test_lambda_get_function() -> None:
    out = parse_request(
        method="GET",
        host="lambda.us-east-1.amazonaws.com",
        path="/2015-03-31/functions/my-func",
        headers={"Authorization": _sigv4("lambda", "us-east-1")},
    )
    assert out is not None
    assert out.action == "GetFunction"


def test_lambda_delete_function() -> None:
    out = parse_request(
        method="DELETE",
        host="lambda.us-east-1.amazonaws.com",
        path="/2015-03-31/functions/my-func",
        headers={"Authorization": _sigv4("lambda", "us-east-1")},
    )
    assert out is not None
    assert out.action == "DeleteFunction"


# ---------------------------------------------------------------------------
# Generic REST fallback
# ---------------------------------------------------------------------------


def test_unknown_rest_service_falls_back_to_method() -> None:
    """A service we don't special-case still parses (just less
    precise action label)."""
    out = parse_request(
        method="POST",
        host="apprunner.us-east-1.amazonaws.com",
        path="/services/abc",
        headers={"Authorization": _sigv4("apprunner", "us-east-1")},
    )
    assert out is not None
    assert out.service == "apprunner"
    assert out.action == "POST"
    assert out.resource_hint == "/services/abc"


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_parse_request_handles_case_insensitive_headers() -> None:
    out = parse_request(
        method="GET",
        host="s3.amazonaws.com",
        path="/b/k",
        headers={"AUTHORIZATION": _sigv4("s3", "us-east-1")},
    )
    assert out is not None
    assert out.service == "s3"


def test_parse_request_handles_bytes_body() -> None:
    out = parse_request(
        method="POST",
        host="dynamodb.us-east-1.amazonaws.com",
        path="/",
        headers={
            "Authorization": _sigv4("dynamodb", "us-east-1"),
            "X-Amz-Target": "DynamoDB_20120810.GetItem",
        },
        body=json.dumps({"TableName": "T1"}).encode("utf-8"),
    )
    assert out is not None
    assert out.resource_hint == "T1"


def test_parse_request_handles_invalid_json_body() -> None:
    """Malformed body must not crash the parser; just no resource hint."""
    out = parse_request(
        method="POST",
        host="dynamodb.us-east-1.amazonaws.com",
        path="/",
        headers={
            "Authorization": _sigv4("dynamodb", "us-east-1"),
            "X-Amz-Target": "DynamoDB_20120810.PutItem",
        },
        body="{not-valid-json",
    )
    assert out is not None
    assert out.action == "PutItem"
    assert out.resource_hint is None


def test_parse_request_to_dict_round_trip() -> None:
    out = parse_request(
        method="GET",
        host="s3.amazonaws.com",
        path="/b/k",
        headers={"Authorization": _sigv4("s3", "us-east-1")},
    )
    assert out is not None
    d = out.to_dict()
    assert d["service"] == "s3"
    assert d["action"] == "GetObject"
    assert d["region"] == "us-east-1"
    assert d["raw_method"] == "GET"
    assert d["raw_path"] == "/b/k"


# ---------------------------------------------------------------------------
# #698 MED-4 — API Gateway (v1 + v2) action+resource extraction. Pre-#698
# every apigateway call fell through to the generic-REST fallback, which
# emitted the bare HTTP method as the action (GET/POST/...). Useless for
# downstream policy matchers that need apigateway:CreateRestApi etc.
# ---------------------------------------------------------------------------


def _apigateway_parse(method: str, path: str, service: str = "apigateway"):
    return parse_request(
        method=method,
        host=f"{service}.us-east-1.amazonaws.com",
        path=path,
        headers={"Authorization": _sigv4(service, "us-east-1")},
    )


@pytest.mark.parametrize("method,path,expected_action,expected_resource", [
    # apigateway v1 — REST APIs management plane
    ("GET", "/restapis", "GetRestApis", None),
    ("POST", "/restapis", "CreateRestApi", None),
    ("GET", "/restapis/abc123", "GetRestApi", "abc123"),
    ("PATCH", "/restapis/abc123", "UpdateRestApi", "abc123"),
    ("DELETE", "/restapis/abc123", "DeleteRestApi", "abc123"),
    ("PUT", "/restapis/abc123", "PutRestApi", "abc123"),
    # Resources
    ("GET", "/restapis/abc123/resources", "GetResources", "abc123"),
    ("POST", "/restapis/abc123/resources", "CreateResource", "abc123"),
    ("GET", "/restapis/abc123/resources/rid1", "GetResource", "abc123"),
    ("DELETE", "/restapis/abc123/resources/rid1", "DeleteResource", "abc123"),
    # Methods
    ("PUT", "/restapis/abc123/resources/rid1/methods/GET", "PutMethod", "abc123"),
    ("GET", "/restapis/abc123/resources/rid1/methods/GET", "GetMethod", "abc123"),
    ("DELETE", "/restapis/abc123/resources/rid1/methods/GET", "DeleteMethod", "abc123"),
    # Integrations (under methods)
    ("PUT", "/restapis/abc123/resources/rid1/methods/GET/integration",
     "PutIntegration", "abc123"),
    ("GET", "/restapis/abc123/resources/rid1/methods/GET/integration",
     "GetIntegration", "abc123"),
    # Deployments
    ("POST", "/restapis/abc123/deployments", "CreateDeployment", "abc123"),
    ("GET", "/restapis/abc123/deployments", "GetDeployments", "abc123"),
    ("GET", "/restapis/abc123/deployments/dep1", "GetDeployment", "abc123"),
    # Stages
    ("POST", "/restapis/abc123/stages", "CreateStage", "abc123"),
    ("GET", "/restapis/abc123/stages/prod", "GetStage", "abc123"),
])
def test_apigateway_v1_action_extraction(
    method: str, path: str, expected_action: str,
    expected_resource: str | None,
) -> None:
    out = _apigateway_parse(method, path)
    assert out is not None, f"parser returned None for {method} {path}"
    assert out.action == expected_action, (
        f"{method} {path} → got {out.action}, expected {expected_action}"
    )
    assert out.resource_hint == expected_resource, (
        f"{method} {path} → got resource {out.resource_hint!r}, "
        f"expected {expected_resource!r}"
    )


@pytest.mark.parametrize("method,path,expected_action,expected_resource", [
    # apigatewayv2 — HTTP / WebSocket APIs
    ("GET", "/v2/apis", "GetApis", None),
    ("POST", "/v2/apis", "CreateApi", None),
    ("GET", "/v2/apis/api1", "GetApi", "api1"),
    ("PATCH", "/v2/apis/api1", "UpdateApi", "api1"),
    ("DELETE", "/v2/apis/api1", "DeleteApi", "api1"),
    # Routes
    ("GET", "/v2/apis/api1/routes", "GetRoutes", "api1"),
    ("POST", "/v2/apis/api1/routes", "CreateRoute", "api1"),
    ("GET", "/v2/apis/api1/routes/r1", "GetRoute", "api1"),
    ("DELETE", "/v2/apis/api1/routes/r1", "DeleteRoute", "api1"),
    # Integrations
    ("GET", "/v2/apis/api1/integrations", "GetIntegrations", "api1"),
    ("POST", "/v2/apis/api1/integrations", "CreateIntegration", "api1"),
    ("GET", "/v2/apis/api1/integrations/i1", "GetIntegration", "api1"),
])
def test_apigateway_v2_action_extraction(
    method: str, path: str, expected_action: str,
    expected_resource: str | None,
) -> None:
    out = _apigateway_parse(method, path, service="apigatewayv2")
    assert out is not None
    assert out.action == expected_action
    assert out.resource_hint == expected_resource


def test_apigateway_unknown_subresource_falls_back_to_composite() -> None:
    """Sub-resources we don't have a curated map for (e.g. /vpclinks)
    produce a composite '{Method}{Entity}' action — useful for audit
    even though it's not the canonical IAM action name."""
    out = _apigateway_parse("POST", "/vpclinks")
    assert out is not None
    assert out.action == "PostVpclinks"


def test_apigateway_bare_root_falls_back_safely() -> None:
    """A bare `/` against the apigateway endpoint shouldn't crash;
    fallback to the HTTP method."""
    out = _apigateway_parse("GET", "/")
    assert out is not None
    assert out.action == "GET"
