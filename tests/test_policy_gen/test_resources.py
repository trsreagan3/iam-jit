"""Tests for resource extraction from task descriptions."""

from __future__ import annotations

from iam_jit.policy_gen.resources import extract_resources, _construct_arn
from iam_jit.policy_gen.result import GenerationContext


def _ctx() -> GenerationContext:
    return GenerationContext(account_id="123456789012", region="us-east-1")


def test_explicit_arn_in_description():
    r = extract_resources(
        "read from arn:aws:s3:::prod-logs/2026-05-*",
        _ctx(),
    )
    assert any("prod-logs" in res.arn for res in r)


def test_named_s3_bucket_forward():
    r = extract_resources("in bucket prod-logs", _ctx())
    assert any(res.service_kind == "s3-bucket" and "prod-logs" in res.arn for res in r)


def test_named_s3_bucket_reverse():
    r = extract_resources("the prod-logs bucket", _ctx())
    assert any(res.service_kind == "s3-bucket" and "prod-logs" in res.arn for res in r)


def test_lambda_function_forward():
    r = extract_resources("invoke function deploy-api now", _ctx())
    assert any(
        res.service_kind == "lambda-function" and "deploy-api" in res.arn
        for res in r
    )


def test_stopwords_block_preposition_capture():
    """`function for incident` should NOT extract "for" as a function name."""
    r = extract_resources(
        "deploy my lambda function for incident response",
        _ctx(),
    )
    extracted_names = [res.arn.rsplit(":", 1)[-1] for res in r if res.service_kind == "lambda-function"]
    assert "for" not in extracted_names, f"got {extracted_names}"


def test_dynamodb_table_reverse_pattern():
    r = extract_resources("update the orders table", _ctx())
    assert any(
        res.service_kind == "dynamodb-table" and "orders" in res.arn
        for res in r
    )


def test_iam_role_extraction():
    r = extract_resources("assume the deploy-admin role", _ctx())
    assert any(
        res.service_kind == "iam-role" and "deploy-admin" in res.arn
        for res in r
    )


def test_no_context_produces_wildcard_segments():
    """When account/region are unset, ARN gets `*` in those segments."""
    r = extract_resources(
        "invoke function deploy-api",
        GenerationContext(),  # no account_id, no region
    )
    arn = next(res.arn for res in r if res.service_kind == "lambda-function")
    assert ":*:" in arn  # region or account or both wildcarded


def test_partition_respected_in_constructed_arn():
    arn = _construct_arn(
        "s3-bucket", "prod-logs",
        partition="aws-us-gov", region="us-gov-west-1", account="123456789012",
    )
    assert arn == "arn:aws-us-gov:s3:::prod-logs"


def test_kms_alias_form():
    arn = _construct_arn(
        "kms-key", "alias/prod-encryption",
        partition="aws", region="us-east-1", account="123456789012",
    )
    assert arn == "arn:aws:kms:us-east-1:123456789012:alias/prod-encryption"


def test_kms_key_id_form():
    arn = _construct_arn(
        "kms-key", "abcd1234-1234-1234-1234-123456789012",
        partition="aws", region="us-east-1", account="123456789012",
    )
    assert "key/abcd1234" in arn
