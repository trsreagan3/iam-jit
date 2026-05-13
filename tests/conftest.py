"""Shared fixtures for the iam-jit test suite.

Defaults to fully-mocked unit tests (Tier 1). Integration and e2e tests opt
in via pytest markers and live under tests/integration/ and tests/e2e/.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest


@pytest.fixture
def mock_aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set fake AWS credentials so boto3 doesn't try to use real ones."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def moto_iam(mock_aws_env: None) -> Iterator[object]:
    """Yield a boto3 IAM client backed by moto's in-memory implementation."""
    from moto import mock_aws as moto_mock_aws

    with moto_mock_aws():
        import boto3

        yield boto3.client("iam", region_name="us-east-1")


@pytest.fixture
def moto_sts(mock_aws_env: None) -> Iterator[object]:
    """Yield a boto3 STS client backed by moto."""
    from moto import mock_aws as moto_mock_aws

    with moto_mock_aws():
        import boto3

        yield boto3.client("sts", region_name="us-east-1")


@pytest.fixture
def moto_events(mock_aws_env: None) -> Iterator[object]:
    """Yield a boto3 EventBridge client backed by moto."""
    from moto import mock_aws as moto_mock_aws

    with moto_mock_aws():
        import boto3

        yield boto3.client("events", region_name="us-east-1")
