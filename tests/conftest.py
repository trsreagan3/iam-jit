"""Shared fixtures for the iam-jit test suite.

Defaults to fully-mocked unit tests (Tier 1). Integration and e2e tests opt
in via pytest markers and live under tests/integration/ and tests/e2e/.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest


# ---------------------------------------------------------------------------
# Global env isolation (applies to EVERY test in the suite).
#
# `IAM_JIT_*` env vars get written by various tests (mostly via
# `local_server._set_local_env_defaults` which uses `os.environ.setdefault`
# bypassing monkeypatch). Those writes leaked across tests and caused
# 8 routes_accounts + routes_admin failures in the full-suite run that
# passed when targeted. Snapshot at session start + restore per test
# keeps every test starting from the same clean env.
# ---------------------------------------------------------------------------


_SESSION_IAM_JIT_ENV: dict[str, str] = {}


@pytest.fixture(scope="session", autouse=True)
def _snapshot_session_iam_jit_env() -> None:
    _SESSION_IAM_JIT_ENV.clear()
    _SESSION_IAM_JIT_ENV.update({
        k: v for k, v in os.environ.items() if k.startswith("IAM_JIT_")
    })


@pytest.fixture(autouse=True)
def _restore_iam_jit_env_per_test() -> Iterator[None]:
    """After every test, restore IAM_JIT_* env to the session-start
    snapshot. Catches the env-leak pattern globally so no test in
    the suite can pollute another's env."""
    try:
        yield
    finally:
        for k in list(os.environ.keys()):
            if k.startswith("IAM_JIT_") and k not in _SESSION_IAM_JIT_ENV:
                del os.environ[k]
        for k, v in _SESSION_IAM_JIT_ENV.items():
            os.environ[k] = v


@pytest.fixture
def mock_aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set fake AWS credentials so boto3 doesn't try to use real ones."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    # Critical for moto-backed tests: if the developer has ibounce wired
    # (AWS_ENDPOINT_URL=http://127.0.0.1:8767 — the normal dogfood state),
    # boto3 routes to the live proxy instead of moto's in-memory mock and the
    # test fails confusingly. Clear it so moto always intercepts. (UAT HIGH:
    # 36 tests failed silently in the wired-ibounce dev state.)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)


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
