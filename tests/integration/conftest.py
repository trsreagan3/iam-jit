"""Fixtures for integration tests.

Integration tests assume Docker-hosted services are reachable. If they
aren't, individual tests skip gracefully — never hard-fail. Bring services
up with `scripts/test-local.sh up` before running, or run the all-in-one:

    scripts/test-local.sh integration
"""

from __future__ import annotations

import os
import socket
from contextlib import closing

import pytest


def _reachable(host: str, port: int, timeout: float = 0.5) -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except OSError:
            return False
        return True


@pytest.fixture(scope="session")
def localstack_endpoint() -> str:
    """URL of a reachable LocalStack instance, or skip the test."""
    url = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
    host = url.split("://", 1)[1].split(":")[0]
    port = int(url.rsplit(":", 1)[1])
    if not _reachable(host, port):
        pytest.skip(
            f"LocalStack not reachable at {url}. "
            "Start it with `scripts/test-local.sh up` or set LOCALSTACK_ENDPOINT."
        )
    return url


@pytest.fixture(scope="session")
def ollama_endpoint() -> str:
    """URL of a reachable Ollama instance, or skip the test."""
    url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    host = url.split("://", 1)[1].split(":")[0]
    port = int(url.rsplit(":", 1)[1])
    if not _reachable(host, port):
        pytest.skip(
            f"Ollama not reachable at {url}. "
            "Start it with `ollama serve` (or `scripts/test-local.sh up` for the docker stack), "
            "and pull a small model: `scripts/pull-test-models.sh`."
        )
    return url


@pytest.fixture
def localstack_iam(localstack_endpoint: str, monkeypatch: pytest.MonkeyPatch) -> object:
    """boto3 IAM client pointed at LocalStack."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    import boto3

    return boto3.client("iam", endpoint_url=localstack_endpoint, region_name="us-east-1")
