from __future__ import annotations

import pathlib

import pytest
from fastapi.testclient import TestClient

from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore


@pytest.fixture
def client(tmp_path: pathlib.Path) -> TestClient:
    requests_dir = tmp_path / "requests"
    requests_dir.mkdir()
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(
        "schema_version: 1\n"
        "auth_mode: local\n"
        "users:\n"
        "  - id: email:alice@example.com\n"
        "    roles: [admin]\n"
    )
    app = create_app(
        request_store=FilesystemStore(requests_dir),
        user_store=FileUserStore(str(users_yaml)),
    )
    return TestClient(app)


def test_healthz_unauthenticated(client: TestClient) -> None:
    """BB-13 / BB3-03 closure: /healthz returns the bare minimum
    needed for a load-balancer liveness probe — status + version.
    The full security_posture object moved to the admin route."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body
    # The leaky fields are GONE from /healthz.
    assert "auth_mode" not in body
    assert "security_posture" not in body
    assert "user_config_source" not in body
    assert "llm_backend" not in body


def test_healthz_does_not_require_auth(client: TestClient) -> None:
    # No cookie, no Authorization header.
    resp = client.get("/healthz", cookies=None)
    assert resp.status_code == 200


def test_app_state_carries_stores(client: TestClient) -> None:
    app = client.app
    assert app.state.request_store is not None
    assert app.state.user_store is not None
