"""#276 — tests for `GET /schemas/config`.

Confirms the embedded ibounce-config.schema.json is reachable from
the bouncer's HTTP surface + the served bytes match the in-tree file
byte-for-byte.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from iam_jit.bouncer.schema_endpoint import (
    _locate_config_schema_path,
    register_config_schema_route,
)


@pytest.fixture
def schema_path() -> pathlib.Path:
    return _locate_config_schema_path()


async def _client_with_endpoint() -> TestClient:
    app = web.Application()
    register_config_schema_route(app)
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    return client


async def test_schema_endpoint_serves_embedded_schema_bytes(
    schema_path: pathlib.Path,
) -> None:
    client = await _client_with_endpoint()
    try:
        resp = await client.get("/schemas/config")
        assert resp.status == 200
        assert resp.headers["Content-Type"].startswith("application/schema+json")
        body = await resp.read()
        # Byte-identical to the in-tree file at process start. Drift
        # surface: a copy-of-a-copy in the binary vs. the published
        # schema would erode trust in `GET /schemas/config`.
        assert body == schema_path.read_bytes()
    finally:
        await client.close()


async def test_schema_endpoint_returns_parseable_json_schema() -> None:
    client = await _client_with_endpoint()
    try:
        resp = await client.get("/schemas/config")
        body = await resp.json()
        assert body.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
        assert body.get("title", "").startswith("ibounce config")
        # Post-#288 wire-shape parity check.
        sv = body["properties"]["schema_version"]
        assert sv["type"] == "string"
        assert sv["enum"] == ["1.0"]
        assert body["properties"]["product"]["enum"] == ["ibounce"]
    finally:
        await client.close()


def test_schema_file_is_in_tree(schema_path: pathlib.Path) -> None:
    """Sanity: the file the endpoint serves actually exists on disk
    in the published schemas/ directory."""
    assert schema_path.is_file(), f"missing in-tree schema: {schema_path}"
    body = json.loads(schema_path.read_text())
    assert body["properties"]["product"]["enum"] == ["ibounce"]
