"""#276 — `GET /schemas/config` HTTP endpoint for ibounce.

Serves the published `schemas/ibounce-config.schema.json` byte-for-byte
on the running bouncer's mgmt port so an agent can fetch the
authoritative wire shape without reaching out to GitHub.

Per [[cross-product-agent-parity]]: every Bounce product exposes the
same endpoint with its own product schema. The endpoint contract:

  GET /schemas/config
  Content-Type: application/schema+json
  Body: the embedded `<product>-config.schema.json` bytes

No auth required. The schema is non-sensitive metadata — the same
file ships in the repo under `schemas/<product>-config.schema.json`.
Per [[self-host-zero-billing-dependency]]: the bytes are loaded from
the in-tree file at process start (NOT a runtime fetch).

Per [[scorer-is-ground-truth]]: this endpoint serves WHATEVER the
embedded schema file says. No re-interpretation, no field-by-field
re-derivation.
"""

from __future__ import annotations

import pathlib

from aiohttp import web


def _locate_config_schema_path() -> pathlib.Path:
    """Locate the in-tree ibounce-config.schema.json.

    The schema lives at <repo-root>/schemas/ibounce-config.schema.json.
    This module is at <repo-root>/src/iam_jit/bouncer/schema_endpoint.py;
    walk up to the repo root + descend into schemas/.

    Returns the resolved Path. Caller is responsible for the
    "file not present" case (handler returns 404).
    """
    here = pathlib.Path(__file__).resolve()
    # bouncer/ -> iam_jit/ -> src/ -> <repo-root>
    repo_root = here.parents[3]
    return repo_root / "schemas" / "ibounce-config.schema.json"


def _load_config_schema_bytes() -> bytes | None:
    """Read the schema file's bytes at process start.

    Returns None when the file is missing (graceful — the endpoint
    surfaces 404 rather than failing the bouncer's bring-up).
    """
    path = _locate_config_schema_path()
    if not path.is_file():
        return None
    return path.read_bytes()


_SCHEMA_CACHE: bytes | None = _load_config_schema_bytes()


async def config_schema_handler(_req: web.Request) -> web.Response:
    """`GET /schemas/config` — return the embedded ibounce-config
    schema. Sets Content-Type: application/schema+json per
    JSON-Schema's IANA media type registration."""
    if _SCHEMA_CACHE is None:
        return web.json_response(
            {
                "error": "schema file not present in this build",
                "expected_path": str(_locate_config_schema_path()),
            },
            status=404,
        )
    return web.Response(
        body=_SCHEMA_CACHE,
        content_type="application/schema+json",
        charset="utf-8",
    )


def register_config_schema_route(app: web.Application) -> None:
    """Register `GET /schemas/config` on the given aiohttp app.
    Called once during proxy bring-up; idempotent (aiohttp will
    raise on re-registration so callers should not invoke twice)."""
    app.router.add_route("GET", "/schemas/config", config_schema_handler)
