"""Blanket fuzz coverage for JSON-body POST routes.

Premise: ANY JSON body a client can POST must produce a 4xx response,
NEVER a 5xx (the canonical "schema validator should be the only
gatekeeper" rule). UX round-2 caught a violation in
/api/v1/requests; this test extends the same assertion to every
JSON-body POST endpoint so the same shape of bug can't ship again.

Each route is hit with a small set of "garbage" payloads:
  - Empty body
  - Non-dict top-level (string, list, int)
  - Random-key dict
  - Common type-confusion (int where string expected, list where dict, etc.)

A response in the 4xx range (including 422 from FastAPI body parsing,
401/403 from auth, 400 from app-level schema, 404 from path) is
acceptable. A 5xx is a bug.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


# Authenticated JSON-body POST endpoints under the iam-jit API surface.
# Path-parametric routes (e.g., /requests/{id}/comments) are listed with
# a known-good ID where the test will substitute a real one if needed,
# OR with a synthetic ID that should produce 404 not 5xx.
_JSON_POST_ROUTES = [
    "/api/v1/requests",
    "/api/v1/requests/preview",
    "/api/v1/intake/turn",
    "/api/v1/feedback/scoring",
    "/api/v1/blacklist",
    "/api/v1/policy/analyze",
    "/api/v1/tokens",
    "/api/v1/users",
    "/api/v1/accounts",
    "/api/v1/accounts/onboarding/preview",
]


_GARBAGE_PAYLOADS: list[tuple[str, Any]] = [
    ("empty_object", {}),
    ("random_keys", {"random": "garbage", "with": [1, 2, 3]}),
    ("nested_garbage", {"spec": 42, "metadata": "string-not-dict"}),
    ("very_nested", {"a": {"b": {"c": {"d": {"e": "f"}}}}}),
    ("array_of_arrays", {"items": [[1, 2], [3, 4]]}),
    ("mixed_null_field", {"spec": None, "metadata": None}),
]


def _ids(item: tuple[str, Any]) -> str:
    return item[0]


@pytest.mark.parametrize("payload", _GARBAGE_PAYLOADS, ids=_ids)
@pytest.mark.parametrize("path", _JSON_POST_ROUTES)
def test_authenticated_post_route_no_5xx_on_garbage(
    as_dev: TestClient, path: str, payload: tuple[str, Any],
) -> None:
    """Any garbage JSON body to a POST route must produce 4xx not 5xx."""
    _, body = payload
    resp = as_dev.post(path, json=body)
    assert resp.status_code < 500, (
        f"POST {path} with payload {body!r} returned {resp.status_code}\n"
        f"Body: {resp.text[:400]}"
    )


# Top-level non-dict bodies — these often crash naive handlers that
# do `body.get("...")` without checking type. Sent as raw JSON so
# FastAPI passes them through to the route's parser.
@pytest.mark.parametrize("path", _JSON_POST_ROUTES)
@pytest.mark.parametrize("non_dict", [
    "just-a-string",
    42,
    [1, 2, 3],
    True,
    None,
])
def test_authenticated_post_route_no_5xx_on_non_dict_body(
    as_dev: TestClient, path: str, non_dict: Any,
) -> None:
    resp = as_dev.post(path, json=non_dict)
    assert resp.status_code < 500, (
        f"POST {path} with non-dict body {non_dict!r} returned "
        f"{resp.status_code}. Body: {resp.text[:400]}"
    )


# Same fuzz, UNAUTHENTICATED. Unauthenticated POSTs should always
# 401 BEFORE any payload parsing — but if a route is mis-decorated
# (auth gate after body parsing) a malformed body could 5xx before
# auth fires. Defensive coverage.
@pytest.mark.parametrize("path", _JSON_POST_ROUTES)
def test_unauth_post_route_no_5xx_on_garbage(
    client: TestClient, path: str,
) -> None:
    resp = client.post(path, json={"random": "garbage"})
    assert resp.status_code < 500, (
        f"Unauthenticated POST {path} returned {resp.status_code}. "
        f"Should be 401 (auth) or 4xx (validation), never 5xx. "
        f"Body: {resp.text[:400]}"
    )
