"""MRR-2 F2 — structured 500 catch-all in the FastAPI app.

Closes the CRYPTIC global 500 surface
(``app.py:458-461`` per docs/MRR-2-ERROR-PATH-AUDIT-2026-05-24.md
commit 4cc6435).

Per ``docs/CONTRIBUTING.md`` state-verification convention: every
assertion verifies the **observable** response shape AND the
server-side log carries a correlatable error_id — not just that
``status_code == 500``. Inner exception text MUST stay server-side
(info-disclosure mitigation for the work-AWS deploy).
"""

from __future__ import annotations

import logging
import pathlib

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from iam_jit.app import create_app
from iam_jit.store import FilesystemStore
from iam_jit.users_store import FileUserStore


_SECRET_INNER_MARKER = "INNER_EXCEPTION_TEXT_THAT_MUST_NOT_LEAK_DEADBEEF"


@pytest.fixture
def client_and_caplog(
    tmp_path: pathlib.Path,
    caplog: pytest.LogCaptureFixture,
) -> tuple[TestClient, pytest.LogCaptureFixture]:
    """Build an app with an extra synthetic route that raises a
    distinctive exception so we can verify (a) the inner text never
    reaches the client, (b) the server log carries the error_id."""
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
    # Inject a route that raises an exception carrying a known marker
    # so we can assert it is NOT leaked downstream.
    synthetic = APIRouter()

    @synthetic.get("/__mrr2_synthetic_500__")
    def _raise():  # pragma: no cover - executed via TestClient
        raise RuntimeError(_SECRET_INNER_MARKER)

    app.include_router(synthetic)

    caplog.set_level(logging.ERROR, logger="iam_jit")
    return TestClient(app, raise_server_exceptions=False), caplog


def _extract_error_id(body: dict) -> str:
    eid = body.get("error_id")
    assert isinstance(eid, str), f"error_id missing or not str: {body!r}"
    return eid


def test_500_response_has_structured_envelope(
    client_and_caplog,
) -> None:
    """Test 1 — trigger synthetic 500 → response has error_id (ULID
    shape) + error_code + route_path + recommended_action."""
    client, _ = client_and_caplog
    resp = client.get("/__mrr2_synthetic_500__")
    assert resp.status_code == 500
    body = resp.json()
    # Required structured fields.
    assert "error_id" in body
    assert "error_code" in body
    assert "route_path" in body
    assert "recommended_action" in body
    # Field-level shape.
    error_id = _extract_error_id(body)
    assert error_id.startswith("err_"), error_id
    # ULID body is 26 Crockford-base32 chars.
    ulid_body = error_id[len("err_"):]
    assert len(ulid_body) == 26, f"ULID body wrong length: {ulid_body!r}"
    assert ulid_body.isupper() or all(
        c in "0123456789ABCDEFGHJKMNPQRSTVWXYZ" for c in ulid_body
    ), f"ULID body not Crockford base32: {ulid_body!r}"
    assert body["error_code"] == "UNHANDLED_EXCEPTION"
    assert body["route_path"] == "/__mrr2_synthetic_500__"
    assert error_id in body["recommended_action"]


def test_500_log_line_carries_matching_error_id(
    client_and_caplog,
) -> None:
    """Test 2 — server-side log line has the same error_id + full
    traceback (so support can correlate the operator's id with the
    actual exception)."""
    client, caplog = client_and_caplog
    resp = client.get("/__mrr2_synthetic_500__")
    assert resp.status_code == 500
    body = resp.json()
    error_id = _extract_error_id(body)

    # The error_id MUST appear in the captured ERROR-level log.
    log_text = "\n".join(rec.getMessage() for rec in caplog.records)
    assert error_id in log_text, (
        f"error_id {error_id!r} not found in server logs; correlation "
        f"impossible. Log lines: {log_text!r}"
    )
    # The full traceback MUST be present (logger.exception attaches
    # exc_info; LogRecord carries it).
    exc_info_records = [r for r in caplog.records if r.exc_info]
    assert exc_info_records, (
        "no LogRecord carried exc_info — the traceback was not "
        "captured server-side; operator has no way to debug"
    )


def test_500_response_does_not_leak_inner_exception_text(
    client_and_caplog,
) -> None:
    """Test 3 — inner exception text MUST NOT appear in HTTP response
    body. This is the info-disclosure mitigation for the work-AWS
    deploy (compliance teams + downstream proxies see response bodies)."""
    client, _ = client_and_caplog
    resp = client.get("/__mrr2_synthetic_500__")
    assert resp.status_code == 500
    raw_body = resp.text
    assert _SECRET_INNER_MARKER not in raw_body, (
        f"inner exception text leaked into response body: {raw_body!r}"
    )
    assert "Traceback" not in raw_body
    assert "RuntimeError" not in raw_body


def test_500_response_keeps_security_headers(
    client_and_caplog,
) -> None:
    """Regression — the BB6-01 invariant (security headers on every
    response, including uncaught-exception paths) must still hold
    after the F2 fix."""
    client, _ = client_and_caplog
    resp = client.get("/__mrr2_synthetic_500__")
    assert resp.status_code == 500
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Content-Security-Policy" in resp.headers
