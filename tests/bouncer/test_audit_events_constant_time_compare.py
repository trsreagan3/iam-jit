"""§A99 — bearer-token comparison on /audit/events uses
``hmac.compare_digest`` (constant time), not the ``!=`` operator
(wall-clock-string compare, which leaks the configured token
byte-by-byte over enough requests).

Two layers of verification per ``docs/CONTRIBUTING.md``:

  1. *Code-shape* assertion (the observable state): the source line
     that gates the bearer header MUST call ``hmac.compare_digest``
     and MUST NOT use ``!=`` on the token value.
  2. *Behavioural* assertion: the live handler still returns 401 on
     missing header / 403 on wrong token / 200 on right token (the
     fix MUST NOT regress the existing auth gate).
"""

from __future__ import annotations

import inspect
import pathlib
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# 1. Code-shape: the OBSERVABLE STATE the fix exists to install.
# ---------------------------------------------------------------------------


def test_handler_uses_hmac_compare_digest_not_eq() -> None:
    """The /audit/events handler MUST gate the bearer token through
    ``hmac.compare_digest``. Pre-§A99 it used ``!=`` which leaks the
    configured token via response-time timing analysis.

    State-verified per ``docs/CONTRIBUTING.md`` — the source file on
    disk is the observable artefact, not the test fixture's mock."""
    from iam_jit.bouncer.audit_export import events_endpoint

    src_path = pathlib.Path(inspect.getfile(events_endpoint))
    src = src_path.read_text(encoding="utf-8")

    # The fix-site MUST use hmac.compare_digest on the bearer.
    assert "hmac.compare_digest(tok, require_bearer)" in src, (
        f"§A99 regression: {src_path} no longer routes the bearer "
        "compare through hmac.compare_digest. A wall-clock-string "
        "compare leaks the token byte-by-byte. See "
        "tests/bouncer/test_audit_events_constant_time_compare.py."
    )

    # And MUST NOT have reintroduced the leaky `!=` form on the
    # token (which is what pre-§A99 used). We scope this assertion
    # narrowly to the bearer comparison so unrelated `!=` uses
    # elsewhere in the file (e.g. method checks) don't trip it.
    assert "tok != require_bearer" not in src, (
        f"§A99 regression: {src_path} reintroduced a non-constant-"
        "time `tok != require_bearer` comparison. Use "
        "hmac.compare_digest instead."
    )


def test_hmac_module_is_imported() -> None:
    """The fix depends on ``import hmac`` at module top — a future
    refactor that drops the import would silently break the fix."""
    from iam_jit.bouncer.audit_export import events_endpoint

    src_path = pathlib.Path(inspect.getfile(events_endpoint))
    src = src_path.read_text(encoding="utf-8")
    assert "import hmac" in src, (
        f"§A99 regression: {src_path} dropped `import hmac`. "
        "The bearer-compare relies on it."
    )


# ---------------------------------------------------------------------------
# 2. Behavioural: the fix MUST NOT regress the existing auth gate.
# ---------------------------------------------------------------------------


def _make_app(
    audit_log_path: pathlib.Path, require_bearer: str | None = None,
):
    pytest.importorskip("aiohttp")
    from aiohttp import web

    from iam_jit.bouncer.audit_export.events_endpoint import (
        register_audit_events_route,
    )

    app = web.Application()
    register_audit_events_route(
        app, audit_log_path=audit_log_path, require_bearer=require_bearer,
    )
    return app


async def _client_request(
    audit_log_path: pathlib.Path,
    path: str,
    headers: dict[str, str] | None = None,
    require_bearer: str | None = None,
):
    from aiohttp.test_utils import TestClient, TestServer
    app = _make_app(audit_log_path, require_bearer=require_bearer)
    async with TestClient(TestServer(app)) as client:
        resp = await client.get(path, headers=headers or {})
        return resp.status


def _run(*args: Any, **kw: Any) -> int:
    import asyncio
    return asyncio.run(_client_request(*args, **kw))


@pytest.fixture
def empty_log(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "audit.jsonl"
    p.write_text("", encoding="utf-8")
    return p


def test_missing_authorization_returns_401(empty_log: pathlib.Path) -> None:
    """Behavioural regression check on §A99 — the fix MUST NOT
    accidentally allow unauthenticated access."""
    status = _run(
        empty_log, "/audit/events", require_bearer="correct-token",
    )
    assert status == 401


def test_wrong_token_returns_403(empty_log: pathlib.Path) -> None:
    """Behavioural regression check on §A99 — wrong token still
    rejected after switching to hmac.compare_digest."""
    status = _run(
        empty_log, "/audit/events",
        headers={"Authorization": "Bearer wrong-token"},
        require_bearer="correct-token",
    )
    assert status == 403


def test_right_token_returns_200(empty_log: pathlib.Path) -> None:
    """Behavioural regression check on §A99 — the correct token
    still passes."""
    status = _run(
        empty_log, "/audit/events",
        headers={"Authorization": "Bearer correct-token"},
        require_bearer="correct-token",
    )
    assert status == 200


def test_token_compare_does_not_leak_on_length_mismatch(
    empty_log: pathlib.Path,
) -> None:
    """``hmac.compare_digest`` accepts unequal-length strings without
    raising AND treats them as not-equal in constant time over the
    shorter string. A pre-§A99 ``!=`` implementation would similarly
    return False, but via a path that short-circuits. This test
    pins the post-§A99 contract: a 1-char token vs the configured
    32-char token still returns 403 (not an exception, not 500)."""
    status = _run(
        empty_log, "/audit/events",
        headers={"Authorization": "Bearer x"},
        require_bearer="x" * 32,
    )
    assert status == 403
