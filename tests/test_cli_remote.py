"""Tests for `iam-jit remote …` CLI surface (#698 MED-2).

The new `revoke` subcommand mirrors `cancel`'s shape but hits the
admin-only `/api/v1/requests/{id}/revoke` endpoint that previously
had no CLI surface.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from unittest import mock

from click.testing import CliRunner

from iam_jit.cli_remote import remote


@contextmanager
def _patched_httpx(captured: list[dict]):
    """Patch httpx.Client so subcommand POSTs land in `captured`
    instead of going to the wire. The fake returns 200/{ok:true}."""
    fake = mock.MagicMock()
    fake.__enter__.return_value = fake
    fake.__exit__.return_value = None

    def _post(path, json=None, **kwargs):
        captured.append({"method": "POST", "path": path, "json": json})
        resp = mock.MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"ok": True, "request_id": "req-xyz"}
        return resp

    fake.post.side_effect = _post
    with mock.patch("httpx.Client", return_value=fake):
        yield captured


def test_remote_revoke_posts_to_revoke_endpoint_with_reason() -> None:
    """`iam-jit remote revoke <id> --reason <text>` posts to
    /api/v1/requests/{id}/revoke with {reason: <text>}."""
    captured: list[dict] = []
    runner = CliRunner()
    with _patched_httpx(captured):
        result = runner.invoke(
            remote,
            [
                "revoke", "req-xyz",
                "--reason", "rotation per quarterly review",
                "--url", "https://iam-jit.example.com",
                "--token", "iamjit_test_token",
            ],
        )
    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    call = captured[0]
    assert call["path"] == "/api/v1/requests/req-xyz/revoke"
    assert call["json"] == {"reason": "rotation per quarterly review"}
    # Response body emitted to stdout as JSON.
    body = json.loads(result.output)
    assert body == {"ok": True, "request_id": "req-xyz"}


def test_remote_revoke_requires_reason_flag() -> None:
    """--reason is required (the server demands it for the audit trail;
    the CLI fails fast instead of bouncing through a 400)."""
    captured: list[dict] = []
    runner = CliRunner()
    with _patched_httpx(captured):
        result = runner.invoke(
            remote,
            [
                "revoke", "req-xyz",
                "--url", "https://iam-jit.example.com",
                "--token", "iamjit_test_token",
            ],
        )
    assert result.exit_code != 0
    assert "--reason" in result.output.lower()
    # No HTTP call made — short-circuited at Click parsing.
    assert captured == []


def test_remote_cancel_still_works() -> None:
    """Regression: adding `revoke` next to `cancel` didn't break
    `cancel`'s endpoint or argument shape."""
    captured: list[dict] = []
    runner = CliRunner()
    with _patched_httpx(captured):
        result = runner.invoke(
            remote,
            [
                "cancel", "req-xyz",
                "--reason", "no longer needed",
                "--url", "https://iam-jit.example.com",
                "--token", "iamjit_test_token",
            ],
        )
    assert result.exit_code == 0, result.output
    assert captured[0]["path"] == "/api/v1/requests/req-xyz/cancel"
    assert captured[0]["json"] == {"reason": "no longer needed"}
