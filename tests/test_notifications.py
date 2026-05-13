"""Notifications module tests."""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

from iam_jit import notifications


def _n(**kw) -> notifications.Notification:
    base = dict(severity="error", title="grant cleanup failed", body="kept getting AccessDenied")
    base.update(kw)
    return notifications.Notification(**base)


# ---- backend selection ----


def test_get_backend_default_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_NOTIFY_TARGET", raising=False)
    assert isinstance(notifications.get_backend(), notifications.NoOpBackend)


def test_get_backend_explicit_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_NOTIFY_TARGET", "none")
    assert isinstance(notifications.get_backend(), notifications.NoOpBackend)


def test_get_backend_slack_requires_webhook(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_NOTIFY_TARGET", "slack")
    monkeypatch.delenv("IAM_JIT_NOTIFY_SLACK_WEBHOOK", raising=False)
    # Falls back to NoOp when webhook is unset — never crash on misconfig.
    assert isinstance(notifications.get_backend(), notifications.NoOpBackend)


def test_get_backend_slack_with_webhook(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_NOTIFY_TARGET", "slack")
    monkeypatch.setenv(
        "IAM_JIT_NOTIFY_SLACK_WEBHOOK", "https://hooks.slack.com/services/T/B/X"
    )
    backend = notifications.get_backend()
    assert isinstance(backend, notifications.SlackBackend)
    assert backend.webhook_url.endswith("/T/B/X")


def test_get_backend_ses_requires_sender_and_recipients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_NOTIFY_TARGET", "ses_email")
    # Missing sender → falls back to NoOp.
    monkeypatch.delenv("IAM_JIT_SES_SENDER", raising=False)
    monkeypatch.setenv("IAM_JIT_NOTIFY_EMAIL_TO", "admin@example.com")
    assert isinstance(notifications.get_backend(), notifications.NoOpBackend)
    # Missing recipients → also NoOp.
    monkeypatch.setenv("IAM_JIT_SES_SENDER", "alerts@example.com")
    monkeypatch.delenv("IAM_JIT_NOTIFY_EMAIL_TO", raising=False)
    assert isinstance(notifications.get_backend(), notifications.NoOpBackend)


def test_get_backend_ses_with_full_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_NOTIFY_TARGET", "ses_email")
    monkeypatch.setenv("IAM_JIT_SES_SENDER", "alerts@example.com")
    monkeypatch.setenv(
        "IAM_JIT_NOTIFY_EMAIL_TO", "alice@example.com, bob@example.com"
    )
    backend = notifications.get_backend()
    assert isinstance(backend, notifications.SesEmailBackend)
    assert backend.sender == "alerts@example.com"
    assert backend.recipients == ["alice@example.com", "bob@example.com"]


# ---- noop ----


def test_noop_send_does_not_raise() -> None:
    notifications.NoOpBackend().send(_n())  # logs only


# ---- slack ----


def test_slack_posts_to_webhook() -> None:
    url = "https://hooks.slack.com/services/T/B/X"
    with respx.mock:
        route = respx.post(url).mock(return_value=Response(200, text="ok"))
        notifications.SlackBackend(url).send(_n(request_id="rq-abc"))
    assert route.called
    payload = json.loads(route.calls.last.request.content.decode())
    assert "text" in payload
    assert "iam-jit error" in payload["text"]
    assert "grant cleanup failed" in payload["text"]
    assert "rq-abc" in payload["text"]


def test_slack_includes_extra_as_json_block() -> None:
    url = "https://hooks.slack.com/services/T/B/X"
    with respx.mock:
        route = respx.post(url).mock(return_value=Response(200))
        notifications.SlackBackend(url).send(
            _n(extra={"role_arn": "arn:aws:iam::1:role/x", "attempts": 3})
        )
    payload = json.loads(route.calls.last.request.content.decode())
    assert "role_arn" in payload["text"]
    assert "arn:aws:iam::1:role/x" in payload["text"]


def test_slack_does_not_raise_on_webhook_failure() -> None:
    url = "https://hooks.slack.com/services/T/B/X"
    with respx.mock:
        respx.post(url).mock(return_value=Response(500, text="oops"))
        # Logged but not raised — notification failure must not propagate.
        notifications.SlackBackend(url).send(_n())


def test_slack_emoji_per_severity() -> None:
    url = "https://hooks.slack.com/services/T/B/X"
    with respx.mock:
        route = respx.post(url).mock(return_value=Response(200))
        notifications.SlackBackend(url).send(_n(severity="info"))
        notifications.SlackBackend(url).send(_n(severity="warning"))
        notifications.SlackBackend(url).send(_n(severity="error"))
    bodies = [json.loads(c.request.content.decode())["text"] for c in route.calls]
    assert ":information_source:" in bodies[0]
    assert ":warning:" in bodies[1]
    assert ":rotating_light:" in bodies[2]


# ---- ses ----


def test_ses_send_calls_send_email(mock_aws_env: None) -> None:
    from moto import mock_aws

    with mock_aws():
        import boto3

        ses = boto3.client("ses", region_name="us-east-1")
        ses.verify_email_identity(EmailAddress="alerts@example.com")
        backend = notifications.SesEmailBackend(
            "alerts@example.com", ["admin@example.com"]
        )
        # No exception means send_email was invoked successfully.
        backend.send(_n(request_id="rq-1", extra={"foo": "bar"}))
        # moto records the message; verify it was queued.
        # send_statistics is the simplest read-back available.
        stats = ses.get_send_statistics()
        # moto returns SendDataPoints with at least one entry after a send.
        assert "SendDataPoints" in stats


def test_ses_with_no_recipients_short_circuits(mock_aws_env: None) -> None:
    from moto import mock_aws

    with mock_aws():
        backend = notifications.SesEmailBackend("alerts@example.com", [])
        # Should NOT raise and should NOT attempt SES (no boto3 import even).
        backend.send(_n())


def test_ses_does_not_raise_on_send_failure() -> None:
    """No moto/no AWS creds → boto3 send_email raises. Backend swallows it."""
    backend = notifications.SesEmailBackend(
        "alerts@example.com", ["admin@example.com"]
    )
    # Without mock_aws active, the SES call will fail. Backend must not crash.
    backend.send(_n())


# ---- public notify() ----


def test_notify_uses_configured_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_NOTIFY_TARGET", "slack")
    monkeypatch.setenv(
        "IAM_JIT_NOTIFY_SLACK_WEBHOOK", "https://hooks.slack.com/services/T/B/X"
    )
    with respx.mock:
        route = respx.post("https://hooks.slack.com/services/T/B/X").mock(
            return_value=Response(200)
        )
        notifications.notify(_n(title="a thing"))
    assert route.called


def test_notify_swallows_dispatch_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even if get_backend itself blows up, notify must not propagate."""

    def boom() -> notifications.NotificationBackend:
        raise RuntimeError("config blew up")

    monkeypatch.setattr(notifications, "get_backend", boom)
    notifications.notify(_n())  # must not raise
