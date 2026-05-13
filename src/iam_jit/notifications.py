"""Admin notifications.

Phase 2/3's provisioning + expiry handlers call into this module when
something needs admin attention — primarily deletion failures, but also
provisioning errors and other "something is stuck" conditions.

Backends:
  - `none`         (default; logs only)
  - `slack`        webhook URL to your team's incoming webhook
  - `ses_email`    AWS SES from the deployment's configured sender to a list of recipients

Configuration via env vars (also surfaced as SAM parameters in Phase 2):
  IAM_JIT_NOTIFY_TARGET           = none | slack | ses_email
  IAM_JIT_NOTIFY_SLACK_WEBHOOK    = https://hooks.slack.com/services/T.../B.../...
  IAM_JIT_NOTIFY_EMAIL_TO         = comma-separated list of admin emails

The scaffold is intentionally tiny so it can be expanded with PagerDuty,
Opsgenie, MS Teams, GitHub Issues, etc. as adopters need them.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger("iam_jit.notifications")


@dataclass(frozen=True)
class Notification:
    """One admin-facing notification."""

    severity: str  # "info" | "warning" | "error"
    title: str
    body: str
    request_id: str | None = None
    extra: dict[str, Any] | None = None


class NotificationBackend(Protocol):
    name: str

    def send(self, n: Notification) -> None: ...


class NoOpBackend:
    name = "none"

    def send(self, n: Notification) -> None:
        logger.info(
            "iam-jit notification (suppressed): severity=%s title=%s request_id=%s",
            n.severity,
            n.title,
            n.request_id,
        )


class SlackBackend:
    name = "slack"

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def send(self, n: Notification) -> None:
        import httpx

        emoji = {"info": ":information_source:", "warning": ":warning:", "error": ":rotating_light:"}.get(
            n.severity, ":bell:"
        )
        text_lines = [f"{emoji} *iam-jit {n.severity}* — {n.title}", n.body]
        if n.request_id:
            text_lines.append(f"_request_: `{n.request_id}`")
        if n.extra:
            text_lines.append("```\n" + json.dumps(n.extra, indent=2, default=str) + "\n```")
        try:
            httpx.post(self.webhook_url, json={"text": "\n".join(text_lines)}, timeout=10.0)
        except Exception:
            logger.exception("slack notification failed")


class SesEmailBackend:
    name = "ses_email"

    def __init__(self, sender: str, recipients: list[str]) -> None:
        self.sender = sender
        self.recipients = recipients

    def send(self, n: Notification) -> None:
        if not self.recipients:
            return
        try:
            import boto3

            body_lines = [n.body]
            if n.request_id:
                body_lines.append(f"\nRequest: {n.request_id}")
            if n.extra:
                body_lines.append("\nDetails:\n" + json.dumps(n.extra, indent=2, default=str))
            boto3.client("ses").send_email(
                Source=self.sender,
                Destination={"ToAddresses": self.recipients},
                Message={
                    "Subject": {"Data": f"[iam-jit {n.severity}] {n.title}"},
                    "Body": {"Text": {"Data": "\n".join(body_lines)}},
                },
            )
        except Exception:
            logger.exception("ses email notification failed")


def get_backend() -> NotificationBackend:
    target = (os.environ.get("IAM_JIT_NOTIFY_TARGET") or "none").lower()
    if target == "slack":
        url = os.environ.get("IAM_JIT_NOTIFY_SLACK_WEBHOOK") or ""
        if url:
            return SlackBackend(url)
    if target == "ses_email":
        sender = os.environ.get("IAM_JIT_SES_SENDER") or ""
        to = [
            r.strip()
            for r in (os.environ.get("IAM_JIT_NOTIFY_EMAIL_TO") or "").split(",")
            if r.strip()
        ]
        if sender and to:
            return SesEmailBackend(sender, to)
    return NoOpBackend()


def notify(notification: Notification) -> None:
    """Best-effort fire-and-forget notification.

    Notification failures are logged but never propagate — a notification
    failure must not break the underlying operation (provisioning, expiry,
    etc.).
    """
    try:
        get_backend().send(notification)
    except Exception:
        logger.exception("notification dispatch failed")
