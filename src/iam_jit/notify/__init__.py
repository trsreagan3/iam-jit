"""Notification channels for bouncer deny / pending-approval events.

This package collects the operator-facing notification CHANNELS that
fire when a bouncer denies a request (or queues a self-grant for
approval). It is deliberately small + additive:

  - :mod:`iam_jit.notify.slack` — Slack incoming-webhook (and optional
    bot-token) channel. Default-OFF; fail-soft; never logs or leaks the
    webhook URL / bot token.

Why a new package rather than extending :mod:`iam_jit.notifications`?
That module is the *admin operational* surface (provisioning failures,
expiry errors) and :mod:`iam_jit.approval_notifier` is the
*new-request* approver surface. This package is the *deny-event*
surface specifically — the "your bouncer caught N things" channel that
ADOPT-8 (#732) wires off the existing ``--notify-denies`` /
``StructuredDenyResponse`` deny path and the §A25 pending-approval
queue. Keeping it separate avoids overloading any one module and makes
the deny-notify channel independently testable.
"""

from __future__ import annotations

__all__: list[str] = []
