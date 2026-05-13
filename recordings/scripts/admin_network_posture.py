"""Admin views the network-posture page."""

from __future__ import annotations

from _lib import goto, record, _step


def scenario(page) -> None:
    goto(page, "/admin/network")
    _step(page, "network posture — current allowlist + recommendation", hold_ms=4500)


if __name__ == "__main__":
    record("10-admin-network-posture", "email:admin@example.com", scenario)
