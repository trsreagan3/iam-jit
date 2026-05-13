"""Show the /all page (the previously-broken link, now fixed)."""

from __future__ import annotations

from _lib import goto, record, _step


def scenario(page) -> None:
    goto(page, "/")
    _step(page, "home dashboard — recent requests", hold_ms=2000)

    goto(page, "/all")
    _step(page, "all requests across every state", hold_ms=3500)


if __name__ == "__main__":
    record("03-all-requests-page", "email:approver@example.com", scenario)
