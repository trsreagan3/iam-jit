"""Approver opens the queue and approves the pending request."""

from __future__ import annotations

from _lib import goto, record, _step


def scenario(page) -> None:
    goto(page, "/queue")
    _step(page, "approver queue — pending requests", hold_ms=2500)

    first = page.locator("table.requests a[href^='/requests/']").first
    if first.count() == 0:
        _step(page, "no pending requests", hold_ms=1500)
        return
    first.click()
    page.wait_for_load_state("networkidle")
    _step(page, "request detail — review", hold_ms=2500)

    approve = page.locator("button:has-text('Approve')").first
    if approve.count() > 0:
        approve.click()
        page.wait_for_load_state("networkidle")
        _step(page, "approved — state moves to active", hold_ms=3000)


if __name__ == "__main__":
    record("04-approver-approves", "email:approver@example.com", scenario)
