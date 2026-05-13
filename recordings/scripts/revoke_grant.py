"""Admin manually revokes an active grant before its expiry."""

from __future__ import annotations

from _lib import goto, record, _step


def scenario(page) -> None:
    goto(page, "/admin/provisioned")
    _step(page, "find an active grant to revoke", hold_ms=2000)

    first = page.locator("table.data a[href^='/requests/']").first
    if first.count() == 0:
        _step(page, "no active grants to revoke in this fixture", hold_ms=2000)
        return
    first.click()
    page.wait_for_load_state("networkidle")
    _step(page, "request detail — admin actions", hold_ms=2500)

    # The revoke button may live behind a fieldset on the detail page;
    # locate by visible text.
    revoke = page.locator("button:has-text('Revoke'), a:has-text('Revoke')").first
    if revoke.count() > 0:
        revoke.click()
        reason = page.locator("input[name=reason], textarea[name=reason]").first
        if reason.count() > 0:
            reason.fill("compliance audit — pulling early")
            page.locator("button[type=submit]").first.click()
            page.wait_for_load_state("networkidle")
        _step(page, "grant revoked — state=revoked", hold_ms=3000)
    else:
        _step(page, "(no revoke button on this page yet)", hold_ms=2000)


if __name__ == "__main__":
    record("06-admin-revoke-active-grant", "email:admin@example.com", scenario)
