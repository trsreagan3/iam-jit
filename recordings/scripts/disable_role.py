"""Recording: an admin manually revokes an active grant before its expiry."""

from __future__ import annotations

from _lib import record


def scenario(page) -> None:
    # Open the home dashboard, find an active request, click into it,
    # then revoke. Falls back to /queue if home doesn't surface
    # provisioned grants for the admin persona.
    page.goto("http://127.0.0.1:8000/")
    page.wait_for_load_state("networkidle")
    active = page.locator("a[href^='/requests/']").first
    if active.count() == 0:
        page.goto("http://127.0.0.1:8000/queue")
        page.wait_for_load_state("networkidle")
        active = page.locator("a[href^='/requests/']").first
        if active.count() == 0:
            page.wait_for_timeout(2000)
            return
    active.click()
    page.wait_for_load_state("networkidle")

    revoke_btn = page.locator("button:has-text('Revoke')").first
    if revoke_btn.count() > 0:
        revoke_btn.click()
        # If a reason field appears, fill it.
        reason = page.locator("input[name=reason], textarea[name=reason]").first
        if reason.count() > 0:
            reason.fill("manual revoke for recording demo")
            page.locator("button[type=submit]").first.click()
        page.wait_for_load_state("networkidle")
    page.wait_for_timeout(2000)


if __name__ == "__main__":
    record("disable_role", "admin@example.com", scenario)
