"""Recording: an admin disables a misbehaving user."""

from __future__ import annotations

from _lib import record


def scenario(page) -> None:
    page.goto("http://127.0.0.1:8000/admin/users")
    page.wait_for_load_state("networkidle")
    # Find the disable button for badactor@example.com.
    target_row = page.locator("tr:has-text('badactor@example.com')").first
    if target_row.count() == 0:
        page.wait_for_timeout(2000)
        return
    disable_btn = target_row.locator(
        "button:has-text('Disable'), a:has-text('Disable')"
    ).first
    if disable_btn.count() > 0:
        disable_btn.click()
        page.wait_for_load_state("networkidle")
    page.wait_for_timeout(2000)


if __name__ == "__main__":
    record("disable_user", "admin@example.com", scenario)
