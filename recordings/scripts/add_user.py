"""Recording: an admin adds a new requester via the users admin page."""

from __future__ import annotations

from _lib import record


def scenario(page) -> None:
    page.goto("http://127.0.0.1:8000/admin/users")
    page.wait_for_load_state("networkidle")
    # Form layout varies; try common selectors.
    email_input = page.locator("input[name=email], input[name=user_id]").first
    if email_input.count() > 0:
        email_input.fill("newhire@example.com")
    role_input = page.locator("select[name=role], input[name=role]").first
    if role_input.count() > 0:
        try:
            role_input.select_option("requester")
        except Exception:
            role_input.fill("requester")
    submit = page.locator("button[type=submit]").first
    if submit.count() > 0:
        submit.click()
        page.wait_for_load_state("networkidle")
    page.wait_for_timeout(2000)


if __name__ == "__main__":
    record("add_user", "admin@example.com", scenario)
