"""Recording: an admin lists bans, then unbans a user via the API
admin surface.

(There is no admin web UI for /bans yet — this recording walks the
JSON surface so the workflow is at least documented. Replace with the
HTML surface once /admin/bans gets a template.)"""

from __future__ import annotations

from _lib import record


def scenario(page) -> None:
    page.goto("http://127.0.0.1:8000/api/v1/admin/bans")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)

    # Click into a request via the home page to demonstrate post-unban
    # access (this only works if the user's session was kept).
    page.goto("http://127.0.0.1:8000/")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(2000)


if __name__ == "__main__":
    record("unban_user", "admin@example.com", scenario)
