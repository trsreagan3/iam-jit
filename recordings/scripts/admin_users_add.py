"""Admin adds a user via the JSON API.

There's no dedicated /admin/users HTML page yet — the user-management
surface is JSON. For the recording we hit the API via fetch() from
the browser context (so the cookie auth flows naturally) and show
the JSON request + response rendered in the page."""

from __future__ import annotations

import json

from _lib import BASE_URL, goto, record, _step


_NEW_USER = {
    "id": "email:newhire@example.com",
    "display_name": "New Hire",
    "roles": ["requester"],
    "enabled": True,
}


def scenario(page) -> None:
    goto(page, "/")  # any same-origin page so the fetch works
    _step(page, "preparing to add a new user via API", hold_ms=1500)

    result = page.evaluate(
        """async (body) => {
            const r = await fetch('/api/v1/users', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'include',
                body: JSON.stringify(body),
            });
            return {status: r.status, body: await r.text()};
        }""",
        _NEW_USER,
    )
    rendered = (
        f"<pre style='font-family:monospace; padding:24px; "
        f"color:#33ff66; background:#000;'>"
        f"POST /api/v1/users\n{json.dumps(_NEW_USER, indent=2)}\n\n"
        f"→ HTTP {result['status']}\n{result['body']}</pre>"
    )
    page.set_content(rendered)
    _step(page, "user added — list refreshes", hold_ms=3500)

    list_result = page.evaluate(
        """async () => {
            const r = await fetch('/api/v1/users', {credentials: 'include'});
            return await r.text();
        }"""
    )
    page.set_content(
        f"<pre style='font-family:monospace; padding:24px; "
        f"color:#33ff66; background:#000;'>"
        f"GET /api/v1/users\n\n{list_result}</pre>"
    )
    _step(page, "GET /api/v1/users — newhire is in the list", hold_ms=3500)


if __name__ == "__main__":
    record("08-admin-add-user", "email:admin@example.com", scenario)
