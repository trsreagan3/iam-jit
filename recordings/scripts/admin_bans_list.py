"""Admin views the current bans list (and unbans a user)."""

from __future__ import annotations

import json

from _lib import goto, record, _step


def scenario(page) -> None:
    goto(page, "/")

    # First, list current bans.
    listing = page.evaluate(
        """async () => {
            const r = await fetch('/api/v1/admin/bans', {credentials: 'include'});
            return {status: r.status, body: await r.text()};
        }"""
    )
    page.set_content(
        f"<pre style='font-family:monospace; padding:24px; "
        f"color:#33ff66; background:#000;'>"
        f"GET /api/v1/admin/bans\n\n"
        f"HTTP {listing['status']}\n{listing['body']}</pre>"
    )
    _step(page, "current bans list", hold_ms=3500)

    # Demo unban shape (no user actually banned in this fixture, so
    # we just show the call shape and the 404 response).
    unban = page.evaluate(
        """async () => {
            const r = await fetch(
                '/api/v1/admin/bans/email:demo@example.com/unban',
                {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    credentials: 'include',
                    body: JSON.stringify({reason: 'false positive — verified legitimate'}),
                },
            );
            return {status: r.status, body: await r.text()};
        }"""
    )
    page.set_content(
        f"<pre style='font-family:monospace; padding:24px; "
        f"color:#33ff66; background:#000;'>"
        f"POST /api/v1/admin/bans/&lt;user_id&gt;/unban\n"
        f"{json.dumps({'reason': 'false positive — verified legitimate'}, indent=2)}\n\n"
        f"HTTP {unban['status']}\n{unban['body']}</pre>"
    )
    _step(page, "unban call shape — 404 when user isn't banned", hold_ms=3500)


if __name__ == "__main__":
    record("11-admin-bans-and-unban", "email:admin@example.com", scenario)
