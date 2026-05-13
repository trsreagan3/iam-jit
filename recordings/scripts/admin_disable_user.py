"""Admin disables a misbehaving user via the JSON API."""

from __future__ import annotations

import json

from _lib import goto, record, _step


def scenario(page) -> None:
    goto(page, "/")
    _step(page, "disable badactor via API", hold_ms=1500)

    result = page.evaluate(
        """async () => {
            const r = await fetch(
                '/api/v1/users/email:badactor@example.com',
                {
                    method: 'PATCH',
                    headers: {'Content-Type': 'application/json'},
                    credentials: 'include',
                    body: JSON.stringify({enabled: false}),
                },
            );
            return {status: r.status, body: await r.text()};
        }"""
    )
    page.set_content(
        f"<pre style='font-family:monospace; padding:24px; "
        f"color:#33ff66; background:#000;'>"
        f"PATCH /api/v1/users/email:badactor@example.com\n"
        f"{json.dumps({'enabled': False}, indent=2)}\n\n"
        f"→ HTTP {result['status']}\n{result['body']}</pre>"
    )
    _step(page, "user disabled — sessions revoked at next request", hold_ms=3500)


if __name__ == "__main__":
    record("09-admin-disable-user", "email:admin@example.com", scenario)
