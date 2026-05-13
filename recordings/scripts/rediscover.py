"""Recording: an admin runs cross-account role rediscovery and reviews
the report.

(There is no admin web UI for /rediscover yet — this records the JSON
endpoint surface so the workflow is at least walked end-to-end.
Replace with the HTML view once `templates/admin/rediscover.html`
exists.)"""

from __future__ import annotations

from _lib import record


def scenario(page) -> None:
    # Show the GET surface first to set context (lists provisioned roles
    # iam-jit thinks it owns).
    page.goto("http://127.0.0.1:8000/api/v1/admin/provisioned")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)

    # Trigger the cross-account scan via fetch — Playwright doesn't
    # natively allow POST-via-navigation, so use page.evaluate.
    page.goto("about:blank")
    page.wait_for_timeout(500)
    result = page.evaluate(
        """async () => {
            const r = await fetch('http://127.0.0.1:8000/api/v1/admin/rediscover', {
                method: 'POST',
                credentials: 'include',
            });
            return { status: r.status, body: await r.text() };
        }"""
    )
    page.set_content(
        f"<pre style='font-family:monospace; padding:24px'>"
        f"POST /api/v1/admin/rediscover\nstatus: {result.get('status')}\n\n"
        f"{result.get('body', '')[:4000]}\n</pre>"
    )
    page.wait_for_timeout(3000)


if __name__ == "__main__":
    record("rediscover", "admin@example.com", scenario)
