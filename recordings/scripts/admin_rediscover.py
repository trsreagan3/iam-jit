"""Admin runs cross-account role rediscovery."""

from __future__ import annotations

from _lib import goto, record, _step


def scenario(page) -> None:
    goto(page, "/admin/rediscover")
    _step(page, "rediscover — initial state", hold_ms=2500)

    # Trigger the scan. (The fixture has one registered account that
    # we can't actually assume into without AWS, so the report shows
    # an inaccessible-account row — useful to demo the error UX.)
    btn = page.locator("button[type=submit]").first
    if btn.count() > 0:
        btn.click()
        page.wait_for_load_state("networkidle")
        _step(page, "report rendered — buckets + errors", hold_ms=4000)
    else:
        _step(page, "(no run-scan button)", hold_ms=2000)


if __name__ == "__main__":
    record("07-admin-cross-account-rediscover", "email:admin@example.com", scenario)
