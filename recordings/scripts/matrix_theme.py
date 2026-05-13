"""Matrix theme tour — quick navigation across the major surfaces so
the visual styling is captured."""

from __future__ import annotations

from _lib import goto, record, _step


def scenario(page) -> None:
    goto(page, "/")
    _step(page, "home dashboard", hold_ms=2500)

    goto(page, "/all")
    _step(page, "all requests page", hold_ms=2500)

    goto(page, "/admin/network")
    _step(page, "network posture", hold_ms=2500)

    goto(page, "/admin/provisioned")
    _step(page, "provisioned grants", hold_ms=2500)

    goto(page, "/admin/rediscover")
    _step(page, "cross-account rediscover", hold_ms=2500)

    goto(page, "/tokens")
    _step(page, "api tokens", hold_ms=2500)

    goto(page, "/")
    _step(page, "back to home", hold_ms=1500)


if __name__ == "__main__":
    record("01-matrix-theme-tour", "email:admin@example.com", scenario)
