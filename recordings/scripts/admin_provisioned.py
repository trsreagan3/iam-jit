"""Admin views the list of currently-provisioned IAM grants."""

from __future__ import annotations

from _lib import goto, record, _step


def scenario(page) -> None:
    goto(page, "/admin/provisioned")
    _step(page, "active iam-jit grants", hold_ms=3500)


if __name__ == "__main__":
    record("05-admin-provisioned-grants", "email:admin@example.com", scenario)
