"""Submit a request via paste-mode."""

from __future__ import annotations

from _lib import BASE_URL, goto, record, _step


_POLICY = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::analytics-prod",
        "arn:aws:s3:::analytics-prod/*"
      ]
    }
  ]
}"""


def scenario(page) -> None:
    goto(page, "/requests/new/paste")
    _step(page, "paste-mode form", hold_ms=1500)

    page.fill(
        "textarea[name=description]",
        "Read-only access to analytics-prod for debugging yesterday's pipeline run.",
    )
    _step(page, "description filled", hold_ms=800)

    page.fill("textarea[name=policy]", _POLICY)
    _step(page, "policy filled", hold_ms=800)

    page.fill("input[name=accounts]", "060392206767")
    page.fill("input[name=duration_hours]", "8")
    _step(page, "account + duration", hold_ms=800)

    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")
    _step(page, "submitted — request detail page", hold_ms=3500)


if __name__ == "__main__":
    record("02-submit-request-paste-mode", "email:dev@example.com", scenario)
