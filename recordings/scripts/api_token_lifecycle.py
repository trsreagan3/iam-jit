"""Mint an API token from the UI, then revoke it."""

from __future__ import annotations

from _lib import goto, record, _step


def scenario(page) -> None:
    goto(page, "/tokens")
    _step(page, "tokens page — initial state", hold_ms=2500)

    # Look for the form to create a new token.
    label_input = page.locator("input[name=label]").first
    if label_input.count() > 0:
        label_input.fill("agent-onboarding")
        submit = page.locator("button[type=submit]").first
        if submit.count() > 0:
            submit.click()
            page.wait_for_load_state("networkidle")
            _step(page, "new token minted — raw value shown once", hold_ms=4000)

    # Revoke it (find a Revoke button anywhere on the page).
    revoke = page.locator("button:has-text('Revoke'), a:has-text('Revoke')").first
    if revoke.count() > 0:
        revoke.click()
        page.wait_for_load_state("networkidle")
        _step(page, "token revoked", hold_ms=2500)


if __name__ == "__main__":
    record("13-api-token-lifecycle", "email:admin@example.com", scenario)
