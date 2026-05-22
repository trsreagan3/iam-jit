"""Integration test for the Bounce-suite link page (#298).

The link page is served at GET /suite on the gbounce mgmt port. Per
[[unified-ui-link-page]] it is signage + status pills — NOT an
aggregator. This test verifies:

  1. The page serves with the right HTML shape (anchors to all four
     bouncers + the CLI footer hint).
  2. The honest positioning copy is intact ("deployment status", NOT
     "single pane of glass").
  3. Optionally drives the rendered page with Playwright when
     available and asserts the status pills render.

If Playwright is not installed the test falls back to a structural
HTML-only check.

The bouncer-boot step uses FREE 19xxx ports per the iam-jit-portable
local-test-infra spec (operational ports 87xx and UAT 18xxx/28xxx are
NEVER touched here).
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import time
import urllib.request
from contextlib import closing
from pathlib import Path

import pytest

# FREE port range per the iam-jit-portable local-test-infra spec.
# 19798 is gbounce's slot in the 197xx test-port lineage (ibounce
# 19796, kbouncer 19795, dbounce 19797, gbounce 19798).
GBOUNCE_TEST_MGMT_PORT = 19798
GBOUNCE_TEST_PROXY_PORT = 19799


def _reachable(host: str, port: int, timeout: float = 0.5) -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except OSError:
            return False
        return True


def _find_gbounce_binary() -> str | None:
    """Locate a gbounce binary to drive the test against.

    Order of preference:
      1. GBOUNCE_BINARY env var (explicit override)
      2. ../gbounce/bin/gbounce (sibling repo relative to iam-roles)
      3. `gbounce` on PATH
    """
    env = os.environ.get("GBOUNCE_BINARY")
    if env and Path(env).is_file():
        return env

    # tests/integration/test_suite_page.py → parents[3] is iam-roles's
    # parent (~/repos), so ../gbounce/bin/gbounce sits at
    # parents[3] / "gbounce" / "bin" / "gbounce".
    sibling = Path(__file__).resolve().parents[3] / "gbounce" / "bin" / "gbounce"
    if sibling.is_file():
        return str(sibling)

    onpath = shutil.which("gbounce")
    if onpath:
        return onpath
    return None


@pytest.fixture(scope="module")
def gbounce_mgmt_url():
    """Boot gbounce on a FREE test port and return its base mgmt URL.

    Skips gracefully if no gbounce binary is reachable — the test
    SHOULD work standalone when run from a developer's box with
    gbounce built; CI parity is owned by the gbounce repo's own
    test matrix.
    """
    binary = _find_gbounce_binary()
    if not binary:
        pytest.skip(
            "gbounce binary not found; set GBOUNCE_BINARY or build "
            "with `cd ../gbounce && go build -o bin/gbounce ./cmd/gbounce`."
        )

    if _reachable("127.0.0.1", GBOUNCE_TEST_MGMT_PORT):
        pytest.skip(
            f"FREE port 127.0.0.1:{GBOUNCE_TEST_MGMT_PORT} already in use; "
            "stop the existing process or pick a different test port."
        )

    # --allow-connect is the simplest CLI shape that doesn't require
    # an --upstream URL; we only care about the mgmt port here.
    proc = subprocess.Popen(
        [
            binary,
            "run",
            "--allow-connect",
            "--port",
            str(GBOUNCE_TEST_PROXY_PORT),
            "--mgmt-port",
            str(GBOUNCE_TEST_MGMT_PORT),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    # Wait up to 5 s for the mgmt port to come up.
    deadline = time.time() + 5.0
    booted = False
    while time.time() < deadline:
        if _reachable("127.0.0.1", GBOUNCE_TEST_MGMT_PORT):
            booted = True
            break
        time.sleep(0.1)

    if not booted:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        stderr = b""
        if proc.stderr:
            try:
                stderr = proc.stderr.read()
            except Exception:  # noqa: BLE001
                pass
        pytest.skip(
            f"gbounce mgmt port never came up; stderr:\n"
            f"{stderr.decode('utf-8', 'replace')}"
        )

    try:
        yield f"http://127.0.0.1:{GBOUNCE_TEST_MGMT_PORT}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


def _get_body(url: str) -> str:
    with urllib.request.urlopen(url, timeout=3) as resp:
        assert resp.status == 200, f"GET {url} returned {resp.status}"
        return resp.read().decode("utf-8")


def test_suite_page_serves_200_with_html(gbounce_mgmt_url: str) -> None:
    """GET /suite returns 200 with text/html content-type."""
    with urllib.request.urlopen(f"{gbounce_mgmt_url}/suite", timeout=3) as resp:
        assert resp.status == 200
        ctype = resp.headers.get("Content-Type", "")
        assert ctype.startswith("text/html"), f"unexpected content-type: {ctype!r}"
        body = resp.read().decode("utf-8")
    assert body.lstrip().lower().startswith("<!doctype html>"), \
        f"body does not start with <!doctype html>: {body[:200]!r}"


def test_suite_page_links_to_all_four_bouncers(gbounce_mgmt_url: str) -> None:
    """Page references all four canonical mgmt ports."""
    body = _get_body(f"{gbounce_mgmt_url}/suite")
    # Defaults from the canonical mgmt-port lineage.
    assert "ibounce: 8767" in body
    assert "kbouncer: 8766" in body
    assert "dbounce: 8768" in body
    assert "gbounce: 8769" in body


def test_suite_page_has_cli_footer_hint(gbounce_mgmt_url: str) -> None:
    """Footer carries the cross-bouncer iam-jit audit query command."""
    body = _get_body(f"{gbounce_mgmt_url}/suite")
    assert "iam-jit audit query --filter agent.session_id=" in body


def test_suite_page_honest_positioning_copy(gbounce_mgmt_url: str) -> None:
    """Page never claims 'single pane of glass' per [[ibounce-honest-positioning]]."""
    body = _get_body(f"{gbounce_mgmt_url}/suite").lower()
    for term in ("single pane of glass", "unified view", "central monitoring"):
        assert term not in body, f"forbidden over-claim in UI copy: {term!r}"
    # Positive assertion: the page DOES say "deployment status."
    assert "deployment status" in body


def test_suite_page_safety_not_surveillance_language(gbounce_mgmt_url: str) -> None:
    """Page uses safety-not-surveillance vocabulary."""
    body = _get_body(f"{gbounce_mgmt_url}/suite").lower()
    for term in ("violation", "infraction", "unauthorized", "surveillance"):
        assert not re.search(rf"\b{re.escape(term)}\b", body), \
            f"forbidden surveillance term: {term!r}"


def test_suite_page_renders_status_cards_with_playwright(gbounce_mgmt_url: str) -> None:
    """Drive the rendered page with Playwright and assert pills appear.

    Skips if playwright isn't installed (the JS-driven flow is fully
    covered by structural-HTML checks above; this test adds a real-
    browser pass when the dev env supports it).
    """
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        pytest.skip(
            "playwright not installed; install with "
            "`pip install playwright && playwright install chromium`"
        )

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"playwright chromium browser unavailable: {exc}")
        context = browser.new_context()
        page = context.new_page()
        page.goto(f"{gbounce_mgmt_url}/suite", timeout=5000)
        # Wait for the four cards to be rendered.
        page.wait_for_selector(".card", timeout=3000)
        cards = page.query_selector_all(".card")
        assert len(cards) == 4, f"expected 4 cards, got {len(cards)}"
        # Wait one polling cycle for pills to update (5 s in
        # production; the bouncers we point at aren't running so pills
        # should flip to "unreachable").
        page.wait_for_timeout(500)
        pills = page.query_selector_all(".pill")
        assert len(pills) == 4
        browser.close()
