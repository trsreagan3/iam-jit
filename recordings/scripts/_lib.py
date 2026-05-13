"""Shared helpers for recording scripts.

Each scenario script imports `record(name, persona, scenario)` and
passes a function that takes a Playwright `page` already signed-in
as the requested persona. The library handles:

  - launching Chromium with video recording
  - signing in via the dev-mode session-cookie shortcut (skips the
    email magic-link UX, which we don't need to demonstrate
    end-to-end here)
  - cleanup on success or failure

We sign in via a directly-injected session cookie minted with the
deployment's MagicLinkSecret. That works because `iam-jit serve`
in dev mode shares the secret across all clients.
"""

from __future__ import annotations

import os
import pathlib
import sys
from typing import Callable

from playwright.sync_api import Page, sync_playwright


BASE_URL = os.environ.get("IAM_JIT_BASE_URL", "http://127.0.0.1:8765")
SECRET = os.environ.get(
    "IAM_JIT_MAGIC_LINK_SECRET", "recording-secret-aaaaaaaaaaaaaaaaaaaaaaaaaa"
)
OUTPUT_DIR = pathlib.Path(__file__).resolve().parents[1] / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _sign_session(user_id: str) -> str:
    """Mint a session cookie from outside the server. The server
    verifies it with the same secret."""
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))
    from iam_jit import auth as auth_mod

    return auth_mod.sign_session(SECRET, user_id)


def _step(page: Page, label: str, *, hold_ms: int = 1500) -> None:
    """Pause for `hold_ms` so the recording shows the result of the
    last action.

    Important headless-Chromium quirk: when the page is COMPLETELY
    STATIC (no DOM mutation, no animation, no scroll), Chromium's
    compositor doesn't tick and Playwright's video recorder writes
    zero frames during the wait — even though wall time advances.
    Result: a 5-second `wait_for_timeout` produces a 1-second video.

    We work around it by tickling the page every ~250ms with a
    no-op DOM mutation (toggle a hidden data attribute on <body>).
    Each mutation forces one composited frame, so a 5s hold lands
    ~20 frames in the output — enough to read the page in playback.
    """
    if label:
        try:
            page.evaluate(
                "(t) => { document.title = `iam-jit · ${t}`; }", label
            )
        except Exception:
            pass

    # Inject a continuous CSS animation so headless Chromium's
    # compositor keeps producing frames during the static-page wait.
    # Without this, a wait_for_timeout(5000) on a static page produces
    # ~1s of recorded video because no paints happen.
    try:
        page.add_style_tag(
            content=(
                "@keyframes _rec_keep_alive { "
                "  0% { caret-color: transparent; } "
                "  50% { caret-color: rgba(0,0,0,0.001); } "
                "  100% { caret-color: transparent; } "
                "} "
                "html { animation: _rec_keep_alive 0.2s infinite linear; }"
            )
        )
    except Exception:
        pass
    page.wait_for_timeout(hold_ms)


def record(
    name: str,
    persona: str,
    scenario: Callable[[Page], None],
    *,
    width: int = 1280,
    height: int = 720,
) -> None:
    """Run `scenario(page)` against the iam-jit dev server, recording
    the session to `output/<name>.webm`.

    `persona` is the user_id (e.g. "email:admin@example.com") that
    the page will be signed in as before scenario() runs.
    """
    out_path = OUTPUT_DIR / f"{name}.webm"
    print(f"→ recording '{name}' as {persona}")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            record_video_dir=str(OUTPUT_DIR),
            record_video_size={"width": width, "height": height},
            viewport={"width": width, "height": height},
        )
        # Inject the session cookie BEFORE any page navigation.
        context.add_cookies(
            [
                {
                    "name": "iam_jit_session",
                    "value": _sign_session(persona),
                    "url": BASE_URL,
                    "httpOnly": True,
                    "sameSite": "Lax",
                }
            ]
        )
        page = context.new_page()
        try:
            scenario(page)
        except Exception as e:
            # Capture whatever's on screen so the failure is visible
            # in the resulting video.
            try:
                page.evaluate(
                    "(m) => { document.title = `iam-jit · ERROR: ${m}`; }",
                    str(e)[:80],
                )
                page.wait_for_timeout(2000)
            except Exception:
                pass
            print(f"  ! scenario raised: {type(e).__name__}: {e}", file=sys.stderr)
        finally:
            page.close()
            context.close()
            browser.close()

    # Playwright writes video to a randomly-named .webm. Rename to ours.
    candidates = sorted(
        (
            p for p in OUTPUT_DIR.iterdir()
            if p.suffix == ".webm" and p.name != out_path.name
        ),
        key=lambda p: p.stat().st_mtime,
    )
    if not candidates:
        print(f"  ! no .webm produced for {name}", file=sys.stderr)
        return
    newest = candidates[-1]
    if out_path.exists():
        out_path.unlink()
    newest.rename(out_path)
    print(f"  ✓ {out_path}")


def goto(page: Page, path: str) -> None:
    """Navigate + wait for network idle. Most pages are CSR-light
    enough that networkidle is the right signal."""
    target = BASE_URL.rstrip("/") + path
    if os.environ.get("IAM_JIT_RECORDING_DEBUG") == "1":
        print(f"  goto: {target}", flush=True)
    response = page.goto(target)
    if os.environ.get("IAM_JIT_RECORDING_DEBUG") == "1":
        print(
            f"    → status={response.status if response else 'None'}, "
            f"url={page.url}",
            flush=True,
        )
    try:
        page.wait_for_load_state("networkidle", timeout=8000)
    except Exception as e:
        # Some pages (with the SSE chat endpoint, CSS/JS preloads, etc.)
        # never reach a strict networkidle. Don't let that abort the
        # recording — we'd rather capture a partially-loaded page than
        # zero frames.
        if os.environ.get("IAM_JIT_RECORDING_DEBUG") == "1":
            print(f"    networkidle timed out ({e}); continuing anyway", flush=True)
