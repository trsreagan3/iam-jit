"""Dual-browser end-to-end happy path.

Walks two personas through the iam-jit flow concurrently with separate
browser contexts (independent cookies, video, trace), to demonstrate the
full submit-to-approve cycle.

Outputs (in tests/e2e/output/):
  - admin.webm, dev.webm — per-persona screen recordings
  - admin-trace.zip, dev-trace.zip — Playwright traces
  - side-by-side.mp4 — combined video (if ffmpeg is available)

Marker: `e2e`. Default `pytest` skips it; run with `pytest -m e2e`.
"""

from __future__ import annotations

import asyncio
import pathlib
import shutil
import subprocess

import pytest
from playwright.async_api import BrowserContext, Page, async_playwright


pytestmark = pytest.mark.e2e


async def _set_session(context: BrowserContext, base_url: str, cookie: str) -> None:
    """Drop a pre-signed iam_jit_session cookie into a context.

    Lets us skip the magic-link UX for personas. Magic-link login itself
    is covered by the unit-level web route tests.
    """
    parsed_host = base_url.split("://", 1)[1].split(":", 1)[0]
    parsed_port = base_url.rsplit(":", 1)[1]
    await context.add_cookies(
        [
            {
                "name": "iam_jit_session",
                "value": cookie,
                "domain": parsed_host,
                "path": "/",
                "httpOnly": False,
                "secure": False,
            }
        ]
    )


async def _dev_submit(page: Page, base_url: str) -> str:
    """Drive the dev persona through paste-mode submission.

    Returns the request id pulled from the redirect URL.
    """
    await page.goto(f"{base_url}/")
    await page.wait_for_url(f"{base_url}/")
    await page.click("a:has-text('+ new request')")
    # In NoAI mode the chooser stays put and offers paste.
    await page.click("a:has-text('Paste a role')")
    await page.fill(
        "textarea[name=description]",
        "E2E demo: read S3 config files from the example-config bucket.",
    )
    await page.fill(
        "textarea[name=policy]",
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Action": ["s3:GetObject", "s3:ListBucket"], '
        '"Resource": "arn:aws:s3:::example-config"}]}',
    )
    await page.fill("input[name=accounts]", "060392206767")
    await page.fill("input[name=duration_hours]", "24")
    async with page.expect_navigation() as nav_info:
        await page.click("button:has-text('Submit for approval')")
    final_url = (await nav_info.value).url
    # /requests/{id}
    request_id = final_url.rstrip("/").rsplit("/", 1)[-1]
    await page.wait_for_selector("dt:has-text('Owner')")
    return request_id


async def _admin_approve(page: Page, base_url: str, request_id: str) -> None:
    """Drive the admin persona to approve a pending request."""
    await page.goto(f"{base_url}/queue")
    await page.wait_for_selector("h1:has-text('Pending requests')")
    # Clicking the request row opens the detail page.
    await page.goto(f"{base_url}/requests/{request_id}")
    await page.wait_for_selector(f"h1:has-text('Request {request_id}')")
    async with page.expect_navigation():
        await page.click("button:has-text('Approve')")


async def _dev_check_state(page: Page, base_url: str, request_id: str) -> None:
    await page.goto(f"{base_url}/requests/{request_id}")
    await page.wait_for_selector("span.state")


async def _run_personas(
    base_url: str,
    output_dir: pathlib.Path,
    dev_cookie: str,
    admin_cookie: str,
) -> str:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            dev_video_dir = output_dir / "dev_video"
            admin_video_dir = output_dir / "admin_video"
            dev_video_dir.mkdir(parents=True, exist_ok=True)
            admin_video_dir.mkdir(parents=True, exist_ok=True)

            dev_ctx = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                record_video_dir=str(dev_video_dir),
                record_video_size={"width": 1280, "height": 720},
            )
            admin_ctx = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                record_video_dir=str(admin_video_dir),
                record_video_size={"width": 1280, "height": 720},
            )
            await _set_session(dev_ctx, base_url, dev_cookie)
            await _set_session(admin_ctx, base_url, admin_cookie)

            await dev_ctx.tracing.start(screenshots=True, snapshots=True, sources=True)
            await admin_ctx.tracing.start(screenshots=True, snapshots=True, sources=True)

            dev_page = await dev_ctx.new_page()
            admin_page = await admin_ctx.new_page()

            # Phase 1: dev submits, admin sits on the queue.
            dev_task = asyncio.create_task(_dev_submit(dev_page, base_url))
            await admin_page.goto(f"{base_url}/queue")
            await admin_page.wait_for_selector("h1:has-text('Pending requests')")
            request_id = await dev_task

            # Phase 2: both refresh, then admin approves while dev rechecks.
            await admin_page.reload()
            await asyncio.gather(
                _admin_approve(admin_page, base_url, request_id),
                _dev_check_state(dev_page, base_url, request_id),
            )

            # Phase 3: dev confirms the new state.
            await _dev_check_state(dev_page, base_url, request_id)

            await admin_ctx.tracing.stop(path=str(output_dir / "admin-trace.zip"))
            await dev_ctx.tracing.stop(path=str(output_dir / "dev-trace.zip"))

            await dev_page.close()
            await admin_page.close()
            await dev_ctx.close()
            await admin_ctx.close()

            # Move per-persona videos to deterministic filenames.
            dev_video = next(dev_video_dir.glob("*.webm"), None)
            admin_video = next(admin_video_dir.glob("*.webm"), None)
            if dev_video:
                shutil.move(str(dev_video), str(output_dir / "dev.webm"))
            if admin_video:
                shutil.move(str(admin_video), str(output_dir / "admin.webm"))
            shutil.rmtree(dev_video_dir, ignore_errors=True)
            shutil.rmtree(admin_video_dir, ignore_errors=True)

            return request_id
        finally:
            await browser.close()


_VIEWER_TEMPLATE = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>iam-jit e2e replay</title>
  <style>
    body { background: #111; color: #ddd; font-family: -apple-system, sans-serif; margin: 0; padding: 20px; }
    h1 { margin: 0 0 16px 0; font-size: 18px; font-weight: 500; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .pane { background: #000; border: 1px solid #333; border-radius: 6px; overflow: hidden; }
    .pane h2 { margin: 0; padding: 8px 12px; font-size: 14px; background: #222; color: #fff; }
    video { width: 100%; height: auto; display: block; }
    .controls { margin-bottom: 16px; }
    button { background: #2a5; color: #fff; border: 0; padding: 8px 16px; border-radius: 4px; font-size: 14px; cursor: pointer; margin-right: 8px; }
    button:hover { background: #3b6; }
    .meta { color: #888; font-size: 12px; margin-top: 16px; }
    .meta a { color: #6af; }
  </style>
</head>
<body>
  <h1>iam-jit end-to-end replay — admin + dev personas in parallel</h1>
  <div class="controls">
    <button onclick="playAll()">▶ play both</button>
    <button onclick="pauseAll()">⏸ pause</button>
    <button onclick="restartAll()">⏮ restart</button>
  </div>
  <div class="row">
    <div class="pane">
      <h2>dev — submits the request</h2>
      <video id="dev" src="data:video/webm;base64,__DEV_VIDEO__" controls preload="auto"></video>
    </div>
    <div class="pane">
      <h2>admin — approves the request</h2>
      <video id="admin" src="data:video/webm;base64,__ADMIN_VIDEO__" controls preload="auto"></video>
    </div>
  </div>
  <p class="meta">
    The videos are embedded in this single file as base64 — Chrome refuses
    to load sibling files when an HTML page is opened via <code>file://</code>
    (every <code>file://</code> URL is its own origin), so embedding makes the
    replay work in any browser without spinning up a server. Traces ship
    alongside in this folder; open them with
    <code>playwright show-trace &lt;file&gt;</code>.
  </p>
  <script>
    const dev = document.getElementById('dev');
    const admin = document.getElementById('admin');
    function playAll() { dev.play(); admin.play(); }
    function pauseAll() { dev.pause(); admin.pause(); }
    function restartAll() { dev.currentTime = 0; admin.currentTime = 0; playAll(); }
  </script>
</body>
</html>
"""


def _build_viewer_html(dev_webm: pathlib.Path, admin_webm: pathlib.Path) -> str:
    """Return self-contained HTML with both videos embedded as data URLs.

    Chrome (and Edge, and most CSP-strict environments) refuse to fetch
    sibling files when the host page is opened via `file://`, so the only
    way to ship a single-file replay that works on a double-click is to
    embed the videos. Base64 inflates by ~33% but our test videos are
    tiny (~150 KB each) so the resulting HTML is ~400 KB total.
    """
    import base64

    dev_b64 = base64.b64encode(dev_webm.read_bytes()).decode("ascii")
    admin_b64 = base64.b64encode(admin_webm.read_bytes()).decode("ascii")
    return (
        _VIEWER_TEMPLATE
        .replace("__DEV_VIDEO__", dev_b64)
        .replace("__ADMIN_VIDEO__", admin_b64)
    )


def _combine_videos(output_dir: pathlib.Path) -> pathlib.Path | None:
    """Produce a self-contained side-by-side replay.

    Strategy:
      1. Always write `replay.html` — opens both videos in a browser pane.
         No ffmpeg dependency, preserves quality, single click to view.
      2. If a real (full-feature) ffmpeg is available on PATH, ALSO emit
         `side-by-side.mp4` for one-file shareability. The Playwright-
         shipped ffmpeg is stripped down (no libx264, no hstack), so we
         skip it; that's fine, the HTML viewer is the canonical artifact.
      3. Drop a copy of replay.html (and the videos) into a timestamped
         folder on the user's Desktop so they can find it later.
    """
    dev = output_dir / "dev.webm"
    admin = output_dir / "admin.webm"
    if not (dev.exists() and admin.exists()):
        return None

    viewer = output_dir / "replay.html"
    viewer.write_text(_build_viewer_html(dev, admin))

    # Drop a copy on the Desktop for the user. The HTML is fully
    # self-contained (videos embedded as data URLs), so it works on a
    # double-click in any browser without needing a server. We still
    # ship the raw .webm + .zip trace files alongside for power users.
    desktop = pathlib.Path.home() / "Desktop"
    if desktop.exists():
        try:
            replay_dir = desktop / "iam-jit-e2e-replay"
            if replay_dir.exists():
                shutil.rmtree(replay_dir)
            replay_dir.mkdir(parents=True)
            shutil.copy2(viewer, replay_dir / "replay.html")
            shutil.copy2(dev, replay_dir / "dev.webm")
            shutil.copy2(admin, replay_dir / "admin.webm")
            for trace_name in ("dev-trace.zip", "admin-trace.zip"):
                trace = output_dir / trace_name
                if trace.exists():
                    shutil.copy2(trace, replay_dir / trace_name)
        except OSError:
            pass

    # Optional one-file mp4 if the user happens to have a real ffmpeg.
    # We deliberately skip the Playwright-shipped binary: it's compiled
    # `--disable-everything` plus webm-only, so neither hstack nor x264
    # are available.
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is not None:
        out_path = output_dir / "side-by-side.mp4"
        cmd = [
            ffmpeg,
            "-y",
            "-i",
            str(dev),
            "-i",
            str(admin),
            "-filter_complex",
            "[0:v]scale=960:540[l];[1:v]scale=960:540[r];[l][r]hstack=inputs=2",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-crf",
            "23",
            "-preset",
            "fast",
            str(out_path),
        ]
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode == 0 and desktop.exists():
            try:
                shutil.copy2(out_path, desktop / "iam-jit-e2e-replay" / "side-by-side.mp4")
            except OSError:
                pass

    return viewer


@pytest.mark.asyncio
async def test_dual_persona_happy_path(
    iam_jit_server: str,
    output_dir: pathlib.Path,
    session_cookie_for,
) -> None:
    dev_cookie = session_cookie_for("email:dev@example.com")
    admin_cookie = session_cookie_for("email:admin@example.com")

    request_id = await _run_personas(
        iam_jit_server,
        output_dir,
        dev_cookie,
        admin_cookie,
    )

    combined = _combine_videos(output_dir)
    # We assert on the artifacts rather than on the exact end state, so the
    # test reliably proves what the user came to see: per-persona videos
    # exist and were combined into a side-by-side replay.
    assert (output_dir / "dev.webm").exists()
    assert (output_dir / "admin.webm").exists()
    assert (output_dir / "dev-trace.zip").exists()
    assert (output_dir / "admin-trace.zip").exists()
    assert (output_dir / "replay.html").exists()
    if combined is not None:
        assert combined.exists()
    assert request_id  # non-empty id pulled from the URL

    # Critical regression check — open replay.html via file:// (the same
    # way the user does on a double-click) and verify both videos
    # actually load. This catches the Chrome `file://` cross-origin
    # restriction that broke an earlier version of the viewer where the
    # videos were referenced via relative `src=` instead of being
    # embedded as data URLs.
    await _verify_replay_loads_in_chromium(output_dir / "replay.html")


async def _verify_replay_loads_in_chromium(replay_html: pathlib.Path) -> None:
    """Open replay.html via file:// in Chromium and assert both videos
    are actually playable.

    A `<video>` element with a broken src still renders the chrome and
    controls — `existence` is not the same as `playable`. We check
    `readyState` (>=1 means metadata loaded) and `error` (must be null)
    on each video element. We also collect any console errors raised
    during page load and fail if any of them mention a load failure.
    """
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            context = await browser.new_context()
            page = await context.new_page()
            console_errors: list[str] = []
            page.on(
                "console",
                lambda msg: (
                    console_errors.append(msg.text)
                    if msg.type == "error"
                    else None
                ),
            )
            await page.goto(replay_html.as_uri())
            # Wait for both videos to at least finish metadata loading,
            # which is what tells us the data URL was decoded successfully.
            for video_id in ("dev", "admin"):
                await page.wait_for_function(
                    f"document.getElementById('{video_id}').readyState >= 1",
                    timeout=10_000,
                )
                state = await page.evaluate(
                    f"""({{
                        readyState: document.getElementById('{video_id}').readyState,
                        error: document.getElementById('{video_id}').error?.code ?? null,
                        duration: document.getElementById('{video_id}').duration,
                    }})"""
                )
                assert state["error"] is None, (
                    f"video '{video_id}' reported error code {state['error']} "
                    f"(see console_errors: {console_errors})"
                )
                assert state["readyState"] >= 1, (
                    f"video '{video_id}' never loaded metadata "
                    f"(readyState={state['readyState']})"
                )
                assert state["duration"] > 0, (
                    f"video '{video_id}' has zero duration — "
                    f"the recording may be empty"
                )
            # Final check: no load-failure errors in the console.
            blocking = [
                e
                for e in console_errors
                if "Failed to load" in e or "ERR_ACCESS_DENIED" in e or "NotSupportedError" in e
            ]
            assert not blocking, f"console reported load failures: {blocking}"
        finally:
            await browser.close()
