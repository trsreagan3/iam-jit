"""§A30 / #359 — proxy serve() SIGTERM-graceful-shutdown tests.

Before the fix: SIGTERM (the signal `systemctl stop`, `docker stop`,
and k8s pod termination send) killed the proxy WITHOUT running the
finally block in serve(). The SessionRecorder's still-open `.partial`
files survived; `iam-jit session list` showed them with
``is_partial=True`` indefinitely.

After the fix: serve() installs an asyncio signal handler on SIGTERM
that triggers the same `finally` cleanup chain as cancellation. The
recorder's stop() finalises every still-open session via atomic
rename.

We exercise both paths in this file:

  * an in-process asyncio test that runs serve() inside pytest's loop
    + raises SIGTERM at our own PID. The loop's signal handler
    intercepts the signal (so pytest doesn't die) + drives serve() to
    a clean shutdown. We assert .partial files are renamed.
  * a more permissive idempotency test that double-fires the shutdown
    Event — verifies the cleanup chain doesn't crash if the signal
    arrives twice.
  * a SIGINT regression test confirming the legacy
    KeyboardInterrupt → CancelledError path still finalises the
    recorder (we only added SIGTERM; SIGINT is unchanged but the test
    is cheap insurance against accidental regression).
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import signal
import socket
import sys
import time

import pytest

from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    register_session_recorder,
    serve,
)
from iam_jit.bouncer.store import BouncerStore


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def _wait_for_listen(host: str, port: int, *, retries: int = 50) -> None:
    for _ in range(retries):
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError(f"nothing listening on {host}:{port}")


SID_TEST = "deadbeef-1111-2222-3333-444444444444"


def _make_session_event(session_id: str) -> dict:
    return {
        "metadata": {"version": "1.1.0"},
        "time": int(time.time() * 1000),
        "class_uid": 6003,
        "class_name": "API Activity",
        "unmapped": {
            "iam_jit": {
                "agent": {
                    "session_id": session_id,
                    "name": "claude-code",
                },
            },
        },
    }


def _drive_event_into_registered_recorder(session_id: str) -> None:
    """Push one event through the proxy module's registered recorder.

    We bypass `_emit_audit_event_raw` (which has many other side
    effects) by reaching directly into the registry the proxy
    populates when `--record-sessions-dir` is set. This mirrors what
    the proxy hot-path does: the recorder receives the event,
    `extract_session_id` returns the session, and a `.partial` file
    opens for that session — which is exactly the state we want to
    catch with SIGTERM.
    """
    from iam_jit.bouncer import proxy as _proxy
    rec = getattr(_proxy, "_session_recorder", None)
    assert rec is not None, (
        "test wiring: proxy._session_recorder should have been set by "
        "serve() because --record-sessions-dir was configured"
    )
    rec.record(_make_session_event(session_id))


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="loop.add_signal_handler is POSIX-only",
)
@pytest.mark.asyncio
async def test_session_recorder_finalizes_partial_on_sigterm(
    tmp_path: pathlib.Path,
) -> None:
    """Drive a session through the recorder, send SIGTERM to our own
    PID, and assert the proxy's serve() finally chain finalised the
    .partial file before exit.
    """
    sessions_dir = tmp_path / "sessions"
    # Spin up serve() with --record-sessions-dir so it constructs +
    # registers a recorder + (per §A30 fix) installs the SIGTERM
    # handler.
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port, mode=ProxyMode.COOPERATIVE,
        record_sessions_dir=str(sessions_dir),
    )
    serve_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        # Push one event so the recorder opens a .partial.
        _drive_event_into_registered_recorder(SID_TEST)
        partial = sessions_dir / f"{SID_TEST}.ndjson.partial"
        final = sessions_dir / f"{SID_TEST}.ndjson"
        assert partial.exists(), (
            "test setup: .partial file should exist after first record()"
        )
        assert not final.exists()

        # The fix-under-test: SIGTERM should trigger serve()'s
        # finally chain → recorder.stop() → atomic rename.
        os.kill(os.getpid(), signal.SIGTERM)
        # Bounded wait — serve() should return well within a few
        # hundred ms once shutdown_event fires.
        await asyncio.wait_for(serve_task, timeout=5.0)

        # The core assertion: the .partial is now finalised.
        assert not partial.exists(), (
            "SIGTERM should have triggered recorder.stop() — "
            ".partial still present"
        )
        assert final.exists(), (
            "expected .ndjson final file after SIGTERM-driven shutdown"
        )
    finally:
        if not serve_task.done():
            serve_task.cancel()
            try:
                await serve_task
            except (asyncio.CancelledError, Exception):
                pass
        store.close()
        # Defensive — clear the singleton even if the test failed
        # before serve()'s finally ran.
        register_session_recorder(None)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="loop.add_signal_handler is POSIX-only",
)
@pytest.mark.asyncio
async def test_session_recorder_finalizes_partial_on_sigint(
    tmp_path: pathlib.Path,
) -> None:
    """Regression for the legacy SIGINT path.

    Before the fix, SIGINT already worked: Python's default handler
    raised KeyboardInterrupt → asyncio.run cancelled the task → the
    CancelledError ran the finally block → recorder.stop() finalised.
    The §A30 fix added SIGTERM without touching SIGINT, but we keep
    this test as insurance against accidental regression.

    Note: when the loop has no custom SIGINT handler, the asyncio
    loop translates SIGINT into CancelledError on the running task.
    We cancel directly here to model the same end state without
    fighting pytest's own signal handling.
    """
    sessions_dir = tmp_path / "sessions"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port, mode=ProxyMode.COOPERATIVE,
        record_sessions_dir=str(sessions_dir),
    )
    serve_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        _drive_event_into_registered_recorder(SID_TEST)
        partial = sessions_dir / f"{SID_TEST}.ndjson.partial"
        final = sessions_dir / f"{SID_TEST}.ndjson"
        assert partial.exists()

        # Cancel directly to mirror what asyncio.run does on the
        # KeyboardInterrupt SIGINT path the CLI relies on.
        serve_task.cancel()
        try:
            await asyncio.wait_for(serve_task, timeout=5.0)
        except asyncio.CancelledError:
            pass

        assert not partial.exists(), (
            "SIGINT/cancel should have triggered recorder.stop() — "
            ".partial still present"
        )
        assert final.exists()
    finally:
        if not serve_task.done():
            serve_task.cancel()
            try:
                await serve_task
            except (asyncio.CancelledError, Exception):
                pass
        store.close()
        register_session_recorder(None)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="loop.add_signal_handler is POSIX-only",
)
@pytest.mark.asyncio
async def test_session_recorder_idempotent_on_double_signal(
    tmp_path: pathlib.Path,
) -> None:
    """A SIGTERM that fires twice (the operator double-tapped, or a
    container runtime resent before the first was acked) MUST NOT
    crash. The first call drives shutdown; the second is absorbed by
    the Event already being set and stop()'s own idempotency."""
    sessions_dir = tmp_path / "sessions"
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port, mode=ProxyMode.COOPERATIVE,
        record_sessions_dir=str(sessions_dir),
    )
    serve_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        _drive_event_into_registered_recorder(SID_TEST)

        # Fire SIGTERM twice in rapid succession.
        os.kill(os.getpid(), signal.SIGTERM)
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.wait_for(serve_task, timeout=5.0)

        final = sessions_dir / f"{SID_TEST}.ndjson"
        partial = sessions_dir / f"{SID_TEST}.ndjson.partial"
        assert final.exists()
        assert not partial.exists()
    finally:
        if not serve_task.done():
            serve_task.cancel()
            try:
                await serve_task
            except (asyncio.CancelledError, Exception):
                pass
        store.close()
        register_session_recorder(None)
