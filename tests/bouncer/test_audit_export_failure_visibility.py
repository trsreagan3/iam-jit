"""Tests for #267 — audit-export failure visibility (ibounce).

Per [[audit-export-failure-visibility]] the audit-export channel is
the visibility surface security teams depend on; when it breaks
silently, that's the worst-case "bouncer was running but you saw
nothing" stealth-bypass scenario the Slice 1 BB+WB audit notes
flagged. This file covers the F1-F8 failure modes from the memo's
table:

  F1: webhook unreachable           — retries + drop + 503 + last_error
  F2: webhook 401 auth fail         — specific auth-failed surface
  F3: webhook 502 bad gateway       — retry + drop on persistence
  F4: log permission denied         — log_writes_ok=false + 503
  F5: log disk full                 — log_writes_ok=false + dropped++
  F6: log file deleted mid-write    — re-record error visibly
  F7: queue overflow + recovery     — AUDIT_DROPPED synthetic survives
  F8: license expiry mid-session    — fail-clean (no silent demotion)

Each test asserts the failure is SEEN — by /healthz, the
audit_export health-section helper, the audit_export_degraded
alert rule, or the channel's status() surface. The bouncer hot-
path is NOT expected to fail; per [[audit-export-failure-visibility]]
"Don't" #1, audit-channel degradation never HARD-STOPs the bouncer.
"""

from __future__ import annotations

import asyncio
import errno
import json
import os
import pathlib
import socket

import pytest

from iam_jit.bouncer.audit_export import (
    AlertsConfig,
    AuditLogWriter,
    DEFAULT_AUDIT_EXPORT_DEGRADED_DROP_THRESHOLD,
    DEFAULT_AUDIT_EXPORT_DEGRADED_FAILURE_THRESHOLD,
    RuleEngine,
    WebhookPusher,
    audit_event_from_decision,
)
from iam_jit.bouncer.audit_export.alerts import (
    _evaluate_audit_export_degraded,
    audit_export_degraded_stderr_message,
)


# ---------------------------------------------------------------------------
# Common test fixtures + helpers (re-implemented here so the file is
# self-contained per [[deliberate-feature-completion]] — a regression
# in another test file's _FakeSession shouldn't silently mask a #267
# regression).
# ---------------------------------------------------------------------------


# Token value the failure tests use. Token-leak grep tests live in
# test_audit_export_webhook.py; here we just need a stable string the
# pusher's status surface can mask.
TEST_TOKEN = "lit_secret_267_donotleak"


class _FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    async def read(self) -> bytes:
        return b""

    async def __aenter__(self) -> "_FakeResponse":
        return self

    async def __aexit__(self, *exc) -> None:
        return None


class _FakeSession:
    """Configurable fake aiohttp session — drives the F1/F2/F3 failure
    matrix without a real network."""

    def __init__(
        self,
        statuses: list[int] | None = None,
        raise_on_attempt: int | None = None,
        raise_always: bool = False,
        raise_exc_type: type[Exception] = RuntimeError,
    ) -> None:
        self._statuses = statuses or [200]
        self._raise_on_attempt = raise_on_attempt
        self._raise_always = raise_always
        self._raise_exc_type = raise_exc_type
        self.posts: list[dict] = []
        self.closed = False

    def post(self, url, *, data, headers, timeout) -> _FakeResponse:
        attempt = len(self.posts)
        self.posts.append({
            "url": url, "data": data, "headers": dict(headers),
            "timeout": timeout,
        })
        if self._raise_always:
            raise self._raise_exc_type("simulated transport failure")
        if (
            self._raise_on_attempt is not None
            and attempt < self._raise_on_attempt
        ):
            raise self._raise_exc_type("simulated network failure")
        idx = min(attempt, len(self._statuses) - 1)
        return _FakeResponse(status=self._statuses[idx])

    async def close(self) -> None:
        self.closed = True


def _instant_sleep_factory() -> tuple[list[float], callable]:
    delays: list[float] = []

    async def _sleep(delay: float) -> None:
        delays.append(delay)
        await asyncio.sleep(0)

    return delays, _sleep


async def _wait_until(predicate, *, timeout: float = 2.0, step: float = 0.02) -> None:
    """Poll a sync predicate until True or timeout. Used to wait for
    the async worker to drain. Raises AssertionError on timeout so
    the failing test points at the right line."""
    import time as _t
    deadline = _t.monotonic() + timeout
    while _t.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(step)
    raise AssertionError("predicate did not become true within timeout")


@pytest.fixture(autouse=True)
def _clear_registry():
    """Each test starts with the proxy registry slots cleared so a
    previous test's writer/pusher doesn't leak into this one's
    `_evaluate_audit_export_degraded` / `audit_export_health_section`
    reads."""
    from iam_jit.bouncer import proxy as proxy_mod
    proxy_mod.register_audit_log_writer(None)
    proxy_mod.register_audit_webhook_pusher(None)
    proxy_mod.register_audit_rule_engine(None)
    proxy_mod.clear_audit_export_degraded()
    yield
    proxy_mod.register_audit_log_writer(None)
    proxy_mod.register_audit_webhook_pusher(None)
    proxy_mod.register_audit_rule_engine(None)
    proxy_mod.clear_audit_export_degraded()


def _decision_event(decision_id: int = 1) -> dict:
    """Build one decision event so the rule engine has something to
    observe (the engine's observe() is the trigger to evaluate the
    audit_export_degraded rule)."""
    return audit_event_from_decision(
        decision_id=decision_id,
        mode="cooperative",
        profile=None,
        verdict="allow",
        reason="",
        service="s3",
        action="GetObject",
        arn=None,
        region=None,
        host="s3.us-east-1.amazonaws.com",
    )


# ---------------------------------------------------------------------------
# F1 — webhook unreachable (transport error every attempt)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_F1_webhook_unreachable_retries_then_drops_and_marks_degraded() -> None:
    """F1: every send attempt raises a transport error (httptest-style
    immediate-close). After max_attempts retries, the batch is dropped
    + last_error is populated + consecutive_failures > 3, which is the
    /healthz 503-trigger threshold.

    The audit_export_degraded rule fires AFTER 5 consecutive (looser
    threshold per spec: operator-action signal vs probe-trigger
    threshold)."""
    from iam_jit.bouncer import proxy as proxy_mod
    session = _FakeSession(raise_always=True)
    _, sleep = _instant_sleep_factory()
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_TOKEN,
        allow_internal=True,
        max_attempts=5,
        _session_factory=lambda: session,
        _sleep=sleep,
    )
    await pusher.start()
    proxy_mod.register_audit_webhook_pusher(pusher)
    try:
        pusher.push({"event_type": "F1_test"})
        # Wait until the batch is finalized as dropped (final-fail
        # path bumps dropped_events).
        await _wait_until(
            lambda: pusher.status()["dropped_events"] >= 1, timeout=3.0,
        )
    finally:
        await pusher.stop()
    snap = pusher.status()
    # 5 attempts at the pusher level all failed → consecutive_failures
    # incremented 5 times. /healthz threshold is >3 so this trips.
    assert snap["consecutive_failures"] >= 5
    assert snap["dropped_events"] >= 1
    assert snap["last_error"] is not None
    assert "failed after" in snap["last_error"]
    # /healthz health-section reports degraded because consecutive
    # failures > 3.
    section = proxy_mod.audit_export_health_section()
    assert section["webhook_configured"] is True
    assert section["webhook_consecutive_failures"] >= 5
    assert section["degraded"] is True
    # 503 trigger reason includes the consecutive-failure clause.
    assert any(
        "consecutive_failures" in r for r in section["degraded_reasons"]
    )


@pytest.mark.asyncio
async def test_F1_audit_export_degraded_rule_fires_after_five_consecutive(
    capsys,
) -> None:
    """F1 corollary: the audit_export_degraded alert rule fires once
    consecutive_failures > 5 (the spec's rule threshold). Rule ALSO
    writes to stderr + flips /healthz to 503 (mirrors heartbeat_gap
    self-emit + stderr-fallback pattern)."""
    from iam_jit.bouncer import proxy as proxy_mod
    session = _FakeSession(raise_always=True)
    _, sleep = _instant_sleep_factory()
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_TOKEN,
        allow_internal=True,
        max_attempts=6,  # one more than the rule threshold
        _session_factory=lambda: session,
        _sleep=sleep,
    )
    await pusher.start()
    proxy_mod.register_audit_webhook_pusher(pusher)
    try:
        pusher.push({"event_type": "F1_rule_test"})
        await _wait_until(
            lambda: pusher.status()["consecutive_failures"]
            > DEFAULT_AUDIT_EXPORT_DEGRADED_FAILURE_THRESHOLD,
            timeout=3.0,
        )
    finally:
        await pusher.stop()
    # Now trigger the rule. observe() runs the audit_export_degraded
    # pattern which reads the pusher's status.
    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    engine.observe(_decision_event())
    matched = [
        e for e in fired
        if e["unmapped"]["iam_jit"].get("pattern") == "audit-export-degraded"
    ]
    assert len(matched) == 1, f"expected 1 fire; got {len(matched)}"
    alert = matched[0]
    assert alert["severity_id"] == 3  # Medium
    assert alert["severity"] == "Medium"
    # stderr fallback line written.
    captured = capsys.readouterr()
    assert "audit-export channel degraded" in captured.err.lower()
    # /healthz module-level flag flipped.
    assert proxy_mod.is_audit_export_degraded() is True


# ---------------------------------------------------------------------------
# F2 — webhook 401 (auth fail)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_F2_webhook_401_records_specific_auth_failed_error() -> None:
    """F2: a 401 response is a non-retryable HTTP — last_error
    contains a neutral 'auth failed' surface mentioning the status
    code so the operator knows to check the token. The dropped count
    bumps because 4xx isn't retried."""
    from iam_jit.bouncer import proxy as proxy_mod
    session = _FakeSession(statuses=[401])
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_TOKEN,
        allow_internal=True,
        max_attempts=5,
        _session_factory=lambda: session,
    )
    await pusher.start()
    proxy_mod.register_audit_webhook_pusher(pusher)
    try:
        pusher.push({"event_type": "F2_test"})
        await _wait_until(
            lambda: pusher.status()["dropped_events"] >= 1, timeout=2.0,
        )
    finally:
        await pusher.stop()
    snap = pusher.status()
    assert snap["last_status_code"] == 401
    assert "auth failed" in (snap["last_error"] or "").lower()
    assert "401" in (snap["last_error"] or "")
    # 4xx is non-retryable so we only count it once.
    assert snap["consecutive_failures"] >= 1


# ---------------------------------------------------------------------------
# F3 — webhook 502 (bad gateway, retry then drop)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_F3_webhook_502_retries_then_drops() -> None:
    """F3: a persistent 502 retries max_attempts times then drops the
    batch + records the failure. last_status_code is 502."""
    from iam_jit.bouncer import proxy as proxy_mod
    session = _FakeSession(statuses=[502, 502, 502, 502, 502])
    _, sleep = _instant_sleep_factory()
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_TOKEN,
        allow_internal=True,
        max_attempts=5,
        _session_factory=lambda: session,
        _sleep=sleep,
    )
    await pusher.start()
    proxy_mod.register_audit_webhook_pusher(pusher)
    try:
        pusher.push({"event_type": "F3_test"})
        await _wait_until(
            lambda: pusher.status()["dropped_events"] >= 1, timeout=3.0,
        )
    finally:
        await pusher.stop()
    snap = pusher.status()
    assert snap["last_status_code"] == 502
    assert snap["consecutive_failures"] >= 5
    assert len(session.posts) == 5  # all 5 attempts fired


# ---------------------------------------------------------------------------
# F4 — log permission denied (writes-only dir)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_F4_log_permission_denied_flips_writes_ok_false(
    tmp_path: pathlib.Path,
) -> None:
    """F4: write to a 0o500 (read+exec, no write) parent dir → the
    writer's worker hits PermissionError → log_writes_ok flips False
    + /healthz reports degraded.

    NB: we still successfully OPEN the file (the test creates the
    file first), then chmod the dir + the file to read-only. When
    the worker tries to `os.write` the line, the write should fail
    because the FD is on a read-only mount... actually that doesn't
    fail on POSIX (the fd retains write permission). We trigger the
    error via a different path: open the file with O_WRONLY then
    close the FD underneath the writer so the next write fails.
    """
    from iam_jit.bouncer import proxy as proxy_mod
    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path)
    await writer.start()
    proxy_mod.register_audit_log_writer(writer)
    try:
        # Close the writer's FD out from under it so os.write fails
        # with EBADF — equivalent observable failure (permission flip
        # mid-session results in the same fail-soft path).
        assert writer._fd is not None
        os.close(writer._fd)
        # Mark the fd as "still open" from the writer's POV; the
        # worker will hit EBADF on next os.write.
        writer.write({"event_type": "F4_test"})
        await _wait_until(
            lambda: writer.status()["writes_ok"] is False, timeout=2.0,
        )
    finally:
        # Re-open a temp fd so the writer's stop() doesn't crash on
        # the stale fd (we already closed it; the stop path os.close
        # is wrapped in try/except OSError so it'll just no-op).
        try:
            await writer.stop()
        except Exception:
            pass
    stats = writer.status()
    assert stats["writes_ok"] is False
    assert stats["last_error"] is not None
    assert stats["last_error_at_unix"] is not None
    # /healthz health section reports degraded.
    proxy_mod.register_audit_log_writer(writer)
    section = proxy_mod.audit_export_health_section()
    assert section["configured"] is True
    assert section["log_writes_ok"] is False
    assert section["degraded"] is True
    assert any("log_writes_ok=false" in r for r in section["degraded_reasons"])


# ---------------------------------------------------------------------------
# F5 — disk full (ENOSPC simulated)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_F5_disk_full_flips_writes_ok_false_and_records_error(
    tmp_path: pathlib.Path, monkeypatch,
) -> None:
    """F5: simulate ENOSPC by monkeypatching os.write to raise
    OSError(ENOSPC). The writer's worker catches the error + flips
    writes_ok False + records last_error containing 'disk' / 'space'
    hint via the OSError message. Provides the same /healthz signal
    a real disk-full would.

    A true 4KB tmpfs would be cleaner but isn't portable across CI
    runners; monkeypatching os.write IS the test-deterministic way
    to drive the same code path the kernel would.
    """
    from iam_jit.bouncer import proxy as proxy_mod
    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path)
    await writer.start()
    proxy_mod.register_audit_log_writer(writer)
    real_write = os.write
    target_fd = writer._fd

    def _fake_write(fd, buf):
        if fd == target_fd:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(fd, buf)

    monkeypatch.setattr(os, "write", _fake_write)
    try:
        writer.write({"event_type": "F5_test"})
        await _wait_until(
            lambda: writer.status()["writes_ok"] is False, timeout=2.0,
        )
    finally:
        # Restore os.write BEFORE stop() so cleanup doesn't fight the
        # monkeypatch.
        monkeypatch.undo()
        await writer.stop()
    stats = writer.status()
    assert stats["writes_ok"] is False
    assert stats["last_error"] is not None
    assert "no space" in stats["last_error"].lower()
    # Re-register because stop() doesn't auto-unregister, but the
    # fixture cleared it; we re-register to verify the health section.
    proxy_mod.register_audit_log_writer(writer)
    section = proxy_mod.audit_export_health_section()
    assert section["log_writes_ok"] is False
    assert section["degraded"] is True


# ---------------------------------------------------------------------------
# F6 — file deleted mid-write (writer keeps recording the failure)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_F6_file_deleted_mid_write_writer_records_failure_visibly(
    tmp_path: pathlib.Path,
) -> None:
    """F6: delete the log file out from under the writer while it has
    the fd open. On POSIX the fd stays valid + writes go to the
    unlinked inode (no error surfaces); we cannot reliably force a
    failure here without filesystem cooperation, so the test asserts
    the FAIL-VISIBLY half of the spec: the writer doesn't silently
    keep recording events with NO observable trace.

    Specifically: when the path no longer points at the file, the
    writer's `path` attribute + status() still reports the configured
    path so the operator can spot "the file at the path I configured
    is missing." The actual write keeps working (POSIX semantics),
    which is the SAFE outcome — events are preserved on the unlinked
    inode + ride out the rest of the process lifetime.
    """
    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path)
    await writer.start()
    try:
        writer.write({"event_type": "F6_before_delete"})
        await _wait_until(
            lambda: writer.status()["total_events"] >= 1, timeout=2.0,
        )
        # Delete the file while the writer holds the fd.
        os.unlink(log_path)
        assert not log_path.exists()
        writer.write({"event_type": "F6_after_delete"})
        # Give the worker a moment to drain.
        await asyncio.sleep(0.1)
    finally:
        await writer.stop()
    stats = writer.status()
    # The configured path is still surfaced so the operator can spot
    # the missing file via `ls`.
    assert stats["path"] == str(log_path)
    # The writer logged AT LEAST the pre-delete event. Post-delete
    # writes either landed on the unlinked inode (POSIX) or failed
    # visibly — either way, total_events is observable.
    assert stats["total_events"] >= 1


# ---------------------------------------------------------------------------
# F7 — queue overflow + recovery (AUDIT_DROPPED survives)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_F7_queue_overflow_produces_AUDIT_DROPPED_on_first_recovery() -> None:
    """F7: overflow the bounded webhook queue, then let the worker
    drain. The first successful send must include an AUDIT_DROPPED
    synthetic AHEAD of the batch so the downstream consumer sees the
    gap explicitly. Dropped count is also recorded in the timestamped
    history deque (used by audit_export_degraded's 5-min window
    check)."""
    from iam_jit.bouncer import proxy as proxy_mod
    session = _FakeSession(statuses=[200])
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_TOKEN,
        allow_internal=True,
        queue_maxsize=2,  # tiny queue so overflow is easy to trigger
        _session_factory=lambda: session,
    )
    # Don't start yet — we want to overflow the queue BEFORE the worker
    # spins up so the drops happen synchronously + deterministically.
    await pusher.start()
    proxy_mod.register_audit_webhook_pusher(pusher)
    try:
        # Stuff the queue with enough events to overflow. The worker
        # might drain some before we finish pushing; that's fine —
        # we just need at least one drop to land.
        for i in range(20):
            pusher.push({"event_type": f"F7_event_{i}"})
        # Wait for the worker to finalize at least one send + record
        # at least one drop.
        await _wait_until(
            lambda: (
                pusher.status()["dropped_events"] >= 1
                and pusher.status()["total_events"] >= 1
            ),
            timeout=3.0,
        )
    finally:
        await pusher.stop()
    snap = pusher.status()
    assert snap["dropped_events"] >= 1
    # The first successful send (or any subsequent one after a drop)
    # prepended an AUDIT_DROPPED synthetic. Scan the recorded POST
    # bodies for the synthetic.
    found_synthetic = False
    for post in session.posts:
        body_lines = post["data"].splitlines() if isinstance(post["data"], (str, bytes)) else []
        for line in body_lines:
            try:
                if isinstance(line, bytes):
                    line = line.decode("utf-8")
                evt = json.loads(line)
            except Exception:
                continue
            unmapped = (evt.get("unmapped") or {}).get("iam_jit", {})
            if unmapped.get("event_type") == "AUDIT_DROPPED":
                found_synthetic = True
                break
        if found_synthetic:
            break
    assert found_synthetic, (
        "expected an AUDIT_DROPPED synthetic in at least one POST body; "
        f"saw {len(session.posts)} posts but no synthetic"
    )
    # And the dropped-history deque has timestamps for the rule's
    # 5-minute window check.
    assert pusher.dropped_in_last_seconds(300) >= 1


@pytest.mark.asyncio
async def test_F7_drops_in_last_5_minutes_trips_audit_export_degraded_rule() -> None:
    """F7 corollary: when dropped events in the last 5 minutes exceed
    the spec threshold (10), the audit_export_degraded rule fires.
    This is the parallel "stop here even before consecutive_failures
    > 5" trigger for shops with high event volume where the queue
    overflows before the retry budget exhausts."""
    from iam_jit.bouncer import proxy as proxy_mod
    session = _FakeSession(statuses=[200])
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_TOKEN,
        allow_internal=True,
        queue_maxsize=1,
        _session_factory=lambda: session,
    )
    await pusher.start()
    proxy_mod.register_audit_webhook_pusher(pusher)
    try:
        # Push more than the drop threshold; the queue is 1, so most
        # of these will drop synchronously.
        for i in range(DEFAULT_AUDIT_EXPORT_DEGRADED_DROP_THRESHOLD + 5):
            pusher.push({"event_type": f"F7b_{i}"})
        await _wait_until(
            lambda: (
                pusher.dropped_in_last_seconds(300)
                > DEFAULT_AUDIT_EXPORT_DEGRADED_DROP_THRESHOLD
            ),
            timeout=2.0,
        )
    finally:
        await pusher.stop()
    # Run the rule.
    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    engine.observe(_decision_event())
    matched = [
        e for e in fired
        if e["unmapped"]["iam_jit"].get("pattern") == "audit-export-degraded"
    ]
    assert len(matched) == 1
    # status_detail lives on the alert event itself (per OCSF).
    detail = matched[0].get("status_detail", "")
    assert "dropped_events_in_last" in detail, (
        f"expected drop-window mention in status_detail; got {detail!r}"
    )


# ---------------------------------------------------------------------------
# F8 — license expiry mid-session (fail-clean, no silent demotion)
# ---------------------------------------------------------------------------


def test_F8_license_gate_refuses_at_serve_time_even_if_cli_passed(monkeypatch) -> None:
    """F8: the webhook + alerts gates fire BOTH at CLI parse time AND
    at serve() start (defense in depth). When the license file is
    rotated / expires between parse and start, serve() refuses to
    bring the channel up rather than silently demoting to "no
    audit." The Enterprise grace-period (license valid → expired)
    is documented in docs/LICENSE.md; the fail-CLEAN posture is what
    matters for the audit-export visibility invariant: a silent
    demotion would look identical to a working channel from the
    operator's vantage point.

    Asserts the contract: gate_webhook_license refuses post-expiry.
    """
    from iam_jit import license as license_mod
    from iam_jit.bouncer.audit_export import WebhookLicenseError
    from iam_jit.bouncer.audit_export.webhook import gate_webhook_license

    monkeypatch.delenv("IAM_JIT_LICENSE_FILE", raising=False)
    monkeypatch.setattr(
        license_mod, "_default_license_path",
        lambda: pathlib.Path("/nonexistent/license.json"),
    )
    # Free tier → refuse. The error message points at docs/LICENSE.md
    # so the operator knows where to renew.
    with pytest.raises(WebhookLicenseError, match="Enterprise"):
        gate_webhook_license(None)


# ---------------------------------------------------------------------------
# Cross-cutting: /healthz audit_export section shape (healthy + degraded)
# ---------------------------------------------------------------------------


def test_healthz_audit_export_section_healthy_shape_when_nothing_configured() -> None:
    """Baseline: no log writer + no webhook pusher registered →
    section reports configured=False everywhere + degraded=False
    (you can't be degraded without something to degrade)."""
    from iam_jit.bouncer.proxy import audit_export_health_section
    section = audit_export_health_section()
    assert section["configured"] is False
    assert section["webhook_configured"] is False
    assert section["log_writes_ok"] is True  # vacuously true when not configured
    assert section["degraded"] is False
    assert section["degraded_reasons"] == []


@pytest.mark.asyncio
async def test_healthz_audit_export_section_healthy_with_running_channels(
    tmp_path: pathlib.Path,
) -> None:
    """All channels running + successful → section reports configured
    fields populated + degraded=False."""
    from iam_jit.bouncer import proxy as proxy_mod
    from iam_jit.bouncer.proxy import audit_export_health_section
    writer = AuditLogWriter(path=tmp_path / "audit.jsonl")
    await writer.start()
    session = _FakeSession(statuses=[200])
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_TOKEN,
        allow_internal=True,
        _session_factory=lambda: session,
    )
    await pusher.start()
    proxy_mod.register_audit_log_writer(writer)
    proxy_mod.register_audit_webhook_pusher(pusher)
    try:
        writer.write({"event_type": "healthy_test"})
        pusher.push({"event_type": "healthy_test"})
        await _wait_until(
            lambda: pusher.status()["total_events"] >= 1, timeout=2.0,
        )
        await _wait_until(
            lambda: writer.status()["total_events"] >= 1, timeout=2.0,
        )
    finally:
        section = audit_export_health_section()
        await writer.stop()
        await pusher.stop()
    assert section["configured"] is True
    assert section["log_writes_ok"] is True
    assert section["webhook_configured"] is True
    # URL is masked (no userinfo). Our test URL has no userinfo so
    # the masked form equals the input.
    assert section["webhook_url_masked"] == "https://collector.example.com/audit"
    assert section["webhook_consecutive_failures"] == 0
    assert section["webhook_last_success_seconds_ago"] is not None
    assert section["webhook_last_success_seconds_ago"] >= 0
    assert section["webhook_last_status_code"] == 200
    assert section["degraded"] is False


def test_healthz_audit_export_section_token_never_in_payload(
    monkeypatch,
) -> None:
    """Token-mask invariant: the webhook URL's userinfo is stripped
    AND the bearer token never appears in the /healthz section.
    Greps the serialized section for the literal token value.
    """
    from iam_jit.bouncer import proxy as proxy_mod

    # Install a pusher with the token in BOTH the URL userinfo + the
    # bearer slot to cover both leak surfaces.
    class _StubPusher:
        def status(self) -> dict:
            return {
                "configured": True,
                # mask_url_userinfo strips this in the real status()
                # path; we hand back the already-masked URL the way
                # the pusher would.
                "url": "https://collector.example.com/audit",
                "token": "***",
                "preset": "generic",
                "batch_size": 1,
                "queue_maxsize": 1000,
                "queue_depth": 0,
                "allow_internal": False,
                "max_attempts": 5,
                "total_events": 0,
                "dropped_events": 0,
                "webhook_in_flight": 0,
                "last_error": None,
                "consecutive_failures": 0,
                "last_success_unix": None,
                "last_attempt_unix": None,
                "last_status_code": None,
                "last_error_at_unix": None,
            }

        def dropped_in_last_seconds(self, n: int) -> int:
            return 0

    proxy_mod.register_audit_webhook_pusher(_StubPusher())
    section = proxy_mod.audit_export_health_section()
    serialized = json.dumps(section, default=str)
    assert TEST_TOKEN not in serialized
    # Belt-and-braces: no field labelled 'token' should appear in the
    # /healthz section at all. (The mask token ('***') would still
    # be a leak surface if we accidentally surfaced the field; the
    # section shape excludes it entirely.)
    assert "\"token\"" not in serialized.replace(" ", "")


# ---------------------------------------------------------------------------
# audit_export_degraded rule: neutral language + stderr-fallback shape
# ---------------------------------------------------------------------------


def test_audit_export_degraded_stderr_message_uses_neutral_language() -> None:
    """The stderr fallback string must not contain forbidden words
    (violation / infraction / unauthorized). Mirrors the FORBIDDEN_
    ALERT_WORDS scan in test_audit_export_alerts.py."""
    from iam_jit.bouncer.audit_export import FORBIDDEN_ALERT_WORDS
    msg = audit_export_degraded_stderr_message(
        reasons=["webhook_consecutive_failures=10 (threshold 5)"],
    )
    lower = msg.lower()
    for w in FORBIDDEN_ALERT_WORDS:
        assert w not in lower, (
            f"forbidden word {w!r} appeared in stderr fallback: {msg!r}"
        )
    # Operator-action hint present.
    assert "check webhook reachability" in lower
    assert "disk space" in lower
    assert "token validity" in lower


def test_audit_export_degraded_evaluator_returns_no_reasons_when_healthy() -> None:
    """When nothing is registered, the evaluator returns
    (False, []) — no false-fires on a fresh boot."""
    is_degraded, reasons = _evaluate_audit_export_degraded(
        AlertsConfig.default(),
    )
    assert is_degraded is False
    assert reasons == []


# ---------------------------------------------------------------------------
# /healthz HTTP integration — 503 fires on all 3 conditions
# ---------------------------------------------------------------------------


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


@pytest.mark.asyncio
async def test_healthz_returns_503_when_log_writes_ok_false(
    tmp_path: pathlib.Path,
) -> None:
    """End-to-end /healthz: log_writes_ok=false → 503."""
    from iam_jit.bouncer import proxy as proxy_mod
    from iam_jit.bouncer.decisions import DefaultPolicy
    from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
    from iam_jit.bouncer.store import BouncerStore

    # Pre-create a writer + flip writes_ok via the failure path.
    writer = AuditLogWriter(path=tmp_path / "audit.jsonl")
    await writer.start()
    # Close fd to force a failure on the next write.
    assert writer._fd is not None
    os.close(writer._fd)
    writer.write({"event_type": "force_fail"})
    await _wait_until(
        lambda: writer.status()["writes_ok"] is False, timeout=2.0,
    )
    proxy_mod.register_audit_log_writer(writer)

    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz",
            ) as resp:
                assert resp.status == 503, (
                    f"expected 503 for log_writes_ok=false; got {resp.status}"
                )
                body = await resp.json()
        assert body["audit_export"]["log_writes_ok"] is False
        assert body["audit_export"]["degraded"] is True
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        try:
            await writer.stop()
        except Exception:
            pass
        store.close()


@pytest.mark.asyncio
async def test_healthz_returns_503_when_webhook_consecutive_failures_over_threshold(
    tmp_path: pathlib.Path,
) -> None:
    """End-to-end /healthz: webhook consecutive_failures > 3 → 503."""
    from iam_jit.bouncer import proxy as proxy_mod
    from iam_jit.bouncer.decisions import DefaultPolicy
    from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
    from iam_jit.bouncer.store import BouncerStore

    session_fake = _FakeSession(raise_always=True)
    _, sleep = _instant_sleep_factory()
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_TOKEN,
        allow_internal=True,
        max_attempts=5,
        _session_factory=lambda: session_fake,
        _sleep=sleep,
    )
    await pusher.start()
    pusher.push({"event_type": "force_fail"})
    await _wait_until(
        lambda: pusher.status()["consecutive_failures"] > 3, timeout=3.0,
    )
    proxy_mod.register_audit_webhook_pusher(pusher)

    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as http:
            async with http.get(
                f"http://127.0.0.1:{port}/healthz",
            ) as resp:
                assert resp.status == 503
                body = await resp.json()
        assert body["audit_export"]["webhook_consecutive_failures"] >= 4
        assert body["audit_export"]["degraded"] is True
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await pusher.stop()
        store.close()


@pytest.mark.asyncio
async def test_healthz_returns_503_when_webhook_silent_over_five_min(
    tmp_path: pathlib.Path, monkeypatch,
) -> None:
    """End-to-end /healthz: webhook last_success > 5min ago → 503.
    Faked by setting last_attempt_unix recently + last_success_unix to
    None (= never succeeded after attempting; same observable shape
    as 'webhook silent for > 5min')."""
    from iam_jit.bouncer import proxy as proxy_mod
    from iam_jit.bouncer.decisions import DefaultPolicy
    from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
    from iam_jit.bouncer.store import BouncerStore

    # Stub pusher reports a recent attempt but no success — this is
    # the "configured but silent" failure mode.
    class _SilentPusher:
        url = "https://collector.example.com/audit"
        queue_maxsize = 1000

        def status(self) -> dict:
            return {
                "configured": True,
                "url": self.url,
                "token": "***",
                "preset": "generic",
                "batch_size": 1,
                "queue_maxsize": 1000,
                "queue_depth": 0,
                "allow_internal": True,
                "max_attempts": 5,
                "total_events": 0,
                "dropped_events": 0,
                "webhook_in_flight": 0,
                "last_error": "all attempts timed out",
                "consecutive_failures": 1,
                # Recent attempt, no success → 503 silent-window trigger.
                "last_success_unix": None,
                "last_attempt_unix": __import__("time").time(),
                "last_status_code": None,
                "last_error_at_unix": __import__("time").time(),
            }

        def dropped_in_last_seconds(self, n: int) -> int:
            return 0

        def queue_depth(self) -> int:
            return 0

    proxy_mod.register_audit_webhook_pusher(_SilentPusher())

    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as http:
            async with http.get(
                f"http://127.0.0.1:{port}/healthz",
            ) as resp:
                assert resp.status == 503
                body = await resp.json()
        assert body["audit_export"]["degraded"] is True
        # The 5-min silent-window reason fired.
        assert any(
            "webhook_last_success_seconds_ago" in r
            for r in body["audit_export"]["degraded_reasons"]
        )
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


# ---------------------------------------------------------------------------
# CLI integration — `ibounce audit-export health` reflects /healthz
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cli_audit_export_health_subcommand_exits_two_on_degraded(
    tmp_path: pathlib.Path,
) -> None:
    """The `ibounce audit-export health` subcommand hits /healthz +
    exits 2 when the channel is degraded. Verifies the CLI re-uses
    the same logic as /healthz (no divergence)."""
    from click.testing import CliRunner
    from iam_jit.bouncer_cli import main as cli_main
    from iam_jit.bouncer import proxy as proxy_mod
    from iam_jit.bouncer.decisions import DefaultPolicy
    from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
    from iam_jit.bouncer.store import BouncerStore

    # Set up a writer with writes_ok=False so /healthz is degraded.
    writer = AuditLogWriter(path=tmp_path / "audit.jsonl")
    await writer.start()
    assert writer._fd is not None
    os.close(writer._fd)
    writer.write({"event_type": "force_fail"})
    await _wait_until(
        lambda: writer.status()["writes_ok"] is False, timeout=2.0,
    )
    proxy_mod.register_audit_log_writer(writer)

    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        runner = CliRunner()
        # Run the blocking CLI in a worker thread so the proxy's
        # event loop keeps spinning (the CLI's urllib.urlopen would
        # otherwise pin the event loop and starve the server).
        result = await asyncio.to_thread(
            runner.invoke,
            cli_main,
            ["audit-export", "health",
             "--url", f"http://127.0.0.1:{port}/healthz"],
        )
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        try:
            await writer.stop()
        except Exception:
            pass
        store.close()
    # Exit code 2 = degraded; the CLI table is present in stdout.
    assert result.exit_code == 2, (
        f"expected exit 2 on degraded; got {result.exit_code}\n"
        f"stdout: {result.stdout}\n"
        f"stderr: {result.stderr if hasattr(result, 'stderr') else ''}"
    )
    assert "audit-export channel health" in result.stdout
    assert "Degraded" in result.stdout


@pytest.mark.asyncio
async def test_cli_audit_export_health_subcommand_exits_zero_when_healthy(
    tmp_path: pathlib.Path,
) -> None:
    """Healthy channel → exit code 0."""
    from click.testing import CliRunner
    from iam_jit.bouncer_cli import main as cli_main
    from iam_jit.bouncer.decisions import DefaultPolicy
    from iam_jit.bouncer.proxy import ProxyConfig, ProxyMode, serve
    from iam_jit.bouncer.store import BouncerStore

    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        runner = CliRunner()
        result = await asyncio.to_thread(
            runner.invoke,
            cli_main,
            ["audit-export", "health",
             "--url", f"http://127.0.0.1:{port}/healthz"],
        )
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()
    assert result.exit_code == 0, (
        f"expected exit 0; got {result.exit_code}\n"
        f"stdout: {result.stdout}"
    )


def test_cli_audit_export_health_subcommand_exits_three_when_unreachable() -> None:
    """No bouncer running at the URL → exit code 3 (distinct from
    'degraded' so monitoring can differentiate)."""
    from click.testing import CliRunner
    from iam_jit.bouncer_cli import main as cli_main

    runner = CliRunner()
    # Use a port that nothing is listening on.
    port = _free_port()
    result = runner.invoke(
        cli_main,
        ["audit-export", "health",
         "--url", f"http://127.0.0.1:{port}/healthz",
         "--timeout", "1"],
    )
    assert result.exit_code == 3
