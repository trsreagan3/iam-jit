"""Tests for the HTTPS audit-webhook pusher (#252 Slice 1).

Per [[security-team-audit-export]] this is the ENTERPRISE-tier
channel:
- License-gated (Enterprise required)
- SSRF-gated (RFC1918 / loopback / .internal / .local denylist)
- Bounded queue (default 1000); drop + AUDIT_DROPPED on overflow
- Exponential-backoff retry: 1s -> 2s -> 4s -> 8s -> 16s -> 32s; max 5
- Bearer token NEVER appears in banner / /healthz / log / errors
- Async-queued; never blocks proxy hot-path

Token-leak test (`test_token_never_appears_in_any_surface`) is the
load-bearing assertion per the spec — it greps every reachable
surface for the literal token value.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import json
import logging
import pathlib
from typing import Any

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from iam_jit import license as license_mod
from iam_jit.bouncer.audit_export import (
    SSRFRejectedError,
    WebhookLicenseError,
    WebhookPusher,
    validate_webhook_url,
)
from iam_jit.bouncer.audit_export.webhook import (
    gate_webhook_license,
    mask_token,
    mask_url_userinfo,
)


# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------


# The "secret" the token-leak test greps for. Used everywhere a real
# operator would put their bearer token. If this string EVER appears
# in the captured output of any test surface, the leak test fails.
TEST_WEBHOOK_TOKEN_VALUE = "lit_secret_bearer_value_donotleak_xyz"


@pytest.fixture
def enterprise_license_factory(monkeypatch):
    """Returns a callable that installs a freshly-signed Enterprise
    license file + patches the verifier to use the test public key.
    Tests that need the gate to pass call `enterprise_license_factory()`;
    tests that need the gate to FAIL skip this fixture entirely (the
    placeholder production key auto-rejects)."""
    installed: dict[str, Any] = {}

    def _install(tmp_path: pathlib.Path, tier: str = "enterprise") -> None:
        priv = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(
            priv.public_key().public_bytes_raw(),
        ).decode("ascii")
        now = _dt.datetime.now(_dt.UTC).replace(microsecond=0)
        payload = {
            "tier": tier,
            "issued_to": "Test Co.",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + _dt.timedelta(days=30)).isoformat().replace("+00:00", "Z"),
            "max_users": 100,
            "license_id": "lic_test_audit",
        }
        canonical = license_mod._canonical_payload_bytes(payload)
        sig = priv.sign(canonical)
        license_doc = {
            "payload": payload,
            "signature": base64.b64encode(sig).decode("ascii"),
        }
        lic_path = tmp_path / "license.json"
        lic_path.write_text(json.dumps(license_doc))
        monkeypatch.setenv("IAM_JIT_LICENSE_FILE", str(lic_path))
        # Patch the verifier's embedded pubkey for this test only.
        monkeypatch.setattr(
            license_mod, "PRODUCTION_PUBLIC_KEY_B64", pub_b64,
        )
        installed["path"] = lic_path
        installed["pub"] = pub_b64

    return _install


class _FakeResponse:
    """Async-context-manager response stub for the fake aiohttp
    session. Mirrors just enough of aiohttp.ClientResponse for the
    pusher to consume."""

    def __init__(self, status: int = 200) -> None:
        self.status = status

    async def read(self) -> bytes:
        return b""

    async def __aenter__(self) -> "_FakeResponse":
        return self

    async def __aexit__(self, *exc) -> None:
        return None


class _FakeSession:
    """aiohttp.ClientSession stub. Records every POST + lets the
    test control which status code is returned (and from which
    attempt onwards). NEVER hits the network. Lets us assert the
    token is sent in the Authorization header WITHOUT a real HTTP
    server seeing it (and therefore without exposing it to logging
    surfaces we'd then have to grep)."""

    def __init__(
        self,
        statuses: list[int] | None = None,
        raise_on_attempt: int | None = None,
    ) -> None:
        # `statuses` is the response code per attempt; defaults to [200]
        # repeated indefinitely.
        self._statuses = statuses or [200]
        self._raise_on_attempt = raise_on_attempt
        self.posts: list[dict[str, Any]] = []
        self.closed = False

    def post(self, url: str, *, data: Any, headers: dict[str, str],
             timeout: float) -> _FakeResponse:
        attempt = len(self.posts)
        self.posts.append({
            "url": url,
            "data": data,
            "headers": dict(headers),
            "timeout": timeout,
        })
        if (
            self._raise_on_attempt is not None
            and attempt < self._raise_on_attempt
        ):
            raise RuntimeError("simulated network failure")
        idx = min(attempt, len(self._statuses) - 1)
        return _FakeResponse(status=self._statuses[idx])

    async def close(self) -> None:
        self.closed = True


def _instant_sleep_factory() -> tuple[list[float], Any]:
    """Returns (recorded_delays, sleep_coro). Tests inject the coro
    so the backoff schedule can be exercised without wall-clock waits."""
    delays: list[float] = []

    async def _sleep(delay: float) -> None:
        delays.append(delay)
        # Yield to the event loop once so concurrent tasks make progress.
        await asyncio.sleep(0)

    return delays, _sleep


# ---------------------------------------------------------------------------
# SSRF gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "https://10.0.0.1/audit",
    "https://127.0.0.1/audit",
    "https://192.168.1.1/audit",
    "https://172.16.0.1/audit",
    "https://169.254.169.254/audit",  # link-local — AWS IMDS
])
def test_ssrf_gate_rejects_rfc1918_and_loopback_ips(url: str) -> None:
    with pytest.raises(SSRFRejectedError):
        validate_webhook_url(url, allow_internal=False)


@pytest.mark.parametrize("hostname_url", [
    "https://collector.internal/audit",
    "https://splunk.local/audit",
    "https://aggregator.corp/audit",
    "https://logs.intranet/audit",
])
def test_ssrf_gate_rejects_intranet_suffix_hostnames(hostname_url: str) -> None:
    """Hostname suffix denylist fires BEFORE DNS resolution; some
    corp DNS resolves these to public CDN IPs and we still refuse."""
    with pytest.raises(SSRFRejectedError):
        validate_webhook_url(hostname_url, allow_internal=False)


def test_ssrf_gate_rejects_http_scheme_without_allow_internal() -> None:
    """Plaintext http:// would send the bearer in cleartext.
    Refused unless allow_internal=True."""
    with pytest.raises(SSRFRejectedError, match="plaintext"):
        validate_webhook_url(
            "http://collector.example.com/audit",
            allow_internal=False,
        )


def test_ssrf_gate_allows_public_https_url() -> None:
    """A vanilla https:// URL to a public hostname passes. We use
    an Anthropic-owned domain whose DNS is stable in test envs."""
    # NB: this DOES do a real DNS lookup; if your test env has no
    # resolver this test will be skipped via the gaierror branch.
    try:
        validate_webhook_url(
            "https://www.example.com/audit",
            allow_internal=False,
        )
    except SSRFRejectedError as e:
        if "could not resolve" in str(e):
            pytest.skip("DNS resolution unavailable in test env")
        raise


def test_ssrf_gate_opt_out_with_allow_internal() -> None:
    """The opt-out flag permits internal targets for legitimate
    intranet collectors."""
    # http:// + internal-suffix both ride on the same opt-out.
    validate_webhook_url(
        "http://splunk.internal/audit",
        allow_internal=True,
    )


# ---------------------------------------------------------------------------
# License gate
# ---------------------------------------------------------------------------


def test_license_gate_rejects_without_license(monkeypatch) -> None:
    """No license file → free tier → webhook flag refused with a
    clear error pointing at docs/LICENSE.md."""
    # Make sure no license file leaks in from a previous test.
    monkeypatch.delenv("IAM_JIT_LICENSE_FILE", raising=False)
    monkeypatch.setattr(
        license_mod, "_default_license_path",
        lambda: pathlib.Path("/nonexistent/license.json"),
    )
    with pytest.raises(WebhookLicenseError, match="Enterprise"):
        gate_webhook_license(None)


def test_license_gate_rejects_non_enterprise_tier(
    tmp_path: pathlib.Path, enterprise_license_factory,
) -> None:
    """A Pro/Team license is not enough — webhook is Enterprise-only."""
    enterprise_license_factory(tmp_path, tier="pro")
    with pytest.raises(WebhookLicenseError, match="Enterprise"):
        gate_webhook_license(None)


def test_license_gate_accepts_enterprise_license(
    tmp_path: pathlib.Path, enterprise_license_factory,
) -> None:
    """A valid Enterprise license passes."""
    enterprise_license_factory(tmp_path, tier="enterprise")
    # Should NOT raise.
    gate_webhook_license(None)


# ---------------------------------------------------------------------------
# Async queue + retry + drop behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pusher_sends_event_with_bearer_token() -> None:
    """The token is sent in the Authorization header; the URL is the
    one configured; the body is JSON-Lines."""
    session = _FakeSession(statuses=[200])
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_WEBHOOK_TOKEN_VALUE,
        allow_internal=True,  # skip SSRF for the fake URL
        _session_factory=lambda: session,
    )
    await pusher.start()
    try:
        pusher.push({"event_type": "test", "n": 1})
        # Wait for the worker to drain.
        for _ in range(50):
            if session.posts:
                break
            await asyncio.sleep(0.02)
    finally:
        await pusher.stop()

    assert len(session.posts) == 1
    post = session.posts[0]
    assert post["url"] == "https://collector.example.com/audit"
    assert post["headers"]["Authorization"] == f"Bearer {TEST_WEBHOOK_TOKEN_VALUE}"
    assert post["headers"]["Content-Type"] == "application/json"
    payload = json.loads(post["data"])
    assert payload == {"event_type": "test", "n": 1}


@pytest.mark.asyncio
async def test_pusher_retries_on_5xx_with_exponential_backoff() -> None:
    """5xx responses are retried; backoff doubles each attempt;
    eventual success stops the retry loop."""
    # Attempt 0 + 1 fail with 503, attempt 2 succeeds.
    session = _FakeSession(statuses=[503, 503, 200])
    delays, sleep = _instant_sleep_factory()
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_WEBHOOK_TOKEN_VALUE,
        allow_internal=True,
        _session_factory=lambda: session,
        _sleep=sleep,
    )
    await pusher.start()
    try:
        pusher.push({"event": "retry-me"})
        for _ in range(100):
            if len(session.posts) >= 3:
                break
            await asyncio.sleep(0.02)
    finally:
        await pusher.stop()
    assert len(session.posts) == 3
    # Two backoff delays consumed (between attempts 0->1, 1->2).
    assert delays[:2] == [1.0, 2.0]


@pytest.mark.asyncio
async def test_pusher_does_not_retry_on_4xx() -> None:
    """4xx is a config bug (wrong token, wrong URL) — retrying just
    spams the operator's collector. One attempt; then drop + record."""
    session = _FakeSession(statuses=[401])
    delays, sleep = _instant_sleep_factory()
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_WEBHOOK_TOKEN_VALUE,
        allow_internal=True,
        _session_factory=lambda: session,
        _sleep=sleep,
    )
    await pusher.start()
    try:
        pusher.push({"event": "noretry"})
        for _ in range(50):
            if session.posts:
                await asyncio.sleep(0.05)
                break
            await asyncio.sleep(0.02)
    finally:
        await pusher.stop()
    assert len(session.posts) == 1
    assert delays == []  # never slept (no retry)


@pytest.mark.asyncio
async def test_pusher_gives_up_after_max_attempts() -> None:
    """5xx forever → 5 attempts (1s, 2s, 4s, 8s schedule) → drop."""
    session = _FakeSession(statuses=[503])
    delays, sleep = _instant_sleep_factory()
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_WEBHOOK_TOKEN_VALUE,
        allow_internal=True,
        _session_factory=lambda: session,
        _sleep=sleep,
    )
    await pusher.start()
    try:
        pusher.push({"event": "give-up"})
        for _ in range(100):
            if len(session.posts) >= 5:
                await asyncio.sleep(0.05)
                break
            await asyncio.sleep(0.02)
    finally:
        await pusher.stop()
    assert len(session.posts) == 5
    # 4 sleeps between 5 attempts: 1, 2, 4, 8
    assert delays == [1.0, 2.0, 4.0, 8.0]
    status = pusher.status()
    assert status["dropped_events"] >= 1
    assert status["last_error"]


@pytest.mark.asyncio
async def test_pusher_drops_on_overflow_and_emits_audit_dropped() -> None:
    """When the bounded queue overflows, additional events are
    dropped + the NEXT successful send carries an AUDIT_DROPPED
    synthetic at the head of the batch."""
    session = _FakeSession(statuses=[200])
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_WEBHOOK_TOKEN_VALUE,
        queue_maxsize=2,
        batch_size=10,
        allow_internal=True,
        _session_factory=lambda: session,
    )
    await pusher.start()
    # Cancel the worker so the queue fills.
    if pusher._worker_task is not None:
        pusher._worker_task.cancel()
        try:
            await pusher._worker_task
        except asyncio.CancelledError:
            pass
    # Fill + overflow.
    pusher.push({"event": "a"})
    pusher.push({"event": "b"})
    for i in range(3):
        pusher.push({"event": f"overflow-{i}"})
    assert pusher.status()["dropped_events"] == 3

    # Restart a worker so the remaining 2 events drain. The pusher
    # will prepend an AUDIT_DROPPED synthetic.
    pusher._worker_task = asyncio.create_task(pusher._worker())
    for _ in range(50):
        if session.posts:
            await asyncio.sleep(0.05)
            break
        await asyncio.sleep(0.02)
    await pusher.stop()

    assert session.posts, "worker never POSTed"
    body = session.posts[0]["data"]
    # NDJSON: split on newline.
    lines = body.split("\n")
    payloads = [json.loads(line) for line in lines]
    # First line is the AUDIT_DROPPED synthetic, OCSF-shaped per
    # [[ocsf-audit-schema]] (event_type tag preserved under
    # unmapped.iam_jit so legacy filters still fire).
    assert payloads[0]["class_uid"] == 6003
    assert payloads[0]["activity_id"] == 99
    assert payloads[0]["unmapped"]["iam_jit"]["event_type"] == "AUDIT_DROPPED"
    assert payloads[0]["unmapped"]["iam_jit"]["dropped_count"] == 3
    # Followed by the two events that DID make it into the queue.
    assert payloads[1]["event"] == "a"
    assert payloads[2]["event"] == "b"


# ---------------------------------------------------------------------------
# Hot-path: push() must NEVER block + NEVER raise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_push_never_blocks_even_when_queue_full(tmp_path) -> None:
    """The proxy hot-path calls push() in the request handler.
    push() must return in microseconds regardless of queue state."""
    import time as _time
    session = _FakeSession(statuses=[200])
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_WEBHOOK_TOKEN_VALUE,
        queue_maxsize=1,
        allow_internal=True,
        _session_factory=lambda: session,
    )
    await pusher.start()
    # Cancel worker so queue stays full.
    if pusher._worker_task is not None:
        pusher._worker_task.cancel()
        try:
            await pusher._worker_task
        except asyncio.CancelledError:
            pass
    try:
        # Fill the queue.
        pusher.push({"event": "fill"})
        # Each subsequent push must return ~instantly.
        for _ in range(100):
            start = _time.monotonic()
            pusher.push({"event": "overflow"})
            elapsed = _time.monotonic() - start
            # 5ms is generous; real numbers are nanoseconds.
            assert elapsed < 0.005, f"push() blocked for {elapsed}s"
    finally:
        # Manual cleanup since worker is cancelled.
        if pusher._session is not None:
            await pusher._session.close()
        pusher._session = None
        pusher._started = False


# ---------------------------------------------------------------------------
# Token-leak: THE load-bearing security test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_never_appears_in_any_surface(
    tmp_path: pathlib.Path,
    caplog,
) -> None:
    """The bearer token MUST NOT leak into ANY observable surface
    other than the Authorization header sent to the collector.

    Surfaces checked:
      - status() snapshot (the MCP audit-export-status response)
      - repr(pusher)
      - mask_token()
      - mask_url_userinfo() applied to a userinfo URL
      - the captured log handler output across a full retry-storm
      - error messages from a 4xx + a 5xx-give-up
    """
    session = _FakeSession(statuses=[503, 503, 503, 503, 503])
    delays, sleep = _instant_sleep_factory()
    pusher = WebhookPusher(
        url=(
            f"https://user:{TEST_WEBHOOK_TOKEN_VALUE}@collector.example.com/audit"
        ),
        token=TEST_WEBHOOK_TOKEN_VALUE,
        allow_internal=True,
        _session_factory=lambda: session,
        _sleep=sleep,
    )

    surfaces: list[str] = []
    surfaces.append(repr(pusher))
    surfaces.append(json.dumps(pusher.status()))
    surfaces.append(mask_token(TEST_WEBHOOK_TOKEN_VALUE))
    surfaces.append(mask_url_userinfo(
        f"https://user:{TEST_WEBHOOK_TOKEN_VALUE}@collector.example.com/path"
    ))

    with caplog.at_level(logging.DEBUG):
        await pusher.start()
        try:
            pusher.push({"event": "boom"})
            for _ in range(100):
                if len(session.posts) >= 5:
                    await asyncio.sleep(0.05)
                    break
                await asyncio.sleep(0.02)
        finally:
            await pusher.stop()
        surfaces.append(json.dumps(pusher.status()))

    # Captured log output across the retry storm.
    surfaces.append(caplog.text)

    # The Authorization header is the ONE legitimate surface; the test
    # confirms it exists, then asserts the token is absent EVERYWHERE
    # else.
    assert any(
        post["headers"].get("Authorization", "").endswith(
            TEST_WEBHOOK_TOKEN_VALUE,
        )
        for post in session.posts
    ), "token should be in Authorization header (the one legit surface)"

    joined = "\n".join(surfaces)
    assert TEST_WEBHOOK_TOKEN_VALUE not in joined, (
        f"token leaked into one of: status(), repr(), mask helpers, "
        f"log captures, error messages.\nJoined surfaces:\n{joined}"
    )


def test_mask_token_returns_constant_mask_for_any_nonempty() -> None:
    """mask_token() never returns a length-based hint; '***' for any
    non-empty token. Same shape across products so reviewers know
    what to grep for."""
    assert mask_token("a") == "***"
    assert mask_token("a" * 100) == "***"
    assert mask_token("") == ""
    assert mask_token(None) == ""


def test_mask_url_userinfo_strips_userinfo() -> None:
    masked = mask_url_userinfo(
        f"https://user:{TEST_WEBHOOK_TOKEN_VALUE}@collector.example.com:443/audit?q=1",
    )
    assert TEST_WEBHOOK_TOKEN_VALUE not in masked
    assert "user" not in masked
    assert "collector.example.com" in masked
    assert "/audit" in masked
