"""HTTPS webhook pusher — Channel 2 of the audit-export transport.

Per `security-team-audit-export`:
- Bounded queue (default 1000); on overflow drop + emit synthetic
  `AUDIT_DROPPED` event with the dropped count + reset.
- Exponential backoff retry: 1s -> 2s -> 4s -> 8s -> 16s -> 32s cap;
  max 5 attempts; final failure drops + logs.
- Bearer token authorization via `Authorization: Bearer <token>`.
- Async worker task; never blocks proxy hot-path.
- License gate: webhook flag requires an Enterprise license file
  (per `enterprise-self-host-only`). Free/Pro/Team can use the
  JSONL log channel.

Security:
- SSRF gate via `socket.gethostbyname_ex()` + RFC1918/loopback/
  link-local/.internal/.local denylist. Mirrors the dbounce MED-D8-
  06 closure pattern. Opt-out via `--allow-internal-webhook` for
  operators that legitimately need to ship to an intranet
  collector.
- Bearer token NEVER appears in: startup banner / /healthz output /
  log file / error messages on retry failures. The URL's userinfo
  (`https://user:pass@host/path`) is masked the same way.

Per `no-hosted-saas`: iam-jit-the-company NEVER receives the
webhook; the customer's URL only.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import threading
import urllib.parse
from typing import Any

from .event import audit_dropped_event

logger = logging.getLogger(__name__)


DEFAULT_WEBHOOK_QUEUE_MAXSIZE = 1000
DEFAULT_MAX_ATTEMPTS = 5
_BACKOFF_SCHEDULE_SECONDS = (1.0, 2.0, 4.0, 8.0, 16.0, 32.0)
# RFC 8375: .home.arpa for residential intranets. Add .internal /
# .local for the patterns common in corporate intranets + Bonjour /
# Avahi. Matches dbounce MED-D8-06 closure shape.
_INTERNAL_HOSTNAME_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".home.arpa",
    ".lan",
    ".intranet",
    ".corp",
)


class WebhookLicenseError(Exception):
    """Raised when webhook flags are passed without an Enterprise
    license file. Surfaced at CLI parse time so the operator
    gets a clear "this feature requires Enterprise" message + a
    pointer to docs/LICENSE.md, not a silent no-op."""


class SSRFRejectedError(Exception):
    """Raised when the webhook URL fails the SSRF gate (RFC1918 /
    loopback / .internal / .local). Opt-out via
    --allow-internal-webhook for intranet collectors."""


def mask_token(token: str | None) -> str:
    """Return the canonical mask used everywhere the token might
    appear (banner, /healthz, error message). Never returns the raw
    token. Returns '***' for any non-empty token; empty/None returns
    the empty string."""
    if not token:
        return ""
    return "***"


def mask_url_userinfo(url: str) -> str:
    """Strip the userinfo (`user:pass@`) from a URL for logging /
    error messages. Preserves the rest of the URL so the operator
    can still see which host the proxy is trying to reach.

    Defensive: a URL with malformed userinfo (e.g. an unencoded ``@``
    that confuses urlparse) is returned as the scheme + host only.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return url
    if not parsed.netloc:
        return url
    # Strip userinfo by reconstructing netloc as host[:port] only.
    host = parsed.hostname or ""
    if parsed.port is not None:
        netloc = f"{host}:{parsed.port}"
    else:
        netloc = host
    return urllib.parse.urlunparse((
        parsed.scheme, netloc, parsed.path,
        parsed.params, parsed.query, parsed.fragment,
    ))


def _is_internal_ip(ip_str: str) -> bool:
    """True if `ip_str` is RFC1918 / loopback / link-local /
    unspecified / reserved — i.e. would let the proxy hit a host
    inside the operator's network. Same shape as dbounce MED-D8-06
    closure (which uses the equivalent net.IP categorisation in Go).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Not an IP literal — caller already resolved via getaddrinfo
        # so we shouldn't end up here, but be defensive: treat as
        # "internal" (refuse) rather than "external" (allow) on parse
        # failure. Fail-closed posture per ibounce-honest-positioning.
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_multicast
    )


def _hostname_has_internal_suffix(hostname: str) -> bool:
    """True if the hostname ends with one of the known intranet
    suffixes. Case-insensitive comparison.

    We can't trust DNS alone for these because some corporate DNS
    setups resolve `.internal` to a public CDN IP (CDN-frontend on
    private hostname); the suffix denylist is belt-and-braces with
    the IP check.
    """
    h = hostname.lower().rstrip(".")
    return any(h.endswith(suf) for suf in _INTERNAL_HOSTNAME_SUFFIXES)


def validate_webhook_url(
    url: str,
    *,
    allow_internal: bool = False,
) -> None:
    """Run the SSRF gate. Raises `SSRFRejectedError` on a refusal;
    returns None on success.

    Checks (in order):
      1. URL must parse + use https:// (we refuse http to prevent the
         token from being sent over the wire in plaintext; bypass by
         passing --allow-internal-webhook AND http://, see CLI).
      2. Hostname must not match an internal-suffix denylist.
      3. socket.gethostbyname_ex() — every resolved IP must be public
         (not RFC1918 / loopback / link-local / unspecified / reserved).

    The check happens at CLI parse time (once) AND at every push
    attempt (because DNS can flip — DNS rebinding is the classic
    SSRF-pivot). Both fire through this function.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        raise SSRFRejectedError(f"could not parse webhook URL: {e}") from e
    if not parsed.scheme or not parsed.hostname:
        raise SSRFRejectedError(
            f"webhook URL {url!r} is missing scheme or host"
        )
    if parsed.scheme not in ("https", "http"):
        raise SSRFRejectedError(
            f"webhook URL must use http:// or https:// (got {parsed.scheme!r})"
        )
    if parsed.scheme == "http" and not allow_internal:
        # Bearer token over plaintext is too dangerous to silently
        # allow. Treat as a special-case SSRF rejection that's also
        # gated behind --allow-internal-webhook (the only legitimate
        # case is an intranet collector).
        raise SSRFRejectedError(
            "webhook URL uses http:// which would send the Bearer token "
            "in plaintext. Use https:// or pass --allow-internal-webhook "
            "if shipping to an intranet collector over a trusted segment."
        )
    hostname = parsed.hostname
    if allow_internal:
        # Operator opted in to "I know what I'm doing." Skip the
        # hostname-suffix denylist AND the DNS resolution entirely —
        # the latter would otherwise refuse legitimate test / dev
        # hostnames that don't exist in DNS (compose / k8s service
        # names not in /etc/hosts on the host).
        return
    if _hostname_has_internal_suffix(hostname):
        raise SSRFRejectedError(
            f"webhook URL hostname {hostname!r} matches an intranet suffix; "
            "pass --allow-internal-webhook to permit (only for legitimate "
            "internal collectors on a trusted network segment)."
        )
    try:
        # `socket.gethostbyname_ex` returns (canonical, aliases, ip_list).
        # We treat ALL resolved IPs as "must pass the gate" — a DNS
        # entry with one public + one private IP is a DNS rebinding
        # vector and we refuse it.
        _, _, ip_list = socket.gethostbyname_ex(hostname)
    except socket.gaierror as e:
        # DNS resolution failed. Refuse — we can't verify the host is
        # external. The operator can re-attempt later if it was a
        # transient failure.
        raise SSRFRejectedError(
            f"could not resolve webhook hostname {hostname!r}: {e}"
        ) from e
    if not ip_list:
        raise SSRFRejectedError(
            f"webhook hostname {hostname!r} resolved to no IPs"
        )
    for ip in ip_list:
        if _is_internal_ip(ip):
            raise SSRFRejectedError(
                f"webhook hostname {hostname!r} resolves to internal IP "
                f"{ip}. Refusing to forward (SSRF gate); pass "
                "--allow-internal-webhook to permit."
            )


def gate_webhook_license(license_obj: Any) -> None:
    """Refuse if the operator passed webhook flags without an active
    Enterprise license. Reads the license via `iam_jit.license`'s
    existing plumbing (per the user-count-soft-cap pattern).

    Raises `WebhookLicenseError` on a refusal; returns None on success.
    """
    # Local import so this module doesn't take a hard dep on the
    # license module at import time (keeps the audit_export package
    # easy to unit-test in isolation).
    from ... import license as license_mod

    if license_obj is None:
        try:
            license_obj = license_mod.load_license()
        except license_mod.LicenseInvalidError as e:
            raise WebhookLicenseError(
                f"audit webhook requires a valid Enterprise license. "
                f"The license file at the configured path failed "
                f"verification: {e}. See docs/LICENSE.md."
            ) from e
    if license_obj is None or license_obj.tier != "enterprise":
        tier = license_obj.tier if license_obj is not None else "free"
        raise WebhookLicenseError(
            f"audit webhook requires an Enterprise license; current tier "
            f"is {tier!r}. The JSONL log channel (--audit-log-path) is "
            f"available on all tiers. See docs/LICENSE.md to obtain an "
            f"Enterprise license."
        )


class WebhookPusher:
    """Async HTTPS webhook pusher.

    Lifecycle::

        pusher = WebhookPusher(
            url="https://collector.example.com/audit",
            token="secret-bearer-token",
        )
        await pusher.start()
        pusher.push({"ts": "...", ...})  # never blocks
        await pusher.stop()

    The token is held in a private attribute that NEVER appears in
    str(self) / repr(self). The `status()` snapshot reports only
    `webhook_configured: True/False`; the token itself is absent.
    """

    def __init__(
        self,
        *,
        url: str,
        token: str,
        batch_size: int = 1,
        queue_maxsize: int = DEFAULT_WEBHOOK_QUEUE_MAXSIZE,
        allow_internal: bool = False,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        timeout_seconds: float = 10.0,
        # For tests: inject a fake aiohttp session. Production callers
        # leave this None + the worker builds its own pooled session.
        _session_factory: Any | None = None,
        # For tests: inject a fake sleep so the backoff schedule can
        # be exercised without real wall-clock waits. Production
        # callers leave this None.
        _sleep: Any | None = None,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self.url = url
        self._token = token
        self.batch_size = batch_size
        self.queue_maxsize = queue_maxsize
        self.allow_internal = allow_internal
        self.max_attempts = max_attempts
        self.timeout_seconds = timeout_seconds
        self._session_factory = _session_factory
        self._sleep = _sleep or asyncio.sleep
        self._queue: asyncio.Queue[dict[str, Any] | None] | None = None
        self._worker_task: asyncio.Task | None = None
        self._session: Any | None = None
        self._owns_session = False
        # Stats — read by the MCP `bouncer_audit_export_status` tool.
        self._stats_lock = threading.Lock()
        self._total_events = 0
        self._dropped_events = 0
        # `_dropped_since_last_synthetic` is the running count that
        # gets attached to the next AUDIT_DROPPED synthetic + reset.
        self._dropped_since_last_synthetic = 0
        self._in_flight = 0
        self._last_error: str | None = None
        self._started = False

    def __repr__(self) -> str:
        # Defensive: NEVER include the token in the default repr.
        return (
            f"WebhookPusher(url={mask_url_userinfo(self.url)!r}, "
            f"token=***, batch_size={self.batch_size}, "
            f"queue_maxsize={self.queue_maxsize})"
        )

    async def start(self) -> None:
        """Validate URL (SSRF gate), build the queue, spawn worker."""
        if self._started:
            return
        # SSRF gate fires at start so a fresh DNS resolution happens
        # at process boot (not just at CLI parse, in case the URL was
        # validated by a different parent process or a long-running
        # daemon was reloaded with the same flag).
        validate_webhook_url(self.url, allow_internal=self.allow_internal)
        self._queue = asyncio.Queue(maxsize=self.queue_maxsize)
        if self._session_factory is None:
            try:
                import aiohttp
                self._session = aiohttp.ClientSession()
                self._owns_session = True
            except ImportError as e:
                raise RuntimeError(
                    "aiohttp is required for the webhook pusher. "
                    "Install it: pip install 'aiohttp>=3.9'"
                ) from e
        else:
            self._session = self._session_factory()
            self._owns_session = False
        self._worker_task = asyncio.create_task(
            self._worker(),
            name="ibounce-audit-webhook-pusher",
        )
        self._started = True

    async def stop(self) -> None:
        if not self._started:
            return
        try:
            await self._queue.put(None)
        except Exception:
            pass
        if self._worker_task is not None:
            try:
                await self._worker_task
            except Exception as e:
                logger.warning("webhook pusher worker exited with %s", e)
        if self._owns_session and self._session is not None:
            try:
                await self._session.close()
            except Exception:
                pass
        self._session = None
        self._started = False

    def push(self, event: dict[str, Any]) -> None:
        """Enqueue one event for the worker. NEVER blocks. NEVER raises.

        Returns immediately. On overflow, the event is dropped + the
        dropped counter is bumped; the next successful send carries
        an AUDIT_DROPPED synthetic event AHEAD of the batch so the
        downstream consumer sees the gap explicitly.
        """
        if not self._started or self._queue is None:
            return
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            with self._stats_lock:
                self._dropped_events += 1
                self._dropped_since_last_synthetic += 1
                self._last_error = (
                    f"webhook queue full at {self.queue_maxsize}; dropped event"
                )

    async def _worker(self) -> None:
        """Drain loop. Pulls up to `batch_size` events at a time +
        sends them with exponential-backoff retry."""
        assert self._queue is not None
        while True:
            batch: list[dict[str, Any]] = []
            first = await self._queue.get()
            if first is None:
                return
            batch.append(first)
            # Try to coalesce up to batch_size without blocking.
            while len(batch) < self.batch_size:
                try:
                    nxt = self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if nxt is None:
                    # Sentinel arrived mid-batch — send what we have,
                    # then exit on the next iteration. Re-queue the
                    # sentinel so the outer loop sees it.
                    await self._queue.put(None)
                    break
                batch.append(nxt)

            # Prepend an AUDIT_DROPPED synthetic if any drops have
            # happened since the last send. Reset the counter ONLY
            # after a successful send (otherwise a retry-storm could
            # double-count).
            with self._stats_lock:
                pending_drops = self._dropped_since_last_synthetic
            if pending_drops > 0:
                synthetic = audit_dropped_event(
                    dropped_count=pending_drops,
                    reason="webhook-queue-overflow",
                )
                batch.insert(0, synthetic)

            try:
                await self._send_with_retry(batch)
                # On success: clear the drop-pending counter ONLY by
                # the amount we actually advertised in the synthetic.
                # New drops that landed during the send remain
                # pending for the NEXT batch.
                if pending_drops > 0:
                    with self._stats_lock:
                        self._dropped_since_last_synthetic -= pending_drops
                with self._stats_lock:
                    self._total_events += len(batch)
            except Exception as e:
                # Final-failure: drop the batch + record. We do NOT
                # raise into the worker loop because that would kill
                # the task; the bouncer must remain operational even
                # if the customer's collector is down for weeks.
                masked_url = mask_url_userinfo(self.url)
                self._record_error(
                    f"webhook send to {masked_url} failed after "
                    f"{self.max_attempts} attempts: {e}"
                )
                with self._stats_lock:
                    self._dropped_events += len(batch)
                    self._dropped_since_last_synthetic += len(batch)

    async def _send_with_retry(self, batch: list[dict[str, Any]]) -> None:
        """One send attempt + retry loop. Retries on 5xx + network
        error; gives up on 4xx (which is a config bug, not a transient
        — repeating it just spams the operator's collector with 4xx
        traffic).

        Schedule: 1s -> 2s -> 4s -> 8s -> 16s -> 32s, capped at
        `max_attempts` total attempts.
        """
        # NB: aiohttp is imported lazily so the audit_export package
        # is unit-testable without the dep being present.
        last_exc: Exception | None = None
        for attempt in range(self.max_attempts):
            with self._stats_lock:
                self._in_flight = len(batch)
            try:
                await self._send_once(batch)
                with self._stats_lock:
                    self._in_flight = 0
                return  # success
            except _NonRetryableHTTPError as e:
                # 4xx — don't retry; this is a config bug.
                masked_url = mask_url_userinfo(self.url)
                raise RuntimeError(
                    f"webhook {masked_url} returned non-retryable HTTP "
                    f"{e.status}; check token + URL"
                ) from None
            except Exception as e:
                last_exc = e
                if attempt + 1 >= self.max_attempts:
                    break
                # Sleep according to the schedule (capped at the last
                # entry for any attempt beyond the schedule length).
                delay = _BACKOFF_SCHEDULE_SECONDS[
                    min(attempt, len(_BACKOFF_SCHEDULE_SECONDS) - 1)
                ]
                await self._sleep(delay)
        with self._stats_lock:
            self._in_flight = 0
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("webhook send failed (no exception captured)")

    async def _send_once(self, batch: list[dict[str, Any]]) -> None:
        """One HTTP POST attempt. Raises _NonRetryableHTTPError on 4xx
        + any other Exception on a transient (5xx, timeout, network)
        for the retry loop to consume."""
        assert self._session is not None
        # The bearer token lives in the Authorization header. We do
        # NOT log this header anywhere; the masked-URL is the only
        # thing that surfaces in error messages.
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "User-Agent": "ibounce-audit-export/1.0",
        }
        # Wire format: NDJSON (one JSON object per line). Matches the
        # JSONL log channel so a collector that ingests both can
        # share a parser. batch_size=1 effectively emits one object
        # per request.
        import json as _json
        body = "\n".join(_json.dumps(e, ensure_ascii=False) for e in batch)
        try:
            async with self._session.post(
                self.url, data=body, headers=headers,
                timeout=self.timeout_seconds,
            ) as resp:
                status = resp.status
                if 200 <= status < 300:
                    # Drain to be a good HTTP citizen.
                    await resp.read()
                    return
                if 400 <= status < 500:
                    await resp.read()
                    raise _NonRetryableHTTPError(status)
                # 5xx + 3xx (we treat redirects as transient — a
                # collector that suddenly redirects is misconfigured).
                await resp.read()
                raise RuntimeError(f"upstream HTTP {status}")
        except _NonRetryableHTTPError:
            raise
        except asyncio.TimeoutError as e:
            raise RuntimeError(
                f"webhook send timed out after {self.timeout_seconds}s"
            ) from e
        # NB: we deliberately don't catch the broad `except Exception:`
        # here so the retry loop can see the real cause. Bearer token
        # never appears in any of the exception messages above.

    def _record_error(self, msg: str) -> None:
        with self._stats_lock:
            self._last_error = msg
        # The masked URL is the only thing that surfaces here.
        logger.warning("webhook pusher error: %s", msg)

    def status(self) -> dict[str, Any]:
        """Snapshot for the MCP status tool. NEVER includes the token."""
        with self._stats_lock:
            return {
                "configured": True,
                "url": mask_url_userinfo(self.url),
                "token": mask_token(self._token),
                "batch_size": self.batch_size,
                "queue_maxsize": self.queue_maxsize,
                "allow_internal": self.allow_internal,
                "max_attempts": self.max_attempts,
                "total_events": self._total_events,
                "dropped_events": self._dropped_events,
                "webhook_in_flight": self._in_flight,
                "last_error": self._last_error,
            }


class _NonRetryableHTTPError(Exception):
    """4xx response — don't retry. Internal-only; not exported."""
    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status
