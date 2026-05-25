"""#407 / §A51 — Threat-feed fetcher + local cache.

Per [[independence-as-security-property]] the fetcher is operator-
driven; the operator's local process pulls (NOT a vendor push). On any
fetch failure the cache is returned + the failure surfaces as an
admin_action OCSF event (handled by the applier) — the bouncer never
silently degrades to "empty feed".

Cache layout (under ``~/.iam-jit/threat_feed/cache/`` by default; env
override ``IAM_JIT_THREAT_FEED_CACHE_DIR``):

    <url_sha256>.json          — last successfully fetched + parsed feed
    <url_sha256>.meta.json     — last fetch metadata (timestamp, etag,
                                  http_status, source_url, manifest hash)

The metadata file separates "last fetch attempt" from "last successful
fetch" so an operator running ``iam-jit updates last-fetch`` sees both
columns. Per [[ibounce-honest-positioning]] we surface the truth — a
24h-old cache shown as "stale" rather than "current".

Both files are 0600-perm. Atomic write (write-temp + rename) so a
concurrent reader never sees a half-written file.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import logging
import os
import pathlib
import tempfile
import typing
import urllib.error
import urllib.request

from .models import Feed, FeedParseError, parse_feed_dict

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


CACHE_DIR_ENV = "IAM_JIT_THREAT_FEED_CACHE_DIR"
_DEFAULT_CACHE_REL = pathlib.Path(".iam-jit") / "threat_feed" / "cache"


def resolve_cache_dir() -> pathlib.Path:
    """Return the cache directory the fetcher reads/writes."""
    raw = (os.environ.get(CACHE_DIR_ENV) or "").strip()
    if raw:
        return pathlib.Path(raw).expanduser()
    return pathlib.Path.home() / _DEFAULT_CACHE_REL


def _slug_for_url(url: str) -> str:
    """Return a deterministic filesystem-safe slug for a feed URL."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]


def _feed_path(url: str, cache_dir: pathlib.Path | None = None) -> pathlib.Path:
    return (cache_dir or resolve_cache_dir()) / f"{_slug_for_url(url)}.json"


def _meta_path(url: str, cache_dir: pathlib.Path | None = None) -> pathlib.Path:
    return (cache_dir or resolve_cache_dir()) / f"{_slug_for_url(url)}.meta.json"


# ---------------------------------------------------------------------------
# Errors + result dataclass
# ---------------------------------------------------------------------------


class FeedFetchError(RuntimeError):
    """Raised by :func:`fetch_feed` for INPUT-side errors (malformed URL,
    refused insecure HTTP, etc.). Network failures + parse failures
    return a :class:`FeedFetchResult` with ``feed=None`` + ``error``
    set — so the autopilot loop never crashes on a flaky feed host."""


@dataclasses.dataclass(frozen=True)
class FeedFetchResult:
    """Outcome of one fetch attempt."""

    url: str
    feed: Feed | None
    """Parsed feed on success; None on every failure path."""

    cached: bool
    """True iff the returned feed came from the local cache (network
    failed; cache served the last known good copy)."""

    fetched_at: str
    """ISO 8601 UTC timestamp the fetch attempt happened."""

    http_status: int | None
    """HTTP status code from the network attempt, or None when
    network was not attempted (e.g. file:// URL, error before fetch)."""

    error: str = ""
    """Structured error string when feed is None OR (cached=True AND
    network failed). Empty on clean network fetch."""

    manifest_sha256: str = ""

    def as_dict(self) -> dict[str, typing.Any]:
        return {
            "url": self.url,
            "feed": self.feed.as_dict() if self.feed else None,
            "cached": self.cached,
            "fetched_at": self.fetched_at,
            "http_status": self.http_status,
            "error": self.error,
            "manifest_sha256": self.manifest_sha256,
        }


# ---------------------------------------------------------------------------
# Cache I/O
# ---------------------------------------------------------------------------


def load_cached_feed(
    url: str,
    *,
    cache_dir: pathlib.Path | None = None,
) -> tuple[Feed | None, dict[str, typing.Any]]:
    """Load (feed, metadata) for one URL from the cache. Returns
    ``(None, {})`` when not present."""
    cd = cache_dir or resolve_cache_dir()
    fp = _feed_path(url, cd)
    mp = _meta_path(url, cd)
    feed: Feed | None = None
    meta: dict[str, typing.Any] = {}
    if fp.exists():
        try:
            raw = json.loads(fp.read_text(encoding="utf-8"))
            feed = parse_feed_dict(raw)
        except (OSError, json.JSONDecodeError, FeedParseError) as e:
            logger.warning("threat_feed cache parse failed for %s: %s", url, e)
    if mp.exists():
        try:
            meta = json.loads(mp.read_text(encoding="utf-8"))
            if not isinstance(meta, dict):
                meta = {}
        except (OSError, json.JSONDecodeError):
            meta = {}
    return feed, meta


def _atomic_write(path: pathlib.Path, content: str, mode: int = 0o600) -> None:
    """Write ``content`` to ``path`` atomically (temp+rename) +
    ``chmod 0600``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _write_cache(
    url: str,
    feed: Feed,
    meta: dict[str, typing.Any],
    *,
    cache_dir: pathlib.Path | None = None,
) -> None:
    cd = cache_dir or resolve_cache_dir()
    _atomic_write(
        _feed_path(url, cd),
        json.dumps(feed.as_dict(), indent=2, sort_keys=True),
    )
    _atomic_write(
        _meta_path(url, cd),
        json.dumps(meta, indent=2, sort_keys=True),
    )


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


_FETCH_TIMEOUT_S = 10.0
_MAX_FEED_BYTES = 8 * 1024 * 1024
"""Hard cap on feed body bytes — defense against an attacker compromising
a publisher's host + serving a multi-GB blob that exhausts disk + RAM.
A real curated feed is well under 1 MB even with hundreds of entries."""


def _now_iso() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _validate_feed_url_ssrf(url: str, *, allow_internal: bool) -> None:
    """#524 WB-3 — gate the threat-feed URL through the same SSRF
    primitives the webhook + ``profile install --from URL`` surfaces
    use (``_hostname_has_internal_suffix`` + ``_is_internal_ip`` from
    ``bouncer.audit_export.webhook``).

    The fetcher accepts an operator-configured URL and the signature
    verification on the response payload mitigates RCE risk, but the
    fetcher itself could be coerced to probe internal IPs /
    cloud-metadata services / private network addresses (standard
    SSRF). This gate refuses those URLs BEFORE the network call.

    Categories rejected (per the underlying helper's categorisation):
      * loopback (127.0.0.0/8, ::1)
      * link-local (169.254.0.0/16) — includes AWS metadata 169.254.169.254
      * RFC1918 private (10/8, 172.16/12, 192.168/16)
      * IPv6 ULA (fc00::/7) — `ipaddress.is_private` covers this
      * multicast / unspecified / reserved
      * intranet hostname suffixes (.internal / .local / .home.arpa /
        .lan / .intranet / .corp / .localhost)

    file:// is NOT gated here (no network) — caller pre-checks scheme.

    Raises :class:`FeedFetchError` on a refusal — same error shape the
    fetcher uses for other INPUT-side rejections (so callers'
    try/except FeedFetchError continues to work).

    Per [[scorer-is-ground-truth]] this REUSES the existing helper
    primitives + does not reinvent SSRF logic. Per
    [[ibounce-honest-positioning]] the error message names the IP
    class rejected + the offending URL so the operator understands
    WHY the fetch was refused.
    """
    if allow_internal:
        return
    # Local import keeps the threat_feed package importable in
    # environments that don't load the audit_export module (e.g. some
    # unit tests).
    from ..bouncer.audit_export.webhook import (
        _hostname_has_internal_suffix,
        _is_internal_ip,
    )
    import socket
    import urllib.parse as _urlparse

    parsed = _urlparse.urlparse(url)
    hostname = parsed.hostname or ""
    if not hostname:
        # Fail-CLOSED per [[scorer-is-ground-truth]]: a URL the caller
        # passed in that we can't parse to a hostname is refused.
        raise FeedFetchError(
            f"refusing to fetch from {url!r}: missing hostname (SSRF gate)"
        )
    if _hostname_has_internal_suffix(hostname):
        raise FeedFetchError(
            f"refusing to fetch from {url!r}: hostname {hostname!r} "
            f"matches an intranet suffix (.internal / .local / "
            f".home.arpa / .lan / .intranet / .corp / .localhost). "
            f"SSRF gate; pass allow_internal=True for legitimate "
            f"internal distribution servers."
        )
    try:
        _, _, ip_list = socket.gethostbyname_ex(hostname)
    except socket.gaierror as e:
        raise FeedFetchError(
            f"refusing to fetch from {url!r}: could not resolve "
            f"hostname {hostname!r} (SSRF gate fails CLOSED on "
            f"unresolvable hosts): {e}"
        ) from e
    if not ip_list:
        raise FeedFetchError(
            f"refusing to fetch from {url!r}: hostname {hostname!r} "
            f"resolved to no IPs (SSRF gate)"
        )
    for ip in ip_list:
        if _is_internal_ip(ip):
            # Categorise the rejection so the operator sees WHY.
            # `_is_internal_ip` returns True for any of: private /
            # loopback / link-local / unspecified / reserved /
            # multicast. We name them explicitly to satisfy
            # [[ibounce-honest-positioning]].
            import ipaddress as _ipaddr
            try:
                parsed_ip = _ipaddr.ip_address(ip)
            except ValueError:
                category = "unparseable"
            else:
                if parsed_ip.is_loopback:
                    category = "loopback"
                elif parsed_ip.is_link_local:
                    category = "link-local (includes AWS metadata 169.254.169.254)"
                elif parsed_ip.is_private:
                    # ipaddress.is_private covers RFC1918 + IPv6 ULA
                    # (fc00::/7) per the stdlib spec.
                    category = "private (RFC1918 or IPv6 ULA)"
                elif parsed_ip.is_multicast:
                    category = "multicast"
                elif parsed_ip.is_unspecified:
                    category = "unspecified"
                elif parsed_ip.is_reserved:
                    category = "reserved"
                else:
                    category = "internal"
            raise FeedFetchError(
                f"refusing to fetch from {url!r}: hostname "
                f"{hostname!r} resolves to {category} IP {ip}. "
                f"SSRF gate; pass allow_internal=True for legitimate "
                f"internal distribution servers on a trusted segment."
            )


def fetch_feed(
    url: str,
    *,
    cache_dir: pathlib.Path | None = None,
    allow_insecure_http: bool = False,
    allow_internal: bool = False,
    timeout_s: float = _FETCH_TIMEOUT_S,
    use_cache_on_failure: bool = True,
) -> FeedFetchResult:
    """Fetch one feed URL + return :class:`FeedFetchResult`.

    Supports HTTPS (default), file:// (air-gap + tests), and HTTP only
    when the caller explicitly opts in via ``allow_insecure_http``.

    On network failure / parse failure: if a prior good cached copy
    exists + ``use_cache_on_failure=True`` returns it with
    ``cached=True`` + ``error=<reason>``. Otherwise returns a result
    with ``feed=None`` + ``error=<reason>``.

    Per [[ibounce-honest-positioning]] every cached-served result
    surfaces the failure reason so the operator's
    ``iam-jit updates last-fetch`` shows BOTH "last good fetch was X
    minutes ago" AND "last attempt failed with Y".

    #524 WB-3 — http(s) URLs are gated through the SSRF helper before
    any network call. Reject categories: loopback / link-local /
    RFC1918 / IPv6 ULA / intranet suffixes. file:// is exempt (no
    network). Pass ``allow_internal=True`` to bypass (only for
    legitimate internal distribution servers on a trusted segment).
    """
    if not url:
        raise FeedFetchError("url is required")
    lowered = url.lower()
    is_https = lowered.startswith("https://")
    is_http = lowered.startswith("http://")
    is_file = lowered.startswith("file://")
    if not (is_https or is_file or (is_http and allow_insecure_http)):
        raise FeedFetchError(
            f"unsupported URL scheme for {url!r}; HTTPS recommended, "
            f"file:// allowed for air-gap, HTTP requires "
            f"allow_insecure_http=True"
        )

    # #524 WB-3 — SSRF gate fires BEFORE any network call. file:// is
    # exempt (no network surface). The gate covers both http + https
    # because an attacker who controls the operator's declarative
    # config can point either at internal IPs / metadata services.
    if is_http or is_https:
        _validate_feed_url_ssrf(url, allow_internal=allow_internal)

    fetched_at = _now_iso()
    http_status: int | None = None
    error_reason = ""
    body_bytes: bytes | None = None

    try:
        req = urllib.request.Request(url, method="GET", headers={
            "User-Agent": "iam-jit-threat-feed/1.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(  # noqa: S310 — scheme-checked above
            req, timeout=timeout_s,
        ) as resp:
            http_status = getattr(resp, "status", None) or resp.getcode()
            # #524 WB-3 — urllib follows 3xx redirects by default (up
            # to ~10 hops), so an attacker can publish a URL that
            # 302s to http://169.254.169.254/... and slip past the
            # initial-URL gate. By the time urlopen returns, the
            # redirect chain has already completed — so we re-validate
            # the final URL. If the chain hit an internal IP, the gate
            # fires (we drop the already-fetched body). Mirrors the
            # ``bouncer_cli._fetch_install_payload`` redirect handling.
            final_url = resp.geturl()
            if final_url != url and (is_http or is_https):
                _validate_feed_url_ssrf(
                    final_url, allow_internal=allow_internal,
                )
            # Read up to the cap. urllib doesn't enforce a max — we do.
            body_bytes = resp.read(_MAX_FEED_BYTES + 1)
            if body_bytes and len(body_bytes) > _MAX_FEED_BYTES:
                error_reason = (
                    f"feed body exceeded {_MAX_FEED_BYTES} bytes cap"
                )
                body_bytes = None
    except FeedFetchError:
        # SSRF gate raised on the post-redirect URL. Re-raise so the
        # caller sees the same rejection shape as the pre-network gate.
        raise
    except urllib.error.HTTPError as e:
        http_status = e.code
        error_reason = f"http_error:{e.code}:{e.reason}"
    except urllib.error.URLError as e:
        error_reason = f"network_error:{e.reason}"
    except (OSError, TimeoutError) as e:
        error_reason = f"network_error:{e}"
    except Exception as e:  # pragma: no cover
        error_reason = f"unexpected:{e}"

    # Cache-fallback path.
    if body_bytes is None:
        if use_cache_on_failure:
            cached, _meta = load_cached_feed(url, cache_dir=cache_dir)
            if cached is not None:
                return FeedFetchResult(
                    url=url,
                    feed=cached,
                    cached=True,
                    fetched_at=fetched_at,
                    http_status=http_status,
                    error=error_reason or "no_response_body",
                    manifest_sha256=cached.manifest_sha256,
                )
        return FeedFetchResult(
            url=url,
            feed=None,
            cached=False,
            fetched_at=fetched_at,
            http_status=http_status,
            error=error_reason or "no_response_body",
            manifest_sha256="",
        )

    # Parse.
    try:
        raw_text = body_bytes.decode("utf-8")
        body_obj = json.loads(raw_text)
        feed = parse_feed_dict(body_obj)
    except (UnicodeDecodeError, json.JSONDecodeError, FeedParseError) as e:
        error_reason = f"parse_error:{e}"
        if use_cache_on_failure:
            cached, _meta = load_cached_feed(url, cache_dir=cache_dir)
            if cached is not None:
                return FeedFetchResult(
                    url=url,
                    feed=cached,
                    cached=True,
                    fetched_at=fetched_at,
                    http_status=http_status,
                    error=error_reason,
                    manifest_sha256=cached.manifest_sha256,
                )
        return FeedFetchResult(
            url=url,
            feed=None,
            cached=False,
            fetched_at=fetched_at,
            http_status=http_status,
            error=error_reason,
            manifest_sha256="",
        )

    # Persist to cache + metadata.
    manifest_sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    meta_blob: dict[str, typing.Any] = {
        "url": url,
        "last_fetch_at": fetched_at,
        "last_fetch_status": "ok",
        "http_status": http_status,
        "manifest_sha256": manifest_sha,
        "feed_id": feed.feed_id,
        "publisher": feed.publisher,
        "entry_count": len(feed.entries),
    }
    try:
        _write_cache(url, feed, meta_blob, cache_dir=cache_dir)
    except OSError as e:  # pragma: no cover — disk issue
        logger.warning("threat_feed cache write failed for %s: %s", url, e)

    return FeedFetchResult(
        url=url,
        feed=feed,
        cached=False,
        fetched_at=fetched_at,
        http_status=http_status,
        error="",
        manifest_sha256=manifest_sha,
    )


__all__ = [
    "CACHE_DIR_ENV",
    "FeedFetchError",
    "FeedFetchResult",
    "_validate_feed_url_ssrf",
    "fetch_feed",
    "load_cached_feed",
    "resolve_cache_dir",
]
