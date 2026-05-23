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


def fetch_feed(
    url: str,
    *,
    cache_dir: pathlib.Path | None = None,
    allow_insecure_http: bool = False,
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
            # Read up to the cap. urllib doesn't enforce a max — we do.
            body_bytes = resp.read(_MAX_FEED_BYTES + 1)
            if body_bytes and len(body_bytes) > _MAX_FEED_BYTES:
                error_reason = (
                    f"feed body exceeded {_MAX_FEED_BYTES} bytes cap"
                )
                body_bytes = None
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
    "fetch_feed",
    "load_cached_feed",
    "resolve_cache_dir",
]
