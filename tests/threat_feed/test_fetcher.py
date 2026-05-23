"""#407 / §A51 — Fetcher tests.

Exercises file:// URLs (no network) + the cache-fallback path. The
HTTPS path is exercised in the smoke test only — unit tests stay
hermetic.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from iam_jit.threat_feed import (
    FeedFetchError,
    fetch_feed,
    load_cached_feed,
    resolve_cache_dir,
)


def _feed_dict(rule_id: str = "tf_A") -> dict:
    return {
        "schema_version": "1.0",
        "feed_id": "test-v1",
        "publisher": "test",
        "generated_at": "2026-05-23T10:00:00Z",
        "entries": [{
            "rule_id": rule_id,
            "rule_kind": "informational_alert",
            "severity": "LOW",
            "compliance_tags": ["SOC2-CC6.1"],
        }],
        "manifest_sha256": "x",
    }


def test_fetch_file_url_writes_cache(tmp_path: pathlib.Path):
    feed_file = tmp_path / "feed.json"
    feed_file.write_text(json.dumps(_feed_dict()))
    url = f"file://{feed_file}"
    result = fetch_feed(url)
    assert result.feed is not None
    assert result.feed.feed_id == "test-v1"
    assert result.cached is False
    assert result.error == ""
    # Cache files written.
    cache_dir = resolve_cache_dir()
    files = list(cache_dir.glob("*"))
    assert len(files) == 2  # feed.json + meta.json


def test_fetch_unreachable_falls_back_to_cache(tmp_path: pathlib.Path):
    """When network fails + cache exists, return the cache."""
    feed_file = tmp_path / "feed.json"
    feed_file.write_text(json.dumps(_feed_dict()))
    url = f"file://{feed_file}"
    # First fetch populates the cache.
    fetch_feed(url)
    # Now delete the source.
    feed_file.unlink()
    # Re-fetch — file:// will fail, cache should serve.
    result = fetch_feed(url)
    assert result.feed is not None
    assert result.cached is True
    assert result.error  # error reason present


def test_fetch_refuses_http_unless_explicitly_allowed():
    with pytest.raises(FeedFetchError) as exc:
        fetch_feed("http://example.com/feed.json")
    assert "HTTPS" in str(exc.value) or "http" in str(exc.value).lower()


def test_fetch_refuses_unknown_scheme():
    with pytest.raises(FeedFetchError):
        fetch_feed("ftp://example.com/feed.json")


def test_load_cached_feed_returns_empty_when_absent():
    feed, meta = load_cached_feed("https://nowhere.example/feed")
    assert feed is None
    assert meta == {}


def test_fetch_returns_no_feed_when_neither_network_nor_cache_works(
    tmp_path: pathlib.Path,
):
    # file:// to a non-existent path with no cache.
    result = fetch_feed(f"file://{tmp_path}/missing.json")
    assert result.feed is None
    assert result.cached is False
    assert result.error
