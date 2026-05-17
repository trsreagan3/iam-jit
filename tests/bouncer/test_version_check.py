"""Tests for `ibounce version-check` (#234).

Per [[update-release-strategy]] + [[self-host-zero-billing-dependency]]:
this subcommand is the explicit, opt-in operator-initiated exception to
the no-phone-home invariant. Tests pin that:

  - response parsing handles up-to-date / newer-available / network-error
  - both env-var opt-outs short-circuit BEFORE any urllib call
  - cache is read on second call + bypassed by --no-cache
  - the User-Agent header is set so GitHub can identify legitimate
    traffic
  - --quiet suppresses up-to-date output + still prints when newer

All GitHub calls are mocked via `unittest.mock.patch("urllib.request.urlopen")`
— no real network calls in the test suite (matches the pattern in
`tests/bouncer/test_profile_install.py`).
"""

from __future__ import annotations

import io
import json
import os
import pathlib
from contextlib import contextmanager
from unittest import mock

import pytest
from click.testing import CliRunner

from iam_jit import __version__ as LOCAL_VERSION
from iam_jit.bouncer_cli import main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeResp:
    """Minimal urlopen-compatible response object."""

    def __init__(self, body: bytes, *, status: int = 200) -> None:
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, *a) -> bool:
        return False


@contextmanager
def _mock_releases(payload: dict, *, capture: dict | None = None):
    """Patch urllib.request.urlopen to return `payload`.

    If `capture` is provided, the actual `urlopen` call's Request arg is
    stashed there for header / URL assertions.
    """
    body = json.dumps(payload).encode("utf-8")

    def _fake_urlopen(req, *args, **kwargs):
        if capture is not None:
            capture["req"] = req
            capture["args"] = args
            capture["kwargs"] = kwargs
        return _FakeResp(body)

    with mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen) as m:
        yield m


@pytest.fixture()
def isolated_cache(tmp_path, monkeypatch):
    """Per-test cache file location so tests can't see each other's
    cache writes."""
    p = tmp_path / "version_check.json"
    monkeypatch.setenv("IBOUNCE_VERSION_CHECK_CACHE", str(p))
    return p


@pytest.fixture(autouse=True)
def clean_opt_out_env(monkeypatch):
    """Ensure neither opt-out env var leaks into a test that doesn't
    explicitly set one."""
    monkeypatch.delenv("IBOUNCE_NO_VERSION_CHECK", raising=False)
    monkeypatch.delenv("IAM_JIT_NO_VERSION_CHECK", raising=False)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def test_up_to_date_response_prints_up_to_date(isolated_cache) -> None:
    runner = CliRunner()
    payload = {
        "tag_name": f"v{LOCAL_VERSION}",
        "html_url": "https://github.com/trsreagan3/iam-jit/releases/tag/"
                    f"v{LOCAL_VERSION}",
    }
    with _mock_releases(payload):
        result = runner.invoke(main, ["version-check"])
    assert result.exit_code == 0, result.output
    assert "up to date" in result.output
    assert LOCAL_VERSION in result.output


def test_newer_version_available_prints_release_url(isolated_cache) -> None:
    runner = CliRunner()
    # Construct a tag definitely-newer than LOCAL_VERSION by bumping
    # the major component (LOCAL_VERSION at 1.0.0 → 999.0.0).
    payload = {
        "tag_name": "v999.0.0",
        "html_url": "https://github.com/trsreagan3/iam-jit/releases/tag/v999.0.0",
    }
    with _mock_releases(payload):
        result = runner.invoke(main, ["version-check"])
    assert result.exit_code == 0, result.output
    assert "v999.0.0 available" in result.output
    assert "Release notes:" in result.output
    assert "github.com/trsreagan3/iam-jit/releases" in result.output


def test_network_error_prints_soft_error_and_exits_zero(isolated_cache) -> None:
    runner = CliRunner()
    import urllib.error

    with mock.patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("dns lookup failed"),
    ):
        result = runner.invoke(main, ["version-check"])
    assert result.exit_code == 0, result.output
    assert "unable to reach GitHub Releases" in result.output
    assert "not a phone-home" in result.output


# ---------------------------------------------------------------------------
# Env-var opt-out
# ---------------------------------------------------------------------------


def test_ibounce_no_version_check_env_short_circuits(
    isolated_cache, monkeypatch
) -> None:
    monkeypatch.setenv("IBOUNCE_NO_VERSION_CHECK", "1")
    runner = CliRunner()
    # If the env var fails to short-circuit, urlopen would be called +
    # raise (no mock installed) — the assertion would still pass on the
    # message text. So we ALSO assert urlopen wasn't touched.
    with mock.patch("urllib.request.urlopen") as m:
        result = runner.invoke(main, ["version-check"])
    assert result.exit_code == 0, result.output
    assert "version-check disabled by IBOUNCE_NO_VERSION_CHECK" in result.output
    assert m.call_count == 0


def test_iam_jit_no_version_check_alias_env_short_circuits(
    isolated_cache, monkeypatch
) -> None:
    monkeypatch.setenv("IAM_JIT_NO_VERSION_CHECK", "1")
    runner = CliRunner()
    with mock.patch("urllib.request.urlopen") as m:
        result = runner.invoke(main, ["version-check"])
    assert result.exit_code == 0, result.output
    assert "version-check disabled by IAM_JIT_NO_VERSION_CHECK" in result.output
    assert m.call_count == 0


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_cache_write_then_read_skips_second_network_call(isolated_cache) -> None:
    runner = CliRunner()
    payload = {
        "tag_name": "v999.0.0",
        "html_url": "https://github.com/trsreagan3/iam-jit/releases/tag/v999.0.0",
    }
    # First call: network path populates the cache.
    with _mock_releases(payload) as m1:
        result1 = runner.invoke(main, ["version-check"])
    assert result1.exit_code == 0
    assert m1.call_count == 1
    assert isolated_cache.exists(), "version-check should write cache after success"

    # Cache file mode = 0o600 (matches BB+WB audit (b)).
    mode = isolated_cache.stat().st_mode & 0o777
    assert mode == 0o600, f"cache file perms should be 0o600, got {oct(mode)}"

    # Second call: should hit cache, NOT urlopen.
    with mock.patch("urllib.request.urlopen") as m2:
        result2 = runner.invoke(main, ["version-check"])
    assert result2.exit_code == 0, result2.output
    assert m2.call_count == 0, "second call within TTL must not hit the network"
    assert "cached, checked" in result2.output
    assert "v999.0.0" in result2.output


def test_no_cache_flag_bypasses_cache(isolated_cache) -> None:
    runner = CliRunner()
    payload = {
        "tag_name": "v999.0.0",
        "html_url": "https://github.com/trsreagan3/iam-jit/releases/tag/v999.0.0",
    }
    # Populate cache.
    with _mock_releases(payload):
        runner.invoke(main, ["version-check"])
    assert isolated_cache.exists()

    # --no-cache should hit urlopen again even though cache is fresh.
    with _mock_releases(payload) as m:
        result = runner.invoke(main, ["version-check", "--no-cache"])
    assert result.exit_code == 0, result.output
    assert m.call_count == 1, "--no-cache must force a fresh network call"
    # Fresh-call output has no "cached, checked" suffix.
    assert "cached, checked" not in result.output


# ---------------------------------------------------------------------------
# User-Agent header
# ---------------------------------------------------------------------------


def test_user_agent_header_includes_local_version(isolated_cache) -> None:
    runner = CliRunner()
    payload = {
        "tag_name": f"v{LOCAL_VERSION}",
        "html_url": f"https://github.com/trsreagan3/iam-jit/releases/tag/v{LOCAL_VERSION}",
    }
    capture: dict = {}
    with _mock_releases(payload, capture=capture):
        result = runner.invoke(main, ["version-check"])
    assert result.exit_code == 0, result.output
    req = capture["req"]
    # urllib.request.Request stores headers title-cased.
    ua = req.get_header("User-agent")
    assert ua is not None, f"missing User-Agent on Request; headers={req.headers}"
    assert ua == f"ibounce-version-check/{LOCAL_VERSION}"
    assert req.full_url.startswith(
        "https://api.github.com/repos/trsreagan3/iam-jit/releases/latest"
    )


# ---------------------------------------------------------------------------
# --quiet
# ---------------------------------------------------------------------------


def test_quiet_suppresses_up_to_date_but_prints_when_newer(isolated_cache) -> None:
    runner = CliRunner()

    # Up-to-date + --quiet → empty (or whitespace-only) output.
    payload_same = {
        "tag_name": f"v{LOCAL_VERSION}",
        "html_url": f"https://github.com/trsreagan3/iam-jit/releases/tag/v{LOCAL_VERSION}",
    }
    with _mock_releases(payload_same):
        result_same = runner.invoke(main, ["version-check", "--quiet"])
    assert result_same.exit_code == 0
    assert "up to date" not in result_same.output
    assert result_same.output.strip() == ""

    # New cache to avoid the first call's write polluting the next.
    if isolated_cache.exists():
        isolated_cache.unlink()

    # Newer-available + --quiet → still prints.
    payload_newer = {
        "tag_name": "v999.0.0",
        "html_url": "https://github.com/trsreagan3/iam-jit/releases/tag/v999.0.0",
    }
    with _mock_releases(payload_newer):
        result_newer = runner.invoke(main, ["version-check", "--quiet"])
    assert result_newer.exit_code == 0
    assert "v999.0.0 available" in result_newer.output
