"""URL-resolution tests.

These pin the precedence (XFH > env var > request.base_url) so a
refactor that breaks magic-link delivery behind CloudFront fails
locally instead of producing dead links in production.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from iam_jit import public_url


def _fake_request(
    headers: dict[str, str] | None = None,
    base_url: str = "https://lambda-url.example.com/",
    peer_host: str = "10.0.0.5",
) -> Any:
    """Minimal Request-like stand-in. The helper touches
    `.headers` (Mapping-like), `.base_url` (string-coercible), and
    `.client.host` (peer IP — used by the BB2-09 trusted-proxy
    gate)."""
    return SimpleNamespace(
        headers=(headers or {}),
        base_url=base_url,
        client=SimpleNamespace(host=peer_host),
    )


def test_falls_back_to_request_base_url_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_HOST", raising=False)
    monkeypatch.delenv("IAM_JIT_PUBLIC_URL", raising=False)
    req = _fake_request(base_url="https://lambda-url.example.com/")
    assert public_url.base_for(req) == "https://lambda-url.example.com"


def test_env_var_overrides_request_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_HOST", raising=False)
    monkeypatch.setenv("IAM_JIT_PUBLIC_URL", "https://iam-jit.example.com")
    req = _fake_request(base_url="https://lambda-url.example.com/")
    assert public_url.base_for(req) == "https://iam-jit.example.com"


def test_xfh_wins_when_trust_flag_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CloudFront posture (BB2-09 closure): trust flag on, peer
    in trusted-proxy CIDRs, AND the XFH value is in the allowed
    public-host list. All three must be present."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_HOST", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_ALLOWED_PUBLIC_HOSTS", "d1234.cloudfront.net")
    monkeypatch.setenv("IAM_JIT_PUBLIC_URL", "https://stale.example.com")
    req = _fake_request(
        headers={
            "x-forwarded-host": "d1234.cloudfront.net",
            "x-forwarded-proto": "https",
        },
        base_url="https://lambda-url.example.com/",
    )
    assert public_url.base_for(req) == "https://d1234.cloudfront.net"


def test_xfh_takes_first_when_comma_separated(monkeypatch: pytest.MonkeyPatch) -> None:
    """A request that hits Layer-7 LB → CloudFront → Lambda can stack
    multiple XFH values. Take the leftmost (the public host the user
    actually typed) — and the public-host allowlist must include it
    for the BB2-09 gate to honor it."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_HOST", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_ALLOWED_PUBLIC_HOSTS", "iam-jit.example.com")
    req = _fake_request(
        headers={"x-forwarded-host": "iam-jit.example.com, d1234.cloudfront.net"},
    )
    assert public_url.base_for(req) == "https://iam-jit.example.com"


def test_xfh_ignored_when_trust_flag_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the explicit trust flag, an attacker spoofing
    X-Forwarded-Host CANNOT redirect magic-links to their own domain."""
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_HOST", raising=False)
    monkeypatch.delenv("IAM_JIT_PUBLIC_URL", raising=False)
    req = _fake_request(
        headers={"x-forwarded-host": "attacker.example.com"},
        base_url="https://real.example.com/",
    )
    assert public_url.base_for(req) == "https://real.example.com"


def test_xfh_default_scheme_is_https(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_HOST", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_ALLOWED_PUBLIC_HOSTS", "iam-jit.example.com")
    req = _fake_request(headers={"x-forwarded-host": "iam-jit.example.com"})
    # No XFP header → assume https (the standard for any prod CDN).
    assert public_url.base_for(req) == "https://iam-jit.example.com"


def test_xfp_overrides_default_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_HOST", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_ALLOWED_PUBLIC_HOSTS", "iam-jit.example.com")
    req = _fake_request(
        headers={
            "x-forwarded-host": "iam-jit.example.com",
            "x-forwarded-proto": "http",
        },
    )
    assert public_url.base_for(req) == "http://iam-jit.example.com"


def test_bb2_09_xfh_ignored_when_peer_not_trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    """BB2-09 closure: even with TRUST_FORWARDED_HOST=1 and an
    allowed-public-hosts list set, an attacker hitting the Function
    URL directly (peer outside trusted-proxy CIDRs) cannot poison
    the public base URL."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_HOST", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_ALLOWED_PUBLIC_HOSTS", "iam-jit.example.com")
    req = _fake_request(
        headers={"x-forwarded-host": "iam-jit.example.com"},
        peer_host="203.0.113.42",  # not in 10.0.0.0/8
    )
    assert public_url.base_for(req) == "https://lambda-url.example.com"


def test_bb2_09_xfh_ignored_when_value_not_in_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BB2-09 closure: even from a trusted proxy, an XFH value not
    in the public-host allowlist is ignored. Defense-in-depth
    against a misconfigured / compromised proxy."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_HOST", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_ALLOWED_PUBLIC_HOSTS", "iam-jit.example.com")
    req = _fake_request(
        headers={"x-forwarded-host": "evil.attacker.example"},
        peer_host="10.0.0.5",
    )
    assert public_url.base_for(req) == "https://lambda-url.example.com"


def test_no_request_falls_back_to_env_or_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scheduled Lambda path has no Request object — the helper
    still needs to produce something usable for tests / logging."""
    monkeypatch.setenv("IAM_JIT_PUBLIC_URL", "https://iam-jit.example.com")
    assert public_url.base_for(None) == "https://iam-jit.example.com"
    monkeypatch.delenv("IAM_JIT_PUBLIC_URL", raising=False)
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_HOST", raising=False)
    assert public_url.base_for(None) == "http://127.0.0.1:8000"


def test_absolute_joins_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_HOST", raising=False)
    monkeypatch.setenv("IAM_JIT_PUBLIC_URL", "https://iam-jit.example.com")
    assert (
        public_url.absolute(None, "/setup")
        == "https://iam-jit.example.com/setup"
    )
    # Missing leading slash is fixed up.
    assert (
        public_url.absolute(None, "api/v1/users/me")
        == "https://iam-jit.example.com/api/v1/users/me"
    )
