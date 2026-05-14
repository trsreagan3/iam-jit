"""Source-IP / CIDR allowlist tests."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from iam_jit import network_acl


pytest_plugins = ["tests.conftest_routes"]


# ---- pure decision logic ----


def test_no_acl_configured_allows_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", raising=False)
    d = network_acl.evaluate(
        path="/api/v1/users/me",
        request_client_host="203.0.113.5",
        xff_header=None,
    )
    assert d.allowed is True
    assert d.reason == "no_acl_configured"


def test_exempt_paths_skip_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8")
    for path in ("/healthz", "/static/style.css", "/static/chat.js"):
        d = network_acl.evaluate(
            path=path,
            request_client_host="203.0.113.5",  # outside allowlist
            xff_header=None,
        )
        assert d.allowed is True, path


def test_ip_in_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8,192.168.0.0/16"
    )
    d = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="10.5.6.7",
        xff_header=None,
    )
    assert d.allowed is True
    assert d.matched_cidr == "10.0.0.0/8"
    assert d.source_ip == "10.5.6.7"


def test_ip_not_in_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8")
    d = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="203.0.113.5",
        xff_header=None,
    )
    assert d.allowed is False
    assert d.reason == "ip_not_in_allowlist"


def test_xff_header_is_ignored_when_no_trusted_proxy_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default-off posture: XFF is NOT trusted unless the operator
    explicitly opts in AND configures `IAM_JIT_TRUSTED_PROXY_CIDRS`.
    BB2-02 closure — internet-exposed Function URLs cannot be
    bypassed by XFF spoofing.
    """
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_FOR", raising=False)
    monkeypatch.delenv("IAM_JIT_TRUSTED_PROXY_CIDRS", raising=False)
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "203.0.113.0/24")
    d = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="10.0.0.1",
        xff_header="203.0.113.5, 10.0.0.1",
    )
    assert d.allowed is False
    assert d.source_ip == "10.0.0.1"


def test_xff_header_honored_when_peer_in_trusted_proxy_cidrs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When TRUST_FORWARDED_FOR=1 AND the immediate peer falls in a
    configured trusted-proxy CIDR, walk XFF right-to-left to find
    the first untrusted hop. That's the real client.
    """
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "203.0.113.0/24")
    d = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="10.0.0.1",
        xff_header="198.51.100.99, 203.0.113.5",
    )
    assert d.allowed is True
    assert d.source_ip == "203.0.113.5"


def test_xff_leftmost_attacker_token_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The leftmost XFF token is attacker-controlled. With a trusted
    proxy, we must walk RIGHT to skip past proxy hops and find the
    real client. An attacker who spoofs a leftmost in-range IP must
    not bypass the allowlist.
    """
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "203.0.113.0/24")
    d = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="10.0.0.1",
        xff_header="203.0.113.5, 198.51.100.7",
    )
    assert d.allowed is False
    assert d.source_ip == "198.51.100.7"


def test_xff_header_ignored_when_trust_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct Function URL exposure: XFF must not be trusted."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "0")
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "203.0.113.0/24")
    d = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="198.51.100.1",
        xff_header="203.0.113.5",  # attacker-spoofed
    )
    assert d.allowed is False
    assert d.source_ip == "198.51.100.1"


def test_invalid_cidr_in_config_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If every entry is malformed, refuse — operator clearly intended
    a restriction."""
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "not-a-cidr,also-bad")
    d = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="10.0.0.1",
        xff_header=None,
    )
    assert d.allowed is False
    assert d.reason == "invalid_acl_config"


def test_invalid_cidr_alongside_valid_skips_only_the_bad_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One typo doesn't disable the whole ACL."""
    monkeypatch.setenv(
        "IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8,not-a-cidr,192.168.0.0/16"
    )
    d_in = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="10.5.6.7",
        xff_header=None,
    )
    assert d_in.allowed is True
    d_out = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="203.0.113.5",
        xff_header=None,
    )
    assert d_out.allowed is False


def test_explicit_zero_allows_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """0.0.0.0/0 is the explicit-public escape hatch."""
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "0.0.0.0/0")
    d = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="1.2.3.4",
        xff_header=None,
    )
    assert d.allowed is True


def test_ipv6_source_doesnt_match_ipv4_acl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cross-family checks shouldn't crash."""
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8")
    d = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="2001:db8::1",
        xff_header=None,
    )
    assert d.allowed is False


def test_ipv6_acl_matches_ipv6_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "2001:db8::/32")
    d = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="2001:db8::1",
        xff_header=None,
    )
    assert d.allowed is True


# ---- middleware integration ----


def test_request_blocked_at_middleware_with_403(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Configure an allowlist that excludes the test client; confirm
    the middleware refuses BEFORE auth runs. Under the BB2-02
    closure (default-off XFF trust), the unparseable 'testclient'
    peer + ignored XFF means the request 403s with
    'invalid_source_ip' — still blocked at the middleware layer
    BEFORE auth runs, which is what this test asserts."""
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "203.0.113.0/24")
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_FOR", raising=False)
    monkeypatch.delenv("IAM_JIT_TRUSTED_PROXY_CIDRS", raising=False)
    r = as_dev.get(
        "/api/v1/users/me",
        headers={"X-Forwarded-For": "198.51.100.5"},
    )
    assert r.status_code == 403
    body = r.json()
    assert body["reason"] in {"ip_not_in_allowlist", "invalid_source_ip"}


def test_healthz_remains_open_under_acl(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "203.0.113.0/24")
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "0")
    r = client.get("/healthz")
    assert r.status_code == 200


def test_request_allowed_via_xff_requires_trusted_proxy_peer(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BB2-02 closure: even with TRUST_FORWARDED_FOR=1 and the XFF
    value in-range, the middleware refuses to honor XFF when the
    immediate peer is not in a configured trusted-proxy CIDR. The
    TestClient peer 127.0.0.1 is excluded from the trusted-proxy
    set (172.16.0.0/12 covers only RFC1918 private), confirming the
    gate is real."""
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "172.16.0.0/12")
    r = as_dev.get(
        "/api/v1/users/me",
        headers={"X-Forwarded-For": "10.5.6.7"},
    )
    assert r.status_code == 403


# ---- helpers ----


def test_get_configured_cidrs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8, 192.168.0.0/16")
    cidrs = network_acl.get_configured_cidrs()
    assert cidrs == ["10.0.0.0/8", "192.168.0.0/16"]
    assert network_acl.is_acl_configured() is True


def test_get_configured_cidrs_empty_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", raising=False)
    assert network_acl.get_configured_cidrs() == []
    assert network_acl.is_acl_configured() is False


# ---- multi-CIDR ergonomics ----


@pytest.mark.parametrize(
    "raw,expected",
    [
        # Comma-separated.
        ("10.0.0.0/8,192.168.0.0/16", ["10.0.0.0/8", "192.168.0.0/16"]),
        # Comma + spaces (the human-friendly default).
        ("10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12",
         ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]),
        # Newline-separated (copy-paste from a config file).
        ("10.0.0.0/8\n192.168.0.0/16", ["10.0.0.0/8", "192.168.0.0/16"]),
        # Space-separated only (copy-paste from a CLI prompt).
        ("10.0.0.0/8 192.168.0.0/16", ["10.0.0.0/8", "192.168.0.0/16"]),
        # Mixed delimiters + extra whitespace.
        ("10.0.0.0/8,  192.168.0.0/16\n  172.16.0.0/12 ",
         ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]),
        # Bare IPs auto-promoted to /32.
        ("203.0.113.5", ["203.0.113.5/32"]),
        ("203.0.113.5, 198.51.100.10",
         ["203.0.113.5/32", "198.51.100.10/32"]),
        # Mix of bare IPs and CIDRs.
        ("10.0.0.0/8, 203.0.113.5",
         ["10.0.0.0/8", "203.0.113.5/32"]),
    ],
)
def test_cidr_parser_accepts_any_reasonable_format(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: list[str]
) -> None:
    """An agent or human pasting a list shouldn't need special
    formatting — comma, space, newline, or mixed all work, and bare
    IPs auto-promote to /32 or /128."""
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", raw)
    assert network_acl.get_configured_cidrs() == expected


def test_cidr_parser_skips_individual_typos(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One bad token doesn't disable the rest. The allowlist is the
    valid ones; the bad token is silently dropped (logged, not
    raised)."""
    monkeypatch.setenv(
        "IAM_JIT_ALLOWED_SOURCE_CIDRS",
        "10.0.0.0/8, definitely-not-an-ip, 192.168.0.0/16",
    )
    assert network_acl.get_configured_cidrs() == [
        "10.0.0.0/8", "192.168.0.0/16",
    ]


def test_bare_ipv6_auto_promotes_to_128(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "2001:db8::1")
    assert network_acl.get_configured_cidrs() == ["2001:db8::1/128"]
