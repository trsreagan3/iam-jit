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


def test_xff_header_is_used_when_trust_is_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Behind CloudFront the original IP is in XFF; honor it."""
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_FOR", raising=False)
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "203.0.113.0/24")
    d = network_acl.evaluate(
        path="/api/v1/requests",
        request_client_host="10.0.0.1",  # CloudFront's IP
        xff_header="203.0.113.5, 10.0.0.1",  # original caller first
    )
    assert d.allowed is True
    assert d.source_ip == "203.0.113.5"


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
    the middleware refuses BEFORE auth runs (so this still 403s
    even though as_dev is a valid logged-in user).

    Pass a valid (but-out-of-range) source IP via X-Forwarded-For
    since starlette's TestClient sets `client.host = 'testclient'`
    which isn't a parseable address."""
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "203.0.113.0/24")
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    r = as_dev.get(
        "/api/v1/users/me",
        headers={"X-Forwarded-For": "198.51.100.5"},
    )
    assert r.status_code == 403
    body = r.json()
    assert body["reason"] == "ip_not_in_allowlist"


def test_healthz_remains_open_under_acl(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "203.0.113.0/24")
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "0")
    r = client.get("/healthz")
    assert r.status_code == 200


def test_request_allowed_via_xff(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    r = as_dev.get(
        "/api/v1/users/me",
        headers={"X-Forwarded-For": "10.5.6.7"},
    )
    assert r.status_code == 200


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
