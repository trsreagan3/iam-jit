"""Runtime CIDR allowlist tests."""

from __future__ import annotations

import pathlib
import time

import pytest
from fastapi.testclient import TestClient

from iam_jit import cidr_store


pytest_plugins = ["tests.conftest_routes"]


# ---- pure helpers ----


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("10.0.0.0/24", "10.0.0.0/24"),
        ("203.0.113.5", "203.0.113.5/32"),
        ("203.0.113.5/32", "203.0.113.5/32"),
        ("2001:db8::1", "2001:db8::1/128"),
        ("2001:db8::/32", "2001:db8::/32"),
        ("  10.0.0.0/8  ", "10.0.0.0/8"),
        # Non-strict CIDR (host bits set) gets normalized.
        ("10.0.0.5/8", "10.0.0.0/8"),
    ],
)
def test_normalize_cidr_canonicalizes(raw: str, expected: str) -> None:
    assert cidr_store.normalize_cidr(raw) == expected


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "not-an-ip", "999.999.999.999", "/24", "10.0.0.0/33"],
)
def test_normalize_cidr_rejects_garbage(bad: str) -> None:
    assert cidr_store.normalize_cidr(bad) is None


# ---- in-memory store contract ----


def _entry(cidr: str, note: str = "x", by: str = "test@example.com") -> cidr_store.CIDREntry:
    return cidr_store.CIDREntry(
        cidr=cidr, note=note, added_by=by, added_at=int(time.time())
    )


def test_in_memory_add_list_remove_round_trip() -> None:
    store = cidr_store.InMemoryCIDRStore()
    store.add(_entry("10.0.0.0/8", note="rfc1918"))
    store.add(_entry("203.0.113.5", note="office"))
    listed = store.list()
    assert {e.cidr for e in listed} == {"10.0.0.0/8", "203.0.113.5/32"}
    assert store.remove("10.0.0.0/8") is True
    assert store.remove("10.0.0.0/8") is False
    assert {e.cidr for e in store.list()} == {"203.0.113.5/32"}


def test_in_memory_add_replaces_existing() -> None:
    """Re-adding the same CIDR updates note/added_by rather than
    creating a duplicate."""
    store = cidr_store.InMemoryCIDRStore()
    store.add(_entry("10.0.0.0/8", note="v1", by="a"))
    store.add(_entry("10.0.0.0/8", note="v2", by="b"))
    listed = store.list()
    assert len(listed) == 1
    assert listed[0].note == "v2"
    assert listed[0].added_by == "b"


def test_in_memory_normalizes_on_add() -> None:
    store = cidr_store.InMemoryCIDRStore()
    store.add(_entry("203.0.113.5"))  # bare IP
    assert [e.cidr for e in store.list()] == ["203.0.113.5/32"]


def test_in_memory_rejects_bad_cidr_on_add() -> None:
    store = cidr_store.InMemoryCIDRStore()
    with pytest.raises(ValueError):
        store.add(_entry("not-a-cidr"))


# ---- filesystem store survives restart ----


def test_filesystem_store_persists_across_instances(tmp_path: pathlib.Path) -> None:
    s1 = cidr_store.FilesystemCIDRStore(tmp_path)
    s1.add(_entry("10.0.0.0/8", note="persisted"))
    s2 = cidr_store.FilesystemCIDRStore(tmp_path)
    listed = s2.list()
    assert [e.cidr for e in listed] == ["10.0.0.0/8"]
    assert listed[0].note == "persisted"


# ---- auto-seed on bootstrap admin sign-in ----


def test_auto_seed_when_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", raising=False)
    cidr_store.reset_default_store_for_tests()
    entry = cidr_store.auto_seed_for_bootstrap(
        source_ip="203.0.113.5",
        user_id="email:founder@example.com",
    )
    assert entry is not None
    assert entry.cidr == "203.0.113.5/32"
    listed = cidr_store.get_default_store().list()
    assert [e.cidr for e in listed] == ["203.0.113.5/32"]


def test_auto_seed_skips_when_runtime_already_populated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", raising=False)
    cidr_store.reset_default_store_for_tests()
    cidr_store.get_default_store().add(_entry("10.0.0.0/8"))
    entry = cidr_store.auto_seed_for_bootstrap(
        source_ip="203.0.113.5",
        user_id="email:founder@example.com",
    )
    assert entry is None
    listed = cidr_store.get_default_store().list()
    assert [e.cidr for e in listed] == ["10.0.0.0/8"]


def test_auto_seed_skips_when_env_has_cidrs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8")
    cidr_store.reset_default_store_for_tests()
    entry = cidr_store.auto_seed_for_bootstrap(
        source_ip="203.0.113.5",
        user_id="email:founder@example.com",
    )
    assert entry is None


def test_auto_seed_skips_when_source_ip_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", raising=False)
    cidr_store.reset_default_store_for_tests()
    assert cidr_store.auto_seed_for_bootstrap(
        source_ip="", user_id="email:x@example.com"
    ) is None


# ---- admin endpoints ----


_XFF_INSIDE = {"X-Forwarded-For": "10.5.6.7"}


def test_admin_list_cidrs(as_admin: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
    cidr_store.get_default_store().add(_entry("10.0.0.0/8", note="rfc1918"))
    body = as_admin.get(
        "/api/v1/admin/network/cidrs", headers=_XFF_INSIDE
    ).json()
    assert body["count"] == 1
    assert body["cidrs"][0]["cidr"] == "10.0.0.0/8"
    assert body["cidrs"][0]["note"] == "rfc1918"


def test_admin_add_cidr(as_admin: TestClient) -> None:
    # confirm_lockout=True opts in to the lockout risk per #609 —
    # this test isn't exercising the lockout flow itself.
    r = as_admin.post(
        "/api/v1/admin/network/cidrs",
        json={
            "cidr": "203.0.113.0/24",
            "note": "office WAN",
            "confirm_lockout": True,
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["cidr"] == "203.0.113.0/24"
    listed = cidr_store.get_default_store().list()
    assert any(e.cidr == "203.0.113.0/24" for e in listed)


def test_admin_add_cidr_normalizes_bare_ip(as_admin: TestClient) -> None:
    r = as_admin.post(
        "/api/v1/admin/network/cidrs",
        json={
            "cidr": "203.0.113.5",
            "note": "single host",
            "confirm_lockout": True,
        },
    )
    assert r.status_code == 201
    assert r.json()["cidr"] == "203.0.113.5/32"


def test_admin_add_cidr_refuses_garbage(as_admin: TestClient) -> None:
    r = as_admin.post(
        "/api/v1/admin/network/cidrs",
        json={"cidr": "not-an-ip"},
    )
    assert r.status_code == 400


def test_admin_remove_cidr(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
    cidr_store.get_default_store().add(_entry("10.0.0.0/8"))
    cidr_store.get_default_store().add(_entry("203.0.113.0/24"))
    r = as_admin.delete(
        "/api/v1/admin/network/cidrs/10.0.0.0/8", headers=_XFF_INSIDE
    )
    assert r.status_code == 200, r.text
    assert r.json()["removed"] is True
    assert [e.cidr for e in cidr_store.get_default_store().list()] == [
        "203.0.113.0/24"
    ]


def test_admin_remove_refuses_last_entry(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Removing the only remaining CIDR would disable enforcement
    silently — refuse."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
    cidr_store.get_default_store().add(_entry("10.0.0.0/8"))
    r = as_admin.delete(
        "/api/v1/admin/network/cidrs/10.0.0.0/8", headers=_XFF_INSIDE
    )
    assert r.status_code == 409
    assert [e.cidr for e in cidr_store.get_default_store().list()] == [
        "10.0.0.0/8"
    ]


def test_admin_remove_missing_returns_404(
    as_admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
    cidr_store.get_default_store().add(_entry("10.0.0.0/8"))
    cidr_store.get_default_store().add(_entry("192.168.0.0/16"))
    r = as_admin.delete(
        "/api/v1/admin/network/cidrs/203.0.113.0/24", headers=_XFF_INSIDE
    )
    assert r.status_code == 404


def test_non_admin_cannot_manage_cidrs(
    as_dev: TestClient, as_approver: TestClient
) -> None:
    assert (
        as_dev.get("/api/v1/admin/network/cidrs").status_code == 403
    )
    assert (
        as_approver.post(
            "/api/v1/admin/network/cidrs",
            json={"cidr": "10.0.0.0/8"},
        ).status_code
        == 403
    )


# ---- runtime store takes precedence over env ----


def test_runtime_store_overrides_env_allowlist(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Env says one range; runtime adds another. The dev client's IP
    is whatever TestClient sends — we use XFF to control the source."""
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "203.0.113.0/24")
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
    # Confirm the env-only allowlist refuses an IP outside its range.
    r1 = as_dev.get(
        "/api/v1/users/me",
        headers={"X-Forwarded-For": "198.51.100.5"},
    )
    assert r1.status_code == 403

    # Add the IP to the RUNTIME store. Env list is now superseded.
    cidr_store.get_default_store().add(_entry("198.51.100.0/24"))

    r2 = as_dev.get(
        "/api/v1/users/me",
        headers={"X-Forwarded-For": "198.51.100.5"},
    )
    assert r2.status_code == 200, r2.text


def test_env_allowlist_used_when_runtime_empty(
    as_dev: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No runtime entries → env list applies."""
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
    r = as_dev.get(
        "/api/v1/users/me",
        headers={"X-Forwarded-For": "10.5.6.7"},
    )
    assert r.status_code == 200
