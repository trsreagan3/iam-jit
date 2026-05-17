"""Tests for the license-file scaffolding (#161, per [[user-count-soft-cap]]).

Covers Ed25519 verification, expiry handling, malformed input, and the
`enforce_user_creation_cap` gate that the user-store consults.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import pathlib

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from iam_jit import license as license_mod


# ---------------------------------------------------------------------------
# Test helpers: generate a fresh keypair + sign a license for verification.
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, str]:
    """Returns (private_key, public_key_b64). Public key base64 is what
    the production code would have embedded as PRODUCTION_PUBLIC_KEY_B64."""
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_key, base64.b64encode(public_bytes).decode("ascii")


def _make_signed_license(
    private_key: Ed25519PrivateKey,
    *,
    tier: str = "enterprise",
    max_users: int = 250,
    issued_to: str = "Test Customer",
    expires_at: _dt.datetime | None = None,
    issued_at: _dt.datetime | None = None,
    license_id: str = "lic_test_001",
) -> bytes:
    """Build and sign a license payload. Returns the raw bytes that
    `verify_license_bytes` consumes."""
    now = _dt.datetime.now(_dt.UTC).replace(microsecond=0)
    payload = {
        "tier": tier,
        "issued_to": issued_to,
        "issued_at": (issued_at or now).isoformat().replace("+00:00", "Z"),
        "expires_at": (expires_at or now + _dt.timedelta(days=365)).isoformat().replace("+00:00", "Z"),
        "max_users": max_users,
        "license_id": license_id,
    }
    canonical = license_mod._canonical_payload_bytes(payload)
    signature = private_key.sign(canonical)
    return json.dumps({
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }).encode("utf-8")


# ---------------------------------------------------------------------------
# verify_license_bytes
# ---------------------------------------------------------------------------


def test_valid_signed_license_verifies(keypair) -> None:
    private_key, pub_b64 = keypair
    raw = _make_signed_license(private_key, max_users=250, tier="enterprise")
    lic = license_mod.verify_license_bytes(raw, public_key_b64=pub_b64)
    assert lic.tier == "enterprise"
    assert lic.max_users == 250
    assert lic.issued_to == "Test Customer"
    assert lic.is_active()
    assert lic.days_until_expiry > 360


def test_wrong_public_key_rejects(keypair) -> None:
    """A license signed by key A must not verify against key B."""
    private_key, _ = keypair
    raw = _make_signed_license(private_key)
    # Generate a DIFFERENT public key
    other_key = Ed25519PrivateKey.generate()
    other_pub = base64.b64encode(other_key.public_key().public_bytes_raw()).decode("ascii")
    with pytest.raises(license_mod.LicenseInvalidError, match="does not verify"):
        license_mod.verify_license_bytes(raw, public_key_b64=other_pub)


def test_tampered_payload_rejects(keypair) -> None:
    """If you change the payload after signing, the signature
    no longer matches."""
    private_key, pub_b64 = keypair
    raw = _make_signed_license(private_key, max_users=100)
    outer = json.loads(raw)
    outer["payload"]["max_users"] = 1_000_000  # tamper
    tampered = json.dumps(outer).encode("utf-8")
    with pytest.raises(license_mod.LicenseInvalidError):
        license_mod.verify_license_bytes(tampered, public_key_b64=pub_b64)


def test_expired_license_rejects(keypair) -> None:
    private_key, pub_b64 = keypair
    past = _dt.datetime.now(_dt.UTC) - _dt.timedelta(days=30)
    raw = _make_signed_license(
        private_key,
        issued_at=past - _dt.timedelta(days=365),
        expires_at=past,
    )
    with pytest.raises(license_mod.LicenseInvalidError, match="expired"):
        license_mod.verify_license_bytes(raw, public_key_b64=pub_b64)


def test_not_yet_active_license_rejects(keypair) -> None:
    """issued_at in the future — license isn't usable yet."""
    private_key, pub_b64 = keypair
    future = _dt.datetime.now(_dt.UTC) + _dt.timedelta(days=30)
    raw = _make_signed_license(
        private_key,
        issued_at=future,
        expires_at=future + _dt.timedelta(days=365),
    )
    with pytest.raises(license_mod.LicenseInvalidError, match="expired"):
        license_mod.verify_license_bytes(raw, public_key_b64=pub_b64)


def test_unknown_tier_rejects(keypair) -> None:
    private_key, pub_b64 = keypair
    raw = _make_signed_license(private_key, tier="ultra-mega")
    with pytest.raises(license_mod.LicenseInvalidError, match="tier"):
        license_mod.verify_license_bytes(raw, public_key_b64=pub_b64)


def test_free_tier_explicitly_rejected_in_signed_file(keypair) -> None:
    """The free tier should NOT be signed; it's the absence-of-license
    state. A signed 'free' license suggests confusion."""
    private_key, pub_b64 = keypair
    raw = _make_signed_license(private_key, tier="free")
    with pytest.raises(license_mod.LicenseInvalidError, match="free"):
        license_mod.verify_license_bytes(raw, public_key_b64=pub_b64)


def test_max_users_out_of_range_rejects(keypair) -> None:
    private_key, pub_b64 = keypair
    for bad in (0, -10, 2_000_000):
        raw = _make_signed_license(private_key, max_users=bad)
        with pytest.raises(license_mod.LicenseInvalidError, match="max_users"):
            license_mod.verify_license_bytes(raw, public_key_b64=pub_b64)


def test_invalid_json_rejects() -> None:
    with pytest.raises(license_mod.LicenseInvalidError, match="JSON"):
        license_mod.verify_license_bytes(b"not json at all")


def test_missing_signature_field_rejects() -> None:
    raw = json.dumps({"payload": {"tier": "enterprise"}}).encode("utf-8")
    with pytest.raises(license_mod.LicenseInvalidError, match="payload.*signature"):
        license_mod.verify_license_bytes(raw)


def test_missing_payload_field_rejects() -> None:
    raw = json.dumps({"signature": "AAAA"}).encode("utf-8")
    with pytest.raises(license_mod.LicenseInvalidError, match="payload.*signature"):
        license_mod.verify_license_bytes(raw)


def test_non_base64_signature_rejects() -> None:
    raw = json.dumps({
        "payload": {"tier": "enterprise"},
        "signature": "not-valid-base64!@#$",
    }).encode("utf-8")
    with pytest.raises(license_mod.LicenseInvalidError, match="base64"):
        license_mod.verify_license_bytes(raw)


def test_canonical_payload_is_stable() -> None:
    """The bytes that get signed must NOT depend on dict-key ordering
    or pretty-printing. Different-shape inputs producing the same
    semantic payload must hash identically."""
    a = {"tier": "enterprise", "max_users": 100, "issued_to": "Acme"}
    b = {"issued_to": "Acme", "max_users": 100, "tier": "enterprise"}
    assert license_mod._canonical_payload_bytes(a) == license_mod._canonical_payload_bytes(b)


# ---------------------------------------------------------------------------
# load_license (path resolution + file IO)
# ---------------------------------------------------------------------------


def test_load_license_missing_file_returns_none(tmp_path, monkeypatch) -> None:
    """No license file = Free tier; not an error."""
    monkeypatch.setenv(license_mod.LICENSE_PATH_ENV, str(tmp_path / "nonexistent.json"))
    assert license_mod.load_license() is None


def test_load_license_explicit_path_overrides_env(tmp_path, keypair) -> None:
    private_key, pub_b64 = keypair
    raw = _make_signed_license(private_key)
    p = tmp_path / "mylic.json"
    p.write_bytes(raw)
    lic = license_mod.load_license(path=p, public_key_b64=pub_b64)
    assert lic is not None
    assert lic.tier == "enterprise"


def test_load_license_invalid_file_raises(tmp_path, monkeypatch) -> None:
    p = tmp_path / "bad.json"
    p.write_bytes(b"garbage")
    monkeypatch.setenv(license_mod.LICENSE_PATH_ENV, str(p))
    with pytest.raises(license_mod.LicenseInvalidError):
        license_mod.load_license()


# ---------------------------------------------------------------------------
# current_user_cap + current_tier
# ---------------------------------------------------------------------------


def test_current_user_cap_no_license(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(license_mod.LICENSE_PATH_ENV, str(tmp_path / "no.json"))
    assert license_mod.current_user_cap() == license_mod.FREE_TIER_MAX_USERS
    assert license_mod.current_tier() == "free"


def test_current_user_cap_invalid_license_falls_back_to_free(
    tmp_path, monkeypatch,
) -> None:
    """An invalid license should NOT crash; it falls back to Free
    tier + logs a warning. Admins use `iam-jit license show` to
    see the verification error."""
    p = tmp_path / "bad.json"
    p.write_bytes(b"corrupted")
    monkeypatch.setenv(license_mod.LICENSE_PATH_ENV, str(p))
    assert license_mod.current_user_cap() == license_mod.FREE_TIER_MAX_USERS
    assert license_mod.current_tier() == "free"


def test_current_user_cap_with_valid_license(keypair) -> None:
    private_key, pub_b64 = keypair
    raw = _make_signed_license(private_key, max_users=500)
    lic = license_mod.verify_license_bytes(raw, public_key_b64=pub_b64)
    assert license_mod.current_user_cap(lic) == 500
    assert license_mod.current_tier(lic) == "enterprise"


# ---------------------------------------------------------------------------
# enforce_user_creation_cap
# ---------------------------------------------------------------------------


def test_enforce_user_creation_under_cap_passes() -> None:
    license_mod.enforce_user_creation_cap(current_user_count=10, license_obj=None)
    license_mod.enforce_user_creation_cap(current_user_count=24, license_obj=None)


def test_enforce_user_creation_at_cap_raises() -> None:
    """At exactly cap, the NEXT creation must be rejected. 25 existing
    means creating the 26th — Free tier maxes at 25."""
    with pytest.raises(license_mod.UserCapExceededError, match="Free tier"):
        license_mod.enforce_user_creation_cap(
            current_user_count=license_mod.FREE_TIER_MAX_USERS, license_obj=None,
        )


def test_enforce_user_creation_above_cap_raises() -> None:
    with pytest.raises(license_mod.UserCapExceededError, match="install"):
        license_mod.enforce_user_creation_cap(
            current_user_count=100, license_obj=None,
        )


def test_enforce_user_creation_under_enterprise_cap_passes(keypair) -> None:
    """An Enterprise license with max_users=500 lets you go up to 499
    existing (creating the 500th is rejected)."""
    private_key, pub_b64 = keypair
    raw = _make_signed_license(private_key, max_users=500)
    lic = license_mod.verify_license_bytes(raw, public_key_b64=pub_b64)
    license_mod.enforce_user_creation_cap(
        current_user_count=499, license_obj=lic,
    )
    with pytest.raises(license_mod.UserCapExceededError, match="enterprise"):
        license_mod.enforce_user_creation_cap(
            current_user_count=500, license_obj=lic,
        )


def test_enforce_message_includes_remediation_path() -> None:
    """The error message must tell the admin HOW to raise the cap.
    Sentry/Mattermost pattern: be loud + helpful at the gate point."""
    try:
        license_mod.enforce_user_creation_cap(current_user_count=50, license_obj=None)
    except license_mod.UserCapExceededError as e:
        msg = str(e)
        assert "license" in msg.lower()
        assert "25" in msg
        assert "existing users continue to work" in msg.lower()
    else:
        pytest.fail("expected UserCapExceededError")


# ---------------------------------------------------------------------------
# CLI smoke tests
# ---------------------------------------------------------------------------


def test_cli_license_show_no_license(monkeypatch, tmp_path) -> None:
    """`iam-jit license show` without a license exits 0 + reports Free."""
    from click.testing import CliRunner
    from iam_jit.cli import main
    monkeypatch.setenv(license_mod.LICENSE_PATH_ENV, str(tmp_path / "absent.json"))
    runner = CliRunner()
    result = runner.invoke(main, ["license", "show"])
    assert result.exit_code == 0, result.output
    assert "free" in result.output.lower()
    assert "25" in result.output


def test_cli_license_verify_bad_file(tmp_path) -> None:
    from click.testing import CliRunner
    from iam_jit.cli import main
    p = tmp_path / "bad.json"
    p.write_bytes(b"corrupted")
    runner = CliRunner()
    result = runner.invoke(main, ["license", "verify", str(p)])
    assert result.exit_code == 1
    assert "INVALID" in result.output


# ---------------------------------------------------------------------------
# DynamoDBUserStore wire-in
# ---------------------------------------------------------------------------


class _FakeDDBTable:
    """In-memory shim mimicking the slice of boto3 DDB Table API
    the user store uses. Sufficient for testing the cap gate."""

    def __init__(self) -> None:
        self.items: dict[str, dict] = {}

    def get_item(self, *, Key: dict) -> dict:
        item = self.items.get(Key["user_id"])
        return {"Item": item} if item else {}

    def put_item(self, *, Item: dict) -> None:
        self.items[Item["user_id"]] = Item

    def scan(self, **kwargs) -> dict:
        if kwargs.get("Select") == "COUNT":
            return {"Count": len(self.items)}
        return {"Items": list(self.items.values())}

    def delete_item(self, *, Key: dict) -> None:
        self.items.pop(Key["user_id"], None)


class _FakeDDBResource:
    def __init__(self, table: _FakeDDBTable) -> None:
        self._table = table

    def Table(self, name: str) -> _FakeDDBTable:
        return self._table


def test_ddb_user_store_blocks_creation_above_free_cap(monkeypatch, tmp_path) -> None:
    """WB30 #161 wire-in: the 26th new user creation under the Free
    tier must be rejected by enforce_user_creation_cap."""
    from iam_jit.users_store import DynamoDBUserStore, User

    # Ensure Free tier (no license file)
    monkeypatch.setenv(license_mod.LICENSE_PATH_ENV, str(tmp_path / "absent.json"))

    table = _FakeDDBTable()
    store = DynamoDBUserStore("test", dynamodb_resource=_FakeDDBResource(table))

    # 25 successful creations
    for i in range(license_mod.FREE_TIER_MAX_USERS):
        store.put(User(id=f"email:user{i}@example.com", roles=("requester",)))
    assert len(table.items) == 25

    # 26th must be rejected
    with pytest.raises(license_mod.UserCapExceededError):
        store.put(User(id="email:user25@example.com", roles=("requester",)))
    assert len(table.items) == 25


def test_ddb_user_store_updates_existing_not_gated(monkeypatch, tmp_path) -> None:
    """The cap fires on NEW creation only. Updating an existing user
    (changing roles, etc.) is never gated."""
    from iam_jit.users_store import DynamoDBUserStore, User

    monkeypatch.setenv(license_mod.LICENSE_PATH_ENV, str(tmp_path / "absent.json"))

    table = _FakeDDBTable()
    store = DynamoDBUserStore("test", dynamodb_resource=_FakeDDBResource(table))

    # Pretend we're already over cap (e.g. from a previous license that expired)
    for i in range(30):
        table.items[f"email:user{i}@example.com"] = {
            "user_id": f"email:user{i}@example.com",
            "roles": ["requester"],
            "enabled": True,
        }

    # Updating an existing user must succeed even though we're over cap
    existing_user = User(
        id="email:user5@example.com",
        roles=("requester", "approver"),  # role change
    )
    store.put(existing_user)
    assert "approver" in table.items["email:user5@example.com"]["roles"]


def test_ddb_user_store_allows_under_enterprise_license(
    monkeypatch, tmp_path, keypair,
) -> None:
    """With a valid Enterprise license raising the cap, more
    creations succeed."""
    from iam_jit.users_store import DynamoDBUserStore, User

    private_key, pub_b64 = keypair
    raw = _make_signed_license(private_key, max_users=100)
    lic_path = tmp_path / "license.json"
    lic_path.write_bytes(raw)
    monkeypatch.setenv(license_mod.LICENSE_PATH_ENV, str(lic_path))
    # Also patch PRODUCTION_PUBLIC_KEY_B64 so load_license accepts
    # the test-keypair-signed file.
    monkeypatch.setattr(license_mod, "PRODUCTION_PUBLIC_KEY_B64", pub_b64)

    table = _FakeDDBTable()
    store = DynamoDBUserStore("test", dynamodb_resource=_FakeDDBResource(table))

    # 50 users — comfortably under the 100-user Enterprise cap
    for i in range(50):
        store.put(User(id=f"email:user{i}@example.com", roles=("requester",)))
    assert len(table.items) == 50
