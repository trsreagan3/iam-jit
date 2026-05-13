"""First-admin bootstrap tests.

The contract being tested:
  - Empty store + valid email env var → admin created, returns
    seeded=True.
  - Re-running on the same store → no-op, returns seeded=False with
    reason='user_already_exists'.
  - No env var (and no explicit email) → no-op, no error.
  - Invalid email (CR/LF, missing @, etc.) → no-op, reason='invalid_email'.
  - Store-write failure → no-op, reason='store_write_failed'. Never
    raises (Lambda startup must not crash on bootstrap failure).
"""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit import user_bootstrap
from iam_jit.users_store import User, UserNotFound


class _FakeStore:
    """Minimal UserStore used to test the bootstrap path without
    standing up DynamoDB or a YAML file."""

    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        self.put_failures = 0
        self.get_failures = 0

    def get(self, user_id: str) -> User:
        if self.get_failures > 0:
            self.get_failures -= 1
            raise RuntimeError("simulated transient DDB error")
        if user_id not in self.users:
            raise UserNotFound(user_id)
        return self.users[user_id]

    def list(self, *, include_disabled: bool = False) -> list[User]:
        return list(self.users.values())

    def put(self, user: User) -> None:
        if self.put_failures > 0:
            self.put_failures -= 1
            raise RuntimeError("simulated transient DDB error")
        self.users[user.id] = user

    def delete(self, user_id: str) -> None:
        self.users.pop(user_id, None)


# ---- happy path ----


def test_seed_creates_admin_when_store_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "founder@example.com")
    store = _FakeStore()
    result = user_bootstrap.maybe_seed_at_startup(store)
    assert result.seeded is True
    assert result.user_id == "email:founder@example.com"
    assert result.reason == "seeded_admin"
    assert "admin" in store.users["email:founder@example.com"].roles
    assert store.users["email:founder@example.com"].enabled is True


def test_seed_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Second startup with the same env var must not change anything."""
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "founder@example.com")
    store = _FakeStore()
    user_bootstrap.maybe_seed_at_startup(store)

    # Mutate the seeded admin to confirm the second call doesn't
    # overwrite their state (e.g., role downgrades, notes).
    rec = store.users["email:founder@example.com"]
    store.users["email:founder@example.com"] = User(
        id=rec.id,
        roles=("admin", "approver"),
        enabled=True,
        display_name="Founder, Promoted",
        notes="manually promoted post-bootstrap",
    )

    result2 = user_bootstrap.maybe_seed_at_startup(store)
    assert result2.seeded is False
    assert result2.reason == "user_already_exists"
    # Mutations preserved.
    final = store.users["email:founder@example.com"]
    assert final.display_name == "Founder, Promoted"
    assert "approver" in final.roles


def test_seed_with_explicit_email_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "from-env@example.com")
    store = _FakeStore()
    result = user_bootstrap.seed_bootstrap_admin(
        store, email="explicit@example.com"
    )
    assert result.seeded is True
    assert result.user_id == "email:explicit@example.com"
    assert "email:from-env@example.com" not in store.users


def test_seed_normalizes_email_case_and_whitespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "  Founder@Example.COM  ")
    store = _FakeStore()
    result = user_bootstrap.maybe_seed_at_startup(store)
    assert result.seeded is True
    assert result.user_id == "email:founder@example.com"


# ---- failure / no-op paths ----


def test_no_env_var_is_clean_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", raising=False)
    store = _FakeStore()
    result = user_bootstrap.maybe_seed_at_startup(store)
    assert result.seeded is False
    assert result.reason == "no_email_configured"
    assert store.users == {}


def test_no_store_is_clean_noop() -> None:
    """Lambda startup before user_store is wired (config error) — must
    not crash."""
    result = user_bootstrap.maybe_seed_at_startup(None)
    assert result.seeded is False
    assert result.reason == "no_store_configured"


@pytest.mark.parametrize(
    "bad_email",
    [
        "not-an-email",
        "no-at-sign.example.com",
        "two@@signs.com",
        "victim@example.com\nBcc: attacker@evil.com",
        "",
        "   ",
    ],
)
def test_invalid_email_refused(
    monkeypatch: pytest.MonkeyPatch, bad_email: str
) -> None:
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", bad_email)
    store = _FakeStore()
    result = user_bootstrap.maybe_seed_at_startup(store)
    assert result.seeded is False
    assert result.reason in ("invalid_email", "no_email_configured")
    assert store.users == {}


def test_invalid_email_with_null_byte_via_explicit_arg() -> None:
    """The OS won't let a NUL through env vars, but a malicious Python
    caller could pass one to the function directly. Defend anyway."""
    store = _FakeStore()
    result = user_bootstrap.seed_bootstrap_admin(
        store, email="evil\x00@example.com"
    )
    assert result.seeded is False
    assert result.reason == "invalid_email"
    assert store.users == {}


# ---- random-fallback bootstrap ----


def test_random_bootstrap_off_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Without explicit opt-in, the fallback never fires."""
    monkeypatch.delenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", raising=False)
    monkeypatch.delenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", raising=False)
    store = _FakeStore()
    result = user_bootstrap.maybe_seed_random_at_startup(
        store,
        public_url="http://127.0.0.1:8000",
        secret="test-secret",
        state_dir=str(tmp_path),
    )
    assert result.seeded is False
    assert result.reason == "not_opted_in"
    assert store.users == {}


def test_random_bootstrap_writes_signin_link_when_opted_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", "1")
    monkeypatch.delenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", raising=False)
    store = _FakeStore()
    store.users.clear()  # ensure empty

    result = user_bootstrap.maybe_seed_random_at_startup(
        store,
        public_url="http://127.0.0.1:8765",
        secret="test-secret-for-route-tests-aaaaaaaaa",
        state_dir=str(tmp_path),
    )
    assert result.seeded is True
    assert result.user_id and result.user_id.startswith("email:bootstrap-")
    assert result.user_id.endswith("@iam-jit.local")
    assert result.written_to and result.written_to.endswith(
        "iam-jit-bootstrap-link.txt"
    )
    body = (tmp_path / "iam-jit-bootstrap-link.txt").read_text()
    assert "/auth/magic-callback?token=" in body
    assert result.user_id in body
    assert result.user_id in store.users


def test_random_bootstrap_signin_link_verifies(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """The minted token must round-trip through verify_magic_link with
    the same secret."""
    from iam_jit import auth as auth_mod

    monkeypatch.setenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", "1")
    monkeypatch.delenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", raising=False)
    secret = "test-secret-for-route-tests-aaaaaaaaa"
    store = _FakeStore()
    store.users.clear()

    result = user_bootstrap.maybe_seed_random_at_startup(
        store,
        public_url="http://127.0.0.1:8000",
        secret=secret,
        state_dir=str(tmp_path),
    )
    assert result.seeded
    # Pull the token out of the URL.
    url = result.sign_in_url or ""
    assert "token=" in url
    token = url.split("token=", 1)[1]
    verified_user_id = auth_mod.verify_magic_link(secret, token)
    assert verified_user_id == result.user_id


def test_random_bootstrap_skips_when_email_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", "1")
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "real@example.com")
    store = _FakeStore()
    store.users.clear()
    result = user_bootstrap.maybe_seed_random_at_startup(
        store,
        public_url="http://127.0.0.1:8000",
        secret="test",
        state_dir=str(tmp_path),
    )
    assert result.seeded is False
    assert result.reason == "email_bootstrap_takes_precedence"


def test_random_bootstrap_skips_when_store_has_users(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", "1")
    monkeypatch.delenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", raising=False)
    store = _FakeStore()
    # _FakeStore starts empty by default; pre-populate one user.
    store.users["email:existing@example.com"] = User(
        id="email:existing@example.com",
        roles=("admin",),
        enabled=True,
    )
    result = user_bootstrap.maybe_seed_random_at_startup(
        store,
        public_url="http://127.0.0.1:8000",
        secret="test",
        state_dir=str(tmp_path),
    )
    assert result.seeded is False
    assert result.reason == "store_already_has_users"


def test_random_bootstrap_link_file_is_mode_600(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """The sign-in link in the file is sensitive — confirm the file is
    user-readable only."""
    import stat

    monkeypatch.setenv("IAM_JIT_ALLOW_RANDOM_BOOTSTRAP", "1")
    monkeypatch.delenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", raising=False)
    store = _FakeStore()
    store.users.clear()

    result = user_bootstrap.maybe_seed_random_at_startup(
        store,
        public_url="http://127.0.0.1:8000",
        secret="test",
        state_dir=str(tmp_path),
    )
    assert result.seeded
    mode = (tmp_path / "iam-jit-bootstrap-link.txt").stat().st_mode
    assert stat.S_IMODE(mode) == 0o600


def test_store_write_failure_is_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A flaky DynamoDB at startup must not crash the Lambda — surface
    via reason='store_write_failed' and let the next cold-start retry."""
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "founder@example.com")
    store = _FakeStore()
    store.put_failures = 1
    result = user_bootstrap.maybe_seed_at_startup(store)
    assert result.seeded is False
    assert result.reason == "store_write_failed"
    # Next startup retries cleanly.
    result2 = user_bootstrap.maybe_seed_at_startup(store)
    assert result2.seeded is True


def test_store_read_failure_is_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL", "founder@example.com")
    store = _FakeStore()
    store.get_failures = 1
    result = user_bootstrap.maybe_seed_at_startup(store)
    assert result.seeded is False
    assert result.reason == "store_read_failed"
