"""Tests for `iam_jit.local_server` — the `iam-jit serve --local`
local-deployment-mode entry point.

These cover the configuration + bootstrap logic that runs BEFORE
the FastAPI app starts. The app-level behavior is covered by the
existing route tests; here we just verify the local-mode glue
works correctly:

- Admin email auto-derivation from OS user + hostname
- Data dir creation + permissions
- users.yaml seed (first run creates; subsequent runs preserve)
- accounts.yaml seed (auto-detects AWS account via STS if available)
- Environment-variable defaults set correctly

We do NOT start uvicorn / run the server in tests — that needs
a port + real network. Smoke-test for actual startup is manual.
"""

from __future__ import annotations

import os
import pathlib
from typing import Any
from unittest import mock

import pytest

from iam_jit import local_server


@pytest.fixture
def tmp_data_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """Isolated data dir per test."""
    return tmp_path / "iam-jit-data"


# IAM_JIT_* env-leak protection now lives in the global
# tests/conftest.py (session-snapshot, per-test restore). Removed
# the per-file copy here so we don't double-restore.


# ---------------------------------------------------------------------------
# Admin email resolution.
# ---------------------------------------------------------------------------


def test_admin_email_from_user_and_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default admin email is `${USER}@${HOSTNAME}.local`."""
    cfg = local_server.LocalServerConfig()
    monkeypatch.setattr("getpass.getuser", lambda: "alice")
    monkeypatch.setattr("socket.gethostname", lambda: "alice-laptop")
    email = cfg.resolve_admin_email()
    assert email == "alice@alice-laptop.local"


def test_admin_email_explicit_override() -> None:
    """If admin_email is explicitly set on config, it wins."""
    cfg = local_server.LocalServerConfig(admin_email="real@email.com")
    assert cfg.resolve_admin_email() == "real@email.com"


def test_admin_email_fallback_on_getuser_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If getpass.getuser() raises, fall back to $USER env or 'local'."""
    cfg = local_server.LocalServerConfig()

    def _raise():
        raise OSError("no user")
    monkeypatch.setattr("getpass.getuser", _raise)
    monkeypatch.setenv("USER", "fallback-user")
    monkeypatch.setattr("socket.gethostname", lambda: "host")
    assert cfg.resolve_admin_email() == "fallback-user@host.local"


# ---------------------------------------------------------------------------
# Data dir creation + permissions.
# ---------------------------------------------------------------------------


def test_ensure_data_dir_creates_directory(tmp_data_dir: pathlib.Path) -> None:
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    assert not tmp_data_dir.exists()
    local_server._ensure_data_dir(cfg)
    assert tmp_data_dir.exists()


def test_ensure_data_dir_idempotent(tmp_data_dir: pathlib.Path) -> None:
    """Calling _ensure_data_dir twice doesn't fail."""
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)
    local_server._ensure_data_dir(cfg)
    assert tmp_data_dir.exists()


def test_ensure_data_dir_permissions_owner_only(tmp_data_dir: pathlib.Path) -> None:
    """Data dir should be 0o700 (owner read/write/exec only).

    Audit log + session state may contain sensitive data; group/world
    must not read. Best-effort — on Windows mounts this may not apply.
    """
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)
    mode = tmp_data_dir.stat().st_mode & 0o777
    # On POSIX systems we expect 0o700. On Windows / weird mounts we
    # tolerate any value — the test exercises the code path.
    if os.name == "posix":
        assert mode == 0o700, f"expected 0o700, got 0o{mode:o}"


# ---------------------------------------------------------------------------
# users.yaml seed.
# ---------------------------------------------------------------------------


def test_seed_local_user_creates_users_yaml(
    tmp_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """First run: users.yaml is auto-generated with the local admin."""
    monkeypatch.setattr("getpass.getuser", lambda: "alice")
    monkeypatch.setattr("socket.gethostname", lambda: "laptop")
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)
    user_id = local_server._seed_local_user(cfg)
    assert user_id == "email:alice@laptop.local"
    assert cfg.users_yaml.exists()
    content = cfg.users_yaml.read_text()
    assert "email:alice@laptop.local" in content
    assert "roles: [admin, approver, requester]" in content
    assert "enabled: true" in content


def test_seed_local_user_preserves_existing_yaml(
    tmp_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subsequent runs: existing users.yaml is preserved (admin may
    have customized it)."""
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)
    custom_content = "schema_version: 1\nauth_mode: local\nusers:\n  - id: email:custom@example.com\n    roles: [admin]\n    enabled: true\n"
    cfg.users_yaml.write_text(custom_content)

    monkeypatch.setattr("getpass.getuser", lambda: "alice")
    monkeypatch.setattr("socket.gethostname", lambda: "laptop")
    user_id = local_server._seed_local_user(cfg)
    # Returns the auto-derived id (caller's responsibility to use it)
    assert user_id == "email:alice@laptop.local"
    # But yaml is unchanged
    assert cfg.users_yaml.read_text() == custom_content


def test_seed_local_user_permissions_owner_only(
    tmp_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """users.yaml should be 0o600 (owner read/write only)."""
    if os.name != "posix":
        pytest.skip("permissions test POSIX-only")
    monkeypatch.setattr("getpass.getuser", lambda: "alice")
    monkeypatch.setattr("socket.gethostname", lambda: "laptop")
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)
    local_server._seed_local_user(cfg)
    mode = cfg.users_yaml.stat().st_mode & 0o777
    assert mode == 0o600, f"expected 0o600, got 0o{mode:o}"


# ---------------------------------------------------------------------------
# accounts.yaml seed.
# ---------------------------------------------------------------------------


def test_seed_local_accounts_creates_yaml_with_placeholder_when_no_aws(
    tmp_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If boto3 can't resolve credentials, fall back to a placeholder
    account ID. The user can edit accounts.yaml later."""
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)

    # Force STS call to fail (no credentials configured).
    def _fail(*args, **kwargs):
        raise Exception("no AWS credentials configured")

    monkeypatch.setattr("boto3.client", _fail)
    local_server._seed_local_accounts(cfg)
    assert cfg.accounts_yaml.exists()
    content = cfg.accounts_yaml.read_text()
    assert "000000000000" in content  # placeholder
    assert 'alias: "local"' in content


def test_seed_local_accounts_uses_sts_account_id_when_available(
    tmp_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When boto3 resolves the account_id, use it."""
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)

    class _FakeSTS:
        def get_caller_identity(self):
            return {"Account": "123456789012", "Arn": "arn:aws:iam::123:user/x"}

    def _client(service_name):
        if service_name == "sts":
            return _FakeSTS()
        raise ValueError(service_name)

    monkeypatch.setattr("boto3.client", _client)
    local_server._seed_local_accounts(cfg)
    content = cfg.accounts_yaml.read_text()
    assert "123456789012" in content


def test_seed_local_accounts_preserves_existing(
    tmp_data_dir: pathlib.Path,
) -> None:
    """If accounts.yaml exists, don't overwrite."""
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)
    cfg.accounts_yaml.write_text("custom: content\n")
    local_server._seed_local_accounts(cfg)
    assert cfg.accounts_yaml.read_text() == "custom: content\n"


# ---------------------------------------------------------------------------
# Environment defaults.
# ---------------------------------------------------------------------------


def test_set_local_env_defaults(
    tmp_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Environment vars set correctly for local mode."""
    # Clear any pre-existing values so we test the defaults.
    # NOTE: env var names below must match the canonical names that
    # `app.py` reads. The original draft used different names that
    # silently went to defaults, leaving user_store unwired (UX-1).
    for var in [
        "IAM_JIT_USER_CONFIG_SOURCE",
        "IAM_JIT_USERS_FILE_LOCAL_PATH",
        "IAM_JIT_ACCOUNTS_FILE_LOCAL_PATH",
        "IAM_JIT_REQUESTS_DIR",
        "IAM_JIT_AUTH_MODE",
        "IAM_JIT_SAFETY_MODE", "IAM_JIT_DEPLOYMENT_MODE",
        "IAM_JIT_MAGIC_LINK_SECRET", "IAM_JIT_LLM_BACKEND",
        "IAM_JIT_AUDIT_LOG",  # #632: must now be wired to <data_dir>/audit.jsonl
    ]:
        monkeypatch.delenv(var, raising=False)

    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._set_local_env_defaults(cfg, "email:alice@laptop.local")

    assert os.environ["IAM_JIT_USER_CONFIG_SOURCE"] == "file"
    assert os.environ["IAM_JIT_USERS_FILE_LOCAL_PATH"] == str(cfg.users_yaml)
    assert os.environ["IAM_JIT_ACCOUNTS_FILE_LOCAL_PATH"] == str(cfg.accounts_yaml)
    assert os.environ["IAM_JIT_REQUESTS_DIR"] == str(cfg.requests_dir)
    assert os.environ["IAM_JIT_AUTH_MODE"] == "local"
    assert os.environ["IAM_JIT_SAFETY_MODE"] == "read_write_swap"
    assert os.environ["IAM_JIT_DEPLOYMENT_MODE"] == "solo"
    assert os.environ["IAM_JIT_LLM_BACKEND"] == "none"
    # #632 CRIT: IAM_JIT_AUDIT_LOG must now be wired so audit.emit() persists.
    assert os.environ["IAM_JIT_AUDIT_LOG"] == str(tmp_data_dir / "audit.jsonl")
    # A magic-link secret was generated.
    assert len(os.environ["IAM_JIT_MAGIC_LINK_SECRET"]) >= 32


def test_set_local_env_defaults_respects_existing(
    tmp_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If env vars are already set, _set_local_env_defaults uses
    setdefault, so existing values win. Allows the user to
    override behaviors (e.g. point at hosted LLM)."""
    monkeypatch.setenv("IAM_JIT_LLM_BACKEND", "anthropic")
    monkeypatch.setenv("IAM_JIT_SAFETY_MODE", "strict")
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._set_local_env_defaults(cfg, "email:alice@laptop.local")
    assert os.environ["IAM_JIT_LLM_BACKEND"] == "anthropic"
    assert os.environ["IAM_JIT_SAFETY_MODE"] == "strict"


# ---------------------------------------------------------------------------
# LocalServerConfig properties.
# ---------------------------------------------------------------------------


def test_config_paths_derive_from_data_dir(tmp_data_dir: pathlib.Path) -> None:
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    assert cfg.audit_db_path == tmp_data_dir / "audit.db"
    assert cfg.requests_dir == tmp_data_dir / "requests"
    assert cfg.users_yaml == tmp_data_dir / "users.yaml"
    assert cfg.accounts_yaml == tmp_data_dir / "accounts.yaml"


def test_config_defaults_to_home() -> None:
    cfg = local_server.LocalServerConfig()
    assert cfg.data_dir == pathlib.Path.home() / ".iam-jit"
    assert cfg.port == 8765
    assert cfg.host == "127.0.0.1"


# UX-1 regression: the local CLI token file is created on first run
# (mode 0o600), and read back unchanged on subsequent runs. Without
# this, every restart would rotate the token and break a long-lived
# Claude Code MCP config.
def test_ensure_local_cli_token_mints_on_first_run(
    tmp_data_dir: pathlib.Path,
) -> None:
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    raw = local_server._ensure_local_cli_token(cfg, admin_user_id="email:a@b")
    assert raw.startswith("iamjit_")
    assert cfg.cli_token_file.exists()
    # File mode on POSIX: owner-only.
    import stat as _stat
    mode = cfg.cli_token_file.stat().st_mode & 0o777
    assert mode == 0o600


def test_ensure_local_cli_token_is_idempotent(
    tmp_data_dir: pathlib.Path,
) -> None:
    """Second call returns the same token (so MCP configs survive
    process restarts)."""
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    first = local_server._ensure_local_cli_token(cfg, admin_user_id="email:a@b")
    second = local_server._ensure_local_cli_token(cfg, admin_user_id="email:a@b")
    assert first == second


def test_ensure_local_cli_token_replaces_corrupt_file(
    tmp_data_dir: pathlib.Path,
) -> None:
    """Corrupt token file (wrong prefix) → re-mint, don't return junk."""
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)
    cfg.cli_token_file.write_text("garbage-not-a-token\n")
    raw = local_server._ensure_local_cli_token(cfg, admin_user_id="email:a@b")
    assert raw.startswith("iamjit_")


def test_seed_api_token_puts_record_with_hash() -> None:
    """The seeded record's hash must match auth.hash_token of the
    raw token so middleware lookups succeed."""
    from iam_jit import auth as _auth
    from iam_jit.api_tokens_store import InMemoryAPITokenStore

    class _StubApp:
        class state:  # type: ignore[no-redef]
            api_tokens_store = InMemoryAPITokenStore()

    raw = "iamjit_test_raw"
    local_server._seed_api_token_into_store(
        _StubApp, raw_token=raw, admin_user_id="email:admin@laptop.local",
    )
    record = _StubApp.state.api_tokens_store.get_by_hash(_auth.hash_token(raw))
    assert record.user_id == "email:admin@laptop.local"
    assert record.label == "iam-jit local-mode admin"


# WB11-03 regression: token file must be created with mode 0o600
# atomically (not write-then-chmod, which leaves a window).
def test_token_file_created_atomically_with_0600(
    tmp_data_dir: pathlib.Path,
) -> None:
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)
    raw = local_server._ensure_local_cli_token(cfg, admin_user_id="email:a@b")
    assert raw.startswith("iamjit_")
    if os.name == "posix":
        # Owner-only at creation time. We can't easily prove the
        # absence of a permission window in a unit test, but we can
        # at minimum confirm the file is 0o600 after the call.
        mode = cfg.cli_token_file.stat().st_mode & 0o777
        assert mode == 0o600


def test_token_file_refuses_symlink_followthrough(
    tmp_data_dir: pathlib.Path, tmp_path: pathlib.Path,
) -> None:
    """O_NOFOLLOW prevents an attacker who pre-creates a symlink
    at the token-file path from redirecting the write to a file
    they own."""
    if os.name != "posix":
        pytest.skip("symlink-followthrough test POSIX-only")
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("O_NOFOLLOW not available")
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)
    # Pre-place a symlink at the token-file path pointing somewhere
    # the attacker controls.
    target = tmp_path / "attacker-controlled"
    target.write_text("attacker placeholder\n")
    cfg.cli_token_file.symlink_to(target)
    with pytest.raises(OSError):
        local_server._ensure_local_cli_token(cfg, admin_user_id="email:a@b")
    # Attacker file must not have been written through.
    assert target.read_text() == "attacker placeholder\n"


# WB11-04 regression: the raw token must NOT appear in the run()
# banner. We can't easily test the actual stdout of run() without
# starting uvicorn; instead we test the banner-construction logic
# by inspecting the local_server module's `run` source for any
# direct interpolation of the raw token into a print() call.
def test_run_banner_does_not_print_raw_token() -> None:
    import inspect
    src = inspect.getsource(local_server.run)
    # The raw_token variable is established for seeding into the
    # token store. It must NOT be passed to print() in any form.
    # (We allow {config.cli_token_file} since that's a path, not
    # the secret itself.)
    bad_patterns = [
        "{raw_token}",
        "Bearer {raw_token}",
    ]
    for pattern in bad_patterns:
        assert pattern not in src, (
            f"local_server.run() banner contains {pattern!r} — "
            f"this leaks the bearer token to stdout (WB11-04). "
            f"Reference the file path instead."
        )


# WB11-08 regression: serve --local refuses non-localhost binds.
def test_local_server_refuses_lan_bind() -> None:
    """`iam-jit serve --local --host 0.0.0.0` would expose the
    admin token + AWS-bridging server to the LAN. Must refuse."""
    with pytest.raises(SystemExit) as excinfo:
        local_server._validate_local_bind("0.0.0.0")
    assert "refuses to bind" in str(excinfo.value)


def test_local_server_refuses_external_ip() -> None:
    with pytest.raises(SystemExit):
        local_server._validate_local_bind("192.168.1.42")


def test_local_server_accepts_loopback_addresses() -> None:
    for host in ("127.0.0.1", "::1", "localhost"):
        # Should not raise
        local_server._validate_local_bind(host)


# WB11-12 regression: poisoned $USER cannot inject YAML structure.
def test_safe_identity_token_strips_yaml_injection() -> None:
    poisoned = 'evil"\nrole: admin\n# '
    safe = local_server._safe_identity_token(poisoned, fallback="fallback")
    # Sanitiser strips quote, newline, colon, space, hash, etc.
    assert "\n" not in safe
    assert '"' not in safe
    assert ":" not in safe
    assert " " not in safe
    assert safe.startswith("evil")


def test_safe_identity_token_falls_back_on_empty() -> None:
    assert local_server._safe_identity_token("", fallback="anonymous") == "anonymous"
    assert local_server._safe_identity_token(None, fallback="anonymous") == "anonymous"
    # All-non-ASCII collapses to fallback
    assert local_server._safe_identity_token("中国 🚀", fallback="anonymous") == "anonymous"


def test_resolve_admin_email_sanitises_poisoned_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: a poisoned $USER doesn't break out of the YAML."""
    monkeypatch.setattr("getpass.getuser", lambda: 'evil"\n  injected: true')
    monkeypatch.setattr("socket.gethostname", lambda: "laptop")
    cfg = local_server.LocalServerConfig()
    email = cfg.resolve_admin_email()
    assert "\n" not in email
    assert ":" not in email or email.endswith(".local")
    assert email.endswith(".local")


# WB11-13 regression: when no AWS credentials are present, the seeded
# accounts.yaml must include a PLACEHOLDER warning so the user can't
# accidentally ship grants targeting "000000000000".
def test_seed_accounts_yaml_marks_placeholder_visibly(
    tmp_data_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = local_server.LocalServerConfig(data_dir=tmp_data_dir)
    local_server._ensure_data_dir(cfg)

    def _fail(*a, **k):
        raise Exception("no creds")
    monkeypatch.setattr("boto3.client", _fail)
    local_server._seed_local_accounts(cfg)
    content = cfg.accounts_yaml.read_text()
    assert "000000000000" in content
    assert "PLACEHOLDER" in content, (
        "Placeholder account_id must be visibly flagged so users "
        "don't accidentally ship grants against the placeholder."
    )
