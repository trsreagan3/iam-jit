"""Local-only deployment mode — `iam-jit serve --local`.

Per [[local-only-safety-mode]] memo. Runs iam-jit as a process
on the dev's laptop, using their AWS credentials (boto3 default
chain), exposing the MCP server + REST API on localhost. ZERO
dependency on iam-jit-the-company's hosted infrastructure.

Architecture:

    Claude Code
       │
       ▼ (MCP, localhost:8765/mcp)
    iam-jit local process (uvicorn)
       ├─ Uses ~/.aws/credentials for AWS API calls
       ├─ Audits to local SQLite (~/.iam-jit/audit.db)
       ├─ Single admin user (the deploying email)
       └─ self_approve_reductions=true by default
       │
       ▼ (STS)
    AWS

Trust model: "trust the binary on your laptop." Same as
aws-cli / kubectl / terraform / aws-vault.

What's IN scope for v1 local-only:
  - MCP server endpoint
  - Scoring engine + recommender
  - Read-only-default behavior contract
  - SQLite audit log
  - Single-user (the local admin)
  - Self-approve reductions (admin's own grants auto-approve)
  - Safety-mode (read_write_swap default; strict opt-in)
  - Local web UI for browsing audit log

What's NOT in scope for v1 local-only:
  - Multi-user / approver flows
  - Slack approval bot
  - OIDC SSO (local mode uses OS-user identity)
  - DDB-backed stores (filesystem / SQLite only)
  - Hosted SaaS infrastructure
"""

from __future__ import annotations

import dataclasses
import getpass
import logging
import os
import pathlib
import socket
from typing import Any

logger = logging.getLogger("iam_jit.local_server")


_DEFAULT_DATA_DIR = pathlib.Path.home() / ".iam-jit"
_DEFAULT_PORT = 8765
_DEFAULT_HOST = "127.0.0.1"


@dataclasses.dataclass(frozen=True)
class LocalServerConfig:
    """Per-process configuration for the local server."""

    host: str = _DEFAULT_HOST
    port: int = _DEFAULT_PORT
    data_dir: pathlib.Path = _DEFAULT_DATA_DIR
    admin_email: str = ""  # auto-derived from $USER@hostname if empty

    @property
    def audit_db_path(self) -> pathlib.Path:
        return self.data_dir / "audit.db"

    @property
    def requests_dir(self) -> pathlib.Path:
        return self.data_dir / "requests"

    @property
    def users_yaml(self) -> pathlib.Path:
        return self.data_dir / "users.yaml"

    @property
    def accounts_yaml(self) -> pathlib.Path:
        return self.data_dir / "accounts.yaml"

    @property
    def cli_token_file(self) -> pathlib.Path:
        return self.data_dir / "cli-token"

    def resolve_admin_email(self) -> str:
        """The admin email defaults to `${USER}@${HOSTNAME}` — this
        is the canonical "local admin" identity. Not a real email,
        but unique per machine + user.

        Avoids double-`.local` suffix when the hostname already ends
        with `.local` (e.g., macOS reports `host.local` by default).
        """
        if self.admin_email:
            return self.admin_email
        try:
            user = getpass.getuser()
        except Exception:
            user = os.environ.get("USER") or "local"
        try:
            host = socket.gethostname()
        except Exception:
            host = "localhost"
        # Strip trailing `.local` if hostname already has it, then
        # re-append uniformly. Keeps the identity stable across
        # platforms.
        host_clean = host.rstrip(".").removesuffix(".local")
        return f"{user}@{host_clean}.local"


def _ensure_data_dir(config: LocalServerConfig) -> None:
    """Create the local data directory if it doesn't exist. Set
    permissions so only the current user can read."""
    config.data_dir.mkdir(parents=True, exist_ok=True)
    try:
        # rwx for owner; nothing for group/world. SQLite + audit log
        # contain sensitive (per-grant) data.
        config.data_dir.chmod(0o700)
    except Exception:
        # On Windows / weird mounts, chmod may not work as expected.
        # Best-effort; the user is local-only anyway.
        pass


def _seed_local_user(config: LocalServerConfig) -> str:
    """Ensure the users.yaml file exists with the local admin user.

    Returns the admin user_id.

    The local admin is auto-created with roles=[admin, approver,
    requester] (in solo mode all three roles collapse to the same
    user) and self_approve_reductions=true.
    """
    admin_email = config.resolve_admin_email()
    user_id = f"email:{admin_email}"
    if config.users_yaml.exists():
        return user_id

    contents = f"""\
# iam-jit local-mode users file.
# Auto-generated on first run. Edit at your own risk.
schema_version: 1
auth_mode: local
users:
  - id: {user_id}
    display_name: "Local admin ({admin_email})"
    roles: [admin, approver, requester]
    enabled: true
    notes: "Auto-created on iam-jit serve --local first run."
"""
    config.users_yaml.write_text(contents)
    try:
        config.users_yaml.chmod(0o600)
    except Exception:
        pass
    return user_id


def _seed_local_accounts(config: LocalServerConfig) -> None:
    """Ensure the accounts.yaml file exists with the user's current
    AWS account auto-detected from the default credential chain."""
    if config.accounts_yaml.exists():
        return

    # Use boto3 + STS to ask "who am I?" against the user's
    # current AWS credentials. Captures the account_id without
    # any standing config.
    account_id = "000000000000"
    try:
        import boto3
        sts = boto3.client("sts")
        ident = sts.get_caller_identity()
        account_id = str(ident.get("Account") or account_id)
    except Exception as e:
        logger.warning(
            "Could not resolve AWS account from default credentials: %s. "
            "Accounts file will use a placeholder.", e,
        )

    contents = f"""\
# iam-jit local-mode accounts file.
# Auto-generated on first run. Add more accounts as you connect them.
apiVersion: iam-jit.dev/v1alpha1
kind: AccountList
accounts:
  - account_id: "{account_id}"
    alias: "local"
    provisioner_role_arn: "arn:aws:iam::{account_id}:role/iam-jit-local-provisioner"
    provisioner_external_id: "iam-jit-local-{account_id}"
    provisioning_mode: "classic_iam"
    enabled: true
    notes: "Local-mode default account. iam-jit assumes a per-grant role here using your local AWS credentials."
"""
    config.accounts_yaml.write_text(contents)
    try:
        config.accounts_yaml.chmod(0o600)
    except Exception:
        pass


def _ensure_local_cli_token(config: LocalServerConfig, admin_user_id: str = "") -> str:
    """Return the raw API bearer token for the local admin.

    On first run, mints a fresh token via `auth.issue_api_token`,
    writes the raw value to `${data_dir}/cli-token` with mode 0o600,
    and returns it. On subsequent runs, reads + returns the existing
    token unchanged (so a long-lived MCP config in Claude Code keeps
    working across restarts).

    Persisting the raw token on disk is acceptable in local mode for
    the same reason aws-cli stores plaintext keys in ~/.aws/credentials
    and gh stores OAuth tokens in ~/.config/gh — the trust model is
    "trust the binary on your laptop" and the file is 0o600.
    """
    config.data_dir.mkdir(parents=True, exist_ok=True)
    if config.cli_token_file.exists():
        raw = config.cli_token_file.read_text().strip()
        if raw.startswith("iamjit_"):
            return raw
        # Corrupt / wrong format → re-mint below.

    from . import auth as _auth
    issued = _auth.issue_api_token(
        user_id=admin_user_id,
        label="iam-jit local-mode admin",
    )
    raw = issued.raw
    # WB11-03 closure: avoid the write_text-then-chmod race that
    # leaves the token briefly readable by other local users.
    # `os.open` with O_CREAT + mode=0o600 establishes the file
    # mode at creation time atomically. We also use O_EXCL to
    # refuse to overwrite an existing file (the early-return
    # above means we should never reach here with one present;
    # this is defense in depth against TOCTOU between the exists()
    # check and the open).
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    try:
        flags |= os.O_NOFOLLOW  # POSIX-only; refuse to write through symlinks
    except AttributeError:
        pass
    fd = os.open(str(config.cli_token_file), flags, 0o600)
    try:
        os.write(fd, (raw + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    # Defensive chmod for the case where umask masked our 0o600.
    try:
        config.cli_token_file.chmod(0o600)
    except Exception:
        pass
    return raw


def _seed_api_token_into_store(
    app: Any, *, raw_token: str, admin_user_id: str,
) -> None:
    """Put the local admin's API token into the running app's
    api_tokens_store so middleware authenticates `Authorization:
    Bearer <token>` requests.

    The token store in local mode is InMemoryAPITokenStore (since
    no DDB table is configured), so seeding it on every startup
    matches the in-memory store's lifetime exactly.
    """
    from . import auth as _auth
    from .api_tokens_store import APITokenRecord
    import time as _time

    store = getattr(app.state, "api_tokens_store", None)
    if store is None:
        return
    record = APITokenRecord(
        token_hash=_auth.hash_token(raw_token),
        user_id=admin_user_id,
        created_at=int(_time.time()),
        label="iam-jit local-mode admin",
    )
    store.put(record)


def _set_local_env_defaults(config: LocalServerConfig, admin_user_id: str) -> None:
    """Set env vars that the rest of iam-jit reads, so the app
    behaves correctly in local mode.

    These are set BEFORE the FastAPI app is built so middleware,
    auth, settings all see the right values.
    """
    # File-mode user store (vs DDB-mode for production). The env var
    # names below are the canonical ones consumed by
    # `app._build_user_store_from_env` /
    # `_build_accounts_store_from_env` /
    # `_build_request_store_from_env`. DO NOT rename these without
    # updating app.py in lockstep — the names are the contract.
    os.environ.setdefault("IAM_JIT_USER_CONFIG_SOURCE", "file")
    os.environ.setdefault(
        "IAM_JIT_USERS_FILE_LOCAL_PATH", str(config.users_yaml)
    )

    # File-mode accounts: app.py probes for the local-path env var
    # directly; no separate "source" toggle.
    os.environ.setdefault(
        "IAM_JIT_ACCOUNTS_FILE_LOCAL_PATH", str(config.accounts_yaml)
    )

    # Filesystem request store (vs DDB-mode).
    os.environ.setdefault("IAM_JIT_REQUESTS_DIR", str(config.requests_dir))
    config.requests_dir.mkdir(parents=True, exist_ok=True)

    # Magic-link secret — local mode generates a per-process ephemeral.
    # Sessions don't persist across restart, which is fine for a
    # single-user laptop process.
    import secrets as _secrets
    os.environ.setdefault(
        "IAM_JIT_MAGIC_LINK_SECRET",
        _secrets.token_hex(32),
    )
    os.environ.setdefault("IAM_JIT_AUTH_MODE", "local")
    # local mode skips the cookie-Secure flag (HTTP-on-localhost).
    os.environ.setdefault("IAM_JIT_DEV_INSECURE_SECRET", "1")

    # Safety-mode defaults for local: read_write_swap +
    # self-approve-reductions for the local admin.
    os.environ.setdefault("IAM_JIT_SAFETY_MODE", "read_write_swap")
    os.environ.setdefault("IAM_JIT_DEPLOYMENT_MODE", "solo")

    # Audit retention generous for solo dev (local SQLite).
    os.environ.setdefault("IAM_JIT_AUDIT_RETENTION_DAYS", "365")

    # LLM defaults to deterministic-only for free local mode.
    # User can override by setting IAM_JIT_LLM_BACKEND.
    os.environ.setdefault("IAM_JIT_LLM_BACKEND", "none")


_LOCALHOST_HOSTS: frozenset[str] = frozenset({
    "127.0.0.1", "::1", "localhost",
})


def _validate_local_bind(host: str) -> None:
    """Refuse to bind a local-mode server to anything other than
    localhost. WB11-08 closure: `serve --local --host 0.0.0.0`
    would expose the admin token + AWS-bridging server to the
    entire LAN (the local-mode trust model is single-machine,
    single-user). The defaults bypass cookie Secure flag,
    enable an ephemeral magic-link secret, and self-approve
    reductions for the OS user; none of that is safe on a
    network-reachable bind.

    If a developer genuinely needs to share their local iam-jit
    with another machine, they should use `iam-jit serve` in
    HOSTED mode instead, with proper TLS / OIDC / DDB-backed stores.
    """
    if host in _LOCALHOST_HOSTS:
        return
    raise SystemExit(
        f"iam-jit serve --local refuses to bind {host!r}. "
        f"Local mode is single-machine; binding to a non-localhost "
        f"address would expose the admin bearer token + the "
        f"AWS-bridging server to the network. Use 127.0.0.1 / ::1 / "
        f"localhost. For multi-machine deployments, use hosted mode."
    )


def run(
    *,
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    data_dir: pathlib.Path | None = None,
) -> int:
    """Start iam-jit in local mode. Blocks until interrupted.

    Returns process exit code.
    """
    _validate_local_bind(host)
    config = LocalServerConfig(
        host=host,
        port=port,
        data_dir=data_dir or _DEFAULT_DATA_DIR,
    )

    print(f"iam-jit local mode")
    print(f"  Data dir: {config.data_dir}")

    _ensure_data_dir(config)
    admin_user_id = _seed_local_user(config)
    _seed_local_accounts(config)
    _set_local_env_defaults(config, admin_user_id)
    raw_token = _ensure_local_cli_token(config, admin_user_id=admin_user_id)

    print(f"  Admin user: {admin_user_id}")
    print(f"  Requests:  {config.requests_dir}")
    print(f"  API token: {config.cli_token_file} (mode 0600)")

    # Build + serve the FastAPI app. Token must be seeded AFTER
    # create_app() so it lands in the same InMemoryAPITokenStore
    # the middleware reads from.
    from .app import create_app

    app = create_app()
    _seed_api_token_into_store(
        app, raw_token=raw_token, admin_user_id=admin_user_id,
    )

    print(f"")
    print(f"  Listening on http://{host}:{port}")
    print(f"")
    # WB11-04 closure: do NOT echo the raw token to stdout. The
    # token is a long-lived credential that bridges to AWS via
    # boto3; printing it leaks via tee, scrollback, journal, ssh
    # session recordings, etc. Reference the file instead.
    print(f"Quick test (token is read from {config.cli_token_file}):")
    print(f"  curl -H \"Authorization: Bearer $(cat {config.cli_token_file})\" \\")
    print(f"       http://{host}:{port}/api/v1/users/me")
    print(f"")
    print(f"To connect Claude Code via MCP (stdio transport):")
    print(f"  iam-jit mcp install-claude-code")
    print(f"")
    print(f"To stop: Ctrl+C")
    print(f"")

    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0
