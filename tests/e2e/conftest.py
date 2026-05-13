"""End-to-end fixtures.

Boots the real iam-jit FastAPI app via uvicorn in a subprocess on a free
port, seeds an admin + dev user via a YAML file, and yields the base
URL. Browsers (Playwright) drive the live HTTP server, not a TestClient.

The video output goes to `tests/e2e/output/`; the dual-persona test
combines its two browser contexts into a side-by-side mp4 the user can
watch back later.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator

import httpx
import pytest

E2E_DIR = pathlib.Path(__file__).resolve().parent
OUTPUT_DIR = E2E_DIR / "output"
SEED_USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:admin@example.com
    display_name: Admin
    roles: [admin]
  - id: email:dev@example.com
    display_name: Dev
    roles: [requester]
  - id: email:approver@example.com
    display_name: Approver
    roles: [approver]
"""

# Test-only stable secret so Playwright can mint session cookies the
# server will accept directly (skips the email-magic-link UX, which we
# don't need to demonstrate end-to-end here).
E2E_SECRET = "e2e-test-secret-for-iam-jit-do-not-use-in-prod"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_health(base_url: str, *, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{base_url}/healthz", timeout=1.0)
            if r.status_code == 200:
                return
        except Exception as e:
            last = e
        time.sleep(0.1)
    raise RuntimeError(f"iam-jit did not come up at {base_url}: {last}")


@pytest.fixture(scope="session")
def output_dir() -> pathlib.Path:
    """Per-session output dir for videos + traces. Cleared on each run."""
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR


@pytest.fixture(scope="session")
def iam_jit_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[str]:
    """Boot the iam-jit FastAPI app via uvicorn on a random port.

    Yields the base URL. Tears the process down on teardown.
    """
    workspace = tmp_path_factory.mktemp("iam-jit-e2e")
    users_yaml = workspace / "users.yaml"
    users_yaml.write_text(SEED_USERS_YAML)
    requests_dir = workspace / "requests"
    requests_dir.mkdir()

    accounts_yaml = workspace / "accounts.yaml"
    accounts_yaml.write_text(
        "apiVersion: iam-jit.dev/v1alpha1\nkind: AccountList\naccounts: []\n"
    )

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    env = os.environ.copy()
    env.update(
        {
            "IAM_JIT_AUTH_MODE": "local",
            "IAM_JIT_MAGIC_LINK_SECRET": E2E_SECRET,
            "IAM_JIT_USER_CONFIG_SOURCE": "file",
            "IAM_JIT_USERS_FILE_LOCAL_PATH": str(users_yaml),
            "IAM_JIT_REQUESTS_DIR": str(requests_dir),
            "IAM_JIT_ACCOUNTS_FILE_LOCAL_PATH": str(accounts_yaml),
            # NoAI mode keeps the e2e flow deterministic: chat surface is
            # disabled, paste surface is the canonical path. (We test the
            # chat flow at the unit-test level with a stub backend.)
            "IAM_JIT_LLM": "none",
            "IAM_JIT_PUBLIC_URL": base_url,
        }
    )

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "iam_jit.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_health(base_url)
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="session")
def session_cookie_for() -> callable:
    """Mint a valid iam_jit_session cookie for a given user_id.

    Bypasses the email magic-link UX, which is unnecessary for the e2e
    happy-path video and depends on inspecting the rendered link.
    """
    from iam_jit import auth as auth_mod

    def _mint(user_id: str) -> str:
        return auth_mod.sign_session(E2E_SECRET, user_id)

    return _mint
