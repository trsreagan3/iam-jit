"""Boot iam-jit serve in the background, run every recording script
in a deterministic order, then tear down.

Each script in `scripts/` (except `_lib.py` and this file) is run in
sequence. Output videos land in `output/<script-name>.webm`.

Why a custom runner instead of `make recordings`: we need ordering
(submit a request before the approve script can find one) and we
need to seed fresh state between groups so a re-record produces the
same shape every time.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
RECORDINGS = REPO / "recordings"
SCRIPTS = RECORDINGS / "scripts"
OUTPUT = RECORDINGS / "output"
WORKSPACE = RECORDINGS / "_workspace"

# Shared state used by both the seeding step and every recording script.
SECRET = "recording-secret-aaaaaaaaaaaaaaaaaaaaaaaaaa"


USERS_YAML = """\
schema_version: 1
auth_mode: local
users:
  - id: email:admin@example.com
    display_name: Admin Person
    roles: [admin]
  - id: email:approver@example.com
    display_name: Approver Person
    roles: [approver]
  - id: email:dev@example.com
    display_name: Dev Person
    roles: [requester]
  - id: email:dev2@example.com
    display_name: Dev Two
    roles: [requester]
  - id: email:badactor@example.com
    display_name: Bad Actor
    roles: [requester]
"""


ACCOUNTS_YAML = """\
apiVersion: iam-jit.dev/v1alpha1
kind: AccountList
accounts:
  - account_id: '060392206767'
    alias: omise-dev
    provisioning_mode: classic_iam
    provisioner_role_arn: arn:aws:iam::060392206767:role/iam-jit-provisioner
    provisioner_external_id: iam-jit-060392206767
    enabled: true
"""


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_health(url: str, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/healthz", timeout=2.0) as r:
                if r.status == 200:
                    return
        except Exception as e:
            last = e
        time.sleep(0.2)
    raise RuntimeError(f"iam-jit did not come up at {url}: {last}")


def seed_state() -> None:
    """Reset workspace, drop seed YAML files."""
    if WORKSPACE.exists():
        shutil.rmtree(WORKSPACE)
    WORKSPACE.mkdir(parents=True)
    (WORKSPACE / "users.yaml").write_text(USERS_YAML)
    (WORKSPACE / "accounts.yaml").write_text(ACCOUNTS_YAML)
    (WORKSPACE / "requests").mkdir()
    (WORKSPACE / "tokens").mkdir()


def start_server(port: int) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(
        {
            "IAM_JIT_AUTH_MODE": "local",
            "IAM_JIT_DEV_INSECURE_SECRET": "1",
            "IAM_JIT_MAGIC_LINK_SECRET": SECRET,
            "IAM_JIT_USER_CONFIG_SOURCE": "file",
            "IAM_JIT_USERS_FILE_LOCAL_PATH": str(WORKSPACE / "users.yaml"),
            "IAM_JIT_ACCOUNTS_FILE_LOCAL_PATH": str(WORKSPACE / "accounts.yaml"),
            "IAM_JIT_REQUESTS_DIR": str(WORKSPACE / "requests"),
            "IAM_JIT_LLM": "none",  # paste-mode is the deterministic path
            "IAM_JIT_PUBLIC_URL": f"http://127.0.0.1:{port}",
            "IAM_JIT_BOOTSTRAP_STATE_DIR": str(WORKSPACE),
        }
    )
    return subprocess.Popen(
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


# Order matters: the approve script needs a pending request to exist;
# the disable-role / revoke scripts need an active grant.
ORDERED_SCRIPTS = [
    "matrix_theme.py",
    "submit_request.py",
    "all_requests.py",
    "approve_request.py",
    "admin_provisioned.py",
    "revoke_grant.py",
    "admin_rediscover.py",
    "admin_users_add.py",
    "admin_disable_user.py",
    "admin_network_posture.py",
    "admin_bans_list.py",
    "get_banned.py",
    "api_token_lifecycle.py",
]


def main() -> int:
    if OUTPUT.exists():
        for f in OUTPUT.glob("*.webm"):
            f.unlink()
        for f in OUTPUT.glob("*.mp4"):
            f.unlink()
    OUTPUT.mkdir(parents=True, exist_ok=True)

    seed_state()
    port = free_port()
    base_url = f"http://127.0.0.1:{port}"

    print(f"== booting iam-jit on {base_url}")
    proc = start_server(port)
    try:
        wait_for_health(base_url)
        print(f"== server ready, running {len(ORDERED_SCRIPTS)} scripts")

        env_for_script = os.environ.copy()
        env_for_script["IAM_JIT_BASE_URL"] = base_url
        env_for_script["IAM_JIT_MAGIC_LINK_SECRET"] = SECRET

        for script_name in ORDERED_SCRIPTS:
            script_path = SCRIPTS / script_name
            if not script_path.exists():
                print(f"  - skipping (missing): {script_name}")
                continue
            r = subprocess.run(
                [sys.executable, str(script_path)],
                env=env_for_script,
                cwd=str(REPO),
            )
            if r.returncode != 0:
                print(f"  ! {script_name} failed (exit {r.returncode})")
        print("== all scripts done")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if WORKSPACE.exists():
            shutil.rmtree(WORKSPACE, ignore_errors=True)

    # Convert to mp4 alongside the webm. Playwright's bundled ffmpeg
    # is a vp8/webm-only build and can't encode H.264, so prefer the
    # imageio-ffmpeg pip package which ships a full build. Fall back
    # to system `ffmpeg` if neither is available.
    print("== converting to mp4")
    ffmpeg_bin = "ffmpeg"
    try:
        import imageio_ffmpeg

        ffmpeg_bin = imageio_ffmpeg.get_ffmpeg_exe()
    except ImportError:
        print(
            "  ! imageio-ffmpeg not installed; falling back to system "
            "ffmpeg. Install with: pip install imageio-ffmpeg"
        )
    converted = 0
    for webm in sorted(OUTPUT.glob("*.webm")):
        mp4 = webm.with_suffix(".mp4")
        r = subprocess.run(
            [
                ffmpeg_bin,
                "-y", "-loglevel", "error",
                "-i", str(webm),
                "-c:v", "libx264",
                "-preset", "fast",
                "-crf", "23",
                "-pix_fmt", "yuv420p",
                str(mp4),
            ],
            capture_output=True,
        )
        if r.returncode == 0:
            converted += 1
        else:
            err = r.stderr.decode("utf-8", errors="replace")[:200]
            print(f"  ! ffmpeg failed for {webm.name}: {err}")
    print(f"== mp4 conversion: {converted} of {len(list(OUTPUT.glob('*.webm')))}")

    listing = sorted(OUTPUT.glob("*.mp4"))
    if not listing:
        listing = sorted(OUTPUT.glob("*.webm"))
    print("\n== final outputs:")
    for f in listing:
        size_kb = f.stat().st_size / 1024
        print(f"  {f.name}  ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
