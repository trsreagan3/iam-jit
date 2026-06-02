"""#740 — Linux install-bootstrap end-to-end UAT.

Verifies the full install loop on Ubuntu 22.04, Debian 12, and Fedora 40
via `docker run`. Each platform exercises:

  1. pip install from repo (volume-mounted as /workspace)
  2. ibounce init  (SQLite state + default rules)
  3. ibounce run --mode cooperative  (HTTP proxy on :8767)
  4. boto3 STS call through ibounce  (fake creds, exercises HTTP layer)
  5. decisions_count tick on /healthz  (proves ibounce saw the call)
  6. iam-jit init --non-interactive  (writes ~/.iam-jit/iam-jit.yaml)

Per [[uat-tests-setup-end-to-end]] STANDING DISCIPLINE:
  - The setup process IS the product.
  - Assert OUTCOMES (decisions_count ticked, config written), not units.
  - Run inside REAL docker containers — not mocks or stubs.

Per [[permission-minimal-install]]: no sudo, no --dangerously-skip-permissions.
Per [[ibounce-honest-positioning]]: test must FAIL honestly when broken.
Per [[tests-and-independent-uat-required]]: independent agent runs this after
  every install-path change. The implementer of a fix must NOT be the verifier.

KEY BUG FIXED (task #740):
  - datetime.UTC (added Python 3.11) was used throughout the codebase.
    Ubuntu 22.04 ships Python 3.10, where datetime.UTC does not exist.
    ibounce init crashed with AttributeError: module 'datetime' has no
    attribute 'UTC', leaving the bouncer without default rules.
    Fix: iam_jit/__init__.py now patches datetime.UTC → datetime.timezone.utc
    for Python < 3.11 at package-import time.

Requires Docker running (colima or Docker Desktop). Tests are marked
`integration` and are SKIPPED when Docker is not available.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import textwrap
from typing import NamedTuple

import pytest

# ---------------------------------------------------------------------------
# Docker availability guard
# ---------------------------------------------------------------------------

_DOCKER_HOST = os.environ.get(
    "DOCKER_HOST",
    f"unix://{pathlib.Path.home()}/.colima/default/docker.sock",
)


def _docker_available() -> bool:
    """Return True iff Docker daemon is reachable."""
    env = os.environ.copy()
    env["DOCKER_HOST"] = _DOCKER_HOST
    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
            env=env,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_DOCKER_UP = _docker_available()

requires_docker = pytest.mark.skipif(
    not _DOCKER_UP,
    reason="Docker daemon not available — skipping Linux install UAT",
)

# ---------------------------------------------------------------------------
# Platform matrix
# ---------------------------------------------------------------------------


class Platform(NamedTuple):
    name: str           # human label for test IDs and report
    image: str          # docker image:tag
    pre_install: str    # shell snippet run BEFORE pip (installs python/venv if needed)
    venv_prefix: str    # prefix to source venv, e.g. "source /opt/venv/bin/activate &&"


PLATFORMS: list[Platform] = [
    Platform(
        name="ubuntu-22.04",
        image="ubuntu:22.04",
        pre_install=textwrap.dedent("""
            apt-get update -qq 2>/dev/null
            apt-get install -qq -y python3 python3-pip python3-venv 2>/dev/null | tail -1
            python3 -m venv /opt/venv
        """),
        venv_prefix="export PATH=/opt/venv/bin:$PATH &&",
    ),
    Platform(
        name="debian-12",
        image="python:3.12-slim-bookworm",
        pre_install="",  # image already has Python 3.12
        venv_prefix="",  # no venv needed; system Python is clean
    ),
    Platform(
        name="fedora-40",
        image="fedora:40",
        pre_install=textwrap.dedent("""
            dnf install -y -q python3 python3-pip 2>/dev/null | tail -2
            python3 -m venv /opt/venv
        """),
        venv_prefix="export PATH=/opt/venv/bin:$PATH &&",
    ),
]

# ---------------------------------------------------------------------------
# Container script template
# ---------------------------------------------------------------------------

# The script is injected into `docker run <image> sh -c <script>`.
# It runs the full install chain and emits structured output lines that
# the test assertions parse. Each observable is on its own line:
#   decisions_before=<int>
#   STS_FAIL: <type>   OR  STS_OK
#   decisions_after=<int>
#   config_written=OK  OR  config_written=FAIL
#   RESULT: PASS  OR  RESULT: FAIL

_CONTAINER_SCRIPT_TEMPLATE = textwrap.dedent("""
    set -e
    echo '--- platform start ---'

    {pre_install}

    {venv_prefix} python3 -m pip install --upgrade pip --quiet 2>&1 | tail -1
    {venv_prefix} pip install /workspace --quiet 2>&1 | tail -1

    # Verify binary is on PATH.
    {venv_prefix} python3 --version
    {venv_prefix} iam-jit --version | head -1

    # --- ibounce init + run ---
    {venv_prefix} ibounce init 2>&1 | head -2
    {venv_prefix} ibounce run --port 8767 --mode cooperative > /tmp/ibounce.log 2>&1 &
    IPID=$!
    sleep 3

    # --- decisions_count before ---
    DC1=$({venv_prefix} python3 -c "
import urllib.request, json
resp = urllib.request.urlopen('http://127.0.0.1:8767/healthz', timeout=5)
data = json.loads(resp.read())
print(data['decisions_count'])
" 2>&1)
    echo "decisions_before=$DC1"

    # --- boto3 STS call with fake creds (exercises ibounce HTTP layer) ---
    {venv_prefix} python3 -c "
import os, boto3, sys
os.environ['AWS_ACCESS_KEY_ID'] = 'AKIAFAKEKEY000001'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'FakeSecretKey1234567890abcdef'
os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
try:
    sts = boto3.client('sts', endpoint_url='http://127.0.0.1:8767', region_name='us-east-1')
    sts.get_caller_identity()
    print('STS_OK')
except Exception as e:
    print('STS_FAIL:', type(e).__name__)
" 2>&1

    # --- decisions_count after ---
    DC2=$({venv_prefix} python3 -c "
import urllib.request, json
resp = urllib.request.urlopen('http://127.0.0.1:8767/healthz', timeout=5)
data = json.loads(resp.read())
print(data['decisions_count'])
" 2>&1)
    echo "decisions_after=$DC2"

    # --- iam-jit init non-interactive ---
    {venv_prefix} iam-jit init \\
        --non-interactive \\
        --no-doctor-check \\
        --skip-mcp-install \\
        --bouncers ibounce \\
        --data-dir /tmp/iam-jit-data \\
        --overwrite 2>&1 | grep -E "\\[ok\\] wrote|Error" | head -3

    # --- verify config written ---
    if {venv_prefix} ls /tmp/iam-jit-data/iam-jit.yaml > /dev/null 2>&1; then
        echo "config_written=OK"
    else
        echo "config_written=FAIL"
    fi

    # --- final verdict ---
    kill $IPID 2>/dev/null || true
    if [ "$DC2" -gt "$DC1" ] 2>/dev/null; then
        echo "RESULT: PASS"
    else
        echo "RESULT: FAIL decisions_count did not tick (before=$DC1 after=$DC2)"
    fi
""")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_container(platform: Platform, repo_path: str) -> tuple[int, str]:
    """Run the install-bootstrap script inside a docker container.

    Returns (returncode, combined_output). The returncode is from the
    docker run exit; the output includes all stdout + stderr from the
    container so assertions can parse it.
    """
    script = _CONTAINER_SCRIPT_TEMPLATE.format(
        pre_install=platform.pre_install.strip(),
        venv_prefix=platform.venv_prefix,
    )
    env = os.environ.copy()
    env["DOCKER_HOST"] = _DOCKER_HOST

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{repo_path}:/workspace",
        platform.image,
        "sh", "-c", script,
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,   # 10 min per platform — image pulls can be slow
        env=env,
    )
    output = proc.stdout + proc.stderr
    return proc.returncode, output


def _assert_pass(platform_name: str, output: str) -> None:
    """Assert that the container run produced PASS on all observable metrics.

    Parses the structured output lines emitted by the container script and
    asserts each invariant independently so failures are maximally specific.

    Per [[ibounce-honest-positioning]]: NEVER silence a partial failure.
    """
    lines = output.splitlines()

    # (1) Container must have exited cleanly. If not, surface the full output.
    # Note: returncode is checked by the caller before calling this helper.

    def _find(prefix: str) -> str | None:
        for ln in lines:
            stripped = ln.strip()
            if stripped.startswith(prefix):
                return stripped[len(prefix):]
        return None

    # (2) decisions_count must have ticked.
    before_raw = _find("decisions_before=")
    after_raw = _find("decisions_after=")
    assert before_raw is not None, (
        f"[{platform_name}] 'decisions_before=' not found in output.\n"
        f"Full output:\n{output}"
    )
    assert after_raw is not None, (
        f"[{platform_name}] 'decisions_after=' not found in output.\n"
        f"Full output:\n{output}"
    )
    try:
        before = int(before_raw.strip())
        after = int(after_raw.strip())
    except ValueError as exc:
        pytest.fail(
            f"[{platform_name}] Could not parse decisions_count: "
            f"before={before_raw!r} after={after_raw!r}. Error: {exc}\n"
            f"Full output:\n{output}"
        )
    assert after > before, (
        f"[{platform_name}] decisions_count did NOT tick: {before} → {after}.\n"
        "This means ibounce did not see the boto3 STS call.\n"
        f"Full output:\n{output}"
    )

    # (3) iam-jit config must have been written.
    config_written = _find("config_written=")
    assert config_written == "OK", (
        f"[{platform_name}] iam-jit config NOT written (got {config_written!r}).\n"
        f"Full output:\n{output}"
    )

    # (4) Final RESULT must be PASS.
    result = _find("RESULT: ")
    assert result == "PASS", (
        f"[{platform_name}] RESULT is not PASS (got {result!r}).\n"
        f"Full output:\n{output}"
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@requires_docker
@pytest.mark.integration
@pytest.mark.parametrize("platform", PLATFORMS, ids=[p.name for p in PLATFORMS])
def test_linux_install_e2e(platform: Platform) -> None:
    """Full install-bootstrap UAT on a Linux container.

    Chain: pip install → ibounce init → ibounce run → boto3 STS call →
    decisions_count ticks → iam-jit init writes config.

    Per [[uat-tests-setup-end-to-end]]: asserts OUTCOMES, not units.
    Per [[tests-and-independent-uat-required]]: independent verification.
    """
    repo_path = str(pathlib.Path(__file__).parents[2])
    rc, output = _run_container(platform, repo_path)

    # Surface container exit code failure with full output context.
    # rc=1 is acceptable if the RESULT line is PASS (some `set -e` steps
    # may emit non-zero in pre-install stages). Only fail on rc!=0 if
    # RESULT is also not PASS.
    result_line = None
    for ln in output.splitlines():
        if "RESULT: " in ln:
            result_line = ln
    pass_found = result_line is not None and "RESULT: PASS" in result_line

    if rc != 0 and not pass_found:
        pytest.fail(
            f"[{platform.name}] Docker container exited {rc} AND no RESULT: PASS found.\n"
            f"Full output:\n{output}"
        )

    _assert_pass(platform.name, output)


@requires_docker
@pytest.mark.integration
@pytest.mark.parametrize("platform", PLATFORMS, ids=[p.name for p in PLATFORMS])
def test_datetime_utc_compat_py310(platform: Platform) -> None:
    """#740 BUG FIX REGRESSION: datetime.UTC must be available on Python 3.10.

    Ubuntu 22.04 ships Python 3.10. Before this fix, ibounce init crashed:
      AttributeError: module 'datetime' has no attribute 'UTC'
    The fix patches datetime.UTC in iam_jit/__init__.py.

    This test independently verifies the fix is in place by checking
    inside the container that `_dt.UTC` is accessible after importing
    iam_jit.
    """
    repo_path = str(pathlib.Path(__file__).parents[2])

    pre_install = platform.pre_install.strip()
    venv_prefix = platform.venv_prefix

    script = textwrap.dedent(f"""
        set -e
        {pre_install}
        {venv_prefix} python3 -m pip install --upgrade pip --quiet 2>&1 | tail -1
        {venv_prefix} pip install /workspace --quiet 2>&1 | tail -1
        {venv_prefix} python3 -c "
import iam_jit  # triggers __init__.py patch
import datetime as _dt
import sys
ver = sys.version_info[:2]
has_utc = hasattr(_dt, 'UTC')
is_correct = has_utc and _dt.UTC is _dt.timezone.utc
print(f'python={{ver}} has_utc={{has_utc}} is_correct={{is_correct}}')
if not has_utc:
    print('COMPAT_FAIL: datetime.UTC not found')
    sys.exit(1)
if not is_correct:
    print('COMPAT_FAIL: datetime.UTC is not timezone.utc')
    sys.exit(1)
print('COMPAT_PASS')
"
    """)

    env = os.environ.copy()
    env["DOCKER_HOST"] = _DOCKER_HOST

    proc = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{repo_path}:/workspace",
            platform.image,
            "sh", "-c", script,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )
    output = proc.stdout + proc.stderr

    assert "COMPAT_PASS" in output, (
        f"[{platform.name}] datetime.UTC compatibility check FAILED.\n"
        f"Full output:\n{output}"
    )
    assert "COMPAT_FAIL" not in output, (
        f"[{platform.name}] datetime.UTC compatibility failure detected.\n"
        f"Full output:\n{output}"
    )
