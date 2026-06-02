"""#741 — Claude-in-Docker E2E UAT.

Per [[uat-tests-setup-end-to-end]] STANDING DISCIPLINE: this test exercises
the FULL chain as a real operator experiences it:

  Pattern A (in-container):
    docker build → docker run (ibounce starts in entrypoint) →
    boto3 AWS call inside container → ibounce audits it →
    decisions_count Δ ≥ 1

  Pattern B (sidecar):
    docker-compose up -d (sidecar becomes healthy, claude depends_on it) →
    docker exec <claude> pip+boto3 call → ibounce sidecar audits it →
    decisions_count Δ ≥ 1 on the sidecar

The setup process IS the product.  The assertion is the OUTCOME (decisions_count
ticked), not just "the binary installed OK".

Per [[ibounce-honest-positioning]] + [[tests-and-independent-uat-required]]:
test is runnable by an independent agent (not the implementer) and verification
is against a REAL bouncer running inside Docker, not a stub.

Per [[permission-minimal-install]]: no sudo, no --dangerously-skip-permissions.

Skips gracefully when Docker daemon is not reachable; never hard-fails the CI
suite on an environment where Docker is absent.

NOTE: The `anthropics/claude-code` image is private/unavailable.
We use `python:3.12-slim-bookworm` as a drop-in; both Dockerfiles document
this substitution and explain the switch to make.  Bouncer behaviour is
identical regardless of the base image.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Repo root (so all paths are absolute regardless of cwd)
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent

# Compose file for Pattern B
_COMPOSE_FILE = _REPO_ROOT / "examples" / "docker" / "docker-compose.claude-sidecar.yml"

# Tag names used for testing — avoids collisions with prod tags.
_PATTERN_A_TAG = "iam-jit-pattern-a-e2e:test"
_SIDECAR_TAG = "iam-jit-sidecar-e2e:test"

# Docker-compose project name (avoids collision with dev stacks).
_COMPOSE_PROJECT = "iam-jit-e2e-741"

# Compose sidecar service/container name derived from project name.
_BOUNCER_SVC = "iam-jit-bouncer"
_CLAUDE_SVC = "claude"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command, streaming output unless capture=True."""
    merged_env = {**os.environ, **(env or {})}
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        timeout=timeout,
        env=merged_env,
    )


def _docker_available() -> bool:
    """Return True iff the Docker daemon is reachable."""
    try:
        result = _run(["docker", "info"], check=False, capture=True, timeout=10)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _docker_compose_cmd() -> list[str]:
    """Return the docker-compose invocation that works on this host."""
    # Try the legacy `docker-compose` binary first (still common on macOS).
    try:
        result = subprocess.run(
            ["docker-compose", "--version"],
            check=False,
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            return ["docker-compose"]
    except FileNotFoundError:
        pass
    # Fall back to `docker compose` plugin (Docker >= 20.10).
    return ["docker", "compose"]


def _compose(
    args: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    """Run docker-compose with the right invocation style."""
    base = _docker_compose_cmd()
    cmd = base + [
        "-f",
        str(_COMPOSE_FILE),
        "--project-name",
        _COMPOSE_PROJECT,
    ] + args
    return _run(cmd, check=check, capture=capture, timeout=timeout)


def _container_name(service: str) -> str:
    """Return the full container name for a compose service."""
    return f"{_COMPOSE_PROJECT}-{service}-1"


def _healthz_from_container(container_name: str) -> dict[str, Any]:
    """Query /healthz from INSIDE the bouncer container — avoids host-port conflicts."""
    result = _run(
        ["docker", "exec", container_name, "curl", "-sf", "http://127.0.0.1:8767/healthz"],
        capture=True,
        timeout=15,
    )
    return json.loads(result.stdout)


def _decisions_count_from_container(container_name: str) -> int:
    """Return decisions_count from the bouncer running inside *container_name*."""
    return int(_healthz_from_container(container_name)["decisions_count"])


def _wait_for_healthz_in_container(
    container_name: str,
    *,
    max_wait: int = 30,
    interval: float = 1.0,
) -> None:
    """Poll /healthz inside the container until it responds OK or times out."""
    deadline = time.monotonic() + max_wait
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _decisions_count_from_container(container_name)
            return  # success
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(interval)
    msg = f"healthz in {container_name} not ready after {max_wait}s"
    raise TimeoutError(msg) from last_exc


# ---------------------------------------------------------------------------
# Skip marker
# ---------------------------------------------------------------------------

_DOCKER_AVAILABLE = _docker_available()

requires_docker = pytest.mark.skipif(
    not _DOCKER_AVAILABLE,
    reason="Docker daemon not reachable — skipping Docker E2E tests",
)


# ---------------------------------------------------------------------------
# Pattern A — in-container install
# ---------------------------------------------------------------------------


@requires_docker
class TestPatternA:
    """Pattern A: iam-jit + ibounce installed INSIDE the Claude container.

    The operator extends their Claude-in-Docker image with a single RUN block
    (from examples/docker/claude-code-with-bouncers.Dockerfile).  The entrypoint
    (start-with-bouncers.sh) starts ibounce before handing off to the agent.
    Every subsequent boto3 / AWS-SDK call is intercepted by ibounce.

    This test:
    1. Builds the Pattern A image.
    2. Runs a container with the entrypoint active (ibounce starts in background).
    3. Makes a real HTTPS/AWS STS call from inside the container with fake creds.
       ibounce intercepts the call regardless of whether the creds are real;
       the proxy sees the SigV4-signed request and audits it.
    4. Asserts decisions_count Δ ≥ 1.
    """

    @pytest.fixture(scope="class", autouse=True)
    def build_pattern_a(self) -> None:  # type: ignore[return]
        """Build the Pattern A image once for all tests in this class."""
        _run(
            [
                "docker",
                "build",
                "-f",
                str(_REPO_ROOT / "examples" / "docker" / "claude-code-with-bouncers.Dockerfile"),
                "-t",
                _PATTERN_A_TAG,
                str(_REPO_ROOT),
            ],
            timeout=600,
        )

    def test_ibounce_audits_aws_call(self) -> None:
        """decisions_count ticks when a boto3 AWS call exits the container."""
        # Run a container with the entrypoint (start-with-bouncers).
        # The entrypoint starts ibounce BEFORE exec'ing our command.
        # We:
        #   1. Read decisions_count from ibounce's own /healthz.
        #   2. Make a boto3 STS GetCallerIdentity call.
        #      ibounce is cooperative (audit-only), so it intercepts +
        #      forwards the call (even with fake creds, the request is
        #      counted; botocore will raise an auth error from AWS, which
        #      is expected and fine).
        #   3. Read decisions_count again.
        #   4. Print the delta for the test runner + exit non-zero on failure.
        python_script = """
import json
import sys
import time
import urllib.request

def healthz() -> dict:
    url = "http://127.0.0.1:8767/healthz"
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.load(r)

# Poll until ibounce is ready (entrypoint already waited, but be defensive).
deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    try:
        h = healthz()
        break
    except Exception:
        time.sleep(0.5)
else:
    print("IBOUNCE_NOT_READY", flush=True)
    sys.exit(2)

before = h["decisions_count"]
print(f"BEFORE={before}", flush=True)

# Make an AWS STS call.  boto3 is installed as a transitive dep of iam-jit.
try:
    import boto3
    client = boto3.client(
        "sts",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )
    client.get_caller_identity()
except Exception as e:
    # Expected — fake creds → AuthFailure from AWS.
    # The REQUEST reaching ibounce is what matters; the response error is OK.
    print(f"CALL_ERROR={type(e).__name__}", flush=True)

after = healthz()["decisions_count"]
print(f"AFTER={after}", flush=True)
delta = after - before
print(f"DELTA={delta}", flush=True)
sys.exit(0 if delta >= 1 else 1)
"""

        result = _run(
            [
                "docker",
                "run",
                "--rm",
                # Fake AWS creds so the SDK sends a real HTTP request.
                "-e",
                "AWS_ACCESS_KEY_ID=testing",
                "-e",
                "AWS_SECRET_ACCESS_KEY=testing",
                "-e",
                "AWS_DEFAULT_REGION=us-east-1",
                # Use the entrypoint (start-with-bouncers), which starts ibounce
                # before running our command.
                "--entrypoint",
                "/usr/local/bin/start-with-bouncers",
                _PATTERN_A_TAG,
                "python3",
                "-c",
                python_script,
            ],
            capture=True,
            check=False,
            timeout=120,
        )

        # Emit stdout/stderr so CI logs show the full trace.
        print("--- Pattern A stdout ---")
        print(result.stdout)
        if result.stderr:
            print("--- Pattern A stderr (ibounce startup) ---")
            print(result.stderr[:2000])  # truncate verbose ibounce banner

        # Parse the key metrics from stdout.
        delta: int | None = None
        for line in result.stdout.splitlines():
            if line.startswith("DELTA="):
                delta = int(line.split("=", 1)[1])
            if line == "IBOUNCE_NOT_READY":
                pytest.fail("ibounce was not ready inside the Pattern A container")

        assert result.returncode == 0, (
            f"Pattern A container exited {result.returncode}.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr[:1000]}"
        )
        assert delta is not None, "DELTA line not found in container output"
        assert delta >= 1, (
            f"Pattern A: decisions_count did NOT tick (delta={delta}). "
            "ibounce is not intercepting AWS calls."
        )

        print(f"\nPattern A: decisions_count Δ={delta} ✓")


# ---------------------------------------------------------------------------
# Pattern B — sidecar deployment
# ---------------------------------------------------------------------------


@requires_docker
class TestPatternB:
    """Pattern B: iam-jit-sidecar runs alongside the Claude container.

    The operator does NOT modify the Claude image.  Instead they add an
    iam-jit-sidecar service to their docker-compose.yml and set
    AWS_ENDPOINT_URL=http://iam-jit-bouncer:8767 on the claude service.

    This test:
    1. Builds the sidecar image.
    2. Brings up the full compose stack (sidecar + claude).
       The sidecar must pass its healthcheck before claude starts.
    3. Makes a real STS call from inside the claude container.
       boto3 is NOT in the base claude image; we install it in one pip call
       as part of the test setup (mirrors what real operators do when they
       add their agent dependencies).
    4. Queries decisions_count via `docker exec` on the sidecar container
       (avoids any host-level port conflict).
    5. Asserts decisions_count Δ ≥ 1.
    6. Always tears down the compose stack — including on failure.
    """

    # -----------------------------------------------------------------------
    # Fixture: bring up / tear down the compose stack
    # -----------------------------------------------------------------------

    @pytest.fixture(scope="class")
    def compose_stack(self):  # type: ignore[return]
        """Yield the sidecar container name; tear down on exit."""
        bouncer_container = _container_name(_BOUNCER_SVC)
        claude_container = _container_name(_CLAUDE_SVC)

        # Build the sidecar image.
        _compose(
            [
                "build",
                "--build-arg",
                "IAM_JIT_REF=main",
            ],
            timeout=600,
        )

        # Bring the stack up.
        _compose(["up", "-d"], timeout=120)

        # Wait for the sidecar's healthz to respond inside its container.
        try:
            _wait_for_healthz_in_container(bouncer_container, max_wait=45)
        except TimeoutError as exc:
            _compose(["logs", "iam-jit-bouncer"], capture=False, check=False)
            _compose(["down", "--remove-orphans"], check=False)
            pytest.fail(f"sidecar healthz timed out: {exc}")

        yield bouncer_container, claude_container

        # Tear down — always.
        _compose(["down", "--remove-orphans"], check=False)

    def test_sidecar_audits_aws_call_from_claude(
        self,
        compose_stack: tuple[str, str],
    ) -> None:
        """decisions_count ticks on the sidecar when claude makes an AWS call."""
        bouncer_container, claude_container = compose_stack

        # Read baseline from sidecar (inside the sidecar container).
        before = _decisions_count_from_container(bouncer_container)
        print(f"\nPattern B: decisions_count before = {before}")

        # Install boto3 in the claude container (not in the base python image).
        # This mirrors what real operators do when they add agent dependencies.
        _run(
            [
                "docker",
                "exec",
                claude_container,
                "pip",
                "install",
                "--quiet",
                "boto3",
            ],
            timeout=120,
        )

        # Make an STS call from the claude container.
        # AWS_ENDPOINT_URL is already set to http://iam-jit-bouncer:8767 in
        # the compose file — boto3 will route through the sidecar automatically.
        aws_call_script = """
import boto3, sys
try:
    client = boto3.client(
        "sts",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )
    client.get_caller_identity()
except Exception as e:
    # Expected — fake creds or proxy response format difference.
    print(f"CALL_ERROR={type(e).__name__}", flush=True)
print("CALL_DONE", flush=True)
"""
        result = _run(
            [
                "docker",
                "exec",
                "-e",
                "AWS_ACCESS_KEY_ID=testing",
                "-e",
                "AWS_SECRET_ACCESS_KEY=testing",
                "-e",
                "AWS_DEFAULT_REGION=us-east-1",
                claude_container,
                "python3",
                "-c",
                aws_call_script,
            ],
            capture=True,
            check=False,
            timeout=30,
        )
        print("claude exec stdout:", result.stdout)
        if result.returncode != 0:
            print("claude exec stderr:", result.stderr)

        # Read after from sidecar.
        after = _decisions_count_from_container(bouncer_container)
        delta = after - before
        print(f"Pattern B: decisions_count after = {after}, Δ = {delta}")

        assert "CALL_DONE" in result.stdout, (
            f"AWS call script did not complete inside claude container.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert delta >= 1, (
            f"Pattern B: sidecar decisions_count did NOT tick (delta={delta}). "
            "ibounce sidecar is not intercepting AWS calls from the claude service."
        )

        print(f"\nPattern B: decisions_count Δ={delta} ✓")
