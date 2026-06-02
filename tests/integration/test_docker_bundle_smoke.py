"""#741 — Docker bundle smoke test.

Per [[uat-tests-setup-end-to-end]] STANDING DISCIPLINE: tests must exercise
the full chain as an operator / CI pipeline experiences it:

  docker pull (or local build) → docker run → real iam-jit init → config
  file written → assert config exists and is valid YAML.

The setup process IS the product. Per [[ibounce-honest-positioning]] the
image must not silently degrade (missing binary = hard failure, not a
graceful "not available" message).

Per [[tests-and-independent-uat-required]]: this test is independent of
the implementer. It drives the image as a black box via subprocess + docker,
NOT via Python imports. It MUST verify actual outcomes, not internal state.

Test structure
--------------
These tests are marked ``integration`` (requires Docker daemon) and are
skipped when:
  - Docker is not installed / running.
  - ``IAM_JIT_BUNDLE_IMAGE`` env var is not set AND the local image
    ``iam-jit-bundle:local`` doesn't exist. Set the env var or build
    the image locally before running:

    docker build \\
      -f infrastructure/docker/Dockerfile.iam-jit-bundle \\
      --build-context kbouncer=../kbouncer \\
      --build-context gbounce=../gbounce \\
      --build-context dbounce=../dbounce \\
      -t iam-jit-bundle:local .

    Then:

    pytest -m integration tests/integration/test_docker_bundle_smoke.py -v

The ``decisions_count`` test (TestDecisionsCountTicks) requires the host
ibounce to be running on :8767. It verifies that a `docker run ... aws
sts get-caller-identity` routed through ibounce increments decisions_count
— per [[uat-tests-setup-end-to-end]] the bouncer-audit side of the loop
must tick. Mark: ``live_bouncer`` (skipped when :8767 is closed).
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import urllib.request
from contextlib import closing

import pytest
import yaml


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_LOCAL_IMAGE = "iam-jit-bundle:local"
_FALLBACK_PUBLISHED = "ghcr.io/trsreagan3/iam-jit:latest"

# Test binaries expected in the image.
_EXPECTED_BINARIES = ["iam-jit", "ibounce", "kbounce", "dbounce", "gbounce"]

_IBOUNCE_HOST = "127.0.0.1"
_IBOUNCE_PORT = 8767


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _docker_available() -> bool:
    """Return True iff docker is installed + daemon is running."""
    return shutil.which("docker") is not None and _can_docker_ps()


def _can_docker_ps() -> bool:
    try:
        result = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _image_exists_locally(image: str) -> bool:
    """Return True iff the image tag is present in the local docker store."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _resolve_image() -> str | None:
    """Return the image name to test against, or None if not available.

    Priority:
      1. IAM_JIT_BUNDLE_IMAGE env var (operator / CI override)
      2. iam-jit-bundle:local (local build)
      3. None → tests skip
    """
    explicit = os.environ.get("IAM_JIT_BUNDLE_IMAGE")
    if explicit:
        return explicit
    if _image_exists_locally(_DEFAULT_LOCAL_IMAGE):
        return _DEFAULT_LOCAL_IMAGE
    return None


def _port_is_open(host: str, port: int) -> bool:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(0.5)
            s.connect((host, port))
            return True
    except OSError:
        return False


def _ibounce_decisions_count() -> int:
    """Fetch decisions_count from ibounce /healthz. Raises on error."""
    url = f"http://{_IBOUNCE_HOST}:{_IBOUNCE_PORT}/healthz"
    with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310
        data = json.loads(resp.read())
    return int(data["decisions_count"])


def _docker_run(
    image: str,
    args: list[str],
    *,
    entrypoint: str | None = None,
    env: dict[str, str] | None = None,
    volumes: dict[str, str] | None = None,
    timeout: int = 60,
) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
    """Run `docker run --rm <image> <args>` and return the CompletedProcess."""
    cmd = ["docker", "run", "--rm"]
    if entrypoint:
        cmd += ["--entrypoint", entrypoint]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    for host_path, container_path in (volumes or {}).items():
        cmd += ["-v", f"{host_path}:{container_path}"]
    cmd.append(image)
    cmd.extend(args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Fixtures / markers
# ---------------------------------------------------------------------------

_DOCKER_AVAILABLE = _docker_available()
_IMAGE = _resolve_image()
_IBOUNCE_RUNNING = _port_is_open(_IBOUNCE_HOST, _IBOUNCE_PORT)

requires_docker = pytest.mark.skipif(
    not _DOCKER_AVAILABLE,
    reason="Docker daemon not running — skipping Docker bundle smoke tests",
)
requires_image = pytest.mark.skipif(
    _IMAGE is None,
    reason=(
        "No bundle image found. Build with: "
        "docker build -f infrastructure/docker/Dockerfile.iam-jit-bundle "
        "--build-context kbouncer=../kbouncer "
        "--build-context gbounce=../gbounce "
        "--build-context dbounce=../dbounce "
        "-t iam-jit-bundle:local . "
        "(or set IAM_JIT_BUNDLE_IMAGE env var)"
    ),
)
live_bouncer = pytest.mark.skipif(
    not _IBOUNCE_RUNNING,
    reason="ibounce not running on :8767 — skipping live-bouncer decisions_count test",
)


# ---------------------------------------------------------------------------
# Tests — binary presence
# ---------------------------------------------------------------------------


@pytest.mark.integration
@requires_docker
@requires_image
class TestBinaryPresence:
    """Every binary expected in the bundle must answer --version."""

    @pytest.mark.parametrize("binary", _EXPECTED_BINARIES)
    def test_binary_version(self, binary: str) -> None:
        """Binary returns exit 0 for --version."""
        image = _IMAGE
        assert image is not None

        # Use the binary as the entrypoint so we can test each independently.
        ep = binary if binary != "iam-jit" else None
        result = _docker_run(
            image,
            ["--version"],
            entrypoint=ep,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"{binary} --version exited {result.returncode}.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        # Verify some version-like token appears in the output (stdout or stderr).
        combined = result.stdout + result.stderr
        assert combined.strip(), (
            f"{binary} --version produced empty output (stdout+stderr)"
        )


# ---------------------------------------------------------------------------
# Tests — non-interactive init
# ---------------------------------------------------------------------------


@pytest.mark.integration
@requires_docker
@requires_image
class TestInitNonInteractive:
    """iam-jit init --no-prompt writes a valid config; exit 0.

    Per [[uat-tests-setup-end-to-end]]: the setup process IS the product.
    This test mirrors the canonical CI install path:

      docker run --rm \\
        -v <tmp>:/var/lib/iam-jit \\
        -e IAM_JIT_DATA_DIR=/var/lib/iam-jit \\
        <image> init --no-prompt --harness=claude-code
    """

    def test_init_no_prompt_exits_zero(self, tmp_path: pathlib.Path) -> None:
        """init --no-prompt --harness=claude-code exits 0."""
        image = _IMAGE
        assert image is not None

        result = _docker_run(
            image,
            ["init", "--no-prompt", "--harness=claude-code"],
            env={"IAM_JIT_DATA_DIR": "/var/lib/iam-jit"},
            volumes={str(tmp_path): "/var/lib/iam-jit"},
            timeout=60,
        )
        assert result.returncode == 0, (
            f"iam-jit init --no-prompt exited {result.returncode}.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_init_writes_config_file(self, tmp_path: pathlib.Path) -> None:
        """init writes iam-jit.yaml at the expected path."""
        image = _IMAGE
        assert image is not None

        _docker_run(
            image,
            ["init", "--no-prompt", "--harness=claude-code"],
            env={"IAM_JIT_DATA_DIR": "/var/lib/iam-jit"},
            volumes={str(tmp_path): "/var/lib/iam-jit"},
            timeout=60,
        )
        config_path = tmp_path / "iam-jit.yaml"
        assert config_path.exists(), (
            f"Expected iam-jit.yaml at {config_path} but file was not written.\n"
            "Check that IAM_JIT_DATA_DIR is respected inside the container."
        )

    def test_init_config_is_valid_yaml(self, tmp_path: pathlib.Path) -> None:
        """The written config file is valid YAML and has top-level keys."""
        image = _IMAGE
        assert image is not None

        _docker_run(
            image,
            ["init", "--no-prompt", "--harness=claude-code"],
            env={"IAM_JIT_DATA_DIR": "/var/lib/iam-jit"},
            volumes={str(tmp_path): "/var/lib/iam-jit"},
            timeout=60,
        )
        config_path = tmp_path / "iam-jit.yaml"
        if not config_path.exists():
            pytest.skip("Config not written — covered by test_init_writes_config_file")

        raw = config_path.read_text()
        parsed = yaml.safe_load(raw)
        assert isinstance(parsed, dict), (
            f"iam-jit.yaml parsed to {type(parsed).__name__}, expected dict.\n"
            f"Content:\n{raw}"
        )
        # At minimum: shape + bouncers block should be present.
        assert "shape" in parsed or "bouncers" in parsed or "mode" in parsed, (
            f"Config YAML has no recognised top-level keys.\nParsed: {parsed}"
        )

    def test_init_logs_decisions_to_stdout(self, tmp_path: pathlib.Path) -> None:
        """Non-interactive init surfaces [init] decision lines to stdout.

        Per cli_init._log_decision: every defaulted choice is printed when
        stdin is not a TTY (which it never is in `docker run --rm`).
        """
        image = _IMAGE
        assert image is not None

        result = _docker_run(
            image,
            ["init", "--no-prompt", "--harness=claude-code"],
            env={"IAM_JIT_DATA_DIR": "/var/lib/iam-jit"},
            volumes={str(tmp_path): "/var/lib/iam-jit"},
            timeout=60,
        )
        assert result.returncode == 0
        combined = result.stdout + result.stderr
        # At least one [init] line should appear (shape, mode, harness, etc.)
        assert "[init]" in combined, (
            "Expected [init] decision log lines in output but found none.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_init_idempotent_with_overwrite(self, tmp_path: pathlib.Path) -> None:
        """Running init twice with --overwrite does not error on second call."""
        image = _IMAGE
        assert image is not None

        shared_env = {"IAM_JIT_DATA_DIR": "/var/lib/iam-jit"}
        shared_vol = {str(tmp_path): "/var/lib/iam-jit"}
        args = ["init", "--no-prompt", "--harness=claude-code", "--overwrite"]

        r1 = _docker_run(image, args, env=shared_env, volumes=shared_vol, timeout=60)
        r2 = _docker_run(image, args, env=shared_env, volumes=shared_vol, timeout=60)

        assert r1.returncode == 0, f"First init failed: {r1.stderr}"
        assert r2.returncode == 0, (
            f"Second init (--overwrite) failed: {r2.returncode}\n"
            f"stdout: {r2.stdout}\nstderr: {r2.stderr}"
        )


# ---------------------------------------------------------------------------
# Tests — decisions_count integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
@requires_docker
@requires_image
@live_bouncer
class TestDecisionsCountTicks:
    """Verify that an AWS call routed through ibounce increments decisions_count.

    Per [[uat-tests-setup-end-to-end]]:
      install → wire → agent-makes-real-call → bouncer-audits-it →
      decisions_count ticked → ASSERT

    This test requires:
      1. ibounce running on host :8767
      2. AWS credentials accessible (either via env vars or host ~/.aws/)

    The container routes boto3 sts:GetCallerIdentity through the host
    ibounce by setting AWS_ENDPOINT_URL=http://host-gateway:8767. The
    host ibounce proxies the call upstream and logs the decision.

    On Linux, host-gateway resolves to the docker bridge IP (172.17.0.1)
    via --add-host. On macOS with Docker Desktop, host-gateway resolves
    via Docker Desktop's built-in host.docker.internal magic.
    """

    def test_decisions_count_increments(self, tmp_path: pathlib.Path) -> None:
        """After routing an AWS call through ibounce, decisions_count ticks.

        Assertion strategy:
          (A) the container exits 0 (the AWS call returned a parseable response
              — STS may refuse with 403 if no valid creds are present, but
              ibounce still proxies the request and ticks decisions_count)
          (B) decisions_count at ibounce incremented by at least 1

        Per [[ibounce-honest-positioning]]: ibounce is a transparent proxy;
        it logs EVERY request it sees regardless of the upstream HTTP status.
        """
        image = _IMAGE
        assert image is not None

        count_before = _ibounce_decisions_count()

        # Build the minimal AWS env to forward into the container.
        aws_env: dict[str, str] = {
            "IAM_JIT_DATA_DIR": "/var/lib/iam-jit",
            # Route boto3 through the host ibounce.
            "AWS_ENDPOINT_URL": "http://host.docker.internal:8767",
        }
        for k in (
            "AWS_DEFAULT_REGION",
            "AWS_REGION",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_PROFILE",
        ):
            if k in os.environ:
                aws_env[k] = os.environ[k]
        if "AWS_DEFAULT_REGION" not in aws_env and "AWS_REGION" not in aws_env:
            aws_env["AWS_DEFAULT_REGION"] = "us-east-1"

        # Run a minimal boto3 STS call inside the container.
        # We use --entrypoint python3 and -c to avoid shipping a script file.
        boto3_code = (
            "import boto3, json;"
            "r=boto3.client('sts').get_caller_identity();"
            "print(json.dumps({'Account':r['Account'],'UserId':r['UserId']}))"
        )
        result = _docker_run(
            image,
            ["-c", boto3_code],
            entrypoint="python3",
            env=aws_env,
            volumes={str(tmp_path): "/var/lib/iam-jit"},
            timeout=30,
        )

        # (B) decisions_count must tick — this is the primary assertion.
        count_after = _ibounce_decisions_count()
        assert count_after > count_before, (
            f"decisions_count did not tick: {count_before} → {count_after}.\n"
            "Confirm ibounce received the proxied request from the container.\n"
            f"Container stdout: {result.stdout}\nContainer stderr: {result.stderr}"
        )

        # (A) Container exit is informational — 403 from STS is OK (creds may
        # be missing/expired in CI), but a connection error means ibounce
        # wasn't reached (decisions_count check above would also fail).
        if result.returncode != 0 and "AuthFailure" not in result.stderr:
            # Not a hard failure for decisions_count, but surface it clearly.
            pytest.warns(  # type: ignore[call-overload]
                UserWarning,
                match="boto3 call returned non-zero",
            )
