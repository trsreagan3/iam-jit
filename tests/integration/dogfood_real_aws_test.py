"""Pytest wrapper for the nightly dogfood script.

`pyproject.toml` runs `pytest -m "not integration and not e2e"` by
default, so this test is SKIPPED in the normal local + CI test runs.
To exercise it explicitly:

    pytest tests/integration/dogfood_real_aws_test.py -m integration

or run the underlying script directly:

    python tests/integration/dogfood_real_aws.py [--dry-run]

The pytest wrapper is here so a dev can pull the dogfood into their
familiar test runner without re-typing argv or env. See
docs/CI-NIGHTLY-DOGFOOD.md for the contract this enforces.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_DOGFOOD_SCRIPT = Path(__file__).resolve().parent / "dogfood_real_aws.py"


@pytest.mark.integration
def test_nightly_dogfood_dry_run() -> None:
    """Dry-run exercises F1..F9 without touching AWS. Safe to run
    on any machine with the venv installed."""
    proc = subprocess.run(
        [sys.executable, str(_DOGFOOD_SCRIPT), "--dry-run"],
        capture_output=True, text=True, timeout=180,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"dogfood --dry-run failed (rc={proc.returncode})\n"
            f"stdout:\n{proc.stdout[-2000:]}\n\n"
            f"stderr:\n{proc.stderr[-1000:]}"
        )


@pytest.mark.integration
def test_nightly_dogfood_full_run_real_aws() -> None:
    """Full run requires AWS credentials + the founder-account
    setup described in the spec. Skips when AWS env isn't present
    so a dev who runs `-m integration` blindly doesn't get a
    confusing botocore.NoCredentialsError."""
    has_aws = any(
        os.environ.get(k)
        for k in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN",
                  "AWS_ROLE_ARN")
    )
    if not has_aws:
        pytest.skip(
            "no AWS creds in env — set AWS_PROFILE or AWS_ACCESS_KEY_ID "
            "to run the full dogfood; see docs/CI-NIGHTLY-DOGFOOD.md."
        )
    proc = subprocess.run(
        [sys.executable, str(_DOGFOOD_SCRIPT)],
        capture_output=True, text=True, timeout=1700,  # < 30min workflow cap
    )
    if proc.returncode != 0:
        pytest.fail(
            f"dogfood full run failed (rc={proc.returncode})\n"
            f"stdout:\n{proc.stdout[-3000:]}\n\n"
            f"stderr:\n{proc.stderr[-1500:]}"
        )
