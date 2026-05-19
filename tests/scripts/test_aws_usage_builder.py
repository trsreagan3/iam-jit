"""Tests for `scripts/aws_usage_builder.py`.

The script lives outside the `src/iam_jit/` import path; we load it as a
file-relative module so the test suite can exercise it without polluting
package namespaces.

All AWS calls are mocked via `moto.mock_aws`. No real AWS network access.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import boto3
import pytest
from moto import mock_aws


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "aws_usage_builder.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "aws_usage_builder_under_test", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def script(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Fresh module + redirected log dir per test."""
    module = _load_module()
    # Redirect log output into tmp so we never write to the operator's home
    log_dir = tmp_path / ".iam-jit"
    monkeypatch.setattr(module, "LOG_DIR", log_dir)
    monkeypatch.setattr(module, "LOG_PATH", log_dir / "aws-usage-builder.log")
    return module


def _read_log(script_mod: Any) -> str:
    if not script_mod.LOG_PATH.exists():
        return ""
    return script_mod.LOG_PATH.read_text(encoding="utf-8")


@pytest.fixture()
def aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Baseline AWS env that satisfies the credential check + region."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# --------------------------------------------------------------------------- #
# Happy path                                                                  #
# --------------------------------------------------------------------------- #


def test_successful_run_all_three_calls_exit_zero(
    script: Any, monkeypatch: pytest.MonkeyPatch, aws_env: None
) -> None:
    bucket = "usage-builder-test"
    monkeypatch.setenv("IAM_JIT_USAGE_BUCKET", bucket)

    with mock_aws():
        # Pre-create the bucket so PutObject succeeds.
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=bucket)
        exit_code = script.run()

    assert exit_code == 0
    log = _read_log(script)
    assert "s3=OK" in log
    assert "cloudwatch=OK" in log
    assert "ec2=OK" in log
    assert "summary ok=3/3" in log


# --------------------------------------------------------------------------- #
# Refusal paths                                                               #
# --------------------------------------------------------------------------- #


def test_missing_bucket_env_exits_clean(
    script: Any, monkeypatch: pytest.MonkeyPatch, aws_env: None
) -> None:
    monkeypatch.delenv("IAM_JIT_USAGE_BUCKET", raising=False)

    # Sentinel: if any AWS call were attempted, _make_session would be hit.
    called = {"n": 0}

    def _boom() -> None:
        called["n"] += 1
        raise AssertionError("session must not be built when bucket env missing")

    monkeypatch.setattr(script, "_make_session", _boom)

    exit_code = script.run()

    assert exit_code == 2
    assert called["n"] == 0
    log = _read_log(script)
    assert "abort=missing-env" in log
    assert "IAM_JIT_USAGE_BUCKET" in log


def test_missing_credentials_exits_clean(
    script: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IAM_JIT_USAGE_BUCKET", "usage-builder-test")
    # Wipe every variable boto3's default chain inspects.
    for var in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
    ):
        monkeypatch.delenv(var, raising=False)

    class _NoCredsSession:
        region_name = "us-east-1"

        def get_credentials(self) -> None:
            return None

        def client(self, *a: Any, **kw: Any) -> Any:
            raise AssertionError("no AWS client should be built without creds")

    monkeypatch.setattr(script, "_make_session", lambda: _NoCredsSession())

    exit_code = script.run()

    assert exit_code == 4
    log = _read_log(script)
    assert "abort=missing-credentials" in log


# --------------------------------------------------------------------------- #
# Partial-failure behavior                                                    #
# --------------------------------------------------------------------------- #


def test_s3_failure_does_not_abort_other_calls(
    script: Any, monkeypatch: pytest.MonkeyPatch, aws_env: None
) -> None:
    # Bucket env is set, but we deliberately do NOT create the bucket so
    # the real moto-backed S3 PutObject raises NoSuchBucket.
    monkeypatch.setenv("IAM_JIT_USAGE_BUCKET", "does-not-exist-bucket")

    with mock_aws():
        exit_code = script.run()

    log = _read_log(script)
    assert "s3=FAIL" in log
    assert "cloudwatch=OK" in log
    assert "ec2=OK" in log
    # Cron-friendly: at least one call succeeded → exit 0
    assert exit_code == 0
    assert "summary ok=2/3" in log


def test_all_three_calls_failing_exits_nonzero(
    script: Any, monkeypatch: pytest.MonkeyPatch, aws_env: None
) -> None:
    monkeypatch.setenv("IAM_JIT_USAGE_BUCKET", "irrelevant")

    class _AlwaysFailClient:
        def __getattr__(self, _name: str) -> Any:
            def _raiser(*_a: Any, **_kw: Any) -> None:
                raise RuntimeError("synthetic failure")

            return _raiser

    class _AlwaysFailSession:
        region_name = "us-east-1"

        def get_credentials(self) -> Any:
            class _C:
                access_key = "x"

                def get_frozen_credentials(self) -> Any:
                    return self

            return _C()

        def client(self, *_a: Any, **_kw: Any) -> Any:
            return _AlwaysFailClient()

    monkeypatch.setattr(script, "_make_session", lambda: _AlwaysFailSession())

    exit_code = script.run()

    assert exit_code == 1
    log = _read_log(script)
    assert "s3=FAIL" in log
    assert "cloudwatch=FAIL" in log
    assert "ec2=FAIL" in log
    assert "summary ok=0/3" in log


# --------------------------------------------------------------------------- #
# Object-shape proof                                                          #
# --------------------------------------------------------------------------- #


def test_s3_object_key_and_body_shape(
    script: Any, monkeypatch: pytest.MonkeyPatch, aws_env: None
) -> None:
    bucket = "shape-test-bucket"
    monkeypatch.setenv("IAM_JIT_USAGE_BUCKET", bucket)

    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=bucket)

        assert script.run() == 0

        listing = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        assert len(listing) == 1
        key = listing[0]["Key"]
        assert key.startswith("usage-builder/")
        assert key.endswith(".txt")

        obj = s3.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read().decode("utf-8")
        assert "usage-builder-tick" in body
