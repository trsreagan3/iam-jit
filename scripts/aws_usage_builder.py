#!/usr/bin/env python3
"""aws_usage_builder.py - tiny daily AWS-usage maker.

Run this daily via cron to build usage + billing history on the operator's
AWS account so a future Bedrock model-access re-application lands against
a matured account. Per Amazon's 2026-05-19 denial-email guidance:

    "Continue to actively use other AWS services on your account to
     build Usage and billing history."

Each run touches three distinct AWS service categories:

  1. S3 PutObject — 1-byte file at  s3://$IAM_JIT_USAGE_BUCKET/usage-builder/YYYY-MM-DD.txt
  2. CloudWatch PutMetricData — namespace=iam-jit/usage-builder, metric=daily_tick, value=1
  3. EC2 DescribeRegions — read-only; free; counts as compute usage

Total cost: well under $1 / month at one tick per day.

This script is deliberately tiny + dumb + reliable:
  - Refuses to run without configured AWS creds  (clean error; no stack trace)
  - Refuses to run without IAM_JIT_USAGE_BUCKET   (clean error; setup hint)
  - Each of the 3 calls runs independently; a single failure does not abort
  - Exits 0 if any call succeeded; non-zero only when ALL 3 failed
    (so cron does not email on partial flake)
  - Appends one structured line per call to ~/.iam-jit/aws-usage-builder.log
  - The AWS account ID is NEVER hardcoded — boto3's default credential
    chain resolves identity (operator's account, not iam-jit's)

Per [[creates-never-mutates]]: read-only on the operator's machine outside
the log file + the 1-byte S3 object.

Per [[self-host-zero-billing-dependency]]: this talks only to the
operator's own AWS account. There is no phone-home to iam-jit.

Per [[don't-tailor-to-lighthouse]]: this is a generic-account warming
helper; nothing about it is customer-specific or account-specific.
"""

from __future__ import annotations

import datetime as _dt
import os
import sys
from pathlib import Path
from typing import Any


USAGE_BUCKET_ENV = "IAM_JIT_USAGE_BUCKET"
LOG_DIR = Path.home() / ".iam-jit"
LOG_PATH = LOG_DIR / "aws-usage-builder.log"
CW_NAMESPACE = "iam-jit/usage-builder"
CW_METRIC_NAME = "daily_tick"
CW_SOURCE_DIMENSION = "usage-builder"
S3_KEY_PREFIX = "usage-builder"


def _now_iso() -> str:
    """UTC timestamp as ISO-8601 with 'Z' suffix."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")


def _ensure_log_dir() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def _log(line: str) -> None:
    """Append one line to the log file; also echo to stdout for cron-mailing."""
    _ensure_log_dir()
    stamped = f"{_now_iso()} {line}"
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(stamped + "\n")
    print(stamped)


def _credentials_configured(session: Any) -> bool:
    """True iff boto3 can resolve credentials via its default chain."""
    creds = session.get_credentials()
    if creds is None:
        return False
    # frozen_credentials() forces a resolution attempt; raises if creds
    # are present but invalid. Treat any exception as not-configured.
    try:
        frozen = creds.get_frozen_credentials()
    except Exception:
        return False
    return bool(frozen and frozen.access_key)


def _put_s3_object(session: Any, bucket: str) -> bool:
    s3 = session.client("s3")
    key = f"{S3_KEY_PREFIX}/{_today_utc()}.txt"
    body = f"{_now_iso()} usage-builder-tick\n".encode("utf-8")
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=body)
    except Exception as exc:  # noqa: BLE001 - log + continue
        _log(f"s3=FAIL bucket={bucket} key={key} err={type(exc).__name__}: {exc}")
        return False
    _log(f"s3=OK bucket={bucket} key={key} bytes={len(body)}")
    return True


def _put_cloudwatch_metric(session: Any) -> bool:
    cw = session.client("cloudwatch")
    try:
        cw.put_metric_data(
            Namespace=CW_NAMESPACE,
            MetricData=[
                {
                    "MetricName": CW_METRIC_NAME,
                    "Dimensions": [{"Name": "Source", "Value": CW_SOURCE_DIMENSION}],
                    "Value": 1,
                    "Unit": "Count",
                }
            ],
        )
    except Exception as exc:  # noqa: BLE001
        _log(f"cloudwatch=FAIL namespace={CW_NAMESPACE} err={type(exc).__name__}: {exc}")
        return False
    _log(f"cloudwatch=OK namespace={CW_NAMESPACE} metric={CW_METRIC_NAME} value=1")
    return True


def _describe_ec2_regions(session: Any) -> bool:
    ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
    try:
        resp = ec2.describe_regions()
    except Exception as exc:  # noqa: BLE001
        _log(f"ec2=FAIL op=describe_regions err={type(exc).__name__}: {exc}")
        return False
    count = len(resp.get("Regions", []))
    _log(f"ec2=OK op=describe_regions regions={count}")
    return True


def _make_session() -> Any:
    """Built lazily so tests can monkeypatch boto3 / env before invocation."""
    import boto3  # local import keeps the module importable without boto3

    return boto3.session.Session()


def run(session: Any | None = None) -> int:
    """Execute one tick. Return process exit code."""
    bucket = os.environ.get(USAGE_BUCKET_ENV, "").strip()
    if not bucket:
        _log(
            f"abort=missing-env var={USAGE_BUCKET_ENV} "
            f"hint=set to a private S3 bucket you own, e.g. "
            f"`export {USAGE_BUCKET_ENV}=my-usage-builder-bucket`"
        )
        return 2

    if session is None:
        try:
            session = _make_session()
        except Exception as exc:  # noqa: BLE001 - boto3 import or session init failed
            _log(f"abort=session-init err={type(exc).__name__}: {exc}")
            return 3

    if not _credentials_configured(session):
        _log(
            "abort=missing-credentials "
            "hint=run `aws configure --profile iam-jit-usage` then "
            "`export AWS_PROFILE=iam-jit-usage` before the cron entry"
        )
        return 4

    results = [
        _put_s3_object(session, bucket),
        _put_cloudwatch_metric(session),
        _describe_ec2_regions(session),
    ]

    succeeded = sum(1 for r in results if r)
    total = len(results)
    _log(f"summary ok={succeeded}/{total}")

    # Cron-friendly: only emit non-zero if EVERY call failed
    return 0 if succeeded > 0 else 1


def main(argv: list[str] | None = None) -> int:  # noqa: ARG001 - argv reserved
    return run()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
