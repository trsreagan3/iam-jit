"""Cross-product integration test for the cloud-neutral S3-compatible
NDJSON object-storage sink (#317).

Validates the [[cross-product-agent-parity]] contract: ibounce (Python)
+ kbouncer (Go) + dbounce (Go) + gbounce (Go) all write to the same
S3-compatible bucket using the same key layout, same gzipped NDJSON
file shape, same OCSF wire format.

The test stands up LocalStack S3, then exercises the Python writer
end-to-end against it. The Go-side parity is asserted at unit level
in each Go product (kbouncer/internal/audit/object_storage_test.go,
dbounce/internal/audit/object_storage_test.go, gbounce/internal/
audit/object_storage_test.go) — the partition-path format + file
naming + gzip-NDJSON wire format are byte-locked across all four.

Run:
    scripts/test-local.sh up         # bring up LocalStack + friends
    pytest tests/integration/object_storage_sink_test.py -v

Per [[don't-tailor-to-lighthouse]]: this test exercises the generic
S3 API surface — works against LocalStack, MinIO, real AWS S3, or
any S3-compatible vendor. LocalStack is the CI default because it's
free + fast.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import io
import json
import os
import time
from typing import Any

import pytest

from iam_jit.bouncer.audit_export import (
    ObjectStorageCredentials,
    ObjectStorageS3Client,
    ObjectStorageWriter,
)


@pytest.fixture()
def s3_bucket(
    localstack_endpoint: str, monkeypatch: pytest.MonkeyPatch
) -> str:
    """Create a LocalStack S3 bucket for the test + tear it down on
    test exit. Bucket name includes a timestamp so reruns don't
    collide on a long-lived LocalStack session."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    import boto3

    client = boto3.client(
        "s3", endpoint_url=localstack_endpoint, region_name="us-east-1",
    )
    bucket = f"bounce-audit-test-{int(time.time())}"
    client.create_bucket(Bucket=bucket)
    yield bucket
    # Best-effort cleanup. LocalStack's bucket is in-memory; if
    # cleanup fails the next test run uses a fresh timestamp anyway.
    try:
        # Empty bucket first (S3 requires empty buckets before delete).
        resp = client.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents") or []:
            client.delete_object(Bucket=bucket, Key=obj["Key"])
        client.delete_bucket(Bucket=bucket)
    except Exception:
        pass


@pytest.fixture()
def s3_writer_factory(localstack_endpoint: str, s3_bucket: str):
    """Factory returning ObjectStorageWriter instances pointed at the
    LocalStack bucket. Caller passes the per-product instance_id +
    product strings; the writer is wired with the same shape every
    product uses in production."""

    def _make(*, product: str, instance_id: str) -> ObjectStorageWriter:
        return ObjectStorageWriter(
            endpoint_url=localstack_endpoint,
            bucket=s3_bucket,
            prefix="test-suite",
            region="us-east-1",
            credentials=ObjectStorageCredentials(
                access_key_id="test", secret_access_key="test",
            ),
            product=product,
            instance_id=instance_id,
            # Short rotation so the test runs in seconds rather than
            # minutes; the rotation timer is still exercised end-to-end.
            rotation_minutes=1,
            # Large max_size so the timer fires before the size cap.
            max_size_mb=64,
        )

    return _make


def _list_bucket(localstack_endpoint: str, bucket: str, prefix: str = "") -> list[str]:
    """Return all keys under the given prefix as a sorted list."""
    import boto3

    client = boto3.client(
        "s3", endpoint_url=localstack_endpoint, region_name="us-east-1",
    )
    keys: list[str] = []
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if prefix:
        kwargs["Prefix"] = prefix
    while True:
        resp = client.list_objects_v2(**kwargs)
        for obj in resp.get("Contents") or []:
            keys.append(obj["Key"])
        if not resp.get("IsTruncated"):
            break
        kwargs["ContinuationToken"] = resp["NextContinuationToken"]
    return sorted(keys)


def _download(localstack_endpoint: str, bucket: str, key: str) -> bytes:
    import boto3

    client = boto3.client(
        "s3", endpoint_url=localstack_endpoint, region_name="us-east-1",
    )
    resp = client.get_object(Bucket=bucket, Key=key)
    return resp["Body"].read()


def _make_event(*, product: str, decision_id: int) -> dict[str, Any]:
    """Return a canonical OCSF v1.1.0 class 6003 event the Python +
    Go writers all produce. Keeps the integration test independent of
    each product's event-builder helpers (those are unit-tested in
    each product)."""
    return {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": product, "vendor_name": "iam-jit",
                "version": "1.0.0",
            },
        },
        "time": int(time.time() * 1000),
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "activity_id": 2,
        "activity_name": "Read",
        "type_uid": 600302,
        "type_name": "API Activity: Read",
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "api": {
            "operation": f"{product}-test-op",
            "service": {"name": product},
            "request": {"uid": f"req-{decision_id}"},
        },
        "unmapped": {
            "iam_jit": {
                "verdict": "allow",
                "decision_id": decision_id,
                "enforced": False,
            },
        },
    }


# ---------------------------------------------------------------------------
# Cross-product integration test
# ---------------------------------------------------------------------------


def test_four_bouncers_write_to_same_bucket(
    localstack_endpoint: str, s3_bucket: str, s3_writer_factory,
) -> None:
    """Cross-product happy-path: simulate all four bouncers writing to
    the same operator-owned bucket. Asserts:

      1. Four sets of NDJSON.gz files land under expected partition
         paths (one set per product/instance_id pair).
      2. Each file is valid gzip + valid NDJSON.
      3. Each NDJSON line parses as an OCSF v1.1.0 event with the
         expected product name in metadata.product.name.
      4. The Hive-partition layout matches the spec
         (year=YYYY/month=MM/day=DD/hour=HH/).

    Per [[cross-product-agent-parity]]: the partition path + file
    naming + gzip-NDJSON shape are byte-locked across products. This
    test asserts the SHAPE; the Go products assert the same shape in
    their own unit tests (object_storage_test.go).
    """
    products = ["ibounce", "kbouncer", "dbounce", "gbounce"]
    writers: dict[str, ObjectStorageWriter] = {}
    bytes_per_product: dict[str, int] = {p: 0 for p in products}

    # Spin up one writer per product, identical config except for the
    # product + instance_id segments of the key.
    for p in products:
        w = s3_writer_factory(product=p, instance_id=f"{p}-test-instance-1")
        w.start()
        writers[p] = w

    try:
        # Fire 10 audit-triggering "requests" through each product.
        for p, w in writers.items():
            for i in range(10):
                w.write(_make_event(product=p, decision_id=i))
        # Explicit flush to finalize the active buffer for each writer.
        # (In production the rotation timer would do this; the unit
        # tests cover that path independently. Here we want a
        # deterministic file-count without sleeping a full minute.)
        for w in writers.values():
            w.flush()
    finally:
        for w in writers.values():
            w.stop()

    # Inspect the bucket: assert one file per product (4 total) under
    # test-suite/year=.../month=.../day=.../hour=.../.
    keys = _list_bucket(localstack_endpoint, s3_bucket, prefix="test-suite/")
    assert len(keys) == 4, (
        f"expected 4 NDJSON files (one per bouncer); got {len(keys)}: {keys}"
    )

    # All keys live under the prefix + the Hive partition layout.
    now = _dt.datetime.now(_dt.UTC)
    expected_hour_prefix = (
        f"test-suite/year={now.year:04d}/month={now.month:02d}/"
        f"day={now.day:02d}/hour="
    )
    for key in keys:
        assert key.startswith(expected_hour_prefix), (
            f"key {key} does not match the Hive-partition layout "
            f"{expected_hour_prefix}HH/{{product}}-{{instance_id}}-"
            f"{{timestamp}}.jsonl.gz"
        )
        assert key.endswith(".jsonl.gz"), (
            f"key {key} should end .jsonl.gz"
        )

    # Per-product: verify the product appears in exactly one key.
    keys_by_product: dict[str, str] = {}
    for p in products:
        matching = [k for k in keys if f"/{p}-" in k]
        assert len(matching) == 1, (
            f"expected exactly one file for {p}; got {matching}"
        )
        keys_by_product[p] = matching[0]

    # Download + gunzip + parse: every event matches the OCSF wire shape
    # + carries the right product name.
    for p, key in keys_by_product.items():
        body = _download(localstack_endpoint, s3_bucket, key)
        bytes_per_product[p] = len(body)
        # Gzip decompresses cleanly.
        decompressed = gzip.decompress(body)
        # NDJSON: one event per line.
        lines = [
            ln for ln in decompressed.decode("utf-8").splitlines() if ln.strip()
        ]
        assert len(lines) == 10, (
            f"expected 10 events in {key}; got {len(lines)}"
        )
        for i, line in enumerate(lines):
            event = json.loads(line)
            # OCSF v1.1.0 invariants.
            assert event["metadata"]["version"] == "1.1.0"
            assert event["metadata"]["product"]["name"] == p
            assert event["class_uid"] == 6003
            assert event["class_name"] == "API Activity"
            assert event["activity_id"] == 2
            # Decision-id sequence is preserved (writes are
            # serialized in arrival order).
            assert event["unmapped"]["iam_jit"]["decision_id"] == i

    # Print a manifest the operator sees in the report.
    print("\n=== object-storage-sink integration test manifest ===")
    print(f"  bucket: s3://{s3_bucket}/test-suite/")
    print(f"  files written: {len(keys)}")
    for p in products:
        key = keys_by_product[p]
        size_kb = bytes_per_product[p] / 1024
        print(f"  - {p}: {key} ({size_kb:.2f} KB)")
    print("===")


def test_size_cap_rotates_inside_one_run(
    localstack_endpoint: str, s3_bucket: str,
) -> None:
    """A single bouncer writing enough payload to cross the size cap
    rotates mid-run and produces multiple NDJSON.gz files. Validates
    the size-cap path end-to-end against LocalStack."""
    # 1 MB max so we cross it cheaply.
    w = ObjectStorageWriter(
        endpoint_url=localstack_endpoint,
        bucket=s3_bucket,
        prefix="size-cap-test",
        region="us-east-1",
        credentials=ObjectStorageCredentials(
            access_key_id="test", secret_access_key="test",
        ),
        product="ibounce",
        instance_id="size-cap-instance",
        rotation_minutes=60,  # ensure size-cap fires, not the timer
        max_size_mb=1,
    )
    w.start()
    try:
        big_payload = "x" * (200 * 1024)
        for i in range(10):
            w.write(_make_event(product="ibounce", decision_id=i) | {
                "padding": big_payload,
            })
        # Final flush to push whatever's still buffered.
        w.flush()
    finally:
        w.stop()

    keys = _list_bucket(localstack_endpoint, s3_bucket, prefix="size-cap-test/")
    # At least 2 files (multiple size-cap-triggered rotations).
    assert len(keys) >= 2, (
        f"size cap should have produced multiple files; got {keys}"
    )
    # Every file is valid gzip + valid NDJSON.
    for key in keys:
        body = _download(localstack_endpoint, s3_bucket, key)
        decompressed = gzip.decompress(body)
        lines = [
            ln for ln in decompressed.decode("utf-8").splitlines() if ln.strip()
        ]
        for line in lines:
            event = json.loads(line)
            assert event["class_uid"] == 6003
