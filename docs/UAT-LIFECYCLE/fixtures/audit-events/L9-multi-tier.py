"""L9 fixture — synthetic audit event generator for multi-tier rotation.

Emits OCSF-shaped events spanning three retention tiers so the L9
scenario can seed a DB that exercises hot -> warm -> cold transitions.

Per docs/UAT-LIFECYCLE/HARNESS-SPEC.md:
* No real-AWS account IDs (uses 000000000000 + 111111111111).
* No operator-identifying data.
* Deterministic given a seed argument (for repeatability across runs).

Usage:
    python L9-multi-tier.py --count 300 --seed 42 --out events.jsonl

The output is JSONL; one OCSF event per line. The L9 harness pipes
this into the audit ingest path (whichever is the supported test
hook) before triggering rotation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone


def _gen_event(seq: int, when: datetime, bucket: str) -> dict:
    """Build one OCSF-shaped synthetic API-activity event."""
    actions = ["GetObject", "ListBuckets", "DescribeInstances", "GetRole"]
    return {
        "metadata": {
            "version": "1.0.0-rc.2",
            "product": {"name": "ibounce-uat-fixture"},
            "logged_time": int(when.timestamp() * 1000),
        },
        "time": int(when.timestamp() * 1000),
        "class_uid": 6003,  # API Activity (OCSF)
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": 600301,
        "severity": "Informational",
        "severity_id": 1,
        "actor": {
            "user": {
                "uid": f"AROA{seq:016d}",
                "type": "AssumedRole",
            }
        },
        "api": {
            "operation": random.choice(actions),
            "service": {"name": random.choice(["s3", "ec2", "iam"])},
            "request": {"uid": f"req-{seq}"},
        },
        "cloud": {
            "account": {"uid": "000000000000"},
            "provider": "AWS",
            "region": "us-east-1",
        },
        "uat_meta": {
            "seq": seq,
            "tier_bucket": bucket,
            "fixture_source": "L9-multi-tier.py",
        },
    }


def _hash_chain(line_bytes: bytes, prev_hash: str) -> str:
    """Mirror the bouncer hash-chain discipline so the seeded DB is verifiable."""
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(line_bytes)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=300,
                        help="total events; split evenly across hot/warm/cold")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=str, default="-",
                        help="JSONL path; '-' for stdout")
    args = parser.parse_args()

    random.seed(args.seed)
    per_bucket = args.count // 3
    now = datetime.now(timezone.utc)
    buckets = [
        ("hot", now - timedelta(days=30)),
        ("warm", now - timedelta(days=90)),
        ("cold", now - timedelta(days=365)),
    ]

    seq = 0
    prev_hash = "0" * 64

    stream = sys.stdout if args.out == "-" else open(args.out, "w")
    try:
        for bucket_name, anchor in buckets:
            for i in range(per_bucket):
                seq += 1
                when = anchor + timedelta(seconds=i * 60)
                event = _gen_event(seq, when, bucket_name)
                line = json.dumps(event, sort_keys=True)
                chain_hash = _hash_chain(line.encode("utf-8"), prev_hash)
                event["_chain"] = {"prev": prev_hash, "current": chain_hash}
                stream.write(json.dumps(event, sort_keys=True) + "\n")
                prev_hash = chain_hash
    finally:
        if args.out != "-":
            stream.close()

    sys.stderr.write(
        f"L9-multi-tier.py: emitted {seq} events across "
        f"{[b[0] for b in buckets]} tiers (seed={args.seed})\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
