#!/usr/bin/env python3
"""Nightly-dogfood orphan sweeper.

The companion workflow (`.github/workflows/dogfood-orphan-sweeper.yml`)
runs this every 4 hours. It queries the resource-groups-tagging-api
for resources tagged `Project=iam-jit-ci-nightly`, looks at the
per-resource `CreatedAt` tag, and deletes anything older than
6 hours.

Sweeper fires an alarm (non-zero exit + a stderr line the workflow
greps for) if it had to clean anything up — a per-run teardown
leaking is itself a bug we want to know about, even if the sweep
cleaned up the leak.

This script intentionally does NOT use `iam-jit remote revoke` —
the leaked resources may have been created by a CI run whose
iam-jit serve is long since gone. We talk to AWS directly.
"""

from __future__ import annotations

import datetime as _dt
import os
import sys
from typing import Iterable

PROJECT_TAG = "iam-jit-ci-nightly"
MAX_AGE_HOURS = 6


def _now_utc() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _parse_iso(s: str) -> _dt.datetime | None:
    """Robust ISO8601 parse — accepts `Z` suffix + naive strings."""
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        out = _dt.datetime.fromisoformat(s)
        if out.tzinfo is None:
            out = out.replace(tzinfo=_dt.timezone.utc)
        return out
    except Exception:
        return None


def _collect_orphans(rgt_client, project_tag: str) -> list[dict]:
    """Return every resource tagged with PROJECT_TAG along with its
    `CreatedAt` value (if any). One paginator pass."""
    found: list[dict] = []
    paginator = rgt_client.get_paginator("get_resources")
    for page in paginator.paginate(
        TagFilters=[{"Key": "Project", "Values": [project_tag]}],
        ResourcesPerPage=100,
    ):
        for r in page.get("ResourceTagMappingList", []):
            arn = r.get("ResourceARN")
            tags = {t["Key"]: t["Value"] for t in r.get("Tags", [])}
            if arn:
                found.append({"arn": arn, "tags": tags})
    return found


def _is_too_old(tags: dict, max_age_hours: int) -> bool:
    """True iff the tags carry a CreatedAt timestamp that's older
    than the threshold. If CreatedAt is missing OR unparseable, we
    err on the side of cleanup — a per-run teardown that DIDN'T tag
    is already a bug."""
    raw = tags.get("CreatedAt", "")
    parsed = _parse_iso(raw)
    if parsed is None:
        # Missing or unparseable → assume orphan
        return True
    age = _now_utc() - parsed
    return age >= _dt.timedelta(hours=max_age_hours)


def _delete_by_arn(arn: str, sess) -> tuple[bool, str]:
    """Delete a single resource ARN. Returns (ok, detail).

    Currently handles IAM roles (the only resource type the dogfood
    creates). We use ARN parsing to route to the right service
    client. Unknown resource types are reported but not deleted —
    the alarm still fires so a human can intervene.
    """
    try:
        # arn:aws:iam::<acct>:role/<name>
        parts = arn.split(":")
        if len(parts) < 6 or parts[2] != "iam":
            return False, f"unsupported resource: {arn}"
        resource = parts[5]
        if not resource.startswith("role/"):
            return False, f"unsupported iam resource: {resource}"
        role_name = resource.split("/", 1)[1]
        iam = sess.client("iam")
        # Detach managed
        try:
            attached = iam.list_attached_role_policies(RoleName=role_name)
            for p in attached.get("AttachedPolicies", []):
                try:
                    iam.detach_role_policy(
                        RoleName=role_name, PolicyArn=p["PolicyArn"])
                except Exception:
                    pass
        except Exception:
            pass
        # Inline
        try:
            inline = iam.list_role_policies(RoleName=role_name)
            for pn in inline.get("PolicyNames", []):
                try:
                    iam.delete_role_policy(
                        RoleName=role_name, PolicyName=pn)
                except Exception:
                    pass
        except Exception:
            pass
        # Instance profiles
        try:
            ips = iam.list_instance_profiles_for_role(RoleName=role_name)
            for ip in ips.get("InstanceProfiles", []):
                try:
                    iam.remove_role_from_instance_profile(
                        InstanceProfileName=ip["InstanceProfileName"],
                        RoleName=role_name,
                    )
                except Exception:
                    pass
        except Exception:
            pass
        iam.delete_role(RoleName=role_name)
        return True, "deleted"
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def main(argv: Iterable[str] | None = None) -> int:
    import boto3  # type: ignore

    region = (
        os.environ.get("AWS_DEFAULT_REGION")
        or os.environ.get("AWS_REGION")
        or "us-east-1"
    )
    project_tag = os.environ.get("IAM_JIT_CI_PROJECT_TAG", PROJECT_TAG)
    max_age = int(os.environ.get("IAM_JIT_CI_MAX_AGE_HOURS", str(MAX_AGE_HOURS)))

    sess = boto3.session.Session(region_name=region)
    rgt = sess.client("resourcegroupstaggingapi")

    print(f"# orphan sweep — project_tag={project_tag} "
          f"max_age_hours={max_age} region={region}")

    try:
        candidates = _collect_orphans(rgt, project_tag)
    except Exception as e:  # noqa: BLE001
        print(f"FATAL: tagging API error: {type(e).__name__}: {e}",
              file=sys.stderr)
        return 2

    print(f"# {len(candidates)} resource(s) tagged {project_tag} total")

    orphans = [c for c in candidates if _is_too_old(c["tags"], max_age)]
    if not orphans:
        print("# zero orphans found — sweep clean")
        return 0

    print(f"# ALARM: {len(orphans)} orphan(s) older than {max_age}h — "
          f"per-run teardown leaked, investigate")
    failed = 0
    for o in orphans:
        ok, detail = _delete_by_arn(o["arn"], sess)
        run_id = o["tags"].get("RunId", "<no-RunId>")
        created = o["tags"].get("CreatedAt", "<no-CreatedAt>")
        status = "DELETED" if ok else "FAILED"
        print(f"  [{status}] {o['arn']} RunId={run_id} "
              f"CreatedAt={created} detail={detail}")
        if not ok:
            failed += 1

    # Emit the alarm line that the workflow greps for. Non-zero exit
    # is the primary signal but the line is human-readable.
    print(f"ALARM: cleaned {len(orphans) - failed}/{len(orphans)} orphans; "
          f"{failed} failed",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
