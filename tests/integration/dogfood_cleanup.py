"""Cleanup helpers shared by the nightly dogfood (see
docs/CI-NIGHTLY-DOGFOOD.md → "Cleanup contract").

The dogfood script wraps every stack in `try / finally`. The finally
block calls into here to:

  1. Revoke the iam-jit request via `iam-jit remote revoke` (exercises
     the MED-2 CLI path — F18). Falls back to raw boto3 IAM teardown
     if revoke fails so a broken revoke never leaks a real role.

  2. Kill any local processes (ibounce / gbounce / iam-jit serve)
     spun up for the run. Idempotent — safe to call multiple times.

  3. Verify zero AWS resources remain tagged with this run's
     `Project=iam-jit-ci-nightly` + `RunId=<id>` (F19). Uses the
     resource-groups-tagging-api which covers every taggable AWS
     service in one call.

Nothing here logs to stdout — the caller owns the PASS/FAIL line
format so the F1-F19 checklist stays uniform.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Iterable


@dataclass
class _RevokeOutcome:
    ok: bool
    via: str           # "revoke-cli" | "boto3-fallback" | "no-op"
    detail: str = ""   # human-readable note for the script's log


def revoke_request(
    *,
    request_id: str,
    reason: str,
    iam_jit_bin: str,
    iam_jit_url: str,
    iam_jit_token: str,
    fallback_role_name: str | None = None,
    aws_profile: str | None = None,
    aws_region: str | None = None,
    timeout_s: float = 30.0,
) -> _RevokeOutcome:
    """Revoke an iam-jit request, with a raw-boto3 fallback.

    First path is the CLI (`iam-jit remote revoke <id> --reason ...`)
    so we exercise the MED-2 surface in CI on every run. If the CLI
    bails out (network, server down, regression), we fall back to
    direct `iam:DeleteRolePolicy` + `iam:DeleteRole` against the
    provisioned role name to ensure we never leak real AWS state.

    Returns a `_RevokeOutcome` so the caller can log + decide whether
    to fail the run (a fallback-fired event still counts as a CI
    failure under F18, even though no AWS state leaked).
    """
    env = dict(os.environ)
    env["IAM_JIT_URL"] = iam_jit_url
    env["IAM_JIT_TOKEN"] = iam_jit_token
    cmd = [
        iam_jit_bin, "remote", "revoke", request_id,
        "--reason", reason,
    ]
    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True,
            timeout=timeout_s,
        )
        if proc.returncode == 0:
            return _RevokeOutcome(ok=True, via="revoke-cli")
        cli_err = (proc.stderr or proc.stdout or "").strip()[:400]
    except subprocess.TimeoutExpired:
        cli_err = "timeout"
    except FileNotFoundError as e:
        cli_err = f"binary missing: {e}"
    except Exception as e:  # noqa: BLE001 — we want every error path swept
        cli_err = f"unexpected: {type(e).__name__}: {e}"

    # Fallback: raw boto3 IAM teardown if we know the role name.
    if not fallback_role_name:
        return _RevokeOutcome(
            ok=False, via="no-op",
            detail=f"revoke-cli failed ({cli_err}); no fallback role name",
        )
    try:
        import boto3  # type: ignore

        sess_kw: dict[str, str] = {}
        if aws_profile:
            sess_kw["profile_name"] = aws_profile
        if aws_region:
            sess_kw["region_name"] = aws_region
        sess = boto3.session.Session(**sess_kw)
        iam = sess.client("iam")
        _force_delete_role(iam, fallback_role_name)
        return _RevokeOutcome(
            ok=False, via="boto3-fallback",
            detail=(
                f"revoke-cli failed ({cli_err}); boto3 deleted "
                f"{fallback_role_name} as fallback"
            ),
        )
    except Exception as e:  # noqa: BLE001
        return _RevokeOutcome(
            ok=False, via="no-op",
            detail=(
                f"revoke-cli failed ({cli_err}); "
                f"boto3 fallback also failed: {type(e).__name__}: {e}"
            ),
        )


def _force_delete_role(iam_client, role_name: str) -> None:
    """Best-effort tear-down of a role + all its inline + attached
    policies. Matches what `iam-jit remote revoke` does server-side
    so the fallback leaves the same end-state."""
    # Detach managed policies first
    try:
        attached = iam_client.list_attached_role_policies(RoleName=role_name)
        for p in attached.get("AttachedPolicies", []):
            try:
                iam_client.detach_role_policy(
                    RoleName=role_name, PolicyArn=p["PolicyArn"])
            except Exception:
                pass
    except iam_client.exceptions.NoSuchEntityException:
        return
    except Exception:
        pass
    # Delete inline policies
    try:
        inline = iam_client.list_role_policies(RoleName=role_name)
        for pn in inline.get("PolicyNames", []):
            try:
                iam_client.delete_role_policy(
                    RoleName=role_name, PolicyName=pn)
            except Exception:
                pass
    except Exception:
        pass
    # Delete instance profiles
    try:
        ips = iam_client.list_instance_profiles_for_role(RoleName=role_name)
        for ip in ips.get("InstanceProfiles", []):
            try:
                iam_client.remove_role_from_instance_profile(
                    InstanceProfileName=ip["InstanceProfileName"],
                    RoleName=role_name,
                )
            except Exception:
                pass
    except Exception:
        pass
    # Finally delete the role
    try:
        iam_client.delete_role(RoleName=role_name)
    except iam_client.exceptions.NoSuchEntityException:
        pass


def verify_no_orphans(
    *,
    run_id: str,
    project_tag: str = "iam-jit-ci-nightly",
    aws_profile: str | None = None,
    aws_region: str | None = None,
) -> list[str]:
    """Query the resource-groups-tagging-api for any taggable AWS
    resource carrying BOTH the project tag and this run's RunId.

    Returns the list of ARNs that should not be there. Empty list
    means clean. The caller treats non-empty as F19 fail.

    The tagging API is the right surface here because it spans every
    taggable AWS service — IAM, S3, EC2, Lambda, API Gateway, etc.
    — in a single call. We don't have to enumerate per-service.
    """
    import boto3  # type: ignore

    sess_kw: dict[str, str] = {}
    if aws_profile:
        sess_kw["profile_name"] = aws_profile
    if aws_region:
        sess_kw["region_name"] = aws_region
    sess = boto3.session.Session(**sess_kw)
    rgt = sess.client("resourcegroupstaggingapi")

    # NOTE: GetResources matches resources with ALL specified tag
    # filters (AND semantics). We pass both keys to scope to THIS
    # run id — the orphan sweeper (separate workflow) does broader
    # age-based cleanup using just the project tag.
    leaked: list[str] = []
    paginator = rgt.get_paginator("get_resources")
    for page in paginator.paginate(
        TagFilters=[
            {"Key": "Project", "Values": [project_tag]},
            {"Key": "RunId", "Values": [run_id]},
        ],
        ResourcesPerPage=100,
    ):
        for r in page.get("ResourceTagMappingList", []):
            arn = r.get("ResourceARN")
            if arn:
                leaked.append(arn)
    return leaked


def kill_local_processes(pids: Iterable[int]) -> list[int]:
    """Kill the listed PIDs (ibounce / gbounce / serve started by
    the dogfood script). Returns the PIDs that were actually
    delivered SIGTERM (vs already-dead).

    Two-phase: SIGTERM, wait 2s, SIGKILL on holdouts. Never raises
    — finally-block code must not throw.
    """
    delivered: list[int] = []
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            delivered.append(pid)
        except ProcessLookupError:
            # already dead — fine
            continue
        except Exception:
            # permission denied / race / etc — log via return value
            continue
    if not delivered:
        return delivered
    time.sleep(2.0)
    for pid in list(delivered):
        try:
            os.kill(pid, 0)  # liveness probe
        except ProcessLookupError:
            continue
        # still alive after SIGTERM — escalate
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    return delivered
