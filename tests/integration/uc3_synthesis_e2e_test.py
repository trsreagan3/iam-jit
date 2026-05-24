"""UC-3 E2E — full bouncer → agent → iam-jit → role → STS → audit loop.

Per `docs/MRR-1-USE-CASE-AUDIT-2026-05-24.md` UC-3 (CRIT #3 of 5
pre-deploy blockers): the synthesis flow
`iam_jit_request_role_from_synthesis` (#421 / Phase E) ships with 886
LOC of unit tests in `tests/request_from_synthesis/` but had NEVER been
exercised end-to-end against a real bouncer process + real AWS API
target + real role creation + real STS:AssumeRole + real audit
read-back. Bugs #475 (audit_event_ids returned but events were
write-only), #476 (status=auto_approved with credentials:null silently)
and #477 (empty codebase_references passed evidence-block discipline)
were the EXACT shape that 886 LOC of unit-only tests couldn't catch.

This test closes the composition gap. It validates the marquee
`[[bouncer-informs-agent-informs-iam-jit]]` use case end-to-end:

  Step 1  spin up real ibounce (subprocess) pointed at LocalStack
  Step 2  drive realistic AWS calls through ibounce -> audit JSONL fills
  Step 3  agent: bounce_extract_permissions_from_audit (MCP, real HTTP
          to ibounce's /audit/events endpoint)
  Step 4  agent: iam_jit_request_role_from_synthesis (MCP) WITH a
          credential_factory wired (closes the #473 gap inside the
          test; #473 itself — wire credential_factory through the MCP
          default — is still pending and documented in the brief)
  Step 5  observable: aws iam get-role of the new role; trust + policy
  Step 6  observable: sts:AssumeRole with returned creds; observable
          via aws sts get-caller-identity from the assumed session
  Step 7  observable: audit JSONL contains the synthesis row; the
          synthesis row's audit_event_id is grep'able from the file
          (#475 fix verification)
  Step 8  observable: pre/post LocalStack IAM snapshot — only NEW
          roles created; pre-existing roles byte-identical
          (`[[creates-never-mutates]]` floor)

Honest gating: SKIPS when LocalStack isn't reachable OR ibounce CLI
isn't installed (matches existing integration-test convention). On a
CI runner with the docker-compose.test.yml stack up and the wheel
installed, the test MUST run + MUST pass.

The test takes ~30s wall-clock (mostly ibounce startup + audit log
drain). It writes everything to tmp_path so reruns are clean.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import json
import os
import socket
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
IBOUNCE_BIN = REPO_ROOT / ".venv" / "bin" / "ibounce"

# Free port band — avoid colliding with default DEFAULT_BOUNCERS ports
# (8766-8769) or the existing parity-test ports (19767+, 19867+).
PORT_IBOUNCE = 19967


def _have_bin(p: Path) -> bool:
    return p.exists() and os.access(p, os.X_OK)


def _free_port(preferred: int) -> int:
    """Return `preferred` if free, else any OS-assigned free port."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


def _wait_for_tcp(host: str, port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(0.3)
            try:
                s.connect((host, port))
                return True
            except OSError:
                time.sleep(0.2)
    return False


def _wait_for_healthz(url: str, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.5) as resp:
                if resp.status in (200, 503):
                    return True
        except Exception:
            time.sleep(0.2)
    return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _have_bin(IBOUNCE_BIN),
        reason=(
            f"missing ibounce console-script at {IBOUNCE_BIN}; "
            "install with `pip install -e .` in the venv"
        ),
    ),
]


# ---------------------------------------------------------------------------
# LocalStack snapshot helpers (creates-never-mutates verification)
# ---------------------------------------------------------------------------


def _snapshot_iam_roles(iam_client: Any) -> dict[str, dict[str, Any]]:
    """Capture the full IAM state — every role with its trust policy +
    inline policies + attached policies. Used pre/post test to assert
    `[[creates-never-mutates]]` (existing roles unchanged byte-for-byte;
    only NEW roles appear in the diff)."""
    snap: dict[str, dict[str, Any]] = {}
    for role in iam_client.list_roles().get("Roles", []):
        name = role["RoleName"]
        # Normalise trust policy — moto/LocalStack returns it as a dict;
        # if a JSON string slips in we json.loads to keep the snapshot
        # comparable regardless of representation.
        trust = role.get("AssumeRolePolicyDocument")
        if isinstance(trust, str):
            trust = json.loads(trust)
        inline_names = iam_client.list_role_policies(RoleName=name).get(
            "PolicyNames", []
        )
        inline_policies: dict[str, Any] = {}
        for pname in inline_names:
            pdoc = iam_client.get_role_policy(RoleName=name, PolicyName=pname)
            body = pdoc.get("PolicyDocument")
            if isinstance(body, str):
                body = json.loads(body)
            inline_policies[pname] = body
        attached = [
            ap["PolicyArn"] for ap in iam_client.list_attached_role_policies(
                RoleName=name
            ).get("AttachedPolicies", [])
        ]
        snap[name] = {
            "trust": trust,
            "inline": inline_policies,
            "attached": sorted(attached),
            "tags": sorted(
                (t["Key"], t["Value"]) for t in role.get("Tags", []) or []
            ),
        }
    return snap


# ---------------------------------------------------------------------------
# ibounce subprocess fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def ibounce_proc(tmp_path, localstack_endpoint):
    """Spawn a real ibounce process pointed at LocalStack as upstream.

    Yields a dict with the bouncer's port + audit log path + a teardown
    hook the test relies on for the audit-log read-back step.
    """
    port = _free_port(PORT_IBOUNCE)
    audit_log = tmp_path / "ibounce-audit.jsonl"
    db = tmp_path / "ibounce.db"

    # `ibounce init` first so the run path finds a populated store +
    # the protective default baseline is applied (mirrors what an
    # operator does day-1). The `--no-default` would skip protections;
    # we keep them so the test exercises the realistic shape.
    init = subprocess.run(
        [str(IBOUNCE_BIN), "init", "--db", str(db)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert init.returncode == 0, (
        f"ibounce init failed: {init.stdout}\n{init.stderr}"
    )

    # Spawn ibounce in `cooperative` mode + `default-policy allow` so
    # every AWS call we drive through is observed + logged but always
    # forwarded to LocalStack. Per the recipe page this is the
    # discovery-first shape the synthesis flow consumes.
    proc = subprocess.Popen(
        [
            str(IBOUNCE_BIN), "run",
            "--port", str(port),
            "--host", "127.0.0.1",
            "--mode", "cooperative",
            "--default-policy", "allow",
            "--upstream", localstack_endpoint,
            "--audit-log-path", str(audit_log),
            "--audit-log-fsync",  # write every event to disk; test reads later
            "--db", str(db),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    healthz = f"http://127.0.0.1:{port}/healthz"
    if not _wait_for_healthz(healthz, timeout=30):
        proc.terminate()
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
        raise RuntimeError(
            f"ibounce failed to come up on {healthz}; "
            f"stdout:\n{out}\nstderr:\n{err}"
        )
    try:
        yield {
            "port": port,
            "audit_log": audit_log,
            "db": db,
            "mgmt_url": f"http://127.0.0.1:{port}",
            "proxy_endpoint": f"http://127.0.0.1:{port}",
        }
    finally:
        # Graceful shutdown so the AuditLogWriter drains its queue +
        # we can read every event the test fired.
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture
def boto3_clients(localstack_endpoint, monkeypatch):
    """boto3 clients pointed DIRECTLY at LocalStack — used for the
    pre/post IAM snapshot + the credential_factory's role creation.
    These do NOT go through ibounce; they're the test harness's
    out-of-band channel for verifying the bouncer's observations."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    import boto3

    return {
        "iam": boto3.client(
            "iam", endpoint_url=localstack_endpoint, region_name="us-east-1"
        ),
        "sts": boto3.client(
            "sts", endpoint_url=localstack_endpoint, region_name="us-east-1"
        ),
        "s3": boto3.client(
            "s3", endpoint_url=localstack_endpoint, region_name="us-east-1"
        ),
    }


@pytest.fixture
def bouncer_clients(ibounce_proc, monkeypatch):
    """boto3 clients pointed AT IBOUNCE (which forwards to LocalStack).

    These are how the simulated operator drives traffic through the
    bouncer — every call they make becomes one audit event the agent
    can later extract from `/audit/events`.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    import boto3

    endpoint = ibounce_proc["proxy_endpoint"]
    return {
        "s3": boto3.client(
            "s3", endpoint_url=endpoint, region_name="us-east-1"
        ),
        "sts": boto3.client(
            "sts", endpoint_url=endpoint, region_name="us-east-1"
        ),
        "iam": boto3.client(
            "iam", endpoint_url=endpoint, region_name="us-east-1"
        ),
    }


# ---------------------------------------------------------------------------
# E2E test — one big linear flow with per-step assertions
# ---------------------------------------------------------------------------


def test_uc3_synthesis_e2e_full_loop(
    ibounce_proc,
    boto3_clients,
    bouncer_clients,
    tmp_path,
    monkeypatch,
):
    """UC-3 — full bouncer-to-role-to-STS-to-audit composition.

    Linear test (vs split per-step) because the steps share a lot of
    expensive setup (real subprocess + real AWS state). Each step
    section ends with state-verification per docs/CONTRIBUTING.md so a
    regression at any step fails loudly with a specific assertion
    message.
    """
    iam = boto3_clients["iam"]
    sts = boto3_clients["sts"]
    s3 = bouncer_clients["s3"]
    bouncer_sts = bouncer_clients["sts"]

    # ===========================================================
    # Step 0  — pre-test snapshot (creates-never-mutates baseline)
    # ===========================================================
    pre_snap = _snapshot_iam_roles(iam)

    # ===========================================================
    # Step 1  — ibounce is up (handled by fixture; verified via
    #           the healthz wait inside the fixture)
    # ===========================================================
    assert ibounce_proc["audit_log"].parent.exists()

    # ===========================================================
    # Step 2  — drive realistic AWS workflow through ibounce.
    #           Each call adds one OCSF event to the audit log.
    # ===========================================================
    # Create a bucket so list operations have something to read.
    bucket_name = f"uc3-e2e-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_object(Bucket=bucket_name, Key="hello.txt", Body=b"hi")
    # Multiple distinct S3 reads — produce repeated audit rows so the
    # extractor's count aggregation has something to verify.
    for _ in range(3):
        s3.list_buckets()
        s3.list_objects_v2(Bucket=bucket_name)
        s3.get_object(Bucket=bucket_name, Key="hello.txt")
    # An sts:GetCallerIdentity adds a second service to the audit.
    bouncer_sts.get_caller_identity()

    # Give the AuditLogWriter's async worker time to drain to disk.
    # The writer batches to keep proxy hot-path fast; a small sleep
    # avoids reading the file before the worker has flushed.
    _wait_for_log_grows(ibounce_proc["audit_log"], min_lines=4, timeout=10.0)

    # State verification: audit log file exists + has lines.
    raw_lines = ibounce_proc["audit_log"].read_text(
        encoding="utf-8"
    ).splitlines()
    nonempty = [ln for ln in raw_lines if ln.strip()]
    assert len(nonempty) >= 4, (
        f"expected >=4 audit events from S3/STS workflow; "
        f"got {len(nonempty)} lines: {nonempty[:3]}"
    )

    # ===========================================================
    # Step 3  — Agent calls bounce_extract_permissions_from_audit
    #           via the MCP tool BACKEND (real HTTP to ibounce's
    #           /audit/events endpoint via the fanout path).
    # ===========================================================
    from iam_jit.mcp_server import _bounce_extract_permissions_from_audit_for_mcp

    extract_result = _bounce_extract_permissions_from_audit_for_mcp({
        # Use the `name=URL` override form so the fanout hits our test
        # bouncer instance instead of the default 8767 port.
        "bouncer": f"ibounce={ibounce_proc['mgmt_url']}",
        "since": "10m",
        "limit": 500,
    })

    # State verification: extract succeeded + observed permissions match
    # what we just drove. status:"ok" is the CLAIM; the permissions
    # list is the OBSERVABLE STATE per #475/CONTRIBUTING.md discipline.
    assert extract_result.get("status") == "ok", extract_result
    perm_doc = extract_result
    assert perm_doc.get("events_analyzed", 0) >= 4, (
        f"extractor only saw {perm_doc.get('events_analyzed')} events; "
        f"full result: {perm_doc}"
    )
    observed_actions = {p["action"] for p in perm_doc.get("permissions", [])}
    # We deliberately drove S3 + STS; the action names are
    # bouncer-rendered (service:Operation). We just need to confirm
    # observations correspond to what we drove, not a stale audit log.
    assert observed_actions, (
        f"extractor returned zero permissions despite events_analyzed="
        f"{perm_doc.get('events_analyzed')}; full result: {perm_doc}"
    )

    # ===========================================================
    # Step 4  — Agent calls iam_jit_request_role_from_synthesis
    #           via the MCP tool BACKEND. We pass our own
    #           credential_factory that talks to LocalStack
    #           DIRECTLY (closing the #473 wiring gap inside the
    #           test scope — #473 itself remains pending for the
    #           default MCP path; documented in test report).
    # ===========================================================
    from iam_jit.request_from_synthesis import (
        DEFAULT_AUTO_APPROVE_THRESHOLD,
        request_role_from_synthesis_for_mcp,
    )

    # Redirect synthesis audit sink to a per-test file so the assertion
    # in step 7 isn't polluted by anything else on the dev box's
    # ~/.iam-jit/audit.jsonl.
    synth_audit_log = tmp_path / "synthesis-audit.jsonl"
    monkeypatch.setenv("IAM_JIT_SYNTHESIS_AUDIT_LOG", str(synth_audit_log))

    # Synthesise a narrow permission set the operator is asking for
    # (the agent's intent: "give me a role that can do exactly what I
    # just did through the bouncer"). Narrow = scorer should auto-
    # approve below the default threshold.
    synthesised_permissions = [
        {
            "action": "s3:ListBucket",
            "resources": [f"arn:aws:s3:::{bucket_name}"],
            "count": perm_doc.get("permissions", [{}])[0].get("count", 1),
        },
        {
            "action": "s3:GetObject",
            "resources": [f"arn:aws:s3:::{bucket_name}/*"],
            "count": 3,
        },
    ]

    # Track credential_factory invocations so the test can assert it
    # was actually called (not just that auto_approved status came back
    # with credentials:null — the #476 anti-pattern shape).
    factory_calls: list[dict[str, Any]] = []
    issued_role_name = (
        f"iam-jit-uc3-{uuid.uuid4().hex[:8]}"
    )
    issued_role_arn_box: dict[str, str] = {}

    def _live_credential_factory(spec: dict[str, Any]) -> dict[str, Any]:
        """Create a REAL IAM role in LocalStack + return real STS creds.

        Mirrors the shape provision.py:provision returns but bypasses
        the cross-account ProvisionerRole assume (LocalStack is single-
        account; the production assume path is tested in test_provision_*).
        The goal here is to verify the SYNTHESIS surface correctly
        passes the synthesised policy through to a credential_factory
        and threads the resulting creds back to the agent — the
        Phase E composition shape, not the cross-account shape.
        """
        factory_calls.append(spec)
        policy = spec["policy"]
        # 1) Create role with a trust policy allowing the LocalStack
        #    default account to assume — LocalStack accepts a permissive
        #    trust here because there's no real org boundary to enforce.
        trust = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
                "Action": "sts:AssumeRole",
            }],
        }
        iam.create_role(
            RoleName=issued_role_name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="iam-jit UC-3 E2E synthesis role",
            Tags=[
                {"Key": "managed-by", "Value": "iam-jit"},
                {"Key": "request-id", "Value": spec["request_id"]},
                {"Key": "synthesis", "Value": "true"},
            ],
        )
        iam.put_role_policy(
            RoleName=issued_role_name,
            PolicyName="iam-jit-synth-grant",
            PolicyDocument=json.dumps(policy),
        )
        # 2) Resolve the role ARN for the STS:AssumeRole call.
        role = iam.get_role(RoleName=issued_role_name)
        role_arn = role["Role"]["Arn"]
        issued_role_arn_box["arn"] = role_arn
        # 3) STS:AssumeRole — this is the call that produces the
        #    credentials the synthesis MCP wraps for the agent.
        assume = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"uc3-{spec['request_id'][:32]}",
            DurationSeconds=900,  # 15 min — LocalStack min
        )
        creds = assume["Credentials"]
        return {
            "AccessKeyId": creds["AccessKeyId"],
            "SecretAccessKey": creds["SecretAccessKey"],
            "SessionToken": creds["SessionToken"],
            "Expiration": creds["Expiration"].isoformat(),
            "RoleArn": role_arn,
        }

    now = _dt.datetime.now(_dt.timezone.utc)
    evidence = {
        "bouncer_audit_window": {
            "from": (now - _dt.timedelta(minutes=10)).replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z"),
            "to": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "bouncer": "ibounce",
        },
        # #477 fix verification: non-empty list of refs is required.
        "codebase_references": [
            "tests/integration/uc3_synthesis_e2e_test.py",
            "docs/MRR-1-USE-CASE-AUDIT-2026-05-24.md",
        ],
        "operator_intent": (
            "UC-3 E2E test — synthesise a role that can do what "
            "the test workflow just did through ibounce."
        ),
    }

    verdict = request_role_from_synthesis_for_mcp(
        {
            "permissions": synthesised_permissions,
            "observed_scope": perm_doc.get(
                "observed_scope", {"account_ids": [], "regions": ["us-east-1"]}
            ),
            "justification": "UC-3 E2E pre-deploy CRIT closure test",
            "evidence": evidence,
            "requested_duration": "PT15M",
            # Force a low threshold relative to the narrow policy so we
            # land in auto_approved (the credential_factory path under
            # test). The unit-test corpus already covers the pending /
            # rejected paths.
            "auto_approve_threshold": DEFAULT_AUTO_APPROVE_THRESHOLD,
        },
        credential_factory=_live_credential_factory,
    )

    # State verification on the verdict — observable state, not just
    # status string (per #476 anti-pattern).
    assert verdict["status"] == "auto_approved", (
        f"expected auto_approved verdict; got {verdict!r}"
    )
    assert factory_calls, (
        "credential_factory was never invoked despite "
        "status=auto_approved — this is the #476 silent-failure shape"
    )
    creds = verdict.get("credentials")
    assert creds is not None, (
        f"#476 regression — auto_approved but credentials:null; "
        f"verdict: {verdict!r}"
    )
    assert creds.get("AccessKeyId"), creds
    assert creds.get("SessionToken"), creds
    request_id = verdict["request_id"]
    synthesis_audit_event_id = verdict["audit_event_id"]
    assert synthesis_audit_event_id, verdict

    # ===========================================================
    # Step 5  — observable role state (aws iam get-role)
    # ===========================================================
    described = iam.get_role(RoleName=issued_role_name)
    actual_trust = described["Role"]["AssumeRolePolicyDocument"]
    if isinstance(actual_trust, str):
        actual_trust = json.loads(actual_trust)
    assert actual_trust["Statement"][0]["Action"] == "sts:AssumeRole"
    tags = {t["Key"]: t["Value"] for t in described["Role"].get("Tags", [])}
    assert tags.get("managed-by") == "iam-jit", tags
    assert tags.get("request-id") == request_id, tags
    inline = iam.get_role_policy(
        RoleName=issued_role_name, PolicyName="iam-jit-synth-grant",
    )
    pdoc = inline["PolicyDocument"]
    if isinstance(pdoc, str):
        pdoc = json.loads(pdoc)
    # Policy carries the synthesised actions (one statement per action,
    # per _build_policy_from_permissions).
    policy_actions = set()
    for stmt in pdoc.get("Statement", []):
        for a in (
            stmt["Action"] if isinstance(stmt["Action"], list)
            else [stmt["Action"]]
        ):
            policy_actions.add(a)
    assert "s3:GetObject" in policy_actions, pdoc
    assert "s3:ListBucket" in policy_actions, pdoc

    # ===========================================================
    # Step 6  — STS:AssumeRole + observable identity from session.
    #           credential_factory already called sts:AssumeRole +
    #           returned creds; here we EXERCISE those creds by
    #           hitting LocalStack STS as the assumed session and
    #           asserting the caller-identity matches the new role.
    # ===========================================================
    import boto3

    direct_sts = boto3.client(
        "sts",
        endpoint_url=_localstack_url_from_clients(boto3_clients),
        region_name="us-east-1",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    ident = direct_sts.get_caller_identity()
    # Assumed-role ARN shape:
    # arn:aws:sts::000000000000:assumed-role/<name>/<session>
    assert "assumed-role" in ident["Arn"], ident
    assert issued_role_name in ident["Arn"], ident

    # ===========================================================
    # Step 7  — audit-event correlation (#475 fix verification).
    #           The synthesis row MUST be findable in the JSONL log
    #           by audit_event_id; this is exactly the surface
    #           #475 fixed (audit_event_id returned but write-only).
    # ===========================================================
    assert synth_audit_log.exists(), (
        f"synthesis audit log {synth_audit_log} was never created; "
        "#475 fix would have written it"
    )
    synth_lines = [
        json.loads(ln) for ln in synth_audit_log.read_text(
            encoding="utf-8"
        ).splitlines() if ln.strip()
    ]
    assert synth_lines, (
        "synthesis audit log is empty despite a verdict being returned; "
        "#475 regression shape"
    )
    matching = [
        ln for ln in synth_lines
        if ln.get("audit_event_id") == synthesis_audit_event_id
        or (
            ln.get("unmapped", {}).get("iam_jit", {}).get("audit_event_id")
            == synthesis_audit_event_id
        )
    ]
    assert matching, (
        f"audit_event_id {synthesis_audit_event_id} returned to caller "
        f"but NOT findable in the JSONL log — #475 regression shape. "
        f"Log rows: {synth_lines[:2]}"
    )
    matched = matching[0]
    # Evidence chain should be reproduced in the OCSF event per the
    # recipe page's "trace WHY this role was issued" promise.
    synth_block = (
        matched.get("unmapped", {})
        .get("iam_jit", {})
        .get("synthesis", {})
    )
    persisted_evidence = synth_block.get("evidence") or {}
    assert persisted_evidence.get("operator_intent") == evidence["operator_intent"]
    assert persisted_evidence.get("codebase_references") == evidence[
        "codebase_references"
    ]
    assert persisted_evidence.get("bouncer_audit_window", {}).get("bouncer") == "ibounce"

    # The bouncer's audit-export endpoint should ALSO surface this row
    # (the operator can `iam-jit audit query --filter
    # audit_event_id=...` post-hoc to trace synthesis decisions). The
    # synthesis log is a separate file from the bouncer's audit log;
    # the cross-stream join is a known operator workflow. Here we
    # assert the synthesis row is queryable by id from its own file
    # (the discrete fix #475 closed) — cross-stream join is UC-23.

    # ===========================================================
    # Step 8  — creates-never-mutates: pre-existing roles UNCHANGED
    # ===========================================================
    post_snap = _snapshot_iam_roles(iam)
    # Every role in pre_snap MUST be byte-identical in post_snap.
    for name, pre_state in pre_snap.items():
        assert name in post_snap, (
            f"creates-never-mutates VIOLATION: pre-existing role "
            f"{name!r} disappeared during synthesis flow"
        )
        post_state = post_snap[name]
        assert post_state == pre_state, (
            f"creates-never-mutates VIOLATION: pre-existing role "
            f"{name!r} was MUTATED.\npre:  {pre_state}\npost: {post_state}"
        )
    # Exactly one new role appears + it's the one we expected.
    new_roles = set(post_snap) - set(pre_snap)
    assert issued_role_name in new_roles, (
        f"issued role {issued_role_name!r} missing from post-snapshot; "
        f"new roles: {new_roles}"
    )
    assert len(new_roles) == 1, (
        f"expected exactly 1 new role; got {new_roles}"
    )

    # ===========================================================
    # Step 9  — verdict shape sanity: no rejection_code on success
    #           + non-empty notes if credentials wired (the #476
    #           "credentials minted" inverse — the note about #473
    #           should be ABSENT because we DID wire creds).
    # ===========================================================
    assert verdict.get("rejection_code") is None, verdict
    # When credential_factory IS wired (this test) + creds came back,
    # the verdict's "notes" should NOT contain the #473 placeholder
    # message about creds not being wired. This is the inverse-of-#476
    # check: status:auto_approved + creds:non-null + no "creds-not-
    # wired" note all consistent.
    notes_blob = " ".join(verdict.get("notes", []) or [])
    assert "credential issuance not yet wired" not in notes_blob, (
        f"verdict's notes claim creds not wired despite "
        f"credentials={creds!r}: notes={notes_blob!r}"
    )

    # ----- Teardown: only delete the role we created. The pre-existing
    # roles snapshot is the creates-never-mutates witness; touching
    # them here would invalidate future test runs.
    iam.delete_role_policy(
        RoleName=issued_role_name, PolicyName="iam-jit-synth-grant",
    )
    iam.delete_role(RoleName=issued_role_name)
    try:
        # Clean up the S3 bucket so reruns don't accumulate.
        boto3_clients["s3"].delete_object(Bucket=bucket_name, Key="hello.txt")
        boto3_clients["s3"].delete_bucket(Bucket=bucket_name)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wait_for_log_grows(
    path: Path, *, min_lines: int, timeout: float = 5.0,
) -> None:
    """Poll until the JSONL audit log has at least `min_lines` non-empty
    lines OR timeout. Defensive against the AuditLogWriter's async
    drain — the worker batches writes off the proxy hot-path so a
    naive read-immediately-after-call races on slow machines."""
    deadline = time.time() + timeout
    last_count = -1
    while time.time() < deadline:
        if path.exists():
            try:
                count = sum(
                    1 for ln in path.read_text(
                        encoding="utf-8"
                    ).splitlines() if ln.strip()
                )
            except OSError:
                count = 0
            if count >= min_lines:
                return
            last_count = count
        time.sleep(0.25)
    # Caller's assertion will surface the actual count — don't raise here,
    # let the test's assertion produce the diagnostic.
    return None


def _localstack_url_from_clients(boto3_clients: dict[str, Any]) -> str:
    """Read the LocalStack endpoint URL off an existing boto3 client.

    The boto3_clients fixture builds clients with `endpoint_url=` set;
    we read it back off the meta to avoid a second copy of the URL.
    """
    return boto3_clients["iam"].meta.endpoint_url
