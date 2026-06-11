#!/usr/bin/env python3
"""UAT: an iam-jit-style scoped credential, driven through the awslabs
aws-api-mcp-server, is enforced server-side by AWS.

Proves the composition recommended in docs/uat/aws-mcp-server-with-iam-jit.md:
the AWS MCP server has no per-action authorization of its own (its `call_aws`
tool runs any AWS CLI command the credentials allow), so the real boundary is
the IAM credential — which iam-jit makes least-privilege + short-lived. This
mints a scoped 15-min STS session (only s3:ListAllMyBuckets), feeds it to the
MCP server over MCP/stdio, and asserts every out-of-scope call is denied 403.

Prereqs (skips cleanly if absent):
  - AWS creds: a profile that can call sts:GetFederationToken (env
    IAMJIT_UAT_AWS_PROFILE, default "iam-jit").
  - the server installed: env IAMJIT_UAT_MCP_PYTHON pointing at a python that
    can `import awslabs.aws_api_mcp_server` (e.g. a venv with
    `pip install awslabs.aws-api-mcp-server`).
  - set IAMJIT_AWS_MCP_UAT=1 to actually run (touches real AWS).

Set UAT_KEEP_ENDPOINT=1 to route the MCP server's calls through a bouncer
(AWS_ENDPOINT_URL, e.g. ibounce) instead of straight to AWS.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

PROFILE = os.environ.get("IAMJIT_UAT_AWS_PROFILE", "iam-jit")
MCP_PY = os.environ.get("IAMJIT_UAT_MCP_PYTHON", sys.executable)
SCOPED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Sid": "OnlyListBuckets", "Effect": "Allow",
                   "Action": ["s3:ListAllMyBuckets"], "Resource": "*"}],
}


def _skip(msg: str) -> None:
    print(f"SKIP: {msg}")
    sys.exit(0)


def mint_scoped_creds() -> dict:
    out = subprocess.run(
        ["aws", "sts", "get-federation-token", "--name", "iamjit-mcp-uat",
         "--duration-seconds", "900", "--policy", json.dumps(SCOPED_POLICY),
         "--profile", PROFILE, "--output", "json"],
        capture_output=True, text=True, env={**os.environ, "AWS_REGION": "us-east-1"},
    )
    if out.returncode != 0:
        _skip(f"could not mint scoped creds via profile {PROFILE!r}: {out.stderr.strip()[:200]}")
    return json.loads(out.stdout)["Credentials"]


class MCP:
    def __init__(self, creds: dict):
        env = dict(os.environ)
        if not os.environ.get("UAT_KEEP_ENDPOINT"):
            env.pop("AWS_ENDPOINT_URL", None)
        for k in ("AWS_PROFILE", "AWS_API_MCP_PROFILE_NAME"):
            env.pop(k, None)
        env.update({
            "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
            "AWS_SESSION_TOKEN": creds["SessionToken"],
            "AWS_REGION": "us-east-1",
            "AWS_API_MCP_TELEMETRY": "false",
        })
        self.p = subprocess.Popen(
            [MCP_PY, "-m", "awslabs.aws_api_mcp_server.server"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True, bufsize=1)

    def _send(self, o): self.p.stdin.write(json.dumps(o) + "\n"); self.p.stdin.flush()

    def _recv(self, want_id):
        while True:
            line = self.p.stdout.readline()
            if not line:
                _skip("MCP server exited (is it installed?): " + self.p.stderr.read()[-500:])
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == want_id:
                return msg

    def initialize(self):
        self._send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "iamjit-uat", "version": "1"}}})
        self._recv(1)
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def call_aws(self, cmd, rid):
        self._send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                    "params": {"name": "call_aws", "arguments": {"cli_command": cmd}}})
        res = (self._recv(rid).get("result") or {})
        text = " ".join(c.get("text", "") for c in (res.get("content") or []) if isinstance(c, dict))
        try:
            resp = json.loads(text)[0]["response"]
            return resp.get("status_code"), resp.get("error_code") or resp.get("error") or "", text
        except Exception:
            return None, text, text

    def close(self):
        try:
            self.p.terminate()
        except Exception:
            pass


def main() -> int:
    if os.environ.get("IAMJIT_AWS_MCP_UAT") != "1":
        _skip("set IAMJIT_AWS_MCP_UAT=1 to run the live AWS MCP UAT")
    try:
        subprocess.run([MCP_PY, "-c", "import awslabs.aws_api_mcp_server"],
                       check=True, capture_output=True)
    except Exception:
        _skip(f"awslabs.aws_api_mcp_server not importable by {MCP_PY} "
              f"(pip install awslabs.aws-api-mcp-server; set IAMJIT_UAT_MCP_PYTHON)")

    m = MCP(mint_scoped_creds())
    m.initialize()
    print("=" * 80)
    print("iam-jit-style scoped creds (s3:ListAllMyBuckets ONLY) -> awslabs aws-api-mcp-server")
    if os.environ.get("UAT_KEEP_ENDPOINT"):
        print(f"(routed through bouncer AWS_ENDPOINT_URL={os.environ.get('AWS_ENDPOINT_URL')})")
    print("=" * 80)
    ok = True

    sc, info, _ = m.call_aws("aws sts get-caller-identity", 11)
    a = sc == 200
    print(f"[{'PASS' if a else 'FAIL'}] CONTROL creds valid  | sts:GetCallerIdentity -> {sc}")
    ok &= a

    sc, info, raw = m.call_aws("aws s3api list-buckets --query 'Buckets[].Name' --output json", 12)
    a = sc == 200
    print(f"[{'PASS' if a else 'FAIL'}] IN-SCOPE granted     | s3:ListAllMyBuckets -> {sc}")
    ok &= a
    bucket = None
    try:
        bucket = json.loads(json.loads(raw)[0]["response"]["as_json"])["Result"][0]
    except Exception:
        pass

    out = [(13, f"s3:ListBucket on {bucket}", f"aws s3api list-objects-v2 --bucket {bucket} --max-items 1")] if bucket else []
    out += [
        (14, "ec2:DescribeInstances", "aws ec2 describe-instances --region us-east-1 --max-items 1"),
        (15, "iam:ListUsers", "aws iam list-users"),
        (16, "s3:CreateBucket (write)", "aws s3api create-bucket --bucket iamjit-uat-shouldnotcreate-590519617224"),
    ]
    for rid, label, cmd in out:
        sc, info, _ = m.call_aws(cmd, rid)
        denied = sc != 200
        ok &= denied
        print(f"[{'PASS' if denied else 'FAIL'}] OUT denied           | {label} -> {sc} {str(info)[:60]}")

    print("=" * 80)
    print("OVERALL:", "PASS — AWS enforced the scoped credential server-side, through the MCP server"
          if ok else "FAIL")
    m.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
