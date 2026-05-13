#!/usr/bin/env python3
"""Claim the bootstrap admin without typing anything into the form.

Run this immediately after `sam deploy` to skip the manual `/setup`
flow. Everything the script needs is already in AWS — the stack
outputs (BootstrapClaimUrl, ALB DNS) and the Lambda env vars
(BootstrapSetupKey, AdminBootstrapEmail). The script:

  1. Reads BootstrapClaimUrl + AdminBootstrapEmail + BootstrapSetupKey
     from the deployed stack + Lambda config.
  2. POSTs to BootstrapClaimUrl with the email + key → admin claimed,
     single-use marker written to the bootstrap user record.
  3. POSTs to /api/v1/auth/magic-link with the admin email →
     iam-jit emits a one-shot magic-link to its CloudWatch log
     (default `log` delivery channel when SES isn't configured).
  4. Tails the Lambda's CloudWatch log group for ~30 seconds,
     extracts the magic-link URL.
  5. Opens the magic-link in the operator's default browser. One
     click and they're signed in as the bootstrap admin — no
     copy/paste, no form, no key handling.

Why magic-link vs the /setup session cookie directly:
  The /setup POST returns a Set-Cookie header, but the cookie is
  HttpOnly + signed — there's no clean way to hand that off to a
  separate browser process. Magic-link is exactly the right
  primitive: a single-use signed URL that the browser can consume
  natively. iam-jit already implements it; we just orchestrate.

Usage:
  scripts/claim-bootstrap.py [--profile PROFILE] [--stack STACK]
                              [--region REGION] [--no-browser]

Defaults: --profile=omise-experimental, --stack=iam-jit,
--region=us-east-1. Override via CLI args or env vars
IAM_JIT_AWS_PROFILE / IAM_JIT_STACK_NAME / IAM_JIT_AWS_REGION.

Failure modes (and what the script does):
  - Stack not found → exit 2 with clear message
  - Lambda env vars empty (no /setup configured) → exit 3
  - Setup already claimed → 200 response with "already consumed"
    body; script exits 4 with the existing login URL printed
  - Magic-link line never appears in logs → exit 5 (probable cause:
    SES is configured, in which case check the inbox instead)
  - Browser open fails → URL printed, exit 0; user clicks manually
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request


DEFAULTS = {
    "profile": os.environ.get("IAM_JIT_AWS_PROFILE", "omise-experimental"),
    "stack": os.environ.get("IAM_JIT_STACK_NAME", "iam-jit"),
    "region": os.environ.get("IAM_JIT_AWS_REGION", "us-east-1"),
}


def _run_aws(args: list[str], profile: str, region: str | None = None) -> dict:
    """Run an aws CLI command with --output json and return the parsed result."""
    cmd = ["aws"] + args + ["--profile", profile, "--output", "json"]
    if region:
        cmd += ["--region", region]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        sys.stderr.write(
            f"aws CLI failed: {' '.join(cmd)}\n"
            f"stderr: {proc.stderr}\n"
        )
        sys.exit(2)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        sys.stderr.write(f"aws CLI returned non-JSON output:\n{proc.stdout}\n")
        sys.exit(2)


def _stack_outputs(stack: str, profile: str, region: str) -> dict[str, str]:
    """Map of OutputKey → OutputValue for the stack."""
    result = _run_aws(
        ["cloudformation", "describe-stacks", "--stack-name", stack],
        profile=profile, region=region,
    )
    stacks = result.get("Stacks") or []
    if not stacks:
        sys.stderr.write(f"stack {stack!r} not found in {profile}/{region}\n")
        sys.exit(2)
    outputs = stacks[0].get("Outputs") or []
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _lambda_env(function_name: str, profile: str, region: str) -> dict[str, str]:
    """Lambda function's env-var map."""
    result = _run_aws(
        ["lambda", "get-function-configuration",
         "--function-name", function_name],
        profile=profile, region=region,
    )
    env = (result.get("Environment") or {}).get("Variables") or {}
    return env


def _http_post(url: str, form_fields: dict[str, str], timeout: int = 30) -> tuple[int, str, dict]:
    """Plain urllib POST. Returns (status, body, headers). Treats 30x
    as the final response (we WANT to see the Set-Cookie). Doesn't
    follow redirects."""
    data = urllib.parse.urlencode(form_fields).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    # Use a no-redirect handler so 303 stays a 303 (we want the Location header).
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body, dict(e.headers or {})


def _http_post_json(url: str, payload: dict, timeout: int = 30) -> tuple[int, str, dict]:
    """JSON POST variant — used for /api/v1/auth/magic-link."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body, dict(e.headers or {})


_MAGIC_LINK_RE = re.compile(r"MAGIC_LINK channel=log user_id=\S+ url=(\S+)")


# Local-loopback IPs the auto-seed shouldn't accept as "the operator's
# real IP" — these come from misconfigured XFF or test harnesses.
_NOT_OPERATOR_IPS = {"127.0.0.1", "0.0.0.0", "localhost", "::1"}


def _wait_for_seeded_ip(public_base: str, deadline: float) -> str | None:
    """Poll the iam-jit Lambda's runtime CIDR allowlist for an entry
    seeded by the magic-callback handler. Returns the CIDR (e.g.,
    '198.51.100.5/32') or None on timeout.

    Doesn't require auth — the runtime allowlist is queryable as
    admin via /api/v1/admin/network/cidrs, but the magic-callback's
    auto-seed also emits a log line that's grep-able. We use the
    log-grep path because it doesn't need a session cookie to be
    threaded through urllib (which is awkward in stdlib).
    """
    profile = DEFAULTS["profile"]
    region = DEFAULTS["region"]
    since = int(time.time())
    while time.time() < deadline:
        # The auto-seed log line is:
        #   "auto-seeded runtime CIDR with bootstrap admin's IP X"
        # (emitted by cidr_store.auto_seed_for_bootstrap). Grep for
        # the unique-ish prefix; fall back to the magic-callback
        # source-ip if needed.
        result = _run_aws(
            ["logs", "filter-log-events",
             "--log-group-name", "/aws/lambda/iam-jit",
             "--filter-pattern", '"auto-seeded CIDR"',
             "--start-time", str(since * 1000)],
            profile=profile, region=region,
        )
        for ev in result.get("events", []):
            msg = ev.get("message", "")
            # Pull the IP out — match anywhere in the message.
            ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", msg)
            for ip in ips:
                if ip not in _NOT_OPERATOR_IPS:
                    return f"{ip}/32"
        time.sleep(3)
    return None


def _alb_sg_id(stack: str, profile: str, region: str) -> str | None:
    result = _run_aws(
        ["cloudformation", "describe-stack-resource",
         "--stack-name", stack,
         "--logical-resource-id", "IAMJitAlbSecurityGroup"],
        profile=profile, region=region,
    )
    return (
        result.get("StackResourceDetail") or {}
    ).get("PhysicalResourceId")


def _narrow_alb_sg(sg_id: str, cidr: str, profile: str, region: str) -> bool:
    """Revoke 0.0.0.0/0 ingress + authorize the operator's CIDR.

    Idempotent on the revoke side: if 0.0.0.0/0 is already missing
    we ignore the error. On the authorize side we treat
    `InvalidPermission.Duplicate` as success."""
    # Revoke open ingress (best-effort; ignore if already revoked).
    for port in (80, 443):
        subprocess.run(
            [
                "aws", "ec2", "revoke-security-group-ingress",
                "--group-id", sg_id,
                "--ip-permissions",
                f'IpProtocol=tcp,FromPort={port},ToPort={port},'
                f'IpRanges=[{{CidrIp=0.0.0.0/0}}]',
                "--profile", profile, "--region", region,
            ],
            capture_output=True, text=True, timeout=30,
        )
    # Authorize the operator's CIDR.
    for port in (80, 443):
        proc = subprocess.run(
            [
                "aws", "ec2", "authorize-security-group-ingress",
                "--group-id", sg_id,
                "--ip-permissions",
                f'IpProtocol=tcp,FromPort={port},ToPort={port},'
                f'IpRanges=[{{CidrIp={cidr}}}]',
                "--profile", profile, "--region", region,
            ],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0 and "Duplicate" not in proc.stderr:
            sys.stderr.write(
                f"authorize-security-group-ingress (port {port}) failed:\n"
                f"{proc.stderr}\n"
            )
            return False
    return True


def _grep_magic_link(profile: str, region: str, since_epoch: int, deadline: float) -> str | None:
    """Poll the Lambda's log group for a MAGIC_LINK log line emitted
    after `since_epoch`. Returns the URL or None on timeout."""
    log_group = "/aws/lambda/iam-jit"
    while time.time() < deadline:
        result = _run_aws(
            ["logs", "filter-log-events",
             "--log-group-name", log_group,
             "--filter-pattern", "MAGIC_LINK",
             "--start-time", str(since_epoch * 1000)],
            profile=profile, region=region,
        )
        for ev in result.get("events", []):
            m = _MAGIC_LINK_RE.search(ev.get("message", ""))
            if m:
                return m.group(1)
        time.sleep(2)
    return None


def _open_browser(url: str) -> bool:
    """Best-effort browser open; True if the OS handler launched."""
    for cmd in (["open", url], ["xdg-open", url], ["explorer", url]):
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except FileNotFoundError:
            continue
    return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Auto-claim the iam-jit bootstrap admin and open a "
                    "browser already signed in.",
    )
    ap.add_argument("--profile", default=DEFAULTS["profile"])
    ap.add_argument("--stack", default=DEFAULTS["stack"])
    ap.add_argument("--region", default=DEFAULTS["region"])
    ap.add_argument(
        "--no-browser", action="store_true",
        help="Print the magic-link URL instead of opening it.",
    )
    ap.add_argument(
        "--no-narrow", action="store_true",
        help="Skip the post-claim ALB SG narrow step.",
    )
    args = ap.parse_args()

    print(f"==> Discovering stack `{args.stack}` in {args.profile}/{args.region}")
    outputs = _stack_outputs(args.stack, args.profile, args.region)
    claim_url = outputs.get("BootstrapClaimUrl")
    public_base = outputs.get("PublicBaseUrl")
    if not claim_url or not public_base:
        sys.stderr.write(
            "stack outputs are missing BootstrapClaimUrl or PublicBaseUrl. "
            "Confirm the stack deployed cleanly via `aws cloudformation "
            "describe-stacks`.\n"
        )
        return 2

    # The Lambda function name is fixed at `iam-jit` in the template.
    # If you renamed it, change here too — or extract from the stack
    # resources.
    env = _lambda_env("iam-jit", args.profile, args.region)
    setup_key = (env.get("IAM_JIT_BOOTSTRAP_SETUP_KEY") or "").strip()
    admin_email = (env.get("IAM_JIT_ADMIN_BOOTSTRAP_EMAIL") or "").strip()
    if not setup_key or not admin_email:
        sys.stderr.write(
            "Lambda env vars are missing IAM_JIT_BOOTSTRAP_SETUP_KEY "
            "or IAM_JIT_ADMIN_BOOTSTRAP_EMAIL. The /setup claim flow "
            "is not configured for this deployment — claim manually "
            "via /login + magic-link, or redeploy with both params "
            "set.\n"
        )
        return 3

    print(f"==> Claiming bootstrap admin: {admin_email}")
    status, body, _ = _http_post(claim_url, {"email": admin_email, "key": setup_key})
    if status == 303:
        print("    ✓ admin claimed (303 → /admin/network)")
    elif status == 200 and "already" in body.lower() and "consumed" in body.lower():
        print(
            "    ⚠ bootstrap setup was already consumed in a prior run. "
            "Skipping the claim and using /login to mint a magic-link "
            "for the existing admin user."
        )
    else:
        sys.stderr.write(
            f"unexpected response from /setup: HTTP {status}\n"
            f"body: {body[:400]}\n"
        )
        return 4

    print(f"==> Requesting a one-shot magic-link for {admin_email}")
    # POST /api/v1/auth/magic-link emits the link to the configured
    # delivery channel. In the no-SES sandbox path that's CloudWatch
    # logs; in production with SES it's an inbox.
    magic_endpoint = public_base.rstrip("/") + "/api/v1/auth/magic-link"
    since = int(time.time())  # We'll poll logs for entries after this timestamp.
    status, body, _ = _http_post_json(magic_endpoint, {"email": admin_email})
    if status != 202:
        sys.stderr.write(
            f"magic-link endpoint returned HTTP {status} (expected 202): {body[:400]}\n"
        )
        return 5

    # Did the response embed the link (dev/insecure mode)? Otherwise
    # we have to read CloudWatch logs to find the URL.
    try:
        parsed = json.loads(body)
        dev_link = parsed.get("dev_link")
    except json.JSONDecodeError:
        dev_link = None

    if dev_link:
        magic_url = dev_link
        print("    ✓ link returned inline (dev mode)")
    else:
        print("==> Polling CloudWatch logs for the magic-link "
              "(up to 60s; the link is emitted as a structured log "
              "line because SES isn't configured for this deploy)")
        magic_url = _grep_magic_link(
            args.profile, args.region, since, deadline=time.time() + 60
        )
        if not magic_url:
            sys.stderr.write(
                "timed out waiting for MAGIC_LINK log entry. Possible causes:\n"
                "  - SES is configured (link went to the inbox; check there)\n"
                "  - Lambda log group hasn't created the stream yet for this "
                "invocation (rare; retry the script)\n"
                "  - The admin user is banned (check /api/v1/admin/bans)\n"
            )
            return 5
        print(f"    ✓ found magic-link in log group /aws/lambda/iam-jit")

    print()
    print("=" * 70)
    print("  Sign-in URL (single-use, expires in 15 minutes):")
    print()
    print(f"  {magic_url}")
    print()
    print("=" * 70)

    if args.no_browser:
        print("(--no-browser was set; copy the URL above into your browser.)")
    else:
        if _open_browser(magic_url):
            print("Opened in your default browser. After this loads, you're admin.")
        else:
            print("Couldn't open a browser automatically — copy the URL above.")

    if args.no_narrow:
        return 0

    # Auto-narrow the ALB SG to the operator's actual IP. We polled
    # `/api/v1/admin/network/cidrs` for an entry that the magic-
    # callback handler's auto-seed populated. Once we see one, we
    # rewrite the ALB security-group ingress to that CIDR — moving
    # from "open to internet (loud warning)" to "narrowed at the
    # network layer" without a redeploy.
    print()
    print("==> Waiting for the magic-link click to record your IP "
          "(up to 5 minutes)")
    print("    (the iam-jit Lambda auto-seeds the runtime CIDR "
          "allowlist with your browser's source IP on first claim)")

    operator_ip = _wait_for_seeded_ip(
        public_base=public_base,
        deadline=time.time() + 300,
    )
    if not operator_ip:
        print("    ⚠ no operator IP detected before timeout. SG stays "
              "at AlbIngressCidr=0.0.0.0/0. Narrow manually if needed:")
        print("        aws ec2 revoke-security-group-ingress …")
        print("        aws ec2 authorize-security-group-ingress …")
        return 0

    print(f"    ✓ detected operator IP: {operator_ip}")
    sg_id = _alb_sg_id(args.stack, args.profile, args.region)
    if not sg_id:
        print("    ⚠ couldn't find the ALB security group from stack "
              "resources. Skipping auto-narrow.")
        return 0
    print(f"==> Narrowing ALB SG {sg_id} to {operator_ip}")
    if _narrow_alb_sg(sg_id, operator_ip, args.profile, args.region):
        print(f"    ✓ ALB SG now allows ingress only from {operator_ip}")
        print()
        print("    Note: the next `sam deploy` will revert SG ingress "
              "unless you pass `AlbIngressCidr={ip}/32` (or whatever "
              "CIDR you want) on the --parameter-overrides line. To "
              "make this durable, also add it to your deploy "
              "parameters file.".format(ip=operator_ip.split('/')[0]))
    else:
        print("    ⚠ narrow failed (likely permission). SG stays at "
              "0.0.0.0/0. Run the aws ec2 commands manually.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
