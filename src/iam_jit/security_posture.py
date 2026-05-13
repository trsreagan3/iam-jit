"""Compute the security posture of the running iam-jit deployment.

Single source of truth for "is this deployment safe to share publicly?"
Consumed by:

  - `/healthz` (anonymous) — agents and load balancers see a
    `security_posture` summary they can act on without auth.
  - `/api/v1/admin/security-posture` (admin) — UI banner +
    detailed dict for the admin's situation report.
  - `templates/admin_network.html` — renders the loud red warning
    banner when the posture says one is warranted.

Risk-level taxonomy:

  - `critical`  — at least one combination that almost certainly
                  leaks the BootstrapSetupKey or session cookies
                  in cleartext to the internet. Show a loud red
                  banner; warn agents at every callable surface.
  - `warn`      — degraded but not actively-leaking posture.
                  Yellow banner; agents should mention it once.
  - `ok`        — no detected issue. No banner.

The current critical condition: ALB ingress is `0.0.0.0/0` AND
ALB has no HTTPS cert. Both must hold; either alone is acceptable
in some legitimate setups (VPN-fronted + 0.0.0.0/0 has the VPN as
the gate; behind-CF + HTTP-only is unusual but possible). The
combination is the foot-gun: cleartext form POSTs of the
BootstrapSetupKey from any internet host.

Posture inputs come from the deployed Lambda's env + the runtime
CIDR store + the SG state. We compute on every request (~ms);
caching would risk staleness when an admin tightens the SG.
"""

from __future__ import annotations

import os
from typing import Any


def _alb_enabled() -> bool:
    return (os.environ.get("IAM_JIT_TRUST_FORWARDED_HOST") or "") == "1"


def _alb_has_https_cert() -> bool:
    # The template doesn't pass the cert status to runtime as an env
    # var (the cert lives on the ALB resource, not the Lambda). We
    # infer indirectly: when the operator generates magic-links the
    # base URL scheme is set via X-Forwarded-Proto. If we're seeing
    # consistent https forwarded-proto, HTTPS is in front. Until a
    # request arrives we can only check the env var that operators
    # set explicitly (`IAM_JIT_ALB_HAS_CERT=1`). Future:
    # populate this at deploy via a stack output.
    return (os.environ.get("IAM_JIT_ALB_HAS_CERT") or "") == "1"


def _runtime_cidr_count() -> int:
    """Number of entries in the runtime CIDR allowlist."""
    try:
        from . import cidr_store
        return len(cidr_store.get_default_store().list())
    except Exception:
        return 0


def _env_cidr_list() -> list[str]:
    """Deploy-time CIDR allowlist (env var)."""
    raw = os.environ.get("IAM_JIT_ALLOWED_SOURCE_CIDRS") or ""
    return [c.strip() for c in raw.split(",") if c.strip()]


def _ses_configured() -> bool:
    return bool((os.environ.get("IAM_JIT_SES_SENDER") or "").strip())


def compute() -> dict[str, Any]:
    """Return the current posture dict. Cheap; safe to call per-request."""
    alb_in_front = _alb_enabled()
    https_on_alb = _alb_has_https_cert()
    runtime_count = _runtime_cidr_count()
    env_cidrs = _env_cidr_list()
    network_acl_active = runtime_count > 0 or len(env_cidrs) > 0

    issues: list[dict[str, str]] = []

    # Critical: ALB + HTTP-only + no app-layer ACL configured.
    # The bare combination "ALB ingress 0.0.0.0/0 AND HTTP-only" is
    # what we want to detect at the SG layer; lacking direct SG
    # introspection from the Lambda, we proxy via "no app-layer
    # restriction either" — if the operator had narrowed the SG,
    # they almost always also tightened the app-layer list. Both
    # being empty is the canonical "wide-open + cleartext" deploy.
    if alb_in_front and not https_on_alb and not network_acl_active:
        issues.append({
            "id": "open_alb_http",
            "severity": "critical",
            "title": "ALB is HTTP-only AND has no source-IP restriction",
            "detail": (
                "The bootstrap-claim form POSTs the BootstrapSetupKey in "
                "cleartext over HTTP, and the network surface is open to "
                "the entire internet. Combined risk: any in-path observer "
                "(public Wi-Fi, ISP, etc.) could read the key. Narrow the "
                "ALB SG to your real ingress (AlbIngressCidr=<IP>/32 on "
                "next redeploy), or provision an ACM cert and set "
                "AlbCertificateArn — ideally both."
            ),
            "fix": (
                "Pass AlbIngressCidr=<your-IP>/32 and "
                "AlbCertificateArn=<arn> on next sam deploy. "
                "See docs/HTTPS-SETUP.md."
            ),
        })
    elif alb_in_front and not https_on_alb:
        issues.append({
            "id": "alb_http_only",
            "severity": "warn",
            "title": "ALB is HTTP-only",
            "detail": (
                "Session cookies and form POSTs travel cleartext. "
                "Acceptable for sandbox / VPN-fronted deployments; "
                "NOT for production."
            ),
            "fix": (
                "Provision an ACM cert and pass AlbCertificateArn= "
                "on next sam deploy. See docs/HTTPS-SETUP.md."
            ),
        })
    elif alb_in_front and not network_acl_active:
        issues.append({
            "id": "open_alb",
            "severity": "warn",
            "title": "ALB SG has no source-IP restriction",
            "detail": (
                "The network surface is open to the entire internet. "
                "The cryptographic defenses on the bootstrap-claim "
                "flow still apply, but narrowing the SG is recommended."
            ),
            "fix": (
                "Pass AlbIngressCidr=<your-IP>/32 on next sam deploy, "
                "OR add your CIDR to the runtime allowlist at "
                "POST /api/v1/admin/network/cidrs."
            ),
        })

    if not _ses_configured():
        # Not strictly an issue — it's the documented Phase-1 path —
        # but agents should know HOW the magic-link reaches the
        # user. The actual channel is determined by
        # magic_link_delivery.decide() and depends on whether the
        # template auto-set IAM_JIT_DEV_INSECURE_SECRET (HTTP-only
        # ALB posture) → inline-on-page delivery, or fell through
        # to CloudWatch logs (HTTPS-without-SES).
        from . import magic_link_delivery
        channel = magic_link_delivery.decide().channel
        if channel == "in_response":
            title = (
                "SES not configured; magic-links rendered INLINE on "
                "the /login response page"
            )
            detail = (
                "This deployment has IAM_JIT_DEV_INSECURE_SECRET=1 "
                "(auto-set by the template's HttpOnlyAlbDeploy "
                "condition when there's no AlbCertificateArn). After "
                "POSTing /login, the magic-link is rendered as a "
                "clickable <a> on the confirmation page — no email, "
                "no CloudWatch round-trip. Acceptable for sandbox "
                "deploys; NOT acceptable for production (the link "
                "appears in any browser that observes the response, "
                "including via shoulder-surfing or browser history)."
            )
            fix = (
                "Wire HTTPS (set AlbCertificateArn) AND set "
                "SesSenderAddress=<verified-sender> on next sam "
                "deploy. The Secure-cookie + email-delivery path "
                "is the production posture."
            )
        else:
            # channel == "log" — HTTPS, no SES, no dev flag.
            title = (
                "SES not configured; magic-links delivered via "
                "CloudWatch logs"
            )
            detail = (
                "Without IAM_JIT_SES_SENDER set, magic-links are "
                "emitted to /aws/lambda/iam-jit as MAGIC_LINK log "
                "entries. An admin retrieves them via "
                "`aws logs filter-log-events --filter-pattern "
                "'MAGIC_LINK'` and shares with the user out-of-band. "
                "Acceptable for ops-team-only deployments; for "
                "end-user rollouts wire SES."
            )
            fix = (
                "Set SesSenderAddress=<verified-sender> on next sam "
                "deploy after verifying the sender in SES console."
            )
        issues.append({
            "id": "no_ses",
            "severity": "info",
            "title": title,
            "detail": detail,
            "fix": fix,
            "delivery_channel": channel,
        })

    severity = "ok"
    for i in issues:
        if i["severity"] == "critical":
            severity = "critical"
            break
        if i["severity"] == "warn":
            severity = "warn"

    return {
        "severity": severity,
        "alb_in_front": alb_in_front,
        "alb_has_https_cert": https_on_alb,
        "network_acl_active": network_acl_active,
        "runtime_cidr_count": runtime_count,
        "env_cidrs_configured": len(env_cidrs) > 0,
        "ses_configured": _ses_configured(),
        "issues": issues,
    }


def warning_dismissed_by(user_notes: str | None, warning_id: str) -> bool:
    """Did the user dismiss this specific warning?

    Uses a line-anchored exact-prefix match so `open_alb_http`
    won't be matched by a marker for `open_alb`. The marker shape is
    `dismissed_warning:<id>=<ts>` (one per line)."""
    if not user_notes:
        return False
    prefix = f"dismissed_warning:{warning_id}="
    for raw_line in user_notes.splitlines():
        if raw_line.strip().startswith(prefix):
            return True
    return False


def append_dismissal(existing_notes: str | None, warning_id: str, when_iso: str) -> str:
    """Append a dismissal marker to a user's notes field. Idempotent —
    re-dismissing the same warning re-stamps but doesn't duplicate."""
    base = (existing_notes or "").strip()
    marker = f"dismissed_warning:{warning_id}={when_iso}"
    # Strip any prior marker for the same id; keep this clean.
    lines = [
        line for line in base.split("\n")
        if not line.strip().startswith(f"dismissed_warning:{warning_id}")
    ]
    lines.append(marker)
    return "\n".join(line for line in lines if line.strip())
