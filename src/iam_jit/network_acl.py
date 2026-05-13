"""Source-IP / CIDR allowlist for the iam-jit HTTP surface.

Lambda Function URLs are reachable from anywhere on the internet. The
SAM template's `AllowPublicNetworkExposure` parameter is one layer of
defense (deploy-time gating). This module is the second: a runtime
allowlist that refuses requests whose source IP isn't in the
configured list — applied to every route except `/healthz` (so probes
work) and `/static/*` (so the operator can still read the
recommendation page if they fat-fingered their own IP).

Reading the source IP:

  - When iam-jit runs behind CloudFront / ALB, the original IP arrives
    in `X-Forwarded-For`. We take the FIRST IP — the closest hop to
    the actual caller — to defeat trivial spoofing of the inner
    elements by an outside attacker.
  - Direct Function URL hits (no front-door) have no XFF. We fall
    back to `request.client.host`.
  - When `IAM_JIT_TRUST_FORWARDED_FOR=0`, we ignore XFF entirely and
    always read `request.client.host`. Use this when iam-jit is
    *directly* exposed (no proxy in front), so an attacker can't fake
    XFF to bypass the allowlist.

Empty config = no enforcement. The middleware is a no-op until the
operator configures `IAM_JIT_ALLOWED_SOURCE_CIDRS`. The bootstrap UX
recommends doing this on first sign-in.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass


logger = logging.getLogger("iam_jit.network_acl")


# Path prefixes that bypass the CIDR check entirely. Health probes
# come from inside the VPC / load balancer, and static assets are
# safe to serve to whoever is currently locked out so they can read
# the "your IP isn't allowed" page without a chicken-and-egg.
_EXEMPT_PATH_PREFIXES = ("/healthz", "/static/")


@dataclass(frozen=True)
class CIDRDecision:
    allowed: bool
    matched_cidr: str | None
    source_ip: str | None
    """The IP we evaluated. Useful in 403 responses (operator can
    confirm what was sent vs. what's allowed) and in audit logs."""
    reason: str
    """One of: 'no_acl_configured', 'ip_in_allowlist',
    'ip_not_in_allowlist', 'no_source_ip_available',
    'invalid_source_ip', 'invalid_acl_config'."""


def _parse_cidrs(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a CIDR list. Accepts ANY of:

      - comma-separated:   "10.0.0.0/8, 192.168.0.0/16"
      - newline-separated: "10.0.0.0/8\\n192.168.0.0/16"
      - space-separated:   "10.0.0.0/8 192.168.0.0/16"
      - mixed / extra whitespace

    Skip blanks; log and skip malformed entries individually so one
    typo doesn't silently disable the whole ACL.

    Also accepts bare IPs ("10.5.6.7" → "10.5.6.7/32") so an agent
    that hands us a single IP doesn't need to know it should add /32.
    """
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    # Normalize all delimiters to a single space, then split.
    normalized = raw.replace(",", " ").replace("\n", " ").replace("\t", " ")
    for token in normalized.split():
        if not token:
            continue
        try:
            out.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            # Bare IP without prefix → add /32 or /128 and retry.
            try:
                addr = ipaddress.ip_address(token)
                prefix = "/32" if addr.version == 4 else "/128"
                out.append(ipaddress.ip_network(f"{token}{prefix}", strict=False))
            except ValueError as e:
                logger.warning(
                    "ignoring malformed CIDR/IP %r in allowlist: %s", token, e
                )
    return out


def _read_source_ip(request_client_host: str | None, xff_header: str | None) -> str | None:
    """Pick the source IP. Honors `IAM_JIT_TRUST_FORWARDED_FOR=0` to
    disable XFF parsing entirely."""
    trust_xff = (
        os.environ.get("IAM_JIT_TRUST_FORWARDED_FOR", "1").lower()
        in {"1", "true", "yes"}
    )
    if trust_xff and xff_header:
        first = xff_header.split(",")[0].strip()
        if first:
            return first
    return request_client_host or None


def evaluate(
    *,
    path: str,
    request_client_host: str | None,
    xff_header: str | None,
) -> CIDRDecision:
    """Decide whether a request should be allowed.

    Resolution order:
      1. Runtime CIDR store (admin-managed, mutable via UI/API).
      2. Env var `IAM_JIT_ALLOWED_SOURCE_CIDRS` (SAM-baked).
      3. Default open (no enforcement).
    """
    if any(path.startswith(p) for p in _EXEMPT_PATH_PREFIXES):
        return CIDRDecision(
            allowed=True, matched_cidr=None, source_ip=None,
            reason="exempt_path",
        )

    # Runtime store first — admin can override the env-baked floor.
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    try:
        from . import cidr_store

        runtime_entries = cidr_store.get_default_store().list()
        for entry in runtime_entries:
            try:
                networks.append(ipaddress.ip_network(entry.cidr, strict=False))
            except ValueError:
                logger.warning("runtime store had bad CIDR %r", entry.cidr)
    except Exception:
        logger.exception("runtime CIDR store read failed; falling back to env")

    if not networks:
        raw_cidrs = os.environ.get("IAM_JIT_ALLOWED_SOURCE_CIDRS", "").strip()
        if not raw_cidrs:
            return CIDRDecision(
                allowed=True, matched_cidr=None, source_ip=None,
                reason="no_acl_configured",
            )
        networks = _parse_cidrs(raw_cidrs)
    if not networks:
        # Operator set the env var but every entry was malformed.
        # Fail CLOSED — they intended a restriction; honor that even
        # though we couldn't parse it.
        return CIDRDecision(
            allowed=False, matched_cidr=None, source_ip=None,
            reason="invalid_acl_config",
        )
    source_ip = _read_source_ip(request_client_host, xff_header)
    if not source_ip:
        # Lambda extension or odd test setup; refuse rather than
        # quietly bypass.
        return CIDRDecision(
            allowed=False, matched_cidr=None, source_ip=None,
            reason="no_source_ip_available",
        )
    try:
        addr = ipaddress.ip_address(source_ip)
    except ValueError:
        return CIDRDecision(
            allowed=False, matched_cidr=None, source_ip=source_ip,
            reason="invalid_source_ip",
        )
    for net in networks:
        # Avoid IPv4-vs-IPv6 mismatch raising.
        if isinstance(addr, ipaddress.IPv4Address) != isinstance(
            net.network_address, ipaddress.IPv4Address
        ):
            continue
        if addr in net:
            return CIDRDecision(
                allowed=True, matched_cidr=str(net),
                source_ip=source_ip, reason="ip_in_allowlist",
            )
    return CIDRDecision(
        allowed=False, matched_cidr=None, source_ip=source_ip,
        reason="ip_not_in_allowlist",
    )


def get_configured_cidrs() -> list[str]:
    """Helper for the admin page — surface what's currently enforced."""
    raw = os.environ.get("IAM_JIT_ALLOWED_SOURCE_CIDRS", "").strip()
    return [str(n) for n in _parse_cidrs(raw)] if raw else []


def is_acl_configured() -> bool:
    return bool(get_configured_cidrs())
