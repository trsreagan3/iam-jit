"""Resolve the externally-visible base URL for the running request.

A reverse-proxy / CDN in front of iam-jit (CloudFront, ALB, custom
Apache/Nginx) terminates TLS and rewrites the Host header to the
origin's domain before forwarding to the Lambda. By the time FastAPI
sees the request, `request.base_url` is the *origin* (the Function
URL), not the *public endpoint* the user actually hit. If we use
`request.base_url` to mint magic-link callbacks the link will point
at a URL no end-user can reach.

This module centralizes the precedence:

  1. `IAM_JIT_TRUST_FORWARDED_HOST=1` AND `X-Forwarded-Host` is set
     → use it (with `X-Forwarded-Proto`, default https). CloudFront
     sets these via the `AllViewerExceptHostHeader` origin-request
     policy. The flag is opt-in because trusting XFH without a real
     proxy in front would let any external caller forge the link
     domain.

  2. `IAM_JIT_PUBLIC_URL` env var set → use it verbatim. The deploy
     operator pinned a known-good public URL.

  3. Fall back to `request.base_url`. Right for local dev and for
     deployments where the Function URL itself is the public surface.

Path callers should pass relative paths (e.g. `/setup`); the helper
joins them onto the resolved base.
"""

from __future__ import annotations

import os
from typing import Any


def _trust_xfh() -> bool:
    return (os.environ.get("IAM_JIT_TRUST_FORWARDED_HOST") or "").lower() in {
        "1", "true", "yes"
    }


def _allowed_public_hosts() -> list[str]:
    raw = (os.environ.get("IAM_JIT_ALLOWED_PUBLIC_HOSTS") or "").strip()
    if not raw:
        return []
    return [
        h.strip().lower()
        for h in raw.replace(",", " ").split()
        if h.strip()
    ]


def _peer_in_trusted_proxy_cidrs(request: Any) -> bool:
    """The immediate peer must fall in a configured trusted-proxy CIDR
    before XFH is honored — closes BB2-09 host-header poisoning on
    deployments where the Function URL is reachable directly."""
    cidrs_raw = (os.environ.get("IAM_JIT_TRUSTED_PROXY_CIDRS") or "").strip()
    if not cidrs_raw:
        return False
    try:
        peer_host = request.client.host if request.client else None
    except Exception:
        peer_host = None
    if not peer_host:
        return False
    import ipaddress as _ipaddress
    try:
        peer_addr = _ipaddress.ip_address(peer_host)
    except ValueError:
        return False
    for tok in cidrs_raw.replace(",", " ").split():
        tok = tok.strip()
        if not tok:
            continue
        try:
            net = _ipaddress.ip_network(tok, strict=False)
        except ValueError:
            continue
        if isinstance(peer_addr, _ipaddress.IPv4Address) != isinstance(
            net.network_address, _ipaddress.IPv4Address
        ):
            continue
        if peer_addr in net:
            return True
    return False


def base_for(request: Any | None) -> str:
    """Return the resolved public base URL with no trailing slash.

    `request` is the FastAPI Request (optional — None forces the
    env-var or fallback paths). The signature accepts `Any` to keep
    this module import-free of FastAPI types.

    XFH-trust path (BB2-09 closure) requires ALL of:
      - `IAM_JIT_TRUST_FORWARDED_HOST=1`
      - the immediate peer IS in `IAM_JIT_TRUSTED_PROXY_CIDRS`
      - the X-Forwarded-Host value matches an entry in
        `IAM_JIT_ALLOWED_PUBLIC_HOSTS`
    Any one missing → fall through to env-pinned `IAM_JIT_PUBLIC_URL`
    or `request.base_url`. This kills host-header smuggling on
    Function-URL deployments where an attacker could otherwise spoof
    XFH directly.
    """
    if (
        request is not None
        and _trust_xfh()
        and _peer_in_trusted_proxy_cidrs(request)
    ):
        try:
            xfh = request.headers.get("x-forwarded-host") or ""
        except Exception:
            xfh = ""
        if xfh:
            xfp = ""
            try:
                xfp = request.headers.get("x-forwarded-proto") or ""
            except Exception:
                pass
            scheme = (xfp.split(",")[0].strip() or "https")
            host = xfh.split(",")[0].strip().lower()
            allowed = _allowed_public_hosts()
            if host and allowed and host in allowed:
                return f"{scheme}://{host}".rstrip("/")

    explicit = (os.environ.get("IAM_JIT_PUBLIC_URL") or "").strip()
    if explicit:
        return explicit.rstrip("/")

    if request is not None:
        try:
            return str(request.base_url).rstrip("/")
        except Exception:
            pass

    return "http://127.0.0.1:8000"


def absolute(request: Any | None, path: str) -> str:
    """`base_for(request) + path`, with a leading slash on `path` if
    the caller forgot one."""
    base = base_for(request)
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"
