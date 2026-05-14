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
    deployments where the Function URL is reachable directly.

    Delegates to the shared `trusted_proxy.peer_in_trusted_cidrs`
    helper so the parser rules and IPv4-mapped-IPv6 normalization
    stay consistent with score / network_acl / web.
    """
    try:
        peer_host = request.client.host if request.client else None
    except Exception:
        peer_host = None
    from . import trusted_proxy

    return trusted_proxy.peer_in_trusted_cidrs(peer_host)


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
            # XFP-SCHEME-INJECTION-IN-PUBLIC-URL closure: allowlist
            # the scheme to {http, https}. A malicious upstream that
            # set `X-Forwarded-Proto: javascript` would otherwise
            # produce `javascript://allowed-host/...` which is a
            # functional JavaScript URL on click. Default to https
            # for any unrecognized scheme.
            raw_scheme = xfp.split(",")[0].strip().lower()
            scheme = raw_scheme if raw_scheme in {"http", "https"} else "https"
            # PUBLIC-URL-XFH-LEFTMOST-TOKEN closure: pick the
            # right-most XFH token that's in the allowed-public-hosts
            # list. Each trusted proxy appends its host on the right,
            # so the right-most is closer to the public surface than
            # the (attacker-controlled) leftmost.
            allowed = _allowed_public_hosts()
            if allowed:
                xfh_tokens = [
                    t.strip().lower() for t in xfh.split(",") if t.strip()
                ]
                for candidate in reversed(xfh_tokens):
                    if candidate in allowed:
                        return f"{scheme}://{candidate}".rstrip("/")

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
