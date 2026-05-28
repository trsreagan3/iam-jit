"""Resolve where ibounce should forward a SigV4-signed AWS request.

#687 fix: the canonical iam-jit setup is `iam-jit attach` writing
``endpoint_url=http://127.0.0.1:8767`` into the SDK config so the SDK
sends every AWS call to ibounce. That makes the inbound HTTP ``Host``
header ``127.0.0.1:8767`` — pointing at ibounce itself. The pre-#687
forward code did ``forward_target_host = override or host_header`` and
in this canonical shape that recursed (ibounce dialing ibounce). Every
real AWS call returned 502 ``UPSTREAM_FORWARD_FAILED``; the audit row
still landed (so the counter ticked and most UATs reported "works")
but the agent's actual workflow was broken.

The fix: when the inbound Host is our own listener address, derive the
upstream from the SigV4 ``Credential=`` scope (service + region) using
botocore's canonical endpoint catalog. That gives us
``sts.us-east-1.amazonaws.com`` / ``iam.amazonaws.com`` /
``s3.us-west-2.amazonaws.com`` / etc. — exactly what AWS expects.

Lookup priority in :func:`resolve_forward_target`:

1. Operator override (``--upstream`` / ``forward_host_override``) — for
   LocalStack + #300 test scenarios. Wins unconditionally.
2. Inbound Host header IF it's NOT ourselves — preserves behaviour for
   SDKs configured against the real AWS endpoint that nonetheless route
   through ibounce (e.g. via system network proxy).
3. SigV4-derived canonical AWS endpoint — the canonical
   ``iam-jit attach`` setup lands here.
4. ``None`` → caller surfaces a clear ``UPSTREAM_RESOLUTION_FAILED``
   instead of recursing (per [[ibounce-honest-positioning]]: an honest
   failure beats a silent infinite-loop dial).
"""
from __future__ import annotations

import functools
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# Module-level cached botocore resolver. botocore's Session construction
# is non-trivial (loads the endpoints.json catalog from disk); doing it
# once at import time keeps the forward path fast. Tests can DI a fake
# via the ``aws_endpoint_resolver`` ProxyConfig field instead of
# monkey-patching this module.
@functools.lru_cache(maxsize=1)
def _botocore_resolver():  # pragma: no cover - thin wrapper
    import botocore.session

    return botocore.session.Session()._get_internal_component(
        "endpoint_resolver"
    )


def canonical_aws_endpoint(service: str, region: Optional[str]) -> Optional[str]:
    """Return the canonical AWS hostname for *service* in *region*.

    Examples (per the AWS endpoints catalog, via botocore):

    >>> canonical_aws_endpoint("sts", "us-east-1")
    'sts.us-east-1.amazonaws.com'
    >>> canonical_aws_endpoint("iam", "us-east-1")
    'iam.amazonaws.com'
    >>> canonical_aws_endpoint("s3", "us-west-2")
    's3.us-west-2.amazonaws.com'

    Returns ``None`` for unknown services or when the resolver bails
    (rather than fabricating a guess). The caller treats ``None`` as
    "we can't safely forward this" and surfaces an honest error.

    *region* may be ``None`` for global services (IAM, etc.). botocore
    falls back to a partition-default in that case.
    """
    if not service:
        return None
    region = region or "us-east-1"  # botocore prefers a region anchor
    try:
        endpoint = _botocore_resolver().construct_endpoint(service, region)
    except Exception as exc:  # botocore raises various NoRegionError/etc.
        logger.debug(
            "upstream_resolver: botocore failed on %s/%s: %s",
            service, region, exc,
        )
        return None
    if not endpoint:
        return None
    hostname = endpoint.get("hostname")
    return hostname or None


def is_loopback_self(
    host_header: str, listen_host: str, listen_port: int
) -> bool:
    """True iff *host_header* points at this bouncer's own listener.

    Covers the canonical ``iam-jit attach`` shapes:

    - ``127.0.0.1:8767``           (default bind)
    - ``localhost:8767``           (some SDKs prefer the name)
    - ``[::1]:8767``               (IPv6 loopback)
    - ``<actual-bind-host>:8767``  (non-default --host)

    Case-insensitive on the host portion. Port match is required so a
    bouncer on :8767 doesn't shadow a different local service on :9000
    that an operator legitimately wants to point at.
    """
    if not host_header:
        return False
    # IPv6-aware host:port split. `[::1]:8767` → host=`::1`, port=8767.
    # `127.0.0.1:8767` → host=`127.0.0.1`, port=8767. Bare host → no port.
    if host_header.startswith("["):
        close = host_header.find("]")
        if close == -1:
            return False
        host_part = host_header[1:close].lower()
        port_part = host_header[close + 1:].lstrip(":")
    else:
        host_part, _, port_part = host_header.partition(":")
        host_part = host_part.lower()
    try:
        port = int(port_part) if port_part else None
    except ValueError:
        port = None
    if port is not None and port != int(listen_port):
        return False
    if port is None:
        # Bare host without port — only match if we're bound to default
        # HTTP/S ports (unusual; ibounce defaults to 8767).
        if int(listen_port) not in (80, 443):
            return False
    listen_host_norm = (listen_host or "").lower()
    loopback_aliases = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
    if host_part in loopback_aliases:
        return True
    if host_part == listen_host_norm:
        return True
    # 127.0.0.0/8 — any 127.x.y.z is loopback.
    if host_part.startswith("127.") and all(
        seg.isdigit() and 0 <= int(seg) <= 255
        for seg in host_part.split(".") if seg
    ) and host_part.count(".") == 3:
        return True
    return False


def resolve_forward_target(
    *,
    override: Optional[str],
    host_header: str,
    listen_host: str,
    listen_port: int,
    service: Optional[str],
    region: Optional[str],
    endpoint_resolver: Optional[Callable[[str, Optional[str]], Optional[str]]] = None,
) -> Optional[str]:
    """Pick the host:port that ``_forward_to_aws`` should dial.

    See module docstring for the priority order. Returns ``None`` only
    in the "SDK pointed at us + can't derive canonical endpoint" case;
    the caller MUST surface a clear failure rather than passing
    ``None`` to the forwarder.

    *endpoint_resolver* is for DI in tests — production passes ``None``
    and we use :func:`canonical_aws_endpoint`. Test fakes can point at
    a local aiohttp server so the no-override path is exercised
    end-to-end without dialling real AWS.
    """
    if override:
        return override
    if not is_loopback_self(host_header, listen_host, listen_port):
        # SDK is pointed at the real AWS endpoint (or at some other
        # legitimate target on the outbound allowlist). Preserve the
        # Host header — that's the established #300/pre-#687 behaviour.
        return host_header
    resolver = endpoint_resolver or canonical_aws_endpoint
    resolved = resolver(service or "", region)
    if resolved:
        logger.debug(
            "upstream_resolver: %r is self; resolved %s/%s -> %s",
            host_header, service, region, resolved,
        )
        return resolved
    # SDK pointed at us AND we couldn't derive the canonical endpoint.
    # Returning None signals the caller to fail honestly.
    logger.warning(
        "upstream_resolver: cannot resolve upstream — host_header=%r is self, "
        "service=%r region=%r not in endpoint catalog",
        host_header, service, region,
    )
    return None
