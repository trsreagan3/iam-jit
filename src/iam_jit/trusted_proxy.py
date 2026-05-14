"""Shared parser + matcher for `IAM_JIT_TRUSTED_PROXY_CIDRS`.

Round-3 WB finding TRUSTED-PROXY-CIDRS-PARSER-DISCREPANCY caught
three modules (`routes/score.py`, `routes/web.py`, `network_acl.py`,
`public_url.py`) parsing the same env var with subtly different
rules. The score module used `.split(",")` (no newline tolerance);
the others used `replace(",", " ").split()` (whitespace-tolerant).
An operator who wrote the env var as a multi-line Terraform value
got score's XFF trust silently disabled while the others worked.

This module is the single source of truth. All callers MUST use
`parse_trusted_cidrs()` and `peer_in_trusted_cidrs()` rather than
inlining their own parse.
"""

from __future__ import annotations

import ipaddress
import os


def parse_trusted_cidrs(
    raw: str | None = None,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse the `IAM_JIT_TRUSTED_PROXY_CIDRS` env var (or `raw` if
    given) into a list of ip_network objects.

    Accepts comma-separated, whitespace-separated, or newline-
    separated entries. Malformed tokens are skipped silently — the
    operator can confirm what was parsed via
    `parse_trusted_cidrs()` if the result is unexpected. Empty
    input returns [].
    """
    if raw is None:
        raw = os.environ.get("IAM_JIT_TRUSTED_PROXY_CIDRS") or ""
    raw = raw.strip()
    if not raw:
        return []
    normalized = (
        raw.replace(",", " ").replace("\n", " ").replace("\t", " ")
    )
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for tok in normalized.split():
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue
    return out


def peer_in_trusted_cidrs(
    peer_host: str | None,
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
) -> bool:
    """Return True iff the peer IP falls inside one of the trusted-
    proxy CIDRs. `nets` defaults to the parsed env var.

    Handles IPv4-mapped IPv6 (`::ffff:10.0.0.5`) by normalizing to
    the embedded IPv4 — closes XFF-IPV4-MAPPED-IPV6 across all
    three call sites at once.
    """
    if not peer_host:
        return False
    if nets is None:
        nets = parse_trusted_cidrs()
    if not nets:
        return False
    try:
        addr = ipaddress.ip_address(peer_host)
    except ValueError:
        return False
    # Normalize IPv4-mapped IPv6 → IPv4 so an operator who wires
    # 10.0.0.0/8 thinking it covers all 10.x clients gets that
    # behavior even when the peer arrives as ::ffff:10.x.y.z.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    for net in nets:
        if isinstance(addr, ipaddress.IPv4Address) != isinstance(
            net.network_address, ipaddress.IPv4Address
        ):
            continue
        if addr in net:
            return True
    return False


def real_client_from_xff(
    peer_host: str | None,
    xff_header: str | None,
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
) -> str | None:
    """Resolve the real client IP behind a chain of trusted proxies.

    Returns:
      - peer_host when XFF parsing should not apply (peer is not in
        the trusted-proxy set; nothing else to consider).
      - the right-most XFF token that is NOT itself a trusted-proxy
        IP — that's the real client per RFC 7239 semantics.
      - peer_host as fallback when XFF only contains trusted-proxy
        hops.
    """
    if nets is None:
        nets = parse_trusted_cidrs()
    if not peer_host or not nets:
        return peer_host
    if not peer_in_trusted_cidrs(peer_host, nets):
        return peer_host
    if not xff_header:
        return peer_host
    tokens = [t.strip() for t in xff_header.split(",") if t.strip()]
    for candidate in reversed(tokens):
        try:
            cand_addr = ipaddress.ip_address(candidate)
        except ValueError:
            # Garbage token — stop walking and return peer_host
            # to avoid leaking attacker-supplied strings into
            # downstream rate-limit keys.
            return peer_host
        # IPv4-mapped normalization for membership tests.
        if (
            isinstance(cand_addr, ipaddress.IPv6Address)
            and cand_addr.ipv4_mapped
        ):
            cand_addr = cand_addr.ipv4_mapped
        for n in nets:
            if isinstance(cand_addr, ipaddress.IPv4Address) != isinstance(
                n.network_address, ipaddress.IPv4Address
            ):
                continue
            if cand_addr in n:
                break
        else:
            return candidate
    return peer_host
