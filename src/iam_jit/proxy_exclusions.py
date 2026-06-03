"""Shared NO_PROXY exclusion list for bouncer HTTP(S)-proxy wiring.

When the gbounce forward proxy is wired via ``HTTP_PROXY``/``HTTPS_PROXY``,
the agent harness's OWN control-plane traffic (e.g. Claude Code ->
api.anthropic.com) gets routed through the bouncer too — unless explicitly
excluded.  That is dangerous: a bouncer is a deterrent/observe proxy, NOT
fail-open for the harness.  If the bouncer is down (or its upstream API has
an outage), the harness can be *permanently* bricked — the proxy env is
static and keeps routing to the dead local proxy even after the upstream
recovers.  The only recovery is to remove the proxy env (delete/edit
``settings.json`` or ``unset HTTPS_PROXY``).

Carving the harness control-plane + telemetry hosts out via ``NO_PROXY``
keeps the agent's *brain* talking directly to its API, while still routing
the agent's *tool / SDK* traffic through the bouncer.  This is the intended
boundary: the bouncer observes/gates what the agent DOES, never what the
harness needs to think.

Reference: the 2026-06-03 lockup incident (an Anthropic API outage left
Claude Code unable to recover until ``~/.claude/settings.json`` was deleted,
because the wired ``HTTPS_PROXY`` had no carve-out for api.anthropic.com).
"""

from __future__ import annotations

# Hosts that must NEVER be routed through a bouncer proxy:
#   * loopback — never proxy to the bouncer itself / other local services
#   * anthropic.com (+ subdomains) — Claude Code's LLM control-plane +
#     telemetry (api / console / statsig.anthropic.com, etc.)
# Both the bare-domain and leading-dot forms are included for broad matcher
# compatibility (Node/undici, Python requests/urllib, Go net/http, curl).
HARNESS_NO_PROXY_HOSTS: tuple[str, ...] = (
    "localhost",
    "127.0.0.1",
    "::1",
    "anthropic.com",
    ".anthropic.com",
)


def merge_no_proxy(existing: str | None = None) -> str:
    """Return a ``NO_PROXY`` value covering the harness hosts.

    Any pre-existing value (operator-supplied, from ``settings.json`` or the
    shell) is preserved and unioned in front of the harness hosts.  The
    result is order-preserving and de-duplicated, and never drops a host the
    operator already had.
    """
    out: list[str] = []
    seen: set[str] = set()

    sources: list[str] = []
    if existing:
        sources.extend(part.strip() for part in existing.split(","))
    sources.extend(HARNESS_NO_PROXY_HOSTS)

    for host in sources:
        if host and host not in seen:
            seen.add(host)
            out.append(host)

    return ",".join(out)
