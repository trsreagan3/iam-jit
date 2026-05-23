# #345 / §A25 — Cross-bouncer profile-reload fan-out.
"""Call each affected bouncer's ``POST /admin/profile/reload`` endpoint
after a profile mutation.

Mirrors :mod:`iam_jit.dynamic_denies.fanout` deliberately so the
operator's mental model is "all admin mutations have a fan-out;
the only thing that changes is the endpoint path."

Per ``[[ibounce-honest-positioning]]``: a 503 / timeout / refused is
surfaced honestly but does NOT abort the CLI. The profiles.yaml IS the
source of truth. If the bouncer ships a polling watcher it picks the
change up on its next poll; otherwise the operator restarts the
bouncer (or runs ``ibounce profile reload`` per Phase 2 once that
lands).
"""

from __future__ import annotations

import dataclasses
import json
import typing
from urllib import error as _urlerr
from urllib import request as _urlreq

# Default mgmt-port URLs. Mirrors
# :data:`iam_jit.dynamic_denies.fanout.DEFAULT_BOUNCER_URLS` so the
# cross-product UX stays parity-shaped.
DEFAULT_PROFILE_RELOAD_URLS: dict[str, str] = {
    "ibounce": "http://127.0.0.1:8767",
    "kbouncer": "http://127.0.0.1:8766",
    "kbounce": "http://127.0.0.1:8766",
    "dbounce": "http://127.0.0.1:8768",
    "gbounce": "http://127.0.0.1:8769",
}

RELOAD_PATH = "/admin/profile/reload"
"""Endpoint path the bouncer ships under its mgmt port. ibounce
implements this in :func:`iam_jit.bouncer.proxy.serve`; the sibling
bouncers ship the same shape in Phase 2 per
``[[cross-product-agent-parity]]``. In the meantime the sibling
bouncers respond 404 which the fan-out surfaces as a warning, not a
fatal error (the profiles.yaml is the source of truth)."""

DEFAULT_TIMEOUT_SECONDS = 5.0


@dataclasses.dataclass(frozen=True)
class ProfileReloadResult:
    """One bouncer's profile-reload outcome."""

    bouncer: str
    url: str
    reloaded: bool
    status_code: int | None
    error: str | None


def fanout_profile_reload(
    affected_bouncers: typing.Iterable[str],
    *,
    overrides: typing.Mapping[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[ProfileReloadResult]:
    """Hit ``POST /admin/profile/reload`` on each affected bouncer."""
    overrides_map: dict[str, str] = dict(overrides or {})
    seen: set[str] = set()
    results: list[ProfileReloadResult] = []
    for raw in affected_bouncers:
        if not raw:
            continue
        bouncer = raw.strip()
        if not bouncer or bouncer in seen:
            continue
        seen.add(bouncer)
        # kbouncer + kbounce share a mgmt port; call once.
        if bouncer == "kbouncer" and "kbounce" in seen:
            continue
        if bouncer == "kbounce" and "kbouncer" in seen:
            continue
        base_url = (
            overrides_map.get(bouncer)
            or DEFAULT_PROFILE_RELOAD_URLS.get(bouncer)
        )
        if not base_url:
            results.append(ProfileReloadResult(
                bouncer=bouncer,
                url="",
                reloaded=False,
                status_code=None,
                error=(
                    f"no default URL for bouncer {bouncer!r}; pass "
                    f"--bouncer {bouncer}=http://host:port to override"
                ),
            ))
            continue
        results.append(_call_reload(bouncer, base_url, timeout=timeout))
    return results


def _call_reload(
    bouncer: str,
    base_url: str,
    *,
    timeout: float,
) -> ProfileReloadResult:
    """POST to one bouncer's reload endpoint + parse the response."""
    url = base_url.rstrip("/") + RELOAD_PATH
    req = _urlreq.Request(
        url,
        data=b"",
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            body = resp.read()
    except _urlerr.HTTPError as e:
        # 404 == sibling bouncer doesn't implement profile reload yet
        # (Phase 2). Treat as a warning, not an error: profiles.yaml is
        # the source of truth.
        if e.code == 404:
            return ProfileReloadResult(
                bouncer=bouncer,
                url=url,
                reloaded=False,
                status_code=404,
                error=(
                    "endpoint not implemented (Phase 2 ships profile "
                    "reload across the suite; profiles.yaml is already "
                    "updated)"
                ),
            )
        try:
            body_text = e.read().decode("utf-8", errors="replace")
        except Exception:
            body_text = str(e)
        return ProfileReloadResult(
            bouncer=bouncer,
            url=url,
            reloaded=False,
            status_code=e.code,
            error=f"HTTP {e.code}: {body_text[:240]}",
        )
    except (_urlerr.URLError, TimeoutError, OSError) as e:
        return ProfileReloadResult(
            bouncer=bouncer,
            url=url,
            reloaded=False,
            status_code=None,
            error=f"unreachable: {e}",
        )

    try:
        payload = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, ValueError):
        return ProfileReloadResult(
            bouncer=bouncer,
            url=url,
            reloaded=False,
            status_code=status,
            error="non-JSON response",
        )
    if not isinstance(payload, dict):
        return ProfileReloadResult(
            bouncer=bouncer,
            url=url,
            reloaded=False,
            status_code=status,
            error="response body was not a JSON object",
        )
    reloaded = bool(payload.get("reloaded"))
    err = None if reloaded else str(payload.get("error") or "reloaded=false")
    return ProfileReloadResult(
        bouncer=bouncer,
        url=url,
        reloaded=reloaded,
        status_code=status,
        error=err,
    )


__all__ = [
    "DEFAULT_PROFILE_RELOAD_URLS",
    "DEFAULT_TIMEOUT_SECONDS",
    "ProfileReloadResult",
    "RELOAD_PATH",
    "fanout_profile_reload",
]
