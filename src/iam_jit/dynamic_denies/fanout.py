# #324e — Cross-bouncer reload fan-out.
"""Call each affected bouncer's
``POST /admin/dynamic-denies/reload`` endpoint after a write.

Per the design doc + ``[[cross-product-agent-parity]]`` every Bounce
product ships the same mgmt-port endpoint shape. Default mgmt ports:

  * ibounce — 8767
  * kbouncer — 8766
  * dbounce — 8768
  * gbounce — 8769

Operators override per-bouncer with the ``--bouncer NAME=URL`` flag
(repeatable). The fan-out is best-effort: per
``[[ibounce-honest-positioning]]`` a 503 / timeout / connection-refused
is surfaced honestly but does NOT abort the CLI — the YAML file IS the
source of truth, and the watcher on the downed bouncer picks the rule
up on its next start.
"""

from __future__ import annotations

import dataclasses
import json
import typing
from urllib import error as _urlerr
from urllib import request as _urlreq

# Default mgmt-port URLs. Mirrors
# ``cli_audit_query.DEFAULT_BOUNCERS`` so the cross-product UX stays
# parity-shaped.
DEFAULT_BOUNCER_URLS: dict[str, str] = {
    "ibounce": "http://127.0.0.1:8767",
    "kbouncer": "http://127.0.0.1:8766",
    # `kbounce` is the schema's canonical name; `kbouncer` is the
    # historical alias kept across the cross-product schema. The
    # writer emits whichever name the resolver returned; we accept
    # both at fan-out time.
    "kbounce": "http://127.0.0.1:8766",
    "dbounce": "http://127.0.0.1:8768",
    "gbounce": "http://127.0.0.1:8769",
}

RELOAD_PATH = "/admin/dynamic-denies/reload"
"""Endpoint path every bouncer ships under its mgmt port."""

DEFAULT_TIMEOUT_SECONDS = 5.0
"""Per-bouncer reload-call timeout. Short enough that one downed
bouncer doesn't pin the CLI; long enough for the slow-network case
(remote bouncer over a VPN)."""


@dataclasses.dataclass(frozen=True)
class ReloadResult:
    """One bouncer's reload outcome.

    The fan-out returns a list of these so the CLI/MCP layer can
    render a "this bouncer reloaded" / "this bouncer is unreachable"
    routing summary in one pass.
    """

    bouncer: str
    """Canonical bouncer name (``ibounce`` / ``kbouncer`` / ``dbounce``
    / ``gbounce``)."""

    url: str
    """Base URL the fan-out POSTed to."""

    reloaded: bool
    """``True`` when the POST returned 200 with ``reloaded: true``.
    ``False`` on any failure path."""

    status_code: int | None
    """HTTP status from the bouncer's response. ``None`` when the
    request failed before a response was received (DNS / refused /
    timeout)."""

    rules_count: int | None
    """Total rules count surfaced by the bouncer's reload response.
    ``None`` when the response wasn't parseable as the documented
    shape."""

    rules_applied_to_self: int | None
    """How many rules in the file the bouncer kept after its own
    ``applied_to`` filter. ``None`` when unparseable."""

    error: str | None
    """Honest error string when ``reloaded`` is ``False``. Empty
    string when the bouncer returned 200 but the body wasn't the
    expected shape."""


def fanout_reload(
    affected_bouncers: typing.Iterable[str],
    *,
    overrides: typing.Mapping[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[ReloadResult]:
    """Hit ``POST /admin/dynamic-denies/reload`` on each affected
    bouncer.

    Parameters
    ----------
    affected_bouncers
        Bouncer names from the rule's ``applied_to`` field. Unknown /
        empty entries are skipped silently — the CLI's writer caught
        unrecognised names before they got here.
    overrides
        Mapping of ``bouncer_name -> base_url`` overrides. Missing
        entries fall back to ``DEFAULT_BOUNCER_URLS``.
    timeout
        Per-bouncer HTTP timeout.

    Returns
    -------
    list[ReloadResult]
        One entry per resolved bouncer. The CLI renders each line in
        the routing-explanation block.
    """
    overrides_map: dict[str, str] = dict(overrides or {})
    seen: set[str] = set()
    results: list[ReloadResult] = []
    for raw in affected_bouncers:
        if not raw:
            continue
        bouncer = raw.strip()
        if not bouncer or bouncer in seen:
            continue
        seen.add(bouncer)
        # `kbouncer` and `kbounce` are the same product (canonical
        # name + historical alias). Treat them as the same node for
        # fan-out — call the configured URL ONCE.
        if bouncer == "kbouncer" and "kbounce" in seen:
            continue
        if bouncer == "kbounce" and "kbouncer" in seen:
            continue

        base_url = (
            overrides_map.get(bouncer)
            or DEFAULT_BOUNCER_URLS.get(bouncer)
        )
        if not base_url:
            results.append(ReloadResult(
                bouncer=bouncer,
                url="",
                reloaded=False,
                status_code=None,
                rules_count=None,
                rules_applied_to_self=None,
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
) -> ReloadResult:
    """POST to a single bouncer's reload endpoint + parse the response."""
    url = base_url.rstrip("/") + RELOAD_PATH
    req = _urlreq.Request(
        url,
        data=b"",  # empty body — the endpoint just triggers a re-read
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            body = resp.read()
    except _urlerr.HTTPError as e:
        # Per the bouncer's reload contract, 422 = parse error;
        # 503 = watcher not configured; 401/403 = auth gate. Surface
        # whatever the bouncer told us so an operator can fix it.
        try:
            body_text = e.read().decode("utf-8", errors="replace")
        except Exception:
            body_text = str(e)
        return ReloadResult(
            bouncer=bouncer,
            url=url,
            reloaded=False,
            status_code=e.code,
            rules_count=None,
            rules_applied_to_self=None,
            error=(
                f"HTTP {e.code}: {body_text[:240]}"
            ),
        )
    except (_urlerr.URLError, TimeoutError, OSError) as e:
        return ReloadResult(
            bouncer=bouncer,
            url=url,
            reloaded=False,
            status_code=None,
            rules_count=None,
            rules_applied_to_self=None,
            error=f"unreachable: {e}",
        )

    return _parse_reload_response(bouncer, url, status, body)


def _parse_reload_response(
    bouncer: str,
    url: str,
    status: int,
    body: bytes,
) -> ReloadResult:
    """Parse a bouncer's reload response body."""
    try:
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("response body was not a JSON object")
    except (json.JSONDecodeError, ValueError) as e:
        return ReloadResult(
            bouncer=bouncer,
            url=url,
            reloaded=False,
            status_code=status,
            rules_count=None,
            rules_applied_to_self=None,
            error=f"non-JSON response: {e}",
        )

    reloaded = bool(payload.get("reloaded"))
    rules_count = _coerce_int(payload.get("rules_count"))
    # Each bouncer surfaces its own-applied count under a product-
    # specific key. Try each in turn so the fan-out is product-agnostic.
    rules_applied_to_self: int | None = None
    for key in (
        "rules_applied_to_ibounce",
        "rules_applied_to_kbouncer",
        "rules_applied_to_kbounce",
        "rules_applied_to_dbounce",
        "rules_applied_to_gbounce",
    ):
        if key in payload:
            rules_applied_to_self = _coerce_int(payload[key])
            break

    error: str | None = None
    if not reloaded:
        error = str(payload.get("error") or "reload returned reloaded=false")

    return ReloadResult(
        bouncer=bouncer,
        url=url,
        reloaded=reloaded,
        status_code=status,
        rules_count=rules_count,
        rules_applied_to_self=rules_applied_to_self,
        error=error,
    )


def _coerce_int(value: typing.Any) -> int | None:
    if isinstance(value, bool):
        # bool is a subclass of int in Python; reject explicitly so a
        # `"reloaded": true` field doesn't leak into the count.
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def parse_bouncer_override(spec: str) -> tuple[str, str]:
    """Parse a single ``--bouncer NAME=URL`` override.

    Raises :class:`ValueError` on malformed input — the CLI surfaces
    the error to the operator.
    """
    if not isinstance(spec, str) or "=" not in spec:
        raise ValueError(
            f"bouncer override {spec!r} must be `NAME=URL` "
            f"(e.g. ibounce=http://host:8767)"
        )
    name, _, url = spec.partition("=")
    name = name.strip()
    url = url.strip()
    if not name or not url:
        raise ValueError(
            f"bouncer override {spec!r} must be `NAME=URL`"
        )
    if name not in DEFAULT_BOUNCER_URLS:
        raise ValueError(
            f"bouncer override name {name!r} is not a recognised "
            f"bouncer (expected one of: "
            f"{sorted(DEFAULT_BOUNCER_URLS.keys())})"
        )
    return name, url


__all__ = [
    "DEFAULT_BOUNCER_URLS",
    "DEFAULT_TIMEOUT_SECONDS",
    "RELOAD_PATH",
    "ReloadResult",
    "fanout_reload",
    "parse_bouncer_override",
]
